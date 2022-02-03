package embedshim

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/containerd/containerd/namespaces"
	shimebpf "github.com/fuweid/embedshim/pkg/ebpf"
	"github.com/fuweid/embedshim/pkg/pidfd"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type callbackFn func(*shimebpf.TaskExitStatus) error

type monitor struct {
	sync.Mutex

	idr     *idAllocator
	epoller *pidfd.Epoller
	store   *shimebpf.SchedProcessExitStore
}

func newMonitor(stateDir string) (_ *monitor, retErr error) {
	idr, err := newIdAllocator(stateDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			idr.close()
		}
	}()

	epoller, err := pidfd.NewEpoller()
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			epoller.Close()
		}
	}()

	store, err := shimebpf.NewSchedProcessExitStore(stateDir)
	if err != nil {
		return nil, err
	}

	m := &monitor{
		idr:     idr,
		epoller: epoller,
		store:   store,
	}

	// TODO: check the return
	go m.epoller.Run()
	return m, nil
}

func (m *monitor) subscribe(ns string, cid string, pid uint32, cb callbackFn) (retErr error) {
	m.Lock()
	defer m.Unlock()

	tid, err := m.idr.nextID(ns, cid)
	if err != nil {
		return fmt.Errorf("failed to allocate ID for container %s in namespace %s: %w", cid, ns, err)
	}
	defer func() {
		if retErr != nil {
			m.idr.releaseID(ns, cid)
		}
	}()

	fd, err := pidfd.Open(pid, 0)
	if err != nil {
		return fmt.Errorf("failed to open pidfd on %v for container %s in namespace %s: %w", pid, cid, ns, err)
	}
	defer func() {
		if retErr != nil {
			unix.Close(int(fd))
		}
	}()

	if err := checkRuncInitAlive(ns, cid, pid); err != nil {
		return err
	}

	nsInfo, err := getPidnsInfo(pid)
	if err != nil {
		return fmt.Errorf("failed to get pidns info: %w")
	}

	if err := m.store.InsertRunningTask(pid, &shimebpf.TaskInfo{
		ID:        tid,
		PidnsInfo: nsInfo,
	}); err != nil {
		return fmt.Errorf("failed to insert taskinfo for container %s in namespace %s: %w", cid, ns, err)
	}
	defer func() {
		if retErr != nil {
			m.store.DelRunningTask(pid)
		}
	}()

	if err := fd.SendSignal(0, 0); err != nil {
		return err
	}

	if err := m.epoller.Add(fd, func() error {
		status, err := m.store.GetExitedTask(tid)
		if err != nil {
			return fmt.Errorf("failed to get exited status: %w", err)
		}

		if status.Pid != pid {
			return fmt.Errorf("expected %v but got pid %v", pid, status.Pid)
		}
		return cb(status)
	}); err != nil {
		return err
	}
	return nil
}

func (m *monitor) resubscribe(ctx context.Context, init *Init) (retErr error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}

	tid, err := m.idr.getID(ns, init.ID())
	if err != nil {
		return err
	}

	err = setExitedStatus(tid, m.store, init)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err

	}

	fd, err := pidfd.Open(uint32(init.Pid()), 0)
	if err != nil {
		if !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return setExitedStatus(tid, m.store, init)
	}
	defer func() {
		if retErr != nil && fd != 0 {
			unix.Close(int(fd))
		}
	}()

	info, err := m.store.GetRunningTask(uint32(init.Pid()))
	if err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return setExitedStatus(tid, m.store, init)
	}

	if info != nil && info.ID == tid {
		init.initState.(*createdState).transition("running")
		if err := m.epoller.Add(fd, func() error {
			return setExitedStatus(tid, m.store, init)
		}); err != nil {
			return err
		}
		return nil
	}

	unix.Close(int(fd))
	fd = 0
	return setExitedStatus(tid, m.store, init)
}

func getPidnsInfo(pid uint32) (shimebpf.PidnsInfo, error) {
	f, err := os.Stat(filepath.Join("/proc", strconv.Itoa(int(pid)), "ns", "pid"))
	if err != nil {
		return shimebpf.PidnsInfo{}, err
	}

	return shimebpf.PidnsInfo{
		Dev: (f.Sys().(*syscall.Stat_t)).Dev,
		Ino: (f.Sys().(*syscall.Stat_t)).Ino,
	}, nil

}

// TODO: check with runc-root dir
func checkRuncInitAlive(ns, cid string, pid uint32) error {
	found := false

	fdDir := filepath.Join("/proc", strconv.Itoa(int(pid)), "fd")
	err := filepath.Walk(fdDir, func(path string, info fs.FileInfo, err error) error {
		if found {
			return nil
		}

		if info.IsDir() {
			if path != fdDir {
				return filepath.SkipDir
			}
			return nil
		}

		fd, err := strconv.Atoi(info.Name())
		if err != nil || fd < 3 {
			return err
		}

		realPath, err := os.Readlink(path)
		if err != nil {
			return fmt.Errorf("failed to readlink fd %v: %w", fd, err)
		}

		if strings.HasSuffix(realPath, filepath.Join(ns, cid, "exec.fifo")) {
			found = true
			return nil
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to check runc-init process is alive: %w", err)
	}

	if !found {
		return fmt.Errorf("pid %v maybe not valid runc-init", pid)
	}
	return nil
}

func setExitedStatus(tid uint64, store *shimebpf.SchedProcessExitStore, init *Init) error {
	exitedStatus, err := store.GetExitedTask(tid)
	if err != nil {
		return err
	}

	init.SetExited(int(exitedStatus.ExitCode))
	return nil
}
