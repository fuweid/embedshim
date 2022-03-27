package embedshim

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/fuweid/embedshim/pkg/exitsnoop"
	"github.com/fuweid/embedshim/pkg/pidfd"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

var (
	// unexpectedExitCode is used when failed to get correct exit code.
	unexpectedExitCode = 128
)

type monitor struct {
	sync.Mutex

	pidPoller *pidfd.Epoller
	store     *exitsnoop.Store
}

func newMonitor(stateDir string) (_ *monitor, retErr error) {
	epoller, err := pidfd.NewEpoller()
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			epoller.Close()
		}
	}()

	store, err := exitsnoop.NewStore(stateDir)
	if err != nil {
		return nil, err
	}

	m := &monitor{
		pidPoller: epoller,
		store:     store,
	}

	// TODO: check the return
	go m.pidPoller.Run()
	return m, nil
}

// traceInitProcess checks init process is alive and starts to trace it's exit
// event by exitsnoop bpf tracepoint.
func (m *monitor) traceInitProcess(init *initProcess) (retErr error) {
	m.Lock()
	defer m.Unlock()

	fd, err := pidfd.Open(uint32(init.Pid()), 0)
	if err != nil {
		return fmt.Errorf("failed to open pidfd for %s: %w", init, err)
	}
	defer func() {
		if retErr != nil {
			unix.Close(int(fd))
		}
	}()

	// NOTE: The pid might be reused before pidfd.Open(like oom-killer or
	// manually kill), so that we need to check the runc-init's exec.fifo
	// file descriptor which is the "identity" of runc-init. :)
	//
	// Why we don't use runc-state commandline?
	//
	// The runc-state command only checks /proc/$pid/status's starttime,
	// which is not reliable. And then it only checks exec.fifo exist in
	// disk, but the runc-init has been killed. So we can't just use it.
	if err := checkRuncInitAlive(init); err != nil {
		return err
	}

	nsInfo, err := getPidnsInfo(uint32(init.Pid()))
	if err != nil {
		return fmt.Errorf("failed to get pidns info: %w", err)
	}

	if err := m.store.Trace(uint32(init.Pid()), &exitsnoop.TaskInfo{
		TraceID:   init.traceEventID,
		PidnsInfo: nsInfo,
	}); err != nil {
		return fmt.Errorf("failed to insert taskinfo for %s: %w", init, err)
	}
	defer func() {
		if retErr != nil {
			m.store.DeleteTracingTask(uint32(init.Pid()))
			m.store.DeleteExitedEvent(init.traceEventID)
		}
	}()

	// Before trace it, the init-process might be killed and the exitsnoop
	// tracepoint will not work, we need to check it alive again by pidfd.
	if err := fd.SendSignal(0, 0); err != nil {
		return err
	}

	if err := m.pidPoller.Add(fd, func() error {
		// TODO(fuweid): do we need to the pid value in event?
		status, err := m.store.GetExitedEvent(init.traceEventID)
		if err != nil {
			init.SetExited(unexpectedExitCode)
			return fmt.Errorf("failed to get exited status: %w", err)
		}

		init.SetExited(int(status.ExitCode))
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// repollingInitProcess is used to watch pidfd event after containerd restarts.
func (m *monitor) repollingInitProcess(init *initProcess) (retErr error) {
	var (
		eventID = init.traceEventID

		exitedStatus *exitsnoop.ExitStatus
		taskInfo     *exitsnoop.TaskInfo

		fd      pidfd.FD
		closeFD bool
		err     error
	)

	// fast path: check exit event from exitsnoop
	exitedStatus, err = m.store.GetExitedEvent(eventID)
	if err == nil {
		init.SetExited(int(exitedStatus.ExitCode))
		return nil
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	fd, err = pidfd.Open(uint32(init.Pid()), 0)
	if err != nil {
		if !errors.Is(err, syscall.ESRCH) {
			return err
		}
		goto set_exitedstatus
	}
	closeFD = true
	defer func() {
		if retErr != nil && closeFD {
			unix.Close(int(fd))
		}
	}()

	taskInfo, err = m.store.GetTracingTask(uint32(init.Pid()))
	if err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		goto set_exitedstatus
	}

	// Just in case, the pid has been reused by other init process
	if taskInfo != nil && taskInfo.TraceID == eventID {
		// TODO(fuweid): Ugly! Need interface here.
		init.initState.(*createdState).transition("running")

		return m.pidPoller.Add(fd, func() error {
			// TODO(fuweid): do we need to the pid value in event?
			exitedStatus, err = m.store.GetExitedEvent(init.traceEventID)
			if err != nil {
				init.SetExited(unexpectedExitCode)
				return fmt.Errorf("failed to get exited status: %w", err)
			}

			init.SetExited(int(exitedStatus.ExitCode))
			return nil
		})
	}

	unix.Close(int(fd))
	closeFD = false

set_exitedstatus:
	exitedStatus, err = m.store.GetExitedEvent(eventID)
	if err != nil {
		init.SetExited(unexpectedExitCode)
		return err
	}

	init.SetExited(int(exitedStatus.ExitCode))
	return nil
}

func getPidnsInfo(pid uint32) (exitsnoop.PidnsInfo, error) {
	f, err := os.Stat(filepath.Join("/proc", strconv.Itoa(int(pid)), "ns", "pid"))
	if err != nil {
		return exitsnoop.PidnsInfo{}, err
	}

	return exitsnoop.PidnsInfo{
		Dev: (f.Sys().(*syscall.Stat_t)).Dev,
		Ino: (f.Sys().(*syscall.Stat_t)).Ino,
	}, nil
}
