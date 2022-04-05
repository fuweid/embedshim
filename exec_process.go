/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package embedshim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/fuweid/embedshim/pkg/exitsnoop"
	"github.com/fuweid/embedshim/pkg/pidfd"
	"github.com/fuweid/embedshim/pkg/runcext"

	"github.com/cilium/ebpf"
	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/fifo"
	runc "github.com/containerd/go-runc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

type execProcess struct {
	parent *initProcess

	id           string
	traceEventID uint64
	spec         specs.Process
	execState    execState

	wg sync.WaitGroup

	waitBlock chan struct{}

	stdio   stdio.Stdio
	console console.Console
	io      *processIO
	stdin   io.Closer
	closers []io.Closer

	mu     sync.Mutex
	status int
	exited time.Time
	pid    safePid
	pidFD  pidfd.FD
}

func (e *execProcess) ID() string {
	return e.id
}

func (e *execProcess) Pid() int {
	return e.pid.get()
}

func (e *execProcess) ExitStatus() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.status
}

func (e *execProcess) ExitedAt() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.exited
}

func (e *execProcess) SetExited(status int) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.execState.SetExited(status)
}

func (e *execProcess) setExited(status int) {
	e.status = unix.WaitStatus(status).ExitStatus()
	e.exited = time.Now()

	if e.parent.platform != nil {
		e.parent.platform.ShutdownConsole(context.Background(), e.console)
	}
	close(e.waitBlock)
}

func (e *execProcess) CloseIO(ctx context.Context) error {
	if stdin := e.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (e *execProcess) Wait(ctx context.Context) (*runtime.Exit, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.waitBlock:
		return &runtime.Exit{
			Pid:       uint32(e.Pid()),
			Status:    uint32(e.ExitStatus()),
			Timestamp: e.ExitedAt(),
		}, nil
	}
}

func (e *execProcess) State(ctx context.Context) (runtime.State, error) {
	st, err := e.Status(ctx)
	if err != nil {
		return runtime.State{}, err
	}

	status := runtime.Status(0) // Unknown
	switch st {
	case "created":
		status = runtime.CreatedStatus
	case "running":
		status = runtime.RunningStatus
	case "stopped":
		status = runtime.StoppedStatus
	}
	return runtime.State{
		Pid:        uint32(e.Pid()),
		Status:     status,
		Stdin:      e.stdio.Stdin,
		Stdout:     e.stdio.Stdout,
		Stderr:     e.stdio.Stderr,
		Terminal:   e.stdio.Terminal,
		ExitStatus: uint32(e.ExitStatus()),
		ExitedAt:   e.ExitedAt(),
	}, nil
}

func (e *execProcess) Delete(ctx context.Context) (*runtime.Exit, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.execState.Delete(ctx); err != nil {
		return nil, err
	}

	e.shim().deleteExecProcess(e.id)
	return &runtime.Exit{
		Pid:       uint32(e.Pid()),
		Status:    uint32(e.status),
		Timestamp: e.exited,
	}, nil
}

func (e *execProcess) delete(ctx context.Context) error {
	waitTimeout(ctx, &e.wg, 2*time.Second)

	if e.io != nil {
		e.io.Close()
	}
	for _, c := range e.closers {
		c.Close()
	}

	// silently ignore error
	os.Remove(e.pidFilePath())
	os.Remove(e.processJSONPath())
	return nil
}

func (e *execProcess) ResizePty(_ context.Context, size runtime.ConsoleSize) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Resize(console.WinSize{
		Width:  uint16(size.Width),
		Height: uint16(size.Height),
	})
}

func (e *execProcess) resize(ws console.WinSize) error {
	if e.console == nil {
		return nil
	}

	return e.console.Resize(ws)
}

func (e *execProcess) Kill(ctx context.Context, sig uint32, _ bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Kill(ctx, sig, false)
}

func (e *execProcess) kill(ctx context.Context, sig uint32, _ bool) error {
	pid := e.pid.get()
	switch {
	case pid == 0:
		return fmt.Errorf("process not created: %w", errdefs.ErrFailedPrecondition)
	case !e.exited.IsZero():
		return fmt.Errorf("process already finished: %w", errdefs.ErrNotFound)
	default:
		if err := e.pidFD.SendSignal(syscall.Signal(sig), 0); err != nil {
			return fmt.Errorf("exec kill error: %w", checkKillError(err))
		}
	}
	return nil
}

func (e *execProcess) Stdin() io.Closer {
	return e.stdin
}

func (e *execProcess) Stdio() stdio.Stdio {
	return e.stdio
}

func (e *execProcess) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.execState.Start(ctx)
}

func (e *execProcess) start(ctx context.Context) (retErr error) {
	// The reaper may receive exit signal right after
	// the container is started, before the e.pid is updated.
	// In that case, we want to block the signal handler to
	// access e.pid until it is updated.
	e.pid.Lock()
	defer e.pid.Unlock()

	var (
		socket *runc.Socket
		pio    *processIO

		ioUID = int(e.parent.options.IoUid)
		ioGID = int(e.parent.options.IoGid)

		err error
	)

	if e.stdio.Terminal {
		if socket, err = runc.NewTempConsoleSocket(); err != nil {
			return fmt.Errorf("failed to create runc console socket: %w", err)
		}
		defer socket.Close()
	} else {
		// FIXME(fuweid):
		//
		// Maybe we should use pipe as relay for exec process, because
		// it should be short-live process. And just in case that
		// the buffer of fifo by UID will be filled with the log.
		if pio, err = createIO(ctx, e.id, ioUID, ioGID, e.stdio); err != nil {
			return fmt.Errorf("failed to create exec process I/O: %w", err)
		}
		e.io = pio
	}

	opts := &runc.ExecOpts{
		PidFile: e.pidFilePath(),
		Detach:  true,
	}
	if pio != nil {
		opts.IO = pio.IO()
	}
	if socket != nil {
		opts.ConsoleSocket = socket
	}

	invokeErr := e.invokeRuncExec(ctx, opts, func(syncPipe *os.File) (retErr error) {
		var (
			execPid uint32
			pidFD   pidfd.FD
			done    bool
			err     error

			pidMonitor    = e.pidMonitor()
			execExitStore = pidMonitor.execStore
		)

		defer func() {
			if retErr != nil {
				if pidFD != 0 {
					unix.Close(int(pidFD))
				}

				e.pid.pid = 0
				e.pidFD = 0
			}
		}()

		syncErr := runcext.ParseProcSync(syncPipe, func(msg *runcext.ProcSync) error {
			switch msg.Type {
			case runcext.ProcSyncExecPid:
				if err = e.handleIOAfterExec(ctx, pio, socket); err != nil {
					return err
				}

				err = func() (retErr error) {
					pidMonitor.Lock()
					defer pidMonitor.Unlock()

					execPid = msg.Pid

					nsInfo, err := getPidnsInfo(execPid)
					if err != nil {
						return err
					}

					pidFD, err = pidfd.Open(execPid, 0)
					if err != nil {
						return err
					}

					defer func() {
						if retErr != nil {
							unix.Close(int(pidFD))
						}
					}()

					return execExitStore.Trace(execPid,
						&exitsnoop.TaskInfo{
							TraceID:   e.traceEventID,
							PidnsInfo: nsInfo,
						},
					)
				}()
				if err != nil {
					return err
				}
				return runcext.WriteProcSyncMessage(syncPipe, runcext.NewProcSyncExecPidDoneMessage())

			case runcext.ProcSyncExecStatus:
				err = func() error {
					if !msg.Exited {
						return nil
					}

					pidMonitor.Lock()
					defer pidMonitor.Unlock()

					taskInfo, err := execExitStore.GetTracingTask(execPid)
					if err == nil && taskInfo.TraceID == e.traceEventID {
						err = execExitStore.DeleteTracingTask(execPid)
					}

					if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						return err
					}

					return execExitStore.ExitedEventFromWaitStatus(e.traceEventID, execPid, msg.ExitedStatus)
				}()
				if err != nil {
					return err
				}

				done = true

				return runcext.WriteProcSyncMessage(syncPipe, runcext.NewProcSyncExecStatusDoneMessage())
			default:
				return fmt.Errorf("unexpected message: %+v", msg)
			}
		})
		syncPipe.Close()

		if syncErr != nil {
			return syncErr
		}
		if !done {
			return fmt.Errorf("unexpected to abort sync from child side")
		}

		e.pid.pid = int(execPid)
		e.pidFD = pidFD
		return pidMonitor.pidPoller.Add(pidFD, func() error {
			execPid := e.Pid()

			status := 255

			event, err := execExitStore.GetExitedEvent(e.traceEventID)
			if err == nil && event.Pid == uint32(execPid) {
				status = int(event.ExitCode)
			}
			execExitStore.DeleteExitedEvent(e.traceEventID)

			e.SetExited(status)
			return nil
		})
	})
	if invokeErr != nil {
		close(e.waitBlock)
		return e.parent.runtimeError(err, "OCI runtime exec failed")
	}
	return nil
}

func (e *execProcess) handleIOAfterExec(ctx context.Context, pio *processIO, socket *runc.Socket) error {
	if e.stdio.Stdin != "" {
		if err := e.openStdin(e.stdio.Stdin); err != nil {
			return err
		}
	}

	if socket != nil {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		console, err := socket.ReceiveMaster()
		if err != nil {
			return fmt.Errorf("failed to retrieve console master: %w", err)
		}

		if e.console, err = e.parent.platform.CopyConsole(ctx, console, e.id, e.stdio.Stdin, e.stdio.Stdout, e.stdio.Stderr, &e.wg); err != nil {
			return fmt.Errorf("failed to start console copy: %w", err)
		}
	} else {
		if err := pio.CopyStdin(); err != nil {
			return fmt.Errorf("failed to start io pipe copy: %w", err)
		}
	}
	return nil
}

func (e *execProcess) invokeRuncExec(ctx context.Context, opts *runc.ExecOpts, syncFn func(syncPipe *os.File) error) (retErr error) {
	processJSON := e.processJSONPath()
	stdioFDCnt := 3

	specF, err := os.Create(processJSON)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", processJSON, err)
	}
	defer os.Remove(processJSON)

	err = json.NewEncoder(specF).Encode(e.spec)
	specF.Close()
	if err != nil {
		return fmt.Errorf("failed to encode process.json: %w", err)
	}

	parentSyncPipe, childSyncPipe, err := runcext.NewSocketPair("exec-" + e.id)
	if err != nil {
		return fmt.Errorf("failed to init sync pipe: %w", err)
	}
	defer func() {
		parentSyncPipe.Close()
		childSyncPipe.Close()
	}()

	args := []string{"exec", "--process", processJSON}
	oargs, err := runcext.RuncExecOptsArgs(opts)
	if err != nil {
		return err
	}
	args = append(args, oargs...)

	execCmd := runcext.RuntimeCommand(ctx, true, e.parent.runtime, append(args, e.parent.ID())...)

	execCmd.ExtraFiles = append(execCmd.ExtraFiles, childSyncPipe)
	execCmd.Env = append(execCmd.Env,
		runcext.EnvNameProcSyncPipe+"="+strconv.Itoa(stdioFDCnt+len(execCmd.ExtraFiles)-1))

	if opts.IO != nil {
		opts.Set(execCmd)
	}

	if err := execCmd.Start(); err != nil {
		return fmt.Errorf("failed to start runc-exec ext: %w", err)
	}
	childSyncPipe.Close()

	waited := false
	defer func() {
		if retErr != nil && !waited {
			execCmd.Process.Kill()
			execCmd.Wait()
		}
	}()

	if opts.IO != nil {
		if c, ok := opts.IO.(runc.StartCloser); ok {
			if err := c.CloseAfterStart(); err != nil {
				return fmt.Errorf("failed to close io after start: %w", err)
			}
		}
	}

	errCh := make(chan error, 1)

	go func() (retErr error) {
		defer func() {
			if retErr != nil {
				errCh <- retErr
			}
			close(errCh)
		}()

		return syncFn(parentSyncPipe)
	}()

	err = execCmd.Wait()
	waited = true

	if err1 := <-errCh; err == nil {
		err = err1
	}
	return err
}

func (e *execProcess) Status(ctx context.Context) (string, error) {
	s, err := e.parent.Status(ctx)
	if err != nil {
		return "", err
	}

	// if the container as a whole is in the pausing/paused state, so are all
	// other processes inside the container, use container state here
	switch s {
	case "paused", "pausing":
		return s, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	return e.execState.Status(ctx)
}

func (e *execProcess) pidFilePath() string {
	return filepath.Join(e.parent.bundle.Path, fmt.Sprintf("%s.pid", e.id))
}

func (e *execProcess) processJSONPath() string {
	return filepath.Join(e.parent.bundle.Path, fmt.Sprintf("%s.json", e.id))
}

func (e *execProcess) pidMonitor() *monitor {
	return e.parent.parent.manager.monitor
}

func (e *execProcess) shim() *shim {
	return e.parent.parent
}

func (e *execProcess) openStdin(path string) error {
	sc, err := fifo.OpenFifo(context.Background(), path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("failed to open stdin fifo %s: %w", path, err)
	}

	e.stdin = sc
	e.closers = append(e.closers, sc)
	return nil
}

// safePid is a thread safe wrapper for pid.
type safePid struct {
	sync.Mutex
	pid int
}

func (s *safePid) get() int {
	s.Lock()
	defer s.Unlock()
	return s.pid
}
