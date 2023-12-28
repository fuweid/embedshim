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
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"

	"github.com/containerd/console"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/fifo"
	"github.com/containerd/go-runc"
	google_protobuf "github.com/gogo/protobuf/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

type initProcess struct {
	parent *shim

	initState initState
	bundle    *pkgbundle.Bundle

	runtime      *runc.Runc
	options      *options.Options
	traceEventID uint64

	wg sync.WaitGroup

	waitBlock chan struct{}

	stdio    stdio.Stdio
	console  console.Console
	platform stdio.Platform // TODO: as shim level instead of initProcess
	io       *processIO
	stdin    io.Closer
	closers  []io.Closer

	mu     sync.Mutex
	status int
	exited time.Time
	pid    int
}

func newInitProcess(bundle *pkgbundle.Bundle) (_ *initProcess, retErr error) {
	opts, err := readInitOptions(bundle)
	if err != nil {
		return nil, err
	}

	initIO, err := readInitStdio(bundle)
	if err != nil {
		return nil, err
	}

	eventID, err := readInitTraceEventID(bundle)
	if err != nil {
		return nil, err
	}

	platform, err := NewPlatform()
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			platform.Close()
		}
	}()

	runtime := newRuncRuntime(
		opts.Root,                          // for working dir
		filepath.Join(bundle.Path, "work"), // for log.json
		bundle.Namespace,                   // for isolation
		opts.BinaryName,                    // other implementation, like crun, youki
		"",
		opts.SystemdCgroup, // use systemd's cgroup
	)

	p := &initProcess{
		bundle:       bundle,
		options:      opts,
		traceEventID: eventID,
		runtime:      runtime,
		stdio: stdio.Stdio{
			Stdin:    initIO.Stdin,
			Stdout:   initIO.Stdout,
			Stderr:   initIO.Stderr,
			Terminal: initIO.Terminal,
		},
		status:    0,
		platform:  platform,
		waitBlock: make(chan struct{}),
	}
	p.initState = &createdState{p: p}
	return p, nil
}

func (p *initProcess) Create(ctx context.Context) (retErr error) {
	var (
		err     error
		socket  *runc.Socket
		pio     *processIO
		pidFile = newInitPidFile(p.bundle)

		ioUID = int(p.options.IoUid)
		ioGID = int(p.options.IoGid)
	)

	// TODO(fuweid):
	//
	// Terminal console poller should be shared in plugin Level.
	if p.stdio.Terminal {
		if socket, err = runc.NewTempConsoleSocket(); err != nil {
			return fmt.Errorf("failed to create OCI runtime console socket: %w", err)
		}
		defer socket.Close()
	} else {
		if pio, err = createIO(ctx, p.ID(), ioUID, ioGID, p.stdio); err != nil {
			return fmt.Errorf("failed to create init process I/O: %w", err)
		}
		p.io = pio
	}

	opts := &runc.CreateOpts{
		PidFile:      pidFile.Path(),
		NoPivot:      p.options.NoPivotRoot,
		NoNewKeyring: p.options.NoNewKeyring,
	}
	if p.io != nil {
		opts.IO = p.io.IO()
	}
	if socket != nil {
		opts.ConsoleSocket = socket
	}

	if err := p.runtime.Create(ctx, p.ID(), p.bundle.Path, opts); err != nil {
		return p.runtimeError(err, "OCI runtime create failed")
	}

	if p.stdio.Stdin != "" {
		if err := p.openStdin(p.stdio.Stdin); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if socket != nil {
		console, err := socket.ReceiveMaster()
		if err != nil {
			return fmt.Errorf("failed to retrieve console master: %w", err)
		}

		console, err = p.platform.CopyConsole(ctx, console, p.ID(), p.stdio.Stdin, p.stdio.Stdout, p.stdio.Stderr, &p.wg)
		if err != nil {
			return fmt.Errorf("failed to start console copy: %w", err)
		}
		p.console = console
	} else {
		// NOTE: There is no stdout/stderr copy because we open Read-Write
		// fifo as init process's stdout/stderr. Unlike the shim server's
		// pipe, the containerd restarts without closing the init process
		// stdout/stderr so that it is easy to recover.
		//
		// But the stdin still needs pipe as relay because we need to
		// notify the init process that the stdin has been closed, like
		//
		// 	echo "hello, world" | cat
		//
		// So, for the init process which needs stdin, we can't recover
		// the stdin after containerd restart, A.K.A we can't re-attach
		// to stdin.
		//
		// This embedshim plugin can't cover 100% cases from shim server,
		// but in producation, most of workloads are headless. The stdin
		// is used to debug or exec operations job. I think it is acceptable :P.
		if err := pio.CopyStdin(); err != nil {
			return fmt.Errorf("failed to start io pipe copy: %w", err)
		}
	}

	pid, err := pidFile.Read()
	if err != nil {
		return fmt.Errorf("failed to retrieve OCI runtime container pid: %w", err)
	}
	p.pid = pid
	return nil
}

func (p *initProcess) openStdin(path string) error {
	sc, err := fifo.OpenFifo(context.Background(), path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("failed to open stdin fifo %s: %w", path, err)
	}

	p.stdin = sc
	p.closers = append(p.closers, sc)
	return nil
}

// Wait for the process to exit
func (p *initProcess) Wait() {
	<-p.waitBlock
}

// ID of the process
func (p *initProcess) ID() string {
	return p.bundle.ID
}

// Pid of the process
func (p *initProcess) Pid() int {
	return p.pid
}

// exitStatus of the process
func (p *initProcess) ExitStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.status
}

// ExitedAt at time when the process exited
func (p *initProcess) ExitedAt() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.exited
}

// Status of the process
func (p *initProcess) Status(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Status(ctx)
}

// Start the init process
func (p *initProcess) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Start(ctx)
}

func (p *initProcess) start(ctx context.Context) error {
	err := p.runtime.Start(ctx, p.ID())
	return p.runtimeError(err, "OCI runtime start failed")
}

// SetExited of the init process with the next status
func (p *initProcess) SetExited(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.initState.SetExited(status)
}

func (p *initProcess) setExited(status int) {
	p.exited = time.Now()
	p.status = unix.WaitStatus(status).ExitStatus()
	if p.platform != nil {
		p.platform.ShutdownConsole(context.Background(), p.console)

		p.platform.Close()
		p.platform = nil
	}
	close(p.waitBlock)
}

// Delete the init process
func (p *initProcess) Delete(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Delete(ctx)
}

func (p *initProcess) delete(ctx context.Context) error {
	waitTimeout(ctx, &p.wg, 2*time.Second)
	err := p.runtime.Delete(ctx, p.ID(), nil)
	// ignore errors if a runtime has already deleted the process
	// but we still hold metadata and pipes
	//
	// this is common during a checkpoint, runc will delete the container state
	// after a checkpoint and the container will no longer exist within runc
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			err = nil
		} else {
			err = p.runtimeError(err, "failed to delete task")
		}
	}
	if p.io != nil {
		for _, c := range p.closers {
			c.Close()
		}
		p.io.Close()
	}

	rootfs := p.bundle.Rootfs()
	if err2 := mount.UnmountAll(rootfs, 0); err2 != nil {
		log.G(ctx).WithError(err2).Warn("failed to cleanup rootfs mount")
		if err == nil {
			err = fmt.Errorf("failed rootfs umount: %w", err)
		}
	}
	return err
}

// Resize the init processes console
func (p *initProcess) Resize(ws console.WinSize) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.console == nil {
		return nil
	}
	return p.console.Resize(ws)
}

// Pause the init process and all its child processes
func (p *initProcess) Pause(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Pause(ctx)
}

// Resume the init process and all its child processes
func (p *initProcess) Resume(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Resume(ctx)
}

// Kill the init process
func (p *initProcess) Kill(ctx context.Context, signal uint32, all bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Kill(ctx, signal, all)
}

func (p *initProcess) kill(ctx context.Context, signal uint32, all bool) error {
	err := p.runtime.Kill(ctx, p.ID(), int(signal), &runc.KillOpts{
		All: all,
	})
	return checkKillError(err)
}

// KillAll processes belonging to the init process
func (p *initProcess) KillAll(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	err := p.runtime.Kill(ctx, p.ID(), int(unix.SIGKILL), &runc.KillOpts{
		All: true,
	})
	return p.runtimeError(err, "OCI runtime killall failed")
}

// Stdin of the process
func (p *initProcess) Stdin() io.Closer {
	return p.stdin
}

// Runtime returns the OCI runtime configured for the init process
func (p *initProcess) Runtime() *runc.Runc {
	return p.runtime
}

// Exec returns a new child process
func (p *initProcess) Exec(ctx context.Context, execID string, opts runtime.ExecOpts) (runtime.Process, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Exec(ctx, execID, opts)
}

func (p *initProcess) exec(ctx context.Context, execID string, opts runtime.ExecOpts) (runtime.Process, error) {
	traceID := traceIDFromContext(ctx)

	// process exec request
	var spec specs.Process
	if err := json.Unmarshal(opts.Spec.Value, &spec); err != nil {
		return nil, err
	}

	spec.Terminal = opts.IO.Terminal
	e := &execProcess{
		parent:       p,
		id:           execID,
		traceEventID: traceID,

		spec: spec,
		stdio: stdio.Stdio{
			Stdin:    opts.IO.Stdin,
			Stdout:   opts.IO.Stdout,
			Stderr:   opts.IO.Stderr,
			Terminal: opts.IO.Terminal,
		},
		waitBlock: make(chan struct{}),
	}
	e.execState = &execCreatedState{p: e}
	return e, nil
}

// Checkpoint the init process
func (p *initProcess) Checkpoint(_ context.Context, _ *CheckpointConfig) error {
	return fmt.Errorf("checkpoint not implemented yet")
}

// Update the processes resource configuration
func (p *initProcess) Update(ctx context.Context, r *google_protobuf.Any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Update(ctx, r)
}

func (p *initProcess) update(ctx context.Context, r *google_protobuf.Any) error {
	var resources specs.LinuxResources
	if err := json.Unmarshal(r.Value, &resources); err != nil {
		return err
	}
	return p.runtime.Update(ctx, p.ID(), &resources)
}

// Stdio of the process
func (p *initProcess) Stdio() stdio.Stdio {
	return p.stdio
}

func (p *initProcess) runtimeError(rErr error, msg string) error {
	if rErr == nil {
		return nil
	}

	rMsg, err := getLastRuntimeError(p.runtime)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %s (%s)", msg, "unable to retrieve OCI runtime error", err.Error())
	case rMsg == "":
		return rErr
	default:
		return fmt.Errorf("%s: %s", msg, rMsg)
	}
}

func (p *initProcess) String() string {
	return fmt.Sprintf("init process(id=%v, namespace=%v)", p.ID(), p.bundle.Namespace)
}

// waitTimeout handles waiting on a waitgroup with a specified timeout.
// this is commonly used for waiting on IO to finish after a process has exited
func waitTimeout(ctx context.Context, wg *sync.WaitGroup, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
