package embedshim

import (
	"context"
	"fmt"
	"os"
	"time"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"

	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/runtime"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var deferCleanupTimeout = 30 * time.Second

type shim struct {
	manager *TaskManager

	bundle *pkgbundle.Bundle
	init   *initProcess
}

func newShim(manager *TaskManager, bundle *pkgbundle.Bundle) (*shim, error) {
	init, err := newInitProcess(bundle)
	if err != nil {
		return nil, err
	}

	return &shim{
		manager: manager,
		bundle:  bundle,
		init:    init,
	}, nil
}

func (s *shim) Create(ctx context.Context, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	rootfs := ""
	if len(opts.Rootfs) > 0 {
		rootfs = s.bundle.Rootfs()
		if err := os.Mkdir(rootfs, 0711); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}

	defer func() {
		if retErr != nil && rootfs != "" {
			if err := mount.UnmountAll(rootfs, 0); err != nil {
				logrus.WithError(err).Warn("failed to cleanup rootfs mount")
			}
		}
	}()

	for _, m := range opts.Rootfs {
		if err := m.Mount(rootfs); err != nil {
			return nil, fmt.Errorf("failed to mount rootfs component %v: %w", m, err)
		}
	}

	if err := s.init.Create(ctx); err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			deferCtx, deferCancel := deferContext()
			defer deferCancel()

			if derr := s.init.Delete(deferCtx); derr != nil {
				log.G(ctx).WithError(derr).Warnf("failed to clean %s in rollback", s.init)
			}
		}
	}()

	if err := s.manager.traceInitProcess(s.init); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *shim) ID() string {
	return s.bundle.ID
}

func (s *shim) PID() uint32 {
	return uint32(s.init.Pid())
}

func (s *shim) Namespace() string {
	return s.bundle.Namespace
}

func (s *shim) Pause(ctx context.Context) error {
	return fmt.Errorf("pause not implemented yet")
}

func (s *shim) Resume(ctx context.Context) error {
	return fmt.Errorf("resume not implemented yet")
}

func (s *shim) Start(ctx context.Context) error {
	return s.init.Start(ctx)
}

func (s *shim) Kill(ctx context.Context, signal uint32, all bool) error {
	return s.init.Kill(ctx, signal, all)
}

func (s *shim) Exec(ctx context.Context, id string, opts runtime.ExecOpts) (runtime.Process, error) {
	return nil, fmt.Errorf("exec not implemented yet")
}

func (s *shim) Pids(ctx context.Context) ([]runtime.ProcessInfo, error) {
	return []runtime.ProcessInfo{
		{Pid: s.PID()},
	}, nil
}

func (s *shim) ResizePty(ctx context.Context, size runtime.ConsoleSize) error {
	return s.init.Resize(console.WinSize{
		Width:  uint16(size.Width),
		Height: uint16(size.Height),
	})
}

func (s *shim) CloseIO(ctx context.Context) error {
	if stdin := s.init.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *shim) Wait(ctx context.Context) (*runtime.Exit, error) {
	taskPid := s.PID()

	// TODO: use ctx
	s.init.Wait()

	return &runtime.Exit{
		Pid:       taskPid,
		Timestamp: s.init.ExitedAt(),
		Status:    uint32(s.init.ExitStatus()),
	}, nil
}

func (s *shim) Checkpoint(ctx context.Context, path string, options *ptypes.Any) error {
	return fmt.Errorf("checkpoint not implemented yet")
}

func (s *shim) Close() error {
	return nil
}

func (s *shim) Update(ctx context.Context, resources *ptypes.Any, _ map[string]string) error {
	return s.init.Update(ctx, resources)
}

func (s *shim) Stats(ctx context.Context) (*ptypes.Any, error) {
	return nil, fmt.Errorf("Stats not implemented yet")
}

func (s *shim) Process(ctx context.Context, id string) (runtime.Process, error) {
	if s.bundle.ID != id {
		return nil, fmt.Errorf("exec %s: %w", id, errdefs.ErrNotFound)
	}

	if _, err := s.init.Status(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *shim) State(ctx context.Context) (runtime.State, error) {
	st, err := s.init.Status(ctx)
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
		Pid:        uint32(s.init.pid),
		Status:     status,
		Stdin:      s.init.stdio.Stdin,
		Stdout:     s.init.stdio.Stdout,
		Stderr:     s.init.stdio.Stderr,
		Terminal:   s.init.stdio.Terminal,
		ExitStatus: uint32(s.init.ExitStatus()),
		ExitedAt:   s.init.ExitedAt(),
	}, nil
}

func (s *shim) Delete(ctx context.Context) (*runtime.Exit, error) {
	err := s.init.Delete(ctx)
	if err != nil && !errors.Is(err, errdefs.ErrNotFound) {
		return nil, err
	}

	if err := s.bundle.Delete(); err != nil {
		return nil, err
	}

	s.manager.cleanInitProcessTraceEvent(s.init)
	s.manager.Delete(ctx, s.init.ID())

	return &runtime.Exit{
		Pid:       uint32(s.init.pid),
		Status:    uint32(s.init.ExitStatus()),
		Timestamp: s.init.ExitedAt(),
	}, nil
}

func deferContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.TODO(), deferCleanupTimeout)
}
