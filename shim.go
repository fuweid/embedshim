package embedshim

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"

	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type embedShim struct {
	tm *TaskManager

	b     *pkgbundle.Bundle
	ropts *options.Options
	init  *initProcess
}

func newEmbedShim(tm *TaskManager, b *pkgbundle.Bundle) *embedShim {
	return &embedShim{
		tm:    tm,
		b:     b,
		ropts: &options.Options{},
	}
}

func (es *embedShim) Create(ctx context.Context, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	rootfs := ""
	if len(opts.Rootfs) > 0 {
		rootfs = filepath.Join(es.b.Path, "rootfs")
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

	p, err := es.newInit()
	if err != nil {
		return nil, err
	}

	if err := p.Create(ctx); err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			// TODO(fuweid): use defer context like CRI plugin
			p.Delete(ctx)
		}
	}()

	if err := es.tm.monitor.traceInitProcess(p); err != nil {
		return nil, err
	}
	es.init = p
	return es, nil
}

func (es *embedShim) ID() string {
	return es.b.ID
}

func (es *embedShim) PID() uint32 {
	return uint32(es.init.Pid())
}

func (es *embedShim) Namespace() string {
	return es.b.Namespace
}

func (es *embedShim) Pause(ctx context.Context) error {
	return fmt.Errorf("pause not implemented yet")
}

func (es *embedShim) Resume(ctx context.Context) error {
	return fmt.Errorf("resume not implemented yet")
}

func (es *embedShim) Start(ctx context.Context) error {
	return es.init.Start(ctx)
}

func (es *embedShim) Kill(ctx context.Context, signal uint32, all bool) error {
	return es.init.Kill(ctx, signal, all)
}

func (es *embedShim) Exec(ctx context.Context, id string, opts runtime.ExecOpts) (runtime.Process, error) {
	return nil, fmt.Errorf("exec not implemented yet")
}

func (es *embedShim) Pids(ctx context.Context) ([]runtime.ProcessInfo, error) {
	return []runtime.ProcessInfo{
		{
			Pid: es.PID(),
		},
	}, nil
}

func (es *embedShim) ResizePty(ctx context.Context, size runtime.ConsoleSize) error {
	return es.init.Resize(console.WinSize{
		Width:  uint16(size.Width),
		Height: uint16(size.Height),
	})
}

func (es *embedShim) CloseIO(ctx context.Context) error {
	if stdin := es.init.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (es *embedShim) Wait(ctx context.Context) (*runtime.Exit, error) {
	taskPid := es.PID()

	// TODO: use ctx
	es.init.Wait()

	return &runtime.Exit{
		Pid:       taskPid,
		Timestamp: es.init.ExitedAt(),
		Status:    uint32(es.init.ExitStatus()),
	}, nil
}

func (es *embedShim) Checkpoint(ctx context.Context, path string, options *ptypes.Any) error {
	return fmt.Errorf("checkpoint not implemented yet")
}

func (es *embedShim) Close() error {
	return nil
}

func (es *embedShim) Update(ctx context.Context, resources *ptypes.Any, _ map[string]string) error {
	return es.init.Update(ctx, resources)
}

func (es *embedShim) Stats(ctx context.Context) (*ptypes.Any, error) {
	return nil, fmt.Errorf("Stats not implemented yet")
}

func (es *embedShim) Process(ctx context.Context, id string) (runtime.Process, error) {
	if es.b.ID != id {
		return nil, fmt.Errorf("exec %s: %w", id, errdefs.ErrNotFound)
	}
	if _, err := es.init.Status(ctx); err != nil {
		return nil, err
	}
	return es, nil
}

func (es *embedShim) State(ctx context.Context) (runtime.State, error) {
	st, err := es.init.Status(ctx)
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
		Pid:        uint32(es.init.pid),
		Status:     status,
		Stdin:      es.init.stdio.Stdin,
		Stdout:     es.init.stdio.Stdout,
		Stderr:     es.init.stdio.Stderr,
		Terminal:   es.init.stdio.Terminal,
		ExitStatus: uint32(es.init.ExitStatus()),
		ExitedAt:   es.init.ExitedAt(),
	}, nil
}

func (es *embedShim) Delete(ctx context.Context) (*runtime.Exit, error) {
	err := es.init.Delete(ctx)
	if err != nil && !errors.Is(err, errdefs.ErrNotFound) {
		return nil, err
	}

	if err := es.b.Delete(); err != nil {
		return nil, err
	}

	// TODO: reconstruct the cleanup-resource
	es.tm.monitor.store.DelExitedTask(es.init.traceEventID)
	es.tm.Delete(ctx, es.init.ID())
	return &runtime.Exit{
		Pid:       uint32(es.init.pid),
		Status:    uint32(es.init.ExitStatus()),
		Timestamp: es.init.ExitedAt(),
	}, nil
}

func (es *embedShim) newInit() (*initProcess, error) {
	return newInitProcess(es.b)
}
