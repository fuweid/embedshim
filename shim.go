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
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type embedShim struct {
	tm *TaskManager

	bundle *Bundle
	ropts  *options.Options
	init   *Init
}

func newEmbedShim(tm *TaskManager, bundle *Bundle) *embedShim {
	return &embedShim{
		tm:     tm,
		bundle: bundle,
		ropts:  &options.Options{},
	}
}

func (es *embedShim) Create(ctx context.Context, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	rootfs := ""
	if len(opts.Rootfs) > 0 {
		rootfs = filepath.Join(es.bundle.Path, "rootfs")
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

	p, err := es.newInit(ctx, rootfs, opts)
	if err != nil {
		return nil, err
	}

	if err := p.Create(ctx); err != nil {
		return nil, err
	}
	es.init = p
	return es, nil
}

func (es *embedShim) ID() string {
	return es.bundle.ID
}

func (es *embedShim) PID() uint32 {
	return uint32(es.init.Pid())
}

func (es *embedShim) Namespace() string {
	return es.bundle.Namespace
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
		runtime.ProcessInfo{
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
	if es.bundle.ID != id {
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
	case "paused":
		status = runtime.PausedStatus
	case "pausing":
		status = runtime.PausingStatus
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

	if err := es.bundle.Delete(); err != nil {
		return nil, err
	}

	// TODO: reconstruct the cleanup-resource
	tid, _ := es.tm.monitor.idr.getID(es.bundle.Namespace, es.bundle.ID)
	es.tm.monitor.idr.releaseID(es.bundle.Namespace, es.bundle.ID)
	es.tm.monitor.store.DelExitedTask(tid)
	es.tm.Delete(ctx, es.init.id)
	return &runtime.Exit{
		Pid:       uint32(es.init.pid),
		Status:    uint32(es.init.ExitStatus()),
		Timestamp: es.init.ExitedAt(),
	}, nil
}

func (es *embedShim) newInit(ctx context.Context, rootfs string, opts runtime.CreateOpts) (*Init, error) {
	runtime := NewRunc(
		"",
		filepath.Join(es.bundle.Path, "work"),
		es.bundle.Namespace,
		"", // use default runc
		"",
		false, // no systemd cgroup
	)

	p := NewInit(
		es.bundle.ID,
		runtime,
		stdio.Stdio{
			Stdin:    opts.IO.Stdin,
			Stdout:   opts.IO.Stdout,
			Stderr:   opts.IO.Stderr,
			Terminal: opts.IO.Terminal,
		},
	)

	p.Bundle = es.bundle.Path
	p.Rootfs = rootfs
	p.WorkDir = filepath.Join(es.bundle.Path, "work")
	p.IoUID = int(es.ropts.IoUid)
	p.IoGID = int(es.ropts.IoGid)
	return p, nil
}
