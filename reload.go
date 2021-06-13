package embedshim

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/stdio"
)

func (tm *TaskManager) reloadExistingTasks(ctx context.Context) error {
	nsDirs, err := ioutil.ReadDir(tm.stateDir)
	if err != nil {
		return err
	}

	for _, nsd := range nsDirs {
		if !nsd.IsDir() {
			continue
		}

		ns := nsd.Name()
		if len(ns) > 0 && ns[0] == '.' {
			continue
		}

		log.G(ctx).WithField("namespace", ns).Info("loading tasks in namespace")
		if err := tm.loadTasks(namespaces.WithNamespace(ctx, ns)); err != nil {
			log.G(ctx).WithField("namespace", ns).WithError(err).Error("loading tasks in namespace")
			continue
		}
	}
	return nil
}

func (tm *TaskManager) loadTasks(ctx context.Context) error {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}

	shimDirs, err := ioutil.ReadDir(filepath.Join(tm.stateDir, ns))
	if err != nil {
		return err
	}

	for _, sd := range shimDirs {
		if !sd.IsDir() {
			continue
		}

		id := sd.Name()
		if len(id) > 0 && id[0] == '.' {
			continue
		}

		bundle, err := LoadBundle(ctx, tm.stateDir, id)
		if err != nil {
			return err
		}

		// fast path
		bf, err := ioutil.ReadDir(bundle.Path)
		if err != nil {
			bundle.Delete()
			log.G(ctx).WithError(err).Errorf("fast path read bundle path for %s", bundle.Path)
			continue
		}

		if len(bf) == 0 {
			bundle.Delete()
			continue
		}

		if _, err := tm.containers.Get(ctx, id); err != nil {
			log.G(ctx).WithError(err).Errorf("loading container %s", id)
			bundle.Delete()
			continue
		}

		shim, err := tm.loadEmbedShim(ctx, bundle)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("loading exiting container %s", id)
			bundle.Delete()
			continue
		}
		tm.tasks.Add(ctx, shim)
	}
	return nil
}

func (tm *TaskManager) loadEmbedShim(ctx context.Context, bundle *Bundle) (_ *embedShim, retErr error) {
	init, err := reconstructInit(ctx, bundle)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			init.Delete(ctx)
		}
	}()

	if err := tm.monitor.resubscribe(ctx, init); err != nil {
		return nil, err
	}

	shim := newEmbedShim(tm, bundle)
	shim.init = init
	return shim, nil
}

func reconstructInit(ctx context.Context, bundle *Bundle) (*Init, error) {
	ioFile := newIospecFile(bundle.Path)
	iospec, err := ioFile.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read container iospec: %w", err)
	}

	pid, err := newPidFile(bundle.Path).Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read container pidfile: %w", err)
	}

	runtime := NewRunc(
		"",
		filepath.Join(bundle.Path, "work"),
		bundle.Namespace,
		"", // use default runc
		"",
		false, // no systemd cgroup
	)

	p := NewInit(
		bundle.ID,
		runtime,
		stdio.Stdio{
			Stdin:    iospec.Stdin,
			Stdout:   iospec.Stdout,
			Stderr:   iospec.Stderr,
			Terminal: iospec.Terminal,
		},
	)

	p.pid = pid
	p.Bundle = bundle.Path
	p.Rootfs = filepath.Join(bundle.Path, "rootfs")
	p.WorkDir = filepath.Join(bundle.Path, "work")
	return p, nil
}
