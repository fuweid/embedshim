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

		b, err := loadBundle(tm.stateDir, ns, id)
		if err != nil {
			return err
		}

		// fast path
		bf, err := ioutil.ReadDir(b.path)
		if err != nil {
			b.delete()
			log.G(ctx).WithError(err).Errorf("fast path read bundle path for %s", b.path)
			continue
		}

		if len(bf) == 0 {
			b.delete()
			continue
		}

		if _, err := tm.containers.Get(ctx, id); err != nil {
			log.G(ctx).WithError(err).Errorf("loading container %s", id)
			b.delete()
			continue
		}

		shim, err := tm.loadEmbedShim(ctx, b)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("loading exiting container %s", id)
			b.delete()
			continue
		}
		tm.tasks.Add(ctx, shim)
	}
	return nil
}

func (tm *TaskManager) loadEmbedShim(ctx context.Context, b *bundle) (_ *embedShim, retErr error) {
	init, err := reconstructInit(ctx, b)
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

	shim := newEmbedShim(tm, b)
	shim.init = init
	return shim, nil
}

func reconstructInit(ctx context.Context, b *bundle) (*Init, error) {
	rstdio, err := b.readInitStdio()
	if err != nil {
		return nil, err
	}

	pid, err := newPidFile(b.path).Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read container pidfile: %w", err)
	}

	runtime := NewRunc(
		"",
		filepath.Join(b.path, "work"),
		b.namespace,
		"", // use default runc
		"",
		false, // no systemd cgroup
	)

	p := NewInit(
		b.id,
		runtime,
		stdio.Stdio{
			Stdin:    rstdio.Stdin,
			Stdout:   rstdio.Stdout,
			Stderr:   rstdio.Stderr,
			Terminal: rstdio.Terminal,
		},
	)

	p.pid = pid
	p.Bundle = b.path
	p.Rootfs = filepath.Join(b.path, "rootfs")
	p.WorkDir = filepath.Join(b.path, "work")
	return p, nil
}
