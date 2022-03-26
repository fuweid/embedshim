package embedshim

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"

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

		b, err := pkgbundle.LoadBundle(tm.stateDir, ns, id)
		if err != nil {
			return err
		}

		// fast path
		bf, err := ioutil.ReadDir(b.Path)
		if err != nil {
			b.Delete()
			log.G(ctx).WithError(err).Errorf("fast path read bundle path for %s", b.Path)
			continue
		}

		if len(bf) == 0 {
			b.Delete()
			continue
		}

		if _, err := tm.containers.Get(ctx, id); err != nil {
			log.G(ctx).WithError(err).Errorf("loading container %s", id)
			b.Delete()
			continue
		}

		shim, err := tm.loadEmbedShim(ctx, b)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("loading exiting container %s", id)
			b.Delete()
			continue
		}
		tm.tasks.Add(ctx, shim)
	}
	return nil
}

func (tm *TaskManager) loadEmbedShim(ctx context.Context, b *pkgbundle.Bundle) (_ *embedShim, retErr error) {
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

func reconstructInit(ctx context.Context, b *pkgbundle.Bundle) (*Init, error) {
	rstdio, err := readInitStdio(b)
	if err != nil {
		return nil, err
	}

	pid, err := newPidFile(b.Path).Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read container pidfile: %w", err)
	}

	runtime := NewRunc(
		"",
		filepath.Join(b.Path, "work"),
		b.Namespace,
		"", // use default runc
		"",
		false, // no systemd cgroup
	)

	p := NewInit(
		b.ID,
		runtime,
		stdio.Stdio{
			Stdin:    rstdio.Stdin,
			Stdout:   rstdio.Stdout,
			Stderr:   rstdio.Stderr,
			Terminal: rstdio.Terminal,
		},
	)

	p.pid = pid
	p.Bundle = b.Path
	p.Rootfs = filepath.Join(b.Path, "rootfs")
	p.WorkDir = filepath.Join(b.Path, "work")
	return p, nil
}
