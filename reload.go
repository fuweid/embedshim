package embedshim

import (
	"context"
	"io/ioutil"
	"path/filepath"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/runtime"
)

func (manager *TaskManager) reloadExistingTasks(ctx context.Context) error {
	nsDirs, err := ioutil.ReadDir(manager.stateDir)
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
		if err := manager.loadTasks(namespaces.WithNamespace(ctx, ns)); err != nil {
			log.G(ctx).WithField("namespace", ns).WithError(err).Error("loading tasks in namespace")
			continue
		}
	}
	return nil
}

func (manager *TaskManager) loadTasks(ctx context.Context) error {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}

	shimDirs, err := ioutil.ReadDir(filepath.Join(manager.stateDir, ns))
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

		bundle, err := pkgbundle.LoadBundle(manager.stateDir, ns, id)
		if err != nil {
			return err
		}

		// fast path
		if err := bundle.IsValid(); err != nil {
			log.G(ctx).WithError(err).Errorf("bundle %s is invalid, cleanup", bundle.Path)
			bundle.Delete()
			continue
		}

		shim, err := manager.loadShim(ctx, bundle)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("failed to load exiting task %s", id)
			bundle.Delete()
			continue
		}

		if _, err := manager.containers.Get(ctx, id); err != nil {
			log.G(ctx).WithError(err).Errorf("failed to load container %s and start to delete task", id)
			shim.Delete(ctx)
			continue
		}
		manager.tasks.Add(ctx, shim)
	}
	return nil
}

func (manager *TaskManager) loadShim(ctx context.Context, bundle *pkgbundle.Bundle) (_ *shim, retErr error) {
	init, err := renewInitProcess(ctx, bundle)
	if err != nil {
		return nil, err
	}

	defer func() {
		if retErr != nil {
			deferCtx, deferCancel := deferContext()
			defer deferCancel()

			init.Delete(deferCtx)

			manager.cleanInitProcessTraceEvent(init)
		}
	}()

	if err := manager.repollingInitProcess(init); err != nil {
		return nil, err
	}
	return renewShim(manager, init), nil
}

func renewShim(manager *TaskManager, init *initProcess) *shim {
	s := &shim{
		manager: manager,
		bundle:  init.bundle,
		init:    init,

		execProcesses:   make(map[string]runtime.Process),
		reservedExecIDs: make(map[string]struct{}),
	}
	init.parent = s
	return s
}

func renewInitProcess(ctx context.Context, bundle *pkgbundle.Bundle) (*initProcess, error) {
	init, err := newInitProcess(bundle)
	if err != nil {
		return nil, err
	}
	if err = init.reload(ctx); err != nil {
		return nil, err
	}

	return init, nil
}
