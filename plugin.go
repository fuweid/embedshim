package embedshim

import (
	"context"
	"fmt"
	"os"

	pkgbundle "github.com/fuweid/embedshim/pkg/bundle"
	shimebpf "github.com/fuweid/embedshim/pkg/ebpf"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/events/exchange"
	"github.com/containerd/containerd/identifiers"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/typeurl"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

var (
	pluginID = fmt.Sprintf("%s.%s", plugin.RuntimePlugin, "embed")

	traceEventIDDBName = "trace_event_id.db"
)

type Config struct{}

func init() {
	plugin.Register(&plugin.Registration{
		Type:   plugin.RuntimePlugin,
		ID:     "embed",
		InitFn: New,
		Requires: []plugin.Type{
			plugin.MetadataPlugin,
		},
		Config: &Config{},
	})
}

func New(ic *plugin.InitContext) (interface{}, error) {
	if err := os.MkdirAll(ic.Root, 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ic.State, 0700); err != nil {
		return nil, err
	}

	ic.Meta.Platforms = []ocispec.Platform{
		platforms.DefaultSpec(),
	}

	m, err := ic.Get(plugin.MetadataPlugin)
	if err != nil {
		return nil, err
	}

	cfg := ic.Config.(*Config)
	tm := &TaskManager{
		rootDir:    ic.Root,
		stateDir:   ic.State,
		tasks:      runtime.NewTaskList(),
		containers: metadata.NewContainerStore(m.(*metadata.DB)),
		events:     ic.Events,
		config:     cfg,
	}

	if err := tm.init(); err != nil {
		return nil, err
	}
	if err := tm.reloadExistingTasks(context.TODO()); err != nil {
		return nil, err
	}
	return tm, nil
}

type TaskManager struct {
	rootDir  string
	stateDir string
	config   *Config

	tasks      *runtime.TaskList
	containers containers.Store
	events     *exchange.Exchange

	idAlloc *idAllocator
	monitor *monitor
}

func (*TaskManager) ID() string {
	return pluginID
}

func (manager *TaskManager) Create(ctx context.Context, id string, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	if err := identifiers.Validate(id); err != nil {
		return nil, errors.Wrapf(err, "invalid task id %s", id)
	}

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	traceEventID, err := manager.nextTraceEventID()
	if err != nil {
		return nil, err
	}

	initOpts, err := initOptionsFromCreateOpts(opts)
	if err != nil {
		return nil, err
	}

	bundle, err := pkgbundle.NewBundle(manager.rootDir, manager.stateDir,
		ns, id,
		withBundleApplyInitOCISpec(opts.Spec),
		withBundleApplyInitOptions(initOpts),
		withBundleApplyInitStdio(opts.IO),
		withBundleApplyInitTraceEventID(traceEventID),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			bundle.Delete()
		}
	}()

	s, err := newShim(manager, bundle)
	if err != nil {
		return nil, err
	}

	task, err := s.Create(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create init process: %w", err)
	}

	manager.tasks.Add(ctx, task)
	return task, nil
}

func (manager *TaskManager) Get(ctx context.Context, id string) (runtime.Task, error) {
	return manager.tasks.Get(ctx, id)
}

func (manager *TaskManager) Add(ctx context.Context, task runtime.Task) error {
	return manager.tasks.Add(ctx, task)
}

func (manager *TaskManager) Delete(ctx context.Context, id string) {
	manager.tasks.Delete(ctx, id)
}

func (manager *TaskManager) Tasks(ctx context.Context, all bool) ([]runtime.Task, error) {
	return manager.tasks.GetAll(ctx, all)
}

func (manager *TaskManager) init() (retErr error) {
	err := shimebpf.EnsurePidMonitorRunning(manager.stateDir)
	if err != nil {
		return err
	}

	manager.idAlloc, err = newIDAllocator(manager.stateDir, traceEventIDDBName)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			manager.idAlloc.close()
		}
	}()

	manager.monitor, err = newMonitor(manager.stateDir)
	if err != nil {
		return err
	}
	return nil
}

func (manager *TaskManager) nextTraceEventID() (uint64, error) {
	return manager.idAlloc.nextID()
}

func (manager *TaskManager) traceInitProcess(init *initProcess) error {
	return manager.monitor.traceInitProcess(init)
}

func (manager *TaskManager) repollingInitProcess(init *initProcess) error {
	return manager.monitor.repollingInitProcess(init)
}

func (manager *TaskManager) cleanInitProcessTraceEvent(init *initProcess) error {
	return manager.monitor.store.DelExitedTask(init.traceEventID)
}

func initOptionsFromCreateOpts(createOpts runtime.CreateOpts) (*options.Options, error) {
	opts := createOpts.RuntimeOptions
	if opts == nil {
		opts = createOpts.TaskOptions
	}

	initOpts := &options.Options{}
	if opts != nil && opts.GetTypeUrl() != "" {
		v, err := typeurl.UnmarshalAny(opts)
		if err != nil {
			return nil, err
		}

		if vopts, ok := v.(*options.Options); ok {
			initOpts = vopts
		}
	}
	return initOpts, nil
}
