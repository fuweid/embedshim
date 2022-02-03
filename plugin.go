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

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/events/exchange"
	"github.com/containerd/containerd/identifiers"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime"
	shimebpf "github.com/fuweid/embedshim/pkg/ebpf"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

var (
	pluginID = fmt.Sprintf("%s.%s", plugin.RuntimePlugin, "embed")
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

	tasks      *runtime.TaskList
	containers containers.Store
	events     *exchange.Exchange

	config  *Config
	monitor *monitor
}

func (tm *TaskManager) ID() string {
	return pluginID
}

func (tm *TaskManager) Create(ctx context.Context, id string, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	if err := identifiers.Validate(id); err != nil {
		return nil, errors.Wrapf(err, "invalid task id %s", id)
	}

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	bundle, err := NewBundle(ctx, tm.rootDir, tm.stateDir, id, ns, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			bundle.Delete()
		}
	}()

	es := newEmbedShim(tm, bundle)
	t, err := es.Create(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create init process: %w", err)
	}

	defer func() {
		if retErr != nil {
			// TODO: use timeout context
			es.Delete(context.TODO())
		}
	}()

	err = tm.monitor.subscribe(
		ns, id, t.PID(),
		func(exited *shimebpf.TaskExitStatus) error {
			es.init.SetExited(int(exited.ExitCode))
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	tm.tasks.Add(ctx, t)
	return t, nil
}

func (tm *TaskManager) Get(ctx context.Context, id string) (runtime.Task, error) {
	return tm.tasks.Get(ctx, id)
}

func (tm *TaskManager) Add(ctx context.Context, task runtime.Task) error {
	return tm.tasks.Add(ctx, task)
}

func (tm *TaskManager) Delete(ctx context.Context, id string) {
	tm.tasks.Delete(ctx, id)
}

func (tm *TaskManager) Tasks(ctx context.Context, all bool) ([]runtime.Task, error) {
	return tm.tasks.GetAll(ctx, all)
}

func (tm *TaskManager) init() error {
	err := shimebpf.EnsurePidMonitorRunning(tm.stateDir)
	if err != nil {
		return err
	}

	tm.monitor, err = newMonitor(tm.stateDir)
	return err
}
