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

	"github.com/containerd/console"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/runtime"
	google_protobuf "github.com/gogo/protobuf/types"
)

type deletedState struct {
}

func (s *deletedState) Pause(_ context.Context) error {
	return fmt.Errorf("cannot pause a deleted process")
}

func (s *deletedState) Resume(_ context.Context) error {
	return fmt.Errorf("cannot resume a deleted process")
}

func (s *deletedState) Update(_ context.Context, _ *google_protobuf.Any) error {
	return fmt.Errorf("cannot update a deleted process")
}

func (s *deletedState) Checkpoint(_ context.Context, _ *CheckpointConfig) error {
	return fmt.Errorf("cannot checkpoint a deleted process")
}

func (s *deletedState) Resize(_ console.WinSize) error {
	return fmt.Errorf("cannot resize a deleted process")
}

func (s *deletedState) Start(_ context.Context) error {
	return fmt.Errorf("cannot start a deleted process")
}

func (s *deletedState) Delete(_ context.Context) error {
	return fmt.Errorf("cannot delete a deleted process: %w", errdefs.ErrNotFound)
}

func (s *deletedState) Kill(_ context.Context, _ uint32, _ bool) error {
	return fmt.Errorf("cannot kill a deleted process: %w", errdefs.ErrNotFound)
}

func (s *deletedState) SetExited(_ int) {
	// no op
}

func (s *deletedState) Exec(_ context.Context, _ string, _ runtime.ExecOpts) (runtime.Process, error) {
	return nil, fmt.Errorf("cannot exec in a deleted state")
}

func (s *deletedState) Status(_ context.Context) (string, error) {
	return "stopped", nil
}
