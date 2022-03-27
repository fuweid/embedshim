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
	"path/filepath"
	"sync/atomic"

	"github.com/containerd/go-runc"
	google_protobuf "github.com/gogo/protobuf/types"
)

// ExecConfig holds exec creation configuration
type ExecConfig struct {
	ID       string
	Terminal bool
	Stdin    string
	Stdout   string
	Stderr   string
	Spec     *google_protobuf.Any
}

// CheckpointConfig holds task checkpoint configuration
type CheckpointConfig struct {
	WorkDir                  string
	Path                     string
	Exit                     bool
	AllowOpenTCP             bool
	AllowExternalUnixSockets bool
	AllowTerminal            bool
	FileLocks                bool
	EmptyNamespaces          []string
}

const (
	// RuncRoot is the path to the root runc state directory
	RuncRoot = "/run/containerd/runc"
)

func newRuncRuntime(root, path, namespace, runtime, criu string, systemd bool) *runc.Runc {
	if root == "" {
		root = RuncRoot
	}

	return &runc.Runc{
		Command:   runtime,
		Log:       filepath.Join(path, "log.json"),
		LogFormat: runc.JSON,
		// NOTE(fuweid):
		//
		// The CRI plugin will use runtime.LockOSThread to create
		// the net namespace and that thread will be terminated because
		// CRI plugin doesn't call the UnlockOSThread.
		//
		// Based on this, we can't use PdeathSignal: SIGKILL here.
		Root:          filepath.Join(root, namespace),
		Criu:          criu,
		SystemdCgroup: systemd,
	}
}

type atomicBool int32

func (ab *atomicBool) set(b bool) {
	if b {
		atomic.StoreInt32((*int32)(ab), 1)
	} else {
		atomic.StoreInt32((*int32)(ab), 0)
	}
}

func (ab *atomicBool) get() bool {
	return atomic.LoadInt32((*int32)(ab)) == 1
}
