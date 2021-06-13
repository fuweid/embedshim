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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/go-runc"
	google_protobuf "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
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
	// InitPidFile name of the file that contains the init pid
	InitPidFile = "init.pid"

	configFilename = "config.json"

	iospecFilename = ".iospec.json"
)

// NewRunc returns a new runc instance for a process
func NewRunc(root, path, namespace, runtime, criu string, systemd bool) *runc.Runc {
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
		//
		// PdeathSignal:  unix.SIGKILL,
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

type pidFile struct {
	path string
}

func (p *pidFile) Path() string {
	return p.path
}

func (p *pidFile) Read() (int, error) {
	return runc.ReadPidFile(p.path)
}

func newPidFile(bundle string) *pidFile {
	return &pidFile{
		path: filepath.Join(bundle, InitPidFile),
	}
}

type iospecFile struct {
	path string
}

func (iospec *iospecFile) Path() string {
	return iospec.path
}

func (iospec *iospecFile) Read() (runtime.IO, error) {
	io := runtime.IO{}

	data, err := ioutil.ReadFile(iospec.path)
	if err != nil {
		return io, err
	}

	if err := json.Unmarshal(data, &io); err != nil {
		return io, err
	}
	return io, nil
}

func newIospecFile(bundle string) *iospecFile {
	return &iospecFile{
		path: filepath.Join(bundle, iospecFilename),
	}
}

func openRWFifo(ctx context.Context, fn string, perm os.FileMode) (*os.File, error) {
	if _, err := os.Stat(fn); err != nil {
		if os.IsNotExist(err) {
			if err := syscall.Mkfifo(fn, uint32(perm&os.ModePerm)); err != nil && !os.IsExist(err) {
				return nil, fmt.Errorf("error creating fifo %v: %w", fn, err)
			}
		} else {
			return nil, err
		}
	}
	return os.OpenFile(fn, syscall.O_RDWR, perm)
}

// waitTimeout handles waiting on a waitgroup with a specified timeout.
// this is commonly used for waiting on IO to finish after a process has exited
func waitTimeout(ctx context.Context, wg *sync.WaitGroup, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func checkKillError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "os: process already finished") ||
		strings.Contains(err.Error(), "container not running") ||
		strings.Contains(strings.ToLower(err.Error()), "no such process") ||
		err == unix.ESRCH {
		return errors.Wrapf(errdefs.ErrNotFound, "process already finished")
	} else if strings.Contains(err.Error(), "does not exist") {
		return errors.Wrapf(errdefs.ErrNotFound, "no such container")
	}
	return errors.Wrapf(err, "unknown error after kill")
}
