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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/go-runc"
	"golang.org/x/sys/unix"
)

const (
	// runcRoot is the path to the root runc state directory
	runcRoot = "/run/containerd/runc"
)

func newRuncRuntime(root, path, namespace, runtime, criu string, systemd bool) *runc.Runc {
	if root == "" {
		root = runcRoot
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

func getLastRuntimeError(r *runc.Runc) (string, error) {
	if r.Log == "" {
		return "", nil
	}

	f, err := os.OpenFile(r.Log, os.O_RDONLY, 0400)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var (
		errMsg string
		log    struct {
			Level string
			Msg   string
			Time  time.Time
		}
	)

	dec := json.NewDecoder(f)
	for err = nil; err == nil; {
		if err = dec.Decode(&log); err != nil && err != io.EOF {
			return "", err
		}
		if log.Level == "error" {
			errMsg = strings.TrimSpace(log.Msg)
		}
	}

	return errMsg, nil
}

func checkKillError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "os: process already finished") ||
		strings.Contains(err.Error(), "container not running") ||
		strings.Contains(strings.ToLower(err.Error()), "no such process") ||
		err == unix.ESRCH {
		return fmt.Errorf("process already finished: %w", errdefs.ErrNotFound)
	} else if strings.Contains(err.Error(), "does not exist") {
		return fmt.Errorf("no such container: %w", errdefs.ErrNotFound)
	}
	return fmt.Errorf("unknown error after kill: %w", err)
}
