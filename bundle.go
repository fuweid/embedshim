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

	"github.com/containerd/containerd/identifiers"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/runtime"
	"github.com/pkg/errors"
)

// Bundle represents an OCI bundle
type Bundle struct {
	// ID of the bundle
	ID string
	// Path to the bundle
	Path string
	// Namespace of the bundle
	Namespace string
}

// LoadBundle loads an existing bundle from disk
func LoadBundle(ctx context.Context, state, id string) (*Bundle, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	return &Bundle{
		ID:        id,
		Path:      filepath.Join(state, ns, id),
		Namespace: ns,
	}, nil
}

// NewBundle returns a new bundle on disk
func NewBundle(ctx context.Context, root, state, id, ns string, opts runtime.CreateOpts) (_ *Bundle, retErr error) {
	if err := identifiers.Validate(id); err != nil {
		return nil, errors.Wrapf(err, "invalid task id %s", id)
	}

	workDir := filepath.Join(root, ns, id)
	stateDir := filepath.Join(state, ns, id)

	b := &Bundle{
		ID:        id,
		Path:      stateDir,
		Namespace: ns,
	}

	var paths []string
	defer func() {
		if retErr != nil {
			for _, d := range paths {
				os.RemoveAll(d)
			}
		}
	}()

	// create state directory for the bundle
	if err := os.MkdirAll(filepath.Dir(b.Path), 0711); err != nil {
		return nil, err
	}
	if err := os.Mkdir(b.Path, 0711); err != nil {
		return nil, err
	}
	paths = append(paths, b.Path)

	rootfs := filepath.Join(b.Path, "rootfs")
	if err := os.MkdirAll(rootfs, 0711); err != nil {
		return nil, err
	}

	// create working directory for the bundle
	if err := os.MkdirAll(filepath.Dir(workDir), 0711); err != nil {
		return nil, err
	}
	if err := os.Mkdir(workDir, 0711); err != nil {
		if !os.IsExist(err) {
			return nil, err
		}

		os.RemoveAll(workDir)
		if err := os.Mkdir(workDir, 0711); err != nil {
			return nil, err
		}
	}
	paths = append(paths, workDir)

	// symlink workdir
	if err := os.Symlink(workDir, filepath.Join(b.Path, "work")); err != nil {
		return nil, err
	}

	// write the spec to the bundle
	if err := ioutil.WriteFile(filepath.Join(b.Path, configFilename), opts.Spec.Value, 0666); err != nil {
		return nil, err
	}

	// write IO spec to the bundle
	ioSpec, err := json.Marshal(opts.IO)
	if err != nil {
		return nil, err
	}
	if err := ioutil.WriteFile(filepath.Join(b.Path, iospecFilename), ioSpec, 0666); err != nil {
		return nil, err
	}
	return b, err
}

// Delete a bundle atomically
func (b *Bundle) Delete() error {
	rootfs := filepath.Join(b.Path, "rootfs")
	if err := mount.UnmountAll(rootfs, 0); err != nil {
		return errors.Wrapf(err, "unmount rootfs %s", rootfs)
	}
	if err := os.Remove(rootfs); err != nil && !os.IsNotExist(err) {
		return errors.Wrap(err, "failed to remove bundle rootfs")
	}

	workDir, werr := os.Readlink(filepath.Join(b.Path, "work"))

	err := atomicDelete(b.Path)
	if err == nil {
		if werr == nil {
			return atomicDelete(workDir)
		}
		return nil
	}

	// error removing the bundle path; still attempt removing work dir
	var err2 error
	if werr == nil {
		err2 = atomicDelete(workDir)
		if err2 == nil {
			return err
		}
	}
	return errors.Wrapf(err, "failed to remove both bundle and workdir locations: %v", err2)
}

// atomicDelete renames the path to a hidden file before removal
func atomicDelete(path string) error {
	// create a hidden dir for an atomic removal
	atomicPath := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s", filepath.Base(path)))
	if err := os.Rename(path, atomicPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.RemoveAll(atomicPath)
}
