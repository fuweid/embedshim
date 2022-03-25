package embedshim

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/mount"
)

var bundleFileMode fs.FileMode = 0711

// bundle represents an OCI bundle.
type bundle struct {
	// id of the bundle
	id string
	// path to the bundle
	path string
	// namespace of the bundle
	namespace string
}

// loadBundle loads an existing bundle from disk
func loadBundle(stateDir, ns, id string) (*bundle, error) {
	return &bundle{
		id:        id,
		path:      filepath.Join(stateDir, ns, id),
		namespace: ns,
	}, nil
}

// bundleApplyOpts is used to store metadata into bundle when newBundle
type bundleApplyOpts func(*bundle) error

func newBundle(root, state, ns, id string, opts ...bundleApplyOpts) (_ *bundle, retErr error) {
	var (
		workDir  = filepath.Join(root, ns, id)
		stateDir = filepath.Join(state, ns, id)

		b = &bundle{
			id:        id,
			path:      stateDir,
			namespace: ns,
		}

		paths []string
	)

	defer func() {
		if retErr != nil {
			for _, d := range paths {
				os.RemoveAll(d)
			}
		}
	}()

	// create state directory for the bundle
	if err := os.MkdirAll(filepath.Dir(b.path), bundleFileMode); err != nil {
		return nil, err
	}

	if err := os.Mkdir(b.path, bundleFileMode); err != nil {
		return nil, err
	}
	paths = append(paths, b.path)

	rootfs := filepath.Join(b.path, "rootfs")
	if err := os.MkdirAll(rootfs, bundleFileMode); err != nil {
		return nil, err
	}

	// apply bundle content
	for _, opt := range opts {
		if err := opt(b); err != nil {
			return nil, err
		}
	}

	// create working directory for the bundle
	if err := os.MkdirAll(filepath.Dir(workDir), bundleFileMode); err != nil {
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
	if err := os.Symlink(workDir, filepath.Join(b.path, "work")); err != nil {
		return nil, err
	}
	return b, nil
}

// delete a bundle atomically
func (b *bundle) delete() error {
	rootfs := filepath.Join(b.path, "rootfs")

	if err := mount.UnmountAll(rootfs, 0); err != nil {
		return fmt.Errorf("unmount rootfs %s: %w", rootfs, err)
	}

	if err := os.Remove(rootfs); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove bundle rootfs: %w", err)
	}

	workDir, werr := os.Readlink(filepath.Join(b.path, "work"))
	err := atomicDelete(b.path)
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
	return fmt.Errorf("failed to remove both bundle and workdir locations: %w", err2)
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
