package bundle

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/mount"
)

var bundleFileMode fs.FileMode = 0711

// Bundle represents an OCI bundle.
type Bundle struct {
	// ID of the bundle
	ID string
	// Path to the bundle
	Path string
	// Namespace of the bundle
	Namespace string
}

// LoadBundle loads an existing bundle from disk.
func LoadBundle(stateDir, ns, id string) (*Bundle, error) {
	return &Bundle{
		ID:        id,
		Path:      filepath.Join(stateDir, ns, id),
		Namespace: ns,
	}, nil
}

// ApplyOpts is used to store metadata into bundle when NewBundle.
type ApplyOpts func(*Bundle) error

// NewBundle creates bundle.
func NewBundle(root, state, ns, id string, opts ...ApplyOpts) (_ *Bundle, retErr error) {
	var (
		workDir  = filepath.Join(root, ns, id)
		stateDir = filepath.Join(state, ns, id)

		b = &Bundle{
			ID:        id,
			Path:      stateDir,
			Namespace: ns,
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
	if err := os.MkdirAll(filepath.Dir(b.Path), bundleFileMode); err != nil {
		return nil, err
	}

	if err := os.Mkdir(b.Path, bundleFileMode); err != nil {
		return nil, err
	}
	paths = append(paths, b.Path)

	rootfs := filepath.Join(b.Path, "rootfs")
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
	if err := os.Symlink(workDir, filepath.Join(b.Path, "work")); err != nil {
		return nil, err
	}
	return b, nil
}

// Rootfs returns rootfs path.
func (b *Bundle) Rootfs() string {
	return filepath.Join(b.Path, "rootfs")
}

// IsValid returns nil if the last-created workdir is there.
func (b *Bundle) IsValid() error {
	_, err := os.Stat(filepath.Join(b.Path, "work"))
	return err
}

// Delete a bundle atomically
func (b *Bundle) Delete() error {
	rootfs := filepath.Join(b.Path, "rootfs")

	if err := mount.UnmountAll(rootfs, 0); err != nil {
		return fmt.Errorf("unmount rootfs %s: %w", rootfs, err)
	}

	if err := os.Remove(rootfs); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove bundle rootfs: %w", err)
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
