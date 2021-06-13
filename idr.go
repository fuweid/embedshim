package embedshim

import (
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/containerd/containerd/errdefs"
	bolt "go.etcd.io/bbolt"
)

var (
	idrDBName = "meta.db" // "idr.db"

	idrBucketVersion = "v1"

	idrBinaryOrder = binary.LittleEndian
)

type idAllocator struct {
	db *bolt.DB
}

func newIdAllocator(storeDir string) (*idAllocator, error) {
	db, err := bolt.Open(filepath.Join(storeDir, idrDBName), 0644, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open idAllocator db: %w", err)
	}
	return &idAllocator{db: db}, nil
}

func (idr *idAllocator) getID(namespace, containerID string) (uint64, error) {
	var id uint64

	if err := idr.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(idrBucketVersion))
		if bkt != nil {
			bkt = bkt.Bucket([]byte(namespace))
		}

		if bkt == nil {
			return fmt.Errorf("namespace %s bucket: %w", namespace, errdefs.ErrNotFound)
		}

		v := bkt.Get([]byte(containerID))
		if len(v) == 0 {
			return fmt.Errorf("id of container %s in namespace %s bucket: %w", containerID, namespace, errdefs.ErrNotFound)
		}

		id = idrBinaryOrder.Uint64(v)
		return nil
	}); err != nil {
		return 0, err
	}
	return id, nil
}

func (idr *idAllocator) nextID(namespace, containerID string) (uint64, error) {
	var id uint64

	if err := idr.db.Update(func(tx *bolt.Tx) error {
		v1bkt, err := tx.CreateBucketIfNotExists([]byte(idrBucketVersion))
		if err != nil {
			return fmt.Errorf("failed to create version bucket: %w", err)
		}

		nsBkt, err := v1bkt.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return fmt.Errorf("failed to create namespace %s bucket: %w", namespace, err)
		}

		v := nsBkt.Get([]byte(containerID))
		if len(v) != 0 {
			return fmt.Errorf("failed to reuse containerID %s in namespace bucket %s", containerID, namespace)
		}

		id, err = v1bkt.NextSequence()
		if err != nil {
			return fmt.Errorf("failed to get next ID: %w", err)
		}

		b := make([]byte, 8)
		idrBinaryOrder.PutUint64(b[0:], id)

		return nsBkt.Put([]byte(containerID), b)
	}); err != nil {
		return 0, err
	}
	return id, nil
}

func (idr *idAllocator) releaseID(namespace, containerID string) error {
	if err := idr.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(idrBucketVersion))
		if bkt != nil {
			bkt = bkt.Bucket([]byte(namespace))
		}

		if bkt == nil {
			return fmt.Errorf("namespace %s bucket: %w", namespace, errdefs.ErrNotFound)
		}

		return bkt.Delete([]byte(containerID))
	}); err != nil {
		return err
	}
	return nil
}

func (idr *idAllocator) close() error {
	return idr.db.Close()
}
