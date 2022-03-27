package embedshim

import (
	"fmt"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var idaBucketVersion = "v1"

// idAllocator is used to generate autoincrementing integer as ID and the state
// can be persisted in disk.
type idAllocator struct {
	db *bolt.DB
}

func newIDAllocator(storeDir string, dbName string) (*idAllocator, error) {
	db, err := bolt.Open(filepath.Join(storeDir, dbName), 0644, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open db in %s: %w", storeDir, err)
	}
	return &idAllocator{db: db}, nil
}

func (ida *idAllocator) nextID() (uint64, error) {
	var id uint64

	if err := ida.db.Update(func(tx *bolt.Tx) error {
		v1bkt, err := tx.CreateBucketIfNotExists([]byte(idaBucketVersion))
		if err != nil {
			return fmt.Errorf("failed to create version bucket: %w", err)
		}

		id, err = v1bkt.NextSequence()
		if err != nil {
			return fmt.Errorf("failed to get next ID: %w", err)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return id, nil
}

func (ida *idAllocator) close() error {
	return ida.db.Close()
}
