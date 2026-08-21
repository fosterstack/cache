// Package metadata tracks per-key size and last-access time in a bbolt
// database, so the cache can enforce a size cap with least-recently-used
// eviction without scanning the filesystem. bbolt is pure Go (no CGO) and
// mmap-based, matching the project's zero-CGO, single-static-binary
// constraint.
package metadata

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"time"

	"go.etcd.io/bbolt"
)

var bucketName = []byte("entries")

// Entry is a snapshot of one key's bookkeeping record.
type Entry struct {
	Key        string
	Size       int64
	LastAccess time.Time
}

// Store is a bbolt-backed metadata index. Safe for concurrent use (bbolt
// serializes writers internally and readers see a consistent snapshot).
type Store struct {
	db *bbolt.DB
}

// Open opens (creating if necessary) a bbolt database at path.
func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("metadata: open: %w", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("metadata: init bucket: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// record is the fixed-width on-disk value: 8 bytes size, 8 bytes unix nano
// last-access, both stored as the bit pattern of a non-negative int64.
// encode/decode bounds-check explicitly rather than trusting the int64/
// uint64 conversion, so a corrupt or crafted record is rejected instead of
// silently wrapping into a negative size or a bogus timestamp.
func encode(size int64, lastAccess time.Time) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("metadata: negative size %d", size)
	}
	nanos := lastAccess.UnixNano()
	if nanos < 0 {
		return nil, fmt.Errorf("metadata: negative timestamp %d", nanos)
	}
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(size))   // #nosec G115 -- size validated >= 0 above
	binary.BigEndian.PutUint64(buf[8:16], uint64(nanos)) // #nosec G115 -- nanos validated >= 0 above
	return buf, nil
}

func decode(key string, buf []byte) (Entry, error) {
	rawSize := binary.BigEndian.Uint64(buf[0:8])
	rawNanos := binary.BigEndian.Uint64(buf[8:16])
	if rawSize > math.MaxInt64 || rawNanos > math.MaxInt64 {
		return Entry{}, fmt.Errorf("metadata: corrupt record for key %q: value exceeds int64 range", key)
	}
	return Entry{
		Key:        key,
		Size:       int64(rawSize),                // #nosec G115 -- bounds-checked above
		LastAccess: time.Unix(0, int64(rawNanos)), // #nosec G115 -- bounds-checked above
	}, nil
}

func decodeSize(buf []byte) (int64, error) {
	rawSize := binary.BigEndian.Uint64(buf[0:8])
	if rawSize > math.MaxInt64 {
		return 0, fmt.Errorf("metadata: corrupt record: size exceeds int64 range")
	}
	return int64(rawSize), nil // #nosec G115 -- bounds-checked above
}

// Record upserts a key's size and sets last-access to now. Call this on
// every successful Put.
func (s *Store) Record(key string, size int64) error {
	val, err := encode(size, time.Now())
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(key), val)
	})
}

// Touch updates a key's last-access time to now without changing its
// recorded size. Call this on every successful Get so LRU eviction reflects
// read traffic, not just writes. A miss (key not recorded) is not an error
// — the blob store is the source of truth for existence.
func (s *Store) Touch(key string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketName)
		existing := b.Get([]byte(key))
		if existing == nil {
			return nil
		}
		size, err := decodeSize(existing)
		if err != nil {
			return err
		}
		val, err := encode(size, time.Now())
		if err != nil {
			return err
		}
		return b.Put([]byte(key), val)
	})
}

// Delete removes a key's bookkeeping record.
func (s *Store) Delete(key string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Delete([]byte(key))
	})
}

// TotalSize sums the recorded size of every entry.
func (s *Store) TotalSize() (int64, error) {
	var total int64
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(k, v []byte) error {
			size, err := decodeSize(v)
			if err != nil {
				return err
			}
			total += size
			return nil
		})
	})
	return total, err
}

// LeastRecentlyUsed returns up to n entries with the oldest last-access
// time, oldest first — candidates for eviction.
func (s *Store) LeastRecentlyUsed(n int) ([]Entry, error) {
	var all []Entry
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).ForEach(func(k, v []byte) error {
			e, err := decode(string(k), v)
			if err != nil {
				return err
			}
			all = append(all, e)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].LastAccess.Before(all[j].LastAccess) })
	if n < len(all) {
		all = all[:n]
	}
	return all, nil
}

// Count returns the number of tracked entries.
func (s *Store) Count() (int, error) {
	var n int
	err := s.db.View(func(tx *bbolt.Tx) error {
		n = tx.Bucket(bucketName).Stats().KeyN
		return nil
	})
	return n, err
}
