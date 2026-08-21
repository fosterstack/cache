// Package blobstore implements a filesystem-backed, path-keyed content
// store. It is deliberately dumb: callers supply the key (Gradle's remote
// build cache protocol computes the cache key client-side; the Apache Maven
// Build Cache Extension does the same), and the store never hashes, parses,
// or interprets the bytes it holds.
//
// Keys may contain '/' so that both frontends work naturally: Gradle keys
// are a single opaque segment, Maven's remote layout is a short path. Every
// segment is validated, and all filesystem access goes through an
// os.Root scoped to the store's directory (Go 1.24+), so a key can neither
// be sanitized past nor symlinked past the store root — traversal is
// rejected by the OS, not just by string checks.
package blobstore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
)

// ErrNotFound is returned when a key has no stored blob.
var ErrNotFound = errors.New("blobstore: not found")

// ErrInvalidKey is returned when a key fails validation (empty segment,
// disallowed characters, path traversal attempt, etc).
var ErrInvalidKey = errors.New("blobstore: invalid key")

// segmentRE matches a single safe path segment: letters, digits, '.', '_',
// '-'. This covers Gradle's hex cache keys and Maven's group/artifact/
// version-shaped segments while rejecting anything that could escape the
// store root.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)

const maxSegments = 16

// dirPerm/filePerm are deliberately tight: this store holds build-artifact
// bytes with no need for group/other access, and a compliance-tier buyer's
// assessor will check exactly this kind of default.
const (
	dirPerm  fs.FileMode = 0o750
	filePerm fs.FileMode = 0o600
)

// Store is a content-addressed blob store rooted at a directory on disk.
type Store struct {
	root   *os.Root
	rootAt string // for diagnostics only; never used to build paths directly
}

// New creates (if necessary) and returns a Store rooted at dir.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("blobstore: create root: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("blobstore: open root: %w", err)
	}
	return &Store{root: root, rootAt: dir}, nil
}

// Close releases the store's root directory handle.
func (s *Store) Close() error { return s.root.Close() }

// ValidateKey reports whether key is safe to use as a store path.
func ValidateKey(key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	segments := strings.Split(key, "/")
	if len(segments) > maxSegments {
		return ErrInvalidKey
	}
	for _, seg := range segments {
		if seg == "." || seg == ".." {
			return ErrInvalidKey
		}
		if !segmentRE.MatchString(seg) {
			return ErrInvalidKey
		}
	}
	return nil
}

// relPath returns the store-relative path for key, sharding on the first
// two characters of the leaf segment so no single directory accumulates
// millions of entries.
func relPath(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	segments := strings.Split(key, "/")
	leaf := segments[len(segments)-1]
	shard := leaf
	if len(shard) > 2 {
		shard = shard[:2]
	}
	parts := append(append([]string{}, segments[:len(segments)-1]...), shard, leaf)
	return path.Join(parts...), nil
}

// Put stores the bytes read from r under key, atomically: write to a
// randomly-named temp file in the same shard directory, fsync, then
// rename over the destination. Every path passed to the OS is resolved
// through s.root, so nothing can land outside the store even if a caller
// somehow got a validated-looking key that resolves to a symlink.
func (s *Store) Put(key string, r io.Reader) (int64, error) {
	dest, err := relPath(key)
	if err != nil {
		return 0, err
	}
	dir := path.Dir(dest)
	if err := s.root.MkdirAll(dir, dirPerm); err != nil {
		return 0, fmt.Errorf("blobstore: create dir: %w", err)
	}

	tmpName, err := randomTempName()
	if err != nil {
		return 0, fmt.Errorf("blobstore: generate temp name: %w", err)
	}
	tmpRel := path.Join(dir, tmpName)

	tmp, err := s.root.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, filePerm)
	if err != nil {
		return 0, fmt.Errorf("blobstore: create temp file: %w", err)
	}
	defer func() {
		// Best-effort cleanup: if Close/Rename below already succeeded,
		// these are no-ops (the file is gone or already closed); if an
		// earlier step failed, that error is what the caller sees.
		_ = tmp.Close()
		_ = s.root.Remove(tmpRel)
	}()

	n, err := io.Copy(tmp, r)
	if err != nil {
		return 0, fmt.Errorf("blobstore: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("blobstore: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("blobstore: close temp file: %w", err)
	}
	if err := s.root.Rename(tmpRel, dest); err != nil {
		return 0, fmt.Errorf("blobstore: rename: %w", err)
	}
	return n, nil
}

// Get opens the blob stored under key. Callers must Close the returned
// reader. Returns ErrNotFound if the key is unknown.
func (s *Store) Get(key string) (io.ReadCloser, int64, error) {
	rel, err := relPath(key)
	if err != nil {
		return nil, 0, err
	}
	f, err := s.root.Open(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("blobstore: open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("blobstore: stat: %w", err)
	}
	return f, info.Size(), nil
}

// Stat reports the size of the blob stored under key without reading it.
// Returns ErrNotFound if the key is unknown.
func (s *Store) Stat(key string) (int64, error) {
	rel, err := relPath(key)
	if err != nil {
		return 0, err
	}
	info, err := s.root.Stat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("blobstore: stat: %w", err)
	}
	return info.Size(), nil
}

// Delete removes the blob stored under key. Deleting a missing key is not
// an error (idempotent, matches eviction-loop usage).
func (s *Store) Delete(key string) error {
	rel, err := relPath(key)
	if err != nil {
		return err
	}
	if err := s.root.Remove(rel); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blobstore: remove: %w", err)
	}
	return nil
}

// Root returns the store's root directory path (for diagnostics/tests).
func (s *Store) Root() string { return s.rootAt }

func randomTempName() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return ".tmp-" + hex.EncodeToString(buf[:]), nil
}
