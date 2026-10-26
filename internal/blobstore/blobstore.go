// Package blobstore implements a filesystem-backed, path-keyed content store.
// It is deliberately dumb: callers supply the key (Gradle and the Apache Maven
// Build Cache Extension both compute it client-side), and the store never
// hashes, parses, or interprets the bytes it holds.
//
// Keys may contain '/': Gradle keys are one opaque segment, Maven's remote
// layout is a short path. Every segment is validated, and all filesystem
// access goes through an os.Root scoped to the store's directory, so a key can
// be neither sanitized past nor symlinked past the store root: traversal is
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
	"strings"
	"syscall"
)

// ErrNotFound is returned when a key has no stored blob.
var ErrNotFound = errors.New("blobstore: not found")

// ErrInvalidKey is returned when a key fails validation (empty segment,
// disallowed characters, path traversal attempt, etc).
var ErrInvalidKey = errors.New("blobstore: invalid key")

// segmentOK reports whether seg is one safe path segment: 1 to 255 letters,
// digits, '.', '_' or '-'. That covers Gradle's hex cache keys and Maven's
// group/artifact/version-shaped segments and rejects anything that could
// escape the store root.
func segmentOK(seg string) bool {
	if len(seg) == 0 || len(seg) > 255 {
		return false
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

const maxSegments = 16

// dotLeafShard is the shard directory for a leaf that starts with "..".
const dotLeafShard = "__"

// tempDirName is the directory, at the top of the store, that holds the
// temporary files of writes in flight. '+' is outside segmentOK's set, so no
// key's path can contain this name (REQ-PROTO-003-AC4).
const tempDirName = "+tmp"

// dirPerm/filePerm are deliberately tight: the store holds build-artifact bytes
// that need no group/other access.
const (
	dirPerm  fs.FileMode = 0o750
	filePerm fs.FileMode = 0o600
)

// Test seams: each is the plain call it names, replaced by tests to reach error
// paths a real filesystem cannot produce (crypto/rand.Read never fails; fsync,
// close, fstat and readdir have no portable fault injection).
var (
	randRead  = rand.Read
	fileSync  = (*os.File).Sync
	fileClose = (*os.File).Close
	fileStat  = (*os.File).Stat
	dirClose  = (*os.File).Close
	// rootOpen opens a regular file for reading without blocking: if something
	// replaced the checked file with a FIFO in between, the open returns at
	// once and the same-file check refuses it.
	rootOpen = func(r *os.Root, name string) (*os.File, error) {
		return r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	}
	readDirAll = func(f *os.File) ([]os.DirEntry, error) { return f.ReadDir(-1) }
	// On some platforms (e.g. darwin's getattrlistbulk-backed ReadDir) the
	// entries above carry their stat info eagerly, so DirEntry.Info cannot
	// fail even for a file deleted mid-walk.
	dirEntryInfo = os.DirEntry.Info
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
		if seg == "." || seg == ".." || !segmentOK(seg) {
			return ErrInvalidKey
		}
	}
	return nil
}

// relPath returns the store-relative path for key, sharding on the first
// two characters of the leaf segment so no single directory accumulates
// millions of entries. A leaf whose first two characters are ".." uses the
// fixed shard dotLeafShard instead (REQ-PROTO-003-AC3); every other key
// keeps the shard it always had.
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
	if shard == ".." {
		shard = dotLeafShard
	}
	parts := append(append([]string{}, segments[:len(segments)-1]...), shard, leaf)
	return path.Join(parts...), nil
}

// Put stores the bytes read from r under key, atomically: write to a randomly
// named temp file in the store's temporary directory (inside the same root, so
// on the same filesystem), fsync, then rename over the destination. Every path
// goes through s.root, so nothing can land outside the store even if a key
// resolves to a symlink.
func (s *Store) Put(key string, r io.Reader) (int64, error) {
	dest, err := relPath(key)
	if err != nil {
		return 0, err
	}
	dir := path.Dir(dest)
	if err := s.root.MkdirAll(dir, dirPerm); err != nil {
		return 0, fmt.Errorf("blobstore: create dir: %w", err)
	}

	if err := s.root.MkdirAll(tempDirName, dirPerm); err != nil {
		return 0, fmt.Errorf("blobstore: create temp dir: %w", err)
	}

	tmpName, err := randomTempName()
	if err != nil {
		return 0, fmt.Errorf("blobstore: generate temp name: %w", err)
	}
	tmpRel := path.Join(tempDirName, tmpName)

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
	if err := fileSync(tmp); err != nil {
		return 0, fmt.Errorf("blobstore: fsync: %w", err)
	}
	if err := fileClose(tmp); err != nil {
		return 0, fmt.Errorf("blobstore: close temp file: %w", err)
	}
	if err := s.root.Rename(tmpRel, dest); err != nil {
		return 0, fmt.Errorf("blobstore: rename: %w", err)
	}
	return n, nil
}

// absent reports whether err says that nothing is stored at the path: the
// path does not exist, or a component of it is a file where a directory
// would have to be (a stored key's blob can sit where another key's
// directory would go).
func absent(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR)
}

// regularFile returns the description of the entry at rel when it is a
// regular file. A directory, a symbolic link or any other kind of file at
// a key's path is not a blob (REQ-PROTO-003-AC5): the answer is
// ErrNotFound, and nothing is opened, so a FIFO cannot block the caller.
// op names the caller's operation in a failure that is not "absent".
func (s *Store) regularFile(rel, op string) (fs.FileInfo, error) {
	info, err := s.root.Lstat(rel)
	if err != nil {
		if absent(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("blobstore: %s: %w", op, err)
	}
	if !info.Mode().IsRegular() {
		return nil, ErrNotFound
	}
	return info, nil
}

// Get opens the blob stored under key. Callers must Close the returned
// reader. Returns ErrNotFound if the key is unknown, or if the path of the
// key is not a regular file.
func (s *Store) Get(key string) (io.ReadCloser, int64, error) {
	rel, err := relPath(key)
	if err != nil {
		return nil, 0, err
	}
	before, err := s.regularFile(rel, "open")
	if err != nil {
		return nil, 0, err
	}
	f, err := rootOpen(s.root, rel)
	if err != nil {
		if absent(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("blobstore: open: %w", err)
	}
	info, err := fileStat(f)
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("blobstore: stat: %w", err)
	}
	// The path was checked before it was opened: what was opened must be
	// that same regular file, not something swapped in between.
	if !info.Mode().IsRegular() || !os.SameFile(before, info) {
		_ = f.Close()
		return nil, 0, ErrNotFound
	}
	return f, info.Size(), nil
}

// Stat reports the size of the blob stored under key without reading it.
// Returns ErrNotFound if the key is unknown, or if the path of the key is
// not a regular file.
func (s *Store) Stat(key string) (int64, error) {
	rel, err := relPath(key)
	if err != nil {
		return 0, err
	}
	info, err := s.regularFile(rel, "stat")
	if err != nil {
		return 0, err
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
	if _, err := randRead(buf[:]); err != nil {
		return "", err
	}
	return ".tmp-" + hex.EncodeToString(buf[:]), nil
}

// Walk calls fn for every stored blob with its reconstructed key and
// on-disk size, and reports (without visiting) stale temporary files left
// by interrupted writes. It exists for startup reconciliation: blobs are
// truth, the metadata index is rebuildable, and this is how the truth is
// enumerated. The on-disk layout is <parent dirs>/<shard>/<leaf>, so a
// key is the file's path with the shard directory (the leaf's first two
// characters, or dotLeafShard) removed; a file is a blob only when it is
// the very file that key's path opens. That is usually the file at exactly
// the key's path; on a case-insensitive filesystem a shard directory keeps
// the case of the key that created it, so a blob can lie at a path that
// differs from its key's path only in case.
//
// Stale temporary files are the files in tempDirName and the ".tmp-"
// files directly at the top of the store; no key's path lies at either
// place (every key's path has at least two parts). Nothing in a shard
// directory is ever reported, so a key whose leaf starts with ".tmp-" is
// a blob like any other (REQ-PROTO-003-AC4), and files earlier versions
// left next to blobs are left alone.
func (s *Store) Walk(fn func(key string, size int64) error) (staleTemp []string, err error) {
	var walk func(rel string) error
	walk = func(rel string) error {
		entries, err := s.readDir(rel)
		if err != nil {
			return err
		}
		top := rel == "."
		for _, e := range entries {
			child := path.Join(rel, e.Name())
			if top && e.Name() == tempDirName && e.IsDir() {
				temps, err := s.readDir(child)
				if err != nil {
					return err
				}
				for _, te := range temps {
					if !te.IsDir() {
						staleTemp = append(staleTemp, path.Join(child, te.Name()))
					}
				}
				continue
			}
			if e.IsDir() {
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue // a symbolic link, FIFO or the like is never a blob (REQ-PROTO-003-AC5)
			}
			if top {
				// A file at the root is not a blob this store wrote; a
				// .tmp- one is a leftover temporary file.
				if strings.HasPrefix(e.Name(), ".tmp-") {
					staleTemp = append(staleTemp, child)
				}
				continue
			}
			info, err := dirEntryInfo(e)
			if err != nil {
				return fmt.Errorf("blobstore: walk stat %q: %w", child, err)
			}
			if !info.Mode().IsRegular() {
				continue // swapped for a link or the like since the listing
			}
			// Invert relPath: drop the shard directory (parent of the leaf).
			parts := strings.Split(child, "/")
			keyParts := append(append([]string{}, parts[:len(parts)-2]...), parts[len(parts)-1])
			key := path.Join(keyParts...)
			want, err := relPath(key)
			if err != nil {
				continue // not a shape this store produces; leave it alone
			}
			if want != child && !s.opensFile(want, info) {
				continue // not the file its key's path opens; leave it alone
			}
			if err := fn(key, info.Size()); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return staleTemp, err
	}
	return staleTemp, nil
}

// opensFile reports whether rel is the regular file described by info: the
// file Get would serve for rel (a link at rel is not followed).
func (s *Store) opensFile(rel string, info fs.FileInfo) bool {
	target, err := s.regularFile(rel, "stat")
	return err == nil && os.SameFile(target, info)
}

// readDir lists the directory rel inside the store root.
func (s *Store) readDir(rel string) ([]os.DirEntry, error) {
	f, err := s.root.Open(path.Join(".", rel))
	if err != nil {
		return nil, fmt.Errorf("blobstore: walk open %q: %w", rel, err)
	}
	entries, err := readDirAll(f)
	closeErr := dirClose(f)
	if err != nil {
		return nil, fmt.Errorf("blobstore: walk read %q: %w", rel, err)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return entries, nil
}

// RemoveStaleTemp deletes a stale temporary file found by Walk.
func (s *Store) RemoveStaleTemp(rel string) error { return s.root.Remove(rel) }
