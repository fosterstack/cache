package blobstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ-PROTO-003-AC5: a path in the store that is a directory, a symbolic
// link or any other non-regular file never answers for a key: Get and Stat
// say not found, and the startup walk reports no entry for it.

func put(t *testing.T, s *Store, key, body string) {
	t.Helper()
	if _, err := s.Put(key, strings.NewReader(body)); err != nil {
		t.Fatalf("Put %q: %v", key, err)
	}
}

func has(m map[string]int64, k string) bool { _, ok := m[k]; return ok }

func wantNotFound(t *testing.T, s *Store, key string) {
	t.Helper()
	if rc, _, err := s.Get(key); !errors.Is(err, ErrNotFound) {
		if rc != nil {
			_ = rc.Close()
		}
		t.Errorf("Get %q: err = %v, want ErrNotFound", key, err)
	}
	if _, err := s.Stat(key); !errors.Is(err, ErrNotFound) {
		t.Errorf("Stat %q: err = %v, want ErrNotFound", key, err)
	}
}

// Key "ab" lives at ab/ab; storing "ab/ab" makes that path a directory.
func TestDirectoryAtAKeysPathIsNotFound(t *testing.T) {
	s, _ := New(t.TempDir())
	defer func() { _ = s.Close() }()
	put(t, s, "ab/ab", "inner")
	wantNotFound(t, s, "ab")
	if k := walkKeys(t, s); len(k) != 1 || !has(k, "ab/ab") {
		t.Errorf("Walk keys = %v, want exactly ab/ab", k)
	}
}

// The same collision in the other order: a stored blob stays served, and the
// second key cannot be stored (the known residual); nothing is crossed.
func TestBlobSurvivesACollidingKey(t *testing.T) {
	s, _ := New(t.TempDir())
	defer func() { _ = s.Close() }()
	put(t, s, "ab", "first")
	if _, err := s.Put("ab/ab", strings.NewReader("second")); err == nil {
		t.Fatal("Put ab/ab beside the blob ab succeeded")
	}
	if got := readAll(t, s, "ab"); got != "first" {
		t.Errorf("Get ab = %q, want first", got)
	}
	wantNotFound(t, s, "ab/ab")
}

func TestSymlinkAtAKeysPathIsNotFound(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	defer func() { _ = s.Close() }()
	put(t, s, "realkey", "real")
	if err := os.MkdirAll(filepath.Join(dir, "li"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "re", "realkey"), filepath.Join(dir, "li", "linkkey")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	wantNotFound(t, s, "linkkey")
	if k := walkKeys(t, s); has(k, "linkkey") || !has(k, "realkey") {
		t.Errorf("Walk keys = %v, want realkey and not linkkey", k)
	}
}

// The path is checked, then opened: whatever happens in between must not
// turn into a served blob or a crash.
func TestGetWhenTheBlobVanishesBeforeItIsOpened(t *testing.T) {
	s, _ := New(t.TempDir())
	defer func() { _ = s.Close() }()
	put(t, s, "abc", "payload")
	setSeam(t, &rootOpen, func(r *os.Root, name string) (*os.File, error) {
		_ = r.Remove(name)
		return r.Open(name)
	})
	if _, _, err := s.Get("abc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get: err = %v, want ErrNotFound", err)
	}
}

func TestGetWhenTheOpenedFileIsNotTheCheckedOne(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	defer func() { _ = s.Close() }()
	put(t, s, "abc", "payload")
	put(t, s, "other", "something else")
	setSeam(t, &fileStat, func(*os.File) (os.FileInfo, error) {
		return os.Stat(filepath.Join(dir, "ot", "other"))
	})
	if rc, _, err := s.Get("abc"); !errors.Is(err, ErrNotFound) {
		if rc != nil {
			_ = rc.Close()
		}
		t.Errorf("Get: err = %v, want ErrNotFound", err)
	}
}

func TestGetSurfacesAnOpenFailureOfARegularFile(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	s, _ := New(dir)
	defer func() { _ = s.Close() }()
	put(t, s, "abc", "payload")
	blob := filepath.Join(dir, "ab", "abc")
	if err := os.Chmod(blob, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blob, 0o600) })
	if _, _, err := s.Get("abc"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get on an unreadable blob: err = %v, want an open failure", err)
	}
}

// A symlink at a key's path is not a blob, and the walk must not find the
// key by following that link to another regular file: Get answers 404 for
// it, so the walk may not report it (the walk reports what Get would serve).
func TestWalkSkipsAKeyWhosePathIsASymlink(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := os.MkdirAll(filepath.Join(dir, "xy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "xy", "abc"), []byte("stray"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "ab"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../xy/abc", filepath.Join(dir, "ab", "abc")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	wantNotFound(t, s, "abc")
	if k := walkKeys(t, s); has(k, "abc") {
		t.Errorf("Walk reported abc, whose path is a symlink: %v", k)
	}
}

// The listing said "regular file"; by the time the walk asks for the entry's
// description it may be something else: it is not reported.
func TestWalkSkipsAnEntryThatStoppedBeingRegularAfterTheListing(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	put(t, s, "abc", "payload")
	setSeam(t, &dirEntryInfo, func(os.DirEntry) (os.FileInfo, error) { return os.Stat(dir) })
	if k := walkKeys(t, s); has(k, "abc") {
		t.Errorf("Walk reported abc although its description is a directory: %v", k)
	}
}
