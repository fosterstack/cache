package blobstore

// Error-path tests. Wherever possible these construct the real filesystem
// failure (files where directories are expected, permission-stripped
// directories, pre-created temp files, malformed shard layouts). The four
// paths that cannot be reached through a healthy local filesystem
// (rand.Read, fsync, close-after-fsync, fstat-of-open-file, and
// readdir/close of an open directory) are exercised through the test
// seams declared in blobstore.go.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zeroTempName is what randomTempName returns when randRead is overridden
// to fill the buffer with zeros.
const zeroTempName = ".tmp-00000000000000000000000000000000"

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission-based failures do not apply")
	}
}

// setSeam swaps a package-level test seam and restores it on cleanup.
func setSeam[T any](t *testing.T, seam *T, replacement T) {
	t.Helper()
	orig := *seam
	*seam = replacement
	t.Cleanup(func() { *seam = orig })
}

func TestNewFailsWhenRootPathIsUnderAFile(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "plainfile")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(file, "sub"))
	if err == nil {
		_ = s.Close()
		t.Fatal("New under a regular file: want error, got nil")
	}
	if !strings.Contains(err.Error(), "create root") {
		t.Fatalf("New error = %v, want create root failure", err)
	}
}

func TestNewFailsWhenRootIsUnopenable(t *testing.T) {
	skipIfRoot(t)
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })
	s, err := New(dir)
	if err == nil {
		_ = s.Close()
		t.Fatal("New on unopenable dir: want error, got nil")
	}
	if !strings.Contains(err.Error(), "open root") {
		t.Fatalf("New error = %v, want open root failure", err)
	}
}

func TestValidateKeyRejectsDisallowedCharacters(t *testing.T) {
	cases := []string{
		"bad key",                // space
		"bad!key",                // punctuation outside the allowed set
		"pfx/b:ad",               // rejected segment after valid ones
		strings.Repeat("a", 256), // over the per-segment length cap
	}
	for _, c := range cases {
		if err := ValidateKey(c); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ValidateKey(%q) = %v, want ErrInvalidKey", c, err)
		}
	}
}

func TestPutFailsWhenShardDirIsAFile(t *testing.T) {
	s := newTestStore(t)
	// Key "abc" shards to directory "ab"; occupy that name with a file.
	if err := os.WriteFile(filepath.Join(s.Root(), "ab"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "create dir") {
		t.Fatalf("Put with file blocking shard dir: err = %v, want create dir failure", err)
	}
}

func TestPutFailsWhenRandomSourceFails(t *testing.T) {
	s := newTestStore(t)
	setSeam(t, &randRead, func([]byte) (int, error) {
		return 0, errors.New("entropy exhausted")
	})
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "generate temp name") {
		t.Fatalf("Put with failing rand: err = %v, want generate temp name failure", err)
	}
	if _, statErr := s.Stat("abc"); !errors.Is(statErr, ErrNotFound) {
		t.Fatalf("blob must not exist after failed Put, Stat err = %v", statErr)
	}
}

func TestRandomTempNameErrorPropagates(t *testing.T) {
	setSeam(t, &randRead, func([]byte) (int, error) {
		return 0, errors.New("entropy exhausted")
	})
	if _, err := randomTempName(); err == nil {
		t.Fatal("randomTempName with failing rand: want error, got nil")
	}
}

func TestPutFailsOnTempFileCollision(t *testing.T) {
	s := newTestStore(t)
	// Make the temp name deterministic, then occupy it so O_EXCL trips.
	setSeam(t, &randRead, func(b []byte) (int, error) {
		clear(b)
		return len(b), nil
	})
	shard := filepath.Join(s.Root(), "ab")
	if err := os.MkdirAll(shard, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shard, zeroTempName), []byte("squatter"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("Put with colliding temp file: err = %v, want create temp file failure", err)
	}
	// The squatter belongs to a concurrent writer; a Put that failed to
	// create its temp file must leave it alone (cleanup is only deferred
	// after a successful create).
	got, readErr := os.ReadFile(filepath.Join(shard, zeroTempName))
	if readErr != nil || string(got) != "squatter" {
		t.Fatalf("colliding temp file disturbed: content %q, err %v", got, readErr)
	}
	if _, statErr := s.Stat("abc"); !errors.Is(statErr, ErrNotFound) {
		t.Fatalf("blob must not exist after failed Put, Stat err = %v", statErr)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("source torn down") }

func TestPutFailsWhenReaderFailsAndCleansUpTemp(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Put("abc", failingReader{})
	if err == nil || !strings.Contains(err.Error(), "blobstore: write") {
		t.Fatalf("Put with failing reader: err = %v, want write failure", err)
	}
	assertNoTempFiles(t, s)
	if _, statErr := s.Stat("abc"); !errors.Is(statErr, ErrNotFound) {
		t.Fatalf("blob must not exist after failed Put, Stat err = %v", statErr)
	}
}

func TestPutFailsWhenFsyncFailsAndCleansUpTemp(t *testing.T) {
	s := newTestStore(t)
	setSeam(t, &fileSync, func(*os.File) error { return errors.New("disk detached") })
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("Put with failing fsync: err = %v, want fsync failure", err)
	}
	assertNoTempFiles(t, s)
	if _, statErr := s.Stat("abc"); !errors.Is(statErr, ErrNotFound) {
		t.Fatalf("blob must not exist after failed Put, Stat err = %v", statErr)
	}
}

func TestPutFailsWhenTempCloseFailsAndCleansUpTemp(t *testing.T) {
	s := newTestStore(t)
	setSeam(t, &fileClose, func(f *os.File) error {
		_ = f.Close() // do not leak the descriptor
		return errors.New("deferred write error surfaced at close")
	})
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "close temp file") {
		t.Fatalf("Put with failing close: err = %v, want close temp file failure", err)
	}
	assertNoTempFiles(t, s)
	if _, statErr := s.Stat("abc"); !errors.Is(statErr, ErrNotFound) {
		t.Fatalf("blob must not exist after failed Put, Stat err = %v", statErr)
	}
}

func TestPutFailsWhenDestinationIsADirectoryAndCleansUpTemp(t *testing.T) {
	s := newTestStore(t)
	// Key "abc" resolves to ab/abc; plant a non-empty directory there so
	// the final rename cannot succeed.
	dest := filepath.Join(s.Root(), "ab", "abc")
	if err := os.MkdirAll(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "occupant"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("Put onto directory: err = %v, want rename failure", err)
	}
	assertNoTempFiles(t, s)
}

// assertNoTempFiles walks the store's real directory tree and fails the
// test if any .tmp-* file survived — failed Puts must clean up after
// themselves.
func assertNoTempFiles(t *testing.T, s *Store) {
	t.Helper()
	err := filepath.WalkDir(s.Root(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), ".tmp-") {
			t.Errorf("stale temp file left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking store dir: %v", err)
	}
}

func TestGetRejectsInvalidKey(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Get("../escape"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Get invalid key: err = %v, want ErrInvalidKey", err)
	}
}

func TestStatRejectsInvalidKey(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Stat("../escape"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Stat invalid key: err = %v, want ErrInvalidKey", err)
	}
}

func TestDeleteRejectsInvalidKey(t *testing.T) {
	s := newTestStore(t)
	if err := s.Delete("../escape"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Delete invalid key: err = %v, want ErrInvalidKey", err)
	}
}

func TestGetAndStatSurfaceNonNotFoundErrors(t *testing.T) {
	skipIfRoot(t)
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	shard := filepath.Join(s.Root(), "ab")
	if err := os.Chmod(shard, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shard, 0o750) })

	_, _, err := s.Get("abc")
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "open") {
		t.Fatalf("Get on unreadable shard: err = %v, want open failure (not ErrNotFound)", err)
	}
	_, err = s.Stat("abc")
	if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "stat") {
		t.Fatalf("Stat on unreadable shard: err = %v, want stat failure (not ErrNotFound)", err)
	}
}

func TestGetFailsWhenFstatFails(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	setSeam(t, &fileStat, func(*os.File) (os.FileInfo, error) {
		return nil, errors.New("descriptor gone bad")
	})
	_, _, err := s.Get("abc")
	if err == nil || !strings.Contains(err.Error(), "blobstore: stat") {
		t.Fatalf("Get with failing fstat: err = %v, want stat failure", err)
	}
}

func TestWalkEnumeratesBlobsAndSkipsForeignEntries(t *testing.T) {
	s := newTestStore(t)
	want := map[string]int64{
		"abc123":                       6,
		"com.example/artifact/1.0/key": 4,
	}
	if _, err := s.Put("abc123", strings.NewReader("sixsix")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("com.example/artifact/1.0/key", strings.NewReader("four")); err != nil {
		t.Fatal(err)
	}
	// Foreign entries Walk must ignore: a stray file at the store root
	// (blobs always live inside a shard directory) and a file whose name
	// can never be a valid key.
	if err := os.WriteFile(filepath.Join(s.Root(), "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.Root(), "xx"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root(), "xx", "not a key!"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := map[string]int64{}
	stale, err := s.Walk(func(key string, size int64) error {
		got[key] = size
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(stale) != 0 {
		t.Fatalf("Walk stale = %v, want none", stale)
	}
	if len(got) != len(want) {
		t.Fatalf("Walk visited %v, want %v", got, want)
	}
	for k, sz := range want {
		if got[k] != sz {
			t.Errorf("Walk key %q size = %d, want %d", k, got[k], sz)
		}
	}
}

func TestWalkReportsStaleTempAndRemoveStaleTempDeletesIt(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	staleName := ".tmp-cafecafecafecafecafecafecafecafe"
	stalePath := filepath.Join(s.Root(), "ab", staleName)
	if err := os.WriteFile(stalePath, []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}

	var keys []string
	stale, err := s.Walk(func(key string, size int64) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(stale) != 1 || stale[0] != "ab/"+staleName {
		t.Fatalf("Walk stale = %v, want [ab/%s]", stale, staleName)
	}
	if len(keys) != 1 || keys[0] != "abc" {
		t.Fatalf("Walk keys = %v, want [abc]; temp files must not be visited as blobs", keys)
	}

	if err := s.RemoveStaleTemp(stale[0]); err != nil {
		t.Fatalf("RemoveStaleTemp: %v", err)
	}
	if _, err := os.Lstat(stalePath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale temp still present after RemoveStaleTemp: lstat err = %v", err)
	}
	stale, err = s.Walk(func(string, int64) error { return nil })
	if err != nil {
		t.Fatalf("Walk after cleanup: %v", err)
	}
	if len(stale) != 0 {
		t.Fatalf("Walk after cleanup stale = %v, want none", stale)
	}
}

func TestWalkPropagatesCallbackError(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("stop the walk")
	_, err := s.Walk(func(string, int64) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("Walk with failing callback: err = %v, want %v", err, sentinel)
	}
}

func TestWalkFailsOnUnreadableSubdirectory(t *testing.T) {
	skipIfRoot(t)
	s := newTestStore(t)
	locked := filepath.Join(s.Root(), "locked")
	if err := os.MkdirAll(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) })
	_, err := s.Walk(func(string, int64) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "walk open") {
		t.Fatalf("Walk over unreadable subdir: err = %v, want walk open failure", err)
	}
}

func TestWalkFailsWhenReadDirFails(t *testing.T) {
	s := newTestStore(t)
	setSeam(t, &readDirAll, func(*os.File) ([]os.DirEntry, error) {
		return nil, errors.New("getdents failed")
	})
	_, err := s.Walk(func(string, int64) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "walk read") {
		t.Fatalf("Walk with failing readdir: err = %v, want walk read failure", err)
	}
}

func TestWalkFailsWhenDirCloseFails(t *testing.T) {
	s := newTestStore(t)
	closeFailure := errors.New("close reported deferred error")
	setSeam(t, &dirClose, func(f *os.File) error {
		_ = f.Close() // do not leak the descriptor
		return closeFailure
	})
	_, err := s.Walk(func(string, int64) error { return nil })
	if !errors.Is(err, closeFailure) {
		t.Fatalf("Walk with failing dir close: err = %v, want %v", err, closeFailure)
	}
}

func TestWalkFailsWhenEntryStatFails(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	// Simulate the blob vanishing between the directory read and the stat
	// (deleting it for real is not enough: on darwin ReadDir captures stat
	// info eagerly, so DirEntry.Info never fails after the fact).
	setSeam(t, &dirEntryInfo, func(e os.DirEntry) (fs.FileInfo, error) {
		return nil, fs.ErrNotExist
	})
	fnCalled := false
	_, err := s.Walk(func(string, int64) error {
		fnCalled = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "walk stat") {
		t.Fatalf("Walk with failing entry stat: err = %v, want walk stat failure", err)
	}
	if fnCalled {
		t.Fatal("callback must not run for an entry whose stat failed")
	}
}

// TestGetReaderStreamsFullBlob guards the seam refactor: fileStat must not
// change what Get returns for a healthy blob.
func TestGetReaderStreamsFullBlob(t *testing.T) {
	s := newTestStore(t)
	payload := strings.Repeat("cache-bytes/", 1000)
	if _, err := s.Put("abc", strings.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	rc, size, err := s.Get("abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if size != int64(len(payload)) {
		t.Fatalf("Get size = %d, want %d", size, len(payload))
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("Get returned %d bytes not matching payload", len(got))
	}
}
