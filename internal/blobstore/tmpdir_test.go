package blobstore

import (
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// REQ-PROTO-003-AC4 tests: temporary files no longer share a name space
// with keys. Temporary files live in the directory below, at the top of
// the store; reconciliation removes files only there (and leftover .tmp-
// files directly at the top of the store), and every key keeps its path.

// storeTempDir is the store's temporary directory, as laid out on disk.
const storeTempDir = "+tmp"

// generatedShape is a leaf shaped exactly like a generated temporary name.
const generatedShape = ".tmp-0123456789abcdef0123456789abcdef"

// tmpLeafKeys are keys whose leaf starts with ".tmp-", with the path each
// one has always had (relPath at 6195872: shard = the leaf's first two
// characters).
var tmpLeafKeys = []struct{ key, rel string }{
	{".tmp-x", ".t/.tmp-x"},
	{"a/b/.tmp-y", "a/b/.t/.tmp-y"},
	{generatedShape, ".t/" + generatedShape},
	{"ab/" + generatedShape, "ab/.t/" + generatedShape},
	{".tmp-probe-1", ".t/.tmp-probe-1"},
}

// REQ-PROTO-003-AC4: no key can produce the temporary directory's name:
// the name is not a valid segment, and over a random corpus of valid keys
// no part of any key's path equals it (case-insensitively, so a
// case-insensitive filesystem cannot fold a key onto it either).
func TestTempDirNameIsNoPartOfAnyKeyPath(t *testing.T) {
	if segmentOK(storeTempDir) || ValidateKey(storeTempDir) == nil {
		t.Fatalf("%q is a valid key segment; a key could produce it", storeTempDir)
	}
	if ValidateKey(storeTempDir+"/x") == nil || ValidateKey("x/"+storeTempDir) == nil {
		t.Fatalf("a key containing the segment %q validates", storeTempDir)
	}
	const alphabet = "+tmpTMP._-x0"
	r := rand.New(rand.NewPCG(3, 4))
	checked := 0
	for i := 0; i < 20000; i++ {
		segs := make([]string, 1+r.IntN(maxSegments))
		for j := range segs {
			b := make([]byte, 1+r.IntN(6))
			for k := range b {
				b[k] = alphabet[r.IntN(len(alphabet))]
			}
			segs[j] = string(b)
		}
		key := strings.Join(segs, "/")
		rel, err := relPath(key)
		if err != nil {
			continue
		}
		checked++
		for _, part := range strings.Split(rel, "/") {
			if strings.EqualFold(part, storeTempDir) {
				t.Fatalf("relPath(%q) = %q contains the temporary directory", key, rel)
			}
		}
	}
	if checked < 1000 {
		t.Fatalf("only %d valid keys in the corpus; the property was not exercised", checked)
	}
}

// REQ-PROTO-003-AC4: the same property as a native fuzz target (seeds only
// in ordinary runs).
func FuzzRelPathAvoidsTempDir(f *testing.F) {
	for _, s := range []string{"+tmp", "+tmp/x", "tmp", ".tmp-x", "a/+tmp", "+TMP", generatedShape} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		rel, err := relPath(key)
		if err != nil {
			return
		}
		for _, part := range strings.Split(rel, "/") {
			if strings.EqualFold(part, storeTempDir) {
				t.Fatalf("relPath(%q) = %q contains the temporary directory", key, rel)
			}
		}
	})
}

// stagingReader serves its payload in two reads and, between them, records
// what the store's directories hold while the write is in flight.
type stagingReader struct {
	t        *testing.T
	s        *Store
	shardDir string
	payload  []byte
	calls    int
	tempSeen []string
	shardSaw []string
}

func (r *stagingReader) Read(p []byte) (int, error) {
	r.calls++
	switch r.calls {
	case 1:
		return copy(p, r.payload[:1]), nil
	case 2:
		r.tempSeen = names(r.t, filepath.Join(r.s.Root(), storeTempDir))
		r.shardSaw = names(r.t, filepath.Join(r.s.Root(), r.shardDir))
		return copy(p, r.payload[1:]), nil
	default:
		return 0, io.EOF
	}
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// REQ-PROTO-003-AC4: while a write is in flight its temporary file is in
// the temporary directory, not next to the key's blob; afterwards the blob
// is at its key's path and the temporary directory is empty.
func TestPutStagesItsTemporaryFileInTheTempDir(t *testing.T) {
	s := newTestStore(t)
	r := &stagingReader{t: t, s: s, shardDir: "a/b/.t", payload: []byte("payload")}
	if _, err := s.Put("a/b/.tmp-y", r); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(r.tempSeen) != 1 || !strings.HasPrefix(r.tempSeen[0], ".tmp-") {
		t.Errorf("temporary directory during the write = %v, want one .tmp- file", r.tempSeen)
	}
	if len(r.shardSaw) != 0 {
		t.Errorf("shard directory during the write = %v, want empty", r.shardSaw)
	}
	if got := names(t, filepath.Join(s.Root(), storeTempDir)); len(got) != 0 {
		t.Errorf("temporary directory after the write = %v, want empty", got)
	}
	if got := readAll(t, s, "a/b/.tmp-y"); got != "payload" {
		t.Errorf("Get = %q, want payload", got)
	}
	if _, err := s.root.Stat("a/b/.t/.tmp-y"); err != nil {
		t.Errorf("blob not at its path: %v", err)
	}
}

// REQ-PROTO-003-AC4 (and REQ-STORE-003-AC1): the temporary directory is
// created with the store's directory mode.
func TestTempDirHasTheStoreDirectoryMode(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	info, err := os.Stat(filepath.Join(s.Root(), storeTempDir))
	if err != nil {
		t.Fatalf("temporary directory: %v", err)
	}
	if !info.IsDir() || info.Mode().Perm() != dirPerm {
		t.Errorf("temporary directory mode = %v, want a directory with %o", info.Mode(), dirPerm)
	}
}

// REQ-PROTO-003-AC4: a write whose temporary directory cannot be created
// fails and stores nothing.
func TestPutFailsWhenTempDirIsAFile(t *testing.T) {
	s := newTestStore(t)
	if err := os.WriteFile(filepath.Join(s.Root(), storeTempDir), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Put("abc", strings.NewReader("payload"))
	if err == nil || !strings.Contains(err.Error(), "create temp dir") {
		t.Fatalf("Put with a file at the temporary directory: err = %v, want create temp dir failure", err)
	}
	if _, statErr := s.Stat("abc"); !errors.Is(statErr, ErrNotFound) {
		t.Fatalf("blob must not exist after failed Put, Stat err = %v", statErr)
	}
}

// REQ-PROTO-003-AC4: keys whose leaf starts with ".tmp-" are visited by
// Walk as keys, keep their paths, and survive removal of everything Walk
// reports; Walk reports only the files in the temporary directory and the
// .tmp- files directly at the top of the store.
func TestWalkKeepsTmpLeafKeysAndReportsOnlyTempDirFiles(t *testing.T) {
	s := newTestStore(t)
	for _, c := range tmpLeafKeys {
		if _, err := s.Put(c.key, strings.NewReader("body:"+c.key)); err != nil {
			t.Fatalf("Put %q: %v", c.key, err)
		}
	}
	tempDir := filepath.Join(s.Root(), storeTempDir)
	for _, n := range []string{".tmp-cafecafecafecafecafecafecafecafe", "other"} {
		if err := os.WriteFile(filepath.Join(tempDir, n), []byte("interrupted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root(), ".tmp-probe-0001"), []byte("probe"), 0o600); err != nil {
		t.Fatal(err)
	}

	seen := map[string]int64{}
	stale, err := s.Walk(func(key string, size int64) error {
		seen[key] = size
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	slices.Sort(stale)
	want := []string{storeTempDir + "/.tmp-cafecafecafecafecafecafecafecafe", storeTempDir + "/other", ".tmp-probe-0001"}
	if !slices.Equal(stale, want) {
		t.Fatalf("Walk stale = %v, want %v", stale, want)
	}
	if len(seen) != len(tmpLeafKeys) {
		t.Errorf("Walk keys = %v, want the %d keys stored", seen, len(tmpLeafKeys))
	}
	for _, c := range tmpLeafKeys {
		if size, ok := seen[c.key]; !ok || size != int64(len("body:"+c.key)) {
			t.Errorf("Walk: key %q seen=%v size=%d", c.key, ok, size)
		}
	}
	for _, rel := range stale {
		if err := s.RemoveStaleTemp(rel); err != nil {
			t.Fatalf("RemoveStaleTemp %q: %v", rel, err)
		}
	}
	for _, c := range tmpLeafKeys {
		if got := readAll(t, s, c.key); got != "body:"+c.key {
			t.Errorf("Get %q after reconciliation = %q", c.key, got)
		}
		if _, err := s.root.Stat(c.rel); err != nil {
			t.Errorf("key %q not at its path %q: %v", c.key, c.rel, err)
		}
	}
	if _, err := os.Stat(filepath.Join(tempDir, "subdir")); err != nil {
		t.Errorf("a directory inside the temporary directory was touched: %v", err)
	}
}

// REQ-PROTO-003-AC4: a file an earlier version left next to a blob in a
// shard directory is neither indexed nor reported for removal.
func TestWalkLeavesEarlierVersionShardFilesAlone(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(s.Root(), "ab", ".tmp-cafecafecafecafecafecafecafecafe")
	if err := os.WriteFile(leftover, []byte("interrupted"), 0o600); err != nil {
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
	if len(stale) != 0 {
		t.Errorf("Walk stale = %v, want none: shard directories are never cleaned", stale)
	}
	if !slices.Equal(keys, []string{"abc"}) {
		t.Errorf("Walk keys = %v, want [abc]: a file not at its own key's path is not a blob", keys)
	}
	if _, err := os.Stat(leftover); err != nil {
		t.Errorf("leftover file was touched: %v", err)
	}
}

// REQ-PROTO-003-AC4 (and REQ-STORE-002-AC1): a crash between the temporary
// write and the rename leaves no key visible: the partial file sits only in
// the temporary directory, no key reaches it, and Walk reports it for
// removal instead of visiting it as a blob.
func TestInterruptedWriteLeavesNoKeyVisible(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("seed", strings.NewReader("x")); err != nil { // creates the temporary directory
		t.Fatal(err)
	}
	if err := s.Delete("seed"); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(s.Root(), storeTempDir, generatedShape)
	if err := os.WriteFile(partial, []byte("trunc"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{generatedShape, storeTempDir + "/" + generatedShape, "abc"} {
		if _, _, err := s.Get(key); err == nil {
			t.Errorf("Get %q found a blob; the partial write must not be visible", key)
		}
	}
	var keys []string
	stale, err := s.Walk(func(key string, size int64) error {
		keys = append(keys, key)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Walk keys = %v, want none", keys)
	}
	if !slices.Equal(stale, []string{storeTempDir + "/" + generatedShape}) {
		t.Errorf("Walk stale = %v, want the partial file", stale)
	}
}
