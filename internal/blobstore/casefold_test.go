package blobstore

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// REQ-PROTO-003-AC4 (with REQ-STORE-005): on a case-insensitive filesystem
// a shard directory keeps the case of the first key that created it, so a
// blob can lie at a path that differs in case from its key's path while
// Get still opens it. Walk visits a file as a blob exactly when its key's
// path opens that very file.

// caseInsensitive reports whether dir is on a case-insensitive filesystem.
func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "casefold-probe")
	if err := os.Mkdir(probe, 0o750); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(probe) }()
	_, err := os.Stat(filepath.Join(dir, "CASEFOLD-PROBE"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

func walkKeys(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	seen := map[string]int64{}
	if _, err := s.Walk(func(key string, size int64) error {
		seen[key] = size
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return seen
}

// REQ-PROTO-003-AC4: on a real case-insensitive filesystem (APFS, NTFS
// defaults), keys whose shard directory was created by a key of other case
// are all visited by Walk. Skipped on case-sensitive filesystems; the
// symlink test below covers the same logic there.
func TestWalkVisitsKeysInCaseFoldedShardDirs(t *testing.T) {
	s := newTestStore(t)
	if !caseInsensitive(t, s.Root()) {
		t.Skip("case-sensitive filesystem: no shard directory can be shared by keys of different case")
	}
	keys := map[string]int64{}
	for _, k := range []string{"aB", "Abc", "x/Pq", "x/pQrs"} {
		n, err := s.Put(k, strings.NewReader("body:"+k))
		if err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
		keys[k] = n
	}
	if got := walkKeys(t, s); !maps.Equal(got, keys) {
		t.Fatalf("Walk keys = %v, want %v", got, keys)
	}
}

// REQ-PROTO-003-AC4: the same situation on any filesystem: the key's path
// "Ab/Abc" opens the file stored at "aB/Abc" (here through a symlink, as a
// case-insensitive filesystem does through case folding). Walk visits it
// once, under its key.
func TestWalkVisitsAFileItsKeysPathOpens(t *testing.T) {
	s := newTestStore(t)
	if caseInsensitive(t, s.Root()) {
		t.Skip("case-insensitive filesystem: aB and Ab cannot both exist; the real test above covers it")
	}
	if err := os.MkdirAll(filepath.Join(s.Root(), "aB"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root(), "aB", "Abc"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("aB", filepath.Join(s.Root(), "Ab")); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, s, "Abc"); got != "payload" {
		t.Fatalf("Get Abc = %q; the setup must make the key's path open the file", got)
	}
	if got := walkKeys(t, s); !maps.Equal(got, map[string]int64{"Abc": 7}) {
		t.Fatalf("Walk keys = %v, want map[Abc:7]", got)
	}
}

// REQ-PROTO-003-AC4: a file that names a key but is not the file the key's
// path opens is not visited, even when the key's path holds a blob.
func TestWalkSkipsACopyAwayFromItsKeysPath(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("abc", strings.NewReader("payload")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.Root(), "zz"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Root(), "zz", "abc"), []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := walkKeys(t, s)
	if !slices.Equal(slices.Collect(maps.Keys(got)), []string{"abc"}) || got["abc"] != 7 {
		t.Fatalf("Walk keys = %v, want map[abc:7]", got)
	}
}
