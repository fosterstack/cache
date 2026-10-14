package blobstore

import (
	"bytes"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
)

// REQ-PROTO-003-AC3 tests: keys whose leaf starts with '..' are stored
// under the fixed shard "__" of their directory; every other key keeps
// exactly the path it had before.

// leavesRoot reports whether a store-relative path has a segment
// equal to "..", or does not stay inside the root. "Starts with '..'" is
// read as a first SEGMENT of "..": a directory segment such as "..a" is a
// valid key part and stays inside the root.
func leavesRoot(rel string) bool {
	if rel == "" || rel == ".." || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") {
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return true
		}
	}
	return false
}

func readAll(t *testing.T, s *Store, key string) string {
	t.Helper()
	rc, size, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get %q: %v", key, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}
	if size != int64(len(b)) {
		t.Fatalf("Get %q size = %d, read %d bytes", key, size, len(b))
	}
	return string(b)
}

// REQ-PROTO-003-AC3: two keys that differ only in their directory part
// keep different content.
func TestDotLeafKeysInDifferentDirectoriesStayDistinct(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put("a/..b", strings.NewReader("first")); err != nil {
		t.Fatalf("Put a/..b: %v", err)
	}
	if _, err := s.Put("x/..b", strings.NewReader("second")); err != nil {
		t.Fatalf("Put x/..b: %v", err)
	}
	if got := readAll(t, s, "a/..b"); got != "first" {
		t.Errorf("a/..b = %q, want first", got)
	}
	if got := readAll(t, s, "x/..b"); got != "second" {
		t.Errorf("x/..b = %q, want second", got)
	}
	ra, _ := relPath("a/..b")
	rx, _ := relPath("x/..b")
	if ra == rx {
		t.Errorf("relPath(a/..b) == relPath(x/..b) == %q", ra)
	}
}

// REQ-PROTO-003-AC3: keys whose leaf starts with '..' go through Put, Get,
// Stat and Delete under the fixed shard.
func TestDotLeafKeysRoundTrip(t *testing.T) {
	want := map[string]string{
		"...":   "__/...",
		"..x":   "__/..x",
		"..0":   "__/..0",
		"a/..x": "a/__/..x",
	}
	for key, wantRel := range want {
		t.Run(key, func(t *testing.T) {
			rel, err := relPath(key)
			if err != nil {
				t.Fatalf("relPath(%q): %v", key, err)
			}
			if rel != wantRel {
				t.Fatalf("relPath(%q) = %q, want %q", key, rel, wantRel)
			}
			s := newTestStore(t)
			payload := "payload-for-" + key
			n, err := s.Put(key, strings.NewReader(payload))
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if n != int64(len(payload)) {
				t.Fatalf("Put wrote %d, want %d", n, len(payload))
			}
			if got := readAll(t, s, key); got != payload {
				t.Fatalf("Get = %q, want %q", got, payload)
			}
			if size, err := s.Stat(key); err != nil || size != int64(len(payload)) {
				t.Fatalf("Stat = %d, %v", size, err)
			}
			if _, err := s.root.Stat(wantRel); err != nil {
				t.Fatalf("blob not at %q: %v", wantRel, err)
			}
			if err := s.Delete(key); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if _, err := s.Stat(key); err != ErrNotFound {
				t.Fatalf("Stat after Delete: %v, want ErrNotFound", err)
			}
		})
	}
}

// REQ-PROTO-003-AC3: Walk (startup reconciliation) gives back the original
// key for a blob under the fixed shard, next to ordinary keys.
func TestWalkReturnsDotLeafKeys(t *testing.T) {
	s := newTestStore(t)
	keys := []string{"..x", "a/..b", "x/..b", "__x", "a/__", "plain/key"}
	for _, k := range keys {
		if _, err := s.Put(k, bytes.NewReader([]byte(k))); err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
	}
	seen := map[string]int64{}
	stale, err := s.Walk(func(key string, size int64) error {
		seen[key] = size
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(stale) != 0 {
		t.Errorf("stale temp = %v", stale)
	}
	if len(seen) != len(keys) {
		t.Errorf("Walk saw %d keys %v, want %d", len(seen), seen, len(keys))
	}
	for _, k := range keys {
		if size, ok := seen[k]; !ok || size != int64(len(k)) {
			t.Errorf("Walk: key %q seen=%v size=%d", k, ok, size)
		}
	}
}

// REQ-PROTO-003-AC3: every key whose leaf does not start with '..' keeps
// exactly the path it had before (values computed from the code at
// 6195872 and hard-coded).
func TestRelPathUnchangedForOtherKeys(t *testing.T) {
	long := strings.Repeat("f", 255)
	nested := strings.TrimSuffix(strings.Repeat("d/", 15), "/") + "/leaf"
	cases := []struct{ key, want string }{
		{"a", "a/a"},
		{"Z", "Z/Z"},
		{"0", "0/0"},
		{"_", "_/_"},
		{"-", "-/-"},
		{".a", ".a/.a"},
		{"ab", "ab/ab"},
		{"AB", "AB/AB"},
		{"a.", "a./a."},
		{"a-", "a-/a-"},
		{"_x", "_x/_x"},
		{"-x", "-x/-x"},
		{"__", "__/__"},
		{".-", ".-/.-"},
		{"abc", "ab/abc"},
		{"abc123def4567890abc123def4567890abc123def4567890abc123def45678", "ab/abc123def4567890abc123def4567890abc123def4567890abc123def45678"},
		{"0123456789abcdef0123456789abcdef", "01/0123456789abcdef0123456789abcdef"},
		{long, "ff/" + long},
		{"__x", "__/__x"},
		{"__..", "__/__.."},
		{"_..", "_./_.."},
		{"-..", "-./-.."},
		{"a..", "a./a.."},
		{"x...y", "x./x...y"},
		{".x", ".x/.x"},
		{".xy", ".x/.xy"},
		{".tmpfile", ".t/.tmpfile"},
		{"A.B-C_D", "A./A.B-C_D"},
		{"Mixed.Case-Key_1", "Mi/Mixed.Case-Key_1"},
		{"a/b", "a/b/b"},
		{"a/bc", "a/bc/bc"},
		{"a/bcd", "a/bc/bcd"},
		{"dir/a..", "dir/a./a.."},
		{"x/.y", "x/.y/.y"},
		{"..a/b", "..a/b/b"},
		{"...a/bc", "...a/bc/bc"},
		{"a.b/c..d", "a.b/c./c..d"},
		{"org/example/lib/1.0.0/lib-1.0.0.jar", "org/example/lib/1.0.0/li/lib-1.0.0.jar"},
		{"com/acme/app/2.3.4-SNAPSHOT/app-2.3.4-SNAPSHOT.pom", "com/acme/app/2.3.4-SNAPSHOT/ap/app-2.3.4-SNAPSHOT.pom"},
		{"v1/build-cache/0f/0f1e2d3c", "v1/build-cache/0f/0f/0f1e2d3c"},
		{"UPPER/lower/MiXeD", "UPPER/lower/Mi/MiXeD"},
		{"a/b/c/d/e/f/g/h", "a/b/c/d/e/f/g/h/h"},
		{nested, "d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/le/leaf"},
		{"_/_/_", "_/_/_/_"},
		{"-/-/-", "-/-/-/-"},
		{"1/22/333", "1/22/33/333"},
		{"a_b-c.d/e_f-g.h", "a_b-c.d/e_/e_f-g.h"},
		{"x/" + long, "x/ff/" + long},
		{"cache/__", "cache/__/__"},
		{"Ab-", "Ab/Ab-"},
	}
	if len(cases) != 50 {
		t.Fatalf("table has %d keys, want 50", len(cases))
	}
	for _, c := range cases {
		got, err := relPath(c.key)
		if err != nil {
			t.Errorf("relPath(%q): %v", c.key, err)
			continue
		}
		if got != c.want {
			t.Errorf("relPath(%q) = %q, want %q (unchanged)", c.key, got, c.want)
		}
	}
}

// REQ-PROTO-003-AC3: the path of a key whose leaf starts with '..' has no
// '..' segment.
func TestRelPathDotLeafHasNoDotDotSegment(t *testing.T) {
	for _, key := range []string{"...", "..x", "..0", "a/..x", "a/b/..", "..a/..b", "x/....", strings.Repeat("a/", 15) + ".." + strings.Repeat("z", 253)} {
		if ValidateKey(key) != nil {
			continue // not a key the store accepts; nothing to place
		}
		rel, err := relPath(key)
		if err != nil {
			t.Errorf("relPath(%q): %v", key, err)
			continue
		}
		if leavesRoot(rel) {
			t.Errorf("relPath(%q) = %q has a '..' segment or leaves the root", key, rel)
		}
	}
}

// REQ-PROTO-003-AC3: over a random corpus of valid keys, relPath never has
// a '..' segment and never starts with '/' or '..'; distinct keys map to
// distinct paths.
func TestRelPathRandomCorpusStaysInside(t *testing.T) {
	const alphabet = "..........ab_-Z09"
	r := rand.New(rand.NewPCG(1, 2))
	seen := map[string]string{}
	for i := 0; i < 20000; i++ {
		nseg := 1 + r.IntN(4)
		segs := make([]string, nseg)
		for j := range segs {
			n := 1 + r.IntN(6)
			b := make([]byte, n)
			for k := range b {
				b[k] = alphabet[r.IntN(len(alphabet))]
			}
			segs[j] = string(b)
		}
		key := strings.Join(segs, "/")
		if ValidateKey(key) != nil {
			continue
		}
		rel, err := relPath(key)
		if err != nil {
			t.Fatalf("relPath(%q): %v", key, err)
		}
		if leavesRoot(rel) {
			t.Fatalf("relPath(%q) = %q has a '..' segment or leaves the root", key, rel)
		}
		if prev, ok := seen[rel]; ok && prev != key {
			t.Fatalf("keys %q and %q share path %q", prev, key, rel)
		}
		seen[rel] = key
	}
}

// REQ-PROTO-003-AC3: the same property as a native fuzz target (seeds
// only in ordinary runs).
func FuzzRelPathStaysInside(f *testing.F) {
	for _, s := range []string{"a", "..x", "a/..b", "...", "..0", "x/..", "0..0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		rel, err := relPath(key)
		if err != nil {
			return
		}
		if leavesRoot(rel) {
			t.Fatalf("relPath(%q) = %q has a '..' segment or leaves the root", key, rel)
		}
	})
}
