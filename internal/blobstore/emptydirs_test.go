package blobstore

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// putString stores s under key.
func putString(t *testing.T, s *Store, key, s2 string) {
	t.Helper()
	if _, err := s.Put(key, strings.NewReader(s2)); err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
}

// entriesBelowRoot lists every path under the root except +tmp and the root itself.
func entriesBelowRoot(t *testing.T, s *Store) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(s.Root(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(s.Root(), p)
		if rel == "." {
			return nil
		}
		if rel == "+tmp" {
			return filepath.SkipDir
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func mustExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); err != nil {
		t.Errorf("%s: %v", p, err)
	}
}

// Rule 1 (empty directories): after deleting 50 Maven-shaped keys no directory is left behind.
func TestDeleteRemovesEmptiedDirectoriesMaven(t *testing.T) {
	s := newTestStore(t)
	var keys []string
	for i := 0; i < 25; i++ {
		dir := fmt.Sprintf("v1.1/com.example.bench/app/%032x", i)
		keys = append(keys, dir+"/buildinfo.xml", dir+"/app.jar")
	}
	for _, k := range keys {
		putString(t, s, k, "data "+k)
	}
	for _, k := range keys {
		if err := s.Delete(k); err != nil {
			t.Fatalf("Delete(%q): %v", k, err)
		}
	}
	if left := entriesBelowRoot(t, s); len(left) != 0 {
		t.Errorf("entries left under the root: %v", left)
	}
	mustExist(t, s.Root())
}

// Rule 1: the walk up stops at the first directory that is not empty.
func TestDeleteKeepsNonEmptyParent(t *testing.T) {
	s := newTestStore(t)
	putString(t, s, "a/b/c/one.jar", "1")
	putString(t, s, "a/b/c/two.jar", "2")
	if err := s.Delete("a/b/c/one.jar"); err != nil {
		t.Fatal(err)
	}
	rc, n, err := s.Get("a/b/c/two.jar")
	if err != nil {
		t.Fatalf("Get after sibling delete: %v", err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if n != 1 || string(b) != "2" {
		t.Errorf("sibling = %q (%d)", b, n)
	}
	if err := s.Delete("a/b/c/two.jar"); err != nil {
		t.Fatal(err)
	}
	if left := entriesBelowRoot(t, s); len(left) != 0 {
		t.Errorf("entries left under the root: %v", left)
	}
	mustExist(t, filepath.Join(s.Root(), "+tmp"))
}

// Rule 1: a key whose blob sits where another key's directory would go is never removed by a Delete of a missing key.
func TestDeleteMissingKeyNeverRemovesOtherBlob(t *testing.T) {
	s := newTestStore(t)
	putString(t, s, "ab", "payload")
	_ = s.Delete("ab/ab") // any result is fine; the file must survive
	mustExist(t, filepath.Join(s.Root(), "ab", "ab"))
	rc, _, err := s.Get("ab")
	if err != nil {
		t.Fatalf("Get(ab): %v", err)
	}
	_ = rc.Close()
}

// Rule 1: deleting a missing key leaves the directories of other keys alone.
func TestDeleteMissingKeyLeavesOtherDirectories(t *testing.T) {
	s := newTestStore(t)
	putString(t, s, "x/y/keep.bin", "k")
	_ = s.Delete("x/y/missing.bin")
	_ = s.Delete("x/z/missing.bin")
	rc, _, err := s.Get("x/y/keep.bin")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = rc.Close()
	mustExist(t, filepath.Join(s.Root(), "x", "y", "ke"))
}

// Rule 1: removing emptied directories never makes a concurrent Put in the same key directory fail or lose bytes.
func TestDeleteEmptyDirsConcurrentWithPut(t *testing.T) {
	s := newTestStore(t)
	const workers, iters = 16, 300
	var wg sync.WaitGroup
	errs := make(chan error, workers+1)
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("g/a/k/f%d", g%4+1) + fmt.Sprintf("x%d", g)
			want := strings.Repeat("v", g+1)
			for i := 0; i < iters; i++ {
				if _, err := s.Put(key, strings.NewReader(want)); err != nil {
					errs <- fmt.Errorf("Put %s: %w", key, err)
					return
				}
				rc, _, err := s.Get(key)
				if err != nil {
					errs <- fmt.Errorf("Get %s: %w", key, err)
					return
				}
				b, _ := io.ReadAll(rc)
				rc.Close()
				if string(b) != want {
					errs <- fmt.Errorf("Get %s = %q", key, b)
					return
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters*2; i++ {
			key := fmt.Sprintf("g/a/k/d%d", i%4)
			if _, err := s.Put(key, strings.NewReader("d")); err != nil {
				errs <- fmt.Errorf("Put %s: %w", key, err)
				return
			}
			if err := s.Delete(key); err != nil {
				errs <- fmt.Errorf("Delete %s: %w", key, err)
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Rule 1: Put succeeds while Delete removes the directories a delete has emptied, for keys sharing parents.
func TestPutSurvivesConcurrentDeleteOfSiblingKeys(t *testing.T) {
	s := newTestStore(t)
	const workers, iters = 16, 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	fail := func(err error) {
		mu.Lock()
		errs = append(errs, err)
		mu.Unlock()
	}
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				key := fmt.Sprintf("v1.1/com.example.bench/app/%032x/app.jar", g*iters+i)
				if _, err := s.Put(key, strings.NewReader("jar")); err != nil {
					fail(fmt.Errorf("Put %s: %w", key, err))
				}
				if err := s.Delete(key); err != nil {
					fail(fmt.Errorf("Delete %s: %w", key, err))
				}
			}
		}(g)
	}
	wg.Wait()
	for i, err := range errs {
		if i == 3 {
			t.Errorf("... and %d more errors", len(errs)-3)
			break
		}
		t.Error(err)
	}
}
