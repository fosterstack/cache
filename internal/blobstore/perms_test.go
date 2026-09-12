package blobstore

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// REQ-STORE-003-AC1: directories 0750, blob files 0600, all the way down.
func TestOnDiskPermissionsAreTight(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Put("a/nested/key", strings.NewReader("bytes")); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		if path == dir {
			// The root was created by the test harness, not the store;
			// the requirement covers what the STORE creates.
			return nil
		}
		if d.IsDir() && perm != 0o750 {
			t.Errorf("dir %s has mode %o, want 750", path, perm)
		}
		if !d.IsDir() && perm != 0o600 {
			t.Errorf("file %s has mode %o, want 600", path, perm)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
