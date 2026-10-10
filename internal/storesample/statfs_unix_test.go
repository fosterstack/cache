//go:build linux || darwin

package storesample

import (
	"path/filepath"
	"syscall"
	"testing"
)

// REQ-OBS-002-AC6: free bytes are the blocks available to an unprivileged
// process (Bavail) times the block size, never the free blocks (Bfree).
func TestAvailIsBavailTimesBsize(t *testing.T) {
	st := &syscall.Statfs_t{}
	st.Bfree, st.Bavail, st.Bsize = 100, 10, 4096
	if got := availFromStatfs(st); got != 40960 {
		t.Fatalf("availFromStatfs = %d; want 40960 (Bavail*Bsize)", got)
	}
}

// a directory that does not exist is a statfs error (the sampler turns it into free 0, not writable)
func TestRealStatfsOnMissingDirIsAnError(t *testing.T) {
	if _, err := realStatfs(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("statfs on a missing directory returned no error")
	}
	if n, err := realStatfs(t.TempDir()); err != nil || n == 0 {
		t.Fatalf("statfs on a real directory = %d, %v", n, err)
	}
}
