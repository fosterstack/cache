//go:build linux || darwin

package storesample

import (
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
