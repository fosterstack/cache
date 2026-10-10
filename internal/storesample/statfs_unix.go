//go:build linux || darwin

package storesample

import "syscall"

// availFromStatfs is the number `df` shows as Avail: blocks available to an
// unprivileged process times the block size (not the free blocks).
func availFromStatfs(st *syscall.Statfs_t) uint64 { return uint64(st.Bavail) * uint64(st.Bsize) }

func realStatfs(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return availFromStatfs(&st), nil
}
