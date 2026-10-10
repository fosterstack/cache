//go:build linux || darwin

package storesample

import "syscall"

// availFromStatfs is the number `df` shows as Avail: blocks available to an
// unprivileged process times the block size (not the free blocks).
func availFromStatfs(st *syscall.Statfs_t) uint64 {
	bs := int64(st.Bsize) // uint32 on darwin, int64 on linux
	if bs <= 0 {
		return 0
	}
	return st.Bavail * uint64(bs) // #nosec G115 -- bs > 0 checked above
}

func realStatfs(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return availFromStatfs(&st), nil
}
