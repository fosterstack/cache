//go:build linux || darwin

package storesample

import "syscall"

// availFromStatfs is the number `df` shows as Avail: blocks available to an
// unprivileged process times the block size (not the free blocks).
func availFromStatfs(st *syscall.Statfs_t) uint64 {
	bs := toInt64(st.Bsize) // uint32 on darwin, int64 on linux: the generic helper converts on both without a conversion that is a no-op on one of them
	if bs <= 0 {
		return 0
	}
	return st.Bavail * uint64(bs) // #nosec G115 -- bs > 0 checked above
}

// toInt64 widens the block size whatever its platform type is (a plain int64(x) is flagged as unnecessary where the field already is int64).
func toInt64[T ~int64 | ~uint32](v T) int64 { return int64(v) }

func realStatfs(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return availFromStatfs(&st), nil
}
