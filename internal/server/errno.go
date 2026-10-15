package server

import (
	"errors"
	"syscall"
)

// isNoSpace: the device is full or a quota is exceeded (includes inode exhaustion).
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

// isReadOnly: a read-only mount or wrong permissions on the data directory.
func isReadOnly(err error) bool {
	return errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}
