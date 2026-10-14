//go:build unix

package main

import (
	"os"
	"syscall"
)

// openTLSFileNoWait opens path for reading without waiting: O_NONBLOCK makes
// the open of a FIFO with no writer return at once instead of blocking (a
// path can be swapped for one after readTLSFile's stat), and the handle is
// then checked to be a regular file before anything is read. A regular file
// opened this way reads normally.
func openTLSFileNoWait(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- the operator names this file in FSCACHE_TLS_CERT or FSCACHE_TLS_KEY; reading it is the feature
}
