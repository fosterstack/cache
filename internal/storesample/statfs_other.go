//go:build !linux && !darwin

package storesample

import "errors"

// realStatfs: a platform without statfs reports an error, which the sampler
// turns into free bytes 0 and writable 0 (fail loud, not silently healthy).
func realStatfs(string) (uint64, error) {
	return 0, errors.New("statfs is not supported on this platform")
}
