//go:build !unix

package main

import "os"

// openTLSFileNoWait is a plain open where there are no FIFOs to wait on.
func openTLSFileNoWait(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- the operator names this file in FSCACHE_TLS_CERT or FSCACHE_TLS_KEY; reading it is the feature
}
