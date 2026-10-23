//go:build unix

package blobstore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO at a key's path would block an open; Get and Stat must answer not
// found without opening it, and the walk must not report it.
func TestFifoAtAKeysPathIsNotFoundAndDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	defer func() { _ = s.Close() }()
	put(t, s, "realkey", "real")
	if err := os.MkdirAll(filepath.Join(dir, "pi"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pi", "pipekey"), 0o600); err != nil {
		t.Skipf("no fifos here: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		wantNotFound(t, s, "pipekey")
		if k := walkKeys(t, s); has(k, "pipekey") || !has(k, "realkey") {
			t.Errorf("Walk keys = %v, want realkey and not pipekey", k)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Get/Stat/Walk blocked on a FIFO at a key's path")
	}
}
