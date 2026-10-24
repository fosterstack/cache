//go:build unix

package blobstore

import (
	"errors"
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

// Between the check and the open, something may replace the regular file
// with a FIFO: the open must not block on it (and the same-file check then
// refuses it).
func TestGetDoesNotBlockWhenAFifoReplacesTheBlobBeforeTheOpen(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	put(t, s, "abc", "payload")
	production := rootOpen
	setSeam(t, &rootOpen, func(r *os.Root, name string) (*os.File, error) {
		_ = r.Remove(name)
		if err := syscall.Mkfifo(filepath.Join(s.Root(), name), 0o600); err != nil {
			t.Skipf("no fifos here: %v", err)
		}
		return production(r, name)
	})
	done := make(chan error, 1)
	go func() {
		rc, _, err := s.Get("abc")
		if rc != nil {
			_ = rc.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("Get: err = %v, want ErrNotFound", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Get blocked on a FIFO that replaced the blob")
	}
}
