package blobstore

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newTestStore(t)
	const key = "abc123def4567890abc123def4567890abc123def4567890abc123def45678"
	payload := []byte("hello, cache")

	n, err := s.Put(key, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("Put wrote %d bytes, want %d", n, len(payload))
	}

	rc, size, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	if size != int64(len(payload)) {
		t.Fatalf("Get size = %d, want %d", size, len(payload))
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestGetMissingReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	_, _, err := s.Get("deadbeef")
	if err != ErrNotFound {
		t.Fatalf("Get missing key: err = %v, want ErrNotFound", err)
	}
}

func TestStatMissingReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Stat("deadbeef")
	if err != ErrNotFound {
		t.Fatalf("Stat missing key: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteMissingIsNotAnError(t *testing.T) {
	s := newTestStore(t)
	if err := s.Delete("deadbeef"); err != nil {
		t.Fatalf("Delete missing key: %v", err)
	}
}

func TestPutOverwrite(t *testing.T) {
	s := newTestStore(t)
	const key = "overwritekey"
	if _, err := s.Put(key, strings.NewReader("first")); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	if _, err := s.Put(key, strings.NewReader("second-longer")); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	rc, _, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "second-longer" {
		t.Fatalf("got %q, want %q", got, "second-longer")
	}
}

func TestNestedKeySupportsMavenLayout(t *testing.T) {
	s := newTestStore(t)
	const key = "com.example/my-artifact/1.0.0/build-cache/deadbeefcafe"
	if _, err := s.Put(key, strings.NewReader("maven blob")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, _, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "maven blob" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateKeyRejectsTraversal(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"a/../../etc/passwd",
		"..",
		".",
		"",
		"a/b/../c",
		strings.Repeat("a/", 20) + "leaf",
	}
	for _, c := range cases {
		if err := ValidateKey(c); err == nil {
			t.Errorf("ValidateKey(%q) = nil, want error", c)
		}
	}
}

func TestValidateKeyAcceptsExpectedShapes(t *testing.T) {
	cases := []string{
		"deadbeefcafefeed0123456789abcdef",
		"com.example/artifact/1.0.0/deadbeef",
		"a.b_c-d",
	}
	for _, c := range cases {
		if err := ValidateKey(c); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want nil", c, err)
		}
	}
}

func TestPathEscapeIsRejectedNotJustSanitized(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Put("../outside", strings.NewReader("x"))
	if err != ErrInvalidKey {
		t.Fatalf("Put with traversal key: err = %v, want ErrInvalidKey", err)
	}
	// Confirm nothing escaped the root.
	outside := filepath.Join(filepath.Dir(s.Root()), "outside")
	if _, statErr := s.Stat("outside"); statErr == nil {
		t.Fatalf("unexpected file materialized at %s", outside)
	}
}
