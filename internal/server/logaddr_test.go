package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// addrErr is the error a dropped client connection produces: a *net.OpError
// whose text carries both socket addresses, here wrapped the way io.Copy
// and the store wrap it.
func addrErr() error {
	op := &net.OpError{
		Op:     "write",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.ParseIP("10.9.8.7"), Port: 8080},
		Addr:   &net.TCPAddr{IP: net.ParseIP("203.0.113.55"), Port: 49152},
		Err:    errors.New("broken pipe"),
	}
	return fmt.Errorf("copy: %w", op)
}

func assertNoClientAddr(t *testing.T, logged string) {
	t.Helper()
	for _, leak := range []string{"203.0.113.55", "10.9.8.7", "49152", "8080"} {
		if strings.Contains(logged, leak) {
			t.Errorf("log %q carries a client or socket address (%s)", logged, leak)
		}
	}
	if !strings.Contains(logged, "broken pipe") {
		t.Errorf("log %q lost the reason (broken pipe)", logged)
	}
}

// REQ-OBS-006-AC1 (statement: never a client address): a failure log never carries a client address, even when
// the error is a *net.OpError whose text formats both socket addresses.
func TestShortWriteLogCarriesNoClientAddress(t *testing.T) {
	c := newTestCache(t)
	if _, err := c.Put(t.Context(), "k", strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	log, buf := captureLogger()
	w := &errWriter{err: addrErr()}
	handleGet(w, httptest.NewRequest(http.MethodGet, "/k", nil), Config{Cache: c, Log: log}, "k")
	assertNoClientAddr(t, buf.String())
}

// REQ-OBS-006-AC1 (statement: never a client address), the store-error site.
func TestStoreErrorLogCarriesNoClientAddress(t *testing.T) {
	log, buf := captureLogger()
	writeStoreError(httptest.NewRecorder(), Config{Log: log}, addrErr(), "PUT", "somekey")
	logged := buf.String()
	assertNoClientAddr(t, logged)
	for _, want := range []string{"PUT", "somekey"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q lost %q", logged, want)
		}
	}
}

// An error with no network part is logged unchanged.
func TestLogErrorPassesPlainErrorsThrough(t *testing.T) {
	if got := loggableErr(errors.New("disk on fire")); got != "disk on fire" {
		t.Errorf("loggableErr = %q, want the error text unchanged", got)
	}
}

// errWriter is a ResponseWriter whose Write fails with a chosen error.
type errWriter struct {
	failingWriter
	err error
}

func (w *errWriter) Write([]byte) (int, error) { return 0, w.err }
