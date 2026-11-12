package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// REQ-OBS-006-AC1 (statement: never a client address) for the lines Go's
// own http.Server writes through ErrorLog; rc-1 ruling, fix 1 (side find).
func TestErrorLogScrubsPeerAddresses(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := NewErrorLog(h)

	// The exact lines net/http and crypto/tls produce.
	l.Printf("http: TLS handshake error from 127.0.0.1:53969: client sent an HTTP request to an HTTPS server")
	l.Printf("http: TLS handshake error from 203.0.113.55:53973: read tcp 10.9.8.7:8443->203.0.113.55:53973: read: connection reset by peer")
	l.Printf("http: TLS handshake error from [2001:db8::7]:41000: EOF")
	zoned := "http: TLS handshake error from [fe80::1%eth0]:41001: EOF" // a variable: vet reads %e in a constant as a verb
	l.Print(zoned)
	logged := buf.String()

	for _, leak := range []string{"127.0.0.1", "203.0.113.55", "10.9.8.7", "2001:db8", "fe80::1", "eth0", "41001", "53969", "53973", "41000", "8443"} {
		if strings.Contains(logged, leak) {
			t.Errorf("log carries an address token %q:\n%s", leak, logged)
		}
	}
	for _, want := range []string{"TLS handshake error", "client sent an HTTP request to an HTTPS server", "connection reset by peer", "EOF"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log lost the reason %q:\n%s", want, logged)
		}
	}
	if !strings.Contains(logged, "level=DEBUG") {
		t.Errorf("lines must stay at DEBUG:\n%s", logged)
	}
}
