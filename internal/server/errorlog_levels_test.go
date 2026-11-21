package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func errorLogOutput(t *testing.T, lines ...string) string {
	t.Helper()
	var buf bytes.Buffer
	l := NewErrorLog(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	for _, line := range lines {
		l.Print(line)
	}
	return buf.String()
}

// Rule 2 (error log levels): a TLS handshake error is DEBUG, so an INFO handler drops it.
func TestErrorLogHandshakeIsDebug(t *testing.T) {
	out := errorLogOutput(t, "http: TLS handshake error from 203.0.113.5:4411: EOF")
	if out != "" {
		t.Errorf("handshake error logged at INFO or above: %q", out)
	}
	var buf bytes.Buffer
	l := NewErrorLog(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	l.Print("http: TLS handshake error from 203.0.113.5:4411: EOF")
	got := buf.String()
	if !strings.Contains(got, "level=DEBUG") || strings.Contains(got, "203.0.113.5") || !strings.Contains(got, "<addr>") {
		t.Errorf("handshake line = %q, want DEBUG with <addr>", got)
	}
}

// Rule 2: any other line is ERROR and its socket addresses are still replaced by <addr>.
func TestErrorLogOtherLinesAreError(t *testing.T) {
	out := errorLogOutput(t,
		"http: panic serving 203.0.113.5:4411: boom\ngoroutine 7 [running]:\nmain.handler(0x1)\n\t/src/x.go:10 +0x1f",
		"http: Accept error: accept tcp 10.0.0.1:8443: too many open files; retrying in 5ms",
		"http: TLS handshake error from 203.0.113.5:4411: EOF",
	)
	if n := strings.Count(out, "level=ERROR"); n != 2 {
		t.Errorf("ERROR lines = %d, want 2; output %q", n, out)
	}
	if strings.Contains(out, "handshake") {
		t.Errorf("handshake line appeared at INFO: %q", out)
	}
	for _, leak := range []string{"203.0.113.5", "10.0.0.1", "4411", "8443"} {
		if strings.Contains(out, leak) {
			t.Errorf("output carries %s: %q", leak, out)
		}
	}
	if !strings.Contains(out, "<addr>") || !strings.Contains(out, "boom") || !strings.Contains(out, "too many open files") {
		t.Errorf("output lost content: %q", out)
	}
}
