package server

import (
	"context"
	"log"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

// hostPort matches an IPv4 or bracketed IPv6 socket address (a zone name such as %eth0 included), the form Go's
// net and crypto/tls errors print for both ends of a connection.
var hostPort = regexp.MustCompile(`(?:\d{1,3}(?:\.\d{1,3}){3}|\[[^\]\s]+\]):\d+`)

// scrubAddrs replaces every socket address in a stdlib log line, so the line
// keeps its reason and loses the peer (REQ-OBS-006).
func scrubAddrs(line string) string {
	return hostPort.ReplaceAllString(line, "<addr>")
}

type scrubWriter struct{ h slog.Handler }

func (w scrubWriter) Write(p []byte) (int, error) {
	msg := scrubAddrs(strings.TrimRight(string(p), "\n"))
	if w.h.Enabled(context.Background(), slog.LevelDebug) {
		var pcs [1]uintptr
		r := slog.NewRecord(time.Now(), slog.LevelDebug, msg, pcs[0])
		_ = w.h.Handle(context.Background(), r)
	}
	return len(p), nil
}

// NewErrorLog is the logger for http.Server.ErrorLog: Go's own server errors
// (TLS handshake failures and the like) reach the process handler at DEBUG,
// with every socket address in the line replaced, since those lines name the
// connecting client and REQ-OBS-006 forbids a client address in any log.
func NewErrorLog(h slog.Handler) *log.Logger {
	return log.New(scrubWriter{h}, "", 0)
}
