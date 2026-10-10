package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// REQ-CFG-005: unknown FSCACHE_ variables are reported, once each, and
// never stop the server.

const unknownMsg = "fscache: unknown environment variable ignored"

type logRec struct {
	Level      string `json:"level"`
	Msg        string `json:"msg"`
	Name       string `json:"name"`
	DidYouMean string `json:"did_you_mean"`
}

func captureWarnings(t *testing.T, environ []string) (string, []logRec) {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	warnUnknownEnv(log, environ)
	var recs []logRec
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var r logRec
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return buf.String(), recs
}

// AC1: one warning per unknown name, sorted by name, at WARN with the
// exact message; case-sensitive FSCACHE_ prefix; other names ignored.
func TestUnknownEnvOneWarningPerName(t *testing.T) {
	_, recs := captureWarnings(t, []string{
		"FSCACHE_MAX_BYTE=1", "FSCACHE_FOO=x", "fscache_addr=:1", "PATH=/bin", "FSCACHE_ADDR=:9",
	})
	if len(recs) != 2 {
		t.Fatalf("got %d warnings, want 2: %+v", len(recs), recs)
	}
	for _, r := range recs {
		if r.Level != "WARN" || r.Msg != unknownMsg {
			t.Errorf("record %+v: want WARN %q", r, unknownMsg)
		}
	}
	if recs[0].Name != "FSCACHE_FOO" || recs[1].Name != "FSCACHE_MAX_BYTE" {
		t.Errorf("names = %q, %q; want sorted FSCACHE_FOO, FSCACHE_MAX_BYTE", recs[0].Name, recs[1].Name)
	}
}

// AC1 (exit status): the server starts and shuts down normally with an
// unknown variable present, and the warning reaches its log.
func TestUnknownEnvDoesNotStopStartup(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", freePort(t))
	t.Setenv("FSCACHE_MAX_BYTE", "1")
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, log, func() { cancel() }) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v with an unknown variable set", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
	if strings.Count(buf.String(), unknownMsg) != 1 || !strings.Contains(buf.String(), "FSCACHE_MAX_BYTE") {
		t.Errorf("expected exactly one unknown-variable warning in the log, got: %s", buf.String())
	}
}

// AC1 (config still wins): an invalid configuration still fails before
// any warning matters - the warning never changes the outcome.
func TestUnknownEnvDoesNotMaskInvalidConfig(t *testing.T) {
	clearEnv(t)
	t.Setenv("FSCACHE_MAX_BYTES", "20GiB")
	t.Setenv("FSCACHE_TYPO", "1")
	if _, err := loadConfig(); err == nil {
		t.Fatal("invalid config accepted")
	}
}

// AC2: the same name twice in the environment slice warns once.
func TestUnknownEnvDuplicateNameWarnsOnce(t *testing.T) {
	_, recs := captureWarnings(t, []string{"FSCACHE_FOO=1", "FSCACHE_FOO=2"})
	if len(recs) != 1 {
		t.Fatalf("got %d warnings, want 1", len(recs))
	}
}

// AC3: the value is never logged, not even a value that looks secret.
func TestUnknownEnvNeverLogsTheValue(t *testing.T) {
	raw, recs := captureWarnings(t, []string{"FSCACHE_PASWORD=hunter2-secret", "FSCACHE_X=a=b=hunter2-secret"})
	if len(recs) != 2 {
		t.Fatalf("got %d warnings, want 2", len(recs))
	}
	if strings.Contains(raw, "hunter2") || strings.Contains(raw, "secret") {
		t.Errorf("a value reached the log: %s", raw)
	}
}

// AC4: every documented variable is known, and every known variable is
// documented in the README configuration table.
func TestKnownEnvMatchesREADMETable(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`FSCACHE_[A-Z0-9_]+`)
	var documented []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "| `FSCACHE_") {
			documented = append(documented, re.FindAllString(line, -1)...)
		}
	}
	if len(documented) == 0 {
		t.Fatal("found no documented variables in the README table")
	}
	for _, d := range documented {
		if !slices.Contains(knownEnv, d) {
			t.Errorf("documented variable %s is not in knownEnv", d)
		}
	}
	for _, k := range knownEnv {
		if !slices.Contains(documented, k) {
			t.Errorf("known variable %s is not documented in the README table", k)
		}
	}
}

// AC4: the code reads variables only by names that are in knownEnv, and
// every knownEnv entry is read: no FSCACHE_ literal outside the list.
func TestKnownEnvMatchesNamesReadInCode(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	// Drop the knownEnv declaration itself.
	if i := strings.Index(text, "var knownEnv"); i >= 0 {
		if j := strings.Index(text[i:], "\n}\n"); j >= 0 {
			text = text[:i] + text[i+j:]
		}
	}
	re := regexp.MustCompile(`"(FSCACHE_[A-Z0-9_]+)"`)
	used := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		used[m[1]] = true
		if !slices.Contains(knownEnv, m[1]) {
			t.Errorf("main.go reads %s, which is not in knownEnv", m[1])
		}
	}
	for _, k := range knownEnv {
		if !used[k] {
			t.Errorf("knownEnv lists %s but main.go never reads it", k)
		}
	}
}

// AC5: known names are never warned about, whatever their value.
func TestKnownEnvNamesNeverWarned(t *testing.T) {
	var environ []string
	for _, k := range knownEnv {
		environ = append(environ, k+"=")
	}
	environ = append(environ, "FSCACHE_USERNAME=")
	if len(knownEnv) == 0 {
		t.Fatal("knownEnv is empty")
	}
	if _, recs := captureWarnings(t, environ); len(recs) != 0 {
		t.Errorf("known names produced warnings: %+v", recs)
	}
}

// AC6: a near miss (Levenshtein distance <= 2 to a known name) carries
// did_you_mean naming the known variable; a far name carries none; the
// suggestion is always a known name, never user text.
func TestUnknownEnvDidYouMean(t *testing.T) {
	cases := map[string]string{
		"FSCACHE_MAX_BYTE":     "FSCACHE_MAX_BYTES",
		"FSCACHE_DATADIR":      "FSCACHE_DATA_DIR",
		"FSCACHE_PASWORD":      "FSCACHE_PASSWORD",
		"FSCACHE_ADRS":         "FSCACHE_ADDR",
		"FSCACHE_COMPLETELY_X": "",
		"FSCACHE_":             "",
	}
	for name, want := range cases {
		_, recs := captureWarnings(t, []string{name + "=v"})
		if len(recs) != 1 {
			t.Fatalf("%s: got %d warnings", name, len(recs))
		}
		if recs[0].DidYouMean != want {
			t.Errorf("%s: did_you_mean = %q, want %q", name, recs[0].DidYouMean, want)
		}
	}
}
