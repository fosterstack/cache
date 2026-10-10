package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

// AC4: every FSCACHE_ name the code reads is in knownEnv, and every
// knownEnv entry is read. The scan walks every non-test .go file under
// cmd/ and internal/ with go/ast and takes every string literal that IS a
// variable name (the whole literal matches FSCACHE_[A-Z0-9_]+) - not only
// the ones passed to os.Getenv, so a name hidden behind any helper is
// still found. Prose such as error messages is not a whole-literal match,
// so there are no false positives today. The knownEnv declaration itself
// is skipped so it cannot vouch for itself.
func TestKnownEnvMatchesNamesReadInCode(t *testing.T) {
	nameRE := regexp.MustCompile(`^FSCACHE_[A-Z0-9_]+$`)
	used := map[string]string{}
	fset := token.NewFileSet()
	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if vs, ok := n.(*ast.ValueSpec); ok && len(vs.Names) == 1 && vs.Names[0].Name == "knownEnv" {
					return false
				}
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && nameRE.MatchString(v) {
						used[v] = p
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(used) == 0 {
		t.Fatal("scan found no FSCACHE_ names at all")
	}
	for name, file := range used {
		if !slices.Contains(knownEnv, name) {
			t.Errorf("%s reads %s, which is not in knownEnv", file, name)
		}
	}
	for _, k := range knownEnv {
		if _, ok := used[k]; !ok {
			t.Errorf("knownEnv lists %s but no non-test code reads it", k)
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
		"FSCACHE_AXXR":         "FSCACHE_ADDR", // two substitutions: distance 2, a hint
		"FSCACHE_AXXXR":        "",             // distance 3 from FSCACHE_ADDR: the boundary, no hint
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

// AC6 tie-break: at equal distance the name earlier in knownEnv wins, and
// the nearer name wins over an earlier but farther one.
func TestUnknownEnvDidYouMeanTieAndNearest(t *testing.T) {
	orig := knownEnv
	defer func() { knownEnv = orig }()
	knownEnv = []string{"FSCACHE_AAAA", "FSCACHE_AAAB", "FSCACHE_ZZZZ"}
	if got := nearestKnown("FSCACHE_AAAC"); got != "FSCACHE_AAAA" {
		t.Errorf("tie: got %q, want the first of the equally near names, FSCACHE_AAAA", got)
	}
	knownEnv = []string{"FSCACHE_AAXX", "FSCACHE_AAAB", "FSCACHE_ZZZZ"}
	if got := nearestKnown("FSCACHE_AAAC"); got != "FSCACHE_AAAB" {
		t.Errorf("nearest: got %q, want the nearer FSCACHE_AAAB over the earlier, farther FSCACHE_AAXX", got)
	}
}
