package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// withCapture runs fn with os.Stdout and os.Stderr redirected to pipes,
// returning everything written to each, plus the value fn panicked with
// (nil if it returned normally). fatal aborts by panicking an exitCode,
// so direct calls to functions that may call fatal are driven through
// this helper.
func withCapture(t *testing.T, fn func()) (stdout, stderr string, panicked any) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	func() {
		defer func() { panicked = recover() }()
		fn()
	}()
	os.Stdout, os.Stderr = oldOut, oldErr
	_ = wOut.Close()
	_ = wErr.Close()
	ob, _ := io.ReadAll(rOut)
	eb, _ := io.ReadAll(rErr)
	return string(ob), string(eb), panicked
}

// runCommand drives runCLI exactly as main would, returning the exit
// code and the captured output streams.
func runCommand(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var p any
	stdout, stderr, p = withCapture(t, func() {
		code = runCLI(append([]string{"requirements"}, args...))
	})
	if p != nil {
		t.Fatalf("runCLI leaked a panic: %v", p)
	}
	return code, stdout, stderr
}

// wantFatalDirect runs fn, requires it to abort via fatal (exit code 1),
// and requires the fatal message on stderr to contain fragment.
func wantFatalDirect(t *testing.T, fragment string, fn func()) {
	t.Helper()
	_, stderr, p := withCapture(t, fn)
	if p == nil {
		t.Fatalf("expected a fatal abort mentioning %q, function returned normally", fragment)
	}
	c, ok := p.(exitCode)
	if !ok {
		t.Fatalf("unexpected panic value %v", p)
	}
	if int(c) != 1 {
		t.Fatalf("fatal exit code = %d, want 1", int(c))
	}
	if !strings.Contains(stderr, fragment) {
		t.Fatalf("fatal stderr %q does not mention %q", stderr, fragment)
	}
}

// fakeGit prepends a directory to PATH containing a `git` shell script
// with the given body, so repoRoot sees a controlled git.
func fakeGit(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// gitInitHere turns the current directory (a test fixture) into a real
// git repository so repoRoot can resolve it.
func gitInitHere(t *testing.T) {
	t.Helper()
	out, err := exec.Command("git", "init", "-q", ".").CombinedOutput()
	if err != nil {
		t.Skipf("git init unavailable: %v (%s)", err, out)
	}
}

// chdirTemp moves into a fresh temp directory that contains no
// requirements file, restoring the previous directory on cleanup.
func chdirTemp(t *testing.T) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatal(err)
		}
	})
}

// richYAML is a schema-valid approved baseline exercising every render
// branch: multiple groups (known and unknown titles), a deprecated
// requirement, release-blocking ACs (candidate and publication phase),
// notes, and pipes needing escaping.
const richYAML = `baseline:
  extracted_from: acd8bac2f9427dee63c71384dcbfecdb5c7ccf1b
  extracted_on: 2026-09-08
  approved: true
  approved_on: 2026-09-11
requirements:
  - id: REQ-PROTO-001
    title: Proto requirement
    statement: The server shall speak the protocol correctly.
    source: [docs/proto.md]
    tier: community
    introduced: v0.1.0
    confidence: documented
    notes: |
      Multi-line
      note text.
    acceptance_criteria:
      - id: REQ-PROTO-001-AC1
        given: a running server
        when: a client sends | a request
        then: it responds
        verification: { method: unit, release_blocking: true }
        status: approved
      - id: REQ-PROTO-001-AC2
        given: a running server
        when: something else happens
        then: it still responds
        verification: { method: manual }
        status: approved
  - id: REQ-ZZZQ-001
    title: Unknown group requirement
    statement: The server shall also do the unknown-group thing.
    source: [docs/zzz.md]
    tier: team
    introduced: v0.1.0
    confidence: implementation-only
    acceptance_criteria:
      - id: REQ-ZZZQ-001-AC1
        given: some context
        when: some action
        then: some outcome
        verification: { method: inspection, release_blocking: false }
        status: approved
  - id: REQ-REL-001
    title: Release requirement
    statement: Releases shall be signed and verifiable by anyone.
    source: [docs/release.md]
    tier: community
    introduced: v0.1.0
    confidence: documented
    acceptance_criteria:
      - id: REQ-REL-001-AC1
        given: a published release
        when: a verifier checks the signature
        then: verification succeeds
        verification: { method: acceptance-release-artifact, release_blocking: true }
        status: approved
  - id: REQ-OLD-001
    title: Old deprecated requirement
    statement: The server shall do the old thing nobody needs.
    source: [docs/old.md]
    tier: community
    introduced: v0.1.0
    confidence: documented
    deprecated: true
    deprecated_reason: replaced by the new thing
    acceptance_criteria:
      - id: REQ-OLD-001-AC1
        given: old context
        when: old action
        then: old outcome
        verification: { method: unit, release_blocking: true }
        status: approved
`

const richMappings = `mappings:
  - ac: REQ-PROTO-001-AC1
    evidence:
      - type: manual
        ref: docs/manual-check.md
`

func richFixture(t *testing.T) {
	t.Helper()
	fixture(t, richYAML)
	if err := os.WriteFile("test-evidence/mappings.yaml", []byte(richMappings), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ── main() and the exit seam ─────────────────────────────────────────

func TestMainDelegatesToRunCLIThroughExitSeam(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	oldArgs, oldExit := os.Args, exit
	defer func() { os.Args, exit = oldArgs, oldExit }()
	got := -1
	exit = func(code int) { got = code }
	os.Args = []string{"requirements", "validate"}
	stdout, _, p := withCapture(t, main)
	if p != nil {
		t.Fatalf("main panicked: %v", p)
	}
	if got != 0 {
		t.Fatalf("main exited with %d, want 0", got)
	}
	if !strings.Contains(stdout, "requirements: valid") {
		t.Fatalf("main stdout %q lacks success message", stdout)
	}
}

// ── runCLI dispatch ──────────────────────────────────────────────────

func TestRunCLIWithoutSubcommandPrintsUsage(t *testing.T) {
	code, _, stderr := runCommand(t)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "usage: requirements validate|generate|check|freeze") {
		t.Fatalf("stderr %q lacks usage", stderr)
	}
}

func TestRunCLIUnknownCommandFails(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	code, _, stderr := runCommand(t, "frobnicate")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, `unknown command "frobnicate"`) {
		t.Fatalf("stderr %q lacks unknown-command message", stderr)
	}
}

func TestRunCLIValidateSucceeds(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	code, stdout, _ := runCommand(t, "validate")
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "requirements: valid") {
		t.Fatalf("stdout %q lacks success message", stdout)
	}
}

func TestRunCLIValidateReportsSemanticErrorsAndExits1(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", "    deprecated: true"))
	code, _, stderr := runCommand(t, "validate")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "deprecated without a deprecated_reason") {
		t.Fatalf("stderr %q lacks the validation error", stderr)
	}
}

func TestRunCLIValidateFailsWhenLoadFails(t *testing.T) {
	fixture(t, "bogus_top_level: true\n"+minimal("false", "", "2026-09-08", "proposed", ""))
	code, _, stderr := runCommand(t, "validate")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "parse requirements/requirements.yaml") {
		t.Fatalf("stderr %q lacks parse error", stderr)
	}
}

func TestRunCLIGenerateWritesRenderedMatrix(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	code, stdout, _ := runCommand(t, "generate")
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "wrote docs/quality/traceability.md") {
		t.Fatalf("stdout %q lacks wrote message", stdout)
	}
	got, err := os.ReadFile("docs/quality/traceability.md")
	if err != nil {
		t.Fatal(err)
	}
	f, m := mustLoadOK(t)
	if string(got) != render(f, m) {
		t.Fatal("generated file does not match render output")
	}
}

func TestRunCLIGenerateFailsWhenOutputUnwritable(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	if err := os.RemoveAll("docs/quality"); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "generate")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "write docs/quality/traceability.md") {
		t.Fatalf("stderr %q lacks write error", stderr)
	}
}

func TestRunCLICheckFreshStaleAndMissing(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	if code, _, _ := runCommand(t, "generate"); code != 0 {
		t.Fatal("generate failed")
	}
	code, stdout, _ := runCommand(t, "check")
	if code != 0 || !strings.Contains(stdout, "requirements: valid; matrix fresh") {
		t.Fatalf("fresh check: code=%d stdout=%q", code, stdout)
	}

	if err := os.WriteFile("docs/quality/traceability.md", []byte("stale content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "check")
	if code != 1 || !strings.Contains(stderr, "STALE") {
		t.Fatalf("stale check: code=%d stderr=%q", code, stderr)
	}

	if err := os.Remove("docs/quality/traceability.md"); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCommand(t, "check")
	if code != 1 || !strings.Contains(stderr, "missing") {
		t.Fatalf("missing check: code=%d stderr=%q", code, stderr)
	}
}

// ── repo-root resolution ─────────────────────────────────────────────

func TestRunCLIChdirsToGitRepoRoot(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	gitInitHere(t)
	if err := os.Chdir("docs"); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCommand(t, "validate")
	if code != 0 {
		t.Fatalf("code = %d, want 0 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stdout, "requirements: valid") {
		t.Fatalf("stdout %q lacks success message", stdout)
	}
}

func TestRunCLIFailsOutsideGitRepoWithoutRequirements(t *testing.T) {
	fakeGit(t, "exit 1")
	chdirTemp(t)
	code, _, stderr := runCommand(t, "validate")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "not in a git repository") {
		t.Fatalf("stderr %q lacks repo-root error", stderr)
	}
}

func TestRunCLIFailsWhenRepoRootIsNotChdirable(t *testing.T) {
	fakeGit(t, "echo /nonexistent/definitely-not-a-dir")
	chdirTemp(t)
	code, _, stderr := runCommand(t, "validate")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "chdir repo root") {
		t.Fatalf("stderr %q lacks chdir error", stderr)
	}
}

// ── freeze ───────────────────────────────────────────────────────────

func TestFreezeWritesUnapprovedBaseline(t *testing.T) {
	richFixture(t)
	code, stdout, stderr := runCommand(t, "freeze", "v0.2.0")
	if code != 0 {
		t.Fatalf("code = %d, want 0 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stdout, "wrote requirements/releases/v0.2.0.yaml (2 release-blocking ACs, UNAPPROVED)") {
		t.Fatalf("stdout %q lacks summary", stdout)
	}
	raw, err := os.ReadFile("requirements/releases/v0.2.0.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), "# GENERATED by `go -C tools/requirements run . freeze v0.2.0`.") {
		t.Fatalf("frozen file lacks generated header: %q", string(raw)[:80])
	}
	var frozen struct {
		Version         string `yaml:"version"`
		Approved        bool   `yaml:"approved"`
		ApprovedOn      string `yaml:"approved_on"`
		RequirementsSHA string `yaml:"requirements_sha256"`
		FrozenFrom      string `yaml:"frozen_from"`
		BlockingACs     []struct {
			ID     string `yaml:"id"`
			Method string `yaml:"method"`
			Phase  string `yaml:"phase"`
		} `yaml:"release_blocking_acs"`
	}
	if err := yaml.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen.Version != "v0.2.0" {
		t.Errorf("version = %q, want v0.2.0", frozen.Version)
	}
	if frozen.Approved || frozen.ApprovedOn != "" {
		t.Errorf("frozen baseline must be unapproved, got approved=%v approved_on=%q", frozen.Approved, frozen.ApprovedOn)
	}
	src, err := os.ReadFile("requirements/requirements.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%x", sha256.Sum256(src)); frozen.RequirementsSHA != want {
		t.Errorf("requirements_sha256 = %q, want %q", frozen.RequirementsSHA, want)
	}
	if frozen.FrozenFrom != "requirements/requirements.yaml" {
		t.Errorf("frozen_from = %q", frozen.FrozenFrom)
	}
	// Deprecated REQ-OLD-001-AC1 excluded; sorted; phases assigned.
	if len(frozen.BlockingACs) != 2 {
		t.Fatalf("release_blocking_acs = %+v, want 2 entries", frozen.BlockingACs)
	}
	if frozen.BlockingACs[0].ID != "REQ-PROTO-001-AC1" || frozen.BlockingACs[0].Phase != "candidate" || frozen.BlockingACs[0].Method != "unit" {
		t.Errorf("first blocking AC = %+v", frozen.BlockingACs[0])
	}
	if frozen.BlockingACs[1].ID != "REQ-REL-001-AC1" || frozen.BlockingACs[1].Phase != "publication" {
		t.Errorf("second blocking AC = %+v", frozen.BlockingACs[1])
	}
}

func TestFreezeRequiresExactlyOneVersionArg(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	for _, args := range [][]string{{"freeze"}, {"freeze", "v1", "extra"}} {
		code, _, stderr := runCommand(t, args...)
		if code != 1 {
			t.Fatalf("args %v: code = %d, want 1", args, code)
		}
		if !strings.Contains(stderr, "usage: requirements freeze <version>") {
			t.Fatalf("args %v: stderr %q lacks freeze usage", args, stderr)
		}
	}
}

func TestFreezeDirectlyResolvesRepoRoot(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	gitInitHere(t)
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("docs"); err != nil {
		t.Fatal(err)
	}
	_, _, p := withCapture(t, func() { freeze([]string{"requirements", "freeze", "v0.0.9"}) })
	if p != nil {
		t.Fatalf("freeze panicked: %v", p)
	}
	if _, err := os.Stat(filepath.Join(root, "requirements", "releases", "v0.0.9.yaml")); err != nil {
		t.Fatalf("frozen file not written at repo root: %v", err)
	}
}

func TestFreezeDirectlyFailsWhenRepoRootUnresolvable(t *testing.T) {
	fakeGit(t, "echo /nonexistent/definitely-not-a-dir")
	chdirTemp(t)
	wantFatalDirect(t, "chdir repo root", func() { freeze([]string{"requirements", "freeze", "v1.0.0"}) })
}

func TestFreezeFailsWhenRequirementsUnreadable(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	// A directory at the requirements path passes Stat but fails ReadFile,
	// covering the read error without permission tricks that break as root.
	if err := os.Remove("requirements/requirements.yaml"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("requirements/requirements.yaml", 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "freeze", "v1.0.0")
	if code != 1 || !strings.Contains(stderr, "read requirements/requirements.yaml") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestFreezeFailsOnMalformedYAML(t *testing.T) {
	fixture(t, "requirements: [unclosed\n")
	code, _, stderr := runCommand(t, "freeze", "v1.0.0")
	if code != 1 || !strings.Contains(stderr, "parse requirements/requirements.yaml") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestFreezeFailsWhenMarshalFails(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	old := yamlMarshal
	yamlMarshal = func(any) ([]byte, error) { return nil, errors.New("synthetic marshal failure") }
	defer func() { yamlMarshal = old }()
	code, _, stderr := runCommand(t, "freeze", "v1.0.0")
	if code != 1 || !strings.Contains(stderr, "marshal frozen baseline: synthetic marshal failure") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestFreezeFailsWhenReleasesDirBlocked(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	if err := os.WriteFile("requirements/releases", []byte("a file, not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "freeze", "v1.0.0")
	if code != 1 || !strings.Contains(stderr, "mkdir requirements/releases") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestFreezeFailsWhenOutputPathUnwritable(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	if err := os.MkdirAll("requirements/releases/v1.0.0.yaml", 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "freeze", "v1.0.0")
	if code != 1 || !strings.Contains(stderr, "write requirements/releases/v1.0.0.yaml") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// ── goTestExists ─────────────────────────────────────────────────────

func TestGoTestExistsSkipsAndErrors(t *testing.T) {
	dir := t.TempDir()
	// A subdirectory whose name carries the test suffix must be skipped.
	if err := os.Mkdir(filepath.Join(dir, "aaa_dir_test.go"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A non-test file mentioning the needle must not count.
	if err := os.WriteFile(filepath.Join(dir, "notatest.go"), []byte("func TestReal(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A dangling symlink with the suffix exercises the ReadFile error path.
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "dangling_test.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real_test.go"), []byte("package p\n\nfunc TestReal(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !goTestExists(dir, "TestReal") {
		t.Error("TestReal exists in real_test.go but was not found")
	}
	if goTestExists(dir, "TestOnlyInNonTestFile") {
		t.Error("found a test that exists nowhere")
	}
	if goTestExists(filepath.Join(dir, "absent"), "TestReal") {
		t.Error("nonexistent directory reported a test")
	}
}

// ── load / unmarshalStrict ───────────────────────────────────────────

func TestLoadFailsWhenRequirementsFileMissing(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	if err := os.Remove("requirements/requirements.yaml"); err != nil {
		t.Fatal(err)
	}
	_, _, err := load()
	if err == nil || !strings.Contains(err.Error(), "read requirements/requirements.yaml") {
		t.Fatalf("err = %v, want read error for requirements.yaml", err)
	}
}

func TestLoadFailsOnMappingsUnknownField(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	if err := os.WriteFile("test-evidence/mappings.yaml", []byte("bogus_field: 1\nmappings: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := load()
	if err == nil || !strings.Contains(err.Error(), "parse test-evidence/mappings.yaml") {
		t.Fatalf("err = %v, want parse error for mappings.yaml", err)
	}
}

// ── validate: semantic branches ──────────────────────────────────────

func TestDuplicateRequirementIDFails(t *testing.T) {
	dup := minimal("false", "", "2026-09-08", "proposed", "")
	block := dup[strings.Index(dup, "  - id: REQ-TEST-001"):]
	block = strings.ReplaceAll(block, "REQ-TEST-001-AC1", "REQ-TEST-001-AC2")
	fixture(t, dup+block)
	wantInvalid(t, "duplicate requirement id REQ-TEST-001")
}

func TestDuplicateACIDFails(t *testing.T) {
	doc := minimal("false", "", "2026-09-08", "proposed", "")
	acBlock := `      - id: REQ-TEST-001-AC1
        given: another fixture
        when: the validator runs again
        then: the duplicate is caught
        verification: { method: unit, release_blocking: false }
        status: proposed
`
	fixture(t, doc+acBlock)
	wantInvalid(t, "duplicate AC id REQ-TEST-001-AC1")
}

func TestACPrefixMismatchFails(t *testing.T) {
	doc := strings.Replace(minimal("false", "", "2026-09-08", "proposed", ""),
		"REQ-TEST-001-AC1", "REQ-OTHER-001-AC1", 1)
	fixture(t, doc)
	wantInvalid(t, "AC REQ-OTHER-001-AC1 does not belong to its requirement REQ-TEST-001")
}

func TestMappingToUnknownACFails(t *testing.T) {
	fixtureWithMappings(t, `mappings:
  - ac: REQ-NOPE-001-AC1
    evidence:
      - type: manual
        ref: docs/somewhere.md
`)
	wantInvalid(t, "unknown AC REQ-NOPE-001-AC1")
}

func TestMappingWithNoEvidenceFails(t *testing.T) {
	fixtureWithMappings(t, `mappings:
  - ac: REQ-TEST-001-AC1
    evidence: []
`)
	wantInvalid(t, "lists no evidence")
}

func TestMappingWithEmptyRefFails(t *testing.T) {
	fixtureWithMappings(t, `mappings:
  - ac: REQ-TEST-001-AC1
    evidence:
      - type: manual
        ref: "   "
`)
	wantInvalid(t, "empty manual ref")
}

func TestSchemaViolationIsReportedNotFatal(t *testing.T) {
	doc := strings.Replace(minimal("false", "", "2026-09-08", "proposed", ""),
		"tier: community", "tier: platinum", 1)
	fixture(t, doc)
	wantInvalid(t, "schema:")
}

func TestApprovedWithoutApprovedOnFails(t *testing.T) {
	fixture(t, minimal("true", "", "2026-09-08", "approved", ""))
	wantInvalid(t, "approved without approved_on")
}

// ── validate: fatal environment failures ─────────────────────────────

func TestValidateFatalWhenSchemaMissing(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := mustLoadOK(t)
	if err := os.Remove("requirements/schema.json"); err != nil {
		t.Fatal(err)
	}
	wantFatalDirect(t, "read requirements/schema.json", func() { validate(f, m) })
}

func TestValidateFatalWhenSchemaNotJSON(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := mustLoadOK(t)
	if err := os.WriteFile("requirements/schema.json", []byte("not json {"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantFatalDirect(t, "parse requirements/schema.json", func() { validate(f, m) })
}

func TestValidateFatalWhenSchemaResourceRejected(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := mustLoadOK(t)
	old := newCompiler
	newCompiler = func() *jsonschema.Compiler {
		c := jsonschema.NewCompiler()
		// Pre-register the schemaFile URL so validate's own AddResource
		// call collides and returns the library's ResourceExistsError.
		if err := c.AddResource(schemaFile, map[string]any{}); err != nil {
			t.Fatalf("pre-registering resource: %v", err)
		}
		return c
	}
	defer func() { newCompiler = old }()
	wantFatalDirect(t, "schema:", func() { validate(f, m) })
}

func TestValidateFatalWhenSchemaDoesNotCompile(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := mustLoadOK(t)
	// Valid JSON, but the $ref points at an unloadable URL, so Compile fails.
	bad := `{"$ref": "http://absent.invalid/schema.json"}`
	if err := os.WriteFile("requirements/schema.json", []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	wantFatalDirect(t, "compile schema", func() { validate(f, m) })
}

func TestValidateFatalWhenRequirementsUnreadableAtValidation(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := mustLoadOK(t)
	if err := os.Remove("requirements/requirements.yaml"); err != nil {
		t.Fatal(err)
	}
	wantFatalDirect(t, "read requirements/requirements.yaml", func() { validate(f, m) })
}

func TestValidateFatalWhenRequirementsUnparseableAtValidation(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := mustLoadOK(t)
	if err := os.WriteFile("requirements/requirements.yaml", []byte("requirements: [unclosed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantFatalDirect(t, "parse requirements/requirements.yaml", func() { validate(f, m) })
}

// ── toJSONTypes / groupTitle ─────────────────────────────────────────

func TestToJSONTypesConvertsEveryShape(t *testing.T) {
	in := map[string]any{
		"list": []any{1, "s", true, time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)},
		"n":    2,
		"nested": map[string]any{
			"when": time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		},
	}
	want := map[string]any{
		"list": []any{float64(1), "s", true, "2026-09-08"},
		"n":    float64(2),
		"nested": map[string]any{
			"when": "2025-01-02",
		},
	}
	if got := toJSONTypes(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("toJSONTypes = %#v, want %#v", got, want)
	}
}

func TestGroupTitleKnownAndUnknown(t *testing.T) {
	if got := groupTitle("PROTO"); got != "Cache protocol" {
		t.Errorf(`groupTitle("PROTO") = %q`, got)
	}
	if got := groupTitle("XYZQ"); got != "XYZQ" {
		t.Errorf(`groupTitle("XYZQ") = %q, want the group echoed back`, got)
	}
}

// ── render: approved baseline, notes, blocking, evidence, groups ─────

func TestRenderApprovedBaselineWithEvidenceAndGroups(t *testing.T) {
	richFixture(t)
	f, m := wantValid(t)
	out := render(f, m)

	for _, want := range []string{
		"approved by the owner on 2026-09-11.",
		"## Cache protocol",
		"## ZZZQ",
		"## Release evidence",
		"## OLD",
		"### REQ-OLD-001 — Old deprecated requirement (DEPRECATED)",
		"> **Deprecated:** replaced by the new thing",
		"> Multi-line note text.",
		"a client sends \\| a request",
		"| Active requirements | 3 |",
		"| Acceptance criteria | 4 |",
		"| Release-blocking ACs | 2 |",
		"| ACs with mapped evidence | 1 |",
		"| Release-blocking ACs with mapped evidence | 1 |",
		"| Confidence: documented | 2 |",
		"| Confidence: implementation-only | 1 |",
		"| unit | yes | approved | 1 item(s) |",
		"| manual |  | approved | none mapped |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output lacks %q", want)
		}
	}
	if !strings.HasSuffix(out, "|\n") || strings.HasSuffix(out, "\n\n") {
		t.Error("rendered output must end with exactly one trailing newline")
	}
}

// ── verify-freeze ────────────────────────────────────────────────────

func TestVerifyFreezeConsistent(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	code, stdout, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 0 {
		t.Fatalf("verify-freeze code = %d, want 0 (stderr %q)", code, stderr)
	}
	if !strings.Contains(stdout, "consistent with requirements.yaml") {
		t.Fatalf("stdout %q lacks the consistency confirmation", stdout)
	}
}

func TestVerifyFreezeRequiresVersionArg(t *testing.T) {
	richFixture(t)
	code, _, stderr := runCommand(t, "verify-freeze")
	if code != 1 || !strings.Contains(stderr, "usage: requirements verify-freeze") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeMissingFile(t *testing.T) {
	richFixture(t)
	code, _, stderr := runCommand(t, "verify-freeze", "v9.9.9")
	if code != 1 || !strings.Contains(stderr, "read requirements/releases/v9.9.9.yaml") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsStaleHash(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	// Mutate requirements.yaml after freezing: the recorded hash is now stale.
	raw, _ := os.ReadFile("requirements/requirements.yaml")
	if err := os.WriteFile("requirements/requirements.yaml", append(raw, []byte("\n# drift\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "does not match the current requirements.yaml") {
		t.Fatalf("stale hash not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsWrongVersion(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	// Rename the file so the on-disk version no longer matches the argument.
	raw, _ := os.ReadFile("requirements/releases/v0.2.0.yaml")
	if err := os.WriteFile("requirements/releases/v0.3.0.yaml", raw, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.3.0")
	if code != 1 || !strings.Contains(stderr, "version is") {
		t.Fatalf("wrong version not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsDroppedRequiredEntry(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	// Remove one release_blocking_acs entry from the frozen file only,
	// leaving requirements.yaml (and its hash) untouched by regenerating
	// the hash-bearing line? No - drop an entry AND keep hash: the hash is
	// of requirements.yaml, unchanged, so the count mismatch must fire.
	raw, _ := os.ReadFile("requirements/releases/v0.2.0.yaml")
	var fb map[string]any
	if err := yaml.Unmarshal(raw, &fb); err != nil {
		t.Fatal(err)
	}
	acs := fb["release_blocking_acs"].([]any)
	fb["release_blocking_acs"] = acs[:len(acs)-1] // drop the last
	out, _ := yaml.Marshal(fb)
	if err := os.WriteFile("requirements/releases/v0.2.0.yaml", out, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "release_blocking_acs has") {
		t.Fatalf("dropped entry not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsRephrasedEntry(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	raw, _ := os.ReadFile("requirements/releases/v0.2.0.yaml")
	var fb map[string]any
	if err := yaml.Unmarshal(raw, &fb); err != nil {
		t.Fatal(err)
	}
	acs := fb["release_blocking_acs"].([]any)
	first := acs[0].(map[string]any)
	first["phase"] = "publication" // wrong phase for a candidate AC
	out, _ := yaml.Marshal(fb)
	if err := os.WriteFile("requirements/releases/v0.2.0.yaml", out, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "the requirements derive") {
		t.Fatalf("rephrased entry not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsEmptyRequiredSet(t *testing.T) {
	// A requirements file with no release-blocking ACs.
	fixture(t, minimal("false", "", "2026-09-08", "approved", ""))
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "refusing an empty required set") {
		t.Fatalf("empty set not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsMalformedRequirements(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	if err := os.WriteFile("requirements/requirements.yaml", []byte("::: not yaml :::\n  - ["), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "parse requirements/requirements.yaml") {
		t.Fatalf("malformed requirements not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeRejectsMalformedFrozenFile(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	if err := os.WriteFile("requirements/releases/v0.2.0.yaml", []byte("::: not yaml :::\n  - ["), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "parse requirements/releases/v0.2.0.yaml") {
		t.Fatalf("malformed frozen file not rejected: code=%d stderr=%q", code, stderr)
	}
}

func TestVerifyFreezeSurfacesRequirementsReadError(t *testing.T) {
	richFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	// Replace requirements.yaml with a directory: os.Stat still succeeds
	// (so runCLI does not chdir away), but ReadFile fails.
	if err := os.Remove("requirements/requirements.yaml"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir("requirements/requirements.yaml", 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "read requirements/requirements.yaml") {
		t.Fatalf("read error not surfaced: code=%d stderr=%q", code, stderr)
	}
}
