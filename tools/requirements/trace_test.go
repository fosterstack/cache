package main

// REQ-REL-007 (register row 79): every AC traces to a test and every test to an AC. `check` fails when
// an AC has no mapping and is not a named residual; a script-test mapping must point at a test file that
// declares the AC (`# proves: <AC>`), and every such declaration must name a real AC mapped to that file.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const oneMapped = `mappings:
  - ac: REQ-TEST-001-AC1
    evidence:
      - type: script-test
        ref: bin/thing-test.sh
`

func writeFile(t *testing.T, rel, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rel, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// generated runs `generate` so `check` judges traceability, not matrix freshness.
func checkAfterGenerate(t *testing.T) (int, string) {
	t.Helper()
	if code, _, stderr := runCommand(t, "generate"); code != 0 {
		return code, stderr
	}
	code, _, stderr := runCommand(t, "check")
	return code, stderr
}

// proves: REQ-REL-007-AC1 — an AC with no mapping and no residual entry fails `check`.
func TestCheckFailsForAnACWithNoTest(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	code, stderr := checkAfterGenerate(t)
	if code != 1 || !strings.Contains(stderr, "REQ-TEST-001-AC1 has no test mapping and is not a listed residual") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// proves: REQ-REL-007-AC1 — a mapped AC passes `check`.
func TestCheckPassesForAMappedAC(t *testing.T) {
	fixtureWithMappings(t, oneMapped)
	writeFile(t, "bin/thing-test.sh", "#!/usr/bin/env bash\n# proves: REQ-TEST-001-AC1\ntrue\n")
	if code, stderr := checkAfterGenerate(t); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// proves: REQ-REL-007-AC1 — a named residual with a reason passes; the report lists it.
func TestCheckAcceptsANamedResidual(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	writeFile(t, "test-evidence/unmapped.yaml", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: no test yet; the owner decides\n")
	code, stderr := checkAfterGenerate(t)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// proves: REQ-REL-007-AC1 — a residual is never silent: no reason, an unknown AC, or an AC that is also
// mapped all fail.
func TestCheckRejectsABadResidual(t *testing.T) {
	cases := map[string]struct{ mappings, unmapped, want string }{
		"no reason":   {"mappings: []\n", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: '  '\n", "residual REQ-TEST-001-AC1 gives no reason"},
		"unknown AC":  {"mappings: []\n", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: r\n  - ac: REQ-NOPE-001-AC1\n    reason: r\n", "residual REQ-NOPE-001-AC1 is not an AC"},
		"also mapped": {oneMapped, "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: r\n", "residual REQ-TEST-001-AC1 is also mapped"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, c.mappings)
			writeFile(t, "bin/thing-test.sh", "# proves: REQ-TEST-001-AC1\n")
			writeFile(t, "test-evidence/unmapped.yaml", c.unmapped)
			code, stderr := checkAfterGenerate(t)
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}

// proves: REQ-REL-007-AC2 — a script-test mapping must name an existing test file, under the test
// directories, that declares the AC.
func TestScriptTestMappingMustPointAtADeclaringTestFile(t *testing.T) {
	cases := map[string]struct{ file, content, ref, want string }{
		"missing file":      {"", "", "bin/thing-test.sh", "script-test bin/thing-test.sh does not exist"},
		"not declared":      {"bin/thing-test.sh", "# proves: REQ-OTHER-001-AC1\n", "bin/thing-test.sh", "bin/thing-test.sh does not declare REQ-TEST-001-AC1"},
		"outside test dirs": {"docs/thing.sh", "# proves: REQ-TEST-001-AC1\n", "docs/thing.sh", "script-test docs/thing.sh is not under a test directory"},
		"escapes the repo":  {"", "", "bin/../../x-test.sh", "script-test bin/../../x-test.sh is not under a test directory"},
		"declared in prose": {"bin/thing-test.sh", "echo 'proves: REQ-TEST-001-AC1'\n", "bin/thing-test.sh", "does not declare REQ-TEST-001-AC1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, strings.Replace(oneMapped, "bin/thing-test.sh", c.ref, 1))
			if c.file != "" {
				writeFile(t, c.file, c.content)
			}
			code, _, stderr := runCommand(t, "validate")
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}

// proves: REQ-REL-007-AC2 — a test file's declaration must name a real AC, mapped back to that file.
func TestEveryDeclaredACExistsAndMapsBack(t *testing.T) {
	cases := map[string]struct{ rel, content, want string }{
		"unknown AC":        {"bin/other-test.sh", "# proves: REQ-GHOST-001-AC1\n", "bin/other-test.sh declares REQ-GHOST-001-AC1, which is not an AC"},
		"not mapped back":   {".github/agent/tests/x-test.sh", "# proves: REQ-TEST-001-AC1\n", ".github/agent/tests/x-test.sh declares REQ-TEST-001-AC1 but no script-test mapping names it"},
		"python unit test":  {".github/agent/bin/tests/test_x.py", "# proves: REQ-GHOST-002-AC1\n", "test_x.py declares REQ-GHOST-002-AC1, which is not an AC"},
		"one line, two ACs": {"bin/other-test.sh", "# proves: REQ-TEST-001-AC1, REQ-GHOST-001-AC1\n", "declares REQ-GHOST-001-AC1, which is not an AC"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, oneMapped)
			writeFile(t, "bin/thing-test.sh", "# proves: REQ-TEST-001-AC1\n")
			writeFile(t, c.rel, c.content)
			code, _, stderr := runCommand(t, "validate")
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}
