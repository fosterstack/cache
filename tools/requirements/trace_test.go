package main

// REQ-REL-007 (register row 79): every AC traces to a test and every test to an AC. `check` fails when
// an AC has no mapping and is not a named residual; a shell-test mapping must point at a test file that
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
      - type: shell-test
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

// checkAfterGenerate makes the matrix fresh (generate must succeed), then runs `check` itself, so a
// failure asserted afterwards is `check`'s own.
func checkAfterGenerate(t *testing.T) (int, string) {
	t.Helper()
	code, _, stderr := checkOut(t)
	return code, stderr
}

func checkOut(t *testing.T) (int, string, string) {
	t.Helper()
	if code, _, stderr := runCommand(t, "generate"); code != 0 {
		t.Fatalf("generate must succeed before check: code=%d stderr=%q", code, stderr)
	}
	code, stdout, stderr := runCommand(t, "check")
	return code, stdout, stderr
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
	code, stdout, stderr := checkOut(t)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "residual REQ-TEST-001-AC1 (no test) — no test yet; the owner decides") {
		t.Fatalf("check does not list the residual for the owner: stdout=%q", stdout)
	}
}

// proves: REQ-REL-007-AC1 — a residual is never silent: no reason, an unknown AC, or an AC that is also
// mapped all fail.
func TestCheckRejectsABadResidual(t *testing.T) {
	cases := map[string]struct{ mappings, unmapped, want string }{
		"no reason":   {"mappings: []\n", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: '  '\n", "residual REQ-TEST-001-AC1 gives no reason"},
		"unknown AC":  {"mappings: []\n", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: r\n  - ac: REQ-NOPE-001-AC1\n    reason: r\n", "residual REQ-NOPE-001-AC1 is not an AC"},
		"also mapped": {oneMapped, "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: r\n", "residual REQ-TEST-001-AC1 is also mapped"},
		"twice":       {"mappings: []\n", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    reason: r\n  - ac: REQ-TEST-001-AC1\n    reason: r\n", "residual REQ-TEST-001-AC1 is listed twice"},
		"malformed":   {"mappings: []\n", "unmapped:\n  - ac: REQ-TEST-001-AC1\n    why: r\n", "parse test-evidence/unmapped.yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, c.mappings)
			if c.mappings == oneMapped { // the mapped file must exist and declare the AC
				writeFile(t, "bin/thing-test.sh", "# proves: REQ-TEST-001-AC1\n")
			}
			writeFile(t, "test-evidence/unmapped.yaml", c.unmapped)
			code, stderr := checkAfterGenerate(t)
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}

// proves: REQ-REL-007-AC2 — a shell-test mapping must name an existing test file, under the test
// directories, that declares the AC.
func TestScriptTestMappingMustPointAtADeclaringTestFile(t *testing.T) {
	cases := map[string]struct{ file, content, ref, want string }{
		"missing file":         {"", "", "bin/thing-test.sh", "shell-test bin/thing-test.sh does not exist"},
		"not declared":         {"bin/thing-test.sh", "# proves: REQ-OTHER-001-AC1\n", "bin/thing-test.sh", "bin/thing-test.sh does not declare REQ-TEST-001-AC1"},
		"outside test dirs":    {"docs/thing.sh", "# proves: REQ-TEST-001-AC1\n", "docs/thing.sh", "shell-test docs/thing.sh is not a test file"},
		"escapes the repo":     {"", "", "bin/../../x-test.sh", "shell-test bin/../../x-test.sh is not a test file"},
		"declared in a string": {"bin/thing-test.sh", "echo '# proves: REQ-TEST-001-AC1'\n", "bin/thing-test.sh", "does not declare REQ-TEST-001-AC1"},
		"not a test file name": {"bin/thing.sh", "# proves: REQ-TEST-001-AC1\n", "bin/thing.sh", "shell-test bin/thing.sh is not a test file"},
		"declared in prose":    {"bin/thing-test.sh", "echo 'proves: REQ-TEST-001-AC1'\n", "bin/thing-test.sh", "does not declare REQ-TEST-001-AC1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, strings.Replace(oneMapped, "bin/thing-test.sh", c.ref, 1))
			if c.file != "" {
				writeFile(t, c.file, c.content)
			}
			code, _, stderr := runCommand(t, "check")
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}

// proves: REQ-REL-007-AC2 — a test file's declaration must name a real AC, mapped back to that file.
func TestEveryDeclaredACExistsAndMapsBack(t *testing.T) {
	cases := map[string]struct{ rel, content, want string }{
		"unknown AC":           {"bin/other-test.sh", "# proves: REQ-GHOST-001-AC1\n", "bin/other-test.sh declares REQ-GHOST-001-AC1, which is not an AC"},
		"not mapped back":      {"tests/x-test.sh", "# proves: REQ-TEST-001-AC1\n", "tests/x-test.sh declares REQ-TEST-001-AC1 but no shell-test mapping names it"},
		"python unit test":     {"py/test_x.py", "# proves: REQ-GHOST-002-AC1\n", "test_x.py declares REQ-GHOST-002-AC1, which is not an AC"},
		"one line, two ACs":    {"bin/other-test.sh", "# proves: REQ-TEST-001-AC1, REQ-GHOST-001-AC1\n", "declares REQ-GHOST-001-AC1, which is not an AC"},
		"anywhere in the repo": {"docs/x-test.sh", "# proves: REQ-GHOST-003-AC1\n", "docs/x-test.sh declares REQ-GHOST-003-AC1, which is not an AC"},
		"a Go test":            {"internal/x/x_test.go", "// proves: REQ-GHOST-004-AC1 — prose after the dash\n", "internal/x/x_test.go declares REQ-GHOST-004-AC1, which is not an AC"},
		"a Go test unmapped":   {"internal/x/x_test.go", "// proves: REQ-TEST-001-AC1\n", "internal/x/x_test.go declares REQ-TEST-001-AC1 but no go-test mapping names a test in internal/x"},
		"no colon":             {"bin/other-test.sh", "# proves REQ-TEST-001-AC1\n", "bin/other-test.sh:1: a malformed `proves` declaration"},
		"not an AC id":         {"bin/other-test.sh", "# proves: everything\n", "bin/other-test.sh:1: a malformed `proves` declaration"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, oneMapped)
			writeFile(t, "bin/thing-test.sh", "# proves: REQ-TEST-001-AC1\n")
			writeFile(t, c.rel, c.content)
			code, _, stderr := runCommand(t, "check")
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}

// proves: REQ-REL-007-AC1 — a deprecated requirement needs no test; its ACs are not gaps.
func TestCheckSkipsDeprecatedRequirements(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", "    deprecated: true\n    deprecated_reason: gone"))
	if code, stderr := checkAfterGenerate(t); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// proves: REQ-REL-007-AC2 — a test file that cannot be read fails, never counts as declaring nothing.
func TestUnreadableTestFilesFail(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-000 file")
	}
	t.Run("directory", func(t *testing.T) {
		fixtureWithMappings(t, "mappings: []\n")
		writeFile(t, "sealed/x-test.sh", "# proves: REQ-GHOST-001-AC1\n")
		if err := os.Chmod("sealed", 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod("sealed", 0o755) })
		code, _, stderr := runCommand(t, "check")
		if code != 1 || !strings.Contains(stderr, "sealed cannot be read while looking for test files") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
	for name, c := range map[string]struct{ mappings, want string }{
		"declaring file": {"mappings: []\n", "bin/locked-test.sh cannot be read"},
		"mapped file":    {strings.Replace(oneMapped, "thing-test", "locked-test", 1), "shell-test bin/locked-test.sh cannot be read"},
	} {
		t.Run(name, func(t *testing.T) {
			fixtureWithMappings(t, c.mappings)
			writeFile(t, "bin/locked-test.sh", "# proves: REQ-TEST-001-AC1\n")
			if err := os.Chmod("bin/locked-test.sh", 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod("bin/locked-test.sh", 0o644) })
			code, _, stderr := runCommand(t, "check")
			if code != 1 || !strings.Contains(stderr, c.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, c.want)
			}
		})
	}
}

// proves: REQ-REL-007-AC2 — a declaration may carry prose after an em dash; it is read as the AC alone.
func TestADeclarationMayCarryProse(t *testing.T) {
	fixtureWithMappings(t, oneMapped)
	writeFile(t, "bin/thing-test.sh", "# proves: REQ-TEST-001-AC1 — the one fixture AC\n")
	if code, stderr := checkAfterGenerate(t); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}
