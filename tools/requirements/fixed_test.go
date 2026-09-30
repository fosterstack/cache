package main

// REQ-REL-006 (register row 80): a frozen release baseline is fixed at a named commit; the freeze
// check compares it with the requirements file as of that commit, never with main's current file;
// editing requirements on main never turns a frozen baseline red.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// commitFixture makes the current fixture directory a git repository with everything committed,
// returning the commit id.
func commitFixture(t *testing.T) string {
	t.Helper()
	gitInitHere(t)
	for _, args := range [][]string{
		{"add", "-A"},
		{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "fixture"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func frozenFixedAt(t *testing.T, version string) string {
	t.Helper()
	raw, err := os.ReadFile("requirements/releases/" + version + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fb struct {
		FixedAt string `yaml:"fixed_at"`
	}
	if err := yaml.Unmarshal(raw, &fb); err != nil {
		t.Fatal(err)
	}
	return fb.FixedAt
}

func setFixedAt(t *testing.T, version, value string) {
	t.Helper()
	path := "requirements/releases/" + version + ".yaml"
	raw, _ := os.ReadFile(path)
	var fb map[string]any
	if err := yaml.Unmarshal(raw, &fb); err != nil {
		t.Fatal(err)
	}
	if value == "" {
		delete(fb, "fixed_at")
	} else {
		fb["fixed_at"] = value
	}
	out, _ := yaml.Marshal(fb)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// proves: REQ-REL-006-AC1 — a freeze names the commit it froze, and freezes that commit's file.
func TestFreezeRecordsItsFixedCommit(t *testing.T) {
	richFixture(t)
	head := commitFixture(t)
	// an uncommitted edit is not what gets frozen
	raw, _ := os.ReadFile("requirements/requirements.yaml")
	if err := os.WriteFile("requirements/requirements.yaml", append(raw, []byte("# uncommitted\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	if got := frozenFixedAt(t, "v0.2.0"); got != head {
		t.Fatalf("fixed_at = %q, want HEAD %s", got, head)
	}
	code, stdout, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 0 || !strings.Contains(stdout, head) {
		t.Fatalf("verify-freeze code=%d stdout=%q stderr=%q; want success naming %s", code, stdout, stderr, head)
	}
}

// proves: REQ-REL-006-AC2 — a new requirement committed on main after the freeze never turns it red.
func TestVerifyFreezeIgnoresMainAfterTheFixedCommit(t *testing.T) {
	richFixture(t)
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	raw, _ := os.ReadFile("requirements/requirements.yaml")
	grown := strings.Replace(string(raw), "  - id: REQ-OLD-001\n", `  - id: REQ-NEW-001
    title: A later requirement
    statement: The server shall do a thing introduced in the next version.
    source: [docs/new.md]
    tier: community
    introduced: v0.3.0
    confidence: documented
    acceptance_criteria:
      - id: REQ-NEW-001-AC1
        given: a later context
        when: a later action
        then: a later outcome
        verification: { method: unit, release_blocking: true }
        status: approved
  - id: REQ-OLD-001
`, 1)
	if err := os.WriteFile("requirements/requirements.yaml", []byte(grown), 0o644); err != nil {
		t.Fatal(err)
	}
	commitFixture(t)
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 0 {
		t.Fatalf("a committed change on main turned the frozen baseline red: %q", stderr)
	}
}

// proves: REQ-REL-006-AC2 — an uncommitted edit of the requirements file never turns it red either.
func TestVerifyFreezeIgnoresTheWorkingTree(t *testing.T) {
	richFixture(t)
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	if err := os.WriteFile("requirements/requirements.yaml", []byte("::: not yaml :::\n  - ["), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0"); code != 0 {
		t.Fatalf("the working tree was read: %q", stderr)
	}
}

// proves: REQ-REL-006-AC1 — a baseline that names no fixed commit fails, never falls back to main.
func TestVerifyFreezeRejectsABaselineWithoutFixedCommit(t *testing.T) {
	richFixture(t)
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	for _, bad := range []string{"", "326c459", "HEAD", "main", strings.Repeat("A", 40)} {
		setFixedAt(t, "v0.2.0", bad)
		code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
		if code != 1 || !strings.Contains(stderr, "fixed_at") {
			t.Fatalf("fixed_at %q: code=%d stderr=%q; want a fixed_at failure", bad, code, stderr)
		}
	}
}

// proves: REQ-REL-006-AC1 — a fixed commit that cannot be read fails: an id that is not a commit here,
// and a commit whose tree holds no requirements file.
func TestVerifyFreezeRejectsAnUnreadableFixedCommit(t *testing.T) {
	richFixture(t)
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	setFixedAt(t, "v0.2.0", strings.Repeat("0", 40))
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "fixed_at "+strings.Repeat("0", 40)+" is not a commit") {
		t.Fatalf("absent commit: code=%d stderr=%q", code, stderr)
	}
	for _, args := range [][]string{
		{"rm", "-q", "--cached", "requirements/requirements.yaml"},
		{"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "no requirements file here"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	out, _ := exec.Command("git", "rev-parse", "HEAD").Output()
	empty := strings.TrimSpace(string(out))
	setFixedAt(t, "v0.2.0", empty)
	code, _, stderr = runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "cannot read requirements/requirements.yaml at "+empty) {
		t.Fatalf("commit without the file: code=%d stderr=%q", code, stderr)
	}
}

// proves: REQ-REL-006-AC1 — the baseline must match the file AT its fixed commit: a baseline fixed at
// the wrong commit (one whose requirements differ) fails.
func TestVerifyFreezeRejectsTheWrongFixedCommit(t *testing.T) {
	richFixture(t)
	first := commitFixture(t)
	raw, _ := os.ReadFile("requirements/requirements.yaml")
	if err := os.WriteFile("requirements/requirements.yaml", append(raw, []byte("# a later edit\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	setFixedAt(t, "v0.2.0", first)
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "does not match requirements/requirements.yaml at "+first) {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// proves: REQ-REL-006-AC1 — freezing needs a commit to fix: outside a git repository it fails.
func TestFreezeFailsWithoutACommit(t *testing.T) {
	richFixture(t)
	fakeGit(t, "exit 128")
	code, _, stderr := runCommand(t, "freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "resolve the commit to fix") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}

// pkgDir is the package directory, captured before any test changes the working directory.
var pkgDir, _ = os.Getwd()

// proves: REQ-REL-006-AC1 — the repository's own v0.2.1 baseline names 326c459 itself (not merely a
// commit with identical bytes).
func TestTheRealV021BaselineIsFixedAt326c459(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(pkgDir, "..", "..", "requirements", "releases", "v0.2.1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var fb frozenBaseline
	if err := yaml.Unmarshal(raw, &fb); err != nil {
		t.Fatal(err)
	}
	if fb.FixedAt != "326c45965bae82b8ca749b84231a866518d9e5ea" {
		t.Fatalf("v0.2.1 fixed_at = %q, want 326c45965bae82b8ca749b84231a866518d9e5ea (register row 80)", fb.FixedAt)
	}
}

// proves: REQ-REL-006-AC2 — a new AC (on an existing requirement) and an edited criterion, committed on
// main, leave the frozen version green and unchanged; the new AC appears when the NEXT version is frozen.
func TestTheNextVersionCarriesTheNewAC(t *testing.T) {
	richFixture(t)
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	before, _ := os.ReadFile("requirements/releases/v0.2.0.yaml")
	raw, _ := os.ReadFile("requirements/requirements.yaml")
	grown := strings.Replace(string(raw), "        then: it still responds\n", `        then: it still responds, reworded
        verification: { method: manual }
        status: approved
      - id: REQ-PROTO-001-AC3
        given: a later context
        when: a later action
        then: a later outcome
`, 1)
	if grown == string(raw) {
		t.Fatal("fixture edit did not apply")
	}
	grown = strings.Replace(grown, "        then: a later outcome\n        verification: { method: manual }\n", "        then: a later outcome\n        verification: { method: unit, release_blocking: true }\n", 1)
	if err := os.WriteFile("requirements/requirements.yaml", []byte(grown), 0o644); err != nil {
		t.Fatal(err)
	}
	commitFixture(t)
	if code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0"); code != 0 {
		t.Fatalf("v0.2.0 turned red after a change on main: %q", stderr)
	}
	after, _ := os.ReadFile("requirements/releases/v0.2.0.yaml")
	if string(after) != string(before) {
		t.Fatal("the frozen v0.2.0 baseline file changed")
	}
	if strings.Contains(string(after), "REQ-PROTO-001-AC3") {
		t.Fatal("the new AC leaked into v0.2.0")
	}
	if code, _, stderr := runCommand(t, "freeze", "v0.3.0"); code != 0 {
		t.Fatalf("freeze v0.3.0 failed: %s", stderr)
	}
	next, _ := os.ReadFile("requirements/releases/v0.3.0.yaml")
	if !strings.Contains(string(next), "REQ-PROTO-001-AC3") {
		t.Fatalf("the new AC is missing from the next version's baseline:\n%s", next)
	}
	if code, _, stderr := runCommand(t, "verify-freeze", "v0.3.0"); code != 0 {
		t.Fatalf("v0.3.0: %q", stderr)
	}
}

// proves: REQ-REL-006-AC1 — fixed_at must name a commit: an annotated tag's object id is refused even
// though git would peel it to one.
func TestVerifyFreezeRejectsATagObjectAsFixedCommit(t *testing.T) {
	richFixture(t)
	commitFixture(t)
	if code, _, stderr := runCommand(t, "freeze", "v0.2.0"); code != 0 {
		t.Fatalf("freeze failed: %s", stderr)
	}
	if out, err := exec.Command("git", "-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "-m", "t", "vtag").CombinedOutput(); err != nil {
		t.Fatalf("git tag: %v (%s)", err, out)
	}
	out, _ := exec.Command("git", "rev-parse", "vtag").Output()
	tagObj := strings.TrimSpace(string(out))
	setFixedAt(t, "v0.2.0", tagObj)
	code, _, stderr := runCommand(t, "verify-freeze", "v0.2.0")
	if code != 1 || !strings.Contains(stderr, "fixed_at "+tagObj+" is not a commit") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
}
