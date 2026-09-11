package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture builds a minimal repo layout in a temp dir — real schema, a
// small requirements file, empty mappings — chdirs into it, and restores
// the working directory on cleanup. Tests exercise load/validate/render
// exactly as the CLI does, against hermetic inputs.
func fixture(t *testing.T, requirementsYAML string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile(filepath.Join(orig, "..", "..", "requirements", "schema.json"))
	if err != nil {
		t.Fatalf("read repo schema: %v", err)
	}
	dir := t.TempDir()
	for _, d := range []string{"requirements", "test-evidence", "docs/quality"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements/schema.json", string(schema))
	write("requirements/requirements.yaml", requirementsYAML)
	write("test-evidence/mappings.yaml", "mappings: []\n")
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatal(err)
		}
	})
}

// minimal returns a smallest-valid requirements file, with substitution
// points for the states each test needs.
func minimal(approved, approvedOn, extractedOn, acStatus, extraReqFields string) string {
	doc := `baseline:
  extracted_from: acd8bac2f9427dee63c71384dcbfecdb5c7ccf1b
  extracted_on: EXTRACTED_ON
  approved: APPROVED
APPROVED_ON_LINE
requirements:
  - id: REQ-TEST-001
    title: A test requirement
    statement: The server shall do the thing this test needs it to do.
    source: [test]
    tier: community
    introduced: v0.1.0
    confidence: documented
EXTRA_FIELDS
    acceptance_criteria:
      - id: REQ-TEST-001-AC1
        given: a fixture
        when: the validator runs
        then: the expected verdict is returned
        verification: { method: unit, release_blocking: false }
        status: AC_STATUS
`
	doc = strings.ReplaceAll(doc, "EXTRACTED_ON", extractedOn)
	// APPROVED_ON_LINE must be substituted BEFORE the shorter APPROVED
	// placeholder, which is its prefix.
	if approvedOn != "" {
		doc = strings.ReplaceAll(doc, "APPROVED_ON_LINE", "  approved_on: "+approvedOn)
	} else {
		doc = strings.ReplaceAll(doc, "APPROVED_ON_LINE\n", "")
	}
	doc = strings.ReplaceAll(doc, "APPROVED", approved)
	if extraReqFields != "" {
		doc = strings.ReplaceAll(doc, "EXTRA_FIELDS", extraReqFields)
	} else {
		doc = strings.ReplaceAll(doc, "EXTRA_FIELDS\n", "")
	}
	doc = strings.ReplaceAll(doc, "AC_STATUS", acStatus)
	return doc
}

func mustLoadOK(t *testing.T) (File, Mappings) {
	t.Helper()
	f, m, err := load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return f, m
}

func wantValid(t *testing.T) (File, Mappings) {
	t.Helper()
	f, m := mustLoadOK(t)
	if errs := validate(f, m); len(errs) != 0 {
		t.Fatalf("expected valid, got: %v", errs)
	}
	return f, m
}

func wantInvalid(t *testing.T, fragment string) {
	t.Helper()
	f, m, err := load()
	if err != nil {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("load failed with %q, want mention of %q", err, fragment)
		}
		return
	}
	errs := validate(f, m)
	if len(errs) == 0 {
		t.Fatalf("expected a validation failure mentioning %q, got valid", fragment)
	}
	for _, e := range errs {
		if strings.Contains(e, fragment) {
			return
		}
	}
	t.Fatalf("failures %v do not mention %q", errs, fragment)
}

// ── Deprecation (handoff item 3) ─────────────────────────────────────

func TestDeprecatedWithReasonParsesAndRendersLabeled(t *testing.T) {
	extra := `    deprecated: true
    deprecated_reason: superseded by REQ-TEST-002 after the widget rework`
	fixture(t, minimal("false", "", "2026-09-08", "proposed", extra))
	f, m := wantValid(t)

	out := render(f, m)
	if !strings.Contains(out, "(DEPRECATED)") {
		t.Error("rendered output does not label the deprecated requirement")
	}
	if !strings.Contains(out, "superseded by REQ-TEST-002") {
		t.Error("rendered output drops the deprecation reason")
	}
	if !strings.Contains(out, "| Active requirements | 0 |") {
		t.Error("deprecated requirement still counted as active")
	}
}

func TestDeprecatedWithoutReasonFails(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", "    deprecated: true"))
	wantInvalid(t, "deprecated without a deprecated_reason")
}

// ── Dates (handoff item 4) ───────────────────────────────────────────

func TestValidDatesPass(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	wantValid(t)
}

func TestMalformedDateFails(t *testing.T) {
	fixture(t, minimal("true", `"definitely-not-a-date"`, "2026-09-08", "approved", ""))
	wantInvalid(t, "definitely-not-a-date")
}

func TestImpossibleCalendarDateFails(t *testing.T) {
	fixture(t, minimal("false", "", `"2026-02-30"`, "proposed", ""))
	wantInvalid(t, "2026-02-30")
}

// ── Approval invariant, both directions (handoff item 6) ─────────────

func TestApprovedBaselineWithProposedACFails(t *testing.T) {
	fixture(t, minimal("true", `"2026-09-11"`, "2026-09-08", "proposed", ""))
	wantInvalid(t, "still proposed")
}

func TestUnapprovedBaselineWithApprovedACFails(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "approved", ""))
	wantInvalid(t, "baseline is not")
}

func TestFullyProposedUnapprovedIsValid(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	wantValid(t)
}

func TestFullyApprovedWithDateIsValid(t *testing.T) {
	fixture(t, minimal("true", `"2026-09-11"`, "2026-09-08", "approved", ""))
	wantValid(t)
}

// ── Single YAML document (handoff item 7) ────────────────────────────

func TestSecondYAMLDocumentFails(t *testing.T) {
	doc := minimal("false", "", "2026-09-08", "proposed", "") + `---
sneaky: second document
`
	fixture(t, doc)
	wantInvalid(t, "more than one YAML document")
}

// ── Generated output (handoff item 9 + determinism) ──────────────────

func TestRenderIsDeterministicAndCarriesCorrectCommand(t *testing.T) {
	fixture(t, minimal("false", "", "2026-09-08", "proposed", ""))
	f, m := wantValid(t)
	a, b := render(f, m), render(f, m)
	if a != b {
		t.Error("render is not deterministic across calls on identical input")
	}
	if !strings.Contains(a, "go -C tools/requirements run . generate") {
		t.Error("generated output does not carry the working regeneration command")
	}
	if strings.Contains(a, "go run ./tools/requirements") {
		t.Error("generated output still carries the broken root-module command form")
	}
}
