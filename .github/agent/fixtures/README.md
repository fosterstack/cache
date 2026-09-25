# Auditor test fixtures

Checked-in INPUTS for the matrix-first suite (`bin/auditor-matrix-test.sh`, backing
`docs/quality/cve-auditor-matrix.md`). The auditor does not exist yet; these are the
native inputs each case drives, and the case then inspects the effect the auditor
would produce. **No fixture contains an expectation** — every expected value lives in
the test file next to its assertion. This is the change the second-gate review required:
the previous fixtures carried `category` / `expected_artifact` / `distinct_lineages`
inside the input, which let an echoing stand-in pass.

## What moved OUT of the fixtures (Round 5)

- Expectation fields (`category`, `expected_artifact`, `report_sections`,
  `lineage_votes`, `expected`, `expected_attempt_order`) were deleted. `multi-category.json`
  and `four-scanner-finding.json` (custom objects full of answers) are gone; in their place
  are native scanner reports plus `run/manifest-multi.json`, which lists only report paths
  and digests.
- Scanner "self-report" flags the tests used to read (`ci_stays_green`, `vex_authored`,
  `model_calls`) are no longer trusted: the tests read written VEX/`.snyk`/ignore files, the
  fake GitHub state file, the rendered report file, the git/gh shim ledger, and the
  independent model-call ledger instead.

## Real captured scanner output (inputs only, trimmed, structure unaltered)

Captured by scanning a public image known to carry findings —
**`debian:12.0` @ `sha256:3d868b5eb908155f3784317b3dda2941df87bbbbaa4608f84881de66d9bb297b`** —
with the pinned scanner versions, then trimmed to a handful of real findings without
changing field structure:

- `scanners/grype-debian12.json` — **grype 0.118.0** (official `anchore/grype:v0.118.0`).
- `scanners/trivy-debian12.json` — **trivy 0.74.0** (`aquasec/trivy:0.74.0`).
- `scanners/osv-debian12.json` — **osv-scanner 2.6.0** (`ghcr.io/google/osv-scanner:v2.6.0`,
  `scan image --archive` of the saved image).
- `scanners/osv-gomod.json` — **osv-scanner 2.6.0** source scan of the Go module below.
- `scanners/snyk-debian12.json` — **BEST-EFFORT, marked synthetic**: snyk 1.1307.0 could not
  be captured here (no `SNYK_TOKEN`/account). Shaped to snyk's published container-test JSON
  and carrying the shared votes CVE, to be replaced by a real capture when a token exists.
- `govulncheck/reachable.json`, `govulncheck/imported-not-called.json` — real
  **govulncheck v1.7.0** `-json` streams over the tiny Go modules in `govulncheck/src/`
  (a module requiring `golang.org/x/text v0.3.0`): GO-2021-0113 is reachable (a call trace
  reaches our code) in `reachable.json`; it is imported-but-not-called in
  `imported-not-called.json`. Non-Go reachability (the libssl case) is a **separate evidence
  type**, `reachability/libssl-not-reachable.evidence.json`, never dressed as govulncheck.
  Those modules' manifests are stored as `go.mod.fixture` (not `go.mod`) so the dependency
  graph never indexes their deliberate vulnerable pin; `bin/govulncheck-fixtures-test.sh`
  materializes them into a throwaway temp module at test time (and, to regenerate the streams,
  materialize the same way, then run govulncheck over the temp module).
- `kev/known-exploited-vulnerabilities.json` — real **CISA KEV** catalog (version 2026.09.21),
  trimmed to include CVE-2023-4911, which the real grype scan of this image also reports; the
  threshold KEV check is a deterministic membership test against this file.

Scenario roles are composed by which trimmed fixture includes a real finding (e.g.
CVE-2016-2781 appears only in the grype trim for the single-scanner case; CVE-2011-3374 is in
grype+trivy+osv+snyk for votes), never by annotating the fixture.

## Test doubles and policy inputs (not the auditor)

- `adjudicator/stub-adjudicator.py` — canned judgment; appends one line per call to
  `$AUDITOR_MODEL_LEDGER`. `adjudicator/fail-on-call.py` — the "no model" spy (exits 99 if a
  deterministic phase calls it). `adjudicator/fake-github-api.py` — records issue create/update
  to a state file the test inspects.
- `testlib/yamlshape.py` — a test-owned minimal YAML reader so the workflow-shape cases parse
  `.github/workflows/auditor.yml` in the test itself (validated against a real committed
  workflow before use), with no auditor helper in between.
- `policy/*.json` — exported GitHub policy shapes (environment branch policy; the main
  ruleset) tested against, not live GitHub. `poam/*.json`, `release/*.json` — normalized
  finding and release-candidate/issue-evidence inputs.
