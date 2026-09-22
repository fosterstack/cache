#!/usr/bin/env bash
# Shared allowlist logic for public-repo hygiene, called by both
# .githooks/pre-commit (local, every commit) and
# .github/workflows/hygiene.yml (CI backstop, catches anything committed
# without the hook installed/enabled). One definition, so the two never
# drift apart. Mirrors the same mechanism in fosterstack/www.
#
# fosterstack/cache is PUBLIC. The specific thing this guards against is
# the private side of the company leaking into it — ops runbooks, sprint
# state, the brief, credential architecture, the owner's real identity —
# which hard_deny forbids but which nothing mechanical was checking on
# this repo until now. Making the repo private later does not undo a push.
#
# Reads file paths, one per line, on stdin. Exits 1 (with the offending
# paths listed) if any path doesn't match an allowed pattern.

set -euo pipefail

ALLOW_PATTERNS=(
  # Go source and module graph — the actual product.
  '^(cmd|internal)/[A-Za-z0-9._/-]+\.go$'
  '^go\.(mod|sum)$'

  # Repo-root documentation and policy.
  '^(README|SECURITY|CONTRIBUTING|RELEASING)\.md$'
  '^LICENSE$'

  # Published documentation, plus the Grafana dashboard operators import.
  '^docs/[A-Za-z0-9._-]+\.md$'
  '^docs/[A-Za-z0-9._-]+\.json$'

  # Build, lint, scan and release configuration.
  '^\.(gitignore|golangci\.yml|goreleaser\.yaml|grype\.yaml|ko\.yaml|gremlins\.yaml)$'

  # Image-assembly Dockerfiles (release chain stage 3): COPY-only, FROM
  # pinned image:tag@sha256, watched by Dependabot's docker ecosystem.
  '^build/docker/Dockerfile\.[a-z]+$'

  # CI/CD. Note these are ALSO gated in autoMode soft_deny — the allowlist
  # says a workflow file may live here, not that it may change freely.
  '^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$'
  '^\.github/dependabot\.yml$'
  '^\.github/PULL_REQUEST_TEMPLATE\.md$'
  # Policy lists: the single sources of truth for the required-check set
  # and the scanner set, consumed by the auto-merge guard and the release
  # workflows.
  '^\.github/policy/[A-Za-z0-9._-]+\.json$'
  '^\.github/policy/allowed_signers$'
  '^\.github/policy/github-web-flow\.gpg$'
  '^\.github/policy/[A-Za-z0-9._-]+\.txt$'

  # VEX statements. Published exception claims — these ship as release
  # assets and are meant to be read by anyone auditing an artifact.
  '^\.vex/[A-Za-z0-9._-]+\.(json|md)$'

  # Requirements traceability (traceability-plan.md §5): the baseline, its
  # schema, the AC-to-evidence mappings, the generated matrix, and the
  # validator/generator tool (a separate Go module so its YAML dependency
  # stays out of the product's go.mod and SBOM). Source and module files
  # only — a compiled binary never belongs in the tree.
  '^requirements/[A-Za-z0-9._-]+\.(yaml|json)$'
  '^requirements/releases/[A-Za-z0-9._-]+\.yaml$'
  '^test-evidence/[A-Za-z0-9._-]+\.yaml$'
  '^test-evidence/vex-scope/[A-Za-z0-9._-]+\.json$'
  '^docs/quality/[A-Za-z0-9._-]+\.md$'
  '^docs/quality/releases/[A-Za-z0-9._-]+\.md$'
  '^tools/requirements/[A-Za-z0-9._-]+\.go$'
  '^tools/requirements/go\.(mod|sum)$'

  # This mechanism itself.
  '^\.githooks/pre-commit$'
  '^bin/check-file-allowlist\.sh$'
  '^bin/check-version-literals\.sh$'
  '^bin/coverage-gate\.sh$'
  '^bin/check-workflow-permissions\.py$'
  '^bin/authorize-acceptance-check\.py$'
  '^bin/authorize-acceptance-check-test\.sh$'
  '^bin/rescan-statement\.py$'
  '^bin/rescan-statement-test\.sh$'
  '^bin/analyze-egress-trace\.py$'
  '^bin/analyze-egress-trace-test\.sh$'
  '^bin/install-scanner\.sh$'
  '^bin/install-scanner-test\.sh$'
  '^bin/vex-scope-test\.sh$'
  '^bin/go-bump-open-pr\.sh$'
  '^bin/go-bump-open-pr-test\.sh$'
  '^bin/auditor-matrix-test\.sh$'
  '^bin/auditor-matrix-mutants\.sh$'
  '^bin/auditor-parser-tests\.sh$'
  # The auditor implementation now lands (Round 8): sealed command scripts, the
  # shared library, and their parser unit tests, plus the parser-test runner.
  '^\.github/agent/bin/auditor-[a-z0-9-]+\.py$'
  '^\.github/agent/bin/auditorlib/[A-Za-z0-9._-]+\.py$'
  '^\.github/agent/bin/tests/[A-Za-z0-9._-]+\.py$'

  # Daily CVE auditor — matrix-first TEST FIXTURES backing
  # docs/quality/cve-auditor-matrix.md and bin/auditor-matrix-test.sh: real
  # captured scanner output, native-schema samples, and canned test doubles
  # (no secrets, no private-side content).
  '^\.github/agent/fixtures/README\.md$'
  '^\.github/agent/fixtures/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.json$'
  # Test doubles and the test-owned YAML reader (Python); the tiny Go modules that
  # produced the real govulncheck fixtures. All test inputs, never auditor code.
  '^\.github/agent/fixtures/adjudicator/[A-Za-z0-9._-]+\.py$'
  '^\.github/agent/fixtures/testlib/[A-Za-z0-9._-]+\.py$'
  # Vendored pure-Python PyYAML (with its LICENSE) — the test-owned YAML reader.
  '^\.github/agent/fixtures/testlib/pyyaml/[A-Za-z0-9._-]+\.py$'
  '^\.github/agent/fixtures/testlib/pyyaml/LICENSE$'
  '^\.github/agent/fixtures/testlib/workflows/[A-Za-z0-9._-]+\.ya?ml$'
  # The reviewers' adversarial stand-ins, checked in as mutation-harness inputs.
  '^\.github/agent/fixtures/mutants/[A-Za-z0-9._-]+\.py$'
  '^\.github/agent/fixtures/govulncheck/src/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\.go$'
  '^\.github/agent/fixtures/govulncheck/src/[A-Za-z0-9._-]+/go\.mod$'
  '^\.github/agent/fixtures/suppression/set-01/\.snyk$'
  '^\.github/agent/fixtures/suppression/set-01/osv-scanner\.toml$'

  # The real Gradle project the benchmark builds against.
  '^bench/gradle-sample/gradlew(\.bat)?$'
  '^bench/gradle-sample/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.(kts|java|properties|jar)$'
  # The acceptance expectation: which tasks the warm build must restore.
  '^bench/gradle-sample/expected-from-cache\.txt$'

  # The real Maven project the Maven acceptance workflow builds.
  '^bench/maven-sample/(\.mvn/)?([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.(xml|java)$'
)

blocked=()
while IFS= read -r path; do
  [ -z "$path" ] && continue
  ok=0
  for pattern in "${ALLOW_PATTERNS[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      ok=1
      break
    fi
  done
  if [ "$ok" -eq 0 ]; then
    blocked+=("$path")
  fi
done

if [ "${#blocked[@]}" -gt 0 ]; then
  echo "blocked — file(s) not on the public-repo allowlist:" >&2
  for f in "${blocked[@]}"; do
    echo "  $f" >&2
  done
  echo "" >&2
  echo "fosterstack/cache is a PUBLIC repo. If a file genuinely belongs here," >&2
  echo "add a pattern to ALLOW_PATTERNS in bin/check-file-allowlist.sh." >&2
  echo "If it is ops/sprint/brief content, it does not belong here at all." >&2
  exit 1
fi
