#!/usr/bin/env bash
# Shared allowlist logic for public-repo hygiene, called by both
# .githooks/pre-commit (local, every commit) and
# .github/workflows/ci.yml (CI backstop, catches anything committed
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
  '^test-evidence/dependabot-reviewer/[A-Za-z0-9._-]+\.json$'
  '^docs/quality/[A-Za-z0-9._-]+\.md$'
  '^docs/quality/releases/[A-Za-z0-9._-]+\.md$'
  '^tools/requirements/[A-Za-z0-9._-]+\.go$'
  '^tools/requirements/go\.(mod|sum)$'

  # This mechanism itself.
  '^\.githooks/pre-commit$'
  '^bin/check-file-allowlist\.sh$'
  '^bin/check-file-allowlist-test\.sh$'
  '^bin/vex-forms\.py$'
  '^bin/vex-forms-test\.sh$'
  '^bin/vex-index\.py$'
  '^bin/vex-index-test\.sh$'
  '^bin/fips-image-posture\.py$'
  '^bin/branch-sweep\.py$'
  '^bin/branch_sweep_test\.py$'
  '^bin/branch-sweep-test\.sh$'
  '^bin/local-prune\.sh$'
  '^\.github/branch-keep\.json$'
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
  '^bin/required-check-guard\.sh$'
  '^bin/required-check-guard-test\.sh$'
  '^bin/dependabot-reviewer\.py$'
  '^bin/dependabot-reviewer-test\.sh$'
  '^bin/dependency-lanes-test\.sh$'
  '^bin/panel\.py$'
  '^bin/scout-vex-scan\.sh$'
  '^bin/scout-selfcheck\.py$'
  '^bin/scout-root-cause(\.py|\.sh|-test\.sh)$'
  '^bin/patch-decide\.py$'
  '^bin/patch-decide-test\.sh$'
  '^bin/release-patch-wiring-test\.sh$'
  '^bin/acceptance-maven-413-test\.sh$'
  '^bin/admission-tag-signer\.py$'
  '^bin/admission-tag-signer-test\.sh$'
  '^bin/panel-test\.sh$'
  '^bin/panel-wiring-test\.sh$'
  '^\.github/agent/supply-chain/pin-(inventory|age-check|audit)\.py$'
  '^\.github/agent/supply-chain/tag_observer\.py$'
  '^\.github/supply-chain-exceptions\.json$'
  '^bin/workflow-consolidation-test\.sh$'
  '^bin/go-freshness-wiring-test\.sh$'
  '^bin/dependabot-reviewer-gather-test\.sh$'
  '^bin/dispatch-fixer\.sh$'
  '^bin/inspector-gate\.py$'
  '^bin/inspector-gate-test\.sh$'
  '^bin/grype-scan\.sh$'
  '^bin/vex-both-scanners-test\.sh$'
  '^bin/vex-scope-test\.sh$'
  '^bin/go-bump-open-pr\.sh$'
  '^bin/go-bump-open-pr-test\.sh$'
  # The v0.3.0 release chain, Sign boundary (PR 1): the verifier, its tests, the hostile dry-run step and the signer table the
  # tests share; the Sigstore PUBLIC trust material the release policy pins (exact names: a private key never matches); results/
  # holds the dry run's per-attempt rows (.gitkeep only, the rows come from the run)
  '^bin/chain-verify\.py$'
  '^bin/chain_(common|hostile)\.py$'
  '^bin/chain-hostile-step\.sh$'
  '^bin/chain-(verify|hostile|records|sign-wiring)-test\.sh$'
  '^bin/chain-test-signers\.(py|json)$'
  '^\.github/policy/cosign-signing-config\.json$'
  '^\.github/policy/(fulcio-chain|tsa-chain)\.pem$'
  '^\.github/policy/rekor\.pub$'
  '^results/\.gitkeep$'
  # The auditor implementation now lands (Round 8): sealed command scripts, the
  # shared library, and their parser unit tests, plus the parser-test runner.
  '^\.github/agent/bin/auditor-[a-z0-9-]+\.py$'
  '^\.github/agent/bin/check-action-pins\.py$'
  '^\.github/agent/bin/auditorlib/[A-Za-z0-9._-]+\.py$'
  # the published OpenVEX schema the writer validates against (production data, beside its code)
  '^\.github/agent/bin/auditorlib/openvex-schema\.json$'
  '^\.github/agent/bin/tests/[A-Za-z0-9._-]+\.py$'
  # REQ-AUD-18 AC1: the auditor's suites (matrix, mutants, parser runner, govulncheck fixture
  # materializer) and its requirements matrix live under .github/agent/ with the code.
  '^\.github/agent/tests/[A-Za-z0-9._-]+\.(sh|py)$'
  # REQ-AUD-18 AC2: the hash-pinned coverage tool and the reasoned exclusion ranges.
  '^\.github/agent/coverage-requirements\.txt$'
  # the report lint's hash-pinned, test-only renderer (GitHub's cmark-gfm)
  '^\.github/agent/test-requirements\.txt$'
  '^\.github/agent/coverage-exclusions\.txt$'
  '^\.github/agent/docs/[A-Za-z0-9._-]+\.md$'
  # REQ-AUD-18 AC3: review-loop records, one per reviewed .github/agent/ content hash, read by
  # .github/agent/bin/auditor-review-gate.py (run from main by .github/workflows/agent-review-gate.yml).
  '^\.github/agent/reviews/[0-9a-f]{64}\.json$'
  # REQ-AUD-018 AC4: the owner-recorded second-seat substitutes, read from the default branch by the same gate
  '^\.github/agent/reviews/substitutes\.json$'
  # The model's versioned standing instructions (REQ-AUD-16 AC2): public, names no vendor or
  # model, changed only through reviewed PRs. Loaded by auditor-adjudicator-client.py.
  '^\.github/agent/prompts/[A-Za-z0-9._-]+\.md$'
  # The production known-defect log the auditor reads (Round 11): trusted
  # dispositions authored only through the audit-lane PR review; starts empty.
  '^\.github/agent/known-defect-log\.json$'
  # The hash-pinned adjudicator SDK requirements (anthropic + transitive tree), installed
  # with --require-hashes on real/schedule runs; bumped by the pip ecosystem in dependabot.yml.
  '^\.github/agent/adjudicator-requirements\.txt$'
  # pip itself, pinned and hash-checked for CI (REQ-SUP-001-AC13); one requirement, bumped by the pip
  # ecosystem in dependabot.yml under the 7-day cooldown.
  '^\.github/agent/pip-requirements\.txt$'

  # Daily CVE auditor — matrix-first TEST FIXTURES backing
  # docs/cve-auditor-matrix.md and tests/auditor-matrix-test.sh (both under .github/agent/): real
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
  # the scanner panel's seat probe: one committed synthetic evidence bundle (no real finding or data)
  '^\.github/agent/fixtures/panel/probe-bundle\.txt$'
  # The reviewers' adversarial stand-ins, checked in as mutation-harness inputs.
  '^\.github/agent/fixtures/mutants/[A-Za-z0-9._-]+\.py$'
  # The fixture modules are stored ENTIRELY as .fixture files — go.mod.fixture / go.sum.fixture
  # AND the sources as *.go.fixture — and materialized into a throwaway temp module at test time
  # (.github/agent/tests/govulncheck-fixtures-test.sh). Storing go.mod/go.sum would re-index the deliberate
  # vulnerable pin (golang.org/x/text v0.3.0) in the dependency graph; storing a plain *.go with
  # no manifest would fold these package-main sources into the parent module and break
  # `go ./...` / gosec. So a plain go.mod / go.sum / *.go here is intentionally NOT allowed.
  '^\.github/agent/fixtures/govulncheck/src/[A-Za-z0-9._-]+/(go\.(mod|sum)|[A-Za-z0-9._-]+\.go)\.fixture$'
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

# Daily CVE auditor SUPPRESSION OUTPUTS — the .snyk / osv-scanner.toml ignore
# files the scanners read, and the .auditor/accepted-items.json inventory the
# release-authorization gate reads (REQ-AUD-11). These are generated, never
# hand-authored, and delivered ONLY through the auditor's own PR lane
# (auditor/<date>-<sha> branches; see _deliver_suppression_pr in
# .github/agent/bin/auditor-run.py). They must be allowed to LIVE on main so
# the next scan suppresses and the release gate can read the inventory — but
# their INTRODUCTION/CHANGE is scoped to the auditor/ branch prefix, so an
# ordinary feature PR cannot add or edit a suppression to slip past a scanner.
# The scoping is enforced by the head branch of the change: a pull_request from
# a non-auditor branch that touches these paths is blocked; the auditor lane and
# the merged state on main are allowed. (VEX itself already lives in .vex/ above,
# published for anyone auditing an artifact; these are its scanner-native forms.)
SUPPRESSION_PATTERNS=(
  '^\.snyk$'
  '^osv-scanner\.toml$'
  '^\.auditor/accepted-items\.json$'
  # REQ-AUD-16: the generated knowledge document (AC3) and the model's merge-gated proposals
  # (AC4), carried in the auditor's own suppression PR. Like the inventory, they are generated,
  # delivered only through the auditor lane, and reviewed before merge.
  '^\.auditor/knowledge\.md$'
  '^\.auditor/proposals/[A-Za-z0-9._-]+\.json$'
  # the scanner panel's memory of its judgments, debates, scores and primary seat (rules 9, 13, 14), delivered only
  # through the auditor lane's auditor/panel branch
  '^\.auditor/panel-state\.json$'
)
# Resolve the branch under check: the PR HEAD (source) branch on pull_request,
# else the pushed ref, else the local branch (pre-commit hook). Empty resolves
# to a non-auditor branch, i.e. suppression paths stay blocked by default.
# GITHUB_HEAD_REF is only the head branch NAME, and a fork can name its branch anything, so:
#   pull_request event (GITHUB_HEAD_REF set): the auditor lane only if the branch is auditor/* AND the
#     head repository is this repository (GITHUB_HEAD_REPO == GITHUB_REPOSITORY; either missing =>
#     not the same repo, fail closed). A PR head named `main` is never special.
#   otherwise (push, or the pre-commit hook): auditor/* or main by the pushed ref / local branch.
_suppression_free=1
if [ -n "${GITHUB_HEAD_REF:-}" ]; then
  case "$GITHUB_HEAD_REF" in
    auditor/*)
      if [ -n "${GITHUB_REPOSITORY:-}" ] && [ "${GITHUB_HEAD_REPO:-}" = "$GITHUB_REPOSITORY" ]; then
        _suppression_free=0
      fi ;;
  esac
else
  _branch="${GITHUB_REF_NAME:-}"
  [ -n "$_branch" ] || _branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  case "$_branch" in
    auditor/*|main) _suppression_free=0 ;;
  esac
fi
if [ "$_suppression_free" -eq 0 ]; then
  ALLOW_PATTERNS+=("${SUPPRESSION_PATTERNS[@]}")
fi

# Any other branch (feature PRs, bots, the pre-commit hook on a local branch) may CONTAIN a
# suppression file but may not ADD or CHANGE one: a suppression path passes only if it exists at the
# merge base with the base branch and is identical there (content and mode, via the index, which is
# what a commit would record and what CI's checkout equals). Base = $GITHUB_BASE_REF, else main.
# Anything that cannot be resolved (missing ref, shallow clone, no merge base) is NOT allowed.
_base_name="${GITHUB_BASE_REF:-main}"
_merge_base=""      # resolved lazily, once, only if a suppression path shows up
_merge_base_tried=0
_merge_base_err=""
# ALLOWLIST_HEAD_REV=<full hex commit sha>: judge that commit instead of the checkout (HEAD and the index);
# for a caller that only has the change as git objects. Set but not a resolvable commit => not allowed.
_rev="${ALLOWLIST_HEAD_REV:-}"
_head_rev=HEAD
_resolve_merge_base() {
  _merge_base_tried=1
  if [ -n "$_rev" ]; then
    if ! [[ "$_rev" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || ! git rev-parse --verify --quiet "$_rev^{commit}" >/dev/null 2>&1; then
      _merge_base_err="ALLOWLIST_HEAD_REV is not a commit here"; return 1
    fi
    _head_rev="$_rev"
  fi
  if ! [[ "$_base_name" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || [[ "$_base_name" == *..* ]]; then
    _merge_base_err="base ref name '$_base_name' is not usable"; return 1
  fi
  local ref="refs/remotes/origin/$_base_name"
  if ! git rev-parse --verify --quiet "$ref^{commit}" >/dev/null 2>&1; then
    _merge_base_err="base ref origin/$_base_name does not exist here (shallow or partial fetch?)"; return 1
  fi
  # --all: a criss-cross history has several merge bases and the file must be unchanged against EVERY one
  if ! _merge_base="$(git merge-base --all "$_head_rev" "$ref" 2>/dev/null)" || [ -z "$_merge_base" ]; then
    _merge_base=""; _merge_base_err="no merge base between $_head_rev and origin/$_base_name (shallow clone?)"; return 1
  fi
}
# 0 only when $1 is present at the merge base and the index holds identical content and mode.
_suppression_unchanged() {
  [ "$_merge_base_tried" -eq 1 ] || _resolve_merge_base || true
  [ -n "$_merge_base" ] || return 1
  local mb
  if [ -n "$_rev" ]; then
    git cat-file -e "$_rev:$1" 2>/dev/null || return 1
  else
    git ls-files --error-unmatch -- "$1" >/dev/null 2>&1 || return 1
  fi
  while IFS= read -r mb; do
    [ -n "$mb" ] || continue
    git cat-file -e "$mb:$1" 2>/dev/null || return 1
    if [ -n "$_rev" ]; then
      git diff --quiet "$mb" "$_rev" -- "$1" 2>/dev/null || return 1
    else
      git diff --cached --quiet "$mb" -- "$1" 2>/dev/null || return 1
    fi
  done <<< "$_merge_base"
  return 0
}

# the script's own git pathspecs are literal paths, never globs or magic
export GIT_LITERAL_PATHSPECS=1

# ALLOWLIST_NUL=1: the list on stdin is NUL-delimited (git ls-tree -z), so a path with a newline is one path
_delim=$'\n'
[ "${ALLOWLIST_NUL:-}" = 1 ] && _delim=''

blocked=()
while IFS= read -r -d "$_delim" path || [ -n "$path" ]; do
  [ -z "$path" ] && continue
  ok=0
  for pattern in "${ALLOW_PATTERNS[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      ok=1
      break
    fi
  done
  if [ "$ok" -eq 0 ] && [ "$_suppression_free" -eq 1 ]; then
    for pattern in "${SUPPRESSION_PATTERNS[@]}"; do
      if [[ "$path" =~ $pattern ]] && _suppression_unchanged "$path"; then
        ok=1
        break
      fi
    done
  fi
  if [ "$ok" -eq 0 ]; then
    blocked+=("$path")
  fi
done

if [ "${#blocked[@]}" -gt 0 ]; then
  echo "blocked — file(s) not on the public-repo allowlist:" >&2
  for f in "${blocked[@]}"; do
    echo "  $f" >&2
  done
  if [ -n "$_merge_base_err" ]; then
    echo "" >&2
    echo "suppression paths on this branch are allowed only if unchanged since the merge base;" >&2
    echo "could not establish that: $_merge_base_err (failing closed)." >&2
  fi
  echo "" >&2
  echo "fosterstack/cache is a PUBLIC repo. If a file genuinely belongs here," >&2
  echo "add a pattern to ALLOW_PATTERNS in bin/check-file-allowlist.sh." >&2
  echo "If it is ops/sprint/brief content, it does not belong here at all." >&2
  exit 1
fi
