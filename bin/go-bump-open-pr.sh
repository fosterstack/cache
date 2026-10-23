#!/usr/bin/env bash
# Open (or recover) the Go-toolchain freshness bump PR. Called by
# go-freshness.yml; extracted so its recovery logic is unit-tested.
#
# Audit R03: a remote branch is NOT proof of an open PR. A prior run can push
# the branch and then fail `gh pr create`, leaving an orphaned branch; the old
# "branch exists -> nothing to do" made every later run early-exit, so the PR
# was never created and the failure stopped being visible. Decide from the
# actual PR state instead:
#   open PR for this branch   -> dedup, nothing to do
#   merged PR                 -> the bump already landed, nothing to do
#   closed (not merged) PR    -> a human declined it; respect that, do not recreate
#   branch exists, no PR      -> orphaned by push-success/create-failure; create the PR from it
#   no branch, no PR          -> fresh: bump both go.mod, commit, push, create the PR
set -euo pipefail
CURRENT="${1:?usage: go-bump-open-pr.sh <current> <latest>}"
LATEST="${2:?usage: go-bump-open-pr.sh <current> <latest>}"
branch="chore/go-${LATEST}"

prs="$(gh pr list --head "$branch" --base main --state all --json number,state,mergedAt)"
open_num="$(jq -r '[.[] | select(.state=="OPEN")] | .[0].number // empty' <<<"$prs")"
merged_num="$(jq -r '[.[] | select(.mergedAt != null)] | .[0].number // empty' <<<"$prs")"
closed_num="$(jq -r '[.[] | select(.state=="CLOSED" and .mergedAt==null)] | .[0].number // empty' <<<"$prs")"

if [ -n "$open_num" ]; then
  echo "PR #${open_num} already open for ${branch} — nothing to do"; exit 0
fi
if [ -n "$merged_num" ]; then
  echo "PR #${merged_num} for ${branch} already merged — the bump has landed; nothing to do"; exit 0
fi
if [ -n "$closed_num" ]; then
  echo "PR #${closed_num} for ${branch} was closed without merging — a human declined this bump; not recreating"; exit 0
fi

if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
  echo "branch ${branch} exists with no PR (orphaned by a prior push-success/create-failure) — creating the PR from the existing branch"
else
  echo "creating ${branch}: bumping the go directive in both modules and the installer's Go pin (GO_VER and both checksums)"
  # the installer pin first, so that any doubt fails closed before a file changes or a branch exists: the two linux tarballs are downloaded over HTTPS from
  # go.dev, their sha256 computed here and compared with the checksum go.dev publishes for them (https://go.dev/dl/?mode=json); the computed values are written
  die() { echo "::error::$1" >&2; exit "${2:-1}"; }
  dl="$(mktemp -d)"; trap 'rm -rf "$dl"' EXIT
  jsonq='?mode=json&include=all'
  curl -q -fsSL -g -o "${dl}/published.json" "https://go.dev/dl/${jsonq}" || die "go.dev is unreachable: cannot read the published checksums" 1
  published="$(cat "${dl}/published.json")"
  sum_amd64=""; sum_arm64=""
  for arch in amd64 arm64; do
    tarball="go${LATEST}.linux-${arch}.tar.gz"
    want="$(jq -r --arg v "go${LATEST}" --arg f "$tarball" '.[] | select(.version==$v) | .files[] | select(.filename==$f) | .sha256' <<<"$published" 2>/dev/null | head -1)"
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::go.dev publishes no valid sha256 for ${tarball}" >&2; exit 1; }
    curl -q -fsSL -g -o "${dl}/${tarball}" "https://go.dev/dl/${tarball}" || die "cannot download the Go tarball from go.dev" 1
    got="$(sha256sum "${dl}/${tarball}" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || { echo "::error::${tarball} is ${got}, go.dev publishes ${want}" >&2; exit 1; }
    printf -v "sum_${arch}" '%s' "$got"
  done
  # the sealed compiler (rc-3 item 6): the recipe template pins the same two tarballs (uri + expected-sha256) and the compiler it builds with is that one, so a
  # bump that leaves them behind is red at the sealed build. Checked BEFORE any file changes: each pin must be at the version being left and appear exactly once.
  tmpl=build/melange.yaml.tmpl; gen=bin/gen-recipes.py
  for arch in amd64 arm64; do
    [ "$(grep -c -E "^ +uri: https://go\.dev/dl/go${CURRENT//./\\.}\.linux-${arch}\.tar\.gz\$" "$tmpl" 2>/dev/null)" = 1 ] \
      || die "${tmpl} does not pin go${CURRENT}.linux-${arch}.tar.gz exactly once: the template is not at the version being bumped" 1
  done
  [ "$(grep -c '^TEMPLATE_SHA256 = "[0-9a-f]\{64\}"' "$gen" 2>/dev/null)" = 1 ] || die "${gen} does not have exactly one TEMPLATE_SHA256 pin" 1
  bump_template() {
    python3 - "$tmpl" "$gen" "$CURRENT" "$LATEST" "$sum_amd64" "$sum_arm64" <<'PY' || { echo "::error::failed to move the recipe template's Go pins" >&2; exit 1; }
import hashlib, re, sys
tmpl, gen, cur, new, amd, arm = sys.argv[1:7]
t = open(tmpl).read()
for arch, want in (("amd64", amd), ("arm64", arm)):
    pat = re.compile(r"(uri: https://go\.dev/dl/go)" + re.escape(cur) + r"(\.linux-" + arch + r"\.tar\.gz\n\s+expected-sha256: )[0-9a-f]{64}")
    t, n = pat.subn(lambda m: m.group(1) + new + m.group(2) + want, t)
    if n != 1:
        sys.exit(1)
open(tmpl, "w").write(t)
h = hashlib.sha256(t.encode()).hexdigest()
g = open(gen).read()
g, n = re.subn(r'^TEMPLATE_SHA256 = "[0-9a-f]{64}"', 'TEMPLATE_SHA256 = "' + h + '"', g, count=1, flags=re.M)
sys.exit(1) if n != 1 else open(gen, "w").write(g)
PY
    python3 bin/gen-recipes.py --write >/dev/null || { echo "::error::bin/gen-recipes.py --write failed after the template changed" >&2; exit 1; }
    python3 bin/gen-recipes.py --check >/dev/null || { echo "::error::bin/gen-recipes.py --check fails after the bump" >&2; exit 1; }
  }
  bump_installer() {
    local f=bin/install-scanner.sh
    [ "$(grep -c '^GO_VER=' "$f")" = 1 ] && [ "$(grep -c 'go:x86_64|go:amd64) SUM=' "$f")" = 1 ] && [ "$(grep -c 'go:aarch64|go:arm64) SUM=' "$f")" = 1 ] \
      || { echo "::error::${f} does not have exactly one Go pin (GO_VER and the two per-arch sums)" >&2; exit 1; }
    sed -i.bak -E "s/^GO_VER=[0-9.]+/GO_VER=${LATEST}/; s/(go:x86_64[|]go:amd64[)] SUM=)[0-9a-f]{64}/\1${sum_amd64}/; s/(go:aarch64[|]go:arm64[)] SUM=)[0-9a-f]{64}/\1${sum_arm64}/" "$f"; rm -f "${f}.bak"      # -i.bak: portable between GNU and BSD sed
    # the installer is a listed script of the release chain: its sha256 row in the policy follows its bytes, in the same commit (the policy validator
    # refuses a row that differs from the file)
    python3 - "$f" .github/policy/chain-scripts.json <<'PY' || { echo "::error::failed to update the installer's sha256 row in .github/policy/chain-scripts.json" >&2; exit 1; }
import hashlib, re, sys
inst, pol = sys.argv[1:3]
h = hashlib.sha256(open(inst, "rb").read()).hexdigest()
t = open(pol).read()
t2, n = re.subn(r'("path": "bin/install-scanner\.sh",\s*"sha256": ")[0-9a-f]{64}(")', lambda m: m.group(1) + h + m.group(2), t)
if n != 1:
    t2, n = re.subn(r'("path": "bin/install-scanner\.sh",(?:(?!"path").)*?"sha256": ")[0-9a-f]{64}(")', lambda m: m.group(1) + h + m.group(2), t, count=1, flags=re.S)
sys.exit(1) if n != 1 else open(pol, "w").write(t2)
PY
    grep -q "^GO_VER=${LATEST}\$" "$f" && grep -q "SUM=${sum_amd64} ;;" "$f" && grep -q "SUM=${sum_arm64} ;;" "$f" \
      || { echo "::error::failed to bump the Go pin in ${f}" >&2; exit 1; }
  }
  for f in go.mod tools/requirements/go.mod; do
    sed -i -E "s/^go ${CURRENT//./\\.}$/go ${LATEST}/" "$f"
    grep -q "^go ${LATEST}$" "$f" || { echo "::error::failed to bump go directive in $f" >&2; exit 1; }
  done
  bump_installer
  bump_template
  # the auditor App's bot when go-freshness.yml runs it with the App's token (owner, Oct 2), else the Actions bot
  slug="${AUDITOR_APP_SLUG:-github-actions}"
  git config user.name  "${slug}[bot]"
  git config user.email "${slug}[bot]@users.noreply.github.com"
  git checkout -b "$branch"
  git add go.mod tools/requirements/go.mod bin/install-scanner.sh .github/policy/chain-scripts.json build/melange.yaml.tmpl bin/gen-recipes.py build/melange.yaml build/melange-fips.yaml
  git commit -q -m "chore(go): bump toolchain ${CURRENT} -> ${LATEST}"
  git push -u origin "$branch"
fi

body="$(cat <<EOF
Automated Go-toolchain freshness bump: \`go ${CURRENT}\` -> \`go ${LATEST}\`. Eight files change together (the installer checks that go.mod and its pin agree; the sealed build compiles with the template's pinned compiler):

| file | change |
| --- | --- |
| \`go.mod\` | \`go ${CURRENT}\` -> \`go ${LATEST}\` |
| \`tools/requirements/go.mod\` | \`go ${CURRENT}\` -> \`go ${LATEST}\` |
| \`bin/install-scanner.sh\` | \`GO_VER\` and the sha256 of go${LATEST}.linux-amd64 and linux-arm64 tarballs, computed from the downloads and equal to go.dev's published checksums |
| \`.github/policy/chain-scripts.json\` | the sha256 row of \`bin/install-scanner.sh\` (a listed script: the row follows the file's bytes) |
| \`build/melange.yaml.tmpl\` | the two go.dev pins (uri and expected-sha256 of go${LATEST}.linux-amd64 and linux-arm64), the same checksums as the installer's |
| \`bin/gen-recipes.py\` | \`TEMPLATE_SHA256\`, the sha256 of the template's new bytes |
| \`build/melange.yaml\`, \`build/melange-fips.yaml\` | regenerated by \`bin/gen-recipes.py --write\` (and \`--check\` passes) |

One step is not part of this pull request: the archive. \`build/archive.json\` and the two tarballs \`go/go${LATEST}.linux-amd64.tar.gz\` and \`go/go${LATEST}.linux-arm64.tar.gz\` are not pushed here, so until a refresh archives them (\`bin/refresh-inputs.sh refresh\` fetches a pinned tarball the archive lacks, REQ-REFRESH-001-AC33) the sealed build of this pull request cannot find the new compiler in the archive and its snapshot build stays red. Do not merge before that refresh has landed.

This tracks the newest patch of a supported Go minor, so it may be a patch bump within the current line or a move to a newer supported minor (the case that let CVE-2026-46600 be fixed — no 1.25.x carried the fix). Merging keeps the shipped binary off disclosed stdlib CVEs — the failure mode that broke the v0.2.0 release scan.

A minor bump can change toolchain behavior (and the FIPS validated-module snapshot); review the \`scan\` and \`fips140-only\` results before merging, and bump golangci-lint / gremlins if the new toolchain needs it.

The required \`scan\` gate must pass on this PR before merge. It is opened as a draft proposal: a minor jump is proposed, never auto-applied.
EOF
)"
gh pr create --draft --base main --head "$branch" \
  --title "chore(go): bump toolchain ${CURRENT} -> ${LATEST}" \
  --body "$body" --label dependencies
