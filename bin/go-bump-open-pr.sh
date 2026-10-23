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
#   branch exists, no PR      -> orphaned by push-success/create-failure; create the PR from it ONLY when its tip is verified by GitHub;
#                                anything else (an unsigned older run's branch, an unreadable answer) fails the run and deletes nothing
#   no branch, no PR          -> fresh: bump both go.mod, commit, push, create the PR
set -euo pipefail
CURRENT="${1:?usage: go-bump-open-pr.sh <current> <latest>}"
LATEST="${2:?usage: go-bump-open-pr.sh <current> <latest>}"
# Both versions go into a sed expression and a branch name: only a Go version (1.27 or 1.27.3) is accepted, before any call is made.
for v in "$CURRENT" "$LATEST"; do
  [[ "$v" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || { echo "::error::not a Go version: ${v}" >&2; exit 2; }
done
branch="chore/go-${LATEST}"

prs="$(gh pr list --head "$branch" --base main --state all --json number,state,mergedAt,comments)"
open_num="$(jq -r '[.[] | select(.state=="OPEN")] | .[0].number // empty' <<<"$prs")"
merged_num="$(jq -r '[.[] | select(.mergedAt != null)] | .[0].number // empty' <<<"$prs")"
# a pull request this script closed itself (its branch moved after verification) is not a human's decline: recovery may go on
closed_num="$(jq -r '[.[] | select(.state=="CLOSED" and .mergedAt==null and ([.comments[]?.body | startswith("closed by go-bump-open-pr.sh:")] | any | not))] | .[0].number // empty' <<<"$prs")"

if [ -n "$open_num" ]; then
  echo "PR #${open_num} already open for ${branch} — nothing to do"; exit 0
fi
if [ -n "$merged_num" ]; then
  echo "PR #${merged_num} for ${branch} already merged — the bump has landed; nothing to do"; exit 0
fi
if [ -n "$closed_num" ]; then
  echo "PR #${closed_num} for ${branch} was closed without merging — a human declined this bump; not recreating"; exit 0
fi

headline="chore(go): bump toolchain ${CURRENT} -> ${LATEST}"
fresh=1
if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
  tip_ans="$(gh api "repos/{owner}/{repo}/commits/${branch}" -q '[.sha, .commit.verification.verified, (.commit.message | split("\n")[0])] | @tsv')" \
    || { echo "::error::could not ask whether the tip of ${branch} is verified; opening no pull request" >&2; exit 1; }
  IFS=$'\t' read -r tip_sha tip_ver tip_head <<<"$tip_ans"
  # Only the exact word true is a verified tip. A branch is never deleted here: an unverified (or unreadable) tip is refused, loudly, for a person
  # to look at, so a branch a human or a concurrent run owns is never removed by this script.
  # The tip must also be a bump commit (this run's headline): a verified tip that is only the base a failed run pushed would open a PR with no bump.
  [[ "$tip_sha" =~ ^[0-9a-f]{40}$ ]] && [ "$tip_ver" = true ] && [ "$tip_head" = "$headline" ] || { echo "::error::branch ${branch} exists with no PR and its tip is not a verified bump commit (verified '${tip_ver}', headline '${tip_head}'; main requires signed commits); opening no pull request. Remove the branch to let the next run rebuild it through the API" >&2; exit 1; }
  echo "branch ${branch} exists with no PR (orphaned by a prior push-success/create-failure) and its tip is verified — creating the PR from the existing branch"
  fresh=0; expected_head="$tip_sha"
fi
if [ "$fresh" = 1 ]; then
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
  bump_installer() {
    local f=bin/install-scanner.sh
    [ "$(grep -c '^GO_VER=' "$f")" = 1 ] && [ "$(grep -c 'go:x86_64|go:amd64) SUM=' "$f")" = 1 ] && [ "$(grep -c 'go:aarch64|go:arm64) SUM=' "$f")" = 1 ] \
      || { echo "::error::${f} does not have exactly one Go pin (GO_VER and the two per-arch sums)" >&2; exit 1; }
    sed -i.bak -E "s/^GO_VER=[0-9.]+/GO_VER=${LATEST}/; s/(go:x86_64[|]go:amd64[)] SUM=)[0-9a-f]{64}/\1${sum_amd64}/; s/(go:aarch64[|]go:arm64[)] SUM=)[0-9a-f]{64}/\1${sum_arm64}/" "$f"; rm -f "${f}.bak"      # -i.bak: portable between GNU and BSD sed
    # the installer is a listed script of the release chain: its sha256 row in the policy follows its bytes, in the same commit (the policy validator
    # refuses a row that differs from the file)
    env -u GH_TOKEN python3 -I -B - "$f" .github/policy/chain-scripts.json <<'PY' || { echo "::error::failed to update the installer's sha256 row in .github/policy/chain-scripts.json" >&2; exit 1; }
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
  # No `git commit` here: main requires signed commits and a commit made in the runner is unsigned (cache#464 sat BLOCKED on one). The branch
  # is pushed at the commit this job started from (nothing new to sign) and the one commit is made through the API, which GitHub signs for the
  # App's token (the same mechanism as bin/refresh-inputs.sh; REQ-REL-004-AC9). Any failure removes the branch and opens no pull request.
  bump_installer
  base="$(git rev-parse HEAD)"
  case "$base" in *[!0-9a-f]*|'') echo "::error::could not read the commit the job started from" >&2; exit 1;; esac
  [ "${#base}" -eq 40 ] || { echo "::error::could not read the commit the job started from" >&2; exit 1; }
  marker="go-bump-run: ${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}"   # unique to this run: two overlapping runs of one bump share parent and headline
  input="$(mktemp)"; enc="$(mktemp -d)"
  # each file's contents are encoded into a file of its own, every encoding checked (a failing encoder must not become an empty file in a signed commit), and the
  # request is built from those files with --rawfile: the policy's base64 alone is over Linux's 128 KiB limit for one argument
  for pair in go.mod:r tools/requirements/go.mod:t bin/install-scanner.sh:i .github/policy/chain-scripts.json:c; do
    { base64 < "${pair%:*}" | tr -d '\n' > "${enc}/${pair##*:}"; } || { echo "::error::could not encode ${pair%:*}; opening no pull request" >&2; rm -rf "$enc" "$input"; exit 1; }
    [ -s "${enc}/${pair##*:}" ] || { echo "::error::the encoding of ${pair%:*} is empty; opening no pull request" >&2; rm -rf "$enc" "$input"; exit 1; }
  done
  jq -n --arg repo "${GITHUB_REPOSITORY:-fosterstack/cache}" --arg b "$branch" --arg base "$base" \
        --arg head "$headline" --arg mark "$marker" \
        --rawfile r "${enc}/r" --rawfile t "${enc}/t" --rawfile i "${enc}/i" --rawfile c "${enc}/c" \
    '{query: "mutation($input: CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}",
      variables: {input: {branch: {repositoryNameWithOwner: $repo, branchName: $b}, message: {headline: $head, body: $mark}, expectedHeadOid: $base,
                          fileChanges: {additions: [{path: "go.mod", contents: $r}, {path: "tools/requirements/go.mod", contents: $t}, {path: "bin/install-scanner.sh", contents: $i}, {path: ".github/policy/chain-scripts.json", contents: $c}]}}}}' > "$input"
  rm -rf "$enc"
  # Cleanup removes only what this run owns: the delete is leased on the tip this run last knew (the commit it pushed, then the one the API made),
  # so a branch someone else advanced is kept. A cleanup that fails is its own loud message: the branch remains and a person must remove it.
  owned="$base"
  # The API may have made the commit although its answer never arrived: before the cleanup, the remote tip is read. It is ours when it is the pushed
  # base, or a commit whose parent is that base and whose message is this run's (headline and its unique run marker); any other tip belongs to
  # someone else (an overlapping run of the same bump included) and is left alone.
  settle_owned() {   # 0: the tip is ours (owned is set); 2: the branch is not there; 1: not ours, or unreadable
    local out tip info
    [ "$owned" = "$base" ] || return 0
    out="$(git ls-remote origin "refs/heads/${branch}")" || return 1
    tip="${out%%$'\t'*}"
    [ -n "$tip" ] || return 2
    [ "$tip" = "$base" ] && return 0
    info="$(gh api "repos/{owner}/{repo}/commits/${tip}" -q '[.parents[0].sha, .commit.message] | @tsv')" || return 1
    [ "$info" = "$(printf '%s\t%s\\n\\n%s' "$base" "$headline" "$marker")" ] || return 1
    owned="$tip"
  }
  refuse() {
    local rc=0
    echo "::error::$1; opening no pull request" >&2
    settle_owned || rc=$?
    case "$rc" in
      0) git push origin ":refs/heads/${branch}" --force-with-lease="refs/heads/${branch}:${owned}" >&2 \
           || echo "::error::could not remove ${branch} (it remains at or after ${owned}); remove it by hand before the next run" >&2 ;;
      2) echo "::error::${branch} is not on the remote; nothing to remove" >&2 ;;
      *) echo "::error::${branch} is not at a tip this run owns, or its tip could not be read; leaving it; remove it by hand before the next run" >&2 ;;
    esac
    rm -f "$input"; exit 1
  }
  # a push whose answer was lost may still have made the branch: it is cleaned up like any later failure
  git push origin "${base}:refs/heads/${branch}" || refuse "the push of ${branch} failed"
  oid="$(gh api graphql --input "$input" -q '.data.createCommitOnBranch.commit.oid')" || refuse "the API could not create the commit"
  case "$oid" in *[!0-9a-f]*|'') refuse "the API returned no commit id";; esac
  [ "${#oid}" -eq 40 ] || refuse "the API returned no commit id"
  owned="$oid"
  ver="$(gh api "repos/{owner}/{repo}/commits/${oid}" -q '.commit.verification.verified')" || refuse "could not ask whether commit ${oid} is verified"
  [ "$ver" = true ] || refuse "commit ${oid} is not verified by GitHub (main requires signed commits)"
  rm -f "$input"
  echo "signed commit ${oid} on ${branch} (verified by GitHub)"
  expected_head="$oid"
fi

body="$(cat <<EOF
Automated Go-toolchain freshness bump: \`go ${CURRENT}\` -> \`go ${LATEST}\`. Four files change together (the installer checks that go.mod and its pin agree):

| file | change |
| --- | --- |
| \`go.mod\` | \`go ${CURRENT}\` -> \`go ${LATEST}\` |
| \`tools/requirements/go.mod\` | \`go ${CURRENT}\` -> \`go ${LATEST}\` |
| \`bin/install-scanner.sh\` | \`GO_VER\` and the sha256 of go${LATEST}.linux-amd64 and linux-arm64 tarballs, computed from the downloads and equal to go.dev's published checksums |
| \`.github/policy/chain-scripts.json\` | the sha256 row of \`bin/install-scanner.sh\` (a listed script: the row follows the file's bytes) |

This tracks the newest patch of a supported Go minor, so it may be a patch bump within the current line or a move to a newer supported minor (the case that let CVE-2026-46600 be fixed — no 1.25.x carried the fix). Merging keeps the shipped binary off disclosed stdlib CVEs — the failure mode that broke the v0.2.0 release scan.

A minor bump can change toolchain behavior (and the FIPS validated-module snapshot); review the \`scan\` and \`fips140-only\` results before merging, and bump golangci-lint / gremlins if the new toolchain needs it.

The required \`scan\` gate must pass on this PR before merge. It is opened as a draft proposal: a minor jump is proposed, never auto-applied.
EOF
)"
pr_link="$(gh pr create --draft --base main --head "$branch" \
  --title "chore(go): bump toolchain ${CURRENT} -> ${LATEST}" \
  --body "$body" --label dependencies
)" || exit $?
echo "$pr_link"
# The branch name is mutable: the pull request must be at the commit that was verified, or it is closed (the verification covers a commit, not a name).
head_now="$(gh pr view "$pr_link" --json headRefOid -q .headRefOid)" || head_now=""
if [ -z "${expected_head:-}" ] || [ "$head_now" != "$expected_head" ]; then
  echo "::error::${pr_link} is at '${head_now}', not at the verified commit '${expected_head:-}'; closing it" >&2
  closed=0
  for _ in 1 2 3; do
    gh pr close "$pr_link" --comment "closed by go-bump-open-pr.sh: the branch moved after its commit was verified" >&2 && { closed=1; break; }
    sleep "${GO_BUMP_CLOSE_WAIT:-5}"
  done
  [ "$closed" = 1 ] || echo "::error::could not close ${pr_link}; it is still open at an unverified commit; close it by hand" >&2
  exit 1
fi
