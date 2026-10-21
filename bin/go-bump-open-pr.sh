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

fresh=1
if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
  tip_ver="$(gh api "repos/{owner}/{repo}/commits/${branch}" -q '.commit.verification.verified')" \
    || { echo "::error::could not ask whether the tip of ${branch} is verified; opening no pull request" >&2; exit 1; }
  # Only the exact word true is a verified tip. A branch is never deleted here: an unverified (or unreadable) tip is refused, loudly, for a person
  # to look at, so a branch a human or a concurrent run owns is never removed by this script.
  [ "$tip_ver" = true ] || { echo "::error::branch ${branch} exists with no PR and its tip is not reported verified by GitHub (got '${tip_ver}'; main requires signed commits); opening no pull request. Remove the branch to let the next run rebuild it through the API" >&2; exit 1; }
  echo "branch ${branch} exists with no PR (orphaned by a prior push-success/create-failure) and its tip is verified — creating the PR from the existing branch"
  fresh=0
fi
if [ "$fresh" = 1 ]; then
  echo "creating ${branch}: bumping the go directive in both modules"
  for f in go.mod tools/requirements/go.mod; do
    sed -i -E "s/^go ${CURRENT//./\\.}$/go ${LATEST}/" "$f"
    grep -q "^go ${LATEST}$" "$f" || { echo "::error::failed to bump go directive in $f" >&2; exit 1; }
  done
  # No `git commit` here: main requires signed commits and a commit made in the runner is unsigned (cache#464 sat BLOCKED on one). The branch
  # is pushed at the commit this job started from (nothing new to sign) and the one commit is made through the API, which GitHub signs for the
  # App's token (the same mechanism as bin/refresh-inputs.sh; REQ-REL-004-AC8). Any failure removes the branch and opens no pull request.
  base="$(git rev-parse HEAD)"
  case "$base" in *[!0-9a-f]*|'') echo "::error::could not read the commit the job started from" >&2; exit 1;; esac
  [ "${#base}" -eq 40 ] || { echo "::error::could not read the commit the job started from" >&2; exit 1; }
  input="$(mktemp)"
  jq -n --arg repo "${GITHUB_REPOSITORY:-fosterstack/cache}" --arg b "$branch" --arg base "$base" \
        --arg head "chore(go): bump toolchain ${CURRENT} -> ${LATEST}" \
        --arg r "$(base64 < go.mod | tr -d '\n')" --arg t "$(base64 < tools/requirements/go.mod | tr -d '\n')" \
    '{query: "mutation($input: CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}",
      variables: {input: {branch: {repositoryNameWithOwner: $repo, branchName: $b}, message: {headline: $head}, expectedHeadOid: $base,
                          fileChanges: {additions: [{path: "go.mod", contents: $r}, {path: "tools/requirements/go.mod", contents: $t}]}}}}' > "$input"
  git push origin "${base}:refs/heads/${branch}"
  refuse() { echo "::error::$1; removing ${branch} and opening no pull request" >&2; git push origin --delete "$branch" >&2 || true; rm -f "$input"; exit 1; }
  oid="$(gh api graphql --input "$input" -q '.data.createCommitOnBranch.commit.oid')" || refuse "the API could not create the commit"
  case "$oid" in *[!0-9a-f]*|'') refuse "the API returned no commit id";; esac
  [ "${#oid}" -eq 40 ] || refuse "the API returned no commit id"
  ver="$(gh api "repos/{owner}/{repo}/commits/${oid}" -q '.commit.verification.verified')" || refuse "could not ask whether commit ${oid} is verified"
  [ "$ver" = true ] || refuse "commit ${oid} is not verified by GitHub (main requires signed commits)"
  rm -f "$input"
  echo "signed commit ${oid} on ${branch} (verified by GitHub)"
fi

body="$(cat <<EOF
Automated Go-toolchain freshness bump: \`go ${CURRENT}\` -> \`go ${LATEST}\` in both modules (root and \`tools/requirements\`).

This tracks the newest patch of a supported Go minor, so it may be a patch bump within the current line or a move to a newer supported minor (the case that let CVE-2026-46600 be fixed — no 1.25.x carried the fix). Merging keeps the shipped binary off disclosed stdlib CVEs — the failure mode that broke the v0.2.0 release scan.

A minor bump can change toolchain behavior (and the FIPS validated-module snapshot); review the \`scan\` and \`fips140-only\` results before merging, and bump golangci-lint / gremlins if the new toolchain needs it.

The required \`scan\` gate must pass on this PR before merge. It is opened as a draft proposal: a minor jump is proposed, never auto-applied.
EOF
)"
gh pr create --draft --base main --head "$branch" \
  --title "chore(go): bump toolchain ${CURRENT} -> ${LATEST}" \
  --body "$body" --label dependencies
