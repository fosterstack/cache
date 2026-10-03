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
  echo "creating ${branch}: bumping the go directive in both modules"
  for f in go.mod tools/requirements/go.mod; do
    sed -i -E "s/^go ${CURRENT//./\\.}$/go ${LATEST}/" "$f"
    grep -q "^go ${LATEST}$" "$f" || { echo "::error::failed to bump go directive in $f" >&2; exit 1; }
  done
  # the auditor App's bot when go-freshness.yml runs it with the App's token (owner, Oct 2), else the Actions bot
  slug="${AUDITOR_APP_SLUG:-github-actions}"
  git config user.name  "${slug}[bot]"
  git config user.email "${slug}[bot]@users.noreply.github.com"
  git checkout -b "$branch"
  git add go.mod tools/requirements/go.mod
  git commit -q -m "chore(go): bump toolchain ${CURRENT} -> ${LATEST}"
  git push -u origin "$branch"
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
