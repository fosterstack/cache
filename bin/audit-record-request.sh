#!/usr/bin/env bash
# Asks for the passed-audit record of a pull request (REQ-REL-012, owner rule 6, Oct 23). The lane runs this once the pull request's review has cleared, right after
# `codex-review.sh --cleared` (the ops runner's --cleared step can call it); it starts the record job of agent-review-gate.yml on main with the pull request number and head.
#   audit-record-request.sh PR HEAD_SHA        env: GITHUB_REPOSITORY (default fosterstack/cache); needs the caller's own gh login (the actor must be a dispatcher named in
#                                              .github/policy/audit-writers.json; the job refuses anyone else). No token is read, printed or stored.
# It checks first, with the caller's read access, that the pull request is into main and that its head is exactly HEAD_SHA, and requests nothing otherwise. A pull request not
# into main needs no record: nothing is requested, exit 0. Exit 1: refused or the request failed (the sweep and a later run cover a transient failure).
set -uo pipefail
pr=${1:-}; head=${2:-}; repo=${GITHUB_REPOSITORY:-fosterstack/cache}
[[ "$pr" =~ ^([1-9][0-9]{0,8}|release)$ ]] || { echo "audit-record-request: the pull request number is not a number (or the word release)" >&2; exit 1; }
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "audit-record-request: the head is not 40 lower-case hex" >&2; exit 1; }
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "audit-record-request: the repository is not owner/name" >&2; exit 1; }
if [ "$pr" = release ]; then       # gate 7: the commit to be tagged must be on main
  cmp=$(gh api "repos/${repo}/compare/${head}...main" -q .status 2>&1) || { echo "audit-record-request: could not compare ${head} with main" >&2; exit 1; }
  [ "$cmp" = identical ] || [ "$cmp" = ahead ] || { echo "audit-record-request: ${head} is not on main: nothing requested" >&2; exit 1; }
  gh workflow run agent-review-gate.yml -R "$repo" --ref main -f audit_pr=release -f audit_head="$head" \
    || { echo "audit-record-request: the record job could not be started" >&2; exit 1; }
  echo "audit-record-request: whole-release record requested at ${head}"; exit 0
fi
view=$(gh pr view "$pr" -R "$repo" --json baseRefName,headRefOid,state -q '.baseRefName + " " + .headRefOid + " " + .state' 2>&1) \
  || { echo "audit-record-request: could not read pull request #${pr}: $(printf '%s' "$view" | tail -c 200 | tr '\n' ' ')" >&2; exit 1; }
read -r base cur state <<< "$view"
[ "$state" = OPEN ] || { echo "audit-record-request: pull request #${pr} is not open" >&2; exit 1; }
if [ "$base" != main ]; then echo "audit-record-request: pull request #${pr} is not into main: no record is needed"; exit 0; fi
[ "$cur" = "$head" ] || { echo "audit-record-request: pull request #${pr} has head ${cur}, not ${head}: nothing requested" >&2; exit 1; }
gh workflow run agent-review-gate.yml -R "$repo" --ref main -f audit_pr="$pr" -f audit_head="$head" \
  || { echo "audit-record-request: the record job could not be started" >&2; exit 1; }
echo "audit-record-request: record requested for #${pr} at ${head}"
