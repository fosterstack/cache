#!/usr/bin/env bash
# Asks for the tag-time passed-audit record of a commit (REQ-REL-012, owner rule 7, Oct 23). It starts the record job of agent-review-gate.yml on main with the word release and the commit.
#   audit-record-request.sh release HEAD_SHA       env: GITHUB_REPOSITORY (default fosterstack/cache); needs the caller's own gh login (the actor must be a dispatcher named in
#                                              .github/policy/audit-writers.json; the job refuses anyone else). No token is read, printed or stored.
# It checks first, with the caller's read access, that main contains HEAD_SHA, and requests nothing otherwise. Exit 1: refused or the request failed (the sweep and a later run cover a transient failure).
set -uo pipefail
pr=${1:-}; head=${2:-}; repo=${GITHUB_REPOSITORY:-fosterstack/cache}
[ "$pr" = release ] || { echo "audit-record-request: the first argument is not the word release" >&2; exit 1; }
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "audit-record-request: the head is not 40 lower-case hex" >&2; exit 1; }
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "audit-record-request: the repository is not owner/name" >&2; exit 1; }
# gate 7: the commit to be tagged must be on main
cmp=$(gh api "repos/${repo}/compare/${head}...main" -q .status 2>&1) \
  || { echo "audit-record-request: could not compare ${head} with main" >&2; exit 1; }
[ "$cmp" = identical ] || [ "$cmp" = ahead ] \
  || { echo "audit-record-request: ${head} is not on main: nothing requested" >&2; exit 1; }
gh workflow run agent-review-gate.yml -R "$repo" --ref main -f audit_pr=release -f audit_head="$head" \
  || { echo "audit-record-request: the record job could not be started" >&2; exit 1; }
echo "audit-record-request: whole-release record requested at ${head}"
