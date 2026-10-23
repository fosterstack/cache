#!/usr/bin/env bash
# The first half of the passed-audit record's writer (REQ-REL-012, owner rule 6, Oct 23): the record job of agent-review-gate.yml runs this from the DEFAULT branch, dispatched with a
# pull request number and a head sha by the step that clears the pull request's review. The job's next steps make the signed commit and judge it (the workflow names the committed
# signed-commit CLI; this script does not).
#   audit-record-prepare.sh PR HEAD_SHA        env: GH_TOKEN (read is enough here), GITHUB_REPOSITORY
# It re-reads the pull request (open, into main, this exact head: bin/audit-record.py plan) and checks whether a passing record is already there. Last line of stdout:
#   present  a passing record already exists: write nothing
#   proceed  the file audit-record (the head sha) is written in the current directory, for the signed commit
# Anything else is a refusal: exit 1 with the reason, nothing written.
set -uo pipefail
pr=${1:-}; head=${2:-}; repo=${GITHUB_REPOSITORY:-}
[[ "$pr" =~ ^[1-9][0-9]{0,8}$ ]] || { echo "audit-record: the pull request number is not a number" >&2; exit 1; }
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "audit-record: the head is not 40 lower-case hex" >&2; exit 1; }
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "audit-record: GITHUB_REPOSITORY is not owner/name" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
gh api "repos/${repo}/pulls/${pr}" > "$tmp/pr.json" 2> "$tmp/err" || { echo "audit-record: could not read pull request #${pr}: $(tail -c 200 "$tmp/err" | tr '\n' ' ')" >&2; exit 1; }
python3 -I bin/audit-record.py plan --pr "$pr" --head "$head" --pr-json "$tmp/pr.json" >&2 || exit 1
if bash bin/audit-record-judge.sh "$head" main > /dev/null 2>&1; then echo present; exit 0; fi
printf '%s\n' "$head" > audit-record
echo proceed
