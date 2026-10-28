#!/usr/bin/env bash
# The review gate's judge for a merge queue's temporary branch (cache#542, REQ-DEP-005-AC3). The queue-judge job and the
# sweep of agent-review-gate.yml run it from the DEFAULT branch's checkout, so the judge is main's copy and never the
# group's. It reads git objects only: nothing of the group is checked out, installed or executed.
#   queue-gate-judge.sh HEAD_SHA REF
#     HEAD_SHA  the queue head (workflow_run.head_sha): exactly 40 lower-case hex
#     REF       the queue ref (workflow_run.head_branch): exactly gh-readonly-queue/main/pr-<N>-<40 lower-case hex>
# Exit 0 only when every check holds. Exit 1: a refusal. Exit 3: the record judge reported a GitHub API error (the
# verdict still fails closed). The checks, in order:
#   1. both arguments are valid (exact matches);
#   2. the objects of HEAD_SHA are readable and the first-parent history BASE..HEAD is not empty;
#   3. EVERY commit on that history is a two-parent merge (a squash or rebase shape, or an octopus, is refused);
#   4. the second parent of each (the pull request head) has a passed-audit record:
#      bin/audit-record-judge.sh <head> main;
#   5. main's judges pass over HEAD_SHA, as the pull request gate runs them over a pull request head.
# Runs from the repository root (the workflow's checkout) and names every program literally, never through a variable.
# Environment: GH_TOKEN (read-only) and GITHUB_REPOSITORY go to the record judge. Two seams, plain values only:
# QUEUE_GATE_GIT_DIR (a git directory) and QUEUE_GATE_BASE_REF (a ref name, default refs/remotes/origin/main).
set -uo pipefail

head=${1:-}
ref=${2:-}
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "queue-gate-judge: HEAD_SHA is not 40 lower-case hex" >&2; exit 1; }
[[ "$ref" =~ ^gh-readonly-queue/main/pr-[0-9]+-[0-9a-f]{40}$ ]] \
  || { echo "queue-gate-judge: REF is not a queue ref of main" >&2; exit 1; }
[[ "$ref" != *$'\n'* ]] || { echo "queue-gate-judge: REF holds a newline" >&2; exit 1; }

# main's judges run from the repository root (the workflow's checkout), as the pull request gate runs them, so nothing
# changes directory and every path below is a literal one
gitdir=${QUEUE_GATE_GIT_DIR:-}
if [ -z "$gitdir" ]; then gitdir=$(git rev-parse --absolute-git-dir 2>/dev/null) || gitdir=; fi
[ -n "$gitdir" ] || { echo "queue-gate-judge: no git directory" >&2; exit 1; }
g() { git --git-dir="$gitdir" "$@"; }

base=$(g rev-parse --verify -q "${QUEUE_GATE_BASE_REF:-refs/remotes/origin/main}^{commit}") \
  || { echo "queue-gate-judge: the default branch's tip is not readable" >&2; exit 1; }
g cat-file -e "${head}^{commit}" 2>/dev/null \
  || { echo "queue-gate-judge: ${head} is not a readable commit" >&2; exit 1; }
list=$(g rev-list --first-parent "${base}..${head}") \
  || { echo "queue-gate-judge: cannot walk the group's history" >&2; exit 1; }
[ -n "$list" ] || { echo "queue-gate-judge: the group holds no commit above the default branch" >&2; exit 1; }

# every program the judge runs must exist as a regular file at its literal path: a missing one is a refusal, not 126/127
for f in bin/audit-record-judge.sh .github/agent/bin/check-action-pins.py bin/check-file-allowlist.sh \
         .github/agent/tests/pin-wiring-test.sh bin/scan-no-workflow-call-test.sh; do
  [ -f "$f" ] || { echo "queue-gate-judge: ${f} is missing (run from the repository root)" >&2; exit 1; }
done

for c in $list; do
  read -r -a parents <<<"$(g log -1 --format=%P "$c")"
  if [ "${#parents[@]}" -ne 2 ]; then
    echo "queue-gate-judge: ${c} is not a two-parent merge (${#parents[@]} parents); only merges are judged" >&2
    exit 1
  fi
  [[ "${parents[1]}" =~ ^[0-9a-f]{40}$ ]] || { echo "queue-gate-judge: bad parent of ${c}" >&2; exit 1; }
  bash bin/audit-record-judge.sh "${parents[1]}" main
  r=$?
  if [ "$r" -eq 3 ]; then
    echo "queue-gate-judge: the record of ${parents[1]} could not be read (API error)" >&2
    exit 3
  fi
  [ "$r" -eq 0 ] || { echo "queue-gate-judge: no passed-audit record for ${parents[1]}" >&2; exit 1; }
done

# main's judges over the group head, the judge job's command lines (the record is judged per pull request head above)
shim=$(mktemp -d) || exit 1
trap 'rm -rf "$shim"' EXIT
ln -s "$PWD/.github/agent/fixtures/testlib/pyyaml" "$shim/yaml" || exit 1
verdict=0
python3 -I .github/agent/bin/check-action-pins.py --verify-tags --git "$head" || verdict=1
g ls-tree -r -z --name-only "$head" \
  | GITHUB_BASE_REF=main ALLOWLIST_NUL=1 ALLOWLIST_HEAD_REV="$head" bash bin/check-file-allowlist.sh || verdict=1
PYTHONPATH="$shim" PIN_WIRING_JUDGE_GIT="$head" bash .github/agent/tests/pin-wiring-test.sh || verdict=1
PYTHONPATH="$shim" SCAN_GUARD_JUDGE_GIT="$head" bash bin/scan-no-workflow-call-test.sh || verdict=1
[ "$verdict" -eq 0 ] || { echo "queue-gate-judge: main's judges failed over ${head}" >&2; exit 1; }
exit 0
