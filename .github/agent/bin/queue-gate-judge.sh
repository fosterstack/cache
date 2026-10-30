#!/usr/bin/env bash
# The review gate's judge for a merge queue's head commit (cache#542, REQ-DEP-005-AC3). The workflow runs it from the
# DEFAULT branch's checkout, so the judge is main's copy and never the group's, and it reads git objects only.
#   queue-gate-judge.sh HEAD_SHA REF
#     HEAD_SHA  the queue head, exactly 40 lower-case hex
#     REF       the queue ref (gh-readonly-queue/main/pr-<N>-<sha>); the allowlist guard finds the pull request from it
# Exit 0 only when every check holds; any refusal exits 1.
set -uo pipefail

# The merge queue must use the MERGE method, so that every group commit is a two-parent merge. The queue setting is the
# owner's; this constant only names what the judge expects.
queue_merge_method=MERGE

head=${1:-}
ref=${2:-}
{ [ "${#head}" -eq 40 ] && [[ "$head" != *[!0-9a-f]* ]]; } \
  || { echo "queue-gate-judge: HEAD_SHA is not 40 lower-case hex" >&2; exit 1; }
[ -n "$ref" ] || { echo "queue-gate-judge: no queue ref" >&2; exit 1; }

base=$(git rev-parse --verify -q "refs/remotes/origin/main^{commit}") \
  || { echo "queue-gate-judge: the default branch's tip is not readable" >&2; exit 1; }
list=$(git rev-list --first-parent "${base}..${head}") \
  || { echo "queue-gate-judge: cannot walk the group's history" >&2; exit 1; }
[ -n "$list" ] || { echo "queue-gate-judge: the group holds no commit above the default branch" >&2; exit 1; }

# every commit in the group is a merge of a pull request head that has a passed-audit record
for c in $list; do
  read -r -a parents <<<"$(git log -1 --format=%P "$c")"
  if [ "${#parents[@]}" -ne 2 ]; then
    echo "queue-gate-judge: ${c} is not a two-parent merge (${#parents[@]} parents);" \
         "queue merge method ${queue_merge_method} is required" >&2
    exit 1
  fi
  bash bin/audit-record-judge.sh "${parents[1]}" main \
    || { echo "queue-gate-judge: no passed-audit record for ${parents[1]}" >&2; exit 1; }
done

# main's judges over the group head: the same command lines the pull request gate runs
shim=$(mktemp -d) || exit 1
trap 'rm -rf "$shim"' EXIT
ln -s "$PWD/.github/agent/fixtures/testlib/pyyaml" "$shim/yaml" || exit 1
verdict=0
python3 -I .github/agent/bin/check-action-pins.py --verify-tags --git "$head" || verdict=1
git ls-tree -r -z --name-only "$head" \
  | GITHUB_BASE_REF=main ALLOWLIST_NUL=1 ALLOWLIST_HEAD_REV="$head" GITHUB_QUEUE_REF="$ref" \
    bash bin/check-file-allowlist.sh || verdict=1
PYTHONPATH="$shim" PIN_WIRING_JUDGE_GIT="$head" bash .github/agent/tests/pin-wiring-test.sh || verdict=1
PYTHONPATH="$shim" SCAN_GUARD_JUDGE_GIT="$head" bash bin/scan-no-workflow-call-test.sh || verdict=1
[ "$verdict" -eq 0 ] || { echo "queue-gate-judge: main's judges failed over ${head}" >&2; exit 1; }
