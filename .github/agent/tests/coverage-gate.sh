#!/usr/bin/env bash
# proves: REQ-AUD-018-AC2 — KNOWN GAP (owner question pending): the gate honours the reasoned exclusion list in coverage-exclusions.txt, which the AC text ("100% coverage") does not mention, and it measures only the auditor bin directory; widening it is a follow-up.
# REQ-AUD-18 AC2: the auditor's Python is held to the 100% coverage gate, the same as the Go
# (bin/coverage-gate.sh): ZERO uncovered eligible statements under .github/agent/bin/, measured
# over the parser unit tests AND the matrix suite (every `python3` the suite spawns is measured
# through coverage's subprocess patch). The only exclusions are the reasoned line ranges in
# .github/agent/coverage-exclusions.txt, checked by coverage-check.py.
#
# Needs a python3 on PATH with the hash-pinned coverage installed:
#   python3 -m pip install --require-hashes --only-binary=:all: -r .github/agent/coverage-requirements.txt
set -euo pipefail
cd "$(dirname "$0")/../../.."
python3 -c 'import coverage' 2>/dev/null || {
  echo "::error::coverage is not importable by python3 — install .github/agent/coverage-requirements.txt" >&2; exit 1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cat > "$W/rc" <<EOF
[run]
source = $PWD/.github/agent/bin
omit = $PWD/.github/agent/bin/tests/*
parallel = true
patch = subprocess
data_file = $W/.coverage
[report]
# NO implicit exclusions: coverage's default rule honours "# pragma: no cover", which would hide
# testable code with no reason. The only exclusions are coverage-exclusions.txt's reasoned ranges;
# this pattern never matches, and coverage-check.py also fails on any implicitly excluded line.
exclude_lines =
    (?!)
EOF
export COVERAGE_RCFILE="$W/rc" COVERAGE_PROCESS_START="$W/rc"
# The suites are independent and each process writes its own coverage data file (parallel = true), so they run at the same time and
# every data file is combined below, before the unchanged threshold check (advisor 0618: the job was 18 minutes, 14 of them the action-pin
# cases one after another). The pin cases run as PINS_SHARDS parallel shards of one list; coverage-shard-sum.py then proves the shards
# together completed exactly the whole list (the manifest is a dry listing of the file), each unit once, by name, and none failed, and coverage-shard-test.sh proves that
# partition and that check first.
PINS_SHARDS=4
unset UNIT_SHARD_DIR UNIT_SHARD_RUNNER UNIT_SHARDS UNIT_SHARD_TIMEOUT   # the unit shards run the real suite, under coverage, with the gate's own settings, never ones the environment left for a self-test
unset PINS_DRY PINS_SHARD   # every launch below is a real run (the self-test and the dry listing set PINS_DRY themselves), never one the environment left dry
bash .github/agent/tests/coverage-shard-test.sh > "$W/shardtest.log" 2>&1 \
  || { tail -25 "$W/shardtest.log" >&2; echo "::error::the shard partition test failed" >&2; exit 1; }
tail -1 "$W/shardtest.log"
PINS_DRY=1 bash .github/agent/tests/check-action-pins-test.sh > "$W/pins.manifest" 2>/dev/null \
  || { echo "::error::could not list the action-pin units" >&2; exit 1; }
bash .github/agent/tests/unit-shards.sh "$W/unit" > "$W/unit.log" 2>&1 & p_unit=$!   # the parser unit tests as UNIT_SHARDS (4) parallel shards under coverage; every shard's exit status is checked and unit-shard-sum.py proves every test finished once
bash .github/agent/tests/auditor-matrix-test.sh > "$W/matrix.log" 2>&1 & p_matrix=$!
p_pins=()
for i in $(seq 0 $((PINS_SHARDS-1))); do   # row 78: the action-pin checker's fixture cases (it lives here so its changes need the independent second review)
  PINS_SHARD=$i/$PINS_SHARDS bash .github/agent/tests/check-action-pins-test.sh > "$W/pins.$i.log" 2>&1 & p_pins+=($!)
done
# the k8s harness's fenced exclusion (advisor 0084): its refusals are branches of the same checker
bash .github/agent/tests/k8s-harness-fence-test.sh > "$W/fence.log" 2>&1 & p_fence=$!
bad=0
wait "$p_unit" || { cat "$W/unit.log" >&2; echo "::error::parser unit tests failed under coverage" >&2; bad=1; }
wait "$p_matrix" || { grep -A2 '^FAIL' "$W/matrix.log" >&2; tail -1 "$W/matrix.log" >&2
                      echo "::error::matrix suite failed under coverage" >&2; bad=1; }
for i in "${!p_pins[@]}"; do
  wait "${p_pins[$i]}" || { grep '^FAIL' "$W/pins.$i.log" >&2; tail -1 "$W/pins.$i.log" >&2
                            echo "::error::action-pin cases (shard $i/$PINS_SHARDS) failed under coverage" >&2; bad=1; }
done
wait "$p_fence" || { tail -25 "$W/fence.log" >&2; echo "::error::k8s fence cases failed under coverage" >&2; bad=1; }
[ "$bad" -eq 0 ] || exit 1
tail -1 "$W/matrix.log"
python3 .github/agent/tests/coverage-shard-sum.py "$W/pins.manifest" "$W"/pins.[0-9].log \
  || { echo "::error::the action-pin shards did not run the whole list exactly once" >&2; exit 1; }
tail -qn1 "$W"/pins.[0-9].log
tail -1 "$W/fence.log"
python3 -m coverage combine -q
python3 -m coverage json -q -o "$W/coverage.json"
python3 .github/agent/tests/coverage-check.py "$W/coverage.json" .github/agent/coverage-exclusions.txt \
  "${COVERAGE_REPORT_OUT:-/dev/null}"
