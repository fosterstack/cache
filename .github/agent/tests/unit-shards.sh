#!/usr/bin/env bash
# proves: REQ-AUD-018-AC2
# The auditor's parser unit tests as parallel shards, for the coverage gate (CI speed, advisor item 6): the one `coverage run -m unittest
# discover` was the gate's long pole. Usage: unit-shards.sh OUTDIR. The shards run under whatever coverage environment the caller exported
# (coverage-gate.sh: parallel = true, one data file per process, combined by the gate before its unchanged threshold check).
#   UNIT_SHARDS          how many shards (default 4)
#   UNIT_SHARD_TIMEOUT   seconds each shard may run before it is killed (default 1500); a killed or timed-out shard is a non-zero status
#   UNIT_SHARD_RUNNER    how a shard is started (default `python3 -m coverage run`); the tests of this script use `python3`
# Exit 0 only if the manifest listing worked, EVERY shard exited 0 (any other status -- a failing test, a kill, a timeout -- fails), and
# unit-shard-sum.py proves the shards together finished every test exactly once. A shard's stderr (unittest's text) is kept in OUTDIR/unit.I.err.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: unit-shards.sh OUTDIR}
n=${UNIT_SHARDS:-4}; limit=${UNIT_SHARD_TIMEOUT:-1500}; runner=${UNIT_SHARD_RUNNER:-python3 -m coverage run}
case "$n" in ''|*[!0-9]*|0) echo "::error::UNIT_SHARDS must be a positive number, got '$n'" >&2; exit 1;; esac
case "$limit" in ''|*[!0-9]*|0) echo "::error::UNIT_SHARD_TIMEOUT must be a positive number of seconds, got '$limit'" >&2; exit 1;; esac
mkdir -p "$out" || exit 1
out=$(mktemp -d "$out/shards.XXXXXX") || exit 1   # this run's files live in a fresh directory of their own
python3 "$here/unit-shard.py" list > "$out/unit.manifest" 2> "$out/unit.manifest.err" \
  || { cat "$out/unit.manifest" "$out/unit.manifest.err" >&2; echo "::error::could not list the unit tests" >&2; exit 1; }
pids=()
for i in $(seq 0 $((n-1))); do
  # shellcheck disable=SC2086
  timeout "$limit" $runner "$here/unit-shard.py" run "$i" "$n" > "$out/unit.$i.log" 2> "$out/unit.$i.err" & pids+=($!)
done
bad=0
for i in "${!pids[@]}"; do
  wait "${pids[$i]}"; rc=$?
  if [ "$rc" -ne 0 ]; then
    tail -40 "$out/unit.$i.err" >&2
    echo "::error::parser unit tests shard $i/$n exited $rc under coverage (124 = timed out after ${limit}s, 137 = killed)" >&2; bad=1
  fi
done
[ "$bad" -eq 0 ] || exit 1
python3 "$here/unit-shard-sum.py" "$out/unit.manifest" "$out"/unit.[0-9]*.log || exit 1
