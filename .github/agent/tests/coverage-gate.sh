#!/usr/bin/env bash
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
EOF
export COVERAGE_RCFILE="$W/rc" COVERAGE_PROCESS_START="$W/rc"
python3 -m coverage run -m unittest discover -s .github/agent/bin/tests -p 'test_*.py' 2> "$W/unit.log" \
  || { cat "$W/unit.log" >&2; echo "::error::parser unit tests failed under coverage" >&2; exit 1; }
bash .github/agent/tests/auditor-matrix-test.sh > "$W/matrix.log" 2>&1 \
  || { grep -A2 '^FAIL' "$W/matrix.log" >&2; tail -1 "$W/matrix.log" >&2
       echo "::error::matrix suite failed under coverage" >&2; exit 1; }
tail -1 "$W/matrix.log"
python3 -m coverage combine -q
python3 -m coverage json -q -o "$W/coverage.json"
python3 .github/agent/tests/coverage-check.py "$W/coverage.json" .github/agent/coverage-exclusions.txt \
  "${COVERAGE_REPORT_OUT:-/dev/null}"
