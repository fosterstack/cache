#!/usr/bin/env bash
# proves: REQ-SCAN-001-AC1
# The auditor's fixtures and tests take the scanner panel's image set from bin/panel.py (VARIANTS), never from a literal list. Main ships v0.2.2
# with the debug variant (production, debug, fips: six images); chain-v030 drops it (production, fips: four). This guard runs the auditor's unit
# suite and the matrix suite on a copy of the working tree with bin/panel.py set to EACH of the two sets, so a fixture or test that hard-codes
# one set fails here on whichever branch it is written on, instead of when the other branch merges it (cache#478, pipeline take 25).
set -uo pipefail
repo="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$repo"
pass=0 fail=0
ok()  { pass=$((pass+1)); echo "ok:   $1"; }
bad() { fail=$((fail+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | tail -15 | sed 's/^/        /'; }

variants_line() { grep -nE '^VARIANTS = \(' bin/panel.py | head -1 | cut -d: -f1; }
[ -n "$(variants_line)" ] && ok "bin/panel.py declares VARIANTS on one line" || { bad "bin/panel.py declares VARIANTS on one line"; echo "auditor-variants: 0 passed, 1 failed"; exit 1; }

# What a passing suite looks like: exit status 0, the summary line, and a non-empty run (a floor, so a suite that discovers nothing or a copy that
# lost its tests cannot pass). The judging is a pair of functions, checked below against output they must refuse.
MIN_UNIT=100; MIN_MATRIX=100
unit_passes()   { local rc="$1" out="$2" n k; [ "$rc" -eq 0 ] || return 1; n="$(printf '%s' "$out" | sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' | tail -1)"
                  k="$(printf '%s' "$out" | sed -n 's/^OK (.*skipped=\([0-9][0-9]*\).*/\1/p' | tail -1)"; [ -n "$n" ] && [ $((n - ${k:-0})) -ge "$MIN_UNIT" ] && printf '%s' "$out" | grep -qE '^OK'; }   # skipped tests are not run tests
matrix_passes() { local rc="$1" out="$2" n; [ "$rc" -eq 0 ] || return 1; n="$(printf '%s' "$out" | sed -n 's/^auditor-matrix: \([0-9][0-9]*\) passed, 0 failed.*/\1/p' | tail -1)"; [ -n "$n" ] && [ "$n" -ge "$MIN_MATRIX" ]; }
unit_passes 0 $'Ran 625 tests in 5.1s\n\nOK (skipped=2)' && ok "the unit judge accepts a full passing run" || bad "the unit judge accepts a full passing run"
unit_passes 0 $'Ran 0 tests in 0.0s\n\nOK' && bad "the unit judge refuses a run that discovered no tests" || ok "the unit judge refuses a run that discovered no tests"
unit_passes 1 $'Ran 625 tests in 5.1s\n\nOK' && bad "the unit judge refuses a non-zero exit with an OK-looking summary" || ok "the unit judge refuses a non-zero exit with an OK-looking summary"
unit_passes 0 $'Ran 150 tests in 0.1s\n\nOK (skipped=150)' && bad "the unit judge refuses a run whose tests were all skipped" || ok "the unit judge refuses a run whose tests were all skipped"
unit_passes 0 $'Ran 625 tests in 5.1s\n\nFAILED (failures=1)' && bad "the unit judge refuses a failed run" || ok "the unit judge refuses a failed run"
matrix_passes 0 'auditor-matrix: 239 passed, 0 failed' && ok "the matrix judge accepts a full passing run" || bad "the matrix judge accepts a full passing run"
matrix_passes 0 'auditor-matrix: 0 passed, 0 failed' && bad "the matrix judge refuses an empty run" || ok "the matrix judge refuses an empty run"
matrix_passes 1 'auditor-matrix: 239 passed, 0 failed' && bad "the matrix judge refuses a non-zero exit" || ok "the matrix judge refuses a non-zero exit"
matrix_passes 0 'auditor-matrix: 200 passed, 3 failed' && bad "the matrix judge refuses failures" || ok "the matrix judge refuses failures"

run_with() {   # run_with <label> <tuple literal>
  local label="$1" tuple="$2" w out rc; w="$(mktemp -d)"
  # the working tree (tracked and new files), not the index: a change under review is what must pass. A copy that cannot be made is a failure.
  if ! { git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$w"; } 2>/dev/null; then
    bad "the working tree copies for VARIANTS = $label"; rm -rf "$w"; return
  fi
  # the copy is a git repository of its own (the layout check lists tracked files), never this checkout's .git
  if ! ( cd "$w" && git init -q && git add -A && git -c user.name=v -c user.email=v@v -c commit.gpgsign=false commit -qm copy ) >/dev/null 2>&1; then
    bad "the copy becomes a git repository for VARIANTS = $label"; rm -rf "$w"; return
  fi
  if ! python3 - "$w/bin/panel.py" "$tuple" <<'PYEOF'
import re, sys
p, tup = sys.argv[1], sys.argv[2]
s = open(p).read()
n = re.subn(r"^VARIANTS = \(.*\)", "VARIANTS = " + tup, s, count=1, flags=re.M)
assert n[1] == 1, "VARIANTS line not found"
open(p, "w").write(n[0])
PYEOF
  then bad "bin/panel.py takes VARIANTS = $label in the copy"; rm -rf "$w"; return; fi
  out="$(cd "$w" && python3 -m unittest discover -s .github/agent/bin/tests -p 'test_*.py' 2>&1)"; rc=$?
  if unit_passes "$rc" "$out"; then ok "the auditor's unit suite passes with VARIANTS = $label"; else bad "the auditor's unit suite passes with VARIANTS = $label" "$(printf '%s' "$out" | tail -6)"; fi
  out="$(cd "$w" && bash .github/agent/tests/auditor-matrix-test.sh 2>&1)"; rc=$?
  if matrix_passes "$rc" "$out"; then ok "the matrix suite passes with VARIANTS = $label"; else bad "the matrix suite passes with VARIANTS = $label" "$(printf '%s' "$out" | grep -E '^FAIL|^auditor-matrix:' | cut -c1-200)"; fi
  rm -rf "$w"
}

run_with "production, debug, fips (main)" '("production", "debug", "fips")'
run_with "production, fips (chain-v030)" '("production", "fips")'

echo "auditor-variants: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
