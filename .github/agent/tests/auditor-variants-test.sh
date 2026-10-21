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

run_with() {   # run_with <label> <tuple literal>
  local label="$1" tuple="$2" w; w="$(mktemp -d)"
  # the working tree (tracked and new files), not the index: a change under review is what must pass
  { git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$w"; } 2>/dev/null
  # the copy is a git repository of its own (the layout check lists tracked files), never this checkout's .git
  ( cd "$w" && git init -q && git add -A && git -c user.name=v -c user.email=v@v -c commit.gpgsign=false commit -qm copy ) >/dev/null 2>&1
  python3 - "$w/bin/panel.py" "$tuple" <<'PYEOF'
import re, sys
p, tup = sys.argv[1], sys.argv[2]
s = open(p).read()
n = re.subn(r"^VARIANTS = \(.*\)", "VARIANTS = " + tup, s, count=1, flags=re.M)
assert n[1] == 1, "VARIANTS line not found"
open(p, "w").write(n[0])
PYEOF
  local out
  out="$(cd "$w" && python3 -m unittest discover -s .github/agent/bin/tests -p 'test_*.py' 2>&1 | tail -4)"
  if printf '%s' "$out" | grep -qE '^OK'; then ok "the auditor's unit suite passes with VARIANTS = $label"; else bad "the auditor's unit suite passes with VARIANTS = $label" "$out"; fi
  out="$(cd "$w" && bash .github/agent/tests/auditor-matrix-test.sh 2>&1 | grep -E '^FAIL|^auditor-matrix:' | cut -c1-200)"
  if printf '%s' "$out" | grep -qE '^auditor-matrix: [0-9]+ passed, 0 failed'; then ok "the matrix suite passes with VARIANTS = $label"; else bad "the matrix suite passes with VARIANTS = $label" "$out"; fi
  rm -rf "$w"
}

run_with "production, debug, fips (main)" '("production", "debug", "fips")'
run_with "production, fips (chain-v030)" '("production", "fips")'

echo "auditor-variants: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
