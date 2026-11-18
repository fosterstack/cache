#!/usr/bin/env bash
# Tests for bin/suite-guard.sh (self-contained: needs only bash and git). Proves:
#  - no tracked test file of any suite is zero bytes or whitespace-only (an empty script exits 0 and proves nothing).
# It prints "suite-guard: N passed, M failed" and exits non-zero if any case fails.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
guard="$root/bin/suite-guard.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -s "$guard" ] || { echo "FAIL bin/suite-guard.sh is missing or empty"; echo "suite-guard: 0 passed, 1 failed"; exit 1; }
# expect RC LABEL WORD -- ARGS : the guard exits RC and its output contains WORD
expect() { local want=$1 label=$2 word=$3 out rc=0; shift 4
  out=$(bash "$guard" "$@" 2>&1 < /dev/null) || rc=$?
  if [ "$rc" = "$want" ] && { [ -z "$word" ] || grep -Fqi -- "$word" <<< "$out"; }; then ok "$label"; else bad "$label -> rc=$rc (want $want), wanted '$word': ${out:0:160}"; fi; }
# ---- files: no empty test file ----------------------------------------------------------------------------------------------------
repo="$work/repo"; mkdir -p "$repo/bin" "$repo/pkg/tests" "$repo/tools/x" "$repo/internal/a" "$repo/results" "$repo/bin/sub"
cd "$repo"; git init -q .; git config user.email t@example.com; git config user.name t; git config commit.gpgsign false
echo 'echo hi' > bin/a-test.sh; echo 'echo hi' > pkg/tests/b.sh; echo 'package x' > tools/x/y_test.go
echo 'pass' > bin/sub/test_z.py; echo 'x' > bin/plain.sh; : > results/.gitkeep; : > internal/a/__init__.py
git add -A; git commit -qm base
expect 0 "files: every test file has content (an empty .gitkeep and __init__.py are not tests)" "" -- files "$repo"
: > bin/a-test.sh; git add -A; expect 1 "files: a zero-byte bin/*-test.sh fails naming it" "bin/a-test.sh" -- files "$repo"
printf ' \n\t\n\r\n' > bin/a-test.sh; git add -A; expect 1 "files: a whitespace-only test script fails" "bin/a-test.sh" -- files "$repo"
echo 'echo hi' > bin/a-test.sh; : > pkg/tests/b.sh; git add -A; expect 1 "files: a zero-byte file under a tests/ directory fails" "pkg/tests/b.sh" -- files "$repo"
echo 'echo hi' > pkg/tests/b.sh; : > tools/x/y_test.go; git add -A; expect 1 "files: a zero-byte *_test.go fails" "tools/x/y_test.go" -- files "$repo"
echo 'package x' > tools/x/y_test.go; : > bin/sub/test_z.py; git add -A; expect 1 "files: a zero-byte test_*.py fails" "bin/sub/test_z.py" -- files "$repo"
echo 'pass' > bin/sub/test_z.py; git add -A
: > bin/untracked-test.sh; expect 0 "files: an untracked empty file is not judged (CI judges the tracked tree)" "" -- files "$repo"; rm bin/untracked-test.sh
cd "$root"
expect 0 "files: this repository holds no empty test file" "" -- files "$root"

echo "suite-guard: $pass passed, $failn failed"
[ "$failn" = 0 ]
