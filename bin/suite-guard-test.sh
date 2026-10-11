#!/usr/bin/env bash
# Tests for bin/suite-guard.sh (self-contained: needs only bash, git, python3). Proves:
#  - no tracked test file of any suite is zero bytes or whitespace-only (an empty script exits 0 and proves nothing);
#  - a suite that prints no case count, or a count below its committed floor, or a count of zero, fails;
#  - floors can only be raised: a floors file that lowers or drops a floor against the merge base fails unless the lowering is named.
# It prints "suite-guard: N passed, M failed" and fails if N+M is not the number of cases it declares.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
guard="$root/bin/suite-guard.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -s "$guard" ] || { echo "FAIL bin/suite-guard.sh is missing or empty"; echo "suite-guard: 0 passed, 1 failed"; exit 1; }
# expect RC LABEL WORD -- ARGS : the guard exits RC and its output contains WORD
expect() { local want=$1 label=$2 word=$3 out rc=0; shift 4; out=$(bash "$guard" "$@" 2>&1 < /dev/null) || rc=$?
  if [ "$rc" = "$want" ] && { [ -z "$word" ] || grep -Fqi -- "$word" <<< "$out"; }; then ok "$label"; else bad "$label -> rc=$rc (want $want), wanted '$word': ${out:0:160}"; fi; }

# ---- files: no empty test file ----------------------------------------------------------------------------------------------------
repo="$work/repo"; mkdir -p "$repo/bin" "$repo/.github/agent/tests" "$repo/tools/x" "$repo/pkg" "$repo/internal/a" "$repo/results" "$repo/bin/sub"
cd "$repo"; git init -q .; git config user.email t@example.com; git config user.name t; git config commit.gpgsign false
echo 'echo hi' > bin/a-test.sh; echo 'echo hi' > .github/agent/tests/b.sh; echo 'package x' > tools/x/y_test.go
echo 'pass' > bin/sub/test_z.py; echo 'x' > bin/plain.sh; : > results/.gitkeep; : > internal/a/__init__.py
git add -A; git commit -qm base
expect 0 "files: every test file has content (an empty .gitkeep and __init__.py are not tests)" "" -- files "$repo"
: > bin/a-test.sh; git add -A; expect 1 "files: a zero-byte bin/*-test.sh fails naming it" "bin/a-test.sh" -- files "$repo"
printf ' \n\t\n\r\n' > bin/a-test.sh; git add -A; expect 1 "files: a whitespace-only test script fails" "bin/a-test.sh" -- files "$repo"
echo 'echo hi' > bin/a-test.sh; : > .github/agent/tests/b.sh; git add -A; expect 1 "files: a zero-byte file under a tests/ directory fails" ".github/agent/tests/b.sh" -- files "$repo"
echo 'echo hi' > .github/agent/tests/b.sh; : > tools/x/y_test.go; git add -A; expect 1 "files: a zero-byte *_test.go fails" "tools/x/y_test.go" -- files "$repo"
echo 'package x' > tools/x/y_test.go; : > bin/sub/test_z.py; git add -A; expect 1 "files: a zero-byte test_*.py fails" "bin/sub/test_z.py" -- files "$repo"
echo 'pass' > bin/sub/test_z.py; git add -A
: > bin/untracked-test.sh; expect 0 "files: an untracked empty file is not judged (CI judges the tracked tree)" "" -- files "$repo"; rm bin/untracked-test.sh
cd "$root"
expect 0 "files: this repository holds no empty test file" "" -- files "$root"

# ---- count: the case count a suite prints --------------------------------------------------------------------------------------------
printf 'ok one\npass=55 fail=0\n' > "$work/l1"; printf 'x: 53 passed, 0 failed\n' > "$work/l2"; printf 'ok one\nok two\n' > "$work/l3"
printf 'pass=0 fail=0\n' > "$work/l4"; : > "$work/l5"; printf 'pass=12 fail=3\n' > "$work/l6"
expect 0 "count: pass=N fail=M is read" "55" -- count "$work/l1"
expect 0 "count: N passed, M failed is read" "53" -- count "$work/l2"
expect 1 "count: a log with no count line fails" "no case count" -- count "$work/l3"
expect 1 "count: a count of zero fails" "zero" -- count "$work/l4"
expect 1 "count: an empty log fails" "no case count" -- count "$work/l5"
expect 0 "count: failures do not change the count (the suite's own exit code says them)" "12" -- count "$work/l6"

# ---- floor: a suite below its committed floor, or unlisted, fails ---------------------------------------------------------------
printf '{"suite-a": 50, "suite-b": 10}\n' > "$work/floors.json"
expect 0 "floor: a count equal to the floor passes" "" -- floor "$work/floors.json" suite-a 50
expect 0 "floor: a count above the floor passes" "" -- floor "$work/floors.json" suite-a 51
expect 1 "floor: a count below the floor fails naming both" "below its floor" -- floor "$work/floors.json" suite-a 49
expect 1 "floor: a suite with no floor fails (a new suite is added to the file in the same PR)" "no floor" -- floor "$work/floors.json" suite-c 5
printf '{"suite-a": 0}\n' > "$work/zero.json"
expect 1 "floor: a floor of zero is refused (it would admit an empty suite)" "floor" -- floor "$work/zero.json" suite-a 5
printf '{"suite-a": 1, "suite-a": 2}\n' > "$work/dup.json"
expect 1 "floor: a duplicate key in the floors file is refused" "duplicate" -- floor "$work/dup.json" suite-a 5

# ---- run: run a suite, require its count line, hold it to its floor ----------------------------------------------------------------
mkdir -p "$work/s"
printf '#!/usr/bin/env bash\necho "ok x"\nexit 0\n' > "$work/s/silent.sh"
printf '#!/usr/bin/env bash\necho "x: 60 passed, 0 failed"\n' > "$work/s/good.sh"
printf '#!/usr/bin/env bash\necho "x: 60 passed, 2 failed"\nexit 1\n' > "$work/s/red.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$work/s/empty-out.sh"
: > "$work/s/zero.sh"
printf '{"silent": 1, "good": 50, "red": 50, "empty-out": 1, "zero": 1}\n' > "$work/rf.json"
expect 1 "run: a suite that exits 0 and prints no count fails" "no case count" -- run "$work/rf.json" silent "$work/s/silent.sh"
expect 1 "run: a suite with no output at all fails" "no case count" -- run "$work/rf.json" empty-out "$work/s/empty-out.sh"
expect 1 "run: a zero-byte suite file fails" "empty" -- run "$work/rf.json" zero "$work/s/zero.sh"
expect 0 "run: a suite at or above its floor passes and the count is printed" "60" -- run "$work/rf.json" good "$work/s/good.sh"
expect 1 "run: a suite that exits non-zero fails" "exit" -- run "$work/rf.json" red "$work/s/red.sh"
expect 0 "run: --count-only holds a known-red suite to its count and floor only, and prints its exit code" "rc=1" -- run --count-only "$work/rf.json" red "$work/s/red.sh"
printf '{"good": 70}\n' > "$work/rf2.json"
expect 1 "run: a suite below its floor fails" "below its floor" -- run "$work/rf2.json" good "$work/s/good.sh"

# ---- floors-vs-base: floors only rise ----------------------------------------------------------------------------------------------
cd "$repo"; mkdir -p test-evidence; printf '{"suite-a": 50, "suite-b": 10}\n' > test-evidence/suite-floors.json; git add -A; git commit -qm floors
base=$(git rev-parse HEAD)
printf '{"suite-a": 60, "suite-b": 10, "suite-c": 5}\n' > test-evidence/suite-floors.json
expect 0 "vs-base: raised floors and a new suite pass" "" -- floors-vs-base "$base" test-evidence/suite-floors.json
printf '{"suite-a": 40, "suite-b": 10}\n' > test-evidence/suite-floors.json
expect 1 "vs-base: a lowered floor fails naming the suite" "suite-a" -- floors-vs-base "$base" test-evidence/suite-floors.json
expect 0 "vs-base: a lowered floor the PR body names (--allow-lowered) passes" "" -- floors-vs-base --allow-lowered suite-a "$base" test-evidence/suite-floors.json
expect 1 "vs-base: naming another suite does not excuse it" "suite-a" -- floors-vs-base --allow-lowered suite-b "$base" test-evidence/suite-floors.json
printf '{"suite-a": 50}\n' > test-evidence/suite-floors.json
expect 1 "vs-base: a dropped suite fails" "suite-b" -- floors-vs-base "$base" test-evidence/suite-floors.json
printf '{"suite-a": 50, "suite-b": 10}\n' > test-evidence/suite-floors.json
expect 0 "vs-base: an unchanged file passes" "" -- floors-vs-base "$base" test-evidence/suite-floors.json
expect 0 "vs-base: a base without a floors file passes (the first PR that adds it)" "" -- floors-vs-base "$(git rev-list --max-parents=0 HEAD)" test-evidence/suite-floors.json
cd "$root"

EXPECT=34
echo "suite-guard: $pass passed, $failn failed"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT"; exit 1; fi
[ "$failn" = 0 ]
