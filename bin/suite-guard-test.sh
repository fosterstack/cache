#!/usr/bin/env bash
# proves: REQ-CI-005-AC1, REQ-CI-005-AC2, REQ-CI-005-AC3, REQ-CI-005-AC4, REQ-CI-005-AC5 — a floored suite is run once by the step that counts it; `all` runs only the rest (the REQ-CI-005 cases)
# Tests for bin/suite-guard.sh (self-contained: needs only bash, git, python3). Proves:
#  - no tracked test file of any suite is zero bytes or whitespace-only (an empty script exits 0 and proves nothing);
#  - a suite that prints no case count, or a count below its committed floor, or a count of zero, fails;
#  - floors can only be raised: a floors file that lowers or drops a floor against the merge base fails unless the lowering is named.
# It prints "suite-guard: N passed, M failed" and fails if N+M is not the number of cases it declares.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
guard="$root/bin/suite-guard.sh"
runner="$root/bin/suite-guard-run.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -s "$guard" ] && [ -s "$runner" ] || { echo "FAIL bin/suite-guard.sh is missing or empty"; echo "suite-guard: 0 passed, 1 failed"; exit 1; }
# expect RC LABEL WORD -- ARGS : the guard exits RC and its output contains WORD
expect() { local want=$1 label=$2 word=$3 out rc=0 tool=$guard; shift 4; case "${1:-}" in run|all) tool=$runner ;; esac
  out=$(if [ "$tool" = "$runner" ]; then python3 -I "$tool" "$@"; else bash "$tool" "$@"; fi 2>&1 < /dev/null) || rc=$?
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

# ---- count: the case count a suite prints --------------------------------------------------------------------------------------------
printf 'ok one\npass=55 fail=0\n' > "$work/l1"; printf 'x: 53 passed, 0 failed\n' > "$work/l2"; printf 'all done\nnothing to count\n' > "$work/l3"
printf 'pass=0 fail=0\n' > "$work/l4"; : > "$work/l5"; printf 'pass=12 fail=3\n' > "$work/l6"
expect 0 "count: pass=N fail=M is read" "55" -- count "$work/l1"
expect 0 "count: N passed, M failed is read" "53" -- count "$work/l2"
expect 1 "count: a log with no count line fails" "no case count" -- count "$work/l3"
printf 'Ran 156 tests in 2.1s\n\nOK\n' > "$work/l7"; printf 'passed: 33 failed: 0\n' > "$work/l8"; printf '263 mutants, 263 killed; 0 failure(s)\n' > "$work/l9"
printf 'ok:   a\nok:   b\nFAIL c\nPASS d\n' > "$work/l10"
expect 0 "count: unittest's Ran N tests is read" "156" -- count "$work/l7"
expect 0 "count: passed: N failed: M is read" "33" -- count "$work/l8"
expect 0 "count: N mutants, N killed is read" "263" -- count "$work/l9"
expect 0 "count: with no summary, the ok/PASS lines are the count" "3" -- count "$work/l10"
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
printf '#!/usr/bin/env bash\necho "all done"\nexit 0\n' > "$work/s/silent.sh"
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

# ---- all: every suite named in the floors file is run (the run-all wrapper) ---------------------------------------------------------
mkdir -p "$work/all/bin"; cp "$work/s/good.sh" "$work/all/bin/a-test.sh"; cp "$work/s/red.sh" "$work/all/bin/b-test.sh"
printf '{"a-test.sh": 50, "b-test.sh": 50}\n' > "$work/all/floors.json"
expect 1 "all: a known-red suite fails the run unless --count-only" "exited" -- all "$work/all/floors.json" "$work/all"
expect 0 "all --count-only: every suite runs, prints its count and passes its floor" "a-test.sh: count 60" -- all --count-only "$work/all/floors.json" "$work/all"
printf '{"a-test.sh": 50, "gone-test.sh": 5}\n' > "$work/all/floors2.json"
expect 1 "all: a suite named in the floors file that is not there fails" "gone-test.sh" -- all --count-only "$work/all/floors2.json" "$work/all"
# a symlink named for a suite is not a suite (the old shell runner selected regular files only): the only match is a link -> zero files -> fails
mkdir -p "$work/lnk/bin"; ln -s "$work/s/good.sh" "$work/lnk/bin/a-test.sh"; printf '{"a-test.sh": 50}\n' > "$work/lnk/floors.json"
expect 1 "all: a symlink named for a suite is not found as a suite" "0 files" -- all --count-only "$work/lnk/floors.json" "$work/lnk"
# ROOT itself a symlink to a tree that holds the suite: not walked (find ROOT, physical, did not follow it)
mkdir -p "$work/lnkroot-real/bin"; cp "$work/s/good.sh" "$work/lnkroot-real/bin/a-test.sh"; ln -s "$work/lnkroot-real" "$work/lnkroot"; printf '{"a-test.sh": 50}\n' > "$work/lnkroot-floors.json"
expect 1 "all: a ROOT that is a symlink is refused" "not a real directory" -- all --count-only "$work/lnkroot-floors.json" "$work/lnkroot"
# a floors key is a plain file name: a glob character, a separator or a line break is refused before anything runs
mkdir -p "$work/gl/bin"; cp "$work/s/good.sh" "$work/gl/bin/a1-test.sh"
printf '{"a1-test.sh": 50, "a[1]-test.sh": 50}\n' > "$work/gl/floors.json"
expect 1 "all: a floors key with glob characters is refused" "plain file name" -- all --count-only "$work/gl/floors.json" "$work/gl"
# and nothing ran first: the valid suite named before the bad key is not executed (the whole floors file is refused up front)
if python3 -I "$runner" all --count-only "$work/gl/floors.json" "$work/gl" 2>&1 < /dev/null | grep -q 'count'; then bad "all: a valid suite ran before a bad floors key was refused"; else ok "all: no suite runs when a floors key is not a plain file name"; fi
printf '{"a?-test.sh": 50}\n' > "$work/gl/floors2.json"
expect 1 "all: a floors key with a ? is refused" "plain file name" -- all --count-only "$work/gl/floors2.json" "$work/gl"
# ROOT inside a .git directory: nothing below it is a suite (the shell runner's -not -path '*/.git/*')
mkdir -p "$work/in/.git/bin"; cp "$work/s/good.sh" "$work/in/.git/bin/a-test.sh"; printf '{"a-test.sh": 50}\n' > "$work/in/floors.json"
expect 1 "all: a ROOT inside a .git directory finds no suite" "0 files" -- all --count-only "$work/in/floors.json" "$work/in/.git"
# ROOT spellings the shell runner's find read differently: find syntax, a .. component, a line break in the path
cd "$work"   # the relative ROOT spellings below create their directories here, not in the checkout
for r in '(' '!' '-x' "$work/in/.git/../bin" "$work/nl
dir"; do
  mkdir -p "$r" 2> /dev/null || true
  expect 1 "all: a ROOT spelled [$(printf %s "$r" | tr '\n' '~')] is refused as not a plain path" "not a plain path" -- all --count-only "$work/in/floors.json" "$r"
done
mkdir -p "$work/nld/a
b"; cp "$work/s/good.sh" "$work/nld/a
b/a-test.sh"; printf '{"a-test.sh": 50}\n' > "$work/nld.json"
expect 1 "all: a suite below a directory whose name holds a line break is not run" "not a plain path" -- all --count-only "$work/nld.json" "$work/nld"
# a duplicate with an odd path: the valid file and one below a directory with a space are two matches, so neither runs (as the shell runner's find found two)
mkdir -p "$work/dup/ok" "$work/dup/bad space"; cp "$work/s/good.sh" "$work/dup/ok/a-test.sh"; cp "$work/s/good.sh" "$work/dup/bad space/a-test.sh"
printf '{"a-test.sh": 50}\n' > "$work/dup.json"
expect 1 "all: a same-name file below a directory with a space makes the name two files: neither runs" "2 files" -- all --count-only "$work/dup.json" "$work/dup"
# a single match with an odd path is not run either
mkdir -p "$work/one/bad space"; cp "$work/s/good.sh" "$work/one/bad space/a-test.sh"
expect 1 "all: the only match below a directory with a space is not run" "not a plain path" -- all --count-only "$work/dup.json" "$work/one"

# round 1 F7 (Codex B4): `all` runs each suite in an `||` context, where `set -e` is off; a suite below its floor must still fail the run
printf '{"a-test.sh": 70}\n' > "$work/all/floors3.json"
expect 1 "all: a suite that passes with fewer cases than its floor fails the run (the floor check is not swallowed by the || context)" "below its floor" -- all "$work/all/floors3.json" "$work/all"
expect 1 "all --count-only: a suite below its floor fails the run" "below its floor" -- all --count-only "$work/all/floors3.json" "$work/all"
printf '#!/usr/bin/env bash\necho "all done"\n' > "$work/all/bin/c-test.sh"; printf '{"a-test.sh": 50, "c-test.sh": 1}\n' > "$work/all/floors4.json"
expect 1 "all: a suite that prints no count fails the run" "no case count" -- all "$work/all/floors4.json" "$work/all"

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
# round 1 F7: a base revision that cannot be read is not "no floors file": the guard fails closed; only a readable base without the file passes
expect 1 "vs-base: a base revision that does not exist fails (it is not 'no floors file')" "base" -- floors-vs-base 0123456789012345678901234567890123456789 test-evidence/suite-floors.json
expect 1 "vs-base: an empty base revision fails" "base" -- floors-vs-base "" test-evidence/suite-floors.json
printf 'not json\n' > test-evidence/suite-floors.json; git add -A; git commit -qm broken
brk=$(git rev-parse HEAD); printf '{"suite-a": 50, "suite-b": 10}\n' > test-evidence/suite-floors.json
expect 1 "vs-base: a floors file at the base that is not valid JSON fails" "base" -- floors-vs-base "$brk" test-evidence/suite-floors.json
expect 0 "vs-base: a readable base without the floors file still passes" "no floors file" -- floors-vs-base "$(git rev-list --max-parents=0 HEAD)" test-evidence/suite-floors.json
cd "$root"
# round 2 (Codex B): an unreadable or empty floors file makes `all` fail, not pass having run nothing
printf 'not json\n' > "$work/bad-floors.json"; printf '{}\n' > "$work/empty-floors.json"; printf '[]\n' > "$work/list-floors.json"; printf '{"x-test.sh": "many"}\n' > "$work/str-floors.json"
expect 1 "all: a floors file that is not JSON fails (it must not pass having run no suite)" "floors" -- all --count-only "$work/bad-floors.json" "$work"
expect 1 "all: a floors file with no suite in it fails" "floors" -- all --count-only "$work/empty-floors.json" "$work"
expect 1 "all: a floors file that is a list, not an object, fails" "floors" -- all --count-only "$work/list-floors.json" "$work"
expect 1 "all: a floors file whose floor is not an integer fails" "floors" -- all --count-only "$work/str-floors.json" "$work"
# round 1 F7: CI runs the suites against their floors at real counts (bin/suite-guard-run.py all), not only the floors file against the base
if grep -Eq 'run: python3 -I bin/suite-guard-run\.py all( --count-only)? test-evidence/suite-floors\.json' "$root/.github/workflows/ci.yml"; then ok "ci.yml: a step runs bin/suite-guard-run.py all against test-evidence/suite-floors.json (real counts)"; else bad "ci.yml has no step running bin/suite-guard-run.sh all against the floors file"; fi

# ---- REQ-CI-005: a suite is run once, by the step that counts it; `all` runs only the rest ------------------------------------------------
# run shows the suite's own output (the step log keeps what `bash PATH` would have shown), exactly once
printf '#!/usr/bin/env bash\necho "marker-line-from-the-suite"\necho "x: 60 passed, 0 failed"\n' > "$work/s/chatty.sh"; printf '{"chatty": 50}\n' > "$work/rc.json"
expect 0 "REQ-CI-005-AC1 run: the suite's own output is shown, not swallowed" "marker-line-from-the-suite" -- run "$work/rc.json" chatty "$work/s/chatty.sh"
n=$(python3 -I "$runner" run "$work/rc.json" chatty "$work/s/chatty.sh" 2>&1 < /dev/null | grep -c 'marker-line-from-the-suite' || true)
if [ "$n" = 1 ]; then ok "REQ-CI-005-AC1 run: the suite's output appears exactly once"; else bad "REQ-CI-005-AC1 run: the suite's output appeared $n times"; fi
ln -s "$work/s/chatty.sh" "$work/s/link.sh"; printf '{"link": 50}\n' > "$work/rl.json"
expect 1 "REQ-CI-005-AC3 run: a suite that is a symlink is refused (as all always held)" "empty or missing" -- run "$work/rl.json" link "$work/s/link.sh"
# a repo with a workflow: trusted counting steps keep their suites out of `all`; the rest still runs; a bad counting step fails
mkdir -p "$work/cw/bin" "$work/cw/.github/workflows" "$work/cw/.github/policy" "$work/cw/test-evidence" "$work/cw/tools"
printf '{"required_checks": [{"context": "j", "integration_id": 15368, "scope": "push"}]}\n' > "$work/cw/.github/policy/required-checks.json"
for sname in a b c; do printf '#!/usr/bin/env bash\necho "ran-%s-in-all"\necho "x: 60 passed, 0 failed"\n' "$sname" > "$work/cw/bin/$sname-test.sh"; done
printf '{"a-test.sh": 50, "b-test.sh": 50, "c-test.sh": 50}\n' > "$work/cw/test-evidence/suite-floors.json"
F=test-evidence/suite-floors.json
CNT="python3 -I bin/suite-guard-run.py run $F"
# cwf JOB-KEYS-BLOCK STEP... : one job `j` (plus the optional extra keys) whose steps are the arguments, each a `run:` of its own; a step may carry extra keys as "RUN|key: value"
cwf() { local keys=$1; shift; { printf 'jobs:\n  j:\n    runs-on: x\n%s    steps:\n' "$keys"; local st; for st in "$@"; do
    if [[ "$st" == *"|"* ]]; then printf '      - run: %s\n        %s\n' "${st%%|*}" "${st#*|}"; else printf '      - run: %s\n' "$st"; fi; done; } > "$work/cw/.github/workflows/ci.yml"; }
cwall() { (cd "$work/cw" && python3 -I "$runner" all --count-only "$F" . 2>&1 < /dev/null); }
cwf "" "bash bin/a-test.sh"
out=$(cwall) || true; if grep -q "a-test.sh: count [0-9]" <<< "$out" && grep -q "b-test.sh: count [0-9]" <<< "$out"; then ok "REQ-CI-005-AC1 all: with no counting step every floored suite is run (as before)"; else bad "all with no counting step did not run every suite: ${out:0:200}"; fi
cwf "" "$CNT a-test.sh bin/a-test.sh" "CHAIN_TEST_REQUIRE_NETCUT=1 $CNT b-test.sh bin/b-test.sh </dev/null"
out=$(cwall) && rc=0 || rc=$?
if [ "$rc" = 0 ] && grep -q "c-test.sh: count [0-9]" <<< "$out" && ! grep -q "a-test.sh: count [0-9]" <<< "$out" && ! grep -q "b-test.sh: count [0-9]" <<< "$out" && grep -q 'a-test.sh: counted by its own step' <<< "$out"; then ok "REQ-CI-005-AC1 all: a suite that a counting step runs (plain, or with the one env prefix and </dev/null) is not run again, says so, and the rest is run"; else bad "all with counting steps: rc=$rc ${out:0:300}"; fi
cwf "" "$CNT zz-test.sh bin/zz-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'unfloored' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting step that names an unfloored suite fails"; else bad "unfloored counting step: rc=$rc ${out:0:200}"; fi
cwf "" "$CNT a-test.sh bin/b-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'file name of its PATH' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting step whose NAME is not the file name of its PATH fails"; else bad "name/path mismatch: rc=$rc ${out:0:200}"; fi
cwf "" "python3 -I bin/suite-guard-run.py run other-floors.json a-test.sh bin/a-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ]; then ok "REQ-CI-005-AC2 all: a counting step that reads another floors file fails"; else bad "other floors file: rc=$rc ${out:0:200}"; fi
cwf "" "$CNT a-test.sh bin/a-test.sh extra"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'not `run FLOORS NAME PATH`' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting step in another form (extra argument) fails"; else bad "odd form: rc=$rc ${out:0:200}"; fi
cwf "" "BASH_ENV=prelude.sh $CNT a-test.sh bin/a-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'not `run FLOORS NAME PATH`' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting step with an env prefix other than the one floored step's fails (no shell hook)"; else bad "env prefix: rc=$rc ${out:0:200}"; fi
# a counting line is trusted only as the WHOLE of its step: a line inside a here-document or after exit is no run, and is refused
{ printf 'jobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n          exit 0\n          %s a-test.sh bin/a-test.sh\n' "$CNT"; } > "$work/cw/.github/workflows/ci.yml"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'not the whole of its step' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting line after exit 0 (not the whole step) is refused, the suite is not skipped"; else bad "inert line: rc=$rc ${out:0:200}"; fi
{ printf 'jobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n          cat <<EOF >/dev/null\n          %s a-test.sh bin/a-test.sh\n          EOF\n' "$CNT"; } > "$work/cw/.github/workflows/ci.yml"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'not the whole of its step' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting line inside a here-document is refused"; else bad "here-doc line: rc=$rc ${out:0:200}"; fi
# a step or job that may not run does not count: the suite is still run here
for label in "a job with an if" "a job that needs another" "a job with a strategy" "a job with continue-on-error"; do
  case "$label" in "a job with an if") k=$'    if: false\n' ;; "a job that needs another") k=$'    needs: k\n' ;; "a job with a strategy") k=$'    strategy: {matrix: {x: [1]}}\n' ;; *) k=$'    continue-on-error: true\n' ;; esac
  cwf "$k" "$CNT a-test.sh bin/a-test.sh"
  out=$(cwall) || true; if grep -q "a-test.sh: count [0-9]" <<< "$out"; then ok "REQ-CI-005-AC1 all: a suite counted only by a step of $label is still run here"; else bad "$label was trusted: ${out:0:200}"; fi
done
for label in "if: false" "continue-on-error: true" "env: {A: b}" "shell: bash"; do
  cwf "" "$CNT a-test.sh bin/a-test.sh|$label"
  out=$(cwall) || true; if grep -q "a-test.sh: count [0-9]" <<< "$out"; then ok "REQ-CI-005-AC1 all: a counting step with '$label' is not trusted: its suite is still run here"; else bad "step with $label was trusted: ${out:0:200}"; fi
done
# a decoy PATH: the counting step runs another file of that name, so the real one would be skipped: refused
cwf "" "$CNT a-test.sh tools/a-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'not bin/a-test.sh\|the one file of that name' <<< "$out"; then ok "REQ-CI-005-AC2 all: a counting step whose PATH is not the one file of that name under ROOT fails (the decoy)"; else bad "decoy path: rc=$rc ${out:0:300}"; fi
cwf "" "$CNT a-test.sh bin/../bin/a-test.sh"
out=$(cwall) || true; if grep -q 'a-test.sh: counted by its own step' <<< "$out"; then ok "REQ-CI-005-AC1 all: the same file spelled with a .. component is still that file"; else bad "normalised path not accepted: ${out:0:200}"; fi
# a counted suite that is wrong is caught by its own step (AC3): below its floor, no count, non-zero exit
printf '{"chatty": 70}\n' > "$work/rc2.json"
expect 1 "REQ-CI-005-AC3 run: a counted suite that lost cases (below its floor) fails its step" "below its floor" -- run "$work/rc2.json" chatty "$work/s/chatty.sh"
expect 1 "REQ-CI-005-AC3 run: a counted suite that prints no count fails its step" "no case count" -- run "$work/rc.json" silent "$work/s/silent.sh"

# REQ-CI-005 on the real tree and the rulings of the audit record (cache#679 round 3, items 1 to 5)
# (1) the real ci.yml (REQ-CI-005-AC5): the suites `all` runs itself are exactly the ones the AC names, each with the number of runs the AC states (its plain steps plus `all`'s one); every other floored suite is counted by its own step
real=$(cd "$root" && python3 -I - <<'PY'
import importlib.util, json, re, yaml
sp = importlib.util.spec_from_file_location("r", "bin/suite-guard-run.py"); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
names = set(json.load(open("test-evidence/suite-floors.json")))
got, bad = m.counting_steps(".", "test-evidence/suite-floors.json", names)
rest = names - set(got)
ac = next(a for r in yaml.safe_load(open("requirements/requirements.yaml"))["requirements"] if r["id"] == "REQ-CI-005" for a in r["acceptance_criteria"] if a["id"] == "REQ-CI-005-AC5")
pinned = {n: int(k) for n, k in re.findall(r"([a-z0-9-]+-test\.sh) \((\d) runs?", ac["then"])}
ci = [l for l in open(".github/workflows/ci.yml").read().splitlines() if not l.lstrip().startswith("#")]
actual = {n: sum(1 for l in ci if re.search(r"\bbash [./A-Za-z0-9_-]*/%s\b" % re.escape(n), l)) + 1 for n in rest}
print("ok" if bad == 0 and rest == set(pinned) and len(pinned) == 3 and actual == pinned else "bad %s residual %s pinned %s actual %s" % (bad, sorted(rest), pinned, actual))
PY
)
if [ "$real" = "ok" ]; then ok "REQ-CI-005-AC5 the real ci.yml: all runs itself exactly the three suites the AC names, each run as many times as the AC states; every other floored suite is counted by its own step"; else bad "real ci.yml residual: $real"; fi
# (2) two counting steps for one suite: refused
cwf "" "$CNT a-test.sh bin/a-test.sh" "$CNT a-test.sh bin/a-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'more than one counting step' <<< "$out"; then ok "REQ-CI-005-AC1 all: two counting steps for one suite are refused (the suite would run twice)"; else bad "duplicate counting step: rc=$rc ${out:0:200}"; fi
# (2b) the same, the first counting step untrusted (an env key) and the second trusted: still refused, whatever the order
cwf "" "$CNT a-test.sh bin/a-test.sh|env: {A: b}" "$CNT a-test.sh bin/a-test.sh"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" = 1 ] && grep -q 'more than one counting step' <<< "$out"; then ok "REQ-CI-005-AC1 all: two counting steps for one suite are refused even when the first is untrusted"; else bad "duplicate, untrusted first: rc=$rc ${out:0:200}"; fi
# (3) a counting step in a job that is not a required check, nor needed by one: not trusted, the suite is still run by `all`
printf '{"required_checks": [{"context": "other", "integration_id": 15368, "scope": "push"}]}\n' > "$work/cw/.github/policy/required-checks.json"
cwf "" "$CNT a-test.sh bin/a-test.sh"
out=$(cwall) || true; if grep -q "a-test.sh: count [0-9]" <<< "$out"; then ok "REQ-CI-005-AC1 all: a counting step in a job that no required check is or needs is not trusted: its suite is still run here"; else bad "non-required job trusted: ${out:0:200}"; fi
{ printf 'jobs:\n  j:\n    runs-on: x\n    steps:\n      - run: %s a-test.sh bin/a-test.sh\n  other:\n    runs-on: x\n    needs: [j]\n    steps:\n      - run: echo gate\n' "$CNT"; } > "$work/cw/.github/workflows/ci.yml"
out=$(cwall) || true; if grep -q 'a-test.sh: counted by its own step' <<< "$out"; then ok "REQ-CI-005-AC1 all: a counting step in a job that a required check needs is trusted"; else bad "needed job not trusted: ${out:0:200}"; fi
rm "$work/cw/.github/policy/required-checks.json"
cwf "" "$CNT a-test.sh bin/a-test.sh"
out=$(cwall) || true; if grep -q "a-test.sh: count [0-9]" <<< "$out"; then ok "REQ-CI-005-AC1 all: with no required-checks policy no counting step is trusted (fail closed)"; else bad "no policy trusted: ${out:0:200}"; fi
printf '{"required_checks": [{"context": "j", "integration_id": 15368, "scope": "push"}]}\n' > "$work/cw/.github/policy/required-checks.json"
# (4) a jobs: that is not a mapping is a named refusal, never a traceback
printf 'jobs: []\n' > "$work/cw/.github/workflows/ci.yml"
out=$(cwall) && rc=0 || rc=$?; if [ "$rc" != 0 ] && ! grep -q Traceback <<< "$out" && grep -q 'cannot be read as a workflow' <<< "$out"; then ok "REQ-CI-005-AC2 all: a ci.yml whose jobs: is not a mapping is refused by name, no traceback"; else bad "jobs list: rc=$rc ${out:0:200}"; fi
# (5) `all` does not print the output of the suites it runs (only a counting step does, AC1)
cwf "" "bash bin/a-test.sh"
out=$(cwall) || true; if ! grep -q 'x: 60 passed' <<< "$out" && grep -q 'a-test.sh: count 60' <<< "$out"; then ok "REQ-CI-005-AC1 all: the suites it runs are counted, their own output is not reprinted"; else bad "all echoes suites: ${out:0:200}"; fi

EXPECT=99
echo "suite-guard: $pass passed, $failn failed"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT"; exit 1; fi
[ "$failn" = 0 ]
