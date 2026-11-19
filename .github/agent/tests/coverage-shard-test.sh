#!/usr/bin/env bash
# proves: REQ-AUD-018-AC2
# The coverage gate (coverage-gate.sh) runs the auditor's parser unit tests as parallel shards (advisor 0618). This proves the sharding cannot
# lose or double a test: unit-shard.py lists and runs one shard, unit-shards.sh runs them all and fails on any non-zero shard status, and
# unit-shard-sum.py proves every test finished exactly once.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
pass=0; fail=0
ok() { echo "ok   $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; fail=$((fail+1)); }
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT


# --- the auditor's parser unit tests run as parallel shards too (advisor item 6): unit-shard.py lists and runs one shard (the unit is the test
# class), unit-shards.sh runs them all and fails on any non-zero shard status (a failing test, a kill, a timeout), and unit-shard-sum.py proves
# every test finished exactly once. A fixture directory of seven tests in three classes stands in for the real suite so each refusal takes seconds.
ush="$here/unit-shard.py"; ushs="$here/unit-shards.sh"; usum="$here/unit-shard-sum.py"
fx="$w/fx"; mkdir -p "$fx"
cat > "$fx/test_a.py" <<'PY'
import os, signal, time, unittest
class A1(unittest.TestCase):
    def test_one(self): self.assertTrue(True)
    def test_two(self):
        if os.environ.get("FX_FAIL"): self.fail("boom")
class A2(unittest.TestCase):
    def test_three(self): pass
    @unittest.skip("fixture skip")
    def test_four(self): pass
PY
cat > "$fx/test_b.py" <<'PY'
import os, signal, time, unittest
class B1(unittest.TestCase):
    def test_five(self):
        if os.environ.get("FX_KILL"): os.kill(os.getpid(), signal.SIGKILL)
    def test_six(self):
        if os.environ.get("FX_SLEEP"): time.sleep(60)
    def test_seven(self): pass
PY
unset FX_FAIL FX_KILL FX_SLEEP
UNIT_SHARD_DIR="$fx" python3 "$ush" list > "$w/um" 2>"$w/um.err"; urc=$?
[ "$urc" -eq 0 ] && grep -q '^unit-shard: list classes=3 tests=7$' "$w/um" && ok "unit-shard list: the fixture's 3 classes and 7 tests are listed from the files" || no "unit-shard list: rc=$urc $(tail -2 "$w/um")"
UNIT_SHARD_DIR="$fx" python3 "$ush" run 0 2 > "$w/u0" 2>/dev/null; r0=$?; UNIT_SHARD_DIR="$fx" python3 "$ush" run 1 2 > "$w/u1" 2>/dev/null; r1=$?
{ [ "$r0" -eq 0 ] && [ "$r1" -eq 0 ]; } && ok "unit-shard run: both shards of a good fixture exit 0" || no "unit-shard run exits $r0 $r1"
[ "$(cat "$w/u0" "$w/u1" | grep -c '^\(PASS\|SKIP\) ')" = 7 ] && ok "unit-shard run: the two shards finish the seven tests between them" || no "unit-shard run finished $(cat "$w/u0" "$w/u1" | grep -c '^\(PASS\|SKIP\) ') tests"
grep -q '^SKIP test_a.A2.test_four$' "$w/u0" "$w/u1" && ok "unit-shard run: a skipped test is a SKIP line, not a pass and not a failure" || no "no SKIP line for the skipped test"
usc() { python3 "$usum" "$@" > "$w/uchk.out" 2>&1; }
usc "$w/um" "$w/u0" "$w/u1" && ok "unit-shard-sum: a complete two-shard run passes" || no "a good unit run was refused: $(cat "$w/uchk.out")"
# the checker refuses every wrong shape (hand-edited copies of the good logs)
# a short log: one finished test removed and the counts rewritten to agree, so only the share check can refuse it
python3 - "$w/u0" "$w/short" <<'PY'
import re, sys
L = open(sys.argv[1]).read().splitlines()
i = next(k for k, x in enumerate(L) if x.startswith("PASS "))
del L[i]
n = sum(1 for x in L if x.startswith(("PASS ", "SKIP ")))
p = sum(1 for x in L if x.startswith("PASS ")); sk = sum(1 for x in L if x.startswith("SKIP "))
L = [re.sub(r" ran=\d+$", " ran=%d" % n, x) for x in L]
L = [("unit-shard: %d passed, %d skipped, 0 failed" % (p, sk)) if x.startswith("unit-shard: ") and " passed," in x else x for x in L]
open(sys.argv[2], "w").write("\n".join(L) + "\n")
PY
usc "$w/um" "$w/short" "$w/u1" && no "a short shard passed" || ok "unit-shard-sum: a shard with a finished test missing is refused"
# a test finished in the WRONG shard with the union still complete and every count consistent: only the share check can refuse it
python3 - "$w/u0" "$w/u1" "$w/wr0" "$w/wr1" <<'PY'
import re, sys
a, b = (open(x).read().splitlines() for x in sys.argv[1:3])
mv = next(x for x in a if x.startswith("PASS "))
a.remove(mv); b.append(mv)
def fix(L):
    n = sum(1 for x in L if x.startswith(("PASS ", "SKIP "))); p = sum(1 for x in L if x.startswith("PASS ")); sk = n - p
    L = [re.sub(r" ran=\d+$", " ran=%d" % n, x) for x in L]
    return [("unit-shard: %d passed, %d skipped, 0 failed" % (p, sk)) if x.startswith("unit-shard: ") and " passed," in x else x for x in L]
open(sys.argv[3], "w").write("\n".join(fix(a)) + "\n"); open(sys.argv[4], "w").write("\n".join(fix(b)) + "\n")
PY
usc "$w/um" "$w/wr0" "$w/wr1" && no "a test in the wrong shard passed" || ok "unit-shard-sum: a test finished in a shard other than its own is refused (union complete, counts consistent)"
usc "$w/um" "$w/u0" && no "a missing shard passed" || ok "unit-shard-sum: a missing shard is refused"
usc "$w/um" "$w/u0" "$w/u0" && no "a repeated shard passed" || ok "unit-shard-sum: a repeated shard is refused"
{ cat "$w/u0"; echo "PASS test_a.A1.test_one"; } > "$w/dup"
usc "$w/um" "$w/dup" "$w/u1" && no "a test finished twice passed" || ok "unit-shard-sum: a test finished twice is refused"
{ cat "$w/u0"; echo "PASS test_zzz.Nope.test_x"; } > "$w/unk"
usc "$w/um" "$w/unk" "$w/u1" && no "an unknown test passed" || ok "unit-shard-sum: a finished test that is not in the manifest is refused"
{ cat "$w/u1"; echo "FAIL test_a.A1.test_two"; } > "$w/fl"
usc "$w/um" "$w/u0" "$w/fl" && no "a FAIL line passed" || ok "unit-shard-sum: a FAIL line is refused even behind a zero-failure summary"
sed 's/ 0 failed$/ 1 failed/' "$w/u1" > "$w/f1"
usc "$w/um" "$w/u0" "$w/f1" && no "a failed count passed" || ok "unit-shard-sum: a closing line that counts a failure is refused"
grep -v '^unit-shard: shard' "$w/u1" > "$w/nosum"
usc "$w/um" "$w/u0" "$w/nosum" && no "a log without a summary passed" || ok "unit-shard-sum: a log with no summary line is refused"
usc "$w/um" "$w/u0" "$w/nonexistent" && no "an unreadable log passed" || ok "unit-shard-sum: an unreadable log is refused"
sed 's#shard 1/2#shard 0/2#' "$w/u1" > "$w/swap1b"
usc "$w/um" "$w/u0" "$w/swap1b" && no "two logs claiming shard 0 passed" || ok "unit-shard-sum: two logs claiming the same shard are refused"
sed 's/^unit-shard: shard 1\/2 classes=3 tests=7/unit-shard: shard 1\/2 classes=3 tests=9/' "$w/u1" > "$w/other"
usc "$w/um" "$w/u0" "$w/other" && no "a shard that saw a different list passed" || ok "unit-shard-sum: a shard that saw a different test count is refused"
sed '$d' "$w/um" > "$w/um-open"
usc "$w/um-open" "$w/u0" "$w/u1" && no "a manifest with no closing line passed" || ok "unit-shard-sum: a manifest with no closing line is refused"
printf 'unit-shard: list classes=0 tests=0\n' > "$w/um0"
usc "$w/um0" "$w/u0" "$w/u1" && no "an empty manifest passed" || ok "unit-shard-sum: an empty manifest is refused"
# the whole-run script: exit 0 on a good run; every kind of non-zero shard status fails it
ushs_run() { env UNIT_SHARD_DIR="$fx" UNIT_SHARD_RUNNER=python3 UNIT_SHARDS=2 "$@" bash "$ushs" "$w/ur" > "$w/ur.out" 2>&1; }
rm -rf "$w/ur"; ushs_run; [ $? -eq 0 ] && grep -q '^unit-shard-sum: ok: 2 shards finished all 7 tests' "$w/ur.out" && ok "unit-shards: a good fixture run exits 0 and proves all 7 tests ran once" || no "unit-shards refused a good run: $(tail -3 "$w/ur.out")"
rm -rf "$w/ur"; ushs_run FX_FAIL=1; [ $? -ne 0 ] && ok "unit-shards: a failing test fails the run" || no "a failing test passed"
rm -rf "$w/ur"; ushs_run FX_KILL=1; kr=$?
[ "$kr" -ne 0 ] && grep -q 'exited 137' "$w/ur.out" && ok "unit-shards: a shard killed by SIGKILL (status 137) fails the run, and the log says so" || no "a killed shard: rc=$kr $(tail -2 "$w/ur.out")"
rm -rf "$w/ur"; ushs_run FX_SLEEP=1 UNIT_SHARD_TIMEOUT=2; tr=$?
[ "$tr" -ne 0 ] && grep -q 'exited 124' "$w/ur.out" && ok "unit-shards: a shard that times out (status 124) fails the run, and the log says so" || no "a timed-out shard: rc=$tr $(tail -2 "$w/ur.out")"
rm -rf "$w/ur"; ushs_run UNIT_SHARDS=5; [ $? -ne 0 ] && ok "unit-shards: more shards than classes (a shard that selects nothing) fails the run" || no "an empty shard passed"
rm -rf "$w/ur"; ushs_run UNIT_SHARDS=0; [ $? -ne 0 ] && ok "unit-shards: UNIT_SHARDS=0 is refused" || no "UNIT_SHARDS=0 passed"
rm -rf "$w/ur"; ushs_run UNIT_SHARD_TIMEOUT=abc; [ $? -ne 0 ] && ok "unit-shards: a non-numeric timeout is refused" || no "a bad timeout passed"
cp -r "$fx" "$w/fxbad"; printf 'import does_not_exist_anywhere\n' > "$w/fxbad/test_c.py"
rm -rf "$w/ur"; UNIT_SHARD_DIR="$w/fxbad" UNIT_SHARD_RUNNER=python3 UNIT_SHARDS=2 bash "$ushs" "$w/ur" > "$w/ur.out" 2>&1; [ $? -ne 0 ] && ok "unit-shards: a test module that fails to import fails the run (it would otherwise vanish from the list)" || no "an unimportable module passed"
# a skip raised by setUpClass never starts the class's tests: each must still get its SKIP line, or the sum check sees them as missing
mkdir -p "$w/fxskip"
cat > "$w/fxskip/test_s.py" <<'PY'
import unittest
class S1(unittest.TestCase):
    @classmethod
    def setUpClass(cls): raise unittest.SkipTest("class fixture skip")
    def test_a(self): pass
    def test_b(self): pass
class S2(unittest.TestCase):
    def test_c(self): pass
PY
rm -rf "$w/ur"; UNIT_SHARD_DIR="$w/fxskip" UNIT_SHARD_RUNNER=python3 UNIT_SHARDS=2 bash "$ushs" "$w/ur" > "$w/ur.out" 2>&1; sk=$?
{ [ "$sk" -eq 0 ] && grep -q '^unit-shard-sum: ok: 2 shards finished all 3 tests' "$w/ur.out"; } && ok "unit-shards: tests skipped by a setUpClass SkipTest are accounted for as SKIP, and the run passes" || no "setUpClass skip: rc=$sk $(tail -3 "$w/ur.out")"
mkdir -p "$w/fxtd"
cat > "$w/fxtd/test_t.py" <<'PY'
import unittest
class T1(unittest.TestCase):
    @classmethod
    def tearDownClass(cls): raise unittest.SkipTest("teardown skip")
    def test_a(self): pass
    def test_b(self): pass
PY
rm -rf "$w/ur"; UNIT_SHARD_DIR="$w/fxtd" UNIT_SHARD_RUNNER=python3 UNIT_SHARDS=1 bash "$ushs" "$w/ur" > "$w/ur.out" 2>&1; td=$?
{ [ "$td" -eq 0 ] && grep -q '^unit-shard-sum: ok: 1 shards finished all 2 tests' "$w/ur.out"; } && ok "unit-shards: a SkipTest from tearDownClass does not double the finished tests, and the run passes" || no "tearDownClass skip: rc=$td $(tail -3 "$w/ur.out")"
mkdir -p "$w/fxcl"
cat > "$w/fxcl/test_u.py" <<'PY'
import unittest
class U1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def clean(): raise unittest.SkipTest("cleanup skip")
        cls.addClassCleanup(clean)
        raise unittest.SkipTest("setup skip")
    def test_a(self): pass
    def test_b(self): pass
PY
rm -rf "$w/ur"; UNIT_SHARD_DIR="$w/fxcl" UNIT_SHARD_RUNNER=python3 UNIT_SHARDS=1 bash "$ushs" "$w/ur" > "$w/ur.out" 2>&1; cl=$?
{ [ "$cl" -eq 0 ] && grep -q '^unit-shard-sum: ok: 1 shards finished all 2 tests' "$w/ur.out"; } && ok "unit-shards: a setUpClass skip plus a skipping class cleanup gives each test one SKIP line, and the run passes" || no "setup+cleanup skip: rc=$cl $(tail -3 "$w/ur.out")"
# the gate boundary: the self-test overrides must not reach the real unit shards, and the helpers are measured or excluded with a reason
grep -q '^unset UNIT_SHARD_DIR UNIT_SHARD_RUNNER UNIT_SHARDS UNIT_SHARD_TIMEOUT' "$here/coverage-gate.sh" && ok "coverage-gate.sh clears the four UNIT_SHARD* overrides before it launches the unit shards" || no "coverage-gate.sh does not clear the UNIT_SHARD* overrides"
ex="$here/../coverage-exclusions.txt"
{ grep -q '^\.github/agent/tests/unit-shard\.py  ' "$ex" && grep -q '^\.github/agent/tests/unit-shard-sum\.py  ' "$ex"; } && ok "the two unit-shard helpers are excluded from coverage with a reason" || no "the unit-shard helpers are not in coverage-exclusions.txt"
# the real suite: the listing is read from the files, partitions by class into non-empty shards, and the gate calls the shard script
UNIT_SHARD_DIR="" python3 "$ush" list > "$w/real.man" 2>"$w/real.err"; rrc=$?
rt=$(grep -c '^TEST ' "$w/real.man")
{ [ "$rrc" -eq 0 ] && [ "$rt" -ge 500 ]; } && ok "the real suite's listing runs and is read from the files ($rt tests)" || no "the real listing: rc=$rrc tests=$rt $(tail -2 "$w/real.err")"
emptyshard=0; for i in 0 1 2 3; do c=$(awk -v i=$i '$1=="TEST" && $2%4==i' "$w/real.man" | wc -l | tr -d ' '); [ "$c" -gt 0 ] || emptyshard=1; done
[ "$emptyshard" -eq 0 ] && ok "the real suite's four shards each hold at least one test" || no "a real shard is empty"
grep -q 'unit-shards.sh' "$here/coverage-gate.sh" && ! grep -q 'coverage run -m unittest discover' "$here/coverage-gate.sh" && ok "coverage-gate.sh runs the unit tests through unit-shards.sh, no longer as one unittest process" || no "coverage-gate.sh does not use unit-shards.sh"

echo "coverage-shard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
