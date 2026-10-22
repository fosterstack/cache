#!/usr/bin/env bash
# proves: REQ-AUD-018-AC2
# The coverage gate (coverage-gate.sh) runs the action-pin cases as parallel shards (advisor 0618). This proves the sharding cannot
# lose or double a case: the dry listing of check-action-pins-test.sh is the full list; four shards partition it exactly (no unit
# twice, none missing, every shard non-empty); and coverage-shard-sum.py, which the gate runs on the shards' logs with the dry listing as its manifest, refuses a short
# sum, a unit completed twice or in the wrong shard, an unknown unit, a shard that saw a different list, a missing or repeated shard, a failing shard,
# a dry log and a log with no summary; a real shard that selects no unit fails.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
pins="$here/check-action-pins-test.sh"; sumchk="$here/coverage-shard-sum.py"
pass=0; fail=0
unset PINS_DRY PINS_SHARD   # the real launches below are real whatever the environment holds; the dry ones set it themselves
ok() { echo "ok   $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; fail=$((fail+1)); }
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT

# --- the dry listing is the full list, read from the file (never a number written here)
PINS_DRY=1 bash "$pins" > "$w/all.out" 2>"$w/all.err"; rc=$?
[ "$rc" -eq 0 ] && ok "the dry listing runs (exit 0)" || no "the dry listing failed: $(tail -3 "$w/all.err")"
grep '^UNIT ' "$w/all.out" | awk '{print $3}' | sort > "$w/all.names"
total=$(wc -l < "$w/all.names" | tr -d ' ')
[ "$total" -ge 1000 ] && ok "the full list is read from the file ($total units)" || no "the full list is implausibly short: $total"
[ -z "$(sort "$w/all.names" | uniq -d)" ] && ok "no unit name appears twice in the full list" || no "duplicate unit names: $(sort "$w/all.names" | uniq -d | head -3)"
grep -q "^check-action-pins: shard 0/1 units=$total ran=$total\$" "$w/all.out" && ok "the dry summary of the whole file names the total and ran = total (nothing executed)" || no "dry summary: $(grep '^check-action-pins: shard' "$w/all.out")"
# (the two pm-case checks only count the case_out calls, run or not, so they print in every mode)
grep '^PASS \|^FAIL ' "$w/all.out" | grep -v '^PASS pm-case-' | grep -q . && no "the dry listing executed a case" || ok "the dry listing executes no case"

# --- four shards partition the list exactly
: > "$w/union"; sumran=0; empty=0
for i in 0 1 2 3; do
  PINS_DRY=1 PINS_SHARD=$i/4 bash "$pins" > "$w/s$i.out" 2>/dev/null
  grep '^RUN ' "$w/s$i.out" | awk '{print $2}' >> "$w/union"
  n=$(grep -c '^RUN ' "$w/s$i.out"); sumran=$((sumran+n)); [ "$n" -gt 0 ] || empty=1
  grep -q "^check-action-pins: shard $i/4 units=$total ran=$n\$" "$w/s$i.out" || no "shard $i summary: $(grep '^check-action-pins: shard' "$w/s$i.out")"
done
[ "$sumran" -eq "$total" ] && ok "the shards' counts sum to the full list ($sumran = $total)" || no "shard counts sum to $sumran, the list has $total"
[ "$(sort "$w/union")" = "$(cat "$w/all.names")" ] && ok "the union of the shards is exactly the full list, each unit once" || no "the union differs from the full list"
[ "$empty" -eq 0 ] && ok "every shard runs at least one unit" || no "a shard is empty"

# --- the sum check: manifest = the dry listing; each log must show EVERY unit of its shard completing, by name
printf 'UNIT 1 u1\nUNIT 2 u2\nUNIT 3 u3\nUNIT 4 u4\nUNIT 5 u5\nUNIT 6 u6\ncheck-action-pins: shard 0/1 units=6 ran=6\ncheck-action-pins: 2 passed, 0 failed\n' > "$w/man"
# slog <i> <n> <units seen> <ran> <failed> <names completed...>: a shard log as the real run prints it
slog() {
  local i=$1 n=$2 units=$3 ran=$4 failed=$5; shift 5
  local nm; for nm in "$@"; do echo "PASS $nm → ok"; done
  echo "PASS pm-case-count → 6"; echo "PASS pm-case-names → abc"
  echo "check-action-pins: shard $i/$n units=$units ran=$ran"
  echo "check-action-pins: $(( $# + 2 )) passed, $failed failed"
}
run() { python3 "$sumchk" "$@" > "$w/chk.out" 2>&1; }
slog 0 2 6 3 0 u2 u4 u6 > "$w/a0"; slog 1 2 6 3 0 u1 u3 u5 > "$w/a1"
run "$w/man" "$w/a0" "$w/a1" && ok "two complete shards, every unit named once in its own shard, pass" || no "good shards refused: $(cat "$w/chk.out")"
slog 1 2 6 2 0 u1 u3 > "$w/b1"
run "$w/man" "$w/a0" "$w/b1" && no "a short sum (5 of 6) passed" || ok "a short sum is refused"
slog 1 2 6 4 0 u1 u3 u5 u5 > "$w/c1"
run "$w/man" "$w/a0" "$w/c1" && no "a unit run twice passed" || ok "a unit completed twice (7 of 6) is refused"
slog 1 2 6 3 0 u1 u3 u3 > "$w/c2"
run "$w/man" "$w/a0" "$w/c2" && no "equal totals with a duplicate and an omission passed" || ok "equal totals with one unit twice and another never are refused"
slog 1 2 8 3 0 u1 u3 u5 > "$w/d1"
run "$w/man" "$w/a0" "$w/d1" && no "a shard that saw a different list passed" || ok "a shard that saw a different total is refused"
run "$w/man" "$w/a0" && no "a missing shard passed" || ok "a missing shard is refused"
run "$w/man" "$w/a0" "$w/a0" && no "a repeated shard passed" || ok "a repeated shard is refused"
{ cat "$w/a1"; } | sed 's/^check-action-pins: 5 passed, 0 failed$/check-action-pins: 5 passed, 1 failed/' > "$w/e1"
run "$w/man" "$w/a0" "$w/e1" && no "a failing shard passed" || ok "a shard whose summary says a case failed is refused"
{ cat "$w/a1"; echo "FAIL u9 → bad (want ok)"; } > "$w/e2"
run "$w/man" "$w/a0" "$w/e2" && no "a FAIL line behind a zero-failure summary passed" || ok "a FAIL line is refused even when the summary says 0 failed"
printf 'PASS u1 → ok\n' > "$w/f1"
run "$w/man" "$w/a0" "$w/f1" && no "a log without a summary passed" || ok "a log without a summary line is refused"
run "$w/man" "$w/a0" "$w/nonexistent" && no "an unreadable log passed" || ok "an unreadable log is refused"
slog 1 3 6 3 0 u1 u3 u5 > "$w/g1"
run "$w/man" "$w/a0" "$w/g1" && no "shards of different n passed" || ok "shards that disagree on how many shards there are are refused"
printf 'check-action-pins: shard 0/1 units=0 ran=0\n' > "$w/man0"
run "$w/man0" "$w/a0" "$w/a1" && no "an empty manifest passed" || ok "a manifest with no unit is refused"
# a dry run is not an execution: the planned selection (UNIT/RUN lines and a ran= count) with no unit completing
{ echo "UNIT 1 u1"; echo "RUN u1"; echo "PASS pm-case-count → 6"; echo "PASS pm-case-names → abc"; echo "check-action-pins: shard 1/2 units=6 ran=3"; echo "check-action-pins: 2 passed, 0 failed"; } > "$w/h1"
run "$w/man" "$w/a0" "$w/h1" && no "a dry log passed" || ok "a dry log (planned units, none completed) is refused"
slog 0 2 6 3 0 u2 u4 u6 > "$w/i0"; slog 1 2 6 3 0 u1 u3 u4 > "$w/i1"
run "$w/man" "$w/i0" "$w/i1" && no "a unit run in the wrong shard passed" || ok "a unit that ran in a shard other than its own is refused"
slog 1 2 6 3 0 u1 u3 u7 > "$w/j1"
run "$w/man" "$w/a0" "$w/j1" && no "an unknown unit name passed" || ok "a completed unit that is not in the manifest is refused"
slog 1 2 6 2 0 u1 u3 u5 > "$w/k1"
run "$w/man" "$w/a0" "$w/k1" && no "ran= that disagrees with the units completed passed" || ok "a ran= count that disagrees with the units that completed is refused"

# the closing pass count must equal the completed units plus the two bookkeeping checks; the bookkeeping records are exactly one each
slog 1 2 6 3 0 u1 u3 u5 | sed 's/^check-action-pins: 5 passed, 0 failed$/check-action-pins: 0 passed, 0 failed/' > "$w/l1"
run "$w/man" "$w/a0" "$w/l1" && no "a closing pass count that contradicts the units passed" || ok "a closing pass count that does not equal units + bookkeeping is refused"
{ cat "$w/a1"; echo "PASS pm-case-count → duplicate"; } > "$w/l2"
run "$w/man" "$w/a0" "$w/l2" && no "a repeated bookkeeping record passed" || ok "a repeated bookkeeping record is refused"
grep -v '^PASS pm-case-names' "$w/a1" | sed 's/^check-action-pins: 5 passed, 0 failed$/check-action-pins: 4 passed, 0 failed/' > "$w/l3"
run "$w/man" "$w/a0" "$w/l3" && no "a missing bookkeeping record passed" || ok "a missing bookkeeping record is refused"
# the manifest is a dry listing in which only the bookkeeping ran: a helper that forgot take() shows up as extra passes in it
sed 's/^check-action-pins: 2 passed, 0 failed$/check-action-pins: 3 passed, 0 failed/' "$w/man" > "$w/man3"
run "$w/man3" "$w/a0" "$w/a1" && no "a manifest listing that ran extra work passed" || ok "a manifest listing in which something besides the bookkeeping ran is refused"
grep -q "^check-action-pins: 2 passed, 0 failed\$" "$w/all.out" && ok "the real dry listing ran only the two bookkeeping checks" || no "the real dry listing's closing line: $(tail -1 "$w/all.out")"

# --- a selector that picks no unit is not a successful run
PINS_SHARD=0/5000 bash "$pins" > "$w/zero.out" 2>&1; zrc=$?
[ "$zrc" -ne 0 ] && ok "a real (non-dry) shard that runs no unit exits non-zero" || no "an empty shard exited 0"

# --- an UNSHARDED real run of check-action-pins-test.sh fans out into parallel shards (CI speed, advisor 0643): it runs the
# same shards, in parallel, and proves their sum with coverage-shard-sum.py, so the CI step is unchanged (`bash check-action-pins-test.sh`)
# and every case still runs exactly once. The fan-out runs PINS_SELF (default: itself); here a stub stands in for the 1000-case
# script so each refusal can be provoked in a second. The stub speaks the real protocol (UNIT/RUN dry lines; PASS lines; the two
# bookkeeping records; the shard and closing lines) over six units u1..u6.
cat > "$w/stub.sh" <<'STUB'
#!/usr/bin/env bash
# env: FAKE_FAIL=<unit> prints FAIL for it; FAKE_DROP=<unit> silently completes nothing for it; FAKE_DUP=<unit> completes it twice;
#      FAKE_CRASH=1 exits 1 before any summary; FAKE_CALLS=<file> gets one line per invocation
echo "${PINS_SHARD:-none}${PINS_DRY:+ dry}" >> "${FAKE_CALLS:-/dev/null}"
i=0 n=1
[ -z "${PINS_SHARD:-}" ] || { i=${PINS_SHARD%/*}; n=${PINS_SHARD#*/}; }
[ -z "${FAKE_CRASH:-}" ] || [ -n "${PINS_DRY:-}" ] || exit 1   # a real shard dies; the dry listing (the manifest) still works
pass=0 failn=0 ran=0
for k in 1 2 3 4 5 6; do
  u=u$k
  [ -z "${PINS_DRY:-}" ] || echo "UNIT $k $u"
  if [ $((k % n)) -eq "$i" ]; then
    ran=$((ran+1))
    [ -z "${PINS_DRY:-}" ] || { echo "RUN $u"; continue; }
    [ "${FAKE_DROP:-}" = "$u" ] && { ran=$((ran-1)); continue; }
    if [ "${FAKE_FAIL:-}" = "$u" ]; then echo "FAIL $u → bad (want ok)"; failn=$((failn+1)); else echo "PASS $u → ok"; pass=$((pass+1)); fi
    [ "${FAKE_DUP:-}" = "$u" ] && { echo "PASS $u → ok"; pass=$((pass+1)); }
  fi
done
echo "PASS pm-case-count → 6"; echo "PASS pm-case-names → abc"; pass=$((pass+2))
echo "check-action-pins: shard $i/$n units=6 ran=$ran"
echo "check-action-pins: $pass passed, $failn failed"
[ -z "${FAKE_LATE_EXIT:-}" ] || [ -n "${PINS_DRY:-}" ] || exit 3   # complete, successful output, then a non-zero exit
[ "$failn" -eq 0 ]
STUB
fan() { env PINS_SELF="$w/stub.sh" PINS_JOBS=2 FAKE_CALLS="$w/calls" "$@" bash "$pins" > "$w/fan.out" 2>&1; }
: > "$w/calls"; fan; frc=$?
[ "$frc" -eq 0 ] && ok "fan-out: every shard passes, the sum holds -> exit 0" || no "fan-out refused a good run: $(tail -3 "$w/fan.out")"
[ "$(grep -c '^PASS u[0-9] ' "$w/fan.out")" = 6 ] && ok "fan-out: all six units' PASS lines are printed" || no "fan-out printed $(grep -c '^PASS u' "$w/fan.out") unit lines"
grep -q "^check-action-pins: 10 passed, 0 failed\$" "$w/fan.out" && ok "fan-out: one closing line with the total (6 units + 2 bookkeeping per shard = 10)" || no "fan-out closing line: $(tail -1 "$w/fan.out")"
[ "$(sort "$w/calls" | tr '\n' ,)" = "0/2,1/2,dry," ] || [ "$(sort "$w/calls" | tr '\n' ,)" = "0/2,1/2,none dry," ] && ok "fan-out: one dry listing and exactly shards 0/2 and 1/2 were launched" || no "fan-out launched: $(sort "$w/calls" | tr '\n' ,)"
fan FAKE_FAIL=u3; [ $? -ne 0 ] && ok "fan-out: a failing case in one shard fails the step" || no "a failing case passed"
grep -q '^FAIL u3' "$w/fan.out" && ok "fan-out: the FAIL line is shown" || no "the FAIL line was not printed"
fan FAKE_DROP=u4; [ $? -ne 0 ] && ok "fan-out: a case silently not run fails the step (the sum)" || no "a dropped case passed"
fan FAKE_DUP=u5; [ $? -ne 0 ] && ok "fan-out: a case completed twice fails the step (the sum)" || no "a duplicated case passed"
: > "$w/calls"; fan FAKE_CRASH=1; crc=$?
[ "$crc" -ne 0 ] && ok "fan-out: shards that die before any summary fail the step" || no "crashed shards passed"
[ "$(grep -c '^[01]/2$' "$w/calls")" = 2 ] && ok "fan-out: the crash test really launched both shards (the manifest listing survived)" || no "the crash test did not launch the shards: $(sort "$w/calls" | tr '\n' ,)"
fan FAKE_LATE_EXIT=1; [ $? -ne 0 ] && ok "fan-out: a shard with complete, passing output that exits non-zero fails the step (child status is checked)" || no "a late non-zero shard exit passed"
: > "$w/calls"; PINS_SERIAL=1 PINS_SELF="$w/stub.sh" FAKE_CALLS="$w/calls" timeout 4 bash "$pins" > "$w/ser.out" 2>&1; src=$?   # the real cases run for minutes: four seconds show it did not fan out
[ "$(wc -l < "$w/calls" | tr -d ' ')" = 0 ] && ok "PINS_SERIAL=1 runs the real script in this process (no fan-out)" || no "PINS_SERIAL=1 still fanned out: $(cat "$w/calls")"
: > "$w/calls"; PINS_SHARD=0/4 PINS_DRY=1 PINS_SELF="$w/stub.sh" FAKE_CALLS="$w/calls" bash "$pins" > /dev/null 2>&1
[ "$(wc -l < "$w/calls" | tr -d ' ')" = 0 ] && ok "an explicit PINS_SHARD (coverage gate, this test) never fans out" || no "a sharded run fanned out"
: > "$w/calls"; PINS_DRY=1 PINS_SELF="$w/stub.sh" FAKE_CALLS="$w/calls" bash "$pins" > /dev/null 2>&1
[ "$(wc -l < "$w/calls" | tr -d ' ')" = 0 ] && ok "a dry listing never fans out" || no "a dry listing fanned out"
# a nonsense job count is refused, not run as one shard
PINS_JOBS=0 PINS_SELF="$w/stub.sh" bash "$pins" > "$w/j0.out" 2>&1 && no "PINS_JOBS=0 passed" || ok "PINS_JOBS=0 is refused"


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
