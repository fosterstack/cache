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

echo "coverage-shard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
