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

# --- a selector that picks no unit is not a successful run
PINS_SHARD=0/5000 bash "$pins" > "$w/zero.out" 2>&1; zrc=$?
[ "$zrc" -ne 0 ] && ok "a real (non-dry) shard that runs no unit exits non-zero" || no "an empty shard exited 0"

echo "coverage-shard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
