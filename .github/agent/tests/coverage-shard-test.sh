#!/usr/bin/env bash
# proves: REQ-AUD-018-AC2
# The coverage gate (coverage-gate.sh) runs the action-pin cases as parallel shards (advisor 0618). This proves the sharding cannot
# lose or double a case: the dry listing of check-action-pins-test.sh is the full list; four shards partition it exactly (no unit
# twice, none missing, every shard non-empty); and coverage-shard-sum.py, which the gate runs on the shards' logs, refuses a short
# sum, a unit counted twice, a shard that saw a different list, a missing or repeated shard, a failing shard and a log with no summary.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
pins="$here/check-action-pins-test.sh"; sumchk="$here/coverage-shard-sum.py"
pass=0; fail=0
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

# --- the sum check
good() { # idx n total ran passed failed
  printf 'PASS x → ok\ncheck-action-pins: shard %s/%s units=%s ran=%s\ncheck-action-pins: %s passed, %s failed\n' "$1" "$2" "$3" "$4" "$5" "$6"
}
mk() { good "$@" > "$w/$LBL"; }
run() { python3 "$sumchk" "$@" > "$w/chk.out" 2>&1; }
LBL=a0; mk 0 2 10 5 5 0; LBL=a1; mk 1 2 10 5 5 0
run 10 "$w/a0" "$w/a1" && ok "two complete shards that sum to the list pass" || no "good shards refused: $(cat "$w/chk.out")"
LBL=b1; mk 1 2 10 4 4 0
run 10 "$w/a0" "$w/b1" && no "a short sum (9 of 10) passed" || ok "a short sum is refused"
LBL=c1; mk 1 2 10 6 6 0
run 10 "$w/a0" "$w/c1" && no "a unit counted twice (11 of 10) passed" || ok "a sum above the list (a unit twice) is refused"
LBL=d1; mk 1 2 12 5 5 0
run 10 "$w/a0" "$w/d1" && no "a shard that saw a different list passed" || ok "a shard that saw a different total is refused"
run 10 "$w/a0" && no "a missing shard passed" || ok "a missing shard is refused"
run 10 "$w/a0" "$w/a0" && no "a repeated shard passed" || ok "a repeated shard is refused"
LBL=e1; mk 1 2 10 5 4 1
run 10 "$w/a0" "$w/e1" && no "a failing shard passed" || ok "a shard with a failed case is refused"
printf 'PASS x → ok\n' > "$w/f1"
run 10 "$w/a0" "$w/f1" && no "a log without a summary passed" || ok "a log without a summary line is refused"
run 10 "$w/a0" "$w/nonexistent" && no "an unreadable log passed" || ok "an unreadable log is refused"
LBL=g1; mk 1 3 10 5 5 0
run 10 "$w/a0" "$w/g1" && no "shards of different n passed" || ok "shards that disagree on how many shards there are are refused"
run 0 "$w/a0" "$w/a1" && no "an expected total of 0 passed" || ok "an expected total of 0 is refused"

echo "coverage-shard: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
