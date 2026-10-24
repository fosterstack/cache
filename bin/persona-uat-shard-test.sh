#!/usr/bin/env bash
# proves: REQ-CI-006-AC1, REQ-CI-006-AC2, REQ-CI-006-AC3 — a suite that runs itself as parallel shards proves, before it prints its one summary line, that the shards together ran every case
# of the committed manifest exactly once, none failed, and the line counts the SUM (bin/persona-uat-shard.sh, bin/persona-uat-shard-sum.py)
# Tests for the shard library and its sum proof. Self-contained (bash, python3). The library is exercised on a small suite built here (three sections, a tail section) so that
# the proof is tested without the 40-minute persona suite. It prints "persona-uat-shard: N passed, M failed" and fails if N+M is not the number of cases it declares.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
lib="$root/bin/persona-uat-shard.sh"
sumtool="$root/bin/persona-uat-shard-sum.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -s "$lib" ] && [ -s "$sumtool" ] || { echo "FAIL the shard library or its sum tool is missing"; echo "persona-uat-shard: 0 passed, 1 failed"; exit 1; }

# ---- the sum tool, on hand-made logs ---------------------------------------------------------------------------------------------------------
# manifest: SECTION<TAB>CASE per line. Three shards (0, 1, 2) and a tail. Section a -> shard 0, b -> shard 1, c -> shard 2, t (tail).
mf="$work/manifest.txt"
printf 'a\tcase a1\na\tcase a2\nb\tcase b1\nc\tcase c1\nc\tcase c2\nc\tcase c3\nt\tcase t1\n' > "$mf"
mklog() { # <file> <shard label (0/3, tail)> <sections csv> <ok case>...
  local f=$1 lab=$2 secs=$3; shift 3
  { for c in "$@"; do echo "ok   $c"; done; echo "persona-uat: shard $lab sections=$secs"; echo "persona-uat: $# passed, 0 failed"; } > "$f"
}
good() { # writes the five logs of a complete, correct run into $work/g
  rm -rf "$work/g"; mkdir -p "$work/g"
  mklog "$work/g/0.log" 0/3 a "case a1" "case a2"
  mklog "$work/g/1.log" 1/3 b "case b1"
  mklog "$work/g/2.log" 2/3 c "case c1" "case c2" "case c3"
  mklog "$work/g/tail.log" tail t "case t1"
}
sumrun() { python3 -I "$sumtool" "$mf" "$@" 2>&1; }
want() { # <label> <rc> <word> -- logs...
  local label=$1 rc_want=$2 word=$3; shift 4; local out rc=0
  out=$(sumrun "$@") || rc=$?
  if [ "$rc" = "$rc_want" ] && { [ -z "$word" ] || grep -Fqi -- "$word" <<< "$out"; }; then ok "$label"; else bad "$label -> rc=$rc (want $rc_want), wanted '$word': ${out:0:200}"; fi
}
good
want "REQ-CI-006-AC1 sum: a complete run (three shards and the tail) is accepted" 0 "persona-uat: 7 passed, 0 failed" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
out=$(sumrun "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"); n=$(grep -c "passed, " <<< "$out")
if [ "$n" = 1 ]; then ok "REQ-CI-006-AC3 sum: exactly ONE summary line is printed, and it counts the sum of all shards (7), not one shard's cases"; else bad "summary lines: $n: $out"; fi
good; sed -i.bak '/case a2/d' "$work/g/0.log"; sed -i.bak 's/^persona-uat: 2 passed/persona-uat: 1 passed/' "$work/g/0.log"
want "REQ-CI-006-AC1 sum: a case of the manifest that no shard ran (a skipped case) is refused and named" 1 "case a2" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; mklog "$work/g/1.log" 1/3 b "case b1" "case invented"
want "REQ-CI-006-AC1 sum: a case that is not in the manifest is refused and named" 1 "case invented" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; mklog "$work/g/1.log" 1/3 b "case b1" "case b1"
want "REQ-CI-006-AC1 sum: a case run twice is refused" 1 "case b1" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; mklog "$work/g/1.log" 1/3 b "case b1" "case a1"
want "REQ-CI-006-AC1 sum: a case run by a shard that does not own its section (and so also run twice) is refused" 1 "case a1" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; echo "FAIL case b1" >> "$work/g/1.log"
want "REQ-CI-006-AC2 sum: a FAIL line in any shard is refused" 1 "FAIL" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; sed -i.bak '/^persona-uat: 1 passed/d' "$work/g/1.log"
want "REQ-CI-006-AC2 sum: a shard that printed no closing summary (it died, or was cut off) is refused" 1 "summary" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; sed -i.bak 's/^persona-uat: 1 passed, 0 failed/persona-uat: 5 passed, 0 failed/' "$work/g/1.log"
want "REQ-CI-006-AC2 sum: a closing count that contradicts the shard's own ok lines is refused" 1 "count" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good
want "REQ-CI-006-AC1 sum: a shard that is missing (two logs of three, no tail) is refused" 1 "shard" -- "$work/g/0.log" "$work/g/2.log" "$work/g/tail.log"
want "REQ-CI-006-AC1 sum: the same shard twice is refused" 1 "shard" -- "$work/g/0.log" "$work/g/0.log" "$work/g/2.log" "$work/g/tail.log"
want "REQ-CI-006-AC1 sum: no tail log while the manifest has a tail section is refused" 1 "tail" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log"
good; mklog "$work/g/2.log" 2/3 c "case c1" "case c2" "case c3" ; sed -i.bak 's/sections=c/sections=c,b/' "$work/g/2.log"
want "REQ-CI-006-AC1 sum: a section run by two shards (declared twice) is refused" 1 "section" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; sed -i.bak 's/sections=b/sections=/' "$work/g/1.log"
want "REQ-CI-006-AC1 sum: a section that no shard declared is refused even when its case is missing from the logs" 1 "section" -- "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log"
good; printf '' > "$work/empty.txt"
out=$(python3 -I "$sumtool" "$work/empty.txt" "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log" 2>&1) && rc=0 || rc=$?
if [ "$rc" = 1 ] && grep -qi "manifest" <<< "$out"; then ok "REQ-CI-006-AC1 sum: an empty manifest is refused (a proof against nothing proves nothing)"; else bad "empty manifest: rc=$rc ${out:0:160}"; fi
good; printf 'a\tcase a1\na\tcase a1\nb\tcase b1\nc\tcase c1\nc\tcase c2\nc\tcase c3\nt\tcase t1\n' > "$work/mf2.txt"
mklog "$work/g/0.log" 0/3 a "case a1" "case a1"
out=$(python3 -I "$sumtool" "$work/mf2.txt" "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log" 2>&1) && rc=0 || rc=$?
if [ "$rc" = 0 ] && grep -q "persona-uat: 7 passed, 0 failed" <<< "$out"; then ok "REQ-CI-006-AC1 sum: a case name that occurs twice in the manifest must occur twice in the logs (multiplicity), and then it is accepted"; else bad "multiplicity: rc=$rc ${out:0:160}"; fi
good; printf 'a\tcase a1\na\tcase a1\nb\tcase b1\nc\tcase c1\nc\tcase c2\nc\tcase c3\nt\tcase t1\n' > "$work/mf2.txt"
out=$(python3 -I "$sumtool" "$work/mf2.txt" "$work/g/0.log" "$work/g/1.log" "$work/g/2.log" "$work/g/tail.log" 2>&1) && rc=0 || rc=$?
if [ "$rc" = 1 ]; then ok "REQ-CI-006-AC1 sum: a doubled manifest entry that ran once is refused"; else bad "multiplicity short: rc=$rc ${out:0:160}"; fi

# ---- the library, on a small suite ----------------------------------------------------------------------------------------------------------
# mini.sh: fixtures (always), sections a, b, c (sharded) and a tail section t that reads every shard's case directory. Cases print ok lines like the real suite.
cat > "$work/mini.sh" <<'MINI'
#!/usr/bin/env bash
here=$(cd "$(dirname "$0")" && pwd)
. "$MINI_LIB"
shard_dispatch "$0" "$@"
work=${PERSONA_WORK:-$(mktemp -d)}; mkdir -p "$work"
pass=0 failn=0
ok()  { [ -n "${SHARD_QUIET:-}" ] || { pass=$((pass + 1)); echo "ok   $1"; }; }
bad() { [ -n "${SHARD_QUIET:-}" ] || { failn=$((failn + 1)); echo "FAIL $1"; }; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }
echo fixture > "$work/fixture.txt"
sec_a() { mkdir -p "$work/ca"; echo "port-offset=$PERSONA_PORT_OFFSET" > "$work/ca/info"; CASE="case a1"; check test -s "$work/ca/info"; CASE="case a2"; check test -s "$work/fixture.txt"; }
sec_b() { mkdir -p "$work/cb"; echo b > "$work/cb/info"; CASE="case b1"; check test -s "$work/cb/info"; [ -z "${MINI_FAIL_B:-}" ] || { CASE="case b2"; check false; }; [ -z "${MINI_DIE_B:-}" ] || exit 7; }
sec_c() { mkdir -p "$work/cc"; echo c > "$work/cc/info"; for i in 1 2 3; do CASE="case c$i"; check test -s "$work/cc/info"; done; [ -z "${MINI_EXTRA_C:-}" ] || { CASE="case c-new"; check true; }; }
sec_t() { CASE="case t1"; check sh -c "test -s '$work/ca/info' -a -s '$work/cb/info' -a -s '$work/cc/info'"; }
shard_section a sec_a
shard_section b sec_b
shard_section c sec_c
shard_tail_section t sec_t
shard_finish
MINI
cat > "$work/mini-manifest.txt" <<'MF'
a	case a1
a	case a2
b	case b1
c	case c1
c	case c2
c	case c3
t	case t1
MF
# weights (seconds per section): a 5, b 3, c 3 -> with two shards: shard 0 = a, shard 1 = b and c
printf 'a 5\nb 3\nc 3\nt tail\n' > "$work/mini-weights.txt"
mini() { # <shards> [VAR=value...] ; prints the output, sets mrc
  local n=$1; shift
  mrc=0
  mout=$(env MINI_LIB="$lib" PERSONA_SHARD_MANIFEST="$work/mini-manifest.txt" PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" PERSONA_SHARDS=$n PERSONA_FAKE_CORES=${FAKE_CORES:-8} "$@" bash "$work/mini.sh" 2>&1) || mrc=$?
}
mini 1
if [ "$mrc" = 0 ] && grep -q "persona-uat: 7 passed, 0 failed" <<< "$mout"; then ok "REQ-CI-006-AC1 library: one shard (PERSONA_SHARDS=1) runs every section and prints the 7 cases"; else bad "single: rc=$mrc ${mout:0:300}"; fi
names1=$(grep '^ok   ' <<< "$mout" | sort)
mini 2
if [ "$mrc" = 0 ] && grep -q "persona-uat: 7 passed, 0 failed" <<< "$mout"; then ok "REQ-CI-006-AC3 library: two shards print one summary line that counts the sum (7)"; else bad "two shards: rc=$mrc ${mout:0:400}"; fi
if [ "$(grep -c 'passed, ' <<< "$mout")" = 1 ]; then ok "REQ-CI-006-AC3 library: the parent prints exactly one 'passed, failed' line (the children's lines are not repeated)"; else bad "summary lines: $mout"; fi
names2=$(grep '^ok   ' <<< "$mout" | sort)
if [ "$names1" = "$names2" ] && [ -n "$names1" ]; then ok "REQ-CI-006-AC1 library: the sharded run reports the same cases as the single-process run (equivalence)"; else bad "equivalence: single=[$names1] sharded=[$names2]"; fi
mini 3
if [ "$mrc" = 0 ] && grep -q "persona-uat: 7 passed, 0 failed" <<< "$mout"; then ok "REQ-CI-006-AC1 library: three shards (a section per shard) also add up to 7"; else bad "three shards: rc=$mrc ${mout:0:400}"; fi
mini 2 MINI_FAIL_B=1
if [ "$mrc" = 1 ] && grep -q "FAIL case b2" <<< "$mout"; then ok "REQ-CI-006-AC2 library: a failing case in one shard fails the suite and is named"; else bad "failing case: rc=$mrc ${mout:0:400}"; fi
mini 2 MINI_DIE_B=1
if [ "$mrc" = 1 ] && grep -qi "shard" <<< "$mout"; then ok "REQ-CI-006-AC2 library: a shard that dies before its summary fails the suite"; else bad "dead shard: rc=$mrc ${mout:0:400}"; fi
mini 2 MINI_EXTRA_C=1
if [ "$mrc" = 1 ] && grep -q "case c-new" <<< "$mout"; then ok "REQ-CI-006-AC1 library: a case added without a manifest entry fails the suite and is named (the manifest is committed, not guessed)"; else bad "unlisted case: rc=$mrc ${mout:0:400}"; fi
mini 2 PERSONA_WRITE_MANIFEST="$work/regen.txt" MINI_EXTRA_C=1
if [ "$mrc" = 0 ] && grep -q "case c-new" "$work/regen.txt" 2>/dev/null && [ "$(wc -l < "$work/regen.txt" | tr -d " ")" = 8 ]; then ok "REQ-CI-006-AC1 library: PERSONA_WRITE_MANIFEST=FILE writes the manifest from a green sharded run (8 cases here), for a human to commit"; else bad "regen: rc=$mrc $(cat "$work/regen.txt" 2>/dev/null | head -3) ${mout:0:200}"; fi
cp "$work/mini-manifest.txt" "$work/mini-manifest.keep"; printf 'a\tcase a1\na\tcase a2\nb\tcase b1\nc\tcase c1\nc\tcase c2\nc\tcase c3\nc\tcase c4\nt\tcase t1\n' > "$work/mini-manifest.txt"
mini 2
if [ "$mrc" = 1 ] && grep -q "case c4" <<< "$mout"; then ok "REQ-CI-006-AC1 library: a manifest entry that no shard ran (a removed or skipped case) fails the suite and is named"; else bad "stale manifest: rc=$mrc ${mout:0:400}"; fi
cp "$work/mini-manifest.keep" "$work/mini-manifest.txt"
FAKE_CORES=2 mini 8
if [ "$mrc" = 0 ] && grep -q "shards=2" <<< "$mout"; then ok "REQ-CI-006-AC1 library: the number of shards never exceeds the cores (8 asked, 2 cores: 2 shards)"; else bad "core cap: rc=$mrc ${mout:0:300}"; fi
FAKE_CORES=1 mini 4
if [ "$mrc" = 0 ] && grep -q "persona-uat: 7 passed, 0 failed" <<< "$mout" && ! grep -q "shards=" <<< "$mout"; then ok "REQ-CI-006-AC1 library: on one core the suite runs as one process (no shard overhead)"; else bad "one core: rc=$mrc ${mout:0:300}"; fi
off=$(env MINI_LIB="$lib" PERSONA_SHARD_MANIFEST="$work/mini-manifest.txt" PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" PERSONA_SHARD=1/2 bash -c ". '$lib'; shard_dispatch x; echo \$PERSONA_PORT_OFFSET \$SHARD_MODE" 2>&1)
off0=$(env MINI_LIB="$lib" PERSONA_SHARD_MANIFEST="$work/mini-manifest.txt" PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" PERSONA_SHARD=0/2 bash -c ". '$lib'; shard_dispatch x; echo \$PERSONA_PORT_OFFSET \$SHARD_MODE" 2>&1)
offt=$(env MINI_LIB="$lib" PERSONA_SHARD_MANIFEST="$work/mini-manifest.txt" PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" PERSONA_SHARD=tail/2 bash -c ". '$lib'; shard_dispatch x; echo \$PERSONA_PORT_OFFSET \$SHARD_MODE" 2>&1)
if [ "$off0" = "0 shard" ] && [ "$off" = "100 shard" ] && [ "$offt" = "0 tail" ]; then ok "REQ-CI-006-AC1 library: each shard has its own port offset (100 x its index: 0, 100) and the tail the base ports"; else bad "port offsets: [$off0] [$off] [$offt]"; fi
# the equivalence of the partition: assignment is deterministic and weighted (greedy by weight): two shards over weights 5,3,3 -> {a} and {b,c}
asg=$(env PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" bash -c ". '$lib'; shard_assign 2 a b c" 2>&1)
if [ "$asg" = "0 a
1 b
1 c" ]; then ok "REQ-CI-006-AC1 library: the section-to-shard assignment is deterministic and balanced by the committed weights (a | b c)"; else bad "assign: $asg"; fi
asg3=$(env PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" bash -c ". '$lib'; shard_assign 3 a b c" 2>&1)
if [ "$(echo "$asg3" | awk '{print $1}' | sort -u | wc -l | tr -d ' ')" = 3 ]; then ok "REQ-CI-006-AC1 library: with as many shards as sections each shard gets exactly one section"; else bad "assign3: $asg3"; fi
asgn=$(env PERSONA_SHARD_WEIGHTS="$work/mini-weights.txt" bash -c ". '$lib'; shard_assign 2 a b c zz" 2>&1)
if grep -q "zz" <<< "$asgn" && [ "$(echo "$asgn" | grep -c .)" = 4 ]; then ok "REQ-CI-006-AC1 library: a section with no weight still gets a shard (it counts as the median weight)"; else bad "unweighted: $asgn"; fi

# ---- shared sections (run in every shard, counted once in their owner) and joined sections (forced into one shard) ---------------------------------
# mini2: section sh is SHARED (its output dir csh is needed by the section u that follows it); u is JOINED with a (they are one unit for the assignment).
sed -e 's|^shard_section a sec_a$|shard_section sh sec_sh\nshard_section a sec_a\nshard_section u sec_u|' \
    -e 's|^sec_t() {|sec_sh() { mkdir -p "$work/csh"; echo shared > "$work/csh/info"; CASE="case sh1"; check test -s "$work/csh/info"; }\nsec_u() { CASE="case u1"; check test -s "$work/csh/info"; }\nsec_t() {|' "$work/mini.sh" > "$work/mini2.sh"
printf 'sh\tcase sh1\na\tcase a1\na\tcase a2\nu\tcase u1\nb\tcase b1\nc\tcase c1\nc\tcase c2\nc\tcase c3\nt\tcase t1\n' > "$work/mini2-manifest.txt"
printf 'sh 2 shared\na 5\nu 1\nb 3\nc 3\nt tail\n@join a u\n' > "$work/mini2-weights.txt"
mini2() { local n=$1; shift; mrc=0
  mout=$(env MINI_LIB="$lib" PERSONA_SHARD_MANIFEST="$work/mini2-manifest.txt" PERSONA_SHARD_WEIGHTS="$work/mini2-weights.txt" PERSONA_SHARDS=$n PERSONA_FAKE_CORES=8 "$@" bash "$work/mini2.sh" 2>&1) || mrc=$?; }
mini2 2
if [ "$mrc" = 0 ] && grep -q "persona-uat: 9 passed, 0 failed" <<< "$mout" && [ "$(grep -c '^ok   case sh1' <<< "$mout")" = 1 ]; then ok "REQ-CI-006-AC1 library: a shared section runs in every shard but its cases are counted once (in its owner), and the section after it finds its output in every shard"; else bad "shared: rc=$mrc ${mout:0:500}"; fi
mini2 3
if [ "$mrc" = 0 ] && grep -q "persona-uat: 9 passed, 0 failed" <<< "$mout"; then ok "REQ-CI-006-AC1 library: a shared section and a joined pair also add up with three shards"; else bad "shared 3: rc=$mrc ${mout:0:500}"; fi
asgj=$(env PERSONA_SHARD_WEIGHTS="$work/mini2-weights.txt" bash -c ". '$lib'; shard_assign 3 sh a u b c" 2>&1)
sa=$(awk '$2 == "a" { print $1 }' <<< "$asgj"); su=$(awk '$2 == "u" { print $1 }' <<< "$asgj")
if [ -n "$sa" ] && [ "$sa" = "$su" ]; then ok "REQ-CI-006-AC1 library: sections joined with @join always land in the same shard"; else bad "join: $asgj"; fi
asgs=$(env PERSONA_SHARD_WEIGHTS="$work/mini2-weights.txt" bash -c ". '$lib'; shard_assign 3 sh a u b c" 2>&1)
if grep -q " sh$" <<< "$asgs"; then ok "REQ-CI-006-AC1 library: a shared section has an owner like any other (the shard that counts it)"; else bad "shared owner: $asgs"; fi
# the quiet runs: the shard that does not own a shared section must not print its cases (otherwise the sum proof would see them twice) -- covered by the count above

EXPECT=37
echo "persona-uat-shard: $pass passed, $failn failed"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT"; exit 1; fi
[ "$failn" = 0 ]
