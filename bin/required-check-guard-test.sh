#!/usr/bin/env bash
# proves: REQ-DEP-002-AC1, REQ-DEP-002-AC2, REQ-DEP-002-AC3
# Offline suite for bin/required-check-guard.sh (register row 75). A ruleset with every
# listed check passes, extra checks on main too (every listed check must be enforced).
# A missing check or wrong integration ID is drift (exit 1). An unreadable side, a
# ruleset with no required checks, or a list with no checks is exit 2, never a pass.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
sut="$here/required-check-guard.sh"
list="$repo/.github/policy/required-checks.json"
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
pass=0; fail=0

check() { # name want_rc regex rules_file list_file
  local out rc
  out="$(GUARD_RULES_JSON="$4" bash "$sut" "$5" 2>&1)"; rc=$?
  if [ "$rc" -ne "$2" ] || ! grep -qE "$3" <<<"$out"; then
    echo "FAIL: $1 (rc ${rc}, want $2; /$3/)"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return
  fi
  echo "ok: $1"; pass=$((pass+1))
}

# A ruleset response built from the committed list (what a matching main returns),
# plus an unrelated rule type that must be ignored.
jq '[{"type":"deletion"},
     {"type":"required_status_checks","parameters":{"required_status_checks":
       [.required_checks[] | {context, integration_id}]}}]' "$list" > "$w/match.json"
jq '(.[1].parameters.required_status_checks) |= map(select(.context != "scan"))' "$w/match.json" > "$w/missing.json"
jq '(.[1].parameters.required_status_checks) += [{"context":"surprise","integration_id":15368}]' "$w/match.json" > "$w/extra.json"
jq '(.[1].parameters.required_status_checks) |= map(if .context=="auditor-review-gate" then .integration_id=0 else . end)' "$w/match.json" > "$w/wrongid.json"
echo '[{"type":"deletion"}]' > "$w/none.json"
echo 'not json' > "$w/garbage.json"
jq '.required_checks |= map(if .context=="auditor-review-gate" then .integration_id=0 else . end)' "$list" > "$w/stale-list.json"
echo '{"comment":["no array"]}' > "$w/nolist.json"
echo '{"required_checks": []}' > "$w/emptylist.json"

check "ruleset == list passes"                    0 "match \([0-9]+ listed checks"            "$w/match.json"   "$list"
check "check removed from the ruleset is drift"   1 '^\{"context":"scan"'                     "$w/missing.json" "$list"
check "extra ruleset check still passes (a superset)" 0 "match \([0-9]+ listed checks"        "$w/extra.json"   "$list"
check "wrong integration ID is drift"             1 '^\{"context":"auditor-review-gate","integration_id":5054756' "$w/wrongid.json" "$list"
check "stale list (the #133 case) is drift"       1 '^\{"context":"auditor-review-gate","integration_id":0' "$w/match.json" "$w/stale-list.json"
check "no required checks on main = exit 2"       2 "NO required status checks"                "$w/none.json"    "$list"
check "unreadable ruleset response = exit 2"      2 "not the expected JSON"                    "$w/garbage.json" "$list"
check "missing ruleset file = exit 2"             2 "cannot read"                              "$w/absent.json"  "$list"
check "list without required_checks = exit 2"     2 "no required_checks array"                 "$w/match.json"   "$w/nolist.json"
check "list naming no check = exit 2"             2 "could not compare"                        "$w/match.json"   "$w/emptylist.json"

echo "----"
echo "required-check-guard: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
