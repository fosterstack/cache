#!/usr/bin/env bash
# proves: REQ-DEP-002-AC1, REQ-DEP-002-AC2, REQ-REL-013-AC2
# Offline suite for bin/required-check-guard.sh (register row 75). Fixtures stand
# in for the ruleset API response; the list side uses the committed file and
# edited copies. What must hold: an exact match passes; a missing check, an extra
# check, or a wrong integration ID is drift (exit 1, with the diff); an unreadable
# side or a ruleset with no required checks is exit 2, never a pass.
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
jq '(.[1].parameters.required_status_checks) |= map(if .context=="lint" then .integration_id=0 else . end)' "$w/match.json" > "$w/wrongid.json"
echo '[{"type":"deletion"}]' > "$w/none.json"
echo 'not json' > "$w/garbage.json"
jq '.required_checks |= map(if .context=="lint" then .integration_id=0 else . end)' "$list" > "$w/stale-list.json"
echo '{"comment":["no array"]}' > "$w/nolist.json"

check "ruleset == list passes"                    0 "match \([0-9]+ checks"                   "$w/match.json"   "$list"
check "check removed from the ruleset is drift"   1 '^\+ .*"context":"scan"'                  "$w/missing.json" "$list"
check "extra ruleset check is drift"              1 '^- .*"context":"surprise"'                "$w/extra.json"   "$list"
check "wrong integration ID is drift"             1 '"lint","integration_id":0' "$w/wrongid.json" "$list"
check "stale list (the #133 case) is drift"       1 '^\+ .*"lint","integration_id":0' "$w/match.json" "$w/stale-list.json"
check "no required checks on main = exit 2"       2 "NO required status checks"                "$w/none.json"    "$list"
check "unreadable ruleset response = exit 2"      2 "not the expected JSON"                    "$w/garbage.json" "$list"
check "missing ruleset file = exit 2"             2 "cannot read"                              "$w/absent.json"  "$list"
check "list without required_checks = exit 2"     2 "no required_checks array"                 "$w/match.json"   "$w/nolist.json"

# REQ-REL-013-AC2: with a second argument the guard also compares release-only-checks.json, entry by entry (context,
# integration_id, scope), with the seven entries pinned in the script
ro="$repo/.github/policy/release-only-checks.json"
check2() { # name want_rc regex release_only_file
  local out rc
  out="$(GUARD_RULES_JSON="$w/match.json" bash "$sut" "$list" "$4" 2>&1)"; rc=$?
  if [ "$rc" -ne "$2" ] || ! grep -qE "$3" <<<"$out"; then
    echo "FAIL: $1 (rc ${rc}, want $2; /$3/)"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); return
  fi
  echo "ok: $1"; pass=$((pass+1))
}
ro_edit() { jq -c "$2" "$ro" > "$w/ro-$1.json"; }
ro_edit id      '(.required_checks[] | select(.context=="auditor-review-gate") | .integration_id) = 15368'
ro_edit scope   '(.required_checks[] | select(.context=="coverage") | .scope) = "pull_request"'
ro_edit dropped '.required_checks |= map(select(.context != "allowlist-chain"))'
ro_edit eighth  '.required_checks += [{"context":"extra-check","integration_id":15368,"scope":"push"}]'
echo 'not json' > "$w/ro-garbage.json"
echo '{"comment":["no array"]}' > "$w/ro-nolist.json"
check2 "pinned release-only list passes"                0 "match"                                   "$ro"
check2 "a changed integration_id is drift"              1 '^[-+] .*"auditor-review-gate".*5054756'  "$w/ro-id.json"
check2 "a changed integration_id prints both entries"   1 '^[-+] .*"auditor-review-gate".*15368'     "$w/ro-id.json"
check2 "a changed scope is drift, whole entry printed"  1 '^[-+] .*"coverage".*"scope":"pull_request"' "$w/ro-scope.json"
check2 "a changed scope prints the pinned entry"        1 '^[-+] .*"coverage".*"scope":"push"'      "$w/ro-scope.json"
check2 "a dropped entry is drift"                       1 '^[-+] .*"allowlist-chain"'               "$w/ro-dropped.json"
check2 "an eighth entry is drift"                       1 '^[-+] .*"extra-check"'                   "$w/ro-eighth.json"
check2 "unreadable release-only file = exit 2"          2 "release-only"                            "$w/ro-absent.json"
check2 "release-only file not JSON = exit 2"            2 "release-only"                            "$w/ro-garbage.json"
check2 "release-only file without the array = exit 2"   2 "release-only"                            "$w/ro-nolist.json"

# REQ-REL-013-AC2: the pin is main's copy of the guard, so a head that edits the file, the judge's constants and the
# guard together is still red; the wiring runs the script fetched from main, not the tree's bin/ copy
mkdir -p "$w/main" "$w/head/.github/policy" "$w/head/bin"
cp "$sut" "$w/main/required-check-guard.sh"
cp "$list" "$w/head/.github/policy/required-checks.json"
sed 's/5054756/15368/' "$ro" > "$w/head/.github/policy/release-only-checks.json"
printf 'JUDGE_PIN=5054756\n' | sed 's/5054756/15368/' > "$w/head/judge-constants.sh"
{ cat "$sut"; echo '# the head moves its own pin'; } | sed 's/5054756/15368/' > "$w/head/bin/required-check-guard.sh"
out="$(cd "$w/head" && GUARD_RULES_JSON="$w/match.json" bash "$w/main/required-check-guard.sh" \
  .github/policy/required-checks.json .github/policy/release-only-checks.json 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && grep -qE '^[-+] .*"auditor-review-gate"' <<<"$out"; then
  echo "ok: main's guard judges a head that edited the file, the judge and the guard together"; pass=$((pass+1))
else echo "FAIL: main's guard over a head that moved its own pin (rc ${rc}, want 1)"; echo "$out" | sed 's/^/    /'; fail=$((fail+1)); fi

python3 - "$repo/.github/workflows/ci.yml" "$w/pin-step.txt" 2>/dev/null <<'PY'
import sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["required-check-guard"]["steps"]
pin = [s for s in steps if "release-only-checks.json" in (s.get("run") or "") and "required-check-guard.sh" in s["run"]]
assert len(pin) == 1, f"{len(pin)} steps of the required-check guard job run the guard over release-only-checks.json"
s = pin[0]
bad = [k for k in ("if", "continue-on-error", "shell", "working-directory") if k in s]
open(sys.argv[2], "w").write(s["run"] + "\n---\n" + ",".join(bad))
PY
if [ -s "$w/pin-step.txt" ]; then
  run="$(sed '/^---$/,$d' "$w/pin-step.txt")"
  if grep -qE '(^|[[:space:];&|])(bash +|sh +)?(\./)?bin/required-check-guard\.sh' <<<"$run"; then
    echo "FAIL: the pin step runs the tree's bin/required-check-guard.sh"; fail=$((fail+1))
  elif ! grep -qE 'ref=main|origin/main|refs/heads/main' <<<"$run"; then
    echo "FAIL: the pin step does not fetch the guard from main"; fail=$((fail+1))
  elif ! grep -qE 'required-checks\.json +\S*release-only-checks\.json' <<<"$run"; then
    echo "FAIL: the pin step does not pass the tree's two policy files to the guard"; fail=$((fail+1))
  elif [ -n "$(sed '1,/^---$/d' "$w/pin-step.txt")" ]; then
    echo "FAIL: the pin step carries $(sed '1,/^---$/d' "$w/pin-step.txt")"; fail=$((fail+1))
  else echo "ok: the pin step runs main's guard over the tree's two policy files"; pass=$((pass+1)); fi
else echo "FAIL: ci.yml's required-check guard job has no single step that runs the guard over release-only-checks.json"; fail=$((fail+1)); fi

# The hygiene step that opens/updates the `required-check drift` issue, run EXACTLY as
# committed under GitHub's default `bash -e` with a recording gh stub (round-1 blocker:
# -e ended the step at the guard's refusal, before any issue call).
python3 - "$repo/.github/workflows/ci.yml" "$w/step.sh" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
steps = wf["jobs"]["required-check-guard"]["steps"]
run = [s["run"] for s in steps if s.get("name", "").startswith("open or update the `required-check drift` issue")]
assert len(run) == 1, "drift-issue step not found"
open(sys.argv[2], "w").write(run[0])
PY
mkdir -p "$w/stub"
cat > "$w/stub/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
case "$1 $2" in
  "api repos/"*) printf '%s' "$(base64 < "$MAIN_LIST" | tr -d '\n')" ;;   # --jq .content
  "issue list")  cat "$ISSUES_JSON" ;;
  "issue edit"|"issue create") echo "https://example.invalid/issues/9" ;;
esac
EOF
chmod +x "$w/stub/gh"
step() { # name rules issues_json want_regex [dont_want_regex]
  : > "$w/gh.log"; : > "$w/out"
  (cd "$repo" && env PATH="$w/stub:$PATH" GH_LOG="$w/gh.log" MAIN_LIST="$list" ISSUES_JSON="$3" \
     GUARD_RULES_JSON="$2" GITHUB_REPOSITORY=o/r RUNNER_TEMP="$w" RUN_URL=https://example.invalid/run GITHUB_OUTPUT="$w/out" \
     bash --noprofile --norc -e -o pipefail "$w/step.sh") >"$w/step.out" 2>&1; local rc=$?
  if [ "$rc" -ne 0 ] || ! grep -qE "$4" "$w/gh.log" || { [ -n "${5:-}" ] && grep -qE "$5" "$w/gh.log"; }; then
    echo "FAIL: $1 (rc ${rc})"; sed 's/^/    log: /' "$w/gh.log"; sed 's/^/    out: /' "$w/step.out"; fail=$((fail+1)); return
  fi
  echo "ok: $1"; pass=$((pass+1))
}
echo '[]' > "$w/no-issues.json"
echo '[{"number":7,"title":"required-check drift"},{"number":8,"title":"required-check drift (old)"}]' > "$w/open-issue.json"
step "drift under bash -e opens the issue"            "$w/missing.json" "$w/no-issues.json"  '^gh issue create --title required-check drift'
grep -qx "issue=9" "$w/out" 2>/dev/null && { echo "ok: the new issue's number is the job output (for the fixer dispatch)"; pass=$((pass+1)); } || { echo "FAIL: drift issue output"; fail=$((fail+1)); }
step "drift with the issue open updates it, no dup"   "$w/missing.json" "$w/open-issue.json" '^gh issue edit 7 ' '^gh issue create'
grep -qx "issue=7" "$w/out" 2>/dev/null && { echo "ok: the updated issue's number is the job output"; pass=$((pass+1)); } || { echo "FAIL: updated issue output"; fail=$((fail+1)); }
step "no required checks on main opens the issue"     "$w/none.json"    "$w/no-issues.json"  '^gh issue create'
step "match opens nothing"                            "$w/match.json"   "$w/no-issues.json"  '^gh api ' '^gh issue (create|edit)'

echo "----"
echo "required-check-guard: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
