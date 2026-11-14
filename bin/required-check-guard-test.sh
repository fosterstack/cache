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

check() { # name want_rc regex rules_file list_file [release_only_file]
  local out rc
  out="$(GUARD_RULES_JSON="$4" bash "$sut" "$5" ${6:+"$6"} 2>&1)"; rc=$?
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
jq '(.[1].parameters.required_status_checks) |=
    map(if .context=="lint" then .integration_id=0 else . end)' "$w/match.json" > "$w/wrongid.json"
echo '[{"type":"deletion"}]' > "$w/none.json"
echo 'not json' > "$w/garbage.json"
jq '.required_checks |= map(if .context=="lint" then .integration_id=0 else . end)' "$list" > "$w/stale-list.json"
echo '{"comment":["no array"]}' > "$w/nolist.json"

check "ruleset == list passes"                    0 "match \([0-9]+ checks"                   "$w/match.json"   "$list"
check "check removed from the ruleset is drift"   1 '^\+ .*"context":"scan"'                  "$w/missing.json" "$list"
check "extra ruleset check is drift"              1 '^- .*"context":"surprise"'                "$w/extra.json"   "$list"
check "wrong integration ID is drift"             1 '"lint","integration_id":0' "$w/wrongid.json" "$list"
check "stale list (the #133 case) is drift"       1 '^\+ .*"lint","integration_id":0' \
  "$w/match.json" "$w/stale-list.json"
check "no required checks on main = exit 2"       2 "NO required status checks"                "$w/none.json"    "$list"
check "unreadable ruleset response = exit 2"      2 "not the expected JSON"                    "$w/garbage.json" "$list"
check "missing ruleset file = exit 2"             2 "cannot read"                              "$w/absent.json"  "$list"
check "list without required_checks = exit 2"     2 "no required_checks array"                 "$w/match.json"   "$w/nolist.json"

# REQ-REL-013-AC2: with a second argument the guard also compares release-only-checks.json, entry by entry (context,
# integration_id, scope), with the seven entries pinned in the script
ro="$repo/.github/policy/release-only-checks.json"
ro_edit() { jq -c "$2" "$ro" > "$w/ro-$1.json"; }
ro_edit id      '(.required_checks[] | select(.context=="auditor-review-gate") | .integration_id) = 15368'
ro_edit scope   '(.required_checks[] | select(.context=="coverage") | .scope) = "pull_request"'
ro_edit dropped '.required_checks |= map(select(.context != "allowlist-chain"))'
ro_edit eighth  '.required_checks += [{"context":"extra-check","integration_id":15368,"scope":"push"}]'
echo 'not json' > "$w/ro-garbage.json"
echo '{"comment":["no array"]}' > "$w/ro-nolist.json"
check "pinned release-only list passes"                0 "release-only list match" "$w/match.json" "$list" "$ro"
check "a changed integration_id is drift"              1 '^[-+] .*"auditor-review-gate".*5054756' \
  "$w/match.json" "$list" "$w/ro-id.json"
check "a changed integration_id prints both entries"   1 '^[-+] .*"auditor-review-gate".*15368' \
  "$w/match.json" "$list" "$w/ro-id.json"
check "a changed scope is drift, whole entry printed"  1 '^[-+] .*"coverage".*"scope":"pull_request"' \
  "$w/match.json" "$list" "$w/ro-scope.json"
check "a changed scope prints the pinned entry"        1 '^[-+] .*"coverage".*"scope":"push"' \
  "$w/match.json" "$list" "$w/ro-scope.json"
check "a dropped entry is drift"                       1 '^[-+] .*"allowlist-chain"' \
  "$w/match.json" "$list" "$w/ro-dropped.json"
check "an eighth entry is drift"                       1 '^[-+] .*"extra-check"' \
  "$w/match.json" "$list" "$w/ro-eighth.json"
check "unreadable release-only file = exit 2"          2 "release-only" "$w/match.json" "$list" "$w/ro-absent.json"
check "release-only file not JSON = exit 2"            2 "release-only" "$w/match.json" "$list" "$w/ro-garbage.json"
check "release-only file without the array = exit 2"   2 "release-only" "$w/match.json" "$list" "$w/ro-nolist.json"

# REQ-REL-013-AC2: the pin is main's copy of the guard, so a head that edits the file is still red; the wiring runs
# the script fetched from main, not the tree's bin/ copy
mkdir -p "$w/main" "$w/head/.github/policy"
cp "$sut" "$w/main/required-check-guard.sh"
cp "$list" "$w/head/.github/policy/required-checks.json"
sed 's/5054756/15368/' "$ro" > "$w/head/.github/policy/release-only-checks.json"
out="$(cd "$w/head" && GUARD_RULES_JSON="$w/match.json" bash "$w/main/required-check-guard.sh" \
  .github/policy/required-checks.json .github/policy/release-only-checks.json 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && grep -qE '^[-+] .*"auditor-review-gate"' <<<"$out"; then
  echo "ok: main's guard judges a head that edited the file, the judge and the guard together"; pass=$((pass+1))
else
  echo "FAIL: main's guard over a head that moved its own pin (rc ${rc}, want 1)"
  echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi

# The pin step, whole: every key and its text, byte for byte. It fetches the guard from main (repository, path,
# ?ref=main), never the pull request's own copy, and runs that fetch once over both policy files. Any other key,
# line, comment or order is refused.
cat > "$w/pin-extract.py" <<'PY'
import json, sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["required-check-guard"]["steps"]
pin = [s for s in steps if "release-only-checks.json" in (s.get("run") or "") and "required-check-guard.sh" in s["run"]]
assert len(pin) == 1, f"{len(pin)} steps of the required-check guard job run the guard over release-only-checks.json"
open(sys.argv[3], "w").write(pin[0]["run"])
with open(sys.argv[2], "w") as out:
    for k, v in pin[0].items():
        if isinstance(v, str) and "\n" in v:
            out.write(f"{k}: |\n" + "".join(f"  {line}\n" for line in v.splitlines()))
        else:
            out.write(f"{k}: {json.dumps(v)}\n")
PY
cat > "$w/pin-want.txt" <<'WANT'
name: "this tree's policy lists vs the ruleset on main and the pin in main's guard"
env: {"GH_TOKEN": "${{ github.token }}"}
run: |
  set -euo pipefail
  gh api "repos/${GITHUB_REPOSITORY}/contents/bin/required-check-guard.sh?ref=main" --jq '.content' \
    | base64 -d > "${RUNNER_TEMP}/required-check-guard.sh"
  [ -s "${RUNNER_TEMP}/required-check-guard.sh" ]
  bash "${RUNNER_TEMP}/required-check-guard.sh" .github/policy/required-checks.json .github/policy/release-only-checks.json
WANT
python3 "$w/pin-extract.py" "$repo/.github/workflows/ci.yml" "$w/pin-step.txt" "$w/pin-run.sh" ||
  { echo "FAIL: ci.yml has no single pin step"; fail=$((fail+1)); }
pin_case() { # name step_file want (0 = identical to the pinned text, 1 = differs)
  if diff -u "$w/pin-want.txt" "$2" > "$w/pin.diff" 2>&1; then got=0; else got=1; fi
  if [ "$got" -eq "$3" ]; then echo "ok: $1"; pass=$((pass+1))
  else echo "FAIL: $1 (differs=$got, want differs=$3)"; sed 's/^/    /' "$w/pin.diff"; fail=$((fail+1)); fi
}
pin_case "the pin step is the pinned text, byte for byte" "$w/pin-step.txt" 0
sed 's|guard.sh?ref=main|guard.sh?ref=${GITHUB_HEAD_REF}|' "$w/pin-step.txt" > "$w/pin-moved.txt"
pin_case "a pin step fetching the guard at the pull request's branch is refused" "$w/pin-moved.txt" 1
cat > "$w/pin-redirect.txt" <<'BAD'
name: "this tree's policy lists vs the ruleset on main and the pin in main's guard"
env: {"GH_TOKEN": "${{ github.token }}"}
run: |
  set -euo pipefail
  # gh api "repos/${GITHUB_REPOSITORY}/contents/bin/required-check-guard.sh?ref=main" --jq '.content' \
  gh api "repos/${GITHUB_REPOSITORY}/contents/bin/required-check-guard.sh?ref=${GITHUB_HEAD_REF}" --jq .content \
    | base64 -d > "$RUNNER_TEMP/other.sh"
  printf 'exit 0' > "${RUNNER_TEMP}/required-check-guard.sh"
  bash "${RUNNER_TEMP}/required-check-guard.sh" .github/policy/required-checks.json .github/policy/release-only-checks.json
BAD
pin_case "a comment holding the fetch text over a fetch elsewhere is refused" "$w/pin-redirect.txt" 1
sed '$i \  echo hi' "$w/pin-step.txt" > "$w/pin-extra.txt"
pin_case "an extra line in the pin step is refused" "$w/pin-extra.txt" 1
cat > "$w/pin-mutate.py" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
for s in wf["jobs"]["required-check-guard"]["steps"]:
    if "release-only-checks.json" in (s.get("run") or "") and "required-check-guard.sh" in s["run"]:
        s.update(yaml.safe_load(sys.argv[3]))
yaml.safe_dump(wf, open(sys.argv[2], "w"))
PY
pin_key_case() { # name key_yaml: the pin step with one more key is refused
  python3 "$w/pin-mutate.py" "$repo/.github/workflows/ci.yml" "$w/ci-mut.yml" "$2"
  python3 "$w/pin-extract.py" "$w/ci-mut.yml" "$w/pin-mut.txt" /dev/null
  pin_case "$1" "$w/pin-mut.txt" 1
}
pin_key_case "a GUARD_RULES_JSON env key on the pin step is refused" \
  '{env: {GH_TOKEN: x, GUARD_RULES_JSON: .github/policy/own.json}}'
pin_key_case "a made-up key on the pin step is refused" '{made-up-key: 1}'

# No step of the guard job may write to GITHUB_PATH, GITHUB_ENV or BASH_ENV: that is how an earlier step puts a fake gh
# in front of the pinned step. (The allowlist job's twin check is in pin-wiring-test.sh; it does not read this job.)
cat > "$w/job-hooks.py" <<'PY'
import json, sys, yaml
job = yaml.safe_load(open(sys.argv[1]))["jobs"]["required-check-guard"]
if len(sys.argv) > 2:
    job["steps"].insert(1, {"run": 'echo /tmp/fake >> "$GITHUB_PATH"'})
sys.exit(any(h in json.dumps(job) for h in ("BASH_ENV", "GITHUB_ENV", "GITHUB_PATH")))
PY
if python3 "$w/job-hooks.py" "$repo/.github/workflows/ci.yml"; then
  echo "ok: the guard job writes no GITHUB_PATH, GITHUB_ENV or BASH_ENV"; pass=$((pass+1))
else echo "FAIL: the guard job mentions GITHUB_PATH, GITHUB_ENV or BASH_ENV"; fail=$((fail+1)); fi
if python3 "$w/job-hooks.py" "$repo/.github/workflows/ci.yml" mutate; then
  echo "FAIL: a GITHUB_PATH write in the guard job was accepted"; fail=$((fail+1))
else echo "ok: a GITHUB_PATH write in the guard job is refused"; pass=$((pass+1)); fi

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

# The pin step, run as GitHub runs a step without `shell:` (bash -e, no pipefail): it must fail when the fetch of main's
# guard fails or comes back empty, and must run the fetched guard once over both policy files with the ruleset from
# GUARD_RULES_JSON.
mkdir -p "$w/pintree/.github/policy" "$w/pinstub"
cp "$list" "$w/pintree/.github/policy/required-checks.json"
cp "$ro" "$w/pintree/.github/policy/release-only-checks.json"
cat > "$w/pinstub/gh" <<'EOF'
#!/usr/bin/env bash
[ -n "${STUB_PRINT:-}" ] && cat "$STUB_PRINT"
exit "${STUB_RC:-0}"
EOF
chmod +x "$w/pinstub/gh"
base64 < "$sut" | tr -d '\n' > "$w/guard.b64"; : > "$w/empty.txt"
pinstep() { # name zero|nonzero stub_rc stub_print_file
  (cd "$w/pintree" && env PATH="$w/pinstub:$PATH" GH_TOKEN=x STUB_RC="$3" STUB_PRINT="$4" \
     GUARD_RULES_JSON="$w/match.json" GITHUB_REPOSITORY=o/r RUNNER_TEMP="$w" \
     bash --noprofile --norc -e "$w/pin-run.sh") >"$w/pin.out" 2>&1; local rc=$?
  if { [ "$2" = zero ] && [ "$rc" -ne 0 ]; } || { [ "$2" = nonzero ] && [ "$rc" -eq 0 ]; }; then
    echo "FAIL: $1 (rc ${rc}, want $2)"; sed 's/^/    /' "$w/pin.out"; fail=$((fail+1)); return
  fi
  echo "ok: $1"; pass=$((pass+1))
}
pinstep "pin step: gh fails with no output = non-zero"          nonzero 1 "$w/empty.txt"
pinstep "pin step: gh prints nothing, exits 0 = non-zero"       nonzero 0 "$w/empty.txt"
pinstep "pin step: gh prints main's guard = exit 0"             zero    0 "$w/guard.b64"
# the step sets pipefail itself: a gh that fails after printing the guard must still fail the step
pinstep "gh fails after printing the guard"                     nonzero 1 "$w/guard.b64"

echo "----"
echo "required-check-guard: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
