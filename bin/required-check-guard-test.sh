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
# integration_id, scope), with the eight entries pinned in the script (allowlist-pins-auditor is the eighth: off the
# ruleset, required by release admission). ro8 is the committed list with that entry present exactly once, so the
# cases below hold whatever the committed file says; the first case checks the committed file itself.
ro_file="$repo/.github/policy/release-only-checks.json"
jq -c '.required_checks |= (map(select(.context != "allowlist-pins-auditor"))
  + [{"context":"allowlist-pins-auditor","integration_id":15368,"scope":"push"}])' "$ro_file" > "$w/ro8.json"
ro="$w/ro8.json"
ro_edit() { jq -c "$2" "$ro" > "$w/ro-$1.json"; }
ro_edit seven   '.required_checks |= map(select(.context != "allowlist-pins-auditor"))'
ro_edit pctx    '(.required_checks[] | select(.context=="allowlist-pins-auditor") | .context) = "allowlist-pins"'
ro_edit pid     '(.required_checks[] | select(.context=="allowlist-pins-auditor") | .integration_id) = 5054756'
ro_edit pscope  '(.required_checks[] | select(.context=="allowlist-pins-auditor") | .scope) = "pull_request"'
ro_edit id      '(.required_checks[] | select(.context=="auditor-review-gate") | .integration_id) = 15368'
ro_edit scope   '(.required_checks[] | select(.context=="coverage") | .scope) = "pull_request"'
ro_edit dropped '.required_checks |= map(select(.context != "allowlist-chain"))'
ro_edit eighth  '.required_checks += [{"context":"extra-check","integration_id":15368,"scope":"push"}]'
echo 'not json' > "$w/ro-garbage.json"
echo '{"comment":["no array"]}' > "$w/ro-nolist.json"
check "pinned release-only list passes"                0 "release-only list match \(8 entries" "$w/match.json" "$list" "$ro"
check "the committed release-only file holds the eight" 0 "release-only list match \(8 entries" \
  "$w/match.json" "$list" "$ro_file"
check "the old seven (no allowlist-pins-auditor) is drift" 1 '^[-+] .*"allowlist-pins-auditor"' \
  "$w/match.json" "$list" "$w/ro-seven.json"
check "the old seven is refused saying eight"          1 "not the eight entries pinned" \
  "$w/match.json" "$list" "$w/ro-seven.json"
check "pins-auditor context changed is drift"          1 '^[-+] .*"allowlist-pins-auditor"' \
  "$w/match.json" "$list" "$w/ro-pctx.json"
check "pins-auditor integration_id changed is drift"   1 '^[-+] .*"allowlist-pins-auditor".*5054756' \
  "$w/match.json" "$list" "$w/ro-pid.json"
check "pins-auditor scope changed is drift"            1 '^[-+] .*"allowlist-pins-auditor".*"scope":"pull_request"' \
  "$w/match.json" "$list" "$w/ro-pscope.json"
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
sed 's/5054756/15368/' "$w/ro8.json" > "$w/head/.github/policy/release-only-checks.json"
out="$(cd "$w/head" && GUARD_RULES_JSON="$w/match.json" bash "$w/main/required-check-guard.sh" \
  .github/policy/required-checks.json .github/policy/release-only-checks.json 2>&1)"; rc=$?
if [ "$rc" -eq 1 ] && grep -qE '^[-+] .*"auditor-review-gate"' <<<"$out"; then
  echo "ok: main's guard judges a head that edited the file, the judge and the guard together"; pass=$((pass+1))
else
  echo "FAIL: main's guard over a head that moved its own pin (rc ${rc}, want 1)"
  echo "$out" | sed 's/^/    /'; fail=$((fail+1))
fi


# The steps of the pinned job, found by what they contain: checkout, fetch of main's guard, run of it, drift issue.
# A step is written to a file only when exactly one step has that content.
ci="${CI_YML:-$repo/.github/workflows/ci.yml}"
python3 - "$ci" "$w" <<'PY' || { echo "FAIL: ci.yml has no single pin step"; exit 1; }
import sys, re, yaml
wf = yaml.safe_load(open(sys.argv[1])); w = sys.argv[2]
steps = wf["jobs"]["required-check-guard"]["steps"]
def pick(what, found):
    assert len(found) == 1, what + " step not found"
    return found[0]
fetch = pick("fetch", [s for s in steps if "contents/bin/required-check-guard.sh" in s.get("run", "")])
pin = pick("run", [s for s in steps if "release-only-checks.json" in s.get("run", "")])
drift = pick("drift-issue", [s for s in steps if s.get("id") == "drift-issue"])
for name, s in (("fetch-run.sh", fetch), ("pin-run.sh", pin), ("step.sh", drift)):
    open(w + "/" + name, "w").write(s["run"])
open(w + "/guard-name", "w").write(re.search(r"RUNNER_TEMP\}?/([\w.-]+)", fetch["run"]).group(1))
PY
gname="$(cat "$w/guard-name" 2>/dev/null)"

# The extraction must say in words when a step is missing or doubled. The suite runs itself over copies of ci.yml with
# no run step and with two (CI_YML set, so the copy's own run skips this case).
if [ -z "${CI_YML:-}" ]; then
  for shape in none two; do
    python3 - "$ci" "$w/ci-$shape.yml" "$shape" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
steps = wf["jobs"]["required-check-guard"]["steps"]
pin = [s for s in steps if "release-only-checks.json" in s.get("run", "")]
rest = [s for s in steps if s not in pin]
wf["jobs"]["required-check-guard"]["steps"] = rest + (pin * 2 if sys.argv[3] == "two" else [])
yaml.safe_dump(wf, open(sys.argv[2], "w"))
PY
    out="$(CI_YML="$w/ci-$shape.yml" bash "$0" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] && grep -qxF "FAIL: ci.yml has no single pin step" <<<"$out"; then
      echo "ok: ci.yml with ${shape} run steps fails in words"; pass=$((pass+1))
    else
      echo "FAIL: ci.yml with ${shape} run steps (rc ${rc}, want non-zero and the sentence)"; fail=$((fail+1))
    fi
  done
fi

# What ci.yml must say, read as text: the step list, the fetch and run steps, no code of the checkout run, the drift
# step on the fetched file, and the guard's own suite in the allowlist job.
python3 - "$repo/.github/workflows/ci.yml" > "$w/static.out" 2>&1 <<'PY'
import sys, re, json, yaml
wf = yaml.safe_load(open(sys.argv[1]))
steps = wf["jobs"]["required-check-guard"]["steps"]
runs = [s.get("run", "") for s in steps]
T = r"\"?\$\{?RUNNER_TEMP\}?/[\w.-]+\"?"
def kind(s):
    if re.match(r"actions/checkout@[0-9a-f]{40}( |$)", s.get("uses", "")): return "checkout"
    if s.get("id") == "drift-issue": return "drift-issue"
    if "contents/bin/required-check-guard.sh" in s.get("run", ""): return "fetch"
    if "release-only-checks.json" in s.get("run", ""): return "run"
    return "other"
kinds = [kind(s) for s in steps]
by = {kind(s): s for s in steps}
def t(name, ok): print(("ok: " if ok else "FAIL: ") + name)
t("job steps are checkout, fetch, run, drift-issue in that order (got %s)" % kinds,
  kinds == ["checkout", "fetch", "run", "drift-issue"])
f = by.get("fetch", {}).get("run", "")
t("fetch step: set -euo pipefail, gh api of main's guard into a file under RUNNER_TEMP, then [ -s ] on it",
  bool(re.search(r"^set -euo pipefail$", f, re.M))
  and bool(re.search(r'gh api "repos/\$\{GITHUB_REPOSITORY\}/contents/bin/required-check-guard\.sh\?ref=main"', f))
  and bool(re.search(r"> " + T, f)) and bool(re.search(r"^\[ -s " + T + r" \]$", f, re.M)))
r = [l.strip() for l in by.get("run", {}).get("run", "").splitlines() if l.strip() and not l.strip().startswith("#")]
t("run step: one line, bash on a file under RUNNER_TEMP over the two policy files (got %s)" % r,
  len(r) == 1 and bool(re.fullmatch(r"bash " + T + r" \.github/policy/required-checks\.json "
                                    r"\.github/policy/release-only-checks\.json", r[0])))
prog = r"(^|[;&|(])\s*(bash\s+|sh\s+|exec\s+)?\"?(\./)?([\w.-]+/)*bin/"
t("no run text of the job runs a path under bin/",
  not any(re.search(prog, l) for x in runs for l in x.splitlines()))
t("no step of the job sources a file or uses a local action",
  not any(re.search(r"(^|[;&|(])\s*(source|\.)\s+\S", l) for x in runs for l in x.splitlines())
  and not any(s.get("uses", "").startswith("./") for s in steps))
d = by.get("drift-issue", {}).get("run", "")
t("drift step runs the guard fetched into RUNNER_TEMP", bool(re.search(r"bash " + T, d)))
t("the guard's fetch path occurs in exactly one step of the job",
  sum("contents/bin/required-check-guard.sh" in json.dumps(s) for s in steps) == 1)
al = [s for s in wf["jobs"]["allowlist"]["steps"] if "required-check-guard-test.sh" in json.dumps(s)]
t("allowlist runs the guard suite as exactly one plain step",
  len(al) == 1 and al[0].get("run") == "bash bin/required-check-guard-test.sh"
  and not {"if", "continue-on-error", "env", "shell"} & set(al[0]))
t("the pinned job does not run the guard suite",
  not any("required-check-guard-test.sh" in json.dumps(s) for s in steps))
PY
while IFS= read -r line; do
  echo "$line"
  case "$line" in ok:*) pass=$((pass+1)) ;; *) fail=$((fail+1)) ;; esac
done < "$w/static.out"

# The hygiene step that opens/updates the `required-check drift` issue, run EXACTLY as committed under GitHub's default
# `bash -e` with a recording gh stub (round-1 blocker: -e ended the step at the guard's refusal, before any issue call).
# It runs the guard fetched into RUNNER_TEMP, so the fetched copy is put there; the tree it runs in may hold a decoy.
mkdir -p "$w/stub" "$w/pintree/.github/policy" "$w/pintree/bin" "$w/pinstub"
cp "$sut" "$w/$gname"
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
tree="$repo"
step() { # name rules issues_json want_regex [dont_want_regex]
  : > "$w/gh.log"; : > "$w/out"
  (cd "$tree" && env PATH="$w/stub:$PATH" GH_LOG="$w/gh.log" MAIN_LIST="$list" ISSUES_JSON="$3" \
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

# The checkout's bin/ copy of the guard is a decoy that leaves a marker if run; no step may run it.
echo "echo ran > $w/tree-ran" > "$w/pintree/bin/required-check-guard.sh"
rm -f "$w/tree-ran"; tree="$w/pintree"
step "drift step opens the issue with the fetched guard" "$w/missing.json" "$w/no-issues.json" '^gh issue create'
if [ ! -e "$w/tree-ran" ]; then echo "ok: the drift step did not run the checkout's guard"; pass=$((pass+1))
else echo "FAIL: the drift step ran the checkout's bin/required-check-guard.sh"; fail=$((fail+1)); fi

# The fetch step, run as GitHub runs a step without `shell:` (bash -e): it writes a non-empty file under RUNNER_TEMP
# and does not run it; it fails when gh fails, prints nothing, or fails after printing.
cp "$list" "$w/pintree/.github/policy/required-checks.json"
cp "$w/ro8.json" "$w/pintree/.github/policy/release-only-checks.json"
cat > "$w/pinstub/gh" <<'EOF'
#!/usr/bin/env bash
[ -n "${STUB_PRINT:-}" ] && cat "$STUB_PRINT"
exit "${STUB_RC:-0}"
EOF
chmod +x "$w/pinstub/gh"
base64 < "$sut" | tr -d '\n' > "$w/guard.b64"; : > "$w/empty.txt"
echo "echo ran > $w/fetched-ran" | base64 | tr -d '\n' > "$w/marker-guard.b64"
fetchstep() { # name zero|nonzero stub_rc stub_print_file
  local rt; rt="$(mktemp -d -p "$w")"; rm -f "$w/fetched-ran"
  (cd "$w/pintree" && env PATH="$w/pinstub:$PATH" GH_TOKEN=x STUB_RC="$3" STUB_PRINT="$4" \
     GITHUB_REPOSITORY=o/r RUNNER_TEMP="$rt" bash --noprofile --norc -e "$w/fetch-run.sh") >"$w/fetch.out" 2>&1
  local rc=$?
  if { [ "$2" = zero ] && { [ "$rc" -ne 0 ] || [ ! -s "$rt/$gname" ] || [ -e "$w/fetched-ran" ]; }; } \
     || { [ "$2" = nonzero ] && [ "$rc" -eq 0 ]; }; then
    echo "FAIL: $1 (rc ${rc}, want $2)"; ls "$rt"; [ -e "$w/fetched-ran" ] && echo "    the fetched guard ran"
    sed 's/^/    /' "$w/fetch.out"; fail=$((fail+1)); return
  fi
  echo "ok: $1"; pass=$((pass+1))
}
fetchstep "fetch step: gh fails with no output = non-zero"        nonzero 1 "$w/empty.txt"
fetchstep "fetch step: gh prints nothing, exits 0 = non-zero"     nonzero 0 "$w/empty.txt"
fetchstep "fetch step: gh fails after printing the guard"         nonzero 1 "$w/guard.b64"
fetchstep "fetch step: writes the guard under RUNNER_TEMP, never runs it" zero 0 "$w/marker-guard.b64"

# The run step: bash on the fetched file over the two policy files of the tree, and nothing else
runstep() { # runner_temp
  (cd "$w/pintree" && env PATH="$w/pinstub:$PATH" GH_TOKEN=x GUARD_RULES_JSON="$w/match.json" \
     GITHUB_REPOSITORY=o/r RUNNER_TEMP="$1" bash --noprofile --norc -e "$w/pin-run.sh") >"$w/pin.out" 2>&1
}
rt="$(mktemp -d -p "$w")"; rm -f "$w/tree-ran"
printf '%s\n' 'printf "%s\n" "$@" > "${0%/*}/args"' > "$rt/$gname"
runstep "$rt"; rc=$?
if [ "$rc" -eq 0 ] && [ ! -e "$w/tree-ran" ] && [ "$(cat "$rt/args" 2>/dev/null)" = \
     ".github/policy/required-checks.json
.github/policy/release-only-checks.json" ]; then
  echo "ok: run step runs the file in RUNNER_TEMP over the two policy files, not the checkout's guard"; pass=$((pass+1))
else
  echo "FAIL: run step (rc ${rc}; checkout's guard $([ -e "$w/tree-ran" ] && echo ran || echo not run))"
  sed 's/^/    /' "$w/pin.out"; fail=$((fail+1))
fi

# REQ-REL-013-AC2: the fetched guard over a tree whose release-only list lacks `coverage` is drift, exit 1
rt="$(mktemp -d -p "$w")"
jq -c '.required_checks |= map(select(.context != "coverage"))' "$ro" \
  > "$w/pintree/.github/policy/release-only-checks.json"
(cd "$w/pintree" && env PATH="$w/pinstub:$PATH" STUB_PRINT="$w/guard.b64" GH_TOKEN=x GITHUB_REPOSITORY=o/r \
   RUNNER_TEMP="$rt" bash --noprofile --norc -e "$w/fetch-run.sh") >/dev/null 2>&1
(cd "$w/pintree" && env PATH="$w/pinstub:$PATH" STUB_PRINT="$w/guard.b64" GH_TOKEN=x GUARD_RULES_JSON="$w/match.json" \
   GITHUB_REPOSITORY=o/r RUNNER_TEMP="$rt" bash --noprofile --norc -e "$w/pin-run.sh") >"$w/pin.out" 2>&1; rc=$?
if [ "$rc" -eq 1 ] && grep -qE '^[-+] .*"coverage"' "$w/pin.out"; then
  echo "ok: dropping coverage from release-only-checks.json is red at the guard"; pass=$((pass+1))
else
  echo "FAIL: dropped coverage (rc ${rc}, want 1)"; sed 's/^/    /' "$w/pin.out"; fail=$((fail+1))
fi

echo "----"
echo "required-check-guard: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
