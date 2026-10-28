#!/usr/bin/env bash
# proves: REQ-DEP-002-AC1, REQ-DEP-002-AC2, REQ-DEP-002-AC3, REQ-DEP-005-AC1, REQ-DEP-005-AC2, REQ-DEP-005-AC3
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
jq '(.[1].parameters.required_status_checks) |= map(if .context=="auditor-review-gate" then .integration_id=0 else . end)' "$w/match.json" > "$w/wrongid.json"
echo '[{"type":"deletion"}]' > "$w/none.json"
echo 'not json' > "$w/garbage.json"
jq '.required_checks |= map(if .context=="auditor-review-gate" then .integration_id=0 else . end)' "$list" > "$w/stale-list.json"
echo '{"comment":["no array"]}' > "$w/nolist.json"

check "ruleset == list passes"                    0 "match \([0-9]+ checks"                   "$w/match.json"   "$list"
check "check removed from the ruleset is drift"   1 '^\+ .*"context":"scan"'                  "$w/missing.json" "$list"
check "extra ruleset check is drift"              1 '^- .*"context":"surprise"'                "$w/extra.json"   "$list"
check "wrong integration ID is drift"             1 '"auditor-review-gate","integration_id":0' "$w/wrongid.json" "$list"
check "stale list (the #133 case) is drift"       1 '^\+ .*"auditor-review-gate","integration_id":0' "$w/match.json" "$w/stale-list.json"
check "no required checks on main = exit 2"       2 "NO required status checks"                "$w/none.json"    "$list"
check "unreadable ruleset response = exit 2"      2 "not the expected JSON"                    "$w/garbage.json" "$list"
check "missing ruleset file = exit 2"             2 "cannot read"                              "$w/absent.json"  "$list"
check "list without required_checks = exit 2"     2 "no required_checks array"                 "$w/match.json"   "$w/nolist.json"

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

# REQ-DEP-005 (merge queue, owner ratified Oct 22): every required context runs on the merge_group event on the queue's commit, and none of its jobs or steps is skipped there.
# The table names, for each context in .github/policy/required-checks.json, the workflow and job that produces it; a context the table does not know fails, so a required
# check added later cannot be missed. The one listed exception is marker-gate (REQ-DEP-005-AC1;
# ops/docs/ratify/2026-10-22-merge-queue-checks.md, owner: "add the landing
# marker check as the second listed exception"): it is a pull-request-only check, so it carries a job-level `if` and
# reports skipped, which GitHub counts as success, on
# the queue. The review gate's check (REQ-DEP-005-AC3) is not excepted: the App publishes it on the queue's head from
# agent-review-gate.yml's `queue-judge` job, which runs
# on the workflow_run event from the default branch's copy (not on merge_group) and fails closed; the dedicated checks
# below pin that wiring.
mq="$(python3 -I - "$repo" <<'PY'
import glob, json, os, re, sys
import yaml
repo = sys.argv[1]
wf = {os.path.basename(f): yaml.safe_load(open(f)) for f in glob.glob(repo + "/.github/workflows/*.yml")}
req = [c["context"] for c in json.load(open(repo + "/.github/policy/required-checks.json"))["required_checks"]]
TABLE = {"analyze (go)": ("codeql.yml", "analyze"), "acceptance-gradle": ("acceptance.yml", "acceptance-gradle"),
         "acceptance-maven (1.2.0)": ("acceptance.yml", "acceptance-maven"), "acceptance-maven (1.2.3)": ("acceptance.yml", "acceptance-maven"),
         "reproducibility": ("scan.yml", "reproducibility"), "scan": ("scan.yml", "scan"), "pin-age": ("supply-chain.yml", "pin-age")}
TABLE["auditor-review-gate"] = ("agent-review-gate.yml", "queue-judge")
for c in ("test", "lint", "gosec", "govulncheck", "allowlist", "allowlist-persona", "allowlist-chain", "allowlist-pins-auditor", "dependency-review", "fips140-only", "requirements", "coverage", "vendor"):
    TABLE[c] = ("ci.yml", c)
EXCEPT = {"marker-gate"}
out = []
def res(ok, label): out.append(("ok   " if ok else "FAIL ") + label)
unknown = sorted(set(req) - set(TABLE) - EXCEPT)
res(set(req) - set(TABLE) == EXCEPT, "every required context is known to the merge-queue table (unknown: %s)" % unknown)
res(EXCEPT == {"marker-gate"} and "auditor-review-gate" in TABLE and "auditor-review-gate" in req,
    "the one merge-queue exception is marker-gate (pull requests only); the review gate's check has a table row")
def has_event(d, name):
    on = d.get(True) if True in d else d.get("on")
    return (isinstance(on, dict) and name in on) or on == name or (isinstance(on, list) and name in on)
def skips(txt):
    if not isinstance(txt, str) or "github.event_name" not in txt:
        return False
    # an event_name condition skips the queue unless it names merge_group, or names it only to exclude it
    return "merge_group" not in txt or re.search(r"event_name\s*!=\s*['\"]merge_group['\"]", txt) is not None
for c in req:
    if c in EXCEPT or c not in TABLE: continue
    f, j = TABLE[c]; d = wf.get(f)
    job = ((d or {}).get("jobs") or {}).get(j)
    if c == "auditor-review-gate":
        # a workflow_run job, not a merge_group job: the dedicated checks below replace the generic event check
        res(job is not None, "%s: %s has the job %s (published on the queue's head)" % (c, f, j))
    else:
        res(job is not None and has_event(d, "merge_group"),
            "%s: %s job %s runs on merge_group (the workflow lists the event)" % (c, f, j))
    if not job: continue
    res(not skips(job.get("if")), "%s: the job has no condition that names an event without merge_group (%r)" % (c, job.get("if")))
    for st in job.get("steps") or []:
        res(not skips(st.get("if")) and not ("github.base_ref" in str(st.get("if")) and "merge_group" not in str(st.get("if"))), "%s: step %r is not skipped on merge_group (%r)" % (c, st.get("name") or st.get("uses") or st.get("run", "")[:30], st.get("if")))
        blob = json.dumps(st)
        res("github.event.pull_request" not in blob or "github.event.merge_group" in blob or re.search(r"pull_request\.head\.repo\.(fork|full_name)", blob) is not None,
            "%s: step %r reads the pull request only where the queue's commits are read too" % (c, st.get("name") or st.get("uses") or st.get("run", "")[:30]))
        res("github.base_ref" not in blob or "merge_group.base_ref" in blob, "%s: step %r names the queue's base wherever it names the pull request's base" % (c, st.get("name") or st.get("uses") or st.get("run", "")[:30]))
# pin age and dependency review read the queue's two commits and refuse an empty one
sc = json.dumps(wf["supply-chain.yml"]["jobs"]["pin-age"]); dr = json.dumps(wf["ci.yml"]["jobs"]["dependency-review"])
res("merge_group.base_sha" in sc and "merge_group.head_sha" in sc, "pin-age reads the queue's base_sha and head_sha")
res("merge_group.base_sha" in dr and "merge_group.head_sha" in dr, "dependency-review reads the queue's base_sha and head_sha")
for nm, blob in (("pin-age", sc), ("dependency-review", dr)):
    res("merge_group" in blob and re.search(r"_SHA:\?|QUEUE_BASE.*QUEUE_HEAD|\[ -n ", blob) is not None, "%s: a queue run with an empty base or head fails (a refusal step names it)" % nm)

# REQ-DEP-005-AC1: marker-gate is pull-request-only by a job-level condition; ci.yml's triggers carry no filter (a
# filtered workflow leaves the required check Pending and blocks the queue)
ci_wf = wf["ci.yml"]
mg = ci_wf["jobs"].get("marker-gate") or {}
res("github.event_name" in str(mg.get("if")) and "pull_request" in str(mg.get("if")),
    "marker-gate has a job-level if naming github.event_name and pull_request (%r)" % mg.get("if"))
con = ci_wf.get(True) if True in ci_wf else ci_wf.get("on")
for ev in ("pull_request", "merge_group"):
    v = con.get(ev) if isinstance(con, dict) else None
    FILTERS = {"paths", "paths-ignore", "branches", "branches-ignore", "tags", "tags-ignore"}
    res(isinstance(con, dict) and ev in con and not (isinstance(v, dict) and set(v) & FILTERS),
        
        "ci.yml %s trigger exists and has no paths, branches or tags filter (%r)" % (ev, v))

# REQ-DEP-005-AC3: the review gate in the queue runs from the default branch's copy (workflow_run), reads git objects
# only, holds the App token only in the agent environment, fails closed
rg = wf["agent-review-gate.yml"]
ron = rg.get(True) if True in rg else rg.get("on")
wr = ron.get("workflow_run") if isinstance(ron, dict) else None
def is_agent(jb):
    e = jb.get("environment")
    return e == "agent" or (isinstance(e, dict) and e.get("name") == "agent")
res(isinstance(wr, dict) and wr.get("workflows") == ["CI"],
    "agent-review-gate.yml triggers on workflow_run of the workflow CI (%r)" % (wr,))
res(isinstance(wr, dict) and sorted(wr.get("types") or []) == ["completed", "requested"],
    "the workflow_run types are exactly requested and completed (%r)" % (wr,))
res(isinstance(ron, dict) and "merge_group" not in ron,
    "agent-review-gate.yml has no merge_group trigger (a queue ref is not the default branch; "
    "no job here runs the group's copy)")
qj = rg["jobs"].get("queue-judge")
res(qj is not None, "agent-review-gate.yml has the job queue-judge")
qj = qj or {}
res("github.event.workflow_run.event == 'merge_group'" in str(qj.get("if")),
    "queue-judge runs only if github.event.workflow_run.event == 'merge_group' (%r)" % qj.get("if"))
for jn, jb in rg["jobs"].items():
    if is_agent(jb):
        res(isinstance(ron, dict) and "merge_group" not in ron,
            "job %s (environment agent) is not triggered by merge_group" % jn)
    blob = json.dumps(jb)
    if "create-github-app-token" in blob or "AUDITOR_APP_PRIVATE_KEY" in blob:
        res(is_agent(jb), "job %s mints or reads the App token only inside environment: agent" % jn)
res(is_agent(qj),
    "queue-judge is an environment: agent job (it holds the App token; main's copy, so the "
    "environment's default-branch rule is met)")
for st in qj.get("steps") or []:
    w = st.get("with") or {}
    nm = st.get("name") or st.get("uses") or st.get("run", "")[:30]
    if str(st.get("uses", "")).startswith("actions/checkout"):
        res("workflow_run" not in json.dumps({k: w[k] for k in ("ref", "path", "repository") if k in w}),
            "queue-judge step %r checks out the default branch only (no ref, path or repository "
            "from workflow_run)" % nm)
    r = st.get("run") or ""
    res(not re.search(r"git\s+(checkout|switch|worktree)\b", r),
        "queue-judge step %r checks nothing of the group out" % nm)
    res(not re.search(r"\$\{\{[^}]*workflow_run", r),
        "queue-judge step %r never inlines workflow_run fields into the script (env vars only)" % nm)
qtxt = json.dumps(qj)
res("queue-gate-judge.sh" in qtxt, "queue-judge runs main's bin/queue-gate-judge.sh")
res("github.event.workflow_run.head_sha" in qtxt, "queue-judge takes the queue head from workflow_run.head_sha")
res("auditor-review-gate" in qtxt and "check-runs" in qtxt,
    "queue-judge publishes the auditor-review-gate check run on that head")

# the sweep also covers the queue's refs and posts at most once per head
sws = "\n".join(st.get("run", "") for st in rg["jobs"]["sweep"]["steps"])
res("gh-readonly-queue" in sws, "the sweep script lists the queue refs (gh-readonly-queue)")
res("matching-refs" in sws or "ls-remote" in sws or "git/refs" in sws,
    "the sweep reads the queue refs through the refs API or the remote, read-only")
res("pr-[0-9]+-[0-9a-f]{40}" in sws, "the sweep validates a queue ref against pr-N-<40 hex> before using it")
res("queue-gate-judge.sh" in sws, "the sweep judges a queue head with main's bin/queue-gate-judge.sh")
posts = len(re.findall(r"-f name=auditor-review-gate", sws))
looks = len(re.findall(r"check_name=auditor-review-gate", sws))
res(posts >= 1 and looks >= posts,
    "every post of the check in the sweep follows a lookup of the App's existing verdict on that head "
    "(%d posts, %d lookups)" % (posts, looks))
res(re.search(r"success\)\s*continue", sws) is not None,
    "a head that already has a success verdict is skipped (no second post)")
res(re.search(r"still failure", sws) is not None, "a head that still fails is not re-posted")
print("\n".join(out))
PY
)"
while IFS= read -r l; do
  case "$l" in
    "ok   "*) echo "ok: ${l#ok   }"; pass=$((pass+1));;
    FAIL*)    echo "FAIL: ${l#FAIL }"; fail=$((fail+1));;
    *) echo "FAIL: merge-queue suite did not run: $l"; fail=$((fail+1));;
  esac
done <<<"${mq:-FAIL the merge-queue python block printed nothing}"
# REQ-DEP-002-AC3 (advisor reading Oct 16, Astra release review R5): the committed list names the two jobs that were not in it, each as a job of ci.yml
ci="$repo/.github/workflows/ci.yml"
# the two jobs and their scopes are read from the criterion's own text (REQ-DEP-002-AC3: "names the job X once with scope S and the job Y once with scope T"), so the list, the criterion and ci.yml are tied to one another
ac3pairs="$(python3 - "$repo/requirements/requirements.yaml" <<'PY'
import re, sys, yaml
q = next(q for q in yaml.safe_load(open(sys.argv[1]))["requirements"] if q["id"] == "REQ-DEP-002")
t = next(a for a in q["acceptance_criteria"] if a["id"] == "REQ-DEP-002-AC3")["then"]
m = re.search(r"names the job (\S+) once with scope (\w+) and the job (\S+) once with scope (\w+)", t)
assert m, t[:200]
print(m.group(1), m.group(2)); print(m.group(3), m.group(4))
PY
)" || { echo "FAIL: REQ-DEP-002-AC3's text could not be parsed for the two job names"; fail=$((fail+1)); ac3pairs=""; }
while read -r ctx scope; do
  [ -n "$ctx" ] || continue
  n="$(jq --arg c "$ctx" --arg s "$scope" '[.required_checks[] | select(.context == $c and .scope == $s and .integration_id == 15368)] | length' "$list")"
  m="$(jq --arg c "$ctx" '[.required_checks[] | select(.context == $c)] | length' "$list")"
  if [ "$n" = 1 ] && [ "$m" = 1 ] && grep -qE "^    name: ${ctx}\$" "$ci"; then
    echo "ok: the committed list names ${ctx} once, scope ${scope}, integration 15368, and ci.yml has that job"; pass=$((pass+1))
  else
    echo "FAIL: the committed list must name ${ctx} exactly once with scope ${scope} and integration 15368, and ci.yml must have a job named ${ctx} (found ${n}/${m})"; fail=$((fail+1))
  fi
done <<< "$ac3pairs"

echo "----"
echo "required-check-guard: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
