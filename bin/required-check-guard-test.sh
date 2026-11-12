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

check "ruleset == list passes"                    0 "match \([0-9]+ listed checks"            "$w/match.json"   "$list"
check "check removed from the ruleset is drift"   1 '^\{"context":"scan"'                     "$w/missing.json" "$list"
check "extra ruleset check still passes (a superset)" 0 "match \([0-9]+ listed checks"        "$w/extra.json"   "$list"
check "wrong integration ID is drift"             1 '^\{"context":"auditor-review-gate","integration_id":5054756' "$w/wrongid.json" "$list"
check "stale list (the #133 case) is drift"       1 '^\{"context":"auditor-review-gate","integration_id":0' "$w/match.json" "$w/stale-list.json"
check "no required checks on main = exit 2"       2 "NO required status checks"                "$w/none.json"    "$list"
check "unreadable ruleset response = exit 2"      2 "not the expected JSON"                    "$w/garbage.json" "$list"
check "missing ruleset file = exit 2"             2 "cannot read"                              "$w/absent.json"  "$list"
check "list without required_checks = exit 2"     2 "no required_checks array"                 "$w/match.json"   "$w/nolist.json"

# REQ-DEP-005-AC3 (merge queue, owner ratified Oct 22): the App publishes the review gate's check on the queue's head from
# agent-review-gate.yml's `queue-publish` job (after the secret-free `queue-judge` job), which run on the workflow_run event
# from the default branch's copy (not on merge_group) and fail closed; the checks below pin that wiring.
mq="$(python3 -I - "$repo" <<'PY'
import glob, json, os, re, sys
import yaml
repo = sys.argv[1]
wf = {os.path.basename(f): yaml.safe_load(open(f)) for f in glob.glob(repo + "/.github/workflows/*.yml")}
def audit(wf):
    out = []
    def res(ok, label): out.append(("ok   " if ok else "FAIL ") + label)

    # REQ-DEP-005-AC3: the review gate in the queue runs from the default branch's copy (workflow_run), reads git
    # objects only, holds the App token only in the agent environment, fails closed
    rg = wf["agent-review-gate.yml"]
    ron = rg.get(True) if True in rg else rg.get("on")
    wr = ron.get("workflow_run") if isinstance(ron, dict) else None
    def is_agent(jb):
        e = jb.get("environment")
        return e == "agent" or (isinstance(e, dict) and e.get("name") == "agent")
    res(isinstance(wr, dict) and wr.get("workflows") == ["CI"],
        "agent-review-gate.yml triggers on workflow_run of the workflow CI (%r)" % (wr,))
    res(isinstance(wr, dict) and wr.get("types") == ["requested"],
        "the workflow_run type is exactly requested: the verdict does not depend on CI's result (%r)" % (wr,))
    res("workflow_run.event" in str(rg.get("concurrency")),
        "the concurrency group names the triggering event, so a pull request's CI run never shares a queue group")
    res(isinstance(ron, dict) and "merge_group" not in ron,
        "agent-review-gate.yml has no merge_group trigger (a queue ref is not the default branch; "
        "no job here runs the group's copy)")
    qj = rg["jobs"].get("queue-judge")
    qp = rg["jobs"].get("queue-publish")
    res(qj is not None, "agent-review-gate.yml has the job queue-judge")
    res(qp is not None, "agent-review-gate.yml has the job queue-publish")
    qj = qj or {}; qp = qp or {}
    MQ_COND = "github.event.workflow_run.event == 'merge_group'"
    res(MQ_COND in str(qj.get("if")),
        "queue-judge runs only if github.event.workflow_run.event == 'merge_group' (%r)" % qj.get("if"))
    res(MQ_COND in str(qp.get("if")) and "!cancelled()" in str(qp.get("if")),
        "queue-publish runs only for a merge_group CI run and not on cancellation (%r)" % qp.get("if"))
    for jn, jb in rg["jobs"].items():
        if is_agent(jb):
            res("queue-gate-judge" not in json.dumps(jb),
                "job %s (environment agent, holds the App token) never runs the queue judge" % jn)
        blob = json.dumps(jb)
        if "create-github-app-token" in blob or "AUDITOR_APP_PRIVATE_KEY" in blob:
            res(is_agent(jb), "job %s mints or reads the App token only inside environment: agent" % jn)
    # the split: queue-judge judges only (no environment, no secret, no token); queue-publish holds the App token
    qjtxt = json.dumps(qj); qptxt = json.dumps(qp)
    qjrun = "\n".join(st.get("run", "") for st in qj.get("steps") or [])   # the scripts as written, quotes unescaped
    qprun = "\n".join(st.get("run", "") for st in qp.get("steps") or [])
    res("environment" not in qj and not is_agent(qj), "queue-judge has no environment (it holds no secret)")
    res(qj.get("permissions") == {"contents": "read", "pull-requests": "read"},
        "queue-judge permissions are contents: read + pull-requests: read only (%r)" % qj.get("permissions"))
    res(wf["ci.yml"].get("permissions") == {"contents": "read"},
        "ci.yml holds contents: read on top and nothing else")
    res("secrets." not in qjtxt and "create-github-app-token" not in qjtxt and "AUDITOR_APP" not in qjtxt
        and "permission-checks" not in qjtxt,
        "queue-judge names no secret and mints no App token")
    res("verdict" in (qj.get("outputs") or {}),
        "queue-judge exports its verdict as a job output (%r)" % (qj.get("outputs"),))
    res(is_agent(qp), "queue-publish is an environment: agent job (it holds the App token; main's copy)")
    res(qp.get("needs") == "queue-judge" or qp.get("needs") == ["queue-judge"],
        "queue-publish needs queue-judge (%r)" % qp.get("needs"))
    res(qp.get("permissions") == {}, "queue-publish has permissions: {} (%r)" % qp.get("permissions"))
    qtok = [st for st in qp.get("steps") or [] if str(st.get("uses", "")).startswith("actions/create-github-app-token")]
    qperms = {k for k in (qtok[0].get("with") or {}) if k.startswith("permission-")} if qtok else set()
    res(len(qtok) == 1 and qperms == {"permission-checks"}
        and (qtok[0].get("with") or {}).get("permission-checks") == "write",
        "queue-publish mints one App token, checks:write only")
    res("actions/checkout" not in qptxt, "queue-publish does not check anything out")
    for st in qp.get("steps") or []:
        nm = st.get("name") or st.get("uses") or st.get("run", "")[:30]
        r = st.get("run") or ""
        # git matched: "git log", "x && git log"; refused: "legit log". An inlined field matched:
        # "${{ github.event.workflow_run.x }}" in a script; refused: "$HEAD_SHA" (an env var)
        res(not re.search(r"(^|[\s;&|(])git\s", r), "queue-publish step %r runs no git" % nm)
        res(not re.search(r"\$\{\{[^}]*workflow_run", r),
            "queue-publish step %r never inlines workflow_run fields into the script (env vars only)" % nm)
    res("github.event.workflow_run.head_sha" in qptxt and "${#HEAD_SHA}" in qprun,
        "queue-publish takes the head from workflow_run.head_sha and validates it as 40 lowercase hex")
    res("needs.queue-judge.outputs.verdict" in qptxt and '[ "$VERDICT" = "success" ]' in qprun,
        "queue-publish reads the verdict from needs.queue-judge.outputs.verdict")
    res("auditor-review-gate" in qptxt and "check-runs" in qptxt,
        "queue-publish publishes the auditor-review-gate check run on that head")
    for st in qj.get("steps") or []:
        w = st.get("with") or {}
        nm = st.get("name") or st.get("uses") or st.get("run", "")[:30]
        if str(st.get("uses", "")).startswith("actions/checkout"):
            res("workflow_run" not in json.dumps({k: w[k] for k in ("ref", "path", "repository") if k in w}),
                "queue-judge step %r checks out the default branch only (no ref, path or repository "
                "from workflow_run)" % nm)
        r = st.get("run") or ""
        # matched: "git checkout x", "git  worktree add"; refused: "git fetch"
        res(not re.search(r"git\s+(checkout|switch|worktree)\b", r),
            "queue-judge step %r checks nothing of the group out" % nm)
        res(not re.search(r"\$\{\{[^}]*workflow_run", r),
            "queue-judge step %r never inlines workflow_run fields into the script (env vars only)" % nm)
    called = qjrun.split("queue-gate-judge.sh")[1][:30] if "queue-gate-judge.sh" in qjrun else ""
    res('"$HEAD_SHA" "$HEAD_BRANCH"' in called,
        "queue-judge runs main's agent/bin/queue-gate-judge.sh with the head sha and the queue ref")
    res("gh-readonly-queue/main/" in qjrun and "fail the job when" not in qjtxt and '[ "$verdict" = success ]' in qjrun,
        "queue-judge checks the ref's prefix, and its judge step itself fails unless the verdict is success")
    res("github.event.workflow_run.head_sha" in qjtxt, "queue-judge takes the queue head from workflow_run.head_sha")
    # pin-age refuses an env var named *_BASE, *_BASE_URL or *_URL whose value is an expression (a "download source"):
    # the new and changed queue steps use other names (RUN_LINK, QUEUE_BASE_SHA)
    SRC = re.compile(r"^[A-Z][A-Z0-9_]*_(BASE_URL|BASE|URL)$")
    def src_envs(job):
        bad = []
        for e in [job.get("env") or {}] + [st.get("env") or {} for st in job.get("steps") or []]:
            bad += [k for k, v in e.items() if SRC.match(k) and "${{" in str(v)]
        return bad
    for nm, jb in (("queue-judge", qj), ("queue-publish", qp),
                   ("supply-chain.yml pin-age", wf["supply-chain.yml"]["jobs"]["pin-age"])):
        res(src_envs(jb) == [],
            "%s: no env var named like *_BASE, *_BASE_URL or *_URL takes an expression (%s)" % (nm, src_envs(jb)))
    res(src_envs({"env": {"X_URL": "${{ a }}"}}) == ["X_URL"] and src_envs({"env": {"RUN_LINK": "${{ a }}"}}) == [],
        "the download-source name check fires on a *_URL expression and not on RUN_LINK")
    res("RUN_URL" not in qjtxt and "RUN_URL" not in qptxt, "the queue jobs name their run link RUN_LINK, not RUN_URL")

    # the sweep judges pull requests only: a queue ref is never proved to come from the queue, so it is not read
    sws = "\n".join(st.get("run", "") for st in rg["jobs"]["sweep"]["steps"])
    LS = "git ls-remote \"https://github.com/${GITHUB_REPOSITORY}\" 'refs/heads/gh-readonly-queue/*'"
    res("gh-readonly-queue" not in sws.replace(LS, "") and "queue-gate-judge" not in sws and sws.count(LS) == 1,
        "the sweep neither reads queue refs nor runs the queue judge; its one git ls-remote only names the branches")
    posts = sws.count("-f name=auditor-review-gate")
    looks = sws.count("check_name=auditor-review-gate")
    res(posts >= 1 and looks >= posts,
        "every post of the check in the sweep follows a lookup of the App's existing verdict on that head "
        "(%d posts, %d lookups)" % (posts, looks))
    # matched: "success) continue ;;"; refused: "failure) continue"
    res(re.search(r"success\)\s*continue", sws) is not None,
        "a head that already has a success verdict is skipped (no second post)")
    res("still failure" in sws, "a head that still fails is not re-posted")
    return out

out = audit(wf)

# every check above must be able to fail: each mutant is a real workflow with one defect the seats named
import copy
def mutant(label, change):
    m = copy.deepcopy(wf)
    change(m)
    caught = [l for l in audit(m) if l.startswith("FAIL")]
    out.append(("ok   " if caught else "FAIL ") + "mutant caught: " + label)
def set_if(f, j, cond): wf_[f]["jobs"][j]["if"] = cond
def add_step_if(f, j, cond): wf_[f]["jobs"][j]["steps"][-1]["if"] = cond
def add_filter(f): m_on(wf_[f])["merge_group"] = {"branches": ["main"]}
def m_on(d): return d[True] if True in d else d["on"]
def edit_run(f, j, old, new):
    for st in wf_[f]["jobs"][j]["steps"]:
        if old in st.get("run", ""): st["run"] = st["run"].replace(old, new)
wf_ = None
def run_mutant(label, fn):
    global wf_
    def change(m):
        global wf_
        wf_ = m; fn()
    mutant(label, change)
run_mutant("the gate also triggered by completed", lambda: m_on(wf_["agent-review-gate.yml"])["workflow_run"].update(
    types=["requested", "completed"]))
run_mutant("the sweep reading queue refs again", lambda: edit_run(
    "agent-review-gate.yml", "sweep", "exit \"$fail\"", "echo gh-readonly-queue; exit \"$fail\""))
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
echo "----"
echo "required-check-guard: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
