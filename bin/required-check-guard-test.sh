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
steps = wf["jobs"]["drift-fixer-dispatch"]["steps"]
run = [s["run"] for s in steps if s.get("name", "").startswith("open or update the `required-check drift` issue")]
assert len(run) == 1, "drift-issue step not found"
guard = wf["jobs"]["required-check-guard"]
# the job that runs a pull request's or a queue group's scripts holds no issue write and exports nothing
assert guard["permissions"] == {"contents": "read"} and "outputs" not in guard, "the guard job holds more than read"
disp = wf["jobs"]["drift-fixer-dispatch"]
assert "push" in disp["if"] and "refs/heads/main" in disp["if"], "the issue write is not push-to-main only"
assert disp["permissions"] == {"contents": "read", "issues": "write"}, "the dispatch job's permissions changed"
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

# REQ-DEP-005 (merge queue, owner ratified Oct 22): every required context runs on the merge_group event on the
# queue's commit, and none of its jobs or steps is skipped there.
# The table names, for each context in .github/policy/required-checks.json, the workflow and job that produces it;
# a context the table does not know fails, so a required check added later cannot be missed. The one listed exception
# is marker-gate (REQ-DEP-005-AC1; ops/docs/ratify/2026-10-22-merge-queue-checks.md, owner: "add the landing marker
# check as the second listed exception"): it is a pull-request-only check, so it carries a job-level `if` and reports
# skipped, which GitHub counts as success, on the queue. The review gate's check (REQ-DEP-005-AC3) is not excepted: the
# App publishes it on the queue's head from agent-review-gate.yml's `queue-publish` job (after the secret-free
# `queue-judge` job), which run on the workflow_run event from the default branch's copy (not on merge_group) and fails
# closed; the dedicated checks below pin that wiring.
mq="$(python3 -I - "$repo" <<'PY'
import glob, json, os, re, sys
import yaml
repo = sys.argv[1]
wf = {os.path.basename(f): yaml.safe_load(open(f)) for f in glob.glob(repo + "/.github/workflows/*.yml")}
def audit(wf):
    req = [c["context"] for c in json.load(open(repo + "/.github/policy/required-checks.json"))["required_checks"]]
    TABLE = {"analyze (go)": ("codeql.yml", "analyze"), "acceptance-gradle": ("acceptance.yml", "acceptance-gradle"),
             "acceptance-maven (1.2.0)": ("acceptance.yml", "acceptance-maven"),
             "acceptance-maven (1.2.3)": ("acceptance.yml", "acceptance-maven"),
             "reproducibility": ("scan.yml", "reproducibility"), "scan": ("scan.yml", "scan"),
             "pin-age": ("supply-chain.yml", "pin-age")}
    TABLE["auditor-review-gate"] = ("agent-review-gate.yml", "queue-publish")
    # a required context that is the name or the key of a job in ci.yml maps to that job; none is listed by hand
    for jk, jb in (wf["ci.yml"].get("jobs") or {}).items():
        for c in {jk, (jb or {}).get("name")} - {None, "marker-gate"}:
            TABLE.setdefault(c, ("ci.yml", jk))
    EXCEPT = {"marker-gate"}
    out = []
    def res(ok, label): out.append(("ok   " if ok else "FAIL ") + label)
    def unknown_of(contexts): return sorted(set(contexts) - set(TABLE) - EXCEPT)
    unknown = unknown_of(req)
    res(unknown_of(req + ["made-up-context"]) == ["made-up-context"] and "made-up-context" not in TABLE,
        "a required context found neither in the table nor as a ci.yml job is reported unknown (fixture)")
    res(set(req) - set(TABLE) == EXCEPT,
        "every required context is known to the merge-queue table (unknown: %s)" % unknown)
    res(EXCEPT == {"marker-gate"} and "auditor-review-gate" in TABLE and "auditor-review-gate" in req,
        "the one merge-queue exception is marker-gate (pull requests only); the review gate's check has a table row")
    def has_event(d, name):
        on = d.get(True) if True in d else d.get("on")
        return (isinstance(on, dict) and name in on) or on == name or (isinstance(on, list) and name in on)
    # REQ-DEP-005-AC1 as written: no required job, step or prerequisite is skipped on the queue. A condition is not
    # judged by its text. Every `if` on a required job, on its steps and on the jobs it needs must be one of these exact
    # strings at that exact place; a new or edited condition fails here until this table is changed in review.
    ALLOWED_IF = {   # (workflow, job, step name or None for the job itself): the exact condition
        ("acceptance.yml", "acceptance-gradle", "stop the capped server"): "always()",
        ("acceptance.yml", "acceptance-gradle", "stop fscache"): "always()",
        ("acceptance.yml", "acceptance-maven", "stop the capped server"): "always()",
        ("acceptance.yml", "acceptance-maven", "stop fscache"): "always()",
        ("agent-review-gate.yml", "queue-judge", None):
            "github.event_name == 'workflow_run' && github.event.workflow_run.event == 'merge_group'",
        ("agent-review-gate.yml", "queue-publish", None):
            "${{ !cancelled() && github.event_name == 'workflow_run' "
            "&& github.event.workflow_run.event == 'merge_group' }}",
        ("ci.yml", "allowlist-chain", None): "${{ always() }}",
        ("ci.yml", "allowlist-chain-4", "suite floors only rise (against the merge base on a pull request)"):
            "${{ github.base_ref != '' || github.event.merge_group.base_ref != '' }}",
        ("ci.yml", "dependency-review", None):
            "${{ github.event_name == 'pull_request' || github.event_name == 'merge_group' }}",
        ("ci.yml", "dependency-review", "the merge queue's base and head are named (REQ-DEP-005-AC2)"):
            "github.event_name == 'merge_group'",
        ("ci.yml", "gosec", "upload SARIF"): "always() && github.event.pull_request.head.repo.fork != true",
        ("scan.yml", "inspector", "Amazon Inspector - restore today's results (same-repo runs only)"):
            "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository",
        ("scan.yml", "inspector", "Amazon Inspector - the UTC day at save time"): "always()",
        ("scan.yml", "inspector",
         "Amazon Inspector - save today's new results (only when this run made some; same-repo runs only)"):
            "always() && steps.insp-scan.outputs.fresh != '' && steps.insp-scan.outputs.fresh != '0' && "
            "(github.event_name != 'pull_request' "
            "|| github.event.pull_request.head.repo.full_name == github.repository)",
        ("scan.yml", "inspector", "keep the Inspector SBOMs and responses"): "always()",
        ("scan.yml", "reproducibility", None): "always()",
        ("scan.yml", "scan", None): "always()",
        ("scan.yml", "scanner", "refuse a scanner this job cannot run"): "matrix.scanner != 'grype'",
        ("scan.yml", "scanner", "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"):
            "matrix.scanner == 'grype'",
        ("scan.yml", "scanner", "verify archives before scanning them"): "matrix.scanner == 'grype'",
        ("scan.yml", "scanner", "Grype scan every image tar and every archive"): "matrix.scanner == 'grype'",
        ("supply-chain.yml", "pin-age", "Trusted checker (the base branch)"):
            "github.event_name == 'pull_request' || github.event_name == 'merge_group'",
        ("supply-chain.yml", "pin-age", "The pull request's tree"):
            "github.event_name == 'pull_request' || github.event_name == 'merge_group'",
        ("supply-chain.yml", "pin-age", "Age of every moved version, and what advisories say about it"):
            "github.event_name == 'pull_request' || github.event_name == 'merge_group'",
    }
    def closure(f, j, acc):
        if (f, j) in acc: return
        acc.add((f, j))
        need = ((wf.get(f) or {}).get("jobs", {}).get(j) or {}).get("needs") or []
        for n in [need] if isinstance(need, str) else need: closure(f, n, acc)
    jobs = set()
    for c in req:
        if c in TABLE and c not in EXCEPT: closure(*TABLE[c], jobs)
    found = {}
    for f, j in jobs:
        jb = wf[f]["jobs"][j]
        if "if" in jb: found[(f, j, None)] = jb["if"]
        for st in jb.get("steps") or []:
            if "if" in st: found[(f, j, st.get("name") or st.get("uses") or st.get("run", "")[:30])] = st["if"]
    odd = sorted(str(k) + " = " + repr(v) for k, v in found.items() if ALLOWED_IF.get(k) != v)
    res(not odd, "every condition on a required job, its steps and its prerequisites is an allowed one (%s)" % odd[:2])
    res(set(ALLOWED_IF) <= set(found), "every allowed condition still exists (the table is not stale): %s"
        % sorted(str(k) for k in set(ALLOWED_IF) - set(found))[:2])
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
        for st in job.get("steps") or []:
            blob = json.dumps(st)
            res("github.event.pull_request" not in blob or "github.event.merge_group" in blob
                or "pull_request.head.repo.fork" in blob or "pull_request.head.repo.full_name" in blob,
                "%s: step %r reads the pull request only where the queue's commits are read too"
                % (c, st.get("name") or st.get("uses") or st.get("run", "")[:30]))
            res("github.base_ref" not in blob or "merge_group.base_ref" in blob,
                "%s: step %r names the queue's base wherever it names the pull request's base"
                % (c, st.get("name") or st.get("uses") or st.get("run", "")[:30]))
    # pin age and dependency review read the queue's two commits and refuse an empty one
    sc = json.dumps(wf["supply-chain.yml"]["jobs"]["pin-age"])
    dr = json.dumps(wf["ci.yml"]["jobs"]["dependency-review"])
    res("merge_group.base_sha" in sc and "merge_group.head_sha" in sc,
        "pin-age reads the queue's base_sha and head_sha")
    res("merge_group.base_sha" in dr and "merge_group.head_sha" in dr,
        "dependency-review reads the queue's base_sha and head_sha")
    pa_run = "\n".join(st.get("run", "") for st in wf["supply-chain.yml"]["jobs"]["pin-age"]["steps"])
    dr_run = "\n".join(st.get("run", "") for st in wf["ci.yml"]["jobs"]["dependency-review"]["steps"])
    res('"${BASE_SHA:?' in pa_run and '"${HEAD_SHA:?' in pa_run and "|| true" not in pa_run,
        "pin-age: an empty base or head ends the step with an error (${VAR:?...}), and nothing swallows it")
    # matched: [ -n "$QUEUE_BASE_SHA" ] && [ -n "$QUEUE_HEAD" ] || { echo x; exit 1; }   refused: the same ending exit 0
    res(re.search(r'\[ -n "\$QUEUE_BASE_SHA" \] && \[ -n "\$QUEUE_HEAD" \] \|\| \{[^}]*exit 1', dr_run) is not None
        and "|| true" not in dr_run,
        "dependency-review: an empty base or head exits 1, and nothing swallows it")

    # REQ-DEP-005-AC1: marker-gate is pull-request-only by a job-level condition; ci.yml's triggers carry no filter (a
    # filtered workflow leaves the required check Pending and blocks the queue)
    ci_wf = wf["ci.yml"]
    mg = ci_wf["jobs"].get("marker-gate") or {}
    res(mg.get("if") == "github.event_name == 'pull_request'",
        "marker-gate's job-level if is exactly github.event_name == 'pull_request' (%r)" % mg.get("if"))
    FILTERS = {"paths", "paths-ignore", "branches", "branches-ignore", "tags", "tags-ignore"}
    for fname in ("ci.yml", "codeql.yml", "acceptance.yml", "scan.yml", "supply-chain.yml"):
        con = wf[fname].get(True) if True in wf[fname] else wf[fname].get("on")
        for ev in ("pull_request", "merge_group"):
            if not isinstance(con, dict) or (fname != "ci.yml" and ev not in con): continue
            v = con.get(ev)
            res(ev in con and not (isinstance(v, dict) and set(v) & FILTERS),
                "%s %s trigger exists and has no paths, branches or tags filter (%r)" % (fname, ev, v))

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
    res(wf["ci.yml"]["jobs"]["allowlist"].get("permissions") == {"contents": "read", "pull-requests": "read"},
        "the allowlist job holds contents: read + pull-requests: read only")
    res(wf["ci.yml"]["jobs"]["dependency-review"].get("permissions") == {"contents": "read"},
        "dependency-review holds contents: read only (no pull-requests: write)")
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
    al = {st.get("name", ""): st for st in wf["ci.yml"]["jobs"]["allowlist"]["steps"]}
    alc = al.get("check every tracked file against the allowlist") or {}
    res((alc.get("env") or {}).get("GITHUB_QUEUE_REF") == "${{ github.event.merge_group.head_ref }}"
        and (alc.get("env") or {}).get("GH_TOKEN") == "${{ github.token }}",
        "the allowlist job gives its check the queue ref and the job's own read token (the pull request lookup)")
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
                   ("ci.yml dependency-review", wf["ci.yml"]["jobs"]["dependency-review"]),
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
run_mutant("a required job with if: false", lambda: set_if("codeql.yml", "analyze", False))
run_mutant("a merge_group branch filter in a workflow other than ci.yml", lambda: add_filter("acceptance.yml"))
run_mutant("a step condition on the pull request's head repository", lambda: add_step_if(
    "scan.yml", "reproducibility", "github.event.pull_request.head.repo.full_name == github.repository"))
run_mutant("a required job that runs on the main branch only", lambda: set_if(
    "codeql.yml", "analyze", "github.ref == 'refs/heads/main'"))
run_mutant("a required job skipped by a false term", lambda: set_if(
    "codeql.yml", "analyze", "false && github.event_name == 'merge_group'"))
run_mutant("a prerequisite shard that runs on the main branch only", lambda: set_if(
    "ci.yml", "allowlist-chain-1", "github.ref == 'refs/heads/main'"))
run_mutant("marker-gate that skips pull requests instead of the queue", lambda: set_if(
    "ci.yml", "marker-gate", "github.event_name != 'pull_request'"))
run_mutant("pin-age with the empty-head refusal removed", lambda: edit_run(
    "supply-chain.yml", "pin-age", "${HEAD_SHA:?no head commit to compare: this check fails}", "${HEAD_SHA:-}"))
run_mutant("dependency-review whose empty-input refusal exits 0", lambda: edit_run(
    "ci.yml", "dependency-review", "exit 1; }", "exit 0; }"))
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
