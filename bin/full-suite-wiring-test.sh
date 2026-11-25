#!/usr/bin/env bash
# proves: REQ-CI-007-AC2, REQ-CI-007-AC3, REQ-CI-007-AC4, REQ-REL-013-AC6
# The full suite at promotion (REQ-CI-007; owner, Nov 10 2026), offline. Reads the real workflows and the policy files as data and judges each
# against the English; every judge is also run over mutated copies, each of which must be caught:
#   AC5  full-suite.yml: a daily schedule and workflow_dispatch only; suite-list, suites and allowlist-chain run the tracked suites that no
#        step of ci.yml runs, ci.yml holds none of the three; acceptance.yml is called once, from source, and by nothing else
#   AC6  full-suite.yml, scan.yml and codeql.yml end with a report-failure job for a failed scheduled run; its script is run here with a stand-in
#        for gh: it opens one issue with a fixed title and label, or comments on the open one, naming the run
#   AC7  full-suite.yml, scan.yml and codeql.yml each can run before the tag, from a schedule or a dispatch; full-suite.yml has no push
#        and no pull_request trigger
#   REL-013-AC6  no job holds actions: write, and release.yml starts no run of the full suite
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -I - "$root" "$work" <<'PY'
import copy, json, os, re, subprocess, sys, tempfile, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
def load(p): return yaml.load(open(os.path.join(root, p)), Loader=yaml.BaseLoader)
WF = ".github/workflows/"
ALL = {fn: load(WF + fn) for fn in sorted(os.listdir(os.path.join(root, WF))) if fn.endswith(".yml")}
ci, fs = ALL["ci.yml"], ALL["full-suite.yml"]
def mutated(doc, fn):
    d = copy.deepcopy(doc); fn(d); return d
def verdict(name, problems, want_ok):
    check(name, (problems == []) == want_ok, problems)

def mutated(doc, fn):
    d = copy.deepcopy(doc); fn(d); return d
def verdict(name, problems, want_ok):
    check(name, (problems == []) == want_ok, problems)
def mutants(label, judge, doc, cases):
    """each case: (name, fn): the mutated copy must have at least one problem"""
    for name, fn in cases:
        try: m = mutated(doc, fn)
        except Exception as e:
            check("%s: a copy with %s can be made (the thing to mutate exists)" % (label, name), False, repr(e)); continue
        try: probs = judge(m)
        except Exception as e: probs = ["judge raised %r" % e]
        check("%s: a copy with %s is refused" % (label, name), probs != [], "accepted")
        if os.environ.get("WIRING_SHOW"): print("      why:", str(probs[:2])[:260])


def runs(job): return [(s, s.get("run") or "") for s in job.get("steps") or []]
def run_step(step, extra_env, ctx, cwd, job=None):
    """run a step's script the way the runner does: bash -e (bash --noprofile --norc -eo pipefail when it sets shell: bash), expressions resolved"""
    def subst(t):
        def one(m):
            for alt in m.group(1).split("||"):
                v = ctx.get(alt.strip())
                if v: return v
            return ""
        return re.sub(r"\$\{\{\s*(.*?)\s*\}\}", one, t)
    env = dict(os.environ, **extra_env)
    for src in ((job or {}).get("env") or {}, step.get("env") or {}):
        for k, v in src.items(): env[k] = subst(str(v))
    shell = step.get("shell") or (job or {}).get("defaults", {}).get("run", {}).get("shell") or ""
    cmd = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c"] if shell.startswith("bash") else ["bash", "-e", "-c"]
    return subprocess.run(cmd + [subst(step.get("run") or "")], capture_output=True, text=True, env=env, cwd=cwd)
def mkexec(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(text); os.chmod(path, 0o755)

# ------------------------------------------------------------------------------------------------------------------ AC5: full-suite.yml
MOVED = ("suite-list", "suites", "allowlist-chain")
def full_problems(w, c, acc):
    bad = []; on = w.get("on") or {}
    if not isinstance(on, dict) or sorted(on) != ["schedule", "workflow_dispatch"]:
        bad.append("triggers are not exactly schedule and workflow_dispatch: %s" % (list(on) if isinstance(on, dict) else on))
    else:
        sch = on["schedule"]
        if not (isinstance(sch, list) and len(sch) == 1 and re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", str(sch[0].get("cron", "")).strip())):
            bad.append("the schedule is not one daily cron (minute hour * * *): %s" % sch)
    jobs = w.get("jobs") or {}
    for jid in MOVED:
        if jid not in jobs: bad.append("full-suite.yml has no job %s" % jid)
        elif jobs[jid].get("name") != jid and jid != "suites": bad.append("job %s is not named %s" % (jid, jid))
        if jid in (c.get("jobs") or {}): bad.append("ci.yml still has the job %s" % jid)
    j = jobs.get("suites") or {}
    if j.get("needs") != "suite-list" or "fromJSON(needs.suite-list.outputs.suites)" not in str((j.get("strategy") or {}).get("matrix")).replace(" ", ""):
        bad.append("suites is not the matrix of suite-list's output")
    if (jobs.get("allowlist-chain") or {}).get("needs") != ["suites"]: bad.append("allowlist-chain does not need the suites alone")
    if any("pull_request" in str(j.get("if", "")) for j in jobs.values()): bad.append("a job of full-suite.yml has a condition on pull_request, an event it never runs on")
    calls = [jid for jid, j in jobs.items() if j.get("uses") == "./.github/workflows/acceptance.yml"]
    if calls != ["acceptance"] or jobs["acceptance"].get("name", "acceptance") != "acceptance" or jobs["acceptance"].get("with"):
        bad.append("acceptance.yml is not called once, from source, by the job acceptance: %s" % calls)
    aon = acc.get("on") or {}
    if list(aon) != ["workflow_call"]: bad.append("acceptance.yml is not callable alone: %s" % list(aon))
    for jid, j in jobs.items():
        other = str(j.get("uses", "")).endswith(("scan.yml", "codeql.yml", "release.yml"))
        if other: bad.append("%s calls another workflow's file" % jid)
    return bad
verdict("full-suite.yml: a daily schedule and dispatch; the three suite jobs moved out of ci.yml; acceptance called once from source",
        full_problems(fs, ci, ALL["acceptance.yml"]), True)
def full_mutants(label, make):
    ok = True
    for name, fn in make:
        d = copy.deepcopy({"fs": fs, "ci": ci, "acc": ALL["acceptance.yml"]}); fn(d)
        check("%s: a copy with %s is refused" % (label, name), full_problems(d["fs"], d["ci"], d["acc"]) != [], "accepted")
full_mutants("full-suite.yml", [
    ("a push trigger", lambda d: d["fs"]["on"].__setitem__("push", {"branches": ["main"]})),
    ("a pull_request trigger", lambda d: d["fs"]["on"].__setitem__("pull_request", "")),
    ("workflow_call added", lambda d: d["fs"]["on"].__setitem__("workflow_call", "")),
    ("no schedule", lambda d: d["fs"]["on"].pop("schedule")),
    ("two schedules", lambda d: d["fs"]["on"].__setitem__("schedule", [{"cron": "1 2 * * *"}, {"cron": "3 4 * * *"}])),
    ("suite-list gone", lambda d: d["fs"]["jobs"].pop("suite-list")),
    ("suites gone", lambda d: d["fs"]["jobs"].pop("suites")),
    ("allowlist-chain renamed", lambda d: d["fs"]["jobs"]["allowlist-chain"].__setitem__("name", "chain")),
    ("allowlist-chain needing nothing", lambda d: d["fs"]["jobs"]["allowlist-chain"].pop("needs")),
    ("the suites matrix cut loose from the list", lambda d: d["fs"]["jobs"]["suites"]["strategy"].__setitem__("matrix", {"suite": ["a-test.sh"]})),
    ("suite-list back in ci.yml", lambda d: d["ci"]["jobs"].__setitem__("suite-list", d["fs"]["jobs"]["suite-list"])),
    ("allowlist-chain back in ci.yml", lambda d: d["ci"]["jobs"].__setitem__("allowlist-chain", d["fs"]["jobs"]["allowlist-chain"])),
    ("a condition on pull_request", lambda d: d["fs"]["jobs"]["suites"].__setitem__("if", "github.event_name != 'pull_request'")),
    ("no call of acceptance.yml", lambda d: d["fs"]["jobs"].pop("acceptance")),
    ("acceptance renamed", lambda d: d["fs"]["jobs"]["acceptance"].__setitem__("name", "accept")),
    ("acceptance called with an input", lambda d: d["fs"]["jobs"]["acceptance"].__setitem__("with", {"image-ref": "x"})),
    ("acceptance.yml with a push trigger", lambda d: d["acc"]["on"].__setitem__("push", {"branches": ["main"]})),
    ("acceptance.yml without workflow_call", lambda d: d["acc"].__setitem__("on", {"workflow_dispatch": ""})),
    ("the scan called from full-suite.yml", lambda d: d["fs"]["jobs"].__setitem__("scan", {"uses": "./.github/workflows/scan.yml"})),
])

# no check name the full suite makes (its gate and the acceptance jobs it calls) is also made by another workflow file
def job_names(w, wfs):
    """the contexts a workflow's jobs report: a called workflow's job as "<calling job> / <job>", a matrix job per value of its first axis"""
    out = set()
    for jid, j in (w.get("jobs") or {}).items():
        called = j.get("uses", "")
        inner = wfs.get(os.path.basename(called)) if called.startswith("./") else None
        pairs = [(j.get("name") or jid, k, i) for i, k in enumerate((inner or {}).get("jobs", {}).values())] if inner else [("", j, 0)]
        for prefix, k, _ in pairs:
            name = (prefix + " / " if prefix else "") + (k.get("name") or jid)
            values = next(iter(((k.get("strategy") or {}).get("matrix") or {}).values()), [])
            out.update([re.sub(r"\$\{\{.*?\}\}", "*", name)] if "${{" in name else [name])
    return out
def full_suite_name(n): return n == "allowlist-chain" or n.startswith("acceptance / ")
def two_makers(wfs):
    mine = {n for n in job_names(wfs["full-suite.yml"], wfs) if full_suite_name(n)}
    made_in_two = [n for f, w in wfs.items() if f != "full-suite.yml" for n in job_names(w, wfs) if n in mine]
    return ["a full-suite.yml job name is also made by another workflow: %s" % made_in_two] if made_in_two else []
verdict("no name made in two files", two_makers(ALL), True)
w_ = copy.deepcopy(ALL)
w_["ci.yml"]["jobs"]["allowlist-chain"] = {"name": "allowlist-chain", "runs-on": "x", "steps": []}
check("a copy with a name made by full-suite.yml and ci.yml is refused", two_makers(w_) != [], "accepted")

# ------------------------------------------------------------------------------------------------------------------ AC6: report-failure
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
a = sys.argv[1:]
rec = open(os.environ["REC"], "a")
def flags(*names):
    out = []
    for i, x in enumerate(a):
        for n in names:
            if x == n and i + 1 < len(a): out.append(a[i + 1])
            elif x.startswith(n + "=") and n.startswith("--"): out.append(x.split("=", 1)[1])
    return out
def body():
    b = flags("--body", "-b"); f = flags("--body-file", "-F")
    if b: return b[0]
    if f: return sys.stdin.read() if f[0] == "-" else open(f[0]).read()
    return ""
openi = os.environ.get("OPEN") == "1"
issue = {"number": 42, "title": os.environ.get("ISSUE_TITLE", ""), "state": "OPEN", "url": "https://github.com/o/r/issues/42",
         "labels": [{"name": os.environ.get("ISSUE_LABEL", "")}], "body": "old"}
def emit(data, filt):
    if filt:
        r = subprocess.run(["jq", "-r", filt[0]], input=json.dumps(data), capture_output=True, text=True)
        sys.stdout.write(r.stdout); sys.exit(r.returncode)
    print(json.dumps(data))
sub = " ".join(a[:2])
if sub == "issue list":
    data = [issue] if openi else []
    if flags("--json") or flags("--jq", "-q"): emit(data, flags("--jq", "-q"))
    else:
        for i in data: print("%d\tOPEN\t%s\t%s\t2026" % (i["number"], i["title"], i["labels"][0]["name"]))
elif sub == "issue create":
    rec.write(json.dumps({"op": "create", "title": (flags("--title", "-t") or [""])[0], "labels": flags("--label", "-l"), "body": body()}) + "\n")
    print("https://github.com/o/r/issues/43")
elif sub == "issue comment":
    rec.write(json.dumps({"op": "comment", "number": a[2], "body": body()}) + "\n")
    print("https://github.com/o/r/issues/42#c1")
elif sub == "issue view": emit(issue, flags("--jq", "-q"))
elif sub in ("label create", "label list", "issue edit", "issue reopen"): pass
elif a[0] == "api":
    path = a[1]
    if "issues" in path and "-X" not in a and "--method" not in a and not flags("-f", "-F", "--field", "--raw-field"):
        emit([issue] if openi else [], flags("--jq", "-q"))
    elif "comments" in path or "issues" in path:
        rec.write(json.dumps({"op": "comment" if "comments" in path else "create", "number": path, "title": (flags("-f", "-F") or [""])[0], "labels": [], "body": " ".join(flags("-f", "-F", "--field", "--raw-field"))}) + "\n")
    else: pass
else:
    rec.write(json.dumps({"op": "unsupported", "args": a}) + "\n"); sys.exit(0)
'''
def failure_problems(w, wfname):
    bad = []
    jobs = w.get("jobs") or {}
    j = jobs.get("report-failure")
    if j is None: return ["%s has no report-failure job" % wfname]
    others = sorted(k for k in jobs if k != "report-failure")
    needs = j.get("needs"); needs = [needs] if isinstance(needs, str) else (needs or [])
    if sorted(needs) != others: bad.append("report-failure does not need every other job: needs %s, jobs %s" % (sorted(needs), others))
    cond = re.sub(r"\s+", "", str(j.get("if", "")))
    cond = re.sub(r"^\$\{\{(.*)\}\}$", r"\1", cond)
    if cond not in ("failure()&&github.event_name=='schedule'", "github.event_name=='schedule'&&failure()"):
        bad.append("report-failure's condition is not failure() on the schedule event: %r" % j.get("if"))
    perms = j.get("permissions") or {}
    if perms.get("issues") != "write" or any(v == "write" for k, v in perms.items() if k != "issues"):
        bad.append("report-failure's permissions are not issues: write and nothing else writable: %s" % perms)
    if bad or not any(s.get("run") for s in j.get("steps") or []): return bad or ["report-failure has no script"]
    ctx = {"github.run_id": "987654", "github.run_attempt": "1", "github.run_number": "12", "github.server_url": "https://github.com",
           "github.repository": "o/r", "github.sha": "a" * 40, "github.workflow": wfname, "github.event_name": "schedule", "github.token": "tok",
           "github.ref_name": "main", "github.ref": "refs/heads/main", "github.job": "report-failure"}
    envs = {"GITHUB_RUN_ID": "987654", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_NUMBER": "12", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
            "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW": wfname, "GITHUB_EVENT_NAME": "schedule", "GH_TOKEN": "tok", "GITHUB_REF_NAME": "main"}
    def scenario(tag, open_, run_id="987654", title="", label=""):
        d = os.path.join(work, "gh-%s-%s" % (wfname.replace(".", "_"), tag)); os.makedirs(d + "/fake"); os.makedirs(d + "/cwd")
        mkexec(d + "/fake/gh", FAKE_GH); rec = d + "/rec"; open(rec, "w").close()
        for n in ("bin", ".github"): os.symlink(os.path.join(root, n), d + "/cwd/" + n)
        e = dict(envs, GITHUB_RUN_ID=run_id, REC=rec, OPEN="1" if open_ else "", ISSUE_TITLE=title, ISSUE_LABEL=label, PATH=d + "/fake:" + os.environ["PATH"], RUNNER_TEMP=d)
        c = dict(ctx, **{"github.run_id": run_id})
        rcs = []
        for s in j["steps"]:
            if not s.get("run"): continue
            r = run_step(s, e, c, d + "/cwd", j); rcs.append(r)
            if r.returncode != 0: break
        ops = [json.loads(l) for l in open(rec).read().splitlines() if l]
        return rcs, ops
    rcs, ops = scenario("new", False)
    if any(r.returncode for r in rcs): return bad + ["the report script fails with no issue open: %s" % rcs[-1].stderr[-300:]]
    creates = [o for o in ops if o["op"] == "create"]
    if len(creates) != 1 or [o for o in ops if o["op"] != "create"]:
        return bad + ["with no open issue it must open exactly one issue and do nothing else: %s" % ops]
    c = creates[0]
    if not c["title"].strip() or "987654" in c["title"] or not c["labels"] or not all(x.strip() for x in c["labels"]):
        bad.append("the issue has no fixed title and label: %s" % {k: c[k] for k in ("title", "labels")})
    if "987654" not in c["body"] and "/actions/runs/987654" not in c["body"]: bad.append("the issue does not name the run: %r" % c["body"])
    rcs, ops2 = scenario("new2", False, run_id="555111")
    c2 = [o for o in ops2 if o["op"] == "create"]
    if len(c2) != 1 or c2[0]["title"] != c["title"] or c2[0]["labels"] != c["labels"]: bad.append("the title and label change from run to run: %s vs %s" % (c["title"], [o.get("title") for o in ops2]))
    if c2 and "555111" not in c2[0]["body"]: bad.append("the second run's issue does not name its own run")
    rcs, ops3 = scenario("open", True, run_id="777222", title=c["title"], label=c["labels"][0])
    if any(r.returncode for r in rcs): bad.append("the report script fails with an issue open: %s" % rcs[-1].stderr[-300:])
    if [o for o in ops3 if o["op"] == "create"]: bad.append("an open issue exists but a second one was opened")
    cm = [o for o in ops3 if o["op"] == "comment"]
    if len(cm) != 1 or "777222" not in cm[0]["body"]: bad.append("with an open issue it must comment once, naming the run: %s" % ops3)
    return bad
WFS = {n: ALL[n] for n in ("full-suite.yml", "scan.yml", "codeql.yml")}
for n in ("full-suite.yml", "scan.yml", "codeql.yml"):
    if n not in WFS: check("%s: a failed scheduled run reports to an issue" % n, False, "no such workflow"); continue
    verdict("%s: report-failure needs every job, runs on a failed scheduled run, opens or comments on one fixed issue naming the run" % n, failure_problems(WFS[n], n), True)
    w = WFS[n]
    rf = lambda d: d["jobs"]["report-failure"]
    mutants(n, lambda d, n=n: failure_problems(d, n), w, [
        ("no report-failure job", lambda d: d["jobs"].pop("report-failure", None)),
        ("it not needing one job", lambda d: rf(d).__setitem__("needs", [x for x in (rf(d)["needs"] if isinstance(rf(d)["needs"], list) else [rf(d)["needs"]])][:-1])),
        ("it running on every ending", lambda d: rf(d).__setitem__("if", "${{ always() && github.event_name == 'schedule' }}")),
        ("it running on a failed push too", lambda d: rf(d).__setitem__("if", "${{ failure() }}")),
        ("it running on a green schedule", lambda d: rf(d).__setitem__("if", "${{ github.event_name == 'schedule' }}")),
        ("it on a failed pull request", lambda d: rf(d).__setitem__("if", "${{ failure() && github.event_name == 'pull_request' }}")),
        ("a token that writes contents", lambda d: rf(d).__setitem__("permissions", {"contents": "write", "issues": "write"})),
        ("no issues permission", lambda d: rf(d).__setitem__("permissions", {"contents": "read"})),
        ("a title that carries the run", lambda d: [s.__setitem__("run", re.sub(r"--title\s+(\"[^\"]*)\"", r'--title \1 ${GITHUB_RUN_ID}"', s["run"])) for s in rf(d)["steps"] if s.get("run")]),
        ("an issue that never reads the open one", lambda d: [s.__setitem__("run", re.sub(r"gh issue comment", "gh issue create", s["run"])) for s in rf(d)["steps"] if s.get("run")]),
        ("an issue that never comments", lambda d: [s.__setitem__("run", re.sub(r"gh issue create", "gh issue comment 42", s["run"])) for s in rf(d)["steps"] if s.get("run")]),
        ("no label", lambda d: [s.__setitem__("run", re.sub(r"\s*(--label|-l)[ =]\S+", "", s["run"])) for s in rf(d)["steps"] if s.get("run")]),
        ("no run in the text", lambda d: [s.__setitem__("run", s["run"].replace("GITHUB_RUN_ID", "GITHUB_SHA").replace("github.run_id", "github.sha")) for s in rf(d)["steps"] if s.get("run")]),
    ])


# ---------------------------------------------------------------------------------- AC7: a run before the tag
# the tag push alone is too late: a patch release waits for runs on the tagged commit, so each workflow of the full suite must also start from a schedule
# or a manual dispatch (workflow_call, a push to main and a tag push do not count: a bound context counts only from a schedule or dispatch run)
def early_run_problems(w, name):
    on = w.get("on") or {}
    if not isinstance(on, dict): return ["%s has no trigger that can run before its tag: %s" % (name, on)]
    bad = []
    if "schedule" not in on or "workflow_dispatch" not in on:
        bad.append("%s lacks a schedule or workflow_dispatch: %s: no run on a commit exists before its release-candidate tag" % (name, sorted(on)))
    if name == "full-suite.yml" and ("push" in on or "pull_request" in on): bad.append("full-suite.yml has a push or pull_request trigger")
    return bad
for n in ("full-suite.yml", "scan.yml", "codeql.yml"):
    verdict("%s: a schedule and workflow_dispatch let a run exist before its release-candidate tag" % n, early_run_problems(ALL[n], n), True)
    mutants(n, lambda d, n=n: early_run_problems(d, n), ALL[n], [
        ("only a tag push", lambda d: d.__setitem__("on", {"push": {"tags": ["v*"]}})),
        ("only workflow_call", lambda d: d.__setitem__("on", {"workflow_call": ""})),
        ("no workflow_dispatch", lambda d: d["on"].pop("workflow_dispatch")),
        ("no schedule", lambda d: d["on"].pop("schedule")),
    ])
mutants("full-suite.yml", lambda d: early_run_problems(d, "full-suite.yml"), fs, [
    ("a push to main", lambda d: d["on"].__setitem__("push", {"branches": ["main"]})),
    ("a pull_request", lambda d: d["on"].__setitem__("pull_request", "")),
])

# ---------------------------------------------------------------------------------- REQ-REL-013-AC6: the releaser's dispatch
def dispatch_problems(wfs):
    bad = []
    for fn, w in sorted(wfs.items()):
        def writes(perm): return isinstance(perm, dict) and perm.get("actions") == "write" or perm == "write-all"
        if writes(w.get("permissions")): bad.append("%s holds actions: write" % fn)
        for jid, j in (w.get("jobs") or {}).items():
            if isinstance(j, dict) and writes(j.get("permissions")): bad.append("%s job %s holds actions: write" % (fn, jid))
    for jid, j in (wfs["release.yml"].get("jobs") or {}).items():
        if "full-suite" in json.dumps(j): bad.append("release.yml job %s starts or names the full suite" % jid)
    return bad
verdict("no job holds actions: write and release.yml starts no run of the full suite", dispatch_problems(ALL), True)
for name, fn in (("a job with actions: write", lambda a: a["release.yml"]["jobs"]["build-apk"].__setitem__("permissions", {"actions": "write"})),
                 ("a workflow with actions: write", lambda a: a["scan.yml"].__setitem__("permissions", {"actions": "write"})),
                 ("release.yml dispatching the full suite", lambda a: a["release.yml"]["jobs"]["build-apk"]["steps"].append({"run": "gh workflow run full-suite.yml"}))):
    aa = copy.deepcopy(ALL); fn(aa)
    check("dispatch: a copy with %s is refused" % name, dispatch_problems(aa) != [], "accepted")
print("full-suite-wiring: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
