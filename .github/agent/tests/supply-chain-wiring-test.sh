#!/usr/bin/env bash
# proves: REQ-SUP-001-AC1, REQ-SUP-001-AC36, REQ-REL-014-AC2
# Where the supply-chain checks run (owner ratified Oct 5, changed Nov 17 2026: no supply-chain check runs on a pull request): Dependabot carries no cooldown and one entry per
# ecosystem root; supply-chain.yml has no pull_request trigger and one job, the daily audit, which may write issues and nothing else (REQ-REL-014-AC2); no job holds actions: write;
# REQ-SUP-001 is pipeline-only for automatic patches; CI runs the tests. Read from the PARSED files: the real files must pass and every mutation (made through the parsed document)
# must be rejected FOR THE REASON NAMED.
#   .github/workflows/supply-chain.yml: the job `daily-audit` (schedule, workflow_dispatch)
set -euo pipefail
export SC_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
python3 - <<'PY'
import copy, json, os, re, subprocess, sys, yaml

CANON = {}   # job -> the exact normalised run text of its check step (filled below from the shipped workflow's ratified text)

root = os.environ["SC_ROOT"]
WF = os.path.join(root, ".github/workflows/supply-chain.yml")
DB = os.path.join(root, ".github/dependabot.yml")
ADM = os.path.join(root, "bin/admission-tag-signer.py")
PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
ALLOWED_ACTIONS = ("actions/checkout",)

CANONICAL_RUNS = {
    'daily-audit': 'python3 .github/agent/supply-chain/pin-audit.py',
}


def load(p): return yaml.load(open(p), Loader=yaml.BaseLoader)

def dup_keys(text):
    """Duplicate mapping keys anywhere in a YAML text (a parse silently keeps the last value; GitHub rejects the file, so its checks would never run)."""
    out = []
    def walk(n, path):
        if isinstance(n, yaml.MappingNode):
            seen = set()
            for k, v in n.value:
                kk = k.value if isinstance(k, yaml.ScalarNode) else None
                if kk in seen:
                    out.append(path + "/" + str(kk))
                seen.add(kk)
                walk(v, path + "/" + str(kk))
        elif isinstance(n, yaml.SequenceNode):
            for i, v in enumerate(n.value):
                walk(v, path + "/" + str(i))
    walk(yaml.compose(text, Loader=yaml.BaseLoader), "")
    return out

def fetches_pull_ref(run):
    """True when a step runs git fetch with a refspec whose source is a pull ref (pull/N/head, refs/pull/*, + or not)."""
    for line in str(run).splitlines():
        words = re.split(r"[\s;&|()]+", line.replace("'", "").replace('"', ""))
        if "git" in words and "fetch" in words[words.index("git"):]:
            after = words[words.index("fetch", words.index("git")) + 1:]
            if any(re.match(r"\+?(refs/)?pull/", w) for w in after):
                return True
    return False


def judge_wf(d, real=False):
    bad = []
    on = d.get("on", {})
    if not isinstance(on, dict):
        return ["the workflow's triggers are not a mapping"]
    for ev in ("pull_request", "pull_request_target", "workflow_run", "push"):
        if ev in on:
            bad.append(f"a {ev} trigger: no job of this workflow runs on a pull request or a push (REQ-REL-014-AC2)")
    if set(on) != {"schedule", "workflow_dispatch"}:
        bad.append(f"the triggers are not exactly schedule and workflow_dispatch: {sorted(on)}")
    if "merge_group" in on:
        bad.append("a merge_group trigger: there is no merge queue")
    crons = [c.get("cron") for c in (on.get("schedule") or [])]
    if len(crons) != 1 or not re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", crons[0] or ""):
        bad.append("no single daily schedule")
    text = open(WF).read() if real else yaml.safe_dump(d)
    if re.search(r"secrets\.", text):
        bad.append("the workflow uses secrets.*: no secrets anywhere (the GitHub token is github.token)")
    top = d.get("permissions")
    if top not in ({}, {"contents": "read"}, None) or (top is None):
        bad.append("the workflow has no top-level permissions block of {} or contents: read")
    jobs = d.get("jobs", {})
    if sorted(jobs) != ["daily-audit"]:
        bad.append(f"the jobs are not exactly daily-audit (no pin-age job): {sorted(jobs)}")
        return bad
    # daily-audit
    j = jobs["daily-audit"]
    if j.get("permissions") != {"contents": "read", "issues": "write"}:
        bad.append(f"daily-audit's permissions are not exactly contents: read + issues: write (found {j.get('permissions')})")
    if (j.get("concurrency") or {}).get("group") != "supply-chain-daily" or (j.get("concurrency") or {}).get("cancel-in-progress") != "false":
        bad.append("daily-audit has no concurrency group (two runs at once could double-file an issue)")
    if str(j.get("if", "")) != "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'":
        bad.append("daily-audit's condition is not exactly the ratified one")
    if "schedule" not in str(j.get("if", "")):
        bad.append("daily-audit does not run on the schedule")
    if ".github/agent/supply-chain/pin-audit.py" not in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])):
        bad.append("daily-audit must run .github/agent/supply-chain/pin-audit.py")
    pull_fetches = [st for st in j.get("steps", []) if fetches_pull_ref(st.get("run", ""))]
    if pull_fetches:
        bad.append("daily-audit has a step that runs git fetch of refs/pull: the history is read from main only")
    # nothing may change WHERE the checker comes from or what runs it
    for key in ("env", "defaults"):
        if key in d:
            bad.append(f"the workflow has a top-level {key}: it could change what the trusted checker runs")
    # the one reviewed block (advisor, Oct 22; cache#583): a pull request's FIRST run attempt joins the pull request's group (a newer push cancels its older run); every other run (the
    # daily schedule, a dispatch, a re-run of any head) gets a group of its own per run and attempt and is never cancelled nor replaced as a pending run. The prefix is a literal. Any other
    # top-level concurrency is refused. daily-audit keeps its own job-level group (checked above).
    if d.get("concurrency") != {
            "group": "${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('supply-chain-pr-{0}', github.event.pull_request.number) || format('supply-chain-{0}-{1}', github.run_id, github.run_attempt) }}",
            "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}:
        bad.append("the workflow's top-level concurrency is not the reviewed block: it could cancel the trusted checker's run")
    for name, jj in jobs.items():
        for key in ("container", "services", "defaults"):
            if key in jj:
                bad.append(f"{name} has a job-level {key} (an image or a shell default that could run PR code or an unpinned image)")
        if name != "daily-audit" and "concurrency" in jj:
            bad.append(f"{name} has a concurrency block")
        if "env" in jj:
            bad.append(f"{name} has a job-level env")
    # the check steps' commands are pinned EXACTLY: any other flag, an extra assignment, a duplicated argument, a changed order is a changed (rejected) workflow
    norm = lambda t: "\n".join(l.strip() for l in str(t).strip().split("\n") if l.strip())
    for jn, want in CANONICAL_RUNS.items():
        for st in jobs[jn].get("steps", []):
            r = str(st.get("run", ""))
            if r and "pin-audit" in r and norm(r) != norm(want):
                bad.append(f"{jn}: the check step's commands differ from the ratified text (any added flag, assignment or duplicated argument is a change)")
    if re.search(r"secrets\s*\[", text):
        bad.append("the workflow indexes secrets[...]: no secrets anywhere")
    for name, jj in jobs.items():
        for st in jj.get("steps", []):
            # a step may not be skipped, tolerated or cut short: the only conditions are the ratified ones
            if "continue-on-error" in st:
                bad.append(f"{name}: a step has continue-on-error: a failing check must fail the job")
            if "if" in st:
                bad.append(f"{name}: a step has a condition ({st.get('if')!r}): the job-level one is the only one, a step could skip the check")
            if "timeout-minutes" in st:
                bad.append(f"{name}: a step has its own timeout-minutes")
            for forbidden in ("shell", "working-directory"):
                if forbidden in st:
                    bad.append(f"{name}: a step sets {forbidden}: it could replace what actually runs")
            may_set = {"GH_TOKEN", "GITHUB_REPOSITORY"}
            extra_env = set(st.get("env") or {}) - may_set
            if extra_env:
                allowed = ' and '.join(sorted(may_set))
                bad.append(f"{name}: a step sets env {sorted(extra_env)}: only {allowed} may be set "
                           "(PYTHONPATH and friends redirect the trusted checker)")
        for st in [x for x in jj.get("steps", []) if "run" in x]:
            run_text = str(st["run"])
            if re.search(r"GITHUB_ENV|GITHUB_PATH|BASH_ENV|ENV=", run_text):
                bad.append(f"{name}: a run step writes the job's environment or path (it could replace python3)")
            if re.search(r"--fixtures|--now\b|PYTHONPATH|PYTHONHOME|PYTHONSTARTUP|PYTHONSAFEPATH=0", run_text):
                bad.append(f"{name}: a run step passes a test-only flag or a Python path override (--fixtures, --now, PYTHONPATH): production runs never take fixtures")
            if re.search(r"(^|[;&|\n])\s*exit\s+(?!\$status\b)", run_text) or re.search(r"\|\|\s*true\b", run_text):
                bad.append(f"{name}: a run step exits early or swallows a failure (exit / || true)")
            if "GH_TOKEN" not in str(st.get("env", "")) and ("pin-" in run_text):
                bad.append(f"{name}: a step that runs the checkers has no GH_TOKEN (without it the live lookups cannot run)")
        for s in jj.get("steps", []):
            u = str(s.get("uses", ""))
            if u and not PIN.match(u):
                bad.append(f"{name}: action {u} is not pinned to a commit digest")
            if u and u.split("@")[0] not in ALLOWED_ACTIONS:
                bad.append(f"{name}: action {u.split('@')[0]} is not on the allowlist {ALLOWED_ACTIONS}")
            if u.startswith("actions/checkout") and str((s.get("with", {}) or {}).get("persist-credentials", "")).lower() != "false":
                bad.append(f"{name}: checkout keeps the job's credentials (persist-credentials must be false)")
        if (jj.get("permissions") or {}).get("actions") is not None:
            bad.append(f"{name} has an actions permission: none may")
        if name != "daily-audit" and "issues" in (jj.get("permissions") or {}):
            bad.append(f"{name} can write issues: only daily-audit may")
        if jj.get("environment") or "secrets" in str(jj.get("env", "")):
            bad.append(f"{name} has an environment or secrets: none are allowed")
    return bad

GOMOD_DIRS = None   # the directories of the go.mod files git tracks ("." is the root); None when git cannot say
try:
    _ls = subprocess.run(["git", "-C", root, "ls-files", "--", "go.mod", "*/go.mod"], capture_output=True, text=True, check=True).stdout.split()
    GOMOD_DIRS = {os.path.dirname(f) or "." for f in _ls}
except Exception:
    pass

def judge_db(d, gomod_dirs=GOMOD_DIRS):
    bad = []
    # entries are keyed by (ecosystem, directory): a second gomod entry must not hide the first; the govulncheck tool
    # module (advisor Oct 12, ruling G) is judged apart from the product's gomod entries
    seen, ups, gm, tool = set(), {}, {}, []
    for u in d.get("updates", []):
        k = (u.get("package-ecosystem"), u.get("directory"))
        if k in seen:
            bad.append(f"duplicate {k[0]} {k[1]} entry")
        seen.add(k)
        if k == ("gomod", "/tools/govulncheck"):
            tool.append(u)
        elif k[0] == "gomod":
            gm.setdefault(k[1], u)
        else:
            ups.setdefault(k[0], u)
    for u in d.get("updates", []):
        if "cooldown" in u:
            bad.append(f"the {u.get('package-ecosystem')} {u.get('directory')} entry has a cooldown: there is no release-age wait")
    for eco in ("github-actions", "pip"):
        # exactly weekly and no extra key (no day, time or timezone)
        if (ups.get(eco) or {}).get("schedule") != {"interval": "weekly"}:
            bad.append(f"the {eco} entry's schedule is not exactly interval: weekly")
    # groups are judged below; the product's gomod entries stay unchanged apart from them
    nog = lambda v: {a: b for a, b in v.items() if a != "groups"}
    for gdir in ("/", "/tools/requirements"):  # both Go modules: the root and the nested tools/requirements module
        if gdir not in gm:
            bad.append(f"the gomod {gdir} entry is missing")
            continue
        if nog(gm[gdir]) != {"package-ecosystem": "gomod", "directory": gdir, "schedule": {"interval": "weekly"}}:
            bad.append(f"the gomod {gdir} entry is not exactly weekly and nothing else")
    # the pinned Go source scanner (advisor Oct 12, ruling G): tools/govulncheck is its own module, bumped through the reviewed path (a tool, not a product dependency)
    if len(tool) != 1:
        bad.append(f"the govulncheck tool entry (gomod, /tools/govulncheck) is missing or repeated ({len(tool)})")
    elif tool[0] != {"package-ecosystem": "gomod", "directory": "/tools/govulncheck", "schedule": {"interval": "weekly"}}:
        bad.append("the govulncheck tool entry is not exactly weekly and nothing else")
    # rule 61 (advisor Oct 12): no Dockerfile exists, so Dependabot's docker ecosystem watches nothing and has no entry
    if any(u.get("package-ecosystem") == "docker" for u in d.get("updates", [])):
        bad.append("a docker entry is back: no Dockerfile exists (rule 61)")
    # coverage: every tracked go.mod has a gomod entry and every gomod entry has a go.mod
    # exact strings, no normalising: an entry spelled any other way ("/tools/requirements/", "tools/requirements", "./")
    # has no go.mod and is red
    if gomod_dirs is None:
        bad.append("cannot list the tracked go.mod files (git ls-files failed)")
    else:
        want_dirs = {("/" if g == "." else "/" + g): g for g in gomod_dirs}
        have = set(gm) | ({"/tools/govulncheck"} if tool else set())
        for w in sorted(set(want_dirs) - have):
            bad.append(f"go.mod at {want_dirs[w]} has no gomod entry")
        for g in sorted(have - set(want_dirs), key=repr):
            bad.append(f"gomod entry {g} has no go.mod")
    # groups (audit ruling Oct 31, widened to the rule 12 shape, cache#817): every github-actions, gomod and pip entry
    # has its minor-patch group with update-types exactly minor and patch (a major never joins a group, except
    # codeql-action, which is major-only and stays FIRST because Dependabot gives a dependency to the first group that
    # matches). The govulncheck tool entry stays exactly as ruling G wrote it (no group).
    # No group sets applies-to anywhere.
    ag = (ups.get("github-actions") or {}).get("groups") or {}
    if list(ag) != ["codeql-action", "actions-minor-patch"]:
        bad.append("the github-actions groups are not exactly codeql-action then actions-minor-patch, in that order")
    if ag.get("codeql-action") != {"patterns": ["github/codeql-action*"], "update-types": ["major"]}:
        bad.append("the codeql-action group is not exactly github/codeql-action* with update-types major (major only)")
    if ag.get("actions-minor-patch") != {"patterns": ["*"], "update-types": ["minor", "patch"]}:
        bad.append("the actions-minor-patch group is not exactly patterns * with update-types minor and patch")
    for gdir, gu in gm.items():
        gg = gu.get("groups") or {}
        if list(gg) != ["gomod-minor-patch"]:
            bad.append(f"the gomod {gdir} groups are not exactly gomod-minor-patch")
        if gg.get("gomod-minor-patch") != {"patterns": ["*"], "update-types": ["minor", "patch"]}:
            bad.append(f"the gomod {gdir} gomod-minor-patch group is not exactly patterns * with update-types minor and patch")
    for u in d.get("updates", []):
        for gname, g in ((u.get("groups") or {}).items()):
            if isinstance(g, dict) and "applies-to" in g:
                bad.append(f"the {u.get('package-ecosystem')} group {gname} sets applies-to (none may: it would change which updates the group takes)")
    pg = (ups.get("pip") or {}).get("groups") or {}
    if list(pg) != ["pydantic", "pip-minor-patch"]:
        bad.append("the pip groups are not exactly pydantic then pip-minor-patch, in that order")
    if pg.get("pydantic") != {"patterns": ["pydantic", "pydantic-core"]}:
        bad.append("the pip pydantic group is not exactly pydantic and pydantic-core")
    # exclude-patterns ["pip"]: pip itself is pinned exactly in pip-requirements.txt (the pip-pin test fails on any
    # other pin), so a bump of pip must not join a group
    if pg.get("pip-minor-patch") != {"exclude-patterns": ["pip"], "update-types": ["minor", "patch"]}:
        bad.append("the pip-minor-patch group is not exactly update-types minor and patch with exclude-patterns pip (a major never joins a group; no patterns)")
    return bad

def judge_rest():
    bad = []
    ns = {}
    src = open(ADM).read()
    m = re.search(r"PIPELINE_ONLY = frozenset\(\[(.*?)\]\)", src, re.S)
    if not m or "REQ-SUP-001" not in m.group(1):
        bad.append("REQ-SUP-001 is not in PIPELINE_ONLY (left off, it is product by default and freezes automatic patches)")
    return bad

real_wf, real_db = None, None
try:
    real_wf = load(WF)
except Exception as e:
    print("FAIL cannot read supply-chain.yml:", e)
real_db = load(DB)

passed = failed = 0
def J_real_steps(): return ((real_wf or {}).get("jobs") or {}).get("daily-audit", {}).get("steps", [])

def result(ok, msg):
    global passed, failed
    if ok: passed += 1; print("ok  ", msg)
    else: failed += 1; print("FAIL", msg)

# the real files
real_text = open(WF).read()
dd = dup_keys(real_text)
result(not dd, "the real supply-chain.yml has no duplicate YAML key" + ("" if not dd else ": " + ", ".join(dd[:5])))
dd = dup_keys(real_text.replace("\nconcurrency:\n", "\nconcurrency: {group: shared, cancel-in-progress: true}\nconcurrency:\n", 1))
result(bool(dd), "caught: a duplicate top-level concurrency key (raw YAML; a parse would keep the last value)" + ("" if dd else "; saw nothing"))
b = judge_wf(real_wf, True) if real_wf is not None else ["supply-chain.yml is missing"]
result(not b, "the real supply-chain.yml satisfies the wiring" + ("" if not b else ": " + "; ".join(b)))
pf = [st for st in J_real_steps() if fetches_pull_ref(st.get("run", ""))]
result(not pf, "the real daily-audit job has no step that runs git fetch of refs/pull" + ("" if not pf else ": " + "; ".join(str(st.get("run", "")) for st in pf)))
b = judge_db(real_db)
result(not b, "the real dependabot.yml: no cooldown anywhere, every gomod entry weekly and nothing else, no docker entry; groups: every github-actions, gomod and pip entry has its minor-patch group (minor and patch only), codeql-action first and major-only, pydantic first on pip, no docker entry, no applies-to" + ("" if not b else ": " + "; ".join(b)))
b = judge_rest()
result(not b, "REQ-SUP-001 is pipeline-only and the CI suite list runs the three tests" + ("" if not b else ": " + "; ".join(b)))

def mut_wf(name, expect, fn):
    if real_wf is None:
        result(False, f"cannot mutate (no workflow): {name}"); return
    d = copy.deepcopy(real_wf)
    try:
        fn(d)
    except Exception as e:
        result(False, f"mutation could not be applied ({name}): {type(e).__name__}: {e}"); return
    if d == real_wf:
        result(False, f"mutation changed nothing ({name})"); return
    yaml.safe_load(yaml.safe_dump(d))
    found = judge_wf(d, False)
    ok = any(expect in x for x in found)
    result(ok, f"caught: {name} (reason: {expect!r})" + ("" if ok else f"; saw {found}"))

def mut_db(name, expect, fn):
    d = copy.deepcopy(real_db)
    try:
        fn(d)
    except Exception as e:
        result(False, f"mutation could not be applied ({name}): {type(e).__name__}: {e}"); return
    if d == real_db:
        result(False, f"mutation changed nothing ({name})"); return
    found = judge_db(d)
    ok = any(expect in x for x in found)
    result(ok, f"caught: {name} (reason: {expect!r})" + ("" if ok else f"; saw {found}"))

def J(d, n): return d["jobs"][n]
def eco(d, e): return next(u for u in d["updates"] if u["package-ecosystem"] == e)
def gmod(d, p): return next(u for u in d["updates"] if u["package-ecosystem"] == "gomod" and u["directory"] == p)

# --- the workflow (AC4, AC6) ---
mut_wf("a pull_request trigger returns", "a pull_request trigger", lambda d: d["on"].update(pull_request={}))
mut_wf("a pull_request trigger with a filter returns", "a pull_request trigger", lambda d: d["on"].update(pull_request={"paths": ["bin/**"]}))
mut_wf("a push trigger appears", "a push trigger", lambda d: d["on"].update(push={"branches": ["main"]}))
mut_wf("a pin-age job returns", "the jobs are not exactly daily-audit",
       lambda d: d["jobs"].update({"pin-age": {"if": "github.event_name == 'pull_request'", "runs-on": "ubuntu-latest", "steps": []}}))
mut_wf("a job-level env appears", "job-level env", lambda d: J(d, "daily-audit").update(env={"PYTHONPATH": "pr"}))
mut_wf("a pull_request_target trigger", "pull_request_target", lambda d: d["on"].update(pull_request_target={}))
mut_wf("a workflow_run trigger", "a workflow_run trigger", lambda d: d["on"].update(workflow_run={"workflows": ["x"]}))
mut_wf("no schedule", "no single daily schedule", lambda d: d["on"].pop("schedule"))
mut_wf("a daily step gains a condition", "a step has a condition", lambda d: [x.update({"if": "false"}) for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a workflow-level env appears", "top-level env", lambda d: d.update(env={"PYTHONPATH": "pr"}))
mut_wf("--report-only on the daily audit", "differ from the ratified text", lambda d: [x.update(run=x["run"] + " --report-only") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a secret indexed with brackets", "indexes secrets", lambda d: [x["env"].update(GH_TOKEN="${{ secrets['PAT'] }}") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a step sets shell", "sets shell", lambda d: [x.update(shell='bash -c "true" {0}') for x in J(d, "daily-audit")["steps"] if "run" in x][-1:])
mut_wf("a step writes BASH_ENV", "writes the job's environment", lambda d: J(d, "daily-audit")["steps"].insert(0, {"run": 'echo "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"'}))
mut_wf("the daily condition gains && false", "not exactly the ratified one", lambda d: J(d, "daily-audit").update({"if": "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' && false"}))
mut_wf("a secret is used", "uses secrets", lambda d: J(d, "daily-audit")["steps"][-1].setdefault("env", {}).update(X="${{ secrets.PAT }}"))
mut_wf("an unpinned action", "is not pinned to a commit digest", lambda d: J(d, "daily-audit")["steps"].insert(0, {"uses": "actions/checkout@v4"}))
mut_wf("an action off the allowlist", "is not on the allowlist", lambda d: J(d, "daily-audit")["steps"].insert(0, {"uses": "evil/action@" + "a" * 40}))
mut_wf("checkout keeps credentials", "persist-credentials", lambda d: next(s for s in J(d, "daily-audit")["steps"] if "checkout" in str(s.get("uses", "")))["with"].pop("persist-credentials"))
mut_wf("daily-audit loses issues: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].pop("issues"))
mut_wf("daily-audit gains contents: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(contents="write"))
mut_wf("daily-audit gains actions: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(actions="write"))
mut_wf("a top-level concurrency that cancels every event", "not the reviewed block", lambda d: d["concurrency"].update({"cancel-in-progress": "true"}))
mut_wf("a top-level concurrency with a shared ref group", "not the reviewed block", lambda d: d.update(concurrency={"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}))
mut_wf("a top-level concurrency whose pull-request group is shared by re-runs", "not the reviewed block", lambda d: d["concurrency"].update(group=d["concurrency"]["group"].replace(" && github.run_attempt == '1'", "")))
mut_wf("a top-level concurrency that borrows github.workflow", "not the reviewed block", lambda d: d["concurrency"].update(group=d["concurrency"]["group"].replace("'supply-chain-pr-{0}', ", "'{0}-pr-{1}', github.workflow, ").replace("'supply-chain-{0}-{1}', ", "'{0}-{1}-{2}', github.workflow, ")))
mut_wf("a top-level concurrency dropped entirely", "not the reviewed block", lambda d: d.pop("concurrency"))
mut_wf("a top-level concurrency on its own", "not the reviewed block", lambda d: d.update(concurrency={"group": "x", "cancel-in-progress": "false"}))
mut_wf("a sixth job appears", "the jobs are not exactly",
       lambda d: d["jobs"].update({"extra": {"runs-on": "ubuntu-latest"}}))
mut_wf("daily-audit loses its concurrency group", "no concurrency group", lambda d: J(d, "daily-audit").pop("concurrency"))
FETCH_REASON = "daily-audit has a step that runs git fetch of refs/pull"
mut_wf("daily-audit gains a pull request fetch", FETCH_REASON,
       lambda d: J(d, "daily-audit")["steps"].insert(1, {"run": "git fetch --no-tags origin '+refs/pull/*/head:refs/pull/*/head'"}))
mut_wf("daily-audit gains a pull request fetch with a token", FETCH_REASON,
       lambda d: J(d, "daily-audit")["steps"].insert(1, {"run": "git fetch --no-tags origin 'refs/pull/*/head:refs/pull/*/head'",
                                                         "env": {"GH_TOKEN": "${{ github.token }}"}}))
# the guard reads the refspec of a fetch, not the words refs/pull: a pull ref spelled without refs/ is caught, an ordinary fetch is not
for spec in ("pull/1/head", "pull/1/head:pr-1", "'+pull/*/head:refs/remotes/pr/*'", "pull/1/merge", '"pull/${PR}/head"', "refs/pull/1/head"):
    mut_wf("daily-audit fetches a pull ref spelled " + spec, FETCH_REASON,
           lambda d, spec=spec: J(d, "daily-audit")["steps"].insert(1, {"run": "git fetch --no-tags origin " + spec}))
mut_wf("daily-audit fetches a pull ref with git -C and a url", FETCH_REASON,
       lambda d: J(d, "daily-audit")["steps"].insert(1, {"run": "git -C . fetch https://example.invalid/o/r.git pull/1/head"}))
def ctl_wf(name, run):
    d = copy.deepcopy(real_wf); J(d, "daily-audit")["steps"].insert(1, {"run": run})
    found = judge_wf(d, False)
    result(not any(FETCH_REASON in x for x in found), f"not caught as a pull ref fetch: {name}" + "".join(f"; saw {x}" for x in found if FETCH_REASON in x))
ctl_wf("an ordinary fetch of main", "git fetch --no-tags origin '+refs/heads/main:refs/remotes/origin/main'")
ctl_wf("a fetch of a branch named like a pull word", "git fetch --no-tags origin refs/heads/pulley:refs/remotes/origin/pulley")
ctl_wf("a fetch of a tag", "git fetch --no-tags origin refs/tags/v1:refs/tags/v1")
ctl_wf("a command that only prints pull/1/head", "echo pull/1/head")
mut_wf("a job gets an environment", "has an environment or secrets", lambda d: J(d, "daily-audit").update(environment="release"))
mut_wf("a merge_group trigger returns", "a merge_group trigger", lambda d: d["on"].update(merge_group={}))
mut_wf("a second job appears", "the jobs are not exactly",
       lambda d: d["jobs"].update(extra={"runs-on": "ubuntu-latest", "steps": []}))
mut_wf("image-signatures returns", "the jobs are not exactly", lambda d: d["jobs"].update({"image-signatures": {"runs-on": "ubuntu-latest", "steps": []}}))
mut_wf("a step gains a condition of its own", "a step has a condition", lambda d: J(d, "daily-audit")["steps"][0].update({"if": "github.event_name == 'pull_request'"}))
mut_wf("a job holds an actions permission", "has an actions permission", lambda d: J(d, "daily-audit")["permissions"].update(actions="read"))
mut_wf("top-level permissions widened", "no top-level permissions block", lambda d: d.update(permissions={"contents": "write"}))
# --- dependabot (AC1) ---
mut_db("github-actions gains a cooldown", "has a cooldown", lambda d: eco(d, "github-actions").update(cooldown={"default-days": "7"}))
mut_db("gomod gains an ignore rule", "the gomod / entry is not exactly weekly and nothing else", lambda d: eco(d, "gomod").update(ignore=[{"dependency-name": "x"}]))
mut_db("gomod's schedule changes", "the gomod / entry is not exactly weekly and nothing else", lambda d: eco(d, "gomod")["schedule"].update(interval="monthly"))
mut_db("a docker entry returns for /build/docker", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/build/docker", "schedule": {"interval": "daily"}}))
mut_db("a docker entry returns for the root", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/", "schedule": {"interval": "weekly"}}))
mut_db("gomod is removed", "the gomod / entry is missing", lambda d: d["updates"].remove(eco(d, "gomod")))
TOOL = lambda d: next(u for u in d["updates"] if u.get("directory") == "/tools/govulncheck")
mut_db("the govulncheck tool entry is removed", "govulncheck tool entry", lambda d: d["updates"].remove(TOOL(d)))
mut_db("the govulncheck tool entry watches another directory", "govulncheck tool entry", lambda d: TOOL(d).update(directory="/tools/requirements"))
mut_db("the govulncheck tool entry runs daily", "govulncheck tool entry", lambda d: TOOL(d)["schedule"].update(interval="daily"))
mut_db("the govulncheck tool entry ignores a dependency", "govulncheck tool entry", lambda d: TOOL(d).update(ignore=[{"dependency-name": "golang.org/x/vuln"}]))
mut_db("the govulncheck tool entry is repeated", "govulncheck tool entry", lambda d: d["updates"].append(copy.deepcopy(TOOL(d))))
mut_db("gomod gets a cooldown", "has a cooldown", lambda d: eco(d, "gomod").update(cooldown={"default-days": "7"}))
mut_db("github-actions loses its groups", "github-actions groups are not exactly codeql-action then actions-minor-patch", lambda d: eco(d, "github-actions").pop("groups"))
mut_db("github-actions loses its actions-minor-patch group", "github-actions groups are not exactly codeql-action then actions-minor-patch", lambda d: eco(d, "github-actions")["groups"].pop("actions-minor-patch"))
mut_db("the codeql-action group widens", "codeql-action group is not exactly",
       lambda d: eco(d, "github-actions")["groups"]["codeql-action"].update(patterns=["github/*"]))
mut_db("codeql-action loses major", "codeql-action group is not exactly",
       lambda d: eco(d, "github-actions")["groups"]["codeql-action"].pop("update-types"))
mut_db("codeql-action takes minor too", "codeql-action group is not exactly",
       lambda d: eco(d, "github-actions")["groups"]["codeql-action"].update({"update-types": ["major", "minor"]}))
mut_db("actions-minor-patch drops update-types", "actions-minor-patch group is not exactly",
       lambda d: eco(d, "github-actions")["groups"]["actions-minor-patch"].pop("update-types"))
mut_db("actions-minor-patch takes a major", "actions-minor-patch group is not exactly",
       lambda d: eco(d, "github-actions")["groups"]["actions-minor-patch"].update({"update-types": ["major", "minor", "patch"]}))
mut_db("actions-minor-patch takes patch only", "actions-minor-patch group is not exactly",
       lambda d: eco(d, "github-actions")["groups"]["actions-minor-patch"].update({"update-types": ["patch"]}))
mut_db("actions-minor-patch gets applies-to", "sets applies-to",
       lambda d: eco(d, "github-actions")["groups"]["actions-minor-patch"].update({"applies-to": "security-updates"}))
mut_db("codeql-action gets applies-to", "sets applies-to",
       lambda d: eco(d, "github-actions")["groups"]["codeql-action"].update({"applies-to": "version-updates"}))
d = copy.deepcopy(real_db)    # dict equality ignores key order, so this one is judged directly too
try:
    eco(d, "github-actions")["groups"] = dict(reversed(list(eco(d, "github-actions")["groups"].items())))
    found = judge_db(d)
    ok = any("github-actions groups are not exactly codeql-action then actions-minor-patch" in x for x in found)
except Exception as e:
    found, ok = [f"{type(e).__name__}: {e}"], False
result(ok, "caught: actions-minor-patch comes before codeql-action (reason: 'github-actions groups are not exactly codeql-action then actions-minor-patch')" + ("" if ok else f"; saw {found}"))
mut_db("gomod loses its groups", "the gomod / groups are not exactly gomod-minor-patch", lambda d: eco(d, "gomod").pop("groups"))
mut_db("gomod-minor-patch drops update-types", "the gomod / gomod-minor-patch group is not exactly",
       lambda d: eco(d, "gomod")["groups"]["gomod-minor-patch"].pop("update-types"))
mut_db("gomod-minor-patch takes a major", "the gomod / gomod-minor-patch group is not exactly",
       lambda d: eco(d, "gomod")["groups"]["gomod-minor-patch"].update({"update-types": ["major", "minor", "patch"]}))
mut_db("gomod-minor-patch gets applies-to", "sets applies-to",
       lambda d: eco(d, "gomod")["groups"]["gomod-minor-patch"].update({"applies-to": "version-updates"}))
# the second Go module (rule 12): tools/requirements has its own gomod entry, judged apart from the root one
mut_db("the tools/requirements entry is removed", "go.mod at tools/requirements has no gomod entry", lambda d: d["updates"].remove(gmod(d, "/tools/requirements")))
mut_db("the tools/requirements entry is removed (named)", "the gomod /tools/requirements entry is missing", lambda d: d["updates"].remove(gmod(d, "/tools/requirements")))
mut_db("the tools/requirements group is dropped", "the gomod /tools/requirements groups are not exactly gomod-minor-patch", lambda d: gmod(d, "/tools/requirements").pop("groups"))
mut_db("the tools/requirements group takes a major", "the gomod /tools/requirements gomod-minor-patch group is not exactly",
       lambda d: gmod(d, "/tools/requirements")["groups"]["gomod-minor-patch"].update({"update-types": ["major", "minor", "patch"]}))
mut_db("the tools/requirements schedule changes", "the gomod /tools/requirements entry is not exactly weekly and nothing else", lambda d: gmod(d, "/tools/requirements")["schedule"].update(interval="daily"))
mut_db("the tools/requirements group gets applies-to", "sets applies-to", lambda d: gmod(d, "/tools/requirements")["groups"]["gomod-minor-patch"].update({"applies-to": "version-updates"}))
mut_db("the root gomod entry is duplicated", "duplicate gomod / entry", lambda d: d["updates"].append(copy.deepcopy(gmod(d, "/"))))
mut_db("the root entry is broken while tools/requirements stays", "the gomod / entry is not exactly weekly and nothing else", lambda d: gmod(d, "/")["schedule"].update(interval="monthly"))
mut_db("the root entry loses its group while tools/requirements stays", "the gomod / groups are not exactly gomod-minor-patch", lambda d: gmod(d, "/").pop("groups"))
mut_db("the tools/requirements directory becomes /tools", "go.mod at tools/requirements has no gomod entry", lambda d: gmod(d, "/tools/requirements").update(directory="/tools"))
mut_db("the tools/requirements directory becomes /tools (named)", "gomod entry /tools has no go.mod", lambda d: gmod(d, "/tools/requirements").update(directory="/tools"))
# a THIRD gomod entry, copied from tools/requirements, under another spelling of a tracked directory
def third_gomod(dirv, sched):
    def fn(d):
        e = copy.deepcopy(gmod(d, "/tools/requirements")); e["directory"] = dirv; e["schedule"]["interval"] = sched
        d["updates"].append(e)
    return fn
mut_db("a third gomod entry /tools/requirements/ (trailing slash), monthly", "gomod entry /tools/requirements/ has no go.mod", third_gomod("/tools/requirements/", "monthly"))
mut_db("a third gomod entry tools/requirements (no leading slash), monthly", "gomod entry tools/requirements has no go.mod", third_gomod("tools/requirements", "monthly"))
mut_db("a third gomod entry ./ (the root spelled ./), monthly", "gomod entry ./ has no go.mod", third_gomod("./", "monthly"))
mut_db("a gomod entry written with directories: instead of directory:", "gomod entry None has no go.mod", lambda d: d["updates"].append({k: v for k, v in gmod(d, "/").items() if k != "directory"} | {"directories": ["/"]}))
# the coverage check alone, with a go.mod the file does not name (a third module)
found = judge_db(real_db, (GOMOD_DIRS or set()) | {"tools/other"})
result(any("go.mod at tools/other has no gomod entry" in x for x in found), "caught: a tracked go.mod with no gomod entry (reason: 'go.mod at tools/other has no gomod entry')" + ("" if found else "; saw nothing"))
result(GOMOD_DIRS == {".", "tools/govulncheck", "tools/requirements"}, f"git tracks exactly three go.mod files: the root, tools/govulncheck and tools/requirements (saw {sorted(GOMOD_DIRS or [])})")
mut_db("github-actions schedule goes monthly", "github-actions entry's schedule is not exactly interval: weekly", lambda d: eco(d, "github-actions")["schedule"].update(interval="monthly"))
mut_db("pip schedule goes monthly", "pip entry's schedule is not exactly interval: weekly", lambda d: eco(d, "pip")["schedule"].update(interval="monthly"))
mut_db("github-actions schedule gains day monday", "github-actions entry's schedule is not exactly interval: weekly", lambda d: eco(d, "github-actions")["schedule"].update(day="monday"))
mut_db("pip-minor-patch drops update-types", "pip-minor-patch group is not exactly update-types minor and patch", lambda d: eco(d, "pip")["groups"]["pip-minor-patch"].pop("update-types"))
mut_db("pip-minor-patch gets applies-to", "sets applies-to", lambda d: eco(d, "pip")["groups"]["pip-minor-patch"].update({"applies-to": "version-updates"}))
mut_db("pydantic gets update-types", "pip pydantic group is not exactly", lambda d: eco(d, "pip")["groups"]["pydantic"].update({"update-types": ["minor", "patch"]}))
mut_db("pip loses the pip-minor-patch group", "pip groups are not exactly pydantic then pip-minor-patch", lambda d: eco(d, "pip")["groups"].pop("pip-minor-patch"))
# dict equality ignores key order, so this one is judged directly instead of through mut_db
d = copy.deepcopy(real_db)
eco(d, "pip")["groups"] = dict(reversed(list(eco(d, "pip")["groups"].items())))
found = judge_db(d)
ok = list(eco(d, "pip")["groups"]) == ["pip-minor-patch", "pydantic"] and any("pip groups are not exactly pydantic then pip-minor-patch" in x for x in found)
result(ok, "caught: pip-minor-patch comes before pydantic (reason: 'pip groups are not exactly pydantic then pip-minor-patch')" + ("" if ok else f"; saw {found}"))
mut_db("pip-minor-patch takes a major", "pip-minor-patch group is not exactly update-types minor and patch",
       lambda d: eco(d, "pip")["groups"]["pip-minor-patch"].update({"update-types": ["major", "minor", "patch"]}))
mut_db("pip-minor-patch gets patterns", "pip-minor-patch group is not exactly update-types minor and patch",
       lambda d: eco(d, "pip")["groups"]["pip-minor-patch"].update(patterns=["*"]))
mut_db("pip-minor-patch exclude-patterns changes", "pip-minor-patch group is not exactly update-types minor and patch",
       lambda d: eco(d, "pip")["groups"]["pip-minor-patch"].update({"exclude-patterns": ["anthropic"]}))
mut_db("pip-minor-patch loses its exclude-patterns", "pip-minor-patch group is not exactly update-types minor and patch",
       lambda d: eco(d, "pip")["groups"]["pip-minor-patch"].pop("exclude-patterns"))
mut_db("the pydantic group changes", "pip pydantic group is not exactly pydantic and pydantic-core",
       lambda d: eco(d, "pip")["groups"]["pydantic"].update(patterns=["pydantic"]))

print(f"supply-chain wiring: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
PY
