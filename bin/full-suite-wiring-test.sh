#!/usr/bin/env bash
# proves: REQ-CI-001-AC1, REQ-CI-001-AC4, REQ-CI-001-AC5, REQ-CI-001-AC6, REQ-CI-001-AC7
# Quick checks on each pull request, the full suite at promotion (REQ-CI-001; owner, Nov 10 2026), offline. Reads the real workflows and
# .github/policy/required-checks.json as data and judges each against the English; every judge is also run over mutated copies, each of which
# must be caught:
#   AC1  the required list is exactly eight contexts, none of them skippable by a job-level condition; the promotion list holds the rest
#   AC4  ci.yml's test job vets, builds and tests only the changed packages (no -race, no fips settings); its allowlist job runs, in ONE step,
#        the lines bin/select-tests.sh prints (the step is run here with a stand-in for the selector), the allowlist of every tracked file
#        and the action-pin checks
#   AC5  full-suite.yml: a daily schedule, workflow_dispatch and workflow_call only; the six moved jobs under their old names, each running
#        its whole suite; one call of acceptance.yml
#   AC6  full-suite.yml, scan.yml and codeql.yml end with a report-failure job for a failed scheduled run; its script is run here with a stand-in
#        for gh: it opens one issue with a fixed title and label, or comments on the open one, naming the run
#   AC7  stage-admission's check step, run here against a stand-in for gh: for a release-candidate tag every promotion_checks context must
#        have a successful run, by its app, on the exact tagged commit; a missing, red, wrong-app or older-commit run stops it, naming the context
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -I - "$root" "$work" <<'PY'
import copy, json, os, re, shlex, stat, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
def load(p): return yaml.load(open(os.path.join(root, p)), Loader=yaml.BaseLoader)
WF = ".github/workflows/"
ci, fs, acc = load(WF + "ci.yml"), None, load(WF + "acceptance.yml")
fs = load(WF + "full-suite.yml") if os.path.exists(os.path.join(root, WF + "full-suite.yml")) else None
POLICY = json.load(open(os.path.join(root, ".github/policy/required-checks.json")))

REQUIRED = ["test", "lint", "requirements", "allowlist", "vendor", "govulncheck", "pin-age", "auditor-review-gate"]
PROMOTION = ["coverage", "fips140-only", "gosec", "analyze (go)", "allowlist-persona", "allowlist-chain", "allowlist-pins-auditor",
             "acceptance / acceptance-gradle", "acceptance / acceptance-maven (1.2.0)", "acceptance / acceptance-maven (1.2.3)", "reproducibility", "scan"]
GONE = PROMOTION + ["dependency-review", "acceptance-gradle", "acceptance-maven"]
def base(ctx): return ctx.split(" (")[0]
def mutated(doc, fn):
    d = copy.deepcopy(doc); fn(d); return d
def verdict(name, problems, want_ok, doc_name=""):
    check(name, (problems == []) == want_ok, problems)
def mutants(label, judge, doc, cases):
    """each case: (name, fn): the mutated copy must have at least one problem"""
    for name, fn in cases:
        try: probs = judge(mutated(doc, fn))
        except Exception as e: probs = ["judge raised %r" % e]
        check("%s: a copy with %s is refused" % (label, name), probs != [], "accepted")
        if os.environ.get("WIRING_SHOW"): print("      why:", str(probs[:2])[:260])

# ------------------------------------------------------------------------------------------------------------------ AC1: the lists
SHAPE = {"context", "integration_id", "scope"}
def policy_problems(doc):
    bad = []
    rc, pc = doc.get("required_checks"), doc.get("promotion_checks")
    if not isinstance(rc, list) or not isinstance(pc, list): return ["required_checks or promotion_checks is not a list"]
    for key, lst in (("required_checks", rc), ("promotion_checks", pc)):
        for e in lst:
            if not isinstance(e, dict) or set(e) != SHAPE: bad.append("%s entry has not the shape context/integration_id/scope: %s" % (key, e)); continue
            want_id = 5054756 if e["context"] == "auditor-review-gate" else 15368
            if e["integration_id"] != want_id: bad.append("%s %r has integration_id %r" % (key, e["context"], e["integration_id"]))
    if sorted(e.get("context") for e in rc) != sorted(REQUIRED): bad.append("required_checks are not exactly the eight: %s" % [e.get("context") for e in rc])
    if sorted(e.get("context") for e in pc) != sorted(PROMOTION): bad.append("promotion_checks are not exactly the twelve: %s" % [e.get("context") for e in pc])
    for e in pc:
        if isinstance(e, dict) and e.get("scope") != "push": bad.append("promotion check %r is not push-scoped (admission reads the exact tagged commit)" % e.get("context"))
    if set(doc) - {"comment", "required_checks", "promotion_checks"}: bad.append("unknown keys: %s" % sorted(set(doc) - {"comment", "required_checks", "promotion_checks"}))
    return bad
verdict("required-checks.json: eight required contexts, twelve promotion contexts, the entry shape of today", policy_problems(POLICY), True)
mutants("required-checks.json", policy_problems, POLICY, [
    ("gosec back in required_checks", lambda d: d["required_checks"].append({"context": "gosec", "integration_id": 15368, "scope": "push"})),
    ("dependency-review back in required_checks", lambda d: d["required_checks"].append({"context": "dependency-review", "integration_id": 15368, "scope": "pull_request"})),
    ("lint dropped from required_checks", lambda d: d.__setitem__("required_checks", [e for e in d["required_checks"] if e["context"] != "lint"])),
    ("auditor-review-gate dropped", lambda d: d.__setitem__("required_checks", [e for e in d["required_checks"] if e["context"] != "auditor-review-gate"])),
    ("no promotion_checks", lambda d: d.pop("promotion_checks")),
    ("scan dropped from promotion_checks", lambda d: d.__setitem__("promotion_checks", [e for e in d["promotion_checks"] if e["context"] != "scan"])),
    ("acceptance / acceptance-maven (1.2.3) dropped", lambda d: d.__setitem__("promotion_checks", [e for e in d["promotion_checks"] if e["context"] != "acceptance / acceptance-maven (1.2.3)"])),
    ("an extra promotion context", lambda d: d["promotion_checks"].append({"context": "extra", "integration_id": 15368, "scope": "push"})),
    ("dependency-review in promotion_checks", lambda d: d["promotion_checks"].append({"context": "dependency-review", "integration_id": 15368, "scope": "push"})),
    ("a promotion entry with another app", lambda d: d["promotion_checks"][0].__setitem__("integration_id", 1)),
    ("a promotion entry without a scope", lambda d: d["promotion_checks"][0].pop("scope")),
    ("a promotion entry with an extra key", lambda d: d["promotion_checks"][0].__setitem__("x", "y")),
    ("a promotion entry scoped to pull requests", lambda d: d["promotion_checks"][0].__setitem__("scope", "pull_request")),
    ("a required entry with another app", lambda d: d["required_checks"][0].__setitem__("integration_id", 1)),
])

# which jobs produce a context on pull_request: every workflow with the event, every job (name, else id), matrix suffix aside
def pr_contexts():
    out = {}
    for fn in sorted(os.listdir(os.path.join(root, WF))):
        w = load(WF + fn); on = w.get("on") or {}
        ev = set(on) if isinstance(on, dict) else ({on} if isinstance(on, str) else set(on))
        if "pull_request" not in ev: continue
        for jid, j in (w.get("jobs") or {}).items():
            out.setdefault(base(j.get("name") or jid), []).append((fn, jid, j))
    return out
prc = pr_contexts()
def ac1_problems(prc):
    bad = []
    for ctx in ("test", "lint", "requirements", "allowlist", "vendor", "govulncheck", "pin-age"):
        if ctx not in prc: bad.append("%s does not run on pull_request" % ctx)
        for fn, jid, j in prc.get(ctx, []):
            if "if" in j: bad.append("%s (%s:%s) has a job-level condition" % (ctx, fn, jid))
    for ctx in GONE:
        if base(ctx) in prc: bad.append("%s still runs on pull_request in %s" % (ctx, [f for f, _, _ in prc[base(ctx)]]))
    return bad
verdict("pull requests: the seven job-made required contexts run unconditionally, none of the thirteen removed ones runs", ac1_problems(prc), True)
for name, fn in (("test skippable", lambda p: p["test"][0][2].__setitem__("if", "${{ false }}")),
                 ("allowlist skippable", lambda p: p["allowlist"][0][2].__setitem__("if", "${{ github.actor != 'x' }}")),
                 ("pin-age skippable", lambda p: p["pin-age"][0][2].__setitem__("if", "${{ true }}")),
                 ("lint gone", lambda p: p.pop("lint")),
                 ("gosec on pull_request", lambda p: p.setdefault("gosec", []).append(("x.yml", "gosec", {}))),
                 ("dependency-review on pull_request", lambda p: p.setdefault("dependency-review", []).append(("x.yml", "d", {}))),
                 ("scan on pull_request", lambda p: p.setdefault("scan", []).append(("x.yml", "scan", {}))),
                 ("acceptance-maven on pull_request", lambda p: p.setdefault("acceptance-maven", []).append(("x.yml", "m", {}))),
                 ("analyze on pull_request", lambda p: p.setdefault("analyze", []).append(("x.yml", "analyze", {})))):
    pp = copy.deepcopy(prc); fn(pp)
    check("pull requests: %s is refused" % name, ac1_problems(pp) != [], "accepted")

# ------------------------------------------------------------------------------------------------------------------ AC4: ci.yml
def runs(job): return [(s, s.get("run") or "") for s in job.get("steps") or []]
def cmd_lines(text, word):
    return [l for l in text.splitlines() if re.search(word, l) and not l.lstrip().startswith("#")]
def test_job_problems(job):
    bad = []
    text = "\n".join(r for _, r in runs(job))
    for what, rx in (("go vet", r"\bgo vet\b"), ("the static build", r"CGO_ENABLED=0\s+go build\b"), ("go test", r"\bgo test\b")):
        ls = cmd_lines(text, rx)
        if not ls: bad.append("the test job runs no %s" % what)
        for l in ls:
            if "./..." in l: bad.append("%s runs over ./... and not over the changed packages: %s" % (what, l.strip()))
    if re.search(r"-race\b", text): bad.append("the test job runs with -race")
    if re.search(r"fips140", text, re.I): bad.append("the test job sets the fips settings")
    if not any("git diff" in r for _, r in runs(job)): bad.append("no step computes the packages from git diff")
    for need in (r"go\\?\.mod", r"go\\?\.sum", r"vendor/"):
        if not re.search(need, text): bad.append("the package step does not mention %s (every package when it changes)" % need)
    if "if" in job: bad.append("the test job has a job-level condition")
    return bad
ALLOW_CHECK = "git ls-files | ./bin/check-file-allowlist.sh"
AGENT = ".github/" + "agent/"
PINS = "python3 " + AGENT + "bin/check-action-pins.py --verify-tags ."
TESTSH = re.compile(r"[\w./-]*-tests?\.sh\b")
GUARD = "bash bin/scan-no-workflow-call-test.sh"
GUARD_NAME = "scan.yml and main-candidate-rescan.yml are never callable as reusable workflows (REQ-SCAN-015-AC1)"
def sel_steps(job): return [s for s, r in runs(job) if "select-tests.sh" in r]
def allowlist_static(job):
    bad = []
    text = " ".join(re.sub(r"\s+", " ", r) for _, r in runs(job))
    if ALLOW_CHECK not in text: bad.append("the allowlist of every tracked file is gone: " + ALLOW_CHECK)
    if PINS not in text: bad.append("the action-pin check is gone: " + PINS)
    ss = sel_steps(job)
    if len(ss) != 1: bad.append("the selected suites are not run in exactly one step (%d steps name bin/select-tests.sh)" % len(ss))
    guards = [s for s, r in runs(job) if r.strip() == GUARD]
    if len(guards) != 1: bad.append("the allowlist job does not have exactly one scanner guard step running %s (%d)" % (GUARD, len(guards)))
    for g in guards:
        if g.get("name") != GUARD_NAME: bad.append("the scanner guard step is not named %r" % GUARD_NAME)
        if any(k in g for k in ("if", "continue-on-error", "shell", "env")): bad.append("the scanner guard step is conditional or weakened: " + ", ".join(k for k in ("if", "continue-on-error", "shell", "env") if k in g))
    for s, r in runs(job):
        if s not in ss and s not in guards and TESTSH.search(r): bad.append("step %r runs a suite directly instead of through the selection" % s.get("name"))
    return bad
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
    open(path, "w").write(text); os.chmod(path, 0o755)
def selection_problems(job):
    """run the one selection step with a stand-in for bin/select-tests.sh"""
    ss = sel_steps(job)
    if len(ss) != 1: return ["no single selection step"]
    step = ss[0]; bad = []
    ctx = {"github.base_ref": "main", "github.event.pull_request.base.sha": "b" * 40, "github.event.pull_request.head.sha": "c" * 40,
           "github.sha": "c" * 40, "github.event_name": "pull_request", "github.head_ref": "feature"}
    def scenario(select_body, ctx=ctx, event="pull_request"):
        cwd = os.path.join(work, "sel%d" % len(os.listdir(work))); os.makedirs(cwd + "/bin")
        subprocess.run("git init -q && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m c && git update-ref refs/remotes/origin/main HEAD", shell=True, cwd=cwd, check=True, capture_output=True)
        log = cwd + "/log"; open(log, "w").close()
        mkexec(cwd + "/bin/select-tests.sh", "#!/usr/bin/env bash\necho \"$@\" >> \"$ARGS\"\n" + select_body)
        r = run_step(step, {"LOG": log, "ARGS": cwd + "/args", "GITHUB_EVENT_NAME": event, "GITHUB_BASE_REF": ctx.get("github.base_ref", "")}, ctx, cwd, job)
        return r, open(log).read(), (open(cwd + "/args").read() if os.path.exists(cwd + "/args") else "")
    r, log, args = scenario("printf '%s\\n' 'echo one >> \"$LOG\"' 'printf \"%s\\n\" \"two words\" >> \"$LOG\"'")
    if r.returncode != 0 or log != "one\ntwo words\n": bad.append("the selected lines are not run as shell commands in order: rc=%s log=%r err=%r" % (r.returncode, log, r.stderr[-200:]))
    if not args.strip(): bad.append("the step never calls bin/select-tests.sh")
    elif "main" not in args.split()[0] and "b" * 40 not in args.split()[0]: bad.append("the base is not the pull request's base: select-tests.sh got %r" % args.strip())
    r, log, args = scenario("printf '%s\\n' 'echo one >> \"$LOG\"' false 'echo three >> \"$LOG\"'")
    if r.returncode == 0: bad.append("a failing selected suite does not fail the step")
    r, log, args = scenario("echo 'no entry for newdir/x' >&2; exit 1")
    if r.returncode == 0: bad.append("a selector that fails (an unmatched path) does not fail the step")
    r, log, args = scenario(":")
    if r.returncode != 0 or log != "": bad.append("a change that selects nothing does not pass quietly: rc=%s" % r.returncode)
    # on a push there is no pull request base: the step is skipped or selects nothing
    pctx = dict(ctx, **{"github.base_ref": "", "github.event.pull_request.base.sha": "", "github.event_name": "push"})
    cond = str(step.get("if", ""))
    if "pull_request" not in cond and "base_ref" not in cond:
        r, log, args = scenario("printf '%s\\n' 'echo ran >> \"$LOG\"'", ctx=pctx, event="push")
        if r.returncode != 0 or log != "": bad.append("on a push the step runs suites or fails: rc=%s log=%r" % (r.returncode, log))
    return bad
def ci_problems(w):
    jobs = w.get("jobs") or {}
    bad = []
    for ctx in REQUIRED[:6]:
        if (jobs.get(ctx) or {}).get("name") != ctx: bad.append("ci.yml has no job named %s" % ctx)
    for ctx in GONE:
        for jid, j in jobs.items():
            if base(j.get("name") or jid) == base(ctx): bad.append("ci.yml still has the job %s" % ctx)
    bad += test_job_problems(jobs.get("test") or {"steps": []})
    al = jobs.get("allowlist") or {"steps": []}
    bad += allowlist_static(al)
    if not bad or all("exactly one step" not in b for b in bad): bad += selection_problems(al)
    return bad
verdict("ci.yml: the eight-context layout, the changed-packages test job, the one-step selection in the allowlist job", ci_problems(ci), True)
def edit_steps(d, job, fn):
    for s in d["jobs"][job]["steps"]: fn(s)
def add_step(d, job, step): d["jobs"][job]["steps"].append(step)
def tj(d): return d["jobs"]["test"]
def subst_in(d, job, a, b):
    for s in d["jobs"][job]["steps"]:
        if a in (s.get("run") or ""): s["run"] = s["run"].replace(a, b)
def swap_all_go(d, repl):
    for s in tj(d)["steps"]:
        if s.get("run"): s["run"] = repl(s["run"])
def sel_edit(d, fn):
    for s in d["jobs"]["allowlist"]["steps"]:
        if "select-tests.sh" in (s.get("run") or ""): fn(s)
mutants("ci.yml", ci_problems, ci, [
    ("the test job back to -race", lambda d: swap_all_go(d, lambda r: re.sub(r"(go test)", r"\1 -race", r))),
    ("the test job on the fips settings", lambda d: swap_all_go(d, lambda r: re.sub(r"(go test)", r"GOFIPS140=v1.0.0 GODEBUG=fips140=only \1", r))),
    ("go test over ./...", lambda d: swap_all_go(d, lambda r: re.sub(r"(go test[^\n]*?)\s+\S+\s*$", r"\1 ./...", r, flags=re.M))),
    ("go vet over ./...", lambda d: swap_all_go(d, lambda r: re.sub(r"(go vet)[^\n]*", r"\1 ./...", r))),
    ("no go vet", lambda d: swap_all_go(d, lambda r: re.sub(r"[^\n]*\bgo vet\b[^\n]*", ":", r))),
    ("no static build", lambda d: swap_all_go(d, lambda r: re.sub(r"[^\n]*CGO_ENABLED=0\s+go build[^\n]*", ":", r))),
    ("no git diff", lambda d: swap_all_go(d, lambda r: r.replace("git diff", "git log"))),
    ("the test job skippable", lambda d: tj(d).__setitem__("if", "${{ github.actor != 'x' }}")),
    ("gosec back in ci.yml", lambda d: d["jobs"].__setitem__("gosec", {"name": "gosec", "runs-on": "ubuntu-latest", "steps": []})),
    ("coverage back in ci.yml", lambda d: d["jobs"].__setitem__("coverage", {"name": "coverage", "runs-on": "ubuntu-latest", "steps": []})),
    ("dependency-review back in ci.yml", lambda d: d["jobs"].__setitem__("dependency-review", {"runs-on": "ubuntu-latest", "steps": []})),
    ("allowlist-chain back in ci.yml", lambda d: d["jobs"].__setitem__("allowlist-chain", {"name": "allowlist-chain", "runs-on": "ubuntu-latest", "steps": []})),
    ("no selection step", lambda d: d["jobs"]["allowlist"].__setitem__("steps", [s for s in d["jobs"]["allowlist"]["steps"] if "select-tests.sh" not in (s.get("run") or "")])),
    ("two selection steps", lambda d: add_step(d, "allowlist", {"name": "again", "run": "bash bin/select-tests.sh origin/main HEAD"})),
    ("a suite run directly in the allowlist job", lambda d: add_step(d, "allowlist", {"name": "direct", "run": "bash bin/branch-sweep-test.sh"})),
    ("an auditor suite run directly", lambda d: add_step(d, "allowlist", {"name": "direct", "run": "bash " + AGENT + "tests/auditor-matrix-test.sh"})),
    ("the scanner guard step gone", lambda d: d["jobs"]["allowlist"].__setitem__("steps", [s for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() != GUARD])),
    ("the scanner guard step conditional", lambda d: [s.__setitem__("if", "github.actor != 'x'") for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() == GUARD]),
    ("the scanner guard step allowed to fail", lambda d: [s.__setitem__("continue-on-error", True) for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() == GUARD]),
    ("the scanner guard step renamed", lambda d: [s.__setitem__("name", "guard") for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() == GUARD]),
    ("the scanner guard step twice", lambda d: add_step(d, "allowlist", {"name": GUARD_NAME, "run": GUARD})),
    ("the allowlist check of tracked files gone", lambda d: [s.__setitem__("run", s["run"].replace("./bin/check-file-allowlist.sh", "true")) for s in d["jobs"]["allowlist"]["steps"] if s.get("run")]),
    ("the pin check gone", lambda d: [s.__setitem__("run", s["run"].replace("--verify-tags", "")) for s in d["jobs"]["allowlist"]["steps"] if s.get("run")]),
    ("the selection discarded", lambda d: sel_edit(d, lambda s: s.__setitem__("run", "bash bin/select-tests.sh origin/${{ github.base_ref }} HEAD >/dev/null"))),
    ("the selection run with its failures swallowed", lambda d: sel_edit(d, lambda s: s.__setitem__("run", "set +e\n" + re.sub(r"set -[euo]+( pipefail)?", "set +e", s["run"]) + "\nexit 0"))),
    ("the selection run word by word", lambda d: sel_edit(d, lambda s: s.__setitem__("run", "bash bin/select-tests.sh origin/${{ github.base_ref }} HEAD | xargs -n1 echo"))),
    ("the selection against the wrong base", lambda d: sel_edit(d, lambda s: s.__setitem__("run", re.sub(r"\S*base\S*", "HEAD~1", s["run"]).replace("HEAD~1 HEAD", "HEAD~1 HEAD") if "base" in s["run"] else s["run"] + " x"))),
])

# ------------------------------------------------------------------------------------------------------------------ AC5: full-suite.yml
MOVED = {"coverage": [r"go test .*-covermode=atomic.*\./\.\.\.", r"coverage-gate"],
         "fips140-only": [r"GODEBUG=fips140=only go test .*\./\.\.\."],
         "gosec": [r"gosec .*\./\.\.\."],
         "allowlist-persona": [r"bin/persona-uat-agent-test\.sh", r"bin/persona-uat-wiring-test\.sh", r"bin/persona-uat-test\.sh"],
         "allowlist-chain": [r"bin/build-helpers-test\.sh", r"bin/vendoring-test\.sh", r"bin/assemble-image-test\.sh", r"bin/install-scanner-test\.sh", r"bin/go-bump-open-pr-test\.sh"],
         "allowlist-pins-auditor": [r"bin/audit-record-test\.sh", r"bin/panel-test\.sh", r"bin/patch-decide-test\.sh", r"bin/job-isolation-test\.sh", r"bin/dependabot-reviewer-test\.sh"]}
def full_problems(w):
    if w is None: return [".github/workflows/full-suite.yml does not exist"]
    bad = []; on = w.get("on") or {}
    if not isinstance(on, dict) or sorted(on) != ["schedule", "workflow_call", "workflow_dispatch"]:
        bad.append("triggers are not exactly schedule, workflow_dispatch, workflow_call: %s" % (list(on) if isinstance(on, dict) else on))
    else:
        sch = on["schedule"]
        if not (isinstance(sch, list) and len(sch) == 1 and re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", str(sch[0].get("cron", "")).strip())):
            bad.append("the schedule is not one daily cron (minute hour * * *): %s" % sch)
    jobs = w.get("jobs") or {}
    for jid, rxs in MOVED.items():
        j = jobs.get(jid)
        if not j or j.get("name") != jid: bad.append("no job %s under its old name" % jid); continue
        if "if" in j: bad.append("%s has a job-level condition" % jid)
        text = "\n".join(r for _, r in runs(j))
        for rx in rxs:
            if not re.search(rx, text): bad.append("%s does not run its whole suite (no %s)" % (jid, rx))
        if "select-tests" in text: bad.append("%s runs a selection and not its whole suite" % jid)
    calls = [jid for jid, j in jobs.items() if j.get("uses") == "./.github/workflows/acceptance.yml"]
    if calls != ["acceptance"] or jobs["acceptance"].get("name", "acceptance") != "acceptance": bad.append("acceptance.yml is not called by exactly one job, id and name acceptance: %s" % calls)
    for jid, j in jobs.items():
        if str(j.get("uses", "")).endswith(("scan.yml", "codeql.yml")) or base(j.get("name") or jid) in ("scan", "analyze", "dependency-review"):
            bad.append("%s belongs to another workflow (scan and CodeQL keep their own)" % jid)
    return bad
verdict("full-suite.yml: a daily schedule, dispatch and call; the six moved jobs whole; acceptance called", full_problems(fs), True)
if fs is not None:
    mutants("full-suite.yml", full_problems, fs, [
        ("a pull_request trigger", lambda d: d["on"].__setitem__("pull_request", "")),
        ("a push trigger", lambda d: d["on"].__setitem__("push", {"branches": ["main"]})),
        ("a merge_group trigger", lambda d: d["on"].__setitem__("merge_group", "")),
        ("no workflow_call", lambda d: d["on"].pop("workflow_call")),
        ("no workflow_dispatch", lambda d: d["on"].pop("workflow_dispatch")),
        ("no schedule", lambda d: d["on"].pop("schedule")),
        ("two crons", lambda d: d["on"]["schedule"].append({"cron": "5 5 * * *"})),
        ("an hourly cron", lambda d: d["on"].__setitem__("schedule", [{"cron": "17 * * * *"}])),
        ("a weekly cron", lambda d: d["on"].__setitem__("schedule", [{"cron": "17 6 * * 1"}])),
        ("gosec renamed", lambda d: d["jobs"]["gosec"].__setitem__("name", "gosec scan")),
        ("coverage dropped", lambda d: d["jobs"].pop("coverage")),
        ("fips140-only dropped", lambda d: d["jobs"].pop("fips140-only")),
        ("allowlist-chain dropped", lambda d: d["jobs"].pop("allowlist-chain")),
        ("gosec skippable", lambda d: d["jobs"]["gosec"].__setitem__("if", "${{ github.event_name == 'workflow_dispatch' }}")),
        ("fips140-only over a selection", lambda d: d["jobs"]["fips140-only"]["steps"].append({"run": "bash bin/select-tests.sh a b"}) or [s.__setitem__("run", s["run"].replace("./...", "$PKGS")) for s in d["jobs"]["fips140-only"]["steps"] if s.get("run")]),
        ("allowlist-persona running one suite", lambda d: [s.__setitem__("run", "true") for s in d["jobs"]["allowlist-persona"]["steps"] if "persona-uat-test.sh" in (s.get("run") or "")]),
        ("allowlist-pins-auditor without the audit record suite", lambda d: [s.__setitem__("run", "true") for s in d["jobs"]["allowlist-pins-auditor"]["steps"] if "audit-record-test.sh" in (s.get("run") or "")]),
        ("coverage without -coverpkg over the tree", lambda d: [s.__setitem__("run", s["run"].replace("./...", "./cmd/...")) for s in d["jobs"]["coverage"]["steps"] if s.get("run")]),
        ("acceptance not called", lambda d: [d["jobs"].pop(k) for k in [k for k, j in d["jobs"].items() if j.get("uses") == "./.github/workflows/acceptance.yml"]]),
        ("acceptance called twice", lambda d: d["jobs"].__setitem__("again", {"uses": "./.github/workflows/acceptance.yml"})),
        ("a scan job in the full suite", lambda d: d["jobs"].__setitem__("scan", {"name": "scan", "runs-on": "ubuntu-latest", "steps": []})),
        ("a CodeQL job in the full suite", lambda d: d["jobs"].__setitem__("analyze", {"name": "analyze (go)", "runs-on": "ubuntu-latest", "steps": []})),
    ])
else:
    check("full-suite.yml mutants: not run, the file does not exist", False, "missing")

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
WFS = {n: load(WF + n) for n in ("full-suite.yml", "scan.yml", "codeql.yml") if os.path.exists(os.path.join(root, WF + n))}
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

# ------------------------------------------------------------------------------------------------------------------ AC7: admission
adm = load(WF + "stage-admission.yml")
STEP = "every required check green, app-pinned, per its scope"
hit = [s for s in adm["jobs"]["admit"]["steps"] if s.get("name") == STEP]
check("stage-admission.yml has the step %r exactly once" % STEP, len(hit) == 1, len(hit))
FAKE_ADM = r'''#!/usr/bin/env python3
import json, os, subprocess, sys
a = sys.argv[1:]
if a[0] != "api": sys.stderr.write("unexpected gh %s\n" % a); sys.exit(9)
path = a[1].split("?")[0]
f = os.path.join(os.environ["FX"], path.strip("/").replace("/", "_") + ".json")
if not os.path.exists(f):
    if path.endswith("/check-runs"): data = {"check_runs": []}
    elif path.endswith("/status"): data = {"statuses": []}
    elif path.endswith("/pulls"): data = []
    else: sys.stderr.write("gh: Not Found (HTTP 404) %s\n" % path); sys.exit(1)
else: data = json.load(open(f))
filt = [a[i + 1] for i, x in enumerate(a) if x in ("--jq", "-q") and i + 1 < len(a)]
if filt:
    r = subprocess.run(["jq", "-c", filt[0]], input=json.dumps(data), capture_output=True, text=True)
    sys.stdout.write(r.stdout); sys.stderr.write(r.stderr); sys.exit(r.returncode)
print(json.dumps(data))
'''
T, O, P = "1" * 40, "2" * 40, "3" * 40          # the tagged commit, an older commit, the head of the merged pull request
def admission(policy, mutate=None, tag="v0.3.0-rc.1", script=None):
    """run the admission check step; mutate(runs) edits {sha: [check runs]}; returns (rc, stderr+stdout)"""
    d = os.path.join(work, "adm%d" % len(os.listdir(work))); os.makedirs(d + "/fake"); os.makedirs(d + "/fx"); os.makedirs(d + "/policy")
    mkexec(d + "/fake/gh", FAKE_ADM)
    json.dump(policy, open(d + "/policy/required-checks.json", "w"))
    runs_by_sha = {T: [], P: [], O: []}; n = [100]
    for key in ("required_checks", "promotion_checks"):
        for e in policy.get(key, []):
            sha = P if e["scope"] == "pull_request" else T
            n[0] += 1; runs_by_sha[sha].append({"name": e["context"], "conclusion": "success", "app": {"id": e["integration_id"]}, "id": n[0], "head_sha": sha})
    if mutate: mutate(runs_by_sha)
    for sha, rs in runs_by_sha.items(): json.dump({"check_runs": rs}, open(d + "/fx/repos_o_r_commits_%s_check-runs.json" % sha, "w"))
    json.dump([{"number": 5, "merge_commit_sha": T, "base": {"ref": "main"}, "merged_at": "2026-11-12T00:00:00Z", "head": {"sha": P}}], open(d + "/fx/repos_o_r_commits_%s_pulls.json" % T, "w"))
    text = script if script is not None else hit[0]["run"]
    text = text.replace("/tmp/", d + "/")
    env = dict(os.environ, PATH=d + "/fake:" + os.environ["PATH"], FX=d + "/fx", GITHUB_REPOSITORY="o/r", GITHUB_SHA=T, GITHUB_REF_NAME=tag, GH_TOKEN="tok", GITHUB_OUTPUT=d + "/out")
    r = subprocess.run(["bash", "-e", "-c", text], capture_output=True, text=True, env=env, cwd=d)
    return r.returncode, r.stdout + r.stderr
def entry(c, scope="push", app=15368): return {"context": c, "integration_id": app, "scope": scope}
SYN = {"required_checks": [entry("test"), entry("lint"), entry("pin-age", "pull_request")],
       "promotion_checks": [entry("coverage"), entry("acceptance / acceptance-maven (1.2.0)"), entry("scan")]}
if len(hit) == 1:
    rc, out = admission(SYN); check("admission: a release candidate whose required and promotion checks are all green on the tagged commit is admitted", rc == 0, (rc, out[-300:]))
    rc, out = admission(POLICY)
    # the real policy: every context green where its scope says (the tagged commit, or the merged pull request's head)
    check("admission: the committed policy with all its checks green is admitted (a policy without promotion_checks cannot be judged)", rc == 0 and "promotion_checks" in POLICY, (rc, out[-300:]))
    def drop(ctx): return lambda R: [R[s].__setitem__(slice(None), [r for r in R[s] if r["name"] != ctx]) for s in R]
    def red(ctx, how): return lambda R: [r.__setitem__("conclusion", how) for s in R for r in R[s] if r["name"] == ctx]
    def older(ctx): return lambda R: [R[O].append(dict(r, head_sha=O)) for r in list(R[T]) if r["name"] == ctx] and R[T].__setitem__(slice(None), [r for r in R[T] if r["name"] != ctx])
    def otherapp(ctx): return lambda R: [r.__setitem__("app", {"id": 1}) for s in R for r in R[s] if r["name"] == ctx]
    for pol_name, pol in (("synthetic policy", SYN), ("committed policy", POLICY)):
        for e in pol.get("promotion_checks", []):
            c = e["context"]
            variants = (("has no run", drop(c)), ("is red (failure)", red(c, "failure")), ("was cancelled", red(c, "cancelled")), ("was skipped", red(c, "skipped")),
                        ("is only green on an older commit", older(c)), ("is green from another app", otherapp(c)))
            for why, mut in (variants if pol is SYN else variants[:2] + variants[4:5]):
                rc, out = admission(pol, mut)
                check("admission (%s): a release candidate whose promotion check %r %s is stopped, naming it" % (pol_name, c, why), rc != 0 and c in out, (rc, out[-300:]))
    for e in SYN["required_checks"]:
        rc, out = admission(SYN, drop(e["context"])); check("admission: a required check %r with no run is still stopped, naming it" % e["context"], rc != 0 and e["context"] in out, (rc, out[-200:]))
    rc, out = admission(SYN, tag="v0.3.0-rc.2", mutate=drop("scan")); check("admission: the second candidate of a line is held to the same rule", rc != 0 and "scan" in out, (rc, out[-200:]))
else:
    check("admission cases not run: the step is missing", False)
print("full-suite-wiring: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
