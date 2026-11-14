#!/usr/bin/env bash
# proves: REQ-CI-001-AC1, REQ-CI-001-AC4, REQ-CI-001-AC5, REQ-CI-001-AC6, REQ-CI-001-AC7
# Quick checks on each pull request, the full suite at promotion (REQ-CI-001; owner, Nov 10 2026), offline. Reads the real workflows and
# .github/policy/required-checks.json as data and judges each against the English; every judge is also run over mutated copies, each of which
# must be caught:
#   AC1  the required list is exactly seven contexts (auditor-review-gate, gosec and dependency-review not among them,
#        and no job makes gosec or dependency-review), none of them skippable by a job-level condition;
#        the promotion list holds the eleven of the full suite
#   AC4  ci.yml's test job vets, builds and tests only the changed packages (no -race, no fips settings); its allowlist job writes the suites
#        bin/select-tests.sh selects to a file and a step output, runs the single-file ones through the committed script bin/run-selected-tests.sh
#        (one plain line each, run here in a scratch tree), runs each of the four multi-file suites as its own step with an if: on that output,
#        and runs the allowlist of every tracked file and the action-pin checks (the contract is written above the AC4 cases below);
#        the test job's package step is run in a throwaway git repository (testdata, renames, tools/requirements)
#   AC5  full-suite.yml: a daily schedule, workflow_dispatch and workflow_call only; the five moved jobs under their
#        old names, each running its whole suite; one call of acceptance.yml; the whole wiring and selection
#        suites run in it too
#   AC6  full-suite.yml, scan.yml and codeql.yml end with a report-failure job for a failed scheduled run; its script is run here with a stand-in
#        for gh: it opens one issue with a fixed title and label, or comments on the open one, naming the run
#   AC7  stage-admission's check step, run here against a stand-in for gh: for a release-candidate tag every promotion_checks context must
#        have a successful run, by its app, on the exact tagged commit, from the one workflow file that produces it;
#        a missing, red, wrong-app, older-commit or wrong-source run stops it, naming the context;
#        full-suite.yml, scan.yml and codeql.yml each can run before the tag
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -I - "$root" "$work" <<'PY'
import copy, json, os, re, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)
def load(p): return yaml.load(open(os.path.join(root, p)), Loader=yaml.BaseLoader)
WF = ".github/workflows/"
ci = load(WF + "ci.yml")
fs = load(WF + "full-suite.yml") if os.path.exists(os.path.join(root, WF + "full-suite.yml")) else None
POLICY = json.load(open(os.path.join(root, ".github/policy/required-checks.json")))

REQUIRED = ["test", "lint", "requirements", "allowlist", "vendor", "govulncheck", "pin-age"]
PROMOTION = ["coverage", "fips140-only", "analyze (go)", "allowlist-persona", "allowlist-chain",
             "allowlist-pins-auditor",
             "acceptance / acceptance-gradle", "acceptance / acceptance-maven (1.2.0)",
             "acceptance / acceptance-maven (1.2.3)", "reproducibility", "scan"]
# deleted from the repository (docs/ratify/2026-11-13-ci-trim-keeps-codeql.md)
REMOVED = ["gosec", "dependency-review"]
def job_stub(name): return {"name": name, "runs-on": "ubuntu-latest", "steps": []}
def pol_entry(ctx, scope="push"): return {"context": ctx, "integration_id": 15368, "scope": scope}
GONE = PROMOTION + REMOVED + ["acceptance-gradle", "acceptance-maven"]
def base(ctx): return ctx.split(" (")[0]
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

# ------------------------------------------------------------------------------------------------------------------ AC1: the lists
SHAPE = {"context", "integration_id", "scope"}
def policy_problems(doc):
    bad = []
    rc, pc = doc.get("required_checks"), doc.get("promotion_checks")
    if not isinstance(rc, list) or not isinstance(pc, list): return ["required_checks or promotion_checks is not a list"]
    for key, lst in (("required_checks", rc), ("promotion_checks", pc)):
        for e in lst:
            if not isinstance(e, dict) or set(e) != SHAPE: bad.append("%s entry has not the shape context/integration_id/scope: %s" % (key, e)); continue
            if e["integration_id"] != 15368: bad.append("%s %r has integration_id %r" % (key, e["context"], e["integration_id"]))
    rc_names, pc_names = [e.get("context") for e in rc], [e.get("context") for e in pc]
    if sorted(rc_names) != sorted(REQUIRED): bad.append("required_checks are not exactly the seven: %s" % rc_names)
    if sorted(pc_names) != sorted(PROMOTION): bad.append("promotion_checks are not exactly the eleven: %s" % pc_names)
    for key, lst in (("required_checks", rc), ("promotion_checks", pc)):
        if any(isinstance(e, dict) and e.get("context") == "auditor-review-gate" for e in lst): bad.append("auditor-review-gate is listed in %s (REQ-CI-001-AC8)" % key)
    for key, lst in (("required_checks", rc), ("promotion_checks", pc)):
        for e in lst:
            if isinstance(e, dict) and e.get("context") in REMOVED:
                bad.append("%s lists %s, which no workflow makes" % (key, e["context"]))
    for e in pc:
        if isinstance(e, dict) and e.get("scope") != "push": bad.append("promotion check %r is not push-scoped (admission reads the exact tagged commit)" % e.get("context"))
    if set(doc) - {"comment", "required_checks", "promotion_checks"}: bad.append("unknown keys: %s" % sorted(set(doc) - {"comment", "required_checks", "promotion_checks"}))
    return bad
verdict("required-checks.json: seven required contexts, eleven promotion contexts, the entry shape of today",
        policy_problems(POLICY), True)
mutants("required-checks.json", policy_problems, POLICY, [
    ("gosec back in required_checks", lambda d: d["required_checks"].append({"context": "gosec", "integration_id": 15368, "scope": "push"})),
    ("dependency-review back in required_checks",
     lambda d: d["required_checks"].append(pol_entry("dependency-review", "pull_request"))),
    ("gosec back in promotion_checks", lambda d: d["promotion_checks"].append(pol_entry("gosec"))),
    ("lint dropped from required_checks", lambda d: d.__setitem__("required_checks", [e for e in d["required_checks"] if e["context"] != "lint"])),
    ("auditor-review-gate added back to required_checks", lambda d: d["required_checks"].append({"context": "auditor-review-gate", "integration_id": 5054756, "scope": "pull_request"})),
    ("auditor-review-gate (Actions app) added to required_checks", lambda d: d["required_checks"].append({"context": "auditor-review-gate", "integration_id": 15368, "scope": "pull_request"})),
    ("auditor-review-gate added to promotion_checks", lambda d: d["promotion_checks"].append({"context": "auditor-review-gate", "integration_id": 15368, "scope": "push"})),
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
    for ctx in REQUIRED:
        if ctx not in prc: bad.append("%s does not run on pull_request" % ctx)
        for fn, jid, j in prc.get(ctx, []):
            if "if" in j: bad.append("%s (%s:%s) has a job-level condition" % (ctx, fn, jid))
    for ctx in GONE:
        if base(ctx) in prc: bad.append("%s still runs on pull_request in %s" % (ctx, [f for f, _, _ in prc[base(ctx)]]))
    return bad
verdict("pull requests: seven required contexts run unconditionally, none of the removed ones runs",
        ac1_problems(prc), True)

# no workflow has a job that makes gosec or dependency-review, on any event (their contexts are in neither list)
def removed_job_problems(wfs):
    bad = []
    for fn, w in sorted(wfs.items()):
        for jid, j in (w.get("jobs") or {}).items():
            if jid in REMOVED or base(j.get("name") or jid) in REMOVED: bad.append("%s has the job %s" % (fn, jid))
    return bad
ALL = {fn: load(WF + fn) for fn in sorted(os.listdir(os.path.join(root, WF)))}
verdict("no workflow has a job named gosec or dependency-review", removed_job_problems(ALL), True)
for name, fn in (("gosec back in full-suite.yml",
                  lambda a: a["full-suite.yml"]["jobs"].__setitem__("gosec", job_stub("gosec"))),
                 ("dependency-review back in ci.yml",
                  lambda a: a["ci.yml"]["jobs"].__setitem__("dependency-review", job_stub("dependency-review"))),
                 ("a job of another id named gosec",
                  lambda a: a["scan.yml"]["jobs"].__setitem__("sec", job_stub("gosec")))):
    aa = copy.deepcopy(ALL); fn(aa)
    check("removed jobs: %s is refused" % name, removed_job_problems(aa) != [], "accepted")

for name, fn in (("test skippable", lambda p: p["test"][0][2].__setitem__("if", "${{ false }}")),
                 ("allowlist skippable", lambda p: p["allowlist"][0][2].__setitem__("if", "${{ github.actor != 'x' }}")),
                 ("pin-age skippable", lambda p: p["pin-age"][0][2].__setitem__("if", "${{ true }}")),
                 ("lint gone", lambda p: p.pop("lint")),
                 ("gosec on pull_request", lambda p: p.setdefault("gosec", []).append(("x.yml", "gosec", {}))),
                 ("dependency-review on pull_request",
                  lambda p: p.setdefault("dependency-review", []).append(("x.yml", "dependency-review", {}))),
                 ("scan on pull_request", lambda p: p.setdefault("scan", []).append(("x.yml", "scan", {}))),
                 ("acceptance-maven on pull_request", lambda p: p.setdefault("acceptance-maven", []).append(("x.yml", "m", {}))),
                 ("analyze on pull_request", lambda p: p.setdefault("analyze", []).append(("x.yml", "analyze", {})))):
    pp = copy.deepcopy(prc)
    try: fn(pp)
    except Exception as e:
        check("pull requests: %s can be made (the thing to mutate exists)" % name, False, repr(e)); continue
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
    for need in (r"go\\?\.mod", r"go\\?\.sum", "vendor/"):
        if not re.search(need, text): bad.append("the package step does not mention %s (every package when it changes)" % need)
    if "if" in job: bad.append("the test job has a job-level condition")
    # tools/requirements is its own Go module: vetted from inside it, never as a package of the root module
    if "go -C tools/requirements vet ./..." not in " ".join(text.split()):
        bad.append("the test job does not run go -C tools/requirements vet ./...")
    for l in cmd_lines(text, r"\bgo vet\b"):
        if "tools/requirements" in l:
            bad.append("tools/requirements is vetted as a package of the root module: %s" % l.strip())
    return bad
# The contract of the suites that a pull request selects (REQ-CI-001-AC4, ruling F1):
#   step `select` (id: select) of the allowlist job runs bin/select-tests.sh "origin/<base>" HEAD, writes its lines to a file under
#     $RUNNER_TEMP and sets the step output `suites` to those lines (the multi-line form name<<DELIMITER); a selector that fails fails the step;
#   step `the suites that are one test file` runs, from the repository root, `bash bin/run-selected-tests.sh <that file>`: ONE argument, the file;
#   bin/run-selected-tests.sh holds one single-line `if grep -qxF '<exact command>' "$selected"; then <that command>; fi` for each suite that is one
#     committed test file (the pattern is the command line as test-paths.json spells it); the vex-both-scanners line first runs ./bin/install-scanner.sh grype;
#     the lines run in SCRIPT order whatever the file's order, the first failing suite stops the script with its failure, an empty file passes and runs
#     nothing, a selected line that neither a line of the script nor a step covers fails the script and is named on stderr; the four commands that have
#     their own steps are covered by those steps, so the script lets them pass and runs nothing for them;
#   each of those four suites is a step of the job whose `if:` is contains(steps.select.outputs.suites, '<the suite's exact command>').
SEL_ID, SEL_OUT = "select", "suites"
PATHS = json.load(open(os.path.join(root, ".github/policy/test-paths.json")))
SUITES = list(dict.fromkeys(s for e in PATHS["entries"] for s in e["suites"]))
STEP_SUITES = {"pip": [s for s in SUITES if s.startswith("for r in ")],
               "panel": [s for s in SUITES if "test_panel_sdk_probe.py" in s],
               "vex-scope": [s for s in SUITES if "vex-scope-test.sh" in s],
               "jwt": [s for s in SUITES if "golang-jwt" in s]}
check("test-paths.json holds one command for each of the four suites that are their own steps", all(len(v) == 1 for v in STEP_SUITES.values()), STEP_SUITES)
STEP_SUITES = {k: (v[0] if v else "") for k, v in STEP_SUITES.items()}
SINGLE = [s for s in SUITES if s not in STEP_SUITES.values()]
VEX_BOTH = "bash bin/vex-both-scanners-test.sh"
STEP_MUST = {"pip": ["--dry-run", "adjudicator-requirements.txt", "coverage-requirements.txt", "test-requirements.txt"],
             "panel": ["python3 -m venv", "PANEL_SDK_TEST_REQUIRED=1", "test_panel_sdk_probe.py -v", "adjudicator-requirements.txt"],
             "vex-scope": ["./bin/install-scanner.sh grype", "bash bin/vex-scope-test.sh"],
             "jwt": ["! grep -q golang-jwt go.sum"]}
def suite_file(suite): return os.path.normpath(re.search(r"[\w./-]+\.(?:sh|py)\b", suite).group(0))
def suite_record(suite): return ("1" if suite.startswith("GRADLE_SUM_ONLINE=1 ") else "") + ":" + suite_file(suite)

def if_literal(step):
    """the command a step's if: names: contains(steps.select.outputs.suites, '<command>'), or None for any other condition"""
    cond = re.sub(r"^\$\{\{\s*(.*?)\s*\}\}$", r"\1", str(step.get("if", "")).strip(), flags=re.S)
    m = re.fullmatch(r"contains\(\s*steps\.%s\.outputs\.%s\s*,\s*'((?:[^']|'')*)'\s*\)" % (SEL_ID, SEL_OUT), cond, re.S)
    return m.group(1).replace("''", "'") if m else None
def step_outputs(text):
    out, lines, i = {}, text.splitlines(), 0
    while i < len(lines):
        m = re.match(r"([\w-]+)<<(\S+)$", lines[i])
        if m:
            end = next((j for j in range(i + 1, len(lines)) if lines[j] == m.group(2)), len(lines))
            out[m.group(1)] = "\n".join(lines[i + 1:end]); i = end + 1
        else:
            k, _, v = lines[i].partition("="); out[k] = v; i += 1
    return out

ALLOW_CHECK = "git ls-files | ./bin/check-file-allowlist.sh"
AGENT = ".github/" + "agent/"
PINS = "python3 " + AGENT + "bin/check-action-pins.py --verify-tags ."
TESTSH = re.compile(r"[\w./-]*-tests?\.sh\b")
GUARD = "bash bin/scan-no-workflow-call-test.sh"
GUARD_NAME = "scan.yml and main-candidate-rescan.yml are never callable as reusable workflows (REQ-SCAN-015-AC1)"
RUNNER = "bin/run-selected-tests.sh"
RUNNER_CALL = re.compile(r"^\s*(?:bash\s+)?" + re.escape(RUNNER) + r"\s+\S+\s*$")
SHELL_C = r"\b(?:ba|z|da)?sh\s+(?:-\w+\s+)*-\w*c\b|\beval\b"
def sel_steps(job): return [s for s, r in runs(job) if "select-tests.sh" in r]
def runner_steps(job): return [s for s, r in runs(job) if RUNNER in r]
def suite_steps(job): return [s for s in job.get("steps") or [] if if_literal(s) in STEP_SUITES.values()]
def runner_call_problems(step):
    """the step runs the script by its literal path with one argument: no shell -c, eval or variable standing for the program"""
    lines = [l for l in (step.get("run") or "").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    bad = []
    if not any(RUNNER_CALL.match(l) for l in lines): bad.append("no command line of the step runs %s by its literal path with one file argument" % RUNNER)
    if any(re.search(SHELL_C, l) for l in lines): bad.append("the step runs a command through a shell -c or eval")
    return bad
def suite_step_problems(job):
    bad = []
    for key, suite in STEP_SUITES.items():
        hit = [s for s in job.get("steps") or [] if if_literal(s) == suite]
        if len(hit) != 1: bad.append("%s: %d steps have an if: that names its exact command (one wanted)" % (key, len(hit))); continue
        run = hit[0].get("run") or ""
        for need in STEP_MUST[key]:
            if need not in run: bad.append("%s: its step does not write %r literally" % (key, need))
        if key == "pip" and re.search(r"\bfor\b|\$r\b", run): bad.append("pip: the step loops over the files and does not write one command for each")
        if RUNNER in run or re.search(SHELL_C, run): bad.append("%s: its step runs through the script or a shell -c" % key)
        if "continue-on-error" in hit[0]: bad.append("%s: its step may fail" % key)
    return bad
def allowlist_static(job):
    bad = []
    text = " ".join(re.sub(r"\s+", " ", r) for _, r in runs(job))
    if ALLOW_CHECK not in text: bad.append("the allowlist of every tracked file is gone: " + ALLOW_CHECK)
    if PINS not in text: bad.append("the action-pin check is gone: " + PINS)
    sel, ss = sel_steps(job), runner_steps(job)
    if len(sel) != 1 or sel[0].get("id") != SEL_ID: bad.append("no single step with id %s runs bin/select-tests.sh (%d steps)" % (SEL_ID, len(sel)))
    if len(ss) != 1: bad.append("the selected suites are not run in exactly one step (%d steps name %s)" % (len(ss), RUNNER))
    for s in ss: bad += runner_call_problems(s)
    for s in sel + ss:
        if "pull_request" not in str(s.get("if", "")): bad.append("step %r does not run on pull requests only" % s.get("name"))
    bad += suite_step_problems(job)
    order = job.get("steps") or []
    if sel and ss and any(s in order and order.index(s) < order.index(sel[0]) for s in ss + suite_steps(job)):
        bad.append("a step that reads the selection comes before the step that writes it")
    guards = [s for s, r in runs(job) if r.strip() == GUARD]
    if len(guards) != 1: bad.append("the allowlist job does not have exactly one scanner guard step running %s (%d)" % (GUARD, len(guards)))
    for g in guards:
        if g.get("name") != GUARD_NAME: bad.append("the scanner guard step is not named %r" % GUARD_NAME)
        if any(k in g for k in ("if", "continue-on-error", "shell", "env")): bad.append("the scanner guard step is conditional or weakened: " + ", ".join(k for k in ("if", "continue-on-error", "shell", "env") if k in g))
    for s, r in runs(job):
        if s not in sel + ss + guards + suite_steps(job) and TESTSH.search(r): bad.append("step %r runs a suite directly instead of through the selection" % s.get("name"))
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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(text); os.chmod(path, 0o755)
def selection_problems(job):
    """run the select step with a stand-in for bin/select-tests.sh, then the runner step with a stand-in for the script"""
    sel, ss = sel_steps(job), runner_steps(job)
    if len(sel) != 1 or len(ss) != 1: return ["no single select step and single runner step"]
    ctx = {"github.base_ref": "main", "github.event.pull_request.base.sha": "b" * 40, "github.event.pull_request.head.sha": "c" * 40,
           "github.sha": "c" * 40, "github.event_name": "pull_request", "github.head_ref": "feature"}
    def scenario(lines, select_rc=0, runner_rc=0):
        cwd = os.path.join(work, "sel%d" % len(os.listdir(work))); os.makedirs(cwd + "/tmp")
        mkexec(cwd + "/bin/select-tests.sh", "#!/usr/bin/env bash\necho \"$@\" > \"$SELECT_ARGS\"\nprintf '%%s' \"$SELECTED\"\nexit %d\n" % select_rc)
        mkexec(cwd + "/" + RUNNER, "#!/usr/bin/env bash\ncat \"$1\" > \"$SAW\"\nexit %d\n" % runner_rc)
        env = {"SELECTED": "".join(l + "\n" for l in lines), "SELECT_ARGS": cwd + "/select-args", "SAW": cwd + "/saw", "RUNNER_TEMP": cwd + "/tmp",
               "GITHUB_OUTPUT": cwd + "/out", "GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main"}
        open(cwd + "/out", "w").close()
        r1 = run_step(sel[0], env, ctx, cwd, job)
        r2 = run_step(ss[0], env, ctx, cwd, job) if r1.returncode == 0 else None
        read = lambda p: open(cwd + "/" + p).read() if os.path.exists(cwd + "/" + p) else None
        return r1, r2, step_outputs(read("out")).get(SEL_OUT), read("saw"), read("select-args")
    bad = []
    want = ["bash bin/a-test.sh", "python3 bin/b.py"]
    r1, r2, out, saw, args = scenario(want)
    if r1.returncode != 0 or r2 is None or r2.returncode != 0: bad.append("the select step or the runner step fails on a selection: %s %s" % (r1.stderr[-200:], r2 and r2.stderr[-200:]))
    if out is None or out.splitlines() != want: bad.append("the step output %s is not the selected lines: %r" % (SEL_OUT, out))
    if saw is None or saw.splitlines() != want: bad.append("the runner does not get a file of the selected lines, one per line: %r" % saw)
    if not args or not any(a in ("origin/main", "main") or "b" * 40 in a for a in args.split()): bad.append("the selection is not made against the pull request's base: %r" % args)
    r1, r2, out, saw, args = scenario([])
    if r1.returncode != 0 or r2 is None or r2.returncode != 0 or (out or "") != "" or saw != "": bad.append("an empty selection does not pass with an empty output and an empty file: out=%r saw=%r" % (out, saw))
    r1, r2, out, saw, args = scenario(want, select_rc=1)
    if r1.returncode == 0: bad.append("a selector that fails (a changed path with no entry) does not fail the select step")
    r1, r2, out, saw, args = scenario(want, runner_rc=1)
    if r2 is None or r2.returncode == 0: bad.append("a failing script does not fail the runner step")
    return bad
def ci_problems(w):
    jobs = w.get("jobs") or {}
    bad = []
    for ctx in REQUIRED[:6]:
        if (jobs.get(ctx) or {}).get("name") != ctx: bad.append("ci.yml has no job named %s" % ctx)
    for ctx in GONE:
        for jid, j in jobs.items():
            if base(j.get("name") or jid) == base(ctx): bad.append("ci.yml still has the job %s" % ctx)
    for jid, j in jobs.items():
        if str(j.get("uses", "")).endswith("full-suite.yml"):
            bad.append("ci.yml calls the full suite from the job %s (it never runs on a pull request)" % jid)
    bad += test_job_problems(jobs.get("test") or {"steps": []})
    al = jobs.get("allowlist") or {"steps": []}
    bad += allowlist_static(al)
    if not bad: bad += selection_problems(al)
    return bad
verdict("ci.yml: the seven-context layout, the changed-packages test job, the select step, the one script step and the four suite steps in the allowlist job",
        ci_problems(ci), True)

# bin/run-selected-tests.sh: run from the root of a scratch tree that holds a stand-in file for every suite (each records which ran in $LOG)
# and a stand-in bin/install-scanner.sh; FAIL names the suite file (or `install`) whose stand-in exits 1
TREE = os.path.join(work, "tree")
for suite in SUITES:
    m = re.search(r"[\w./-]+\.(?:sh|py)\b", suite)
    if m and suite not in (STEP_SUITES["pip"], STEP_SUITES["panel"], STEP_SUITES["jwt"]):
        record = '"${GRADLE_SUM_ONLINE:-}:%s" >> "$LOG"' % suite_file(suite)
        fails = '[ "${FAIL:-}" != "%s" ] || exit 1' % suite_file(suite)
        mkexec(os.path.join(TREE, suite_file(suite)), "#!/usr/bin/env bash\necho %s\n%s\n" % (record, fails))
mkexec(TREE + "/bin/install-scanner.sh", "#!/usr/bin/env bash\necho \"install $*\" >> \"$LOG\"\n[ \"${FAIL:-}\" != install ] || exit 1\n")
for suite in SUITES:     # .py stand-ins are run by python3, not by bash
    if suite not in (STEP_SUITES["pip"], STEP_SUITES["jwt"]) and suite_file(suite).endswith(".py") and os.path.exists(os.path.join(TREE, suite_file(suite))):
        mkexec(os.path.join(TREE, suite_file(suite)), "import os, sys\nopen(os.environ['LOG'], 'a').write(os.environ.get('GRADLE_SUM_ONLINE', '') + ':%s\\n')\nsys.exit(1 if os.environ.get('FAIL') == '%s' else 0)\n" % (suite_file(suite), suite_file(suite)))
subprocess.run("git init -q && git add -A", shell=True, cwd=TREE, check=True, capture_output=True)
RUNNER_TEXT = open(os.path.join(root, RUNNER)).read()
def runner_run(text, lines, fail=""):
    """returns (exit code, the lines the stand-ins logged, stdout and stderr)"""
    n = len(os.listdir(work)); selected = os.path.join(work, "selected%d" % n); log = os.path.join(work, "log%d" % n)
    open(selected, "w").write("".join(l + "\n" for l in lines)); open(log, "w").close()
    mkexec(os.path.join(TREE, RUNNER), text)
    r = subprocess.run(["bash", RUNNER, selected], capture_output=True, text=True, cwd=TREE, timeout=60, env=dict(os.environ, LOG=log, FAIL=fail))
    return r.returncode, open(log).read().splitlines(), r.stdout + r.stderr
FORBIDDEN = [(r"\bcd\b", "a cd"), (r"\bcase\b", "a case statement"), (SHELL_C, "a shell -c or eval"),
             (r"^\s*[\"{]?\$", "a variable standing for the program"), (r"\b(?:bash|sh|python3)\s+\"?\$", "a variable standing for the file run")]
GREP_LINE = re.compile(r"^if grep -qxF '([^']+)' \"\$\w+\"; then (.+); fi$")
def runner_shape_problems(text):
    bad = []
    for line in (l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")):
        for rx, what in FORBIDDEN:
            if re.search(rx, line): bad.append("the script has %s: %s" % (what, line.strip()))
        if line.startswith("if "):
            m = GREP_LINE.match(line)
            if not m: bad.append("an if line is not the plain one-line if that reads the file: %s" % line.strip())
            elif m.group(1) in STEP_SUITES.values(): bad.append("the script has a line for a suite that is its own step: %s" % m.group(1))
            elif suite_file(m.group(1)) not in m.group(2): bad.append("the line does not run the command it greps for: %s" % line.strip())
    return bad
def runner_problems(text, stop=False):
    """stop: return at the first problem (the mutated copies need no more)"""
    bad = runner_shape_problems(text)
    if bad and stop: return bad
    for s in SINGLE:
        if bad and stop: return bad
        rc, log, out = runner_run(text, [s])
        if rc != 0 or log != (["install grype"] if s == VEX_BOTH else []) + [suite_record(s)]: bad.append("%r selected alone: rc=%s ran %s" % (s, rc, log))
    if bad and stop: return bad
    a, b = SINGLE[0], SINGLE[-1]
    rc1, log1, _ = runner_run(text, [a, b]); rc2, log2, _ = runner_run(text, [b, a])
    if rc1 != 0 or rc2 != 0 or log1 != log2 or sorted(log1) != sorted([suite_record(a), suite_record(b)]):
        bad.append("the order of the lines is not the script's whatever the file's order: %s then %s" % (log1, log2))
    for fail in (a, b):
        rc, log, out = runner_run(text, [a, b], fail=suite_file(fail))
        if rc == 0 or not log or log[-1] != suite_record(fail): bad.append("a failing suite %r does not fail the script and stop it: rc=%s ran %s" % (fail, rc, log))
    rc, log, out = runner_run(text, SINGLE, fail="install")
    if rc == 0 or any(suite_file(VEX_BOTH) in l for l in log): bad.append("a failed grype install does not fail the script before the suite: rc=%s" % rc)
    for unknown in ("bash bin/no-such-test.sh", "bash bin/panel-test.sh --other-argument"):
        rc, log, out = runner_run(text, [unknown])
        if rc == 0 or unknown not in out or log: bad.append("an unknown selected command %r does not fail the script and get named: rc=%s out=%r" % (unknown, rc, out[-200:]))
    for s in STEP_SUITES.values():
        rc, log, out = runner_run(text, [s])
        if rc != 0 or log: bad.append("a suite that is its own step is run or refused by the script: %r rc=%s ran %s" % (s, rc, log))
    rc, log, out = runner_run(text, [])
    if rc != 0 or log: bad.append("an empty selection does not pass quietly: rc=%s ran %s" % (rc, log))
    return bad
verdict("bin/run-selected-tests.sh: one plain line for each single-file suite of test-paths.json, grype before the vex suite and only there, an unknown name fails",
        runner_problems(RUNNER_TEXT), True)
def before_first_if(text, line): return re.sub(r"^(if grep)", lambda m: line + "\n" + m.group(1), text, count=1, flags=re.M)
def runner_mutant(label, make):
    m = make(RUNNER_TEXT)
    if m == RUNNER_TEXT: check("bin/run-selected-tests.sh: a copy with %s can be made" % label, False, "nothing to change in the script"); return
    check("bin/run-selected-tests.sh: a copy with %s is refused" % label, runner_problems(m, stop=True) != [], "accepted")
def other_file(t): return re.sub(r"(grep -qxF 'bash bin/panel-test\.sh'[^\n]*?; then [^\n]*?)bin/panel-test\.sh", r"\1bin/panel-wiring-test.sh", t)
runner_mutant("the grype install gone", lambda t: re.sub(r"\./bin/install-scanner\.sh grype\s*(?:&&|;|\n)\s*", "", t))
runner_mutant("the grype install always run", lambda t: before_first_if(t, "./bin/install-scanner.sh grype"))
runner_mutant("a failing suite ignored by || true", lambda t: re.sub(r"; fi$", " || true; fi", t, flags=re.M))
runner_mutant("the suites run without -e", lambda t: re.sub(r"^set -[^\n]*\n", "", t, flags=re.M))
runner_mutant("the line of a suite dropped (a selected suite silently not run)", lambda t: re.sub(r"^.*grep -qxF 'bash bin/panel-test\.sh'.*\n", "", t, flags=re.M))
runner_mutant("an unknown selected name accepted", lambda t: re.sub(r"\b(?:exit|return)\s+[1-9]\d*", "exit 0", t))
runner_mutant("a line that runs another file than its grep names", other_file)
runner_mutant("a cd added", lambda t: before_first_if(t, "cd ."))
runner_mutant("a case statement added", lambda t: before_first_if(t, "case x in x) ;; esac"))
runner_mutant("an eval added", lambda t: before_first_if(t, "eval :"))
runner_mutant("a bash -c added", lambda t: before_first_if(t, "bash -c :"))
runner_mutant("a variable program added", lambda t: before_first_if(t, "prog=true\n$prog"))
runner_mutant("the vex-scope suite merged back into the script",
              lambda t: before_first_if(t, "if grep -qxF '%s' \"$1\"; then ./bin/install-scanner.sh grype; bash bin/vex-scope-test.sh; fi" % STEP_SUITES["vex-scope"]))

# the test job's package step, run in a throwaway git repository:
# the base commit holds FILES, then CHANGE(sh) makes the second commit
GO_SRC = "package p\n\nfunc One() int {\n\treturn 1\n}\n\nfunc Two() int {\n\treturn 2\n}\n"
def pkg_step(job):
    hit = [s for s in job.get("steps") or [] if s.get("name") == "the packages the change touches"]
    return hit[0] if len(hit) == 1 else None
def pkg_list(step, files, change):
    d = os.path.join(work, "pkgs%d" % len(os.listdir(work))); os.makedirs(d)
    def sh(cmd): subprocess.run(cmd, shell=True, cwd=d, check=True, capture_output=True)
    commit = "git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m c"
    sh("git init -q")
    for path, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(d, path)), exist_ok=True); open(os.path.join(d, path), "w").write(text)
    sh("git add -A && " + commit)
    change(sh)
    sh("git add -A && " + commit)
    out = os.path.join(d, "out"); open(out, "w").close()
    r = run_step(step, {"GITHUB_OUTPUT": out}, {}, d)
    lines = [l for l in open(out).read().splitlines() if l.startswith("list=")]
    return r.returncode, (sorted(lines[-1][5:].split()) if lines else None), r.stderr[-200:]
PKG_CASES = [
    ("a change in a package selects that package only", {"pkg/a/a.go": GO_SRC, "pkg/b/b.go": GO_SRC},
     lambda sh: sh("echo x >> pkg/a/a.go"), ["./pkg/a"]),
    ("a change under testdata/ selects the package that owns it (a .go file in testdata is no package)",
     {"pkg/a/a.go": GO_SRC},
     lambda sh: sh("mkdir -p pkg/a/testdata/src && echo 'package x' > pkg/a/testdata/src/x.go"), ["./pkg/a"]),
    ("a renamed Go file selects its old and its new package", {"pkg/old/old.go": GO_SRC, "pkg/old/keep.go": GO_SRC},
     lambda sh: sh("mkdir pkg/new && git mv pkg/old/old.go pkg/new/new.go"), ["./pkg/new", "./pkg/old"]),
    ("a change under tools/requirements is not a package of the root module",
     {"pkg/a/a.go": GO_SRC, "tools/requirements/main.go": GO_SRC},
     lambda sh: sh("echo x >> tools/requirements/main.go && echo x >> pkg/a/a.go"), ["./pkg/a"]),
]
def pkg_problems(step):
    bad = []
    for name, files, change, want in PKG_CASES:
        rc, got, err = pkg_list(step, files, change)
        if rc != 0 or got != want: bad.append("%s: rc=%s list=%s want %s %s" % (name, rc, got, want, err))
    return bad
pstep = pkg_step(ci["jobs"]["test"])
for name, files, change, want in PKG_CASES:
    if pstep is None:
        check("ci.yml test job: " + name, False, "no step named 'the packages the change touches'"); continue
    rc, got, err = pkg_list(pstep, files, change)
    check("ci.yml test job: " + name, rc == 0 and got == want, "rc=%s list=%s want %s %s" % (rc, got, want, err))
OLD_PKGS = r"""set -euo pipefail
changed=$(git diff --name-only HEAD^1 HEAD)
dirs=$(grep -v '^third_party/' <<< "${changed}" | grep -v '/testdata/' | xargs -r -d '\n' -n1 dirname |
  sort -u | while read -r d; do
  compgen -G "${d}/*.go" >/dev/null && echo "./${d}"
done || true)
echo "list=$(echo ${dirs})" >> "$GITHUB_OUTPUT"
"""
for name, text in (("the earlier script (testdata skipped, renames and tools/requirements not judged)", OLD_PKGS),
                   ("a step that always selects every package", 'echo "list=./..." >> "$GITHUB_OUTPUT"'),
                   ("a step that selects nothing", 'echo "list=" >> "$GITHUB_OUTPUT"')):
    check("package step: %s is refused" % name, pkg_problems({"run": text}) != [], "accepted")

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
def wrong_base(step):
    new = re.sub(r"\"?origin/\$\{?BASE\}?\"?", "HEAD~1", step["run"])
    if new == step["run"]: raise ValueError("the step does not diff against origin/${BASE}")
    step["run"] = new
def step_edit(d, pick, fn):
    hit = [s for s in d["jobs"]["allowlist"]["steps"] if pick(s)]
    if not hit: raise ValueError("no such step")
    for s in hit: fn(s)
def runner_edit(d, fn): step_edit(d, lambda s: RUNNER in (s.get("run") or ""), fn)
def select_edit(d, fn): step_edit(d, lambda s: "select-tests.sh" in (s.get("run") or ""), fn)
def suite_edit(d, key, fn): step_edit(d, lambda s: if_literal(s) == STEP_SUITES[key], fn)
def set_run(text): return lambda s: s.__setitem__("run", text)
def drop_steps(d, pick): d["jobs"]["allowlist"]["steps"] = [s for s in d["jobs"]["allowlist"]["steps"] if not pick(s)]
ARG = '"${RUNNER_TEMP}/selected-suites"'
def names(suite): return lambda s: s.__setitem__("if", "${{ contains(steps.%s.outputs.%s, '%s') }}" % (SEL_ID, SEL_OUT, suite.replace("'", "''")))
suite_mutants = []
for key, suite in STEP_SUITES.items():
    other = [v for v in STEP_SUITES.values() if v != suite][0]
    suite_mutants += [
        ("the %s step losing its if" % key, lambda d, key=key: suite_edit(d, key, lambda s: s.pop("if"))),
        ("the %s step's if naming a single-file suite" % key, lambda d, key=key: suite_edit(d, key, names("bash bin/panel-test.sh"))),
        ("the %s step's if naming the suite of another step" % key, lambda d, key=key, other=other: suite_edit(d, key, names(other))),
        ("the %s step merged back into the script path" % key, lambda d, key=key: suite_edit(d, key, set_run("bash bin/run-selected-tests.sh " + ARG))),
        ("the %s step gone" % key, lambda d, suite=suite: drop_steps(d, lambda s: if_literal(s) == suite)),
    ]
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
    ("dependency-review back in ci.yml",
     lambda d: d["jobs"].__setitem__("dependency-review", job_stub("dependency-review"))),
    ("the full suite called from ci.yml",
     lambda d: d["jobs"].__setitem__("full", {"uses": "./.github/workflows/full-suite.yml"})),
    ("tools/requirements vetted from the root",
     lambda d: add_step(d, "test", {"name": "vet", "run": "go vet ./tools/requirements"})),
    ("no vet inside tools/requirements",
     lambda d: swap_all_go(d, lambda r: re.sub(r"[^\n]*go -C tools/requirements vet[^\n]*", ":", r))),
    ("allowlist-chain back in ci.yml", lambda d: d["jobs"].__setitem__("allowlist-chain", {"name": "allowlist-chain", "runs-on": "ubuntu-latest", "steps": []})),
    ("no select step", lambda d: drop_steps(d, lambda s: "select-tests.sh" in (s.get("run") or ""))),
    ("no step that runs the script", lambda d: drop_steps(d, lambda s: RUNNER in (s.get("run") or ""))),
    ("two steps that run the script", lambda d: add_step(d, "allowlist", {"name": "again", "if": "${{ github.event_name == 'pull_request' }}", "run": "bash bin/run-selected-tests.sh " + ARG})),
    ("the select step without its id", lambda d: select_edit(d, lambda s: s.pop("id"))),
    ("the select step setting no output named suites", lambda d: select_edit(d, lambda s: s.__setitem__("run", s["run"].replace("GITHUB_OUTPUT", "GITHUB_ENV")))),
    ("the select step swallowing a failing selector", lambda d: select_edit(d, lambda s: s.__setitem__("run", "set +e\n" + s["run"] + "\nexit 0"))),
    ("the select step run on pushes too", lambda d: select_edit(d, lambda s: s.pop("if"))),
    ("the script step run on pushes too", lambda d: runner_edit(d, lambda s: s.pop("if"))),
    ("the script given another file than the one written", lambda d: runner_edit(d, lambda s: s.__setitem__("run", re.sub(r"(run-selected-tests\.sh\s+).*", r"\1/nonexistent", s["run"])))),
    ("the script given no file", lambda d: runner_edit(d, lambda s: s.__setitem__("run", "bash bin/run-selected-tests.sh"))),
    ("the script step before the select step", lambda d: d["jobs"]["allowlist"]["steps"].insert(0, d["jobs"]["allowlist"]["steps"].pop(next(i for i, s in enumerate(d["jobs"]["allowlist"]["steps"]) if RUNNER in (s.get("run") or ""))))),
    ("a suite run directly in the allowlist job", lambda d: add_step(d, "allowlist", {"name": "direct", "run": "bash bin/branch-sweep-test.sh"})),
    ("an auditor suite run directly", lambda d: add_step(d, "allowlist", {"name": "direct", "run": "bash " + AGENT + "tests/auditor-matrix-test.sh"})),
    ("the scanner guard step gone", lambda d: d["jobs"]["allowlist"].__setitem__("steps", [s for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() != GUARD])),
    ("the scanner guard step conditional", lambda d: [s.__setitem__("if", "github.actor != 'x'") for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() == GUARD]),
    ("the scanner guard step allowed to fail", lambda d: [s.__setitem__("continue-on-error", True) for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() == GUARD]),
    ("the scanner guard step renamed", lambda d: [s.__setitem__("name", "guard") for s in d["jobs"]["allowlist"]["steps"] if (s.get("run") or "").strip() == GUARD]),
    ("the scanner guard step twice", lambda d: add_step(d, "allowlist", {"name": GUARD_NAME, "run": GUARD})),
    ("the allowlist check of tracked files gone", lambda d: [s.__setitem__("run", s["run"].replace("./bin/check-file-allowlist.sh", "true")) for s in d["jobs"]["allowlist"]["steps"] if s.get("run")]),
    ("the pin check gone", lambda d: [s.__setitem__("run", s["run"].replace("--verify-tags", "")) for s in d["jobs"]["allowlist"]["steps"] if s.get("run")]),
    ("the script run with its failure swallowed by || true", lambda d: runner_edit(d, set_run("bash bin/run-selected-tests.sh " + ARG + " || true"))),
    ("the script run with its failures swallowed", lambda d: runner_edit(d, set_run("set +e\nbash bin/run-selected-tests.sh " + ARG + "\nexit 0"))),
    ("the script named only in an echo", lambda d: runner_edit(d, set_run("echo bin/run-selected-tests.sh " + ARG))),
    ("the script reached through a variable", lambda d: runner_edit(d, set_run("runner=bin/run-selected-tests.sh\nbash \"${runner}\" " + ARG))),
    ("the script run through bash -c", lambda d: runner_edit(d, set_run("bash -c \"bash bin/run-selected-tests.sh " + ARG + "\""))),
    ("the selected lines run by the step itself through bash -c", lambda d: runner_edit(d, set_run("# bin/run-selected-tests.sh\nwhile read -r suite; do bash -c \"${suite}\"; done < " + ARG))),
    ("the selection against the parent commit, not the pull request's base", lambda d: select_edit(d, wrong_base)),
] + suite_mutants)

# ------------------------------------------------------------------------------------------------------------------ AC5: full-suite.yml
MOVED = {"coverage": [r"go test .*-covermode=atomic.*\./\.\.\.", r"coverage-gate"],
         "fips140-only": [r"GODEBUG=fips140=only go test .*\./\.\.\."],
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
    # the two long wiring suites are run whole by some job of this workflow
    all_runs = "\n".join(r for j in jobs.values() for _, r in runs(j))
    for suite in ("bin/full-suite-wiring-test.sh", "bin/select-tests-test.sh"):
        lines = cmd_lines(all_runs, re.escape(suite))
        if not any(re.search(r"\bbash\s+(\./)?%s\s*$" % re.escape(suite), l.strip()) for l in lines):
            bad.append("no job runs %s whole" % suite)
    calls = [jid for jid, j in jobs.items() if j.get("uses") == "./.github/workflows/acceptance.yml"]
    if calls != ["acceptance"] or jobs["acceptance"].get("name", "acceptance") != "acceptance": bad.append("acceptance.yml is not called by exactly one job, id and name acceptance: %s" % calls)
    for jid, j in jobs.items():
        other_workflow = str(j.get("uses", "")).endswith(("scan.yml", "codeql.yml"))
        if other_workflow or base(j.get("name") or jid) in ("scan", "analyze") + tuple(REMOVED):
            bad.append("%s belongs to another workflow (scan and CodeQL keep their own)" % jid)
    return bad
verdict("full-suite.yml: a daily schedule, dispatch and call; the five moved jobs whole; the two wiring suites; "
        "acceptance called; no gosec", full_problems(fs), True)
def turn_off(d, suite):
    hit = [s for j in d["jobs"].values() for s in j.get("steps") or [] if suite in (s.get("run") or "")]
    if not hit: raise ValueError("no step runs " + suite)
    for s in hit: s["run"] = "true"
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
        ("coverage renamed", lambda d: d["jobs"]["coverage"].__setitem__("name", "coverage run")),
        ("a gosec job back in the full suite", lambda d: d["jobs"].__setitem__("gosec", job_stub("gosec"))),
        ("a dependency-review job in the full suite",
         lambda d: d["jobs"].__setitem__("dependency-review", job_stub("dependency-review"))),
        ("the wiring suite turned off", lambda d: turn_off(d, "full-suite-wiring-test.sh")),
        ("the selection suite turned off", lambda d: turn_off(d, "select-tests-test.sh")),
        ("coverage dropped", lambda d: d["jobs"].pop("coverage")),
        ("fips140-only dropped", lambda d: d["jobs"].pop("fips140-only")),
        ("allowlist-chain dropped", lambda d: d["jobs"].pop("allowlist-chain")),
        ("coverage skippable",
         lambda d: d["jobs"]["coverage"].__setitem__("if", "${{ github.event_name == 'workflow_dispatch' }}")),
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

# ---------------------------------------------------------------------------------- AC7: a run before the tag
# the tag push alone is too late: admission reads runs on the tagged commit, so each workflow of the full suite
# must also start from a schedule, a manual dispatch or a push to main (workflow_call and a tag push do not count)
def early_run_problems(w, name):
    on = w.get("on") or {}
    if not isinstance(on, dict): return ["%s has no trigger that can run before its tag: %s" % (name, on)]
    push = on.get("push")
    on_main = isinstance(push, dict) and "main" in (push.get("branches") or [])
    if "schedule" in on or "workflow_dispatch" in on or on_main: return []
    return ["%s starts only from %s: no run on a commit exists before its release-candidate tag" % (name, sorted(on))]
for n in ("full-suite.yml", "scan.yml", "codeql.yml"):
    if n not in WFS: check("%s can run before the tag" % n, False, "no such workflow"); continue
    verdict("%s: a schedule, workflow_dispatch or push to main lets a run exist before its release-candidate tag" % n,
            early_run_problems(WFS[n], n), True)
    mutants(n, lambda d, n=n: early_run_problems(d, n), WFS[n], [
        ("only a tag push", lambda d: d.__setitem__("on", {"push": {"tags": ["v*"]}})),
        ("only workflow_call", lambda d: d.__setitem__("on", {"workflow_call": ""})),
        ("a push of other branches", lambda d: d.__setitem__("on", {"push": {"branches": ["release/*"]}})),
    ])

# ---------------------------------------------------------------------------------- AC7: admission
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
    # gh prints a string result without its quotes; every other result stays one compact JSON value per line
    for line in r.stdout.splitlines(): print(json.loads(line) if line.startswith('"') else line)
    sys.stderr.write(r.stderr); sys.exit(r.returncode)
print(json.dumps(data))
'''
T, O, P = "1" * 40, "2" * 40, "3" * 40          # the tagged commit, an older commit, the head of the merged pull request
# the workflow file that produces each context: the full suite's contexts come from full-suite.yml,
# but analyze (go) from codeql.yml and reproducibility and scan from scan.yml; the quick checks come from ci.yml
SOURCE = {"analyze (go)": "codeql.yml", "reproducibility": "scan.yml", "scan": "scan.yml"}
def source_of(policy, key, ctx):
    return SOURCE.get(ctx, "full-suite.yml") if key == "promotion_checks" else "ci.yml"
def admission(policy, mutate=None, tag="v0.3.0-rc.1", script=None, paths=None, no_details=(), no_run=()):
    """run the admission check step; mutate(runs) edits {sha: [check runs]}; returns (rc, stderr+stdout)
    paths {context: workflow file}: whose run backs a check; no_details: contexts whose check run names no workflow run;
    no_run: contexts whose workflow run answers 404"""
    d = os.path.join(work, "adm%d" % len(os.listdir(work))); os.makedirs(d + "/fake"); os.makedirs(d + "/fx"); os.makedirs(d + "/policy")
    mkexec(d + "/fake/gh", FAKE_ADM)
    json.dump(policy, open(d + "/policy/required-checks.json", "w"))
    runs_by_sha = {T: [], P: [], O: []}; n = [100]; workflow_runs = {}
    for key in ("required_checks", "promotion_checks"):
        for e in policy.get(key, []):
            sha = P if e["scope"] == "pull_request" else T
            ctx = e["context"]; n[0] += 1
            run_id = 9000 + n[0]
            url = "https://github.com/o/r/actions/runs/%d/job/%d" % (run_id, n[0])
            if ctx in no_details: url = "https://example.com/checks/%d" % n[0]
            runs_by_sha[sha].append({"name": ctx, "conclusion": "success", "app": {"id": e["integration_id"]},
                                     "id": n[0], "head_sha": sha, "details_url": url})
            if ctx not in no_run:
                workflow_runs[run_id] = ".github/workflows/" + (paths or {}).get(ctx, source_of(policy, key, ctx))
    for run_id, path in workflow_runs.items():
        json.dump({"id": run_id, "path": path}, open(d + "/fx/repos_o_r_actions_runs_%d.json" % run_id, "w"))
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
    # a promotion context is taken only from the workflow file that produces it (REQ-CI-001-AC7)
    def stopped(what, ctx, res): check("admission: %s is stopped, naming it" % what, res[0] != 0 and ctx in res[1], res)
    for e in POLICY.get("promotion_checks", []):
        c = e["context"]
        stopped("the promotion check %r backed by a run of ci.yml" % c, c, admission(POLICY, paths={c: "ci.yml"}))
    for c, wrong in (("scan", "full-suite.yml"), ("reproducibility", "full-suite.yml"), ("analyze (go)", "scan.yml"),
                     ("coverage", "codeql.yml"), ("acceptance / acceptance-gradle", "scan.yml")):
        stopped("%r backed by a run of %s, not its own workflow file" % (c, wrong), c,
                admission(POLICY, paths={c: wrong}))
    # release.yml also has jobs of these names (acceptance, reproducibility): they never count, stage-admission refuses them by path
    for c in ("reproducibility", "acceptance / acceptance-gradle"):
        stopped("%r backed by a run of release.yml, a job of the same name in another workflow file" % c, c,
                admission(POLICY, paths={c: "release.yml"}))
    for c in ("coverage", "scan"):
        stopped("%r whose check run points at no workflow run" % c, c, admission(POLICY, no_details=(c,)))
        stopped("%r whose workflow run cannot be read" % c, c, admission(POLICY, no_run=(c,)))
    def on_pr_head(ctx):
        def move(R):
            R[P] += [dict(r, head_sha=P) for r in R[T] if r["name"] == ctx]
            R[T][:] = [r for r in R[T] if r["name"] != ctx]
        return move
    stopped("'coverage' green only on the merged pull request's head, not the tagged commit", "coverage",
            admission(POLICY, on_pr_head("coverage")))
    rc, out = admission(SYN, tag="v0.3.0-rc.2", mutate=drop("scan")); check("admission: the second candidate of a line is held to the same rule", rc != 0 and "scan" in out, (rc, out[-200:]))
else:
    check("admission cases not run: the step is missing", False)
print("full-suite-wiring: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
