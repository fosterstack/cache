#!/usr/bin/env bash
# proves: REQ-REL-014-AC1, REQ-REL-014-AC2, REQ-REL-014-AC3
# Pull requests run six checks; the rest run on push to main (owner, Nov 17 2026). Read from the PARSED workflow files:
#   AC1  the jobs that run on the pull_request event (a workflow's `on:` keys and each job's `if` and `needs` decide) are
#        test, lint, govulncheck, analyze (go), fips140-only and scan, the jobs scan needs, and the jobs of the two
#        untouched workflows (agent-review-gate.yml, dependabot-auto-merge.yml); every other job of ci.yml, scan.yml,
#        acceptance.yml still runs on push to main; supply-chain.yml has no job on a pull request or a push.
#   AC2  supply-chain.yml (the daily audit) has no push, pull_request, pull_request_target or workflow_run trigger: the
#        pin-age pull-request scan was deleted. dependency-review (ci.yml) runs on push to main only and judges the commit
#        before the push (github.event.before) to the commit after it (github.sha) through its base-ref and head-ref.
#   AC3  required-checks.json scopes dependency-review to push, and release admission's own step (run from
#        stage-admission.yml against a stub of the GitHub API) refuses a tag whose commit has a red or missing run of any
#        push-scoped check, dependency-review included.
# The real files must pass and each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
export PRC_ROOT="$root" PRC_WORK="$work"
python3 - <<'PY'
import copy, glob, json, os, re, shutil, subprocess, sys, yaml

root, work = os.environ["PRC_ROOT"], os.environ["PRC_WORK"]
WF = os.path.join(root, ".github/workflows")
passed = failed = 0


def check(name, ok, got=""):
    global passed, failed
    if ok:
        passed += 1; print("PASS", name)
    else:
        failed += 1; print("FAIL", name, "->", got)


def load(path): return yaml.load(open(path), Loader=yaml.BaseLoader)


def workflows(d):
    return {os.path.basename(p): load(p) for p in sorted(glob.glob(os.path.join(d, "*.yml")))}


# ---- a small evaluator of a job's `if`: True, False, or None (unknown: the job may run) --------------------------------
TOK = re.compile(r"\s*(==|!=|&&|\|\||!|\(|\)|,|'[^']*'|[A-Za-z_][\w.\-\[\]*]*|\d+)")
STATUS = {"always": True, "success": True, "failure": False, "cancelled": False}


def evaluate(cond, event):
    if cond is None:
        return True
    s = str(cond).strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", s, re.S)
    s = m.group(1) if m else s
    toks, pos = [], 0
    while pos < len(s.rstrip()):
        m = TOK.match(s, pos)
        if not m:
            return None
        toks.append(m.group(1)); pos = m.end()
    i = 0

    def peek(): return toks[i] if i < len(toks) else None

    def take():
        nonlocal i
        i += 1; return toks[i - 1]

    def p_or():
        v = p_and()
        while peek() == "||":
            take(); r = p_and()
            v = True if (v is True or r is True) else (None if (v is None or r is None) else False)
        return v

    def p_and():
        v = p_not()
        while peek() == "&&":
            take(); r = p_not()
            v = False if (v is False or r is False) else (None if (v is None or r is None) else True)
        return v

    def p_not():
        if peek() == "!":
            take(); v = p_not()
            return None if v is None else (not v)
        return p_cmp()

    def p_cmp():
        a = p_atom()
        if peek() in ("==", "!="):
            op = take(); b = p_atom()
            if a is None or b is None:
                return None
            return (a == b) if op == "==" else (a != b)
        return a

    def p_atom():
        t = take()
        if t == "(":
            v = p_or(); take(); return v
        if t.startswith("'"):
            return t[1:-1]
        if t in ("true", "false"):
            return t == "true"
        if t == "github.event_name":
            return event
        if peek() == "(":
            take()
            while peek() != ")":
                take()
            take()
            return STATUS.get(t) if t in STATUS else None
        return None
    try:
        v = p_or()
    except (IndexError, ValueError):
        return None
    return v if v is None or isinstance(v, bool) else bool(v)


def events_of(w):
    on = w.get("on")
    return set(on) if isinstance(on, (dict, list)) else {on}


def runs_on(w, event):
    """job ids of workflow w that run for `event`: the trigger exists, the job's own `if` is not false, every need ran."""
    if event not in events_of(w):
        return set()
    jobs, ran, todo = w.get("jobs") or {}, set(), True
    while todo:
        todo = False
        for jid, j in jobs.items():
            if jid in ran:
                continue
            cond = j.get("if")
            ignores_needs = re.search(r"always\(\)|cancelled\(\)|failure\(\)", str(cond or ""))
            needs = j.get("needs") or []
            needs = [needs] if isinstance(needs, str) else needs
            if evaluate(cond, event) is not False and (ignores_needs or all(n in ran for n in needs)):
                ran.add(jid); todo = True
    return ran


def pr_jobs(wfs):
    out = set()
    for f, w in wfs.items():
        for ev in ("pull_request", "pull_request_target"):
            out |= {f"{f}:{j}" for j in runs_on(w, ev)}
    return out


def closure(w, jid):
    seen, stack = set(), [jid]
    while stack:
        n = stack.pop()
        needs = (w["jobs"].get(n) or {}).get("needs") or []
        for m in ([needs] if isinstance(needs, str) else needs):
            if m not in seen:
                seen.add(m); stack.append(m)
    return seen


SIX = {"ci.yml:test", "ci.yml:lint", "ci.yml:govulncheck", "ci.yml:fips140-only", "codeql.yml:analyze", "scan.yml:scan"}
SIX_NAMES = {"test", "lint", "govulncheck", "analyze (go)", "fips140-only", "scan"}
UNTOUCHED = {"agent-review-gate.yml:judge", "agent-review-gate.yml:publish", "dependabot-auto-merge.yml:auto-merge"}


def judge_ac1(wfs):
    bad = []
    scan = wfs["scan.yml"]
    wanted = SIX | {f"scan.yml:{n}" for n in closure(scan, "scan")} | UNTOUCHED
    if wanted - SIX - UNTOUCHED != {"scan.yml:build", "scan.yml:assemble", "scan.yml:scanners", "scan.yml:scanner"}:
        bad.append("scan no longer needs exactly build, assemble, the scanner list and the scanners: %s" % sorted(wanted))
    got = pr_jobs(wfs)
    if got - wanted:
        bad.append("jobs that run on a pull request and should not: %s" % sorted(got - wanted))
    if wanted - got:
        bad.append("jobs that no longer run on a pull request: %s" % sorted(wanted - got))
    names = {(wfs[f]["jobs"][j].get("name") or j) for f, j in (x.split(":") for x in SIX)}
    if names != SIX_NAMES:
        bad.append("the six jobs' check names are not %s: %s" % (sorted(SIX_NAMES), sorted(names)))
    # the checks that left the pull request still run on push to main (and so on the exact tagged commit)
    for f in ("ci.yml", "scan.yml", "acceptance.yml"):
        lost = set(wfs[f]["jobs"]) - runs_on(wfs[f], "push")
        if lost:
            bad.append("%s jobs that no longer run on push to main: %s" % (f, sorted(lost)))
    return bad


def judge_ac2(wfs):
    bad = []
    sc = wfs["supply-chain.yml"]
    for ev in ("push", "pull_request", "pull_request_target", "workflow_run"):
        if ev in events_of(sc):
            bad.append("supply-chain.yml still has the %s trigger" % ev)
    if "pin-age" in (sc.get("jobs") or {}):
        bad.append("supply-chain.yml still has the pin-age job")
    ci = wfs["ci.yml"]["jobs"]["dependency-review"]
    if evaluate(ci.get("if"), "push") is False:
        bad.append("ci.yml's dependency-review is skipped on push")
    act = [s for s in ci.get("steps") or [] if str(s.get("uses", "")).startswith("actions/dependency-review-action@")]
    w = (act[0].get("with") or {}) if act else {}
    if w.get("base-ref") != "${{ github.event.before }}" or w.get("head-ref") != "${{ github.sha }}":
        bad.append("dependency-review does not judge github.event.before to github.sha: %s" % w)
    return bad


# ---- mutated copies of the real workflows ------------------------------------------------------------------------------
def mutated(fname, edit):
    d = os.path.join(work, "wf%d" % (passed + failed)); shutil.copytree(WF, d)
    w = load(os.path.join(d, fname))
    exec(edit, {"d": w, "J": w.get("jobs")})
    yaml.safe_dump(w, open(os.path.join(d, fname), "w"), sort_keys=False)
    return workflows(d)


real = workflows(WF)
NOPR = "github.event_name != 'pull_request'"
# the evaluator itself
for cond, ev, want in [(None, "pull_request", True), ("${{ github.event_name != 'pull_request' }}", "pull_request", False),
                       ("${{ github.event_name != 'pull_request' }}", "push", True), ("github.event_name == 'pull_request'", "push", False),
                       ("always()", "pull_request", True), ("${{ vars.X == 'true' && github.event_name == 'push' }}", "pull_request", False),
                       ("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", "pull_request", False),
                       ("!cancelled() && github.event_name == 'push'", "push", True), ("inputs.x != ''", "push", None)]:
    check("evaluator: %s on %s -> %s" % (cond, ev, want), evaluate(cond, ev) is want, evaluate(cond, ev))

# AC1
bad = judge_ac1(real)
check("AC1 the real workflows: the pull_request job list is the six, scan's needs and the two untouched workflows", not bad, "; ".join(bad))
for name, f, edit, want_bad in [
    ("gosec-on-pull-request", "ci.yml", "J['gosec'].pop('if', None)", True),
    ("test-skipped-on-pull-request", "ci.yml", "J['test']['if'] = \"github.event_name != 'pull_request'\"", True),
    ("vendored-job-unconditional", "ci.yml", "J['ven' + 'dor'].pop('if', None)", True),
    ("dependency-review-on-pull-request", "ci.yml", "J['dependency-review']['if'] = \"${{ github.event_name == 'pull_request' }}\"", True),
    ("reproducibility-on-pull-request", "scan.yml", "J['reproducibility'].pop('if', None); J['assemble-b'].pop('if', None)", True),
    ("artifact-acceptance-on-pull-request", "scan.yml", "J['artifact-acceptance'].pop('if', None)", True),
    ("acceptance-on-pull-request", "acceptance.yml", "d['on']['pull_request'] = ''", True),
    ("codeql-off-pull-request", "codeql.yml", "d['on'].pop('pull_request')", True),
    ("supply-chain-on-pull-request", "supply-chain.yml", "d['on']['pull_request'] = {}; J['daily-audit'].pop('if')", True),
    ("scan-off-pull-request", "scan.yml", "d['on'].pop('pull_request')", True),
    ("scan-dropped-from-push", "scan.yml", "d['on'].pop('push')", True),
    ("review-gate-job-added", "agent-review-gate.yml", "J['sweep'].pop('if')", True),
]:
    got = judge_ac1(mutated(f, edit))
    check("AC1 mutant %s is caught" % name, bool(got) == want_bad, got)

# AC2
bad = judge_ac2(real)
check("AC2 the real workflows: supply-chain.yml has no pull-request or push trigger; dependency-review runs on push to main and judges before..sha", not bad, "; ".join(bad))
for name, f, edit in [
    ("pull-request-trigger-back", "supply-chain.yml", "d['on']['pull_request'] = {}"),
    ("push-trigger-back", "supply-chain.yml", "d['on']['push'] = {'branches': ['main']}"),
    ("pin-age-job-back", "supply-chain.yml", "J['pin-age'] = J['daily-audit']"),
    ("review-skipped-on-push", "ci.yml", "J['dependency-review']['if'] = \"${{ github.event_name == 'pull_request' }}\""),
    ("review-base-ref-dropped", "ci.yml", "[s.setdefault('with', {}).pop('base-ref', None) for s in J['dependency-review']['steps'] if str(s.get('uses','')).startswith('actions/dependency-review-action@')]"),
    ("review-head-ref-pr", "ci.yml", "[s.setdefault('with', {}).__setitem__('head-ref', '${{ github.event.pull_request.head.sha }}') for s in J['dependency-review']['steps'] if str(s.get('uses','')).startswith('actions/dependency-review-action@')]"),
]:
    got = judge_ac2(mutated(f, edit))
    check("AC2 mutant %s is caught" % name, bool(got), got)

# AC3: the policy files, and release admission's own step against a stub of the GitHub API
POL = os.path.join(root, ".github/policy")
req = json.load(open(os.path.join(POL, "required-checks.json")))["required_checks"]
rel = json.load(open(os.path.join(POL, "release-only-checks.json")))["required_checks"]
for ctx in ("dependency-review",):
    ents = [c for c in req + rel if c["context"] == ctx]
    check("AC3 %s is listed once, scope push, Actions app" % ctx, ents == [{"context": ctx, "integration_id": 15368, "scope": "push"}], ents)

adm = load(os.path.join(WF, "stage-admission.yml"))
step = next(s for j in adm["jobs"].values() for s in j["steps"] if s.get("name") == "every required check green, app-pinned, per its scope")
SHA, PRHEAD = "a" * 40, "b" * 40
os.makedirs(os.path.join(work, "bin"))
open(os.path.join(work, "bin/gh"), "w").write("""#!/usr/bin/env bash
case "$*" in
  *"/commits/$FAKE_SHA/check-runs"*) cat "$FAKE_DIR/sha-runs.json" ;;
  *"/commits/$FAKE_PRHEAD/check-runs"*) cat "$FAKE_DIR/pr-runs.json" ;;
  *"/pulls"*) cat "$FAKE_DIR/pulls.json" ;;
  *"/status"*) echo '[]' ;;
  *) echo "stub gh: unexpected $*" >&2; exit 9 ;;
esac
""")
os.chmod(os.path.join(work, "bin/gh"), 0o755)
text = step["run"].replace("/tmp/", work + "/")
os.makedirs(os.path.join(work, "policy"), exist_ok=True)
json.dump({"required_checks": req + rel}, open(os.path.join(work, "policy/required-checks.json"), "w"))
open(os.path.join(work, "pulls.json"), "w").write(json.dumps([{"number": 7, "head_sha": PRHEAD}]))


def admit(name, drop=(), red=(), only_on_pr=()):
    """run the real step with every required check green on the tagged commit except `drop` (missing) and `red` (failed)."""
    sha_runs, pr_runs = [], []
    for i, c in enumerate(req + rel):
        run = {"name": c["context"], "conclusion": "failure" if c["context"] in red else "success", "app_id": c["integration_id"], "id": 100 + i, "head_sha": SHA}
        if c["context"] not in drop and (c["scope"] == "pull_request" or c["context"] in only_on_pr):
            pr_runs.append(run)
        if c["context"] not in drop and c["context"] != "auditor-review-gate" and c["context"] not in only_on_pr:
            sha_runs.append(run)
    for n, v in (("sha-runs", sha_runs), ("pr-runs", pr_runs)):
        json.dump(v, open(os.path.join(work, n + ".json"), "w"))
    env = dict(os.environ, PATH=os.path.join(work, "bin") + ":" + os.environ["PATH"], FAKE_DIR=work, FAKE_SHA=SHA, FAKE_PRHEAD=PRHEAD,
               GITHUB_SHA=SHA, GITHUB_REPOSITORY="o/r", GH_TOKEN="x")
    r = subprocess.run(["bash", "-c", text], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


rc, out = admit("all green")
check("AC3 admission passes when every required check is green on the tagged commit", rc == 0, out.strip()[-300:])
for ctx in [c["context"] for c in req + rel if c["context"] != "auditor-review-gate"]:
    rc, out = admit("missing " + ctx, drop=(ctx,))
    check("AC3 admission refuses a tag whose commit has no run of %s" % ctx, rc != 0 and "'%s'" % ctx in out and "tagged commit" in out, out.strip()[-300:])
for ctx in ("dependency-review",):
    rc, out = admit("red " + ctx, red=(ctx,))
    check("AC3 admission refuses a tag whose commit has a red run of %s" % ctx, rc != 0 and "'%s'" % ctx in out, out.strip()[-300:])
    rc, out = admit("pr-only " + ctx, drop=(ctx,), only_on_pr=(ctx,))
    check("AC3 admission does not take %s from the merged pull request's head" % ctx, rc != 0 and "tagged commit" in out, out.strip()[-300:])

print("pull-request-checks: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
