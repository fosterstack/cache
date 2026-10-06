#!/usr/bin/env bash
# proves: REQ-SUP-001-AC1, REQ-SUP-001-AC4, REQ-SUP-001-AC6
# Where the supply-chain checks run (owner ratified Oct 5; advisor 0172, 0175): Dependabot waits 7 days on the github-actions and pip entries only (AC1);
# the pull request check is a job that runs on EVERY pull request on pull_request (never pull_request_target), with a read-only token and no secrets, so it
# can be the owner's required check without ever blocking an unrelated PR (AC4); the daily job may write issues and nothing else; the one job that re-runs
# held PRs has actions: write and nothing else (AC6); REQ-SUP-001 is pipeline-only for automatic patches; CI runs the three tests. Read from the PARSED files:
# the real files must pass and every mutation (made through the parsed document) must be rejected FOR THE REASON NAMED.
#   .github/workflows/supply-chain.yml: jobs `pin-age` (pull_request), `daily-audit` (schedule), `rerun-held` (schedule)
set -euo pipefail
export SC_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
python3 - <<'PY'
import copy, os, re, sys, yaml

root = os.environ["SC_ROOT"]
WF = os.path.join(root, ".github/workflows/supply-chain.yml")
DB = os.path.join(root, ".github/dependabot.yml")
CI = os.path.join(root, ".github/workflows/ci.yml")
ADM = os.path.join(root, "bin/admission-tag-signer.py")
PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
ALLOWED_ACTIONS = ("actions/checkout", "actions/upload-artifact")

def load(p): return yaml.load(open(p), Loader=yaml.BaseLoader)

def judge_wf(d, real=False):
    bad = []
    on = d.get("on", {})
    if not isinstance(on, dict):
        return ["the workflow's triggers are not a mapping"]
    if "pull_request_target" in on or "workflow_run" in on:
        bad.append("a pull_request_target or workflow_run trigger (the PR check must run PR code only with a read-only token)")
    pr = on.get("pull_request")
    if "pull_request" not in on:
        bad.append("no pull_request trigger")
    elif pr and any(k in pr for k in ("paths", "paths-ignore", "branches", "branches-ignore", "types")):
        bad.append("the pull_request trigger has a filter (paths, branches or types): the check must run on EVERY pull request")
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
    if sorted(jobs) != ["daily-audit", "pin-age", "rerun-held"]:
        bad.append(f"the jobs are not exactly pin-age, daily-audit and rerun-held: {sorted(jobs)}")
        return bad
    # pin-age
    j = jobs["pin-age"]
    if "if" in j or "needs" in j or "strategy" in j or "continue-on-error" in j or "environment" in j:
        bad.append("pin-age has an if, needs, strategy, continue-on-error or environment: a required check must run on every PR and fail when it should")
    if j.get("permissions") != {"contents": "read", "actions": "read"}:
        bad.append(f"pin-age's permissions are not exactly contents: read + actions: read (found {j.get('permissions')})")
    if int(str(j.get("timeout-minutes", "999"))) > 10:
        bad.append("pin-age has no short timeout-minutes (<= 10): it must pass fast")
    runs = "\n".join(str(s.get("run", "")) for s in j.get("steps", []))
    for prog, flag in ((".github/agent/bin/pin-age-check.py", "--base"), (".github/agent/bin/pin-audit.py", "--base")):
        if prog not in runs or flag not in runs:
            bad.append(f"pin-age does not run {prog} {flag} (the age check and the audit of what the PR moves)")
    if "checker=trusted" not in runs or "[ ! -f trusted/.github/agent/bin/pin-age-check.py ]" not in runs or runs.count("checker=pr") != 1 or '"$checker/.github/agent/bin/pin-age-check.py"' not in runs or '"$checker/.github/agent/bin/pin-audit.py"' not in runs:
        bad.append("pin-age does not run the BASE branch's checker (trusted/) and fall back to the PR's copy only when the base has none")
    if "exceptions=trusted/.github/supply-chain-exceptions.json" not in runs or '--exceptions "$exceptions"' not in runs or "pr/.github/supply-chain-exceptions.json" in runs:
        bad.append("pin-age does not take the exceptions from the BASE branch (trusted/): a pull request must not bring its own rulings")
    if "set -e" in runs or runs.count("|| status=1") != 2 or "exit $status" not in runs:
        bad.append("pin-age stops at the first failure: the age check and the advisory audit must both run, and the job fails if either did")
    if "${{ github.event.pull_request.base.sha }}" not in runs or "${{ github.event.pull_request.head.sha }}" not in runs:
        bad.append("pin-age does not compare the PR's base and head commits")
    # daily-audit
    j = jobs["daily-audit"]
    if j.get("permissions") != {"contents": "read", "issues": "write", "actions": "read"}:
        bad.append(f"daily-audit's permissions are not exactly contents: read + issues: write + actions: read (found {j.get('permissions')})")
    if (j.get("concurrency") or {}).get("group") != "supply-chain-daily" or (j.get("concurrency") or {}).get("cancel-in-progress") != "false":
        bad.append("daily-audit has no concurrency group (two runs at once could double-file an issue)")
    ups = [st for st in j.get("steps", []) if str(st.get("uses", "")).startswith("actions/upload-artifact@")]
    w = (ups[0].get("with") or {}) if len(ups) == 1 else {}
    if len(ups) != 1 or w.get("name") != "tag-observations" or w.get("retention-days") != "90" or w.get("if-no-files-found") != "error" or ups[0].get("if") != "always()":
        bad.append("daily-audit does not keep the tag observations: exactly one upload-artifact step named tag-observations, retention 90, error if missing, if always()")
    if "--observations-out" not in "\n".join(str(st.get("run", "")) for st in j.get("steps", [])):
        bad.append("daily-audit does not write the tag observations (--observations-out)")
    if any("--observations-out" in str(st.get("run", "")) for jn, jj in jobs.items() if jn != "daily-audit" for st in jj.get("steps", [])):
        bad.append("only daily-audit may write the tag observations")
    if "schedule" not in str(j.get("if", "")):
        bad.append("daily-audit does not run on the schedule")
    if ".github/agent/bin/pin-audit.py" not in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])) or "--rerun-held" in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])):
        bad.append("daily-audit must run .github/agent/bin/pin-audit.py without --rerun-held")
    # rerun-held
    j = jobs["rerun-held"]
    if j.get("permissions") != {"actions": "write", "contents": "read", "pull-requests": "read"}:
        bad.append(f"rerun-held's permissions are not exactly actions: write + contents: read + pull-requests: read (found {j.get('permissions')})")
    if "--rerun-held" not in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])):
        bad.append("rerun-held does not run .github/agent/bin/pin-audit.py --rerun-held")
    for name, jj in jobs.items():
        for s in jj.get("steps", []):
            u = str(s.get("uses", ""))
            if u and not PIN.match(u):
                bad.append(f"{name}: action {u} is not pinned to a commit digest")
            if u and u.split("@")[0] not in ALLOWED_ACTIONS:
                bad.append(f"{name}: action {u.split('@')[0]} is not on the allowlist {ALLOWED_ACTIONS}")
            if u.startswith("actions/checkout") and str((s.get("with", {}) or {}).get("persist-credentials", "")).lower() != "false":
                bad.append(f"{name}: checkout keeps the job's credentials (persist-credentials must be false)")
        if name != "rerun-held" and (jj.get("permissions") or {}).get("actions") not in (None, "read"):
            bad.append(f"{name} has actions write: only rerun-held may")
        if name != "daily-audit" and "issues" in (jj.get("permissions") or {}):
            bad.append(f"{name} can write issues: only daily-audit may")
        if jj.get("environment") or "secrets" in str(jj.get("env", "")):
            bad.append(f"{name} has an environment or secrets: none are allowed")
    return bad

def judge_db(d):
    bad = []
    ups = {u.get("package-ecosystem"): u for u in d.get("updates", [])}
    for eco in ("github-actions", "pip"):
        cd = (ups.get(eco) or {}).get("cooldown")
        if not cd or cd != {"default-days": "7"}:  # exactly 7 days and no per-semver override that could shorten it
            bad.append(f"the {eco} entry has no 7-day cooldown (default-days: 7)")
    want = {"gomod": {"package-ecosystem": "gomod", "directory": "/", "schedule": {"interval": "weekly"}},
            "docker": {"package-ecosystem": "docker", "directory": "/build/docker", "schedule": {"interval": "daily"}}}  # the product's CVE-fix targets: byte-for-byte unchanged
    for eco, entry in want.items():
        if eco in ups and ups[eco] != entry:
            bad.append(f"the {eco} entry is not unchanged")
    for eco in ("gomod", "docker"):
        if eco not in ups:
            bad.append(f"the {eco} entry is missing")
        elif "cooldown" in ups[eco]:
            bad.append(f"the {eco} entry has a cooldown: product dependencies keep the 24-48h CVE target")
    return bad

def judge_rest():
    bad = []
    ns = {}
    src = open(ADM).read()
    m = re.search(r"PIPELINE_ONLY = frozenset\(\[(.*?)\]\)", src, re.S)
    if not m or "REQ-SUP-001" not in m.group(1):
        bad.append("REQ-SUP-001 is not in PIPELINE_ONLY (left off, it is product by default and freezes automatic patches)")
    ci = open(CI).read()
    for t in ("pin-age-check-test.sh", "pin-audit-test.sh", "supply-chain-wiring-test.sh"):
        if f"bash .github/agent/tests/{t}" not in ci:
            bad.append(f"ci.yml does not run .github/agent/tests/{t}")
    return bad

real_wf, real_db = None, None
try:
    real_wf = load(WF)
except Exception as e:
    print("FAIL cannot read supply-chain.yml:", e)
real_db = load(DB)

passed = failed = 0
def result(ok, msg):
    global passed, failed
    if ok: passed += 1; print("ok  ", msg)
    else: failed += 1; print("FAIL", msg)

# the real files
b = judge_wf(real_wf, True) if real_wf is not None else ["supply-chain.yml is missing"]
result(not b, "the real supply-chain.yml satisfies the wiring" + ("" if not b else ": " + "; ".join(b)))
b = judge_db(real_db)
result(not b, "the real dependabot.yml: 7-day cooldown on github-actions and pip, none on gomod and docker" + ("" if not b else ": " + "; ".join(b)))
b = judge_rest()
result(not b, "REQ-SUP-001 is pipeline-only and ci.yml runs the three tests" + ("" if not b else ": " + "; ".join(b)))

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

# --- the workflow (AC4, AC6) ---
mut_wf("pull_request gets a paths filter", "has a filter", lambda d: d["on"].update(pull_request={"paths": ["bin/**"]}))
mut_wf("pull_request gets a branches filter", "has a filter", lambda d: d["on"].update(pull_request={"branches": ["main"]}))
mut_wf("pull_request limited to types", "has a filter", lambda d: d["on"].update(pull_request={"types": ["opened"]}))
mut_wf("a pull_request_target trigger", "pull_request_target", lambda d: d["on"].update(pull_request_target={}))
mut_wf("a workflow_run trigger", "pull_request_target or workflow_run", lambda d: d["on"].update(workflow_run={"workflows": ["x"]}))
mut_wf("no pull_request trigger", "no pull_request trigger", lambda d: d["on"].pop("pull_request"))
mut_wf("no schedule", "no single daily schedule", lambda d: d["on"].pop("schedule"))
mut_wf("pin-age is skipped for bots", "pin-age has an if", lambda d: J(d, "pin-age").update({"if": "github.actor != 'dependabot[bot]'"}))
mut_wf("pin-age needs another job", "pin-age has an if, needs", lambda d: J(d, "pin-age").update(needs=["daily-audit"]))
mut_wf("pin-age is allowed to fail", "pin-age has an if, needs", lambda d: J(d, "pin-age").update({"continue-on-error": "true"}))
mut_wf("pin-age can write", "pin-age's permissions are not exactly contents: read + actions: read", lambda d: J(d, "pin-age")["permissions"].update(issues="write"))
mut_wf("pin-age has actions write", "pin-age's permissions are not exactly contents: read + actions: read", lambda d: J(d, "pin-age")["permissions"].update(actions="write"))
mut_wf("pin-age has no timeout", "no short timeout-minutes", lambda d: J(d, "pin-age").pop("timeout-minutes"))
mut_wf("pin-age never runs the age check", "does not run .github/agent/bin/pin-age-check.py", lambda d: J(d, "pin-age").update(steps=[s for s in J(d, "pin-age")["steps"] if "pin-age-check" not in str(s.get("run", ""))]))
mut_wf("pin-age never audits what moves", "does not run .github/agent/bin/pin-audit.py", lambda d: J(d, "pin-age").update(steps=[s for s in J(d, "pin-age")["steps"] if "pin-audit" not in str(s.get("run", ""))]))
mut_wf("pin-age compares the wrong commits", "does not compare the PR's base and head", lambda d: [s.update(run=s["run"].replace("github.event.pull_request.base.sha", "github.sha")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the PR's own checker always runs", "does not run the BASE branch's checker", lambda d: [s.update(run=s["run"].replace("checker=trusted", "checker=pr")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the fallback is unconditional", "does not run the BASE branch's checker", lambda d: [s.update(run=s["run"].replace("[ ! -f trusted/.github/agent/bin/pin-age-check.py ]", "true")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the checker is taken from the PR even when the base has it", "does not run the BASE branch's checker", lambda d: [s.update(run=s["run"].replace('"$checker/.github/agent/bin/pin-age-check.py"', "pr/bin/pin-age-check.py")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("exceptions are read from the PR's tree", "does not take the exceptions from the BASE branch", lambda d: [s.update(run=s["run"].replace("exceptions=trusted/.github", "exceptions=pr/.github")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the audit stops passing --exceptions", "does not take the exceptions from the BASE branch", lambda d: [s.update(run=s["run"].replace(' --exceptions "$exceptions"', "")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the age check's failure hides the audit", "pin-age stops at the first failure", lambda d: [s.update(run=s["run"].replace("set -uo pipefail", "set -euo pipefail")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the audit's exit status is dropped", "pin-age stops at the first failure", lambda d: [s.update(run=s["run"].replace("--report-only || status=1", "--report-only")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("a secret is used", "uses secrets", lambda d: J(d, "daily-audit")["steps"][-1].setdefault("env", {}).update(X="${{ secrets.PAT }}"))
mut_wf("an unpinned action", "is not pinned to a commit digest", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "actions/checkout@v4"}))
mut_wf("an action off the allowlist", "is not on the allowlist", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "evil/action@" + "a" * 40}))
mut_wf("checkout keeps credentials", "persist-credentials", lambda d: next(s for s in J(d, "pin-age")["steps"] if "checkout" in str(s.get("uses", "")))["with"].pop("persist-credentials"))
mut_wf("daily-audit loses issues: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].pop("issues"))
mut_wf("daily-audit gains contents: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(contents="write"))
mut_wf("daily-audit gains actions: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(actions="write"))
mut_wf("daily-audit loses its concurrency group", "no concurrency group", lambda d: J(d, "daily-audit").pop("concurrency"))
mut_wf("daily-audit stops keeping the observations", "does not keep the tag observations", lambda d: J(d, "daily-audit").update(steps=[x for x in J(d, "daily-audit")["steps"] if "upload-artifact" not in str(x.get("uses", ""))]))
mut_wf("the observations are kept only on success", "does not keep the tag observations", lambda d: [x.pop("if") for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("the observations are kept under another name", "does not keep the tag observations", lambda d: [x["with"].update(name="other") for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("the observations expire in a day", "does not keep the tag observations", lambda d: [x["with"].update({"retention-days": "1"}) for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("the PR job writes observations", "only daily-audit may write the tag observations", lambda d: [x.update(run=x["run"] + " --observations-out /tmp/x") for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("the audit stops writing observations", "does not write the tag observations", lambda d: [x.update(run=x["run"].replace("--observations-out", "--quiet")) for x in J(d, "daily-audit")["steps"] if "run" in x])
mut_wf("daily-audit re-runs PRs itself", "daily-audit must run .github/agent/bin/pin-audit.py without --rerun-held", lambda d: [x.update(run=x["run"] + " --rerun-held") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("rerun-held loses actions: write", "rerun-held's permissions are not exactly", lambda d: J(d, "rerun-held")["permissions"].pop("actions"))
mut_wf("rerun-held gains issues: write", "can write issues", lambda d: J(d, "rerun-held")["permissions"].update(issues="write"))
mut_wf("rerun-held never re-runs", "does not run .github/agent/bin/pin-audit.py --rerun-held", lambda d: J(d, "rerun-held").update(steps=[s for s in J(d, "rerun-held")["steps"] if "--rerun-held" not in str(s.get("run", ""))]))
mut_wf("a job gets an environment", "has an environment or secrets", lambda d: J(d, "daily-audit").update(environment="release"))
mut_wf("a fourth job appears", "the jobs are not exactly", lambda d: d["jobs"].update(extra={"runs-on": "ubuntu-latest", "steps": []}))
mut_wf("top-level permissions widened", "no top-level permissions block", lambda d: d.update(permissions={"contents": "write"}))
# --- dependabot (AC1) ---
mut_db("github-actions cooldown gains a semver override", "github-actions entry has no 7-day cooldown", lambda d: eco(d, "github-actions")["cooldown"].update({"semver-major-days": "0"}))
mut_db("gomod gains an ignore rule", "gomod entry is not unchanged", lambda d: eco(d, "gomod").update(ignore=[{"dependency-name": "x"}]))
mut_db("gomod's schedule changes", "gomod entry is not unchanged", lambda d: eco(d, "gomod")["schedule"].update(interval="monthly"))
mut_db("docker's directory changes", "docker entry is not unchanged", lambda d: eco(d, "docker").update(directory="/"))
mut_db("docker's schedule slows", "docker entry is not unchanged", lambda d: eco(d, "docker")["schedule"].update(interval="weekly"))
mut_db("gomod is removed", "the gomod entry is missing", lambda d: d["updates"].remove(eco(d, "gomod")))
mut_db("github-actions loses its cooldown", "github-actions entry has no 7-day cooldown", lambda d: eco(d, "github-actions").pop("cooldown"))
mut_db("pip loses its cooldown", "pip entry has no 7-day cooldown", lambda d: eco(d, "pip").pop("cooldown"))
mut_db("github-actions cooldown is the default 3", "github-actions entry has no 7-day cooldown", lambda d: eco(d, "github-actions")["cooldown"].update({"default-days": "3"}))
mut_db("gomod gets a cooldown", "gomod entry has a cooldown", lambda d: eco(d, "gomod").update(cooldown={"default-days": "7"}))
mut_db("docker gets a cooldown", "docker entry has a cooldown", lambda d: eco(d, "docker").update(cooldown={"default-days": "7"}))

print(f"supply-chain wiring: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
PY
