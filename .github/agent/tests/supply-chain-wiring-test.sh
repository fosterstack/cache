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

CANON = {}   # job -> the exact normalised run text of its check step (filled below from the shipped workflow's ratified text)

root = os.environ["SC_ROOT"]
WF = os.path.join(root, ".github/workflows/supply-chain.yml")
DB = os.path.join(root, ".github/dependabot.yml")
CI = os.path.join(root, ".github/workflows/ci.yml")
ADM = os.path.join(root, "bin/admission-tag-signer.py")
PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
ALLOWED_ACTIONS = ("actions/checkout", "actions/upload-artifact")

CANONICAL_RUNS = {'pin-age': 'set -uo pipefail\nstatus=0\n# a pull request is read at its own base and head; the merge queue at the queue\'s (REQ-DEP-005-AC2);\n# an empty one fails\nBASE_SHA="${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}"\nHEAD_SHA="${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}"\n: "${BASE_SHA:?no base commit to compare: this check fails}" \\\n  "${HEAD_SHA:?no head commit to compare: this check fails}"\npython3 trusted/.github/agent/supply-chain/pin-age-check.py --root pr --base "$BASE_SHA" \\\n  --head "$HEAD_SHA" || status=1\n# the advisor\'s rulings come from the base branch too: a pull request must not bring its own\nexceptions=trusted/.github/supply-chain-exceptions.json\nif [ ! -f "$exceptions" ]; then\n  exceptions="$RUNNER_TEMP/no-exceptions.json"\n  echo \'{"exceptions": []}\' > "$exceptions"\nfi\npython3 trusted/.github/agent/supply-chain/pin-audit.py --root pr --base "$BASE_SHA" --head "$HEAD_SHA" \\\n  --exceptions "$exceptions" --report-only || status=1\nexit $status\n', 'daily-audit': 'python3 .github/agent/supply-chain/pin-audit.py --observations-out "$RUNNER_TEMP/tag-observations/state.json"', 'rerun-held': 'python3 .github/agent/supply-chain/pin-audit.py --rerun-held'}


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
    if j.get("permissions") != {"contents": "read", "actions": "read", "checks": "read"}:
        bad.append(f"pin-age's permissions are not exactly contents: read + actions: read + checks: read (found {j.get('permissions')})")
    if int(str(j.get("timeout-minutes", "999"))) > 20:
        bad.append("pin-age has no bounded timeout-minutes (<= 20): the 90-day history scan of pin-audit needs the room until it is made cheaper")
    runs = "\n".join(str(s.get("run", "")) for s in j.get("steps", []))
    for prog, flag in ((".github/agent/supply-chain/pin-age-check.py", "--base"), (".github/agent/supply-chain/pin-audit.py", "--base")):
        if prog not in runs or flag not in runs:
            bad.append(f"pin-age does not run {prog} {flag} (the age check and the audit of what the PR moves)")
    if ("python3 trusted/.github/agent/supply-chain/pin-age-check.py" not in runs or "python3 trusted/.github/agent/supply-chain/pin-audit.py" not in runs
            or "checker=" in runs or "$checker" in runs or "pr/.github/agent" in runs):
        bad.append("pin-age does not run the BASE branch's checker (trusted/) at literal paths: the pull request's copy never runs, and no variable names the program (REQ-SUP-001, advisor 0198)")
    if "exceptions=trusted/.github/supply-chain-exceptions.json" not in runs or '--exceptions "$exceptions"' not in runs or "pr/.github/supply-chain-exceptions.json" in runs:
        bad.append("pin-age does not take the exceptions from the BASE branch (trusted/): a pull request must not bring its own rulings")
    if "set -e" in runs or runs.count("|| status=1") != 2 or "exit $status" not in runs:
        bad.append("pin-age stops at the first failure: the age check and the advisory audit must both run, and the job fails if either did")
    if ("${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}" not in runs
            or "${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}" not in runs):
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
    if str(j.get("if", "")) != "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'":
        bad.append("daily-audit's condition is not exactly the ratified one")
    if "schedule" not in str(j.get("if", "")):
        bad.append("daily-audit does not run on the schedule")
    if ".github/agent/supply-chain/pin-audit.py" not in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])) or "--rerun-held" in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])):
        bad.append("daily-audit must run .github/agent/supply-chain/pin-audit.py without --rerun-held")
    # rerun-held
    j = jobs["rerun-held"]
    if j.get("permissions") != {"actions": "write", "contents": "read", "pull-requests": "read", "checks": "read"}:
        bad.append(f"rerun-held's permissions are not exactly actions: write + contents: read + pull-requests: read + checks: read (found {j.get('permissions')})")
    if "--rerun-held" not in "\n".join(str(s.get("run", "")) for s in j.get("steps", [])):
        bad.append("rerun-held does not run .github/agent/supply-chain/pin-audit.py --rerun-held")
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
        if name != "pin-age" and "env" in jj:
            bad.append(f"{name} has a job-level env")
        if name == "pin-age" and "env" in jj:
            bad.append("pin-age has a job-level env (PYTHONPATH and friends could redirect the trusted checker)")
    seq = [("checkout" if str(st.get("uses", "")).startswith("actions/checkout@") else "run" if "run" in st else "other") for st in jobs["pin-age"].get("steps", [])]
    if seq != ["checkout", "checkout", "run"]:
        bad.append(f"pin-age's steps are not exactly [trusted checkout, PR checkout, the check step] (found {seq}): no step may be added between them")
    pa_steps = [st for st in jobs["pin-age"].get("steps", []) if str(st.get("uses", "")).startswith("actions/checkout@")]
    if len(pa_steps) != 2:
        bad.append("pin-age must have exactly two checkouts (the base's trusted checker, the PR's tree)")
    else:
        t, pr_ = pa_steps
        tw, pw = t.get("with") or {}, pr_.get("with") or {}
        if set(tw) != {"ref", "path", "persist-credentials"} or set(pw) != {"path", "fetch-depth", "persist-credentials"}:
            bad.append("pin-age's checkouts take inputs other than the ratified ones (e.g. sparse-checkout would empty the trusted checker)")
        if (tw.get("ref") != "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}"
                or tw.get("path") != "trusted" or str(tw.get("persist-credentials")).lower() != "false"):
            bad.append("pin-age's trusted checkout is not the BASE sha at path trusted with persist-credentials false")
        if "ref" in pw or pw.get("path") != "pr" or pw.get("fetch-depth") != "0" or str(pw.get("persist-credentials")).lower() != "false":
            bad.append("pin-age's PR checkout is not the default (merge) ref at path pr, full depth, persist-credentials false")
    # the check steps' commands are pinned EXACTLY: any other flag, an extra assignment, a duplicated argument, a changed order is a changed (rejected) workflow
    norm = lambda t: "\n".join(l.strip() for l in str(t).strip().split("\n") if l.strip())
    for jn, want in CANONICAL_RUNS.items():
        for st in jobs[jn].get("steps", []):
            r = str(st.get("run", ""))
            if r and ("pin-age-check" in r or "pin-audit" in r) and norm(r) != norm(want):
                bad.append(f"{jn}: the check step's commands differ from the ratified text (any added flag, assignment or duplicated argument is a change)")
    if re.search(r"secrets\s*\[", text):
        bad.append("the workflow indexes secrets[...]: no secrets anywhere")
    PR_IF = "github.event_name == 'pull_request' || github.event_name == 'merge_group'"
    for name, jj in jobs.items():
        for st in jj.get("steps", []):
            # a step may not be skipped, tolerated or cut short: the only conditions are the ratified ones
            if "continue-on-error" in st:
                bad.append(f"{name}: a step has continue-on-error: a failing check must fail the job")
            allowed_if = PR_IF if name == "pin-age" else ("always()" if "upload-artifact" in str(st.get("uses", "")) else None)
            if st.get("if") != allowed_if:
                bad.append(f"{name}: a step has a condition ({st.get('if')!r}) other than the ratified one ({allowed_if!r}): it could skip the check")
            if "timeout-minutes" in st:
                bad.append(f"{name}: a step has its own timeout-minutes")
            for forbidden in ("shell", "working-directory"):
                if forbidden in st:
                    bad.append(f"{name}: a step sets {forbidden}: it could replace what actually runs")
            if "include-hidden-files" in (st.get("with") or {}):
                bad.append(f"{name}: a step uploads hidden files")
            if str(st.get("uses", "")).startswith("actions/upload-artifact@") and (st.get("with") or {}).get("path") != "${{ runner.temp }}/tag-observations/state.json":
                bad.append(f"{name}: the artifact path is not exactly the tag-observations state file (only public tag mappings may be uploaded)")
            extra_env = set(st.get("env") or {}) - {"GH_TOKEN", "GITHUB_REPOSITORY"}
            if extra_env:
                bad.append(f"{name}: a step sets env {sorted(extra_env)}: only GH_TOKEN and GITHUB_REPOSITORY may be set (PYTHONPATH and friends redirect the trusted checker)")
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
        if name != "rerun-held" and (jj.get("permissions") or {}).get("actions") not in (None, "read"):
            bad.append(f"{name} has actions write: only rerun-held may")
        if name != "daily-audit" and "issues" in (jj.get("permissions") or {}):
            bad.append(f"{name} can write issues: only daily-audit may")
        if jj.get("environment") or "secrets" in str(jj.get("env", "")):
            bad.append(f"{name} has an environment or secrets: none are allowed")
    return bad

def judge_db(d):
    bad = []
    ups = {u.get("package-ecosystem"): u for u in d.get("updates", []) if not (u.get("package-ecosystem") == "gomod" and u.get("directory") == "/tools/govulncheck")}
    for eco in ("github-actions", "pip"):
        cd = (ups.get(eco) or {}).get("cooldown")
        if not cd or cd != {"default-days": "7"}:  # exactly 7 days and no per-semver override that could shorten it
            bad.append(f"the {eco} entry has no 7-day cooldown (default-days: 7)")
    want = {"gomod": {"package-ecosystem": "gomod", "directory": "/", "schedule": {"interval": "weekly"}}}  # the product's CVE-fix target: byte-for-byte unchanged
    for eco, entry in want.items():
        if eco in ups and ups[eco] != entry:
            bad.append(f"the {eco} entry is not unchanged")
    for eco in ("gomod",):
        if eco not in ups:
            bad.append(f"the {eco} entry is missing")
        elif "cooldown" in ups[eco]:
            bad.append(f"the {eco} entry has a cooldown: product dependencies keep the 24-48h CVE target")
    # the pinned Go source scanner (advisor Oct 12, ruling G): tools/govulncheck is its own module, bumped through the reviewed path with the same 7-day wait as the
    # actions and the pip pins (it is a tool, not a product dependency: the product's CVE-fix target above stays without a cooldown)
    tool = [u for u in d.get("updates", []) if u.get("package-ecosystem") == "gomod" and u.get("directory") == "/tools/govulncheck"]
    if len(tool) != 1:
        bad.append(f"the govulncheck tool entry (gomod, /tools/govulncheck) is missing or repeated ({len(tool)})")
    elif tool[0] != {"package-ecosystem": "gomod", "directory": "/tools/govulncheck", "schedule": {"interval": "weekly"}, "cooldown": {"default-days": "7"}}:
        bad.append("the govulncheck tool entry is not exactly weekly with a 7-day cooldown (default-days: 7) and nothing else")
    # rule 61 (advisor Oct 12): no Dockerfile exists, so Dependabot's docker ecosystem watches nothing and has no entry
    if any(u.get("package-ecosystem") == "docker" for u in d.get("updates", [])):
        bad.append("a docker entry is back: no Dockerfile exists (rule 61)")
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
        if f"bash .github/agent/tests/{t}" not in ci and f"suite-floors.json {t} .github/agent/tests/{t}" not in ci:     # plain, or the counting step of REQ-CI-005
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
real_text = open(WF).read()
dd = dup_keys(real_text)
result(not dd, "the real supply-chain.yml has no duplicate YAML key" + ("" if not dd else ": " + ", ".join(dd[:5])))
dd = dup_keys(real_text.replace("\nconcurrency:\n", "\nconcurrency: {group: shared, cancel-in-progress: true}\nconcurrency:\n", 1))
result(bool(dd), "caught: a duplicate top-level concurrency key (raw YAML; a parse would keep the last value)" + ("" if dd else "; saw nothing"))
b = judge_wf(real_wf, True) if real_wf is not None else ["supply-chain.yml is missing"]
result(not b, "the real supply-chain.yml satisfies the wiring" + ("" if not b else ": " + "; ".join(b)))
b = judge_db(real_db)
result(not b, "the real dependabot.yml: 7-day cooldown on github-actions, pip and the govulncheck tool module, none on the product gomod, no docker entry" + ("" if not b else ": " + "; ".join(b)))
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
mut_wf("pin-age can write", "pin-age's permissions are not exactly contents: read + actions: read + checks: read", lambda d: J(d, "pin-age")["permissions"].update(issues="write"))
mut_wf("pin-age has actions write", "pin-age's permissions are not exactly contents: read + actions: read + checks: read", lambda d: J(d, "pin-age")["permissions"].update(actions="write"))
mut_wf("pin-age has no timeout", "no bounded timeout-minutes", lambda d: J(d, "pin-age").pop("timeout-minutes"))
mut_wf("pin-age timeout above 20", "no bounded timeout-minutes", lambda d: J(d, "pin-age").update({"timeout-minutes": 21}))
mut_wf("pin-age timeout far above", "no bounded timeout-minutes", lambda d: J(d, "pin-age").update({"timeout-minutes": 360}))
mut_wf("pin-age never runs the age check", "does not run .github/agent/supply-chain/pin-age-check.py", lambda d: J(d, "pin-age").update(steps=[s for s in J(d, "pin-age")["steps"] if "pin-age-check" not in str(s.get("run", ""))]))
mut_wf("pin-age never audits what moves", "does not run .github/agent/supply-chain/pin-audit.py", lambda d: J(d, "pin-age").update(steps=[s for s in J(d, "pin-age")["steps"] if "pin-audit" not in str(s.get("run", ""))]))
mut_wf("pin-age compares the wrong commits", "does not compare the PR's base and head", lambda d: [s.update(run=s["run"].replace("github.event.pull_request.base.sha", "github.sha")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the PR's own checker runs", "does not run the BASE branch's checker", lambda d: [x.update(run=x["run"].replace("python3 trusted/.github/agent/supply-chain/pin-age-check.py", "python3 pr/.github/agent/supply-chain/pin-age-check.py")) for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("the audit runs from the PR's tree", "does not run the BASE branch's checker", lambda d: [x.update(run=x["run"].replace("python3 trusted/.github/agent/supply-chain/pin-audit.py", "python3 pr/.github/agent/supply-chain/pin-audit.py")) for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("a variable names the checker again", "does not run the BASE branch's checker", lambda d: [x.update(run="checker=trusted\n" + x["run"].replace("python3 trusted/.github/agent/supply-chain/pin-age-check.py", 'python3 "$checker/.github/agent/supply-chain/pin-age-check.py"')) for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("exceptions are read from the PR's tree", "does not take the exceptions from the BASE branch", lambda d: [s.update(run=s["run"].replace("exceptions=trusted/.github", "exceptions=pr/.github")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the audit stops passing --exceptions", "does not take the exceptions from the BASE branch", lambda d: [s.update(run=s["run"].replace(' --exceptions "$exceptions"', "")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the age check's failure hides the audit", "pin-age stops at the first failure", lambda d: [s.update(run=s["run"].replace("set -uo pipefail", "set -euo pipefail")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the audit's exit status is dropped", "pin-age stops at the first failure", lambda d: [s.update(run=s["run"].replace("--report-only || status=1", "--report-only")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("a step is disabled with if: false", "a step has a condition", lambda d: J(d, "pin-age")["steps"][-1].update({"if": "false"}))
mut_wf("a step skips bots", "a step has a condition", lambda d: J(d, "pin-age")["steps"][-1].update({"if": "github.actor != 'dependabot[bot]'"}))
mut_wf("a step tolerates failure", "continue-on-error", lambda d: J(d, "pin-age")["steps"][-1].update({"continue-on-error": "true"}))
mut_wf("exit 0 is appended to the check step", "exits early", lambda d: [x.update(run=x["run"] + "\nexit 0") for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("exit 0 is put first", "exits early", lambda d: [x.update(run="exit 0\n" + x["run"]) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a failure is swallowed with || true", "exits early", lambda d: [x.update(run=x["run"].replace("|| status=1", "|| true")) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("the check step loses its token", "no GH_TOKEN", lambda d: [x.pop("env") for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a daily step gains a condition", "a step has a condition", lambda d: [x.update({"if": "false"}) for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("the trusted checkout takes the PR's head", "trusted checkout is not the BASE", lambda d: [x["with"].update(ref="${{ github.event.pull_request.head.sha }}") for x in J(d, "pin-age")["steps"] if str(x.get("uses", "")).startswith("actions/checkout") and x["with"].get("path") == "trusted"])
mut_wf("the PR checkout lands in trusted", "PR checkout is not", lambda d: [x["with"].update(path="trusted") for x in J(d, "pin-age")["steps"] if str(x.get("uses", "")).startswith("actions/checkout") and x["with"].get("path") == "pr"])
mut_wf("the PR checkout picks a ref", "PR checkout is not", lambda d: [x["with"].update(ref="refs/heads/evil") for x in J(d, "pin-age")["steps"] if str(x.get("uses", "")).startswith("actions/checkout") and x["with"].get("path") == "pr"])
mut_wf("a job container image appears", "job-level container", lambda d: J(d, "pin-age").update(container={"image": "evil:latest"}))
mut_wf("a job service appears", "job-level services", lambda d: J(d, "pin-age").update(services={"x": {"image": "evil"}}))
mut_wf("a workflow-level env appears", "top-level env", lambda d: d.update(env={"PYTHONPATH": "pr"}))
mut_wf("a job-level env appears", "job-level env", lambda d: J(d, "pin-age").update(env={"PYTHONPATH": "pr"}))
mut_wf("a shell default appears", "job-level defaults", lambda d: J(d, "pin-age").update(defaults={"run": {"shell": "python3 {0}"}}))
mut_wf("a third checkout appears", "exactly two checkouts", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "actions/checkout@" + "a" * 40, "with": {"persist-credentials": "false"}}))
mut_wf("fixtures are passed to the checker", "test-only flag", lambda d: [x.update(run=x["run"].replace("--report-only", "--report-only --fixtures pr/fx.json")) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("--now is passed", "test-only flag", lambda d: [x.update(run=x["run"].replace("pin-age-check.py", "pin-age-check.py --now 2020-01-01T00:00:00Z")) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a step sets PYTHONPATH", "sets env", lambda d: [x.setdefault("env", {}).update(PYTHONPATH="pr") for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("PYTHONPATH in the script", "test-only flag", lambda d: [x.update(run="export PYTHONPATH=pr\n" + x["run"]) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("status=0 before the exit", "differ from the ratified text", lambda d: [x.update(run=x["run"].replace("exit $status", "status=0\nexit $status")) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("--min-days 0 is added", "differ from the ratified text", lambda d: [x.update(run=x["run"].replace("--root pr", "--min-days 0 --root pr", 1)) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a duplicated --base argument", "differ from the ratified text", lambda d: [x.update(run=x["run"].replace("--report-only", "--base ${{ github.event.pull_request.head.sha }} --report-only")) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("--report-only on the daily audit", "differ from the ratified text", lambda d: [x.update(run=x["run"] + " --report-only") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a secret indexed with brackets", "indexes secrets", lambda d: [x["env"].update(GH_TOKEN="${{ secrets['PAT'] }}") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a step sets shell", "sets shell", lambda d: [x.update(shell='bash -c "true" {0}') for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a step writes BASH_ENV", "writes the job's environment", lambda d: J(d, "pin-age")["steps"].insert(0, {"run": 'echo "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"'}))
mut_wf("the daily condition gains && false", "not exactly the ratified one", lambda d: J(d, "daily-audit").update({"if": "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' && false"}))
mut_wf("the artifact path widens", "artifact path is not exactly", lambda d: [x["with"].update(path=".github/workflows") for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("hidden files are uploaded", "uploads hidden files", lambda d: [x["with"].update({"include-hidden-files": "true"}) for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("sparse-checkout empties the trusted checker", "checkouts take inputs other than", lambda d: [x["with"].update({"sparse-checkout": "bin"}) for x in J(d, "pin-age")["steps"] if str(x.get("uses", "")).startswith("actions/checkout") and x["with"].get("path") == "trusted"])
mut_wf("a step between the checkouts and the check", "not exactly [trusted checkout", lambda d: J(d, "pin-age")["steps"].insert(2, {"if": "github.event_name == 'pull_request'", "run": 'find trusted -name "*.py" -exec cp /dev/null {} \\;'}))
mut_wf("a secret is used", "uses secrets", lambda d: J(d, "daily-audit")["steps"][-1].setdefault("env", {}).update(X="${{ secrets.PAT }}"))
mut_wf("an unpinned action", "is not pinned to a commit digest", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "actions/checkout@v4"}))
mut_wf("an action off the allowlist", "is not on the allowlist", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "evil/action@" + "a" * 40}))
mut_wf("checkout keeps credentials", "persist-credentials", lambda d: next(s for s in J(d, "pin-age")["steps"] if "checkout" in str(s.get("uses", "")))["with"].pop("persist-credentials"))
mut_wf("daily-audit loses issues: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].pop("issues"))
mut_wf("daily-audit gains contents: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(contents="write"))
mut_wf("daily-audit gains actions: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(actions="write"))
mut_wf("a top-level concurrency that cancels every event", "not the reviewed block", lambda d: d["concurrency"].update({"cancel-in-progress": "true"}))
mut_wf("a top-level concurrency with a shared ref group", "not the reviewed block", lambda d: d.update(concurrency={"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}))
mut_wf("a top-level concurrency whose pull-request group is shared by re-runs", "not the reviewed block", lambda d: d["concurrency"].update(group=d["concurrency"]["group"].replace(" && github.run_attempt == '1'", "")))
mut_wf("a top-level concurrency that borrows github.workflow", "not the reviewed block", lambda d: d["concurrency"].update(group=d["concurrency"]["group"].replace("'supply-chain-pr-{0}', ", "'{0}-pr-{1}', github.workflow, ").replace("'supply-chain-{0}-{1}', ", "'{0}-{1}-{2}', github.workflow, ")))
mut_wf("a top-level concurrency dropped entirely", "not the reviewed block", lambda d: d.pop("concurrency"))
mut_wf("a top-level concurrency on its own", "not the reviewed block", lambda d: d.update(concurrency={"group": "x", "cancel-in-progress": "false"}))
mut_wf("daily-audit loses its concurrency group", "no concurrency group", lambda d: J(d, "daily-audit").pop("concurrency"))
mut_wf("daily-audit stops keeping the observations", "does not keep the tag observations", lambda d: J(d, "daily-audit").update(steps=[x for x in J(d, "daily-audit")["steps"] if "upload-artifact" not in str(x.get("uses", ""))]))
mut_wf("the observations are kept only on success", "does not keep the tag observations", lambda d: [x.pop("if") for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("the observations are kept under another name", "does not keep the tag observations", lambda d: [x["with"].update(name="other") for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("the observations expire in a day", "does not keep the tag observations", lambda d: [x["with"].update({"retention-days": "1"}) for x in J(d, "daily-audit")["steps"] if "upload-artifact" in str(x.get("uses", ""))])
mut_wf("the PR job writes observations", "only daily-audit may write the tag observations", lambda d: [x.update(run=x["run"] + " --observations-out /tmp/x") for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("the audit stops writing observations", "does not write the tag observations", lambda d: [x.update(run=x["run"].replace("--observations-out", "--quiet")) for x in J(d, "daily-audit")["steps"] if "run" in x])
mut_wf("daily-audit re-runs PRs itself", "daily-audit must run .github/agent/supply-chain/pin-audit.py without --rerun-held", lambda d: [x.update(run=x["run"] + " --rerun-held") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("rerun-held loses actions: write", "rerun-held's permissions are not exactly", lambda d: J(d, "rerun-held")["permissions"].pop("actions"))
mut_wf("rerun-held gains issues: write", "can write issues", lambda d: J(d, "rerun-held")["permissions"].update(issues="write"))
mut_wf("rerun-held never re-runs", "does not run .github/agent/supply-chain/pin-audit.py --rerun-held", lambda d: J(d, "rerun-held").update(steps=[s for s in J(d, "rerun-held")["steps"] if "--rerun-held" not in str(s.get("run", ""))]))
mut_wf("a job gets an environment", "has an environment or secrets", lambda d: J(d, "daily-audit").update(environment="release"))
mut_wf("a fourth job appears", "the jobs are not exactly", lambda d: d["jobs"].update(extra={"runs-on": "ubuntu-latest", "steps": []}))
mut_wf("top-level permissions widened", "no top-level permissions block", lambda d: d.update(permissions={"contents": "write"}))
# --- dependabot (AC1) ---
mut_db("github-actions cooldown gains a semver override", "github-actions entry has no 7-day cooldown", lambda d: eco(d, "github-actions")["cooldown"].update({"semver-major-days": "0"}))
mut_db("gomod gains an ignore rule", "gomod entry is not unchanged", lambda d: eco(d, "gomod").update(ignore=[{"dependency-name": "x"}]))
mut_db("gomod's schedule changes", "gomod entry is not unchanged", lambda d: eco(d, "gomod")["schedule"].update(interval="monthly"))
mut_db("a docker entry returns for /build/docker", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/build/docker", "schedule": {"interval": "daily"}}))
mut_db("a docker entry returns for the root", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/", "schedule": {"interval": "weekly"}}))
mut_db("gomod is removed", "the gomod entry is missing", lambda d: d["updates"].remove(eco(d, "gomod")))
TOOL = lambda d: next(u for u in d["updates"] if u.get("directory") == "/tools/govulncheck")
mut_db("the govulncheck tool entry is removed", "govulncheck tool entry", lambda d: d["updates"].remove(TOOL(d)))
mut_db("the govulncheck tool entry loses its cooldown", "govulncheck tool entry", lambda d: TOOL(d).pop("cooldown"))
mut_db("the govulncheck tool cooldown is 3 days", "govulncheck tool entry", lambda d: TOOL(d)["cooldown"].update({"default-days": "3"}))
mut_db("the govulncheck tool cooldown gains a semver override", "govulncheck tool entry", lambda d: TOOL(d)["cooldown"].update({"semver-patch-days": "0"}))
mut_db("the govulncheck tool entry watches another directory", "govulncheck tool entry", lambda d: TOOL(d).update(directory="/tools/requirements"))
mut_db("the govulncheck tool entry runs daily", "govulncheck tool entry", lambda d: TOOL(d)["schedule"].update(interval="daily"))
mut_db("the govulncheck tool entry ignores a dependency", "govulncheck tool entry", lambda d: TOOL(d).update(ignore=[{"dependency-name": "golang.org/x/vuln"}]))
mut_db("the govulncheck tool entry is repeated", "govulncheck tool entry", lambda d: d["updates"].append(copy.deepcopy(TOOL(d))))
mut_db("github-actions loses its cooldown", "github-actions entry has no 7-day cooldown", lambda d: eco(d, "github-actions").pop("cooldown"))
mut_db("pip loses its cooldown", "pip entry has no 7-day cooldown", lambda d: eco(d, "pip").pop("cooldown"))
mut_db("github-actions cooldown is the default 3", "github-actions entry has no 7-day cooldown", lambda d: eco(d, "github-actions")["cooldown"].update({"default-days": "3"}))
mut_db("gomod gets a cooldown", "gomod entry has a cooldown", lambda d: eco(d, "gomod").update(cooldown={"default-days": "7"}))
mut_db("a docker entry returns with a cooldown", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/build/docker", "schedule": {"interval": "daily"}, "cooldown": {"default-days": "7"}}))

print(f"supply-chain wiring: {passed} passed, {failed} failed")
sys.exit(0 if failed == 0 else 1)
PY
