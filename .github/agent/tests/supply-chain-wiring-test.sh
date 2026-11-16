#!/usr/bin/env bash
# proves: REQ-SUP-001-AC4, REQ-SUP-001-AC36
# proves: REQ-REL-014-AC11
# Where the supply-chain checks run (owner ratified Oct 5; advisor 0172, 0175; the owner removed the wait for new
# versions on Nov 11 2026): the pull request check is a job that runs
# on EVERY pull request on pull_request (never pull_request_target), with a read-only token and no secrets, so it can
# be the owner's required check without ever blocking an
# unrelated PR (AC4); the daily job may write issues and nothing else; no job holds actions: write; REQ-SUP-001 is
# pipeline-only for automatic patches; CI runs the tests.
# Read from the PARSED files: the real files must pass and every mutation (made through the parsed document) must be
# rejected FOR THE REASON NAMED.
#   .github/workflows/supply-chain.yml: jobs `pin-age` (pull_request, merge_group), `image-signatures` (pull_request),
#   `daily-audit` (schedule), `evidence-letter-present` (schedule; the monthly evidence
#   letter's daily presence check, read-only)
set -euo pipefail
export SC_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
python3 - <<'PY'
import copy, os, re, subprocess, sys, yaml

CANON = {}   # job -> the exact normalised run text of its check step (filled below from the shipped workflow's ratified text)

root = os.environ["SC_ROOT"]
WF = os.path.join(root, ".github/workflows/supply-chain.yml")
DB = os.path.join(root, ".github/dependabot.yml")
CI = os.path.join(root, ".github/workflows/ci.yml")
ADM = os.path.join(root, "bin/admission-tag-signer.py")
PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
ALLOWED_ACTIONS = ("actions/checkout",)

CANONICAL_RUNS = {
    'image-signatures':
        'set -euo pipefail\n'
        'python3 trusted/.github/agent/supply-chain/pin-age-check.py cosign-verify --root pr --head '
        '"$HEAD_SHA" \\\n'
        '--tools-file trusted/bin/persona-uat-tools.json',
    'pin-age':
        'set -uo pipefail\n'
        'status=0\n'
        "# a pull request is read at its own base and head; the merge queue at the queue's "
        '(REQ-DEP-005-AC2);\n'
        '# an empty one fails\n'
        'BASE_SHA="${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}"\n'
        'HEAD_SHA="${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}"\n'
        ': "${BASE_SHA:?no base commit to compare: this check fails}" \\\n'
        '  "${HEAD_SHA:?no head commit to compare: this check fails}"\n'
        'python3 trusted/.github/agent/supply-chain/pin-age-check.py --root pr --base "$BASE_SHA" \\\n'
        '  --head "$HEAD_SHA" || status=1\n'
        "# the reviewers' rulings come from the base branch too: a pull request must not bring its own\n"
        'exceptions=trusted/.github/supply-chain-exceptions.json\n'
        'if [ ! -f "$exceptions" ]; then\n'
        '  exceptions="$RUNNER_TEMP/no-exceptions.json"\n'
        '  echo \'{"exceptions": []}\' > "$exceptions"\n'
        'fi\n'
        'python3 trusted/.github/agent/supply-chain/pin-audit.py --root pr --base "$BASE_SHA" --head '
        '"$HEAD_SHA" \\\n'
        '  --exceptions "$exceptions" --report-only || status=1\n'
        'exit $status\n',
    'daily-audit':
        'python3 .github/agent/supply-chain/pin-audit.py',
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
    if sorted(jobs) != ["daily-audit", "evidence-letter-present", "image-signatures", "pin-age"]:
        bad.append("the jobs are not exactly pin-age, image-signatures, daily-audit and "
                   f"evidence-letter-present: {sorted(jobs)}")
        return bad
    # pin-age
    j = jobs["pin-age"]
    if "if" in j or "needs" in j or "strategy" in j or "continue-on-error" in j or "environment" in j:
        bad.append("pin-age has an if, needs, strategy, continue-on-error or environment: a required check must run on every PR and fail when it should")
    if j.get("permissions") != {"contents": "read"}:
        bad.append(f"pin-age's permissions are not exactly contents: read (found {j.get('permissions')})")
    if int(str(j.get("timeout-minutes", "999"))) > 15:
        bad.append("pin-age has no short timeout-minutes (<= 15): it must pass fast (a refresh pull request moves many files and runs longer than 8 minutes)")
    runs = "\n".join(str(s.get("run", "")) for s in j.get("steps", []))
    for prog, flag in ((".github/agent/supply-chain/pin-age-check.py", "--base"), (".github/agent/supply-chain/pin-audit.py", "--base")):
        if prog not in runs or flag not in runs:
            bad.append(f"pin-age does not run {prog} {flag} (the pin scan and the audit of what the PR moves)")
    if ("python3 trusted/.github/agent/supply-chain/pin-age-check.py" not in runs or "python3 trusted/.github/agent/supply-chain/pin-audit.py" not in runs
            or "checker=" in runs or "$checker" in runs or "pr/.github/agent" in runs):
        bad.append("pin-age does not run the BASE branch's checker (trusted/) at literal paths: the pull request's copy never runs, and no variable names the program (REQ-SUP-001, advisor 0198)")
    if "exceptions=trusted/.github/supply-chain-exceptions.json" not in runs or '--exceptions "$exceptions"' not in runs or "pr/.github/supply-chain-exceptions.json" in runs:
        bad.append("pin-age does not take the exceptions from the BASE branch (trusted/): a pull request must not bring its own rulings")
    if "set -e" in runs or runs.count("|| status=1") != 2 or "exit $status" not in runs:
        bad.append("pin-age stops at the first failure: the pin scan and the advisory audit must both run, "
                   "and the job fails if either did")
    if ("${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}" not in runs
            or "${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}" not in runs):
        bad.append("pin-age does not compare the PR's base and head commits")
    # daily-audit
    j = jobs["daily-audit"]
    if j.get("permissions") != {"contents": "read", "issues": "write"}:
        bad.append(f"daily-audit's permissions are not exactly contents: read + issues: write "
                   f"(found {j.get('permissions')})")
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
    for jn, jj in jobs.items():
        if re.search(r"rerun|observations-out|gh run ", "\n".join(str(s.get("run", "")) for s in jj.get("steps", []))):
            bad.append(f"{jn} re-runs a run or records tag observations: nothing waits for a re-run")
    # evidence-letter-present: the daily presence check of the monthly evidence letter; reads releases, writes nothing
    j = jobs["evidence-letter-present"]
    if j.get("permissions") != {"contents": "read"}:
        bad.append("evidence-letter-present's permissions are not exactly contents: read "
                   f"(found {j.get('permissions')})")
    if str(j.get("if", "")) != "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'":
        bad.append("evidence-letter-present's condition is not exactly the schedule or dispatch allow list")
    elp = j.get("steps", [])
    elp_co = [st for st in elp if str(st.get("uses", "")).startswith("actions/checkout@")]
    if len(elp_co) != 1 or str((elp_co[0].get("with") or {}).get("persist-credentials")).lower() != "false":
        bad.append("evidence-letter-present must check out once, with persist-credentials false")
    if [str(st.get("run", "")).strip() for st in elp if "run" in st] != [
            "bash bin/install-scanner.sh cosign", "bash bin/evidence-letter-present.sh"]:
        bad.append("evidence-letter-present's run steps are not exactly the cosign install and the presence script")
    # image-signatures: the cosign check of each pinned third-party image (reads only, the base checker, no token)
    j = jobs["image-signatures"]
    if (j.get("if") != "github.event_name == 'pull_request'"
            or any(k in j for k in ("needs", "strategy", "continue-on-error", "environment"))):
        bad.append("image-signatures does not run on exactly pull_request "
                   "(no needs, strategy, continue-on-error or environment)")
    if j.get("permissions") != {"contents": "read"}:
        bad.append(f"image-signatures' permissions are not exactly contents: read (found {j.get('permissions')})")
    if int(str(j.get("timeout-minutes", "999"))) > 20:
        bad.append("image-signatures has no bounded timeout-minutes (<= 20)")
    sig_runs = "\n".join(str(s.get("run", "")) for s in j.get("steps", []))
    checker = "python3 trusted/.github/agent/supply-chain/pin-age-check.py cosign-verify"
    if checker not in sig_runs or "--tools-file trusted/bin/persona-uat-tools.json" not in sig_runs:
        bad.append("image-signatures does not run the BASE branch's checker (trusted/) cosign-verify "
                   "with the BASE tools file: the pull request's copy never runs")
    if "${{" in sig_runs:
        bad.append("image-signatures has ${{ }} inside run: values go through env")
    head_env = {"HEAD_SHA": "${{ github.event.pull_request.head.sha }}"}
    if [st.get("env") for st in j.get("steps", []) if "run" in st] != [head_env]:
        bad.append("image-signatures' run step does not take exactly HEAD_SHA from env "
                   "(no GH_TOKEN, no other variable)")
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
    for jn in ("pin-age", "image-signatures"):
        steps = jobs[jn].get("steps", [])
        is_checkout = lambda st: str(st.get("uses", "")).startswith("actions/checkout@")
        seq = ["checkout" if is_checkout(st) else "run" if "run" in st else "other" for st in steps]
        if seq != ["checkout", "checkout", "run"]:
            bad.append(f"{jn}'s steps are not exactly [trusted checkout, PR checkout, the check step] (found {seq}): "
                       "no step may be added between them")
        pa_steps = [st for st in steps if is_checkout(st)]
        if len(pa_steps) != 2:
            bad.append(f"{jn} must have exactly two checkouts (the base's trusted checker, the PR's tree)")
        else:
            t, pr_ = pa_steps
            tw, pw = t.get("with") or {}, pr_.get("with") or {}
            if (set(tw) != {"ref", "path", "persist-credentials"}
                    or set(pw) != {"path", "fetch-depth", "persist-credentials"}):
                bad.append(f"{jn}'s checkouts take inputs other than the ratified ones "
                           "(e.g. sparse-checkout would empty the trusted checker)")
            # pin-age also runs in the merge queue (REQ-DEP-005-AC2); image-signatures is a pull_request check only
            ref = "${{ github.event.pull_request.base.sha }}"
            if jn == "pin-age":
                ref = "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha }}"
            base_ok = (tw.get("ref") == ref and tw.get("path") == "trusted"
                       and str(tw.get("persist-credentials")).lower() == "false")
            if not base_ok:
                bad.append(f"{jn}'s trusted checkout is not the BASE sha at path trusted "
                           "with persist-credentials false")
            pr_ok = ("ref" not in pw and pw.get("path") == "pr" and pw.get("fetch-depth") == "0"
                     and str(pw.get("persist-credentials")).lower() == "false")
            if not pr_ok:
                bad.append(f"{jn}'s PR checkout is not the default (merge) ref at path pr, full depth, "
                           "persist-credentials false")
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
            allowed_if = PR_IF if name == "pin-age" else None
            if st.get("if") != allowed_if:
                bad.append(f"{name}: a step has a condition ({st.get('if')!r}) other than the ratified one ({allowed_if!r}): it could skip the check")
            if "timeout-minutes" in st:
                bad.append(f"{name}: a step has its own timeout-minutes")
            for forbidden in ("shell", "working-directory"):
                if forbidden in st:
                    bad.append(f"{name}: a step sets {forbidden}: it could replace what actually runs")
            if "include-hidden-files" in (st.get("with") or {}):
                bad.append(f"{name}: a step uploads hidden files")
            may_set = {"HEAD_SHA"} if name == "image-signatures" else {"GH_TOKEN", "GITHUB_REPOSITORY"}
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
            if name != "image-signatures" and "GH_TOKEN" not in str(st.get("env", "")) and ("pin-" in run_text):
                bad.append(f"{name}: a step that runs the checkers has no GH_TOKEN (without it the live lookups cannot run)")
        for s in jj.get("steps", []):
            u = str(s.get("uses", ""))
            if u and not PIN.match(u):
                bad.append(f"{name}: action {u} is not pinned to a commit digest")
            if u and u.split("@")[0] not in ALLOWED_ACTIONS:
                bad.append(f"{name}: action {u.split('@')[0]} is not on the allowlist {ALLOWED_ACTIONS}")
            if u.startswith("actions/checkout") and str((s.get("with", {}) or {}).get("persist-credentials", "")).lower() != "false":
                bad.append(f"{name}: checkout keeps the job's credentials (persist-credentials must be false)")
        if (jj.get("permissions") or {}).get("actions") == "write":
            bad.append(f"{name} has actions write: no job may")
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
    for eco in ("github-actions", "pip"):
        # exactly weekly and no extra key (no day, time or timezone)
        if (ups.get(eco) or {}).get("schedule") != {"interval": "weekly"}:
            bad.append(f"the {eco} entry's schedule is not exactly interval: weekly")
    for u in d.get("updates", []):
        if "cooldown" in u:
            bad.append(f"the {u.get('package-ecosystem')} {u.get('directory')} entry has a cooldown: the wait for new versions is gone")
    # groups are judged below; the product's gomod entries stay unchanged apart from them
    nog = lambda v: {a: b for a, b in v.items() if a != "groups"}
    for gdir in ("/", "/tools/requirements"):  # both Go modules: the root and the nested tools/requirements module
        if gdir not in gm:
            bad.append(f"the gomod {gdir} entry is missing")
            continue
        if gdir == "/":
            if nog(gm[gdir]) != {"package-ecosystem": "gomod", "directory": gdir, "schedule": {"interval": "weekly"}}:
                bad.append(f"the gomod {gdir} entry is not unchanged")
        # tools/requirements is a CI tool like tools/govulncheck: weekly, nothing else but its group
        elif nog(gm[gdir]) != {"package-ecosystem": "gomod", "directory": gdir, "schedule": {"interval": "weekly"}}:
            bad.append(f"the gomod {gdir} entry is not exactly weekly and nothing else")
    # the pinned Go source scanner (advisor Oct 12, ruling G): tools/govulncheck is its own module, bumped through the reviewed path
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
result(not b, "the real dependabot.yml: no cooldown anywhere, the tools/requirements and govulncheck tool entries weekly, no docker entry; groups: every github-actions, gomod and pip entry has its minor-patch group (minor and patch only), codeql-action first and major-only, pydantic first on pip, no docker entry, no applies-to" + ("" if not b else ": " + "; ".join(b)))
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
def gmod(d, p): return next(u for u in d["updates"] if u["package-ecosystem"] == "gomod" and u["directory"] == p)

# --- the workflow (AC4) ---
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
mut_wf("pin-age can write", "pin-age's permissions are not exactly contents: read", lambda d: J(d,
        "pin-age")["permissions"].update(issues="write"))
mut_wf("pin-age has actions write", "pin-age has actions write", lambda d: J(d,
        "pin-age")["permissions"].update(actions="write"))
mut_wf("pin-age reads actions again", "pin-age's permissions are not exactly contents: read", lambda d: J(d,
        "pin-age")["permissions"].update(actions="read"))
mut_wf("pin-age has no timeout", "no short timeout-minutes", lambda d: J(d, "pin-age").pop("timeout-minutes"))
mut_wf("pin-age timeout above 15", "no short timeout-minutes", lambda d: J(d, "pin-age").update({"timeout-minutes": 16}))
mut_wf("pin-age timeout far above", "no short timeout-minutes", lambda d: J(d, "pin-age").update({"timeout-minutes": 360}))
mut_wf("pin-age never runs the pin scan", "does not run .github/agent/supply-chain/pin-age-check.py", lambda d: J(d,
        "pin-age").update(steps=[s for s in J(d, "pin-age")["steps"] if "pin-age-check" not in str(s.get("run", ""))]))
mut_wf("pin-age never audits what moves", "does not run .github/agent/supply-chain/pin-audit.py", lambda d: J(d, "pin-age").update(steps=[s for s in J(d, "pin-age")["steps"] if "pin-audit" not in str(s.get("run", ""))]))
mut_wf("pin-age compares the wrong commits", "does not compare the PR's base and head", lambda d: [s.update(run=s["run"].replace("github.event.pull_request.base.sha", "github.sha")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the PR's own checker runs", "does not run the BASE branch's checker", lambda d: [x.update(run=x["run"].replace("python3 trusted/.github/agent/supply-chain/pin-age-check.py", "python3 pr/.github/agent/supply-chain/pin-age-check.py")) for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("the audit runs from the PR's tree", "does not run the BASE branch's checker", lambda d: [x.update(run=x["run"].replace("python3 trusted/.github/agent/supply-chain/pin-audit.py", "python3 pr/.github/agent/supply-chain/pin-audit.py")) for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("a variable names the checker again", "does not run the BASE branch's checker", lambda d: [x.update(run="checker=trusted\n" + x["run"].replace("python3 trusted/.github/agent/supply-chain/pin-age-check.py", 'python3 "$checker/.github/agent/supply-chain/pin-age-check.py"')) for x in J(d, "pin-age")["steps"] if "run" in x])
mut_wf("exceptions are read from the PR's tree", "does not take the exceptions from the BASE branch", lambda d: [s.update(run=s["run"].replace("exceptions=trusted/.github", "exceptions=pr/.github")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the audit stops passing --exceptions", "does not take the exceptions from the BASE branch", lambda d: [s.update(run=s["run"].replace(' --exceptions "$exceptions"', "")) for s in J(d, "pin-age")["steps"] if "run" in s])
mut_wf("the pin scan's failure hides the audit", "pin-age stops at the first failure",
        lambda d: [s.update(run=s["run"].replace("set -uo pipefail", "set -euo pipefail")) for s in J(d,
        "pin-age")["steps"] if "run" in s])
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
mut_wf("--exceptions is added to the scan", "differ from the ratified text",
        lambda d: [x.update(run=x["run"].replace("--root pr", "--exceptions pr/x.json --root pr", 1)) for x in J(d,
        "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a duplicated --base argument", "differ from the ratified text", lambda d: [x.update(run=x["run"].replace("--report-only", "--base ${{ github.event.pull_request.head.sha }} --report-only")) for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("--report-only on the daily audit", "differ from the ratified text", lambda d: [x.update(run=x["run"] + " --report-only") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a secret indexed with brackets", "indexes secrets", lambda d: [x["env"].update(GH_TOKEN="${{ secrets['PAT'] }}") for x in J(d, "daily-audit")["steps"] if "pin-audit" in str(x.get("run", ""))])
mut_wf("a step sets shell", "sets shell", lambda d: [x.update(shell='bash -c "true" {0}') for x in J(d, "pin-age")["steps"] if "run" in x][-1:])
mut_wf("a step writes BASH_ENV", "writes the job's environment", lambda d: J(d, "pin-age")["steps"].insert(0, {"run": 'echo "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"'}))
mut_wf("the daily condition gains && false", "not exactly the ratified one", lambda d: J(d, "daily-audit").update({"if": "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' && false"}))
mut_wf("sparse-checkout empties the trusted checker", "checkouts take inputs other than", lambda d: [x["with"].update({"sparse-checkout": "bin"}) for x in J(d, "pin-age")["steps"] if str(x.get("uses", "")).startswith("actions/checkout") and x["with"].get("path") == "trusted"])
mut_wf("a step between the checkouts and the check", "not exactly [trusted checkout", lambda d: J(d, "pin-age")["steps"].insert(2, {"if": "github.event_name == 'pull_request'", "run": 'find trusted -name "*.py" -exec cp /dev/null {} \\;'}))
mut_wf("a secret is used", "uses secrets", lambda d: J(d, "daily-audit")["steps"][-1].setdefault("env", {}).update(X="${{ secrets.PAT }}"))
mut_wf("an unpinned action", "is not pinned to a commit digest", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "actions/checkout@v4"}))
mut_wf("an action off the allowlist", "is not on the allowlist", lambda d: J(d, "pin-age")["steps"].insert(0, {"uses": "evil/action@" + "a" * 40}))
mut_wf("checkout keeps credentials", "persist-credentials", lambda d: next(s for s in J(d, "pin-age")["steps"] if "checkout" in str(s.get("uses", "")))["with"].pop("persist-credentials"))
mut_wf("daily-audit loses issues: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].pop("issues"))
mut_wf("daily-audit gains contents: write", "daily-audit's permissions are not exactly", lambda d: J(d, "daily-audit")["permissions"].update(contents="write"))
mut_wf("daily-audit gains actions: write", "daily-audit has actions write", lambda d: J(d,
        "daily-audit")["permissions"].update(actions="write"))
mut_wf("daily-audit reads actions again", "daily-audit's permissions are not exactly", lambda d: J(d,
        "daily-audit")["permissions"].update(actions="read"))
mut_wf("a top-level concurrency that cancels every event", "not the reviewed block", lambda d: d["concurrency"].update({"cancel-in-progress": "true"}))
mut_wf("a top-level concurrency with a shared ref group", "not the reviewed block", lambda d: d.update(concurrency={"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}))
mut_wf("a top-level concurrency whose pull-request group is shared by re-runs", "not the reviewed block", lambda d: d["concurrency"].update(group=d["concurrency"]["group"].replace(" && github.run_attempt == '1'", "")))
mut_wf("a top-level concurrency that borrows github.workflow", "not the reviewed block", lambda d: d["concurrency"].update(group=d["concurrency"]["group"].replace("'supply-chain-pr-{0}', ", "'{0}-pr-{1}', github.workflow, ").replace("'supply-chain-{0}-{1}', ", "'{0}-{1}-{2}', github.workflow, ")))
mut_wf("a top-level concurrency dropped entirely", "not the reviewed block", lambda d: d.pop("concurrency"))
mut_wf("a top-level concurrency on its own", "not the reviewed block", lambda d: d.update(concurrency={"group": "x", "cancel-in-progress": "false"}))
mut_wf("a fifth job appears", "the jobs are not exactly",
       lambda d: d["jobs"].update({"extra": {"runs-on": "ubuntu-latest"}}))
mut_wf("evidence-letter-present gains id-token", "evidence-letter-present's permissions are not exactly",
       lambda d: J(d, "evidence-letter-present")["permissions"].update({"id-token": "write"}))
mut_wf("evidence-letter-present runs on any event but a pull request",
       "evidence-letter-present's condition is not exactly",
       lambda d: J(d, "evidence-letter-present").update({"if": "github.event_name != 'pull_request'"}))
mut_wf("evidence-letter-present keeps the token in the checkout", "must check out once, with persist-credentials false",
       lambda d: [x["with"].update({"persist-credentials": "true"})
                  for x in J(d, "evidence-letter-present")["steps"] if "uses" in x])
mut_wf("evidence-letter-present runs another script", "run steps are not exactly the cosign install",
       lambda d: [x.update(run="bash bin/other.sh") for x in J(d, "evidence-letter-present")["steps"]
                  if "evidence-letter-present" in str(x.get("run", ""))])
mut_wf("daily-audit loses its concurrency group", "no concurrency group", lambda d: J(d, "daily-audit").pop("concurrency"))
mut_wf("the PR job writes observations", "re-runs a run or records tag observations",
        lambda d: [x.update(run=x["run"] + " --observations-out /tmp/x") for x in J(d, "pin-age")["steps"]
        if "run" in x])
mut_wf("the daily audit records observations again", "re-runs a run or records tag observations",
        lambda d: [x.update(run=x["run"] + " --observations-out /tmp/x") for x in J(d, "daily-audit")["steps"]
        if "pin-audit" in str(x.get("run", ""))])
mut_wf("the daily audit re-runs a run", "re-runs a run or records tag observations",
        lambda d: [x.update(run=x["run"] + "\ngh run rerun 1") for x in J(d, "daily-audit")["steps"]
        if "pin-audit" in str(x.get("run", ""))])
mut_wf("an upload-artifact step appears", "is not on the allowlist", lambda d: J(d,
        "daily-audit")["steps"].append({"uses": "actions/upload-artifact@" + "a" * 40, "with": {"name": "x"}}))
mut_wf("a rerun job comes back", "the jobs are not exactly",
        lambda d: d["jobs"].update({"rerun-pr": {"runs-on": "ubuntu-latest", "permissions": {"actions": "write"},
        "steps": []}}))
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
SIG = lambda d: J(d, "image-signatures")
RUN = lambda d: SIG(d)["steps"][2]      # the steps are [trusted checkout, PR checkout, the check step]
mut_wf("image-signatures is removed", "the jobs are not exactly", lambda d: d["jobs"].pop("image-signatures"))
mut_wf("image-signatures can write contents", "image-signatures' permissions are not exactly",
       lambda d: SIG(d).update(permissions={"contents": "write"}))
mut_wf("image-signatures gets an id-token", "image-signatures' permissions are not exactly",
       lambda d: SIG(d).update(permissions={"contents": "read", "id-token": "write"}))
mut_wf("image-signatures skips bots", "does not run on exactly pull_request",
       lambda d: SIG(d).update({"if": "github.actor != 'dependabot[bot]'"}))
mut_wf("image-signatures runs on every event", "does not run on exactly pull_request", lambda d: SIG(d).pop("if"))
for key, val in (("needs", "pin-age"), ("strategy", {"matrix": {"x": ["1"]}}),
                 ("continue-on-error", "true"), ("environment", "prod")):
    mut_wf(f"image-signatures gets {key}", "does not run on exactly pull_request",
           lambda d, k=key, v=val: SIG(d).update({k: v}))
mut_wf("image-signatures has no timeout bound", "no bounded timeout-minutes",
       lambda d: SIG(d).update({"timeout-minutes": "120"}))
mut_wf("image-signatures runs the PR's checker", "does not run the BASE branch's checker",
       lambda d: RUN(d).update(run=RUN(d)["run"].replace("trusted/.github", "pr/.github")))
mut_wf("image-signatures takes the PR's tools file", "does not run the BASE branch's checker",
       lambda d: RUN(d).update(run=RUN(d)["run"].replace("trusted/bin/", "pr/bin/")))
mut_wf("image-signatures puts the head sha inline", "inside run",
       lambda d: RUN(d).update(run=RUN(d)["run"].replace('"$HEAD_SHA"', "${{ github.event.pull_request.head.sha }}")))
mut_wf("image-signatures passes a token", "does not take exactly HEAD_SHA",
       lambda d: RUN(d)["env"].update(GH_TOKEN="${{ github.token }}"))
mut_wf("image-signatures sets PYTHONPATH", "sets env", lambda d: RUN(d)["env"].update(PYTHONPATH="pr"))
mut_wf("image-signatures gains a flag", "differ from the ratified text",
       lambda d: RUN(d).update(run=RUN(d)["run"] + " --report-only"))
mut_wf("image-signatures gets a third checkout", "exactly two checkouts",
       lambda d: SIG(d)["steps"].insert(0, {"uses": "actions/checkout@" + "a" * 40,
                                            "with": {"persist-credentials": "false"}}))
mut_wf("image-signatures checks out the head as trusted", "trusted checkout is not the BASE",
       lambda d: SIG(d)["steps"][0]["with"].update(ref="${{ github.event.pull_request.head.sha }}"))
mut_wf("image-signatures keeps credentials", "persist-credentials",
       lambda d: SIG(d)["steps"][0]["with"].update({"persist-credentials": "true"}))
mut_wf("image-signatures has a container", "has a job-level container",
       lambda d: SIG(d).update(container="evil/image:latest"))
mut_wf("top-level permissions widened", "no top-level permissions block", lambda d: d.update(permissions={"contents": "write"}))
# --- dependabot ---
mut_db("github-actions gets a cooldown", "github-actions / entry has a cooldown", lambda d: eco(d, "github-actions").update(cooldown={"default-days": "7"}))
mut_db("pip gets a cooldown", "pip /.github/agent entry has a cooldown", lambda d: eco(d, "pip").update(cooldown={"default-days": "7"}))
mut_db("gomod gains an ignore rule", "the gomod / entry is not unchanged", lambda d: eco(d, "gomod").update(ignore=[{"dependency-name": "x"}]))
mut_db("gomod's schedule changes", "the gomod / entry is not unchanged", lambda d: eco(d, "gomod")["schedule"].update(interval="monthly"))
mut_db("a docker entry returns for /build/docker", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/build/docker", "schedule": {"interval": "daily"}}))
mut_db("a docker entry returns for the root", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/", "schedule": {"interval": "weekly"}}))
mut_db("a docker entry returns with a cooldown", "docker entry is back", lambda d: d["updates"].append({"package-ecosystem": "docker", "directory": "/build/docker", "schedule": {"interval": "daily"}, "cooldown": {"default-days": "7"}}))
mut_db("gomod is removed", "the gomod / entry is missing", lambda d: d["updates"].remove(eco(d, "gomod")))
TOOL = lambda d: next(u for u in d["updates"] if u.get("directory") == "/tools/govulncheck")
mut_db("the govulncheck tool entry is removed", "govulncheck tool entry", lambda d: d["updates"].remove(TOOL(d)))
mut_db("the govulncheck tool entry gets a cooldown", "govulncheck tool entry", lambda d: TOOL(d).update(cooldown={"default-days": "7"}))
mut_db("the govulncheck tool entry watches another directory", "govulncheck tool entry", lambda d: TOOL(d).update(directory="/tools/requirements"))
mut_db("the govulncheck tool entry runs daily", "govulncheck tool entry", lambda d: TOOL(d)["schedule"].update(interval="daily"))
mut_db("the govulncheck tool entry ignores a dependency", "govulncheck tool entry", lambda d: TOOL(d).update(ignore=[{"dependency-name": "golang.org/x/vuln"}]))
mut_db("the govulncheck tool entry is repeated", "govulncheck tool entry", lambda d: d["updates"].append(copy.deepcopy(TOOL(d))))
mut_db("gomod gets a cooldown", "gomod / entry has a cooldown", lambda d: eco(d, "gomod").update(cooldown={"default-days": "7"}))
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
mut_db("the tools/requirements entry gets a cooldown", "the gomod /tools/requirements entry is not exactly weekly", lambda d: gmod(d, "/tools/requirements").update(cooldown={"default-days": "7"}))
mut_db("the tools/requirements schedule changes", "the gomod /tools/requirements entry is not exactly weekly", lambda d: gmod(d, "/tools/requirements")["schedule"].update(interval="daily"))
mut_db("the tools/requirements group gets applies-to", "sets applies-to", lambda d: gmod(d, "/tools/requirements")["groups"]["gomod-minor-patch"].update({"applies-to": "version-updates"}))
mut_db("the root gomod entry is duplicated", "duplicate gomod / entry", lambda d: d["updates"].append(copy.deepcopy(gmod(d, "/"))))
mut_db("the root entry is broken while tools/requirements stays", "the gomod / entry is not unchanged", lambda d: gmod(d, "/")["schedule"].update(interval="monthly"))
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
