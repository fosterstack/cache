#!/usr/bin/env bash
# proves: REQ-SCAN-015-AC2 — the scanner guard is run by the review gate from main's copy over the PR head (agent-review-gate.yml); ci.yml's allowlist job no longer runs it
# proves: REQ-CI-001-AC1, REQ-CI-001-AC2, REQ-CI-001-AC3, REQ-CI-001-AC4 — allowlist-chain is accepted only as the suite-list job, the one matrix job of suites and the exact gate (the suites and gate cases)
# proves: REQ-CI-005-AC2 — a counting step is accepted only in exactly its form (the count-step cases)
# proves: REQ-REL-004-AC1 — the pull-request gate's govulncheck job judges the way Check does: it is accepted only in exactly its form (the govulncheck-gate cases)
# REQ-REL-005-AC1 (register row 78): the review gate (.github/workflows/agent-review-gate.yml) runs main's pin checker and this
# judge over every pull request head, and ci.yml's workflow triggers cannot be narrowed to skip the rest. (Mapped from the product
# matrix as workflow-job evidence: REQ-AUD-18 AC1 keeps .github/agent/ paths out of files outside it.)
# The real ci.yml must pass; each mutated copy must be caught.
# The checks of a pull request's own tree can be edited by that pull request; the gate re-runs main's copies over the PR head.
set -euo pipefail
here=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0


judge() { PIN_WIRING_WORKFLOWS_DIR="${PIN_WIRING_WORKFLOWS_DIR:-$here/.github/workflows}" PIN_WIRING_FLOORS_FILE="${PIN_WIRING_FLOORS_FILE:-$here/test-evidence/suite-floors.json}" PIN_WIRING_POLICY_FILE="${PIN_WIRING_POLICY_FILE:-$here/.github/policy/required-checks.json}" PIN_WIRING_SUITES_FILE="${PIN_WIRING_SUITES_FILE:-$here/.github/policy/ci-suites.json}" python3 - "$1" <<'PY'
import sys, os, yaml
# cheap pre-parse, BEFORE any structure is built: a token scan is linear and expands nothing, so an
# anchor/alias bomb cannot hang the judge; the pin checker refuses anchors and aliases too
_text = open(sys.argv[1]).read()
_n = 0
for _t in yaml.scan(_text, Loader=yaml.BaseLoader):
    _n += 1
    if isinstance(_t, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken)):
        print("the workflow uses a YAML anchor or alias"); sys.exit(1)
    if _n > 200000:
        print("the workflow is implausibly large"); sys.exit(1)
# a duplicate mapping key silently keeps the LAST value in the parsed structure: refuse it anywhere in the file
_dups = []
def _walk(n, path):
    if isinstance(n, yaml.MappingNode):
        seen = set()
        for k, v in n.value:
            kk = k.value if isinstance(k, yaml.ScalarNode) else None
            if kk in seen:
                _dups.append(path + "/" + str(kk))
            seen.add(kk)
            _walk(v, path + "/" + str(kk))
    elif isinstance(n, yaml.SequenceNode):
        for i, v in enumerate(n.value):
            _walk(v, path + "/" + str(i))
_walk(yaml.compose(_text, Loader=yaml.BaseLoader), "")
if _dups:
    print("the workflow has duplicate YAML key(s): " + ", ".join(_dups[:5])); sys.exit(1)
d = yaml.load(_text, Loader=yaml.BaseLoader)   # every scalar a string, as GitHub reads it
# REQ-CI-005: a floored suite may be run by a counting step, `python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json NAME PATH` (NAME the file name of
# PATH, a suite the committed floors file names), which runs it once and holds it to its floor and to exit 0. Every such line (optionally after env assignments, and
# with a trailing </dev/null) is read back to the plain `bash PATH` line it stands for, so every exact-run check below judges one text for both forms; a line that
# is not exactly this form is left as written and is judged (and refused) as any other unknown run text.
import json as _json_, re as _re_
try:
    _floored_ = set(_json_.load(open(os.environ["PIN_WIRING_FLOORS_FILE"])))
except Exception:
    _floored_ = set()
_COUNT_ = _re_.compile(r"((?:CHAIN_TEST_REQUIRE_NETCUT=1 )?)python3 -I bin/suite-guard-run\.py run test-evidence/suite-floors\.json (\S+) (\S+)( </dev/null)?")
def _unwrap_(line):
    m = _COUNT_.fullmatch(line)
    if not m or m.group(2) not in _floored_ or os.path.basename(m.group(3)) != m.group(2):
        return line
    return m.group(1) + "bash " + m.group(3) + (m.group(4) or "")
if isinstance(d, dict):
    for _j_ in (d.get("jobs") or {}).values():
        for _st_ in (_j_.get("steps") or []) if isinstance(_j_, dict) else []:
            if isinstance(_st_, dict) and isinstance(_st_.get("run"), str):
                _st_["run"] = "\n".join(_unwrap_(l) for l in _st_["run"].split("\n"))
bad = []
for k in sorted(set(d) - {"name", "on", "permissions", "jobs", "concurrency"}):
    bad.append(f"the workflow sets `{k}`")
# the one reviewed concurrency block (advisor, Oct 22; cache#583): a pull request's FIRST run attempt of a head shares a group with the pull request's other first attempts, so a newer
# push cancels its older run; every other run (a re-run of any head, a push to main, a merge_group) gets a group of its own per run and attempt, so ci.yml itself never cancels it nor
# replaces it as a pending run, and a re-run of an old head cancels nothing. Anything else is refused: a shared group or cancel-in-progress on other events could cancel a required check.
# Concurrency groups are repository-wide: another workflow that picks a colliding group is not checked here (a computed group defeats a prefix check, and a cancel fails closed:
# a cancelled check is not a success).
if "concurrency" in d and d["concurrency"] != {
        "group": "${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}:
    bad.append("the workflow's concurrency is not the reviewed block")
if d.get("permissions") != {"contents": "read"}:
    bad.append("the workflow permissions are not exactly {contents: read}")
on = d.get("on", {})
if "pull_request" not in on:
    bad.append("not triggered on pull_request")
pr = on.get("pull_request") if isinstance(on, dict) else None
if isinstance(pr, dict) and pr:
    bad.append("pull_request is filtered: " + ", ".join(sorted(pr)))
push = on.get("push") if isinstance(on, dict) else None
if not isinstance(push, dict) or push.get("branches") != ["main"]:
    bad.append("not triggered on push to main")
elif set(push) != {"branches"}:
    bad.append("push is filtered: " + ", ".join(sorted(set(push) - {"branches"})))
# the only triggers ci.yml may have: push (main) and pull_request. workflow_call and workflow_dispatch are refused: a called or dispatched run
# would carry another context into the reviewed concurrency group.
if isinstance(on, dict) and sorted(set(on) - {"push", "pull_request"}):
    bad.append("ci.yml has triggers beyond push and pull_request: " + ", ".join(sorted(set(on) - {"push", "pull_request"})))
# no job of ci.yml may carry a concurrency setting: a job group competes with its parent workflow's group and can cancel the whole run
for _jid, _j in (d.get("jobs") or {}).items():
    if isinstance(_j, dict) and "concurrency" in _j:
        bad.append(f"the job {_jid} has `concurrency`")
if "defaults" in d:
    bad.append("the workflow sets `defaults` (a shell override could skip every run)")
job = d.get("jobs", {}).get("allowlist", {})
# the guard's job is exactly name / runs-on / steps: no `needs` (a skipped prerequisite skips the whole guard),
# `if`, `timeout-minutes`, `permissions`, `strategy`, `concurrency`, `container`, `services`, `env`, `defaults`, ...
for k in sorted(set(job) - {"name", "runs-on", "steps"}):
    bad.append(f"the allowlist job has `{k}`")
if job.get("runs-on") != "ubuntu-latest":
    bad.append("the allowlist job does not run on exactly `ubuntu-latest` (GitHub-hosted)")
want = {"bash .github/agent/tests/check-action-pins-test.sh",
        "bash .github/agent/tests/auditor-matrix-test.sh", "bash .github/agent/tests/auditor-labels-test.sh"}  # REQ-CI-005: their counting steps, split out of the parser-tests block (cache#705 round 1)
seen = set()
for st in job.get("steps", []):
    run = (st.get("run") or "").strip()
    if run in want:
        seen.add(run)
        for k in ("if", "continue-on-error", "shell", "working-directory") + (("env",) if run == "bash .github/agent/tests/check-action-pins-test.sh" else ()):   # env on the cases step: the PINS_* controls (shard, dry, serial, self, jobs) are never set from the workflow
            if k in st:
                bad.append(f"the step `{run}` has `{k}`")
        if run in ("bash .github/agent/tests/auditor-matrix-test.sh", "bash .github/agent/tests/auditor-labels-test.sh"):     # REQ-CI-005: a counting step is trusted only with no key but name and run, so any other key makes `all` run the suite again
            for k in sorted(set(st) - {"name", "run"}):
                bad.append(f"the counting step `{run}` has `{k}` (a counting step has no key but name and run)")
# nothing may redirect how those steps execute (step 8 r3, residual 2): a shell startup file, an
# environment or PATH written for later steps, interpreter search paths, or a checkout of another tree
import json
hooks = ("BASH_ENV", "GITHUB_ENV", "GITHUB_PATH")
text = json.dumps(job)
for h in hooks:
    if h in text:
        bad.append(f"the allowlist job mentions {h}")
import re
risky = {"BASH_ENV", "ENV", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "SHELLOPTS", "BASHOPTS", "PS4", "IFS",
         "PROMPT_COMMAND", "CDPATH", "GLOBIGNORE", "TMPDIR", "HOME", "XDG_CONFIG_HOME"}
def is_risky(k):
    return k in risky or re.match(r"(GIT_|GITHUB_|LD_|DYLD_|PYTHON|BASH_|RUNNER_)", k) is not None
steps_all = job.get("steps", [])
for where, env in [("the workflow", d.get("env")), ("the allowlist job", job.get("env"))] + \
        [(f"step {i}", st.get("env")) for i, st in enumerate(steps_all)]:
    if isinstance(env, dict):
        for k in sorted(k for k in env if is_risky(k)):
            bad.append(f"{where} sets env {k}")
# nothing that reaches every step of the allowlist job from above
for k in ("env", "defaults", "container", "services", "strategy"):
    if k in job:
        bad.append(f"the allowlist job sets `{k}`")
if "env" in d:
    bad.append("the workflow sets `env`")
for st in job.get("steps", []):
    if str(st.get("uses", "")).startswith("actions/checkout@"):
        w = st.get("with") or {}
        for k in ("ref", "repository", "path"):
            if k in w:
                bad.append(f"the checkout selects another tree ({k})")
# the allowlist job is named `allowlist` (the required-check context), its checkout is full-depth and first, and the base-ref fetch is exactly the one step
# below it, which takes the base name through env (never inline in the script) and refuses an odd name before it fetches
if job.get("name") != "allowlist":
    bad.append("the allowlist job is not named `allowlist` (the required-check context)")
FETCH_RUN = """# empty on a push (nothing to compare against); on a pull request refuse an odd base name before the fetch
if [ -n "${BASE}" ]; then
  [[ "${BASE}" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1
  [[ "${BASE}" != *..* ]] || exit 1
  git fetch --no-tags origin "+refs/heads/${BASE}:refs/remotes/origin/${BASE}"
fi"""
def norm(r):  # drop comment lines; the command text itself must match exactly. A comment line is one whose first
    # character after ONLY spaces and tabs is `#` (bash's rule; Python's str.strip/lstrip/splitlines also
    # treat U+00A0, U+3000, U+2028 ... as whitespace or line ends, which bash does not)
    return "\n".join(l for l in (r or "").strip(" \t\n").split("\n") if not l.lstrip(" \t").startswith("#"))
def odd_chars(r):  # anything but printable ASCII, tab and newline in a protected run string
    return sorted({hex(ord(c)) for c in (r or "") if not (c in "\t\n" or " " <= c <= "~")})
steps_ = job.get("steps", [])
for i, st in enumerate(steps_):
    if i == 1 or "git fetch" in (st.get("run") or ""):
        if odd_chars(st.get("run")):
            bad.append(f"a protected allowlist step's run text has non-ASCII or control characters {odd_chars(st.get('run'))}")
    if "git fetch" in (st.get("run") or "") and "${{" in (st.get("run") or ""):   # raw text, comment lines included: an expression is rendered before bash sees it
        bad.append("a protected allowlist step's run text contains a `${{` expression")
plain = ("if", "continue-on-error", "shell", "working-directory", "timeout-minutes")
fetch_idx = [i for i, st in enumerate(steps_) if norm(st.get("run")) == norm(FETCH_RUN)]
co = [i for i, st in enumerate(steps_) if str(st.get("uses", "")).startswith("actions/checkout@")]
if not co or co[0] != 0:
    bad.append("the allowlist job does not start with the checkout")
else:
    if steps_[0].get("with") != {"fetch-depth": "0"}:
        bad.append("the allowlist checkout is not exactly `fetch-depth: 0`")
    for k in plain + ("env",):
        if k in steps_[0]:
            bad.append(f"the allowlist checkout has `{k}`")
if len(fetch_idx) != 1 or any("git fetch" in (st.get("run") or "") for i, st in enumerate(steps_) if i not in fetch_idx):
    bad.append("the allowlist job does not have exactly one fetch step with the exact command")
else:
    st = steps_[fetch_idx[0]]
    if st.get("env") != {"BASE": "${{ github.base_ref }}"}:
        bad.append("the allowlist fetch step env is not exactly {'BASE': '${{ github.base_ref }}'}")
    for k in plain:
        if k in st:
            bad.append(f"the allowlist fetch step has `{k}`")
if fetch_idx != [1]:
    bad.append("the allowlist job's first two steps are not exactly: checkout, base-ref fetch (nothing before or between)")
for w in sorted(want - seen):
    bad.append(f"no step runs `{w}`")
# The jobs that run the suites (REQ-CI-001; a required job that is skipped, or whose step is skipped, disabled through its environment, or whose failure is ignored, passes
# while the suites never ran). Each is EXACTLY the form below (every key, name, uses, with, env and run text, in order): the list job reads the committed suite list, the
# suites job runs one leg per suite of it with the failure of any leg counting, and the gate keeps the name allowlist-chain and fails unless the suites job succeeded.
# The suite list itself is judged below. This judge cannot be changed by a pull request for itself (the review gate runs main's copy).
def _by_shape(st):
    """A step with `uses: name@<full 40-hex commit>` stands for every digest of
    that action: the digest VALUE is judged by
    check-action-pins --verify-tags, pin-age and the daily audit (a Dependabot bump moves it), not by these lists. The
    action name and the exact shape of the ref (40 lower-case hex) stay compared; the stand-in is a tuple, which no YAML
    scalar can equal."""
    u = st.get("uses")
    if isinstance(u, str) and u.count("@") == 1:
        name, _, ref = u.partition("@")
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return dict(st, uses=(name, "@40-hex"))
    return st


EXPECT = json.loads(r'''{
 "suite-list": {
  "name": "suite-list",
  "runs-on": "ubuntu-latest",
  "outputs": {
   "suites": "${{ steps.list.outputs.suites }}"
  },
  "steps": [
   {
    "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "with": {
     "persist-credentials": "false"
    }
   },
   {
    "id": "list",
    "run": "echo \"suites=$(jq -c . .github/policy/ci-suites.json)\" >> \"$GITHUB_OUTPUT\""
   }
  ]
 },
 "suites": {
  "name": "suites (${{ matrix.suite }})",
  "needs": "suite-list",
  "runs-on": "ubuntu-latest",
  "strategy": {
   "fail-fast": "false",
   "matrix": {
    "include": "${{ fromJSON(needs.suite-list.outputs.suites) }}"
   }
  },
  "steps": [
   {
    "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "with": {
     "fetch-depth": "0"
    }
   },
   {
    "name": "set up Python",
    "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
    "with": {
     "python-version": "3.12"
    }
   },
   {
    "name": "pin pip (hash-checked)",
    "run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/pip-requirements.txt\npython3 -m pip --version\n"
   },
   {
    "name": "the hash-pinned test requirements (PyYAML, which the wiring suites read the workflows with, and the report lint's cmark-gfm)",
    "run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/test-requirements.txt\n"
   },
   {
    "name": "install the pinned grype (the suites that run the real scanner)",
    "if": "${{ matrix.grype }}",
    "run": "./bin/install-scanner.sh grype"
   },
   {
    "name": "the suite, held to its floor",
    "env": {
     "SUITE": "${{ matrix.suite }}",
     "CHAIN_TEST_REQUIRE_NETCUT": "1"
    },
    "run": "path=$(git ls-files -- \"bin/$SUITE\" \".github/agent/tests/$SUITE\")\npython3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json \"$SUITE\" \"$path\"\n"
   }
  ]
 },
 "allowlist-chain": {
  "name": "allowlist-chain",
  "runs-on": "ubuntu-latest",
  "needs": [
   "suites"
  ],
  "if": "${{ always() }}",
  "steps": [
   {
    "name": "every suite succeeded (a failed, skipped, cancelled or missing result fails)",
    "env": {
     "RESULT": "${{ needs.suites.result }}"
    },
    "run": "[ \"$RESULT\" = success ] || { echo \"the suites did not all succeed: [$RESULT]\"; exit 1; }"
   }
  ]
 },
 "__floors_step__": {
  "name": "suite floors only rise (against the merge base on a pull request)",
  "if": "${{ github.base_ref != '' }}",
  "env": {
   "BASE": "${{ github.base_ref }}",
   "PR_BODY": "${{ github.event.pull_request.body }}"
  },
  "run": "bash bin/suite-guard.sh floors-vs-base --allow-from-body \"$(git merge-base HEAD \"origin/${BASE}\")\" \\\n  test-evidence/suite-floors.json\n"
 }
}''')
FLOORS_STEP = EXPECT.pop("__floors_step__")   # the floors-only-rise step carries an `if` and an `env` on purpose: judged as a whole step, every key and value
if [st for st in steps_ if st.get("name") == FLOORS_STEP["name"]] != [FLOORS_STEP]:
    bad.append(f"the allowlist job does not have exactly the guard step {FLOORS_STEP['name']!r} as judged (every key and value)")
_jobs_ = d.get("jobs") or {}
def _job_shape(j):
    return dict(j, steps=[_by_shape(s) if isinstance(s, dict) else s for s in j.get("steps") or []])
for jid, want_job in EXPECT.items():
    got = _jobs_.get(jid)
    if not isinstance(got, dict):
        bad.append(f"the job {jid} is missing")
        continue
    g, w = _job_shape(got), _job_shape(want_job)
    if g != w:
        keys = sorted(k for k in set(g) | set(w) if g.get(k) != w.get(k))
        msg = f"the job {jid} is not exactly the judged form (differs in: {', '.join(keys)})"
        if "steps" in keys:
            for _i, (_g, _w) in enumerate(zip(g["steps"], w["steps"])):
                if _g != _w:
                    _sk = sorted(k for k in set(_g) | set(_w) if _g.get(k) != _w.get(k))
                    msg += f"; the {jid} step {_i + 1} ({_g.get('name') or _g.get('uses')}) differs in: {', '.join(_sk)}"
                    break
            else:
                msg += "; the number of steps differs"
        bad.append(msg)
# the committed suite list (REQ-CI-005): a readable list of suites, each a test script named by its file name with an optional `grype: true`; every suite the floors file names runs
# exactly once in all of ci.yml and the list (a counting step or a plain `bash PATH` line of a job, or one entry of the list), so a suite cannot be dropped from the list unseen
try:
    _suites_ = _json_.load(open(os.environ["PIN_WIRING_SUITES_FILE"]))
    if not (isinstance(_suites_, list) and all(isinstance(e, dict) and set(e) <= {"suite", "grype"} and isinstance(e.get("suite"), str) and e.get("grype", True) is True
                                                and re.fullmatch(r"[A-Za-z0-9._-]+-test\.sh", e["suite"]) for e in _suites_)):
        raise ValueError("not a list of suites")
except (OSError, ValueError):
    _suites_ = None
    bad.append("the suite list is unreadable or not a list of {suite, grype} test scripts")
if _suites_ is not None:
    _listed_ = [e["suite"] for e in _suites_]
    _counted_ = []
    for _j_ in _jobs_.values():
        for _st_ in (_j_.get("steps") or []) if isinstance(_j_, dict) else []:
            for _l_ in (_st_.get("run") or "").split("\n") if isinstance(_st_, dict) else []:
                _m_ = _re_.fullmatch(r"(?:CHAIN_TEST_REQUIRE_NETCUT=1 )?bash (\S+)(?: </dev/null)?", _l_.strip())
                if _m_ and os.path.basename(_m_.group(1)) in _floored_:
                    _counted_.append(os.path.basename(_m_.group(1)))
    for _n_ in sorted(_floored_):
        _k_ = _listed_.count(_n_) + _counted_.count(_n_)
        if _k_ != 1:
            bad.append(f"the floored suite {_n_} runs {_k_} times across ci.yml and the suite list, not once (REQ-CI-005)")
    for _n_ in sorted({n for n in _listed_ if _listed_.count(n) > 1}):
        bad.append(f"the suite list names {_n_} more than once")
# the required-check policy (release admission reads it): a readable JSON object whose required_checks is a list of objects with unique contexts,
# and exactly one correct entry (integration 15368, scope push) for each protected job. Anything unreadable or malformed is refused (fail closed).
PROTECTED = ("allowlist", "allowlist-chain")
try:
    pol = json.load(open(os.environ["PIN_WIRING_POLICY_FILE"]))["required_checks"]
    if not isinstance(pol, list) or not all(isinstance(c, dict) for c in pol):
        raise ValueError("required_checks is not a list of objects")
except (OSError, ValueError, KeyError, TypeError) as e:
    pol = None
    bad.append(f"required-checks.json is unreadable or malformed ({type(e).__name__})")
if pol is not None:
    ctxs = [c.get("context") for c in pol]
    for dup in sorted({c for c in ctxs if ctxs.count(c) > 1}, key=str):
        bad.append(f"required-checks.json lists the context {dup} more than once")
    for jid in PROTECTED:
        if sum(1 for c in pol if c == {"context": jid, "integration_id": 15368, "scope": "push"}) != 1 or ctxs.count(jid) != 1:
            bad.append(f"required-checks.json does not have exactly one entry {jid} (integration 15368, scope push)")
# the protected check names belong to their jobs alone: no other job of this workflow may produce a check run with such a name (a job named
# `allowlist-chain` that succeeds after the real one failed satisfies admission, which accepts any success with the matching name), and no job
# name may be an expression or come from a matrix (its rendered name cannot be judged).
def name_disjoint(nm):   # a literal name is compared as it is; an expression name may hold only plain `${{ matrix.a.b }}` tokens and must keep a
    nm = str(nm)        # literal space or `(` around them (no protected name has either); any other `${{` is refused, never parsed
    if "${{" not in nm:
        return True
    rest = re.sub(r"\$\{\{ *matrix(\.[A-Za-z_][A-Za-z0-9_]*)+ *\}\}", "", nm)
    return "${{" not in rest and "}}" not in rest and bool(re.search(r"[ (]", rest))
def writes_checks(perm):   # GITHUB_TOKEN authenticates as the Actions app (integration 15368): checks: write can publish a check with a protected name
    return perm == "write-all" or (isinstance(perm, dict) and perm.get("checks") == "write")
for jid_, j_ in d.get("jobs", {}).items():
    if not isinstance(j_, dict):
        continue
    nm = j_.get("name", jid_)
    if jid_ not in PROTECTED and (nm in PROTECTED or jid_ in PROTECTED):
        bad.append(f"the job {jid_} produces the protected check name {nm}")
    if jid_ not in PROTECTED and not name_disjoint(nm):
        bad.append(f"the job {jid_} has an expression name that could render as a protected check name")
    if writes_checks(j_.get("permissions")):
        bad.append(f"the job {jid_} can write checks with the Actions token (it could publish a check run under a protected name)")
if writes_checks(d.get("permissions")):
    bad.append("the workflow can write checks with the Actions token (it could publish a check run under a protected name)")
# and no other workflow file may carry such a job either (admission accepts any success with the matching name and app); an unreadable or
# unparseable workflow file is refused, since its job names cannot be judged
_wdir = os.environ["PIN_WIRING_WORKFLOWS_DIR"]
for _f in sorted(os.listdir(_wdir)):
    if not _f.endswith((".yml", ".yaml")) or _f == "ci.yml":
        continue
    try:
        _w = yaml.load(open(os.path.join(_wdir, _f)).read(), Loader=yaml.BaseLoader)
        _jobs = (_w or {}).get("jobs") or {}
        if not isinstance(_jobs, dict):
            raise ValueError("jobs is not a mapping")
    except Exception as e:
        bad.append(f"the workflow {_f} cannot be read ({type(e).__name__}), so its job names cannot be judged")
        continue
    if "permissions" not in (_w or {}):   # omitted permissions inherit the repository default, which may include checks: write
        bad.append(f"{_f}: no workflow-level `permissions` (an omitted block inherits repository defaults that may allow writing checks)")
    for _jid, _j in _jobs.items():
        _nm = _j.get("name", _jid) if isinstance(_j, dict) else _jid
        if _jid in PROTECTED or _nm in PROTECTED:
            bad.append(f"{_f}: the job {_jid} takes the protected check name {_nm if _nm in PROTECTED else _jid}")
        elif not name_disjoint(_nm):
            bad.append(f"{_f}: the job {_jid} has an expression name that could render as a protected check name")
        if isinstance(_j, dict) and writes_checks(_j.get("permissions")):
            bad.append(f"{_f}: the job {_jid} can write checks with the Actions token")
    if writes_checks((_w or {}).get("permissions")):
        bad.append(f"{_f}: the workflow can write checks with the Actions token")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}

# PR B (read-back approved by the advisor, Oct 23; Fable ruling of record cache#703): the pull-request gate's govulncheck job (the required context) installs the pinned Go, installs
# govulncheck at the version tools/govulncheck pins, and runs bin/check-govulncheck.py by its fixed path on the repository's scanner list, as its LAST step and with nothing between:
# the step list is exactly checkout, setup-go, the installer, the install and the script; the job keeps its name, contents: read, and holds no secret, id-token or environment.
# It is defined BEFORE judge mode because the trusted gate (which re-runs main's copy of this script over the PR head) runs it there too (REQ-REL-004-AC1; the scan is REQ-CHAIN-006-AC18).
gvgate_judge() { # gvgate_judge CIYML GOMOD : exit 0 when the job named govulncheck is exactly the Check-equivalent form (the pin is the one in GOMOD)
  python3 - "$1" "$2" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
pin = None
for line in open(sys.argv[2]):
    m = re.match(r"^\s*(?:require\s+)?golang\.org/x/vuln\s+(v\d+\.\d+\.\d+)\b", line)
    if m: pin = m.group(1); break
if not pin: sys.exit(1)
j = (d.get("jobs") or {}).get("govulncheck")
if not isinstance(j, dict): sys.exit(1)
bad = []
if j.get("name") != "govulncheck": bad.append("name")
if j.get("permissions") != {"contents": "read"}: bad.append("permissions")
if set(j) - {"name", "runs-on", "permissions", "steps"}: bad.append("job keys")
steps = j.get("steps") or []
if len(steps) != 5: bad.append("step count")
else:
    s0, s1, s2, s3, s4 = steps
    if not str(s0.get("uses", "")).startswith("actions/checkout@") or set(s0) - {"uses"}: bad.append("checkout step")
    if not str(s1.get("uses", "")).startswith("actions/setup-go@") or set(s1) - {"uses", "with"}: bad.append("setup-go step")
    if s2.get("run") != "bash bin/install-scanner.sh go" or set(s2) - {"name", "run"}: bad.append("installer step")
    if s3.get("run") != "go install golang.org/x/vuln/cmd/govulncheck@" + pin or set(s3) - {"name", "run"}: bad.append("install step")
    if s4.get("run") != 'python3 -I -B bin/check-govulncheck.py --scanners .github/policy/scanners.json --out "$RUNNER_TEMP/gv"' or set(s4) - {"name", "run"}: bad.append("script step")
sys.exit(1 if bad else 0)
PY
}
# judge mode, for the trusted review gate: judge the ci.yml of one commit of the current repo, read as a git
# object (never checked out, never run), and nothing else
if [ -n "${PIN_WIRING_JUDGE_GIT:-}" ]; then
  git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/ci.yml" > "$work/head-ci.yml" || { echo "pin-wiring: no ci.yml at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  git show "${PIN_WIRING_JUDGE_GIT}:.github/policy/required-checks.json" > "$work/head-policy.json" || { echo "pin-wiring: no required-checks.json at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  mkdir -p "$work/head-wf"
  for wf in $(git ls-tree --name-only "${PIN_WIRING_JUDGE_GIT}" .github/workflows/ | sed 's|.*/||'); do   # every workflow of the commit, as git objects
    git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/$wf" > "$work/head-wf/$wf" || { echo "pin-wiring: cannot read workflow $wf" >&2; exit 1; }
  done
  git show "${PIN_WIRING_JUDGE_GIT}:test-evidence/suite-floors.json" > "$work/head-floors.json" 2> /dev/null || echo '{}' > "$work/head-floors.json"     # REQ-CI-005: the floors file of the judged commit, as the policy file is
  git show "${PIN_WIRING_JUDGE_GIT}:.github/policy/ci-suites.json" > "$work/head-suites.json" 2> /dev/null || echo '{}' > "$work/head-suites.json"     # and the suite list of the judged commit (a missing one is refused by the judge)
  git show "${PIN_WIRING_JUDGE_GIT}:tools/govulncheck/go.mod" > "$work/head-gomod" || { echo "pin-wiring: no tools/govulncheck/go.mod at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  PIN_WIRING_WORKFLOWS_DIR="$work/head-wf" PIN_WIRING_POLICY_FILE="$work/head-policy.json" PIN_WIRING_FLOORS_FILE="$work/head-floors.json" PIN_WIRING_SUITES_FILE="$work/head-suites.json" judge "$work/head-ci.yml" || exit 1
  gvgate_judge "$work/head-ci.yml" "$work/head-gomod" || { echo "pin-wiring: the govulncheck job of the head's ci.yml is not the Check-equivalent form (REQ-REL-004-AC1)" >&2; exit 1; }
  exit 0
fi

case_() {  # case_ <name> <expect ok|bad> <python edit of the parsed copy, or empty>
  local f="$work/$1.yml"
  cp "$here/.github/workflows/ci.yml" "$f"
  # an edit that cannot apply (its step is missing) is a failed case, not an aborted run
  if [ -n "$3" ]; then python3 - "$f" "$3" 2> /dev/null <<'PY' || { failn=$((failn+1)); echo "FAIL $1 → the edit did not apply"; return 0; }
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}

# case_msg <name> <python edit> <text>: the judge refuses the copy and its message holds the text
case_msg() {
  local f="$work/$1.yml"
  cp "$here/.github/workflows/ci.yml" "$f"
  python3 - "$f" "$2" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = bad ] && grep -qF -- "$3" <<<"$out"; then pass=$((pass+1)); echo "PASS $1 → bad, names: $3"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want bad naming: $3 ($out)"; fi
}

steps='d["jobs"]["allowlist"]["steps"]'
pick='[s for s in '"$steps"' if "check-action-pins-test.sh" in (s.get("run") or "")][0]'
case_ the-real-hygiene      ok  ""
# REQ-CI-005: a floored suite's step may call the counting runner instead of `bash PATH`; exactly that form is read back to the plain line, anything else is judged as unknown text
CW="[s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip() in ('bash .github/agent/tests/check-action-pins-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh')][0]"
CF="python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json"
case_ count-step-wrapped-ok         ok  "w = $CW; w['run'] = '$CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ count-step-devnull-added      bad "w = $CW; w['run'] = '$CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh </dev/null'"
case_ count-step-name-not-path      bad "w = $CW; w['run'] = '$CF install-scanner-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ count-step-other-path         bad "w = $CW; w['run'] = '$CF install-scanner-test.sh bin/install-scanner-test.sh'"
case_ count-step-unfloored-name     bad "w = $CW; w['run'] = '$CF zz-not-floored-test.sh bin/zz-not-floored-test.sh'"
case_ count-step-other-floors       bad "w = $CW; w['run'] = 'python3 -I bin/suite-guard-run.py run /tmp/floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ count-step-count-only         bad "w = $CW; w['run'] = 'python3 -I bin/suite-guard-run.py run --count-only test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ count-step-or-true            bad "w = $CW; w['run'] = '$CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh || true'"
case_ count-step-no-isolation       bad "w = $CW; w['run'] = 'python3 bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ count-step-twice              bad "w = $CW; w['run'] = '$CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh\n$CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ count-step-if-false           bad "w = $CW; w['run'] = '$CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'; w['if'] = 'false'"
case_ count-step-env-injected       bad "w = $CW; w['run'] = 'BASH_ENV=/tmp/x $CF check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
case_ step-if-false         bad "$pick['if'] = 'false'"
case_ step-continue         bad "$pick['continue-on-error'] = 'true'"
case_ step-weakened         bad "$pick['run'] = $pick['run'].strip() + ' || true'"
case_ job-if-false          bad "d['jobs']['allowlist']['if'] = 'false'"
case_ no-pull-request       bad "d['on'].pop('pull_request')"
case_ push-not-main         bad "d['on']['push']['branches'] = ['release']"
case_ pr-paths-filter       bad "d['on']['pull_request'] = {'paths': ['README.md']}"
case_ pr-branches-filter    bad "d['on']['pull_request'] = {'branches': ['release']}"
case_ push-paths-filter     bad "d['on']['push']['paths'] = ['README.md']"
case_ push-paths-ignore     bad "d['on']['push']['paths-ignore'] = ['**']"
case_ step-shell-override   bad "$pick['shell'] = \"bash -c 'true' {0}\""
case_ job-defaults-shell    bad "d['jobs']['allowlist']['defaults'] = {'run': {'shell': \"bash -c 'true' {0}\"}}"
case_ workflow-defaults     bad "d['defaults'] = {'run': {'shell': \"bash -c 'true' {0}\"}}"
case_ bash-env-on-step      bad "$pick['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ bash-env-on-job       bad "d['jobs']['allowlist']['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ path-on-workflow      bad "d['env'] = {'PATH': '/tmp/fake:/usr/bin'}"
case_ github-env-write      bad "$steps.insert(1, {'run': 'echo BASH_ENV=/tmp/x.sh >> \"\$GITHUB_ENV\"'})"
case_ github-path-write     bad "$steps.insert(1, {'run': 'echo /tmp/fake >> \"\$GITHUB_PATH\"'})"
case_ checkout-other-ref    bad "$steps[0]['with'] = {'ref': 'main'}"
case_ cases-step-env        bad "[s.__setitem__('env', {'PINS_DRY': '1'}) for s in $steps if (s.get('run') or '').strip() in ('bash .github/agent/tests/check-action-pins-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh')]"
case_ cases-step-env-self   bad "[s.__setitem__('env', {'PINS_SELF': '/bin/true'}) for s in $steps if (s.get('run') or '').strip() in ('bash .github/agent/tests/check-action-pins-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh')]"
case_ cases-step-removed    bad "$steps[:] = [s for s in $steps if (s.get('run') or '').strip() not in ('bash .github/agent/tests/check-action-pins-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh')]"
# the matrix and label suites (REQ-CI-005, cache#705): each is its own step of the allowlist job and cannot be removed, skipped, made non-blocking or given a shell
for sfx in matrix labels; do
  sel="[s for s in $steps if 'auditor-$sfx-test.sh' in (s.get('run') or '')][0]"
  case_ "auditor-$sfx-removed"  bad "$steps[:] = [s for s in $steps if 'auditor-$sfx-test.sh' not in (s.get('run') or '')]"
  case_ "auditor-$sfx-if"       bad "$sel['if'] = 'false'"
  case_ "auditor-$sfx-continue" bad "$sel['continue-on-error'] = 'true'"
  case_ "auditor-$sfx-shell"    bad "$sel['shell'] = \"bash -c 'true' {0}\""
  case_ "auditor-$sfx-env"      bad "$sel['env'] = {'A': 'b'}"
  case_ "auditor-$sfx-timeout"  bad "$sel['timeout-minutes'] = '5'"
done

fe='[s for s in '"$steps"' if "git fetch" in (s.get("run") or "")][0]'
case_ fetch-removed             bad "$steps[:] = [s for s in $steps if 'git fetch' not in (s.get('run') or '')]"
case_ fetch-or-true             bad "$fe['run'] = $fe['run'].rstrip() + ' || true'"
case_ fetch-if-false            bad "$fe['if'] = 'false'"
case_ fetch-continue            bad "$fe['continue-on-error'] = 'true'"
case_ fetch-env-removed         bad "$fe.pop('env')"
case_ fetch-inline-expression   bad "$fe.pop('env'); $fe['run'] = 'git fetch --no-tags origin +refs/heads/\${{ github.base_ref }}:refs/remotes/origin/\${{ github.base_ref }}'"
case_ fetch-after-check         bad "$steps.append($steps.pop(1))"
case_ fetch-depth-reverted      bad "$steps[0].pop('with')"
case_ fetch-depth-shallow       bad "$steps[0]['with'] = {'fetch-depth': '1'}"
case_ allowlist-job-renamed     bad "d['jobs']['allowlist']['name'] = 'file allowlist'"
case_ allowlist-job-unnamed     bad "d['jobs']['allowlist'].pop('name')"

case_ insert-step-before-checkout bad "$steps.insert(0, {'run': 'true'})"
case_ job-env-shellopts         bad "d['jobs']['allowlist']['env'] = {'SHELLOPTS': 'noexec'}"
case_ wf-env-shellopts          bad "d['env'] = {'SHELLOPTS': 'noexec'}"
case_ step-env-shellopts        bad "$steps[3]['env'] = {'SHELLOPTS': 'noexec'}"
case_ job-env-head-ref          bad "d['jobs']['allowlist']['env'] = {'GITHUB_HEAD_REF': 'auditor/x'}"
case_ wf-env-head-ref           bad "d['env'] = {'GITHUB_HEAD_REF': 'auditor/x'}"
case_ step-env-head-ref         bad "$steps[1]['env']['GITHUB_HEAD_REF'] = 'auditor/x'"
case_ job-env-repository        bad "d['jobs']['allowlist']['env'] = {'GITHUB_REPOSITORY': 'x/y'}"
case_ wf-env-repository         bad "d['env'] = {'GITHUB_REPOSITORY': 'x/y'}"
case_ step-env-repository       bad "$steps[1]['env']['GITHUB_REPOSITORY'] = 'x/y'"
case_ job-env-index-file        bad "d['jobs']['allowlist']['env'] = {'GIT_INDEX_FILE': '/tmp/i'}"
case_ wf-env-index-file         bad "d['env'] = {'GIT_INDEX_FILE': '/tmp/i'}"
case_ step-env-index-file       bad "$steps[1]['env']['GIT_INDEX_FILE'] = '/tmp/i'"
case_ fetch-env-git-dir         bad "$steps[1]['env']['GIT_DIR'] = '/tmp/g'"
case_ job-container             bad "d['jobs']['allowlist']['container'] = 'debian:12'"
case_ job-services              bad "d['jobs']['allowlist']['services'] = {'x': {'image': 'y'}}"
case_ job-strategy              bad "d['jobs']['allowlist']['strategy'] = {'matrix': {'a': ['1']}}"
case_ job-defaults-run          bad "d['jobs']['allowlist']['defaults'] = {'run': {'working-directory': 'bin'}}"
case_ ps4-ifs-prompt            bad "d['jobs']['allowlist']['env'] = {'IFS': 'x'}"
case_ ld-preload-step           bad "$steps[4]['env'] = {'LD_PRELOAD': '/tmp/x.so'}"

# the jobs that run the suites (REQ-CI-001): the list job reads the committed suite list, the suites job runs one leg per suite of it, the gate keeps the name allowlist-chain; each mutation is caught
S='d["jobs"]["suites"]'; SL='d["jobs"]["suite-list"]'; GT='d["jobs"]["allowlist-chain"]'; SS="$S['steps'][-1]"
case_ suites-removed            bad "d['jobs'].pop('suites')"
case_ suites-if                 bad "$S['if'] = 'false'"
case_ suites-continue           bad "$S['continue-on-error'] = 'true'"
case_ suites-matrix-literal     bad "$S['strategy']['matrix'] = {'include': [{'suite': 'x-test.sh'}]}"
case_ suites-matrix-other-job   bad "$S['strategy']['matrix']['include'] = '\${{ fromJSON(needs.lint.outputs.suites) }}'"
case_ suites-needs-other        bad "$S['needs'] = 'lint'"
case_ suites-runs-on            bad "$S['runs-on'] = 'self-hosted'"
case_ suites-job-env            bad "$S['env'] = {'BASH_ENV': '/tmp/x'}"
case_ suites-permissions        bad "$S['permissions'] = {'id-token': 'write'}"
case_ suites-step-removed       bad "$S['steps'].pop()"
case_ suites-step-added         bad "$S['steps'].append({'name': 'x', 'run': 'true'})"
case_ suites-step-env-bash-env  bad "$S['steps'][2]['env'] = {'BASH_ENV': '/tmp/x'}"
case_ suites-suite-or-true      bad "$SS['run'] += ' || true'"
case_ suites-suite-continue     bad "$SS['continue-on-error'] = 'true'"
case_ suites-suite-if           bad "$SS['if'] = 'false'"
case_ suites-suite-shell        bad "$SS['shell'] = \"bash -c 'true' {0}\""
case_ suites-suite-shellopts    bad "$SS['env']['SHELLOPTS'] = 'noexec'"
case_ suites-suite-netcut-off   bad "$SS['env']['CHAIN_TEST_REQUIRE_NETCUT'] = '0'"
case_ suites-suite-no-floor     bad "$SS['run'] = 'bash \"\$SUITE\" < /dev/null'"
case_ suite-list-removed        bad "d['jobs'].pop('suite-list')"
case_ suite-list-if             bad "$SL['if'] = 'false'"
case_ suite-list-continue       bad "$SL['steps'][-1]['continue-on-error'] = 'true'"
case_ suite-list-other-file     bad "$SL['steps'][-1]['run'] = $SL['steps'][-1]['run'].replace('.github/policy/ci-suites.json', '/tmp/ci-suites.json')"
case_ gate-renamed              bad "$GT['name'] = 'allowlist-chain-gate'"
case_ gate-needs-other          bad "$GT['needs'] = ['lint']"
case_ gate-needs-removed        bad "$GT.pop('needs')"
case_ gate-no-always            bad "$GT.pop('if')"
case_ gate-if-false             bad "$GT['if'] = 'false'"
case_ gate-success-only         bad "$GT['if'] = '\${{ success() }}'"
case_ gate-checkout             bad "$GT['steps'].insert(0, $S['steps'][0])"
case_ gate-or-true              bad "$GT['steps'][0]['run'] += ' || true'"
case_ gate-skipped-passes       bad "$GT['steps'][0]['run'] = '[ \"\$RESULT\" != failure ] || exit 1'"
case_ gate-env-literal          bad "$GT['steps'][0]['env']['RESULT'] = 'success'"
case_ gate-env-other-job        bad "$GT['steps'][0]['env']['RESULT'] = '\${{ needs.suite-list.result }}'"
case_ gate-continue             bad "$GT['steps'][0]['continue-on-error'] = 'true'"
case_ gate-job-env              bad "$GT['env'] = {'X': '1'}"
case_ gate-runs-on              bad "$GT['runs-on'] = 'self-hosted'"
case_ gate-permissions          bad "$GT['permissions'] = {'checks': 'write'}"
case_ gate-impersonated         bad "d['jobs']['replacement'] = {'name': 'allowlist-chain', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
# the floors-only-rise step (an `if` and an `env` on purpose) is judged as a whole step
FS="[s for s in $steps if 'floors-vs-base' in (s.get('run') or '')][0]"
case_ floors-step-removed       bad "$steps[:] = [s for s in $steps if 'floors-vs-base' not in (s.get('run') or '')]"
case_ floors-step-if            bad "$FS['if'] = 'false'"
case_ floors-step-or-true       bad "$FS['run'] = $FS['run'] + ' || true'"
case_ floors-step-body-in-run   bad "$FS['run'] = 'bash bin/suite-guard.sh floors-vs-base --allow-lowered \"\${{ github.event.pull_request.body }}\" x y'"
case_ floors-step-body-env-gone bad "$FS['env'].pop('PR_BODY')"
case_ floors-step-body-title    bad "$FS['env']['PR_BODY'] = '\${{ github.event.pull_request.title }}'"
case_ floors-step-continue      bad "$FS['continue-on-error'] = 'true'"
# the committed suite list: every suite the floors file names runs exactly once in ci.yml and the list, and the list is a plain list of test scripts
listcase() {  # listcase <name> <expect ok|bad> <python edit of the parsed list d>
  local f="$work/suites-$1.json"; cp "$here/.github/policy/ci-suites.json" "$f"
  python3 - "$f" "$3" <<'PY'
import sys, json
p, edit = sys.argv[1], sys.argv[2]
d = json.load(open(p))
exec(edit)
json.dump(d, open(p, "w"))
PY
  if out=$(PIN_WIRING_SUITES_FILE="$f" judge "$here/.github/workflows/ci.yml"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS list:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL list:$1 → $got, want $2 ($out)"; fi
}
listcase real                   ok  ""
listcase new-unfloored-suite    ok  "d.append({'suite': 'new-thing-test.sh'})"
listcase floored-suite-dropped  bad "d[:] = [e for e in d if e['suite'] != 'chain-verify-test.sh']"
listcase floored-suite-twice    bad "d.append({'suite': 'chain-verify-test.sh'})"
listcase unfloored-twice        bad "d.append(dict(d[0]))"
listcase suite-with-a-dir        bad "d.append({'suite': 'tmp/evil-test.sh'})"
listcase suite-not-a-test        bad "d.append({'suite': 'evil.sh'})"
listcase suite-traversal         bad "d.append({'suite': '../evil-test.sh'})"
listcase extra-key              bad "d[0]['path'] = 'bin/x-test.sh'"
listcase grype-not-true         bad "d[0]['grype'] = 'yes'"
listcase not-a-list             bad "d = {'suite': 'x-test.sh'}"
listcase empty                  bad "d = []"
case_ suite-counted-and-listed  bad "$steps.append({'name': 'x', 'run': 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json chain-verify-test.sh bin/chain-verify-test.sh'})"
case_ counting-step-dropped     bad "d['jobs']['test']['steps'][:] = [s for s in d['jobs']['test']['steps'] if 'check-no-outbound-test.sh' not in (s.get('run') or '')]"

# judge mode (the trusted gate, .github/workflows/agent-review-gate.yml): PIN_WIRING_JUDGE_GIT=<commit> judges THAT
# commit's .github/workflows/ci.yml, read as a git object from the current repo (nothing checked out or run), and
# does nothing else; exit 1 and the reasons when it fails
gitcase() {  # gitcase <name> <expect ok|bad> <python edit or empty>
  local r="$work/git-$1"; rm -rf "$r"; mkdir -p "$r/.github/workflows"
  cp "$here/.github/workflows/ci.yml" "$r/.github/workflows/ci.yml"
  mkdir -p "$r/.github/policy"; cp "$here/.github/policy/required-checks.json" "$r/.github/policy/required-checks.json"
  cp "$here"/.github/workflows/*.y*ml "$r/.github/workflows/" 2>/dev/null || true; cp "$here/.github/workflows/ci.yml" "$r/.github/workflows/ci.yml"
  mkdir -p "$r/tools/govulncheck"; cp "$here/tools/govulncheck/go.mod" "$r/tools/govulncheck/go.mod"      # the pin the govulncheck-gate judge reads at the judged commit
  mkdir -p "$r/test-evidence"; cp "$here/test-evidence/suite-floors.json" "$r/test-evidence/suite-floors.json"     # REQ-CI-005: the judge reads the floors file of the judged commit
  cp "$here/.github/policy/ci-suites.json" "$r/.github/policy/ci-suites.json"                                       # and the suite list of the judged commit
  if [ -n "${GIT_FLOORS_EDIT:-}" ]; then python3 - "$r/test-evidence/suite-floors.json" "$GIT_FLOORS_EDIT" <<'PY'
import sys, json
p, edit = sys.argv[1], sys.argv[2]
d = json.load(open(p)); exec(edit); json.dump(d, open(p, "w"))
PY
  fi
  if [ -n "$3" ]; then python3 - "$r/.github/workflows/ci.yml" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  ( cd "$r" && git init -q . && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm c )
  if out=$(cd "$r" && PIN_WIRING_JUDGE_GIT="$(cd "$r" && git rev-parse HEAD)" bash "$here/.github/agent/tests/pin-wiring-test.sh" 2>&1); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS git:$1 → $got"
  else failn=$((failn+1)); echo "FAIL git:$1 → $got, want $2 ($out)"; fi
}
gitcase the-real-ci-at-a-commit   ok  ""
WRAP="w = [s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip() in ('bash .github/agent/tests/check-action-pins-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh')][0]; w['run'] = 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh'"
gitcase counting-step-at-a-commit ok  "$WRAP"
GIT_FLOORS_EDIT="d.pop('check-action-pins-test.sh')" gitcase counting-step-unfloored-at-that-commit bad "$WRAP"     # the floors file of the judged commit decides, not the checkout's
# the policy at the commit is read too: a missing split entry is refused (and so is a missing file, above)

# the govulncheck-gate judge runs in judge mode too, over the head's own ci.yml (the trusted gate path)
GVJ="[j for j in [d['jobs']['govulncheck']]][0]['steps']"
gitcase govulncheck-gate-old-step-at-a-commit  bad "$GVJ[-1]['run'] = 'govulncheck ./...'"
gitcase govulncheck-gate-no-installer-at-a-commit  bad "$GVJ[:] = [s for s in $GVJ if s.get('run') != 'bash bin/install-scanner.sh go']"
gitcase govulncheck-gate-extra-step-at-a-commit  bad "$GVJ.insert(3, {'run': 'cp /bin/true /usr/local/bin/fscache-go/bin/govulncheck'})"
gitcase fetch-depth-at-a-commit   bad "$steps[0].pop('with')"

case_ job-needs-skipped          bad "d['jobs']['skip_guard'] = {'runs-on': 'ubuntu-latest', 'if': 'false', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist']['needs'] = 'skip_guard'"
# a bump of an action that the judged jobs use (cache#790: setup-python 7.0.0 to 7.1.0) moves the digest in every judged
# step; the digest value is judged by check-action-pins --verify-tags, pin-age and the daily audit, not by this list.
# The action name and the full 40-hex shape of the ref stay exact.
BUMP="for j in ('allowlist', 'suites'): "
BUMP+="[s.__setitem__('uses', '%s') for s in d['jobs'][j]['steps'] "
BUMP+="if s.get('uses', '').startswith('actions/setup-python@')]"
case_ uses-digest-bumped       ok  "${BUMP//%s/actions/setup-python@abababababababababababababababababababab}"
case_ uses-tag-ref             bad "${BUMP//%s/actions/setup-python@v7}"
case_ uses-short-digest        bad "${BUMP//%s/actions/setup-python@abababababababababababababababababababa}"
case_ uses-upper-digest        bad "${BUMP//%s/actions/setup-python@ABABABABABABABABABABABABABABABABABABABAB}"
case_ uses-other-action-name   bad "${BUMP//%s/evil/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97}"
case_ uses-literal-marker       bad "${BUMP//%s/actions/setup-python@<commit>}"
RUNX="d['jobs']['suites']['steps'][-1]['run'] += ' || true'"
case_msg run-changed-names-step "$RUNX" "the suites step 6 ("
case_msg run-changed-names-key  "$RUNX" "differs in: run"
case_ impersonate-by-name     bad "d['jobs']['replacement'] = {'name': 'allowlist-chain', 'runs-on': 'ubuntu-latest', 'needs': 'allowlist-chain', 'if': '\${{ always() }}', 'steps': [{'run': 'true'}]}"
case_ impersonate-allowlist   bad "d['jobs']['replacement'] = {'name': 'allowlist', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
case_ job-name-expression     bad "d['jobs']['lint']['name'] = '\${{ matrix.x }}'"
case_ job-name-expr-spaced    ok  "d['jobs']['lint']['name'] = 'lint (\${{ matrix.x }})'"
case_ job-matrix-other        ok  "d['jobs']['lint']['strategy'] = {'matrix': {'x': ['1']}}"
case_ checks-write-job        bad "d['jobs']['lint']['permissions'] = {'checks': 'write'}"
case_ checks-write-all        bad "d['permissions'] = 'write-all'"
case_ checks-write-top        bad "d['permissions'] = {'contents': 'read', 'checks': 'write'}"
case_ name-expr-quoted        bad "d['jobs']['lint']['name'] = \"\${{ 'allowlist-chain' || '}} ' }}\""
case_ name-expr-multiline     bad "d['jobs']['lint']['name'] = \"\${{\\n  'allowlist-chain'\\n}}\""
case_ name-expr-function      bad "d['jobs']['lint']['name'] = \"x \${{ format('{0}', 'a') }}\""
case_ job-needs-list             bad "d['jobs']['allowlist']['needs'] = ['lint']"
case_ job-timeout                bad "d['jobs']['allowlist']['timeout-minutes'] = '1'"
case_ job-concurrency            bad "d['jobs']['allowlist']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
case_ job-concurrency-test       bad "d['jobs']['test']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
# the live test's one-at-a-time group (REQ-SCAN-012, ratified): live-test alone may carry exactly this block (take 30, advisor)
case_ other-job-live-test-block        bad "d['jobs']['test']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false'}"
case_ allowlist-live-test-block        bad "d['jobs']['allowlist']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false'}"
case_ job-concurrency-lint-same  bad "d['jobs']['lint']['concurrency'] = d['concurrency'] if 'concurrency' in d else {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': 'true'}"
case_ on-workflow-call           bad "d['on']['workflow_call'] = {}"
case_ on-workflow-dispatch       bad "d['on']['workflow_dispatch'] = {}"
case_ on-merge-group             bad "d['on']['merge_group'] = {'types': ['checks_requested']}"
case_ on-schedule                bad "d['on']['schedule'] = [{'cron': '0 0 * * *'}]"
case_ wf-concurrency             bad "d['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
case_ wf-concurrency-reviewed    ok  "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ wf-concurrency-cancel-all  bad "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': 'true'}"
case_ wf-concurrency-shared-ref  bad "d['concurrency'] = {'group': \"\${{ github.workflow }}-\${{ github.ref }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ wf-concurrency-rerun-shares bad "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ wf-concurrency-workflow-name bad "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('{0}-pr-{1}', github.workflow, github.event.pull_request.number) || format('{0}-{1}-{2}', github.workflow, github.run_id, github.run_attempt) }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ job-permissions            bad "d['jobs']['allowlist']['permissions'] = {'contents': 'write'}"
case_ job-regains-a-block        bad \
  "d['jobs']['allowlist']['permissions'] = {'contents': 'read', 'pull-requests': 'read'}"
case_ wf-permissions-gains-write bad "d['permissions'] = {'contents': 'read', 'pull-requests': 'write'}"
case_ wf-permissions-widened     bad "d['permissions'] = {'contents': 'write'}"
case_ wf-permissions-removed     bad "d.pop('permissions')"
case_ runs-on-self-hosted        bad "d['jobs']['allowlist']['runs-on'] = 'self-hosted'"
case_ runs-on-list               bad "d['jobs']['allowlist']['runs-on'] = ['ubuntu-latest', 'x']"
case_ job-strategy-matrix        bad "d['jobs']['allowlist']['strategy'] = {'fail-fast': 'true'}"
case_ expression-in-fetch        bad "$fe['run'] = '# \${{ github.sha }}\\n' + $fe['run']"
case_ anchor-alias-in-ci         bad "sh = {'k': 'v'}; d['jobs']['test']['x-shared'] = sh; d['jobs']['lint']['x-shared'] = sh"
case_ anchor-bomb                bad "a = ['x']; b = [a, a, a, a, a, a, a, a, a]; c = [b, b, b, b, b, b, b, b, b]; e = [c, c, c, c, c, c, c, c, c]; d['jobs']['test']['bomb'] = [e, e, e, e, e, e, e, e, e]"

for u in 00a0 3000 2028 2029; do
  case_ "unicode-space-in-fetch-$u" bad "$fe['run'] = '\\u$u# x\\n' + $fe['run']"
done
case_ ctrl-in-fetch          bad "$fe['run'] = $fe['run'] + '\\x01'"

# duplicate keys can only be written as text, so these edit the YAML text of a copy
textcase() {  # textcase <name> <expect> <python expression editing the text variable t>
  local f="$work/t-$1.yml"; cp "$here/.github/workflows/ci.yml" "$f"
  python3 - "$f" "$3" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
t = open(p).read()
exec(edit)
open(p, "w").write(t)
PY
  if out=$(judge "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
textcase duplicate-run-in-pins-step   bad "t = t.replace('        run: python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh', '        run: python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json check-action-pins-test.sh .github/agent/tests/check-action-pins-test.sh\\n        run: true', 1)"
textcase duplicate-name-allowlist-job  bad "t = t.replace('  allowlist:\\n    name: allowlist', '  allowlist:\\n    name: allowlist\\n    name: allowlist', 1)"
textcase duplicate-top-level-key       bad "t = t.replace('\\njobs:\\n', '\\npermissions:\\n  contents: read\\njobs:\\n', 1)"
textcase the-text-edit-itself-is-neutral ok "t = t"

# the trusted gate's judge and sweep jobs are time-bounded (a hung judge must fail, not hang the required check)
gate_timeouts() {
  python3 - "$1" <<'PY'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
bad = [j for j in ("judge", "sweep") if not (d["jobs"][j].get("timeout-minutes", "").isdigit() and 0 < int(d["jobs"][j]["timeout-minutes"]) <= 30)]
print(",".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
}
if out=$(gate_timeouts "$here/.github/workflows/agent-review-gate.yml"); then pass=$((pass+1)); echo "PASS gate judge+sweep have timeout-minutes"
else failn=$((failn+1)); echo "FAIL gate jobs without timeout-minutes: $out"; fi
cp "$here/.github/workflows/agent-review-gate.yml" "$work/gate-mut.yml"; sed -i.bak '/^    timeout-minutes:/d' "$work/gate-mut.yml"
if gate_timeouts "$work/gate-mut.yml" >/dev/null; then failn=$((failn+1)); echo "FAIL gate without timeouts accepted"; else pass=$((pass+1)); echo "PASS gate without timeouts → bad"; fi

# a job in ANOTHER workflow file that takes a protected check name, or can render as one, or a workflow that cannot be read
for mut in "name" "id" "expr" "garbage" "okexpr" "checks" "checks-top" "quoted" "noperms"; do
  rm -rf "$work/wf-$mut"; mkdir -p "$work/wf-$mut"; cp "$here"/.github/workflows/*.y*ml "$work/wf-$mut/"
  case "$mut" in
    name) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    name: allowlist-chain\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    id) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  allowlist-chain:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    expr) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    name: ${{ matrix.n }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    garbage) printf 'jobs: [\n' > "$work/wf-$mut/zz.yml" ;;
    checks) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    runs-on: ubuntu-latest\n    permissions:\n      checks: write\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    checks-top) printf 'name: x\non: push\npermissions: write-all\njobs:\n  zz:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    noperms) printf 'name: x\non: push\njobs:\n  zz:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    quoted) cat > "$work/wf-$mut/zz.yml" <<'WF'
name: x
on: push
permissions:
  contents: read
jobs:
  zz:
    name: "${{ 'allowlist-chain' || '}} ' }}"
    runs-on: ubuntu-latest
    steps:
      - run: "true"
WF
      ;;
    okexpr) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    name: scan (${{ matrix.n }})\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
  esac
  want=bad; [ "$mut" = okexpr ] && want=ok
  if out=$(PIN_WIRING_WORKFLOWS_DIR="$work/wf-$mut" judge "$here/.github/workflows/ci.yml"); then got=ok; else got=bad; fi
  if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "PASS other-workflow-$mut → $got"; else failn=$((failn+1)); echo "FAIL other-workflow-$mut → $got, want $want ($out)"; fi
done

# the required-check policy: each split job must stay listed with integration 15368 and scope push (release admission reads them)
for mut in "drop" "scope" "integration" "null" "empty" "garbage" "dup" "notlist"; do
  python3 - "$here/.github/policy/required-checks.json" "$work/pol-$mut.json" "$mut" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); rc = d["required_checks"]
e = [c for c in rc if c["context"] == "allowlist-chain"][0]
if sys.argv[3] == "drop": rc.remove(e)
elif sys.argv[3] == "scope": e["scope"] = "pull_request"
elif sys.argv[3] == "integration": e["integration_id"] = 1
elif sys.argv[3] == "null": d["required_checks"] = None
elif sys.argv[3] == "empty": d = {}
elif sys.argv[3] == "dup": rc.append(dict(e, scope="pull_request"))
elif sys.argv[3] == "notlist": d["required_checks"] = {"a": 1}
if sys.argv[3] == "garbage": open(sys.argv[2], "w").write("{not json")
else: json.dump(d, open(sys.argv[2], "w"))
PY
  if out=$(PIN_WIRING_POLICY_FILE="$work/pol-$mut.json" judge "$here/.github/workflows/ci.yml"); then failn=$((failn+1)); echo "FAIL policy-$mut accepted"; else pass=$((pass+1)); echo "PASS policy-$mut → bad ($out)"; fi
done

gvgate_ci="${PIN_WIRING_WORKFLOWS_DIR:-$here/.github/workflows}/ci.yml"
if gvgate_judge "$gvgate_ci" "$here/tools/govulncheck/go.mod"; then pass=$((pass+1)); echo "PASS govulncheck-gate real job"; else failn=$((failn+1)); echo "FAIL govulncheck-gate real job is not the Check-equivalent form"; fi
gvgate_mut() { # gvgate_mut LABEL OLD NEW : the ci.yml with one change inside the govulncheck job must be refused
  python3 - "$gvgate_ci" "$work/gvgate-ci.yml" "$2" "$3" <<'PY'
import sys
t = open(sys.argv[1]).read(); a, b = sys.argv[3], sys.argv[4]
i = t.index("  govulncheck:\n    name: govulncheck")
head, job = t[:i], t[i:]
j = job.index("\n\n")
body, rest = job[:j], job[j:]
assert a in body, a
open(sys.argv[2], "w").write(head + body.replace(a, b, 1) + rest)
PY
  if gvgate_judge "$work/gvgate-ci.yml" "$here/tools/govulncheck/go.mod"; then failn=$((failn+1)); echo "FAIL govulncheck-gate $1 accepted"; else pass=$((pass+1)); echo "PASS govulncheck-gate $1 → refused"; fi
}
gvgate_mut "old-bare-step" 'python3 -I -B bin/check-govulncheck.py --scanners .github/policy/scanners.json --out "$RUNNER_TEMP/gv"' 'govulncheck ./...'
gvgate_mut "no-installer" 'bash bin/install-scanner.sh go' 'true'
gvgate_mut "script-path" 'bin/check-govulncheck.py' 'bin/check-other.py'
gvgate_mut "scanner-list" '.github/policy/scanners.json' '/tmp/scanners.json'
gvgate_mut "no-isolation-flags" 'python3 -I -B bin' 'python3 bin'
gvgate_mut "id-token" 'contents: read' 'contents: read
      id-token: write'
gvgate_mut "job-renamed" 'name: govulncheck' 'name: govulncheck-gate'
gvgate_mut "install-and-copy" 'govulncheck@v1.7.0' 'govulncheck@v1.7.0 && cp /bin/true ~/go/bin/govulncheck'
gvgate_mut "planted-binary-step" '      - name: govulncheck (the same judgment as Check)' '      - name: plant
        run: cp /bin/true /usr/local/bin/fscache-go/bin/govulncheck
      - name: govulncheck (the same judgment as Check)'

echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
