#!/usr/bin/env bash
# proves: REQ-CI-001-AC1, REQ-CI-001-AC2, REQ-CI-001-AC3, REQ-CI-001-AC4 — the gate allowlist-chain is accepted only exactly (the gate cases)
# proves: REQ-CI-005-AC2 — a suite counted by its own step is accepted only as exactly `bash PATH`, and the suites matrix only in its judged structure (the count-step and suites cases)
# proves: REQ-REL-004-AC1 — the pull-request gate's govulncheck job judges the way Check does: it is accepted only in exactly its form (the govulncheck-gate cases)
# proves: REQ-REL-014-AC1 — the job allowlist runs on push to main only, accepted only exactly (the push-condition cases)
# proves: REQ-CI-007-AC4 — the jobs suite-list, suites and allowlist-chain of full-suite.yml run on a schedule and on workflow_dispatch only, the gate only as `always()` (plain or in an expression), accepted only exactly (the full-suite event cases)
# The workflow ci.yml runs a suite by a counting step (`bash PATH`); full-suite.yml runs every other suite by its own leg of the suites matrix, which the job suite-list computes
# from the tracked files, and its job allowlist-chain is the one gate over the suites job (a release-only check, bound to full-suite.yml by admission). The judge below takes the
# pinned actions, permissions and env of every job of ci.yml, the step lists' shape of the job allowlist, the required-check policy (allowlist) and the release-only policy
# (allowlist-chain) and the check names of every other workflow. The judge of full-suite.yml takes the same hazards of every job of that file and the step lists' shape of the jobs
# suite-list, suites and allowlist-chain (not the text of the list and leg steps: ci-suites-matrix-test.sh judges those by running them). The real ci.yml and the real
# full-suite.yml must pass; each mutated copy must be caught.
# Known limit (by design): later steps of the CI allowlist job can edit this test on disk;
# the trusted gate (.github/workflows/agent-review-gate.yml) re-runs main's copy of it over the PR head.
set -euo pipefail
here=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

judge() { PIN_WIRING_WORKFLOWS_DIR="${PIN_WIRING_WORKFLOWS_DIR:-$here/.github/workflows}" PIN_WIRING_POLICY_FILE="${PIN_WIRING_POLICY_FILE:-$here/.github/policy/required-checks.json}" PIN_WIRING_RELEASE_ONLY_FILE="${PIN_WIRING_RELEASE_ONLY_FILE:-$here/.github/policy/release-only-checks.json}" python3 - "$1" <<'PY'
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
bad = []
# REQ-CI-005: a suite counted by its own step is run by exactly `bash PATH` (PATH the suite's repo path). A counting step has no key but name and run (a skipped or
# failure-tolerant step would drop the suite from the run), shares its run with no other line, and a suite is counted by one step of the workflow at most.
# A line that names a suite path in any other form is refused.
import json, re
_COUNT_ = re.compile(r"bash ((?:bin|\.github/agent/tests)/[^ /]+-test\.sh)")
_SUITE_PATH_ = re.compile(r"(?:bin|\.github/agent/tests)/[^ /]+-test\.sh")
_counted_ = []
if isinstance(d, dict):
    for _jid_, _j_ in (d.get("jobs") or {}).items():
        for _st_ in (_j_.get("steps") or []) if isinstance(_j_, dict) else []:
            if isinstance(_st_, dict) and isinstance(_st_.get("run"), str):
                _old_ = _st_["run"].split("\n")
                for _o_ in _old_:
                    if _o_.lstrip().startswith("#"):
                        continue
                    _m_ = _COUNT_.fullmatch(_o_)
                    if _m_:
                        _counted_.append(_m_.group(1))
                        for _k_ in sorted(set(_st_) - {"name", "run"}):
                            bad.append(f"the counting step `{_o_}` has `{_k_}` (a counting step has no key but name and run)")
                        if len(_old_) != 1:
                            bad.append(f"the counting step `{_o_}` shares its run text with other lines")
                    elif _SUITE_PATH_.search(_o_):
                        bad.append(f"the job {_jid_} has a line that runs a suite in a form that is not exactly a counting step: `{_o_.strip()}`")
for _c_ in sorted({c for c in _counted_ if _counted_.count(c) > 1}):
    bad.append(f"the suite {_c_} is counted by more than one step (REQ-CI-005-AC1: a suite is run once)")
for k in sorted(set(d) - {"name", "on", "permissions", "jobs", "concurrency"}):
    bad.append(f"the workflow sets `{k}`")
# the one reviewed concurrency block (advisor, Oct 22; cache#583): a pull request's FIRST run attempt of a head shares a group with the pull request's other first attempts, so a newer
# push cancels its older run; every other run (a re-run of any head, a push to main) gets a group of its own per run and attempt, so ci.yml itself never cancels it nor
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
# the only triggers ci.yml may have: push (main), pull_request and merge_group. workflow_call and workflow_dispatch are refused: a called or dispatched run
# would carry another context into the reviewed concurrency group.
if isinstance(on, dict) and sorted(set(on) - {"push", "pull_request", "merge_group"}):
    bad.append("ci.yml has triggers beyond push, pull_request and merge_group: " + ", ".join(sorted(set(on) - {"push", "pull_request", "merge_group"})))
# no job of ci.yml may carry a concurrency setting: a job group competes with its parent workflow's group and can cancel the whole run
for _jid, _j in (d.get("jobs") or {}).items():
    if isinstance(_j, dict) and "concurrency" in _j:
        bad.append(f"the job {_jid} has `concurrency`")
    if isinstance(_j, dict) and "uses" in _j:
        bad.append(f"the job {_jid} calls a reusable workflow (`uses` on a job)")
    if isinstance(_j, dict) and ("defaults" in _j or "continue-on-error" in _j):
        bad.append(f"the job {_jid} has `defaults` or `continue-on-error`")
    for _st_ in (_j.get("steps") or []) if isinstance(_j, dict) else []:
        if isinstance(_st_, dict) and "continue-on-error" in _st_:
            bad.append(f"the job {_jid} has a step with `continue-on-error` ({_st_.get('name') or _st_.get('uses') or _st_.get('run')})")
if "defaults" in d:
    bad.append("the workflow sets `defaults` (a shell override could skip every run)")
if "env" in d:
    bad.append("the workflow sets `env`")
job = d.get("jobs", {}).get("allowlist", {})
steps_ = job.get("steps", [])
# nothing may redirect how the steps of any job execute (step 8 r3, residual 2): a shell startup file, an environment or PATH written for later steps, interpreter search paths
hooks = ("BASH_ENV", "GITHUB_ENV", "GITHUB_PATH")
risky = {"BASH_ENV", "ENV", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "SHELLOPTS", "BASHOPTS", "PS4", "IFS",
         "PROMPT_COMMAND", "CDPATH", "GLOBIGNORE", "TMPDIR", "HOME", "XDG_CONFIG_HOME"}
def is_risky(k):
    return k in risky or re.match(r"(GIT_|GITHUB_|LD_|DYLD_|PYTHON|BASH_|RUNNER_)", k) is not None
for _jid, _j in (d.get("jobs") or {}).items():
    if not isinstance(_j, dict):
        continue
    for h in hooks:
        if h in json.dumps(_j):
            bad.append(f"the job {_jid} mentions {h}")
    for where, env in [(f"the job {_jid}", _j.get("env"))] + [(f"step {i} of {_jid}", st.get("env")) for i, st in enumerate(_j.get("steps") or []) if isinstance(st, dict)]:
        if isinstance(env, dict):
            for k in sorted(k for k in env if is_risky(k)):
                bad.append(f"{where} sets env {k}")
# every action of ci.yml is one of the four pinned ones, by a full lower-case commit digest (the digest VALUE is judged by check-action-pins --verify-tags and the daily
# audit: a Dependabot bump moves it); a tag, a short or upper-case digest, a local action or another owner's action is refused in every job
_PINNED_ACTIONS = ("actions/checkout", "actions/setup-go", "actions/setup-python", "actions/upload-artifact")
for _jid, _j in (d.get("jobs") or {}).items():
    for _i, _st_ in enumerate((_j.get("steps") or []) if isinstance(_j, dict) else []):
        _u = _st_.get("uses") if isinstance(_st_, dict) else None
        if _u is not None and not (isinstance(_u, str) and re.fullmatch(r"(%s)@[0-9a-f]{40}" % "|".join(map(re.escape, _PINNED_ACTIONS)), _u)):
            bad.append(f"the {_jid} step {_i + 1} ({_st_.get('name') or _u}) uses an action that is not a pinned one of ci.yml")
# the allowlist job: exactly name / runs-on / steps and the one `if` of a push-only check (REQ-REL-014-AC1): no `needs` (a skipped prerequisite skips the whole job),
# `timeout-minutes`, `permissions`, `strategy`, `concurrency`, `container`, `services`, `env`, `defaults`, ...
PUSH_IF = "github.event_name == 'push'"
for k in sorted(set(job) - {"name", "runs-on", "steps", "if"}):
    bad.append(f"the allowlist job has `{k}`")
if job.get("if") != PUSH_IF:
    bad.append(f"the allowlist job's `if` is not exactly `{PUSH_IF}` (it runs on push to main only)")
if job.get("runs-on") != "ubuntu-latest":
    bad.append("the allowlist job does not run on exactly `ubuntu-latest` (GitHub-hosted)")
if job.get("name") != "allowlist":
    bad.append("the allowlist job is not named `allowlist` (the required-check context)")
for st in steps_:
    if str(st.get("uses", "")).startswith("actions/checkout@"):
        w = st.get("with") or {}
        for k in ("ref", "repository", "path"):
            if k in w:
                bad.append(f"the checkout selects another tree ({k})")
FETCH_RUN = """if [ -n "${BASE}" ]; then
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
JUDGED_JOBS = ("allowlist",)
for _jid in JUDGED_JOBS:
    for st in (d.get("jobs", {}).get(_jid) or {}).get("steps") or []:
        if not isinstance(st, dict):
            continue
        # the raw text, comment lines included, of the protected steps: the base-ref fetch and every step of the other judged jobs (the other steps of the allowlist job are
        # compared character by character with the exact list)
        if (_jid != "allowlist" or norm(st.get("run")) == FETCH_RUN) and odd_chars(st.get("run")):
            bad.append(f"a run text of the {_jid} job has non-ASCII or control characters {odd_chars(st.get('run'))}")
        if "${{" in (st.get("run") or ""):   # raw text, comment lines included: an expression is rendered before bash sees it
            bad.append(f"a run text of the {_jid} job contains a `${{{{` expression")
# the whole-job judgements: the base-ref fetch step is exactly this text with exactly this env, right after the full-depth checkout, and nothing redirects it
fetch_idx = [i for i, st in enumerate(steps_) if norm(st.get("run")) == FETCH_RUN]
git_idx = [i for i, st in enumerate(steps_) if "git fetch" in (st.get("run") or "")]
co = [i for i, st in enumerate(steps_) if str(st.get("uses", "")).startswith("actions/checkout@")]
if not co or co[0] != 0:
    bad.append("the allowlist job does not start with the checkout")
elif steps_[0].get("with") != {"fetch-depth": "0"} or set(steps_[0]) - {"uses", "with"}:
    bad.append("the allowlist checkout is not exactly `fetch-depth: 0` and nothing else")
if len(fetch_idx) != 1 or git_idx != fetch_idx:
    bad.append("the allowlist job does not have exactly one fetch step with the exact command")
elif fetch_idx != [1]:
    bad.append("the allowlist job's first two steps are not exactly: checkout, base-ref fetch (nothing before or between)")
else:
    if set(steps_[1]) != {"name", "env", "run"} or steps_[1].get("env") != {"BASE": "${{ github.base_ref }}"}:
        bad.append("the allowlist fetch step is not exactly name, env {BASE: ${{ github.base_ref }}} and run")
# the exact step lists (name, uses, with, env, if and run text with its comment lines dropped, in order) of the jobs that gate the required check: a suite cannot be deleted,
# edited, wrapped (|| true), reordered or given an environment (BASH_ENV, SHELLOPTS ...) without this judge, which a PR cannot change for itself (the gate runs
# main's copy), being changed first. Adding a step to one of these jobs means adding it here. The run text of the suite-list `list` step and of the suites leg is not judged here (ci-suites-matrix-test.sh runs it).
def _by_shape(st):
    """A step with `uses: name@<full 40-hex commit>` stands for every digest of
    that action: the digest VALUE is judged by check-action-pins --verify-tags and the daily audit (a Dependabot bump moves it), not by these lists. The
    action name and the exact shape of the ref (40 lower-case hex) stay compared; the stand-in is a tuple, which no YAML
    scalar can equal."""
    u = st.get("uses")
    if isinstance(u, str) and u.count("@") == 1:
        name, _, ref = u.partition("@")
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            st = dict(st, uses=(name, "@40-hex"))
    if "run" in st:
        st = dict(st, run=norm(st["run"]))
    if st.get("id") == "list" or "SUITE" in (st.get("env") or {}):   # the list step and the leg: run text (and the leg's name) are judged by ci-suites-matrix-test.sh
        st = dict(st, run="<judged elsewhere>", **({"name": "<judged elsewhere>"} if "SUITE" in (st.get("env") or {}) else {}))
    return st
JUDGED = json.loads(r'''{
 "steps": {
  "allowlist": [
   {
    "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "with": {
     "fetch-depth": "0"
    }
   },
   {
    "name": "make sure the base branch ref exists",
    "env": {
     "BASE": "${{ github.base_ref }}"
    },
    "run": "if [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi"
   },
   {
    "name": "allowlist branch-scoping regressions",
    "run": "bash bin/check-file-allowlist-test.sh"
   },
   {
    "name": "customer-word check regressions",
    "run": "bash bin/check-customer-words-test.sh"
   },
   {
    "name": "branch sweep and local prune regressions",
    "run": "bash bin/branch-sweep-test.sh"
   },
   {
    "name": "govulncheck fixture modules materialize (never indexed by the dependency graph)",
    "run": "bash .github/agent/tests/govulncheck-fixtures-test.sh"
   },
   {
    "name": "suite guard (no tracked test file is empty)",
    "run": "bash bin/suite-guard.sh files"
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
    "run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/pip-requirements.txt\npython3 -m pip --version"
   },
   {
    "name": "the hash-pinned test requirements (PyYAML, which the workflow checks read the workflows with, and the report lint's cmark-gfm)",
    "run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/test-requirements.txt"
   },
   {
    "name": "every reusable-workflow caller covers its callees' permissions (R01)",
    "run": "python3 bin/check-workflow-permissions.py"
   },
   {
    "name": "the pin checker's own cases (row 78)",
    "run": "bash .github/agent/tests/check-action-pins-test.sh"
   },
   {
    "name": "the pip that CI runs is pinned in every job that installs with pip (REQ-SUP-001-AC13)",
    "run": "bash .github/agent/tests/pip-pin-test.sh"
   },
   {
    "name": "the documented Gradle and Maven snippets have the structure acceptance runs, and the Kubernetes reset order",
    "run": "bash .github/agent/tests/docs-snippets-test.sh"
   },
   {
    "name": "auditor Python requirements resolve (hash-pinned SDK + coverage tool)",
    "run": "for r in .github/agent/adjudicator-requirements.txt .github/agent/coverage-requirements.txt .github/agent/test-requirements.txt; do\n  python3 -m pip install --quiet --dry-run --ignore-installed --require-hashes --only-binary=:all: \\\n    --target \"$RUNNER_TEMP/resolve-check\" -r \"$r\"\ndone"
   },
   {
    "name": "auditor layout \u2014 everything auditor-related under .github/agent/ (REQ-AUD-18 AC1)",
    "run": "git ls-files | python3 .github/agent/bin/auditor-layout-check.py"
   },
   {
    "name": "auditor suites \u2014 parser unit tests and the requirements-matrix suite",
    "env": {
     "BASE": "${{ github.base_ref }}"
    },
    "run": "if [ -n \"${BASE}\" ] && ! git diff --quiet \"origin/${BASE}...HEAD\" -- bench/gradle-sample/gradle/wrapper/gradle-wrapper.properties bench/gradle-sample/gradle/wrapper/gradle-wrapper.jar .github/policy/gradle-wrapper-jar-sha256.txt; then\n  export GRADLE_SUM_ONLINE=1\nfi\nbash .github/agent/tests/auditor-parser-tests.sh"
   },
   {
    "name": "auditor requirements-matrix suite (REQ-CI-005, a counting step)",
    "run": "bash .github/agent/tests/auditor-matrix-test.sh"
   },
   {
    "name": "auditor report-label suite (REQ-CI-005, a counting step)",
    "run": "bash .github/agent/tests/auditor-labels-test.sh"
   },
   {
    "name": "the probe's one-request-per-seat cap against the hash-pinned SDKs (REQ-SCAN-008)",
    "run": "set -euo pipefail\npython3 -m venv \"$RUNNER_TEMP/panel-sdk\"\n\"$RUNNER_TEMP/panel-sdk/bin/python\" -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/pip-requirements.txt\n\"$RUNNER_TEMP/panel-sdk/bin/python\" -m pip --version\n\"$RUNNER_TEMP/panel-sdk/bin/pip\" install --quiet --require-hashes --only-binary=:all: -r .github/agent/adjudicator-requirements.txt\nPANEL_SDK_TEST_REQUIRED=1 \"$RUNNER_TEMP/panel-sdk/bin/python\" .github/agent/bin/tests/test_panel_sdk_probe.py -v"
   },
   {
    "name": "the committed melange recipes are exactly the generator's output from build/melange.yaml.tmpl (REQ-BUILDTOOLS-001-AC5)",
    "run": "python3 bin/gen-recipes.py --check"
   },
   {
    "name": "no unmarked version literals in public docs",
    "run": "./bin/check-version-literals.sh"
   },
   {
    "name": "VEX tripwire \u2014 components answered by a VEX statement must stay absent",
    "run": "set -euo pipefail\nif grep -q 'golang-jwt' go.sum; then\n  echo \"::error::golang-jwt has entered go.sum. The published VEX statement for CVE-2024-51744 claims component_not_present, which is no longer true on its face. VEX statement requires review before this can merge \u2014 see .vex/README.md.\" >&2\n  exit 1\nfi\necho \"VEX tripwire: golang-jwt absent from go.sum, as the published statement asserts.\""
   }
  ]
 },
 "shape": {
  "allowlist": {
   "name": "allowlist",
   "runs-on": "ubuntu-latest",
   "if": "github.event_name == 'push'"
  }
 }
}''')
JUDGED_STEPS, JUDGED_SHAPE = JUDGED["steps"], JUDGED["shape"]
for jid, want_steps in JUDGED_STEPS.items():
    sj = d.get("jobs", {}).get(jid)
    if not isinstance(sj, dict):
        bad.append(f"the job {jid} is missing")
        continue
    got_shape = {k: v for k, v in sj.items() if k != "steps"}
    if got_shape != JUDGED_SHAPE[jid]:
        bad.append(f"the {jid} job is not exactly {JUDGED_SHAPE[jid]} apart from its steps (REQ-CI-001, REQ-CI-005: name, runs-on, needs, if, strategy and outputs as judged)")
    got = sj.get("steps", [])
    if [_by_shape(st) for st in got] != [_by_shape(st) for st in want_steps]:
        have = [_by_shape(st).get("name") or st.get("uses") for st in got]
        want_n = [_by_shape(st).get("name") or st.get("uses") for st in want_steps]
        why = [f"missing {n}" for n in want_n if n not in have] + [f"unexpected {n}" for n in have if n not in want_n]
        if not why:      # the same names: say which step differs and in which keys
            for _i, (_g, _w) in enumerate(zip(got, want_steps)):
                _keys = sorted(k for k in set(_g) | set(_w) if _by_shape(_g).get(k) != _by_shape(_w).get(k))
                if _keys:
                    _nm = _g.get("name") or _g.get("uses")
                    bad.append(f"the {jid} step {_i + 1} ({_nm}) differs in: {', '.join(_keys)}")
                    break
            else:
                bad.append(f"the {jid} steps are not exactly the judged list (same steps, other number or order)")
        else:
            bad.append(f"the {jid} steps are not exactly the judged list ({'; '.join(why)})")
# the allowlist job's actions are judged on their own, so the job cannot borrow another's: the checkout (full depth) and the one setup-python
ALLOWLIST_ACTIONS = [_by_shape(st) for st in (
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "with": {"fetch-depth": "0"}},
    {"name": "set up Python", "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
     "with": {"python-version": "3.12"}})]
for _i, st in enumerate(steps_):
    if "uses" in st and _by_shape(st) not in ALLOWLIST_ACTIONS:
        bad.append(f"the allowlist step {_i + 1} ({st.get('name') or st['uses']}) is not a judged action step")

# the policy lists (release admission reads them): each a readable JSON object whose required_checks is a list of objects with unique contexts. required-checks.json has exactly
# one correct entry (integration 15368, scope push) for the job allowlist and none for the gate allowlist-chain; release-only-checks.json has exactly one correct entry for the gate
# (a context is in one file or the other, never both). Anything unreadable or malformed is refused (fail closed).
PROTECTED = ("allowlist", "allowlist-chain")
def policy_entries(var, label):
    try:
        pol = json.load(open(os.environ[var]))["required_checks"]
        if not isinstance(pol, list) or not all(isinstance(c, dict) for c in pol):
            raise ValueError("required_checks is not a list of objects")
    except (OSError, ValueError, KeyError, TypeError) as e:
        bad.append(f"{label} is unreadable or malformed ({type(e).__name__})")
        return None
    ctxs = [c.get("context") for c in pol]
    for dup in sorted({c for c in ctxs if ctxs.count(c) > 1}, key=str):
        bad.append(f"{label} lists the context {dup} more than once")
    return pol, ctxs
def one_entry(listing, label, jid):
    if listing is not None and (sum(1 for c in listing[0] if c == {"context": jid, "integration_id": 15368, "scope": "push"}) != 1 or listing[1].count(jid) != 1):
        bad.append(f"{label} does not have exactly one entry {jid} (integration 15368, scope push)")
required = policy_entries("PIN_WIRING_POLICY_FILE", "required-checks.json")
one_entry(required, "required-checks.json", "allowlist")
if required is not None and "allowlist-chain" in required[1]:
    bad.append("required-checks.json lists allowlist-chain, which is release-only (release-only-checks.json), bound to full-suite.yml")
one_entry(policy_entries("PIN_WIRING_RELEASE_ONLY_FILE", "release-only-checks.json"), "release-only-checks.json", "allowlist-chain")
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
    if jid_ != "allowlist" and (nm in PROTECTED or jid_ in PROTECTED):
        bad.append(f"the job {jid_} produces the protected check name {nm}")
    if jid_ in ("suite-list", "suites"):
        bad.append(f"ci.yml holds the job {jid_}: the full suite's jobs live in full-suite.yml only (REQ-CI-007-AC2)")
    if jid_ != "allowlist" and not name_disjoint(nm):
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
        if (_jid in PROTECTED or _nm in PROTECTED) and not (_f == "full-suite.yml" and _jid == _nm == "allowlist-chain"):   # the gate lives there, judged by fsjudge
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

# the jobs of full-suite.yml that this judge takes: suite-list, suites and allowlist-chain (REQ-CI-007-AC2, REQ-CI-001, REQ-CI-005). The workflow runs on a schedule and on workflow_dispatch
# only, so a job carries no event condition but the gate's `always()` (a gate skipped by a condition counts as passed, and a `push` condition would skip every run).
fsjudge() { python3 - "$1" <<'PY'
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
bad = []
import json, re
for k in sorted(set(d) - {"name", "on", "permissions", "jobs", "concurrency"}):
    bad.append(f"the workflow sets `{k}`")
if d.get("concurrency") != {"group": "${{ format('full-suite-{0}-{1}', github.run_id, github.run_attempt) }}", "cancel-in-progress": "false"}:
    bad.append("the workflow's concurrency is not the reviewed block (a group of its own per run and attempt, never cancelled)")
if d.get("permissions") != {"contents": "read"}:
    bad.append("the workflow permissions are not exactly {contents: read}")
on = d.get("on", {})
if not isinstance(on, dict) or sorted(on) != ["schedule", "workflow_dispatch"] or on["workflow_dispatch"] != "" or not isinstance(on["schedule"], list) or len(on["schedule"]) != 1:
    bad.append("full-suite.yml's events are not exactly one schedule and workflow_dispatch (no push, no pull_request, no merge_group, no workflow_call)")
if "defaults" in d or "env" in d:
    bad.append("the workflow sets `defaults` or `env`")
hooks = ("BASH_ENV", "GITHUB_ENV", "GITHUB_PATH")
risky = {"BASH_ENV", "ENV", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "SHELLOPTS", "BASHOPTS", "PS4", "IFS",
         "PROMPT_COMMAND", "CDPATH", "GLOBIGNORE", "TMPDIR", "HOME", "XDG_CONFIG_HOME"}
def is_risky(k):
    return k in risky or re.match(r"(GIT_|GITHUB_|LD_|DYLD_|PYTHON|BASH_|RUNNER_)", k) is not None
_PINNED_ACTIONS = ("actions/checkout", "actions/setup-python")
for _jid, _j in (d.get("jobs") or {}).items():
    if not isinstance(_j, dict):
        continue
    _nm = _j.get("name", _jid)
    if _jid != "allowlist-chain" and ("allowlist-chain" in (_jid, _nm) or "allowlist" in (_jid, _nm)):   # the protected names belong to their jobs alone
        bad.append(f"the job {_jid} produces the protected check name {_nm}")
    if "concurrency" in _j:
        bad.append(f"the job {_jid} has `concurrency`")
    if "defaults" in _j or "continue-on-error" in _j:
        bad.append(f"the job {_jid} has `defaults` or `continue-on-error`")
    for h in hooks:
        if h in json.dumps(_j):
            bad.append(f"the job {_jid} mentions {h}")
    for where, env in [(f"the job {_jid}", _j.get("env"))] + [(f"step {i} of {_jid}", st.get("env")) for i, st in enumerate(_j.get("steps") or []) if isinstance(st, dict)]:
        if isinstance(env, dict):
            for k in sorted(k for k in env if is_risky(k)):
                bad.append(f"{where} sets env {k}")
    for _i, _st_ in enumerate(_j.get("steps") or []):
        if isinstance(_st_, dict) and "continue-on-error" in _st_:
            bad.append(f"the job {_jid} has a step with `continue-on-error` ({_st_.get('name') or _st_.get('uses') or _st_.get('run')})")
        _u = _st_.get("uses") if isinstance(_st_, dict) else None
        if _u is not None and not (isinstance(_u, str) and re.fullmatch(r"(%s)@[0-9a-f]{40}" % "|".join(map(re.escape, _PINNED_ACTIONS)), _u)):
            bad.append(f"the {_jid} step {_i + 1} ({_st_.get('name') or _u}) uses an action that is not a pinned one of full-suite.yml")
def norm(r):  # drop comment lines; the command text itself must match exactly. A comment line is one whose first
    # character after ONLY spaces and tabs is `#` (bash's rule; Python's str.strip/lstrip/splitlines also
    # treat U+00A0, U+3000, U+2028 ... as whitespace or line ends, which bash does not)
    return "\n".join(l for l in (r or "").strip(" \t\n").split("\n") if not l.lstrip(" \t").startswith("#"))
def odd_chars(r):  # anything but printable ASCII, tab and newline in a protected run string
    return sorted({hex(ord(c)) for c in (r or "") if not (c in "\t\n" or " " <= c <= "~")})
for _jid in ("suite-list", "suites", "allowlist-chain"):
    for st in (d.get("jobs", {}).get(_jid) or {}).get("steps") or []:
        if not isinstance(st, dict):
            continue
        if odd_chars(st.get("run")):
            bad.append(f"a run text of the {_jid} job has non-ASCII or control characters {odd_chars(st.get('run'))}")
        if "${{" in (st.get("run") or ""):   # raw text, comment lines included: an expression is rendered before bash sees it
            bad.append(f"a run text of the {_jid} job contains a `${{{{` expression")
def _by_shape(st):
    """A step with `uses: name@<full 40-hex commit>` stands for every digest of
    that action: the digest VALUE is judged by check-action-pins --verify-tags and the daily audit (a Dependabot bump moves it), not by these lists. The
    action name and the exact shape of the ref (40 lower-case hex) stay compared; the stand-in is a tuple, which no YAML
    scalar can equal."""
    u = st.get("uses")
    if isinstance(u, str) and u.count("@") == 1:
        name, _, ref = u.partition("@")
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            st = dict(st, uses=(name, "@40-hex"))
    if "run" in st:
        st = dict(st, run=norm(st["run"]))
    if st.get("id") == "list" or "SUITE" in (st.get("env") or {}):   # the list step and the leg: run text (and the leg's name) are judged by ci-suites-matrix-test.sh
        st = dict(st, run="<judged elsewhere>", **({"name": "<judged elsewhere>"} if "SUITE" in (st.get("env") or {}) else {}))
    return st
JUDGED = json.loads(r'''{
 "steps": {
  "suite-list": [
   {
    "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "with": {
     "persist-credentials": "false"
    }
   },
   {
    "id": "list",
    "run": "<judged elsewhere>"
   }
  ],
  "suites": [
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
    "run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/pip-requirements.txt\npython3 -m pip --version"
   },
   {
    "name": "the hash-pinned test requirements (PyYAML, which the wiring suites read the workflows with, and the report lint's cmark-gfm)",
    "run": "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/test-requirements.txt"
   },
   {
    "name": "install the pinned grype (the suites that run the real scanner)",
    "if": "${{ matrix.suite == 'vex-scope-test.sh' || matrix.suite == 'vex-both-scanners-test.sh' }}",
    "run": "./bin/install-scanner.sh grype"
   },
   {
    "name": "<judged elsewhere>",
    "env": {
     "SUITE": "${{ matrix.suite }}"
    },
    "run": "<judged elsewhere>"
   }
  ],
  "allowlist-chain": [
   {
    "name": "every suite succeeded (a failed, skipped, cancelled or missing result fails)",
    "env": {
     "RESULT": "${{ needs.suites.result }}"
    },
    "run": "[ \"$RESULT\" = success ] || { echo \"the suites did not all succeed: [$RESULT]\"; exit 1; }"
   }
  ]
 },
 "shape": {
  "suite-list": {
   "name": "suite-list",
   "runs-on": "ubuntu-latest",
   "outputs": {
    "suites": "${{ steps.list.outputs.suites }}"
   }
  },
  "suites": {
   "name": "suites (${{ matrix.suite }})",
   "needs": "suite-list",
   "runs-on": "ubuntu-latest",
   "strategy": {
    "fail-fast": "false",
    "matrix": {
     "suite": "${{ fromJSON(needs.suite-list.outputs.suites) }}"
    }
   }
  },
  "allowlist-chain": {
   "name": "allowlist-chain",
   "runs-on": "ubuntu-latest",
   "needs": [
    "suites"
   ],
   "if": "always()"
  }
 }
}''')
JUDGED_STEPS, JUDGED_SHAPE = JUDGED["steps"], JUDGED["shape"]
for jid, want_steps in JUDGED_STEPS.items():
    sj = d.get("jobs", {}).get(jid)
    if not isinstance(sj, dict):
        bad.append(f"the job {jid} is missing")
        continue
    got_shape = {k: v for k, v in sj.items() if k != "steps"}
    if jid == "allowlist-chain" and got_shape.get("if") == "${{ always() }}":
        got_shape["if"] = "always()"      # the same condition, in its expression form
    if got_shape != JUDGED_SHAPE[jid]:
        bad.append(f"the {jid} job is not exactly {JUDGED_SHAPE[jid]} apart from its steps (REQ-CI-001, REQ-CI-005: name, runs-on, needs, if, strategy and outputs as judged)")
    got = sj.get("steps", [])
    if [_by_shape(st) for st in got] != [_by_shape(st) for st in want_steps]:
        have = [_by_shape(st).get("name") or st.get("uses") for st in got]
        want_n = [_by_shape(st).get("name") or st.get("uses") for st in want_steps]
        why = [f"missing {n}" for n in want_n if n not in have] + [f"unexpected {n}" for n in have if n not in want_n]
        if not why:      # the same names: say which step differs and in which keys
            for _i, (_g, _w) in enumerate(zip(got, want_steps)):
                _keys = sorted(k for k in set(_g) | set(_w) if _by_shape(_g).get(k) != _by_shape(_w).get(k))
                if _keys:
                    _nm = _g.get("name") or _g.get("uses")
                    bad.append(f"the {jid} step {_i + 1} ({_nm}) differs in: {', '.join(_keys)}")
                    break
            else:
                bad.append(f"the {jid} steps are not exactly the judged list (same steps, other number or order)")
        else:
            bad.append(f"the {jid} steps are not exactly the judged list ({'; '.join(why)})")
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
    if s3.get("run") != "bash bin/install-scanner.sh govulncheck" or set(s3) - {"name", "run"}: bad.append("install step")
    if s4.get("run") != 'python3 -I -B bin/check-govulncheck.py --scanners .github/policy/scanners.json --out "$RUNNER_TEMP/gv"' or set(s4) - {"name", "run"}: bad.append("script step")
sys.exit(1 if bad else 0)
PY
}
# judge mode, for the trusted review gate: judge the ci.yml and the full-suite.yml of one commit of the current repo, read as git
# objects (never checked out, never run), and nothing else
if [ -n "${PIN_WIRING_JUDGE_GIT:-}" ]; then
  git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/ci.yml" > "$work/head-ci.yml" || { echo "pin-wiring: no ci.yml at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  git show "${PIN_WIRING_JUDGE_GIT}:.github/policy/required-checks.json" > "$work/head-policy.json" || { echo "pin-wiring: no required-checks.json at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  git show "${PIN_WIRING_JUDGE_GIT}:.github/policy/release-only-checks.json" > "$work/head-release-only.json" || { echo "pin-wiring: no release-only-checks.json at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  mkdir -p "$work/head-wf"
  for wf in $(git ls-tree --name-only "${PIN_WIRING_JUDGE_GIT}" .github/workflows/ | sed 's|.*/||'); do   # every workflow of the commit, as git objects
    git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/$wf" > "$work/head-wf/$wf" || { echo "pin-wiring: cannot read workflow $wf" >&2; exit 1; }
  done
  git show "${PIN_WIRING_JUDGE_GIT}:tools/govulncheck/go.mod" > "$work/head-gomod" || { echo "pin-wiring: no tools/govulncheck/go.mod at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  PIN_WIRING_WORKFLOWS_DIR="$work/head-wf" PIN_WIRING_POLICY_FILE="$work/head-policy.json" PIN_WIRING_RELEASE_ONLY_FILE="$work/head-release-only.json" judge "$work/head-ci.yml" || exit 1
  [ -f "$work/head-wf/full-suite.yml" ] || { echo "pin-wiring: no full-suite.yml at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  fsjudge "$work/head-wf/full-suite.yml" || exit 1
  gvgate_judge "$work/head-ci.yml" "$work/head-gomod" || { echo "pin-wiring: the govulncheck job of the head's ci.yml is not the Check-equivalent form (REQ-REL-004-AC1)" >&2; exit 1; }
  exit 0
fi

case_on() {  # case_on <workflow file> <judge function> <name> <expect ok|bad> <python edit of the parsed copy, or empty>
  local wf=$1 jf=$2; shift 2
  local f="$work/$1.yml"
  cp "$here/.github/workflows/$wf" "$f"
  # an edit that cannot apply (its step is missing) is a failed case, not an aborted run
  if [ -n "$3" ]; then python3 - "$f" "$3" 2> /dev/null <<'PY' || { failn=$((failn+1)); echo "FAIL $1 → the edit did not apply"; return 0; }
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$($jf "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
case_() { case_on ci.yml judge "$@"; }
case_fs() { case_on full-suite.yml fsjudge "$@"; }

# case_msg <name> <python edit> <text>: the judge refuses the copy and its message holds the text
case_msg_on() {  # case_msg_on <workflow file> <judge function> <name> <python edit> <text>
  local wf=$1 jf=$2; shift 2
  local f="$work/$1.yml"
  cp "$here/.github/workflows/$wf" "$f"
  python3 - "$f" "$2" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  if out=$($jf "$f"); then got=ok; else got=bad; fi
  if [ "$got" = bad ] && grep -qF -- "$3" <<<"$out"; then pass=$((pass+1)); echo "PASS $1 → bad, names: $3"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want bad naming: $3 ($out)"; fi
}
case_msg() { case_msg_on ci.yml judge "$@"; }
case_msg_fs() { case_msg_on full-suite.yml fsjudge "$@"; }

steps='d["jobs"]["allowlist"]["steps"]'
# a counting step of ci.yml, by the file name of the suite it runs (its run is `bash PATH`)
cnt() { echo "[s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip().startswith('bash ') and (s.get('run') or '').strip().endswith('/$1')][0]"; }
pick=$(cnt check-action-pins-test.sh)
CW=$(cnt check-file-allowlist-test.sh)
case_ the-real-hygiene      ok  ""
case_fs the-real-full-suite ok  ""
# the event part of full-suite.yml (REQ-CI-007-AC4): one schedule and workflow_dispatch, nothing else
case_fs full-suite-push-trigger         bad "d['on']['push'] = {'branches': ['main']}"
case_fs full-suite-pull-request-trigger bad "d['on']['pull_request'] = ''"
case_fs full-suite-merge-group-trigger  bad "d['on']['merge_group'] = {'types': ['checks_requested']}"
case_fs full-suite-workflow-call-trigger bad "d['on']['workflow_call'] = {}"
case_fs full-suite-schedule-gone        bad "d['on'].pop('schedule')"
case_fs full-suite-dispatch-gone        bad "d['on'].pop('workflow_dispatch')"
case_fs full-suite-second-schedule      bad "d['on']['schedule'].append({'cron': '0 0 * * *'})"
case_fs full-suite-permissions-widened  bad "d['permissions'] = {'contents': 'write'}"
case_fs full-suite-concurrency-shared   bad "d['concurrency'] = {'group': 'full-suite', 'cancel-in-progress': 'true'}"
# REQ-CI-005: a counting step is exactly `bash PATH`; any other form of the line is refused
case_ count-step-plain-ok           ok  "w = $CW; w['run'] = 'bash bin/check-file-allowlist-test.sh'"
case_ count-step-devnull-added      bad "w = $CW; w['run'] = 'bash bin/check-file-allowlist-test.sh </dev/null'"
case_ count-step-other-path         bad "w = $CW; w['run'] = 'bash bin/check-customer-words-test.sh'"
case_ count-step-or-true            bad "w = $CW; w['run'] = 'bash bin/check-file-allowlist-test.sh || true'"
case_ count-step-wrapper            bad "w = $CW; w['run'] = 'timeout 60 bash bin/check-file-allowlist-test.sh'"
case_ count-step-twice              bad "w = $CW; w['run'] = 'bash bin/check-file-allowlist-test.sh\nbash bin/check-file-allowlist-test.sh'"
case_ count-step-if-false           bad "w = $CW; w['if'] = 'false'"
case_ count-step-continue           bad "w = $CW; w['continue-on-error'] = 'true'"
case_ count-step-env-injected       bad "w = $CW; w['run'] = 'BASH_ENV=/tmp/x bash bin/check-file-allowlist-test.sh'"
case_ count-step-copied-to-test-job bad "d['jobs']['test']['steps'].append(dict($CW))"
case_ count-step-two-suites-one-step bad "w = $CW; w['run'] = w['run'] + '\nbash bin/check-customer-words-test.sh'"
case_ step-removed          bad "$steps[:] = [s for s in $steps if (s.get('run') or '').strip() != $pick['run']]"
case_ step-if-false         bad "$pick['if'] = 'false'"
case_ step-continue         bad "$pick['continue-on-error'] = 'true'"
case_ step-weakened         bad "$pick['run'] = $pick['run'] + ' || true'"
case_ job-if-false          bad "d['jobs']['allowlist']['if'] = 'false'"
case_ job-if-gone           bad "d['jobs']['allowlist'].pop('if', None)"
case_ job-if-always         bad "d['jobs']['allowlist']['if'] = 'always()'"
case_ no-pull-request       bad "d['on'].pop('pull_request')"
case_ push-not-main         bad "d['on']['push']['branches'] = ['release']"
case_ pr-paths-filter       bad "d['on']['pull_request'] = {'paths': ['README.md']}"
case_ pr-branches-filter    bad "d['on']['pull_request'] = {'branches': ['release']}"
case_ push-paths-filter     bad "d['on']['push']['paths'] = ['README.md']"
case_ push-paths-ignore     bad "d['on']['push']['paths-ignore'] = ['**']"
case_ step-shell-override   bad "$pick['shell'] = \"bash -c 'true' {0}\""
case_ job-defaults-shell    bad "d['jobs']['allowlist']['defaults'] = {'run': {'shell': \"bash -c 'true' {0}\"}}"
case_ other-job-defaults    bad "d['jobs']['test']['defaults'] = {'run': {'shell': \"bash -c 'true' {0}\"}}"
case_ workflow-defaults     bad "d['defaults'] = {'run': {'shell': \"bash -c 'true' {0}\"}}"
case_ other-job-continue    bad "d['jobs']['lint']['continue-on-error'] = 'true'"
case_ other-step-continue   bad "d['jobs']['requirements']['steps'][-1]['continue-on-error'] = 'true'"
case_ bash-env-on-step      bad "$pick['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ bash-env-on-job       bad "d['jobs']['allowlist']['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ bash-env-on-other-job bad "d['jobs']['test']['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ shellopts-on-other-step bad "d['jobs']['lint']['steps'][-1]['env']['SHELLOPTS'] = 'noexec'"
case_ path-on-workflow      bad "d['env'] = {'PATH': '/tmp/fake:/usr/bin'}"
case_ github-env-write      bad "$steps.insert(1, {'run': 'echo BASH_ENV=/tmp/x.sh >> \"\$GITHUB_ENV\"'})"
case_ github-path-write     bad "$steps.insert(1, {'run': 'echo /tmp/fake >> \"\$GITHUB_PATH\"'})"
case_ github-env-write-test-job bad "d['jobs']['test']['steps'].insert(1, {'run': 'echo BASH_ENV=/tmp/x.sh >> \"\$GITHUB_ENV\"'})"
case_ checkout-other-ref    bad "$steps[0]['with'] = {'ref': 'main'}"
case_ cases-step-env        bad "$pick['env'] = {'PINS_DRY': '1'}"
case_ cases-step-env-self   bad "$pick['env'] = {'PINS_SELF': '/bin/true'}"
case_ cases-step-removed    bad "$steps[:] = [s for s in $steps if s is not $pick]"

# the counting steps of the allowlist job (REQ-CI-005): each is one step with exactly its name and its counting line and nothing else, so a pull request cannot remove, skip, rename, weaken, wrap or move it
for sfx in check-file-allowlist check-customer-words branch-sweep govulncheck-fixtures check-action-pins pip-pin docs-snippets auditor-matrix auditor-labels; do
  sel=$(cnt "$sfx-test.sh")
  case_ "$sfx-removed"  bad "$steps[:] = [s for s in $steps if s is not $sel]"
  case_ "$sfx-if"       bad "$sel['if'] = 'false'"
  case_ "$sfx-continue" bad "$sel['continue-on-error'] = 'true'"
  case_ "$sfx-or-true"  bad "$sel['run'] = $sel['run'] + ' || true'"
  case_ "$sfx-renamed"  bad "$sel['name'] = 'tests'"
  case_ "$sfx-env"      bad "$sel['env'] = {'A': 'b'}"
  case_ "$sfx-shell"    bad "$sel['shell'] = \"bash -c 'true' {0}\""
  case_ "$sfx-workdir"  bad "$sel['working-directory'] = 'bin'"
  case_ "$sfx-timeout"  bad "$sel['timeout-minutes'] = '5'"
  case_ "$sfx-twice"    bad "$steps.append(dict($sel))"
  case_ "$sfx-other-job" bad "x = $sel; $steps.remove(x); d['jobs']['test']['steps'].append(x)"
done
# the counting steps of the other jobs: not a listed job, but a counting step has no key but name and run, and no line may run the runner in another form
for sfx in check-no-outbound rescan-statement; do
  sel=$(cnt "$sfx-test.sh")
  case_ "$sfx-if"       bad "$sel['if'] = 'false'"
  case_ "$sfx-continue" bad "$sel['continue-on-error'] = 'true'"
  case_ "$sfx-or-true"  bad "$sel['run'] = $sel['run'] + ' || true'"
  case_ "$sfx-env"      bad "$sel['env'] = {'A': 'b'}"
  case_ "$sfx-shell"    bad "$sel['shell'] = \"bash -c 'true' {0}\""
  case_ "$sfx-workdir"  bad "$sel['working-directory'] = 'bin'"
  case_ "$sfx-timeout"  bad "$sel['timeout-minutes'] = '5'"
  case_ "$sfx-twice"    bad "j = [j for j in d['jobs'].values() if any(s is $sel for s in (j.get('steps') or []))][0]; j['steps'].append(dict($sel))"
done

fe='[s for s in '"$steps"' if "git fetch" in (s.get("run") or "")][0]'
case_ fetch-removed             bad "$steps[:] = [s for s in $steps if 'git fetch' not in (s.get('run') or '')]"
case_ fetch-or-true             bad "$fe['run'] = $fe['run'].rstrip() + ' || true'"
case_ fetch-if-false            bad "$fe['if'] = 'false'"
case_ fetch-continue            bad "$fe['continue-on-error'] = 'true'"
case_ fetch-shell               bad "$fe['shell'] = \"bash -c 'true' {0}\""
case_ fetch-workdir             bad "$fe['working-directory'] = 'bin'"
case_ fetch-env-removed         bad "$fe.pop('env')"
case_ fetch-env-changed         bad "$fe['env'] = {'BASE': 'main'}"
case_ fetch-inline-expression   bad "$fe.pop('env'); $fe['run'] = 'git fetch --no-tags origin +refs/heads/\${{ github.base_ref }}:refs/remotes/origin/\${{ github.base_ref }}'"
case_ fetch-moved-last          bad "$steps.append($steps.pop(1))"
case_ fetch-depth-reverted      bad "$steps[0].pop('with')"
case_ fetch-depth-shallow       bad "$steps[0]['with'] = {'fetch-depth': '1'}"
case_ allowlist-job-renamed     bad "d['jobs']['allowlist']['name'] = 'file allowlist'"
case_ allowlist-job-unnamed     bad "d['jobs']['allowlist'].pop('name')"

case_ insert-update-index-step  bad "$steps.insert(2, {'run': 'git update-index --force-remove -- .snyk'})"
case_ insert-update-ref-step    bad "$steps.insert(2, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
case_ insert-update-ref-first   bad "$steps.insert(1, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
case_ insert-script-overwrite   bad "$steps.insert(2, {'run': 'echo true > bin/check-file-allowlist.sh'})"
case_ insert-step-before-checkout bad "$steps.insert(0, {'run': 'true'})"
case_ insert-step-at-the-end    bad "$steps.append({'run': 'true'})"
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
case_ ld-preload-other-job      bad "d['jobs']['govulncheck']['steps'][-1]['env'] = {'LD_PRELOAD': '/tmp/x.so'}"

# the suite guard step of the allowlist job (an `if` or an `env` on purpose, or the guard's own regressions): every key and value is judged
for g in "suite-guard.sh files"; do
  gs="[s for s in $steps if '$g' in (s.get('run') or '')][0]"; gn=${g// /-}
  case_ "guard-$gn-removed"  bad "$steps[:] = [s for s in $steps if '$g' not in (s.get('run') or '')]"
  case_ "guard-$gn-if"       bad "$gs['if'] = 'false'"
  case_ "guard-$gn-env"      bad "$gs['env'] = {'A': '0'}"
  case_ "guard-$gn-or-true"  bad "$gs['run'] = $gs['run'] + ' || true'"
  case_ "guard-$gn-renamed"  bad "$gs['name'] = 'guard'"
  case_ "guard-$gn-shell"    bad "$gs['shell'] = \"bash -c 'true' {0}\""
  case_ "guard-$gn-continue" bad "$gs['continue-on-error'] = 'true'"
  case_ "guard-$gn-moved"    bad "x = $gs; $steps.remove(x); d['jobs']['test']['steps'].append(x)"
done

# the suites matrix of full-suite.yml (REQ-CI-005-AC2, REQ-CI-007-AC2): the structure of the list job and of the legs (the run text of the list step and of the leg is judged by ci-suites-matrix-test.sh)
SL='d["jobs"]["suite-list"]'; SU='d["jobs"]["suites"]'
LS="[s for s in $SL['steps'] if s.get('id') == 'list'][0]"
LEG="[s for s in $SU['steps'] if (s.get('env') or {}).get('SUITE')][0]"
GR="[s for s in $SU['steps'] if 'install-scanner.sh grype' in (s.get('run') or '')][0]"
case_fs suites-job-missing          bad "d['jobs'].pop('suites')"
case_fs suite-list-missing          bad "d['jobs'].pop('suite-list')"
case_fs suite-list-id-changed       bad "$LS['id'] = 'other'"
case_fs suite-list-output-gone      bad "$SL.pop('outputs')"
case_fs suite-list-output-other     bad "$SL['outputs']['suites'] = '\${{ steps.other.outputs.suites }}'"
case_fs suite-list-if               bad "$SL['if'] = 'false'"
case_fs suite-list-if-push          bad "$SL['if'] = \"github.event_name == 'push'\""
case_fs suite-list-env              bad "$SL['env'] = {'X': '1'}"
case_fs suite-list-step-if          bad "$LS['if'] = 'false'"
case_fs suite-list-checkout-creds   bad "$SL['steps'][0]['with'].pop('persist-credentials')"
case_fs suite-list-extra-step       bad "$SL['steps'].append({'run': 'true'})"
case_fs suites-needs-gone           bad "$SU.pop('needs')"
case_fs suites-needs-other          bad "$SU['needs'] = 'lint'"
case_fs suites-matrix-literal       bad "$SU['strategy']['matrix']['suite'] = ['check-archive-test.sh']"
case_fs suites-matrix-other-output  bad "$SU['strategy']['matrix']['suite'] = '\${{ fromJSON(needs.suite-list.outputs.other) }}'"
case_fs suites-matrix-include       bad "$SU['strategy']['matrix']['include'] = [{'suite': 'x'}]"
case_fs suites-matrix-exclude       bad "$SU['strategy']['matrix']['exclude'] = [{'suite': 'chain-verify-test.sh'}]"
case_fs suites-fail-fast            bad "$SU['strategy']['fail-fast'] = 'true'"
case_fs suites-max-parallel         bad "$SU['strategy']['max-parallel'] = '1'"
case_fs suites-strategy-gone        bad "$SU.pop('strategy')"
case_fs suites-job-if               bad "$SU['if'] = 'false'"
case_fs suites-job-if-push          bad "$SU['if'] = \"github.event_name == 'push'\""
case_fs suites-job-continue         bad "$SU['continue-on-error'] = 'true'"
case_fs suites-job-timeout          bad "$SU['timeout-minutes'] = '1'"
case_fs suites-job-permissions      bad "$SU['permissions'] = {'contents': 'write'}"
case_fs suites-job-env              bad "$SU['env'] = {'SUITE': 'x'}"
case_fs suites-job-container        bad "$SU['container'] = 'alpine'"
case_fs suites-job-runs-on          bad "$SU['runs-on'] = 'self-hosted'"
case_fs suites-job-renamed          bad "$SU['name'] = 'suites'"
case_fs suites-leg-if               bad "$LEG['if'] = 'false'"
case_fs suites-leg-continue         bad "$LEG['continue-on-error'] = 'true'"
case_fs suites-leg-suite-env-literal bad "$LEG['env']['SUITE'] = 'x'"
case_fs suites-leg-suite-env-gone   bad "$LEG.pop('env')"
case_fs suites-leg-shell            bad "$LEG['shell'] = \"bash -c 'true' {0}\""
case_fs suites-leg-removed          bad "$SU['steps'][:] = [s for s in $SU['steps'] if s is not $LEG]"
case_fs suites-grype-always         bad "$GR['if'] = 'true'"
case_fs suites-grype-condition-narrowed bad "$GR['if'] = \"\${{ matrix.suite == 'vex-scope-test.sh' }}\""
case_fs suites-grype-removed        bad "$SU['steps'][:] = [s for s in $SU['steps'] if s is not $GR]"
case_fs suites-checkout-shallow     bad "$SU['steps'][0]['with'] = {'fetch-depth': '1'}"
case_fs suites-checkout-other-ref   bad "$SU['steps'][0]['with']['ref'] = 'main'"
case_fs suites-step-added           bad "$SU['steps'].append({'name': 'x', 'run': 'true'})"
case_fs suites-steps-reordered      bad "st = $SU['steps']; st[0], st[1] = st[1], st[0]"
case_fs suites-pip-env              bad "[s for s in $SU['steps'] if s.get('name') == 'pin pip (hash-checked)'][0]['env'] = {'PIP_INDEX_URL': 'http://x'}"

# the gate of full-suite.yml: the release-only check allowlist-chain (REQ-CI-001, REQ-CI-007-AC2): the name, needs the suites job and no other, always runs (no event condition: the file has no push run), no checkout and no action, fails unless the result is exactly success
GT='d["jobs"]["allowlist-chain"]'
case_fs gate-renamed          bad "$GT['name'] = 'allowlist-chain-gate'"
case_fs gate-needs-gone       bad "$GT.pop('needs')"
case_fs gate-needs-extra      bad "$GT['needs'] = ['suites', 'lint']"
case_fs gate-needs-other      bad "$GT['needs'] = ['lint']"
case_fs gate-needs-str        bad "$GT['needs'] = 'suites'"
case_fs gate-needs-suite-list bad "$GT['needs'] = ['suite-list']"
case_fs gate-no-always        bad "$GT.pop('if')"
case_fs gate-if-always-wrapped ok  "$GT['if'] = '\${{ always() }}'"
case_fs gate-if-push-only     bad "$GT['if'] = \"github.event_name == 'push'\""
case_fs gate-if-or-push       bad "$GT['if'] = \"always() || github.event_name == 'push'\""
case_fs gate-if-pull-request  bad "$GT['if'] = \"always() && github.event_name == 'pull_request'\""
case_fs gate-if-always-plain   ok  "$GT['if'] = 'always()'"
case_fs gate-if-push-added     bad "$GT['if'] = \"always() && github.event_name == 'push'\""
case_fs gate-if-push-added-wrapped bad "$GT['if'] = \"\${{ always() && github.event_name == 'push' }}\""
case_fs gate-if-false         bad "$GT['if'] = 'false'"
case_fs gate-success          bad "$GT['if'] = '\${{ success() }}'"
case_fs gate-checkout         bad "$GT['steps'].insert(0, $SU['steps'][0])"
case_fs gate-action           bad "$GT['steps'].insert(0, {'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'})"
case_fs gate-or-true          bad "$GT['steps'][0]['run'] += ' || true'"
case_fs gate-skipped-ok       bad "$GT['steps'][0]['run'] = '[ \"\$RESULT\" != failure ] || exit 1'"
case_fs gate-empty-ok         bad "$GT['steps'][0]['run'] = '[ \"\$RESULT\" = success ] || [ -z \"\$RESULT\" ] || exit 1'"
case_fs gate-env-wrong        bad "$GT['steps'][0]['env']['RESULT'] = '\${{ needs.suite-list.result }}'"
case_fs gate-env-lit          bad "$GT['steps'][0]['env']['RESULT'] = 'success'"
case_fs gate-env-gone         bad "$GT['steps'][0].pop('env')"
case_fs gate-continue         bad "$GT['steps'][0]['continue-on-error'] = 'true'"
case_fs gate-step-if          bad "$GT['steps'][0]['if'] = 'false'"
case_fs gate-job-env          bad "$GT['env'] = {'X': '1'}"
case_fs gate-runs-on          bad "$GT['runs-on'] = 'self-hosted'"
case_fs gate-permissions      bad "$GT['permissions'] = {'checks': 'write'}"
case_fs gate-timeout          bad "$GT['timeout-minutes'] = '1'"
case_fs gate-container        bad "$GT['container'] = 'alpine'"
case_fs gate-continue-job     bad "$GT['continue-on-error'] = 'true'"
case_fs gate-step-added       bad "$GT['steps'].append({'run': 'true'})"
case_fs gate-missing          bad "d['jobs'].pop('allowlist-chain')"
case_fs gate-impersonated     bad "d['jobs']['replacement'] = {'name': 'allowlist-chain', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
case_fs gate-impersonated-by-id bad "d['jobs']['allowlist-chain-2'] = {'name': 'x', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist-chain']['needs'] = ['suites', 'allowlist-chain-2']"
# the old four-shard form of REQ-CI-001 is no longer accepted: a shard job and a gate that needs the shards
case_fs shard-form-refused    bad "d['jobs']['allowlist-chain-1'] = {'name': 'allowlist-chain-1', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist-chain']['needs'] = ['allowlist-chain-1']"
case_ impersonate-allowlist bad "d['jobs']['replacement'] = {'name': 'allowlist', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
case_ impersonate-by-id     bad "d['jobs']['allowlist-chain-x'] = {'name': 'allowlist', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"

# judge mode (the trusted gate, .github/workflows/agent-review-gate.yml): PIN_WIRING_JUDGE_GIT=<commit> judges THAT
# commit's .github/workflows/ci.yml, read as a git object from the current repo (nothing checked out or run), and
# does nothing else; exit 1 and the reasons when it fails
gitcase() {  # gitcase <name> <expect ok|bad> <python edit or empty> [the workflow file the edit applies to, ci.yml by default]
  local r="$work/git-$1"; rm -rf "$r"; mkdir -p "$r/.github/workflows"
  cp "$here/.github/workflows/ci.yml" "$r/.github/workflows/ci.yml"
  mkdir -p "$r/.github/policy"; cp "$here/.github/policy/required-checks.json" "$r/.github/policy/required-checks.json"; cp "$here/.github/policy/release-only-checks.json" "$r/.github/policy/release-only-checks.json"
  cp "$here"/.github/workflows/*.y*ml "$r/.github/workflows/" 2>/dev/null || true
  mkdir -p "$r/tools/govulncheck"; cp "$here/tools/govulncheck/go.mod" "$r/tools/govulncheck/go.mod"      # the pin the govulncheck-gate judge reads at the judged commit
  if [ -n "$3" ]; then python3 - "$r/.github/workflows/${4:-ci.yml}" "$3" <<'PY'
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
gitcase counting-step-wrapped-at-a-commit bad "w = $CW; w['run'] = 'bash bin/check-file-allowlist-test.sh || true'"
# the policy at the commit is read too: a missing entry is refused (and so is a missing file, above)

# the govulncheck-gate judge runs in judge mode too, over the head's own ci.yml (the trusted gate path)
GVJ="[j for j in [d['jobs']['govulncheck']]][0]['steps']"
gitcase govulncheck-gate-old-step-at-a-commit  bad "$GVJ[-1]['run'] = 'govulncheck ./...'"
gitcase govulncheck-gate-no-installer-at-a-commit  bad "$GVJ[:] = [s for s in $GVJ if s.get('run') != 'bash bin/install-scanner.sh go']"
gitcase govulncheck-gate-extra-step-at-a-commit  bad "$GVJ.insert(3, {'run': 'cp /bin/true /usr/local/bin/fscache-go/bin/govulncheck'})"
gitcase fetch-true-at-a-commit    bad "$fe['run'] = 'true'"
gitcase inserted-step-at-a-commit bad "$steps.insert(2, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
gitcase fetch-depth-at-a-commit   bad "$steps[0].pop('with')"
gitcase gate-or-true-at-a-commit  bad "$GT['steps'][0]['run'] += ' || true'" full-suite.yml
gitcase suites-leg-if-at-a-commit bad "$LEG['if'] = 'false'" full-suite.yml
gitcase full-suite-push-at-a-commit bad "d['on']['push'] = {'branches': ['main']}" full-suite.yml

case_ job-needs-skipped          bad "d['jobs']['skip_guard'] = {'runs-on': 'ubuntu-latest', 'if': 'false', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist']['needs'] = 'skip_guard'"
# a bump of an action that ci.yml uses moves the digest in every step that uses it; the digest value is judged by check-action-pins --verify-tags and the daily audit,
# not by this judge. The action name and the full 40-hex lower-case shape of the ref stay exact, in every job.
BUMP="for j in d['jobs'].values(): "
BUMP+="[s.__setitem__('uses', '%s') for s in (j.get('steps') or []) "
BUMP+="if s.get('uses', '').startswith('actions/setup-python@')]"
case_ uses-digest-bumped       ok  "${BUMP//%s/actions/setup-python@abababababababababababababababababababab}"
case_ uses-tag-ref             bad "${BUMP//%s/actions/setup-python@v7}"
case_ uses-short-digest        bad "${BUMP//%s/actions/setup-python@abababababababababababababababababababa}"
case_ uses-upper-digest        bad "${BUMP//%s/actions/setup-python@ABABABABABABABABABABABABABABABABABABABAB}"
case_ uses-other-action-name   bad "${BUMP//%s/evil/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97}"
case_ uses-literal-marker       bad "${BUMP//%s/actions/setup-python@<commit>}"
BUMPJ="[s.__setitem__('uses', '%s') for s in d['jobs']['JOB']['steps'] if s.get('uses', '').startswith('actions/%a@')]"
for jb in test lint govulncheck allowlist suite-list suites requirements marker-gate; do
  wf=ci.yml; cs=case_; case $jb in suite-list|suites) wf=full-suite.yml; cs=case_fs;; esac
  for act in checkout setup-go setup-python upload-artifact; do
    if python3 - "$here/.github/workflows/$wf" "$jb" "$act" <<'PYU'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
sys.exit(0 if any(s.get("uses", "").startswith("actions/" + sys.argv[3] + "@") for s in d["jobs"][sys.argv[2]]["steps"]) else 1)
PYU
    then
      b=${BUMPJ//JOB/$jb}; b=${b//%a/$act}
      $cs "uses-$act-in-$jb-digest-bumped" ok  "${b//%s/actions/$act@abababababababababababababababababababab}"
      $cs "uses-$act-in-$jb-tag"           bad "${b//%s/actions/$act@v4}"
      $cs "uses-$act-in-$jb-short-digest"  bad "${b//%s/actions/$act@abababababababababababababababababababa}"
      $cs "uses-$act-in-$jb-other-owner"   bad "${b//%s/evil/$act@abababababababababababababababababababab}"
    fi
  done
done
case_ uses-third-party-in-test bad "d['jobs']['test']['steps'].insert(2, {'uses': 'actions/cache@abababababababababababababababababababab'})"
case_ uses-third-party-in-lint  bad "d['jobs']['lint']['steps'].insert(2, {'uses': 'actions/cache@abababababababababababababababababababab'})"
case_ uses-third-party-in-requirements bad "d['jobs']['requirements']['steps'].insert(2, {'uses': 'docker/login-action@abababababababababababababababababababab'})"
case_ uses-local-action-in-marker-gate bad "d['jobs']['marker-gate']['steps'].insert(2, {'uses': './.github/actions/x'})"
case_ uses-reusable-workflow-job bad "d['jobs']['extra'] = {'uses': 'o/r/.github/workflows/w.yml@abababababababababababababababababababab'}"
# each job's actions are judged on their own, so one job cannot borrow another's
case_ allowlist-uses-bumped-digest-ok ok "d['jobs']['allowlist']['steps'][7]['uses'] = 'actions/setup-python@abababababababababababababababababababab'"
case_msg allowlist-uses-setup-python-tag "d['jobs']['allowlist']['steps'][7]['uses'] = 'actions/setup-python@v7'" "the allowlist step 8 (set up Python) is not a judged action step"
case_msg allowlist-uses-setup-python-39-hex "d['jobs']['allowlist']['steps'][7]['uses'] = 'actions/setup-python@0123456789abcdef0123456789abcdef0123456'" "the allowlist step 8 (set up Python) is not a judged action step"
case_msg allowlist-uses-setup-python-upper-hex "d['jobs']['allowlist']['steps'][7]['uses'] = 'actions/setup-python@0123456789ABCDEF0123456789ABCDEF01234567'" "the allowlist step 8 (set up Python) is not a judged action step"
case_msg allowlist-uses-setup-python-other-owner "d['jobs']['allowlist']['steps'][7]['uses'] = 'evil/setup-python@0123456789abcdef0123456789abcdef01234567'" "the allowlist step 8 (set up Python) is not a judged action step"
case_msg allowlist-uses-setup-python-commit-placeholder "d['jobs']['allowlist']['steps'][7]['uses'] = 'actions/setup-python@<commit>'" "the allowlist step 8 (set up Python) is not a judged action step"
case_msg allowlist-uses-extra-action-step "d['jobs']['allowlist']['steps'].insert(3, {'name': 'x', 'uses': 'actions/cache@0123456789abcdef0123456789abcdef01234567'})" "the allowlist step 4 (x) is not a judged action step"
case_msg allowlist-uses-checkout-tag "s = d['jobs']['allowlist']['steps'][0]; s.pop('name', None); s['uses'] = 'actions/checkout@v4'" "the allowlist step 1 (actions/checkout@v4) is not a judged action step"
case_msg_fs suites-uses-tag-names-job "d['jobs']['suites']['steps'][0]['uses'] = 'actions/checkout@v4'" "the suites step 1 (actions/checkout@v4) uses an action that is not a pinned one of full-suite.yml"
RUNX="d['jobs']['suites']['steps'][2]['run'] += ' || true'"
case_msg_fs run-changed-names-step "$RUNX" "the suites step 3 ("
case_msg_fs run-changed-names-key  "$RUNX" "differs in: run"
case_msg counting-step-key-names-the-step "w = $CW; w['if'] = 'false'" "has \`if\` (a counting step has no key but name and run)"
case_msg counted-twice-names-the-suite "d['jobs']['test']['steps'].append(dict($CW))" "the suite bin/check-file-allowlist-test.sh is counted by more than one step"
case_ impersonate-by-name     bad "d['jobs']['replacement'] = {'name': 'allowlist-chain', 'runs-on': 'ubuntu-latest', 'needs': 'allowlist-chain', 'if': '\${{ always() }}', 'steps': [{'run': 'true'}]}"
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
case_fs job-concurrency-suites     bad "d['jobs']['suites']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'false'}"
case_ job-concurrency-lint-same  bad "d['jobs']['lint']['concurrency'] = d['concurrency'] if 'concurrency' in d else {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': 'true'}"
case_ on-workflow-call           bad "d['on']['workflow_call'] = {}"
case_ on-workflow-dispatch       bad "d['on']['workflow_dispatch'] = {}"
case_ on-merge-group             ok  "d['on']['merge_group'] = {'types': ['checks_requested']}"
case_ on-schedule                bad "d['on']['schedule'] = [{'cron': '0 0 * * *'}]"
case_ wf-concurrency             bad "d['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
case_ wf-concurrency-reviewed    ok  "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ wf-concurrency-cancel-all  bad "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': 'true'}"
case_ wf-concurrency-shared-ref  bad "d['concurrency'] = {'group': \"\${{ github.workflow }}-\${{ github.ref }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ wf-concurrency-rerun-shares bad "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && format('ci-pr-{0}', github.event.pull_request.number) || format('ci-{0}-{1}', github.run_id, github.run_attempt) }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ wf-concurrency-workflow-name bad "d['concurrency'] = {'group': \"\${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('{0}-pr-{1}', github.workflow, github.event.pull_request.number) || format('{0}-{1}-{2}', github.workflow, github.run_id, github.run_attempt) }}\", 'cancel-in-progress': \"\${{ github.event_name == 'pull_request' }}\"}"
case_ job-permissions            bad "d['jobs']['allowlist']['permissions'] = {'contents': 'write'}"
case_ job-regains-a-block        bad "d['jobs']['allowlist']['permissions'] = {'contents': 'read'}"
case_ wf-permissions-gains-pr-read bad "d['permissions'] = {'contents': 'read', 'pull-requests': 'read'}"
case_ wf-permissions-gains-write bad "d['permissions'] = {'contents': 'read', 'pull-requests': 'write'}"
case_ wf-permissions-widened     bad "d['permissions'] = {'contents': 'write'}"
case_ wf-permissions-id-token    bad "d['permissions'] = {'contents': 'read', 'id-token': 'write'}"
case_ wf-permissions-removed     bad "d.pop('permissions')"
case_ wf-permissions-empty       bad "d['permissions'] = {}"
case_ runs-on-self-hosted        bad "d['jobs']['allowlist']['runs-on'] = 'self-hosted'"
case_ runs-on-list               bad "d['jobs']['allowlist']['runs-on'] = ['ubuntu-latest', 'x']"
case_ job-strategy-matrix        bad "d['jobs']['allowlist']['strategy'] = {'fail-fast': 'true'}"
case_ expression-in-comment      bad "$fe['run'] = '# \${{ fromJSON(\\'\"\\\\nexit 0\\\\n#\"\\') }}\\n' + $fe['run']"
case_ expression-in-fetch        bad "$fe['run'] = '# \${{ github.sha }}\\n' + $fe['run']"
case_fs expression-in-leg-comment  bad "$LEG['run'] = '# \${{ github.sha }}\\n' + $LEG['run']"
case_ anchor-alias-in-ci         bad "sh = {'k': 'v'}; d['jobs']['test']['x-shared'] = sh; d['jobs']['lint']['x-shared'] = sh"
case_ anchor-bomb                bad "a = ['x']; b = [a, a, a, a, a, a, a, a, a]; c = [b, b, b, b, b, b, b, b, b]; e = [c, c, c, c, c, c, c, c, c]; d['jobs']['test']['bomb'] = [e, e, e, e, e, e, e, e, e]"

for u in 00a0 3000 2028 2029; do
  case_ "unicode-space-comment-$u" bad "$fe['run'] = '\\u$u# x\\n' + $fe['run']"
  case_fs "unicode-space-in-leg-$u" bad "$LEG['run'] = '\\u$u# x\\n' + $LEG['run']"
done
case_ cr-in-fetch            bad "$fe['run'] = $fe['run'] + '\\r'"
case_ vt-in-fetch            bad "$fe['run'] = '\\x0b# x\\n' + $fe['run']"
case_ ff-in-fetch            bad "$fe['run'] = '\\x0c# x\\n' + $fe['run']"
case_ ctrl-in-fetch          bad "$fe['run'] = $fe['run'] + '\\x01'"
case_ nbsp-inside-command    bad "$fe['run'] = $fe['run'].replace(' -n ', '\\u00a0-n\\u00a0')"
case_ tab-comment-still-ok-shape bad "$fe['run'] = '\\t# note\\n' + $fe['run'] + ' || true'"

# duplicate keys can only be written as text, so these edit the YAML text of a copy
textcase() {  # textcase <name> <expect> <python expression editing the text variable t> [the workflow file, ci.yml by default; full-suite.yml is judged by fsjudge]
  local f="$work/t-$1.yml" jf=judge; cp "$here/.github/workflows/${4:-ci.yml}" "$f"; [ "${4:-ci.yml}" = ci.yml ] || jf=fsjudge
  python3 - "$f" "$3" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
t = open(p).read()
exec(edit)
open(p, "w").write(t)
PY
  if out=$($jf "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS $1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL $1 → $got, want $2 ($out)"; fi
}
textcase duplicate-run-in-counting-step bad "a = 'run: bash bin/check-file-allowlist-test.sh'; assert a in t; t = t.replace(a, a + '\\n        run: true', 1)"
textcase duplicate-name-allowlist-job  bad "t = t.replace('  allowlist:\\n    name: allowlist', '  allowlist:\\n    name: allowlist\\n    name: allowlist', 1)"
textcase duplicate-name-gate-job       bad "t = t.replace('  allowlist-chain:\\n    name: allowlist-chain', '  allowlist-chain:\\n    name: allowlist-chain\\n    name: allowlist-chain', 1)" full-suite.yml
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

# the release-only policy: the gate allowlist-chain must stay listed with integration 15368 and scope push (release admission reads it)
for mut in "drop" "scope" "integration" "null" "empty" "garbage" "dup" "notlist"; do
  python3 - "$here/.github/policy/release-only-checks.json" "$work/pol-$mut.json" "$mut" <<'PY'
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
  if out=$(PIN_WIRING_RELEASE_ONLY_FILE="$work/pol-$mut.json" judge "$here/.github/workflows/ci.yml"); then failn=$((failn+1)); echo "FAIL policy-$mut accepted"; else pass=$((pass+1)); echo "PASS policy-$mut → bad ($out)"; fi
done
# the gate is release-only: listed in required-checks.json it would be a push context that nothing produces, and admission would refuse every tag
python3 - "$here/.github/policy/required-checks.json" "$work/pol-chain-required.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["required_checks"].append({"context": "allowlist-chain", "integration_id": 15368, "scope": "push"})
json.dump(d, open(sys.argv[2], "w"))
PY
if out=$(PIN_WIRING_POLICY_FILE="$work/pol-chain-required.json" judge "$here/.github/workflows/ci.yml"); then failn=$((failn+1)); echo "FAIL policy-gate-also-required accepted"; else pass=$((pass+1)); echo "PASS policy-gate-also-required → bad ($out)"; fi

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
gvgate_mut "install-and-copy" 'bash bin/install-scanner.sh govulncheck' 'bash bin/install-scanner.sh govulncheck && cp /bin/true ~/go/bin/govulncheck'
gvgate_mut "planted-binary-step" '      - name: govulncheck (the same judgment as Check)' '      - name: plant
        run: cp /bin/true /usr/local/bin/fscache-go/bin/govulncheck
      - name: govulncheck (the same judgment as Check)'

echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
