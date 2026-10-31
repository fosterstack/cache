#!/usr/bin/env bash
# proves: REQ-SCAN-015-AC2 — the scanner guard step is required, exactly, in the allowlist job (the scanguard cases)
# REQ-REL-005-AC1 (register row 78): the hygiene check runs the pin checker on every pull request and
# every push to main, and nothing can skip it or swallow its failure. (Mapped from the product matrix as
# workflow-job evidence: REQ-AUD-18 AC1 keeps .github/agent/ paths out of files outside it.)
# The real ci.yml must pass; each mutated copy must be caught.
# Known limit (by design): later steps of the CI allowlist job can edit the pin checker or this test on disk;
# the trusted gate (.github/workflows/agent-review-gate.yml) re-runs main's copies of all of them over the PR head.
set -euo pipefail
here=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

# The chain's 25 suite steps (REQ-CHAIN-001..003 and the suites that followed), exactly as they stand in allowlist-chain on the release-chain branch. The judge below
# accepts the allowlist-chain job in EXACTLY TWO forms: main's own steps, or main's steps followed by these 25, each exact and in order (the transition judge,
# cache#508's landing: the strict single form arrives with the landing and replaces this file). The cases read the same data.
read -r -d '' PIN_WIRING_CHAIN25 <<'JSON' || true
[
 {
  "name": "suite guard (no tracked test file is empty; the guard's own regressions)",
  "run": "bash bin/suite-guard.sh files && bash bin/suite-guard-test.sh"
 },
 {
  "env": {
   "BASE": "${{ github.base_ref }}"
  },
  "if": "${{ github.base_ref != '' }}",
  "name": "suite floors only rise (against the merge base on a pull request)",
  "run": "bash bin/suite-guard.sh floors-vs-base \"$(git merge-base HEAD \"origin/${BASE}\")\" test-evidence/suite-floors.json"
 },
 {
  "name": "same-day reuse of Amazon Inspector results \u2014 keyed by the SBOM's package inventory, reuse on a match, a fresh call on each way it differs (REQ-REL-004 AC5)",
  "run": "bash bin/inspector-reuse-test.sh"
 },
 {
  "name": "the release chain verifier: identities, timestamps, Rekor, digests, action pins (REQ-CHAIN-001..003)",
  "run": "CHAIN_TEST_REQUIRE_NETCUT=1 bash bin/chain-verify-test.sh"
 },
 {
  "name": "the release chain's hostile dry run, judged offline (REQ-CHAIN-001-AC5)",
  "run": "bash bin/chain-hostile-test.sh"
 },
 {
  "name": "the Sign boundary's wiring: one Sign file, the closed stage grammar, no secrets (REQ-CHAIN-001, 002-AC4, 003-AC5)",
  "run": "bash bin/chain-sign-wiring-test.sh"
 },
 {
  "name": "the release chain's record types: one row, claim and consumer per signed type (REQ-CHAIN-003-AC3)",
  "run": "bash bin/chain-records-test.sh"
 },
 {
  "name": "Build's wiring: the exact stage grammar, the scripts' behaviour, the snapshot callers, the graph (REQ-CHAIN-004, 005; red on 005-AC5 until PRs 3 and 4)",
  "run": "bash bin/chain-build-wiring-test.sh"
 },
 {
  "name": "the final image index that carries our OpenVEX for Docker Scout: the tool and its sidecar, offline (REQ-REL-010-AC1, AC3)",
  "run": "bash bin/vex-index-test.sh </dev/null"
 },
 {
  "name": "Build's admission: every check of the former admission stage, with a counterpart (REQ-CHAIN-004-AC4, AC5)",
  "run": "bash bin/chain-build-admit-test.sh"
 },
 {
  "name": "the files a stage binds and the items it writes (REQ-CHAIN-004-AC3, AC8, AC9; REQ-CHAIN-005-AC1)",
  "run": "bash bin/chain-bind-test.sh"
 },
 {
  "name": "Rebuild's comparison of every item (REQ-CHAIN-005-AC3)",
  "run": "bash bin/chain-rebuild-test.sh"
 },
 {
  "name": "snapshot records and versions are refused by every verifier (REQ-CHAIN-004-AC13, AC15)",
  "run": "bash bin/chain-snapshot-test.sh"
 },
 {
  "name": "the pinned Witness install (REQ-CHAIN-004-AC2, REQ-CHAIN-005-AC1)",
  "run": "bash bin/chain-install-witness-test.sh"
 },
 {
  "name": "Check's scripts: scan, FIPS, artifacts, guide, dispatcher, helper (REQ-CHAIN-006-AC3..AC7, AC9, AC11, AC12, AC15..AC17; REQ-PLAT-001-AC1)",
  "run": "bash bin/chain-check-scripts-test.sh"
 },
 {
  "name": "Check's wiring: the stage grammar, the arm64 job, the dispatcher, the graph (REQ-CHAIN-006-AC1..AC3, AC8..AC14, AC17; red on the guide until cache-3f, known-red.json)",
  "run": "bash bin/chain-check-wiring-test.sh"
 },
 {
  "name": "the customer verification guide: length, commands, coverage, cannot-run list (REQ-GUIDE-001-AC1..AC7)",
  "run": "bash bin/verify-release-guide-test.sh </dev/null"
 },
 {
  "name": "the pinned crane install (REQ-CHAIN-007-AC7)",
  "run": "bash bin/chain-install-crane-test.sh"
 },
 {
  "name": "Release's wiring: the stage grammar, credentials, graph, verify order, release candidates, named records (REQ-CHAIN-007)",
  "run": "bash bin/chain-release-wiring-test.sh"
 },
 {
  "name": "Release's scripts: verify, apks, publish, sign, assets, post-publish verification (REQ-CHAIN-007, REQ-REL-009-AC11, REQ-CHAIN-006-AC7)",
  "run": "bash bin/chain-release-scripts-test.sh"
 },
 {
  "name": "Release's metadata: the vex-forms input, the manifest, release-files.sha256 and the coverage gate (REQ-CHAIN-007-AC19)",
  "run": "bash bin/chain-release-metadata-test.sh"
 },
 {
  "name": "the customer guide \u2014 every scanner's file, check and exact command, no competitor named (scanner-panel rule 11)",
  "run": "bash bin/vex-guide-test.sh"
 },
 {
  "name": "the live test's plan, test copy, fixture and wiring, offline (scanner-panel rule 12)",
  "run": "bash bin/vex-live-test-test.sh"
 },
 {
  "name": "the live test's page and orchestrator are read by the action-pin checker (scanner-panel rule 12)",
  "run": "bash .github/agent/tests/vex-live-pins-test.sh"
 },
 {
  "env": {
   "CHAIN_TEST_REQUIRE_NETCUT": "1"
  },
  "name": "every suite runs at or above its committed floor (real counts)",
  "run": "python3 -I bin/suite-guard-run.py all --count-only test-evidence/suite-floors.json ."
 }
]
JSON
export PIN_WIRING_CHAIN25

judge() { PIN_WIRING_WORKFLOWS_DIR="${PIN_WIRING_WORKFLOWS_DIR:-$here/.github/workflows}" PIN_WIRING_POLICY_FILE="${PIN_WIRING_POLICY_FILE:-$here/.github/policy/required-checks.json}" python3 - "$1" <<'PY'
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
# the only triggers ci.yml may have: push (main), pull_request and merge_group (the merge queue). workflow_call and workflow_dispatch are refused: a called or dispatched run
# would carry another context into the reviewed concurrency group.
if isinstance(on, dict) and sorted(set(on) - {"push", "pull_request", "merge_group"}):
    bad.append("ci.yml has triggers beyond push, pull_request and merge_group: " + ", ".join(sorted(set(on) - {"push", "pull_request", "merge_group"})))
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
want = {"bash .github/agent/tests/check-action-pins-test.sh", "python3 .github/agent/bin/check-action-pins.py --verify-tags .",
        "bash .github/agent/tests/pin-wiring-test.sh"}  # this test's own step, too
seen = set()
for st in job.get("steps", []):
    run = (st.get("run") or "").strip()
    if run in want:
        seen.add(run)
        for k in ("if", "continue-on-error", "shell", "working-directory") + (("env",) if run == "bash .github/agent/tests/check-action-pins-test.sh" else ()):   # env on the cases step: the PINS_* controls (shard, dry, serial, self, jobs) are never set from the workflow
            if k in st:
                bad.append(f"the step `{run}` has `{k}`")
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
# the two steps whose env is judged exactly below are exempt from the name list (BASE, GITHUB_HEAD_REPO)
for where, env in [("the workflow", d.get("env")), ("the allowlist job", job.get("env"))] + \
        [(f"step {i}", st.get("env")) for i, st in enumerate(steps_all)]:
    if isinstance(env, dict):
        for k in sorted(k for k in env if is_risky(k)):
            if where == "step 2" and k == "GITHUB_HEAD_REPO":
                continue
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
# the whole-tree allowlist guard (bin/check-file-allowlist.sh) cannot be disabled by the PR that changes
# this workflow: the job is named `allowlist` (the required-check context), the checkout is full-depth and
# first, then exactly the base-ref step and exactly the check step, in that order, nothing redirecting them
if job.get("name") != "allowlist":
    bad.append("the allowlist job is not named `allowlist` (the required-check context)")
FETCH_RUN = """if [ -n "${BASE}" ]; then
  [[ "${BASE}" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1
  [[ "${BASE}" != *..* ]] || exit 1
  git fetch --no-tags origin "+refs/heads/${BASE}:refs/remotes/origin/${BASE}"
fi"""
CHECK_RUN = "git ls-files | ./bin/check-file-allowlist.sh"
def norm(r):  # drop comment lines; the command text itself must match exactly. A comment line is one whose first
    # character after ONLY spaces and tabs is `#` (bash's rule; Python's str.strip/lstrip/splitlines also
    # treat U+00A0, U+3000, U+2028 ... as whitespace or line ends, which bash does not)
    return "\n".join(l for l in (r or "").strip(" \t\n").split("\n") if not l.lstrip(" \t").startswith("#"))
def odd_chars(r):  # anything but printable ASCII, tab and newline in a protected run string
    return sorted({hex(ord(c)) for c in (r or "") if not (c in "\t\n" or " " <= c <= "~")})
steps_ = job.get("steps", [])
for i, st in enumerate(steps_):
    if i in (1, 2) or "check-file-allowlist.sh" in (st.get("run") or "") or "git fetch" in (st.get("run") or ""):
        if odd_chars(st.get("run")):
            bad.append(f"a protected allowlist step's run text has non-ASCII or control characters {odd_chars(st.get('run'))}")
for st in steps_:
    if norm(st.get("run")) in (FETCH_RUN, CHECK_RUN) or "check-file-allowlist.sh" in (st.get("run") or "") or "git fetch" in (st.get("run") or ""):
        if "${{" in (st.get("run") or ""):   # raw text, comment lines included: an expression is rendered before bash sees it
            bad.append("a protected allowlist step's run text contains a `${{` expression")
plain = ("if", "continue-on-error", "shell", "working-directory", "timeout-minutes")
idx = {"fetch": [i for i, st in enumerate(steps_) if norm(st.get("run")) == FETCH_RUN],
       "check": [i for i, st in enumerate(steps_) if norm(st.get("run")) == CHECK_RUN]}
co = [i for i, st in enumerate(steps_) if str(st.get("uses", "")).startswith("actions/checkout@")]
if not co or co[0] != 0:
    bad.append("the allowlist job does not start with the checkout")
else:
    if steps_[0].get("with") != {"fetch-depth": "0"}:
        bad.append("the allowlist checkout is not exactly `fetch-depth: 0`")
    for k in plain + ("env",):
        if k in steps_[0]:
            bad.append(f"the allowlist checkout has `{k}`")
for name, want_env in (("fetch", {"BASE": "${{ github.base_ref }}"}),
                       ("check", {"GITHUB_HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}"})):
    if len(idx[name]) != 1:
        bad.append(f"the allowlist job does not have exactly one {name} step with the exact command")
        continue
    st = steps_[idx[name][0]]
    if st.get("env") != want_env:
        bad.append(f"the allowlist {name} step env is not exactly {want_env}")
    for k in plain:
        if k in st:
            bad.append(f"the allowlist {name} step has `{k}`")
if idx["fetch"] != [1] or idx["check"] != [2]:
    bad.append("the allowlist job's first three steps are not exactly: checkout, base-ref fetch, check (nothing before or between)")
for w in sorted(want - seen):
    bad.append(f"no step runs `{w}`")
# REQ-SCAN-015-AC2: exactly one step runs the scanner guard, and it is exactly this name and run and nothing else
# (no if, continue-on-error, env, shell, working-directory, timeout); its place after the PyYAML install is not
# judged, since the guard run without PyYAML fails, which is red, not a bypass
SCAN_STEP = {"name": "scan.yml and main-candidate-rescan.yml are never callable as reusable workflows (REQ-SCAN-015-AC1)",
             "run": "bash bin/scan-no-workflow-call-test.sh"}
sg = [st for st in steps_ if "scan-no-workflow-call-test.sh" in json.dumps(st)]
if len(sg) != 1:
    bad.append(f"the allowlist job has {len(sg)} scanner guard steps, not exactly one (REQ-SCAN-015-AC2)")
elif sg[0] != SCAN_STEP:
    bad.append(f"the scanner guard step is not exactly {SCAN_STEP} (REQ-SCAN-015-AC2)")
# The three jobs that took the slow suites out of `allowlist` (cache#499; REQ-SCAN-015-AC2's reasoning applies to each: a required job that is skipped,
# or whose step is skipped, disabled through its environment, or whose failure is ignored, passes while the suites never ran). Each is exactly
# name / runs-on / steps, named as its id, on ubuntu-latest, and its steps are EXACTLY the list below (name, uses, with, env and run text, in order):
# a suite cannot be deleted, edited, wrapped (|| true), reordered or given an environment (BASH_ENV, SHELLOPTS ...) without this judge, which a PR
# cannot change for itself (the gate runs main's copy), being changed first. Adding a suite to a split job means adding its step here.
def _by_shape(st):
    """A step with `uses: name@<full 40-hex commit>` stands for every digest of
    that action: the digest VALUE is judged by
    check-action-pins --verify-tags, pin-age and the daily audit (a Dependabot bump moves it), not by these lists. The
    action name and the exact shape of the ref (40 lower-case hex) stay compared."""
    u = st.get("uses")
    if isinstance(u, str) and u.count("@") == 1:
        name, _, ref = u.partition("@")
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return dict(st, uses=name + "@<commit>")
    return st


SPLIT_STEPS = json.loads(r'''{
 "allowlist-chain": [
  {
   "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
   "with": {
    "fetch-depth": "0"
   }
  },
  {
   "env": {
    "BASE": "${{ github.base_ref }}"
   },
   "name": "make sure the base branch ref exists",
   "run": "if [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi\n"
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
   "name": "build helper tools regressions (apk tool, recipe generator, lock tool, module SBOM)",
   "run": "bash bin/build-helpers-test.sh"
  },
  {
   "name": "vendor check regressions (REQ-VEND-001-AC2, AC3, AC11)",
   "run": "bash bin/vendoring-test.sh </dev/null"
  },
  {
   "name": "apk build driver and release signing regressions",
   "run": "bash bin/build-apk-test.sh"
  },
  {
   "name": "input refresh script regressions",
   "run": "bash bin/refresh-inputs-test.sh"
  },
  {
   "name": "archive push, pull and verify regressions",
   "run": "bash bin/archive-test.sh"
  },
  {
   "name": "the committed melange recipes are exactly the generator's output from build/melange.yaml.tmpl (REQ-BUILDTOOLS-001-AC5)",
   "run": "python3 bin/gen-recipes.py --check"
  },
  {
   "name": "vendored tree and provenance regressions (REQ-VEND-001-AC1, AC4-AC14)",
   "run": "bash bin/vendor-provenance-test.sh </dev/null"
  },
  {
   "name": "image assembly, lock proof and sealed proof regressions",
   "run": "bash bin/assemble-image-test.sh"
  },
  {
   "name": "privacy candidate-trace analyzer regressions (B03)",
   "run": "bash bin/analyze-egress-trace-test.sh"
  },
  {
   "name": "scanner installer failure-path regressions (pinned-checksum contract)",
   "run": "bash bin/install-scanner-test.sh"
  },
  {
   "name": "PR-gate image verdict regressions (row 57 \u2014 counts, did-not-run, VEX coverage)",
   "run": "bash bin/inspector-gate-test.sh"
  },
  {
   "name": "VEX product-scope regressions (audit R01 \u2014 exception bound to the FosterStack product)",
   "run": "./bin/install-scanner.sh grype\nbash bin/vex-scope-test.sh\n"
  },
  {
   "name": "VEX applied by both gate scanners (REQ-REL-004-AC1 \u2014 covered suppressed, uncovered blocks, zero packages fails)",
   "run": "bash bin/vex-both-scanners-test.sh"
  },
  {
   "name": "our VEX in three forms \u2014 the same statements, generated before the signed manifest (scanner-panel rule 10)",
   "run": "bash bin/vex-forms-test.sh"
  },
  {
   "name": "the Docker Scout root-cause round's documents, matrix and judge (advisor 0120/0122)",
   "run": "bash bin/scout-root-cause-test.sh"
  },
  {
   "name": "the Docker Scout older-versions sweep (advisor 0520) \u2014 table logic with docker stubbed, installer pins, dispatch-only job",
   "run": "bash bin/scout-older-versions-test.sh"
  },
  {
   "name": "Go-bump PR recovery regressions (audit R03 \u2014 orphaned branch / closed-merged)",
   "run": "bash bin/go-bump-open-pr-test.sh"
  }
 ],
 "allowlist-persona": [
  {
   "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
   "with": {
    "fetch-depth": "0"
   }
  },
  {
   "env": {
    "BASE": "${{ github.base_ref }}"
   },
   "name": "make sure the base branch ref exists",
   "run": "if [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi\n"
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
   "name": "persona UAT \u2014 agent and provider suite",
   "run": "bash bin/persona-uat-agent-test.sh"
  },
  {
   "name": "persona UAT \u2014 wiring suite (workflows, tools file, installer, identity refresher)",
   "run": "bash bin/persona-uat-wiring-test.sh"
  },
  {
   "name": "persona UAT \u2014 driver suite",
   "run": "bash bin/persona-uat-test.sh"
  }
 ],
 "allowlist-pins-auditor": [
  {
   "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
   "with": {
    "fetch-depth": "0"
   }
  },
  {
   "env": {
    "BASE": "${{ github.base_ref }}"
   },
   "name": "make sure the base branch ref exists",
   "run": "if [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi\n"
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
   "name": "Dependabot reviewer regressions (row 75 \u2014 updates parsing, findings validation, mechanical decision)",
   "run": "bash bin/dependabot-reviewer-test.sh"
  },
  {
   "name": "dependency lanes wiring \u2014 reviewer hourly from main, guard on every PR/push, patch/minor lane after the guard (rows 75, 80)",
   "run": "bash bin/dependency-lanes-test.sh"
  },
  {
   "name": "the Dependabot reviewer's bundle carries the diff, every in-range release note and our usage (row 75 b)",
   "run": "bash bin/dependabot-reviewer-gather-test.sh"
  },
  {
   "name": "the scanner panel's judge \u2014 counts and quorum, the VEX, seen by N of M, unique findings audited (scanner-panel rules 3-9)",
   "run": "bash bin/panel-test.sh"
  },
  {
   "name": "the final image index that carries our OpenVEX for Docker Scout \u2014 the tool and its sidecar, offline (REQ-REL-010-AC1, AC3)",
   "run": "bash bin/vex-index-test.sh </dev/null"
  },
  {
   "name": "the auditor's fixtures and tests follow the panel's image set \u2014 the unit and matrix suites pass with VARIANTS both ways (main's six images, chain-v030's four)",
   "run": "bash .github/agent/tests/auditor-variants-test.sh"
  },
  {
   "name": "the automatic patch-release decision \u2014 fix-class commits, next patch, one a day, notes, floating tags (owner Oct 2)",
   "run": "bash bin/patch-decide-test.sh"
  },
  {
   "name": "gate 6 of the release process \u2014 a pull request into main needs a passed-audit record for its exact head (REQ-REL-012, owner Oct 23)",
   "run": "bash bin/audit-record-test.sh"
  },
  {
   "name": "admission's tag signer \u2014 the owner's SSH key on any tag, the release workflow's keyless identity on patch tags only (owner Oct 2)",
   "run": "bash bin/admission-tag-signer-test.sh"
  },
  {
   "name": "release.yml's automatic patch wiring \u2014 decide on main only, keyless gitsign, the App pushes, failures open an issue (owner Oct 2)",
   "run": "bash bin/release-patch-wiring-test.sh"
  },
  {
   "name": "the Maven capped scenario recognises the server's 413 in either resolver wording (REQ-EVICT-002-AC4)",
   "run": "bash bin/acceptance-maven-413-test.sh"
  },
  {
   "name": "release.yml's notes commit runs exactly the committed signed-commit CLI (advisor 0210; the literal path is judged under .github/agent/)",
   "run": "bash .github/agent/tests/release-notes-signed-test.sh"
  },
  {
   "name": "go-freshness opens its bump PR with the auditor App's token, read-only otherwise (owner, Oct 2)",
   "run": "bash bin/go-freshness-wiring-test.sh"
  },
  {
   "name": "the ratified workflow consolidation (mutation runs weekly inside go-freshness; owner Oct 2)",
   "run": "bash bin/workflow-consolidation-test.sh"
  },
  {
   "name": "a job that holds a credential never builds, each build its own job, govulncheck handed to the audit job by digest (REQ-REL-011; owner Oct 21)",
   "run": "bash bin/job-isolation-test.sh"
  },
  {
   "name": "the daily rescan covers the current release only (REQ-REL-004-AC5)",
   "run": "bash bin/rescan-current-only-test.sh"
  },
  {
   "name": "the scanner panel's wiring \u2014 which scanner on which image, Google by federation, the VEX the only exception (rules 1, 2, 4, 9)",
   "run": "bash bin/panel-wiring-test.sh"
  },
  {
   "name": "the k8s acceptance harness's fenced exclusion \u2014 its two generated scripts come only from docs/kubernetes.md (advisor 0084)",
   "run": "bash .github/agent/tests/k8s-harness-fence-test.sh"
  },
  {
   "name": "the pin age check \u2014 7 days by a server-side time, named per moved version (REQ-SUP-001 AC2, AC3)",
   "run": "bash .github/agent/tests/pin-age-check-test.sh"
  },
  {
   "name": "the daily supply-chain audit \u2014 advisories, upstream, disputed hits with checked-in exceptions, held-PR re-runs (REQ-SUP-001 AC5-AC10)",
   "run": "bash .github/agent/tests/pin-audit-test.sh"
  },
  {
   "name": "where the supply-chain checks run \u2014 Dependabot cooldown, the PR job's read-only token, one writer per job (REQ-SUP-001 AC1, AC4, AC6)",
   "run": "bash .github/agent/tests/supply-chain-wiring-test.sh"
  }
 ]
}''')
GATE6_NAME = "gate 6 of the release process \u2014 a pull request into main needs a passed-audit record for its exact head (REQ-REL-012, owner Oct 23)"
for jid, want_steps in SPLIT_STEPS.items():
    sj = d.get("jobs", {}).get(jid)
    if not isinstance(sj, dict):
        bad.append(f"the job {jid} is missing")
        continue
    for k in sorted(set(sj) - {"name", "runs-on", "steps"}):
        bad.append(f"the {jid} job has `{k}`")
    if sj.get("name") != jid:
        bad.append(f"the {jid} job is not named `{jid}` (the required-check context)")
    if sj.get("runs-on") != "ubuntu-latest":
        bad.append(f"the {jid} job does not run on exactly `ubuntu-latest`")
    got = sj.get("steps", [])
    accepted = [want_steps]
    if jid == "allowlist-chain":      # the transition: the second exact form carries the chain's 25 suites (nothing between, nothing after)
        accepted.append(want_steps + json.loads(os.environ["PIN_WIRING_CHAIN25"]))
    if jid == "allowlist-pins-auditor":   # the transition (cache#669's landing): exactly main's list, or it plus the gate-6 step once, right after patch-decide
        _gi = [k for k, x in enumerate(want_steps) if x.get("run") == "bash bin/patch-decide-test.sh"]
        if len(_gi) == 1 and not any(x.get("run") == "bash bin/audit-record-test.sh" for x in want_steps):
            accepted.append(want_steps[:_gi[0] + 1] + [{"name": GATE6_NAME, "run": "bash bin/audit-record-test.sh"}] + want_steps[_gi[0] + 1:])
    if [_by_shape(st) for st in got] not in [[_by_shape(st) for st in a] for a in accepted]:
        have = [st.get("name") or st.get("uses") for st in got]
        want_n = [st.get("name") or st.get("uses") for st in want_steps]
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
# the required-check policy (release admission reads it): a readable JSON object whose required_checks is a list of objects with unique contexts,
# and exactly one correct entry (integration 15368, scope push) for each protected job. Anything unreadable or malformed is refused (fail closed).
PROTECTED = ("allowlist",) + tuple(SPLIT_STEPS)
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
# the four protected check names belong to their jobs alone: no other job of this workflow may produce a check run with such a name (a job named
# `allowlist-persona` that succeeds after the real one failed satisfies admission, which accepts any success with the matching name), and no job
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

# judge mode, for the trusted review gate: judge the ci.yml of one commit of the current repo, read as a git
# object (never checked out, never run), and nothing else
if [ -n "${PIN_WIRING_JUDGE_GIT:-}" ]; then
  git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/ci.yml" > "$work/head-ci.yml" || { echo "pin-wiring: no ci.yml at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  git show "${PIN_WIRING_JUDGE_GIT}:.github/policy/required-checks.json" > "$work/head-policy.json" || { echo "pin-wiring: no required-checks.json at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  mkdir -p "$work/head-wf"
  for wf in $(git ls-tree --name-only "${PIN_WIRING_JUDGE_GIT}" .github/workflows/ | sed 's|.*/||'); do   # every workflow of the commit, as git objects
    git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/$wf" > "$work/head-wf/$wf" || { echo "pin-wiring: cannot read workflow $wf" >&2; exit 1; }
  done
  # Two exact forms are accepted: main's own (judged here) or the landing form, chain-v030's ci.yml, judged by
  # pin-wiring-landing.sh in the same mode over the same commit. A head that fits neither is refused with both findings.
  export PIN_WIRING_WORKFLOWS_DIR="$work/head-wf" PIN_WIRING_POLICY_FILE="$work/head-policy.json"
  if main_out=$(judge "$work/head-ci.yml"); then exit 0; fi
  landing="$here/.github/agent/tests/pin-wiring-landing.sh"
  [ -f "$landing" ] || { printf '%s\nno landing judge at %s\n' "$main_out" "$landing"; exit 1; }
  if land_out=$(bash "$landing" 2>&1); then exit 0; fi
  printf '%s\nthe landing form also refuses it: %s\n' "$main_out" "$land_out"
  exit 1
fi

case_() {  # case_ <name> <expect ok|bad> <python edit of the parsed copy, or empty>
  local f="$work/$1.yml"
  cp "$here/.github/workflows/ci.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
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
pick='[s for s in '"$steps"' if (s.get("run") or "").startswith("python3 .github/agent/bin/check-action-pins.py")][0]'
case_ the-real-hygiene      ok  ""
case_ step-removed          bad "$steps[:] = [s for s in $steps if not (s.get('run') or '').startswith('python3 .github/agent/bin/check-action-pins.py')]"
case_ step-if-false         bad "$pick['if'] = 'false'"
case_ step-continue         bad "$pick['continue-on-error'] = 'true'"
case_ step-weakened         bad "$pick['run'] = 'python3 .github/agent/bin/check-action-pins.py . || true'"
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
case_ wiring-step-removed   bad "$steps[:] = [s for s in $steps if (s.get('run') or '').strip() != 'bash .github/agent/tests/pin-wiring-test.sh']"
case_ bash-env-on-step      bad "$pick['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ bash-env-on-job       bad "d['jobs']['allowlist']['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ path-on-workflow      bad "d['env'] = {'PATH': '/tmp/fake:/usr/bin'}"
case_ github-env-write      bad "$steps.insert(1, {'run': 'echo BASH_ENV=/tmp/x.sh >> \"\$GITHUB_ENV\"'})"
case_ github-path-write     bad "$steps.insert(1, {'run': 'echo /tmp/fake >> \"\$GITHUB_PATH\"'})"
case_ checkout-other-ref    bad "$steps[0]['with'] = {'ref': 'main'}"
case_ cases-step-env        bad "[s.__setitem__('env', {'PINS_DRY': '1'}) for s in $steps if (s.get('run') or '').strip() == 'bash .github/agent/tests/check-action-pins-test.sh']"
case_ cases-step-env-self   bad "[s.__setitem__('env', {'PINS_SELF': '/bin/true'}) for s in $steps if (s.get('run') or '').strip() == 'bash .github/agent/tests/check-action-pins-test.sh']"
case_ cases-step-removed    bad "$steps[:] = [s for s in $steps if (s.get('run') or '').strip() != 'bash .github/agent/tests/check-action-pins-test.sh']"

ck='[s for s in '"$steps"' if (s.get("run") or "").strip().endswith("check-file-allowlist.sh")][0]'
fe='[s for s in '"$steps"' if "git fetch" in (s.get("run") or "")][0]'
case_ allowlist-check-removed   bad "$steps[:] = [s for s in $steps if not (s.get('run') or '').strip().endswith('check-file-allowlist.sh')]"
case_ allowlist-run-true        bad "$ck['run'] = 'true'"
case_ allowlist-or-true         bad "$ck['run'] = 'git ls-files | ./bin/check-file-allowlist.sh || true'"
case_ allowlist-if-false        bad "$ck['if'] = 'false'"
case_ allowlist-continue        bad "$ck['continue-on-error'] = 'true'"
case_ allowlist-shell-override  bad "$ck['shell'] = \"bash -c 'true' {0}\""
case_ allowlist-workdir         bad "$ck['working-directory'] = 'bin'"
case_ allowlist-env-removed     bad "$ck.pop('env')"
case_ allowlist-env-changed     bad "$ck['env'] = {'GITHUB_HEAD_REPO': ''}"
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

case_ insert-update-index-step  bad "$steps.insert(2, {'run': 'git update-index --force-remove -- .snyk'})"
case_ insert-update-ref-step    bad "$steps.insert(2, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
case_ insert-update-ref-first   bad "$steps.insert(1, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
case_ insert-script-overwrite   bad "$steps.insert(2, {'run': 'echo true > bin/check-file-allowlist.sh'})"
case_ insert-step-before-checkout bad "$steps.insert(0, {'run': 'true'})"
case_ job-env-shellopts         bad "d['jobs']['allowlist']['env'] = {'SHELLOPTS': 'noexec'}"
case_ wf-env-shellopts          bad "d['env'] = {'SHELLOPTS': 'noexec'}"
case_ step-env-shellopts        bad "$steps[3]['env'] = {'SHELLOPTS': 'noexec'}"
case_ job-env-head-ref          bad "d['jobs']['allowlist']['env'] = {'GITHUB_HEAD_REF': 'auditor/x'}"
case_ wf-env-head-ref           bad "d['env'] = {'GITHUB_HEAD_REF': 'auditor/x'}"
case_ step-env-head-ref         bad "$steps[2]['env']['GITHUB_HEAD_REF'] = 'auditor/x'"
case_ job-env-repository        bad "d['jobs']['allowlist']['env'] = {'GITHUB_REPOSITORY': 'x/y'}"
case_ wf-env-repository         bad "d['env'] = {'GITHUB_REPOSITORY': 'x/y'}"
case_ step-env-repository       bad "$steps[2]['env']['GITHUB_REPOSITORY'] = 'x/y'"
case_ job-env-index-file        bad "d['jobs']['allowlist']['env'] = {'GIT_INDEX_FILE': '/tmp/i'}"
case_ wf-env-index-file         bad "d['env'] = {'GIT_INDEX_FILE': '/tmp/i'}"
case_ step-env-index-file       bad "$steps[2]['env']['GIT_INDEX_FILE'] = '/tmp/i'"
case_ fetch-env-git-dir         bad "$steps[1]['env']['GIT_DIR'] = '/tmp/g'"
case_ job-container             bad "d['jobs']['allowlist']['container'] = 'debian:12'"
case_ job-services              bad "d['jobs']['allowlist']['services'] = {'x': {'image': 'y'}}"
case_ job-strategy              bad "d['jobs']['allowlist']['strategy'] = {'matrix': {'a': ['1']}}"
case_ job-defaults-run          bad "d['jobs']['allowlist']['defaults'] = {'run': {'working-directory': 'bin'}}"
case_ ps4-ifs-prompt            bad "d['jobs']['allowlist']['env'] = {'IFS': 'x'}"
case_ ld-preload-step           bad "$steps[4]['env'] = {'LD_PRELOAD': '/tmp/x.so'}"

# judge mode (the trusted gate, .github/workflows/agent-review-gate.yml): PIN_WIRING_JUDGE_GIT=<commit> judges THAT
# commit's .github/workflows/ci.yml, read as a git object from the current repo (nothing checked out or run), and
# does nothing else; exit 1 and the reasons when it fails
gitcase() {  # gitcase <name> <expect ok|bad> <python edit or empty>
  local r="$work/git-$1"; rm -rf "$r"; mkdir -p "$r/.github/workflows"
  cp "$here/.github/workflows/ci.yml" "$r/.github/workflows/ci.yml"
  mkdir -p "$r/.github/policy"; cp "$here/.github/policy/required-checks.json" "$r/.github/policy/required-checks.json"
  cp "$here"/.github/workflows/*.y*ml "$r/.github/workflows/" 2>/dev/null || true; cp "$here/.github/workflows/ci.yml" "$r/.github/workflows/ci.yml"
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
# the policy at the commit is read too: a missing split entry is refused (and so is a missing file, above)

gitcase run-true-at-a-commit      bad "[s for s in $steps if (s.get('run') or '').strip().endswith('check-file-allowlist.sh')][0]['run'] = 'true'"
gitcase inserted-step-at-a-commit bad "$steps.insert(2, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
gitcase fetch-depth-at-a-commit   bad "$steps[0].pop('with')"

case_ job-needs-skipped          bad "d['jobs']['skip_guard'] = {'runs-on': 'ubuntu-latest', 'if': 'false', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist']['needs'] = 'skip_guard'"
case_ split-job-if            bad "d['jobs']['allowlist-chain']['if'] = 'false'"
case_ split-job-missing       bad "d['jobs'].pop('allowlist-persona')"
case_ split-job-renamed       bad "d['jobs']['allowlist-pins-auditor']['name'] = 'pins'"
case_ split-job-needs         bad "d['jobs']['allowlist-chain']['needs'] = ['lint']"
case_ split-job-runs-on       bad "d['jobs']['allowlist-persona']['runs-on'] = 'self-hosted'"
case_ split-job-continue      bad "d['jobs']['allowlist-chain']['steps'][-1]['continue-on-error'] = 'true'"
case_ split-step-if           bad "d['jobs']['allowlist-persona']['steps'][-1]['if'] = 'false'"
case_ split-step-shell        bad "d['jobs']['allowlist-pins-auditor']['steps'][-2]['shell'] = 'bash -c true {0}'"
case_ split-anchor-gone       bad "st = d['jobs']['allowlist-chain']['steps']; st[:] = [x for x in st if 'assemble-image-test' not in (x.get('run') or '')]"
case_ split-no-checkout       bad "d['jobs']['allowlist-persona']['steps'].pop(0)"
case_ split-job-env           bad "d['jobs']['allowlist-chain']['env'] = {'X': '1'}"
case_ split-env-bash-env      bad "d['jobs']['allowlist-chain']['steps'][-1]['env'] = {'BASH_ENV': '/tmp/x'}"
case_ split-env-shellopts     bad "d['jobs']['allowlist-persona']['steps'][-1]['env'] = {'SHELLOPTS': 'noexec'}"
case_ split-suite-deleted     bad "st = d['jobs']['allowlist-persona']['steps']; st[:] = [x for x in st if 'persona-uat-agent-test' not in (x.get('run') or '')]"
case_ split-suite-or-true     bad "x = [x for x in d['jobs']['allowlist-persona']['steps'] if 'persona-uat-agent-test' in (x.get('run') or '')][0]; x['run'] += ' || true'"
case_ split-suite-reordered   bad "st = d['jobs']['allowlist-chain']['steps']; st[-1], st[-2] = st[-2], st[-1]"
case_ split-suite-added       bad "d['jobs']['allowlist-chain']['steps'].append({'name': 'x', 'run': 'true'})"
# The transition judge (cache#508's landing): allowlist-chain is accepted in EXACTLY two forms, main's steps, or main's steps + the chain's 25 suites (the data of
# PIN_WIRING_CHAIN25), each exact and in order. Every other shape is refused.
C25="import os, json; c25 = json.loads(os.environ['PIN_WIRING_CHAIN25']); cs = d['jobs']['allowlist-chain']['steps']; "
case_ chain25-form-accepted        ok  "${C25}cs.extend(c25)"
case_ chain25-last-missing         bad "${C25}cs.extend(c25[:-1])"
case_ chain25-first-missing        bad "${C25}cs.extend(c25[1:])"
case_ chain25-half                 bad "${C25}cs.extend(c25[:12])"
case_ chain25-one-extra            bad "${C25}cs.extend(c25); cs.append({'name': 'x', 'run': 'true'})"
case_ chain25-twice                bad "${C25}cs.extend(c25); cs.extend(c25)"
case_ chain25-swapped-first-two    bad "${C25}cs.extend(c25[1::-1] + c25[2:])"
case_ chain25-reversed             bad "${C25}cs.extend(reversed(c25))"
case_ chain25-before-main-steps    bad "${C25}cs[:] = c25 + cs"
case_ chain25-inserted-in-middle   bad "${C25}cs[10:10] = c25"
case_ chain25-one-moved-to-allowlist bad "${C25}cs.extend(c25[1:]); d['jobs']['allowlist']['steps'].append(c25[0])"
# the first form (main's own 22 steps in allowlist-chain) with the suites elsewhere: allowlist is not an exact list (the release-chain branch's form before its move)
case_ chain25-first-form-suites-in-allowlist ok "${C25}d['jobs']['allowlist']['steps'].extend(c25)"
case_ chain25-guard-if-changed     bad "${C25}x = [dict(s) for s in c25]; [s.__setitem__('if', 'true') for s in x if 'if' in s]; cs.extend(x)"
case_ chain25-guard-env-changed    bad "${C25}x = [dict(s) for s in c25]; [s.__setitem__('env', {'CHAIN_TEST_REQUIRE_NETCUT': '0'}) for s in x if 'env' in s]; cs.extend(x)"
for i in $(seq 0 24); do
  case_ "chain25-step-$i-removed"   bad "${C25}cs.extend(c25[:$i] + c25[$i+1:])"
  case_ "chain25-step-$i-or-true"   bad "${C25}x = [dict(s) for s in c25]; x[$i]['run'] = x[$i]['run'] + ' || true'; cs.extend(x)"
  case_ "chain25-step-$i-renamed"   bad "${C25}x = [dict(s) for s in c25]; x[$i]['name'] = 'renamed'; cs.extend(x)"
  case_ "chain25-step-$i-continue"  bad "${C25}x = [dict(s) for s in c25]; x[$i]['continue-on-error'] = 'true'; cs.extend(x)"
  case_ "chain25-step-$i-shell"     bad "${C25}x = [dict(s) for s in c25]; x[$i]['shell'] = 'bash -c true {0}'; cs.extend(x)"
done
# allowlist-pins-auditor is accepted in ONE form only (cache#489 and #521 landed; the transition's other forms are gone): main's list, which carries the VEX step after panel-test and the isolation step after workflow-consolidation, each exactly once
PA="ps = d['jobs']['allowlist-pins-auditor']['steps']; ix = lambda r: [k for k, x in enumerate(ps) if x.get('run') == r][0]; "
case_ pa-vex-removed              bad "${PA}del ps[ix('bash bin/vex-index-test.sh </dev/null')]"
case_ pa-iso-removed              bad "${PA}del ps[ix('bash bin/job-isolation-test.sh')]"
case_ pa-vex-twice                bad "${PA}ps.insert(ix('bash bin/panel-test.sh') + 1, dict(ps[ix('bash bin/vex-index-test.sh </dev/null')]))"
case_ pa-iso-twice                bad "${PA}ps.insert(ix('bash bin/workflow-consolidation-test.sh') + 1, dict(ps[ix('bash bin/job-isolation-test.sh')]))"
case_ pa-iso-at-start             bad "${PA}ps.insert(0, ps.pop(ix('bash bin/job-isolation-test.sh')))"
case_ pa-vex-at-end               bad "${PA}ps.append(ps.pop(ix('bash bin/vex-index-test.sh </dev/null')))"
case_ pa-iso-or-true              bad "${PA}ps[ix('bash bin/job-isolation-test.sh')]['run'] += ' || true'"
case_ pa-iso-continue             bad "${PA}ps[ix('bash bin/job-isolation-test.sh')]['continue-on-error'] = 'true'"
case_ pa-vex-env                  bad "${PA}ps[ix('bash bin/vex-index-test.sh </dev/null')]['env'] = {'X': '1'}"
case_ pa-other-step-added         bad "${PA}ps.insert(ix('bash bin/panel-test.sh') + 1, {'name': 'x', 'run': 'true'})"
# The transition judge (cache#669's landing): allowlist-pins-auditor is accepted in EXACTLY two forms: main's list, or it plus the gate-6 step once, right after patch-decide
G6="ps = d['jobs']['allowlist-pins-auditor']['steps']; ix = lambda r: [k for k, x in enumerate(ps) if x.get('run') == r][0]; g6 = {'name': 'gate 6 of the release process \\u2014 a pull request into main needs a passed-audit record for its exact head (REQ-REL-012, owner Oct 23)', 'run': 'bash bin/audit-record-test.sh'}; "
case_ g6-at-start                 bad "${G6}ps.insert(0, g6)"
case_ g6-at-end                   bad "${G6}ps.append(g6)"
case_ g6-before-patch-decide      bad "${G6}ps.insert(ix('bash bin/patch-decide-test.sh'), g6)"
case_ g6-twice                    bad "${G6}ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6); ps.insert(ix('bash bin/patch-decide-test.sh') + 1, dict(g6))"
case_ g6-or-true                  bad "${G6}g6['run'] += ' || true'; ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6)"
case_ g6-renamed                  bad "${G6}g6['name'] = 'x'; ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6)"
case_ g6-continue                 bad "${G6}g6['continue-on-error'] = 'true'; ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6)"
case_ g6-env                      bad "${G6}g6['env'] = {'X': '1'}; ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6)"
case_ g6-other-script             bad "${G6}g6['run'] = 'bash bin/other-test.sh'; ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6)"
case_ g6-and-another-step         bad "${G6}ps.insert(ix('bash bin/patch-decide-test.sh') + 1, g6); ps.insert(ix('bash bin/panel-test.sh') + 1, {'name': 'x', 'run': 'true'})"
case_ split-setup-env         bad "d['jobs']['allowlist-pins-auditor']['steps'][3]['env'] = {'X': '1'}"
# a bump of an action that the judged jobs use (cache#790: setup-python 7.0.0 to 7.1.0) moves the digest in every judged
# step; the digest value is judged by check-action-pins --verify-tags, pin-age and the daily audit, not by this list.
# The action name and the full 40-hex shape of the ref stay exact.
BUMP="for j in ('allowlist', 'allowlist-chain', 'allowlist-persona', 'allowlist-pins-auditor'): "
BUMP+="[s.__setitem__('uses', '%s') for s in d['jobs'][j]['steps'] "
BUMP+="if s.get('uses', '').startswith('actions/setup-python@')]"
case_ uses-digest-bumped       ok  "${BUMP//%s/actions/setup-python@abababababababababababababababababababab}"
case_ uses-tag-ref             bad "${BUMP//%s/actions/setup-python@v7}"
case_ uses-short-digest        bad "${BUMP//%s/actions/setup-python@abababababababababababababababababababa}"
case_ uses-upper-digest        bad "${BUMP//%s/actions/setup-python@ABABABABABABABABABABABABABABABABABABABAB}"
case_ uses-other-action-name   bad "${BUMP//%s/evil/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97}"
RUNX="d['jobs']['allowlist-persona']['steps'][-1]['run'] += ' || true'"
case_msg run-changed-names-step "$RUNX" "the allowlist-persona step "
case_msg run-changed-names-key  "$RUNX" "differs in: run"
case_ impersonate-by-name     bad "d['jobs']['replacement'] = {'name': 'allowlist-persona', 'runs-on': 'ubuntu-latest', 'needs': 'allowlist-persona', 'if': '\${{ always() }}', 'steps': [{'run': 'true'}]}"
case_ impersonate-allowlist   bad "d['jobs']['replacement'] = {'name': 'allowlist', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
case_ job-name-expression     bad "d['jobs']['lint']['name'] = '\${{ matrix.x }}'"
case_ job-name-expr-spaced    ok  "d['jobs']['lint']['name'] = 'lint (\${{ matrix.x }})'"
case_ job-matrix-other        ok  "d['jobs']['lint']['strategy'] = {'matrix': {'x': ['1']}}"
case_ checks-write-job        bad "d['jobs']['lint']['permissions'] = {'checks': 'write'}"
case_ checks-write-all        bad "d['permissions'] = 'write-all'"
case_ checks-write-top        bad "d['permissions'] = {'contents': 'read', 'checks': 'write'}"
case_ name-expr-quoted        bad "d['jobs']['lint']['name'] = \"\${{ 'allowlist-persona' || '}} ' }}\""
case_ name-expr-multiline     bad "d['jobs']['lint']['name'] = \"\${{\\n  'allowlist-persona'\\n}}\""
case_ name-expr-function      bad "d['jobs']['lint']['name'] = \"x \${{ format('{0}', 'a') }}\""
case_ job-needs-list             bad "d['jobs']['allowlist']['needs'] = ['lint']"
case_ job-timeout                bad "d['jobs']['allowlist']['timeout-minutes'] = '1'"
case_ job-concurrency            bad "d['jobs']['allowlist']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
case_ job-concurrency-test       bad "d['jobs']['test']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
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
case_ wf-permissions-widened     bad "d['permissions'] = {'contents': 'write'}"
case_ wf-permissions-removed     bad "d.pop('permissions')"
case_ runs-on-self-hosted        bad "d['jobs']['allowlist']['runs-on'] = 'self-hosted'"
case_ runs-on-list               bad "d['jobs']['allowlist']['runs-on'] = ['ubuntu-latest', 'x']"
case_ job-strategy-matrix        bad "d['jobs']['allowlist']['strategy'] = {'fail-fast': 'true'}"
case_ expression-in-comment      bad "$ck['run'] = '# \${{ fromJSON(\\'\"\\\\nexit 0\\\\n#\"\\') }}\\n' + $ck['run']"
case_ expression-in-fetch        bad "$fe['run'] = '# \${{ github.sha }}\\n' + $fe['run']"
case_ anchor-alias-in-ci         bad "sh = {'k': 'v'}; d['jobs']['test']['x-shared'] = sh; d['jobs']['lint']['x-shared'] = sh"
case_ anchor-bomb                bad "a = ['x']; b = [a, a, a, a, a, a, a, a, a]; c = [b, b, b, b, b, b, b, b, b]; e = [c, c, c, c, c, c, c, c, c]; d['jobs']['test']['bomb'] = [e, e, e, e, e, e, e, e, e]"

for u in 00a0 3000 2028 2029; do
  case_ "unicode-space-comment-$u" bad "$ck['run'] = '\\u$u# x\\n' + $ck['run']"
  case_ "unicode-space-in-fetch-$u" bad "$fe['run'] = '\\u$u# x\\n' + $fe['run']"
done
case_ cr-in-check            bad "$ck['run'] = $ck['run'] + '\\r'"
case_ vt-in-check            bad "$ck['run'] = '\\x0b# x\\n' + $ck['run']"
case_ ff-in-check            bad "$ck['run'] = '\\x0c# x\\n' + $ck['run']"
case_ ctrl-in-fetch          bad "$fe['run'] = $fe['run'] + '\\x01'"
case_ nbsp-inside-command    bad "$ck['run'] = $ck['run'].replace(' | ', '\\u00a0|\\u00a0')"
case_ tab-comment-still-ok-shape bad "$ck['run'] = '\\t# note\\n' + $ck['run'] + ' || true'"

# REQ-SCAN-015-AC2: the scanner guard step (scan.yml and main-candidate-rescan.yml never callable as reusable
# workflows) is exactly one step of the allowlist job, with its exact name and run and nothing that skips,
# swallows or redirects it; else a PR could pair a weakened step with `on: workflow_call`
sg='[s for s in '"$steps"' if "scan-no-workflow-call-test.sh" in (s.get("run") or "")][0]'
case_ scanguard-real-ci-ok      ok  ""
case_ scanguard-step-removed    bad "$steps[:] = [s for s in $steps if 'scan-no-workflow-call-test.sh' not in (s.get('run') or '')]"
case_ scanguard-if-false        bad "$sg['if'] = 'false'"
case_ scanguard-continue        bad "$sg['continue-on-error'] = 'true'"
case_ scanguard-run-echo        bad "$sg['run'] = 'echo bash bin/scan-no-workflow-call-test.sh'"
case_ scanguard-or-true         bad "$sg['run'] = 'bash bin/scan-no-workflow-call-test.sh || true'"
case_ scanguard-renamed         bad "$sg['name'] = 'scanner guard'"
case_ scanguard-unnamed         bad "$sg.pop('name')"
case_ scanguard-env             bad "$sg['env'] = {'SCAN_GUARD': 'off'}"
case_ scanguard-shell           bad "$sg['shell'] = \"bash -c 'true' {0}\""
case_ scanguard-workdir         bad "$sg['working-directory'] = 'bin'"
case_ scanguard-duplicated      bad "$steps.append(dict($sg))"
case_ scanguard-other-job       bad "s = $sg; $steps.remove(s); d['jobs']['requirements']['steps'].append(s)"
gitcase scanguard-removed-at-a-commit bad "$steps[:] = [s for s in $steps if 'scan-no-workflow-call-test.sh' not in (s.get('run') or '')]"
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
textcase duplicate-run-in-check-step   bad "t = t.replace('        run: git ls-files | ./bin/check-file-allowlist.sh', '        run: git ls-files | ./bin/check-file-allowlist.sh\\n        run: true', 1)"
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
    name) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    name: allowlist-persona\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
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
    name: "${{ 'allowlist-persona' || '}} ' }}"
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


# ---- cutover: the landing form (chain-v030's ci.yml) -------------------------------------------------------
# The gate runs this file over a PR head. Judge mode accepts main's own ci.yml or the landing form, which
# pin-wiring-landing.sh accepts: it is chain-v030's own pin-wiring-test.sh, byte for byte (checked below).
# The cases read chain-v030 as git objects at ONE pinned commit, the one the copy was taken from, so a later
# push to chain-v030 cannot turn main red; the re-copy before the landing moves the pin. The follow-up after
# the landing deletes this section.
LANDING_COMMIT=6a36b066b38cc9820be4db2f516057026df30b99
landing_ref=""
if git cat-file -e "$LANDING_COMMIT^{commit}" 2> /dev/null; then landing_ref=$LANDING_COMMIT; fi
git_commit() { git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm c; }
landing_edit() {  # <ci.yml path> <python edit of the parsed file>
  python3 - "$1" "$2" <<'PYL'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
exec(sys.argv[2])
yaml.safe_dump(d, open(sys.argv[1], "w"), sort_keys=False)
PYL
}
lcase() {  # <name> <ok|bad> <python edit of chain-v030's ci.yml, or empty>: judge mode over a temp commit
  local r="$work/land-$1"; rm -rf "$r"; mkdir -p "$r/.github/policy" "$r/test-evidence" "$r/tools/govulncheck"
  git archive "$landing_ref" .github/workflows | tar -x -C "$r"
  git show "$landing_ref:.github/policy/required-checks.json" > "$r/.github/policy/required-checks.json"
  git show "$landing_ref:test-evidence/suite-floors.json" > "$r/test-evidence/suite-floors.json"
  git show "$landing_ref:tools/govulncheck/go.mod" > "$r/tools/govulncheck/go.mod"
  [ -z "$3" ] || landing_edit "$r/.github/workflows/ci.yml" "$3"
  ( cd "$r" && git init -q . && git add -A && git_commit )
  head=$(cd "$r" && git rev-parse HEAD)
  if out=$(cd "$r" && PIN_WIRING_JUDGE_GIT="$head" bash "$here/.github/agent/tests/pin-wiring-test.sh" 2>&1)
  then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS landing:$1 -> $got"
  else failn=$((failn+1)); echo "FAIL landing:$1 -> $got, want $2 ($out)"; fi
}
if [ -z "$landing_ref" ]; then
  failn=$((failn+1)); echo "FAIL landing form: commit $LANDING_COMMIT is not in this clone (CI fetches every branch)"
else
  J='d["jobs"]'
  WF_CONC='d["concurrency"] = {"group": "ci-pr", "cancel-in-progress": "true"}'
  COUNTING='[s for j in d["jobs"].values() for s in (j.get("steps") or [])'
  COUNTING+=' if "chain-hostile-test.sh" in (s.get("run") or "") and "suite-guard-run.py run" in s["run"]][0]'
  lcase chain-v030-as-it-is                    ok  ""
  lcase wrong-workflow-concurrency             bad "$WF_CONC"
  lcase job-concurrency-on-lint                bad "$J['lint']['concurrency'] = {'group': 'x'}"
  lcase live-test-group-cancels                bad "$J['live-test']['concurrency']['cancel-in-progress'] = 'true'"
  lcase shard-step-deleted                     bad "$J['allowlist-chain-2']['steps'].pop()"
  lcase shard-step-if-false                    bad "$J['allowlist-chain-3']['steps'][-1]['if'] = 'false'"
  lcase gate-if-removed                        bad "$J['allowlist-chain'].pop('if')"
  lcase gate-needs-a-shard-short               bad "$J['allowlist-chain']['needs'] = $J['allowlist-chain']['needs'][:3]"
  lcase counting-step-or-true                  bad "x = $COUNTING; x['run'] += ' || true'"
  lcase counting-step-env                      bad "x = $COUNTING; x['env'] = {'PINS_DRY': '1'}"
  lcase persona-step-removed                   bad "$J['allowlist-persona']['steps'].pop()"
  lcase pins-auditor-step-removed              bad "$J['allowlist-pins-auditor']['steps'].pop()"
  # main's own single-job allowlist-chain inside chain-v030's ci.yml fits neither form
  MAIN="m = yaml.load(open('$here/.github/workflows/ci.yml'), Loader=yaml.BaseLoader)"
  SINGLE="$MAIN; [$J.pop('allowlist-chain-%d' % k) for k in (1, 2, 3, 4)]; "
  SINGLE+="$J['allowlist-chain'] = m['jobs']['allowlist-chain']"
  lcase mixed-single-job-chain                 bad "$SINGLE"
  # the landing judge is chain-v030's own, byte for byte
  judge_file=.github/agent/tests/pin-wiring-test.sh
  if git show "$landing_ref:$judge_file" | cmp -s - "$here/.github/agent/tests/pin-wiring-landing.sh"
  then pass=$((pass+1)); echo "PASS landing judge is chain-v030's pin-wiring-test.sh at $landing_ref, byte for byte"
  else failn=$((failn+1)); echo "FAIL landing judge differs from chain-v030's pin-wiring-test.sh at $landing_ref"; fi
fi

echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
