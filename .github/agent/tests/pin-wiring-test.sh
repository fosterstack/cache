#!/usr/bin/env bash
# proves: REQ-SCAN-015-AC2 — the scanner guard step is required, exactly, in the allowlist job (the scanguard cases)
# proves: REQ-CI-001-AC1, REQ-CI-001-AC2, REQ-CI-001-AC3, REQ-CI-001-AC4 — the split form of allowlist-chain is accepted only exactly (the chain-split cases)
# proves: REQ-CI-005-AC2 — a counting step is accepted only in exactly its form (the count-step cases)
# proves: REQ-REL-004-AC1 — the pull-request gate's govulncheck job judges the way Check does: it is accepted only in exactly its form (the govulncheck-gate cases)
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


judge() { PIN_WIRING_WORKFLOWS_DIR="${PIN_WIRING_WORKFLOWS_DIR:-$here/.github/workflows}" PIN_WIRING_FLOORS_FILE="${PIN_WIRING_FLOORS_FILE:-$here/test-evidence/suite-floors.json}" PIN_WIRING_POLICY_FILE="${PIN_WIRING_POLICY_FILE:-$here/.github/policy/required-checks.json}" python3 - "$1" <<'PY'
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
# the only triggers ci.yml may have: push (main), pull_request and merge_group (the merge queue). workflow_call and workflow_dispatch are refused: a called or dispatched run
# would carry another context into the reviewed concurrency group.
if isinstance(on, dict) and sorted(set(on) - {"push", "pull_request", "merge_group"}):
    bad.append("ci.yml has triggers beyond push, pull_request and merge_group: " + ", ".join(sorted(set(on) - {"push", "pull_request", "merge_group"})))
# no job of ci.yml may carry a concurrency setting: a job group competes with its parent workflow's group and can cancel the whole run
for _jid, _j in (d.get("jobs") or {}).items():
    # the one exception: the live test's one-at-a-time group (REQ-SCAN-012). It never cancels a run in progress and its group is shared with no workflow-level group.
    if isinstance(_j, dict) and "concurrency" in _j and not (_jid == "live-test" and _j["concurrency"] == {"group": "vex-live-test", "cancel-in-progress": "false"}):
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
        "bash .github/agent/tests/pin-wiring-test.sh",  # this test's own step, too
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
# the two steps whose env is judged exactly below are exempt from the name list (BASE, GITHUB_HEAD_REPO, GITHUB_QUEUE_REF)
for where, env in [("the workflow", d.get("env")), ("the allowlist job", job.get("env"))] + \
        [(f"step {i}", st.get("env")) for i, st in enumerate(steps_all)]:
    if isinstance(env, dict):
        for k in sorted(k for k in env if is_risky(k)):
            if where == "step 2" and k in ("GITHUB_HEAD_REPO", "GITHUB_QUEUE_REF"):
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
FETCH_RUN = """BASE="${BASE#refs/heads/}"
if [ -n "${BASE}" ]; then
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
for name, want_env in (("fetch", {"BASE": "${{ github.base_ref || github.event.merge_group.base_ref }}"}),
                       ("check", {"GITHUB_HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
                                  "GITHUB_QUEUE_REF": "${{ github.event.merge_group.head_ref }}",
                                  "GH_TOKEN": "${{ github.token }}"})):
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
# the release chain's suites (REQ-CHAIN-001..003, Codex #249 r2 blocker; the #251 lesson; moved from `allowlist` to `allowlist-chain` so `allowlist` stays fast): each is ONE step of the allowlist-chain job with
# exactly this name and this run line and nothing else (no if, continue-on-error, env, shell, working-directory, timeout-minutes), so a
# pull request cannot remove, skip, rename, weaken or move them
CHAIN_STEPS = {
    "suite guard (no tracked test file is empty; the guard's own regressions)": "bash bin/suite-guard.sh files",
    "the suite guard's own regressions (REQ-CI-005, a counting step)": "bash bin/suite-guard-test.sh",
    "same-day reuse of Amazon Inspector results — keyed by the SBOM's package inventory, reuse on a match, a fresh call on each way it differs (REQ-REL-004 AC5)": "bash bin/inspector-reuse-test.sh",
    "the release chain verifier: identities, timestamps, Rekor, digests, action pins (REQ-CHAIN-001..003)": "CHAIN_TEST_REQUIRE_NETCUT=1 bash bin/chain-verify-test.sh",
    "the release chain's hostile dry run, judged offline (REQ-CHAIN-001-AC5)": "bash bin/chain-hostile-test.sh",
    "the Sign boundary's wiring: one Sign file, the closed stage grammar, no secrets (REQ-CHAIN-001, 002-AC4, 003-AC5)": "bash bin/chain-sign-wiring-test.sh",
    "the release chain's record types: one row, claim and consumer per signed type (REQ-CHAIN-003-AC3)": "bash bin/chain-records-test.sh",
    "Build's wiring: the exact stage grammar, the scripts' behaviour, the snapshot callers, the graph (REQ-CHAIN-004, 005; red on 005-AC5 until PRs 3 and 4)": "bash bin/chain-build-wiring-test.sh",
    "Build's admission: every check of the former admission stage, with a counterpart (REQ-CHAIN-004-AC4, AC5)": "bash bin/chain-build-admit-test.sh",
    "the files a stage binds and the items it writes (REQ-CHAIN-004-AC3, AC8, AC9; REQ-CHAIN-005-AC1)": "bash bin/chain-bind-test.sh",
    "Rebuild's comparison of every item (REQ-CHAIN-005-AC3)": "bash bin/chain-rebuild-test.sh",
    "snapshot records and versions are refused by every verifier (REQ-CHAIN-004-AC13, AC15)": "bash bin/chain-snapshot-test.sh",
    "the pinned Witness install (REQ-CHAIN-004-AC2, REQ-CHAIN-005-AC1)": "bash bin/chain-install-witness-test.sh",
    "Check's scripts: scan, FIPS, artifacts, guide, dispatcher, helper (REQ-CHAIN-006-AC3..AC7, AC9, AC11, AC12, AC15..AC17; REQ-PLAT-001-AC1)": "bash bin/chain-check-scripts-test.sh",
    "Check's wiring: the stage grammar, the arm64 job, the dispatcher, the graph (REQ-CHAIN-006-AC1..AC3, AC8..AC14, AC17; red on the guide until cache-3f, known-red.json)": "bash bin/chain-check-wiring-test.sh",
    "the customer verification guide: length, commands, coverage, cannot-run list (REQ-GUIDE-001-AC1..AC7)": "bash bin/verify-release-guide-test.sh </dev/null",
    "the pinned crane install (REQ-CHAIN-007-AC7)": "bash bin/chain-install-crane-test.sh",
    "Release's wiring: the stage grammar, credentials, graph, verify order, release candidates, named records (REQ-CHAIN-007)": "bash bin/chain-release-wiring-test.sh",
    "Release's scripts: verify, apks, publish, sign, assets, post-publish verification (REQ-CHAIN-007, REQ-REL-009-AC11, REQ-CHAIN-006-AC7)": "bash bin/chain-release-scripts-test.sh",
    "Release's metadata: the vex-forms input, the manifest, release-files.sha256 and the coverage gate (REQ-CHAIN-007-AC19)": "bash bin/chain-release-metadata-test.sh",
    "the customer guide — every scanner's file, check and exact command, no competitor named (scanner-panel rule 11)": "bash bin/vex-guide-test.sh",
    "the live test's plan, test copy, fixture and wiring, offline (scanner-panel rule 12)": "bash bin/vex-live-test-test.sh",
    "the live test's page and orchestrator are read by the action-pin checker (scanner-panel rule 12)": "bash .github/agent/tests/vex-live-pins-test.sh",
}
# the two guard steps of the suite floors carry an `if` or an `env` on purpose: judged as whole steps, every key and value
GUARD_STEPS = [
    {
        "name": "suite floors only rise (against the merge base on a pull request)",
        "if": "${{ github.base_ref != '' || github.event.merge_group.base_ref != '' }}",
        "env": {
            "BASE": "${{ github.base_ref || github.event.merge_group.base_ref }}"
        },
        "run": "BASE=\"${BASE#refs/heads/}\"\nbash bin/suite-guard.sh floors-vs-base \"$(git merge-base HEAD \"origin/${BASE}\")\" \\\n  test-evidence/suite-floors.json\n"
    },
    {
        "name": "every suite runs at or above its committed floor (real counts)",
        "env": {
            "CHAIN_TEST_REQUIRE_NETCUT": "1"
        },
        "run": "python3 -I bin/suite-guard-run.py all --count-only test-evidence/suite-floors.json ."
    }
]
# REQ-CI-001 (advisor Oct 23, CI speed): allowlist-chain is accepted in EXACTLY TWO forms: the one job (SPLIT_STEPS below), or four parallel jobs
# allowlist-chain-1..4 plus a gate job that keeps the name allowlist-chain. The groups name steps of the one job's list by run text (the first group is the
# Sign boundary's wiring suite, 691 s alone, the long one; the second holds image assembly, 267 s); the fourth shard takes every other suite step and the two guard steps. Every shard opens with the five setup steps.
# The groups name their steps by run text (stripped), not by position, so an edit of the one job's step list cannot move a suite to another shard silently.
CHAIN_SHARD_IDS = ["allowlist-chain-1", "allowlist-chain-2", "allowlist-chain-3", "allowlist-chain-4"]
CHAIN_GROUPS = [
    ["bash bin/chain-sign-wiring-test.sh"],
    ["bash bin/assemble-image-test.sh", "bash bin/inspector-reuse-test.sh", "bash bin/go-bump-open-pr-test.sh"],
    ["bash bin/refresh-inputs-test.sh", "CHAIN_TEST_REQUIRE_NETCUT=1 bash bin/chain-verify-test.sh", "bash bin/build-apk-test.sh"],
]
# Installed state does not cross jobs (each shard is a fresh runner): the one step that installs a tool for later steps, `./bin/install-scanner.sh grype` (with the
# vex-scope suite), stays in shard 4 with its consumers, vex-both-scanners-test and the suite-floor re-run (suite-guard-run.py all). cache#608 round 2, both seats.
CHAIN_SETUP = 5
CHAIN_GATE = {
    "name": "allowlist-chain",
    "runs-on": "ubuntu-latest",
    "needs": CHAIN_SHARD_IDS,
    "if": "${{ always() }}",
    "steps": [{
        "name": "every shard of allowlist-chain succeeded (a failed, skipped, cancelled or missing result fails)",
        "env": {"R%d" % k: "${{ needs.allowlist-chain-%d.result }}" % k for k in range(1, 5)},
        "run": "for r in \"$R1\" \"$R2\" \"$R3\" \"$R4\"; do [ \"$r\" = success ] || { echo \"a shard of allowlist-chain did not succeed: [$r]\"; exit 1; }; done",
    }],
}
_jobs_ = d.get("jobs") or {}
chain_split = any(k in _jobs_ for k in CHAIN_SHARD_IDS)
if chain_split:   # the suites and guard steps are then spread over the shards: each must still be there exactly once in all of them
    chain_steps = [st for k in CHAIN_SHARD_IDS for st in ((_jobs_.get(k) or {}).get("steps") or []) if isinstance(st, dict)]
else:
    chain_steps = ((d.get("jobs") or {}).get("allowlist-chain") or {}).get("steps", [])
for name, run in CHAIN_STEPS.items():
    hits = [st for st in chain_steps if (st.get("run") or "").strip(" \t\n") == run]
    if len(hits) != 1:
        bad.append(f"the allowlist-chain job does not have exactly one step running `{run}`")
        continue
    if hits[0] != {"name": name, "run": hits[0].get("run")} or "\n" in hits[0]["run"].strip("\n"):
        bad.append(f"the step running `{run}` is not exactly name {name!r} and that one run line (keys: {sorted(hits[0])})")
for want in GUARD_STEPS:
    hits = [st for st in chain_steps if st.get("name") == want["name"]]
    if hits != [want]:
        bad.append(f"the allowlist-chain job does not have exactly the guard step {want['name']!r} as judged (every key and value)")
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
    "BASE": "${{ github.base_ref || github.event.merge_group.base_ref }}"
   },
   "name": "make sure the base branch ref exists",
   "run": "BASE=\"${BASE#refs/heads/}\"\nif [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi\n"
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
   "name": "install the pinned grype for the VEX product-scope regressions and the suites after them (shard 4 keeps it with its consumers)",
   "run": "./bin/install-scanner.sh grype"
  },
  {
   "name": "VEX product-scope regressions (audit R01 \u2014 exception bound to the FosterStack product)",
   "run": "bash bin/vex-scope-test.sh"
  },
  {
   "name": "VEX applied by both gate scanners (REQ-REL-004-AC1 \u2014 covered suppressed, uncovered blocks, zero packages fails)",
   "run": "bash bin/vex-both-scanners-test.sh"
  },
  {
   "name": "the candidate's OCI layout turned into a scan tar, digests checked (REQ-REL-004-AC1)",
   "run": "bash bin/layout-archive-test.sh"
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
  },
  {
   "name": "suite guard (no tracked test file is empty; the guard's own regressions)",
   "run": "bash bin/suite-guard.sh files"
  },
  {
   "name": "the suite guard's own regressions (REQ-CI-005, a counting step)",
   "run": "bash bin/suite-guard-test.sh"
  },
  {
   "env": {
    "BASE": "${{ github.base_ref || github.event.merge_group.base_ref }}"
   },
   "if": "${{ github.base_ref != '' || github.event.merge_group.base_ref != '' }}",
   "name": "suite floors only rise (against the merge base on a pull request)",
   "run": "BASE=\"${BASE#refs/heads/}\"\nbash bin/suite-guard.sh floors-vs-base \"$(git merge-base HEAD \"origin/${BASE}\")\" \\\n  test-evidence/suite-floors.json\n"
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
    "BASE": "${{ github.base_ref || github.event.merge_group.base_ref }}"
   },
   "name": "make sure the base branch ref exists",
   "run": "BASE=\"${BASE#refs/heads/}\"\nif [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi\n"
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
    "BASE": "${{ github.base_ref || github.event.merge_group.base_ref }}"
   },
   "name": "make sure the base branch ref exists",
   "run": "BASE=\"${BASE#refs/heads/}\"\nif [ -n \"${BASE}\" ]; then\n  [[ \"${BASE}\" =~ ^[A-Za-z0-9._][A-Za-z0-9._/-]*$ ]] || exit 1\n  [[ \"${BASE}\" != *..* ]] || exit 1\n  git fetch --no-tags origin \"+refs/heads/${BASE}:refs/remotes/origin/${BASE}\"\nfi\n"
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
   "name": "the review gate's judge of the merge queue's head fails closed (REQ-DEP-005-AC3)",
   "run": "bash .github/agent/tests/queue-gate-judge-test.sh"
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
def chain_shard_steps(k):   # the exact step list of shard k (1-based): the setup steps, then its suites in the one job's order
    full = SPLIT_STEPS["allowlist-chain"]
    pos = {}
    for i in range(CHAIN_SETUP, len(full)):
        pos.setdefault((full[i].get("run") or "").strip(), []).append(i)
    groups = []
    for g in CHAIN_GROUPS:
        idx = []
        for r in g:
            if len(pos.get(r, [])) != 1:
                bad.append(f"CHAIN_GROUPS names a step that is not exactly once in the one job's list: {r!r}")
            else:
                idx.append(pos[r][0])
        groups.append(sorted(idx))
    taken = {i for g in groups for i in g}
    groups.append([i for i in range(CHAIN_SETUP, len(full)) if i not in taken])
    return full[:CHAIN_SETUP] + [full[i] for i in groups[k - 1]]
for jid, want_steps in SPLIT_STEPS.items():
    if jid == "allowlist-chain" and chain_split:   # the second exact form: four shards (each exactly its list) and the gate (exactly CHAIN_GATE)
        extra = sorted(k for k in _jobs_ if k.startswith("allowlist-chain-") and k not in CHAIN_SHARD_IDS)
        if extra:
            bad.append(f"unexpected jobs {extra} next to the allowlist-chain shards")
        for n_, k in enumerate(CHAIN_SHARD_IDS, 1):
            sj = _jobs_.get(k)
            if not isinstance(sj, dict):
                bad.append(f"the shard {k} of allowlist-chain is missing")
                continue
            for key in sorted(set(sj) - {"name", "runs-on", "steps"}):
                bad.append(f"the {k} job has `{key}`")
            if sj.get("name") != k:
                bad.append(f"the {k} job is not named `{k}`")
            if sj.get("runs-on") != "ubuntu-latest":
                bad.append(f"the {k} job does not run on exactly `ubuntu-latest`")
            if sj.get("steps") != chain_shard_steps(n_):
                bad.append(f"the {k} steps are not exactly the judged list (REQ-CI-001-AC1: every step of the one job in exactly one shard, unchanged, in order)")
        # REQ-CI-001-AC1/AC4, exactly once across the WHOLE workflow: a chain suite appears once more than it does in the other judged jobs (the pins-auditor
        # job runs one of them too) and nowhere else, so a copy kept in the allowlist job or in a renamed original job is refused
        others = [st for oj, ws in SPLIT_STEPS.items() if oj != "allowlist-chain" for st in ws]
        for st_ in SPLIT_STEPS["allowlist-chain"][CHAIN_SETUP:]:
            r_ = (st_.get("run") or "").strip()
            have_ = sum(1 for j_ in _jobs_.values() if isinstance(j_, dict) for x_ in (j_.get("steps") or []) if isinstance(x_, dict) and (x_.get("run") or "").strip() == r_)
            want_ = 1 + sum(1 for x_ in others if (x_.get("run") or "").strip() == r_)
            if have_ != want_:
                bad.append(f"the step running `{r_}` appears {have_} times in the workflow, not {want_} (REQ-CI-001-AC1: exactly once across the shards, nowhere else)")
        if _jobs_.get("allowlist-chain") != CHAIN_GATE:
            bad.append("the allowlist-chain gate job is not exactly the judged gate (REQ-CI-001-AC2: needs the four shards, always runs, no checkout, fails on anything but success)")
        continue
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
    if got not in accepted:
        have = [st.get("name") or st.get("uses") for st in got]
        want_n = [st.get("name") or st.get("uses") for st in want_steps]
        why = [f"missing {n}" for n in want_n if n not in have] + [f"unexpected {n}" for n in have if n not in want_n]
        bad.append(f"the {jid} steps are not exactly the judged list ({'; '.join(why) or 'a step differs in its command, env, uses, with or order'})")
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
  git show "${PIN_WIRING_JUDGE_GIT}:tools/govulncheck/go.mod" > "$work/head-gomod" || { echo "pin-wiring: no tools/govulncheck/go.mod at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  PIN_WIRING_WORKFLOWS_DIR="$work/head-wf" PIN_WIRING_POLICY_FILE="$work/head-policy.json" PIN_WIRING_FLOORS_FILE="$work/head-floors.json" judge "$work/head-ci.yml" || exit 1
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

steps='d["jobs"]["allowlist"]["steps"]'
pick='[s for s in '"$steps"' if (s.get("run") or "").startswith("python3 .github/agent/bin/check-action-pins.py")][0]'
case_ the-real-hygiene      ok  ""
# REQ-CI-005: a floored suite's step may call the counting runner instead of `bash PATH`; exactly that form is read back to the plain line, anything else is judged as unknown text
CW="[s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip() in ('bash bin/inspector-gate-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json inspector-gate-test.sh bin/inspector-gate-test.sh')][0]"
CF="python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json"
case_ count-step-wrapped-ok         ok  "w = $CW; w['run'] = '$CF inspector-gate-test.sh bin/inspector-gate-test.sh'"
case_ count-step-devnull-added      bad "w = $CW; w['run'] = '$CF inspector-gate-test.sh bin/inspector-gate-test.sh </dev/null'"
case_ count-step-devnull-kept       ok  "w = [s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip() in ('bash bin/verify-release-guide-test.sh </dev/null', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json verify-release-guide-test.sh bin/verify-release-guide-test.sh </dev/null')][0]; w['run'] = '$CF verify-release-guide-test.sh bin/verify-release-guide-test.sh </dev/null'"
case_ count-step-devnull-dropped    bad "w = [s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip() in ('bash bin/verify-release-guide-test.sh </dev/null', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json verify-release-guide-test.sh bin/verify-release-guide-test.sh </dev/null')][0]; w['run'] = '$CF verify-release-guide-test.sh bin/verify-release-guide-test.sh'"
case_ count-step-name-not-path      bad "w = $CW; w['run'] = '$CF install-scanner-test.sh bin/inspector-gate-test.sh'"
case_ count-step-other-path         bad "w = $CW; w['run'] = '$CF install-scanner-test.sh bin/install-scanner-test.sh'"
case_ count-step-unfloored-name     bad "w = $CW; w['run'] = '$CF zz-not-floored-test.sh bin/zz-not-floored-test.sh'"
case_ count-step-other-floors       bad "w = $CW; w['run'] = 'python3 -I bin/suite-guard-run.py run /tmp/floors.json inspector-gate-test.sh bin/inspector-gate-test.sh'"
case_ count-step-count-only         bad "w = $CW; w['run'] = 'python3 -I bin/suite-guard-run.py run --count-only test-evidence/suite-floors.json inspector-gate-test.sh bin/inspector-gate-test.sh'"
case_ count-step-or-true            bad "w = $CW; w['run'] = '$CF inspector-gate-test.sh bin/inspector-gate-test.sh || true'"
case_ count-step-no-isolation       bad "w = $CW; w['run'] = 'python3 bin/suite-guard-run.py run test-evidence/suite-floors.json inspector-gate-test.sh bin/inspector-gate-test.sh'"
case_ count-step-twice              bad "w = $CW; w['run'] = '$CF inspector-gate-test.sh bin/inspector-gate-test.sh\n$CF inspector-gate-test.sh bin/inspector-gate-test.sh'"
case_ count-step-if-false           bad "w = $CW; w['run'] = '$CF inspector-gate-test.sh bin/inspector-gate-test.sh'; w['if'] = 'false'"
case_ count-step-env-injected       bad "w = $CW; w['run'] = 'BASH_ENV=/tmp/x $CF inspector-gate-test.sh bin/inspector-gate-test.sh'"
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
case_ wiring-step-removed   bad "$steps[:] = [s for s in $steps if (s.get('run') or '').strip() not in ('bash .github/agent/tests/pin-wiring-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json pin-wiring-test.sh .github/agent/tests/pin-wiring-test.sh')]"
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
case_ allowlist-queue-ref-changed bad "$ck['env']['GITHUB_QUEUE_REF'] = 'other'"
case_ allowlist-queue-token-gone  bad "$ck['env'].pop('GH_TOKEN')"
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

# the release chain's required steps (REQ-CHAIN-001..003 and the suites that followed), all in the allowlist-chain job: each mutation of each step is caught
# the chain suites live in the four shards (REQ-CI-001): each case below mutates the shard that holds the suite (found in the real ci.yml)
shard_of() { python3 - "$here/.github/workflows/ci.yml" "$1" "$2" <<'PYF'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])); mode, key = sys.argv[2], sys.argv[3]
for k in ("allowlist-chain-1", "allowlist-chain-2", "allowlist-chain-3", "allowlist-chain-4"):
    for st in d["jobs"][k]["steps"]:
        r = (st.get("run") or "")
        if (mode == "exact" and r.strip() == key) or (mode == "has" and key in r):
            print(k); sys.exit(0)
sys.exit(1)
PYF
}
actual_of() { python3 - "$here/.github/workflows/ci.yml" "$1" <<'PYA'
import re, sys
ci, r = open(sys.argv[1]).read(), sys.argv[2]
m = re.fullmatch(r'((?:CHAIN_TEST_REQUIRE_NETCUT=1 )?)bash ((?:bin|\.github/agent/tests)/(\S+))( </dev/null)?', r)
if m:
    w = m.group(1) + "python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json " + m.group(3) + " " + m.group(2) + (m.group(4) or "")
    if ("run: " + w + "\n") in ci:
        print(w); sys.exit(0)
print(r)
PYA
}
for r in "bash bin/suite-guard.sh files" "bash bin/suite-guard-test.sh" "bash bin/inspector-reuse-test.sh" "CHAIN_TEST_REQUIRE_NETCUT=1 bash bin/chain-verify-test.sh" "bash bin/chain-hostile-test.sh" "bash bin/chain-sign-wiring-test.sh" "bash bin/chain-records-test.sh" "bash bin/chain-build-wiring-test.sh" "bash bin/chain-build-admit-test.sh" "bash bin/chain-bind-test.sh" "bash bin/chain-rebuild-test.sh" "bash bin/chain-snapshot-test.sh" "bash bin/chain-install-witness-test.sh" "bash bin/chain-check-scripts-test.sh" "bash bin/chain-check-wiring-test.sh" "bash bin/verify-release-guide-test.sh </dev/null" "bash bin/chain-install-crane-test.sh" "bash bin/chain-release-wiring-test.sh" "bash bin/chain-release-scripts-test.sh" "bash bin/chain-release-metadata-test.sh" "bash bin/vex-guide-test.sh" "bash bin/vex-live-test-test.sh" "bash .github/agent/tests/vex-live-pins-test.sh"; do
  ar=$(actual_of "$r"); n=$(basename "${r##* }" .sh); csteps="d[\"jobs\"][\"$(shard_of exact "$ar")\"][\"steps\"]"; cs="[s for s in $csteps if (s.get('run') or '').strip() == '$ar'][0]"
  case_ "$n-removed"     bad "$csteps[:] = [s for s in $csteps if (s.get('run') or '').strip() != '$ar']"
  case_ "$n-if-false"    bad "$cs['if'] = 'false'"
  case_ "$n-continue"    bad "$cs['continue-on-error'] = 'true'"
  case_ "$n-or-true"     bad "$cs['run'] = '$ar || true'"
  case_ "$n-renamed"     bad "$cs['name'] = 'chain tests'"
  case_ "$n-env"         bad "$cs['env'] = {'CHAIN_X': '1'}"
  case_ "$n-shell"       bad "$cs['shell'] = \"bash -c 'true' {0}\""
  case_ "$n-workdir"     bad "$cs['working-directory'] = 'bin'"
  case_ "$n-timeout"     bad "$cs['timeout-minutes'] = '1'"
  case_ "$n-other-job"   bad "x = $cs; $csteps.remove(x); d['jobs']['test']['steps'].append(x)"
  case_ "$n-back-in-allowlist" bad "x = $cs; $csteps.remove(x); $steps.append(x)"
  case_ "$n-twice"       bad "$csteps.append(dict($cs))"
done
# the two suite-floor guard steps (an `if` or an `env` on purpose): every key and value is judged
for g in "floors-vs-base" "suite-guard-run.py all"; do
  csteps="d[\"jobs\"][\"$(shard_of has "$g")\"][\"steps\"]"; gs="[s for s in $csteps if '$g' in (s.get('run') or '')][0]"
  case_ "guard-$g-removed"  bad "$csteps[:] = [s for s in $csteps if '$g' not in (s.get('run') or '')]"
  case_ "guard-$g-if"       bad "$gs['if'] = 'false'"
  case_ "guard-$g-env"      bad "$gs['env'] = {'CHAIN_TEST_REQUIRE_NETCUT': '0'}"
  case_ "guard-$g-or-true"  bad "$gs['run'] = $gs['run'] + ' || true'"
  case_ "guard-$g-renamed"  bad "$gs['name'] = 'guard'"
  case_ "guard-$g-shell"    bad "$gs['shell'] = \"bash -c 'true' {0}\""
  case_ "guard-$g-continue" bad "$gs['continue-on-error'] = 'true'"
  case_ "guard-$g-in-allowlist" bad "x = $gs; $csteps.remove(x); $steps.append(x)"
done
csteps="d[\"jobs\"][\"$(shard_of has chain-verify-test.sh)\"][\"steps\"]"
case_ chain-verify-no-netcut bad "[s for s in $csteps if 'chain-verify-test.sh' in (s.get('run') or '')][0]['run'] = 'bash bin/chain-verify-test.sh'"

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
WRAP="w = [s for j in d['jobs'].values() for s in (j.get('steps') or []) if (s.get('run') or '').strip() in ('bash bin/inspector-gate-test.sh', 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json inspector-gate-test.sh bin/inspector-gate-test.sh')][0]; w['run'] = 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json inspector-gate-test.sh bin/inspector-gate-test.sh'"
gitcase counting-step-at-a-commit ok  "$WRAP"
GIT_FLOORS_EDIT="d.pop('inspector-gate-test.sh')" gitcase counting-step-unfloored-at-that-commit bad "$WRAP"     # the floors file of the judged commit decides, not the checkout's
# the policy at the commit is read too: a missing split entry is refused (and so is a missing file, above)

# the govulncheck-gate judge runs in judge mode too, over the head's own ci.yml (the trusted gate path)
GVJ="[j for j in [d['jobs']['govulncheck']]][0]['steps']"
gitcase govulncheck-gate-old-step-at-a-commit  bad "$GVJ[-1]['run'] = 'govulncheck ./...'"
gitcase govulncheck-gate-no-installer-at-a-commit  bad "$GVJ[:] = [s for s in $GVJ if s.get('run') != 'bash bin/install-scanner.sh go']"
gitcase govulncheck-gate-extra-step-at-a-commit  bad "$GVJ.insert(3, {'run': 'cp /bin/true /usr/local/bin/fscache-go/bin/govulncheck'})"
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
case_ split-anchor-gone       bad "st = d['jobs']['allowlist-chain-2']['steps']; st[:] = [x for x in st if 'assemble-image-test' not in (x.get('run') or '')]"
case_ split-no-checkout       bad "d['jobs']['allowlist-persona']['steps'].pop(0)"
case_ split-job-env           bad "d['jobs']['allowlist-chain']['env'] = {'X': '1'}"
case_ split-env-bash-env      bad "d['jobs']['allowlist-chain']['steps'][-1]['env'] = {'BASH_ENV': '/tmp/x'}"
case_ split-env-shellopts     bad "d['jobs']['allowlist-persona']['steps'][-1]['env'] = {'SHELLOPTS': 'noexec'}"
case_ split-suite-deleted     bad "st = d['jobs']['allowlist-persona']['steps']; st[:] = [x for x in st if 'persona-uat-agent-test' not in (x.get('run') or '')]"
case_ split-suite-or-true     bad "x = [x for x in d['jobs']['allowlist-persona']['steps'] if 'persona-uat-agent-test' in (x.get('run') or '')][0]; x['run'] += ' || true'"
case_ split-suite-reordered   bad "st = d['jobs']['allowlist-chain-4']['steps']; st[-1], st[-2] = st[-2], st[-1]"
case_ split-suite-added       bad "d['jobs']['allowlist-chain']['steps'].append({'name': 'x', 'run': 'true'})"
# REQ-CI-001 (advisor Oct 23: CI speed, no check dropped, exactly once): allowlist-chain is ALSO accepted split into four parallel jobs
# (allowlist-chain-1..4) plus a gate job that keeps the name allowlist-chain. This helper builds that form from the real ci.yml's own job, independently of the judge:
# the five setup steps open every shard, the groups below name steps of the old job by run text (the first is the Sign boundary's wiring suite, the long one).
cat > "$work/split.py" <<'PYS'
import copy
GROUPS = [["bash bin/chain-sign-wiring-test.sh"], ["bash bin/assemble-image-test.sh", "bash bin/inspector-reuse-test.sh", "bash bin/go-bump-open-pr-test.sh"],
          ["bash bin/refresh-inputs-test.sh", "CHAIN_TEST_REQUIRE_NETCUT=1 bash bin/chain-verify-test.sh", "bash bin/build-apk-test.sh"]]   # the rest is the fourth shard (it keeps the grype installer with its consumers)
def split_chain(d):
    if "allowlist-chain-1" in d["jobs"]:   # ci.yml is already split: the cases then mutate the real shards and gate
        return
    old = d["jobs"]["allowlist-chain"]
    steps = old["steps"]
    pre, suites = steps[:5], steps[5:]
    idx = {(st.get("run") or "").strip(): i for i, st in enumerate(steps) if i >= 5}
    groups = [sorted(idx[r] for r in g) for g in GROUPS]
    taken = {i for g in groups for i in g}
    groups.append([i for i in range(5, len(steps)) if i not in taken])
    jobs = {}
    for k, g in enumerate(groups, 1):
        jobs[f"allowlist-chain-{k}"] = {"name": f"allowlist-chain-{k}", "runs-on": "ubuntu-latest", "steps": copy.deepcopy(pre) + [copy.deepcopy(steps[i]) for i in g]}
    gate = {"name": "allowlist-chain", "runs-on": "ubuntu-latest", "needs": [f"allowlist-chain-{k}" for k in range(1, 5)], "if": "${{ always() }}",
            "steps": [{"name": "every shard of allowlist-chain succeeded (a failed, skipped, cancelled or missing result fails)",
                       "env": {f"R{k}": "${{ needs.allowlist-chain-%d.result }}" % k for k in range(1, 5)},
                       "run": 'for r in "$R1" "$R2" "$R3" "$R4"; do [ "$r" = success ] || { echo "a shard of allowlist-chain did not succeed: [$r]"; exit 1; }; done'}]}
    new = {}
    for jid, j in d["jobs"].items():
        if jid == "allowlist-chain":
            new.update(jobs); new["allowlist-chain"] = gate
        else:
            new[jid] = j
    d["jobs"] = new
PYS
SC="exec(open('$work/split.py').read()); split_chain(d); "
S1='d["jobs"]["allowlist-chain-1"]'; S4='d["jobs"]["allowlist-chain-4"]'; GT='d["jobs"]["allowlist-chain"]'
case_ chain-split-accepted        ok  "${SC}"
# AC1: every step of the old job is in exactly one shard, unchanged, and no other step exists
case_ chain-split-step-dropped    bad "${SC}${S4}['steps'].pop()"
case_ chain-split-step-dropped-c  bad "${SC}${S1}['steps'].pop()"
case_ chain-split-step-in-two     bad "${SC}${S4}['steps'].append(dict(${S1}['steps'][-1]))"
case_ chain-split-step-moved      bad "${SC}${S4}['steps'].append(${S1}['steps'].pop())"
case_ chain-split-step-edited     bad "${SC}${S1}['steps'][-1]['run'] += ' || true'"
case_ chain-split-step-renamed    bad "${SC}${S4}['steps'][-1]['name'] = 'renamed'"
case_ chain-split-step-reordered  bad "${SC}${S4}['steps'][6], ${S4}['steps'][7] = ${S4}['steps'][7], ${S4}['steps'][6]"
case_ chain-split-step-added      bad "${SC}${S4}['steps'].append({'name': 'x', 'run': 'true'})"
case_ chain-split-setup-dropped   bad "${SC}${S4}['steps'].pop(0)"
case_ chain-split-shard-missing   bad "${SC}d['jobs'].pop('allowlist-chain-3')"
case_ chain-split-shard-extra     bad "${SC}d['jobs']['allowlist-chain-5'] = {'name': 'allowlist-chain-5', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
case_ chain-split-guard-dropped   bad "${SC}${S4}['steps'][:] = [x for x in ${S4}['steps'] if 'floors-vs-base' not in (x.get('run') or '')]"
case_ chain-split-old-steps-left  bad "${SC}${GT}['steps'].append(dict(${S1}['steps'][-1]))"
# AC2: the gate keeps the name, needs every shard, always runs, takes no checkout and no action, and fails on anything but success (incl. a missing or empty result)
case_ chain-split-gate-renamed    bad "${SC}${GT}['name'] = 'allowlist-chain-gate'"
case_ chain-split-gate-needs-3    bad "${SC}${GT}['needs'].pop()"
case_ chain-split-gate-needs-str  bad "${SC}${GT}['needs'] = 'allowlist-chain-1'"
case_ chain-split-gate-no-always  bad "${SC}${GT}.pop('if')"
case_ chain-split-gate-if-false   bad "${SC}${GT}['if'] = 'false'"
case_ chain-split-gate-success    bad "${SC}${GT}['if'] = '\${{ success() }}'"
case_ chain-split-gate-checkout   bad "${SC}${GT}['steps'].insert(0, ${S1}['steps'][0])"
case_ chain-split-gate-or-true    bad "${SC}${GT}['steps'][0]['run'] += ' || true'"
case_ chain-split-gate-skipped-ok bad "${SC}${GT}['steps'][0]['run'] = 'for r in \"\$R1\" \"\$R2\" \"\$R3\" \"\$R4\"; do [ \"\$r\" != failure ] || exit 1; done'"
case_ chain-split-gate-empty-ok   bad "${SC}${GT}['steps'][0]['run'] = 'for r in \"\$R1\" \"\$R2\" \"\$R3\"; do [ \"\$r\" = success ] || exit 1; done'"
case_ chain-split-gate-env-wrong  bad "${SC}${GT}['steps'][0]['env']['R4'] = '\${{ needs.allowlist-chain-3.result }}'"
case_ chain-split-gate-env-lit    bad "${SC}${GT}['steps'][0]['env']['R2'] = 'success'"
case_ chain-split-gate-continue   bad "${SC}${GT}['steps'][0]['continue-on-error'] = 'true'"
case_ chain-split-gate-job-env    bad "${SC}${GT}['env'] = {'X': '1'}"
case_ chain-split-gate-runs-on    bad "${SC}${GT}['runs-on'] = 'self-hosted'"
case_ chain-split-gate-permissions bad "${SC}${GT}['permissions'] = {'checks': 'write'}"
# AC3: no `if`, env, continue-on-error, timeout, container, services, permissions, id-token or secrets on a shard or its steps
case_ chain-split-shard-if        bad "${SC}${S1}['if'] = 'false'"
case_ chain-split-shard-needs     bad "${SC}${S1}['needs'] = ['lint']"
case_ chain-split-shard-env       bad "${SC}${S1}['env'] = {'BASH_ENV': '/tmp/x'}"
case_ chain-split-shard-timeout   bad "${SC}${S1}['timeout-minutes'] = '1'"
case_ chain-split-shard-container bad "${SC}${S1}['container'] = 'alpine'"
case_ chain-split-shard-services  bad "${SC}${S1}['services'] = {'x': {'image': 'alpine'}}"
case_ chain-split-shard-perms     bad "${SC}${S1}['permissions'] = {'id-token': 'write'}"
case_ chain-split-shard-continue  bad "${SC}${S4}['continue-on-error'] = 'true'"
case_ chain-split-step-if         bad "${SC}${S1}['steps'][-1]['if'] = 'false'"
case_ chain-split-step-env        bad "${SC}${S4}['steps'][-1]['env'] = {'SHELLOPTS': 'noexec'}"
case_ chain-split-step-shell      bad "${SC}${S4}['steps'][-1]['shell'] = 'bash -c true {0}'"
case_ chain-split-step-secrets    bad "${SC}${S1}['steps'][-1]['env'] = {'T': '\${{ secrets.X }}'}"
case_ chain-split-shard-runs-on   bad "${SC}${S1}['runs-on'] = 'self-hosted'"
case_ chain-split-shard-name      bad "${SC}${S1}['name'] = 'allowlist-chain'"
case_ chain-split-impersonate     bad "${SC}d['jobs']['replacement'] = {'name': 'allowlist-chain', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
# exactly once across the whole workflow (seat A of cache#608, round 1): a copy of a chain suite kept in another job is refused
case_ chain-split-copy-in-allowlist bad "${SC}d['jobs']['allowlist']['steps'].append(copy.deepcopy(${S1}['steps'][-1]))"
# a copy of the VEX-index suite in a shard of the chain job is refused: the suite runs once, in the pins-auditor job (REQ-CI-005; the name of the file is built from two parts, a scope test reads this file line by line)
case_ chain-split-vex-copy-in-chain bad "${SC}d['jobs']['allowlist-chain-4']['steps'].append({'name': 'x', 'run': 'bash bin/vex-' + 'index-test.sh </dev/null'})"
case_ chain-split-copy-in-pa        bad "${SC}d['jobs']['allowlist-pins-auditor']['steps'].append({'name': 'x', 'run': 'bash bin/assemble-image-test.sh'})"
case_ chain-split-original-kept     bad "${SC}d['jobs']['legacy-chain'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'bash bin/assemble-image-test.sh'}]}"
# installed state does not cross jobs: every shard that runs a consumer of the installed grype (vex-both-scanners-test, the suite-floor re-run) must also run the installer step
# and run it BEFORE the consumer. Checked on the split form the helper builds from the real ci.yml (independent of the judge's groups).
if python3 - "$here/.github/workflows/ci.yml" "$work/split.py" > "$work/dep.out" 2>&1 <<'PYD'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])); exec(open(sys.argv[2]).read()); split_chain(d)
inst, cons, bad = "install-scanner.sh grype", ("vex-both-scanners-test.sh", "suite-guard-run.py all"), []
for k in ("allowlist-chain-1", "allowlist-chain-2", "allowlist-chain-3", "allowlist-chain-4"):
    runs = [(st.get("run") or "") for st in d["jobs"][k]["steps"]]
    pos_i = [n for n, r in enumerate(runs) if inst in r]
    for n, r in enumerate(runs):
        if any(c in r for c in cons) and not (pos_i and min(pos_i) < n):
            bad.append(f"{k}: `{r.strip()[:50]}` runs without the grype installer before it")
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PYD
then pass=$((pass+1)); echo "PASS chain-split-grype-installer-with-consumers → ok"; else failn=$((failn+1)); echo "FAIL chain-split-grype-installer-with-consumers → $(cat "$work/dep.out")"; fi
# a half-done split: one shard job is gone, so a suite would run in no shard (the old case here replaced a shard with a copy of the aggregate and failed on the YAML alias it created, not on the split)
case_ chain-shard-missing         bad "del d['jobs']['allowlist-chain-4']"
# allowlist-pins-auditor is accepted in ONE form only (cache#489 and #521 landed; the transition's other forms are gone): main's list, which carries the VEX step after panel-test and the isolation step after workflow-consolidation, each exactly once
PA="ps = d['jobs']['allowlist-pins-auditor']['steps']; pth = lambda t: [w for w in t.split() if w.startswith('bin/')][-1:]; ix = lambda r: [k for k, x in enumerate(ps) if x.get('run') == r or ((x.get('run') or '').startswith('python3 -I bin/suite-guard-run.py run ') and pth(x['run']) == pth(r))][0]; "
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
case_ split-setup-env         bad "d['jobs']['allowlist-pins-auditor']['steps'][3]['env'] = {'X': '1'}"
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
# the live test's one-at-a-time group (REQ-SCAN-012, ratified): live-test alone may carry exactly this block (take 30, advisor)
case_ live-test-concurrency-reviewed   ok  "d['jobs']['live-test']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false'}"
case_ live-test-concurrency-cancels    bad "d['jobs']['live-test']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'true'}"
case_ live-test-concurrency-group      bad "d['jobs']['live-test']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'false'}"
case_ live-test-concurrency-extra-key  bad "d['jobs']['live-test']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false', 'other': 'x'}"
case_ live-test-concurrency-string     bad "d['jobs']['live-test']['concurrency'] = 'vex-live-test'"
case_ live-test-concurrency-no-cancel-key bad "d['jobs']['live-test']['concurrency'] = {'group': 'vex-live-test'}"
case_ other-job-live-test-block        bad "d['jobs']['test']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false'}"
case_ allowlist-live-test-block        bad "d['jobs']['allowlist']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false'}"
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
