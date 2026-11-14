#!/usr/bin/env bash
# proves: REQ-SCAN-015-AC2 — the scanner guard step is required, exactly, in the allowlist job (the scanguard cases)
# REQ-REL-005-AC1 (register row 78): the hygiene check runs the pin checker on every pull request and
# every push to main, and nothing can skip it or swallow its failure. (Mapped from the product matrix as
# workflow-job evidence: REQ-AUD-18 AC1 keeps .github/agent/ paths out of files outside it.)
# The real ci.yml must pass; each mutated copy must be caught. ci.yml (REQ-CI-001) holds the eight required contexts; the suites the changed files need are
# selected by bin/select-tests.sh and the whole suites run in full-suite.yml, so this judge holds the allowlist job's guards (the pin step, the scanner guard), not a list of suites.
# Known limit (by design): later steps of the CI allowlist job can edit the pin checker or this test on disk;
# the trusted gate (.github/workflows/agent-review-gate.yml) re-runs main's copies of all of them over the PR head.
set -euo pipefail
here=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

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
# the only triggers ci.yml may have: push (main) and pull_request (REQ-CI-001-AC2; no workflow gains a merge_group trigger). workflow_call and workflow_dispatch are refused: a called
# or dispatched run would carry another context into the reviewed concurrency group.
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
want = {"python3 .github/agent/bin/check-action-pins.py --verify-tags ."}   # REQ-REL-005-AC1: the action-pin step, on every pull request and push to main
seen = set()
for st in job.get("steps", []):
    run = (st.get("run") or "").strip()
    if run in want:
        seen.add(run)
        for k in ("if", "continue-on-error", "shell", "working-directory"):
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

def _by_shape(st):
    """A step with `uses: name@<full 40-hex commit>` stands for every digest of
    that action: the digest VALUE is judged by check-action-pins --verify-tags, pin-age and the daily audit (a
    Dependabot bump moves it). The action name and the exact shape of the ref (40 lower-case hex) stay compared; the
    stand-in is a tuple, which no YAML scalar can equal."""
    u = st.get("uses")
    if isinstance(u, str):
        name, _, ref = u.partition("@")
        # matches "0123456789abcdef0123456789abcdef01234567"; refuses "v7"
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            return dict(st, uses=(name, "@40-hex"))
    return st


# each job's actions are judged on their own, so one job cannot borrow another's
ALLOWLIST_ACTIONS = [_by_shape(st) for st in (
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "with": {"fetch-depth": "0"}},
    {"name": "set up Python for the selected suites", "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
     "with": {"python-version": "3.12"}})]
for _i, st in enumerate(steps_):
    if "uses" in st and _by_shape(st) not in ALLOWLIST_ACTIONS:
        bad.append(f"the allowlist step {_i + 1} ({st.get('name') or st['uses']}) is not a judged action step")

# the required-check policy (release admission reads it): a readable JSON object whose required_checks is a list of objects with unique contexts,
# and exactly one correct entry (integration 15368, scope push) for the protected job (the full suite's contexts are promotion_checks, read by stage-admission, not here). Anything unreadable or malformed is refused (fail closed).
PROTECTED = ("allowlist",)
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
# a promotion context (the full suite's, read by stage-admission) is made by one job: no job of ci.yml takes its name, and no workflow has two
# jobs with it (a called workflow's job reports as "<calling job> / <job>", so the calling job's name counts). A job of another workflow with
# that name does not satisfy admission: it reads the workflow file that made the check run.
try:
    PROMO = sorted({c["context"].split(" / ")[0]: c["context"] for c in json.load(open(os.environ["PIN_WIRING_POLICY_FILE"]))["promotion_checks"]}.items())
except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
    PROMO = []
    bad.append(f"required-checks.json has no readable promotion_checks ({type(e).__name__})")
# the protected check name belongs to its job alone: no other job of this workflow may produce a check run with such a name (a job named
# `allowlist` that succeeds after the real one failed satisfies admission, which accepts any success with the matching name), and no job
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
    for _base, _ctx in PROMO:
        if _base in (nm, jid_):
            bad.append(f"the job {jid_} produces the promotion check name {_ctx}, which the full suite's workflows make")
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
    for _base, _ctx in PROMO:
        _made = [_jid for _jid, _j in _jobs.items() if _base in (_jid, _j.get("name", _jid) if isinstance(_j, dict) else _jid)]
        if len(_made) > 1:
            bad.append(f"{_f}: {len(_made)} jobs produce the promotion check name {_ctx}")
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
case_ bash-env-on-step      bad "$pick['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ bash-env-on-job       bad "d['jobs']['allowlist']['env'] = {'BASH_ENV': '/tmp/x.sh'}"
case_ path-on-workflow      bad "d['env'] = {'PATH': '/tmp/fake:/usr/bin'}"
case_ github-env-write      bad "$steps.insert(1, {'run': 'echo BASH_ENV=/tmp/x.sh >> \"\$GITHUB_ENV\"'})"
case_ github-path-write     bad "$steps.insert(1, {'run': 'echo /tmp/fake >> \"\$GITHUB_PATH\"'})"
case_ checkout-other-ref    bad "$steps[0]['with'] = {'ref': 'main'}"

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
# the policy at the commit is read too: a missing allowlist entry is refused (and so is a missing file, above)

gitcase run-true-at-a-commit      bad "[s for s in $steps if (s.get('run') or '').strip().endswith('check-file-allowlist.sh')][0]['run'] = 'true'"
gitcase inserted-step-at-a-commit bad "$steps.insert(2, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
gitcase fetch-depth-at-a-commit   bad "$steps[0].pop('with')"

case_ job-needs-skipped          bad "d['jobs']['skip_guard'] = {'runs-on': 'ubuntu-latest', 'if': 'false', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist']['needs'] = 'skip_guard'"
bump() {
  echo "[s.__setitem__('uses', '$2') for s in d['jobs']['$1']['steps']" \
       "if s.get('uses', '').startswith('actions/setup-python@')]"
}
BUMPED=actions/setup-python@abababababababababababababababababababab
ALL_JOBS="allowlist"
for j in $ALL_JOBS; do case_ "uses-digest-bumped-$j" ok "$(bump $j $BUMPED)"; done

DIGEST=5fda3b95a4ea91299a34e894583c3862153e4b97
BAD_TAG=actions/setup-python@v7
BAD_SHORT=actions/setup-python@${DIGEST:0:39}
BAD_UPPER=actions/setup-python@${DIGEST^^}
BAD_NAME=evil/setup-python@$DIGEST
BAD_MARKER='actions/setup-python@<commit>'

want="the allowlist step 4 (set up Python for the selected suites) is not a judged action step"
case_msg uses-tag-ref-allowlist           "$(bump allowlist "$BAD_TAG")"    "$want"
case_msg uses-short-digest-allowlist      "$(bump allowlist "$BAD_SHORT")"  "$want"
case_msg uses-upper-digest-allowlist      "$(bump allowlist "$BAD_UPPER")"  "$want"
case_msg uses-other-action-name-allowlist "$(bump allowlist "$BAD_NAME")"   "$want"
case_msg uses-literal-marker-allowlist    "$(bump allowlist "$BAD_MARKER")" "$want"
case_msg uses-checkout-tag-ref-allowlist  "d['jobs']['allowlist']['steps'][0]['uses'] = 'actions/checkout@v4'" \
  "the allowlist step 1 (actions/checkout@v4) is not a judged action step"
case_ impersonate-allowlist   bad "d['jobs']['replacement'] = {'name': 'allowlist', 'runs-on': 'ubuntu-latest', 'steps': [{'run': 'true'}]}"
# a promotion context (the full suite's, read by stage-admission) comes from one workflow file:
# a second job with its name is refused
SECOND="{'name': 'coverage', 'runs-on': 'x', 'steps': [{'run': 'true'}]}"
case_ promotion-context-second-job bad "d['jobs']['second'] = $SECOND"
case_ job-name-expression     bad "d['jobs']['lint']['name'] = '\${{ matrix.x }}'"
case_ job-name-expr-spaced    ok  "d['jobs']['lint']['name'] = 'lint (\${{ matrix.x }})'"
case_ job-matrix-other        ok  "d['jobs']['lint']['strategy'] = {'matrix': {'x': ['1']}}"
case_ checks-write-job        bad "d['jobs']['lint']['permissions'] = {'checks': 'write'}"
case_ checks-write-all        bad "d['permissions'] = 'write-all'"
case_ checks-write-top        bad "d['permissions'] = {'contents': 'read', 'checks': 'write'}"
case_ name-expr-quoted        bad "d['jobs']['lint']['name'] = \"\${{ 'allowlist' || '}} ' }}\""
case_ name-expr-multiline     bad "d['jobs']['lint']['name'] = \"\${{\\n  'allowlist'\\n}}\""
case_ name-expr-function      bad "d['jobs']['lint']['name'] = \"x \${{ format('{0}', 'a') }}\""
case_ job-needs-list             bad "d['jobs']['allowlist']['needs'] = ['lint']"
case_ job-timeout                bad "d['jobs']['allowlist']['timeout-minutes'] = '1'"
case_ job-concurrency            bad "d['jobs']['allowlist']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
case_ job-concurrency-test       bad "d['jobs']['test']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
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
for mut in "name" "id" "expr" "garbage" "okexpr" "okshard" "checks" "checks-top" "quoted" "noperms"; do
  rm -rf "$work/wf-$mut"; mkdir -p "$work/wf-$mut"; cp "$here"/.github/workflows/*.y*ml "$work/wf-$mut/"
  case "$mut" in
    name) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    name: allowlist\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    id) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  allowlist:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
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
    name: "${{ 'allowlist' || '}} ' }}"
    runs-on: ubuntu-latest
    steps:
      - run: "true"
WF
      ;;
    okshard) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  allowlist-chain:\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
    okexpr) printf 'name: x\non: push\npermissions:\n  contents: read\njobs:\n  zz:\n    name: scan (${{ matrix.n }})\n    runs-on: ubuntu-latest\n    steps:\n      - run: "true"\n' > "$work/wf-$mut/zz.yml" ;;
  esac
  want=bad; case "$mut" in okexpr|okshard) want=ok ;; esac
  if out=$(PIN_WIRING_WORKFLOWS_DIR="$work/wf-$mut" judge "$here/.github/workflows/ci.yml"); then got=ok; else got=bad; fi
  if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "PASS other-workflow-$mut → $got"; else failn=$((failn+1)); echo "FAIL other-workflow-$mut → $got, want $want ($out)"; fi
done

# the required-check policy: the allowlist job must stay listed with integration 15368 and scope push (release admission reads them)
for mut in "drop" "scope" "integration" "null" "empty" "garbage" "dup" "notlist"; do
  python3 - "$here/.github/policy/required-checks.json" "$work/pol-$mut.json" "$mut" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); rc = d["required_checks"]
e = [c for c in rc if c["context"] == "allowlist"][0]
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


echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
