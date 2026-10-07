#!/usr/bin/env bash
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

judge() { python3 - "$1" <<'PY'
import sys, yaml
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
for k in sorted(set(d) - {"name", "on", "permissions", "jobs"}):
    bad.append(f"the workflow sets `{k}`")
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
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}

# judge mode, for the trusted review gate: judge the ci.yml of one commit of the current repo, read as a git
# object (never checked out, never run), and nothing else
if [ -n "${PIN_WIRING_JUDGE_GIT:-}" ]; then
  git show "${PIN_WIRING_JUDGE_GIT}:.github/workflows/ci.yml" > "$work/head-ci.yml" || { echo "pin-wiring: no ci.yml at ${PIN_WIRING_JUDGE_GIT}" >&2; exit 1; }
  judge "$work/head-ci.yml" && exit 0
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
gitcase run-true-at-a-commit      bad "[s for s in $steps if (s.get('run') or '').strip().endswith('check-file-allowlist.sh')][0]['run'] = 'true'"
gitcase inserted-step-at-a-commit bad "$steps.insert(2, {'run': 'git update-ref refs/remotes/origin/main HEAD'})"
gitcase fetch-depth-at-a-commit   bad "$steps[0].pop('with')"

case_ job-needs-skipped          bad "d['jobs']['skip_guard'] = {'runs-on': 'ubuntu-latest', 'if': 'false', 'steps': [{'run': 'true'}]}; d['jobs']['allowlist']['needs'] = 'skip_guard'"
case_ job-needs-list             bad "d['jobs']['allowlist']['needs'] = ['lint']"
case_ job-timeout                bad "d['jobs']['allowlist']['timeout-minutes'] = '1'"
case_ job-concurrency            bad "d['jobs']['allowlist']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
case_ wf-concurrency             bad "d['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
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

echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
