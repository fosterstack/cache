#!/usr/bin/env bash
# REQ-REL-005-AC1 (register row 78): the hygiene check runs the pin checker on every pull request and
# every push to main, and nothing can skip it or swallow its failure. (Mapped from the product matrix as
# workflow-job evidence: REQ-AUD-18 AC1 keeps .github/agent/ paths out of files outside it.)
# The real ci.yml must pass; each mutated copy must be caught.
set -euo pipefail
here=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

judge() { python3 - "$1" <<'PY'
import sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)   # every scalar a string, as GitHub reads it
bad = []
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
for k in ("if", "continue-on-error", "defaults"):
    if k in job:
        bad.append(f"the allowlist job has `{k}`")
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
risky = {"BASH_ENV", "ENV", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME"}
for where, env in [("the workflow", d.get("env")), ("the allowlist job", job.get("env"))] + \
        [(f"step {i}", st.get("env")) for i, st in enumerate(job.get("steps", []))]:
    if isinstance(env, dict):
        for k in sorted(set(env) & risky):
            bad.append(f"{where} sets env {k}")
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
def norm(r):  # drop comment lines; the command text itself must match exactly
    return "\n".join(l for l in (r or "").strip().splitlines() if not l.lstrip().startswith("#"))
steps_ = job.get("steps", [])
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
if len(idx["fetch"]) == 1 and len(idx["check"]) == 1 and not (0 < idx["fetch"][0] < idx["check"][0]):
    bad.append("the allowlist steps are not in order: checkout, base-ref fetch, check")
for w in sorted(want - seen):
    bad.append(f"no step runs `{w}`")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}

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

echo "pin-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
