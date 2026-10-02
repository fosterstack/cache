#!/usr/bin/env bash
# proves: REQ-REL-008-AC2, REQ-REL-008-AC3
# The ratified workflow consolidation (owner, Oct 2), mutation into go-freshness: the mutation job runs weekly on its
# own schedule and the freshness check daily on its own, each guarded by the schedule that fired, a dispatch runs
# both, mutation.yml is gone, the docs link points to go-freshness.yml. The real workflow must pass; each mutated
# copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" "$root" <<'PY'
import os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
crons = [c.get("cron") for c in (d.get("on") or {}).get("schedule") or []]
daily, weekly = "23 6 * * *", "43 6 * * 1"
if sorted(crons) != sorted([daily, weekly]):
    bad.append("schedules are not exactly the daily freshness cron and the weekly mutation cron: %s" % crons)
if "workflow_dispatch" not in (d.get("on") or {}):
    bad.append("no workflow_dispatch")
jobs = d.get("jobs") or {}
m, c = jobs.get("mutation"), jobs.get("check")
if not m or m.get("name") != "mutation":
    bad.append("no mutation job named mutation")
if not c:
    bad.append("no freshness check job")
if m and c:
    mi, ci = str(m.get("if", "")).replace(" ", ""), str(c.get("if", "")).replace(" ", "")
    if "github.event.schedule=='%s'" % weekly.replace(" ", "") not in mi or "github.event_name=='workflow_dispatch'" not in mi:
        bad.append("the mutation job is not guarded to the weekly schedule (or dispatch)")
    if "github.event.schedule=='%s'" % daily.replace(" ", "") not in ci or "github.event_name=='workflow_dispatch'" not in ci:
        bad.append("the freshness check is not guarded to the daily schedule (or dispatch)")
    if not any("gremlins" in (s.get("run") or "") for s in m.get("steps") or []):
        bad.append("the mutation job does not run gremlins")
    import re as _re
    # EVERY `go install` target, one by one: module@<full commit> (a tag, a branch, @latest or no version fails). The run
    # text is split into words the way the shell splits them (escapes and quotes undone: g\o is go), command by command.
    import shlex
    targets, unparsed = [], []
    for st in m.get("steps") or []:
        lx = shlex.shlex(st.get("run") or "", posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        lx.commenters = "#"
        try:
            words = list(lx)
        except ValueError:
            unparsed.append(st.get("name")); continue
        for i in range(len(words) - 1):
            if words[i].rsplit("/", 1)[-1] == "go" and words[i + 1] == "install":
                rest = [w for w in words[i + 2:] if not w.startswith("-")]
                targets.append(rest[0] if rest else "")
    if unparsed or not targets or not all(_re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", t) for t in targets):
        bad.append("a go install in the mutation job is not pinned to a full commit: %s %s" % (targets, unparsed))
if os.path.exists(os.path.join(root, ".github/workflows/mutation.yml")):
    bad.append("mutation.yml still exists")
doc = open(os.path.join(root, "docs/quality/mutation.md")).read()
if "workflows/go-freshness.yml" not in doc or "workflows/mutation.yml" in doc:
    bad.append("docs/quality/mutation.md does not link to go-freshness.yml")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/go-freshness.yml" "$f"
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
J='d["jobs"]'
case_ real                    ok  ""
case_ mutation-daily          bad "d['on']['schedule'] = [{'cron': '23 6 * * *'}]"
case_ mutation-unguarded      bad "$J['mutation'].pop('if')"
case_ check-unguarded         bad "$J['check'].pop('if')"
case_ no-dispatch             bad "d['on'].pop('workflow_dispatch')"
case_ mutation-renamed        bad "$J['mutation']['name'] = 'mutation testing'"
case_ no-gremlins             bad "$J['mutation']['steps'] = [s for s in $J['mutation']['steps'] if 'gremlins' not in (s.get('run') or '')]"
case_ gremlins-by-tag          bad "s=[x for x in $J['mutation']['steps'] if 'go install' in (x.get('run') or '')][0]; s['run'] = s['run'].replace('@e05b1d47b8c55748e50abc28ff6b132c536bacca', '@latest')"
case_ second-install-by-tag    bad "s=[x for x in $J['mutation']['steps'] if 'go install' in (x.get('run') or '')][0]; s['run'] = 'go install github.com/x/y@latest; ' + s['run']"
case_ install-no-version      bad "s=[x for x in $J['mutation']['steps'] if 'go install' in (x.get('run') or '')][0]; s['run'] = s['run'] + '\\ngo install github.com/x/y'"
case_ escaped-go-by-tag        bad "s=[x for x in $J['mutation']['steps'] if 'go install' in (x.get('run') or '')][0]; s['run'] = s['run'] + '\\ng\\\\o install github.com/x/y@v0.6.0'"
case_ quoted-go-by-tag        bad "s=[x for x in $J['mutation']['steps'] if 'go install' in (x.get('run') or '')][0]; s['run'] = s['run'] + '\\n\\\"go\\\" install github.com/x/y@v0.6.0'"
case_ full-path-go-by-tag     bad "s=[x for x in $J['mutation']['steps'] if 'go install' in (x.get('run') or '')][0]; s['run'] = s['run'] + '\\n/usr/local/go/bin/go install github.com/x/y@main'"
case_ guards-swapped           bad "a, b = $J['mutation']['if'], $J['check']['if']; $J['mutation']['if'], $J['check']['if'] = b, a"

# ---------------------------------------------------------------------------------------------------------------------
# PR 2 of 4: ci.yml absorbs hygiene.yml, requirements.yml and dependency-review.yml (REQ-REL-008-AC2). Every moved job
# keeps its exact check name, top-level placement, job permissions, environment, needs and condition; ci.yml's
# top-level permissions stay read-only and it gains no concurrency; dependency-review runs only on pull requests (the
# only scope it is required on); every required check in .github/policy/required-checks.json is still produced by a
# top-level job of a workflow on its scope's event. dependabot-auto-merge.yml does NOT move: its events
# (pull_request only) differ from ci.yml's (advisor, 0051 check 3).
judge_ci() { python3 - "$1" "$root" <<'PY'
import glob, json, os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
MOVED = {   # job id -> (name, permissions, environment, needs, if) exactly as in the original file
    "allowlist": ("allowlist", None, None, None, None),
    "required-check-guard": ("required-check guard", {"contents": "read", "issues": "write"}, None, None, None),
    "drift-fixer-dispatch": ("dispatch the fixer for required-check drift", {"contents": "read"}, "agent", "required-check-guard",
                             "${{ always() && github.event_name == 'push' && github.ref == 'refs/heads/main' && needs.required-check-guard.outputs.drift_issue != '' }}"),
    "requirements": ("requirements", None, None, None, None),
    "dependency-review": (None, {"contents": "read", "pull-requests": "write"}, None, None, "${{ github.event_name == 'pull_request' }}"),
}
jobs = d.get("jobs") or {}
for jid, (name, perms, env, needs, cond) in MOVED.items():
    j = jobs.get(jid)
    if j is None:
        bad.append("job %s is not in ci.yml" % jid); continue
    got = (j.get("name"), j.get("permissions"), j.get("environment"), j.get("needs"), j.get("if"))
    if got != (name, perms, env, needs, cond):
        bad.append("job %s changed: %s" % (jid, got))
    if "uses" in j:
        bad.append("job %s is reached through uses: (its check would be renamed)" % jid)
if d.get("permissions") != {"contents": "read"}:
    bad.append("ci.yml's top-level permissions changed: %s" % d.get("permissions"))
if d.get("concurrency") or any(j.get("concurrency") for j in jobs.values()):
    bad.append("ci.yml gained a concurrency setting")
if d.get("on") != {"push": {"branches": ["main"]}, "pull_request": ""}:
    bad.append("ci.yml's events changed: %s" % d.get("on"))
for gone in ("hygiene.yml", "requirements.yml", "dependency-review.yml"):
    if os.path.exists(os.path.join(root, ".github/workflows", gone)):
        bad.append("%s still exists" % gone)
if not os.path.exists(os.path.join(root, ".github/workflows/dependabot-auto-merge.yml")):
    bad.append("dependabot-auto-merge.yml was moved, but its events differ from ci.yml's")
# every required check is produced by a top-level job (name or id) of some workflow, on its scope's event
names = {}
for wf in glob.glob(os.path.join(root, ".github/workflows/*.yml")):
    w = d if os.path.basename(wf) == "ci.yml" else yaml.load(open(wf), Loader=yaml.BaseLoader)
    on = w.get("on") or {}
    events = set(on) if isinstance(on, dict) else {on}
    for jid, j in (w.get("jobs") or {}).items():
        if "uses" in j:
            continue
        names.setdefault(j.get("name") or jid, set()).update(events)
for rc in json.load(open(os.path.join(root, ".github/policy/required-checks.json")))["required_checks"]:
    ev = "push" if rc["scope"] == "push" else "pull_request"
    if rc["integration_id"] != 15368:
        continue                                    # the review gate's App check, published by the App, not a job
    if not any(n == rc["context"] or n.split(" (")[0] == rc["context"].split(" (")[0] for n in names) or \
            not any(ev in evs for n, evs in names.items() if n == rc["context"] or n.split(" (")[0] == rc["context"].split(" (")[0]):
        bad.append("required check %r is no longer produced on %s" % (rc["context"], ev))
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_ci() {
  local f="$work/ci-$1.yml"
  cp "$root/.github/workflows/ci.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge_ci "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS ci:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL ci:$1 → $got, want $2 ($out)"; fi
}
case_ci real                     ok  ""
case_ci allowlist-renamed        bad "d['jobs']['allowlist']['name'] = 'file allowlist'"
case_ci requirements-dropped     bad "d['jobs'].pop('requirements')"
case_ci guard-widened            bad "d['jobs']['required-check-guard']['permissions']['contents'] = 'write'"
case_ci drift-no-environment     bad "d['jobs']['drift-fixer-dispatch'].pop('environment')"
case_ci review-on-push-too       bad "d['jobs']['dependency-review'].pop('if')"
case_ci top-level-widened        bad "d['permissions']['contents'] = 'write'"
case_ci concurrency-added        bad "d['concurrency'] = {'group': 'ci', 'cancel-in-progress': 'true'}"
case_ci events-changed           bad "d['on'].pop('pull_request')"
case_ci required-check-gone      bad "d['jobs']['lint']['name'] = 'lint-go'"

# ---------------------------------------------------------------------------------------------------------------------
# PR 3 of 4: main-candidate-rescan.yml absorbs daily-rescan.yml under its ONE schedule (the auditor finds its run by this
# file's name and must never pick a run that lacks the candidate); rescan-v010.yml (a one-shot) is deleted and
# SECURITY.md links its historical run instead of the vanished workflow page (REQ-REL-008-AC2).
judge_rescan() { python3 - "$1" "$root" <<'PY'
import os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
jobs = d.get("jobs") or {}
crons = [c.get("cron") for c in (d.get("on") or {}).get("schedule") or []]
if crons != ["41 7 * * *"]:
    bad.append("main-candidate-rescan.yml must keep exactly its one 07:41 schedule: %s" % crons)
m, r = jobs.get("manifests") or {}, jobs.get("rescan") or {}
if m.get("name") != "enumerate release manifests" or m.get("needs") or m.get("if"):
    bad.append("the manifests job changed: %s" % {k: m.get(k) for k in ("name", "needs", "if")})
if (r.get("needs"), r.get("if"), r.get("permissions")) != ("manifests", "needs.manifests.outputs.any == 'true'",
                                                           {"contents": "read", "issues": "write", "packages": "read"}):
    bad.append("the rescan job changed: %s" % {k: r.get(k) for k in ("needs", "if", "permissions")})
if not r.get("strategy") or "fromJSON(needs.manifests.outputs.targets)" not in str(r.get("strategy")).replace(" ", ""):
    bad.append("the rescan matrix no longer comes from the manifests job")
for gone in ("daily-rescan.yml", "rescan-v010.yml"):
    if os.path.exists(os.path.join(root, ".github/workflows", gone)):
        bad.append("%s still exists" % gone)
sec = open(os.path.join(root, "SECURITY.md")).read()
if "actions/workflows/rescan-v010.yml" in sec or "actions/runs/34551059239" not in sec:
    bad.append("SECURITY.md does not link the historical v0.1.0 rescan run")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_rescan() {
  local f="$work/mcr-$1.yml"
  cp "$root/.github/workflows/main-candidate-rescan.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge_rescan "$f"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS rescan:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL rescan:$1 → $got, want $2 ($out)"; fi
}
case_rescan real                  ok  ""
case_rescan second-cron           bad "d['on']['schedule'].append({'cron': '11 7 * * *'})"
case_rescan manifests-renamed     bad "d['jobs']['manifests']['name'] = 'manifests'"
case_rescan rescan-widened        bad "d['jobs']['rescan']['permissions']['contents'] = 'write'"
case_rescan rescan-unconditional  bad "d['jobs']['rescan'].pop('if')"
case_rescan matrix-lost           bad "d['jobs']['rescan'].pop('strategy')"
echo "workflow-consolidation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
