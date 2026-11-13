#!/usr/bin/env bash
# proves: REQ-REL-008-AC1, REQ-REL-008-AC2, REQ-REL-008-AC3
# The ratified workflow consolidation (owner, Oct 2): go-freshness.yml keeps the freshness check on its daily schedule (and on a
# dispatch) and the weekly cron of persona-uat. The real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" "$root" <<'PY'
import os, subprocess, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
crons = [c.get("cron") for c in (d.get("on") or {}).get("schedule") or []]
daily, weekly = "23 6 * * *", "43 6 * * 1"
if sorted(crons) != sorted([daily, weekly]):
    bad.append("schedules are not exactly the daily freshness cron and the weekly persona-uat cron: %s" % crons)
if "workflow_dispatch" not in (d.get("on") or {}):
    bad.append("no workflow_dispatch")
c = (d.get("jobs") or {}).get("check")
if not c:
    bad.append("no freshness check job")
else:
    ci = str(c.get("if", "")).replace(" ", "")
    if "github.event.schedule=='%s'" % daily.replace(" ", "") not in ci or "github.event_name=='workflow_dispatch'" not in ci:
        bad.append("the freshness check is not guarded to the daily schedule (or dispatch)")
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
case_ weekly-cron-gone       bad "d['on']['schedule'] = [{'cron': '23 6 * * *'}]"
case_ check-unguarded         bad "$J['check'].pop('if')"
case_ no-dispatch             bad "d['on'].pop('workflow_dispatch')"

# ---------------------------------------------------------------------------------------------------------------------
# PR 2 of 4: ci.yml absorbs hygiene.yml and requirements.yml (REQ-REL-008-AC2). Every moved job
# keeps its exact check name, top-level placement, job permissions, environment, needs and condition; ci.yml's
# top-level permissions stay read-only and its one concurrency block is the reviewed one (judge_conc); every required check in
# .github/policy/required-checks.json is still produced by a top-level job of a workflow on its scope's event.
# dependabot-auto-merge.yml does NOT move: its events (pull_request only) differ from ci.yml's (advisor, 0051 check 3).
judge_ci() { python3 - "$1" "$root" <<'PY'
import glob, json, os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
MOVED = {   # job id -> (name, permissions, environment, needs, if) exactly as in the original file
    "allowlist": ("allowlist", None, None, None, None),
    "requirements": ("requirements", None, None, None, None),
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
if any(j.get("concurrency") for j in jobs.values()):
    bad.append("ci.yml gained a job-level concurrency setting")   # the one top-level block is judged by judge_conc
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
case_ci top-level-widened        bad "d['permissions']['contents'] = 'write'"
case_ci top-level-pr-write       bad "d['permissions']['pull-requests'] = 'write'"
case_ci allowlist-regains-block  bad "d['jobs']['allowlist']['permissions'] = {'contents': 'read'}"
case_ci concurrency-other-job    bad "d['jobs']['allowlist']['concurrency'] = {'group': 'x', 'cancel-in-progress': 'false'}"
case_ci merge-group-back         bad "d['on']['merge_group'] = ''"
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
# Codex #160 pin pass (B78-01): release-manifest data must never become shell source. Every matrix value is checked for
# its exact shape before the matrix is emitted (the collector's TARGET_SHAPE, run here against hostile targets), and no
# run: script interpolates ${{ matrix.* }} or ${{ needs.* }} (they arrive through env, quoted)
import json, re, subprocess
mrun = "\n".join(st.get("run") or "" for st in m.get("steps") or [])
shape = re.search(r"TARGET_SHAPE='([^']*)'", mrun)
if not shape or 'jq -e "$TARGET_SHAPE"' not in mrun:
    bad.append("the manifests job does not check every target's shape before emitting the matrix")
else:
    def ok(t):
        return subprocess.run(["jq", "-e", shape.group(1)], input=json.dumps([t]), capture_output=True, text=True).returncode == 0
    good = {"release": "v0.2.1", "variant": "production", "digest": "sha256:" + "a" * 64, "scanner": "grype"}
    if not ok(good) or not ok(dict(good, release="v0.3.0-rc.1")):
        bad.append("TARGET_SHAPE refuses a well-formed target")
    hostile = [dict(good, digest=good["digest"] + "$(docker run alpine:latest true)"),
               dict(good, variant="production'$(docker run alpine:latest true)'"),
               dict(good, release="v0.2.1$(id)"), dict(good, scanner="grype;id"), dict(good, digest=None),
               dict(good, digest="sha256:" + "A" * 64), {k: v for k, v in good.items() if k != "variant"}]
    for t in hostile:
        if ok(t):
            bad.append("TARGET_SHAPE accepts %r" % t)
for job in (m, r):
    for st in job.get("steps") or []:
        if re.search(r"\$\{\{\s*(matrix|needs)\.", st.get("run") or ""):
            bad.append("a run: script interpolates matrix/needs data: %s" % (st.get("name") or st.get("id")))
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
case_rescan shape-check-dropped   bad "s=[x for x in d['jobs']['manifests']['steps'] if 'TARGET_SHAPE' in (x.get('run') or '')][0]; s['run'] = s['run'].replace('jq -e \"\$TARGET_SHAPE\"', 'true')"
case_rescan shape-digest-loose    bad "s=[x for x in d['jobs']['manifests']['steps'] if 'TARGET_SHAPE' in (x.get('run') or '')][0]; s['run'] = s['run'].replace('{64}\$', '{64}')"
case_rescan digest-interpolated   bad "s=[x for x in d['jobs']['rescan']['steps'] if x.get('name') == 'enumerate platform children'][0]; s['run'] = s['run'] + '\necho \${{ matrix.target.digest }}'"

# ---------------------------------------------------------------------------------------------------------------------
# PR 4 of 4: acceptance-gradle.yml + acceptance-maven.yml -> acceptance.yml (REQ-REL-008-AC2), later one job `acceptance` that runs
# the Gradle suite, then the Maven suite once per extension version (1.2.0, 1.2.3); maven's scenario environment sits on the step that
# runs it. The workflow is not callable (release.yml does not call it, see REQ-CHAIN-006-AC10 below) and has no outputs.
judge_acc() { python3 - "$1" "$root" <<'PY'
import os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
on = d.get("on") or {}
if on.get("push") != {"branches": ["main"]} or "pull_request" not in on or "workflow_call" in on:
    bad.append("acceptance.yml's events changed: %s" % list(on))
jobs = d.get("jobs") or {}
a = jobs.get("acceptance") or {}
if list(jobs) != ["acceptance"] or a.get("name") != "acceptance" or a.get("permissions") != {"contents": "read"} or "strategy" in a or "outputs" in a:
    bad.append("acceptance is not the one job named acceptance with contents: read, no matrix and no outputs: %s" % list(jobs))
steps = a.get("steps") or []
maven = [s for s in steps if "bin/acceptance-maven.sh" in (s.get("run") or "")]
if len(maven) != 1 or "for v in 1.2.0 1.2.3; do" not in maven[0]["run"] or (maven[0].get("env") or {}) != {"COLD_LOOKUPS": "2", "COLD_UPLOADS": "5", "MODULES": "2"} or d.get("env"):
    bad.append("the Maven suite is not one step over both extension versions with its scenario environment")
if any("id" in s or "docker " in (s.get("run") or "") for s in steps):
    bad.append("acceptance has a results id or a docker command (it starts no container)")
if d.get("permissions") != {"contents": "read"}:
    bad.append("top-level permissions changed")
for gone in ("acceptance-gradle.yml", "acceptance-maven.yml"):
    if os.path.exists(os.path.join(root, ".github/workflows", gone)):
        bad.append("%s still exists" % gone)
rel = yaml.load(open(os.path.join(root, ".github/workflows/release.yml")), Loader=yaml.BaseLoader)["jobs"]
# REQ-CHAIN-006-AC10 (PR 3): the release chain no longer calls acceptance.yml (Check runs the shared suite scripts itself); the workflow stays for the PR gate
calls = [j for j, v in rel.items() if "acceptance" in str(v.get("uses", ""))]
if calls:
    bad.append("release.yml still calls an acceptance workflow (Check runs the suites): %s" % calls)
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_acc() {
  local f="$work/acc-$1.yml"
  cp "$root/.github/workflows/acceptance.yml" "$f" 2>/dev/null || : > "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge_acc "$f" 2>&1); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS acc:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL acc:$1 → $got, want $2 ($out)"; fi
}
case_acc real                  ok  ""
case_acc renamed               bad "d['jobs']['acceptance']['name'] = 'gradle'"
case_acc maven-version-cut     bad "[s.__setitem__('run', s['run'].replace('1.2.0 1.2.3', '1.2.3')) for s in d['jobs']['acceptance']['steps'] if 'bin/acceptance-maven.sh' in (s.get('run') or '')]"
case_acc env-at-top            bad "d['env'] = {'COLD_LOOKUPS': '2'}"
case_acc workflow-call-back    bad "d['on']['workflow_call'] = ''"
case_acc results-id-back       bad "d['jobs']['acceptance']['steps'][-2]['id'] = 'results'"
case_acc job-split-again       bad "d['jobs']['acceptance-gradle'] = d['jobs']['acceptance']"
case_acc no-pr-trigger         bad "d['on'].pop('pull_request')"

# ---------------------------------------------------------------------------------------------------------------------
# PR 5: release-chain-pr.yml -> scan.yml (REQ-REL-008-AC2; advisor read-back 0062). One build feeds both: scan's own
# assembly (which uploads oci-candidate) is assembly A, a verify-only assembly B uploads nothing (stage-image's artifact
# name stays unique); the required check `reproducibility` stays a top-level job with its exact name (since PR 2: `if: always()`, see below) and no
# token beyond contents read; release.yml's own reproducibility stage is untouched and stays the one the release relies on.
judge_scan() { python3 - "$1" "$root" <<'PY'
import os, subprocess, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
on = d.get("on") or {}
# exactly: an unfiltered pull_request (no types, branches, paths filter), pushes to main and v* tags (Codex #162 pin, R78-B1)
if on != {"pull_request": "", "push": {"branches": ["main"], "tags": ["v*"]}}:
    bad.append("scan.yml's events changed (pull requests, pushes to main and v* tags): %s" % on)
jobs = d.get("jobs") or {}
builds = [j for j, v in jobs.items() if v.get("uses") == "./.github/workflows/stage-build.yml"]
if builds != ["build"]:
    bad.append("not exactly one build feeds both: %s" % builds)
# PR 2 of the v0.3.0 chain (REQ-CHAIN-004-AC14, REQ-CHAIN-005-AC7): stage-image.yml is gone. The one build runs in SNAPSHOT mode and a snapshot Rebuild rebuilds
# everything on fresh runners and FAILS on any differing item (rule 31 is kept, in the Rebuild stage); the required check `reproducibility` keeps its exact name and
# no token beyond contents read, runs under exactly `if: always()` (a job that needs a failed job is SKIPPED, and a skipped required check counts as passing) and
# its one step fails unless ${{ needs.rebuild.result }} is exactly success. The old inline comparison of two assemblies' digests is replaced by that stage
# (bin/chain-rebuild-test.sh proves the comparison itself).
if any(v.get("uses") == "./.github/workflows/stage-image.yml" for v in jobs.values()):
    bad.append("a job still calls the deleted stage-image.yml")
if (jobs.get("build") or {}).get("with") != {"mode": "snapshot"}:
    bad.append("the one build is not a snapshot build: %s" % (jobs.get("build") or {}).get("with"))
rb = jobs.get("rebuild") or {}
if rb.get("uses") != "./.github/workflows/stage-reproducibility.yml" or rb.get("needs") != "build" or rb.get("with") != {"mode": "snapshot"}:
    bad.append("rebuild is not the snapshot Rebuild of the one build: %s" % rb)
r = jobs.get("reproducibility") or {}
# `if: always()` and nothing else: when `rebuild` FAILS, GitHub SKIPS a job that needs it, and branch protection counts a skipped required check as passing, so
# the required check must run in every case and fail unless rebuild succeeded (the pattern of the `scan` aggregate below; step-8 B1, Opus)
if r.get("name") != "reproducibility" or r.get("if") != "always()" or r.get("needs") != "rebuild":
    bad.append("reproducibility must be named reproducibility, need rebuild and carry exactly `if: always()`: %s" % {k: r.get(k) for k in ("name", "if", "needs")})
if r.get("permissions") not in (None, {"contents": "read"}):
    bad.append("reproducibility's token is wider than contents read: %s" % r.get("permissions"))
# fail closed (continue-on-error also hides a failure): the jobs the check rests on carry exactly the keys reviewed here
KEYS = {"build": {"permissions", "uses", "with"}, "rebuild": {"needs", "permissions", "uses", "with"},
        "reproducibility": {"name", "needs", "if", "runs-on", "steps"}}
for j, keys in KEYS.items():
    if set(jobs.get(j) or {}) - keys:
        bad.append("%s carries a key that can skip or soften it: %s" % (j, sorted(set(jobs.get(j) or {}) - keys)))
# what the job inherits: the workflow's token and shell (Codex #162 pin r2, R78-B4/B5)
if d.get("permissions") != {"contents": "read"} or set(d) - {"concurrency"} != {"name", "on", "permissions", "jobs"}:
    # fail closed: env (a PATH that fakes jq), defaults, concurrency … — every top-level key is reviewed (Sonnet #162
    # pin r3, NEW-B6 / R2)
    bad.append("the workflow's inherited settings changed: keys %s, permissions %s" % (sorted(d), d.get("permissions")))
if (jobs.get("reproducibility") or {}).get("runs-on") != "ubuntu-latest":
    bad.append("reproducibility runs elsewhere than a GitHub-hosted ubuntu runner: %s" % (jobs.get("reproducibility") or {}).get("runs-on"))
steps = r.get("steps") or []
RESULT = "${{ needs.rebuild.result }}"
if len(steps) != 1 or set(steps[0]) != {"name", "run"}:
    bad.append("the reproducibility job is not one plain step (name + run): %s" % [sorted(st) for st in steps])
else:
    run = steps[0]["run"]
    if run.count(RESULT) != 1 or "${{" in run.replace(RESULT, ""):
        bad.append("the reproducibility step must test ${{ needs.rebuild.result }} once and carry no other expression")
    else:
        # proven by running it: only the result `success` passes; failure, skipped and cancelled (and an empty result) fail
        def verdict(result):
            return subprocess.run(["bash", "-c", run.replace(RESULT, result)], capture_output=True, text=True).returncode
        if verdict("success") != 0:
            bad.append("the reproducibility step fails when rebuild succeeded")
        for result in ("failure", "skipped", "cancelled", ""):
            if verdict(result) == 0:
                bad.append("the reproducibility step passes when rebuild's result is %r" % result)
if "artifact-acceptance" in jobs:
    bad.append("scan.yml still has artifact-acceptance (REQ-CHAIN-006-AC10: its stage is gone; Check checks the Linux-only archive set)")
if os.path.exists(os.path.join(root, ".github/workflows/release-chain-pr.yml")):
    bad.append("release-chain-pr.yml still exists")
rel = yaml.load(open(os.path.join(root, ".github/workflows/release.yml")), Loader=yaml.BaseLoader)["jobs"]
if (rel.get("rebuild") or {}).get("uses") != "./.github/workflows/stage-reproducibility.yml":
    bad.append("release.yml's own Rebuild stage changed (PR 2 renamed its reproducibility job to rebuild)")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_scan() {
  local f="$work/scan-$1.yml"
  cp "$root/.github/workflows/scan.yml" "$f"
  if [ -n "$3" ]; then python3 - "$f" "$3" <<'PY'
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  fi
  if out=$(judge_scan "$f" 2>&1); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS scan:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL scan:$1 → $got, want $2 ($out)"; fi
}
case_scan real                   ok  ""
case_scan tags-dropped           bad "d['on']['push'].pop('tags')"
case_scan event-added            bad "d['on']['workflow_dispatch'] = ''"
case_scan second-build           bad "d['jobs']['build-b'] = dict(d['jobs']['build'])"
case_scan build-release-mode     bad "d['jobs']['build']['with'] = {'mode': 'release'}"
case_scan stage-image-back       bad "d['jobs']['assemble'] = {'needs': 'build', 'uses': './.github/workflows/stage-image.yml'}"
case_scan rebuild-release-mode   bad "d['jobs']['rebuild']['with'] = {'mode': 'release'}"
case_scan rebuild-gone           bad "d['jobs'].pop('rebuild')"
case_scan rebuild-ungated        bad "d['jobs']['rebuild'].pop('needs')"
case_scan rebuild-coe            bad "d['jobs']['rebuild']['continue-on-error'] = 'true'"
case_scan repro-skippable        bad "d['jobs']['reproducibility']['if'] = \"github.event_name == 'pull_request'\""
case_scan repro-if-removed       bad "d['jobs']['reproducibility'].pop('if')"
case_scan repro-if-success       bad "d['jobs']['reproducibility']['if'] = \"\${{ success() }}\""
case_scan repro-only-echoes      bad "d['jobs']['reproducibility']['steps'][0]['run'] = 'echo identical'"
case_scan repro-tests-build      bad "s = d['jobs']['reproducibility']['steps'][0]; s['run'] = s['run'].replace('needs.rebuild.result', 'needs.build.result')"
case_scan repro-ignores-result   bad "s = d['jobs']['reproducibility']['steps'][0]; s['run'] += ' || true'"
case_scan repro-accepts-skipped  bad "s = d['jobs']['reproducibility']['steps'][0]; s['run'] = s['run'].replace('= \"success\" ]', '!= \"failure\" ]')"
case_scan repro-result-twice     bad "s = d['jobs']['reproducibility']['steps'][0]; s['run'] += '; echo \${{ needs.rebuild.result }}'"
case_scan repro-extra-expression bad "s = d['jobs']['reproducibility']['steps'][0]; s['run'] += '; echo \${{ github.sha }}'"
case_scan repro-renamed          bad "d['jobs']['reproducibility']['name'] = 'reproducible'"
case_scan repro-widened          bad "d['jobs']['reproducibility']['permissions'] = {'contents': 'read', 'packages': 'write'}"
case_scan repro-not-after-rebuild bad "d['jobs']['reproducibility']['needs'] = 'build'"
case_scan pr-types-closed        bad "d['on']['pull_request'] = {'types': ['closed']}"
case_scan pr-branches-ignore     bad "d['on']['pull_request'] = {'branches-ignore': ['main']}"
case_scan pr-paths               bad "d['on']['pull_request'] = {'paths': ['never/**']}"
case_scan compare-step-off       bad "d['jobs']['reproducibility']['steps'][0]['if'] = '\${{ false }}'"
case_scan step-continue-on-error  bad "d['jobs']['reproducibility']['steps'][0]['continue-on-error'] = 'true'"
case_scan job-continue-on-error   bad "d['jobs']['reproducibility']['continue-on-error'] = 'true'"
case_scan build-coe               bad "d['jobs']['build']['continue-on-error'] = 'true'"
case_scan repro-matrix            bad "d['jobs']['reproducibility']['strategy'] = {'matrix': {'x': ['1']}}"
case_scan defaults-shell-true    bad "d['defaults'] = {'run': {'shell': 'true {0}'}}"
case_scan workflow-token-write   bad "d['permissions']['contents'] = 'write'"
case_scan workflow-env-path      bad "d['env'] = {'PATH': '/tmp/evil:/usr/bin:/bin'}"
case_scan repro-self-hosted      bad "d['jobs']['reproducibility']['runs-on'] = 'self-hosted'"

# ---------------------------------------------------------------------------------------------------------------------
# REQ-REL-008-AC1 (owner RATIFIED Oct 2): the workflow directory holds exactly the ratified files and nothing else, so
# no workflow sprawls. Today's 19 are the consolidation's "keep" rows, the attestation-signer stages and
# dependabot-auto-merge.yml. Two files are admitted beyond them: stage-sign.yml (v0.3.0 rule 52, owner Oct 9) and customer-words-edited.yml (decision 98, Oct 3).
# The history of the count (24, 25, 26, 24, 19) is in the git log of this file.
ratified="acceptance.yml agent-review-gate.yml auditor.yml ci.yml dependabot-auto-merge.yml dependabot-reviewer.yml
go-freshness.yml main-candidate-rescan.yml release.yml reserved-branch-guard.yml scan.yml scorecard.yml
stage-build.yml stage-promote.yml stage-reproducibility.yml stage-verify.yml
stage-sign.yml supply-chain.yml customer-words-edited.yml"
judge_set() {  # $1: the directory's entries as a JSON list (every entry, not only *.yml)
  python3 - "$1" "$ratified" <<'PY'
import json, sys
got, want = json.loads(sys.argv[1]), sys.argv[2].split()
if len(want) != 19:
    print("the ratified list is not 19 files (rule 52 and the owner's Oct 3 amendment admit the two new files)")
    sys.exit(1)
odd = [n for n in got if "\n" in n or "/" in n]
extra, missing = sorted(set(got) - set(want)), sorted(set(want) - set(got))
if odd or extra or missing or len(got) != len(set(got)):
    print("extra: %s missing: %s odd names: %s (the list is rule 52 and the owner's Oct 3 amendment: "
          "stage-sign.yml and customer-words-edited.yml)" % (extra, missing, odd)); sys.exit(1)
print("ok")
PY
}
case_set() {
  if out=$(judge_set "$3"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS set:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL set:$1 → $got, want $2 ($out)"; fi
}
case_cites() { # case_cites NAME SET: the refusal names rule 52 and the owner's Oct 3 amendment (the two new files)
  out=$(judge_set "$2") || true
  if [[ "$out" == *"rule 52"* && "$out" == *"Oct 3"* ]]; then pass=$((pass+1)); echo "PASS cites:$1 ($out)"
  else failn=$((failn+1)); echo "FAIL cites:$1 → the refusal does not name rule 52 and the Oct 3 amendment ($out)"; fi
}
# every entry of the directory, unfiltered: a non-YAML file or a name with a newline is a difference (Codex #162 pin, R78-B3)
real_set=$(python3 -c 'import json, os, sys; print(json.dumps(sorted(os.listdir(sys.argv[1]))))' "$root/.github/workflows")
edit_set() { python3 -c 'import json, sys; s = json.loads(sys.argv[1]); exec(sys.argv[2]); print(json.dumps(s))' "$real_set" "$1"; }
case_set real          ok  "$real_set"
case_set a-new-file    bad "$(edit_set 's.append("sprawl.yml")')"
case_set a-third-new-file bad "$(edit_set 's.append("stage-extra.yml")')"
case_set letter-back   bad "$(edit_set 's.append("evidence-letter.yml")')"
case_cites a-third-new-file "$(edit_set 's.append("stage-extra.yml")')"
case_cites letter-back "$(edit_set 's.append("evidence-letter.yml")')"
case_set a-non-yaml    bad "$(edit_set 's.append("README.txt")')"
case_set one-missing   bad "$(edit_set 's.remove("go-freshness.yml")')"
case_set newline-name  bad "$(edit_set 's.remove("go-freshness.yml"); s.remove("scorecard.yml"); s.append("go-freshness.yml\nscorecard.yml")')"
case_set codeql-back   bad "$(edit_set 's.append("codeql.yml")')"
case_set back-to-old   bad "$(edit_set 's.remove("acceptance.yml"); s.append("acceptance-gradle.yml")')"

# ---------------------------------------------------------------------------------------------------------------------
# PR concurrency (advisor, Oct 22: superseded pull-request runs starved the merge train). ci, scan, supply-chain and acceptance each carry ONE
# top-level concurrency block: a pull request's FIRST run attempt of a workflow shares a group with that pull request's other first attempts, so a newer push cancels its older
# run; NOTHING ELSE is ever cancelled or replaced: every other run (a re-run of any head, a push to main, a tag, a schedule, a manual dispatch, a workflow_call, a merge_group)
# gets a group of its own per run and attempt. The prefix is a literal per workflow (not github.workflow), so no workflow name can collide with another's group. Supply-chain's
# daily-audit job keeps its own job-level group; no other job has one. A duplicate YAML key anywhere is refused (GitHub rejects it, so a required check would never run).
judge_conc() {  # $1: a workflow file, $2: its key (ci scan supply-chain acceptance)
  python3 - "$1" "$2" <<'PY'
import sys, yaml
text = open(sys.argv[1]).read()
key = sys.argv[2]
bad = []
dups = []
def walk(n, path):
    if isinstance(n, yaml.MappingNode):
        seen = set()
        for k, v in n.value:
            kk = k.value if isinstance(k, yaml.ScalarNode) else None
            if kk in seen:
                dups.append(path + "/" + str(kk))
            seen.add(kk)
            walk(v, path + "/" + str(kk))
    elif isinstance(n, yaml.SequenceNode):
        for i, v in enumerate(n.value):
            walk(v, path + "/" + str(i))
walk(yaml.compose(text, Loader=yaml.BaseLoader), "")
if dups:
    bad.append("duplicate YAML key(s): " + ", ".join(dups[:5]))
d = yaml.load(text, Loader=yaml.BaseLoader)
pfx = key
grp = "${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('%s-pr-{0}', github.event.pull_request.number) || format('%s-{0}-{1}', github.run_id, github.run_attempt) }}" % (pfx, pfx)
want = {"group": grp, "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}
if d.get("concurrency") != want:
    bad.append("%s's top-level concurrency is not the reviewed block: %s" % (key, d.get("concurrency")))
jobs = d.get("jobs") or {}
for jid, j in jobs.items():
    c = j.get("concurrency")
    if key == "supply-chain" and jid == "daily-audit":
        if c != {"group": "supply-chain-daily", "cancel-in-progress": "false"}:
            bad.append("supply-chain daily-audit's own group changed: %s" % c)
    elif c:
        bad.append("job %s carries a concurrency setting: %s" % (jid, c))
if key == "supply-chain" and "daily-audit" not in jobs:
    bad.append("supply-chain lost its daily-audit job")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_conc() {  # name want key edit   (edit: python on the parsed workflow d; empty = the real file)
  local k="$3" f="$work/conc-$1.yml"
  cp "$root/.github/workflows/$k.yml" "$f"
  if [ -n "$4" ]; then python3 - "$f" "$4" <<'PY' || true   # a mutation that cannot apply leaves the file as it is
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False, width=10000)
PY
  fi
  if out=$(judge_conc "$f" "$k"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS conc:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL conc:$1 → $got, want $2 ($out)"; fi
}
case_conc_raw() {  # name want key python-on-the-text (a string edit of the raw file: duplicate keys cannot survive a parse)
  local k="$3" f="$work/conc-$1.yml"
  cp "$root/.github/workflows/$k.yml" "$f"
  python3 - "$f" "$4" <<'PY'
import sys
p, edit = sys.argv[1], sys.argv[2]
t = open(p).read()
exec(edit)
open(p, "w").write(t)
PY
  if out=$(judge_conc "$f" "$k"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS conc:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL conc:$1 → $got, want $2 ($out)"; fi
}
for k in ci scan supply-chain acceptance; do
  case_conc "$k-real"                 ok  "$k" ""
  case_conc "$k-missing"              bad "$k" "d.pop('concurrency', None)"
  case_conc "$k-cancels-every-event"  bad "$k" "d['concurrency']['cancel-in-progress'] = 'true'"
  case_conc "$k-not-main-only"        bad "$k" "d['concurrency']['cancel-in-progress'] = \"\${{ github.ref != 'refs/heads/main' }}\""
  case_conc "$k-shared-ref-group"     bad "$k" "d['concurrency']['group'] = '\${{ github.workflow }}-\${{ github.event.pull_request.number || github.ref }}'"
  case_conc "$k-fixed-group"          bad "$k" "d['concurrency']['group'] = '$k'"
  case_conc "$k-never-cancels"        bad "$k" "d['concurrency']['cancel-in-progress'] = 'false'"
  case_conc "$k-rerun-shares-group"   bad "$k" "d['concurrency']['group'] = d['concurrency']['group'].replace(\" && github.run_attempt == '1'\", '')"
  case_conc "$k-workflow-name-prefix" bad "$k" "d['concurrency']['group'] = d['concurrency']['group'].replace(\"'$k-pr-{0}', \", \"'{0}-pr-{1}', github.workflow, \").replace(\"'$k-{0}-{1}', \", \"'{0}-{1}-{2}', github.workflow, \")"
  case_conc "$k-other-workflows-prefix" bad "$k" "d['concurrency']['group'] = d['concurrency']['group'].replace('$k-', 'other-')"
  case_conc "$k-job-level-added"      bad "$k" "list(d['jobs'].values())[0]['concurrency'] = {'group': 'x', 'cancel-in-progress': 'true'}"
  case_conc_raw "$k-duplicate-key"    bad "$k" "t = t.replace('\nconcurrency:\n', '\nconcurrency: {group: shared, cancel-in-progress: true}\nconcurrency:\n', 1)"
done
case_conc supply-chain-daily-group-dropped bad supply-chain "d['jobs']['daily-audit'].pop('concurrency')"
case_conc supply-chain-daily-cancels bad supply-chain "d['jobs']['daily-audit']['concurrency']['cancel-in-progress'] = 'true'"
case_conc ci-live-test-group-back bad ci "d['jobs']['test']['concurrency'] = {'group': 'vex-live-test', 'cancel-in-progress': 'false'}"

# The fixer is retired (row 76): no job in ci.yml dispatches it.
if grep -q "drift-fixer-dispatch" "$root/.github/workflows/ci.yml"; then
  echo "FAIL: ci.yml holds the retired drift-fixer-dispatch job"; failn=$((failn+1))
else echo "ok: ci.yml has no drift-fixer-dispatch job"; pass=$((pass+1)); fi

echo "workflow-consolidation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
