#!/usr/bin/env bash
# proves: REQ-REL-008-AC1, REQ-REL-008-AC2, REQ-REL-008-AC3
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
# PR 4 of 4: acceptance-gradle.yml + acceptance-maven.yml -> acceptance.yml (REQ-REL-008-AC2). Same events; both jobs
# keep their check names (acceptance-gradle; acceptance-maven (1.2.0) / (1.2.3) from the matrix), permissions and
# results outputs; maven's scenario environment moves onto its job unchanged; release.yml calls the one file and hands
# both results to the acceptance predicate.
judge_acc() { python3 - "$1" "$root" <<'PY'
import os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
on = d.get("on") or {}
if on.get("push") != {"branches": ["main"]} or "pull_request" not in on or "workflow_call" not in on:
    bad.append("acceptance.yml's events changed: %s" % list(on))
outs = (on.get("workflow_call") or {}).get("outputs") or {}
if {k: v.get("value") for k, v in outs.items()} != {"gradle-results": "${{ jobs.acceptance-gradle.outputs.results }}",
                                                   "maven-results": "${{ jobs.acceptance-maven.outputs.results }}"}:
    bad.append("the workflow_call outputs are not both suites' results: %s" % outs)
jobs = d.get("jobs") or {}
g, m = jobs.get("acceptance-gradle") or {}, jobs.get("acceptance-maven") or {}
if g.get("name") != "acceptance-gradle" or g.get("permissions") != {"contents": "read", "packages": "read"}:
    bad.append("acceptance-gradle changed: %s" % {k: g.get(k) for k in ("name", "permissions")})
if m.get("name") != "acceptance-maven" or m.get("permissions") != {"contents": "read", "packages": "read"} or \
        (m.get("strategy") or {}).get("matrix", {}).get("extension-version") != ["1.2.0", "1.2.3"]:
    bad.append("acceptance-maven changed: %s" % {k: m.get(k) for k in ("name", "permissions", "strategy")})
if m.get("env") != {"COLD_LOOKUPS": "2", "COLD_UPLOADS": "5", "MODULES": "2"} or d.get("env"):
    bad.append("maven's scenario environment did not move onto its job unchanged")
if d.get("permissions") != {"contents": "read"}:
    bad.append("top-level permissions changed")
for gone in ("acceptance-gradle.yml", "acceptance-maven.yml"):
    if os.path.exists(os.path.join(root, ".github/workflows", gone)):
        bad.append("%s still exists" % gone)
rel = yaml.load(open(os.path.join(root, ".github/workflows/release.yml")), Loader=yaml.BaseLoader)["jobs"]
calls = [j for j, v in rel.items() if "acceptance" in str(v.get("uses", "")) and "stage-" not in str(v.get("uses", ""))]
if calls != ["acceptance"] or rel["acceptance"].get("uses") != "./.github/workflows/acceptance.yml":
    bad.append("release.yml does not call acceptance.yml once: %s" % calls)
pred = (rel.get("acceptance-predicate") or {}).get("with") or {}
if pred.get("gradle-results") != "${{ needs.acceptance.outputs.gradle-results }}" or \
        pred.get("maven-results") != "${{ needs.acceptance.outputs.maven-results }}":
    bad.append("the predicate does not receive both results")
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
case_acc gradle-renamed        bad "d['jobs']['acceptance-gradle']['name'] = 'gradle'"
case_acc maven-matrix-cut      bad "d['jobs']['acceptance-maven']['strategy']['matrix']['extension-version'] = ['1.2.3']"
case_acc env-at-top            bad "d['env'] = d['jobs']['acceptance-maven'].pop('env')"
case_acc output-lost           bad "d['on']['workflow_call']['outputs'].pop('maven-results')"
case_acc no-pr-trigger         bad "d['on'].pop('pull_request')"

# ---------------------------------------------------------------------------------------------------------------------
# PR 5: release-chain-pr.yml -> scan.yml (REQ-REL-008-AC2; advisor read-back 0062). One build feeds both: scan's own
# assembly (which uploads oci-candidate) is assembly A, a verify-only assembly B uploads nothing (stage-image's artifact
# name stays unique); the required check `reproducibility` stays a top-level job with its exact name, no condition and no
# token beyond contents read; release.yml's own reproducibility stage is untouched and stays the one the release relies on.
judge_scan() { python3 - "$1" "$root" <<'PY'
import os, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
root = sys.argv[2]
bad = []
on = d.get("on") or {}
# exactly: an unfiltered pull_request (no types, branches, paths filter), pushes to main and v* tags (Codex #162 pin, R78-B1)
if on != {"pull_request": "", "push": {"branches": ["main"], "tags": ["v*"]}}:
    bad.append("scan.yml's events changed (pull requests, pushes to main and v* tags, unchanged): %s" % on)
jobs = d.get("jobs") or {}
builds = [j for j, v in jobs.items() if v.get("uses") == "./.github/workflows/stage-build.yml"]
if builds != ["build"]:
    bad.append("not exactly one build feeds both: %s" % builds)
# PR 2 of the v0.3.0 chain (REQ-CHAIN-004-AC14, REQ-CHAIN-005-AC7): stage-image.yml is gone. The one build runs in SNAPSHOT mode and a snapshot Rebuild rebuilds
# everything on fresh runners and FAILS on any differing item (rule 31 is kept, in the Rebuild stage); the required check `reproducibility` keeps its exact name,
# no condition and no token beyond contents read, and passes only when the Rebuild job passed. The old inline comparison of two assemblies' digests is replaced
# by that stage (bin/chain-rebuild-test.sh proves the comparison itself).
if any(v.get("uses") == "./.github/workflows/stage-image.yml" for v in jobs.values()):
    bad.append("a job still calls the deleted stage-image.yml")
if (jobs.get("build") or {}).get("with") != {"mode": "snapshot"}:
    bad.append("the one build is not a snapshot build: %s" % (jobs.get("build") or {}).get("with"))
rb = jobs.get("rebuild") or {}
if rb.get("uses") != "./.github/workflows/stage-reproducibility.yml" or rb.get("needs") != "build" or rb.get("with") != {"mode": "snapshot"}:
    bad.append("rebuild is not the snapshot Rebuild of the one build: %s" % rb)
r = jobs.get("reproducibility") or {}
if r.get("name") != "reproducibility" or r.get("if") or r.get("needs") != "rebuild":
    bad.append("reproducibility changed: %s" % {k: r.get(k) for k in ("name", "if", "needs")})
if r.get("permissions") not in (None, {"contents": "read"}):
    bad.append("reproducibility's token is wider than contents read: %s" % r.get("permissions"))
# fail closed (continue-on-error also hides a failure): the jobs the check rests on carry exactly the keys reviewed here
KEYS = {"build": {"permissions", "uses", "with"}, "rebuild": {"needs", "permissions", "uses", "with"},
        "reproducibility": {"name", "needs", "runs-on", "steps"}}
for j, keys in KEYS.items():
    if set(jobs.get(j) or {}) - keys:
        bad.append("%s carries a key that can skip or soften it: %s" % (j, sorted(set(jobs.get(j) or {}) - keys)))
# what the job inherits: the workflow's token and shell
if d.get("permissions") != {"contents": "read"} or set(d) != {"name", "on", "permissions", "jobs"}:
    bad.append("the workflow's inherited settings changed: keys %s, permissions %s" % (sorted(d), d.get("permissions")))
if (jobs.get("reproducibility") or {}).get("runs-on") != "ubuntu-latest":
    bad.append("reproducibility runs elsewhere than a GitHub-hosted ubuntu runner: %s" % (jobs.get("reproducibility") or {}).get("runs-on"))
steps = r.get("steps") or []
if len(steps) != 1 or set(steps[0]) != {"run"} or "${{" in steps[0].get("run", ""):
    bad.append("the reproducibility job is not one plain step with no expression: %s" % [sorted(st) for st in steps])
a = jobs.get("artifact-acceptance") or {}
if a.get("uses") != "./.github/workflows/stage-acceptance-artifacts.yml" or a.get("needs") != "build" or \
        (a.get("with") or {}) != {"dist-artifact": "dist", "expected-checksums": "${{ needs.build.outputs.digests }}"}:
    bad.append("artifact-acceptance changed: %s" % a)
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
case_scan repro-renamed          bad "d['jobs']['reproducibility']['name'] = 'reproducible'"
case_scan repro-widened          bad "d['jobs']['reproducibility']['permissions'] = {'contents': 'read', 'packages': 'write'}"
case_scan repro-not-after-rebuild bad "d['jobs']['reproducibility']['needs'] = 'build'"
case_scan repro-expression       bad "d['jobs']['reproducibility']['steps'][0]['run'] = 'exit \${{ 0 }}'"
case_scan acceptance-lost        bad "d['jobs'].pop('artifact-acceptance')"
case_scan acceptance-old-inputs  bad "d['jobs']['artifact-acceptance']['with'] = {'dist-artifact': 'dist-snapshot', 'expected-checksums': '\${{ needs.build.outputs.checksums }}'}"
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
case_scan workflow-concurrency   bad "d['concurrency'] = {'group': 'scan', 'cancel-in-progress': 'true'}"
case_scan repro-self-hosted      bad "d['jobs']['reproducibility']['runs-on'] = 'self-hosted'"

# ---------------------------------------------------------------------------------------------------------------------
# REQ-REL-008-AC1 (owner RATIFIED Oct 2, amended to 24; 25 with supply-chain.yml, REQ-SUP-001, a new file under the Oct 3 amendment, reported to the owner; 26 with stage-sign.yml, the one new workflow file of v0.3.0, named by rule 52 and RATIFIED by the owner Oct 9; 24 again when PR 2 removes stage-image.yml and stage-admission.yml, rules 50 and 61): after the consolidation PRs the workflow directory holds exactly
# the ratified files — the "keep" rows of docs/ratify/2026-10-02-workflow-consolidation.md, the 11 attestation-signer
# stages, and dependabot-auto-merge.yml (its events differ from ci.yml's) — and nothing else (no workflow sprawl).
ratified="acceptance.yml agent-review-gate.yml auditor.yml ci.yml codeql.yml dependabot-auto-merge.yml dependabot-reviewer.yml
go-freshness.yml main-candidate-rescan.yml release.yml reserved-branch-guard.yml scan.yml scorecard.yml
stage-acceptance-artifacts.yml stage-acceptance-egress.yml stage-acceptance-k8s.yml stage-acceptance-predicate.yml
stage-authorize.yml stage-build.yml stage-promote.yml stage-reproducibility.yml stage-verify.yml
stage-sign.yml supply-chain.yml"
judge_set() {  # $1: the directory's entries as a JSON list (every entry, not only *.yml)
  python3 - "$1" "$ratified" <<'PY'
import json, sys
got, want = json.loads(sys.argv[1]), sys.argv[2].split()
if len(want) != 24:
    print("the ratified list is not 24 files"); sys.exit(1)
odd = [n for n in got if "\n" in n or "/" in n]
extra, missing = sorted(set(got) - set(want)), sorted(set(want) - set(got))
if odd or extra or missing or len(got) != len(set(got)):
    print("extra: %s missing: %s odd names: %s" % (extra, missing, odd)); sys.exit(1)
print("ok")
PY
}
case_set() {
  if out=$(judge_set "$3"); then got=ok; else got=bad; fi
  if [ "$got" = "$2" ]; then pass=$((pass+1)); echo "PASS set:$1 → $got ($out)"
  else failn=$((failn+1)); echo "FAIL set:$1 → $got, want $2 ($out)"; fi
}
# every entry of the directory, unfiltered: a non-YAML file or a name with a newline is a difference (Codex #162 pin, R78-B3)
real_set=$(python3 -c 'import json, os, sys; print(json.dumps(sorted(os.listdir(sys.argv[1]))))' "$root/.github/workflows")
edit_set() { python3 -c 'import json, sys; s = json.loads(sys.argv[1]); exec(sys.argv[2]); print(json.dumps(s))' "$real_set" "$1"; }
case_set real          ok  "$real_set"
case_set a-new-file    bad "$(edit_set 's.append("sprawl.yml")')"
case_set a-non-yaml    bad "$(edit_set 's.append("README.txt")')"
case_set one-missing   bad "$(edit_set 's.remove("codeql.yml")')"
case_set newline-name  bad "$(edit_set 's.remove("codeql.yml"); s.remove("scorecard.yml"); s.append("codeql.yml\nscorecard.yml")')"
case_set back-to-old   bad "$(edit_set 's.remove("acceptance.yml"); s.append("acceptance-gradle.yml")')"
echo "workflow-consolidation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
