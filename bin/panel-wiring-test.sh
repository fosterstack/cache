#!/usr/bin/env bash
# proves: REQ-SCAN-001-AC1, REQ-SCAN-001-AC2, REQ-SCAN-001-AC3, REQ-SCAN-002-AC1, REQ-SCAN-004-AC1, REQ-SCAN-004-AC2, REQ-SCAN-009-AC5, REQ-REL-004-AC3
# The scanner panel's wiring in the daily rescan (scanner-panel rules 1, 2, 4, 9; ratified Oct 2): which
# scanner runs on which images (fixed in the workflow, never computed), Google only through the federation
# with repository variables, the VEX as the only exception (Grype and Scout given the file, no ignore
# options anywhere), Trivy and Snyk gone from the panel, and no audit in the rescan (the auditor judges unique findings). The
# real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
export PANEL_ROOT="$root"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
jobs = d.get("jobs", {})
bad = []
def text(j): return "\n".join((s.get("run") or "") for s in jobs.get(j, {}).get("steps", []))
def uses(j): return [str(s.get("uses", "")) for s in jobs.get(j, {}).get("steps", [])]
VAR = ("production", "debug", "fips")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if j not in jobs:
        bad.append(f"no {j} job")
if bad:
    print("; ".join(bad)); sys.exit(1)
# rule 1: the fixed image set, written in the workflow
for j in ("panel-grype", "panel-scout", "panel-inspector"):
    t = text(j)
    if "for v in production debug fips" not in t or "for arch in amd64 arm64" not in t:
        bad.append(f"{j} does not scan the six images, fixed in the workflow")
tg = text("panel-google")
if "for v in production debug fips" not in tg or "arm64" in tg or "for arch" in tg \
        or "--override-arch amd64" not in tg or 'cand-${v}-amd64"' not in tg:
    bad.append("panel-google does not scan exactly the three variants on linux/amd64 (and never arm64)")
for j in jobs:
    # scanner-reports hands the auditor its inputs; manifests/rescan are the PUBLISHED-release rescan (merged from
    # daily-rescan.yml, consolidation 3 of 4; REQ-REL-003), which runs only the scanners in .github/policy/scanners.json —
    # none of the three is the scanner panel
    if any(x in (text(j) + " ".join(uses(j))).lower() for x in ("trivy", "snyk")) and j not in ("scanner-reports", "manifests", "rescan"):
        bad.append(f"{j} runs Trivy or Snyk")
for gone in ("scan-main", "trivy-main", "snyk-main"):
    if gone in jobs:
        bad.append(f"the retired {gone} job is still there")
# rule 2: Google through the federation, identifiers from repository variables, no secrets, no keys
gj = jobs["panel-google"]
if (gj.get("permissions") or {}).get("id-token") != "write":
    bad.append("panel-google lacks id-token: write")
auth = [s for s in gj.get("steps", []) if str(s.get("uses", "")).startswith("google-github-actions/auth@")]
w = (auth[0].get("with") or {}) if auth else {}
if not auth or w.get("workload_identity_provider") != "${{ vars.CACHE_SCANNER_PROVIDER }}" \
        or w.get("service_account") != "${{ vars.CACHE_SCANNER_SERVICE_ACCOUNT }}" or "credentials_json" in w:
    bad.append("panel-google does not authenticate through the federation with the two repository variables")
if "secrets." in str(gj) or "GOOGLE_APPLICATION_CREDENTIALS" in tg:
    bad.append("panel-google uses a secret or a key file")
# rule 4: the VEX is the only exception
if "--vex .vex/fosterstack-cache.openvex.json" not in text("panel-grype"):
    bad.append("Grype is not given the VEX file")
if "--vex-location .vex/fosterstack-cache.openvex.json" not in text("panel-scout"):
    bad.append("Scout is not given the VEX file")
# Scout applies only statements by an author --vex-author accepts (default Docker's own): the scan and the self-check
# both name ours, anchored and equal to the file's author (rule 4; Sonnet #167 r1 found the gate)
import json, os
author = json.load(open(os.path.join(os.environ.get("PANEL_ROOT", "."), ".vex/fosterstack-cache.openvex.json")))["author"]
want_flag = "--vex-author '^%s$'" % re.escape(author).replace("\\ ", " ")
scout_steps = jobs.get("panel-scout", {}).get("steps", [])
scan = [i for i, s in enumerate(scout_steps) if "--vex-location .vex/fosterstack-cache.openvex.json" in (s.get("run") or "")]
selfcheck = [i for i, s in enumerate(scout_steps) if "rule 4 self-check" in (s.get("name") or "")]
if not scan or want_flag not in scout_steps[scan[0]].get("run", ""):
    bad.append("Scout's scan does not accept our file's author (%s)" % want_flag)
# a VEX'd finding is proven dropped: our author and product form, on the pinned fixture under our image's name, through
# the same local:// path, before the scan — and the job fails when Scout keeps it
if len(selfcheck) != 1 or not scan or selfcheck[0] > scan[0]:
    bad.append("no Scout self-check before the scan")
else:
    sc = scout_steps[selfcheck[0]].get("run", "")
    for need in (want_flag, "local://ghcr.io/fosterstack/cache:selfcheck", "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache",
                 "docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab",
                 "exit 1"):
        if need not in sc:
            bad.append("the Scout self-check lacks %s" % need)
    if scout_steps[selfcheck[0]].get("continue-on-error") or scout_steps[selfcheck[0]].get("if"):
        bad.append("the Scout self-check can be skipped or softened")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google"):
    if re.search(r"--(ignore|only-fixed|exclude|ignore-base|only-severity|severity)\b|\.grype\.yaml|suppress", text(j)):
        bad.append(f"{j} carries an ignore or severity option")
# rule 9 (owner, Oct 3): the AI judging lives in the auditor; the rescan's panel job tallies and cannot audit
pj = jobs["panel"]
if "id-token" in (pj.get("permissions") or {}) or pj.get("environment") or re.search(r"profiles|audit|--prior", text("panel")):
    bad.append("the rescan's panel job can audit (identity, environment, profiles or history): the auditor judges unique findings")
# the tally step (one step, the verdict the auditor reads)
pj = jobs["panel"]
judge_steps = [s for s in pj.get("steps", []) if "bin/panel.py tally" in (s.get("run") or "")]
if len(judge_steps) != 1 or "if" in judge_steps[0] and "always()" not in judge_steps[0]["if"]:
    bad.append("no single step runs `bin/panel.py tally`")
if any(re.search(r"\b(schedule|workflow_run|repository_dispatch)\b", str(s)) for s in pj.get("steps", [])):
    bad.append("the panel defers audits to another workflow")
needs = pj.get("needs", [])
if sorted(needs if isinstance(needs, list) else [needs]) != ["panel-google", "panel-grype", "panel-inspector", "panel-scout"] or "always()" not in pj.get("if", ""):
    bad.append("the panel does not wait for all four scanners whatever their outcome")
# the run is daily, and nothing in the panel is switched off or allowed to fail quietly
crons = [c.get("cron", "") for c in ((d.get("on") or {}).get("schedule") or []) if isinstance(c, dict)]
if not any(re.fullmatch(r"\d{1,2} \d{1,2} \* \* \*", c.split("#")[0].strip()) for c in crons):
    bad.append("the rescan has no daily schedule")
# the exact scan commands: each architecture once, Google's package count from its request log
for j in ("panel-grype", "panel-scout", "panel-inspector"):
    t = text(j)
    if not re.search(r"for arch in amd64 arm64; do", t) or t.count("for arch in") != 1 \
            or '--override-arch "${arch}"' not in t or 'cand-${v}-${arch}' not in t:
        bad.append(f"{j} does not load each architecture once by the loop variable")
if "--log-http" not in tg or "bin/panel.py google-packages" not in tg or "list-vulnerabilities" not in tg:
    bad.append("panel-google does not take its package count from the request log and its findings from list-vulnerabilities")
if jobs["panel-google"].get("environment") != "agent":
    bad.append("panel-google is not in the main-only agent environment (its identity admits a scheduled main run only there)")
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google", "panel"):
    if "if" in jobs[j] and j != "panel":
        bad.append(f"{j} is conditional")
    for st in jobs[j].get("steps", []):
        cond = str(st.get("if", "")).replace(" ", "")
        if cond and not cond.startswith("${{always()") and "steps.judge" not in cond:
            bad.append(f"{j}: step {st.get('name')!r} is conditional ({st.get('if')})")
        if str(st.get("continue-on-error", "false")) != "false" and "download-artifact" not in str(st.get("uses", "")):
            bad.append(f"{j}: step {st.get('name')!r} may fail quietly")
issue = [st for st in pj.get("steps", []) if "gh issue create" in (st.get("run") or "") and "gh issue comment" in (st.get("run") or "")]
if len(issue) != 1 or "refs/heads/main" not in str(issue[0].get("if", "")) or "issue.md" not in issue[0].get("run", ""):
    bad.append("no step opens or updates the tracking issue from main with the tally's issue text")
elif re.search(r"^\s*exit 0\s*$", issue[0]["run"], re.M) or issue[0]["run"].count("exit 0") != 1:
    bad.append("the issue step can exit before filing")
js = judge_steps[0].get("run", "") if judge_steps else ""
if 'echo "rc=$?" >> "$GITHUB_OUTPUT"' not in js or not re.search(r"bin/panel\.py tally[^\n]*(\\\n[^\n]*)*\n\s*echo \"rc=\$\?\"", js):
    bad.append("the tally's exit code is not what the panel exports")
last = pj.get("steps", [])[-1] if pj.get("steps") else {}
if "steps.judge.outputs.rc != '0'" not in str(last.get("if", "")) or "exit 1" not in (last.get("run") or ""):
    bad.append("the panel's last step does not fail the run when the judge's verdict is not clean")
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
case_() {
  local f="$work/$1.yml"
  cp "$root/.github/workflows/main-candidate-rescan.yml" "$f"
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
step_of() { echo "[s for s in $J['$1']['steps'] if '$2' in (s.get('run') or '')][0]"; }
case_ real                    ok  ""
case_ google-arm64            bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('--override-arch amd64', '--override-arch arm64')"
case_ grype-five-images       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for v in production debug fips', 'for v in production debug')"
case_ computed-images         bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in \$ARCHES')"
case_ trivy-back              bad "$J['trivy-main'] = {'runs-on': 'ubuntu-latest', 'steps': [{'run': 'trivy image x'}]}"
case_ google-secret           bad "[s.__setitem__('with', {'credentials_json': '\${{ secrets.GCP_KEY }}'}) for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-literal-provider bad "[s['with'].__setitem__('workload_identity_provider', 'projects/1/locations/global/workloadIdentityPools/p/providers/q') for s in $J['panel-google']['steps'] if str(s.get('uses','')).startswith('google-github-actions/auth@')]"
case_ google-no-idtoken       bad "$J['panel-google']['permissions'].pop('id-token')"
case_ grype-no-vex            bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('--vex .vex/fosterstack-cache.openvex.json', '')"
case_ scout-no-author         bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace(\"--vex-author '^FosterStack LLC\$' \", '')"
case_ scout-any-author        bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace(\"'^FosterStack LLC\$'\", \"'.*'\")"
case_ scout-no-selfcheck      bad "$J['panel-scout']['steps'] = [s for s in $J['panel-scout']['steps'] if 'self-check' not in (s.get('name') or '')]"
case_ scout-selfcheck-soft    bad "[s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]['continue-on-error'] = 'true'"
case_ scout-selfcheck-no-fail bad "s = [s for s in $J['panel-scout']['steps'] if 'self-check' in (s.get('name') or '')][0]; s['run'] = s['run'].replace('exit 1', 'true')"
case_ scout-no-vex            bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('--vex-location .vex/fosterstack-cache.openvex.json', '')"
case_ grype-only-fixed        bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('grype ', 'grype --only-fixed ', 1)"
case_ audits-elsewhere        bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('bin/panel.py tally', 'bin/panel.py collect')"
case_ google-amd64-gone        bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('cand-\${v}-amd64', 'cand-\${v}')"
case_ no-schedule             bad "d['on'].pop('schedule')"
case_ scan-disabled           bad "s=$(step_of panel-inspector 'for v in'); s['if'] = 'false'"
case_ scan-may-fail           bad "s=$(step_of panel-grype 'for v in'); s['continue-on-error'] = 'true'"
case_ job-disabled            bad "$J['panel-scout']['if'] = 'false'"
case_ no-issue-step           bad "$J['panel']['steps'] = [s for s in $J['panel']['steps'] if 'gh issue' not in (s.get('run') or '')]"
case_ issue-from-any-branch   bad "[s.__setitem__('if', '\${{ always() }}') for s in $J['panel']['steps'] if 'gh issue' in (s.get('run') or '')]"
case_ no-final-failure        bad "$J['panel']['steps'] = $J['panel']['steps'][:-1]"
case_ yearly-schedule         bad "d['on']['schedule'][0]['cron'] = '41 7 1 1 *'"
case_ google-no-environment   bad "$J['panel-google'].pop('environment')"
case_ grype-amd64-twice       bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('for arch in amd64 arm64', 'for arch in amd64 amd64')"
case_ issue-exits-early       bad "[s.__setitem__('run', 'exit 0\n' + s['run']) for s in $J['panel']['steps'] if 'gh issue' in (s.get('run') or '')]"
case_ rc-forced-zero          bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('echo \"rc=\$?\"', 'echo \"rc=0\"')"
case_ google-no-log-http      bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace(' --log-http', '')"
case_ panel-audits             bad "$J['panel']['permissions']['id-token'] = 'write'"
case_ panel-reads-history     bad "s=$(step_of panel 'bin/panel.py tally'); s['run'] = s['run'].replace('--out', '--prior /tmp/prior/judgments.json --out')"
case_ panel-skips-on-failure  bad "$J['panel']['if'] = 'success()'"
echo "panel-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
