#!/usr/bin/env bash
# proves: REQ-SCAN-001-AC1, REQ-SCAN-001-AC2, REQ-SCAN-001-AC3, REQ-SCAN-002-AC1, REQ-SCAN-004-AC1, REQ-SCAN-009-AC5, REQ-REL-004-AC3
# The scanner panel's wiring in the daily rescan (scanner-panel rules 1, 2, 4, 9; ratified Oct 2): which
# scanner runs on which images (fixed in the workflow, never computed), Google only through the federation
# with repository variables, the VEX as the only exception (Grype and Scout given the file, no ignore
# options anywhere), Trivy and Snyk gone from the panel, and the audits in the same step that judges. The
# real workflow must pass; each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
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
    if any(x in (text(j) + " ".join(uses(j))).lower() for x in ("trivy", "snyk")) and j != "scanner-reports":
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
for j in ("panel-grype", "panel-scout", "panel-inspector", "panel-google"):
    if re.search(r"--(ignore|only-fixed|exclude|ignore-base|only-severity|severity)\b|\.grype\.yaml|suppress", text(j)):
        bad.append(f"{j} carries an ignore or severity option")
# rule 9: the audits run in the step that judges findings, inside the rescan run
pj = jobs["panel"]
judge_steps = [s for s in pj.get("steps", []) if "bin/panel.py judge" in (s.get("run") or "")]
if len(judge_steps) != 1 or "if" in judge_steps[0] and "always()" not in judge_steps[0]["if"]:
    bad.append("no single step runs `bin/panel.py judge` (findings judged and audited in one step)")
if any(re.search(r"\b(schedule|workflow_run|repository_dispatch)\b", str(s)) for s in pj.get("steps", [])):
    bad.append("the panel defers audits to another workflow")
needs = pj.get("needs", [])
if sorted(needs if isinstance(needs, list) else [needs]) != ["panel-google", "panel-grype", "panel-inspector", "panel-scout"] or "always()" not in pj.get("if", ""):
    bad.append("the panel does not wait for all four scanners whatever their outcome")
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
case_ scout-no-vex            bad "s=$(step_of panel-scout 'for v in'); s['run'] = s['run'].replace('--vex-location .vex/fosterstack-cache.openvex.json', '')"
case_ grype-only-fixed        bad "s=$(step_of panel-grype 'for v in'); s['run'] = s['run'].replace('grype ', 'grype --only-fixed ', 1)"
case_ audits-elsewhere        bad "s=$(step_of panel 'bin/panel.py judge'); s['run'] = s['run'].replace('bin/panel.py judge', 'bin/panel.py collect')"
case_ google-amd64-gone        bad "s=$(step_of panel-google 'for v in'); s['run'] = s['run'].replace('cand-\${v}-amd64', 'cand-\${v}')"
case_ panel-skips-on-failure  bad "$J['panel']['if'] = 'success()'"
echo "panel-wiring: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
