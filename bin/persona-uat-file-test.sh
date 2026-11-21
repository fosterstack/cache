#!/usr/bin/env bash
# proves: REQ-UAT-001-AC6
# persona-uat.yml is the only file with a persona job (REQ-UAT-001-AC6; orchestrator ruling 3 of Nov 13 2026, owner rule workflow-grouped-by-purpose: one purpose per file).
#   - its triggers are exactly the weekly cron of the Monday run (moved from go-freshness.yml) and workflow_call (release.yml runs the release-candidate leg through it);
#   - every job is in the environment persona-uat, behind the gate PERSONA_UAT_ENABLED, and holds only contents read and the identity token for the persona federation: never the release
#     signing key's role, never another environment, never a write grant; the secrets it names are the persona federation's and the two model ids, nothing else;
#   - go-freshness.yml keeps only its freshness jobs and its daily cron (judged here too, from the other side), and no other file holds a persona job: release.yml's one call of this file
#     is a job with `uses`, judged by bin/release-workflow-wiring-test.sh (the gate and the release-candidate tag condition live on that call).
# The jobs' steps, gate and private reports (AC1 to AC3) stay as bin/persona-uat-wiring-test.sh judges them. Judged from the PARSED workflows; the real file must pass, each mutated copy must be
# refused FOR THE REASON NAMED. Needs python3 with PyYAML. No network, no secrets.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (install the python3-yaml package)"; exit 1; }
cat > "$work/judge.py" <<'PY'
import glob, json, os, re, sys, yaml
tree = sys.argv[1]                                    # a repository root (the real one, or a scratch copy with one workflow edited)
WF = os.path.join(tree, ".github/workflows")
CRON = "43 6 * * 1"
ALLOWED_SECRETS = {"ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID", "PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"}
def load(p): return yaml.load(open(p), Loader=yaml.BaseLoader)
bad = []
path = os.path.join(WF, "persona-uat.yml")
if not os.path.exists(path):
    print("persona-uat.yml does not exist (REQ-UAT-001-AC6: the persona jobs live in their own file)"); sys.exit(1)
d = load(path)
on = d.get("on") or {}
if sorted(on) != ["schedule", "workflow_call"]:
    bad.append("the triggers are not exactly schedule and workflow_call: %s" % sorted(on))
if on.get("schedule") != [{"cron": CRON}]:
    bad.append("the schedule is not exactly the weekly Monday cron %s: %s" % (CRON, on.get("schedule")))
wc = on.get("workflow_call")
if isinstance(wc, dict) and (wc.get("secrets") or wc.get("outputs")):
    bad.append("workflow_call declares secrets or outputs: results stay private and the caller passes no secret")
if d.get("permissions") not in (None, {}, {"contents": "read"}):
    bad.append("the workflow-level permissions are wider than contents read: %s" % d.get("permissions"))
for k in ("env", "defaults"):
    if d.get(k):
        bad.append("persona-uat.yml has a workflow-level %s" % k)
jobs = d.get("jobs") or {}
if not jobs:
    bad.append("persona-uat.yml has no job")
if not any(re.sub(r"\s+", "", "github.event.schedule == '%s'" % CRON) in re.sub(r"\s+", "", str(j.get("if", ""))) for j in jobs.values()):
    bad.append("no persona job runs only on its Monday cron (github.event.schedule == '%s')" % CRON)
for jn, j in jobs.items():
    t = json.dumps(j, sort_keys=True)
    if j.get("environment") != "persona-uat":
        bad.append("job %s is not in the environment persona-uat: %s" % (jn, j.get("environment")))
    if "PERSONA_UAT_ENABLED" not in str(j.get("if", "")) or "'true'" not in str(j.get("if", "")):
        bad.append("job %s lacks the gate vars.PERSONA_UAT_ENABLED == 'true'" % jn)
    p = j.get("permissions")
    if p != {"contents": "read", "id-token": "write"}:
        bad.append("job %s does not hold exactly contents read and the identity token (persona federation only): %s" % (jn, p))
    if re.search(r"RELEASE_KMS_KEY_REF|AWS_ROLE_ARN|AWS_REGION|fosterstack-cache-release-signing|environment.{0,6}\bsign\b|release-sign|release-apks", t):
        bad.append("job %s names the release signing key's role or a signing command" % jn)
    extra = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", t)) - ALLOWED_SECRETS
    if extra:
        bad.append("job %s names secrets beyond the persona federation and the model ids: %s" % (jn, sorted(extra)))
    if "uses" in j:
        bad.append("job %s calls another workflow: persona-uat.yml holds the persona jobs themselves" % jn)
# the other files: no persona job, no persona environment (release.yml's call is a job with uses, judged by the release suite)
for f in sorted(glob.glob(os.path.join(WF, "*.y*ml"))):
    b = os.path.basename(f)
    if b == "persona-uat.yml":
        continue
    w = load(f) or {}
    for jn, j in ((w.get("jobs") or {}) if isinstance(w.get("jobs"), dict) else {}).items():
        if j.get("environment") == "persona-uat":
            bad.append("%s job %s is in the environment persona-uat: persona-uat.yml is the only file with a persona job" % (b, jn))
        if "persona-uat" in jn and not (b == "release.yml" and j.get("uses") == "./.github/workflows/persona-uat.yml"):
            bad.append("%s has a job named %s: persona-uat.yml is the only file with a persona job" % (b, jn))
        if re.search(r"bin/persona-uat(-agent)?\.py", json.dumps(j)):
            bad.append("%s job %s runs the persona driver: persona-uat.yml is the only file with a persona job" % (b, jn))
gf = load(os.path.join(WF, "go-freshness.yml")) or {}
crons = [c.get("cron") for c in ((gf.get("on") or {}).get("schedule") or [])]
if crons != ["23 6 * * *"]:
    bad.append("go-freshness.yml keeps only its daily freshness cron: %s" % crons)
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
# case NAME want WORD FILE EDIT   (FILE: the workflow file edited in a scratch copy of the workflows; EDIT: python on the parsed document d; empty = the real tree)
case_() {
  local t="$work/tree-$1"; rm -rf "$t"; mkdir -p "$t/.github/workflows"; cp "$root"/.github/workflows/*.y*ml "$t/.github/workflows/"
  if [ -n "${5:-}" ]; then python3 - "$t/.github/workflows/$4" "$5" <<'PY' || { failn=$((failn+1)); echo "FAIL $1 (the mutation did not apply)"; return 0; }
import sys, yaml
p, edit = sys.argv[1], sys.argv[2]
d = yaml.load(open(p), Loader=yaml.BaseLoader)
exec(edit)
yaml.safe_dump(d, open(p, "w"), sort_keys=False, width=100000)
PY
  fi
  local out rc=0
  out=$(python3 "$work/judge.py" "$t" 2>&1) || rc=$?
  if [ "$2" = ok ]; then
    if [ "$rc" = 0 ]; then pass=$((pass+1)); echo "PASS $1 -> ok"; else failn=$((failn+1)); echo "FAIL $1 -> $out"; fi
  elif [ "$rc" = 1 ] && grep -Fq -- "$3" <<< "$out"; then pass=$((pass+1)); echo "PASS $1 -> refused ($3)"
  else failn=$((failn+1)); echo "FAIL $1 -> rc=$rc, wanted a refusal containing '$3': ${out:0:400}"; fi
}
P=persona-uat.yml
FIRST="list(d['jobs'])[0]"
case_ real ok "" "" ""
# the file and its triggers
case_ trigger-push-added  bad "triggers are not exactly" "$P" "d['on']['push'] = {'branches': ['main']}"
case_ trigger-dispatch    bad "triggers are not exactly" "$P" "d['on']['workflow_dispatch'] = ''"
case_ no-workflow-call    bad "triggers are not exactly" "$P" "d['on'].pop('workflow_call')"
case_ no-schedule         bad "triggers are not exactly" "$P" "d['on'].pop('schedule')"
case_ cron-other-day      bad "weekly Monday cron" "$P" "d['on']['schedule'] = [{'cron': '43 6 * * 2'}]"
case_ cron-daily          bad "weekly Monday cron" "$P" "d['on']['schedule'] = [{'cron': '23 6 * * *'}]"
case_ two-crons           bad "weekly Monday cron" "$P" "d['on']['schedule'].append({'cron': '23 6 * * *'})"
case_ call-with-secrets   bad "declares secrets or outputs" "$P" "d['on']['workflow_call'] = {'secrets': {'K': {'required': 'true'}}}"
case_ call-with-outputs   bad "declares secrets or outputs" "$P" "d['on']['workflow_call'] = {'outputs': {'r': {'value': 'x'}}}"
case_ no-monday-job       bad "no persona job runs only on its Monday cron" "$P" "for j in d['jobs'].values(): j['if'] = \"\${{ vars.PERSONA_UAT_ENABLED == 'true' }}\""
case_ workflow-write      bad "workflow-level permissions are wider" "$P" "d['permissions'] = {'contents': 'write'}"
case_ workflow-env        bad "workflow-level env" "$P" "d['env'] = {'X': 'y'}"
case_ no-jobs             bad "has no job" "$P" "d['jobs'] = {}"
# every job: the environment, the gate, the grants, the key
case_ environment-gone    bad "is not in the environment persona-uat" "$P" "d['jobs'][$FIRST].pop('environment')"
case_ environment-release bad "is not in the environment persona-uat" "$P" "d['jobs'][$FIRST]['environment'] = 'release'"
case_ environment-sign    bad "is not in the environment persona-uat" "$P" "d['jobs'][$FIRST]['environment'] = 'sign'"
case_ gate-gone           bad "lacks the gate" "$P" "for j in d['jobs'].values(): j['if'] = \"\${{ github.event.schedule == '43 6 * * 1' }}\""
case_ gate-wrong-value    bad "lacks the gate" "$P" "for j in d['jobs'].values(): j['if'] = \"\${{ vars.PERSONA_UAT_ENABLED && github.event.schedule == '43 6 * * 1' }}\""
case_ contents-write      bad "does not hold exactly contents read" "$P" "d['jobs'][$FIRST]['permissions']['contents'] = 'write'"
case_ packages-write      bad "does not hold exactly contents read" "$P" "d['jobs'][$FIRST]['permissions']['packages'] = 'write'"
case_ id-token-gone       bad "does not hold exactly contents read" "$P" "d['jobs'][$FIRST]['permissions'].pop('id-token')"
case_ no-permissions      bad "does not hold exactly contents read" "$P" "d['jobs'][$FIRST].pop('permissions')"
case_ names-the-kms-key   bad "names the release signing key's role" "$P" "d['jobs'][$FIRST].setdefault('env', {})['RELEASE_KMS_KEY_REF'] = 'x'"
case_ names-the-role      bad "names the release signing key's role" "$P" "d['jobs'][$FIRST].setdefault('env', {})['AWS_ROLE_ARN'] = 'arn:aws:iam::1:role/x'"
case_ runs-release-sign   bad "names the release signing key's role" "$P" "d['jobs'][$FIRST]['steps'].append({'run': 'bash bin/release-sign.sh'})"
case_ foreign-secret      bad "names secrets beyond the persona federation" "$P" "d['jobs'][$FIRST]['steps'].append({'run': 'echo x', 'env': {'T': '\${{ secrets.DOCKERHUB_TOKEN }}'}})"
case_ app-key-secret      bad "names secrets beyond the persona federation" "$P" "d['jobs'][$FIRST]['steps'].append({'run': 'echo x', 'env': {'T': '\${{ secrets.AUDITOR_APP_PRIVATE_KEY }}'}})"
case_ job-calls-workflow  bad "calls another workflow" "$P" "d['jobs'][$FIRST]['uses'] = './.github/workflows/release.yml'"
# the other files
case_ go-freshness-persona-job bad "persona-uat.yml is the only file with a persona job" go-freshness.yml "d['jobs']['persona-uat'] = {'runs-on': 'ubuntu-24.04', 'environment': 'persona-uat', 'steps': []}"
case_ go-freshness-weekly-cron bad "go-freshness.yml keeps only its daily freshness cron" go-freshness.yml "d['on']['schedule'].append({'cron': '43 6 * * 1'})"
case_ release-persona-job bad "persona-uat.yml is the only file with a persona job" release.yml "d['jobs']['persona-uat'] = {'runs-on': 'ubuntu-24.04', 'environment': 'persona-uat', 'steps': []}"
case_ release-persona-env bad "is in the environment persona-uat" release.yml "d['jobs']['uat'] = {'runs-on': 'ubuntu-24.04', 'environment': 'persona-uat', 'steps': []}"
case_ ci-runs-the-driver  bad "runs the persona driver" ci.yml "d['jobs']['uat'] = {'runs-on': 'ubuntu-24.04', 'steps': [{'run': 'python3 bin/persona-uat.py --publish'}]}"

echo "persona-uat-file: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
