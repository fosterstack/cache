#!/usr/bin/env bash
# proves: REQ-UAT-001-AC6
# persona-uat.yml is the only file with a persona job (REQ-UAT-001-AC6; orchestrator ruling 3 of Nov 13 2026, owner rule workflow-grouped-by-purpose: one purpose per file).
#   - its only trigger is workflow_call (owner decision: persona tests run only at code promotion, never on a timer; no schedule). release.yml calls it twice: the release-candidate leg (persona-uat-rc)
#     and, as the last step of the run a release tag push starts, the compliance reviewer against the published image (persona-uat-compliance); its jobs are exactly those two;
#   - every job is in the environment persona-uat, behind the gate PERSONA_UAT_ENABLED, and holds only contents read and the identity token for the persona federation: never the release
#     signing key's role, never another environment, never a write grant; the secrets it names are the persona federation's and the two model ids, nothing else;
#   - go-freshness.yml keeps only its freshness jobs and its daily cron (judged here too, from the other side), and no other file holds a persona job: release.yml's one call of this file
#     is a job with `uses`, judged by bin/release-workflow-wiring-test.sh (the gate and the release-branch push condition live on that call).
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
CRON = "43 6 * * 1"                                  # the old Monday persona cron: no file has it any more
GATE = "vars.PERSONA_UAT_ENABLED=='true'"
SECRETS = {"PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID"}
def squash(e): return re.sub(r"\s+", "", str(e)).replace("${{", "").replace("}}", "")
ALLOWED_SECRETS = {"ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID", "PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"}
def load(p): return yaml.load(open(p), Loader=yaml.BaseLoader)
bad = []
path = os.path.join(WF, "persona-uat.yml")
if not os.path.exists(path):
    print("persona-uat.yml does not exist (REQ-UAT-001-AC6: the persona jobs live in their own file)"); sys.exit(1)
d = load(path)
on = d.get("on") or {}
if sorted(on) != ["workflow_call"]:
    bad.append("the triggers are not exactly workflow_call (no schedule, no dispatch, no push): %s" % sorted(on))
wc = on.get("workflow_call")
if not isinstance(wc, dict):
    bad.append("workflow_call is not a mapping with inputs and secrets")
else:
    ins = wc.get("inputs") or {}
    if sorted(ins) != ["digests", "image"] or any(not isinstance(v, dict) or v.get("type") != "string" or v.get("default") != "" for v in ins.values()):
        bad.append("workflow_call inputs are not exactly digests and image, each a string defaulting to the empty string: %s" % ins)
    if sorted(wc.get("secrets") or {}) != sorted(SECRETS):
        bad.append("workflow_call secrets are not exactly the six persona secrets: %s" % sorted(wc.get("secrets") or {}))
    if wc.get("outputs"):
        bad.append("workflow_call declares outputs: results stay private")
if d.get("permissions") not in (None, {}, {"contents": "read"}):
    bad.append("the workflow-level permissions are wider than contents read: %s" % d.get("permissions"))
for k in ("env", "defaults"):
    if d.get(k):
        bad.append("persona-uat.yml has a workflow-level %s" % k)
jobs = d.get("jobs") or {}
if not jobs:
    bad.append("persona-uat.yml has no job")
if sorted(jobs) != ["persona-uat-compliance", "persona-uat-rc"]:
    bad.append("the jobs are not exactly persona-uat-rc and persona-uat-compliance (no weekly job): %s" % sorted(jobs))
comp = jobs.get("persona-uat-compliance") or {}
if squash(comp.get("if", "")) != GATE + "&&inputs.image!=''":
    bad.append("persona-uat-compliance does not run only behind the gate and a published image (if: %s)" % comp.get("if"))
if "needs" in comp:
    bad.append("persona-uat-compliance has needs: it runs from the caller's own ordering, never from a dependency in this file")
if "schedule" in json.dumps(jobs):
    bad.append("a job names a schedule event: nothing in persona-uat.yml runs on a timer")
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
rel = load(os.path.join(WF, "release.yml")) or {}
calls = sorted(n for n, j in (rel.get("jobs") or {}).items() if "persona-uat.yml" in str(j.get("uses", "")))
if calls != ["persona-uat-compliance", "persona-uat-rc"]:
    bad.append("release.yml's calls of persona-uat.yml are not exactly persona-uat-rc and persona-uat-compliance: %s" % calls)
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
for f in sorted(glob.glob(os.path.join(WF, "*.y*ml"))):
    w_ = load(f) or {}
    on_ = w_.get("on") if isinstance(w_.get("on"), dict) else {}
    for c in on_.get("schedule") or []:
        if isinstance(c, dict) and c.get("cron") == CRON:
            bad.append("%s has the Monday persona cron: no file has a persona cron any more" % os.path.basename(f))
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
case_ schedule-added      bad "triggers are not exactly" "$P" "d['on']['schedule'] = [{'cron': '43 6 * * 1'}]"
case_ schedule-other-cron bad "triggers are not exactly" "$P" "d['on']['schedule'] = [{'cron': '23 6 * * *'}]"
case_ schedule-empty      bad "triggers are not exactly" "$P" "d['on']['schedule'] = []"
case_ monday-cron-in-persona bad "has the Monday persona cron" "$P" "d['on']['schedule'] = [{'cron': '43 6 * * 1'}]"
case_ image-input-gone    bad "inputs are not exactly digests and image" "$P" "d['on']['workflow_call']['inputs'].pop('image')"
case_ digests-input-gone  bad "inputs are not exactly digests and image" "$P" "d['on']['workflow_call']['inputs'].pop('digests')"
case_ third-input         bad "inputs are not exactly digests and image" "$P" "d['on']['workflow_call']['inputs']['tag'] = {'type': 'string', 'default': ''}"
case_ image-default-set   bad "inputs are not exactly digests and image" "$P" "d['on']['workflow_call']['inputs']['image']['default'] = 'ghcr.io/x/cache@sha256:abc'"
case_ image-not-string    bad "inputs are not exactly digests and image" "$P" "d['on']['workflow_call']['inputs']['image']['type'] = 'boolean'"
case_ call-secret-dropped bad "secrets are not exactly the six" "$P" "d['on']['workflow_call']['secrets'].pop('PERSONA_UAT_MODEL')"
case_ call-seventh-secret bad "secrets are not exactly the six" "$P" "d['on']['workflow_call']['secrets']['GITHUB_TOKEN'] = {'required': 'false'}"
case_ call-with-outputs   bad "declares outputs" "$P" "d['on']['workflow_call']['outputs'] = {'r': {'value': 'x'}}"
case_ weekly-job-back     bad "the jobs are not exactly" "$P" "d['jobs']['persona-uat-weekly'] = d['jobs']['persona-uat-compliance']"
case_ compliance-renamed  bad "the jobs are not exactly" "$P" "d['jobs']['persona-uat-weekly'] = d['jobs'].pop('persona-uat-compliance')"
case_ compliance-gone     bad "the jobs are not exactly" "$P" "d['jobs'].pop('persona-uat-compliance')"
case_ third-job           bad "the jobs are not exactly" "$P" "d['jobs']['persona-uat-extra'] = d['jobs']['persona-uat-rc']"
case_ compliance-no-image-condition bad "does not run only behind the gate and a published image" "$P" "d['jobs']['persona-uat-compliance']['if'] = \"\${{ vars.PERSONA_UAT_ENABLED == 'true' }}\""
case_ compliance-no-gate  bad "does not run only behind the gate and a published image" "$P" "d['jobs']['persona-uat-compliance']['if'] = \"\${{ inputs.image != '' }}\""
case_ compliance-or-image bad "does not run only behind the gate and a published image" "$P" "d['jobs']['persona-uat-compliance']['if'] = \"\${{ vars.PERSONA_UAT_ENABLED == 'true' || inputs.image != '' }}\""
case_ compliance-on-cron  bad "does not run only behind the gate and a published image" "$P" "d['jobs']['persona-uat-compliance']['if'] = \"\${{ vars.PERSONA_UAT_ENABLED == 'true' && github.event.schedule == '43 6 * * 1' }}\""
case_ compliance-needs    bad "persona-uat-compliance has needs" "$P" "d['jobs']['persona-uat-compliance']['needs'] = ['persona-uat-rc']"
case_ compliance-needs-str bad "persona-uat-compliance has needs" "$P" "d['jobs']['persona-uat-compliance']['needs'] = 'persona-uat-rc'"
case_ workflow-write      bad "workflow-level permissions are wider" "$P" "d['permissions'] = {'contents': 'write'}"
case_ workflow-env        bad "workflow-level env" "$P" "d['env'] = {'X': 'y'}"
case_ no-jobs             bad "has no job" "$P" "d['jobs'] = {}"
# every job: the environment, the gate, the grants, the key
case_ environment-gone    bad "is not in the environment persona-uat" "$P" "d['jobs'][$FIRST].pop('environment')"
case_ environment-release bad "is not in the environment persona-uat" "$P" "d['jobs'][$FIRST]['environment'] = 'release'"
case_ environment-sign    bad "is not in the environment persona-uat" "$P" "d['jobs'][$FIRST]['environment'] = 'sign'"
case_ gate-gone           bad "lacks the gate" "$P" "for j in d['jobs'].values(): j['if'] = \"\${{ inputs.image != '' }}\""
case_ gate-wrong-value    bad "lacks the gate" "$P" "for j in d['jobs'].values(): j['if'] = \"\${{ vars.PERSONA_UAT_ENABLED && inputs.image != '' }}\""
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
case_ go-freshness-weekly-cron-named bad "has the Monday persona cron" go-freshness.yml "d['on']['schedule'].append({'cron': '43 6 * * 1'})"
case_ release-monday-cron bad "has the Monday persona cron" release.yml "d['on']['schedule'].append({'cron': '43 6 * * 1'})"
case_ release-drops-compliance-call bad "release.yml's calls of persona-uat.yml are not exactly" release.yml "d['jobs'].pop('persona-uat-compliance')"
case_ release-third-call  bad "release.yml's calls of persona-uat.yml are not exactly" release.yml "d['jobs']['persona-uat-more'] = dict(d['jobs']['persona-uat-rc'])"
case_ release-persona-job bad "persona-uat.yml is the only file with a persona job" release.yml "d['jobs']['persona-uat'] = {'runs-on': 'ubuntu-24.04', 'environment': 'persona-uat', 'steps': []}"
case_ release-persona-env bad "is in the environment persona-uat" release.yml "d['jobs']['uat'] = {'runs-on': 'ubuntu-24.04', 'environment': 'persona-uat', 'steps': []}"
case_ ci-runs-the-driver  bad "runs the persona driver" ci.yml "d['jobs']['uat'] = {'runs-on': 'ubuntu-24.04', 'steps': [{'run': 'python3 bin/persona-uat.py --publish'}]}"

echo "persona-uat-file: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
