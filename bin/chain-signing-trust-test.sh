#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC8
# REQ-CHAIN-001-AC8: exactly the four jobs sign, sign-rebuild, sign-check and sign-release of release.yml run in the environment sign and request the identity token for the release signing
# role (the job holds id-token: write and names the role: AWS_ROLE_ARN or RELEASE_KMS_KEY_REF); no other job of any workflow file does. The role's trust itself lives in the ops repository,
# so this suite reads the workflow files only. The real files are judged, then mutated copies of them (each refused for its reason).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
cat > "$work/jobs.py" <<'PY'
import copy, glob, json, os, re, sys
import yaml

FOUR = ["sign", "sign-check", "sign-rebuild", "sign-release"]
KMS = re.compile(r"\bAWS_ROLE_ARN|RELEASE_KMS_KEY_REF|release-signing")

def load(root):
    return {os.path.basename(p): yaml.safe_load(open(p)) for p in sorted(glob.glob(root + "/.github/workflows/*.yml"))}

def holds_token(wf, job):
    perms = job.get("permissions", wf.get("permissions"))
    return isinstance(perms, dict) and perms.get("id-token") == "write"

def findings(wfs):
    """what is wrong with the set of workflow files: the jobs in the environment sign and the jobs that ask for the KMS role's token, each against the four"""
    in_sign, asking, bad = [], [], []
    for name, wf in wfs.items():
        for jn, job in (wf.get("jobs") or {}).items():
            env = job.get("environment")
            env = env.get("name") if isinstance(env, dict) else env
            if env == "sign":
                in_sign.append((name, jn))
            if holds_token(wf, job) and KMS.search(json.dumps(job) + json.dumps(wf.get("env"))):
                asking.append((name, jn))
    want = [("release.yml", j) for j in FOUR]
    if sorted(in_sign) != want:
        bad.append("the jobs in the environment sign are %s, not %s" % (sorted(in_sign), want))
    if sorted(asking) != want:
        bad.append("the jobs that request the identity token for the release signing role are %s, not %s" % (sorted(asking), want))
    return bad

def mutate(wfs, how):
    w = copy.deepcopy(wfs)
    jobs = w["release.yml"]["jobs"]
    extra = {"runs-on": "ubuntu-24.04", "environment": "sign", "permissions": {"id-token": "write"}, "env": {"AWS_ROLE_ARN": "arn:aws:iam::1:role/fosterstack-cache-release-signing"}, "steps": []}
    if how == "release-job-signs":
        jobs["release"]["permissions"] = {"id-token": "write"}; jobs["release"]["env"] = dict(jobs["release"].get("env") or {}, AWS_ROLE_ARN="x")
    elif how == "release-job-in-sign":
        jobs["release"]["environment"] = "sign"
    elif how == "fifth-job-in-release-yml":
        jobs["extra"] = extra
    elif how == "job-of-another-file":
        w["ci.yml"]["jobs"]["extra"] = extra
    elif how == "persona-uat-asks":
        w["persona-uat.yml"]["jobs"]["extra"] = dict(extra, environment="persona-uat")
    elif how == "live-test-asks":
        jobs["live-test"]["env"] = dict(jobs["live-test"].get("env") or {}, RELEASE_KMS_KEY_REF="awskms:///alias/x")
    elif how == "sign-check-leaves-sign":
        jobs["sign-check"]["environment"] = "release"
    elif how == "sign-release-drops-token":
        jobs["sign-release"]["permissions"] = {"contents": "read"}
    elif how == "sign-rebuild-gone":
        del jobs["sign-rebuild"]
    elif how == "workflow-level-token":
        w["ci.yml"]["permissions"] = {"id-token": "write"}; w["ci.yml"]["env"] = {"AWS_ROLE_ARN": "arn:aws:iam::1:role/fosterstack-cache-release-signing"}
    return w

if sys.argv[1] == "real":
    bad = findings(load(sys.argv[2]))
    print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
bad = findings(mutate(load(sys.argv[2]), sys.argv[1]))
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
report() { # report NAME RC TEXT
  if [ "$2" = 0 ]; then pass=$((pass+1)); echo "PASS $1 -> $3"; else failn=$((failn+1)); echo "FAIL $1 -> $3"; fi
}
rc=0; out=$(python3 "$work/jobs.py" real "$root" 2>&1) || rc=$?
report "only sign, sign-rebuild, sign-check and sign-release of release.yml run in the environment sign and request the KMS role's identity token" "$rc" "$out"
mutated() { # mutated NAME
  local rc=0 out; out=$(python3 "$work/jobs.py" "$1" "$root" 2>&1) || rc=$?
  if [ "$rc" = 1 ]; then pass=$((pass+1)); echo "PASS mutation $1 -> refused ($out)"
  else failn=$((failn+1)); echo "FAIL mutation $1 -> rc=$rc, wanted a refusal: $out"; fi
}
for m in release-job-signs release-job-in-sign fifth-job-in-release-yml job-of-another-file persona-uat-asks live-test-asks sign-check-leaves-sign sign-release-drops-token sign-rebuild-gone workflow-level-token; do
  mutated "$m"
done
echo "chain-signing-trust: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
