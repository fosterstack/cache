#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC8
# The trust text of the release signing key's role (REQ-CHAIN-001-AC8; orchestrator ruling 4 of Nov 13 2026, /srv/handoffs/briefs/cache-921-signer-identity-ruling.md): the committed record
# .github/policy/release-signing-trust.json holds the conditions the owner applies by hand in terraform/aws-apply, so a test can read them offline. The record is ONE JSON object whose
# keys include aud, sub and job_workflow_ref (the three conditions of the role's trust):
#     aud               the audience the AWS trust requires (sts.amazonaws.com), compared for EQUALITY
#     sub               repo:fosterstack/cache:environment:sign, compared for EQUALITY (no wildcard)
#     job_workflow_ref  fosterstack/cache/.github/workflows/release.yml@refs/tags/v*  (the one `*` is the tag suffix after refs/tags/v)
# Each token below is evaluated against that text on its own, offline: exactly the token of the environment sign from release.yml at a v* tag is accepted; the tokens of the environments release,
# evidence-letter and persona-uat, of no environment (a tag push or a branch), of the environment sign from any other workflow file, of another repository and of another audience are refused.
# The record does not exist before the cache#921 code lands: until then this suite fails (the record is missing), which is the correct state of a test written first.
# The record itself is judged too: a wildcard on aud or sub, a missing condition, or any other `*` in job_workflow_ref is refused as a text (mutated copies, each refused for its reason).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
cat > "$work/trust.py" <<'PY'
import json, re, sys

REPO = "fosterstack/cache"
AUD = "sts.amazonaws.com"
SUB = "repo:%s:environment:sign" % REPO
JWR = "%s/.github/workflows/release.yml@refs/tags/v*" % REPO

def lint(rec):
    """the record as a text: an object with aud, sub and job_workflow_ref; aud and sub are exact (no wildcard); job_workflow_ref has one `*`, the tag suffix after refs/tags/v"""
    bad = []
    if not isinstance(rec, dict):
        return ["the record is not a JSON object"]
    for k in ("aud", "sub", "job_workflow_ref"):
        if not isinstance(rec.get(k), str) or not rec.get(k):
            bad.append("the record has no %s condition" % k)
    for k in ("aud", "sub"):
        if isinstance(rec.get(k), str) and re.search(r"[*?]", rec[k]):
            bad.append("the %s condition holds a wildcard" % k)
    j = rec.get("job_workflow_ref")
    if isinstance(j, str) and j.count("*") + j.count("?") != 1 or isinstance(j, str) and not j.endswith("@refs/tags/v*"):
        bad.append("job_workflow_ref is not pinned to one file at a v* tag (the only wildcard is the tag suffix after refs/tags/v)")
    if rec.get("sub") != SUB and isinstance(rec.get("sub"), str):
        bad.append("sub is not %s" % SUB)
    if rec.get("job_workflow_ref") != JWR and isinstance(j, str):
        bad.append("job_workflow_ref is not %s" % JWR)
    if rec.get("aud") != AUD and isinstance(rec.get("aud"), str):
        bad.append("aud is not %s" % AUD)
    return bad

def evaluate(rec, tok):
    """accept a token only when aud and sub are EQUAL to the record's and job_workflow_ref matches it (the single trailing * stands for the rest of the tag name, never a slash-free guess)"""
    if tok.get("aud") != rec["aud"]:
        return False, "the audience differs"
    if tok.get("sub") != rec["sub"]:
        return False, "the subject differs"
    pat, ref = rec["job_workflow_ref"], tok.get("job_workflow_ref", "")
    prefix = pat[:-1]
    if not (pat.endswith("*") and ref.startswith(prefix) and len(ref) > len(prefix)):
        return False, "job_workflow_ref differs"
    return True, "accepted"

def tok(**kw):
    t = {"aud": AUD, "sub": SUB, "job_workflow_ref": "%s/.github/workflows/release.yml@refs/tags/v0.3.0" % REPO}
    t.update(kw)
    return t
WF = lambda f, ref="refs/tags/v0.3.0", repo=REPO: "%s/.github/workflows/%s@%s" % (repo, f, ref)
TOKENS = [   # name, token, accepted
    ("sign-from-release-yml-at-a-tag", tok(), True),
    ("sign-from-release-yml-at-a-patch-tag", tok(job_workflow_ref=WF("release.yml", "refs/tags/v0.3.1")), True),
    ("sign-from-release-yml-at-an-rc-tag", tok(job_workflow_ref=WF("release.yml", "refs/tags/v0.3.0-rc1")), True),
    ("environment-release", tok(sub="repo:%s:environment:release" % REPO), False),
    ("environment-release-persona-file", tok(sub="repo:%s:environment:release" % REPO, job_workflow_ref=WF("persona-uat.yml")), False),
    ("environment-evidence-letter", tok(sub="repo:%s:environment:evidence-letter" % REPO, job_workflow_ref=WF("evidence-letter.yml", "refs/heads/main")), False),
    ("environment-evidence-letter-from-release-yml", tok(sub="repo:%s:environment:evidence-letter" % REPO), False),
    ("environment-persona-uat", tok(sub="repo:%s:environment:persona-uat" % REPO, job_workflow_ref=WF("persona-uat.yml")), False),
    ("environment-persona-uat-from-release-yml", tok(sub="repo:%s:environment:persona-uat" % REPO), False),
    ("no-environment-tag-push", tok(sub="repo:%s:ref:refs/tags/v0.3.0" % REPO), False),
    ("no-environment-branch-push", tok(sub="repo:%s:ref:refs/heads/main" % REPO, job_workflow_ref=WF("release.yml", "refs/heads/main")), False),
    ("no-environment-pull-request", tok(sub="repo:%s:pull_request" % REPO, job_workflow_ref=WF("ci.yml", "refs/pull/1/merge")), False),
    ("sign-from-ci-yml", tok(job_workflow_ref=WF("ci.yml")), False),
    ("sign-from-scan-yml", tok(job_workflow_ref=WF("scan.yml")), False),
    ("sign-from-persona-uat-yml", tok(job_workflow_ref=WF("persona-uat.yml")), False),
    ("sign-from-main-candidate-rescan-yml", tok(job_workflow_ref=WF("main-candidate-rescan.yml")), False),
    ("sign-from-release-yml-on-a-branch", tok(job_workflow_ref=WF("release.yml", "refs/heads/main")), False),
    ("sign-from-release-yml-at-a-non-v-tag", tok(job_workflow_ref=WF("release.yml", "refs/tags/x1")), False),
    ("sign-from-release-yml-with-no-tag-name", tok(job_workflow_ref=WF("release.yml", "refs/tags/v")), False),
    ("sign-from-a-lookalike-file", tok(job_workflow_ref=WF("release.yml.evil", "refs/tags/v0.3.0")), False),
    ("sign-from-a-nested-path", tok(job_workflow_ref="%s/.github/workflows/sub/release.yml@refs/tags/v0.3.0" % REPO), False),
    ("another-repository", tok(sub="repo:evil/cache:environment:sign", job_workflow_ref=WF("release.yml", repo="evil/cache")), False),
    ("another-repository-same-prefix", tok(sub="repo:%s2:environment:sign" % REPO, job_workflow_ref=WF("release.yml", repo=REPO + "2")), False),
    ("a-fork-with-the-real-workflow-ref", tok(sub="repo:evil/cache:environment:sign"), False),
    ("another-audience", tok(aud="sigstore"), False),
    ("another-audience-suffix", tok(aud=AUD + ".evil"), False),
    ("audience-in-another-case", tok(aud="STS.amazonaws.com"), False),
    ("no-audience", {k: v for k, v in tok().items() if k != "aud"}, False),
    ("environment-sign-with-a-suffix", tok(sub=SUB + "-x"), False),
    ("environment-sign-prefix-only", tok(sub=SUB[:-1]), False),
    ("environment-star", tok(sub="repo:%s:environment:*" % REPO), False),
    ("subject-of-any-ref", tok(sub="repo:%s:*" % REPO), False),
]

def record():
    return json.load(open(sys.argv[2]))

if sys.argv[1] == "names":
    print(" ".join(n for n, _, _ in TOKENS)); sys.exit(0)
if sys.argv[1] == "want":
    print("accepted" if {n: a for n, _, a in TOKENS}[sys.argv[2]] else "refused"); sys.exit(0)
if sys.argv[1] == "accepted":
    print(" ".join(n for n, _, a in TOKENS if a)); sys.exit(0)

if sys.argv[1] == "lint":
    bad = lint(record())
    print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
if sys.argv[1] == "token":
    rec = record()
    name = sys.argv[3]
    want = {n: a for n, _, a in TOKENS}[name]
    t = {n: t for n, t, _ in TOKENS}[name]
    got, why = evaluate(rec, t)
    print("%s (%s)" % ("accepted" if got else "refused", why)); sys.exit(0 if got == want else 1)
PY
REC="$root/.github/policy/release-signing-trust.json"
report() { # report NAME RC TEXT WANT
  if [ "$2" = 0 ]; then pass=$((pass+1)); echo "PASS $1 -> $3"; else failn=$((failn+1)); echo "FAIL $1 -> $3 ${4:-}"; fi
}
# the record exists and is well formed text (it is the test's input: a missing record fails every case)
if [ ! -f "$REC" ]; then
  failn=$((failn+1)); echo "FAIL .github/policy/release-signing-trust.json does not exist (REQ-CHAIN-001-AC8: the trust text of the release signing key's role, held as a record)"
else
  rc=0; out=$(python3 "$work/trust.py" lint "$REC" 2>&1) || rc=$?; report "the real record is a well-formed trust text" "$rc" "$out"
fi
# one case per token, each on its own, against the real record
for name in $(python3 "$work/trust.py" names); do
  if [ ! -f "$REC" ]; then failn=$((failn+1)); echo "FAIL token $name -> no record to evaluate against"; continue; fi
  rc=0; out=$(python3 "$work/trust.py" token "$REC" "$name" 2>&1) || rc=$?
  report "token $name must be $(python3 "$work/trust.py" want "$name")" "$rc" "$out"
done
# the accepted tokens: sign from release.yml at a v* tag (its tag forms: final, patch, release candidate), nothing else
acc=$(python3 "$work/trust.py" accepted)
if [ "$acc" = "sign-from-release-yml-at-a-tag sign-from-release-yml-at-a-patch-tag sign-from-release-yml-at-an-rc-tag" ]; then pass=$((pass+1)); echo "PASS the accepted tokens are the tag forms of sign from release.yml, nothing else"
else failn=$((failn+1)); echo "FAIL the accepted tokens listed are: $acc"; fi
# the record as a text: mutated copies, each refused for its reason (a record that accepts a wildcard subject could never refuse a token of another environment)
lint_case() { # lint_case NAME WORD PYEDIT
  local f="$work/rec-$1.json"
  if [ -f "$REC" ]; then cp "$REC" "$f"; else echo '{}' > "$f"; fi
  python3 - "$f" "$3" <<'PY'
import json, sys
p, edit = sys.argv[1], sys.argv[2]
r = json.load(open(p))
exec(edit)
json.dump(r, open(p, "w"))
PY
  local rc=0 out; out=$(python3 "$work/trust.py" lint "$f" 2>&1) || rc=$?
  if [ "$rc" = 1 ] && grep -Fq -- "$2" <<< "$out"; then pass=$((pass+1)); echo "PASS record:$1 -> refused ($2)"
  else failn=$((failn+1)); echo "FAIL record:$1 -> rc=$rc, wanted a refusal containing '$2': $out"; fi
}
lint_case sub-wildcard        "sub condition holds a wildcard" "r['sub'] = 'repo:fosterstack/cache:environment:*'"
lint_case sub-repo-wildcard   "sub condition holds a wildcard" "r['sub'] = 'repo:fosterstack/*:environment:sign'"
lint_case aud-wildcard        "aud condition holds a wildcard"  "r['aud'] = '*'"
lint_case sub-other-env       "sub is not"                      "r['sub'] = 'repo:fosterstack/cache:environment:release'"
lint_case aud-other           "aud is not"                      "r['aud'] = 'sigstore'"
lint_case jwr-any-file        "job_workflow_ref is not pinned"  "r['job_workflow_ref'] = 'fosterstack/cache/.github/workflows/*@refs/tags/v*'"
lint_case jwr-any-ref         "job_workflow_ref is not pinned"  "r['job_workflow_ref'] = 'fosterstack/cache/.github/workflows/release.yml@*'"
lint_case jwr-branch          "job_workflow_ref is not"         "r['job_workflow_ref'] = 'fosterstack/cache/.github/workflows/release.yml@refs/heads/main'"
lint_case jwr-other-file      "job_workflow_ref is not"         "r['job_workflow_ref'] = 'fosterstack/cache/.github/workflows/scan.yml@refs/tags/v*'"
lint_case jwr-gone            "no job_workflow_ref condition"   "r.pop('job_workflow_ref', None)"
lint_case sub-gone            "no sub condition"                "r.pop('sub', None)"
lint_case aud-gone            "no aud condition"                "r.pop('aud', None)"
lint_case not-an-object       "not a JSON object"               "r = ['aud']"

echo "chain-signing-trust: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
