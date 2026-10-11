#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC17, REQ-CHAIN-006-AC1, REQ-CHAIN-006-AC2, REQ-CHAIN-006-AC3, REQ-CHAIN-006-AC8, REQ-CHAIN-006-AC9, REQ-CHAIN-006-AC10, REQ-CHAIN-006-AC11, REQ-CHAIN-006-AC12, REQ-CHAIN-006-AC13, REQ-CHAIN-006-AC5, REQ-CHAIN-006-AC14, REQ-CHAIN-007-AC15
# RED until PR 3 is implemented (stage-verify.yml rewritten, bin/check-*.sh, bin/witnessed.sh, release.yml graph, the old acceptance stages removed): step 4.
#
# Check, static half (v0.3.0 rules 50, 53, 55, 58, 61, 63, 65, 66, 68, 70, 72, 79; advisor read-back approved Oct 9; PR 3 merges into chain-v030 only).
# Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml), jq. No network, no secrets, no keys.
# Every judge lives in bin/chain-check-shape.py and is FIRST proven on a known-good fixture and on mutated copies (a judge that cannot fail
# is worth nothing), then applied to the real repository, which must pass. Finite grammars and allowlists, no shell analysis.
#
# WHAT IS FIXED BY AN EXISTING FILE and what is PROPOSED/UNVERIFIED (the lines marked [P] may change when the implementation PR is written):
#   [F] .github/policy/scanners.json lists the release scanners (today grype and osv-scanner); REQ-REL-004-AC1 (every scanner reports its package
#       count, zero fails); /statusz reports "fips140" (bool) and "fips140_note" (internal/server/status.go:30-31, internal/buildinfo/buildinfo.go:85-97:
#       "active (Go validated module v1.0.0, CMVP cert #5247)" for the validated build, "off" for the standard one).
#   [F] PR 1's bin/chain-verify.py contract (stage-start, verify) and PR 2's artifact names (witness-build, digests, dist, locks) and the OCI index
#       digest outputs (OUT/<variant>.tar, .digest, .manifests) of cache's assemble-image.sh.
#   [P] images arrive as files under images/ (OCI tarballs from Build's artifacts; Check logs in to no registry), the artifact names `provenance`
#       (Sign's bundle) and `check-results`/`witness-check` (Check's), the five script names and command lines of bin/check-stage.sh, the guide
#       file docs/verify-release.md (the www lane's customer guide), the results file names.
#
# RULE 68 AS AMENDED BY THE OWNER (Oct 9, 16:47 EDT): every command run under Witness is limited to 9 minutes (`timeout 540`), because Fulcio's
# certificate lives 10 minutes and Witness checks it at the TIMESTAMP's time (harness spike (d): a 13-minute command yields a record that never
# verifies). The cap lives in ONE place, the helper bin/witnessed.sh (PR 2 defines it; judge `helper` below is its seam and is kept identical to
# PR 2's). Check is split into three plainly named witnessed steps (scanners / acceptance / runtime) so none nears the cap. The owner also asked
# for code a human can read: the stage file is four short lines, the helper is the only place with Witness flags, the judges accept the plain form
# and reject variants instead of growing clever.
#
# CREDENTIALS (coordinator correction, Oct 9): Check holds NO secret and no cloud federation: the release scanners need none. id-token: write is
# only for Witness to sign Check's own record. A test below refuses a secret, a registry login and a packages/attestations permission.
#
# STEP-5 REVISIT (advisor rulings Q2-Q8, Oct 10), what changed and why:
#   Q2 the helper judge is PR 2's accepted bin/witnessed.sh (token by process substitution, witness-STEP/STEP-collection.json, the four
#      sensitive keys) plus PR 3's three steps in its closed list; witness-check carries the three record directories.
#   Q3 bin/check-stage.sh is judged by `script` only (its pinned lines name witness-build/), and its verify lines run python3 -I -B (PR 1 r5).
#   Q4 the Check job downloads the images artifact exactly once. Q7 acceptance.yml runs the shared suite scripts (`suites`).
#   Q5 (Oct 10, second ruling) bin/check-stage.sh first MAKES policy.json per tag, as PR 2's Rebuild does (`script` judge, POLICY line).
#   Q9 the last stage's job in release.yml is named release (the ratified rules' name), not promotion; check needs build AND sign.
#   Q10 bin/check-guide.sh may name exactly the verify-only commands (cosign verify, verify-attestation, verify-blob,
#      verify-blob-attestation, gh attestation verify); the `plain` judge keeps refusing every other signing word there, and refuses even
#      these in every other check script.
#   Q10 interim (advisor, Oct 10 late): the guide's commands that need a registry image are listed in docs/verify-release.cannot-run.json;
#      bin/check-guide.sh records them as not-run (it exits 0 for listed entries), but while that list is non-empty AC7 is NOT satisfied:
#      the `guidelist` case below FAILS with the line "rule 79: N guide commands listed as not-run: <list>" (and fails while the guide is
#      missing). It passes only for a guide whose cannot-run list is empty or absent.
#   Graph aligned with PR 2 (3e883b3): the release job needs EXACTLY check, rebuild and sign (build is reached through check); check
#      needs exactly build and sign.
#   Q8 REQ-CHAIN-006-AC14: kind and kubectl from bin/install-kind.sh (exact versions, amd64 sha256 committed), no kind action, the node
#      image by digest (`kind`, `cluster`); the runtime phase runs the k8s suite.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shape="$root/bin/chain-check-shape.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
judge() { python3 "$shape" "$@"; }
expect() { # expect ok|caught LABEL WORD args...  (WORD: a word the fault message must contain, for caught)
  local want=$1 label=$2 word=$3; shift 3; local out rc=0
  out=$(judge "$@" 2>&1) || rc=$?
  if [ "$want" = ok ]; then
    if [ "$rc" = 0 ]; then ok "$label"; else bad "$label -> $out"; fi
  else
    if [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$out"; then ok "$label (caught: ${out:0:90})"; else bad "$label -> rc=$rc, wanted a refusal containing '$word': ${out:0:140}"; fi
  fi
}
mutate() { # mutate SRC DST REGEX REPLACEMENT   (a pattern that no longer matches is a FAILURE, never a skipped case)
  python3 - "$1" "$2" "$3" "$4" <<'PY' || { bad "mutation did not apply: $3"; return 1; }
import re, sys
t = open(sys.argv[1]).read()
n = re.sub(sys.argv[3], sys.argv[4].replace("\\n", "\n"), t, count=1, flags=re.S)
assert n != t, "mutation did not change the fixture"
open(sys.argv[2], "w").write(n)
PY
}
# ---- known-good fixtures ----------------------------------------------------------------------------------------------
python3 - "$work" <<'PY'
import sys, os
w = sys.argv[1]
CHK = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
UPL = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
DWN = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
def dn(name, path): return f"      - uses: {DWN}\n        with:\n          name: {name}\n          path: {path}\n"
def up(name, path): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: {path}\n"
def wit(step): return f"      - name: {step}\n        run: bash bin/witnessed.sh {step} bin/check-phase-{step}.sh\n"
stage = ("name: 'Stage: check'\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-24.04\n"
         "    permissions:\n      contents: read\n      id-token: write\n    steps:\n"
         f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
         "      - name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness\n"
         "      - name: install kind and kubectl (pinned by sha256)\n        run: bash bin/install-kind.sh\n"
         + dn("witness-build", "witness-build") + dn("digests", "witness-build") + dn("provenance", "provenance") + dn("dist", "dist")
         + dn("images", "images")
         + wit("scanners") + wit("acceptance") + wit("runtime")
         + f"      - uses: {UPL}\n        with:\n          name: witness-check\n          path: |\n            witness-scanners\n            witness-acceptance\n            witness-runtime\n"
         + up("check-results", "check-results"))
# REQ-CHAIN-006-AC1 (advisor 0385): the second job, check-arm64, on a hosted arm64 runner, artifact checks only, its own Witness record
stage += ("  check-arm64:\n    runs-on: ubuntu-24.04-arm\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n"
          f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
          "      - name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness\n"
          + dn("witness-build", "witness-build") + dn("digests", "witness-build") + dn("provenance", "provenance") + dn("dist", "dist") + dn("images", "images")
          + "      - name: arm64 under Witness\n        run: bash bin/witnessed.sh arm64 bin/check-phase-arm64.sh\n"
          + up("witness-check-arm64", "witness-arm64"))
open(w + "/stage.yml", "w").write(stage)
open(w + "/witnessed.sh", "w").write("""#!/usr/bin/env bash
# PR 2's helper (origin/pipeline-chain-build-rebuild) with PR 3's three steps in the closed list.
set -euo pipefail
step="$1"
shift
case "$step" in apk|build|rapk|rebuild|snapshot-apk|snapshot-build|snapshot-rapk|snapshot-rebuild|scanners|acceptance|runtime|arm64|release-verify|release-apks|release-publish|release-sign|release-assets|release-postverify) ;; *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac
mkdir -p "witness-${step#snapshot-}"
tok=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)
echo "::add-mask::$tok"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL
exec witness run --step "$step" \\
  --signer-fulcio-url https://fulcio.sigstore.dev \\
  --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \\
  --signer-fulcio-oidc-client-id sigstore \\
  --signer-fulcio-token-path <(printf %s "$tok") \\
  -t https://timestamp.sigstore.dev/api/v1/timestamp \\
  -a environment,git,material,product \\
  --env-filter-sensitive-vars \\
  --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' \\
  --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN \\
  --env-add-sensitive-key GH_TOKEN \\
  --env-add-sensitive-key GITHUB_TOKEN \\
  --env-add-sensitive-key APK_RELEASE_SIGNING_KEY \\
  --env-add-sensitive-key DOCKERHUB_USERNAME \\
  --env-add-sensitive-key DOCKERHUB_TOKEN \\
  -o "witness-${step#snapshot-}/$step-collection.json" -- timeout 540 bash "$@"
""")
V = ["python3 -I -B bin/chain-verify.py stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json",
     "python3 -I -B bin/chain-verify.py verify --stage sign --record provenance/provenance.json --policy policy.json --rekor-stub provenance/provenance.rekor.json"]
PH = [("scanners", ["bash bin/check-scan.sh --scanners .github/policy/scanners.json --digests witness-build/digests.json --images images --archives dist --out check-results"]),
      ("acceptance", ["bash bin/check-acceptance.sh gradle --digests witness-build/digests.json --images images --out check-results",
                      "bash bin/check-acceptance.sh maven --digests witness-build/digests.json --images images --out check-results"]),
      ("runtime", ["bash bin/check-acceptance.sh egress --digests witness-build/digests.json --images images --out check-results",
                   "bash bin/check-acceptance.sh k8s --digests witness-build/digests.json --images images --out check-results",
                   "bash bin/check-fips.sh --digests witness-build/digests.json --images images --out check-results",
                   "bash bin/check-artifacts.sh --digests witness-build/digests.json --images images --archives dist --out check-results",
                   "bash bin/check-guide.sh --guide docs/verify-release.md --digests witness-build/digests.json --images images --out check-results"])]
POL = 'python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json'
body = "set -euo pipefail\n" + POL + "\n" + "\n".join(V) + '\ncase "$1" in\n'
for n, cs in PH:
    body += n + ")\n" + "".join(c + "\n" for c in cs) + ";;\n"
body += '*) echo "unknown phase: $1" >&2; exit 2 ;;\nesac\n'
open(w + "/script.sh", "w").write("#!/usr/bin/env bash\n" + body)
import json
open(w + "/records.json", "w").write(json.dumps({"records": [
    {"type": "https://witness.testifysec.com/attestation-collection/v0.1", "claim": "what Build, Rebuild and Check each observed and found", "consumer": "release"},
    {"type": "https://slsa.dev/provenance/v1", "claim": "how the release was built", "consumer": "release"}]}))
open(w + "/release.yml", "w").write("""name: Release
on:
  push:
    tags: ["v*"]
jobs:
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
  release:
    needs: [check, rebuild, sign]
    uses: ./.github/workflows/stage-promote.yml
""")
open(w + "/install-kind.sh", "w").write("""#!/usr/bin/env bash
# kind and kubectl for the Check runner (REQ-CHAIN-006-AC14).
set -euo pipefail
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "install-kind: only linux amd64 is pinned (the Check runner is ubuntu-24.04)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/kind" https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64
curl -fsSL -o "$tmp/kubectl" https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl
printf '%s  %s\\n' aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d "$tmp/kind" 6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f "$tmp/kubectl" | sha256sum -c -
install -m 0755 "$tmp/kind" "$tmp/kubectl" /usr/local/bin/
kind version
kubectl version --client
""")
open(w + "/k8s.sh", "w").write("#!/usr/bin/env bash\nset -eo pipefail\ncreate_cluster() (\nkind create cluster --name fscache-accept --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5\n)\ncreate_cluster\n")
open(w + "/acceptance.yml", "w").write("""name: Acceptance
on:
  pull_request:
jobs:
  acceptance-gradle:
    runs-on: ubuntu-latest
    steps:
      - run: echo start
      - run: bash bin/acceptance-gradle.sh
      - id: results
        run: bash bin/acceptance-gradle-capped.sh
  acceptance-maven:
    runs-on: ubuntu-latest
    steps:
      - run: bash bin/acceptance-maven.sh
      - id: results
        run: bash bin/acceptance-maven-capped.sh
""")
os.makedirs(w + "/plain", exist_ok=True)
for n in ("check-stage", "check-phase-scanners", "check-phase-acceptance", "check-phase-runtime", "check-phase-arm64", "check-scan", "check-fips", "check-artifacts", "check-acceptance", "check-guide"):
    open(f"{w}/plain/{n}.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\ngrype --version\nosv-scanner --version\ndocker run --rm -d image\ncurl -sS http://127.0.0.1:8080/statusz\n")
PY
expect ok "fixture: the known-good stage-verify.yml passes the stage judge" "" stage "$work/stage.yml"
expect ok "fixture: the known-good bin/check-stage.sh passes the script judge" "" script "$work/script.sh"
expect ok "fixture: the known-good bin/witnessed.sh passes the helper judge (rule 68 seam)" "" helper "$work/witnessed.sh"
# ---- the thin phase targets (ruling 0384): bin/witnessed.sh admits exactly `STEP TARGET`, so each step has a one-line target ------------------
for s in scanners acceptance runtime; do printf '#!/usr/bin/env bash\nbash bin/check-stage.sh %s\n' "$s" > "$work/ph_$s.sh"; done
expect ok "fixture: a known-good phase target passes the phase judge" "" phase "$work/ph_scanners.sh" scanners
printf '#!/usr/bin/env bash\nbash bin/check-stage.sh runtime\n' > "$work/ph_wrong.sh"
expect caught "AC3 a phase target that runs another phase" "exactly the one line" phase "$work/ph_wrong.sh" scanners
printf '#!/usr/bin/env bash\nbash bin/check-stage.sh scanners\ntrue\n' > "$work/ph_extra.sh"
expect caught "AC3 a phase target with a second command" "exactly the one line" phase "$work/ph_extra.sh" scanners
printf '#!/usr/bin/env bash\nbash bin/check-stage.sh scanners || true\n' > "$work/ph_swallow.sh"
expect caught "AC3 a phase target that swallows a failure" "exactly the one line" phase "$work/ph_swallow.sh" scanners
expect caught "AC3 a phase outside the closed list" "unknown phase" phase "$work/ph_scanners.sh" checks
ARMV='python3 -I -B bin/chain-verify.py'
ARML='bash bin/check-artifacts.sh --arch arm64 --digests witness-build/digests.json --images images --archives dist --out check-results'
armt() { # armt FILE LINE... : an arm64 target holding exactly these lines after the shebang
  local f=$1; shift; { printf '#!/usr/bin/env bash\n'; printf '%s\n' "$@"; } > "$f"; }
P1="$ARMV policy make --template .github/policy/release-policy.template.json --tag \"\$GITHUB_REF_NAME\" --out policy.json"
P2="$ARMV stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json"
P3="$ARMV verify --stage sign --record provenance/provenance.json --policy policy.json --rekor-stub provenance/provenance.rekor.json"
armt "$work/ph_arm64.sh" "set -euo pipefail" "$P1" "$P2" "$P3" "$ARML"
expect ok "fixture: the arm64 target passes the phase judge (rule 58: it verifies Build and Sign, then the artifact checks)" "" phase "$work/ph_arm64.sh" arm64
armt "$work/ph_arm64b.sh" "set -euo pipefail" "$P1" "$P2" "$P3" "${ARML/ --arch arm64/}"
expect caught "AC17 an arm64 target without --arch arm64" "exactly" phase "$work/ph_arm64b.sh" arm64
armt "$work/ph_arm64c.sh" "set -euo pipefail" "$P1" "$P2" "$P3" "$ARML || true"
expect caught "AC17 an arm64 target that swallows a failure" "exactly" phase "$work/ph_arm64c.sh" arm64
armt "$work/ph_arm64d.sh" "set -euo pipefail" "$P1" "$P3" "$ARML"
expect caught "rule 58 an arm64 target that does not verify Build's record (no stage-start)" "exactly" phase "$work/ph_arm64d.sh" arm64
armt "$work/ph_arm64e.sh" "set -euo pipefail" "$P1" "$P2" "$ARML"
expect caught "rule 58 an arm64 target that does not verify Sign's provenance" "exactly" phase "$work/ph_arm64e.sh" arm64
armt "$work/ph_arm64f.sh" "set -euo pipefail" "$P1" "$P2" "$ARML" "$P3"
expect caught "rule 58 an arm64 target that checks the artifacts before it verifies Sign" "exactly" phase "$work/ph_arm64f.sh" arm64
armt "$work/ph_arm64g.sh" "set -euo pipefail" "$P1" "${P2/python3 -I -B/python3}" "$P3" "$ARML"
expect caught "rule 58 an arm64 target whose verifier is not isolated" "exactly" phase "$work/ph_arm64g.sh" arm64
armt "$work/ph_arm64h.sh" "set -euo pipefail" "$P1" "${P2/witness-build\/digests.json/other\/digests.json}" "$P3" "$ARML"
expect caught "rule 58 an arm64 target that verifies other digests than the ones it checks" "exactly" phase "$work/ph_arm64h.sh" arm64
armt "$work/ph_arm64i.sh" "$P1" "$P2" "$P3" "$ARML"
expect caught "an arm64 target without set -euo pipefail" "exactly" phase "$work/ph_arm64i.sh" arm64
expect ok "fixture: the known-good chain-records.json passes the records judge" "" records "$work/records.json"
expect ok "fixture: the known-good release.yml passes the graph judge" "" graph "$work/release.yml"
expect ok "fixture: plain scripts that only use scanners, docker and curl pass the plain judge" "" plain "$work"/plain/check-*.sh
expect ok "fixture: the known-good bin/install-kind.sh passes the kind judge (AC14)" "" kind "$work/install-kind.sh"
expect ok "fixture: the known-good k8s suite passes the cluster judge (AC14)" "" cluster "$work/k8s.sh"
expect ok "fixture: the known-good acceptance.yml passes the suites judge (AC5)" "" suites "$work/acceptance.yml"
# ---- AC1/AC9: the stage file, mutated one rule at a time ----------------------------------------------------------------
m() { # m NAME REGEX REPL WORD LABEL
  if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" stage "$work/$1.yml"; fi
}
m s_job2   'jobs:\n  check:'                                  'jobs:\n  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n  check:'  'exactly two jobs'  "AC1 a third job"
m s_selfh  'runs-on: ubuntu-24.04'                             'runs-on: self-hosted'                                  'ubuntu-24.04'      "AC1 a self-hosted runner"
m s_cont   '    runs-on: ubuntu-24.04\n'                       '    runs-on: ubuntu-24.04\n    container: alpine\n'       'job keys'          "AC1 a job container"
m s_serv   '    runs-on: ubuntu-24.04\n'                       '    runs-on: ubuntu-24.04\n    services: {db: {image: x}}\n' 'job keys'        "AC1 job services"
m s_env    '    runs-on: ubuntu-24.04\n'                       '    runs-on: ubuntu-24.04\n    env: {X: y}\n'              'job keys'          "AC1 job env"
m s_def    '    runs-on: ubuntu-24.04\n'                       '    runs-on: ubuntu-24.04\n    defaults: {run: {shell: sh}}\n' 'job keys'      "AC1 job defaults"
m s_needs  '    runs-on: ubuntu-24.04\n'                       '    runs-on: ubuntu-24.04\n    needs: x\n'                 'job keys'          "AC1 a needs inside the stage file"
m s_pkgw   'id-token: write\n    steps'                      'id-token: write\n      packages: write\n    steps'     'permissions'       "AC1 packages: write"
m s_pkgr   'id-token: write\n    steps'                      'id-token: write\n      packages: read\n    steps'      'permissions'       "AC1 packages: read (images travel as files)"
m s_att    'id-token: write\n    steps'                      'id-token: write\n      attestations: write\n    steps'  'permissions'       "AC1 attestations: write"
m s_noid   'id-token: write'                                   'id-token: none'                                         'permissions'       "AC1 no id-token"
m s_sec    'name: scanners'                                   'name: scanners\n        env:\n          K: ${{ secrets.SNYK_TOKEN }}'  'step keys'  "AC1 a secret in a step"
m s_login  '      - name: install Witness'                     '      - name: login\n        run: echo x | docker login ghcr.io -u u --password-stdin\n      - name: install Witness' 'registry login' "AC1 a registry login"
m s_unp    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v4'                                  'digest-pinned'    "AC1 an unpinned checkout"
m s_persist 'persist-credentials: false'                       'persist-credentials: true'                              'persist-credentials' "AC1 persisted credentials"
m s_dlname 'name: provenance'                                  'name: not-listed'                                       'download-artifact' "AC1 a download outside the allowlist"
m s_dlbin  'path: provenance'                                  'path: bin'                                              'download-artifact' "AC1 a download into bin/"
m s_upname 'name: check-results'                               'name: anything'                                         'upload-artifact'   "AC1 an upload outside the allowlist"
m s_ghscr  '      - name: install Witness'                     '      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n      - name: install Witness' 'uses not allowed' "AC1 github-script"
m s_comp   '      - name: install Witness'                     '      - uses: ./.github/actions/x\n      - name: install Witness'  'uses not allowed' "AC1 a local composite action"
m s_after  '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-check' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: dist2\n      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-check' 'after Witness' "AC1 a download after Witness started"
m s_wf     'permissions:\n  contents: read\njobs'             'permissions:\n  contents: read\nenv: {A: b}\njobs'      'workflow keys'     "AC1 workflow env"
m s_trig   'workflow_call:'                                    'workflow_call:\n  push:'                                  'workflow_call'     "AC1 an extra trigger"
m s_direct 'run: bash bin/witnessed.sh scanners bin/check-phase-scanners.sh' 'run: witness run --step scanners -- ./bin/check-stage.sh'  'witnessed.sh' "AC11 a direct witness run in the stage file (the helper is the one place)"
m s_tmo    'run: bash bin/witnessed.sh scanners bin/check-phase-scanners.sh' 'run: timeout 540 bash bin/witnessed.sh scanners bin/check-phase-scanners.sh' 'witnessed.sh' "AC11 timeout boilerplate repeated in the stage file"
m s_name   'witnessed.sh runtime bin/check-phase-runtime.sh'  'witnessed.sh checks bin/check-phase-checks.sh'  'exactly' "AC11 a step name outside the closed list"
m s_mism   'witnessed.sh acceptance bin/check-phase-acceptance.sh' 'witnessed.sh acceptance bin/check-phase-runtime.sh' 'witnessed.sh' "AC11 the step name and the phase differ"
m s_four   '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-check' '      - name: extra\n        run: bash bin/witnessed.sh extra bin/check-phase-extra.sh\n      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-check' 'THREE' "AC11 a fourth witnessed step"
m s_order  '      - name: scanners\n        run: bash bin/witnessed.sh scanners bin/check-phase-scanners.sh\n      - name: acceptance\n        run: bash bin/witnessed.sh acceptance bin/check-phase-acceptance.sh\n' '      - name: acceptance\n        run: bash bin/witnessed.sh acceptance bin/check-phase-acceptance.sh\n      - name: scanners\n        run: bash bin/witnessed.sh scanners bin/check-phase-scanners.sh\n' 'in that order' "AC11 the steps run in another order"
m s_threeup 'witness-runtime\n' 'elsewhere\n' 'upload-artifact' "AC12 a record directory is not what witness-check uploads"
m s_img2   'name: images\n          path: images\n' 'name: images\n          path: images\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images2\n' 'exactly one download of the images' "AC1 a second download of the images artifact (Q4)"
m s_imgno  '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images\n' '' 'exactly one download of the images' "AC1 no download of the images artifact (Q4)"
m s_imgother 'name: images\n          path: images' 'name: image-cache\n          path: images' 'download-artifact' "AC1 another artifact name in place of images (Q4)"
m s_kindact '        run: bash bin/install-kind.sh\n' '        uses: helm/kind-action@06c1ae10762d3b9c1644e7fe69596ae519e015a2 # v1.15.0\n' 'uses not allowed' "AC14 helm/kind-action in place of the pinned install"
m s_kindform 'run: bash bin/install-kind.sh' 'run: bash bin/install-kind.sh \&\& kind create cluster' 'witnessed.sh' "AC14 the install step in another form"
# the arm64 job (advisor 0385): exactly this job, this label, these steps, and nothing else
m a_name   '  check-arm64:'                                    '  check-arm:'                                              'two jobs'          "AC1 the second job under another name"
m a_label  'runs-on: ubuntu-24.04-arm'                         'runs-on: ubuntu-24.04'                                  'ubuntu-24.04-arm'  "AC1 the arm64 job on the amd64 label"
m a_label2 'runs-on: ubuntu-24.04-arm'                         'runs-on: ubuntu-latest-arm'                             'ubuntu-24.04-arm'  "AC1 the arm64 job on another arm label"
m a_self   'runs-on: ubuntu-24.04-arm'                         'runs-on: self-hosted'                                   'ubuntu-24.04-arm'  "AC1 the arm64 job on a self-hosted runner"
m a_if     '  check-arm64:\n    runs-on'                       '  check-arm64:\n    if: always()\n    runs-on'             'check-arm64'       "AC1 an if on the arm64 job"
m a_needs  '  check-arm64:\n    runs-on'                       '  check-arm64:\n    needs: check\n    runs-on'         'check-arm64'       "AC1 a needs on the arm64 job"
m a_idoff  'ubuntu-24.04-arm\n    permissions:\n      contents: read\n      id-token: write' 'ubuntu-24.04-arm\n    permissions:\n      contents: read\n      id-token: none' 'check-arm64' "AC1 a different id-token setting on the arm64 job"
m a_idread 'ubuntu-24.04-arm\n    permissions:\n      contents: read\n      id-token: write' 'ubuntu-24.04-arm\n    permissions:\n      contents: read' 'check-arm64' "AC1 no id-token on the arm64 job"
m a_pkg    'ubuntu-24.04-arm\n    permissions:\n      contents: read\n      id-token: write' 'ubuntu-24.04-arm\n    permissions:\n      contents: read\n      id-token: write\n      packages: read' 'check-arm64' "AC1 packages: read on the arm64 job"
m a_sec    'name: arm64 under Witness\n'                       'name: arm64 under Witness\n        env:\n          K: ${{ secrets.SNYK_TOKEN }}\n' 'secret'  "AC1 a secret in the arm64 job"
m a_extra  'name: arm64 under Witness\n'                       'name: extra\n        run: bash bin/install-kind.sh\n      - name: arm64 under Witness\n' 'check-arm64' "AC1 an extra step in the arm64 job"
m a_nokind '      - name: arm64 under Witness\n        run: bash bin/witnessed.sh arm64 bin/check-phase-arm64.sh\n' '' 'check-arm64' "AC1 the arm64 job without its witnessed step"
m a_noinst '      - name: install Witness \(pinned by checksum\)\n        run: bash bin/install-scanner.sh witness\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: witness-build\n          path: witness-build\n' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: witness-build\n          path: witness-build\n' 'check-arm64' "AC1 the arm64 job without the Witness install"
m a_nowb   '          name: witness-build\n          path: witness-build\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: digests\n          path: witness-build\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: provenance\n          path: provenance\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: dist\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images\n      - name: arm64' '          name: digests\n          path: witness-build\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: provenance\n          path: provenance\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: dist\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: images\n          path: images\n      - name: arm64' 'check-arm64' "rule 58 the arm64 job without the Build record download"
m a_stepwhat 'run: bash bin/witnessed.sh arm64 bin/check-phase-arm64.sh' 'run: bash bin/witnessed.sh arm64 bin/check-phase-runtime.sh' 'check-arm64' "AC1 the arm64 step with another target"
m a_stepname 'run: bash bin/witnessed.sh arm64 bin/check-phase-arm64.sh' 'run: bash bin/witnessed.sh scanners bin/check-phase-scanners.sh' 'check-arm64' "AC1 the arm64 job running another step"
m a_upname 'name: witness-check-arm64'                         'name: check-results'                                    'check-arm64'       "AC1 the arm64 upload under another artifact name"
m a_uppath 'path: witness-arm64'                               'path: witness-scanners'                                 'check-arm64'       "AC1 the arm64 upload of another directory"
m a_dlimg  'name: images\n          path: images\n      - name: arm64' 'name: images\n          path: images\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: image-cache\n          path: image-cache\n      - name: arm64' 'check-arm64' "AC1 an extra download in the arm64 job"
m a_unpin  'name: install Witness \(pinned by checksum\)\n        run: bash bin/install-scanner.sh witness\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: witness-build' 'name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness\n      - uses: actions/download-artifact@v8\n        with:\n          name: digests' 'check-arm64' "AC1 an unpinned download in the arm64 job"
m s_kindno '      - name: install kind and kubectl \(pinned by sha256\)\n        run: bash bin/install-kind.sh\n' '' 'install kind' "AC14 no kind install step"
# ---- AC11: the helper (the rule 68 seam) -----------------------------------------------------------------------------
hm() { if mutate "$work/witnessed.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" helper "$work/$1.sh"; fi; }
hm h_notmo   ' -- timeout 540 bash "\$@"'                      ' -- bash "$@"'                                          'the helper'        "AC11 no timeout around the wrapped command"
hm h_600     'timeout 540'                                      'timeout 600'                                            'the helper'        "AC11 a cap of 10 minutes (the certificate lifetime)"
hm h_two     'echo "::add-mask'                                 'timeout 540 true\necho "::add-mask'                      'the helper'        "AC11 timeout stated twice"
hm h_twowit  'unset ACTIONS_RUNTIME_TOKEN'                      'witness run --step x -- true\nunset ACTIONS_RUNTIME_TOKEN' 'the helper'     "AC11 a second witness run"
hm h_dflag   '  -o "witness-'                                   '  -d out -o "witness-'                                   'the helper'        "AC9 the working-directory flag"
hm h_gh      '-a environment,git,material,product'              '-a environment,git,github,product'                      'the helper'        "AC9 the github attestor (it embeds the raw OIDC token)"
hm h_slsa    '-a environment,git,material,product'              '-a environment,git,material,product,slsa'               'the helper'        "AC9 the slsa attestor (Sign's alone)"
hm h_ts      '-t https://timestamp.sigstore.dev/api/v1/timestamp' '-t https://timestamp.example.com/api'                  'the helper'        "AC9 another timestamp authority"
hm h_fulcio  '--signer-fulcio-url https://fulcio.sigstore.dev'  '--signer-fulcio-url https://fulcio.example.com'          'the helper'        "AC9 another Fulcio"
hm h_nofilt  '  --env-filter-sensitive-vars \\\n'             ''                                                       'the helper'        "AC9 the environment filter dropped"
hm h_tok     '--env-add-sensitive-key GITHUB_TOKEN'             '--env-add-sensitive-key SOMETHING_ELSE'                  'the helper'        "AC9 a token variable no longer filtered"
hm h_out     '-o "witness-\$\{step#snapshot-\}/\$step-collection.json"' '-o elsewhere.json'                                'the helper'        "AC9 the record written elsewhere"
hm h_mask    'echo "::add-mask::\$tok"'                        'echo hi'                                                'the helper'        "AC9 the token is no longer masked"
hm h_unset   'unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL\n' ''                                    'the helper'        "AC9 the request variables stay set for the wrapped script"
hm h_tokfile '<\(printf %s "\$tok"\)'                         '"$RUNNER_TEMP/tok"'                                     'the helper'        "AC9 the token passed through a file (PR 2: one-read process substitution)"
hm h_noset   'set -euo pipefail\n'                              ''                                                       'the helper'        "AC11 the helper without set -euo pipefail"
hm h_nostep  '\|scanners\|acceptance\|runtime\|arm64\|release-verify\|release-apks\|release-publish\|release-sign\|release-assets\|release-postverify\)'              ')'                                                      'the helper'        "AC11 PR 3's steps missing from the closed list"
hm h_open    '\*\) echo "witnessed: unknown step \$step" >&2; exit 2 ;;' '*) ;;'                                    'the helper'        "AC11 an unknown step accepted"
hm h_extra   '\|release-postverify\)'                          '|release-postverify|extra)'                                       'the helper'        "AC11 a fourth Check step in the closed list"
# ---- AC14: the kind install and the cluster ------------------------------------------------------------------------------
km() { if mutate "$work/install-kind.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" kind "$work/$1.sh"; fi; }
km k_ver     'v0.33.0/kind-linux-amd64'                         'v0.32.0/kind-linux-amd64'                                'the kind installer' "AC14 another kind version"
km k_kver    'v1.37.0/bin/linux/amd64'                          'v1.36.0/bin/linux/amd64'                                'the kind installer' "AC14 another kubectl version"
km k_sha     'aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d' 'aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0e' 'the kind installer' "AC14 a changed kind sha256"
km k_ksha    '6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f' '922df28df248cc00a9e025f947704f1d1482de64ece54cfe57e61f19eaf1eef3' 'the kind installer' "AC14 the arm64 kubectl sha256 (the runner is amd64)"
km k_nocheck ' \| sha256sum -c -'                              ''                                                       'the kind installer' "AC14 the downloads are not checked"
km k_arm     'kind-linux-amd64'                                 'kind-linux-arm64'                                       'the kind installer' "AC14 another architecture"
km k_after   'install -m 0755[^\n]*\n'                          ''                                                       'the kind installer' "AC14 nothing installed (or installed elsewhere)"
cm() { if mutate "$work/k8s.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" cluster "$work/$1.sh"; fi; }
cm c8_tag    '@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5' ''                             'by digest'          "AC14 the node image by tag only"
cm c8_noimg  ' --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5' '' 'by digest'      "AC14 kind's default node image"
cm c8_two    'create_cluster\n$'                               'create_cluster\nkind create cluster --name second\n'    'exactly once'       "AC14 a second cluster"
cm c8_act    'set -eo pipefail\n'                              'set -eo pipefail\n# uses: helm/kind-action\n'            'kind action'        "AC14 a kind action named in the suite"
um() { if mutate "$work/acceptance.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" suites "$work/$1.yml"; fi; }
um u_inline  '      - run: bash bin/acceptance-gradle.sh\n'   '      - run: ./gradlew build\n'                          'acceptance-gradle'  "AC5 the gradle suite inline instead of the shared script"
um u_res     '      - id: results\n        run: bash bin/acceptance-maven-capped.sh' '      - run: bash bin/acceptance-maven-capped.sh\n      - id: results\n        run: echo results' 'results step' "AC5 the maven results step is not the suite"
# ---- AC3: the order of bin/check-stage.sh --------------------------------------------------------------------------------
sm() { if mutate "$work/script.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" script "$work/$1.sh"; fi; }
sm c_nofirst 'python3 -I -B bin/chain-verify.py stage-start[^\n]*\n'   ''                                                 'not the pinned form' "AC3 the verify step dropped"
sm c_nopol   'python3 -I -B bin/chain-verify.py policy make[^\n]*\n'   ''                                                 'not the pinned form' "AC3 the policy is not made per tag (Q5)"
sm c_poltag  '--tag "\$GITHUB_REF_NAME"'                       '--tag v0.3.0'                                           'not the pinned form' "AC3 the policy made for a fixed tag instead of the run's tag (Q5)"
sm c_noiso   'python3 -I -B bin/chain-verify.py stage-start'  'python3 bin/chain-verify.py stage-start'                'not the pinned form' "AC3 the verifier not isolated (PR 1: python3 -I -B)"
sm c_nok8s   'bash bin/check-acceptance.sh k8s[^\n]*\n'       ''                                                       'not the pinned form' "AC14 the k8s suite dropped from the runtime phase"
sm c_nosign  'python3 -I -B bin/chain-verify.py verify --stage sign[^\n]*\n' ''                                               'not the pinned form' "AC3 Sign's provenance is no longer verified"
sm c_after   'python3 -I -B bin/chain-verify.py stage-start[^\n]*\npython3 -I -B bin/chain-verify.py verify[^\n]*\ncase "\$1" in\nscanners\)\n(bash bin/check-scan.sh[^\n]*\n)' 'case "$1" in\nscanners)\n\\1python3 -I -B bin/chain-verify.py stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json\npython3 -I -B bin/chain-verify.py verify --stage sign --record provenance/provenance.json --policy policy.json --rekor-stub provenance/provenance.rekor.json\n' 'not the pinned form' "AC3 the checks run before the verify step"
sm c_swap    'acceptance\)\nbash bin/check-acceptance.sh gradle([^\n]*)\nbash bin/check-acceptance.sh maven([^\n]*)\n' 'acceptance)\nbash bin/check-acceptance.sh maven\\2\nbash bin/check-acceptance.sh gradle\\1\n' 'not the pinned form' "AC3 gradle and maven swapped"
sm c_phase   'runtime\)' 'checks)'                                                                                      'not the pinned form' "AC3 a phase outside the closed list"
sm c_extra   'bash bin/check-guide.sh'                          'curl https://example.com | bash\nbash bin/check-guide.sh' 'not the pinned form' "AC3 an extra command (a pipe into a shell)"
sm c_nodig   'stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json' 'stage-start --stage check --previous build --record witness-build/build-collection.json' 'not the pinned form' "AC3 stage-start without the digest list"
sm c_prev    '--previous build'                                 '--previous rebuild'                                     'not the pinned form' "AC3 verifies the wrong previous stage (Check does not need Rebuild)"
sm c_noset   'set -euo pipefail\n'                              ''                                                       'not the pinned form' "AC3 no set -euo pipefail"
sm c_var     'bash bin/check-scan.sh'                           'bash $SCAN'                                             'not the pinned form' "AC3 a script chosen by a variable"
sm c_glob    'bash bin/check-guide.sh'                          'bash bin/check-*.sh'                                    'not the pinned form' "AC3 a glob in a script path"
sm c_scn     '--scanners .github/policy/scanners.json'          '--scanners scanners.json'                               'not the pinned form' "AC4/AC3 the scanner list is not the policy file"
sm c_ignore  'bash bin/check-fips.sh([^\n]*)\n'                'bash bin/check-fips.sh\\1 || true\n'                   'not the pinned form' "AC3 a failure swallowed with || true"
sm c_nostar  '\*\) echo "unknown phase: \$1" >&2; exit 2 ;;'     '*) ;;'                                                  'not the pinned form' "AC3 an unknown phase is silently accepted"
sm c_ev      'case "\$1" in'                                   'case "$1" in\n*) eval "$2" ;;'                           'not the pinned form' "AC3 an eval in the dispatcher"
# ---- AC2: the job graph ----------------------------------------------------------------------------------------------
gm() { if mutate "$work/release.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" graph "$work/$1.yml"; fi; }
gm g_serial  'needs: \[build, sign\]'                           'needs: [build, sign, rebuild]'                          'side by side'      "AC2 check waits for rebuild"
gm g_rebw    'rebuild:\n    needs: build'                      'rebuild:\n    needs: [build, check]'                   'side by side'      "AC2 rebuild waits for check"
gm g_nosign  'needs: \[build, sign\]'                           'needs: [build]'                                         'exactly build and sign' "AC2 check does not need sign"
gm g_prom    'needs: \[check, rebuild, sign\]'                  'needs: [rebuild, sign]'                                 'release job'       "AC2 the release job does not need check"
gm g_relbld  'needs: \[check, rebuild, sign\]'                  'needs: [build, check, rebuild, sign]'                   'exactly'           "AC2 the release job also lists build (redundant: check needs build; PR 2 pins exactly check, rebuild, sign)"
gm g_promo   '  release:\n'                                    '  promotion:\n'                                       'no job release'    "AC2 the last stage's job named promotion (the ratified name is release, Q9)"
gm g_uses    'stage-verify.yml'                                 'ci.yml'                                                 'stage-verify.yml'  "AC2 check calls another workflow"
# ---- AC8: plain scripts and the list ---------------------------------------------------------------------------------
pm() { mkdir -p "$work/$1"; cp "$work"/plain/*.sh "$work/$1/"; python3 - "$work/$1/$2" "$3" <<'PY'
import sys
open(sys.argv[1], "a").write(sys.argv[2] + "\n")
PY
  expect caught "$5" "$4" plain "$work/$1"/check-*.sh; }
pm p_cosign  check-scan.sh      'cosign verify "$IMG"'                'cosign'            "AC8 a signing tool in a check script"
pm p_wit     check-stage.sh     'witness verify -p policy.json'       'witness'           "AC8 witness in a check script"
pm p_login   check-fips.sh      'docker login ghcr.io -u u'           'docker login'      "AC8 a registry login"
pm p_secret  check-guide.sh     'echo "$SECRET_KEY"'                  'secret'            "AC8 a secret"
pm p_token   check-acceptance.sh 'curl -H "Authorization: $GITHUB_TOKEN" x' 'GITHUB_TOKEN' "AC8 the job token"
pm p_idtok   check-scan.sh      'echo "$ACTIONS_ID_TOKEN_REQUEST_URL"' 'ACTIONS_ID_TOKEN'  "AC8 the identity token request"
pm p_snyk    check-scan.sh      'snyk test --severity-threshold=low'  'snyk'               "AC8 Snyk (rescan only, needs a token)"
pm p_attest  check-guide.sh     'gh attestation download x'           'attest'            "AC8 attestation tooling other than verify (Q10)"
pm p_sign    check-guide.sh     'cosign sign "$IMG"'                  'cosign'            "AC8 cosign sign in the guide check (Q10: verify only)"
pm p_attc    check-guide.sh     'cosign attest --predicate p "$IMG"'  'cosign'            "AC8 cosign attest in the guide check (Q10: verify only)"
pm p_upl     check-guide.sh     'cosign upload blob x'                'cosign'            "AC8 cosign upload in the guide check (Q10: verify only)"
pm p_vfx     check-guide.sh     'cosign verify-foo x'                 'cosign'            "AC8 a cosign subcommand that only starts like verify (Q10)"
pm p_vscan   check-scan.sh      'cosign verify "$IMG"'                'cosign'            "AC8 cosign verify in a check script other than the guide check (Q10)"
pv() { mkdir -p "$work/$1"; cp "$work"/plain/*.sh "$work/$1/"; printf '%s\n' "$2" >> "$work/$1/check-guide.sh"; expect ok "$3" "" plain "$work/$1"/check-*.sh; }
pv p_okv     'case "$1 $2" in "cosign verify"|"cosign verify-attestation"|"cosign verify-blob"|"cosign verify-blob-attestation") ;; esac' "AC8 the guide check may name the cosign verify commands (Q10)"
pv p_okg     'gh attestation verify "oci://$REF" --owner o' "AC8 the guide check may name gh attestation verify (Q10)"
pm p_com     check-fips.sh      '# cosign sign is not used here'      'cosign'            "AC8 a signer named in a comment (over-reports by design)"
mkdir -p "$work/l" && python3 - "$work/l" <<'PY'
import hashlib, json, os, sys
w = sys.argv[1]
os.makedirs(w + "/bin", exist_ok=True)
rows = []
for n in ("check-stage", "check-phase-scanners", "check-phase-acceptance", "check-phase-runtime", "check-phase-arm64", "check-scan", "check-fips", "check-artifacts", "check-acceptance", "check-guide", "acceptance-gradle", "acceptance-gradle-capped",
          "acceptance-maven", "acceptance-maven-capped", "acceptance-egress", "acceptance-k8s", "acceptance-serve", "install-kind"):
    p = f"bin/{n}.sh"; open(f"{w}/{p}", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n")
    rows.append({"path": p, "sha256": hashlib.sha256(open(f"{w}/{p}", "rb").read()).hexdigest(), "tools": [], "signs": False, "runs": [], "reason": "fixture"})
os.makedirs(w + "/.github/policy", exist_ok=True)
json.dump({"env_names": [], "scripts": rows}, open(w + "/.github/policy/chain-scripts.json", "w"))
PY
expect ok "fixture: all eighteen Check scripts listed with their sha256 and signs: false" "" listed "$work/l/.github/policy/chain-scripts.json" "$work/l"
cp -r "$work/l" "$work/l2"; python3 - "$work/l2" <<'PY'
import json, sys
p = sys.argv[1] + "/.github/policy/chain-scripts.json"; d = json.load(open(p)); d["scripts"] = d["scripts"][1:]; json.dump(d, open(p, "w"))
PY
expect caught "AC8 a check script not listed" "not listed" listed "$work/l2/.github/policy/chain-scripts.json" "$work/l2"
cp -r "$work/l" "$work/l3"; echo "echo changed" >> "$work/l3/bin/check-fips.sh"
expect caught "AC8 a script changed after it was listed (sha256)" "sha256" listed "$work/l3/.github/policy/chain-scripts.json" "$work/l3"
cp -r "$work/l" "$work/l4"; python3 - "$work/l4" <<'PY'
import json, sys
p = sys.argv[1] + "/.github/policy/chain-scripts.json"; d = json.load(open(p)); d["scripts"][2]["signs"] = "other"; json.dump(d, open(p, "w"))
PY
expect caught "AC8 a check script listed as a signer" "signs: false" listed "$work/l4/.github/policy/chain-scripts.json" "$work/l4"
# ---- AC13 (rule 66): the table of records ------------------------------------------------------------------------------
rm_() { python3 - "$work/records.json" "$work/$1.json" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); eval(sys.argv[3], {"d": d}); json.dump(d, open(sys.argv[2], "w"))
PY
  expect caught "$4" "$3" records "$work/$1.json"; }
rm_ r_old   'd["records"].append({"type": "https://fosterstack.com/attestations/acceptance/v1", "claim": "x", "consumer": "release"})' 'acceptance' "AC13 the old custom acceptance record is still in the table"
rm_ r_nocon 'd["records"][0].__setitem__("consumer", "nobody")' 'no row' "AC13 the Witness collection row has no real consumer"
rm_ r_noclm 'd["records"][0].__setitem__("claim", "what was built")' 'no row' "AC13 the Witness collection row does not name Check"
# ---- AC7 (rule 79 amended, owner Oct 10): listed guide commands are covered by Release's post-publish verification ------------------
# The cannot-run list is the single exact-text list Release reads: valid JSON, rows exactly {command, reason}, no duplicate, each
# command a command of the guide, each one of the verify forms. A valid list satisfies AC7 (the commands run after publishing).
mkdir -p "$work/gl1/docs" "$work/gl2/docs" "$work/gl3/docs" "$work/gl4/docs" "$work/gl5/docs" "$work/gl6/docs" "$work/gl7/docs" "$work/gl8/docs"
for d in gl1 gl2 gl3 gl4 gl5 gl6 gl8; do printf '# guide\n\n```sh\ncosign verify <IMAGE_REF>\n```\n' > "$work/$d/docs/verify-release.md"; done
printf '# guide\n\n```sh\ngh release view v1\n```\n' > "$work/gl7/docs/verify-release.md"
R='"reason": "needs the image in a registry; run right after publishing"'
printf '[{"command": "cosign verify <IMAGE_REF>", %s}]\n' "$R" > "$work/gl1/docs/verify-release.cannot-run.json"
printf '[]\n' > "$work/gl2/docs/verify-release.cannot-run.json"
printf '[{"command": "cosign verify <IMAGE_REF>", %s}, {"command": "cosign verify <IMAGE_REF>", %s}]\n' "$R" "$R" > "$work/gl4/docs/verify-release.cannot-run.json"
printf '[{"command": "cosign verify <IMAGE_REF>", "reason": " "}]\n' > "$work/gl5/docs/verify-release.cannot-run.json"
printf '[{"command": "cosign verify <OTHER_REF>", %s}]\n' "$R" > "$work/gl6/docs/verify-release.cannot-run.json"
printf '[{"command": "gh release view v1", %s}]\n' "$R" > "$work/gl7/docs/verify-release.cannot-run.json"
printf '[{"command": \n' > "$work/gl8/docs/verify-release.cannot-run.json"
expect ok "AC7 a listed registry command is covered by the post-publish step: a valid cannot-run list satisfies rule 79 (no longer a failure)" "" guidelist "$work/gl1/docs/verify-release.md"
expect ok "fixture: a guide whose cannot-run list is empty satisfies the list check" "" guidelist "$work/gl2/docs/verify-release.md"
expect ok "fixture: a guide with no cannot-run list satisfies the list check" "" guidelist "$work/gl3/docs/verify-release.md"
expect caught "AC7 a missing guide is not a pass" "does not exist" guidelist "$work/gl3/docs/nothing.md"
expect caught "AC7 a command listed twice in the cannot-run list is refused" "twice" guidelist "$work/gl4/docs/verify-release.md"
expect caught "AC7 a cannot-run entry with no reason is refused" "reason" guidelist "$work/gl5/docs/verify-release.md"
expect caught "AC7 a cannot-run entry that is not a command of the guide is refused (stale list)" "not in the guide" guidelist "$work/gl6/docs/verify-release.md"
expect caught "AC7 a cannot-run entry that is not a verify form is refused (Release would refuse it)" "not a verify form" guidelist "$work/gl7/docs/verify-release.md"
expect caught "AC7 an unparsable cannot-run list is refused with a named failure" "not JSON" guidelist "$work/gl8/docs/verify-release.md"
# ---- AC10: the old acceptance stages --------------------------------------------------------------------------------
mkdir -p "$work/r/.github/workflows"; cp "$work/release.yml" "$work/r/.github/workflows/release.yml"
expect ok "fixture: none of the old acceptance stages and no call to them" "" removed "$work/r"
cp -r "$work/r" "$work/r2"; : > "$work/r2/.github/workflows/stage-authorize.yml"
expect caught "AC10 stage-authorize.yml still exists" "stage-authorize.yml" removed "$work/r2"
cp -r "$work/r" "$work/r3"; printf '  accept:\n    uses: ./.github/workflows/stage-acceptance-egress.yml\n' >> "$work/r3/.github/workflows/release.yml"
expect caught "AC10 release.yml still calls an old acceptance stage" "stage-acceptance-egress.yml" removed "$work/r3"
cp -r "$work/r" "$work/r4"; printf '  acc:\n    uses: ./.github/workflows/acceptance.yml\n' >> "$work/r4/.github/workflows/release.yml"
expect caught "AC10 release.yml still calls acceptance.yml" "acceptance.yml" removed "$work/r4"
cp -r "$work/r" "$work/r5"; mkdir -p "$work/r5/bin"; : > "$work/r5/bin/authorize-acceptance-check.py"
expect caught "AC10 the custom authorization verifier still exists (rule 65)" "authorize-acceptance-check.py" removed "$work/r5"
cp -r "$work/r" "$work/r6"; mkdir -p "$work/r6/.github/workflows"; printf 'jobs:\n  t:\n    steps:\n      - run: bash bin/authorize-acceptance-check-test.sh\n' > "$work/r6/.github/workflows/ci.yml"
expect caught "AC10 ci.yml still runs the custom authorization verifier's test (rule 65)" "ci.yml" removed "$work/r6"
# ---- the real repository (RED until PR 3 is implemented) ---------------------------------------------------------------
expect ok "the real stage-verify.yml is the Check stage" "" stage "$root/.github/workflows/stage-verify.yml"
expect ok "the real bin/check-stage.sh verifies, then dispatches scanners / acceptance / runtime" "" script "$root/bin/check-stage.sh"
for s in scanners acceptance runtime arm64; do expect ok "the real bin/check-phase-$s.sh is the one line of its phase (AC1, AC3)" "" phase "$root/bin/check-phase-$s.sh" "$s"; done
expect ok "the real bin/witnessed.sh is the one helper with the Witness flags and the 9-minute cap (rule 68)" "" helper "$root/bin/witnessed.sh"
expect ok "the real chain-records.json has Check's Witness collection and no old acceptance record (rule 66)" "" records "$root/.github/policy/chain-records.json"
expect ok "the real release.yml runs check beside rebuild, check needs build and sign, and the release job needs exactly check, rebuild and sign" "" graph "$root/.github/workflows/release.yml"
expect ok "the real check scripts are plain (check-stage.sh is judged by script alone, Q3)" "" plain "$root"/bin/check-scan.sh "$root"/bin/check-fips.sh "$root"/bin/check-artifacts.sh "$root"/bin/check-acceptance.sh "$root"/bin/check-guide.sh
expect ok "the real check scripts are listed in chain-scripts.json with their sha256" "" listed "$root/.github/policy/chain-scripts.json" "$root"
expect ok "the old acceptance stages are gone from the real repository and release.yml" "" removed "$root"
expect ok "the real bin/install-kind.sh installs kind v0.33.0 and kubectl v1.37.0 against their committed sha256 (AC14)" "" kind "$root/bin/install-kind.sh"
expect ok "the real k8s suite creates its cluster with the node image by digest (AC14)" "" cluster "$root/bin/acceptance-k8s.sh"
expect ok "the real acceptance.yml runs the shared gradle and maven suite scripts (AC5)" "" suites "$root/.github/workflows/acceptance.yml"
expect ok "rule 79 on the real guide: it exists and its cannot-run list is a valid exact-text list (AC7; RED until cache-3f's guide exists)" "" guidelist "$root/docs/verify-release.md"
EXPECT=191
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
