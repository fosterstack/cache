#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC1, REQ-CHAIN-004-AC2, REQ-CHAIN-004-AC3, REQ-CHAIN-004-AC6, REQ-CHAIN-004-AC8, REQ-CHAIN-004-AC9,
#         REQ-CHAIN-004-AC10 (the flags; PR 1's verify cases cover the identity), REQ-CHAIN-004-AC11, REQ-CHAIN-005-AC5, REQ-CHAIN-005-AC6
# RED until PR 2 is implemented (stage-build.yml rewritten, bin/build-stage.sh, bin/chain-verify.py record-env): tests first, step 4.
#
# Build, static half and the stage script's behaviour (v0.3.0 rules 24, 38a, 38b, 39, 50, 51, 62, 63, 68, 70; advisor read-back 0338).
# Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml), jq, git. No network, no secrets, no keys.
# Every judge lives in bin/chain-test-shape.py (shared with bin/chain-rebuild-test.sh) and is FIRST proven on a known-good fixture and
# on mutated copies (a judge that cannot fail proves nothing), then applied to the real repository, which must pass.
#
# THE CACHE INTERFACE THIS ASSUMES (cache-3f's note ops/handoffs/outbox/2026-10-09-cache-pipeline-interface.md; [F n] = fixed by an
# assertion of bin/melange-apko-test.sh in cache's branch, [P] = PROPOSED/UNVERIFIED and may change). cache-3f's UPDATE (Oct 9) now FIXES the
# exit codes by cache tests: 0, 2 (a named refusal before any tool), 4 (a network attempt inside the sealed call: the sealed tool
# exits non-zero, its stderr matches ENETUNREACH|network is unreachable|dial tcp|no such host AND `sudo unshare -n python3 bin/net-probe.py`
# exits 101), any other failure non-zero and not 4; and the image digest is the OCI INDEX digest (OUT/<variant>.digest, .tar,
# .manifests; bin/oci-digest.py). Still [P]: the layout of the apkindex/inputs-manifest/binary items, the SBOM directory, sudo's PATH.
#   ./bin/build-apk.sh --print-source-date-epoch --source-dir DIR       [F L740-741] prints the commit time, digits only
#   ./bin/build-apk.sh --variant standard|fips --arch x86_64|aarch64 --version X.Y.Z --source-dir DIR --repo DIR --keyring FILE
#                      --go-archive DIR --melange-lock FILE --out DIR   [F L665-666]; SOURCE_DATE_EPOCH digits required [F L674-675]
#   ./bin/assemble-image.sh --variant production|fips --version X.Y.Z --archive DIR --melange-repo DIR --keyring-dir DIR --out DIR [F L867]
#   the SCRIPTS run `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` and `sudo ... unshare -n melange|apko ...`
#   themselves [F r38a L696-698, r38b L875-877]; the STAGE does not wrap them and does not run the sysctl. Refusals exit 2 before any tool
#   [F L613]; build-apk.sh refuses APK_RELEASE_SIGNING_KEY, GOPROXY other than off, HTTPS_PROXY and --signing-key [F L676-679] so the
#   stage sets none of them. Outputs: OUT/<arch>/fscache-0.3.0-r0.apk + APKINDEX.tar.gz, OUT/fscache-modules.spdx.json,
#   OUT/inputs-manifest.json [F L722-731]; OUT/V.full.lock.json, OUT/V.digest ("sha256:<64hex>\n") [F L890-895]. NOT fixed by cache's
#   tests, so PROPOSED here: the apkindex/inputs-manifest/binary item layouts, the SBOM directory, whether sudo's PATH finds melange/apko.
#   bin/build-version-check.py --binary PATH --tag vX.Y.Z --sha SHA is this lane's (REQ-CHAIN-004-AC7, bin/chain-build-admit-test.sh).
#
# THE STAGE SCRIPT bin/build-stage.sh build|rebuild (this lane): commands in the order bin/chain-test-shape.py `script` pins.
#   Behaviour is tested here with FAKE cache scripts in a throw-away tree: the fakes log their argv and the SOURCE_DATE_EPOCH they saw,
#   and write plausible outputs under whatever --out they are given; the script's own paths for OUT are its choice. Build writes
#   digests.json (the image and apk digests, names [a-z0-9-]+, values sha256:<64 hex>: PR 1 owns that schema, REQ-CHAIN-001-AC2) and
#   items.json (every comparable item, bin/chain-test-shape.py `items`), both as products of the Witness step.
# A STATED GAP: the real melange/apko, the real sudo/unshare and the real Witness signing are proven only by the GitHub dry run; the
# two native-runner architectures meeting in one apko run (rule 33) is an open question for the advisor (see the REQ-CHAIN-004 notes).
# INTEGRATION BRANCH (advisor 0341): PR 2 targets chain-v030, not main. The old chain stays live on main until the cutover PR (chain-v030 -> main, after a
# green dry run, with its own final review round); the real-tree cases below (the 'real' behaviour cases, the stage files, release.yml, the removed
# stage-image.yml / stage-admission.yml, install-scanner.sh) are RED here and become green only on chain-v030 after PR 1 and PR 2 are merged there.
# TWO-ARCHITECTURE SHAPE (advisor interim reading, Oct 9, put to the owner): one stage = one workflow file = one identity; stage-build.yml has an
# `apk` matrix job (native ubuntu-24.04 and ubuntu-24.04-arm: bin/build-stage.sh apk) and one `assemble` job on the VM (bin/build-stage.sh assemble);
# stage-reproducibility.yml has the same two jobs (kinds rebuild-apk and rebuild-assemble). The Witness `github` attestor is not allowed (it embeds
# the raw OIDC token); run/job identity comes from the Fulcio certificate extensions pinned by PR 1's policy.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shape="$root/bin/chain-test-shape.py"
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
# ---- known-good fixtures: ONE file per stage, TWO jobs (apk matrix + assemble on the VM), advisor reading 0341 ------------
python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
CHK = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
UPL = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
DWN = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65 # v5.0.0"
def witness(step, out, kind):
    return f"""      - name: {step} under Witness
        run: |
          set -euo pipefail
          curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${{ACTIONS_ID_TOKEN_REQUEST_URL}}&audience=sigstore" -o "$RUNNER_TEMP/tok.json"
          jq -r .value "$RUNNER_TEMP/tok.json" > "$RUNNER_TEMP/tok"
          echo "::add-mask::$(cat "$RUNNER_TEMP/tok")"
          witness run --step {step} \\
            --signer-fulcio-url https://fulcio.sigstore.dev \\
            --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \\
            --signer-fulcio-oidc-client-id sigstore \\
            --signer-fulcio-token-path "$RUNNER_TEMP/tok" \\
            -t https://timestamp.sigstore.dev/api/v1/timestamp \\
            -a environment,git,material,product \\
            --env-filter-sensitive-vars \\
            --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN \\
            -d out -o {out} \\
            -- ./bin/build-stage.sh {kind}
"""
def up(name, path): return f"      - uses: {UPL}\n        with:\n          name: {name}\n          path: {path}\n"
def dn(name, path): return f"      - uses: {DWN}\n        with:\n          name: {name}\n          path: {path}\n"
HEAD = "name: 'Stage: %s'\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n"
PERM = "    permissions:\n      contents: read\n      id-token: write\n"
BASE = f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n      - name: install Witness (pinned by checksum)\n        run: ./bin/install-scanner.sh witness\n"
MATRIX = "    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n"
R = ("ubuntu-24.04", "ubuntu-24.04-arm")
def stage(fam):
    if fam == "build":
        apk = (HEAD % "build") + "  apk:\n    runs-on: ${{ matrix.runner }}\n" + MATRIX + PERM + "    steps:\n" + BASE + witness("apk", "witness-apk/apk-collection.json", "apk") \
              + up("apk-${{ matrix.runner }}", "out") + up("witness-apk-${{ matrix.runner }}", "witness-apk")
        asm = "  assemble:\n    needs: apk\n    runs-on: ubuntu-24.04\n" + PERM + "    steps:\n" + BASE \
              + "".join(dn("apk-" + r, "apk-" + r) + dn("witness-apk-" + r, "witness-apk-" + r) for r in R) \
              + witness("build", "witness-build/build-collection.json", "assemble") + up("witness-build", "witness-build") + up("digests", "witness-build/digests.json")
    else:
        apk = (HEAD % "reproducibility") + "  apk:\n    runs-on: ${{ matrix.runner }}\n" + MATRIX + PERM + "    steps:\n" + BASE + dn("witness-build", "witness-build") \
              + witness("rebuild-apk", "witness-rapk/rapk-collection.json", "rebuild-apk") + up("rapk-${{ matrix.runner }}", "out") + up("witness-rapk-${{ matrix.runner }}", "witness-rapk")
        asm = "  assemble:\n    needs: apk\n    runs-on: ubuntu-24.04\n" + PERM + "    steps:\n" + BASE + dn("witness-build", "witness-build") \
              + "".join(dn("rapk-" + r, "rapk-" + r) + dn("witness-rapk-" + r, "witness-rapk-" + r) for r in R) \
              + witness("rebuild", "witness-rebuild/rebuild-collection.json", "rebuild-assemble") + up("witness-rebuild", "witness-rebuild")
    return apk + asm
open(w + "/build.yml", "w").write(stage("build"))
open(w + "/rebuild.yml", "w").write(stage("rebuild"))
SDE = 'export SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"\n'
POL = 'python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json\n'
APKS = "./bin/build-apk.sh --variant standard --arch \"$(uname -m)\" --version \"${GITHUB_REF_NAME#v}\" --source-dir . --out out\n./bin/build-apk.sh --variant fips --arch \"$(uname -m)\" --version \"${GITHUB_REF_NAME#v}\" --source-dir . --out out\n"
IMGS = "./bin/assemble-image.sh --variant production --version \"${GITHUB_REF_NAME#v}\" --out out\n./bin/assemble-image.sh --variant fips --version \"${GITHUB_REF_NAME#v}\" --out out\n"
def vrf(stage_, pfx): return "".join(f"python3 bin/chain-verify.py verify --stage {stage_} --record witness-{pfx}-{r}/{pfx}-collection.json --policy policy.json\n" for r in R)
START = "python3 bin/chain-verify.py stage-start --stage rebuild --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json\n"
H = "#!/usr/bin/env bash\nset -euo pipefail\n"
scripts = {
 "build-stage-apk.sh": H + "python3 bin/build-admit.py run\n" + SDE + APKS + 'python3 bin/build-version-check.py --binary out/fscache --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA"\n',
 "build-stage-assemble.sh": H + POL + vrf("build", "apk") + SDE + IMGS
     + "jq -n --arg p \"$(cat out/production.digest)\" --arg f \"$(cat out/fips.digest)\" '{\"image-production\":$p,\"image-fips\":$f}' > witness-build/digests.json\n"
     + "jq -n --arg p \"$(cat out/production.digest)\" --arg f \"$(cat out/fips.digest)\" '{\"image-production\":$p,\"image-fips\":$f}' > witness-build/items.json\n",
 "build-stage-rebuild-apk.sh": H + POL + START + SDE + APKS,
 "build-stage-rebuild-assemble.sh": H + POL + vrf("rebuild", "rapk") + START + SDE + IMGS
     + "jq -n --arg p \"$(cat out/production.digest)\" --arg f \"$(cat out/fips.digest)\" '{\"image-production\":$p,\"image-fips\":$f}' > items.json\n"
     + "python3 bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json --expected witness-build/items.json --actual items.json --out verdict.json\n",
}
for k, v in scripts.items(): open(w + "/" + k, "w").write(v)
PY
cat > "$work/release.yml" <<'EOF'
name: Release
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
    needs: build
    uses: ./.github/workflows/stage-verify.yml
  release:
    needs: [rebuild, check, sign]
    uses: ./.github/workflows/stage-promote.yml
EOF
# the old single-script names, used by the behaviour harness below
cp "$work/build-stage-apk.sh" "$work/build-stage.sh"
# ---- the stage-file judge (REQ-CHAIN-004-AC1, AC2; REQ-CHAIN-005-AC1, AC4) -----------------------------------------------
expect ok     "AC1/AC2 fixture: the known-good Build stage file (apk matrix + assemble) passes" "" stage "$work/build.yml" build
expect ok     "005-AC1 fixture: the known-good Rebuild stage file passes" "" stage "$work/rebuild.yml" rebuild
m() { mutate "$work/build.yml" "$work/$1.yml" "$2" "$3"; }
m s_cont  'runs-on: ubuntu-24.04\n    permissions' 'runs-on: ubuntu-24.04\n    container: debian:12\n    permissions'  && expect caught "AC1 a container on the assemble job (rule 62)" container stage "$work/s_cont.yml" build
m s_self  'ubuntu-24.04-arm\]' 'self-hosted]'                                         && expect caught "AC1 a self-hosted runner in the matrix" matrix stage "$work/s_self.yml" build
m s_third 'ubuntu-24.04-arm\]' 'ubuntu-24.04-arm, ubuntu-22.04]'                       && expect caught "AC1 a third runner in the matrix" matrix stage "$work/s_third.yml" build
m s_one   'runner: \[ubuntu-24.04, ubuntu-24.04-arm\]' 'runner: [ubuntu-24.04]'         && expect caught "AC1 only one native runner (both architectures are required)" matrix stage "$work/s_one.yml" build
m s_asmr  'assemble:\n    needs: apk\n    runs-on: ubuntu-24.04' 'assemble:\n    needs: apk\n    runs-on: ubuntu-24.04-arm' && expect caught "AC1 the assemble job on the arm runner" "assemble job must run directly on" stage "$work/s_asmr.yml" build
m s_need  'needs: apk' 'needs: []'                                                      && expect caught "AC1 the assemble job does not need the apk jobs" "must need exactly apk" stage "$work/s_need.yml" build
m s_env   'permissions:\n      contents: read\n      id-token' 'env:\n      A: b\n    permissions:\n      contents: read\n      id-token' && expect caught "AC1 job-level env" env stage "$work/s_env.yml" build
m s_pkg   'id-token: write' 'id-token: write\n      packages: write'                     && expect caught "AC1 packages: write" permissions stage "$work/s_pkg.yml" build
m s_noid  '      id-token: write\n' ''                                                  && expect caught "AC1 no id-token (Witness cannot sign keyless)" permissions stage "$work/s_noid.yml" build
m s_sec   'name: apk under Witness' 'name: apk under Witness\n        env:\n          K: ${{ secrets.KEY }}' && expect caught "AC1 a secret in the Witness step" secrets stage "$work/s_sec.yml" build
m s_push  'workflow_call:' 'push:\n  workflow_call:'                                  && expect caught "AC1 an extra trigger" workflow_call stage "$work/s_push.yml" build
m s_job3  '  assemble:' '  third:\n    runs-on: ubuntu-24.04\n    steps: []\n  assemble:' && expect caught "AC1 a third job (one stage = one file = two jobs)" "exactly two jobs" stage "$work/s_job3.yml" build
m s_top   'permissions:\n  contents: read\njobs' 'permissions:\n  contents: read\nenv:\n  X: y\njobs' && expect caught "AC1 a top-level env" top-level stage "$work/s_top.yml" build
m s_unp   'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v7' && expect caught "AC2 checkout not pinned by digest" checkout stage "$work/s_unp.yml" build
m s_cred  'persist-credentials: false' 'persist-credentials: true'                    && expect caught "AC2 persisted credentials" persist stage "$work/s_cred.yml" build
m s_inst  'run: ./bin/install-scanner.sh witness' 'run: curl -sSL https://example.com/witness | tar xz -C /usr/local/bin' && expect caught "AC2 Witness installed by an unpinned download" install stage "$work/s_inst.yml" build
m s_mid   '      - name: apk under Witness' '      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n      - name: apk under Witness' && expect caught "AC2 a third-party action between the install and Witness in the apk job (rule 68)" "Witness step" stage "$work/s_mid.yml" build
m s_env2  'name: apk under Witness' 'name: apk under Witness\n        env:\n          A: b'    && expect caught "AC2 env on the Witness step" "Witness step" stage "$work/s_env2.yml" build
m s_two   '            -- ./bin/build-stage.sh apk' '            -- ./bin/build-stage.sh apk\n          witness run --step build -- true' && expect caught "AC2 two witness runs" "exactly one" stage "$work/s_two.yml" build
m s_pip   'set -euo pipefail\n' 'set -euo pipefail\n          pip install requests\n'      && expect caught "AC2 a command outside the token fetch and witness run" "outside" stage "$work/s_pip.yml" build
m s_url   'https://fulcio.sigstore.dev' 'http://fulcio.evil.example'                    && expect caught "AC2 another Fulcio address" fulcio stage "$work/s_url.yml" build
m s_tsa   'https://timestamp.sigstore.dev/api/v1/timestamp' 'https://tsa.example/ts'    && expect caught "AC2 another timestamp authority" "-t" stage "$work/s_tsa.yml" build
m s_flt   '            --env-filter-sensitive-vars \\\n' ''                              && expect caught "AC8 no environment filter flag (tokens would be recorded, even if obfuscated)" "env-filter" stage "$work/s_flt.yml" build
m s_key   " --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST\*'" ''                   && expect caught "AC8 no token-variable key pattern" "sensitive-key" stage "$work/s_key.yml" build
m s_slsa  'environment,git,material,product' 'environment,git,material,slsa'            && expect caught "AC2 the slsa attestor (provenance is Sign's alone)" slsa stage "$work/s_slsa.yml" build
m s_gh    'environment,git,material,product' 'environment,git,github,material,product'  && expect caught "AC8 the github attestor (it embeds the raw OIDC token; advisor 0341)" github stage "$work/s_gh.yml" build
m s_gh2   'environment,git,material,product' 'github'                                    && expect caught "AC8 the github attestor alone" github stage "$work/s_gh2.yml" build
m s_cmd   '-- ./bin/build-stage.sh apk' '-- sh -c "make all"'                           && expect caught "AC2 the command under Witness is not the committed script" build-stage stage "$work/s_cmd.yml" build
m s_kind  '-- ./bin/build-stage.sh apk' '-- ./bin/build-stage.sh assemble'               && expect caught "AC2 the apk job running the assemble script" build-stage stage "$work/s_kind.yml" build
m s_out   'witness-apk/apk-collection.json \\' 'out/x.json \\'                          && expect caught "AC2 Witness's record written elsewhere" "-o must" stage "$work/s_out.yml" build
m s_up    'name: digests' 'name: registry-creds'                                         && expect caught "AC2 an upload outside the allowed artifact names" "not an allowed artifact" stage "$work/s_up.yml" build
m s_dlx   'name: apk-ubuntu-24.04\n' 'name: dist\n'                                         && expect caught "AC2 a download outside the allowed names (the assemble job takes only the apk and record artifacts)" "download of" stage "$work/s_dlx.yml" build
m s_dlbad 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65' 'actions/download-artifact@v5' && expect caught "AC2 a download not pinned by digest" "download step" stage "$work/s_dlbad.yml" build
m s_dlapk '    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n      - name: install Witness \(pinned by checksum\)\n        run: ./bin/install-scanner.sh witness\n      - name: apk under Witness' '    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n      - name: install Witness (pinned by checksum)\n        run: ./bin/install-scanner.sh witness\n      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65 # v5.0.0\n        with:\n          name: witness-build\n          path: x\n      - name: apk under Witness' && expect caught "AC2 the Build apk job downloads something (it takes nothing from outside)" "download of" stage "$work/s_dlapk.yml" build
m s_act   '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: digests' '      - uses: actions/cache@0000000000000000000000000000000000000000 # v4\n        with:\n          name: digests' && expect caught "AC2 a third-party action after Witness" "after the Witness step" stage "$work/s_act.yml" build
mutate "$work/rebuild.yml" "$work/r_step.yml" '--step rebuild \\' '--step build \\'   && expect caught "005-AC1 Rebuild's assemble Witness step is named build" "--step must be rebuild" stage "$work/r_step.yml" rebuild
mutate "$work/rebuild.yml" "$work/r_up.yml" 'name: witness-rebuild' 'name: dist'    && expect caught "005-AC4 Rebuild uploads anything but its verdict" "not an allowed artifact" stage "$work/r_up.yml" rebuild
mutate "$work/rebuild.yml" "$work/r_out.yml" 'witness-rebuild/rebuild-collection.json \\' 'witness-build/build-collection.json \\' && expect caught "005-AC4 Rebuild writing Build's record path" "-o must" stage "$work/r_out.yml" rebuild
mutate "$work/rebuild.yml" "$work/r_dl.yml" 'name: witness-build\n          path: witness-build' 'name: dist\n          path: witness-build' && expect caught "005-AC4 Rebuild downloads Build's dist (it publishes nothing and takes only the record)" "download of" stage "$work/r_dl.yml" rebuild
mutate "$work/build.yml" "$work/r_kind.yml" 'build-stage.sh apk' 'build-stage.sh rebuild-apk' && expect caught "005-AC1 Build running the rebuild script" build-stage stage "$work/r_kind.yml" build
# ---- the stage-script judge (REQ-CHAIN-004-AC3, AC6; REQ-CHAIN-005-AC2) ------------------------------------------------
expect ok     "AC3 fixture: the known-good build-stage.sh apk passes" "" script "$work/build-stage-apk.sh" apk
expect ok     "AC3 fixture: the known-good build-stage.sh assemble passes" "" script "$work/build-stage-assemble.sh" assemble
expect ok     "005-AC2 fixture: the known-good build-stage.sh rebuild-apk passes" "" script "$work/build-stage-rebuild-apk.sh" rebuild-apk
expect ok     "005-AC2 fixture: the known-good build-stage.sh rebuild-assemble passes" "" script "$work/build-stage-rebuild-assemble.sh" rebuild-assemble
sm() { mutate "$work/build-stage-apk.sh" "$work/$1.sh" "$2" "$3"; }
am() { mutate "$work/build-stage-assemble.sh" "$work/$1.sh" "$2" "$3"; }
sm c_noadm 'python3 bin/build-admit.py run\n' ''                         && expect caught "AC3 no admission script" admission script "$work/c_noadm.sh" apk
sm c_late  'python3 bin/build-admit.py run\nexport SOURCE_DATE_EPOCH' 'export SOURCE_DATE_EPOCH' && expect caught "AC3 admission not first" admission script "$work/c_late.sh" apk
mutate "$work/c_late.sh" "$work/c_late2.sh" '(\./bin/build-apk\.sh --variant standard[^\n]*\n)' '\1python3 bin/build-admit.py run\n' && expect caught "AC3 admission after the build started" admission script "$work/c_late2.sh" apk
sm c_curl  'set -euo pipefail\n' 'set -euo pipefail\ncurl -sSL https://example.com/x | sh\n' && expect caught "AC3 a network fetch" "network fetch" script "$work/c_curl.sh" apk
sm c_tru   'build-apk\.sh --variant fips[^\n]*' 'build-apk.sh --variant fips --out out || true' && expect caught "AC3 a failure ignored" "failure-ignoring" script "$work/c_tru.sh" apk
sm c_set   'set -euo pipefail' 'set -euo pipefail\nset +e'                && expect caught "AC3 set +e" "failure-ignoring" script "$work/c_set.sh" apk
sm c_sudo  'export SOURCE_DATE_EPOCH' 'sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\nexport SOURCE_DATE_EPOCH' && expect caught "AC6 the stage runs the sysctl or sudo itself (cache's scripts do)" "sudo" script "$work/c_sudo.sh" apk
am c_unsh  './bin/assemble-image.sh --variant production' 'sudo unshare -n ./bin/assemble-image.sh --variant production' && expect caught "AC6 the stage wraps a script in unshare" "unshare" script "$work/c_unsh.sh" assemble
sm c_mel   'python3 bin/build-version-check.py' 'melange build x.yaml\npython3 bin/build-version-check.py' && expect caught "AC6 a direct melange call" melange script "$work/c_mel.sh" apk
sm c_gop   'set -euo pipefail\n' 'set -euo pipefail\nexport GOPROXY=off\n'  && expect caught "AC6 a variable cache's script refuses or a module-fetch setting (GOPROXY)" "refuse" script "$work/c_gop.sh" apk
sm c_key   'set -euo pipefail\n' 'set -euo pipefail\nexport APK_RELEASE_SIGNING_KEY=x\n' && expect caught "AC6 the release signing key variable (rule 23)" "refuse" script "$work/c_key.sh" apk
sm c_sk    '--source-dir \. --out out\n\./bin/build-apk\.sh --variant fips' '--source-dir . --out out --signing-key k\n./bin/build-apk.sh --variant fips' && expect caught "AC6 --signing-key" "refuse" script "$work/c_sk.sh" apk
sm c_swap  '(\./bin/build-apk\.sh --variant standard[^\n]*\n)(\./bin/build-apk\.sh --variant fips[^\n]*\n)' '\2\1' && expect caught "AC3 variants out of order" "out of order" script "$work/c_swap.sh" apk
sm c_ver   'python3 bin/build-version-check.py[^\n]*\n' ''               && expect caught "AC3 no version check (rule 24)" "version-check" script "$work/c_ver.sh" apk
sm c_sde   'export SOURCE_DATE_EPOCH=[^\n]*' 'export SOURCE_DATE_EPOCH="$(date +%s)"' && expect caught "AC6 the build date is the wall clock, not the tagged commit" SOURCE_DATE_EPOCH script "$work/c_sde.sh" apk
am a_dig   '[^\n]*> witness-build/digests.json\n' ''                      && expect caught "AC3 the assemble job writes no digests.json" "digests" script "$work/a_dig.sh" assemble
am a_nov   '(python3 bin/chain-verify\.py verify --stage build --record witness-apk-ubuntu-24\.04/[^\n]*\n)' '' && expect caught "AC3 one architecture's apk record is not verified before the images are assembled (rule 58)" "witness-apk-ubuntu-24.04/" script "$work/a_nov.sh" assemble
am a_nov2  '(python3 bin/chain-verify\.py verify --stage build --record witness-apk-ubuntu-24\.04-arm/[^\n]*\n)' '' && expect caught "AC3 the arm64 apk record is not verified before the images are assembled" "24.04-arm" script "$work/a_nov2.sh" assemble
am a_late  '(python3 bin/chain-verify\.py verify[^\n]*\n)(python3 bin/chain-verify\.py verify[^\n]*\n)(export SOURCE_DATE_EPOCH[^\n]*\n)(\./bin/assemble-image\.sh --variant production[^\n]*\n)' '\3\4\1\2' && expect caught "AC3 the records are verified AFTER an image is assembled from the downloaded apks" "out of order" script "$work/a_late.sh" assemble
am a_nopol '[^\n]*policy make[^\n]*\n' ''                                  && expect caught "AC3 no policy made for the tag before verifying" "policy make" script "$work/a_nopol.sh" assemble
am a_wrong 'verify --stage build --record witness-apk-ubuntu-24.04/' 'verify --stage rebuild --record witness-apk-ubuntu-24.04/' && expect caught "AC3 verified as the wrong stage" "witness-apk-ubuntu-24.04/" script "$work/a_wrong.sh" assemble
am a_adm   'set -euo pipefail\n' 'set -euo pipefail\npython3 bin/build-admit.py run\n' && expect ok "AC3 control: admission in the assemble job is not forbidden by the order judge (the apk job's first command is what is pinned)" "" script "$work/a_adm.sh" assemble
mutate "$work/build-stage-rebuild-apk.sh" "$work/rc_first.sh" '(python3 bin/chain-verify\.py stage-start[^\n]*\n)' '' && expect caught "005-AC1 Build's record not verified first" "stage-start" script "$work/rc_first.sh" rebuild-apk
mutate "$work/build-stage-rebuild-assemble.sh" "$work/rc_cmp.sh" '[^\n]*rebuild-compare[^\n]*\n' ''  && expect caught "005-AC2 no comparison" "rebuild-compare" script "$work/rc_cmp.sh" rebuild-assemble
mutate "$work/build-stage-rebuild-assemble.sh" "$work/rc_nov.sh" '(python3 bin/chain-verify\.py verify --stage rebuild --record witness-rapk-ubuntu-24\.04/[^\n]*\n)' '' && expect caught "005-AC2 a Rebuild apk record is not verified before the images are assembled" "witness-rapk-ubuntu-24.04/" script "$work/rc_nov.sh" rebuild-assemble
mutate "$work/build-stage-rebuild-assemble.sh" "$work/rc_pub.sh" 'set -euo pipefail\n' 'set -euo pipefail\ncp -r out dist\n' && expect ok "005-AC2 fixture control: an extra local copy is not itself a fault of the order judge" "" script "$work/rc_pub.sh" rebuild-assemble
# ---- the job-graph judge (REQ-CHAIN-005-AC5) ----------------------------------------------------------------------------
expect ok     "005-AC5 fixture: build -> (rebuild || check) -> release passes" "" graph "$work/release.yml"
mutate "$work/release.yml" "$work/g1.yml" '  rebuild:\n    needs: build' '  rebuild:\n    needs: [build, check]' && expect caught "005-AC5 rebuild waits for check" "rebuild must need only build" graph "$work/g1.yml"
mutate "$work/release.yml" "$work/g2.yml" '  check:\n    needs: build' '  check:\n    needs: [build, rebuild]' && expect caught "005-AC5 check waits for rebuild" "check must need only build" graph "$work/g2.yml"
mutate "$work/release.yml" "$work/g3.yml" 'needs: \[rebuild, check, sign\]' 'needs: [check, sign]' && expect caught "005-AC5 release does not need rebuild" "release must need" graph "$work/g3.yml"
mutate "$work/release.yml" "$work/g4.yml" '  sign:\n    needs: build' '  sign:\n    needs: check' && expect caught "005-AC5 sign does not need build" "sign must need build" graph "$work/g4.yml"
mutate "$work/release.yml" "$work/g5.yml" '  rebuild:\n    needs: build' '  rebuild:\n    needs: build\n    if: always()' && expect caught "005-AC5 rebuild runs even when build failed" always graph "$work/g5.yml"
# ---- the Witness record never holds the token variables (REQ-CHAIN-004-AC8): the judge, then the product check ----------
python3 - "$work" <<'PY'
import json, sys
w = sys.argv[1]
def coll(env_vars, extra=None):
    att = [{"type": "https://witness.dev/attestations/environment/v0.1",
            "attestation": {"os": "linux", "hostname": "runner", "username": "runner", "variables": env_vars}},
           {"type": "https://witness.dev/attestations/command-run/v0.1", "attestation": {"cmd": ["./bin/build-stage.sh", "build"], "exitcode": 0}}]
    if extra: att.append(extra)
    return {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
            "subject": [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}],
            "predicate": {"name": "build", "attestations": att}}
clean = {"GITHUB_SHA": "abc", "GITHUB_REF_NAME": "v0.3.0", "RUNNER_TEMP": "/home/runner/work/_temp"}
cases = {"env_clean": coll(clean),
         "env_masked": coll(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="******")),
         "env_value": coll(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="abcdef0123456789")),
         "env_url": coll(dict(clean, ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.actions.githubusercontent.com/x?api-version=2.0")),
         "env_runtime": coll(dict(clean, ACTIONS_RUNTIME_TOKEN="******")),
         "env_jwt": coll(dict(clean, SOMETHING="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl")),
         "env_other_att": coll(clean, {"type": "https://witness.dev/attestations/github/v0.1", "attestation": {"jwt": {"claims": {"sub": "repo:x"}, "raw": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl"}}})}
for k, v in cases.items():
    json.dump(v, open("%s/%s.json" % (w, k), "w"))
PY
expect ok     "AC8 fixture: a clean environment record passes the judge" "" recordenv "$work/env_clean.json"
expect caught "AC8 judge: an obfuscated ACTIONS_ID_TOKEN_REQUEST_TOKEN is still a fault" ACTIONS_ID_TOKEN_REQUEST_TOKEN recordenv "$work/env_masked.json"
expect caught "AC8 judge: ACTIONS_ID_TOKEN_REQUEST_URL" ACTIONS_ID_TOKEN_REQUEST_URL recordenv "$work/env_url.json"
expect caught "AC8 judge: ACTIONS_RUNTIME_TOKEN" ACTIONS_RUNTIME_TOKEN recordenv "$work/env_runtime.json"
expect caught "AC8 judge: a compact JWT anywhere in the record (the github attestor's raw token)" JWT recordenv "$work/env_other_att.json"
CV="$root/bin/chain-verify.py"
run_cv() { local rc=0; python3 "$CV" "$@" > "$work/cv.out" 2> "$work/cv.err" || rc=$?; echo "$rc"; }
rec_expect() { # rec_expect ok|refuse LABEL WORD FILE
  local want=$1 label=$2 word=$3 f=$4 rc; rc=$(run_cv record-env --record "$f")
  if grep -q Traceback "$work/cv.err" 2> /dev/null; then bad "$label -> a Python traceback is a crash, not a refusal"; return; fi
  if [ "$want" = ok ]; then [ "$rc" = 0 ] && ok "$label" || bad "$label -> exit $rc: $(head -c 160 "$work/cv.err" | tr '\n' ' ')"
  else if [ "$rc" = 1 ] && grep -Fq -- "$word" "$work/cv.err"; then ok "$label"; else bad "$label -> exit $rc, wanted 1 naming '$word': $(head -c 160 "$work/cv.err" | tr '\n' ' ')"; fi; fi
}
[ -f "$CV" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
rec_expect ok     "AC8 chain-verify record-env: a clean record is accepted" "" "$work/env_clean.json"
rec_expect refuse "AC8 chain-verify record-env: a masked ACTIONS_ID_TOKEN_REQUEST_TOKEN is refused and named" ACTIONS_ID_TOKEN_REQUEST_TOKEN "$work/env_masked.json"
rec_expect refuse "AC8 chain-verify record-env: a real-looking value is refused and named" ACTIONS_ID_TOKEN_REQUEST_TOKEN "$work/env_value.json"
rec_expect refuse "AC8 chain-verify record-env: ACTIONS_ID_TOKEN_REQUEST_URL" ACTIONS_ID_TOKEN_REQUEST_URL "$work/env_url.json"
rec_expect refuse "AC8 chain-verify record-env: ACTIONS_RUNTIME_TOKEN" ACTIONS_RUNTIME_TOKEN "$work/env_runtime.json"
rec_expect refuse "AC8 chain-verify record-env: a compact JWT in a variable value" JWT "$work/env_jwt.json"
rec_expect refuse "AC8 chain-verify record-env: the github attestor's raw token" JWT "$work/env_other_att.json"
rc=$(run_cv record-env --record "$work/does-not-exist.json"); [ "$rc" = 2 ] && ok "AC8 a missing record is a usage error (exit 2), not a clean pass" || bad "AC8 a missing record exit $rc, wanted 2"
# ---- the stage script's behaviour with FAKE cache scripts (REQ-CHAIN-004-AC3, AC6, AC9; REQ-CHAIN-005-AC2) -----------
# bin/build-stage.sh KIND is run in a throw-away tree: apk (the Build matrix job), assemble (the Build VM job). The fakes log their argv and the
# SOURCE_DATE_EPOCH they saw; the fake chain-verify.py logs `verify ARGS` and exits FAKE_VERIFY_RC.
mk_tree() { # mk_tree DIR SCRIPT  -> a throw-away repo layout with fake cache scripts and the script under test
  local d=$1 s=$2; mkdir -p "$d/bin" "$d/out" "$d/witness-build" "$d/witness-apk-ubuntu-24.04" "$d/witness-apk-ubuntu-24.04-arm"
  cp "$s" "$d/bin/build-stage.sh"; chmod +x "$d/bin/build-stage.sh"
  : > "$d/witness-apk-ubuntu-24.04/apk-collection.json"; : > "$d/witness-apk-ubuntu-24.04-arm/apk-collection.json"
  cat > "$d/bin/build-admit.py" <<'FAKE_EOF'
#!/usr/bin/env python3
import os, sys
open("calls.log", "a").write("admit\n")
sys.exit(int(os.environ.get("FAKE_ADMIT_RC", "0")))
FAKE_EOF
  cat > "$d/bin/chain-verify.py" <<'FAKE_EOF'
#!/usr/bin/env python3
import os, sys
open("calls.log", "a").write("verify " + " ".join(sys.argv[1:]) + "\n")
sys.exit(int(os.environ.get("FAKE_VERIFY_RC", "0")))
FAKE_EOF
  cat > "$d/bin/build-apk.sh" <<'FAKE_EOF'
#!/usr/bin/env bash
if [ "${1:-}" = --print-source-date-epoch ]; then echo 1700000000; exit 0; fi
echo "apk $* SDE=${SOURCE_DATE_EPOCH:-unset}" >> calls.log
env | sort > "env-apk-$(date +%s%N).txt"
exit "${FAKE_APK_RC:-0}"
FAKE_EOF
  cat > "$d/bin/assemble-image.sh" <<'FAKE_EOF'
#!/usr/bin/env bash
echo "image $* SDE=${SOURCE_DATE_EPOCH:-unset}" >> calls.log
v=production; while [ $# -gt 0 ]; do [ "$1" = --variant ] && v=$2; shift; done
mkdir -p out; printf 'sha256:%064d\n' "${#v}" > "out/$v.digest"
exit "${FAKE_IMAGE_RC:-0}"
FAKE_EOF
  cat > "$d/bin/build-version-check.py" <<'FAKE_EOF'
#!/usr/bin/env python3
open("calls.log", "a").write("version\n")
FAKE_EOF
  chmod +x "$d"/bin/*; : > "$d/out/fscache"
}
run_stage() { # run_stage DIR KIND [ENV=VAL...]
  local d=$1 k=$2; shift 2; (cd "$d" && env "$@" GITHUB_REF_NAME=v0.3.0 GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 PATH="$d/bin:$PATH" bash ./bin/build-stage.sh "$k" > stage.out 2> stage.err; echo $?)
}
for variant in fixture real; do
  if [ "$variant" = fixture ]; then sa="$work/build-stage-apk.sh"; ss="$work/build-stage-assemble.sh"; tag="fixture"; else sa="$root/bin/build-stage.sh"; ss="$root/bin/build-stage.sh"; tag="real"; fi
  if [ ! -f "$sa" ]; then
    for l in "AC3 $tag: the apk script runs, and admission is the first call" "AC6 $tag: SOURCE_DATE_EPOCH reaches every apk build" "AC3 $tag: a refused admission runs nothing else" \
             "AC6 $tag: build-apk.sh exit 2 stops the job before the version check" "AC6 $tag: build-apk.sh exit 4 (network attempt) stops the job before the version check" \
             "AC3 $tag: a refused apk record stops the assemble job before any image" "AC6 $tag: assemble-image.sh failing stops the job before any digests.json" \
             "AC9 $tag: digests.json passes PR 1's digest-list schema"; do bad "$l (bin/build-stage.sh does not exist: RED until implemented)"; done
    continue
  fi
  d="$work/tree-$tag-a"; rm -rf "$d"; mk_tree "$d" "$sa"
  rc=$(run_stage "$d" apk); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && [ "$(sed -n 1p <<< "$calls")" = admit ] && grep -q '^version' <<< "$calls"; then ok "AC3 $tag: the apk script runs, admission is the first call and the version check follows the builds"; else bad "AC3 $tag: exit $rc, first call '$(sed -n 1p <<< "$calls")'"; fi
  if ! grep -q 'SDE=unset' <<< "$calls" && [ "$(grep -c 'SDE=1700000000' <<< "$calls")" -ge 2 ]; then ok "AC6 $tag: SOURCE_DATE_EPOCH (the tagged commit's time from cache's script) reaches every apk build"; else bad "AC6 $tag: SOURCE_DATE_EPOCH not exported to every call: $calls"; fi
  rm -rf "$d"; mk_tree "$d" "$sa"; rc=$(run_stage "$d" apk FAKE_ADMIT_RC=1); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" != 0 ] && [ "$calls" = admit ]; then ok "AC3 $tag: a refused admission runs nothing else (no script is called)"; else bad "AC3 $tag: after a refused admission rc=$rc calls=$calls"; fi
  for rcv in 2 4; do
    rm -rf "$d"; mk_tree "$d" "$sa"; rc=$(run_stage "$d" apk FAKE_APK_RC=$rcv); calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^version' <<< "$calls"; then ok "AC6 $tag: build-apk.sh exit $rcv ($( [ $rcv = 4 ] && echo 'a network attempt in the sealed call, FIXED by cache tests' || echo 'a named refusal' )) stops the job before the version check"; else bad "AC6 $tag: apk exit $rcv -> rc=$rc calls=$calls"; fi
  done
  d="$work/tree-$tag-s"; rm -rf "$d"; mk_tree "$d" "$ss"
  rc=$(run_stage "$d" assemble FAKE_VERIFY_RC=1); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && [ ! -e "$d/witness-build/digests.json" ]; then ok "AC3 $tag: a refused apk record stops the assemble job before any image is assembled (rule 58)"; else bad "AC3 $tag: refused record -> rc=$rc calls=$calls"; fi
  rm -rf "$d"; mk_tree "$d" "$ss"; rc=$(run_stage "$d" assemble FAKE_IMAGE_RC=4)
  if [ "$rc" != 0 ] && [ ! -e "$d/witness-build/digests.json" ]; then ok "AC6 $tag: assemble-image.sh failing stops the job before any digests.json"; else bad "AC6 $tag: assemble failure -> rc=$rc, digests.json present=$([ -e "$d/witness-build/digests.json" ] && echo yes || echo no)"; fi
  rm -rf "$d"; mk_tree "$d" "$ss"; rc=$(run_stage "$d" assemble); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  nv=$(grep -n '^verify' <<< "$calls" | tail -1 | cut -d: -f1); ni=$(grep -n '^image ' <<< "$calls" | head -1 | cut -d: -f1)
  if [ "$rc" = 0 ] && [ "$(grep -c '^verify .*--stage build' <<< "$calls")" -ge 2 ] && [ -n "$nv" ] && [ -n "$ni" ] && [ "$nv" -lt "$ni" ] && python3 - "$d" <<'PY'
import json, re, sys
d = sys.argv[1]
j = json.load(open(d + "/witness-build/digests.json"))
assert isinstance(j, dict) and j, "empty"
for k, v in j.items():
    assert re.fullmatch(r"[a-z0-9-]+", k), k
    assert isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v), v
items = json.load(open(d + "/witness-build/items.json"))
assert isinstance(items, dict) and set(j) <= set(items), "digests.json names are not all items"
PY
  then ok "AC9 $tag: both apk records are verified before the first image; digests.json passes PR 1's schema and its names are also items"; else bad "AC9 $tag: assemble rc=$rc verify-before-image=$nv/$ni digests.json missing or off-schema"; fi
done
# the harness itself can fail: a script that ignores failures is caught by the behaviour check (a control)
d="$work/tree-ctl"; rm -rf "$d"; sed -e 's#^\(\./bin/build-apk\.sh --variant .*\)$#\1 || true#' "$work/build-stage-apk.sh" > "$work/ctl-stage.sh"
mk_tree "$d" "$work/ctl-stage.sh"; rc=$(run_stage "$d" apk FAKE_APK_RC=4)
if [ "$rc" = 0 ] || grep -q '^version' "$d/calls.log" 2> /dev/null; then ok "control: a script that ignores a failing apk build is visible to the behaviour harness (exit $rc, version check ran)"; else bad "control: the ignoring script was NOT visible to the behaviour harness (exit $rc)"; fi
# ---- the real repository -------------------------------------------------------------------------------------------------
expect ok "AC1/AC2 the real stage-build.yml passes the Build allowlist" "" stage "$root/.github/workflows/stage-build.yml" build
expect ok "005-AC1/AC4 the real stage-reproducibility.yml passes the Rebuild allowlist" "" stage "$root/.github/workflows/stage-reproducibility.yml" rebuild
for k in apk assemble rebuild-apk rebuild-assemble; do
  expect ok "AC3/005-AC2 the real bin/build-stage.sh passes the order judge for kind $k" "" script "$root/bin/build-stage.sh" "$k"
done
expect ok "005-AC5 the real release.yml job graph" "" graph "$root/.github/workflows/release.yml"
[ ! -e "$root/.github/workflows/stage-image.yml" ] && [ ! -e "$root/.github/workflows/stage-admission.yml" ] && ok "AC1 stage-image.yml and stage-admission.yml are gone (rules 50, 61)" || bad "AC1 stage-image.yml / stage-admission.yml still exist (RED until PR 2)"
grep -q 'witness' "$root/bin/install-scanner.sh" && ok "AC2 bin/install-scanner.sh installs witness pinned by checksum" || bad "AC2 bin/install-scanner.sh has no witness (RED: the implementation adds it)"
# ---- the apko lock flow and the fixed relative config path (REQ-CHAIN-004-AC11, REQ-CHAIN-005-AC6; cache-3f's real apko v1.4.6 run) ---------------
# (A) apko only through bin/assemble-image.sh (always --lockfile), identical arguments in Build and Rebuild; (B) configs only from build/apko.yaml and
# build/apko-fips.yaml in the repo root. Source: ~/fosterstack/audits/2026-10-09/real-lock/REPORT.md ("CAVEAT: build WITH --lockfile vs WITHOUT gives
# DIFFERENT digests"; "config.name is the path as typed, so make the lock with a fixed relative path").
LA="$work/build-stage-assemble.sh"; LR="$work/build-stage-rebuild-assemble.sh"
lf() { judge lockflow "$work/build.yml" "$work/rebuild.yml" "$@"; }
lfx() { # lfx ok|caught LABEL WORD ASSEMBLE_SCRIPT REBUILD_SCRIPT [BUILD_YML REBUILD_YML]
  local want=$1 label=$2 word=$3 a=$4 r=$5 by=${6:-$work/build.yml} ry=${7:-$work/rebuild.yml}
  expect "$want" "$label" "$word" lockflow "$by" "$ry" "$a" "$r"
}
lfx ok "AC11/005-AC6 fixture: the known-good Build and Rebuild assemble scripts and stage files pass the lock-flow judge" "" "$LA" "$LR"
# a control: the fixed relative config paths, passed consistently in both, are allowed
sed -e 's#--variant production#--variant production --config build/apko.yaml#' -e 's#--variant fips#--variant fips --config build/apko-fips.yaml#' "$LA" > "$work/lf_cfg_a.sh"
sed -e 's#--variant production#--variant production --config build/apko.yaml#' -e 's#--variant fips#--variant fips --config build/apko-fips.yaml#' "$LR" > "$work/lf_cfg_r.sh"
lfx ok "AC11 control: the fixed relative config paths (build/apko.yaml, build/apko-fips.yaml) are allowed" "" "$work/lf_cfg_a.sh" "$work/lf_cfg_r.sh"
mutate "$LA" "$work/lf_dir.sh" 'set -euo pipefail\n' 'set -euo pipefail\napko build --lockfile out/production.lock.json build/apko.yaml fscache:x out/production.tar\n' \
  && lfx caught "AC11 (A) a direct apko call in a stage script" "apko" "$work/lf_dir.sh" "$LR"
mutate "$LA" "$work/lf_nolock.sh" 'set -euo pipefail\n' 'set -euo pipefail\napko build build/apko.yaml fscache:x out/production.tar\n' \
  && lfx caught "AC11 (A) apko build WITHOUT the lock (a different image digest, per the real run)" "apko" "$work/lf_nolock.sh" "$LR"
mutate "$LR" "$work/lf_date.sh" '(assemble-image\.sh --variant production)' '\1 --build-date 2026-10-09T00:00:00Z' \
  && lfx caught "AC11 (A) Rebuild passes its own --build-date" "--build-date" "$LA" "$work/lf_date.sh"
mutate "$LA" "$work/lf_lockflag.sh" '(assemble-image\.sh --variant fips)' '\1 --lockfile out/fips.lock.json' \
  && lfx caught "AC11 (A) the stage passes --lockfile itself (the script owns the lock flow)" "--lockfile" "$work/lf_lockflag.sh" "$LR"
mutate "$LA" "$work/lf_nolockflag.sh" '(assemble-image\.sh --variant fips)' '\1 --no-lock' \
  && lfx caught "AC11 (A) --no-lock" "--no-lock" "$work/lf_nolockflag.sh" "$LR"
mutate "$LR" "$work/lf_ver.sh" '(assemble-image\.sh --variant production --version )"\$\{GITHUB_REF_NAME#v\}"' '\1"9.9.9"' \
  && lfx caught "AC11 (A) Rebuild's arguments differ from Build's for the same variant" "DIFFERENT" "$LA" "$work/lf_ver.sh"
mutate "$LR" "$work/lf_sde.sh" 'export SOURCE_DATE_EPOCH=[^\n]*' 'export SOURCE_DATE_EPOCH=1700000000' \
  && lfx caught "AC11 (A) Rebuild exports a different SOURCE_DATE_EPOCH than Build" "differently" "$LA" "$work/lf_sde.sh"
mutate "$work/build.yml" "$work/lf_wfapko.yml" '(-- \./bin/build-stage\.sh assemble)' '\1 \&\& apko build build/apko.yaml fscache:x out.tar' \
  && lfx caught "AC11 (A) a stage workflow names apko in a run step" "apko" "$LA" "$LR" "$work/lf_wfapko.yml"
mutate "$work/build.yml" "$work/lf_wd.yml" '(run: \./bin/install-scanner\.sh witness)' '\1\n        working-directory: build' \
  && lfx caught "AC11 (B) a working-directory in a stage step (not the repo root)" "working-directory" "$LA" "$LR" "$work/lf_wd.yml"
mutate "$LA" "$work/lf_abs.sh" '(assemble-image\.sh --variant production)' '\1 --config /work/archive/apko.yaml' \
  && lfx caught "AC11 (B) an absolute config path" "fixed relative path" "$work/lf_abs.sh" "$LR"
mutate "$LA" "$work/lf_cp.sh" 'set -euo pipefail\n' 'set -euo pipefail\ncp build/apko.yaml "$RUNNER_TEMP/apko.yaml"\n' \
  && lfx caught "AC11 (B) a temp copy of the config" "copies a config" "$work/lf_cp.sh" "$LR"
mutate "$LA" "$work/lf_cd.sh" 'set -euo pipefail\n' 'set -euo pipefail\ncd build\n' \
  && lfx caught "AC11 (B) a cd away from the repo root" "repo root" "$work/lf_cd.sh" "$LR"
mutate "$LA" "$work/lf_name.sh" '(assemble-image\.sh --variant production)' '\1 --config build/apko-prod.yaml' \
  && lfx caught "AC11 (B) a different config name" "fixed relative path" "$work/lf_name.sh" "$LR"
mutate "$LA" "$work/lf_var.sh" '(assemble-image\.sh --variant production)' '\1 --config build/apko-fips.yaml' \
  && lfx caught "AC11 (B) the fips config for the production variant" "fixed relative path" "$work/lf_var.sh" "$LR"
expect ok "AC11/005-AC6 the real stage files and bin/build-stage.sh keep apko behind assemble-image.sh and the config at its fixed relative path" "" \
  lockflow "$root/.github/workflows/stage-build.yml" "$root/.github/workflows/stage-reproducibility.yml" "$root/bin/build-stage.sh"
EXPECT=135
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
