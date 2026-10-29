"""Test infrastructure (not product code), shared by bin/chain-build-wiring-test.sh and bin/chain-rebuild-test.sh: the judges for
the shape of the Build and Rebuild stage files, the four stage scripts, the job graph of release.yml and the environment record of
a Witness collection. Each judge prints `ok` or the list of faults and exits 1 on any fault; the tests first prove every judge on a
known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then apply it to the real repository (RED until
PR 2 is implemented).

DESIGN RULE (PR 1's ten lost rounds): NO denylists, NO shell analysis, NO subsequence checks. Every judge below is a FINITE EXACT
GRAMMAR over an allowlist: a stage file is exactly the steps in JOBS, a stage script is exactly the lines of expected_lines(KIND),
the job graph is exactly the keys and targets in CHAIN. Anything else is a fault by construction.

  helper FILE                               REQ-CHAIN-004-AC2 (the Witness seam): bin/witnessed.sh is exactly the canonical helper, `timeout -k 20 540` included
  directwitness FILE...                     REQ-CHAIN-004-AC2: no `witness run` in any stage file or stage script (every call goes through the helper)
  stage FILE build|rebuild [ALLOWED.json]   REQ-CHAIN-004-AC1, AC2 / REQ-CHAIN-005-AC1, AC4
  script FILE KIND                          REQ-CHAIN-004-AC3, AC6, AC11 / REQ-CHAIN-005-AC2: FILE is exactly expected_lines(KIND)
  lockflow BUILD_ASM REBUILD_ASM STAGE_YML...   REQ-CHAIN-004-AC11 / REQ-CHAIN-005-AC6: Build and Rebuild assemble identically; no stage file names apko
  listed CHAIN_SCRIPTS.json ROOT            the four scripts are rows of .github/policy/chain-scripts.json with their real sha256 (PR 1's design)
  callers FILE                              REQ-CHAIN-004-AC14: a proof workflow calls stage-build.yml with mode: snapshot and nothing else
  graph FILE                                REQ-CHAIN-005-AC5: the chain jobs of release.yml
  workflows DIR                             REQ-CHAIN-004-AC1: no workflow file is added beyond stage-sign.yml,
                                             and stage-image.yml / stage-admission.yml are gone
  recordenv FILE                            REQ-CHAIN-004-AC8: no token variable or token in a Witness collection (a DSSE envelope)

=== Rule 68 seam (advisor ruling, Oct 9; owner's amendment of rule 68: every command run under Witness is wrapped in `timeout 540`) ===========
Fulcio's keyless certificate lives 10 minutes and Witness verifies it at the timestamp's time (harness spike (d)), so no witnessed command may
outlive it. The wrapping lives in ONE place: the committed helper bin/witnessed.sh `witnessed <step> <script>`, which holds ALL the Witness flags
(keyless Fulcio, the timestamp authority, the attestors, the output path, `timeout 540`). Every stage calls it; no stage file and no listed script
names `witness run`. The seam in this file is exactly three functions: witness_seam (the stage's one run line), helper (the helper's exact lines)
and directwitness (nothing else runs Witness). If harness spike (d) changes the wrapping (witness wraps only short steps; or a second witness run
signs a record of the first), only those three functions and the fixture generators (witness_block, witnessed_text in
bin/chain-build-wiring-test.sh) change; the per-kind script grammar (expected_lines) never names Witness.
READABILITY FOR A HUMAN IS AN EXPLICIT REVIEW ITEM (owner, Oct 9): the judges accept the plain form and reject variants rather than growing clever.
==============================================================================================================================

PROPOSED/UNVERIFIED layout constants (cache's archive layout and the items layout are not fixed by any cache test; each is ONE
constant here, so a cache amendment changes one line): ARCHIVE, GO_ARCHIVE, KEYRING_WOLFI, MELANGE_LOCK, ASSEMBLY_PUB.
"""
import hashlib, json, os, re, shlex, sys, yaml

ARCHIVE, GO_ARCHIVE = "archive", "archive/go"
KEYRING_WOLFI, MELANGE_LOCK, ASSEMBLY_PUB = "archive/keys/wolfi-signing.rsa.pub", "build/locks/melange.lock", "build/keys/assembly.rsa.pub"
VER = '"${GITHUB_REF_NAME#v}"'          # --version is the tag minus the leading v: 0.3.0, or 0.3.0-rc.1 for a release candidate (PROPOSED, cache-3f)
RUNNERS = [("ubuntu-24.04", "x86_64"), ("ubuntu-24.04-arm", "aarch64")]
H = "set -euo pipefail"
POLICY = 'python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json'
SDE = ['SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"', "export SOURCE_DATE_EPOCH"]
START = ("python3 bin/chain-verify.py stage-start --stage rebuild --previous build --record witness-build/build-collection.json "
         "--digests build-in/digests.json --policy policy.json")


# SNAPSHOT MODE (REQ-CHAIN-004-AC12): the proof workflows (scan.yml, main-candidate-rescan.yml) build with no tag, so there is no version to take from
# one; the snapshot scripts pass this fixed release-candidate-shaped version to cache's scripts (PROPOSED/UNVERIFIED: cache confirms that
# build-apk.sh and assemble-image.sh accept it). Nothing built in snapshot mode is ever published, signed by Sign or accepted by a verifier.
SNAPSHOT_VERSION = "0.0.0-rc.1"
SNAPSHOT_TAG = "v" + SNAPSHOT_VERSION
# cache's driver (rule 24) accepts a binary only when its Go build stamp is exactly v<version> and vcs.revision is the source HEAD, so an untagged commit
# (a pseudo-version) is refused. The snapshot apk script therefore makes a LOCAL lightweight tag at HEAD in the job's own checkout and never pushes it.
# ADVISOR RULING (Oct 9): a v* tag that HEAD already carries in snapshot mode (scan.yml also runs on a push of a v* tag) is ACCEPTED: nothing is refused. But
# Go stamps the HIGHEST semver tag at HEAD (probe: with v0.3.0 at HEAD, `git tag --force v0.0.0-rc.1 HEAD` still gives the stamp v0.3.0, and cache's
# driver reads the buildinfo `mod` line and would refuse). So the script first DELETES every other local v* tag that points at HEAD (git tag -d in the
# job's own checkout; nothing is pushed, fetched or restored, and no ref of the remote is touched), then makes v0.0.0-rc.1, then refuses, naming the tag, if HEAD still carries any
# tag other than v0.0.0-rc.1 (a non-v* tag is not ours to delete). The real-Go proof is in bin/chain-snapshot-test.sh.
# GUARD (advisor, Oct 9 night): deleting tags is destructive on a developer's clone (an unpushed local tag would be lost), so outside GitHub Actions the script
# refuses, before any `git tag`, and exits 2 naming the reason. A local run belongs in a throwaway clone, where GITHUB_ACTIONS=true can be set on purpose.
SNAPSHOT_TAG_GUARD = ('[ "${GITHUB_ACTIONS:-}" = true ] || { echo "refusing to delete tags outside GitHub Actions (run in a throwaway clone)" >&2; exit 2; }')
SNAPSHOT_TAG_DELETE = ("for t in $(git tag --list 'v*' --points-at HEAD); do [ \"$t\" = %s ] || git tag -d \"$t\" > /dev/null; done" % SNAPSHOT_TAG)
SNAPSHOT_TAG_LINE = "git tag --force %s HEAD" % SNAPSHOT_TAG
SNAPSHOT_TAG_CHECK = ("if git tag --points-at HEAD | grep -qvx '%s'; then "
                      "echo \"::error::HEAD carries the tag $(git tag --points-at HEAD | grep -vx '%s' | head -1): not a snapshot\" >&2; exit 1; fi"
                      % (SNAPSHOT_TAG, SNAPSHOT_TAG))
SNAPSHOT_TAG_LINES = [SNAPSHOT_TAG_GUARD, SNAPSHOT_TAG_DELETE, SNAPSHOT_TAG_LINE, SNAPSHOT_TAG_CHECK]


def apk_cmd(variant, ver=VER):
    return ('./bin/build-apk.sh --variant %s --arch "$(uname -m)" --version %s --source-dir . --repo %s --keyring %s --go-archive %s '
            "--melange-lock %s --out out" % (variant, ver, ARCHIVE, KEYRING_WOLFI, GO_ARCHIVE, MELANGE_LOCK))


def image_cmd(variant, ver=VER):
    return ("./bin/assemble-image.sh --variant %s --version %s --archive %s --melange-repo melange-repo --keyring-dir keyring --out out"
            % (variant, ver, ARCHIVE))


VEX_FILE = ".vex/fosterstack-cache.openvex.json"


def vex_attach():
    """REQ-REL-010-AC1: right after the images are assembled and before items-merge writes digests.json, each variant's built index becomes the final index (one
    attestation child per platform carrying the release's OpenVEX), and its digest file follows; the same four lines in every assembly, Build's and Rebuild's, snapshot or not."""
    lines = []
    for variant in ("production", "fips"):
        lines.append("python3 bin/vex-index.py layout --layout out/%s --vex %s" % (variant, VEX_FILE))
        lines.append("python3 bin/vex-index.py sidecar --layout out/%s --vex %s --digest-file out/%s.digest" % (variant, VEX_FILE, variant))
    return lines


def version_check(variant):
    return ('python3 bin/build-version-check.py --apk-dir "out/$(uname -m)" --variant %s --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA"' % variant)


def bind_files(step, rec_dir, record, apk_dir):
    """Every file of each downloaded apk artifact must be the product the building job's LOCAL record holds under the same name (rule 58); the record is unsigned
    (the building jobs hold no identity token) and Sign checks it again against the artifacts it receives before it signs it."""
    return ["python3 bin/chain-verify.py bind --local --step %s --record %s/%s/%s --dir %s/%s --as out" % (step, rec_dir, r, record, apk_dir, r)
            for r, a in RUNNERS]


def melange_repo(apk_dir):
    return (["mkdir -p melange-repo"] + ["cp -R %s/%s/%s melange-repo/%s" % (apk_dir, r, a, a) for r, a in RUNNERS]
            + ["mkdir -p keyring", "cp %s keyring/wolfi-signing.rsa.pub" % KEYRING_WOLFI, "cp %s keyring/assembly.rsa.pub" % ASSEMBLY_PUB])


def archives(ver=VER):
    return "python3 bin/build-archives.py --melange-repo melange-repo --version %s --out dist" % ver


def merge(apk_dir, outputs, ver=VER):
    frags = " ".join("--fragment %s/%s/items-apk.json" % (apk_dir, r) for r, a in RUNNERS)
    return "python3 bin/chain-verify.py items-merge %s --images out --archives dist --version %s --archive %s %s" % (frags, ver, ARCHIVE, outputs)


def items_apk():
    return 'python3 bin/chain-verify.py items-apk --out-dir "out/$(uname -m)" --result out/items-apk.json'


def expected_lines(kind):
    """The exact lines (shebang, comments and blank lines aside; a trailing-backslash break is joined) of bin/build-stage-KIND.sh."""
    if kind == "apk":
        return ([H, "python3 bin/build-admit.py run", "unset GH_TOKEN"] + SDE + [apk_cmd("standard"), apk_cmd("fips"),
                version_check("standard"), version_check("fips"), items_apk(), ADMISSION_COPY])
    if kind == "assemble":
        return ([H] + bind_files("apk", "rec-apk", "apk-collection.local.json", "apk")
                + [ADMISSION_BASELINE] + melange_repo("apk") + SDE + [image_cmd("production"), image_cmd("fips")] + vex_attach() + [archives(),
                merge("apk", "--digests digests.json --items items.json")])
    if kind == "snapshot-apk":       # no admission, no version check, no tag: the version is the fixed snapshot one
        return ([H] + SNAPSHOT_TAG_LINES + SDE
                + [apk_cmd("standard", SNAPSHOT_VERSION), apk_cmd("fips", SNAPSHOT_VERSION), items_apk()])
    if kind == "snapshot-assemble":  # no policy and no verify (a snapshot record is refused by every verifier): the bind is the only link to the record
        return ([H] + bind_files("snapshot-apk", "rec-apk", "snapshot-apk-collection.local.json", "apk") + melange_repo("apk") + SDE
                + [image_cmd("production", SNAPSHOT_VERSION), image_cmd("fips", SNAPSHOT_VERSION)] + vex_attach() + [archives(SNAPSHOT_VERSION),
                   merge("apk", "--digests digests.json --items items.json", SNAPSHOT_VERSION)])
    if kind == "snapshot-rebuild-apk":      # the same local-tag discipline as the snapshot Build; no policy, no stage-start (a snapshot record is refused)
        return ([H] + SNAPSHOT_TAG_LINES + SDE
                + [apk_cmd("standard", SNAPSHOT_VERSION), apk_cmd("fips", SNAPSHOT_VERSION), items_apk()])
    if kind == "snapshot-rebuild-assemble":     # --snapshot makes rebuild-compare accept exactly Build's snapshot-build record and nothing else
        return ([H] + bind_files("snapshot-rapk", "rec-rapk", "snapshot-rapk-collection.local.json", "rapk") + melange_repo("rapk") + SDE
                + [image_cmd("production", SNAPSHOT_VERSION), image_cmd("fips", SNAPSHOT_VERSION)] + vex_attach() + [archives(SNAPSHOT_VERSION),
                   merge("rapk", "--items items.json", SNAPSHOT_VERSION),
                   "python3 bin/chain-verify.py rebuild-compare --snapshot --build-record witness-build/snapshot-build-collection.local.json "
                   "--expected build-in/items.json --actual items.json --out %s" % SNAPSHOT_VERDICT])
    if kind == "rebuild-apk":
        return [H, POLICY, START] + SDE + [apk_cmd("standard"), apk_cmd("fips"), items_apk()]
    if kind == "rebuild-assemble":
        return ([H, POLICY, START]
                + bind_files("rapk", "rec-rapk", "rapk-collection.local.json", "rapk") + melange_repo("rapk") + SDE
                + [image_cmd("production"), image_cmd("fips")] + vex_attach() + [archives(), merge("rapk", "--items items.json"),
                   "cp build-in/digests.json digests.json",          # REQ-CHAIN-005-AC2 (Astra R2): Rebuild's record carries the digest list it was started against as a product
                   "python3 bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json "
                   "--expected build-in/items.json --actual items.json --out witness-rebuild/verdict.json"])
    raise KeyError(kind)


SCRIPTS = {"witnessed": "bin/witnessed.sh", "apk": "bin/build-stage-apk.sh", "assemble": "bin/build-stage-assemble.sh",
           "rebuild-apk": "bin/build-stage-rebuild-apk.sh", "rebuild-assemble": "bin/build-stage-rebuild-assemble.sh",
           "snapshot-apk": "bin/build-stage-snapshot-apk.sh", "snapshot-assemble": "bin/build-stage-snapshot-assemble.sh",
           "snapshot-rebuild-apk": "bin/build-stage-snapshot-rebuild-apk.sh", "snapshot-rebuild-assemble": "bin/build-stage-snapshot-rebuild-assemble.sh"}


def read_exact(path):
    """The bytes as bash sees them: newline="" keeps a lone CR or a CRLF, which Python's default reading would turn into a plain newline."""
    return open(path, newline="").read()


def control_chars(raw):
    """Only tab and newline are allowed (so a CR is refused too). Python's splitlines() and strip() treat VT, FF, FS, NEL and U+2028 as line breaks
    or space and bash does not; read with split("\\n") and refused if the script holds any other control character."""
    return sorted({"U+%04X" % ord(c) for c in raw if (ord(c) < 32 and c not in "\t\n") or 127 <= ord(c) <= 159 or c in "\u2028\u2029"})


def commands_of(raw):
    """(commands, faults) of a committed script, read the way bash reads it. Blank lines and comment lines are dropped. A command line may end in
    ` \\` (a space and one backslash): bash then joins the next physical line, and so does this. A comment line is never joined, even if it ends in a
    backslash (bash does not continue a comment: the next line is a command and is judged as one). A backslash at the end of any other line is a fault."""
    commands, faults, pending = [], [], None
    lines = raw.split("\n")
    for number, line in enumerate(lines, 1):
        if pending is not None and number == len(lines) and not line:
            break                                   # the file ends right after a continuation: pending is reported below
        if pending is not None:
            line, pending = pending + " " + line.lstrip(" \t"), None
        elif line.lstrip(" \t").startswith("#") or not line.strip(" \t"):
            continue
        if line.endswith(" \\"):
            pending = line[:-2]
        elif line.endswith("\\"):
            faults.append("line %d ends in a backslash that is not preceded by a space (bash joins the next line with no space)" % number)
        else:
            commands.append(line)
    if pending is not None:
        faults.append("the script ends in a line continuation")
    return commands, faults


def compare(got, want, what):
    """Command by command, exactly: the first difference is named, then the counts (no extra command, no missing command)."""
    bad = []
    for i in range(max(len(want), len(got))):
        w, g = (want[i] if i < len(want) else None), (got[i] if i < len(got) else None)
        if w != g:
            bad.append("%s command %d: expected %r, found %r" % (what, i + 1, (w or "<end of file>")[:170], (g or "<end of file>")[:170])); break
    if len(want) != len(got):
        bad.append("%s has %d commands, the grammar has %d" % (what, len(got), len(want)))
    return bad


def script(path, kind):
    raw = read_exact(path)
    commands, faults = commands_of(raw)
    return ["control character %s in the script" % c for c in control_chars(raw)] + faults + compare(commands, expected_lines(kind), "the script")


# ---- the stage files -----------------------------------------------------------------------------------------------------------
PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
CHECKOUT_WITH = {"persist-credentials": "false", "fetch-depth": "0"}      # fetch-depth 0 fetches every tag too (fetch-tags is not a key the final judge allows)
# the four building jobs hold NO identity token (owner Oct 22 2026, ops/docs/ratify/2026-10-22-witness-signed-outside-build.md): their Witness record is made with a throwaway key and
# signed outside the build, by Sign
PERM_PLAIN = {"contents": "read"}
PERM_ADMIT = {"contents": "read", "checks": "read", "statuses": "read", "pull-requests": "read"}
MAT = "${{ matrix.runner }}"
# Build hands Sign the digests.json text: the stage output reads the assemble job's output, which one pinned step fills from digests.json
STAGE_OUTPUT = "${{ jobs.assemble.outputs.digests }}"
JOB_OUTPUT = "${{ steps.digests.outputs.digests }}"
ALWAYS = "always()"
VERDICT_ARTIFACT = "witness-rebuild"
# Rebuild receives Build's record under one name in a release (the copy Sign signed) and under another in a snapshot (nothing signs a snapshot)
WB_DOWN = "${{ inputs.mode == 'release' && 'signed-witness-build' || 'witness-build' }}"
MODE_RELEASE_IF = "${{ inputs.mode == 'release' }}"
MODE_SNAPSHOT_IF = "${{ inputs.mode == 'snapshot' }}"
MODE_GUARD_ENV = {"MODE": "${{ inputs.mode }}"}
# Rebuild's apk job installs the same pinned Go toolchain (release review R1, Oct 21: bin/build-apk.sh refuses to run in CI without the pinned Go at /usr/local/bin/fscache-go, REQ-CHAIN-005-AC2: Rebuild uses the same pinned tools as Build)
# Build's apk job installs the Go toolchain admission's verify-freeze needs (the old stage-admission did, from go.mod) the way the chain installs Witness: a
# checksum-pinned `bash bin/install-scanner.sh go` run line, AFTER the Witness install (rule 68: Witness first) and before the downloads and the Witness step
# (advisor, Codex A r3 F4: no setup-go action; the toolchain bytes are pinned by a committed sha256)
# admission.json is written once per apk leg (the Witness record of each leg holds it as a product) but uploaded ONCE, from the leg on ubuntu-24.04 and only in a
# release run, under the fixed name `admission` (PR 4's Release reads the baseline a CI patch tag used from it; a matrix upload under one name would clash)
ADMISSION_IF = "${{ inputs.mode == 'release' && matrix.runner == 'ubuntu-24.04' }}"
# REQ-CHAIN-007-AC19 (advisor ruling B, Oct 12): the baseline admission chose reaches Release as a product of Build's own record. Each apk leg copies its admission.json
# into out/ (so the leg's record holds it and the assemble job's `bind` verifies it), the assemble job writes admission-baseline.json from both legs (a product of
# Build's record), and uploads it under the fixed name `admission-baseline` in a release run only.
BASELINE_IF = "${{ inputs.mode == 'release' }}"
ADMISSION_COPY = "cp admission.json out/admission.json"
ADMISSION_BASELINE = ('python3 bin/chain-verify.py admission-baseline --admission apk/ubuntu-24.04/admission.json --admission apk/ubuntu-24.04-arm/admission.json '
                      '--tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" --out admission-baseline.json')
INSTALL_GO = "bash bin/install-scanner.sh go"
# REQ-CHAIN-004-AC3 (rule 62, advisor 0393 item 1; advisor Oct 12 item 4): the VM runs melange and apko, each in the job that uses it: an apk job of Build and Rebuild installs
# melange ONLY and an assemble job apko ONLY, from cache's bin/install-build-tools.sh, the pinned and checksummed installer (version and sha256 per tool and architecture, fixed
# destination /usr/local/bin), one step, right after the Witness (and Go) install and so before admission; no secret, the same way as Witness and Go
INSTALL_MELANGE = "bash bin/install-build-tools.sh melange"
INSTALL_APKO = "bash bin/install-build-tools.sh apko"
# REQ-CHAIN-004-AC16 (advisor ACs 10-13, Oct 15; owner rules 3 and 9): every job builds from archive/, so each installs the checksum-pinned crane (fixed
# destination /usr/local/bin, where bin/archive-pull.sh names it) and pulls the archive by the digest committed in build/archive.json, into archive/, as two
# steps of their own after the build tools and before the downloads and the Witness step; a failed pull fails the job (no if, no continue-on-error, no env)
INSTALL_CRANE = "bash bin/install-scanner.sh crane"
ARCHIVE_PULL = "bash bin/archive-pull.sh --pointer build/archive.json --out archive"
ARCHIVE_SCRIPTS = ("bin/archive-pull.sh", "bin/archive-verify.py", "bin/install-host-bwrap.py")      # the files the pull step and the host-tools step run: rows of chain-scripts.json with their sha256
# REQ-CHAIN-004-AC17 (advisor reading Oct 20, rules 15 and 38a): melange's bubblewrap runner needs bwrap, which the hosted images do not ship. An apk job (the jobs that run
# melange) unpacks it, and what it needs, from the archive just pulled: one step right after the pull, a name and a run and nothing else, never a package manager or sudo.
INSTALL_HOSTTOOLS = "python3 -I bin/install-host-bwrap.py --archive archive --lock build/locks/host-tools.lock --root host-tools"
PRE_INSTALLS = ("bash bin/install-scanner.sh witness", INSTALL_GO, INSTALL_MELANGE, INSTALL_APKO, INSTALL_CRANE, ARCHIVE_PULL, INSTALL_HOSTTOOLS)
# The guard step has NO `if` and runs a listed script that judges the raw mode string, case-sensitively: GitHub's `==` and `!=` in an expression compare
# case-insensitively ('Release' == 'release' is true), so an `if` could not tell a mixed-case mode from the exact one (Codex A r1 F6). The mode reaches the
# script as a whole "$MODE" argument of a step env (MODE is in env_names of chain-scripts.json).
MODE_GUARD_RUN = 'bash bin/build-stage-refuse-mode.sh "$MODE"'
# the closed list of snapshot step names
SNAPSHOT_STEP = {"apk": "snapshot-apk", "build": "snapshot-build", "rapk": "snapshot-rapk", "rebuild": "snapshot-rebuild"}
SNAPSHOT_VERDICT = "witness-rebuild/snapshot-verdict.json"       # a snapshot Rebuild's verdict: named, so it can never be mistaken for a release verdict
HOSTILE_IF = "${{ inputs.hostile }}"
HOSTILE_RUN = "bash bin/chain-hostile-step.sh"
HOSTILE_UP = {"name": "hostile-attempts", "path": "attempts", "if-no-files-found": "error"}
EXPOSE = 'echo "digests=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"'
# Rebuild's assemble job exposes the sha256 of every record and of the verdict it made or consumed, for Sign (the Witness move, adversarial pass R2): a job output only that job can write
EXPOSE_RECORDS = 'r=$(bash bin/rebuild-records-digests.sh witness-rebuild rec-rapk/ubuntu-24.04 rec-rapk/ubuntu-24.04-arm) && echo "records=$r" >> "$GITHUB_OUTPUT"'
RECORDS_STAGE_OUTPUT = "${{ jobs.assemble.outputs.records }}"
# the Rebuild apk jobs, one per architecture, each exposes the sha256 of its record at its own upload (adversarial pass round 6, A1); assemble checks what it downloads against them
def exposerapk(runner): return 'r=$(bash bin/rebuild-records-digests.sh --rapk %s witness-rapk) && echo "records=$r" >> "$GITHUB_OUTPUT"' % runner
RAPK_CHECK_ENV = {"RAPK_RECORDS": "${{ needs.rapk.outputs.records }}", "RAPK_ARM_RECORDS": "${{ needs.rapk-arm.outputs.records }}"}
RAPK_CHECK_RUN = 'bash bin/rebuild-records-digests.sh --check "$RAPK_RECORDS" "$RAPK_ARM_RECORDS"'
RAPK_JOBS = {"rapk": "ubuntu-24.04", "rapk-arm": "ubuntu-24.04-arm"}
RECORDS_JOB_OUTPUT = "${{ steps.records.outputs.records }}"
JOBS = {  # (family, job) -> spec; every step list is EXACT and in this order. An upload names ONE path (the artifact is rooted at it).
    ("build", "apk"): dict(kind="apk", step="apk", perm=PERM_ADMIT, gh=True, matrix=True, down=[], mode=True, setup_go=True, tools=(INSTALL_MELANGE,), hosttools=True,
        up=[("apk-" + MAT, "out"), ("witness-apk-" + MAT, "witness-apk"), ("admission", "admission.json")]),
    ("build", "assemble"): dict(kind="assemble", step="build", perm=PERM_PLAIN, gh=False, matrix=False, tools=(INSTALL_APKO,), expose=True, hostile=True, mode=True,
        down=[("apk-" + r, "apk/" + r) for r, a in RUNNERS] + [("witness-apk-" + r, "rec-apk/" + r) for r, a in RUNNERS],
        up=[("witness-build", "witness-build"), ("digests", "digests.json"), ("items", "items.json"), ("admission-baseline", "admission-baseline.json"), ("dist", "dist"), ("images", "out")]),
    ("rebuild", "rapk"): dict(kind="rebuild-apk", step="rapk", perm=PERM_PLAIN, gh=False, matrix=False, runner="ubuntu-24.04", tools=(INSTALL_MELANGE,), hosttools=True, mode=True, setup_go=True, expose_rapk=True,
        down=[(WB_DOWN, "witness-build"), ("digests", "build-in")],
        up=[("rapk-ubuntu-24.04", "out"), ("witness-rapk-ubuntu-24.04", "witness-rapk")]),
    ("rebuild", "rapk-arm"): dict(kind="rebuild-apk", step="rapk", perm=PERM_PLAIN, gh=False, matrix=False, runner="ubuntu-24.04-arm", tools=(INSTALL_MELANGE,), hosttools=True, mode=True, setup_go=True, expose_rapk=True,
        down=[(WB_DOWN, "witness-build"), ("digests", "build-in")],
        up=[("rapk-ubuntu-24.04-arm", "out"), ("witness-rapk-ubuntu-24.04-arm", "witness-rapk")]),
    ("rebuild", "assemble"): dict(kind="rebuild-assemble", step="rebuild", perm=PERM_PLAIN, gh=False, matrix=False, tools=(INSTALL_APKO,), mode=True, expose_records=True, check_rapk=True,
        down=[(WB_DOWN, "witness-build"), ("digests", "build-in"), ("items", "build-in")]
              + [("rapk-" + r, "rapk/" + r) for r, a in RUNNERS] + [("witness-rapk-" + r, "rec-rapk/" + r) for r, a in RUNNERS],
        up=[("witness-rebuild", "witness-rebuild")]),
}


def stage(path, family, allowed_path=None):
    bad = []
    text = open(path).read()
    d = yaml.load(text, Loader=yaml.BaseLoader)
    if not isinstance(d, dict) or set(d) - {"name", "on", "permissions", "jobs"}:
        return ["top-level keys beyond name/on/permissions/jobs: %s" % (sorted(set(d) - {"name", "on", "permissions", "jobs"}) if isinstance(d, dict) else d)]
    on = d.get("on")
    call = on.get("workflow_call") if isinstance(on, dict) else None
    mode_input = {"type": "string", "default": "release"}
    want_call = ({"inputs": {"hostile": {"type": "boolean", "default": "false"}, "mode": mode_input}, "outputs": {"digests": {"value": STAGE_OUTPUT}}}
                 if family == "build" else {"inputs": {"mode": mode_input}, "outputs": {"records": {"value": RECORDS_STAGE_OUTPUT}}})
    if isinstance(call, dict):       # a description is free text
        call = {k: {n: ({a: b for a, b in v.items() if a != "description"} if isinstance(v, dict) else v) for n, v in call[k].items()}
                if isinstance(call[k], dict) else call[k] for k in call}
    if not isinstance(on, dict) or set(on) != {"workflow_call"} or (call or None) != want_call:
        bad.append("on: must be exactly workflow_call with %s, got %s"
                   % ("the inputs hostile (boolean, default false; the dry run's hostile Build step) and mode (string, default release; release or snapshot) "
                      "and the one output digests = %s" % STAGE_OUTPUT
                      if family == "build" else "the one input mode (string, default release; release or snapshot) and the one output records = %s" % RECORDS_STAGE_OUTPUT, on))
    if d.get("permissions") != {"contents": "read"}:
        bad.append("workflow permissions must be exactly contents: read, got %s" % d.get("permissions"))
    if re.search(r"\bwitness\s+run\b", text): bad.append("the stage file names `witness run` directly (every stage goes through bin/witnessed-local.sh)")
    jobs = d.get("jobs") or {}
    names = ("rapk", "rapk-arm", "assemble") if family == "rebuild" else ("apk", "assemble")
    if set(jobs) != set(names):
        return bad + ["exactly the jobs %s required (one stage = one file = one identity), found %s" % (" and ".join(names), sorted(jobs))]
    allowed = None
    if allowed_path:
        try:
            allowed = set(json.load(open(allowed_path)).get("actions", []))
        except (OSError, ValueError):
            bad.append("the allowed-actions list %s is unreadable (fail closed)" % allowed_path)
    for name in names:
        bad += ["%s: %s" % (name, m) for m in job(jobs[name], family, name, allowed)]
    return bad


def pinned(uses, prefix, allowed):
    u = (uses or "").split(" ")[0]
    if not u.startswith(prefix + "@") or not PIN.match(u):
        return False
    return allowed is None or u in allowed


def job(j, family, name, allowed):
    spec = JOBS[(family, name)]
    bad = []
    keys = {"runs-on", "permissions", "steps", "timeout-minutes"} | ({"strategy"} if spec["matrix"] else (set() if spec.get("runner") else {"needs"}))
    if spec.get("expose") or spec.get("expose_records") or spec.get("expose_rapk"): keys.add("outputs")
    if set(j) - keys:
        bad.append("job keys outside the allowlist: %s" % sorted(set(j) - keys))
    if {"runs-on", "permissions", "steps"} - set(j):
        bad.append("job lacks %s" % sorted({"runs-on", "permissions", "steps"} - set(j)))
    for k in ("container", "services", "env", "defaults", "environment", "outputs", "if", "continue-on-error", "uses", "secrets"):
        if k in j and not (k == "outputs" and (spec.get("expose") or spec.get("expose_records") or spec.get("expose_rapk"))): bad.append("job has %s" % k)
    if spec.get("expose") and j.get("outputs") != {"digests": JOB_OUTPUT}:
        bad.append("the assemble job must expose exactly outputs: digests: %s, got %s" % (JOB_OUTPUT, j.get("outputs")))
    if spec.get("expose_records") and j.get("outputs") != {"records": RECORDS_JOB_OUTPUT}:
        bad.append("the Rebuild assemble job must expose exactly outputs: records: %s, got %s" % (RECORDS_JOB_OUTPUT, j.get("outputs")))
    if spec.get("expose_rapk") and j.get("outputs") != {"records": RECORDS_JOB_OUTPUT}:
        bad.append("the Rebuild apk job must expose exactly outputs: records: %s, got %s" % (RECORDS_JOB_OUTPUT, j.get("outputs")))
    if spec.get("runner"):
        if j.get("runs-on") != spec["runner"]: bad.append("this Rebuild apk job must run directly on %s (a native runner, no matrix), got %r" % (spec["runner"], j.get("runs-on")))
    elif spec["matrix"]:
        st = j.get("strategy") or {}
        if j.get("runs-on") != MAT:
            bad.append("the apk job must run on matrix.runner, got %r" % j.get("runs-on"))
        runners = sorted(((st.get("matrix") or {}).get("runner")) or [])
        if set(st) - {"matrix", "fail-fast"} or set(st.get("matrix") or {}) != {"runner"} or runners != sorted(r for r, a in RUNNERS):
            bad.append("strategy must be exactly matrix.runner: both of %s (native runners, no emulation, no include/exclude)" % [r for r, a in RUNNERS])
    else:
        if j.get("runs-on") != "ubuntu-24.04": bad.append("the assemble job must run directly on the ubuntu-24.04 VM (rule 62), got %r" % j.get("runs-on"))
        if family == "rebuild":
            if sorted(j.get("needs") or []) != ["rapk", "rapk-arm"] or not isinstance(j.get("needs"), list): bad.append("assemble must need exactly rapk and rapk-arm, got %s" % j.get("needs"))
        elif j.get("needs") not in ("apk", ["apk"]): bad.append("assemble must need exactly apk, got %s" % j.get("needs"))
    if j.get("permissions") != spec["perm"]:
        bad.append("permissions must be exactly %s, got %s" % (spec["perm"], j.get("permissions")))
    steps = j.get("steps") or []
    if len(steps) < 3: return bad + ["fewer than three steps"]
    if allowed is not None:
        for s_ in steps:
            u_ = (s_.get("uses") or "").split(" ")[0]
            if PIN.match(u_) and u_ not in allowed: bad.append("action %s is not on the allowed-actions list" % u_)
    if spec.get("gh"):       # the admission job: the advisor's reading of rule 51 (admission is the first TRUST decision), made a test
        first_wit = next((k for k, x in enumerate(steps) if "witnessed-local.sh" in str(x.get("run", ""))), len(steps))
        if first_wit < len(steps) and (steps[first_wit].get("if") != MODE_RELEASE_IF or "witnessed-local.sh apk " not in str(steps[first_wit].get("run", ""))):
            bad.append("the first step that runs bin/witnessed-local.sh must be the release admission step `bash bin/witnessed-local.sh apk ...` under if: %s; another Witness "
                       "step before it runs before admission" % MODE_RELEASE_IF)
        for k, x in enumerate(steps[:first_wit]):
            run_ = str(x.get("run", "")).strip()
            kind = ("checkout" if k == 0 and set(x) <= {"uses", "with", "name"} and pinned(x.get("uses"), "actions/checkout", allowed) and (x.get("with") or {}) == CHECKOUT_WITH
                    else "guard" if set(x) == {"name", "env", "run"} and x.get("env") == MODE_GUARD_ENV and run_ == MODE_GUARD_RUN
                    else "install" if set(x) <= {"name", "run"} and run_ in PRE_INSTALLS else None)
            if kind is None:
                bad.append("step %d runs before admission (the first step that runs bin/witnessed-local.sh) and is not the checkout, the mode guard or a checksum-pinned "
                           "install line: %s (nothing with an env, a token, a secret, a build command, a download or an upload may come before admission)"
                           % (k + 1, sorted(x)))
    i = 0
    s = steps[i]; i += 1
    if set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/checkout", allowed) or (s.get("with") or {}) != CHECKOUT_WITH:
        bad.append("step 1 must be a digest-pinned actions/checkout (on the allowed list) with exactly %s" % CHECKOUT_WITH)
    if spec.get("mode"):         # a mode that is neither release nor snapshot would skip both Witness steps and upload nothing, green: refuse it first
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) != {"name", "env", "run"} or s.get("env") != MODE_GUARD_ENV or str(s.get("run") or "").strip() != MODE_GUARD_RUN:
            bad.append("step %d must be exactly env %s, run: %s, and no if (the mode guard)" % (i, MODE_GUARD_ENV, MODE_GUARD_RUN))
    s = steps[i] if i < len(steps) else {}; i += 1
    if set(s) - {"run", "name"} or str(s.get("run") or "").strip() != "bash bin/install-scanner.sh witness":
        bad.append("step 2 must be exactly: run bash bin/install-scanner.sh witness (checksum-pinned Witness install, FIRST)")
    if spec.get("setup_go"):
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"run", "name"} or str(s.get("run") or "").strip() != INSTALL_GO:
            bad.append("step %d must be exactly: run %s (the checksum-pinned Go toolchain of admission's verify-freeze, right after Witness)" % (i, INSTALL_GO))
    for cmd in spec["tools"]:       # an apk job installs melange only, an assemble job apko only (advisor Oct 12, item 4)
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"run", "name"} or str(s.get("run") or "").strip() != cmd:
            bad.append("step %d must be exactly: run %s (the checksum-pinned build tool this job uses and no other, right after the Witness and Go installs, before admission; no env, no secret)" % (i, cmd))
    for cmd in (INSTALL_CRANE, ARCHIVE_PULL) + ((INSTALL_HOSTTOOLS,) if spec.get("hosttools") else ()):       # REQ-CHAIN-004-AC16: the pinned crane, then the archive pull (AC17: and in an apk job the host tools out of it), each a step of a name and a run and nothing else
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"run", "name"} or str(s.get("run") or "").strip() != cmd:
            bad.append("step %d must be exactly: run %s (REQ-CHAIN-004-AC16: the archive is pulled by its committed digest right after the build tools of "
                       "bin/install-build-tools.sh and before the downloads; no env, no if, no continue-on-error, no other argument, no other install)" % (i, cmd))
    for nm, path_ in spec["down"]:
        s = steps[i] if i < len(steps) else {}; i += 1
        if (set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/download-artifact", allowed)
                or (s.get("with") or {}) != {"name": nm, "path": path_}):
            bad.append("step %d must be a pinned actions/download-artifact with exactly name %s and path %s "
                       "(a fresh named directory, never . or bin/ or .github/)" % (i, nm, path_))
    if spec.get("check_rapk"):       # A1: what assemble downloaded of each rapk record is what that rapk job uploaded (release mode only), checked before anything is built
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"name", "if", "env", "run"} or s.get("if") != MODE_RELEASE_IF or s.get("env") != RAPK_CHECK_ENV or str(s.get("run") or "").strip() != RAPK_CHECK_RUN:
            bad.append("step %d must be exactly if: %s, env %s, run: %s (the rapk records are checked against their jobs' outputs before the Witness step)" % (i, MODE_RELEASE_IF, RAPK_CHECK_ENV, RAPK_CHECK_RUN))
    s = steps[i] if i < len(steps) else {}; i += 1
    want_keys = {"run", "name"} | ({"env"} if spec["gh"] else set()) | ({"if"} if spec.get("mode") else set())
    if set(s) - want_keys: bad.append("the Witness step may carry only %s (no shell, working-directory)" % sorted(want_keys))
    if spec.get("mode") and s.get("if") != MODE_RELEASE_IF:
        bad.append("the release Witness step must carry exactly if: %s" % MODE_RELEASE_IF)
    if spec["gh"] and s.get("env") != {"GH_TOKEN": "${{ github.token }}"}:
        bad.append("the admission job's Witness step must carry env exactly GH_TOKEN: ${{ github.token }} (PROPOSED, advisor-confirmed default)")
    if not spec["gh"] and "env" in s: bad.append("the Witness step has env")
    bad += witness_seam(s.get("run") or "", spec, family)
    if spec.get("mode"):         # the snapshot Witness step: its own closed step name and script, no GH_TOKEN (nothing is admitted), gated by the mode
        s = steps[i] if i < len(steps) else {}; i += 1
        snap = dict(spec, step=SNAPSHOT_STEP[spec["step"]], kind="snapshot-" + spec["kind"])
        if set(s) - {"run", "name", "if"} or s.get("if") != MODE_SNAPSHOT_IF:
            bad.append("step %d (the snapshot Witness step) may carry only name, run and if: %s" % (i, MODE_SNAPSHOT_IF))
        bad += witness_seam(s.get("run") or "", snap, family)
    if spec.get("expose"):
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"id", "name", "run"} or s.get("id") != "digests" or str(s.get("run") or "").strip() != EXPOSE:
            bad.append("step %d must be exactly id: digests, run: %s (the stage output is the digests.json text, compact)" % (i, EXPOSE))
    if spec.get("expose_rapk"):
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"id", "name", "if", "run"} or s.get("id") != "records" or s.get("if") != MODE_RELEASE_IF or str(s.get("run") or "").strip() != exposerapk(spec["runner"]):
            bad.append("step %d must be exactly id: records, if: %s, run: %s (the record digests of this apk job, a job output, release mode only)" % (i, MODE_RELEASE_IF, exposerapk(spec["runner"])))
    if spec.get("expose_records"):
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"id", "name", "if", "run"} or s.get("id") != "records" or s.get("if") != MODE_RELEASE_IF or str(s.get("run") or "").strip() != EXPOSE_RECORDS:
            bad.append("step %d must be exactly id: records, if: %s, run: %s (the stage output is the record digests Sign checks, release mode only)" % (i, MODE_RELEASE_IF, EXPOSE_RECORDS))
    if spec.get("hostile"):       # PR 1's static contract (bin/chain-hostile-test.sh): the dry run's hostile Build step, then its upload
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"name", "if", "run"} or s.get("if") != HOSTILE_IF or str(s.get("run") or "").strip() != HOSTILE_RUN:
            bad.append("step %d must be exactly if: %s, run: %s (the dry run's hostile Build step; never in a release)" % (i, HOSTILE_IF, HOSTILE_RUN))
        s = steps[i] if i < len(steps) else {}; i += 1
        if (set(s) - {"name", "if", "uses", "with"} or s.get("if") != HOSTILE_IF
                or not pinned(s.get("uses"), "actions/upload-artifact", allowed) or (s.get("with") or {}) != HOSTILE_UP):
            bad.append("step %d must be a pinned actions/upload-artifact of %s under if: %s" % (i, HOSTILE_UP, HOSTILE_IF))
    for nm, path_ in spec["up"]:
        s = steps[i] if i < len(steps) else {}; i += 1
        want_if = ALWAYS if nm == VERDICT_ARTIFACT else (ADMISSION_IF if nm == "admission" else BASELINE_IF if nm == "admission-baseline" else None)      # the verdict is uploaded even when the comparison failed: it is the only place the differences are readable
        if (set(s) - {"uses", "with", "name", "if"} or s.get("if") != want_if or not pinned(s.get("uses"), "actions/upload-artifact", allowed)
                or (s.get("with") or {}) != {"name": nm, "path": path_}):
            bad.append("step %d must be a pinned actions/upload-artifact with exactly name %s and the ONE path %s%s "
                       "(the artifact is rooted at its common ancestor, so a second path changes every file name in it)"
                       % (i, nm, path_, " under if: %s" % want_if if want_if else " and no if"))
    if i != len(steps):
        bad.append("%d steps, the grammar has %d (no extra step)" % (len(steps), i))
    return bad


# ---- THE RULE 68 SEAM (three functions) -----------------------------------------------------------------------------------------------
STEPS = ("apk", "build", "rapk", "rebuild",
         "snapshot-apk", "snapshot-build", "snapshot-rapk", "snapshot-rebuild",
         "scanners", "acceptance", "runtime", "arm64",
         "release-verify", "release-apks", "release-publish", "release-sign", "release-assets", "release-postverify")      # the closed list (PR 3 adds Check's three steps, PR 4 the six of Release); the record is witness-DIR/STEP-collection.json
# (DIR is STEP without a leading snapshot-, so a snapshot job uploads the same directories as a release job; the file name carries the snapshot marker)
# The identity token reaches Witness through a one-read process substitution, so no file holds it while the wrapped command runs (Witness loads its
# signer before it runs the command: in-toto-witness cmd/run.go:51). SOURCE-CHECKED, one read: in-toto-witness cmd/keyloader.go:85 and
# go-witness signer/fulcio/fulcio.go:295-300 read the path with a single os.ReadFile. DOCUMENTED FALLBACK if that ever changes: write the token to a file
# and delete it before
# the command starts, which is not possible with `exec witness run`, so the fallback is the older file form (a token file under $RUNNER_TEMP):
#   curl ... -o "$RUNNER_TEMP/tok.json"; jq -r .value "$RUNNER_TEMP/tok.json" > "$RUNNER_TEMP/tok"; echo "::add-mask::$(cat "$RUNNER_TEMP/tok")"
#   with --signer-fulcio-token-path "$RUNNER_TEMP/tok". Changing to it changes only TOKEN and TOKEN_PATH below.
OIDC_TOKEN = [
    "oidc_token() {",
    '  sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" '
    '"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value',
    "}",
]
TOKEN = OIDC_TOKEN + [
    "tok=$(oidc_token)",
    'echo "::add-mask::$tok"',
]
# the one extra token the step release-sign alone holds (advisor ruling, Oct 12; REQ-CHAIN-007-AC15): fetched with audience sigstore, masked, exported as
# SIGSTORE_ID_TOKEN; a failed or empty fetch stops the helper before anything runs
SIGTOK = [
    "unset SIGSTORE_ID_TOKEN",
    'if [ "$step" = release-sign ]; then',
    "  sig=$(oidc_token)",
    '  [ -n "$sig" ] && [ "$sig" != null ] || { echo "witnessed: no identity token for release-sign" >&2; exit 1; }',
    '  echo "::add-mask::$sig"',
    '  export SIGSTORE_ID_TOKEN="$sig"',
    "fi",
]
TOKEN_PATH = '<(printf %s "$tok")'
SENSITIVE = ["ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "APK_RELEASE_SIGNING_KEY", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "SIGSTORE_ID_TOKEN"]   # never github (raw OIDC token) or slsa (Sign's alone)


def witnessed_lines():
    """The exact lines of bin/witnessed.sh (backslash continuations are joined before comparing: the committed file may break the long line)."""
    keys = " ".join("--env-add-sensitive-key %s" % ("'%s'" % k if "*" in k else k) for k in SENSITIVE)
    return ["set -euo pipefail", 'step="$1"', "shift",
            'case "$step" in release-verify|release-apks|release-publish|release-sign|release-assets|release-postverify) ;; '
            '*) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac',
            'mkdir -p "witness-${step#snapshot-}"'] + TOKEN + SIGTOK + [
            "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL",
            "unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL",
            'exec witness run --step "$step" --signer-fulcio-url https://fulcio.sigstore.dev '
            "--signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com --signer-fulcio-oidc-client-id sigstore "
            "--signer-fulcio-token-path %s -t https://timestamp.sigstore.dev/api/v1/timestamp "
            "-a environment,git,material,product --env-filter-sensitive-vars %s "
            '-o "witness-${step#snapshot-}/$step-collection.json" -- timeout -k 20 540 bash "$@"' % (TOKEN_PATH, keys)]


LOCAL_STEPS = "apk|build|rapk|rebuild|snapshot-apk|snapshot-build|snapshot-rapk|snapshot-rebuild|scanners|acceptance|runtime|arm64"


def local_lines():
    """The exact lines of bin/witnessed-local.sh (owner Oct 22 2026, ops/docs/ratify/2026-10-22-witness-signed-outside-build.md, option 1): the building steps record under Witness
    with a throwaway ed25519 key made in the job and destroyed before it ends; no identity token, no Fulcio, no timestamp. Sign re-signs the payload keyless. Key hygiene, not the
    trust boundary: the record carries no trust until Sign has checked its product digests (backslash continuations are joined before comparing)."""
    keys = " ".join("--env-add-sensitive-key %s" % ("'%s'" % k if "*" in k else k) for k in SENSITIVE)
    return ["set -euo pipefail", 'step="$1"', "shift",
            'case "$step" in', "  %s) ;;" % LOCAL_STEPS, '  *) echo "witnessed-local: unknown step $step" >&2; exit 2 ;;', "esac",
            'mkdir -p "witness-${step#snapshot-}"',
            "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL SIGSTORE_ID_TOKEN",
            "umask 077",
            'kd=$(mktemp -d "${RUNNER_TEMP:?}/witness-key.XXXXXX")',
            "trap 'rm -rf \"$kd\"' EXIT HUP INT TERM",
            'openssl genpkey -algorithm ed25519 -out "$kd/key.pem"',
            "rc=0",
            'witness run --step "$step" --signer-file-key-path "$kd/key.pem" -a environment,git,material,product --env-filter-sensitive-vars %s '
            '-o "witness-${step#snapshot-}/$step-collection.local.json" -- timeout -k 20 540 bash "$@" || rc=$?' % keys,
            'rm -rf "$kd"',
            '[ ! -e "$kd" ] || { echo "witnessed-local: the throwaway key directory still exists" >&2; exit 1; }',
            'exit "$rc"']


def localhelper(path):
    """bin/witnessed-local.sh is exactly the canonical local helper: the only place a building step runs Witness."""
    raw = read_exact(path)
    commands, faults = commands_of(raw)
    return ["control character %s in the local helper" % c for c in control_chars(raw)] + faults + compare(commands, local_lines(), "the local helper")


def witness_seam(run, spec, family):
    """1/3: the stage's Witness step is exactly ONE line through the helper, with the step name of its job and the committed script of its kind."""
    want = "bash bin/witnessed-local.sh %s bin/build-stage-%s.sh" % (spec["step"], spec["kind"])
    got = str(run).strip()
    return [] if got == want else ["the Witness step must be exactly the one line `%s`, found %r" % (want, got[:120])]


def helper(path):
    """2/3: bin/witnessed.sh is exactly the canonical helper: the only place the Witness flags and `timeout 540` live."""
    raw = read_exact(path)
    commands, faults = commands_of(raw)
    return ["control character %s in the helper" % c for c in control_chars(raw)] + faults + compare(commands, witnessed_lines(), "the helper")


def directwitness(files):
    """3/3: nothing but the helper runs Witness: no `witness run` in a stage file or a stage script."""
    bad = []
    for f in files:
        try:
            if re.search(r"\bwitness\s+run\b", read_exact(f)): bad.append("%s names `witness run` directly (every stage goes through bin/witnessed.sh)" % f)
        except FileNotFoundError:
            bad.append("missing file: %s" % f)
    return bad


# ---- Build vs Rebuild --------------------------------------------------------------------------------------------------------------
def lockflow(files):
    bad = []
    if len(files) < 2: return ["lockflow needs the Build and Rebuild assemble scripts"]
    asm = []
    for f in files[:2]:
        try:
            asm.append([l for l in commands_of(read_exact(f))[0] if l.startswith("./bin/assemble-image.sh")])
        except FileNotFoundError:
            bad.append("missing file: %s" % f); asm.append([])
    if not bad and (not asm[0] or asm[0] != asm[1]):
        bad.append("Build and Rebuild assemble-image.sh lines are not identical (same script, same arguments, same lock flow): %s vs %s" % (asm[0], asm[1]))
    for f in files[2:]:
        try:
            d = yaml.load(open(f).read(), Loader=yaml.BaseLoader)
        except FileNotFoundError:
            bad.append("missing file: %s" % f); continue
        # the one exception (advisor 0393 item 1; REQ-CHAIN-004-AC11 says so): the pinned installer line `bash bin/install-build-tools.sh apko` as a step of its own (a name and a run, nothing else)
        for j in ((d or {}).get("jobs") or {}).values():
            if isinstance(j, dict) and isinstance(j.get("steps"), list):
                j["steps"] = [s for s in j["steps"] if not (isinstance(s, dict) and set(s) <= {"name", "run"} and str(s.get("run") or "").strip() == INSTALL_APKO)]
        if re.search(r"\bapko\b", json.dumps(d)):
            bad.append("%s: names apko (only bin/assemble-image.sh may run it, always with the lock)" % f)
    return bad


def archive_listed(path, root):
    """REQ-CHAIN-004-AC16: the files the stage's pull step runs are rows of chain-scripts.json with the committed file's sha256."""
    bad = []
    try:
        rows = {r.get("path"): r for r in json.load(open(path)).get("scripts", [])}
    except (OSError, ValueError):
        return ["%s is unreadable" % path]
    for p in ARCHIVE_SCRIPTS:
        r = rows.get(p)
        if r is None: bad.append("%s is not a row of chain-scripts.json" % p); continue
        try:
            h = hashlib.sha256(open(root + "/" + p, "rb").read()).hexdigest()
        except OSError:
            bad.append("%s is listed but missing" % p); continue
        if r.get("sha256") != h: bad.append("%s: the listed sha256 is not the committed file's" % p)
    return bad


def listed(path, root):
    bad = []
    try:
        rows = {r.get("path"): r for r in json.load(open(path)).get("scripts", [])}
    except (OSError, ValueError):
        return ["%s is unreadable" % path]
    for k, p in SCRIPTS.items():
        r = rows.get(p)
        if r is None: bad.append("%s is not a row of chain-scripts.json" % p); continue
        try:
            h = hashlib.sha256(open(root + "/" + p, "rb").read()).hexdigest()
        except OSError:
            bad.append("%s is listed but missing" % p); continue
        if r.get("sha256") != h: bad.append("%s: the listed sha256 is not the committed script's" % p)
    return bad


# ---- nosource: the build is the only step that runs source code (sandboxed-build ratify, Oct 27 2026, rule 1) ------------------------
# In Build and Rebuild the compile of our source and of its dependencies happens only inside melange's sandbox (bin/build-apk.sh); apko only lays packages down. This judge reads every
# script the four stage scripts (and bin/witnessed-local.sh) can start and applies an ALLOW-LIST, and it refuses what it cannot read:
#   shell: a command word is accepted only when it is a shell keyword or builtin, an ordinary file utility (NS_UTILS, with the options that start programs refused), a repository
#   script of the closure, a program in the script's own NS_EXTRA row, or a variable in its NS_VARS row. Wrappers (timeout, nice, command, time, exec, env, sudo, unshare) are looked
#   through; substitutions are read wherever they stand (also inside double quotes, ${...}, array assignments, [[ ... ]] and process substitutions); a command word the judge cannot
#   resolve (computed, globbed, or built from an expansion) is a finding, as are eval, alias, xargs, `trap --`, find -exec, awk system() and an interpreter run with -c. For an interpreter
#   the file it runs is the first non-option word and must be a script of the closure. The Go toolchain is accepted only as `version`.
#   Python: every call that starts a program is judged by its first argument (a list literal, or a name assigned one earlier); the program must be on the script's own NS_PYPROGS row,
#   the interpreter or Go `version`; executable=, exec(), eval(), a name bound to a program-starting function, and a command line that is not a list are findings.
# Which scripts are read: the `runs` rows of chain-scripts.json, every bin/ script the code names, and every sibling module a closure script loads (load_sibling, import).
# bin/install-scanner.sh and bin/install-build-tools.sh are not read. The stage files pin which installs run (PRE_INSTALLS: witness, go, crane, melange, apko), and the compile branch
# of install-scanner.sh (govulncheck) is not one of them; install-build-tools.sh downloads checksum-pinned release binaries and compiles nothing (read at the source, Oct 28 2026).
# One more run of install-scanner.sh is not a stage-file install: bin/build-admit.py:217 runs `bash <policy folder>/install-scanner.sh gitsign`. That copy is origin/main's: check_policy_from_main
# runs `git fetch --no-tags origin main` and writes `git show origin/main:bin/install-scanner.sh` into the job's policy folder, so the tagged tree's own file is never run there. Main's copy is
# not pinned by a hash; origin/main itself is the pin, and what runs is whatever main holds when the admission step fetches it.
# THE ONE KNOWN FINDING on the real tree: bin/build-admit.py:456 runs `go -C tools/requirements run . verify-freeze` of the tagged tree. It is reported as a finding (rule 1 forbids it);
# the decision is its own job before Build in stage-build.yml, in its own pull request. Until that lands rule 1 is NOT done.
NS_ROOTS = ("bin/build-stage-*.sh", "bin/witnessed-local.sh")
NS_SKIP = ("bin/install-scanner.sh", "bin/install-build-tools.sh")
NS_KEYWORDS = frozenset("if then else elif fi while until do done esac in time ! { } ]]".split())
NS_UTILS = frozenset("rmdir awk basename cat chmod cmp cp cut date diff dirname find grep head ln ls mkdir mktemp mv rm readlink realpath sed sort tail tee touch tr uname wc id sleep sha256sum jq tar gzip gunzip curl".split())
NS_WRAPPERS = frozenset("sudo env timeout nice ionice nohup setsid stdbuf command exec unshare builtin".split())
NS_INTERP = frozenset("bash sh dash zsh ksh python python3 perl ruby node".split())
NS_NEVER = frozenset("eval alias xargs source . make cargo npm npx yarn pnpm gcc cc clang rustc javac mvn gradle pip pip3 cmake ninja".split())
NS_EXTRA = {      # per script: reviewed extra command words (programs the script really starts; every entry is read at the source)
    "bin/build-apk.sh": ("git", "grep", "sysctl"),      # sysctl: the sudo call that relaxes the unprivileged-namespace restriction of Ubuntu runners (rule 62)
    "bin/witnessed-local.sh": ("witness", "openssl"),
    "bin/build-stage-snapshot-apk.sh": ("git",), "bin/build-stage-snapshot-rebuild-apk.sh": ("git",),
}
NS_VAR_LINES = {       # per script: variables that may stand in command position, each bound to its ONE assignment (the fixed tool locations of REQ-BUILDAPK-001-AC3; each is one TEST-SUBST constant)
    "bin/build-apk.sh": {"PY3": "PY3=/usr/bin/python3", "GIT": "GIT=/usr/bin/git", "SUDO": "SUDO=/usr/bin/sudo", "UNSHARE": "UNSHARE=/usr/bin/unshare", "MELANGE": "MELANGE=/usr/local/bin/melange",
                         "GO_TOOL": "GO_TOOL=/usr/local/bin/fscache-go/bin/go", "SHA256SUM": "SHA256SUM=/usr/bin/sha256sum", "ENVBIN": "ENVBIN=/usr/bin/env", "melange_bin": "melange_bin=$MELANGE",
                         "call": 'call=("$ENVBIN" -i "${sealed[@]}" "$UNSHARE" -n "$melange_bin" "${margs[@]}")'},      # call: the array the sealed-call checker judged
    "bin/assemble-image.sh": {"PY3": "PY3=/usr/bin/python3", "SUDO": "SUDO=/usr/bin/sudo", "UNSHARE": "UNSHARE=/usr/bin/unshare", "BASHBIN": "BASHBIN=/bin/bash", "APKO": "APKO=/usr/local/bin/apko", "ENVBIN": "ENVBIN=/usr/bin/env"},
    "bin/apko-lock.sh": {"PY3": "PY3=/usr/bin/python3"},
}
NS_VARS = {p: tuple(v) for p, v in NS_VAR_LINES.items()}
NS_INTERP_VARS = ("PY3", "BASHBIN")      # variables that stand for an interpreter: the interpreter rules apply to them
NS_ENGINE = {"melange": ("bin/build-apk.sh",), "apko": ("bin/assemble-image.sh", "bin/apko-lock.sh")}
NS_ENGINE_VARS = {"MELANGE": "melange", "melange_bin": "melange", "APKO": "apko"}
NS_PYPROGS = {    # per Python script: the programs it may start by name (the interpreter and Go `version` are judged by their own rules)
    "bin/admission-tag-signer.py": ("git",), "bin/apk-tool.py": ("openssl",), "bin/chain-bytes-sha.py": ("git",), "bin/chain-verify.py": ("cosign",),
    "bin/build-admit.py": ("bash", "git", "gh", "gitsign", "gpg", "gpgconf", "openssl", "python3"),
    "bin/chain_common.py": ("openssl",),
}
NS_PYVARS = {"bin/chain_common.py": {"OPENSSL": ("openssl", 'os.environ.get("OPENSSL", "openssl")')}}      # a module constant that names the program, bound to its ONE assignment (documented in chain-verify.py; no workflow or stage script sets it)
NS_PYEXEC = {"bin/chain-verify.py": ("load_sibling", 'exec(compile(src, mod.__file__, "exec"), mod.__dict__)')}      # the ONE exec(): in the loader that checks a sibling module's sha256 against chain-scripts.json first; the siblings are in the closure and read here
NS_PYCOMPUTED = {"bin/build-admit.py": (      # (function, interpreter, the file operand, its one assignment): the copies of origin/main's scripts in the job's policy folder, never the tagged tree
    ("route_tag", "python3", "os.path.join(ctx.policy, os.path.basename(SIGNER))", None),
    ("verify_tag_keyless", "bash", "os.path.join(ctx.policy, os.path.basename(INSTALLER))", None),
    ("patch_baseline_version", "python3", "script", "os.path.join(ctx.policy, os.path.basename(SIGNER))"),
    ("check_rc_proof", "python3", "script_path", "os.path.join(ctx.policy, os.path.basename(RC_BYTES))"))}
NS_PYWRAP = {"bin/build-admit.py": ("run_cmd",)}        # reviewed wrappers whose parameter is an argument list; their callers' list literals are judged
NS_PYFUNCS = {"bin/apk-tool.py": {"_openssl": "openssl"}}      # reviewed helpers that return one fixed program
NS_START_MODULES = ("subprocess", "os", "pty", "asyncio")      # the modules whose calls start a program
NS_START_ONLY = re.compile(r"^(Popen|check_output|check_call|system|popen\w*|spawn\w*|posix_spawn\w*|exec\w*|getoutput|getstatusoutput|startfile|forkpty)$")      # names that start a program on any owner


def ns_start_calls():
    """The call names that start a program or load code by name: the PY_START_CALLS line of chain-check-shape.py, read at the source (None when it cannot be read)."""
    import ast
    try:
        tree = ast.parse(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "chain-check-shape.py")).read())
    except (OSError, SyntaxError):
        return None
    for n in tree.body:
        if isinstance(n, ast.Assign) and any(getattr(x, "id", "") == "PY_START_CALLS" for x in n.targets) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            return re.compile(n.value.value)
    return None


def ns_closure(root):
    import glob
    try:
        rows = {r.get("path"): r for r in json.load(open(root + "/.github/policy/chain-scripts.json")).get("scripts", [])}
    except (OSError, ValueError):
        return None, ["chain-scripts.json is unreadable"]
    todo = [os.path.relpath(f, root) for g in NS_ROOTS for f in sorted(glob.glob(root + "/" + g))]
    seen, bad = [], []
    while todo:
        p = todo.pop()
        if p in seen or p in NS_SKIP:
            continue
        seen.append(p)
        if p not in rows:
            bad.append("%s is started by a stage script but is not a row of chain-scripts.json" % p)
            continue
        todo += rows[p].get("runs", [])
        try:
            text = open(root + "/" + p).read()
        except OSError:
            continue
        for n in ns_named(p, text):      # a script a code word or string constant names, or a sibling module it loads, is read too even when no `runs` row lists it
            if n != p and os.path.isfile(root + "/" + n):
                todo.append(n)
    return sorted(seen), bad


def ns_named(path, text):
    """The repository files a script's CODE names: shell words and Python string constants that are exactly bin/NAME.sh|py; for Python also load_sibling("NAME") and `import NAME`
    (the candidate bin/NAME.py is kept when it exists). Comments, docstrings and tests are not references."""
    pat = re.compile(r"(?:\./)?(bin/[A-Za-z0-9_][A-Za-z0-9_.-]*)")
    names = set()
    if path.endswith(".py"):
        import ast
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return []
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and pat.fullmatch(n.value): names.add(pat.fullmatch(n.value).group(1))
            elif isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "load_sibling" and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                names.add("bin/%s.py" % n.args[0].value)
            elif isinstance(n, ast.Import):
                for x in n.names: names.add("bin/%s.py" % x.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                names.add("bin/%s.py" % n.module.split(".")[0])
    else:
        for cmd in ns_commands(text):
            for w in cmd:
                for m in pat.finditer(w):
                    if re.fullmatch(r"(?:.*[\s=/\"'])?(?:\./)?bin/[A-Za-z0-9_][A-Za-z0-9_.-]*", w): names.add(m.group(1))
    return sorted(names)


def ns_find_subs(text):
    """The inner text of every $(...), <(...), >(...) and backtick substitution in a raw string (balanced, nested ones are found when that text is read again)."""
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c == "`":
            j = text.find("`", i + 1)
            j = len(text) if j < 0 else j
            out.append(text[i + 1:j]); i = j + 1; continue
        if text.startswith("$((", i):
            d, j = 0, i + 2
            while j < len(text):
                if text[j] == "(": d += 1
                elif text[j] == ")":
                    d -= 1
                    if d == 0: break
                j += 1
            inner = text[i + 3:j]
            out += ns_find_subs(inner)      # arithmetic holds no command of its own; a substitution inside it does
            i = j + 1; continue
        if (text[i:i + 2] in ("$(", "<(", ">(")):
            d, j = 0, i + 1
            while j < len(text):
                if text[j] == "(": d += 1
                elif text[j] == ")":
                    d -= 1
                    if d == 0: break
                j += 1
            out.append(text[i + 2:j]); i = j + 1; continue
        i += 1
    return out


NS_CASEPAT = re.compile(r"^\s*\(?[^\s()=;&'\"$]*(?:\|[^\s()=;&'\"$]*)*\)[ \t]*")      # `-rc*)`, `a|b)`, `*)`: the pattern in front of a case branch is not a command


def ns_sub_end(s, i):
    """The index of the `)` that closes the `$(` at s[i], the way a shell reads it: a parenthesis in single or double quotes does not count, and a `$(` inside double quotes is a
    substitution of its own. -1 when it does not close on this line."""
    d, j, q = 0, i + 1, None
    while j < len(s):
        c = s[j]
        if q == "'":
            if c == "'": q = None
        elif c == "\\": j += 1
        elif q == '"':
            if c == '"': q = None
            elif s.startswith("$(", j):
                j = ns_sub_end(s, j)
                if j < 0: return -1
        elif c in "'\"": q = c
        elif s.startswith("$(", j) and j > i + 1:
            j = ns_sub_end(s, j)
            if j < 0: return -1
        elif c == "(": d += 1
        elif c == ")":
            d -= 1
            if d == 0: return j
        j += 1
    return -1


def ns_join_arrays(text):
    """An array assignment `NAME=(` that runs over several lines is joined into one line (its closing parenthesis ends it), so its continuation lines are not read as commands."""
    lines, out, k = text.split("\n"), [], 0
    while k < len(lines):
        ln = lines[k]; k += 1
        code = ns_bare_code(ln)
        while re.search(r"(?<![\w$])[A-Za-z_]\w*\+?=\(", code) and code.count("(") > code.count(")") and k < len(lines):
            ln += " " + lines[k].strip(); k += 1
            code = ns_bare_code(ln)
        out.append(ln)
    return "\n".join(out)


def ns_commands(text, depth=0):
    """The simple commands of a shell text, each a list of unquoted words: quote-aware; split at ; & | ( ) { } and newlines; redirections dropped; ${...}, array assignments, [[ ... ]] and
    quotes stay inside their words, but the text of every substitution in them (also <( ) and >( )) is read as commands of its own; comments dropped. Not a shell parser: a judge's
    reading, with the over-reporting that comes with it. What it cannot place it keeps as a word, and ns_shell refuses a command word it cannot resolve."""
    cmds = []
    if depth > 6:
        return [["<too-deeply-nested>"]]
    case_depth = 0      # a pattern `word)` at the start of a line is dropped only inside case ... esac: `make)` closing a subshell is a command
    for ln in ns_join_arrays(text.replace("\\\n", "")).split("\n"):
        code = ns_bare_code(ln).strip()
        why = ("esac does not stand alone on its line" if re.search(r"(?<![\w-])esac(?![\w-])", code) and code != "esac"
               else ";; does not end its line" if code.count(";;") > (1 if code.endswith(";;") else 0)
               else "a case is opened on a line that does not end in `in`" if re.search(r"(?:^|[;&|{(]|\b(?:then|do|else)\b)\s*case\b", code) and not re.search(r"\bcase\s+.+\s+in\s*$", ln) else None)
        if why:
            cmds.append(["<cannot-read: %s>" % why]); continue
        if case_depth:      # inside case ... esac: the arm loses its pattern, and the `;;` that ends the line
            ln = NS_CASEPAT.sub("", ln.rstrip()[:-2] if ln.rstrip().endswith(";;") else ln, count=1)
        if re.search(r"(?:^|[;&|{(]|\b(?:then|do|else)\b)\s*case\s+.+\s+in\s*$", ln): case_depth += 1
        elif code == "esac": case_depth = max(0, case_depth - 1)
        cur, tok, q, started, i, subs = [], "", None, False, 0, []
        while i < len(ln):
            c = ln[i]
            if c == "$" and ln[i + 1:i + 2] == "{" and q != "'":
                j = ln.find("}", i)
                j = len(ln) - 1 if j < 0 else j
                subs += ns_find_subs(ln[i:j + 1])
                if "[" in ln[i:j + 1] and "'" in ln[i:j + 1] and ("$(" in ln[i:j + 1] or "`" in ln[i:j + 1]): cmds.append(["<cannot-read: a substitution inside a quoted subscript of ${...}>"])      # a subscript runs a $( ) even inside single quotes
                tok += ln[i:j + 1]; i = j + 1; started = True
                continue
            if q != "'" and (c == "`" or ln.startswith("$(", i) or (not q and ln[i:i + 2] in ("<(", ">("))):      # a substitution: its text is read as commands of its own
                if c == "`":
                    j = ln.find("`", i + 1); j = len(ln) if j < 0 else j
                    subs.append(ln[i + 1:j]); i = j + 1; started = True; tok += "SUB"
                    continue
                if ln.startswith("$((", i):
                    d, j = 0, i + 2
                    while j < len(ln):
                        if ln[j] == "(": d += 1
                        elif ln[j] == ")":
                            d -= 1
                            if d == 0: break
                        j += 1
                    subs += ns_find_subs(ln[i + 3:j]); i = j + 2; started = True; tok += "ARITH"
                    continue
                d, j = 0, i + 1
                while j < len(ln):
                    if ln[j] == "(": d += 1
                    elif ln[j] == ")":
                        d -= 1
                        if d == 0: break
                    j += 1
                if ns_sub_end(ln, i) != j: cmds.append(["<cannot-read: the end of $( ) is not where the parenthesis count puts it (a quoted parenthesis)>"])      # the count above does not know quotes
                subs.append(ln[i + 2:j]); i = j + 1; started = True; tok += "SUB"
                continue
            if not q and not started and not cur and ln.startswith("[[", i) and ln[i + 2:i + 3] in (" ", "\t"):      # [[ ... ]] is one test: its operators are not commands, its substitutions are
                j = ln.find("]]", i + 2)
                end = len(ln) if j < 0 else j + 2
                subs += ns_find_subs(ln[i:end])
                i = end
                continue
            if not q and c == "(" and re.fullmatch(r"[A-Za-z_]\w*\+?=", tok):      # NAME=(...) / NAME+=(...): an array assignment, one word; substitutions inside are read
                d, j, qq = 0, i, None
                while j < len(ln):
                    ch = ln[j]
                    if qq:
                        if ch == qq: qq = None
                    elif ch in "'\"": qq = ch
                    elif ch == "(": d += 1
                    elif ch == ")":
                        d -= 1
                        if d == 0: break
                    j += 1
                subs += ns_find_subs(ln[i:j + 1])
                tok += ln[i:j + 1]; i = j + 1; started = True
                continue
            if q:
                if c == q: q = None
                elif c == "\\" and q == '"' and i + 1 < len(ln): tok += ln[i + 1]; i += 1
                else: tok += c
                started = True
            elif c in "'\"": q, started = c, True
            elif c == "\\" and i + 1 < len(ln): tok += ln[i + 1]; i += 1; started = True
            elif c == "#" and not started: break
            elif c in "<>":      # a redirection: the operator and its target word are not commands
                if started and tok.isdigit(): tok, started = "", False
                elif started: cur.append(tok); tok, started = "", False
                while i < len(ln) and ln[i] in "<>&|": i += 1
                while i < len(ln) and ln[i] in " \t": i += 1
                qq, j = None, i
                while j < len(ln) and (qq or ln[j] not in " \t;&|(){}"):
                    if qq:
                        if ln[j] == qq: qq = None
                    elif ln[j] in "'\"": qq = ln[j]
                    j += 1
                subs += ns_find_subs(ln[i:j])
                i = j
                continue
            elif c in " \t":
                if started: cur.append(tok)
                tok, started = "", False
            elif c in ";|&(){}":
                if started: cur.append(tok)
                tok, started = "", False
                if cur: cmds.append(cur)
                cur = []
            else: tok += c; started = True
            i += 1
        if started: cur.append(tok)
        if cur: cmds.append(cur)
        if q: cmds.append(["<cannot-read: a quote stays open at the end of a line>"])      # the reader reads line by line; a string over several lines puts it out of step
        for sub in subs: cmds += ns_commands(sub, depth + 1)
    return cmds


def ns_word(w):
    """('var', NAME) for $NAME / ${NAME} / ${NAME[@]}; ('word', basename) for a plain word or path; None for a token that cannot name a program (option, number)."""
    m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)(?:\[[@*0-9]+\])?\}?", w)      # $NAME, ${NAME}, ${NAME[@]}: an array expansion in command position names a program too
    if m: return ("var", m.group(1))
    if w.startswith("-") or re.fullmatch(r"[0-9,]+", w):
        return None
    if w in ("[", "[[", "]", "]]", "!", "{", "}", "(("): return ("word", w)
    if re.fullmatch(r"[A-Za-z_./][A-Za-z0-9_./+@:-]*", w): return ("word", w)
    return ("odd", w)


NS_WHOLE = frozenset("for case select function echo printf set unset export local readonly declare shift return exit break continue true false test read mapfile wait umask cd pwd shopt [ [[ ((".split())      # their other words are data, not programs
NS_UTIL_OPTS = {      # per utility: the option words it may carry (fullmatch). Any other option word is refused: a utility is never given an option that starts a program or reads a program
    "awk": r"-F.*", "basename": r"-s", "cat": r"-n", "chmod": r"-R", "cmp": r"-s", "cp": r"-[Rrpa]+", "cut": r"-[dfc].*", "date": r"-[ud]",
    "diff": r"-[uqr]+", "dirname": r"", "find": r"-(name|type|maxdepth|mindepth|newer|path|print|print0|empty|not|prune|mtime|size|o|a|L|P)",
    "grep": r"-([EFqivxwcnlsoe]+|f)", "gunzip": r"-[cdkf]+", "gzip": r"-[cdknf1-9]+", "head": r"-([nc].*|[0-9]+)", "id": r"-[ugn]+",
    "jq": r"-[rcesnRSj]+|--(arg|argjson|slurpfile|rawfile|raw-output|compact-output|exit-status|slurp|null-input)", "ln": r"-[sTfn]+", "ls": r"-[AlaRdhtr1]+",
    "mkdir": r"-[pm]+", "mktemp": r"-[dtp]+", "mv": r"-[fnT]+", "readlink": r"-[fem]+", "realpath": r"-[em]+", "rm": r"-[rf]+", "rmdir": r"-p", "sed": r"-[nEres]",
    "sha256sum": r"-[cb]+|--(check|quiet|status)", "sleep": r"", "sort": r"-([nruVfbd]+|k.*|t.*)", "tail": r"-([nc].*|[0-9]+)", "tar": r"-?[cxtvfzpCO]+|--(exclude|numeric-owner|sort|owner|group|mtime|format|no-same-owner|strip-components)(=.*)?",
    "tee": r"-a", "touch": r"-[acdtr]+", "tr": r"-[dcs]+", "uname": r"-[smrnpoa]+", "wc": r"-[lcwm]+",
    "curl": r"-[fsSLo]+|--(retry|connect-timeout|max-time|output|fail|silent|show-error|location)(=.*)?",
}
NS_WRAPPER_OPTS = {      # the wrappers look through to a program; their options are refused unless listed (env -S, sudo -s and the like carry a command line)
    "timeout": r"-k|-s|--preserve-status", "sudo": r"-n|-E", "env": r"-i", "nice": r"-n", "ionice": r"-c", "nohup": r"", "setsid": r"-w|-f", "stdbuf": r"-[ioe]L?",
    "command": r"-p", "exec": r"", "unshare": r"-[rmupinUCT]+|--(map-root-user|mount|pid|fork|user|net)", "builtin": r"",
}
NS_AWK_RUNS = re.compile(r"system\s*\(|\|\s*getline|\|&|print[^;}]*\|\s*[\"'$A-Za-z]|printf[^;}]*\|\s*[\"'$A-Za-z]|close\s*\(")
NS_SED_PROG = re.compile(r"s(.)(?:(?!\1).)*\1(?:(?!\1).)*\1[gpI0-9]*", re.S)      # the one sed script the stage scripts use: a single s command (no e flag, no e, w, r or other command)
NS_AWK_EXPAND = re.compile(r"`|\$[A-Za-z_{(]|\bSUB\b")      # an awk program is one literal word: no expansion builds part of it ($2 is a field, $x is the shell, and a substitution reads as the word SUB)


def ns_sed_awk(path, base, rest, bad):
    if base == "sed":
        progs, first, i, e_seen = [], None, 0, False
        while i < len(rest):
            x = rest[i]
            if x == "--": break
            if x.startswith("-") and not x.startswith("--") and "e" in x:
                e_seen = True
                if i + 1 < len(rest): progs.append(rest[i + 1])
                i += 2; continue
            if not x.startswith("-") and first is None: first = x
            i += 1
        if not e_seen and first is not None: progs.append(first)
        if not progs or any(not NS_SED_PROG.fullmatch(x) for x in progs):
            bad.append("%s runs sed with a script that is not one plain s command (the e flag, the e command and every other command are refused)" % path)
    elif base == "awk":
        words, i = [], 0
        while i < len(rest):
            x = rest[i]
            if x == "--": break
            if x == "-F": i += 2; continue
            if not x.startswith("-"): words.append(x)
            i += 1
        prog = words[0] if words else None
        if prog is None or NS_AWK_EXPAND.search(prog) or NS_AWK_RUNS.search(prog):
            bad.append("%s runs awk with a program that is not one literal word, or that starts a command (system(), a pipe or getline from one)" % path)



NS_GIT_SUBS = ("tag", "log", "rev-parse")      # the git calls the stage scripts make (read at the source); `git -c`, --exec-path and --config-env carry a program, so only `-C DIR` may come before the subcommand
NS_VAR_UTILS = {"GIT": "git", "SHA256SUM": "sha256sum"}


def ns_git_check(path, rest, bad):
    i = 0
    if rest[:1] == ["-C"]: i = 2
    if i >= len(rest) or rest[i] not in NS_GIT_SUBS:
        bad.append("%s runs git with %s before a subcommand it may use (%s; only -C DIR may come first)" % (path, rest[i] if i < len(rest) else "nothing", ", ".join(NS_GIT_SUBS)))


def ns_util_opts(path, base, rest, bad):
    if base == "git": return ns_git_check(path, rest, bad)
    for x in rest:
        if x == "--": break
        if x.startswith("-") and x != "-" and not re.fullmatch(NS_UTIL_OPTS.get(base, r".*"), x):
            bad.append("%s runs %s with the option %s, which is not on its list of options" % (path, base, x)); break


NS_INTERP_OPTS = ("-I", "-B")      # the only option words an interpreter takes, and only python: isolated mode and no bytecode files. Neither can run stdin or inline code.


def ns_interp_check(path, base, rest, closure, vars_ok, bad):
    """An interpreter (by name or by a variable that stands for one) takes no option word but the two above; the file it runs is the first word and a script of the closure."""
    python = base.lstrip("$").lower() in ("python", "python3", "py3")
    script = None
    for x in rest:
        if not x.startswith("-"):
            script = x; break
        if not (python and x in NS_INTERP_OPTS):
            bad.append("%s runs %s with the option word %s: an interpreter takes no option (-c, -m, -s and - run inline code or stdin)" % (path, base, x)); return
    if script is None:
        bad.append("%s runs %s on no script file" % (path, base)); return
    clean = script.strip("\"'")
    if re.fullmatch(r"(\./)?bin/[A-Za-z0-9_.-]+", clean):
        if clean.lstrip("./") not in closure: bad.append("%s runs %s, which is not in the closure the judge reads" % (path, clean))
    else:
        bad.append("%s runs %s on %r, which is not a script of the closure" % (path, base, script))


def ns_var_lines(path, text, bad):
    """Every variable that may stand in command position has its bare name (not $NAME or ${NAME}) on ONE line of the file: its reviewed assignment (a trailing comment and a `;` command after it are not part of the line)."""
    lines, codes = text.split("\n"), ns_bare_code(text).replace("${", "$").split("\n")
    for var, want in NS_VAR_LINES.get(path, {}).items():
        hits = [ln.strip() for ln, code in zip(lines, codes) for _ in re.findall(r"(?<![\w$.\-/])%s(?![\w\-])" % re.escape(var), code)]      # a hyphenated word (sealed-call) or a path is not a use of the variable
        ok = [h for h in hits if re.split(r"\s+#", h)[0].strip() == want or re.split(r"\s+#", h)[0].strip().startswith(want + ";")]
        if len(hits) != 1 or len(ok) != 1:
            bad.append("%s: the name %s is written bare %d times, or on a line other than `%s`" % (path, var, len(hits), want))


def ns_bare_code(text):
    """The text without comments and without the inside of quoted strings (each line on its own, as the reader reads it)."""
    out = []
    for ln in text.split("\n"):
        res, q, k = "", None, 0
        while k < len(ln):
            c = ln[k]
            if q:
                if c == q: q = None
                elif c == "\\" and q == '"': k += 1
            elif c in "'\"": q = c
            elif c == "\\": res += " "; k += 1
            elif c == "#" and (not res or res[-1] in " \t;&|("): break
            else: res += c
            k += 1
        out.append(res)
    return "\n".join(out)


def ns_shell(path, text, closure, funcs=None):
    bad = []
    extra = set(NS_EXTRA.get(path, ())); vars_ok = set(NS_VARS.get(path, ()))
    if funcs is None: ns_var_lines(path, text, bad)      # the whole file once (a trap handler or a function body is read again with funcs set)
    funcs = set(funcs or ()) | set(re.findall(r"(?:^|[;&{(\s])(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\)", ns_bare_code(text)))      # shell functions the script defines (found in code only: not in a comment or a string): their bodies are read like everything else
    for cmd in ns_commands(text):
        if cmd and cmd[0].startswith("<cannot-read"):
            bad.append("%s %s (the judge reads line by line and does not guess)" % (path, cmd[0].strip("<>").replace("cannot-read:", "cannot be read:"))); continue
        if cmd and cmd[0] == "trap":      # a trap handler is code: it is read as commands too (`trap -- 'cmd' EXIT` included)
            args = [x for x in cmd[1:] if x != "--" and not (x.startswith("-") and len(x) > 1 and x != "-")]
            if args: bad += ns_shell(path, args[0], closure, funcs)
            continue
        i = 0
        while i < len(cmd) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", cmd[i]): i += 1      # NAME=value words
        while i < len(cmd):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\+?=.*", cmd[i]):      # an assignment word, also after a keyword (`then x=1`)
                i += 1; continue
            w = ns_word(cmd[i])
            if w is None or (w[0] == "word" and "/" in w[1]):
                break
            name = w[1] if w[0] == "var" else w[1].rsplit("/", 1)[-1]
            if w[0] == "word" and name == "mapfile" and any(re.fullmatch(r"-[A-Za-z]*C.*", x) for x in cmd[i + 1:] if x.startswith("-")):
                bad.append("%s runs mapfile with -C, which calls a command" % path)      # readarray is not on NS_WHOLE, so it is refused as a command
            if w[0] == "word" and name in NS_WHOLE:
                i = len(cmd); break
            if w[0] == "word" and name in NS_KEYWORDS:
                i += 1; continue
            if (w[0] == "word" and name in NS_WRAPPERS) or (w[0] == "var" and name in vars_ok and name in ("SUDO", "ENVBIN", "UNSHARE")):      # look through the wrapper to the program it starts
                wrap = name if w[0] == "word" else name.lower()
                i += 1
                while i < len(cmd) and (cmd[i].startswith("-") or re.fullmatch(r"[0-9.]+", cmd[i]) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", cmd[i])):
                    if cmd[i].startswith("-") and cmd[i] != "--" and not re.fullmatch(NS_WRAPPER_OPTS.get(wrap, r""), cmd[i]):
                        bad.append("%s runs %s with the option %s, which is not on its list of options" % (path, wrap, cmd[i])); i = len(cmd); break
                    i += 1
                continue
            break
        if i >= len(cmd): continue
        w = ns_word(cmd[i])
        if w is None:
            bad.append("%s has a command word that starts with - or is only digits: %r (a program with that name is not one the judge knows)" % (path, cmd[i])); continue
        kind, name = w
        if kind == "odd":
            bad.append("%s has a command word the judge cannot resolve: %r (computed, globbed or built from an expansion)" % (path, name)); continue
        base = name.rsplit("/", 1)[-1]
        rest = cmd[i + 1:]
        if kind == "word" and "/" in name:      # a command word with a directory is judged before any builtin, wrapper or utility rule: it is a script of the closure or a finding
            if not re.fullmatch(r"(\./)?bin/[A-Za-z0-9_][A-Za-z0-9_.-]*", name):
                bad.append("%s starts %s, a path-qualified command word that is not a script of the closure" % (path, name))
            elif name.lstrip("./") not in closure:
                bad.append("%s runs %s, which is not in the closure the judge reads" % (path, name))
            continue
        if kind == "var":
            if name in NS_ENGINE_VARS:
                eng = NS_ENGINE_VARS[name]
                if path not in NS_ENGINE[eng]: bad.append("%s starts %s outside %s" % (path, eng, " and ".join(NS_ENGINE[eng])))
            elif name == "GO_TOOL":
                if not rest or rest[0] != "version": bad.append("%s runs the Go toolchain with %s (only `version` reads without running)" % (path, rest[0] if rest else "nothing"))
            elif name in NS_INTERP_VARS and name in vars_ok:
                ns_interp_check(path, "$" + name, rest, closure, vars_ok, bad)
            elif name not in vars_ok:
                bad.append("%s starts a program named by the variable $%s, which is not in this script's reviewed variables" % (path, name))
            elif name in NS_VAR_UTILS:
                ns_util_opts(path, NS_VAR_UTILS[name], rest, bad)
            continue
        if base in NS_WHOLE or base in NS_KEYWORDS:
            continue
        if base == "go":
            if not rest or rest[0] != "version": bad.append("%s runs the Go toolchain with %s (only `version` reads without running)" % (path, rest[0] if rest else "nothing"))
        elif base in ("melange", "apko"):
            if path not in NS_ENGINE[base]: bad.append("%s starts %s outside %s" % (path, base, " and ".join(NS_ENGINE[base])))
        elif base in NS_NEVER or re.fullmatch(r"fscache(\.bin)?|fscache-fips", base):
            bad.append("%s starts %s, which compiles or runs source code or builds a command line from text" % (path, base))
        elif base in NS_INTERP:
            ns_interp_check(path, base, rest, closure, vars_ok, bad)
        elif base in NS_UTILS or base in extra or base in ("exit", "return") or name in funcs or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\(\)", name):
            ns_util_opts(path, base, rest, bad)
            if base in ("sed", "awk"): ns_sed_awk(path, base, rest, bad)
        else:
            bad.append("%s starts %s, which is not an accepted command of this script (allow-list: keywords, file utilities, the closure's own scripts and its reviewed extras)" % (path, name))
    return bad


def ns_python(path, text, closure=None):
    import ast
    bad = []
    rx = ns_start_calls()
    if rx is None:
        return ["%s cannot be judged: the list of program-starting calls (PY_START_CALLS in bin/chain-check-shape.py) is unreadable" % path]
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ["%s does not parse" % path]
    wrappers = set(NS_PYWRAP.get(path, ()))
    progs = set(NS_PYPROGS.get(path, ()))
    alias = {}      # local name -> module, for `import subprocess as _sp`, `from os import execv as go`
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for x in n.names: alias[x.asname or x.name.split(".")[0]] = x.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module:
            for x in n.names: alias[x.asname or x.name] = n.module.split(".")[0] + "." + x.name
    parents = {}
    for node in ast.walk(tree):
        for ch in ast.iter_child_nodes(node): parents[ch] = node
    def enclosing(n):
        while n in parents:
            n = parents[n]
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)): return n.name
        return None
    def is_start_ref(v):      # an expression naming a program-starting function: subprocess.run, os.execv, a from-imported run
        if isinstance(v, ast.Attribute): return bool(rx.match(v.attr)) and alias.get(getattr(v.value, "id", ""), "") in NS_START_MODULES
        if isinstance(v, ast.Name): return bool(rx.match(alias.get(v.id, "").split(".")[-1])) and alias.get(v.id, "").split(".")[0] in NS_START_MODULES
        return False
    called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    exec_seen = []      # the reviewed exec() may stand once
    def stores(name, scope):      # every place that binds or deletes `name` inside scope
        return [n for n in ast.walk(scope) if (isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del))) or (isinstance(n, (ast.Global, ast.Nonlocal)) and name in n.names)
                or (isinstance(n, ast.arg) and n.arg == name)]
    def assigned_once(name, scope, src):      # `name` is bound exactly once in scope, by `name = src`
        st = stores(name, scope)
        asg = [n for n in ast.walk(scope) if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
        return len(st) == 1 and len(asg) == 1 and ast.dump(asg[0].value) == ast.dump(ast.parse(src, mode="eval").body)
    for pv, (_prog, src) in NS_PYVARS.get(path, {}).items():
        if not assigned_once(pv, tree, src): bad.append("%s binds %s more than once or not as `%s` (the reviewed program name)" % (path, pv, src))
    local_defs = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}      # a function the file defines is judged where it is defined
    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Name)) and is_start_ref(node) and id(node) not in called:      # passed, returned, stored or bound: partial(subprocess.run), x = os.execv
            bad.append("%s:%d uses a program-starting function as a value (bound, passed or stored): its calls cannot be judged" % (path, node.lineno))
        if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and alias.get(node.id, "") in NS_START_MODULES + ("importlib",)
                and not (isinstance(parents.get(node), ast.Attribute) and parents[node].value is node)):      # the module name is used as `module.attr` and in no other way
            bad.append("%s:%d uses the module name %s other than as the base of module.attr (assigned, passed, returned or stored): its calls cannot be judged" % (path, node.lineno, node.id))
        if isinstance(node, ast.ImportFrom) and any(x.name == "*" for x in node.names) and (node.module or "").split(".")[0] in NS_START_MODULES + ("importlib",):
            bad.append("%s:%d imports * from %s: its calls cannot be judged" % (path, node.lineno, node.module))
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
        if isinstance(f, ast.Name) and f.id in ("exec", "eval") and f.id not in alias:
            fn_ok, src_ok = NS_PYEXEC.get(path, (None, None))
            if fn_ok is None or enclosing(node) != fn_ok or f.id != "exec" or ast.dump(node) != ast.dump(ast.parse(src_ok).body[0].value) or exec_seen:
                bad.append("%s:%d runs %s(), which executes code from a string" % (path, node.lineno, f.id))
            exec_seen.append(node)
            continue
        owner = alias.get(getattr(f.value, "id", ""), getattr(f.value, "id", "")) if isinstance(f, ast.Attribute) else ""
        if isinstance(f, ast.Name) and alias.get(f.id, "").count("."):      # `from os import execv`: the called name is the module's function
            owner, name = alias[f.id].split(".", 1)
        if any(k.arg == "shell" and not (isinstance(k.value, ast.Constant) and k.value.value is False) for k in node.keywords):
            bad.append("%s:%d starts a program through a shell" % (path, node.lineno)); continue
        if name in ("system", "popen") and isinstance(f, ast.Attribute):
            bad.append("%s:%d starts a program through a shell (.%s)" % (path, node.lineno, name)); continue
        if isinstance(f, ast.Name) and f.id == "getattr" and node.args and alias.get(getattr(node.args[0], "id", ""), "") in NS_START_MODULES + ("importlib",):
            bad.append("%s:%d gets a function of %s by name (getattr): its calls cannot be judged" % (path, node.lineno, alias[node.args[0].id])); continue
        if name in ("__import__", "import_module"):
            bad.append("%s:%d loads a module by name (%s): its calls cannot be judged" % (path, node.lineno, name)); continue
        if isinstance(f, ast.Attribute) and NS_START_ONLY.match(name) and owner not in NS_START_MODULES and not (owner == "" and name in wrappers):
            bad.append("%s:%d calls .%s on something the judge cannot trace to subprocess, os, pty or asyncio" % (path, node.lineno, name)); continue
        starts = (bool(rx.match(name)) and owner in NS_START_MODULES) or name in wrappers or (bool(rx.match(name)) and owner == "" and name not in local_defs)
        if name in ("spawn",) and owner == "pty": starts = True
        if not starts:
            continue
        if any(k.arg is None for k in node.keywords) or any(isinstance(x, ast.Starred) for x in node.args):
            bad.append("%s:%d starts a program with ** or * arguments: the command line cannot be judged" % (path, node.lineno)); continue
        if any(k.arg == "executable" for k in node.keywords):
            bad.append("%s:%d starts a program with executable=, which names a program other than the command line shows" % (path, node.lineno)); continue
        a = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "args"), None)
        if isinstance(a, ast.BinOp) and isinstance(a.op, ast.Add) and isinstance(a.left, (ast.List, ast.Tuple)):
            a = a.left       # ["git", "-C", repo] + list(args): the program and its first words are the literal side
        if name.startswith(("exec", "spawn", "posix_spawn")) and owner == "os":
            bad.append("%s:%d starts a program with os.%s, which takes a path and an argument list apart; use a reviewed list-literal call" % (path, node.lineno, name)); continue
        if isinstance(a, ast.Name):      # argv = [...] built a few lines earlier in the same function (or at module level)
            fn = node
            while fn in parents and not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)): fn = parents[fn]
            var, found = a.id, None
            for st in ast.walk(fn):
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) and st.targets[0].id == var and st.lineno < node.lineno:
                    v = st.value.left if isinstance(st.value, ast.BinOp) and isinstance(st.value.op, ast.Add) else st.value
                    if isinstance(v, (ast.List, ast.Tuple)): found = v      # the last list assigned before the call
            def start_arg(n):      # this load of the list is the first argument (or args=) of a program-starting call
                par = parents.get(n)
                if isinstance(par, ast.keyword): n, par = par, parents.get(par)
                if not isinstance(par, ast.Call): return False
                cname = par.func.attr if isinstance(par.func, ast.Attribute) else getattr(par.func, "id", "")
                return (bool(rx.match(cname)) or cname in wrappers) and (par.args[:1] == [n] or (isinstance(n, ast.keyword) and n.arg == "args"))
            stored = [st for st in ast.walk(fn) if isinstance(st, ast.Name) and st.id == var and isinstance(st.ctx, (ast.Store, ast.Del))]
            loose = [st for st in ast.walk(fn) if isinstance(st, ast.Name) and st.id == var and isinstance(st.ctx, ast.Load) and not start_arg(st)]
            if found is not None and (len(stored) != 1 or loose):
                bad.append("%s:%d starts a program from the list %s, which is assigned more than once or used for anything but the start call (aliased, indexed, passed on, changed): it cannot be judged" % (path, node.lineno, var)); continue
            if found is not None: a = found
        if not isinstance(a, (ast.List, ast.Tuple)) or not a.elts:
            if enclosing(node) in wrappers and isinstance(a, ast.Name):
                continue        # the reviewed wrapper's own call: its parameter is judged at its callers
            bad.append("%s:%d starts a program whose command line is not a list literal (a variable or a call): it cannot be judged" % (path, node.lineno)); continue
        e0 = a.elts[0]
        first = e0.value if isinstance(e0, ast.Constant) and isinstance(e0.value, str) else (e0.id if isinstance(e0, ast.Name) else (e0.attr if isinstance(e0, ast.Attribute) and e0.attr in ("go",) else None))
        if first is None and isinstance(e0, ast.Call) and isinstance(e0.func, ast.Name) and NS_PYFUNCS.get(path, {}).get(e0.func.id):
            first = NS_PYFUNCS[path][e0.func.id]       # a reviewed helper that returns a fixed program location (apk-tool.py _openssl)
        if first in NS_PYVARS.get(path, {}):
            first = NS_PYVARS[path][first][0]       # a reviewed module constant that names the program (bound to its one assignment at the top of ns_python)
        word = os.path.basename(first) if first else None
        rest = a.elts[1:]
        consts = [x.value for x in rest if isinstance(x, ast.Constant) and isinstance(x.value, str)]
        is_interp = (first is None and isinstance(e0, ast.Attribute) and e0.attr == "executable") or (word in NS_INTERP)
        if word in ("go", "GO_TOOL"):
            if not (rest and isinstance(rest[0], ast.Constant) and rest[0].value == "version"):
                bad.append("%s:%d runs the Go toolchain with %r (only `version` reads without running)" % (path, node.lineno, consts[0] if consts else None))
        elif word in ("melange", "apko"):
            if path not in NS_ENGINE[word]: bad.append("%s:%d starts %s outside %s" % (path, node.lineno, word, " and ".join(NS_ENGINE[word])))
        elif word and (word in NS_NEVER or re.fullmatch(r"fscache(\.bin)?|fscache-fips", word)):
            bad.append("%s:%d starts %s, which compiles or runs source code" % (path, node.lineno, word))
        elif is_interp:
            is_opt = lambda x: isinstance(x, ast.Constant) and isinstance(x.value, str) and x.value.startswith("-")
            operand = next((x for x in rest if not is_opt(x)), None)
            python = (first is None and word is None) or word in ("python", "python3")      # sys.executable
            wrong = [x.value for x in rest[:rest.index(operand) if operand is not None else len(rest)] if not (python and x.value in NS_INTERP_OPTS)]
            if wrong:
                bad.append("%s:%d runs the interpreter with the option word %s: an interpreter takes no option (-c, -m, -s and - run inline code or stdin)" % (path, node.lineno, wrong[0])); continue
            computed = False
            for fn_name, w_ok, osrc, asrc in NS_PYCOMPUTED.get(path, ()):
                if operand is None or fn_name != enclosing(node) or w_ok != word or ast.dump(operand) != ast.dump(ast.parse(osrc, mode="eval").body): continue
                defs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn_name]
                bound = asrc is None or (len(defs) == 1 and assigned_once(osrc, defs[0], asrc))
                consts = [n.id for n in ast.walk(ast.parse(asrc or osrc, mode="eval")) if isinstance(n, ast.Name) and n.id.isupper()]
                consts_ok = all(len(stores(c, tree)) == 1 and any(isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id == c and isinstance(n.value, ast.Constant)
                                                                  and isinstance(n.value.value, str) and n.value.value.startswith("bin/") for n in tree.body) for c in consts)
                computed = bound and consts_ok
            if computed:
                continue
            if not (isinstance(operand, ast.Constant) and isinstance(operand.value, str) and re.fullmatch(r"(\./)?bin/[A-Za-z0-9_.-]+", operand.value)):
                bad.append("%s:%d runs the interpreter on something that is not a repository script (the first non-option argument must be a bin/ script of the closure)" % (path, node.lineno))
            elif closure is not None and operand.value.lstrip("./") not in closure:
                bad.append("%s:%d runs the interpreter on %s, which is not in the closure the judge reads" % (path, node.lineno, operand.value))
        elif word and word in progs:
            pass
        else:
            bad.append("%s:%d starts %s, which is not on this script's list of programs" % (path, node.lineno, word or type(e0).__name__))
    return bad


def nosource(root):
    seen, bad = ns_closure(root)
    if seen is None:
        return bad
    for p in seen:
        try:
            text = open(root + "/" + p).read()
        except OSError:
            bad.append("%s is listed but missing" % p)
            continue
        bad += ns_python(p, text, seen) if p.endswith(".py") else ns_shell(p, text, seen)
    return bad

# ---- release.yml --------------------------------------------------------------------------------------------------------------------
CHAIN = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml",
         "sign-rebuild": "stage-sign.yml", "check": "stage-verify.yml", "sign-check": "stage-sign.yml", "release": "stage-promote.yml"}
# Check needs exactly build (REQ-CHAIN-005-AC5: Rebuild and Check each need only Build, so they run side by side; Codex B r2 R3). Release needs all three.
# The Witness move (owner Oct 22 2026): the building jobs' records are signed by Sign, so Rebuild and Check start after Sign (they verify Build's record as Sign
# signed it), and Rebuild's own records are signed by Sign's second call after Rebuild. Release needs Check, Sign and Sign-rebuild (it reaches Rebuild through it).
NEEDS = {"build": [], "sign": ["build"], "rebuild": ["build", "sign"], "sign-rebuild": ["build", "rebuild"], "check": ["build", "sign"],
         "sign-check": ["build", "check"], "release": ["check", "sign", "sign-check", "sign-rebuild"]}


# The `if` of the chain jobs (REQ-CHAIN-005-AC5). ONE gate G, the same exact text on build and sign: the chain starts on a v* tag PUSH, or in a dry-run
# dispatch on any branch. (A manual workflow_dispatch on an existing v* tag is therefore NOT a release run: its event is not push and its dry-run is
# not true.) rebuild and check carry no if: they run after build through needs. release carries exactly !inputs.dry-run (a dry run neither tags
# nor publishes; on a tag push inputs.dry-run is null, so it runs). No !cancelled(), no needs.admission: admission is gone in PR 2's graph and
# build needs nothing. PR 1's release.yml has other strings (`!inputs.dry-run && ...` conjuncts on other jobs, `if: ${{ inputs.dry-run }}` on sign):
# at the merge of PR 1 into chain-v030 they are replaced by these.
GATE = "${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}"
RELEASE_IF = "${{ startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}"
# patch-failed also fires when the release job was CANCELLED (audit ruling, Oct 22): the release job's concurrency group keeps one pending run, a third queued tag run replaces it, and
# the replaced run ends as cancelled, which failure() does not see
PATCH_FAILED_IF = "${{ always() && (contains(needs.*.result, 'failure') || needs.release.result == 'cancelled') && startsWith(github.ref, 'refs/tags/v') && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}"
RELEASE_CONCURRENCY_LINE = re.compile(r"(?m)^  release:\n(?:    .*\n|\n)*?    concurrency:\n      group: release-publish\n      cancel-in-progress: false\n")
GATED = ("build", "sign")      # sign runs in a release and in a dry run, so it carries the same gate G (Build hands it the digests)
RC_PUSH = "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc')"
BUILD_WITH = {"hostile": "${{ %s }}" % RC_PUSH}      # the hostile Build step runs on a push of a release-candidate tag only (advisor 0383)
SIGN_PERMISSIONS = {"contents": "read", "id-token": "write"}
# PR 1's stage-sign.yml takes exactly ONE input, digests (Build's record is downloaded by the fixed artifact name witness-build, not passed). PR 1's
# placeholder needs.build.outputs.checksums (raw checksums.txt text) is replaced at the cutover by Build's digests output, the digests.json text.
SIGN_WITH = {"sign": {"digests": "${{ needs.build.outputs.digests }}", "stage": "build"},
             "sign-rebuild": {"digests": "${{ needs.build.outputs.digests }}", "stage": "rebuild", "records": "${{ needs.rebuild.outputs.records }}"},
             "sign-check": {"digests": "${{ needs.build.outputs.digests }}", "stage": "check", "records": "${{ needs.check.outputs.records }}", "records-arm64": "${{ needs.check.outputs.records-arm64 }}"}}

# The jobs of release.yml that are not chain jobs, each a finite spec: its exact permissions, whether it may name `environment: agent` and `secrets.`
# (the auditor App's secrets live in that environment, main only), and the exact `needs` / `if` where they matter. decide, patch-notes and
# patch-failed exist today (automatic patch releases, REQ-REL-009); the hostile-* jobs are PR 1's dry-run proof (contents: read, no environment,
# no secrets). Anything else is a way to publish around Rebuild or Check.
PATCH_NOTES_IF = "${{ needs.decide.outputs.tagged == 'true' && !inputs.dry-run }}"
LIVE_TEST_RC_IF = "${{ startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') && !inputs.dry-run }}"
LIVE_TEST_FINAL_IF = "${{ startsWith(github.ref, 'refs/tags/v') && !contains(github.ref_name, '-rc') && !inputs.dry-run }}"
PERSONA_RC_IF = "${{ vars.PERSONA_UAT_ENABLED == 'true' && startsWith(github.ref, 'refs/tags/v') && contains(github.ref_name, '-rc') && !inputs.dry-run }}"
# The persona job's only secrets (REQ-UAT-001-AC1, the persona-uat environment): the model names and the federation identifiers. It holds no registry credential or write token.
# The live-test environment's Docker Hub credentials (REQ-SCAN-012-AC1, amended on the advisor reading of Oct 17): the test user and its push token (an organization access token
# scoped to the test repository only) and the read-only Scout token with its user; the same four in both live-test jobs, nothing else
LIVE_TEST_SECRETS = {"DOCKERHUB_USERNAME", "DOCKERHUB_TEST_USERNAME", "DOCKERHUB_TEST_PUSH_TOKEN", "DOCKERHUB_SCOUT_TOKEN"}
PERSONA_SECRETS = {"PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID"}
DECIDE_IF = "${{ github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}"
# The secrets context in any spelling (secrets.X, secrets['X'], toJSON(secrets), secrets ['X']): the word itself, not the dotted form only.
# Contexts are case-insensitive and an expression may span lines or hold tabs, so every DECODED string of the job (keys too) is searched, never its JSON text.
SECRETS_CONTEXT = re.compile(r"\bsecrets\b", re.IGNORECASE)


def names_other_secrets(obj, allowed):
    """names_secrets, except for the dotted form secrets.NAME with NAME in `allowed`: every other spelling of the secrets context still counts"""
    if isinstance(obj, str):
        return bool(SECRETS_CONTEXT.search(re.sub(r"\bsecrets\.(\w+)", lambda m: "" if m.group(1) in allowed else m.group(0), obj, flags=re.IGNORECASE)))
    if isinstance(obj, dict):
        return any(names_other_secrets(k, allowed) or names_other_secrets(v, allowed) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return any(names_other_secrets(v, allowed) for v in obj)
    return False


def names_secrets(obj):
    if isinstance(obj, str):
        return bool(SECRETS_CONTEXT.search(obj))
    if isinstance(obj, dict):
        return any(names_secrets(k) or names_secrets(v) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return any(names_secrets(v) for v in obj)
    return False
NON_CHAIN = {
    "decide": {"perm": {"contents": "read", "checks": "read", "id-token": "write", "issues": "write"}, "agent": True, "if": DECIDE_IF},
    "patch-notes": {"perm": {"contents": "read"}, "agent": True, "needs": ["decide"], "if": PATCH_NOTES_IF},
    "patch-failed": {"perm": {"contents": "read", "issues": "write"}, "agent": False, "needs": sorted(CHAIN)},
    # The rule-12 live tests of our VEX files (REQ-SCAN-012): federated into the dedicated live-test accounts only (environment live-test, whose trust names nothing
    # else), after Check on a release candidate and after Release on a final tag; they publish nothing, hold no secrets but the live-test environment's four Docker Hub test credentials (LIVE_TEST_SECRETS), and cannot run in the dry run.
    "live-test": {"perm": {"contents": "read", "id-token": "write"}, "agent": False, "env": "live-test", "needs": ["check"], "if": LIVE_TEST_RC_IF, "secrets": LIVE_TEST_SECRETS},
    "live-test-release": {"perm": {"contents": "read", "id-token": "write"}, "agent": False, "env": "live-test", "needs": ["release"], "if": LIVE_TEST_FINAL_IF, "secrets": LIVE_TEST_SECRETS},
    # The persona UAT of a release candidate (REQ-UAT-001-AC1): after Build only, against Build's own layout loaded into a registry on the runner; the persona-uat environment
    # holds the model secrets and nothing else; contents read and the federated token (id-token write), no registry credential, no write.
    "persona-uat": {"perm": {"contents": "read", "id-token": "write"}, "agent": False, "env": "persona-uat", "needs": ["build"], "if": PERSONA_RC_IF, "secrets": PERSONA_SECRETS},
}
HOSTILE = {"perm": {"contents": "read"}, "agent": False}


def needs_of(job):
    needs = job.get("needs")
    return [] if needs is None else ([needs] if isinstance(needs, str) else list(needs))


class _NoDuplicateKeys(yaml.BaseLoader):
    """A YAML loader keeps the LAST of two equal mapping keys, so a first, wider definition of a job (or of a key inside one) would be invisible to the specs
    below. Every mapping key is unique or the file is refused (fail closed)."""
    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(None, None, "duplicate mapping key %r" % (key,), key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def graph(path):
    raw_text = read_exact(path)
    try:
        d = yaml.load(raw_text, Loader=_NoDuplicateKeys)
    except yaml.YAMLError as e:
        return ["%s cannot be read as a workflow: %s" % (path, str(e).replace("\n", " ")[:160])]
    jobs, bad = d.get("jobs") or {}, []
    if d.get("permissions") != {"contents": "read"}:
        bad.append("workflow-level permissions must be exactly contents: read (every job asks for what it needs), got %s" % d.get("permissions"))
    dispatch = ((d.get("on") or {}).get("workflow_dispatch") or {}) if isinstance(d.get("on"), dict) else {}
    dry = (dispatch.get("inputs") or {}).get("dry-run") if isinstance(dispatch, dict) else None
    if dry is not None and (dry or {}).get("type") != "boolean":
        bad.append("on.workflow_dispatch.inputs.dry-run must be type: boolean (a string input makes `inputs.dry-run == true` false and silently skips "
                   "the dry run), got %s" % (dry or {}).get("type"))
    for name, file in CHAIN.items():
        job = jobs.get(name)
        if job is None:
            bad.append("chain job %s is missing (the job id is the stage name, so a failure names it)" % name); continue
        # `concurrency` is allowed on the release job ONLY, and must be exactly the constant group with cancel-in-progress false (release review R3, Oct 22:
        # bin/release-publish.sh decides :X and :latest from the registry's tag list, so two release runs must not interleave; a cancelling or per-ref group
        # would kill a publication half way or not serialize at all). On any other chain job it stays outside the allowed keys.
        extra = set(job) - {"uses", "needs", "permissions", "with", "if"} - ({"concurrency"} if name == "release" else set())
        if name == "release" and (job.get("concurrency") != {"group": "release-publish", "cancel-in-progress": "false"} or not RELEASE_CONCURRENCY_LINE.search(raw_text)):
            # this loader keeps every scalar as text, so the quoted string "false" cannot be told from the boolean: the raw file must hold the unquoted line
            bad.append("release must hold exactly the concurrency {group: release-publish, cancel-in-progress: false} with the unquoted line `cancel-in-progress: false` (two publications must not interleave; actionlint refuses a quoted string), got %r" % (job.get("concurrency"),))
        if extra:
            bad.append("%s: keys outside {uses, needs, permissions, with} and build's one if: %s (no continue-on-error, secrets, strategy, env)"
                       % (name, sorted(extra)))
        if name in GATED:
            if job.get("if") != GATE:
                bad.append("%s must carry exactly one if, the gate %s, got %r" % (name, GATE, job.get("if")))
        elif name == "release":
            if job.get("if") != RELEASE_IF:
                bad.append("release must carry exactly the if %s (a dry run publishes nothing), got %r" % (RELEASE_IF, job.get("if")))
        elif "if" in job:
            bad.append("%s may not carry an if (it runs after build through needs), got %r" % (name, job["if"]))
        if name == "rebuild" and "with" in job:
            bad.append("rebuild may not pass inputs (stage-reproducibility.yml takes none; a mode there would make a snapshot Rebuild), got %s" % job["with"])
        if name == "build" and job.get("with") != BUILD_WITH:
            bad.append("build must pass exactly with: %s (the hostile Build step runs only on a push of an rc tag), got %s" % (BUILD_WITH, job.get("with")))
        if name in SIGN_WITH:
            if job.get("permissions") != SIGN_PERMISSIONS:
                bad.append("sign must hold exactly the permissions %s, got %s" % (SIGN_PERMISSIONS, job.get("permissions")))
            with_ = job.get("with") or {}
            if with_ != SIGN_WITH[name]:
                bad.append("%s must pass exactly with: %s (the digests.json text of build's output and the stage it signs; stage-sign.yml takes no other input), got %s"
                           % (name, SIGN_WITH[name], with_))
        if job.get("uses") != "./.github/workflows/" + file:
            bad.append("%s must call exactly ./.github/workflows/%s, got %r" % (name, file, job.get("uses")))
        if sorted(needs_of(job)) != NEEDS[name]:
            bad.append("%s must need exactly %s, got %s" % (name, NEEDS[name], sorted(needs_of(job))))
        if "secrets." in json.dumps(job) or "environment" in job:
            bad.append("%s names secrets. or an environment (a chain job calls its stage with nothing of the kind)" % name)
    for name, job in jobs.items():
        if name in CHAIN:
            continue
        job = job or {}
        granted = job.get("permissions", d.get("permissions"))
        if "uses" in job:
            bad.append("job %s has a job-level uses (%s): only the five chain jobs call a workflow" % (name, job["uses"]))
        if name == "patch-failed" and job.get("if") != PATCH_FAILED_IF:
            bad.append("patch-failed must carry exactly the if %s (a cancelled, replaced release opens an issue too), got %r" % (PATCH_FAILED_IF, job.get("if")))
        spec = HOSTILE if name.startswith("hostile-") else NON_CHAIN.get(name)
        if spec is None:
            bad.append("job %s is not one of the five chain jobs or the allowed non-chain jobs %s plus hostile-*" % (name, sorted(NON_CHAIN)))
            continue
        if granted != spec["perm"]:
            bad.append("job %s must hold exactly the permissions %s, got %s" % (name, spec["perm"], granted))
        if spec["agent"]:
            if job.get("environment", "agent") != "agent":
                bad.append("job %s may name only environment: agent, got %r" % (name, job["environment"]))
        elif spec.get("env"):
            if job.get("environment") != spec["env"]: bad.append("job %s must name exactly environment: %s, got %r" % (name, spec["env"], job.get("environment")))
            if names_other_secrets(job, spec.get("secrets", set())):
                bad.append("job %s may not use secrets. (only decide and patch-notes hold the App's%s)" % (name, "; %s holds only %s" % (name, sorted(spec["secrets"])) if spec.get("secrets") else ""))
        else:
            if "environment" in job: bad.append("job %s may not name an environment (the App secrets live in agent), got %r" % (name, job["environment"]))
            if names_secrets(job): bad.append("job %s may not use secrets. (only decide and patch-notes hold the App's)" % name)
        if "if" in spec and job.get("if") != spec["if"]:
            bad.append("job %s must carry exactly the if %s, got %r" % (name, spec["if"], job.get("if")))
        if "needs" in spec and sorted(needs_of(job)) != spec["needs"]:
            bad.append("job %s must need exactly %s, got %s" % (name, spec["needs"], sorted(needs_of(job))))
    return bad


# ---- the proof workflows call Build in snapshot mode (REQ-CHAIN-004-AC14) ---------------------------------------------------------------
# scan.yml (every pull request and push) and main-candidate-rescan.yml (daily) keep their file names, because the scanner cloud trust is pinned to exactly
# those two (ops#107) and REQ-SCAN-015 forbids anyone calling them. Their job `build` calls stage-build.yml with `mode: snapshot` and NOTHING else: no
# other input (so the dry run's hostile hook stays off), no secrets, no `if`, and exactly the permissions the called stage requests (a caller that grants
# less is a startup_failure with zero jobs; one that grants more holds rights no job uses). No job of these files calls a stage that signs, compares or
# publishes (stage-sign, stage-reproducibility, stage-promote), or the deleted stage-image.yml. THE JUDGE READS ONLY `on` AND THE JOBS THAT CALL A STAGE
# FILE: the scanner steps and the other jobs (`manifests` of main-candidate-rescan.yml, edited by cache's REQ-REL-004-AC5) are cache's and not read here.
SNAPSHOT_CALLER_PERMISSIONS = dict(PERM_ADMIT)       # the union of what the apk job (PERM_ADMIT) and the assemble job (PERM_PLAIN) of stage-build.yml request
# THE ALLOWLIST (step-6 round 1, both seats: a deny-list of stage-file names is bypassed by `@ref`, `owner/repo/...` forms and by release.yml): in a proof
# workflow the only jobs that carry a job-level `uses` are these, each calling EXACTLY the file named, whatever the form. PR 3 removed scan.yml's artifact-acceptance
# (its stage is gone; Check checks the Linux-only archive set); main-candidate-rescan.yml calls Build only.
CALLER_ALLOWLIST = {"build": "./.github/workflows/stage-build.yml", "rebuild": "./.github/workflows/stage-reproducibility.yml"}
NOT_IN_FILE = {"main-candidate-rescan.yml": ("rebuild", "artifact-acceptance")}
# scan.yml (the PR gate keeps rule 31's two-assembly reproducibility check) also calls Rebuild in snapshot mode after Build; main-candidate-rescan.yml does not
SNAPSHOT_REBUILD_PERMISSIONS = dict(PERM_PLAIN)


def ceiling(job_name, perm):
    """A snapshot caller's grants are a STATIC CEILING: contents read, checks/statuses/pull-requests read, and no write at all (the building jobs hold no id-token, only because the
    called stage requests it). Any other write fails here, whatever the stage asks for."""
    if not isinstance(perm, dict):
        return []
    return ["job %s grants %s: write; the grants of a snapshot caller are a static ceiling (read only: the building jobs hold no identity token)" % (job_name, k)
            for k, v in sorted(perm.items()) if v == "write" and k != "id-token"]


def callers(path):
    d = yaml.load(read_exact(path), Loader=yaml.BaseLoader)
    if not isinstance(d, dict):
        return ["%s is not a YAML mapping (an empty or malformed workflow file is refused, never read as having no calls)" % path]
    bad, on = [], d.get("on")
    if not isinstance(on, dict) or "workflow_call" in on:
        bad.append("%s: on: must be a mapping without workflow_call (REQ-SCAN-015: nothing may call a scanner workflow), got %s" % (path, on))
    jobs = d.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return bad + ["%s: jobs must be a non-empty mapping, got %s" % (path, type(jobs).__name__)]
    name, nope = os.path.basename(path), NOT_IN_FILE.get(os.path.basename(path), ())
    for n, j in jobs.items():
        if not isinstance(j, dict):
            bad.append("job %s is not a mapping" % n)
        elif "uses" in j and (n not in CALLER_ALLOWLIST or n in nope):
            bad.append("job %s has a job-level uses (%s), which is not in the allowlist of this proof workflow (build; rebuild and artifact-acceptance "
                       "in scan.yml only): a proof workflow reaches no other workflow, in any form" % (n, j["uses"]))
        elif "uses" in j and j["uses"] != CALLER_ALLOWLIST[n]:
            bad.append("job %s must call exactly %s, got %r" % (n, CALLER_ALLOWLIST[n], j["uses"]))
    build = jobs.get("build")
    if not isinstance(build, dict):
        return bad + ["job build is missing (the proof workflow's one call of stage-build.yml)"]
    if "uses" not in build:
        bad.append("job build must call exactly %s, got nothing" % CALLER_ALLOWLIST["build"])
    if build.get("with") != {"mode": "snapshot"}:
        bad.append("job build must pass exactly with: mode: snapshot (no other input, so no hostile hook), got %s" % build.get("with"))
    bad += ceiling("build", build.get("permissions"))
    if build.get("permissions") != SNAPSHOT_CALLER_PERMISSIONS:
        bad.append("job build must hold exactly the permissions the called stage requests %s, got %s" % (SNAPSHOT_CALLER_PERMISSIONS, build.get("permissions")))
    extra = set(build) - {"uses", "with", "permissions"}
    if extra:
        bad.append("job build: keys outside {uses, with, permissions}: %s (no secrets, if, needs, strategy)" % sorted(extra))
    rebuild = jobs.get("rebuild")
    if name == "scan.yml" and rebuild is None:
        bad.append("scan.yml must also call Rebuild in snapshot mode (job rebuild): the PR gate keeps the two-assembly reproducibility check (rule 31)")
    if name == "main-candidate-rescan.yml" and rebuild is not None:
        bad.append("main-candidate-rescan.yml calls Build only: it needs no Rebuild")
    if isinstance(rebuild, dict) and name != "main-candidate-rescan.yml":
        if "uses" not in rebuild:
            bad.append("job rebuild must call exactly %s, got nothing" % CALLER_ALLOWLIST["rebuild"])
        if rebuild.get("with") != {"mode": "snapshot"}:
            bad.append("job rebuild must pass exactly with: mode: snapshot, got %s" % rebuild.get("with"))
        if needs_of(rebuild) != ["build"]:
            bad.append("job rebuild must need exactly build, got %s" % needs_of(rebuild))
        bad += ceiling("rebuild", rebuild.get("permissions"))
        if rebuild.get("permissions") != SNAPSHOT_REBUILD_PERMISSIONS:
            bad.append("job rebuild must hold exactly the permissions the called stage requests %s, got %s"
                       % (SNAPSHOT_REBUILD_PERMISSIONS, rebuild.get("permissions")))
        if set(rebuild) - {"uses", "with", "permissions", "needs"}:
            bad.append("job rebuild: keys outside {uses, with, permissions, needs}: %s" % sorted(set(rebuild) - {"uses", "with", "permissions", "needs"}))
    return bad


# ---- no other workflow file is added (REQ-CHAIN-004-AC1) -------------------------------------------------------------------------------
KNOWN_WORKFLOWS = set("""acceptance.yml agent-review-gate.yml auditor.yml ci.yml codeql.yml dependabot-auto-merge.yml dependabot-reviewer.yml
go-freshness.yml main-candidate-rescan.yml release.yml reserved-branch-guard.yml scan.yml scorecard.yml stage-acceptance-artifacts.yml
stage-acceptance-egress.yml stage-acceptance-k8s.yml stage-acceptance-predicate.yml stage-admission.yml stage-authorize.yml stage-build.yml
stage-image.yml stage-promote.yml stage-reproducibility.yml stage-verify.yml supply-chain.yml""".split())    # the v0.2.2 set; PRs 2-4 only remove from it


def workflows(directory):
    import os
    have = set(os.listdir(directory))
    added = sorted(have - KNOWN_WORKFLOWS - {"stage-sign.yml"})
    bad = ["workflow file %s was added (the only new file of v0.3.0 is stage-sign.yml, rule 52)" % f for f in added]
    return bad + ["%s still exists (PR 2 removes it, rules 50 and 61)" % f for f in ("stage-image.yml", "stage-admission.yml") if f in have]


# ---- the Witness record -------------------------------------------------------------------------------------------------------------
NAMES = ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL", "GH_TOKEN", "GITHUB_TOKEN")


def recordenv(path):
    import base64
    d = json.load(open(path))
    texts = [json.dumps(d)]
    if isinstance(d, dict) and "payload" in d:
        try:
            texts.append(base64.b64decode(d["payload"]).decode("utf-8", "replace"))
        except Exception:
            return ["the DSSE payload is not base64"]
    elif isinstance(d, dict) and "predicate" in d:
        return ["the record is a bare Statement, not a DSSE envelope (Witness -o writes {payloadType, payload, signatures})"]
    txt = "\n".join(texts)
    bad = []
    for v in NAMES:
        if v in txt: bad.append("the record names %s" % v)
    if re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", txt): bad.append("the record holds a compact JWT")
    if re.search(r"\bgh[pousr]_[A-Za-z0-9]{20,}", txt): bad.append("the record holds a GitHub token")
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "expected":
        print("\n".join(expected_lines(sys.argv[2]))); sys.exit(0)
    if sys.argv[2:3] and not os.path.exists(sys.argv[2]):
        print("missing file: %s" % sys.argv[2]); sys.exit(1)
    bad = {"stage": lambda: stage(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None), "script": lambda: script(sys.argv[2], sys.argv[3]),
           "lockflow": lambda: lockflow(sys.argv[2:]), "graph": lambda: graph(sys.argv[2]), "recordenv": lambda: recordenv(sys.argv[2]),
           "listed": lambda: listed(sys.argv[2], sys.argv[3]), "archive-listed": lambda: archive_listed(sys.argv[2], sys.argv[3]), "helper": lambda: helper(sys.argv[2]), "localhelper": lambda: localhelper(sys.argv[2]), "workflows": lambda: workflows(sys.argv[2]),
            "callers": lambda: callers(sys.argv[2]),
            "directwitness": lambda: directwitness(sys.argv[2:]), "nosource": lambda: nosource(sys.argv[2])}[cmd]()
    if bad and os.environ.get("CHAIN_FINDINGS") == "1":      # output only: the structured ids the known-red judge compares (bin/chain-known-red.py)
        print("FINDINGS-JSON " + json.dumps(bad), file=sys.stderr)
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
