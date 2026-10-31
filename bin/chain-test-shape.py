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
  nosource ROOT                             sandboxed-build rule 1: no step of Build or Rebuild runs source code
    outside melange (34 closure files:
                                             13 shell files by exact lines, 21 files held whole by sha256)

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
POLICY = ('python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json'
          ' --tag "$GITHUB_REF_NAME" --out policy.json')
SDE = ['SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"', "export SOURCE_DATE_EPOCH"]
START = ("python3 -I bin/chain-verify.py stage-start --stage rebuild --previous build --record "
    "witness-build/build-collection.json "
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
        lines.append("python3 -I bin/vex-index.py layout --layout out/%s --vex %s" % (variant, VEX_FILE))
        lines.append("python3 -I bin/vex-index.py sidecar --layout out/%s --vex %s --digest-file "
            "out/%s.digest" % (variant, VEX_FILE, variant))
    return lines


def version_check(variant):
    return ('python3 -I bin/build-version-check.py --apk-dir "out/$(uname -m)" --variant %s --tag "$GITHUB_REF_NAME" '
        '--sha "$GITHUB_SHA"' % variant)


def bind_files(step, rec_dir, record, apk_dir):
    """Every file of each downloaded apk artifact must be the product the building job's LOCAL record holds under the same name (rule 58); the record is unsigned
    (the building jobs hold no identity token) and Sign checks it again against the artifacts it receives before it signs it."""
    return ["python3 -I bin/chain-verify.py bind --local --step %s --record %s/%s/%s --dir %s/%s --as out" % (step,
        rec_dir, r, record, apk_dir, r)
            for r, a in RUNNERS]


def melange_repo(apk_dir):
    return (["mkdir -p melange-repo"] + ["cp -R %s/%s/%s melange-repo/%s" % (apk_dir, r, a, a) for r, a in RUNNERS]
            + ["mkdir -p keyring", "cp %s keyring/wolfi-signing.rsa.pub" % KEYRING_WOLFI, "cp %s keyring/assembly.rsa.pub" % ASSEMBLY_PUB])


def archives(ver=VER):
    return "python3 -I bin/build-archives.py --melange-repo melange-repo --version %s --out dist" % ver


def merge(apk_dir, outputs, ver=VER):
    frags = " ".join("--fragment %s/%s/items-apk.json" % (apk_dir, r) for r, a in RUNNERS)
    return ("python3 -I bin/chain-verify.py items-merge %s --images out --archives dist --version %s --archive %s %s"
            % (frags, ver, ARCHIVE, outputs))


def items_apk():
    return 'python3 -I bin/chain-verify.py items-apk --out-dir "out/$(uname -m)" --result out/items-apk.json'


def expected_lines(kind):
    """The exact lines (shebang, comments and blank lines aside; a trailing-backslash break is joined) of bin/build-stage-KIND.sh."""
    if kind == "apk":
        return ([H, "python3 -I bin/build-admit.py run", "unset GH_TOKEN"] + SDE + [apk_cmd("standard"),
            apk_cmd("fips"),
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
                   "python3 -I bin/chain-verify.py rebuild-compare --snapshot --build-record "
                   "witness-build/snapshot-build-collection.local.json "
                   "--expected build-in/items.json --actual items.json --out %s" % SNAPSHOT_VERDICT])
    if kind == "rebuild-apk":
        return [H, POLICY, START] + SDE + [apk_cmd("standard"), apk_cmd("fips"), items_apk()]
    if kind == "rebuild-assemble":
        return ([H, POLICY, START]
                + bind_files("rapk", "rec-rapk", "rapk-collection.local.json", "rapk") + melange_repo("rapk") + SDE
                + [image_cmd("production"), image_cmd("fips")] + vex_attach() + [archives(), merge("rapk", "--items items.json"),
                   "cp build-in/digests.json digests.json",          # REQ-CHAIN-005-AC2 (Astra R2): Rebuild's record carries the digest list it was started against as a product
                   "python3 -I bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json "
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
ADMISSION_BASELINE = ('python3 -I bin/chain-verify.py admission-baseline --admission apk/ubuntu-24.04/admission.json '
    '--admission apk/ubuntu-24.04-arm/admission.json '
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
            'case "$step" in %s) ;; *) echo "witnessed-local: unknown step $step" >&2; exit 2 ;; esac' % LOCAL_STEPS,
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


# ---- nosource: no step of Build or Rebuild runs source code outside melange (sandboxed-build rule 1) -----------------
# In Build and Rebuild the compile of our source and of its dependencies happens only inside melange's sandbox
# (bin/build-apk.sh); apko only lays packages down.
# The judge reads every script the stage scripts and the workflows' other bin/ steps can start, 34 files, and reads no
# free-form shell or Python (orchestrator ruling of Oct 30):
#   shell by exact text: the nine stage scripts, bin/witnessed-local.sh, the three helpers (build-apk.sh,
#   assemble-image.sh, apko-lock.sh) and the mode guard are compared
#   command by command with the lines held here (script, localhelper, shell_exact); a case, a loop, a function, a
#   subshell or a read in a helper is one more command,
#   so it is a finding. Line 1 of each is held too (the shebang picks the program that runs the file).
#   held whole by sha256 (NS_SHA, 21 files): the 15 Python closure files and the 6 files that the two stage workflows
#   run outside the stage scripts (archive-pull.sh,
#   archive-verify.py, install-host-bwrap.py, chain-hostile-step.sh, loopback-get.sh, rebuild-records-digests.sh). Any
#   change is a finding until NS_SHA is re-pinned in a
#   security-tier change. The stage lines and every python3 child that a closure file starts (build-admit.py,
#   chain_items.py) run python3 -I, so a file of bin/ cannot
#   shadow a module for them and they ignore PYTHON* variables. The program python3 is still found by PATH, and a file
#   written by one step and run by the next is not
#   seen (both: P6, filed).
# Which scripts are read: the `runs` rows of chain-scripts.json and every bin/ script the code names (also load_sibling
# and import). A file that does not read as UTF-8
# text or does not parse is a finding (its children could not be followed). bin/install-scanner.sh and
# bin/install-build-tools.sh are not read: install-scanner.sh is on
# the review list (its witness, go, crane and gitsign arms run in Build, so a change there gets the second review), and
# install-build-tools.sh compiles nothing.
# THE ONE KNOWN FINDING on the real tree: the admission step in bin/build-admit.py runs
# `go -C tools/requirements run . verify-freeze` of the tagged tree. It is reported (rule 1 forbids it) while
# its two lines are in the file; the decision is its own job before Build in stage-build.yml, in its own pull request.
# Until that lands rule 1 is NOT done.
NS_ROOTS = ("bin/build-stage-*.sh", "bin/witnessed-local.sh", "bin/archive-pull.sh", "bin/install-host-bwrap.py",
            # what the run: lines of stage-build.yml and stage-reproducibility.yml start, bar NS_SKIP
            "bin/chain-hostile-step.sh", "bin/rebuild-records-digests.sh")
NS_SKIP = ("bin/install-scanner.sh", "bin/install-build-tools.sh")
NS_NAME = re.compile(r"(?<![\w/.-])(?:\./)?(bin/[A-Za-z0-9_][A-Za-z0-9_.-]*)")


def ns_named(path, text):
    """The repository files a script's code names: shell words bin/NAME; for Python the strings that are exactly
    bin/NAME, load_sibling("NAME") and imports."""
    names = set()
    if path.endswith(".py"):
        import ast
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError) as e:
            raise ValueError("does not parse (%s)" % type(e).__name__)
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value,
                str) and re.fullmatch(r"bin/[A-Za-z0-9_][A-Za-z0-9_.-]*", n.value): names.add(n.value)
            elif isinstance(n, ast.Call) and getattr(n.func, "id",
                "") == "load_sibling" and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value,
                str):
                names.add("bin/%s.py" % n.args[0].value)
            elif isinstance(n, ast.Import):
                names.update("bin/%s.py" % x.name.split(".")[0] for x in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                names.add("bin/%s.py" % n.module.split(".")[0])
    else:
        for cmd in commands_of(text)[0]:
            names.update(m.group(1).rstrip(".") for m in NS_NAME.finditer(cmd))
    return sorted(names)


def ns_closure(root):
    """(files, faults): the scripts the stage scripts can start. A file with no row in chain-scripts.json is a fault."""
    import glob
    try:
        rows = {r.get("path"): r for r in json.load(open(root + "/.github/policy/chain-scripts.json")).get("scripts",
            [])}
    except (OSError, ValueError, AttributeError):
        return None, ["chain-scripts.json cannot be read"]
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
            text = open(root + "/" + p, encoding="utf-8").read()
            todo += [n for n in ns_named(p, text) if n != p and os.path.isfile(root + "/" + n)]
        except (OSError, ValueError) as e:
            bad.append("%s cannot be followed: it %s (its children are not in the closure)" % (
                p, "does not read as UTF-8 text" if isinstance(e,
                UnicodeDecodeError) else str(e) if "parse" in str(e) else "cannot be read"))
    return sorted(seen), bad


def shell_exact(path, name, want):
    """A shell helper is exactly the lines held here. The first difference is named and so are the counts, even when
    both are the same."""
    try:
        raw = read_exact(path)
    except (OSError, ValueError):
        return ["%s cannot be read" % name]
    commands, faults = commands_of(raw)
    bad = compare(commands, want, name)
    if bad and not any("commands, the grammar has" in b for b in bad):
        bad.append("%s has %d commands, the grammar has %d (the order differs)" % (name, len(commands), len(want)))
    return ["control character %s in %s" % (c, name) for c in control_chars(raw)] + faults + bad


def ns_shell(path, name):
    """One closure shell file: a stage script, the Witness local helper, a helper or the mode guard (each exact
    text)."""
    stage = {v: k for k, v in SCRIPTS.items() if k != "witnessed"}
    if name in stage:
        return ["%s: %s" % (name, b) for b in script(path, stage[name])]
    if name == "bin/witnessed-local.sh":
        return ["%s: %s" % (name, b) for b in localhelper(path)]
    if name in SHELL_LINES:
        return shell_exact(path, name, SHELL_LINES[name])
    return ["%s is a shell script of the closure with no exact lines held (commands, the grammar has none)" % name]


NS_SHEBANG = b"#!/usr/bin/env bash"
NS_KNOWN_FILE = "bin/build-admit.py"
NS_KNOWN_LINES = (      # the two physical lines of the admission step's go run
    '    rc, _, err = outcome(lambda: subprocess.run([ctx.go, "-C", "tools/requirements", "run", ".",'
    ' "verify-freeze", base],',
    '        capture_output=True, env=dict(os.environ, **{"GOTOOLCHAIN": "local"}), check=False))')
NS_SHA = {
    "bin/admission-tag-signer.py": "03b66ea50f873de93047bfb4becd305ba6c81fcb1506584990ade81bd16bab40",
    "bin/apk-tool.py": "9c5e1d6e66796173425ac8e417b5d920fc2c3a3d72f5409dcf260670df8ba796",
    "bin/archive-pull.sh": "f7f07098d60b94ba22d8f355b95336303b9c4bd1d10a94c5d1952774ae22dfd3",
    "bin/archive-verify.py": "0dd011c43a4c0afc4543afbcede9f43849b9ea3f54a91432fe5aaa2768000e31",
    "bin/build-admit.py": "bb6172792dcdb176d7971131d9112fdec21654d9c6b1af366af50f90cd535144",
    "bin/build-apk-helper.py": "c3e04e80dfd88e34d0c16cc41e5e889129d682997af80eac3452deba874fe0dc",
    "bin/build-archives.py": "8a2f8998521cf83e941221169051dbfa4903c31e5866fe0fb62896d186751a77",
    "bin/build-version-check.py": "71513126e5c2db74a381089711bb763c0d7aedde1502abae0fb24a1c51938a4a",
    "bin/chain-bytes-sha.py": "8c886b5d99273a6343795d6aafc3a8bb37615b96bae1902da8dfb1fdb8559976",
    "bin/chain-hostile-step.sh": "1f2adc9dffff576748641d93d2321b2b983c4deb77edfea48ba212ee55a11b44",
    "bin/chain-verify.py": "51c0dfa9739ddc5cc83d2e7596258014f29e41160be4671f2c71c77fa1c133df",
    "bin/chain_common.py": "c007d131524a5ca82c17f3ca0829bbfb52c19303f093e34a0ae1d3fd0b459238",
    "bin/chain_hostile.py": "377ac8e8f5440fb51616ae937416ba0a206c70bce93999270c2df5cfb9c92d0c",
    "bin/chain_items.py": "a2d194f4f616f4c050b69a1966384275889da42a1d6b90de8cb1b0a31386c2d6",
    "bin/go-module-sbom.py": "70dce4789b0cb905e496ad18d026877c01609fe0f86234f320b5ef1a8b296935",
    "bin/install-host-bwrap.py": "b0d980cbf3c46c2cb757021cec510d38be73199c8ca77d9aca688d190c95def4",
    "bin/loopback-get.sh": "2561cb23762601bdd0540a8f861fe595df946d4988de6694e419b89bd92c7857",
    "bin/net-probe.py": "5c6e0693d4af7f0ac9dd54d707a9f896cd3293b3e9df20178752ea0fa21c8729",
    "bin/oci-digest.py": "4619886c66e7ccb9d361e221748bb8c195c18fc8acb55c178b7321062361a081",
    "bin/rebuild-records-digests.sh": "15ec6de48964af3ccb82e97b4beb3e3448dd240781f2b954a9d26a2926bbcf49",
    "bin/vex-index.py": "3306a83ca4704a9069b44a72bc853d2d9f0c2e668a5454f6b07e0bd52bfbfe3d",
}


def ns_held(path, raw):
    """A closure file held whole by sha256; the one known finding is reported while its lines are in the file."""
    want, got = NS_SHA.get(path), hashlib.sha256(raw).hexdigest()
    bad = []
    if want is None:
        bad.append("%s is a closure Python file with no held sha256 in NS_SHA" % path)
    elif got != want:
        bad.append("%s: sha256 %s is not the held %s; a file held whole changes only with a re-pin of NS_SHA in "
                   "bin/chain-test-shape.py (short-list review, with this file's diff)" % (path, got[:12], want[:12]))
    if path == NS_KNOWN_FILE:
        text = raw.decode("utf-8", "replace").split("\n")
        for n in range(1, len(text)):
            if (text[n - 1], text[n]) == NS_KNOWN_LINES:
                bad.append("%s:%d `%s` runs go of the tagged tree outside melange (sandboxed-build rule 1 is NOT done: "
                           "the admission step's go run is its own job before Build)"
                           % (path, n, text[n - 1].strip()[:100]))
    return bad


def nosource(root):
    seen, bad = ns_closure(root)
    if seen is None:
        return bad
    bad += ["NS_SHA holds %s, which is not a file of the closure" % p for p in sorted(NS_SHA) if p not in seen]
    for p in seen:
        path = root + "/" + p
        try:
            raw = open(path, "rb").read()
        except OSError:
            bad.append("%s cannot be read" % p)
            continue
        if p in NS_SHA or p.endswith(".py"):
            bad += ns_held(p, raw)
        else:
            if raw.split(b"\n", 1)[0] != NS_SHEBANG:
                bad.append("%s: line 1 is not the held shebang %s" % (p, NS_SHEBANG.decode()))
            bad += ns_shell(path, p)
    return bad


SHELL_LINES = {      # per shell helper: its commands (comments and blank lines aside) exactly
    'bin/apko-lock.sh': [
        'set -euo pipefail',
        'PY3=/usr/bin/python3                 # TEST-SUBST',
        '"$PY3" -I -B bin/oci-digest.py lock "$@"',
    ],
    'bin/assemble-image.sh': [
        'set -euo pipefail',
        "HOST_OS=${BASH_VERSINFO[5]}          # TEST-SUBST (the running bash's own build host: no tool, no caller "
        "input)",
        'PY3=/usr/bin/python3                 # TEST-SUBST',
        'SUDO=/usr/bin/sudo                   # TEST-SUBST',
        'UNSHARE=/usr/bin/unshare             # TEST-SUBST',
        'BASHBIN=/bin/bash                    # TEST-SUBST',
        'APKO=/usr/local/bin/apko             # TEST-SUBST (the chain installs it there)',
        'ENVBIN=/usr/bin/env                  # TEST-SUBST',
        'WORKDIR=/work                        # TEST-SUBST (the fixed path the config and the locks name, rule 31)',
        'RENDER_DIR=                          # TEST-SUBST (empty: a private temporary directory)',
        'here_=${BASH_SOURCE[0]%/*}; [ "$here_" != "${BASH_SOURCE[0]}" ] || here_=.   # the script\'s own directory, '
        'no tool',
        'start_=$PWD',
        'cd -P "$here_/.."',
        'root=$PWD',
        '[[ $HOST_OS == *linux* ]] || { echo "assemble-image.sh: refusing to run on $HOST_OS: this script uses sudo," '
        '"unshare and the sealed build tools, which run on Linux only (inside a Linux container or on a GitHub '
        'runner)," "never on the Mac itself" >&2; exit 2; }',
        '[ "$start_" -ef "$root" ] || { echo "assemble-image.sh: assemble-image.sh runs from the repository root '
        '($root)," "not from $start_: the helpers are named by repo-root-relative paths" >&2; exit 2; }',
        '[ $# -eq 12 ] && [ "$1" = --variant ] && [ "$3" = --version ] && [ "$5" = --archive ] && [ "$7" = '
        '--melange-repo ] && [ "$9" = --keyring-dir ] && [ "${11}" = --out ] || { echo "assemble-image.sh: unknown '
        'argument or missing value" >&2; exit 2; }',
        'variant=$2; version=$4; archive=$6; melrepo=$8; keydir=${10}; out=${12}; render=$RENDER_DIR',
        '[ "$variant" = production ] || [ "$variant" = fips ] || { echo "assemble-image.sh: --variant must be '
        'production or fips" >&2; exit 2; }',
        '[[ $version =~ ^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-rc[1-9][0-9]*)?$ || $version = '
        '0.0.0-rc.1 ]] || { echo "assemble-image.sh: --version must be X.Y.Z, X.Y.Z-rcN or the snapshot version '
        '0.0.0-rc.1" "(numbers without leading zeros; not \'$version\')" >&2; exit 2; }',
        'pkg=$("$PY3" -I -B bin/oci-digest.py variant-field "$variant" pkg)',
        'config=$("$PY3" -I -B bin/oci-digest.py variant-field "$variant" config)',
        'baselock=$("$PY3" -I -B bin/oci-digest.py variant-field "$variant" baselock)',
        '"$PY3" -I -B bin/oci-digest.py check-roots "$archive" "$melrepo" "$keydir" "$out" "$render"',
        'archive=$("$PY3" -I -B bin/oci-digest.py abs-dir "$archive")',
        'melrepo=$("$PY3" -I -B bin/oci-digest.py abs-dir "$melrepo")',
        'keydir=$("$PY3" -I -B bin/oci-digest.py abs-dir "$keydir")',
        'baselock=$("$PY3" -I -B bin/oci-digest.py abs-file "$baselock")',
        'config=$("$PY3" -I -B bin/oci-digest.py abs-file "$config")',
        '[ -z "$render" ] || render=$("$PY3" -I -B bin/oci-digest.py abs-file "$render")',
        'apkver=$("$PY3" -I -B bin/oci-digest.py apk-version "$version")',
        '[[ ${SOURCE_DATE_EPOCH:-} =~ ^[0-9]{1,12}$ ]] || { echo "assemble-image.sh: SOURCE_DATE_EPOCH must hold '
        'digits (the commit time, at most 12 digits)" >&2; exit 2; }',
        'build_date=$("$PY3" -I -B bin/oci-digest.py render-date "$SOURCE_DATE_EPOCH" 2>/dev/null) || { echo '
        '"assemble-image.sh: SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH is not a date" >&2; exit 2; }',
        '"$PY3" -I -B bin/oci-digest.py check-inputs "$archive" "$melrepo" "$keydir" "$out" "$config" "$baselock"',
        '"$PY3" -I -B bin/oci-digest.py check-config "$config" || exit 2',
        '"$PY3" -I -B bin/oci-digest.py check-keydir "$keydir"',
        'keyrec=build/locks/archive-keys.sha256',
        '[ -f "$keyrec" ] || { echo "assemble-image.sh: the key record $keyrec is missing:" "cannot tell which keys '
        'the keyring directory must hold" >&2; exit 2; }',
        '"$PY3" -I -B bin/oci-digest.py check-keys "$keyrec" "$keydir" || exit 2',
        'idxrec=build/locks/archive-index.sha256',
        '[ -f "$idxrec" ] || { echo "assemble-image.sh: the index record $idxrec is missing:" "cannot tell which '
        'package index the archive must hold" >&2; exit 2; }',
        '"$PY3" -I -B bin/oci-digest.py check-index "$idxrec" "$archive" >/dev/null || exit 2',
        '"$BASHBIN" bin/apko-lock.sh verify-archive --lock "$baselock" --archive "$archive" --index-record "$idxrec" '
        '|| { echo "assemble-image.sh: the archive does not satisfy the base lock $baselock (see above)" >&2; exit 2; '
        '}',
        '"$PY3" -I -B bin/oci-digest.py check-melrepo "$melrepo" "$pkg" "$apkver"',
        'workdir=$WORKDIR',
        'lock=$workdir/.assemble.lock',
        '[ ! -e "$lock" ] || { echo "assemble-image.sh: another assembly is in progress (the lock $lock exists);" '
        '"wait for it or remove the lock if no run is active" >&2; exit 2; }',
        '"$PY3" -I -B bin/oci-digest.py check-workdir "$workdir"',
        'tmp=$(mktemp -d)',
        'made=',
        'trap \'rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1 || true\' EXIT',
        'rdir=$("$PY3" -I -B bin/oci-digest.py prepare-render "$render" "$tmp")',
        'rendered=$rdir/$(basename "$config")',
        '"$PY3" -I -B bin/oci-digest.py render-config "$config" "$rendered" "$apkver" || { echo "assemble-image.sh: '
        'cannot render the config $config" >&2; exit 1; }',
        '"$PY3" -I -B bin/oci-digest.py check-out "$out" "$variant"',
        'mkdir -p "$out"',
        'out=$("$PY3" -I -B bin/oci-digest.py abs-dir "$out")',
        'view=$rdir/archive-view',
        '"$PY3" -I -B bin/oci-digest.py make-view "$idxrec" "$archive" "$view" || exit 2',
        '"$SUDO" mkdir -p "$workdir" || { echo "assemble-image.sh: cannot create $workdir" >&2; exit 2; }',
        '"$SUDO" mkdir "$lock" || { echo "assemble-image.sh: another assembly is in progress" "(could not take '
        '$lock)" >&2; exit 2; }',
        'trap \'{ "$SUDO" rm -f $made; "$SUDO" rmdir "$lock"; rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp"; } '
        '|| true\' EXIT',
        '"$SUDO" ln -sT "$view" "$workdir/archive" || { echo "assemble-image.sh: cannot make the link '
        '$workdir/archive" "(it exists: another assembly?); stopping" >&2; exit 2; }',
        'made="$made $workdir/archive"',
        '"$SUDO" ln -sT "$melrepo" "$workdir/melange-repo" || { echo "assemble-image.sh: cannot make the link" '
        '"$workdir/melange-repo (it exists: another assembly?); stopping" >&2; exit 2; }',
        'made="$made $workdir/melange-repo"',
        '"$SUDO" ln -sT "$keydir" "$workdir/keyring" || { echo "assemble-image.sh: cannot make the link '
        '$workdir/keyring" "(it exists: another assembly?); stopping" >&2; exit 2; }',
        'made="$made $workdir/keyring"',
        'mkdir -p "$tmp/apko-cache"',
        'full=$tmp/$variant.full.lock.json',
        'cd "$rdir"',
        '"$SUDO" "$ENVBIN" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$UNSHARE" -n "$APKO" lock "$(basename '
        '"$rendered")" --cache-dir "$tmp/apko-cache" --output "$full" >"$tmp/apko.err" 2>&1 && rc=0 || rc=$?',
        'cd "$root"',
        'cat "$tmp/apko.err" >&2',
        '[ "$rc" != 0 ] && grep -Eqi -e \'ENETUNREACH|network is unreachable|dial tcp|no such host|no route to host\' '
        '-e \'connection refused|network request blocked|name resolution|Name or service not known|could not resolve '
        'host\' "$tmp/apko.err" 2>/dev/null && probe=0 || probe=',
        '[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?',
        '"$PY3" -I -B bin/oci-digest.py apko-verdict lock "$rc" "$probe"',
        '"$BASHBIN" bin/apko-lock.sh compare "$baselock" "$full" --apk "$pkg" || { echo "assemble-image.sh: the full '
        'lock\'s package entries differ from the base lock (see above);" "not building" >&2; exit 2; }',
        '"$BASHBIN" bin/apko-lock.sh arch-check "$full" || { echo "assemble-image.sh: the full lock resolves '
        'different versions per architecture (see above);" "not building" >&2; exit 2; }',
        '"$BASHBIN" bin/apko-lock.sh verify-archive --lock "$full" --archive "$archive" --melange-repo "$melrepo" '
        '--index-record "$idxrec" || { echo "assemble-image.sh: the full lock does not verify against the archive and '
        'the melange repository" "(see above)" >&2; exit 2; }',
        'cp "$full" "$out/$variant.full.lock.json"',
        'mkdir -p "$tmp/sbom"   # apko renames its SBOMs into --sbom-path and does not create it (real-run finding)',
        'cd "$rdir"',
        '"$SUDO" "$ENVBIN" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$UNSHARE" -n "$APKO" build "$(basename '
        '"$rendered")" "$pkg:$version" "$tmp/$variant.tar" --offline --cache-dir "$tmp/apko-cache" --lockfile "$full" '
        '--vcs=false --sbom-path "$tmp/sbom" --build-date "$build_date" >"$tmp/apko.err" 2>&1 && rc=0 || rc=$?',
        'cd "$root"',
        'cat "$tmp/apko.err" >&2',
        '[ "$rc" != 0 ] && grep -Eqi -e \'ENETUNREACH|network is unreachable|dial tcp|no such host|no route to host\' '
        '-e \'connection refused|network request blocked|name resolution|Name or service not known|could not resolve '
        'host\' "$tmp/apko.err" 2>/dev/null && probe=0 || probe=',
        '[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?',
        '"$PY3" -I -B bin/oci-digest.py apko-verdict build "$rc" "$probe"',
        '"$PY3" -I -B bin/oci-digest.py unpack "$tmp/$variant.tar" "$out/$variant" "$out/$variant.digest" '
        '"$out/$variant.manifests" || { echo "assemble-image.sh: the image layout is unusable (see above)" >&2; exit '
        '1; }',
        'sbomsrc=$("$PY3" -I -B bin/oci-digest.py pick-sbom "$tmp/sbom")',
        'mkdir -p "$out/$variant-sbom"',
        'cp "$sbomsrc" "$out/$variant-sbom/sbom.json"',
        'echo "assembled $variant $version: $(cat "$out/$variant.digest")"',
    ],
    'bin/build-apk.sh': [
        'set -euo pipefail',
        'PY3=/usr/bin/python3            # TEST-SUBST',
        'GIT=/usr/bin/git                # TEST-SUBST',
        'SUDO=/usr/bin/sudo              # TEST-SUBST',
        'UNSHARE=/usr/bin/unshare        # TEST-SUBST',
        'MELANGE=/usr/local/bin/melange  # TEST-SUBST (the chain installs it there)',
        'GO_TOOL=/usr/local/bin/fscache-go/bin/go  # TEST-SUBST (bin/install-scanner.sh go puts the pinned toolchain '
        'there)',
        'SHA256SUM=/usr/bin/sha256sum    # TEST-SUBST',
        'ENVBIN=/usr/bin/env             # TEST-SUBST',
        'SEALED_ENV=build/sealed-env.json  # TEST-SUBST',
        'RECIPE_STANDARD=$PWD/build/melange.yaml  # TEST-SUBST',
        'RECIPE_FIPS=$PWD/build/melange-fips.yaml  # TEST-SUBST',
        'FIPS_MODULE=$PWD/build/locks/fips-module.txt  # TEST-SUBST (the module the FIPS build uses; the daily '
        'refresh sets it)',
        '[ -f bin/build-apk.sh ] && [ -f bin/build-apk-helper.py ] && [ -f build/sealed-env.json ] || { echo '
        '"build-apk.sh: run bin/build-apk.sh from the repository root" "(its helpers are named by repo-relative '
        'paths)" >&2; exit 2; }',
        'root_=$PWD',
        'mode=$("$PY3" -I -B bin/build-apk-helper.py check-args "$(uname -s)" "$(uname -m)" "$@")',
        'src=$("$PY3" -I -B bin/build-apk-helper.py arg src "$@")',
        '[ "$mode" != sde ] || "$GIT" -C "$src" log -1 --format=%ct 2>/dev/null | grep -E \'^[0-9]+$\' || { echo '
        '"build-apk.sh: $src has no git history" >&2; exit 2; }',
        '[ "$mode" != sde ] || exit 0',
        'variant=$("$PY3" -I -B bin/build-apk-helper.py arg variant "$@")',
        'arch=$("$PY3" -I -B bin/build-apk-helper.py arg arch "$@")',
        'goarch=$("$PY3" -I -B bin/build-apk-helper.py arg goarch "$@")',
        'version=$("$PY3" -I -B bin/build-apk-helper.py arg version "$@")',
        'apkver=$("$PY3" -I -B bin/build-apk-helper.py arg apkver "$@")',
        'build_date=$("$PY3" -I -B bin/build-apk-helper.py arg build-date "$@")',
        'repo=$("$PY3" -I -B bin/build-apk-helper.py arg repo "$@")',
        'keyring=$("$PY3" -I -B bin/build-apk-helper.py arg keyring "$@")',
        'goarch_dir=$("$PY3" -I -B bin/build-apk-helper.py arg go-archive "$@")',
        'mlock=$("$PY3" -I -B bin/build-apk-helper.py arg melange-lock "$@")',
        'out=$("$PY3" -I -B bin/build-apk-helper.py arg out "$@")',
        'render=$("$PY3" -I -B bin/build-apk-helper.py arg render-dir "$@")',
        'apkcache=$("$PY3" -I -B bin/build-apk-helper.py arg apk-cache-dir "$@")',
        'assembly_key=$PWD/build/keys/assembly.rsa',
        '[ -f "$assembly_key" ] || { echo "build-apk.sh: the committed assembly key $assembly_key is missing" >&2; '
        'exit 2; }',
        'if [ "$variant" = fips ]; then recipe=$RECIPE_FIPS; else recipe=$RECIPE_STANDARD; fi',
        '[ -f "$recipe" ] || { echo "build-apk.sh: recipe not found: $recipe" >&2; exit 2; }',
        'recipe=$("$PY3" -I -B bin/build-apk-helper.py abs-file "$recipe")',
        'mkdir -p "$out"',
        '[ -z "$render" ] || mkdir -p "$render"',
        'tmp=$(mktemp -d)',
        'trap \'rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1 || true\' EXIT',
        '"$PY3" -I -B bin/build-apk-helper.py recipe-facts "$recipe" "$goarch" "$tmp/recipe.facts" || { echo '
        '"build-apk.sh: cannot read the recipe $recipe" >&2; exit 2; }',
        'pkg=$(sed -n \'s/^name=//p\' "$tmp/recipe.facts")',
        'gofile=$(sed -n \'s/^file=//p\' "$tmp/recipe.facts")',
        'gosha=$(sed -n \'s/^sha=//p\' "$tmp/recipe.facts")',
        '[ -f "$goarch_dir/$gofile" ] || { echo "build-apk.sh: the Go archive $goarch_dir has no $gofile" "(rule 12: '
        'Go comes from the archive)" >&2; exit 2; }',
        '[ -x "$SHA256SUM" ] || { echo "build-apk.sh: sha256sum is not installed at $SHA256SUM" >&2; exit 1; }',
        'got=$("$SHA256SUM" "$goarch_dir/$gofile" | cut -d\' \' -f1)',
        '[ "$got" = "$gosha" ] || { echo "build-apk.sh: sha256 checksum of $gofile ($got) differs from the recipe\'s '
        'pin ($gosha)" >&2; exit 2; }',
        'sed -n \'s/^pin=//p\' "$tmp/recipe.facts" >"$tmp/pins"',
        'missing=$(grep -Fxv -f "$mlock" "$tmp/pins" | head -n 1 || true)',
        '[ -z "$missing" ] || { echo "build-apk.sh: the recipe pins $missing but the melange lock $mlock does not '
        'have it;" "the recipe and the lock must agree" >&2; exit 2; }',
        'extra=$(grep -v \'^$\' "$mlock" | grep -Fxv -f "$tmp/pins" || true)',
        '[ -z "$extra" ] || { echo "build-apk.sh: the melange lock $mlock has lines the recipe does not pin" '
        '"($(printf \'%s\' "$extra" | head -n 3 | tr \'\\n\' \' \')): the recipe and the lock must agree both ways" '
        '>&2; exit 2; }',
        'rdir=${render:-$tmp/render}; mkdir -p "$rdir"',
        'rendered=$rdir/$(basename "$recipe")',
        'sed "s/@VERSION@/$apkver/g" "$recipe" >"$rendered"',
        'mkdir -p "$tmp/cache"; cp "$goarch_dir/$gofile" "$tmp/cache/sha256:$gosha"',
        'excl=$("$GIT" -C "$src" rev-parse --path-format=absolute --git-path info/exclude 2>/dev/null) || { echo '
        '"build-apk.sh: cannot locate the exclude file of $src (git rev-parse failed)" >&2; exit 1; }',
        'exdir=${excl%/*}',
        'mkdir -p "$exdir" 2>/dev/null || true   # a checkout made with an empty template has no info/ directory',
        '"$PY3" -I -B bin/build-apk-helper.py exclude-file "$excl" "$exdir"',
        'margs=(build "$(basename "$rendered")" --arch "$arch" --runner bubblewrap --namespace fosterstack',
        '  --signing-key "$assembly_key"',
        '  --keyring-append "$keyring" --repository-append "$repo" --build-date "$build_date"',
        '  --cache-dir "$tmp/cache" --source-dir "$src" --out-dir "$out")',
        '[ -z "$apkcache" ] || margs+=(--apk-cache-dir "$apkcache")',
        'melange_bin=$MELANGE; [ -x "$melange_bin" ] || { echo "build-apk.sh: melange is not installed (the chain '
        'installs it before this step)" >&2; exit 1; }',
        'mapfile -d \'\' -t sealed < <("$PY3" -I -B bin/build-apk-helper.py sealed-env "$SEALED_ENV")',
        '[ "${#sealed[@]}" -ge 4 ] || { echo "build-apk.sh: the sealed environment could not be made" '
        '"(build/sealed-env.json, SOURCE_DATE_EPOCH)" >&2; exit 1; }',
        'call=("$ENVBIN" -i "${sealed[@]}" "$UNSHARE" -n "$melange_bin" "${margs[@]}")',
        'why=$("$PY3" -I -B bin/build-apk-helper.py sealed-call --sealed-env "$SEALED_ENV" "${call[@]}" 2>&1) || { '
        'echo "build-apk.sh: refusing the melange call: $why" >&2; exit 2; }',
        '"$SUDO" sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null 2>&1 ||',
        '  echo "build-apk.sh: warning: could not relax kernel.apparmor_restrict_unprivileged_userns" "(not needed '
        'off Ubuntu 24.04)" >&2',
        'cd "$rdir"',
        '"$SUDO" "${call[@]}" 2>"$tmp/melange.err" && rc=0 || rc=$?',
        'cd "$root_"',
        'cat "$tmp/melange.err" >&2',
        'probe=',
        '[ "$rc" != 0 ] && grep -Eqi -e \'ENETUNREACH|network is unreachable|dial tcp|no such host|name resolution\' '
        '-e \'Name or service not known|could not resolve host\' "$tmp/melange.err" 2>/dev/null && probe=0 || probe=',
        '[ -z "$probe" ] || "$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || probe=$?',
        '"$PY3" -I -B bin/build-apk-helper.py melange-verdict "$rc" "$probe"',
        'apk=$out/$arch/$pkg-$apkver-r0.apk',
        'vsfx=; [ "$variant" = fips ] && vsfx=-fips   # standard and fips build into ONE --out: the fips files must '
        'not overwrite',
        '[ -f "$apk" ] || { echo "build-apk.sh: melange did not produce $apk" >&2; exit 1; }',
        'signer=$("$PY3" -I -B bin/apk-tool.py signer "$apk") || { echo "build-apk.sh: cannot read the signer of '
        '$apk" >&2; exit 1; }',
        '[ "$signer" = assembly.rsa.pub ] || { echo "build-apk.sh: $apk is signed by \'$signer\', not '
        'assembly.rsa.pub:" "the assembly key is the only build signer" >&2; exit 1; }',
        '"$PY3" -I -B bin/apk-tool.py verify "$apk" build/keys/assembly.rsa.pub >/dev/null || { echo "build-apk.sh: '
        'the signature of $apk does not verify against the committed build/keys/assembly.rsa.pub:" "the apk is not '
        'signed with the assembly key" >&2; exit 1; }',
        '"$PY3" -I -B bin/apk-tool.py cat "$apk" usr/share/fscache/buildinfo.txt >"$tmp/buildinfo.txt" || { echo '
        '"build-apk.sh: $apk has no usr/share/fscache/buildinfo.txt" >&2; exit 1; }',
        '"$PY3" -I -B bin/build-apk-helper.py check-buildinfo "$tmp/buildinfo.txt" "$version"',
        'headrev=$("$GIT" -C "$src" rev-parse HEAD 2>/dev/null) || { echo "build-apk.sh: cannot read the source HEAD '
        'of $src" >&2; exit 1; }',
        '"$PY3" -I -B bin/build-apk-helper.py check-revision "$tmp/buildinfo.txt" "$headrev" "$variant" "$FIPS_MODULE"',
        '"$PY3" -I -B bin/apk-tool.py cat "$apk" usr/bin/fscache >"$tmp/fscache.bin" || { echo "build-apk.sh: $apk '
        'has no usr/bin/fscache" >&2; exit 1; }',
        'gorc=127; gov=',
        '[ ! -x "$GO_TOOL" ] || gorc=0',
        '[ "$gorc" != 0 ] || gov=$("$ENVBIN" GOTOOLCHAIN=local GOFLAGS= GOENV=off "$GO_TOOL" version -m '
        '"$tmp/fscache.bin" 2>"$tmp/go.err") || gorc=$?',
        'printf \'%s\\n\' "$gov" >"$tmp/go.out"',
        '"$PY3" -I -B bin/build-apk-helper.py go-verdict "$gorc" "$tmp/go.out" "$tmp/buildinfo.txt" "$tmp/go.err"',
        '"$PY3" -I -B bin/go-module-sbom.py --modules "$src/vendor/modules.txt" --provenance '
        '"$src/dependency-provenance.json" --buildinfo "$tmp/buildinfo.txt" --name '
        '"$pkg" --version "$apkver" --out "$out/fscache-modules$vsfx.spdx.json" || { echo "build-apk.sh: the Go module list does not match the binary '
        '(see above)" >&2; exit 1; }',
        '"$PY3" -I -B bin/apk-tool.py inputs-manifest --apk "$apk" --melange-lock "$mlock" --out '
        '"$out/inputs-manifest$vsfx.json" || { echo "build-apk.sh: the inputs manifest could not be made (see above)" '
        '>&2; exit 1; }',
        'echo "built $apk"',
    ],
    'bin/build-stage-refuse-mode.sh': [
        'set -euo pipefail',
        'case "${1-}" in',
        '  release|snapshot) ;;',
        '  *) echo "::error::mode must be release or snapshot" >&2; exit 1 ;;',
        'esac',
    ],
}


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
