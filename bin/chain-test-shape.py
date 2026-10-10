"""Test infrastructure (not product code), shared by bin/chain-build-wiring-test.sh and bin/chain-rebuild-test.sh: the judges for
the shape of the Build and Rebuild stage files, the four stage scripts, the job graph of release.yml and the environment record of
a Witness collection. Each judge prints `ok` or the list of faults and exits 1 on any fault; the tests first prove every judge on a
known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then apply it to the real repository (RED until
PR 2 is implemented).

DESIGN RULE (PR 1's ten lost rounds): NO denylists, NO shell analysis, NO subsequence checks. Every judge below is a FINITE EXACT
GRAMMAR over an allowlist: a stage file is exactly the steps in JOBS, a stage script is exactly the lines of expected_lines(KIND),
the job graph is exactly the keys and targets in CHAIN. Anything else is a fault by construction.

  helper FILE                               REQ-CHAIN-004-AC2 (the Witness seam): bin/witnessed.sh is exactly the canonical helper, `timeout 540` included
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


def version_check(variant):
    return ('python3 bin/build-version-check.py --apk-dir "out/$(uname -m)" --variant %s --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA"' % variant)


def verify_records(stage, rec_dir, record):
    return ["python3 bin/chain-verify.py verify --stage %s --record %s/%s/%s --policy policy.json" % (stage, rec_dir, r, record) for r, a in RUNNERS]


def bind_files(step, rec_dir, record, apk_dir):
    """Every file of each downloaded apk artifact must be the product the verified record holds under the same name (rule 58)."""
    return ["python3 bin/chain-verify.py bind --step %s --record %s/%s/%s --dir %s/%s --as out" % (step, rec_dir, r, record, apk_dir, r)
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
                version_check("standard"), version_check("fips"), items_apk()])
    if kind == "assemble":
        return ([H, POLICY] + verify_records("build", "rec-apk", "apk-collection.json") + bind_files("apk", "rec-apk", "apk-collection.json", "apk")
                + melange_repo("apk") + SDE + [image_cmd("production"), image_cmd("fips"), archives(),
                merge("apk", "--digests digests.json --items items.json")])
    if kind == "snapshot-apk":       # no admission, no version check, no tag: the version is the fixed snapshot one
        return ([H] + SNAPSHOT_TAG_LINES + SDE
                + [apk_cmd("standard", SNAPSHOT_VERSION), apk_cmd("fips", SNAPSHOT_VERSION), items_apk()])
    if kind == "snapshot-assemble":  # no policy and no verify (a snapshot record is refused by every verifier): the bind is the only link to the record
        return ([H] + bind_files("snapshot-apk", "rec-apk", "snapshot-apk-collection.json", "apk") + melange_repo("apk") + SDE
                + [image_cmd("production", SNAPSHOT_VERSION), image_cmd("fips", SNAPSHOT_VERSION), archives(SNAPSHOT_VERSION),
                   merge("apk", "--digests digests.json --items items.json", SNAPSHOT_VERSION)])
    if kind == "snapshot-rebuild-apk":      # the same local-tag discipline as the snapshot Build; no policy, no stage-start (a snapshot record is refused)
        return ([H] + SNAPSHOT_TAG_LINES + SDE
                + [apk_cmd("standard", SNAPSHOT_VERSION), apk_cmd("fips", SNAPSHOT_VERSION), items_apk()])
    if kind == "snapshot-rebuild-assemble":     # --snapshot makes rebuild-compare accept exactly Build's snapshot-build record and nothing else
        return ([H] + bind_files("snapshot-rapk", "rec-rapk", "snapshot-rapk-collection.json", "rapk") + melange_repo("rapk") + SDE
                + [image_cmd("production", SNAPSHOT_VERSION), image_cmd("fips", SNAPSHOT_VERSION), archives(SNAPSHOT_VERSION),
                   merge("rapk", "--items items.json", SNAPSHOT_VERSION),
                   "python3 bin/chain-verify.py rebuild-compare --snapshot --build-record witness-build/snapshot-build-collection.json "
                   "--expected build-in/items.json --actual items.json --out %s" % SNAPSHOT_VERDICT])
    if kind == "rebuild-apk":
        return [H, POLICY, START] + SDE + [apk_cmd("standard"), apk_cmd("fips"), items_apk()]
    if kind == "rebuild-assemble":
        return ([H, POLICY] + verify_records("rebuild", "rec-rapk", "rapk-collection.json") + [START]
                + bind_files("rapk", "rec-rapk", "rapk-collection.json", "rapk") + melange_repo("rapk") + SDE
                + [image_cmd("production"), image_cmd("fips"), archives(), merge("rapk", "--items items.json"),
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
CHECKOUT_WITH = {"persist-credentials": "false", "fetch-depth": "0", "fetch-tags": "true"}
PERM_PLAIN = {"contents": "read", "id-token": "write"}
PERM_ADMIT = {"contents": "read", "checks": "read", "statuses": "read", "pull-requests": "read", "id-token": "write"}
MAT = "${{ matrix.runner }}"
# Build hands Sign the digests.json text: the stage output reads the assemble job's output, which one pinned step fills from digests.json
STAGE_OUTPUT = "${{ jobs.assemble.outputs.digests }}"
JOB_OUTPUT = "${{ steps.digests.outputs.digests }}"
MODE_RELEASE_IF = "${{ inputs.mode == 'release' }}"
MODE_SNAPSHOT_IF = "${{ inputs.mode == 'snapshot' }}"
MODE_GUARD_ENV = {"MODE": "${{ inputs.mode }}"}
# The guard compares in bash, case-sensitively, on purpose: GitHub's `==` in an expression is case-insensitive (inputs.mode == 'Snapshot' is true), so the
# guard is load-bearing, not redundant: a looser one would let a mixed-case mode skip both Witness steps.
MODE_GUARD_RUN = 'case "$MODE" in release|snapshot) ;; *) echo "::error::mode must be release or snapshot" >&2; exit 1 ;; esac'
# the closed list of snapshot step names
SNAPSHOT_STEP = {"apk": "snapshot-apk", "build": "snapshot-build", "rapk": "snapshot-rapk", "rebuild": "snapshot-rebuild"}
SNAPSHOT_VERDICT = "witness-rebuild/snapshot-verdict.json"       # a snapshot Rebuild's verdict: named, so it can never be mistaken for a release verdict
HOSTILE_IF = "${{ inputs.hostile }}"
HOSTILE_RUN = "bash bin/chain-hostile-step.sh"
HOSTILE_UP = {"name": "hostile-attempts", "path": "attempts", "if-no-files-found": "error"}
EXPOSE = 'echo "digests=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"'
JOBS = {  # (family, job) -> spec; every step list is EXACT and in this order. An upload names ONE path (the artifact is rooted at it).
    ("build", "apk"): dict(kind="apk", step="apk", perm=PERM_ADMIT, gh=True, matrix=True, down=[], mode=True,
        up=[("apk-" + MAT, "out"), ("witness-apk-" + MAT, "witness-apk")]),
    ("build", "assemble"): dict(kind="assemble", step="build", perm=PERM_PLAIN, gh=False, matrix=False, expose=True, hostile=True, mode=True,
        down=[("apk-" + r, "apk/" + r) for r, a in RUNNERS] + [("witness-apk-" + r, "rec-apk/" + r) for r, a in RUNNERS],
        up=[("witness-build", "witness-build"), ("digests", "digests.json"), ("items", "items.json"), ("dist", "dist"), ("images", "out")]),
    ("rebuild", "apk"): dict(kind="rebuild-apk", step="rapk", perm=PERM_PLAIN, gh=False, matrix=True, mode=True,
        down=[("witness-build", "witness-build"), ("digests", "build-in")],
        up=[("rapk-" + MAT, "out"), ("witness-rapk-" + MAT, "witness-rapk")]),
    ("rebuild", "assemble"): dict(kind="rebuild-assemble", step="rebuild", perm=PERM_PLAIN, gh=False, matrix=False, mode=True,
        down=[("witness-build", "witness-build"), ("digests", "build-in"), ("items", "build-in")]
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
                 if family == "build" else {"inputs": {"mode": mode_input}})
    if isinstance(call, dict):       # a description is free text
        call = {k: {n: ({a: b for a, b in v.items() if a != "description"} if isinstance(v, dict) else v) for n, v in call[k].items()}
                if isinstance(call[k], dict) else call[k] for k in call}
    if not isinstance(on, dict) or set(on) != {"workflow_call"} or (call or None) != want_call:
        bad.append("on: must be exactly workflow_call with %s, got %s"
                   % ("the inputs hostile (boolean, default false; the dry run's hostile Build step) and mode (string, default release; release or snapshot) "
                      "and the one output digests = %s" % STAGE_OUTPUT
                      if family == "build" else "the one input mode (string, default release; release or snapshot) and no secrets or outputs", on))
    if d.get("permissions") != {"contents": "read"}:
        bad.append("workflow permissions must be exactly contents: read, got %s" % d.get("permissions"))
    if re.search(r"\bwitness\s+run\b", text): bad.append("the stage file names `witness run` directly (every stage goes through bin/witnessed.sh)")
    jobs = d.get("jobs") or {}
    if set(jobs) != {"apk", "assemble"}:
        return bad + ["exactly two jobs required, apk and assemble (one stage = one file = one identity), found %s" % sorted(jobs)]
    allowed = None
    if allowed_path:
        try:
            allowed = set(json.load(open(allowed_path)).get("actions", []))
        except (OSError, ValueError):
            bad.append("the allowed-actions list %s is unreadable (fail closed)" % allowed_path)
    for name in ("apk", "assemble"):
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
    keys = {"runs-on", "permissions", "steps", "timeout-minutes"} | ({"strategy"} if spec["matrix"] else {"needs"})
    if spec.get("expose"): keys.add("outputs")
    if set(j) - keys:
        bad.append("job keys outside the allowlist: %s" % sorted(set(j) - keys))
    if {"runs-on", "permissions", "steps"} - set(j):
        bad.append("job lacks %s" % sorted({"runs-on", "permissions", "steps"} - set(j)))
    for k in ("container", "services", "env", "defaults", "environment", "outputs", "if", "continue-on-error", "uses", "secrets"):
        if k in j and not (k == "outputs" and spec.get("expose")): bad.append("job has %s" % k)
    if spec.get("expose") and j.get("outputs") != {"digests": JOB_OUTPUT}:
        bad.append("the assemble job must expose exactly outputs: digests: %s, got %s" % (JOB_OUTPUT, j.get("outputs")))
    if spec["matrix"]:
        st = j.get("strategy") or {}
        if j.get("runs-on") != MAT:
            bad.append("the apk job must run on matrix.runner, got %r" % j.get("runs-on"))
        runners = sorted(((st.get("matrix") or {}).get("runner")) or [])
        if set(st) - {"matrix", "fail-fast"} or set(st.get("matrix") or {}) != {"runner"} or runners != sorted(r for r, a in RUNNERS):
            bad.append("strategy must be exactly matrix.runner: both of %s (native runners, no emulation, no include/exclude)" % [r for r, a in RUNNERS])
    else:
        if j.get("runs-on") != "ubuntu-24.04": bad.append("the assemble job must run directly on the ubuntu-24.04 VM (rule 62), got %r" % j.get("runs-on"))
        if j.get("needs") not in ("apk", ["apk"]): bad.append("assemble must need exactly apk, got %s" % j.get("needs"))
    if j.get("permissions") != spec["perm"]:
        bad.append("permissions must be exactly %s, got %s" % (spec["perm"], j.get("permissions")))
    steps = j.get("steps") or []
    if len(steps) < 3: return bad + ["fewer than three steps"]
    if allowed is not None:
        for s_ in steps:
            u_ = (s_.get("uses") or "").split(" ")[0]
            if PIN.match(u_) and u_ not in allowed: bad.append("action %s is not on the allowed-actions list" % u_)
    i = 0
    s = steps[i]; i += 1
    if set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/checkout", allowed) or (s.get("with") or {}) != CHECKOUT_WITH:
        bad.append("step 1 must be a digest-pinned actions/checkout (on the allowed list) with exactly %s" % CHECKOUT_WITH)
    if spec.get("mode"):         # a mode that is neither release nor snapshot would skip both Witness steps and upload nothing, green: refuse it first
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"name", "env", "run"} or s.get("env") != MODE_GUARD_ENV or str(s.get("run") or "").strip() != MODE_GUARD_RUN:
            bad.append("step %d must be exactly env %s, run: %s (the mode guard)" % (i, MODE_GUARD_ENV, MODE_GUARD_RUN))
    s = steps[i] if i < len(steps) else {}; i += 1
    if set(s) - {"run", "name"} or str(s.get("run") or "").strip() != "./bin/install-scanner.sh witness":
        bad.append("step 2 must be exactly: run ./bin/install-scanner.sh witness (checksum-pinned Witness install)")
    for nm, path_ in spec["down"]:
        s = steps[i] if i < len(steps) else {}; i += 1
        if (set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/download-artifact", allowed)
                or (s.get("with") or {}) != {"name": nm, "path": path_}):
            bad.append("step %d must be a pinned actions/download-artifact with exactly name %s and path %s "
                       "(a fresh named directory, never . or bin/ or .github/)" % (i, nm, path_))
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
        if (set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/upload-artifact", allowed)
                or (s.get("with") or {}) != {"name": nm, "path": path_}):
            bad.append("step %d must be a pinned actions/upload-artifact with exactly name %s and the ONE path %s "
                       "(the artifact is rooted at its common ancestor, so a second path changes every file name in it)" % (i, nm, path_))
    if i != len(steps):
        bad.append("%d steps, the grammar has %d (no extra step)" % (len(steps), i))
    return bad


# ---- THE RULE 68 SEAM (three functions) -----------------------------------------------------------------------------------------------
STEPS = ("apk", "build", "rapk", "rebuild",
         "snapshot-apk", "snapshot-build", "snapshot-rapk", "snapshot-rebuild")      # the closed list; the record is witness-DIR/STEP-collection.json
# (DIR is STEP without a leading snapshot-, so a snapshot job uploads the same directories as a release job; the file name carries the snapshot marker)
# The identity token reaches Witness through a one-read process substitution, so no file holds it while the wrapped command runs (Witness loads its
# signer before it runs the command: in-toto-witness cmd/run.go:51). SOURCE-CHECKED, one read: in-toto-witness cmd/keyloader.go:85 and
# go-witness signer/fulcio/fulcio.go:295-300 read the path with a single os.ReadFile. DOCUMENTED FALLBACK if that ever changes: write the token to a file
# and delete it before
# the command starts, which is not possible with `exec witness run`, so the fallback is the older file form (a token file under $RUNNER_TEMP):
#   curl ... -o "$RUNNER_TEMP/tok.json"; jq -r .value "$RUNNER_TEMP/tok.json" > "$RUNNER_TEMP/tok"; echo "::add-mask::$(cat "$RUNNER_TEMP/tok")"
#   with --signer-fulcio-token-path "$RUNNER_TEMP/tok". Changing to it changes only TOKEN and TOKEN_PATH below.
TOKEN = [
    'tok=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)',
    'echo "::add-mask::$tok"',
]
TOKEN_PATH = '<(printf %s "$tok")'
SENSITIVE = ["ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]   # never github (raw OIDC token) or slsa (Sign's alone)


def witnessed_lines():
    """The exact lines of bin/witnessed.sh (backslash continuations are joined before comparing: the committed file may break the long line)."""
    keys = " ".join("--env-add-sensitive-key %s" % ("'%s'" % k if "*" in k else k) for k in SENSITIVE)
    return ["set -euo pipefail", 'step="$1"', "shift",
            'case "$step" in apk|build|rapk|rebuild|snapshot-apk|snapshot-build|snapshot-rapk|snapshot-rebuild) ;; '
            '*) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac',
            'mkdir -p "witness-${step#snapshot-}"'] + TOKEN + [
            "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL",
            "unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL",
            'exec witness run --step "$step" --signer-fulcio-url https://fulcio.sigstore.dev '
            "--signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com --signer-fulcio-oidc-client-id sigstore "
            "--signer-fulcio-token-path %s -t https://timestamp.sigstore.dev/api/v1/timestamp "
            "-a environment,git,material,product --env-filter-sensitive-vars %s "
            '-o "witness-${step#snapshot-}/$step-collection.json" -- timeout 540 bash "$@"' % (TOKEN_PATH, keys)]


def witness_seam(run, spec, family):
    """1/3: the stage's Witness step is exactly ONE line through the helper, with the step name of its job and the committed script of its kind."""
    want = "bash bin/witnessed.sh %s bin/build-stage-%s.sh" % (spec["step"], spec["kind"])
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
        if re.search(r"\bapko\b", json.dumps(d)):
            bad.append("%s: names apko (only bin/assemble-image.sh may run it, always with the lock)" % f)
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


# ---- release.yml --------------------------------------------------------------------------------------------------------------------
CHAIN = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml", "check": "stage-verify.yml",
         "release": "stage-promote.yml"}
NEEDS = {"build": [], "sign": ["build"], "rebuild": ["build"], "check": ["build"], "release": ["check", "rebuild", "sign"]}


# The `if` of the chain jobs (REQ-CHAIN-005-AC5). ONE gate G, the same exact text on build and sign: the chain starts on a v* tag PUSH, or in a dry-run
# dispatch on any branch. (A manual workflow_dispatch on an existing v* tag is therefore NOT a release run: its event is not push and its dry-run is
# not true.) rebuild and check carry no if: they run after build through needs. release carries exactly !inputs.dry-run (a dry run neither tags
# nor publishes; on a tag push inputs.dry-run is null, so it runs). No !cancelled(), no needs.admission: admission is gone in PR 2's graph and
# build needs nothing. PR 1's release.yml has other strings (`!inputs.dry-run && ...` conjuncts on other jobs, `if: ${{ inputs.dry-run }}` on sign):
# at the merge of PR 1 into chain-v030 they are replaced by these.
GATE = "${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}"
RELEASE_IF = "${{ !inputs.dry-run }}"
GATED = ("build", "sign")      # sign runs in a release and in a dry run, so it carries the same gate G (Build hands it the digests)
BUILD_WITH = {"hostile": "${{ inputs.dry-run == true && github.ref_type == 'branch' }}"}
SIGN_PERMISSIONS = {"contents": "read", "id-token": "write"}
# PR 1's stage-sign.yml takes exactly ONE input, digests (Build's record is downloaded by the fixed artifact name witness-build, not passed). PR 1's
# placeholder needs.build.outputs.checksums (raw checksums.txt text) is replaced at the cutover by Build's digests output, the digests.json text.
SIGN_WITH = {"digests": "${{ needs.build.outputs.digests }}"}

# The jobs of release.yml that are not chain jobs, each a finite spec: its exact permissions, whether it may name `environment: agent` and `secrets.`
# (the auditor App's secrets live in that environment, main only), and the exact `needs` / `if` where they matter. decide, patch-notes and
# patch-failed exist today (automatic patch releases, REQ-REL-009); the hostile-* jobs are PR 1's dry-run proof (contents: read, no environment,
# no secrets). Anything else is a way to publish around Rebuild or Check.
PATCH_NOTES_IF = "${{ needs.decide.outputs.tagged == 'true' }}"
DECIDE_IF = "${{ github.ref == 'refs/heads/main' && github.event_name != 'workflow_dispatch' && !inputs.dry-run }}"
NON_CHAIN = {
    "decide": {"perm": {"contents": "read", "checks": "read", "id-token": "write", "issues": "write"}, "agent": True, "if": DECIDE_IF},
    "patch-notes": {"perm": {"contents": "read"}, "agent": True, "needs": ["decide"], "if": PATCH_NOTES_IF},
    "patch-failed": {"perm": {"contents": "read", "issues": "write"}, "agent": False, "needs": sorted(CHAIN)},
}
HOSTILE = {"perm": {"contents": "read"}, "agent": False}


def needs_of(job):
    needs = job.get("needs")
    return [] if needs is None else ([needs] if isinstance(needs, str) else list(needs))


def graph(path):
    d = yaml.load(read_exact(path), Loader=yaml.BaseLoader)
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
        extra = set(job) - {"uses", "needs", "permissions", "with", "if"}
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
            bad.append("build must pass exactly with: %s (the hostile Build step runs only in a dry run on a branch), got %s" % (BUILD_WITH, job.get("with")))
        if name == "sign":
            if job.get("permissions") != SIGN_PERMISSIONS:
                bad.append("sign must hold exactly the permissions %s, got %s" % (SIGN_PERMISSIONS, job.get("permissions")))
            with_ = job.get("with") or {}
            if with_ != SIGN_WITH:
                bad.append("sign must pass exactly with: %s (the digests.json text of build's output; stage-sign.yml takes no other input), got %s"
                           % (SIGN_WITH, with_))
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
        spec = HOSTILE if name.startswith("hostile-") else NON_CHAIN.get(name)
        if spec is None:
            bad.append("job %s is not one of the five chain jobs or the allowed non-chain jobs %s plus hostile-*" % (name, sorted(NON_CHAIN)))
            continue
        if granted != spec["perm"]:
            bad.append("job %s must hold exactly the permissions %s, got %s" % (name, spec["perm"], granted))
        if spec["agent"]:
            if job.get("environment", "agent") != "agent":
                bad.append("job %s may name only environment: agent, got %r" % (name, job["environment"]))
        else:
            if "environment" in job: bad.append("job %s may not name an environment (the App secrets live in agent), got %r" % (name, job["environment"]))
            if "secrets." in json.dumps(job): bad.append("job %s may not use secrets. (only decide and patch-notes hold the App's)" % name)
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
# workflow the only jobs that carry a job-level `uses` are these, each calling EXACTLY the file named, whatever the form. artifact-acceptance is what
# scan.yml legitimately calls today that is not Release (cache's job; PR 3, Check, moves it); main-candidate-rescan.yml calls Build only.
CALLER_ALLOWLIST = {"build": "./.github/workflows/stage-build.yml", "rebuild": "./.github/workflows/stage-reproducibility.yml",
                    "artifact-acceptance": "./.github/workflows/stage-acceptance-artifacts.yml"}
NOT_IN_FILE = {"main-candidate-rescan.yml": ("rebuild", "artifact-acceptance")}
# scan.yml (the PR gate keeps rule 31's two-assembly reproducibility check) also calls Rebuild in snapshot mode after Build; main-candidate-rescan.yml does not
SNAPSHOT_REBUILD_PERMISSIONS = dict(PERM_PLAIN)
ACCEPTANCE_PERMISSIONS = {"contents": "read", "packages": "read"}       # scan.yml's artifact-acceptance grants at origin/chain-v030
# its two required inputs keep their names with NEW values (cache-3f, option b, approved by the advisor): the artifact is Build's `dist`, and the
# checksums input becomes the one-line digests JSON (it was the raw checksums.txt text). stage-acceptance-artifacts.yml's handling of that form is
# PR 3's change (Check absorbs it).
ACCEPTANCE_WITH = {"dist-artifact": "dist", "expected-checksums": "${{ needs.build.outputs.digests }}"}


def ceiling(job_name, perm):
    """A snapshot caller's grants are a STATIC CEILING: contents read, checks/statuses/pull-requests read, and id-token write (the one write, only because the
    called stage requests it). Any other write fails here, whatever the stage asks for."""
    if not isinstance(perm, dict):
        return []
    return ["job %s grants %s: write; the grants of a snapshot caller are a static ceiling (read only, id-token write as the stage requests)" % (job_name, k)
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
    acceptance = jobs.get("artifact-acceptance")
    if isinstance(acceptance, dict) and "uses" in acceptance and name != "main-candidate-rescan.yml":
        # what scan.yml calls today that is not Release (cache's job; PR 3, Check, moves it): the same ceiling and key check as the other calls
        if acceptance.get("permissions") != ACCEPTANCE_PERMISSIONS:
            bad.append("job artifact-acceptance must hold exactly the permissions %s, got %s" % (ACCEPTANCE_PERMISSIONS, acceptance.get("permissions")))
        bad += ceiling("artifact-acceptance", acceptance.get("permissions"))
        if needs_of(acceptance) != ["build"]:
            bad.append("job artifact-acceptance must need exactly build, got %s" % needs_of(acceptance))
        if acceptance.get("with") != ACCEPTANCE_WITH:
            bad.append("job artifact-acceptance must pass exactly with: %s, got %s" % (ACCEPTANCE_WITH, acceptance.get("with")))
        if set(acceptance) - {"uses", "permissions", "needs", "with"}:
            extra = sorted(set(acceptance) - {"uses", "permissions", "needs", "with"})
            bad.append("job artifact-acceptance: keys outside {uses, permissions, needs, with} (no secrets, no if): %s" % extra)
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
           "listed": lambda: listed(sys.argv[2], sys.argv[3]), "helper": lambda: helper(sys.argv[2]), "workflows": lambda: workflows(sys.argv[2]),
            "callers": lambda: callers(sys.argv[2]),
            "directwitness": lambda: directwitness(sys.argv[2:])}[cmd]()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
