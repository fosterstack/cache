#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC13, REQ-CHAIN-004-AC15 — a snapshot record, and anything carrying the snapshot version 0.0.0, is refused everywhere, by name
#
# Snapshot mode (REQ-CHAIN-004-AC12) lets the proof workflows (scan.yml, main-candidate-rescan.yml) build with no tag and no admission. Witness still signs
# the step, and the marker is the step name in the signed collection: snapshot-apk and snapshot-build (Build), snapshot-rapk and snapshot-rebuild (Rebuild),
# a closed list. So that a pull request's build can never be mistaken for a release build, EVERY reader of a record in bin/chain-verify.py (verify,
# stage-start, check-build-record, sign --check, record-env, and rebuild-compare through its --build-record) applies ONE RULE to the collection name,
# BEFORE it looks at a certificate, a signature or a timestamp: a name that is EXACTLY `snapshot-` followed by [a-z0-9_-]* (possibly nothing) is refused as
# a snapshot record; any other name that is not exactly a release name of that stage is refused by `collection name ...` (see the closed-name section below).
# The first says:
#
#     refused at <stage>: snapshot record
#
# where <stage> is the stage whose record it was (verify --stage S: S; stage-start: --previous; check-build-record, sign --check and record-env: build;
# rebuild-compare: rebuild). The stages and (stage, previous) pairs are read from chain-verify.py's own tables, so a new one needs a case. Nothing in
# this test needs a key, a network or OpenSSL beyond what `policy make` uses for the committed trust files: the fixtures are unsigned DSSE envelopes with
# one dummy signature entry, so a record named build gets past the name check and is refused LATER for what it is (a certificate that is not one). That is
# the control of every case: the same fixture named build is refused, but never as a snapshot record; a refusal that fires for both would prove nothing.
# The full acceptance of a genuine, signed build record is proven by bin/chain-verify-test.sh.
#
# SNAPSHOT VERSION (REQ-CHAIN-004-AC15, cache-3f's finding): a snapshot apk is built as version 0.0.0-rc.1 (fscache-0.0.0_rc1-r0.apk), so it could
# in principle be smuggled into a release by a record that was NOT named snapshot-*. A second, independent refusal covers that: every verifier also
# refuses a record whose product subjects name a file with the 0.0.0 version (an apk, the fips apk, an archive), `refused at <stage>: snapshot version`,
# and `policy make` refuses a tag whose X.Y.Z is 0.0.0 (v0.0.0, v0.0.0-rc.1), so no policy, hence no Sign or Release, can exist for it. The same fixture
# with 0.3.0 is the control.
#
# Needs: python3, the committed trust files under .github/policy (policy make reads them).
exec python3 - "$(cd "$(dirname "$0")/.." && pwd)" <<'PY'
import atexit, base64, importlib.util, json, os, shutil, subprocess, sys, tempfile

root = sys.argv[1]
CV = root + "/bin/chain-verify.py"
TEMPLATE = root + "/.github/policy/release-policy.template.json"
work = tempfile.mkdtemp()
atexit.register(shutil.rmtree, work, ignore_errors=True)
passed = failed = 0
PRODUCT = "https://witness.dev/attestations/product/v0.1/file:digests.json"


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print("ok   " + label)
    else:
        failed += 1
        print("FAIL %s %s" % (label, detail))


def run(args, env=None, timeout=60):
    """Run chain-verify.py from the work directory; (exit code, stdout, stderr). A missing script is an error, never a pass."""
    full_env = dict(os.environ, **(env or {}))
    try:
        r = subprocess.run(["python3", CV] + args, cwd=work, capture_output=True, text=True, timeout=timeout, env=full_env)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    return r.returncode, r.stdout, r.stderr


def record(path, name, files=()):
    """An unsigned DSSE envelope of a Witness collection called `name` whose product subjects also name `files`, with one dummy signature entry."""
    subjects = [{"name": PRODUCT, "digest": {"sha256": "a" * 64}}]
    subjects += [{"name": "https://witness.dev/attestations/product/v0.1/file:" + f, "digest": {"sha256": "b" * 64}} for f in files]
    statement = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
                 "subject": subjects, "predicate": {"name": name, "attestations": []}}
    envelope = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signatures": [{"sig": base64.b64encode(b"x").decode(), "certificate": base64.b64encode(b"x").decode()}]}
    with open(os.path.join(work, path), "w") as f:
        json.dump(envelope, f)


with open(work + "/digests.json", "w") as f:
    json.dump({"image-production": "sha256:" + "a" * 64}, f)
check("bin/chain-verify.py exists", os.path.exists(CV), "(every case below needs it)")
rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--tag", "v0.3.0", "--out", "policy.json"])
check("a policy for v0.3.0 is made from the committed template (the fixture of every case)", rc == 0 and os.path.exists(work + "/policy.json"), err[:120])

SIGN_ENV = {"GITHUB_REF": "refs/tags/v0.3.0", "GITHUB_EVENT_NAME": "push"}
# THE SUBCOMMANDS ARE GENERATED from chain-verify.py's own tables (step-6 round 1, both seats): every stage `verify` takes and EVERY (stage, previous) pair that
# `stage-start` takes, so an implementation that refuses snapshot records for one stage or one pair only fails. A pair added to the tables without a case
# is caught by the first check below, which pins the tables this test was written against.
WRITTEN_FOR = {"stages": ["build", "sign", "rebuild", "check", "release"],
               "starts_from": {"rebuild": ["build"], "check": ["build"], "sign": ["build"], "release": ["build", "sign", "rebuild", "check"]}}
sys.path.insert(0, root + "/bin")      # chain-verify.py imports its sibling modules
try:
    spec = importlib.util.spec_from_file_location("chain_verify_tables", CV)
    cv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cv)
    tables = {"stages": list(cv.STAGES), "starts_from": {k: list(v) for k, v in cv.STARTS_FROM.items()}}
except Exception as ex:      # a missing or broken script: every case below fails on its own; the tables fall back to the ones written for
    tables = WRITTEN_FOR
    print("note: could not read the tables of chain-verify.py (%s)" % type(ex).__name__)
check("the stages and (stage, previous) pairs of chain-verify.py are the ones this test was written for (a new one needs a case)", tables == WRITTEN_FOR,
      "%s" % tables)
SUBCOMMANDS = [("verify --stage %s" % s, ["verify", "--policy", "policy.json", "--stage", s, "--record", "{rec}"], s, None) for s in WRITTEN_FOR["stages"]]
for stage, previous_list in WRITTEN_FOR["starts_from"].items():
    for previous in previous_list:
        SUBCOMMANDS.append(("stage-start %s from %s" % (stage, previous), ["stage-start", "--stage", stage, "--previous", previous, "--record", "{rec}",
                                                                            "--digests", "digests.json", "--policy", "policy.json"], previous, None))
SUBCOMMANDS += [
    ("check-build-record", ["check-build-record", "--digests", "digests.json", "--build-record", "{rec}", "--policy", "policy.json"], "build", None),
    ("sign --check", ["sign", "--check", "--signer", "cosign", "--digests", "digests.json", "--build-record", "{rec}",
                      "--template", TEMPLATE, "--out", "provenance"], "build", SIGN_ENV),
]
for label, args, stage, env in SUBCOMMANDS:
    for name, want_snapshot in (("snapshot-build", True), (stage, False)):
        record("rec.json", name)
        rc, out, err = run([a.replace("{rec}", "rec.json") for a in args], env)
        first = err.split("\n", 1)[0]
        named_stage = first.startswith("refused at %s: " % stage)
        if want_snapshot:
            check("%s: a collection named snapshot-build is refused as a snapshot record" % label,
                  rc == 1 and first == "refused at %s: snapshot record" % stage and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
        else:
            check("%s: the same fixture named %s is refused for something else, never as a snapshot record" % (label, name),
                  rc == 1 and named_stage and "snapshot" not in first and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
for name in ("snapshot-apk", "snapshot-rapk", "snapshot-anything", "snapshot-", "snapshot-a_b-9"):
    record("rec.json", name)
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("a collection name that is exactly snapshot- plus [a-z0-9_-]* is refused as a snapshot record (%s)" % name,
          rc == 1 and first == "refused at build: snapshot record",
          "exit %s, first line %r" % (rc, first[:140]))
# ---- every reader of a record, not only the verifiers (step-6 round 1, Sonnet 3): record-env and rebuild-compare read it through the same function --------
rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--tag", "v0.3.0", "--out", "policy.json"])
for name, want_snapshot in (("snapshot-build", True), ("build", False)):
    record("rec.json", name)
    rc, out, err = run(["record-env", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    if want_snapshot:
        check("record-env: a collection named snapshot-build is refused as a snapshot record",
              rc == 1 and first == "refused at build: snapshot record" and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
    else:
        check("record-env: the same fixture named build is accepted (the control)",
              rc == 0 and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
for name, want_snapshot in (("snapshot-build", True), ("build", False)):
    record("rec.json", name)
    with open(work + "/items.json", "w") as f:
        json.dump({}, f)
    rc, out, err = run(["rebuild-compare", "--build-record", "rec.json", "--expected", "items.json", "--actual", "items.json", "--out", "verdict.json"])
    first = err.split("\n", 1)[0]
    if want_snapshot:
        check("rebuild-compare: a collection named snapshot-build is refused as a snapshot record (without --snapshot)",
              rc == 1 and first == "refused at rebuild: snapshot record" and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
    else:
        check("rebuild-compare: the same fixture named build is refused for something else, never as a snapshot record",
              rc == 1 and first.startswith("refused at rebuild: ") and "snapshot" not in first and "Traceback" not in err,
              "exit %s, first line %r" % (rc, first[:140]))


def raw_record(path, statement):
    envelope = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
                "signatures": [{"sig": base64.b64encode(b"x").decode(), "certificate": base64.b64encode(b"x").decode()}]}
    with open(os.path.join(work, path), "w") as f:
        json.dump(envelope, f)


# ---- odd statements are refused or accepted cleanly: never as a snapshot, never with a traceback (Sonnet 4) ------------------------------------------------
COLLECTION = "https://witness.testifysec.com/attestation-collection/v0.1"
STMT = "https://in-toto.io/Statement/v0.1"
ODD = [("a statement with no predicate at all", {"_type": STMT, "predicateType": COLLECTION, "subject": []}),
       ("a predicate whose name is the number 5", {"_type": STMT, "predicateType": COLLECTION, "subject": [], "predicate": {"name": 5}}),
       ("a null predicate", {"_type": STMT, "predicateType": COLLECTION, "subject": [], "predicate": None}),
       ("a predicate that is a list", {"_type": STMT, "predicateType": COLLECTION, "subject": [], "predicate": []}),
       ("a SLSA provenance statement (what Release's stage-start --previous sign reads)",
        {"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": [],
         "predicate": {"buildDefinition": {}, "runDetails": {}}})]
for what, statement in ODD:
    raw_record("rec.json", statement)
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("verify --stage build: %s is refused cleanly, never as a snapshot record" % what,
          rc == 1 and first.startswith("refused at build: ") and "snapshot" not in first and "Traceback" not in err,
          "exit %s, first line %r" % (rc, first[:140]))
for what, statement in ODD[:4]:
    raw_record("rec.json", statement)
    rc, out, err = run(["record-env", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("record-env: %s ends cleanly (accepted or refused), never as a snapshot record" % what,
          rc in (0, 1, 2) and "snapshot" not in err and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
# ---- ruling (1): a snapshot built in a checkout whose HEAD carries v0.3.0 is still a snapshot, and release verification refuses what it left ----------------
# The snapshot scripts ignore the v* tag at HEAD and build 0.0.0-rc.1, so the record they leave names a snapshot step and 0.0.0 files, while the policy is the
# one for v0.3.0 (the tag that HEAD carried). Both ways of passing it off are refused: under its own name, and renamed to build.
rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--tag", "v0.3.0", "--out", "policy.json"])
for what, name in (("under its own name (snapshot-build)", "snapshot-build"), ("renamed to build", "build")):
    record("rec.json", name, ["out/x86_64/fscache-0.0.0_rc1-r0.apk"])
    want = "refused at build: snapshot record" if name.startswith("snapshot-") else "refused at build: snapshot version"
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("a v0.3.0 policy and a snapshot record %s (HEAD carried v0.3.0) is refused by verify: %s" % (what, want.split(": ", 1)[1]),
          rc == 1 and first == want, "exit %s, first line %r" % (rc, first[:140]))
    rc, out, err = run(["stage-start", "--stage", "release", "--previous", "build", "--record", "rec.json",
             "--digests", "digests.json", "--policy", "policy.json"])
    first = err.split("\n", 1)[0]
    check("the same record %s is refused at the Release side (stage-start release from build): %s" % (what, want.split(": ", 1)[1]),
          rc == 1 and first == want, "exit %s, first line %r" % (rc, first[:140]))
# ---- REQ-CHAIN-004-AC13, the closed-name check (advisor, Oct 9) ------------------------------------------------------------------------------------
# The snapshot- prefix refusal is a denylist; a collection name must also be EXACTLY a release name for the stage that reads it: apk or build for Build,
# rapk or rebuild for Rebuild (check, sign and release records are unaffected here: PR 3 names the Check steps).
# Anything else, spelling variants and Unicode lookalikes included, is refused BEFORE any certificate with `refused at <stage>: collection name ...`. This is
# early protection against honest confusion and lookalikes; the real boundary stays the Build Config URI pin of check_identity (a run of scan.yml can name its
# own record build, but it is not release.yml at the tag).
LOOKALIKES = [("Snapshot-build (capital S)", "Snapshot-build"), ("a leading space", " snapshot-build"), ("a trailing space", "snapshot-build "),
              ("a non-breaking hyphen (U+2011)", "snapshot\u2011build"), ("a Cyrillic s (U+0455)", "\u0455napshot-build"),
              ("an upper-case SNAPSHOT-BUILD", "SNAPSHOT-BUILD"), ("an underscore", "snapshot_build"), ("a different name entirely", "release"),
              ("Build (capital B)", "Build"), ("builds", "builds"), ("a one for an l (bui1d)", "bui1d"), ("a trailing newline", "build\n"),
              ("a zero-width space (U+200B)", "bui\u200bld"),
              ("a capital after the prefix (not [a-z0-9_-])", "snapshot-Build"), ("a zero-width space after the prefix", "snapshot-bu\u200bild"),
              ("a newline after the prefix", "snapshot-build\n"), ("a dot after the prefix", "snapshot-build.1"),
              ("a Cyrillic a in apk (U+0430)", "\u0430pk"), ("the empty name", "")]
for what, name in LOOKALIKES:
    record("rec.json", name)
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("verify --stage build: a collection name with %s is refused by name before any certificate" % what,
          rc == 1 and first.startswith("refused at build: collection name ") and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
for what, name in (("rapk", "rapk"), ("rebuild", "rebuild"), ("Rebuild (capital R)", "Rebuild"), ("a Build record (build) given to the Rebuild stage", "build"),
                   ("a Cyrillic e in rebuild (U+0435)", "r\u0435build")):
    record("rec.json", name)
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "rebuild", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    if name in ("rapk", "rebuild"):
        check("verify --stage rebuild: the release name %s passes the name check (refused later, for what the fixture is)" % what,
              rc == 1 and first.startswith("refused at rebuild: ") and not first.startswith("refused at rebuild: collection name ") and "Traceback" not in err,
              "exit %s, first line %r" % (rc, first[:140]))
    else:
        check("verify --stage rebuild: %s is refused by name before any certificate" % what,
              rc == 1 and first.startswith("refused at rebuild: collection name ") and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
for name in ("apk", "build"):
    record("rec.json", name)
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("verify --stage build: the release name %s passes the name check (refused later, for what the fixture is)" % name,
          rc == 1 and first.startswith("refused at build: ") and not first.startswith("refused at build: collection name ") and "Traceback" not in err,
          "exit %s, first line %r" % (rc, first[:140]))
for label, args, stage, env in SUBCOMMANDS:
    if label.startswith("verify") or stage not in ("build", "rebuild"):
        continue
    record("rec.json", "Build" if stage == "build" else "Rebuild")
    rc, out, err = run([a.replace("{rec}", "rec.json") for a in args], env)
    first = err.split("\n", 1)[0]
    check("%s: a lookalike collection name is refused by name at every reader of the %s record" % (label, stage),
          rc == 1 and first.startswith("refused at %s: collection name " % stage) and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
for flag, what, name in (("--snapshot", "Build (capital B)", "Build"), ("--snapshot", "a leading space", " snapshot-build"), ("", "Build (capital B)", "Build"),
                         ("", "a Cyrillic s", "\u0455napshot-build")):
    record("rec.json", name)
    with open(work + "/items.json", "w") as f:
        json.dump({}, f)
    args = ["rebuild-compare"] + ([flag] if flag else [])
    args += ["--build-record", "rec.json", "--expected", "items.json", "--actual", "items.json", "--out", "verdict.json"]
    rc, out, err = run(args)
    first = err.split("\n", 1)[0]
    check("rebuild-compare %s: Build's record named %s is refused by name" % (flag or "(release)", what),
          rc == 1 and first.startswith("refused at rebuild: ") and "Traceback" not in err and "digest: items.json" not in first,
          "exit %s, first line %r" % (rc, first[:140]))
# ---- REQ-CHAIN-004-AC15: the snapshot version -------------------------------------------------------------------------------------------------------------
SNAP_APK, REAL_APK = "out/x86_64/fscache-0.0.0_rc1-r0.apk", "out/x86_64/fscache-0.3.0-r0.apk"
for label, args, stage, env in SUBCOMMANDS:
    for files, want_snapshot in (([SNAP_APK], True), ([REAL_APK], False)):
        record("rec.json", stage, files)
        rc, out, err = run([a.replace("{rec}", "rec.json") for a in args], env)
        first = err.split("\n", 1)[0]
        if want_snapshot:
            check("%s: a record that names fscache-0.0.0_rc1-r0.apk is refused as a snapshot version" % label,
                  rc == 1 and first == "refused at %s: snapshot version" % stage and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
        else:
            check("%s: the same fixture naming fscache-0.3.0-r0.apk is refused for something else, never as a snapshot version" % label,
                  rc == 1 and first.startswith("refused at %s: " % stage) and "snapshot" not in first and "Traceback" not in err,
                  "exit %s, first line %r" % (rc, first[:140]))
for what, f in (("the fips apk", "out/aarch64/fscache-fips-0.0.0_rc1-r0.apk"), ("a final 0.0.0 apk", "out/x86_64/fscache-0.0.0-r0.apk"),
                ("a standard archive", "dist/fscache_0.0.0-rc.1_linux_amd64.tar.gz"), ("a fips archive", "dist/fscache-fips_0.0.0-rc.1_linux_arm64.tar.gz")):
    record("rec.json", "build", [f])
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("verify: a record naming %s with the version 0.0.0 is refused as a snapshot version" % what,
          rc == 1 and first == "refused at build: snapshot version", "exit %s, first line %r" % (rc, first[:140]))
for tag in ("v0.0.0-rc.1", "v0.0.0"):
    rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--tag", tag, "--out", "p0.json"])
    first = err.split("\n", 1)[0]
    check("policy make --tag %s is refused as a snapshot version and writes no policy" % tag,
          rc == 1 and first.startswith("refused at policy: snapshot version") and not os.path.exists(work + "/p0.json"),
          "exit %s, first line %r" % (rc, first[:140]))
rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--tag", "v0.3.1", "--out", "p1.json"])
check("policy make --tag v0.3.1 is still made (the control of the two refusals above)", rc == 0 and os.path.exists(work + "/p1.json"), err[:120])
rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--ref", "refs/tags/v0.0.0-rc.1", "--out", "p2b.json"])
check("policy make --ref refs/tags/v0.0.0-rc.1 is refused as a snapshot version and writes no policy",
      rc == 1 and err.startswith("refused at policy: snapshot version") and not os.path.exists(work + "/p2b.json"), "exit %s, %r" % (rc, err[:120]))
rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--ref", "refs/tags/v0.0.0", "--out", "p2.json"])
check("policy make --ref refs/tags/v0.0.0 is refused as a snapshot version too (the form sign --check uses)",
      rc == 1 and err.startswith("refused at policy: snapshot version") and not os.path.exists(work + "/p2.json"), "exit %s, %r" % (rc, err[:120]))
# ---- the 0.0.0 check must not over-reach (step-6 round 2, S3): versions that merely CONTAIN the digits are not snapshot versions -----------
for what, f in (("fscache-10.0.0-r0.apk (version 10.0.0)", "out/x86_64/fscache-10.0.0-r0.apk"),
                ("fscache-0.10.0-r0.apk (version 0.10.0)", "out/x86_64/fscache-0.10.0-r0.apk"),
                ("fscache-1.0.0_rc1-r0.apk", "out/x86_64/fscache-1.0.0_rc1-r0.apk"),
                ("fscache_10.0.0_linux_amd64.tar.gz", "dist/fscache_10.0.0_linux_amd64.tar.gz")):
    record("rec.json", "build", [f])
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("verify: a record naming %s is NOT refused as a snapshot version" % what,
          rc == 1 and first.startswith("refused at build: ") and "snapshot" not in first and "Traceback" not in err,
          "exit %s, first line %r" % (rc, first[:140]))
for tag in ("v10.0.0", "v0.0.1", "v0.10.0", "v1.0.0"):
    rc, out, err = run(["policy", "make", "--template", TEMPLATE, "--tag", tag, "--out", "p3.json"])
    check("policy make --tag %s is made (it is not a 0.0.0 tag)" % tag, rc == 0 and os.path.exists(work + "/p3.json"), "exit %s, %r" % (rc, err[:120]))
    if os.path.exists(work + "/p3.json"):
        os.remove(work + "/p3.json")
# ---- odd subject shapes end cleanly: no traceback, never as a snapshot (step-6 round 2, S3) -------------------------------------------
ODD_SUBJECTS = [("subject is the number 5", 5), ("subject is a list of a bare string", ["x"]), ("a subject whose name is the number 5", [{"name": 5}]),
                ("subject is null", None), ("a subject that is a list", [[]]), ("a subject whose digest is a string", [{"name": "a", "digest": "x"}])]
for what, subject in ODD_SUBJECTS:
    raw_record("rec.json", {"_type": STMT, "predicateType": COLLECTION, "subject": subject, "predicate": {"name": "build", "attestations": []}})
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("verify --stage build: %s is refused cleanly (never as a snapshot, no traceback)" % what,
          rc == 1 and first.startswith("refused at build: ") and "snapshot" not in first and "Traceback" not in err,
          "exit %s, first line %r" % (rc, first[:140]))
    rc, out, err = run(["record-env", "--record", "rec.json"])
    check("record-env: %s ends cleanly (no traceback, never as a snapshot)" % what, rc in (0, 1, 2) and "snapshot" not in err and "Traceback" not in err,
          "exit %s, %r" % (rc, err[:140]))
# ---- AC15 reaches digests.json too, by NAME only (never its values): a digests.json that names a 0.0.0 file is refused before any certificate -----------
for label, args, stage, env in SUBCOMMANDS:
    if label not in ("stage-start rebuild from build", "check-build-record", "sign --check"):
        continue
    for name, want_snapshot in (("fscache-0.0.0_rc1-r0.apk", True), ("fscache-0.3.0-r0.apk", False)):
        record("rec.json", "build")
        with open(work + "/digests.json", "w") as f:
            json.dump({name: "sha256:" + "a" * 64}, f)
        rc, out, err = run([a.replace("{rec}", "rec.json") for a in args], env)
        first = err.split("\n", 1)[0]
        if want_snapshot:
            check("%s: a digests.json that names fscache-0.0.0_rc1-r0.apk is refused as a snapshot version before any certificate" % label,
                  rc == 1 and first == "refused at build: snapshot version" and "Traceback" not in err, "exit %s, first line %r" % (rc, first[:140]))
        else:
            check("%s: the same digests.json naming 0.3.0 is refused for something else, never as a snapshot version" % label,
                  rc == 1 and first.startswith("refused at build: ") and "snapshot" not in first and "Traceback" not in err,
                  "exit %s, first line %r" % (rc, first[:140]))
with open(work + "/digests.json", "w") as f:
    json.dump({"image-production": "sha256:" + "a" * 64}, f)
# ---- REAL git and REAL go (step-6 round 3, F2): the tag lines of the snapshot apk scripts make Go stamp v0.0.0-rc.1 -------------------
# Go stamps the highest semver tag at HEAD, so with v0.3.0 at HEAD the single line `git tag --force v0.0.0-rc.1 HEAD` still gives the stamp v0.3.0 and cache's
# driver (which reads the buildinfo `mod` line) would refuse. The lines come from bin/chain-test-shape.py (SNAPSHOT_TAG_LINES, the same text the script judge
# demands of the committed scripts) and run in a throw-away repository with a go.mod and a tiny main, whose origin is a bare repository. SKIPPED CLEANLY (and
# counted, so the total is stable) when go or git is missing: the CI runner has both.
spec = importlib.util.spec_from_file_location("shape", root + "/bin/chain-test-shape.py")
shape = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shape)
HAVE_TOOLS = shutil.which("go") is not None and shutil.which("git") is not None


def git(repo, *args):
    return subprocess.run(["git", "-C", repo] + list(args), capture_output=True, text=True)


def make_repo(name):
    """A repository with a commit, tags v0.3.0 (and what the caller adds) at HEAD, and a bare origin that has v0.3.0 pushed. Returns (clone, bare)."""
    bare, clone = "%s/%s-origin.git" % (work, name), "%s/%s" % (work, name)
    subprocess.run(["git", "init", "-q", "--bare", bare], check=True)
    subprocess.run(["git", "init", "-q", clone], check=True)
    for k, v in (("user.email", "t@example.com"), ("user.name", "t"), ("commit.gpgsign", "false"), ("tag.gpgsign", "false")):
        git(clone, "config", k, v)
    with open(clone + "/go.mod", "w") as f:
        f.write("module example.com/snap\n\ngo 1.22\n")
    with open(clone + "/main.go", "w") as f:
        f.write("package main\n\nfunc main() {}\n")
    git(clone, "add", "-A")
    git(clone, "commit", "-q", "-m", "c")
    git(clone, "remote", "add", "origin", bare)
    git(clone, "tag", "v0.3.0")
    git(clone, "push", "-q", "origin", "v0.3.0")
    return clone, bare


def run_lines(clone, lines, github_actions="true"):
    """Run the tag lines in the clone with GITHUB_ACTIONS set to `github_actions` (None removes it): this test may itself run in CI, where it is true."""
    script = "#!/usr/bin/env bash\nset -euo pipefail\n" + "\n".join(lines) + "\n"
    with open(work + "/tag-lines.sh", "w") as f:
        f.write(script)
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
    if github_actions is not None:
        env["GITHUB_ACTIONS"] = github_actions
    return subprocess.run(["bash", work + "/tag-lines.sh"], cwd=clone, capture_output=True, text=True, env=env)


def stamp(clone):
    """The main module version in the Go buildinfo (what cache's driver reads), from a build whose output stays outside the clean tree."""
    out = work + "/app-" + os.path.basename(clone)
    b = subprocess.run(["go", "build", "-o", out, "."], cwd=clone, capture_output=True, text=True)
    m = subprocess.run(["go", "version", "-m", out], capture_output=True, text=True)
    mod = [l.split() for l in m.stdout.splitlines() if l.strip().startswith("mod\t")]
    rev = [l.split("=", 1)[1] for l in m.stdout.splitlines() if "vcs.revision=" in l]
    return (mod[0][2] if mod else None), (rev[0] if rev else None), b.stderr


def real(label, fn):
    if not HAVE_TOOLS:
        check(label + " [SKIP: go or git is not installed here; the CI runner has both]", True)
        return
    ok, detail = fn()
    check(label, ok, detail)


def case_control():
    clone, bare = make_repo("ctl")
    git(clone, "tag", "--force", "v0.0.0-rc.1", "HEAD")
    version, rev, err = stamp(clone)
    return version == "v0.3.0", "stamp %r (the control: the single tag line alone leaves the highest tag, v0.3.0, as the stamp)" % version


def case_stamp():
    clone, bare = make_repo("fix")
    r = run_lines(clone, shape.SNAPSHOT_TAG_LINES)
    version, rev, err = stamp(clone)
    head = git(clone, "rev-parse", "HEAD").stdout.strip()
    return (r.returncode == 0 and version == "v0.0.0-rc.1" and rev == head,
            "rc %s, stamp %r, revision %r (HEAD %r), %s" % (r.returncode, version, rev, head, r.stderr[:100]))


def case_tags():
    clone, bare = make_repo("tags")
    git(clone, "tag", "v0.2.9")
    r = run_lines(clone, shape.SNAPSHOT_TAG_LINES)
    left = git(clone, "tag", "--points-at", "HEAD").stdout.split()
    return r.returncode == 0 and left == ["v0.0.0-rc.1"], "rc %s, tags at HEAD %s" % (r.returncode, left)


def case_remote():
    clone, bare = make_repo("remote")
    before = subprocess.run(["git", "ls-remote", "--tags", bare], capture_output=True, text=True).stdout
    r = run_lines(clone, shape.SNAPSHOT_TAG_LINES)
    after = subprocess.run(["git", "ls-remote", "--tags", bare], capture_output=True, text=True).stdout
    return r.returncode == 0 and before == after and "v0.3.0" in after and "v0.0.0-rc.1" not in after, "remote before %r after %r" % (before, after)


def case_nonv():
    clone, bare = make_repo("nonv")
    git(clone, "tag", "keep-me")
    r = run_lines(clone, shape.SNAPSHOT_TAG_LINES)
    left = sorted(git(clone, "tag", "--points-at", "HEAD").stdout.split())
    return (r.returncode != 0 and "keep-me" in r.stderr and "keep-me" in left and "v0.3.0" not in left,
            "rc %s, stderr %r, tags %s" % (r.returncode, r.stderr[:120], left))


def case_rerun():
    clone, bare = make_repo("rerun")
    first = run_lines(clone, shape.SNAPSHOT_TAG_LINES)
    second = run_lines(clone, shape.SNAPSHOT_TAG_LINES)
    version, rev, err = stamp(clone)
    return first.returncode == 0 and second.returncode == 0 and version == "v0.0.0-rc.1", "rc %s %s, stamp %r" % (first.returncode, second.returncode, version)


def case_guard():
    """Outside GitHub Actions the lines refuse before any `git tag`: a developer's clone keeps every tag, an unpushed local one included."""
    problems = []
    for value in (None, "", "false", "FALSE", "TRUE", "1", "true "):
        clone, bare = make_repo("guard")
        git(clone, "tag", "keep-me")
        git(clone, "tag", "unpushed-local-v9.9.9")
        before = sorted(git(clone, "tag", "--points-at", "HEAD").stdout.split())
        r = run_lines(clone, shape.SNAPSHOT_TAG_LINES, value)
        after = sorted(git(clone, "tag", "--points-at", "HEAD").stdout.split())
        if r.returncode != 2 or "outside GitHub Actions" not in r.stderr or before != after:
            problems.append("GITHUB_ACTIONS=%r -> rc %s, stderr %r, tags %s -> %s" % (value, r.returncode, r.stderr[:100], before, after))
        shutil.rmtree(clone, ignore_errors=True)
        shutil.rmtree(bare, ignore_errors=True)
    return not problems, "; ".join(problems)[:300]


real("real git: outside GitHub Actions (unset, empty, false, FALSE, TRUE, 1, 'true ') the lines exit 2 naming the reason, every tag stays",
     case_guard)
real("real git and go: CONTROL - with only `git tag --force v0.0.0-rc.1 HEAD` and v0.3.0 at HEAD, Go's stamp is still v0.3.0 (the problem)", case_control)
real("real git and go: the snapshot tag lines make the stamp v0.0.0-rc.1 and vcs.revision equal to HEAD, although v0.3.0 was at HEAD", case_stamp)
real("real git and go: after the lines HEAD carries only v0.0.0-rc.1 (v0.3.0 and v0.2.9 deleted locally)", case_tags)
real("real git and go: the remote is untouched - v0.3.0 is still there, v0.0.0-rc.1 was never pushed", case_remote)
real("real git and go: a non-v* tag at HEAD fails the lines naming it, and it is not deleted or restored", case_nonv)
real("real git and go: a second run (v0.0.0-rc.1 already there) succeeds and the stamp is still v0.0.0-rc.1", case_rerun)
EXPECT = 160
total = passed + failed
print("pass=%d fail=%d" % (passed, failed))
if total != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (total, EXPECT))
    sys.exit(1)
sys.exit(1 if failed else 0)
PY
