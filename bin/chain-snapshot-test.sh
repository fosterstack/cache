#!/usr/bin/env bash
# proves: REQ-CHAIN-004-AC13 — a record whose Witness collection is named snapshot-* is refused by every verifier, at every stage, by name
#
# Snapshot mode (REQ-CHAIN-004-AC12) lets the proof workflows (scan.yml, main-candidate-rescan.yml) build with no tag and no admission. Witness still signs
# the step, and the marker is the step name in the signed collection: snapshot-apk and snapshot-build (a closed list). So that a pull request's build can
# never be mistaken for a release build, EVERY subcommand of bin/chain-verify.py that reads a stage's record refuses a collection whose name starts with
# `snapshot-`, BEFORE it looks at a certificate, a signature or a timestamp, and says so:
#
#     refused at <stage>: snapshot record
#
# where <stage> is the stage whose record it was (verify --stage S: S; stage-start: --previous; check-build-record and sign --check: build). Nothing in
# this test needs a key, a network or OpenSSL beyond what `policy make` uses for the committed trust files: the fixtures are unsigned DSSE envelopes with
# one dummy signature entry, so a record named build gets past the name check and is refused LATER for what it is (a certificate that is not one). That is
# the control of every case: the same fixture named build is refused, but never as a snapshot record; a refusal that fires for both would prove nothing.
# The full acceptance of a genuine, signed build record is proven by bin/chain-verify-test.sh.
#
# Needs: python3, the committed trust files under .github/policy (policy make reads them).
exec python3 - "$(cd "$(dirname "$0")/.." && pwd)" <<'PY'
import atexit, base64, json, os, shutil, subprocess, sys, tempfile

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


def record(path, name):
    """An unsigned DSSE envelope of a Witness collection called `name`, with one dummy signature entry."""
    statement = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
                 "subject": [{"name": PRODUCT, "digest": {"sha256": "a" * 64}}], "predicate": {"name": name, "attestations": []}}
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
# (label, arguments, stage the refusal names, environment); {rec} is the record file
SUBCOMMANDS = [
    ("verify --stage build", ["verify", "--policy", "policy.json", "--stage", "build", "--record", "{rec}"], "build", None),
    ("verify --stage check", ["verify", "--policy", "policy.json", "--stage", "check", "--record", "{rec}"], "check", None),
    ("stage-start rebuild from build", ["stage-start", "--stage", "rebuild", "--previous", "build", "--record", "{rec}", "--digests", "digests.json",
                                        "--policy", "policy.json"], "build", None),
    ("stage-start check from build", ["stage-start", "--stage", "check", "--previous", "build", "--record", "{rec}", "--digests", "digests.json",
                                      "--policy", "policy.json"], "build", None),
    ("stage-start release from check (the Release side)", ["stage-start", "--stage", "release", "--previous", "check", "--record", "{rec}",
                                                           "--digests", "digests.json", "--policy", "policy.json"], "check", None),
    ("stage-start release from rebuild (the Release side)", ["stage-start", "--stage", "release", "--previous", "rebuild", "--record", "{rec}",
                                                             "--digests", "digests.json", "--policy", "policy.json"], "rebuild", None),
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
for name in ("snapshot-apk", "snapshot-rapk", "snapshot-anything"):
    record("rec.json", name)
    rc, out, err = run(["verify", "--policy", "policy.json", "--stage", "build", "--record", "rec.json"])
    first = err.split("\n", 1)[0]
    check("every collection name that starts with snapshot- is refused (%s)" % name, rc == 1 and first == "refused at build: snapshot record",
          "exit %s, first line %r" % (rc, first[:140]))
EXPECT = 21
total = passed + failed
print("pass=%d fail=%d" % (passed, failed))
if total != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (total, EXPECT))
    sys.exit(1)
sys.exit(1 if failed else 0)
PY
