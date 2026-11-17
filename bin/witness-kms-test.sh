#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC12
# proves: REQ-CHAIN-007-AC15
# (#822 round 1: T1 and P1 below. Wording pending the owner's approval, for the ACs whose approved text the round 1 fixes make false: REQ-CHAIN-007-AC1 and AC2 (no env up to and including release-verify;
#  any other env name refused), REQ-CHAIN-007-AC18 (any other env name refused), REQ-CHAIN-001-AC1 (step env names come from the closed env_names list), REQ-CHAIN-001-AC2 (Sign's steps: a Witness install and a
#  Witness sign step, no step env, cosign in one job), REQ-CHAIN-007-AC9 (what is attached: no entries files). REQ-CHAIN-004-AC10 (Sign signs keyless with the Sigstore timestamp) was already made false by the
#  KMS signing of the base and is named here for the same reason.)
# Tests for how Sign's helpers sign with the release KMS key (handoff 0713, rows P2 and P9) and for the Release helper that does not (S2, R1, R3):
#   bin/witnessed.sh STEP SCRIPT...      Release's six steps: `witness run` with a throwaway ed25519 key made under RUNNER_TEMP, nothing else. The Release job holds no KMS role, no key, no AWS name and no identity
#                                        token: no token fetch, no `signers` list, no sign-record tail; the record is witness-DIR/STEP-collection.local.json (DIR: the step without a leading snapshot-). Its text is judged exactly by
#                                        bin/chain-test-shape.py (`python3 -I -B bin/chain-test-shape.py helper bin/witnessed.sh` prints ok); here it is run against doubles.
#   bin/witness-sign-staged.sh STAGED SIGNED   Sign's step for Build's, Rebuild's and Check's records: the one signing function (sign-record, through bin/with-aws-token.sh)
# Offline: `witness`, the token endpoint helper (bin/loopback-get.sh, which only Sign's wrapper uses) and the verifier (which holds the signing function, `sign-record`) are doubles made here;
# nothing reaches AWS, KMS, a network or a public log (the signing function itself is tested in bin/chain-rekor-key-test.sh with a fake cosign).
# What it proves for bin/witnessed.sh, by running the real helper against the doubles (the doubles record what they were given):
#   - for every one of the six steps, with none of AWS_ROLE_ARN, AWS_REGION, RELEASE_KMS_KEY_REF or ACTIONS_ID_TOKEN_REQUEST_* in the environment: Witness runs with a throwaway ed25519 key file of mode 0600 in a directory
#     of mode 0700 under RUNNER_TEMP (never the KMS key, no Fulcio, timestamp or certificate flag), attestors environment,git,material,product, the wrapped command the plain `bash SCRIPT`, from the repository root; the
#     key directory is gone when the helper ends; no identity token is fetched and no signing call is made; neither Witness nor the wrapped script sees an AWS_, RELEASE_, request or SIGSTORE name
#   - with those names set anyway Witness still sees no request variable, no role and no token file, no token is fetched; a failing Witness keeps its exit status and leaves nothing; an unknown step exits 2; a job with no RUNNER_TEMP stops before Witness runs
#   - the helper's text names no signers list, sign-record, kms-sign, with-aws-token, loopback helper, RELEASE_* name, audience or old record name
#   bin/with-aws-token.sh (Sign's one token fetch, of its provenance signature and of each staged record): a fresh token, mode 0600 in a 0700 directory under RUNNER_TEMP, for one call only,
#     removed the moment the call ends, its exit status kept; no request variable reaches the call; no call on a failed, empty or null token
#   - the Release scripts name no RELEASE_ROLE_ARN, RELEASE_TOKEN_FILE or AWS_ROLE_ARN
# Each property is also proven on a MUTANT of the helper (a copy with that one property broken): a judge that cannot fail proves nothing.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 - "$root" <<'PY'
import base64, json, os, re, shutil, stat, subprocess, sys, tempfile

root = sys.argv[1]
KEY = "awskms:///alias/fosterstack-release-signing"
TOKEN = "TOK-SECRET-9f3a"
ROLE = "arn:aws:iam::111122223333:role/release-signing"
passn = failn = 0


def check(label, good, detail=""):
    global passn, failn
    if good:
        passn += 1
        print("ok   " + label)
    else:
        failn += 1
        print("FAIL %s%s" % (label, (" (" + detail[:1500] + ")") if detail else ""))


FAKE_LOOP = r'''#!/bin/sh
echo "$*" >> "$LOG/loop.log"
echo loop >> "$LOG/seq"
[ -z "${FAKE_FETCH_FAIL:-}" ] || exit 1
printf '{"value":"%s"}\n' "${FAKE_TOKEN-TOK-SECRET-9f3a}"
'''

# the Witness double: records its arguments and what it can see, then runs the wrapped command (what follows --) the way Witness does, with its own environment
FAKE_WITNESS = r'''#!/usr/bin/env bash
set -u
{
  echo "ARGV $*"
  echo "SUB $1"
  echo "ROLE ${AWS_ROLE_ARN-UNSET}"
  echo "TOKFILE ${AWS_WEB_IDENTITY_TOKEN_FILE-UNSET}"
  echo "REQ ${ACTIONS_ID_TOKEN_REQUEST_TOKEN-UNSET}|${ACTIONS_ID_TOKEN_REQUEST_URL-UNSET}|${ACTIONS_RUNTIME_TOKEN-UNSET}"
  echo "NAMES $(env | grep -E '^(AWS_|RELEASE_)' | cut -d= -f1 | sort | tr '\n' ' ')"
  if [ -n "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]; then
    echo "TOKEXISTS $([ -f "$AWS_WEB_IDENTITY_TOKEN_FILE" ] && echo yes || echo no)"
    echo "TOKMODE $(stat -c %a "$AWS_WEB_IDENTITY_TOKEN_FILE" 2> /dev/null || echo none)"
    echo "TOKDIRMODE $(stat -c %a "$(dirname "$AWS_WEB_IDENTITY_TOKEN_FILE")" 2> /dev/null || echo none)"
    echo "TOKCONTENT $(cat "$AWS_WEB_IDENTITY_TOKEN_FILE" 2> /dev/null)"
  fi
  kp=""; prev=""; for a in "$@"; do [ "$prev" = --signer-file-key-path ] && kp=$a; prev=$a; done
  echo "KEYPATH $kp"
  echo "KEYEXISTS $([ -f "$kp" ] && echo yes || echo no)"
  echo "KEYMODE $(stat -c %a "$kp" 2> /dev/null || echo none) $(stat -c %a "$(dirname "$kp")" 2> /dev/null || echo none)"
  echo "KEYALG $(openssl pkey -in "$kp" -noout -text 2> /dev/null | head -1)"
  echo "CWD $(pwd)"
  echo "RTFILES $(find "$RUNNER_TEMP" -type f -name token 2> /dev/null | wc -l)"
  echo "LOOPN $(cat "$LOG/loop.log" 2> /dev/null | wc -l)"
} >> "$LOG/witness.log"
echo witness >> "$LOG/seq"
args=("$@")
n=0
for a in "${args[@]}"; do n=$((n + 1)); [ "$a" = -- ] && break; done
if [ "$n" -lt "${#args[@]}" ] || [ "${args[$((n - 1))]}" = -- ]; then
  cmd=("${args[@]:$n}")
  [ "${#cmd[@]}" -eq 0 ] || "${cmd[@]}" || true
fi
out=""; prev=""; for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done
if [ -n "$out" ] && [ "${FAKE_WITNESS_RC:-0}" = 0 ]; then
  mkdir -p "$(dirname "$out")"
  if [ -n "${FAKE_WITNESS_NOPAYLOAD:-}" ]; then printf '{"payloadType":"application/vnd.in-toto+json","signatures":[]}\n' > "$out"
  elif [ -n "${FAKE_WITNESS_REC:-}" ]; then
    # a record with the command-run attestor the way Witness 0.12.0 writes it: its cmd is the argv after `--`; FAKE_WITNESS_REC is "min" (a minimal collection) or the path of the committed real record
    python3 - "$out" "$FAKE_WITNESS_REC" "${cmd[@]}" <<'PYREC'
import base64, json, sys
out, rec, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
if rec == "min":
    stmt = {"_type": "https://in-toto.io/Statement/v0.1", "predicateType": "https://witness.testifysec.com/attestation-collection/v0.1",
            "subject": [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "a" * 64}}],
            "predicate": {"name": "release", "attestations": [{"type": "https://witness.dev/attestations/environment/v0.1", "attestation": {"os": "linux", "variables": {"GITHUB_REF": "refs/tags/v0.3.0"}}},
                                                              {"type": "https://witness.dev/attestations/command-run/v0.1", "attestation": {"cmd": cmd, "stdout": "", "stderr": "", "exitcode": 0}}]}}
else:
    text = [l for l in open(rec).read().split("\n") if l and not l.startswith("#")]
    stmt = json.loads(base64.b64decode("".join(text[text.index("payload:") + 1:])))
    [a for a in stmt["predicate"]["attestations"] if a["type"].endswith("/command-run/v0.1")][0]["attestation"]["cmd"] = cmd
json.dump({"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(stmt).encode()).decode(), "signatures": []}, open(out, "w"))
PYREC
  else printf '{"payloadType":"application/vnd.in-toto+json","payload":"%s","signatures":[]}\n' "$(printf 'PAYLOAD-OF-WITNESS' | base64 -w0)" > "$out"; fi
fi
exit "${FAKE_WITNESS_RC:-0}"
'''

FAKE_CV = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
log = os.environ["LOG"]
open(log + "/cv.log", "a").write(" ".join(a) + "\n")
if a[:1] == ["verify"]:
    n = 0
    for dp, dn, fn in os.walk(os.environ["RUNNER_TEMP"]):
        n += len([f for f in fn if "token" in f])
    open(log + "/verify.tokens", "a").write("%d\n" % n)
if a[:2] == ["policy", "make"]:
    open(a[a.index("--out") + 1], "w").write("{}")
if a[:1] == ["sign"]:
    tf = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "UNSET")
    try:
        import stat as _st
        open(log + "/signprov.tok", "a").write("MODE=%o DIRMODE=%o CONTENT=%s ROLE=%s\n" % (
            _st.S_IMODE(os.stat(tf).st_mode), _st.S_IMODE(os.stat(os.path.dirname(tf)).st_mode), open(tf).read().strip(), os.environ.get("AWS_ROLE_ARN", "UNSET")))
    except OSError:
        open(log + "/signprov.tok", "a").write("NOTOKEN\n")
    if os.environ.get("FAKE_SIGN_RC"):
        sys.exit(int(os.environ["FAKE_SIGN_RC"]))
if a[:1] == ["kms-sign"]:      # KA-2 p4 group 4: the evidence letter's one signing call, run under the same token wrapper
    tf = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "UNSET")
    try:
        import stat as _st
        open(log + "/kmssign.tok", "a").write("MODE=%o DIRMODE=%o CONTENT=%s ROLE=%s\n" % (
            _st.S_IMODE(os.stat(tf).st_mode), _st.S_IMODE(os.stat(os.path.dirname(tf)).st_mode), open(tf).read().strip(), os.environ.get("AWS_ROLE_ARN", "UNSET")))
    except OSError:
        open(log + "/kmssign.tok", "a").write("NOTOKEN\n")
if a[:1] == ["sign-record"]:
    open(log + "/seq", "a").write("sign-record\n")
    tf = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "UNSET")
    try:
        import stat as _st
        open(log + "/signrec.tok", "a").write("MODE=%o DIRMODE=%o CONTENT=%s REGION=%s KEYREF=%s\n" % (
            _st.S_IMODE(os.stat(tf).st_mode), _st.S_IMODE(os.stat(os.path.dirname(tf)).st_mode), open(tf).read().strip(),
            os.environ.get("AWS_REGION", "UNSET"), os.environ.get("RELEASE_KMS_KEY_REF", "UNSET")))
    except OSError:
        open(log + "/signrec.tok", "a").write("NOTOKEN\n")
    open(log + "/signrec.env", "a").write("ROLE=%s TOKFILE=%s TOKEXISTS=%s REQ=%s|%s|%s\n" % (
        os.environ.get("AWS_ROLE_ARN", "UNSET"), tf, "yes" if os.path.isfile(tf) else "no", os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "UNSET"),
        os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "UNSET"), os.environ.get("ACTIONS_RUNTIME_TOKEN", "UNSET")))
    prior = ""
    try:
        for l in open(log + "/inner.log"):
            if l.startswith("RELEASE_TOKEN_FILE="):
                prior = l.split("=", 1)[1].strip()
    except OSError:
        pass
    open(log + "/signrec.prior", "a").write("PRIOR=%s EXISTS=%s\n" % (prior or "none", os.path.exists(prior) if prior else "none"))
    open(log + "/signrec.payload", "wb").write(open(a[a.index("--payload") + 1], "rb").read())
    if os.environ.get("FAKE_SIGN_RC"):
        sys.exit(int(os.environ["FAKE_SIGN_RC"]))
    out = a[a.index("--out") + 1]
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    open(out, "w").write("{}")
    open(out[: -len(".json")] + ".rekor.json", "w").write("{}")
'''

FAKE_INNER = r'''#!/usr/bin/env bash
env | grep -E '^(AWS_|ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|SIGSTORE|RELEASE_)' | sort >> "$LOG/inner.log"
t="${AWS_WEB_IDENTITY_TOKEN_FILE-${RELEASE_TOKEN_FILE-}}"
if [ -n "$t" ]; then
  echo "TOKEXISTS $([ -f "$t" ] && echo yes || echo no)" >> "$LOG/inner.log"
  echo "TOKMODE $(stat -c %a "$t" 2> /dev/null || echo none)" >> "$LOG/inner.log"
  echo "TOKCONTENT $(cat "$t" 2> /dev/null)" >> "$LOG/inner.log"
fi
echo "RTFILES $(find "$RUNNER_TEMP" -type f -name token 2> /dev/null | wc -l)" >> "$LOG/inner.log"
echo ran >> "$LOG/inner.log"
'''


def sh(path, text, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def tree(helper, text, wrapper=None):
    """A repository tree with the helper under test (and the token-fetch script it calls: the committed one, or the given text), the doubles on PATH, and a RUNNER_TEMP outside the tree."""
    t = tempfile.mkdtemp()
    repo, log, runner, fakebin = (os.path.join(t, n) for n in ("repo", "log", "runner", "fakebin"))
    for d in (repo, log, runner, fakebin):
        os.makedirs(d)
    sh(os.path.join(repo, "bin", helper), text)
    if helper != "with-aws-token.sh" and (wrapper is not None or os.path.exists(os.path.join(root, "bin", "with-aws-token.sh"))):
        sh(os.path.join(repo, "bin", "with-aws-token.sh"), wrapper if wrapper is not None else open(os.path.join(root, "bin", "with-aws-token.sh")).read())
    sh(os.path.join(repo, "bin", "loopback-get.sh"), FAKE_LOOP)
    sh(os.path.join(repo, "bin", "inner.sh"), FAKE_INNER)
    sh(os.path.join(repo, "bin", "chain-verify.py"), FAKE_CV)
    os.makedirs(os.path.join(repo, ".github/policy"))
    open(os.path.join(repo, ".github/policy/release-policy.template.json"), "w").write("{}")
    sh(os.path.join(fakebin, "witness"), FAKE_WITNESS)
    return t, repo, log, runner, fakebin


def env_of(t, log, runner, fakebin, extra=None, drop=()):
    e = {"PATH": fakebin + ":" + os.environ["PATH"], "HOME": t, "LOG": log, "RUNNER_TEMP": runner, "GITHUB_ENV": os.path.join(log, "github_env"),
         "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "REQTOK", "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example/idtoken?api-version=2.0",
         "ACTIONS_RUNTIME_TOKEN": "RT", "ACTIONS_RUNTIME_URL": "https://rt.example/", "AWS_ROLE_ARN": ROLE, "AWS_REGION": "us-east-1", "RELEASE_KMS_KEY_REF": KEY,
         "GH_TOKEN": "x", "GITHUB_ACTIONS": "true"}
    e.update(extra or {})
    for k in drop:
        e.pop(k, None)
    open(e["GITHUB_ENV"], "w").close()
    return e


def read(p):
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return ""


def lines(log, name, key):
    return [l.split(" ", 1)[1] if " " in l else "" for l in read(os.path.join(log, name)).splitlines() if l.split(" ", 1)[0] == key]


STEPS = ("release-verify", "release-apks", "release-publish", "release-sign", "release-assets", "release-postverify")
IDENTITY = ("AWS_ROLE_ARN", "AWS_REGION", "RELEASE_KMS_KEY_REF", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL")


def run_witnessed(text, step="release-verify", extra=None, drop=(), identity=False):
    """R3/I5: the Release job holds no KMS role, no key and no identity token, so by default none of those names is in the environment; identity=True puts them back (a workflow that still sets them)"""
    t, repo, log, runner, fakebin = tree("witnessed.sh", text)
    e = env_of(t, log, runner, fakebin, extra, drop)
    if not identity:
        for k in IDENTITY:
            if k not in (extra or {}):
                e.pop(k, None)
    r = subprocess.run(["bash", "bin/witnessed.sh", step, "bin/inner.sh"], cwd=repo, env=e, capture_output=True, text=True, timeout=60)
    return t, repo, log, runner, r


def problems_witnessed(text, shape=True):
    """Everything wrong with a witnessed.sh (R3): Witness signs with a throwaway ed25519 key made under RUNNER_TEMP; no identity token, no signers, no KMS tail; the record is witness-DIR/STEP-collection.local.json"""
    bad = []
    for stp in STEPS:
        t, repo, log, runner, r = run_witnessed(text, stp)
        argv = (lines(log, "witness.log", "ARGV") or [""])[0]
        if r.returncode != 0:
            bad.append("%s exit %d without any AWS, KMS or identity-token variable: %s" % (stp, r.returncode, r.stderr.strip()[:120]))
        mk = re.search(r"--signer-file-key-path (\S+)/key\.pem", argv)
        kp = (lines(log, "witness.log", "KEYPATH") or [""])[0]
        if not mk or "--signer-kms-ref" in argv:
            bad.append("%s: Witness is not told to sign with a throwaway key file (or is told a KMS key)" % stp)
        elif not os.path.realpath(kp).startswith(os.path.realpath(runner) + os.sep) or os.path.realpath(kp).startswith(os.path.realpath(repo) + os.sep):
            bad.append("%s: the throwaway key is not under RUNNER_TEMP, outside the repository tree: %s" % (stp, kp))
        if (lines(log, "witness.log", "KEYEXISTS") or [""])[0] != "yes" or (lines(log, "witness.log", "KEYMODE") or [""])[0] != "600 700":
            bad.append("%s: the key is not a file of mode 600 in a directory of mode 700 while Witness runs: %r" % (stp, lines(log, "witness.log", "KEYMODE")))
        if "ED25519" not in (lines(log, "witness.log", "KEYALG") or [""])[0].upper():
            bad.append("%s: the throwaway key is not an ed25519 key: %r" % (stp, lines(log, "witness.log", "KEYALG")))
        if runner and os.listdir(runner):
            bad.append("%s: the key directory is left behind after success: %r" % (stp, os.listdir(runner)))
        if re.search(r"fulcio|oidc|--timestamp|timestamp\.sigstore|\s-t\s|certificate|kms", argv):
            bad.append("%s: a Fulcio, OIDC, timestamp, certificate or KMS flag is given to Witness" % stp)
        if not re.search(r" -a environment,git,material,product( |$)", argv):
            bad.append("%s: the attestors are not exactly environment,git,material,product" % stp)
        if argv.split(" -- ", 1)[-1].strip() != "bash bin/inner.sh":
            bad.append("%s: the wrapped command is not the plain `bash SCRIPT`: %r" % (stp, argv[-120:]))
        out = os.path.join(repo, "witness-" + stp)
        if " -o witness-%s/%s-collection.local.json" % (stp, stp) not in argv or not os.path.isfile(os.path.join(out, stp + "-collection.local.json")) or os.listdir(out) != [stp + "-collection.local.json"]:
            bad.append("%s: the record is not written to witness-%s/%s-collection.local.json (and nowhere else): %r" % (stp, stp, stp, os.path.isdir(out) and os.listdir(out)))
        if os.path.exists(os.path.join(log, "loop.log")) or os.path.exists(os.path.join(log, "cv.log")) or os.path.exists(os.path.join(log, "signrec.tok")):
            bad.append("%s: an identity token is fetched or a signing call is made (the Release job has no key)" % stp)
        if (lines(log, "witness.log", "NAMES") or ["x"])[0].strip() != "":
            bad.append("%s: Witness sees AWS_ or RELEASE_ variables: %r" % (stp, (lines(log, "witness.log", "NAMES") or [""])[0]))
        if (lines(log, "witness.log", "CWD") or [""])[0] != repo and os.path.realpath((lines(log, "witness.log", "CWD") or [""])[0]) != os.path.realpath(repo):
            bad.append("%s: Witness does not run from the repository root" % stp)
        inner = read(os.path.join(log, "inner.log"))
        if "ran" not in inner:
            bad.append("%s: the wrapped script did not run" % stp)
        if re.search(r"^(AWS_|RELEASE_|ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|SIGSTORE)", inner, re.M):
            bad.append("%s: the wrapped script sees an AWS_, RELEASE_, request or SIGSTORE variable: %r" % (stp, inner[:120]))
        for k in ("--env-filter-sensitive-vars", "--env-add-sensitive-key GH_TOKEN", "--env-add-sensitive-key GITHUB_TOKEN", "--env-add-sensitive-key DOCKERHUB_USERNAME", "--env-add-sensitive-key DOCKERHUB_TOKEN"):
            if k not in argv:
                bad.append("%s: %s is not given to Witness (the record would hold Release's credentials)" % (stp, k))
        if read(os.path.join(log, "github_env")):
            bad.append("%s: something was written to GITHUB_ENV" % stp)
        shutil.rmtree(t, ignore_errors=True)
    # a workflow that still sets the old names: Witness and the wrapped script still see none of them, and still no token is fetched
    t, repo, log, runner, r = run_witnessed(text, "release-sign", identity=True)
    if r.returncode != 0 or (lines(log, "witness.log", "REQ") or [""])[0] != "UNSET|UNSET|UNSET" or (lines(log, "witness.log", "ROLE") or [""])[0] != "UNSET" or (lines(log, "witness.log", "TOKFILE") or [""])[0] != "UNSET":
        bad.append("with the old identity names set, Witness still sees the request variables, the role or a token file, or the helper fails (exit %d): %r" % (r.returncode, lines(log, "witness.log", "REQ")))
    if os.path.exists(os.path.join(log, "loop.log")) or os.path.exists(os.path.join(log, "cv.log")) or os.listdir(runner):
        bad.append("with the old identity names set, a token is fetched, a signing call is made or a directory is left")
    shutil.rmtree(t, ignore_errors=True)
    # a failing Witness: its exit status is kept, nothing is left, no output
    t3, repo3, log3, runner3, r3 = run_witnessed(text, "release-verify", {"FAKE_WITNESS_RC": "7"})
    if r3.returncode != 7:
        bad.append("a failing Witness (7) ends the helper with %d" % r3.returncode)
    if os.listdir(runner3):
        bad.append("the key directory still exists after a failing Witness")
    # no RUNNER_TEMP: nothing runs; an unknown step exits 2
    t4, repo4, log4, runner4, r4 = run_witnessed(text, "release-verify", drop=("RUNNER_TEMP",))
    if r4.returncode == 0 or os.path.exists(os.path.join(log4, "witness.log")):
        bad.append("without RUNNER_TEMP the helper goes on (exit %d)" % r4.returncode)
    t5, repo5, log5, runner5, r5 = run_witnessed(text, "release-nonsense")
    if r5.returncode != 2 or os.path.exists(os.path.join(log5, "witness.log")):
        bad.append("an unknown step does not exit 2 before Witness runs")
    # the text: R3 says what is not in the helper
    code = "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))
    for pat in (r"\bsigners\b", r"sign-record", r"kms-sign", r"with-aws-token", r"loopback", r"RELEASE_ROLE_ARN", r"RELEASE_TOKEN_FILE", r"RELEASE_KMS_KEY_REF", r"AWS_REGION", r"audience", r"-collection\.json", r"\bjq\b", r"\bcurl\b"):
        if re.search(pat, code):
            bad.append("witnessed.sh still names %s" % pat)
    if shape:
        tf = tempfile.mkdtemp()
        open(os.path.join(tf, "w.sh"), "w").write(text)
        rs = subprocess.run([sys.executable, "-I", "-B", os.path.join(root, "bin", "chain-test-shape.py"), "helper", os.path.join(tf, "w.sh")], capture_output=True, text=True, cwd=root)
        shutil.rmtree(tf, ignore_errors=True)
        if rs.stdout.strip() != "ok":
            bad.append("bin/chain-test-shape.py helper does not print ok: %s" % (rs.stdout + rs.stderr).strip()[:200])
    for d in (t3, t4, t5):
        shutil.rmtree(d, ignore_errors=True)
    return bad


src = open(os.path.join(root, "bin", "witnessed.sh")).read()
b = problems_witnessed(src)
check("witnessed.sh: Witness signs with a throwaway ed25519 key under RUNNER_TEMP, no identity token, no KMS, record at witness-DIR/STEP-collection.local.json, cleaned up, shape ok", not b, "; ".join(b))


def mutant(label, fn):
    text = fn(src)
    if text == src:
        check("mutant (%s) changed nothing: the mutation is wrong" % label, False)
        return
    bad = problems_witnessed(text, shape=False)
    check("witnessed.sh mutant caught: %s" % label, bool(bad), "caught nothing")


mutant("the key directory inside the repository", lambda s: re.sub(r'"\$\{RUNNER_TEMP:\?\}/witness-key\.XXXXXX"', '"./witness-key.XXXXXX"', s))
mutant("no trap and no removal of the key directory", lambda s: re.sub(r'^trap .*\n', "", s, flags=re.M).replace('rm -rf "$kd"\n', ""))
mutant("Witness told to sign with the KMS key again", lambda s: s.replace('--signer-file-key-path "$kd/key.pem"', '--signer-kms-ref "$RELEASE_KMS_KEY_REF"'))
mutant("the record keeps the old name", lambda s: s.replace("-collection.local.json", "-collection.json"))
mutant("the exit status of Witness lost", lambda s: s.replace('exit "$rc"', "exit 0"))
mutant("the github attestor added", lambda s: s.replace("environment,git,material,product", "environment,git,github,material,product"))
mutant("the identity request variables left in Witness's environment", lambda s: re.sub(r'^unset ACTIONS_ID_TOKEN_REQUEST_TOKEN.*\n', "", s, flags=re.M))
mutant("an identity token fetched before Witness", lambda s: s.replace("rc=0\n", "rc=0\nsh bin/loopback-get.sh -sSf https://token.example/ > /dev/null\n", 1))
mutant("the role handed to the wrapped script", lambda s: s.replace('-- bash "$@"', '-- env RELEASE_ROLE_ARN=x bash "$@"'))
mutant("a KMS tail signs the record", lambda s: s.replace('rm -rf "$kd"\n', 'bash bin/with-aws-token.sh sign-record --payload x\nrm -rf "$kd"\n', 1))
mutant("an ed25519 key replaced by an RSA key", lambda s: s.replace("-algorithm ed25519", "-algorithm RSA"))
mutant("GH_TOKEN not a sensitive key", lambda s: s.replace("  --env-add-sensitive-key GH_TOKEN \\\n", ""))
mutant("an unknown step goes on", lambda s: re.sub(r'  \*\) echo "witnessed: unknown step \$step" >&2; exit 2 ;; esac', "  *) : ;; esac", s))

# release-sign-apks.sh and release-sign.sh no longer map RELEASE_ROLE_ARN / RELEASE_TOKEN_FILE (R3): the Release job has no role and no token file
for nm in ("release-sign-apks.sh", "release-sign.sh", "release-apks.sh", "release-publish.sh"):
    code = "\n".join(l for l in open(os.path.join(root, "bin", nm)).read().split("\n") if not l.lstrip().startswith("#"))
    check("%s: names no RELEASE_ROLE_ARN, RELEASE_TOKEN_FILE or AWS_ROLE_ARN (R3: nothing hands a Release step a role or a token file)" % nm, not re.search(r"RELEASE_ROLE_ARN|RELEASE_TOKEN_FILE|AWS_ROLE_ARN|AWS_WEB_IDENTITY_TOKEN_FILE", code))

# ---------------------------------------------------------------------------------------------------------------------------------------
# bin/witness-sign-staged.sh: Sign's step for the records of the jobs that hold no token



def staged_tree(text, wrapper=None):
    t, repo, log, runner, fakebin = tree("witness-sign-staged.sh", text, wrapper)
    st = os.path.join(repo, "staged")
    os.makedirs(os.path.join(st, "witness-build"))
    open(os.path.join(st, "witness-build", "build-collection.payload"), "w").write("payload")
    open(os.path.join(st, "witness-build", "digests.json"), "w").write("{}")
    open(os.path.join(st, "plan.txt"), "w").write("staged/witness-build/build-collection.payload\tsigned/witness-build/build-collection.json\n")
    return t, repo, log, runner, fakebin




def problems_staged(text, wrapper=None):
    bad = []
    t, repo, log, runner, fakebin = staged_tree(text, wrapper)
    # the plan is written with paths relative to the repository root, as the verifier prints them
    plan = os.path.join(repo, "staged", "plan.txt")
    open(plan, "w").write("%s\t%s\n" % (os.path.join(repo, "staged/witness-build/build-collection.payload"), os.path.join(repo, "signed/witness-build/build-collection.json")))
    e = env_of(t, log, runner, fakebin, {"GITHUB_REF": "refs/tags/v0.3.0"})
    r = subprocess.run(["bash", "bin/witness-sign-staged.sh", os.path.join(repo, "staged"), os.path.join(repo, "signed")], cwd=repo, env=e, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        bad.append("exit %d: %s" % (r.returncode, r.stderr.strip()[:160]))
    if os.path.exists(os.path.join(log, "witness.log")):
        bad.append("Witness is run: Sign signs through the one signing function only")
    want_sr = "sign-record --payload %s --out %s --template .github/policy/release-policy.template.json --aws %s/aws-cli/aws --public-key build/keys/release.rsa.pub" % (
        os.path.join(repo, "staged/witness-build/build-collection.payload"), os.path.join(repo, "signed/witness-build/build-collection.json"), runner)     # KA-2 p4 g3: with-aws-token.sh adds the last two options
    if want_sr not in read(os.path.join(log, "cv.log")).splitlines():
        bad.append("the staged payload is not signed by sign-record as pinned: %r" % read(os.path.join(log, "cv.log"))[:300])
    argv = want_sr
    loops = read(os.path.join(log, "loop.log")).splitlines()
    if len(loops) != 1 or not loops[0].endswith("&audience=sts.amazonaws.com"):
        bad.append("the identity token is not asked for exactly once per record with audience sts.amazonaws.com: %r" % loops)
    if read(os.path.join(log, "seq")).split() != ["loop", "sign-record"]:
        bad.append("the order is not a fresh token, then sign-record: %r" % read(os.path.join(log, "seq")).split())
    se = read(os.path.join(log, "signrec.env")).splitlines()
    if len(se) != 1 or not se[0].startswith("ROLE=" + ROLE) or "TOKEXISTS=yes" not in se[0] or not se[0].endswith("REQ=UNSET|UNSET|UNSET"):
        bad.append("sign-record does not see the role and the token file, or sees a request variable: %r" % se)
    else:
        tokfile = re.search(r"TOKFILE=(\S+)", se[0]).group(1)
        if not os.path.realpath(tokfile).startswith(os.path.realpath(runner) + os.sep):
            bad.append("the token file is not under RUNNER_TEMP")
        if os.path.exists(os.path.dirname(tokfile)):
            bad.append("the token directory still exists after success")
    vt = read(os.path.join(log, "verify.tokens")).split()
    if vt != ["0"]:
        bad.append("a token file is still on disk when the signed record is checked (each token is removed right after its sign call): %r" % vt)
    cv = read(os.path.join(log, "cv.log"))
    if "policy make" not in cv or not re.search(r"^verify --policy policy\.json --stage build --record .*build-collection\.json$", cv, re.M):
        bad.append("the signed record is not checked with the verifier under the policy made for the ref: %r" % cv[:200])
    if TOKEN in argv or TOKEN in r.stdout.replace("::add-mask::" + TOKEN, "") or TOKEN in r.stderr:
        bad.append("the token is in an argument or the output")
    if read(os.path.join(log, "github_env")):
        bad.append("something was written to GITHUB_ENV")
    shutil.rmtree(t, ignore_errors=True)
    # T1: two records, two fresh tokens, each fetched just before its own sign-record call
    t8, repo8, log8, runner8, fakebin8 = staged_tree(text, wrapper)
    os.makedirs(os.path.join(repo8, "staged", "witness-rebuild")); open(os.path.join(repo8, "staged", "witness-rebuild", "rebuild-collection.payload"), "w").write("payload2")
    open(os.path.join(repo8, "staged", "plan.txt"), "w").write("%s\t%s\n%s\t%s\n" % (
        os.path.join(repo8, "staged/witness-build/build-collection.payload"), os.path.join(repo8, "signed/witness-build/build-collection.json"),
        os.path.join(repo8, "staged/witness-rebuild/rebuild-collection.payload"), os.path.join(repo8, "signed/witness-rebuild/rebuild-collection.json")))
    e8 = env_of(t8, log8, runner8, fakebin8, {"GITHUB_REF": "refs/tags/v0.3.0"})
    r8 = subprocess.run(["bash", "bin/witness-sign-staged.sh", os.path.join(repo8, "staged"), os.path.join(repo8, "signed")], cwd=repo8, env=e8, capture_output=True, text=True, timeout=60)
    if read(os.path.join(log8, "seq")).split() != ["loop", "sign-record", "loop", "sign-record"]:
        bad.append("two records: the order is not a fresh token before each sign-record call: %r (exit %d %s)" % (read(os.path.join(log8, "seq")).split(), r8.returncode, r8.stderr.strip()[:100]))
    shutil.rmtree(t8, ignore_errors=True)
    # a failing signature stops the job and leaves no token directory
    t2, repo2, log2, runner2, fakebin2 = staged_tree(text, wrapper)
    open(os.path.join(repo2, "staged", "plan.txt"), "w").write("%s\t%s\n" % (os.path.join(repo2, "staged/witness-build/build-collection.payload"), os.path.join(repo2, "signed/witness-build/build-collection.json")))
    e2 = env_of(t2, log2, runner2, fakebin2, {"GITHUB_REF": "refs/tags/v0.3.0", "FAKE_SIGN_RC": "5"})
    r2 = subprocess.run(["bash", "bin/witness-sign-staged.sh", os.path.join(repo2, "staged"), os.path.join(repo2, "signed")], cwd=repo2, env=e2, capture_output=True, text=True, timeout=60)
    if r2.returncode == 0:
        bad.append("a failing signature does not stop the job")
    if os.listdir(runner2):
        bad.append("a token directory is left after a failing signature")
    if "--stage build" in read(os.path.join(log2, "cv.log")):
        bad.append("a record whose signing failed is still checked")
    shutil.rmtree(t2, ignore_errors=True)
    # refusals before any token is asked for
    for label, extra, drop in (("no role", {}, ("AWS_ROLE_ARN",)), ("no key reference", {}, ("RELEASE_KMS_KEY_REF",)), ("a failed fetch", {"FAKE_FETCH_FAIL": "1"}, ()), ("a null token", {"FAKE_TOKEN": "null"}, ())):
        t3, repo3, log3, runner3, fakebin3 = staged_tree(text, wrapper)
        open(os.path.join(repo3, "staged", "plan.txt"), "w").write("%s\t%s\n" % (os.path.join(repo3, "staged/witness-build/build-collection.payload"), os.path.join(repo3, "signed/witness-build/build-collection.json")))
        e3 = env_of(t3, log3, runner3, fakebin3, dict({"GITHUB_REF": "refs/tags/v0.3.0"}, **extra), drop)
        r3 = subprocess.run(["bash", "bin/witness-sign-staged.sh", os.path.join(repo3, "staged"), os.path.join(repo3, "signed")], cwd=repo3, env=e3, capture_output=True, text=True, timeout=60)
        if r3.returncode == 0 or os.path.exists(os.path.join(log3, "signrec.env")):
            bad.append("%s: the helper went on" % label)
        if os.listdir(runner3):
            bad.append("%s: a token directory is left behind" % label)
        shutil.rmtree(t3, ignore_errors=True)
    return bad


src2 = open(os.path.join(root, "bin", "witness-sign-staged.sh")).read()
src3 = open(os.path.join(root, "bin", "with-aws-token.sh")).read() if os.path.exists(os.path.join(root, "bin", "with-aws-token.sh")) else None
b2 = problems_staged(src2)
check("witness-sign-staged.sh: signs with the KMS key, token to a private file, cleaned up, every record checked", not b2, "; ".join(b2))


def mutant2(label, fn, on_wrapper=False):
    """A copy of the staged helper (or, with on_wrapper, of the token-fetch script it calls) with one property broken."""
    base = src3 if on_wrapper else src2
    if base is None:
        check("witness-sign-staged.sh mutant caught: %s" % label, False, "bin/with-aws-token.sh is missing")
        return
    text = fn(base)
    if text == base:
        check("mutant (%s) changed nothing: the mutation is wrong" % label, False)
        return
    bad = problems_staged(src2, text) if on_wrapper else problems_staged(text)
    check("witness-sign-staged.sh mutant caught: %s" % label, bool(bad), "caught nothing")


mutant2("audience sigstore", lambda s: s.replace("audience=sts.amazonaws.com", "audience=sigstore"), True)
mutant2("Witness used again to sign", lambda s: s.replace("bash bin/with-aws-token.sh sign-record --payload", "witness sign -f"))
mutant2("the staged payload not signed", lambda s: s.replace("sign-record", "verify"))
mutant2("the signing step runs under another template", lambda s: s.replace("release-policy.template.json", "other.json", 1) if "sign-record" in s.split("release-policy.template.json")[0].split("\n")[-1] else s.replace("--out \"$final\" --template .github/policy/release-policy.template.json", "--out \"$final\" --template other.json"))
mutant2("the sign-record call without the token script (no token per record)", lambda s: s.replace("bash bin/with-aws-token.sh sign-record", "python3 -I -B bin/chain-verify.py sign-record"))
mutant2("no cleanup of the token directory", lambda s: re.sub(r"^trap .*\n", "", s, flags=re.M).replace('rm -rf "$td"\n', ""), True)
mutant2("the signed record not checked", lambda s: re.sub(r"^  python3 -I -B bin/chain-verify.py verify .*\n", "", s, flags=re.M))
mutant2("the token directory inside the repository", lambda s: s.replace('"${RUNNER_TEMP:?}/witness-aws.XXXXXX"', '"./witness-aws.XXXXXX"'), True)

# ---------------------------------------------------------------------------------------------------------------------------------------
# bin/with-aws-token.sh CMD...: Sign's one copy of the token fetch for a signing call of its own (A1, #822 round 2: the provenance signature of the Sign job)

WARGS = ("sign-record", "--payload", "/x/payload", "--out", "/x/out.json", "--template", "t.json")


def run_wrapper(text, extra=None, drop=(), args=WARGS):
    t, repo, log, runner, fakebin = tree("with-aws-token.sh", text)
    e = env_of(t, log, runner, fakebin, extra, drop)
    open(os.path.join(t, "payload"), "w").write("p")
    a = [os.path.join(t, "payload") if x == "/x/payload" else (os.path.join(t, "out", "out.json") if x == "/x/out.json" else x) for x in args]
    r = subprocess.run(["bash", "bin/with-aws-token.sh"] + a, cwd=repo, env=e, capture_output=True, text=True, timeout=60)
    return t, repo, log, runner, r


def problems_wrapper(text):
    bad = []
    t, repo, log, runner, r = run_wrapper(text)
    stok = read(os.path.join(log, "signrec.tok")).splitlines()
    se = read(os.path.join(log, "signrec.env")).splitlines()
    tf = re.search(r"TOKFILE=(\S+)", (se or [""])[0])
    tf = tf.group(1) if tf else ""
    if r.returncode != 0:
        bad.append("exit %d: %s" % (r.returncode, r.stderr.strip()[:120]))
    if not read(os.path.join(log, "cv.log")).startswith("sign-record --payload "):
        bad.append("the verifier is not called with the arguments given: %r" % read(os.path.join(log, "cv.log"))[:200])
    if len(stok) != 1 or not stok[0].startswith("MODE=600 DIRMODE=700 CONTENT=" + TOKEN + " ") or not stok[0].endswith(" REGION=us-east-1 KEYREF=" + KEY):
        bad.append("the call does not see a mode 0600 token file in a 0700 directory holding exactly the token, with the region and the key reference: %r" % stok)
    if not tf or tf == "UNSET" or not os.path.realpath(tf).startswith(os.path.realpath(runner) + os.sep) or os.path.realpath(tf).startswith(os.path.realpath(repo) + os.sep):
        bad.append("the token file is not under RUNNER_TEMP outside the repository: %r" % tf)
    if len(se) != 1 or not se[0].startswith("ROLE=" + ROLE) or "TOKEXISTS=yes" not in se[0] or not se[0].endswith("REQ=UNSET|UNSET|UNSET"):
        bad.append("the call does not see the role and the token file, or sees a request variable: %r" % se)
    loops = read(os.path.join(log, "loop.log")).splitlines()
    if len(loops) != 1 or not loops[0].endswith("&audience=sts.amazonaws.com"):
        bad.append("the token is not asked for exactly once with audience sts.amazonaws.com: %r" % loops)
    if tf and tf != "UNSET" and os.path.exists(os.path.dirname(tf)):
        bad.append("the token directory still exists after the call")
    if TOKEN in r.stdout.replace("::add-mask::" + TOKEN, "") or TOKEN in r.stderr:
        bad.append("the token is in the output")
    if read(os.path.join(log, "github_env")):
        bad.append("something was written to GITHUB_ENV")
    shutil.rmtree(t, ignore_errors=True)
    # B3 (#822 round 3): the provenance signature of Sign is `with-aws-token.sh sign --check ...`: the same token, in the same private file, for that call too
    t9, repo9, log9, runner9, r9 = run_wrapper(text, args=("sign", "--check", "--signer", "cosign"))
    sp = read(os.path.join(log9, "signprov.tok")).splitlines()
    if r9.returncode != 0 or not read(os.path.join(log9, "cv.log")).startswith("sign --check --signer cosign"):
        bad.append("the provenance call `sign --check ...` does not reach the verifier with its arguments (exit %d): %r" % (r9.returncode, read(os.path.join(log9, "cv.log"))[:200]))
    if len(sp) != 1 or not sp[0].startswith("MODE=600 DIRMODE=700 CONTENT=" + TOKEN + " ROLE=" + ROLE):
        bad.append("the provenance call does not see a mode 0600 token file in a 0700 directory holding exactly the token, with the role: %r" % sp)
    if os.listdir(runner9):
        bad.append("a token directory is left after the provenance call")
    shutil.rmtree(t9, ignore_errors=True)
    # KA-2 p4 group 4: the evidence letter's kms-sign call runs under the same wrapper: the same fresh token, in the same private file, for that call only
    tk, repok, logk, runnerk, rk = run_wrapper(text, args=("kms-sign", "--aws", "/x/aws-cli/aws"))
    kt = read(os.path.join(logk, "kmssign.tok")).splitlines()
    if rk.returncode != 0 or not read(os.path.join(logk, "cv.log")).startswith("kms-sign --aws /x/aws-cli/aws"):
        bad.append("the kms-sign call does not reach the verifier with its arguments (exit %d): %r" % (rk.returncode, read(os.path.join(logk, "cv.log"))[:200]))
    if len(kt) != 1 or not kt[0].startswith("MODE=600 DIRMODE=700 CONTENT=" + TOKEN + " ROLE=" + ROLE):
        bad.append("the kms-sign call does not see a mode 0600 token file in a 0700 directory holding exactly the token, with the role: %r" % kt)
    if os.listdir(runnerk):
        bad.append("a token directory is left after the kms-sign call")
    shutil.rmtree(tk, ignore_errors=True)
    t2, repo2, log2, runner2, r2 = run_wrapper(text, {"FAKE_SIGN_RC": "7"})
    if r2.returncode != 7 or os.listdir(runner2):
        bad.append("the call's exit status (7) is not kept or a token directory is left (exit %d, left %r)" % (r2.returncode, os.listdir(runner2)))
    shutil.rmtree(t2, ignore_errors=True)
    for label, extra, drop in (("an empty token", {"FAKE_TOKEN": ""}, ()), ("a null token", {"FAKE_TOKEN": "null"}, ()), ("a failed fetch", {"FAKE_FETCH_FAIL": "1"}, ()),
                               ("no role", {}, ("AWS_ROLE_ARN",)), ("no region", {}, ("AWS_REGION",)), ("no key reference", {}, ("RELEASE_KMS_KEY_REF",)), ("no RUNNER_TEMP", {}, ("RUNNER_TEMP",))):
        t3, repo3, log3, runner3, r3 = run_wrapper(text, extra, drop)
        if r3.returncode == 0 or os.path.exists(os.path.join(log3, "signrec.env")):
            bad.append("%s: the call ran or the wrapper did not fail (exit %d)" % (label, r3.returncode))
        if label != "no RUNNER_TEMP" and os.listdir(runner3):
            bad.append("%s: a token directory is left behind" % label)
        shutil.rmtree(t3, ignore_errors=True)
    for label, args in (("no subcommand", ()), ("another subcommand (verify)", ("verify", "--record", "r.json")), ("a program instead of a subcommand", ("bash", "-c", "true"))):
        t4, repo4, log4, runner4, r4 = run_wrapper(text, args=args)
        if r4.returncode == 0 or os.path.exists(os.path.join(log4, "loop.log")) or os.path.exists(os.path.join(log4, "cv.log")):
            bad.append("%s: the wrapper went on (exit %d)" % (label, r4.returncode))
        shutil.rmtree(t4, ignore_errors=True)
    return bad


if src3 is None:
    check("with-aws-token.sh exists: the provenance signature and the staged records share one token fetch", False, "bin/with-aws-token.sh is missing")
else:
    b3 = problems_wrapper(src3)
    check("with-aws-token.sh: a fresh token to a private file for one command, removed right after, nothing else sees it", not b3, "; ".join(b3))


def mutant3(label, fn):
    if src3 is None:
        check("with-aws-token.sh mutant caught: %s" % label, False, "bin/with-aws-token.sh is missing")
        return
    text = fn(src3)
    if text == src3:
        check("mutant (%s) changed nothing: the mutation is wrong" % label, False)
        return
    check("with-aws-token.sh mutant caught: %s" % label, bool(problems_wrapper(text)), "caught nothing")


mutant3("audience sigstore", lambda s: s.replace("audience=sts.amazonaws.com", "audience=sigstore"))
mutant3("the token directory is not removed", lambda s: re.sub(r"^trap .*\n", "", s, flags=re.M).replace('rm -rf "$td"\n', ""))
mutant3("the command's exit status lost", lambda s: s.replace('exit "$rc"', "exit 0"))
mutant3("a null token accepted", lambda s: s.replace('[ -n "$tok" ] && [ "$tok" != null ] || ', "true || "))
mutant3("the request variables stay in the command's environment", lambda s: re.sub(r"^unset ACTIONS_ID_TOKEN_REQUEST_TOKEN.*\n", "", s, flags=re.M))
mutant3("the token file is set for sign-record only (the provenance call gets none)", lambda s: s.replace('AWS_WEB_IDENTITY_TOKEN_FILE="$td/token" python3 -I -B bin/chain-verify.py "$@" ${extra[@]+"${extra[@]}"} || rc=$?', 'if [ "$1" = sign-record ]; then export AWS_WEB_IDENTITY_TOKEN_FILE="$td/token"; fi; python3 -I -B bin/chain-verify.py "$@" ${extra[@]+"${extra[@]}"} || rc=$?'))
mutant3("the token file readable by others", lambda s: s.replace("umask 077\n", "umask 022\n"))
mutant3("the wrapper no longer passes kms-sign through (KA-2 p4 group 4)", lambda s: s.replace("sign-record|sign|kms-sign)", "sign-record|sign)"))


EXPECT = 36
print("pass=%d fail=%d" % (passn, failn))
if passn + failn != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passn + failn, EXPECT))
    sys.exit(1)
sys.exit(0 if failn == 0 else 1)
PY
