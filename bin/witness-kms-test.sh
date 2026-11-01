#!/usr/bin/env bash
# Tests for how the two Witness helpers that hold an identity token sign with the release KMS key (handoff 0713, rows P2 and P9):
#   bin/witnessed.sh STEP SCRIPT...      Release's six steps: `witness run` with a throwaway key, then the one signing function
#   bin/witness-sign-staged.sh STAGED SIGNED   Sign's step for Build's, Rebuild's and Check's records: the same signing function
# Offline: `witness`, the token endpoint helper (bin/loopback-get.sh) and the verifier (which holds the signing function, `sign-record`) are doubles made here;
# nothing reaches AWS, KMS, a network or a public log (the signing function itself is tested in bin/chain-rekor-key-test.sh with a fake cosign).
# What it proves, by running the real helper against the doubles (the doubles record what they were given):
#   - Witness runs with a throwaway key file made for the step (never the KMS key, no Fulcio, timestamp or certificate flag); the collection's payload is then signed by
#     `sign-record` (the key named by RELEASE_KMS_KEY_REF, the job pins the value awskms:///alias/fosterstack-release-signing); a failing Witness is not signed; a failing signature fails the helper
#   - the identity token is asked for exactly once, with audience sts.amazonaws.com (the audience the AWS trust requires), and lands in a file of mode 0600 in a
#     directory under RUNNER_TEMP, outside the repository tree; the file holds only the token, and the token is in no argument, log line or record
#   - the AWS SDK is pointed at that file by AWS_WEB_IDENTITY_TOKEN_FILE and at the role by AWS_ROLE_ARN, for Witness; the wrapped script of every step but
#     release-sign and release-apks has neither; the request variables are gone for all; nothing is written to GITHUB_ENV
#   - both variables are sensitive keys of the record; no SIGSTORE_ID_TOKEN is used
#   - the token directory is gone after success, after a failing Witness (its exit status is kept), and after a refusal
#   - a job with no role or region, a missing RUNNER_TEMP, or an empty or null token stops before Witness runs
# Each property is also proven on a MUTANT of the helper (a copy with that one property broken): a judge that cannot fail proves nothing.
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 - "$root" <<'PY'
import json, os, re, shutil, stat, subprocess, sys, tempfile

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
        print("FAIL %s%s" % (label, (" (" + detail[:240] + ")") if detail else ""))


FAKE_LOOP = r'''#!/bin/sh
echo "$*" >> "$LOG/loop.log"
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
  if [ -n "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]; then
    echo "TOKEXISTS $([ -f "$AWS_WEB_IDENTITY_TOKEN_FILE" ] && echo yes || echo no)"
    echo "TOKMODE $(stat -c %a "$AWS_WEB_IDENTITY_TOKEN_FILE" 2> /dev/null || echo none)"
    echo "TOKDIRMODE $(stat -c %a "$(dirname "$AWS_WEB_IDENTITY_TOKEN_FILE")" 2> /dev/null || echo none)"
    echo "TOKCONTENT $(cat "$AWS_WEB_IDENTITY_TOKEN_FILE" 2> /dev/null)"
  fi
  echo "CWD $(pwd)"
} >> "$LOG/witness.log"
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
  printf '{"payloadType":"application/vnd.in-toto+json","payload":"%s","signatures":[]}\n' "$(printf 'PAYLOAD-OF-WITNESS' | base64 -w0)" > "$out"
fi
exit "${FAKE_WITNESS_RC:-0}"
'''

FAKE_CV = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv[1:]
log = os.environ["LOG"]
open(log + "/cv.log", "a").write(" ".join(a) + "\n")
if a[:2] == ["policy", "make"]:
    open(a[a.index("--out") + 1], "w").write("{}")
if a[:1] == ["sign-record"]:
    tf = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "UNSET")
    open(log + "/signrec.env", "a").write("ROLE=%s TOKFILE=%s TOKEXISTS=%s REQ=%s|%s|%s\n" % (
        os.environ.get("AWS_ROLE_ARN", "UNSET"), tf, "yes" if os.path.isfile(tf) else "no", os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "UNSET"),
        os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "UNSET"), os.environ.get("ACTIONS_RUNTIME_TOKEN", "UNSET")))
    open(log + "/signrec.payload", "wb").write(open(a[a.index("--payload") + 1], "rb").read())
    if os.environ.get("FAKE_SIGN_RC"):
        sys.exit(int(os.environ["FAKE_SIGN_RC"]))
    out = a[a.index("--out") + 1]
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    open(out, "w").write("{}")
    open(out[: -len(".json")] + ".rekor.json", "w").write("{}")
'''

FAKE_INNER = r'''#!/usr/bin/env bash
env | grep -E '^(AWS_|ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|SIGSTORE)' | sort >> "$LOG/inner.log"
echo ran >> "$LOG/inner.log"
'''


def sh(path, text, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


def tree(helper, text):
    """A repository tree with the helper under test, the doubles on PATH, and a RUNNER_TEMP outside the tree."""
    t = tempfile.mkdtemp()
    repo, log, runner, fakebin = (os.path.join(t, n) for n in ("repo", "log", "runner", "fakebin"))
    for d in (repo, log, runner, fakebin):
        os.makedirs(d)
    sh(os.path.join(repo, "bin", helper), text)
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


def run_witnessed(text, step="release-verify", extra=None, drop=()):
    t, repo, log, runner, fakebin = tree("witnessed.sh", text)
    e = env_of(t, log, runner, fakebin, extra, drop)
    r = subprocess.run(["bash", "bin/witnessed.sh", step, "bin/inner.sh"], cwd=repo, env=e, capture_output=True, text=True, timeout=60)
    return t, repo, log, runner, r


def problems_witnessed(text):
    """Everything wrong with a witnessed.sh, judged by running it for release-verify (a step with no key of its own) and for release-sign."""
    bad = []
    t, repo, log, runner, r = run_witnessed(text, "release-verify")
    argv = (lines(log, "witness.log", "ARGV") or [""])[0]
    tokfile = (lines(log, "witness.log", "TOKFILE") or [""])[0]
    tokdir = os.path.dirname(tokfile) if tokfile and tokfile != "UNSET" else ""
    if r.returncode != 0:
        bad.append("release-verify exit %d: %s" % (r.returncode, r.stderr.strip()[:120]))
    if "--signer-kms-ref" in argv or not re.search(r"--signer-file-key-path \S+/key\.pem", argv):
        bad.append("Witness is not told to sign with a throwaway key file (or is still told the KMS key)")
    sr = [l for l in read(os.path.join(log, "cv.log")).splitlines() if l.startswith("sign-record ")]
    want_sr = "sign-record --payload %s --out witness-release-verify/release-verify-collection.json --template .github/policy/release-policy.template.json"
    if len(sr) != 1 or not re.fullmatch(re.escape(want_sr).replace("%s", r"\S+/payload"), sr[0].replace("\\", "")) and not re.fullmatch(want_sr % r"\S+/payload", sr[0]):
        bad.append("the collection is not signed once by sign-record with --payload, --out and --template as pinned: %r" % sr)
    se = read(os.path.join(log, "signrec.env")).splitlines()
    if len(se) != 1 or not se[0].startswith("ROLE=" + ROLE) or "TOKEXISTS=yes" not in se[0] or not se[0].endswith("REQ=UNSET|UNSET|UNSET"):
        bad.append("sign-record does not see the role and the token file, or sees a request variable: %r" % se)
    if read(os.path.join(log, "signrec.payload")) != "PAYLOAD-OF-WITNESS":
        bad.append("sign-record is not handed the payload Witness wrote")
    if re.search(r"fulcio|oidc|--timestamp|timestamp\.sigstore|\s-t\s|certificate", argv):
        bad.append("a Fulcio, OIDC, timestamp or certificate flag is still given to Witness")
    if "timeout" in argv:
        bad.append("the wrapped command is still under the ten-minute certificate timeout")
    loops = read(os.path.join(log, "loop.log")).splitlines()
    if len(loops) != 1 or not loops[0].endswith("&audience=sts.amazonaws.com"):
        bad.append("the identity token is not asked for exactly once with audience sts.amazonaws.com: %r" % loops)
    if tokfile in ("", "UNSET"):
        bad.append("Witness does not see AWS_WEB_IDENTITY_TOKEN_FILE")
    else:
        if (lines(log, "witness.log", "TOKEXISTS") or [""])[0] != "yes":
            bad.append("the token file does not exist while Witness runs")
        if (lines(log, "witness.log", "TOKMODE") or [""])[0] != "600":
            bad.append("the token file is not mode 0600")
        if (lines(log, "witness.log", "TOKDIRMODE") or [""])[0] != "700":
            bad.append("the token directory is not mode 0700")
        if (lines(log, "witness.log", "TOKCONTENT") or [""])[0] != TOKEN:
            bad.append("the token file does not hold exactly the token")
        if not os.path.realpath(tokfile).startswith(os.path.realpath(runner) + os.sep):
            bad.append("the token file is not under RUNNER_TEMP")
        if os.path.realpath(tokfile).startswith(os.path.realpath(repo) + os.sep):
            bad.append("the token file is inside the repository tree")
    if (lines(log, "witness.log", "ROLE") or [""])[0] != ROLE:
        bad.append("Witness does not see AWS_ROLE_ARN")
    if (lines(log, "witness.log", "REQ") or [""])[0] != "UNSET|UNSET|UNSET":
        bad.append("the identity-token request or runtime variables reach Witness: %r" % (lines(log, "witness.log", "REQ") or [""])[0])
    inner = read(os.path.join(log, "inner.log"))
    if "ran" not in inner:
        bad.append("the wrapped script did not run")
    if re.search(r"^AWS_(WEB_IDENTITY_TOKEN_FILE|ROLE_ARN)=", inner, re.M):
        bad.append("the wrapped script of release-verify still sees the AWS variables")
    if re.search(r"^ACTIONS_ID_TOKEN|^SIGSTORE", inner, re.M):
        bad.append("the wrapped script sees a request variable or SIGSTORE_ID_TOKEN")
    for k in ("AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"):
        if "--env-add-sensitive-key " + k not in argv:
            bad.append("%s is not a sensitive key of the record" % k)
    if "SIGSTORE_ID_TOKEN" in argv:
        bad.append("SIGSTORE_ID_TOKEN is still a sensitive key (it no longer exists)")
    if TOKEN in argv or TOKEN in read(os.path.join(log, "inner.log")) or TOKEN in r.stderr.replace("::add-mask::" + TOKEN, ""):
        bad.append("the token is in an argument, the script's environment or the output")
    if read(os.path.join(log, "github_env")):
        bad.append("something was written to GITHUB_ENV")
    if tokdir and os.path.exists(tokdir):
        bad.append("the token directory still exists after success")
    # release-sign: the one wrapped script that signs with the key itself keeps both variables
    t2, repo2, log2, runner2, r2 = run_witnessed(text, "release-sign")
    inner2 = read(os.path.join(log2, "inner.log"))
    if not (re.search(r"^AWS_ROLE_ARN=" + re.escape(ROLE) + "$", inner2, re.M) and re.search(r"^AWS_WEB_IDENTITY_TOKEN_FILE=", inner2, re.M)):
        bad.append("the wrapped script of release-sign does not keep AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE")
    if len(read(os.path.join(log2, "loop.log")).splitlines()) != 1:
        bad.append("release-sign asks for more than one token")
    # release-apks (K2): the apk signer calls cosign with the KMS key itself, so its wrapped script keeps both variables too
    t2b, repo2b, log2b, runner2b, r2b = run_witnessed(text, "release-apks")
    inner2b = read(os.path.join(log2b, "inner.log"))
    if not (re.search(r"^AWS_ROLE_ARN=" + re.escape(ROLE) + "$", inner2b, re.M) and re.search(r"^AWS_WEB_IDENTITY_TOKEN_FILE=", inner2b, re.M)):
        bad.append("the wrapped script of release-apks does not keep AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE")
    # a failing Witness: its exit status is kept and the token directory is gone
    t3, repo3, log3, runner3, r3 = run_witnessed(text, "release-verify", {"FAKE_WITNESS_RC": "7"})
    d3 = os.path.dirname((lines(log3, "witness.log", "TOKFILE") or [""])[0])
    if r3.returncode != 7:
        bad.append("a failing Witness (7) ends the helper with %d" % r3.returncode)
    if "sign-record" in read(os.path.join(log3, "cv.log")):
        bad.append("a failing Witness is still signed")
    # a failing signature fails the helper and leaves no token directory
    t6, repo6, log6, runner6, r6 = run_witnessed(text, "release-verify", {"FAKE_SIGN_RC": "3"})
    if r6.returncode == 0:
        bad.append("a failing signature does not fail the helper")
    if os.listdir(runner6):
        bad.append("a token directory is left after a failing signature")
    shutil.rmtree(t6, ignore_errors=True)
    if d3 and os.path.exists(d3):
        bad.append("the token directory still exists after a failing Witness")
    # refusals: nothing is run, nothing is left
    for label, extra, drop in (("no role", {}, ("AWS_ROLE_ARN",)), ("no region", {}, ("AWS_REGION",)), ("no key reference", {}, ("RELEASE_KMS_KEY_REF",)), ("a key reference that is not a KMS one", {"RELEASE_KMS_KEY_REF": "arn:aws:kms:x"}, ()), ("no RUNNER_TEMP", {}, ("RUNNER_TEMP",)),
                               ("an empty token", {"FAKE_TOKEN": ""}, ()), ("a null token", {"FAKE_TOKEN": "null"}, ()), ("a failed fetch", {"FAKE_FETCH_FAIL": "1"}, ())):
        t4, repo4, log4, runner4, r4 = run_witnessed(text, "release-verify", extra, drop)
        if r4.returncode == 0 or os.path.exists(os.path.join(log4, "witness.log")):
            bad.append("%s: the helper went on (exit %d)" % (label, r4.returncode))
        if label != "no RUNNER_TEMP" and os.listdir(runner4):
            bad.append("%s: a token directory is left behind" % label)
        if label in ("no role", "no region", "no key reference", "a key reference that is not a KMS one") and os.path.exists(os.path.join(log4, "loop.log")):
            bad.append("%s: a token was asked for before the job was checked" % label)
    t5, repo5, log5, runner5, r5 = run_witnessed(text, "release-nonsense")
    if r5.returncode != 2:
        bad.append("an unknown step does not exit 2")
    for d in (t, t2, t3, t4, t5):
        shutil.rmtree(d, ignore_errors=True)
    return bad


src = open(os.path.join(root, "bin", "witnessed.sh")).read()
b = problems_witnessed(src)
check("witnessed.sh: signs with the KMS key, token to a private file, variables scoped, cleaned up", not b, "; ".join(b))


def mutant(label, fn):
    text = fn(src)
    if text == src:
        check("mutant (%s) changed nothing: the mutation is wrong" % label, False)
        return
    bad = problems_witnessed(text)
    check("witnessed.sh mutant caught: %s" % label, bool(bad), "caught nothing")


mutant("audience sigstore", lambda s: s.replace("audience=sts.amazonaws.com", "audience=sigstore"))
mutant("no trap and no removal of the token directory", lambda s: re.sub(r"^trap .*\n", "", s, flags=re.M).replace('rm -rf "$td"\n', ""))
mutant("the wrapped script keeps the AWS variables", lambda s: s.replace("wrap=(env -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN)", "wrap=()"))
mutant("a value written to GITHUB_ENV", lambda s: s.replace("rc=0\nwitness run", 'echo "AWS_ROLE_ARN=$AWS_ROLE_ARN" >> "${GITHUB_ENV:-/dev/null}"\nrc=0\nwitness run'))
mutant("the token directory inside the repository", lambda s: s.replace('"${RUNNER_TEMP:?}/witness-aws.XXXXXX"', '"./witness-aws.XXXXXX"'))
mutant("AWS_ROLE_ARN not a sensitive key", lambda s: s.replace("  --env-add-sensitive-key AWS_ROLE_ARN \\\n", ""))
mutant("a Fulcio flag", lambda s: s.replace("witness run --step", "witness run --signer-fulcio-url https://fulcio.sigstore.dev --step"))
mutant("Witness told to sign with the KMS key itself again", lambda s: s.replace('--signer-file-key-path "$td/key.pem"', '--signer-kms-ref "$RELEASE_KMS_KEY_REF"'))
mutant("the collection is not signed with the release key", lambda s: s.replace("sign-record", "verify"))
mutant("a failing signature ignored", lambda s: s.replace("--template .github/policy/release-policy.template.json || rc=$?", "--template .github/policy/release-policy.template.json || true"))
mutant("a failing Witness signed anyway", lambda s: s.replace('if [ "$rc" -eq 0 ]; then', "if true; then"))
mutant("the ten-minute timeout kept", lambda s: s.replace('bash "$@" || rc=$?', 'timeout -k 20 540 bash "$@" || rc=$?'))
mutant("the exit status of Witness lost", lambda s: s.replace('exit "$rc"', "exit 0"))
mutant("the token file readable by others", lambda s: s.replace("umask 077\n", "umask 022\n"))
mutant("no role check before the token is asked for", lambda s: s.replace(': "${AWS_ROLE_ARN:?witnessed: AWS_ROLE_ARN is missing}"\n', ""))
mutant("the token not checked for null", lambda s: s.replace('[ -n "$tok" ] && [ "$tok" != null ] || { echo "witnessed: no identity token" >&2; exit 1; }\n', ""))
mutant("release-sign loses the variables too", lambda s: s.replace("  release-sign|release-apks) wrap=() ;;", "  release-apks) wrap=() ;;"))
mutant("release-apks loses the variables too", lambda s: s.replace("  release-sign|release-apks) wrap=() ;;", "  release-sign) wrap=() ;;"))

# ---------------------------------------------------------------------------------------------------------------------------------------
# bin/witness-sign-staged.sh: Sign's step for the records of the jobs that hold no token



def staged_tree(text):
    t, repo, log, runner, fakebin = tree("witness-sign-staged.sh", text)
    st = os.path.join(repo, "staged")
    os.makedirs(os.path.join(st, "witness-build"))
    open(os.path.join(st, "witness-build", "build-collection.payload"), "w").write("payload")
    open(os.path.join(st, "witness-build", "digests.json"), "w").write("{}")
    open(os.path.join(st, "plan.txt"), "w").write("staged/witness-build/build-collection.payload\tsigned/witness-build/build-collection.json\n")
    return t, repo, log, runner, fakebin




def problems_staged(text):
    bad = []
    t, repo, log, runner, fakebin = staged_tree(text)
    # the plan is written with paths relative to the repository root, as the verifier prints them
    plan = os.path.join(repo, "staged", "plan.txt")
    open(plan, "w").write("%s\t%s\n" % (os.path.join(repo, "staged/witness-build/build-collection.payload"), os.path.join(repo, "signed/witness-build/build-collection.json")))
    e = env_of(t, log, runner, fakebin, {"GITHUB_REF": "refs/tags/v0.3.0"})
    r = subprocess.run(["bash", "bin/witness-sign-staged.sh", os.path.join(repo, "staged"), os.path.join(repo, "signed")], cwd=repo, env=e, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        bad.append("exit %d: %s" % (r.returncode, r.stderr.strip()[:160]))
    if os.path.exists(os.path.join(log, "witness.log")):
        bad.append("Witness is run: Sign signs through the one signing function only")
    want_sr = "sign-record --payload %s --out %s --template .github/policy/release-policy.template.json" % (
        os.path.join(repo, "staged/witness-build/build-collection.payload"), os.path.join(repo, "signed/witness-build/build-collection.json"))
    if want_sr not in read(os.path.join(log, "cv.log")).splitlines():
        bad.append("the staged payload is not signed by sign-record as pinned: %r" % read(os.path.join(log, "cv.log"))[:300])
    argv = want_sr
    loops = read(os.path.join(log, "loop.log")).splitlines()
    if len(loops) != 1 or not loops[0].endswith("&audience=sts.amazonaws.com"):
        bad.append("the identity token is not asked for exactly once with audience sts.amazonaws.com: %r" % loops)
    se = read(os.path.join(log, "signrec.env")).splitlines()
    if len(se) != 1 or not se[0].startswith("ROLE=" + ROLE) or "TOKEXISTS=yes" not in se[0] or not se[0].endswith("REQ=UNSET|UNSET|UNSET"):
        bad.append("sign-record does not see the role and the token file, or sees a request variable: %r" % se)
    else:
        tokfile = re.search(r"TOKFILE=(\S+)", se[0]).group(1)
        if not os.path.realpath(tokfile).startswith(os.path.realpath(runner) + os.sep):
            bad.append("the token file is not under RUNNER_TEMP")
        if os.path.exists(os.path.dirname(tokfile)):
            bad.append("the token directory still exists after success")
    cv = read(os.path.join(log, "cv.log"))
    if "policy make" not in cv or not re.search(r"^verify --policy policy\.json --stage build --record .*build-collection\.json$", cv, re.M):
        bad.append("the signed record is not checked with the verifier under the policy made for the ref: %r" % cv[:200])
    if TOKEN in argv or TOKEN in r.stdout.replace("::add-mask::" + TOKEN, "") or TOKEN in r.stderr:
        bad.append("the token is in an argument or the output")
    if read(os.path.join(log, "github_env")):
        bad.append("something was written to GITHUB_ENV")
    shutil.rmtree(t, ignore_errors=True)
    # a failing Witness stops the job and leaves no token directory
    t2, repo2, log2, runner2, fakebin2 = staged_tree(text)
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
        t3, repo3, log3, runner3, fakebin3 = staged_tree(text)
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
b2 = problems_staged(src2)
check("witness-sign-staged.sh: signs with the KMS key, token to a private file, cleaned up, every record checked", not b2, "; ".join(b2))


def mutant2(label, fn):
    text = fn(src2)
    if text == src2:
        check("mutant (%s) changed nothing: the mutation is wrong" % label, False)
        return
    check("witness-sign-staged.sh mutant caught: %s" % label, bool(problems_staged(text)), "caught nothing")


mutant2("audience sigstore", lambda s: s.replace("audience=sts.amazonaws.com", "audience=sigstore"))
mutant2("Witness used again to sign", lambda s: s.replace("python3 -I -B bin/chain-verify.py sign-record --payload", "witness sign -f"))
mutant2("the staged payload not signed", lambda s: s.replace("sign-record", "verify"))
mutant2("the signing step runs under another template", lambda s: s.replace("release-policy.template.json", "other.json", 1) if "sign-record" in s.split("release-policy.template.json")[0].split("\n")[-1] else s.replace("--out \"$final\" --template .github/policy/release-policy.template.json", "--out \"$final\" --template other.json"))
mutant2("no cleanup of the token directory", lambda s: re.sub(r"^trap .*\n", "", s, flags=re.M).replace('rm -rf "$td"\n', ""))
mutant2("the signed record not checked", lambda s: re.sub(r"^  python3 -I -B bin/chain-verify.py verify .*\n", "", s, flags=re.M))
mutant2("the token directory inside the repository", lambda s: s.replace('"${RUNNER_TEMP:?}/witness-aws.XXXXXX"', '"./witness-aws.XXXXXX"'))

EXPECT = 26
print("pass=%d fail=%d" % (passn, failn))
if passn + failn != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passn + failn, EXPECT))
    sys.exit(1)
sys.exit(0 if failn == 0 else 1)
PY
