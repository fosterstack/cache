#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC12
# proves: REQ-CHAIN-007-AC15
# (#822 round 1: T1 and P1 below. Wording pending the owner's approval, for the ACs whose approved text the round 1 fixes make false: REQ-CHAIN-007-AC1 and AC2 (no env up to and including release-verify;
#  any other env name refused), REQ-CHAIN-007-AC18 (any other env name refused), REQ-CHAIN-001-AC1 (step env names come from the closed env_names list), REQ-CHAIN-001-AC2 (Sign's steps: a Witness install and a
#  Witness sign step, no step env, cosign in one job), REQ-CHAIN-007-AC9 (what is attached: no entries files). REQ-CHAIN-004-AC10 (Sign signs keyless with the Sigstore timestamp) was already made false by the
#  KMS signing of the base and is named here for the same reason.)
# Tests for how the two Witness helpers that hold an identity token sign with the release KMS key (handoff 0713, rows P2 and P9):
#   bin/witnessed.sh STEP SCRIPT...      Release's six steps: `witness run` with a throwaway key, then the one signing function
#   bin/witness-sign-staged.sh STAGED SIGNED   Sign's step for Build's, Rebuild's and Check's records: the same signing function
# Offline: `witness`, the token endpoint helper (bin/loopback-get.sh) and the verifier (which holds the signing function, `sign-record`) are doubles made here;
# nothing reaches AWS, KMS, a network or a public log (the signing function itself is tested in bin/chain-rekor-key-test.sh with a fake cosign).
# What it proves, by running the real helper against the doubles (the doubles record what they were given):
#   - Witness runs with a throwaway key file made for the step (never the KMS key, no Fulcio, timestamp or certificate flag); the collection's payload is then signed by
#     `sign-record` (the key named by RELEASE_KMS_KEY_REF, the job pins the value awskms:///alias/fosterstack-release-signing); a failing Witness is not signed; a failing signature fails the helper
#   - the identity token is asked for once for the step and once for the signing call on release-sign and release-apks, exactly once on every other step, with audience sts.amazonaws.com (the audience the AWS
#     trust requires), and lands in a file of mode 0600 in a directory under RUNNER_TEMP, outside the repository tree; the file holds only the token, and the token is in no argument, log line or record
#   - Witness's own environment holds no AWS role or token-path variable, no AWS_ name at all on a step that does not sign, and no request variable, for every step; the AWS SDK is pointed at a token file by
#     AWS_WEB_IDENTITY_TOKEN_FILE and at the role by AWS_ROLE_ARN for the signing call only (sign-record, with a fresh token). The wrapped command is the plain `bash SCRIPT` for every step (the command-run
#     attestor records it, and record-env refuses a record that names the AWS role or token-file variables). release-sign and release-apks only are handed the role and a token file as RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE
#     (sensitive keys, so no record holds them), and bin/release-sign.sh and bin/release-sign-apks.sh map them onto the two AWS variables themselves, each before its first aws or cosign call, refusing (naming only RELEASE_*)
#     when either is empty; the token file is removed when Witness returns, before the fresh token for the signing call is fetched; nothing is written to GITHUB_ENV
#   - bin/with-aws-token.sh (Sign's one token fetch, of its provenance signature and of each staged record): a fresh token, mode 0600 in a 0700 directory under RUNNER_TEMP, for one call only,
#     removed the moment the call ends, its exit status kept; no request variable reaches the call; no call on a failed, empty or null token
#   - both variables are sensitive keys of the record; no SIGSTORE_ID_TOKEN is used
#   - the token directory is gone after success, after a failing Witness (its exit status is kept), and after a refusal
#   - a job with no role or region, a missing RUNNER_TEMP, or an empty or null token stops before Witness runs
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
    sh(os.path.join(repo, "bin", "release-sign.sh"), FAKE_INNER)
    sh(os.path.join(repo, "bin", "release-apks.sh"), FAKE_INNER)      # the target of release-apks, the other step whose script signs itself (bin/release-sign-apks.sh maps the sensitive names itself)      # the target of release-sign, the one step whose script signs itself (bin/release-sign.sh maps the sensitive names itself, see problems_creds)
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
    r = subprocess.run(["bash", "bin/witnessed.sh", step, ("bin/%s.sh" % step) if step in ("release-sign", "release-apks") else "bin/inner.sh"], cwd=repo, env=e, capture_output=True, text=True, timeout=60)
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
    # T1 (#822 round 1): Witness and the wrapped command run first, with no token file and no AWS variable; the token is fetched just before sign-record
    if read(os.path.join(log, "seq")).split() != ["witness", "loop", "sign-record"]:
        bad.append("the order is not Witness, then one token fetch, then sign-record: %r" % read(os.path.join(log, "seq")).split())
    if tokfile not in ("", "UNSET") or (lines(log, "witness.log", "RTFILES") or ["0"])[0] != "0" or (lines(log, "witness.log", "LOOPN") or ["9"])[0] != "0":
        bad.append("Witness runs with a token already fetched (token variable %r, files under RUNNER_TEMP %r, fetches so far %r)" % (
            tokfile, (lines(log, "witness.log", "RTFILES") or ["?"])[0], (lines(log, "witness.log", "LOOPN") or ["?"])[0]))
    stok = read(os.path.join(log, "signrec.tok")).splitlines()
    srtf = re.search(r"TOKFILE=(\S+)", (read(os.path.join(log, "signrec.env")).splitlines() or [""])[0])
    tokdir = os.path.dirname(srtf.group(1)) if srtf and srtf.group(1) != "UNSET" else ""
    if len(stok) != 1 or not stok[0].startswith("MODE=600 DIRMODE=700 CONTENT=" + TOKEN + " ") or not stok[0].endswith(" REGION=us-east-1 KEYREF=" + KEY):
        bad.append("sign-record does not see a mode 0600 token file in a 0700 directory holding exactly the token, with the region and the key reference: %r" % stok)
    if srtf and (not os.path.realpath(srtf.group(1)).startswith(os.path.realpath(runner) + os.sep) or os.path.realpath(srtf.group(1)).startswith(os.path.realpath(repo) + os.sep)):
        bad.append("the token file is not under RUNNER_TEMP, outside the repository tree")
    if (lines(log, "witness.log", "ROLE") or [""])[0] != "UNSET":
        bad.append("Witness sees AWS_ROLE_ARN")
    if (lines(log, "witness.log", "NAMES") or ["x"])[0].strip() != "":
        bad.append("release-verify: Witness sees AWS_ or RELEASE_ variables (it must see none on a step that does not sign): %r" % (lines(log, "witness.log", "NAMES") or [""])[0])
    if (lines(log, "witness.log", "REQ") or [""])[0] != "UNSET|UNSET|UNSET":
        bad.append("the identity-token request or runtime variables reach Witness: %r" % (lines(log, "witness.log", "REQ") or [""])[0])
    inner = read(os.path.join(log, "inner.log"))
    if "ran" not in inner:
        bad.append("the wrapped script did not run")
    if re.search(r"^(AWS_|RELEASE_)", inner, re.M):
        bad.append("the wrapped script of release-verify still sees an AWS variable")
    if "RTFILES 0" not in inner:
        bad.append("a token file exists while the wrapped script of release-verify runs")
    if re.search(r"^ACTIONS_ID_TOKEN|^SIGSTORE", inner, re.M):
        bad.append("the wrapped script sees a request variable or SIGSTORE_ID_TOKEN")
    for k in ("AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "RELEASE_ROLE_ARN", "RELEASE_TOKEN_FILE"):
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
    for stp in ("release-sign", "release-apks"):
        def badx(m, stp=stp):
            bad.append(m.replace("release-sign", stp))
        # release-sign: the one wrapped script that signs with the key itself is handed the role and a token file as RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE (bin/release-sign.sh maps them onto the AWS variables
        # itself, see problems_creds); Witness's argv and environment hold no AWS role or token-path name, value or path (REQ-CHAIN-007-AC12, AC15), because the command-run attestor records argv
        t2, repo2, log2, runner2, r2 = run_witnessed(text, stp)
        inner2 = read(os.path.join(log2, "inner.log"))
        wargv2 = (lines(log2, "witness.log", "ARGV") or [""])[0]
        after2 = wargv2.split(" -- ", 1)[1] if " -- " in wargv2 else wargv2
        if not re.search(r"^RELEASE_ROLE_ARN=" + re.escape(ROLE) + "$", inner2, re.M):
            badx("the wrapped script of release-sign does not see RELEASE_ROLE_ARN = the role")
        if re.search(r"^AWS_(ROLE_ARN|WEB_IDENTITY_TOKEN_FILE)=", inner2, re.M):
            badx("the wrapped script of release-sign sees an AWS_ role or token variable from the helper (bin/release-sign.sh maps RELEASE_* itself)")
        if read(os.path.join(log2, "seq")).split() != ["loop", "witness", "loop", "sign-record"]:
            badx("release-sign: the order is not a token for its own signing script, Witness, a fresh token, sign-record: %r" % read(os.path.join(log2, "seq")).split())
        if "RTFILES 1" not in inner2:
            badx("release-sign: the token file does not exist while its script runs")
        # A2 (#822 round 2) and F1 (round 3): Witness's own environment holds no AWS role or token path for ANY step; on release-sign it holds only RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE (sensitive keys) beside the
        # region and the key alias (not credentials); the token made for the wrapped script is removed before the fresh one for sign-record is fetched
        if (lines(log2, "witness.log", "ROLE") or [""])[0] != "UNSET" or (lines(log2, "witness.log", "TOKFILE") or [""])[0] != "UNSET":
            badx("release-sign: Witness itself sees AWS_ROLE_ARN or a token path: %r %r" % ((lines(log2, "witness.log", "ROLE") or [""])[0], (lines(log2, "witness.log", "TOKFILE") or [""])[0]))
        if (lines(log2, "witness.log", "NAMES") or [""])[0].split() != ["AWS_REGION", "RELEASE_KMS_KEY_REF", "RELEASE_ROLE_ARN", "RELEASE_TOKEN_FILE"]:
            badx("release-sign: Witness's environment holds other AWS_ or RELEASE_ names than AWS_REGION, RELEASE_KMS_KEY_REF, RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE: %r" % (lines(log2, "witness.log", "NAMES") or [""])[0])
        mt2 = re.search(r"^RELEASE_TOKEN_FILE=(\S+)$", inner2, re.M)
        if ROLE in wargv2 or "role/" in wargv2 or TOKEN in wargv2 or not mt2 or mt2.group(1) in wargv2 or "/step/token" in wargv2:
            badx("release-sign: Witness's argv holds the role value or the token path (the command-run attestor records argv): %r" % wargv2[-300:])
        if "AWS_" in wargv2.replace("--env-add-sensitive-key AWS_WEB_IDENTITY_TOKEN_FILE", "").replace("--env-add-sensitive-key AWS_ROLE_ARN", ""):
            badx("release-sign: Witness's argv holds an AWS_ name outside the two sensitive-key flags: %r" % wargv2[-300:])
        if after2.strip() != "bash bin/%s.sh" % stp:
            badx("release-sign: the wrapped command is not the plain `bash SCRIPT`: %r" % after2[-200:])
        if not (re.search(r"^TOKEXISTS yes$", inner2, re.M) and re.search(r"^TOKMODE 600$", inner2, re.M) and re.search(r"^TOKCONTENT " + re.escape(TOKEN) + "$", inner2, re.M)):
            badx("release-sign: its script does not see an existing mode 0600 token file holding the token while it runs: %r" % inner2[-300:])
        # the record the command-run attestor writes for this step (cmd = the argv after `--`), judged by the real record-env: a minimal collection and the committed real Witness record
        shutil.rmtree(t2, ignore_errors=True)
        for kind, rec in (("min", "min"), ("real", os.path.join(root, "test-evidence", "witness-real", "build-collection.real.txt"))):
            t7, repo7, log7, runner7, r7 = run_witnessed(text, stp, {"FAKE_WITNESS_REC": rec})
            pl = os.path.join(log7, "signrec.payload")
            if not os.path.exists(pl):
                badx("release-sign: no %s record was signed (exit %d)" % (kind, r7.returncode))
            else:
                envp = os.path.join(t7, "record.json")
                json.dump({"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(open(pl, "rb").read()).decode(), "signatures": []}, open(envp, "w"))
                rv = subprocess.run([sys.executable, "-I", "-B", os.path.join(root, "bin", "chain-verify.py"), "record-env", "--record", envp], capture_output=True, text=True)
                if rv.returncode != 0:
                    badx("release-sign: record-env refuses the %s record the step writes: %s" % (kind, (rv.stdout + rv.stderr).strip()[:160]))
            shutil.rmtree(t7, ignore_errors=True)
        t2, repo2, log2, runner2, r2 = run_witnessed(text, stp)
        pr2 = read(os.path.join(log2, "signrec.prior")).strip()
        tf2 = re.search(r"TOKFILE=(\S+)", (read(os.path.join(log2, "signrec.env")).splitlines() or [""])[0])
        mprior = re.fullmatch(r"PRIOR=(\S+) EXISTS=(\S+)", pr2)
        if not mprior or mprior.group(1) == "none" or mprior.group(2) != "False" or (tf2 and mprior.group(1) == tf2.group(1)):
            badx("release-sign: the token made for the wrapped script is not removed, as a separate file, before sign-record's fresh one: %r" % pr2)
    # a failing Witness: its exit status is kept and the token directory is gone
    t3, repo3, log3, runner3, r3 = run_witnessed(text, "release-verify", {"FAKE_WITNESS_RC": "7"})
    d3 = ""
    if os.path.exists(os.path.join(log3, "loop.log")):
        bad.append("a token is fetched although Witness failed")
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
    if os.listdir(runner3):
        bad.append("the token directory still exists after a failing Witness")
    # refusals: nothing is run, nothing is left
    for label, extra, drop in (("no role", {}, ("AWS_ROLE_ARN",)), ("no region", {}, ("AWS_REGION",)), ("no key reference", {}, ("RELEASE_KMS_KEY_REF",)), ("no RUNNER_TEMP", {}, ("RUNNER_TEMP",)),
                               ("an empty token", {"FAKE_TOKEN": ""}, ()), ("a null token", {"FAKE_TOKEN": "null"}, ()), ("a failed fetch", {"FAKE_FETCH_FAIL": "1"}, ())):
        t4, repo4, log4, runner4, r4 = run_witnessed(text, "release-verify", extra, drop)
        late = label in ("an empty token", "a null token", "a failed fetch")      # the token is fetched after Witness ran: the step ran, nothing is signed
        if r4.returncode == 0 or (os.path.exists(os.path.join(log4, "witness.log")) and not late) or "sign-record" in read(os.path.join(log4, "cv.log")):
            bad.append("%s: the helper went on (exit %d)" % (label, r4.returncode))
        if label != "no RUNNER_TEMP" and os.listdir(runner4):
            bad.append("%s: a token directory is left behind" % label)
        if label in ("no role", "no region", "no key reference") and os.path.exists(os.path.join(log4, "loop.log")):
            bad.append("%s: a token was asked for before the job was checked" % label)
    # P1 (#822 round 1): a collection with no payload is refused before the signing function is called (jq -er: a missing field is an error, not the text null)
    t7, repo7, log7, runner7, r7 = run_witnessed(text, "release-verify", {"FAKE_WITNESS_NOPAYLOAD": "1"})
    if r7.returncode == 0 or "sign-record" in read(os.path.join(log7, "cv.log")):
        bad.append("a collection with no payload is not refused before sign-record (exit %d)" % r7.returncode)
    if os.listdir(runner7):
        bad.append("a token directory is left after a collection with no payload")
    shutil.rmtree(t7, ignore_errors=True)
    t5, repo5, log5, runner5, r5 = run_witnessed(text, "release-nonsense")
    if r5.returncode != 2:
        bad.append("an unknown step does not exit 2")
    for d in (t, t2, t3, t4, t5):
        shutil.rmtree(d, ignore_errors=True)
    return bad


def problems_none(text, step):
    """A step that does not sign (S5 gap 2(a)): Witness and the wrapped script see no AWS_ or RELEASE_ variable, no token file exists while it runs, and the step exits 0."""
    bad = []
    t, repo, log, runner, r = run_witnessed(text, step)
    if r.returncode != 0:
        bad.append("%s exit %d: %s" % (step, r.returncode, r.stderr.strip()[:120]))
    if (lines(log, "witness.log", "NAMES") or ["x"])[0].strip() != "":
        bad.append("%s: Witness sees AWS_ or RELEASE_ variables (a step that does not sign must see none): %r" % (step, (lines(log, "witness.log", "NAMES") or [""])[0]))
    inner = read(os.path.join(log, "inner.log"))
    if "ran" not in inner:
        bad.append("%s: the wrapped script did not run" % step)
    if re.search(r"^(AWS_|RELEASE_)", inner, re.M):
        bad.append("%s: the wrapped script sees an AWS_ or RELEASE_ variable" % step)
    if "RTFILES 0" not in inner:
        bad.append("%s: a token file exists while the wrapped script runs" % step)
    shutil.rmtree(t, ignore_errors=True)
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


NONSIGN = ("release-verify", "release-publish", "release-assets", "release-postverify")
for stp in NONSIGN:
    b = problems_none(src, stp)
    check("witnessed.sh: %s is a step that does not sign: Witness and the wrapped script see no AWS_ or RELEASE_ name and no token file" % stp, not b, "; ".join(b))
_ms = src.replace('signers=" release-sign release-apks "\n', 'signers=" release-sign release-apks release-publish "\n')
check("witnessed.sh mutant caught: release-publish added to the signers", _ms != src and bool(problems_none(_ms, "release-publish")), "caught nothing" if _ms != src else "the mutation changed nothing")

mutant("audience sigstore", lambda s: s.replace("audience=sts.amazonaws.com", "audience=sigstore"))
mutant("no trap and no removal of the token directory", lambda s: re.sub(r"^trap .*\n", "", s, flags=re.M).replace('rm -rf "$td"\n', ""))
mutant("Witness keeps the AWS role and the token path", lambda s: s.replace("unset AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE\n", ":\n"))
mutant("the other steps keep the region and the key reference", lambda s: s.replace("*) unset AWS_REGION RELEASE_KMS_KEY_REF ;;", "*) : ;;"))
mutant("the token is fetched before Witness for every step", lambda s: s.replace('signers=" release-sign release-apks "\n', 'signers=" release-sign release-apks "\noidc_token\nexport AWS_WEB_IDENTITY_TOKEN_FILE="$td/token"\n'))
mutant("no fresh token before sign-record", lambda s: s.replace("  oidc_token\n  AWS_WEB_IDENTITY_TOKEN_FILE=", "  AWS_WEB_IDENTITY_TOKEN_FILE="))
mutant("Witness itself gets the role (exported, not only in the wrapped command)", lambda s: s.replace('signers=" release-sign release-apks "\n', 'signers=" release-sign release-apks "\nexport AWS_ROLE_ARN=$role\n', 1))
mutant("the token made for the wrapped script stays until the end", lambda s: s.replace('rm -rf "$td/step"\n', "", 1))
LIT = """bash -c 'AWS_ROLE_ARN=$RELEASE_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE=$RELEASE_TOKEN_FILE exec "$@"' release-creds"""
mutant("the release-creds literal (AWS names in the recorded command) put back in front of the wrapped script", lambda s: s.replace('-- bash "$@" || rc=$?', "-- " + LIT + ' bash "$@" || rc=$?'))
mutant("the values in the wrapped command (env AWS_ROLE_ARN=... in front of the script)", lambda s: s.replace('-- bash "$@" || rc=$?', '-- env "AWS_ROLE_ARN=$role" "AWS_WEB_IDENTITY_TOKEN_FILE=$td/step/token" bash "$@" || rc=$?'))
mutant("RELEASE_ROLE_ARN exported for every step", lambda s: s.replace('signers=" release-sign release-apks "\n', 'signers=" release-sign release-apks "\nexport RELEASE_ROLE_ARN=$role\n', 1))
mutant("a wrong token path for the script", lambda s: s.replace('RELEASE_TOKEN_FILE="$td/step/token"', 'RELEASE_TOKEN_FILE="$td/token"'))
mutant("RELEASE_ROLE_ARN not a sensitive key", lambda s: s.replace("  --env-add-sensitive-key RELEASE_ROLE_ARN \\\n", ""))
mutant("RELEASE_TOKEN_FILE not a sensitive key", lambda s: s.replace("  --env-add-sensitive-key RELEASE_TOKEN_FILE \\\n", ""))
mutant("a payload read with jq -r (null passes)", lambda s: s.replace("jq -er .payload", "jq -r .payload"))
mutant("a value written to GITHUB_ENV", lambda s: s.replace("rc=0\nwitness run", 'echo "AWS_ROLE_ARN=$AWS_ROLE_ARN" >> "${GITHUB_ENV:-/dev/null}"\nrc=0\nwitness run'))
mutant("release-apks dropped from the signers", lambda s: s.replace('signers=" release-sign release-apks "\n', 'signers=" release-sign "\n'))
mutant("the token directory inside the repository", lambda s: s.replace('"${RUNNER_TEMP:?}/witness-aws.XXXXXX"', '"./witness-aws.XXXXXX"'))
mutant("AWS_ROLE_ARN not a sensitive key", lambda s: s.replace("  --env-add-sensitive-key AWS_ROLE_ARN \\\n", ""))
mutant("a Fulcio flag", lambda s: s.replace("witness run --step", "witness run --signer-fulcio-url https://fulcio.sigstore.dev --step"))
mutant("Witness told to sign with the KMS key itself again", lambda s: s.replace('--signer-file-key-path "$td/key.pem"', '--signer-kms-ref "$RELEASE_KMS_KEY_REF"'))
mutant("the collection is not signed with the release key", lambda s: s.replace("sign-record", "verify"))
mutant("a failing signature ignored", lambda s: s.replace("--template .github/policy/release-policy.template.json || rc=$?", "--template .github/policy/release-policy.template.json || true"))
mutant("the token request variables exported to the wrapped script", lambda s: s.replace("req_tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN req_url=$ACTIONS_ID_TOKEN_REQUEST_URL\nunset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL\n", "req_tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN req_url=$ACTIONS_ID_TOKEN_REQUEST_URL\n"))
mutant("a failing Witness signed anyway", lambda s: s.replace('if [ "$rc" -eq 0 ]; then', "if true; then"))
mutant("the ten-minute timeout kept", lambda s: s.replace('-- bash "$@" || rc=$?', '-- timeout -k 20 540 bash "$@" || rc=$?'))
mutant("the exit status of Witness lost", lambda s: s.replace('exit "$rc"', "exit 0"))
mutant("the token file readable by others", lambda s: s.replace("umask 077\n", "umask 022\n"))
mutant("no role check before the token is asked for", lambda s: s.replace(': "${AWS_ROLE_ARN:?witnessed: AWS_ROLE_ARN is missing}"\n', "").replace("role=$AWS_ROLE_ARN ", "role=${AWS_ROLE_ARN-} "))
mutant("the token not checked for null", lambda s: s.replace('[ -n "$tok" ] && [ "$tok" != null ] || { echo "witnessed: no identity token" >&2; exit 1; }\n', ""))

# ---------------------------------------------------------------------------------------------------------------------------------------
# the two scripts that sign with the key map RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE onto the AWS variables themselves (P11 round 3, F1; REQ-CHAIN-007-AC12, AC15): one export line, preceded by a
# refusal that names only RELEASE_* when either is empty, before the script's first signing call

EXPORT = 'export AWS_ROLE_ARN="$RELEASE_ROLE_ARN" AWS_WEB_IDENTITY_TOKEN_FILE="$RELEASE_TOKEN_FILE"'


def problems_creds(text, name, behave):
    bad = []
    if text.count(EXPORT) != 1:
        return ["%s: the line `%s` is not there exactly once" % (name, EXPORT)]
    at = text.index(EXPORT)
    before = text[:at]
    for v in ("RELEASE_ROLE_ARN", "RELEASE_TOKEN_FILE"):
        mm = [m for m in re.finditer(r'^[^#\n]*\$\{%s:-\}[^\n]*$' % v, before, re.M)]
        if not mm:
            bad.append("%s: no refusal of an empty %s before the export" % (name, v))
        elif "AWS_" in mm[-1].group(0):
            bad.append("%s: the refusal of %s names an AWS variable" % (name, v))
    first = re.search(r"^(?!\s*#).*(?<![\w./-])(cosign\s+(sign|attest|login)|kms-sign\s|sign-record\s|aws\s)", text, re.M)
    if first and first.start() < at:
        bad.append("%s: a signing call comes before the export" % name)
    if behave:
        t = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(t, "bin"))
            sh(os.path.join(t, "bin", name), text)
            base = {"PATH": os.environ["PATH"], "HOME": t, "DOCKERHUB_USERNAME": "u", "DOCKERHUB_TOKEN": "t", "GH_TOKEN": "g", "RELEASE_KMS_KEY_REF": KEY, "GITHUB_REF_NAME": "not-a-tag"}
            for drop in ("RELEASE_ROLE_ARN", "RELEASE_TOKEN_FILE"):
                e = dict(base, RELEASE_ROLE_ARN=ROLE, RELEASE_TOKEN_FILE="/x/token")
                e[drop] = ""
                r = subprocess.run(["bash", "bin/" + name], cwd=t, env=e, capture_output=True, text=True, timeout=60)
                if r.returncode != 2 or drop not in r.stderr or "AWS_" in r.stderr:
                    bad.append("%s: an empty %s is not refused with exit 2 naming only RELEASE_*: rc %d %r" % (name, drop, r.returncode, r.stderr.strip()[:120]))
            r = subprocess.run(["bash", "bin/" + name], cwd=t, env=dict(base, RELEASE_ROLE_ARN=ROLE, RELEASE_TOKEN_FILE="/x/token"), capture_output=True, text=True, timeout=60)
            if "tag refused" not in r.stderr:
                bad.append("%s: with both set the script does not go on to its next check: rc %d %r" % (name, r.returncode, r.stderr.strip()[:120]))
        finally:
            shutil.rmtree(t, ignore_errors=True)
    return bad


apk_src = open(os.path.join(root, "bin", "release-sign-apks.sh")).read()
rs_src = open(os.path.join(root, "bin", "release-sign.sh")).read()
b = problems_creds(apk_src, "release-sign-apks.sh", False)
check("release-sign-apks.sh: maps RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE onto the AWS variables once, after a refusal naming only RELEASE_*, before it signs", not b, "; ".join(b))
b = problems_creds(rs_src, "release-sign.sh", True)
check("release-sign.sh: the same export, refused with exit 2 naming only RELEASE_* when either is empty, and it goes on to its next check when both are set", not b, "; ".join(b))
for nm, txt, beh in (("release-sign-apks.sh", apk_src, False), ("release-sign.sh", rs_src, True)):
    mt = txt.replace(EXPORT, "true")
    check("%s mutant caught: the export line removed" % nm, mt != txt and bool(problems_creds(mt, nm, beh)), "caught nothing")

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
    want_sr = "sign-record --payload %s --out %s --template .github/policy/release-policy.template.json" % (
        os.path.join(repo, "staged/witness-build/build-collection.payload"), os.path.join(repo, "signed/witness-build/build-collection.json"))
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
mutant3("the token file is set for sign-record only (the provenance call gets none)", lambda s: s.replace('AWS_WEB_IDENTITY_TOKEN_FILE="$td/token" python3 -I -B bin/chain-verify.py "$@" || rc=$?', 'if [ "$1" = sign-record ]; then export AWS_WEB_IDENTITY_TOKEN_FILE="$td/token"; fi; python3 -I -B bin/chain-verify.py "$@" || rc=$?'))
mutant3("the token file readable by others", lambda s: s.replace("umask 077\n", "umask 022\n"))


EXPECT = 57
print("pass=%d fail=%d" % (passn, failn))
if passn + failn != EXPECT:
    print("FAIL case count %d != expected %d (a case was skipped or added)" % (passn + failn, EXPECT))
    sys.exit(1)
sys.exit(0 if failn == 0 else 1)
PY
