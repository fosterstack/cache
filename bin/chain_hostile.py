"""The dry run's judges (v0.3.0 rules 52a and 59; REQ-CHAIN-001-AC5), reached through `chain-verify.py hostile-*`: one row per
hostile attempt written from the verifier's OWN exit code, the merge of the rows, the grading of the token and key material the
hostile step found, and the verdict. Specified in the header of bin/chain-hostile-test.sh."""
import base64
import hashlib
import json
import os
import re
import sys
import tempfile

from chain_common import b64d, refuse, ssl, strict_json


ATTEMPTS = ["mint_sign_cert", "read_sign_token", "read_sign_key", "hand_sign_code", "forge_provenance", "call_sign_from_other_workflow"]
ALL_ROWS = ATTEMPTS + ["positive_control"]
ROW_STAGES = ("runner", "build", "sign", "rebuild", "check", "release")
# (allowed stages, cause words) per attempt; a refusal counts only when stage and cause fit
FITS = {
    "mint_sign_cert": (("sign", "release"), ("stage-sign.yml", "identity")),
    "read_sign_token": (("runner",), ("nothing usable",)),
    "read_sign_key": (("runner",), ("nothing usable",)),
    "hand_sign_code": (("sign",), ("digest", "format")),
    "forge_provenance": (("sign", "release"), ("identity", "stage-sign.yml", "signature", "root")),
    "call_sign_from_other_workflow": (("sign", "release"), ("release.yml", "build config")),
}
MISSING = ("no such file", "does not exist", "missing", "not found")
UNREAD = ("cannot read", "unreadable", "permission denied")


def cmd_hostile_row(a):
    if a.attempt not in ALL_ROWS:
        print("error: attempt %r is not one of %s" % (a.attempt, ", ".join(ALL_ROWS)), file=sys.stderr)
        sys.exit(1)
    try:
        with open(a.stderr, errors="replace") as f:
            err = f.read()
    except OSError:
        err = ""
    if "Traceback" in err:
        print("error: the verifier crashed (traceback); a crash is not a refusal", file=sys.stderr)
        sys.exit(1)
    if a.exit_code == 0:
        row = {"attempt": a.attempt, "outcome": "accepted", "stage": "sign", "reason": "accepted", "judged_by": "verifier", "exit_code": 0}
    else:
        first = err.splitlines()[0] if err.splitlines() else ""
        m = re.fullmatch(r"refused at (runner|build|sign|rebuild|check|release): (.+)", first)
        if a.exit_code != 1 or not m:
            print("error: the verifier's first line is not 'refused at <stage>: <reason>' (stage), so it is not a refusal (not a 'refused at' line)", file=sys.stderr)
            sys.exit(1)
        row = {"attempt": a.attempt, "outcome": "refused", "stage": m.group(1), "reason": m.group(2), "judged_by": "verifier", "exit_code": a.exit_code}
    with open(a.out, "w") as f:
        json.dump(row, f)


def cmd_hostile_collect(a):
    rows, errs = {}, []
    for fn in sorted(os.listdir(a.dir)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(a.dir, fn)) as f:
                r = json.load(f)
        except ValueError:
            errs.append("error: %s is not JSON" % fn)
            continue
        n = r.get("attempt")
        if n not in ALL_ROWS:
            errs.append("error: extra row %r in %s" % (n, fn))
        elif n in rows:
            errs.append("error: duplicate row for %s" % n)
        else:
            rows[n] = r
    for n in ALL_ROWS:
        if n not in rows:
            errs.append("error: missing row for %s" % n)
    if errs:
        print("\n".join(errs), file=sys.stderr)
        sys.exit(1)
    with open(a.out, "w") as f:
        json.dump({"attempts": [rows[n] for n in ALL_ROWS]}, f)


def _transcript(path):
    try:
        with open(path, errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        print("error: cannot read %s" % path, file=sys.stderr)
        sys.exit(2)
    if not lines or not lines[0].startswith("# transcript:") or len(lines[0][len("# transcript:"):].strip()) < 20:
        print("error: %s has no transcript line of at least 20 characters" % path, file=sys.stderr)
        sys.exit(2)
    rest = [x for x in lines[1:] if x.strip()]
    if not rest:
        print("error: %s has a transcript but no output of the attempt" % path, file=sys.stderr)
        sys.exit(2)
    return rest


def sign_key_hash(record_path):
    """sha256 of the public key (DER) in the certificate of Sign's own provenance: the key a stolen private key would have to match."""
    try:
        with open(record_path, "rb") as f:
            sg = strict_json(f.read())["signatures"][0]
        with tempfile.TemporaryDirectory() as d:
            cp = os.path.join(d, "cert.pem")
            with open(cp, "wb") as f:
                f.write(b64d(sg["certificate"]))
            pub = ssl("x509", "-in", cp, "-pubkey", "-noout").stdout
            kp = os.path.join(d, "pub.pem")
            with open(kp, "wb") as f:
                f.write(pub)
            return hashlib.sha256(ssl("pkey", "-pubin", "-in", kp, "-outform", "DER").stdout).hexdigest()
    except Exception:
        print("error: cannot read Sign's certificate from %s" % record_path, file=sys.stderr)
        sys.exit(2)


def grade_key(rest, sign_record):
    """The search must have looked at files (a count above zero); it is accepted only if a key it found is Sign's key."""
    counts = [int(m.group(1)) for line in rest for m in [re.fullmatch(r"searched: ([0-9]+) files", line.strip())] if m]
    if not counts or counts[0] < 1:
        print("error: the key search says it looked at no files, so an empty result proves nothing", file=sys.stderr)
        sys.exit(2)
    found = {m.group(1) for line in rest for m in [re.fullmatch(r"pubkey-sha256: ([0-9a-f]{64})", line.strip())] if m}
    if sign_key_hash(sign_record) in found:
        print("ok")
        return
    refuse("runner", "nothing usable for Sign: none of the %d keys found on this runner is Sign's key" % len(found))


def grade_token(rest):
    claims = [line[len("claims: "):] for line in rest if line.startswith("claims: ")]
    if not claims:
        print("error: the attempt wrote no claims of the token it fetched, so it cannot be graded", file=sys.stderr)
        sys.exit(2)
    m = re.fullmatch(r"[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*", claims[0].strip())
    if not m:
        print("error: the claims line is not header.payload.", file=sys.stderr)
        sys.exit(2)
    try:
        seg = m.group(1)
        parsed = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        print("error: the token's payload is not decodable", file=sys.stderr)
        sys.exit(2)
    ref = parsed.get("job_workflow_ref")
    if not ref:
        print("error: the token has no job_workflow_ref claim, so it cannot be graded", file=sys.stderr)
        sys.exit(2)
    # exactly Sign's workflow file of THIS repository: <repo>/.github/workflows/stage-sign.yml@<ref>, not a file that ends the same way
    repo = os.environ.get("GITHUB_REPOSITORY", "fosterstack/cache")
    if re.fullmatch(re.escape(repo) + r"/\.github/workflows/stage-sign\.yml@refs/[A-Za-z0-9._/-]+", ref):
        print("ok")
        return
    refuse("runner", "nothing usable for Sign: the token's job_workflow_ref is %s" % ref)


def cmd_hostile_material(a):
    if a.kind not in ("token", "key"):
        print("error: unknown kind %r (kind must be token or key)" % a.kind, file=sys.stderr)
        sys.exit(1)
    rest = _transcript(a.file)
    if a.kind == "token":
        grade_token(rest)
    elif not a.sign_record:
        print("error: --sign-record (Sign's provenance.json) is needed to grade a key", file=sys.stderr)
        sys.exit(2)
    else:
        grade_key(rest, a.sign_record)


def cmd_hostile_verdict(a):
    try:
        with open(a.results) as f:
            d = json.load(f)
        rows = d["attempts"]
    except Exception:
        print("error: %s is not the JSON results file (json)" % a.results, file=sys.stderr)
        sys.exit(1)
    errs, by = [], {}
    if not rows:
        errs.append("error: no attempt rows (attempt)")
    for r in rows:
        n = r.get("attempt")
        if n not in ALL_ROWS:
            errs.append("error: %r is not one of the six attempts or the positive control" % n)
        elif n in by:
            errs.append("error: duplicate row for %s" % n)
        else:
            by[n] = r
    for n in ALL_ROWS:
        if rows and n not in by:
            errs.append("error: missing row for %s" % n)
    for n, r in by.items():
        if r.get("judged_by") != "verifier":
            errs.append("error: %s: the outcome was not judged by the verifier (judged_by %r)" % (n, r.get("judged_by")))
            continue
        if n == "positive_control":
            if r.get("outcome") != "accepted" or r.get("exit_code") != 0:
                errs.append("error: positive_control must be accepted (exit 0) by the same policy: %s" % r.get("reason"))
            continue
        if r.get("outcome") != "refused":
            errs.append("error: %s was %s: the system accepted a hostile attempt" % (n, r.get("outcome")))
            continue
        if r.get("exit_code") in (0, None):
            errs.append("error: %s: outcome refused contradicts exit code %r" % (n, r.get("exit_code")))
            continue
        stage, reason = r.get("stage"), str(r.get("reason") or "")
        if stage not in ROW_STAGES:
            errs.append("error: %s: stage %r is not a stage" % (n, stage))
            continue
        if len(reason.strip()) < 2:
            errs.append("error: %s: the refusal has no reason" % n)
            continue
        low = reason.lower()
        if any(w in low for w in UNREAD):
            errs.append("error: %s: its material was unreadable: the refusal does not count (cause: unreadable)" % n)
            continue
        if any(w in low for w in MISSING):
            errs.append("error: %s: its material was missing: the refusal does not count (cause: missing)" % n)
            continue
        stages, words = FITS[n]
        if stage not in stages:
            errs.append("error: %s: refused at stage %s, expected %s (stage)" % (n, stage, "|".join(stages)))
        elif not any(w in low for w in words):
            errs.append("error: %s: the reason does not fit this attempt (cause): %s" % (n, reason))
    if errs:
        print("\n".join(errs), file=sys.stderr)
        sys.exit(1)
    print("ok")
