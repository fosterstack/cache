#!/usr/bin/env python3
"""The plain verifier of the v0.3.0 release chain (rules 52, 53, 53b, 57 verify side, 58, 63, 67).

Subcommands: policy make, verify, sign --check, check-build-record, stage-start, actions, hostile-row, hostile-collect,
hostile-material, hostile-verdict. The CLI contract is the header of the verify test; the hostile
subcommands are specified in the header of the hostile test.

Every refusal exits 1 and prints, as its FIRST stderr line, `refused at <stage>: <reason>`. Anything else
(bad usage, an unreadable input of the hostile helpers) is `error: ...` and exits 2 (or 1 where the test says so).
No network is used: certificates, timestamps and Rekor entries are verified from files only, with the openssl binary
(named by $OPENSSL, default `openssl`). Tokens in the environment are never read, printed or stored here.

Modelled on: in-toto-witness cmd/verify.go:116-163,211 (roots, intermediates, timestamp authorities taken from the
policy; a verifier's refusal is its exit code and message), options/sign.go:36 (policy payloadType),
options/verify.go:80-99 (the Fulcio extensions Witness itself can pin), docs/tutorials/artifact-policy.md:58-70
(collection predicate type, product subject name `.../product/v0.1/file:<name>`);
in-toto-attestation spec/v1/statement.md:11,19 (_type, subject, predicateType), spec/predicates/provenance.md:3.
"""
import argparse
import base64
import datetime as dt
import math
from fractions import Fraction
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

# PyYAML is imported by the `actions` subcommand only (load_yaml): the Sign job installs cosign and nothing else (Codex security r1 S4)
import importlib.util


def load_sibling(name):
    """Load the helper module <name> from this directory by its path, never through sys.path (Opus #249 r4): the Sign job runs the
    interpreter isolated (-I), so this directory is not on sys.path and no file here can stand in for a standard-library module. The
    module is registered under its name, so the other helper's `from chain_common import` gets this same copy."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, os.path.join(os.path.dirname(os.path.abspath(__file__)), name + os.extsep + "py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_common = load_sibling("chain_common")
Refuse, b64d, b64e, load_json, parse_now, refuse, ssl, strict_json = (_common.Refuse, _common.b64d, _common.b64e, _common.load_json,
                                                                      _common.parse_now, _common.refuse, _common.ssl, _common.strict_json)
chain_hostile = load_sibling("chain_hostile")

PROV = "https://slsa.dev/provenance/v1"
COLL = "https://witness.testifysec.com/attestation-collection/v0.1"
POLT = "https://witness.testifysec.com/policy/v0.1"
DSSE_STMT = "application/vnd.in-toto+json"
STMT_TYPES = ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1")
PRODUCT = "https://witness.dev/attestations/product/v0.1/file:digests.json"
OID_ISSUER, OID_CONFIG = "1.3.6.1.4.1.57264.1.8", "1.3.6.1.4.1.57264.1.18"
STAGES = ("build", "sign", "rebuild", "check", "release")
WITNESS_STAGES = ("build", "rebuild", "check")


# ---- minimal DER reading (certificate fields the policy needs) ---------------------------------------------------
# BOUNDARY: this is not a general DER parser. It reads the fields below from a certificate that openssl has verified to chain to a
# Fulcio root (the same DER, see single_cert_der); it trusts the structure of a Fulcio-signed TBS and refuses what it cannot read
# (a repeated extension, a second SAN) instead of guessing. Do not point it at bytes nobody has verified.
def _tlv(b, i):
    tag, ln = b[i], b[i + 1]
    if ln < 0x80:
        return tag, i + 2, i + 2 + ln
    k = ln & 0x7F
    n = int.from_bytes(b[i + 2:i + 2 + k], "big")
    return tag, i + 2 + k, i + 2 + k + n


def _children(b, s, e):
    out, i = [], s
    while i < e:
        tag, cs, ce = _tlv(b, i)
        out.append((tag, cs, ce))
        i = ce
    return out


def _oid(b, s, e):
    first = b[s]
    parts = [first // 40, first % 40]
    v = 0
    for x in b[s + 1:e]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def _time(b, tag, s, e):
    t = b[s:e].decode()
    if tag == 0x17:
        yy = int(t[:2])
        t = ("20" if yy < 50 else "19") + t
    return dt.datetime.strptime(t[:14], "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc)


def pem_blocks(text):
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)


ONE_CERT_PEM = re.compile(r"\s*-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----\s*")


def single_cert_der(text):
    """The DER of a field that holds EXACTLY ONE certificate PEM block with nothing but whitespace around it, else ValueError.
    The identity is read from this DER and openssl verifies a PEM re-made from this same DER (der_to_pem), so the bytes that are
    read and the bytes that are verified cannot differ: text before the block, a second block, or bytes after the outer
    SEQUENCE are refused instead of being skipped by one reader and used by the other."""
    m = ONE_CERT_PEM.fullmatch(text)
    if not m:
        raise ValueError("the certificate field is not exactly one PEM certificate block")
    der = base64.b64decode(re.sub(r"\s", "", m.group(1)), validate=True)
    if len(der) < 4 or der[0] != 0x30:
        raise ValueError("the certificate is not a DER SEQUENCE")
    _, _, end = _tlv(der, 0)
    if end != len(der):
        raise ValueError("bytes after the certificate's outer SEQUENCE")
    return der


def der_to_pem(der):
    b = b64e(der)
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def parse_cert(der):
    _, s, _e = _tlv(der, 0)
    _tbs_t, ts, te = _tlv(der, s)
    kids = _children(der, ts, te)
    i = 0
    if kids[0][0] == 0xA0:
        i = 1
    validity = kids[i + 3]
    vk = _children(der, validity[1], validity[2])
    nb, na = _time(der, vk[0][0], vk[0][1], vk[0][2]), _time(der, vk[1][0], vk[1][1], vk[1][2])
    exts = {}
    for tag, cs, ce in kids[i + 6:]:
        if tag != 0xA3:
            continue
        for _t, es, ee in _children(der, cs, ce)[0:1]:
            for x in _children(der, es, ee):
                xk = _children(der, x[1], x[2])
                oid = _oid(der, xk[0][1], xk[0][2])
                val = xk[-1]
                if oid in exts:
                    raise ValueError("repeated extension %s" % oid)   # a second SAN or Fulcio field would otherwise silently replace the first
                exts[oid] = der[val[1]:val[2]]
    return {"not_before": nb, "not_after": na, "exts": exts, "der": der}


def ext_string(cert, oid):
    """A Fulcio v2 extension's value (.1.8 issuer, .1.18 Build Config URI): exactly ONE DER UTF8String TLV (tag 0x0C, minimal definite
    length, no bytes after it), as Fulcio's OID specification defines it (REQ-CHAIN-001-AC4, Codex security r3); anything else is
    ValueError, never read as raw text."""
    raw = cert["exts"].get(oid)
    if raw is None:
        return None
    if len(raw) < 2 or raw[0] != 0x0C:
        raise ValueError("extension %s is not a DER UTF8String" % oid)
    n = raw[1]
    if n < 0x80:
        start, length = 2, n
    else:
        k = n & 0x7F
        length = int.from_bytes(raw[2:2 + k], "big")
        if k == 0 or k > 2 or length < 0x80 or raw[2] == 0:     # DER: the long form only for 128+ bytes, in the fewest octets
            raise ValueError("extension %s has a non-minimal length" % oid)
        start = 2 + k
    if start + length != len(raw):
        raise ValueError("extension %s length does not cover exactly its bytes" % oid)
    return raw[start:].decode("utf-8")


def san_uris(cert):
    raw = cert["exts"].get("2.5.29.17")
    if raw is None:
        return []
    _, s, e = _tlv(raw, 0)
    return [raw[cs:ce].decode() for tag, cs, ce in _children(raw, s, e) if tag == 0x86]


# ---- the policy ----------------------------------------------------------------------------------------------------
def first_cert_der(pem_text):
    blocks = pem_blocks(pem_text)
    if not blocks:
        raise Refuse("policy", "trust: no certificate in the chain file")
    return base64.b64decode(re.sub(r"-----(BEGIN|END) CERTIFICATE-----|\s", "", blocks[0]), validate=True), blocks


def policy_make(a):
    tpl = load_json(a.template, "template")
    d = os.path.dirname(os.path.abspath(a.template))
    trust_p = a.trust or os.path.join(d, "sigstore-trust.json")
    fulcio_p = a.fulcio_chain or os.path.join(d, "fulcio-chain.pem")
    tsa_p = a.tsa_chain or os.path.join(d, "tsa-chain.pem")
    rekor_p = a.rekor_key or os.path.join(d, "rekor.pub")
    if a.tag:
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", a.tag):
            refuse("policy", "tag %r is not vX.Y.Z" % a.tag)
        ref, tag, dry = "refs/tags/" + a.tag, a.tag, False
    else:
        ref = a.ref or ""
        m = re.fullmatch(r"refs/tags/(v[0-9]+\.[0-9]+\.[0-9]+)", ref)
        if m:
            tag, dry = m.group(1), False
        elif ref.startswith("refs/heads/") and len(ref) > len("refs/heads/"):
            tag, dry = "", True
        else:
            refuse("policy", "ref %r is neither refs/tags/vX.Y.Z nor a branch (tag)" % ref)
    trust = load_json(trust_p, "trust file")
    try:
        with open(fulcio_p) as f1, open(tsa_p) as f2, open(rekor_p) as f3:
            fulcio_text, tsa_text, rekor_text = f1.read(), f2.read(), f3.read()
    except OSError as ex:
        raise Refuse("policy", "trust: cannot read %s" % ex)
    froot, fblocks = first_cert_der(fulcio_text)
    troot, tblocks = first_cert_der(tsa_text)
    rdir = ssl("pkey", "-pubin", "-in", rekor_p, "-outform", "DER").stdout
    got = {"fulcio_root_sha256": hashlib.sha256(froot).hexdigest(), "tsa_root_sha256": hashlib.sha256(troot).hexdigest(),
           "rekor_sha256": hashlib.sha256(rdir).hexdigest()}
    for k, v in got.items():
        if trust.get(k) != v:
            refuse("policy", "trust: %s of the chain file does not match the committed trust file" % k)
    repo = tpl["repository"]

    def ident(wf):
        return "https://github.com/%s/%s@%s" % (repo, wf, ref)

    pol = {
        "tag": tag, "ref": ref, "repository": repo, "oidc_issuer": tpl["oidc_issuer"],
        "caller_identity": ident(tpl["caller_workflow"]),
        "roots": {got["fulcio_root_sha256"]: {"certificate": b64e((fblocks[0] + "\n").encode()), "intermediates": [b64e((x + "\n").encode()) for x in fblocks[1:]]}},
        "timestampauthorities": {got["tsa_root_sha256"]: {"certificate": b64e((tblocks[0] + "\n").encode()), "intermediates": [b64e((x + "\n").encode()) for x in tblocks[1:]]}},
        "rekor_public_key": rekor_text,
        "stages": {k: {"identity": ident(v["workflow"])} for k, v in tpl["stages"].items()},
    }
    if dry:
        pol["dry_run"] = True
    with open(a.out, "w") as f:
        json.dump(pol, f, sort_keys=True, indent=1)
        f.write("\n")
    return pol


# ---- DSSE records --------------------------------------------------------------------------------------------------
def pae(t, body):
    return b"DSSEv1 %d %s %d %s" % (len(t.encode()), t.encode(), len(body), body)


def envelope_shape(dsse):
    """Every envelope field has its JSON type (Codex security r3): payloadType and payload strings, signatures a list of objects whose
    sig and certificate are strings, intermediates a list of strings, timestamps a list of objects. Returns the first wrong field or None."""
    if not isinstance(dsse, dict):
        return "the envelope is not an object"
    for k in ("payloadType", "payload"):
        if not isinstance(dsse.get(k), str):
            return "%s is not a string" % k
    sigs = dsse.get("signatures")
    if not isinstance(sigs, list) or not all(isinstance(x, dict) for x in sigs):
        return "signatures is not a list of objects"
    for x in sigs:
        for k in ("sig", "certificate"):
            if not isinstance(x.get(k), str):
                return "signature field %s is not a string" % k
        if not isinstance(x.get("intermediates", []), list) or not all(isinstance(i, str) for i in x.get("intermediates", [])):
            return "intermediates is not a list of strings"
        if not isinstance(x.get("timestamps", []), list) or not all(isinstance(t, dict) for t in x.get("timestamps", [])):
            return "timestamps is not a list of objects"
    return None


def read_record(stage, path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        refuse(stage, "record missing or unreadable: %s" % os.path.basename(path))
    try:
        dsse = strict_json(raw)
        why = envelope_shape(dsse)
        payload = b64d(dsse["payload"]) if not why else None
    except Exception as ex:
        refuse(stage, "record is not a DSSE envelope (%s)" % (ex if isinstance(ex, ValueError) and "duplicate" in str(ex) else type(ex).__name__))
    if why:
        refuse(stage, "record is not a DSSE envelope (%s)" % why)
    ptype = dsse["payloadType"]
    if len(dsse["signatures"]) != 1:
        refuse(stage, "record must carry exactly one signature, it has %d" % len(dsse["signatures"]))
    return dsse, payload, ptype


# The two timestamp forms in the chain: Witness stores the bare token (go-witness timestamp/tsp.go: `return timestamp.RawToken`),
# a Sigstore bundle stores the whole DER TimeStampResponse (protobuf-specs sigstore_common.proto RFC3161SignedTimestamp,
# sigstore-go pkg/sign/timestamping.go). The type of the entry says which: "tsp" is a token, "rfc3161-response" a response.
STAMP_TOKEN, STAMP_RESPONSE = "tsp", "rfc3161-response"
# Which form each record type carries: a Witness collection stores the bare token, a Sigstore bundle (the provenance) the whole
# TimeStampResponse. The signed release policy may carry either (PR 4 decides how Release signs it).
STAMP_FORM = {COLL: STAMP_TOKEN, PROV: STAMP_RESPONSE}
FORM_NAME = {STAMP_TOKEN: "bare token (tsp)", STAMP_RESPONSE: "whole response (rfc3161-response)"}


def expected_stamp_kind(ptype, payload):
    """The stamp form the record's type carries, or None (any) when the type is not known here: check_record_type refuses it later."""
    if ptype == POLT:
        return None
    try:
        return STAMP_FORM.get(strict_json(payload).get("predicateType"))
    except (ValueError, AttributeError):
        return None


def stamp_token(stamp_der, kind, tmp):
    """The bare timestamp token (a file) of a stamp. A whole response is first checked for a clean status and then reduced to its
    token, so that the time is read from, and the TSA's signature is verified over, the SAME token bytes. The response's status
    section (a status string, a failure info) is outside the TSA's signature: reading the time from the response text let an edited
    status string `x\\nTime stamp: <date>` set the time that is compared with the certificate's validity."""
    resp = os.path.join(tmp, "stamp.der")
    with open(resp, "wb") as f:
        f.write(stamp_der)
    if kind == STAMP_TOKEN:
        return resp
    text = ssl("ts", "-reply", "-in", resp, "-text").stdout.decode(errors="replace")
    status = re.search(r"^Status info:\n(.*?)(?=^TST info:|\Z)", text, re.S | re.M)
    fields = dict(re.findall(r"^(Status|Status description|Failure info): (.*)$", status.group(1) if status else "", re.M))
    if fields.get("Status") != "Granted." or fields.get("Status description", "unspecified") != "unspecified" or fields.get("Failure info", "unspecified") != "unspecified":
        raise ValueError("the response carries a status string or failure info (status)")
    token = os.path.join(tmp, "stamp-token.der")
    ssl("ts", "-reply", "-in", resp, "-token_out", "-out", token)
    return token


def stamp_time(token_path):
    """genTime of a bare token, as exact epoch seconds (a Fraction): the one `Time stamp:` line of `openssl ts -reply -token_in -text`
    (no status section exists there). The fraction of a second is KEPT (REQ-CHAIN-002-AC1, Codex security r2 note): 12:00:00.5 is
    after a certificate that ends at 12:00:00."""
    text = ssl("ts", "-reply", "-in", token_path, "-token_in", "-text").stdout.decode(errors="replace")
    hits = re.findall(r"^Time stamp: (\w{3})\s+(\d+) (\d\d):(\d\d):(\d\d)(?:\.(\d+))? (\d{4}) GMT$", text, re.M)
    if len(hits) != 1:
        raise ValueError("not exactly one genTime in the timestamp token")
    mon, day, hh, mm, ss, frac, year = hits[0]
    whole = dt.datetime.strptime("%s %s %s:%s:%s %s" % (mon, day, hh, mm, ss, year), "%b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc)
    return Fraction(epoch(whole)) + (Fraction(int(frac), 10 ** len(frac)) if frac else 0)


def epoch(when):
    """Whole epoch seconds of a certificate or clock time (certificate times have no fraction)."""
    return int(when.timestamp())


def stamp_text(when):
    """A datetime, or exact epoch seconds with any fraction shown."""
    if isinstance(when, dt.datetime):
        return when.strftime("%Y-%m-%dT%H:%M:%SZ")
    whole = math.floor(when)
    text = dt.datetime.fromtimestamp(whole, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    if when != whole:
        text += ("%.9f" % float(when - whole))[1:].rstrip("0")
    return text + "Z"


def attimes(when):
    """The whole second at which openssl checks a chain for `when`. openssl treats a certificate as expired when notAfter <= the
    -attime and as not yet valid when notBefore > it, and certificate times are whole seconds, so the floor gives the exact answer
    for a time with a fraction; for a whole-second time equal to a notAfter it refuses (one second stricter: fail closed)."""
    return [math.floor(when)]


def check_identity(stage, pol, leaf):
    """The certificate must be the stage's workflow file at the ref, called by release.yml at the same ref, from GitHub's issuer."""
    want_id = pol["stages"][stage]["identity"]
    try:
        uris = san_uris(leaf)
        cfg = ext_string(leaf, OID_CONFIG)
        iss = ext_string(leaf, OID_ISSUER)
    except (UnicodeDecodeError, IndexError, ValueError):
        refuse(stage, "certificate identity fields are malformed")
    if uris != [want_id]:
        refuse(stage, "certificate identity %s is not %s" % (", ".join(uris) or "(none)", want_id))
    if cfg is None:
        refuse(stage, "certificate has no build config URI extension (the calling workflow)")
    if cfg != pol["caller_identity"]:
        refuse(stage, "certificate build config URI %s is not %s" % (cfg, pol["caller_identity"]))
    if iss is None:
        refuse(stage, "certificate has no OIDC issuer extension")
    if iss != pol["oidc_issuer"]:
        refuse(stage, "certificate issuer %s is not %s" % (iss, pol["oidc_issuer"]))


def check_chain(stage, pol, cert_pem, intermediates, tmp):
    """The certificate must chain to a root of the policy and to nothing else: the system trust store is switched off."""
    leaf_p = os.path.join(tmp, "leaf.pem")
    with open(leaf_p, "w") as f:
        f.write(cert_pem)
    untrusted = os.path.join(tmp, "untrusted.pem")
    policy_inter = [b64d(x).decode() for root in pol["roots"].values() for x in root.get("intermediates", [])]
    with open(untrusted, "w") as f:
        f.write("".join(x.rstrip("\n") + "\n" for x in intermediates + policy_inter))
    for rid, root in pol["roots"].items():
        rp = os.path.join(tmp, "root-%s.pem" % rid[:12])
        with open(rp, "w") as f:
            f.write(b64d(root["certificate"]).decode())
        # no default file, directory or store: only the policy's root is trusted, whatever SSL_CERT_FILE / SSL_CERT_DIR say
        # the path is found here; its validity is checked at the stamp time by chain_valid_at, once that time is known
        r = ssl("verify", "-no_check_time", "-no-CAfile", "-no-CApath", "-no-CAstore", "-trusted", rp, "-untrusted", untrusted, leaf_p, check=False)
        if r.returncode == 0:
            return leaf_p, rp, untrusted
    refuse(stage, "certificate does not chain to a root of the policy (root)")


def chain_valid_at(stage, chain, when):
    """Every certificate of the chain (leaf, intermediates, root) was valid at the stamp's authenticated time (REQ-CHAIN-002-AC1,
    Codex security r2): an intermediate that had expired, or was not yet valid, then is refused, not only the leaf."""
    leaf_p, root_p, untrusted = chain
    for t in attimes(when):
        r = ssl("verify", "-attime", str(t), "-no-CAfile", "-no-CApath", "-no-CAstore", "-trusted", root_p, "-untrusted", untrusted, leaf_p, check=False)
        if r.returncode != 0:
            detail = (r.stdout + r.stderr).decode(errors="replace").strip().splitlines()
            refuse(stage, "certificate chain is not valid at the timestamp time %s (validity): %s" % (stamp_text(when), detail[-1] if detail else "openssl verify failed"))


def check_signature(stage, leaf_p, ptype, payload, sig, tmp):
    pub = os.path.join(tmp, "leaf.pub")
    with open(pub, "wb") as f:
        f.write(ssl("x509", "-in", leaf_p, "-pubkey", "-noout").stdout)
    for n, data in (("pae.bin", pae(ptype, payload)), ("sig.bin", sig)):
        with open(os.path.join(tmp, n), "wb") as f:
            f.write(data)
    if ssl("dgst", "-sha256", "-verify", pub, "-signature", os.path.join(tmp, "sig.bin"), os.path.join(tmp, "pae.bin"), check=False).returncode != 0:
        refuse(stage, "signature does not verify over the payload")


def check_timestamp(stage, pol, signature_entry, sig, leaf, now, tmp, want_kind=None):
    """A stamp over sha256(signature) from a policy authority, inside the certificate's validity (the cert may have expired since)."""
    stamps = signature_entry.get("timestamps") or []
    if not stamps:
        refuse(stage, "record has no timestamp, so a certificate that has expired cannot be accepted")
    why = "no authority of the policy accepts the timestamp"
    stamped = None
    for st in stamps:
        try:
            kind = st["type"]
            if kind not in (STAMP_TOKEN, STAMP_RESPONSE):
                raise ValueError(kind)
            if want_kind and kind != want_kind:
                why = "timestamp type %s is not the form this record carries: %s" % (kind, FORM_NAME[want_kind])
                continue
            tokp = stamp_token(b64d(st["data"]), kind, tmp)
            when = stamp_time(tokp)
        except Exception as ex:
            why = "timestamp token is malformed (%s)" % (ex if isinstance(ex, ValueError) else type(ex).__name__)
            continue
        for aid, auth in pol.get("timestampauthorities", {}).items():
            cp = os.path.join(tmp, "tsa-%s.pem" % aid[:12])
            ip = os.path.join(tmp, "tsa-int-%s.pem" % aid[:12])
            with open(cp, "w") as f:
                f.write(b64d(auth["certificate"]).decode())
            with open(ip, "w") as f:
                f.write("".join(b64d(x).decode().rstrip("\n") + "\n" for x in auth.get("intermediates", [])))
            # the TSA's signing certificate and its chain must be valid AT genTime (Codex security r2), not merely ever
            if all(ssl("ts", "-verify", "-digest", hashlib.sha256(sig).hexdigest(), "-in", tokp, "-token_in", "-CAfile", cp, "-untrusted", ip,
                       "-attime", str(t), check=False).returncode == 0 for t in attimes(when)):
                stamped = when
                break
        if stamped is not None:
            break
    if stamped is None:
        refuse(stage, "timestamp: " + why)
    if not (epoch(leaf["not_before"]) <= stamped <= epoch(leaf["not_after"])):
        refuse(stage, "timestamp time %s is outside the certificate validity %s..%s" % (stamp_text(stamped), stamp_text(leaf["not_before"]), stamp_text(leaf["not_after"])))
    if stamped > epoch(now) + 600:
        refuse(stage, "timestamp time %s is later than the verification time" % stamp_text(stamped))
    return stamped


def check_record_type(stage, pol, ptype, payload):
    """Bind the record type to the stage. Returns (statement, needs_rekor)."""
    if ptype == POLT:
        if stage != "release":
            refuse(stage, "predicate: the signed policy type (policy payloadType) is the release stage's record, not %s's" % stage)
        try:
            return strict_json(payload), True
        except ValueError:
            refuse(stage, "predicate: the policy payload is not JSON")
    if ptype != DSSE_STMT:
        refuse(stage, "predicate: payloadType %s is not allowed" % ptype)
    try:
        stmt = strict_json(payload)
        st_type, pt = stmt["_type"], stmt["predicateType"]
    except Exception:
        refuse(stage, "predicate: the payload is not an in-toto statement")
    if st_type not in STMT_TYPES:
        refuse(stage, "predicate: statement type %s is not allowed" % st_type)
    if pt == PROV:
        if stage != "sign":
            refuse(stage, "predicate type provenance is the sign stage's record type, not %s's" % stage)
        predicate = stmt.get("predicate")
        if isinstance(predicate, dict) and predicate.get("dryRun") and not pol.get("dry_run"):
            refuse(stage, "the provenance says dryRun true (dry): only a dry-run policy accepts it")
        return stmt, True
    if pt == COLL:
        if stage not in WITNESS_STAGES:
            refuse(stage, "predicate type %s (a witness collection) is not the %s stage's record type" % (pt, stage))
        return stmt, False
    refuse(stage, "predicate type %s is not allowed for stage %s" % (pt, stage))


def verify_record(pol, stage, rec_path, rekor_path, now, tmp):
    """Verify one stage's DSSE record against the policy. Returns (statement-or-policy-dict, payload, envelope)."""
    if stage not in STAGES or stage not in pol.get("stages", {}):
        refuse(stage, "stage %r is not in the policy" % stage)
    if pol.get("dry_run") and stage != "sign":
        refuse(stage, "the policy is a dry-run policy (dry): it is accepted only for stage sign")
    dsse, payload, ptype = read_record(stage, rec_path)
    entry = dsse["signatures"][0]
    try:
        leaf_der = single_cert_der(b64d(entry["certificate"]).decode())
        leaf = parse_cert(leaf_der)
        cert_pem = der_to_pem(leaf_der)
        intermediates = [b64d(x).decode() for x in entry.get("intermediates", [])]
        sig = b64d(entry["sig"])
    except Exception as ex:
        refuse(stage, "record certificate or signature is malformed (%s)" % (ex if isinstance(ex, ValueError) else type(ex).__name__))
    check_identity(stage, pol, leaf)
    chain = check_chain(stage, pol, cert_pem, intermediates, tmp)
    check_signature(stage, chain[0], ptype, payload, sig, tmp)
    stamped = check_timestamp(stage, pol, entry, sig, leaf, now, tmp, expected_stamp_kind(ptype, payload))
    chain_valid_at(stage, chain, stamped)
    stmt, needs_rekor = check_record_type(stage, pol, ptype, payload)
    if needs_rekor:
        check_rekor(pol, stage, rekor_path, payload, sig, leaf_der, leaf)
    return stmt, payload, dsse


# ---- Rekor (v1 log, the DSSE entry kind that `cosign attest-blob` writes) -----------------------------------------------
# An entry is a protobuf-JSON TransparencyLogEntry as it sits in a Sigstore bundle's verificationMaterial.tlogEntries
# (protobuf-specs sigstore_rekor.proto: logIndex and integratedTime are strings, logId.keyId and canonicalizedBody are base64,
# inclusionPromise.signedEntryTimestamp is the log's signature). Its canonical body is a Rekor `dsse` 0.0.1 entry:
# {"apiVersion","kind":"dsse","spec":{"envelopeHash","payloadHash","signatures":[{"signature","verifier"}]}} where signature
# is the base64 DSSE signature and verifier the base64 PEM certificate. The signed entry timestamp is an ECDSA signature over
# the canonical JSON {body, integratedTime, logID, logIndex} (sigstore-go pkg/tlog/entry.go VerifySET).
CANONICAL_DECIMAL = re.compile(r"0|[1-9][0-9]*")


def canonical_int(e, field):
    """protobuf-JSON writes int64 as a decimal STRING; only its one canonical spelling is accepted (REQ-CHAIN-002-AC3, Codex security r2):
    int() would read 7, "+7", " 7", "07" and 7.9 alike, so an edited outer entry would still match the log's signed numbers."""
    v = e[field]
    if not isinstance(v, str) or not CANONICAL_DECIMAL.fullmatch(v):
        raise ValueError("%s %r is not a canonical decimal string" % (field, v))
    return int(v)


def rekor_entry_fields(e):
    return {
        "body": e["canonicalizedBody"],
        "integratedTime": canonical_int(e, "integratedTime"),
        "logID": b64d(e["logId"]["keyId"]).hex(),
        "logIndex": canonical_int(e, "logIndex"),
    }


def set_is_valid(e, key_pem):
    canon = json.dumps(rekor_entry_fields(e), sort_keys=True, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory() as d:
        for name, data in (("key.pem", key_pem.encode()), ("set.bin", canon), ("set.sig", b64d(e["inclusionPromise"]["signedEntryTimestamp"]))):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        r = ssl("dgst", "-sha256", "-verify", os.path.join(d, "key.pem"), "-signature", os.path.join(d, "set.sig"), os.path.join(d, "set.bin"), check=False)
    return r.returncode == 0


def rekor_log_id(key_pem):
    with tempfile.TemporaryDirectory() as d:
        kp = os.path.join(d, "key.pem")
        with open(kp, "w") as f:
            f.write(key_pem)
        return hashlib.sha256(ssl("pkey", "-pubin", "-in", kp, "-outform", "DER").stdout).hexdigest()


def rekor_body(e):
    """The decoded canonical body of a dsse entry, or None when the entry is of another kind."""
    kv = e.get("kindVersion") or {}
    if kv.get("kind") != "dsse" or kv.get("version") != "0.0.1":
        return None
    body = strict_json(b64d(e["canonicalizedBody"]))
    return body if body.get("kind") == "dsse" and body.get("apiVersion") == "0.0.1" else None


def check_rekor_entry(pol, e, body, sig, leaf_der, leaf):
    """Returns None when the entry is good, else the reason it is not."""
    try:
        rekor_entry_fields(e)
    except (ValueError, KeyError, TypeError) as ex:
        return "rekor entry is malformed (%s)" % ex
    spec = body["spec"]
    if not set_is_valid(e, pol["rekor_public_key"]):
        return "rekor entry: the signed entry timestamp does not verify against the policy's rekor key"
    if rekor_entry_fields(e)["logID"] != rekor_log_id(pol["rekor_public_key"]):
        return "rekor entry names another log (log id is not the policy's rekor key)"
    signatures = spec.get("signatures") or []
    if len(signatures) != 1 or signatures[0].get("signature") != b64e(sig):
        return "rekor entry body is for another signature than this record's"
    try:
        verifier_der = single_cert_der(b64d(signatures[0]["verifier"]).decode())
    except Exception:
        return "rekor entry body has no usable certificate (verifier)"
    if verifier_der != leaf_der:
        return "rekor entry body is for another certificate than this record's"
    when = dt.datetime.fromtimestamp(rekor_entry_fields(e)["integratedTime"], dt.timezone.utc)
    if not (leaf["not_before"] <= when <= leaf["not_after"]):
        return "rekor entry integrated time %s is outside the certificate validity" % stamp_text(when)
    return None


def read_rekor_entries(stage, rekor_path):
    """The `entries` list of a Rekor entries file. Anything but a list of objects is a refusal, never a traceback
    (REQ-CHAIN-002-AC3, Codex security r1 S2)."""
    try:
        with open(rekor_path, "rb") as f:
            entries = strict_json(f.read())["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        refuse(stage, "rekor entries file is missing or not JSON")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        refuse(stage, "rekor entries file: entries is not a list of entry objects")
    return entries


def check_rekor(pol, stage, rekor_path, payload, sig, leaf_der, leaf):
    if not rekor_path:
        refuse(stage, "rekor entry required for this record type but no Rekor entries file (--rekor-stub) was given")
    entries = read_rekor_entries(stage, rekor_path)
    payload_hash = hashlib.sha256(payload).hexdigest()
    candidates = []
    for e in entries:
        try:
            body = rekor_body(e)
            if body and body["spec"]["payloadHash"]["value"] == payload_hash and body["spec"]["payloadHash"]["algorithm"] == "sha256":
                candidates.append((e, body))
        except Exception:
            continue
    if not candidates:
        refuse(stage, "no rekor entry (kind dsse) binds this record's payload hash")
    first = None
    for e, body in candidates:
        try:
            why = check_rekor_entry(pol, e, body, sig, leaf_der, leaf)
        except Exception:
            why = "rekor entry is malformed"
        if why is None:
            return
        first = first or why
    refuse(stage, first)


def typed_subjects(stage, stmt):
    """The statement's subjects, each {name: string, digest: {algorithm: string}}; anything else is a refusal naming the subject,
    never a traceback (REQ-CHAIN-003-AC1, 001-AC2, Codex security r2)."""
    subs = stmt.get("subject")
    if not isinstance(subs, list):
        refuse(stage, "the record's subjects are malformed (subject is not a list)")
    for s in subs:
        ok = isinstance(s, dict) and isinstance(s.get("name"), str) and isinstance(s.get("digest"), dict) \
            and all(isinstance(k, str) and isinstance(v, str) for k, v in s["digest"].items())
        if not ok:
            refuse(stage, "the record's subjects are malformed (a subject is {name: string, digest: {algorithm: string}}, got %s)" % json.dumps(s)[:120])
    return subs


def product_digest(subs):
    """The sha256 of the one product subject file:digests.json, or None when there is not exactly one."""
    hits = [s for s in subs if s["name"] == PRODUCT]
    return hits[0]["digest"].get("sha256") if len(hits) == 1 else None


def digest_compare(stage_prev, stmt, d_bytes, d_obj):
    """Compare the given digest list with the record's subjects (provenance) or its product subject (collection)."""
    subs = typed_subjects(stage_prev, stmt)
    if stmt.get("predicateType") == PROV:
        got = {s["name"]: "sha256:" + str(s["digest"].get("sha256")) for s in subs}
        if len(got) != len(subs) or got != d_obj:
            refuse(stage_prev, "digest list differs from the subjects of the record")
        return
    if product_digest(subs) != hashlib.sha256(d_bytes).hexdigest():
        refuse(stage_prev, "digest of the digest file differs from the digests file the record attests")


def parse_digest_bytes(raw, stage="sign"):
    """The digest list from the bytes that were read ONCE, or raise Refuse(stage, 'format ...'): the hash Build attested and the
    subjects of the provenance are then made from the same bytes, never from two reads of a file that could change in between.
    Sign and stage-start use this one check (REQ-CHAIN-001-AC2, 003-AC1)."""
    try:
        obj = strict_json(raw)
    except ValueError as ex:
        refuse(stage, "digest file format: not UTF-8 JSON or has a duplicate key (%s)" % ex)
    if not isinstance(obj, dict) or not obj:
        refuse(stage, "digest file format: must be a non-empty JSON object")
    for k, v in obj.items():
        if not re.fullmatch(r"[a-z0-9-]+", k):
            refuse(stage, "digest file format: name %r is not [a-z0-9-]+" % k)
        if not isinstance(v, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", v):
            refuse(stage, "digest file format: value of %r is not sha256:<64 lower-case hex>" % k)
    return obj


# ---- subcommands ---------------------------------------------------------------------------------------------------
def cmd_verify(a):
    pol = load_json(a.policy, "policy")
    now = parse_now(a.now)
    with tempfile.TemporaryDirectory() as tmp:
        verify_record(pol, a.stage, a.record, a.rekor_stub, now, tmp)
    print("ok")


# the stage that may start from each earlier stage's record (rule 58: each stage verifies the one before it)
STARTS_FROM = {"rebuild": ("build",), "check": ("build",), "sign": ("build",), "release": ("build", "sign", "rebuild", "check")}


def cmd_stage_start(a):
    if a.previous not in STARTS_FROM.get(a.stage, ()):
        refuse(a.previous, "stage %s does not start from the %s stage's record (stage)" % (a.stage, a.previous))
    pol = load_json(a.policy, "policy")
    now = parse_now(a.now)
    if pol.get("dry_run"):
        refuse(a.previous, "the policy is a dry-run policy (dry): no stage may start from it")
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
        d_obj = strict_json(d_bytes)
    except (OSError, ValueError):
        refuse(a.previous, "digest file is missing or not JSON")
    with tempfile.TemporaryDirectory() as tmp:
        stmt, payload, dsse = verify_record(pol, a.previous, a.record, a.rekor_stub, now, tmp)
    if dsse["payloadType"] == POLT:
        refuse(a.previous, "predicate: a signed release policy is not a record a stage starts from")
    parse_digest_bytes(d_bytes, a.previous)   # the same format check Sign applies (Codex security r2), before any comparison
    digest_compare(a.previous, stmt, d_bytes, d_obj)
    print("ok")


def make_policy_from_template(a, tpl_path):
    ref = os.environ.get("GITHUB_REF", "")
    ev = os.environ.get("GITHUB_EVENT_NAME", "")
    is_tag = re.fullmatch(r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+", ref)
    is_branch = ref.startswith("refs/heads/") and len(ref) > len("refs/heads/")
    if is_tag and ev == "workflow_dispatch":
        refuse("sign", "a workflow_dispatch on the tag %s is not a production run: production tags come from a push (tag)" % ref)
    if not (is_tag and ev == "push") and not (is_branch and ev == "workflow_dispatch"):
        refuse("sign", "GITHUB_REF %r (event %r) is neither a pushed refs/tags/vX.Y.Z nor a workflow_dispatch on a branch (tag)" % (ref, ev))
    out = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    out.close()
    ns = argparse.Namespace(template=tpl_path, tag=None, ref=ref, trust=a.trust, fulcio_chain=a.fulcio_chain, tsa_chain=a.tsa_chain, rekor_key=a.rekor_key, out=out.name)
    try:
        policy_make(ns)
        with open(out.name) as f:
            return json.load(f)
    finally:
        os.unlink(out.name)


def check_build_record(a):
    """What Sign must establish before it signs anything: Build's record is genuine, the digest list is the one Build attested,
    and the list has the right format. Returns (policy, digest-object). Signs nothing and calls no tool."""
    # two clearly named inputs: --template makes the per-tag policy here (the production Sign job), --policy is a finished one
    # (the dry run's own policy.json); exactly one is given
    pol = make_policy_from_template(a, a.template) if a.template else load_json(a.policy, "policy")
    if "roots" not in pol:
        refuse("sign", "--policy must be a finished policy; a template goes to --template")
    now = parse_now(a.now)
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
    except OSError:
        refuse("sign", "digest file is missing or unreadable (format)")
    # Build's record first, as stage build, under the policy's build identity (a dry-run policy is allowed for this)
    pol_b = dict(pol)
    pol_b.pop("dry_run", None)
    with tempfile.TemporaryDirectory() as tmp:
        stmt, payload, dsse = verify_record(pol_b, "build", a.build_record, None, now, tmp)
    if product_digest(typed_subjects("sign", stmt)) != hashlib.sha256(d_bytes).hexdigest():
        refuse("sign", "digest list differs from the digests Build attested (its digest does not match the record's product subject)")
    return pol, parse_digest_bytes(d_bytes)


def cmd_check_build_record(a):
    check_build_record(a)
    print("ok")


def provenance_statement(pol, obj, dry):
    """The SLSA v1 provenance Sign signs: what was built (the digests), from which commit and run (GitHub's own variables)."""
    repo, ref = pol["repository"], pol.get("ref", "")
    run_url = "%s/%s/actions/runs/%s" % (os.environ.get("GITHUB_SERVER_URL", "https://github.com"), repo, os.environ.get("GITHUB_RUN_ID", "0"))
    commit = os.environ.get("GITHUB_SHA", "")
    statement = {
        "_type": "https://in-toto.io/Statement/v1", "predicateType": PROV,
        "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1]}} for k, v in sorted(obj.items())],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/%s/release-chain/v0.3.0" % repo,
                "externalParameters": {"ref": ref, "workflow": pol["caller_identity"]},
                "internalParameters": {},
                "resolvedDependencies": [{"uri": "git+https://github.com/%s@%s" % (repo, ref), "digest": {"gitCommit": commit}}],
            },
            "runDetails": {"builder": {"id": pol["stages"]["sign"]["identity"]}, "metadata": {"invocationId": run_url}},
        },
    }
    if dry:
        statement["predicate"]["dryRun"] = True
    return statement


def bundle_materials(vm):
    """The bundle's timestamps and Rekor entries. Both must be present and non-empty: a provenance with either missing cannot be
    accepted by Release, so Sign refuses it here and names each missing one (REQ-CHAIN-002-AC1, 002-AC3, Codex security r1 S1)."""
    stamps = (vm.get("timestampVerificationData") or {}).get("rfc3161Timestamps")
    tlog = vm.get("tlogEntries")
    missing = []
    if not isinstance(stamps, list) or not stamps:
        missing.append("no timestamp (verificationMaterial.timestampVerificationData.rfc3161Timestamps is missing or empty)")
    if not isinstance(tlog, list) or not tlog:
        missing.append("no Rekor entry (verificationMaterial.tlogEntries is missing or empty)")
    if missing:
        refuse("sign", "the bundle cosign wrote has " + " and ".join(missing))
    return stamps, tlog


def bundle_to_outputs(bun, out_dir, pol):
    """Turn the Sigstore bundle cosign wrote into the two files Release verifies: the DSSE envelope with its certificate chain and
    timestamps (provenance.json) and the bundle's own Rekor entries, untouched (provenance.rekor.json)."""
    try:
        vm = bun["verificationMaterial"]
        stamps, tlog = bundle_materials(vm)
        leaf_pem = der_to_pem(b64d(vm["certificate"]["rawBytes"]))
        dsse = bun["dsseEnvelope"]
        envelope = {
            "payloadType": dsse["payloadType"], "payload": dsse["payload"],
            "signatures": [{"keyid": "", "sig": dsse["signatures"][0]["sig"], "certificate": b64e(leaf_pem.encode()),
                            "intermediates": [x for root in pol["roots"].values() for x in root.get("intermediates", []) + [root["certificate"]]],
                            "timestamps": [{"type": STAMP_RESPONSE, "data": s["signedTimestamp"]} for s in stamps]}],
        }
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as ex:
        # a malformed bundle is a refusal, never a traceback (property e); the field named is the one that was missing or wrong
        refuse("sign", "the bundle cosign wrote is malformed: certificate or envelope field %s (%s)" % (ex, type(ex).__name__))
    with open(os.path.join(out_dir, "provenance.json"), "w") as f:
        json.dump(envelope, f)
    with open(os.path.join(out_dir, "provenance.rekor.json"), "w") as f:
        json.dump({"entries": tlog}, f)


# the files Sign writes into its output folder: on a refusal exactly these, and the folder Sign made, are removed
OWN_FILES = ("provenance.bundle.json", "provenance.json", "provenance.rekor.json", "DRY-RUN")


def require_fresh_out(out):
    """--out must not exist yet, as a file, a folder or a symlink (REQ-CHAIN-001-AC2, Opus r1-verify H1): Sign creates it and removes
    only what it created, so a refusal can never delete `.`, an existing folder, or a symlink's target. A usage error, before anything runs."""
    if os.path.lexists(out):
        print("error: --out %s already exists; sign writes into a folder it creates itself" % out, file=sys.stderr)
        sys.exit(2)


def make_out(out):
    try:
        os.mkdir(out)
    except OSError as ex:
        refuse("sign", "cannot create the output folder %s (%s)" % (out, type(ex).__name__))


def remove_own_out(out):
    """Remove the files Sign wrote and the folder it made; anything else found there (and the folder holding it) is left alone."""
    for name in OWN_FILES:
        try:
            os.unlink(os.path.join(out, name))
        except FileNotFoundError:
            pass
    try:
        os.rmdir(out)
    except OSError:
        pass


def cmd_sign(a):
    if not a.check:
        refuse("sign", "sign requires --check: the check comes before the signature")
    if a.signer != "cosign":
        refuse("sign", "the only signer is cosign")
    require_fresh_out(a.out)
    pol, obj = check_build_record(a)
    dry = bool(pol.get("dry_run"))
    signing_config = os.path.join(os.path.dirname(os.path.abspath(a.template or a.policy)), "cosign-signing-config.json")
    with tempfile.TemporaryDirectory() as tmpd:
        sp = os.path.join(tmpd, "statement.json")
        statement = provenance_statement(pol, obj, dry)
        with open(sp, "w") as f:
            json.dump(statement, f, sort_keys=True)
        make_out(a.out)
        bundle = os.path.join(os.path.abspath(a.out), "provenance.bundle.json")
        try:
            r = subprocess.run(["cosign", "attest-blob", "--yes", "--signing-config", signing_config, "--statement", sp, "--bundle", bundle], capture_output=True)
        except OSError as ex:   # no cosign on PATH, or not runnable: a refusal, and the fresh output folder goes
            remove_own_out(a.out)
            refuse("sign", "cosign not found on PATH" if isinstance(ex, FileNotFoundError) else "cosign could not be started (%s)" % type(ex).__name__)
        if r.returncode != 0:
            remove_own_out(a.out)
            refuse("sign", "cosign failed: %s" % r.stderr.decode(errors="replace")[:200])
        try:
            convert_and_verify(bundle, a.out, pol, statement, parse_now(a.now), tmpd)
        except Refuse as bad:
            remove_own_out(a.out)   # a failed sign leaves no provenance behind (001-AC2)
            refuse("sign", bad.reason)
        except Exception as ex:
            # anything else in the self-check (openssl failing, a file that cannot be written) is a refusal too, never a traceback
            remove_own_out(a.out)
            refuse("sign", "the check of the provenance Sign wrote could not run: %s" % str(ex)[:200])
        if dry:
            with open(os.path.join(a.out, "DRY-RUN"), "w") as f:
                f.write("dry run: Release can never accept this record\n")
    print("ok")


def same_json(a, b):
    """Equal JSON values of the SAME types (Opus r1-verify H2): Python's == says true == 1 == 1.0, which would let a signed
    `"dryRun": 1` pass for the `true` Sign built; here bool, int and float are three types and each container is compared item by item."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_json(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_json(x, y) for x, y in zip(a, b))
    return a == b


def convert_and_verify(bundle, out_dir, pol, statement, now, tmpd):
    """Write Release's two files from cosign's bundle, then verify them as stage sign exactly as Release will, and require that the
    payload cosign signed IS the statement Sign built, before Sign says ok (REQ-CHAIN-001-AC2, 002-AC1, 002-AC3; Codex security r1 S1,
    Opus r1-verify F1): Sign never reports success for provenance Release would refuse, nor for a statement it did not make."""
    try:
        with open(bundle, "rb") as f:
            bun = strict_json(f.read())
    except (OSError, ValueError) as ex:
        refuse("sign", "the bundle cosign wrote is missing or not JSON (%s)" % type(ex).__name__)
    bundle_to_outputs(bun, out_dir, pol)
    vdir = os.path.join(tmpd, "verify-own-output")
    os.makedirs(vdir)
    signed, _payload, _dsse = verify_record(pol, "sign", os.path.join(out_dir, "provenance.json"), os.path.join(out_dir, "provenance.rekor.json"), now, vdir)
    # compared as parsed JSON, not as bytes: what matters is what the statement says, and cosign may re-serialise the statement file
    # it was given (key order, spacing) without changing a single subject or field; the parse is strict (no duplicate key, no NaN)
    if not same_json(signed, statement):
        refuse("sign", "the statement cosign signed is not the statement Sign built (subjects or predicate differ)")


# ---- actions: every reference is a listed full digest ------------------------------------------------------------
def _walk_uses(tree, out, where=""):
    """Collect every reference: ("uses", ref) for a step, ("jobuses", ref) for a job-level `uses:` (a reusable workflow call)."""
    if isinstance(tree, dict):
        for k, v in tree.items():
            if k == "jobs" and isinstance(v, dict) and where == "":
                for job in v.values():
                    if isinstance(job, dict):
                        if isinstance(job.get("uses"), str):
                            out.append(("jobuses", job["uses"], where))
                        _walk_uses({kk: vv for kk, vv in job.items() if kk != "uses"}, out, where)
            elif k == "uses" and isinstance(v, str):
                out.append(("uses", v, where))
            elif k == "container":
                out.append(("image", v.get("image") if isinstance(v, dict) else v, where))
            elif k == "services" and isinstance(v, dict):
                for sv in v.values():
                    if isinstance(sv, dict):
                        out.append(("image", sv.get("image"), where))
            elif k == "image" and isinstance(v, str) and where == "runs":
                out.append(("runsimage", v, where))
            else:
                _walk_uses(v, out, "runs" if k == "runs" else where)
    elif isinstance(tree, list):
        for x in tree:
            _walk_uses(x, out, where)


def follow_local(ref, allowed, root, seen, errs, job_level):
    """A local reference must be listed by path; a listed local action is read and judged too. Only a JOB-level `uses:` names a
    reusable workflow FILE (judged as a workflow of its own, so not opened here); a step-level reference names an action directory
    wherever it sits and whatever it is called."""
    p = ref[2:]
    if p not in set(allowed.get("local", [])):
        errs.append("%s is a local reference that is not on the allowed list" % ref)
    elif (job_level and p.endswith((".yml", ".yaml"))) or p in seen:
        return
    elif not root:
        errs.append("%s is a listed local action but no --root was given to read it" % ref)
    else:
        seen.add(p)
        found = [os.path.join(root, p, n) for n in ("action.yml", "action.yaml") if os.path.exists(os.path.join(root, p, n))]
        if not found:
            errs.append("%s is a listed local action with no action.yml or action.yaml under --root" % ref)
        for f in found:
            check_actions(f, allowed, root, seen, errs)


class DuplicateKey(Exception):
    pass


def import_yaml():
    """PyYAML, which only this subcommand needs (Codex security r1 S4); missing, it is a usage error that says so."""
    try:
        import yaml
    except ImportError:
        print("error: the actions subcommand needs PyYAML (apt: python3-yaml; pip: pyyaml)", file=sys.stderr)
        sys.exit(2)
    return yaml


def load_yaml(path):
    """The file as plain strings (BaseLoader), refusing a mapping key that repeats another key of the same mapping once both are
    trimmed and case-folded (REQ-CHAIN-003-AC4, Codex security r1 S5): a YAML reader keeps only one of two `uses:` keys, so the
    reference judged here need not be the one GitHub runs. A key that is not a plain scalar is refused for the same reason."""
    yaml = import_yaml()

    class NoDuplicateKeys(yaml.BaseLoader):
        def construct_mapping(self, mnode, deep=False):
            first = {}
            for key, _value in mnode.value:
                if not isinstance(key, yaml.ScalarNode):
                    raise DuplicateKey("%s: a mapping key at line %d is not a plain scalar" % (path, key.start_mark.line + 1))
                norm = key.value.strip().casefold()
                if norm in first:
                    raise DuplicateKey("%s: duplicate key %r at line %d repeats %r at line %d (a YAML reader keeps only one of them)"
                                       % (path, key.value, key.start_mark.line + 1, first[norm].value, first[norm].start_mark.line + 1))
                first[norm] = key
            return super().construct_mapping(mnode, deep)

    with open(path) as f:
        return yaml.load(f.read(), Loader=NoDuplicateKeys)


def workflow_shape(path, d):
    """The shapes GitHub accepts, named where they are not (Codex security r3): a reference that is not a string, a services entry that is
    not a mapping, a container that is neither, steps that are not a list of mappings, jobs that are not a mapping. A shape the walk below
    would skip is refused here instead (REQ-CHAIN-003-AC4)."""
    errs = []
    if not isinstance(d, dict):
        return ["%s: the file is not a mapping" % path]
    def steps_of(where, steps):
        if steps is None:
            return
        if not isinstance(steps, list):
            errs.append("%s: %s steps is not a list" % (path, where)); return
        for i, st in enumerate(steps):
            if not isinstance(st, dict):
                errs.append("%s: %s step %d is not a mapping" % (path, where, i))
            elif "uses" in st and not isinstance(st["uses"], str):
                errs.append("%s: %s step %d uses is not a string" % (path, where, i))
    if "jobs" in d:
        if not isinstance(d["jobs"], dict):
            return ["%s: jobs is not a mapping" % path]
        for jn, j in d["jobs"].items():
            where = "job %s" % jn
            if not isinstance(j, dict):
                errs.append("%s: %s is not a mapping" % (path, where)); continue
            if "uses" in j and not isinstance(j["uses"], str):
                errs.append("%s: %s uses is not a string" % (path, where))
            c = j.get("container")
            if c is not None and not isinstance(c, str) and not (isinstance(c, dict) and isinstance(c.get("image"), str)):
                errs.append("%s: %s container is not an image string or a mapping with an image string" % (path, where))
            sv = j.get("services")
            if sv is not None and (not isinstance(sv, dict) or not all(isinstance(x, dict) and isinstance(x.get("image"), str) for x in sv.values())):
                errs.append("%s: %s services is not a mapping of service mappings, each with an image string" % (path, where))
            steps_of(where, j.get("steps"))
    runs = d.get("runs")
    if isinstance(runs, dict):
        steps_of("runs", runs.get("steps"))
    return errs


def check_actions(path, allowed, root, seen, errs):
    try:
        d = load_yaml(path)
    except DuplicateKey as ex:
        errs.append(str(ex))
        return
    except Exception as ex:
        errs.append("%s is not YAML (%s)" % (path, type(ex).__name__))
        return
    shape = workflow_shape(path, d)
    if shape:
        errs.extend(shape)
        return
    refs = []
    _walk_uses(d, refs)
    acts = set(allowed.get("actions", []))
    imgs = set(allowed.get("images", []))
    local = set(allowed.get("local", []))
    for kind, ref, _w in refs:
        if ref is None or not isinstance(ref, str):
            continue
        job_level = kind == "jobuses"
        kind = "uses" if job_level else kind
        if "${{" in ref:
            errs.append("%s is an expression, not a pinned reference" % ref)
        elif kind in ("image", "runsimage") or ref.startswith("docker://"):
            img = ref[len("docker://"):] if ref.startswith("docker://") else ref
            if kind == "runsimage" and not ref.startswith("docker://"):
                errs.append("%s: a build file or unpinned image in a container action is built at run time" % ref)
            elif not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", img):
                errs.append("%s is not pinned by a full image digest" % ref)
            elif img not in imgs:
                errs.append("%s is a digest that is not on the allowed list" % ref)
        elif ref.startswith("./"):
            follow_local(ref, allowed, root, seen, errs, job_level)
        else:
            if not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref):
                errs.append("%s is not pinned by a full lower-case commit digest" % ref)
            elif ref not in acts:
                errs.append("%s is a digest that is not on the allowed list" % ref)


def cmd_actions(a):
    allowed = load_json(a.allowed, "allowed list")
    errs = []
    check_actions(a.workflow, allowed, a.root, set(), errs)
    if errs:
        refuse("actions", "; ".join(errs))
    print("ok")


# ---- main ----------------------------------------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="chain-verify.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    pm = sub.add_parser("policy")
    ps = pm.add_subparsers(dest="sub", required=True)
    m = ps.add_parser("make")
    m.add_argument("--template", required=True)
    g = m.add_mutually_exclusive_group(required=True)
    g.add_argument("--tag")
    g.add_argument("--ref")
    for n in ("trust", "fulcio-chain", "tsa-chain", "rekor-key"):
        m.add_argument("--" + n)
    m.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--policy", required=True)
    v.add_argument("--stage", required=True)
    v.add_argument("--record", required=True)
    v.add_argument("--now")
    v.add_argument("--rekor-stub")
    for name in ("sign", "check-build-record"):
        s = sub.add_parser(name)
        if name == "sign":
            s.add_argument("--check", action="store_true")
            s.add_argument("--signer", default="")
            s.add_argument("--out", required=True)
        s.add_argument("--digests", required=True)
        s.add_argument("--build-record", required=True)
        which = s.add_mutually_exclusive_group(required=True)
        which.add_argument("--template")   # the committed release-policy template: the per-tag policy is made here from GITHUB_REF
        which.add_argument("--policy")     # a finished policy (the dry run's policy.json)
        s.add_argument("--now")
        for n in ("trust", "fulcio-chain", "tsa-chain", "rekor-key"):
            s.add_argument("--" + n)
    st = sub.add_parser("stage-start")
    st.add_argument("--stage", required=True)
    st.add_argument("--previous", required=True)
    st.add_argument("--record", required=True)
    st.add_argument("--digests", required=True)
    st.add_argument("--policy", required=True)
    st.add_argument("--now")
    st.add_argument("--rekor-stub")
    ac = sub.add_parser("actions")
    ac.add_argument("workflow")
    ac.add_argument("--allowed", required=True)
    ac.add_argument("--root")
    hr = sub.add_parser("hostile-row")
    hr.add_argument("--attempt", required=True)
    hr.add_argument("--exit-code", type=int, required=True)
    hr.add_argument("--stderr", required=True)
    hr.add_argument("--out", required=True)
    hc = sub.add_parser("hostile-collect")
    hc.add_argument("dir")
    hc.add_argument("--out", required=True)
    hm = sub.add_parser("hostile-material")
    hm.add_argument("--kind", required=True)
    hm.add_argument("--file", required=True)
    hm.add_argument("--sign-record")
    hv = sub.add_parser("hostile-verdict")
    hv.add_argument("results")
    return p


def main(argv):
    a = build_parser().parse_args(argv)
    try:
        if a.cmd == "policy":
            policy_make(a)
        elif a.cmd == "verify":
            cmd_verify(a)
        elif a.cmd == "sign":
            cmd_sign(a)
        elif a.cmd == "check-build-record":
            cmd_check_build_record(a)
        elif a.cmd == "stage-start":
            cmd_stage_start(a)
        elif a.cmd == "actions":
            cmd_actions(a)
        elif a.cmd == "hostile-row":
            chain_hostile.cmd_hostile_row(a)
        elif a.cmd == "hostile-collect":
            chain_hostile.cmd_hostile_collect(a)
        elif a.cmd == "hostile-material":
            chain_hostile.cmd_hostile_material(a)
        elif a.cmd == "hostile-verdict":
            chain_hostile.cmd_hostile_verdict(a)
    except Refuse as r:
        print("refused at %s: %s" % (r.stage, r.reason), file=sys.stderr)
        sys.exit(1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
