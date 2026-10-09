#!/usr/bin/env python3
"""The plain verifier of the v0.3.0 release chain (rules 52, 53, 53b, 57 verify side, 58, 63, 67).

Subcommands: policy make, verify, sign --check, stage-start, actions, hostile-row, hostile-collect,
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
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

OPENSSL = os.environ.get("OPENSSL", "openssl")
PROV = "https://slsa.dev/provenance/v1"
COLL = "https://witness.testifysec.com/attestation-collection/v0.1"
POLT = "https://witness.testifysec.com/policy/v0.1"
DSSE_STMT = "application/vnd.in-toto+json"
STMT_TYPES = ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1")
PRODUCT = "https://witness.dev/attestations/product/v0.1/file:digests.json"
OID_ISSUER, OID_CONFIG = "1.3.6.1.4.1.57264.1.8", "1.3.6.1.4.1.57264.1.18"
STAGES = ("build", "sign", "rebuild", "check", "release")
WITNESS_STAGES = ("build", "rebuild", "check")


class Refuse(Exception):
    def __init__(self, stage, reason):
        super().__init__(reason)
        self.stage, self.reason = stage, reason


def refuse(stage, reason):
    raise Refuse(stage, reason)


def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode()


def ssl(*args, inp=None, check=True):
    r = subprocess.run((OPENSSL,) + args, input=inp, capture_output=True)
    if check and r.returncode:
        raise RuntimeError("openssl %s failed: %s" % (" ".join(args[:2]), r.stderr.decode(errors="replace")[:200]))
    return r


# ---- minimal DER reading (certificate fields the policy needs) ---------------------------------------------------
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


def pem_to_der(pem):
    body = re.sub(r"-----(BEGIN|END) CERTIFICATE-----|\s", "", pem)
    return b64d(body)


def der_to_pem(der):
    b = b64e(der)
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def parse_cert(der):
    _, s, e = _tlv(der, 0)
    tbs_t, ts, te = _tlv(der, s)
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
        _, xs, xe = _tlv(der, cs)
        for _t, es, ee in _children(der, cs, ce)[0:1]:
            for x in _children(der, es, ee):
                xk = _children(der, x[1], x[2])
                oid = _oid(der, xk[0][1], xk[0][2])
                val = xk[-1]
                exts[oid] = der[val[1]:val[2]]
    return {"not_before": nb, "not_after": na, "exts": exts, "der": der}


def ext_string(cert, oid):
    raw = cert["exts"].get(oid)
    if raw is None:
        return None
    if raw[:1] == b"\x0c":  # DER UTF8String (Fulcio v2 extensions)
        _, s, e = _tlv(raw, 0)
        return raw[s:e].decode()
    return raw.decode(errors="replace")


def san_uris(cert):
    raw = cert["exts"].get("2.5.29.17")
    if raw is None:
        return []
    _, s, e = _tlv(raw, 0)
    return [raw[cs:ce].decode() for tag, cs, ce in _children(raw, s, e) if tag == 0x86]


# ---- time ---------------------------------------------------------------------------------------------------------
def parse_now(s):
    if not s:
        return dt.datetime.now(dt.timezone.utc)
    for f in ("%Y%m%d%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return dt.datetime.strptime(s, f).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            pass
    raise SystemExit("error: --now must be ISO 8601 UTC (YYYYmmddHHMMSSZ or YYYY-mm-ddTHH:MM:SSZ)")


# ---- the policy ----------------------------------------------------------------------------------------------------
def load_json(path, what):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError) as ex:
        raise Refuse("policy", "%s %s is missing or not JSON: %s" % (what, path, ex))


def first_cert_der(pem_text):
    blocks = pem_blocks(pem_text)
    if not blocks:
        raise Refuse("policy", "trust: no certificate in the chain file")
    return pem_to_der(blocks[0]), blocks


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
        fulcio_text, tsa_text, rekor_text = open(fulcio_p).read(), open(tsa_p).read(), open(rekor_p).read()
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
    return b"DSSEv1 %d %s %d %s" % (len(t), t.encode(), len(body), body)


def read_record(stage, path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as ex:
        refuse(stage, "record missing or unreadable: %s" % os.path.basename(path))
    try:
        dsse = json.loads(raw)
        payload = b64d(dsse["payload"])
        ptype = dsse["payloadType"]
        assert isinstance(dsse.get("signatures"), list)
    except Exception as ex:
        refuse(stage, "record is not a DSSE envelope (%s)" % type(ex).__name__)
    return dsse, payload, ptype


def stamp_time(tok_der, tmp):
    p = os.path.join(tmp, "tok.der")
    with open(p, "wb") as f:
        f.write(tok_der)
    txt = ssl("ts", "-reply", "-in", p, "-token_in", "-text").stdout.decode(errors="replace")
    m = re.search(r"Time stamp:\s+(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(\d{4})", txt)
    if not m:
        raise RuntimeError("no time in the timestamp token")
    return dt.datetime.strptime("%s %s %s:%s:%s %s" % m.groups(), "%b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc), p


def verify_record(pol, stage, rec_path, rekor_path, now, tmp):
    """Verify one stage's DSSE record against the policy. Returns (statement-or-policy-dict, payload, envelope)."""
    if stage not in STAGES or stage not in pol.get("stages", {}):
        refuse(stage, "stage %r is not in the policy" % stage)
    if pol.get("dry_run") and stage != "sign":
        refuse(stage, "the policy is a dry-run policy (dry): it is accepted only for stage sign")
    dsse, payload, ptype = read_record(stage, rec_path)
    sigs = dsse["signatures"]
    if not sigs:
        refuse(stage, "record has no signature")
    sg = sigs[0]
    try:
        cert_pem = b64d(sg["certificate"]).decode()
        leaf = parse_cert(pem_to_der(cert_pem))
        inter = [b64d(x).decode() for x in sg.get("intermediates", [])]
        sig = b64d(sg["sig"])
    except Exception as ex:
        refuse(stage, "record certificate or signature is malformed (%s)" % type(ex).__name__)
    want_id = pol["stages"][stage]["identity"]
    uris = san_uris(leaf)
    if uris != [want_id]:
        refuse(stage, "certificate identity %s is not %s" % (", ".join(uris) or "(none)", want_id))
    cfg = ext_string(leaf, OID_CONFIG)
    if cfg is None:
        refuse(stage, "certificate has no build config URI extension (the calling workflow)")
    if cfg != pol["caller_identity"]:
        refuse(stage, "certificate build config URI %s is not %s" % (cfg, pol["caller_identity"]))
    iss = ext_string(leaf, OID_ISSUER)
    if iss is None:
        refuse(stage, "certificate has no OIDC issuer extension")
    if iss != pol["oidc_issuer"]:
        refuse(stage, "certificate issuer %s is not %s" % (iss, pol["oidc_issuer"]))
    # chain to a policy root (validity is judged below against the timestamp, not the clock)
    untrusted = os.path.join(tmp, "untrusted.pem")
    leaf_p = os.path.join(tmp, "leaf.pem")
    with open(leaf_p, "w") as f:
        f.write(cert_pem)
    chain_ders = []
    for root in pol["roots"].values():
        chain_ders += [b64d(x).decode() for x in root.get("intermediates", [])]
    with open(untrusted, "w") as f:
        f.write("".join(x.rstrip("\n") + "\n" for x in inter + chain_ders))
    chained = None
    for rid, root in pol["roots"].items():
        rp = os.path.join(tmp, "root-%s.pem" % rid[:12])
        with open(rp, "w") as f:
            f.write(b64d(root["certificate"]).decode())
        r = ssl("verify", "-no_check_time", "-CAfile", rp, "-untrusted", untrusted, leaf_p, check=False)
        if r.returncode == 0:
            chained = rid
            break
    if chained is None:
        refuse(stage, "certificate does not chain to a root of the policy (root)")
    # the signature over the DSSE PAE
    pub = os.path.join(tmp, "leaf.pub")
    with open(pub, "wb") as f:
        f.write(ssl("x509", "-in", leaf_p, "-pubkey", "-noout").stdout)
    for n, data in (("pae.bin", pae(ptype, payload)), ("sig.bin", sig)):
        with open(os.path.join(tmp, n), "wb") as f:
            f.write(data)
    if ssl("dgst", "-sha256", "-verify", pub, "-signature", os.path.join(tmp, "sig.bin"), os.path.join(tmp, "pae.bin"), check=False).returncode != 0:
        refuse(stage, "signature does not verify over the payload")
    # the timestamp: a stamp over sha256(sig) from a policy authority, inside the certificate's validity
    stamps = sg.get("timestamps") or []
    if not stamps:
        refuse(stage, "record has no timestamp, so a certificate that has expired cannot be accepted")
    stamped = None
    why = "no authority of the policy accepts the timestamp"
    for st in stamps:
        try:
            tok = b64d(st["data"])
            when, tokp = stamp_time(tok, tmp)
        except Exception:
            why = "timestamp token is malformed"
            continue
        for aid, auth in pol.get("timestampauthorities", {}).items():
            cp = os.path.join(tmp, "tsa-%s.pem" % aid[:12])
            ip = os.path.join(tmp, "tsa-int-%s.pem" % aid[:12])
            with open(cp, "w") as f:
                f.write(b64d(auth["certificate"]).decode())
            with open(ip, "w") as f:
                f.write("".join(b64d(x).decode().rstrip("\n") + "\n" for x in auth.get("intermediates", [])))
            r = ssl("ts", "-verify", "-digest", hashlib.sha256(sig).hexdigest(), "-in", tokp, "-token_in", "-CAfile", cp, "-untrusted", ip, "-no_check_time", check=False)
            if r.returncode == 0:
                stamped = when
                break
        if stamped:
            break
    if stamped is None:
        refuse(stage, "timestamp: " + why)
    if not (leaf["not_before"] <= stamped <= leaf["not_after"]):
        refuse(stage, "timestamp time %s is outside the certificate validity %s..%s" % (stamped.strftime("%Y-%m-%dT%H:%M:%SZ"), leaf["not_before"].strftime("%Y-%m-%dT%H:%M:%SZ"), leaf["not_after"].strftime("%Y-%m-%dT%H:%M:%SZ")))
    if stamped > now + dt.timedelta(minutes=10):
        refuse(stage, "timestamp time %s is later than the verification time" % stamped.strftime("%Y-%m-%dT%H:%M:%SZ"))
    # the record type, bound to the stage
    if ptype == POLT:
        if stage != "release":
            refuse(stage, "predicate: the signed policy type (policy payloadType) is the release stage's record, not %s's" % stage)
        try:
            stmt = json.loads(payload)
        except ValueError:
            refuse(stage, "predicate: the policy payload is not JSON")
        needs_rekor, dry_record = True, False
    elif ptype == DSSE_STMT:
        try:
            stmt = json.loads(payload)
            st_type, pt = stmt["_type"], stmt["predicateType"]
        except Exception:
            refuse(stage, "predicate: the payload is not an in-toto statement")
        if st_type not in STMT_TYPES:
            refuse(stage, "predicate: statement type %s is not allowed" % st_type)
        if pt == PROV:
            if stage != "sign":
                refuse(stage, "predicate type provenance is the sign stage's record type, not %s's" % stage)
            needs_rekor = True
        elif pt == COLL:
            if stage not in WITNESS_STAGES:
                refuse(stage, "predicate type %s (a witness collection) is not the %s stage's record type" % (pt, stage))
            needs_rekor = False
        else:
            refuse(stage, "predicate type %s is not allowed for stage %s" % (pt, stage))
        dry_record = bool((stmt.get("predicate") or {}).get("dryRun")) if pt == PROV else False
    else:
        refuse(stage, "predicate: payloadType %s is not allowed" % ptype)
    if dry_record and not pol.get("dry_run"):
        refuse(stage, "the provenance says dryRun true (dry): only a dry-run policy accepts it")
    if needs_rekor:
        check_rekor(pol, stage, rekor_path, payload, sig, sg["certificate"])
    return stmt, payload, dsse


def check_rekor(pol, stage, rekor_path, payload, sig, cert_b64):
    if not rekor_path:
        refuse(stage, "rekor entry required for this record type but no --rekor-stub was given")
    try:
        with open(rekor_path) as f:
            entries = json.load(f).get("entries", [])
    except (OSError, ValueError):
        refuse(stage, "rekor stub is missing or not JSON")
    ph = hashlib.sha256(payload).hexdigest()
    cands = []
    for e in entries:
        try:
            body = json.loads(b64d(e["canonicalizedBody"]))
            if body["spec"]["data"]["hash"]["value"] == ph:
                cands.append((e, body))
        except Exception:
            continue
    if not cands:
        refuse(stage, "no rekor entry binds this record's payload hash")
    pubp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
    try:
        pubp.write(pol["rekor_public_key"])
        pubp.close()
        logid = hashlib.sha256(ssl("pkey", "-pubin", "-in", pubp.name, "-outform", "DER").stdout).hexdigest()
        first = None
        for e, body in cands:
            try:
                canon = json.dumps({"body": e["canonicalizedBody"], "integratedTime": e["integratedTime"], "logID": e["logID"], "logIndex": e["logIndex"]}, sort_keys=True, separators=(",", ":")).encode()
                tmpd = tempfile.mkdtemp()
                try:
                    with open(tmpd + "/set.bin", "wb") as f:
                        f.write(canon)
                    with open(tmpd + "/set.sig", "wb") as f:
                        f.write(b64d(e["signedEntryTimestamp"]))
                    ok = ssl("dgst", "-sha256", "-verify", pubp.name, "-signature", tmpd + "/set.sig", tmpd + "/set.bin", check=False).returncode == 0
                finally:
                    shutil.rmtree(tmpd, ignore_errors=True)
            except Exception:
                ok = False
            if not ok:
                first = first or "rekor entry: the signed entry timestamp does not verify against the policy's rekor key"
                continue
            if e["logID"] != logid:
                first = first or "rekor entry names another log (log id is not the policy's rekor key)"
                continue
            spec = body["spec"]
            if spec.get("signature", {}).get("content") != b64e(sig):
                first = first or "rekor entry body is for another signature than this record's"
                continue
            if spec.get("signature", {}).get("publicKey", {}).get("content") != cert_b64:
                first = first or "rekor entry body is for another certificate than this record's"
                continue
            return
        refuse(stage, first or "rekor entry does not verify")
    finally:
        os.unlink(pubp.name)


def digest_compare(stage_prev, stmt, d_bytes, d_obj):
    """Compare the given digest list with the record's subjects (provenance) or its product subject (collection)."""
    subs = stmt.get("subject") or []
    if stmt.get("predicateType") == PROV:
        got = {s.get("name"): "sha256:" + str((s.get("digest") or {}).get("sha256")) for s in subs}
        if len(got) != len(subs) or got != d_obj:
            refuse(stage_prev, "digest list differs from the subjects of the record")
        return
    hits = [s for s in subs if s.get("name") == PRODUCT]
    if len(hits) != 1 or (hits[0].get("digest") or {}).get("sha256") != hashlib.sha256(d_bytes).hexdigest():
        refuse(stage_prev, "digest of the digest file differs from the digests file the record attests")


def parse_digest_file(path):
    """Return (bytes, object) or raise Refuse('sign', 'format ...')."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        refuse("sign", "digest file is missing or unreadable (format)")

    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(pairs)
    try:
        obj = json.loads(raw.decode(), object_pairs_hook=hook)
    except Exception as ex:
        refuse("sign", "digest file format: not JSON or has a duplicate key (%s)" % ex)
    if not isinstance(obj, dict) or not obj:
        refuse("sign", "digest file format: must be a non-empty JSON object")
    for k, v in obj.items():
        if not re.fullmatch(r"[a-z0-9-]+", k):
            refuse("sign", "digest file format: name %r is not [a-z0-9-]+" % k)
        if not isinstance(v, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", v):
            refuse("sign", "digest file format: value of %r is not sha256:<64 lower-case hex>" % k)
    return raw, obj


# ---- subcommands ---------------------------------------------------------------------------------------------------
def cmd_verify(a):
    pol = load_json(a.policy, "policy")
    now = parse_now(a.now)
    with tempfile.TemporaryDirectory() as tmp:
        verify_record(pol, a.stage, a.record, a.rekor_stub, now, tmp)
    print("ok")


def cmd_stage_start(a):
    pol = load_json(a.policy, "policy")
    now = parse_now(a.now)
    if pol.get("dry_run"):
        refuse(a.previous, "the policy is a dry-run policy (dry): no stage may start from it")
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
        d_obj = json.loads(d_bytes)
    except (OSError, ValueError):
        refuse(a.previous, "digest file is missing or not JSON")
    with tempfile.TemporaryDirectory() as tmp:
        stmt, payload, dsse = verify_record(pol, a.previous, a.record, a.rekor_stub, now, tmp)
    if isinstance(stmt, dict) and stmt.get("predicateType") in (PROV, COLL):
        digest_compare(a.previous, stmt, d_bytes, d_obj)
    print("ok")


def make_policy_from_template(a, tpl_path):
    ref = os.environ.get("GITHUB_REF", "")
    ev = os.environ.get("GITHUB_EVENT_NAME", "")
    if re.fullmatch(r"refs/tags/v[0-9]+\.[0-9]+\.[0-9]+", ref):
        mode = "tag"
    elif ev == "workflow_dispatch" and ref.startswith("refs/heads/") and len(ref) > len("refs/heads/"):
        mode = "ref"
    else:
        refuse("sign", "GITHUB_REF %r (event %r) is neither refs/tags/vX.Y.Z nor a workflow_dispatch on a branch (tag)" % (ref, ev))
    out = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    out.close()
    ns = argparse.Namespace(template=tpl_path, tag=None, ref=ref, trust=a.trust, fulcio_chain=a.fulcio_chain, tsa_chain=a.tsa_chain, rekor_key=a.rekor_key, out=out.name)
    try:
        policy_make(ns)
        with open(out.name) as f:
            return json.load(f)
    finally:
        os.unlink(out.name)


def cmd_sign(a):
    if not a.check:
        refuse("sign", "sign requires --check: the check comes before the signature")
    if a.signer != "cosign":
        refuse("sign", "the only signer is cosign")
    pol = load_json(a.policy, "policy")
    if "roots" not in pol:
        pol = make_policy_from_template(a, a.policy)
    now = parse_now(a.now)
    d_bytes_obj = None
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
    hits = [s for s in (stmt.get("subject") or []) if s.get("name") == PRODUCT]
    if len(hits) != 1 or (hits[0].get("digest") or {}).get("sha256") != hashlib.sha256(d_bytes).hexdigest():
        refuse("sign", "digest list differs from the digests Build attested (its digest does not match the record's product subject)")
    raw, obj = parse_digest_file(a.digests)
    dry = bool(pol.get("dry_run"))
    sign_id = pol["stages"]["sign"]["identity"]
    statement = {
        "_type": "https://in-toto.io/Statement/v1", "predicateType": PROV,
        "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1]}} for k, v in sorted(obj.items())],
        "predicate": {
            "buildDefinition": {"buildType": "https://github.com/%s/release-chain/v0.3.0" % pol["repository"],
                                "externalParameters": {"ref": pol.get("ref", "")}, "internalParameters": {}, "resolvedDependencies": []},
            "runDetails": {"builder": {"id": sign_id}, "metadata": {"invocationId": "sign"}},
        },
    }
    if dry:
        statement["predicate"]["dryRun"] = True
    tmpd = tempfile.mkdtemp()
    try:
        sp = os.path.join(tmpd, "statement.json")
        with open(sp, "w") as f:
            json.dump(statement, f, sort_keys=True)
        os.makedirs(a.out, exist_ok=True)
        bundle = os.path.join(os.path.abspath(a.out), "provenance.bundle.json")
        r = subprocess.run(["cosign", "attest-blob", "--yes", "--statement", sp, "--bundle", bundle], capture_output=True)
        if r.returncode != 0:
            shutil.rmtree(a.out, ignore_errors=True)
            refuse("sign", "cosign failed: %s" % r.stderr.decode(errors="replace")[:200])
        with open(bundle) as f:
            bun = json.load(f)
        vm = bun["verificationMaterial"]
        leaf_pem = der_to_pem(b64d(vm["certificate"]["rawBytes"]))
        sg = bun["dsseEnvelope"]["signatures"][0]
        chain = []
        for root in pol["roots"].values():
            chain += root.get("intermediates", []) + [root["certificate"]]
        env_out = {
            "payloadType": bun["dsseEnvelope"]["payloadType"], "payload": bun["dsseEnvelope"]["payload"],
            "signatures": [{"keyid": "", "sig": sg["sig"], "certificate": b64e(leaf_pem.encode()), "intermediates": chain,
                            "timestamps": [{"type": "tsp", "data": t["signedTimestamp"]} for t in vm.get("timestampVerificationData", {}).get("rfc3161Timestamps", [])]}],
        }
        with open(os.path.join(a.out, "provenance.json"), "w") as f:
            json.dump(env_out, f)
        with open(os.path.join(a.out, "provenance.rekor.json"), "w") as f:
            json.dump({"entries": vm.get("tlogEntries", [])}, f)
        if dry:
            open(os.path.join(a.out, "DRY-RUN"), "w").write("dry run: Release can never accept this record\n")
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    print("ok")


# ---- actions: every reference is a listed full digest ------------------------------------------------------------
def _walk_uses(tree, out, where=""):
    if isinstance(tree, dict):
        for k, v in tree.items():
            if k == "uses" and isinstance(v, str):
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


def check_actions(path, allowed, root, seen, errs):
    import yaml
    try:
        d = yaml.load(open(path).read(), Loader=yaml.BaseLoader)
    except Exception as ex:
        errs.append("%s is not YAML (%s)" % (path, type(ex).__name__))
        return
    refs = []
    _walk_uses(d, refs)
    acts = set(allowed.get("actions", []))
    imgs = set(allowed.get("images", []))
    local = set(allowed.get("local", []))
    for kind, ref, _w in refs:
        if ref is None or not isinstance(ref, str):
            continue
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
            p = ref[2:]
            if p not in local:
                errs.append("%s is a local reference that is not on the allowed list" % ref)
            elif root and ref.startswith("./.github/actions/") and p not in seen:
                seen.add(p)
                f = os.path.join(root, p, "action.yml")
                if os.path.exists(f):
                    check_actions(f, allowed, root, seen, errs)
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


# ---- the hostile dry run's rows ------------------------------------------------------------------------------------
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
        err = open(a.stderr, errors="replace").read()
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
            r = json.load(open(os.path.join(a.dir, fn)))
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
        lines = open(path, errors="replace").read().splitlines()
    except OSError as ex:
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


def cmd_hostile_material(a):
    if a.kind not in ("token", "key"):
        print("error: unknown kind %r (kind must be token or key)" % a.kind, file=sys.stderr)
        sys.exit(1)
    rest = _transcript(a.file)
    text = "\n".join(rest)
    if a.kind == "key":
        if "PRIVATE KEY" in text:
            print("ok")
            return
        refuse("runner", "nothing usable for Sign: no key material")
    m = re.search(r"[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*", text)
    if not m:
        refuse("runner", "nothing usable for Sign: no token")
    try:
        seg = m.group(1)
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        print("error: the token's payload is not decodable", file=sys.stderr)
        sys.exit(2)
    ref = claims.get("job_workflow_ref")
    if not ref:
        print("error: the token has no job_workflow_ref claim, so it cannot be graded", file=sys.stderr)
        sys.exit(2)
    if "/stage-sign.yml@" in ref:
        print("ok")
        return
    refuse("runner", "nothing usable for Sign: the token's job_workflow_ref is %s" % ref)


def cmd_hostile_verdict(a):
    try:
        d = json.load(open(a.results))
        rows = d["attempts"]
    except Exception as ex:
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
    s = sub.add_parser("sign")
    s.add_argument("--check", action="store_true")
    s.add_argument("--signer", default="")
    s.add_argument("--digests", required=True)
    s.add_argument("--build-record", required=True)
    s.add_argument("--policy", required=True)
    s.add_argument("--now")
    s.add_argument("--out", required=True)
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
        elif a.cmd == "stage-start":
            cmd_stage_start(a)
        elif a.cmd == "actions":
            cmd_actions(a)
        elif a.cmd == "hostile-row":
            cmd_hostile_row(a)
        elif a.cmd == "hostile-collect":
            cmd_hostile_collect(a)
        elif a.cmd == "hostile-material":
            cmd_hostile_material(a)
        elif a.cmd == "hostile-verdict":
            cmd_hostile_verdict(a)
    except Refuse as r:
        print("refused at %s: %s" % (r.stage, r.reason), file=sys.stderr)
        sys.exit(1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
