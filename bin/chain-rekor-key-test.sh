#!/usr/bin/env bash
# proves: REQ-CHAIN-002-AC3
# Ratify B (owner, Oct 29): a record signed by the KMS release key must carry a Rekor entry, and Release refuses a signature without one.
# This is the key form of the Rekor check that bin/chain-verify.py had in its certificate form. It names three things the verifier must offer,
# so the tests are red until they exist:
#   check_rekor_entry(pol, entry, body, sig, key_der) -> None when good, else the reason it is not
#   check_rekor(pol, stage, entries_path, payload, sig, key_der)   raises Refuse when no entry binds this record
#   rekor_with_retry(fetch, sleep)  one try, then up to six retries after waits of 1, 2, 4, 8, 16 and 32 seconds; then Refuse in one line naming Rekor
# `key_der` is the DER of the manifest's KMS public key; the entry's `verifier` must be that key. No certificate, no Fulcio, and no time
# inside the entry is trusted (an entry integrated long ago is accepted; only the log's signature over it counts).
# Nothing here opens a network connection: every entry is built in this file and signed with a throwaway key made for this run
# (the Oct 29 Rekor incident: no test writes to a public service).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 -I - "$root" "$work" <<'PY'
import base64, hashlib, importlib.util, json, os, subprocess, sys, traceback

root, work = sys.argv[1], sys.argv[2]
passed = failed = 0


def ok(msg):
    global passed
    passed += 1
    print("ok   " + msg)


def bad(msg):
    global failed
    failed += 1
    print("FAIL " + msg)


def sh(*args, inp=None):
    return subprocess.run(args, input=inp, capture_output=True, check=True).stdout


def keypair(name):
    priv, pub = os.path.join(work, name + ".key"), os.path.join(work, name + ".pub")
    sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", priv)
    sh("openssl", "ec", "-in", priv, "-pubout", "-out", pub)
    return priv, open(pub).read(), sh("openssl", "pkey", "-pubin", "-in", pub, "-outform", "DER")


b64 = lambda b: base64.b64encode(b).decode()
rekor_priv, rekor_pem, rekor_der = keypair("rekor")
other_rekor_priv, other_rekor_pem, _ = keypair("other-rekor")
_, kms_pem, kms_der = keypair("kms")
_, other_kms_pem, other_kms_der = keypair("other-kms")
payload = b'{"_type":"https://in-toto.io/Statement/v1","subject":[]}'
sig = b"signature-bytes-of-the-record"

# a log tree of five leaves (the entry is the third) with its checkpoint, signed by the log key: the inclusion proof Rekor sends with every entry
def _mh(l, r): return hashlib.sha256(b"\x01" + l + r).digest()
def _mroot(ls):
    if len(ls) == 1: return ls[0]
    k = 1
    while k * 2 < len(ls): k *= 2
    return _mh(_mroot(ls[:k]), _mroot(ls[k:]))
def _mpath(m, ls):
    if len(ls) == 1: return []
    k = 1
    while k * 2 < len(ls): k *= 2
    return _mpath(m, ls[:k]) + [_mroot(ls[k:])] if m < k else _mpath(m - k, ls[k:]) + [_mroot(ls[:k])]
def add_proof(e, sign, log_der, pos=2, n=5):
    leaf = hashlib.sha256(b"\x00" + base64.b64decode(e["canonicalizedBody"])).digest()
    ls = [hashlib.sha256(b"\x00" + bytes([i]) * 8).digest() for i in range(n)]
    ls[pos] = leaf
    root = _mroot(ls)
    note = "rekor.sigstore.dev - 1193050959916656506\n%d\n%s\n" % (n, base64.b64encode(root).decode())
    sg = hashlib.sha256(log_der).digest()[:4] + sign(note.encode())
    e["inclusionProof"] = {"logIndex": str(pos), "rootHash": base64.b64encode(root).decode(), "treeSize": str(n),
                           "hashes": [base64.b64encode(h).decode() for h in _mpath(pos, ls)],
                           "checkpoint": {"envelope": note + "\n\u2014 rekor.sigstore.dev " + base64.b64encode(sg).decode() + "\n"}}
    return e


def entry(rk=rekor_priv, rk_der=rekor_der, payload=payload, sig=sig, verifier_pem=kms_pem, index="7", itime="1761800000", proof=True):
    """A Rekor v1 `dsse` entry as it sits in a bundle's tlogEntries, signed (the signed entry timestamp) by the log key `rk`."""
    body = {"apiVersion": "0.0.1", "kind": "dsse", "spec": {
        "envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
        "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()},
        "signatures": [{"signature": b64(sig), "verifier": b64(verifier_pem.encode())}]}}
    cb = b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    log_id = hashlib.sha256(rk_der).hexdigest()
    canon = json.dumps({"body": cb, "integratedTime": int(itime), "logID": log_id, "logIndex": int(index)}, sort_keys=True, separators=(",", ":")).encode()
    set_sig = sh("openssl", "dgst", "-sha256", "-sign", rk, inp=canon)
    e = {"logIndex": index, "integratedTime": itime, "logId": {"keyId": b64(bytes.fromhex(log_id))}, "kindVersion": {"kind": "dsse", "version": "0.0.1"},
         "canonicalizedBody": cb, "inclusionPromise": {"signedEntryTimestamp": b64(set_sig)}}
    return (add_proof(e, lambda note: sh("openssl", "dgst", "-sha256", "-sign", rk, inp=note), rk_der) if proof else e), body


spec = importlib.util.spec_from_file_location("chain_verify", os.path.join(root, "bin", "chain-verify.py"))
cv = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(cv)
except BaseException as ex:         # a verifier that does not load is one failure, not a stack of them
    bad("bin/chain-verify.py does not load: %s" % ex)
    print("pass=%d fail=%d" % (passed, failed))
    sys.exit(1)
pol = {"rekor_public_key": rekor_pem}


def good(label, e_body, want_reason=None, **kw):
    e, body = e_body
    try:
        why = cv.check_rekor_entry(kw.get("pol", pol), e, body, kw.get("sig", sig), kw.get("key_der", kms_der))
    except Exception as ex:
        bad("%s -> %s: %s" % (label, type(ex).__name__, ex))
        return
    if want_reason is None:
        ok(label) if why is None else bad("%s -> refused: %s" % (label, why))
    else:
        ok("%s (refused: %s)" % (label, why)) if (why and want_reason in why) else bad("%s -> wanted a refusal naming %r, got %r" % (label, want_reason, why))


good("key form: an entry for this signature, this key and this log is accepted", entry())
good("key form: an entry integrated long ago is accepted (no time in a record is trusted)", entry(itime="1000000000"))
good("key form: a signed entry timestamp from another log key is refused", entry(rk=other_rekor_priv, rk_der=sh("openssl", "pkey", "-in", other_rekor_priv, "-pubout", "-outform", "DER")), "signed entry timestamp")
good("key form: an entry naming another log id is refused", entry(rk=rekor_priv, rk_der=other_kms_der), "another log")
good("key form: an entry for another signature than this record's is refused", entry(sig=b"some other signature"), "another signature")
good("key form: an entry whose verifier is another public key is refused", entry(verifier_pem=other_kms_pem), "another key")
good("key form: a verifier that is not a public key is refused", entry(verifier_pem="not a key"), "no usable public key")
good("key form: a logIndex spelled 07 is not canonical and is refused", entry(index="07"), "malformed")
good("key form: an entry with the right key but the policy holding another rekor key is refused", entry(), "signed entry timestamp", pol={"rekor_public_key": other_rekor_pem})


def entries_file(name, content):
    p = os.path.join(work, name)
    with open(p, "w") as f:
        f.write(content if isinstance(content, str) else json.dumps(content))
    return p


def refused(label, path, want, payload_=payload, sig_=sig, kdr=kms_der):
    try:
        cv.check_rekor(pol, "sign", path, payload_, sig_, kdr)
    except cv.Refuse as ex:
        ok("%s (refused: %s)" % (label, ex)) if want in str(ex) else bad("%s -> wrong reason: %s" % (label, ex))
    except Exception as ex:
        bad("%s -> %s: %s" % (label, type(ex).__name__, ex))
    else:
        bad("%s -> accepted" % label)


e_good, _ = entry()
try:
    cv.check_rekor(pol, "sign", entries_file("good.json", {"entries": [e_good]}), payload, sig, kms_der)
    ok("the Rekor check accepts a file holding the one good entry")
except Exception as ex:
    bad("the Rekor check accepts a file holding the one good entry -> %s: %s" % (type(ex).__name__, ex))
refused("a record with no Rekor entries file is refused (Release refuses a signature without its entry)", "", "rekor")
refused("a missing entries file is refused", os.path.join(work, "absent.json"), "entries file")
refused("an entries file that is not JSON is refused", entries_file("junk.json", "not json"), "entries file")
refused("an entries value that is not a list is refused", entries_file("notlist.json", {"entries": {"a": 1}}), "not a list")
refused("an empty list of entries is refused: no entry binds this record", entries_file("empty.json", {"entries": []}), "no rekor entry")
refused("an entry for another payload is refused", entries_file("otherp.json", {"entries": [e_good]}), "no rekor entry", payload_=b"another payload")

# the wait and retry when Rekor is down: one try, then six retries after 1, 2, 4, 8, 16, 32 seconds (about a minute), then one refusing line
slept = []
calls = {"n": 0}


def down():
    calls["n"] += 1
    raise OSError("connection refused")


try:
    cv.rekor_with_retry(down, slept.append)
except cv.Refuse as ex:
    line = str(ex)
    ok("Rekor down: refused after the last retry in one line naming Rekor (%s)" % line) if ("\n" not in line and "ekor" in line) else bad("Rekor down: the refusal is not one line naming Rekor: %r" % line)
except Exception as ex:
    bad("Rekor down -> %s: %s" % (type(ex).__name__, ex))
else:
    bad("Rekor down -> accepted")
ok("Rekor down: seven tries in all") if calls["n"] == 7 else bad("Rekor down: %d tries, wanted 7 (one, then six retries)" % calls["n"])
ok("Rekor down: waits 1, 2, 4, 8, 16, 32 seconds") if slept == [1, 2, 4, 8, 16, 32] else bad("Rekor down: waits %r" % slept)

slept2, calls2 = [], {"n": 0}


def flaky():
    calls2["n"] += 1
    if calls2["n"] < 3:
        raise OSError("connection refused")
    return {"entries": [e_good]}


try:
    got = cv.rekor_with_retry(flaky, slept2.append)
    ok("Rekor back on the third try: the entries are returned after waits 1 and 2") if (slept2 == [1, 2] and got == {"entries": [e_good]}) else bad("Rekor back on the third try: waits %r, got %r" % (slept2, got))
except Exception as ex:
    bad("Rekor back on the third try -> %s: %s" % (type(ex).__name__, ex))

# the wiring: verify_record asks for the Rekor entry of a provenance and of the release policy, and of no Witness record
# (the signature and the record-type checks are replaced here by stubs that accept; only the Rekor decision is under test)
tmpd = os.path.join(work, "vr"); os.makedirs(tmpd)
real = {n: getattr(cv, n) for n in ("local_records", "read_record", "check_signature", "check_record_type")}
PROV, POLT, COLL = cv.PROV, cv.POLT, cv.COLL
dsse = {"payloadType": "application/vnd.in-toto+json", "payload": b64(payload), "signatures": [{"keyid": "", "sig": b64(sig)}]}
vpol = {"rekor_public_key": rekor_pem, "release_key": {"public_key": kms_pem}, "stages": {"sign": {}, "build": {}, "release": {}}}


def stub(ptype, predicate_type):
    cv.local_records = lambda stage, p: None
    cv.read_record = lambda stage, p: (dsse, payload, ptype)
    cv.check_signature = lambda *a: None
    cv.check_record_type = lambda stage, pol, pt, pl: {"predicateType": predicate_type}


def vr(label, stage, ptype, predicate_type, rekor_path, want):
    stub(ptype, predicate_type)
    try:
        cv.verify_record(vpol, stage, "rec.json", tmpd, rekor_path=rekor_path)
        res = None
    except cv.Refuse as ex:
        res = str(ex)
    except Exception as ex:
        res = "%s: %s" % (type(ex).__name__, ex)
    if want is None:
        ok(label) if res is None else bad("%s -> refused: %s" % (label, res))
    else:
        ok("%s (refused: %s)" % (label, res)) if (res and want in res) else bad("%s -> wanted a refusal naming %r, got %r" % (label, want, res))


stat = entries_file("vr-good.json", {"entries": [e_good]})
# every record type verify_record accepts (the provenance, the release policy and a Witness collection) needs its entry: the same cases run over all three
other_entries = entries_file("vr-other.json", {"entries": [entry(payload=b"another payload")[0]]})
for kind, stage_, ptype_, pred_ in (("provenance", "sign", cv.DSSE_STMT, PROV), ("release policy", "release", POLT, "policy"), ("Witness collection", "build", cv.DSSE_STMT, COLL)):
    vr("verify_record: a %s with its entry is accepted" % kind, stage_, ptype_, pred_, stat, None)
    vr("verify_record: a %s with no entries file is refused" % kind, stage_, ptype_, pred_, None, "rekor")
    vr("verify_record: a %s with a missing entries file is refused" % kind, stage_, ptype_, pred_, os.path.join(work, "absent-entries.json"), "entries file")
    vr("verify_record: a %s whose entries file holds no entry at all is refused" % kind, stage_, ptype_, pred_, entries_file("vr-empty-%s.json" % stage_, {"entries": []}), "no rekor entry")
    vr("verify_record: a %s whose only entry is for another payload is refused" % kind, stage_, ptype_, pred_, other_entries, "no rekor entry")
for n, f in real.items():
    setattr(cv, n, f)

# Sign's output: the bundle cosign wrote carries the Rekor entries, and they go to provenance.rekor.json
bun = {"verificationMaterial": {"tlogEntries": [e_good]}, "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": b64(payload), "signatures": [{"keyid": "", "sig": b64(sig)}]}}
od = os.path.join(work, "out1"); os.makedirs(od)
try:
    cv.bundle_to_outputs(bun, od)
    wrote = json.load(open(os.path.join(od, "provenance.rekor.json")))
    ok("Sign writes the bundle's Rekor entries to provenance.rekor.json, untouched") if wrote == {"entries": [e_good]} else bad("provenance.rekor.json holds %r" % wrote)
except Exception as ex:
    bad("Sign writes the bundle's Rekor entries -> %s: %s" % (type(ex).__name__, ex))
for label, vm in (("no tlogEntries", {}), ("an empty tlogEntries", {"tlogEntries": []})):
    od2 = os.path.join(work, "out2-" + label.replace(" ", "")); os.makedirs(od2)
    try:
        cv.bundle_to_outputs({"verificationMaterial": vm, "dsseEnvelope": bun["dsseEnvelope"]}, od2)
        bad("Sign refuses a bundle with %s -> accepted" % label)
    except cv.Refuse as ex:
        ok("Sign refuses a bundle with %s (%s)" % (label, ex)) if "ekor" in str(ex) else bad("Sign refuses a bundle with %s -> reason does not name Rekor: %s" % (label, ex))
    except Exception as ex:
        bad("Sign refuses a bundle with %s -> %s: %s" % (label, type(ex).__name__, ex))
ok("Sign removes provenance.rekor.json with its other files on a refusal (OWN_FILES)") if "provenance.rekor.json" in cv.OWN_FILES else bad("OWN_FILES lacks provenance.rekor.json: %r" % (cv.OWN_FILES,))
ok("rc-proof lists the rekor record again") if ("rekor", "provenance/provenance.rekor.json") in tuple(cv.RC_RECORDS) else bad("RC_RECORDS has no rekor row: %r" % (cv.RC_RECORDS,))

# the policy takes the Rekor key from the committed files, only when sigstore-trust.json pins it by sha256 (policy make reads both)
pinned = os.path.join(work, "pin"); os.makedirs(pinned)
open(os.path.join(pinned, "rekor.pub"), "w").write(rekor_pem)
trust_good = {"_note": "x", "rekor_sha256": hashlib.sha256(rekor_der).hexdigest()}


def pin(label, trust, rekor_file, want):
    tp = entries_file("pin/trust-%s.json" % label.split()[0], trust)
    try:
        got = cv.rekor_pin(tp, rekor_file)
        res = None if got == rekor_pem else "returned %r" % got[:40]
    except cv.Refuse as ex:
        res = str(ex)
    except Exception as ex:
        res = "%s: %s" % (type(ex).__name__, ex)
    if want is None:
        ok("rekor_pin: " + label) if res is None else bad("rekor_pin: %s -> %s" % (label, res))
    else:
        ok("rekor_pin: %s (refused: %s)" % (label, res)) if (res and want in res) else bad("rekor_pin: %s -> wanted a refusal naming %r, got %r" % (label, want, res))


pin("the key the trust file pins is returned", trust_good, os.path.join(pinned, "rekor.pub"), None)
pin("another key than the pinned one is refused", dict(trust_good, rekor_sha256=hashlib.sha256(other_kms_der).hexdigest()), os.path.join(pinned, "rekor.pub"), "rekor_sha256")
pin("a trust file with no rekor_sha256 is refused", {"_note": "x"}, os.path.join(pinned, "rekor.pub"), "rekor_sha256")
pin("a missing rekor.pub is refused", trust_good, os.path.join(pinned, "absent.pub"), "cannot read")
open(os.path.join(pinned, "junk.pub"), "w").write("not a key")
pin("a rekor.pub that is not a public key is refused", trust_good, os.path.join(pinned, "junk.pub"), "rekor")

# ---- the entry must be IN the log: an inclusion proof (RFC 9162 audit path) and a checkpoint signed by the same key ------------------------------
# REAL_ENTRY is a real Rekor v1 `dsse` entry of the public log, read-only (GET /api/v1/log/entries?logIndex=3596758986 on Oct 30), put into the
# bundle's TransparencyLogEntry form. The committed rekor.pub verifies its signed entry timestamp, its audit path and its checkpoint.
REAL_ENTRY = json.loads(r'''{"logIndex":"3596758986","logId":{"keyId":"wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"1793375135","inclusionPromise":{"signedEntryTimestamp":"MEUCIAPZzJOQc4/RYpr1mqDcbPjMOeyh4Y3YtqbQ9E1lqSIiAiEAxiAv3OYLyIfBYXLE71NIVwN/s/+93PGkwAeiVef51OI="},"inclusionProof":{"logIndex":"3474854724","rootHash":"iLMSzTZM6W4tTIcEqPrjAtYr0R4R+PnRoR+hqAu4dco=","treeSize":"3474858492","hashes":["5FgF15wrcQXMpdyk9hZwq/j/9+zoMrsJfaHw24U253I=","gy8th3X2NaWfeKngoiW3ExHAXfgfHVR6kx+IaSPfZ9M=","mgD1rjMvLEd/jBAACsFzGc/Qe7sENuDLl9DUvVZ/kQE=","ngvKn1LvKpm4i0dxPgNDysYhhg4huNIvCMiJj8kxJZo=","gr6S+W4YdjpKSQNFKi90HZTYtoc2eft1PqtRlxtQa4g=","t8jm9QfjoSamWiAECdZXqcsS10z6GxrHPDY6UN/389A=","B0wQ28tM8cOymFwod78SfmBAqHC68AJ/6XozW29SLLI=","XxDCkZQUuL1gBC0y2dodj9UVHzXW2uBT7IwtDzxNHzI=","lkzgo9700vS02OF8GpULgp/YaGN6+Elz0Rare+ZDZ7o=","lOn2CIBtm11VM6YdPvjgzWQOTmj8upWNBWk3T/bUV+E=","QUlpEWnxQeS97alX7kPFB8ZwswPgXahcR1oD9asQohw=","i2/eKn54aDqf3ojEDyKQpkLBshK8t+6ubCNKQrLdwPM=","Nre0/7J2r2kMdZGmlvOMh7vUp65Jm6bMtIb0LrZ54AU=","sAqjevn5dJSYv+M8/xHPEvA90vkgtR7WYykumSZmfnU=","m4q/2xqKhDKw3zaiWyQGw2uAblXSCvWOLU5u+Rqh6TQ=","Vj1dqwl91IKLknCTGMZxfRmGLwaaOKyzWYkqpfhlx8o=","p1I5ZggjULSs5zA57RP0QvK+8kSLtJbmWwR3QOsQo7g=","dWJeI0tsGHeawe97b89LCkAlxWCLfrUshw9/HC6cfWA=","e3OaWwzL1tEWYXiUzGpH+1v9CiFPwweyfRzIh3Z+uO4=","b+938HIdfjdD/+LgIs3AVRE3Wc65/1NSSAL4OJ5FUXE=","kQz/4ND7LdhfAQn+idNsO+ZFC32sfkYRlhjWF5W+sPc=","zGfeoWKmrZlXMOvyi3R2GDbGpmI1skJW/wLTXCCgF0o=","1DaDKzrCNNBhmSdY5vFjz+NpAmxmYfYEgBCdPLrMP1A=","xH/DCseLHr9eKoYT8qsORZK7zVdEGYWHuVtsVrD95wY="],"checkpoint":{"envelope":"rekor.sigstore.dev - 1193050959916656506\n3474858492\niLMSzTZM6W4tTIcEqPrjAtYr0R4R+PnRoR+hqAu4dco=\n\n\u2014 rekor.sigstore.dev wNI9ajBGAiEA/QPzICrjz8Gm2Kr3sH+mYPPtuElqhzjcPmcK4BJpFbQCIQCspTXJiVpjMPoB5EJH3DG/EdBwaNnrhGvnePTfXtF5Wg==\n"}},"canonicalizedBody":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiMjU0NWVlOTg1YWUzMzExNTQzZDA1ZmEwOTU1MjZkMmE2NDlhMGI4MjNmNGM1YTQyYTIwZTEyYmRhMWNmZjQzOSJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjliYmUzOWQ1MmFlNjM0YWI1MDQ1YTVmMWFiNWFlNDBkODM3ZWVkNjY0MGM5NWFjYTM4MTBiZDU5OThmMDFiNWYifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVRQ0lFZG5BZGliaVdvekxhYVdhbVRHY0RPUjBHYnhBdzNPa2MrdWRtaENHdEpjQWlBTDBEbEtjRkdySlhwRGN5SnVxbTJwZlphTGw1N0t6SFFSSGlrZ29ma2JoQT09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VST1ZFTkRRWEo1WjBGM1NVSkJaMGxWVFVkUVNHaHBWM0pDVUdwd1ZuY3pPRUZtYmpGUVNUZHZiME5WZDBObldVbExiMXBKZW1vd1JVRjNUWGNLVG5wRlZrMUNUVWRCTVZWRlEyaE5UV015Ykc1ak0xSjJZMjFWZFZwSFZqSk5ValIzU0VGWlJGWlJVVVJGZUZaNllWZGtlbVJIT1hsYVV6RndZbTVTYkFwamJURnNXa2RzYUdSSFZYZElhR05PVFdwWmVFMUVUWGROVkZVd1RVUlJNMWRvWTA1TmFsbDRUVVJOZDAxVVZURk5SRkV6VjJwQlFVMUdhM2RGZDFsSUNrdHZXa2w2YWpCRFFWRlpTVXR2V2tsNmFqQkVRVkZqUkZGblFVVjBVaXQ0VVZBMUx6RTNNSGhFYVZSTFdXRnFlVmhRU2xCaGVXUjFja2h1VGpCNVJYWUtSR0ZSYkhOdVJFdFpVVEF6TTFSUldqZzVWakJsVXpKcmRuaFliMEppZDI0MWVrSkRhRVp5WmpsbGVHWkxRbWd4Tmt0UFEwRmtjM2RuWjBoWVRVRTBSd3BCTVZWa1JIZEZRaTkzVVVWQmQwbElaMFJCVkVKblRsWklVMVZGUkVSQlMwSm5aM0pDWjBWR1FsRmpSRUY2UVdaQ1owNVdTRk5OUlVkRVFWZG5RbFJtQ2pBcmJsQldhVkZTYkhadGJ6SlBhMjlXWVV4SFRHaG9hMUI2UW1sQ1owNVdTRkpGUWtGbU9FVlhSRUpYYUd4U2IyUklVbmRqZW05MlRESnNlbU16Vm13S1kyazFiR0p0V25aamJVNXNURzFTYkdScE9EQk9hbXN3VFVST2FFOVVhekphUjFVMFdsUmFhVTlFVFhwTlZFVjVXVEpPYVUxRVRUSk5WRUpxVFZSQ2FBcE9SRWw0VGtSa2JVeDZUWGxhYlZVd1RXMUZNMWxYVFhwTlJHdDZXbTFOZDB0QldVdExkMWxDUWtGSFJIWjZRVUpCVVZGaFlVaFNNR05JVFRaTWVUbHdDbU16VGpGYVdFbDFXbGMxYldJelNtcGFVelZyV2xoWmQwdG5XVXRMZDFsQ1FrRkhSSFo2UVVKRFFWRmpSRUp3YjJSSVVuZGplbTkyVERKc2VtTXpWbXdLWTJrMWJHSnRXblpqYlU1c1RHMVNiR1JxUWtwQ1oyOXlRbWRGUlVGWlR5OU5RVVZaUWtSelRVOVVVVEpQVkZGM1RUSkZOVTlVV210YVZHaHNUbTFKTkFwTmVrMTRUVlJLYWxreVNYZE5lbGw0VFVkTmVFMUhSVEJOYWtVd1RqSlpkazE2U20xYVZGRjVXVlJrYUZsNlRYZFBWRTV0V1hwRFFtbFJXVXRMZDFsQ0NrSkJTRmRsVVVsRlFXZFNOMEpJYTBGa2QwSXhRVTR3T1UxSGNrZDRlRVY1V1hoclpVaEtiRzVPZDB0cFUydzJORE5xZVhRdk5HVkxZMjlCZGt0bE5rOEtRVUZCUW05Wk1UUm5VR3RCUVVGUlJFRkZXWGRTUVVsbldsTnJWVlpCTjFWWkswdHlXV1pyUVZCWGRHeFRZMGxJUkROalRIbzJLMEpGTVhsclZYVTRjUXBaTUdORFNVRnNObXcyTUhocWVEQXhMMjFqZWxSSFRVOXZSRFI0YzBsb2MwMXZaVTV6WTJNMFEwVXlUM2hWU1c5TlFXOUhRME54UjFOTk5EbENRVTFFQ2tFeVkwRk5SMUZEVFVaa2JVRnpNM2d6YlhoNlRVUndSR1pWV21vcmQwVk9WbWR3TVhkSlNteHZUV0p5U2tsWVdIaENlRXBpY2pkbGVUTkhZM1UxYjBjS2FFMVZURnB1ZVZrdlowbDNZVWRNU0ZSWldrNHpiVVpQVGtWdlJFbzVlbU51ZDI5RWRsQjNlbXQ2TjBzeWN6TlZkM2hhTkhVMk9VeDJOMjFXWTNwU01BcFRWRVJqTnk5aFZVaHlLMklLTFMwdExTMUZUa1FnUTBWU1ZFbEdTVU5CVkVVdExTMHRMUW89In1dfX0="}''')
real_pem = open(os.path.join(root, ".github", "policy", "rekor.pub")).read()
(ok if cv.set_is_valid(REAL_ENTRY, real_pem) else bad)("a real public Rekor entry: its signed entry timestamp verifies against the committed rekor.pub")
(ok if cv.check_inclusion(REAL_ENTRY, real_pem) is None else bad)("a real public Rekor entry: its audit path and checkpoint verify against the committed rekor.pub")
import copy
def inc(label, e, want=None, pem=rekor_pem):
    why = cv.check_inclusion(e, pem)
    if want is None:
        ok(label) if why is None else bad("%s -> refused: %s" % (label, why))
    else:
        ok("%s (refused: %s)" % (label, why)) if (why and want in why) else bad("%s -> wanted a refusal naming %r, got %r" % (label, want, why))
def sign_note(note, key=rekor_priv): return sh("openssl", "dgst", "-sha256", "-sign", key, inp=note)
base_e, _ = entry()
for pos, n in ((0, 1), (0, 5), (4, 5), (3, 7), (6, 7), (2, 8)):
    e2 = add_proof(copy.deepcopy(base_e), sign_note, rekor_der, pos=pos, n=n)
    inc("inclusion: leaf %d of a tree of %d is accepted" % (pos, n), e2)
inc("inclusion: an entry with no inclusionProof is refused (a signed timestamp alone is not enough)", {k: v for k, v in base_e.items() if k != "inclusionProof"}, "inclusion proof")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["hashes"][0] = b64(b"\x00" * 32)
inc("inclusion: a changed audit-path hash is refused", e2, "not in the tree")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["hashes"] = e2["inclusionProof"]["hashes"][:-1]
inc("inclusion: a shortened audit path is refused", e2, "not in the tree")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["logIndex"] = "3"
inc("inclusion: a leaf index that is not this entry's place in the tree is refused", e2, "not in the tree")
e2 = copy.deepcopy(base_e); e2["canonicalizedBody"] = b64(b"another body")
inc("inclusion: an entry whose body is not the leaf the path starts from is refused", e2, "not in the tree")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["rootHash"] = b64(b"\x01" * 32)
inc("inclusion: a root hash that the path does not reach is refused", e2, "not in the tree")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["treeSize"] = "6"
inc("inclusion: a tree size other than the signed checkpoint's is refused", e2, "another log or another tree size")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["treeSize"] = "07"
inc("inclusion: a tree size spelled 07 is refused", e2, "no usable inclusion proof")
e2 = add_proof(copy.deepcopy(base_e), lambda note: sign_note(note, other_rekor_priv), rekor_der)
inc("inclusion: a checkpoint signed by another key is refused", e2, "not signed by the policy")
e2 = copy.deepcopy(base_e); env = e2["inclusionProof"]["checkpoint"]["envelope"]
e2["inclusionProof"]["checkpoint"]["envelope"] = env.replace("\n5\n", "\n6\n", 1)
inc("inclusion: a checkpoint that names another tree size is refused", e2, "another log or another tree size")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["checkpoint"]["envelope"] = env.replace("rekor.sigstore.dev - ", "evil.example - ", 1)
inc("inclusion: a checkpoint of another origin is refused", e2, "another log or another tree size")
e2 = copy.deepcopy(base_e); e2["inclusionProof"]["checkpoint"]["envelope"] = env.split("\n\n")[0] + "\n\n"
inc("inclusion: a checkpoint with no signature line is refused", e2, "not signed by the policy")
e2 = copy.deepcopy(base_e); note_lines = env.split("\n")
note_lines[2] = b64(b"\x02" * 32); resigned = "\n".join(note_lines[:3]) + "\n"
e2["inclusionProof"]["checkpoint"]["envelope"] = resigned + "\n\u2014 rekor.sigstore.dev " + b64(hashlib.sha256(rekor_der).digest()[:4] + sign_note(resigned.encode())) + "\n"
inc("inclusion: a validly signed checkpoint for another root than the proof's is refused", e2, "another root hash")
good("an entry with a good signed timestamp and no inclusion proof is refused by check_rekor_entry", entry(proof=False), "inclusion proof")

# ---- the one signing function (handoff 0713 P2): kms_sign runs `cosign attest-blob` with the release key, retries when Rekor does not answer, and
# writes the record (one signature) and its entries file beside it. `run` and `sleep` are arguments of the function, not flags: the tests pass a fake
# cosign and a clock that waits for nothing, so no test calls cosign, KMS or a public Rekor.
import types
STATEMENT = b'{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"x","subject":[],"predicate":{}}'
SIGNING_CONFIG = os.path.join(root, ".github", "policy", "cosign-signing-config.json")


def fake_cosign(mode="ok", failures=0, stderr=b"", payload=STATEMENT, sigs=1):
    calls = []

    def run(argv, **kw):
        calls.append(list(argv))
        if mode == "missing":
            raise FileNotFoundError("cosign")
        if len(calls) <= failures:
            return types.SimpleNamespace(returncode=1, stdout=b"", stderr=stderr)
        bundle_path = argv[argv.index("--bundle") + 1]
        e, _ = entry(payload=payload)
        dsse = {"payloadType": "application/vnd.in-toto+json", "payload": b64(payload),
                "signatures": [{"keyid": "", "sig": b64(sig)}] * sigs}
        vm = {"publicKey": {"hint": "k"}, "tlogEntries": [] if mode == "notlog" else [e]}
        json.dump({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": vm,
                   "dsseEnvelope": dsse}, open(bundle_path, "w"))
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    return run, calls


def ks(label, want, mode="ok", failures=0, stderr=b"", payload=STATEMENT, sigs=1, outname="rec/a-collection.json"):
    """Run kms_sign with the fake cosign; want is None (success) or a word the refusal must hold. Returns (calls, slept, out)."""
    d = os.path.join(work, "ks-" + label.replace(" ", "_")[:40])
    os.makedirs(os.path.join(d, "rec"), exist_ok=True)
    sp, out = os.path.join(d, "statement.json"), os.path.join(d, outname)
    open(sp, "wb").write(STATEMENT)
    run, calls = fake_cosign(mode, failures, stderr, payload, sigs)
    slept = []
    try:
        cv.kms_sign(sp, out, SIGNING_CONFIG, run=run, sleep=slept.append)
        got = None
    except cv.Refuse as ex:
        got = ex.reason
    if want is None:
        (ok if got is None else bad)(label if got is None else "%s -> refused: %s" % (label, got))
    else:
        (ok if got and want.lower() in got.lower() else bad)("%s (refused: %s)" % (label, got) if got and want.lower() in got.lower() else
                                              "%s -> wanted a refusal naming %r, got %r" % (label, want, got))
    return calls, slept, out


calls, slept, out = ks("kms_sign: a good bundle gives the record and its entries file", None)
env = json.load(open(out)) if os.path.exists(out) else {}
ent = json.load(open(out[:-len(".json")] + ".rekor.json")) if os.path.exists(out[:-len(".json")] + ".rekor.json") else {}
(ok if len(env.get("signatures", [])) == 1 and len(ent.get("entries", [])) == 1 and base64.b64decode(env.get("payload", "")) == STATEMENT
 else bad)("kms_sign: the record holds the staged payload and exactly one signature; <record>.rekor.json holds the bundle's entry")
want_argv = ["cosign", "attest-blob", "--yes", "--key", cv.RELEASE_KEY_REF, "--signing-config", SIGNING_CONFIG, "--statement"]
(ok if len(calls) == 1 and calls[0][:8] == want_argv and calls[0][9] == "--bundle" and len(calls[0]) == 11 else bad)(
    "kms_sign: cosign is called once with exactly attest-blob --yes --key <the KMS key> --signing-config <config> --statement S --bundle B: %s" % calls)
(ok if slept == [] else bad)("kms_sign: a first try that works waits for nothing")
ks("kms_sign: a bundle that signed another payload than the staged one is refused", "payload", payload=b"another statement")
ks("kms_sign: a bundle with no Rekor entry is refused", "rekor", mode="notlog")
ks("kms_sign: a bundle with two signatures is refused", "signatures", sigs=2)
calls, slept, out = ks("kms_sign: a Rekor outage for three tries and then an answer succeeds", None, failures=3,
                       stderr=b"error: creating log entry: rekor: 503 Service Unavailable")
(ok if slept == [1, 2, 4] and len(calls) == 4 else bad)("kms_sign: it waited 1, 2 and 4 seconds and tried four times: %s %d" % (slept, len(calls)))
calls, slept, out = ks("kms_sign: Rekor down for all seven tries is one refusal naming Rekor", "rekor", failures=99,
                       stderr=b"error: tlog: rekor 502 bad gateway")
(ok if slept == [1, 2, 4, 8, 16, 32] and len(calls) == 7 and not os.path.exists(out) else bad)(
    "kms_sign: one try and six retries (waits 1, 2, 4, 8, 16, 32) and no record left: %s %d" % (slept, len(calls)))
calls, slept, out = ks("kms_sign: a cosign failure that is not Rekor (KMS refused) is refused at once, without a wait", "cosign failed",
                       failures=99, stderr=b"AccessDeniedException: not authorized to perform kms:Sign")
(ok if slept == [] and len(calls) == 1 else bad)("kms_sign: the KMS refusal was tried once and waited for nothing: %s %d" % (slept, len(calls)))
ks("kms_sign: cosign missing from the PATH is a refusal", "cosign", mode="missing")
d = os.path.join(work, "ks-exists"); os.makedirs(d, exist_ok=True)
open(os.path.join(d, "statement.json"), "wb").write(STATEMENT); open(os.path.join(d, "r.json"), "w").write("old")
run, calls = fake_cosign()
try:
    cv.kms_sign(os.path.join(d, "statement.json"), os.path.join(d, "r.json"), SIGNING_CONFIG, run=run, sleep=lambda s: None)
    bad("kms_sign: an existing record is not overwritten")
except cv.Refuse as ex:
    (ok if "exists" in ex.reason and not calls else bad)("kms_sign: an existing record is refused before cosign is asked (%s)" % ex.reason)

# KMS rule 4 / build-apk rule 22: production code holds no test hook. The flags that swapped the trust root or the clock are gone from every
# subcommand, and verify_record takes no `now`.
import inspect
act = [a for a in cv.build_parser()._actions if a.__class__.__name__ == "_SubParsersAction"][0]
for flag in ("--keys-dir", "--trust", "--rekor-key", "--now"):
    held = sorted(n for n, sp in act.choices.items() if any(flag in o.option_strings for o in sp._actions))
    (ok if not held else bad)("no subcommand takes %s%s" % (flag, "" if not held else ": " + " ".join(held)))
(ok if "now" not in inspect.signature(cv.verify_record).parameters else bad)("verify_record takes no `now` (no time inside a record is trusted)")
(ok if not hasattr(cv, "parse_now") else bad)("the verifier has no --now parser")

# Every pinned `chain-verify.py` line in the workflows and the release scripts must parse (it once failed in production with exit 2 when a flag was
# renamed and five pinned lines were not): each line is run through build_parser(); a $-word or an expression stands for a value.
import glob, re, shlex
lines = []
for path in sorted(glob.glob(os.path.join(root, ".github", "workflows", "*.yml")) + glob.glob(os.path.join(root, "bin", "*.sh"))):
    if path.endswith("-test.sh"):
        continue
    for n, text in enumerate(re.sub(r"\\\n\s*", " ", open(path, errors="replace").read()).split("\n"), 1):     # a continued line is one line
        m = re.search(r"chain-verify\.py\s+[a-z][a-z-]*\s.*", text)
        if m and "--help" not in text and not text.lstrip().startswith("#"):
            lines.append((os.path.relpath(path, root), n, m.group(0)))
parsed = 0
for rel, n, cmd in lines:
    cmd = re.sub(r"\$\{\{.*?\}\}", "x", cmd)
    cmd = re.split(r"\s(?:2>|>|\|\||&&|\||;)\s*", cmd)[0].rstrip("\\ ")
    try:
        words = shlex.split(cmd)
        argv = [(("1" if words[i - 1] == "--exit-code" else "x") if "$" in w else w) for i, w in enumerate(words)][1:]
        cv.build_parser().parse_args(argv)
        parsed += 1
    except SystemExit:
        bad("%s:%d: the pinned line does not parse: %s" % (rel, n, cmd[:120]))
    except ValueError:
        pass                      # a line cut in the middle of a quote: its other lines are checked
if lines and parsed == len(lines):
    ok("every pinned chain-verify.py line (%d, in the workflows and bin/*.sh) parses through build_parser()" % len(lines))
else:
    bad("no pinned chain-verify.py line was found to parse")
try:
    cv.build_parser().parse_args(["verify", "--stage", "sign", "--record", "x", "--policy", "x", "--rekor-stub", "x"])
    ok("--rekor-stub is accepted by verify")
    cv.build_parser().parse_args(["stage-start", "--stage", "release", "--previous", "sign", "--record", "x", "--digests", "x", "--policy", "x", "--rekor-stub", "x"])
    ok("--rekor-stub is accepted by stage-start")
except SystemExit:
    bad("--rekor-stub is not accepted by the parser")

print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
