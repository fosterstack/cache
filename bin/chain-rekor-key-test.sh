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


def entry(rk=rekor_priv, rk_der=rekor_der, payload=payload, sig=sig, verifier_pem=kms_pem, index="7", itime="1761800000"):
    """A Rekor v1 `dsse` entry as it sits in a bundle's tlogEntries, signed (the signed entry timestamp) by the log key `rk`."""
    body = {"apiVersion": "0.0.1", "kind": "dsse", "spec": {
        "envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
        "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()},
        "signatures": [{"signature": b64(sig), "verifier": b64(verifier_pem.encode())}]}}
    cb = b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    log_id = hashlib.sha256(rk_der).hexdigest()
    canon = json.dumps({"body": cb, "integratedTime": int(itime), "logID": log_id, "logIndex": int(index)}, sort_keys=True, separators=(",", ":")).encode()
    set_sig = sh("openssl", "dgst", "-sha256", "-sign", rk, inp=canon)
    return {"logIndex": index, "integratedTime": itime, "logId": {"keyId": b64(bytes.fromhex(log_id))}, "kindVersion": {"kind": "dsse", "version": "0.0.1"},
            "canonicalizedBody": cb, "inclusionPromise": {"signedEntryTimestamp": b64(set_sig)}}, body


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
        cv.verify_record(vpol, stage, "rec.json", None, tmpd, rekor_path=rekor_path)
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
vr("verify_record: a provenance with its Rekor entry is accepted", "sign", cv.DSSE_STMT, PROV, stat, None)
vr("verify_record: a provenance with no Rekor entries file is refused", "sign", cv.DSSE_STMT, PROV, None, "rekor")
vr("verify_record: a provenance whose entries file holds no entry for it is refused", "sign", cv.DSSE_STMT, PROV, entries_file("vr-empty.json", {"entries": []}), "no rekor entry")
vr("verify_record: the release policy with no Rekor entries file is refused", "release", POLT, "policy", None, "rekor")
vr("verify_record: a Witness record needs no Rekor entry", "build", cv.DSSE_STMT, COLL, None, None)
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

print("pass=%d fail=%d" % (passed, failed))
sys.exit(1 if failed else 0)
PY
