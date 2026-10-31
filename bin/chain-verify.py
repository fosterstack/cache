#!/usr/bin/env python3
"""The plain verifier of the v0.3.0 release chain (rules 52, 53, 53b, 57 verify side, 58, 63, 67).

Subcommands: policy make, verify, sign --check, check-build-record, stage-start, actions, hostile-row, hostile-collect,
hostile-material, hostile-verdict, rc-proof. The CLI contract is the header of the verify test; the hostile
subcommands are specified in the header of the hostile test.

Every refusal exits 1 and prints, as its FIRST stderr line, `refused at <stage>: <reason>`. Anything else
(bad usage, an unreadable input of the hostile helpers) is `error: ...` and exits 2 (or 1 where the test says so).
No network is used: the record's signature, the key manifest and the Rekor entries (the signed entry timestamp, the
inclusion proof and the checkpoint) are verified from files only, with the openssl binary (the fixed path OPENSSL in the
common helper module). Tokens in the environment are never read, printed or stored here.

Modelled on: in-toto-witness cmd/verify.go:116-163,211 (a verifier's refusal is its exit code and message),
options/sign.go:36 (policy payloadType), docs/tutorials/artifact-policy.md:58-70 (collection predicate type, product
subject name `.../product/v0.1/file:<name>`);
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
import stat
import subprocess
import unicodedata
import sys
import tempfile
import time

# PyYAML is imported by the `actions` subcommand only (load_yaml): the Sign job installs cosign and nothing else (Codex security r1 S4)
import types


def load_sibling(name):
    """Load the helper module <name> from this directory, never through sys.path and never from a bytecode cache (Opus #249 r4, r5): its
    bytes must carry the sha256 listed for it in .github/policy/chain-scripts.json, and those same bytes are compiled and run, so a
    __pycache__ entry cannot stand in for the hashed file. The module is registered under its name first, so the other helper's
    `from chain_common import` gets this same copy."""
    if name in sys.modules:
        return sys.modules[name]
    here = os.path.dirname(os.path.abspath(__file__))
    rel = "bin/" + name + os.extsep + "py"
    with open(os.path.join(here, name + os.extsep + "py"), "rb") as f:
        src = f.read()
    try:
        with open(os.path.join(os.path.dirname(here), ".github", "policy", "chain-scripts.json"), "rb") as f:
            listed = {r["path"]: r["sha256"] for r in json.load(f)["scripts"]}
    except (OSError, ValueError, KeyError, TypeError) as ex:
        sys.exit("error: cannot read the listed hashes of the helper modules (%s)" % type(ex).__name__)
    if listed.get(rel) != hashlib.sha256(src).hexdigest():
        sys.exit("error: %s does not match its sha256 in .github/policy/chain-scripts.json; refusing to run it" % rel)
    mod = types.ModuleType(name)
    mod.__file__ = os.path.join(here, name + os.extsep + "py")
    sys.modules[name] = mod
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    return mod


_common = load_sibling("chain_common")
Refuse, b64d, b64e, load_json, refuse, ssl_done, strict_json = (
    _common.Refuse, _common.b64d, _common.b64e, _common.load_json, _common.refuse, _common.ssl_done, _common.strict_json)
OPENSSL = _common.OPENSSL
chain_hostile = load_sibling("chain_hostile")
chain_items = load_sibling("chain_items")

PROV = "https://slsa.dev/provenance/v1"
COLL = "https://witness.testifysec.com/attestation-collection/v0.1"
POLT = "https://witness.testifysec.com/policy/v0.1"
DSSE_STMT = "application/vnd.in-toto+json"
STMT_TYPES = ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1")
PRODUCT = "https://witness.dev/attestations/product/v0.1/file:digests.json"
STAGES = ("build", "sign", "rebuild", "check", "release")
WITNESS_STAGES = ("build", "rebuild", "check")
ENV_ATTESTOR = "https://witness.dev/attestations/environment/v0.1"


TAG_GRAMMAR = r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?"


MANIFEST_FILES = ("release-key-root.pub", "release-key-manifest.json", "release-key-manifest.sig")
MANIFEST_FIELDS = ("public_key", "key_id", "valid_from", "valid_to", "revoked_at")
ONE_PUBLIC_KEY_PEM = re.compile(r"\s*-----BEGIN PUBLIC KEY-----[A-Za-z0-9+/=\s]*-----END PUBLIC KEY-----\s*")
MANIFEST_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def read_manifest_file(path, what):
    """The bytes of a regular file that is not a link, else a refusal: a manifest file must not be missing, a directory
    or a link."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            refuse("manifest", "%s is not a regular file (a link or a directory): %s" % (what, os.path.basename(path)))
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        refuse("manifest", "%s is missing or unreadable: %s" % (what, os.path.basename(path)))


def manifest_date(m, field, required):
    if field not in m:
        if required:
            refuse("manifest", "%s is missing" % field)
        return None
    v = m[field]
    try:
        if not (isinstance(v, str) and MANIFEST_DATE.fullmatch(v)):
            raise ValueError(v)
        return dt.datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        refuse("manifest", "%s is not a date written YYYY-mm-ddTHH:MM:SSZ" % field)


def check_manifest(keys_dir):
    """The release key manifest, checked before anything else is read (handoff 0713 P1): the offline root key's
    signature over the exact
    bytes of the manifest file, then the closed field list, the key (ECDSA P-256) and its key_id, and the window against
    the clock of this run.
    No time inside a record is trusted (ruling R3), so a revoked_at at or before now refuses the manifest. Returns
    {key_id, public_key}."""
    root_p, man_p, sig_p = (os.path.join(keys_dir, n) for n in MANIFEST_FILES)
    root_raw = read_manifest_file(root_p, "root key file")
    body = read_manifest_file(man_p, "manifest file")
    sig_raw = read_manifest_file(sig_p, "signature file")
    try:
        sig = b64d(sig_raw.decode("ascii").rstrip("\n"))
    except ValueError:
        refuse("manifest", "the signature file is not canonical base64")
    with tempfile.TemporaryDirectory() as tmp:
        for name, data in (("root.pub", root_raw), ("manifest.json", body), ("manifest.sig", sig)):
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(data)
        root_der = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", os.path.join(tmp, "root.pub"), "-outform", "DER"], capture_output=True)
        if root_der.returncode != 0 or not root_der.stdout:
            refuse("manifest", "the root key file is not a public key")
        if not is_p256_spki(root_der.stdout):
            refuse("manifest", "the root key file is not an ECDSA P-256 key")
        verified = subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", os.path.join(tmp, "root.pub"),
                       "-signature", os.path.join(tmp, "manifest.sig"), os.path.join(tmp, "manifest.json")], capture_output=True)
        if not sig or verified.returncode != 0:
            refuse("manifest", "the signature of the manifest does not verify with the root key")
        m = parse_manifest_body(body)
        key = manifest_key(m, tmp)
    now = dt.datetime.now(dt.timezone.utc)
    start = manifest_date(m, "valid_from", True)
    end, revoked = manifest_date(m, "valid_to", False), manifest_date(m, "revoked_at", False)
    if now < start:
        refuse("manifest", "the key is not yet valid (valid_from %s)" % m["valid_from"])
    if end is not None and now >= end:
        refuse("manifest", "the key has expired (valid_to %s)" % m["valid_to"])
    if revoked is not None and now >= revoked:
        refuse("manifest", "the key was revoked (revoked_at %s)" % m["revoked_at"])
    return key


def parse_manifest_body(body):
    try:
        m = strict_json(body)
    except ValueError as ex:
        refuse("manifest", "the manifest is not JSON (%s)" % ex)
    if not isinstance(m, dict):
        refuse("manifest", "the manifest is not a JSON object")
    for k in m:
        if k not in MANIFEST_FIELDS:
            refuse("manifest", "unknown field %r" % k)
    for k in ("public_key", "key_id"):
        if k not in m:
            refuse("manifest", "%s is missing" % k)
    return m


# SubjectPublicKeyInfo of an ECDSA P-256 key, up to its point
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def is_p256_spki(der):
    """True for the DER of an ECDSA P-256 public key: the 26-byte SPKI prefix, then the 65-byte uncompressed point
    (91 bytes in all)."""
    n = len(P256_SPKI_PREFIX)
    return len(der) == n + 65 and der.startswith(P256_SPKI_PREFIX) and der[n] == 4


def manifest_key(m, tmp):
    """The manifest's key: one PEM public key block, ECDSA P-256 (the KMS key's type), and key_id = the lower-case
    sha256 of its DER."""
    pem = m["public_key"]
    if not (isinstance(pem, str) and ONE_PUBLIC_KEY_PEM.fullmatch(pem)):
        refuse("manifest", "public_key is not exactly one PEM public key block")
    der = public_key_der(pem)
    if der is None:
        refuse("manifest", "public_key is not a public key")
    if not is_p256_spki(der):
        refuse("manifest", "public_key is not an ECDSA P-256 key")
    if m["key_id"] != hashlib.sha256(der).hexdigest():
        refuse("manifest", "key_id is not the lower-case sha256 of the public key")
    return {"key_id": m["key_id"], "public_key": pem}


def rekor_pin(trust_path, rekor_path):
    """The Rekor log's public key (PEM text), taken from rekor.pub only when sigstore-trust.json pins it: the sha256 of
    the key's DER must be
    the file's rekor_sha256. This is only a drift check, not an authorization: a hash edited in the same pull request
    authorizes nothing, the
    boundary is review of these files. rekor_sha256 records the refresh from Sigstore's TUF root. It is the only
    Sigstore material the
    key-signed chain trusts (ratify B: Rekor kept, Fulcio and the TSA gone)."""
    trust = load_json(trust_path, "trust file")
    try:
        with open(rekor_path) as f:
            text = f.read()
    except OSError as ex:
        raise Refuse("policy", "trust: cannot read %s" % ex)
    der = public_key_der(text)
    if der is None:
        refuse("policy", "trust: the rekor key file is not a public key")
    if trust.get("rekor_sha256") != hashlib.sha256(der).hexdigest():
        refuse("policy", "trust: rekor_sha256 of the rekor key file does not match the committed trust file")
    return text


def policy_make(a):
    # the key files sit beside the template: there is no flag that points elsewhere
    pol_dir = os.path.dirname(os.path.abspath(a.template))
    key = check_manifest(pol_dir)
    tpl = load_json(a.template, "template")
    rekor_text = rekor_pin(os.path.join(pol_dir, "sigstore-trust.json"), os.path.join(pol_dir, "rekor.pub"))
    if re.match(r"(refs/tags/)?v0\.0\.0($|-)", a.tag or a.ref or ""):
        refuse("policy", "snapshot version")      # no policy, hence no Sign or Release, can exist for a snapshot version (REQ-CHAIN-004-AC15)
    if a.tag:
        if not re.fullmatch(TAG_GRAMMAR, a.tag):
            refuse("policy", "tag %r is not vX.Y.Z or vX.Y.Z-rcN" % a.tag)
        ref, tag, dry = "refs/tags/" + a.tag, a.tag, False
    else:
        ref = a.ref or ""
        m = re.fullmatch(r"refs/tags/(%s)" % TAG_GRAMMAR, ref)
        if m:
            tag, dry = m.group(1), False
        elif ref.startswith("refs/heads/") and len(ref) > len("refs/heads/"):
            tag, dry = "", True
        else:
            refuse("policy", "ref %r is neither refs/tags/vX.Y.Z[-rcN] nor a branch (tag)" % ref)
    pol = {"tag": tag, "ref": ref, "repository": tpl["repository"], "release_key": key,
           "rekor_public_key": rekor_text, "stages": tpl["stages"]}
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
    """Every envelope field has its JSON type: payloadType and payload strings, signatures a list of objects that hold a
    string sig and
    an optional string keyid and nothing else (a certificate, intermediates or timestamps field is an old-form record).
    Returns the first wrong field or None."""
    if not isinstance(dsse, dict):
        return "the envelope is not an object"
    for k in ("payloadType", "payload"):
        if not isinstance(dsse.get(k), str):
            return "%s is not a string" % k
    sigs = dsse.get("signatures")
    if not isinstance(sigs, list) or not all(isinstance(x, dict) for x in sigs):
        return "signatures is not a list of objects"
    for x in sigs:
        extra = sorted(set(x) - {"keyid", "sig"})
        if extra:
            return "signature field %s is not part of the form (a signature is {keyid, sig})" % extra[0]
        if not isinstance(x.get("sig"), str):
            return "signature field sig is not a string"
        if "keyid" in x and not isinstance(x["keyid"], str):
            return "signature field keyid is not a string"
    return None


def local_records(stage, rec_path):
    """A *.local.json is the building job's untrusted local record: it is never read as a record, and a directory handed to a verifier must not hold one."""
    d = os.path.dirname(os.path.abspath(rec_path))
    try:
        names = sorted(os.listdir(d))
    except OSError:
        names = []
    bad = [n for n in names if n.endswith(".local.json")] + ([os.path.basename(rec_path)] if rec_path.endswith(".local.json") and os.path.basename(rec_path) not in names else [])
    if bad:
        refuse(stage, "record: %s holds %s: an unsigned local record (*.local.json) is never trusted and must not sit beside a trusted one" % (os.path.basename(d) or d, " ".join(bad)))


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
    # a snapshot record or version, a name that is not the stage's: refused before the signature
    chain_items.check_record_names(stage, payload)
    return dsse, payload, ptype


def release_key_pem(stage, pol):
    """The policy's one release key (the manifest key `policy make` put there); a policy without one verifies
    nothing."""
    k = pol.get("release_key")
    if not (isinstance(k, dict) and isinstance(k.get("public_key"), str)):
        refuse(stage, "the policy has no release key (release_key)")
    return k["public_key"]


def check_signature(stage, pol, ptype, payload, sig, tmp):
    """The record's one signature is the release key's ECDSA P-256 signature over the DSSE PAE. A record signed by
    another key, by the
    building job's throwaway key, or by nobody ends here (ruling F2: one refusal, the same words)."""
    for n, data in (("release.pub", release_key_pem(stage, pol).encode()), ("pae.bin", pae(ptype, payload)),
                    ("sig.bin", sig)):
        with open(os.path.join(tmp, n), "wb") as f:
            f.write(data)
    r = subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", os.path.join(tmp, "release.pub"), "-signature", os.path.join(tmp, "sig.bin"),
            os.path.join(tmp, "pae.bin")], capture_output=True)
    # the one pass is exit status 0; openssl exits 1 for a bad signature and for an error alike, so what it said is
    # appended, not matched
    if r.returncode != 0:
        said = " / ".join((r.stdout + r.stderr).decode(errors="replace").strip().splitlines())[:200] or "no output"
        refuse(stage, "signature does not verify over the payload: the record is not signed by the manifest key "
                      "(openssl exit %d: %s)" % (r.returncode, said))



TYPE_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:\S+")


def _type_uri(v):
    """A SLSA v1 TypeURI: a string with a scheme, a colon and a non-empty remainder, and no whitespace, control, format, separator or
    other invisible character anywhere (Unicode categories Z* and C*: NBSP, U+200B and the rest)."""
    return (isinstance(v, str) and TYPE_URI.fullmatch(v) is not None
            and not any(unicodedata.category(c)[0] in "ZC" for c in v))


HEX_LEN = {"sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}


def check_subjects(stage, stmt):
    """REQ-CHAIN-001-AC4 (Codex #249 r7 B6): every signed in-toto statement, provenance or Witness collection, has a subject list that is a
    non-empty list of objects, each with a non-empty string name and a non-empty digest object whose algorithm names are non-empty
    lowercase strings and whose values are strings; a sha1/sha256/sha384/sha512 value is lowercase hex of its length. Checked when the
    record type is judged, before anything reads a subject."""
    subs = stmt.get("subject")
    if not isinstance(subs, list) or not subs:
        refuse(stage, "the record's subjects are malformed (the subject list is missing, empty or not a list)")
    for sub in subs:
        shown = json.dumps(sub)[:120]
        if not isinstance(sub, dict) or not isinstance(sub.get("name"), str) or not sub["name"].strip():
            refuse(stage, "the record's subjects are malformed (a subject has no non-empty string name): %s" % shown)
        dg = sub.get("digest")
        if not isinstance(dg, dict) or not dg:
            refuse(stage, "the record's subjects are malformed (a subject's digest is not a non-empty object): %s" % shown)
        for alg, val in dg.items():
            if not isinstance(alg, str) or not alg or alg != alg.lower() or not isinstance(val, str) or not val:
                refuse(stage, "the record's subjects are malformed (a digest entry is not a lowercase algorithm with a string value): %s" % shown)
            if alg in HEX_LEN and not re.fullmatch(r"[0-9a-f]{%d}" % HEX_LEN[alg], val):
                refuse(stage, "the record's subjects are malformed (a %s digest is not %d lowercase hex characters): %s" % (alg, HEX_LEN[alg], shown))


def check_slsa_v1(stage, predicate):
    """REQ-CHAIN-001-AC4 (Codex #249 r4 B4, r5 B5 + Sonnet: the class closed): the provenance is a standard SLSA v1 record
    (https://slsa.dev/spec/v1.0/provenance) and every field of it has its type. Required: buildDefinition {buildType: TypeURI,
    externalParameters: object} and runDetails {builder {id: TypeURI}}. When present: internalParameters an object;
    resolvedDependencies and byproducts lists of objects (a dependency's uri a string, its digest an object of string values);
    builder.version an object of strings; metadata an object whose invocationId, startedOn and finishedOn are strings."""
    def bad(what):
        refuse(stage, "predicate: the provenance %s (not a SLSA v1 record)" % what)
    if not isinstance(predicate, dict):
        bad("predicate is not an object")
    bd, rd = predicate.get("buildDefinition"), predicate.get("runDetails")
    if not isinstance(bd, dict):
        bad("has no buildDefinition object")
    if "buildType" not in bd:
        bad("buildDefinition has no buildType")
    if not _type_uri(bd["buildType"]):
        bad("buildDefinition.buildType is not a URI string")
    if "externalParameters" not in bd:
        bad("buildDefinition has no externalParameters")
    if not isinstance(bd["externalParameters"], dict):
        bad("buildDefinition.externalParameters is not an object")
    if "internalParameters" in bd and not isinstance(bd["internalParameters"], dict):
        bad("buildDefinition.internalParameters is not an object")
    if "resolvedDependencies" in bd:
        deps = bd["resolvedDependencies"]
        if not isinstance(deps, list) or not all(isinstance(x, dict) for x in deps):
            bad("buildDefinition.resolvedDependencies is not a list of objects")
        for x in deps:
            if "uri" in x and not isinstance(x["uri"], str):
                bad("resolvedDependencies uri is not a string")
            if "digest" in x and (not isinstance(x["digest"], dict) or not all(isinstance(v, str) for v in x["digest"].values())):
                bad("resolvedDependencies digest is not an object of strings")
    if not isinstance(rd, dict):
        bad("has no runDetails object")
    builder = rd.get("builder")
    if not isinstance(builder, dict):
        bad("runDetails.builder is not an object")
    if not _type_uri(builder.get("id")):
        bad("runDetails.builder.id is not a URI string")
    if "version" in builder and (not isinstance(builder["version"], dict) or not all(isinstance(v, str) for v in builder["version"].values())):
        bad("runDetails.builder.version is not an object of strings")
    if "metadata" in rd:
        md = rd["metadata"]
        if not isinstance(md, dict):
            bad("runDetails.metadata is not an object")
        for k in ("invocationId", "startedOn", "finishedOn"):
            if k in md and not isinstance(md[k], str):
                bad("runDetails.metadata.%s is not a string" % k)
    if "byproducts" in rd and (not isinstance(rd["byproducts"], list) or not all(isinstance(x, dict) for x in rd["byproducts"])):
        bad("runDetails.byproducts is not a list of objects")


def check_record_type(stage, pol, ptype, payload):
    """Bind the record type to the stage. Returns the statement (the policy payload for the release stage)."""
    if ptype == POLT:
        if stage != "release":
            refuse(stage, "predicate: the signed policy type (policy payloadType) is the release stage's record, not %s's" % stage)
        try:
            return strict_json(payload)
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
    if not isinstance(pt, str):
        refuse(stage, "predicate: the predicateType is not a string")
    check_subjects(stage, stmt)
    if pt == PROV:
        if stage != "sign":
            refuse(stage, "predicate type provenance is the sign stage's record type, not %s's" % stage)
        predicate = stmt.get("predicate")
        check_slsa_v1(stage, predicate)
        params = predicate["buildDefinition"]["externalParameters"]
        found = params.get("ref")
        if found != pol.get("ref"):
            refuse(stage, "ref: the ref inside the provenance (%s) is not the policy's ref %s"
                   % (json.dumps(found), pol.get("ref")))
        # the provenance names the ref twice (the run's ref and the calling workflow's `file@ref`); a branch run must
        # not pass as the tag by either one
        workflow = params.get("workflow")
        want = "https://github.com/%s/.github/workflows/release.yml@%s" % (pol.get("repository"), pol.get("ref"))
        if workflow != want:
            refuse(stage, "ref: the calling workflow inside the provenance (%s) is not %s"
                   % (json.dumps(workflow), want))
        if predicate.get("dryRun") and not pol.get("dry_run"):
            refuse(stage, "the provenance says dryRun true (dry): only a dry-run policy accepts it")
        return stmt
    if pt == COLL:
        if stage not in WITNESS_STAGES:
            refuse(stage, "predicate type %s (a witness collection) is not the %s stage's record type" % (pt, stage))
        collection_ref(stage, pol, stmt)
        return stmt
    refuse(stage, "predicate type %s is not allowed for stage %s" % (pt, stage))


def collection_ref(stage, pol, stmt):
    """Tag binding of a Witness collection: the environment attestor (the building job runs it under Witness) records
    GITHUB_REF, and it must be the policy's ref, so a collection made at another tag, an rc tag or a branch (same
    digests) is refused. Exactly one environment attestor."""
    atts = (stmt.get("predicate") or {}).get("attestations") if isinstance(stmt, dict) else None
    envs = [a for a in atts if isinstance(a, dict) and a.get("type") == ENV_ATTESTOR] if isinstance(atts, list) else []
    if len(envs) != 1:
        refuse(stage, "ref: the collection holds %d environment attestations, not exactly one" % len(envs))
    att = envs[0].get("attestation")
    found = ((att.get("variables") or {}).get("GITHUB_REF") if isinstance(att, dict) else None)
    if not isinstance(found, str) or found != pol.get("ref"):
        refuse(stage, "ref: the ref inside the collection (%s) is not the policy's ref %s"
               % (json.dumps(found), pol.get("ref")))


def verify_record(pol, stage, rec_path, tmp, rekor_path=None):
    """Verify one stage's DSSE record against the policy: the envelope, the release key's signature, the record type
    bound to the stage, and the Rekor entry of that signature (ratify B: every signature by the release key has one,
    and Release refuses a signature without it). The entries file is `rekor_path`, else the file beside the record
    (see rekor_entries_path). No time inside a record is trusted.
    Returns (statement-or-policy-dict, payload, envelope)."""
    if stage not in STAGES or stage not in pol.get("stages", {}):
        refuse(stage, "stage %r is not in the policy" % stage)
    if pol.get("dry_run") and stage != "sign":
        refuse(stage, "the policy is a dry-run policy (dry): it is accepted only for stage sign")
    local_records(stage, rec_path)
    dsse, payload, ptype = read_record(stage, rec_path)
    try:
        sig = b64d(dsse["signatures"][0]["sig"])
    except Exception as ex:
        refuse(stage, "record is not a DSSE envelope (signature is malformed: %s)"
                      % (ex if isinstance(ex, ValueError) else type(ex).__name__))
    check_signature(stage, pol, ptype, payload, sig, tmp)
    stmt = check_record_type(stage, pol, ptype, payload)
    check_rekor(pol, stage, rekor_path or rekor_entries_path(rec_path, None), payload, sig,
                public_key_der(release_key_pem(stage, pol)))
    if isinstance(stmt, dict) and stmt.get("predicateType") == COLL:
        chain_items.check_record_env(stage, dsse, payload)      # REQ-CHAIN-004-AC8: no token variable or value in a verified Witness collection
    return stmt, payload, dsse


# ---- Rekor (v1 log, the DSSE entry kind that `cosign attest-blob --key` writes) --------------------------------------
# Ratify B (owner, Oct 29): every signature by the KMS release key keeps its Rekor entry, and Release refuses a
# signature without one.
# An entry is a protobuf-JSON TransparencyLogEntry as it sits in a Sigstore bundle's tlogEntries (logIndex and
# integratedTime are
# decimal strings; logId.keyId and canonicalizedBody are base64; inclusionPromise.signedEntryTimestamp is the log's
# signature).
# Its body is a Rekor `dsse` 0.0.1 entry:
# {"apiVersion","kind":"dsse","spec":{"payloadHash","signatures":[{"signature","verifier"}]}}.
# For a key signature the verifier is the base64 PEM of the PUBLIC KEY, so the entry is bound to the manifest's KMS key,
# not to a
# certificate. The signed entry timestamp is the log's ECDSA signature over the canonical JSON {body, integratedTime,
# logID, logIndex}.
# The entry must also be IN the log: its inclusionProof (RFC 9162 audit path to the root) and the checkpoint signed by
# the same key are checked.
# No time in the entry is trusted: the log's signature over it is checked, and the integrated time is not compared with
# anything.
CANONICAL_DECIMAL = re.compile(r"0|[1-9][0-9]*")
# seconds between one try and six retries (about 63 s in all); then Release fails closed
REKOR_WAITS = (1, 2, 4, 8, 16, 32)


def canonical_int(e, field):
    """protobuf-JSON writes int64 as a decimal STRING; only its one canonical spelling is accepted: int() would read 7,
    "+7", " 7", "07"
    and 7.9 alike, so an edited outer entry would still match the log's signed numbers."""
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


def public_key_der(pem):
    """The DER of one PEM public key, or None when the text is not one."""
    with tempfile.TemporaryDirectory() as d:
        kp = os.path.join(d, "key.pem")
        with open(kp, "w") as f:
            f.write(pem)
        r = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", kp, "-outform", "DER"], capture_output=True)
    return r.stdout if r.returncode == 0 and r.stdout else None


def set_is_valid(e, key_pem):
    canon = json.dumps(rekor_entry_fields(e), sort_keys=True, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory() as d:
        for name, data in (("key.pem", key_pem.encode()), ("set.bin", canon), ("set.sig", b64d(e["inclusionPromise"]["signedEntryTimestamp"]))):
            with open(os.path.join(d, name), "wb") as f:
                f.write(data)
        r = subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", os.path.join(d, "key.pem"), "-signature",
            os.path.join(d, "set.sig"), os.path.join(d, "set.bin")], capture_output=True)
    return r.returncode == 0


def merkle_inclusion_ok(index, size, leaf, hashes, root):
    """RFC 9162 section 2.1.3.2: does `hashes` (32-byte audit path) take the leaf at `index` to `root` in a tree of
    `size` leaves."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in hashes:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def check_inclusion(e, rekor_pem):
    """None when the entry is IN the log's tree, else the reason it is not: the leaf hash of the canonical body takes
    the audit path to the
    root hash at the tree size, and the checkpoint (a signed note) is signed by the policy's Rekor key and names that
    same size and root."""
    try:
        proof = e["inclusionProof"]
        index, size = canonical_int(proof, "logIndex"), canonical_int(proof, "treeSize")
        root = b64d(proof["rootHash"])
        hashes = [b64d(h) for h in proof["hashes"]]
        envelope = proof["checkpoint"]["envelope"]
        leaf = hashlib.sha256(b"\x00" + b64d(e["canonicalizedBody"])).digest()
    except (KeyError, TypeError, ValueError, AttributeError):
        return "rekor entry has no usable inclusion proof (a signed entry timestamp alone is not enough)"
    if len(root) != 32 or not all(len(h) == 32 for h in hashes):
        return "rekor entry inclusion proof: a hash is not 32 bytes"
    if not merkle_inclusion_ok(index, size, leaf, hashes, root):
        return "rekor entry is not in the tree: its audit path does not lead to the root hash"
    if not isinstance(envelope, str) or "\n\n" not in envelope:
        return "rekor entry checkpoint is not a signed note"
    text, _, sigs = envelope.partition("\n\n")
    text += "\n"
    lines = text.split("\n")
    if len(lines) < 4 or not lines[0].startswith("rekor.sigstore.dev - ") or lines[1] != str(size):
        return "rekor entry checkpoint names another log or another tree size"
    try:
        if b64d(lines[2]) != root:
            return "rekor entry checkpoint names another root hash than the inclusion proof"
    except ValueError:
        return "rekor entry checkpoint root hash is malformed"
    rekor_der = public_key_der(rekor_pem)
    if rekor_der is None:
        return "rekor entry: the policy's rekor key is not a public key"
    for line in sigs.split("\n"):
        if not line.startswith("\u2014 "):
            continue
        try:
            blob = b64d(line.split(" ")[2])
        except (IndexError, ValueError):
            continue
        if blob[:4] != hashlib.sha256(rekor_der).digest()[:4]:
            continue
        with tempfile.TemporaryDirectory() as d:
            for name, data in (("key.pem", rekor_pem.encode()), ("note.bin", text.encode()), ("note.sig", blob[4:])):
                with open(os.path.join(d, name), "wb") as f:
                    f.write(data)
            r = subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", os.path.join(d, "key.pem"), "-signature", os.path.join(d, "note.sig"),
                    os.path.join(d, "note.bin")], capture_output=True)
        if r.returncode == 0:
            return None
    return "rekor entry checkpoint is not signed by the policy's rekor key"


def rekor_body(e):
    """The decoded canonical body of a dsse entry, or None when the entry is of another kind."""
    kv = e.get("kindVersion") or {}
    if kv.get("kind") != "dsse" or kv.get("version") != "0.0.1":
        return None
    body = strict_json(b64d(e["canonicalizedBody"]))
    return body if body.get("kind") == "dsse" and body.get("apiVersion") == "0.0.1" else None


def check_rekor_entry(pol, e, body, sig, key_der):
    """None when the entry is good, else the reason it is not: the log's signed timestamp verifies against the policy's
    Rekor key, the entry
    names that log, and its one signature is this record's signature made by the manifest's KMS key (key_der)."""
    try:
        fields = rekor_entry_fields(e)
    except (ValueError, KeyError, TypeError) as ex:
        return "rekor entry is malformed (%s)" % ex
    rekor_pem = pol["rekor_public_key"]
    if not set_is_valid(e, rekor_pem):
        return "rekor entry: the signed entry timestamp does not verify against the policy's rekor key"
    rekor_der = public_key_der(rekor_pem)
    if rekor_der is None or fields["logID"] != hashlib.sha256(rekor_der).hexdigest():
        return "rekor entry names another log (log id is not the policy's rekor key)"
    why = check_inclusion(e, rekor_pem)
    if why:
        return why
    signatures = body["spec"].get("signatures") or []
    if len(signatures) != 1 or signatures[0].get("signature") != b64e(sig):
        return "rekor entry body is for another signature than this record's"
    try:
        verifier_pem = b64d(signatures[0]["verifier"]).decode()
        # one key block, nothing around it
        verifier_der = public_key_der(verifier_pem) if ONE_PUBLIC_KEY_PEM.fullmatch(verifier_pem) else None
    except Exception:
        verifier_der = None
    if verifier_der is None:
        return "rekor entry body has no usable public key (verifier)"
    if verifier_der != key_der:
        return "rekor entry body is for another key than the manifest's release key"
    return None


def read_rekor_entries(stage, rekor_path):
    """The `entries` list of a Rekor entries file. Anything but a list of objects is a refusal, never a traceback."""
    try:
        with open(rekor_path, "rb") as f:
            entries = strict_json(f.read())["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        refuse(stage, "rekor entries file is missing or not JSON")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        refuse(stage, "rekor entries file: entries is not a list of entry objects")
    return entries


def check_rekor(pol, stage, rekor_path, payload, sig, key_der):
    """Release refuses a signature without its Rekor entry: some entry in the file must bind this payload's hash and
    pass check_rekor_entry."""
    if not rekor_path:
        refuse(stage, "rekor entry required for this record type but no Rekor entries file was given")
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
            why = check_rekor_entry(pol, e, body, sig, key_der)
        except Exception:
            why = "rekor entry is malformed"
        if why is None:
            return
        first = first or why
    refuse(stage, first)


class RekorDown(Exception):
    """Raised by a fetch when Rekor did not answer: the one failure that is worth a wait and another try."""


def rekor_with_retry(fetch, sleep, stage="release"):
    """Ask Rekor for the entries with `fetch`: one try, then up to six retries after waits of 1, 2, 4, 8, 16 and 32
    seconds. A refusal raised by `fetch` is final and is not retried. Rekor still down after the last wait: the run
    fails closed with one line naming Rekor, and a re-run continues. `sleep` is passed in so a test waits for nothing."""
    for wait in REKOR_WAITS + (None,):
        try:
            return fetch()
        except Refuse:
            raise
        except Exception:
            if wait is None:
                refuse(stage, "rekor did not answer after one try and six retries (63 seconds): the run stops here, "
                              "run it again when Rekor is back")
            sleep(wait)


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
def rekor_entries_path(record, given):
    """The Rekor entries file of a record: the one named, else <record>.rekor.json beside it (Release lays them out so:
    provenance.json and
    provenance.rekor.json). Whether this record needs one is verify_record's decision; a file that is not there is a
    refusal there."""
    if given:
        return given
    base = record[:-len(".json")] if record.endswith(".json") else record
    return base + ".rekor.json"


def cmd_verify(a):
    pol = load_json(a.policy, "policy")
    with tempfile.TemporaryDirectory() as tmp:
        verify_record(pol, a.stage, a.record, tmp,
                      rekor_path=rekor_entries_path(a.record, getattr(a, "rekor_entries", None)))
    print("ok")


# the stage that may start from each earlier stage's record (rule 58: each stage verifies the one before it)
STARTS_FROM = {"rebuild": ("build",), "check": ("build",), "sign": ("build",), "release": ("build", "sign", "rebuild", "check")}


def cmd_stage_start(a):
    if a.previous not in STARTS_FROM.get(a.stage, ()):
        refuse(a.previous, "stage %s does not start from the %s stage's record (stage)" % (a.stage, a.previous))
    chain_items.check_digest_names(a.previous, a.digests)
    pol = load_json(a.policy, "policy")
    if pol.get("dry_run"):
        refuse(a.previous, "the policy is a dry-run policy (dry): no stage may start from it")
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
        d_obj = strict_json(d_bytes)
    except (OSError, ValueError):
        refuse(a.previous, "digest file is missing or not JSON")
    with tempfile.TemporaryDirectory() as tmp:
        stmt, payload, dsse = verify_record(pol, a.previous, a.record, tmp,
                                            rekor_path=rekor_entries_path(a.record, getattr(a, "rekor_entries", None)))
    if dsse["payloadType"] == POLT:
        refuse(a.previous, "predicate: a signed release policy is not a record a stage starts from")
    parse_digest_bytes(d_bytes, a.previous)   # the same format check Sign applies (Codex security r2), before any comparison
    digest_compare(a.previous, stmt, d_bytes, d_obj)
    print("ok")


# ---- Release's two refuse-only bindings (PR 4; advisor read-back verifier-bindings) -------------------------------------------------------
# Both are new commands run by Release's first witnessed step only. They add refusals and change no existing subcommand, pin or message.
CHECK_RECORDS = ("scanners", "acceptance", "runtime", "arm64")        # the four Check records, by step name (REQ-CHAIN-007-AC16)
MATERIAL = "https://witness.dev/attestations/material/v0.1/file:witness-build/digests.json"
ITEMS_PRODUCT = "https://witness.dev/attestations/product/v0.1/file:items.json"


def _sha256_bytes_of(path, stage, what):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        refuse(stage, "%s is missing or unreadable" % what)


def _release_policy(a, stage):
    pol = load_json(a.policy, "policy")
    if pol.get("dry_run"):
        refuse(stage, "the policy is a dry-run policy (dry): Release verifies nothing against it")
    return pol


def cmd_bind_items(a):
    """items.json is a product of Build's VERIFIED record with the same sha256: its children, locks and SBOMs are then not a side channel."""
    pol = _release_policy(a, "build")
    product = (a.product if "product" in a else None) or "items.json"      # REQ-CHAIN-007-AC19: a second product of Build's record, admission-baseline.json, is bound the same way
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", product):
        refuse("build", "product: %r is not a plain file name" % product)
    want = ITEMS_PRODUCT if product == "items.json" else "https://witness.dev/attestations/product/v0.1/file:" + product
    have = _sha256_bytes_of(a.items, "build", product)
    with tempfile.TemporaryDirectory() as tmp:
        stmt, _payload, dsse = verify_record(pol, "build", a.record, tmp)
    if dsse["payloadType"] == POLT:
        refuse("build", "predicate: a signed release policy is not Build's record")
    hits = [s for s in typed_subjects("build", stmt) if s["name"] == want]
    if len(hits) != 1:
        refuse("build", "%s: Build's record holds %d product subjects named file:%s, exactly one is required" % (product, len(hits), product))
    if hits[0]["digest"].get("sha256") != have:
        refuse("build", "digest: %s is not the file Build's record holds" % product)
    print("ok")


BIND_CHECK_PRODUCT = re.compile(r"check-results/[A-Za-z0-9][A-Za-z0-9._-]*")
PRODUCT_PREFIX = "https://witness.dev/attestations/product/v0.1/file:"


def cmd_bind_check(a):
    """A file of Check's artifact check-results (govulncheck.json, advisor ruling G) is a PRODUCT of Check's scanners record with the same sha256: the record is
    verified under Check's identity at the tag, is the record of the step scanners, and names Build's verified digest list as its material (rule 55: results tied to
    the exact digests). A missing, duplicated, material-named or different product, or a record of another step, is refused."""
    pol = _release_policy(a, "check")
    if not BIND_CHECK_PRODUCT.fullmatch(a.product):
        refuse("check", "product: %r is not a plain file of check-results/" % a.product)
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
    except OSError:
        refuse("check", "the digest list is missing or unreadable")
    chain_items.check_digest_bytes("check", d_bytes)
    parse_digest_bytes(d_bytes, "check")
    want = hashlib.sha256(d_bytes).hexdigest()
    have = _sha256_bytes_of(a.file, "check", a.product)
    with tempfile.TemporaryDirectory() as tmp:
        stmt, _payload, dsse = verify_record(pol, "check", a.record, tmp)
    if dsse["payloadType"] == POLT:
        refuse("check", "predicate: a signed release policy is not Check's record")
    step = (stmt.get("predicate") or {}).get("name") if isinstance(stmt.get("predicate"), dict) else None
    if step != "scanners":
        refuse("check", "the record is the record of step %r, not scanners (a product is bound only to the record of the step that made it)" % step)
    mats = [x for x in typed_subjects("check", stmt) if x["name"] == MATERIAL]
    if len(mats) != 1:
        refuse("check", "digests: the scanners record names %d material subjects file:witness-build/digests.json, exactly one is required" % len(mats))
    if mats[0]["digest"].get("sha256") != want:
        refuse("check", "digest: the scanners record is about another digests list than the one Build attested")
    hits = [x for x in typed_subjects("check", stmt) if x["name"] == PRODUCT_PREFIX + a.product]
    if len(hits) != 1:
        refuse("check", "%s: Check's scanners record holds %d product subjects named file:%s, exactly one is required" % (a.product, len(hits), a.product))
    if hits[0]["digest"].get("sha256") != have:
        refuse("check", "digest: %s is not the file Check's scanners record holds" % a.product)
    print("ok")


def cmd_apk_compare(a):
    """The comparison job's result (the release stage's comparison step, run in a job with no key and no token; the owner's rule of Oct 21 2026: the signer and the builder
    never share a machine, Rebuild's apks never reach a job that holds a credential) is a small file: verdict pass and exactly the four expected pairs (amd64 and
    arm64, standard and fips) with the whole-file sha256 and the apk-tool digest of Build's apk and of Rebuild's. It is accepted only for Build's attested digests:
    each pair's Build digest is the apk-<variant>-<arch> digest Build attested in witness-build/digests.json, and Rebuild's is the same. Nothing else about the
    file is trusted: a verdict other than the word pass, another number of pairs, a repeated or unknown pair, a key that is not in the schema, or a hash that is
    not 64 lower-case hex is refused."""
    stage = "rebuild"
    try:
        with open(a.digests, "rb") as f:
            d = parse_digest_bytes(f.read(), stage)
    except OSError:
        refuse(stage, "apk-compare: the digest list is missing or unreadable")
    try:
        with open(a.file, "rb") as f:
            raw = f.read(200001)
    except OSError:
        refuse(stage, "apk-compare: %s is missing or unreadable" % a.file)
    if len(raw) > 200000:
        refuse(stage, "apk-compare: the result file is implausibly large")
    try:
        obj = strict_json(raw)
    except ValueError as ex:
        refuse(stage, "apk-compare: not UTF-8 JSON, or has a duplicate key (%s)" % ex)
    if not isinstance(obj, dict):
        refuse(stage, "apk-compare: the result is not a JSON object")
    if set(obj) != {"verdict", "pairs"}:
        refuse(stage, "apk-compare: the result's keys must be exactly verdict and pairs, got %s (an unknown key is refused)" % sorted(obj))
    if obj["verdict"] != "pass":
        refuse(stage, "apk-compare: the verdict is %r, only the word pass is accepted" % (obj["verdict"],))
    pairs = obj["pairs"]
    if not isinstance(pairs, list):
        refuse(stage, "apk-compare: pairs is not a list")
    if len(pairs) != 4:
        refuse(stage, "apk-compare: %d pairs, exactly four are required (amd64 and arm64, standard and fips)" % len(pairs))
    want_keys = {"arch", "variant", "name", "build_sha256", "rebuild_sha256", "build_digest", "rebuild_digest"}
    seen = set()
    for p in pairs:
        if not isinstance(p, dict) or set(p) != want_keys:
            refuse(stage, "apk-compare: a pair's keys must be exactly %s (an unknown key is refused)" % sorted(want_keys))
        if p["arch"] not in ("amd64", "arm64"):
            refuse(stage, "apk-compare: arch %r is neither amd64 nor arm64" % (p["arch"],))
        if p["variant"] not in ("standard", "fips"):
            refuse(stage, "apk-compare: variant %r is neither standard nor fips" % (p["variant"],))
        pat = r"fscache-[0-9][0-9A-Za-z.+_~-]*-r0\.apk" if p["variant"] == "standard" else r"fscache-fips-[0-9][0-9A-Za-z.+_~-]*-r0\.apk"
        if not isinstance(p["name"], str) or not re.fullmatch(pat, p["name"]):
            refuse(stage, "apk-compare: the name %r is not an apk Build makes for the %s variant" % (p["name"], p["variant"]))
        key = (p["arch"], p["variant"])
        if key in seen:
            refuse(stage, "apk-compare: the pair %s/%s is listed twice (and another of the four is missing)" % key)
        seen.add(key)
        for k in ("build_sha256", "rebuild_sha256"):
            if not isinstance(p[k], str) or not re.fullmatch(r"[0-9a-f]{64}", p[k]):
                refuse(stage, "apk-compare: %s of %s/%s is not a sha256 (64 lower-case hex)" % (k, p["arch"], p["variant"]))
        for k in ("build_digest", "rebuild_digest"):
            if not isinstance(p[k], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", p[k]):
                refuse(stage, "apk-compare: %s of %s/%s is not sha256:<64 lower-case hex>" % (k, p["arch"], p["variant"]))
        attested = d.get("apk-%s-%s" % (p["variant"], p["arch"]))
        if attested is None:
            refuse(stage, "apk-compare: Build attested no digest apk-%s-%s" % (p["variant"], p["arch"]))
        if p["build_digest"] != attested:
            refuse(stage, "apk-compare: the Build apk of %s/%s has digest %s, Build attested %s" % (p["arch"], p["variant"], p["build_digest"], attested))
        if p["rebuild_digest"] != p["build_digest"]:
            refuse(stage, "apk-compare: the rebuild digest of %s/%s differs from Build's (%s, %s)" % (p["arch"], p["variant"], p["rebuild_digest"], p["build_digest"]))
    print("ok")


def cmd_check_list(a):
    """Exactly the four Check records, scanners, acceptance, runtime and arm64, each verified under Check's identity at the tag and each tied by its
    material digest list to the digest list Build attested; a missing, extra, duplicated, substituted, unverifiable or wrong-job record is refused."""
    pol = _release_policy(a, "check")
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
    except OSError:
        refuse("check", "the digest list is missing or unreadable")
    chain_items.check_digest_bytes("check", d_bytes)
    parse_digest_bytes(d_bytes, "check")
    want = hashlib.sha256(d_bytes).hexdigest()
    try:
        names = sorted(os.listdir(a.dir))
    except OSError:
        refuse("check", "missing: the Check records directory %s is unreadable" % a.dir)
    expected = ["witness-" + n for n in CHECK_RECORDS]
    for n in names:
        if n not in expected:
            refuse("check", "extra: %s is not one of the four Check records (%s)" % (n, ", ".join(CHECK_RECORDS)))
    for n in CHECK_RECORDS:
        d = os.path.join(a.dir, "witness-" + n)
        if os.path.islink(d) or not os.path.isdir(d):
            refuse("check", "missing: the %s record (witness-%s/%s-collection.json)" % (n, n, n))
        inside = sorted(os.listdir(d))
        record, entries = "%s-collection.json" % n, "%s-collection.rekor.json" % n      # a record and, beside it, its Rekor entries file (nothing else)
        if record not in inside:
            refuse("check", "missing: the %s record (witness-%s/%s)" % (n, n, record))
        stray = [x for x in inside if x not in (record, entries)]
        if stray:
            refuse("check", "extra: witness-%s holds %s besides its record and its Rekor entries file" % (n, ", ".join(stray)))
        for x in (record, entries):
            if x in inside and os.path.islink(os.path.join(d, x)):
                refuse("check", "the %s %s is a symlink" % (n, "record" if x == record else "Rekor entries file"))
    seen = set()
    for n in CHECK_RECORDS:
        path = os.path.join(a.dir, "witness-" + n, "%s-collection.json" % n)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                stmt, _payload, dsse = verify_record(pol, "check", path, tmp)
        except Refuse as r:
            refuse("check", "the %s record: %s" % (n, r.reason))
        if dsse["payloadType"] == POLT:
            refuse("check", "predicate: the %s record is a signed release policy" % n)
        step = (stmt.get("predicate") or {}).get("name") if isinstance(stmt.get("predicate"), dict) else None
        if step != n:
            refuse("check", "the %s record is the record of step %r (a record is accepted only in the slot of its own step)" % (n, step))
        mats = [s for s in typed_subjects("check", stmt) if s["name"] == MATERIAL]
        if len(mats) != 1:
            refuse("check", "digests: the %s record names %d material subjects file:witness-build/digests.json, exactly one is required" % (n, len(mats)))
        if mats[0]["digest"].get("sha256") != want:
            refuse("check", "digest: the %s record is about another digest list than the one Build attested" % n)
        h = _sha256_bytes_of(path, "check", n)
        if h in seen:
            refuse("check", "the %s record is a duplicate of another record" % n)
        seen.add(h)
    print("ok")


# ---- rc-proof (REQ-CHAIN-001-AC6, advisor Oct 12): the rc run's records, verified under the rc tag's identities, against the committed marker -------------------
# Run by the pull request that writes .github/policy/rc-proof.json, on the records the rc run uploaded (laid out as Release's own step finds them). It adds no new
# trust: every record goes through the verifiers Release itself runs (stage-start, bind-items, check-list) under the policy made for the marker's rc tag, the
# hostile verdict through hostile-verdict, and the marker's digests are compared with the sha256 of each record file.
RC_RECORDS = (
    ("build", "witness-build/build-collection.json"),
    ("sign", "provenance/provenance.json"),
    ("rekor", "provenance/provenance.rekor.json"),
    ("rebuild", "witness-rebuild/rebuild-collection.json"),
    ("scanners", "witness-check/witness-scanners/scanners-collection.json"),
    ("acceptance", "witness-check/witness-acceptance/acceptance-collection.json"),
    ("runtime", "witness-check/witness-runtime/runtime-collection.json"),
    ("arm64", "witness-check/witness-arm64/arm64-collection.json"),
    ("hostile_verdict", "hostile-results/hostile-results.json"),
)


def cmd_rc_proof(a):
    import contextlib
    import io
    bs = load_sibling("chain-bytes-sha")      # loaded here only: Sign's own run of this file never needs the marker helper
    try:
        marker = bs.check_marker(a.marker, a.commit, a.repo)
    except bs.Refusal as r:
        refuse("marker", str(r))
    rec = lambda rel: os.path.join(a.records, rel)
    with tempfile.TemporaryDirectory() as tmp:
        pol_path = os.path.join(tmp, "policy.json")
        ns = argparse.Namespace(template=a.template, tag=marker["rc_tag"], ref=None, out=pol_path)
        policy_make(ns)
        quiet = io.StringIO()
        with contextlib.redirect_stdout(quiet):
            digests = rec("witness-build/digests.json")
            cmd_stage_start(argparse.Namespace(stage="release", previous="build", record=rec("witness-build/build-collection.json"),
                                               digests=digests, policy=pol_path))
            cmd_bind_items(argparse.Namespace(policy=pol_path, record=rec("witness-build/build-collection.json"),
                                              items=rec("witness-build/items.json")))
            # Build's record names the tag through its signed admission-baseline.json product (`tag`): the baseline is
            # bound to the record like items.json, and
            # its tag must be the marker's rc tag, so a Build record made in the run for another tag (the final one) is
            # refused here
            cmd_bind_items(argparse.Namespace(policy=pol_path, record=rec("witness-build/build-collection.json"),
                                              items=rec("witness-build/admission-baseline.json"),
                                              product="admission-baseline.json"))
            cmd_stage_start(argparse.Namespace(stage="release", previous="sign", record=rec("provenance/provenance.json"), digests=digests,
                                               policy=pol_path))
            cmd_stage_start(argparse.Namespace(stage="release", previous="rebuild", record=rec("witness-rebuild/rebuild-collection.json"),
                                               digests=digests, policy=pol_path))
            cmd_check_list(argparse.Namespace(policy=pol_path, digests=digests, dir=rec("witness-check")))
        # the marker's run id is the run Sign's provenance came from: the statement (verified above under the rc tag's Sign identity) names its run as
        # invocationId, and that must be exactly this repository's URL for exactly this run (not a prefix, not another repository)
        baseline = load_json(rec("witness-build/admission-baseline.json"), "admission baseline")
        if not isinstance(baseline, dict) or baseline.get("tag") != marker["rc_tag"]:
            baseline_tag = baseline.get("tag") if isinstance(baseline, dict) else None
            refuse("build", "tag: Build's admission baseline is for %s, the marker's rc tag is %s"
                   % (json.dumps(baseline_tag), marker["rc_tag"]))
        pol = load_json(pol_path, "policy")
        with tempfile.TemporaryDirectory() as tmp2:
            pstmt, _pp, _pd = verify_record(pol, "sign", rec("provenance/provenance.json"), tmp2,
                                            rekor_path=rec("provenance/provenance.rekor.json"))
        inv = (((pstmt.get("predicate") or {}).get("runDetails") or {}).get("metadata") or {}).get("invocationId")
        want_run = "https://github.com/%s/actions/runs/%s" % (a.repository, marker["run_id"])
        if inv != want_run:
            refuse("marker", "run: the marker names run %s of the repository %s but Sign's provenance names the run %r" % (marker["run_id"], a.repository, inv))
        # the commit the provenance was built from is the rc tag's commit as the repository holds it now: a moved or recreated tag cannot borrow the run of its earlier commit
        deps = (((pstmt.get("predicate") or {}).get("buildDefinition") or {}).get("resolvedDependencies"))
        srcs = [(d.get("digest") or {}).get("gitCommit") for d in deps if isinstance(d, dict)] if isinstance(deps, list) else []
        if srcs != [marker["rc_commit"]]:
            refuse("marker", "built: Sign's provenance names the built commit(s) %r but the rc tag %s is at %s" % (srcs, marker["rc_tag"], marker["rc_commit"]))
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(quiet):
                chain_hostile.cmd_hostile_verdict(argparse.Namespace(results=rec("hostile-results/hostile-results.json")))
        except SystemExit as ex:
            if ex.code not in (0, None):
                refuse("hostile", "the hostile verdict of the rc run is not green: %s" % " ".join(err.getvalue().split())[:400])
    for name, rel in RC_RECORDS:
        have = _sha256_bytes_of(rec(rel), "marker", "the %s record %s" % (name, rel))
        if have != marker["records"][name]:
            refuse("marker", "digest: the %s record %s is not the file the marker names (sha256 %s, marker %s)" % (name, rel, have, marker["records"][name]))
    print("ok")


def make_policy_from_template(a, tpl_path):
    ref = os.environ.get("GITHUB_REF", "")
    ev = os.environ.get("GITHUB_EVENT_NAME", "")
    is_tag = re.fullmatch(r"refs/tags/%s" % TAG_GRAMMAR, ref)
    is_branch = ref.startswith("refs/heads/") and len(ref) > len("refs/heads/")
    if is_tag and ev == "workflow_dispatch":
        refuse("sign", "a workflow_dispatch on the tag %s is not a production run: production tags come from a push (tag)" % ref)
    if not (is_tag and ev == "push") and not (is_branch and ev == "workflow_dispatch"):
        refuse("sign", "GITHUB_REF %r (event %r) is neither a pushed refs/tags/vX.Y.Z[-rcN] nor a workflow_dispatch on a branch (tag)" % (ref, ev))
    out = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    out.close()
    ns = argparse.Namespace(template=tpl_path, tag=None, ref=ref, out=out.name)
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
    if "release_key" not in pol:
        refuse("sign", "--policy must be a finished policy; a template goes to --template")
    try:
        with open(a.digests, "rb") as f:
            d_bytes = f.read()
    except OSError:
        refuse("sign", "digest file is missing or unreadable (format)")
    chain_items.check_digest_bytes("build", d_bytes)       # a snapshot version in the list: refused before any signature check, from the bytes read once (REQ-CHAIN-004-AC15)
    # Build's record first, as stage build, under the policy's build identity (a dry-run policy is allowed for this)
    pol_b = dict(pol)
    pol_b.pop("dry_run", None)
    with tempfile.TemporaryDirectory() as tmp:
        stmt, payload, dsse = verify_record(pol_b, "build", a.build_record, tmp)
    if product_digest(typed_subjects("sign", stmt)) != hashlib.sha256(d_bytes).hexdigest():
        refuse("sign", "digest list differs from the digests Build attested (its digest does not match the record's product subject)")
    return pol, parse_digest_bytes(d_bytes)


def cmd_check_build_record(a):
    check_build_record(a)
    print("ok")


# the KMS key, named by its alias and never by an ARN, a token or a file (ruling of Oct 28)
RELEASE_KEY_REF = "awskms:///alias/fosterstack-release-signing"


def provenance_statement(pol, obj, dry):
    """The SLSA v1 provenance Sign signs: what was built (the digests), from which commit and run (GitHub's own variables)."""
    repo, ref = pol["repository"], pol.get("ref", "")
    site = "https://github.com/" + repo
    run_url = "%s/%s/actions/runs/%s" % (os.environ.get("GITHUB_SERVER_URL", "https://github.com"), repo, os.environ.get("GITHUB_RUN_ID", "0"))
    commit = os.environ.get("GITHUB_SHA", "")
    # the calling workflow is the one GitHub names for this run, and it must be release.yml at the policy's ref: Sign
    # writes what it was
    # told, never a constant, so a run of another workflow (or of release.yml at another ref) cannot produce a
    # provenance that passes
    caller = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if caller != "%s/.github/workflows/release.yml@%s" % (repo, ref):
        refuse("sign", "workflow: GITHUB_WORKFLOW_REF (%s) is not %s/.github/workflows/release.yml@%s"
                       % (json.dumps(caller), repo, ref))
    statement = {
        "_type": "https://in-toto.io/Statement/v1", "predicateType": PROV,
        "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1]}} for k, v in sorted(obj.items())],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/%s/release-chain/v0.3.0" % repo,
                "externalParameters": {"ref": ref, "workflow": "https://github.com/" + caller},
                "internalParameters": {},
                "resolvedDependencies": [{"uri": "git+https://github.com/%s@%s" % (repo, ref), "digest": {"gitCommit": commit}}],
            },
            "runDetails": {"builder": {"id": "%s/.github/workflows/stage-sign.yml@%s" % (site, ref)},
                           "metadata": {"invocationId": run_url}},
        },
    }
    if dry:
        statement["predicate"]["dryRun"] = True
    return statement


def bundle_to_outputs(bun, out_dir, name="provenance", expect_payload=None):
    """Turn the bundle cosign wrote into the two files Release verifies: its DSSE envelope, one signature {keyid, sig}
    (<name>.json), and the bundle's own Rekor entries, untouched (<name>.rekor.json). The bundle must hold a DSSE
    envelope and no certificate (a key signed it; nothing here is keyless). With `expect_payload`, the payload it signed
    must be byte-equal to those bytes."""
    try:
        vm = bun["verificationMaterial"]
        if not isinstance(vm, dict):
            raise TypeError("verificationMaterial")
        if "certificate" in vm or "x509CertificateChain" in vm:
            refuse("sign", "the bundle cosign wrote carries a certificate: no certificate belongs to this chain")
        dsse = bun["dsseEnvelope"]
        sigs = dsse["signatures"]
        if not isinstance(sigs, list) or len(sigs) != 1:
            refuse("sign", "the bundle cosign wrote holds %s signatures, not exactly one: a second signature would be "
                           "dropped unseen" % (len(sigs) if isinstance(sigs, list) else "no list of"))
        sig = sigs[0]
        envelope = {"payloadType": dsse["payloadType"], "payload": dsse["payload"],
                    "signatures": [{"keyid": sig.get("keyid", ""), "sig": sig["sig"]}]}
        if expect_payload is not None and b64d(dsse["payload"]) != expect_payload:
            refuse("sign", "the bundle cosign wrote signed another payload than the statement handed to it")
        tlog = vm.get("tlogEntries")
        if not isinstance(tlog, list) or not tlog:
            refuse("sign", "the bundle cosign wrote has no Rekor entry (verificationMaterial.tlogEntries is missing or "
                           "empty): Release refuses a signature without one")
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as ex:
        # a malformed bundle is a refusal, never a traceback (property e); the field named is the one that was missing or wrong
        refuse("sign", "the bundle cosign wrote is malformed: envelope field %s (%s)" % (ex, type(ex).__name__))
    with open(os.path.join(out_dir, name + ".json"), "w") as f:
        json.dump(envelope, f)
    with open(os.path.join(out_dir, name + ".rekor.json"), "w") as f:
        json.dump({"entries": tlog}, f)



# One plain string decides whether a cosign failure is Rekor's (worth the retries): the word "rekor" in its error text. It matches
# `error: creating log entry: rekor: 503 Service Unavailable`; it refuses `AccessDeniedException: not authorized to perform kms:Sign`
# (a KMS or argument error is refused at once, with no second signature asked of KMS). UNVERIFIED against a real cosign v3.1.3 outage.
REKOR_WORD = b"rekor"


def kms_sign(statement_path, out_record, signing_config, run=subprocess.run, sleep=time.sleep, bundle_path=None):
    """The one signing function of the release chain: sign the statement in `statement_path` with the release key held in
    AWS KMS through `cosign attest-blob --key`, keep its Rekor entry, and write `out_record` (a DSSE envelope with exactly
    one signature) and the entries file beside it (<out_record minus .json>.rekor.json). One try and six retries while
    Rekor does not answer (waits 1, 2, 4, 8, 16, 32 seconds); any other failure, a bundle that signed another payload than
    the staged one, a bundle with no Rekor entry or with more than one signature is a refusal, and no record is left.
    `bundle_path` keeps cosign's bundle at that path (Sign publishes it); without it the bundle is a temporary file.
    `run` and `sleep` are arguments so a test passes a fake cosign and a clock that waits for nothing."""
    out_record = os.path.abspath(out_record)
    if os.path.lexists(out_record):
        refuse("sign", "the record %s exists: a signed record is never overwritten" % os.path.basename(out_record))
    out_dir, base = os.path.split(out_record)
    stem = base[:-len(".json")] if base.endswith(".json") else base
    with open(statement_path, "rb") as f:
        statement = f.read()
    with tempfile.TemporaryDirectory() as tmp:
        bundle = bundle_path or os.path.join(tmp, "record.bundle.json")

        def fetch():
            argv = ["cosign", "attest-blob", "--yes", "--key", RELEASE_KEY_REF, "--signing-config", signing_config,
                    "--statement", statement_path, "--bundle", bundle]
            try:
                r = run(argv, capture_output=True)
            except OSError as ex:
                refuse("sign", "cosign not found on PATH" if isinstance(ex, FileNotFoundError)
                       else "cosign could not be started (%s)" % type(ex).__name__)
            if r.returncode != 0:
                if REKOR_WORD in (r.stderr or b"").lower():
                    raise RekorDown(r.stderr[:200])
                refuse("sign", "cosign failed: %s" % (r.stderr or b"").decode(errors="replace")[:200])
            try:
                with open(bundle, "rb") as f:
                    return strict_json(f.read())
            except (OSError, ValueError):
                refuse("sign", "the bundle cosign wrote is missing or not JSON")

        bun = rekor_with_retry(fetch, sleep, "sign")
        bundle_to_outputs(bun, tmp, stem, expect_payload=statement)
        os.makedirs(out_dir, exist_ok=True)
        entries = os.path.join(out_dir, stem + ".rekor.json")
        shutil.copyfile(os.path.join(tmp, stem + ".json"), out_record)
        shutil.copyfile(os.path.join(tmp, stem + ".rekor.json"), entries)


def cmd_sign_record(a):
    """Sign one staged Witness payload with the release key (the one signing function), write the record and its entries."""
    signing_config = os.path.join(os.path.dirname(os.path.abspath(a.template)), "cosign-signing-config.json")
    kms_sign(a.payload, a.out, signing_config)

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
    # rc-2 R1a: GITHUB_SHA and GITHUB_RUN_ID are written into the signed provenance, so Sign refuses (before cosign is asked, before an output folder is made) a commit that is not 40 lowercase hex and a run id that is not a number, rather than signing the defaults "" and "0"
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("GITHUB_SHA", "")):
        refuse("sign", "provenance: GITHUB_SHA is not a 40-hex commit")
    if not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")):
        refuse("sign", "provenance: GITHUB_RUN_ID is not a run number (digits)")
    signing_config = os.path.join(os.path.dirname(os.path.abspath(a.template or a.policy)), "cosign-signing-config.json")
    with tempfile.TemporaryDirectory() as tmpd:
        sp = os.path.join(tmpd, "statement.json")
        statement = provenance_statement(pol, obj, dry)
        with open(sp, "w") as f:
            json.dump(statement, f, sort_keys=True)
        make_out(a.out)
        bundle = os.path.join(os.path.abspath(a.out), "provenance.bundle.json")
        try:
            kms_sign(sp, os.path.join(os.path.abspath(a.out), "provenance.json"), signing_config, bundle_path=bundle)
            verify_own_output(a.out, pol, statement, tmpd)
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


# ---- sign-records (the Witness move; owner Oct 22): Sign's check-and-stage step for the building jobs' local records ---------------------------------------
# Build and Rebuild record under Witness with a throwaway key inside their jobs; those records are UNTRUSTED. This step is the check that comes before Sign re-signs the
# payloads with the release key: it signs nothing, calls no tool and reads no token. A shell step of the Sign job signs each
# staged payload and `verify` checks the result.
SR_STEPS = {"build": ("apk", "build"), "rebuild": ("rapk", "rebuild"), "check": ("scanners", "acceptance", "runtime", "arm64")}
SR_CHECK_FOLDER = {"witness-scanners": "scanners", "witness-acceptance": "acceptance", "witness-runtime": "runtime", "witness-arm64": "arm64"}     # Check's four record folders, each named for its one step
SR_CHECK_GROUPS = (("check-results", ("witness-scanners", "witness-acceptance", "witness-runtime")), ("check-results-arm64", ("witness-arm64",)))     # (artifact folder under --artifacts-dir, the records whose products it carries)
SR_CHECK_PREFIX = "check-results/"
SR_DATA = ("digests.json", "items.json", "admission-baseline.json", "verdict.json")
SR_REQUIRED = {"build": ("digests.json", "items.json", "admission-baseline.json"), "rebuild": ("verdict.json",)}
SR_PATH = {"verdict.json": "witness-rebuild/verdict.json"}   # a data file's product name is its path from the repository root: Build's three sit at the root, Rebuild's verdict in witness-rebuild/; matched in full, never by basename
# Witness 0.12.0 writes these five attestors and no other; command-run holds what ran, its stdout and stderr and its exit code
SR_ATTESTORS = ("environment", "git", "material", "command-run", "product")
GIT_COMMIT_PREFIX = "https://witness.dev/attestations/git/v0.1/commithash:"
ATTESTOR_URI = re.compile(r"https://witness\.dev/attestations/([a-z-]+)/v0\.1")


def sr_received(stage, rec_dir, art_dir, name):
    """{relative name: sha256} of the files Sign RECEIVES for one record: the data files of the record directory and every file under art_dir/name."""
    got = {}
    for n in sorted(os.listdir(rec_dir)):
        path = os.path.join(rec_dir, n)
        if os.path.islink(path) or not os.path.isfile(path):
            refuse(stage, "record: %s/%s is not a regular file (a link or a folder in a record directory)" % (name, n))
        if n.endswith(".local.json"):
            continue
        if n not in SR_DATA:
            refuse(stage, "record: %s holds %s, which is neither the record (<step>-collection.local.json) nor a data file (%s)" % (name, n, " ".join(SR_DATA)))
        got[SR_PATH.get(n, n)] = _sha256_bytes_of(path, stage, n)
    if art_dir:
        base = os.path.join(art_dir, name)
        if os.path.lexists(base):
            links = []
            def walk_failed(ex):
                refuse(stage, "unreadable: %s (%s)" % (ex.filename, type(ex).__name__))
            for here, dirs, files in os.walk(base, onerror=walk_failed):
                for n in dirs + files:
                    if os.path.islink(os.path.join(here, n)):
                        links.append(os.path.relpath(os.path.join(here, n), base))
            if links:
                refuse(stage, "symlink: %s" % " ".join(sorted(links)))
            for here, _dirs, files in os.walk(base, onerror=walk_failed):
                for n in files:
                    rel = os.path.relpath(os.path.join(here, n), base)
                    got.setdefault(rel, _sha256_bytes_of(os.path.join(here, n), stage, rel))
                    if got[rel] != _sha256_bytes_of(os.path.join(here, n), stage, rel):
                        refuse(stage, "digest: %s differs between the record directory and the artifacts" % rel)
    return got


def sr_check_record(stage, rec_dir, name, art_dir, commit, digests_sha, ref):
    """Checks one record directory; returns (step, payload bytes, [data file names])."""
    steps = SR_STEPS[stage]
    names = sorted(os.listdir(rec_dir))
    locals_ = [n for n in names if n.endswith(".local.json")]
    if len(locals_) != 1:
        refuse(stage, "record: %s must hold exactly one *.local.json record, it holds %d" % (name, len(locals_)))
    fname = locals_[0]
    if fname.startswith("snapshot-"):
        refuse(stage, "snapshot record: %s/%s is a snapshot step's file name" % (name, fname))
    m = re.fullmatch(r"([a-z][a-z0-9]*)-collection\.local\.json", fname)
    if not m or m.group(1) not in steps:
        refuse(stage, "step: %s/%s is not a record of the %s stage (%s-collection.local.json)" % (name, fname, stage, " or ".join(steps)))
    step = m.group(1)
    for n in names:
        if stage == "check" and n != fname:
            refuse(stage, "record: %s holds %s: a Check record folder holds only its record (%s), nothing else is staged or signed" % (name, n, fname))
        if n != fname and n not in SR_DATA:
            refuse(stage, "record: %s holds %s, which is neither the record (%s) nor a data file (%s)" % (name, n, fname, " ".join(SR_DATA)))
    try:
        with open(os.path.join(rec_dir, fname), "rb") as f:
            dsse = strict_json(f.read())
        payload = b64d(dsse["payload"])
        ptype = dsse["payloadType"]
        stmt = strict_json(payload)
        pred = stmt["predicate"]
        cname, atts = pred["name"], pred["attestations"]
    except Exception as ex:
        refuse(stage, "record: %s/%s is not a DSSE envelope of a Witness collection (%s)" % (name, fname, type(ex).__name__))
    if not isinstance(dsse, dict) or ptype != DSSE_STMT:
        refuse(stage, "payloadType: %r is not %s" % (ptype, DSSE_STMT))
    if stmt.get("predicateType") != COLL or stmt.get("_type") not in STMT_TYPES:
        refuse(stage, "record: %s/%s is not an in-toto statement with the Witness collection predicate" % (name, fname))
    chain_items.check_record_names(stage, payload)             # a snapshot name or version; a collection name that is not a release name of the stage
    if cname != step:
        refuse(stage, "step: the record's collection name %r is not its file's step %r" % (cname, step))
    chain_items.check_record_env(stage, dsse, payload)         # no token variable or value (REQ-CHAIN-004-AC8)
    kinds = []
    for att in atts if isinstance(atts, list) else []:
        t = att.get("type") if isinstance(att, dict) else None
        mm = ATTESTOR_URI.fullmatch(t) if isinstance(t, str) else None
        kinds.append(mm.group(1) if mm else repr(t))
    extra, missing = sorted(set(kinds) - set(SR_ATTESTORS)), sorted(set(SR_ATTESTORS) - set(kinds))
    if extra or missing or len(kinds) != len(set(kinds)):
        refuse(stage, "attestors: exactly %s are allowed (beyond: %s; missing: %s; a repeated attestor is refused too)" % (", ".join(SR_ATTESTORS), " ".join(extra) or "none", " ".join(missing) or "none"))
    # the KMS key never signs a collection of another ref: the environment attestor's GITHUB_REF is Sign's own
    for att in atts:
        if ATTESTOR_URI.fullmatch(att["type"]).group(1) == "environment":
            ev = att.get("attestation")
            found = ((ev.get("variables") or {}).get("GITHUB_REF") if isinstance(ev, dict) else None)
            if not isinstance(found, str) or found != ref:
                refuse(stage, "ref: the ref inside %s/%s (%s) is not Sign's ref %s"
                              % (name, fname, json.dumps(found), ref))
    subs = typed_subjects(stage, stmt)
    commits = [x["name"][len(GIT_COMMIT_PREFIX):] for x in subs if x["name"].startswith(GIT_COMMIT_PREFIX)]
    if commits != [commit]:
        refuse(stage, "commit: the record's git commit %s is not the run's commit %s" % (", ".join(commits) or "(none)", commit))
    products = {}
    for x in subs:
        if x["name"].startswith(PRODUCT_PREFIX):
            products.setdefault(x["name"][len(PRODUCT_PREFIX):], []).append(x["digest"].get("sha256"))
    if step == "rapk" and art_dir and os.path.lexists(os.path.join(art_dir, name)):
        refuse(stage, "rapk: %s has artifacts under %s, but Rebuild's apks never reach Sign" % (name, art_dir))
    if stage == "check":
        if SR_CHECK_FOLDER.get(name) != step:
            refuse(stage, "record: the folder %s holds the %s record; Check's folders are %s, each named for its step" % (name, step, " ".join(sorted(SR_CHECK_FOLDER))))
        mats = [x for x in subs if x["name"] == MATERIAL]
        if len(mats) != 1 or mats[0]["digest"].get("sha256") != digests_sha:
            refuse(stage, "material: the %s record's file:witness-build/digests.json is not Build's attested digests.json (--digests)" % step)
        return step, payload, [n for n in names if n != fname], {k: v for k, v in products.items() if k.startswith(SR_CHECK_PREFIX)}
    received = sr_received(stage, rec_dir, art_dir, name)
    wrong = sorted(n for n, h in received.items() if products.get(n) != [h])
    if wrong:
        refuse(stage, "digest: a received file is not a product of the record with the same sha256, or the record names it twice: %s" % " ".join(wrong))
    if step in SR_REQUIRED:
        lacking = sorted(SR_PATH.get(n, n) for n in SR_REQUIRED[step] if SR_PATH.get(n, n) not in received or SR_PATH.get(n, n) not in products)
        if lacking:
            refuse(stage, "missing: %s must be a product of the %s record and be received: %s" % (step, step, " ".join(lacking)))
    unreceived = [] if stage != "build" else sorted(n for n in products if n.startswith(("out/", "dist/")) and n not in received)
    if unreceived:
        refuse(stage, "missing: the record names build products under out/ or dist/ that Sign did not receive: %s" % " ".join(unreceived))
    if stage == "rebuild":
        mats = [x for x in subs if x["name"] == MATERIAL]
        if len(mats) != 1 or mats[0]["digest"].get("sha256") != digests_sha:
            refuse(stage, "material: the record's file:witness-build/digests.json is not Build's attested digests.json (--digests)")
    return step, payload, [n for n in names if n != fname], {}


def sr_expected_many(stage, paths):
    """One or more lists of the records the producing jobs made (Check has two: the check job and check-arm64). The folder sets must be disjoint."""
    merged = {}
    for path in paths:
        for folder, files in sr_expected(stage, path).items():
            if folder in merged:
                refuse(stage, "expect-digests: the folder %s is listed twice (%s)" % (folder, path))
            merged[folder] = files
    return merged


def sr_expected(stage, path):
    """The list of the records the Rebuild assemble job made, as a job output: {record folder: {file: "sha256:<hex>"}}. Returns {folder: {file: hex}}."""
    try:
        with open(path, "rb") as f:
            exp = strict_json(f.read())
    except (OSError, ValueError) as ex:
        refuse(stage, "expect-digests: %s is missing or not JSON (%s)" % (path, type(ex).__name__))
    ok = isinstance(exp, dict) and bool(exp)
    for folder, files in (exp.items() if isinstance(exp, dict) else []):
        ok = ok and isinstance(files, dict) and bool(files) and all(isinstance(h, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", h) for h in files.values())
    if not ok:
        refuse(stage, "expect-digests: %s is not {record folder: {file: sha256:<64 hex>}} (non-empty)" % path)
    return {folder: {n: h[len("sha256:"):] for n, h in files.items()} for folder, files in exp.items()}


def sr_check_expected(stage, expected, rec_dirs):
    """Every record folder Sign received must be exactly what the producing job listed: same folders, same files, same sha256 (no extra, no missing)."""
    names = {os.path.basename(d.rstrip("/")) for d in rec_dirs}
    if names != set(expected):
        refuse(stage, "expect-digests: the record folders received (%s) are not the ones the Rebuild job listed (%s)" % (" ".join(sorted(names)) or "none", " ".join(sorted(expected))))
    for d in rec_dirs:
        name = os.path.basename(d.rstrip("/"))
        if not os.path.isdir(d) or os.path.islink(d):
            refuse(stage, "record: %r is not a distinct plain record directory" % d)
        have = sorted(os.listdir(d))
        if have != sorted(expected[name]):
            refuse(stage, "expect-digests: %s holds %s, the Rebuild job listed %s" % (name, " ".join(have) or "no file", " ".join(sorted(expected[name]))))
        for n in have:
            path = os.path.join(d, n)
            if os.path.islink(path) or not os.path.isfile(path):
                refuse(stage, "record: %s/%s is not a regular file (a link or a folder in a record directory)" % (name, n))
            if _sha256_bytes_of(path, stage, n) != expected[name][n]:
                refuse(stage, "expect-digests: %s/%s is not the file the Rebuild job made (sha256 differs)" % (name, n))


def sr_check_results(stage, art_dir, products):
    """Check's results: each record folder group has its artifact folder under --artifacts-dir (check-results for scanners, acceptance and runtime; check-results-arm64 for arm64). Every
    file received must be a product `check-results/<path>` of exactly one record of its group with the same sha256, and every such product the records name must be received; products
    elsewhere in the repository (a log in a scratch folder) are not Sign's concern, as for Build."""
    if not art_dir:
        refuse(stage, "artifacts: --artifacts-dir is required for the check stage (the check-results artifacts)")
    for art, folders in SR_CHECK_GROUPS:
        base = os.path.join(art_dir, art)
        if not os.path.isdir(base) or os.path.islink(base):
            refuse(stage, "artifacts: %s is missing or not a plain folder under %s" % (art, art_dir))
        def walk_failed(ex):
            refuse(stage, "unreadable: %s (%s)" % (ex.filename, type(ex).__name__))
        links, got = [], {}
        for here, dirs, files in os.walk(base, onerror=walk_failed):
            for n in dirs + files:
                if os.path.islink(os.path.join(here, n)):
                    links.append(os.path.relpath(os.path.join(here, n), base))
        if links:
            refuse(stage, "symlink: %s" % " ".join(sorted(links)))
        for here, _dirs, files in os.walk(base, onerror=walk_failed):
            for n in files:
                full = os.path.join(here, n)
                got[SR_CHECK_PREFIX + os.path.relpath(full, base)] = _sha256_bytes_of(full, stage, n)
        named = {}
        for f in folders:
            for pn, hs in products[f].items():
                if pn in named or len(hs) != 1:
                    refuse(stage, "digest: the product %s is named twice in the records of %s" % (pn, art))
                named[pn] = hs[0]
        wrong = sorted(n for n, h in got.items() if named.get(n) != h)
        if wrong:
            refuse(stage, "digest: a received file of %s is not a product of its records with the same sha256: %s" % (art, " ".join(wrong)))
        lacking = sorted(n for n in named if n not in got)
        if lacking:
            refuse(stage, "missing: the records of %s name products that were not received: %s" % (art, " ".join(lacking)))


def cmd_sign_records(a):
    stage = a.stage
    require_fresh_out(a.out)
    make_policy_from_template(a, a.template)                    # the same policy gate as `sign --check`: a pushed tag, or a workflow_dispatch on a branch (the dry run)
    commit = os.environ.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        refuse(stage, "commit: GITHUB_SHA is not a 40-hex commit")
    digests_sha = _sha256_bytes_of(a.digests, stage, "--digests")
    if stage in ("rebuild", "check") and not a.expect_digests:
        refuse(stage, "expect-digests: --expect-digests FILE is required for the %s stage (the producing job's list of the records it made)" % stage)
    if stage == "rebuild" and len(a.expect_digests) != 1:
        refuse(stage, "expect-digests: the rebuild stage takes exactly one list")
    if stage in ("rebuild", "check"):
        sr_check_expected(stage, sr_expected_many(stage, a.expect_digests), a.record_dir)   # before any record is read: a folder that is not what the Rebuild job made is never parsed
    seen, plan, check_products = set(), [], {}
    for rec_dir in a.record_dir:
        name = os.path.basename(rec_dir.rstrip("/"))
        if name in seen or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or not os.path.isdir(rec_dir) or os.path.islink(rec_dir):
            refuse(stage, "record: %r is not a distinct plain record directory" % rec_dir)
        seen.add(name)
        step, payload, data, prods = sr_check_record(stage, rec_dir, name, a.artifacts_dir, commit, digests_sha,
                                                     os.environ.get("GITHUB_REF", ""))
        plan.append((rec_dir, name, step, payload, data))
        check_products[name] = prods
    if stage == "check":
        if sorted(seen) != sorted(SR_CHECK_FOLDER):
            refuse(stage, "record: Check's records are exactly %s, got %s" % (" ".join(sorted(SR_CHECK_FOLDER)), " ".join(sorted(seen))))
        sr_check_results(stage, a.artifacts_dir, check_products)
    make_out(a.out)
    try:
        lines = []
        for rec_dir, name, step, payload, data in plan:
            os.mkdir(os.path.join(a.out, name))
            with open(os.path.join(a.out, name, step + "-collection.payload"), "wb") as f:
                f.write(payload)
            for n in data:
                with open(os.path.join(rec_dir, n), "rb") as src, open(os.path.join(a.out, name, n), "wb") as dst:
                    dst.write(src.read())
            lines.append("%s\t%s" % (os.path.join(a.out, name, step + "-collection.payload"), "signed/%s/%s-collection.json" % (name, step)))
        with open(os.path.join(a.out, "plan.txt"), "w") as f:      # the list the signing step reads: it signs exactly these payloads and refuses any other
            f.write("\n".join(lines) + "\n")
    except OSError as ex:
        shutil.rmtree(a.out, ignore_errors=True)
        refuse(stage, "staging: cannot write %s (%s)" % (a.out, type(ex).__name__))
    print("\n".join(lines))


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


def verify_own_output(out_dir, pol, statement, tmpd):
    """Verify what the one signing function wrote as stage sign exactly as Release will, and require that the payload cosign signed
    IS the statement Sign built, before Sign says ok (REQ-CHAIN-001-AC2, 002-AC1, 002-AC3): Sign never reports success for
    provenance Release would refuse, nor for a statement it did not make."""
    vdir = os.path.join(tmpd, "verify-own-output")
    os.makedirs(vdir)
    signed, _payload, _dsse = verify_record(pol, "sign", os.path.join(out_dir, "provenance.json"), vdir,
                                            rekor_path=os.path.join(out_dir, "provenance.rekor.json"))
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
    m.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--policy", required=True)
    v.add_argument("--stage", required=True)
    v.add_argument("--record", required=True)
    # the Rekor entries file of a provenance or a release policy (provenance.rekor.json)
    v.add_argument("--rekor-stub", dest="rekor_entries")
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
    sg = sub.add_parser("sign-record")
    sg.add_argument("--payload", required=True)      # the staged statement, signed byte for byte
    sg.add_argument("--out", required=True)          # the record to write; its Rekor entries file is written beside it
    sg.add_argument("--template", required=True)     # the release policy template: the signing config sits beside it
    sr = sub.add_parser("sign-records")
    sr.add_argument("--stage", required=True, choices=sorted(SR_STEPS))
    sr.add_argument("--template", required=True)
    sr.add_argument("--digests", required=True)
    sr.add_argument("--out", required=True)
    sr.add_argument("--record-dir", action="append", required=True)
    sr.add_argument("--artifacts-dir")
    sr.add_argument("--expect-digests", action="append")
    st = sub.add_parser("stage-start")
    st.add_argument("--stage", required=True)
    st.add_argument("--previous", required=True)
    st.add_argument("--record", required=True)
    # the previous stage's Rekor entries file, when its record is a provenance
    st.add_argument("--rekor-stub", dest="rekor_entries")
    st.add_argument("--digests", required=True)
    st.add_argument("--policy", required=True)
    bi = sub.add_parser("bind-items")
    bi.add_argument("--policy", required=True)
    bi.add_argument("--record", required=True)
    bi.add_argument("--items", required=True)
    bi.add_argument("--product")
    bc = sub.add_parser("bind-check")
    bc.add_argument("--policy", required=True)
    bc.add_argument("--record", required=True)
    bc.add_argument("--digests", required=True)
    bc.add_argument("--file", required=True)
    bc.add_argument("--product", required=True)
    ap = sub.add_parser("apk-compare")
    ap.add_argument("--file", required=True)
    ap.add_argument("--digests", required=True)
    cl = sub.add_parser("check-list")
    cl.add_argument("--policy", required=True)
    cl.add_argument("--digests", required=True)
    cl.add_argument("--dir", required=True)
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
    hm.add_argument("--policy")
    hv = sub.add_parser("hostile-verdict")
    hv.add_argument("results")
    rp = sub.add_parser("rc-proof")
    rp.add_argument("--marker", required=True)
    rp.add_argument("--commit", required=True)
    rp.add_argument("--repo", default=".")
    rp.add_argument("--records", required=True)
    rp.add_argument("--template", required=True)
    rp.add_argument("--repository", required=True)      # owner/name of the repository the rc run ran in (GITHUB_REPOSITORY of the caller)
    chain_items.add_parsers(sub)
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
        elif a.cmd == "bind-items":
            cmd_bind_items(a)
        elif a.cmd == "apk-compare":
            cmd_apk_compare(a)
        elif a.cmd == "check-list":
            cmd_check_list(a)
        elif a.cmd == "bind-check":
            cmd_bind_check(a)
        elif a.cmd == "sign-record":
            cmd_sign_record(a)
        elif a.cmd == "sign-records":
            cmd_sign_records(a)
        elif a.cmd == "actions":
            cmd_actions(a)
        elif a.cmd in chain_items.COMMANDS:
            chain_items.COMMANDS[a.cmd](a)
        elif a.cmd == "hostile-row":
            chain_hostile.cmd_hostile_row(a)
        elif a.cmd == "hostile-collect":
            chain_hostile.cmd_hostile_collect(a)
        elif a.cmd == "hostile-material":
            chain_hostile.cmd_hostile_material(a)
        elif a.cmd == "hostile-verdict":
            chain_hostile.cmd_hostile_verdict(a)
        elif a.cmd == "rc-proof":
            cmd_rc_proof(a)
    except Refuse as r:
        print("refused at %s: %s" % (r.stage, r.reason), file=sys.stderr)
        sys.exit(1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
