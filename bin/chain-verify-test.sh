#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3 (key material), REQ-CHAIN-001-AC4, REQ-CHAIN-002-AC1, REQ-CHAIN-002-AC2, REQ-CHAIN-002-AC3,
#         REQ-CHAIN-003-AC1, REQ-CHAIN-003-AC2, REQ-CHAIN-003-AC4
# RED until bin/chain-verify.py exists (tests before implementation, step 4 of the nine-step process).
#
# Tests for the plain verify script of the v0.3.0 release chain (rules 52, 53, 53b, 57 verify side, 58, 63, 67).
# Needs: bash, OpenSSL 3 (macOS: brew install openssl@3, found automatically), python3 with PyYAML (apt: python3-yaml).
# Offline: a synthetic Fulcio-shaped chain (root -> intermediate -> leaf with a SAN URI and the Fulcio OIDC-issuer
# extension), a synthetic timestamp authority (root -> leaf), and a synthetic Rekor key are made at test time; no Sigstore,
# no key is committed. Every verify case runs with the network genuinely cut (macOS sandbox-exec, Linux unshare -rn or
# sudo unshare -n) and a control proves the cut; if no way exists the run says so loudly (CHAIN_TEST_REQUIRE_NETCUT=1
# makes that a failure; the CI wiring added by the implementation PR MUST set CHAIN_TEST_REQUIRE_NETCUT=1, and on ubuntu-24.04
# unprivileged user namespaces are AppArmor-restricted, so the `sudo -n unshare -n` fallback runs the verifier as root: files it
# leaves in the work dir are removed by the exit trap with sudo). Every refusal case is judged by exit code 1 (0 accepted; anything else, such
# as a missing script or a Python traceback, is an ERROR and fails the case) AND by words the message must contain.
#
# Certificate extensions: Witness's verify checks only the Fulcio extensions it has flags for (issuer, build trigger, source
# repository digest/ref/identifier, run invocation URI: in-toto-witness options/verify.go:80-99, passed on at cmd/verify.go:215)
# and its certConstraint matches only commonname/dns/email/org/uri (harness spike (b) line 8). It has NO check for the Build
# Config URI (Fulcio OID 1.3.6.1.4.1.57264.1.18, the calling top-level workflow). So bin/chain-verify.py must check, itself,
# on every Sign record: SAN == stage-sign.yml@tag AND 1.18 == release.yml@the same tag AND issuer (1.8) == the policy issuer;
# a missing extension is a refusal. OID check: Fulcio's oid-info (cited in options/verify.go:81) numbers .1.8 issuer v2,
# .1.9 Build Signer URI (= the SAN), .1.18 Build Config URI; this agrees with the spike-b dump (.1.9 = SAN, .1.18 = caller).
# MISMATCH TO CONFIRM IN THE DRY RUN: the spike dumps list the issuer as .1.1 (the deprecated v1 extension) and do not show
# .1.8; Fulcio docs say both are issued. These fixtures carry .1.8 only; if a real cert lacks it the implementer must decide
# (read .1.1 as a fallback) and the advisor should rule, since a fallback changes the refusal case "no issuer extension".
#
# Real formats this models (Modelled on, read-only clones):
#   Witness collection: predicateType https://witness.testifysec.com/attestation-collection/v0.1 inside a Statement
#     _type https://in-toto.io/Statement/v0.1 (in-toto-witness docs/tutorials/artifact-policy.md:60-70; the ops spike
#     2026-10-09-ccode-ops-witness-spike.md:36). Statement v1 is accepted too.
#   Signed policy: a DSSE envelope whose payloadType is https://witness.testifysec.com/policy/v0.1 and whose payload is
#     the policy JSON, not a Statement (in-toto-witness options/sign.go:36; test/fulcio-policy-presigned.json:
#     payload/payloadType/signatures).
#   Envelope signature fields: sig, certificate (base64 of PEM), intermediates (list of base64 PEM, leaf's issuers
#     with the root last), timestamps [{"type":"tsp","data":b64 RFC 3161 token}] (harness spike 2026-10-09-harness-
#     witness-spikes-a-c.md:31-32). Policy shape roots/timestampauthorities {id:{certificate,intermediates}}
#     (same spike :54-64; in-toto-witness cmd/verify.go:116-163,211).
#   SLSA provenance: https://slsa.dev/provenance/v1, Statement v1 (in-toto-attestation spec/predicates/provenance.md:3).
#     Only v1 is allowed: v0.2, a trailing slash, other case and other hosts are refused.
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py policy make --template T.json --tag vX.Y.Z --trust TRUST.json --fulcio-chain F.pem --tsa-chain S.pem
#                               --rekor-key K.pem --out POLICY.json
#       T.json  {"repository":"owner/repo","oidc_issuer":"https://...","stages":{"<stage>":{"workflow":".github/workflows/<file>.yml"}}}
#       TRUST.json {"fulcio_root_sha256","tsa_root_sha256","rekor_sha256"}: hex of the DER of the FIRST cert of F.pem and
#       S.pem (the roots; the rest are their intermediates / the TSA leaf) and of the DER public key K.pem.
#       exit 1 ("trust") when any hash differs from TRUST.json.
#       POLICY.json {"tag","repository","oidc_issuer","roots":{id:{"certificate":b64 PEM,"intermediates":[b64 PEM]}},
#                    "timestampauthorities":{id:{...same...}},"rekor_public_key":PEM,
#                    "stages":{"<stage>":{"identity":"https://github.com/<repo>/<workflow>@refs/tags/<tag>"}}}
#   chain-verify.py verify --policy POLICY.json --stage NAME --record REC.json --now ISO8601Z [--rekor-stub STUB.json]
#       REC.json is a DSSE envelope signed over the DSSE PAE. Checks, any failure exit 1 with the cause on stderr:
#       the chain from certificate+intermediates to a policy root; leaf SAN URI EXACTLY == stages[NAME].identity (the
#       message names the identity found); the Fulcio OIDC-issuer extension 1.3.6.1.4.1.57264.1.8 == policy oidc_issuer
#       ("issuer"); the signature ("signature"); a TSA stamp over sha256(sig bytes) from a policy authority whose time
#       lies inside the leaf's validity ("timestamp"/"validity"); the record type: Witness collection only for stages
#       build/rebuild/check, SLSA provenance v1 only for stage sign ("provenance"), the Witness policy payloadType
#       only for stage release, nothing else ("predicate"). KIND IS DERIVED FROM THE TYPE, there is no --kind flag:
#       every type except the Witness collection needs a Rekor entry ("rekor") in the stub
#       {"entries":[<cosign-bundle tlogEntry>...]} where a tlogEntry is {"logIndex":N,"logID":hex,"integratedTime":T,
#        "canonicalizedBody":b64(JSON hashedrekord body: {"apiVersion","kind","spec":{"data":{"hash":{"algorithm":"sha256",
#        "value":<sha256 hex of the DECODED payload>}},"signature":{"content":<b64 sig of THIS record>,"publicKey":{"content":
#        <b64 of THIS record's leaf PEM>}}}}),"signedEntryTimestamp":b64(ECDSA-SHA256 over json.dumps({"body":canonicalizedBody,
#        "integratedTime","logID","logIndex"},sort_keys=True,separators=(",",":")))}. Checked against the policy rekor_public_key;
#        the body must bind THIS record's payload hash, signature AND certificate (not just the payload hash). NO Rekor clone
#        exists under reference/: this shape rests on the cosign bundle format and Rekor's documented SET (the signed entry
#        timestamp is over the canonical {body, integratedTime, logID, logIndex}); the real kind for DSSE is `intoto`/`dsse`,
#        which the implementer checks against a real bundle in the dry run (flagged: the stub's body kind is hashedrekord).
#   chain-verify.py sign --check --signer cosign --digests D.json --build-record REC.json --policy POLICY.json --now ISO8601Z
#                   --out DIR
#       D.json is the digest list FILE {"<name>":"sha256:<64 lower-case hex>"}. REC.json is Build's Witness collection, verified
#       as stage build FIRST (every verify cause: chain, SAN, Build Config URI, issuer, signature, timestamp, type, tag; any
#       failure exits 1 naming "build" and the cause). Build's command writes digests.json as a PRODUCT, so the collection holds
#       the REAL Witness product subject https://witness.dev/attestations/product/v0.1/file:digests.json with digest
#       {sha256, gitoid:sha1, gitoid:sha256} (in-toto-witness docs/tutorials/artifact-policy.md:58-70), next to a git
#       commit subject; the check requires that subject's sha256 == sha256(the bytes of D.json) (exit 1 "digest" otherwise),
#       THEN checks D.json's CONTENT on its own (exit 1 "format"): JSON object, no duplicate key, every name matching
#       [a-z0-9-]+ (no upper case, slash, dot or code), every value a string sha256:<64 lower-case hex> (no sha512:, 63 hex,
#       upper case, null, number or path). Only after both does it sign, and the ONLY signer is --signer cosign (no test-only signer exists in production code):
#       it writes the unsigned in-toto Statement v1 (SLSA provenance v1, subjects = the digests, names and values as in D.json) to a
#       temp file and runs EXACTLY `cosign attest-blob --yes --statement STATEMENT.json --bundle DIR/provenance.bundle.json`
#       (no --key, no --identity-token, no flag that carries key material: cosign requests the OIDC token inside its own process),
#       then writes DIR/provenance.json = the DSSE envelope {payloadType,payload,signatures} taken from the bundle's dsseEnvelope.
#       The tests put a fake `cosign` first on PATH that implements just that call and signs with a local key; bin/install-scanner.sh
#       must gain a checksum-pinned cosign for the Sign job. A failed check writes NOTHING to DIR. DIR never holds private key material.
#   chain-verify.py stage-start --stage NAME --previous PREV --record REC.json --digests D.json --policy POLICY.json
#                               --now ISO8601Z [--rekor-stub STUB.json]
#       runs the SAME verification as verify for stage PREV, then compares digests exactly: for a SLSA provenance record the
#       subjects equal D.json's entries; for a Witness collection the product subject file:digests.json has sha256 == the
#       sha256 of D.json's bytes (equal, not subset or superset); exit 1 with PREV and the cause
#       (digest/identity/signature/missing/timestamp/rekor/issuer/build config) in the message.
#   chain-verify.py actions WORKFLOW.yml --allowed ALLOWED.json [--root DIR]
#       ALLOWED.json {"actions":["owner/repo[/sub/path]@<40 lower-case hex>"],"images":["<image>@sha256:<64 hex>"],"local":["<path>"]}
#       reads steps AND job-level `uses:`, container (string or {image:}), services images, docker:// references,
#       composite action.yml `runs.steps` (and, for a local `uses: ./path` named in "local", the action.yml found under --root,
#       recursively); exit 1 naming the reference for anything not exactly listed by full digest,
#       for an expression (${{ }}) in a reference, a short or upper-case sha, a tag or branch; a repository-local
#       reusable call (`uses: ./path`) passes only if its path is in "local".
#   chain-verify.py hostile-verdict|hostile-row|hostile-collect|hostile-material   (tested in bin/chain-hostile-test.sh)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cv="$root/bin/chain-verify.py"
work=$(mktemp -d); trap 'rm -rf "$work" 2> /dev/null || sudo -n rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass + 1)); echo "ok   $1"; }
bad()  { failn=$((failn + 1)); echo "FAIL $1"; }

# ---- tools ------------------------------------------------------------------------------------------------------
OPENSSL=openssl
if ! openssl version 2> /dev/null | grep -q '^OpenSSL 3'; then
  for c in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do [ -x "$c" ] && OPENSSL=$c && break; done
fi
$OPENSSL version 2> /dev/null | grep -q '^OpenSSL 3' || { echo "FAIL fixtures need OpenSSL 3 (macOS: brew install openssl@3)"; exit 1; }
export OPENSSL
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (apt install python3-yaml)"; exit 1; }
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
import base64, datetime as dt, hashlib, json, os, subprocess, sys, textwrap
W = sys.argv[1]
SSL = os.environ["OPENSSL"]
def sh(*a, inp=None):
    a = (SSL,) + a[1:] if a[0] == "openssl" else a
    r = subprocess.run(a, input=inp, capture_output=True)
    if r.returncode: sys.stderr.write("%s\n%s\n" % (" ".join(a), r.stderr.decode())); sys.exit(1)
    return r.stdout
def p(n): return os.path.join(W, n)
def fmt(t): return t.strftime("%Y%m%d%H%M%SZ")
def b64(b): return base64.b64encode(b).decode()
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
def cfg(name):
    d = p(name + ".db"); os.makedirs(d, exist_ok=True)
    open(d + "/index.txt", "w").close(); open(d + "/serial", "w").write("01\n")
    c = p(name + ".cnf")
    open(c, "w").write(textwrap.dedent("""\
        [ca]
        default_ca = c
        [c]
        dir = %s
        database = $dir/index.txt
        new_certs_dir = $dir
        serial = $dir/serial
        default_md = sha256
        policy = pol
        unique_subject = no
        [pol]
        commonName = optional
        [req]
        distinguished_name = dn
        prompt = no
        [dn]
        CN = x
        [v3_ca]
        basicConstraints = critical,CA:TRUE
        keyUsage = critical,keyCertSign,cRLSign
        """ % d))
    return c
def mkca(name):
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", p(name + ".key"),
       "-out", p(name + ".pem"), "-days", "2", "-subj", "/CN=" + name, "-config", cfg(name), "-extensions", "v3_ca")
def issue(ca, name, ext, start, end):
    sh("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", p(name + ".key"),
       "-out", p(name + ".csr"), "-subj", "/CN=" + name)
    open(p(name + ".ext"), "w").write(ext + "\n")
    sh("openssl", "ca", "-batch", "-config", p(ca + ".cnf"), "-cert", p(ca + ".pem"), "-keyfile", p(ca + ".key"),
       "-in", p(name + ".csr"), "-out", p(name + ".pem"), "-notext", "-startdate", fmt(start), "-enddate", fmt(end), "-extfile", p(name + ".ext"))
# Fulcio-shaped chain: root -> intermediate -> leaf (the real envelope lists intermediates then the root, spike :31)
mkca("root"); mkca("otherroot"); mkca("tsaroot"); mkca("othertsaroot")
issue("root", "interm", "basicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign", now - dt.timedelta(hours=1), now + dt.timedelta(hours=20))
cfg("interm")
for t in ("tsa", "othertsa"):
    ca = "tsaroot" if t == "tsa" else "othertsaroot"
    issue(ca, t, "extendedKeyUsage = critical,timeStamping", now - dt.timedelta(hours=1), now + dt.timedelta(hours=20))
    open(p(t + ".cnf"), "w").write(textwrap.dedent("""\
        [tsa]
        default_tsa = t
        [t]
        serial = %s
        signer_digest = sha256
        default_policy = 1.2.3.4
        other_policies = 1.2.3.4
        digests = sha256
        accuracy = secs:1
        ordering = no
        tsa_name = no
        ess_cert_id_chain = no
        ess_cert_id_alg = sha256
        """ % p(t + ".serial")))
    open(p(t + ".serial"), "w").write("0A\n")
def stamp(sigbytes, tsa):
    q = sh("openssl", "ts", "-query", "-digest", hashlib.sha256(sigbytes).hexdigest(), "-sha256", "-cert", "-no_nonce")
    open(p("q.tsq"), "wb").write(q)
    ca = "tsaroot" if tsa == "tsa" else "othertsaroot"
    sh("openssl", "ts", "-reply", "-queryfile", p("q.tsq"), "-signer", p(tsa + ".pem"), "-inkey", p(tsa + ".key"),
       "-chain", p(ca + ".pem"), "-config", p(tsa + ".cnf"), "-section", "t", "-token_out", "-out", p("r.tst"))
    return b64(open(p("r.tst"), "rb").read())
def gitoid(data, algo): return hashlib.new(algo, b"blob %d\0" % len(data) + data).hexdigest()
def pae(t, b): return b"DSSEv1 %d %s %d %s" % (len(t), t.encode(), len(b), b)
REPO = "fosterstack/cache"
ISSUER = "https://token.actions.githubusercontent.com"
def uri(wf, ref, repo=REPO): return "https://github.com/%s/.github/workflows/%s@%s" % (repo, wf, ref)
_n = [0]
STMT = {"v0.1": "https://in-toto.io/Statement/v0.1", "v1": "https://in-toto.io/Statement/v1"}
DSSE = "application/vnd.in-toto+json"
def record(name, wf, ref, ptype, subjects, ca="interm", start=None, end=None, tsa="tsa", signed=True, repo=REPO, issuer=ISSUER,
           stmt="v1", dsse=DSSE, payload=None, config_wf="release.yml", config_ref=None, config_repo=None, no_config=False, no_issuer=False,
           coll_file=None):
    _n[0] += 1; leaf = "leaf%d" % _n[0]
    ext = "subjectAltName = critical,URI:" + uri(wf, ref, repo)
    if not no_issuer: ext += "\n1.3.6.1.4.1.57264.1.8 = ASN1:UTF8String:" + issuer
    # Build Config URI (Fulcio 1.3.6.1.4.1.57264.1.18) = the TOP-LEVEL workflow that called the stage (workflow_ref); the SAN
    # (Build Signer URI, .1.9) is the called file. Harness spike (b): a second workflow that calls stage-sign.yml gets Sign's SAN.
    if not no_config: ext += "\n1.3.6.1.4.1.57264.1.18 = ASN1:UTF8String:" + uri(config_wf, config_ref or ref, config_repo or repo)
    issue(ca, leaf, ext, start or now - dt.timedelta(minutes=5), end or now + dt.timedelta(minutes=10))
    if payload is None and coll_file:
        # REAL Witness collection shape (in-toto-witness docs/tutorials/artifact-policy.md:58-70): the product attestor names the
        # file `https://witness.dev/attestations/product/v0.1/file:<name>` with sha256 + gitoid:sha1 + gitoid:sha256 digests, the git
        # attestor adds the commit; the predicate lists the attestations that ran (environment, git, product, command-run)
        data = open(p(coll_file), "rb").read()
        subj = [{"name": "https://witness.dev/attestations/product/v0.1/file:digests.json",
                 "digest": {"sha256": hashlib.sha256(data).hexdigest(), "gitoid:sha1": "gitoid:blob:sha1:" + gitoid(data, "sha1"),
                            "gitoid:sha256": "gitoid:blob:sha256:" + gitoid(data, "sha256")}},
                {"name": "https://witness.dev/attestations/git/v0.1/commithash:" + "f" * 40, "digest": {"gitoid:sha1": "gitoid:commit:sha1:" + "f" * 40}}]
        att = [{"type": "https://witness.dev/attestations/%s/v0.1" % k, "attestation": {}} for k in ("environment", "git", "product", "command-run")]
        payload = json.dumps({"_type": STMT[stmt], "predicateType": ptype, "predicate": {"name": "build", "attestations": att}, "subject": subj}).encode()
    if payload is None:
        payload = json.dumps({"_type": STMT[stmt], "predicateType": ptype, "predicate": {},
                              "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1] if v.startswith("sha256:") else v}} for k, v in subjects.items()]}).encode()
    open(p("pae.bin"), "wb").write(pae(dsse, payload))
    sh("openssl", "dgst", "-sha256", "-sign", p(leaf + ".key"), "-out", p("sig.bin"), p("pae.bin"))
    sig = open(p("sig.bin"), "rb").read()
    chain = [b64(open(p(c + ".pem"), "rb").read()) for c in (("interm", "root") if ca == "interm" else (ca,))]
    s = {"keyid": "", "sig": b64(sig), "certificate": b64(open(p(leaf + ".pem"), "rb").read()), "intermediates": chain}
    if tsa: s["timestamps"] = [{"type": "tsp", "data": stamp(sig, tsa)}]
    env = {"payloadType": dsse, "payload": b64(payload), "signatures": [s] if signed else []}
    json.dump(env, open(p(name + ".json"), "w"))
    return hashlib.sha256(payload).hexdigest()
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
FMT = {"sha512": dict(D, apk="sha512:" + "c" * 128), "63": dict(D, apk="sha256:" + "c" * 63), "upper": dict(D, apk="sha256:" + "C" * 64),
       "null": dict(D, apk=None), "number": dict(D, apk=7), "path": dict(D, apk="./dist/run.sh"), "code": dict(D, apk="sha256:$(curl evil)"),
       "badval": dict(D, apk="sha256:./dist/run.sh"), "codename": {"image-production;curl evil": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "uppername": {"Image-Production": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "slashname": {"dist/image-production": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]},
       "dotdotname": {"..": D["image-production"], "image-fips": D["image-fips"], "apk": D["apk"]}}
for k, v in FMT.items(): dj("digests-%s.json" % k, v)
open(p("digests-dupkey.json"), "w").write('{"image-production":"sha256:%s","image-fips":"sha256:%s","apk":"sha256:%s","apk":"sha256:%s"}' % ("a" * 64, "b" * 64, "d" * 64, "c" * 64))
open(p("digests-notobject.json"), "w").write('["sha256:%s"]' % ("a" * 64))
FMT["dupkey"] = FMT["notobject"] = None
STAGES = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml", "check": "stage-verify.yml", "release": "stage-promote.yml"}
json.dump({"repository": REPO, "oidc_issuer": ISSUER, "caller_workflow": ".github/workflows/release.yml", "stages": {k: {"workflow": ".github/workflows/" + v} for k, v in STAGES.items()}}, open(p("template.json"), "w"))
sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("rekor.key"))
sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("rekor2.key"))
sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p("signstub.key"))   # the stub signer's key: test-only, lives in the temp dir
for k in ("rekor", "rekor2"): sh("openssl", "pkey", "-in", p(k + ".key"), "-pubout", "-out", p(k + ".pub"))
def der_sha(pem, pub=False):
    a = ["openssl", "pkey", "-pubin", "-in", pem, "-outform", "DER"] if pub else ["openssl", "x509", "-in", pem, "-outform", "DER"]
    return hashlib.sha256(sh(*a)).hexdigest()
def cat(out, *names): open(p(out), "w").write("".join(open(p(n + ".pem")).read() for n in names))
cat("fulcio-chain.pem", "root", "interm"); cat("tsa-chain.pem", "tsaroot", "tsa")
good = {"fulcio_root_sha256": der_sha(p("root.pem")), "tsa_root_sha256": der_sha(p("tsaroot.pem")), "rekor_sha256": der_sha(p("rekor.pub"), True)}
dj("trust.json", good)
dj("trust-badroot.json", dict(good, fulcio_root_sha256=der_sha(p("otherroot.pem"))))
dj("trust-badtsa.json", dict(good, tsa_root_sha256=der_sha(p("othertsaroot.pem"))))
dj("trust-badrekor.json", dict(good, rekor_sha256=der_sha(p("rekor2.pub"), True)))
T, T2 = "refs/tags/v0.3.0", "refs/tags/v0.3.1"
PAY = {}
def add(n, *a, **k): PAY[n] = record(n, *a, **k)
# ---- Sign's provenance and its identity variants (001-AC4, 002-AC2)
add("sign_prov", STAGES["sign"], T, PROV, D)
add("sign_prov_v0.2", STAGES["sign"], T, "https://slsa.dev/provenance/v0.2", D)
for s in ("build", "rebuild", "check", "release"): add(s + "_as_sign", STAGES[s], T, PROV, D)
add("sibling_as_sign", "other.yml", T, PROV, D)
add("evilext_as_sign", "stage-sign.yml.evil", T, PROV, D)
add("xprefix_as_sign", "xstage-sign.yml", T, PROV, D)
add("sign_rc", STAGES["sign"], "refs/tags/v0.3.0-rc1", PROV, D)
add("sign_othertag", STAGES["sign"], T2, PROV, D)
add("sign_branch", STAGES["sign"], "refs/heads/main", PROV, D)
add("sign_wrongrepo", STAGES["sign"], T, PROV, D, repo="attacker/cache")
add("sign_badissuer", STAGES["sign"], T, PROV, D, issuer="https://accounts.google.com")
add("sign_noissuer", STAGES["sign"], T, PROV, D, no_issuer=True)
# advisor reading 1 (0334): Sign's identity = SAN stage-sign.yml@tag + Build Config URI release.yml@same tag + the GitHub issuer
add("sign_othercaller", STAGES["sign"], T, PROV, D, config_wf="other-caller.yml")        # a second workflow that CALLS stage-sign.yml
add("sign_callertag", STAGES["sign"], T, PROV, D, config_ref=T2)                          # right SAN, caller at another tag
add("sign_callerbranch", STAGES["sign"], T, PROV, D, config_ref="refs/heads/main")        # right SAN, caller on a branch
add("sign_noconfig", STAGES["sign"], T, PROV, D, no_config=True)                          # Build Config URI extension absent
add("sign_wrongroot", STAGES["sign"], T, PROV, D, ca="otherroot")
add("sign_otherdigests", STAGES["sign"], T, PROV, dict(D, apk="sha256:" + "d" * 64))
add("sign_coll", STAGES["sign"], T, COLL, D, stmt="v0.1")
# ---- timestamps (002-AC1). Stamps are taken at generation time (real wall clock = "now"); each case isolates its cause.
add("sign_nostamp", STAGES["sign"], T, PROV, D, tsa=None)
add("sign_othertsa", STAGES["sign"], T, PROV, D, tsa="othertsa")
add("sign_stampbefore", STAGES["sign"], T, PROV, D, start=now + dt.timedelta(minutes=60), end=now + dt.timedelta(minutes=120))
add("sign_stampafter", STAGES["sign"], T, PROV, D, start=now - dt.timedelta(minutes=120), end=now - dt.timedelta(minutes=60))
add("sign_unsigned", STAGES["sign"], T, PROV, D, signed=False)
_g = json.load(open(p("sign_prov.json")))
def variant(name, edit):
    t = json.loads(json.dumps(_g)); edit(t); json.dump(t, open(p(name + ".json"), "w"))
def _payload(t):
    st = json.loads(base64.b64decode(t["payload"])); st["subject"][0]["digest"]["sha256"] = "e" * 64; t["payload"] = b64(json.dumps(st).encode())
def _sig(t):
    sg = bytearray(base64.b64decode(t["signatures"][0]["sig"])); sg[-1] ^= 1; t["signatures"][0]["sig"] = b64(bytes(sg))
def _stamp(t): t["signatures"][0]["timestamps"] = json.load(open(p("sign_othertag.json")))["signatures"][0]["timestamps"]
variant("sign_tamper_payload", _payload); variant("sign_tamper_sig", _sig); variant("sign_tamper_stamp", _stamp)
# ---- Witness collections (real type, Statement v0.1 as Witness writes it; one in v1 form) and the signed policy
add("build_coll", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json")
add("build_coll_v1", STAGES["build"], T, COLL, None, stmt="v1", coll_file="digests.json")
add("build_coll_scan", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", config_wf="scan.yml")   # stage-build.yml called from scan.yml, not release.yml
add("build_coll_nostamp", STAGES["build"], T, COLL, None, tsa=None, stmt="v0.1", coll_file="digests.json")
add("build_coll_plus", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests-extra.json")
add("build_coll_swapped", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests-swapped.json")
for k in FMT: add("build_coll_" + k, STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests-%s.json" % k)
# through sign --check, every cause verify knows must be named for Build's record too
add("build_coll_badissuer", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", issuer="https://accounts.google.com")
add("build_coll_wrongroot", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", ca="otherroot")
add("build_coll_wrongrepo", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", repo="attacker/cache")
add("build_coll_noconfig", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", no_config=True)
add("check_coll", STAGES["check"], T, COLL, None, stmt="v0.1", coll_file="digests.json")
add("rebuild_coll", STAGES["rebuild"], T, COLL, None, stmt="v0.1", coll_file="digests.json")
add("rebuild_coll_other", STAGES["rebuild"], T, COLL, None, stmt="v0.1", coll_file="digests-other.json")
add("build_coll_othertag", STAGES["build"], T2, COLL, None, stmt="v0.1", coll_file="digests.json")
# near misses of the Build Config URI (the calling top-level workflow) and of the repository, for the Sign stage (001-AC4/002-AC2)
add("sign_cfg_wrongrepo", STAGES["sign"], T, PROV, D, config_repo="attacker/cache")
add("sign_cfg_repoevil", STAGES["sign"], T, PROV, D, config_repo="fosterstack/cache-evil")
add("sign_cfg_repox", STAGES["sign"], T, PROV, D, config_repo="fosterstack/cachex")
add("sign_cfg_prerelease", STAGES["sign"], T, PROV, D, config_wf="prerelease.yml")
add("sign_cfg_xrelease", STAGES["sign"], T, PROV, D, config_wf="xrelease.yml")
add("sign_cfg_rc", STAGES["sign"], T, PROV, D, config_ref="refs/tags/v0.3.0-rc1")
add("sign_san_repoevil", STAGES["sign"], T, PROV, D, repo="fosterstack/cache-evil", config_repo="fosterstack/cache")
# the extension checks are not Sign-only: Rebuild, Check and Release must each refuse a wrong top-level workflow and a wrong issuer
for s in ("rebuild", "check"):
    add(s + "_cfg", STAGES[s], T, COLL, None, stmt="v0.1", coll_file="digests.json", config_wf="scan.yml")
    add(s + "_issuer", STAGES[s], T, COLL, None, stmt="v0.1", coll_file="digests.json", issuer="https://accounts.google.com")
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
    add(n, STAGES["build"], T, ty, None, stmt="v0.1", coll_file="digests.json")
polbody = json.dumps({"expires": "2031-01-01T00:00:00Z", "steps": {}, "roots": {}, "timestampauthorities": {}}).encode()
add("release_policy", STAGES["release"], T, None, None, dsse=POLT, payload=polbody)
add("build_policy", STAGES["build"], T, None, None, dsse=POLT, payload=polbody)
add("release_policy_cfg", STAGES["release"], T, None, None, dsse=POLT, payload=polbody, config_wf="scan.yml")
add("release_policy_issuer", STAGES["release"], T, None, None, dsse=POLT, payload=polbody, issuer="https://accounts.google.com")
add("release_stmt_policy", STAGES["release"], T, "https://in-toto.io/attestation/release/v0.1", D)
# ---- Rekor, shaped like a cosign bundle tlogEntry (no Rekor clone exists; see the header). The body binds the record's payload
# hash, signature AND certificate; the signed entry timestamp is over the canonical {body, integratedTime, logID, logIndex}.
def entry(rec_name, idx, key="rekor", body_from=None):
    env = json.load(open(p(rec_name + ".json"))); src = json.load(open(p((body_from or rec_name) + ".json")))
    sg = src["signatures"][0]
    body = b64(json.dumps({"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {"data": {"hash": {"algorithm": "sha256", "value": PAY[body_from or rec_name]}},
            "signature": {"content": sg["sig"], "publicKey": {"content": sg["certificate"]}}}}, sort_keys=True, separators=(",", ":")).encode())
    e = {"logIndex": idx, "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d", "integratedTime": int(now.timestamp()), "canonicalizedBody": body}
    open(p("set.bin"), "wb").write(json.dumps({"body": body, "integratedTime": e["integratedTime"], "logID": e["logID"], "logIndex": idx}, sort_keys=True, separators=(",", ":")).encode())
    sh("openssl", "dgst", "-sha256", "-sign", p(key + ".key"), "-out", p("set.sig"), p("set.bin"))
    e["signedEntryTimestamp"] = b64(open(p("set.sig"), "rb").read())
    return e
dj("rekor.json", {"entries": [entry("sign_prov", 7), entry("release_policy", 8)]})
dj("rekor-empty.json", {"entries": []})
dj("rekor-other.json", {"entries": [entry("sign_otherdigests", 9)]})
e = entry("sign_prov", 7); e["signedEntryTimestamp"] = b64(b"\x30\x06\x02\x01\x01\x02\x01\x01"); dj("rekor-badset.json", {"entries": [e]})
dj("rekor-wrongkey.json", {"entries": [entry("sign_prov", 7, "rekor2")]})
e = entry("sign_prov", 7); e["logIndex"] = 99; dj("rekor-editedidx.json", {"entries": [e]})
e = entry("sign_prov", 7); e["integratedTime"] += 3600; dj("rekor-editedtime.json", {"entries": [e]})
# an entry whose body is for another record's SIGNATURE and CERTIFICATE but the right payload hash (validly SET-signed by the log)
_s = json.load(open(p("sign_prov.json"))); _o = json.load(open(p("sign_cfg_rc.json")))["signatures"][0]
_e = entry("sign_prov", 7); _body = json.loads(base64.b64decode(_e["canonicalizedBody"])); _body["spec"]["signature"] = {"content": _o["sig"], "publicKey": {"content": _o["certificate"]}}
_e["canonicalizedBody"] = b64(json.dumps(_body, sort_keys=True, separators=(",", ":")).encode())
open(p("set.bin"), "wb").write(json.dumps({"body": _e["canonicalizedBody"], "integratedTime": _e["integratedTime"], "logID": _e["logID"], "logIndex": 7}, sort_keys=True, separators=(",", ":")).encode())
sh("openssl", "dgst", "-sha256", "-sign", p("rekor.key"), "-out", p("set.sig"), p("set.bin")); _e["signedEntryTimestamp"] = b64(open(p("set.sig"), "rb").read())
dj("rekor-bodysig.json", {"entries": [_e]})
# the verify times: NOW is 16+ minutes after every default leaf expired (leaf validity [now-5m, now+10m])
open(p("now.txt"), "w").write(fmt(now + dt.timedelta(minutes=26)))
open(p("now-in.txt"), "w").write(fmt(now + dt.timedelta(minutes=2)))
open(p("now-mid.txt"), "w").write(fmt(now + dt.timedelta(minutes=90)))   # inside sign_stampbefore's certificate window
open(p("rekor-len.txt"), "w").write(str(len(PAY)))
e = json.load(open(p("sign_prov.json")))["signatures"][0]
open(p("chk.tst"), "wb").write(base64.b64decode(e["timestamps"][0]["data"]))
sh("openssl", "ts", "-verify", "-digest", hashlib.sha256(base64.b64decode(e["sig"])).hexdigest(), "-in", p("chk.tst"), "-token_in", "-CAfile", p("tsaroot.pem"), "-no_check_time")
print("fixtures ok")
PY
python3 "$work/fx.py" "$work" > "$work/fx.log" 2>&1 || { cat "$work/fx.log"; echo "FAIL fixture generation"; exit 1; }
NOW=$(cat "$work/now.txt"); NOWIN=$(cat "$work/now-in.txt"); NOWMID=$(cat "$work/now-mid.txt")

# fixture self-checks: the inputs are what the cases claim they are (so a refusal is about the claimed cause)
O=$OPENSSL
$O verify -CAfile "$work/root.pem" -untrusted "$work/interm.pem" "$work/leaf1.pem" > /dev/null 2>&1 && ok "fixture: leaf chains root -> intermediate -> leaf" || bad "fixture: leaf chain"
$O verify -CAfile "$work/otherroot.pem" -untrusted "$work/interm.pem" "$work/leaf1.pem" > /dev/null 2>&1 && bad "fixture: leaf must NOT chain to the other root" || ok "fixture: other root does not verify the leaf"
$O x509 -in "$work/leaf1.pem" -noout -ext subjectAltName 2> /dev/null | grep -F -q 'stage-sign.yml@refs/tags/v0.3.0' && ok "fixture: leaf SAN is the Sign file at the tag" || bad "fixture: leaf SAN"
$O x509 -in "$work/leaf1.pem" -noout -text 2> /dev/null | grep -F -q '1.3.6.1.4.1.57264.1.8' && ok "fixture: leaf carries the Fulcio OIDC-issuer extension" || bad "fixture: issuer extension"
$O x509 -in "$work/leaf1.pem" -noout -text 2> /dev/null | grep -F -q '1.3.6.1.4.1.57264.1.18' && ok "fixture: leaf carries the Build Config URI extension (.1.18)" || bad "fixture: Build Config URI extension"
grep -F -q "fixtures ok" "$work/fx.log" && ok "fixture: the timestamp token verifies against the TSA root (openssl ts -verify)" || bad "fixture: timestamp token"
python3 - "$work" <<'PY' && ok "fixture: the real envelope shape (base64 PEM certificate, intermediates, Statement v0.1 collection, policy payloadType)" || bad "fixture: envelope shape"
import base64, json, sys
w = sys.argv[1]; r = lambda n: json.load(open(w + "/" + n + ".json"))
s = r("build_coll")["signatures"][0]
assert base64.b64decode(s["certificate"]).startswith(b"-----BEGIN CERTIFICATE-----") and len(s["intermediates"]) == 2
st = json.loads(base64.b64decode(r("build_coll")["payload"]))
assert st["_type"] == "https://in-toto.io/Statement/v0.1"
sub = st["subject"][0]
assert sub["name"] == "https://witness.dev/attestations/product/v0.1/file:digests.json" and set(sub["digest"]) == {"sha256", "gitoid:sha1", "gitoid:sha256"}, sub
import hashlib
assert sub["digest"]["sha256"] == hashlib.sha256(open(w + "/digests.json", "rb").read()).hexdigest()
for k in ("upper", "sha512", "codename", "dotdotname"):   # the format cases ATTEST their own file, so equality cannot be what refuses them
    s2 = json.loads(base64.b64decode(r("build_coll_" + k)["payload"]))["subject"][0]["digest"]["sha256"]
    assert s2 == hashlib.sha256(open(w + "/digests-%s.json" % k, "rb").read()).hexdigest(), k
assert r("release_policy")["payloadType"] == "https://witness.testifysec.com/policy/v0.1"
PY

# ---- harness ----------------------------------------------------------------------------------------------------
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
# a fake `cosign` (test-generated, first on PATH): implements only `attest-blob --yes --statement S --bundle B`, signs the DSSE PAE with
# the local test key, writes a bundle holding the dsseEnvelope, and records its argv so the test can pin the exact invocation
mkdir -p "$work/fakebin"
cat > "$work/fakebin/cosign" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >> "$work/cosign-argv.log"
[ "\${1:-}" = attest-blob ] && [ "\${2:-}" = --yes ] && [ "\${3:-}" = --statement ] && [ "\${5:-}" = --bundle ] && [ "\$#" = 6 ] || { echo "fake cosign: unexpected argv: \$*" >&2; exit 2; }
python3 - "\$4" "\$6" "$work/signstub.key" "$work" <<'PYF'
import base64, json, subprocess, sys
st, out, key, w = sys.argv[1:5]
body = open(st, "rb").read(); pt = "application/vnd.in-toto+json"
pae = b"DSSEv1 %d %s %d %s" % (len(pt), pt.encode(), len(body), body)
open(w + "/fake.pae", "wb").write(pae)
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key, w + "/fake.pae"], capture_output=True, check=True).stdout
json.dump({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "dsseEnvelope": {"payloadType": pt,
    "payload": base64.b64encode(body).decode(), "signatures": [{"sig": base64.b64encode(sig).decode(), "keyid": ""}]}}, open(out, "w"))
PYF
FAKE
chmod +x "$work/fakebin/cosign"
run() { PATH="$work/fakebin:$PATH" "${netcut[@]+"${netcut[@]}"}" python3 "$cv" "$@" 2> "$work/err" > "$work/out" || return $?; }
errlc() { tr 'A-Z' 'a-z' < "$work/err"; }
# a Python crash exits 1 with a traceback: never a refusal
crashed() { grep -F -q "Traceback" "$work/err"; }
expect_ok() { local l=$1; shift; local rc=0; run "$@" || rc=$?
  if [ "$rc" = 0 ]; then ok "$l"; else bad "$l (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
# expect_refuse LABEL "word[|word...]" args...   every word must appear in the message (lower-cased), exit exactly 1, no traceback
expect_refuse() { local l=$1 w=$2 x=; shift 2; local rc=0 miss=0; run "$@" || rc=$?
  IFS='|' read -r -a ws <<< "$w"; for x in "${ws[@]}"; do errlc | grep -F -q -- "$x" || miss=1; done
  if [ "$rc" = 1 ] && [ "$miss" = 0 ] && ! crashed; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with '$w'; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
mkpol() { run policy make --template "$work/template.json" --tag v0.3.0 --trust "${2:-$work/trust.json}" \
  --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --out "$work/$1"; }
V() { echo --policy "$work/policy.json" --now "${1:-$NOW}"; }
R() { echo --rekor-stub "$work/${1:-rekor.json}"; }
rec() { echo --record "$work/$1.json"; }

# ---- REQ-CHAIN-002-AC2: the per-tag policy ----------------------------------------------------------------------
rc=0; mkpol policy.json || rc=$?; [ "$rc" = 0 ] && ok "002-AC2 policy for v0.3.0 is made from the template" || bad "002-AC2 policy make (exit $rc)"
for c in badroot:"a Fulcio root" badtsa:"a timestamp authority root" badrekor:"a Rekor key"; do
  k=${c%%:*}; rc=0; mkpol "policy-$k.json" "$work/trust-$k.json" || rc=$?
  { [ "$rc" = 1 ] && grep -F -q -i trust "$work/err" && ! crashed; } && ok "002-AC2 ${c#*:} whose hash differs from the trust file is refused" || bad "002-AC2 $k hash (exit $rc)"
done
expect_ok     "002-AC2 sign file at v0.3.0 is accepted as stage sign" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_refuse "002-AC2 sibling file at the same tag is refused" "other.yml" verify $(V) --stage sign $(rec sibling_as_sign) $(R)
expect_refuse "002-AC2 the same file at another tag is refused" "v0.3.1" verify $(V) --stage sign $(rec sign_othertag) $(R)
expect_refuse "002-AC2 a tag that only starts like the tag (v0.3.0-rc1) is refused" "v0.3.0-rc1" verify $(V) --stage sign $(rec sign_rc) $(R)
expect_refuse "002-AC2 the same file on a branch is refused" "refs/heads/main" verify $(V) --stage sign $(rec sign_branch) $(R)
expect_refuse "002-AC2 a file whose name merely starts with stage-sign.yml is refused" "stage-sign.yml.evil" verify $(V) --stage sign $(rec evilext_as_sign) $(R)
expect_refuse "002-AC2 a file whose name merely ends with stage-sign.yml is refused" "xstage-sign.yml" verify $(V) --stage sign $(rec xprefix_as_sign) $(R)
expect_refuse "002-AC2 the right file in another repository is refused" "attacker/cache" verify $(V) --stage sign $(rec sign_wrongrepo) $(R)
expect_refuse "002-AC2 a certificate from another OIDC issuer is refused" "issuer" verify $(V) --stage sign $(rec sign_badissuer) $(R)
expect_refuse "001-AC4/002-AC2 right SAN but the top-level workflow is another file that calls stage-sign.yml: refused, the caller is named" "other-caller.yml" verify $(V) --stage sign $(rec sign_othercaller) $(R)
expect_refuse "002-AC2 right SAN but the calling release.yml is at another tag is refused" "v0.3.1" verify $(V) --stage sign $(rec sign_callertag) $(R)
expect_refuse "002-AC2 right SAN but the calling release.yml is on a branch is refused" "refs/heads/main" verify $(V) --stage sign $(rec sign_callerbranch) $(R)
expect_refuse "002-AC2 right SAN but the calling workflow lives in another repository (attacker/cache) is refused" "attacker/cache" verify $(V) --stage sign $(rec sign_cfg_wrongrepo) $(R)
expect_refuse "002-AC2 a calling repository that only starts like ours (fosterstack/cache-evil) is refused" "cache-evil" verify $(V) --stage sign $(rec sign_cfg_repoevil) $(R)
expect_refuse "002-AC2 a calling repository that only has ours as a prefix (fosterstack/cachex) is refused" "cachex" verify $(V) --stage sign $(rec sign_cfg_repox) $(R)
expect_refuse "002-AC2 a calling workflow that only ends like ours (prerelease.yml) is refused" "prerelease.yml" verify $(V) --stage sign $(rec sign_cfg_prerelease) $(R)
expect_refuse "002-AC2 a calling workflow with a prefixed name (xrelease.yml) is refused" "xrelease.yml" verify $(V) --stage sign $(rec sign_cfg_xrelease) $(R)
expect_refuse "002-AC2 a calling release.yml at a tag that only starts like ours (v0.3.0-rc1) is refused" "v0.3.0-rc1" verify $(V) --stage sign $(rec sign_cfg_rc) $(R)
expect_refuse "002-AC2 a SAN repository that only starts like ours (cache-evil) is refused" "cache-evil" verify $(V) --stage sign $(rec sign_san_repoevil) $(R)
expect_refuse "002-AC2 a certificate with no Build Config URI extension is refused" "build config" verify $(V) --stage sign $(rec sign_noconfig) $(R)
expect_refuse "002-AC2 a certificate with no OIDC-issuer extension is refused" "issuer" verify $(V) --stage sign $(rec sign_noissuer) $(R)
expect_refuse "002-AC2 a certificate from another root is refused" "root" verify $(V) --stage sign $(rec sign_wrongroot) $(R)
python3 - "$root" 2> /dev/null <<'PY' && ok "002-AC2 .github/policy/release-policy.template.json names the five stage files and the issuer" || bad "002-AC2 committed template missing or wrong"
import json, sys
t = json.load(open(sys.argv[1] + "/.github/policy/release-policy.template.json"))
want = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml", "check": "stage-verify.yml", "release": "stage-promote.yml"}
assert t["caller_workflow"] == ".github/workflows/release.yml", t.get("caller_workflow")
assert t["repository"] == "fosterstack/cache" and t["oidc_issuer"] == "https://token.actions.githubusercontent.com"
assert {k: v["workflow"].rsplit("/", 1)[-1] for k, v in t["stages"].items()} == want, t["stages"]
PY
python3 - "$root" 2> /dev/null <<'PY' && ok "002-AC2 .github/policy/sigstore-trust.json pins the Fulcio root (3ba7b6cc..80c1), the TSA root (2aca8fea..d633) and the Rekor key" || bad "002-AC2 committed trust file missing or wrong"
import json, re, sys
t = json.load(open(sys.argv[1] + "/.github/policy/sigstore-trust.json"))
assert set(t) == {"fulcio_root_sha256", "tsa_root_sha256", "rekor_sha256"} and all(re.fullmatch(r"[0-9a-f]{64}", v) for v in t.values()), t
# the Fulcio root fingerprint recorded by the Oct 9 spike (CN=sigstore, spike :50) starts with 3ba7b6cc and ends 80c1
assert t["fulcio_root_sha256"].startswith("3ba7b6cc") and t["fulcio_root_sha256"].endswith("80c1"), t["fulcio_root_sha256"]
# the TSA root fingerprint recorded by the Oct 9 spike (CN=sigstore-tsa-selfsigned, spike :51) starts with 2aca8fea and ends d633
assert t["tsa_root_sha256"].startswith("2aca8fea") and t["tsa_root_sha256"].endswith("d633"), t["tsa_root_sha256"]
PY

# ---- REQ-CHAIN-001-AC4: provenance only from Sign's identity, only as the Sign stage's record ------------------------
expect_ok     "001-AC4 provenance under stage-sign.yml@tag is accepted" verify $(V) --stage sign $(rec sign_prov) $(R)
for s in build:stage-build.yml rebuild:stage-reproducibility.yml check:stage-verify.yml release:stage-promote.yml; do
  expect_refuse "001-AC4 ${s%%:*}'s identity is refused and named" "${s#*:}" verify $(V) --stage sign $(rec ${s%%:*}_as_sign) $(R)
done
expect_refuse "001-AC4 a sibling file is refused and named" "other.yml" verify $(V) --stage sign $(rec sibling_as_sign) $(R)
expect_refuse "001-AC4 provenance presented as stage build's record is refused (type is bound to the stage)" "provenance" verify $(V) --stage build $(rec build_as_sign) $(R)
expect_refuse "002-AC2/003-AC5 stage-build.yml run from scan.yml (Build Config URI scan.yml) is refused for the build stage and the caller is named" "scan.yml" verify $(V) --stage build $(rec build_coll_scan)
for s in rebuild check release; do
  expect_refuse "001-AC4 provenance presented as stage $s's record is refused (type is bound to the stage)" "provenance" verify $(V) --stage $s $(rec ${s}_as_sign) $(R)
done
expect_refuse "001-AC4 a Witness collection signed by Sign is refused (Sign signs provenance only)" "collection|sign" verify $(V) --stage sign $(rec sign_coll)
expect_refuse "001-AC4 SLSA provenance v0.2 is not the allowed type" "predicate" verify $(V) --stage sign $(rec sign_prov_v0.2) $(R)

# ---- REQ-CHAIN-002-AC1: timestamps, checked 16 minutes after the certificate expired, offline ----------------------
expect_ok     "002-AC1 expired certificate + valid stamp from the policy's authority, verified 16 min after expiry" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_ok     "002-AC1 the same record inside the certificate window" verify $(V $NOWIN) --stage sign $(rec sign_prov) $(R)
expect_refuse "002-AC1 no timestamp after expiry is refused" "timestamp" verify $(V) --stage sign $(rec sign_nostamp) $(R)
expect_refuse "002-AC1 a stamp from another authority is refused" "timestamp" verify $(V) --stage sign $(rec sign_othertsa) $(R)
expect_refuse "002-AC1 a stamp BEFORE the certificate's validity is refused even when --now is inside the window" "validity" verify $(V $NOWMID) --stage sign $(rec sign_stampbefore) $(R)
expect_refuse "002-AC1 a stamp AFTER the certificate expired is refused" "validity" verify $(V) --stage sign $(rec sign_stampafter) $(R)
expect_refuse "002-AC1 tamper: payload changed after signing is refused" "signature" verify $(V) --stage sign $(rec sign_tamper_payload) $(R)
expect_refuse "002-AC1 tamper: signature bytes altered is refused" "signature" verify $(V) --stage sign $(rec sign_tamper_sig) $(R)
expect_refuse "002-AC1 tamper: a stamp taken over a different signature is refused" "timestamp" verify $(V) --stage sign $(rec sign_tamper_stamp) $(R)
expect_refuse "002-AC1 an unsigned record is refused" "signature" verify $(V) --stage sign $(rec sign_unsigned) $(R)
python3 - "$work/policy.json" "$work/policy-notsa.json" 2> /dev/null <<'PY' || true
import json, sys
d = json.load(open(sys.argv[1])); d["timestampauthorities"] = {}; json.dump(d, open(sys.argv[2], "w"))
PY
true
expect_refuse "002-AC1 a policy naming no authority refuses even a valid stamp" "timestamp" verify --policy "$work/policy-notsa.json" --now "$NOW" --stage sign $(rec sign_prov) $(R)

# ---- REQ-CHAIN-002-AC3: Rekor for everything but Witness collections; the entry must be for THIS record ------------
expect_ok     "002-AC3 provenance with a matching, correctly signed Rekor entry is accepted" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_refuse "002-AC3 provenance with no Rekor entry is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-empty.json)
expect_refuse "002-AC3 provenance is refused when no Rekor source is given (the type decides, not a flag)" "rekor" verify $(V) --stage sign $(rec sign_prov)
expect_refuse "002-AC3 an entry for a DIFFERENT record's payload is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-other.json)
expect_refuse "002-AC3 an entry whose signed entry timestamp is garbage is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-badset.json)
expect_refuse "002-AC3 an entry signed by a key that is not the policy's Rekor key is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-wrongkey.json)
expect_refuse "002-AC3 an entry whose log index was edited after signing is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-editedidx.json)
expect_refuse "002-AC3 an entry whose integrated time was edited after signing is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-editedtime.json)
expect_refuse "002-AC3 an entry with the right payload hash but another record's signature and certificate in its body (validly signed by the log) is refused" "rekor|signature" verify $(V) --stage sign $(rec sign_prov) $(R rekor-bodysig.json)
expect_ok     "002-AC3 the signed release policy with its Rekor entry is accepted" verify $(V) --stage release $(rec release_policy) $(R)
expect_ok     "002-AC3 a Witness stage record needs no Rekor entry" verify $(V) --stage build $(rec build_coll) $(R rekor-empty.json)
expect_refuse "002-AC3 a Witness record is checked for the timestamp instead" "timestamp" verify $(V) --stage build $(rec build_coll_nostamp)

# ---- REQ-CHAIN-003-AC2: only the standard record types, exact strings ------------------------------------------------
expect_ok     "003-AC2 the Witness collection type (Statement v0.1, as Witness writes it) is allowed" verify $(V) --stage build $(rec build_coll)
expect_ok     "003-AC2 the Witness collection type in a Statement v1 is allowed" verify $(V) --stage build $(rec build_coll_v1)
expect_ok     "003-AC2 SLSA provenance v1 is allowed" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_ok     "003-AC2 the Witness policy payloadType is allowed (stage release)" verify $(V) --stage release $(rec release_policy) $(R)
expect_refuse "003-AC2 an in-toto release Statement is not the signed policy and is refused" "predicate" verify $(V) --stage release $(rec release_stmt_policy) $(R)
expect_refuse "003-AC2 the policy type presented by stage build is refused" "predicate|policy" verify $(V) --stage build $(rec build_policy) $(R)
for c in madeup ours ours_style v02 plural oldhost slash upper prefix slsa_slash; do
  expect_refuse "003-AC2 near-miss/made-up type '$c' is refused" "predicate" verify $(V) --stage build $(rec build_$c) $(R)
done

# ---- REQ-CHAIN-001-AC2: Sign takes Build's digests (a FILE), checked against Build's VERIFIED record ----------------------
# The record binds the digest file by the sha256 of its bytes (the real product subject file:digests.json); the file's CONTENT is
# then judged on its own, so the format cases below are attested by their own collections and equality cannot be what refuses them.
S() { echo sign --check --signer cosign --build-record "$work/${1:-build_coll}.json" --policy "$work/policy.json" --now "${2:-$NOW}" --out "$work/out-$RANDOM$RANDOM$RANDOM"; }
expect_ok     "001-AC2 a digest file whose bytes Build's record attests is accepted (and signed)" $(S) --digests "$work/digests.json"
for c in other:"a digest that differs" extra:"an extra entry" subset:"a missing entry" swapped:"two names with their values swapped"; do
  expect_refuse "001-AC2 ${c#*:} (other bytes than Build attested) is refused" "digest" $(S) --digests "$work/digests-${c%%:*}.json"
done
expect_refuse "001-AC2 Build's record for a different file than the one given (extra entries attested) is refused" "digest" $(S build_coll_plus) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record for the swapped file is refused against the real list" "digest" $(S build_coll_swapped) --digests "$work/digests.json"
for c in sha512:"a sha512 value" 63:"63 hex characters" upper:"upper-case hex" null:"a null value" number:"a number" path:"a path instead of a digest" \
         code:"code in a value" badval:"a non-hex value" codename:"code in a name" uppername:"an upper-case name" slashname:"a slash in a name" \
         dotdotname:"a .. name" dupkey:"a duplicate JSON key" notobject:"a JSON array instead of an object"; do
  expect_refuse "001-AC2 Build attests the file AS IT IS and the content is still refused: ${c#*:}" "format" $(S build_coll_${c%%:*}) --digests "$work/digests-${c%%:*}.json"
done
expect_refuse "001-AC2 Build's record unsigned is refused before the digests are read" "build|signature" $(S build_coll_unsigned) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record tampered after signing (the file hash still equal) is refused" "build|signature" $(S build_coll_tampered) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record signed by another stage's identity is refused" "build|stage-verify.yml" $(S check_coll) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record from another tag is refused" "build|v0.3.1" $(S build_coll_othertag) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record run from a calling workflow that is not release.yml is refused" "build|scan.yml" $(S build_coll_scan) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record with no timestamp is refused" "build|timestamp" $(S build_coll_nostamp) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record of another type (made up) is refused" "build|predicate" $(S build_madeup) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record presented as the signed policy type is refused" "build|predicate|policy" $(S build_policy) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record under another OIDC issuer is refused" "build|issuer" $(S build_coll_badissuer) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record from a certificate under another root is refused" "build|root" $(S build_coll_wrongroot) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record signed in another repository is refused" "build|attacker/cache" $(S build_coll_wrongrepo) --digests "$work/digests.json"
expect_refuse "001-AC2 Build's record with no Build Config URI is refused" "build|build config" $(S build_coll_noconfig) --digests "$work/digests.json"
# the sign side (rule 52: Sign WRITES the provenance only after the check passes), with a fake cosign on PATH
mkdir -p "$work/sd"
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/ok" || rc=$?
if [ -f "$work/cosign-argv.log" ] && grep -E -q '^attest-blob --yes --statement [^ ]+ --bundle [^ ]+/provenance\.bundle\.json$' "$work/cosign-argv.log" \
   && ! grep -E -q -- '--key|--identity-token|--sk|--output-key|--signing-config|--fulcio|--rekor' "$work/cosign-argv.log"; then
  ok "001-AC3 sign runs exactly `cosign attest-blob --yes --statement S --bundle DIR/provenance.bundle.json`, with no key, token or endpoint flag"
else bad "001-AC3 the cosign invocation is not the pinned one ($(tr '\n' ' ' < "$work/cosign-argv.log" 2> /dev/null | head -c 200))"; fi
python3 - "$work/sd/ok" "$work/digests.json" <<'PY' 2> /dev/null && ok "001-AC2 sign writes SLSA provenance v1 whose subjects equal the digest list (names and values)" || bad "001-AC2 the provenance written by sign is missing or wrong"
import base64, json, os, sys
d, df = sys.argv[1], json.load(open(sys.argv[2]))
env = json.load(open(os.path.join(d, "provenance.json")))
st = json.loads(base64.b64decode(env["payload"]))
assert st["_type"] == "https://in-toto.io/Statement/v1" and st["predicateType"] == "https://slsa.dev/provenance/v1", st
assert {s["name"]: "sha256:" + s["digest"]["sha256"] for s in st["subject"]} == df and len(st["subject"]) == len(df)
assert env["signatures"] and env["payloadType"] == "application/vnd.in-toto+json"
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
rc=0; run sign --check --signer cosign --build-record "$work/build_coll_tampered.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/bad" || rc=$?
if [ "$rc" = 1 ] && [ -z "$(ls -A "$work/sd/bad" 2> /dev/null)" ]; then ok "001-AC2 a failed check writes NOTHING to the output folder"; else bad "001-AC2 a failed check left output (exit $rc)"; fi
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests-other.json" --out "$work/sd/bad2" || rc=$?
if [ "$rc" = 1 ] && [ -z "$(ls -A "$work/sd/bad2" 2> /dev/null)" ]; then ok "001-AC2 replay: provenance is not written for digests Build did not attest"; else bad "001-AC2 replay with other digests wrote output (exit $rc)"; fi
rc=0; run sign --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/nocheck" || rc=$?
if [ "$rc" = 1 ] && ! crashed && [ -z "$(ls -A "$work/sd/nocheck" 2> /dev/null)" ]; then ok "001-AC2 sign without --check is not a mode: it refuses and writes nothing"; else bad "001-AC2 sign without --check wrote output (exit $rc)"; fi

# ---- REQ-CHAIN-003-AC1: each stage verifies the one before it, with the cause named ------------------------------------
ST() { local cur=$1 prev=$2; shift 2; echo stage-start --stage "$cur" --previous "$prev" --policy "$work/policy.json" --now "$NOW" "$@"; }
expect_ok     "003-AC1 rebuild <- build: a valid record about exactly the given digests lets the stage start" $(ST rebuild build) $(rec build_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 check <- build: the same for Check" $(ST check build) $(rec build_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 release <- sign: provenance with its Rekor entry lets Release start" $(ST release sign) $(rec sign_prov) $(R) --digests "$work/digests.json"
expect_ok     "003-AC1 release <- rebuild" $(ST release rebuild) $(rec rebuild_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 release <- check" $(ST release check) $(rec check_coll) --digests "$work/digests.json"
expect_refuse "003-AC1 other digests: names build and the digest cause" "build|digest" $(ST rebuild build) $(rec build_coll) --digests "$work/digests-other.json"
expect_refuse "003-AC1 a SUBSET of the record's digests is refused" "build|digest" $(ST rebuild build) $(rec build_coll) --digests "$work/digests-subset.json"
expect_refuse "003-AC1 a SUPERSET of the record's digests is refused" "build|digest" $(ST rebuild build) $(rec build_coll) --digests "$work/digests-extra.json"
expect_refuse "003-AC1 a record with more subjects than the given list is refused" "build|digest" $(ST rebuild build) $(rec build_coll_plus) --digests "$work/digests.json"
expect_refuse "003-AC1 wrong signer stage (a Check record offered as Build's): names build and identity" "build|stage-verify.yml" $(ST rebuild build) $(rec check_coll) --digests "$work/digests.json"
expect_refuse "003-AC1 an unsigned record: names build and signature" "build|signature" $(ST rebuild build) $(rec build_coll_unsigned) --digests "$work/digests.json"
expect_refuse "003-AC1 tamper through stage-start: payload changed after signing" "build|signature" $(ST rebuild build) $(rec build_coll_tampered) --digests "$work/digests.json"
expect_refuse "003-AC1 wrong tag through stage-start" "build|v0.3.1" $(ST rebuild build) $(rec build_coll_othertag) --digests "$work/digests.json"
expect_refuse "003-AC1 no timestamp through stage-start" "build|timestamp" $(ST rebuild build) $(rec build_coll_nostamp) --digests "$work/digests.json"
expect_refuse "003-AC1 no record: names build and missing" "build|missing" $(ST rebuild build) --record "$work/does-not-exist.json" --digests "$work/digests.json"
expect_refuse "003-AC1 release <- sign without a Rekor entry: names sign and rekor" "sign|rekor" $(ST release sign) $(rec sign_prov) --digests "$work/digests.json"
expect_refuse "003-AC1 release <- sign with forged provenance signed by Build: names sign and the identity found" "sign|stage-build.yml" $(ST release sign) $(rec build_as_sign) $(R) --digests "$work/digests.json"
expect_refuse "002-AC2 rebuild's record from a calling workflow that is not release.yml is refused: names rebuild and scan.yml" "rebuild|scan.yml" $(ST release rebuild) $(rec rebuild_cfg) --digests "$work/digests.json"
expect_refuse "002-AC2 check's record from a calling workflow that is not release.yml is refused: names check and scan.yml" "check|scan.yml" $(ST release check) $(rec check_cfg) --digests "$work/digests.json"
expect_refuse "002-AC2 release's policy from a calling workflow that is not release.yml is refused" "release|scan.yml" verify $(V) --stage release $(rec release_policy_cfg) $(R)
expect_refuse "002-AC2 rebuild's record under another OIDC issuer is refused: names rebuild and issuer" "rebuild|issuer" $(ST release rebuild) $(rec rebuild_issuer) --digests "$work/digests.json"
expect_refuse "002-AC2 check's record under another OIDC issuer is refused: names check and issuer" "check|issuer" $(ST release check) $(rec check_issuer) --digests "$work/digests.json"
expect_refuse "002-AC2 release's policy under another OIDC issuer is refused" "release|issuer" verify $(V) --stage release $(rec release_policy_issuer) $(R)
expect_refuse "003-AC1 replay: release <- sign with the provenance of OLD digests is refused as a digest mismatch" "sign|digest" $(ST release sign) $(rec sign_otherdigests) $(R rekor-other.json) --digests "$work/digests.json"
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
A() { echo actions "$work/$1.yml" --allowed "$work/${2:-allowed}.json"; }
expect_ok     "003-AC4 a file whose references (steps, container, services) are all listed digests is accepted" $(A w_good)
expect_ok     "003-AC4 a job-level reusable call listed by digest is accepted" $(A w_jobreuseok)
expect_ok     "003-AC4 a container mapping form listed by digest is accepted" $(A w_contmapok)
expect_ok     "003-AC4 a docker:// reference listed by digest is accepted" $(A w_dockerd)
expect_ok     "003-AC4 a local reusable call named by path in the list is accepted" $(A w_local)
expect_ok     "003-AC4 a composite action.yml whose steps are all listed is accepted" $(A action-good)
for c in w_unl:upload-artifact w_tag:checkout@v4 w_branch:checkout@main w_otherd:checkout w_short:aaaaaaa w_upper:checkout w_sub:cache/save \
         w_expr:inputs.ref w_exprname:inputs.action w_jobreuse:other.yml w_jobreusemain:lib.yml@main w_cont:runner:latest w_contmap:runner:latest \
         w_contd:runner w_svc:postgres:latest w_svcd:postgres w_docker:alpine w_dockerun:alpine w_localbad:stage-build.yml w_localstep:thing action-tag:checkout@v4; do
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

EXPECT=187
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
