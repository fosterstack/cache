#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-001-AC4, REQ-CHAIN-002-AC1, REQ-CHAIN-002-AC2, REQ-CHAIN-002-AC3, REQ-CHAIN-003-AC1, REQ-CHAIN-003-AC2, REQ-CHAIN-003-AC4 — 001-AC3 here is the key-material and token-sentinel part
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
#       DEFAULTS (round 7, Opus B-NEW a): --trust, --fulcio-chain, --tsa-chain and --rekor-key are OPTIONAL. When absent they default to
#       sigstore-trust.json, fulcio-chain.pem, tsa-chain.pem and rekor.pub NEXT TO THE TEMPLATE (the committed .github/policy/ files), and the
#       trust-hash check applies to the defaults exactly as to explicit files ("trust" on a drifted default). The dry run's pinned
#       `policy make --template .github/policy/release-policy.template.json --ref "$GITHUB_REF" --out policy.json` and Release's
#       `--tag` line pass no file flags, so this is what makes them work.
#       chain-verify.py policy make ... --ref REF   (instead of --tag; round 5) makes the policy for a run's own ref: REF
#       refs/tags/vX.Y.Z (exactly) == --tag vX.Y.Z; a BRANCH ref (the dry run's refs/heads/..., e.g. refs/heads/hostile-proof/x)
#       makes a policy with "dry_run": true whose identities end @REF; refs/tags/v0.3.0-rc1, refs/tags/x and anything else
#       exits 1 "tag". A dry-run policy is NEVER what Release uses (Release's is made with --tag), so a Sign record whose SAN ref
#       is a branch is refused by Release's tag-pinned policy (cases below).
#   DRY RUN vs PRODUCTION for `sign --check` in template mode (decided in round 5; the Sign job's command line is the same in both):
#       GITHUB_REF == refs/tags/vX.Y.Z (exactly)                         -> production (policy for that tag)
#       GITHUB_EVENT_NAME == workflow_dispatch and GITHUB_REF a branch   -> DRY RUN: policy for that ref, the written provenance
#           predicate carries "dryRun": true and DIR/DRY-RUN exists beside it; Release can never accept such a record
#       anything else (-rc1 tag, refs/tags/x, a branch on push, workflow_dispatch on a tag that is not vX.Y.Z, no ref) -> exit 1 "tag"
#       No flag or environment variable can switch either mode on: the run's own GITHUB_REF / GITHUB_EVENT_NAME decide.
#   TOKEN SENTINEL: every run passes ACTIONS_ID_TOKEN_REQUEST_TOKEN / _URL and COSIGN_IDENTITY_TOKEN set to SENTINEL values; they
#       must appear in no stdout, stderr, output folder or cosign argv (the verifier and signer never print, store or forward them).
#   DRY-RUN POLICIES ARE SIGN-ONLY (round 6, fail closed): a policy with "dry_run": true is accepted by `verify` for --stage sign
#       ONLY (that is how the dry run's hostile-verify judges Sign's record: its positive control and its attempts); `verify` for any
#       other stage, and EVERY `stage-start` (what Build's successors and Release run), refuse a dry_run policy ("dry"). A Sign
#       record whose predicate carries "dryRun": true is refused under a non-dry policy even when its SAN ref is a tag ("dry"), and
#       Release's policy step is `policy make --tag` (bin/chain-hostile-test.sh pins it), so no branch edit can make Release accept one.
#   chain-verify.py verify --policy POLICY.json --stage NAME --record REC.json [--now ISO8601Z] [--rekor-stub STUB.json]
#       --now is OPTIONAL and defaults to the current UTC time, exactly like `sign --check`'s (round 6: the dry run's pinned verify
#       lines pass none, so no job env or step has to feed it)
#       REC.json is a DSSE envelope signed over the DSSE PAE. Checks, any failure exit 1 with the cause on stderr:
#       the chain from certificate+intermediates to a policy root; leaf SAN URI EXACTLY == stages[NAME].identity (the
#       message names the identity found); the Fulcio OIDC-issuer extension 1.3.6.1.4.1.57264.1.8 == policy oidc_issuer
#       ("issuer"); the signature ("signature"); a TSA stamp over sha256(sig bytes) from a policy authority whose time
#       lies inside the leaf's validity ("timestamp"/"validity"); the record type: Witness collection only for stages
#       build/rebuild/check, SLSA provenance v1 only for stage sign ("provenance"), the Witness policy payloadType
#       only for stage release, nothing else ("predicate"). KIND IS DERIVED FROM THE TYPE, there is no --kind flag:
#       every type except the Witness collection needs a Rekor entry ("rekor") in the file given as --rekor-stub
#       {"entries":[<tlogEntry>...]}: the bundle's tlogEntries untouched, in the REAL protobuf-JSON shape of a Rekor v1 `dsse` 0.0.1
#       entry (what `cosign attest-blob` writes by default): {"logIndex":"N","logId":{"keyId":b64(sha256 of the log key DER)},
#        "kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"T","inclusionPromise":{"signedEntryTimestamp":b64(ECDSA-
#        SHA256 over json.dumps({"body":canonicalizedBody,"integratedTime":T,"logID":hex(keyId),"logIndex":N},sort_keys=True,
#        separators=(",",":")))},"canonicalizedBody":b64(JSON {"apiVersion":"0.0.1","kind":"dsse","spec":{"envelopeHash",
#        "payloadHash":{"algorithm":"sha256","value":<sha256 hex of the DECODED payload>},"signatures":[{"signature":<b64 sig of THIS
#        record>,"verifier":<b64 of THIS record's leaf PEM>}]}})}. Checked against the policy rekor_public_key: the entry must
#        bind THIS record's payload hash, signature AND certificate, name the policy's log (logID = sha256 of its key), carry a valid
#        signed entry timestamp, and have an integrated time inside the certificate's validity. Any other entry kind (a hashedrekord)
#        is refused. Modelled on sigstore-go v1.2.2 pkg/tlog/entry.go (VerifySET, Signature, PublicKey, GetDssePayloadHash),
#        pkg/verify/tlog.go (the dsse payload-hash and certificate comparisons) and protobuf-specs v0.5.1 sigstore_rekor.proto. NO
#        Rekor clone exists under reference/ and the entry here is synthetic: the first real dry run captures a genuine bundle to
#        replace it (Rekor v1 is pinned by the committed cosign-signing-config.json; the log key is the v1 key only).
#        TIMESTAMPS: a record's signatures[0].timestamps[] entry is {"type":"tsp","data":<bare token>} (Witness) or
#        {"type":"rfc3161-response","data":<DER TimeStampResponse>} (a Sigstore bundle); an unknown type is "timestamp ... malformed".
#        EVERY record must be a DSSE envelope with NO duplicate JSON key and EXACTLY ONE signature ("signature").
#        ONE CERTIFICATE, ONE DER (step-8 round 2, NB-1): the certificate field of a record (and the verifier of a Rekor entry's body) is
#        EXACTLY ONE certificate PEM block with nothing but whitespace around it, whose base64 is valid and whose DER is exactly its outer
#        SEQUENCE; anything else ("certificate ... malformed": text or base64 before the block, a second block, bytes after the SEQUENCE) is
#        refused. The identity is read from that DER and openssl verifies a PEM re-made from that same DER, so the two cannot read different bytes.
#        JSON READERS are UTF-8 only: a record, a Rekor entries file, a digest file or a policy written in UTF-16/32 is refused, not guessed.
#        TRUST STORE: the certificate chain is checked against the policy's root ONLY; the system trust store (SSL_CERT_FILE,
#        SSL_CERT_DIR, the OpenSSL default directory) is never consulted ("root").
#   DRY-RUN POLICY AND sign --check (round 7, Opus B-NEW b): `sign --check --policy <a made dry_run policy>` is accepted ONLY to
#       verify Build's record (the hostile hand_sign_code attempt runs exactly that, with the dry policy from `policy make --ref`); the
#       refusal causes it can give are digest and format, never "dry". It is not the sign-only rule of `verify` that refuses dry
#       policies for other stages: sign --check checks Build's record under the dry policy's build identity. N-c: the dry run's own
#       positive control (Sign's dry output, the dry policy, no --now) is covered here only by the synthetic sign_br record; the end to end
#       run is the GitHub dry run itself.
#   chain-verify.py sign --check --signer cosign --digests D.json --build-record REC.json (--template TEMPLATE.json | --policy POLICY.json)
#                   --now ISO8601Z --out DIR [--trust TRUST.json --fulcio-chain F.pem --tsa-chain S.pem --rekor-key K.pem]
#       exactly ONE of --template (the committed template .github/policy/release-policy.template.json, which is what the Sign job passes:
#       its command line is pinned in bin/chain-sign-wiring-test.sh) and --policy (a finished POLICY.json, the dry run's); both or neither is
#       a usage error (exit 2) and a template given as --policy is refused ("policy"). Given --template, sign --check makes the
#       per-tag policy itself (rule 57: from the template, the committed .github/policy/sigstore-trust.json and the PEMs committed next to
#       it, fulcio-chain.pem / tsa-chain.pem / rekor.pub, each overridable by the four flags) with the tag taken from the env var
#       GITHUB_REF, which must be refs/tags/vX.Y.Z (a branch ref or an empty value exits 1 "tag"); a trust hash that differs exits 1 "trust".
#       --now defaults to the current UTC time when absent (the Sign job does not pass it).
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
#       temp file and runs EXACTLY `cosign attest-blob --yes --signing-config <policy dir>/cosign-signing-config.json --statement STATEMENT.json --bundle DIR/provenance.bundle.json`
#       (no --key, no --identity-token, no flag that carries key material: cosign requests the OIDC token inside its own process),
#       then writes (a) DIR/provenance.json = the verify-shape DSSE envelope: payloadType, payload and signatures[0] {sig, certificate =
#       base64 of the PEM of the bundle's leaf, intermediates = the policy's chain, timestamps = [{"type":"rfc3161-response","data":<the bundle's
#       signedTimestamp, a DER TimeStampResponse>}]}; and (b) DIR/provenance.rekor.json = {"entries":[the bundle's tlogEntries, untouched]}.
#       (Witness records carry {"type":"tsp","data":<bare token>}: go-witness timestamp/tsp.go; the verifier reads each form by its type.) Both come from the
#       bundle, so Sign's own output goes straight into `verify` (a case below does it). The Statement's predicate is a real SLSA v1
#       one: buildDefinition present and runDetails.builder.id = the Sign workflow identity URI (.../stage-sign.yml@refs/tags/vX.Y.Z).
#       The tests put a fake `cosign` first on PATH that implements just that call and signs with a local key; bin/install-scanner.sh
#       must gain a checksum-pinned cosign for the Sign job. A failed check writes NOTHING to DIR. DIR never holds private key material.
#       The statement Sign signs also names the source and the run (SLSA v1): buildDefinition.resolvedDependencies[0].digest.gitCommit =
#       $GITHUB_SHA, runDetails.metadata.invocationId = $GITHUB_SERVER_URL/<repository>/actions/runs/$GITHUB_RUN_ID, externalParameters.workflow =
#       the calling workflow (release.yml at the ref). A pushed refs/tags/vX.Y.Z is the only production ref: a workflow_dispatch on a tag is refused.
#   chain-verify.py check-build-record --digests D.json --build-record REC.json (--template T.json | --policy POLICY.json) [--now ..] [--trust ..]
#       exactly the checks Sign makes BEFORE it signs (Build's record genuine under the build identity, D.json is the file the record attests
#       by its sha256, D.json passes the format check) and nothing after: it prints ok, calls no tool and writes no file. The dry run's hostile
#       verify job uses it for the hand-code attempt, so that job holds no signing subcommand at all.
#   chain-verify.py stage-start --stage NAME --previous PREV --record REC.json --digests D.json --policy POLICY.json
#                               --now ISO8601Z [--rekor-stub STUB.json]
#       STAGE PAIRS (rule 58): rebuild<-build, check<-build, sign<-build, release<-{build, sign, rebuild, check}; any other pair is refused
#       ("stage"), so nothing starts from the release policy. A statement whose subject list holds anything but objects is refused by name.
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
# the runner's own GITHUB_REF / GITHUB_EVENT_NAME (refs/pull/N/merge, pull_request ...) must never leak into a case: every case that
# needs them sets both itself (Opus r5 N-b, Sonnet r5 finding 4)
unset GITHUB_REF GITHUB_EVENT_NAME
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
    open(p(t + ".frac.cnf"), "w").write(open(p(t + ".cnf")).read() + "clock_precision_digits = 3\n")   # the same TSA, genTime with milliseconds
def stamp(sigbytes, tsa, response=False, frac=False):
    # Witness stores the bare token (go-witness timestamp/tsp.go returns RawToken); a Sigstore bundle stores the whole DER
    # TimeStampResponse (protobuf-specs sigstore_common.proto RFC3161SignedTimestamp): response=True makes the second form
    q = sh("openssl", "ts", "-query", "-digest", hashlib.sha256(sigbytes).hexdigest(), "-sha256", "-cert", "-no_nonce")
    open(p("q.tsq"), "wb").write(q)
    ca = "tsaroot" if tsa == "tsa" else "othertsaroot"
    sh("openssl", "ts", "-reply", "-queryfile", p("q.tsq"), "-signer", p(tsa + ".pem"), "-inkey", p(tsa + ".key"),
       "-chain", p(ca + ".pem"), "-config", p(tsa + (".frac.cnf" if frac else ".cnf")), "-section", "t", *([] if response else ["-token_out"]), "-out", p("r.tst"))
    return b64(open(p("r.tst"), "rb").read())
def gitoid(data, algo): return hashlib.new(algo, b"blob %d\0" % len(data) + data).hexdigest()
def pae(t, b): return b"DSSEv1 %d %s %d %s" % (len(t), t.encode(), len(b), b)
REPO = "fosterstack/cache"
ISSUER = "https://token.actions.githubusercontent.com"
def uri(wf, ref, repo=REPO): return "https://github.com/%s/.github/workflows/%s@%s" % (repo, wf, ref)
_n = [0]
STMT = {"v0.1": "https://in-toto.io/Statement/v0.1", "v1": "https://in-toto.io/Statement/v1"}
DSSE = "application/vnd.in-toto+json"
PROV_URI = "https://slsa.dev/provenance/v1"
def record(name, wf, ref, ptype, subjects, ca="interm", start=None, end=None, tsa="tsa", signed=True, repo=REPO, issuer=ISSUER,
           stmt="v1", dsse=DSSE, payload=None, config_wf="release.yml", config_ref=None, config_repo=None, no_config=False, no_issuer=False,
           coll_file=None, coll_variant=None, predicate=None, san_der=None):
    _n[0] += 1; leaf = "leaf%d" % _n[0]
    ext = "subjectAltName = critical," + ("DER:" + san_der if san_der else "URI:" + uri(wf, ref, repo))
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
        payload = json.dumps({"_type": STMT[stmt], "predicateType": ptype, "predicate": {"name": "build", "attestations": att}, "subject": subj}).encode()
    if payload is None:
        payload = json.dumps({"_type": STMT[stmt], "predicateType": ptype, "predicate": predicate or {},
                              "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1] if v.startswith("sha256:") else v}} for k, v in subjects.items()]}).encode()
    open(p("pae.bin"), "wb").write(pae(dsse, payload))
    sh("openssl", "dgst", "-sha256", "-sign", p(leaf + ".key"), "-out", p("sig.bin"), p("pae.bin"))
    sig = open(p("sig.bin"), "rb").read()
    chain = [b64(open(p(c + ".pem"), "rb").read()) for c in (("interm", "root") if ca == "interm" else (ca,))]
    s = {"keyid": "", "sig": b64(sig), "certificate": b64(open(p(leaf + ".pem"), "rb").read()), "intermediates": chain}
    if tsa: s["timestamps"] = [{"type": "rfc3161-response" if ptype == PROV_URI else "tsp", "data": stamp(sig, tsa, response=ptype == PROV_URI)}]
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
# the leaf the fake cosign signs with: SAN stage-sign.yml@T, Build Config URI release.yml@T, the GitHub issuer; valid like the others
issue("interm", "fakeleaf", "subjectAltName = critical,URI:" + uri("stage-sign.yml", T) + "\n1.3.6.1.4.1.57264.1.8 = ASN1:UTF8String:" + ISSUER
      + "\n1.3.6.1.4.1.57264.1.18 = ASN1:UTF8String:" + uri("release.yml", T), now - dt.timedelta(minutes=30), now + dt.timedelta(minutes=180))
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
DRYREF = "refs/heads/hostile-proof/x"
add("sign_br", STAGES["sign"], DRYREF, PROV, D, predicate={"dryRun": True})            # what a dry run's Sign writes (SAN ref = the branch, dryRun true)
add("sign_flag_tag", STAGES["sign"], T, PROV, D, predicate={"dryRun": True})         # dryRun true even though the SAN ref IS the tag: Release must still refuse
# branches NAMED like the tag (round 5 Opus B2a): a "last path segment" ref comparison accepts these
add("sign_brtag", STAGES["sign"], "refs/heads/v0.3.0", PROV, D)
add("sign_brrel", STAGES["sign"], "refs/heads/release/v0.3.0", PROV, D)
add("sign_cfg_brtag", STAGES["sign"], T, PROV, D, config_ref="refs/heads/v0.3.0")
add("build_coll_br", STAGES["build"], DRYREF, COLL, None, stmt="v0.1", coll_file="digests.json")
add("build_coll_rc", STAGES["build"], "refs/tags/v0.3.0-rc1", COLL, None, stmt="v0.1", coll_file="digests.json")
add("build_coll_tagx", STAGES["build"], "refs/tags/x", COLL, None, stmt="v0.1", coll_file="digests.json")
add("build_coll_branchx", STAGES["build"], "refs/heads/x", COLL, None, stmt="v0.1", coll_file="digests.json")
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
# step-8 round 1 (Opus N-1, N-5, Sonnet SF3): a record with a repeated JSON key, one with two signatures, one whose SAN is not valid UTF-8,
# and a collection whose subject list holds things that are not subjects
_t = open(p("sign_prov.json")).read(); open(p("sign_dupkey.json"), "w").write(_t.replace('"payloadType"', '"payloadType": "x", "payloadType"', 1))
_j = json.load(open(p("sign_prov.json"))); _j["signatures"] = _j["signatures"] * 2; json.dump(_j, open(p("sign_2sig.json"), "w"))
add("sign_utf8", STAGES["sign"], T, PROV, D, san_der="30048602ff41")
add("build_badsubj", STAGES["build"], T, COLL, None, stmt="v0.1", payload=json.dumps({"_type": STMT["v0.1"], "predicateType": COLL, "predicate": {}, "subject": ["x", 5]}).encode())
add("build_coll_v1", STAGES["build"], T, COLL, None, stmt="v1", coll_file="digests.json")
add("build_coll_scan", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", config_wf="scan.yml")   # stage-build.yml called from scan.yml, not release.yml
add("build_coll_nostamp", STAGES["build"], T, COLL, None, tsa=None, stmt="v0.1", coll_file="digests.json")
add("build_coll_plus", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests-extra.json")
for v in ("wrongname", "dup", "dup2", "bak", "xname", "evilhost", "material", "gitoidonly"): add("build_coll_" + v, STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", coll_variant=v)
add("build_coll_swapped", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests-swapped.json")
for k in FMT: add("build_coll_" + k, STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests-%s.json" % k)
add("build_coll_br_badval", STAGES["build"], DRYREF, COLL, None, stmt="v0.1", coll_file="digests-badval.json")   # a dry-run Build record over a malformed digests file
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
# illustrative: https://in-toto.io/attestation/release/v0.1 is the in-toto *registry release* predicate (in-toto-attestation
# spec/predicates/release.md:74), used here only as a NEGATIVE fixture: it is not the signed policy and must be refused
add("release_stmt_policy", STAGES["release"], T, "https://in-toto.io/attestation/release/v0.1", D)
# step-8 round 2 NB-1 (Opus): the identity must be read from the SAME bytes openssl verifies. A certificate field that holds anything but
# exactly one PEM block is refused: junk base64 or text before a genuine block, a second appended block, bytes after the outer SEQUENCE.
# ATTACK shape: the field = a self-made certificate with the RIGHT identity (issued by an attacker root) followed by a GENUINE certificate of
# ANY identity (chains to the policy root, and its key signed the payload); a reader that takes the first DER for the identity and openssl
# that skips to the genuine block both say yes. ATK is that self-made certificate; each record below is a genuine record or the attack.
add("atk_cert", STAGES["check"], T, COLL, None, stmt="v0.1", coll_file="digests.json", ca="otherroot")
add("check_as_build", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json")   # genuine chain and key, BUILD's identity
def cert_text(name): return base64.b64decode(json.load(open(p(name + ".json")))["signatures"][0]["certificate"]).decode()
def pem_der(text): return base64.b64decode("".join(l for l in text.splitlines() if not l.startswith("-----")))
def to_pem(der): b = base64.b64encode(der).decode(); return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"
def reshape(src, name, fn):
    r = json.load(open(p(src + ".json"))); r["signatures"][0]["certificate"] = b64(fn(cert_text(src)).encode()); json.dump(r, open(p(name + ".json"), "w"))
ATK = cert_text("atk_cert")
# the attacker pads his DER with zero bytes to a multiple of 3 so its base64 has no '=' and survives being concatenated with the genuine block
# (a reader that ignores bytes after the outer SEQUENCE still reads his identity from it)
_ad = pem_der(ATK); ATK_PAD_DER = _ad + b"\x00" * (-len(_ad) % 3); ATK_PAD_PEM = to_pem(ATK_PAD_DER)
CERT_VARIANTS = {
    "junkb64": lambda g: base64.b64encode(ATK_PAD_DER).decode() + "\n" + g,       # base64 of a self-made DER, then the genuine PEM
    "second": lambda g: g + "\n" + ATK,                                              # a second block appended
    "trailing": lambda g: to_pem(pem_der(g) + b"\x00\x00"),                          # bytes after the outer SEQUENCE
    "leadtext": lambda g: "hello\n" + g,                                              # leading garbage text
    "trailtext": lambda g: g + "junk",                                               # garbage after the block
    "attack": lambda g: ATK_PAD_PEM + "\n" + g,                                               # the attack itself: right identity first, genuine block second
}
for src in ("build_coll", "rebuild_coll", "check_coll", "sign_prov"):
    for v, fn in CERT_VARIANTS.items(): reshape(src, src + "_c" + v, fn)
reshape("check_as_build", "check_attack", lambda g: ATK_PAD_PEM + "\n" + g)
reshape("check_as_build", "check_attack_b64", lambda g: base64.b64encode(ATK_PAD_DER).decode() + "\n" + g)   # the coordinator's exact shape: bare base64 then the genuine PEM   # signed by a genuine key of the WRONG identity, field says check
# ---- step-8 round 3: the TIME of a stamp is read from the TSA-signed token, never from the unsigned status section of a response ----
def tlv(tag, c): n = len(c); l = bytes([n]) if n < 128 else (bytes([0x80 | len(n.to_bytes((n.bit_length() + 7) // 8, "big"))]) + n.to_bytes((n.bit_length() + 7) // 8, "big")); return bytes([tag]) + l + c
def rd(b, i):
    ln = b[i + 1]
    if ln < 0x80: return b[i], i + 2, i + 2 + ln
    k = ln & 0x7F; n = int.from_bytes(b[i + 2:i + 2 + k], "big"); return b[i], i + 2 + k, i + 2 + k + n
def inject_status(resp, text):
    """A TimeStampResp whose PKIStatusInfo got a statusString: it sits OUTSIDE the TSA's signature, so the response still verifies."""
    _, s, e = rd(resp, 0); _, ss, se = rd(resp, s)
    status = resp[ss:se] + tlv(0x30, tlv(0x0C, text.encode()))
    return tlv(0x30, tlv(0x30, status) + resp[se:e])
def gmt(x): return "%s %2d %s %d GMT" % (x.strftime("%b"), x.day, x.strftime("%H:%M:%S"), x.year)
def restamp(src, name, kind, inject=None, frac=False, label=None, tsa="tsa"):
    r = json.load(open(p(src + ".json"))); sg = r["signatures"][0]; sigb = base64.b64decode(sg["sig"])
    der = base64.b64decode(stamp(sigb, tsa, response=(kind == "rfc3161-response"), frac=frac))
    if inject: der = inject_status(der, inject)
    sg["timestamps"] = [{"type": label or kind, "data": b64(der)}]; json.dump(r, open(p(name + ".json"), "w"))
WINDOW_MID = gmt(now - dt.timedelta(minutes=90))   # inside the certificate window of the *_sa fixtures (it ended an hour ago)
INJ = "x\nTime stamp: " + WINDOW_MID
add("build_sa", STAGES["build"], T, COLL, None, stmt="v0.1", coll_file="digests.json", start=now - dt.timedelta(minutes=120), end=now - dt.timedelta(minutes=60))
add("rebuild_sa", STAGES["rebuild"], T, COLL, None, stmt="v0.1", coll_file="digests.json", start=now - dt.timedelta(minutes=120), end=now - dt.timedelta(minutes=60))
add("check_sa", STAGES["check"], T, COLL, None, stmt="v0.1", coll_file="digests.json", start=now - dt.timedelta(minutes=120), end=now - dt.timedelta(minutes=60))
restamp("sign_stampafter", "sign_sa_inj", "rfc3161-response", inject=INJ)          # a genuine post-expiry stamp with a backdated TEXT in its status string
for s in ("build", "rebuild", "check"):
    restamp(s + "_sa", s + "_sa_inj", "rfc3161-response", inject=INJ)                 # the same injection on a Witness record that (wrongly) carries a response
    restamp(s + "_coll", s + "_coll_resp", "rfc3161-response")                       # a Witness record carrying a whole response (no injection)
restamp("sign_prov", "sign_prov_tok", "tsp")                                          # a provenance carrying a bare token
restamp("sign_prov", "sign_prov_toklabel", "tsp", label="rfc3161-response")          # token bytes labelled as a response
restamp("sign_prov", "sign_prov_frac", "rfc3161-response", frac=True)                # genTime with milliseconds, genuinely inside the window
# a repeated extension in the certificate (the DER reader used to let the last one win, so a second SAN could replace the first)
OID_SAN, OID_CFG = bytes.fromhex("551d11"), bytes.fromhex("2b06010401" + "83bf30" + "0112")
def dup_ext(der, oid):
    _, s, e = rd(der, 0); _, ts, te = rd(der, s)
    kids = []; i = ts
    while i < te: tg, cs, ce = rd(der, i); kids.append((tg, cs, ce, der[i:ce])); i = ce
    out = []
    for tg, cs, ce, raw in kids:
        if tg == 0xA3:
            _, ls, le = rd(der, cs); exts = []; j = ls
            while j < le: _tg, xs, xe = rd(der, j); exts.append(der[j:xe]); j = xe
            more = [x for x in exts if oid in x[:16]]
            assert more, "extension not found"
            raw = tlv(0xA3, tlv(0x30, b"".join(exts) + more[0]))
        out.append(raw)
    return tlv(0x30, tlv(0x30, b"".join(out)) + der[te:e])
for nm, oid in (("dupsan", OID_SAN), ("dupcfg", OID_CFG)):
    reshape("build_coll", "build_" + nm, lambda g, oid=oid: to_pem(dup_ext(pem_der(g), oid)))
# UTF-16 spellings of the same JSON (json.loads on bytes would guess the encoding from the first bytes)
for src in ("build_coll", "sign_prov"):
    open(p(src + "_u16.json"), "wb").write(open(p(src + ".json"), "rb").read().decode().encode("utf-16"))
# ---- Rekor, in the shape a Sigstore bundle carries it (REAL fields; the first dry run replaces this synthetic entry by a genuine one).
# Modelled on protobuf-specs v0.5.1 sigstore_rekor.proto TransparencyLogEntry (protobuf-JSON: int64 as strings, bytes as base64) and
# sigstore-go v1.2.2 pkg/tlog/entry.go (VerifySET: the log signs the canonical {body, integratedTime, logID, logIndex}; for a DSSE
# entry Signature() and PublicKey() read the body's signatures[0].signature and .verifier, GetDssePayloadHash() its payloadHash).
# The body is a Rekor `dsse` 0.0.1 entry, the kind `cosign attest-blob` writes by default (cosign v3.1.3 options.go rekorEntryTypes).
def tlog_entry(body_obj, idx, key="rekor", logkey="rekor", itime=None, kind="dsse", version="0.0.1"):
    body = b64(json.dumps(body_obj, sort_keys=True, separators=(",", ":")).encode())
    logid = der_sha(p(logkey + ".pub"), True)
    itime = int(now.timestamp()) if itime is None else itime
    open(p("set.bin"), "wb").write(json.dumps({"body": body, "integratedTime": itime, "logID": logid, "logIndex": idx}, sort_keys=True, separators=(",", ":")).encode())
    sh("openssl", "dgst", "-sha256", "-sign", p(key + ".key"), "-out", p("set.sig"), p("set.bin"))
    return {"logIndex": str(idx), "logId": {"keyId": b64(bytes.fromhex(logid))}, "kindVersion": {"kind": kind, "version": version},
            "integratedTime": str(itime), "inclusionPromise": {"signedEntryTimestamp": b64(open(p("set.sig"), "rb").read())}, "canonicalizedBody": body}
def dsse_body(rec_name, body_from=None, cert_from=None, sig_from=None):
    src = json.load(open(p((sig_from or body_from or rec_name) + ".json")))["signatures"][0]
    cert = json.load(open(p((cert_from or body_from or rec_name) + ".json")))["signatures"][0]["certificate"]
    return {"apiVersion": "0.0.1", "kind": "dsse", "spec": {"envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
            "payloadHash": {"algorithm": "sha256", "value": PAY[body_from or rec_name]}, "signatures": [{"signature": src["sig"], "verifier": cert}]}}
def entry(rec_name, idx, key="rekor", body_from=None, logkey="rekor", cert_from=None, itime=None):
    return tlog_entry(dsse_body(rec_name, body_from, cert_from), idx, key, logkey, itime)
dj("rekor.json", {"entries": [entry("sign_prov", 7), entry("release_policy", 8)]})
dj("rekor-empty.json", {"entries": []})
# a Rekor entry whose body names a verifier that is a genuine PEM followed by junk (validly signed by the log): the comparison is by the one DER
_vb = dsse_body("sign_prov"); _vb["spec"]["signatures"][0]["verifier"] = b64(base64.b64decode(_vb["spec"]["signatures"][0]["verifier"]) + b"junk")
dj("rekor-verifierjunk.json", {"entries": [tlog_entry(_vb, 7)]})
open(p("rekor-u16.json"), "wb").write(open(p("rekor.json"), "rb").read().decode().encode("utf-16"))
open(p("digests-u16.json"), "wb").write(open(p("digests.json"), "rb").read().decode().encode("utf-16"))
dj("rekor-br.json", {"entries": [entry("sign_br", 11)]})
dj("rekor-flag.json", {"entries": [entry("sign_flag_tag", 12)]})
dj("rekor-brtag.json", {"entries": [entry("sign_brtag", 13), entry("sign_brrel", 14), entry("sign_cfg_brtag", 15)]})
dj("rekor-other.json", {"entries": [entry("sign_otherdigests", 9)]})
e = entry("sign_prov", 7); e["inclusionPromise"]["signedEntryTimestamp"] = b64(b"\x30\x06\x02\x01\x01\x02\x01\x01"); dj("rekor-badset.json", {"entries": [e]})
dj("rekor-wrongkey.json", {"entries": [entry("sign_prov", 7, "rekor2")]})
e = entry("sign_prov", 7); e["logIndex"] = "99"; dj("rekor-editedidx.json", {"entries": [e]})
e = entry("sign_prov", 7); e["integratedTime"] = str(int(e["integratedTime"]) + 3600); dj("rekor-editedtime.json", {"entries": [e]})
# validly signed by the log, but the integrated time is long after the certificate expired: refused on its own
dj("rekor-latetime.json", {"entries": [entry("sign_prov", 7, itime=int(now.timestamp()) + 3600)]})
# an entry whose body is for another record's SIGNATURE and CERTIFICATE but the right payload hash (validly SET-signed by the log)
dj("rekor-bodysig.json", {"entries": [tlog_entry(dsse_body("sign_prov", cert_from="sign_cfg_rc", sig_from="sign_cfg_rc"), 7)]})
dj("rekor-wronglogid.json", {"entries": [entry("sign_prov", 7, logkey="rekor2")]})          # validly SET-signed, but names another log
dj("rekor-bodycert.json", {"entries": [entry("sign_prov", 7, cert_from="sign_cfg_rc")]})     # right payload hash and signature, ANOTHER record's certificate
# a hashedrekord entry (the kind a MESSAGE signature gets) is not what an attestation gets: refused although validly signed
_hb = {"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": {"data": {"hash": {"algorithm": "sha256", "value": PAY["sign_prov"]}},
       "signature": {"content": json.load(open(p("sign_prov.json")))["signatures"][0]["sig"], "publicKey": {"content": json.load(open(p("sign_prov.json")))["signatures"][0]["certificate"]}}}}
dj("rekor-hashedrekord.json", {"entries": [tlog_entry(_hb, 7, kind="hashedrekord")]})
# the verify times: NOW is 16+ minutes after every default leaf expired (leaf validity [now-5m, now+10m])
open(p("now.txt"), "w").write(fmt(now + dt.timedelta(minutes=26)))
open(p("now-in.txt"), "w").write(fmt(now + dt.timedelta(minutes=2)))
open(p("now-mid.txt"), "w").write(fmt(now + dt.timedelta(minutes=90)))   # inside sign_stampbefore's certificate window
open(p("rekor-len.txt"), "w").write(str(len(PAY)))
e = json.load(open(p("sign_prov.json")))["signatures"][0]
open(p("chk.tst"), "wb").write(base64.b64decode(e["timestamps"][0]["data"]))
sh("openssl", "ts", "-verify", "-digest", hashlib.sha256(base64.b64decode(e["sig"])).hexdigest(), "-in", p("chk.tst"), "-CAfile", p("tsaroot.pem"), "-no_check_time")
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
for k in ("upper", "sha512", "codename", "dotdotname", "hex65", "newline", "prefixed", "emptyname", "underscorename", "emptyobj", "newlinename", "unicodename", "unicodehex", "fullwidthhex"):   # the format cases ATTEST their own file, so equality cannot be what refuses them
    s2 = json.loads(base64.b64decode(r("build_coll_" + k)["payload"]))["subject"][0]["digest"]["sha256"]
    assert s2 == hashlib.sha256(open(w + "/digests-%s.json" % k, "rb").read()).hexdigest(), k
assert r("release_policy")["payloadType"] == "https://witness.testifysec.com/policy/v0.1"
PY

# ---- harness ----------------------------------------------------------------------------------------------------
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
# a fake `cosign` (test-generated, first on PATH): implements only the pinned call
#   cosign attest-blob --yes --signing-config CFG --statement S --bundle B
# (cosign v3.1.3 cmd/cosign/cli/attest_blob.go; options/attest_blob.go: --statement needs no positional argument, --signing-config
# needs --bundle and selects the services, here the committed .github/policy/cosign-signing-config.json that names Rekor v1: the
# default --use-signing-config would pick the TUF-published config, which can name Rekor v2 (tiles, no signed entry timestamp)).
# It signs the DSSE PAE with the fake leaf's key (SAN stage-sign.yml@v0.3.0, Build Config URI release.yml@v0.3.0) and writes a
# bundle in the REAL protobuf-JSON shape (mediaType ...bundle.v0.3+json): dsseEnvelope; verificationMaterial.certificate.rawBytes
# (base64 DER); timestampVerificationData.rfc3161Timestamps[].signedTimestamp = a DER TimeStampResponse (openssl ts -reply without
# -token_out); tlogEntries[] = a Rekor v1 `dsse` entry (logId.keyId, string logIndex/integratedTime, kindVersion, inclusionPromise,
# canonicalizedBody) signed by the test log key. Synthetic: the first real dry run captures a genuine bundle to replace this
# fixture (cosign major version, entry kind and SET shape are confirmed there). The fake records its argv so the test pins it.
# sign converts the bundle: DIR/provenance.json is the verify-shape envelope (certificate = base64 PEM, intermediates = the policy's
# chain, timestamps = [{"type":"rfc3161-response","data":<signedTimestamp>}]) and DIR/provenance.rekor.json = {"entries":[the
# bundle's tlogEntries, untouched]}, so a record Sign wrote can go straight into verify (a case below does exactly that).
cp "$root/.github/policy/cosign-signing-config.json" "$work/cosign-signing-config.json" 2> /dev/null || echo '{"missing":true}' > "$work/cosign-signing-config.json"
mkdir -p "$work/fakebin"
cat > "$work/fakebin/cosign" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >> "$work/cosign-argv.log"
[ "\${1:-}" = attest-blob ] && [ "\${2:-}" = --yes ] && [ "\${3:-}" = --signing-config ] && [ "\${5:-}" = --statement ] && [ "\${7:-}" = --bundle ] && [ "\$#" = 8 ] || { echo "fake cosign: unexpected argv: \$*" >&2; exit 2; }
exec python3 - "\$4" "\$6" "\$8" "$work" <<'PYF'
import base64, datetime as dt, hashlib, json, os, subprocess, sys
cfg, st, out, w = sys.argv[1:5]
SSL = os.environ.get("OPENSSL", "openssl")
def sh(*a): return subprocess.run((SSL,) + a, capture_output=True, check=True).stdout
b64 = lambda b: base64.b64encode(b).decode()
conf = json.load(open(cfg))
assert conf["rekorTlogUrls"][0]["majorApiVersion"] == 1, "the signing config must name Rekor v1"
body = open(st, "rb").read(); pt = "application/vnd.in-toto+json"
pae = b"DSSEv1 %d %s %d %s" % (len(pt), pt.encode(), len(body), body)
open(w + "/fake.pae", "wb").write(pae)
sig = sh("dgst", "-sha256", "-sign", w + "/fakeleaf.key", w + "/fake.pae")
q = sh("ts", "-query", "-digest", hashlib.sha256(sig).hexdigest(), "-sha256", "-cert", "-no_nonce"); open(w + "/fake.tsq", "wb").write(q)
sh("ts", "-reply", "-queryfile", w + "/fake.tsq", "-signer", w + "/tsa.pem", "-inkey", w + "/tsa.key", "-chain", w + "/tsaroot.pem",
   "-config", w + "/tsa.cnf", "-section", "t", "-out", w + "/fake.tsr")
leaf_pem = open(w + "/fakeleaf.pem").read(); leaf_b64 = b64(leaf_pem.encode())
rb = json.dumps({"apiVersion": "0.0.1", "kind": "dsse", "spec": {"envelopeHash": {"algorithm": "sha256", "value": "0" * 64},
      "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(body).hexdigest()}, "signatures": [{"signature": b64(sig), "verifier": leaf_b64}]}},
      sort_keys=True, separators=(",", ":")).encode()
logid = hashlib.sha256(sh("pkey", "-pubin", "-in", w + "/rekor.pub", "-outform", "DER")).hexdigest()
itime = int(dt.datetime.now(dt.timezone.utc).timestamp())
canon = b64(rb)
open(w + "/fake.set", "wb").write(json.dumps({"body": canon, "integratedTime": itime, "logID": logid, "logIndex": 4242}, sort_keys=True, separators=(",", ":")).encode())
tl = {"logIndex": "4242", "logId": {"keyId": b64(bytes.fromhex(logid))}, "kindVersion": {"kind": "dsse", "version": "0.0.1"}, "integratedTime": str(itime),
      "inclusionPromise": {"signedEntryTimestamp": b64(sh("dgst", "-sha256", "-sign", w + "/rekor.key", w + "/fake.set"))}, "canonicalizedBody": canon}
der = sh("x509", "-in", w + "/fakeleaf.pem", "-outform", "DER")
json.dump({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
           "verificationMaterial": {"certificate": {"rawBytes": b64(der)}, "tlogEntries": [tl],
                                     "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": b64(open(w + "/fake.tsr", "rb").read())}]}},
           "dsseEnvelope": {"payloadType": pt, "payload": b64(body), "signatures": [{"sig": b64(sig), "keyid": ""}]}}, open(out, "w"))
PYF
FAKE
chmod +x "$work/fakebin/cosign"
PY3=$(command -v python3)
MARK="$work/.start-marker"; : > "$MARK"
: > "$work/cosign-all.log"; SIGNS_OK=0; LEAKS=0
ARGV_RE='^attest-blob --yes --signing-config [^ ]+/cosign-signing-config\.json --statement [^ ]+ --bundle [^ ]+/provenance\.bundle\.json$'
SENT_TOK="SENTINEL-TOKEN-$$-7f3a"; SENT_URL="SENTINEL-URL-$$-9c1d"; SENT_CIT="SENTINEL-CIT-$$-2b8e"
# run ARGS...: the verifier under the network cut; PATH (fake cosign first), OPENSSL and GITHUB_REF are passed THROUGH `env` so
# sudo's env_reset/secure_path (the ubuntu-24.04 fallback) cannot drop them; the fake's argv log is per run and appended to a total
run() { : > "$work/cosign-argv.log"; local rc=0
  "${netcut[@]+"${netcut[@]}"}" env PATH="$work/fakebin:$PATH" OPENSSL="$OPENSSL" GITHUB_REF="${GITHUB_REF:-}" GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-}" \
    ${SSL_CERT_FILE:+SSL_CERT_FILE=$SSL_CERT_FILE} ${SSL_CERT_DIR:+SSL_CERT_DIR=$SSL_CERT_DIR} \
    ${GITHUB_SHA:+GITHUB_SHA=$GITHUB_SHA} ${GITHUB_RUN_ID:+GITHUB_RUN_ID=$GITHUB_RUN_ID} ${GITHUB_SERVER_URL:+GITHUB_SERVER_URL=$GITHUB_SERVER_URL} \
    ACTIONS_ID_TOKEN_REQUEST_TOKEN="$SENT_TOK" ACTIONS_ID_TOKEN_REQUEST_URL="https://token.invalid/$SENT_URL" COSIGN_IDENTITY_TOKEN="$SENT_CIT" \
    "$PY3" "$cv" "$@" 2> "$work/err" > "$work/out" || rc=$?
  if grep -F -q -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" "$work/err" "$work/out" "$work/cosign-argv.log" 2> /dev/null; then LEAKS=$((LEAKS + 1)); fi
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
# must also never have been called (the check comes BEFORE the signature: Opus r3 B1).
expect_refuse() { local l=$1 w=$2 x=; shift 2; local rc=0 miss=0 l1 st reason; run "$@" || rc=$?
  l1=$(head -n 1 "$work/err" | tr 'A-Z' 'a-z')
  if printf '%s' "$l1" | grep -E -q '^refused at [a-z]+: .'; then
    st=$(printf '%s' "$l1" | sed -E 's/^refused at ([a-z]+): .*/\1/'); reason=${l1#*: }
    reason=${reason//"$(printf '%s' "$work" | tr 'A-Z' 'a-z')"/}   # round 8: the random mktemp path can never stand in for (or against) a cause word
    IFS='|' read -r -a ws <<< "$w"
    for x in "${ws[@]}"; do
      case $x in
        '!'*) ! printf '%s' "$reason" | grep -F -q -- "${x#!}" || miss=1 ;;          # a word the reason must NOT contain (the other causes)
        *) [ "$x" = "$st" ] || printf '%s' "$reason" | grep -F -q -- "$x" || miss=1 ;;
      esac
    done
  else miss=1; fi
  if [ "$rc" = 1 ] && [ "$miss" = 0 ] && ! crashed && { [ "${1:-}" != sign ] || [ ! -s "$work/cosign-argv.log" ]; }; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with first line 'refused at <stage>: ...' and '$w'; fake cosign called: $([ -s "$work/cosign-argv.log" ] && echo YES || echo no); $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
mkpol() { run policy make --template "$work/template.json" --tag v0.3.0 --trust "${2:-$work/trust.json}" \
  --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --out "$work/$1"; }
V() { echo --policy "$work/policy.json" --now "${1:-$NOW}"; }
R() { echo --rekor-stub "$work/${1:-rekor.json}"; }
rec() { echo --record "$work/$1.json"; }
ST() { local cur=$1 prev=$2; shift 2; echo stage-start --stage "$cur" --previous "$prev" --policy "$work/policy.json" --now "$NOW" "$@"; }

# ---- REQ-CHAIN-002-AC2: the per-tag policy ----------------------------------------------------------------------
rc=0; mkpol policy.json || rc=$?; [ "$rc" = 0 ] && ok "002-AC2 policy for v0.3.0 is made from the template" || bad "002-AC2 policy make (exit $rc)"
for c in badroot:"a Fulcio root" badtsa:"a timestamp authority root" badrekor:"a Rekor key"; do
  k=${c%%:*}; rc=0; mkpol "policy-$k.json" "$work/trust-$k.json" || rc=$?
  { [ "$rc" = 1 ] && grep -F -q -i trust "$work/err" && ! crashed; } && ok "002-AC2 ${c#*:} whose hash differs from the trust file is refused" || bad "002-AC2 $k hash (exit $rc)"
done
expect_ok     "002-AC2 sign file at v0.3.0 is accepted as stage sign" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_refuse "002-AC2 sibling file at the same tag is refused" "other.yml|!digest|!timestamp|!rekor|!signature" verify $(V) --stage sign $(rec sibling_as_sign) $(R)
expect_refuse "002-AC2 the same file at another tag is refused" "v0.3.1" verify $(V) --stage sign $(rec sign_othertag) $(R)
expect_refuse "002-AC2 a tag that only starts like the tag (v0.3.0-rc1) is refused" "v0.3.0-rc1" verify $(V) --stage sign $(rec sign_rc) $(R)
expect_refuse "002-AC2 the same file on a branch is refused" "refs/heads/main" verify $(V) --stage sign $(rec sign_branch) $(R)
expect_refuse "002-AC2 a file whose name merely starts with stage-sign.yml is refused" "stage-sign.yml.evil" verify $(V) --stage sign $(rec evilext_as_sign) $(R)
expect_refuse "002-AC2 a file whose name merely ends with stage-sign.yml is refused" "xstage-sign.yml" verify $(V) --stage sign $(rec xprefix_as_sign) $(R)
expect_refuse "002-AC2 the right file in another repository is refused" "attacker/cache" verify $(V) --stage sign $(rec sign_wrongrepo) $(R)
expect_refuse "002-AC2 a certificate from another OIDC issuer is refused" "issuer|!digest|!timestamp|!rekor" verify $(V) --stage sign $(rec sign_badissuer) $(R)
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
assert set(t) - {"_note"} == {"fulcio_root_sha256", "tsa_root_sha256", "rekor_sha256"} and all(re.fullmatch(r"[0-9a-f]{64}", t[k]) for k in t if k != "_note"), t
# the Rekor key hash is NOT recorded by any spike, so this test cannot pin it to a known value: the implementation PR must source it
# from Sigstore's published trusted_root.json (tlogs[].publicKey) and say so in _note; an unexplained 64-hex value fails here
assert "trusted_root" in t.get("_note", ""), "rekor_sha256 needs a _note naming its source (trusted_root.json tlogs publicKey)"
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
expect_refuse "001-AC4 a Witness collection signed by Sign is refused (Sign signs provenance only)" "predicate" verify $(V) --stage sign $(rec sign_coll)
expect_refuse "001-AC4 SLSA provenance v0.2 is not the allowed type" "predicate" verify $(V) --stage sign $(rec sign_prov_v0.2) $(R)

# ---- REQ-CHAIN-002-AC1: timestamps, checked 16 minutes after the certificate expired, offline ----------------------
expect_ok     "002-AC1 expired certificate + valid stamp from the policy's authority, verified 16 min after expiry" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_ok     "002-AC1 the same record inside the certificate window" verify $(V $NOWIN) --stage sign $(rec sign_prov) $(R)
expect_refuse "002-AC1 no timestamp after expiry is refused" "timestamp|!signature|!identity|!rekor" verify $(V) --stage sign $(rec sign_nostamp) $(R)
expect_refuse "002-AC1 a stamp from another authority is refused" "timestamp" verify $(V) --stage sign $(rec sign_othertsa) $(R)
expect_refuse "002-AC1 a stamp BEFORE the certificate's validity is refused even when --now is inside the window" "validity" verify $(V $NOWMID) --stage sign $(rec sign_stampbefore) $(R)
expect_refuse "002-AC1 a stamp AFTER the certificate expired is refused" "validity" verify $(V) --stage sign $(rec sign_stampafter) $(R)
# round 8 (Opus N-a, taken without faketime): with NO --now the default clock (the current UTC time) still judges the stamp against the certificate's
# window. This certificate's window ended an hour before it was issued and the stamp is dated now, so an implementation that skips the time checks when --now is
# absent accepts it and fails here; a correct one refuses it as a validity failure.
expect_refuse "002-AC1 no --now: a stamp after the certificate expired is still refused (the default clock does not skip the validity check)" "validity" verify --policy "$work/policy.json" --stage sign $(rec sign_stampafter) $(R)
expect_refuse "002-AC1 tamper: payload changed after signing is refused" "signature|!timestamp|!rekor|!identity" verify $(V) --stage sign $(rec sign_tamper_payload) $(R)
expect_refuse "002-AC1 tamper: signature bytes altered is refused" "signature|!timestamp|!rekor|!identity" verify $(V) --stage sign $(rec sign_tamper_sig) $(R)
expect_refuse "002-AC1 tamper: a stamp taken over a different signature is refused" "timestamp" verify $(V) --stage sign $(rec sign_tamper_stamp) $(R)
expect_refuse "002-AC1 an unsigned record is refused" "signature|!timestamp|!identity" verify $(V) --stage sign $(rec sign_unsigned) $(R)
python3 - "$work/policy.json" "$work/policy-notsa.json" 2> /dev/null <<'PY' || true
import json, sys
d = json.load(open(sys.argv[1])); d["timestampauthorities"] = {}; json.dump(d, open(sys.argv[2], "w"))
PY
true
expect_refuse "002-AC1 a policy naming no authority refuses even a valid stamp" "timestamp" verify --policy "$work/policy-notsa.json" --now "$NOW" --stage sign $(rec sign_prov) $(R)

# ---- REQ-CHAIN-002-AC3: Rekor for everything but Witness collections; the entry must be for THIS record ------------
expect_ok     "002-AC3 provenance with a matching, correctly signed Rekor entry is accepted" verify $(V) --stage sign $(rec sign_prov) $(R)
expect_refuse "002-AC3 provenance with no Rekor entry is refused" "rekor|!identity|!signature|!timestamp|!digest" verify $(V) --stage sign $(rec sign_prov) $(R rekor-empty.json)
expect_refuse "002-AC3 provenance is refused when no Rekor source is given (the type decides, not a flag)" "rekor" verify $(V) --stage sign $(rec sign_prov)
expect_refuse "002-AC3 an entry for a DIFFERENT record's payload is refused" "rekor|!identity|!timestamp" verify $(V) --stage sign $(rec sign_prov) $(R rekor-other.json)
expect_refuse "002-AC3 an entry whose signed entry timestamp is garbage is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-badset.json)
expect_refuse "002-AC3 an entry signed by a key that is not the policy's Rekor key is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-wrongkey.json)
expect_refuse "002-AC3 an entry whose log index was edited after signing is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-editedidx.json)
expect_refuse "002-AC3 an entry whose integrated time was edited after signing is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-editedtime.json)
expect_refuse "002-AC3 an entry with the right payload hash but another record's signature and certificate in its body (validly signed by the log) is refused" "rekor|signature" verify $(V) --stage sign $(rec sign_prov) $(R rekor-bodysig.json)
expect_refuse "002-AC3 an entry validly signed by the log but naming ANOTHER log (logID is not the sha256 of the policy's Rekor key) is refused" "rekor|log" verify $(V) --stage sign $(rec sign_prov) $(R rekor-wronglogid.json)
expect_refuse "002-AC3 an entry with the right payload hash and signature but ANOTHER record's certificate in its body is refused" "rekor|certificate" verify $(V) --stage sign $(rec sign_prov) $(R rekor-bodycert.json)
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
if [ -f "$work/cosign-argv.log" ] && grep -E -q "$ARGV_RE" "$work/cosign-argv.log" \
   && ! grep -E -q -- '--key|--identity-token|--sk|--output-key|--use-signing-config|--fulcio|--rekor|--tlog-upload' "$work/cosign-argv.log"; then
  ok "001-AC3 sign runs exactly 'cosign attest-blob --yes --signing-config <committed config> --statement S --bundle DIR/provenance.bundle.json', with no key, token or endpoint flag"
else bad "001-AC3 the cosign invocation is not the pinned one ($(tr '\n' ' ' < "$work/cosign-argv.log" 2> /dev/null | head -c 200))"; fi
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
# the provenance says what was built from which source in which run (SLSA v1 buildDefinition / runDetails), from GitHub's own variables
GITHUB_SHA=0123456789abcdef0123456789abcdef01234567 GITHUB_RUN_ID=424242 run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/meta" || true
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
# sign's OWN output goes straight through verify (the bundle shape and the verify shape cannot drift): the envelope Sign wrote with its
# certificate, the policy's intermediates and the timestamp, and the Rekor entries Sign extracted from the bundle
expect_ok     "001-AC4 the provenance Sign itself wrote verifies as stage sign with the Rekor entry Sign extracted (the two shapes agree)" verify $(V) --stage sign --record "$work/sd/ok/provenance.json" --rekor-stub "$work/sd/ok/provenance.rekor.json"
# the dry run's POSITIVE CONTROL line, exactly (no --now: the default is the current UTC time; the stub is the one Sign extracted)
expect_ok     "001-AC5 positive-control shape: verify --stage sign --record <Sign's output> --policy P --rekor-stub <Sign's stub>, with NO --now, is accepted" verify --stage sign --record "$work/sd/ok/provenance.json" --policy "$work/policy.json" --rekor-stub "$work/sd/ok/provenance.rekor.json"
expect_refuse "001-AC5 Sign's own output verified WITHOUT the stub is refused 'rekor' (a control without the pinned --rekor-stub could not pass by a shortcut)" "rekor" verify --stage sign --record "$work/sd/ok/provenance.json" --policy "$work/policy.json"
expect_ok     "002-AC1 verify with no --now uses the current time: a record generated seconds ago is accepted" verify --policy "$work/policy.json" --stage sign $(rec sign_prov) $(R)
expect_ok     "003-AC1 and release <- sign accepts Sign's own output for exactly the digests it signed" $(ST release sign) --record "$work/sd/ok/provenance.json" --rekor-stub "$work/sd/ok/provenance.rekor.json" --digests "$work/digests.json"
rc=0; run sign --check --signer cosign --build-record "$work/build_coll_tampered.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/bad" || rc=$?
if [ "$rc" = 1 ] && [ -z "$(ls -A "$work/sd/bad" 2> /dev/null)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "001-AC2 a failed check writes NOTHING to the output folder and never calls cosign"; else bad "001-AC2 a failed check left output or called cosign (exit $rc)"; fi
rc=0; run sign --check --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests-other.json" --out "$work/sd/bad2" || rc=$?
if [ "$rc" = 1 ] && [ -z "$(ls -A "$work/sd/bad2" 2> /dev/null)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "001-AC2 replay: provenance is not written, and cosign is not called, for digests Build did not attest"; else bad "001-AC2 replay with other digests wrote output (exit $rc)"; fi
rc=0; run sign --signer cosign --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/nocheck" || rc=$?
if [ "$rc" = 1 ] && ! crashed && [ -z "$(ls -A "$work/sd/nocheck" 2> /dev/null)" ] && [ ! -s "$work/cosign-argv.log" ]; then ok "001-AC2 sign without --check is not a mode: it refuses, calls no cosign and writes nothing"; else bad "001-AC2 sign without --check wrote output (exit $rc)"; fi

# the Sign job passes the committed TEMPLATE as --policy: sign --check makes the per-tag policy itself (rule 57) from the template,
# the committed trust file and PEMs (defaults next to the template, overridable by flags) and the tag from GITHUB_REF
TP() { echo sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/template.json" --trust "$work/trust.json" \
  --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/$1"; }
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "001-AC2 --policy the template + GITHUB_REF=refs/tags/v0.3.0: the per-tag policy is made and Build's record verifies" $(TP tpl1)
GITHUB_REF=refs/heads/main GITHUB_EVENT_NAME=push expect_refuse "001-AC2 template mode on a branch (GITHUB_REF is not a tag) is refused" "tag|github_ref" $(TP tpl2)
GITHUB_REF=refs/tags/v0.3.1 GITHUB_EVENT_NAME=push expect_refuse "001-AC2 template mode at v0.3.1 refuses a Build record signed at v0.3.0" "v0.3.1|v0.3.0" $(TP tpl3)
GITHUB_REF= GITHUB_EVENT_NAME=push expect_refuse "001-AC2 template mode with no GITHUB_REF is refused" "tag|github_ref" $(TP tpl4)
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_refuse "001-AC2 template mode with a trust file whose hash differs is refused" "trust" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/template.json" --trust "$work/trust-badroot.json" --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/tpl5"


# ---- production vs dry run (round 5): the ref shapes, the dry-run mode, and Release's tag-pinned refusal of any branch record ----------
TPR() { echo sign --check --signer cosign --build-record "$work/$1.json" --template "$work/template.json" --trust "$work/trust.json" \
  --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/$2"; }
GITHUB_REF=refs/tags/v0.3.0-rc1 GITHUB_EVENT_NAME=push expect_refuse "001-AC2 production: refs/tags/v0.3.0-rc1 is not vX.Y.Z and is refused (even with a Build record signed at that ref)" "tag" $(TPR build_coll_rc tagrc)
GITHUB_REF=refs/tags/x GITHUB_EVENT_NAME=push expect_refuse "001-AC2 production: refs/tags/x is refused" "tag" $(TPR build_coll_tagx tagx)
GITHUB_REF=refs/heads/x GITHUB_EVENT_NAME=push expect_refuse "001-AC2 production: a branch on a push event is refused" "tag" $(TPR build_coll_branchx branchx)
GITHUB_REF=refs/tags/x GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 a workflow_dispatch on a tag that is not vX.Y.Z is refused (dry run is for branches)" "tag" $(TPR build_coll_tagx dispx)
for ev in schedule pull_request pull_request_target repository_dispatch; do
  GITHUB_REF=refs/heads/x GITHUB_EVENT_NAME=$ev expect_refuse "001-AC2 event $ev on a branch is neither production nor a dry run: refused, no record" "tag" $(TPR build_coll_branchx evb-$ev)
  GITHUB_REF=refs/pull/1/merge GITHUB_EVENT_NAME=$ev expect_refuse "001-AC2 event $ev on refs/pull/1/merge is refused" "tag" $(TPR build_coll_branchx evp-$ev)
done
GITHUB_REF=refs/pull/1/merge GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 workflow_dispatch on refs/pull/1/merge (not a branch) is refused" "tag" $(TPR build_coll_branchx evpd)
GITHUB_REF= GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 workflow_dispatch with an EMPTY ref is refused" "tag" $(TPR build_coll_branchx evempty)
GITHUB_REF=main GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC2 workflow_dispatch with a ref that is not fully qualified (main) is refused" "tag" $(TPR build_coll_branchx evbare)
GITHUB_REF=refs/heads/x GITHUB_EVENT_NAME= expect_refuse "001-AC2 an empty event name on a branch is refused" "tag" $(TPR build_coll_branchx evnone)
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_ok "001-AC2 DRY RUN: workflow_dispatch on a branch makes the policy for that ref and signs" $(TPR build_coll_br br1)
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
rc=0; run policy make --template "$work/template.json" --ref refs/heads/hostile-proof/x --trust "$work/trust.json" --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --out "$work/policy-br.json" || rc=$?
[ "$rc" = 0 ] && python3 -c 'import json,sys; p=json.load(open(sys.argv[1])); sys.exit(0 if p.get("dry_run") is True and p["stages"]["sign"]["identity"].endswith("stage-sign.yml@refs/heads/hostile-proof/x") else 1)' "$work/policy-br.json" && ok "002-AC2 policy make --ref <branch> makes a dry_run policy whose identities end @ that ref" || bad "002-AC2 policy make --ref <branch> (exit $rc)"
for r in refs/tags/v0.3.0-rc1 refs/tags/x refs/pull/1/merge; do
  expect_refuse "002-AC2 policy make --ref $r is refused" "tag" policy make --template "$work/template.json" --ref "$r" --trust "$work/trust.json" --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --out "$work/policy-bad.json"
done
rc=0; run policy make --template "$work/template.json" --ref refs/tags/v0.3.0 --trust "$work/trust.json" --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --out "$work/policy-reftag.json" || rc=$?
[ "$rc" = 0 ] && cmp -s "$work/policy.json" "$work/policy-reftag.json" && ok "002-AC2 policy make --ref refs/tags/v0.3.0 is the same policy as --tag v0.3.0" || bad "002-AC2 --ref on the exact tag differs from --tag (exit $rc)"
expect_ok     "002-AC2 the dry-run policy accepts Sign's record at the dry-run ref (the positive control passes)" verify --policy "$work/policy-br.json" --now "$NOW" --stage sign $(rec sign_br) $(R rekor-br.json)
expect_refuse "002-AC2 RELEASE'S TAG-PINNED POLICY REFUSES a Sign record whose SAN ref is a branch: a dry run can never be accepted" "refs/heads/hostile-proof/x" verify $(V) --stage sign $(rec sign_br) $(R rekor-br.json)
expect_refuse "002-AC2 round 5 B2a: a BRANCH named like the tag (refs/heads/v0.3.0) is refused by the tag policy (the ref is compared whole, not by its last segment)" "refs/heads/v0.3.0" verify $(V) --stage sign $(rec sign_brtag) $(R rekor-brtag.json)
expect_refuse "002-AC2 round 5 B2a: refs/heads/release/v0.3.0 is refused" "refs/heads/release/v0.3.0" verify $(V) --stage sign $(rec sign_brrel) $(R rekor-brtag.json)
expect_refuse "002-AC2 round 5 B2a: right SAN but the calling workflow ref is the BRANCH refs/heads/v0.3.0 is refused" "refs/heads/v0.3.0" verify $(V) --stage sign $(rec sign_cfg_brtag) $(R rekor-brtag.json)
expect_refuse "002-AC2 round 5 B2b: a Sign record whose predicate says dryRun true is refused under the TAG policy even though its SAN ref is the tag" "dry" verify $(V) --stage sign $(rec sign_flag_tag) $(R rekor-flag.json)
expect_refuse "003-AC1 round 5 B2b: release <- sign with a dryRun-true record at the tag is refused: names sign and dry" "sign|dry" $(ST release sign) $(rec sign_flag_tag) $(R rekor-flag.json) --digests "$work/digests.json"
expect_refuse "003-AC1 round 5 B2b: stage-start refuses a dry_run POLICY (release <- sign, a dry record): names dry" "dry" stage-start --stage release --previous sign --policy "$work/policy-br.json" --now "$NOW" $(rec sign_br) $(R rekor-br.json) --digests "$work/digests.json"
expect_refuse "003-AC1 round 5 B2b: stage-start refuses a dry_run policy for every stage (rebuild <- build)" "dry" stage-start --stage rebuild --previous build --policy "$work/policy-br.json" --now "$NOW" $(rec build_coll_br) --digests "$work/digests.json"
expect_refuse "002-AC2 round 5 B2b: verify with a dry_run policy is for stage sign ONLY (stage build is refused)" "dry" verify --policy "$work/policy-br.json" --now "$NOW" --stage build $(rec build_coll_br)
expect_refuse "002-AC2 round 5 B2b: verify with a dry_run policy is for stage sign ONLY (stage release is refused)" "dry" verify --policy "$work/policy-br.json" --now "$NOW" --stage release $(rec release_policy) $(R)
expect_refuse "003-AC1 release <- sign with a dry-run record is refused: names sign and the branch ref" "sign|refs/heads/hostile-proof/x" $(ST release sign) $(rec sign_br) $(R rekor-br.json) --digests "$work/digests.json"
# template mode with the DEFAULT locations (no override flags) in a copy of the policy folder, and a drifted default PEM
mkdir -p "$work/polcopy"; cp "$work/template.json" "$work/polcopy/release-policy.template.json"; cp "$work/trust.json" "$work/polcopy/sigstore-trust.json"
cp "$work/fulcio-chain.pem" "$work/polcopy/fulcio-chain.pem"; cp "$work/tsa-chain.pem" "$work/polcopy/tsa-chain.pem"; cp "$work/rekor.pub" "$work/polcopy/rekor.pub"; cp "$work/cosign-signing-config.json" "$work/polcopy/cosign-signing-config.json"
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "002-AC2 template mode with NO override flags uses the committed defaults next to the template (the production invocation)" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/polcopy/release-policy.template.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/default1"
cp "$work/othertsaroot.pem" "$work/polcopy/tsa-chain.pem"
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_refuse "002-AC2 a default PEM that no longer matches sigstore-trust.json is refused" "trust" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/polcopy/release-policy.template.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/default2"
cp "$work/tsa-chain.pem" "$work/polcopy/tsa-chain.pem"; cp "$work/otherroot.pem" "$work/polcopy/fulcio-chain.pem"
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_refuse "002-AC2 a default Fulcio chain that no longer matches sigstore-trust.json is refused" "trust" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/polcopy/release-policy.template.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/default3"
cp "$work/fulcio-chain.pem" "$work/polcopy/fulcio-chain.pem"; cp "$work/rekor2.pub" "$work/polcopy/rekor.pub"
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_refuse "002-AC2 a default Rekor key that no longer matches sigstore-trust.json is refused" "trust" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/polcopy/release-policy.template.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/default4"
cp "$work/rekor.pub" "$work/polcopy/rekor.pub"
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "002-AC2 with all three default PEMs restored the production invocation succeeds again (the refusals were about the drift)" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/polcopy/release-policy.template.json" --now "$NOW" --digests "$work/digests.json" --out "$work/sd/default5"
# ---- round 7 (Opus B-NEW a): policy make with NO file flags (the dry run's and Release's pinned lines), defaults next to the template ----
rc=0; run policy make --template "$work/polcopy/release-policy.template.json" --tag v0.3.0 --out "$work/polcopy-made.json" || rc=$?
[ "$rc" = 0 ] && cmp -s "$work/policy.json" "$work/polcopy-made.json" && ok "002-AC2 policy make --tag with NO file flags uses the defaults next to the template and equals the policy made with explicit files (Release's pinned line)" || bad "002-AC2 policy make --tag with no file flags (exit $rc)"
rc=0; run policy make --template "$work/polcopy/release-policy.template.json" --ref refs/tags/v0.3.0 --out "$work/polcopy-made-ref.json" || rc=$?
[ "$rc" = 0 ] && cmp -s "$work/policy.json" "$work/polcopy-made-ref.json" && ok "002-AC2 policy make --ref refs/tags/v0.3.0 with NO file flags equals the --tag policy" || bad "002-AC2 policy make --ref on the tag with no file flags (exit $rc)"
rc=0; run policy make --template "$work/polcopy/release-policy.template.json" --ref refs/heads/hostile-proof/x --out "$work/polcopy-made-br.json" || rc=$?
[ "$rc" = 0 ] && cmp -s "$work/policy-br.json" "$work/polcopy-made-br.json" && ok "002-AC2 policy make --ref <branch> with NO file flags equals the dry-run policy (the dry run's pinned line)" || bad "002-AC2 policy make --ref <branch> with no file flags (exit $rc)"
for c in tsa-chain:othertsaroot:"TSA" fulcio-chain:otherroot:"Fulcio"; do
  f=${c%%:*}; r=${c#*:}; r=${r%%:*}; cp "$work/polcopy/$f.pem" "$work/$f.keep"; cp "$work/$r.pem" "$work/polcopy/$f.pem"
  expect_refuse "002-AC2 policy make --tag with a drifted default ${c##*:} chain and no file flags is refused" "trust" policy make --template "$work/polcopy/release-policy.template.json" --tag v0.3.0 --out "$work/polcopy-drift.json"
  cp "$work/$f.keep" "$work/polcopy/$f.pem"
done
cp "$work/rekor2.pub" "$work/polcopy/rekor.pub"
expect_refuse "002-AC2 policy make --tag with a drifted default Rekor key and no file flags is refused" "trust" policy make --template "$work/polcopy/release-policy.template.json" --tag v0.3.0 --out "$work/polcopy-drift.json"
cp "$work/rekor.pub" "$work/polcopy/rekor.pub"
expect_refuse "002-AC2 policy make --ref <branch> given a trust file whose hashes differ from the committed PEMs is refused too (the dry run trusts nothing the committed hashes do not)" "trust" policy make --template "$work/polcopy/release-policy.template.json" --ref refs/heads/hostile-proof/x --trust "$work/trust-badtsa.json" --out "$work/polcopy-drift.json"
# ---- round 7 (Opus B-NEW b, Sonnet findings 1-3): the dry run's pinned hostile lines can reach their causes ----------------------------
# (1) verify --stage sign with NO --rekor-stub: identity / build config is checked BEFORE Rekor, so a hostile record is refused for the
#     attack, never for the missing stub ("!rekor" is what makes an implementation that checks Rekor first fail here)
expect_refuse "001-AC5 hostile row shape (no stub): a second workflow that calls stage-sign.yml is refused for its Build Config, not for Rekor" "other-caller.yml|!rekor" verify $(V) --stage sign $(rec sign_othercaller)
expect_refuse "001-AC5 hostile row shape (no stub): provenance signed by Build's identity is refused for the identity, not for Rekor" "stage-build.yml|!rekor" verify $(V) --stage sign $(rec build_as_sign)
expect_refuse "001-AC5 hostile row shape (no stub): a certificate with no Build Config URI is refused for that, not for Rekor" "build config|!rekor" verify $(V) --stage sign $(rec sign_noconfig)
expect_refuse "001-AC5 hostile row shape under the DRY policy (no stub): Build's identity is refused for the identity, not for Rekor" "stage-build.yml|!rekor" verify --policy "$work/policy-br.json" --now "$NOW" --stage sign $(rec build_as_sign)
# (2) sign --check under a made DRY policy (the hand_sign_code attempt): refused for digest or format, never for "dry"; cosign never called
DSC() { echo sign --check --signer cosign --build-record "$work/$1.json" --policy "$work/policy-br.json" --now "$NOW" --digests "$work/$2.json" --out "$work/sd/$3"; }
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC5 sign --check --policy <dry policy>: digests Build did not attest are refused 'digest', not 'dry'" "digest|!dry" $(DSC build_coll_br digests-other dsc1)
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_refuse "001-AC5 sign --check --policy <dry policy>: malformed digests Build attested are refused 'format', not 'dry'" "format|!dry" $(DSC build_coll_br_badval digests-badval dsc2)
GITHUB_REF=refs/heads/hostile-proof/x GITHUB_EVENT_NAME=workflow_dispatch expect_ok "001-AC5 sign --check --policy <dry policy>: valid digests Build attested are accepted (so the two refusals above are about the digests)" $(DSC build_coll_br digests dsc3)
GITHUB_REF=refs/tags/v0.3.0 GITHUB_EVENT_NAME=push expect_ok "001-AC2 sign --check with no --now (the Sign job passes none) uses the current time" sign --check --signer cosign --build-record "$work/build_coll.json" --template "$work/template.json" --trust "$work/trust.json" --fulcio-chain "$work/fulcio-chain.pem" --tsa-chain "$work/tsa-chain.pem" --rekor-key "$work/rekor.pub" --digests "$work/digests.json" --out "$work/sd/nonow"
python3 - "$root" "$OPENSSL" 2> /dev/null <<'PY' && ok "002-AC2 the committed fulcio-chain.pem, tsa-chain.pem and rekor.pub hash to the values in sigstore-trust.json" || bad "002-AC2 committed PEMs missing, or their sha256(DER) differs from sigstore-trust.json"
import hashlib, json, re, subprocess, sys
root, ssl = sys.argv[1], sys.argv[2]
pol = root + "/.github/policy/"; tr = json.load(open(pol + "sigstore-trust.json"))
def first_cert_der(path):
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", open(path).read(), re.S)
    return subprocess.run([ssl, "x509", "-outform", "DER"], input=m.group(0).encode(), capture_output=True, check=True).stdout
assert hashlib.sha256(first_cert_der(pol + "fulcio-chain.pem")).hexdigest() == tr["fulcio_root_sha256"]
assert hashlib.sha256(first_cert_der(pol + "tsa-chain.pem")).hexdigest() == tr["tsa_root_sha256"]
der = subprocess.run([ssl, "pkey", "-pubin", "-in", pol + "rekor.pub", "-outform", "DER"], capture_output=True, check=True).stdout
assert hashlib.sha256(der).hexdigest() == tr["rekor_sha256"]
PY

# ---- REQ-CHAIN-003-AC1: each stage verifies the one before it, with the cause named ------------------------------------
expect_ok     "003-AC1 rebuild <- build: a valid record about exactly the given digests lets the stage start" $(ST rebuild build) $(rec build_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 check <- build: the same for Check" $(ST check build) $(rec build_coll) --digests "$work/digests.json"
expect_ok     "003-AC1 release <- sign: provenance with its Rekor entry lets Release start" $(ST release sign) $(rec sign_prov) $(R) --digests "$work/digests.json"
expect_refuse "003-AC1 release <- sign with a SUPERSET of the provenance's subjects is refused" "sign|digest" $(ST release sign) $(rec sign_prov) $(R) --digests "$work/digests-extra.json"
expect_refuse "003-AC1 release <- sign with a SUBSET of the provenance's subjects is refused" "sign|digest" $(ST release sign) $(rec sign_prov) $(R) --digests "$work/digests-subset.json"
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

# ---- step-8 round 1: the findings of the adversarial audit, each a case that fails on the old code ------------------------------
# B-1 (Opus): the chain is checked against the policy root ONLY. An attacker CA that the environment's trust store knows (SSL_CERT_FILE,
# SSL_CERT_DIR) must not make a forged record chain: the same record is refused with and without it.
mkdir -p "$work/certdir"; cp "$work/otherroot.pem" "$work/certdir/attacker.pem"
ln -sf attacker.pem "$work/certdir/$("$OPENSSL" x509 -hash -noout -in "$work/otherroot.pem").0"
cp "$work/othertsaroot.pem" "$work/certdir/attacker-tsa.pem"   # the attacker's TIMESTAMP root is trusted by the store too, so the TSA path is exercised
ln -sf attacker-tsa.pem "$work/certdir/$("$OPENSSL" x509 -hash -noout -in "$work/othertsaroot.pem").0"
expect_refuse "B-1 a record that chains only to an attacker root is refused (no trust store)" "root" verify $(V) --stage sign $(rec sign_wrongroot) $(R)
SSL_CERT_FILE="$work/otherroot.pem" expect_refuse "B-1 the same record is STILL refused when SSL_CERT_FILE trusts the attacker root" "root" verify $(V) --stage sign $(rec sign_wrongroot) $(R)
SSL_CERT_DIR="$work/certdir" expect_refuse "B-1 the same record is STILL refused when SSL_CERT_DIR trusts the attacker root" "root" verify $(V) --stage sign $(rec sign_wrongroot) $(R)
SSL_CERT_FILE="$work/othertsaroot.pem" SSL_CERT_DIR="$work/certdir" expect_refuse "B-1 a stamp from an attacker timestamp authority is STILL refused when the trust store knows its root" "timestamp" verify $(V) --stage sign $(rec sign_othertsa) $(R)
SSL_CERT_FILE="$work/otherroot.pem" SSL_CERT_DIR="$work/certdir" expect_ok "B-1 control: the genuine record is still accepted with the attacker root in the trust store" verify $(V) --stage sign $(rec sign_prov) $(R)
# the real shapes (Opus SF-2, Sonnet blocker 1)
expect_refuse "SF-2 a hashedrekord entry (the kind a message signature gets) is refused although the log signed it: kind dsse is required" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-hashedrekord.json)
expect_refuse "SF-2 a validly signed entry whose integrated time is long after the certificate expired is refused" "rekor|integrated" verify $(V) --stage sign $(rec sign_prov) $(R rekor-latetime.json)
# N-1: strict records
expect_refuse "N-1 a record with a repeated JSON key is refused" "envelope|duplicate" verify $(V) --stage sign $(rec sign_dupkey) $(R)
expect_refuse "N-1 a record with two signatures is refused: exactly one is judged" "exactly one signature" verify $(V) --stage sign $(rec sign_2sig) $(R)
# N-5: bytes that are not UTF-8 in the certificate are a refusal, not a traceback
expect_refuse "N-5 a certificate whose SAN is not valid UTF-8 is refused with a 'refused at' line" "malformed|identity" verify $(V) --stage sign $(rec sign_utf8) $(R)
# N-2: a stage starts only from the records it may start from
expect_refuse "N-2 sign cannot start from rebuild's record" "stage" $(ST sign rebuild) $(rec rebuild_coll) --digests "$work/digests.json"
expect_refuse "N-2 rebuild cannot start from sign's record" "stage" $(ST rebuild sign) $(rec sign_prov) $(R) --digests "$work/digests.json"
expect_refuse "N-2 check cannot start from check's own record" "stage" $(ST check check) $(rec check_coll) --digests "$work/digests.json"
expect_refuse "N-2 nothing starts from the release policy (release is nobody's predecessor)" "stage" $(ST release release) $(rec release_policy) $(R) --digests "$work/digests.json"
expect_ok     "N-2 control: rebuild <- build, check <- build and sign <- build are the pairs" $(ST rebuild build) $(rec build_coll) --digests "$work/digests.json"
# Sonnet SF3: a malformed statement is a refusal with a name, not a traceback
expect_refuse "SF3 a collection whose subject list holds non-subjects is refused with a 'refused at' line" "subjects|malformed" $(ST rebuild build) $(rec build_badsubj) --digests "$work/digests.json"
# check-build-record: Sign's check without the signature, no cosign in sight
rc=0; run check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW" || rc=$?
if [ "$rc" = 0 ] && [ ! -s "$work/cosign-argv.log" ]; then ok "check-build-record accepts Build's genuine record and the attested digests and calls no tool"; else bad "check-build-record on a genuine record (exit $rc)"; fi
expect_refuse "check-build-record refuses a digest list Build did not attest: names digest" "digest" check-build-record --digests "$work/digests-other.json" --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW"
expect_refuse "check-build-record refuses attested digests of the wrong format: names format" "format" check-build-record --digests "$work/digests-upper.json" --build-record "$work/build_coll_upper.json" --policy "$work/policy.json" --now "$NOW"
expect_refuse "check-build-record refuses a tampered Build record: names the signature" "signature" check-build-record --digests "$work/digests.json" --build-record "$work/build_coll_tampered.json" --policy "$work/policy.json" --now "$NOW"
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

# ---- step-8 round 2: NB-1 one certificate, one DER; N-8 UTF-8 only; S-1 composite actions under .github/workflows -------------------
for v in junkb64 second trailing leadtext trailtext attack; do
  for s in build rebuild check; do
    expect_refuse "NB-1 $s record whose certificate field is '$v' (not exactly one PEM block) is refused, whatever its identity" "certificate|!digest|!rekor" verify $(V) --stage $s $(rec ${s}_coll_c$v) $(R)
  done
  expect_refuse "NB-1 $v through stage-start (release <- check) is refused" "certificate|!digest" $(ST release check) $(rec check_coll_c$v) --digests "$work/digests.json"
  expect_refuse "NB-1 $v through check-build-record (the check sign --check runs before cosign) is refused, cosign not called" "certificate|!digest" check-build-record --digests "$work/digests.json" --build-record "$work/build_coll_c$v.json" --policy "$work/policy.json" --now "$NOW"
  expect_refuse "NB-1 $v on the provenance (stage sign) is refused before any Rekor lookup" "certificate|!rekor" verify $(V) --stage sign $(rec sign_prov_c$v) $(R)
done
expect_refuse "NB-1 the ATTACK: a genuine Build-identity record whose field is [self-made check-identity certificate, genuine block] is refused for stage check" "certificate" verify $(V) --stage check $(rec check_attack) $(R)
expect_refuse "NB-1 the same attack through stage-start (release <- check)" "certificate" $(ST release check) $(rec check_attack) --digests "$work/digests.json"
expect_refuse "NB-1 the attack in its bare form (base64 of a self-made DER, a newline, then the genuine PEM) is refused for stage check" "certificate" verify $(V) --stage check $(rec check_attack_b64) $(R)
expect_refuse "NB-1 the bare-form attack through stage-start (release <- check)" "certificate" $(ST release check) $(rec check_attack_b64) --digests "$work/digests.json"
expect_refuse "NB-1 control: the same genuine key with its true certificate is refused for stage check by IDENTITY (stage-build.yml), so the attack above was the only way past" "stage-build.yml" verify $(V) --stage check $(rec check_as_build) $(R)
expect_refuse "NB-1 a Rekor entry whose verifier is a genuine PEM plus junk is refused (the log's certificate is compared as one DER)" "rekor" verify $(V) --stage sign $(rec sign_prov) $(R rekor-verifierjunk.json)
expect_ok     "NB-1 control: the genuine records are accepted (one PEM block, whitespace around it allowed)" verify $(V) --stage build $(rec build_coll) $(R)
# N-8: every JSON reader is UTF-8 only; UTF-16 spellings are refused, not guessed
expect_refuse "N-8 a record written in UTF-16 is refused" "envelope" verify $(V) --stage build --record "$work/build_coll_u16.json" $(R)
expect_refuse "N-8 a Rekor entries file in UTF-16 is refused" "rekor" verify $(V) --stage sign $(rec sign_prov) --rekor-stub "$work/rekor-u16.json"
expect_refuse "N-8 a digest file in UTF-16 is refused by stage-start" "digest" $(ST release check) $(rec check_coll) --digests "$work/digests-u16.json"
expect_refuse "N-8 a digest file in UTF-16 is refused by check-build-record" "digest" check-build-record --digests "$work/digests-u16.json" --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW"
iconv -f UTF-8 -t UTF-16 "$work/policy.json" > "$work/policy-u16.json"
expect_refuse "N-8 a policy file in UTF-16 is refused" "policy" verify --policy "$work/policy-u16.json" --now "$NOW" --stage build $(rec build_coll)
# N-7: --template (the committed template, the policy is made here) and --policy (a finished policy) are two inputs, exactly one is given
expect_refuse "N-7 a template given as --policy is refused: it is not a finished policy" "template|policy" check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --policy "$work/template.json" --now "$NOW"
rc=0; run check-build-record --digests "$work/digests.json" --build-record "$work/build_coll.json" --template "$work/template.json" --policy "$work/policy.json" --now "$NOW" || rc=$?
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

# ---- step-8 round 3: B-1 the time of a stamp comes from the TSA-signed token only; the stamp form is bound to the record type -----------------
# (a) a genuine stamp taken AFTER the certificate expired, whose response got a statusString `x\nTime stamp: <date inside the window>`: the
#     status section is outside the TSA's signature, so the response still verifies; the old reader took the time from the first
#     `Time stamp:` line of the whole text and backdated the stamp into the window.
expect_refuse "B-1 control: the genuine post-expiry stamp is refused as outside the certificate window" "outside|validity" verify $(V) --stage sign $(rec sign_stampafter) $(R)
expect_refuse "B-1 (a) a response with an injected statusString that fakes a time inside the window is refused (status), not accepted as backdated" "timestamp|status" verify $(V) --stage sign $(rec sign_sa_inj) $(R)
expect_refuse "B-1 (a) the same injected response through stage-start (release <- sign)" "timestamp|status" $(ST release sign) $(rec sign_sa_inj) $(R) --digests "$work/digests.json"
for s in build rebuild check; do
  expect_refuse "B-1 (a) the injection on a $s record that carries a response is refused: timestamp" "timestamp" verify $(V) --stage $s $(rec ${s}_sa_inj) $(R)
  expect_refuse "B-1 (b) a $s Witness record carrying a whole response instead of the bare token is refused: names the form" "timestamp|form" verify $(V) --stage $s $(rec ${s}_coll_resp) $(R)
done
expect_refuse "B-1 (a) the injected record through stage-start (release <- check)" "timestamp" $(ST release check) $(rec check_sa_inj) --digests "$work/digests.json"
expect_refuse "B-1 (a) the injected record through check-build-record (build)" "timestamp" check-build-record --digests "$work/digests.json" --build-record "$work/build_sa_inj.json" --policy "$work/policy.json" --now "$NOW"
expect_refuse "B-1 (b) a Witness record with a response-form stamp through check-build-record" "timestamp|form" check-build-record --digests "$work/digests.json" --build-record "$work/build_coll_resp.json" --policy "$work/policy.json" --now "$NOW"
expect_refuse "B-1 (b) a Witness record with a response-form stamp through stage-start (release <- check)" "timestamp|form" $(ST release check) $(rec check_coll_resp) --digests "$work/digests.json"
expect_refuse "B-1 (c) a provenance carrying a BARE TOKEN (type tsp) is refused: names the form" "timestamp|form" verify $(V) --stage sign $(rec sign_prov_tok) $(R)
expect_refuse "B-1 (c) token bytes labelled as a response are refused (a response is not parsable from a token)" "timestamp" verify $(V) --stage sign $(rec sign_prov_toklabel) $(R)
# (d) a genTime with milliseconds is read (the fraction is dropped) and accepted when the stamp is genuinely inside the window
expect_ok     "B-1 (d) a stamp whose genTime has milliseconds does not crash and is accepted when it is inside the window (the fraction is dropped)" verify $(V) --stage sign $(rec sign_prov_frac) $(R)
# S-1 (Sonnet): a certificate with a repeated extension is refused, whatever it says (a second SAN used to replace the first)
expect_refuse "S-1 a certificate with a second SAN extension is refused before anything is trusted: repeated extension" "certificate|repeated" verify $(V) --stage build $(rec build_dupsan) $(R)
expect_refuse "S-1 a certificate with a second Build Config URI extension is refused: repeated extension" "certificate|repeated" verify $(V) --stage build $(rec build_dupcfg) $(R)
expect_refuse "S-1 a repeated extension through check-build-record" "certificate|repeated" check-build-record --digests "$work/digests.json" --build-record "$work/build_dupsan.json" --policy "$work/policy.json" --now "$NOW"
# N-c: only a JOB-level `uses:` naming a .yml/.yaml file is a reusable workflow (not opened as a directory); a STEP-level reference to a
# directory that is called thing.yml and holds an action.yml is followed
mkdir -p "$work/tree/.github/workflows/acts/d.yml"
printf 'name: t\nruns:\n  using: composite\n  steps:\n    - uses: evil/act@main\n' > "$work/tree/.github/workflows/acts/d.yml/action.yml"
echo '{"actions":["actions/checkout@'$a40'"],"images":[],"local":[".github/workflows/acts/d.yml"]}' > "$work/allowed-nc.json"
w w_ncstep "  j:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/workflows/acts/d.yml\n"
printf 'name: t\non: workflow_call\njobs:\n  j:\n    uses: ./.github/workflows/acts/d.yml\n' > "$work/w_ncjob.yml"
expect_refuse "N-c a STEP-level local path that is a directory named d.yml holding an action.yml is followed: the unpinned action inside it is rejected" "evil/act" actions "$work/w_ncstep.yml" --allowed "$work/allowed-nc.json" --root "$work/tree"
expect_ok     "N-c the same path at JOB level is a reusable workflow file and is not opened as a directory" actions "$work/w_ncjob.yml" --allowed "$work/allowed-nc.json" --root "$work/tree"

# every call the fake cosign ever received is the pinned form, and there were exactly as many as successful signs (never one for a refusal)
n=$(grep -c . "$work/cosign-all.log" 2> /dev/null || true)
if [ "$n" = "$SIGNS_OK" ] && [ "$SIGNS_OK" -ge 1 ] && ! grep -E -v -q "$ARGV_RE" "$work/cosign-all.log"; then ok "001-AC2 cosign was called exactly once per successful sign ($SIGNS_OK) and always with the pinned argv"; else bad "001-AC2 cosign calls ($n) != successful signs ($SIGNS_OK), or an unpinned argv was used"; fi
[ "$LEAKS" = 0 ] && ok "001-AC3 the token sentinels (ACTIONS_ID_TOKEN_REQUEST_TOKEN/URL, COSIGN_IDENTITY_TOKEN) appear in no stdout, stderr or cosign argv of any run" || bad "001-AC3 a token sentinel leaked into $LEAKS run(s)' output or the cosign argv"
if ! grep -r -F -q -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" "$work/sd" 2> /dev/null; then ok "001-AC3 the token sentinels appear in no file Sign wrote to any output folder"; else bad "001-AC3 a token sentinel was written into an output folder"; fi
# the sentinels also appear in no file written ANYWHERE the verifier could write: the whole work dir (policies, stubs, outputs), the
# current directory, and the temp dir, for files newer than the first run
leakfiles=$( { grep -r -l -F -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" "$work" 2> /dev/null || true
               find "$PWD" -maxdepth 3 -type f -newer "$MARK" -not -path '*/.git/*' -not -path "$work/*" -print0 2> /dev/null | xargs -0 grep -l -F -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" 2> /dev/null || true
               find "${TMPDIR:-/tmp}" -maxdepth 3 -type f -newer "$MARK" -not -path "$work/*" -print0 2> /dev/null | xargs -0 grep -l -F -e "$SENT_TOK" -e "$SENT_URL" -e "$SENT_CIT" 2> /dev/null || true; } | sort -u)
if [ -z "$leakfiles" ]; then ok "001-AC3 the token sentinels appear in no file written under the work dir, the current directory or the temp dir"; else bad "001-AC3 a token sentinel was written to: $(echo "$leakfiles" | head -3 | tr '\n' ' ')"; fi
EXPECT=389
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
