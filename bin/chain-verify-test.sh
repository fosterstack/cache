#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC4, REQ-CHAIN-002-AC1, REQ-CHAIN-002-AC2, REQ-CHAIN-002-AC3,
#         REQ-CHAIN-003-AC1, REQ-CHAIN-003-AC2, REQ-CHAIN-003-AC4
# RED until bin/chain-verify.py exists (tests before implementation, step 4 of the nine-step process).
#
# Tests for the plain verify script of the v0.3.0 release chain (rules 52, 53, 53b, 57 verify side, 58, 63, 67).
# Offline: a synthetic CA, a synthetic timestamp authority (TSA) and leaf certificates carrying SAN URIs are made with
# openssl at test time; no Sigstore, no network, no key is committed. Every refusal case is judged by its exit code
# (0 accepted, 1 refused; anything else, such as a missing script, is an error and fails the case) AND a word the
# message must contain, so "the script is missing" can never pass as "the script refused".
#
# THE CLI THIS TEST ASSUMES (the implementer matches it; anything else is a change to this header first):
#   chain-verify.py policy make --template T.json --tag vX.Y.Z --trust TRUST.json --fulcio-root ROOT.pem --tsa-cert TSA.pem --out POLICY.json
#       T.json  {"repository":"owner/repo","stages":{"<stage>":{"workflow":".github/workflows/<file>.yml"}}}
#       TRUST.json {"fulcio_root_sha256":"<hex of the DER cert>","tsa_sha256":"<hex of the DER cert>"}
#       exit 1 ("trust") when either PEM's sha256 differs from TRUST.json.
#       POLICY.json {"tag","repository","roots":[PEM text],"timestamp_authorities":[PEM text],
#                    "stages":{"<stage>":{"identity":"https://github.com/<repo>/<workflow>@refs/tags/<tag>"}}}
#   chain-verify.py verify --policy POLICY.json --stage NAME --record REC.json --now ISO8601Z
#                          [--kind customer|witness] [--rekor-stub STUB.json]
#       REC.json is a DSSE envelope {"payloadType","payload"(b64 in-toto Statement v1),"signatures":[{"sig"(b64),
#       "certificate"(PEM),"timestamps":[{"type":"tsp","data":"<b64 DER RFC 3161 token over sha256(sig bytes)>"}]}]}
#       signed over DSSE PAE. Checks: chain to a policy root; leaf SAN URI == stages[NAME].identity; the signature;
#       a TSA stamp from a policy authority whose time lies inside the leaf's validity (so --now after expiry is fine);
#       predicate type on the allowed list; for --kind customer a Rekor entry in the stub
#       {"entries":[{"sha256":"<hex of the REC.json file bytes>","logIndex":N}]} (default kind: customer).
#       exit 0 accepted; exit 1 refused, message on stderr naming the cause and, for an identity refusal, the identity found.
#   chain-verify.py sign --check --digests D.json --build-record REC.json --policy POLICY.json --now ISO8601Z
#       D.json {"<name>":"sha256:<64 hex>"}; REC.json is Build's record (verify --stage build passes; statement subjects
#       {"name","digest":{"sha256"}}); exit 1 ("digest") when the sets differ or any value is not sha256:<64 hex>.
#   chain-verify.py stage-start --stage NAME --previous PREV --record REC.json --digests D.json --policy POLICY.json --now ISO8601Z
#       exit 1 with PREV named in the message for: other digests, wrong signer stage, no signature, no/missing record.
#   chain-verify.py actions WORKFLOW.yml --allowed ALLOWED.json
#       ALLOWED.json {"actions":["owner/repo[/path]@<40 hex>"],"images":["<image>@sha256:<64 hex>"],"local":["<path>"]}
#       exit 1 naming the reference for any `uses:` / container / services image not exactly listed by full digest;
#       a repository-local reusable call (`uses: ./path`) passes only if its path is in "local".
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cv="$root/bin/chain-verify.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass + 1)); echo "ok   $1"; }
bad()  { failn=$((failn + 1)); echo "FAIL $1"; }

# ---- fixtures ---------------------------------------------------------------------------------------------------
cat > "$work/fx.py" <<'PY'
import base64, datetime as dt, hashlib, json, os, subprocess, sys, textwrap
W = sys.argv[1]
def sh(*a, inp=None):
    r = subprocess.run(a, input=inp, capture_output=True)
    if r.returncode: sys.stderr.write("%s\n%s\n" % (" ".join(a), r.stderr.decode())); sys.exit(1)
    return r.stdout
def p(n): return os.path.join(W, n)
def fmt(t): return t.strftime("%Y%m%d%H%M%SZ")
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
mkca("root"); mkca("otherroot"); mkca("tsaroot"); mkca("othertsaroot")
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
    return base64.b64encode(open(p("r.tst"), "rb").read()).decode()
def pae(t, b): return b"DSSEv1 %d %s %d %s" % (len(t), t.encode(), len(b), b)
REPO = "fosterstack/cache"
def uri(wf, ref): return "https://github.com/%s/.github/workflows/%s@%s" % (REPO, wf, ref)
_n = [0]
def record(name, wf, ref, ptype, subjects, ca="root", start=None, end=None, tsa="tsa", signed=True):
    _n[0] += 1; leaf = "leaf%d" % _n[0]
    issue(ca, leaf, "subjectAltName = critical,URI:" + uri(wf, ref), start or now - dt.timedelta(minutes=1), end or now + dt.timedelta(minutes=10))
    st = json.dumps({"_type": "https://in-toto.io/Statement/v1", "predicateType": ptype, "predicate": {},
                     "subject": [{"name": k, "digest": {"sha256": v.split(":", 1)[1] if v.startswith("sha256:") else v}} for k, v in subjects.items()]}).encode()
    pl = base64.b64encode(st).decode()
    open(p("pae.bin"), "wb").write(pae("application/vnd.in-toto+json", st))
    sh("openssl", "dgst", "-sha256", "-sign", p(leaf + ".key"), "-out", p("sig.bin"), p("pae.bin"))
    sig = open(p("sig.bin"), "rb").read()
    s = {"keyid": "", "sig": base64.b64encode(sig).decode(), "certificate": open(p(leaf + ".pem")).read()}
    if tsa: s["timestamps"] = [{"type": "tsp", "data": stamp(sig, tsa)}]
    env = {"payloadType": "application/vnd.in-toto+json", "payload": pl, "signatures": [s] if signed else []}
    json.dump(env, open(p(name + ".json"), "w"))
    return hashlib.sha256(open(p(name + ".json"), "rb").read()).hexdigest()
PROV, COLL, REL = "https://slsa.dev/provenance/v1", "https://witness.dev/attestation-collections/v0.1", "https://in-toto.io/attestation/release/v0.1"
D = {"image-production": "sha256:" + "a" * 64, "image-fips": "sha256:" + "b" * 64, "apk": "sha256:" + "c" * 64}
json.dump(D, open(p("digests.json"), "w"))
Dother = dict(D, apk="sha256:" + "d" * 64); json.dump(Dother, open(p("digests-other.json"), "w"))
Dextra = dict(D, extra="sha256:" + "e" * 64); json.dump(Dextra, open(p("digests-extra.json"), "w"))
json.dump(dict(D, apk="./dist/run.sh"), open(p("digests-path.json"), "w"))
json.dump(dict(D, apk="sha256:$(curl evil)"), open(p("digests-code.json"), "w"))
STAGES = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml", "check": "stage-verify.yml", "release": "stage-promote.yml"}
json.dump({"repository": REPO, "stages": {k: {"workflow": ".github/workflows/" + v} for k, v in STAGES.items()}}, open(p("template.json"), "w"))
def der_sha(pem): return hashlib.sha256(sh("openssl", "x509", "-in", pem, "-outform", "DER")).hexdigest()
json.dump({"fulcio_root_sha256": der_sha(p("root.pem")), "tsa_sha256": der_sha(p("tsa.pem"))}, open(p("trust.json"), "w"))
json.dump({"fulcio_root_sha256": der_sha(p("otherroot.pem")), "tsa_sha256": der_sha(p("tsa.pem"))}, open(p("trust-badroot.json"), "w"))
json.dump({"fulcio_root_sha256": der_sha(p("root.pem")), "tsa_sha256": der_sha(p("othertsa.pem"))}, open(p("trust-badtsa.json"), "w"))
T, T2 = "refs/tags/v0.3.0", "refs/tags/v0.3.1"
rekor = []
R = {}
def add(n, *a, **k): R[n] = record(n, *a, **k)
add("sign_prov", STAGES["sign"], T, PROV, D)
add("build_as_sign", STAGES["build"], T, PROV, D)
add("rebuild_as_sign", STAGES["rebuild"], T, PROV, D)
add("check_as_sign", STAGES["check"], T, PROV, D)
add("release_as_sign", STAGES["release"], T, PROV, D)
add("sibling_as_sign", "other.yml", T, PROV, D)
add("sign_othertag", STAGES["sign"], T2, PROV, D)
add("sign_branch", STAGES["sign"], "refs/heads/main", PROV, D)
add("sign_wrongroot", STAGES["sign"], T, PROV, D, ca="otherroot")
add("sign_nostamp", STAGES["sign"], T, PROV, D, tsa=None)
add("sign_othertsa", STAGES["sign"], T, PROV, D, tsa="othertsa")
add("sign_stampbefore", STAGES["sign"], T, PROV, D, start=now + dt.timedelta(hours=1), end=now + dt.timedelta(minutes=70))
add("sign_unsigned", STAGES["sign"], T, PROV, D, signed=False)
add("sign_otherdigests", STAGES["sign"], T, PROV, Dother)
# tamper cases (advisor 0328 item 2): a good record changed after signing, three ways
_g = json.load(open(p("sign_prov.json")))
_t = json.loads(json.dumps(_g)); _st = json.loads(base64.b64decode(_t["payload"]))
_st["subject"][0]["digest"]["sha256"] = "e" * 64; _t["payload"] = base64.b64encode(json.dumps(_st).encode()).decode()
json.dump(_t, open(p("sign_tamper_payload.json"), "w"))
_t = json.loads(json.dumps(_g)); _sg = bytearray(base64.b64decode(_t["signatures"][0]["sig"])); _sg[-1] ^= 1
_t["signatures"][0]["sig"] = base64.b64encode(bytes(_sg)).decode(); json.dump(_t, open(p("sign_tamper_sig.json"), "w"))
_t = json.loads(json.dumps(_g)); _t["signatures"][0]["timestamps"] = json.load(open(p("sign_othertag.json")))["signatures"][0]["timestamps"]
json.dump(_t, open(p("sign_tamper_stamp.json"), "w"))
add("build_coll", STAGES["build"], T, COLL, D)
add("build_coll_nostamp", STAGES["build"], T, COLL, D, tsa=None)
add("build_madeup", STAGES["build"], T, "https://example.com/made-up/v1", D)
add("build_ours", STAGES["build"], T, "https://fosterstack.com/attestations/build/v1", D)
add("release_policy", STAGES["release"], T, REL, D)
add("check_coll", STAGES["check"], T, COLL, D)
json.dump({"entries": [{"sha256": R["sign_prov"], "logIndex": 7}, {"sha256": R["release_policy"], "logIndex": 8}]}, open(p("rekor.json"), "w"))
json.dump({"entries": []}, open(p("rekor-empty.json"), "w"))
# the timestamps of the fixtures lie inside the leaf validity [now-1m, now+10m]; these verify times are 16 min after expiry
open(p("now.txt"), "w").write(fmt(now + dt.timedelta(minutes=26)))
open(p("now-in.txt"), "w").write(fmt(now + dt.timedelta(minutes=2)))
e = json.load(open(p("sign_prov.json")))["signatures"][0]
open(p("chk.tst"), "wb").write(base64.b64decode(e["timestamps"][0]["data"]))
sh("openssl", "ts", "-verify", "-digest", hashlib.sha256(base64.b64decode(e["sig"])).hexdigest(), "-in", p("chk.tst"), "-token_in", "-CAfile", p("tsaroot.pem"), "-no_check_time")
print("fixtures ok")
PY
python3 "$work/fx.py" "$work" > "$work/fx.log" 2>&1 || { cat "$work/fx.log"; echo "FAIL fixture generation"; exit 1; }
NOW=$(cat "$work/now.txt"); NOWIN=$(cat "$work/now-in.txt")

# fixture self-checks: the judge's inputs are what the cases claim they are (so a refusal is about the claimed cause)
openssl verify -CAfile "$work/root.pem" "$work/leaf1.pem" > /dev/null 2>&1 && ok "fixture: leaf chains to the policy root" || bad "fixture: leaf chain"
openssl verify -CAfile "$work/otherroot.pem" "$work/leaf1.pem" > /dev/null 2>&1 && bad "fixture: leaf must NOT chain to the other root" || ok "fixture: other root does not verify the leaf"
openssl x509 -in "$work/leaf1.pem" -noout -ext subjectAltName 2> /dev/null | grep -q 'stage-sign.yml@refs/tags/v0.3.0' && ok "fixture: leaf SAN is the Sign file at the tag" || bad "fixture: leaf SAN"
openssl x509 -in "$work/leaf1.pem" -noout -enddate | grep -q . && ok "fixture: leaf carries a validity window" || bad "fixture: validity"

grep -q "fixtures ok" "$work/fx.log" && ok "fixture: the timestamp token verifies against the TSA root (openssl ts -verify)" || bad "fixture: timestamp token"

# ---- harness ----------------------------------------------------------------------------------------------------
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist (RED: not implemented yet)"
run() { python3 "$cv" "$@" 2> "$work/err" > "$work/out" || return $?; }
# expect_ok LABEL args...   expect_refuse LABEL WORD args...   (WORD: lower-case text the refusal must contain)
expect_ok() { local l=$1; shift; local rc=0; run "$@" || rc=$?
  if [ "$rc" = 0 ]; then ok "$l"; else bad "$l (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
expect_refuse() { local l=$1 w=$2; shift 2; local rc=0; run "$@" || rc=$?
  if [ "$rc" = 1 ] && tr 'A-Z' 'a-z' < "$work/err" | grep -q -- "$w"; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with '$w'; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
mkpol() { run policy make --template "$work/template.json" --tag v0.3.0 --trust "${2:-$work/trust.json}" \
  --fulcio-root "$work/root.pem" --tsa-cert "$work/tsa.pem" --out "$work/$1"; }
V() { echo --policy "$work/policy.json" --now "$NOW"; }

# ---- REQ-CHAIN-002-AC2: the per-tag policy ----------------------------------------------------------------------
rc=0; mkpol policy.json || rc=$?; [ "$rc" = 0 ] && ok "002-AC2 policy for v0.3.0 is made from the template" || bad "002-AC2 policy make (exit $rc)"
rc=0; mkpol policy-badroot.json "$work/trust-badroot.json" || rc=$?
{ [ "$rc" = 1 ] && grep -qi trust "$work/err"; } && ok "002-AC2 a root whose hash differs from the trust file is refused" || bad "002-AC2 bad root hash (exit $rc)"
rc=0; mkpol policy-badtsa.json "$work/trust-badtsa.json" || rc=$?
{ [ "$rc" = 1 ] && grep -qi trust "$work/err"; } && ok "002-AC2 a timestamp authority whose hash differs from the trust file is refused" || bad "002-AC2 bad TSA hash (exit $rc)"
expect_ok     "002-AC2 sign file at v0.3.0 is accepted as stage sign" verify $(V) --stage sign --record "$work/sign_prov.json" --kind witness
expect_refuse "002-AC2 sibling file at the same tag is refused" "other.yml" verify $(V) --stage sign --record "$work/sibling_as_sign.json" --kind witness
expect_refuse "002-AC2 the same file at another tag is refused" "v0.3.1" verify $(V) --stage sign --record "$work/sign_othertag.json" --kind witness
expect_refuse "002-AC2 the same file on a branch is refused" "refs/heads/main" verify $(V) --stage sign --record "$work/sign_branch.json" --kind witness
expect_refuse "002-AC2 a certificate from another root is refused" "root" verify $(V) --stage sign --record "$work/sign_wrongroot.json" --kind witness
# the committed template (rule 57): names the five stage files, repository fosterstack/cache
python3 - "$root" <<'PY' && ok "002-AC2 .github/policy/release-policy.template.json names the five stage files" || bad "002-AC2 committed template missing or wrong"
import json, sys
t = json.load(open(sys.argv[1] + "/.github/policy/release-policy.template.json"))
want = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml", "check": "stage-verify.yml", "release": "stage-promote.yml"}
assert t["repository"] == "fosterstack/cache"
assert {k: v["workflow"].rsplit("/", 1)[-1] for k, v in t["stages"].items()} == want, t["stages"]
PY
python3 - "$root" <<'PY' && ok "002-AC2 .github/policy/sigstore-trust.json pins both hashes" || bad "002-AC2 committed trust file missing or wrong"
import json, re, sys
t = json.load(open(sys.argv[1] + "/.github/policy/sigstore-trust.json"))
assert all(re.fullmatch(r"[0-9a-f]{64}", t[k]) for k in ("fulcio_root_sha256", "tsa_sha256")), t
PY

# ---- REQ-CHAIN-001-AC4: provenance only from Sign's identity ----------------------------------------------------
expect_ok     "001-AC4 provenance under stage-sign.yml@tag is accepted" verify $(V) --stage sign --record "$work/sign_prov.json" --kind witness
expect_refuse "001-AC4 Build's identity is refused and named" "stage-build.yml" verify $(V) --stage sign --record "$work/build_as_sign.json" --kind witness
expect_refuse "001-AC4 Rebuild's identity is refused and named" "stage-reproducibility.yml" verify $(V) --stage sign --record "$work/rebuild_as_sign.json" --kind witness
expect_refuse "001-AC4 Check's identity is refused and named" "stage-verify.yml" verify $(V) --stage sign --record "$work/check_as_sign.json" --kind witness
expect_refuse "001-AC4 Release's identity is refused and named" "stage-promote.yml" verify $(V) --stage sign --record "$work/release_as_sign.json" --kind witness
expect_refuse "001-AC4 a sibling file is refused and named" "other.yml" verify $(V) --stage sign --record "$work/sibling_as_sign.json" --kind witness
expect_refuse "001-AC4 another tag is refused and named" "v0.3.1" verify $(V) --stage sign --record "$work/sign_othertag.json" --kind witness

# ---- REQ-CHAIN-002-AC1: timestamps, checked 16 minutes after the certificate expired, offline -------------------
expect_ok     "002-AC1 expired certificate + valid stamp from the policy's authority, verified 16 min after expiry" verify $(V) --stage sign --record "$work/sign_prov.json" --kind witness
expect_ok     "002-AC1 the same record inside the certificate window" verify --policy "$work/policy.json" --now "$NOWIN" --stage sign --record "$work/sign_prov.json" --kind witness
expect_refuse "002-AC1 no timestamp after expiry is refused" "timestamp" verify $(V) --stage sign --record "$work/sign_nostamp.json" --kind witness
expect_refuse "002-AC1 a stamp from another authority is refused" "timestamp" verify $(V) --stage sign --record "$work/sign_othertsa.json" --kind witness
expect_refuse "002-AC1 a stamp outside the certificate's validity is refused" "validity" verify $(V) --stage sign --record "$work/sign_stampbefore.json" --kind witness
expect_refuse "002-AC1 tamper: payload changed after signing is refused" "signature" verify $(V) --stage sign --record "$work/sign_tamper_payload.json" --kind witness
expect_refuse "002-AC1 tamper: signature bytes altered is refused" "signature" verify $(V) --stage sign --record "$work/sign_tamper_sig.json" --kind witness
expect_refuse "002-AC1 tamper: a stamp taken over a different signature is refused" "timestamp" verify $(V) --stage sign --record "$work/sign_tamper_stamp.json" --kind witness
python3 - "$work/policy.json" "$work/policy-notsa.json" <<'PY' || true
import json, sys
d = json.load(open(sys.argv[1])); d["timestamp_authorities"] = []; json.dump(d, open(sys.argv[2], "w"))
PY
true
expect_refuse "002-AC1 a policy naming no authority refuses even a valid stamp" "timestamp" verify --policy "$work/policy-notsa.json" --now "$NOW" --stage sign --record "$work/sign_prov.json" --kind witness

# ---- REQ-CHAIN-002-AC3: Rekor for what customers verify; Witness records exempt --------------------------------
expect_ok     "002-AC3 a customer record with a Rekor entry is accepted" verify $(V) --stage sign --record "$work/sign_prov.json" --kind customer --rekor-stub "$work/rekor.json"
expect_refuse "002-AC3 a customer record with no Rekor entry is refused" "rekor" verify $(V) --stage sign --record "$work/sign_prov.json" --kind customer --rekor-stub "$work/rekor-empty.json"
expect_refuse "002-AC3 a customer record is refused when no Rekor source is given (the default kind is customer)" "rekor" verify $(V) --stage sign --record "$work/sign_prov.json"
expect_ok     "002-AC3 a Witness stage record needs no Rekor entry" verify $(V) --stage build --record "$work/build_coll.json" --kind witness --rekor-stub "$work/rekor-empty.json"
expect_refuse "002-AC3 a Witness record is checked for the timestamp instead" "timestamp" verify $(V) --stage build --record "$work/build_coll_nostamp.json" --kind witness

# ---- REQ-CHAIN-003-AC2: only the standard record types ------------------------------------------------------------
expect_ok     "003-AC2 the Witness collection type is allowed" verify $(V) --stage build --record "$work/build_coll.json" --kind witness
expect_ok     "003-AC2 SLSA provenance is allowed" verify $(V) --stage sign --record "$work/sign_prov.json" --kind witness
expect_ok     "003-AC2 the signed release policy type is allowed" verify $(V) --stage release --record "$work/release_policy.json" --kind witness
expect_refuse "003-AC2 a made-up type is refused" "predicate" verify $(V) --stage build --record "$work/build_madeup.json" --kind witness
expect_refuse "003-AC2 a FosterStack-made type is refused" "predicate" verify $(V) --stage build --record "$work/build_ours.json" --kind witness

# ---- REQ-CHAIN-001-AC2: Sign takes only Build's digests, checked against Build's record ---------------------------
S() { echo sign --check --build-record "$work/build_coll.json" --policy "$work/policy.json" --now "$NOW"; }
expect_ok     "001-AC2 digests equal to Build's record are accepted" $(S) --digests "$work/digests.json"
expect_refuse "001-AC2 a digest that differs from Build's record is refused" "digest" $(S) --digests "$work/digests-other.json"
expect_refuse "001-AC2 an extra entry in the list is refused" "digest" $(S) --digests "$work/digests-extra.json"
expect_refuse "001-AC2 a path instead of a digest is refused" "digest" $(S) --digests "$work/digests-path.json"
expect_refuse "001-AC2 code in a value is refused" "digest" $(S) --digests "$work/digests-code.json"

# ---- REQ-CHAIN-003-AC1: each stage verifies the one before it ---------------------------------------------------
ST() { echo stage-start --stage rebuild --previous build --policy "$work/policy.json" --now "$NOW"; }
expect_ok     "003-AC1 a valid record about exactly the given digests lets the stage start" $(ST) --record "$work/build_coll.json" --digests "$work/digests.json"
expect_refuse "003-AC1 a record about other digests stops it and names build" "build" $(ST) --record "$work/build_coll.json" --digests "$work/digests-other.json"
expect_refuse "003-AC1 a record signed by the wrong stage stops it and names build" "build" $(ST) --record "$work/check_coll.json" --digests "$work/digests.json"
python3 - "$work/build_coll.json" "$work/build_coll_unsigned.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["signatures"] = []; json.dump(d, open(sys.argv[2], "w"))
PY
expect_refuse "003-AC1 an unsigned record stops it and names build" "build" $(ST) --record "$work/build_coll_unsigned.json" --digests "$work/digests.json"
expect_refuse "003-AC1 no record stops it and names build" "build" $(ST) --record "$work/does-not-exist.json" --digests "$work/digests.json"

# ---- REQ-CHAIN-003-AC4: every action reference is a listed full digest -----------------------------------------
a40=$(printf 'a%.0s' $(seq 40)); b40=$(printf 'b%.0s' $(seq 40)); i64=$(printf '1%.0s' $(seq 64))
cat > "$work/allowed.json" <<EOF
{"actions":["actions/checkout@$a40","fosterstack/cache/.github/workflows/lib.yml@$b40"],"images":["ghcr.io/fosterstack/runner@sha256:$i64"],"local":[".github/workflows/stage-sign.yml"]}
EOF
wf() { printf 'name: t\non: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-24.04\n%b    steps:\n%b' "$2" "$3" > "$work/$1.yml"; }
wf w_good  "    container: ghcr.io/fosterstack/runner@sha256:$i64\n" "      - uses: actions/checkout@$a40 # v7.0.1\n"
wf w_unl   "" "      - uses: actions/upload-artifact@$a40 # v7\n"
wf w_tag   "" "      - uses: actions/checkout@v4\n"
wf w_otherd "" "      - uses: actions/checkout@$b40\n"
wf w_reuse "" "      - uses: fosterstack/cache/.github/workflows/other.yml@$b40\n"
wf w_cont  "    container: ghcr.io/fosterstack/runner:latest\n" "      - run: true\n"
wf w_contd "    container: ghcr.io/fosterstack/runner@sha256:$(printf '2%.0s' $(seq 64))\n" "      - run: true\n"
wf w_docker "" "      - uses: docker://alpine:3.20\n"
wf w_local "" "      - uses: ./.github/workflows/stage-sign.yml\n"
wf w_localbad "" "      - uses: ./.github/workflows/stage-build.yml\n"
A() { echo actions "$work/$1.yml" --allowed "$work/allowed.json"; }
expect_ok     "003-AC4 a file whose references are all listed digests is accepted" $(A w_good)
expect_refuse "003-AC4 an unlisted action is rejected and named" "upload-artifact" $(A w_unl)
expect_refuse "003-AC4 a tag-pinned action is rejected" "checkout@v4" $(A w_tag)
expect_refuse "003-AC4 a listed action at another digest is rejected" "checkout" $(A w_otherd)
expect_refuse "003-AC4 an unlisted reusable-workflow call is rejected" "other.yml" $(A w_reuse)
expect_refuse "003-AC4 a container image by tag is rejected" "runner:latest" $(A w_cont)
expect_refuse "003-AC4 an unlisted image digest is rejected" "runner" $(A w_contd)
expect_refuse "003-AC4 a docker:// reference is rejected" "alpine" $(A w_docker)
expect_ok     "003-AC4 a local reusable call named by path in the list is accepted" $(A w_local)
expect_refuse "003-AC4 a local reusable call not in the list is rejected" "stage-build.yml" $(A w_localbad)
python3 - "$root" <<'PY' && ok "003-AC4 .github/policy/allowed-actions.json exists, digest-only" || bad "003-AC4 committed allowed-actions.json missing or not digest-only"
import json, re, sys
a = json.load(open(sys.argv[1] + "/.github/policy/allowed-actions.json"))
assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", x) for x in a["actions"]), a["actions"]
assert all(re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", x) for x in a["images"]), a["images"]
PY

echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
