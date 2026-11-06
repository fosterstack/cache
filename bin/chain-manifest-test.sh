#!/usr/bin/env bash
# proves: REQ-CHAIN-002-AC2
# Tests for the key manifest of the v0.3.0 release chain (handoff 0713, row P1): `chain-verify.py policy make` reads the manifest first.
# Offline: the root key, the release key and every manifest are made here with openssl; nothing is committed and no AWS is used.
#
# The manifest, in .github/policy/ beside the template:
#   release-key-root.pub        the offline root key's public key (PEM, ECDSA P-256), committed by the owner
#   release-key-manifest.json   {"public_key": PEM, "key_id": sha256 hex of the key's DER, "valid_from": "YYYY-mm-ddTHH:MM:SSZ",
#                                optional "valid_to", optional "revoked_at"}; no other field
#   release-key-manifest.sig    base64 of the root key's ECDSA signature (DER) over the exact bytes of the manifest file
# `policy make --template T --tag vX.Y.Z --out P` checks the manifest BEFORE it writes anything, and a failure
# is `refused at manifest: <reason>`, exit 1, no policy file. The policy it writes holds the release key (public_key, key_id) and no
# certificate root, timestamp authority or OIDC issuer. No time inside a record is trusted: a manifest whose revoked_at is at or
# before the verification time is refused (ruling R3).
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cv="$root/bin/chain-verify.py"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
OPENSSL=openssl
export OPENSSL
[ -f "$cv" ] && ok "bin/chain-verify.py exists" || bad "bin/chain-verify.py does not exist"

# ---- fixtures: one root key, two release keys, a template, and a manifest maker -----------------------------------------------------------
cat > "$work/fx.py" <<'PY'
import base64, datetime as dt, hashlib, json, os, shutil, subprocess, sys
W = sys.argv[1]
T0 = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
def at(days): return (T0 + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")      # the window is judged by the real clock
def p(n): return os.path.join(W, n)
def sh(*a):
    r = subprocess.run(a, capture_output=True)
    if r.returncode: sys.exit("%s\n%s" % (" ".join(a), r.stderr.decode()))
    return r.stdout
def genkey(name, *opts):
    sh("openssl", "genpkey", *opts, "-out", p(name + ".key"))
    sh("openssl", "pkey", "-in", p(name + ".key"), "-pubout", "-out", p(name + ".pub"))
for n in ("root", "otherroot", "rel", "rel2"): genkey(n, "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
genkey("rekor", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")      # this run's Rekor key: rekor.pub beside the template, pinned by sigstore-trust.json
genkey("ed", "-algorithm", "ED25519")
genkey("rsa", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
genkey("p384", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384")
def der_sha(name): return hashlib.sha256(sh("openssl", "pkey", "-pubin", "-in", p(name + ".pub"), "-outform", "DER")).hexdigest()
def pem(name): return open(p(name + ".pub")).read()
json.dump({"_note": "throwaway trust file for this test run", "rekor_sha256": der_sha("rekor")}, open(p("sigstore-trust.json"), "w"))
def sign_with(rootkey, data):
    open(p("m.tmp"), "wb").write(data)
    return base64.b64encode(sh("openssl", "dgst", "-sha256", "-sign", p(rootkey + ".key"), p("m.tmp"))).decode() + "\n"
def write_set(d, manifest, rootkey="root", raw=None, sig=None, root_pub="root"):
    """A keys directory: the root public key, the manifest (as bytes, or a dict made into JSON) and its signature by `rootkey`."""
    os.makedirs(p(d), exist_ok=True)
    body = raw if raw is not None else json.dumps(manifest, sort_keys=True, indent=1).encode() + b"\n"
    open(p(d + "/release-key-root.pub"), "w").write(pem(root_pub))
    open(p(d + "/release-key-manifest.json"), "wb").write(body)
    open(p(d + "/release-key-manifest.sig"), "w").write(sig if sig is not None else sign_with(rootkey, body))
    for f in ("template.json", "sigstore-trust.json", "rekor.pub"):      # the key files sit beside the template: no flag points elsewhere
        shutil.copy(p(f), p(d + "/" + f))
def good(**over):
    m = {"public_key": pem("rel"), "key_id": der_sha("rel"), "valid_from": "2026-01-01T00:00:00Z"}
    m.update(over)
    return {k: v for k, v in m.items() if v is not None}
json.dump({"repository": "fosterstack/cache", "stages": ["build", "sign", "rebuild", "check", "release"]}, open(p("template.json"), "w"))
write_set("good", good())
write_set("window", good(valid_to=at(30)))
write_set("future-revoke", good(revoked_at=at(30)))
write_set("revoked", good(revoked_at=at(-30)))
write_set("revoked-now", good(revoked_at=at(0)))
write_set("notyet", good(valid_from=at(1)))
write_set("expired", good(valid_to=at(-30)))
write_set("expired-now", good(valid_to=at(0)))
write_set("unknown-field", good(note="x"))
write_set("no-key", good(public_key=None))
write_set("no-id", good(key_id=None))
write_set("no-from", good(valid_from=None))
write_set("wrong-id", good(key_id=der_sha("rel2")))
write_set("id-upper", good(key_id=der_sha("rel").upper()))
write_set("bad-date", good(valid_from="2026-01-01"))
write_set("bad-date2", good(valid_from="2026-13-01T00:00:00Z"))
write_set("bad-date3", good(valid_to="soon"))
write_set("date-number", good(valid_from=20260101))
write_set("key-number", good(public_key=7))
write_set("ed-key", good(public_key=pem("ed"), key_id=der_sha("ed")))
write_set("rsa-key", good(public_key=pem("rsa"), key_id=der_sha("rsa")))
write_set("p384-key", good(public_key=pem("p384"), key_id=der_sha("p384")))
write_set("two-keys", good(public_key=pem("rel") + pem("rel2")))
write_set("junk-key", good(public_key="not a key"))
write_set("pad-key", good(public_key="x\n" + pem("rel")))
write_set("other-root", good(), rootkey="otherroot")
write_set("root-mismatch", good(), root_pub="otherroot")
for _t in ("rsa", "p384"):       # a root key of another type, signing with its own key: refused for its type, before its signature counts
    write_set("root-" + _t, good(), rootkey=_t, root_pub=_t)
write_set("root-ed", good(), root_pub="ed", sig=base64.b64encode(os.urandom(64)).decode() + "\n")       # openssl dgst cannot sign with Ed25519
write_set("dup-key", None, raw=b'{"public_key": %s, "key_id": "%s", "valid_from": "2026-01-01T00:00:00Z", "valid_from": "2026-12-01T00:00:00Z"}\n'
          % (json.dumps(pem("rel")).encode(), der_sha("rel").encode()))
write_set("array", None, raw=b'[1]\n')
write_set("not-json", None, raw=b'{not json\n')
write_set("utf16", None, raw=json.dumps(good()).encode("utf-16"))
write_set("empty", None, raw=b"")
# the manifest signed, then changed by one byte: the signature is the old one
write_set("edited", good())
mf = p("edited/release-key-manifest.json"); b = open(mf, "rb").read(); open(mf, "wb").write(b.replace(b"2026-01-01", b"2025-01-01"))
write_set("sig-garbage", good(), sig="!!!not-base64!!!\n")
write_set("sig-empty", good(), sig="")
write_set("sig-noncanon", good())           # the same signature with a line break inside its base64
s = open(p("sig-noncanon/release-key-manifest.sig")).read().strip()
open(p("sig-noncanon/release-key-manifest.sig"), "w").write(s[:20] + "\n" + s[20:] + "\n")
write_set("sig-ed", good())                 # a signature that is not ECDSA over this file: the manifest signed with the wrong algorithm
open(p("sig-ed/release-key-manifest.sig"), "w").write(base64.b64encode(os.urandom(64)).decode() + "\n")
for gone in ("no-manifest", "no-sig", "no-rootkey"):
    write_set(gone, good())
os.remove(p("no-manifest/release-key-manifest.json")); os.remove(p("no-sig/release-key-manifest.sig")); os.remove(p("no-rootkey/release-key-root.pub"))
write_set("link-manifest", good())
os.remove(p("link-manifest/release-key-manifest.json")); os.symlink(p("good/release-key-manifest.json"), p("link-manifest/release-key-manifest.json"))
json.dump({"id": der_sha("rel")}, open(p("expect.json"), "w"))
PY
python3 "$work/fx.py" "$work" || { echo "FAIL fixtures could not be made"; exit 1; }
KID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$work/expect.json")

# ---- harness -------------------------------------------------------------------------------------------------------------------------------
run() { local rc=0; python3 -I "$cv" "$@" 2> "$work/err" > "$work/out" || rc=$?; return $rc; }
mk() { local d=$1; shift; rm -f "$work/policy.json"; run policy make --template "$work/$d/template.json" --tag v0.3.0 --out "$work/policy.json" "$@"; }
# expect_ok LABEL DIR
expect_ok() { local rc=0; mk "$2" || rc=$?
  if [ "$rc" = 0 ] && [ -s "$work/policy.json" ]; then ok "$1"; else bad "$1 (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"; fi; }
# expect_refuse LABEL "word|word" DIR: exit 1, no traceback, first stderr line `refused at manifest: <reason>` holding every word, and NO policy file
expect_refuse() { local l=$1 w=$2 d=$3 rc=0 miss=0 l1 x; shift 3; mk "$d" "$@" || rc=$?
  l1=$(head -n 1 "$work/err" | tr 'A-Z' 'a-z')
  case $l1 in "refused at manifest: "*) ;; *) miss=1 ;; esac
  IFS='|' read -r -a ws <<< "$w"
  for x in "${ws[@]}"; do case ${l1#*: } in *"$x"*) ;; *) miss=1 ;; esac; done
  if [ "$rc" = 1 ] && [ "$miss" = 0 ] && ! grep -q Traceback "$work/err" && [ ! -e "$work/policy.json" ]; then ok "$l"
  else bad "$l (exit $rc, wanted 1 with 'refused at manifest: ...' and '$w', no policy file; got: $(head -c 200 "$work/err" | tr '\n' ' '); policy $([ -e "$work/policy.json" ] && echo WRITTEN || echo absent))"; fi; }

# ---- the good manifest and what the policy holds ---------------------------------------------------------------------------------------
expect_ok "a signed manifest inside its window makes the policy" good
python3 - "$work/policy.json" "$KID" "$work/rel.pub" "$work/rekor.pub" > "$work/shape.out" 2>&1 <<'PY' && ok "the policy holds the release key, its key_id and the pinned Rekor key, and no certificate, timestamp or issuer field" || bad "policy shape: $(head -c 300 "$work/shape.out")"
import json, sys
pol = json.load(open(sys.argv[1])); kid, pub = sys.argv[2], open(sys.argv[3]).read()
assert pol["release_key"] == {"key_id": kid, "public_key": pub}, pol.get("release_key")
assert pol["tag"] == "v0.3.0" and pol["ref"] == "refs/tags/v0.3.0" and pol["repository"] == "fosterstack/cache", pol
assert pol["stages"] == ["build", "sign", "rebuild", "check", "release"], pol["stages"]
assert pol["rekor_public_key"] == open(sys.argv[4]).read(), "the policy's Rekor key is the pinned rekor.pub"
for gone in ("roots", "timestampauthorities", "oidc_issuer", "caller_identity"):
    assert gone not in pol, gone
PY
expect_ok "valid_to in the future is accepted" window
expect_ok "revoked_at in the future is accepted (the key is still good now)" future-revoke
cp -r "$work/good/." "$work/"; rm -f "$work/policy.json"
rc=0; run policy make --template "$work/template.json" --tag v0.3.0 --out "$work/policy.json" || rc=$?
[ "$rc" = 0 ] && [ -s "$work/policy.json" ] && ok "policy make reads the three files beside the template" || bad "default keys directory (exit $rc; $(head -c 200 "$work/err" | tr '\n' ' '))"

# ---- the manifest is checked FIRST and is all or nothing ----------------------------------------------------------------------------------
expect_refuse "no manifest file" "manifest|missing" no-manifest
expect_refuse "no signature file" "signature|missing" no-sig
expect_refuse "no root key file" "root|missing" no-rootkey
expect_refuse "a manifest that is a link is not read" "manifest|link" link-manifest
expect_refuse "a manifest edited after it was signed" "signature" edited
expect_refuse "a manifest signed by another root key" "signature" other-root
expect_refuse "the committed root key is not the signer's" "signature" root-mismatch
expect_refuse "an RSA root key" "root key|p-256" root-rsa
expect_refuse "an Ed25519 root key" "root key|p-256" root-ed
expect_refuse "an ECDSA P-384 root key" "root key|p-256" root-p384
expect_refuse "a signature that is not base64" "signature" sig-garbage
expect_refuse "an empty signature file" "signature" sig-empty
expect_refuse "a signature that is not an ECDSA signature of the file" "signature" sig-ed
expect_refuse "a signature with a line break inside its base64" "signature" sig-noncanon
expect_refuse "an empty manifest" "manifest" empty
expect_refuse "a manifest that is not JSON" "manifest|json" not-json
expect_refuse "a manifest that is a JSON array" "manifest|object" array
expect_refuse "a manifest in UTF-16" "manifest" utf16
expect_refuse "a manifest with a repeated key" "manifest|duplicate" dup-key
expect_refuse "an unknown field" "unknown field|note" unknown-field
expect_refuse "no public_key" "public_key|missing" no-key
expect_refuse "no key_id" "key_id|missing" no-id
expect_refuse "no valid_from" "valid_from|missing" no-from
expect_refuse "a key_id that is not the hash of the key" "key_id" wrong-id
expect_refuse "a key_id in capital letters (one spelling)" "key_id" id-upper
expect_refuse "a public_key that is not a string" "public_key" key-number
expect_refuse "a public_key that is not a key" "public_key" junk-key
expect_refuse "two keys in one public_key" "public_key" two-keys
expect_refuse "text around the PEM block" "public_key" pad-key
expect_refuse "an ed25519 key (the KMS key is ECDSA P-256)" "public_key|p-256" ed-key
expect_refuse "an RSA key" "public_key|p-256" rsa-key
expect_refuse "an ECDSA P-384 key" "public_key|p-256" p384-key

# ---- time: the clock of the run against the manifest's window, never a time inside a record --------------------------------
expect_refuse "valid_from after the verification time" "not yet valid" notyet
expect_refuse "valid_to before the verification time" "expired" expired
expect_refuse "valid_to equal to the verification time (the window is half open)" "expired" expired-now
expect_refuse "revoked_at before the verification time" "revoked" revoked
expect_refuse "revoked_at equal to the verification time" "revoked" revoked-now
expect_refuse "a date without a time" "valid_from|date" bad-date
expect_refuse "a date that does not exist" "valid_from|date" bad-date2
expect_refuse "a valid_to that is not a date" "valid_to|date" bad-date3
expect_refuse "a date that is a number" "valid_from|date" date-number

# ---- the manifest is read before the template's tag rules write anything -----------------------------------------------------------------
rm -f "$work/policy.json"; rc=0; run policy make --template "$work/edited/template.json" --tag v0.3.0 --out "$work/policy.json" || rc=$?
[ "$rc" = 1 ] && [ ! -e "$work/policy.json" ] && ok "a refused manifest leaves no policy file behind" || bad "a policy file exists after a refusal (exit $rc)"

echo "chain-manifest-test: $pass passed, $failn failed"
[ "$failn" = 0 ]
