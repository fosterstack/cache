#!/usr/bin/env bash
# proves: REQ-CHAIN-007-AC8
#
# The Release step's referrer (bin/release-sign.sh): the release manifest attestation Sign made is a Sigstore bundle that
# carries its Rekor entry; the step writes it as the layer of an OCI referrer manifest, pushes that by digest and runs the
# customer guide's own `cosign verify-attestation`. This suite runs the step's two functions (write_referrer_layout,
# attach_manifest) for real, with the pinned cosign 3.1.3 and crane 0.22.1 on PATH, against a local `crane registry serve`
# (no network). Rekor is a stub: the bundle's entry is signed by a test log key that a test trusted root holds; the only
# change to the guide's command is --trusted-root, added by a wrapper named cosign. With no cosign or crane on PATH it
# prints SKIP and exits 0, but under GITHUB_ACTIONS=true it fails.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
sut="$here/release-sign.sh"
pass=0; fail=0
ok() { echo "ok:   $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }
if ! command -v cosign > /dev/null 2>&1 || ! command -v crane > /dev/null 2>&1; then
  if [ "${GITHUB_ACTIONS:-}" = true ]; then echo "FAIL: the pinned cosign and crane are not installed"; echo "pass=0 fail=1"; exit 1; fi
  echo "SKIP: cosign and crane are not on PATH (the pinned cosign 3.1.3 and crane 0.22.1 are needed)"; echo "pass=0 fail=0"; exit 0
fi
real_cosign="$(command -v cosign)"
work="$(mktemp -d)"
regpid=""
cleanup() { [ -z "$regpid" ] || kill "$regpid" 2> /dev/null; rm -rf "$work"; }
trap cleanup EXIT
type_url=https://fosterstack.com/attestations/release-manifest/v1

cat > "$work/mk.py" <<'PY'
import base64, hashlib, json, os, subprocess, sys, time
b64 = lambda b: base64.b64encode(b).decode()
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
compact = lambda o: json.dumps(o, separators=(",", ":"))
def sh(*a, inp=None): return subprocess.run(a, input=inp, check=True, capture_output=True).stdout
def spki(key): return sh("openssl", "pkey", "-in", key, "-pubout", "-outform", "DER")
def ecsign(key, data): return sh("openssl", "dgst", "-sha256", "-sign", key, inp=data)
cmd, d = sys.argv[1], sys.argv[2]
if cmd == "init":
    der = spki(d + "/log.key")
    root = {"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1", "tlogs": [{"baseUrl": "http://127.0.0.1:3000", "hashAlgorithm": "SHA2_256",
            "publicKey": {"rawBytes": b64(der), "keyDetails": "PKIX_ECDSA_P256_SHA_256", "validFor": {"start": "2020-01-01T00:00:00Z"}}, "logId": {"keyId": b64(hashlib.sha256(der).digest())}}],
            "certificateAuthorities": [], "ctlogs": [], "timestampAuthorities": []}
    open(d + "/trusted-root.json", "w").write(compact(root))
elif cmd == "bundle":
    ref, hexd, mode, out = sys.argv[3:7]
    logkey = d + ("/log2.key" if mode == "wronglog" else "/log.key")
    stmt = compact({"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": ref, "digest": {"sha256": hexd}}],
                    "predicateType": "https://fosterstack.com/attestations/release-manifest/v1", "predicate": {"version": "1.0"}}).encode()
    ptype = b"application/vnd.in-toto+json"
    pae = b"DSSEv1 %d %s %d %s" % (len(ptype), ptype, len(stmt), stmt)
    sig = sh("openssl", "dgst", "-sha256", "-sign", d + "/release.rsa.key", inp=pae)
    env = {"payloadType": ptype.decode(), "payload": b64(stmt), "signatures": [{"sig": b64(sig)}]}
    open(out + ".envelope.json", "w").write(compact(env))
    der = spki(logkey); keyid = hashlib.sha256(der).digest(); t = int(time.time())
    body = canon({"apiVersion": "0.0.1", "kind": "dsse", "spec": {"envelopeHash": {"algorithm": "sha256", "value": hashlib.sha256(canon(env)).hexdigest()},
            "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(stmt).hexdigest()},
            "signatures": [{"signature": env["signatures"][0]["sig"], "verifier": b64(open(d + "/release.rsa.pub", "rb").read())}]}})
    set_ = ecsign(logkey, canon({"body": b64(body), "integratedTime": t, "logID": keyid.hex(), "logIndex": 0}))
    root = hashlib.sha256(b"\x00" + body).digest()
    text = "rekor.stub.test - 1\n1\n" + b64(root) + "\n"
    cp = text + "\n— rekor.stub.test " + b64(keyid[:4] + ecsign(logkey, text.encode())) + "\n"
    entries = [] if mode == "noentry" else [{"logIndex": "0", "logId": {"keyId": b64(keyid)}, "kindVersion": {"kind": "dsse", "version": "0.0.1"}, "integratedTime": str(t),
            "inclusionPromise": {"signedEntryTimestamp": b64(set_)}, "canonicalizedBody": b64(body),
            "inclusionProof": {"logIndex": "0", "rootHash": b64(root), "treeSize": "1", "hashes": [], "checkpoint": {"envelope": cp}}}]
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"publicKey": {"hint": "release-key"}, "tlogEntries": entries}, "dsseEnvelope": env}
    open(out + ".bundle.json", "w").write(compact(bundle))
elif cmd == "layoutcheck":
    bundle_f, subj_f, digest = sys.argv[3:6]
    bb = open(bundle_f, "rb").read(); mt = json.loads(bb)["mediaType"]; sb = open(subj_f, "rb").read()
    bad = []
    def need(c, m):
        if not c: bad.append(m)
    sha = lambda b: hashlib.sha256(b).hexdigest()
    need(os.path.isfile(d + "/oci-layout"), "no oci-layout file")
    blobs = d + "/blobs/sha256"
    names = sorted(os.listdir(blobs)) if os.path.isdir(blobs) else []
    need(bool(names), "no blobs/sha256")
    for n in names: need(sha(open(blobs + "/" + n, "rb").read()) == n, "blob %s is not named by its sha256" % n[:12])
    try: idx = json.load(open(d + "/index.json"))
    except Exception as e: idx = {"manifests": []}; bad.append("index.json unreadable: %s" % e)
    ms = idx.get("manifests", [])
    need(len(ms) == 1, "index.json lists %d manifests, want 1" % len(ms))
    if len(ms) == 1:
        dg = ms[0].get("digest", ""); p = blobs + "/" + dg.replace("sha256:", "")
        if not os.path.isfile(p): bad.append("the indexed manifest blob is missing")
        else:
            mb = open(p, "rb").read(); m = json.loads(mb)
            need(ms[0].get("size") == len(mb) and dg == "sha256:" + sha(mb), "index.json digest or size of the manifest is wrong")
            need(m.get("mediaType") == "application/vnd.oci.image.manifest.v1+json", "manifest mediaType %r" % m.get("mediaType"))
            need(m.get("artifactType") == mt, "artifactType %r, want %r" % (m.get("artifactType"), mt))
            c = m.get("config", {})
            need(c.get("mediaType") == "application/vnd.oci.empty.v1+json" and c.get("size") == 2 and c.get("digest") == "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "config is not the empty JSON descriptor")
            need(os.path.isfile(blobs + "/44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a") and open(blobs + "/44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "rb").read() == b"{}", "the empty config blob is missing or not {}")
            ls = m.get("layers", [])
            need(len(ls) == 1, "%d layers, want 1" % len(ls))
            if len(ls) == 1:
                need(ls[0].get("mediaType") == mt and ls[0].get("digest") == "sha256:" + sha(bb) and ls[0].get("size") == len(bb), "the layer descriptor is not the bundle's")
                lp = blobs + "/" + sha(bb)
                need(os.path.isfile(lp) and open(lp, "rb").read() == bb, "the layer blob is not byte-identical to the bundle")
            s = m.get("subject", {})
            need(s.get("digest") == digest, "subject.digest %r" % s.get("digest"))
            need(s.get("mediaType") == json.loads(sb).get("mediaType"), "subject.mediaType %r" % s.get("mediaType"))
            need(s.get("size") == len(sb), "subject.size %r, want %d" % (s.get("size"), len(sb)))
    if bad: print("; ".join(bad)); sys.exit(1)
elif cmd == "payload":     # the decoded payload of cosign's verify-attestation output: print subject digest and predicateType
    for line in open(sys.argv[3]).read().split("\n"):
        if line.strip().startswith("{"):
            st = json.loads(base64.b64decode(json.loads(line)["payload"]))
            print(st["subject"][0]["digest"]["sha256"], st["predicateType"]); break
PY
py() { python3 -I "$work/mk.py" "$@"; }

# the stub log's keys, the release key, the wrapper that adds --trusted-root to verify-attestation
openssl ecparam -name prime256v1 -genkey -noout -out "$work/log.key" 2> /dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$work/log2.key" 2> /dev/null
openssl genrsa -out "$work/release.rsa.key" 3072 2> /dev/null
openssl rsa -in "$work/release.rsa.key" -pubout -out "$work/release.rsa.pub" 2> /dev/null
py init "$work"
mkdir -p "$work/wrap"
cat > "$work/wrap/cosign" <<WRAP
#!/usr/bin/env bash
if [ "\${1:-}" = verify-attestation ]; then exec "$real_cosign" "\$@" --trusted-root "$work/trusted-root.json"; fi
exec "$real_cosign" "\$@"
WRAP
chmod +x "$work/wrap/cosign"
export PATH="$work/wrap:$PATH"
pub="$work/release.rsa.pub"

# the local registry (no referrers API: crane keeps the fallback tag index of a subject)
port=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
crane registry serve --address "127.0.0.1:$port" > "$work/registry.log" 2>&1 &
regpid=$!
up=""
for _ in $(seq 1 50); do crane catalog "127.0.0.1:$port" > /dev/null 2>&1 && { up=1; break; }; sleep 0.2; done
[ -n "$up" ] || { echo "FAIL: the local registry did not start"; cat "$work/registry.log"; echo "pass=$pass fail=$((fail+1))"; exit 1; }
base="127.0.0.1:$port/cache"

# the step's two functions, each from its line `NAME() {` to the first line that is exactly `}`
for fn in write_referrer_layout attach_manifest; do
  awk -v n="$fn" '$0 == n "() {" {f=1} f {print} f && $0 == "}" {exit}' "$sut" > "$work/$fn.sh"
  # shellcheck disable=SC1090
  . "$work/$fn.sh"
  if declare -F "$fn" > /dev/null; then have_$fn=1; else echo "bin/release-sign.sh defines no function $fn"; fi
done 2> /dev/null
have_ok=0; declare -F write_referrer_layout > /dev/null && declare -F attach_manifest > /dev/null && have_ok=1
need_funcs() { # label: fails the case, naming the missing functions, when they are not defined
  [ "$have_ok" = 1 ] && return 0
  bad "$1 -> bin/release-sign.sh does not define the functions write_referrer_layout and attach_manifest yet"; return 1
}

# one image per case: a layer of its own content gives its own digest; sets ref, dig, hex
mkimage() {
  local n=$1 d="$work/img$1"; mkdir -p "$d"
  echo "layer content $n" > "$d/f.txt"; tar -C "$d" -cf "$d/layer.tar" f.txt
  crane append -t "$base:$n" -f "$d/layer.tar" > /dev/null 2>&1 || { bad "image $n: crane append failed"; return 1; }
  dig=$(crane digest "$base:$n"); hex=${dig#sha256:}; ref="$base@$dig"
  crane manifest "$ref" > "$d/subject.json"
}
guide() { cosign verify-attestation --key "$pub" --type "$type_url" "$1"; }

# 6
if cosign version 2>&1 | grep -q 'GitVersion:[[:space:]]*v3\.1\.3\b'; then ok "the cosign this test runs is v3.1.3"; else bad "the cosign on PATH is not v3.1.3: $(cosign version 2>&1 | grep GitVersion)"; fi

# 1 and 2: the good bundle
if mkimage 1; then
  d="$work/img1"; py bundle "$work" "$base" "$hex" good "$d/good"
  if need_funcs "1 LAYOUT"; then
    ( write_referrer_layout "$d/good.bundle.json" "$d/subject.json" "$dig" "$d/layout" ) > "$d/layout.out" 2>&1; rc=$?
    msg=$(py layoutcheck "$d/layout" "$d/good.bundle.json" "$d/subject.json" "$dig" 2>&1); lrc=$?
    if [ $rc -eq 0 ] && [ $lrc -eq 0 ]; then ok "1 LAYOUT: one referrer manifest, blobs named by sha256, bundle as the layer, empty config, subject = the image manifest"; else bad "1 LAYOUT -> rc=$rc $msg $(head -c 300 "$d/layout.out")"; fi
    if [ $rc -eq 0 ] && [ $lrc -eq 0 ]; then
      ( attach_manifest "$d/layout" "$ref" ) > "$d/attach.out" 2>&1; arc=$?
      guide "$ref" > "$d/guide.out" 2> "$d/guide.err"; grc=$?
      pl=$(py payload "$d" "$d/guide.out" 2> /dev/null)
      if [ $arc -eq 0 ] && [ $grc -eq 0 ] && [ "$pl" = "$hex $type_url" ]; then ok "2 GOOD: attach_manifest returns 0 and the guide's command verifies, with this digest and predicateType"; else bad "2 GOOD -> attach=$arc guide=$grc payload=[$pl] $(head -c 400 "$d/attach.out") $(head -c 400 "$d/guide.err")"; fi
    else bad "2 GOOD -> no layout to attach"; fi
  else bad "2 GOOD -> the functions are not defined"; fi
fi

# 3: no Rekor entry in the bundle
if mkimage 2; then
  d="$work/img2"; py bundle "$work" "$base" "$hex" noentry "$d/b"
  if need_funcs "3 NO ENTRY"; then
    ( write_referrer_layout "$d/b.bundle.json" "$d/subject.json" "$dig" "$d/layout" ) > "$d/layout.out" 2>&1; lrc=$?
    ( attach_manifest "$d/layout" "$ref" ) > "$d/attach.out" 2>&1; arc=$?
    guide "$ref" > /dev/null 2> "$d/guide.err"; grc=$?
    if [ $lrc -eq 0 ] && [ $arc -ne 0 ] && [ $grc -ne 0 ]; then ok "3 NO ENTRY: a bundle with no Rekor entry: attach_manifest and the guide's command both fail"; else bad "3 NO ENTRY -> layout=$lrc attach=$arc guide=$grc $(head -c 300 "$d/layout.out")"; fi
  fi
fi

# 4: the entry is signed by a log the trusted root does not hold
if mkimage 3; then
  d="$work/img3"; py bundle "$work" "$base" "$hex" wronglog "$d/b"
  if need_funcs "4 WRONG LOG"; then
    ( write_referrer_layout "$d/b.bundle.json" "$d/subject.json" "$dig" "$d/layout" ) > "$d/layout.out" 2>&1; lrc=$?
    ( attach_manifest "$d/layout" "$ref" ) > "$d/attach.out" 2>&1; arc=$?
    if [ $lrc -eq 0 ] && [ $arc -ne 0 ]; then ok "4 WRONG LOG: an entry from a log the trusted root does not hold makes attach_manifest fail"; else bad "4 WRONG LOG -> layout=$lrc attach=$arc $(head -c 300 "$d/layout.out")"; fi
  fi
fi

# 5: the old form, the bare envelope
if mkimage 4; then
  d="$work/img4"; py bundle "$work" "$base" "$hex" good "$d/b"
  cosign attach attestation --attestation "$d/b.envelope.json" "$ref" > "$d/att.out" 2>&1; att=$?
  guide "$ref" > /dev/null 2> "$d/guide.err"; grc=$?
  if [ $att -eq 0 ] && [ $grc -ne 0 ]; then ok "5 BARE ENVELOPE: the bare envelope attached with cosign attach attestation cannot be verified by the guide's command"; else bad "5 BARE ENVELOPE -> attach=$att guide=$grc $(head -c 300 "$d/att.out")"; fi
fi

# 7: no bypass flag in this file (the pattern is built in pieces so this line does not match itself)
pat="--insecure-ignore-""tlog"
hits=$(grep -c -e "$pat" "$0")
if [ "$hits" = 0 ]; then ok "7 this test never passes the transparency-log bypass flag"; else bad "7 the bypass flag appears $hits times in this test"; fi

echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
