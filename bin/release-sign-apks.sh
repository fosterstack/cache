#!/usr/bin/env bash
# Sign the released apks with the stored release key (v0.3.0 rules 17, 22).
#
#   release-sign-apks.sh --build-dir A --key K        (K must be the key whose public half is build/keys/release.rsa.pub)
#
# A is the output directory of Build (<dir>/<arch>/<name>-<version>.apk, signed with the non-secret assembly key). Each apk in A is
# re-signed in place with `melange sign --signing-key K`, so the released apk carries the release key and nothing a customer trusts is
# ever signed with the assembly key. K must not be the committed assembly key.
# Rebuild's apks never reach this script (owner's rule of Oct 21 2026, ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md: the job that
# holds the signing key receives no build output but the artifacts it signs): the comparison of Build's and Rebuild's apks is bin/release-compare.sh,
# which runs in a job without a key, and the release job needs that job.
#
# Only files named *.apk are signed. An APKINDEX.tar.gz in Build keeps its assembly-key signature: the release workflow must not ship it as it is.
# Exit codes: 0 all signed | 1 a signing step failed (nothing in Build's directory was changed) |
# 2 refused: a missing argument or file, a symlink, a key that is not a readable RSA private key, the key is
# the assembly key (recognised by its public half), build/keys/release.rsa.pub is not a readable public key (the committed placeholder, until a
# human commits the real half: every release is refused), the public half of --key does not match release.rsa.pub, or Build carries a
# signature other than the assembly key's (no tool run).
set -euo pipefail

die() { echo "release-sign-apks.sh: $1" >&2; exit "${2:-2}"; }
# run from the repository root only: bin/apk-tool.py is named by its literal repo-relative path, as build-apk.sh names its helpers
[ -f bin/release-sign-apks.sh ] && [ -f bin/apk-tool.py ] || die "run bin/release-sign-apks.sh from the repository root (bin/apk-tool.py is named by its repo-relative path)" 2
# fixed locations, no test hook in this file: bin/build-apk-test.sh runs a COPY in which exactly the lines ending in TEST-SUBST are replaced and
# checks that the copy differs from this file in no other line (REQ-BUILDAPK-001-AC7, AC8)
PY3=/usr/bin/python3            # TEST-SUBST
OPENSSL=/usr/bin/openssl        # TEST-SUBST
MELANGE=/usr/local/bin/melange  # TEST-SUBST
KEYS_DIR=$PWD/build/keys        # TEST-SUBST

a= key=
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || die "missing value for $1"
  case $1 in
    --build-dir) a=$2;; --key) key=$2;;
    *) die "unknown argument: $1";;
  esac
  shift 2
done
keysdir=$KEYS_DIR
[ -d "$a" ] || die "--build-dir is not a directory: $a"
[ ! -L "$key" ] || die "--key is a symlink; refusing (the key is read from a regular file, never through a link)"
[ -f "$key" ] || die "--key is not a file: $key"
# Everything below reads PRIVATE COPIES (a 0700 temp directory): the key and Build's apks are copied once, and the guard and melange both use those
# copies, so nothing can be swapped between a check and its use. Only the final replace touches Build.
tmp=$(mktemp -d)
staged=()
cleanup() { local rc=$?; set +e; for f in "${staged[@]}"; do rm -f "$f"; done; rm -rf "$tmp" 2>/dev/null || true; exit $rc; }
trap cleanup EXIT
mkdir "$tmp/key" && cp "$key" "$tmp/key/release.rsa" || die "cannot copy --key to the private area"
cp -RP "$a" "$tmp/build" || die "cannot copy --build-dir to the private area"
orig_a=$a; ca=$tmp/build; keyfile=$key; key=$tmp/key/release.rsa
# The key is read the way melange reads it (apko pkg/apk/signature: the FIRST PEM block of any label, then PKCS#1): the file must hold exactly
# ONE PEM block, labelled exactly RSA PRIVATE KEY, with no headers (so not encrypted), no CR, and its public half is derived from that one block.
# The assembly key is recognised by its public half (not by its bytes or file name), derived the same way from the committed files.
derive_pub() { # <private key file>  -> the public key (PEM) of its single RSA PRIVATE KEY block, or exit 2 with the reason
  "$PY3" -I -B - "$1" "$OPENSSL" <<'PY'
import base64, re, subprocess, sys
path = sys.argv[1]
def _tlv(b, i, end):
    if i + 2 > end: raise ValueError("truncated")
    tag, l = b[i], b[i + 1]
    if l < 0x80: n, h = l, 2
    elif l == 0x80 or l > 0x84: raise ValueError("indefinite or oversized length")
    else:
        k = l & 0x7F
        if i + 2 + k > end: raise ValueError("truncated length")
        n, h = int.from_bytes(b[i + 2:i + 2 + k], "big"), 2 + k
    if i + h + n > end: raise ValueError("content past the end")
    return tag, i + h, i + h + n
def _children(b, s, e):
    out = []
    while s < e:
        t, cs, ce = _tlv(b, s, e); out.append((t, cs, ce)); s = ce
    return out
def der_rsa_private(b):
    """exactly ONE PKCS#1 RSAPrivateKey and nothing after it: SEQUENCE { INTEGER version 0, then eight INTEGERs }"""
    t, s, e = _tlv(b, 0, len(b))
    if t != 0x30 or e != len(b): raise ValueError("not one SEQUENCE spanning the whole block (trailing bytes, or a second object)")
    ch = _children(b, s, e)
    if len(ch) != 9 or any(c[0] != 0x02 for c in ch) or b[ch[0][1]:ch[0][2]] != b"\x00": raise ValueError("not a PKCS#1 RSAPrivateKey (version 0 and eight INTEGERs)")
def der_rsa_public(b):
    """exactly ONE SubjectPublicKeyInfo of rsaEncryption and nothing after it"""
    t, s, e = _tlv(b, 0, len(b))
    if t != 0x30 or e != len(b): raise ValueError("not one SEQUENCE spanning the whole block (trailing bytes, or a second object)")
    ch = _children(b, s, e)
    if len(ch) != 2 or ch[0][0] != 0x30 or ch[1][0] != 0x03: raise ValueError("not a SubjectPublicKeyInfo")
    alg = _children(b, ch[0][1], ch[0][2])
    if len(alg) != 2 or b[alg[0][1]:alg[0][2]] != bytes.fromhex("2a864886f70d010101") or alg[0][0] != 0x06 or alg[1][0] != 0x05 or alg[1][1] != alg[1][2]: raise ValueError("not rsaEncryption with NULL parameters")
    bits = b[ch[1][1]:ch[1][2]]
    if not bits or bits[0] != 0: raise ValueError("bit string with unused bits")
    inner = bits[1:]
    t2, s2, e2 = _tlv(inner, 0, len(inner))
    k = _children(inner, s2, e2)
    if t2 != 0x30 or e2 != len(inner) or len(k) != 2 or any(c[0] != 0x02 for c in k): raise ValueError("not RSAPublicKey (two INTEGERs) spanning the bit string")
def refuse(m): print("release-sign-apks.sh: " + m, file=sys.stderr); sys.exit(2)
try:
    data = open(path, "rb").read(); text = data.decode("ascii")
except (OSError, UnicodeDecodeError):
    refuse("--key %s cannot be read as an ASCII PEM file" % path)
if "\r" in text:
    refuse("--key %s has carriage returns (CRLF line endings); refusing" % path)
lines = text.split("\n")
b = [i for i, l in enumerate(lines) if l.startswith("-----BEGIN ")]; e = [i for i, l in enumerate(lines) if l.startswith("-----END ")]
if len(b) != 1 or len(e) != 1 or e[0] < b[0]:
    refuse("--key %s must hold exactly one PEM block (found %d BEGIN and %d END lines); refusing" % (path, len(b), len(e)))
if lines[b[0]] != "-----BEGIN RSA PRIVATE KEY-----" or lines[e[0]] != "-----END RSA PRIVATE KEY-----":
    refuse("--key %s: the PEM label must be exactly RSA PRIVATE KEY (the only form melange parses); got %r" % (path, lines[b[0]]))
body = lines[b[0] + 1:e[0]]
if not body or any(not re.fullmatch(r"[A-Za-z0-9+/=]+", l) for l in body):
    refuse("--key %s has a header line or other non-base64 text inside the block (an encrypted key?); refusing" % path)
try:
    der_rsa_private(base64.b64decode("".join(body), validate=True))   # exactly ONE complete PKCS#1 key, no second key and no trailing bytes in the block
except Exception as ex:
    refuse("--key %s: the block is not exactly one PKCS#1 RSA private key (%s); refusing" % (path, ex))
block = "\n".join(lines[b[0]:e[0] + 1]) + "\n"
r = subprocess.run([sys.argv[2], "rsa", "-pubout", "-passin", "pass:"], input=block.encode(), capture_output=True, env={"LC_ALL": "C", "PATH": "/nonexistent"})
if r.returncode != 0:
    refuse("--key %s is not a readable RSA private key (openssl: %s)" % (path, r.stderr.decode(errors="replace").strip()[:100]))
sys.stdout.write(r.stdout.decode())
PY
}
keypub=$(derive_pub "$key") || exit 2   # the private copy
asmpub=$(derive_pub "$keysdir/assembly.rsa") || die "the committed assembly key $keysdir/assembly.rsa cannot be read"
asmpub2=$("$OPENSSL" rsa -pubin -in "$keysdir/assembly.rsa.pub" -pubout 2>/dev/null) || die "the committed $keysdir/assembly.rsa.pub cannot be read"
if [ "$keypub" = "$asmpub" ] || [ "$keypub" = "$asmpub2" ]; then die "refusing the assembly key (its public half is build/keys/assembly.rsa.pub): nothing a customer trusts is signed with it (rule 22)"; fi
[ "$(basename "$keyfile")" = release.rsa ] || die "--key must be a file named release.rsa: melange names the signature after the key file, and the committed public key is build/keys/release.rsa.pub"

relpub=$("$OPENSSL" rsa -pubin -in "$keysdir/release.rsa.pub" -pubout 2>/dev/null) || die "$keysdir/release.rsa.pub is not a readable public key (the committed placeholder, until a human commits the real public half of the release key); no release can be signed yet"
[ "$keypub" = "$relpub" ] || die "the public half of --key does not match $keysdir/release.rsa.pub: this is not the stored release key"

# fail closed on anything but plain files: a symlink anywhere, and an apk that is not a regular file
for d in "$ca"; do
  link=$(find "$d" -type l -print -quit)
  [ -z "$link" ] || die "$link is a symlink; refusing (only regular files are signed or compared)"
  ctl=$(LC_ALL=C find "$d" -name '*[[:cntrl:]]*' -print -quit | LC_ALL=C tr '\001-\037\177' '?')
  [ -z "$ctl" ] || die "a file name under $d holds a control character (newline or other): ${ctl#"$d"/}; refusing (a name is never split into two)"
  odd=$(find "$d" -name '*.apk' ! -type f -print -quit)
  [ -z "$odd" ] || die "$odd is not a regular file; refusing"
done
apks=()
while read -r f; do apks+=("$f"); done < <(cd "$ca" && LC_ALL=C find . -name '*.apk' -type f | sort)
[ ${#apks[@]} -gt 0 ] || die "no apk in $orig_a"
for rel in "${apks[@]}"; do   # Build's apks come from the assembly-key build: anything else was signed by somebody else
  sg=$("$PY3" -I -B bin/apk-tool.py signer "$ca/$rel") || die "cannot read the signer of ${rel#./}"
  [ "$sg" = assembly.rsa.pub ] || die "${rel#./} is signed by '$sg', not assembly.rsa.pub: Build must carry the assembly key's signature"
  "$PY3" -I -B bin/apk-tool.py verify "$ca/$rel" "$keysdir/assembly.rsa.pub" >/dev/null || die "the signature of ${rel#./} does not verify against the committed assembly.rsa.pub: a signature name is not a signature"
done
melange_bin=$MELANGE; [ -x "$melange_bin" ] || die "melange is not installed at $MELANGE (bin/install-build-tools.sh melange)" 1
# sign the private copies, check each signer, and only when every one succeeded replace the originals: a failure leaves Build's directory untouched
for rel in "${apks[@]}"; do
  [ ! -e "$orig_a/$rel.new" ] || die "$orig_a/$rel.new already exists (a leftover or a planted file); refusing, nothing in $orig_a was changed"
  "$melange_bin" sign --signing-key "$key" "$ca/$rel" || die "melange sign failed for ${rel#./}; nothing in $orig_a was changed" 1
  signer=$("$PY3" -I -B bin/apk-tool.py signer "$ca/$rel") || die "cannot read the signer of the signed ${rel#./}; nothing in $orig_a was changed" 1
  [ "$signer" = release.rsa.pub ] || die "${rel#./} is signed by '$signer', not release.rsa.pub; nothing in $orig_a was changed" 1
  "$PY3" -I -B bin/apk-tool.py verify "$ca/$rel" "$keysdir/release.rsa.pub" >/dev/null || die "the signature of the signed ${rel#./} does not verify against the committed release.rsa.pub; nothing in $orig_a was changed" 1
done
# stage every replacement next to its original FIRST (any failure here leaves the originals alone), then rename them all
for rel in "${apks[@]}"; do
  cp "$ca/$rel" "$orig_a/$rel.new" || die "cannot stage the signed ${rel#./} in $orig_a; nothing in $orig_a was changed" 1
  staged+=("$orig_a/$rel.new")
done
for rel in "${apks[@]}"; do
  mv -f "$orig_a/$rel.new" "$orig_a/$rel" || die "cannot replace ${rel#./} in $orig_a: the directory may now hold a MIX of signed and unsigned apks; discard it and rebuild" 1
done
staged=()
for rel in "${apks[@]}"; do   # the final directory itself is checked
  [ "$("$PY3" -I -B bin/apk-tool.py signer "$orig_a/$rel")" = release.rsa.pub ] || die "after replacing, ${rel#./} in $orig_a is not signed by release.rsa.pub; discard the directory" 1
  "$PY3" -I -B bin/apk-tool.py verify "$orig_a/$rel" "$keysdir/release.rsa.pub" >/dev/null || die "after replacing, the signature of ${rel#./} in $orig_a does not verify against release.rsa.pub; discard the directory" 1
done
echo "signed ${#apks[@]} apk(s) with the release key"
