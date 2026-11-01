#!/usr/bin/env bash
# Sign the released apks with the release KMS key (v0.3.0 rules 17, 22; the one-key rule: no stored apk key exists).
#
#   RELEASE_KMS_KEY_REF=awskms:///<key> release-sign-apks.sh --build-dir A
#
# A is the output directory of Build (<dir>/<arch>/<name>-<version>.apk, signed with the non-secret assembly key).
# Each apk in A is re-signed in place: the control stream is signed by cosign with the release KMS key
# (the Rekor-only signing config of the chain), the signature is checked as RSA PKCS#1 v1.5 SHA-256 against the
# committed build/keys/release.rsa.pub (a key that lists a PSS algorithm first would sign PSS, which apk-tools rejects:
# that fails here, closed), and the apk tool puts it in front of the unchanged control and data streams as the one
# .SIGN.RSA256.release.rsa.pub member. cosign v3.1.3 ignores --output-signature: the signature is taken from the bundle (messageSignature, strict
# base64, its messageDigest the SHA2_256 of the signed control stream). The Rekor bundle of each signature is kept beside the apk as <apk>.bundle.
# Nothing a customer trusts is ever signed with the assembly key.
# Rebuild's apks never reach this job (owner's rule of Oct 21 2026,
# ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md: the job that holds the signing role receives no build
# output but the artifacts it signs). The compare job checks Build's apks against Rebuild's, without a key, and the
# release job needs that job.
#
# Only files named *.apk are signed. An APKINDEX.tar.gz in Build keeps its assembly-key signature, so the release
# workflow must not ship it as it is.
# Exit codes: 0 all signed | 1 a signing step failed (nothing in Build's directory was changed) |
# 2 refused: a missing or unknown argument (--key is unknown), RELEASE_KMS_KEY_REF unset or not awskms:///<name>, a
# missing file, a symlink, build/keys/release.rsa.pub is not a readable public key (the committed placeholder, until a
# human commits the real half: every release is refused) or is the assembly public key, or Build carries a signature
# other than the assembly key's (no tool run).
set -euo pipefail
root_dir=$PWD

die() { echo "release-sign-apks.sh: $1" >&2; exit "${2:-2}"; }
# Run from the repository root only: bin/apk-tool.py is named by its literal repo-relative path, as build-apk.sh
# names its helpers.
[ -f bin/release-sign-apks.sh ] && [ -f bin/apk-tool.py ] ||
  die "run bin/release-sign-apks.sh from the repository root (bin/apk-tool.py is named by its repo-relative path)"
# Fixed locations, no test hook in this file: bin/build-apk-test.sh runs a COPY in which exactly the lines ending
# in TEST-SUBST are replaced and checks that the copy differs from this file in no other line
# (REQ-BUILDAPK-001-AC7, AC8).
PY3=/usr/bin/python3            # TEST-SUBST
OPENSSL=/usr/bin/openssl        # TEST-SUBST
COSIGN=/usr/local/bin/cosign    # TEST-SUBST
KEYS_DIR=$PWD/build/keys        # TEST-SUBST

build_dir=
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || die "missing value for $1"
  case $1 in
    --build-dir) build_dir=$2;;
    *) die "unknown argument: $1";;
  esac
  shift 2
done
# the key is the KMS reference the job pins (as the release signing step reads it); checked before any tool runs
[ -n "${RELEASE_KMS_KEY_REF:-}" ] || die "RELEASE_KMS_KEY_REF is unset"
case "$RELEASE_KMS_KEY_REF" in awskms:///?*) ;; *) die "RELEASE_KMS_KEY_REF is not a KMS key reference (awskms:///<name>)";; esac
kept="nothing in $build_dir was changed"
[ -d "$build_dir" ] || die "--build-dir is not a directory: $build_dir"
# Everything below reads PRIVATE COPIES (a 0700 temp directory): Build's apks are copied once, and the checks and
# the signing all use those copies, so nothing can be swapped between a check and its use. Only the final replace
# touches Build.
tmp=$(mktemp -d)
staged=()
cleanup() { local rc=$?; set +e; for f in "${staged[@]}"; do rm -f "$f"; done; rm -rf "$tmp" 2>/dev/null; exit $rc; }
trap cleanup EXIT
cp -RP "$build_dir" "$tmp/build" || die "cannot copy --build-dir to the private area"
copy=$tmp/build

# the release public key: a readable public key, and not the assembly public key (nothing a customer trusts is signed with that one)
relpub=$("$OPENSSL" rsa -pubin -in "$KEYS_DIR/release.rsa.pub" -pubout 2>/dev/null) ||
  die "$KEYS_DIR/release.rsa.pub is not a readable public key (the committed placeholder, until a human commits "\
"the real public half of the release key); no release can be signed yet"
asmpub=$("$OPENSSL" rsa -pubin -in "$KEYS_DIR/assembly.rsa.pub" -pubout 2>/dev/null) ||
  die "the committed $KEYS_DIR/assembly.rsa.pub cannot be read"
[ "$relpub" != "$asmpub" ] ||
  die "$KEYS_DIR/release.rsa.pub is the assembly public key: nothing a customer trusts is signed with the assembly key (rule 22)"

# fail closed on anything but plain files: a symlink anywhere, and an apk that is not a regular file
link=$(find "$copy" -type l -print -quit)
[ -z "$link" ] || die "$link is a symlink; refusing (only regular files are signed or compared)"
ctl=$(LC_ALL=C find "$copy" -name '*[[:cntrl:]]*' -print -quit | LC_ALL=C tr '\001-\037\177' '?')
name=${ctl#"$copy"/}
[ -z "$ctl" ] ||
  die "a file name under $copy holds a control character (newline or other): $name; "\
"refusing (a name is never split into two)"
odd=$(find "$copy" -name '*.apk' ! -type f -print -quit)
[ -z "$odd" ] || die "$odd is not a regular file; refusing"
apks=()
while read -r f; do apks+=("$f"); done < <(cd "$copy" && LC_ALL=C find . -name '*.apk' -type f | sort)
[ ${#apks[@]} -gt 0 ] || die "no apk in $build_dir"
n=0
for rel in "${apks[@]}"; do   # Build's apks come from the assembly-key build: anything else was signed by somebody else
  sg=$("$PY3" -I -B bin/apk-tool.py signer "$copy/$rel") || die "cannot read the signer of ${rel#./}"
  [ "$sg" = assembly.rsa.pub ] ||
    die "${rel#./} is signed by '$sg', not assembly.rsa.pub: Build must carry the assembly key's signature"
  "$PY3" -I -B bin/apk-tool.py verify "$copy/$rel" "$KEYS_DIR/assembly.rsa.pub" >/dev/null ||
    die "the signature of ${rel#./} does not verify against the committed assembly.rsa.pub: "\
"a signature name is not a signature"
  dg=$("$PY3" -I -B bin/apk-tool.py digest "$copy/$rel") || die "cannot read the digest of ${rel#./}"
  printf '%s\n' "$dg" >"$tmp/digest.$n"
  n=$((n + 1))
done
for rel in "${apks[@]}"; do
  [ ! -e "$build_dir/$rel.bundle" ] ||
    die "$build_dir/$rel.bundle already exists (a leftover or a planted file); refusing, $kept"
  [ ! -e "$build_dir/$rel.new" ] || die "$build_dir/$rel.new already exists (a leftover or a planted file); refusing, $kept"
  [ ! -e "$build_dir/$rel.bundle.new" ] ||
    die "$build_dir/$rel.bundle.new already exists (a leftover or a planted file); refusing, $kept"
done
[ -x "$COSIGN" ] || die "cosign is not installed at $COSIGN (install it before this step)" 1
# Sign the private copies, check each signature and signer, and only when every one succeeded replace the originals:
# a failure leaves Build's directory untouched.
n=0
for rel in "${apks[@]}"; do
  w=$tmp/work/$n; mkdir -p "$w"
  "$PY3" -I -B bin/apk-tool.py control "$copy/$rel" "$w/control.gz" || die "cannot read the control stream of ${rel#./}; $kept" 1
  cp .github/policy/cosign-signing-config.json "$w/signing-config.json" || die "cannot copy the signing config; $kept" 1
  # run in the private directory with literal file names: the chain's records judge needs every argument of the signing call to be a literal (its blob, and so its type, must be known)
  cd "$w"
  # cosign v3.1.3 writes the signature into the bundle (messageSignature) and ignores --output-signature, so none is passed and none is read from a file
  "$COSIGN" sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config signing-config.json --bundle sig.bundle control.gz ||
    die "signing the control stream failed for ${rel#./}; $kept" 1
  cd "$root_dir"
  [ -s "$w/sig.bundle" ] || die "cosign left no signature or no bundle for ${rel#./}; $kept" 1
  # the signature is taken from the bundle, strictly: messageSignature.signature is base64 and messageSignature.messageDigest is the SHA2_256 of exactly these control bytes;
  # anything absent, undecodable or different stops the apk (exit 1, no .SIGN written)
  rc=0; "$PY3" -I -B - "$w/sig.bundle" "$w/control.gz" "$w/sig.bin" <<'PY' || rc=$?
import base64, binascii, hashlib, json, sys
try:
    doc = json.load(open(sys.argv[1]))
    ms = doc["messageSignature"]
    sig = base64.b64decode(ms["signature"], validate=True)
    if not sig:
        raise ValueError("empty")
except (OSError, ValueError, KeyError, TypeError, AttributeError, binascii.Error):
    sys.exit(11)
try:
    md = ms["messageDigest"]
    want = base64.b64decode(md["digest"], validate=True)
    ok = md["algorithm"] == "SHA2_256" and want == hashlib.sha256(open(sys.argv[2], "rb").read()).digest()
except (OSError, ValueError, KeyError, TypeError, AttributeError, binascii.Error):
    ok = False
if not ok:
    sys.exit(12)
entries = doc.get("verificationMaterial", {}).get("tlogEntries") if isinstance(doc.get("verificationMaterial"), dict) else None
if not (isinstance(entries, list) and len(entries) == 1):
    sys.exit(13)
fd = open(sys.argv[3], "xb"); fd.write(sig); fd.close()
PY
  case $rc in
    0) ;;
    11) die "the bundle of ${rel#./} holds no messageSignature signature that decodes as base64; $kept" 1;;
    12) die "the messageDigest of the bundle of ${rel#./} is not the SHA2_256 of the control stream that was signed; $kept" 1;;
    13) die "the bundle of ${rel#./} does not hold exactly one tlogEntries item (Rekor entry); $kept" 1;;
    *) die "cannot read the bundle of ${rel#./}; $kept" 1;;
  esac
  # RSA PKCS#1 v1.5 SHA-256 only: a signature of another form (PSS, from a key that lists PSS first) is refused, no .SIGN is written
  "$OPENSSL" dgst -sha256 -verify "$KEYS_DIR/release.rsa.pub" -signature "$w/sig.bin" "$w/control.gz" >/dev/null ||
    die "the KMS signature of ${rel#./} is not RSA PKCS#1 v1.5 SHA-256 under build/keys/release.rsa.pub (a PSS key, another key, "\
"or a bad signature); $kept" 1
  "$PY3" -I -B bin/apk-tool.py attach-signature "$copy/$rel" "$w/sig.bin" "$w/signed.apk" ||
    die "cannot attach the signature to ${rel#./}; $kept" 1
  mv -f "$w/signed.apk" "$copy/$rel" || die "cannot place the signed ${rel#./}; $kept" 1
  signer=$("$PY3" -I -B bin/apk-tool.py signer "$copy/$rel") ||
    die "cannot read the signer of the signed ${rel#./}; $kept" 1
  [ "$signer" = release.rsa.pub ] || die "${rel#./} is signed by '$signer', not release.rsa.pub; $kept" 1
  "$PY3" -I -B bin/apk-tool.py verify "$copy/$rel" "$KEYS_DIR/release.rsa.pub" >/dev/null ||
    die "the signature of the signed ${rel#./} does not verify against the committed release.rsa.pub; $kept" 1
  want=$(cat "$tmp/digest.$n")
  [ "$("$PY3" -I -B bin/apk-tool.py digest "$copy/$rel")" = "$want" ] ||
    die "the digest of ${rel#./} changed by signing; $kept" 1
  n=$((n + 1))
done
# Stage every replacement next to its original FIRST (any failure here leaves the originals alone), then rename them.
n=0
for rel in "${apks[@]}"; do
  cp "$copy/$rel" "$build_dir/$rel.new" || die "cannot stage the signed ${rel#./} in $build_dir; $kept" 1
  staged+=("$build_dir/$rel.new")
  cp "$tmp/work/$n/sig.bundle" "$build_dir/$rel.bundle.new" || die "cannot stage the bundle of ${rel#./} in $build_dir; $kept" 1
  staged+=("$build_dir/$rel.bundle.new")
  n=$((n + 1))
done
for rel in "${apks[@]}"; do
  mv -f "$build_dir/$rel.bundle.new" "$build_dir/$rel.bundle" ||
    die "cannot place the bundle of ${rel#./} in $build_dir: the directory may now hold a MIX of signed and unsigned apks; "\
"discard it and rebuild" 1
  mv -f "$build_dir/$rel.new" "$build_dir/$rel" ||
    die "cannot replace ${rel#./} in $build_dir: the directory may now hold a MIX of signed and unsigned apks; "\
"discard it and rebuild" 1
done
staged=()
n=0
for rel in "${apks[@]}"; do   # the final directory itself is checked
  [ "$("$PY3" -I -B bin/apk-tool.py signer "$build_dir/$rel")" = release.rsa.pub ] ||
    die "after replacing, ${rel#./} in $build_dir is not signed by release.rsa.pub; discard the directory" 1
  "$PY3" -I -B bin/apk-tool.py verify "$build_dir/$rel" "$KEYS_DIR/release.rsa.pub" >/dev/null ||
    die "after replacing, the signature of ${rel#./} in $build_dir does not verify against release.rsa.pub; "\
"discard the directory" 1
  want=$(cat "$tmp/digest.$n")
  [ "$("$PY3" -I -B bin/apk-tool.py digest "$build_dir/$rel")" = "$want" ] ||
    die "after replacing, the digest of ${rel#./} in $build_dir changed; discard the directory" 1
  n=$((n + 1))
done
echo "signed ${#apks[@]} apk(s) with the release key"
