#!/usr/bin/env bash
# Checks every signature Sign made (release-signed/) before the Release job logs in to a registry or pushes anything: release-publish and release-sign
# both run it first. A file is good only when its bundle holds one Rekor entry of this file's sha256 and the signature verifies under build/keys/release.rsa.pub
# (bin/chain-verify.py bundle-check, offline). A bad or missing signature stops the run with exit 1 and names the file. It changes nothing and needs no credential.
set -euo pipefail
repo="fosterstack/cache"
cfg=.github/policy/cosign-signing-config.json
pub=build/keys/release.rsa.pub
signed=release-signed
[ -d "$signed" ] && [ ! -L "$signed" ] || { echo "release-sign-verify: $signed (Sign's signatures) is missing or not a directory" >&2; exit 1; }
openssl rsa -pubin -in "$pub" -noout 2>/dev/null || { echo "release-sign-verify: $pub is not a readable public key" >&2; exit 1; }
prod=$(jq -r '."image-production" // empty' witness-build/digests.json)
fips=$(jq -r '."image-fips" // empty' witness-build/digests.json)
rx='^sha256:[0-9a-f]{64}$'
[[ "$prod" =~ $rx ]] && [[ "$fips" =~ $rx ]] || { echo "release-sign-verify: an attested image digest is missing or malformed" >&2; exit 1; }
scratch=$(mktemp -d)
[ -n "$scratch" ] && [ -d "$scratch" ] || { echo "release-sign-verify: no scratch directory" >&2; exit 1; }
trap 'rm -rf "$scratch"' EXIT
# check_signed FILE BUNDLE: the bundle holds one Rekor entry of the signature of exactly this file's sha256, and the signature is RSA PKCS#1 v1.5 SHA-256 under the release public key
check_signed() {
  local dg
  [ -f "$1" ] && [ ! -L "$1" ] && [ -f "$2" ] && [ ! -L "$2" ] || { echo "release-sign-verify: $1 or its bundle $2 is missing or not a regular file" >&2; exit 1; }
  read -r dg _ < <(sha256sum "$1")
  python3 -I -B bin/chain-verify.py bundle-check --bundle "$2" --digest "$dg" --public-key "$pub" --signing-config "$cfg" || { echo "release-sign-verify: $2 is not the signature of $1 with its Rekor entry" >&2; exit 1; }
  jq -er .messageSignature.signature "$2" | base64 -d > "$scratch/check.sig"
  openssl dgst -sha256 -verify "$pub" -signature "$scratch/check.sig" "$1" > /dev/null || { echo "release-sign-verify: the signature in $2 does not verify for $1 under $pub" >&2; exit 1; }
}
for f in "$signed"/release-evidence/*.json; do
  check_signed "$f" "$f.bundle"
done
check_signed "$signed/checksums.txt" "$signed/checksums.txt.bundle"
check_signed "$signed/release-metadata/release-files.sha256" "$signed/release-metadata/release-files.sha256.bundle"
# the blobs Release holds from Build: their bundles are Sign's
check_signed images/production-sbom/sbom.json "$signed/release-evidence/production.sbom.json.bundle"
check_signed images/fips-sbom/sbom.json "$signed/release-evidence/fips.sbom.json.bundle"
check_signed apks/ubuntu-24.04/fscache-modules.spdx.json "$signed/release-evidence/fscache-modules.spdx.json.bundle"
check_signed apks/ubuntu-24.04/fscache-modules-fips.spdx.json "$signed/release-evidence/fscache-modules-fips.spdx.json.bundle"
check_signed images/production.full.lock.json "$signed/release-evidence/production.full.lock.json.bundle"
check_signed images/fips.full.lock.json "$signed/release-evidence/fips.full.lock.json.bundle"
check_signed policy.json "$signed/release-evidence/release-policy.bundle"
# an image payload names its registry's repository and this digest
for host in ghcr.io docker.io; do
  for pair in "production:$prod" "fips:$fips"; do
    v="${pair%%:*}"; d="${pair#*:}"; p="$signed/images/$host/$v.payload"
    check_signed "$p" "$signed/images/$host/$v.bundle"
    jq -e --arg d "$d" --arg r "$host/$repo" '.critical.image."docker-manifest-digest" == $d and .critical.identity."docker-reference" == $r' "$p" > /dev/null || { echo "release-sign-verify: $p does not name $host/$repo@$d" >&2; exit 1; }
  done
done
