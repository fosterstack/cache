#!/usr/bin/env bash
# Release, second witnessed step (rules 56 and 64): re-signs the apks Build made with the stored release key. Each apk is first compared with
# the digest Build attested (control and data sections, signature ignored) and nothing is signed unless all of them match. The key is written
# to a private file that is removed on every exit; it is never put on an argument list, in the output or in a log.
set -euo pipefail
if [ -z "${APK_RELEASE_SIGNING_KEY:-}" ]; then echo "release-apks: APK_RELEASE_SIGNING_KEY is not set" >&2; exit 2; fi
archs="amd64 arm64"
for arch in $archs; do
  want=$(jq -r --arg k "apk-$arch" '.[$k] // empty' witness-build/digests.json)
  files=("apks/$arch"/*.apk)
  if [ ! -e "${files[0]}" ]; then echo "release-apks: no apk found for $arch" >&2; exit 1; fi
  if [ "${#files[@]}" != 1 ]; then echo "release-apks: ${#files[@]} apks for $arch, Build attested exactly one" >&2; exit 1; fi
  got=$(python3 bin/apk-tool.py digest "${files[0]}")
  if [ -z "$want" ] || [ "$got" != "$want" ]; then echo "release-apks: ${files[0]} differs from the digest Build attested ($got, attested ${want:-none})" >&2; exit 1; fi
done
umask 077
keyfile=$(mktemp)
trap 'rm -f "$keyfile"' EXIT
printf %s "$APK_RELEASE_SIGNING_KEY" > "$keyfile"
for arch in $archs; do
  mkdir -p "release-apks/$arch"
  for f in "apks/$arch"/*.apk; do
    out="release-apks/$arch/${f##*/}"
    cp "$f" "$out"
    melange sign --key "$keyfile" "$out"
    signer=$(python3 bin/apk-tool.py signer "$out")
    if [ "$signer" != release.rsa.pub ]; then echo "release-apks: $out is not signed by the release key (signer: $signer)" >&2; exit 1; fi
  done
done
