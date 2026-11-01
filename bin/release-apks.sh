#!/usr/bin/env bash
# Release, second witnessed step (rules 17, 22, 56, 64): the apks Build made are signed with the release KMS key. Build's names are read through one
# fixed table (REQ-CHAIN-007-AC17): the artifact apk-ubuntu-24.04 holds x86_64/ (amd64) and apk-ubuntu-24.04-arm holds aarch64/ (arm64), each with the
# standard apk fscache-<version>-r0.apk and the fips apk fscache-fips-<version>-r0.apk. Each of the
# four apks must have exactly the digest Build attested (apk-standard-amd64, apk-standard-arm64, apk-fips-amd64, apk-fips-arm64) before anything is signed.
# The signing is cache's bin/release-sign-apks.sh with RELEASE_KMS_KEY_REF (awskms:///<key>) from the environment: no key file exists and no secret is read. Each signed apk
# is copied to release-apks/<arch>/ with its Rekor bundle <apk>.bundle beside it. Rebuild's apks are NOT here: the job that holds the signing role receives
# no build output but Build's own apks (the owner's rule of Oct 21 2026); the comparison with Rebuild is the compare job's, which this job needs.
set -euo pipefail
shopt -s nullglob
if [ -z "${RELEASE_KMS_KEY_REF:-}" ]; then echo "release-apks: RELEASE_KMS_KEY_REF is unset" >&2; exit 2; fi
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-apks: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never signs)" >&2; exit 1; }
runners="ubuntu-24.04:x86_64:amd64 ubuntu-24.04-arm:aarch64:arm64"
variants="standard fips"
pattern() { case "$1" in standard) printf %s 'fscache-[0-9]*-r0.apk' ;; fips) printf %s 'fscache-fips-*-r0.apk' ;; esac; }
rm -rf release-apks release-apks-build
for row in $runners; do
  runner="${row%%:*}"
  rest="${row#*:}"
  arch="${rest%%:*}"
  short="${rest#*:}"
  for variant in $variants; do
    pat=$(pattern "$variant")
    key="apk-$variant-$short"
    want=$(jq -r --arg k "$key" '.[$k] // empty' witness-build/digests.json)
    if [ -z "$want" ]; then echo "release-apks: the attested digest $key is missing" >&2; exit 1; fi
    files=("apks/$runner/$arch"/$pat)
    if [ "${#files[@]}" = 0 ]; then echo "release-apks: no apk found for $variant $arch" >&2; exit 1; fi
    if [ "${#files[@]}" != 1 ]; then echo "release-apks: ${#files[@]} $variant apks for $arch, Build attested exactly one" >&2; exit 1; fi
    got=$(python3 bin/apk-tool.py digest "${files[0]}")
    if [ "$got" != "$want" ]; then echo "release-apks: ${files[0]} differs from the digest Build attested for $key ($got, attested $want)" >&2; exit 1; fi
    mkdir -p "release-apks-build/$arch"
    cp "${files[0]}" "release-apks-build/$arch/"
  done
done
bash bin/release-sign-apks.sh --build-dir release-apks-build
for row in $runners; do
  runner="${row%%:*}"
  rest="${row#*:}"
  arch="${rest%%:*}"
  short="${rest#*:}"
  for variant in $variants; do
    pat=$(pattern "$variant")
    for f in release-apks-build/$arch/$pat; do
      signer=$(python3 bin/apk-tool.py signer "$f")
      if [ "$signer" != release.rsa.pub ]; then echo "release-apks: $f is not signed by the release key (signer: $signer)" >&2; exit 1; fi
      got=$(python3 bin/apk-tool.py digest "$f")
      want=$(jq -r --arg k "apk-$variant-$short" '.[$k]' witness-build/digests.json)
      if [ "$got" != "$want" ]; then echo "release-apks: $f differs from the attested digest after signing ($got, attested $want)" >&2; exit 1; fi
      [ -f "$f.bundle" ] && [ ! -L "$f.bundle" ] || { echo "release-apks: $f has no Rekor bundle beside it after signing" >&2; exit 1; }
      mkdir -p "release-apks/$arch"
      cp "$f" "$f.bundle" "release-apks/$arch/"
    done
  done
done
