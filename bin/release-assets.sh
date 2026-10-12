#!/usr/bin/env bash
# Release, fifth witnessed step (rules 56 and 64): attaches the evidence to the GitHub release. It uploads what the earlier steps made, nothing
# is rebuilt and nothing is signed here. A release is created only when none exists, only with --verify-tag (the tag must already exist), and
# nothing in the chain creates, moves or pushes a tag. The apks of the two architectures, and the SBOMs and lock files of the two images, have
# the same file names, so each is attached under its architecture's or variant's name.
set -euo pipefail
shopt -s nullglob
if [ -z "${GH_TOKEN:-}" ]; then echo "release-assets: GH_TOKEN is not set" >&2; exit 2; fi
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-assets: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
rel="$GITHUB_REF_NAME"
# Everything is staged under its release name in release-upload/. The apks of the two architectures, and the SBOMs and lock files of the two images,
# have the same file names, so each is staged under its architecture's or variant's name.
rm -rf release-upload release-published
mkdir release-upload
for f in release-apks/*/*.apk; do
  arch="${f#release-apks/}"
  arch="${arch%%/*}"
  case "$arch" in x86_64) short=amd64 ;; aarch64) short=arm64 ;; *) echo "release-assets: the apk architecture $arch is not in the table" >&2; exit 1 ;; esac
  cp "$f" "release-upload/$short-${f##*/}"
done
for v in production fips; do
  for kind in "$v.full.lock.json:images/$v.full.lock.json" "$v.sbom.json:images/$v-sbom/sbom.json"; do
    if [ -f "${kind#*:}" ]; then cp "${kind#*:}" "release-upload/${kind%%:*}"; fi
  done
done
for f in dist/*.tar.gz dist/*.txt release-evidence/*.bundle release-evidence/*.json release-metadata/release-manifest.json release-metadata/fosterstack-cache*.json release-metadata/release-files.sha256 policy.json witness-build/*.json provenance/provenance.json provenance/provenance.rekor.json provenance/provenance.bundle.json witness-rebuild/*.json witness-check/*.json witness-check/*/*.json; do
  cp "$f" "release-upload/${f##*/}"
done
python3 bin/release-metadata.py gate --dir release-upload
files=()
for f in release-upload/*.apk release-upload/*.json release-upload/*.txt release-upload/*.sha256 release-upload/*.bundle release-upload/*.gz; do
  files+=("$f")
done
if [ "${#files[@]}" = 0 ]; then echo "release-assets: nothing to attach" >&2; exit 1; fi
if ! gh release view "$rel" > /dev/null 2>&1; then
  gh release create "$rel" --title "fscache $rel" --notes "Evidence: see docs/verify-release.md for the verification commands of this release." --verify-tag
fi
gh release upload "$rel" "${files[@]}"
gh release download "$rel" -D release-published
python3 bin/release-metadata.py gate --dir release-published --same-as release-upload
