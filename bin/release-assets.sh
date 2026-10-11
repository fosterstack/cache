#!/usr/bin/env bash
# Release, fifth witnessed step (rules 56 and 64): attaches the evidence to the GitHub release. It uploads what the earlier steps made, nothing
# is rebuilt and nothing is signed here. A release is created only when none exists, only with --verify-tag (the tag must already exist), and
# nothing in the chain creates, moves or pushes a tag. The two apks have the same file name, so each is attached under its
# architecture's name.
set -euo pipefail
shopt -s nullglob
if [ -z "${GH_TOKEN:-}" ]; then echo "release-assets: GH_TOKEN is not set" >&2; exit 2; fi
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "release-assets: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z or vX.Y.Z-rc.N" >&2; exit 1; }
rel="$GITHUB_REF_NAME"
flags=()
if [[ "$rel" == *-rc.* ]]; then flags+=(--prerelease); fi
rm -rf release-apks-upload
mkdir release-apks-upload
for f in release-apks/*/*.apk; do
  arch="${f#release-apks/}"
  cp "$f" "release-apks-upload/${arch%%/*}-${f##*/}"
done
files=()
for f in release-apks-upload/*.apk dist/*.tar.gz dist/*.txt sboms/*.json locks/*.json release-evidence/*.bundle release-evidence/*.json dependency-provenance.json policy.json witness-build/*.json witness-rebuild/*.json witness-check/*.json witness-check/*/*.json; do
  files+=("$f")
done
if [ "${#files[@]}" = 0 ]; then echo "release-assets: nothing to attach" >&2; exit 1; fi
if ! gh release view "$rel" > /dev/null 2>&1; then
  gh release create "$rel" --title "fscache $rel" --notes "Evidence: see docs/verify-release.md for the verification commands of this release." ${flags[@]+"${flags[@]}"} --verify-tag
fi
gh release upload "$rel" "${files[@]}"
