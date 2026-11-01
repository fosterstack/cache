#!/usr/bin/env bash
# Release, fifth witnessed step (rules 56 and 64): attaches the evidence to the GitHub release. It uploads what the earlier steps made, nothing
# is rebuilt and nothing is signed here. A release is created only when none exists, only with --verify-tag (the tag must already exist), and
# nothing in the chain creates, moves or pushes a tag. The apks of the two architectures, and the SBOMs and lock files of the two images, have
# the same file names, so each is attached under its architecture's or variant's name.
set -euo pipefail
shopt -s nullglob
if [ -z "${GH_TOKEN:-}" ]; then echo "release-assets: GH_TOKEN is unset" >&2; exit 2; fi
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-assets: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
rel="$GITHUB_REF_NAME"
# Everything is staged under its release name in release-upload/. The apks of the two architectures, and the SBOMs and lock files of the two images,
# have the same file names, so each is staged under its architecture's or variant's name.
# Round 1 B3: what is attached is what Build recorded and the list is complete, checked before a release is created or anything is staged. The four
# Linux archives are exactly Build's (digests.json item archive-linux-ARCH / archive-fips-linux-ARCH names the sha256 of fscache_VER_linux_ARCH.tar.gz /
# fscache-fips_VER_linux_ARCH.tar.gz); both architectures have an apk; the Check records are there to attach.
for arch in x86_64 aarch64; do
  std=(release-apks/$arch/fscache-[0-9]*.apk); fips=(release-apks/$arch/fscache-fips-*.apk); all=(release-apks/$arch/*.apk)
  [ "${#std[@]}" = 1 ] || { echo "release-assets: release-apks/$arch must hold exactly one standard apk (fscache-VERSION.apk), it holds ${#std[@]}: the list is incomplete" >&2; exit 1; }
  [ "${#fips[@]}" = 1 ] || { echo "release-assets: release-apks/$arch must hold exactly one -fips apk (fscache-fips-VERSION.apk), it holds ${#fips[@]}: the list is incomplete" >&2; exit 1; }
  [ "${#all[@]}" = 2 ] || { echo "release-assets: release-apks/$arch holds ${#all[@]} apks, exactly the two Build attested are attached" >&2; exit 1; }
done
for n in scanners acceptance runtime arm64; do
  [ -f "witness-check/witness-$n/$n-collection.json" ] || { echo "release-assets: the Check record witness-check/witness-$n/$n-collection.json is missing: the list is incomplete" >&2; exit 1; }
done
for r in witness-build/build witness-rebuild/rebuild witness-check/witness-scanners/scanners witness-check/witness-acceptance/acceptance witness-check/witness-runtime/runtime witness-check/witness-arm64/arm64; do
  [ -f "$r-collection.rekor.json" ] || { echo "release-assets: $r-collection.rekor.json is missing: the entries file beside the record is part of the list, which is incomplete" >&2; exit 1; }
done
python3 bin/release-metadata.py bind-archives --version "${rel#v}" --digests witness-build/digests.json --dist dist
rm -rf release-upload release-published
mkdir release-upload
# Everything attached comes from an explicit inventory, and a release name has exactly one origin (round 1 F4): a second file under a name already
# staged, or a file in a record directory that is not named below, stops the step before anything is created or uploaded.
stage() { # stage SRC NAME
  [ -f "$1" ] && [ ! -L "$1" ] || { echo "release-assets: $1 is not a regular file" >&2; exit 1; }
  [ ! -e "release-upload/$2" ] || { echo "release-assets: $1 would replace $2, which an earlier file already staged: a release name has one origin" >&2; exit 1; }
  cp "$1" "release-upload/$2"
}
only() { # only DIR NAME...: DIR holds no json file besides these
  local dir="$1" f n ok; shift
  for f in "$dir"/*.json; do
    ok=0; for n in "$@"; do [ "${f##*/}" = "$n" ] && ok=1; done
    [ "$ok" = 1 ] || { echo "release-assets: $f is not in the inventory of $dir ($*)" >&2; exit 1; }
  done
}
for f in release-apks/*/*.apk; do
  arch="${f#release-apks/}"
  arch="${arch%%/*}"
  case "$arch" in x86_64) short=amd64 ;; aarch64) short=arm64 ;; *) echo "release-assets: the apk architecture $arch is not in the table" >&2; exit 1 ;; esac
  stage "$f" "$short-${f##*/}"
done
for v in production fips; do
  for kind in "$v.full.lock.json:images/$v.full.lock.json" "$v.sbom.json:images/$v-sbom/sbom.json"; do
    if [ -f "${kind#*:}" ]; then stage "${kind#*:}" "${kind%%:*}"; fi
  done
done
only witness-build build-collection.json build-collection.rekor.json digests.json items.json admission-baseline.json
only witness-rebuild rebuild-collection.json rebuild-collection.rekor.json verdict.json
only provenance provenance.json provenance.rekor.json provenance.bundle.json
for n in scanners acceptance runtime arm64; do only "witness-check/witness-$n" "$n-collection.json" "$n-collection.rekor.json"; done
for f in dist/*.txt; do [ "${f##*/}" = checksums.txt ] || { echo "release-assets: $f is not in the inventory of dist (the four archives and checksums.txt)" >&2; exit 1; }; done
for f in dist/*.tar.gz dist/checksums.txt release-evidence/*.bundle release-evidence/*.json release-metadata/release-manifest.json release-metadata/fosterstack-cache*.json release-metadata/release-files.sha256 policy.json \
         witness-build/build-collection.json witness-build/build-collection.rekor.json witness-build/digests.json witness-build/items.json witness-build/admission-baseline.json witness-rebuild/rebuild-collection.json witness-rebuild/rebuild-collection.rekor.json witness-check/witness-*/*-collection.json witness-check/witness-*/*-collection.rekor.json provenance/provenance.json provenance/provenance.rekor.json provenance/provenance.bundle.json; do
  stage "$f" "${f##*/}"
done
python3 bin/release-metadata.py gate --dir release-upload
files=()
for f in release-upload/*.apk release-upload/*.json release-upload/*.txt release-upload/*.sha256 release-upload/*.bundle release-upload/*.gz; do
  files+=("$f")
done
if [ "${#files[@]}" = 0 ]; then echo "release-assets: nothing to attach" >&2; exit 1; fi
# The release's notes: a generated patch tag's notes (REQ-REL-009-AC8; bin/release-metadata.py tag-notes accepts only the release workflow's own patch tag), else
# the fixed evidence text. Only a definite "release not found" creates a release; any other failure of the view stops here (round 1 R3).
notes=(--notes "Evidence: see docs/verify-release.md for the verification commands of this release.")
if git cat-file tag "$rel" > release-tag.txt 2> /dev/null && python3 bin/release-metadata.py tag-notes --tag "$rel" --object release-tag.txt > release-notes.md 2> /dev/null && [ -s release-notes.md ]; then
  notes=(--notes-file release-notes.md)
fi
rm -f release-tag.txt
if ! view_err=$(gh release view "$rel" 2>&1 > /dev/null); then
  [[ "$view_err" == *"release not found"* ]] || { echo "release-assets: cannot tell whether release $rel exists: $view_err" >&2; exit 1; }
  gh release create "$rel" --title "fscache $rel" "${notes[@]}" --verify-tag
elif [ "${notes[0]}" = --notes-file ]; then
  gh release edit "$rel" "${notes[@]}"      # the release exists already: a generated patch tag's notes are still the release's notes
fi
gh release upload "$rel" "${files[@]}"
gh release download "$rel" -D release-published
python3 bin/release-metadata.py gate --dir release-published --same-as release-upload
