#!/usr/bin/env bash
# Release, last witnessed step (rules 56 and 64): creates the GitHub release and attaches release-upload/, which release-postverify staged and verified; that step
# has passed before this one runs. A release is created only when none exists, only with --verify-tag (the tag must already exist), and nothing in the chain
# creates, moves or pushes a tag. Nothing is rebuilt and nothing is signed here.
set -euo pipefail
shopt -s nullglob
if [ -z "${GH_TOKEN:-}" ]; then echo "release-assets: GH_TOKEN is unset" >&2; exit 2; fi
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-assets: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
rel="$GITHUB_REF_NAME"
files=()
for f in release-upload/*.apk release-upload/*.json release-upload/*.txt release-upload/*.sha256 release-upload/*.sig release-upload/*.bundle release-upload/*.gz; do
  files+=("$f")
done
if [ "${#files[@]}" = 0 ]; then echo "release-assets: nothing to attach" >&2; exit 1; fi
# Only a definite "release not found" creates a release; any other failure of the view stops here (round 1 R3).
if ! view_err=$(gh release view "$rel" 2>&1 > /dev/null); then
  [[ "$view_err" == *"release not found"* ]] || { echo "release-assets: cannot tell whether release $rel exists: $view_err" >&2; exit 1; }
  # a generated patch tag carries its notes (exit 0); any other tag keeps the fixed text (exit 1); a refused form stops here (exit 2)
  notes=$(mktemp)
  tag_object=$(git cat-file tag "$rel" 2>/dev/null) || tag_object=
  status=0
  python3 -I -B bin/patch-decide.py tag-notes <<< "$tag_object" > "$notes" || status=$?
  case $status in
    0) gh release create "$rel" --title "fscache $rel" --notes-file "$notes" --verify-tag ;;
    1) gh release create "$rel" --title "fscache $rel" --notes "Evidence: see docs/verify-release.md for the verification commands of this release." --verify-tag ;;
    *) echo "release-assets: the notes of $rel are refused" >&2; exit 1 ;;
  esac
  rm -f "$notes"
fi
gh release upload "$rel" "${files[@]}"
rm -rf release-published
gh release download "$rel" -D release-published
python3 -I -B bin/release-metadata.py gate --dir release-published --same-as release-upload
