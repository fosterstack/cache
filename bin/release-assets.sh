#!/usr/bin/env bash
# Release, last witnessed step (rules 56 and 64): creates the GitHub release as a draft and attaches release-upload/, which release-postverify staged and verified;
# that step has passed before this one runs. The draft is downloaded and compared with release-upload/, and only then published. A release is created only when none
# exists, only with --verify-tag (the tag must already exist), and nothing in the chain creates, moves or pushes a tag. Nothing is rebuilt and nothing is signed here.
set -euo pipefail
shopt -s nullglob
if [ -z "${GH_TOKEN:-}" ]; then echo "release-assets: GH_TOKEN is unset" >&2; exit 2; fi
rel="$GITHUB_REF_NAME"
files=()
for f in release-upload/*.apk release-upload/*.json release-upload/*.txt release-upload/*.sha256 release-upload/*.sig release-upload/*.bundle release-upload/*.gz; do
  files+=("$f")
done
if [ "${#files[@]}" = 0 ]; then echo "release-assets: nothing to attach" >&2; exit 1; fi
# A tag with any release, a draft a failed run left included, stops here: nothing is deleted or overwritten, an operator deletes the draft by hand.
listed=$(gh release list --limit 1000 --json tagName,isDraft | python3 -I -B -c 'import json, sys; print(any(r["tagName"] == sys.argv[1] for r in json.load(sys.stdin)))' "$rel")
[ "$listed" = False ] || { echo "release-assets: $rel already has a release or a draft: delete it by hand before a re-run" >&2; exit 1; }
# the notes are release-stage's (a generated patch tag's notes, else the fixed evidence text); this step reads no tag object
[ -f release-notes.txt ] && [ ! -L release-notes.txt ] || { echo "release-assets: release-notes.txt, written by release-stage, is missing" >&2; exit 1; }
# a draft: nobody sees the release until what it stores has been compared with what was staged
gh release create "$rel" --draft --title "fscache $rel" --notes-file release-notes.txt --verify-tag
gh release upload "$rel" "${files[@]}"
rm -rf release-published
gh release download "$rel" -D release-published
python3 -I -B bin/release-gate.py --dir release-published --same-as release-upload
gh release edit "$rel" --draft=false
