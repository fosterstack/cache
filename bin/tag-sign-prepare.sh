#!/usr/bin/env bash
# The first step of sign-tag: the tag object decide asked for and the digest the release key signs.
set -euo pipefail
tag=$(cat tag-request/tag)
when=$(cat tag-request/time)
tagger='fosterstack release <release@users.noreply.github.com>'
python3 -I bin/tag-sign.py prepare --tag "$tag" --commit "$GITHUB_SHA" --notes tag-request/notes.md --tagger "$tagger" --time "$when" --object tag-work/tag.object --digest tag-work/tag.digest
