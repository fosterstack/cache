#!/usr/bin/env bash
# The first step of sign-tag: the tag object decide asked for and the digest the release key signs.
set -euo pipefail
python3 -I bin/tag-sign.py prepare --tag "$(cat tag-request/tag)" --commit "$GITHUB_SHA" --notes tag-request/notes.md --tagger 'fosterstack release <release@users.noreply.github.com>' --time "$(cat tag-request/time)" --object tag-work/tag.object --digest tag-work/tag.digest
