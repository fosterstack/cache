#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): downloads what bin/evidence-letter.py reads. For the month it takes every final release
# published in it and the latest final release before it (the current images when the month had none), and the published advisories.
#   arguments: the month YYYY-MM, then the output folder (GH_TOKEN set; REPO defaults to fosterstack/cache)
# Reads only; it writes into OUTDIR/rel/<tag>/ and OUTDIR/advisories.json.
set -euo pipefail
month=${1:?the month YYYY-MM is the first argument}
out=${2:?the output folder is the second argument}
[[ "$month" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || { echo "evidence-letter-fetch: the month is YYYY-MM" >&2; exit 2; }
repo=${REPO:-fosterstack/cache}
mkdir -p "$out/rel"
# final releases only (vX.Y.Z): the ones published in the month, plus the newest one before it
tags=$(gh release list --repo "$repo" --exclude-drafts --exclude-pre-releases --limit 200 --json tagName,publishedAt |
  jq -r --arg m "$month" '[.[] | select(.tagName | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))] as $r
    | ([$r[] | select(.publishedAt | startswith($m))] + ([$r[] | select(.publishedAt < ($m + "-01"))] | sort_by(.publishedAt) | .[-1:]))
    | .[].tagName')
for tag in $tags; do
  dir="$out/rel/$tag"
  mkdir -p "$dir"
  gh api "repos/$repo/releases/tags/$tag" > "$dir/release.json"
  # the three files the letter reads, by asset id through the API (no `gh release download`)
  jq -r '.assets[] | select(.name == "release-manifest.json" or .name == "fosterstack-cache.openvex.json" or (.name | test("-collection\\.json$"))) | "\(.id) \(.name)"' "$dir/release.json" |
    while read -r id name; do
      gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$dir/$name"
    done
done
gh api "repos/$repo/security-advisories?state=published&per_page=100" --paginate --slurp | jq 'add // []' > "$out/advisories.json"
