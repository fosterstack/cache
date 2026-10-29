#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): downloads what bin/evidence-letter.py reads. For the month it takes every final release
# published in it and the latest final release before it (the current images when the month had none), and the published advisories.
#   evidence-letter-fetch.sh YYYY-MM OUTDIR      (GH_TOKEN set; REPO defaults to fosterstack/cache)
# Reads only; it writes into OUTDIR/rel/<tag>/ and OUTDIR/advisories.json.
set -euo pipefail
month=${1:?usage: evidence-letter-fetch.sh YYYY-MM OUTDIR}
out=${2:?usage: evidence-letter-fetch.sh YYYY-MM OUTDIR}
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
  gh release download "$tag" --repo "$repo" --dir "$dir" --pattern release-manifest.json \
    --pattern fosterstack-cache.openvex.json --pattern '*-collection.json'
  gh api "repos/$repo/releases/tags/$tag" > "$dir/release.json"
done
gh api "repos/$repo/security-advisories?state=published&per_page=100" --paginate --slurp | jq 'add // []' > "$out/advisories.json"
