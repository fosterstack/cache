#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): downloads what bin/evidence-letter.py reads, and checks it against the
# release's own signatures first, so the letter never states a file nobody signed.
#   arguments: the month YYYY-MM (it must be over), then the output folder
#   (GH_TOKEN set; REPO defaults to fosterstack/cache)
# It takes every final release published in the month, or the newest one before it when the month had none. Per release:
#   release-files.sha256 must verify by the release key of that release's policy and the pinned log (the shared
#   bin/evidence-letter-verify.sh), and list the manifest and OpenVEX files by their hashes; the four Check records must
#   verify under the same policy (the chain-verify.py command Release runs). Any failure ends here with one line.
# Reads only: it writes into OUT/rel/<tag>/ and OUT/advisories.json.
set -euo pipefail
die() { echo "evidence-letter-fetch: $*" >&2; exit 1; }
month=${1:?the month YYYY-MM is the first argument}
out=${2:?the output folder is the second argument}
# "2026-11" matches; "2026-13" and "2026-1" do not
[[ "$month" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] || { echo "evidence-letter-fetch: the month is YYYY-MM" >&2; exit 2; }
[[ "$month" < "$(date -u +%Y-%m)" ]] || die "$month is not over yet: no letter"
repo=${REPO:-fosterstack/cache}
mkdir -p "$out/rel"

# every release, all pages; the letter's releases are the final ones published in the month, else the newest
# one before it. A final tag is vX.Y.Z by bin/build-admit.py's one tag grammar: "v0.3.1" matches; "v0.3.1-rc1" and "0.3.1" do not
gh api --paginate --slurp "repos/$repo/releases?per_page=100" | jq 'add // []' > "$out/releases.json"
asset() { # asset RELEASE.JSON NAME FOLDER: downloads the release's asset of that name by its id
  local id
  id=$(jq -r --arg n "$2" '[.assets[] | select(.name == $n) | .id][0] // empty' "$1")
  [ -n "$id" ] || die "$(jq -r .tag_name "$1") has no asset $2"
  gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$3/$2"
}

verify_signed() { # verify_signed TAG DIR: the release's release-files.sha256 verifies, and lists the manifest in DIR; one line on any failure
  local tag=$1 dir=$2 refusal
  refusal=$(python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
    --tag "$tag" --out "$dir/policy.json" 2>&1 > /dev/null) ||
    die "$tag: no release policy: $(head -n 1 <<< "$refusal")"
  refusal=$(bash bin/evidence-letter-verify.sh "$dir/policy.json" "$dir/release-files.sha256" 2>&1) ||
    die "$tag: ${refusal#evidence-letter-verify: }"
  grep -qxF "$(sha256sum "$dir/release-manifest.json" | cut -d' ' -f1)  release-manifest.json" "$dir/release-files.sha256" ||
    die "$tag: release-manifest.json is not the file the signed release-files.sha256 lists"
}

# the release's date is the published_at of its release-manifest.json once that file is verified against the signed
# release-files.sha256, never the API's unsigned one; a final release from v0.3.0 on with no verified manifest date
# has no signed date, and the fetch refuses. A release below v0.3.0 has no signed files and is never selected: its
# manifest must still name its own tag's version, so the tag alone (the API's word) does not place it
: > "$out/dates.jsonl"
for tag in $(jq -r --arg t "$(python3 -I bin/build-admit.py tag-pattern)" '.[] | select(.draft == false and .prerelease == false
    and (.tag_name | test("\\A" + $t + "\\z") and (contains("-rc") | not))) | .tag_name' "$out/releases.json"); do
  dir="$out/rel/$tag"
  mkdir -p "$dir"
  jq --arg t "$tag" '.[] | select(.tag_name == $t)' "$out/releases.json" > "$dir/release.json"
  asset "$dir/release.json" release-manifest.json "$dir"
  jq -e --arg v "${tag#v}" '.version == $v' "$dir/release-manifest.json" > /dev/null 2>&1 ||
    die "$tag: release-manifest.json names another version"
  if [ "$tag" != v0.3.0 ] && [ "$(printf '%s\n' v0.3.0 "$tag" | sort -V | head -n 1)" = "$tag" ]; then
    rm -r "$dir"
    continue
  fi
  asset "$dir/release.json" release-files.sha256 "$dir"
  asset "$dir/release.json" release-files.sha256.bundle "$dir"
  verify_signed "$tag" "$dir"
  jq -ce --arg t "$tag" '{tag_name: $t, published_at: (.published_at | if type == "string" then . else error("no date") end)}' "$dir/release-manifest.json" \
    >> "$out/dates.jsonl" 2> /dev/null || die "$tag: release-manifest.json holds no readable published_at: no signed date"
done
tags=$(jq -rs --arg m "$month" '
  . as $final
  | [$final[] | select(.published_at | startswith($m))] as $in
  | if ($in | length) > 0 then $in
    else [$final[] | select(.published_at < ($m + "-01"))] | sort_by(.published_at) | .[-1:] end
  | .[].tag_name' "$out/dates.jsonl")

for tag in $tags; do
  dir="$out/rel/$tag"
  for name in fosterstack-cache.openvex.json digests.json; do
    asset "$dir/release.json" "$name" "$dir"
  done
  grep -qxF "$(sha256sum "$dir/fosterstack-cache.openvex.json" | cut -d' ' -f1)  fosterstack-cache.openvex.json" "$dir/release-files.sha256" ||
    die "$tag: fosterstack-cache.openvex.json is not the file the signed release-files.sha256 lists"
  for step in scanners acceptance runtime arm64; do
    asset "$dir/release.json" "$step-collection.json" "$dir"
    mkdir -p "$dir/witness-check/witness-$step"
    cat "$dir/$step-collection.json" > "$dir/witness-check/witness-$step/$step-collection.json"
  done
  python3 -I bin/chain-verify.py check-list --policy "$dir/policy.json" --digests "$dir/digests.json" \
    --dir "$dir/witness-check" > /dev/null 2> "$dir/refusal" ||
    die "$tag: the Check records: $(head -n 1 "$dir/refusal")"
done
# published advisories of a public repository are readable without a token; all pages.
# A refusal (403, 404) ends the letter.
advisories=$(gh api --paginate --slurp "repos/$repo/security-advisories?state=published&per_page=100" 2>&1) ||
  die "the published advisories cannot be read ($(head -n 1 <<< "$advisories")): no letter"
jq 'add // []' <<< "$advisories" > "$out/advisories.json"
