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
# one before it. A final tag is vX.Y.Z: "v0.3.1" matches; "v0.3.1-rc1" and "0.3.1" do not
gh api --paginate --slurp "repos/$repo/releases?per_page=100" | jq 'add // []' > "$out/releases.json"
tags=$(jq -r --arg m "$month" '
  [.[] | select(.draft == false and .prerelease == false
                and (.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")))] as $final
  | [$final[] | select(.published_at | startswith($m))] as $in
  | if ($in | length) > 0 then $in
    else [$final[] | select(.published_at < ($m + "-01"))] | sort_by(.published_at) | .[-1:] end
  | .[].tag_name' "$out/releases.json")

asset() { # asset RELEASE.JSON NAME FOLDER: downloads the release's asset of that name by its id
  local id
  id=$(jq -r --arg n "$2" '[.assets[] | select(.name == $n) | .id][0] // empty' "$1")
  [ -n "$id" ] || die "$(jq -r .tag_name "$1") has no asset $2"
  gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$3/$2"
}

verify() { # verify TAG FOLDER: the checks above, one line on any failure
  local tag=$1 dir=$2 name refusal
  refusal=$(python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
    --tag "$tag" --out "$dir/policy.json" 2>&1 > /dev/null) ||
    die "$tag: no release policy: $(head -n 1 <<< "$refusal")"
  refusal=$(bash bin/evidence-letter-verify.sh "$dir/policy.json" "$dir/release-files.sha256" 2>&1) ||
    die "$tag: ${refusal#evidence-letter-verify: }"
  for name in release-manifest.json fosterstack-cache.openvex.json; do
    grep -qxF "$(sha256sum "$dir/$name" | cut -d' ' -f1)  $name" "$dir/release-files.sha256" ||
      die "$tag: $name is not the file the signed release-files.sha256 lists"
  done
  python3 -I bin/chain-verify.py check-list --policy "$dir/policy.json" --digests "$dir/digests.json" \
    --dir "$dir/witness-check" > /dev/null 2> "$dir/refusal" ||
    die "$tag: the Check records: $(head -n 1 "$dir/refusal")"
}

for tag in $tags; do
  dir="$out/rel/$tag"
  mkdir -p "$dir"
  jq --arg t "$tag" '.[] | select(.tag_name == $t)' "$out/releases.json" > "$dir/release.json"
  for name in release-manifest.json fosterstack-cache.openvex.json release-files.sha256 \
      release-files.sha256.bundle digests.json; do
    asset "$dir/release.json" "$name" "$dir"
  done
  for step in scanners acceptance runtime arm64; do
    asset "$dir/release.json" "$step-collection.json" "$dir"
    mkdir -p "$dir/witness-check/witness-$step"
    cat "$dir/$step-collection.json" > "$dir/witness-check/witness-$step/$step-collection.json"
  done
  verify "$tag" "$dir"
done
# published advisories of a public repository are readable without a token; all pages.
# A refusal (403, 404) ends the letter.
advisories=$(gh api --paginate --slurp "repos/$repo/security-advisories?state=published&per_page=100" 2>&1) ||
  die "the published advisories cannot be read ($(head -n 1 <<< "$advisories")): no letter"
jq 'add // []' <<< "$advisories" > "$out/advisories.json"
