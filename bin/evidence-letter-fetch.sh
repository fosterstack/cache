#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): downloads what bin/evidence-letter.py reads, and checks it against the
# release's own signatures first, so the letter never states a file nobody signed.
#   arguments: the month YYYY-MM (it must be over), then the output folder
#   (GH_TOKEN set; REPO defaults to fosterstack/cache)
# It takes every final release published in the month, or the newest one before it when the month had none. Per release:
#   release-files.sha256 must verify by the release key of that release's policy and the pinned log (the shared
#   bin/evidence-letter-verify.sh), and list the manifest and OpenVEX files by their hashes; the six Check records must
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
asset() { # asset RELEASE.JSON NAME FOLDER: downloads the release's asset of that name by its id
  local id
  id=$(jq -r --arg n "$2" '[.assets[] | select(.name == $n) | .id][0] // empty' "$1")
  [ -n "$id" ] || die "$(jq -r .tag_name "$1") has no asset $2"
  gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$3/$2"
}

verify_signed() { # verify_signed TAG DIR: the release's release-files.sha256 verifies, and lists the manifest in DIR; one line on any failure
  local tag=$1 dir=$2 refusal signed
  asset "$dir/release.json" release-key-manifest.json "$dir"
  asset "$dir/release.json" release-key-manifest.sig "$dir"
  # the time the list was signed: only the inclusionPromise signs integratedTime, and the verification that follows covers it
  jq -e '.verificationMaterial.tlogEntries | length == 1' "$dir/release-files.sha256.bundle" > /dev/null 2>&1 ||
    die "$tag: the bundle does not hold exactly one Rekor entry: no one signed time"
  jq -e '.verificationMaterial.tlogEntries[0].inclusionPromise | type == "object"' "$dir/release-files.sha256.bundle" > /dev/null 2>&1 ||
    die "$tag: the bundle holds no inclusionPromise: its Rekor time is not signed"
  signed=$(jq -r '.verificationMaterial.tlogEntries[0].integratedTime // empty' "$dir/release-files.sha256.bundle")
  [[ "$signed" =~ ^[0-9]+$ ]] || die "$tag: the bundle holds no readable Rekor time: no signed date"
  # the key this release was signed with, from its own manifest, root-checked and valid at that time: a rotation or an
  # expiry since then must not stop an old release's letter
  cat .github/policy/release-key-root.pub > "$dir/release-key-root.pub"
  refusal=$(python3 -I bin/chain-verify.py manifest-at --dir "$dir" --at "$signed" 2>&1 > /dev/null) ||
    die "$tag: the key manifest is refused: ${refusal#refused at manifest: }"
  # a revocation committed since then, for the same key, still counts
  if [ "$(jq -r .key_id .github/policy/release-key-manifest.json)" = "$(jq -r .key_id "$dir/release-key-manifest.json")" ]; then
    refusal=$(python3 -I bin/chain-verify.py manifest-now --dir .github/policy 2>&1 > /dev/null) ||
      die "$tag: the current key manifest is refused: ${refusal#refused at manifest: }"
  fi
  jq --arg t "$tag" --arg rekor "$(cat .github/policy/rekor.pub)" \
    --slurpfile tpl .github/policy/release-policy.template.json --slurpfile key "$dir/release-key-manifest.json" -n \
    '{tag: $t, ref: ("refs/tags/" + $t), repository: $tpl[0].repository, release_key: $key[0] | {key_id, public_key},
      rekor_public_key: $rekor, stages: $tpl[0].stages}' > "$dir/policy.json"
  refusal=$(bash bin/evidence-letter-verify.sh "$dir/policy.json" "$dir/release-files.sha256" 2>&1) ||
    die "$tag: ${refusal#evidence-letter-verify: }"
  grep -qxF "$(sha256sum "$dir/release-manifest.json" | cut -d' ' -f1)  release-manifest.json" "$dir/release-files.sha256" ||
    die "$tag: release-manifest.json is not the file the signed release-files.sha256 lists"
}

# the release's date is the published_at of its release-manifest.json once that file is verified against the signed
# release-files.sha256, never the API's unsigned one; a final release from v0.3.0 on with no verified manifest date
# has no signed date, and the fetch refuses. A release below v0.3.0 has no signed files and is never selected or downloaded
: > "$out/dates.jsonl"
for tag in $(jq -r '.[] | select(.draft == false and .prerelease == false and (.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$")))
    | .tag_name' "$out/releases.json"); do
  # a release below v0.3.0 has no signed files and no manifest: no download for it
  if [ "$tag" != v0.3.0 ] && [ "$(printf '%s\n' v0.3.0 "$tag" | sort -V | head -n 1)" = "$tag" ]; then
    continue
  fi
  dir="$out/rel/$tag"
  mkdir -p "$dir"
  jq --arg t "$tag" '.[] | select(.tag_name == $t)' "$out/releases.json" > "$dir/release.json"
  asset "$dir/release.json" release-manifest.json "$dir"
  jq -e --arg v "$tag" '.version == $v' "$dir/release-manifest.json" > /dev/null 2>&1 ||
    die "$tag: release-manifest.json names another version"
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
  # the six Check records, scanners, acceptance and runtime of each runner, each with the entries file of its Rekor log, attached as <runner>-<step>-collection[.rekor].json
  for runner in ubuntu-24.04 ubuntu-24.04-arm; do
    for step in scanners acceptance runtime; do
      mkdir -p "$dir/witness-check/$runner/witness-$step"
      for kind in collection collection.rekor; do
        asset "$dir/release.json" "$runner-$step-$kind.json" "$dir"
        cat "$dir/$runner-$step-$kind.json" > "$dir/witness-check/$runner/witness-$step/$step-$kind.json"
      done
    done
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
