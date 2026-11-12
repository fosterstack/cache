#!/usr/bin/env bash
# The daily presence check of the monthly evidence letter (REQ-REL-013, the owner's Oct 3 amendment): from the 3rd
# of each month, once a letter has been published at all, last month's letter and its bundle must be on one
# published release, and every copy must verify (bin/evidence-letter-verify.sh: the release key that the root-signed
# key manifest of that release lists for the month, and the pinned log, no identity). A miss ends here with one plain line, and a failed scheduled run is reported. It reads only;
# it is run by a job of supply-chain.yml.
#   no argument (GH_TOKEN set, read-only; REPO defaults to fosterstack/cache)
set -euo pipefail
die() { echo "evidence-letter-present: $*" >&2; exit 1; }
repo=${REPO:-fosterstack/cache}
today=$(date -u +%Y-%m-%d)
[ "$((10#${today:8:2}))" -ge 3 ] || exit 0
year=${today:0:4}; mon=$((10#${today:5:2}))
if [ "$mon" -eq 1 ]; then year=$((year - 1)); mon=12; else mon=$((mon - 1)); fi
month=$(printf '%04d-%02d' "$year" "$mon")
next=${today:0:7}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
# every page of the releases; a draft never counts
gh api --paginate --slurp "repos/$repo/releases?per_page=100" |
  jq 'add // [] | map(select(.draft == false))' > "$work/releases.json"
# the check starts once some published release carries a letter, named exactly evidence-letter-YYYY-MM.md:
# "evidence-letter-2026-11.md" matches; "evidence-letter-2026-11.md.bundle" and "evidence-letter-2026-1.md" do not
letters='[.[].assets[].name | select(test("^evidence-letter-[0-9]{4}-[0-9]{2}\\.md$"))] | length > 0'
jq -e "$letters" "$work/releases.json" > /dev/null || exit 0
md="evidence-letter-$month.md"
# the letter and its bundle on the same release; every such release is a copy to verify
jq -c --arg md "$md" '.[] | select([.assets[].name] | (index($md) != null and index($md + ".bundle") != null))' \
  "$work/releases.json" > "$work/copies.jsonl"
[ -s "$work/copies.jsonl" ] || die "$md and its bundle are on no published release: no letter for $month"
refusal=$(python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
  --ref refs/heads/main --out "$work/policy.json" 2>&1 > /dev/null) ||
  die "$month: the key manifest is not accepted ($(head -n 1 <<< "$refusal"))"
# The policy of a copy that carries the root-signed key manifest: the key it lists for the letter's month, not
# today's. Prints the policy path; prints nothing when the release carries no manifest; else one line and exit 1.
key_policy() {
  local release=$1 dir=$2 name id
  for name in release-key-manifest.json release-key-manifest.sig; do
    id=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<< "$release")
    [ -n "$id" ] || return 0
    gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$dir/$name"
  done
  base64 -d "$dir/release-key-manifest.sig" > "$dir/manifest.sig" 2> /dev/null ||
    { echo "the key manifest signature is not base64"; return 1; }
  openssl dgst -sha256 -verify .github/policy/release-key-root.pub -signature "$dir/manifest.sig" \
    "$dir/release-key-manifest.json" > /dev/null 2>&1 ||
    { echo "the key manifest is not signed by the root key"; return 1; }
  # the key's window meets the month; a revoked key is refused
  jq -e --arg from "$month-01T00:00:00Z" --arg to "$next-01T00:00:00Z" '.revoked_at == null and .valid_from < $to and
    (.valid_to == null or .valid_to > $from)' "$dir/release-key-manifest.json" > /dev/null ||
    { echo "the key manifest lists no usable key for $month"; return 1; }
  jq '{release_key: {public_key: .public_key}}' "$dir/release-key-manifest.json" > "$dir/policy.json"
  echo "$dir/policy.json"
}
n=0
while read -r release; do
  n=$((n + 1)); mkdir -p "$work/copy$n"
  for name in "$md" "$md.bundle"; do
    id=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<< "$release")
    gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$work/copy$n/$name"
  done
  tag=$(jq -r .tag_name <<< "$release")
  policy=$(key_policy "$release" "$work/copy$n") || die "$month, $tag: $policy"
  refusal=$(bash bin/evidence-letter-verify.sh "${policy:-$work/policy.json}" "$work/copy$n/$md" 2>&1) ||
    die "$month, $tag: ${refusal#evidence-letter-verify: }"
done < "$work/copies.jsonl"
