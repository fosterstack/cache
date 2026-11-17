#!/usr/bin/env bash
# The daily presence check of the monthly evidence letter (REQ-REL-014, the owner's Oct 3 amendment): from the 3rd
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
# The policy of a copy that carries the root-signed key manifest: the key it lists for the letter's month, not
# today's. Prints the policy path; else one line and exit 1.
key_policy() {
  local release=$1 dir=$2 name id signed refusal
  for name in release-key-manifest.json release-key-manifest.sig; do
    id=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<< "$release")
    [ -n "$id" ] || { echo "the release carries no $name"; return 1; }
    gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$dir/$name"
  done
  # the key's window meets the date the letter was SIGNED (the bundle's Rekor time), not the month it is about and not the
  # release's unsigned published_at. Only the inclusionPromise (the signed entry timestamp) signs integratedTime, so a bundle
  # without one has no signed date; the verification of the bundle that follows covers the time read here, and a failure there ends the run.
  jq -e '.verificationMaterial.tlogEntries | length == 1' "$dir/$md.bundle" > /dev/null 2>&1 ||
    { echo "the bundle does not hold exactly one Rekor entry: no one signed time"; return 1; }
  jq -e '.verificationMaterial.tlogEntries[0].inclusionPromise | type == "object"' "$dir/$md.bundle" > /dev/null 2>&1 ||
    { echo "the bundle holds no inclusionPromise: its Rekor time is not signed"; return 1; }
  signed=$(jq -r '.verificationMaterial.tlogEntries[0].integratedTime // empty' "$dir/$md.bundle" 2> /dev/null) || signed=
  [[ "$signed" =~ ^[0-9]+$ ]] || { echo "the bundle holds no readable Rekor time: no signed date"; return 1; }
  # the checks of chain-verify.py check_manifest (root signature, closed fields, RSA-4096, key_id, window, no revocation) at that time
  cat .github/policy/release-key-root.pub > "$dir/release-key-root.pub"
  refusal=$(python3 -I bin/chain-verify.py manifest-at --dir "$dir" --at "$signed" 2>&1 > /dev/null) ||
    { echo "the key manifest is refused: ${refusal#refused at manifest: }"; return 1; }
  # the key's standing now: the root-checked manifest committed here, when it is for the same key, may have revoked it after this copy was signed
  cur=.github/policy
  now_id=$(jq -er .key_id "$cur/release-key-manifest.json" 2> /dev/null) || { echo "the current key manifest is unreadable"; return 1; }
  [ "$now_id" != "$(jq -r .key_id "$dir/release-key-manifest.json")" ] ||
    refusal=$(python3 -I bin/chain-verify.py manifest-now --dir "$cur" 2>&1 > /dev/null) ||
    { echo "the current key manifest is refused: ${refusal#refused at manifest: }"; return 1; }
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
  refusal=$(bash bin/evidence-letter-verify.sh "$policy" "$work/copy$n/$md" 2>&1) ||
    die "$month, $tag: ${refusal#evidence-letter-verify: }"
done < "$work/copies.jsonl"
