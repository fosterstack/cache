#!/usr/bin/env bash
# The daily presence check of the monthly evidence letter (REQ-REL-013, the owner's Oct 3 amendment): from the 3rd
# of each month, once a letter has been published at all, last month's letter and its bundle must be on one
# published release, and every copy must verify (bin/evidence-letter-verify.sh: the release key and the pinned
# log, no identity). A miss ends here with one plain line, and a failed scheduled run is reported. It reads only;
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
# the check starts once some published release carries a letter, named exactly evidence-letter-YYYY-MM.md
letters='[.[].assets[].name | select(test("^evidence-letter-[0-9]{4}-[0-9]{2}\\.md$"))] | length > 0'
jq -e "$letters" "$work/releases.json" > /dev/null || exit 0
md="evidence-letter-$month.md"
# the letter and its bundle on the same release; every such release is a copy to verify
jq -c --arg md "$md" '.[] | select([.assets[].name] | (index($md) != null and index($md + ".bundle") != null))' \
  "$work/releases.json" > "$work/copies.jsonl"
[ -s "$work/copies.jsonl" ] || die "$md and its bundle are on no published release: no letter for $month"
refusal=$(bash bin/evidence-letter-verify.sh key "$work/release-key.pub" 2>&1) ||
  die "$month: ${refusal#evidence-letter-verify: }"
n=0
while read -r release; do
  n=$((n + 1)); mkdir -p "$work/copy$n"
  for name in "$md" "$md.bundle"; do
    id=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<< "$release")
    gh api "repos/$repo/releases/assets/$id" -H "Accept: application/octet-stream" > "$work/copy$n/$name"
  done
  refusal=$(bash bin/evidence-letter-verify.sh pair "$work/copy$n/$md" "$work/release-key.pub" 2>&1) ||
    die "$month, $(jq -r .tag_name <<< "$release"): ${refusal#evidence-letter-verify: }"
done < "$work/copies.jsonl"
