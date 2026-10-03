#!/usr/bin/env bash
# Scanner-panel rule 12 (owner RATIFIED Oct 2; REQ-SCAN-012; read-back approved, advisor 0098): the live test of our VEX
# files and of docs/using-our-vex.md against the real services. Runs only in the `live-test` environment, one run at a
# time (concurrency group vex-live-test), from the release-candidate job of release.yml and the main-push job of ci.yml,
# as the federated live-test identities.
#
#   bin/vex-live-test.sh run       sweep the test resources; every guide command block exactly as written (settings
#                                  blocks take the test's values); our images and the pinned fixture copied by digest to
#                                  the two test repositories (at most 50 pushes); the fixture's finding shown before and
#                                  suppressed by our files after, in Inspector, Google, Grype and Scout
#   bin/vex-live-test.sh cleanup   sweep again: the two test repositories emptied, every live-test Inspector filter and
#                                  every VEX note on the test repository's images deleted — and proven gone
#
# Inputs (env): MODE (rc|main), ECR, GAR (the test repositories), GITHUB_REF_NAME (rc), GH_TOKEN (main: the releases),
# DOCKERHUB_USERNAME + DOCKERHUB_SCOUT_TOKEN (Scout; set in the environment by the owner).
REGION=us-east-1
MAX_PUSHES=50
PUSHES=0
here_lt=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LT="python3 $here_lt/vex-live-test.py"
TEST_FILTER_PREFIX=fosterstack-cache-livetest-

push_copy() {   # <src> <dst>: one push, journaled BEFORE it starts (a copy that dies midway is still swept); the 51st
  PUSHES=$((PUSHES + 1))   # fails the run (REQ-SCAN-012-AC4). The sweep empties the test repositories regardless.
  if [ "$PUSHES" -gt "$MAX_PUSHES" ]; then
    echo "::error::more than ${MAX_PUSHES} pushes in one live-test run" >&2
    return 1
  fi
  printf '%s\n' "$2" >> "${PUSHED_LOG:-/dev/null}"
  crane copy "$1" "$2"
}

guide() {   # <section>: source each command block of that section byte for byte, under errexit AND pipefail — a failing
  local f   # command anywhere, inside a pipe too, stops the run (Codex #169 r1, SEC-169-03)
  for f in $(grep -- "-$1\.sh$" plan.txt); do
    echo "::group::guide, as written: ${f}"
    cat "plan/$f"
    echo "::endgroup::"
    # shellcheck disable=SC1090
    source "plan/$f"
  done
}

ca() {   # Container Analysis REST, as the live-test service account
  local tok
  tok=$(gcloud auth print-access-token) || return 1
  curl -fsS -H "Authorization: Bearer ${tok}" "$@"
}

notes_of() {   # <uri prefix>: the names of every VULNERABILITY_ASSESSMENT note on images under that prefix, all pages;
  local project page parsed token="" names="" more   # every step is checked: a failure anywhere fails the enumeration,
  project=$(cut -d/ -f2 <<<"$GAR") || return 1        # never an empty answer (Codex #169 r2/r3, SEC-169-08)
  [ -n "$project" ] || return 1
  while :; do
    page=$(ca "https://containeranalysis.googleapis.com/v1/projects/${project}/notes?filter=kind%3D%22VULNERABILITY_ASSESSMENT%22&pageSize=1000${token:+&pageToken=${token}}") || return 1
    parsed=$($LT inventory --kind notes --prefix "$1" <<<"$page") || return 1
    more=$(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])["names"]))' "$parsed") || return 1
    [ -z "$more" ] || names+="${more}"$'\n'
    token=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["next"])' "$parsed") || return 1
    [ -n "$token" ] || break
  done
  printf '%s' "$names" || return 1
}

sweep() {   # empty the two dedicated test repositories, delete every live-test filter and every VEX note on the test
  local rc=0 out lst r pass n f chunk ref   # repository's images; every listing is parsed strictly, and any listing,
  local repo=${ECR#*/}                       # parsing or deletion failure — or anything left — fails the sweep
  for pass in 1 2 3; do   # indexes first, then the children they held
    out=$(aws ecr list-images --region "$REGION" --repository-name "$repo" --output json) \
      || { echo "::error::cannot list the test ECR repository" >&2; return 1; }
    lst=$($LT inventory --kind ecr <<<"$out") || return 1
    [ -n "$lst" ] || break
    while read -r chunk; do
      r=$(aws ecr batch-delete-image --region "$REGION" --repository-name "$repo" --image-ids "$chunk" --output json) \
        || { echo "::error::ECR delete failed" >&2; rc=1; continue; }
      n=$($LT inventory --kind ecr-delete <<<"$r") || { rc=1; continue; }
      [ "$n" = 0 ] || [ "$pass" -lt 3 ] || { echo "::error::ECR could not delete ${n} images" >&2; rc=1; }
    done <<<"$lst"
  done
  out=$(aws ecr list-images --region "$REGION" --repository-name "$repo" --output json) || return 1
  lst=$($LT inventory --kind ecr <<<"$out") || return 1
  [ -z "$lst" ] || { echo "::error::the test ECR repository is not empty after the sweep" >&2; rc=1; }
  for pass in 1 2 3; do
    out=$(gcloud artifacts docker images list "$GAR" --include-tags --format=json) \
      || { echo "::error::cannot list the test Artifact Registry repository" >&2; return 1; }
    lst=$($LT inventory --kind gar <<<"$out") || return 1
    [ -n "$lst" ] || break
    while read -r ref; do
      gcloud artifacts docker images delete "$ref" --delete-tags --quiet >/dev/null 2>&1 || [ "$pass" -lt 3 ] \
        || { echo "::error::cannot delete ${ref}" >&2; rc=1; }
    done <<<"$lst"
  done
  out=$(gcloud artifacts docker images list "$GAR" --format=json) || return 1
  lst=$($LT inventory --kind gar <<<"$out") || return 1
  [ -z "$lst" ] || { echo "::error::the test Artifact Registry repository is not empty after the sweep" >&2; rc=1; }
  out=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS --output json) \
    || { echo "::error::cannot list the Inspector filters" >&2; return 1; }
  lst=$($LT inventory --kind filters --prefix "$TEST_FILTER_PREFIX" <<<"$out") || return 1
  while read -r f; do
    [ -n "$f" ] || continue
    aws inspector2 delete-filter --region "$REGION" --arn "$f" >/dev/null || { echo "::error::cannot delete ${f}" >&2; rc=1; }
  done <<<"$lst"
  out=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS --output json) || return 1
  lst=$($LT inventory --kind filters --prefix "$TEST_FILTER_PREFIX" <<<"$out") || return 1
  [ -z "$lst" ] || { echo "::error::live-test Inspector filters remain after the sweep" >&2; rc=1; }
  lst=$(notes_of "https://${GAR}/") || { echo "::error::cannot list the VEX notes" >&2; return 1; }
  while read -r n; do
    [ -n "$n" ] || continue
    ca -X DELETE "https://containeranalysis.googleapis.com/v1/${n}" >/dev/null || { echo "::error::cannot delete ${n}" >&2; rc=1; }
  done <<<"$lst"
  lst=$(notes_of "https://${GAR}/") || return 1
  [ -z "$lst" ] || { echo "::error::VEX notes remain on the test repository's images" >&2; rc=1; }
  return "$rc"
}

select_release() {   # the release under test: the rc tag, or on main the newest published release with the rule-10 files
  if [ "${MODE:?}" = rc ]; then
    tag=$GITHUB_REF_NAME
    return 0
  fi
  gh api "repos/${GITHUB_REPOSITORY}/releases?per_page=50" \
    --jq '[.[] | {tagName: .tag_name, isDraft: .draft, assets: [.assets[].name]}]' > releases.json
  tag=$($LT release --releases releases.json)
  if [ -z "$tag" ]; then   # missing inputs are not a passed live test (Codex #169 r1, SEC-169-11)
    echo "::error::no published release carries the rule-10 files: the guide and the VEX files cannot be live-tested yet" >&2
    return 1
  fi
}
[ "${VEX_LIVE_TEST_LIB:-}" = 1 ] && return 0

set -euo pipefail
root=$(cd "$here_lt/.." && pwd)
: "${ECR:?}" "${GAR:?}"
work="${RUNNER_TEMP:?}/vex-live-test"
mkdir -p "$work"
cd "$work"
if [ "${1:-}" = cleanup ]; then
  sweep
  exit 0
fi
[ "${1:-}" = run ] || { echo "usage: vex-live-test.sh run|cleanup" >&2; exit 2; }
# the fixture: debian 12.0, linux/amd64, by digest — known findings every scanner reports; pushed only to the test repos
FIXTURE_SRC=docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
FIX=${FIXTURE_SRC#*@}
PROJECT=$(cut -d/ -f2 <<<"$GAR")
RUN="live-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:-1}"
export PUSHED_LOG="$work/pushed.txt"
: > "$PUSHED_LOG"
mkdir -p plan
waitfor() {   # <what> <function…>: poll every 30 s for up to 45 min until it succeeds
  local what=$1
  shift
  for _ in $(seq 1 90); do
    if "$@"; then return 0; fi
    sleep 30
  done
  echo "::error::timed out waiting for ${what}" >&2
  return 1
}

# --- start from nothing: leftovers of an earlier run that died are reclaimed first (one run at a time)
sweep
select_release
echo "release under test: ${tag}"

# --- the guide's blocks; settings take the test's values, commands run as written (REQ-SCAN-012-AC5)
$LT plan --guide "$root/docs/using-our-vex.md" --out-dir plan > plan.txt
eval "$($LT settings "VER=${tag#v}")"
guide digest
guide download
guide verify
prod=$DIGEST

# --- the release's images, as the verified manifest names them, and their linux children
echo '{}' > images.json
for v in production debug fips; do
  d=$(jq -er --arg v "$v" '.images[] | select(.variant == $v) | .digest' release-manifest.verified.json)
  kids=$(crane manifest "ghcr.io/fosterstack/cache@${d}" \
    | jq -c '[.manifests[] | select(.platform.os == "linux") | {key: ("linux/" + .platform.architecture), value: .digest}] | from_entries')
  jq --arg v "$v" --arg d "$d" --argjson k "$kids" '. + {($v): {index: $d, children: $k}}' images.json > images.tmp
  mv images.tmp images.json
done
if [ "$MODE" = rc ]; then   # on a release candidate the downloaded files are the generator's output for the committed file
  cmp -s fosterstack-cache.openvex.json "$root/.vex/fosterstack-cache.openvex.json" \
    || { echo "::error::the release's OpenVEX file is not the committed one" >&2; exit 1; }
  mkdir -p regen
  python3 "$root/bin/vex-forms.py" --openvex "$root/.vex/fosterstack-cache.openvex.json" --images images.json \
    --version "$tag" --out-dir regen >/dev/null
  cmp -s "regen/fosterstack-cache-${tag}.inspector-filters.json" "fosterstack-cache-${tag}.inspector-filters.json" \
    || { echo "::error::the release's Inspector file is not the generator's output" >&2; exit 1; }
fi

# --- push by digest to the two test repositories: our three images and the fixture (REQ-SCAN-012-AC2)
aws ecr get-login-password --region "$REGION" | crane auth login "${ECR%%/*}" -u AWS --password-stdin
gcloud auth print-access-token | crane auth login "${GAR%%/*}" -u oauth2accesstoken --password-stdin
gcloud auth print-access-token | docker login "${GAR%%/*}" -u oauth2accesstoken --password-stdin
for v in production debug fips; do
  d=$(jq -r --arg v "$v" '.[$v].index' images.json)
  push_copy "ghcr.io/fosterstack/cache@${d}" "${ECR}:${RUN}-${v}"
  push_copy "ghcr.io/fosterstack/cache@${d}" "${GAR}/cache:${RUN}-${v}"
done
push_copy "$FIXTURE_SRC" "${ECR}:${RUN}-fixture"
push_copy "$FIXTURE_SRC" "${GAR}/cache:${RUN}-fixture"
while read -r ref; do
  case "$ref" in *-fixture) want=$FIX ;; *) want=$(jq -r --arg v "${ref##*-}" '.[$v].index' images.json) ;; esac
  [ "$(crane digest "$ref")" = "$want" ] || { echo "::error::${ref} does not keep its digest" >&2; exit 1; }
done < "$PUSHED_LOG"

# --- what every service reports for the fixture, before any statement is loaded
inspector_cves() {   # <status>: the fixture's CVEs Inspector lists with that status (fails on a malformed answer)
  aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
    "$(jq -nc --arg h "$FIX" --arg s "$1" '{ecrImageHash: [{comparison: "EQUALS", value: $h}], findingStatus: [{comparison: "EQUALS", value: $s}]}')" \
    | jq -ec '[.findings[].packageVulnerabilityDetails.vulnerabilityId] | unique'
}
google_occ() {   # every vulnerability occurrence of the fixture in Artifact Analysis, all pages, as one document
  local token="" page all="[]" f
  f=$(jq -rn --arg u "https://${GAR}/cache@${FIX}" '"kind=\"VULNERABILITY\" AND resourceUrl=\"" + $u + "\"" | @uri')
  while :; do
    page=$(ca "https://containeranalysis.googleapis.com/v1/projects/${PROJECT}/occurrences?pageSize=1000&filter=${f}${token:+&pageToken=${token}}") || return 1
    all=$(jq -c --argjson a "$all" '$a + (.occurrences // [])' <<<"$page") || return 1
    token=$(jq -r '.nextPageToken // empty' <<<"$page")
    [ -n "$token" ] || break
  done
  jq -c '{occurrences: .}' <<<"$all"
}
inspector_sees_fixture() { local c; c=$(inspector_cves ACTIVE) && [ "$c" != "[]" ]; }
google_sees_fixture() { local o; o=$(google_occ) && [ "$(jq '.occurrences | length' <<<"$o")" -gt 0 ]; }
waitfor "Inspector's findings for the fixture" inspector_sees_fixture
waitfor "Google's findings for the fixture" google_sees_fixture
grype "${GAR}/cache@${FIX}" -o json -q > grype.before.json
printf '%s' "${DOCKERHUB_SCOUT_TOKEN:?the owner sets the Scout token in the live-test environment}" \
  | docker login docker.io -u "${DOCKERHUB_USERNAME:?}" --password-stdin
docker scout cves --format gitlab "registry://${GAR}/cache@${FIX}" > scout.before.json
google_occ > google.before.json
jq -n --slurpfile g grype.before.json --slurpfile s scout.before.json --slurpfile o google.before.json \
  --argjson i "$(inspector_cves ACTIVE)" '{
    grype: ([$g[0].matches[] | {key: .vulnerability.id, value: .vulnerability.severity}] | from_entries),
    inspector: $i,
    google: [$o[0].occurrences[] | .noteName | split("/") | last],
    scout: [$s[0].vulnerabilities[] | .identifiers[0].value] | unique}' > reports.json
CVE=$($LT pick-cve --reports reports.json --openvex "$root/.vex/fosterstack-cache.openvex.json")
echo "the fixture's finding under test: ${CVE}"

# --- the files the guide's commands load: the shipped statements plus the fixture's, the Inspector copy tagged and
#     test-prefixed and checked to differ in nothing else (advisor 0098)
$LT test-files --openvex "$root/.vex/fosterstack-cache.openvex.json" --images images.json --version "$tag" \
  --fixture-digest "$FIX" --cve "$CVE" --out-dir .

# --- Grype and Scout: the guide's commands as written, then the fixture without and with our file, judged
guide grype
guide scout
grype "${GAR}/cache@${FIX}" --vex fosterstack-cache.openvex.json -o json -q > grype.after.json
docker scout cves --format gitlab --vex-location ./vex --vex-author '^FosterStack LLC$' \
  "registry://${GAR}/cache@${FIX}" > scout.after.json
$LT judge --kind grype --before grype.before.json --after grype.after.json --cve "$CVE"
$LT judge --kind scout --before scout.before.json --after scout.after.json --cve "$CVE"

# --- Inspector: the CVE active before; the guide's command as written; then every finding of it suppressed
inspector_cves ACTIVE | jq -e --arg c "$CVE" 'index($c) != null' >/dev/null \
  || { echo "::error::Inspector does not show ${CVE} on the fixture before the suppression" >&2; exit 1; }
guide inspector
inspector_suppressed() {   # at least one finding of the CVE on the fixture, all SUPPRESSED
  local s
  s=$(aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
        "$(jq -nc --arg h "$FIX" --arg c "$CVE" '{ecrImageHash: [{comparison: "EQUALS", value: $h}], vulnerabilityId: [{comparison: "EQUALS", value: $c}]}')" \
      | jq -er '[.findings[].status] | unique | join(",")') && [ "$s" = SUPPRESSED ]
}
waitfor "Inspector to suppress ${CVE} on the fixture" inspector_suppressed

# --- Google: the guide's command as written for our production image, then for the fixture; the assessment must come
#     from a note this run's load created (the sweep left none)
eval "$($LT settings "IMAGE=${GAR}/cache")"
DIGEST=$prod
guide google
DIGEST=$FIX
guide google
notes_of "https://${GAR}/cache@${FIX}" > run-notes.txt
google_judged() { google_occ > google.after.json && $LT judge --kind google --before google.before.json \
                    --after google.after.json --cve "$CVE" --notes run-notes.txt 2>/dev/null; }
waitfor "Google to assess ${CVE} on the fixture from our note" google_judged
$LT judge --kind google --before google.before.json --after google.after.json --cve "$CVE" --notes run-notes.txt

# --- staying current: the guide's removal as written leaves none of ours
guide inspector-remove
left=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS \
  --query "length(filters[?starts_with(name, 'fosterstack-cache-')])" --output text)
[ "$left" = 0 ] || { echo "::error::the guide's removal left ${left} of our Inspector filters" >&2; exit 1; }
echo "live test passed: ${tag}, ${CVE}, ${PUSHES} pushes"
