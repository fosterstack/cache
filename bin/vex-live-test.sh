#!/usr/bin/env bash
# Scanner-panel rule 12 (owner RATIFIED Oct 2; REQ-SCAN-012; read-back approved, advisor 0098): the live test of our VEX
# files and of docs/using-our-vex.md against the real services. Runs only in the `live-test` environment, from the
# release-candidate job of release.yml and the main-push job of ci.yml, as the federated live-test identities.
#
#   bin/vex-live-test.sh run       every guide command block exactly as written (settings blocks take the test's
#                                  values), our images and the pinned fixture pushed by digest to the two test
#                                  repositories (at most 50 pushes), the fixture's finding shown before and gone after
#                                  in Inspector, Google, Grype and Scout
#   bin/vex-live-test.sh cleanup   deletes what the run created: images, live-test Inspector filters, VEX notes
#
# Inputs (env): MODE (rc|main), ECR, GAR (the test repositories), GITHUB_REF_NAME (rc), GH_TOKEN (main: the releases),
# DOCKERHUB_USERNAME + DOCKERHUB_SCOUT_TOKEN (Scout; set in the environment by the owner).
MAX_PUSHES=50
PUSHES=0
push_copy() {   # <src> <dst>: one push, counted; the 51st fails the run (REQ-SCAN-012-AC4)
  PUSHES=$((PUSHES + 1))
  if [ "$PUSHES" -gt "$MAX_PUSHES" ]; then
    echo "::error::more than ${MAX_PUSHES} pushes in one live-test run" >&2
    return 1
  fi
  crane copy "$1" "$2" || return 1
  printf '%s\n' "$2" >> "${PUSHED_LOG:-/dev/null}"
}
[ "${VEX_LIVE_TEST_LIB:-}" = 1 ] && return 0

set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
LT="python3 $here/vex-live-test.py"
# the fixture: debian 12.0, linux/amd64, by digest — known findings every scanner reports; pushed only to the test repos
FIXTURE_SRC=docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
FIX=${FIXTURE_SRC#*@}
work="${RUNNER_TEMP:?}/vex-live-test"
export PUSHED_LOG="$work/pushed.txt"
REGION=us-east-1
: "${ECR:?}" "${GAR:?}"
PROJECT=$(cut -d/ -f2 <<<"$GAR")
RUN="live-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:-1}"

ca() {   # Container Analysis REST, as the live-test service account
  curl -fsS -H "Authorization: Bearer $(gcloud auth print-access-token)" "$@"
}

if [ "${1:-}" = cleanup ]; then
  set +e
  rc=0
  if [ -f "$PUSHED_LOG" ]; then
    while read -r ref; do
      case "$ref" in
        "$ECR":*) aws ecr batch-delete-image --region "$REGION" --repository-name "${ECR#*/}" \
                    --image-ids "imageTag=${ref##*:}" >/dev/null || rc=1 ;;
        "$GAR"/*) gcloud artifacts docker images delete "$ref" --delete-tags --quiet >/dev/null 2>&1 || rc=1 ;;
      esac
    done < "$PUSHED_LOG"
  fi
  for arn in $(aws inspector2 list-filters --region "$REGION" --action SUPPRESS \
                 --query "filters[?starts_with(name, 'fosterstack-cache-livetest-')].arn" --output text); do
    aws inspector2 delete-filter --region "$REGION" --arn "$arn" >/dev/null || rc=1
  done
  # the VEX notes the guide's Google command created for the test repository's images
  for n in $(ca "https://containeranalysis.googleapis.com/v1/projects/${PROJECT}/notes?filter=kind%3D%22VULNERABILITY_ASSESSMENT%22&pageSize=1000" \
               | jq -r --arg g "https://${GAR}/" '.notes[]? | select((.vulnerabilityAssessment.product.genericUri // "") | startswith($g)) | .name'); do
    ca -X DELETE "https://containeranalysis.googleapis.com/v1/${n}" >/dev/null || rc=1
  done
  exit "$rc"
fi

mkdir -p "$work/plan" && cd "$work"
: > "$PUSHED_LOG"
waitfor() {   # <what> <command…>: poll every 30 s for up to 45 min until the command succeeds
  local what=$1
  shift
  for _ in $(seq 1 90); do
    if "$@"; then return 0; fi
    sleep 30
  done
  echo "::error::timed out waiting for ${what}" >&2
  return 1
}

# --- the release under test
if [ "${MODE:?}" = rc ]; then
  tag=$GITHUB_REF_NAME
else
  gh api "repos/${GITHUB_REPOSITORY}/releases?per_page=50" \
    --jq '[.[] | {tagName: .tag_name, isDraft: .draft, assets: [.assets[].name]}]' > releases.json
  tag=$($LT release --releases releases.json)
  if [ -z "$tag" ]; then
    echo "::notice::no published release carries the rule-10 files yet: the first release candidate is the first live test"
    exit 0
  fi
fi
echo "release under test: ${tag}"

# --- the guide's blocks; settings take the test's values, commands run as written (REQ-SCAN-012-AC5)
$LT plan --guide "$root/docs/using-our-vex.md" --out-dir plan > plan.txt
guide() {   # <section>: source each command block of that section, byte for byte
  local f
  for f in $(grep -- "-$1\.sh$" plan.txt); do
    echo "::group::guide, as written: ${f}"
    cat "plan/$f"
    echo "::endgroup::"
    # as a customer's shell runs it: no pipefail, but any failing command stops the run
    set +o pipefail
    # shellcheck disable=SC1090
    source "plan/$f"
    set -o pipefail
  done
}
eval "$($LT settings "VER=${tag#v}")"
guide digest
guide download
guide verify
prod=$DIGEST

# --- the release's images, as the verified manifest names them, and their linux children
echo '{}' > images.json
for v in production debug fips; do
  d=$(jq -r --arg v "$v" '.images[] | select(.variant == $v) | .digest' release-manifest.verified.json)
  kids=$(crane manifest "ghcr.io/fosterstack/cache@${d}" \
    | jq -c '[.manifests[] | select(.platform.os == "linux") | {key: ("linux/" + .platform.architecture), value: .digest}] | from_entries')
  jq --arg v "$v" --arg d "$d" --argjson k "$kids" '. + {($v): {index: $d, children: $k}}' images.json > images.tmp
  mv images.tmp images.json
done
# on a release candidate the downloaded files are the generator's output for the committed OpenVEX file
if [ "$MODE" = rc ]; then
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
for ref in $(cat "$PUSHED_LOG"); do
  want=$(case "$ref" in *-fixture) echo "$FIX";; *) jq -r --arg v "${ref##*-}" '.[$v].index' images.json;; esac)
  [ "$(crane digest "$ref")" = "$want" ] || { echo "::error::${ref} does not keep its digest" >&2; exit 1; }
done

# --- what every service reports for the fixture, before any statement is loaded
inspector_cves() {   # <status>: the fixture's CVEs Inspector lists with that status
  aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
    "$(jq -nc --arg h "$FIX" --arg s "$1" '{ecrImageHash: [{comparison: "EQUALS", value: $h}], findingStatus: [{comparison: "EQUALS", value: $s}]}')" \
    | jq -c '[.findings[].packageVulnerabilityDetails.vulnerabilityId] | unique'
}
google_occ() {   # the fixture's vulnerability occurrences in Artifact Analysis
  ca "https://containeranalysis.googleapis.com/v1/projects/${PROJECT}/occurrences?pageSize=1000&filter=$(jq -rn \
    --arg u "https://${GAR}/cache@${FIX}" '"kind=\"VULNERABILITY\" AND resourceUrl=\"" + $u + "\"" | @uri')"
}
inspector_sees_fixture() { [ "$(inspector_cves ACTIVE)" != "[]" ]; }
google_sees_fixture() { [ -n "$(google_occ | jq -r '.occurrences[0].name // empty')" ]; }
waitfor "Inspector's findings for the fixture" inspector_sees_fixture
waitfor "Google's findings for the fixture" google_sees_fixture
grype "${GAR}/cache@${FIX}" -o json -q > grype.before.json
docker scout cves --format sarif --output scout.before.sarif "registry://${GAR}/cache@${FIX}"
jq -n --slurpfile g grype.before.json --slurpfile s scout.before.sarif \
  --argjson i "$(inspector_cves ACTIVE)" --argjson o "$(google_occ)" '{
    grype: ([$g[0].matches[] | {key: .vulnerability.id, value: .vulnerability.severity}] | from_entries),
    inspector: $i,
    google: [$o.occurrences[]? | .noteName | split("/") | last],
    scout: [$s[0].runs[].results[].ruleId] | unique}' > reports.json
CVE=$($LT pick-cve --reports reports.json --openvex "$root/.vex/fosterstack-cache.openvex.json")
echo "the fixture's finding under test: ${CVE}"

# --- the files the guide's commands load: the shipped statements plus the fixture's, the Inspector copy tagged and
#     test-prefixed and checked to differ in nothing else (advisor 0098)
$LT test-files --openvex "$root/.vex/fosterstack-cache.openvex.json" --images images.json --version "$tag" \
  --fixture-digest "$FIX" --cve "$CVE" --out-dir .

# --- Grype and Scout: the guide's commands as written, then the fixture without and with our file
grype_has() { jq -e --arg c "$CVE" 'any(.matches[]; .vulnerability.id == $c)' "$1" >/dev/null; }
scout_has() { jq -e --arg c "$CVE" 'any(.runs[].results[]; .ruleId == $c)' "$1" >/dev/null; }
guide grype
printf '%s' "${DOCKERHUB_SCOUT_TOKEN:?the owner sets the Scout token in the live-test environment}" \
  | docker login docker.io -u "${DOCKERHUB_USERNAME:?}" --password-stdin
guide scout
grype "${GAR}/cache@${FIX}" --vex fosterstack-cache.openvex.json -o json -q > grype.after.json
docker scout cves --format sarif --output scout.after.sarif --vex-location ./vex --vex-author '^FosterStack LLC$' \
  "registry://${GAR}/cache@${FIX}"
grype_has grype.before.json && ! grype_has grype.after.json \
  || { echo "::error::Grype: ${CVE} on the fixture was not dropped by our file" >&2; exit 1; }
scout_has scout.before.sarif && ! scout_has scout.after.sarif \
  || { echo "::error::Scout: ${CVE} on the fixture was not dropped by our file" >&2; exit 1; }

# --- Inspector: the guide's command as written, then the finding is suppressed
inspector_cves ACTIVE | jq -e --arg c "$CVE" 'index($c) != null' >/dev/null \
  || { echo "::error::Inspector does not show ${CVE} on the fixture before the suppression" >&2; exit 1; }
guide inspector
inspector_suppressed() {   # every finding of the CVE on the fixture is suppressed, and none is active
  [ "$(aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
        "$(jq -nc --arg h "$FIX" --arg c "$CVE" '{ecrImageHash: [{comparison: "EQUALS", value: $h}], vulnerabilityId: [{comparison: "EQUALS", value: $c}]}')" \
       | jq -r '[.findings[].status] | unique | join(",")')" = SUPPRESSED ]
}
waitfor "Inspector to suppress ${CVE} on the fixture" inspector_suppressed

# --- Google: the guide's command as written for our production image, then for the fixture
eval "$($LT settings "IMAGE=${GAR}/cache")"
DIGEST=$prod
guide google
DIGEST=$FIX
guide google
google_not_affected() {   # every occurrence of the CVE on the fixture carries our NOT_AFFECTED assessment
  [ "$(google_occ | jq -r --arg c "$CVE" '[.occurrences[]? | select((.noteName | split("/") | last) == $c)
        | .vulnerability.vexAssessment.state // "NONE"] | unique | join(",")')" = NOT_AFFECTED ]
}
waitfor "Google to mark ${CVE} on the fixture not affected" google_not_affected

# --- staying current: the guide's removal as written leaves none of ours
guide inspector-remove
left=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS \
  --query "length(filters[?starts_with(name, 'fosterstack-cache-')])" --output text)
[ "$left" = 0 ] || { echo "::error::the guide's removal left ${left} of our Inspector filters" >&2; exit 1; }
echo "live test passed: ${tag}, ${CVE}, $(wc -l < "$PUSHED_LOG") pushes"
