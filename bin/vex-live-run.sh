#!/usr/bin/env bash
# Scanner-panel rule 12 (owner RATIFIED Oct 2; REQ-SCAN-012; read-back approved, advisor 0098): the live test of our VEX
# files and of docs/using-our-vex.md against the real services. Runs only in the `live-test` environment, one run at a
# time (concurrency group vex-live-test), from the release-candidate job of release.yml and the main-push job of ci.yml,
# as the federated live-test identities.
#
#   bin/vex-live-run.sh run       sweep the test resources; every guide command block exactly as written (settings
#                                  blocks take the test's values); our images and the pinned fixture copied by digest to
#                                  the two test repositories (at most 50 pushes); the fixture's finding shown before and
#                                  suppressed by our files after, in Inspector, Google and Grype (Docker Scout is not tested here: see REQ-REL-010)
#   bin/vex-live-run.sh cleanup   sweep again: the two test repositories emptied, every live-test Inspector filter and
#                                  every VEX note on the test repository's images deleted — and proven gone
#
# Inputs (env): MODE (rc|main), ECR, GAR (the test repositories), GITHUB_REF_NAME (rc), GH_TOKEN (main: the releases),
REGION=us-east-1
MAX_PUSHES=50
PUSHES=0
here_lt=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
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

copy_candidate() {   # <layout dir> <dst ref> <attested digest>: a release candidate publishes nothing, so each image is pushed from Build's OCI layout
  local layout=$1 dst=$2 want=$3 got   # directory; the digest that comes out must be the one Build attested, never a digest read from a registry
  [[ "$want" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "::error::the attested digest of ${dst} is malformed" >&2; return 1; }
  PUSHES=$((PUSHES + 1))
  if [ "$PUSHES" -gt "$MAX_PUSHES" ]; then
    echo "::error::more than ${MAX_PUSHES} pushes in one live-test run" >&2
    return 1
  fi
  printf '%s\n' "$dst" >> "${PUSHED_LOG:-/dev/null}"   # journaled BEFORE the push, so a push that dies midway is still swept
  crane push "$layout" "$dst" || return 1
  got=$(crane digest "$dst") || return 1
  [ "$got" = "$want" ] || { echo "::error::${dst} came out as ${got}, Build attested ${want}" >&2; return 1; }
}

guide() {   # <section>: every command block of that section, exactly as written, in ONE bash under errexit AND pipefail with the test's settings (SEC-169-03)
  python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" guide --plan plan.txt --state state.env "$1"
}

ca_get() {   # Container Analysis REST, as the live-test service account (an API call for data, not a download: the python helper, fixed host, no redirects)
  python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" ca GET "$1"
}
ca_delete() {
  python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" ca DELETE "$1"
}

notes_of() {   # <uri prefix>: the names of every VULNERABILITY_ASSESSMENT note on images under that prefix, all pages;
  local project page parsed token="" names="" more   # every step is checked: a failure anywhere fails the enumeration,
  project=$(cut -d/ -f2 <<<"$GAR") || return 1        # never an empty answer (Codex #169 r2/r3, SEC-169-08)
  [ -n "$project" ] || return 1
  while :; do
    page=$(ca_get "https://containeranalysis.googleapis.com/v1/projects/${project}/notes?filter=kind%3D%22VULNERABILITY_ASSESSMENT%22&pageSize=1000${token:+&pageToken=${token}}") || return 1
    parsed=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind notes --prefix "$1" <<<"$page") || return 1
    more=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" field names <<<"$parsed") || return 1
    [ -z "$more" ] || names="${names}${more}"$'\n'
    token=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" field next <<<"$parsed") || return 1
    [ -n "$token" ] || break
  done
  printf '%s' "$names" || return 1
}

# The sweep empties the dedicated test resources. Every resource family is cleaned on its own: a failing listing or delete in one family never stops the others, every
# failure is kept, and the sweep fails at the end if any family did (Codex #387 r3). Any listing, parsing or deletion failure, or anything left, fails its family.
sweep_ecr() {
  local rc=0 out lst r pass n chunk
  local repo=${ECR#*/}
  # ECR refuses to delete an image a manifest list still references, so the manifest lists go first (found by their media type), then everything else
  out=$(aws ecr describe-images --region "$REGION" --repository-name "$repo" --output json) \
    || { echo "::error::cannot describe the test ECR repository" >&2; return 1; }
  lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind ecr-indexes <<<"$out") || return 1
  while read -r chunk; do
    [ -n "$chunk" ] || continue
    r=$(aws ecr batch-delete-image --region "$REGION" --repository-name "$repo" --image-ids "$chunk" --output json) \
      || { echo "::error::ECR delete of the manifest lists failed" >&2; rc=1; continue; }
    n=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind ecr-delete <<<"$r") || { rc=1; continue; }
    [ "$n" = 0 ] || { echo "::error::ECR could not delete ${n} manifest lists" >&2; rc=1; }
  done <<<"$lst"
  for pass in 1 2 3; do   # then the rest
    out=$(aws ecr list-images --region "$REGION" --repository-name "$repo" --output json) \
      || { echo "::error::cannot list the test ECR repository" >&2; return 1; }
    lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind ecr <<<"$out") || return 1
    [ -n "$lst" ] || break
    while read -r chunk; do
      r=$(aws ecr batch-delete-image --region "$REGION" --repository-name "$repo" --image-ids "$chunk" --output json) \
        || { echo "::error::ECR delete failed" >&2; rc=1; continue; }
      n=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind ecr-delete <<<"$r") || { rc=1; continue; }
      [ "$n" = 0 ] || { echo "::error::ECR could not delete ${n} images" >&2; rc=1; }   # recorded for good: a later pass that succeeds does not erase it
    done <<<"$lst"
  done
  out=$(aws ecr list-images --region "$REGION" --repository-name "$repo" --output json) || return 1
  lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind ecr <<<"$out") || return 1
  [ -z "$lst" ] || { echo "::error::the test ECR repository is not empty after the sweep" >&2; rc=1; }
  return "$rc"
}

sweep_gar() {
  local rc=0 out lst pass ref
  for pass in 1 2 3; do
    out=$(gcloud artifacts docker images list "$GAR" --include-tags --format=json) \
      || { echo "::error::cannot list the test Artifact Registry repository" >&2; return 1; }
    lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind gar <<<"$out") || return 1
    [ -n "$lst" ] || break
    while read -r ref; do
      gcloud artifacts docker images delete "$ref" --delete-tags --quiet >/dev/null 2>&1 \
        || { echo "::error::cannot delete ${ref}" >&2; rc=1; }   # recorded for good: a later empty listing does not erase it
    done <<<"$lst"
  done
  out=$(gcloud artifacts docker images list "$GAR" --format=json) || return 1
  lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind gar <<<"$out") || return 1
  [ -z "$lst" ] || { echo "::error::the test Artifact Registry repository is not empty after the sweep" >&2; rc=1; }
  return "$rc"
}

sweep_filters() {
  local rc=0 out lst f
  out=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS --output json) \
    || { echo "::error::cannot list the Inspector filters" >&2; return 1; }
  lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind filters --prefix "$TEST_FILTER_PREFIX" <<<"$out") || return 1
  while read -r f; do
    [ -n "$f" ] || continue
    aws inspector2 delete-filter --region "$REGION" --arn "$f" >/dev/null || { echo "::error::cannot delete ${f}" >&2; rc=1; }
  done <<<"$lst"
  out=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS --output json) || return 1
  lst=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind filters --prefix "$TEST_FILTER_PREFIX" <<<"$out") || return 1
  [ -z "$lst" ] || { echo "::error::live-test Inspector filters remain after the sweep" >&2; rc=1; }
  return "$rc"
}

sweep_notes() {
  local rc=0 lst n
  lst=$(notes_of "https://${GAR}/") || { echo "::error::cannot list the VEX notes" >&2; return 1; }
  while read -r n; do
    [ -n "$n" ] || continue
    ca_delete "https://containeranalysis.googleapis.com/v1/${n}" >/dev/null || { echo "::error::cannot delete ${n}" >&2; rc=1; }
  done <<<"$lst"
  lst=$(notes_of "https://${GAR}/") || return 1
  [ -z "$lst" ] || { echo "::error::VEX notes remain on the test repository's images" >&2; rc=1; }
  return "$rc"
}

sweep() {
  local rc=0
  sweep_ecr || rc=1
  sweep_gar || rc=1
  sweep_filters || rc=1
  sweep_notes || rc=1
  return "$rc"
}

check_removal_scope() {   # the page's removal block deletes every Inspector filter named fosterstack-cache-*: run it only when each such filter is a live-test one
  local out all test
  out=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS --output json) \
    || { echo "::error::cannot list the Inspector filters" >&2; return 1; }
  all=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind filters --prefix "fosterstack-cache-" <<<"$out") || return 1
  test=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" inventory --kind filters --prefix "$TEST_FILTER_PREFIX" <<<"$out") || return 1
  [ "$all" = "$test" ] || { echo "::error::the guide's removal would delete Inspector filters that are not live-test ones" >&2; return 1; }
}

compare_release_files() {   # <tag> <committed openvex>: the three downloaded forms equal the committed OpenVEX file and the generator's output (in regen/); the test replaces them
  local tag=$1 committed=$2   # with its own copies only after this
  cmp -s fosterstack-cache.openvex.json "$committed" \
    || { echo "::error::the release's OpenVEX file is not the committed one" >&2; return 1; }
  cmp -s "regen/fosterstack-cache-${tag}.inspector-filters.json" "fosterstack-cache-${tag}.inspector-filters.json" \
    || { echo "::error::the release's Inspector file is not the generator's output" >&2; return 1; }
  cmp -s "regen/fosterstack-cache-${tag}.csaf.json" "fosterstack-cache-${tag}.csaf.json" \
    || { echo "::error::the release's CSAF file is not the generator's output" >&2; return 1; }
}

select_release() {   # the release under test: MODE rc = the release candidate tag (vX.Y.Z-rcN, nothing published); MODE release = the final tag just
  skip=""            # published (vX.Y.Z); MODE main = the newest published release with the rule-10 files, or an announced skip while none exists
  case "${MODE:?}" in
    rc)
      [[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ ]] || { echo "::error::MODE rc needs a tag vX.Y.Z-rcN, got '${GITHUB_REF_NAME:-}'" >&2; return 1; }
      tag=$GITHUB_REF_NAME ;;
    release)
      [[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::MODE release needs a final tag vX.Y.Z, got '${GITHUB_REF_NAME:-}'" >&2; return 1; }
      tag=$GITHUB_REF_NAME ;;
    main)
      gh api "repos/${GITHUB_REPOSITORY}/releases?per_page=50" \
        --jq '[.[] | {tagName: .tag_name, isDraft: .draft, assets: [.assets[].name]}]' > releases.json
      tag=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" release --releases releases.json)
      if [ -z "$tag" ]; then   # not a passed live test: an announced skip, until a release carries the files (no v0.3 release exists yet)
        echo "::notice::live test skipped: no published release carries the rule-10 files yet (the guide and the VEX files ship with the first v0.3 release)"
        skip=yes
      fi ;;
    *) echo "::error::MODE must be rc, release or main" >&2; return 1 ;;
  esac
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
[ "${1:-}" = run ] || { echo "usage: vex-live-run.sh run|cleanup" >&2; exit 2; }
# the fixture: debian 12.0, linux/amd64, by digest — known findings every scanner reports; pushed only to the test repos
FIXTURE_SRC=docker.io/library/debian@sha256:60774985572749dc3c39147d43089d53e7ce17b844eebcf619d84467160217ab
FIX=${FIXTURE_SRC#*@}
PROJECT=$(cut -d/ -f2 <<<"$GAR")
RUN="live-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:-1}"
export PUSHED_LOG="$work/pushed.txt"
: > "$PUSHED_LOG"
mkdir -p plan
# --- start from nothing: leftovers of an earlier run that died are reclaimed first (one run at a time)
sweep
select_release
if [ "$skip" = yes ]; then exit 0; fi
echo "release under test: ${tag} (${MODE})"

# --- the guide's blocks; settings take the test's values, commands run as written (REQ-SCAN-012-AC5). A release candidate publishes nothing (v0.3), so
#     the blocks the cannot-run list names (digest, download, verify) are left out of its plan and run in the post-publish run (MODE release) instead
if [ "$MODE" = rc ]; then
  python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" plan --guide "$root/docs/using-our-vex.md" --pins "$root/docs/using-our-vex.live-blocks.json" --skip-cannot-run "$root/docs/using-our-vex.cannot-run.json" --out-dir plan > plan.txt
else
  python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" plan --guide "$root/docs/using-our-vex.md" --pins "$root/docs/using-our-vex.live-blocks.json" --out-dir plan > plan.txt
fi
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" settings --state state.env "VER=${tag#v}"
echo '{}' > images.json
if [ "$MODE" = rc ]; then
  # the candidate: Build's artifacts (CANDIDATE_DIR holds digests.json, items.json and images/<variant>/ layouts with <variant>.digest and <variant>.manifests);
  # the images map is made by the chain's own tool, so it is exactly what Release gives the generator
  : "${CANDIDATE_DIR:?the candidate Build artifacts}"
  python3 "$GITHUB_WORKSPACE/bin/release-metadata.py" images --digests "$CANDIDATE_DIR/digests.json" --images-dir "$CANDIDATE_DIR/images" \
    --items "$CANDIDATE_DIR/items.json" --out images.json
  cp "$root/.vex/fosterstack-cache.openvex.json" ./fosterstack-cache.openvex.json
  python3 "$GITHUB_WORKSPACE/bin/vex-forms.py" --openvex "$root/.vex/fosterstack-cache.openvex.json" --images images.json --version "$tag" --out-dir . >/dev/null
  prod=$(jq -r '.production.index' images.json)
else
  guide digest
  guide download
  guide verify
  prod=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" state --state state.env DIGEST)
  # the release's images, as the verified manifest names them, and their linux children
  for v in production fips; do
    d=$(jq -er --arg v "$v" '.images[] | select(.variant == $v) | .digest' release-manifest.verified.json)
    kids=$(crane manifest "ghcr.io/fosterstack/cache@${d}" \
      | jq -c '[.manifests[] | select(.platform.os == "linux") | {key: ("linux/" + .platform.architecture), value: .digest}] | from_entries')
    jq --arg v "$v" --arg d "$d" --argjson k "$kids" '. + {($v): {index: $d, children: $k}}' images.json > images.tmp
    mv images.tmp images.json
  done
fi
if [ "$MODE" = release ]; then   # a just-published release: the downloaded files are the generator's output for the committed file and the published images
  mkdir -p regen
  python3 "$GITHUB_WORKSPACE/bin/vex-forms.py" --openvex "$root/.vex/fosterstack-cache.openvex.json" --images images.json \
    --version "$tag" --out-dir regen >/dev/null
  compare_release_files "$tag" "$root/.vex/fosterstack-cache.openvex.json"
fi

# --- push by digest to the two test repositories: our two images and the fixture (REQ-SCAN-012-AC2)
aws ecr get-login-password --region "$REGION" | crane auth login "${ECR%%/*}" -u AWS --password-stdin
gcloud auth print-access-token | crane auth login "${GAR%%/*}" -u oauth2accesstoken --password-stdin
gcloud auth print-access-token | docker login "${GAR%%/*}" -u oauth2accesstoken --password-stdin
for v in production fips; do
  d=$(jq -r --arg v "$v" '.[$v].index' images.json)
  if [ "$MODE" = rc ]; then
    copy_candidate "$CANDIDATE_DIR/images/${v}" "${ECR}:${RUN}-${v}" "$d"
    copy_candidate "$CANDIDATE_DIR/images/${v}" "${GAR}/cache:${RUN}-${v}" "$d"
  else
    push_copy "ghcr.io/fosterstack/cache@${d}" "${ECR}:${RUN}-${v}"
    push_copy "ghcr.io/fosterstack/cache@${d}" "${GAR}/cache:${RUN}-${v}"
  fi
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
inspector_packages() {   # <status>: {cve: [{name, version}]} for the fixture's findings with that status; a finding that names other than ONE package is refused (the judge keys findings by package)
  aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
    "$(jq -nc --arg h "$FIX" --arg s "$1" '{ecrImageHash: [{comparison: "EQUALS", value: $h}], findingStatus: [{comparison: "EQUALS", value: $s}]}')" \
    | jq -ec '[.findings[] | .packageVulnerabilityDetails as $d | ($d.vulnerablePackages // []) as $p
                | if ($p | length) == 1 then {cve: $d.vulnerabilityId, name: $p[0].name, version: $p[0].version} else error("a finding that does not name exactly one package") end]
              | group_by(.cve) | map({key: .[0].cve, value: (map({name: .name, version: .version}) | unique)}) | from_entries'
}
google_occ() {   # every vulnerability occurrence of the fixture in Artifact Analysis, all pages, as one document
  local token="" page all="[]" f
  f=$(jq -rn --arg u "https://${GAR}/cache@${FIX}" '"kind=\"VULNERABILITY\" AND resourceUrl=\"" + $u + "\"" | @uri')
  while :; do
    page=$(ca_get "https://containeranalysis.googleapis.com/v1/projects/${PROJECT}/occurrences?pageSize=1000&filter=${f}${token:+&pageToken=${token}}") || return 1
    all=$(jq -c --argjson a "$all" '$a + (.occurrences // [])' <<<"$page") || return 1
    token=$(jq -r '.nextPageToken // empty' <<<"$page")
    [ -n "$token" ] || break
  done
  jq -c '{occurrences: .}' <<<"$all"
}
inspector_sees_fixture() { local c; c=$(inspector_cves ACTIVE) && [ "$c" != "[]" ]; }
google_sees_fixture() { local o; o=$(google_occ) && [ "$(jq '.occurrences | length' <<<"$o")" -gt 0 ]; }
# each poll below: every 30 s for up to 45 min until the condition holds
for _ in $(seq 1 90); do inspector_sees_fixture && break; sleep 30; done
inspector_sees_fixture || { echo "::error::timed out waiting for Inspector's findings for the fixture" >&2; exit 1; }
for _ in $(seq 1 90); do google_sees_fixture && break; sleep 30; done
google_sees_fixture || { echo "::error::timed out waiting for Google's findings for the fixture" >&2; exit 1; }
grype "${GAR}/cache@${FIX}" -o json -q > grype.before.json
google_occ > google.before.json
jq -n --slurpfile g grype.before.json --slurpfile o google.before.json \
  --argjson i "$(inspector_packages ACTIVE)" '{
    grype: ([$g[0].matches[] | {key: .vulnerability.id, value: .vulnerability.severity}] | from_entries),
    inspector: $i,
    google: [$o[0].occurrences[] | .noteName | split("/") | last]}' > reports.json
CVE=$(python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" pick-cve --reports reports.json --openvex "$root/.vex/fosterstack-cache.openvex.json")
echo "the fixture's finding under test: ${CVE}"
# the package Inspector found it in, and the decoy: our Inspector rules always name a package (owner Oct 16), and the same CVE in another package stays visible
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" pick-scope --reports reports.json --cve "$CVE" --openvex "$root/.vex/fosterstack-cache.openvex.json" > scope.json

# --- the files the guide's commands load: the shipped statements plus the fixture's, the Inspector copy tagged and
#     test-prefixed and checked to differ in nothing else (advisor 0098)
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" test-files --openvex "$root/.vex/fosterstack-cache.openvex.json" --images images.json --version "$tag" \
  --fixture-digest "$FIX" --cve "$CVE" --scope scope.json --grype-repository "${GAR}/cache" --out-dir .

# --- Grype: the guide's command as written, then the fixture without and with our file, judged
guide grype
grype "${GAR}/cache@${FIX}" --vex fosterstack-cache.openvex.json -o json -q > grype.after.json
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" judge --kind grype --before grype.before.json --after grype.after.json --cve "$CVE"

# --- Inspector: the CVE active before; the guide's command as written; then every finding of it suppressed
inspector_inventory() {   # every finding of the fixture in any status: {findings: [{findingArn, vulnerabilityId, status}]}
  aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
    "$(jq -nc --arg h "$FIX" '{ecrImageHash: [{comparison: "EQUALS", value: $h}]}')" \
    | jq -ec '{findings: [.findings[] | .packageVulnerabilityDetails.vulnerablePackages as $p
        | if ($p | length) == 1 then {findingArn: .findingArn, vulnerabilityId: .packageVulnerabilityDetails.vulnerabilityId, status: .status, packageName: $p[0].name, packageVersion: $p[0].version}
          else error("a finding that does not name exactly one package") end]}'
}
inspector_inventory > inspector.before.json
inspector_cves ACTIVE | jq -e --arg c "$CVE" 'index($c) != null' >/dev/null \
  || { echo "::error::Inspector does not show ${CVE} on the fixture before the suppression" >&2; exit 1; }
guide inspector
inspector_suppressed() {   # at least one finding of the CVE in the package under test on the fixture, all SUPPRESSED
  local s
  s=$(aws inspector2 list-findings --region "$REGION" --output json --filter-criteria \
        "$(jq -nc --arg h "$FIX" --arg c "$CVE" '{ecrImageHash: [{comparison: "EQUALS", value: $h}], vulnerabilityId: [{comparison: "EQUALS", value: $c}]}')" \
      | jq -er --slurpfile sc scope.json '[.findings[] | select(any(.packageVulnerabilityDetails.vulnerablePackages[]?; .name == $sc[0].package.name and .version == $sc[0].package.version)) | .status] | unique | join(",")') \
    && [ "$s" = SUPPRESSED ]
}
for _ in $(seq 1 90); do inspector_suppressed && break; sleep 30; done
inspector_suppressed || { echo "::error::timed out waiting for Inspector to suppress ${CVE} on the fixture" >&2; exit 1; }
inspector_inventory > inspector.after.json
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" judge --kind inspector --before inspector.before.json --after inspector.after.json --cve "$CVE" --scope scope.json

# --- Google: the guide's command as written for our production image, then for the fixture; the assessment must come
#     from a note this run's load created (the sweep left none)
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" settings --state state.env "IMAGE=${GAR}/cache" "DIGEST=${prod}"
guide google
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" settings --state state.env "DIGEST=${FIX}"
guide google
notes_of "https://${GAR}/cache@${FIX}" > run-notes.txt
google_judged() { google_occ > google.after.json && python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" judge --kind google --before google.before.json \
                    --after google.after.json --cve "$CVE" --notes run-notes.txt 2>/dev/null; }
for _ in $(seq 1 90); do google_judged && break; sleep 30; done
google_judged || { echo "::error::timed out waiting for Google to assess ${CVE} on the fixture from our note" >&2; exit 1; }
python3 "$GITHUB_WORKSPACE/bin/vex-live-test.py" judge --kind google --before google.before.json --after google.after.json --cve "$CVE" --notes run-notes.txt

# --- staying current: the guide's removal as written leaves none of ours
check_removal_scope
guide inspector-remove
left=$(aws inspector2 list-filters --region "$REGION" --action SUPPRESS \
  --query "length(filters[?starts_with(name, 'fosterstack-cache-')])" --output text)
[ "$left" = 0 ] || { echo "::error::the guide's removal left ${left} of our Inspector filters" >&2; exit 1; }
echo "live test passed: ${tag}, ${CVE}, ${PUSHES} pushes"
