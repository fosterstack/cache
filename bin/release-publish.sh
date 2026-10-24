#!/usr/bin/env bash
# Release, third witnessed step (rules 56 and 64): publishes the exact image bytes Build made, with no rebuild, to ghcr.io first and then to the
# Docker Hub mirror, and reads each registry back. Every digest read back must equal the attested one, else the release stops on the first
# difference and names the image and both digests. Credentials are passed by standard input only. A target version tag that already shows another
# digest is refused before anything is pushed. Only a final release reaches this step (a release candidate stops after release-verify, REQ-CHAIN-007-AC14):
# it gets its exact vX.Y.Z tag and also moves the floating tags of REQ-REL-009-AC11 (:X.Y every time, :X and :latest only when this is the highest released version).
set -euo pipefail
for name in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GH_TOKEN; do
  if [ -z "${!name:-}" ]; then echo "release-publish: $name is unset" >&2; exit 2; fi
done
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-publish: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
ver="${GITHUB_REF_NAME#v}"
repo="fosterstack/cache"
rx='^sha256:[0-9a-f]{64}$'
prod=$(jq -r '."image-production" // empty' witness-build/digests.json)
fips=$(jq -r '."image-fips" // empty' witness-build/digests.json)
[[ "$prod" =~ $rx ]] || { echo "release-publish: the attested image-production digest is missing or malformed" >&2; exit 1; }
[[ "$fips" =~ $rx ]] || { echo "release-publish: the attested image-fips digest is missing or malformed" >&2; exit 1; }
# PROPOSED/UNVERIFIED (#299): Build's images artifact holds one OCI image layout DIRECTORY per variant, images/<variant>/ with oci-layout and index.json,
# beside images/<variant>.digest. Measured: pushing a docker-format tarball re-creates the manifest and changes the digest; a layout directory keeps it.
for pair in "production:$prod" "fips:$fips"; do
  v="${pair%%:*}"
  if [ -L "images/$v" ] || [ ! -d "images/$v" ] || [ ! -f "images/$v/oci-layout" ] || [ ! -f "images/$v/index.json" ]; then
    echo "release-publish: images/$v is not an OCI image layout directory (oci-layout and index.json): refusing to publish it" >&2; exit 1
  fi
  own=$(cat "images/${pair%%:*}.digest")
  if [ "$own" != "${pair#*:}" ]; then echo "release-publish: images/${pair%%:*} is $own, Build attested ${pair#*:}: refusing to publish it" >&2; exit 1; fi
  # The sidecar is a name, not a proof: the layout's own bytes are the attested image (round 1 B4). index.json holds exactly one descriptor, the attested
  # digest; every blob hashes to its name; the index blob and every manifest, config and layer it reaches are present. Checked before any login or push.
  python3 bin/release-layout.py "images/$v" "${pair#*:}"
done

digest_of() {
  local out
  if out=$(crane digest "$1" 2>&1); then printf '%s\n' "$out"
  elif [[ "$out" == *NAME_UNKNOWN* || "$out" == *MANIFEST_UNKNOWN* ]]; then echo none
  else echo "release-publish: cannot read $1: $out" >&2; return 1; fi
}

# The logins live in a private DOCKER_CONFIG of this step, removed when it ends (round 1 F2): crane saves credentials in the runner's shared
# ~/.docker/config.json, where a later step without the secret could still use them.
DOCKER_CONFIG=$(mktemp -d)
[ -n "$DOCKER_CONFIG" ] && [ -d "$DOCKER_CONFIG" ] || { echo "release-publish: no private credential directory: refusing to log in" >&2; exit 1; }
export DOCKER_CONFIG
trap 'rm -rf "$DOCKER_CONFIG"' EXIT
crane auth login ghcr.io -u "${GITHUB_ACTOR:-fosterstack}" --password-stdin <<< "$GH_TOKEN"
crane auth login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin <<< "$DOCKERHUB_TOKEN"

plan=("production:$ver" "fips:$ver-fips")
# The highest released version: ghcr.io's plain X.Y.Z tags with this version counted as released (highest_now), or only those of one X.Y line (highest_now X.Y.).
# It is read again right before the floating tags are pushed (release review R3, Oct 22): a higher release published meanwhile must never lose :X and :latest to this
# older one. The window that remains between a reading and a push is closed by the release job's concurrency group (release.yml, job release); what is left of a lost
# race, a retry or a diverged mirror is caught by verify_end_state below, which every final run ends with.
highest_now() {
  local existing
  if existing=$(crane ls "ghcr.io/$repo" 2>&1); then :
  elif [[ "$existing" == *NAME_UNKNOWN* ]]; then existing=""
  else echo "release-publish: cannot list the tags of ghcr.io/$repo: $existing" >&2; return 1; fi
  printf '%s\n' "$existing" | jq -R -s -r --arg cur "$ver" --arg pre "${1:-}" 'split("\n") | map(select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))) + [$cur] | map(select(startswith($pre))) | map({s: ., k: (split(".") | map(tonumber))}) | max_by(.k) | .s'
}
# The end state of a final run, in BOTH registries (audit ruling, Oct 22; a retry or a diverged mirror must never pass over a rolled-back floating tag): the highest plain
# X.Y.Z on ghcr.io exists on each registry with ghcr.io's digest; :latest and :<its major> and :<its X.Y> carry that same digest; and :<this version's X.Y> carries the
# digest of that line's highest release (so the rollback of :X.Y by a resumed older patch, which is pushed on purpose, is never silent). Digests are only read: nothing is retagged.
verify_end_state() {
  local hi hl gd gl host t d xy bad=0
  xy=${ver%.*}
  hi=$(highest_now) || return 1
  hl=$(highest_now "$xy.") || return 1
  gd=$(digest_of "ghcr.io/$repo:$hi") || return 1
  gl=$(digest_of "ghcr.io/$repo:$hl") || return 1
  if [ "$gd" = none ]; then echo "release-publish: end state: ghcr.io/$repo:$hi, the highest release, does not exist; publish $hi again" >&2; return 1; fi
  for host in ghcr.io docker.io; do
    for t in "$hi" latest "${hi%%.*}" "${hi%.*}"; do
      d=$(digest_of "$host/$repo:$t") || return 1
      if [ "$d" != "$gd" ]; then echo "release-publish: end state: $host/$repo:$t shows $d, the highest release $hi shows $gd on ghcr.io; publish $hi again to restore it" >&2; bad=1; fi
    done
    d=$(digest_of "$host/$repo:$xy") || return 1
    if [ "$d" != "$gl" ]; then echo "release-publish: end state: $host/$repo:$xy shows $d, the highest release of that line, $hl, shows $gl on ghcr.io; publish $hl again to restore it" >&2; bad=1; fi
  done
  return $bad
}
final=0
if [[ "$ver" != *-* ]]; then
  final=1
  highest_now > /dev/null || exit 1       # an unreadable tag list stops the release before any push, as before
  plan+=("production:${ver%.*}")
fi

for host in ghcr.io docker.io; do
  for entry in "${plan[@]:0:2}"; do
    ref="$host/$repo:${entry#*:}"
    want="$prod"; [ "${entry%%:*}" = fips ] && want="$fips"
    have=$(digest_of "$ref")
    if [ "$have" != none ] && [ "$have" != "$want" ]; then echo "release-publish: $ref already shows another digest ($have, attested $want): an exact release tag is never moved" >&2; exit 1; fi
  done
done

for host in ghcr.io docker.io; do
  for entry in "${plan[@]}"; do
    ref="$host/$repo:${entry#*:}"
    want="$prod"; [ "${entry%%:*}" = fips ] && want="$fips"
    crane push "images/${entry%%:*}" "$ref"
    got=$(digest_of "$ref")
    if [ "$got" != "$want" ]; then echo "release-publish: $ref differs: the registry shows $got, Build attested $want" >&2; exit 1; fi
  done
  if [ "$final" = 1 ]; then
    # decided again now, not from the reading made before the exact tags were pushed
    if ! highest=$(highest_now); then exit 1; fi
    if [ "$highest" = "$ver" ]; then
      for fl in "${ver%%.*}" latest; do
        ref="$host/$repo:$fl"
        crane push "images/production" "$ref"
        got=$(digest_of "$ref")
        if [ "$got" != "$prod" ]; then echo "release-publish: $ref differs: the registry shows $got, Build attested $prod" >&2; exit 1; fi
      done
    fi
  fi
done
if [ "$final" = 1 ]; then verify_end_state || exit 1; fi
