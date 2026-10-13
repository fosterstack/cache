#!/usr/bin/env bash
# Release, third witnessed step (rules 56 and 64): publishes the exact image bytes Build made, with no rebuild, to ghcr.io first and then to the
# Docker Hub mirror, and reads each registry back. Every digest read back must equal the attested one, else the release stops on the first
# difference and names the image and both digests. Credentials are passed by standard input only. A target version tag that already shows another
# digest is refused before anything is pushed. A release candidate gets its exact tags; a final release also moves the floating tags of
# REQ-REL-009-AC11 (:X.Y every time, :X and :latest only when this is the highest released version).
set -euo pipefail
for name in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GH_TOKEN; do
  if [ -z "${!name:-}" ]; then echo "release-publish: $name is not set" >&2; exit 2; fi
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

crane auth login ghcr.io -u "${GITHUB_ACTOR:-fosterstack}" --password-stdin <<< "$GH_TOKEN"
crane auth login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin <<< "$DOCKERHUB_TOKEN"

plan=("production:$ver" "fips:$ver-fips")
if [[ "$ver" != *-* ]]; then
  if existing=$(crane ls "ghcr.io/$repo" 2>&1); then :
  elif [[ "$existing" == *NAME_UNKNOWN* ]]; then existing=""
  else echo "release-publish: cannot list the tags of ghcr.io/$repo: $existing" >&2; exit 1; fi
  highest=$(printf '%s\n' "$existing" | jq -R -s -r --arg cur "$ver" 'split("\n") | map(select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))) + [$cur] | map({s: ., k: (split(".") | map(tonumber))}) | max_by(.k) | .s')
  plan+=("production:${ver%.*}")
  if [ "$highest" = "$ver" ]; then plan+=("production:${ver%%.*}" "production:latest"); fi
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
done
