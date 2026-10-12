#!/usr/bin/env bash
# bin/check-fips.sh --digests FILE --images DIR --out DIR
# The FIPS start check (v0.3.0 rule 72; REQ-CHAIN-006-AC6). For each candidate image (the OCI layout directories DIR/production and DIR/fips) it loads (as a tar made of the layout) the
# image, starts it, reads /statusz and removes the container (always, also on failure). The -fips image must report fips140 true with
# a note that starts "active (Go validated module v1.0.0"; the production image must report fips140 false. Anything else, or a status
# that cannot be read, fails naming the image. Writes OUT/fips-result.json with what each image reported: the booleans and the module
# version only. The certificate number is a documented mapping, not something a binary reports, so it is never written here.
set -euo pipefail
# an OCI layout directory (PR 2's interface, PROPOSED): oci-layout and an index.json; a docker-save tarball or any other directory is refused
is_layout() { [ -d "$1" ] && [ -f "$1/oci-layout" ] && [ -f "$1/index.json" ]; }
usage() { echo "usage: check-fips.sh --digests FILE --images DIR --out DIR" >&2; exit 2; }
fail() { echo "check-fips: $*" >&2; exit 1; }
digests="" images="" out=""
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --out) out=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$digests" ] && [ -n "$images" ] && [ -n "$out" ] || usage
[ -f "$digests" ] || fail "the digest list $digests does not exist"
[ -d "$images" ] || fail "the image directory $images does not exist"
for v in production fips; do
  d=$(jq -r --arg k "image-$v" '.[$k] // empty' "$digests")
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-$v digest"
  is_layout "$images/$v" || fail "the $v image $images/$v is missing or not an OCI layout directory (oci-layout and index.json)"
done
# Round 1 F1: the images are the ones Build recorded, bound to digests.json before anything is loaded or started.
python3 bin/check-bind.py --digests "$digests" --images "$images" || exit 1
mkdir -p "$out"
tmp=$(mktemp -d)
cleanup() { rm -rf "$tmp"; for v in production fips; do docker rm -f "fscache-check-$v" > /dev/null 2>&1 || true; done; }
trap cleanup EXIT

PREFIX="active (Go validated module v1.0.0"
failed=0
results="[]"
for v in production fips; do
  d=$(jq -r --arg k "image-$v" '.[$k]' "$digests")
  name="fscache-check-$v"
  tar -C "$images/$v" -cf "$tmp/$v.tar" . && loaded=$(docker load -i "$tmp/$v.tar") || { echo "check-fips: $v: the image could not be loaded" >&2; failed=1; continue; }
  ref=$(sed -n 's/^Loaded image: //p; s/^Loaded image ID: //p' <<< "$loaded" | tail -1)
  [ -n "$ref" ] || { echo "check-fips: $v: docker load named no image" >&2; failed=1; continue; }
  if ! docker run -d --name "$name" -p 127.0.0.1::8080 "$ref" > /dev/null; then
    echo "check-fips: $v: the image did not start" >&2; failed=1; continue
  fi
  port=$(docker port "$name" 8080/tcp | sed -n '1s/.*://p')
  status=""
  for _ in $(seq 20); do
    if status=$(curl -sf --max-time 5 "http://127.0.0.1:${port}/statusz"); then break; fi
    status=""; sleep 0.5
  done
  if [ -z "$status" ]; then
    echo "check-fips: $v: no readable /statusz (no silent pass)" >&2; docker logs "$name" >&2 || true; failed=1; continue
  fi
  if ! jq -e 'type == "object" and (.fips140 | type) == "boolean"' <<< "$status" > /dev/null 2>&1; then
    echo "check-fips: $v: /statusz is not JSON with a boolean fips140 field" >&2; failed=1; continue
  fi
  fips=$(jq -r '.fips140' <<< "$status"); note=$(jq -r '.fips140_note // ""' <<< "$status")
  module=null
  [[ "$note" == "$PREFIX"* ]] && module='"v1.0.0"'
  case "$v" in
    fips)
      if [ "$fips" != true ] || [ "$module" = null ]; then
        echo "check-fips: fips: the -fips image must report the FIPS mode active with the validated module v1.0.0; it reports fips140=$fips, note: $note" >&2
        failed=1
      fi ;;
    production)
      if [ "$fips" != false ]; then
        echo "check-fips: production: the production image must report the FIPS mode off; it reports fips140=$fips" >&2
        failed=1
      fi ;;
  esac
  results=$(jq -c --arg n "$v" --arg d "$d" --argjson f "$fips" --argjson m "$module" '. + [{name: $n, digest: $d, fips140: $f, validated_module: $m}]' <<< "$results")
done
jq -n --argjson i "$results" '{images: $i}' > "$out/fips-result.json"
[ "$failed" = 0 ] || exit 1
echo "check-fips: the -fips image runs the validated module v1.0.0 and the production image reports FIPS off"
