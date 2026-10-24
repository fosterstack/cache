#!/usr/bin/env bash
# bin/layout-archive.sh LAYOUT ARCH ARCHIVE TAG
# Makes a docker-save tar of the linux/ARCH image of an OCI layout, so a scanner reads it without a Docker daemon.
# The tar holds manifest.json (naming TAG as the image name: grype takes the image identity from it, which is how the
# published VEX applies), then the child's config blob and its layer blobs, and nothing else of the layout.
# Prints "child sha256:<child manifest> config sha256:<config>", for the caller to check against the scanner.
set -euo pipefail
layout=${1:?}
arch=${2:?}; archive=${3:?}; tag=${4:?}
die() { echo "layout-archive: $*" >&2; exit 1; }

# A digest becomes a path only here: it must be sha256:<64 hex>, and the blob's bytes must hash to it. A layout
# is only ever read, never trusted.
member() {
  [[ $1 =~ ^sha256:[0-9a-f]{64}$ ]] || die "not a sha256:<64 hex> digest: $1"
  local path="blobs/sha256/${1#sha256:}"
  echo "${1#sha256:}  $path" | (cd "$layout" && sha256sum -c --quiet) > /dev/null 2>&1 \
    || die "$path is missing or does not match its digest"
  echo "$path"
}

[ "$(jq -e '.manifests | length' "$layout/index.json" 2> /dev/null)" = 1 ] \
  || die "$layout/index.json is missing or does not hold exactly one image index"
index=$(member "$(jq -er '.manifests[0].digest' "$layout/index.json")")
select='.manifests | map(select(.platform.os == "linux" and .platform.architecture == $a))'
child=$(jq -er --arg a "$arch" "$select | if length == 1 then .[0].digest else empty end" "$layout/$index") \
  || die "the index of $layout holds no single linux/$arch image"
manifest=$(member "$child")
jq -e '(.layers | length) > 0' "$layout/$manifest" > /dev/null || die "the image $child has no layers"

members=()
for digest in $(jq -er '.config.digest, .layers[].digest' "$layout/$manifest"); do
  path=$(member "$digest")
  members+=("$path")
done

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "${members[@]}" | jq -R . \
  | jq -s --arg tag "$tag" '[{Config: .[0], RepoTags: [$tag], Layers: .[1:]}]' > "$tmp/manifest.json"
tar -cf "$archive" -C "$tmp" manifest.json -C "$layout" "${members[@]}" || { rm -f "$archive"; die "tar failed"; }
echo "child $child config $(jq -r '.config.digest' "$layout/$manifest")"
