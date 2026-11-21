#!/usr/bin/env bash
# bin/layout-archive.sh LAYOUT ARCH ARCHIVE TAG
# Builds a docker-save tar of the linux/ARCH image of an OCI layout, so a scanner reads it without a Docker daemon.
# The tar holds manifest.json (naming TAG as the image name: grype takes the image identity from it, which is how the
# published VEX applies), then the child's config blob and its layer blobs, and nothing else of the layout.
# Prints "child sha256:<child manifest> config sha256:<config>", for the caller to check against the scanner.
set -euo pipefail
layout=${1:?}
arch=${2:?}; archive=${3:?}; tag=${4:?}
die() { echo "layout-archive: $*" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
stage="$tmp/stage"; mkdir -p "$stage/blobs/sha256"

# A layout is only ever read, never trusted. A digest becomes a path only here: it must be sha256:<64 hex>, the
# blob must be a regular file, and a private copy of it must hash to the digest. Everything after this (parsing,
# the tar) uses the copy, so the bytes checked are the bytes shipped, whatever happens to the layout meanwhile.
member() {
  [[ $1 =~ ^sha256:[0-9a-f]{64}$ ]] || die "not a sha256:<64 hex> digest: $1"
  local path="blobs/sha256/${1#sha256:}"
  [ -f "$layout/$path" ] && [ ! -L "$layout/$path" ] || die "$path is not a regular file"
  if [ ! -e "$stage/$path" ]; then   # a digest met again is already staged and verified
    cp "$layout/$path" "$stage/$path" 2> /dev/null || die "$path cannot be read"
    echo "${1#sha256:}  $path" | (cd "$stage" && sha256sum -c --quiet) > /dev/null 2>&1 \
      || die "$path does not match its digest"
  fi
  echo "$path"
}

count=$(jq -e '.manifests | length' "$layout/index.json" 2> /dev/null) || count=""
[ "$count" = 1 ] || die "$layout/index.json is missing or does not hold exactly one image index"
index=$(member "$(jq -er '.manifests[0].digest' "$layout/index.json")")
select='.manifests | map(select(.platform.os == "linux" and .platform.architecture == $a))'
child=$(jq -er --arg a "$arch" "$select | if length == 1 then .[0].digest else empty end" "$stage/$index") \
  || die "the index of $layout holds no single linux/$arch image"
manifest=$(member "$child")

# one line per digest; each must be a whole string, so a newline inside one cannot split it in two
is_digest='type == "string" and test("\\Asha256:[0-9a-f]{64}\\z")'
has_layers='(.layers | type) == "array" and (.layers | length) > 0'
all_digests='all([.config.digest, .layers[].digest][]; is_digest)'
program="def is_digest: $is_digest; select($has_layers and $all_digests) | [.config.digest, .layers[].digest][]"
digests=$(jq -er "$program" "$stage/$manifest") \
  || die "the image $child needs a non-empty layers list; every digest must be sha256:<64 hex>"
members=()
mapfile -t digest_list <<< "$digests"
for digest in "${digest_list[@]}"; do
  path=$(member "$digest")
  members+=("$path")
done

# a layer listed twice stays listed twice in manifest.json but is one member of the tar
printf '%s\n' "${members[@]}" | jq -R . \
  | jq -s --arg tag "$tag" '[{Config: .[0], RepoTags: [$tag], Layers: .[1:]}]' > "$tmp/manifest.json"
mapfile -t once < <(printf '%s\n' "${members[@]}" | awk '!seen[$0]++')
tar -cf "$archive" -C "$tmp" manifest.json -C "$stage" "${once[@]}" || { rm -f "$archive"; die "tar failed"; }
echo "child $child config $(jq -r '.config.digest' "$stage/$manifest")"
