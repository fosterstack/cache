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
blob() { echo "$layout/blobs/sha256/${1#sha256:}"; }

index=$(jq -er '.manifests[0].digest' "$layout/index.json") || die "$layout has no readable index.json"
select='.manifests | map(select(.platform.os == "linux" and .platform.architecture == $a))'
child=$(jq -er --arg a "$arch" "$select | if length == 1 then .[0].digest else empty end" "$(blob "$index")") \
  || die "the index of $layout holds no single linux/$arch image"
manifest=$(blob "$child")

# Every digest is sha256:<64 hex> before it becomes a path; a layout is only ever read, never trusted.
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
jq -ce --arg tag "$tag" '
  def ok: type == "string" and test("^sha256:[0-9a-f]{64}$");
  if (.config.digest | ok) and (.layers | length) > 0 and all(.layers[]; .digest | ok)
  then [{Config: ("blobs/sha256/" + (.config.digest | ltrimstr("sha256:"))), RepoTags: [$tag],
         Layers: [.layers[].digest | "blobs/sha256/" + ltrimstr("sha256:")]}]
  else empty end' "$manifest" > "$tmp/manifest.json" || die "the image $child has no valid config and layers"

mapfile -t members < <(jq -r '.[0] | .Config, .Layers[]' "$tmp/manifest.json")
tar -cf "$archive" -C "$tmp" manifest.json -C "$layout" "${members[@]}" || { rm -f "$archive"; die "tar failed"; }
echo "child $child config $(jq -r '.config.digest' "$manifest")"
