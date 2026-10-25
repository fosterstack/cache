#!/usr/bin/env bash
# bin/check-scan.sh --scanners FILE --digests FILE --images DIR --archives DIR --out DIR
# Runs every scanner listed in FILE (.github/policy/scanners.json, "scanners") against the exact candidates (v0.3.0 rule 55;
# REQ-CHAIN-006-AC4; REQ-REL-004-AC1). The candidate image is selected by the index digest in the digest list; grype
# scans each of its two platform children (linux/amd64 and linux/arm64, named in the results by the child's own manifest
# digest), osv-scanner scans each child from a docker-save archive built from the layout (bin/layout-archive.sh); grype
# also scans every release archive (ARCHIVES/*.tar.gz) and osv-scanner the Go
# modules (go.mod, tools/requirements/go.mod), as scanners.json (row 45) and today's stage-verify.yml have it. No unlisted scanner runs.
# A scanner exits 0 (clean), 1 (findings the published VEX document does not except) or anything else (could not run). The package
# count is read from the tool's own machine output: the components of the CycloneDX SBOM grype writes (-o cyclonedx-json=FILE, as
# the PR scan script counts them for REQ-REL-004-AC1) and the packages osv-scanner lists with --format json --all-packages (shapes as
# recorded in the scanner fixtures of the auditor directory (fixtures/scanners)).
# Vulnerability databases (REQ-CHAIN-006-AC15): grype fetches its database fresh (grype db update) before the first scan, and every scan
# is then held to that database (no auto-update, a 48-hour built-age limit); the database each scan used is read from its own output
# (descriptor.db.status, the shape recorded in the scanner fixtures of the auditor directory (fixtures/scanners)/grype.json) and must come from grype.anchore.io, carry
# its sha256 in the download URL's checksum and be built less than 48 hours before now (the runner's clock, `date +%s`; a CHECK_SCAN_NOW in
# the environment is refused: no variable sets it). osv-scanner runs in its documented offline mode (v2.6.0 docs/offline-mode.md): --offline-vulnerabilities
# --download-offline-databases with OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY an empty directory made fresh for this run inside the script's own
# temporary directory (a variable of that name already defined is refused, as is every OSV_SCANNER_* one), so every database is downloaded in this job as
# <ecosystem>/all.zip from osv-vulnerabilities.storage.googleapis.com; the evidence is read from those files (the zip's sha256, the newest
# `modified` of its OSV records) and every zip must be for an ecosystem the scans reported. The results record db_source_url,
# db_source_basis, the date and db_digest: grype per scanner, its date db_built_or_published (the database build time) and its URL
# observed in its status output; osv-scanner per ecosystem in `databases`, its date db_newest_record_modified (the newest record
# `modified`, not a build date) and its URL the documented one (no osv file or output names it). The script fails, naming the
# scanner, when a listed scanner is missing, could not
# run, found anything, reports no version or zero packages, or when the number that ran differs from the number listed.
# Writes OUT/scan-results.json {listed, ran, scanners: [{name, version, verdict, subjects: [{name, digest, packages, verdict}]}]}.
set -euo pipefail
# an OCI layout directory (PR 2's interface, PROPOSED): oci-layout and an index.json; a docker-save tarball or any other directory is refused
is_layout() { [ -d "$1" ] && [ -f "$1/oci-layout" ] && [ -f "$1/index.json" ]; }
usage() { echo "usage: check-scan.sh --scanners FILE --digests FILE --images DIR --archives DIR --out DIR" >&2; exit 2; }
fail() { echo "check-scan: $*" >&2; exit 1; }
list="" digests="" images="" archives="" out=""
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --scanners) list=$2 ;;
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --archives) archives=$2 ;;
    --out) out=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$list" ] && [ -n "$digests" ] && [ -n "$images" ] && [ -n "$archives" ] && [ -n "$out" ] || usage
[ -f "$list" ] || fail "the scanner list $list does not exist"
[ -f "$digests" ] || fail "the digest list $digests does not exist"
scanners=()
mapfile -t scanners < <(jq -r '.scanners[]' "$list")
[ "${#scanners[@]}" -gt 0 ] || fail "no scanner is listed in $list (a vacuous pass is not a pass)"
for v in production fips; do
  d=$(jq -r --arg k "image-$v" '.[$k] // empty' "$digests")
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-$v digest"
  is_layout "$images/$v" || fail "the $v image $images/$v is missing or not an OCI layout directory (oci-layout and index.json)"
done
shopt -s nullglob
# REQ-PLAT-001-AC1 (Linux only): the archive list is exactly the four Linux archives, fscache and fscache-fips for amd64 and arm64, of one version,
# and no darwin or windows file of any kind exists beside them. Anything else stops here, before a scan counts it as covered.
for f in "$archives"/*; do
  case "${f,,}" in *darwin*|*windows*) fail "a darwin or windows file exists in $archives ($(basename "$f")): REQ-PLAT-001 ships Linux only" ;; esac
done
tars=("$archives"/*.tar.gz)
want=$(printf '%s\n' fscache_VER_linux_amd64.tar.gz fscache_VER_linux_arm64.tar.gz fscache-fips_VER_linux_amd64.tar.gz fscache-fips_VER_linux_arm64.tar.gz)
ver=$(basename "${tars[0]:-x}" | sed -n 's/^fscache[a-z-]*_\([^_]*\)_linux_.*/\1/p')
got=$(for f in "$archives"/*; do basename "$f"; done | sort)
[ -n "$ver" ] && [ "$got" = "$(sed "s/VER/$ver/" <<< "$want" | sort)" ] \
  || fail "the archive list in $archives is not exactly the four Linux archives (fscache and fscache-fips, amd64 and arm64, of one version): found $(tr '\n' ' ' <<< "$got")"
# Round 1 F1: the layouts and archives are the ones Build recorded (re-derived from digests.json, every blob and archive re-hashed), before any scan.
python3 bin/check-bind.py --digests "$digests" --images "$images" --archives "$archives" || exit 1
mods=(go.mod tools/requirements/go.mod)
for m in "${mods[@]}"; do [ -f "$m" ] || fail "the Go module file $m is missing"; done
mkdir -p "$out"
VEX=.vex/fosterstack-cache.openvex.json
# The clock is the runner's (round 1 F4): the age of a database is judged against `date +%s` and nothing the environment says. A CHECK_SCAN_NOW in the
# environment (an older `now` would pass any database as fresh) is refused, defined or empty, never read; the tests give the clock by a fake date command.
# "The VEX is the only exception" (register rows 18 and 38; cache#580 for the PR gate): grype also drops findings through GRYPE_* settings (GRYPE_ONLY_FIXED, GRYPE_IGNORE_WONTFIX, ...)
# and through a config file, so any GRYPE_* variable other than the database cache and update settings stops the pass (names only, values are never printed), and
# grype runs with -c and an EMPTY config file ($tmp/empty.yaml) so no repository, home or XDG config applies. The same holds for osv-scanner (the owner: the published OpenVEX file is the
# only exception for all four scanners): any OSV_SCANNER_* variable other than its database cache directory stops the pass, and both osv-scanner calls get --config with an EMPTY toml
# ($tmp/empty.toml), because it reads an osv-scanner.toml beside the scanned go.mod and drops the vulnerabilities it lists from its report, where the VEX check below never sees them.
# Its database directory is always a fresh one of this run, so every OSV_SCANNER_* variable is refused, the cache directory one included.
bad_env=""
for v in "${!GRYPE_@}"; do
  case "$v" in GRYPE_DB_CACHE_DIR|GRYPE_DB_AUTO_UPDATE) ;; *) bad_env="${bad_env}${v} " ;; esac
done
for v in "${!OSV_SCANNER_@}"; do
  bad_env="${bad_env}${v} "
done
if [ -n "$bad_env" ]; then
  echo "check-scan: $bad_env found in the environment: only the VEX document may hide a finding, and these settings can; refusing to run (names only, values are never printed)" >&2
  exit 2
fi
[ -z "${CHECK_SCAN_NOW+x}" ] || fail "CHECK_SCAN_NOW is defined in the environment: the database age is judged by the runner's clock, which no variable can change"
now=$(date +%s)
[[ "$now" =~ ^[0-9]+$ ]] || fail "the runner's clock did not give epoch seconds: $now"
GRYPE_HOST=grype.anchore.io   # the host in grype's recorded database status (the scanner fixtures of the auditor directory (fixtures/scanners)/grype.json)
MAX_AGE=172800                # 48 hours
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
: > "$tmp/empty.yaml"; : > "$tmp/empty.toml"   # empty.yaml is the one config grype reads (it needs the extension); empty.toml is osv-scanner's

# one scan target: its name, digest, the file the scanner reads and, for an image, its platform and config digest
add_target() {
  tname+=("$1")
  tdigest+=("$2")
  tpath+=("$3")
  tplat+=("${4:-}")
  tconf+=("${5:-}")
}
# The platform children of an image layout (S1, chain-v030 review): grype on the multi-platform index with no platform scans only the runner's own
# platform, so each variant is scanned once per child, by the child's own manifest digest, and an index that lacks a child is a failure.
# Layout is already bound to digests.json by check-bind (index, child manifests, every blob re-hashed), so the index it reads here is Build's.
PLATFORMS=(amd64 arm64)
# image_archive LAYOUT ARCH ARCHIVE TAG: the docker-save tar of the linux/ARCH child, made by bin/layout-archive.sh
# (the one definition of it: it re-hashes every blob it packs). Prints "<child manifest digest> <config digest>", or
# fails; the script's own message is on stderr.
image_archive() {
  local line
  line=$(bash bin/layout-archive.sh "$@") || return 1
  # the script's one output line: "child sha256:<64 hex> config sha256:<64 hex>" yes; a missing config, an extra
  # word or an upper-case digest no
  [[ "$line" =~ ^child\ (sha256:[0-9a-f]{64})\ config\ (sha256:[0-9a-f]{64})$ ]] || return 1
  echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
}
other_platforms() {   # other_platforms LAYOUT -> one os/arch per line for every index descriptor that is neither linux/amd64, linux/arm64 nor the unknown/unknown provenance descriptor
  local idx blob d mf out line prog pprog; idx=$(jq -r '.manifests[0].digest // empty' "$1/index.json" 2> /dev/null) || return 0
  [[ "$idx" =~ ^sha256:[0-9a-f]{64}$ ]] || return 0
  blob="$1/blobs/sha256/${idx#sha256:}"; [ -f "$blob" ] || return 0
  # unknown/unknown is buildkit's descriptor for one of the two children: annotations vnd.docker.reference.type (a string) and
  # vnd.docker.reference.digest (a string equal to a linux/amd64 or linux/arm64 child digest), AND its own manifest holds only JSON layers
  # (application/...+json, no filesystem layer) (an ordinary image manifest carrying the annotations is a third image nobody scanned). Anything else is named and fails.
  # Golang's decoders (containerd, go-containerregistry, stereoscope) match JSON keys without regard to case, jq does not: an object whose keys collide once
  # lower-cased reads one way here and another way there, so it is refused; so is any key outside printable ASCII (Golang also folds U+017F and U+212A to s and k).
  # Each file is exactly ONE JSON value (jq reads them all and answers for the last; Golang's decoders read the first and ignore the rest).
  if ! jq -s -e 'length == 1 and ([.[0] | .. | objects | keys | (map(ascii_downcase) | length != (unique | length)) or any(.[]; test("^[ -~]+$") | not)] | any | not)' "$blob" > /dev/null 2>&1 \
     || ! jq -s -e 'length == 1 and ([.[0] | .. | objects | keys | any(.[]; test("^[ -~]+$") | not)] | any | not)' "$1/index.json" > /dev/null 2>&1; then
    echo "index descriptors with keys that differ only in case, with a key outside printable ASCII, or that cannot be read"; return 0
  fi
  prog='def obj: if type == "object" then . else {} end; ([.manifests[]? | select((.platform | obj).os == "linux" and ((.platform | obj).architecture == "amd64" or (.platform | obj).architecture == "arm64")) | .digest]) as $kids | .manifests[]? | (((.platform | obj) as $q | "\($q.os // "none")/\($q.architecture // "none")")) as $p | (.annotations | obj) as $a | if $p == "unknown/unknown" and ($a["vnd.docker.reference.type"] | type) == "string" and ($a["vnd.docker.reference.digest"] | type) == "string" and ($kids | index($a["vnd.docker.reference.digest"])) != null and (.digest | type) == "string" then "@@check " + .digest elif $p == "unknown/unknown" then "unknown/unknown (not a descriptor of one of the two children)" else $p end | select(. != "linux/amd64" and . != "linux/arm64")'
  out=$(jq -r "$prog" "$blob" 2> /dev/null) || out="unreadable index descriptors"
  local -a lines_
  mapfile -t lines_ <<< "$out"   # the lines are read byte for byte: a trailing space or tab on a digest or a platform string is not trimmed away
  for line in "${lines_[@]}"; do
    case "$line" in
      "@@check "*)
        d=${line#@@check }
        pprog='length == 1 and (.[0] | ([.. | objects | keys | (map(ascii_downcase) | length != (unique | length)) or any(.[]; test("^[ -~]+$") | not)] | any | not) and .mediaType == "application/vnd.oci.image.manifest.v1+json" and (.layers | type) == "array" and (.layers | length) > 0 and all(.layers[]; (.mediaType | type) == "string" and (.mediaType | test("^application/[a-z0-9.+-]+[+]json\\z"))))'
        mf="$1/blobs/sha256/${d#sha256:}"
        if [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] && [ -f "$mf" ] && jq -s -e "$pprog" "$mf" > /dev/null 2>&1; then :
        else echo "unknown/unknown (its own manifest is not a provenance manifest)"; fi ;;
      "") ;;
      *) echo "$line" ;;
    esac
  done
}
vex_image_repo() {   # the one repository the published VEX names for the cache image (pkg:oci/cache[@sha256:<64 hex>]?[...&]repository_url=REPO[&...][#...]), or nothing.
  # Every identifier of every product counts (grype's VEX reader considers @id and identifiers.* alike): a product that is not an object, or a cache identifier
  # (pkg:oci/cache followed by @ ? # / or the end) in any other form or with two repository_url, or a conflicting second repository, leaves nothing (fail closed).
  local repo='[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+'
  jq -r --arg repo "$repo" '[.statements[]?.products[]? | if type == "object" then ((.["@id"]?), ((.identifiers? | objects | .[]?))) else "pkg:oci/cache?malformed" end | select(type == "string" and test("^pkg:oci/cache([@?#/]|$)"))] as $ids | if any($ids | .[]; (test("^pkg:oci/cache(@sha256:[0-9a-f]{64})?[?]([^#]*&)?repository_url=" + $repo + "(&[^#]*)?(#.*)?\\z") | not) or ([sub("#.*$"; "") | match("repository_url=";"g")] | length) != 1) then empty else [$ids | .[] | sub("#.*$"; "") | capture("repository_url=(?<r>" + $repo + ")") | .r] | unique | if length == 1 then .[0] else empty end end' "$VEX" 2> /dev/null
}
failed=0 ran=0
all="[]"
for s in "${scanners[@]}"; do
  if ! type -P "$s" > /dev/null 2>&1; then
    echo "check-scan: $s is listed but not installed" >&2; failed=1; continue
  fi
  case "$s" in grype|osv-scanner) ;; *) echo "check-scan: $s is listed but this script knows no way to run it" >&2; failed=1; continue ;; esac
  version=$("$s" --version 2> /dev/null | sed -n 1p) || true
  db_url="" db_built="" db_digest=""
  : > "$tmp/osv-ecos"
  if [ "$s" = osv-scanner ]; then
    osvcache="$tmp/osv-db"; mkdir -p "$osvcache"   # always a fresh directory of this run: the cache variable is refused above, so no earlier or planted database is ever read
  fi
  dbrc=0; [ "$s" != grype ] || grype db update -c "$tmp/empty.yaml" < /dev/null || dbrc=$?
  if [ "$dbrc" != 0 ]; then
    echo "check-scan: grype could not fetch its vulnerability database (grype db update exit $dbrc): nothing is scanned, nothing is clean" >&2
    failed=1
    all=$(jq -c --arg n "$s" --arg ver "$version" '. + [{name: $n, version: $ver, verdict: "fail", db_source_url: null, db_built_or_published: null, db_digest: null, subjects: []}]' <<< "$all")
    continue
  fi
  ran=$((ran + 1))
  verdict=pass
  [ -n "$version" ] || { echo "check-scan: $s reports no version" >&2; verdict=fail; }
  subjects="[]"
  tname=() tdigest=() tpath=() tplat=() tconf=()
  imgrepo=""
  if [ "$s" = grype ]; then
    imgrepo=$(vex_image_repo) || imgrepo=""
  fi
  for v in production fips; do
    if [ "$s" = grype ]; then
      mapfile -t others_ < <(other_platforms "$images/$v")
      for o in "${others_[@]}"; do
        [ -n "$o" ] || continue
        echo "check-scan: grype: the $v image index lists a platform other than linux/amd64 and linux/arm64 ($o): it would be left unscanned, so it is not scanned clean" >&2
        verdict=fail
        subjects=$(jq -c --arg n "$v/$o" '. + [{name: $n, digest: null, packages: 0, verdict: "fail"}]' <<< "$subjects")
      done
      for a in "${PLATFORMS[@]}"; do
        arc="$tmp/grype-$v-linux-$a.tar"
        if ids=$(image_archive "$images/$v" "$a" "$arc" "${imgrepo:+$imgrepo:}cand-$v-$a"); then
          add_target "$v/linux/$a" "${ids% *}" "$arc" "linux/$a" "${ids#* }"
        else
          echo "check-scan: grype: no archive of $v/linux/$a (bin/layout-archive.sh refused it): not scanned clean" >&2
          verdict=fail
          subjects=$(jq -c --arg n "$v/linux/$a" '. + [{name: $n, digest: null, packages: 0, verdict: "fail"}]' <<< "$subjects")
        fi
      done
    else
      for a in "${PLATFORMS[@]}"; do   # both scanners read a single image per run: each variant is scanned once per platform child (osv-scanner reads an archive of ONE image)
        arc="$tmp/img-$v-linux-$a.tar"
        if ids=$(image_archive "$images/$v" "$a" "$arc" "cand-$v-$a"); then
          add_target "$v/linux/$a" "${ids% *}" "$arc" "linux/$a" "${ids#* }"
        else
          echo "check-scan: $s: no archive of $v/linux/$a (bin/layout-archive.sh refused it): not scanned clean" >&2
          verdict=fail
          subjects=$(jq -c --arg n "$v/linux/$a" '. + [{name: $n, digest: null, packages: 0, verdict: "fail"}]' <<< "$subjects")
        fi
      done
    fi
  done
  if [ "$s" = grype ]; then
    for a in "${tars[@]}"; do add_target "$(basename "$a")" "sha256:$(sha256sum "$a" | cut -d' ' -f1)" "$a"; done
  else
    for m in "${mods[@]}"; do add_target "$m" "sha256:$(sha256sum "$m" | cut -d' ' -f1)" "$m"; done
  fi
  for ti in "${!tname[@]}"; do
    name=${tname[$ti]} digest=${tdigest[$ti]} path=${tpath[$ti]} plat=${tplat[$ti]} conf=${tconf[$ti]:-}
    rc=0
    : > "$tmp/out.json"; rm -f "$tmp/sbom.json"
    case "$s:$path" in
      grype:*.tar.gz) GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h grype "file:$path" -c "$tmp/empty.yaml" --fail-on negligible --vex "$VEX" -o json -o "cyclonedx-json=$tmp/sbom.json" > "$tmp/out.json" || rc=$? ;;
      grype:*)
        # An oci-dir: layout carries no tag and no repo digest, so grype derives no image identity from it and applies NO VEX statement (rc-5a I, ruling R1; probed on
        # the pinned grype). The child is read from an image archive that names it <repository>:cand-<variant>-<arch>, the name the cache image statements are
        # matched by (the same name the rescan and the PR gate scan under), so the one published VEX applies here as everywhere. A check script knows no registry
        # (REQ-CHAIN-006-AC8): the repository is the one the VEX itself names for the cache image; none, or two, cannot be judged and nothing is scanned under an image name.
        if [ -z "$imgrepo" ]; then
          echo "check-scan: grype: the published VEX names no single cache image repository, so $name cannot be scanned under its image name" >&2; rc=2
        else
          GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h \
            grype "docker-archive:$path" -c "$tmp/empty.yaml" --fail-on negligible --vex "$VEX" \
            -o json -o "cyclonedx-json=$tmp/sbom.json" > "$tmp/out.json" || rc=$?
        fi ;;
      osv-scanner:*.mod) OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$osvcache" osv-scanner scan source --config "$tmp/empty.toml" --all-vulns --offline-vulnerabilities --download-offline-databases --format json --all-packages "$path" > "$tmp/out.json" || rc=$? ;;
      osv-scanner:*)
        OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$osvcache" osv-scanner scan image --config "$tmp/empty.toml" --all-vulns \
          --archive --offline-vulnerabilities --download-offline-databases --format json --all-packages "$path" \
          > "$tmp/out.json" || rc=$? ;;
    esac
    # A tool that failed before writing leaves nothing to read, and anything but a number is 0 packages (did not run).
    if [ "$s" = grype ]; then
      packages=$(jq '[.components[]? | select((.purl | type) == "string" and (.purl | test("^pkg:[a-z][a-z0-9.+-]*\\x2f.")))] | length' "$tmp/sbom.json" 2> /dev/null) || packages=0   # components with a package URL (pkg:<type>/<name>, not any string): grype also lists files (rc-5a C)
      jq -c '{grype: .descriptor.version, matches: ([.matches[]?] | length), db: .descriptor.db.status}' "$tmp/out.json" 2> /dev/null || true
    else
      packages=$(jq '[.results[]?.packages[]?] | length' "$tmp/out.json" 2> /dev/null) || packages=0
      jq -r '.results[]?.packages[]?.package.ecosystem // empty' "$tmp/out.json" >> "$tmp/osv-ecos" 2> /dev/null || true
    fi
    [[ "$packages" =~ ^[0-9]+$ ]] || packages=0
    echo "check-scan: $s $name ($digest): $packages packages, exit $rc"
    sv=pass vexn=0
    if [ "$s" = grype ] && [ "$rc" = 0 ]; then
      # The owner's rule (register rows 18 and 38): every severity blocks, and the published VEX is the only exception. --fail-on negligible does not fire
      # on a finding of UNKNOWN severity, so the result is judged here: a match that survived --vex fails whatever its severity, and a result with no
      # matches list is a scan that did not run (fail closed).
      um=$(jq -e 'if (.matches | type) == "array" then (.matches | length) else error("matches is not a list") end' "$tmp/out.json" 2> /dev/null) || um=unreadable
      if [[ ! "$um" =~ ^[0-9]+$ ]]; then
        echo "check-scan: grype's result for $name has no readable matches list: nothing is judged behind a result that cannot be read" >&2; rc=2
      elif [ "$um" -gt 0 ]; then
        echo "check-scan: grype reported $um finding(s) in $name ($digest) of any severity, UNKNOWN included, that the VEX document does not except" >&2; rc=1
      else
        # Everything grype left out must have been left out by the VEX: absent or null is none, otherwise a list whose entries each carry a non-empty list of rule objects, every one
        # namespace "vex" with a vex-status of not_affected or fixed (a config or environment ignore carries another namespace). Known limit, pending the owner's ruling: grype's own
        # distro exclusions drop matches before results are built and are not in ignoredMatches; the images are assembled from Wolfi packages, where this has no known effect.
        igrc=0; ig=$(jq -r 'if .ignoredMatches == null then [] elif (.ignoredMatches | type) == "array" then [.ignoredMatches[] | select((type != "object") or ((.appliedIgnoreRules | type) != "array") or ((.appliedIgnoreRules | length) == 0) or (.appliedIgnoreRules | any((type != "object") or (.namespace != "vex") or ((.["vex-status"] != "not_affected") and (.["vex-status"] != "fixed"))))) | (if type == "object" then ((.vulnerability.id // "?") + " " + (.artifact.name // "?") + "@" + (.artifact.version // "?")) else "a malformed entry" end)] else error("ignoredMatches is not a list") end | .[]' "$tmp/out.json" 2> /dev/null) || igrc=$?
        if [ "$igrc" -ne 0 ]; then
          echo "check-scan: grype's result for $name has no readable ignoredMatches list: nothing is judged behind a result that cannot be read" >&2; rc=2
        elif [ -n "$ig" ]; then
          igl=$(printf '%s' "$ig" | tr '\n' ',')
          echo "check-scan: grype hid finding(s) in $name ($digest) by something other than the published VEX document (not a VEX rule): $igl" >&2; rc=1
        fi
      fi
    fi
    if [ "$s" = grype ] && [ -n "$plat" ] && [ "$rc" = 0 ]; then
      # the image grype reports it scanned is the child recorded for this subject: the archive was made from that child's own blobs, and an archive's image ID is
      # its config digest, so the report's imageID must be the config the child's manifest names (the manifest digest grype reports for an archive is its own, not the child's). This confirms grype read the archive made here from that child, not an independent view of what was scanned: the layers are bound by check-bind (every blob re-hashed) and by the explicit member list of bin/layout-archive.sh
      want=$conf
      md=$(jq -r '.source.target.imageID // empty' "$tmp/out.json" 2> /dev/null) || md=""
      if [ -z "$want" ] || [ "$md" != "$want" ]; then
        echo "check-scan: grype's report for $name names image ID '${md:-none}', not the config '${want:-none}' of the child $digest it was asked to scan: the recorded digest is not the one scanned" >&2; rc=2
      fi
    fi
    if [ "$rc" = 0 ] && [ "$s" = osv-scanner ]; then
      # An exit 0 does not mean an empty report: osv-scanner can list findings and still exit 0 (findings it classes as unimportant or, with call analysis, uncalled).
      # --all-vulns shows them; call analysis is OFF by default in 2.6.0 (probed) and no config or variable can turn it on here (the config is empty, OSV_SCANNER_* is refused),
      # so the scanner never decides not-affected on its own; the report is judged here whatever the exit code. Known limit, pending the owner: osv-scanner's container filter
      # drops a package named linux before matching, whatever the config or the VEX says.
      nf=$(jq -e 'def lst(k): if type != "object" then error("not an object") elif has(k) then (if (.[k] | type) == "array" then .[k] else error("not a list") end) else [] end; [lst("results")[] | lst("packages")[] | lst("vulnerabilities") | length] | add // 0' "$tmp/out.json" 2> /dev/null) || nf=unreadable
      if [[ ! "$nf" =~ ^[0-9]+$ ]]; then
        echo "check-scan: osv-scanner's report for $name cannot be read: nothing is judged behind a result that cannot be read" >&2; rc=2
      elif [ "$nf" -gt 0 ]; then
        rc=1   # findings in the report: the published VEX decides below, exactly as for an exit 1
      fi
    fi
    if [ "$rc" = 1 ] && [ "$s" = osv-scanner ]; then
      # grype read the VEX itself (--vex); osv-scanner cannot, so its findings are held to the same published document here (round 1 F3): exit 1 stands
      # unless the report holds findings and every one is excepted by a statement (the rescan's product-and-alias-scoped decision)
      vv=""; case "${name%%/*}" in production|fips) vv=${name%%/*} ;; esac
      if python3 bin/check-osv-vex.py --vex "$VEX" --report "$tmp/out.json" --variant "$vv" ${plat:+--platform "$plat"} > "$tmp/vex-out.json"; then
        vexn=$(jq -r '.excepted' "$tmp/vex-out.json"); rc=0
        echo "check-scan: osv-scanner: all $vexn findings in $name ($digest) are excepted by the published VEX document"
      fi
    fi
    if [ "$rc" = 1 ]; then
      echo "check-scan: $s found vulnerabilities in $name ($digest) that the VEX document does not except" >&2; sv=fail
    elif [ "$rc" != 0 ]; then
      echo "check-scan: $s could not run on $name (exit $rc): nothing is judged behind a scanner that did not run" >&2; sv=fail
    elif [ "$packages" -eq 0 ]; then
      echo "check-scan: $s reported 0 packages for $name: a scan that inventoried nothing did not run (REQ-REL-004-AC1)" >&2; sv=fail
    fi
    if [ "$s" = grype ]; then   # the database this scan used (REQ-CHAIN-006-AC15)
      from=$(jq -r '.descriptor.db.status.from // empty' "$tmp/out.json" 2> /dev/null) || from=""
      built=$(jq -r '.descriptor.db.status.built // empty' "$tmp/out.json" 2> /dev/null) || built=""
      sum=""; [[ "$from" =~ [?\&]checksum=sha256(%3A|%3a|:)([0-9a-f]{64})($|\&) ]] && sum="sha256:${BASH_REMATCH[2]}"
      host=""; case "$from" in https://*/*) host=${from#https://}; host=${host%%/*} ;; esac
      bt=$(jq -rn --arg b "$built" '$b | fromdateiso8601' 2> /dev/null) || bt=""
      if [ "$host" != "$GRYPE_HOST" ]; then
        echo "check-scan: grype's database for $name came from ${from:-nowhere}, not grype's own database host ($GRYPE_HOST)" >&2; sv=fail
      elif [ -z "$sum" ]; then
        echo "check-scan: grype's database for $name carries no digest (no sha256 checksum in its source URL)" >&2; sv=fail
      elif [[ ! "$bt" =~ ^[0-9]+$ ]]; then
        echo "check-scan: grype's database for $name reports no readable build date" >&2; sv=fail
      elif [ $((now - bt)) -gt "$MAX_AGE" ]; then
        echo "check-scan: grype's database for $name was built $built, older than 48 hours: a stale database is never scanned against" >&2; sv=fail
      elif [ -n "$db_url" ] && { [ "$from" != "$db_url" ] || [ "$built" != "$db_built" ]; }; then
        echo "check-scan: grype used another database for $name than for the earlier subjects" >&2; sv=fail
      else
        db_url=$from db_built=$built db_digest=$sum
      fi
    fi
    [ "$sv" = pass ] || verdict=fail
    subjects=$(jq -c --arg n "$name" --arg d "$digest" --argjson p "$packages" --arg sv "$sv" --argjson vx "$vexn" \
      '. + [{name: $n, digest: $d, packages: $p, verdict: $sv} + (if $vx > 0 then {vex_suppressed: $vx} else {} end)]' <<< "$subjects")
  done
  dbs="[]"
  if [ "$s" = osv-scanner ]; then   # the databases the scans used, read from the downloaded files (REQ-CHAIN-006-AC15)
    if dbs=$(python3 bin/check-osv-db.py "$osvcache" "$tmp/osv-ecos" "$now" "$MAX_AGE"); then :; else dbs="[]"; verdict=fail; fi
  elif [ -z "$db_url" ]; then
    verdict=fail
  fi
  [ "$verdict" = pass ] || failed=1
  all=$(jq -c --arg n "$s" --arg ver "$version" --arg vd "$verdict" --argjson sub "$subjects" --arg u "$db_url" --arg b "$db_built" --arg g "$db_digest" \
    --argjson dbs "$dbs" --arg kind "$s" '. + [{name: $n, version: $ver, verdict: $vd, subjects: $sub}
      + (if $kind == "osv-scanner" then {databases: $dbs}
         else {db_source_url: (if $u == "" then null else $u end), db_source_basis: (if $u == "" then null else "observed" end),
               db_built_or_published: (if $b == "" then null else $b end), db_digest: (if $g == "" then null else $g end)} end)]' <<< "$all")
done
jq -n --argjson l "${#scanners[@]}" --argjson r "$ran" --argjson s "$all" '{listed: $l, ran: $r, scanners: $s}' > "$out/scan-results.json"
if [ "$ran" != "${#scanners[@]}" ]; then
  echo "check-scan: $ran of the ${#scanners[@]} listed scanners ran; every listed scanner must run" >&2; failed=1
fi
[ "$failed" = 0 ] || exit 1
echo "check-scan: all ${#scanners[@]} listed scanners ran clean on every candidate"
