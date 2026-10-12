#!/usr/bin/env bash
# bin/check-scan.sh --scanners FILE --digests FILE --images DIR --archives DIR --out DIR
# Runs every scanner listed in FILE (.github/policy/scanners.json, "scanners") against the exact candidates (v0.3.0 rule 55;
# REQ-CHAIN-006-AC4; REQ-REL-004-AC1). Each listed scanner scans both candidate images (DIR/production.tar and DIR/fips.tar, named in
# the results by the digest in the digest list); grype also scans every release archive (ARCHIVES/*.tar.gz) and osv-scanner the Go
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
# --download-offline-databases with OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY an empty directory (made fresh for this run, or, when the
# variable is already set, refused unless empty: "cache directory not empty"), so every database is downloaded in this job as
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
# REQ-PLAT-001-AC1 (Linux only): the archive set is exactly the four Linux archives, fscache and fscache-fips for amd64 and arm64, of one version,
# and no darwin or windows file of any kind exists beside them. Anything else stops here, before a scan counts it as covered.
for f in "$archives"/*; do
  case "${f,,}" in *darwin*|*windows*) fail "a darwin or windows file exists in $archives ($(basename "$f")): REQ-PLAT-001 ships Linux only" ;; esac
done
tars=("$archives"/*.tar.gz)
want=$(printf '%s\n' fscache_VER_linux_amd64.tar.gz fscache_VER_linux_arm64.tar.gz fscache-fips_VER_linux_amd64.tar.gz fscache-fips_VER_linux_arm64.tar.gz)
ver=$(basename "${tars[0]:-x}" | sed -n 's/^fscache[a-z-]*_\([^_]*\)_linux_.*/\1/p')
got=$(for f in "$archives"/*; do basename "$f"; done | sort)
[ -n "$ver" ] && [ "$got" = "$(sed "s/VER/$ver/" <<< "$want" | sort)" ] \
  || fail "the archive set in $archives is not exactly the four Linux archives (fscache and fscache-fips, amd64 and arm64, of one version): found $(tr '\n' ' ' <<< "$got")"
# Round 1 F1: the layouts and archives are the ones Build recorded (re-derived from digests.json, every blob and archive re-hashed), before any scan.
python3 bin/check-bind.py --digests "$digests" --images "$images" --archives "$archives" || exit 1
mods=(go.mod tools/requirements/go.mod)
for m in "${mods[@]}"; do [ -f "$m" ] || fail "the Go module file $m is missing"; done
mkdir -p "$out"
VEX=.vex/fosterstack-cache.openvex.json
# The clock is the runner's (round 1 F4): the age of a database is judged against `date +%s` and nothing the environment says. A CHECK_SCAN_NOW in the
# environment (an older `now` would pass any database as fresh) is refused, set or empty, never read; the tests give the clock by a fake date command.
[ -z "${CHECK_SCAN_NOW+x}" ] || fail "CHECK_SCAN_NOW is set in the environment: the database age is judged by the runner's clock, which no variable can set"
now=$(date +%s)
[[ "$now" =~ ^[0-9]+$ ]] || fail "the runner's clock did not give epoch seconds: $now"
GRYPE_HOST=grype.anchore.io   # the host in grype's recorded database status (the scanner fixtures of the auditor directory (fixtures/scanners)/grype.json)
MAX_AGE=172800                # 48 hours
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

add_target() { tname+=("$1"); tdigest+=("$2"); tpath+=("$3"); }   # one scan target: its name, its digest and the file the scanner reads
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
    if [ -n "${OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY:-}" ]; then
      osvcache=$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY; mkdir -p "$osvcache"
      if [ -n "$(find "$osvcache" -mindepth 1 -print -quit)" ]; then
        echo "check-scan: osv-scanner's database cache directory not empty ($osvcache): the databases must be downloaded fresh in this job" >&2
        failed=1
        all=$(jq -c --arg n "$s" --arg ver "$version" '. + [{name: $n, version: $ver, verdict: "fail", databases: [], subjects: []}]' <<< "$all")
        continue
      fi
    else
      osvcache="$tmp/osv-db"; mkdir -p "$osvcache"
    fi
  fi
  dbrc=0; [ "$s" != grype ] || grype db update < /dev/null || dbrc=$?
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
  tname=() tdigest=() tpath=()
  for v in production fips; do add_target "$v" "$(jq -r --arg k "image-$v" '.[$k]' "$digests")" "$images/$v"; done
  if [ "$s" = grype ]; then
    for a in "${tars[@]}"; do add_target "$(basename "$a")" "sha256:$(sha256sum "$a" | cut -d' ' -f1)" "$a"; done
  else
    for m in "${mods[@]}"; do add_target "$m" "sha256:$(sha256sum "$m" | cut -d' ' -f1)" "$m"; done
  fi
  for ti in "${!tname[@]}"; do
    name=${tname[$ti]} digest=${tdigest[$ti]} path=${tpath[$ti]}
    rc=0
    : > "$tmp/out.json"; rm -f "$tmp/sbom.json"
    case "$s:$path" in
      grype:*.tar.gz) GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h grype "file:$path" --fail-on negligible --vex "$VEX" -o json -o "cyclonedx-json=$tmp/sbom.json" > "$tmp/out.json" || rc=$? ;;
      grype:*) GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_MAX_ALLOWED_BUILT_AGE=48h grype "oci-dir:$path" --fail-on negligible --vex "$VEX" -o json -o "cyclonedx-json=$tmp/sbom.json" > "$tmp/out.json" || rc=$? ;;
      osv-scanner:*.mod) OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$osvcache" osv-scanner scan source --offline-vulnerabilities --download-offline-databases --format json --all-packages "$path" > "$tmp/out.json" || rc=$? ;;
      osv-scanner:*) tar -C "$path" -cf "$tmp/img-$name.tar" . && OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$osvcache" osv-scanner scan image --archive --offline-vulnerabilities --download-offline-databases --format json --all-packages "$tmp/img-$name.tar" > "$tmp/out.json" || rc=$? ;;
    esac
    # A tool that failed before writing leaves nothing to read, and anything but a number is 0 packages (did not run).
    if [ "$s" = grype ]; then
      packages=$(jq '[.components[]?] | length' "$tmp/sbom.json" 2> /dev/null) || packages=0
      jq -c '{grype: .descriptor.version, matches: ([.matches[]?] | length), db: .descriptor.db.status}' "$tmp/out.json" 2> /dev/null || true
    else
      packages=$(jq '[.results[]?.packages[]?] | length' "$tmp/out.json" 2> /dev/null) || packages=0
      jq -r '.results[]?.packages[]?.package.ecosystem // empty' "$tmp/out.json" >> "$tmp/osv-ecos" 2> /dev/null || true
    fi
    [[ "$packages" =~ ^[0-9]+$ ]] || packages=0
    echo "check-scan: $s $name ($digest): $packages packages, exit $rc"
    sv=pass vexn=0
    if [ "$rc" = 1 ] && [ "$s" = osv-scanner ]; then
      # grype read the VEX itself (--vex); osv-scanner cannot, so its findings are held to the same published document here (round 1 F3): exit 1 stands
      # unless the report holds findings and every one is excepted by a statement (the rescan's product-and-alias-scoped decision)
      vv=""; case "$name" in production|fips) vv=$name ;; esac
      if python3 bin/check-osv-vex.py --vex "$VEX" --report "$tmp/out.json" --variant "$vv" > "$tmp/vex-out.json"; then
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
