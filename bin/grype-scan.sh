#!/usr/bin/env bash
# The PR gate's Grype verdict for one target (scan.yml, REQ-REL-004-AC1):
# one pass, the table to the log, CycloneDX and grype's native JSON to files for the verdict.
# Blocks at any severity, UNKNOWN included; the published VEX document is the only exception
# (Grype applies it natively). A zero-package inventory is "did not run"
# (row 53) and fails, never a clean pass.
#
# "The VEX is the only exception" is enforced three ways, because grype also drops findings through a config file (.grype.yaml `ignore:`, a home or XDG
# config) and through GRYPE_* settings (GRYPE_ONLY_FIXED, GRYPE_IGNORE_WONTFIX, ...):
#   1. grype runs with `-c` and an EMPTY config file, so no config of the repository, the home directory or XDG applies;
#   2. any GRYPE_* variable other than GRYPE_DB_CACHE_DIR and GRYPE_DB_AUTO_UPDATE stops the script with exit 2, naming the variable (never its value);
#   3. every entry of the native JSON's `ignoredMatches` must come from a VEX rule (namespace "vex" and a vex-status); an entry with no rule, no namespace
#      or any other rule exits 1 and is named.
#
# Usage: grype-scan.sh <grype-target> <label>
#   e.g. grype-scan.sh docker:ghcr.io/fosterstack/cache:cand-production-amd64 cand-production-amd64
# EXPECT_IMAGE_ID=<config digest> (optional) makes grype's reported image ID have to equal it (exit 2 otherwise).
# Appends "- <label>: N packages, M finding(s)" to $GITHUB_STEP_SUMMARY when set.
# Exit: grype's own status (0 clean, non-zero findings or error); 1 when grype exits 0 but findings survive the VEX (UNKNOWN severity, which
# --fail-on negligible does not fire on) or something other than the VEX hid a finding; 2 on zero packages, on a GRYPE_* setting, or when an output
# of grype cannot be read.
set -uo pipefail
target="${1:?usage: grype-scan.sh <target> <label>}"; label="${2:?usage: grype-scan.sh <target> <label>}"
here="$(cd "$(dirname "$0")" && pwd)"
vex="${here}/../.vex/fosterstack-cache.openvex.json"   # the published document only: there is no override

bad_env=""
for v in "${!GRYPE_@}"; do
  case "$v" in GRYPE_DB_CACHE_DIR|GRYPE_DB_AUTO_UPDATE) ;; *) bad_env="${bad_env}${v} " ;; esac
done
if [ -n "$bad_env" ]; then
  echo "::error::grype ${label}: ${bad_env}set in the environment: only the VEX document may hide a finding, and these settings can; refusing to run (names only, values are never printed)" >&2
  exit 2
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cdx="$tmp/result.cdx.json"; js="$tmp/result.json"; cfg="$tmp/empty.yaml"; : > "$cfg"   # $cfg stays empty: it is the one config grype reads (grype needs the extension)

# GRYPE is a test seam (a stand-in for the grype binary); no workflow ever sets it, so CI always runs the pinned grype.
"${GRYPE:-grype}" "$target" -c "$cfg" --fail-on negligible --vex "$vex" -o table -o "cyclonedx-json=${cdx}" -o "json=${js}"; rc=$?
# EXPECT_IMAGE_ID (optional): the config digest of the image the caller built the scanned tar from
# (bin/layout-archive.sh). A tar's image ID is its config
# digest, so grype's report must name it: the image scanned is then the one we ship, not another tar in its place.
if [ -n "${EXPECT_IMAGE_ID:-}" ] && jq -e . "$js" >/dev/null 2>&1; then
  got=$(jq -r '.source.target.imageID // empty' "$js" 2>/dev/null) || got=""
  if [ "$got" != "$EXPECT_IMAGE_ID" ]; then
    echo "::error::grype ${label}: image ID '${got:-none}', expected '${EXPECT_IMAGE_ID}': not the image we ship" >&2
    exit 2
  fi
fi
# A grype that failed before writing leaves a file that is empty or not one complete JSON document: that is 0 packages here ("did not run").
if jq -e . "$cdx" >/dev/null 2>&1; then
  # packages are the components that carry a package URL (pkg:deb/debian/glibc@2.36, not any string); grype also lists every file it catalogued as a component (946 of 965 on a real image), and a
  # file-only inventory is not a scan that ran (row 53; rc-5a C)
  n=$(jq -e '[.components[]? | select((.purl | type) == "string" and (.purl | startswith("pkg:") and (.[4:] | index("/") as $i | $i != null and $i > 0 and $i < length - 1)))] | length' "$cdx" 2>/dev/null) || n=0
  f=$(jq -e 'if .vulnerabilities == null then 0 elif (.vulnerabilities | type) == "array" then (.vulnerabilities | length) else error("vulnerabilities is not a list") end' "$cdx" 2>/dev/null) || f="?"
else
  n=0; f="?"
fi
[[ "$n" =~ ^[0-9]+$ ]] || n=0
[[ "$f" =~ ^[0-9]+$ ]] || f="?"
echo "grype ${label}: ${n} packages, ${f} finding(s)"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- ${label}: ${n} packages, ${f} finding(s)" >> "$GITHUB_STEP_SUMMARY"
if [ "${n}" -eq 0 ]; then
  echo "::error::grype inventoried 0 packages in ${label} — did not run (row 53), not a clean pass" >&2
  exit 2
fi
# Grype's own non-zero status already blocks. The judgment below is for a grype that exited 0.
if [ "$rc" -eq 0 ]; then
  # "Blocks at any severity": --fail-on negligible does not fire on a finding of UNKNOWN severity (grype ranks it below negligible), so the findings that
  # survived --vex are judged here, whatever their severity (bin/check-scan.sh does the same for the release Check). Grype leaves every VEX-covered
  # finding out of the CycloneDX file and the matches list, so these counts never hold one. Findings that cannot be read are not a pass (exit 2).
  if [[ ! "$f" =~ ^[0-9]+$ ]]; then
    echo "::error::grype ${label}: the findings in its CycloneDX output cannot be read; nothing is judged behind a result that cannot be read" >&2
    exit 2
  fi
  if ! jq -e . "$js" >/dev/null 2>&1; then
    echo "::error::grype ${label}: its JSON output is not one complete JSON document; nothing is judged behind a result that cannot be read" >&2
    exit 2
  fi
  m=$(jq -e 'if (.matches | type) == "array" then (.matches | length) else error("matches is not a list") end' "$js" 2>/dev/null) || m="?"
  if [[ ! "$m" =~ ^[0-9]+$ ]]; then
    echo "::error::grype ${label}: its JSON output has no readable matches list; nothing is judged behind a result that cannot be read" >&2
    exit 2
  fi
  if [ "$f" -gt 0 ] || [ "$m" -gt 0 ]; then
    echo "::error::grype ${label}: ${f} finding(s) in the CycloneDX output and ${m} in the matches list, of any severity, UNKNOWN included, that the VEX document does not except" >&2
    exit 1
  fi
  # Everything grype left out must have been left out by the VEX: absent or null is none; otherwise a list whose entries each have a non-empty LIST of rule
  # OBJECTS, every one with namespace "vex" and a vex-status of not_affected or fixed. Known limit, pending the owner's ruling: grype's own distro
  # exclusions (for example its built-in exclusion of some Debian findings) drop matches before results are built, so they are not in ignoredMatches
  # and cannot be seen here; the images are assembled from Wolfi packages, where this has no known effect.
  nonvex=$(jq -r 'if .ignoredMatches == null then [] elif (.ignoredMatches | type) == "array" then
      [.ignoredMatches[] | select((type != "object") or ((.appliedIgnoreRules | type) != "array") or ((.appliedIgnoreRules | length) == 0) or
          (.appliedIgnoreRules | any((type != "object") or (.namespace != "vex") or ((.["vex-status"] != "not_affected") and (.["vex-status"] != "fixed"))))) |
        (if type == "object" then "\(.vulnerability.id // "?") \(.artifact.name // "?")@\(.artifact.version // "?")" else "a malformed entry" end)] else error("ignoredMatches is not a list") end | .[]' "$js" 2>/dev/null); jqrc=$?
  if [ "$jqrc" -ne 0 ]; then
    echo "::error::grype ${label}: its JSON output has no readable ignoredMatches list; nothing is judged behind a result that cannot be read" >&2
    exit 2
  fi
  if [ -n "$nonvex" ]; then
    echo "::error::grype ${label}: finding(s) hidden by something other than the published VEX document (not a VEX rule): ${nonvex//$'\n'/, }" >&2
    exit 1
  fi
fi
exit "$rc"
