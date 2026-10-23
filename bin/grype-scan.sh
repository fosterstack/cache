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
#   2. any GRYPE_* variable other than GRYPE_DB_* (the database cache and update settings) stops the script with exit 2, naming the variable (never its value);
#   3. every entry of the native JSON's `ignoredMatches` must come from a VEX rule (namespace "vex" and a vex-status); an entry with no rule, no namespace
#      or any other rule exits 1 and is named.
#
# Usage: grype-scan.sh <grype-target> <label>
#   e.g. grype-scan.sh docker:ghcr.io/fosterstack/cache:cand-production-amd64 cand-production-amd64
# Appends "- <label>: N packages, M finding(s)" to $GITHUB_STEP_SUMMARY when set.
# Exit: grype's own status (0 clean, non-zero findings or error); 1 when grype exits 0 but findings survive the VEX (UNKNOWN severity, which
# --fail-on negligible does not fire on) or something other than the VEX hid a finding; 2 on zero packages, on a GRYPE_* setting, or when an output
# of grype cannot be read.
set -uo pipefail
target="${1:?usage: grype-scan.sh <target> <label>}"; label="${2:?usage: grype-scan.sh <target> <label>}"
here="$(cd "$(dirname "$0")" && pwd)"
vex="${VEX:-${here}/../.vex/fosterstack-cache.openvex.json}"

bad_env=$(compgen -e | grep -E '^GRYPE_' | grep -v -E '^GRYPE_DB_' | tr '\n' ' ')
if [ -n "$bad_env" ]; then
  echo "::error::grype ${label}: ${bad_env}set in the environment: only the VEX document may hide a finding, and these settings can; refusing to run (names only, values are never printed)" >&2
  exit 2
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cdx="$tmp/result.cdx.json"; js="$tmp/result.json"; cfg="$tmp/empty.yaml"; : > "$cfg"   # $cfg stays empty: it is the one config grype reads (grype needs the extension)

"${GRYPE:-grype}" "$target" -c "$cfg" --fail-on negligible --vex "$vex" -o table -o "cyclonedx-json=${cdx}" -o "json=${js}"; rc=$?
# A grype that failed before writing leaves a file that is empty or not one complete JSON document: that is 0 packages here ("did not run").
if jq -e . "$cdx" >/dev/null 2>&1; then
  n=$(jq -e '[.components[]?] | length' "$cdx" 2>/dev/null) || n=0
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
  # Everything grype left out must have been left out by the VEX: namespace "vex" and a vex-status on every applied rule, and at least one rule.
  nonvex=$(jq -r 'if .ignoredMatches == null then [] elif (.ignoredMatches | type) == "array" then
      [.ignoredMatches[] | select(((.appliedIgnoreRules // []) | length) == 0 or ((.appliedIgnoreRules // []) | any(.namespace != "vex" or ((.["vex-status"] // "") == "")))) |
        "\(.vulnerability.id // "?") \(.artifact.name // "?")@\(.artifact.version // "?")"] else error("ignoredMatches is not a list") end | .[]' "$js" 2>/dev/null); jqrc=$?
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
