#!/usr/bin/env bash
# The PR gate's Grype verdict for one target (scan.yml, REQ-REL-004-AC1):
# one pass, the table to the log and CycloneDX to a file for the counts.
# Blocks at any severity, UNKNOWN included (see the end of this file); the published VEX document is the only exception
# (Grype applies it natively). A zero-package inventory is "did not run"
# (row 53) and fails, never a clean pass.
#
# Usage: grype-scan.sh <grype-target> <label>
#   e.g. grype-scan.sh docker:ghcr.io/fosterstack/cache:cand-debug-amd64 cand-debug-amd64
# Appends "- <label>: N packages, M finding(s)" to $GITHUB_STEP_SUMMARY when set.
# Exit: grype's own status (0 clean, non-zero findings or error); 1 when grype exits 0 but findings survive the VEX (UNKNOWN severity); 2 on zero packages
# or when the findings in the CycloneDX output cannot be read.
set -uo pipefail
target="${1:?usage: grype-scan.sh <target> <label>}"; label="${2:?usage: grype-scan.sh <target> <label>}"
here="$(cd "$(dirname "$0")" && pwd)"
vex="${VEX:-${here}/../.vex/fosterstack-cache.openvex.json}"
cdx="$(mktemp)"; trap 'rm -f "$cdx"' EXIT

"${GRYPE:-grype}" "$target" --fail-on negligible --vex "$vex" -o table -o "cyclonedx-json=${cdx}"; rc=$?
# A grype that failed before writing leaves the file empty, and jq exits 0
# with no output on empty input: anything but a number is 0 packages.
n=$(jq '[.components[]?] | length' "$cdx" 2>/dev/null); [[ "$n" =~ ^[0-9]+$ ]] || n=0
f=$(jq -e 'if .vulnerabilities == null then 0 elif (.vulnerabilities | type) == "array" then (.vulnerabilities | length) else error("vulnerabilities is not a list") end' "$cdx" 2>/dev/null); [[ "$f" =~ ^[0-9]+$ ]] || f="?"
echo "grype ${label}: ${n} packages, ${f} finding(s)"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- ${label}: ${n} packages, ${f} finding(s)" >> "$GITHUB_STEP_SUMMARY"
if [ "${n}" -eq 0 ]; then
  echo "::error::grype inventoried 0 packages in ${label} — did not run (row 53), not a clean pass" >&2
  exit 2
fi
# "Blocks at any severity": --fail-on negligible does not fire on a finding of UNKNOWN severity (grype ranks it below negligible), so the findings that
# survived --vex are judged here, whatever their severity (the release Check does the same in bin/check-scan.sh). Grype leaves every VEX-covered
# finding out of the CycloneDX file, so this count never holds one. Findings that cannot be read are not a pass (exit 2).
if [ "$rc" -eq 0 ]; then
  if [[ ! "$f" =~ ^[0-9]+$ ]]; then
    echo "::error::grype ${label}: the findings in its CycloneDX output cannot be read; nothing is judged behind a result that cannot be read" >&2
    exit 2
  elif [ "$f" -gt 0 ]; then
    echo "::error::grype ${label}: ${f} finding(s) of any severity, UNKNOWN included, that the VEX document does not except" >&2
    exit 1
  fi
fi
exit "$rc"
