#!/usr/bin/env bash
# The PR gate's Grype verdict for one target (scan.yml, REQ-REL-004-AC1):
# one pass, the table to the log and CycloneDX to a file for the counts.
# Blocks at any severity; the published VEX document is the only exception
# (Grype applies it natively). A zero-package inventory is "did not run"
# (row 53) and fails, never a clean pass.
#
# Usage: grype-scan.sh <grype-target> <label>
#   e.g. grype-scan.sh docker:ghcr.io/fosterstack/cache:cand-debug-amd64 cand-debug-amd64
# Appends "- <label>: N packages, M finding(s)" to $GITHUB_STEP_SUMMARY when set.
# Exit: grype's own status (0 clean, non-zero findings or error); 2 on zero packages.
set -uo pipefail
target="${1:?usage: grype-scan.sh <target> <label>}"; label="${2:?usage: grype-scan.sh <target> <label>}"
here="$(cd "$(dirname "$0")" && pwd)"
vex="${VEX:-${here}/../.vex/fosterstack-cache.openvex.json}"
grype="${GRYPE:-grype}"
cdx="$(mktemp)"; trap 'rm -f "$cdx"' EXIT

"$grype" "$target" --fail-on negligible --vex "$vex" -o table -o "cyclonedx-json=${cdx}"; rc=$?
# A grype that failed before writing leaves the file empty, and jq exits 0
# with no output on empty input: anything but a number is 0 packages.
n=$(jq '[.components[]?] | length' "$cdx" 2>/dev/null); [[ "$n" =~ ^[0-9]+$ ]] || n=0
f=$(jq '[.vulnerabilities[]?] | length' "$cdx" 2>/dev/null); [[ "$f" =~ ^[0-9]+$ ]] || f="?"
echo "grype ${label}: ${n} packages, ${f} finding(s)"
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "- ${label}: ${n} packages, ${f} finding(s)" >> "$GITHUB_STEP_SUMMARY"
if [ "${n}" -eq 0 ]; then
  echo "::error::grype inventoried 0 packages in ${label} — did not run (row 53), not a clean pass" >&2
  exit 2
fi
exit "$rc"
