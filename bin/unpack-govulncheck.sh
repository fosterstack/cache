#!/usr/bin/env bash
# The Check job installs the govulncheck that the govulncheck-build job built (REQ-REL-011-AC1). The download step before this one keeps download-artifact's own digest check
# on, so a binary whose digest differs from the one GitHub recorded at upload never reaches this script; this script only refuses a missing file.
set -euo pipefail
[ -f govulncheck-dl/govulncheck ] || { echo "unpack: govulncheck-dl/govulncheck is missing" >&2; exit 1; }
install -m 0755 govulncheck-dl/govulncheck /usr/local/bin/govulncheck
