#!/usr/bin/env bash
# The Check job installs the govulncheck that the govulncheck-build job built (REQ-REL-011-AC1).
# The download step before this one keeps the digest check of download-artifact on. This file only refuses a missing binary.
set -euo pipefail
[ -f govulncheck-dl/govulncheck ] || { echo "unpack: govulncheck-dl/govulncheck is missing" >&2; exit 1; }
install -m 0755 govulncheck-dl/govulncheck /usr/local/bin/govulncheck
