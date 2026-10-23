#!/usr/bin/env bash
# bin/pack-govulncheck.sh: the last step of the govulncheck-build job (stage-verify.yml; REQ-REL-011-AC1). govulncheck publishes no release binary, so that job built it with
# bin/install-scanner.sh govulncheck; this puts the one binary where the job uploads it from (a plain relative path in the workspace). The Check job downloads it and
# bin/unpack-govulncheck.sh installs it. No credential is held by either side of the build.
set -euo pipefail
mkdir -p govulncheck-out
install -m 0755 /usr/local/bin/govulncheck govulncheck-out/govulncheck
