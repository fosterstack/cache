#!/usr/bin/env bash
# The last step of the govulncheck-build job in the Check stage file (REQ-REL-011-AC1). govulncheck publishes no release binary, so that job builds it from the committed
# module; this puts the one binary where the job uploads it from, a plain relative path in the workspace. The Check job downloads it and installs it. Neither side of the
# build holds a credential.
set -euo pipefail
mkdir -p govulncheck-out
install -m 0755 /usr/local/bin/govulncheck govulncheck-out/govulncheck
