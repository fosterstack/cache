#!/usr/bin/env bash
# Install the bubblewrap package on the hosted runner, from the runner's own signed Ubuntu repository (REQ-CHAIN-004-AC3; v0.3.0 rule 38a: melange's
# bubblewrap runner; read-back approved by the advisor Oct 20, handoff 0522). The hosted ubuntu-24.04 images do not ship bwrap, and melange refuses to
# build without it ("bwrap not found on $PATH"). bwrap is the SANDBOX the sealed melange call runs in, never an input of the built bytes: Rebuild
# compares the digests of a second machine's build, so a different bwrap cannot change the product unseen. This is a distribution package, not a
# pinned download: the same stated limit as the skopeo installs (R7 of the Oct 16 review). One package, no recommends, no other argument.
# Exit codes: 0 installed and bwrap runs | 1 the install failed or bwrap does not run afterwards.
set -euo pipefail

# fixed locations: the programs this installer runs are named by path, never resolved through the caller's search path
SUDO=/usr/bin/sudo
APT=/usr/bin/apt-get
BWRAP=/usr/bin/bwrap

"$SUDO" "$APT" update -qq
"$SUDO" "$APT" install -y -qq --no-install-recommends bubblewrap
"$BWRAP" --version >/dev/null
