#!/usr/bin/env bash
# Release's comparison of Build's and Rebuild's apks: the compare job's one plain step. No key, no secret, no id-token, nothing signed. The work is the Python file named
# below; the owner's rule of Oct 21 2026 is that Rebuild's apks never reach a job that holds a credential. That file's header gives the layout and the refusals.
set -euo pipefail
[ -f bin/release-compare.py ] && [ -f bin/release-compare.sh ] || { echo "release-compare.sh: run bin/release-compare.sh from the repository root" >&2; exit 2; }
python3 -I -B bin/release-compare.py
