#!/usr/bin/env bash
# Release, post-publish verification (v0.3.0 rule 79, amended by the owner Oct 10: "run those commands right after
# publishing"). The customer-guide commands that need a registry run here, against what was newly published; a failure
# fails the release run.
set -euo pipefail
[ -n "${GH_TOKEN:-}" ] || { echo "release-postverify: GH_TOKEN is unset" >&2; exit 2; }
python3 bin/release-postverify.py
