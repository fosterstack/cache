#!/usr/bin/env bash
# Release, post-publish verification (v0.3.0 rule 79, amended by the owner Oct 10: "run those commands right after publishing"). The
# customer-guide commands that need a registry run here, against what was just published; a failure fails the release run.
set -euo pipefail
python3 -I -B bin/release-postverify.py
