#!/usr/bin/env bash
# Release, post-publish verification (v0.3.0 rule 79, amended by the owner Oct 10: "run those commands right after
# publishing"). The customer-guide commands that need a registry run here, against what was newly published; a failure
# fails the release run. It first stages the assets the release will carry (bin/release-stage.sh: it holds no credential), so postverify
# runs against them before the release-assets step creates the GitHub release (B-F22).
set -euo pipefail
bash bin/release-stage.sh
python3 -I bin/release-postverify.py
