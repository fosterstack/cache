#!/usr/bin/env bash
# The guard of stage-build.yml and stage-reproducibility.yml (REQ-CHAIN-004-AC12, REQ-CHAIN-005-AC7): the step that runs this file is gated by an `if`
# that is true only when the stage's `mode` input is neither release nor snapshot, so a third value is refused before any Witness step is skipped green.
set -euo pipefail
echo "::error::mode must be release or snapshot" >&2
exit 1
