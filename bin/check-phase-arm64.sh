#!/usr/bin/env bash
# The target of the check-arm64 job's arm64 step (REQ-CHAIN-006-AC17): the dispatcher's arm64 phase, which verifies Build's record before it loads or runs anything of the candidate.
set -euo pipefail
bash bin/check-stage.sh arm64
