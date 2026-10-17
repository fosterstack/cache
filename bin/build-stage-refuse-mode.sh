#!/usr/bin/env bash
# The guard of stage-build.yml and stage-reproducibility.yml (REQ-CHAIN-004-AC12, REQ-CHAIN-005-AC7). The step passes the stage's `mode` input as the one
# argument. Exactly release or snapshot is accepted, compared here in the shell, case-sensitively: GitHub's expression operators compare strings without regard
# to case, so an `if` in the workflow cannot tell 'Release' from 'release'. Anything else is refused before any Witness step is skipped green.
set -euo pipefail
case "${1-}" in
  release|snapshot) ;;
  *) echo "::error::mode must be release or snapshot" >&2; exit 1 ;;
esac
