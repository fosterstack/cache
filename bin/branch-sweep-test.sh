#!/usr/bin/env bash
# proves: REQ-REPO-001-AC1, REQ-REPO-001-AC2, REQ-REPO-001-AC3, REQ-REPO-001-AC4, REQ-REPO-001-AC5, REQ-REPO-001-AC6, REQ-REPO-001-AC7, REQ-REPO-001-AC8, REQ-REPO-001-AC9, REQ-REPO-001-AC10, REQ-REPO-001-AC11, REQ-REPO-001-AC12, REQ-REPO-001-AC13, REQ-REPO-001-AC14, REQ-REPO-001-AC15, REQ-REPO-001-AC16, REQ-REPO-001-AC17, REQ-REPO-001-AC18, REQ-REPO-001-AC19, REQ-REPO-001-AC20, REQ-REPO-001-AC21, REQ-REPO-001-AC22, REQ-REPO-001-AC23, REQ-REPO-001-AC24, REQ-REPO-001-AC25
# Branch hygiene without a human (owner, Oct 8): the daily sweep of stale remote branches (planner, keep-file, ref API
# calls, fail-closed listings, summary log, dry run), its workflow wiring, and the local prune script. Offline: a fake
# GitHub API behind the injectable runner, temporary git repositories and a fake gh. BRANCH_SWEEP_ROOT points the suite
# at another tree (used to prove the suite against a reference and to run the mutants).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec python3 "$here/branch_sweep_test.py" "$@"
