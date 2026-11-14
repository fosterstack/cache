#!/usr/bin/env bash
# Runs the suites bin/select-tests.sh selects for the changes from BASE to HEAD (REQ-CI-001-AC4).
#   bin/run-selected-tests.sh BASE HEAD
set -euo pipefail
cd "$(dirname "$0")/.."
suites=$(bash bin/select-tests.sh "$1" "$2")
# the vex suite needs the pinned grype on the PATH
if grep -qxF 'bash bin/vex-both-scanners-test.sh' <<< "${suites}"; then
  ./bin/install-scanner.sh grype
fi
while IFS= read -r suite; do
  [ -z "${suite}" ] || { echo "::group::${suite}"; bash -euo pipefail -c "${suite}"; echo "::endgroup::"; }
done <<< "${suites}"
