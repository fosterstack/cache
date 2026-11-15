#!/usr/bin/env bash
# Runs the suites that are one committed test file that sits outside the auditor folder, from the file of suite commands that ci.yml's select step wrote (REQ-CI-001-AC4).
#   bin/run-selected-tests.sh SELECTED
# Run it from the repository root. SELECTED holds the commands bin/select-tests.sh printed, one per line. Each line below runs one suite
# when SELECTED holds its exact command. The suites of the auditor folder and the four that are more than one file are lines and steps of ci.yml's
# allowlist job. A selected command that neither a line below nor such a line or step of ci.yml covers fails the script, and is named.
set -euo pipefail
selected=$1
covered=$(sed -n -e "s/^ *if grep -qxF '\(.*\)' \"\$selected\"; then .*/\1/p" -e "s/^ *\${{ contains(steps.select.outputs.suites, '\(.*\)') }}\$/\1/p" "$0" .github/workflows/ci.yml)
unknown=$(grep -vxF "$covered" "$selected" || true)
[ -z "$unknown" ] || { echo "run-selected-tests: no line of this script and no line or step of ci.yml runs: $unknown" >&2; exit 1; }
if grep -qxF 'bash bin/workflow-consolidation-test.sh' "$selected"; then bash bin/workflow-consolidation-test.sh; fi
if grep -qxF 'bash bin/full-suite-wiring-test.sh' "$selected"; then bash bin/full-suite-wiring-test.sh; fi
if grep -qxF 'bash bin/select-tests-test.sh' "$selected"; then bash bin/select-tests-test.sh; fi
if grep -qxF 'bash bin/persona-uat-wiring-test.sh' "$selected"; then bash bin/persona-uat-wiring-test.sh; fi
if grep -qxF 'bash bin/dependency-lanes-test.sh' "$selected"; then bash bin/dependency-lanes-test.sh; fi
if grep -qxF 'bash bin/release-patch-wiring-test.sh' "$selected"; then bash bin/release-patch-wiring-test.sh; fi
if grep -qxF 'bash bin/go-freshness-wiring-test.sh' "$selected"; then bash bin/go-freshness-wiring-test.sh; fi
if grep -qxF 'bash bin/job-isolation-test.sh' "$selected"; then bash bin/job-isolation-test.sh; fi
if grep -qxF 'bash bin/rescan-current-only-test.sh' "$selected"; then bash bin/rescan-current-only-test.sh; fi
if grep -qxF 'bash bin/panel-wiring-test.sh' "$selected"; then bash bin/panel-wiring-test.sh; fi
if grep -qxF 'bash bin/admission-tag-signer-test.sh' "$selected"; then bash bin/admission-tag-signer-test.sh; fi
if grep -qxF 'bash bin/acceptance-maven-413-test.sh' "$selected"; then bash bin/acceptance-maven-413-test.sh; fi
if grep -qxF 'bash bin/audit-record-test.sh' "$selected"; then bash bin/audit-record-test.sh; fi
if grep -qxF 'python3 bin/check-workflow-permissions.py' "$selected"; then python3 bin/check-workflow-permissions.py; fi
if grep -qxF 'bash bin/persona-uat-agent-test.sh' "$selected"; then bash bin/persona-uat-agent-test.sh; fi
if grep -qxF 'bash bin/persona-uat-test.sh' "$selected"; then bash bin/persona-uat-test.sh; fi
if grep -qxF 'bash bin/check-file-allowlist-test.sh' "$selected"; then bash bin/check-file-allowlist-test.sh; fi
if grep -qxF 'bash bin/branch-sweep-test.sh' "$selected"; then bash bin/branch-sweep-test.sh; fi
if grep -qxF './bin/check-version-literals.sh' "$selected"; then ./bin/check-version-literals.sh; fi
if grep -qxF 'bash bin/build-helpers-test.sh' "$selected"; then bash bin/build-helpers-test.sh; fi
if grep -qxF 'bash bin/vendoring-test.sh </dev/null' "$selected"; then bash bin/vendoring-test.sh </dev/null; fi
if grep -qxF 'bash bin/build-apk-test.sh' "$selected"; then bash bin/build-apk-test.sh; fi
if grep -qxF 'bash bin/refresh-inputs-test.sh' "$selected"; then bash bin/refresh-inputs-test.sh; fi
if grep -qxF 'bash bin/archive-test.sh' "$selected"; then bash bin/archive-test.sh; fi
if grep -qxF 'python3 bin/gen-recipes.py --check' "$selected"; then python3 bin/gen-recipes.py --check; fi
if grep -qxF 'bash bin/vendor-provenance-test.sh </dev/null' "$selected"; then bash bin/vendor-provenance-test.sh </dev/null; fi
if grep -qxF 'bash bin/assemble-image-test.sh' "$selected"; then bash bin/assemble-image-test.sh; fi
if grep -qxF 'bash bin/analyze-egress-trace-test.sh' "$selected"; then bash bin/analyze-egress-trace-test.sh; fi
if grep -qxF 'bash bin/install-scanner-test.sh' "$selected"; then bash bin/install-scanner-test.sh; fi
if grep -qxF 'bash bin/inspector-gate-test.sh' "$selected"; then bash bin/inspector-gate-test.sh; fi
if grep -qxF 'bash bin/vex-both-scanners-test.sh' "$selected"; then ./bin/install-scanner.sh grype; bash bin/vex-both-scanners-test.sh; fi
if grep -qxF 'bash bin/vex-forms-test.sh' "$selected"; then bash bin/vex-forms-test.sh; fi
if grep -qxF 'bash bin/scout-root-cause-test.sh' "$selected"; then bash bin/scout-root-cause-test.sh; fi
if grep -qxF 'bash bin/scout-older-versions-test.sh' "$selected"; then bash bin/scout-older-versions-test.sh; fi
if grep -qxF 'bash bin/go-bump-open-pr-test.sh' "$selected"; then bash bin/go-bump-open-pr-test.sh; fi
if grep -qxF 'bash bin/dependabot-reviewer-test.sh' "$selected"; then bash bin/dependabot-reviewer-test.sh; fi
if grep -qxF 'bash bin/dependabot-reviewer-gather-test.sh' "$selected"; then bash bin/dependabot-reviewer-gather-test.sh; fi
if grep -qxF 'bash bin/panel-test.sh' "$selected"; then bash bin/panel-test.sh; fi
if grep -qxF 'bash bin/vex-index-test.sh </dev/null' "$selected"; then bash bin/vex-index-test.sh </dev/null; fi
if grep -qxF 'bash bin/patch-decide-test.sh' "$selected"; then bash bin/patch-decide-test.sh; fi
