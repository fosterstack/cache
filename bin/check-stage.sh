#!/usr/bin/env bash
# bin/check-stage.sh PHASE  (PHASE: scanners | acceptance | runtime)
# Check's one dispatcher (v0.3.0 rules 55, 58, 72, 79; REQ-CHAIN-006-AC3). Every phase first makes the release policy for the run's tag
# (as PR 2's Rebuild does), then verifies Build's record (its previous stage, rule 58; Release verifies
# Sign's own record) for the digests it was given, isolated (python3 -I -B, as PR 1's Sign step runs the verifier; a failure stops here, before any check), then runs only that phase's checks, each a
# listed script named by its literal path. The exact form is judged by the script judge of the Check wiring test; change both together.
set -euo pipefail
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json
python3 -I -B bin/chain-verify.py stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json
case "$1" in
  scanners)
    bash bin/check-scan.sh --scanners .github/policy/scanners.json --digests witness-build/digests.json --images images --archives dist --out check-results
    python3 -I -B bin/check-govulncheck.py --scanners .github/policy/scanners.json --out check-results
    ;;
  acceptance)
    bash bin/check-acceptance.sh gradle --digests witness-build/digests.json --images images --out check-results
    bash bin/check-acceptance.sh maven --digests witness-build/digests.json --images images --out check-results
    ;;
  runtime)
    bash bin/check-acceptance.sh egress --digests witness-build/digests.json --images images --out check-results
    bash bin/check-acceptance.sh k8s --digests witness-build/digests.json --images images --out check-results
    bash bin/check-fips.sh --digests witness-build/digests.json --images images --out check-results
    bash bin/check-artifacts.sh --digests witness-build/digests.json --images images --archives dist --out check-results
    bash bin/check-guide.sh --guide docs/verify-release.md --digests witness-build/digests.json --images images --out check-results
    ;;
  *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
