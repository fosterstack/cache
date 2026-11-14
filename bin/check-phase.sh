#!/usr/bin/env bash
# bin/check-phase.sh PHASE  (PHASE: scanners | acceptance | runtime)
# Check's one script, run by the same three witnessed steps on both chips (v0.3.0 rules 55, 58, 72, 79; REQ-CHAIN-006-AC1, AC3). The chip comes from uname -m, never from an argument. Every phase first makes the release policy for the run's tag
# (as Rebuild does), then verifies Build's record (its previous stage, rule 58; Release verifies Sign's own record) for the digests it was given, isolated (python3 -I -B, as Sign's step runs the verifier; a failure stops here,
# before any check), then runs only that phase's checks, each a listed script named by its literal path. The exact form is judged by the script judge of the Check wiring test; change both together.
set -euo pipefail
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo "unknown chip: $(uname -m)" >&2; exit 2 ;;
esac
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json
python3 -I -B bin/chain-verify.py stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json
case "$1" in
  scanners)
    bash bin/check-scan.sh --scanners .github/policy/scanners.json --digests witness-build/digests.json --images images --archives dist --out check-results
    # govulncheck reads the source, not the chip: it runs once, on the amd64 leg
    if [ "$arch" = amd64 ]; then
      python3 -I -B bin/check-govulncheck.py --scanners .github/policy/scanners.json --out check-results
    fi
    ;;
  acceptance)
    bash bin/check-acceptance.sh gradle --digests witness-build/digests.json --images images --out check-results
    bash bin/check-acceptance.sh maven --digests witness-build/digests.json --images images --out check-results
    ;;
  runtime)
    bash bin/check-acceptance.sh egress --digests witness-build/digests.json --images images --out check-results
    bash bin/check-acceptance.sh k8s --digests witness-build/digests.json --images images --out check-results
    bash bin/check-fips.sh --digests witness-build/digests.json --images images --out check-results
    bash bin/check-artifacts.sh --arch "$arch" --digests witness-build/digests.json --images images --archives dist --out check-results
    bash bin/check-guide.sh --guide docs/verify-release.md --digests witness-build/digests.json --images images --out check-results
    ;;
  *) echo "unknown phase: $1" >&2; exit 2 ;;
esac
