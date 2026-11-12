#!/usr/bin/env bash
# The target of the check-arm64 job's arm64 step (REQ-CHAIN-006-AC17). Rule 58: before it loads or runs anything of the candidate it makes the release
# policy for the run's tag, verifies Build's record for the digests it was given (the same line the Check dispatcher runs, isolated; Release verifies Sign's record), and only then runs the artifact checks for linux/arm64 on that same digest file. The exact form is judged by the phase judge of the Check wiring test.
set -euo pipefail
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json
python3 -I -B bin/chain-verify.py stage-start --stage check --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json
bash bin/check-artifacts.sh --arch arm64 --digests witness-build/digests.json --images images --archives dist --out check-results
