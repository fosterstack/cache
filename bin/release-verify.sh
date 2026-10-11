#!/usr/bin/env bash
# Release, first witnessed step (rules 56, 57, 58, 69, 71): the tag is checked, the release policy is made for it, and every earlier stage's
# signed record is verified in rule 69's order. No credential exists in this step. A failure stops the run and names the stage (the message starts with the stage).
set -euo pipefail
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || { echo "refused at tag: ${GITHUB_REF_NAME:-} is not vX.Y.Z or vX.Y.Z-rc.N" >&2; exit 1; }
python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json
python3 bin/chain-verify.py stage-start --stage release --previous build --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json
python3 bin/chain-verify.py stage-start --stage release --previous sign --record provenance/provenance.json --digests witness-build/digests.json --policy policy.json --rekor-stub provenance/provenance.rekor.json
python3 bin/chain-verify.py stage-start --stage release --previous rebuild --record witness-rebuild/rebuild-collection.json --digests witness-build/digests.json --policy policy.json
python3 bin/chain-verify.py stage-start --stage release --previous check --record witness-check/check-collection.json --digests witness-build/digests.json --policy policy.json
