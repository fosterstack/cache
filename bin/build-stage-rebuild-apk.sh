#!/usr/bin/env bash
# Rebuild stage, job `rapk` (fresh runner per architecture; REQ-CHAIN-005-AC2). Run under Witness by bin/witnessed.sh.
# Verify Build's record first, then build the same apks with the same arguments and date, and write this architecture's fragment.
set -euo pipefail
python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
  --tag "$GITHUB_REF_NAME" --out policy.json
python3 bin/chain-verify.py stage-start --stage rebuild --previous build \
  --record witness-build/build-collection.json --digests build-in/digests.json --policy policy.json
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/build-apk.sh --variant standard --arch "$(uname -m)" --version "${GITHUB_REF_NAME#v}" --source-dir . \
  --repo archive --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go \
  --melange-lock build/locks/melange.lock --out out
./bin/build-apk.sh --variant fips --arch "$(uname -m)" --version "${GITHUB_REF_NAME#v}" --source-dir . \
  --repo archive --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go \
  --melange-lock build/locks/melange.lock --out out
python3 bin/chain-verify.py items-apk --out-dir "out/$(uname -m)" --result out/items-apk.json
