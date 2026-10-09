#!/usr/bin/env bash
# Rebuild stage, job `rebuild` (REQ-CHAIN-005-AC2). Run under Witness by bin/witnessed.sh.
# Verify Build's and Rebuild's apk records, bind the rebuilt apks, assemble the images and archives exactly as Build did, and compare
# every item with Build's items.json: the verdict is witness-rebuild/verdict.json. Nothing is published (rule 64).
set -euo pipefail
python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
  --tag "$GITHUB_REF_NAME" --out policy.json
python3 bin/chain-verify.py verify --stage rebuild --record rec-rapk/ubuntu-24.04/rapk-collection.json \
  --policy policy.json
python3 bin/chain-verify.py verify --stage rebuild --record rec-rapk/ubuntu-24.04-arm/rapk-collection.json \
  --policy policy.json
python3 bin/chain-verify.py stage-start --stage rebuild --previous build \
  --record witness-build/build-collection.json --digests build-in/digests.json --policy policy.json
python3 bin/chain-verify.py bind --step rapk --record rec-rapk/ubuntu-24.04/rapk-collection.json \
  --dir rapk/ubuntu-24.04 --as out
python3 bin/chain-verify.py bind --step rapk --record rec-rapk/ubuntu-24.04-arm/rapk-collection.json \
  --dir rapk/ubuntu-24.04-arm --as out
mkdir -p melange-repo
cp -R rapk/ubuntu-24.04/x86_64 melange-repo/x86_64
cp -R rapk/ubuntu-24.04-arm/aarch64 melange-repo/aarch64
mkdir -p keyring
cp archive/keys/wolfi-signing.rsa.pub keyring/wolfi-signing.rsa.pub
cp build/keys/assembly.rsa.pub keyring/assembly.rsa.pub
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/assemble-image.sh --variant production --version "${GITHUB_REF_NAME#v}" --archive archive \
  --melange-repo melange-repo --keyring-dir keyring --out out
./bin/assemble-image.sh --variant fips --version "${GITHUB_REF_NAME#v}" --archive archive \
  --melange-repo melange-repo --keyring-dir keyring --out out
python3 bin/build-archives.py --melange-repo melange-repo --version "${GITHUB_REF_NAME#v}" --out dist
python3 bin/chain-verify.py items-merge --fragment rapk/ubuntu-24.04/items-apk.json \
  --fragment rapk/ubuntu-24.04-arm/items-apk.json --images out --archives dist --version "${GITHUB_REF_NAME#v}" \
  --archive archive --items items.json
python3 bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json \
  --expected build-in/items.json --actual items.json --out witness-rebuild/verdict.json
