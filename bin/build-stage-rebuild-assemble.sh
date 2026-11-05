#!/usr/bin/env bash
# Rebuild stage, job `rebuild` (REQ-CHAIN-005-AC2). Run under Witness by bin/witnessed-local.sh.
# Verify Build's record first (stage-start), then bind the rebuilt apks to Rebuild's apk records (local records; Sign checks them and signs them), assemble the images and archives exactly as Build did, and compare
# every item with Build's items.json: the verdict is witness-rebuild/verdict.json. Nothing is published (rule 64).
set -euo pipefail
python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json
python3 -I bin/chain-verify.py stage-start --stage rebuild --previous build --record witness-build/build-collection.json \
  --digests build-in/digests.json --policy policy.json
python3 -I bin/chain-verify.py bind --local --step rapk --record rec-rapk/ubuntu-24.04/rapk-collection.local.json --dir rapk/ubuntu-24.04 --as out
python3 -I bin/chain-verify.py bind --local --step rapk --record rec-rapk/ubuntu-24.04-arm/rapk-collection.local.json --dir rapk/ubuntu-24.04-arm --as out
mkdir -p melange-repo
cp -R rapk/ubuntu-24.04/x86_64 melange-repo/x86_64
cp -R rapk/ubuntu-24.04-arm/aarch64 melange-repo/aarch64
mkdir -p keyring
cp archive/keys/wolfi-signing.rsa.pub keyring/wolfi-signing.rsa.pub
cp build/keys/assembly.rsa.pub keyring/assembly.rsa.pub
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/assemble-image.sh --variant production --version "${GITHUB_REF_NAME#v}" --archive archive --melange-repo melange-repo \
  --keyring-dir keyring --out out
./bin/assemble-image.sh --variant fips --version "${GITHUB_REF_NAME#v}" --archive archive --melange-repo melange-repo --keyring-dir keyring \
  --out out
# the release's OpenVEX becomes attestation children of each image index (REQ-REL-010-AC1), before items-merge writes the digests Sign signs
python3 -I bin/vex-index.py layout --layout out/production --vex .vex/fosterstack-cache.openvex.json
python3 -I bin/vex-index.py sidecar --layout out/production --vex .vex/fosterstack-cache.openvex.json --digest-file out/production.digest
python3 -I bin/vex-index.py layout --layout out/fips --vex .vex/fosterstack-cache.openvex.json
python3 -I bin/vex-index.py sidecar --layout out/fips --vex .vex/fosterstack-cache.openvex.json --digest-file out/fips.digest
python3 -I bin/build-archives.py --melange-repo melange-repo --version "${GITHUB_REF_NAME#v}" --out dist
python3 -I bin/chain-verify.py items-merge --fragment rapk/ubuntu-24.04/items-apk.json --fragment rapk/ubuntu-24.04-arm/items-apk.json \
  --images out --archives dist --version "${GITHUB_REF_NAME#v}" --archive archive --items items.json
cp build-in/digests.json digests.json
python3 -I bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json --expected build-in/items.json \
  --actual items.json --out witness-rebuild/verdict.json
