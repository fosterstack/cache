#!/usr/bin/env bash
# Snapshot Rebuild, job `rebuild` (REQ-CHAIN-005-AC7). Run under Witness as the step snapshot-rebuild. Bind the rebuilt apks to their snapshot-rapk records,
# assemble the images and archives as the snapshot Build did, and compare EVERY item with the items.json that Build's snapshot-build record holds
# (rebuild-compare --snapshot). The verdict is witness-rebuild/snapshot-verdict.json (never verdict.json); a difference fails the job.
set -euo pipefail
python3 -I bin/chain-verify.py bind --local --step snapshot-rapk --record rec-rapk/ubuntu-24.04/snapshot-rapk-collection.local.json --dir rapk/ubuntu-24.04 \
  --as out
python3 -I bin/chain-verify.py bind --local --step snapshot-rapk --record rec-rapk/ubuntu-24.04-arm/snapshot-rapk-collection.local.json \
  --dir rapk/ubuntu-24.04-arm --as out
mkdir -p melange-repo
cp -R rapk/ubuntu-24.04/x86_64 melange-repo/x86_64
cp -R rapk/ubuntu-24.04-arm/aarch64 melange-repo/aarch64
mkdir -p keyring
cp archive/keys/wolfi-signing.rsa.pub keyring/wolfi-signing.rsa.pub
cp build/keys/assembly.rsa.pub keyring/assembly.rsa.pub
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/assemble-image.sh --variant production --version 0.0.0-rc.1 --archive archive --melange-repo melange-repo --keyring-dir keyring \
  --out out
./bin/assemble-image.sh --variant fips --version 0.0.0-rc.1 --archive archive --melange-repo melange-repo --keyring-dir keyring --out out
# the release's OpenVEX becomes attestation children of each image index (REQ-REL-010-AC1), before items-merge writes the digests Sign signs
python3 -I bin/vex-index.py layout --layout out/production --vex .vex/fosterstack-cache.openvex.json
python3 -I bin/vex-index.py sidecar --layout out/production --vex .vex/fosterstack-cache.openvex.json --digest-file out/production.digest
python3 -I bin/vex-index.py layout --layout out/fips --vex .vex/fosterstack-cache.openvex.json
python3 -I bin/vex-index.py sidecar --layout out/fips --vex .vex/fosterstack-cache.openvex.json --digest-file out/fips.digest
python3 -I bin/build-archives.py --melange-repo melange-repo --version 0.0.0-rc.1 --out dist
python3 -I bin/chain-verify.py items-merge --fragment rapk/ubuntu-24.04/items-apk.json --fragment rapk/ubuntu-24.04-arm/items-apk.json \
  --images out --archives dist --version 0.0.0-rc.1 --archive archive --items items.json
python3 -I bin/chain-verify.py rebuild-compare --snapshot --build-record witness-build/snapshot-build-collection.local.json \
  --expected build-in/items.json --actual items.json --out witness-rebuild/snapshot-verdict.json
