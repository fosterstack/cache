#!/usr/bin/env bash
# Snapshot Build, job `assemble` (REQ-CHAIN-004-AC12). Run under Witness as the step snapshot-build. No policy, no verify, no stage-start (a snapshot
# record is refused by them): the bind of each downloaded apk directory to its snapshot-apk record is the only link. It writes digests.json and items.json
# like a release does, with the fixed snapshot version.
set -euo pipefail
python3 bin/chain-verify.py bind --step snapshot-apk --record rec-apk/ubuntu-24.04/snapshot-apk-collection.json --dir apk/ubuntu-24.04 \
  --as out
python3 bin/chain-verify.py bind --step snapshot-apk --record rec-apk/ubuntu-24.04-arm/snapshot-apk-collection.json \
  --dir apk/ubuntu-24.04-arm --as out
mkdir -p melange-repo
cp -R apk/ubuntu-24.04/x86_64 melange-repo/x86_64
cp -R apk/ubuntu-24.04-arm/aarch64 melange-repo/aarch64
mkdir -p keyring
cp archive/keys/wolfi-signing.rsa.pub keyring/wolfi-signing.rsa.pub
cp build/keys/assembly.rsa.pub keyring/assembly.rsa.pub
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/assemble-image.sh --variant production --version 0.0.0-rc.1 --archive archive --melange-repo melange-repo --keyring-dir keyring \
  --out out
./bin/assemble-image.sh --variant fips --version 0.0.0-rc.1 --archive archive --melange-repo melange-repo --keyring-dir keyring --out out
python3 bin/build-archives.py --melange-repo melange-repo --version 0.0.0-rc.1 --out dist
python3 bin/chain-verify.py items-merge --fragment apk/ubuntu-24.04/items-apk.json --fragment apk/ubuntu-24.04-arm/items-apk.json \
  --images out --archives dist --version 0.0.0-rc.1 --archive archive --digests digests.json --items items.json
