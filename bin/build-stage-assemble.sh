#!/usr/bin/env bash
# Build stage, job `assemble` (ubuntu-24.04 VM). Run under Witness by bin/witnessed.sh.
# Verify both apk records and bind every downloaded apk file to its record, assemble the two images and the archives from the
# melange repository, and write digests.json and items.json at the repository root (the Witness record names both as products).
set -euo pipefail
python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
  --tag "$GITHUB_REF_NAME" --out policy.json
python3 bin/chain-verify.py verify --stage build --record rec-apk/ubuntu-24.04/apk-collection.json \
  --policy policy.json
python3 bin/chain-verify.py verify --stage build --record rec-apk/ubuntu-24.04-arm/apk-collection.json \
  --policy policy.json
python3 bin/chain-verify.py bind --step apk --record rec-apk/ubuntu-24.04/apk-collection.json \
  --dir apk/ubuntu-24.04 --as out
python3 bin/chain-verify.py bind --step apk --record rec-apk/ubuntu-24.04-arm/apk-collection.json \
  --dir apk/ubuntu-24.04-arm --as out
mkdir -p melange-repo
cp -R apk/ubuntu-24.04/x86_64 melange-repo/x86_64
cp -R apk/ubuntu-24.04-arm/aarch64 melange-repo/aarch64
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
python3 bin/chain-verify.py items-merge --fragment apk/ubuntu-24.04/items-apk.json \
  --fragment apk/ubuntu-24.04-arm/items-apk.json --images out --archives dist --version "${GITHUB_REF_NAME#v}" \
  --archive archive --digests digests.json --items items.json
