#!/usr/bin/env bash
# Build stage, job `assemble` (ubuntu-24.04 VM). Run under Witness by bin/witnessed-local.sh.
# Bind every downloaded apk file to its apk record (a local record: Sign checks it again and signs it), assemble the two images and the archives from the
# melange repository, and write digests.json and items.json at the repository root (the Witness record names both as products).
set -euo pipefail
python3 -I bin/chain-verify.py bind --local --step apk --record rec-apk/ubuntu-24.04/apk-collection.local.json --dir apk/ubuntu-24.04 --as out
python3 -I bin/chain-verify.py bind --local --step apk --record rec-apk/ubuntu-24.04-arm/apk-collection.local.json --dir apk/ubuntu-24.04-arm --as out
# the baseline admission chose (both legs, bound by the binds above and checked again by Sign) becomes a file of Build's own record, which Release verifies (REQ-CHAIN-007-AC19)
python3 -I bin/chain-verify.py admission-baseline --admission apk/ubuntu-24.04/admission.json --admission apk/ubuntu-24.04-arm/admission.json --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" --out admission-baseline.json
mkdir -p melange-repo
cp -R apk/ubuntu-24.04/x86_64 melange-repo/x86_64
cp -R apk/ubuntu-24.04-arm/aarch64 melange-repo/aarch64
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
python3 -I bin/chain-verify.py items-merge --fragment apk/ubuntu-24.04/items-apk.json --fragment apk/ubuntu-24.04-arm/items-apk.json \
  --images out --archives dist --version "${GITHUB_REF_NAME#v}" --archive archive --digests digests.json --items items.json
