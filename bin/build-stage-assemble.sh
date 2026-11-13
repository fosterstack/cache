#!/usr/bin/env bash
# Job `assemble` of Build and of Rebuild, release and snapshot (ubuntu-24.04 VM), run under Witness by
# bin/witnessed-local.sh:  bin/build-stage-assemble.sh STEP
# STEP is the step of the apk jobs whose apks it assembles: apk or rapk (the version is the tag minus its v),
# snapshot-apk or snapshot-rapk (the version is 0.0.0-rc.1). The apks are in the directory STEP names, minus snapshot-.
# It binds every downloaded apk file to its apk record (a local record: Sign checks it again and signs it), assembles
# the two images and the archives from the melange repository and writes items.json and, for Build, digests.json
# at the repository root (the Witness record names both as products). Rebuild then compares every item with Build's.
set -euo pipefail
step=$1
dir=${step#snapshot-}
version=${GITHUB_REF_NAME#v}
case "$step" in
  snapshot-*) version=0.0.0-rc.1 ;;
esac
case "$step" in
  rapk)
    python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
      --tag "$GITHUB_REF_NAME" --out policy.json
    python3 -I bin/chain-verify.py stage-start --stage rebuild --previous build \
      --record witness-build/build-collection.json --digests build-in/digests.json --policy policy.json ;;
esac
python3 -I bin/chain-verify.py bind --local --step "$step" \
  --record "rec-$dir/ubuntu-24.04/$step-collection.local.json" --dir "$dir/ubuntu-24.04" --as out
python3 -I bin/chain-verify.py bind --local --step "$step" \
  --record "rec-$dir/ubuntu-24.04-arm/$step-collection.local.json" --dir "$dir/ubuntu-24.04-arm" --as out
case "$step" in
  apk)
    # the baseline admission chose (both legs, bound by the binds above) becomes a file of Build's own record,
    # which Release verifies (REQ-CHAIN-007-AC19)
    python3 -I bin/chain-verify.py admission-baseline --admission apk/ubuntu-24.04/admission.json \
      --admission apk/ubuntu-24.04-arm/admission.json --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" \
      --out admission-baseline.json ;;
esac
mkdir -p melange-repo
cp -R "$dir/ubuntu-24.04/x86_64" melange-repo/x86_64
cp -R "$dir/ubuntu-24.04-arm/aarch64" melange-repo/aarch64
mkdir -p keyring
cp archive/keys/wolfi-signing.rsa.pub keyring/wolfi-signing.rsa.pub
cp build/keys/assembly.rsa.pub keyring/assembly.rsa.pub
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/assemble-image.sh --variant production --version "$version" --archive archive --melange-repo melange-repo \
  --keyring-dir keyring --out out
./bin/assemble-image.sh --variant fips --version "$version" --archive archive --melange-repo melange-repo \
  --keyring-dir keyring --out out
# the release's OpenVEX becomes attestation children of each image index (REQ-REL-010-AC1),
# before items-merge writes the digests Sign signs
python3 -I bin/vex-index.py layout --layout out/production --vex .vex/fosterstack-cache.openvex.json
python3 -I bin/vex-index.py sidecar --layout out/production --vex .vex/fosterstack-cache.openvex.json \
  --digest-file out/production.digest
python3 -I bin/vex-index.py layout --layout out/fips --vex .vex/fosterstack-cache.openvex.json
python3 -I bin/vex-index.py sidecar --layout out/fips --vex .vex/fosterstack-cache.openvex.json \
  --digest-file out/fips.digest
python3 -I bin/build-archives.py --melange-repo melange-repo --version "$version" --out dist
digests=()
case "$step" in
  apk | snapshot-apk) digests=(--digests digests.json) ;;
esac
python3 -I bin/chain-verify.py items-merge --fragment "$dir/ubuntu-24.04/items-apk.json" \
  --fragment "$dir/ubuntu-24.04-arm/items-apk.json" --images out --archives dist --version "$version" \
  --archive archive "${digests[@]}" --items items.json
case "$step" in
  rapk)
    cp build-in/digests.json digests.json
    python3 -I bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json \
      --expected build-in/items.json --actual items.json --out witness-rebuild/verdict.json ;;
  snapshot-rapk)
    python3 -I bin/chain-verify.py rebuild-compare --snapshot \
      --build-record witness-build/snapshot-build-collection.local.json --expected build-in/items.json \
      --actual items.json --out witness-rebuild/snapshot-verdict.json ;;
esac
