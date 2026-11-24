#!/usr/bin/env bash
# Rebuild stage, job `rapk` (fresh runner per architecture; REQ-CHAIN-005-AC2). Run under Witness by bin/witnessed-local.sh.
# Build the same apks with the same arguments and date, and write this architecture's fragment.
# The tag and, on a release branch (the ref name carried "release/"), the job-local tag at HEAD are made as in Build's apk job.
set -euo pipefail
tag=${GITHUB_REF_NAME#release/}
if [ "$tag" != "$GITHUB_REF_NAME" ]; then
  [ "${GITHUB_ACTIONS:-}" = true ] || { echo "refusing to delete tags outside GitHub Actions (run in a throwaway clone)" >&2; exit 2; }
  for t in $(git tag --list 'v*' --points-at HEAD); do [ "$t" = "$tag" ] || git tag -d "$t" > /dev/null; done
  git tag --force "$tag" HEAD
fi
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/build-apk.sh --variant standard --arch "$(uname -m)" --version "${tag#v}" --source-dir . --repo archive \
  --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go --melange-lock build/locks/melange.lock --out out
./bin/build-apk.sh --variant fips --arch "$(uname -m)" --version "${tag#v}" --source-dir . --repo archive \
  --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go --melange-lock build/locks/melange.lock --out out
./bin/build-baselayout-apk.sh --arch "$(uname -m)" --version "${tag#v}" --source-dir . --repo archive \
  --keyring archive/keys/wolfi-signing.rsa.pub --melange-lock build/locks/melange.lock --out out
python3 -I bin/chain-verify.py items-apk --out-dir "out/$(uname -m)" --result out/items-apk.json
