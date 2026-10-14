#!/usr/bin/env bash
# Snapshot Build, job `apk` (REQ-CHAIN-004-AC12): the proof workflows (scan.yml, main-candidate-rescan.yml) build with no tag. Run under Witness
# as the step snapshot-apk. NO admission, no version check, no GitHub API call, no GH_TOKEN; the apks are signed with the assembly key only (no --signing-key).
# Go stamps the HIGHEST semver tag at HEAD and cache's driver wants the stamp v0.0.0-rc.1, so the other LOCAL v* tags at HEAD are deleted first (job-local,
# never pushed) and v0.0.0-rc.1 is made. Deleting tags destroys an unpushed local tag on a developer's clone, so the first line refuses to run outside
# GitHub Actions (a local run belongs in a throwaway clone with GITHUB_ACTIONS=true set on purpose). The job fails naming any other tag that is left.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] || { echo "refusing to delete tags outside GitHub Actions (run in a throwaway clone)" >&2; exit 2; }
for t in $(git tag --list 'v*' --points-at HEAD); do [ "$t" = v0.0.0-rc.1 ] || git tag -d "$t" > /dev/null; done
git tag --force v0.0.0-rc.1 HEAD
if git tag --points-at HEAD | grep -qvx 'v0.0.0-rc.1'; then \
  echo "::error::HEAD carries the tag $(git tag --points-at HEAD | grep -vx 'v0.0.0-rc.1' | head -1): not a snapshot" >&2; exit 1; fi
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/build-apk.sh --variant standard --arch "$(uname -m)" --version 0.0.0-rc.1 --source-dir . --repo archive \
  --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go --melange-lock build/locks/melange.lock --out out
./bin/build-apk.sh --variant fips --arch "$(uname -m)" --version 0.0.0-rc.1 --source-dir . --repo archive \
  --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go --melange-lock build/locks/melange.lock --out out
python3 bin/chain-verify.py items-apk --out-dir "out/$(uname -m)" --result out/items-apk.json
