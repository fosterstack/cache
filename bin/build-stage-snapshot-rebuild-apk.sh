#!/usr/bin/env bash
# Snapshot Rebuild, job `rapk` (REQ-CHAIN-005-AC7): the PR gate keeps rule 31's two-assembly check. Run under Witness as the step snapshot-rapk. The same
# tag discipline as the snapshot Build (refuse outside GitHub Actions, delete the other local v* tags at HEAD, make v0.0.0-rc.1, fail on a tag that is left);
# no policy, no stage-start, no admission, no GitHub API call.
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
