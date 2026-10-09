#!/usr/bin/env bash
# Build stage, job `apk` (one run per architecture, on a native runner; REQ-CHAIN-004-AC3). Run under Witness by bin/witnessed.sh.
# Admission first (it is the only step that holds GH_TOKEN, and the token is unset right after), then both apks with the date of the
# tagged commit, the version check on each, and this architecture's items fragment in out/items-apk.json (uploaded with out/).
set -euo pipefail
python3 bin/build-admit.py run
unset GH_TOKEN
SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"
export SOURCE_DATE_EPOCH
./bin/build-apk.sh --variant standard --arch "$(uname -m)" --version "${GITHUB_REF_NAME#v}" --source-dir . \
  --repo archive --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go \
  --melange-lock build/locks/melange.lock --out out
./bin/build-apk.sh --variant fips --arch "$(uname -m)" --version "${GITHUB_REF_NAME#v}" --source-dir . \
  --repo archive --keyring archive/keys/wolfi-signing.rsa.pub --go-archive archive/go \
  --melange-lock build/locks/melange.lock --out out
python3 bin/build-version-check.py --apk-dir "out/$(uname -m)" --variant standard --tag "$GITHUB_REF_NAME" \
  --sha "$GITHUB_SHA"
python3 bin/build-version-check.py --apk-dir "out/$(uname -m)" --variant fips --tag "$GITHUB_REF_NAME" \
  --sha "$GITHUB_SHA"
python3 bin/chain-verify.py items-apk --out-dir "out/$(uname -m)" --result out/items-apk.json
