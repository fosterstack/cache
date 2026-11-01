#!/usr/bin/env bash
# The check of a monthly evidence letter's signature, and of the files it vouches for (REQ-REL-013), in one place.
# Callers make the policy (bin/evidence-letter-publish.sh before it signs, the daily presence check once per run, the
# fetch once per release); the key is the one in that policy, which was checked against the offline root when the
# policy was made, and the log is the one pinned log. Never an identity, never the ignored log.
#   evidence-letter-verify.sh POLICY FILE    FILE.bundle holds a Rekor entry and verifies FILE against the policy's key
set -euo pipefail
die() { echo "evidence-letter-verify: $*" >&2; exit 1; }
policy=${1:?the policy file is the first argument}
file=${2:?the file to verify is the second argument}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
jq -er .release_key.public_key "$policy" > "$tmp/release-key.pub" 2> /dev/null || die "$policy holds no release key"
jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$file.bundle" > /dev/null ||
  die "$file.bundle has no Rekor entry"
cosign verify-blob --key "$tmp/release-key.pub" --trusted-root .github/policy/rekor-trusted-root.json \
  --bundle "$file.bundle" "$file" > /dev/null 2>&1 ||
  die "the signature of $file does not verify against the release key and the pinned log"
