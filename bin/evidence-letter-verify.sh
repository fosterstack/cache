#!/usr/bin/env bash
# The check of a monthly evidence letter's signature (REQ-REL-013), in one place: bin/evidence-letter-publish.sh runs it
# before it uploads, and the daily presence check runs it on every copy it finds. The key is the one Release trusts,
# checked against the offline root; the log is the one pinned log. Never an identity, never the ignored log.
#   evidence-letter-verify.sh key OUTFILE        writes the release public key; a manifest the root does not vouch for,
#                                                or a revoked one, ends here (publish runs this before it signs)
#   evidence-letter-verify.sh pair LETTER KEY    the bundle (LETTER.bundle) holds a Rekor entry and verifies against KEY
set -euo pipefail
die() { echo "evidence-letter-verify: $*" >&2; exit 1; }
case "${1:-}" in
  key)
    out=${2:?the key file is the second argument}
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    refusal=$(python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
      --ref refs/heads/main --out "$tmp/policy.json" 2>&1 > /dev/null) ||
      die "the key manifest is not accepted ($(head -n 1 <<< "$refusal"))"
    jq -r .release_key.public_key "$tmp/policy.json" > "$out" ;;
  pair)
    letter=${2:?the letter file is the second argument}
    key=${3:?the key file is the third argument}
    jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$letter.bundle" > /dev/null ||
      die "$letter.bundle has no Rekor entry"
    cosign verify-blob --key "$key" --trusted-root .github/policy/rekor-trusted-root.json \
      --bundle "$letter.bundle" "$letter" > /dev/null 2>&1 ||
      die "the signature of $letter does not verify against the release key and the pinned log" ;;
  *) die "usage: key OUTFILE | pair LETTER KEY" ;;
esac
