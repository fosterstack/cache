#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): signs the letter with the release KMS key and attaches it, with its
# bundle, to the latest published release. The key is the one Release trusts, checked against the offline root
# before anything is signed or written to the public log; the signing call is Sign's (chain-verify.py), so the one-
# log signing config applies. Before anything is uploaded the signature is verified against that key and the pinned
# Rekor log only: no Sigstore root, no identity. The upload never overwrites, so a second run, or a repository whose
# releases are immutable, ends here with one plain line and publishes nothing. The bundle goes up first and the
# letter second; if the letter is refused, the bundle this run uploaded is removed again, so no half pair is left to
# block the month.
#   argument: the letter file (GH_TOKEN set; REPO defaults to fosterstack/cache). The sign call can only succeed once
#   the KMS federation of the Sign role reaches this job (cache6's P3); until then it fails closed.
set -euo pipefail
die() { echo "evidence-letter-publish: $*" >&2; exit 1; }
letter=${1:?the letter file is the first argument}
[ -f "$letter" ] && [ ! -L "$letter" ] || die "$letter is not a regular file"
repo=${REPO:-fosterstack/cache}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
# the key Release trusts, checked against the offline root: a manifest not vouched for, or a revoked one, ends it here
make_policy=(python3 -I bin/chain-verify.py policy make --template .github/policy/release-policy.template.json
  --ref refs/heads/main --out "$work/policy.json")
refusal=$("${make_policy[@]}" 2>&1 > /dev/null) ||
  die "the key manifest is not accepted ($(head -n 1 <<< "$refusal")): nothing is signed"
jq -r .release_key.public_key "$work/policy.json" > "$work/release-key.pub"
cosign sign-blob --yes --key awskms:///alias/fosterstack-release-signing \
  --signing-config .github/policy/cosign-signing-config.json --bundle "$letter.bundle" "$letter"
jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$letter.bundle" > /dev/null ||
  die "$letter.bundle has no Rekor entry: the letter is not published"
cosign verify-blob --key "$work/release-key.pub" --trusted-root .github/policy/rekor-trusted-root.json \
  --bundle "$letter.bundle" "$letter" > /dev/null 2>&1 ||
  die "the signature does not verify against the release key and the pinned log: not published"
tag=$(gh release view --repo "$repo" --json tagName --jq .tagName)
first_line() { head -n 1 <<< "$1"; }
refusal=$(gh release upload "$tag" "$letter.bundle" --repo "$repo" 2>&1 > /dev/null) ||
  die "the upload to $tag was refused ($(first_line "$refusal")): not published"
refusal=$(gh release upload "$tag" "$letter" --repo "$repo" 2>&1 > /dev/null) || {
  gh release delete-asset "$tag" "$(basename "$letter.bundle")" --repo "$repo" --yes > /dev/null 2>&1 ||
    die "the upload of the letter to $tag was refused ($(first_line "$refusal")), and its bundle could not be removed"
  die "the upload of the letter to $tag was refused ($(first_line "$refusal")): not published"
}
