#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): signs the letter keyless and attaches it, with its bundle, to the latest published release.
# The signing call, the signing config and the transparency-log check are those of bin/release-sign.sh. Before anything is uploaded the
# signature is verified against the identity customers use (docs/verify-release.md). The upload never overwrites, so a second run, or a
# repository whose releases are immutable, ends here with one plain line and publishes nothing. The bundle goes up first and the letter
# second; if the letter is refused, the bundle this run uploaded is removed again, so no half pair is left to block the month.
#   argument: the letter file (GH_TOKEN set; the job's identity token is what cosign uses; REPO defaults to fosterstack/cache)
set -euo pipefail
die() { echo "evidence-letter-publish: $*" >&2; exit 1; }
letter=${1:?the letter file is the first argument}
[ -f "$letter" ] && [ ! -L "$letter" ] || die "$letter is not a regular file"
repo=${REPO:-fosterstack/cache}
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle "$letter.bundle" "$letter"
jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$letter.bundle" > /dev/null ||
  die "$letter.bundle has no Rekor entry: the letter is not published"
cosign verify-blob --bundle "$letter.bundle" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/$repo/.github/workflows/evidence-letter.yml@refs/heads/main" "$letter" > /dev/null 2>&1 ||
  die "the signature does not verify under the identity in the verify guide (a run from another ref?): not published"
tag=$(gh release view --repo "$repo" --json tagName --jq .tagName)
first_line() { head -n 1 <<< "$1"; }
refusal=$(gh release upload "$tag" "$letter.bundle" --repo "$repo" 2>&1 > /dev/null) ||
  die "the upload to $tag was refused ($(first_line "$refusal")): not published"
refusal=$(gh release upload "$tag" "$letter" --repo "$repo" 2>&1 > /dev/null) || {
  gh release delete-asset "$tag" "$(basename "$letter.bundle")" --repo "$repo" --yes > /dev/null 2>&1 ||
    die "the upload of the letter to $tag was refused ($(first_line "$refusal")), and its bundle could not be removed"
  die "the upload of the letter to $tag was refused ($(first_line "$refusal")): not published"
}
