#!/usr/bin/env bash
# The monthly evidence letter (REQ-REL-013): signs the letter keyless and attaches it, with its bundle, to the latest published release.
# The signing call, the signing config and the transparency-log check are those of bin/release-sign.sh. The upload never overwrites, so a
# second run, or a repository whose releases are immutable, ends here with one plain line and publishes nothing.
#   evidence-letter-publish.sh LETTER.md      (GH_TOKEN set; the job's identity token is what cosign uses; REPO defaults to fosterstack/cache)
set -euo pipefail
letter=${1:?usage: evidence-letter-publish.sh LETTER.md}
[ -f "$letter" ] && [ ! -L "$letter" ] || { echo "evidence-letter-publish: $letter is not a regular file" >&2; exit 1; }
repo=${REPO:-fosterstack/cache}
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle "$letter.bundle" "$letter"
jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$letter.bundle" > /dev/null ||
  { echo "evidence-letter-publish: $letter.bundle has no Rekor entry: the letter is not published" >&2; exit 1; }
tag=$(gh release view --repo "$repo" --json tagName --jq .tagName)
gh release upload "$tag" "$letter" "$letter.bundle" --repo "$repo" ||
  { echo "evidence-letter-publish: the upload to $tag was refused (a release that cannot take new files, or the letter is already there): not published" >&2; exit 1; }
