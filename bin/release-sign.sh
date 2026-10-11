#!/usr/bin/env bash
# Release, fourth witnessed step (rules 53, 56, 63): signs, keyless and with a Rekor entry, everything a customer verifies. The images are signed
# by digest in BOTH registries (a signature is a per-registry object). The SBOMs, the lock files, the dependency evidence, the release policy
# and the archives' checksums file are signed with a bundle each, kept in release-evidence/. The transparency log is never turned off: a bundle without a Rekor entry fails the
# step and names the file. The Witness records of the earlier stages are extra evidence and are not signed again.
set -euo pipefail
for name in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GH_TOKEN; do
  if [ -z "${!name:-}" ]; then echo "release-sign: $name is not set" >&2; exit 2; fi
done
repo="fosterstack/cache"
prod=$(jq -r '."image-production" // empty' witness-build/digests.json)
fips=$(jq -r '."image-fips" // empty' witness-build/digests.json)
python3 bin/vendor-provenance.py evidence --out release-evidence
cosign login ghcr.io -u "${GITHUB_ACTOR:-fosterstack}" --password-stdin <<< "$GH_TOKEN"
cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin <<< "$DOCKERHUB_TOKEN"
for host in ghcr.io docker.io; do
  for digest in "$prod" "$fips"; do
    cosign sign --yes --signing-config .github/policy/cosign-signing-config.json "$host/$repo@$digest"
  done
done
mkdir -p release-evidence
has_rekor() {
  if ! jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$1" > /dev/null; then echo "release-sign: $1 has no Rekor entry: its signature cannot be checked in the public log" >&2; exit 1; fi
}
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/production.spdx.json.bundle sboms/production.spdx.json
has_rekor release-evidence/production.spdx.json.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/fips.spdx.json.bundle sboms/fips.spdx.json
has_rekor release-evidence/fips.spdx.json.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/production.full.lock.json.bundle locks/production.full.lock.json
has_rekor release-evidence/production.full.lock.json.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/fips.full.lock.json.bundle locks/fips.full.lock.json
has_rekor release-evidence/fips.full.lock.json.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/vendor-evidence.json.bundle release-evidence/vendor-evidence.json
has_rekor release-evidence/vendor-evidence.json.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/dependency-provenance.json.bundle dependency-provenance.json
has_rekor release-evidence/dependency-provenance.json.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/checksums.txt.bundle dist/checksums.txt
has_rekor release-evidence/checksums.txt.bundle
cosign sign-blob --yes --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/release-policy.bundle policy.json
has_rekor release-evidence/release-policy.bundle
