#!/usr/bin/env bash
# Release, fourth witnessed step (rules 53, 56, 63): signs with the release KMS key (handoff 0713), and with a Rekor entry, everything a customer verifies. The images are signed
# by digest in BOTH registries (a signature is a per-registry object). The SBOMs, the lock files, the dependency evidence, the release policy
# and the archives' checksums file are signed with a bundle each, kept in release-evidence/. The transparency log is never turned off: a bundle without a Rekor entry fails the
# step and names the file. The four release metadata files (the OpenVEX file, the CSAF file, the inspector-filters file and release-manifest.json) are made
# from Build's verified digest list and listed, with their hashes, in release-files.sha256, which is signed too. The Witness records of the earlier stages are extra evidence and are not signed again.
set -euo pipefail
for name in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GH_TOKEN RELEASE_KMS_KEY_REF; do
  if [ -z "${!name:-}" ]; then echo "release-sign: $name is unset" >&2; exit 2; fi
done
# the job pins the key's reference (awskms:///<name>); a KMS key's name form is not written in this script, because the script scan of the release chain refuses it
case "$RELEASE_KMS_KEY_REF" in awskms:///?*) ;; *) echo "release-sign: RELEASE_KMS_KEY_REF is not a KMS key reference" >&2; exit 1 ;; esac
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-sign: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
# REQ-CHAIN-007-AC21 (Astra R3): checksums.txt has no other producer. Before any evidence is made or anything is signed, the four archives in dist are bound to Build's digests.json
# and the file release-assets attaches and this step signs is written from them; an archive that is missing, extra or not Build's stops the step here
python3 bin/release-metadata.py checksums --version "${GITHUB_REF_NAME#v}" --digests witness-build/digests.json --dist dist --out dist/checksums.txt
repo="fosterstack/cache"
prod=$(jq -r '."image-production" // empty' witness-build/digests.json)
fips=$(jq -r '."image-fips" // empty' witness-build/digests.json)
# ruling G (cache-ce's interface): the dependency list is the tag checkout's own file, the govulncheck stream is Check's product (bound to its scanners record by
# release-verify), and the date is the admitted tag commit's committer date, never a clock; a file or a date that is not usable stops the step before anything is made
gv=check-results/govulncheck.json
[ -f "$gv" ] && [ ! -L "$gv" ] && [ -s "$gv" ] || { echo "release-sign: $gv (Check's govulncheck stream) is missing, empty or not a regular file" >&2; exit 1; }
[ -f dependency-provenance.json ] && [ ! -L dependency-provenance.json ] && [ -s dependency-provenance.json ] || { echo "release-sign: dependency-provenance.json of the tag's checkout is missing, empty or not a regular file" >&2; exit 1; }
date=$(git log -1 --format=%ct "$GITHUB_SHA")
[[ "$date" =~ ^[0-9]+$ ]] || { echo "release-sign: the commit date of $GITHUB_SHA is not epoch seconds: $date" >&2; exit 1; }
python3 bin/vendor-provenance.py evidence --out release-evidence --provenance dependency-provenance.json --govulncheck "$gv" --date "$date"
mkdir -p release-metadata
python3 bin/release-metadata.py images --digests witness-build/digests.json --images-dir images --items witness-build/items.json --out release-metadata/vex-images.json
cp .vex/fosterstack-cache.openvex.json release-metadata/
python3 bin/vex-forms.py --openvex .vex/fosterstack-cache.openvex.json --images release-metadata/vex-images.json --version "$GITHUB_REF_NAME" --out-dir release-metadata
# the baseline is the one admission chose (REQ-CHAIN-007-AC19): read from Build's verified admission-baseline.json (bound to Build's record by release-verify), so an
# owner-signed tag uses its own and a CI patch tag the line's owner baseline; Release never picks one itself
baseline=$(python3 bin/release-metadata.py baseline --admission witness-build/admission-baseline.json --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA")
python3 bin/release-metadata.py manifest --digests witness-build/digests.json --images-dir images --items witness-build/items.json --vex-dir release-metadata --baseline-version "$baseline" --repo-root . --version "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --ci-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" --workflow "$GITHUB_WORKFLOW_REF" --out release-metadata/release-manifest.json
python3 bin/release-metadata.py list --version "$GITHUB_REF_NAME" --dir release-metadata --out release-metadata/release-files.sha256
# The logins live in a private DOCKER_CONFIG of this step, removed when it ends (round 1 F2).
DOCKER_CONFIG=$(mktemp -d)
[ -n "$DOCKER_CONFIG" ] && [ -d "$DOCKER_CONFIG" ] || { echo "release-sign: no private credential directory: refusing to log in" >&2; exit 1; }
export DOCKER_CONFIG
trap 'rm -rf "$DOCKER_CONFIG"' EXIT
cosign login ghcr.io -u "${GITHUB_ACTOR:-fosterstack}" --password-stdin <<< "$GH_TOKEN"
cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin <<< "$DOCKERHUB_TOKEN"
for host in ghcr.io docker.io; do
  for digest in "$prod" "$fips"; do
    cosign sign --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json "$host/$repo@$digest"
  done
done
# the release manifest stays attached to each public digest as an OCI referrer, as on v0.2.x (REQ-CHAIN-007-AC8): GHCR is authoritative and required; the Docker Hub mirror
# is best-effort with a loud warning, never a silent skip (referrer support there varies). The predicate is the file release-files.sha256 lists and signs.
for digest in "$prod" "$fips"; do
  cosign attest --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --predicate release-metadata/release-manifest.json --type https://fosterstack.com/attestations/release-manifest/v1 "ghcr.io/$repo@$digest"
  cosign attest --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --predicate release-metadata/release-manifest.json --type https://fosterstack.com/attestations/release-manifest/v1 "docker.io/$repo@$digest" || echo "::warning::could not attach the manifest referrer on docker.io/$repo@$digest: the GHCR referrer is authoritative"
done
mkdir -p release-evidence
# the dependency list is signed and attached as dependency-list.json: a signing call that names provenance is read as a provenance signer, which only Sign may be
cp dependency-provenance.json release-evidence/dependency-list.json
has_rekor() {
  if ! jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$1" > /dev/null; then echo "release-sign: $1 has no Rekor entry: its signature cannot be checked in the public log" >&2; exit 1; fi
}
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/production.sbom.json.bundle images/production-sbom/sbom.json
has_rekor release-evidence/production.sbom.json.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/fips.sbom.json.bundle images/fips-sbom/sbom.json
has_rekor release-evidence/fips.sbom.json.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/production.full.lock.json.bundle images/production.full.lock.json
has_rekor release-evidence/production.full.lock.json.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/fips.full.lock.json.bundle images/fips.full.lock.json
has_rekor release-evidence/fips.full.lock.json.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/vendor-evidence.json.bundle release-evidence/vendor-evidence.json
has_rekor release-evidence/vendor-evidence.json.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/dependency-list.json.bundle release-evidence/dependency-list.json
has_rekor release-evidence/dependency-list.json.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/checksums.txt.bundle dist/checksums.txt
has_rekor release-evidence/checksums.txt.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/release-policy.bundle policy.json
has_rekor release-evidence/release-policy.bundle
cosign sign-blob --yes --key "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json --bundle release-evidence/release-files.sha256.bundle release-metadata/release-files.sha256
has_rekor release-evidence/release-files.sha256.bundle
