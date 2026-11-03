#!/usr/bin/env bash
# Release, fourth witnessed step (rules 53, 56, 63): signs with the release KMS key (handoff 0713), and with a Rekor entry, everything a customer verifies. The images are signed
# by digest in BOTH registries (a signature is a per-registry object). The SBOMs, the lock files, the dependency evidence, the release policy
# and the archives' checksums file are signed with a bundle each, kept in release-evidence/. The transparency log is never turned off: a bundle without a Rekor entry fails the
# step and names the file. The four release metadata files (the OpenVEX file, the CSAF file, the inspector-filters file and release-manifest.json) are made
# from Build's verified digest list and listed, with their hashes, in release-files.sha256, which is signed too. The Witness records of the earlier stages are extra evidence and are not signed again.
set -euo pipefail
for name in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GH_TOKEN RELEASE_KMS_KEY_REF RUNNER_TEMP; do
  if [ -z "${!name:-}" ]; then echo "release-sign: $name is unset" >&2; exit 2; fi
done
# RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE come from the Witness wrapper (what Witness records must hold no AWS name); the AWS SDK reads the same values as AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE, exported on the last line below
case "${RELEASE_ROLE_ARN:-}" in ?*) ;; *) echo "release-sign: RELEASE_ROLE_ARN is unset" >&2; exit 2;; esac
case "${RELEASE_TOKEN_FILE:-}" in ?*) ;; *) echo "release-sign: RELEASE_TOKEN_FILE is unset" >&2; exit 2;; esac
export AWS_ROLE_ARN="$RELEASE_ROLE_ARN" AWS_WEB_IDENTITY_TOKEN_FILE="$RELEASE_TOKEN_FILE"
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-sign: tag refused: ${GITHUB_REF_NAME:-} is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
# the one key-reference check (bin/chain-verify.py key-ref-check): the job's reference is the release key's, byte for byte, and the key lists RSASSA_PKCS1_V1_5_SHA_256 (the KA-0 guard; kms-sign asserts it again on every signing call);
# exit 2 before anything is made or signed (the tag check above runs no tool).
python3 -I -B bin/chain-verify.py key-ref-check --algorithm-guard || exit $?
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
# KA-2: nothing here is signed by cosign: a file or an image is signed by bin/chain-verify.py kms-sign, never by cosign: RSASSA_PKCS1_V1_5_SHA_256 is named on the KMS call, the key must list it, and the same call posts the one Rekor entry
# and writes the v0.3 bundle (<bundle>). Blob kinds: the digest is the sha256 of the file's own bytes and each call has its own signature file (kms-sign never overwrites). Image kinds (the image signature and the manifest
# referrer): a local in-toto statement (subject = the image digest, fields in protojson order) is signed as a DSSE envelope (kms-sign --dsse-statement) and the bundle is attached to the image with cosign attach attestation
# (a referrer; cosign makes no signature). A refusal of kms-sign ends the step.
ksd=$(mktemp -d)
[ -n "$ksd" ] && [ -d "$ksd" ] || { echo "release-sign: no private directory for the signature files: refusing to sign" >&2; exit 1; }
trap 'rm -rf "$DOCKER_CONFIG" "$ksd"' EXIT
ks_n=0
kms_blob() {
  local dg _
  read -r dg _ < <(sha256sum "$2") && [ -n "$dg" ] || { echo "release-sign: cannot hash $2" >&2; exit 1; }
  ks_n=$((ks_n + 1))
  python3 -I -B bin/chain-verify.py kms-sign --aws "$RUNNER_TEMP/aws-cli/aws" --key-ref "$RELEASE_KMS_KEY_REF" --digest "$dg" --signing-config .github/policy/cosign-signing-config.json \
    --public-key build/keys/release.rsa.pub --out "$ksd/signature.$ks_n" --bundle "$1" || { echo "release-sign: kms-sign refused to sign $2" >&2; exit 1; }
}
has_rekor() {
  if ! jq -e '(.verificationMaterial.tlogEntries // []) | length > 0' "$1" > /dev/null; then echo "release-sign: $1 has no Rekor entry: its signature cannot be checked in the public log" >&2; exit 1; fi
}
kms_image() { # <sign|attest> <image name> <sha256:digest>: the statement, its DSSE bundle (kms-sign) and the referrer (cosign attach attestation); the attach is the only step that may fail without ending the step (the caller decides)
  local kind=$1 name=$2 dg=$3 stmt bundle
  ks_n=$((ks_n + 1)); stmt="$ksd/statement.$ks_n"; bundle="$ksd/image.$ks_n.bundle"
  case "$kind" in
    sign) jq -cn --arg n "$name" --arg d "${dg#sha256:}" '{_type: "https://in-toto.io/Statement/v1", subject: [{name: $n, digest: {sha256: $d}}], predicateType: "https://sigstore.dev/cosign/sign/v1", predicate: {}}' > "$stmt" || { echo "release-sign: cannot build the signature statement of $name@$dg" >&2; exit 1; } ;;
    attest) jq -cn --arg n "$name" --arg d "${dg#sha256:}" --slurpfile p release-metadata/release-manifest.json '{_type: "https://in-toto.io/Statement/v1", subject: [{name: $n, digest: {sha256: $d}}], predicateType: "https://fosterstack.com/attestations/release-manifest/v1", predicate: $p[0]}' > "$stmt" || { echo "release-sign: cannot build the manifest statement of $name@$dg" >&2; exit 1; } ;;
    *) echo "release-sign: kms_image: unknown kind $kind" >&2; exit 1 ;;
  esac
  python3 -I -B bin/chain-verify.py kms-sign --aws "$RUNNER_TEMP/aws-cli/aws" --key-ref "$RELEASE_KMS_KEY_REF" --signing-config .github/policy/cosign-signing-config.json \
    --public-key build/keys/release.rsa.pub --dsse-statement "$stmt" --bundle "$bundle" || { echo "release-sign: kms-sign refused to sign the $kind statement of $name@$dg" >&2; exit 1; }
  has_rekor "$bundle"
  cosign attach attestation --attestation "$bundle" "$name@$dg"
}
cosign login ghcr.io -u "${GITHUB_ACTOR:-fosterstack}" --password-stdin <<< "$GH_TOKEN"
cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin <<< "$DOCKERHUB_TOKEN"
for host in ghcr.io docker.io; do
  for digest in "$prod" "$fips"; do
    kms_image sign "$host/$repo" "$digest"
  done
done
# the release manifest stays attached to each public digest as an OCI referrer, as on v0.2.x (REQ-CHAIN-007-AC8): GHCR is authoritative and required; the Docker Hub mirror
# is best-effort with a loud warning, never a silent skip (referrer support there varies). The predicate is the file release-files.sha256 lists and signs.
for digest in "$prod" "$fips"; do
  kms_image attest "ghcr.io/$repo" "$digest"
  kms_image attest "docker.io/$repo" "$digest" || echo "::warning::could not attach the manifest referrer on docker.io/$repo@$digest: the GHCR referrer is authoritative"
done
mkdir -p release-evidence
# the dependency list is signed and attached as dependency-list.json: a signing call that names provenance is read as a provenance signer, which only Sign may be
cp dependency-provenance.json release-evidence/dependency-list.json
kms_blob release-evidence/production.sbom.json.bundle images/production-sbom/sbom.json
has_rekor release-evidence/production.sbom.json.bundle
kms_blob release-evidence/fips.sbom.json.bundle images/fips-sbom/sbom.json
has_rekor release-evidence/fips.sbom.json.bundle
kms_blob release-evidence/production.full.lock.json.bundle images/production.full.lock.json
has_rekor release-evidence/production.full.lock.json.bundle
kms_blob release-evidence/fips.full.lock.json.bundle images/fips.full.lock.json
has_rekor release-evidence/fips.full.lock.json.bundle
kms_blob release-evidence/vendor-evidence.json.bundle release-evidence/vendor-evidence.json
has_rekor release-evidence/vendor-evidence.json.bundle
kms_blob release-evidence/dependency-list.json.bundle release-evidence/dependency-list.json
has_rekor release-evidence/dependency-list.json.bundle
kms_blob release-evidence/checksums.txt.bundle dist/checksums.txt
has_rekor release-evidence/checksums.txt.bundle
kms_blob release-evidence/release-policy.bundle policy.json
has_rekor release-evidence/release-policy.bundle
kms_blob release-evidence/release-files.sha256.bundle release-metadata/release-files.sha256
has_rekor release-evidence/release-files.sha256.bundle
