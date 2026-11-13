#!/usr/bin/env bash
# Sign job, release signatures (rules 53, 56, 63; docs/ratify/2026-10-28-kms-signing-key-and-one-step-build.md:22, :24, :27): the Sign job alone reaches the release KMS key, and nothing is published
# before it. This step makes, from Build's verified outputs, everything a customer verifies, and signs it with the release key: one detached KMS signature, with its own Rekor entry made here, over each
# image payload, each release manifest attestation, each blob and each apk's control stream. Every signature comes from bin/chain-verify.py kms-sign (the algorithm named on the call, one Rekor entry
# posted, retried while Rekor is down, a bundle written), run through bin/with-aws-token.sh, one fresh identity token per call. The Release job holds no key: it checks these files against
# build/keys/release.rsa.pub and pushes them (its own signing steps).
# The blobs are made here, once: the four archives' checksums file, the vendor evidence, the dependency list, the four release metadata files (made from Build's verified digest list) and the list that pins
# them, release-files.sha256. Release ships exactly these bytes and the SBOMs, lock files and policy it received from Build.
# Output, release-signed/ (it is the artifact Release downloads):
#   checksums.txt, release-evidence/*, release-metadata/*          the blobs this step made, each with its <file>.bundle (the SBOMs, lock files and policy only the bundle)
#   images/<host>/<variant>.payload, .bundle                       the simple-signing payload of the image digest and the bundle of its signature
#   images/<host>/<variant>.attestation.bundle                     the release manifest attestation (a DSSE bundle) of the image digest
#   apks/<arch>/<apk>.kms.sig, <apk>.bundle                        the signature of each apk's control stream
# Exit codes: 0 all signed | 1 a signing step or an input check failed | 2 refused: an unset name.
set -euo pipefail
for name in RELEASE_KMS_KEY_REF RUNNER_TEMP GITHUB_SHA GITHUB_SERVER_URL GITHUB_REPOSITORY GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_WORKFLOW_REF; do
  printenv "$name" > /dev/null || { echo "release-signatures: $name is unset" >&2; exit 2; }
done
tag=${GITHUB_REF_NAME:-}
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release-signatures: tag refused: $tag is not vX.Y.Z (a release candidate never reaches this step)" >&2; exit 1; }
# the one key-reference check (bin/chain-verify.py key-ref-check): the job's reference is the release key's, byte for byte; exit 2 before anything is made or signed. kms-sign asks the key for its algorithm on every call.
python3 -I -B bin/chain-verify.py key-ref-check || exit $?
# the release policy of this tag, made as release-verify makes it for Release: it is signed below, and Release checks the bundle against its own copy
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json
repo="fosterstack/cache"
cfg=.github/policy/cosign-signing-config.json
pub=build/keys/release.rsa.pub
out=release-signed
rm -rf "$out"
mkdir -p "$out/release-evidence" "$out/release-metadata" "$out/images" "$out/apks"
scratch=$(mktemp -d)
[ -n "$scratch" ] && [ -d "$scratch" ] || { echo "release-signatures: no scratch directory" >&2; exit 1; }
trap 'rm -rf "$scratch"' EXIT
n=0
# sign_file FILE BUNDLE: the detached signature over the file's sha256, with its Rekor entry, as a bundle
sign_file() {
  local dg
  read -r dg _ < <(sha256sum "$1")
  n=$((n + 1))
  bash bin/with-aws-token.sh kms-sign --aws "$RUNNER_TEMP/aws-cli/aws" --key-ref "$RELEASE_KMS_KEY_REF" --signing-config "$cfg" --public-key "$pub" --digest "$dg" --out "$scratch/$n.sig" --bundle "$2"
}
# REQ-CHAIN-007-AC21 (Astra R3): checksums.txt has no other producer. Before any evidence is made or anything is signed, the four archives in dist are bound to Build's digests.json
python3 -I -B bin/release-metadata.py checksums --version "${GITHUB_REF_NAME#v}" --digests witness-build/digests.json --dist dist --out "$out/checksums.txt"
prod=$(jq -r '."image-production" // empty' witness-build/digests.json)
fips=$(jq -r '."image-fips" // empty' witness-build/digests.json)
rx='^sha256:[0-9a-f]{64}$'
[[ "$prod" =~ $rx ]] && [[ "$fips" =~ $rx ]] || { echo "release-signatures: an attested image digest is missing or malformed" >&2; exit 1; }
# ruling G (cache-ce's interface): the dependency list is the tag checkout's own file, the govulncheck stream is Check's product, and the date is the admitted tag commit's committer date, never a clock
gv=check-results/govulncheck.json
[ -f "$gv" ] && [ ! -L "$gv" ] && [ -s "$gv" ] || { echo "release-signatures: $gv (Check's govulncheck stream) is missing, empty or not a regular file" >&2; exit 1; }
[ -f dependency-provenance.json ] && [ ! -L dependency-provenance.json ] && [ -s dependency-provenance.json ] || { echo "release-signatures: dependency-provenance.json of the tag's checkout is missing, empty or not a regular file" >&2; exit 1; }
date=$(git log -1 --format=%ct "$GITHUB_SHA")
[[ "$date" =~ ^[0-9]+$ ]] || { echo "release-signatures: the commit date of $GITHUB_SHA is not epoch seconds: $date" >&2; exit 1; }
python3 -I -B bin/vendor-provenance.py evidence --out "$out/release-evidence" --provenance dependency-provenance.json --govulncheck "$gv" --date "$date"
# the dependency list is signed and shipped as dependency-list.json: a signing call that names provenance is read as a provenance signer, which only Sign may be
cp dependency-provenance.json "$out/release-evidence/dependency-list.json"
python3 -I -B bin/release-metadata.py images --digests witness-build/digests.json --images-dir images --items witness-build/items.json --out "$out/release-metadata/vex-images.json"
cp .vex/fosterstack-cache.openvex.json "$out/release-metadata/"
python3 -I -B bin/vex-forms.py --openvex .vex/fosterstack-cache.openvex.json --images "$out/release-metadata/vex-images.json" --version "$GITHUB_REF_NAME" --out-dir "$out/release-metadata"
# the baseline is the one admission chose (REQ-CHAIN-007-AC19), read from Build's verified admission-baseline.json
baseline=$(python3 -I -B bin/release-metadata.py baseline --admission witness-build/admission-baseline.json --tag "$GITHUB_REF_NAME" --commit "$GITHUB_SHA")
python3 -I -B bin/release-metadata.py manifest --digests witness-build/digests.json --images-dir images --items witness-build/items.json --modules-dir apks/ubuntu-24.04 --vex-dir "$out/release-metadata" --baseline-version "$baseline" --repo-root . --version "$GITHUB_REF_NAME" --commit "$GITHUB_SHA" --ci-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT" --workflow "$GITHUB_WORKFLOW_REF" --out "$out/release-metadata/release-manifest.json"
python3 -I -B bin/release-metadata.py list --version "$GITHUB_REF_NAME" --dir "$out/release-metadata" --out "$out/release-metadata/release-files.sha256"
# the images: for each registry and variant, the payload of the digest and its signature; the release manifest stays attached to each digest as an in-toto attestation (REQ-CHAIN-007-AC8)
for host in ghcr.io docker.io; do
  mkdir -p "$out/images/$host"
  for pair in "production:$prod" "fips:$fips"; do
    v="${pair%%:*}"; d="${pair#*:}"
    jq -cj -n --arg ref "$host/$repo" --arg d "$d" '{critical: {identity: {"docker-reference": $ref}, image: {"docker-manifest-digest": $d}, type: "cosign container image signature"}, optional: null}' > "$out/images/$host/$v.payload"
    sign_file "$out/images/$host/$v.payload" "$out/images/$host/$v.bundle"
    jq -cj -n --arg ref "$host/$repo" --arg d "${d#sha256:}" --slurpfile m "$out/release-metadata/release-manifest.json" '{_type: "https://in-toto.io/Statement/v0.1", predicateType: "https://fosterstack.com/attestations/release-manifest/v1", subject: [{name: $ref, digest: {sha256: $d}}], predicate: $m[0]}' > "$scratch/$host-$v.statement"
    n=$((n + 1))
    bash bin/with-aws-token.sh kms-sign --aws "$RUNNER_TEMP/aws-cli/aws" --key-ref "$RELEASE_KMS_KEY_REF" --signing-config "$cfg" --public-key "$pub" --dsse-statement "$scratch/$host-$v.statement" --bundle "$out/images/$host/$v.attestation.bundle"
  done
done
# the blobs: the SBOMs, lock files and policy are Build's and stay where Release has them; the rest were made above. Each gets its bundle beside it under the name the customer fetches
sign_file images/production-sbom/sbom.json "$out/release-evidence/production.sbom.json.bundle"
sign_file images/fips-sbom/sbom.json "$out/release-evidence/fips.sbom.json.bundle"
sign_file apks/ubuntu-24.04/fscache-modules.spdx.json "$out/release-evidence/fscache-modules.spdx.json.bundle"
sign_file apks/ubuntu-24.04/fscache-modules-fips.spdx.json "$out/release-evidence/fscache-modules-fips.spdx.json.bundle"
sign_file images/production.full.lock.json "$out/release-evidence/production.full.lock.json.bundle"
sign_file images/fips.full.lock.json "$out/release-evidence/fips.full.lock.json.bundle"
sign_file policy.json "$out/release-evidence/release-policy.bundle"
for f in vendor-evidence.json dependency-list.json; do sign_file "$out/release-evidence/$f" "$out/release-evidence/$f.bundle"; done
sign_file "$out/checksums.txt" "$out/checksums.txt.bundle"
sign_file "$out/release-metadata/release-files.sha256" "$out/release-metadata/release-files.sha256.bundle"
# the apks: the sha256 of each control stream, as the apk tool puts it in front of the unchanged streams. An apk that is not one Build attested is not signed.
for f in apks/ubuntu-24.04/x86_64/*.apk apks/ubuntu-24.04-arm/aarch64/*.apk; do
  [ -f "$f" ] && [ ! -L "$f" ] || { echo "release-signatures: $f is not a regular file" >&2; exit 1; }
  got=$(python3 -I -B bin/apk-tool.py digest "$f")
  jq -e --arg d "$got" '[to_entries[] | select(.key | startswith("apk-")) | .value] | index($d) != null' witness-build/digests.json > /dev/null || { echo "release-signatures: $f ($got) is not an apk Build attested" >&2; exit 1; }
  arch=$(basename "$(dirname "$f")")
  mkdir -p "$out/apks/$arch"
  python3 -I -B bin/apk-tool.py control "$f" "$scratch/control.gz"
  read -r dg _ < <(sha256sum "$scratch/control.gz")
  bash bin/with-aws-token.sh kms-sign --aws "$RUNNER_TEMP/aws-cli/aws" --key-ref "$RELEASE_KMS_KEY_REF" --signing-config "$cfg" --public-key "$pub" --digest "$dg" --out "$out/apks/$arch/$(basename "$f").kms.sig" --bundle "$out/apks/$arch/$(basename "$f").bundle"
done
