#!/usr/bin/env bash
# Release, fourth witnessed step (rules 53, 56, 63): pushes Sign's signatures and holds no key (docs/ratify/2026-10-28-kms-signing-key-and-one-step-build.md:24). Sign made them, each with its Rekor entry, and
# shipped them in release-signed/ (the Sign job's signing step). Every file is checked first by bin/release-sign-verify.sh (release-publish runs it before its login too) against build/keys/release.rsa.pub and its bundle's one Rekor entry
# (bin/chain-verify.py bundle-check, offline: the entry travels in the bundle) before it is used; a signature with no entry, or with an entry that is not this signature's, stops the step and names the file, so nothing is pushed without a log entry. The images' signatures are attached by digest in BOTH
# registries (a signature is a per-registry object): the payload and signature Sign made, with the Rekor entry as the bundle of the signature object. The release manifest stays attached to each public digest as an OCI referrer, as on v0.2.x
# (REQ-CHAIN-007-AC8): GHCR is authoritative and required; the Docker Hub mirror is best-effort with a loud warning. The blobs and their bundles are placed where release-stage reads them: release-evidence/, release-metadata/ and dist/checksums.txt.
# The Witness records of the earlier stages are extra evidence and are not signed again.
set -euo pipefail
for name in DOCKERHUB_USERNAME DOCKERHUB_TOKEN GH_TOKEN; do
  printenv "$name" > /dev/null || { echo "release-sign: $name is unset" >&2; exit 2; }
done
repo="fosterstack/cache"
pub=build/keys/release.rsa.pub
signed=release-signed
bash bin/release-sign-verify.sh
prod=$(jq -r '."image-production" // empty' witness-build/digests.json)
fips=$(jq -r '."image-fips" // empty' witness-build/digests.json)
scratch=$(mktemp -d)
[ -n "$scratch" ] && [ -d "$scratch" ] || { echo "release-sign: no scratch directory" >&2; exit 1; }
trap 'rm -rf "$scratch"' EXIT
# the blobs Sign made, which release-sign-verify.sh has checked: placed where release-stage reads them
mkdir -p release-evidence release-metadata
for f in "$signed"/release-evidence/*.json; do
  cp "$f" "$f.bundle" release-evidence/
done
cp "$signed/checksums.txt" dist/checksums.txt
cp "$signed/checksums.txt.bundle" release-evidence/checksums.txt.bundle
for f in "$signed"/release-metadata/*.json "$signed"/release-metadata/release-files.sha256; do cp "$f" release-metadata/; done
cp "$signed/release-metadata/release-files.sha256.bundle" release-evidence/release-files.sha256.bundle
for b in production.sbom.json fips.sbom.json fscache-modules.spdx.json fscache-modules-fips.spdx.json production.full.lock.json fips.full.lock.json; do cp "$signed/release-evidence/$b.bundle" release-evidence/; done
cp "$signed/release-evidence/release-policy.bundle" release-evidence/
# The logins live in a private DOCKER_CONFIG of this step, removed when it ends (round 1 F2).
DOCKER_CONFIG=$(mktemp -d)
[ -n "$DOCKER_CONFIG" ] && [ -d "$DOCKER_CONFIG" ] || { echo "release-sign: no private credential directory: refusing to log in" >&2; exit 1; }
export DOCKER_CONFIG
trap 'rm -rf "$DOCKER_CONFIG" "$scratch"' EXIT
cosign login ghcr.io -u "${GITHUB_ACTOR:-fosterstack}" --password-stdin <<< "$GH_TOKEN"
cosign login docker.io -u "$DOCKERHUB_USERNAME" --password-stdin <<< "$DOCKERHUB_TOKEN"
for host in ghcr.io docker.io; do
  for pair in "production:$prod" "fips:$fips"; do
    v="${pair%%:*}"; d="${pair#*:}"; ref="$host/$repo@$d"
    p="$signed/images/$host/$v.payload"; b="$signed/images/$host/$v.bundle"
    # cosign's signature object: the payload, the signature (base64) and the log entry in the form cosign reads (--rekor-response)
    jq -er .messageSignature.signature "$b" > "$scratch/image.sig"
    logid=$(jq -er '.verificationMaterial.tlogEntries[0].logId.keyId' "$b" | base64 -d | od -An -tx1 | tr -d ' \n')
    jq -ce --arg logid "$logid" '.verificationMaterial.tlogEntries[0] as $e | {base64Signature: .messageSignature.signature, rekorBundle: {SignedEntryTimestamp: $e.inclusionPromise.signedEntryTimestamp, Payload: {body: $e.canonicalizedBody, integratedTime: ($e.integratedTime | tonumber), logIndex: ($e.logIndex | tonumber), logID: $logid}}}' "$b" > "$scratch/rekor.json"
    cosign attach signature --payload "$p" --signature "$scratch/image.sig" --rekor-response "$scratch/rekor.json" "$ref"
    cosign verify --key "$pub" "$ref" > /dev/null || { echo "release-sign: cosign verify --key does not pass on the signature attached to $ref" >&2; exit 1; }
  done
done
# cosign attach cannot write a Sigstore bundle (pinned cosign 3.1.3: "invalid payloadType"), so the bundle, with its Rekor entry, is the
# one layer of an OCI referrer manifest in a layout, and crane push keeps the manifest's subject.
# write_referrer_layout BUNDLE SUBJECT-MANIFEST-FILE DIGEST DIR
write_referrer_layout() {
  local bundle=$1 subject=$2 digest=$3 dir=$4 type blobs layer manifest
  local empty=44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a # sha256 of {}, the config
  type=$(jq -r .mediaType "$bundle")
  blobs="$dir/blobs/sha256"
  mkdir -p "$blobs"
  layer=$(sha256sum "$bundle" | cut -d ' ' -f 1)
  cp "$bundle" "$blobs/$layer"
  printf '{}' > "$blobs/$empty"
  jq -cnj --arg type "$type" --arg layer "$layer" --argjson layer_size "$(wc -c < "$bundle")" --arg digest "$digest" --arg empty "sha256:$empty" \
    --slurpfile subject "$subject" --argjson subject_size "$(wc -c < "$subject")" \
    '{schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json", artifactType: $type, config: {mediaType: "application/vnd.oci.empty.v1+json", digest: $empty, size: 2}, layers: [{mediaType: $type, digest: ("sha256:" + $layer), size: $layer_size}], subject: {mediaType: $subject[0].mediaType, digest: $digest, size: $subject_size}}' > "$dir/manifest.json"
  manifest=$(sha256sum "$dir/manifest.json" | cut -d ' ' -f 1)
  mv "$dir/manifest.json" "$blobs/$manifest"
  printf '{"imageLayoutVersion":"1.0.0"}' > "$dir/oci-layout"
  jq -cn --arg manifest "$manifest" --argjson size "$(wc -c < "$blobs/$manifest")" \
    '{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: ("sha256:" + $manifest), size: $size}]}' > "$dir/index.json"
}
# the guide's own check, so a bundle without its Rekor entry is never left on a public digest unnoticed
# attach_manifest LAYOUT REF@DIGEST
attach_manifest() {
  crane push "$1" "${2%@*}@$(jq -r '.manifests[0].digest' "$1/index.json")" &&
    cosign verify-attestation --key "$pub" --type https://fosterstack.com/attestations/release-manifest/v1 "$2" > /dev/null
}
# the release manifest, attached to each public digest: the attestation Sign made (a bundle with its Rekor entry)
for host in ghcr.io docker.io; do
  for pair in "production:$prod" "fips:$fips"; do
    v="${pair%%:*}"; d="${pair#*:}"; ref="$host/$repo@$d"
    att="$signed/images/$host/$v.attestation.bundle"
    jq -e --arg d "${d#sha256:}" --slurpfile m release-metadata/release-manifest.json '(.dsseEnvelope.payload | @base64d | fromjson) as $s | $s.subject[0].digest.sha256 == $d and $s.predicate == $m[0]' "$att" > /dev/null || { echo "release-sign: $att is not the attestation of release-manifest.json for $ref" >&2; exit 1; }
    crane manifest "$ref" > "$scratch/$host-$v.subject"
    write_referrer_layout "$att" "$scratch/$host-$v.subject" "$d" "$scratch/$host-$v.layout"
    if [ "$host" = ghcr.io ]; then
      attach_manifest "$scratch/$host-$v.layout" "$ref" ||
        { echo "release-sign: the manifest referrer on $ref does not verify" >&2; exit 1; }
    else
      attach_manifest "$scratch/$host-$v.layout" "$ref" ||
        echo "::warning::could not attach the manifest referrer on $ref: the GHCR referrer is authoritative"
    fi
  done
done
