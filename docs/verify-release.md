# Verify a FosterStack Cache release (v0.3.0 and later) <!-- pinned: historical -->

DRAFT. Every line marked TO-VERIFY has not been run against a real release.
For v0.2.x releases, use [Verify our images](verify-images.md).
Every image and file of a v0.3.0 and later release is signed with the release key; each step below checks it with the release public key and a Rekor entry, not with a workflow identity. <!-- pinned: historical -->

You need cosign and jq. The steps cover both images: production and -fips.
Set these once:

- `<IMAGE_REF>`: the production image by digest, as repository@sha256:digest. The digest is `image-production` in `digests.json` on the release page.
- `<IMAGE_REF_FIPS>`: the -fips image by digest. The digest is `image-fips` in the same file.
- `<TAG>`: the release tag, for example v0.3.0.
- `release.rsa.pub`: the release public key. Fetch it once: `curl -fsSLO https://raw.githubusercontent.com/fosterstack/cache/<TAG>/build/keys/release.rsa.pub`.

## 1. Image signatures

Are these exact images signed with the release key? TO-VERIFY: these commands have not been run against a real release.

```sh
# Not run before release: it needs the image in a registry.
cosign verify --key release.rsa.pub <IMAGE_REF>
# Not run before release: it needs the image in a registry.
cosign verify --key release.rsa.pub <IMAGE_REF_FIPS>
```

## 2. Provenance

Download the release files named below from the release page for `<TAG>`.

The provenance says how the images were built, and is signed with the release key. TO-VERIFY: the flags against a real bundle.

```sh
# Not run before release.
cosign verify-blob-attestation --key release.rsa.pub --bundle provenance.bundle.json \
  --type https://slsa.dev/provenance/v1 --check-claims=false
```

## 3. Digests

The provenance names each image by digest. The first command succeeds only if it names your production image; the second lists every digest, to compare with yours. TO-VERIFY: the field names against a real bundle.

```sh
# Not run before release.
jq -e --arg ref '<IMAGE_REF>' '.dsseEnvelope.payload | @base64d | fromjson | .predicateType == "https://slsa.dev/provenance/v1" and any(.subject[]; .name == "image-production" and (.digest.sha256 as $d | $ref | endswith("@sha256:" + $d)))' provenance.bundle.json
# Not run before release.
jq -r '.dsseEnvelope.payload | @base64d | fromjson | (.subject[], .predicate.runDetails.byproducts[]) | .name + " sha256:" + .digest.sha256' provenance.bundle.json
```

## 4. The SBOM and the inputs

Each SBOM lists what is in an image; each lock lists the packages it was assembled from. TO-VERIFY: the flags against a real bundle.

```sh
# Not run before release.
cosign verify-blob --key release.rsa.pub --bundle production.sbom.json.bundle production.sbom.json
# Not run before release.
cosign verify-blob --key release.rsa.pub --bundle fips.sbom.json.bundle fips.sbom.json
# Not run before release.
cosign verify-blob --key release.rsa.pub --bundle production.full.lock.json.bundle production.full.lock.json
# Not run before release.
cosign verify-blob --key release.rsa.pub --bundle fips.full.lock.json.bundle fips.full.lock.json
```

## What this shows, and what it does not

TO-VERIFY: what these steps prove and do not prove, written after a real release.

To check a file with no network access, add --insecure-ignore-tlog to a cosign verify-blob command; this skips the Rekor entry. TO-VERIFY: not yet run.

Witness records are signed with the same key; they are extra evidence, outside these steps.
