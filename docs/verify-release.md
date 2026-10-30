# Verify a FosterStack Cache release (v0.3.0 and later) <!-- pinned: historical -->

DRAFT. Every line marked TO-VERIFY has not been run against a real release.
For v0.2.x releases, use [Verify our images](verify-images.md).

You need cosign, gh and jq. The steps cover both images: production and -fips.
Set these once:

- `<IMAGE_REF>`: the production image by digest, as repository@sha256:digest. TO-VERIFY: where the release names it.
- `<IMAGE_REF_FIPS>`: the -fips image by digest, as repository@sha256:digest.
- `<TAG>`: the release tag, for example v0.3.0.
- `<RELEASE_KEY>`: the release public key file, from our key manifest after the manifest is checked against our root public key. TO-VERIFY: where the manifest and the root key are published, and the manifest check.

Without network access, add `--insecure-ignore-tlog` to each cosign command below: it checks our key alone and skips the public log entry. TO-VERIFY: offline.

## 1. Image signatures

Did our release key sign these exact images? TO-VERIFY: the flags.

```sh
# Not run before release: it needs the image in a registry.
cosign verify <IMAGE_REF> --key <RELEASE_KEY>
# Not run before release: it needs the image in a registry.
cosign verify <IMAGE_REF_FIPS> --key <RELEASE_KEY>
```

## 2. Provenance

Download the release files named below from the release page for `<TAG>`.

The provenance is a SLSA provenance statement (predicate type https://slsa.dev/provenance/v1) signed with the release key. TO-VERIFY: the flags against a real bundle.

```sh
# Not run before release.
cosign verify-blob-attestation --key <RELEASE_KEY> --bundle provenance.bundle.json \
  --type https://slsa.dev/provenance/v1 --check-claims=false
```

## 3. Digests

The provenance names each image by digest. The first command succeeds only if the subject named image-production is the production image you set; the second lists every image and digest, so you can compare the -fips digest with yours. TO-VERIFY: the field names against a real bundle.

```sh
# Not run before release.
jq -e --arg ref '<IMAGE_REF>' '.dsseEnvelope.payload | @base64d | fromjson | .predicateType == "https://slsa.dev/provenance/v1" and any(.subject[]; .name == "image-production" and (.digest.sha256 as $d | $ref | endswith("@sha256:" + $d)))' provenance.bundle.json
# Not run before release.
jq -r '.dsseEnvelope.payload | @base64d | fromjson | .subject[] | .name + " sha256:" + .digest.sha256' provenance.bundle.json
```

## 4. The SBOM and the inputs

Each SBOM lists what is in an image; each lock lists the packages the image was assembled from. TO-VERIFY: the flags against a real bundle, and the build's own inputs manifest, which is in Build's record and not a signed file of its own.

```sh
# Not run before release.
cosign verify-blob --key <RELEASE_KEY> --bundle production.sbom.json.bundle production.sbom.json
# Not run before release.
cosign verify-blob --key <RELEASE_KEY> --bundle fips.sbom.json.bundle fips.sbom.json
# Not run before release.
cosign verify-blob --key <RELEASE_KEY> --bundle production.full.lock.json.bundle production.full.lock.json
# Not run before release.
cosign verify-blob --key <RELEASE_KEY> --bundle fips.full.lock.json.bundle fips.full.lock.json
```

## What this shows, and what it does not

TO-VERIFY: the trust boundary, written once the chain has run end to end.

Witness records from the build stages are extra evidence anyone with Witness can check; they are outside the steps above.
