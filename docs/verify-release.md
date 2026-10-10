# Verify a FosterStack Cache release (v0.3.0 and later) <!-- pinned: historical -->

DRAFT. Every line marked TO-VERIFY has not been run against a real release.
For v0.2.x releases, use [Verify our images](verify-images.md).

You need cosign, gh and jq. The steps cover both images: production and -fips.
Set these once:

- `<IMAGE_REF>`: the production image by digest, as repository@sha256:digest. TO-VERIFY: where the release names it.
- `<TAG>`: the release tag, for example v0.3.0.
- `<IDENTITY>`: https://github.com/fosterstack/cache/.github/workflows/stage-sign.yml@refs/tags/<TAG>, the workflow that signs the provenance.

## 1. Image signatures

Did our release workflow sign these exact images? TO-VERIFY: the signing workflow and the -fips image reference.

```sh
# Not run before release: it needs the image in a registry.
cosign verify <IMAGE_REF> \
  --certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/<TAG> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# Not run before release: it needs the image in a registry.
cosign verify ghcr.io/fosterstack/cache:<TAG>-fips \
  --certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/<TAG> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 2. Provenance

Download the release files named below from the release page for `<TAG>`. TO-VERIFY: the file names.

The provenance is a SLSA provenance statement (predicate type https://slsa.dev/provenance/v1) signed by `<IDENTITY>`, issuer https://token.actions.githubusercontent.com. TO-VERIFY: the flags against a real bundle.

```sh
cosign verify-blob-attestation --bundle provenance.sigstore.json --new-bundle-format \
  --type https://slsa.dev/provenance/v1 --check-claims=false \
  --certificate-identity <IDENTITY> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## 3. Digests

The provenance names each image by digest. The first command succeeds only if it names the production image you set; the second lists every image and digest, so you can compare the -fips digest with yours. TO-VERIFY: the field names against a real bundle.

```sh
jq -e --arg ref '<IMAGE_REF>' '.dsseEnvelope.payload | @base64d | fromjson | .predicateType == "https://slsa.dev/provenance/v1" and any(.subject[]; .digest.sha256 as $d | $ref | endswith("@sha256:" + $d))' provenance.sigstore.json
jq -r '.dsseEnvelope.payload | @base64d | fromjson | .subject[] | .name + " sha256:" + .digest.sha256' provenance.sigstore.json
```

## 4. The SBOM and the inputs

The SBOM lists what is in each image; the inputs record lists what the build used. TO-VERIFY: the file names, the signing workflow, and a jq check of the inputs.

```sh
cosign verify-blob --bundle sbom.spdx.json.sigstore.json --new-bundle-format \
  --certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/<TAG> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com sbom.spdx.json
cosign verify-blob --bundle inputs.json.sigstore.json --new-bundle-format \
  --certificate-identity https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/<TAG> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com inputs.json
```

## What this shows, and what it does not

TO-VERIFY: the trust boundary, written once the chain has run end to end.

Witness records from the build stages are extra evidence anyone with Witness can check; they are outside the steps above.
