# Verify our images

Every FosterStack Cache release is signed and provenance-attested by
GitHub's own CI — not by us claiming it, by a chain you can check yourself
in under a minute, with nothing installed but `cosign` and `gh`.

This isn't a hypothetical example. Every command below was run for real
against `v0.1.0`, on the maintainer's own laptop, with zero GitHub
credentials configured, and succeeded.

## 1. Verify the cosign signature and SLSA provenance

```sh
cosign verify ghcr.io/fosterstack/cache:0.1.0 \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

Expected output includes two claim types on the same image digest:

```
[
  { "critical": { ... }, "optional": {}, ... "type": "https://sigstore.dev/cosign/sign/v1" },
  { "critical": { ... }, "optional": {}, ... "type": "https://slsa.dev/provenance/v1" }
]
```

There is no signing key to leak, steal, or rotate — the certificate is
short-lived, minted by Sigstore's Fulcio from a GitHub Actions OIDC token
at the moment the release workflow ran, and the signature's existence is
recorded in the public Rekor transparency log.

## 2. Verify with GitHub's own attestation store

```sh
gh attestation verify oci://ghcr.io/fosterstack/cache:0.1.0 --owner fosterstack
```

This is the more direct proof for most people: it names the exact
workflow run that produced the image you pulled.

```
✓ Verification succeeded!
- Build repo:..... fosterstack/cache
- Build workflow:. .github/workflows/release.yml@refs/tags/v0.1.0
- Signer repo:.... fosterstack/cache
- Signer workflow: .github/workflows/release.yml@refs/tags/v0.1.0
```

`Build workflow` is the whole point of this page: it's cryptographic
confirmation that the bytes you pulled came out of this repository's own
public CI pipeline — [`.github/workflows/release.yml`](../.github/workflows/release.yml),
readable in full — not from anywhere else, and not hand-pushed by a
developer machine (see [`RELEASING.md`](../RELEASING.md)'s "releases build
only in CI" rule).

## 3. Which tags to verify

| Tag | What it is |
|---|---|
| `X.Y.Z` | Production image, `gcr.io/distroless/static:nonroot` base |
| `X.Y.Z-debug` | Same binary, busybox-bearing base — interactive troubleshooting only |
| `X.Y.Z-fips` | Same binary, `GOFIPS140=v1.0.0` build (Go's CMVP FIPS 140-3 validated module) |
| `latest` / `debug` / `fips` | Floating tags, always point at the newest release of that variant |

All three variants of every release are signed and attested the same way.

## 4. Verify the binary archives

Container images aren't the only artifact. Bare-binary releases (for
container-averse or air-gapped environments — see
["Installing on disconnected networks"](offline-install.md)) ship a
`checksums.txt` covering every archive, plus a cosign keyless blob-signature
bundle over that file:

```sh
# Download checksums.txt and checksums.txt.bundle from the release page, then:
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum -c checksums.txt   # verifies every archive you downloaded, transitively
```

## 5. Enforcing this in your own cluster (Kyverno)

For customers who want to *require* this at admission time rather than
verify manually, a starting Kyverno policy — restrict a namespace to only
admit images signed by this repository's own release workflow:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-fosterstack-cache-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "ghcr.io/fosterstack/cache:*"
          attestors:
            - entries:
                - keyless:
                    subjectRegExp: "^https://github.com/fosterstack/cache/"
                    issuer: "https://token.actions.githubusercontent.com"
```

Adjust `subjectRegExp` if you pin to a specific workflow ref rather than
any ref in this repo. This is a starting point, not a turnkey compliance
artifact — review it against your own cluster's admission-control setup.

## Why this matters more than most vendors' equivalent page

Free and paid tiers pull the exact same bytes (brief §0.2) — there is no
"trust us" tier. Everything on this page works identically whether you're
paying us anything or not.
