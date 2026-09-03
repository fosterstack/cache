# Releasing

**Releases build only in CI.** No binary, image, or tag that ships to a user
is ever produced on a developer machine — including the maintainers'. This
is a hard rule, not a preference: it's what makes the SLSA provenance and
Sigstore signatures on every release mean something (an attacker with a
laptop cannot forge a release that GitHub's own runners never built).

## Pipeline (live since v0.1.0, `.github/workflows/release.yml`)

```
build (snapshot, local only) → scan (Trivy AND Grype, all 3 image variants)
  → [gate] → build (real) → push → SBOM (ko) → cosign sign (keyless)
  → SLSA provenance attestation → gh attestation verify → publish release
```

Two jobs, a hard dependency between them: `build-and-scan` builds every
artifact in `goreleaser --snapshot` mode (verified: this never touches a
real registry — `ko` loads images into the runner's local Docker daemon
instead of pushing) and scans all three image variants with both Trivy and
Grype. `publish` only runs if that job succeeds, and is the only place in
this repo that ever pushes to GHCR. A release is never pushed unscanned.

## Cutting a release

```sh
git tag -s -m "..." vX.Y.Z
git push origin vX.Y.Z
```

The tag must be signed (`tag.gpgSign = true` is already set inside
`~/fosterstack/`). Pushing it is the only trigger — there is no manual
release path.

## What a release contains

- `linux/amd64` + `linux/arm64` container images on a digest-pinned
  `gcr.io/distroless/static:nonroot` base (built with `ko`, zero
  Dockerfile, zero docker daemon needed to build), at `ghcr.io/fosterstack/cache:X.Y.Z`.
- A `:X.Y.Z-debug` variant on `gcr.io/distroless/static:debug-nonroot`
  (busybox shell at `/busybox/sh`, for interactive troubleshooting only —
  never the default). See below on why there is no `/bin/sh`.
### Decided: the `:debug` base is never modified

`:debug` ships the **unmodified** `gcr.io/distroless/static:debug-nonroot`
base. Its shell is at `/busybox/sh`; there is no `/bin/sh` and no
`/bin/bash`.

**We do not add a `/bin/sh` symlink layer, now or later.** It would be a
one-line convenience, and it was considered and rejected on 2026-09-02.
The reason is that "our images are the upstream distroless base, pinned by
digest, with one Go binary added" is a claim that holds for all three
variants or none. Adding a layer to `:debug` to make it feel familiar
trades a verifiable property for ergonomics, and the ergonomics problem is
better solved by documentation — which is what
[the variant docs](docs/verify-images.md#the-images-have-no-shell-and-debugs-is-not-where-you-expect)
and [the troubleshooting section](docs/docker-deploy.md#troubleshooting-with-the-debug-image)
now do. Do not revisit without a reason that outweighs that.

- A `:X.Y.Z-fips` variant, `GOFIPS140=v1.0.0` baked in at compile time
  (Go's CMVP FIPS 140-3 validated module, cert #5247) — built from the
  first release even before the Compliance tier ships.
- Bare binaries + `checksums.txt` (via `goreleaser`), `linux`/`darwin` ×
  `amd64`/`arm64`, for container-averse or air-gapped environments.
- Per image: an SPDX SBOM (`ko`'s own SBOM generation, attached to the
  pushed image as an OCI referrer — this is where the SBOM materializes,
  no separate step), a cosign keyless signature, and a SLSA provenance
  attestation.
- For the binary archives: a SLSA provenance attestation covering
  `dist/*.tar.gz` + `checksums.txt`, and a cosign keyless blob signature
  bundle (`checksums.txt.bundle`) covering every archive transitively by
  hash.
- All Sigstore material is keyless: identity-bound short-lived certs from
  Fulcio via GitHub OIDC, logged to Rekor. No signing key exists anywhere
  to steal.

## Verifying a release

The commands below run against `v0.1.0` with no GitHub credentials, as an
anonymous pull:

```sh
# Image signature + provenance (cosign)
cosign verify ghcr.io/fosterstack/cache:0.1.0 \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'

# GitHub's own attestation store — confirms which workflow run built it
gh attestation verify oci://ghcr.io/fosterstack/cache:0.1.0 --owner fosterstack
```

The `gh attestation verify` output includes `Build workflow:
.github/workflows/release.yml@refs/tags/v0.1.0`. That line is
cryptographic proof the bytes you pulled came from this repo's CI. Swap `0.1.0` for `0.1.0-debug` or
`0.1.0-fips` to verify those variants; swap the tag for any later release.

The `:debug` variant's documented entry point is checked the same way. The
docs tell users to exec `/busybox/sh`, so that path has to work:

```sh
docker run --rm --entrypoint /busybox/sh \
  ghcr.io/fosterstack/cache:0.1.0-debug -c 'echo shell-ok'
# shell-ok
```

CI runs this assertion against the snapshot images on every release, before
anything is published — see the "debug variant must have a working shell"
step in `.github/workflows/release.yml`. It also asserts that `/bin/sh` is
*absent*, because the docs say so; if an upstream base change ever added
one, the release fails rather than the documentation going quietly wrong.

For the binary archives, verify `checksums.txt` against its cosign bundle
(`checksums.txt.bundle`, attached to the GitHub release) the same way, then
verify each archive against `checksums.txt` with `sha256sum -c`.

## One-time footnote: GHCR package visibility

**Discovered during the v0.1.0 release, not obvious in advance:** GHCR
gives every *new* container package its own visibility setting, separate
from the repo's — a brand-new package defaults to **private** even though
`fosterstack/cache` is a public repo. The first push under a new image
name (or a new package, e.g. if the repo path ever changes)
needs a one-time manual flip:

`https://github.com/orgs/fosterstack/packages/container/cache/settings` →
Change visibility → Public.

Until that's done, the push and every signature/attestation step still
succeed — but `cosign verify` / `gh attestation verify` / a plain
`docker pull` all fail with `UNAUTHORIZED`, because the bytes are sitting
behind a private-package auth wall despite the workflow having done
everything right. This is a package-level setting, outside repo
`Administration` — the interactive-session credential tier can't read or
write it (`403` on the packages API either way), so it's an owner action
every time a new package is created. Existing package, new
version: no action needed, this is one-time-per-package, not per-release.

## CI-only releases, verified in practice

`v0.1.0` was cut four times before it published. A Go stdlib CVE
(govulncheck and Grype caught it independently), an EOL debug base image,
and a cosign v3 flag change were each caught by the pipeline before
anything shipped. Every fix was a normal signed
commit to `main`, same as any other change; nothing was ever hand-pushed
to a registry to route around a failing gate.
