# Releasing

**Releases build only in CI.** No binary, image, or tag that ships to a user
is ever produced on a developer machine — including the maintainers'. This
is a hard rule, not a preference: it's what makes the SLSA provenance and
Sigstore signatures on every release mean something (an attacker with a
laptop cannot forge a release that GitHub's own runners never built).

## Pipeline (`.github/workflows/release.yml`)

```
source admission → build (binaries) → image assembly → reproducibility
  → { scans, acceptance } → release authorization → promotion
```

One build, one set of digests, promoted without a rebuild. Each stage is
a reusable workflow with its own OIDC identity; each signs a predicate
about what it produced or verified, and each verifies its inputs'
predicates on entry — so the bytes that are scanned, tested, and finally
made public are provably the same bytes, referenced by digest at every
step, never re-resolved from a registry.

- **Source admission** runs before any repository-controlled command:
  the tag's SSH signature and the tagged commit's signature are checked
  against the allowed-signers list on protected `main`, the commit must
  be an ancestor of `main` with every required check green on the exact
  SHA, and an approved requirements baseline must exist for the version.
- **Build** compiles the binary matrix with a toolchain pinned to
  `go.mod` (`GOTOOLCHAIN=local`, `go mod verify`, manifests never
  mutated), produces the archives, `checksums.txt`, and per-archive
  SBOMs, and signs a build predicate whose subjects are the archive
  digests as the builder itself emitted them.
- **Image assembly** verifies each archive against that signed predicate
  before opening it, assembles each variant with a COPY-only Dockerfile
  (digest-pinned distroless base, zero `RUN`), and pushes by digest only
  to a private candidates package — no tags, nothing public.
- **Reproducibility** repeats the assembly on a separate runner and
  asserts the digests come out identical. The images are reproducible,
  and this check is what makes that a tested claim rather than a
  promise: if it ever fails, the release fails.
- **Scans**: every scanner in
  [`.github/policy/scanners.json`](.github/policy/scanners.json) runs
  against the exact candidate digests; block at any severity; a
  published VEX statement is the only exception. **Acceptance**: the
  release-artifact scenarios plus the Gradle and Maven acceptance
  suites run against the exact candidate image.
- **Release authorization** verifies the entire graph — every predicate,
  signed by the expected stage, naming these digests — and is the only
  stage that can approve promotion. Anything missing fails closed.
- **Promotion** copies the approved digests to the public registries
  with no build step of any kind, asserts the public digest equals the
  candidate digest after every copy, signs, publishes the release
  files, re-verifies everything as an anonymous customer would, and
  only then undrafts the release.

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
  `gcr.io/distroless/static:nonroot` base (a COPY-only Dockerfile: the
  verified release binary added to the unmodified base, zero `RUN`
  steps, reproducible digests), at `ghcr.io/fosterstack/cache:X.Y.Z` —
  and mirrored, same digests, at `docker.io/fosterstack/cache:X.Y.Z`.
  GHCR is canonical; the Docker Hub mirror exists for tooling that
  defaults there. Pull-by-digest is identical at either.
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

- A `:X.Y.Z-fips` variant, `GOFIPS140=v1.0.0` baked in at compile time <!-- pinned: upstream -->
  (Go's CMVP FIPS 140-3 validated module, cert #5247) — built from the
  first release even before the Compliance tier ships.
- Bare binaries + `checksums.txt` (via `goreleaser`), `linux`/`darwin` ×
  `amd64`/`arm64`, for container-averse or air-gapped environments.
- Per image: a cosign keyless signature **in both registries**, a SLSA
  provenance attestation, and the full release-chain predicates
  (image-build, reproducibility, per-scanner scan verdicts, acceptance,
  release authorization) in GitHub's attestation store, keyed to the
  image digest. The SBOMs of record are the per-archive SPDX documents
  on the release page — the image is the unmodified distroless base
  plus exactly that archive's binary.
- For the binary archives: a SLSA provenance attestation covering
  `dist/*.tar.gz` + `checksums.txt`, and a cosign keyless blob signature
  bundle (`checksums.txt.bundle`) covering every archive transitively by
  hash.
- `release-manifest.json`: the release evidence bundle — every artifact
  digest, both registry references per image, the requirements-baseline
  and test-evidence hashes, per-AC acceptance results, and the Rekor log
  index of every statement the authorization stage verified. The daily
  rescan reads this file's digests, never tags.
- All Sigstore material is keyless: identity-bound short-lived certs from
  Fulcio via GitHub OIDC, logged to Rekor. No signing key exists anywhere
  to steal.

## Verifying a release

Every command below runs with no GitHub credentials, as an anonymous pull.
Resolve the current release first and the rest parameterize themselves:

```sh
VER=$(curl -fsSL https://api.github.com/repos/fosterstack/cache/releases/latest \
        | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
echo "$VER"
```

That uses only `curl` and `sed` — no `jq`, no GNU-only flags, and no
authentication, so it works on a stock macOS or a minimal container.

```sh
# Image signature + provenance (cosign)
cosign verify "ghcr.io/fosterstack/cache:${VER}" \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'

# GitHub's own attestation store — confirms which workflow run built it
gh attestation verify "oci://ghcr.io/fosterstack/cache:${VER}" --owner fosterstack
```

The `gh attestation verify` output includes a `Build workflow:` line naming
`.github/workflows/release.yml` at the tag being verified. That line is
cryptographic proof the bytes you pulled came from this repo's CI.

The same two commands verify the other variants — use `${VER}-debug` or
`${VER}-fips` in place of `${VER}`.

The `:debug` variant's documented entry point is checked the same way. The
docs tell users to exec `/busybox/sh`, so that path has to work:

```sh
docker run --rm --entrypoint /busybox/sh \
  "ghcr.io/fosterstack/cache:${VER}-debug" -c 'echo shell-ok'
# shell-ok
```

CI runs this assertion against the snapshot images on every release, before
anything is published — see the "debug variant must have a working shell"
step in `.github/workflows/release.yml`. It also asserts that `/bin/sh` is
*absent*, because the docs say so; if an upstream base change ever added
one, the release fails rather than the documentation going quietly wrong.

### Binary archives

The archives are not signed individually. `checksums.txt` is signed, and it
pins every archive by SHA-256 — so verifying the checksums file and then
checking an archive against it is a complete chain, not two half-measures.

```sh
# 1. Prove the checksums file is ours
cosign verify-blob checksums.txt \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'

# 2. Prove the archive matches that file
sha256sum -c <(grep "fscache_${VER}_linux_amd64.tar.gz" checksums.txt)
```

Do step 1. Without it, `checksums.txt` is self-referential: it proves the
archive matches a file that anyone could have written.

### What is signed, and what that covers

| Artifact | Signature | SLSA provenance | SBOM |
|---|---|---|---|
| Images (`${VER}`, `-debug`, `-fips`) | cosign, per digest, both registries | yes, in the attestation store | via the archive SBOMs |
| Binary archives | via the signed `checksums.txt` | yes | no |
| `checksums.txt` | cosign `sign-blob` bundle | yes | — |

### VEX statements

Any scanner finding we ship past is answered by a published statement in
[`.vex/`](.vex/), attached to the release as
`fosterstack-cache.openvex.json`. Both release scanners read it, so an
exception is one public claim rather than two tool-local suppressions. No
statement, no exception, no push.

## CI-only releases, verified in practice

`v0.1.0` was cut four times before it published. <!-- pinned: historical -->
A Go stdlib CVE
(govulncheck and Grype caught it independently), an EOL debug base image,
and a cosign v3 flag change were each caught by the pipeline before
anything shipped. Every fix was a normal signed
commit to `main`, same as any other change; nothing was ever hand-pushed
to a registry to route around a failing gate.
