# Releasing

**Releases build only in CI.** No binary, image, or tag that ships to a user
is ever produced on a developer machine — including the maintainers'. This
is a hard rule, not a preference: it's what makes the SLSA provenance and
Sigstore signatures on every release mean something (an attacker with a
laptop cannot forge a release that GitHub's own runners never built).

## Pipeline (`.github/workflows/release.yml`)

From v0.3.0 the release is five stages, each one reusable workflow file with its
own job and its own signing identity, on a fresh GitHub-hosted runner:

```
Build -> { Sign, Rebuild } ; { Build, Sign } -> Check ; { Check, Rebuild, Sign } -> Release
```

The chain starts on a pushed `v*` tag (or a branch dry run, which publishes
nothing). Every stage first verifies the signed record of the stage before it
and ties its work to the digest list Build attested; Release publishes by
digest the exact bytes Build made and Rebuild and Check judged, and never
rebuilds. Release is the only job that holds a registry credential, the apk
signing key or `packages: write`.

- **Build** (`stage-build.yml`): admits the tagged commit (tag signature,
  ancestry of `main`, required checks, approved requirements baseline), builds
  the apks on two native runners (amd64 and arm64) and assembles the images
  and archives. Witness (pinned by checksum, set up first) wraps every step
  through `bin/witnessed.sh` and signs Build's record keyless under Build's
  identity; `digests.json` is the list of everything Build made.
- **Sign** (`stage-sign.yml`): its own job and workflow file; it receives only
  Build's digest list, never runs code from the build, and writes and signs the
  SLSA provenance keyless under its own identity.
- **Rebuild** (`stage-reproducibility.yml`): builds the same commit on fresh
  machines and compares every item with Build's; any difference blocks the
  release.
- **Check** (`stage-verify.yml`): runs every scanner of
  [`.github/policy/scanners.json`](.github/policy/scanners.json), the Gradle
  and Maven suites, the no-phone-home and Kubernetes suites, the FIPS check
  and the customer-guide commands against the exact candidate digests, as
  Witness steps; it runs beside Rebuild.
- **Release** (`stage-promote.yml`, environment `release`): six Witness steps,
  each a committed script. `release-verify` checks the tag and verifies the
  earlier stages' records in order before any credential exists in the job;
  `release-apks` re-signs the apks with the stored release key through
  `bin/release-sign-apks.sh`; `release-publish` pushes the images by digest to
  `ghcr.io/fosterstack/cache` and `docker.io/fosterstack/cache` and reads each
  registry back; `release-sign` signs the images in both registries and the
  release files keyless, each with a Rekor entry; `release-assets` attaches the
  evidence to the GitHub release; `release-postverify` runs the customer-guide
  commands that need a registry against what was just published. Release
  creates no tag.
- **Release candidates**: a tag matching exactly `vX.Y.Z-rcN` runs every stage
  and Release's `release-verify`, and then ends: no credential is read, nothing
  is pushed, no release is created, no floating tag moves. A tag that is
  neither `vX.Y.Z` nor that form is refused by `release-verify`.
- **Floating tags**: a final release moves `:X.Y` to itself every time and `:X`
  and `:latest` only when it is the highest released version (the plain
  `X.Y.Z` tags of `ghcr.io/fosterstack/cache`); the `-fips` image gets its exact
  tag only.

Releases before v0.3.0 were built by the earlier eight-stage chain (source
admission, build, image assembly, reproducibility, scans and acceptance,
release authorization, promotion); the image signer of those releases is
`stage-promote.yml` too.

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

The **pull** and the **cosign** verifications below are fully anonymous —
no GitHub or registry credentials. The `gh attestation verify` command is
different: it reads GitHub's attestation API and needs a token in the
environment (`GH_TOKEN` or `gh auth login`) even for a public repo. Where
"no credentials" is the requirement, use the cosign route. Resolve the
current release first and the rest parameterize themselves:

```sh
VER=$(curl -fsSL https://api.github.com/repos/fosterstack/cache/releases/latest \
        | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
echo "$VER"
```

That uses only `curl` and `sed` — no `jq`, no GNU-only flags, and no
authentication, so it works on a stock macOS or a minimal container.

```sh
# Image SIGNATURE (cosign) — who signed these exact bytes. This is the
# image signature only; the build provenance is verified via the
# gh attestation route below. The signer is the promotion workflow at
# this release tag.
cosign verify "ghcr.io/fosterstack/cache:${VER}" \
  --certificate-identity-regexp="^https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}$" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'

# GitHub's own attestation store — confirms which workflow run built it.
# Needs a token (GH_TOKEN / gh auth login). Pin the producing workflow:
gh attestation verify "oci://ghcr.io/fosterstack/cache:${VER}" \
  --repo fosterstack/cache \
  --signer-workflow fosterstack/cache/.github/workflows/stage-image.yml
```

The `--signer-workflow` to pin is **version-scoped**: releases built by
the current chain use `stage-image.yml`, while the earliest release used
the old `release.yml` — pin whichever matches the `${VER}` you resolved. <!-- pinned: historical -->
On a current-chain release the image signature is made by the promotion
workflow (`stage-promote.yml`), and the publication-phase outcomes
(anonymous verification and every-tag anonymous pull) are recorded in a
separate signed attestation over the same digests — see
[docs/verify-images.md](docs/verify-images.md#2b-verify-the-whole-chain).

The `gh attestation verify` output includes a `Build workflow:` line naming
the image-assembly stage (`.github/workflows/stage-image.yml`) at the tag
being verified. That line is cryptographic proof the bytes you pulled came
from this repo's CI. The whole release chain is additionally verifiable —
see [docs/verify-images.md](docs/verify-images.md#2b-verify-the-whole-chain).

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
# 1. Prove the checksums file is ours. The checksums bundle is signed by
#    the promotion workflow at this release tag - pin it (same identity as
#    the image signature above), not "any workflow in this repo".
cosign verify-blob checksums.txt \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp="^https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}$" \
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
