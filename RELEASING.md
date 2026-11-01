# Releasing

**Releases build only in CI.** No binary, image, or tag that ships to a user
is ever produced on a developer machine — including the maintainers'. This
is a hard rule, not a preference: it's what makes the SLSA provenance and
Sigstore signatures on every release mean something (an attacker with a
laptop cannot forge a release that GitHub's own runners never built).

## Pipeline (`.github/workflows/release.yml`)

From v0.3.0 the release is five stages, each one reusable workflow file with its <!-- pinned: historical -->
own job on a fresh GitHub-hosted runner. Sign signs the records and the provenance of Build, Rebuild and
Check under its own identity (`stage-sign.yml`); Release signs what it makes under its own:

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
  and writes Build's record; Build signs its records only with a throwaway key
  that nothing trusts, and Sign signs them (below);
  `digests.json` is the list of everything Build made. Before
  `digests.json`, Build makes each image's final index from the built index
  and the committed VEX file: the platform manifests plus one VEX attestation
  child per platform. The final index's digest is the one that is signed,
  attested, tested and promoted.
- **Sign** (`stage-sign.yml`): its own job and workflow file; it receives
  Build's records and the artifacts they name, never runs code from the build,
  checks the records against those artifacts, signs the records keyless under
  its own identity, then checks Build's digest list against the signed record
  and signs the SLSA provenance.
- **Rebuild** (`stage-reproducibility.yml`): builds the same commit on fresh
  machines and compares its items with Build's; any difference blocks the
  release. Its items include the apks' digests. The `compare` job of
  `stage-promote.yml` compares the apks once more (control and data sections;
  the job has `contents: read` only: no key, no write token, no identity token).
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

Releases before v0.3.0 were built by the earlier eight-stage chain (source <!-- pinned: historical -->
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

From v0.3.0, with every file below made by the Release stage from what Build <!-- pinned: historical -->
made (nothing is rebuilt), and every signature keyless (Fulcio certificate
from GitHub OIDC, entry in Rekor; no signing key exists to steal, except the
apk release key, which only Release's `release-apks` step reads):

- Two image variants, `production` and `-fips`, each a `linux/amd64` +
  `linux/arm64` index holding the `fscache` binary and a few packages (base layout, CA
  certificates, time zone data), with no base image,
  at `ghcr.io/fosterstack/cache` and mirrored, same digests, at
  `docker.io/fosterstack/cache`. Tags: `:X.Y.Z` and `:X.Y.Z-fips` exactly;
  `:X.Y` moves to every final release of that line; `:X` and `:latest` move
  only when the release is the highest released version. Releases before
  v0.3.0 also had a `-debug` variant; v0.3.0 and later do not. <!-- pinned: historical -->
- Per image: a cosign signature by digest in both registries, made by
  `stage-promote.yml` at the release tag. Sign's SLSA provenance, signed under
  `stage-sign.yml`, is verified by Release before anything is published.
- The apks of both architectures, re-signed with the release key and attached
  as `<arch>-<name>` (both architectures carry the same file names).
- The Linux archives with `checksums.txt` and its bundle
  (`checksums.txt.bundle`), which covers every archive transitively by hash.
- Per variant: the SBOM (`<variant>.sbom.json`) and the lock file
  (`<variant>.full.lock.json`), each with its bundle; the vendor evidence and
  the dependency list, each with its bundle; the release policy
  (`policy.json`) with its bundle.
- Four metadata files, covered by `release-files.sha256` and its bundle:
  `release-manifest.json` (image digests, both registry references, the
  requirements-baseline and test-evidence hashes; the daily rescan reads its
  digests, never tags), `fosterstack-cache.openvex.json`,
  `fosterstack-cache-vX.Y.Z.csaf.json` and
  `fosterstack-cache-vX.Y.Z.inspector-filters.json`.
- The Witness records of Build, Rebuild and Check (and Build's `digests.json`
  and `items.json`), which later stages and customers verify.
- A coverage gate: Release refuses to publish unless every asset is in
  `checksums.txt`, in `release-files.sha256`, a bundle of a covered file, or
  one of the kinds that carry their own signature (an apk, a Witness record,
  Build's digest and item lists). The gate runs again on what the release
  stores after the upload.

### Earlier releases and the `:debug` base

Releases built by the earlier eight-stage chain shipped a `-debug` variant on
the unmodified `gcr.io/distroless/static:debug-nonroot` base (shell at
`/busybox/sh`, no `/bin/sh`; a `/bin/sh` symlink layer was considered and
rejected on 2026-09-02 because "the upstream distroless base, pinned by digest,
with one Go binary added" must hold for every variant). Those releases are
verified as their own documentation says; see
[docs/verify-images.md](docs/verify-images.md).

The `-fips` variant has `GOFIPS140=v1.0.0` baked in at compile time <!-- pinned: upstream -->
(Go's CMVP FIPS 140-3 validated module, cert #5247).

## Verifying a release

The **pull** and the **cosign** verifications are fully anonymous: no GitHub
or registry credentials. Resolve the current release first:

```sh
VER=$(curl -fsSL https://api.github.com/repos/fosterstack/cache/releases/latest \
        | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
echo "$VER"
```

```sh
# Image signature: who signed these exact bytes. The signer is the Release
# stage's workflow at this release tag.
cosign verify "ghcr.io/fosterstack/cache:${VER}" \
  --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

The same command verifies the `-fips` variant with `${VER}-fips`. The whole
chain (Build, Sign, Rebuild, Check, Release) is verifiable record by record;
the commands are in [docs/verify-images.md](docs/verify-images.md).

### Archives and metadata files

The archives are not signed individually: `checksums.txt` is signed and pins
every archive by SHA-256. The four metadata files are pinned the same way by
`release-files.sha256`.

```sh
# 1. Prove each list is ours (pin the Release stage at this tag).
for f in checksums.txt release-files.sha256; do
  cosign verify-blob "$f" \
    --bundle "$f.bundle" \
    --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
done

# 2. Prove the files you downloaded match those lists.
sha256sum -c <(grep "fscache_${VER}_linux_amd64.tar.gz" checksums.txt)
sha256sum -c release-files.sha256
```

Do step 1. Without it, a list is self-referential: it proves the files match
a file that anyone could have written.

### What is signed, and what that covers

| Artifact | Signature | Covered by |
|---|---|---|
| Images (`${VER}`, `-fips`) | cosign, per digest, both registries | the signature itself |
| Binary archives | via the signed `checksums.txt` | `checksums.txt` |
| `checksums.txt`, `release-files.sha256`, SBOMs, lock files, vendor evidence, dependency list, release policy | cosign `sign-blob` bundle each | its own bundle |
| `release-manifest.json`, OpenVEX, CSAF, Inspector filters | via the signed `release-files.sha256` | `release-files.sha256` |
| apks | the release key, inside the file | the apk signature |
| Witness records | Witness envelope, signed with the KMS key; its Rekor entry is recorded | `stage-sign.yml` for Build, Rebuild and Check; `stage-promote.yml` for Release's own |

### VEX statements

Any scanner finding we ship past is answered by a published statement in
[`.vex/`](.vex/), attached to the release as
`fosterstack-cache.openvex.json` and, generated from it, as a CSAF file and an
Inspector filters file. Grype reads it, and the release gate holds OSV-Scanner's findings
to the same document (`bin/check-osv-vex.py`), so an exception is one public
claim rather than two tool-local suppressions. No statement, no
exception, no push.

### Dependency provenance: when the checksum-log record is checked
`dependency-provenance.json` lists each vendored module with `checksum_log.included: true`. Only
`bin/vendor-provenance.py build` verifies that, against a checksum-database record file passed as
`--sumdb-record` (it refuses a module whose record is missing, not marked included, or whose hash
differs from `go.sum`). No workflow or script runs `build`: a maintainer runs it by hand, with a
fresh record, whenever `dependency-provenance.json` is regenerated (a module added, removed or
bumped). CI runs `bin/vendor-provenance.py check`, which verifies the module set, the `go.sum`
hashes and the form of each entry, and does not re-verify the log, so the log claim is as current as the last run of
`build`.

## CI-only releases, verified in practice

`v0.1.0` was cut four times before it published. <!-- pinned: historical -->
A Go stdlib CVE
(govulncheck and Grype caught it independently), an EOL debug base image,
and a cosign v3 flag change were each caught by the pipeline before
anything shipped. Every fix was a normal signed
commit to `main`, same as any other change; nothing was ever hand-pushed
to a registry to route around a failing gate.
