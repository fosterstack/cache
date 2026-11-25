# Releasing

**Releases build only in CI.** No binary or image that ships to a user is
ever produced on a developer machine, including the maintainers'. The only thing
made by hand is a maintainer's signed release tag, and the release workflow makes
and signs the tag of an automatic patch release itself; CI builds everything else
and signs it with the release signing key. This is a hard rule, not a preference: it's what makes the SLSA provenance and
signatures on every release mean something (an attacker with a
laptop cannot forge a release that GitHub's own runners never built).

## Pipeline (`.github/workflows/release.yml`)

From v0.3.0 the release is five stages in one workflow file, each made of its <!-- pinned: historical -->
own jobs, each on a fresh GitHub-hosted runner (Sign is three jobs: for Build's, Rebuild's and Check's
records). The jobs that build or run workloads (Build, Rebuild and Check)
hold no signing identity; the Sign stage signs their Witness records:

```
Build -> { Sign, Rebuild, Check } ; Rebuild -> Sign (second call) ; Check -> Sign (third call) ; { Check, Sign, Sign (second call), Sign (third call) } -> Release
```

The chain starts on a pushed `v*` tag or a push of a `release/*` branch
(or a branch dry run, which publishes nothing). Release first verifies the signed records of the stages
before it; Rebuild and Check tie their work to the digest list Build made; Sign checks
the building jobs' records (Build's against the artifacts it receives, Rebuild's
against Build's digest list) and signs them. Release publishes by
digest the exact bytes Build made and Rebuild and Check judged, and never
rebuilds. Of the jobs above, Release is the only one that holds a registry credential or
`packages: write`.

- **Build** (`build-apk`, `build-assemble`): builds
  the apks on two native runners (amd64 and arm64) and assembles the images
  and archives. Witness (pinned by checksum, set up first) wraps every
  building step; the building jobs hold no identity token, so those records
  are made with a throwaway key (`bin/witnessed-local.sh`) and leave Build as
  local files that nothing trusts until the Sign stage has signed them.
  `digests.json` is the list of everything Build made. Before
  `digests.json`, Build makes each image's final index from the built index
  and the committed VEX file: the platform manifests plus one VEX attestation
  child per platform. The final index's digest is the one that is signed,
  attested, tested and promoted.
- **Sign** (`sign`, `sign-rebuild`, `sign-check`): its own jobs, in the `sign`
  environment; it never runs code from the build. It receives Build's records and the artifacts they name,
  checks each record against them, signs the records with the release
  key (the KMS key), and writes and signs the SLSA provenance. The second job
  signs Rebuild's records; it receives no Rebuild apk or image. The third job
  signs Check's records; it receives only those records and the results they name.
- **Rebuild** (`rebuild-apk`, `rebuild-assemble`): builds the same commit on fresh
  machines and compares every item with Build's; any difference blocks the
  release. Its records are signed by the Sign stage, not by Rebuild.
- **Check** (`check-govulncheck`, `check`): runs every scanner of
  [`.github/policy/scanners.json`](.github/policy/scanners.json), the Gradle
  and Maven suites, the no-phone-home and Kubernetes suites, the FIPS check
  and the customer-guide commands against the exact candidate digests, as
  Witness steps; it runs beside Rebuild.
- **Release** (`release.yml`, environment `release`): six Witness steps,
  each a committed script, in one job that holds no signing role and no key.
  `release-verify` checks the tag and verifies the earlier stages' records in
  order before any credential exists in the job; `release-apks` puts the apk
  signatures Sign made on the apks; `release-publish` pushes the images by
  digest to `ghcr.io/fosterstack/cache` and `docker.io/fosterstack/cache` and
  reads each registry back, after `bin/release-sign-verify.sh` has checked every
  signature Sign made, each with its Rekor entry, against the public release
  key (a bad one stops the release before any login or push); `release-sign`
  runs that check again and pushes the signatures;
  `release-postverify` runs the customer-guide commands that need a registry
  against what was just published; and `release-assets` creates the GitHub
  release only after that. Every signature is made before publishing by Sign's
  third job, `sign-check`, on a final tag (`bin/release-signatures.sh`).
  The stages of Release create no tag: a tag is made before they start, by a
  maintainer, or for an automatic patch release by the `sign-tag` and `cut` jobs
  of `release.yml` (see "Cutting a release" below).
- **Release branches**: a push of a `release/vX.Y` branch builds once as the next patch version of the line and
  runs Rebuild, Check and the persona tests on that build, with no key: Sign
  and Release do not run, nothing is pushed and no release is created. The
  release tag `vX.Y.0` of a minor or major release is pushed by hand;
  patch tags are made on `main` by the `sign-tag` and `cut` jobs.
- **Floating tags**: a final release moves `:X.Y` to itself every time and `:X`
  and `:latest` only when it is the highest released version (the plain
  `X.Y.Z` tags of `ghcr.io/fosterstack/cache`); the `-fips` image gets its exact
  tag only.

Releases before v0.3.0 were built by the earlier eight-stage chain (source <!-- pinned: historical -->
admission, build, image assembly, reproducibility, scans and acceptance,
release authorization, promotion); the image signer of those releases was that
chain's promotion workflow, which the v0.3.0 chain replaced. <!-- pinned: historical -->

## Cutting a release

The release signing key is made by a terraform apply of the release signing
key (the role `fosterstack-cache-release-signing` and the alias
`alias/fosterstack-release-signing`), and that apply is the precondition of a
real release: without it Sign's jobs cannot sign (Release's `release-sign` step
holds no key and only pushes what they signed). Before the first
release, once the key exists, a person commits its public half as
`build/keys/release.rsa.pub`, replacing the placeholder there (the output of
`cosign public-key --key awskms:///alias/fosterstack-release-signing`).

The release APKs are signed with the same key. Until the public half is committed, the placeholder stays and the APK signing step refuses every release.

```sh
git tag -s -m "..." vX.Y.Z
git push origin vX.Y.Z
```

Sign the tag with SSH: set `gpg.format` to `ssh` and `user.signingkey` to the SSH key
listed for you as a maintainer, then run `git tag -s`. Pushing it is the only trigger — there is no manual
release path.

An automatic patch release has no maintainer step. On a push to `main` or on the daily
schedule, `release.yml` runs `decide`, which says which patch tag is due, then `sign-tag`,
which makes the tag object and signs it with the release KMS key, then `cut`, which pushes
that signed tag.

## What a release contains

From v0.3.0, with every file below made by the Release stage from what Build <!-- pinned: historical -->
made (nothing is rebuilt). The images and the release files are signed with
the release signing key, a key held in a cloud key service that the Sign jobs
reach with short-lived credentials, each with an entry in Rekor. Sign's
records and provenance are signed with the same key through the cloud key
service (entry in Rekor). The apks are signed by `sign-check` with
the same key, and Release's `release-apks` step attaches the signatures; no apk key is stored anywhere:

- Two image variants, `production` and `-fips`, each a `linux/amd64` +
  `linux/arm64` index holding the `fscache` binary and a few packages (base layout and
  time zone data), with no base image,
  at `ghcr.io/fosterstack/cache` and mirrored, same digests, at
  `docker.io/fosterstack/cache`. Tags: `:X.Y.Z` and `:X.Y.Z-fips` exactly;
  `:X.Y` moves to every final release of that line; `:X` and `:latest` move
  only when the release is the highest released version. Releases before
  v0.3.0 also had a `-debug` variant; v0.3.0 and later do not. <!-- pinned: historical -->
- Per image: a cosign signature by digest in both registries, made with the
  release signing key by the Sign stage (`sign-check`) and pushed by the Release stage. Sign's SLSA provenance, signed by the
  `sign` job, is verified by Release before anything is published.
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
`/busybox/sh`, no `/bin/sh`). Those releases are
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

Get the release signing key from this repository, at the release tag. Until the
key manifest is published, the key file named in this repository is the
reference.

```sh
curl -fsSLO "https://raw.githubusercontent.com/fosterstack/cache/v${VER}/build/keys/release.rsa.pub"
```

```sh
# Image signature: was this exact image signed with the release signing key.
cosign verify --key release.rsa.pub "ghcr.io/fosterstack/cache:${VER}"
```

The same command verifies the `-fips` variant with `${VER}-fips`. Sign's
provenance is signed with the release key and is checked against the release public key
(there is no certificate identity or issuer to pin):

```sh
cosign verify-blob-attestation --key release.rsa.pub --bundle provenance.bundle.json \
  --type https://slsa.dev/provenance/v1 --check-claims=false
```

The whole
chain (Build, Sign, Rebuild, Check, Release) is verifiable record by record;
the commands are in [docs/verify-images.md](docs/verify-images.md).

### Archives and metadata files

The archives are not signed individually: `checksums.txt` is signed and pins
every archive by SHA-256. The four metadata files are pinned the same way by
`release-files.sha256`.

```sh
# 1. Prove each list is ours (signed with the release signing key).
for f in checksums.txt release-files.sha256; do
  cosign verify-blob --key release.rsa.pub --bundle "$f.bundle" "$f"
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
| Images (`${VER}`, `-fips`) | cosign with the release signing key, per digest, both registries | the signature itself |
| Binary archives | via the signed `checksums.txt` | `checksums.txt` |
| `checksums.txt`, `release-files.sha256`, SBOMs, lock files, vendor evidence, dependency list, release policy | cosign `sign-blob` bundle each, with the release signing key | its own bundle |
| `release-manifest.json`, OpenVEX, CSAF, Inspector filters | via the signed `release-files.sha256` | `release-files.sha256` |
| apks | the release key, inside the file | the apk signature |
| Witness records | Witness envelope, signed with the KMS key; its Rekor entry is recorded | Build's, Rebuild's and Check's: the Sign jobs at the tag; Release's own six steps: a throwaway key (no release-key signature) |

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
