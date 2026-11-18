# Controls: how our build and images are made and checked

DRAFT. Not signed. This document stays a draft until it is signed. It says how our build chain
meets each control below, what evidence the chain leaves and the command that checks it. It makes no promise beyond those
facts, and no claim that FosterStack Cache is compliant with, or certified against, any framework: a control here means the
practice is designed to serve it.

No release built by this chain has been published yet, so none of the commands below has been run against a real release.
Each one says so. The published release files are the evidence; this page names the file that carries each one.

Version 1 is the first version of this document. The version changes only when the build chain changes, never for a
patch release. Each version is signed once, with the signer's typed name and title, and the plain-words change note for
it is in [controls-change-notes.md](controls-change-notes.md). Earlier versions and the differences between them are in
this repository's history.

## Version history

| Version | Signed | Change |
|---|---|---|
| 1 | not yet signed | The first version. |

## How a release is built

A release is built only by the workflow [release.yml](../.github/workflows/release.yml), started by a pushed, signed release
tag. Each step is its own job on a fresh GitHub-hosted runner, and every job asks only for the permissions it needs.

| Stage | Jobs | What it does |
|---|---|---|
| Build | `build-freeze`, `build-apk`, `build-assemble` | Admits the tagged commit, builds the packages on two native runners, assembles the two images and the archives, and lists everything it made in a digest list. |
| Rebuild | `rebuild-apk`, `rebuild-assemble` | Builds the same commit again on fresh machines; the images are compared with Build's before the release. |
| Sign | `sign`, `sign-rebuild`, `sign-check` | The only jobs that can reach the release key. They check the records of Build, Rebuild and Check and sign them, sign the provenance, and make the signatures of the release files. |
| Check | `check-govulncheck`, `check` | Runs the scanners in [scanners.json](../.github/policy/scanners.json), the build-tool, Kubernetes and no-outbound suites and the FIPS check against the exact candidate images. |
| Release | `release-compare`, `release-verify`, `release` | Compares the packages of Build and Rebuild in a job with no secret, verifies every earlier record, then publishes the images by digest and attaches the evidence to the release. |

The longer account is in [build and signing-key isolation](build-and-signing-isolation.md) and [RELEASING.md](../RELEASING.md).

## The controls

Control numbers are from NIST SP 800-53 Rev. 5. In every command, `<IMAGE_REF>`, `<IMAGE_REF_FIPS>` and `<TAG>` are the
ones defined in [verify-release.md](verify-release.md), which also tells you how to get `release.rsa.pub`.

| Control | How the build and images meet it | Evidence: the release file or repository file that shows it | Command you run |
|---|---|---|---|
| CM-7 Least functionality | Each image holds only our own base-layout package, time zone data and the `fscache` program: no shell, no package manager, no base image ([apko.yaml](../build/apko.yaml)). | `production.sbom.json` and `fips.sbom.json`, each with its `.bundle`, on every release. | `cosign verify-blob --key release.rsa.pub --bundle production.sbom.json.bundle production.sbom.json`, then `jq -r '.packages[].name' production.sbom.json` lists every package in the image. Not run against a real release. |
| SC-7 Boundary protection | The program makes no outbound connection and the images carry no certificate bundle, so no call to a public server can succeed. A test of each release starts the candidate with outbound traffic denied; a source check refuses outbound code ([check-no-outbound.py](../bin/check-no-outbound.py)). | The package list in the SBOM above; the runtime record of the Check stage for each chip, `ubuntu-24.04-runtime-collection.json` and `ubuntu-24.04-arm-runtime-collection.json`, each with its `.rekor.json`, on every release. | The `jq` command of the CM-7 row. The record's contents are for you to read; no command that checks the denied-traffic result is published yet. |
| SC-12 Cryptographic key management | One long-lived key signs every release file: the release key, held in a cloud key service and never in a build job. Only the Sign jobs ([release.yml](../.github/workflows/release.yml)) can reach it, and each signature has an entry in the public Rekor log. A separate root key, kept offline, signs a manifest that names the release key and its validity. | `release-key-manifest.json` and `release-key-manifest.sig` on every release (the repository holds them in `.github/policy/` once the release key is first issued; they are not in it yet). | The commands of [Check the release key](verify-key.md). Not run against a real release. |
| SC-13 Cryptographic protection | The `-fips` image uses Go's FIPS 140-3 module with FIPS mode on by default, as [fips.md](fips.md) states, including what the validation does and does not cover. The release pipeline's own signing tools are not claimed to be FIPS-validated. The test suite also runs in `fips140=only` mode on every pull request ([ci.yml](../.github/workflows/ci.yml)). Each release's Check stage starts both images and fails unless the `-fips` image reports FIPS mode on and the production image reports it off ([check-fips.sh](../bin/check-fips.sh)). | The startup log and `/statusz` of the image you run; the runtime records of the Check stage named in the SC-7 row. | Start the `-fips` image as in the [install guide](install.md), then `curl -fsS localhost:8080/statusz`: it shows `"fips140":true` and the module note described in [fips.md](fips.md). Not run against a real release. |
| SC-17 Public key infrastructure certificates | The images hold no public root certificates; the server uses only a certificate and key the operator supplies (`FSCACHE_TLS_CERT` and `FSCACHE_TLS_KEY`, see [docker-deploy.md](docker-deploy.md)). Our release signing uses a key, not a certificate, so there is no certificate authority of ours to trust. | The package list in the SBOM. | `jq -e '[.packages[].name | select(test("ca-certificates"))] | length == 0' production.sbom.json` prints `true`. Not run against a real release. |
| SR-4 Provenance | Each release carries signed build provenance that names the commit and the run that made the images and archives, and the digest of each image. | `provenance.bundle.json` on every release. | `cosign verify-blob-attestation --key release.rsa.pub --bundle provenance.bundle.json --type https://slsa.dev/provenance/v1 --check-claims=false`, and the digest check in step 3 of [verify-release.md](verify-release.md). Not run against a real release. |
| SR-11 Component authenticity | Packages come only from our own archive, named by a committed digest, and each is checked against its recorded hash and its signing key before an image is assembled; the build tools are checked against pinned checksums. The images are signed by digest in both registries. | `production.full.lock.json` and `fips.full.lock.json` (the packages each image was assembled from), `dependency-list.json`, each with its `.bundle`, and the image signatures, on every release. | `cosign verify-blob --key release.rsa.pub --bundle production.full.lock.json.bundle production.full.lock.json`, and `cosign verify --key release.rsa.pub <IMAGE_REF>`. Not run against a real release. |

## What this document does not cover

- The Rebuild stage's records (`rebuild-collection.json` and its `.rekor.json`) are attached to every release. No command
  that checks them is published yet, so no row above relies on them.
- Hardware separation of builds is not something GitHub-hosted runners let us show; the other known gaps are listed in
  [build and signing-key isolation](build-and-signing-isolation.md).
- No automated rotation of the release key is claimed.
