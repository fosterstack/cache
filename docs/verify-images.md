# Verify our images

GitHub's own CI signs every FosterStack Cache release and attaches its
provenance (a signed record of how the release was built). You don't have to
take our word for it. You can check the chain yourself in under a minute, with
`cosign` and `gh` plus standard tools (`curl`, `sed`, `jq`, `base64`,
`sha256sum` or `shasum`).

None of the commands below for v0.3.0 and later needs a GitHub token or a registry <!-- pinned: historical -->
login. They find the release and fetch files with `curl`, and check them
with `cosign`, `sha256sum` or `shasum`, `jq` and `base64`.

Only the `gh attestation verify` commands of the earlier chain read GitHub's
attestation API, and those need a token. They are marked "before v0.3.0". <!-- pinned: historical -->

Run this once to find the current release. The other commands use the result:

```sh
VER=$(curl -fsSL https://api.github.com/repos/fosterstack/cache/releases/latest \
        | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
```

This page covers v0.3.0 and later. <!-- pinned: historical -->

A release before v0.3.0 was built by the <!-- pinned: historical -->
earlier eight-stage chain. It has a `-debug` image and darwin archives.
Where its commands differ, they are marked "before v0.3.0", <!-- pinned: historical -->
and they are gathered under
[Releases before v0.3.0](#releases-before-v030). <!-- pinned: historical -->

## 1. Verify the signature

You verify two different things on an image, and they answer two
different questions. **The signature** answers: did FosterStack's release
workflow sign these exact bytes? It vouches for who signed the artifact and
that the bytes are unchanged. It says nothing more.

```sh
# The public image signature is made with the FosterStack release key by
# the Release stage. Fetch the release public key from the release tag and
# check the image against it.
curl -fsSLO "https://raw.githubusercontent.com/fosterstack/cache/v${VER}/build/keys/release.rsa.pub"
cosign verify --key release.rsa.pub ghcr.io/fosterstack/cache:${VER}
```

The release key lives in a cloud key service and never leaves it. The
Release stage can ask the service to sign, but nothing in the workflow can
read the key. Each signature is also recorded in Rekor, a public
transparency log.

A release before v0.3.0 carries a short-lived certificate instead of a key. <!-- pinned: historical -->
Verify it against the exact identity of the signing workflow, tied to the
release tag, and not against "any workflow in this repo":

```sh
cosign verify ghcr.io/fosterstack/cache:${VER} \
  --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

The signing workflow depends on the release. The releases of the earlier chain <!-- pinned: historical -->
were signed by `stage-promote.yml` (the one in the command above). The earliest release
was signed by the old `release.yml`. For that release, use
`--certificate-identity-regexp='^https://github.com/fosterstack/cache/.github/workflows/release.yml@'` instead. <!-- pinned: historical -->

Sigstore's Fulcio (its certificate service) issued that certificate from a
GitHub Actions OIDC token (a short-lived proof of identity from GitHub) at the
moment the release workflow ran.

## 2. Verify the provenance

**The provenance** answers a different question: what *produced* these
bytes? It is a signed SLSA statement about the build: which repository,
which workflow file and which run. That is more than a signature over the
artifact. A valid signature with no provenance tells you who signed, but not
how the thing was built.

From v0.3.0 the Sign stage (`stage-sign.yml`) writes and signs the provenance. <!-- pinned: historical -->
It signs with the release key, through the cloud key service (the `kms-sign` step).
The Release stage verifies the provenance before anything is published.

The provenance is attached to the GitHub release as `provenance.json`. Its
signature bundle is `provenance.bundle.json`, and its Rekor entry is
`provenance.rekor.json`.

Check it against the release public key `release.rsa.pub` that you fetched in
section 1. There is no certificate identity or issuer to check.

The provenance names each image (`production` and `-fips`) by digest. Compare
those digests with the digest of the image you pulled.

The step-by-step commands are in the v0.3.0 release guide, <!-- pinned: historical -->
[`docs/verify-release.md`](verify-release.md). Its commands are TO-VERIFY (not yet run) until a release candidate has run them.

Neither step tells you whether the artifact was scanned or tested. Other
stages of the chain make those statements separately. See "Verify the whole
chain" below.

## 2b. Verify the whole chain

From v0.3.0 the chain has five stages: Build, Sign, Rebuild, Check and Release <!-- pinned: historical -->
(see [`RELEASING.md`](../RELEASING.md)). Each stage checks the work before it:

- Rebuild, Check and Release each verify the signed records of the stages before them.
- Sign checks the records of the jobs that build things, and then signs them. It checks Build's records against the artifacts Build hands over, and Rebuild's records against Build's digest list.

The records are attached to the release, so you can verify them too. They are
Witness records (Witness is the tool that records what each job did):

- Build: `build-collection.json`, `digests.json`, `items.json`, `admission-baseline.json`
- Rebuild: `rebuild-collection.json`, `verdict.json`
- Check: the `scanners`, `acceptance` and `runtime` collections of each of the two runners, attached as `ubuntu-24.04-scanners-collection.json`, `ubuntu-24.04-arm-scanners-collection.json` and so on

The jobs that build or run workloads hold no signing identity. The Sign stage
(`stage-sign.yml` at the release tag) signs Build's, Rebuild's and Check's
records with the KMS key (the key in the cloud key service).

Two signed lists cover the other release files. The signed `release-files.sha256`
covers `release-manifest.json`, the OpenVEX file, the CSAF file and the
inspector-filters file. The signed `checksums.txt` covers the archives.
Verify each one with the release key (fetched as above):

```sh
cosign verify-blob --key release.rsa.pub --bundle checksums.txt.bundle checksums.txt
cosign verify-blob --key release.rsa.pub --bundle release-files.sha256.bundle release-files.sha256
```

### The signed evidence files

Besides the images, the Release stage's `release-sign` step signs each of the
files below with the release key (the same key as the images). Each signature
has a Rekor entry, and the release carries each file with its bundle:

- `<variant>.sbom.json` and `<variant>.full.lock.json`, for `production` and `fips`
- `vendor-evidence.json`
- `dependency-list.json`
- `policy.json` (its bundle is `release-policy.bundle`)
- `checksums.txt`
- `release-files.sha256`

Each bundle is named after its file with `.bundle` added
(`vendor-evidence.json.bundle`, `production.sbom.json.bundle`). The policy's
bundle is the exception: `release-policy.bundle`.

To verify one, use the release public key `release.rsa.pub` that you fetched in
section 1: `cosign verify-blob --key release.rsa.pub
--bundle NAME.bundle FILE`.

The Witness records themselves are the `*-collection.json` files. `stage-sign.yml`
signs Build's, Rebuild's and Check's. They are extra evidence that anyone with
Witness can check. The release guide,
[`docs/verify-release.md`](verify-release.md), does not cover them.
[`RELEASING.md`](../RELEASING.md) describes the stages that make them.

### The release manifest

**Verifying the release manifest.** Before the GitHub release is published, the
promotion workflow attaches the release manifest to each public image digest
(production and `-fips`; releases before v0.3.0 also `-debug`). <!-- pinned: historical -->
It attaches the manifest as a cosign attestation (predicate type
`https://fosterstack.com/attestations/release-manifest/v1`), signed with the
release key. The attestation is stored as a referrer of the image, so you find it
through the image digest and not through a separate tag. It goes to GHCR, which is
authoritative, and to the Docker Hub mirror, on a best-effort basis.

The attestation exists from v0.2.1 on. v0.1.0 has none, so the command below fails there. <!-- pinned: historical -->
v0.3.0 and later attach it too, signed with our release key. <!-- pinned: historical -->
`release-manifest.json` is also a release file, covered by the signed `release-files.sha256`.

The `release-manifest.json` on the release page has the same content. It has
no separate signature file, and `gh attestation verify <file>` does not apply
to it. The manifest is an attestation on the image, so verify it on the image
(anonymous, no token):

```sh
cosign verify-attestation --key release.rsa.pub \
  --type https://fosterstack.com/attestations/release-manifest/v1 \
  ghcr.io/fosterstack/cache:${VER} > manifest-att.json
```

`release.rsa.pub` is the release public key that you fetched in section 1. For a
release before v0.3.0, whose attestation carries a certificate, replace <!-- pinned: historical -->
`--key release.rsa.pub` with `--certificate-identity
"https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}"
--certificate-oidc-issuer https://token.actions.githubusercontent.com`.

The OpenVEX, CSAF and inspector-filters files on the release page have no
signature of their own. Two things cover them: the sha256 values recorded in the
signed manifest, and the signed `release-files.sha256`. The `cosign
verify-blob` and `sha256sum -c` commands for that list are in
[`RELEASING.md`](../RELEASING.md#archives-and-metadata-files). Check the
downloaded files against the manifest:

```sh
for f in release-manifest.json fosterstack-cache.openvex.json \
           "fosterstack-cache-v${VER}.csaf.json" "fosterstack-cache-v${VER}.inspector-filters.json"; do
  curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/${f}"
done

jq -r '.payload' manifest-att.json | base64 -d \
  | jq -r '.predicate.vex[] | "\(.sha256)  \(.file)"' > vex.sha256
sha256sum -c vex.sha256    # or: shasum -a 256 -c vex.sha256
```

Each line must print `OK`. (`base64 -d` works on GNU coreutils and on
macOS 14 and later. On older macOS, use `base64 -D`.)

### The Docker Hub mirror

The same images, with the same digests, are mirrored at
`docker.io/fosterstack/cache` for tooling that defaults to Docker Hub.
GHCR is canonical.

The image signatures are made in both registries, and they verify the same way
against either one. Verification uses the digest, not the registry.

The one exception is the release-manifest attestation. It is required on GHCR.
On Docker Hub it is attached on a best-effort basis: the release step warns and
continues when Docker Hub refuses it. So verify the manifest attestation
against GHCR.

One practical note: Docker Hub limits anonymous pulls by the **puller's** IP
and login, not by anything we control. If you hit a limit, authenticate with
any free Docker account or pull from GHCR.

### Releases before v0.3.0 <!-- pinned: historical -->

The rest of this section, and the `-debug` image in section 3, describe the
earlier eight-stage chain. It signed one predicate (a signed statement) per
stage on the image digest.

Every stage of the release chain signs its own statement about the exact
digest you pulled, and you can verify each one independently. This is the one
that implies all the others:

```sh
gh attestation verify oci://ghcr.io/fosterstack/cache:${VER} \
  --repo fosterstack/cache \
  --signer-workflow fosterstack/cache/.github/workflows/stage-authorize.yml \
  --predicate-type https://fosterstack.com/attestations/release-authorization/v1
```

That statement exists only if the authorization stage verified the full
graph for this digest: admission, build, image assembly, reproducibility,
one scan verdict per scanner, and acceptance. Its predicate body lists the
Rekor log index of everything it checked. Pinning `--signer-workflow` is what
makes this "signed by the authorization stage" and not merely "signed by
something in this repo."

**These chain predicates exist for releases built by the new chain (v0.2.1 and later, the first published release built by the new chain). The previous release carries only the image signature and SLSA provenance shown above.** <!-- pinned: historical -->

`gh attestation verify` reads GitHub's attestation API, so it needs a token in
the environment (`GH_TOKEN` or `gh auth login`), even for a public repo. The
token authenticates you to the API, not to the image. The image pull and the
**cosign** verification below are the fully anonymous routes. Use those when
you need "no credentials."

The individual statements can all be verified with the same command shape
(`--predicate-type <type>`):

| Predicate type | Signed by | Says |
|---|---|---|
| `https://fosterstack.com/attestations/image-build/v1` | the image-assembly stage | how this digest was assembled: base digest, binary hashes, Dockerfile hash |
| `https://fosterstack.com/attestations/reproducibility/v1` | the reproducibility stage | an independent rebuild produced this exact digest |
| `https://fosterstack.com/attestations/scan-trivy/v1` (also `-grype`, `-snyk`) | the verification stage | this digest was scanned clean by that scanner, with its version and database state |
| `https://fosterstack.com/attestations/acceptance/v1` | the acceptance stage | the per-AC acceptance results for this digest |
| `https://fosterstack.com/attestations/release-authorization/v1` | the authorization stage | the whole graph above verified; this digest is approved for this version |
| `https://fosterstack.com/attestations/publication/v1` | the promotion stage | the publication-phase results (REQ-REL-001/002): the anonymous verification and every-tag anonymous pull passed for this digest |

**Where the two publication results are.** The release manifest is attached
before publication. So its `ac_results` shows the two publication acceptance
criteria (`REQ-REL-001-AC1` and `REQ-REL-002-AC1`) as
`deferred-to-publication`, and its `publication_evidence` field points here.
Their **pass** result is in the separate publication attestation above. Verify
it (this needs a token), checking it against the promotion workflow and this
release ref:

```sh
# Verify the attestation AND extract its predicate as JSON, then assert
# the two release ACs are pass and bound to this tag/digest - a signature
# alone is not the outcome.
gh attestation verify oci://ghcr.io/fosterstack/cache:${VER} \
  --repo fosterstack/cache \
  --predicate-type https://fosterstack.com/attestations/publication/v1 \
  --signer-workflow fosterstack/cache/.github/workflows/stage-promote.yml \
  --source-ref "refs/tags/v${VER}" \
  --format json \
  --jq '.[0].verificationResult.statement.predicate' > /tmp/pub.json

# tag binding, then both ACs pass:
jq -e --arg t "v${VER}" '.tag == $t' /tmp/pub.json >/dev/null \
  && jq -e '[.publication_ac_results[] | select(.ac=="REQ-REL-001-AC1" or .ac=="REQ-REL-002-AC1") | .result] | (length==2 and all(.=="pass"))' /tmp/pub.json >/dev/null \
  && echo "publication outcomes: REQ-REL-001-AC1 and REQ-REL-002-AC1 both pass for v${VER}"
```

The `--jq` and `jq` commands read the predicate's `publication_ac_results`
directly. That way you check the outcome fields, and not only that a
signature exists.

The scanner list lives in
[`.github/policy/scanners.json`](../.github/policy/scanners.json). The
per-scanner types follow that list, not this table.

`release-manifest.json` on the release page carries the same evidence in
one file: every digest, both registry references, the result for each
acceptance criterion, and the Rekor log indexes.

## 3. Which tags to verify

| Tag | Shell | What it is |
|---|---|---|
| `X.Y.Z` | none | Production. Deploy this one. |
| `X.Y.Z-fips` | none | Same source built with `GOFIPS140=v1.0.0` (Go's CMVP FIPS 140-3 validated module) | <!-- pinned: upstream -->
| `X.Y` | — | Floating: moves to every final release of that line |
| `X` / `latest` | — | Floating: move only when the release is the highest released version |

There is no base image from v0.3.0 on: each image holds only the packages named in <!-- pinned: historical -->
[`build/apko.yaml`](../build/apko.yaml) (base layout, time zone data and `fscache`),
pinned by the lock files in `build/locks/`.

Both variants of every release are signed the same way. The `-fips` image has
its exact tag only; it has no floating tags. Releases before v0.3.0 also had <!-- pinned: historical -->
`X.Y.Z-debug` and the floating `debug` and `fips` tags; v0.3.0 and later do <!-- pinned: historical -->
not.

### The images have no shell

Production and `-fips` contain the `fscache` binary and a few packages
(base layout, time zone data; see `build/apko.yaml`). They have
no shell, no package manager and no coreutils. Running `docker exec ... sh` in
them fails, by design.

What this gives you:

- An attacker who gets code execution has no tools on the image to work with.
  There is no `sh` for a reverse-shell one-liner, and nothing to download or
  install helpers with.
- The OS package surface is small: just those few packages. We patch them by
  publishing a new release, not on the running image.

What it does not prevent:

- code execution itself
- anything an attacker can do through the process's own capabilities and syscalls
- attacks that bring their own tools

A minimal image narrows the toolbox. It is not a sandbox.

To troubleshoot, run a separate toolbox container that shares the server's
network and process namespaces; see
[Troubleshooting without a shell](docker-deploy.md#troubleshooting-without-a-shell-in-the-image).

Each tag is a multi-arch manifest (`linux/amd64` and `linux/arm64`). The
`cosign verify` command above checks the **index digest**. That digest covers
both platform manifests, so one verification covers every architecture. To see
what the index contains:

```sh
docker manifest inspect ghcr.io/fosterstack/cache:${VER} \
  | jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture)\t\(.digest)"'
# linux/amd64     sha256:d26325eb...
# linux/arm64     sha256:ba6e3cc6...
# unknown/unknown sha256:5c1e9a07...
# unknown/unknown sha256:77b0d2f3...
```

The published index is the final index. It holds the platform manifests plus
one VEX attestation child per platform. (VEX is our statement on whether a known
vulnerability affects the image.) These children list with the platform
`unknown/unknown`, so the jq filter above also prints them, as the last two
lines. Signatures and the other attestations are separate artifacts, tied to the
index digest. The digests we sign and attest for a release are the final
index's digests.

### The `-debug` image, before v0.3.0 <!-- pinned: historical -->

Those releases also shipped `:X.Y.Z-debug` (and `:debug`) on Google's
`gcr.io/distroless/static:debug-nonroot` base, which adds busybox under
`/busybox/` (no `/bin/sh`, no package manager; the shell is `/busybox/sh`,
uid 65532):

```sh
docker run -it --entrypoint /busybox/sh ghcr.io/fosterstack/cache:debug
kubectl exec -it <pod> -- /busybox/sh      # a pod running the :debug tag
```

## 4. Verify the binary archives

Container images aren't the only thing we release. Bare-binary releases are for
environments without containers or without internet access. See
[Install FosterStack Cache](install.md), or
["Installing on disconnected networks"](offline-install.md) for the air-gap
path. Each release ships a `checksums.txt` that covers every archive. It also
ships a signature for that file, made with the release key, as a bundle:

```sh
# Download checksums.txt and checksums.txt.bundle from the release page, then:
cosign verify-blob --key release.rsa.pub --bundle checksums.txt.bundle checksums.txt

sha256sum -c checksums.txt   # verifies every archive you downloaded, transitively
```

## 5. Enforcing this in your own cluster (Kyverno)

If you want your cluster to *require* this signature when a pod is admitted,
and not rely on checking by hand, here is a starting Kyverno policy. Kyverno is
a Kubernetes policy engine. This policy restricts a namespace to images signed
with this repository's release key:

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
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      (the contents of release.rsa.pub, fetched from the release tag)
                      -----END PUBLIC KEY-----
```

This policy is for v0.3.0 and later, whose images are signed with the release key. <!-- pinned: historical -->
A release before v0.3.0 carries a certificate. <!-- pinned: historical -->
For those releases, use a certificate attestor with the
signing workflow's identity and the issuer
`https://token.actions.githubusercontent.com` instead.

This is a starting point, not a turnkey compliance artifact. Review it against
your own cluster's admission-control setup.

## Why this matters more than most vendors' equivalent page

Free and paid tiers pull the exact same bytes. There is no "trust us" tier.
Everything on this page works the same whether or not you pay us anything.
