# Verify our images

Every FosterStack Cache release is signed and provenance-attested by
GitHub's own CI — not by us claiming it, by a chain you can check yourself
in under a minute, with `cosign` and `gh` plus standard tools (`curl`,
`sed`, `jq`, `base64`, `sha256sum` or `shasum`).

No command for v0.3.0 and later below needs a GitHub token or a registry <!-- pinned: historical -->
login: they resolve the release and fetch files with `curl`, and check them
with `cosign`, `sha256sum` or `shasum`, `jq` and `base64`. Only the
`gh attestation verify` commands of the earlier chain (marked "before
v0.3.0") read GitHub's attestation API and need a token. Resolve the <!-- pinned: historical -->
current release once and the rest parameterize themselves:

```sh
VER=$(curl -fsSL https://api.github.com/repos/fosterstack/cache/releases/latest \
        | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
```

This page covers v0.3.0 and later. A release before v0.3.0 was built by the <!-- pinned: historical -->
earlier eight-stage chain and has a `-debug` image and darwin archives; where
its commands differ they are marked "before v0.3.0", and gathered under <!-- pinned: historical -->
[Releases before v0.3.0](#releases-before-v030). <!-- pinned: historical -->

## 1. Verify the signature

Two different things get verified on an image, and they answer two
different questions. **The signature** answers: did FosterStack's release
workflow sign these exact bytes? It vouches for identity and integrity of
the artifact, nothing more.

```sh
# The public image signature is made by the promotion workflow; pin it
# and the release tag rather than "any workflow in this repo".
cosign verify ghcr.io/fosterstack/cache:${VER} \
  --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

The signing workflow is **version-scoped**: v0.3.0 and later sign the <!-- pinned: historical -->
public image in the Release stage, `stage-promote.yml` (pinned above), and
so did the releases of the earlier chain; the earliest release
was signed by the old `release.yml`, so for it use
`--certificate-identity-regexp='^https://github.com/fosterstack/cache/.github/workflows/release.yml@'` instead. <!-- pinned: historical -->

There is no signing key to leak, steal, or rotate — the certificate is
short-lived, minted by Sigstore's Fulcio from a GitHub Actions OIDC token
at the moment the release workflow ran, and the signature's existence is
recorded in the public Rekor transparency log.

## 2. Verify the provenance

**The provenance** answers a different question: what *produced* these
bytes? It is a signed SLSA statement about the build — which repository,
which workflow file, which run — not merely a signature over the artifact.
A valid signature with no provenance tells you who signed, but nothing about
how the thing was built.

From v0.3.0 the provenance is written and signed by the Sign stage <!-- pinned: historical -->
(`stage-sign.yml`), keyless, under its own identity, and Release verifies it
before anything is published. It is attached to the GitHub release as
`provenance.json`, with its signature bundle `provenance.bundle.json` and its
Rekor entry `provenance.rekor.json`. The signer to pin is
`https://github.com/fosterstack/cache/.github/workflows/stage-sign.yml@refs/tags/v${VER}`,
with the issuer `https://token.actions.githubusercontent.com`. The provenance
names each image (`production` and `-fips`) by digest; compare those with the
digest of the image you pulled. The step-by-step commands are in the
v0.3.0 release guide, [`docs/verify-release.md`](verify-release.md) (the commands in it are TO-VERIFY until a release candidate has run them). <!-- pinned: historical -->

What neither step tells you, stated so nobody over-reads them: whether the
artifact was scanned or tested. Those are separate statements, made by other
stages of the chain. See "Verify the whole chain" below.

## 2b. Verify the whole chain

From v0.3.0 the chain is five stages (Build, Sign, Rebuild, Check, Release; <!-- pinned: historical -->
see [`RELEASING.md`](../RELEASING.md)). Each stage verifies the signed record
of the one before it, and the records are attached to the release so you can
verify them too: the Witness records of Build (`build-collection.json`,
`digests.json`, `items.json`, `admission-baseline.json`), Rebuild (`rebuild-collection.json`,
`verdict.json`) and Check (`scanners-collection.json`,
`acceptance-collection.json`, `runtime-collection.json`,
`arm64-collection.json`). `release-manifest.json`, the OpenVEX, CSAF and
inspector-filters files are covered by the signed `release-files.sha256`;
the archives are covered by the signed `checksums.txt`. The commands for
those two lists are in [`RELEASING.md`](../RELEASING.md#archives-and-metadata-files).

### The signed evidence files

Beside the images, the Release stage's `release-sign` step signs each of these
files keyless, under `stage-promote.yml` at the release tag, with a Rekor
entry, and the release carries the file with its bundle:
`<variant>.sbom.json` and `<variant>.full.lock.json` for `production` and
`fips`, `vendor-evidence.json`, `dependency-list.json`, `policy.json` (its
bundle is `release-policy.bundle`), `checksums.txt` and
`release-files.sha256`. Each bundle is named after its file with `.bundle`
added (`vendor-evidence.json.bundle`, `production.sbom.json.bundle`), except
the policy's, `release-policy.bundle`. Verify one the same way as
`checksums.txt` in section 4: `cosign verify-blob --bundle NAME.bundle FILE`
with the pinned identity. The Witness records themselves (the `*-collection.json`
files) are extra evidence that anyone with Witness can check; the release guide,
[`docs/verify-release.md`](verify-release.md), does not cover them, and
[`RELEASING.md`](../RELEASING.md) describes the stages that make them.

### The release manifest

**Verifying the release manifest.** The promotion workflow attaches the
release manifest as a cosign attestation (predicate type
`https://fosterstack.com/attestations/release-manifest/v1`) to each public
image digest (production and `-fips`; releases before v0.3.0 also `-debug`) on GHCR, which is authoritative, and <!-- pinned: historical -->
on the Docker Hub mirror (best effort), BEFORE the GitHub release is
published.
The attestation exists from v0.2.1 on (v0.1.0 has none, so the command below fails there) and v0.3.0 and later attach it too, signed by `stage-promote.yml` in the Release stage's `release-sign` step; `release-manifest.json` is also a release file covered by the signed `release-files.sha256`. <!-- pinned: historical -->
The `release-manifest.json` on the release page is the same
content. It has no separate signature file, and `gh attestation verify
<file>` does not apply to it: it is an attestation on the image, so verify
it on the image (anonymous, no token):

```sh
cosign verify-attestation \
  --type https://fosterstack.com/attestations/release-manifest/v1 \
  --certificate-identity "https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/fosterstack/cache:${VER} > manifest-att.json
```

The OpenVEX, CSAF and inspector-filters files on the release page have no
signature of their own. They are covered by the sha256 values recorded in the
signed manifest, and by the signed `release-files.sha256` (the `cosign
verify-blob` and `sha256sum -c` commands for that list are in
[`RELEASING.md`](../RELEASING.md#archives-and-metadata-files)). Check the
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
macOS 14 and later; on older macOS use `base64 -D`.)

### The Docker Hub mirror

The same images, same digests, are mirrored at
`docker.io/fosterstack/cache` for tooling that defaults to Docker Hub.
GHCR is canonical. The image signatures are made in both registries and
verify identically against either one, because verification is keyed to the
digest, not the registry. The one exception is the release-manifest
attestation: it is required on GHCR, but on Docker Hub it is attached on a
best-effort basis (the release step warns and continues when Docker Hub
refuses it), so verify the manifest attestation against GHCR. One practical note: Docker Hub rate-limits anonymous pulls by
the **puller's** IP and login (not by anything we control) — if you hit
a limit, authenticate with any free Docker account or pull from GHCR.

### Releases before v0.3.0 <!-- pinned: historical -->

The rest of this section, and the `-debug` image in section 3, describe the
earlier eight-stage chain, which signed one predicate per stage on the image
digest.

Every stage of the release chain signs its own statement about the exact
digest you pulled, and each is independently verifiable. The one that
implies all the others:

```sh
gh attestation verify oci://ghcr.io/fosterstack/cache:${VER} \
  --repo fosterstack/cache \
  --signer-workflow fosterstack/cache/.github/workflows/stage-authorize.yml \
  --predicate-type https://fosterstack.com/attestations/release-authorization/v1
```

That statement exists only if the authorization stage verified the full
graph for this digest — admission, build, image assembly,
reproducibility, one scan verdict per scanner, acceptance — and its
predicate body lists the Rekor log index of everything it checked.
Pinning `--signer-workflow` is what makes this "signed by the
authorization stage" rather than merely "signed by something in this
repo." **These chain predicates exist for releases built by the new chain (v0.2.1 and later, the first published release built by the new chain); the previous release carries only the image signature and SLSA provenance shown above.** <!-- pinned: historical -->

`gh attestation verify` reads GitHub's attestation API and therefore
needs a token in the environment (`GH_TOKEN` or `gh auth login`) even
for a public repo — it authenticates you to the API, not to the image.
The image pull and the **cosign** verification below are the fully
anonymous routes; use those where "no credentials" is the requirement.

The individual statements, all verifiable with the same command shape
(`--predicate-type <type>`):

| Predicate type | Signed by | Says |
|---|---|---|
| `https://fosterstack.com/attestations/image-build/v1` | the image-assembly stage | how this digest was assembled: base digest, binary hashes, Dockerfile hash |
| `https://fosterstack.com/attestations/reproducibility/v1` | the reproducibility stage | an independent rebuild produced this exact digest |
| `https://fosterstack.com/attestations/scan-trivy/v1` (also `-grype`, `-snyk`) | the verification stage | this digest was scanned clean by that scanner, with its version and database state |
| `https://fosterstack.com/attestations/acceptance/v1` | the acceptance stage | the per-AC acceptance results for this digest |
| `https://fosterstack.com/attestations/release-authorization/v1` | the authorization stage | the whole graph above verified; this digest is approved for this version |
| `https://fosterstack.com/attestations/publication/v1` | the promotion stage | the publication-phase results (REQ-REL-001/002): the anonymous verification and every-tag anonymous pull passed for this digest |

**Resolving the deferred release ACs.** Because the release manifest is
attached BEFORE publication, its `ac_results` shows the two publication
ACs (`REQ-REL-001-AC1`, `REQ-REL-002-AC1`) as
`deferred-to-publication`, and its `publication_evidence` field points
here. Their **pass** outcome lives in the separate publication attestation
above — verify it (needs a token), pinned to the promotion workflow and
this release ref:

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

The `--jq`/`jq` extraction reads the predicate's `publication_ac_results`
directly, so the customer checks the outcome fields, not merely that a
signature exists.

The scanner list lives in
[`.github/policy/scanners.json`](../.github/policy/scanners.json) — the
per-scanner types track that list, not this table.

`release-manifest.json` on the release page carries the same evidence in
one file: every digest, both registry references, per-AC results, and
the Rekor log indexes.

## 3. Which tags to verify

| Tag | Shell | What it is |
|---|---|---|
| `X.Y.Z` | none | Production. Deploy this one. |
| `X.Y.Z-fips` | none | Same source built with `GOFIPS140=v1.0.0` (Go's CMVP FIPS 140-3 validated module) | <!-- pinned: upstream -->
| `X.Y` | — | Floating: moves to every final release of that line |
| `X` / `latest` | — | Floating: move only when the release is the highest released version |

There is no base image from v0.3.0 on: each image holds only the packages named in <!-- pinned: historical -->
[`build/apko.yaml`](../build/apko.yaml) (base layout, CA certificates, time zone data and `fscache`),
pinned by the lock files in `build/locks/`.

Both variants of every release are signed the same way. The `-fips` image has
its exact tag only; it has no floating tags. Releases before v0.3.0 also had <!-- pinned: historical -->
`X.Y.Z-debug` and the floating `debug` and `fips` tags; v0.3.0 and later do <!-- pinned: historical -->
not.

### The images have no shell

Production and `-fips` contain the `fscache` binary and a few packages
(base layout, CA certificates, time zone data; see `build/apko.yaml`) — no
shell, no package manager, no coreutils. `docker exec ... sh` into them
fails, by design. What that buys, stated precisely: no shell and no package
manager means an attacker who gains code execution has no on-image tooling
to work with — no `sh` for a reverse shell one-liner, nothing to download
or install helpers with — and the OS package surface is small: those few packages, which are patched by
a new release, not on the running image. What it does not prevent: code execution itself, anything an
attacker can do through the process's own capabilities and syscalls, or
attacks that bring their own tooling. A minimal image narrows the toolbox;
it is not a sandbox.

To troubleshoot, run a separate toolbox container that shares the server's
network and process namespaces; see
[Troubleshooting without a shell](docker-deploy.md#troubleshooting-without-a-shell-in-the-image).

Each tag is a multi-arch manifest (`linux/amd64` + `linux/arm64`), and
`cosign verify` above validates the **index digest** — which covers both
platform manifests, so one verification covers every architecture. To see
what the index contains:

```sh
docker manifest inspect ghcr.io/fosterstack/cache:${VER} \
  | jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture)\t\(.digest)"'
# linux/amd64     sha256:d26325eb...
# linux/arm64     sha256:ba6e3cc6...
# unknown/unknown sha256:5c1e9a07...
# unknown/unknown sha256:77b0d2f3...
```

The published index is the final index: the platform manifests plus one VEX
attestation child per platform (these list with the platform `unknown/unknown`,
so the jq filter above also prints them, as the last two lines). Signatures and
the other attestations are separate artifacts keyed to the index digest. The
digests signed and attested for a release are the final index's digests.

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

Container images aren't the only artifact. Bare-binary releases (for
container-averse or air-gapped environments — see
[Install FosterStack Cache](install.md), or
["Installing on disconnected networks"](offline-install.md) for the air-gap
path) ship a
`checksums.txt` covering every archive, plus a cosign keyless blob-signature
bundle over that file:

```sh
# Download checksums.txt and checksums.txt.bundle from the release page, then:
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
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
