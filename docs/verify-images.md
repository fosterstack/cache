# Verify our images

Every FosterStack Cache release is signed and provenance-attested by
GitHub's own CI — not by us claiming it, by a chain you can check yourself
in under a minute, with nothing installed but `cosign` and `gh`.

Every command below runs against `v0.1.0` with no GitHub credentials
configured.

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

`Build workflow` is cryptographic confirmation that the bytes you pulled
came out of this repository's public CI pipeline —
[`.github/workflows/release.yml`](../.github/workflows/release.yml),
readable in full — and not from a developer machine (see
[`RELEASING.md`](../RELEASING.md)'s "releases build only in CI" rule).

## 3. Which tags to verify

| Tag | Base image | Shell | What it is |
|---|---|---|---|
| `X.Y.Z` | `gcr.io/distroless/static:nonroot` | none | Production. Deploy this one. |
| `X.Y.Z-debug` | `gcr.io/distroless/static:debug-nonroot` | busybox at `/busybox/` | Same binary, plus troubleshooting tools. Not for deployment. |
| `X.Y.Z-fips` | `gcr.io/distroless/static:nonroot` | none | Same source built with `GOFIPS140=v1.0.0` (Go's CMVP FIPS 140-3 validated module) |
| `latest` / `debug` / `fips` | — | — | Floating tags, always the newest release of that variant |

All three variants of every release are signed and attested the same way.

### The images have no shell, and `:debug`'s is not where you expect

Production and `-fips` contain the `fscache` binary and nothing else — no
shell, no package manager, no coreutils. `docker exec ... sh` into them
fails, by design: a container with no shell has nothing for an attacker who
gets code execution to pivot into, and no OS package surface to patch.

`:debug` is the escape hatch. It is the same `fscache` binary on
Google's `debug-nonroot` base, which adds busybox. **The layout is not the
one you know from other Linux images.** Debian, RHEL, Amazon Linux, Alpine
and Wolfi all give you `/bin/sh`. Distroless does not:

- There is **no `/bin/sh`** and **no `/bin/bash`**. (`/bin` exists, as a
  symlink to `usr/bin`, but contains no shell.)
- There is **no package manager** — no `apt`, `apk`, `yum`, `dnf`. Nothing
  to install means nothing to drift, and nothing for an attacker to use.
- Everything busybox provides lives under **`/busybox/`** — 382 applets,
  including `sh`, `ls`, `cat`, `ps`, `netstat`, `wget`, `grep`, `df`, `vi`.

So the shell is at `/busybox/sh`:

```sh
docker run -it --entrypoint /busybox/sh ghcr.io/fosterstack/cache:debug
```

```sh
# a pod already running the :debug tag
kubectl exec -it <pod> -- /busybox/sh
```

`/busybox` is on the image's `PATH`, so bare `sh` resolves too
(`--entrypoint sh`). The full path is shown first because it works whether
or not `PATH` survives however you invoke the container.

Both commands run as the image's default user, uid **65532** (`nonroot`) —
no `--user=root`. Clusters that enforce `runAsNonRoot` reject a root
override, and troubleshooting as root would not reflect what the server
sees anyway.

Verify the difference yourself:

```sh
docker run --rm --entrypoint /busybox/sh ghcr.io/fosterstack/cache:0.1.0-debug -c 'id; ls /busybox | wc -l'
# uid=65532(nonroot) gid=65532(nonroot) groups=65532(nonroot)
# 382

docker run --rm --entrypoint /busybox/sh ghcr.io/fosterstack/cache:0.1.0 -c 'echo reached'
# error ... exec: "/busybox/sh": stat /busybox/sh: no such file or directory
```

The second command failing is the point: the production image has no shell
to exec.

Each tag is a multi-arch manifest (`linux/amd64` + `linux/arm64`), and
`cosign verify` above validates the **index digest** — which covers both
platform manifests, so one verification covers every architecture. To see
what the index contains:

```sh
docker manifest inspect ghcr.io/fosterstack/cache:0.1.0 \
  | jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture)\t\(.digest)"'
# linux/amd64   sha256:d26325eb...
# linux/arm64   sha256:ba6e3cc6...
```

The index holds exactly the platform manifests — signatures and attestations
are separate artifacts keyed to each digest, not extra entries here. A
third line means something else is in the index.

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
