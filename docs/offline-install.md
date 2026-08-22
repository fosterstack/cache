# Installing on disconnected networks

FosterStack Cache is a single static binary with zero runtime
dependencies (`CGO_ENABLED=0`, `FROM scratch`/distroless — nothing to
`apt-get` on the host, nothing the binary reaches out for at startup), so
an air-gapped install is cheap: move the artifact across, verify it,
run it. This page is the DISA CHPG §2.1(7) deliverable ("no build-time
downloads; dependencies pre-staged") — the product ships that way by
construction, not as a special disconnected-mode build.

## What to bring across the gap

From a release page (e.g. `https://github.com/fosterstack/cache/releases/tag/vX.Y.Z`)
on a connected machine, download:

- The bare binary archive for your platform, e.g.
  `fscache_X.Y.Z_linux_amd64.tar.gz` (or `fscache-fips_X.Y.Z_linux_amd64.tar.gz`
  for the FIPS build).
- `checksums.txt` and `checksums.txt.bundle` (the cosign signature over the
  checksums file).
- If you're deploying via container instead of a bare binary: the image
  tarball —

  ```sh
  # On the connected machine, with docker/skopeo/crane available:
  crane pull ghcr.io/fosterstack/cache:X.Y.Z fscache-X.Y.Z.tar
  # or, with the FIPS variant:
  crane pull ghcr.io/fosterstack/cache:X.Y.Z-fips fscache-X.Y.Z-fips.tar
  ```

Move these files across your air gap by whatever sanctioned mechanism your
environment uses (this product has no opinion on that part).

## Verify before you trust it — on the connected side, before the transfer

Do this on the connected machine, so verification happens against the real
Sigstore/Rekor infrastructure rather than something you'd need connectivity
for on the disconnected side too:

```sh
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum -c checksums.txt   # confirms the archive(s) you're about to move
```

For a container tarball, verify the pulled image before exporting it (same
`cosign verify` invocation as [Verify our images](verify-images.md)) — do
this step while you still have registry access.

## Install: bare binary

```sh
tar xzf fscache_X.Y.Z_linux_amd64.tar.gz
sudo install -m 0755 fscache /usr/local/bin/fscache
```

A minimal systemd unit for container-averse compliance environments:

```ini
[Unit]
Description=FosterStack Cache
After=network.target

[Service]
ExecStart=/usr/local/bin/fscache
Environment=FSCACHE_ADDR=:8080
Environment=FSCACHE_DATA_DIR=/var/lib/fscache
DynamicUser=yes
StateDirectory=fscache
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

## Install: container tarball

```sh
# Docker
docker load -i fscache-X.Y.Z.tar
docker run -d -p 8080:8080 ghcr.io/fosterstack/cache:X.Y.Z

# containerd/nerdctl or podman: same idea, their own `load` equivalent
```

## Ongoing operation without connectivity

- The server makes no outbound network calls at runtime — it's a pure
  HTTP server over local state. Nothing in normal operation needs the
  network beyond what your build tools' own traffic requires to reach it.
- Patch delivery has to be a manual re-import of a newer release across
  the gap — there's no phone-home update mechanism, deliberately. Track
  new releases (and the security advisories that trigger them) through
  whatever channel your environment allows outbound (RSS on the GitHub
  releases feed, a mirrored changelog, etc.).
- The public changelog and CVE-status information (see
  ["Scanning FosterStack in your compliance pipeline"](scanning.md)) is
  the same evidence trail whether or not your deployment can reach it
  directly — bring the pages across along with the binary if your
  assessor wants the paper trail on the disconnected side too.

## FIPS build note

The `-fips` variant (`GOFIPS140=v1.0.0`) is a second build of the same
source, not a different distribution channel — everything above applies
identically. See the Compliance-tier pricing page (when live) for the
attestation/evidence pack that pairs with this build for a CMMC/NIST SP
800-171 assessment boundary.
