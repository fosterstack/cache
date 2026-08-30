# Install FosterStack Cache

The server is a single static binary with no runtime dependencies
(`CGO_ENABLED=0`, nothing to `apt-get`, nothing fetched at startup). Download
the archive for your platform, verify it, run it.

Prefer containers? See [One-command Docker deploy](docker-deploy.md) or
[Deploying on Kubernetes](kubernetes.md). Air-gapped? Start here, then read
[Installing on disconnected networks](offline-install.md) for the transfer
and verification deltas.

## Supported platforms

Every release builds all of these. There is no "primary" platform — the
binaries are cross-compiled from the same source in the same CI run.

| Platform | Archive | Notes |
|---|---|---|
| `linux/amd64` | `fscache_X.Y.Z_linux_amd64.tar.gz` | The usual CI runner |
| `linux/arm64` | `fscache_X.Y.Z_linux_arm64.tar.gz` | AWS Graviton, Ampere, Raspberry Pi 4/5 |
| `darwin/amd64` | `fscache_X.Y.Z_darwin_amd64.tar.gz` | Intel Mac |
| `darwin/arm64` | `fscache_X.Y.Z_darwin_arm64.tar.gz` | **Apple Silicon** (M1–M4) |

**FIPS builds are Linux-only**: `fscache-fips_X.Y.Z_linux_amd64.tar.gz` and
`fscache-fips_X.Y.Z_linux_arm64.tar.gz`. The `-fips` variant is the same
source built with `GOFIPS140=v1.0.0`, selecting Go's CMVP FIPS 140-3
validated cryptographic module (cert #5247). There is no darwin FIPS build:
the compliance buyer this serves deploys on Linux, so a macOS FIPS binary
would double CI time for a configuration nobody assesses.

**Container images are multi-arch** (`linux/amd64` + `linux/arm64`), so
`docker pull` resolves the right one automatically — including on Apple
Silicon and Graviton. See
[docker-deploy.md](docker-deploy.md#platforms-and-multi-arch-images).

**Windows is not built and not planned.** This is a server-side cache that
lives next to your CI runners; there's no meaningful market for a Windows
build. If you develop on Windows, run the server under WSL2 — that's
`linux/amd64`.

## Which archive do I need?

```sh
# Prints e.g. "darwin_arm64" — the exact string in the archive name.
echo "$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
```

`uname -m` reports `arm64` on Apple Silicon and `x86_64` on Intel Macs. If
you get `darwin_arm64`, you want the Apple Silicon archive.

## Install

```sh
VERSION=0.1.0
PLATFORM=linux_amd64   # or the output of the command above

curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VERSION}/fscache_${VERSION}_${PLATFORM}.tar.gz"
tar xzf "fscache_${VERSION}_${PLATFORM}.tar.gz"
sudo install -m 0755 fscache /usr/local/bin/fscache

fscache --version 2>/dev/null || fscache &   # starts on :8080 by default
curl -fsS localhost:8080/healthz             # -> ok
```

Then point your build tool at it: [Gradle setup](gradle.md) ·
[Maven setup](maven.md).

## Verify what you downloaded

Do this before you install it, not after. Every release ships a
`checksums.txt` covering all six archives plus a cosign keyless signature
bundle over that file:

```sh
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VERSION}/checksums.txt"
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VERSION}/checksums.txt.bundle"

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp='^https://github.com/fosterstack/cache/' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum -c checksums.txt 2>/dev/null | grep OK   # or `shasum -a 256 -c` on macOS
```

The signature proves the checksums file came from this repo's release
workflow; the checksums then cover every archive transitively. Full detail,
including image signatures and SLSA provenance, is in
[Verify our images](verify-images.md).

## Run it as a service (systemd)

```ini
[Unit]
Description=FosterStack Cache
After=network.target

[Service]
ExecStart=/usr/local/bin/fscache
Environment=FSCACHE_ADDR=:8080
Environment=FSCACHE_DATA_DIR=/var/lib/fscache
Environment=FSCACHE_MAX_BYTES=53687091200
DynamicUser=yes
StateDirectory=fscache
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

Save as `/etc/systemd/system/fscache.service`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fscache
systemctl status fscache
```

`DynamicUser=yes` + `StateDirectory=fscache` means systemd creates an
unprivileged user and `/var/lib/fscache` for you — no manual `useradd`, and
the data directory is owned correctly on first start.

Set `FSCACHE_MAX_BYTES` to your eviction cap and size the disk above it; see
[Sizing](docker-deploy.md#sizing) for the numbers.

## Configuration

All configuration is environment variables — the full table is in the
[README](../README.md#build-and-run-from-source): `FSCACHE_ADDR`,
`FSCACHE_DATA_DIR`, `FSCACHE_MAX_BYTES`, `FSCACHE_USERNAME` /
`FSCACHE_PASSWORD`, `FSCACHE_MAX_BODY_BYTES`.

## Build from source

```sh
git clone https://github.com/fosterstack/cache.git
cd cache
CGO_ENABLED=0 go build -o fscache ./cmd/fscache
```

A source build is not a released artifact: releases are built only by this
repo's CI (see [`RELEASING.md`](../RELEASING.md)), which is what the
signatures and provenance attest to.
