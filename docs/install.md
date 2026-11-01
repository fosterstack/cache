# Install FosterStack Cache

The server is a single static binary with no runtime dependencies
(`CGO_ENABLED=0`, nothing to `apt-get`, nothing fetched at startup). Download
the archive for your platform, verify it, run it.

Prefer containers? See [One-command Docker deploy](docker-deploy.md) or
[Deploying on Kubernetes](kubernetes.md). Air-gapped? Start here, then read
[Installing on disconnected networks](offline-install.md) for the transfer
and verification deltas.

## Supported platforms

Every release builds both of these, from the same source in the same CI run.
From v0.3.0 the release carries Linux archives only: there is no macOS <!-- pinned: historical -->
binary, and no darwin archive on the release page (releases before v0.3.0 <!-- pinned: historical -->
had one).

| Platform | Archive | Notes |
|---|---|---|
| `linux/amd64` | `fscache_X.Y.Z_linux_amd64.tar.gz` | The usual CI runner |
| `linux/arm64` | `fscache_X.Y.Z_linux_arm64.tar.gz` | AWS Graviton, Ampere, Raspberry Pi 4/5 |

**FIPS builds are Linux-only**: `fscache-fips_X.Y.Z_linux_amd64.tar.gz` and
`fscache-fips_X.Y.Z_linux_arm64.tar.gz`. The `-fips` variant is the same
source built with `GOFIPS140=v1.0.0` <!-- pinned: upstream -->, selecting Go's CMVP FIPS 140-3
validated cryptographic module (cert #5247). The compliance buyer this
serves deploys on Linux, so there is no FIPS build for any other platform.

The FIPS build says so at startup, so the property is observable rather than
taken on trust:

```json
{"msg":"fscache: starting","fips140":"active (Go validated module ..., CMVP cert #5247)", ...}
```

Standard builds report `"fips140":"off"`. `/statusz` carries the same
information as two fields: `fips140` (a boolean) and `fips140_note` (the same
text, with the module version in it). Running a standard build with `GODEBUG=fips140=on` does not claim the
certificate: the note then reads `active (fips140 mode forced at runtime; not
the validated-module build)`. An assessor can confirm which build is running
from the process log and the install path, without access to your build
pipeline.

**Container images are multi-arch** (`linux/amd64` + `linux/arm64`), so
`docker pull` resolves the right one automatically — including on Apple
Silicon and Graviton. See
[docker-deploy.md](docker-deploy.md#platforms-and-multi-arch-images).

**macOS and Windows are not built.** On a Mac, run the container image
(Docker Desktop pulls `linux/arm64` on Apple Silicon). **Windows is not
planned.** This is a server-side cache that
lives next to your CI runners; there's no meaningful market for a Windows
build. If you develop on Windows, run the server under WSL2 — that's
`linux/amd64`.

## Which archive do I need?

```sh
# Prints e.g. "linux_arm64" — the exact string in the archive name.
echo "$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
```

`uname -m` reports `aarch64` on 64-bit ARM Linux and `x86_64` on Intel/AMD.
If the command prints `darwin_...`, you are on a Mac: there is no archive for
it, use the container image.

## Install

```sh
# Resolve the current release — anonymous, no gh auth needed.
VERSION=$(curl -fsSL https://api.github.com/repos/fosterstack/cache/releases/latest \
            | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')

PLATFORM=linux_amd64   # or the output of the command above
BIN=fscache            # use fscache-fips for the FIPS build (Linux only)

curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VERSION}/${BIN}_${VERSION}_${PLATFORM}.tar.gz"
tar xzf "${BIN}_${VERSION}_${PLATFORM}.tar.gz"
sudo install -m 0755 "${BIN}" "/usr/local/bin/${BIN}"

"${BIN}" &                                   # starts on :8080 by default
curl -fsS localhost:8080/healthz             # -> ok
```

`BIN` carries through every command on this page, including the systemd unit
below. Set it once and the standard and FIPS paths are the same instructions.

The FIPS build keeps `-fips` in its filename, its install path, and its process
name on purpose: which build is running stays visible in `ps`, in the unit file,
and to anyone auditing the host, rather than being recoverable only from logs.

Then point your build tool at it: [Gradle setup](gradle.md) ·
[Maven setup](maven.md).

To move to another version later, see [upgrading and pinning](upgrading.md).

## Verify what you downloaded

Do this before you install it, not after. Every release ships a
`checksums.txt` covering all four archives plus a cosign keyless signature
bundle over that file:

```sh
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VERSION}/checksums.txt"
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VERSION}/checksums.txt.bundle"

cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum -c checksums.txt 2>/dev/null | grep OK
```

The signature proves the checksums file was signed by this repo's Release
stage (`stage-promote.yml`) at this release's tag; the checksums then cover every archive transitively. Full detail,
including image signatures and SLSA provenance, is in
[Verify our images](verify-images.md).

## Run it as a service (systemd)

If the unit fails with `status=203/EXEC`, `ExecStart` points at a path that does
not exist — almost always the FIPS build installed as `fscache-fips` while the
unit still names `fscache`. The two must match.


```ini
[Unit]
Description=FosterStack Cache
After=network.target

[Service]
ExecStart=/usr/local/bin/fscache          # fscache-fips for the FIPS build — must match what you installed
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
