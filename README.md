# FosterStack Cache

[![CI](https://github.com/fosterstack/cache/actions/workflows/ci.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/ci.yml)
[![CodeQL](https://github.com/fosterstack/cache/actions/workflows/codeql.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fosterstack/cache/badge)](https://scorecard.dev/viewer/?uri=github.com/fosterstack/cache)
[![Latest release](https://img.shields.io/github/v/release/fosterstack/cache?sort=semver)](https://github.com/fosterstack/cache/releases/latest)

A self-hosted, drop-in remote build cache for **Gradle** — and for **Maven**
through the Apache Maven Build Cache Extension (implemented; acceptance
coverage in progress). Ships as
a single static binary or a distroless container image, MIT-licensed, with
security patches under a standing policy ([SECURITY.md](SECURITY.md)). Every
image is keylessly signed (Sigstore); every binary archive is covered by a
signed checksums file; both carry SLSA provenance naming the CI run that built
them. ["Verifying a release"][releasing-verify] has the commands.

**Website:** [fosterstack.com](https://fosterstack.com) · **Docs:**
[Install](docs/install.md) · [Docker](docs/docker-deploy.md) ·
[Kubernetes](docs/kubernetes.md) · [Gradle](docs/gradle.md) ·
[Maven](docs/maven.md)

[releasing-verify]: RELEASING.md#verifying-a-release

## Why this exists

Gradle Inc. is discontinuing the free, standalone [Develocity Build Cache
Node][bcn-eol] — no further distribution, support, or updates after
**December 31, 2026**. Teams running the free cache node on open-source
Gradle (no Develocity subscription) need a maintained, drop-in replacement.
FosterStack Cache speaks Gradle's documented [`HttpBuildCache`][gradle-http]
protocol (a plain content-addressed `GET`/`PUT` over HTTP) and the [Apache
Maven Build Cache Extension][maven-cache]'s remote HTTP mode
(`GET`/`PUT`/`HEAD`) — same server, same core. The Gradle path is
acceptance-tested against a real multi-module build in CI; the Maven path is
implemented and its acceptance coverage is in progress.

[bcn-eol]: https://docs.develocity.ai/bcn/21.2/
[gradle-http]: https://docs.gradle.org/current/userguide/build_cache.html#sec:build_cache_configure_remote
[maven-cache]: https://maven.apache.org/extensions/maven-build-cache-extension/

## Status

Shipped:

- Cache server core: content-addressed filesystem blob store, `bbolt`
  metadata index, size-capped LRU eviction — all tested.
- HTTP surface: `GET`/`PUT`/`HEAD`, optional Basic Auth, Prometheus
  metrics at `/metrics`, liveness at `/healthz`.
- `CGO_ENABLED=0` static binary — builds and runs today (see below).
- CI on every push/PR: tests (race-enabled), `go vet`, golangci-lint
  (staticcheck + a repo-wide `crypto/md5`/`crypto/sha1` import ban), gosec,
  govulncheck, CodeQL, dependency review on PRs, OpenSSF Scorecard, and a
  public-repo file allowlist.
- Release pipeline: signed, provenance-attested container images
  (production, `-debug`, `-fips`) on GHCR, plus bare binaries and a signed
  checksums file. Every release is built only by CI. A pre-publish snapshot
  build is scanned by every scanner in the repo's list; the published images
  are a separate build of the same commit and are covered by the daily
  rescan. [`RELEASING.md`](RELEASING.md) describes the pipeline as it is,
  including that gap.
- Acceptance-tested against a real multi-module Gradle project on every
  push/PR — a from-scratch second build must produce real `FROM-CACHE`
  hits, with the sample's local build cache disabled so a hit is remote
  evidence. There is no benchmark suite yet; this is a correctness gate,
  not a performance number.
- Deployment docs: [Install](docs/install.md) (binaries + systemd),
  [Docker](docs/docker-deploy.md) (with sizing),
  [Kubernetes](docs/kubernetes.md), [Gradle](docs/gradle.md),
  [Maven](docs/maven.md), and
  [disconnected networks](docs/offline-install.md).

Not yet shipped:

- **Production use beyond our own CI.** Nobody is running this in a real
  build pipeline yet except us.
- **A Helm chart.** Deploying to Kubernetes today means applying the plain
  manifests in [docs/kubernetes.md](docs/kubernetes.md).
- **The paid tiers.** Single sign-on, high-availability replication, and
  the license key that unlocks them are not built. Everything in this
  repository is the free MIT core.
- **A CVE patch commitment you can hold us to.** We aim to ship fixes for
  dependency CVEs within 48 hours of public disclosure. That is a stated
  intention, not a contractual promise, and it will not be one until the
  paid tiers exist. What already runs today is the detection half: every
  published image is rescanned daily, so a CVE disclosed against bytes we
  already shipped raises an issue without anyone remembering to look.

Tracked in this repo's issues, which is also where the roadmap gets argued
with. There is no published schedule: the list above is direction, not dates.

There is no waitlist and no signup. Pull the image and run it — the quickstart
below is the whole gate.

Each item above names the workflow or command that demonstrates it —
Actions history for the CI claims, the commands in
[`RELEASING.md`](RELEASING.md) for signatures and provenance. What those
commands prove, and what they do not, is stated in RELEASING.md itself.

Full core (eviction, size limits, metrics) is free forever under MIT — see
[`LICENSE`](LICENSE). Paid tiers add SSO, HA/replication, a documented CVE
SLA, and compliance support on top of the same open core; nothing is
withheld from the free tier for security.

The security evidence itself is public and free: SBOMs, SLSA provenance,
signatures, VEX statements, and the FIPS 140-3 module certificate number are
published with every release and verifiable by anyone, with no account and
no purchase. Scan verdicts are visible in the public CI logs; they are not
yet attached to releases as durable, digest-bound evidence. The FIPS-mode image is publicly pullable too.
What the Compliance tier sells is the authored analysis, the vendor signature,
and the hours — never access to the bytes or the evidence.

## Quickstart (Docker)

```sh
docker run -d -p 8080:8080 ghcr.io/fosterstack/cache:latest
curl localhost:8080/healthz   # -> ok
```

Pin a specific version for anything beyond a first look — the badge above
shows the current one, and [`docs/docker-deploy.md`](docs/docker-deploy.md)
covers pinning by digest.

That's the whole install. No registration, no license key for the
Community tier — pull, run, point your build tool at it (below).

## Supported platforms

Every release builds this whole matrix from the same source in the same CI
run — there is no primary platform.

| Artifact | Platforms |
|---|---|
| Binaries (`fscache`) | `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64` |
| FIPS binaries (`fscache-fips`) | `linux/amd64`, `linux/arm64` |
| Container images (prod, `-debug`, `-fips`) | multi-arch: `linux/amd64` + `linux/arm64` |

### Image variants

| Tag | Shell | Use |
|---|---|---|
| `X.Y.Z` | none | Production |
| `X.Y.Z-debug` | busybox at `/busybox/sh` | Interactive troubleshooting |
| `X.Y.Z-fips` | none | Production, FIPS 140-3 validated crypto module |

Production and `-fips` are distroless: the `fscache` binary and nothing
else, so there is no shell to exec into and no package manager to patch.
`:debug` adds busybox for troubleshooting, and its shell is at
**`/busybox/sh`** — distroless has no `/bin/sh`, unlike Debian, Alpine or
Wolfi. See
[the variant docs](docs/verify-images.md#the-images-have-no-shell-and-debugs-is-not-where-you-expect)
and [troubleshooting](docs/docker-deploy.md#troubleshooting-with-the-debug-image).

FIPS is Linux-only on purpose: the compliance buyer it serves deploys on
Linux, so a macOS FIPS build would double CI time for a configuration nobody
assesses. Container images ship as multi-arch manifests, so `docker pull`
resolves the right image by itself on Apple Silicon and Graviton. Windows is
not built and not planned — this is a server that lives next to your CI
runners; develop on Windows via WSL2, which is `linux/amd64`.

Full install instructions, including which archive to download and a systemd
unit: **[docs/install.md](docs/install.md)**.

## Build and run from source

```sh
git clone https://github.com/fosterstack/cache.git
cd cache
CGO_ENABLED=0 go build -o fscache ./cmd/fscache
./fscache
```

Configuration is via environment variables (flags are not yet wired):

| Variable | Default | Meaning |
|---|---|---|
| `FSCACHE_ADDR` | `:8080` | Listen address |
| `FSCACHE_DATA_DIR` | `./data` | Where blobs and the metadata index live |
| `FSCACHE_MAX_BYTES` | `0` (unbounded) | Size cap; oldest-unused entries evicted first |
| `FSCACHE_USERNAME` / `FSCACHE_PASSWORD` | unset (auth disabled) | HTTP Basic Auth, required together |
| `FSCACHE_RO_USERNAME` / `FSCACHE_RO_PASSWORD` | unset | Optional read-only pair: `GET`/`HEAD` only, writes get 403. Requires the read-write pair; usernames must differ |
| `FSCACHE_MAX_BODY_BYTES` | `1073741824` (1 GiB) | Max accepted blob size per `PUT` |

## Gradle setup

In `settings.gradle` / `settings.gradle.kts`, point the remote cache at
your server (the whole request path is the cache key, so a trailing slash
on the URL is all that's needed):

```kotlin
buildCache {
    remote<HttpBuildCache> {
        url = uri("https://cache.example.com/")
        isPush = true
        // credentials { username = "..."; password = "..." } // if auth is enabled
    }
}
```

## Maven setup

Basic Auth credentials come from `settings.xml` `<server>` conventions, the
Apache extension's standard pattern. See [Maven setup in 10 minutes](docs/maven.md)
for the full walkthrough.

## Product promises and proof

Every externally observable behavior of this server is a written requirement
with measurable acceptance criteria, and the matrix at
[docs/quality/traceability.md](docs/quality/traceability.md) maps each
criterion to its evidence — including, honestly, the criteria that have no
sufficient evidence yet. The baseline was extracted from the code and docs
and owner-approved; since Sep 8, 2026, acceptance criteria are written
before implementation. CI fails if the matrix drifts from its sources.

## Documentation

- [Gradle setup](docs/gradle.md) · [Maven setup](docs/maven.md)
- [Migrate off Build Cache Node in 30 minutes](docs/migrate-from-bcn.md)
- [Install (binaries, systemd, platforms)](docs/install.md)
- [One-command Docker deploy](docs/docker-deploy.md) · [Deploying on Kubernetes](docs/kubernetes.md)
- [Installing on disconnected networks](docs/offline-install.md)
- [Verify our images](docs/verify-images.md) · [Scanning FosterStack in your compliance pipeline](docs/scanning.md)
- [Releasing](RELEASING.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Security

- Static binary, zero CGO, no OS package surface to patch.
- Approved-only cryptography is enforced by the validated module itself, not
  by a list: CI runs the full test suite under `GODEBUG=fips140=only`, where
  Go's FIPS 140-3 module refuses any non-approved algorithm at runtime. A
  `depguard` allowlist covers the static side, permitting only in-boundary
  crypto imports and denying third-party crypto outright. Both are described
  in [`SECURITY.md`](SECURITY.md), including what each does and does not
  prove.
- **No telemetry and no required FosterStack connection.** The server
  reports nothing to us — no usage reporting, no licence check, no update
  ping — and today's free core initiates no outbound connections at all, so
  it runs identically on a host with no route to the internet. When paid
  features ship, traffic you configure will exist (an identity provider for
  SSO, peer replicas for replication) — connections to endpoints you
  choose, never to FosterStack. Check the current behavior yourself:
  `lsof -nP -a -p <pid> -i` against a running server shows one listening
  socket and accepted inbound connections, nothing else.
- See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure process
  and patch SLA once published.

## License

MIT — see [`LICENSE`](LICENSE).
