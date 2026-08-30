# FosterStack Cache

[![CI](https://github.com/fosterstack/cache/actions/workflows/ci.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/ci.yml)
[![CodeQL](https://github.com/fosterstack/cache/actions/workflows/codeql.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fosterstack/cache/badge)](https://scorecard.dev/viewer/?uri=github.com/fosterstack/cache)

A self-hosted, drop-in remote build cache for **Gradle** and **Maven** — a
single small static binary, MIT-licensed, patched forever, and verifiable:
every release is signed keylessly (Sigstore/cosign) and carries a SLSA
provenance attestation proving which CI run built it. See
["Verifying a release"][releasing-verify] for the exact commands — they're
copy-pasteable against `v0.1.0` right now, not aspirational.

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
(`GET`/`PUT`/`HEAD`), so it's a drop-in for both build tools — same server,
same core.

[bcn-eol]: https://docs.develocity.ai/bcn/21.2/
[gradle-http]: https://docs.gradle.org/current/userguide/build_cache.html#sec:build_cache_configure_remote
[maven-cache]: https://maven.apache.org/extensions/maven-build-cache-extension/

## Status

Sprint 4, in progress. What's real today:

- ✅ Cache server core: content-addressed filesystem blob store, `bbolt`
  metadata index, size-capped LRU eviction — all tested.
- ✅ HTTP surface: `GET`/`PUT`/`HEAD`, optional Basic Auth, Prometheus
  metrics at `/metrics`, liveness at `/healthz`.
- ✅ `CGO_ENABLED=0` static binary — builds and runs today (see below).
- ✅ CI on every push/PR: tests (race-enabled), `go vet`, golangci-lint
  (staticcheck + a repo-wide `crypto/md5`/`crypto/sha1` import ban), gosec,
  govulncheck, CodeQL, dependency review on PRs, OpenSSF Scorecard, and a
  public-repo file allowlist.
- ✅ Release pipeline live (`v0.1.0`): signed, provenance-attested
  container images (production, `-debug`, `-fips`) on GHCR, plus bare
  binaries + checksums. See [`RELEASING.md`](RELEASING.md).
- ✅ Benchmarked against a real multi-module Gradle project on every
  push/PR — the gate is a correctness assertion (a from-scratch second
  build must produce real `FROM-CACHE` hits), not just a timing number.
- ✅ Deployment docs: [Install](docs/install.md) (binaries + systemd),
  [Docker](docs/docker-deploy.md) (with sizing),
  [Kubernetes](docs/kubernetes.md), [Gradle](docs/gradle.md),
  [Maven](docs/maven.md), and
  [disconnected networks](docs/offline-install.md).
- 🚧 Not yet shipped: private beta on real external CI, a Helm chart, and
  the paid-tier features (SSO, HA/replication, license-key validation).
  The CVE patch SLA is a roadmap commitment, not yet a live promise.
  Tracked in this repo's issues as they land.

**On the claims above:** anything marked ✅ is something you can verify
yourself from this repo's Actions history or by running the commands in
[`RELEASING.md`](RELEASING.md). We would rather carry a ⚠️ than describe a
control that has never actually run — a security claim you can't reproduce
is worth less than no claim.

Full core (eviction, size limits, metrics) is free forever under MIT — see
[`LICENSE`](LICENSE). Paid tiers add SSO, HA/replication, a documented CVE
SLA, and compliance artifacts on top of the same open core; nothing is
withheld from the free tier for security.

## Quickstart (Docker)

```sh
docker run -d -p 8080:8080 ghcr.io/fosterstack/cache:0.1.0
curl localhost:8080/healthz   # -> ok
```

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
- `crypto/md5` and `crypto/sha1` are banned imports, repo-wide, enforced in
  CI (`golangci-lint` `depguard`) regardless of intended use — SHA-256 is
  the only hash this codebase is allowed to reach for if a future feature
  needs one.
- See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure process
  and patch SLA once published.

## License

MIT — see [`LICENSE`](LICENSE).
