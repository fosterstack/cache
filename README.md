# FosterStack Cache

[![CI](https://github.com/fosterstack/cache/actions/workflows/ci.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/ci.yml)
[![CodeQL](https://github.com/fosterstack/cache/actions/workflows/codeql.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fosterstack/cache/badge)](https://scorecard.dev/viewer/?uri=github.com/fosterstack/cache)

A self-hosted, drop-in remote build cache for **Gradle** and **Maven** — a
single small static binary, MIT-licensed, patched forever. (Signed,
verifiable release artifacts are the release pipeline's job, not built
yet — see Status below; nothing to verify exists today, so this line
doesn't claim it does.)

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
  govulncheck, CodeQL, dependency review on PRs, OpenSSF Scorecard.
- 🚧 Not yet shipped: container image / release pipeline, one-command
  Docker deploy, Maven and Gradle setup docs, FIPS build variant. Tracked
  in this repo's issues as they land — see [`RELEASING.md`](RELEASING.md)
  for how releases will be built (CI only, never from a developer
  machine).

Full core (eviction, size limits, metrics) is free forever under MIT — see
[`LICENSE`](LICENSE). Paid tiers add SSO, HA/replication, a documented CVE
SLA, and compliance artifacts on top of the same open core; nothing is
withheld from the free tier for security.

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
Apache extension's standard pattern. A full "Maven in 10 minutes" walkthrough
is coming; the server-side pieces (`GET`/`PUT`/`HEAD`, Basic Auth) are
implemented and tested today.

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
