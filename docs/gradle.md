# Gradle setup

FosterStack Cache implements Gradle's documented [`HttpBuildCache`
protocol][gradle-http] directly — a plain content-addressed `GET`/`PUT`
over HTTP, computed and requested by Gradle itself. There's nothing
FosterStack-specific in the client config below; this is standard Gradle
pointed at a self-hosted endpoint instead of Develocity.

[gradle-http]: https://docs.gradle.org/current/userguide/build_cache.html

## 1. Enable the build cache and point it at your server

In `settings.gradle.kts`:

```kotlin
buildCache {
    remote<HttpBuildCache> {
        url = uri("https://cache.example.com/")
        isPush = true
    }
}
```

Or `settings.gradle` (Groovy):

```groovy
buildCache {
    remote(HttpBuildCache) {
        url = 'https://cache.example.com/'
        push = true
    }
}
```

The trailing slash on the URL matters — Gradle appends the cache key
directly onto it, and our server treats the whole request path as the
key, so no extra path prefix configuration is needed on either side.

## 2. Credentials (if Basic Auth is enabled on your server)

```kotlin
buildCache {
    remote<HttpBuildCache> {
        url = uri("https://cache.example.com/")
        isPush = true
        credentials {
            username = "gradle"
            password = System.getenv("FSCACHE_PASSWORD")
        }
    }
}
```

If your server has `FSCACHE_USERNAME`/`FSCACHE_PASSWORD` unset (the
default — open, self-hosted-on-a-trusted-network posture), skip this
block entirely.

## 3. Push vs. pull-only

`isPush = true` everywhere is the simplest starting point and matches how
FosterStack Cache is meant to be run (a private, self-hosted cache with
no untrusted writers). If you want only CI to populate the cache and
developer machines to read-only, gate it the standard Gradle way:

```kotlin
buildCache {
    remote<HttpBuildCache> {
        url = uri("https://cache.example.com/")
        isPush = System.getenv("CI") != null
    }
}
```

## 4. Verify it's actually being used

```sh
./gradlew build --build-cache
```

Gradle prints a task-execution summary; look for `FROM-CACHE` next to
tasks that didn't need to re-run. This repo's own CI does exactly that
against a real (if small) multi-module project on every push — see
[`.github/workflows/benchmark.yml`](../.github/workflows/benchmark.yml)
and [`bench/gradle-sample/`](../bench/gradle-sample/) for a worked,
runnable example: a from-scratch second build asserting real
`FROM-CACHE` hits, not just a timing claim.

## Local-only quickstart, if you just want to try it

```sh
docker run -d -p 8080:8080 ghcr.io/fosterstack/cache:0.1.0
```

Point `buildCache.remote.url` at `http://localhost:8080/` and build.

## Migrating from the deprecated Build Cache Node

If you're currently running Gradle's own
[`gradle/build-cache-node`][bcn-hub] Docker image, see
["Migrate off Build Cache Node in 30 minutes"](migrate-from-bcn.md) —
the config change above is most of it.

[bcn-hub]: https://hub.docker.com/r/gradle/build-cache-node
