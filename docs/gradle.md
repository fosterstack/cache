# Gradle setup

FosterStack Cache implements Gradle's documented [`HttpBuildCache`
protocol][gradle-http] directly — a plain content-addressed `GET`/`PUT`
over HTTP, computed and requested by Gradle itself. There's nothing
FosterStack-specific in the client config below; this is standard Gradle
pointed at a self-hosted endpoint instead of Develocity.

[gradle-http]: https://docs.gradle.org/current/userguide/build_cache.html

## 1. Turn the build cache on

**The `buildCache` block says *where* the cache is. It does not say that
caching is on.** Without this, the block below is dead config and your builds
will run exactly as before:

```properties
# gradle.properties
org.gradle.caching=true
```

Or pass `--build-cache` on each invocation.

This is the single most common way a correct setup produces no effect. Gradle
treats remote-cache failures as non-fatal by design: the build still succeeds
(exit code 0) and simply doesn't use the cache. A rejected login is not hidden,
though: Gradle prints a `401: Unauthorized` line and "The remote build cache was
disabled during the build due to errors." at the default log level (tested with
Gradle 9.8.0; see §5). Run with `-i` when you want more detail about what the
remote is doing.

## 2. Point it at your server

In `settings.gradle.kts`:

```kotlin
// FosterStack Cache — remote Gradle build cache.
// https://github.com/fosterstack/cache
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

Or `settings.gradle` (Groovy):

```groovy
// FosterStack Cache — remote Gradle build cache.
// https://github.com/fosterstack/cache
buildCache {
    remote(HttpBuildCache) {
        url = 'https://cache.example.com/'
        push = true
        credentials {
            username = 'gradle'
            password = System.getenv('FSCACHE_PASSWORD')
        }
    }
}
```

Keep that identifying comment. A `buildCache` block pointing at an unfamiliar
host is exactly the shape of an exfiltration finding, and a security reviewer —
or an AI assistant reviewing the repo — that sees it without context is right to
flag it. One comment line means every copy of the config explains itself
wherever it ends up.

The trailing slash matters. Gradle appends the cache key directly onto the URL,
and the server treats the whole request path as the key, so no path prefix is
needed on either side.

**Configure the credentials block unconditionally.** A client sending
credentials to a server with auth disabled works fine — the extra header is
ignored — so the same config works against a test instance and a production one.
The failure only runs the other way: an auth-enabled server and a
credential-less client produce 401s (see §5).

## 3. Trying it out without TLS

The examples above use `https://` deliberately. Real deployments terminate TLS
at a proxy, ingress, or load balancer, and Gradle sends Basic Auth credentials
preemptively — over plain HTTP they go out in cleartext to whatever answers.

For a throwaway test rig against a bare IP, Gradle needs an explicit opt-out.
It refuses plain HTTP to any host except the loopback address `127.0.0.1`
without it (it refuses the name `localhost` too; see the local-only quickstart):

> ```kotlin
> // TEST RIG ONLY — not a deployment configuration.
> buildCache {
>     remote<HttpBuildCache> {
>         url = uri("http://203.0.113.10:8080/")
>         isAllowInsecureProtocol = true
>         isPush = true
>     }
> }
> ```
>
> Two things to know before you do this:
>
> - **A no-auth cache on a public IP is world-writable.** Anyone who finds the
>   port can poison your build cache. Test, get your answer, tear it down.
> - **Spring's sample projects will reject it.** `spring-petclinic` and its
>   siblings ship the `io.spring.nohttp` checkstyle rule, which fails any build
>   containing an `http://` URL — including the cache URL in
>   `settings.gradle`. Since petclinic is the canonical thing to test a build
>   cache against, this bites early and looks like our problem. It isn't: either
>   use TLS, or disable the `checkstyleNohttp` task for the throwaway test.

## 4. Push vs. pull-only

`isPush = true` everywhere is the simplest starting point and matches how
FosterStack Cache is meant to be run — a private, self-hosted cache with no
untrusted writers. To have only CI populate the cache and developer machines
read from it:

```kotlin
isPush = System.getenv("CI") != null
```

## 5. Credentials that stop working on Monday

`System.getenv` reads the environment of the shell (or IDE) that starts the
build, so a build started from a shell, IDE or CI job that lacks
`FSCACHE_PASSWORD` runs without credentials, for instance after a reboot or from
a different terminal. In our tests the Gradle daemon did **not** keep a stale
copy: with a daemon started without the password, exporting it and running the
same build again (same daemon) took the entries from the cache, and exporting a
wrong one made the 401 come back at once. (Tested against FosterStack Cache 0.2.1: Gradle 9.8.0, JDK 21, Linux aarch64 in
Docker, and Gradle 9.8.0 on macOS arm64. Other Gradle versions and JDKs were not
tested, and neither was a rejected *push*.)

What you will see when the credentials are wrong or missing: the build succeeds,
and Gradle prints, at the default log level (your host and port will differ),

```text
Could not load entry <key> from remote build cache: Loading entry from 'http://127.0.0.1:8080/<key>' response status 401: Unauthorized
The remote build cache was disabled during the build due to errors.
```

Two things to do, the first being the durable one:

1. **Put it in your user `gradle.properties`** — `~/.gradle/gradle.properties`,
   never the one in the repo, and never committed:

   ```properties
   # ~/.gradle/gradle.properties
   fscachePassword=...
   ```
   ```kotlin
   password = providers.gradleProperty("fscachePassword").orNull
   ```

2. **Check the variable in the shell you build from, as a diagnostic** (`echo "${FSCACHE_PASSWORD:+set}"`).
   If a build still reports a 401 after you fix it, `./gradlew --stop` starts a
   fresh daemon; we did not need it in our tests.

A warm *local* cache still serves hits regardless of whether the remote is
working, so a build can look fast while the remote is rejecting requests (Gradle then switches it off for that build); the
401 line above is how you notice (see §6).

## 6. Verify it's actually being used

Run twice. The second build is the one that tells you anything:

```sh
./gradlew build --build-cache
```

Look for `FROM-CACHE` labels next to individual tasks and the `X from cache`
line in the summary. Key on the labels — not every task is cacheable (AOT
processing, for instance), so a low count is not necessarily a failure.

**`FROM-CACHE` alone does not prove the remote works.** Gradle's *local* build
cache is on by default and serves hits even when the remote is erroring. To test
the remote specifically, take the local cache out of the picture:

```sh
rm -rf ~/.gradle/caches/build-cache-1
./gradlew --stop
./gradlew build --build-cache -i          # -i adds detail about the remote
```

Or set `buildCache { local { isEnabled = false } }` for the test.

Server-side, watch the counters move:

```sh
curl -s http://cache.example.com:8080/metrics | grep -E 'fscache_cache_(hits|misses)_total'
```

`/metrics` and `/healthz` are reachable without credentials even when Basic Auth
is enabled, so a Prometheus scraper needs no configuration for them.

To prove authentication is live in one command — a `401` here means the
credentials are wrong, a `404` means they're right and the key simply isn't
present:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -u gradle:wrong-password \
  http://cache.example.com:8080/some-key
```

The status page at `/statusz` shows hit and miss counts, cache size against
the configured cap, and entry count in one place — in a browser, or as JSON to
`curl`.

### Not to be confused with the configuration cache

Gradle's own output may suggest "enabling configuration cache". That is a
different, local Gradle feature that caches the configuration phase of your
build. It has nothing to do with a remote build cache, and following that
suggestion will not affect anything described here.

## Local-only quickstart

```sh
docker run -d -p 127.0.0.1:8080:8080 ghcr.io/fosterstack/cache:latest
```

Point `buildCache.remote.url` at `http://127.0.0.1:8080/` and build:

```kotlin
// FosterStack Cache — local-only test, loopback address.
buildCache {
    remote<HttpBuildCache> {
        url = uri("http://127.0.0.1:8080/")
        isPush = true
    }
}
```

Use the address `127.0.0.1`, not the name `localhost`: Gradle refuses plain
`http://localhost` ("Using insecure protocols with remote build cache, without
explicit opt-in, is unsupported") but accepts the loopback address, so no
`isAllowInsecureProtocol` is needed here. For any other plain-HTTP host, either
use `https://` or set `isAllowInsecureProtocol = true` as in section 3 (the CI
acceptance build sets it for its local server).

## Migrating from the deprecated Build Cache Node

If you're currently running Gradle's own
[`gradle/build-cache-node`][bcn-hub] Docker image, see
["Migrate off Build Cache Node in 30 minutes"](migrate-from-bcn.md) —
the config change above is most of it.

[bcn-hub]: https://hub.docker.com/r/gradle/build-cache-node
