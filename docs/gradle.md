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
also treats remote-cache failures as non-fatal by design, so a misconfigured
remote fails **silently** at the default log level — no error, no warning, just
a build that quietly doesn't use the cache. Run with `-i` when you want to see
what the remote is actually doing.

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
credential-less client produce silent 401s (see §5).

## 3. Trying it out without TLS

The examples above use `https://` deliberately. Real deployments terminate TLS
at a proxy, ingress, or load balancer, and Gradle sends Basic Auth credentials
preemptively — over plain HTTP they go out in cleartext to whatever answers.

For a throwaway test rig against a bare IP, Gradle needs an explicit opt-out.
It refuses non-localhost plain HTTP without it:

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

`System.getenv` reads the environment of the **Gradle daemon**, which snapshots
it at startup and outlives your shell. So an `export FSCACHE_PASSWORD=...` works
all week and fails after a reboot, and a fresh `export` does not reliably reach
a daemon that's already running.

Two fixes, in order of durability:

1. **Put it in your user `gradle.properties`** — `~/.gradle/gradle.properties`,
   never the one in the repo, and never committed:

   ```properties
   # ~/.gradle/gradle.properties
   fscachePassword=...
   ```
   ```kotlin
   password = providers.gradleProperty("fscachePassword").orNull
   ```

2. **After changing the environment, restart the daemon**: `./gradlew --stop`.

This failure is **silent** by default, for the reason in §6: a warm local cache
serves hits regardless of whether the remote is working, so the build still
looks fast while the remote 401s on every request.

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
./gradlew build --build-cache -i          # -i surfaces remote errors
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
docker run -d -p 8080:8080 ghcr.io/fosterstack/cache:latest
```

Point `buildCache.remote.url` at `http://localhost:8080/` and build. localhost
is exempt from Gradle's plain-HTTP guard, so no `allowInsecureProtocol` is
needed here.

## Migrating from the deprecated Build Cache Node

If you're currently running Gradle's own
[`gradle/build-cache-node`][bcn-hub] Docker image, see
["Migrate off Build Cache Node in 30 minutes"](migrate-from-bcn.md) —
the config change above is most of it.

[bcn-hub]: https://hub.docker.com/r/gradle/build-cache-node
