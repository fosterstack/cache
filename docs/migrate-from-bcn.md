# Migrate off Build Cache Node in 30 minutes

Gradle Inc. has deprecated the free, standalone Develocity Build Cache
Node — no further distribution, support, or updates after
**December 31, 2026** ([official notice][bcn-eol]). If you're running the
free `gradle/build-cache-node` image with plain open-source Gradle (no
Develocity subscription), this is the drop-in replacement: same protocol,
same self-hosted model, actively maintained.

[bcn-eol]: https://docs.develocity.ai/bcn/21.2/

## The short version

There is no data to migrate. A build cache is disposable by design — every
entry is reproducible from source, so an empty cache on day one just means
your first build after cutover repopulates it (same as any cold cache).
That's the whole reason this category of infrastructure is fail-safe:
worst case is a slower build, never a correctness problem or lost work.
So "migration" here means: stand up the new server, point Gradle at it,
done.

## Step by step

**1. Stand up FosterStack Cache** (replaces however you're currently
running the Build Cache Node container):

```sh
docker run -d -p 8080:8080 -v fscache-data:/home/nonroot ghcr.io/fosterstack/cache:0.1.0
```

(The volume mounts at `/home/nonroot`, not `/data` — see
[One-command Docker deploy](docker-deploy.md#the-one-command) for why, and
for the compose form.)

Or as a systemd-managed bare binary — see
[Install FosterStack Cache](install.md) for that path; it applies whether or
not you're air-gapped, and it lists which archive to grab for your platform.

**2. Update your Gradle config.** Wherever `settings.gradle(.kts)`
currently points at your Build Cache Node's URL, change only the URL (the
protocol is the same `HttpBuildCache` either way — see
[Gradle setup](gradle.md) for the full config):

```kotlin
buildCache {
    remote<HttpBuildCache> {
        url = uri("https://your-new-fosterstack-cache-url/")
        isPush = true
    }
}
```

**3. Retire the old Build Cache Node container** once you've confirmed
builds are hitting the new server (see verification below). No data
export step — see "The short version" above.

**4. Confirm it's working:**

```sh
./gradlew clean build --build-cache
```

Look for `FROM-CACHE` in the task summary on a second run against
unchanged sources.

## Why now, not December 31

The incumbent image has been unpatched since June 2025 — 2 critical and 8
high-severity known CVEs as of this writing, and that count only grows
while it sits frozen. Every scanner-gated pipeline (Trivy, Snyk, and
similar tools failing builds on known-vulnerable images) that touches that
image is already accruing findings today, not on the EOL date. Moving
earlier means moving on your own schedule instead of during a January
scramble.

## What you get that the free BCN never had

The free Build Cache Node was a dumb HTTP endpoint. FosterStack Cache adds
(all in the free MIT core — nothing here is paywalled):

- Size-capped LRU eviction (the free BCN required manual size management)
- Prometheus metrics
- A documented, active patch cadence — see
  [Scanning FosterStack in your compliance pipeline](scanning.md) and
  [Verify our images](verify-images.md) for the evidence trail
- Maven support in the same server, if you're a mixed Gradle+Maven shop
  (see [Maven setup](maven.md))

Paid tiers (Team/Business/Compliance) add SSO, HA/replication, a
documented 24–48h CVE response SLA, and compliance artifacts on top of the
same core — see the pricing page. Security patches are never withheld
from the free tier.
