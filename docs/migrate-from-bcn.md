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
That's why this category of infrastructure is fail-safe against ordinary
availability failures: if the cache is down, unreachable, or empty, the
worst case is a slower build, never a correctness problem or lost work.
So "migration" here means: stand up the new server, point Gradle at it,
done.

That fail-safe claim is scoped to availability, deliberately. A cache that
serves *wrong bytes* — because something untrusted could write to it — is a
different failure class entirely, which is what the next paragraph is about.

## Who may write to your cache

Treat the cache as part of your build's supply chain, because it is: any
writer can influence what later builds consume as task outputs. Two rules
follow. Run it with Basic Auth anywhere untrusted parties could reach the
port, and share the credential only with CI and developers you already
trust to write code. And know what the client-side "push disabled" setting
is: `isPush = false` in a Gradle config is that *client* volunteering not to
upload — it is not a server-side permission, and any client holding the
credential can still write. Today the server has one credential and one
permission level; a real server-side split (read-only clients, per-writer
identity) is tracked as issue #8 and specified as a requirement before it
is built.

## Step by step

**1. Stand up FosterStack Cache** (replaces however you're currently
running the Build Cache Node container):

```sh
docker run -d -p 8080:8080 -v fscache-data:/home/nonroot ghcr.io/fosterstack/cache:latest
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

## The trade

### What you give up

The free Build Cache Node had a small web UI — status, usage, settings, and a
purge button. FosterStack Cache has no equivalent settings page, and that is a
deliberate choice rather than a missing feature.

Configuration is flags and environment variables only, so the running server
always matches the deployment manifest in your git repository: diffable,
reviewable, and with no drift between what is deployed and what is described.
It also means there is no mutable admin surface for whoever finds the port —
and an unpatched, forgotten appliance with a web console is the exact failure
this project exists to replace.

What replaces the UI:

- **`/statusz`** — a read-only status page: version, uptime, cache size against
  the configured cap, entry count, hit and miss counts. Readable in a browser
  or as JSON. It sits behind Basic Auth when auth is enabled.
- **`/metrics`** — the full Prometheus set, plus a
  [Grafana dashboard](grafana-dashboard.json) in this repository.
- **Purging** is `docker compose down -v && docker compose up -d`, or deleting
  the PVC on Kubernetes — declarative and auditable, rather than a button
  anyone with the page open can press. See
  [Resetting the cache](docker-deploy.md#resetting-the-cache).

### What you get that the free BCN never had

FosterStack Cache adds (all in the free MIT core — nothing here is paywalled):

- Size-capped LRU eviction (the free BCN required manual size management)
- Prometheus metrics
- A documented, active patch cadence — see
  [Scanning FosterStack in your compliance pipeline](scanning.md) and
  [Verify our images](verify-images.md) for the evidence trail
- Maven support in the same server, if you're a mixed Gradle+Maven shop
  (see [Maven setup](maven.md))

Paid tiers (Team/Business/Compliance) add SSO, HA/replication, a
documented 24–48h CVE response SLA, and compliance support on top of the
same core — see the pricing page. Security patches are never withheld
from the free tier.

The security evidence itself is public and free: SBOMs, SLSA provenance,
signatures, scan results, VEX statements, and the FIPS 140-3 module
certificate number ship with every release and are verifiable by anyone, with
no account and no purchase. The FIPS-mode image is publicly pullable too. What
the Compliance tier sells is the authored analysis — a FIPS applicability
statement mapping the validated module boundary onto this product — plus
per-release attestation letters signed by FosterStack LLC, and time on your
security questionnaires.

FosterStack Cache is not "FedRAMP compliant" or "CMMC compliant". Those attach
to your service and your organization, never to a component you deploy. This is
validated crypto and publishable evidence **for** your compliance program.
