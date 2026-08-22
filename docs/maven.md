# Maven setup in 10 minutes

FosterStack Cache speaks the [Apache Maven Build Cache Extension][mvn-ext]'s
remote HTTP mode directly — `GET`/`PUT`/`HEAD` against a plain HTTP
endpoint, which is exactly what our server implements. The client side is
Apache's; we maintain the server. If a specific project's cache-hit rate
looks off, that's usually the extension's own project-configuration
tuning, not something to file against this repo — see "Support boundary"
below.

[mvn-ext]: https://maven.apache.org/extensions/maven-build-cache-extension/

## 1. Enable the extension

In `.mvn/extensions.xml` (create the file if it doesn't exist):

```xml
<extensions>
  <extension>
    <groupId>org.apache.maven.extensions</groupId>
    <artifactId>maven-build-cache-extension</artifactId>
    <version>1.3.0</version>
  </extension>
</extensions>
```

Check [Maven Central](https://search.maven.org/artifact/org.apache.maven.extensions/maven-build-cache-extension)
for the current version.

## 2. Point it at your FosterStack Cache server

Create `.mvn/maven-build-cache-config.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<cache xmlns="http://maven.apache.org/BUILD-CACHE-CONFIG/1.2.0"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://maven.apache.org/BUILD-CACHE-CONFIG/1.2.0 https://maven.apache.org/xsd/build-cache-config-1.2.0.xsd">
  <configuration>
    <enabled>true</enabled>
  </configuration>
  <!-- Default @id is "cache" if omitted -->
  <remote enabled="true" id="fosterstack-cache">
    <url>https://cache.example.com/</url>
  </remote>
</cache>
```

Replace `https://cache.example.com/` with your server's URL — a trailing
slash matters (the extension appends its own path segments to it, same as
Gradle's config: see [Gradle setup](gradle.md)).

## 3. Credentials (if Basic Auth is enabled on your server)

In `~/.m2/settings.xml` (or your CI system's equivalent), matching the
`id` you chose above:

```xml
<settings>
  <servers>
    <server>
      <id>fosterstack-cache</id>
      <username>maven</username>
      <password>your-password-or-CI-secret</password>
    </server>
  </servers>
</settings>
```

The `<server>` `id` must match the `<remote id="...">` from step 2. If
your server has `FSCACHE_USERNAME`/`FSCACHE_PASSWORD` unset (the default —
open, self-hosted-on-a-trusted-network posture), skip this step entirely.

## 4. Build

```sh
mvn install
```

First run populates the cache; subsequent runs from a clean checkout (or
`mvn clean install`) should show cache hits in the build log for
unchanged modules.

## Support boundary

We maintain FosterStack Cache's server side: the `GET`/`PUT`/`HEAD`
protocol implementation, auth, eviction, metrics. The **client side —
the Apache Maven Build Cache Extension itself — is Apache's project**, not
ours. Cache-hit quality (how often the extension correctly recognizes a
module hasn't changed) depends on the extension's own project-specific
tuning (skip-cache rules, glob configuration for what counts as an input)
— that's the same variability you'd see against any remote cache backend,
including Apache's own reference setups (Nexus raw repository, Artifactory
generic repository, nginx with the `fs` module). If your hit rate looks
wrong, the extension's own [configuration reference][mvn-ext] is the right
place to start, not an issue against this repo.

## Positioning

FosterStack Cache is, as far as we've found, the only maintained,
purpose-built remote-cache **server** for Maven — the alternative is
Develocity's Maven extension, which requires a full Develocity
subscription (same ~$17.5k/yr+ floor as their Gradle offering). If you're
already running FosterStack Cache for Gradle, pointing Maven modules at
the same server (mixed Gradle+Maven shops, one deploy) is the whole
pitch: "one self-hosted cache server for Gradle **and** Maven."
