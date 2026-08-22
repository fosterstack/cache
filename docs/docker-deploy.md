# One-command Docker deploy

## The one command

```sh
docker run -d -p 8080:8080 -v fscache-data:/data ghcr.io/fosterstack/cache:0.1.0
```

That's a working, persistent (named volume) deployment. Point your build
tool at it — [Gradle setup](gradle.md) / [Maven setup](maven.md) — and
you're done.

## A slightly more real deployment (docker-compose)

```yaml
services:
  fscache:
    image: ghcr.io/fosterstack/cache:0.1.0
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - fscache-data:/data
    environment:
      FSCACHE_MAX_BYTES: "53687091200"   # 50 GiB — size to your CI volume
      # FSCACHE_USERNAME: gradle          # uncomment to require Basic Auth
      # FSCACHE_PASSWORD: change-me       # and set both together

volumes:
  fscache-data:
```

**No Docker-native `HEALTHCHECK` in the compose file above, on purpose:**
the image is `FROM scratch`-class distroless — no shell, no `curl`/`wget`,
no second binary inside the container to run a healthcheck command with.
A container-internal `HEALTHCHECK: [...]` directive would have nothing
valid to execute. Probe `/healthz` from *outside* the container instead —
your orchestrator's own HTTP healthcheck (Kubernetes `livenessProbe` with
`httpGet`, an external monitoring check, or `curl -f
http://localhost:8080/healthz` from the host/CI runner). This is a direct
consequence of the zero-CVE-surface design — see
[Scanning FosterStack in your compliance pipeline](scanning.md) for why
there's no shell in the image in the first place.

## Configuration

All configuration is environment variables (see the main
[README](../README.md#build-and-run-from-source) for the full table):
`FSCACHE_ADDR`, `FSCACHE_DATA_DIR` (already `/data` in the image, matching
the volume mount above), `FSCACHE_MAX_BYTES`, `FSCACHE_USERNAME` /
`FSCACHE_PASSWORD`, `FSCACHE_MAX_BODY_BYTES`.

## Sizing the cache volume

There's no universal answer — it depends on your build graph's total
cacheable-output size and how far back you want cache hits to reach.
Set `FSCACHE_MAX_BYTES` to whatever you provision the volume at; the
server evicts least-recently-used entries automatically once it's full,
never growing past the cap.

## Not a container shop? Bare binary + systemd

See ["Installing on disconnected networks"](offline-install.md) for the
bare-binary + systemd path — it's the same install whether or not you're
actually air-gapped.

## Verify what you're running

Before or after deploying, confirm the image is the real, signed,
attested thing — see [Verify our images](verify-images.md).
