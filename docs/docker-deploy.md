# One-command Docker deploy

## The one command

```sh
docker run -d -p 8080:8080 -v fscache-data:/home/nonroot ghcr.io/fosterstack/cache:0.1.0
```

That's a working, persistent (named volume) deployment. Point your build
tool at it — [Gradle setup](gradle.md) / [Maven setup](maven.md) — and
you're done.

**Why the volume mounts at `/home/nonroot` and not `/data`:** the image
sets no `FSCACHE_DATA_DIR`, so the server uses its default of `./data`,
resolved against the image's working directory `/home/nonroot` — i.e.
`/home/nonroot/data`. Mounting there is also what gets you a writable
volume for free: Docker seeds a *fresh* named volume with the ownership of
the image directory it covers, and `/home/nonroot` is owned by `65532`.
Mount a fresh named volume anywhere else — `/data` included — and Docker
creates it `root:root`, which the nonroot server cannot write to. If you
prefer an explicit `/data`, you must set `FSCACHE_DATA_DIR=/data` **and**
chown the volume first:

```sh
docker volume create fscache-data
docker run --rm -v fscache-data:/data busybox chown 65532:65532 /data
docker run -d -p 8080:8080 -v fscache-data:/data \
  -e FSCACHE_DATA_DIR=/data ghcr.io/fosterstack/cache:0.1.0
```

## Sizing

The server is a single static Go binary that idles in tens of megabytes.
On any of these, the operating system is most of the footprint — you are
sizing a disk, not a compute tier.

| | vCPU | RAM | Disk |
|---|---|---|---|
| **Absolute minimum** | 1 | 1 GB | cache cap + ~5 GB for OS/overhead |
| **Recommended start** (~5–20 devs + CI) | 1–2 | 2 GB | 25–50 GB SSD |
| **Larger CI farms** | 2–4 | 4–8 GB | cap + ~20% headroom |

Yes, it depends on your build graph — but if you are standing at a droplet
size picker right now, take the recommended row and move on. It is very
hard to be CPU-bound here: the hot path is a content-addressed blob read or
write, not computation.

**Disk is the real variable.** Size it from your eviction cap plus ~20%
headroom, not the other way round: set `FSCACHE_MAX_BYTES` (see
[Configuration](#configuration)) to the cap you want and provision the
volume above it. The server evicts least-recently-used entries once it
reaches the cap and never grows past it, so the headroom absorbs
filesystem overhead and in-flight uploads rather than runaway growth.
Leaving `FSCACHE_MAX_BYTES` at its `0` (unbounded) default on a small
volume is the one configuration that will fill your disk.

**At the larger end, the network matters more than the CPU.** Throughput
and round-trip latency between the cache and your CI runners set your hit
latency; a colocated 1 vCPU box beats a cross-region 8 vCPU one. Put the
server in the same region — ideally the same VPC — as the runners that
hammer it.

**It runs as nonroot (uid 65532) by default**, inherited from the
`gcr.io/distroless/static:nonroot` base — there is no root process in the
container and no shell to become one with. Whatever storage you attach has
to be writable by uid 65532; see the mount note above, and
[`securityContext`](kubernetes.md#securitycontext) on Kubernetes.

## A slightly more real deployment (docker-compose)

```yaml
services:
  fscache:
    image: ghcr.io/fosterstack/cache:0.1.0
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - fscache-data:/home/nonroot     # see "The one command" for why this path
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
`FSCACHE_ADDR`, `FSCACHE_DATA_DIR` (defaults to `./data`, which resolves to
`/home/nonroot/data` in the image), `FSCACHE_MAX_BYTES`,
`FSCACHE_USERNAME` / `FSCACHE_PASSWORD`, `FSCACHE_MAX_BODY_BYTES`.

## Running on Kubernetes

Plain manifests — Deployment, PVC, Service, `securityContext` — are in
[Deploying on Kubernetes](kubernetes.md). Note the single-replica
constraint documented there before you scale anything.

## Not a container shop? Bare binary + systemd

See ["Installing on disconnected networks"](offline-install.md) for the
bare-binary + systemd path — it's the same install whether or not you're
actually air-gapped.

## Verify what you're running

Before or after deploying, confirm the image is the real, signed,
attested thing — see [Verify our images](verify-images.md).
