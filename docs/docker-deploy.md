# One-command Docker deploy

## The one command

```sh
docker run -d -p 127.0.0.1:8080:8080 -v fscache-data:/home/nonroot ghcr.io/fosterstack/cache:latest
```

The `127.0.0.1:` prefix binds the port to loopback: the cache is reachable
from this machine only, which is the right shape for a trial — a bare
`-p 8080:8080` publishes to every interface, and on a cloud host that is a
world-writable, unauthenticated cache the moment the command returns. The
production shape (all interfaces, Basic Auth on) is the compose example
below.

That's a working, persistent (named volume) deployment. Point your build
tool at it — [Gradle setup](gradle.md) / [Maven setup](maven.md) — and
you're done.

Pin a version tag for anything real; `:latest` is for a first look.

### Verify it is working

No Gradle project required. The cache protocol is a plain `GET`/`PUT` on the
request path, so `curl` exercises the whole round trip:

```sh
curl -s localhost:8080/healthz                                   # -> ok
curl -s -X PUT --data-binary 'hello' localhost:8080/testkey123   # -> 201
curl -s localhost:8080/testkey123                                # -> hello
docker volume inspect fscache-data                               # where the data lives
```

The same bytes coming back from the third command is the whole proof: the blob
was written, indexed, and served.

Cache keys are path segments of `[A-Za-z0-9._-]`, so `testkey123` is valid and
a key with a space or a `/../` is rejected with `400`. There is no `/cache/`
prefix — the entire request path is the key.

Host-side inspection is the only way to look inside: the production image has no
shell by design, so `docker exec` is deliberately foreclosed. The data sits at
the nonroot user's home inside the container and in the named volume on the
host.

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
docker run -d -p 127.0.0.1:8080:8080 -v fscache-data:/data \
  -e FSCACHE_DATA_DIR=/data ghcr.io/fosterstack/cache:latest
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

It depends on your build graph. If you are choosing a droplet size, take
the recommended row. It is hard to be CPU-bound here: the hot path is a
content-addressed blob read or write, not computation.

**Disk is the real variable.** Size it from your eviction cap plus ~20%
headroom, not the other way round: set `FSCACHE_MAX_BYTES` (see
[Configuration](#configuration)) to the cap you want and provision the
volume above it.

`FSCACHE_MAX_BYTES` is in **bytes**, so the value is easy to get wrong by a
factor of 1024. Copy one of these rather than doing the arithmetic:

| Cap | `FSCACHE_MAX_BYTES` |
|---|---|
| 10 GiB | `10737418240` |
| 20 GiB | `21474836480` |
| 50 GiB | `53687091200` |
| 100 GiB | `107374182400` |

It must be smaller than the volume. A value that looks like 20 GiB but is
actually 20 MiB (`20971520`) produces constant eviction and a hit rate that
never climbs — which reads like "the cache isn't helping" rather than a typo.
`/statusz` shows the parsed cap next to current usage, which is the fastest way
to catch it. The server evicts least-recently-used entries once it
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

This is the production shape, and it is authenticated on purpose: it
publishes on every interface so CI runners can reach it, and a cache that
untrusted parties can write to can feed bytes into your builds — so the
port never opens beyond loopback without the credential.

```yaml
services:
  fscache:
    image: ghcr.io/fosterstack/cache:latest
    restart: unless-stopped
    ports:
      - "8080:8080"                    # all interfaces — which is why auth is on
    volumes:
      - fscache-data:/home/nonroot     # see "The one command" for why this path
    environment:
      FSCACHE_MAX_BYTES: "53687091200"   # 50 GiB — size to your CI volume
      FSCACHE_USERNAME: gradle
      FSCACHE_PASSWORD: change-me        # generate one: openssl rand -base64 24

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

Configuration is flags and environment only, on purpose. There is no settings
page and no runtime reconfiguration, which means the running server always
matches the deployment manifest in your git repository — diffable, reviewable,
and with no drift to reconcile. It also means there is no mutable admin surface
for whoever finds the port.

Basic Auth is the **client** credential: it lives in every CI runner and every
developer's `gradle.properties`, and it answers "may you read and write cache
entries", never "may you reconfigure this server". Read-only status is a fine
thing to gate behind it; administration is not, and doing that properly would
mean a second credential system, roles, and an audit log — the appliance path
this project deliberately avoids.

`/statusz` and the browser landing page sit behind Basic Auth when it is
enabled. `/healthz` and `/metrics` stay open, so liveness probes and Prometheus
scrapers need no credentials.

## Resetting the cache

There is no purge endpoint and no admin UI, by design — see
[Configuration](#configuration) and the
[security policy](../SECURITY.md). The server cannot be reconfigured or emptied
at runtime by anyone, including us. Resetting means removing the data and
restarting, which is declarative and leaves an audit trail in whatever manages
your deployment.

**docker compose**

```sh
docker compose down -v && docker compose up -d
```

`-v` removes the project-prefixed named volume; the fresh `up` re-seeds
ownership correctly.

**plain docker**

```sh
docker rm -f fscache
docker volume rm fscache-data
# then re-run the original docker run command
```

**Kubernetes**

Delete the PersistentVolumeClaim — or scale to zero, delete the claim, and
scale back up. Either way the pod comes back with a fresh volume.

```sh
kubectl scale deploy/fscache --replicas=0
kubectl delete pvc fscache-data
kubectl scale deploy/fscache --replicas=1
```

**bare binary**

Stop the process, `rm -rf` the data directory, start it again.

### Benchmarking honestly

A cold-cache measurement has to purge **both** sides. Gradle's local build cache
is on by default and will serve hits from the client machine no matter what you
do to the server:

```sh
rm -rf ~/.gradle/caches/build-cache-1     # the client's cache
./gradlew --stop                          # and the daemon holding it
```

Skip that and your "cold" number is flattered by local hits, which is how a
remote cache gets credit for work it never did.

## Running on Kubernetes

Plain manifests — Deployment, PVC, Service, `securityContext` — are in
[Deploying on Kubernetes](kubernetes.md). Note the single-replica
constraint documented there before you scale anything.

## Platforms and multi-arch images

Every image tag is a **multi-arch manifest** covering `linux/amd64` and
`linux/arm64`, so `docker pull` (or Kubernetes, or podman) selects the right
image for the node automatically — Apple Silicon and Graviton included. You
never pick an architecture-specific tag.

You can confirm that rather than take our word for it:

```sh
docker manifest inspect ghcr.io/fosterstack/cache:latest \
  | jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture)"'
# linux/amd64
# linux/arm64
```

Exactly two entries, both real platforms. Signatures and SBOM/provenance are
stored as separate artifacts against each digest rather than as extra
entries in this index, so nothing else should appear here — see
[Verify our images](verify-images.md).

There are no darwin or windows images: containers on those platforms run a
Linux VM, and it pulls `linux/*` like any other Linux host. For a native
macOS binary, see [Install FosterStack Cache](install.md).

## Troubleshooting with the `:debug` image

The production image has no shell, so `docker exec ... sh` into it fails.
That is deliberate — see [Platforms and multi-arch images](#platforms-and-multi-arch-images)
above and the [variant docs](verify-images.md#the-images-have-no-shell-and-debugs-is-not-where-you-expect).
When you need a shell, run the `:debug` tag, which is the same binary on a
base that adds busybox.

**The shell is at `/busybox/sh`, not `/bin/sh`.** Distroless keeps busybox
under `/busybox/` and ships no `/bin/sh`, no bash, and no package manager.
If you have used Debian, RHEL, Amazon Linux, Alpine or Wolfi images, this
is the one thing that will trip you up.

```sh
# a throwaway shell in the debug image
docker run -it --entrypoint /busybox/sh ghcr.io/fosterstack/cache:debug

# same, with your cache volume attached, to inspect what the server sees
docker run -it --entrypoint /busybox/sh \
  -v fscache-data:/home/nonroot ghcr.io/fosterstack/cache:debug
```

Inside, useful things to check:

```sh
ls -la /home/nonroot/data/blobs     # is the blob store where you think it is?
du -sh /home/nonroot/data           # how big has the cache grown?
wget -qO- http://localhost:8080/healthz   # only if you exec into a RUNNING container
```

To get a shell in a container that is already running, swap the deployment
to the `:debug` tag first — you cannot exec a shell into the production
image, because there is not one to exec. On Kubernetes, with a pod running
the `:debug` tag:

```sh
kubectl exec -it <pod> -- /busybox/sh
```

`/busybox` is on the image `PATH`, so bare `sh` also resolves. The full
path is shown first because it works regardless of how the container was
invoked.

These run as the image's default user, uid 65532 (`nonroot`). Do not add
`--user=root`: clusters that enforce `runAsNonRoot` reject it, and root
would not show you what the server process sees.

## Not a container shop? Bare binary + systemd

See [Install FosterStack Cache](install.md) — download, verify, and a
systemd unit. That page is the base install for every non-container
deployment; ["Installing on disconnected networks"](offline-install.md)
covers only the air-gap deltas on top of it.

## Verify what you're running

Before or after deploying, confirm the image is the real, signed,
attested thing — see [Verify our images](verify-images.md).
