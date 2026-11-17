# FosterStack Cache

We build tools that help you secure your build pipeline. It made sense to start with the build cache.

We built FosterStack Cache by meticulously following the security guidance that matters: NIST SP 800-204C and 800-204D, and SLSA (a framework for build integrity). The package and image build steps run with the network cut off (hermetic builds), the builds give the same bytes every time (reproducible builds), the image is distroless (no shell, no package manager, only what the server needs), and more. [Read the full list](docs/everything-we-do-for-security.md).

[![CI](https://github.com/fosterstack/cache/actions/workflows/ci.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/ci.yml)
[![CodeQL](https://github.com/fosterstack/cache/actions/workflows/codeql.yml/badge.svg)](https://github.com/fosterstack/cache/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fosterstack/cache/badge)](https://scorecard.dev/viewer/?uri=github.com/fosterstack/cache)
[![Latest release](https://img.shields.io/github/v/release/fosterstack/cache?sort=semver)](https://github.com/fosterstack/cache/releases/latest)

FosterStack Cache is a self-hosted, drop-in remote build cache for **Gradle**. It also works with **Maven**, through the Apache Maven Build Cache Extension.

It ships as a single static binary or a minimal container image (no shell, no base image). It is MIT-licensed. Security patches follow a standing policy ([SECURITY.md](SECURITY.md)).

Every release is signed, and you can check the signatures yourself:

- Every image is signed with the release signing key and recorded in the Sigstore transparency log.
- Every binary archive is covered by a signed checksums file.
- The release pipeline's Sign stage signs a SLSA provenance statement (a signed record of how the images were built). The statement names every image by its digest (the hash that identifies the exact image).

["Verifying a release"][releasing-verify] has the commands.

**Website:** [fosterstack.com](https://fosterstack.com) · **Docs:**
[Install](docs/install.md) · [Docker](docs/docker-deploy.md) ·
[Kubernetes](docs/kubernetes.md) · [Gradle](docs/gradle.md) ·
[Maven](docs/maven.md)

[releasing-verify]: RELEASING.md#verifying-a-release

## Why this exists

Teams that run a free, standalone build cache node for open-source Gradle need a maintained, drop-in replacement.

FosterStack Cache is one server that speaks two protocols:

- For Gradle, it speaks Gradle's documented [`HttpBuildCache`][gradle-http] protocol. That is plain `GET` and `PUT` over HTTP, with each entry stored under a hash of its content.
- For Maven, it speaks the remote HTTP mode of the [Apache Maven Build Cache Extension][maven-cache]: `GET`, `PUT` and `HEAD`.

Both protocols use the same core.

We test both against real multi-module builds in CI. For Gradle, the test builds a real multi-module project. For Maven, the test builds a real multi-module Maven project with the extension (versions 1.2.0 and 1.2.3 <!-- pinned: upstream -->). Its second build restores from the remote cache with byte-identical jars. Wrong or missing credentials fail the documented way.

[gradle-http]: https://docs.gradle.org/current/userguide/build_cache.html#sec:build_cache_configure_remote
[maven-cache]: https://maven.apache.org/extensions/maven-build-cache-extension/

## Status

Shipped:

- **Cache server core.** The server stores blobs on the filesystem under their content hash. A `bbolt` database indexes the metadata. When the cache reaches its size cap, it evicts the least recently used entries. All of this is tested.
- **HTTP surface.** The server answers `GET`, `PUT` and `HEAD`. Basic Auth is optional. Prometheus metrics are at `/metrics`, and a liveness check is at `/healthz`.
- **A static binary.** It is built with `CGO_ENABLED=0`. It builds and runs today (see below).
- **CI checks.** CI runs the tests (race-enabled), `go vet`, golangci-lint (staticcheck, plus a repo-wide ban on importing `crypto/md5` and `crypto/sha1`), govulncheck, CodeQL, the full test suite under `GODEBUG=fips140=only`, and the tests of the allowlist check that keeps the public repo to approved files. It also [scans the candidate images](.github/workflows/scan.yml), and OpenSSF Scorecard runs too.
- **Release pipeline.** We publish signed container images (production and `-fips`) on GHCR (GitHub's container registry), with provenance attached. We also publish bare Linux binaries and a signed checksums file. Only CI builds a release. Each release image is built once, then built a second time independently to check the two match. The scans and acceptance tests run on the first build's exact digest, and that same digest is what we publish: the bytes we tested are the bytes you pull. A daily rescan re-checks the current release. [`RELEASING.md`](RELEASING.md) describes the pipeline stage by stage.
- **Acceptance tests.** Acceptance tests run before every release. They build a real multi-module Gradle project from scratch, twice. The second build must get real `FROM-CACHE` hits (Gradle's label for a task result restored from a cache). The sample's local build cache is off, so a hit is evidence that the remote cache served it. There is no benchmark suite yet. These tests check correctness, not speed.
- **Deployment docs.** [Install](docs/install.md) (binaries and systemd), [Docker](docs/docker-deploy.md) (with sizing), [Kubernetes](docs/kubernetes.md), [Gradle](docs/gradle.md), [Maven](docs/maven.md), and [disconnected networks](docs/offline-install.md).

Not yet shipped:

- **Production use beyond our own CI.** Nobody is running this in a real build pipeline yet except us.
- **A Helm chart.** To deploy to Kubernetes today, you apply the plain manifests in [docs/kubernetes.md](docs/kubernetes.md).
- **The paid tiers.** Single sign-on, high-availability replication, and the license key that unlocks them are not built. Everything in this repository is the free MIT core.
- **A CVE patch commitment you can hold us to.** We aim to ship fixes for dependency CVEs (publicly listed security vulnerabilities) within 48 hours of public disclosure. That is an intention, not a contractual promise. It will not become one until the paid tiers exist. The detection half already runs today. We rescan the current release's images daily. If a CVE is disclosed against bytes we already shipped, an issue is raised without anyone remembering to look.

We track this work in this repo's issues, which is also where you can argue with the roadmap. There is no published schedule. The list above shows direction, not dates.

There is no waitlist and no signup. Pull the image and run it. The quickstart below is the whole gate.

The full core (eviction, size limits, metrics) is free under MIT: see [`LICENSE`](LICENSE). Paid tiers add single sign-on (SSO), high-availability (HA) replication, a 48-hour CVE response target, and compliance support. They sit on top of the same open core. Nothing is withheld from the free tier for security.

The security evidence itself is public and free. These are published with every release, and anyone can verify them with no account and no purchase:

- SBOMs (lists of what is inside each image)
- SLSA provenance
- signatures
- VEX statements (our statements on whether a known vulnerability affects an image)
- the FIPS 140-3 module certificate number

From v0.3.0 <!-- pinned: historical --> each release also carries signed Check records. They bind the scan results, by hash, to the image digests they cover. The results file itself is not attached. The FIPS-mode image is publicly pullable too.

The Compliance tier sells the authored analysis, the vendor signature, and the hours. It never sells access to the bytes or the evidence.

## Quickstart (Docker)

```sh
docker run -d -p 8080:8080 ghcr.io/fosterstack/cache:latest
curl localhost:8080/healthz   # -> ok
```

Pin a specific version for anything beyond a first look. The badge above shows the current version, and [`docs/docker-deploy.md`](docs/docker-deploy.md) covers pinning by digest.

The same images, with the same digests, are mirrored at `docker.io/fosterstack/cache` for tooling that defaults to Docker Hub. GHCR is canonical. Docker Hub's anonymous pull limits apply to whoever pulls, not to us. If they block you, authenticate or pull from GHCR.

That's the whole install. There is no registration and no license key for the Community tier. Pull, run, and point your build tool at it (below).

## Supported platforms

Every release builds all of these from the same source, in the same CI run. No platform is the primary one.

| Artifact | Platforms |
|---|---|
| Binaries (`fscache`) | `linux/amd64`, `linux/arm64` |
| FIPS binaries (`fscache-fips`) | `linux/amd64`, `linux/arm64` |
| Container images (prod, `-fips`) | multi-arch: `linux/amd64` + `linux/arm64` |

### Image variants

| Tag | Shell | Use |
|---|---|---|
| `X.Y.Z` | none | Production |
| `X.Y.Z-fips` | none | Production, FIPS 140-3 validated crypto module ([details](docs/fips.md)) |

Both images hold only the `fscache` binary and the few packages it needs (base layout, time zone data). There is no base image, no CA certificate bundle, no shell to exec into and no package manager.

The server cannot verify any outside certificate. It serves HTTPS from the certificate and key you give it.

To troubleshoot, attach a second container from the outside ([below](#debugging-a-running-container)). See also [the variant docs](docs/verify-images.md).

There is no debug image from v0.3.0 <!-- pinned: historical -->. See
[the images have no shell](docs/verify-images.md#the-images-have-no-shell) and
[troubleshooting without a shell](docs/docker-deploy.md#troubleshooting-without-a-shell-in-the-image).

The fscache-fips build uses the Go Cryptographic Module. The module is validated to FIPS 140-3 under CMVP certificate #5247, and FIPS mode is on by default. The certificate's vendor-affirmed operating environments include Linux on x86-64 and ARM64, where our images run, so the module keeps its validation inside our images.

That gives you a FIPS-validated cryptographic module for control SC-13 in the NIST SP 800-53B low, moderate and high baselines (FedRAMP Low, Moderate and High), where FedRAMP accepts FIPS-validated modules. Details: [FIPS 140-3](docs/fips.md).

There are no macOS or Windows binaries. All release archives are Linux, and on a Mac you run the container image. Container images ship as multi-arch manifests, so `docker pull` picks the right image by itself on Apple Silicon and Graviton. We do not build for Windows and do not plan to. This is a server that lives next to your CI runners. To develop on Windows, use WSL2, which is `linux/amd64`.

For full install instructions, including which archive to download and a systemd unit, see **[docs/install.md](docs/install.md)**.

## Debugging a running container

The production and `-fips` images have no shell, so you debug them from the outside. You attach a second container that carries the tools. There are three ways, below.

**Kubernetes: `kubectl debug`.** An ephemeral debug container joins the running pod (stable since Kubernetes v1.25):

```sh
kubectl debug -it <pod> --image=busybox:1.37 --target=<container> -- sh
# inside it:
wget -qO- http://127.0.0.1:8080/healthz
ps
```

`--target` points the debug container at the `fscache` container so it can see its processes. The container runtime has to support that. The pod's network is shared, so `127.0.0.1:8080` is the cache. Use any image that already has the tools you need.

The debug container inherits the pod's security context. With the Deployment in [docs/kubernetes.md](docs/kubernetes.md) (`runAsNonRoot`, user 65532), it runs as that non-root user, so it cannot install packages. A tools image that installs packages needs a pod that allows root.

You cannot change or remove an ephemeral container once it is added. It goes away with the pod. To debug a modified copy instead, use `kubectl debug <pod> -it --copy-to=<new-name> --image=...`. To debug the node itself, use `kubectl debug node/<node> -it --image=...`.

**Docker: `docker debug`.**

```sh
docker debug <container>
```

This opens a shell in a toolbox attached to the container, even though the image
has no shell. It ships with Docker Desktop and is free from Docker Desktop 4.50 on. See
[Docker's announcement](https://www.docker.com/blog/docker-desktop-4-50/) and the
[command reference](https://docs.docker.com/reference/cli/docker/debug/).

**Docker without `docker debug`** works on any Docker, with no plan or sign-in. You start a tools container that shares the cache container's network and process namespaces. This is the no-shell route, because the images have no shell of their own. See also the
[troubleshooting section](docs/docker-deploy.md#troubleshooting-without-a-shell-in-the-image).

```sh
docker run --rm -it --network=container:<name> --pid=container:<name> \
  busybox:1.37 sh
# inside it: wget -qO- http://127.0.0.1:8080/healthz, then ps
```

The tool images in the examples are not pinned. Pin them by digest in anything you automate. We wrote these commands for the v0.3 images and have not run them against one here. We checked `kubectl debug` against the Kubernetes documentation only.

## Build and run from source

```sh
git clone https://github.com/fosterstack/cache.git
cd cache
CGO_ENABLED=0 go build -o fscache ./cmd/fscache
./fscache
```

You configure the server with environment variables. Flags are not wired yet.

| Variable | Default | Meaning |
|---|---|---|
| `FSCACHE_ADDR` | `:8080` | Listen address |
| `FSCACHE_DATA_DIR` | `./data` | Where blobs and the metadata index live |
| `FSCACHE_MAX_BYTES` | `0` (unbounded) | Size cap; oldest-unused entries evicted first |
| `FSCACHE_USERNAME` / `FSCACHE_PASSWORD` | unset (auth disabled) | HTTP Basic Auth, required together |
| `FSCACHE_RO_USERNAME` / `FSCACHE_RO_PASSWORD` | unset | Optional read-only pair: `GET`/`HEAD` only, writes get 403. Requires the read-write pair; usernames must differ |
| `FSCACHE_MAX_BODY_BYTES` | `1073741824` (1 GiB) | Max accepted blob size per `PUT` |
| `FSCACHE_MAX_CONCURRENT_UPLOADS` | `32` (`0` disables the bound) | Max `PUT`s in flight; the request past the limit gets `429` with `Retry-After` and stores nothing |
| `FSCACHE_TLS_CERT` / `FSCACHE_TLS_KEY` | unset (plain HTTP) | PEM certificate file (it may hold the chain) and its private key file, required together. When both are set the server serves HTTPS only, on `FSCACHE_ADDR`, with TLS 1.2 as the minimum version; HTTP/2 is not offered. Each file may be at most 1 MiB. The files are read only at startup: replace them, then restart |

The server ignores a variable that starts with `FSCACHE_` and is not in this table. It logs one `WARN` line naming the variable (never its value). If the name is a near miss for a real one, the line also carries a `did_you_mean` hint. The server still starts.

## Gradle setup

In `settings.gradle` or `settings.gradle.kts`, point the remote cache at your server. The whole request path is the cache key, so the URL only needs a trailing slash:

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

Maven reads Basic Auth credentials from the `<server>` entries in `settings.xml`. That is the Apache extension's standard pattern. For the full walkthrough, see [Maven setup in 10 minutes](docs/maven.md).

## Product promises and proof

Every behavior of this server that you can observe from outside is a written requirement, with acceptance criteria you can measure. The matrix at [docs/quality/traceability.md](docs/quality/traceability.md) maps each criterion to its evidence. It also lists, honestly, the criteria that have no sufficient evidence yet.

We extracted the first set of requirements from the code and docs. Since Sep 8, 2026, we write acceptance criteria before we write the code. CI fails if the matrix drifts from its sources.

## Documentation

- [Gradle setup](docs/gradle.md) · [Maven setup](docs/maven.md)
- [Migrate off Build Cache Node in 30 minutes](docs/migrate-from-bcn.md)
- [Install (binaries, systemd, platforms)](docs/install.md)
- [One-command Docker deploy](docs/docker-deploy.md) · [Deploying on Kubernetes](docs/kubernetes.md)
- [Installing on disconnected networks](docs/offline-install.md)
- [FIPS 140-3](docs/fips.md) · [Verify a release](docs/verify-release.md) · [Using our VEX](docs/using-our-vex.md)
- [Verify our images](docs/verify-images.md) · [Scanning FosterStack in your compliance pipeline](docs/scanning.md)
- [Releasing](RELEASING.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Security

- A static binary with zero CGO. The image has no shell and no package manager, and a small OS package surface (base layout, time zone data). We patch by publishing a new image, never on a running one.
- CI runs the full test suite under `GODEBUG=fips140=only`. In that mode, Go's FIPS 140-3 module makes non-approved algorithms fail. The mode is a best-effort test aid, and the released `-fips` build runs with FIPS mode on. A `depguard` allowlist covers the static side. It permits only in-boundary crypto imports and denies third-party crypto outright. [`SECURITY.md`](SECURITY.md) describes both, including what each does and does not prove.
- **No telemetry and no required FosterStack connection.** The server reports nothing to us: no usage reporting, no license check, no update ping. Today's free core makes no outbound connections at all, so it runs the same on a host with no route to the internet.

  When paid features ship, there will be traffic that you configure: an identity provider for SSO, and peer replicas for replication. Those are connections to endpoints you choose, never to FosterStack.

  You can check the current behavior yourself. Run `lsof -nP -a -p <pid> -i` against a running server. It shows one listening socket and accepted inbound connections, nothing else.
- See [`SECURITY.md`](SECURITY.md) for the vulnerability disclosure process and the 48-hour response target.

## License

MIT — see [`LICENSE`](LICENSE).
