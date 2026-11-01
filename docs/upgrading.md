# Upgrading and pinning a version

This page says how versions are named, how to pin one, and what to do when you move to another. The tag rules are read from `bin/release-publish.sh` and `RELEASING.md`; the single-writer rules from [Kubernetes](kubernetes.md) and the server code.

## Which tag points at what

Images are published to `ghcr.io/fosterstack/cache` and mirrored, with the same digests, to `docker.io/fosterstack/cache`. There are two image variants, production and `-fips`.

| Tag | What it is |
|---|---|
| `:X.Y.Z` | The production image of exactly that release. |
| `:X.Y.Z-fips` | The `-fips` image of exactly that release. The `-fips` image has this exact tag only; there are no floating tags for it. |
| `:X.Y` | A floating tag for the X.Y line; it can move. Pin `:X.Y.Z` or a digest. |
| `:X` and `:latest` | Move only when the release is the highest released version. |

A release candidate (a tag like `vX.Y.Z-rcN`) runs the release chain and then stops: nothing is pushed, no release is created and no floating tag moves. A candidate never shows up as an image tag.

## Pin a version

A tag can move (`:latest`, `:X.Y` and `:X` do by design). For anything you run for real, use an exact tag, or the digest.

```sh
docker pull ghcr.io/fosterstack/cache:X.Y.Z
# or, by digest
docker pull ghcr.io/fosterstack/cache@sha256:<digest>
```

The digest of each image is listed in `digests.json` on the release page, under `image-production` and `image-fips`; pull by that digest.

To see which version a running server is, read the `version` field of `GET /statusz` (it also appears on the status page and in the startup log line). `/statusz` needs credentials when authentication is on.

## Move to another version

The cache keeps its entries in one data directory, and the metadata index in it is held under an exclusive lock by one process. Never run two servers on the same data directory, not even for a moment. So an upgrade replaces the old server; it does not run beside it.

**Container**

1. Pull the new tag or digest.
2. Stop the old container. On `SIGTERM` or `SIGINT` the server tries to shut down cleanly, waiting up to 10 seconds for requests in flight.
3. Start the new one with the same data volume and the same `FSCACHE_` settings.

**Kubernetes**: use `replicas: 1` and `strategy: Recreate`, as in the [Kubernetes page](kubernetes.md). The default rolling update starts the new pod before the old one stops, and the two contend for the lock.

**Binary**: download the new archive, [verify it](install.md#verify-what-you-downloaded), replace the binary and restart the service. The archive names are in [Install](install.md).

If the old server did not exit cleanly, the new one reconciles the store before it serves (see [Kubernetes](kubernetes.md) for how long that can take and how to give it room).

## Go back

Run the earlier tag or digest the same way. This page does not state whether an older version reads a data directory written by a newer one; if you are unsure, start the earlier version on a fresh data directory ([resetting the cache](docker-deploy.md#resetting-the-cache)).
