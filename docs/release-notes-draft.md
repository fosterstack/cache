# DRAFT release notes for the next release (not published)

## Next release: Go 1.27.4<!-- pinned: upstream -->, optional HTTPS, and building and signing kept apart

This release is rebuilt with **Go 1.27.4**<!-- pinned: upstream -->. It fixes **GO-2026-6809** (CVE-2026-111943) in Go's standard library: crypto/x509 now distrusts compromised intermediate certificates. The fix ships in this release; there is no separate patch release for it. [TO ADD from pkg.go.dev/vuln/GO-2026-6809 on the day: the affected functions and a one-line description of the defect. TO ADD from this release's own VEX statement: whether the previous release is affected.]

### What changes for Gradle and Maven users

- **Optional HTTPS.** Set `FSCACHE_TLS_CERT` and `FSCACHE_TLS_KEY` and the cache serves HTTPS, with TLS 1.2 as the minimum.
- **Clearer start-up.** The cache opens its listener first, warns about unknown `FSCACHE_` variables, and reports how many uploads it found.
- **Safer disk handling.** A failed recovery check, or an error while serving or shutting down, keeps the "unclean" marker so the next start checks again. Temporary files no longer share a name space with cache keys, and keys whose last part starts with `..` are stored in a fixed place.
- **Disk-trouble metrics.** `store_writable`, `store_free_bytes` and `put_errors_total{reason}` are new, and the store gauges are present from start-up.
- **No client addresses in failure logs.** A dropped client's address no longer appears in the cache's failure logs, including the lines Go's own server writes (for example a failed TLS handshake).
- **Credential check.** The configured credentials are compared as fixed-size digests, so the comparison no longer reveals how long a configured credential is.
- **Bounded metrics.** The HTTP method label on the request metrics takes only GET, HEAD, PUT and other, so a client sending unusual methods cannot create new metric series.
- **Store consistency.** Two uploads of the same key at once no longer leave the size record different from the stored bytes, and the size cap and eviction follow the stored bytes. A directory or other non-regular file at a key's path reads as not found, the store's scan follows no link, and a damaged record is reported as corrupt instead of stopping the cache.
- **One behaviour change you could notice.** Go 1.27<!-- pinned: upstream --> rejects a request with more than 500 header values with 431 Request Header Fields Too Large before it reaches the cache. Gradle and Maven build-cache clients send far fewer.
- **Platforms.** Linux on amd64 and arm64 only, for `fscache` and `fscache-fips`. There are no macOS or Windows binaries.

Upgrade by pulling the new tag or `:latest`.

### Building and signing, in plain words

Each build (one per architecture, and the assembly of the images) runs as its own job, and each job runs on a fresh virtual machine that GitHub provides and then discards. The software packages inside the images, the images and the checksum list that covers every release archive are all signed with one release key. The key stays in the cloud key service, and only the signing jobs can ask the service to use it. The job that signs and publishes is handed only the exact files the build made, never the files from the second, independent rebuild. The comparison between the build and the rebuild runs in a job that holds no secrets and has no permission to publish. You check the signatures with the release public key. (The archives are not signed one by one; the signed checksum list covers each of them.)

This is designed to meet the build-isolation asks of SLSA, NIST SP 800-53 Rev. 5 and Executive Order 14028 with its NIST guidance; we claim no certification. The page `docs/build-and-signing-isolation.md` names the specific controls and lists the known gaps.

### Dependency updates

- Go 1.27.4<!-- pinned: upstream --> (above).
- `github.com/prometheus/client_golang` 1.24.1 to 1.25.0, with its supporting libraries (`prometheus/common` 0.72.0, `prometheus/procfs` 0.22.0, `golang.org/x/sys` 0.48.0). <!-- pinned: upstream -->

### What this release does not do

- The jobs are separated at the level of a virtual machine, not on separate physical hardware.
- The release key is not rotated automatically.
- The release pipeline's own signing tools are not FIPS-validated. (The `-fips` image uses Go's FIPS 140-3 module, which is a different claim.)

See `release-manifest.json` for the evidence bundle: image digests, archive checksums, the requirements baseline, per-AC results and the transparency-log index.
