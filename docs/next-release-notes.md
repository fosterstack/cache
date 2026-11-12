# Notes for the next release

Behavior changes since the last release, carried into its notes.

- Go 1.27: a request with more than 500 header values is rejected with 431 Request Header Fields Too Large before it
  reaches the cache. Gradle and Maven build-cache clients send far fewer (decided 2026-10-03).
- No macOS or Windows binaries are shipped; use the container image. The release binaries are fscache and
  fscache-fips for linux/amd64 and linux/arm64 (decided 2026-10-09).
