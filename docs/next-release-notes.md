# Notes for the next release

Behavior changes since the last release, carried into its notes. Each entry is a change that cannot affect supported
clients, written for customers. Put its source on an indented `Source:` line under it; that line is checked but never
published.

- Go 1.27: a request with more than 500 header values is rejected with 431 Request Header Fields Too Large before it
  reaches the cache. Gradle and Maven build-cache clients send far fewer.
  Source: advisor 0115
