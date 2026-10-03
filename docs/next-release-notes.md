# Notes for the next release

Behavior changes since the last release, carried into its notes. Each entry is a change the owner or the advisor
judged unable to affect supported clients and ends by citing that handoff (advisor 0130).

- Go 1.27: a request with more than 500 header values is rejected with 431 Request Header Fields Too Large before it
  reaches the cache. Gradle and Maven build-cache clients send far fewer (owner accepted; advisor 0115).
