#!/usr/bin/env bash
# bin/acceptance-serve.sh SUITE main|capped|stop   (SUITE: gradle | maven)
# Starts the candidate image IMAGE_REF the way acceptance.yml's release-chain mode starts it for that suite (same container name, port,
# environment and health wait; no registry login: Check loads the candidate from Build's tarball), or removes every suite container.
# Used by the Check acceptance wrapper (REQ-CHAIN-006-AC5). The Maven password below is the suite's fixture credential, the one its
# settings.xml step writes; it protects nothing.
set -euo pipefail
suite=${1:-} what=${2:-}
case "$suite:$what" in
  gradle:main) name=fscache-acc port=18095 env=() ;;
  gradle:capped) name=fscache-capped port=18096 env=(-e FSCACHE_MAX_BYTES=49152) ;;
  maven:main) name=fscache-mvn-acc port=18098 env=(-e FSCACHE_USERNAME=mvn -e FSCACHE_PASSWORD=acceptance-secret) ;;
  maven:capped) name=fscache-mvn-capped port=18099 env=(-e FSCACHE_MAX_BYTES=262144 -e FSCACHE_USERNAME=mvn -e FSCACHE_PASSWORD=acceptance-secret) ;;
  gradle:stop|maven:stop) docker rm -f fscache-acc fscache-capped fscache-mvn-acc fscache-mvn-capped > /dev/null 2>&1 || true; exit 0 ;;
  *) echo "acceptance-serve: unknown suite or action: $suite $what" >&2; exit 2 ;;
esac
[ -n "${IMAGE_REF:-}" ] || { echo "acceptance-serve: IMAGE_REF is unset" >&2; exit 2; }
docker run -d --name "$name" "${env[@]}" -p "127.0.0.1:$port:8080" "$IMAGE_REF"
for _ in $(seq 1 20); do
  curl -sf "http://localhost:$port/healthz" && exit 0
  sleep 0.5
done
echo "candidate $name never became healthy" >&2
docker logs "$name" >&2 || true
exit 1
