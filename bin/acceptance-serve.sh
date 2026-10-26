#!/usr/bin/env bash
# bin/acceptance-serve.sh SUITE main|capped|stop   (SUITE: gradle | maven)
# Starts the candidate image IMAGE_REF the way the suite's own server step starts it (same container name, port,
# environment and health wait; no registry login: Check loads the candidate from Build's tarball), or removes every suite container.
# Used by the Check acceptance wrapper (REQ-CHAIN-006-AC5). The Maven password below is the suite's fixture credential, the one its
# settings.xml step writes; it protects nothing.
set -euo pipefail
LGROOT=$PWD
lg() { (cd "$LGROOT" && sh bin/loopback-get.sh "$@"); }   # every request to the cache under test goes through the loopback helper (REQ-SUP-001-AC24)
suite=${1:-} what=${2:-}
case "$suite:$what" in
  gradle:main) name=fscache-acc port=18095 envs='' ;;
  gradle:capped) name=fscache-capped port=18096 envs='FSCACHE_MAX_BYTES=49152' ;;
  maven:main) name=fscache-mvn-acc port=18098 envs='FSCACHE_USERNAME=mvn FSCACHE_PASSWORD=acceptance-secret' ;;
  maven:capped) name=fscache-mvn-capped port=18099 envs='FSCACHE_MAX_BYTES=262144 FSCACHE_USERNAME=mvn FSCACHE_PASSWORD=acceptance-secret' ;;
  gradle:stop|maven:stop) docker rm -f fscache-acc fscache-capped fscache-mvn-acc fscache-mvn-capped > /dev/null 2>&1 || true; exit 0 ;;
  *) echo "acceptance-serve: unknown suite or action: $suite $what" >&2; exit 2 ;;
esac
[ -n "${IMAGE_REF:-}" ] || { echo "acceptance-serve: IMAGE_REF is unset" >&2; exit 2; }
# the image is named by content (REQ-SUP-001-AC30): name@sha256:<64 hex> or an image ID sha256:<64 hex>; a tag is refused (ASCII classes only)
export LC_ALL=C
# the hex and the classes below are matched exactly, whatever the caller's shell options
shopt -u nocasematch
label='[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?'
host="${label}(\\.${label})*(:[0-9]+)?"
part='[a-z0-9]+(([._]|__|-+)[a-z0-9]+)*'
tag='[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}'
by_name="^(${host}/)?${part}(/${part})*(:${tag})?@sha256:[0-9a-f]{64}"'$'
by_id='^sha256:[0-9a-f]{64}$'
[[ "$IMAGE_REF" =~ $by_id ]] || [[ "$IMAGE_REF" =~ $by_name ]] || { printf 'acceptance-serve: IMAGE_REF must be content-addressed (name@sha256:<64 hex> or an image ID sha256:<64 hex>), got: %q\n' "$IMAGE_REF" >&2; exit 2; }
# Only the inspected image ID is tagged to the fixed local name (a fixed name, so no variable image is run); right before the container starts the name must still resolve to exactly that ID
id=$(docker image inspect --format '{{.Id}}' "$IMAGE_REF") || { echo "acceptance-serve: docker could not inspect $IMAGE_REF" >&2; exit 2; }
[[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'acceptance-serve: docker named no image ID for %q\n' "$IMAGE_REF" >&2; exit 2; }
docker tag "$id" localhost/fscache-serve-candidate
docker image inspect --format '{{.Id}}' localhost/fscache-serve-candidate | grep -qxF "$id" || { echo "acceptance-serve: localhost/fscache-serve-candidate no longer resolves to $id (re-tagged); nothing is started" >&2; exit 1; }
docker run --pull=never -d --name "$name" --env-file /dev/stdin -p "127.0.0.1:$port:8080" localhost/fscache-serve-candidate <<< "$(printf '%s\n' $envs)"   # the suite's environment (space-separated NAME=value words), one per line
for _ in $(seq 1 20); do
  lg -sf "http://localhost:$port/healthz" && exit 0
  sleep 0.5
done
echo "candidate $name never became healthy" >&2
docker logs "$name" >&2 || true
exit 1
