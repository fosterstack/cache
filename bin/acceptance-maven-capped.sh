#!/usr/bin/env bash
# bin/acceptance-maven-capped.sh: the Maven capped-server suite (REQ-EVICT-002-AC4) and the suite's results line, extracted
# unchanged from acceptance.yml (advisor ruling Q7; REQ-CHAIN-006-AC5). The capped server is already listening on localhost:18099.
# Each step_NN below is the `run:` body of that step, byte for byte, run in its own subshell with the step's working directory, as
# GitHub runs a step (bash -eo pipefail, its own process): its exit, cd, variables and traps stay inside it, and the first failing
# step stops the suite. Only errexit and pipefail are applied here, GitHub's default for a run step (no -u: the bodies never ran with it).
set -eo pipefail

# acceptance.yml, job acceptance-maven, step 17: REQ-EVICT-002-AC4 — oversized module output never caches, the build never cares
step_17() (
set -euo pipefail
# One incompressible 512 KiB resource, generated ONCE and copied
# byte-for-byte into BOTH workspaces. A per-workspace random file
# (the old bug) gave the app module a DIFFERENT cache key in a and
# b, so a warm restore of the app could never even be attempted and
# the two keys could not be compared. Shared bytes => identical app
# key across builds. 512 KiB exceeds the 256 KiB cap even after the
# cache's gzip; the lib module stays small and caches normally.
head -c 524288 /dev/urandom > /tmp/mvn-oversized-shared.bin
for copy in a b; do
  cp -r bench/maven-sample "/tmp/mvn-capped-${copy}"
  rm -rf "/tmp/mvn-capped-${copy}/lib/target" "/tmp/mvn-capped-${copy}/app/target"
  mkdir -p "/tmp/mvn-capped-${copy}/app/src/main/resources"
  cp /tmp/mvn-oversized-shared.bin \
    "/tmp/mvn-capped-${copy}/app/src/main/resources/bench-large.bin"
done
# Keep the full build-cache extension log (INFO level, not -q) so
# the real app artifact key and its 413 rejection are identifiable.
run_build() { # dir, cache-location, logfile
  (cd "$1" && mvn -B -s /tmp/m2-good/settings.xml verify \
    -Dmaven.build.cache.location="$2" \
    -Dmaven.build.cache.remote.url=http://localhost:18099/maven \
    -Dmaven.build.cache.remote.save.enabled=true) 2>&1 | tee "$3"
}
run_build /tmp/mvn-capped-a /tmp/mvn-bc-capped-a /tmp/mvn-capped-a.log \
  || { echo "::error::first capped build failed - an oversized output must be a cache miss, never a build failure" >&2; exit 1; }
run_build /tmp/mvn-capped-b /tmp/mvn-bc-capped-b /tmp/mvn-capped-b.log \
  || { echo "::error::second capped build failed - the oversized app must not break a same-key rebuild" >&2; exit 1; }

# Proof 1 (shared-resource fix): the app hashed to the SAME key in
# both builds. The local cache always stores a built module under
# <loc>/v1.1/<group>/app/<KEY>/local/, independent of extension
# version or remote outcome, so read the KEY off the filesystem.
app_local_a=$(find /tmp/mvn-bc-capped-a -type f -path '*/app/*/local/app.jar' | head -1)
app_local_b=$(find /tmp/mvn-bc-capped-b -type f -path '*/app/*/local/app.jar' | head -1)
test -n "$app_local_a" && test -n "$app_local_b" \
  || { echo "::error::app module was not built into either local cache - cannot identify its key" >&2; exit 1; }
app_key_a=$(basename "$(dirname "$(dirname "$app_local_a")")")
app_key_b=$(basename "$(dirname "$(dirname "$app_local_b")")")
echo "app cache key: a=${app_key_a} b=${app_key_b}"
test "$app_key_a" = "$app_key_b" \
  || { echo "::error::app cache key differs across workspaces (${app_key_a} vs ${app_key_b}) - the oversized resource was not shared byte-for-byte" >&2; exit 1; }
app_key="$app_key_a"

# Proof 2 (real key rejected): the extension UPLOADS the oversized
# app artifact and the server answers 413 - it does not pre-skip.
# Tie the 413 to the real app key, not to any incidental entry. The resolver words it differently by runner image (older:
# "status code: 413 ... Request Entity Too Large", newer: "HTTP Status: 413"); the Maven 413 test pins both.
grep -Eq 'status code: 413|HTTP Status: 413|Request Entity Too Large' /tmp/mvn-capped-a.log \
  || { echo "::error::build a logged no 413 - the oversized app upload was not rejected by the server" >&2; exit 1; }
grep -Fq "app/${app_key}/app.jar" /tmp/mvn-capped-a.log \
  || { echo "::error::build a never attempted the app/${app_key}/app.jar remote save" >&2; exit 1; }

# Proof 3 (remote absence of the real key): search the EXTENSION
# CACHE directories, NOT the project tree - a remotely restored
# artifact lands under fscache/, a locally built one under local/.
# The oversized app.jar must appear under fscache/ in NEITHER build.
if find /tmp/mvn-bc-capped-a /tmp/mvn-bc-capped-b -type f -path '*/app/*/fscache/*.jar' | grep -q .; then
  echo "::error::the oversized app archive was restored from the remote despite the cap" >&2; exit 1
fi
# ...and confirm directly on the server that the real app key holds
# no artifact: HEAD the exact remote path -> 404.
app_code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w '%{http_code}' -I "http://localhost:18099/maven/v1.1/com.fosterstack.bench/app/${app_key}/app.jar")
test "$app_code" = "404" \
  || { echo "::error::app/${app_key}/app.jar is retrievable from the remote (${app_code}) - the oversized artifact was stored" >&2; exit 1; }

# Proof 4 (small module DID round-trip): on build b the lib module
# is served from the remote - the extension logs the restore and the
# downloaded artifact lands under fscache/ - and it is byte-identical
# to build a's freshly compiled lib. This, not an aggregate PUT
# count, is what proves the warm restore of the small module.
grep -q 'Found cached build, restoring com.fosterstack.bench:lib' /tmp/mvn-capped-b.log \
  || { echo "::error::the small lib module was NOT restored from the remote on the second build" >&2; exit 1; }
find /tmp/mvn-bc-capped-b -type f -path '*/lib/*/fscache/lib.jar' | grep -q . \
  || { echo "::error::lib was not populated from the remote (no fscache/lib.jar) on the second build" >&2; exit 1; }
lib_a=$(sha256sum /tmp/mvn-capped-a/lib/target/lib-*.jar | awk '{print $1}')
lib_b=$(sha256sum /tmp/mvn-capped-b/lib/target/lib-*.jar | awk '{print $1}')
echo "lib sha256: a=${lib_a} b=${lib_b}"
test "$lib_a" = "$lib_b" \
  || { echo "::error::remotely restored lib jar differs from the uploaded bytes" >&2; exit 1; }

# Mechanism check (kept, but NOT a substitute for the build evidence
# above): the server's rejection contract, probed directly.
head -c 524288 /dev/urandom > /tmp/mvn-oversized-probe.bin
hdr=$(curl -s -u mvn:acceptance-secret -D - -o /dev/null -X PUT --data-binary @/tmp/mvn-oversized-probe.bin http://localhost:18099/maven/oversizedprobe)
grep -q '^HTTP/[0-9.]* 413' <<<"$hdr" || { echo "::error::oversized probe was not 413" >&2; exit 1; }
grep -qi '^X-FSCache-Reject: entry-exceeds-cache-cap' <<<"$hdr" \
  || { echo "::error::413 lacks the X-FSCache-Reject: entry-exceeds-cache-cap header" >&2; exit 1; }
code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w '%{http_code}' -I http://localhost:18099/maven/oversizedprobe)
test "$code" = "404" || { echo "::error::rejected entry is retrievable (${code}) - it was stored" >&2; exit 1; }
echo "REQ-EVICT-002-AC4: identical app key ${app_key} across builds; oversized app upload 413'd and absent from the remote; small lib restored remotely byte-for-byte; reject mechanism verified"
)

# acceptance.yml, job acceptance-maven, step 19: report the ACs this suite asserted
# Reached only when every assertion above passed; the aggregation
# stage merges this into the acceptance predicate (chain mode).
step_19() (
echo 'results=[{"ac":"REQ-MAVEN-001-AC1","result":"pass"},{"ac":"REQ-MAVEN-001-AC2","result":"pass"},{"ac":"REQ-EVICT-002-AC4","result":"pass"}]' >> "$GITHUB_OUTPUT"
)

step_17
step_19
