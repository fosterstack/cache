#!/usr/bin/env bash
# bin/acceptance-maven.sh: the Maven remote-cache suite (REQ-MAVEN-001-AC1, AC2), extracted unchanged from acceptance.yml
# (advisor ruling Q7; REQ-CHAIN-006-AC5). The server is already listening on localhost:18098 with Basic Auth, and the matrix
# extension version is already pinned in bench/maven-sample/.mvn/extensions.xml; COLD_LOOKUPS, COLD_UPLOADS and MODULES come
# from the caller (acceptance.yml's job env; the Check acceptance wrapper).
# Each step_NN below is the `run:` body of that step, byte for byte, run in its own subshell with the step's working directory, as
# GitHub runs a step (bash -eo pipefail, its own process): its exit, cd, variables and traps stay inside it, and the first failing
# step stops the suite. Only errexit and pipefail are applied here, GitHub's default for a run step (no -u: the bodies never ran with it).
set -eo pipefail

# acceptance.yml, job acceptance-maven, step 6: write settings.xml credential sets
step_06() (
mkdir -p /tmp/m2-good /tmp/m2-bad
cat > /tmp/m2-good/settings.xml <<'XML'
<settings>
  <servers>
    <server><id>fscache</id><username>mvn</username><password>acceptance-secret</password></server>
  </servers>
</settings>
XML
sed 's/acceptance-secret/WRONG-password/' /tmp/m2-good/settings.xml > /tmp/m2-bad/settings.xml
)

# acceptance.yml, job acceptance-maven, step 7: cold build (uploads; Basic Auth via settings.xml) (working-directory bench/maven-sample)
# Scenarios 1 + 6: a real multi-module build uploads remote entries,
# authenticated via the documented settings.xml <server> conventions.
step_07() (
cd bench/maven-sample
rm -rf /tmp/mvn-bc lib/target app/target
mvn -B -s /tmp/m2-good/settings.xml verify \
  -Dmaven.build.cache.location=/tmp/mvn-bc \
  -Dmaven.build.cache.remote.url=http://localhost:18098/maven \
  -Dmaven.build.cache.remote.save.enabled=true
)

# acceptance.yml, job acceptance-maven, step 8: assert the cold build populated the remote (server-side evidence)
step_08() (
set -euo pipefail
curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-cold.txt
puts=$(awk '/^fscache_http_requests_total\{method="PUT",status="201"\}/ {print $2}' /tmp/m-cold.txt || true)
gets404=$(awk '/^fscache_http_requests_total\{method="GET",status="404"\}/ {print $2}' /tmp/m-cold.txt || true)
echo "cold: uploads=${puts:-0} lookups-missed=${gets404:-0}"
test "${puts:-0}" -eq "$COLD_UPLOADS" || { echo "::error::cold uploads ${puts:-0}, expected $COLD_UPLOADS" >&2; exit 1; }
test "${gets404:-0}" -eq "$COLD_LOOKUPS" || { echo "::error::cold lookups ${gets404:-0}, expected $COLD_LOOKUPS" >&2; exit 1; }
)

# acceptance.yml, job acceptance-maven, step 9: checksum the cold build's artifacts (working-directory bench/maven-sample)
step_09() (
cd bench/maven-sample
sha256sum lib/target/lib-*.jar app/target/app-*.jar | tee /tmp/cold-jars.sha256
)

# acceptance.yml, job acceptance-maven, step 10: wipe local outputs and local cache (working-directory bench/maven-sample)
# Scenario 2: local outputs AND local cache removed — the warm build
# can only be served by the remote.
step_10() (
cd bench/maven-sample
rm -rf /tmp/mvn-bc lib/target app/target
)

# acceptance.yml, job acceptance-maven, step 11: warm build (must restore from the remote) (working-directory bench/maven-sample)
# Scenarios 3 + 5: the clean second build restores from fscache, and
# the server's counters prove where the bytes came from.
step_11() (
cd bench/maven-sample
mvn -B -s /tmp/m2-good/settings.xml verify \
  -Dmaven.build.cache.location=/tmp/mvn-bc \
  -Dmaven.build.cache.remote.url=http://localhost:18098/maven \
  -Dmaven.build.cache.remote.save.enabled=true | tee /tmp/warm.log
)

# acceptance.yml, job acceptance-maven, step 12: assert both modules restored, served by the remote
step_12() (
set -euo pipefail
restored=$(grep -c 'Found cached build, restoring' /tmp/warm.log || true)
echo "restored modules: ${restored}"
test "${restored}" -eq "$MODULES" || { echo "::error::${restored} modules restored, expected $MODULES" >&2; exit 1; }
curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-warm.txt
hits=$(awk '/^fscache_cache_hits_total/ {print $2}' /tmp/m-warm.txt)
echo "server-side cache hits: ${hits:-0}"
test "${hits:-0}" -ge "$MODULES" || { echo "::error::server saw ${hits:-0} hits; the restore did not come from the remote" >&2; exit 1; }
)

# acceptance.yml, job acceptance-maven, step 13: assert restored artifacts are byte-identical (working-directory bench/maven-sample)
# Scenario 4: restored artifacts are the same bytes the cold build
# uploaded.
step_13() (
cd bench/maven-sample
set -euo pipefail
sha256sum lib/target/lib-*.jar app/target/app-*.jar > /tmp/warm-jars.sha256
diff -u /tmp/cold-jars.sha256 /tmp/warm-jars.sha256
echo "restored jars byte-identical"
)

# acceptance.yml, job acceptance-maven, step 14: wrong and missing credentials fail the documented way (working-directory bench/maven-sample)
# Scenario 7: wrong credentials, then no credentials. Documented
# behavior: build completes, errors logged, server 401s, nothing
# stored.
step_14() (
cd bench/maven-sample
set -euo pipefail
before_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk '/^fscache_http_requests_total\{method="PUT",status="201"\}/ {print $2}')

rm -rf /tmp/mvn-bad lib/target app/target
mvn -B -s /tmp/m2-bad/settings.xml verify \
  -Dmaven.build.cache.location=/tmp/mvn-bad \
  -Dmaven.build.cache.remote.url=http://localhost:18098/maven \
  -Dmaven.build.cache.remote.save.enabled=true | tee /tmp/bad.log
grep -q 'Error downloading cache item' /tmp/bad.log \
  || { echo "::error::wrong credentials produced no logged download errors" >&2; exit 1; }

rm -rf /tmp/mvn-none lib/target app/target
mvn -B verify \
  -Dmaven.build.cache.location=/tmp/mvn-none \
  -Dmaven.build.cache.remote.url=http://localhost:18098/maven \
  -Dmaven.build.cache.remote.save.enabled=true | tee /tmp/none.log
grep -q 'Error downloading cache item' /tmp/none.log \
  || { echo "::error::missing credentials produced no logged download errors" >&2; exit 1; }

after_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk '/^fscache_http_requests_total\{method="PUT",status="201"\}/ {print $2}')
echo "stored uploads before=${before_puts} after=${after_puts}"
test "${after_puts}" -eq "${before_puts}" \
  || { echo "::error::unauthenticated runs stored entries on the server" >&2; exit 1; }
)

step_06
step_07
step_08
step_09
step_10
step_11
step_12
step_13
step_14
