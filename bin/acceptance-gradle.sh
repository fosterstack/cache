#!/usr/bin/env bash
# bin/acceptance-gradle.sh: the Gradle remote-cache suite (REQ-GRADLE-001-AC1..AC4), extracted unchanged from acceptance.yml
# (advisor ruling Q7; REQ-CHAIN-006-AC5). The server is already listening on localhost:18095: acceptance.yml starts it (from source,
# or the candidate image), and in Check the Check acceptance wrapper starts the candidate from Build's tarball.
# Before the steps, the wrapper jar is checked (preamble, not from acceptance.yml). Each step_NN below is the `run:` body of that step, byte for byte, run in its own subshell with the step's working directory, as
# GitHub runs a step (bash -eo pipefail, its own process): its exit, cd, variables and traps stay inside it, and the first failing
# step stops the suite. Only errexit and pipefail are applied here, GitHub's default for a run step (no -u: the bodies never ran with it).
set -eo pipefail
# the wrapper jar is the reviewed one before anything runs it (REQ-SUP-001-AC32): the expected file is exactly one line, the one for the jar, and the jar matches it; else refuse
sed -n 1p .github/policy/gradle-wrapper-jar-sha256.txt | grep -qxE '[0-9a-f]{64}  bench/gradle-sample/gradle/wrapper/gradle-wrapper\.jar' && ! sed -n '2,$p' .github/policy/gradle-wrapper-jar-sha256.txt | grep '' > /dev/null \
  && sha256sum -c --status .github/policy/gradle-wrapper-jar-sha256.txt || { echo "acceptance-gradle: gradle-wrapper.jar does not match .github/policy/gradle-wrapper-jar-sha256.txt" >&2; exit 1; }

# acceptance.yml, job acceptance-gradle, step 6: gradlew build (cold — populates the remote cache) (working-directory bench/gradle-sample)
# --info so Gradle logs each task's cache key: the assertions below
# verify the EXACT key of every expected task on the server, which
# is environment-independent — a fresh runner also uploads Gradle's
# Kotlin-DSL script-compilation entries, so a raw PUT count is not a
# stable expectation (found empirically: 6 task entries + 9 script
# entries on CI vs 6 total on a warmed-up machine).
step_06() (
cd bench/gradle-sample
./gradlew build --build-cache -PcacheUrl=http://localhost:18095/ --no-daemon --console=plain --info 2>&1 \
  | tee /tmp/cold.log | grep -E '> Task|BUILD' || true
)

# acceptance.yml, job acceptance-gradle, step 7: assert the cold build stored every expected task's entry
# REQ-GRADLE-001-AC2 (cold half): every expected task's OWN cache
# entry is on the server — verified key by key with HEAD (which does
# not perturb the hit/miss counters) — and nothing was served from
# an empty cache.
step_07() (
set -euo pipefail
: > /tmp/task-keys.txt
while read -r task; do
  key=$(grep -oE "Build cache key for task '${task}' is [0-9a-f]+" /tmp/cold.log | awk '{print $NF}' | head -1)
  if [ -z "${key}" ]; then
    echo "::error::no cache key logged for expected task ${task} — did it execute as cacheable?" >&2; exit 1
  fi
  echo "${task} ${key}" >> /tmp/task-keys.txt
  code=$(curl -s -o /dev/null -w '%{http_code}' -I "localhost:18095/${key}")
  [ "${code}" = "200" ] || { echo "::error::entry for ${task} (key ${key}) not on the server (HEAD=${code})" >&2; exit 1; }
  echo "stored: ${task} -> ${key}"
done < bench/gradle-sample/expected-from-cache.txt
curl -s localhost:18095/metrics > /tmp/metrics-cold.txt
hits=$(awk '/^fscache_cache_hits_total/ {print $2}' /tmp/metrics-cold.txt)
[ "${hits:-0}" -eq 0 ] || { echo "::error::cold build had ${hits} hits against an empty cache" >&2; exit 1; }
)

# acceptance.yml, job acceptance-gradle, step 8: checksum the cold build's outputs (working-directory bench/gradle-sample)
# REQ-GRADLE-001-AC3: snapshot the compiled outputs so the warm
# build's restored bytes can be proven identical, not assumed.
step_08() (
cd bench/gradle-sample
find . -path '*/build/classes/*' -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/cold-outputs.sha256
wc -l < /tmp/cold-outputs.sha256
)

# acceptance.yml, job acceptance-gradle, step 9: remove build outputs (simulate a fresh checkout) (working-directory bench/gradle-sample)
step_09() (
cd bench/gradle-sample
find . -name build -type d -not -path '*/.gradle/*' -exec rm -rf {} +
)

# acceptance.yml, job acceptance-gradle, step 10: gradlew build (fresh checkout — must hit the remote cache) (working-directory bench/gradle-sample)
step_10() (
cd bench/gradle-sample
./gradlew build --build-cache -PcacheUrl=http://localhost:18095/ --no-daemon --console=plain \
  | tee /tmp/gradle-second-build.log
)

# acceptance.yml, job acceptance-gradle, step 11: assert the exact expected tasks were restored from cache
# REQ-GRADLE-001-AC1: the EXACT expected task list restored FROM-CACHE
# — not "at least one". An unexpected miss in this list fails; a task
# appearing that is not in the list fails too, because it means the
# sample changed and the expectation file must change with it.
step_11() (
set -euo pipefail
grep 'FROM-CACHE' /tmp/gradle-second-build.log \
  | sed 's/^> Task //; s/ FROM-CACHE.*//' | sort > /tmp/actual-from-cache.txt
sort bench/gradle-sample/expected-from-cache.txt > /tmp/expected-from-cache.txt
echo "expected:"; cat /tmp/expected-from-cache.txt
echo "actual:"; cat /tmp/actual-from-cache.txt
if ! diff -u /tmp/expected-from-cache.txt /tmp/actual-from-cache.txt; then
  echo "::error::FROM-CACHE task list differs from bench/gradle-sample/expected-from-cache.txt — an unexpected miss or an unlisted task. If the sample changed, change the expectation file in the same PR." >&2
  exit 1
fi
)

# acceptance.yml, job acceptance-gradle, step 12: assert the warm build hit the server (server-side evidence)
# REQ-GRADLE-001-AC2 (warm half): the restores happened ON THE
# SERVER — at least one hit per expected task (script-compilation
# entries also hit, so >= not ==), and the warm build uploaded
# NOTHING new (restored outputs must not re-upload).
step_12() (
set -euo pipefail
expected=$(wc -l < bench/gradle-sample/expected-from-cache.txt | tr -d ' ')
cold_puts=$(awk '/^fscache_http_requests_total\{method="PUT",status="201"\}/ {print $2}' /tmp/metrics-cold.txt)
curl -s localhost:18095/metrics > /tmp/metrics-warm.txt
hits=$(awk '/^fscache_cache_hits_total/ {print $2}' /tmp/metrics-warm.txt)
warm_puts=$(awk '/^fscache_http_requests_total\{method="PUT",status="201"\}/ {print $2}' /tmp/metrics-warm.txt)
echo "warm: hits=${hits:-0} (>= ${expected} required); PUTs cold=${cold_puts:-0} warm-cumulative=${warm_puts:-0} (must be equal)"
[ "${hits:-0}" -ge "${expected}" ] || { echo "::error::server saw ${hits:-0} hits, expected at least ${expected}" >&2; exit 1; }
[ "${warm_puts:-0}" -eq "${cold_puts:-0}" ] || { echo "::error::the warm build uploaded new entries - restored outputs must not re-upload" >&2; exit 1; }
)

# acceptance.yml, job acceptance-gradle, step 13: assert restored outputs are byte-identical (working-directory bench/gradle-sample)
# REQ-GRADLE-001-AC3: restored outputs are byte-identical to what the
# cold build produced.
step_13() (
cd bench/gradle-sample
set -euo pipefail
find . -path '*/build/classes/*' -type f -print0 | sort -z | xargs -0 sha256sum > /tmp/warm-outputs.sha256
if ! diff -u /tmp/cold-outputs.sha256 /tmp/warm-outputs.sha256; then
  echo "::error::restored outputs differ from the cold build's — the cache returned different bytes" >&2
  exit 1
fi
echo "outputs byte-identical across cold and restored builds"
)

# acceptance.yml, job acceptance-gradle, step 14: assert no remote-cache errors were silently ignored
# REQ-GRADLE-001-AC4: a remote-cache error Gradle shrugged off is a
# failure here. Silent degradation is the failure mode this whole
# workflow exists to catch.
step_14() (
set -euo pipefail
if grep -Ei 'Could not (load|store) entry|remote build cache.*(error|unavailable|disabled)' /tmp/gradle-second-build.log; then
  echo "::error::the warm build logged remote-cache errors that Gradle treated as non-fatal" >&2
  exit 1
fi
echo "no ignored remote-cache errors in the warm build log"
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
