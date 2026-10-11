#!/usr/bin/env bash
# bin/check-acceptance.sh SUITE --digests FILE --images DIR --out DIR   (SUITE: gradle | maven | egress | k8s)
# Runs one existing acceptance suite against the production candidate from Build's artifacts (v0.3.0 rule 55; REQ-CHAIN-006-AC5).
# It loads DIR/production.tar and runs the suite's shared scripts (bin/acceptance-*.sh, the bodies acceptance.yml and the old stages ran,
# unchanged) against that image: gradle and maven start the candidate as acceptance.yml's release-chain mode does (bin/acceptance-serve.sh),
# maven once per extension version of acceptance.yml's matrix (1.2.0, 1.2.3) from a clean state; egress runs it as REF; k8s loads it into
# its kind cluster as CANDIDATE_LOCAL. The suite's last step writes the ACs it asserted as results=JSON to $GITHUB_OUTPUT; the script
# fails when a suite fails or reports no passing assertion, and writes OUT/acceptance-SUITE.json naming the candidate digest.
# Refusals (exit 2): no suite, an unknown suite, a missing argument, a missing image directory.
set -euo pipefail
usage() { echo "check-acceptance: $*; usage: check-acceptance.sh gradle|maven|egress|k8s --digests FILE --images DIR --out DIR" >&2; exit 2; }
fail() { echo "check-acceptance: $*" >&2; exit 1; }
suite=${1:-}
case "$suite" in gradle|maven|egress|k8s) shift ;; "") usage "no suite named" ;; *) usage "unknown suite: $suite" ;; esac
digests="" images="" out=""
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage "missing value for $1"
  case "$1" in
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --out) out=$2 ;;
    *) usage "unknown argument: $1" ;;
  esac
  shift 2
done
[ -n "$digests" ] && [ -n "$images" ] && [ -n "$out" ] || usage "missing argument"
[ -d "$images" ] || usage "the image directory $images does not exist"
[ -f "$digests" ] || fail "the digest list $digests does not exist"
d=$(jq -r '."image-production" // empty' "$digests")
[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-production digest"
[ -f "$images/production.tar" ] || fail "the production image $images/production.tar is missing"
[ -f "bin/acceptance-$suite.sh" ] || fail "the $suite suite (bin/acceptance-$suite.sh) is not in the tree"
mkdir -p "$out"
loaded=$(docker load -i "$images/production.tar")
ref=$(sed -n 's/^Loaded image: //p; s/^Loaded image ID: //p' <<< "$loaded" | tail -1)
[ -n "$ref" ] || fail "docker load named no image for the production candidate"
tmp=$(mktemp -d)
cleanup() { [ ! -f "$tmp/extensions.xml" ] || cp "$tmp/extensions.xml" bench/maven-sample/.mvn/extensions.xml; bash bin/acceptance-serve.sh gradle stop; rm -rf "$tmp"; }
trap cleanup EXIT
# The suites ran under setup-java 21 in acceptance.yml; the ubuntu-24.04 runner carries a Java 21 beside its default.
[ -z "${JAVA_HOME_21_X64:-}" ] || { export JAVA_HOME="$JAVA_HOME_21_X64"; export PATH="$JAVA_HOME/bin:$PATH"; }

run() { # run SCRIPT: one shared suite script, its results line (if any) appended to $tmp/results
  : > "$tmp/output"
  GITHUB_OUTPUT="$tmp/output" bash "bin/$1" < /dev/null || fail "$1 failed against $d"
  sed -n 's/^results=//p' "$tmp/output" >> "$tmp/results"
}
: > "$tmp/results"
case "$suite" in
  gradle)
    IMAGE_REF="$ref" bash bin/acceptance-serve.sh gradle main
    run acceptance-gradle.sh
    IMAGE_REF="$ref" bash bin/acceptance-serve.sh gradle capped
    run acceptance-gradle-capped.sh ;;
  maven)
    cp bench/maven-sample/.mvn/extensions.xml "$tmp/extensions.xml"
    export COLD_LOOKUPS=2 COLD_UPLOADS=5 MODULES=2   # acceptance.yml's acceptance-maven job env, unchanged
    for v in 1.2.0 1.2.3; do                         # acceptance.yml's matrix; each leg there starts on a fresh runner
      bash bin/acceptance-serve.sh maven stop
      rm -rf /tmp/mvn-* /tmp/m2-* /tmp/m-cold* /tmp/m-warm*
      find bench/maven-sample -name target -type d -prune -exec rm -rf {} +
      sed "s|<version>[0-9.]*</version>|<version>$v</version>|" "$tmp/extensions.xml" > bench/maven-sample/.mvn/extensions.xml
      IMAGE_REF="$ref" bash bin/acceptance-serve.sh maven main
      run acceptance-maven.sh
      IMAGE_REF="$ref" bash bin/acceptance-serve.sh maven capped
      run acceptance-maven-capped.sh
    done ;;
  egress)
    REF="$ref" run acceptance-egress.sh ;;
  k8s)
    docker tag "$ref" fscache-candidate:accept
    CANDIDATE_LOCAL=fscache-candidate:accept run acceptance-k8s.sh ;;
esac
want=1; [ "$suite" != maven ] || want=2
jq -s -e --argjson n "$want" 'length == $n and all(.[]; type == "array" and length > 0 and all(.[]; .result == "pass"))' "$tmp/results" > /dev/null 2>&1 \
  || fail "the $suite suite reported no passing assertion against $d (a suite that ran no test fails)"
jq -s --arg s "$suite" --arg d "$d" '{suite: $s, candidate: $d, asserted: (add | unique)}' "$tmp/results" > "$out/acceptance-$suite.json"
echo "check-acceptance: the $suite suite passed against $d"
