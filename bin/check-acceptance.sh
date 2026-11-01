#!/usr/bin/env bash
# bin/check-acceptance.sh SUITE --digests FILE --images DIR --out DIR   (SUITE: gradle | maven | egress | k8s)
# Runs one existing acceptance suite against the production candidate from Build's artifacts (v0.3.0 rule 55; REQ-CHAIN-006-AC5).
# It loads DIR/production (an OCI layout directory, as a tar made of it) and runs the suite's shared scripts (the bodies acceptance.yml and the old stages ran, unchanged: the
# bin/acceptance-SUITE scripts) against that image: gradle and maven start it through bin/acceptance-serve.sh,
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
[ -d "$images/production" ] && [ -f "$images/production/oci-layout" ] && [ -f "$images/production/index.json" ] || fail "the production image $images/production is missing or not an OCI layout directory (oci-layout and index.json)"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT   # until the suite's own cleanup below replaces it
# Round 1 F1: the image is the one Build recorded, bound to digests.json before anything is loaded or run; the bind also lists the files of the layout
# docker may be given (REQ-SUP-001-AC33)
python3 bin/check-bind.py --digests "$digests" --images "$images" --members-out "$tmp" || exit 1
[ -f "bin/acceptance-$suite.sh" ] || fail "the $suite suite script is not in the tree"
tar -C "$images/production" -cf "$tmp/production.tar" -T "$tmp/production.members" || fail "the production image layout could not be archived"
loaded=$(docker load -i "$tmp/production.tar")
ref=$(sed -n 's/^Loaded image: //p; s/^Loaded image ID: //p' <<< "$loaded" | tail -1)
[ -n "$ref" ] || fail "docker load named no image for the production candidate"
ref=$(docker image inspect --format '{{.Id}}' "$ref") || fail "docker could not inspect the loaded production candidate"   # serve takes the image by its ID, never by a tag (REQ-SUP-001-AC30)
[[ "$ref" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "docker named no image ID for the production candidate"
cleanup() { [ ! -f "$tmp/extensions.xml" ] || cp "$tmp/extensions.xml" bench/maven-sample/.mvn/extensions.xml; bash bin/acceptance-serve.sh gradle stop; rm -rf "$tmp"; }
trap cleanup EXIT
# The suites ran under setup-java 21 in acceptance.yml; the ubuntu-24.04 runner carries a Java 21 beside its default.
[ -z "${JAVA_HOME_21_X64:-}" ] || export JAVA_HOME="$JAVA_HOME_21_X64"

fresh_output() { : > "$tmp/output"; }   # each suite script writes its results=JSON line to its own GITHUB_OUTPUT file
collect() { sed -n 's/^results=//p' "$tmp/output" >> "$tmp/results"; }   # its results line (if any) is appended to $tmp/results
: > "$tmp/results"
case "$suite" in
  gradle)
    IMAGE_REF="$ref" bash bin/acceptance-serve.sh gradle main
    fresh_output; GITHUB_OUTPUT="$tmp/output" bash bin/acceptance-gradle.sh || fail "the gradle suite script failed against $d"; collect
    IMAGE_REF="$ref" bash bin/acceptance-serve.sh gradle capped
    fresh_output; GITHUB_OUTPUT="$tmp/output" bash bin/acceptance-gradle-capped.sh || fail "the gradle-capped suite script failed against $d"; collect ;;
  maven)
    cp bench/maven-sample/.mvn/extensions.xml "$tmp/extensions.xml"
    export COLD_LOOKUPS=2 COLD_UPLOADS=5 MODULES=2   # acceptance.yml's acceptance-maven job env, unchanged
    for v in 1.2.0 1.2.3; do                         # acceptance.yml's matrix; each leg there starts on a fresh runner
      bash bin/acceptance-serve.sh maven stop
      rm -rf /tmp/mvn-* /tmp/m2-* /tmp/m-cold* /tmp/m-warm*
      rm -rf bench/maven-sample/target bench/maven-sample/lib/target bench/maven-sample/app/target
      sed "s|<version>[0-9.]*</version>|<version>$v</version>|" "$tmp/extensions.xml" > bench/maven-sample/.mvn/extensions.xml
      IMAGE_REF="$ref" bash bin/acceptance-serve.sh maven main
      fresh_output; GITHUB_OUTPUT="$tmp/output" bash bin/acceptance-maven.sh || fail "the maven suite script failed against $d"; collect
      IMAGE_REF="$ref" bash bin/acceptance-serve.sh maven capped
      fresh_output; GITHUB_OUTPUT="$tmp/output" bash bin/acceptance-maven-capped.sh || fail "the maven-capped suite script failed against $d"; collect
    done ;;
  egress)
    fresh_output; GITHUB_OUTPUT="$tmp/output" REF="$ref" bash bin/acceptance-egress.sh || fail "the egress suite script failed against $d"; collect ;;
  k8s)
    docker tag "$ref" fscache-candidate:accept
    fresh_output; GITHUB_OUTPUT="$tmp/output" CANDIDATE_LOCAL=fscache-candidate:accept bash bin/acceptance-k8s.sh || fail "the k8s suite script failed against $d"; collect ;;
esac
want=1; [ "$suite" != maven ] || want=2
jq -s -e --argjson n "$want" 'length == $n and all(.[]; type == "array" and length > 0 and all(.[]; .result == "pass"))' "$tmp/results" > /dev/null 2>&1 \
  || fail "the $suite suite reported no passing assertion against $d (a suite that ran no test fails)"
jq -s --arg s "$suite" --arg d "$d" '{suite: $s, candidate: $d, asserted: (add | unique)}' "$tmp/results" > "$out/acceptance-$suite.json"
echo "check-acceptance: the $suite suite passed against $d"
