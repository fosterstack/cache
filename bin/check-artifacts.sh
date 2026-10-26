#!/usr/bin/env bash
# bin/check-artifacts.sh [--arch amd64|arm64] --digests FILE --images DIR --archives DIR --out DIR
# The release-artifact checks of the old stage-acceptance-artifacts.yml, now run by Check against the exact candidates (advisor ruling 0384; rule 55).
#   REQ-PLAT-001-AC1  each Linux amd64 binary (fscache, fscache-fips) of the archives executes: it starts, answers /healthz and round-trips a key
#   REQ-FIPS-001-AC1  fscache-fips embeds the module selection GOFIPS140=v1.0.0 in its build info and fscache embeds none
#   REQ-FIPS-002-AC1  three runtime postures read from /statusz: the -fips build names the validated module, the standard build is off, and the
#                     standard build with GODEBUG=fips140=on reports its true state and never claims the validated module or a certificate
#   REQ-FIPS-001-AC2  that forced-standard build is not a validated-module build: the module check of AC1 rejects its binary
#   REQ-PLAT-003-AC1  the production and the -fips image run no shell at any probed path
#   REQ-PLAT-002-AC1  the production and the -fips image archives carry both linux/amd64 and linux/arm64, and the image serves cache traffic here
# --arch arm64 (REQ-CHAIN-006-AC17) runs the same checks on the linux/arm64 binaries and images; the check-arm64 job runs it on an arm64 runner. The default
# is amd64, run by the check job. Writes OUT/artifacts-result.json (arm64: artifacts-result-arm64.json, with the arch) naming both candidate digests and every AC asserted. The certificate number is never written.
set -euo pipefail
LGROOT=$PWD
lg() { (cd "$LGROOT" && sh bin/loopback-get.sh "$@"); }   # every request to the cache under test goes through the loopback helper (REQ-SUP-001-AC24)
# an OCI layout directory (PR 2's interface, PROPOSED): oci-layout and an index.json; a docker-save tarball or any other directory is refused
is_layout() { [ -d "$1" ] && [ -f "$1/oci-layout" ] && [ -f "$1/index.json" ]; }
usage() { echo "usage: check-artifacts.sh [--arch amd64|arm64] --digests FILE --images DIR --archives DIR --out DIR" >&2; exit 2; }
fail() { echo "check-artifacts: $*" >&2; exit 1; }
digests="" images="" archives="" out="" arch=amd64
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --archives) archives=$2 ;;
    --out) out=$2 ;;
    --arch) arch=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$digests" ] && [ -n "$images" ] && [ -n "$archives" ] && [ -n "$out" ] || usage
case "$arch" in amd64) ;; arm64) export DOCKER_DEFAULT_PLATFORM=linux/arm64 ;; *) echo "check-artifacts: --arch must be amd64 or arm64, not $arch" >&2; exit 2 ;; esac
[ -f "$digests" ] || fail "the digest list $digests does not exist"
[ -d "$images" ] || fail "the image directory $images does not exist"
[ -d "$archives" ] || fail "the archive directory $archives does not exist"
for v in production fips; do
  d=$(jq -r --arg k "image-$v" '.[$k] // empty' "$digests")
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-$v digest"
  is_layout "$images/$v" || fail "the $v image $images/$v is missing or not an OCI layout directory (oci-layout and index.json)"
done
shopt -s nullglob
tmp=$(mktemp -d)
mkdir -p "$out" "$tmp/bin"
pids=()
# stop one of this check's servers and wait until it is gone, so a server never outlives the check (a dying server must not meet a later run)
stop_pid() { local p=$1 _; kill "$p" > /dev/null 2>&1 || true; for _ in $(seq 40); do kill -0 "$p" > /dev/null 2>&1 || break; sleep 0.25; done; kill -9 "$p" > /dev/null 2>&1 || true; wait "$p" > /dev/null 2>&1 || true; }
cleanup() { for p in ${pids[@]+"${pids[@]}"}; do stop_pid "$p"; done; docker rm -f fscache-art-production fscache-art-fips > /dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

checks="[]"
passed() { checks=$(jq -c --arg ac "$1" --arg s "$2" '. + [{ac: $ac, subject: $s, result: "pass"}]' <<< "$checks"); }
# healthy PORT [PID]: /healthz answers within 20 tries (a refused try costs 0.5 s, a silent one up to 2.5 s);
# with a PID, a server that is gone ends the wait at once
healthy() {
  local pid=${2:-}
  for _ in $(seq 20); do
    lg -sf --max-time 2 "http://127.0.0.1:$1/healthz" > /dev/null && return 0
    if [ -n "$pid" ] && ! kill -0 "$pid" > /dev/null 2>&1; then return 1; fi
    sleep 0.5
  done
  return 1
}
roundtrip() { lg -sf ${3:+-u "$3"} -X PUT --data-binary "$2" "http://127.0.0.1:$1/acckey" > /dev/null && [ "$(lg -sf ${3:+-u "$3"} "http://127.0.0.1:$1/acckey")" = "$2" ]; }
# the posture as one string, boolean first: it is compared whole, so the boolean and the note are checked together (round 1 F5)
posture() { lg -sf --max-time 5 "http://127.0.0.1:$1/statusz" | jq -r 'if type == "object" and (.fips140 | type) == "boolean" and (.fips140_note | type) == "string" then "\(.fips140)|\(.fips140_note)|end" else "unreadable" end'; }
stop_last() { stop_pid "${pids[${#pids[@]}-1]}"; }

# the binaries of this architecture out of the archives (REQ-PLAT-001-AC1: each of the four archives must exist; this architecture's are executed)
for n in fscache fscache-fips; do
  for a in amd64 arm64; do
    found=("$archives"/${n}_*_linux_${a}.tar.gz)
    [ "${#found[@]}" = 1 ] || fail "the Linux $a archive of $n is missing or not unique in $archives"
  done
  sel=("$archives"/${n}_*_linux_${arch}.tar.gz)
  tar -xzf "${sel[0]}" -C "$tmp/bin" "$n" || fail "the $arch archive of $n holds no binary named $n"
done

# Round 1 F1: the images and archives are the ones Build recorded (re-derived from digests.json), before anything is loaded or executed; the bind also
# lists the files of each layout docker may be given (REQ-SUP-001-AC33).
python3 bin/check-bind.py --digests "$digests" --images "$images" --archives "$archives" --members-out "$tmp" || exit 1

# REQ-PLAT-001-AC1: the binaries execute (they start, answer /healthz and round-trip a key); the fips one runs with the credentials of its image
# Each server asks the kernel for its own port (127.0.0.1:0) and the check reads the port from the server's "starting"
# log line, so no port is guessed: another run's server, or a connection that is open on a port, can never be what a
# server of this run fails to get.
# bound_port PID LOG: the port the server reports; fails when the process is gone first or 80 looks (about 20 s)
# see no line
bound_port() {
  local i addr
  for i in $(seq 80); do
    addr=$(jq -nRr 'first(inputs | fromjson? | select(.msg == "fscache: starting") | .addr) // empty' "$2")
    if [ -n "$addr" ]; then
      echo "${addr##*:}"
      return 0
    fi
    kill -0 "$1" > /dev/null 2>&1 || return 1
    sleep 0.25
  done
  return 1
}
last_output() { tail -n 3 "$1" | tr '\n' ' '; }
# start_server NAME BINARY DESCRIPTION [GODEBUG]: runs one server of this run and sets $port. GODEBUG is always given
# (empty when not asked), so a runner's own value never reaches the binary under test. A server that dies or never
# answers fails the check with its last output.
start_server() {
  local log="$tmp/log-$1" pid
  FSCACHE_ADDR=127.0.0.1:0 FSCACHE_DATA_DIR="$tmp/data-$1" GODEBUG="${4:-}" "$2" > "$log" 2>&1 &
  pid=$!
  pids+=("$pid")
  port=$(bound_port "$pid" "$log") && healthy "$port" "$pid" ||
    fail "$3 never answered /healthz: it does not execute; its last output: $(last_output "$log")"
}
start_server std "$tmp/bin/fscache" "fscache (linux/$arch)"
port_std=$port
roundtrip "$port_std" std-bytes || fail "fscache (linux/$arch) answered /healthz but did not round-trip a key"
note_std=$(posture "$port_std") || note_std=""
start_server fips "$tmp/bin/fscache-fips" "fscache-fips (linux/$arch)"
port_fips=$port
roundtrip "$port_fips" fips-bytes || fail "fscache-fips (linux/$arch) answered /healthz but did not round-trip a key"
note_fips=$(posture "$port_fips") || note_fips=""
start_server forced "$tmp/bin/fscache" "fscache (linux/$arch, GODEBUG=fips140=on)" fips140=on
port_forced=$port
note_forced=$(posture "$port_forced") || note_forced=""
passed REQ-PLAT-001-AC1 "linux/$arch fscache and fscache-fips"

# REQ-FIPS-001-AC1: the module selection is read from the binaries' build info, not from a runtime self-report
info_fips=$(go version -m "$tmp/bin/fscache-fips")
grep -Eq 'build[[:space:]]+GOFIPS140=v1\.0\.0' <<< "$info_fips" || fail "fscache-fips does not embed GOFIPS140=v1.0.0: the validated module was not selected into this artifact"
info_std=$(go version -m "$tmp/bin/fscache")
if grep -Eq 'build[[:space:]]+GOFIPS140=' <<< "$info_std"; then fail "the standard binary embeds a GOFIPS140 selection: variants are crossed"; fi
passed REQ-FIPS-001-AC1 "fscache-fips"

# REQ-FIPS-002-AC1 and REQ-FIPS-001-AC2: each posture tells the truth, and the forced-standard build is not the validated-module build
# each posture is exactly its boolean and its note (the -fips note is the documented mapping of v1.0.0 to its certificate line; the version is compared whole)
[ "$note_fips" = "true|active (Go validated module v1.0.0, CMVP cert #5247)|end" ] || fail "fips build posture is '$note_fips', want the validated-module line, exactly, with fips140 true"
[ "$note_std" = "false|off|end" ] || fail "standard build reports '$note_std', want fips140 false and the note off, exactly"
case "$note_forced" in *"validated module"*|*cert*) fail "forced-standard build claims the validated module or a certificate: '$note_forced'" ;; esac
[ "$note_forced" = "true|active (fips140 mode forced at runtime; not the validated-module build)|end" ] || fail "forced-standard posture is '$note_forced', want the mode-forced line, exactly, with fips140 true"
passed REQ-FIPS-002-AC1 "fscache-fips, fscache, fscache with GODEBUG=fips140=on"
passed REQ-FIPS-001-AC2 "fscache with GODEBUG=fips140=on"

# the images: platform entries, no shell, serves cache traffic (production and -fips; -debug has no subject, owner Oct 9)
for v in production fips; do
  plats=$(python3 bin/check-image-platforms.py "$images/$v") || fail "the $v image archive carries no readable platform list"
  for want in linux/amd64 linux/arm64; do
    grep -qx "$want" <<< "$plats" || fail "the $v image archive has no $want platform entry"
  done
  tar -C "$images/$v" -cf "$tmp/$v.tar" -T "$tmp/$v.members" || fail "the $v image layout could not be archived"
  loaded=$(docker load -i "$tmp/$v.tar") || fail "the $v image could not be loaded"
  ref=$(sed -n 's/^Loaded image: //p; s/^Loaded image ID: //p' <<< "$loaded" | tail -1)
  [ -n "$ref" ] || fail "docker load named no image for the $v candidate"
  docker tag "$ref" "localhost/fscache-$v-image"   # a fixed local name per image, run below with --pull=never: no variable image for pin-age to refuse
  for probe in busybox:sh busybox:ash bin:sh bin:ash bin:bash bin:dash usr-bin:sh usr-bin:bash sbin:sh; do
    sh="${probe%%:*}"; sh="${sh//-//}/${probe##*:}"   # the directory (a - stands for /) and the shell name
    if [ "$v" = fips ]; then
      if docker run --pull=never --rm --entrypoint "/$sh" localhost/fscache-fips-image -c true > /dev/null 2>&1; then fail "the $v image has a shell at /$sh"; fi
    else
      if docker run --pull=never --rm --entrypoint "/$sh" localhost/fscache-production-image -c true > /dev/null 2>&1; then fail "the $v image has a shell at /$sh"; fi
    fi
  done
  name="fscache-art-$v"
  if [ "$v" = fips ]; then
    docker run --pull=never -d --name "$name" -e FSCACHE_USERNAME=acc -e FSCACHE_PASSWORD=accpw -p 127.0.0.1::8080 localhost/fscache-fips-image > /dev/null || fail "the $v image did not start"
    auth=acc:accpw
  else
    docker run --pull=never -d --name "$name" -p 127.0.0.1::8080 localhost/fscache-production-image > /dev/null || fail "the $v image did not start"
    auth=""
  fi
  port=$(docker port "$name" 8080/tcp | sed -n '1s/.*://p')
  healthy "$port" || fail "the $v image never answered /healthz"
  roundtrip "$port" "$v-bytes" "$auth" || fail "the $v image did not round-trip a key"
  docker rm -f "$name" > /dev/null 2>&1 || true
done
passed REQ-PLAT-003-AC1 "production and fips images"
passed REQ-PLAT-002-AC1 "production and fips images (linux/$arch served)"

dp=$(jq -r '."image-production"' "$digests"); df=$(jq -r '."image-fips"' "$digests")
resfile=artifacts-result.json; [ "$arch" = amd64 ] || resfile=artifacts-result-$arch.json
jq -n --arg a "$arch" --arg p "$dp" --arg f "$df" --argjson c "$checks" '{arch: $a, production: {digest: $p}, fips: {digest: $f}, checks: $c}' > "$out/$resfile"
echo "check-artifacts: the $arch binaries execute, the postures are truthful, the production and -fips images have no shell and serve cache traffic"
