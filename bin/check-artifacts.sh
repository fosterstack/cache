#!/usr/bin/env bash
# bin/check-artifacts.sh --digests FILE --images DIR --archives DIR --out DIR
# The release-artifact checks of the old stage-acceptance-artifacts.yml, now run by Check against the exact candidates (advisor ruling 0384; rule 55).
#   REQ-PLAT-001-AC1  each Linux amd64 binary (fscache, fscache-fips) of the archives executes: it starts, answers /healthz and round-trips a key
#   REQ-FIPS-001-AC1  fscache-fips embeds the module selection GOFIPS140=v1.0.0 in its build info and fscache embeds none
#   REQ-FIPS-002-AC1  three runtime postures read from /statusz: the -fips build names the validated module, the standard build is off, and the
#                     standard build with GODEBUG=fips140=on reports its true state and never claims the validated module or a certificate
#   REQ-FIPS-001-AC2  that forced-standard build is not a validated-module build: the module check of AC1 rejects its binary
#   REQ-PLAT-003-AC1  the production and the -fips image run no shell at any probed path
#   REQ-PLAT-002-AC1  the production and the -fips image archives carry both linux/amd64 and linux/arm64, and the image serves cache traffic here
# The arm64 binaries and images need a runner of their own architecture, which this one-job stage does not have: only the amd64 halves run here.
# Writes OUT/artifacts-result.json naming both candidate digests and every AC asserted. The certificate number is never written.
set -euo pipefail
usage() { echo "usage: check-artifacts.sh --digests FILE --images DIR --archives DIR --out DIR" >&2; exit 2; }
fail() { echo "check-artifacts: $*" >&2; exit 1; }
digests="" images="" archives="" out=""
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --archives) archives=$2 ;;
    --out) out=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$digests" ] && [ -n "$images" ] && [ -n "$archives" ] && [ -n "$out" ] || usage
[ -f "$digests" ] || fail "the digest list $digests does not exist"
[ -d "$images" ] || fail "the image directory $images does not exist"
[ -d "$archives" ] || fail "the archive directory $archives does not exist"
for v in production fips; do
  d=$(jq -r --arg k "image-$v" '.[$k] // empty' "$digests")
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-$v digest"
  [ -f "$images/$v.tar" ] || fail "the $v image $images/$v.tar is missing"
done
shopt -s nullglob
tmp=$(mktemp -d)
mkdir -p "$out" "$tmp/bin"
pids=()
cleanup() { for p in ${pids[@]+"${pids[@]}"}; do kill "$p" > /dev/null 2>&1 || true; done; docker rm -f fscache-art-production fscache-art-fips > /dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT

checks="[]"
passed() { checks=$(jq -c --arg ac "$1" --arg s "$2" '. + [{ac: $ac, subject: $s, result: "pass"}]' <<< "$checks"); }
healthy() { for _ in $(seq 20); do curl -sf --max-time 2 "http://127.0.0.1:$1/healthz" > /dev/null && return 0; sleep 0.5; done; return 1; }
roundtrip() { curl -sf ${3:+-u "$3"} -X PUT --data-binary "$2" "http://127.0.0.1:$1/acckey" > /dev/null && [ "$(curl -sf ${3:+-u "$3"} "http://127.0.0.1:$1/acckey")" = "$2" ]; }
note() { curl -sf --max-time 5 "http://127.0.0.1:$1/statusz" | jq -r '.fips140_note // empty'; }
stop_last() { kill "${pids[${#pids[@]}-1]}" > /dev/null 2>&1 || true; }

# the amd64 binaries out of the archives (REQ-PLAT-001-AC1: each of the four archives must exist; the amd64 ones are executed here)
for n in fscache fscache-fips; do
  for a in amd64 arm64; do
    found=("$archives"/${n}_*_linux_${a}.tar.gz)
    [ "${#found[@]}" = 1 ] || fail "the Linux $a archive of $n is missing or not unique in $archives"
  done
  amd=("$archives"/${n}_*_linux_amd64.tar.gz)
  tar -xzf "${amd[0]}" -C "$tmp/bin" "$n" || fail "the amd64 archive of $n holds no binary named $n"
done

# REQ-PLAT-001-AC1: the binaries execute (they start, answer /healthz and round-trip a key); the fips one runs with the credentials of its image
FSCACHE_ADDR=":19101" FSCACHE_DATA_DIR="$tmp/data-std" "$tmp/bin/fscache" > "$tmp/log-std" 2>&1 &
pids+=("$!")
healthy 19101 || fail "fscache (linux/amd64) never answered /healthz: it does not execute"
roundtrip 19101 std-bytes || fail "fscache (linux/amd64) answered /healthz but did not round-trip a key"
note_std=$(note 19101) || note_std=""
FSCACHE_ADDR=":19102" FSCACHE_DATA_DIR="$tmp/data-fips" "$tmp/bin/fscache-fips" > "$tmp/log-fips" 2>&1 &
pids+=("$!")
healthy 19102 || fail "fscache-fips (linux/amd64) never answered /healthz: it does not execute"
roundtrip 19102 fips-bytes || fail "fscache-fips (linux/amd64) answered /healthz but did not round-trip a key"
note_fips=$(note 19102) || note_fips=""
FSCACHE_ADDR=":19103" FSCACHE_DATA_DIR="$tmp/data-forced" GODEBUG=fips140=on "$tmp/bin/fscache" > "$tmp/log-forced" 2>&1 &
pids+=("$!")
healthy 19103 || fail "fscache (linux/amd64, GODEBUG=fips140=on) never answered /healthz"
note_forced=$(note 19103) || note_forced=""
passed REQ-PLAT-001-AC1 "linux/amd64 fscache and fscache-fips"

# REQ-FIPS-001-AC1: the module selection is read from the binaries' build info, not from a runtime self-report
info_fips=$(go version -m "$tmp/bin/fscache-fips")
grep -Eq 'build[[:space:]]+GOFIPS140=v1\.0\.0' <<< "$info_fips" || fail "fscache-fips does not embed GOFIPS140=v1.0.0: the validated module was not selected into this artifact"
info_std=$(go version -m "$tmp/bin/fscache")
if grep -Eq 'build[[:space:]]+GOFIPS140=' <<< "$info_std"; then fail "the standard binary embeds a GOFIPS140 selection: variants are crossed"; fi
passed REQ-FIPS-001-AC1 "fscache-fips"

# REQ-FIPS-002-AC1 and REQ-FIPS-001-AC2: each posture tells the truth, and the forced-standard build is not the validated-module build
[[ "$note_fips" == "active (Go validated module v1.0.0"* ]] || fail "fips build posture is '$note_fips', want the validated-module line"
[ "$note_std" = off ] || fail "standard build reports '$note_std', want off"
[[ "$note_forced" == "active (fips140 mode forced at runtime"* ]] || fail "forced-standard posture is '$note_forced', want the mode-forced line"
case "$note_forced" in *"validated module"*|*cert*) fail "forced-standard build claims the validated module or a certificate: '$note_forced'" ;; esac
passed REQ-FIPS-002-AC1 "fscache-fips, fscache, fscache with GODEBUG=fips140=on"
passed REQ-FIPS-001-AC2 "fscache with GODEBUG=fips140=on"

# the images: platform entries, no shell, serves cache traffic (production and -fips; -debug has no subject, owner Oct 9)
for v in production fips; do
  plats=$(python3 bin/check-image-platforms.py "$images/$v.tar") || fail "the $v image archive carries no readable platform list"
  for want in linux/amd64 linux/arm64; do
    grep -qx "$want" <<< "$plats" || fail "the $v image archive has no $want platform entry"
  done
  loaded=$(docker load -i "$images/$v.tar") || fail "the $v image could not be loaded"
  ref=$(sed -n 's/^Loaded image: //p; s/^Loaded image ID: //p' <<< "$loaded" | tail -1)
  [ -n "$ref" ] || fail "docker load named no image for the $v candidate"
  for probe in busybox:sh busybox:ash bin:sh bin:ash bin:bash bin:dash usr-bin:sh usr-bin:bash sbin:sh; do
    sh="${probe%%:*}"; sh="${sh//-//}/${probe##*:}"   # the directory (a - stands for /) and the shell name
    if docker run --rm --entrypoint "/$sh" "$ref" -c true > /dev/null 2>&1; then fail "the $v image has a shell at /$sh"; fi
  done
  name="fscache-art-$v"
  if [ "$v" = fips ]; then
    docker run -d --name "$name" -e FSCACHE_USERNAME=acc -e FSCACHE_PASSWORD=accpw -p 127.0.0.1::8080 "$ref" > /dev/null || fail "the $v image did not start"
    auth=acc:accpw
  else
    docker run -d --name "$name" -p 127.0.0.1::8080 "$ref" > /dev/null || fail "the $v image did not start"
    auth=""
  fi
  port=$(docker port "$name" 8080/tcp | sed -n '1s/.*://p')
  healthy "$port" || fail "the $v image never answered /healthz"
  roundtrip "$port" "$v-bytes" "$auth" || fail "the $v image did not round-trip a key"
  docker rm -f "$name" > /dev/null 2>&1 || true
done
passed REQ-PLAT-003-AC1 "production and fips images"
passed REQ-PLAT-002-AC1 "production and fips images (linux/amd64 served; the arm64 half needs an arm64 runner)"

dp=$(jq -r '."image-production"' "$digests"); df=$(jq -r '."image-fips"' "$digests")
jq -n --arg p "$dp" --arg f "$df" --argjson c "$checks" '{production: {digest: $p}, fips: {digest: $f}, checks: $c}' > "$out/artifacts-result.json"
echo "check-artifacts: the amd64 binaries execute, the postures are truthful, the production and -fips images have no shell and serve cache traffic"
