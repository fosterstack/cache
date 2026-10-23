#!/usr/bin/env bash
# bin/acceptance-egress.sh: the no-phone-home suite (REQ-PRIV-001-AC1), extracted unchanged from stage-acceptance-egress.yml
# (advisor ruling Q7; REQ-CHAIN-006-AC5). REF is the candidate image to run (the Check acceptance wrapper sets it to the image it
# loaded from Build's tarball). The old stage's evidence upload is not carried: Check uploads check-results/ only.
# Each step_NN below is the `run:` body of that step, byte for byte, run in its own subshell with the step's working directory, as
# GitHub runs a step (bash -eo pipefail, its own process): its exit, cd, variables and traps stay inside it, and the first failing
# step stops the suite. Only the option line below (errexit and pipefail) applies here, GitHub's default for a run step (no -u: the bodies never ran with it).
LGROOT=$PWD
lgin() { (cd "$LGROOT" && "$@" < bin/loopback-get.sh); }   # the loopback helper, fed on stdin to the client inside the shared network namespace (REQ-SUP-001-AC24)
set -eo pipefail

# stage-acceptance-egress.yml, job egress, step 2: capture from before startup, prove the monitor, run both policies
step_02() (
set -euo pipefail

# Builder for the static strace and a libc-less image used to PROVE
# the tracer is truly static (pinned by digest, row 78).
# strace release built from source, statically linked, so it can be
# the entrypoint of the distroless (no libc) candidate image.
STRACE_VER=6.9
# SHA256 of https://strace.io/files/${STRACE_VER}/strace-${STRACE_VER}.tar.xz
# (official release host). Cross-verified: this tarball's sha512 equals
# Alpine 3.20's recorded strace-6.9 sha512, and its size (2,466,252 B)
# matches strace.io's published size. Empty => fail closed.
STRACE_SHA256='da189e990a82e3ca3a5a4631012f7ecfd489dab459854d82d8caf6a865c1356a'
# Host dirs: the static strace binary (mounted read-only into the
# candidate) and the per-scenario trace output (mounted read-write).
TRACE_BIN=/tmp/fstrace/bin
TRACE_OUT=/tmp/fstrace/out
# The candidate image's real entrypoint (what strace execs).
CANDIDATE_ENTRYPOINT=/usr/bin/fscache

fail() { echo "::error::$*" >&2; exit 1; }

# ------------------------------------------------------------------
# get_static_strace
# Build a statically-linked strace from pinned, checksum-verified
# source in a pinned Alpine (musl) builder, write it to TRACE_BIN,
# and PROVE it executes with no libc present by running `strace -V`
# inside a distroless "static" image (the same class of image as the
# candidate). Any failure fails the job (fail closed): a tracer that
# cannot run in the candidate's environment would let the candidate
# run untraced, which is precisely the audited gap.
# ------------------------------------------------------------------
get_static_strace() {
  rm -rf "$TRACE_BIN" "$TRACE_OUT"
  mkdir -p "$TRACE_BIN" "$TRACE_OUT"
  chmod 0777 "$TRACE_OUT"
  [ -n "$STRACE_SHA256" ] || fail "STRACE_SHA256 is not pinned; refusing to build the syscall tracer from unverified source (fail closed). Pin the published checksum of strace-${STRACE_VER}.tar.xz."
  docker run --rm -v "$TRACE_BIN":/out -e V="$STRACE_VER" -e SUM="$STRACE_SHA256" alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc sh -euc '
    apk add --no-cache build-base linux-headers xz >/dev/null
    cd /tmp
    wget -q -O "strace-${V}.tar.xz" "https://github.com/strace/strace/releases/download/v6.9/strace-6.9.tar.xz"
    echo "${SUM}  strace-${V}.tar.xz" | sha256sum -c -
    tar -xf "strace-${V}.tar.xz"
    cd "strace-${V}"
    ./configure --disable-mpers LDFLAGS="-static -pthread" >/dev/null
    make -j"$(nproc)" >/dev/null
    if [ -x src/strace ]; then cp src/strace /out/strace; else cp strace /out/strace; fi
    chmod 0755 /out/strace
  ' || fail "static strace build failed (checksum mismatch or build error) - failing closed"
  [ -s "$TRACE_BIN/strace" ] || fail "static strace binary not produced - failing closed"
  # PROOF the tracer runs in a libc-less image (like the candidate):
  # strace -V prints its version and exits 0 with no target. If the
  # binary were dynamically linked this errors (no loader) and fails.
  if ! docker run --rm -v "$TRACE_BIN":/trace:ro --entrypoint /trace/strace gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab -V > /tmp/strace.ver 2>&1; then
    cat /tmp/strace.ver >&2 || true
    fail "the built strace did not execute in a libc-less distroless image - it is not usable as the candidate entrypoint (fail closed)"
  fi
  echo "static tracer ready: $(head -n1 /tmp/strace.ver)"
}

# ------------------------------------------------------------------
# analyze_strace <strace-file> <label> <own_ip> <own_ip6>
#
# Parse the CANDIDATE's own syscall trace. A VIOLATION is any
# connect()/sendto()/sendmsg() whose AF_INET/AF_INET6 destination is
# not an allowed EXACT address - INCLUDING calls that returned an
# error (ENETUNREACH/EPERM/ECONNREFUSED/...). The AC forbids the
# ATTEMPT, so return status is deliberately ignored. Name resolution
# (any such call to port 53) is a violation regardless of address.
# Allowed destinations are EXACTLY loopback (127.0.0.1 / ::1) and the
# netns's own IP (self); the in-netns test client reaches the server
# over loopback. bind/listen/accept/socket are ignored (a server
# binding its own address and accepting inbound is not an outbound
# attempt). Writes /tmp/<label>.sys.ext (flagged calls),
# /tmp/<label>.sys.dnscount and /tmp/<label>.sys.extcount. A missing,
# empty or unparseable trace fails the job (monitor failure).
# ------------------------------------------------------------------
analyze_strace() {
  local sfile="$1" label="$2" own="$3" own6="$4"
  local args=()
  [ -n "$own" ] && args+=("$own")
  [ -n "$own6" ] && [ "$own6" != "invalid IP" ] && args+=("$own6")
  # The analyzer (bin/analyze-egress-trace.py) is committed and
  # regression-tested (bin/analyze-egress-trace-test.sh). It covers
  # connect/sendto/sendmsg/sendmmsg (every message destination),
  # ignores return status (a denied attempt is a violation), and
  # FAILS CLOSED on an empty/garbage/unparseable trace. It prints
  # DNS/OUT violations to stdout and exits non-zero on any
  # violation OR unusable trace.
  set +e
  python3 bin/analyze-egress-trace.py "$sfile" "${args[@]}" \
    > "/tmp/${label}.sys.ext" 2> "/tmp/${label}.sys.err"
  local rc=$?
  set -e
  grep -c '^DNS ' "/tmp/${label}.sys.ext" 2>/dev/null | tr -d ' ' > "/tmp/${label}.sys.dnscount" || echo 0 > "/tmp/${label}.sys.dnscount"
  grep -c '^OUT ' "/tmp/${label}.sys.ext" 2>/dev/null | tr -d ' ' > "/tmp/${label}.sys.extcount" || echo 0 > "/tmp/${label}.sys.extcount"
  # A non-zero exit with NO DNS/OUT lines means the trace was
  # unusable (empty/garbage/unparseable) - fail closed, do not
  # treat it as "no attempts".
  if [ "$rc" -ne 0 ] && [ "$(cat "/tmp/${label}.sys.dnscount")" = "0" ] && [ "$(cat "/tmp/${label}.sys.extcount")" = "0" ]; then
    echo "unusable" > "/tmp/${label}.sys.usable"
  else
    echo "ok" > "/tmp/${label}.sys.usable"
  fi
}

# ------------------------------------------------------------------
# analyze_pcap <pcap> <label> <own_ip> <own_ip6>
#
# Reads a capture taken on the candidate's shared netns and writes:
#   /tmp/<label>.dnscount : DNS packets (udp OR tcp port 53), any peer
#   /tmp/<label>.extcount : server-ORIGINATED packets (UDP or TCP SYN)
#                           whose destination is not an allowed EXACT
#                           test address.
#   /tmp/<label>.ext      : the flagged flows ("PROTO src > dst:port")
#
# Server-originated = source is inside this netns (own IPv4/IPv6 or
# loopback). Allowed destinations are EXACT addresses only: loopback
# (127.0.0.1 / ::1) and the netns's own IP (self). There is NO
# gateway exemption and NO RFC1918 range - a server-originated
# UDP/SYN/DNS to any other address, private or public, is flagged.
#
# ANY tool/parse failure (unreadable pcap, tshark error, zero packets)
# returns non-zero and, under errexit, fails the job. A broken
# capture never passes silently.
# ------------------------------------------------------------------
analyze_pcap() {
  local pcap="$1" label="$2" own="$3" own6="$4"
  local base allowed total
  base=$(basename "$pcap")
  allowed="127.0.0.1 ::1 ${own}"
  [ -n "$own6" ] && allowed="${allowed} ${own6}"
  [ -s "$pcap" ] || { echo "::error::${label}: capture ${pcap} missing or empty (monitor failure)" >&2; return 1; }
  if ! total=$(docker run --rm -v /tmp:/caps nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b tshark -r "/caps/${base}" -T fields -e frame.number 2>/dev/null | wc -l); then
    echo "::error::${label}: tshark could not read ${pcap} (parser failure)" >&2
    return 1
  fi
  [ "$total" -gt 0 ] || { echo "::error::${label}: capture contained zero packets (monitor blind)" >&2; return 1; }
  # DNS: ANY packet on port 53 (udp or tcp), regardless of peer/direction.
  if ! docker run --rm -v /tmp:/caps nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b tshark -r "/caps/${base}" \
       -Y 'udp.port == 53 || tcp.port == 53' -T fields -e frame.number \
       > "/tmp/${label}.dnsraw" 2>/dev/null; then
    echo "::error::${label}: DNS analysis failed (parser failure)" >&2
    return 1
  fi
  # TCP connection initiations (pure SYN): src/dst + dport, IPv4 and IPv6.
  if ! docker run --rm -v /tmp:/caps nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b tshark -r "/caps/${base}" \
       -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' \
       -T fields -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tcp.dstport -E separator='|' 2>/dev/null \
       | sed 's/^/TCP|/' > "/tmp/${label}.synraw"; then
    echo "::error::${label}: SYN analysis failed (parser failure)" >&2
    return 1
  fi
  # Non-DNS UDP datagrams: src/dst + dport, IPv4 and IPv6. This is the
  # category the previous analyzer ignored (the audited false negative).
  if ! docker run --rm -v /tmp:/caps nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b tshark -r "/caps/${base}" \
       -Y 'udp && !(udp.port == 53)' \
       -T fields -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e udp.dstport -E separator='|' 2>/dev/null \
       | sed 's/^/UDP|/' > "/tmp/${label}.udpraw"; then
    echo "::error::${label}: UDP analysis failed (parser failure)" >&2
    return 1
  fi
  cat "/tmp/${label}.synraw" "/tmp/${label}.udpraw" > "/tmp/${label}.outraw"
  awk -F'|' -v allowed="$allowed" '
    BEGIN { n = split(allowed, a, " "); for (i = 1; i <= n; i++) ok[a[i]] = 1 }
    {
      proto = $1
      src = ($2 != "" ? $2 : $4)
      dst = ($3 != "" ? $3 : $5)
      dport = $6
      if (src == "") next
      if (!(src in ok)) next        # not server-originated (inbound) - ignore
      if (dst in ok) next           # loopback / self - the only allowed in-band path
      print proto " " src " > " dst ":" dport
    }' "/tmp/${label}.outraw" > "/tmp/${label}.ext"
  wc -l < "/tmp/${label}.dnsraw" | tr -d ' ' > "/tmp/${label}.dnscount"
  wc -l < "/tmp/${label}.ext"    | tr -d ' ' > "/tmp/${label}.extcount"
}

wait_for_tcpdump() {
  local cname="$1" label="$2" t=0
  until docker exec "$cname" pgrep -x tcpdump >/dev/null 2>&1; do
    t=$((t + 1))
    if [ "$t" -ge 20 ]; then
      echo "::error::${label}: tcpdump never started on the shared netns (monitor failure)" >&2
      return 1
    fi
    sleep 1
  done
}

# start_stack <label> <network-name>
# Brings up the netns owner (NO published host port) and the capture
# sidecar, and confirms capture is running BEFORE any server exists.
# Sets OWN_IP / OWN_IP6 for the shared netns.
start_stack() {
  local label="$1" net="$2"
  docker rm -f "fscache-net-${label}" "fscache-tap-${label}" "fscache-cand-${label}" >/dev/null 2>&1 || true
  docker run -d --name "fscache-net-${label}" --network "$net" nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b sleep infinity >/dev/null
  OWN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "fscache-net-${label}")
  OWN_IP6=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "fscache-net-${label}")
  if [ -z "$OWN_IP" ]; then
    echo "::error::${label}: could not determine netns own IP" >&2
    return 1
  fi
  docker run -d --name "fscache-tap-${label}" --net "container:fscache-net-${label}" \
    -v /tmp:/caps nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b tcpdump -i any -n -U -w "/caps/${label}.pcap" >/dev/null
  wait_for_tcpdump "fscache-tap-${label}" "$label"
}

freeze_capture() {
  local label="$1"
  # SIGTERM to tcpdump (PID 1 of the sidecar): it flushes the pcap and
  # exits. `|| true` only tolerates an already-stopped sidecar; the
  # capture is written unbuffered (-U) so the file is complete either way.
  docker stop -t 15 "fscache-tap-${label}" >/dev/null 2>&1 || true
  sleep 1
}

teardown() {
  local label="$1"
  docker rm -f "fscache-cand-${label}" "fscache-tap-${label}" "fscache-net-${label}" >/dev/null 2>&1 || true
}

# run_scenario <label> <network-name>
# startup -> load (real PUT/GET over loopback INSIDE the shared netns,
# asserting 200/201 + exact bytes) -> idle -> freeze -> analyze. Writes
# /tmp/<label>.summary (status+bytes per key) for cross-policy
# comparison. Any DNS or non-allowed outbound fails the job.
run_scenario() {
  local label="$1" net="$2" owner="fscache-net-$1"
  start_stack "$label" "$net"
  # Start the candidate INTO the already-monitored netns (no -p: it
  # shares the owner's namespace). No host port is published anywhere.
  #
  # The candidate runs UNDER the static strace as its ENTRYPOINT, so
  # tracing starts before the cache's first instruction and follows
  # every thread/child (-f). We trace network syscalls only (low
  # overhead) with -yy (decode socket addresses) and -qq (quiet
  # attach/exit noise), writing to a per-scenario file in the
  # read-write TRACE_OUT mount; the read-only TRACE_BIN mount carries
  # the tracer. strace then execs the real entrypoint. SYS_PTRACE and
  # an unconfined seccomp/apparmor profile are required for ptrace.
  # FSCACHE_* env is inherited unchanged (none is defined here), so the
  # cache runs identically to a bare `docker run "$REF"`.
  docker tag "$REF" localhost/fscache-egress-candidate
  docker run --pull=never -d --name "fscache-cand-${label}" --net "container:fscache-net-${label}" --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --security-opt apparmor=unconfined -v "$TRACE_BIN":/trace:ro -v "$TRACE_OUT":/out --entrypoint /trace/strace localhost/fscache-egress-candidate -f -e trace=network -yy -qq -o "/out/${label}.strace" "$CANDIDATE_ENTRYPOINT" >/dev/null
  # ---- startup interval (capture already running) ----
  # The client runs INSIDE the shared netns, so it reaches the server
  # over loopback with no egress and no host port - identical on the
  # ordinary and the --internal networks.
  local ok=0 t
  for ((t = 1; t <= 30; t++)); do
    if lgin docker exec -i "$owner" sh -s -- -sf "http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" != 1 ]; then
    echo "::error::${label}: candidate never became healthy over loopback (egress policy may have changed its behavior)" >&2
    docker logs "fscache-cand-${label}" >&2 || true
    freeze_capture "$label"; teardown "$label"
    return 1
  fi
  # ---- load interval: real cache traffic, asserting status + bytes ----
  : > "/tmp/${label}.summary"
  local i key payload put resp get body
  for ((i = 1; i <= 20; i++)); do
    key="k${i}"
    payload="fostercache-payload-${i}-abcdefgh"
    put=$(lgin docker exec -i "$owner" sh -s -- -s -o /dev/null -w '%{http_code}' -X PUT --data-binary "$payload" "http://127.0.0.1:8080/${key}")
    case "$put" in
      200|201) ;;
      *) echo "::error::${label}: PUT ${key} returned status ${put} (expected 200/201)" >&2
         freeze_capture "$label"; teardown "$label"; return 1;;
    esac
    resp=$(lgin docker exec -i "$owner" sh -s -- -s -w $'\n%{http_code}' "http://127.0.0.1:8080/${key}")
    get=${resp##*$'\n'}
    body=${resp%$'\n'*}
    if [ "$get" != 200 ]; then
      echo "::error::${label}: GET ${key} returned status ${get} (expected 200)" >&2
      freeze_capture "$label"; teardown "$label"; return 1
    fi
    if [ "$body" != "$payload" ]; then
      echo "::error::${label}: GET ${key} returned wrong bytes (cache behavior differs)" >&2
      freeze_capture "$label"; teardown "$label"; return 1
    fi
    printf '%s PUT=%s GET=%s BYTES=%s\n' "$key" "$put" "$get" "${#body}" >> "/tmp/${label}.summary"
  done
  # ---- idle interval ----
  sleep 6
  # ---- freeze and analyze ----
  # Stop the capture, then stop the candidate so strace detaches,
  # flushes and closes its trace file before we read it. SIGTERM
  # (docker stop) lets strace flush; -o output is line-oriented.
  freeze_capture "$label"
  docker stop -t 15 "fscache-cand-${label}" >/dev/null 2>&1 || true
  sleep 1
  # (1) packet analysis (unchanged): sees emitted packets.
  analyze_pcap "/tmp/${label}.pcap" "$label" "$OWN_IP" "$OWN_IP6"
  # (2) candidate syscall analysis: sees the ATTEMPT even when no
  #     packet is emitted (the audited packetless-connect gap).
  analyze_strace "$TRACE_OUT/${label}.strace" "$label" "$OWN_IP" "$OWN_IP6"
  local dns ext sdns sext
  dns=$(cat "/tmp/${label}.dnscount")
  ext=$(cat "/tmp/${label}.extcount")
  sdns=$(cat "/tmp/${label}.sys.dnscount")
  sext=$(cat "/tmp/${label}.sys.extcount")
  if [ "$(cat "/tmp/${label}.sys.usable")" != "ok" ]; then
    echo "::error::${label}: candidate syscall trace was unusable (empty/garbage/unparseable) - failing closed, not counting it as clean" >&2
    cat "/tmp/${label}.sys.err" >&2 || true
    teardown "$label"
    return 1
  fi
  echo "${label}: allowed_exact={127.0.0.1, ::1, ${OWN_IP} (self)${OWN_IP6:+, ${OWN_IP6} (self6)}} packet[dns=${dns} non_allowed_outbound=${ext}] syscall[dns=${sdns} non_allowed_attempts=${sext}]"
  teardown "$label"
  # Both observers must be clean. Packet capture proves nothing was
  # emitted; syscall attribution proves nothing was even ATTEMPTED
  # (incl. attempts the kernel rejected before a packet - the false
  # pass the audit demonstrated with connect([2001:db8::7]:80)).
  if [ "$dns" -ne 0 ]; then
    echo "::error::${label}: candidate attempted name resolution (DNS) - seen on the wire" >&2
    cat "/tmp/${label}.dnsraw" >&2 || true
    return 1
  fi
  if [ "$ext" -ne 0 ]; then
    echo "::error::${label}: candidate attempted an outbound connection (UDP/TCP) to a non-allowed address - seen on the wire" >&2
    cat "/tmp/${label}.ext" >&2 || true
    return 1
  fi
  if [ "$sdns" -ne 0 ]; then
    echo "::error::${label}: candidate made a name-resolution syscall (connect/sendto/sendmsg to :53)" >&2
    grep '^DNS ' "/tmp/${label}.sys.ext" >&2 || true
    return 1
  fi
  if [ "$sext" -ne 0 ]; then
    echo "::error::${label}: candidate attempted an outbound connection syscall to a non-allowed address (attempt forbidden even if the kernel rejected it before a packet)" >&2
    grep '^OUT ' "/tmp/${label}.sys.ext" >&2 || true
    return 1
  fi
}

# negative_controls
# Separate phase, own networks and own pcaps, so it cannot contaminate
# the real measurement. Exercises EACH branch of the new detector and
# requires the SAME analysis apparatus to observe it. If it does not,
# the monitor is blind and no clean result can be trusted -> fail.
#
# Sub-phase A (ordinary control net): four deliberate outbound
# operations that each emit a packet - a startup DNS lookup, a
# private-TCP connect, a public-TCP connect, and a non-DNS UDP
# datagram to 203.0.113.1:4444 (the exact false negative the audit
# found). Each must be flagged.
#
# Sub-phase B (--internal control net): an outbound connect that is
# DENIED before any packet leaves. Packet capture is BLIND to it by
# construction; syscall attribution (strace) must observe the attempt.
# This proves the residual "denied before packet" gap and the method
# that closes it. Targets are RFC5737 TEST-NET-3 documentation
# addresses. `|| true` is only ever on the CONTROL traffic, never on
# the capture or analysis.
negative_controls() {
  local own_ip own_ip6

  echo "-- control A: packet-emitting outbound (DNS / private-TCP / public-TCP / non-DNS UDP) --"
  start_stack ctlopen fscache-nc-open
  own_ip="$OWN_IP"; own_ip6="$OWN_IP6"
  docker exec fscache-net-ctlopen sh -c 'dig +time=2 +tries=1 @203.0.113.53 probe.invalid >/dev/null 2>&1 || true'
  docker exec fscache-net-ctlopen sh -c 'nc -w 2 10.10.10.10 80 </dev/null >/dev/null 2>&1 || true'
  docker exec fscache-net-ctlopen sh -c 'nc -w 2 203.0.113.9 80 </dev/null >/dev/null 2>&1 || true'
  docker exec fscache-net-ctlopen sh -c 'printf audit-control | nc -u -w 1 203.0.113.1 4444 >/dev/null 2>&1 || true'
  sleep 2
  freeze_capture ctlopen
  analyze_pcap /tmp/ctlopen.pcap ctlopen "$own_ip" "$own_ip6"
  local cdns cext
  cdns=$(cat /tmp/ctlopen.dnscount)
  cext=$(cat /tmp/ctlopen.extcount)
  echo "control A: dns_packets=${cdns} non_allowed_outbound=${cext}"
  echo "control A flagged flows:"; cat /tmp/ctlopen.ext || true
  [ "$cdns" -ge 1 ] || fail "control A: startup DNS lookup NOT observed - monitor blind to name resolution"
  grep -q "^UDP .*> 203\.0\.113\.1:4444$" /tmp/ctlopen.ext || fail "control A: non-DNS UDP to 203.0.113.1:4444 NOT flagged (the audited false negative is not fixed)"
  grep -q "^TCP .*> 10\.10\.10\.10:80$"   /tmp/ctlopen.ext || fail "control A: private-TCP connect NOT flagged"
  grep -q "^TCP .*> 203\.0\.113\.9:80$"   /tmp/ctlopen.ext || fail "control A: public-TCP connect NOT flagged"
  teardown ctlopen

  echo "-- control B: denied-before-packet connect (syscall attribution) --"
  start_stack ctldenied fscache-nc-denied
  own_ip="$OWN_IP"; own_ip6="$OWN_IP6"
  # A benign loopback ICMP so the capture is provably live (not empty).
  docker exec fscache-net-ctldenied sh -c 'ping -c 1 -W 2 127.0.0.1 >/dev/null 2>&1 || true'
  # An outbound TCP connect on the --internal netns: it fails with
  # ENETUNREACH/EHOSTUNREACH before any SYN is emitted. strace observes
  # the connect() syscall (SYS_PTRACE); the packet monitor cannot.
  docker run --rm --net "container:fscache-net-ctldenied" --cap-add SYS_PTRACE nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b \
    sh -c 'command -v strace >/dev/null 2>&1 || { echo "MISSING-STRACE" >&2; exit 3; }; strace -f -e trace=connect nc -w 2 203.0.113.7 80' \
    > /tmp/ctldenied.strace 2>&1 || true
  sleep 1
  freeze_capture ctldenied
  analyze_pcap /tmp/ctldenied.pcap ctldenied "$own_ip" "$own_ip6"
  if grep -q 'MISSING-STRACE' /tmp/ctldenied.strace; then
    fail "control B: netshoot image lacks strace - cannot attribute operations denied before a packet is emitted"
  fi
  # The packet monitor is blind to the denied connect (no packet left):
  docker run --rm -v /tmp:/caps nicolaka/netshoot:v0.13@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b tshark -r /caps/ctldenied.pcap \
    -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 203.0.113.7' \
    -T fields -e frame.number 2>/dev/null > /tmp/ctldenied.leak || true
  if [ -s /tmp/ctldenied.leak ]; then
    fail "control B: a SYN to 203.0.113.7 WAS emitted - this control is not demonstrating a packetless denial"
  fi
  # Syscall attribution DID observe the attempt:
  grep -Eq 'connect\(.*203\.0\.113\.7' /tmp/ctldenied.strace || fail "control B: syscall attribution did NOT observe the denied-before-packet connect attempt"
  echo "control B: packet monitor non_allowed_outbound=$(cat /tmp/ctldenied.extcount) (blind); strace observed the connect():"
  grep -E 'connect\(.*203\.0\.113\.7' /tmp/ctldenied.strace | head -n 2 || true
  teardown ctldenied

  echo "-- control C: candidate-trace analyzer regression suite --"
  # The analyzer that judges the real candidate is the committed,
  # regression-tested bin/analyze-egress-trace.py. Run its suite
  # here so the release gate itself proves the analyzer catches
  # the connect AND sendmmsg packetless canaries and fails closed
  # on unusable traces - not a single ad-hoc example.
  bash bin/analyze-egress-trace-test.sh \
    || fail "control C: the candidate-trace analyzer regression suite failed"
          }

docker network create fscache-open >/dev/null 2>&1 || true
docker network create --internal fscache-denied >/dev/null 2>&1 || true
docker network create fscache-nc-open >/dev/null 2>&1 || true
docker network create --internal fscache-nc-denied >/dev/null 2>&1 || true

echo "== phase pre-0: build and prove the static candidate tracer =="
get_static_strace

echo "== phase 0: negative controls (prove the monitor detects every branch) =="
negative_controls

echo "== phase 1: ordinary network =="
run_scenario open fscache-open

echo "== phase 2: egress-denied (--internal) network =="
run_scenario denied fscache-denied

echo "== phase 3: identical cache behavior across policies (status + bytes) =="
if ! diff -u /tmp/open.summary /tmp/denied.summary; then
  echo "::error::service behaved differently under egress-denied vs ordinary network (status/bytes mismatch)" >&2
  exit 1
fi

echo "REQ-PRIV-001-AC1: the candidate was syscall-traced from its first instruction (static strace as entrypoint, -f across all threads/children) AND packet-captured in both policies. Packet monitor proven to catch DNS, non-DNS UDP and TCP SYN to non-allowed addresses; the candidate-trace analyzer proven (control C) to flag the packetless connect([2001:db8::7]:80) that packet capture misses while passing the clean loopback/self path. No DNS and no non-allowed outbound - emitted OR merely attempted (incl. kernel-rejected before a packet) - at startup, under load or idle in either policy; identical status codes and returned bytes across policies."
)

# stage-acceptance-egress.yml, job egress, step 4: report the AC this stage asserted
step_04() (
echo 'results=[{"ac":"REQ-PRIV-001-AC1","result":"pass"}]' >> "$GITHUB_OUTPUT"
)

step_02
step_04
