#!/usr/bin/env bash
# Repeatable regressions for the privacy candidate-trace analyzer (audit
# B03). Real strace-formatted fixtures: a clean serving cache, the
# connect and sendmmsg packetless canaries, and unusable traces (empty,
# garbage, unparseable destination). No Docker, no network - pure parser.
set -euo pipefail
cd "$(dirname "$0")/.."
CHK=bin/analyze-egress-trace.py
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
OWN=10.88.0.7   # a plausible netns self-IPv4 for the fixtures
pass=0; fail=0

run() { # description, expected-exit, file, [expected-substring-in-stdout]
  local desc="$1" want="$2" file="$3" needle="${4:-}"
  set +e
  out=$(python3 "$CHK" "$file" "$OWN" 2>"$TMP/err"); got=$?
  set -e
  local ok=1
  [ "$got" = "$want" ] || ok=0
  [ -z "$needle" ] || grep -qF "$needle" <<<"$out" || ok=0
  if [ "$ok" = 1 ]; then pass=$((pass+1)); else
    fail=$((fail+1)); echo "FAIL: ${desc} (exit ${got}, want ${want}) out=[${out}] err=[$(cat "$TMP/err")]"
  fi
}

# 1. Clean serving cache: socket/bind/listen/accept + a loopback connect.
cat > "$TMP/clean.strace" <<'T'
socket(AF_INET6, SOCK_STREAM, IPPROTO_IP) = 3<TCP:[150000]>
setsockopt(3<TCP:[150000]>, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
bind(3<TCP:[150000]>, {sa_family=AF_INET6, sin6_port=htons(8080), inet_pton(AF_INET6, "::", &sin6_addr), sin6_scope_id=0}, 28) = 0
listen(3<TCP:[150000]>, 4096) = 0
accept4(3<TCP:[150000]>, {sa_family=AF_INET, sin_port=htons(51000), sin_addr=inet_addr("127.0.0.1")}, [128 => 16], SOCK_CLOEXEC) = 5<TCP:[127.0.0.1:8080->127.0.0.1:51000]>
connect(6<TCP:[150100]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
T
run "clean serving cache" 0 "$TMP/clean.strace"

# self connect (own IP) is allowed too
cat > "$TMP/self.strace" <<T
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("${OWN}")}, 16) = 0
T
run "self-address connect allowed" 0 "$TMP/self.strace"

# 2. Original packetless connect canary
cat > "$TMP/connect.strace" <<'T'
socket(AF_INET6, SOCK_STREAM, IPPROTO_IP) = 4
connect(4, {sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::7", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network unreachable)
bind(3, {sa_family=AF_INET6, sin6_port=htons(8080), inet_pton(AF_INET6, "::", &sin6_addr)}, 28) = 0
listen(3, 4096) = 0
T
run "connect canary rejected" 1 "$TMP/connect.strace" "OUT connect 2001:db8::7:80"

# 3. The sendmmsg batch-send canary (the B03 miss) - real strace shape
cat > "$TMP/sendmmsg.strace" <<'T'
socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 4<UDPv6:[150168]>
sendmmsg(4<UDPv6:[150168]>, [{msg_hdr={msg_name={sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::7", &sin6_addr), sin6_scope_id=0}, msg_namelen=28, msg_iov=[{iov_base="audit", iov_len=5}], msg_iovlen=1, msg_controllen=0, msg_flags=0}}], 1, 0) = -1 ENETUNREACH (Network unreachable)
bind(3, {sa_family=AF_INET6, sin6_port=htons(8080), inet_pton(AF_INET6, "::", &sin6_addr)}, 28) = 0
listen(3, 4096) = 0
T
run "sendmmsg canary rejected" 1 "$TMP/sendmmsg.strace" "OUT sendmmsg 2001:db8::7:80"

# sendmmsg with TWO messages: both destinations must be flagged
cat > "$TMP/sendmmsg2.strace" <<'T'
socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4
sendmmsg(4, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.9")}, msg_namelen=16, msg_iov=[{iov_base="a", iov_len=1}], msg_iovlen=1}}, {msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("198.51.100.4")}, msg_namelen=16, msg_iov=[{iov_base="b", iov_len=1}], msg_iovlen=1}}], 2, 0) = -1 ENETUNREACH (Network unreachable)
listen(3, 4096) = 0
T
run "sendmmsg two dests both flagged (first)" 1 "$TMP/sendmmsg2.strace" "OUT sendmmsg 203.0.113.9:80"
run "sendmmsg two dests both flagged (second)" 1 "$TMP/sendmmsg2.strace" "OUT sendmmsg 198.51.100.4:4444"

# DNS attempt (port 53) is a violation
cat > "$TMP/dns.strace" <<'T'
socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 4
connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("203.0.113.53")}, 16) = 0
listen(3, 4096) = 0
T
run "DNS attempt flagged" 1 "$TMP/dns.strace" "DNS connect 203.0.113.53:53"

# 4. Fail-closed: empty
: > "$TMP/empty.strace"; run "empty trace fails closed" 1 "$TMP/empty.strace"

# 4b. Fail-closed: nonempty garbage (no recognizable network syscall)
printf 'this is not an strace\nrandom bytes 12345\n' > "$TMP/garbage.strace"
run "garbage trace fails closed" 1 "$TMP/garbage.strace"

# 4c. Fail-closed: an AF_INET6 outbound whose destination cannot be parsed
cat > "$TMP/unparsed.strace" <<'T'
socket(AF_INET6, SOCK_STREAM, IPPROTO_IP) = 4
connect(4, {sa_family=AF_INET6, sin6_port=htons(80), inet_pton(AF_INET6, /* corrupt */ ), sin6_scope_id=0}, 28) = -1 ENETUNREACH
listen(3, 4096) = 0
T
run "unparseable destination fails closed" 1 "$TMP/unparsed.strace"

# 5. Split record: sendmmsg unfinished/resumed rejoined
cat > "$TMP/split.strace" <<'T'
sendmmsg(4, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("203.0.113.1")} <unfinished ...>
listen(3, 4096) = 0
<... sendmmsg resumed>, msg_namelen=16}}], 1, 0) = -1 ENETUNREACH
T
run "split sendmmsg record flagged" 1 "$TMP/split.strace" "OUT sendmmsg 203.0.113.1:80"

echo "analyze-egress-trace: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
