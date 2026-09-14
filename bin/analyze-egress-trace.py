#!/usr/bin/env python3
"""Analyze a candidate's strace (from `strace -f -e trace=network`) for any
OUTBOUND network attempt, for the no-outbound privacy acceptance
(REQ-PRIV-001-AC1, audit B03).

Usage: analyze-egress-trace.py <strace-file> <allowed-addr>...

Prints one line per violation to stdout:
    DNS <syscall> <dst>:<port>     - a name-resolution attempt (port 53)
    OUT <syscall> <dst>:<port>     - an outbound attempt to a non-allowed dst
Exit 0 with no output = clean. Exit 1 = a violation OR an unusable trace
(fail closed): an empty/garbage trace, or an outbound syscall carrying an
AF_INET/AF_INET6 family whose destination cannot be parsed, is NOT
evidence of "no attempts".

Detection covers connect, sendto, sendmsg AND sendmmsg (the batch send the
earlier awk analyzer ignored), and EVERY message destination within a
sendmmsg. The return status is deliberately ignored - a kernel-rejected
attempt (ENETUNREACH/EPERM/...) is still a forbidden attempt. Inbound
server operations (bind/listen/accept/recv*) are not outbound initiation
and are used only to confirm the trace is a real, usable strace.
"""
import re
import sys

# Syscalls that initiate outbound traffic / name resolution.
OUTBOUND = ("connect", "sendto", "sendmsg", "sendmmsg")
# Any recognized network syscall (proves the trace is a usable strace).
NET_SYSCALLS = OUTBOUND + ("socket", "bind", "listen", "accept", "accept4",
                           "recvfrom", "recvmsg", "recvmmsg", "getsockname",
                           "getpeername", "setsockopt", "getsockopt", "close")

# A strace line looks like:  [pid NNN] name(args...) = ret   (pid optional).
SYSCALL_RE = re.compile(r'^(?:\[pid\s+\d+\]\s*|\d+\s+)?([a-z_][a-z0-9_]*)\(')
# One AF_INET/AF_INET6 sockaddr block, split point.
FAMILY_RE = re.compile(r'sa_family=AF_INET6?\b')
IPV4_RE = re.compile(r'inet_addr\("([0-9.]+)"\)')
IPV6_RE = re.compile(r'inet_pton\(AF_INET6,\s*"([0-9A-Fa-f:.]+)"')
PORT_RE = re.compile(r'htons\((\d+)\)')


def join_unfinished(lines):
    """Rejoin strace's split records: `... <unfinished ...>` followed later
    by `... <... name resumed> rest`. Conservative: pair each unfinished
    with the next resumed line, so a batch-send split across the boundary
    is analyzed as one record."""
    out = []
    pending = None
    for ln in lines:
        if pending is not None:
            m = re.search(r'<\.\.\.\s+\w+\s+resumed>(.*)$', ln)
            if m:
                out.append(pending.replace('<unfinished ...>', '') + m.group(1))
                pending = None
                continue
            # no matching resume yet - flush the pending as-is and continue
            out.append(pending)
            pending = None
        if ln.rstrip().endswith('<unfinished ...>'):
            pending = ln
        else:
            out.append(ln)
    if pending is not None:
        out.append(pending)
    return out


def syscall_name(line):
    m = SYSCALL_RE.match(line.strip())
    return m.group(1) if m else None


def destinations_in(segment):
    """Return (addr, port) for one sockaddr segment, or (None, None) if the
    family is AF_INET(6) but no literal address is parseable."""
    v4 = IPV4_RE.search(segment)
    v6 = IPV6_RE.search(segment)
    addr = v4.group(1) if v4 else (v6.group(1) if v6 else None)
    p = PORT_RE.search(segment)
    port = p.group(1) if p else ""
    return addr, port


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: analyze-egress-trace.py <strace-file> <allowed-addr>...\n")
        sys.exit(2)
    path = sys.argv[1]
    allowed = set(a for a in sys.argv[2:] if a and a != "invalid IP")
    allowed.update({"127.0.0.1", "::1"})

    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        sys.stderr.write(f"::error::candidate trace {path} unreadable: {e}\n")
        sys.exit(1)
    if not raw.strip():
        sys.stderr.write(f"::error::candidate trace {path} is empty (tracer failure) - not evidence of no attempts\n")
        sys.exit(1)

    lines = join_unfinished(raw.splitlines())

    saw_net = False
    violations = []
    for line in lines:
        name = syscall_name(line)
        if name is None:
            continue
        if name in NET_SYSCALLS:
            saw_net = True
        if name not in OUTBOUND:
            continue
        # Split the line into per-sockaddr segments so a sendmmsg with
        # several msg_name blocks yields one destination each.
        starts = [m.start() for m in FAMILY_RE.finditer(line)]
        if not starts:
            continue  # an outbound call with no AF_INET(6) sockaddr (e.g. AF_UNIX/AF_NETLINK)
        for i, s in enumerate(starts):
            end = starts[i + 1] if i + 1 < len(starts) else len(line)
            seg = line[s:end]
            addr, port = destinations_in(seg)
            if addr is None:
                # An AF_INET/AF_INET6 outbound attempt whose destination we
                # cannot parse: fail closed rather than skip it.
                sys.stderr.write(f"::error::candidate trace has an AF_INET(6) {name} whose destination could not be parsed - refusing to treat an unreadable attempt as clean: {line.strip()[:200]}\n")
                sys.exit(1)
            if port == "53":
                violations.append(f"DNS {name} {addr}:{port}")
            elif addr not in allowed:
                violations.append(f"OUT {name} {addr}:{port}")
            # addr in allowed and port != 53 -> loopback/self, allowed

    if not saw_net:
        # A real strace of a serving cache always contains socket/bind/
        # listen/accept; a trace with none is garbage or a tracer failure.
        sys.stderr.write(f"::error::candidate trace {path} contains no recognizable network syscalls - unusable trace, failing closed\n")
        sys.exit(1)

    if violations:
        for v in violations:
            print(v)
        sys.exit(1)


if __name__ == "__main__":
    main()
