#!/usr/bin/env python3
"""Tell whether a network namespace is really sealed (v0.3.0 rule 40).

  net-probe.py

Connects to 192.0.2.1:9 (TEST-NET-1, never routed) and exits with the connect errno: 0 if it connected, ENETUNREACH (101)
inside a namespace with no route, another errno otherwise. The build drivers run it as `sudo unshare -n python3
bin/net-probe.py` after a failed sealed tool call: 101 means the sealed tool really attempted a network call (exit 4);
anything else means the namespace was not sealed, which is its own failure.
"""
import errno
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("192.0.2.1", 9))
except OSError as e:
    code = e.errno if e.errno else (errno.ETIMEDOUT if isinstance(e, socket.timeout) else 1)
    print("net-probe: connect to 192.0.2.1:9 failed: %s (errno %d)" % (e.strerror or e, code), file=sys.stderr)
    sys.exit(code)
finally:
    s.close()
print("net-probe: connected to 192.0.2.1:9 (errno 0)")
