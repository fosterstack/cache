#!/usr/bin/env python3
"""Ask a running candidate container what it reports at /statusz and judge the answer (REQ-FIPS-002-AC2).

    python3 -I bin/fips-image-posture.py check --arch A --variant V --port N [--user U --password P] --matrix FILE

One GET of http://127.0.0.1:N/statusz, never redirected, status exactly 200, one overall deadline, a capped
body, strict JSON, and .fips140_note equal to the expected string for the variant. Only after all of that is
the line 'linux/<arch> <variant>' appended to the matrix file. Any other outcome writes nothing to the matrix,
prints 'variant <name>: ...' (fixed text and repr()-quoted data only) to stderr. The exit code is 2 only when no
HTTP status line was received yet (refused, reset or closed connection, or the deadline expiring first): the
caller may retry that. Every other failure is final and exits 1.
Standard library only; the environment (proxies, credentials, files) is not read.
"""
import base64
import http.client
import json
import signal
import sys
import time

NOTES = {
    "production": "off",
    "debug": "off",
    "fips": "active (Go validated module v1.0.0, CMVP cert #5247)",
}
CAP = 64 * 1024
DEADLINE = 3
MATRIX = None
PASSWORD = ""
SEEN = []
ARCH = None
VARIANT = "?"


def on_alarm(sig, frame):
    raise TimeoutError("deadline")


def bad_constant(c):
    raise ValueError("constant %s" % q(c))


def scrub(text):
    if PASSWORD:
        text = text.replace(PASSWORD, "***").replace(repr(PASSWORD)[1:-1], "***")
    return text


def q(x):
    """repr()-quoted data, the password scrubbed out first, then cut to 80 characters."""
    return scrub(repr(x))[:80]


def fail(variant, why, code=1):
    signal.alarm(0)
    print("variant %s: %s" % (variant, scrub(why)[:600]), file=sys.stderr)
    sys.exit(code)


def tracking_response(*a, **k):
    r = http.client.HTTPResponse(*a, **k)
    SEEN.append(r)
    return r


def pairs(p):
    seen = set()
    for k, _ in p:
        if k in seen:
            raise ValueError("duplicate key %s" % q(k))
        seen.add(k)
    return dict(p)


def parse(argv):
    if not argv or argv[0] != "check":
        return None
    d, i = {}, 1
    while i < len(argv):
        k = argv[i]
        if k not in ("--arch", "--variant", "--port", "--user", "--password", "--matrix") or k in d or i + 1 >= len(argv):
            return None
        d[k] = argv[i + 1]
        i += 2
    if not all(k in d for k in ("--arch", "--variant", "--port", "--matrix")):
        return None
    if ("--user" in d) != ("--password" in d):
        return None
    if d["--arch"] not in ("amd64", "arm64") or d["--variant"] not in NOTES:
        return None
    if not (d["--port"].isascii() and d["--port"].isdigit() and 1 <= int(d["--port"]) <= 65535):
        return None
    return d


def main(argv):
    global MATRIX, ARCH, VARIANT, PASSWORD
    d = parse(argv)
    if d is None:
        fail("?", "usage: check --arch A --variant V --port N [--user U --password P] --matrix FILE")
    variant, MATRIX, ARCH = d["--variant"], d["--matrix"], d["--arch"]
    VARIANT = variant
    want = NOTES[variant]
    PASSWORD = d.get("--password", "")
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(DEADLINE)
    hdrs = {}
    if "--user" in d:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (d["--user"], d["--password"])).encode()).decode()
    t0 = time.monotonic()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", int(d["--port"]), timeout=DEADLINE)
        conn.response_class = tracking_response
        conn.request("GET", "/statusz", headers=hdrs)
        resp = conn.getresponse()
        if resp.status != 200:
            fail(variant, "HTTP status %s" % q(resp.status))
        buf = b""
        while True:
            if time.monotonic() - t0 > DEADLINE:
                fail(variant, "timeout")
            chunk = resp.read1(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > CAP:
                fail(variant, "body over the size cap")
        if resp.length not in (None, 0) or (resp.chunked and resp.chunk_left not in (None, 0)):
            fail(variant, "incomplete body")
    except (OSError, http.client.HTTPException) as e:
        got_status = bool(SEEN) and isinstance(SEEN[0].status, int)
        no_response = isinstance(e, OSError) or isinstance(e, http.client.RemoteDisconnected)
        fail(variant, "request failed: %s" % q(e), 1 if got_status or not no_response else 2)
    signal.alarm(0)
    if buf.startswith(b"\xef\xbb\xbf"):
        fail(variant, "BOM")
    try:
        doc = json.loads(buf.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad_constant)
    except Exception as e:
        fail(variant, "not strict JSON: %s" % q(e))
    if not isinstance(doc, dict):
        fail(variant, "not an object")
    got = doc.get("fips140_note")
    if not isinstance(got, str):
        fail(variant, "no fips140_note string")
    if got != want:
        fail(variant, "reports %s, want %s" % (q(got), q(want)))
    try:
        open(MATRIX, "a").write("linux/%s %s\n" % (ARCH, variant))
    except OSError as e:
        fail(variant, "matrix not writable: %s" % q(e))
    return 0


try:
    sys.exit(main(sys.argv[1:]))
except SystemExit:
    raise
except BaseException as e:
    fail(VARIANT, "unexpected error: %s" % q(e))
