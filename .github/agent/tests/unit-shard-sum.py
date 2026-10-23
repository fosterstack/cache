#!/usr/bin/env python3
"""The coverage gate's check on the unit-test shards (CI speed, advisor item 6; REQ-AUD-018-AC2).

Usage: unit-shard-sum.py MANIFEST LOG...

MANIFEST is `unit-shard.py list`: one `TEST <class-index> <id>` line per test and `unit-shard: list classes=C tests=T`. Each LOG is one real
shard's stdout (`unit-shard.py run I N`). Exit 0 only if every LOG is a real run of shard I/N (its summary `unit-shard: shard I/N classes=C
tests=T ran=R` and closing `unit-shard: P passed, S skipped, F failed` with F = 0, no FAIL line, C and T equal to the manifest's), the tests
that finished in it (a PASS or SKIP line each) are EXACTLY the manifest tests whose class index is I (mod N) -- each once, none missing, none
from another shard, none unknown -- R equals their number and P + S does too; and the shards are exactly 0..N-1, each once. All shards together
then completed the whole manifest exactly once. Anything else is a refusal.

Not defended, by design: forged producer output. The logs are the stdout of the shards the gate itself launched into a fresh temporary
directory, and the gate checks every child's exit status (a shard that is killed or times out is a non-zero status and fails the gate before this
check runs). Someone who can edit the gate can edit this checker too; that change needs the independent second review like every change here.
"""
import re
import sys


def refuse(why):
    print("unit-shard-sum: REFUSED: " + why)
    sys.exit(1)


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        refuse("cannot read %s: %s" % (path, e))


def main(argv):
    if len(argv) < 3:
        refuse("usage: unit-shard-sum.py MANIFEST LOG...")
    tests, mlines = {}, read(argv[1])
    for x in mlines:
        m = re.fullmatch(r"TEST ([0-9]+) (\S+)", x)
        if m:
            if m.group(2) in tests:
                refuse("the manifest repeats test %r" % m.group(2))
            tests[m.group(2)] = int(m.group(1))
    head = [m for m in (re.fullmatch(r"unit-shard: list classes=([0-9]+) tests=([0-9]+)", x) for x in mlines) if m]
    if len(head) != 1 or int(head[0].group(2)) != len(tests) or not tests:
        refuse("the manifest has no closing line, no test, or a closing line that disagrees with its tests")
    classes = int(head[0].group(1))
    if len({k for k in tests.values()}) != classes:
        refuse("the manifest's class count disagrees with its class indexes")
    total = len(tests)
    seen, n_shards, done_all = [], None, []
    for path in argv[2:]:
        lines = read(path)
        summ = [m for m in (re.fullmatch(r"unit-shard: shard ([0-9]+)/([0-9]+) classes=([0-9]+) tests=([0-9]+) ran=([0-9]+)", x) for x in lines) if m]
        closing = [m for m in (re.fullmatch(r"unit-shard: ([0-9]+) passed, ([0-9]+) skipped, ([0-9]+) failed", x) for x in lines) if m]
        if len(summ) != 1 or len(closing) != 1:
            refuse("%s has %d shard summary line(s) and %d closing line(s), want one of each" % (path, len(summ), len(closing)))
        i, n, c, t, ran = (int(summ[0].group(k)) for k in (1, 2, 3, 4, 5))
        p, s, f = (int(closing[0].group(k)) for k in (1, 2, 3))
        if f != 0 or any(x.startswith("FAIL ") for x in lines):
            refuse("%s: a test failed" % path)
        if (c, t) != (classes, total):
            refuse("%s saw %d classes / %d tests, the manifest has %d / %d" % (path, c, t, classes, total))
        if n_shards is None:
            n_shards = n
        elif n != n_shards:
            refuse("%s says %d shards, another shard says %d" % (path, n, n_shards))
        done = []
        for x in lines:
            m = re.fullmatch(r"(PASS|SKIP) (\S+)", x)
            if m:
                if m.group(2) not in tests:
                    refuse("%s finished %r, which is not in the manifest" % (path, m.group(2)))
                done.append(m.group(2))
        if len(set(done)) != len(done):
            refuse("%s finished a test more than once" % path)
        want = {name for name, idx in tests.items() if idx % n == i}
        if set(done) != want:
            refuse("%s: tests finished differ from shard %d/%d's share (missing %d, other %d)" % (path, i, n, len(want - set(done)), len(set(done) - want)))
        if ran != len(done) or p + s != len(done):
            refuse("%s: ran=%d, passed+skipped=%d, but %d tests finished" % (path, ran, p + s, len(done)))
        seen.append(i)
        done_all += done
    if sorted(seen) != list(range(n_shards)):
        refuse("shards seen %s, want exactly 0..%d once each" % (sorted(seen), n_shards - 1))
    if sorted(done_all) != sorted(tests):
        refuse("the shards together did not finish the whole manifest exactly once")
    print("unit-shard-sum: ok: %d shards finished all %d tests exactly once, none failed" % (n_shards, total))


main(sys.argv)
