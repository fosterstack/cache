#!/usr/bin/env python3
"""The coverage gate's check on the action-pin shards (advisor 0618; REQ-AUD-018-AC2).

Usage: coverage-shard-sum.py TOTAL LOG...

TOTAL is the full unit list, counted by the dry listing of check-action-pins-test.sh. Each LOG is one shard's output. Exit 0 only if
every shard log has its summary line `check-action-pins: shard I/N units=T ran=R` and its closing `check-action-pins: P passed, F failed`
with F = 0, the shards are exactly 0..N-1 each once, every shard saw the same list (T = TOTAL), and the R values sum to exactly TOTAL.
Anything else (a short or long sum, a missing, repeated or failing shard, an unreadable or summary-less log) is a refusal.
"""
import re
import sys


def refuse(why):
    print("coverage-shard-sum: REFUSED: " + why)
    sys.exit(1)


def main(argv):
    if len(argv) < 3:
        refuse("usage: coverage-shard-sum.py TOTAL LOG...")
    if not re.fullmatch(r"[0-9]+", argv[1]) or int(argv[1]) < 1:
        refuse("the expected total %r is not a positive integer" % argv[1])
    total = int(argv[1])
    seen, ran_sum, n_shards = [], 0, None
    for path in argv[2:]:
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError as e:
            refuse("cannot read %s: %s" % (path, e))
        summ = [m for m in (re.fullmatch(r"check-action-pins: shard ([0-9]+)/([0-9]+) units=([0-9]+) ran=([0-9]+)", x) for x in lines) if m]
        done = [m for m in (re.fullmatch(r"check-action-pins: ([0-9]+) passed, ([0-9]+) failed", x) for x in lines) if m]
        if len(summ) != 1 or len(done) != 1:
            refuse("%s has %d shard summary line(s) and %d closing line(s), want one of each" % (path, len(summ), len(done)))
        i, n, units, ran = (int(summ[0].group(k)) for k in (1, 2, 3, 4))
        if int(done[0].group(2)) != 0:
            refuse("%s: %s case(s) failed" % (path, done[0].group(2)))
        if units != total:
            refuse("%s saw a list of %d units, the full list is %d" % (path, units, total))
        if n_shards is None:
            n_shards = n
        elif n != n_shards:
            refuse("%s says %d shards, another shard says %d" % (path, n, n_shards))
        seen.append(i)
        ran_sum += ran
    if sorted(seen) != list(range(n_shards)):
        refuse("shards seen %s, want exactly 0..%d once each" % (sorted(seen), n_shards - 1))
    if ran_sum != total:
        refuse("the shards ran %d units, the full list is %d" % (ran_sum, total))
    print("coverage-shard-sum: ok: %d shards ran %d of %d units, none failed" % (n_shards, ran_sum, total))


main(sys.argv)
