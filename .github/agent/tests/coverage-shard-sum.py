#!/usr/bin/env python3
"""The coverage gate's check on the action-pin shards (advisor 0618; REQ-AUD-018-AC2).

Usage: coverage-shard-sum.py MANIFEST LOG...

MANIFEST is the dry listing of check-action-pins-test.sh (`PINS_DRY=1`): one `UNIT <index> <name>` line per unit, the full list. Each LOG is one
real shard's output. Exit 0 only if, for every shard I/N: the log is not a dry run (no UNIT/RUN lines), it has its summary line
`check-action-pins: shard I/N units=T ran=R` and closing line `check-action-pins: P passed, F failed` with F = 0 and no FAIL line; T equals the
manifest's unit count; the units that COMPLETED (a `PASS <name>` line each) are exactly the manifest units whose index is I (mod N) -- each
once, none missing, none from another shard, none unknown -- and R equals their number; and the shards are exactly 0..N-1, each once. The
units of all shards together are then the whole manifest exactly once. Anything else is a refusal. The summary counts alone prove nothing: a
dry run, or a shard that planned units it never ran, prints the same numbers.

Also required: each shard's closing pass count equals its completed units plus exactly one record of each bookkeeping check (so a pass
count that contradicts the units, or a repeated or missing bookkeeping record, is refused), and the manifest itself is a dry listing in which
nothing but the bookkeeping checks ran (its closing line says exactly that many passed and none failed), so a helper that forgot take()
shows up as extra work in the listing.

What this does NOT defend against, by design (documented exclusion, round "adversarial" of cache#500): forged producer output. The checker
trusts that the logs are the output of the shards the gate itself launched into a fresh temporary directory (coverage-gate.sh truncates every
log with its redirection and checks every child's exit status); a case cannot print into them because every case runs the checker under test
with its output discarded. Someone who can edit the test script or the gate can edit this checker too, and that change needs the independent
second review like every change under the auditor directory.
"""
import re
import sys

# the two bookkeeping checks every shard prints in addition to its units (they count the case_out calls, run or not)
BOOKKEEPING = {"pm-case-count", "pm-case-names"}


def refuse(why):
    print("coverage-shard-sum: REFUSED: " + why)
    sys.exit(1)


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        refuse("cannot read %s: %s" % (path, e))


def main(argv):
    if len(argv) < 3:
        refuse("usage: coverage-shard-sum.py MANIFEST LOG...")
    units = {}
    for x in read(argv[1]):
        m = re.fullmatch(r"UNIT ([0-9]+) (\S+)", x)
        if m:
            idx, name = int(m.group(1)), m.group(2)
            if idx in units.values() or name in units:
                refuse("the manifest repeats unit %r" % name)
            units[name] = idx
    total = len(units)
    if total < 1:
        refuse("the manifest lists no unit")
    mclose = [m for m in (re.fullmatch(r"check-action-pins: ([0-9]+) passed, ([0-9]+) failed", x) for x in read(argv[1])) if m]
    if len(mclose) != 1 or int(mclose[0].group(1)) != len(BOOKKEEPING) or int(mclose[0].group(2)) != 0:
        refuse("the manifest listing ran something besides the %d bookkeeping checks (or has no closing line): a helper without take()?" % len(BOOKKEEPING))
    seen, n_shards = [], None
    done_all = []
    for path in argv[2:]:
        lines = read(path)
        if any(re.match(r"(UNIT|RUN) ", x) for x in lines):
            refuse("%s is a dry run (UNIT/RUN lines), not an execution" % path)
        summ = [m for m in (re.fullmatch(r"check-action-pins: shard ([0-9]+)/([0-9]+) units=([0-9]+) ran=([0-9]+)", x) for x in lines) if m]
        closing = [m for m in (re.fullmatch(r"check-action-pins: ([0-9]+) passed, ([0-9]+) failed", x) for x in lines) if m]
        if len(summ) != 1 or len(closing) != 1:
            refuse("%s has %d shard summary line(s) and %d closing line(s), want one of each" % (path, len(summ), len(closing)))
        i, n, seen_units, ran = (int(summ[0].group(k)) for k in (1, 2, 3, 4))
        if int(closing[0].group(2)) != 0 or any(x.startswith("FAIL ") for x in lines):
            refuse("%s: a case failed" % path)
        if seen_units != total:
            refuse("%s saw a list of %d units, the full list is %d" % (path, seen_units, total))
        if n_shards is None:
            n_shards = n
        elif n != n_shards:
            refuse("%s says %d shards, another shard says %d" % (path, n, n_shards))
        done, book = [], []
        for x in lines:
            m = re.match(r"PASS (\S+) ", x)
            if m and m.group(1) in BOOKKEEPING:
                book.append(m.group(1))
            elif m:
                if m.group(1) not in units:
                    refuse("%s completed %r, which is not in the manifest" % (path, m.group(1)))
                done.append(m.group(1))
        if sorted(book) != sorted(BOOKKEEPING):
            refuse("%s has bookkeeping records %s, want exactly one each of %s" % (path, sorted(book), sorted(BOOKKEEPING)))
        if int(closing[0].group(1)) != len(done) + len(BOOKKEEPING):
            refuse("%s: the closing line says %s passed but %d units and %d bookkeeping checks completed"
                   % (path, closing[0].group(1), len(done), len(BOOKKEEPING)))
        if len(set(done)) != len(done):
            refuse("%s completed a unit more than once" % path)
        want = {name for name, idx in units.items() if idx % n == i}
        if set(done) != want:
            refuse("%s: units completed differ from shard %d/%d's share (missing %d, other %d)"
                   % (path, i, n, len(want - set(done)), len(set(done) - want)))
        if ran != len(done):
            refuse("%s says ran=%d but %d units completed" % (path, ran, len(done)))
        seen.append(i)
        done_all += done
    if sorted(seen) != list(range(n_shards)):
        refuse("shards seen %s, want exactly 0..%d once each" % (sorted(seen), n_shards - 1))
    if sorted(done_all) != sorted(units):
        refuse("the shards together did not complete the whole manifest exactly once")
    print("coverage-shard-sum: ok: %d shards completed all %d units exactly once, none failed" % (n_shards, total))


main(sys.argv)
