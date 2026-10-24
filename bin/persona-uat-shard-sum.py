#!/usr/bin/env python3
"""The sum proof of a suite that runs itself as parallel shards (REQ-CI-006; bin/persona-uat-shard.sh).

Usage: persona-uat-shard-sum.py MANIFEST LOG...

MANIFEST is the committed list of the suite's cases: one `SECTION<TAB>CASE` line per case (a name that occurs twice in a section is listed twice).
Each LOG is the output of one shard, I/N (a shard log), or of the tail (a log labelled `tail`, which runs the sections that need every shard's case
directories). A log holds `ok   CASE` and `FAIL CASE` lines, one line `persona-uat: shard I/N sections=A,B` (the sections it ran) and one closing line
`persona-uat: P passed, F failed`.

Exit 0 only if ALL of these hold; anything else is a refusal that names the case, section or shard:
  - the manifest lists at least one case;
  - the shards are exactly 0..N-1, each once, with the same N, plus at most one tail; every log has its `shard` line and its closing line;
  - the sections the logs declare are a partition of the manifest's sections: each section run by exactly one log, none missing, none unknown;
  - no log has a FAIL line, every closing line says F = 0 and P equals the number of that log's ok lines;
  - the ok lines of every log are cases of the sections that log declared, and, section by section, they are exactly the manifest's cases with their
    multiplicity: no case missing, none doubled, none unlisted, none run by a shard that does not own its section.
Then it prints the one line the counting step reads, `persona-uat: S passed, 0 failed`, where S is the SUM over all logs. A floor is held against that
sum, so it cannot be met by one shard alone. Counts alone prove nothing (a shard that never ran a section prints a smaller number that nobody checks):
the proof is the comparison with the manifest, case by case.
"""
import re
import sys
from collections import Counter


def refuse(why):
    print("persona-uat-shard-sum: REFUSED: " + why)
    sys.exit(1)


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        refuse("cannot read %s: %s" % (path, e))


def write_manifest(argv):
    """--write FILE LOG...: the manifest of a green sharded run, for a human to commit: SECTION<TAB>CASE per ok line, by the `section` marker line before it. Refuses a run with a
    FAIL line, a log without its closing line, or an ok line before any section marker."""
    out, rows = argv[2], []
    for path in argv[3:]:
        lines = read(path)
        if not [l for l in lines if re.fullmatch(r"persona-uat: ([0-9]+) passed, ([0-9]+) failed", l)]:
            refuse("%s has no closing summary line (the shard died or was cut off)" % path)
        sec = None
        for l in lines:
            m = re.fullmatch(r"persona-uat: section (\S+)", l)
            if m:
                sec = m.group(1)
            elif l.startswith("FAIL "):
                refuse("%s has a FAIL line: %s (a manifest is written from a green run only)" % (path, l))
            elif l.startswith("ok   "):
                if sec is None:
                    refuse("%s has an ok line before any section marker" % path)
                rows.append((sec, l[5:]))
    if not rows:
        refuse("no case in the logs")
    order = []
    for sec, _ in rows:
        if sec not in order:
            order.append(sec)
    with open(out, "w", encoding="utf-8") as fh:
        for sec in order:
            for s_, c in rows:
                if s_ == sec:
                    fh.write("%s\t%s\n" % (sec, c))
    print("persona-uat-shard-sum: wrote %d cases in %d sections to %s" % (len(rows), len(order), out))


def main(argv):
    if len(argv) >= 4 and argv[1] == "--write":
        return write_manifest(argv)
    if len(argv) < 3:
        refuse("usage: persona-uat-shard-sum.py MANIFEST LOG...")
    want = {}          # section -> Counter of cases
    for x in read(argv[1]):
        if not x.strip() or x.startswith("#"):
            continue
        sec, sep, case = x.partition("\t")
        if not sep or not sec or not case:
            refuse("the manifest line %r is not SECTION<TAB>CASE" % x)
        want.setdefault(sec, Counter())[case] += 1
    if not want:
        refuse("the manifest lists no case (a proof against nothing proves nothing)")
    logs = {}          # label ("0".."N-1" or "tail") -> (sections, ok Counter)
    n_of = set()
    total = 0
    for path in argv[2:]:
        lines = read(path)
        shard = [m for m in (re.fullmatch(r"persona-uat: shard (tail|[0-9]+/[0-9]+) sections=(.*)", l) for l in lines) if m]
        close = [m for m in (re.fullmatch(r"persona-uat: ([0-9]+) passed, ([0-9]+) failed", l) for l in lines) if m]
        if len(shard) != 1:
            refuse("%s has no (or more than one) `shard` line: not a shard log" % path)
        if len(close) != 1:
            refuse("%s has no closing summary line (the shard died or was cut off)" % path)
        label = shard[0].group(1)
        if "/" in label:
            i, n = label.split("/")
            n_of.add(int(n))
            label = i
        if label in logs:
            refuse("shard %s is given twice" % label)
        secs = [s for s in shard[0].group(2).split(",") if s]
        if len(set(secs)) != len(secs):
            refuse("%s declares a section twice" % path)
        oks = Counter(l[5:] for l in lines if l.startswith("ok   "))
        for l in lines:
            if l.startswith("FAIL "):
                refuse("%s has a FAIL line: %s" % (path, l))
        if int(close[0].group(2)) != 0:
            refuse("%s says %s failed" % (path, close[0].group(2)))
        if int(close[0].group(1)) != sum(oks.values()):
            refuse("%s: the closing count %s contradicts its %d ok lines" % (path, close[0].group(1), sum(oks.values())))
        logs[label] = (secs, oks)
        total += sum(oks.values())
    if len(n_of) != 1:
        refuse("the shards disagree on how many shards there are, or none is a numbered shard: %s" % sorted(n_of))
    n = n_of.pop()
    numbered = sorted(int(k) for k in logs if k != "tail")
    if numbered != list(range(n)):
        refuse("shards given %s, expected exactly 0..%d (a shard is missing or doubled)" % (numbered, n - 1))
    owner = {}
    for label, (secs, _) in logs.items():
        for s in secs:
            if s in owner:
                refuse("section %s is declared by shard %s and by shard %s" % (s, owner[s], label))
            if s not in want:
                refuse("section %s is not in the manifest" % s)
            owner[s] = label
    for s in sorted(want):
        if s not in owner:
            refuse("section %s was run by no shard (is a tail log missing?)" % s)
    for label, (secs, oks) in logs.items():
        mine = Counter()
        for s in secs:
            mine.update(want[s])
        for case, k in oks.items():
            if case not in mine:
                where = [s for s in want if case in want[s]]
                refuse("case %r ran in shard %s, which does not own its section%s" % (case, label, " (it belongs to %s)" % ",".join(where) if where else " (it is not in the manifest)"))
            if k > mine[case]:
                refuse("case %r ran %d times in shard %s, the manifest lists it %d times" % (case, k, label, mine[case]))
        for case, k in mine.items():
            if oks[case] < k:
                refuse("case %r of section(s) %s is missing from shard %s (%d of %d)" % (case, ",".join(secs), label, oks[case], k))
    print("persona-uat-shard-sum: %d shards%s, %d sections, %d cases, each exactly as the manifest lists" % (n, " and the tail" if "tail" in logs else "", len(want), total))
    print("persona-uat: %d passed, 0 failed" % total)


if __name__ == "__main__":
    main(sys.argv)
