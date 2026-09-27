#!/usr/bin/env python3
"""REQ-AUD-18 AC2 — the zero-uncovered check over a `coverage json` report.

usage: coverage-check.py <coverage.json> <exclusions.txt> [<report-out>]

Exclusions file: one range per line, `<path relative to the repo>:<first>-<last>  <reason>`
(`#` comments and blank lines ignored). Every range must carry a reason, must cover at least one
statement that is actually unexecuted, and must cover NO executed statement — a range that
hides code the suite already runs is stale or too wide and fails the gate (the review loop's
merge-blocker list separately includes "an exclusion that hides testable code").

Fails on: any uncovered, non-excluded statement; an empty measurement; any malformed, stale,
or over-wide exclusion. Writes a per-file table to <report-out> when given.
"""
import json, os, re, sys

_LINE = re.compile(r"^(?P<path>[^\s:]+):(?P<a>\d+)-(?P<b>\d+)\s+(?P<reason>\S.*)$")


def load_exclusions(path):
    ranges, errs = [], []
    for n, raw in enumerate(open(path), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = _LINE.match(s)
        if not m:
            errs.append("exclusions line %d: want '<path>:<first>-<last>  <reason>', got %r" % (n, s))
            continue
        a, b = int(m["a"]), int(m["b"])
        if a > b:
            errs.append("exclusions line %d: range %d-%d is backwards" % (n, a, b))
            continue
        ranges.append((n, m["path"], a, b, m["reason"]))
    return ranges, errs


def check(cov, ranges, root):
    files = {os.path.relpath(k, root) if os.path.isabs(k) else k: v for k, v in cov["files"].items()}
    errs, table = [], []
    excluded = {}
    for n, path, a, b, _ in ranges:
        f = files.get(path)
        if f is None:
            errs.append("exclusions line %d: %s is not a measured file" % (n, path))
            continue
        span = set(range(a, b + 1))
        hides = sorted(span & set(f["executed_lines"]))
        if hides:
            errs.append("exclusions line %d: %s:%d-%d covers EXECUTED line(s) %s — narrow it"
                        % (n, path, a, b, hides[:8]))
        hit = span & set(f["missing_lines"])
        if not hit:
            errs.append("exclusions line %d: %s:%d-%d excludes no unexecuted statement — remove it"
                        % (n, path, a, b))
        excluded.setdefault(path, set()).update(hit)
    total = cov_n = exc_n = 0
    for path in sorted(files):
        f = files[path]
        stmts = len(f["executed_lines"]) + len(f["missing_lines"])
        exc = excluded.get(path, set())
        unc = sorted(set(f["missing_lines"]) - exc)
        total += stmts - len(exc); cov_n += len(f["executed_lines"]); exc_n += len(exc)
        table.append("%-58s %5d stmts %5d excluded %5d uncovered" % (path, stmts, len(exc), len(unc)))
        if unc:
            errs.append("%s: %d uncovered statement(s) at line(s) %s" % (path, len(unc), _ranges(unc)))
    if total == 0:
        errs.append("no eligible statements measured — an empty measurement is not 100%")
    return errs, table, (cov_n, total, exc_n)


def _ranges(lines):
    out, start, prev = [], None, None
    for x in lines + [None]:
        if start is None:
            start = prev = x
        elif x == prev + 1:
            prev = x
        else:
            out.append(str(start) if start == prev else "%d-%d" % (start, prev))
            start = prev = x
    return ",".join(out)


def main(argv):
    cov = json.load(open(argv[0]))
    ranges, errs = load_exclusions(argv[1])
    more, table, (cov_n, total, exc_n) = check(cov, ranges, os.getcwd())
    errs += more
    if len(argv) > 2:
        with open(argv[2], "w") as fh:
            fh.write("\n".join(table) + "\n")
    for e in errs:
        print("::error::auditor python coverage: %s" % e)
    print("auditor python: %d/%d eligible statements covered, %d excluded in %d range(s)"
          % (cov_n, total, exc_n, len(ranges)))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
