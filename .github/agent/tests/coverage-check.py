#!/usr/bin/env python3
"""REQ-AUD-18 AC2 — the zero-uncovered check over a `coverage json` report.

usage: coverage-check.py <coverage.json> <exclusions.txt> [<report-out>] [--inventory <file>]

Exclusions file, one entry per line (`#` comments and blank lines ignored), each with a reason:
  <path>:<first>-<last>  <reason>   a line range in a measured file
  <glob>  <reason>                  whole files that are not auditor code (tests, doubles, vendored
                                    third-party code); `*` never crosses a `/`
A range must cover at least one unexecuted statement and NO executed one; a glob must match at
least one inventory file and no file the report measured. (The review loop's merge-blocker list
separately includes "an exclusion that hides testable code".)

The INVENTORY is every tracked .py under .github/agent/ (`git ls-files`, or --inventory: one path
per line) — independent of the coverage config. Every inventory file must be measured in the report
or matched by a glob entry, so no `omit`/`include`/`source` setting can drop a file silently. A
tracked symlink under .github/agent/ fails (it could alias measured code into an excluded path).

Fails on: any uncovered, non-excluded statement; an empty measurement; any malformed, stale or
over-wide entry; any line coverage.py excluded on its own (an inline `pragma: no cover`); any
inventory file neither measured nor excluded; any tracked symlink.
Writes a per-file table to <report-out> when given.
"""
import json, os, re, subprocess, sys

AGENT = ".github/agent/"
_RANGE = re.compile(r"^(?P<path>[^\s:]+):(?P<a>\d+)-(?P<b>\d+)\s+(?P<reason>\S.*)$")
_GLOB = re.compile(r"^(?P<glob>[^\s:]+)\s+(?P<reason>\S.*)$")


def _glob_re(g):
    return re.compile("^" + "".join("[^/]*" if c == "*" else re.escape(c) for c in g) + "$")


def load_exclusions(path):
    ranges, globs, errs = [], [], []
    for n, raw in enumerate(open(path), 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = _RANGE.match(s)
        if m:
            a, b = int(m["a"]), int(m["b"])
            if a > b:
                errs.append("exclusions line %d: range %d-%d is backwards" % (n, a, b))
            else:
                ranges.append((n, m["path"], a, b, m["reason"]))
            continue
        m = _GLOB.match(s)
        if m and m["glob"].startswith(AGENT) and m["glob"].endswith(".py"):
            globs.append((n, m["glob"], _glob_re(m["glob"]), m["reason"]))
            continue
        errs.append("exclusions line %d: want '<path>:<first>-<last>  <reason>' or "
                    "'<.github/agent/...py glob>  <reason>', got %r" % (n, s))
    return ranges, globs, errs


def check(cov, ranges, root, globs=(), inventory=None):
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
    if inventory is not None:
        for n, g, rx, _ in globs:
            if not any(rx.match(p) for p in inventory):
                errs.append("exclusions line %d: %s matches no tracked file — remove it" % (n, g))
            for p in sorted(p for p in files if rx.match(p)):
                errs.append("exclusions line %d: %s excludes %s, which the report MEASURES — "
                            "a whole-file entry may not hide measured code" % (n, g, p))
        for p in sorted(inventory):
            if p not in files and not any(rx.match(p) for _, _, rx, _ in globs):
                errs.append("%s: not measured and not excluded — every tracked .py under %s is "
                            "either covered or a reasoned whole-file entry" % (p, AGENT))
    total = cov_n = exc_n = 0
    for path in sorted(files):
        f = files[path]
        if f.get("excluded_lines"):
            errs.append("%s: line(s) %s excluded by an inline pragma / implicit rule — no inline "
                        "exclusions; use coverage-exclusions.txt with a reason"
                        % (path, _ranges(sorted(f["excluded_lines"]))))
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


def _tracked(root):
    """(tracked .py paths under .github/agent/, tracked symlinks there) from the git index."""
    out = subprocess.run(["git", "ls-files", "-s", "--", AGENT], cwd=root, capture_output=True,
                         text=True, check=True).stdout
    py, links = [], []
    for ln in out.splitlines():
        meta, path = ln.split("\t", 1)
        if meta.split()[0] == "120000":
            links.append(path)
        if path.endswith(".py"):
            py.append(path)
    return py, links


def main(argv):
    inv_file = None
    if "--inventory" in argv:
        i = argv.index("--inventory"); inv_file = argv[i + 1]; argv = argv[:i] + argv[i + 2:]
    cov = json.load(open(argv[0]))
    ranges, globs, errs = load_exclusions(argv[1])
    root = os.getcwd()
    if inv_file:
        inventory, links = [ln.strip() for ln in open(inv_file) if ln.strip()], []
    else:
        inventory, links = _tracked(root)
    errs += ["%s: tracked symlink under %s — not allowed (it could alias measured code into an "
             "excluded path)" % (p, AGENT) for p in links]
    more, table, (cov_n, total, exc_n) = check(cov, ranges, root, globs, inventory)
    errs += more
    if len(argv) > 2:
        with open(argv[2], "w") as fh:
            fh.write("\n".join(table) + "\n")
    for e in errs:
        print("::error::auditor python coverage: %s" % e)
    print("auditor python: %d/%d eligible statements covered, %d excluded in %d range(s); "
          "%d file(s) outside the gate by %d reasoned whole-file entr%s"
          % (cov_n, total, exc_n, len(ranges),
             sum(1 for p in inventory if p not in {os.path.relpath(k, root) if os.path.isabs(k) else k
                                                   for k in cov["files"]}),
             len(globs), "y" if len(globs) == 1 else "ies"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
