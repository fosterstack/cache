#!/usr/bin/env python3
# bin/suite-guard-run.py: the run-all half of the suite guard (bin/suite-guard.sh holds the checks; this file executes suites, so CI steps that only
# check files and floors do not read it). Run as `python3 -I bin/suite-guard-run.py ...`; a committed Python file, so the pin checker reads
# the one literal command line in ci.yml and not a shell script whose suite path is a variable.
#   run [--count-only] FLOORS SUITE PATH   runs `bash PATH` with stdin closed, requires a case count at or above the floor of SUITE, and (unless
#                                          --count-only, for a suite with known reds) a zero exit; prints `suite-guard: SUITE: count N (floor F) rc=R`
#   all [--count-only] FLOORS [ROOT]       runs every suite the floors file names (key = file name, found once under ROOT) through `run`; any failure fails
# What this runs: only files named by key in the committed floors file, each found exactly once as a regular file (never a symlink) under ROOT; the pin
# checker reads this file's one literal command line in ci.yml, not the suites it dispatches (the documented other-language boundary: the suites are
# the repository's committed tests, each held by the suite guard's floors and by their own review).
import json
import os
import re
import subprocess
import sys
import tempfile

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suite-guard.sh")
USAGE = "usage: suite-guard-run.py run [--count-only] FLOORS SUITE PATH | all [--count-only] FLOORS [ROOT]"


def die(msg):
    print("suite-guard: " + msg, file=sys.stderr)
    sys.exit(1)


def guard(*args):
    p = subprocess.run(["bash", GUARD, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout.strip()


def cmd_run(floors, name, path, count_only):
    try:
        if os.path.getsize(path) == 0 or not os.path.isfile(path):
            raise OSError
    except OSError:
        print("suite-guard: suite %s: %s is empty or missing" % (name, path), file=sys.stderr)
        return 1
    with tempfile.NamedTemporaryFile("w+b", prefix="suite-guard-") as log:
        rc = subprocess.run(["bash", path], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT).returncode
        grc, n = guard("count", log.name)
    if grc != 0:
        print("suite-guard: suite %s: %s (rc=%d)" % (name, n, rc), file=sys.stderr)
        return 1
    frc, msg = guard("floor", floors, name, n)
    if frc != 0:
        print(msg, file=sys.stderr)
        return 1
    print("suite-guard: %s: count %s rc=%d" % (name, n, rc))
    if not count_only and rc != 0:
        print("suite-guard: suite %s exited %d" % (name, rc), file=sys.stderr)
        return 1
    return 0


def suite_names(floors):
    try:
        with open(floors) as f:
            d = json.load(f)
        if not isinstance(d, dict) or not d or not all(isinstance(v, int) and not isinstance(v, bool) for v in d.values()):
            raise ValueError("the floors file is not a non-empty JSON object of integer floors")
    except (OSError, ValueError) as e:
        die("the floors file %s cannot be read as suite floors (%s)" % (floors, e))
    for k in d:   # a suite name is a plain file name: no glob characters, escapes, separators or line breaks (the shell runner's find -name read it as a pattern)
        if not re.fullmatch(r"[A-Za-z0-9._+@-]+", k) or k in (".", ".."):
            die("the floors file names %r, which is not a plain file name" % k)
    return list(d)


def cmd_all(floors, root, count_only):
    if not os.path.isfile(floors) or os.path.getsize(floors) == 0:
        die("the floors file %s is empty or missing" % floors)
    # ROOT is a plain path: a conservative alphabet, no leading - ! ( (find reads those as expression syntax), no .. component (it changes what a .git
    # predicate sees), no line break; and every candidate path below it must stay in the alphabet too (a line break splits find's output into two paths)
    if not re.fullmatch(r"[A-Za-z0-9._+@/-]+", root) or root.startswith("-") or ".." in root.split("/"):
        die("the suite root %r is not a plain path" % root)
    if os.path.islink(root) or not os.path.isdir(root):   # ROOT is a real directory, as `find ROOT` (physical) required: a link would lead outside it
        die("the suite root %s is not a real directory (a symlink or missing)" % root)
    bad = 0
    for s in suite_names(floors):
        found = []
        for dp, dn, fn in os.walk(root):
            dn[:] = [d for d in dn if d != ".git"]
            q = os.path.join(dp, s)
            if ".git" in q.split(os.sep) or ".git" in os.path.abspath(q).split(os.sep):   # as -not -path '*/.git/*': any candidate below a .git directory, ROOT's own ancestors included
                continue
            if s in fn and os.path.isfile(q) and not os.path.islink(q):   # a regular file, as `find -type f` selected: a symlink named for a suite is no suite
                found.append(os.path.join(dp, s))
        if len(found) != 1:
            print("suite-guard: the floors file names %s, which is %d files under %s (it must be exactly one)" % (s, len(found), root), file=sys.stderr)
            bad = 1
            continue
        # every same-name regular file was counted above, so a duplicate with an odd path runs neither (fail closed); only now is the one match's path held to the alphabet
        if not re.fullmatch(r"[A-Za-z0-9._+@/-]+", found[0]):
            print("suite-guard: the suite %s is at %r, which is not a plain path; not run" % (s, found[0]), file=sys.stderr)
            bad = 1
            continue
        if cmd_run(floors, s, found[0], count_only) != 0:
            bad = 1
    if bad:
        sys.exit(1)


def main(argv):
    if not argv or argv[0] not in ("run", "all"):
        print(USAGE, file=sys.stderr)
        return 2
    sub, rest = argv[0], argv[1:]
    only = bool(rest) and rest[0] == "--count-only"
    if only:
        rest = rest[1:]
    if sub == "run":
        if len(rest) != 3:
            print(USAGE, file=sys.stderr)
            return 2
        return cmd_run(rest[0], rest[1], rest[2], only)
    if len(rest) not in (1, 2):
        print(USAGE, file=sys.stderr)
        return 2
    cmd_all(rest[0], rest[1] if len(rest) == 2 else ".", only)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
