#!/usr/bin/env python3
# bin/suite-guard-run.py: runs one suite for CI (bin/suite-guard.sh holds the checks; this file executes a suite, so CI steps that only check files
# and floors do not read it). Run as `python3 -I bin/suite-guard-run.py run [--count-only] FLOORS SUITE PATH`: runs `bash PATH` with stdin closed,
# requires a case count at or above the floor of SUITE, and (unless --count-only, for a suite with known reds) a zero exit; prints
# `suite-guard: SUITE: count N rc=R`. A committed Python file, so the pin checker reads the one literal command line in ci.yml and not a shell
# script whose suite path is a variable.
import os
import subprocess
import sys
import tempfile

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suite-guard.sh")
USAGE = "usage: suite-guard-run.py run [--count-only] FLOORS SUITE PATH"


def guard(*args):
    p = subprocess.run(["bash", GUARD, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout.strip()


def cmd_run(floors, name, path, count_only):
    try:
        if os.path.islink(path) or os.path.getsize(path) == 0 or not os.path.isfile(path):   # a symlink named for a suite is no suite
            raise OSError
    except OSError:
        print("suite-guard: suite %s: %s is empty or missing" % (name, path), file=sys.stderr)
        return 1
    with tempfile.NamedTemporaryFile("w+b", prefix="suite-guard-") as log:
        sys.stdout.flush()      # the runner's own earlier lines come out before the suite's bytes
        proc = subprocess.Popen(["bash", path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for chunk in iter(lambda: proc.stdout.read1(65536), b""):   # the suite's own output stays in the step log as it would have under `bash PATH`
            log.write(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        rc = proc.wait()
        log.flush()
        grc, n = guard("count", log.name)
    if grc != 0:
        print("suite-guard: suite %s: %s (rc=%d)" % (name, n, rc), file=sys.stderr)
        return 1
    frc, msg = guard("floor", floors, name, n)
    if frc != 0:
        print(msg, file=sys.stderr)
        return 1
    print("suite-guard: %s: count %s rc=%d" % (name, n, rc)); sys.stdout.flush()
    if not count_only and rc != 0:
        print("suite-guard: suite %s exited %d" % (name, rc), file=sys.stderr)
        return 1
    return 0


def main(argv):
    if not argv or argv[0] != "run":
        print(USAGE, file=sys.stderr)
        return 2
    rest = argv[1:]
    only = bool(rest) and rest[0] == "--count-only"
    if only:
        rest = rest[1:]
    if len(rest) != 3:
        print(USAGE, file=sys.stderr)
        return 2
    return cmd_run(rest[0], rest[1], rest[2], only)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
