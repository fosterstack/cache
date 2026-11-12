#!/usr/bin/env python3
# bin/suite-guard-run.py: the run-all half of the suite guard (bin/suite-guard.sh holds the checks; this file executes suites, so CI steps that only
# check files and floors do not read it). Run as `python3 -I bin/suite-guard-run.py ...`; a committed Python file, so the pin checker reads
# the one literal command line in ci.yml and not a shell script whose suite path is a variable.
#   run [--count-only] FLOORS SUITE PATH   runs `bash PATH` with stdin closed, requires a case count at or above the floor of SUITE, and (unless
#                                          --count-only, for a suite with known reds) a zero exit; prints `suite-guard: SUITE: count N (floor F) rc=R`
#   all [--count-only] FLOORS [ROOT]       runs every suite the floors file names (key = file name, found once under ROOT) through `run`; any failure fails.
#                                          A suite that a counting step of ROOT/.github/workflows/ci.yml already runs (REQ-CI-005) is not run again here: that step
#                                          is `python3 -I bin/suite-guard-run.py run FLOORS NAME PATH` (NAME the file name of PATH), runs the suite once, shows its
#                                          output, and holds it to its floor and to exit 0 itself. `all` also fails when such a step names an unfloored suite or a
#                                          NAME that is not the file name of its PATH (REQ-CI-005-AC2).
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


def cmd_run(floors, name, path, count_only, echo=True):
    try:
        if os.path.islink(path) or os.path.getsize(path) == 0 or not os.path.isfile(path):   # a symlink named for a suite is no suite (as `all` always held)
            raise OSError
    except OSError:
        print("suite-guard: suite %s: %s is empty or missing" % (name, path), file=sys.stderr)
        return 1
    with tempfile.NamedTemporaryFile("w+b", prefix="suite-guard-") as log:
        sys.stdout.flush()      # the runner's own earlier lines come out before the suite's bytes
        proc = subprocess.Popen(["bash", path], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for chunk in iter(lambda: proc.stdout.read1(65536), b""):   # the suite's own output stays in the step log as it would have under `bash PATH`
            log.write(chunk)
            if echo:
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


COUNTING = re.compile(r"(?:CHAIN_TEST_REQUIRE_NETCUT=1 )?python3 -I bin/suite-guard-run\.py run (\S+) (\S+) (\S+)(?: </dev/null)?")   # the one env prefix the floored steps of ci.yml carry; any other is not a counting step


def required_contexts(root):
    """The required-check contexts of ROOT/.github/policy/required-checks.json, or None when the file cannot be read (then no counting step is trusted)."""
    try:
        with open(os.path.join(root, ".github", "policy", "required-checks.json")) as f:
            return {c["context"] for c in json.load(f)["required_checks"]}
    except Exception:
        return None


def counting_steps(root, floors, names):
    """{suite name: PATH} of the counting steps of ROOT/.github/workflows/ci.yml that are trusted (REQ-CI-005), and the number of malformed ones.
    A counting step is trusted only if it is the WHOLE run text of its step (one line: no here-document, `exit` or branch around it), the step has no key but name and run,
    and its job has no key but name, runs-on and steps (no if, needs, strategy, container or continue-on-error that could skip it): a line that fails any of this is not
    trusted and its suite stays in the residual run of `all`. A line that mentions the runner's `run` form inside a longer step, or a counting step that names an
    unfloored suite, another floors file or a NAME that is not the file name of its PATH, is malformed and fails `all`."""
    wf = os.path.join(root, ".github", "workflows", "ci.yml")
    if not os.path.isfile(wf):
        return {}, 0
    try:
        import yaml
        with open(wf) as f:
            doc = yaml.safe_load(f)
        jobs = doc["jobs"]
        if not isinstance(jobs, dict):
            raise TypeError("jobs is not a mapping")
    except Exception as e:
        die("%s cannot be read as a workflow (%s)" % (wf, e))
    required = required_contexts(root)
    got, bad, seen = {}, 0, {}
    for jname, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        plain_job = set(job) <= {"name", "runs-on", "steps"}
        # a counting step is trusted only in a job whose failure turns the run red: a required check, or a job a required check needs
        gated = required is not None and (str(job.get("name", jname)) in required or any(
            isinstance(o, dict) and (str(o.get("name", on)) in required) and jname in (o.get("needs") if isinstance(o.get("needs"), list) else [o.get("needs")])
            for on, o in jobs.items()))
        for st in job["steps"]:
            if not isinstance(st, dict) or not isinstance(st.get("run"), str):
                continue
            lines = [l for l in st["run"].split("\n") if l.strip()]
            for line in lines:
                if "suite-guard-run.py run" not in line or line.lstrip().startswith("#"):
                    continue
                m = COUNTING.fullmatch(line.strip())
                if not m:
                    print("suite-guard: job %s: the line %r runs the suite runner in a form that is not `run FLOORS NAME PATH`" % (jname, line.strip()), file=sys.stderr)
                    bad = 1
                    continue
                fl, name, path = m.groups()
                seen[name] = seen.get(name, 0) + 1
                if seen[name] == 2:     # every counting line counts, trusted or not and in whatever order: a suite with two of them would run twice
                    print("suite-guard: the suite %s has more than one counting step (it would run twice)" % name, file=sys.stderr)
                    bad = 1
                if fl != floors or name not in names or os.path.basename(path) != name:
                    print("suite-guard: job %s: the counting step %r names a floors file other than %s, an unfloored suite, or a NAME that is not the file name of its PATH" % (jname, line.strip(), floors), file=sys.stderr)
                    bad = 1
                    continue
                if len(lines) != 1:
                    print("suite-guard: job %s: the counting line %r is not the whole of its step" % (jname, line.strip()), file=sys.stderr)
                    bad = 1
                elif plain_job and gated and set(st) <= {"name", "run"}:
                    got[name] = os.path.normpath(path)
    return got, bad


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
    names = suite_names(floors)
    counted, cbad = counting_steps(root, floors, set(names))
    bad = cbad
    for s in names:
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
        if s in counted:   # run, counted and held to its floor and exit 0 by its own step (REQ-CI-005-AC1), provided that step runs THE file this search found
            if os.path.normpath(os.path.relpath(found[0], root)) != counted[s]:
                print("suite-guard: the counting step of %s runs %s, not %s (the one file of that name under %s)" % (s, counted[s], os.path.relpath(found[0], root), root), file=sys.stderr)
                bad = 1
            else:
                print("suite-guard: %s: counted by its own step" % s)
            continue
        if cmd_run(floors, s, found[0], count_only, echo=False) != 0:
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
