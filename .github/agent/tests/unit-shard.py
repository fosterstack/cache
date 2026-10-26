#!/usr/bin/env python3
"""One shard of the auditor's parser unit tests, for the coverage gate (CI speed, advisor item 6; REQ-AUD-018-AC2).

  unit-shard.py list            print the manifest: one `TEST <class-index> <test id>` line per test of the whole discovery, then
                                `unit-shard: list classes=C tests=T`. Nothing is executed.
  unit-shard.py run I N         run the tests whose class index is I (mod N) and print, on stdout, one `PASS|SKIP|FAIL <test id>` line per
                                test that finished, then `unit-shard: shard I/N classes=C tests=T ran=R` and
                                `unit-shard: P passed, S skipped, F failed`. The unittest text goes to stderr. Exit 0 only if every selected
                                test passed or was skipped and at least one test ran.

The unit is the TEST CLASS (module.Class), numbered 0.. in sorted order, so a class's setUpClass cost is paid by one shard only; every
shard imports every module (discovery is whole), so test_0000_arm_fs_guard.py still arms the runtime guard before any other module loads
(REQ-AUD-019-AC1). A module that fails to import is a refusal in both modes: it would silently remove its tests from the list.
UNIT_SHARD_DIR overrides the directory (the tests of this script use a fixture directory); the default is the auditor's .github/agent/bin/tests.
"""
import os
import re
import sys
import unittest

START = os.environ.get("UNIT_SHARD_DIR") or ".github/agent/bin/tests"


def refuse(why):
    print("unit-shard: REFUSED: " + why)
    sys.exit(2)


def flat(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from flat(t)
        else:
            yield t


def discover():
    tests = list(flat(unittest.defaultTestLoader.discover(START, pattern="test_*.py")))
    bad = [t.id() for t in tests if t.__class__.__module__ == "unittest.loader"]
    if bad:
        refuse("a test module failed to import or load (%s)" % ", ".join(sorted(bad)[:3]))
    cls = lambda t: "%s.%s" % (t.__class__.__module__, t.__class__.__qualname__)
    names = sorted({cls(t) for t in tests})
    index = {c: k for k, c in enumerate(names)}
    ids = [t.id() for t in tests]
    if len(set(ids)) != len(ids):
        refuse("two tests share an id")
    return tests, cls, index


class Result(unittest.TextTestResult):
    """One line per finished test: FAIL if anything failed in it (a failure, an error, a failing subtest, an unexpected success), else SKIP
    if it was skipped, else PASS (an expected failure counts as a pass, as unittest does)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.lines, self._status = [], {}
        self.groups = {}   # class name -> its selected test ids (set by main), for a skip raised by setUpClass / setUpModule

    def _mark(self, test, what):
        i = test.id()
        order = {"PASS": 0, "SKIP": 1, "FAIL": 2}
        if order[what] >= order.get(self._status.get(i, "PASS"), 0):
            self._status[i] = what

    def addFailure(self, test, err):
        super().addFailure(test, err); self._mark(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err); self._mark(test, "FAIL")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test); self._mark(test, "FAIL")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if isinstance(test, unittest.TestCase):
            self._mark(test, "SKIP")
            return
        # a skip raised by setUpClass / setUpModule: unittest names the class or module and never starts the tests under it, so each
        # of them gets its SKIP line here (else the sum check would see them as missing)
        m = re.fullmatch(r"setUp(?:Class|Module) \((.+)\)", test.id())   # a tearDown skip comes after the tests finished: they already have their line
        if m:
            for cname, ids in self.groups.items():
                if cname == m.group(1) or cname.startswith(m.group(1) + "."):
                    have = {x.split(" ", 1)[1] for x in self.lines}   # unittest can name one holder twice (a cleanup that also skips): once per test
                    self.lines.extend("SKIP " + i for i in ids if i not in have)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._mark(test, "FAIL")

    def stopTest(self, test):
        super().stopTest(test)
        self.lines.append("%s %s" % (self._status.pop(test.id(), "PASS"), test.id()))


def _run(runner, suite, res):
    """TextTestRunner.run with our own result object (the runner would build a fresh one), same start/stop/summary behavior."""
    import time
    unittest.registerResult(res)
    res.failfast, res.buffer = runner.failfast, runner.buffer
    t0 = time.perf_counter()
    try:
        suite(res)
    finally:
        unittest.removeResult(res)
    res.printErrors()
    runner.stream.write("Ran %d tests in %.3fs\n" % (res.testsRun, time.perf_counter() - t0))
    return res


def main(argv):
    if argv[1:] == ["list"]:
        tests, cls, index = discover()
        for t in tests:
            print("TEST %d %s" % (index[cls(t)], t.id()))
        print("unit-shard: list classes=%d tests=%d" % (len(index), len(tests)))
        return 0
    if len(argv) == 4 and argv[1] == "run" and argv[2].isdigit() and argv[3].isdigit() and int(argv[3]) >= 1 and int(argv[2]) < int(argv[3]):
        i, n = int(argv[2]), int(argv[3])
        tests, cls, index = discover()
        mine = [t for t in tests if index[cls(t)] % n == i]
        if not mine:
            refuse("shard %d/%d selects no test" % (i, n))
        suite = unittest.TestSuite(mine)
        runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=Result)
        groups = {}
        for t in mine:
            groups.setdefault(cls(t), []).append(t.id())
        res = runner._makeResult()
        res.groups = groups
        res = _run(runner, suite, res)
        for line in res.lines:
            print(line)
        passed = sum(1 for x in res.lines if x.startswith("PASS "))
        skipped = sum(1 for x in res.lines if x.startswith("SKIP "))
        failed = sum(1 for x in res.lines if x.startswith("FAIL ")) + (0 if res.wasSuccessful() else 1)   # a class-level error (setUpClass, a module fixture) is no test's line: count it here
        print("unit-shard: shard %d/%d classes=%d tests=%d ran=%d" % (i, n, len(index), len(tests), len(mine)))
        print("unit-shard: %d passed, %d skipped, %d failed" % (passed, skipped, failed))
        return 0 if res.wasSuccessful() else 1
    refuse("usage: unit-shard.py list | unit-shard.py run I N")


sys.exit(main(sys.argv))
