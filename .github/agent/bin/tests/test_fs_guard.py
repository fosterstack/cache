"""REQ-AUD tripwire: tests must not touch real system paths. Importing this module (unittest discovery does, before any test
runs) arms fs_guard for the whole run; the tests below prove the guard bites and run the static scan over every test script."""
import os, re, subprocess, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fs_guard as G  # noqa: E402

G.install()
REPO = G.REPO

# Absolute system-path literals a test script may not contain. A leading boundary keeps URLs, relative paths and $VAR/path out.
SYS_DIRS = r"etc|usr|var|private|Library|System|opt|bin|sbin|dev|home|root|proc|sys|Users|tmp|Applications|Volumes|run|srv|lib|boot|mnt|nix"
SHEBANG = re.compile(r"#!\s*/(?:usr/)?bin/(?:env\s+)?[a-z0-9]+")     # a script's first line written into a fixture file: file content, not a path used
LITERAL = re.compile(r"(?<![A-Za-z0-9_.$/{}:\-~)])/(?:%s)(?:/|(?![A-Za-z0-9_\-]))" % SYS_DIRS)
HOME_USE = re.compile(r"~/|\$HOME|\$\{HOME|expanduser|Path\.home")
SELF = "bin/tests/test_fs_guard.py"


def test_files():
    out = subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True, text=True, check=True).stdout.split("\n")
    pat = re.compile(r"(^|/)(test_[^/]*\.py|[^/]*[-_]test\.py|[^/]*-tests?\.(sh|py)|[^/]*_tests?\.sh)$|^\.github/agent/tests/[^/]+\.(sh|py)$")
    return sorted(f for f in out if pat.search(f) and not f.endswith(SELF) and f != ".github/agent/tests/coverage-gate.sh")


def load_allow():
    import system_path_allowlist as A
    rows = []
    for n, row in enumerate(A.ROWS, 1):
        assert len(row) == 3 and len(row[2].strip()) >= 12, "allow-list row %d needs file, substring, reason" % n
        rows.append(tuple(p.strip() for p in row))
    return rows


def scan():
    allow = load_allow()
    used, bad = set(), []
    for rel in test_files():
        with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                if line.startswith("#!") or not (LITERAL.search(SHEBANG.sub("", line).replace("/dev/null", "")) or HOME_USE.search(line)):
                    continue
                hit = [a for a in allow if a[0] == rel and a[1] in line]
                if hit:
                    used.update(hit)
                else:
                    bad.append("%s:%d: %s" % (rel, n, line.strip()[:110]))
    return bad, [a for a in allow if a not in used]


class Static(unittest.TestCase):
    def test_no_test_script_names_a_real_system_path_outside_the_reviewed_allowlist(self):
        bad, _ = scan()
        self.assertEqual(bad, [], "system-path literals in tests (use a temp dir, or allow-list pure data with a reason):\n" + "\n".join(bad))

    def test_the_allowlist_has_no_stale_rows(self):
        _, stale = scan()
        self.assertEqual(stale, [], "allow-list rows that match nothing")

    def test_every_shell_test_that_makes_files_uses_mktemp(self):
        bad = []
        for rel in test_files():
            if not rel.endswith(".sh"):
                continue
            with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as fh:
                s = fh.read()
            if re.search(r"^\s*(mkdir|touch|cp|mv|ln)\s", s, re.M) and "mktemp" not in s and "tempfile" not in s:
                bad.append(rel)
        self.assertEqual(bad, [], "shell tests that write files without mktemp")


class Guard(unittest.TestCase):
    def test_open_of_a_system_file_raises(self):
        with self.assertRaises(G.SystemPathAccess):
            open("/etc/hostname")

    def test_stat_realpath_exists_readlink_listdir_of_system_paths_raise(self):
        for fn in (os.stat, os.lstat, os.readlink, os.path.realpath, os.path.exists, os.path.isfile, os.path.isdir, os.listdir):
            with self.assertRaises(G.SystemPathAccess, msg=fn.__name__):
                fn("/usr/local/bin")

    def test_a_symlink_in_the_temp_dir_to_a_system_file_is_refused_when_followed(self):
        with tempfile.TemporaryDirectory() as d:
            os.symlink("/etc/hostname", os.path.join(d, "l"))
            with self.assertRaises(G.SystemPathAccess):
                open(os.path.join(d, "l"))
            with self.assertRaises(G.SystemPathAccess):
                os.path.exists(os.path.join(d, "l"))
            self.assertTrue(os.path.islink(os.path.join(d, "l")))      # the link itself is a temp-dir object

    def test_the_violation_is_not_swallowed_by_except_exception(self):
        try:
            try:
                open("/etc/hostname")
            except Exception:
                self.fail("swallowed")
        except G.SystemPathAccess:
            pass

    def test_temp_repo_devnull_and_stdlib_stay_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "etc", "passwd"); os.makedirs(os.path.dirname(p))
            open(p, "w").close(); self.assertTrue(os.path.isfile(p)); self.assertEqual(os.listdir(d), ["etc"])
        open(os.devnull).close(); self.assertTrue(os.path.isdir(REPO)); self.assertTrue(os.path.isfile(os.__file__))

    def test_a_mutant_test_that_opens_a_system_file_fails_under_the_guard(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "test_mutant.py"), "w") as f:
                f.write("import unittest\nclass M(unittest.TestCase):\n    def test_x(self):\n        open('/etc/hostname').read()\n")
            r = subprocess.run([sys.executable, "-c",
                                "import sys; sys.path[:0]=[%r, %r]; import fs_guard; fs_guard.install(); import unittest; "
                                "unittest.main(module='test_mutant', argv=['x'])" % (G.HERE, d)], capture_output=True, text=True, cwd=d)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("SystemPathAccess", r.stderr)


if __name__ == "__main__":
    unittest.main()
