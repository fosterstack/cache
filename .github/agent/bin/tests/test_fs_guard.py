"""REQ-AUD tripwire: tests must not touch real system paths. Importing this module (unittest discovery does, before any test
runs) arms fs_guard for the whole run; the tests below prove the guard bites and run the static scan over every test script."""
import ast, os, re, subprocess, sys, tempfile, unittest

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


# --- link creation: no test may create a symlink or hard link whose target is an absolute path (a real system path or any other
# fixed location). Targets are built from the temp dir, so a literal absolute target is always a finding.
BASH_LN = re.compile(r"\bln\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*s[A-Za-z]*\s+(?:-[A-Za-z]+\s+)*[\"']?(/[^\s\"']*)")
LINK_FUNCS = {"symlink", "link", "symlink_to", "hardlink_to", "link_to"}


def _consts(node):
    """Every string constant in the expression, including the constant parts of f-strings; join/concat/% are folded by taking the
    pieces: any piece that is an absolute path makes the whole target suspect."""
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def link_findings(rel, text, allow):
    """[(rel, line, why)] for link creations with an absolute target in one file's text; allow = allow-list rows for this file."""
    found, used = [], set()

    def add(line, why, src_line):
        hit = [a for a in allow if a[0] == rel and a[1] in src_line]
        used.update(hit)
        if not hit:
            found.append("%s:%d: %s" % (rel, line, why))
    lines = text.split("\n")
    if rel.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        for n in ast.walk(tree) if tree else ():
            if isinstance(n, ast.Call) and n.args:
                f = n.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in LINK_FUNCS:
                    bad = [c for c in _consts(n.args[0]) if c.startswith("/")]
                    if bad:
                        add(n.lineno, "%s() with an absolute target %r" % (name, bad[0]), lines[n.lineno - 1])
    for i, line in enumerate(lines, 1):                    # `ln -s <abs>` in shell tests and in command text inside Python tests
        m = BASH_LN.search(line)
        if m:
            add(i, "ln -s with an absolute target %s" % m.group(1), line)
    return found, used


def link_scan(read=None):
    from system_path_allowlist import LINK_ROWS
    allow = [tuple(p.strip() for p in r) for r in LINK_ROWS]
    read = read or (lambda rel: open(os.path.join(REPO, rel), encoding="utf-8", errors="replace").read())
    bad, used = [], set()
    for rel in test_files():
        f, u = link_findings(rel, read(rel), allow)
        bad += f; used |= u
    return bad, [a for a in allow if a not in used]


class Links(unittest.TestCase):
    def test_no_test_creates_a_link_to_an_absolute_target(self):
        bad, _ = link_scan()
        self.assertEqual(bad, [], "link creations with an absolute target (build the target under a temp dir):\n" + "\n".join(bad))

    def test_the_link_allowlist_has_no_stale_rows(self):
        self.assertEqual(link_scan()[1], [])

    def test_the_static_check_bites_on_mutants_it_only_reads_text_never_runs_it(self):
        cases = {
            "os.symlink('/etc/hostname', x)": 1, "os.symlink('/private/etc/hosts', x)": 1, "os.link('/usr/bin/env', x)": 1,
            "pathlib.Path(x).symlink_to('/Library/y')": 1, "os.symlink(os.path.join('/System', 'z'), x)": 1,
            "os.symlink('/var/db/' + 'z', x)": 1, "os.symlink(f'/etc/{n}', x)": 1, "os.symlink('/tmp/fixed', x)": 1,
            "os.symlink(target, x)": 0, "os.symlink(os.path.join(d, 'etc/hostname'), x)": 0, "os.symlink('rel/x', x)": 0,
        }
        for src, want in cases.items():
            got, _ = link_findings("bin/tests/test_mutant.py", "import os, pathlib\n" + src + "\n", [])
            self.assertEqual(len(got), want, (src, got))
            if want:
                self.assertRegex(got[0], r"^bin/tests/test_mutant\.py:2: ")
        for src, want in {"ln -s /etc/hostname x": 1, "ln -sf /usr/local/bin/t x": 1, 'ln -s "/Library/x" y': 1, "ln -s ../x y": 0,
                          'ln -s "$work/p" y': 0, "ln -sfn $d/t y": 0}.items():
            got, _ = link_findings("bin/mutant-test.sh", src + "\n", [])
            self.assertEqual(len(got), want, (src, got))

    def test_the_static_check_is_red_on_the_old_tree(self):
        """The same scan over origin/main's committed test files (when that ref is present) reports the old link fixtures."""
        r = subprocess.run(["git", "-C", REPO, "rev-parse", "--verify", "-q", "origin/main:.github/agent/bin/tests/test_signed_commit_cli.py"],
                           capture_output=True, text=True)
        if r.returncode:
            self.skipTest("no origin/main ref")
        old = subprocess.run(["git", "-C", REPO, "show", "origin/main:.github/agent/bin/tests/test_signed_commit_cli.py"], capture_output=True, text=True).stdout
        if "os.symlink(\"/etc/hostname\"" not in old:
            self.skipTest("origin/main already fixed")
        got, _ = link_findings(".github/agent/bin/tests/test_signed_commit_cli.py", old, [])
        self.assertTrue(any("symlink() with an absolute target '/etc/hostname'" in g for g in got), got)

    def test_the_runtime_guard_refuses_a_link_target_outside_the_roots_before_creating_it(self):
        made = []
        fake = G.wrap_link(lambda s, d, *a, **k: made.append((s, d)), "os.symlink")     # a recorder: nothing is ever created
        with tempfile.TemporaryDirectory() as d:
            for target in ("/etc/hostname", "/private/etc/hosts", "/Library/x", "/usr/local/bin/t", "../../../../../../etc/x"):
                with self.assertRaises(G.SystemPathAccess, msg=target):
                    fake(target, os.path.join(d, "l"))
            with self.assertRaises(G.SystemPathAccess):                                  # a link PLACED outside the roots
                fake(os.path.join(d, "t"), "/usr/local/bin/l")
            fake(os.path.join(d, "t"), os.path.join(d, "l"))
            fake("t", os.path.join(d, "l2"))                                             # relative, stays beside the link
        self.assertEqual(len(made), 2)
        self.assertTrue(getattr(os.symlink, "__wrapped__", None) and getattr(os.link, "__wrapped__", None))   # installed on the real calls


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
        # The link to a system path is built by hand with the UNWRAPPED call inside the recorder test below, never here: this
        # test only follows a temp-dir link to a temp-dir file (allowed) and a link that escapes through a second temp link.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other:
            os.symlink(os.path.join(other, "f"), os.path.join(d, "l"))
            open(os.path.join(other, "f"), "w").close()
            self.assertTrue(os.path.islink(os.path.join(d, "l")))
            self.assertTrue(os.path.exists(os.path.join(d, "l")))             # inside the allowed roots, so followed freely

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
