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


def literal_findings(rel, text, allow):
    used, bad = set(), []
    for n, line in enumerate(text.split("\n"), 1):
        if line.startswith("#!") or not (LITERAL.search(SHEBANG.sub("", line).replace("/dev/null", "")) or HOME_USE.search(line)):
            continue
        hit = [a for a in allow if a[0] == rel and a[1] in line]
        if hit:
            used.update(hit)
        else:
            bad.append("%s:%d: %s" % (rel, n, line.strip()[:110]))
    return bad, used


def scan():
    allow = load_allow()
    used, bad = set(), []
    for rel in test_files():
        with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as f:
            b, u = literal_findings(rel, f.read(), allow)
        bad += b; used |= u
    return bad, [a for a in allow if a not in used]


# --- link creation: no test may create a symlink or hard link whose target is an absolute path (a real system path or any other
# fixed location). Targets are built from the temp dir, so a literal absolute target is always a finding.
SHELL_CMD = re.compile(r"(?<![A-Za-z0-9_./-])(ln|cp)\s+([^;&|)\n]*)")
CP_LINK_FLAGS = re.compile(r"^-[A-Za-z]*[sl][A-Za-z]*$|^--(symbolic-link|link)$")


def shell_link_target(line):
    """The absolute link target of an `ln` (soft or hard, any flags, `--`, --symbolic) or a link-making `cp` (-s, -l) on a line, or None.
    Quotes around the target are stripped; $VAR, $(..) and relative targets are not absolute and are not reported."""
    for m in SHELL_CMD.finditer(line):
        toks, flags, opts = m.group(2).split(), [], True
        for tok in toks:
            if opts and tok == "--":
                opts = False
                continue
            if opts and tok.startswith("-"):
                flags.append(tok)
                continue
            tgt = tok.strip("\"'")
            if m.group(1) == "cp" and not any(CP_LINK_FLAGS.match(f) for f in flags):
                break
            if tgt.startswith("/"):
                return tgt
            break
    return None


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
        tgt = shell_link_target(line)
        if tgt:
            add(i, "link made by ln/cp with an absolute target %s" % tgt, line)
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


def makes_files_without_temp(text):
    """True when a shell test creates files (mkdir/touch/cp/mv/ln at the start of a line) but never CALLS mktemp or python's tempfile.
    Comments and words inside strings do not count."""
    code = [l for l in text.split("\n") if not l.lstrip().startswith("#")]
    body = "\n".join(re.sub(r"\s#\s.*$", "", l) for l in code)
    makes = re.search(r"^\s*(mkdir|touch|cp|mv|ln)\s", body, re.M)
    calls = re.search(r"\$\(\s*mktemp\b|`\s*mktemp\b|^\s*[A-Za-z_]+=\s*mktemp\b|\btempfile\.(mkdtemp|mkstemp|TemporaryDirectory|NamedTemporaryFile|mktemp)\(", body, re.M)
    return bool(makes and not calls)


# A command at the START of a line (so not inside a quoted `case_ name bad "..."` argument) acting on an absolute system path.
CMD_START = re.compile(r"^\s*(?:cp|mv|rm|ln|cat|touch|mkdir|chmod|tee|install|tar|curl|wget)\b[^\n]*?(?<![A-Za-z0-9_.$/{}:\-~)])/(?:%s)(?:/|(?![A-Za-z0-9_\-]))" % SYS_DIRS)
REDIRECT = re.compile(r"(?<![0-9&])>>?\s*/(?:%s)(?:/|(?![A-Za-z0-9_\-]))" % SYS_DIRS)
OPEN_ABS = re.compile(r"\b(?:open|Path|listdir|scandir|stat|lstat|symlink|rmtree|copy\w*|move)\(\s*[rb]?[\"']/(?:%s)(?:/|[\"'])" % SYS_DIRS)


def real_command_on_system_path(line):
    if line.lstrip().startswith("#"):
        return False
    line = line.replace("/dev/null", "")
    return bool(CMD_START.search(line) or OPEN_ABS.search(line) or (REDIRECT.search(line) and re.match(r"\s*(echo|printf|cat|:)\b", line)))


def whole_file_row_commands():
    """Whole-file allow rows (empty substring) exempt every literal in the file, so the file may contain NO line that is a command
    acting on a system path. Lines inside a multi-line double-quoted fixture (workflow step text a case wraps in quotes) are skipped,
    tracked by quote parity; an added command at the start of an unquoted line fails here. (Per-pattern rows were not cheap for
    the 2000-line pin-checker suite, whose lines are overwhelmingly such text.)"""
    out = []
    for rel, sub, _ in load_allow():
        if sub:
            continue
        with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as fh:
            quoted = 0
            for n, line in enumerate(fh, 1):
                # track an open multi-line quoted string: an odd number of unescaped double quotes toggles it
                inside = quoted
                quoted ^= (len(re.findall(r'(?<!\\)"', line)) % 2)
                if not inside and real_command_on_system_path(line):
                    out.append("%s:%d: %s" % (rel, n, line.strip()[:100]))
    return out


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
                          'ln -s "$work/p" y': 0, "ln -sfn $d/t y": 0, "ln -s -- /etc/hostname x": 1, "ln --symbolic /etc/hosts x": 1,
                          "cp -s /etc/hosts x": 1, "cp -sf /etc/hosts x": 1, "cp --symbolic-link /etc/hosts x": 1, "ln /etc/hosts x": 1,
                          "cp /etc/hosts x": 0, "cp -r /tmp/a /tmp/b": 0, "ln -s $(which d) x": 0}.items():
            got, _ = link_findings("bin/mutant-test.sh", src + "\n", [])
            self.assertEqual(len(got), want, (src, got))

    def test_the_static_check_is_red_on_the_old_fixtures(self):
        """The old (origin/main) fixture lines, embedded as TEXT (never run): the scan reports each with its file:line."""
        old = 'x = 1\nos.symlink("/etc/hostname", os.path.join(self.dir.name, "docs", "link.md"))\n'
        got, _ = link_findings(".github/agent/bin/tests/test_signed_commit_cli.py", old, [])
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith(".github/agent/bin/tests/test_signed_commit_cli.py:2: symlink() with an absolute target '/etc/hostname'"), got)
        got, _ = link_findings(".github/agent/tests/check-action-pins-test.sh", 'case_ r24 bad "$(rb \'x\')" "ln -s /tmp/poison.txt reqs.txt"\n', [])
        self.assertEqual(len(got), 1, got)

    def test_the_runtime_guard_refuses_a_link_target_outside_the_roots_before_creating_it(self):
        made = []
        fake = G.wrap_link(lambda s, d, *a, **k: made.append((s, d)), "os.symlink")     # a recorder: nothing is ever created
        refused = []
        with tempfile.TemporaryDirectory() as d:
            for target in ("/etc/hostname", "/private/etc/hosts", "/Library/x", "/usr/local/bin/t", "../../../../../../etc/x"):
                with self.assertRaises(G.SystemPathAccess, msg=target):
                    fake(target, os.path.join(d, "l"))
                refused.append(target)
                self.assertEqual(made, [], "the recorder must NOT have been called for " + target)
            with self.assertRaises(G.SystemPathAccess):                                  # a link PLACED outside the roots
                fake(os.path.join(d, "t"), "/usr/local/bin/l")
            self.assertEqual((made, len(refused)), ([], 5))
            fake(os.path.join(d, "t"), os.path.join(d, "l"))
            fake("t", os.path.join(d, "l2"))                                             # relative, stays beside the link
        self.assertEqual(len(made), 2)
        self.assertTrue(getattr(os.symlink, "__wrapped__", None) and getattr(os.link, "__wrapped__", None))   # installed on the real calls


class Static(unittest.TestCase):
    def test_the_literal_scan_bites_on_a_mutant_file(self):
        bad, _ = literal_findings("bin/tests/test_mutant.py", "import os\nx = 1\nopen('/etc/hostname').read()\n", [])
        self.assertEqual(len(bad), 1, bad)
        self.assertTrue(bad[0].startswith("bin/tests/test_mutant.py:3: "), bad)
        for text in ("p = '/private/etc/hosts'", "ln -s a /Library/x", "echo $HOME/x", "os.path.expanduser('~')", "d = '/var/db/x'"):
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        for text in ("p = os.path.join(d, 'etc/hostname')", "u = 'https://e/etc/x'", "#!/usr/bin/env python3", "x = '/dev/null'"):
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)
        allow = [("f.py", "/etc/hostname", "pure data in a string that is only parsed")]
        self.assertEqual(literal_findings("f.py", "p = '/etc/hostname'", allow)[0], [])


    def test_no_test_script_names_a_real_system_path_outside_the_reviewed_allowlist(self):
        bad, _ = scan()
        self.assertEqual(bad, [], "system-path literals in tests (use a temp dir, or allow-list pure data with a reason):\n" + "\n".join(bad))

    def test_the_allowlist_has_no_stale_rows(self):
        _, stale = scan()
        self.assertEqual(stale, [], "allow-list rows that match nothing")

    def test_every_shell_test_that_makes_files_uses_mktemp(self):
        bad = []
        for rel in test_files():
            if rel.endswith(".sh"):
                with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as fh:
                    if makes_files_without_temp(fh.read()):
                        bad.append(rel)
        self.assertEqual(bad, [], "shell tests that write files without a mktemp call")

    def test_the_mktemp_check_wants_a_call_not_a_comment_or_a_word(self):
        mk = "mkdir -p x\n"
        self.assertTrue(makes_files_without_temp(mk))
        self.assertTrue(makes_files_without_temp("# uses mktemp somewhere\n" + mk))
        self.assertTrue(makes_files_without_temp('echo "no mktemp here"\n' + mk))
        self.assertFalse(makes_files_without_temp('w="$(mktemp -d)"\n' + mk))
        self.assertFalse(makes_files_without_temp("w=`mktemp -d`\n" + mk))
        self.assertFalse(makes_files_without_temp(mk.replace("mkdir", "touch") + "python3 -c 'import tempfile; tempfile.mkdtemp()'\n"))
        self.assertFalse(makes_files_without_temp("echo hi\n"))

    def test_a_whole_file_allow_row_cannot_hide_a_real_command_on_a_system_path(self):
        bad = whole_file_row_commands()
        self.assertEqual(bad, [], "a whole-file allow row covers a file with a command acting on a system path:\n" + "\n".join(bad))

    def test_the_whole_file_row_check_bites(self):
        cmds = ["cp x /etc/hosts", "rm -rf /tmp/x", "cat /etc/passwd", "mkdir -p /opt/y", "open('/etc/hostname')", "ln -s a /usr/b", "echo hi > /var/log/x", "printf x >> /etc/hosts"]
        for c in cmds:
            self.assertTrue(real_command_on_system_path(c), c)
        for c in ["case_ x bad \"$(r 'cp a /tmp/b')\"", "# cp x /etc/hosts", "  - run: rm -rf /tmp/x", "assert M._outside('/home/runner/work/x')", "echo hi"]:
            self.assertFalse(real_command_on_system_path(c), c)

class Guard(unittest.TestCase):
    def test_open_of_a_system_file_raises(self):
        with self.assertRaises(G.SystemPathAccess):
            open("/etc/hostname")

    def test_stat_realpath_exists_readlink_listdir_of_system_paths_raise(self):
        for fn in (os.stat, os.lstat, os.readlink, os.path.realpath, os.path.exists, os.path.isfile, os.path.isdir, os.listdir):
            with self.assertRaises(G.SystemPathAccess, msg=fn.__name__):
                fn("/etc")

    def test_a_symlink_in_the_temp_dir_to_a_system_file_is_refused_when_followed(self):
        # The link to a system path is built by hand with the UNWRAPPED call inside the recorder test below, never here: this
        # test only follows a temp-dir link to a temp-dir file (allowed) and a link that escapes through a second temp link.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other:
            os.symlink(os.path.join(other, "f"), os.path.join(d, "l"))
            open(os.path.join(other, "f"), "w").close()
            self.assertTrue(os.path.islink(os.path.join(d, "l")))
            self.assertTrue(os.path.exists(os.path.join(d, "l")))             # inside the allowed roots, so followed freely

    def test_the_violation_is_not_swallowed_by_except_exception(self):
        escaped = []
        try:
            try:
                open("/etc/hostname")
                self.fail("the open was not refused")
            except Exception:
                self.fail("swallowed by except Exception")
        except G.SystemPathAccess:
            escaped.append(1)
        self.assertEqual(escaped, [1])

    def test_ancestors_of_an_allowed_root_allow_metadata_only(self):
        saved = G.ROOTS
        try:
            for root in ("/mnt/rev/w", "/opt/zz/w", "/Users/zz/work/w"):
                G.ROOTS = [root, "/usr/lib/python3.12"]
                top = "/" + root.split("/")[1]
                for p in ("/", top, os.path.dirname(root), root, root + "/x/y.py", "/usr", "/usr/lib"):
                    for fn in (os.stat, os.lstat, os.path.realpath, os.path.exists, os.path.isdir):
                        try:
                            fn(p)
                        except G.SystemPathAccess:
                            self.fail("%s(%s) refused with root %s" % (fn.__name__, p, root))
                        except OSError:
                            pass
                os.path.realpath("/usr/lib/python3.12/os.py")
                for p in (os.path.dirname(root) + "-other", "/opt/other", "/etc"):
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        os.stat(p)
                for p in (top, os.path.dirname(root)):                     # an ancestor's CONTENTS stay off limits
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        os.listdir(p)
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        open(os.path.join(p, "f"))
        finally:
            G.ROOTS = saved

    def test_the_interpreter_environment_is_readable_not_writable_and_siblings_stay_refused(self):
        """CI shape: venv root /mnt/rev/work/cache (pyvenv.cfg, bin/, lib/), repo /mnt/rev/work/cache/cache."""
        saved = (G.ROOTS, G.ENV)
        try:
            G.ROOTS = ["/mnt/rev/work/cache/cache"]
            G.ENV = ["/mnt/rev/work/cache", "/usr/lib/python3.12"]
            cfg = "/mnt/rev/work/cache/pyvenv.cfg"
            G.check(cfg, "stat", False, True)
            G.check(cfg, "lstat", True, True)
            G.check("/mnt/rev/work/cache/lib/python3.12/site-packages/coverage/tracer.py", "open")           # read
            G.check("/usr/lib/python3.12/os.py", "realpath", False, True)
            for p in (cfg, "/mnt/rev/work/cache/bin/python"):                                              # but never written
                with self.assertRaises(G.SystemPathAccess, msg=p):
                    G.check(p, "open", write=True)
            G.check("/mnt/rev/work/cache/lib/python3.12/site-packages/x/__pycache__/m.pyc", "open", write=True)   # bytecode cache
            G.check("/mnt/rev/work/cache/cache/new.txt", "open", write=True)                              # the repo is writable
            for p in ("/mnt/rev/work/other/pyvenv.cfg", "/mnt/rev/work/cache2/pyvenv.cfg",
                      "/usr/local/bin/python3", "/etc/pyvenv.cfg"):
                for meta in (True, False):
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        G.check(p, "stat", False, meta)
            self.assertTrue(G._open_writes(("p", "w")) and G._open_writes(("p", "r+")) and G._open_writes(("p", None, os.O_WRONLY | os.O_CREAT)))
            self.assertFalse(G._open_writes(("p", "r")) or G._open_writes(("p", "rb", 0)) or G._open_writes(("p", None, os.O_RDONLY)))
        finally:
            G.ROOTS, G.ENV = saved

    def test_coverages_virtualenv_walk_is_allowed_for_pyvenv_cfg_only(self):
        """coverage/inorout.py asks os.path.exists(<dir>/pyvenv.cfg) for EVERY ancestor directory of each traced module."""
        def coverage_walk(module_file):
            d, hits = os.path.dirname(module_file), []
            while True:
                hits.append(os.path.exists(os.path.join(d, "pyvenv.cfg")))
                parent = os.path.dirname(d)
                if parent == d:
                    return hits
                d = parent
        # the real walk, from a traced test module up to / (the checkout may sit anywhere: /home/runner/work/cache/cache, /Users/..)
        self.assertTrue(coverage_walk(os.path.join(G.HERE, "test_panel.py")))
        saved = (G.ROOTS, G.ENV)
        try:
            G.ROOTS, G.ENV = ["/mnt/rev/work/cache/cache"], []                       # CI shape, interpreter elsewhere
            f = "/mnt/rev/work/cache/cache/.github/agent/bin/tests/test_panel.py"
            d = os.path.dirname(f)
            while True:
                G.check(os.path.join(d, "pyvenv.cfg"), "exists", False, True)       # every ancestor, up to /
                G.check(os.path.join(d, "pyvenv.cfg"), "lstat", True, True)
                if os.path.dirname(d) == d:
                    break
                d = os.path.dirname(d)
            for p in ("/mnt/rev/work/cache/secret", "/mnt/rev/work/cache/pyvenv.cfgx", "/mnt/rev/work/cache/xpyvenv.cfg",
                      "/mnt/rev/work/other/pyvenv.cfg", "/mnt/rev/work/cache/other/pyvenv.cfg", "/etc/pyvenv.cfg",
                      "/usr/local/bin/pyvenv.cfg", "/mnt/rev/work/cache/pyvenv.cfg/x"):
                with self.assertRaises(G.SystemPathAccess, msg=p):
                    G.check(p, "exists", False, True)
            for kind in ("open-read", "write", "listdir-of-the-dir"):               # the file's CONTENT and any write stay refused
                with self.assertRaises(G.SystemPathAccess, msg=kind):
                    if kind == "open-read":
                        G.check("/mnt/rev/work/cache/pyvenv.cfg", "open")
                    elif kind == "write":
                        G.check("/mnt/rev/work/cache/pyvenv.cfg", "open", False, True, write=True)
                    else:
                        G.check("/mnt/rev/work/cache", "os.listdir")
            with self.assertRaises(G.SystemPathAccess):
                os.stat("/etc/pyvenv.cfg")                                          # the installed wrappers agree
        finally:
            G.ROOTS, G.ENV = saved

    def test_interpreter_named_directories_allow_their_own_metadata_only(self):
        """coverage realpaths every sysconfig path (scripts, include, the user base ...) at start-up: /root/.local/bin on a bare box."""
        saved = (G.ROOTS, G.ENV, G.META)
        try:
            G.ROOTS, G.ENV, G.META = ["/mnt/rev/work/cache/cache"], [], ["/mnt/q/.local/bin"]
            for fn in ("stat", "lstat", "realpath", "exists"):
                for p in ("/mnt", "/mnt/q", "/mnt/q/.local", "/mnt/q/.local/bin"):
                    G.check(p, fn, False, True)
            for p in ("/mnt/q/.local/share", "/mnt/q/.local/bin/tool", "/mnt/q/other", "/mnt/r"):
                with self.assertRaises(G.SystemPathAccess, msg=p):
                    G.check(p, "stat", False, True)
            for ev in ("open", "os.listdir", "os.scandir"):                           # contents stay off limits
                with self.assertRaises(G.SystemPathAccess, msg=ev):
                    G.check("/mnt/q/.local/bin", ev)
        finally:
            G.ROOTS, G.ENV, G.META = saved

    def test_a_broad_system_prefix_is_never_an_environment_root(self):
        got = G._canon_set(["/usr", "/usr/local", "/opt/homebrew", "/Users", "/home", "/opt/hostedtoolcache/Python/3.12.3/x64"], drop_broad=True)
        self.assertIn("/opt/hostedtoolcache/Python/3.12.3/x64", got)
        self.assertFalse({"/usr", "/usr/local", "/opt/homebrew", "/Users", "/home"} & got, got)
        env = G._env_roots()
        self.assertNotIn("/usr", env); self.assertNotIn("/usr/local", env)
        with self.assertRaises(G.SystemPathAccess):
            os.stat("/etc")

    def test_the_other_metadata_calls_are_wrapped_too(self):
        for n in ("access", "statvfs", "pathconf"):
            with self.assertRaises(G.SystemPathAccess, msg=n):
                getattr(os, n)("/etc", *((os.R_OK,) if n == "access" else ("PC_NAME_MAX",) if n == "pathconf" else ()))
        for n in ("listxattr", "getxattr"):
            if hasattr(os, n):
                with self.assertRaises(G.SystemPathAccess, msg=n):
                    getattr(os, n)("/etc", *(("user.x",) if n == "getxattr" else ()))

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
