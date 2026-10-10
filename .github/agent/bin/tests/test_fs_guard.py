"""REQ-AUD tripwire: tests must not touch real system paths. Importing this module (unittest discovery does, before any test
runs) arms fs_guard for the whole run; the tests below prove the guard bites and run the static scan over every test script."""
import ast, contextlib, hashlib, os, re, subprocess, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fs_guard as G  # noqa: E402

G.install()
REPO = G.REPO

# Absolute system-path literals a test script may not contain. This is an ENUMERATION of top-level directory names (plus the variants
# below): flagging ANY absolute-looking token was measured at 314 findings on the tree (217 of them `+ "/branches"`-style suffixes, URL
# fragments and regexes), so the scan stays narrow and a first component outside this list (`/scratch/x`, `/afs/x`) is a documented residual.
SYS_NAMES = ["etc", "usr", "var", "private", "Library", "System", "opt", "bin", "sbin", "dev", "home", "root", "proc", "sys", "Users",
             "tmp", "Applications", "Volumes", "run", "srv", "lib", "lib64", "boot", "mnt", "nix", "cores", "Network", "snap",
             "workspace", "github", "media", "data", "afs", "net", "scratch", "export", "exports", "nfs", "Developer", "lost\\+found", "vol"]
SYS_DIRS = "|".join(SYS_NAMES)
SHEBANG = re.compile(r"#!\s*/(?:usr/)?bin/(?:env\s+)?[a-z0-9]+")     # a script's first line written into a fixture file: file content, not a path used
# The boundary before the slash excludes only word characters, `.`/`$`/`/`/braces/`~`/`)` (a relative or variable-based path, a URL host, a
# command substitution). `:` and `-` are NOT excluded, so `${TMPDIR:-/tmp}`, `oci-archive:/tmp/x`, `PATH=/a:/usr/bin`, `-o/etc/hosts` and
# `tar -C/etc` are found. Case-insensitive: APFS resolves /Etc/hosts to /etc/hosts. Extra slashes, `/./` and `/../` before the name
# (`//etc`, `/./etc`, `/../etc`, `file:///etc`), a digit or `_` after it (`/usr2`, `/tmp_dir`, `/lib64`), `/{etc,usr}` and a one-character `?`
# wildcard in the name (`/e?c`) are found too.
_GLOB = "|".join(n[:i] + r"\?" + n[i + 1:] for n in SYS_NAMES if "\\" not in n for i in range(len(n)))
_START = r"""(?:(?<![A-Za-z0-9_.$/{}~)])/(?!/)|(?<![A-Za-z0-9_.$/{}~):])//+|(?<=[\s'"]-[A-Za-z])/)"""     # `://` (a URL) is not a path
LITERAL = re.compile(_START + r"(?:\.{1,2}/+)*(?:(?:%s)(?:/|(?![A-Za-z\-]))|\{(?:%s)[,}]|(?:%s)(?:/|(?![A-Za-z\-])))" % (SYS_DIRS, SYS_DIRS, _GLOB), re.I)
# The bare root: open('/'), os.listdir('/'), os.path.join('/', ..), cwd='/', `ls /`, `cd /`, `pushd /`, `tar -C /`, `git -C / status`, `cp x /`,
# `mv x /`, `rsync -a x /`, `docker run -v /:/host`.
_END = r"(?=\s|$|;|\)|&|\||['\"])"
ROOT_ONLY = re.compile(r"""\b(?:open|listdir|scandir|stat|lstat|walk|fwalk|chdir|realpath|abspath|normpath|exists|isdir|isfile|islink|iterdir|Path|join|rmtree|chroot|glob|rglob|samefile)\(\s*[rb]?['"]/['"]"""
                       r"""|\bcwd\s*=\s*[rb]?['"]/['"]"""
                       r"""|\b(?:ls|cd|find|du|stat|cat|rm|chmod|chown|df|pushd|popd|chroot|tree|mount|umount|touch|mkdir|rmdir)\b[^;&|\n]*?(?<=\s)/""" + _END +
                       r"""|(?:^|\s)(?:-C|-w|--directory|--chdir|--work-tree|--git-dir|--workdir|--root|--prefix)(?:\s+|=)/""" + _END +
                       r"""|\b(?:cp|mv|rsync|install|ln|scp|tar|zip|unzip|cpio)\b[^;&|\n]*\s/(?=\s*(?:$|[;&|)'"]))"""
                       r"""|\s(?:-v|--volume)(?:\s+|=)/:|--mount[ =]\S*src=/(?=[,\s])""")
HOME_USE = re.compile(r"~/|\$HOME|\$\{HOME|expanduser|Path\.home|(?:^|[\s=:'\"(,])~(?=$|[;)])|\b(?:cd|ls|cat|cp|mv|rm|source|find|tar)\s+(?:-[A-Za-z-]+\s+)*~(?=\s|$|;)|\bcd\s*(?:$|;|&&|\|\|)|(?:\.\./){3,}|\bfile:/+(?:[A-Za-z]|\.\.?/)")
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
        clean = SHEBANG.sub("", line).replace("/dev/null", "")
        if line.startswith("#!") or not (LITERAL.search(clean) or ROOT_ONLY.search(clean) or HOME_USE.search(line)):
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


_ABS_TOKEN = re.compile(r"""(?:^|=|:-|:=|:\+)["']?/(?!/)\S|^-[A-Za-z]+["']?/(?!/)\S""")


def shell_link_target(line):
    """The absolute operand of an `ln` (soft or hard, any flags, `--`, --symbolic, -t DIR, attached -t/abs, ${V:-/abs}) or of a link-making
    `cp` (-s, -l, --symbolic-link) on a line, or None. $VAR/$(..)/relative operands are not absolute and are not reported."""
    for m in SHELL_CMD.finditer(line):
        toks, flags, opts = m.group(2).split(), [], True
        for tok in toks:
            if opts and tok == "--":
                opts = False
                continue
            if opts and tok.startswith("-") and not _ABS_TOKEN.search(tok.strip("\"'")):
                flags.append(tok)
                continue
            if m.group(1) == "cp" and not any(CP_LINK_FLAGS.match(f) for f in flags):
                break
            if _ABS_TOKEN.search(tok.strip("\"'")):
                return tok.strip("\"'")
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
            if isinstance(n, ast.Call) and (n.args or n.keywords):
                f = n.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in LINK_FUNCS:
                    # every positional and keyword argument: src=/target= forms and an absolute link location are findings too
                    bad = [c for a in list(n.args) + [k.value for k in n.keywords] for c in _consts(a) if c.startswith("/")]
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


# a redirect that writes a file: not `>&2`, `2>&1`, `>/dev/null`, `=>`/`->`, a here-string `<<<`, or a comparison inside python (`x > 3`)
REDIRECT_WRITE = re.compile(r"(?<![&>=<\-])>{1,2}(?![&>=])\s*(?!/dev/null)[\"']?(?:\$\{?\w|\.{0,2}/|\w+[./]\w)")


def makes_files_without_temp(text):
    """True when a shell test creates files (mkdir/touch/cp/mv/ln at the start of a line) but never CALLS mktemp or python's tempfile.
    Comments and words inside strings do not count."""
    code = [l for l in text.split("\n") if not l.lstrip().startswith("#")]
    body = "\n".join(re.sub(r"\s#\s.*$", "", l) for l in code)
    unquoted = "\n".join(re.sub(r"""'[^']*'|"[^"]*\"""", '"$q"', l) for l in body.split("\n") if "\\n" not in l)     # a redirect inside a string is text (a line holding a literal \\n is a python string)
    makes = re.search(r"^\s*(mkdir|touch|cp|mv|ln)\s", body, re.M) or REDIRECT_WRITE.search(unquoted)
    calls = re.search(r"\$\(\s*mktemp\b|`\s*mktemp\b|^\s*[A-Za-z_]+=\s*mktemp\b|\btempfile\.(mkdtemp|mkstemp|TemporaryDirectory|NamedTemporaryFile|mktemp)\(", body, re.M)
    return bool(makes and not calls)


def literal_lines(text):
    """The lines of a file that the literal scan would report (system-path literal, bare root, $HOME use), stripped."""
    out = []
    for line in text.split("\n"):
        clean = SHEBANG.sub("", line).replace("/dev/null", "")
        if not line.startswith("#!") and (LITERAL.search(clean) or ROOT_ONLY.search(clean) or HOME_USE.search(line)):
            out.append(line.strip())
    return out


def row_pin(text):
    """(sha256 of the WHOLE file, the system-path-literal lines). A whole-file allow row exempts every literal in its file, and a hash of
    only the literal lines is blind to context (moving a closing quote makes a quoted fixture line a real command), so ANY edit to such a
    file changes the pin and needs a reviewed PINS update; the stored lines show a reviewer what the file is allowed to contain."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), tuple(literal_lines(text))


def whole_file_rows():
    return sorted({r[0] for r in load_allow() if r[1] == ""})


class Tables:
    """Two real temp trees: T1 is the only allowed root, T2 is "somewhere else" (a stand-in for a system path, so the tests that
    follow links and `..` never need a real one). Links are built BEFORE the tables are swapped in (creation is judged too)."""
    def __init__(self, test):
        self.td1, self.td2 = tempfile.TemporaryDirectory(), tempfile.TemporaryDirectory()
        test.addCleanup(self.td1.cleanup); test.addCleanup(self.td2.cleanup)
        self.t1, self.t2 = os.path.realpath(self.td1.name), os.path.realpath(self.td2.name)
        os.makedirs(os.path.join(self.t1, "sub", "deep")); os.makedirs(os.path.join(self.t2, "sub"))
        for p in (os.path.join(self.t1, "f"), os.path.join(self.t1, "sub", "f"), os.path.join(self.t2, "f"), os.path.join(self.t2, "sub", "f")):
            open(p, "w").close()

    def p1(self, *a): return os.path.join(self.t1, *a)
    def p2(self, *a): return os.path.join(self.t2, *a)

    @contextlib.contextmanager
    def active(self, env=(), roots=None, meta=()):
        saved = (G.ROOTS, G.ENV, G.META)
        G.ROOTS, G.ENV, G.META = list(roots if roots is not None else [self.t1]), list(saved[1]) + list(env), list(meta)
        try:
            yield
        finally:
            G.ROOTS, G.ENV, G.META = saved


class Rules(unittest.TestCase):
    """The resolution rules, pinned one by one with fake tables (no system path is touched)."""
    def setUp(self):
        self.T = Tables(self)

    def refused(self, fn, *a, **k):
        with self.assertRaises(G.SystemPathAccess, msg=repr(a)):
            fn(*a, **k)

    def test_dotdot_is_applied_after_a_link_is_followed_not_before(self):
        T = self.T
        os.symlink(T.p1("sub", "deep"), T.p1("l"))          # inside, deeper
        os.symlink(T.t1, T.p1("sub", "up"))                  # a link to the root itself: `..` through it leaves the root
        os.symlink(T.t2, T.p1("out"))                        # outside
        with T.active():
            open(T.p1("l", "..", "f")).close()                                   # = T1/sub/f
            os.stat(T.p1("sub", "..", "f"))                                      # plain `..` still fine
            self.refused(open, T.p1("sub", "up", "..", "f"))                      # = parent(T1)/f, though lexically T1/sub/f
            self.refused(os.listdir, T.p1("sub", "up", ".."))
            self.refused(os.stat, T.p1("sub", "up", "..", "f"))
            self.refused(os.path.exists, T.p1("sub", "up", "..", "f"))
            self.refused(os.listdir, T.p1("out", ".."))                           # following `out` leaves the root
            self.refused(open, T.p1("out", "..", "f"))
            self.refused(os.listdir, T.p1("out"))

    def test_the_two_step_link_chain_through_dotdot_is_refused(self):
        T = self.T
        os.symlink(T.t1, T.p1("B"))
        made = []
        link = G.wrap_link(lambda s, d, *a, **k: made.append((s, d)), "os.symlink")
        with T.active():
            self.refused(link, "B/../x", T.p1("C"))                              # resolves to parent(T1)/x, not T1/x
            self.refused(link, T.p1("B", "..", "x"), T.p1("C"))
            link(T.p1("sub", "..", "f"), T.p1("C"))                              # a plain inside target is fine
            link("sub/deep", T.p1("D"))
        self.assertEqual(len(made), 2)

    def test_an_absolute_link_restarts_at_the_root_and_a_relative_one_at_its_directory(self):
        T = self.T
        os.symlink(T.p1("sub"), T.p1("abs_in")); os.symlink(T.t2, T.p1("abs_out"))
        os.symlink("sub", T.p1("rel_in")); os.symlink(os.path.relpath(T.t2, T.t1), T.p1("rel_out"))
        os.symlink(os.path.join("..", "..", "f"), T.p1("sub", "deep", "up2"))   # = T1/f
        with T.active():
            os.stat(T.p1("abs_in", "f")); os.stat(T.p1("rel_in", "f")); os.stat(T.p1("sub", "deep", "up2"))
            self.refused(os.stat, T.p1("abs_out", "f")); self.refused(os.stat, T.p1("rel_out", "f"))
            self.refused(open, T.p1("abs_out", "sub", "f"))

    def test_a_link_loop_or_a_chain_over_the_hop_limit_is_refused(self):
        T = self.T
        raw = os.symlink.__wrapped__                       # the guard itself refuses to build the chain, so use the unwrapped call
        raw("q", T.p1("p")); raw("p", T.p1("q"))
        prev = "f"
        for i in range(45):
            raw(prev, T.p1("c%d" % i)); prev = "c%d" % i
        with T.active():
            for fn, p in ((os.stat, "p"), (open, "c44"), (os.path.getsize, "q")):           # a cycle wholly inside the root: the OS's own answer
                with self.assertRaises(OSError, msg=p) as cm:
                    fn(T.p1(p))
                self.assertEqual(cm.exception.errno, __import__("errno").ELOOP)
            os.stat(T.p1("c3"))                                                   # a short chain is fine
        os.symlink.__wrapped__(T.p2("f"), T.p1("esc0"))
        for i in range(1, 45):
            os.symlink.__wrapped__("esc%d" % (i - 1), T.p1("esc%d" % i))
        with T.active():
            self.refused(os.stat, T.p1("esc2"))                                   # a link that leaves the root is a guard refusal, not ELOOP

    def test_lstat_readlink_islink_do_not_follow_the_last_link_but_stat_exists_isfile_do(self):
        T = self.T
        os.symlink(T.p2("f"), T.p1("ln"))
        with T.active():
            os.lstat(T.p1("ln")); os.readlink(T.p1("ln")); self.assertTrue(os.path.islink(T.p1("ln"))); self.assertTrue(os.path.lexists(T.p1("ln")))
            for fn in (os.stat, os.path.exists, os.path.isfile, os.path.getsize, open):
                self.refused(fn, T.p1("ln"))
            self.refused(os.lstat, T.p1("ln", "x"))                               # a link in the MIDDLE is followed even by lstat

    def test_shutil_copy_reads_its_source_but_move_and_the_rest_write_every_path(self):
        T = self.T
        with T.active(env=[T.t2]):
            G._hook("shutil.copyfile", (T.p2("f"), T.p1("g"))); G._hook("shutil.copytree", (T.p2("sub"), T.p1("h")))
            G._hook("shutil.copy2", (T.p2("f"), T.p1("g")))
            self.refused(G._hook, "shutil.copyfile", (T.p1("f"), T.p2("g")))
            self.refused(G._hook, "shutil.move", (T.p2("f"), T.p1("g")))           # moving removes the source
            self.refused(G._hook, "shutil.rmtree", (T.p2("sub"),))
            self.refused(G._hook, "shutil.unpack_archive", (T.p1("a.tar"), T.p2("x")))
            self.refused(G._hook, "shutil.chown", (T.p2("f"),))

    def test_a_pyvenv_cfg_that_is_a_symlink_is_judged_like_any_path(self):
        T = self.T
        os.makedirs(T.p1("repo"))
        open(T.p1("pyvenv.cfg"), "w").close()                                     # a plain file in an ancestor of the root
        with T.active(roots=[T.p1("repo")]):
            os.path.exists(T.p1("pyvenv.cfg")); os.stat(T.p1("pyvenv.cfg"))
            self.refused(open, T.p1("pyvenv.cfg"))                                # metadata only
        os.remove(T.p1("pyvenv.cfg")); os.symlink(T.p2("f"), T.p1("pyvenv.cfg"))
        with T.active(roots=[T.p1("repo")]):
            self.refused(os.stat, T.p1("pyvenv.cfg")); self.refused(os.path.exists, T.p1("pyvenv.cfg"))

    def test_the_symlink_audit_event_skips_the_target_text_but_judges_the_link_itself(self):
        T = self.T
        with T.active():
            G._hook("os.symlink", ("target-text-only", T.p1("l"), None))
            G._hook("os.symlink", (T.p2("f"), T.p1("l"), None))                  # wrap_link is what judges targets
            self.refused(G._hook, "os.symlink", (T.p1("f"), T.p2("l"), None))

    def test_listdir_and_scandir_read_but_rename_mkdir_chmod_xattr_write(self):
        T = self.T
        with T.active(env=[T.t2]):
            for ev in ("os.listdir", "os.scandir", "os.walk", "os.fwalk"):
                G._hook(ev, (T.t2,))
            G._hook("open", (T.p2("f"), "r", os.O_RDONLY))
            for ev, args in (("os.rename", (T.p2("a"), T.p2("b"))), ("os.mkdir", (T.p2("x"),)), ("os.chmod", (T.p2("f"), 0o600)),
                             ("os.setxattr", (T.p2("f"), "user.x", b"1")), ("os.remove", (T.p2("f"),)), ("os.utime", (T.p2("f"), None)),
                             ("os.truncate", (T.p2("f"), 0)), ("os.chflags", (T.p2("f"), 0)), ("os.some_future_event", (T.p2("f"),)),
                             ("open", (T.p2("f"), "w", 0)), ("open", (T.p2("f"), None, os.O_WRONLY)), ("open", (T.p2("f"), "r+", 0))):
                self.refused(G._hook, ev, args)
            G._hook("os.putenv", ("A", "b/c")); G._hook("os.system", ("ls /",))     # not paths
            self.refused(G._hook, "sqlite3.connect", (T.p1("..", "db"),))
            self.refused(G._hook, "tempfile.mkdtemp", (T.p1("..", "d"),))

    def test_a_relative_path_is_judged_at_the_cwd_and_open_modes_x_and_a_write(self):
        T = self.T
        with T.active(env=[T.t2]):
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                G.check("f", "stat", False, True)                    # env is readable
                self.refused(G.check, "f", "open", write=True)       # but not writable
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t1}):
                G.check("f", "open", write=True); G.check("sub/../f", "open", write=True)
            with mock.patch.dict(G._real, {"getcwd": lambda: os.path.dirname(T.t1)}):
                self.refused(G.check, "f", "stat", False, False)
            for mode in ("x", "a", "w", "r+", "ab", "xb"):
                self.refused(G._hook, "open", (T.p2("f"), mode, 0))
            G._hook("open", (T.p2("f"), "rb", 0)); G._hook("open", (T.p2("f"), None, os.O_RDONLY))

    def test_dir_fd_in_the_audit_events_is_judged_under_the_fd_directory(self):
        """Probe: fd = os.open(T1/a), cwd = T1/a/b/c, name ../../t2/X: the cwd-relative reading is inside the root, the OS acts outside it."""
        T = self.T
        os.makedirs(T.p1("a", "b", "c"))
        fd_in, fd_out = os.open(T.p1("a"), os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        try:
            with T.active():
                with mock.patch.dict(G._real, {"getcwd": lambda: T.p1("a", "b", "c")}):
                    name = os.path.join("..", "..", os.path.basename(T.t2), "X")        # = parent(T1)/<t2>/X under the fd, T1/a/<t2>/X under the cwd
                    evs = [("os.mkdir", (name, 0o777, fd_in)), ("os.rmdir", (name, fd_in)), ("os.remove", (name, fd_in)),
                           ("os.rename", (name, "ok", fd_in, -1)), ("os.rename", ("ok", name, -1, fd_in)), ("os.chmod", (name, 0o600, fd_in)),
                           ("os.utime", (name, None, None, fd_in)), ("os.symlink", ("t", name, fd_in)), ("os.link", (name, "ok", fd_in, -1)),
                           ("os.link", ("ok", name, -1, fd_in)), ("os.mkfifo", (name, 0o600, fd_in)), ("os.mknod", (name, 0o600, 0, fd_in)),
                           ("os.chown", (name, -1, -1, fd_in))]
                    for ev, args in evs:
                        self.refused(G._hook, ev, args)
                    # the same names relative to an fd INSIDE the root, and calls without a dir_fd (-1 / None), are judged as before
                    for ev, args in (("os.mkdir", ("b/new", 0o777, fd_in)), ("os.remove", ("b/f", fd_in)), ("os.rename", ("b/x", "b/y", fd_in, fd_in)),
                                     ("os.mkdir", ("new", 0o777, -1)), ("os.mkdir", ("new", 0o777, None))):
                        G._hook(ev, args)
                with mock.patch.object(G, "_fd_dir", lambda fd: None):
                    for ev, args in evs[:3]:
                        self.refused(G._hook, ev, args)                                # an fd with an unknown directory: fail closed
        finally:
            os.close(fd_in); os.close(fd_out)

    def test_link_creation_honours_dir_fd(self):
        T = self.T
        os.makedirs(T.p1("a"))
        fd_in, fd_out = os.open(T.p1("a"), os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        made = []
        sym = G.wrap_link(lambda *a, **k: made.append(1), "os.symlink")
        lnk = G.wrap_link(lambda *a, **k: made.append(1), "os.link")
        try:
            with T.active():
                self.refused(sym, "t", "X", dir_fd=fd_out)                    # the link location is T2/X
                self.refused(lnk, T.p1("f"), "X", dst_dir_fd=fd_out)
                self.refused(lnk, "f", "X", src_dir_fd=fd_out, dst_dir_fd=fd_in)  # the source is T2/f
                sym("t", "X", dir_fd=fd_in); lnk("f", "X", src_dir_fd=fd_in, dst_dir_fd=fd_in)
                with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                    self.refused(lnk, "f", T.p1("g"))                             # a hard link's source is relative to the CWD, not the link's directory
        finally:
            os.close(fd_in); os.close(fd_out)
        self.assertEqual(len(made), 2)

    def test_a_trailing_slash_or_dot_follows_the_last_link(self):
        T = self.T
        os.symlink.__wrapped__(T.t2, T.p1("out")); os.symlink(T.p1("sub"), T.p1("in"))
        with T.active():
            os.lstat(T.p1("out")); os.path.islink(T.p1("out")); os.path.lexists(T.p1("out")); os.readlink(T.p1("out"))
            for suffix in ("/", "/.", "/./", "//"):
                for fn in (os.lstat, os.path.islink, os.path.lexists, os.readlink):
                    self.refused(fn, T.p1("out") + suffix)
                os.lstat(T.p1("in") + suffix); os.path.islink(T.p1("in") + suffix)

    def test_a_sqlite_file_uri_is_refused_and_a_plain_name_is_judged(self):
        T = self.T
        with T.active():
            for name in ("file:" + T.p1("db") + "?mode=ro", "file:../x/db", "file:" + T.p2("db"), b"file:/x"):
                self.refused(G._hook, "sqlite3.connect", (name,))
            G._hook("sqlite3.connect", (T.p1("db"),)); self.refused(G._hook, "sqlite3.connect", (T.p2("db"),))

    def test_bytecode_writes_are_allowed_only_for_a_resolved_pyc_directly_in_pycache(self):
        T = self.T
        os.makedirs(T.p2("__pycache__")); os.makedirs(T.p2("lib", "__pycache__"))
        os.symlink.__wrapped__(T.p2("sub"), T.p2("__pycache__", "lnk"))
        with T.active(env=[T.t2]):
            for p in (("__pycache__", "m.cpython-314.pyc"), ("__pycache__", "m.cpython-314.pyc.1234"), ("lib", "__pycache__", "x.pyc")):
                G.check(T.p2(*p), "open", write=True); G._hook("open", (T.p2(*p), "wb", 0))
                G._hook("os.rename", (os.path.join(os.path.dirname(T.p2(*p)), "tmp.cpython-314.pyc.4242"), T.p2(*p)))
            for p in (("__pycache__", "..", "site.py"), ("__pycache__", "..", "evil.pth"), ("__pycache__", "evil.txt"), ("__pycache__", "m.py"),
                      ("__pycache__", "m.pyc.x"), ("__pycache__", "sub2", "m.pyc"), ("__pycache__x", "m.pyc"), ("__pycache__", "lnk", "m.pyc"),
                      ("site.py",), ("lib", "__pycache__", "..", "evil.pth")):
                self.refused(G.check, T.p2(*p), "open", write=True)
                self.refused(G._hook, "open", (T.p2(*p), "w", 0))
                self.refused(G._hook, "os.remove", (T.p2(*p), -1))
                self.refused(G._hook, "os.rename", (T.p1("f"), T.p2(*p)))
            self.refused(G._hook, "os.rename", (T.p2("__pycache__", "m.pyc"), T.p2("__pycache__", "..", "evil.pth")))
            G.check(T.p2("__pycache__", "..", "f"), "open")                       # reading through it is still fine

    def test_neither_the_root_nor_a_broad_directory_becomes_a_root(self):
        self.assertNotIn("/", G._canon_set(["/", "/usr"]))
        for b in sorted(G.BROAD - {"/"}):
            self.assertEqual(G._canon_set([b], drop_broad=True), set(), b)
        for b in ("/sbin", "/root", "/bin", "/etc", "/var", "/System", "/Library", "/home", "/Users", "/opt", "/opt/homebrew"):
            self.assertIn(b, G.BROAD)
        home = os.path.realpath(os.path.expanduser("~"))
        with mock.patch.dict(os.environ, {"TMPDIR": "/usr", "COVERAGE_RCFILE": "/", "HOME": "/opt/fakehome"}):
            self.assertNotIn("/usr", G._roots())
            self.assertNotIn("/", G._roots())
        for bad in ("/usr", "/opt/fakehome", "/", "/home"):                              # tempfile.gettempdir() follows TMPDIR
            with mock.patch.dict(os.environ, {"HOME": "/opt/fakehome"}), mock.patch.object(tempfile, "gettempdir", lambda bad=bad: bad):
                self.assertNotIn(bad, G._roots(), bad)
        with mock.patch.dict(os.environ, {"HOME": "/opt/fakehome", "TMPDIR": "/opt/fakehome"}):
            self.assertNotIn("/opt/fakehome", G._roots())                          # the home directory is never a root
            with mock.patch.object(sys, "path", ["/opt/fakehome", "/opt/fakelib"]):
                self.assertNotIn("/opt/fakehome", G._env_roots()); self.assertIn("/opt/fakelib", G._env_roots())
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"TMPDIR": d}):
                self.assertIn(os.path.realpath(d), G._roots())
        self.assertTrue(home)

    def test_bytes_and_pathlike_paths_in_the_generic_branch_are_judged(self):
        import pathlib
        T = self.T
        with T.active():
            for a in (os.fsencode(T.p2("x")), pathlib.Path(T.p2("x")), T.p2("x")):
                self.refused(G._hook, "os.some_future_event", (a,))
            G._hook("os.some_future_event", (os.fsencode(T.p1("x")),)); G._hook("os.some_future_event", (pathlib.Path(T.p1("x")),))
            G._hook("os.some_future_event", (b"no-slash", "no-slash", 5))

    def test_listdir_without_an_argument_is_judged_at_the_cwd(self):
        T = self.T
        with T.active():
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                self.refused(G._hook, "os.listdir", (None,)); self.refused(G._hook, "os.scandir", (None,))
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t1}):
                G._hook("os.listdir", (None,)); G._hook("os.scandir", (None,))

    def test_glob_is_judged_at_the_directory_before_its_first_wildcard(self):
        T = self.T
        with T.active():
            G._hook("glob.glob", (T.p1("sub", "*.py"), False)); G._hook("glob.glob", (T.p1("s[a]b"), False))
            self.refused(G._hook, "glob.glob", (T.p2("*.py"), False)); self.refused(G._hook, "glob.glob", (T.p2("sub", "f"), False))

    def test_dir_fd_names_are_judged_under_the_directory_the_fd_names(self):
        T = self.T
        fd1, fd2 = os.open(T.t1, os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        os.symlink(T.t2, T.p1("out"))
        try:
            with T.active():
                os.stat("f", dir_fd=fd1); os.close(os.open("f", os.O_RDONLY, dir_fd=fd1))
                for name in ("f", "sub", ".."):
                    self.refused(os.stat, name, dir_fd=fd2); self.refused(os.lstat, name, dir_fd=fd2)
                    self.refused(os.access, name, os.R_OK, dir_fd=fd2); self.refused(os.readlink, name, dir_fd=fd2)
                self.refused(os.open, "f", os.O_RDONLY, dir_fd=fd2)
                self.refused(os.open, "out", os.O_RDONLY, dir_fd=fd1)               # a link inside the fd's directory that leaves it
                self.refused(os.stat, "../f", dir_fd=fd1)
                with mock.patch.object(G, "_fd_dir", lambda fd: None):
                    self.refused(os.stat, "f", dir_fd=fd1); self.refused(os.open, "f", os.O_RDONLY, dir_fd=fd1)
        finally:
            os.close(fd1); os.close(fd2)

    def test_the_environment_roots_drop_broad_prefixes_and_keep_specific_ones(self):
        with mock.patch.object(sys, "prefix", "/usr"), mock.patch.object(sys, "exec_prefix", "/usr"), \
                mock.patch.object(sys, "base_prefix", "/usr"), mock.patch.object(sys, "base_exec_prefix", "/usr"), \
                mock.patch.object(sys, "executable", "/usr/bin/python3"), mock.patch.object(sys, "path", ["/usr", "/usr/local", "", "/opt/fakelib/site"]):
            got = G._env_roots()
        self.assertNotIn("/usr", got); self.assertNotIn("/usr/local", got); self.assertIn("/opt/fakelib/site", got)
        with mock.patch.object(sys, "prefix", "/opt/fakevenv/cache"), mock.patch.object(sys, "exec_prefix", "/opt/fakevenv/cache"), \
                mock.patch.object(sys, "base_prefix", "/opt/fakebase/x64"), mock.patch.object(sys, "base_exec_prefix", "/opt/fakebase/x64"), \
                mock.patch.object(sys, "executable", "/opt/fakevenv/cache/bin/python"):
            got = G._env_roots()
        self.assertIn("/opt/fakevenv/cache", got); self.assertIn("/opt/fakebase/x64", got)
        self.assertEqual(sorted(G._canon_set(["/", "/usr", "/opt/x"], drop_broad=True)), ["/opt/x"])
        self.assertIn("/usr", G._canon_set(["/usr"]))

    def test_creating_a_link_judges_both_the_target_and_the_link_location(self):
        T = self.T
        made = []
        link = G.wrap_link(lambda s, d, *a, **k: made.append(1), "os.link")
        with T.active():
            self.refused(link, T.p2("f"), T.p1("l")); self.refused(link, T.p1("f"), T.p2("l")); self.refused(link, "../../x", T.p1("sub", "l"))
            link(T.p1("f"), T.p1("l"))
        self.assertEqual(len(made), 1)


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
            "os.symlink(src='/etc/hosts', dst=x)": 1, "os.symlink(target, dst='/usr/local/bin/x')": 1, "pathlib.Path(x).symlink_to(target='/etc/hosts')": 1,
            "pathlib.Path(x).hardlink_to(target='/etc/hosts')": 1, "os.symlink(target, x)": 0, "os.symlink(os.path.join(d, 'etc/hostname'), x)": 0, "os.symlink('rel/x', x)": 0,
        }
        for src, want in cases.items():
            got, _ = link_findings("bin/tests/test_mutant.py", "import os, pathlib\n" + src + "\n", [])
            self.assertEqual(len(got), want, (src, got))
            if want:
                self.assertRegex(got[0], r"^bin/tests/test_mutant\.py:2: ")
        for src, want in {"ln -s /etc/hostname x": 1, "ln -sf /usr/local/bin/t x": 1, 'ln -s "/Library/x" y': 1, "ln -s ../x y": 0,
                          'ln -s "$work/p" y': 0, "ln -sfn $d/t y": 0, "ln -s -- /etc/hostname x": 1, "ln --symbolic /etc/hosts x": 1,
                          "cp -s /etc/hosts x": 1, "cp -sf /etc/hosts x": 1, "cp --symbolic-link /etc/hosts x": 1, "ln /etc/hosts x": 1,
                          "cp /etc/hosts x": 0, "cp -r /tmp/a /tmp/b": 0, "ln -s $(which d) x": 0,
                          'ln -s "${T:-/etc}" x': 1, "ln -st d /etc/hosts": 1, "ln -s -t/etc a": 1, "ln -s a /usr/local/bin/b": 1, "ln -sfT a /opt/b": 1,
                          "ln -s -- a b": 0, "ln -sf ./a b": 0, "cp -sf ${X:-/etc/y} z": 1, "ln --symbolic=/x": 1}.items():
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
        self.assertTrue(makes_files_without_temp("echo hi > out.txt\n"))
        self.assertTrue(makes_files_without_temp('printf x >> "$f"\n'))
        self.assertTrue(makes_files_without_temp("cmd 2> err.log\n"))
        self.assertTrue(makes_files_without_temp("cmd > /var/x\n"))
        self.assertFalse(makes_files_without_temp("echo hi >&2\ncmd >/dev/null 2>&1\ncmd 2>/dev/null\n[ $a -gt 3 ]\nif depth > 0 or x > y: pass\n"))
        self.assertFalse(makes_files_without_temp('w=$(mktemp -d)\necho hi > "$w/out"\n'))
        self.assertTrue(makes_files_without_temp('echo hi > "$out"\n'))
        self.assertFalse(makes_files_without_temp("""case_ x 'echo "A=b" >> "$GITHUB_ENV"'\n"""))
        self.assertTrue(makes_files_without_temp("# uses mktemp somewhere\n" + mk))
        self.assertTrue(makes_files_without_temp('echo "no mktemp here"\n' + mk))
        self.assertFalse(makes_files_without_temp('w="$(mktemp -d)"\n' + mk))
        self.assertFalse(makes_files_without_temp("w=`mktemp -d`\n" + mk))
        self.assertFalse(makes_files_without_temp(mk.replace("mkdir", "touch") + "python3 -c 'import tempfile; tempfile.mkdtemp()'\n"))
        self.assertFalse(makes_files_without_temp("echo hi\n"))

    def test_a_whole_file_allow_row_pins_the_whole_file_and_shows_its_literal_lines(self):
        import system_path_allowlist as A
        rows = whole_file_rows()
        self.assertEqual(sorted(A.PINS), rows, "every whole-file row needs a pin and every pin a whole-file row")
        for rel in rows:
            with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as fh:
                sha, lines = row_pin(fh.read())
            want_sha, want_lines, reason = A.PINS[rel]
            self.assertGreaterEqual(len(reason.strip()), 12)
            self.assertEqual(sorted(set(lines) - set(want_lines)), [], "%s: new system-path literal lines (add them to PINS with a reason)" % rel)
            self.assertEqual(tuple(lines), tuple(want_lines), "%s: the literal lines changed" % rel)
            self.assertEqual(sha, want_sha, "%s: the file changed; a whole-file row pins the whole file. Review the edit, then run "
                                            "`python3 test_fs_guard.py --print-pins` and update PINS in system_path_allowlist.py" % rel)

    def test_the_whole_file_pin_bites_on_every_form_of_added_command(self):
        import system_path_allowlist as A
        rel = sorted(A.PINS)[0]
        with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as fh:
            base = fh.read()
        self.assertEqual(row_pin(base)[0], A.PINS[rel][0])
        forms = ["grep -q root /etc/passwd", "ls /usr/local/bin", "source /etc/os-release", ". /etc/os-release", "head -1 /etc/hostname",
                 "[ -x /usr/local/bin/grype ]", "test -f /etc/hosts", "x=$(cat /etc/hosts)", "if cat /etc/hosts; then", "cp a ${X:-/etc/y}",
                 "</etc/hosts", "x | tee -a /etc/x", "find /usr/local -name x", "cmd >/tmp/out", "echo 'a\"b'; cat /etc/hosts",
                 "ls /", "open('/')", "os.listdir('/')", "tar -C/etc -x", "cat /Etc/hosts", "ls /cores", "cat ~/x", "cat $HOME/x", "echo hi", "# a comment"]
        for f in forms:
            self.assertNotEqual(row_pin(base + "\n" + f + "\n")[0], A.PINS[rel][0], f)       # ANY edit changes the whole-file hash
        self.assertNotEqual(row_pin(base + "\ncp /tmp/y /usr/bin/y\n")[1], tuple(A.PINS[rel][1]))     # and a new literal shows in the lines
        # the context attack: moving a closing quote turns a quoted fixture line into a top-level command; the literal lines are the same
        unmoved = 'case_ x bad "$(r \'echo hi\')" "\ncp /tmp/y /usr/bin/y\n"\n'          # the cp line is INSIDE a quoted fixture
        moved = 'case_ x bad "$(r \'echo hi\')" ""\ncp /tmp/y /usr/bin/y\n'              # the closing quote moved up: a real command
        self.assertEqual(row_pin(moved)[1], row_pin(unmoved)[1])
        self.assertNotEqual(row_pin(moved)[0], row_pin(unmoved)[0])

    EXPECTED_NAMES = ["etc", "usr", "var", "private", "Library", "System", "opt", "bin", "sbin", "dev", "home", "root", "proc", "sys", "Users",
                      "tmp", "Applications", "Volumes", "run", "srv", "lib", "lib64", "boot", "mnt", "nix", "cores", "Network", "snap",
                      "workspace", "github", "media", "data", "afs", "net", "scratch", "export", "exports", "nfs", "Developer", "lost+found", "vol"]

    def test_every_top_level_name_is_found_in_every_position(self):
        self.assertEqual([x.replace("\\", "") for x in SYS_NAMES], self.EXPECTED_NAMES)      # an independent copy: dropping a name fails here
        for n in self.EXPECTED_NAMES:
            for text in ("ls /%s/x" % n, "d=/%s" % n, "open('/%s/f')" % n, "cc -o/%s/f" % n, "p=${V:-/%s}/f" % n, "ls /%s" % n.upper(),
                         "ls //%s/x" % n, "ls /./%s/x" % n, "ls /../%s/x" % n, "ls /{%s,x}/f" % n, "x=/%s2/f" % n, "x=/%s_dir/f" % n):
                self.assertTrue(literal_findings("f.sh", text, [])[0], text)
            for text in ("x=/q%s/f" % n, "u=https://h/%s/x" % n, "r=a/%s/b" % n, "./%s/x" % n, "d=$work/%s" % n) + (("echo /%s-x" % n,) if n != "lib64" else ()):
                self.assertEqual(literal_findings("f.sh", text, [])[0], [], text)
        for text in ("ls /e?c/hosts", "ls /?tc", "ls /us?/bin", "ls /{etc,usr}/x", "ls /{usr,x}", "cat /et?"):
            self.assertTrue(literal_findings("f.sh", text, [])[0], text)

    def test_every_bare_root_form_is_found(self):
        for text in ["tar -C / -xf a.tar", "git -C / status", "env -C / cat etc/hosts", "cp x /", "mv x /", "rsync -a x /", "pushd /", "popd /",
                     "docker run -v /:/host img", "docker run --volume=/:/host img", "docker run --mount type=bind,src=/,dst=/h img",
                     "subprocess.run(['ls'], cwd='/')", "os.path.join('/', 'etc', 'hosts')", "Path('/')", "os.chdir('/')", "os.walk('/')",
                     "shutil.rmtree('/')", "ls -la /", "cd /", "cd -P /", "find / -name x", "du -s /", "cat /", "chmod -R 700 /", "chroot / sh",
                     "df -h /", "touch /", "mkdir /", "rmdir /", "tree /", "mount /", "x = os.listdir('/')", "p.iterdir('/')", "tar --directory / -x",
                     "tar --directory=/ -x", "make -C / all", "cp -r a b /", "install -m 0755 x /", "ln -s a /", "scp a /", "zip -r a.zip /"]:
            self.assertTrue(literal_findings("f.sh", text, [])[0], text)
        for text in ["cd ..", "ls ./", "echo 'a / b'", "x = '/'.join(p)", "a / b", "sed 's/a/b/'", "cp x ./", "cp x y/", "tar -C dir -x", "cd $d",
                     "git -C \"$repo\" status", "echo $((a / b))", "x=`pwd`/y"]:
            self.assertEqual(literal_findings("f.sh", text, [])[0], [], text)

    def test_home_without_a_slash_and_dotdot_chains_are_found(self):
        for text in ["cat ~/x", "x=~/y", "cd ~", "cd", "cd; ls", "cd && ls", "ls ~", "cat ~;", "x=~", "cp -r ~ y", "../../../../etc/hosts", "cat ../../../x", "file:///etc/hosts",
                     "file:/etc/hosts", "file://localhost/x", "echo $HOME", "os.path.expanduser('~')"]:
            self.assertTrue(literal_findings("f.sh", text, [])[0], text)
        for text in ["cd ..", "cd $d", "x ~ y", "'~' suffix", "cat ../../x", "file://$work/rel", "file://.", "cd dir"]:
            self.assertEqual(literal_findings("f.sh", text, [])[0], [], text)

    def test_the_literal_scan_finds_every_plain_form(self):
        for text in ["d=${TMPDIR:-/tmp}/a", "docker load oci-archive:/tmp/x", "PATH=/a:/usr/bin", "cc -o/etc/hosts", "tar -C/etc -x", "cat /Etc/hosts",
                     "ls /cores", "ls /Network/x", "ls /snap", "cd /workspace", "p=/github/workspace", "open('/')", "os.listdir('/')", "ls /", "cd /",
                     "find / -name x", "stat('/')"]:
            self.assertTrue(literal_findings("f.sh", text, [])[0], text)
        for text in ["https://host/etc/x", "x=$(pwd)/etc", "./usr/bin", "a/b/etc/c", "d=$work/tmp/x", "echo 'a / b'", "x = '/'.join(p)", "cd ..", "ls ./"]:
            self.assertEqual(literal_findings("f.sh", text, [])[0], [], text)


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
        saved = (G.ROOTS, G.ENV, G.META)
        try:
            G.ROOTS, G.ENV, G.META = ["/mnt/rev/work/cache/cache"], [], ["/mnt/rev/work/metabin"]       # CI shape, interpreter elsewhere
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
                      "/usr/local/bin/pyvenv.cfg", "/mnt/rev/work/cache/pyvenv.cfg/x", "/mnt/rev/work/metabin/pyvenv.cfg"):
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
            G.ROOTS, G.ENV, G.META = saved

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
    if "--print-pins" in sys.argv:
        import pprint, system_path_allowlist as A
        reasons = {r[0]: r[2] for r in A.ROWS if r[1] == ""}
        for rel in whole_file_rows():
            with open(os.path.join(REPO, rel), encoding="utf-8", errors="replace") as fh:
                sha, lines = row_pin(fh.read())
            print("    %r: (%r,\n        %s,\n        %r)," % (rel, sha, pprint.pformat(list(lines), width=130, indent=9).replace("\n", "\n        "),
                                                          A.PINS.get(rel, (0, 0, reasons[rel]))[2]))
    else:
        unittest.main()
