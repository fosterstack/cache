"""Tripwire: no unit test may touch the real filesystem outside its temp dir and the repo.

Why: a test that opens, stats or resolves a real system path (/etc/hostname, /usr/local/bin ...) can raise macOS
'administer your computer' prompts for the interpreter. Fixtures that need such a path build the same shape under a
temporary directory instead (a tree holding etc/passwd, a symlink to a temp file, ...).

Design (installed once, on import, by test_fs_guard.py, which unittest discovery imports before any test runs):
  * sys.addaudithook: refuses 'open', os.listdir/scandir/rename/replace/remove/rmdir/mkdir/chdir/symlink/link/truncate/
    chmod/chown/utime and shutil.* events whose path resolves outside the allowed roots.
  * CPython emits no audit event for stat/realpath/readlink, so os.stat, os.lstat, os.readlink, os.path.realpath,
    os.path.exists/isfile/isdir/islink/lexists/getsize are wrapped with the same check.
  * Allowed roots, read/metadata/write (ROOTS): the temp dir, the repo, this directory, /dev/null and /dev/urandom.
  * META: the directories the interpreter names in every sysconfig scheme and its user base (coverage realpaths them at start-up):
    metadata of the directory itself only, never its contents. Also `<ancestor>/pyvenv.cfg` for every ancestor of an allowed root
    (coverage asks "is this module in a virtualenv?" at each level): metadata only, never open.
  * The INTERPRETER ENVIRONMENT (ENV), read and metadata only: sys.prefix and its siblings, the directory two levels above
    sys.executable (a venv root with its pyvenv.cfg, bin/, lib/), stdlib and site-packages, every sys.path entry. A prefix that is a
    broad system directory (/usr, /usr/local, /opt, /opt/homebrew ...) is NOT taken, or /usr/local/bin would be allowed with it.
    Writes there are refused except bytecode under __pycache__. A path is checked both lexically and after resolving symlinks, so a symlink
    inside the temp dir that points at /etc/hostname is refused when it is followed.
  * The violation is a BaseException, so a code path under test that does `except Exception` cannot swallow it.
Subprocesses (bash, git, a spawned python3) are not covered here; the static scan in test_fs_guard.py covers the shell tests.
"""
import os, shutil, site, sys, sysconfig, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
_real = {n: getattr(os, n) for n in ("stat", "lstat", "readlink", "getcwd", "fspath")}
_realpath = os.path.realpath
_installed = False
ROOTS = []   # temp dir, repo, this dir: read, metadata AND write
META = []    # directories the interpreter names (every sysconfig scheme, user base): METADATA of the directory only, never contents
ENV = []     # the interpreter environment (venv, prefix, stdlib, site-packages): read and metadata only
_busy = __import__('threading').local()
_busy.on = False
EXACT = {"/dev/null", "/dev/urandom", "/dev/zero", "/dev/tty"}


class SystemPathAccess(BaseException):
    """A test touched a real system path."""


def _resolve(p, what, orig, nofollow=False, meta=False, write=False):
    """Resolve symlinks component by component using the unwrapped lstat/readlink, and refuse BEFORE touching any component
    that is lexically outside the allowed roots (so a link to /etc/hostname is refused without ever stat-ing /etc)."""
    todo = [c for c in p.split("/") if c]
    cur, hops = "/", 0
    while todo:
        c = todo.pop(0)
        last = not todo
        if c == ".":
            continue
        if c == "..":
            cur = os.path.dirname(cur) or "/"
            continue
        nxt = os.path.join(cur, c)
        if not _under(nxt, write) and not _ancestor(nxt):
            raise SystemPathAccess("test touched a real system path (%s): %s" % (what, orig))
        try:
            st = _real["lstat"](nxt)
        except OSError:
            cur = nxt
            continue
        import stat as _st
        if _st.S_ISLNK(st.st_mode) and not (nofollow and last):
            hops += 1
            if hops > 40:
                return nxt
            t = _real["readlink"](nxt)
            if t.startswith("/"):
                cur = "/"
            todo = [x for x in t.split("/") if x] + todo
        else:
            cur = nxt
    return cur


def _ancestor(p, with_meta=True):
    """A directory on the way down to an allowed root (/home and /home/user above a checkout, /var above the temp dir, / itself).
    Its METADATA (stat, lstat, realpath, exists, isdir) may be read because every path walk starts at the root and the interpreter
    resolves each module path that way; its CONTENTS (open, listdir, scandir, rename ...) never may. It must not itself be a link
    that escapes (checked by _resolve on the next hop)."""
    q = p.rstrip("/")
    extra = list(META) if with_meta else []
    return (with_meta and q in META) or any(r.startswith(q + "/") for r in list(ROOTS) + list(ENV) + extra + sorted(EXACT))


# Prefixes too broad to treat as "the interpreter's own environment": with a system Python the prefix is /usr, and allowing it would
# allow /usr/local/bin and every other system path. Only a venv or an interpreter installed in its own directory counts.
BROAD = {"/", "/usr", "/usr/local", "/opt", "/opt/homebrew", "/opt/local", "/System", "/Library", "/var", "/etc", "/bin", "/sbin", "/home", "/Users", "/root"}


def _canon_set(cands, drop_broad=False):
    """Canonical forms of the candidate roots. realpath here is the guard's own bookkeeping, so it is not itself judged."""
    _busy.bypass = True
    try:
        return _canon_inner(cands, drop_broad)
    finally:
        _busy.bypass = False


def _canon_inner(cands, drop_broad):
    out = set()
    for c in cands:
        if c and os.path.isabs(c):
            for v in (c.rstrip("/") or "/", _realpath(c)):
                if not (drop_broad and v in BROAD):
                    out.add(v)
    out.discard("/")
    return out


def _roots():
    cand = {tempfile.gettempdir(), REPO, HERE}
    cand.update(os.environ.get(k, "") for k in ("COVERAGE_RCFILE", "TMPDIR"))
    return sorted(_canon_set(cand))


def _env_roots():
    """The interpreter environment, read-only: sys.prefix and its siblings (a venv root holds pyvenv.cfg, bin/, lib/), the directory
    two levels above sys.executable (where pyvenv.cfg lives), the stdlib and site-packages paths, and sys.path."""
    _busy.bypass = True
    try:
        real_exe = os.path.realpath(sys.executable)
    finally:
        _busy.bypass = False
    cand = {sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix,
            os.path.dirname(os.path.dirname(sys.executable)), os.path.dirname(os.path.dirname(real_exe))}
    broad_ok = _canon_set(cand, drop_broad=True)
    precise = set(sysconfig.get_paths()[k] for k in ("stdlib", "platstdlib", "purelib", "platlib"))
    precise.update(site.getsitepackages())
    try:
        precise.add(site.getusersitepackages())
    except Exception:
        pass
    precise.update(p for p in sys.path if p)
    return sorted(broad_ok | _canon_set(precise, drop_broad=True))


def _meta_roots():
    """Directories the interpreter itself names, which coverage (TreeMatcher/abs_file) realpaths at startup: every path of every
    sysconfig scheme (scripts, include, data, ... for posix_prefix, posix_user ...) and the user base. Metadata of the directory only."""
    cand = set()
    for scheme in sysconfig.get_scheme_names():
        try:
            cand.update(sysconfig.get_paths(scheme).values())
        except Exception:
            pass
    for f in (site.getuserbase, site.getusersitepackages):
        try:
            cand.add(f())
        except Exception:
            pass
    return sorted(_canon_set(cand, drop_broad=True))


def _under(p, write=False):
    if p in EXACT or any(p == r or p.startswith(r + "/") for r in ROOTS):
        return True
    return not write and any(p == r or p.startswith(r + "/") for r in ENV)


def _pyvenv_probe(absp, what, orig):
    """Metadata of `<dir>/pyvenv.cfg` where <dir> is an ancestor of an allowed root (or inside one). Only that one file name; the
    directory walk is still judged (a link that escapes is refused), and a pyvenv.cfg that is itself a symlink is judged like any path."""
    d = os.path.dirname(absp)
    if not (_ancestor(d, False) or _under(d)):
        return False
    _busy.bypass = True
    try:
        res = _resolve(d, what, orig, False, True, False)
    finally:
        _busy.bypass = False
    if not (_under(res) or _ancestor(res, False)):
        return False
    try:
        import stat as _st
        return not _st.S_ISLNK(_real["lstat"](absp).st_mode)
    except OSError:
        return True                        # absent: the common case


def check(path, what="", nofollow=False, meta=False, write=False):
    """Raise unless `path` (lexically and after symlink resolution) is inside an allowed root."""
    if not (ROOTS or ENV or META) or isinstance(path, int) or getattr(_busy, "bypass", False):
        return
    try:
        p = _real["fspath"](path)
    except TypeError:
        return
    if isinstance(p, bytes):
        p = os.fsdecode(p)
    if p == "":
        return
    absp = os.path.abspath(p)
    if meta and not write and os.path.basename(absp) == "pyvenv.cfg" and _pyvenv_probe(absp, what, p):
        return                             # coverage asks "is this file in a virtualenv?" for every ancestor of every traced module
    if write and "/__pycache__/" in absp and _under(absp):
        write = False                      # the import system caches bytecode beside the module it just read
    if not _under(absp, write) and not (meta and _ancestor(absp)):
        raise SystemPathAccess("test touched a real system path (%s): %s" % (what, p))
    if getattr(_busy, "on", False):
        return
    _busy.on = True
    try:
        res = _resolve(absp, what, p, nofollow, meta, write)
    finally:
        _busy.on = False
    if not _under(res, write) and not (meta and _ancestor(res)):
        raise SystemPathAccess("test touched a real system path (%s -> %s): %s" % (what, res, p))


_AUDIT_PATH = {  # event -> indexes of the path arguments
    "open": (0,), "os.listdir": (0,), "os.scandir": (0,), "os.rename": (0, 1), "os.remove": (0,), "os.rmdir": (0,),
    "os.mkdir": (0,), "os.chdir": (0,), "os.symlink": (0, 1), "os.link": (0, 1), "os.truncate": (0,), "os.chmod": (0,),
    "os.chown": (0,), "os.utime": (0,), "os.mkfifo": (0,), "os.mknod": (0,),
}


_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
_READ_EVENTS = {"os.listdir", "os.scandir"}


def _open_writes(args):
    mode = args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
    return (isinstance(mode, str) and any(c in mode for c in "wax+")) or bool(flags & _WRITE_FLAGS)


def _hook(event, args):
    if event in _AUDIT_PATH:
        write = _open_writes(args) if event == "open" else event not in _READ_EVENTS
        for i in _AUDIT_PATH[event]:
            if i < len(args) and args[i] is not None and not isinstance(args[i], int):
                if event == "os.symlink" and i == 0:
                    continue           # a symlink's target text is data; following it is what open/stat check
                check(args[i], event, write=write)
    elif event.startswith("shutil."):
        for i, a in enumerate(args):
            if isinstance(a, (str, bytes, os.PathLike)):
                check(a, event, write=not (i == 0 and event.startswith(("shutil.copy", "shutil.move"))))


def _wrap1(mod, name, nofollow=False):
    orig = getattr(mod, name, None)
    if orig is None:
        return                                    # not on this platform (the xattr calls are Linux only)

    def f(path, *a, **k):
        check(path, name, nofollow, True)
        return orig(path, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(mod, name, f)


def check_link(target, dst, what):
    """Creating a link whose TARGET text is outside the allowed roots is refused, though the target is never opened (symlink
    creation emits no audit event, and a link to a system path is what the OS asked the user to administer). A relative target
    is judged where it would resolve: next to the link."""
    t = os.fsdecode(_real["fspath"](target))
    if not os.path.isabs(t):
        t = os.path.join(os.path.dirname(os.path.abspath(os.fsdecode(_real["fspath"](dst)))), t)
    check(os.path.normpath(t), what, True, write=True)
    check(dst, what, True, write=True)


def wrap_link(orig, name):
    def f(src, dst, *a, **k):
        check_link(src, dst, name)
        return orig(src, dst, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    return f


def install(extra_roots=()):
    global _installed, ROOTS, ENV, META
    if _installed:
        return
    _installed = True
    ROOTS = _roots() + [r for r in extra_roots]
    ENV = _env_roots()
    META = _meta_roots()
    sys.addaudithook(_hook)
    for n in ("stat", "lstat", "readlink", "access", "statvfs", "pathconf", "listxattr", "getxattr"):
        _wrap1(os, n, n in ("lstat", "readlink"))
    for n in ("realpath", "exists", "isfile", "isdir", "islink", "lexists", "getsize"):
        _wrap1(os.path, n, n in ("islink", "lexists"))
    for n in ("symlink", "link"):
        setattr(os, n, wrap_link(getattr(os, n), "os." + n))
