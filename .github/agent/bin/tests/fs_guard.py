"""Tripwire: no unit test may touch the real filesystem outside its temp dir and the repo.

Why: a test that opens, stats or resolves a real system path (/etc/hostname, /usr/local/bin ...) can raise macOS
'administer your computer' prompts for the interpreter. Fixtures that need such a path build the same shape under a
temporary directory instead (a tree holding etc/passwd, a symlink to a temp file, ...).

Design (installed once, on import, by test_fs_guard.py, which unittest discovery imports before any test runs):
  * sys.addaudithook: refuses 'open', os.listdir/scandir/rename/replace/remove/rmdir/mkdir/chdir/symlink/link/truncate/
    chmod/chown/utime and shutil.* events whose path resolves outside the allowed roots.
  * CPython emits no audit event for stat/realpath/readlink, so os.stat, os.lstat, os.readlink, os.path.realpath,
    os.path.exists/isfile/isdir/islink/lexists/getsize are wrapped with the same check.
  * Allowed roots: the temp dir, the repo, the interpreter's stdlib and site-packages (never the whole prefix: /usr is a prefix on Linux), every sys.path entry at
    install time, /dev/null and /dev/urandom. A path is checked both lexically and after resolving symlinks, so a symlink
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
ROOTS = []
_busy = __import__('threading').local()
_busy.on = False
EXACT = {"/dev/null", "/dev/urandom", "/dev/zero", "/dev/tty"}


class SystemPathAccess(BaseException):
    """A test touched a real system path."""


def _resolve(p, what, orig, nofollow=False, meta=False):
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
        if not _under(nxt) and not _ancestor(nxt):
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


def _ancestor(p):
    """A directory on the way down to an allowed root (/home and /home/user above a checkout, /var above the temp dir, / itself).
    Its METADATA (stat, lstat, realpath, exists, isdir) may be read because every path walk starts at the root and the interpreter
    resolves each module path that way; its CONTENTS (open, listdir, scandir, rename ...) never may. It must not itself be a link
    that escapes (checked by _resolve on the next hop)."""
    return any(r.startswith(p.rstrip("/") + "/") for r in list(ROOTS) + sorted(EXACT))


def _roots():
    cand = {tempfile.gettempdir(), REPO, HERE}
    cand.update(sysconfig.get_paths()[k] for k in ("stdlib", "platstdlib", "purelib", "platlib"))
    cand.update(site.getsitepackages())
    try:
        cand.add(site.getusersitepackages())
    except Exception:
        pass
    cand.update(p for p in sys.path if p)
    cand.update(os.environ.get(k, "") for k in ("COVERAGE_RCFILE", "TMPDIR"))
    out = set()
    for c in cand:
        if c and os.path.isabs(c):
            out.add(c.rstrip("/") or "/"); out.add(_realpath(c))
    out.discard("/")
    return sorted(out)


def _under(p):
    return p in EXACT or any(p == r or p.startswith(r + "/") for r in ROOTS)


def check(path, what="", nofollow=False, meta=False):
    """Raise unless `path` (lexically and after symlink resolution) is inside an allowed root."""
    if not ROOTS or isinstance(path, int):
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
    if not _under(absp) and not (meta and _ancestor(absp)):
        raise SystemPathAccess("test touched a real system path (%s): %s" % (what, p))
    if getattr(_busy, "on", False):
        return
    _busy.on = True
    try:
        res = _resolve(absp, what, p, nofollow, meta)
    finally:
        _busy.on = False
    if not _under(res) and not (meta and _ancestor(res)):
        raise SystemPathAccess("test touched a real system path (%s -> %s): %s" % (what, res, p))


_AUDIT_PATH = {  # event -> indexes of the path arguments
    "open": (0,), "os.listdir": (0,), "os.scandir": (0,), "os.rename": (0, 1), "os.remove": (0,), "os.rmdir": (0,),
    "os.mkdir": (0,), "os.chdir": (0,), "os.symlink": (0, 1), "os.link": (0, 1), "os.truncate": (0,), "os.chmod": (0,),
    "os.chown": (0,), "os.utime": (0,), "os.mkfifo": (0,), "os.mknod": (0,),
}


def _hook(event, args):
    if event in _AUDIT_PATH:
        for i in _AUDIT_PATH[event]:
            if i < len(args) and args[i] is not None and not isinstance(args[i], int):
                if event == "os.symlink" and i == 0:
                    continue           # a symlink's target text is data; following it is what open/stat check
                check(args[i], event)
    elif event.startswith("shutil."):
        for a in args:
            if isinstance(a, (str, bytes, os.PathLike)):
                check(a, event)


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
    check(os.path.normpath(t), what, True)
    check(dst, what, True)


def wrap_link(orig, name):
    def f(src, dst, *a, **k):
        check_link(src, dst, name)
        return orig(src, dst, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    return f


def install(extra_roots=()):
    global _installed, ROOTS
    if _installed:
        return
    _installed = True
    ROOTS = _roots() + [r for r in extra_roots]
    sys.addaudithook(_hook)
    for n in ("stat", "lstat", "readlink", "access", "statvfs", "pathconf", "listxattr", "getxattr"):
        _wrap1(os, n, n in ("lstat", "readlink"))
    for n in ("realpath", "exists", "isfile", "isdir", "islink", "lexists", "getsize"):
        _wrap1(os.path, n, n in ("islink", "lexists"))
    for n in ("symlink", "link"):
        setattr(os, n, wrap_link(getattr(os, n), "os." + n))
