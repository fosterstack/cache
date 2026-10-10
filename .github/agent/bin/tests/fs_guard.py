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
  * CPython emits no audit event for os.mkfifo, os.mknod or os.chroot: those are wrapped. sqlite3.connect judges a plain path as a write and refuses `file:` URIs
    (the connection denies ATTACH / VACUUM INTO). os.scandir returns entries that judge stat/is_dir/is_file on a symlink.
Subprocesses (bash, git, a spawned python3) are not covered here; the static scan in test_fs_guard.py covers the shell tests.
"""
import errno, os, re, shutil, site, sys, sysconfig, tempfile

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
        if not _under(nxt) and not _ancestor(nxt):          # walking THROUGH a directory is a read, whatever the final operation is
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
                # every link on the way was inside an allowed root (a step outside is refused above), so this is the OS's own answer
                raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), orig)
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


def _broad_set():
    """BROAD, its canonical forms (/etc is /private/etc on macOS) and the home directory: none of them may become a root."""
    out = set(BROAD)
    for b in BROAD:
        out.add(_realpath(b))
    home = os.path.expanduser("~")
    if home and os.path.isabs(home):
        out.add(home.rstrip("/")); out.add(_realpath(home))
    return out


def _canon_inner(cands, drop_broad):
    out, broad = set(), _broad_set()
    for c in cands:
        if c and os.path.isabs(c):
            for v in (c.rstrip("/") or "/", _realpath(c)):
                if not (drop_broad and v in broad):
                    out.add(v)
    out.discard("/")
    return out


# Where a temp dir named by the environment may live. TMPDIR, tempfile.gettempdir() and COVERAGE_RCFILE are accepted as roots only under one
# of these parents ($RUNNER_TEMP too); anything else (TMPDIR=/etc, =$HOME, =/Users/x/Documents) is ignored, which fails closed.
STANDARD_TEMP = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders", "/dev/shm")


def _standard_temp_parents():
    out = set(STANDARD_TEMP)
    rt = os.environ.get("RUNNER_TEMP", "")
    if rt and os.path.isabs(rt):
        out.add(rt.rstrip("/"))
    return out | _canon_set(out)


def _under_standard_temp(v):
    return any(v == p or v.startswith(p + "/") for p in _standard_temp_parents())


def _roots():
    own = {REPO, HERE}
    named = {tempfile.gettempdir()} | {os.environ.get(k, "") for k in ("COVERAGE_RCFILE", "TMPDIR")}
    return sorted(_canon_set(own) | {v for v in _canon_set(named) if _under_standard_temp(v)})


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
    return sorted(_canon_set(cand))                # metadata of a named directory is harmless, so nothing is dropped for breadth here


def _under(p, write=False):
    if p in EXACT or any(p == r or p.startswith(r + "/") for r in ROOTS):
        return True
    return not write and any(p == r or p.startswith(r + "/") for r in ENV)


def _pyvenv_probe(absp, what, orig):
    """Metadata of `<dir>/pyvenv.cfg` where <dir> is an ancestor of an allowed root (or inside one). Only that one file name; the
    directory walk is still judged (a link that escapes is refused), and a pyvenv.cfg that is itself a symlink is judged like any path."""
    d = os.path.dirname(absp)
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


_PYC = re.compile(r"\.pyc(\.\d+)?$")           # importlib writes <name>.pyc.<id> and renames it to <name>.pyc


def _bytecode_cache(res):
    """The RESOLVED path is a bytecode file directly inside a directory named exactly __pycache__."""
    return os.path.basename(os.path.dirname(res)) == "__pycache__" and bool(_PYC.search(os.path.basename(res)))


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
    # NOT os.path.abspath: that collapses `..` lexically, but the OS follows a link BEFORE it applies `..` (T/L/../x with L -> /etc/ssl
    # is /etc/x, not T/x). _resolve applies `..` to the already-resolved directory.
    absp = p if os.path.isabs(p) else os.path.join(_real["getcwd"](), p)
    if meta and not write and os.path.basename(absp) == "pyvenv.cfg" and _pyvenv_probe(absp, what, p):
        return                             # coverage asks "is this file in a virtualenv?" for every ancestor of every traced module
    if getattr(_busy, "on", False):
        return
    if nofollow and p.endswith("/"):
        nofollow = False                   # `L/` names the directory the link points to: the OS follows the last link (`L/.` already does)
    _busy.on = True
    try:
        res = _resolve(absp, what, p, nofollow, meta, write)
    finally:
        _busy.on = False
    if write and _bytecode_cache(res):
        write = False                      # the import system caches bytecode beside the module it just read
    if not _under(res, write) and not (meta and _ancestor(res)):
        raise SystemPathAccess("test touched a real system path (%s -> %s): %s" % (what, res, p))


_AUDIT_PATH = {  # event -> indexes of the path arguments
    "open": (0,), "os.listdir": (0,), "os.scandir": (0,), "os.rename": (0, 1), "os.remove": (0,), "os.rmdir": (0,),
    "os.mkdir": (0,), "os.chdir": (0,), "os.symlink": (0, 1), "os.link": (0, 1), "os.truncate": (0,), "os.chmod": (0,),
    "os.chown": (0,), "os.utime": (0,), "os.setxattr": (0,), "os.removexattr": (0,),
    "os.getxattr": (0,), "os.listxattr": (0,), "os.chflags": (0,), "os.walk": (0,), "os.fwalk": (0,), "sqlite3.connect": (0,), "tempfile.mkstemp": (0,), "tempfile.mkdtemp": (0,),
    "ctypes.dlopen": (0,), "os.add_dll_directory": (0,),
}
_NOT_PATHS = {"os.putenv", "os.unsetenv", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty", "os.kill",
              "os.killpg", "os.startfile", "os.getxattr", "os.listxattr", "os.setxattr", "os.removexattr"}
_READ_EVENTS = {"os.listdir", "os.scandir", "os.walk", "os.fwalk", "os.getxattr", "os.listxattr", "sqlite3.connect"}
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _open_writes(args):
    mode = args[1] if len(args) > 1 else None
    flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
    return (isinstance(mode, str) and any(c in mode for c in "wax+")) or bool(flags & _WRITE_FLAGS)


# audit event -> {path index: index of the dir_fd that path is relative to}; -1 or None means "no dir_fd"
_DIRFD = {"os.mkdir": {0: 2}, "os.rmdir": {0: 1}, "os.remove": {0: 1}, "os.rename": {0: 2, 1: 3}, "os.chmod": {0: 2}, "os.utime": {0: 3},
          "os.symlink": {1: 2}, "os.link": {0: 2, 1: 3}, "os.chown": {0: 3}}
# CPython (3.12 and 3.14) emits NO audit event for os.mkfifo, os.mknod or os.chroot (nor for lchown/lchmod/lchflags, which report as
# os.chown/os.chmod/os.chflags): those three are wrapped in install() instead, and test_fs_guard.AuditRows fails any row that is dead.


# these act on the directory entry itself (they never follow a final symlink): unlink/rename/mkdir of a link do not touch its target
_NOFOLLOW = {"os.remove", "os.rmdir", "os.rename", "os.mkdir", "os.link"}


def _judged_path(event, args, i):
    """args[i] as the operating system will see it: relative to the dir_fd the same call carries, when there is one."""
    p = args[i] if args[i] is not None else "."
    j = _DIRFD.get(event, {}).get(i)
    if j is not None and j < len(args) and isinstance(args[j], int) and args[j] >= 0:
        return _with_dir_fd(p, args[j], event)
    return p


def _hook(event, args):
    if event == "sqlite3.connect" and args:
        # coverage keeps its data file in sqlite, so a plain path is judged like any other write. Refused (fail closed): a `file:` URI in
        # any form (str, bytes, PathLike: "file:/abs/db?mode=ro", "file:../x/db" name a path the argument does not show as one) and "". The
        # connection itself denies ATTACH and VACUUM INTO (no audit event exists for them), so a database can write nowhere else.
        name = os.fsdecode(args[0]) if isinstance(args[0], (str, bytes, os.PathLike)) else None
        if name is None or name == "" or name.startswith("file:"):
            raise SystemPathAccess("test touched a real system path (sqlite3.connect): a file: URI or empty name is refused: %r" % (args[:1],))
        if name == ":memory:":
            return
        check(name, event, write=True)
        return
    if event in _AUDIT_PATH:
        write = _open_writes(args) if event == "open" else event not in _READ_EVENTS
        for i in _AUDIT_PATH[event]:
            if i >= len(args) or isinstance(args[i], int):
                continue
            if event == "os.symlink" and i == 0:
                continue           # a symlink's target text is data; wrap_link judges it where it would resolve
            check(_judged_path(event, args, i), event, (event in _NOFOLLOW and not (event == "os.link" and i == 0)) or (event == "os.symlink" and i == 1), write=write)        # listdir()/scandir() with no argument = the cwd
    elif event in ("glob.glob", "glob.glob/2") and args and isinstance(args[0], (str, bytes, os.PathLike)):
        pat = os.fsdecode(args[0])
        cut = min([i for i in (pat.find(c) for c in "*?[") if i >= 0] or [len(pat)])
        check(os.path.dirname(pat[:cut]) or ".", event)
    elif event.startswith("shutil."):
        # copy*: the source is only read; move and everything else (rmtree, chown, unpack_archive ...) writes every path
        for i, a in enumerate(args):
            if isinstance(a, (str, bytes, os.PathLike)):
                check(a, event, write=not (i == 0 and event.startswith("shutil.copy")))
    elif event.startswith("os.") and event not in _NOT_PATHS:
        for a in args:                       # any other os.* event that carries a path: judge it as a write
            if isinstance(a, os.PathLike) or (isinstance(a, (str, bytes)) and (b"/" in a if isinstance(a, bytes) else "/" in a)):
                check(a, event, write=True)


def _fd_dir(fd):
    """The directory a dir_fd refers to (macOS F_GETPATH, Linux /proc/self/fd), or None when it cannot be told."""
    try:
        import fcntl
        if hasattr(fcntl, "F_GETPATH"):
            return os.fsdecode(fcntl.fcntl(fd, fcntl.F_GETPATH, b"\0" * 1024).split(b"\0")[0])
    except (ImportError, OSError):
        pass
    try:
        return _real["readlink"]("/proc/self/fd/%d" % fd)
    except OSError:
        return None


def _with_dir_fd(path, dir_fd, what):
    """A name relative to dir_fd is judged as <the fd's directory>/<name>; an fd whose directory is unknown is refused (fail closed)."""
    base = _fd_dir(dir_fd)
    p = os.fsdecode(_real["fspath"](path))
    if base is None:
        raise SystemPathAccess("test touched a real system path (%s): dir_fd with an unknown directory: %s" % (what, p))
    return p if os.path.isabs(p) else os.path.join(base, p)


def _wrap1(mod, name, nofollow=False):
    orig = getattr(mod, name, None)
    if orig is None:
        return                                    # not on this platform (the xattr calls are Linux only)

    def f(path, *a, **k):
        if k.get("dir_fd") is not None and not isinstance(path, int):
            check(_with_dir_fd(path, k["dir_fd"], name), name, nofollow, True)
        else:
            check(path, name, nofollow, True)
        return orig(path, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(mod, name, f)


def _deny_attach(action, *rest):
    import sqlite3
    return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_ATTACH else sqlite3.SQLITE_OK      # VACUUM INTO is authorised as an ATTACH


def _wrap_sqlite():
    try:
        import sqlite3
    except ImportError:
        return
    orig = sqlite3.connect

    def connect(*a, **k):
        c = orig(*a, **k)
        c.set_authorizer(_deny_attach)
        return c
    connect.__name__ = "connect"; connect.__wrapped__ = orig
    sqlite3.connect = connect


def _wrap_write_path(name):
    """os.mkfifo / os.mknod / os.chroot create or redirect a directory entry but emit no audit event: judge the path (and its dir_fd) here."""
    orig = getattr(os, name, None)
    if orig is None:
        return

    def f(path, *a, dir_fd=None, **k):
        p = _with_dir_fd(path, dir_fd, "os." + name) if dir_fd is not None else path
        check(p, "os." + name, name != "chroot", False, True)
        return orig(path, *a, dir_fd=dir_fd, **k) if dir_fd is not None else orig(path, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(os, name, f)


def _wrap_xattr_write(name):
    orig = getattr(os, name, None)
    if orig is None:
        return

    def f(path, *a, **k):
        check(path, "os." + name, k.get("follow_symlinks", True) is False, True, True)
        return orig(path, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(os, name, f)


class _Entry:
    """An os.DirEntry whose stat/is_dir/is_file are judged when the entry is a symlink (they follow it, with no audit event)."""
    __slots__ = ("_e",)

    def __init__(self, e):
        self._e = e

    name = property(lambda self: self._e.name)
    path = property(lambda self: self._e.path)

    def inode(self):
        return self._e.inode()

    def is_symlink(self):
        return self._e.is_symlink()

    def _follow(self, follow):
        if follow and self._e.is_symlink():
            check(self._e.path, "DirEntry", False, True)

    def is_dir(self, *, follow_symlinks=True):
        self._follow(follow_symlinks)
        return self._e.is_dir(follow_symlinks=follow_symlinks)

    def is_file(self, *, follow_symlinks=True):
        self._follow(follow_symlinks)
        return self._e.is_file(follow_symlinks=follow_symlinks)

    def stat(self, *, follow_symlinks=True):
        self._follow(follow_symlinks)
        return self._e.stat(follow_symlinks=follow_symlinks)

    def __fspath__(self):
        return self._e.path

    def __repr__(self):
        return "<guarded %r>" % (self._e,)


class _Scan:
    def __init__(self, it):
        self._it = it

    def __iter__(self):
        return self

    def __next__(self):
        return _Entry(next(self._it))

    def close(self):
        self._it.close()

    def __enter__(self):
        self._it.__enter__()
        return self

    def __exit__(self, *a):
        return self._it.__exit__(*a)


def _wrap_scandir():
    orig = os.scandir

    def scandir(path=None):
        it = orig(path) if path is not None else orig()
        return it if isinstance(path, int) else _Scan(it)
    scandir.__name__ = "scandir"; scandir.__wrapped__ = orig
    os.scandir = scandir


def _wrap_os_open():
    orig = os.open

    def f(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            check(_with_dir_fd(path, dir_fd, "os.open"), "os.open", False, False, bool(flags & _WRITE_FLAGS))
        return orig(path, flags, mode, dir_fd=dir_fd)
    f.__name__ = "open"; f.__wrapped__ = orig
    os.open = f


def check_link(target, dst, what, dir_fd=None, src_dir_fd=None):
    """Creating a link whose TARGET is outside the allowed roots is refused, though the target is never opened (symlink creation emits
    no audit event of its own for the target, and a link to a system path is what the OS asked the user to administer).
    A symlink's relative target is judged where it would resolve: next to the link (NOT normalised: `B/../x` goes through B's link).
    A hard link's source is relative to the cwd or src_dir_fd. dir_fd names the directory the link location is relative to."""
    t = os.fsdecode(_real["fspath"](target))
    d = os.fsdecode(_real["fspath"](dst))
    if isinstance(dir_fd, int) and dir_fd >= 0:
        d = _with_dir_fd(d, dir_fd, what)
    if not os.path.isabs(d):
        d = os.path.join(_real["getcwd"](), d)
    if what == "os.link":
        if isinstance(src_dir_fd, int) and src_dir_fd >= 0:
            t = _with_dir_fd(t, src_dir_fd, what)
        elif not os.path.isabs(t):
            t = os.path.join(_real["getcwd"](), t)
    elif not os.path.isabs(t):
        t = os.path.join(os.path.dirname(d), t)
    check(t, what, False, write=True)
    check(d, what, True, write=True)


def wrap_link(orig, name):
    def f(src, dst, *a, **k):
        if name == "os.link":
            check_link(src, dst, name, k.get("dst_dir_fd"), k.get("src_dir_fd"))
        else:
            check_link(src, dst, name, k.get("dir_fd"))
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
    _wrap_os_open()
    _wrap_sqlite()
    _wrap_scandir()
    for n in ("mkfifo", "mknod", "chroot"):
        _wrap_write_path(n)
    for n in ("setxattr", "removexattr"):
        _wrap_xattr_write(n)
