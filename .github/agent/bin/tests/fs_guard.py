"""Tripwire: no unit test may touch the real filesystem outside its temp dir and the repo.

Why: a test that opens, stats or resolves a real system path (/etc/hostname, /usr/local/bin ...) can raise macOS
'administer your computer' prompts for the interpreter. Fixtures that need such a path build the same shape under a
temporary directory instead (a tree holding etc/passwd, a symlink to a temp file, ...).

Design (installed once, on import, by test_0000_arm_fs_guard.py, the first module unittest discovery imports; test_fs_guard.py proves it):
  * sys.addaudithook: refuses 'open', os.listdir/scandir/rename/replace/remove/rmdir/mkdir/chdir/symlink/link/truncate/
    chmod/chown/utime and shutil.* events whose path resolves outside the allowed roots.
  * CPython emits no audit event for stat/realpath/readlink, so os.stat, os.lstat, os.readlink, os.path.realpath,
    os.path.exists/isfile/isdir/islink/lexists/getsize are wrapped with the same check.
  * Allowed roots, read/metadata/write (ROOTS): the temp dir and the repo (this directory is inside it). Devices: /dev/null may be opened (also for
    writing), /dev/urandom may be opened for reading; nothing else may be done to either.
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
_real = {n: getattr(os, n) for n in ("stat", "lstat", "readlink", "getcwd", "fspath", "fstat")}
_realpath = os.path.realpath
_installed = False
ROOTS = []   # temp dir, repo, this dir: read, metadata AND write
META = []    # directories the interpreter names (every sysconfig scheme, user base): METADATA of the directory only, never contents
ENV = []     # the interpreter environment (venv, prefix, stdlib, site-packages): read and metadata only
_busy = __import__('threading').local()
_busy.on = False
EXACT = {"/dev/null", "/dev/urandom"}          # the only device files a test may open: /dev/null (also for writing) and /dev/urandom (reading only);
                                               # nothing needs /dev/zero or /dev/tty, and no other operation (remove, rename, chmod, utime, truncate ...) on either


THREAD_VIOLATIONS = []      # SystemPathAccess raised in a worker thread: threading.excepthook only prints it, so it is recorded and fails the run at exit


def _record_thread_violations():
    import atexit, threading
    prev = threading.excepthook

    def hook(args):
        if issubclass(args.exc_type, SystemPathAccess):
            THREAD_VIOLATIONS.append("%s: %s" % (getattr(args.thread, "name", "?"), args.exc_value))
        prev(args)
    threading.excepthook = hook
    prev_unraisable = sys.unraisablehook

    def unraisable(args):                                    # raised in a __del__ / weakref callback / finaliser: nobody can catch it
        if args.exc_type is not None and issubclass(args.exc_type, SystemPathAccess):
            THREAD_VIOLATIONS.append("unraisable: %s" % (args.exc_value,))
        prev_unraisable(args)
    sys.unraisablehook = unraisable

    def at_exit():
        if THREAD_VIOLATIONS:
            sys.stdout.flush()
            sys.stderr.write("fs_guard: a worker thread touched a real system path:\n  " + "\n  ".join(THREAD_VIOLATIONS) + "\n")
            sys.stderr.flush()
            os._exit(1)
    atexit.register(at_exit)


class SystemPathAccess(BaseException):
    """A test touched a real system path."""
    def __init__(self, *a):
        super().__init__(*a)
        import threading
        if threading.current_thread() is not threading.main_thread():
            THREAD_VIOLATIONS.append("%s: %s" % (threading.current_thread().name, " ".join(map(str, a))))        # even when the thread's own handler hides it


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
            for v in (os.path.normpath(c), _realpath(c)):          # normpath: TMPDIR=/tmp/../etc is /etc, not a dead lexical /tmp/../etc entry
                if not (drop_broad and v in broad):
                    out.add(v)
    out.discard("/")
    return out


# Where a temp dir named by the environment may live. TMPDIR, tempfile.gettempdir() and COVERAGE_RCFILE are accepted as roots only under one
# of these parents ($RUNNER_TEMP too); anything else (TMPDIR=/etc, =$HOME, =/Users/x/Documents) is ignored, which fails closed.
# FIXED list: $RUNNER_TEMP (or any other variable) must never define a parent, or RUNNER_TEMP=/etc + TMPDIR=/etc would make /etc a writable
# root. The two runner locations are written out.
STANDARD_TEMP = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders", "/dev/shm",
                 "/home/runner/work/_temp", "/__w/_temp")


def _standard_temp_parents():
    return set(STANDARD_TEMP) | _canon_set(set(STANDARD_TEMP))


def _under_standard_temp(v):
    return any(v == p or v.startswith(p + "/") for p in _standard_temp_parents())


def _roots():
    own = {REPO, HERE}
    named = {tempfile.gettempdir()} | {os.environ.get(k, "") for k in ("COVERAGE_RCFILE", "TMPDIR")}
    # a root named by the environment must be under a standard temp parent AND must not be the home directory, `/` or a broad directory: the
    # home check is independent of the parent check (HOME == TMPDIR == /tmp/h must not make the home directory writable)
    return sorted(_canon_set(own) | {v for v in _canon_set(named, drop_broad=True) if _under_standard_temp(v)})


def _env_roots():
    """The interpreter environment, read-only: sys.prefix and its siblings (a venv root holds pyvenv.cfg, bin/, lib/), the directory
    two levels above sys.executable (where pyvenv.cfg lives), the stdlib and site-packages paths (all in _interpreter_dirs), and the sys.path
    entries (and so PYTHONPATH) that are inside those or a standard temp parent; any other entry is at most METADATA (see _meta_roots)."""
    base = _interpreter_dirs()
    paths = {v for v in _canon_set({p for p in sys.path if p}, drop_broad=True) if _trusted_path(v, base)}
    return sorted(base | paths)


def _interpreter_dirs(with_user_site=True):
    """The interpreter's own directories, computed from sys.prefix / sysconfig / site (not from the environment): the base of _env_roots()."""
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
    if with_user_site:
        try:
            precise.add(site.getusersitepackages())
        except Exception:
            pass
    return broad_ok | _canon_set(precise, drop_broad=True)


def _trusted_path(v, interp):
    return any(v == r or v.startswith(r + "/") for r in interp) or _under_standard_temp(v)


def _meta_roots():
    """Directories the interpreter itself names, which coverage (TreeMatcher/abs_file) realpaths at startup: every path of every
    sysconfig scheme (scripts, include, data, ... for posix_prefix, posix_user ...) and the stdlib zip beside the stdlib directory. Metadata
    of the directory only. The user base / user site and every sys.path entry (coverage stats those too) count only when they are under the
    interpreter's own directories or a standard temp parent, like the environment roots."""
    cand = set()
    for scheme in sysconfig.get_scheme_names():
        try:
            cand.update(sysconfig.get_paths(scheme).values())
        except Exception:
            pass
    cand.add(os.path.join(os.path.dirname(sysconfig.get_paths()["stdlib"]), "python%d%d.zip" % sys.version_info[:2]))
    out = _canon_set(cand)
    interp = _interpreter_dirs(with_user_site=False)          # the user site is named by HOME, so it cannot vouch for itself
    extra = set()
    for f in (site.getuserbase, site.getusersitepackages):
        try:
            extra.add(f())
        except Exception:
            pass
    extra.update(p for p in sys.path if p and os.path.isabs(p))
    return sorted(out | {v for v in _canon_set(extra) if _trusted_path(v, interp)})


def _under(p, write=False):
    if (p in EXACT and not write) or any(p == r or p.startswith(r + "/") for r in ROOTS):
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


# The ONLY writes the import system makes under the environment: it opens / renames / removes a .pyc directly in a __pycache__ directory and
# creates that directory (mkdir of exactly that name). rmdir, chmod, utime, truncate, rmtree, symlink ... of either are refused.
_PYC_EVENTS = {"open", "os.open", "os.rename", "os.remove"}
_PYC = re.compile(r"\.pyc(\.\d+)?$")           # importlib writes <name>.pyc.<id> and renames it to <name>.pyc


def _bytecode_cache(res):
    """The RESOLVED path is a bytecode file directly inside a directory named exactly __pycache__."""
    return os.path.basename(os.path.dirname(res)) == "__pycache__" and bool(_PYC.search(os.path.basename(res)))


_PREEXISTING = set()        # (st_dev, st_ino) of every regular file / directory that was already open when install() ran


def _open_fds():
    """Every fd this process holds: /dev/fd (macOS, BSD) or /proc/self/fd (Linux) is enumerated; if neither can be listed, 0..4095 is probed."""
    for d in ("/dev/fd", "/proc/self/fd"):
        try:
            return sorted(int(n) for n in os.listdir(d) if n.isdigit())
        except OSError:
            continue
    return list(range(4096))


def _snapshot_fds():
    import stat as _st
    for fd in _open_fds():
        try:
            st = _real["fstat"](fd)
        except OSError:
            continue
        if _st.S_ISREG(st.st_mode) or _st.S_ISDIR(st.st_mode):
            _PREEXISTING.add((st.st_dev, st.st_ino))


def _judge_fd(fd, what, write=False, meta=False):
    """An integer fd names a file or directory only through the kernel: resolve it (macOS F_GETPATH, Linux /proc/self/fd) and judge THAT.
    A pipe, socket or tty has no filesystem location to protect and an unlinked file has no name, so those pass; a regular file or
    directory whose location cannot be told is refused (fail closed)."""
    import stat as _st
    if isinstance(fd, bool) or fd < 0:
        return
    try:
        st = _real["fstat"](fd)
    except OSError:
        return                                                       # not an open fd: the OS reports it
    if not (_st.S_ISREG(st.st_mode) or _st.S_ISDIR(st.st_mode)) or st.st_nlink == 0:
        return
    if (st.st_dev, st.st_ino) in _PREEXISTING:
        return                                                       # open before the guard was armed (a redirect of stdout / stderr): not the test's access
    base = _fd_dir(fd)
    if base is None or not os.path.isabs(base):
        raise SystemPathAccess("test touched a real system path (%s): an open fd whose location cannot be told: %d" % (what, fd))
    check(base, what, False, meta, write)


def check(path, what="", nofollow=False, meta=False, write=False):
    """Raise unless `path` (lexically and after symlink resolution) is inside an allowed root."""
    if not (ROOTS or ENV or META) or getattr(_busy, "bypass", False):
        return
    if isinstance(path, int):
        return _judge_fd(path, what, write, meta)
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
    if write and ((_bytecode_cache(res) and what in _PYC_EVENTS) or (what == "os.mkdir" and os.path.basename(res) == "__pycache__")):
        write = False                      # the import system caches bytecode beside the module it just read
    if res == "/dev/null" and what in ("open", "os.open"):
        return                             # the only device a test may WRITE, and only by opening it; no other operation on either device
    if not _under(res, write) and not (meta and _ancestor(res)):
        raise SystemPathAccess("test touched a real system path (%s -> %s): %s" % (what, res, p))


_AUDIT_PATH = {  # event -> indexes of the path arguments
    "open": (0,), "os.listdir": (0,), "os.scandir": (0,), "os.rename": (0, 1), "os.remove": (0,), "os.rmdir": (0,),
    "os.mkdir": (0,), "os.chdir": (0,), "os.symlink": (0, 1), "os.link": (0, 1), "os.truncate": (0,), "os.chmod": (0,),
    "os.chown": (0,), "os.utime": (0,), "os.setxattr": (0,), "os.removexattr": (0,),
    "os.getxattr": (0,), "os.listxattr": (0,), "os.chflags": (0,), "os.walk": (0,), "os.fwalk": (0,), "sqlite3.connect": (0,), "tempfile.mkstemp": (0,), "tempfile.mkdtemp": (0,),
    "os.add_dll_directory": (0,),
}
# events with their own branch in _hook (not rows of _AUDIT_PATH): AuditRows checks that CPython really emits each of them
_SPECIAL_EVENTS = ("ctypes.dlopen", "socket.bind", "socket.connect", "socket.sendto", "socket.sendmsg", "sqlite3.load_extension", "sqlite3.enable_load_extension")
_NON_PATH_PREFIXES = ("import", "exec", "compile", "code.", "marshal.", "object.", "builtins.", "sys.", "gc.", "cpython.", "pickle.", "time.", "input",
                      "setopencodehook", "subprocess.", "urllib.", "http.", "ftplib.", "smtplib.", "telnetlib.", "imaplib.", "poplib.", "nntplib.", "ssl.",
                      "webbrowser.", "socket.getaddrinfo", "socket.gethost", "socket.getnameinfo", "socket.getserv", "socket.sethostname",
                      "socket.__new__", "winreg.", "msvcrt.", "syslog.", "signal.", "resource.", "multiprocessing.", "threading.", "asyncio.", "uuid.",
                      "sched.", "importlib.", "zipimport.", "mmap.", "pty.", "fcntl.", "readline.", "ctypes.cdata", "ctypes.call_function",
                      "ctypes.dlsym", "ctypes.set_errno", "ctypes.set_exception", "ctypes.get_errno", "ctypes.get_last_error", "ctypes.addressof",
                      "ctypes.create_", "ctypes.seh_exception", "sqlite3.connect/handle", "sqlite3.enable", "sqlite3.add", "unittest.", "pdb.")
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


def _nofollow_flag():
    return bool(getattr(_busy, "nofollow", False))


def _wrap_nofollow_aware(name):
    """chmod / utime / chown / lchown / lchmod / chflags with follow_symlinks=False act on the link itself; the audit event does not say so."""
    orig = getattr(os, name, None)
    if orig is None:
        return
    always = name.startswith("l")

    def f(*a, **k):
        if always or k.get("follow_symlinks") is False:
            _busy.nofollow = True
            try:
                return orig(*a, **k)
            finally:
                _busy.nofollow = False
        return orig(*a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(os, name, f)


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
            if i >= len(args):
                continue
            if isinstance(args[i], int) and not isinstance(args[i], bool):
                _judge_fd(args[i], event, write, False)                         # open(fd), listdir(fd), scandir(fd), chdir(fd), chmod(fd) ...
                continue
            if event == "os.symlink" and i == 0:
                continue           # a symlink's target text is data; wrap_link judges it where it would resolve
            check(_judged_path(event, args, i), event, (event in _NOFOLLOW and not (event == "os.link" and i == 0)) or (event == "os.symlink" and i == 1)
                  or (_nofollow_flag() and event in ("os.chmod", "os.utime", "os.chown", "os.chflags")), write=write)        # listdir()/scandir() with no argument = the cwd
    elif event in ("glob.glob", "glob.glob/2") and args and isinstance(args[0], (str, bytes, os.PathLike)):
        pat = os.fsdecode(args[0])
        cut = min([i for i in (pat.find(c) for c in "*?[") if i >= 0] or [len(pat)])
        check(os.path.dirname(pat[:cut]) or ".", event)
    elif event.startswith("shutil."):
        # copy*: the source is only read; move and everything else (rmtree, chown, unpack_archive ...) writes every path
        for i, a in enumerate(args):
            if isinstance(a, (str, bytes, os.PathLike)):
                check(a, event, write=not (i == 0 and event.startswith("shutil.copy")))
    elif event in ("socket.bind", "socket.connect", "socket.sendto", "socket.sendmsg"):
        # an AF_UNIX address is a filesystem path (bind creates the socket file); a tuple is an inet address. "\0name" is the abstract namespace.
        addr = args[1] if len(args) > 1 else None
        if isinstance(addr, (bytearray, memoryview)):
            addr = bytes(memoryview(addr))                                    # a bytes-like address is judged as the bytes it holds
        if isinstance(addr, (str, bytes, os.PathLike)):
            name = os.fsdecode(addr)
            if not name.startswith("\0"):
                check(name, event, write=(event == "socket.bind"))
        elif addr is not None and not isinstance(addr, tuple):
            raise SystemPathAccess("test touched a real system path (%s): an address of an unknown type is refused: %s" % (event, type(addr).__name__))
    elif event == "ctypes.dlopen":
        # a bare library name ("libz.dylib") is searched along paths the guard cannot see: refuse it; a name with a slash is judged as a path
        lib = args[0] if args else None
        if lib is not None:
            name = os.fsdecode(lib) if isinstance(lib, (str, bytes, os.PathLike)) else None
            if name is None or "/" not in name:
                raise SystemPathAccess("test touched a real system path (ctypes.dlopen): a bare library name is searched outside the roots: %r" % (lib,))
            check(name, event)
    elif event == "sqlite3.load_extension":
        check(args[1], event) if len(args) > 1 and isinstance(args[1], (str, bytes, os.PathLike)) else None    # dlopen of the named library
    elif event == "sqlite3.enable_load_extension":
        if len(args) < 2 or args[1]:
            raise SystemPathAccess("test touched a real system path (sqlite3): loading extensions is refused while the guard is armed")
    elif event not in _NOT_PATHS and not event.startswith(_NON_PATH_PREFIXES):
        # fail closed: EVERY other audit event is examined, and an argument that is a PathLike, or a str/bytes naming a path, is judged as a
        # write. Only the explicit prefixes in _NON_PATH_PREFIXES (events whose strings are code, hosts, URLs, module names ...) are skipped.
        for a in args:
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
        nf = nofollow or k.get("follow_symlinks") is False          # os.stat(link, follow_symlinks=False) acts on the link itself
        if k.get("dir_fd") is not None and not isinstance(path, int):
            check(_with_dir_fd(path, k["dir_fd"], name), name, nf, True)
        else:
            check(path, name, nf, True)
        return orig(path, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(mod, name, f)


def _deny_attach(action, arg1=None, *rest):
    import sqlite3
    if action == sqlite3.SQLITE_ATTACH:                         # VACUUM INTO is authorised as an ATTACH
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() in ("temp_store_directory", "data_store_directory"):
        return sqlite3.SQLITE_DENY                              # where sqlite writes its temporary files: not a path the guard can judge
    return sqlite3.SQLITE_OK


def _wrap_sqlite():
    """Every way to open a database goes through the authorizer: sqlite3.connect, sqlite3.dbapi2.connect, _sqlite3.connect and a direct
    sqlite3.Connection(...) (a subclass that sets it in __init__; connect(factory=...) is covered because the result is authorised afterwards)."""
    try:
        import sqlite3, sqlite3.dbapi2
        import _sqlite3
    except ImportError:
        return

    def make_connect(orig):
        def connect(*a, **k):
            if "factory" not in k and len(a) < 6:
                k["factory"] = Connection                  # so connect() still returns an instance of sqlite3.Connection
            c = orig(*a, **k)
            c.set_authorizer(_deny_attach)
            return c
        connect.__name__ = "connect"; connect.__wrapped__ = orig
        return connect
    base = sqlite3.Connection

    class Connection(base):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.set_authorizer(_deny_attach)
    Connection.__name__ = Connection.__qualname__ = "Connection"
    for mod in (sqlite3, sqlite3.dbapi2, _sqlite3):
        if hasattr(mod, "connect"):
            mod.connect = make_connect(mod.connect)
        if hasattr(mod, "Connection"):
            mod.Connection = Connection


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
    __slots__ = ("_e", "_base")

    def __init__(self, e, base=None):
        self._e = e
        self._base = base                       # the directory an fd scan is relative to (entry.path is then just the name)

    name = property(lambda self: self._e.name)
    path = property(lambda self: self._e.path)

    def inode(self):
        return self._e.inode()

    def is_symlink(self):
        return self._e.is_symlink()

    def is_junction(self):
        return getattr(self._e, "is_junction", lambda: False)()

    @property
    def __class__(self):                       # isinstance(entry, os.DirEntry) stays true (os.DirEntry cannot be subclassed)
        return os.DirEntry

    def _follow(self, follow):
        if follow and self._e.is_symlink():
            check(os.path.join(self._base, self._e.name) if self._base else self._e.path, "DirEntry", False, True)

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
    def __init__(self, it, base=None):
        self._it = it
        self._base = base

    def __iter__(self):
        return self

    def __next__(self):
        return _Entry(next(self._it), self._base)

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
        return _Scan(it, _fd_dir(path) if isinstance(path, int) else None)
    scandir.__name__ = "scandir"; scandir.__wrapped__ = orig
    os.scandir = scandir


def _wrap_fd_function(name, write=False, meta=False):
    orig = getattr(os, name, None)
    if orig is None:
        return

    def f(fd, *a, **k):
        _judge_fd(fd, "os." + name, write, meta)
        return orig(fd, *a, **k)
    f.__name__ = name; f.__wrapped__ = orig
    setattr(os, name, f)


def _wrap_os_open():
    orig = os.open

    def f(path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is not None:
            check(_with_dir_fd(path, dir_fd, "os.open"), "os.open", False, False, bool(flags & _WRITE_FLAGS))
            _busy.bypass = True               # judged above under the fd's directory; the open event only carries the bare relative name
            try:
                return orig(path, flags, mode, dir_fd=dir_fd)
            finally:
                _busy.bypass = False
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
    _snapshot_fds()
    sys.addaudithook(_hook)
    _record_thread_violations()
    for n in ("stat", "lstat", "readlink", "access", "statvfs", "pathconf", "listxattr", "getxattr"):
        _wrap1(os, n, n in ("lstat", "readlink"))
    for n in ("realpath", "exists", "isfile", "isdir", "islink", "lexists", "getsize"):
        _wrap1(os.path, n, n in ("islink", "lexists"))
    for n in ("symlink", "link"):
        setattr(os, n, wrap_link(getattr(os, n), "os." + n))
    _wrap_os_open()
    _wrap_sqlite()
    for n in ("chmod", "utime", "chown", "lchown", "lchmod", "lchflags", "chflags"):
        _wrap_nofollow_aware(n)
    _wrap_scandir()
    _wrap_fd_function("fstat", False, True)
    _wrap_fd_function("fstatvfs", False, True)
    _wrap_fd_function("fpathconf", False, True)
    # fchmod / fchown / ftruncate / fchdir emit os.chmod / os.chown / os.truncate / os.chdir with the fd as the argument: the hook judges them
    for n in ("mkfifo", "mknod", "chroot"):
        _wrap_write_path(n)
    for n in ("setxattr", "removexattr"):
        _wrap_xattr_write(n)
    # os.supports_dir_fd / supports_fd / supports_follow_symlinks / supports_effective_ids hold the ORIGINAL functions, and shutil (and others)
    # test membership in them: register each wrapper wherever its original is a member, or the stdlib silently takes the slower / skipping path
    for name in dir(os):
        fn = getattr(os, name, None)
        orig = getattr(fn, "__wrapped__", None)
        if orig is not None:
            for sup in (os.supports_dir_fd, os.supports_fd, os.supports_follow_symlinks, os.supports_effective_ids):
                if orig in sup:
                    sup.add(fn)
