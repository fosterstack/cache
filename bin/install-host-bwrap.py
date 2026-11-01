#!/usr/bin/env python3
"""Unpack the host tools (bubblewrap and what it needs) from the pulled archive (REQ-CHAIN-004-AC17; rules 15 and 38a).

  install-host-bwrap.py --archive archive --lock build/locks/host-tools.lock --root host-tools [--bin /usr/local/bin] [--arch x86_64|aarch64]

melange's bubblewrap runner needs bwrap on the machine, and the hosted images do not ship it. It comes from the archive like every other build
tool, never from a package manager: the packages the committed lock names (name=version rows, REQ-REFRESH-001-AC35) are read for this machine's
architecture from archive/<arch>/<name>-<version>.apk, which the pull step before this one has already checked against the committed pointer. Each is checked
once more here (the file is there, its control segment names the lock's name and version and this architecture, the sha256 of its data segment equals
the datahash the control segment records), unpacked into the NEW directory --root, and a small wrapper --bin/bwrap runs the extracted loader with
--library-path over the extracted libraries and the extracted usr/bin/bwrap (the glibc of the archive, not the runner's).

Nothing is fetched, no other program is started and nothing needs a privilege: the apk is read as data (gzip and the archive format as a library). Everything is
checked and unpacked in a staging directory beside --root and renamed to --root only when every check passed; a refusal leaves nothing at --root and
no wrapper. An existing --root is refused untouched.
Exit codes: 0 done | 1 a file is missing, does not match its record or is unsafe, the loader or bwrap is missing (nothing written) | 2 refused: bad
arguments, a lock that is empty or not closed, an unsupported architecture, an existing --root.
"""
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile
import zlib

ARCHS = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*")
SAFE_PATH = re.compile(r"[A-Za-z0-9_./+-]+")
USAGE = "usage: install-host-bwrap.py --archive DIR --lock FILE --root DIR [--bin DIR] [--arch x86_64|aarch64]"


def die(msg, code=1):
    sys.stderr.write("install-host-bwrap.py: %s\n" % msg)
    sys.exit(code)


def read_lock(path):
    try:
        text = open(path, "rb").read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        die("cannot read the lock %s: %s" % (path, e), 2)
    if not text:
        die("the host tools lock %s is empty: the refresh job has not filled it yet" % path, 2)
    if not text.endswith("\n"):
        die("the host tools lock %s does not end with a line end" % path, 2)
    rows, seen = [], set()
    for row in text.split("\n")[:-1]:
        name, eq, ver = row.partition("=")
        if not eq or not NAME.fullmatch(name) or not VERSION.fullmatch(ver) or ".." in name or ".." in ver:
            die("the host tools lock %s has a row that is not name=version: %r" % (path, row), 2)
        if name in seen:
            die("the host tools lock %s names %s twice" % (path, name), 2)
        seen.add(name)
        rows.append((name, ver))
    return rows


def members(raw, what):
    """Split an apk into its gzip members (signature, control, data; the signature is optional): the raw bytes of each and what it decompresses to."""
    out, rest = [], raw
    while rest:
        d = zlib.decompressobj(31)
        try:
            data = d.decompress(rest)
        except zlib.error as e:
            die("%s is not an apk (gzip: %s)" % (what, e))
        if not d.eof:
            die("%s is truncated" % what)
        used = len(rest) - len(d.unused_data)
        out.append((rest[:used], data))
        rest = d.unused_data
    if len(out) not in (2, 3):
        die("%s is not an apk: %d gzip members, expected a control and a data segment (and perhaps a signature first)" % (what, len(out)))
    return out


def pkginfo(ctl, what):
    try:
        with tarfile.open(fileobj=io.BytesIO(ctl), mode="r:") as t:
            f = t.extractfile(".PKGINFO")
            if f is None:
                die("%s has no .PKGINFO" % what)
            text = f.read().decode("utf-8")
    except (tarfile.TarError, KeyError, UnicodeDecodeError) as e:
        die("%s has no readable .PKGINFO (%s)" % (what, e))
    info = {}
    for line in text.splitlines():
        k, eq, v = line.partition(" = ")
        if eq and k in ("pkgname", "pkgver", "arch", "datahash") and k not in info:
            info[k] = v.strip()
    return info


def inside(root_parts_target):
    depth = 0
    for p in root_parts_target:
        if p in ("", "."):
            continue
        if p == "..":
            depth -= 1
            if depth < 0:
                return False
        else:
            depth += 1
    return True


SKIPPED = set()   # the paths of absolute links that were not created


def check_place(stage, norm, what, kind):
    """Nothing is written through a symlink or over something that is not what the entry is: every directory above the entry must be a real directory inside the
    staging directory (never a symlink an earlier entry made), and the entry's own place must be free (a directory entry may meet a real directory)."""
    cur = stage
    for part in norm.split("/")[:-1]:
        cur = os.path.join(cur, part)
        if os.path.relpath(cur, stage) in SKIPPED:
            die("%s: %s is written below %s, an absolute symlink that was not created" % (what, norm, os.path.relpath(cur, stage)))
        if os.path.islink(cur) or (os.path.lexists(cur) and not os.path.isdir(cur)):
            die("%s: %s is written below %s, which is a symlink or a file, not a directory" % (what, norm, os.path.relpath(cur, stage)))
    if norm in SKIPPED:
        die("%s: %s is the path of an absolute symlink that was not created: nothing of any kind is placed there" % (what, norm))
    if kind != "dir" and any(sk.startswith(norm + "/") for sk in SKIPPED):
        die("%s: %s is not a directory but an absolute symlink that was not created lies below it" % (what, norm))
    dest = os.path.join(stage, norm)
    if os.path.lexists(dest) and not (kind == "dir" and os.path.isdir(dest) and not os.path.islink(dest)):
        die("%s: the place of %s is already taken" % (what, norm))


def unpack(data, stage, owner, owners, what):
    try:
        t = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        infos = t.getmembers()
    except tarfile.TarError as e:
        die("%s: the data segment is not a tar archive (%s)" % (what, e))
    for m in infos:
        name = m.name
        parts = name.split("/")
        if name.startswith("/") or ".." in parts or not name or "\0" in name:
            die("%s: unsafe path %r in the data segment" % (what, name))
        norm = "/".join(p for p in parts if p not in ("", "."))
        if not norm:
            continue
        dest = os.path.join(stage, norm)
        check_place(stage, norm, what, "dir" if m.isdir() else "other")
        if m.isdir():
            os.makedirs(dest, exist_ok=True)
            continue
        if norm in owners:
            die("%s: the path %s is also in %s" % (what, norm, owners[norm]))
        if m.issym():
            target = m.linkname
            if not target or "\0" in target:
                die("%s: the symlink %s has an empty target" % (what, norm))
            if target.startswith("/"):
                # an ABSOLUTE link is never created (wolfi-baselayout's etc/mtab -> /proc/mounts): it would be resolved on the host by whatever reads the root later (the
                # extracted loader looks up libraries and the wrapper runs usr/bin/bwrap through it). The path stays held by the package that named it, and nothing is placed below it.
                print("install-host-bwrap.py: skipped absolute link %s -> %s (%s)" % (norm, target, what))
                SKIPPED.add(norm)
                owners[norm] = owner
                continue
            if not inside(norm.split("/")[:-1] + target.split("/")):
                die("%s: the symlink %s leaves the directory (target %r)" % (what, norm, target))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.symlink(target, dest)
        elif m.isfile():
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            src = t.extractfile(m)
            with open(dest, "wb") as out:
                out.write(src.read())
            os.chmod(dest, 0o755 if m.mode & 0o111 else 0o644)
        else:
            die("%s: %s is a hard link, a device or another kind of entry that is not unpacked" % (what, norm))
        owners[norm] = owner


def escapes(stage, rel):
    """Walk the symlink `rel` of the staging tree component by component, following the other links as they are met, and answer whether the walk ever goes above the
    staging root (even if it would come back in under the staging name: the directory is renamed afterwards, so that way back no longer exists) or loops."""
    stack = rel.split("/")[:-1]
    pending = os.readlink(os.path.join(stage, rel)).split("/")
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return True
            stack.pop()
            continue
        full = os.path.join(stage, *(stack + [part]))
        if os.path.islink(full):
            hops += 1
            target = os.readlink(full)
            if hops > 40 or target.startswith("/"):
                return True
            pending = target.split("/") + pending
            continue
        stack.append(part)
    return False


def check_links(stage):
    """Every symlink of the finished staging tree stays inside the root however the other symlinks are chained, in whatever order the packages named them."""
    for dirpath, dirs, files in os.walk(stage):
        for n in dirs + files:
            p = os.path.join(dirpath, n)
            if os.path.islink(p) and escapes(stage, os.path.relpath(p, stage)):
                die("the symlink %s leaves the directory once the other links are followed" % os.path.relpath(p, stage))


def loader_of(root):
    found = []
    for d in ("usr/lib", "lib"):
        full = os.path.join(root, d)
        if os.path.isdir(full) and not os.path.islink(full):
            for f in sorted(os.listdir(full)):
                p = os.path.join(full, f)
                if re.fullmatch(r"ld-linux-[A-Za-z0-9._-]+\.so\.[0-9]+", f) and os.path.isfile(p) and not os.path.islink(p):
                    found.append(p)
    return found


def main(argv):
    args, i = {}, 0
    while i < len(argv):
        a = argv[i]
        if a in ("--archive", "--lock", "--root", "--bin", "--arch") and i + 1 < len(argv):
            if a in args:
                die("%s given twice" % a, 2)
            args[a] = argv[i + 1]
            i += 2
        else:
            die("unknown or incomplete argument %r\n%s" % (a, USAGE), 2)
    for need in ("--archive", "--lock", "--root"):
        if need not in args:
            die(USAGE, 2)
    arch = ARCHS.get(args.get("--arch") or os.uname().machine)
    if arch is None:
        die("unsupported architecture %r (x86_64 or aarch64)" % (args.get("--arch") or os.uname().machine), 2)
    binary = args.get("--bin", "/usr/local/bin")
    root = os.path.abspath(args["--root"])
    if not SAFE_PATH.fullmatch(root):
        die("the directory %s has characters the wrapper does not quote" % root, 2)
    if os.path.lexists(root):
        die("%s exists: the host tools are unpacked into a new directory" % root, 2)
    rows = read_lock(args["--lock"])

    owners, plan = {}, []
    for name, ver in rows:
        path = "%s/%s/%s-%s.apk" % (args["--archive"], arch, name, ver)
        what = "%s-%s.apk (%s)" % (name, ver, arch)
        if os.path.islink(path) or not os.path.isfile(path):
            die("%s is not in the archive (%s): the lock names it, so the archive must hold it" % (what, path))
        raw = open(path, "rb").read()
        parts = members(raw, what)
        info = pkginfo(parts[-2][1], what)
        if info.get("pkgname") != name or info.get("pkgver") != ver:
            die("%s: its control segment names %s-%s, the lock row is %s-%s" % (what, info.get("pkgname"), info.get("pkgver"), name, ver))
        if info.get("arch") not in (arch, "noarch"):
            die("%s: its control segment says architecture %s" % (what, info.get("arch")))
        want = info.get("datahash", "")
        if not re.fullmatch(r"[0-9a-f]{64}", want) or hashlib.sha256(parts[-1][0]).hexdigest() != want:
            die("%s: the sha256 of its data segment is not the datahash its control segment records" % what)
        plan.append((name, ver, what, parts[-1][1]))

    stage = root + ".staging"
    if os.path.lexists(stage):
        die("%s exists: a staging directory of an earlier run" % stage, 2)
    os.makedirs(stage)
    try:
        for name, ver, what, data in plan:
            unpack(data, stage, "%s-%s" % (name, ver), owners, what)
        check_links(stage)
        bw = os.path.join(stage, "usr/bin/bwrap")
        if not os.path.isfile(bw) or os.path.islink(bw):
            die("the unpacked packages hold no usr/bin/bwrap")
        loaders = loader_of(stage)
        if len(loaders) != 1:
            die("the unpacked packages hold %d dynamic loaders (usr/lib or lib, ld-linux-*.so.N), expected exactly one" % len(loaders))
        loader = os.path.relpath(loaders[0], stage)
        os.rename(stage, root)
    except BaseException as e:
        import shutil
        shutil.rmtree(stage, ignore_errors=True)
        if isinstance(e, SystemExit):
            raise
        die("cannot unpack the host tools (%s: %s); nothing was written" % (type(e).__name__, e))
    wrapper = '#!/bin/sh\nexec %s/%s --library-path %s/usr/lib:%s/lib %s/usr/bin/bwrap "$@"\n' % (root, loader, root, root, root)
    try:
        os.makedirs(binary, exist_ok=True)
        tmp = os.path.join(binary, ".bwrap.%d" % os.getpid())
        with open(tmp, "w") as f:
            f.write(wrapper)
        os.chmod(tmp, 0o755)
        os.replace(tmp, os.path.join(binary, "bwrap"))
    except OSError as e:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
        try:
            os.unlink(tmp)
        except (OSError, NameError):
            pass
        die("cannot write the wrapper in %s: %s" % (binary, e))
    print("installed bubblewrap and %d package(s) from the archive (%s) into %s; wrapper %s/bwrap" % (len(plan), arch, root, binary))


if __name__ == "__main__":
    main(sys.argv[1:])
