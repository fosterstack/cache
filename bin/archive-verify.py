#!/usr/bin/env python3
"""The archive tools' checker and packer (REQ-ARCHIVE-001; rules 26, 27, 29, 30, 44).

  archive-verify.py verify --pointer FILE --dir DIR [--pushed-digest sha256:HEX]
  archive-verify.py pointer-check --pointer FILE
  archive-verify.py artifact --pointer FILE        print the artifact the pointer names
  archive-verify.py pack --dir DIR --layout DIR    write an OCI layout; print REPO@sha256:<manifest digest>
  archive-verify.py unpack --pointer FILE --layout DIR --out DIR
  archive-verify.py make-pointer --dir DIR --digest sha256:HEX --out FILE   write the pointer naming that artifact and DIR's files

Exit codes: 0 ok, 1 verification failed (names the file), 2 refused (bad input).
This file reads nothing from its caller's surroundings and runs no other program; it uses hashlib, json, os, re, signal and sys only.
"""
import hashlib
import json
import os
import re
import signal
import sys

REPO = "ghcr.io/fosterstack/cache-archive"
HEX = re.compile(r"[0-9a-f]{64}")
ARTIFACT = re.compile(re.escape(REPO) + r"@sha256:([0-9a-f]{64})")
COMPONENT = re.compile(r"[A-Za-z0-9_+~-][A-Za-z0-9._+~-]*")
APK = re.compile(r"(.+)-([0-9][A-Za-z0-9._+~]*-r[0-9]+)\.apk")
T_TITLE = "org.opencontainers.image.title"
T_VERSION = "org.fosterstack.cache-archive.version"
T_SHA = "org.fosterstack.cache-archive.sha256"
M_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
M_CONFIG = "application/vnd.fosterstack.cache-archive.config.v1+json"
M_FILE = "application/vnd.fosterstack.cache-archive.file.v1"


def die(msg, rc=2):
    sys.stderr.write("archive-verify.py: %s\n" % msg)
    sys.exit(rc)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    return isinstance(name, str) and bool(name) and all(COMPONENT.fullmatch(c) for c in name.split("/"))


def load_pointer(path):
    """Return (digest 'sha256:<hex>', {name: sha256}); refuse anything but the exact schema."""
    try:
        with open(path, "rb") as f:
            d = json.loads(f.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        die("pointer %s is not readable JSON: %s" % (path, e))
    if not isinstance(d, dict) or sorted(d) != ["artifact", "files", "schema"]:
        die("pointer %s must hold exactly schema, artifact and files" % path)
    if type(d["schema"]) is not int or d["schema"] != 1:
        die("pointer %s: schema must be the number 1" % path)
    m = ARTIFACT.fullmatch(d["artifact"]) if isinstance(d["artifact"], str) else None
    if not m:
        die("pointer %s: artifact must be %s@sha256:<64 lower-case hex> (by digest only)" % (path, REPO))
    files = d["files"]
    if not isinstance(files, list) or not files:
        die("pointer %s: files must be a non-empty list" % path)
    want, last = {}, None
    for e in files:
        if not isinstance(e, dict) or sorted(e) != ["name", "sha256"]:
            die("pointer %s: each file must hold exactly name and sha256" % path)
        n, h = e["name"], e["sha256"]
        if not safe_name(n):
            die("pointer %s: unsafe file name %r" % (path, n))
        if not isinstance(h, str) or not HEX.fullmatch(h):
            die("pointer %s: %s: sha256 must be 64 lower-case hex" % (path, n))
        if last is not None and n <= last:
            die("pointer %s: files must be sorted and unique (at %s)" % (path, n))
        last = n
        want[n] = h
    return "sha256:" + m.group(1), want


def scan(d):
    """{name: sha256} of the regular files under d; also the problems: symlinks, other entries, empty directories."""
    have, extra = {}, []
    if not os.path.isdir(d) or os.path.islink(d):
        die("%s is not a directory" % d, 1)
    for root, dirs, files in os.walk(d):
        dirs.sort()
        for n in sorted(dirs):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, d)
            if os.path.islink(p):
                extra.append("%s (a symlink)" % rel)
            elif not any(True for _ in os.scandir(p)):
                extra.append("%s (an empty directory)" % rel)
        for n in sorted(files):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, d)
            if os.path.islink(p) or not os.path.isfile(p):
                extra.append("%s (not a regular file)" % rel)
                continue
            with open(p, "rb") as f:
                have[rel] = sha(f.read())
        # symlinks to directories are listed in dirs by os.walk but not followed (followlinks False)
    return have, extra


def verify_dir(d, want):
    have, odd = scan(d)
    missing = sorted(set(want) - set(have))
    extra = sorted(set(have) - set(want))
    altered = sorted(n for n in want if n in have and have[n] != want[n])
    problems = ["missing: %s" % n for n in missing] + ["extra: %s" % n for n in extra] + ["altered: %s" % n for n in altered] + ["extra: %s" % n for n in odd]
    return problems


def cmd_verify(a):
    digest, want = load_pointer(a["--pointer"])
    pushed = a.get("--pushed-digest")
    if pushed is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", pushed):
        die("--pushed-digest must be sha256:<64 lower-case hex>")
    if pushed is not None and pushed != digest:
        die("the pointer names %s but the job pushed %s" % (digest, pushed), 1)
    problems = verify_dir(a["--dir"], want)
    if problems:
        die("%s does not match the pointer:\n  %s" % (a["--dir"], "\n  ".join(problems)), 1)


def cmd_pointer_check(a):
    load_pointer(a["--pointer"])


def cmd_artifact(a):
    digest, _ = load_pointer(a["--pointer"])
    print("%s@%s" % (REPO, digest))


def cmd_make_pointer(a):
    digest = a["--digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        die("--digest must be sha256:<64 lower-case hex>")
    have, odd = scan(a["--dir"])
    if odd:
        die("%s holds what a pointer cannot name:\n  %s" % (a["--dir"], "\n  ".join(sorted(odd))), 1)
    if not have:
        die("%s holds no file" % a["--dir"], 1)
    doc = {"schema": 1, "artifact": "%s@%s" % (REPO, digest), "files": [{"name": n, "sha256": have[n]} for n in sorted(have)]}
    out = a["--out"]
    tmp = "%s.tmp-%s" % (out, os.urandom(8).hex())
    with open(tmp, "x", encoding="utf-8") as f:
        f.write(json.dumps(doc, indent=1) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)


def put(layout, data):
    h = sha(data)
    with open(os.path.join(layout, "blobs", "sha256", h), "wb") as f:
        f.write(data)
    return "sha256:" + h


def cmd_pack(a):
    d, layout = a["--dir"], a["--layout"]
    if not os.path.isdir(d) or os.path.islink(d):
        die("%s is not a directory" % d)
    names = []
    for root, dirs, files in os.walk(d):
        for n in dirs:
            p = os.path.join(root, n)
            if os.path.islink(p):
                die("%s is a symlink; the archive holds regular files only" % os.path.relpath(p, d))
        for n in files:
            p = os.path.join(root, n)
            rel = os.path.relpath(p, d)
            if os.path.islink(p) or not os.path.isfile(p):
                die("%s is a symlink or not a regular file; the archive holds regular files only" % rel)
            if not safe_name(rel):
                die("%s: file names are letters, digits and . _ + ~ - only, never starting with a dot" % rel)
            names.append(rel)
    if not names:
        die("%s holds no file" % d)
    names.sort()
    if os.path.exists(layout):
        die("%s exists" % layout)
    os.makedirs(os.path.join(layout, "blobs", "sha256"))
    layers = []
    for rel in names:
        with open(os.path.join(d, rel), "rb") as f:
            data = f.read()
        m = APK.fullmatch(rel.split("/")[-1])
        digest = put(layout, data)
        layers.append({"mediaType": M_FILE, "digest": digest, "size": len(data),
                       "annotations": {T_TITLE: rel, T_VERSION: m.group(2) if m else "", T_SHA: digest[7:]}})
    config = put(layout, canon({"schema": 1, "files": [x["annotations"][T_TITLE] for x in layers]}))
    manifest = {"schemaVersion": 2, "mediaType": M_MANIFEST,
                "config": {"mediaType": M_CONFIG, "digest": config, "size": len(canon({"schema": 1, "files": [x["annotations"][T_TITLE] for x in layers]}))},
                "layers": layers}
    raw = canon(manifest)
    md = put(layout, raw)
    with open(os.path.join(layout, "oci-layout"), "wb") as f:
        f.write(canon({"imageLayoutVersion": "1.0.0"}))
    with open(os.path.join(layout, "index.json"), "wb") as f:
        f.write(canon({"schemaVersion": 2, "manifests": [{"mediaType": M_MANIFEST, "digest": md, "size": len(raw)}]}))
    print("%s@%s" % (REPO, md))


def blob(layout, digest):
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        die("bad digest %r in the artifact" % digest, 1)
    p = os.path.join(layout, "blobs", "sha256", digest[7:])
    try:
        with open(p, "rb") as f:
            data = f.read()
    except OSError:
        die("the artifact lacks the blob %s" % digest, 1)
    if sha(data) != digest[7:]:
        die("the blob %s does not hash to its name" % digest, 1)
    return data


def cmd_unpack(a):
    digest, want = load_pointer(a["--pointer"])
    layout, out = a["--layout"], a["--out"]
    if os.path.lexists(out):
        die("%s exists" % out)
    try:
        with open(os.path.join(layout, "index.json"), "rb") as f:
            idx = json.loads(f.read().decode("utf-8"))
        ms = idx["manifests"]
        assert isinstance(ms, list) and len(ms) == 1 and ms[0]["digest"] == digest
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        die("the layout's index.json does not name exactly the committed manifest %s" % digest, 1)
    raw = blob(layout, digest)
    try:
        manifest = json.loads(raw.decode("utf-8"))
        layers = manifest["layers"]
        assert isinstance(layers, list)
    except (ValueError, KeyError, AssertionError):
        die("the manifest is not an archive manifest", 1)
    got = {}
    for L in layers:
        try:
            ann = L["annotations"]
            name, h = ann[T_TITLE], ann[T_SHA]
            ld = L["digest"]
        except (KeyError, TypeError):
            die("a layer lacks its annotations", 1)
        if not safe_name(name):
            die("unsafe layer name %r" % name, 1)
        if name in got:
            die("%s appears twice in the artifact" % name, 1)
        if h != str(ld)[7:] or h != sha(blob(layout, ld)):
            die("%s: the layer does not match its sha256 annotation" % name, 1)
        got[name] = h
    # the artifact must be exactly the pointer's list before anything is written
    bad = ["missing: %s" % n for n in sorted(set(want) - set(got))] + ["extra: %s" % n for n in sorted(set(got) - set(want))] \
        + ["altered: %s" % n for n in sorted(n for n in want if n in got and got[n] != want[n])]
    if bad:
        die("the artifact does not match the pointer:\n  %s" % "\n  ".join(bad), 1)
    stage = out + ".stage"
    if os.path.lexists(stage):
        die("%s exists" % stage)
    # a terminating signal during the extraction must run the cleanup below: the default SIGTERM action ends the process without it
    # (REQ-ARCHIVE-001-AC6: an interrupted pull leaves nothing at the output path or beside it)
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        for L in layers:
            p = os.path.join(stage, L["annotations"][T_TITLE])
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "xb") as f:
                f.write(blob(layout, L["digest"]))
            os.chmod(p, 0o644)
        problems = verify_dir(stage, want)
        if problems:
            die("the unpacked files do not match the pointer:\n  %s" % "\n  ".join(problems), 1)
        os.rename(stage, out)
    except BaseException:
        _ignore_signals()           # whatever failed, the cleanup that follows is not interrupted by a signal
        remove_tree(stage)          # a failed or interrupted extraction leaves neither the stage nor the output behind
        raise


def _stop(signum, frame):
    _ignore_signals()          # a second signal must not interrupt the cleanup the first one starts
    raise SystemExit(128 + signum)


def _ignore_signals():
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def remove_tree(path):
    """remove a directory tree this process made (os only: this file runs no subprocess)"""
    if not os.path.lexists(path):
        return
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for n in files:
            os.unlink(os.path.join(root, n))
        for n in dirs:
            p = os.path.join(root, n)
            os.unlink(p) if os.path.islink(p) else os.rmdir(p)
    os.rmdir(path)


def main(argv):
    if len(argv) < 2:
        die("usage: archive-verify.py verify|pointer-check|artifact|pack|unpack|make-pointer ...")
    cmd, rest = argv[1], argv[2:]
    allowed = {"verify": ("--pointer", "--dir", "--pushed-digest"), "pointer-check": ("--pointer",), "artifact": ("--pointer",),
               "pack": ("--dir", "--layout"), "unpack": ("--pointer", "--layout", "--out"),
               "make-pointer": ("--dir", "--digest", "--out")}
    required = {"verify": ("--pointer", "--dir"), "pointer-check": ("--pointer",), "artifact": ("--pointer",),
                "pack": ("--dir", "--layout"), "unpack": ("--pointer", "--layout", "--out"),
                "make-pointer": ("--dir", "--digest", "--out")}
    if cmd not in allowed:
        die("unknown command %s" % cmd)
    a = {}
    i = 0
    while i < len(rest):
        if rest[i] not in allowed[cmd] or i + 1 >= len(rest):
            die("bad argument %s" % rest[i])
        a[rest[i]] = rest[i + 1]
        i += 2
    for r in required[cmd]:
        if r not in a:
            die("%s is required" % r)
    {"verify": cmd_verify, "pointer-check": cmd_pointer_check, "artifact": cmd_artifact, "pack": cmd_pack, "unpack": cmd_unpack,
     "make-pointer": cmd_make_pointer}[cmd](a)


if __name__ == "__main__":
    main(sys.argv)
