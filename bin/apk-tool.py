#!/usr/bin/env python3
"""Read-only apk inspection for the build (v0.3.0 rules 14, 15, 22).

An apk is up to three concatenated gzip streams: an optional signature (a tar with .SIGN.RSA.<key>), the control
section (.PKGINFO, .melange.yaml) and the data section (the files).

  apk-tool.py digest APK                  prints sha256:<hex> of the CONTROL and DATA sections together (the apk's identity; the signature
                                          is excluded, so re-signing never changes it)
  apk-tool.py same A B                    exit 0 if A and B have the same control AND data sections (signatures ignored, an unsigned
                                          copy is the same), 1 if not (names B), 2 on an unreadable file
  apk-tool.py signer APK                  prints the signing key's name (<key file name>.rsa.pub) or
                                          "unsigned"
  apk-tool.py verify APK PUBKEY           cryptographically verifies the apk's signature against the public key file PUBKEY (the signature member
                                          is an RSA signature over the compressed CONTROL stream: .SIGN.RSA.<name> is SHA-1, .SIGN.RSA256.<name>
                                          SHA-256); prints verified:<name> and exits 0 only when the signature is valid for that key.
                                          exit 1 if unsigned, the signature does not verify, or its algorithm is not RSA/RSA256; 2 unreadable
  apk-tool.py control APK OUT             writes the CONTROL stream of APK to OUT exactly as stored (the gzip bytes the signature covers); OUT must not
                                          exist yet
  apk-tool.py attach-signature APK SIG OUT
                                          writes to OUT (which must not exist yet) a copy of APK whose signature stream is replaced by a gzip of a tar
                                          holding the one member .SIGN.RSA256.release.rsa.pub = the bytes of SIG; the control and data streams are copied
                                          unchanged, so the digest of the result equals the digest of APK and the result has exactly one .SIGN member
  apk-tool.py cat APK MEMBER              writes the bytes of MEMBER from the data section to standard output
                                          (exit 2 if it is not there)
  apk-tool.py binary-check APK FILE       rule 14: exit 0 if FILE equals usr/bin/fscache in APK, 1 if not (prints both
                                          sha256 digests), 2 if APK has no usr/bin/fscache
  apk-tool.py inputs-manifest --apk APK --melange-lock FILE --out FILE
                                          rule 15: reads the build environment melange embedded in APK (.melange.yaml),
                                          requires every name=version in it to be in the melange lock, and writes the
                                          manifest (the lock plus the environment read back) as JSON.
                                          exit 0 | 1 a package of the environment is not in the lock (names it) | 2 bad input
Exit codes: 0 ok, 1 the check failed, 2 refused (unreadable or malformed input).
"""
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import sys
import tarfile
import zlib

import yaml


def refuse(msg, code=2):
    print("apk-tool: " + msg, file=sys.stderr)
    sys.exit(code)


INFLATE_CAP = 1 << 30   # 1 GiB per section


def streams(path):
    try:
        raw = open(path, "rb").read()
    except OSError as e:
        refuse("cannot read %s: %s" % (path, e))
    out = []
    total = 0
    while raw:
        d = zlib.decompressobj(31)
        try:
            data = d.decompress(raw, INFLATE_CAP + 1)
        except zlib.error as e:
            refuse("%s is not an apk (gzip: %s)" % (path, e))
        if len(data) > INFLATE_CAP or d.unconsumed_tail:
            refuse("%s: a section decompresses to more than %d MiB (refusing)" % (path, INFLATE_CAP >> 20))
        if not d.eof:
            refuse("%s: a gzip stream is not complete (it ends before its CRC/size trailer: truncated)" % path)
        validate_tar(path, data)
        total += len(data)
        if total > INFLATE_CAP:
            refuse("%s: the sections inflate to more than %d MiB in total (refusing)" % (path, INFLATE_CAP >> 20))
        used = len(raw) - len(d.unused_data)
        out.append((raw[:used], data))
        raw = d.unused_data
    if not out:
        refuse("%s is empty" % path)
    if len(out) > 3:
        refuse("%s has %d gzip streams; an apk has at most three (signature, control, data), so nothing may hide between them" % (path, len(out)))
    return out


def norm(n):
    return n[2:] if n.startswith("./") else n


ALLOWED_TYPES = (b"0", b"5")   # regular file and directory only: a symlink or hard link could make a later name overwrite usr/bin/fscache (apko follows it)
NUMERIC_FIELDS = (("mode", 100, 108), ("uid", 108, 116), ("gid", 116, 124), ("size", 124, 136), ("mtime", 136, 148), ("checksum", 148, 156), ("devmajor", 329, 337), ("devminor", 337, 345))
PAX_KEY = "APK-TOOLS.checksum.SHA1"


def validate_tar(path, raw):
    """Walk every 512-byte header block of a section and refuse anything that Go's archive/tar and Python's tarfile could read differently:
    bytes 345..500 (the ustar prefix, atime/ctime in GNU and V7 headers) must be zero, only plain entry types are allowed, a PAX extended header may carry
    the one key melange writes (APK-TOOLS.checksum.SHA1) and nothing else, GNU long names and global PAX headers are refused, and after the
    end-of-archive blocks every byte must be zero."""
    pos = 0
    entries = 0
    while pos < len(raw):
        blk = raw[pos:pos + 512]
        if len(blk) < 512:
            refuse("%s: a tar section ends inside a header block; refusing" % path)
        if blk.strip(b"\0") == b"":
            if raw[pos:].strip(b"\0") != b"":
                refuse("%s: non-zero bytes after the end-of-archive blocks of a tar section; refusing" % path)
            return entries
        flag = blk[156:157]
        if flag in (b"1", b"2"):
            refuse("%s: a symlink or hard link entry in a tar section; refusing (a name under a link could overwrite another file)" % path)
        for fname, lo, hi in NUMERIC_FIELDS:
            f = blk[lo:hi]
            if f[0:1] >= b"\x80" and fname == "size":
                refuse("%s: a tar header with a base-256 size; refusing" % path)
            if not re.fullmatch(rb" *[0-7]*[\0 ]*", f):
                refuse("%s: the numeric field %s of a tar header is not plain octal (Go and Python read other forms differently); refusing" % (path, fname))
        want = sum(blk[:148]) + 32 * 8 + sum(blk[156:])
        if int(blk[148:156].rstrip(b"\0 ").lstrip(b" ") or b"0", 8) != want:
            refuse("%s: a tar header whose checksum does not match its bytes; refusing" % path)
        if flag == b"\0":
            refuse("%s: a tar header of type NUL (the old-style regular file, which Go and Python read differently); refusing: melange writes only types 0 and 5" % path)
        if flag not in ALLOWED_TYPES and flag != b"x":
            refuse("%s: a tar header of type %r (GNU long name, global PAX header or another type) is not allowed; refusing, Go and Python would read it differently" % (path, flag))
        if blk[345:500].strip(b"\0") != b"":
            refuse("%s: a tar header has bytes in the prefix/atime area (345..500); Go and Python read that area differently; refusing" % path)
        sz_raw = blk[124:136]
        try:
            size = int(sz_raw.rstrip(b"\0 ") or b"0", 8)
        except ValueError:
            refuse("%s: a tar header with an unreadable size field; refusing" % path)
        if flag == b"x":
            body = raw[pos + 512:pos + 512 + size]
            recs = re.findall(rb"(\d+) ([^=\n]+)=([^\n]*)\n", body)
            if not recs or sum(int(n) for n, _, _ in recs) != len(body) or any(k.decode("utf-8", "replace") != PAX_KEY or not re.fullmatch(rb"[0-9a-f]{40}", v) for _, k, v in recs):
                refuse("%s: a PAX extended header may carry only the %s record; refusing (PAX key)" % (path, PAX_KEY))
        elif flag == b"5":
            if size != 0:
                refuse("%s: a directory header with a non-zero size (data under a directory could hide another header); refusing" % path)
        if flag != b"x":
            entries += 1
        pos += 512 + ((size + 511) // 512) * 512
    return entries


def headers(tar_bytes):
    """every tar header of a section, of every type, with its raw name; a malformed tar is refused"""
    want = validate_tar("a tar section", tar_bytes)
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as t:   # a plain tar only: no compression auto-detect
            ms = t.getmembers()
    except tarfile.TarError as e:
        refuse("malformed tar section: %s" % e)
    if len(ms) != want:
        refuse("a tar section has %d entries by the header walk but %d by the tar reader: they read it differently; refusing" % (want, len(ms)))
    return [(m.name, m.type, m) for m in ms]


def members(tar_bytes):
    """name (without a leading ./) -> bytes of the regular files; any name that occurs twice (counting ./x and x as one), of any entry type, is refused:
    a later entry must never shadow an earlier one"""
    out, seen = {}, set()
    want = validate_tar("a tar section", tar_bytes)
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as t:
            if len(t.getmembers()) != want:
                refuse("a tar section has %d entries by the header walk but %d by the tar reader: they read it differently; refusing" % (want, len(t.getmembers())))
            for m in t.getmembers():
                n = norm(m.name)
                c = n.rstrip("/") if m.isdir() else n
                if c.startswith("/") or c == "" or posixpath.normpath(c) != c:
                    refuse("the entry name %r is not canonical (an empty, . or .. component, a doubled slash, or an absolute path: it would extract to the same place as another name); refusing" % m.name)
                if n in seen:
                    refuse("the entry %s occurs twice in a section (a later entry would shadow the first); refusing" % n)
                seen.add(n)
                if m.isfile():
                    out[n] = t.extractfile(m).read()
    except tarfile.TarError as e:
        refuse("malformed tar section: %s" % e)
    return out


def first_block(tar_bytes):
    """name and type flag of the FIRST 512-byte block, exactly as apko reads the first header (Python's tarfile would skip a PAX header)"""
    blk = tar_bytes[:512]
    return blk[:100].split(b"\0", 1)[0].decode("utf-8", "replace"), blk[156:157]


def is_signature_stream(path, tar_bytes):
    """A stream is the signature exactly when the raw name of its first header starts with .SIGN. (apko pkg/apk/expandapk/split.go, melange pkg/sign/apk.go);
    then it must hold that one entry and nothing else, of any type. Any other stream must not hold a .SIGN entry at all, with or without a ./ prefix."""
    raw_name, flag = first_block(tar_bytes)
    # The first header is the signature test. Go's tar reader resolves PAX, GNU long-name and ustar-prefix headers before apko looks at the name, so
    # only a PLAIN header (regular file or NUL type, empty prefix field) is read here: anything else is refused instead of guessed.
    if flag != b"0":
        refuse("%s: the first header of a stream is not a plain file header (type %r: PAX, GNU long name or another type); refusing, apko would read a different first name" % (path, flag))
    if tar_bytes[345:500].strip(b"\0") != b"":
        refuse("%s: the first header has a ustar prefix field; Go joins it onto the name, so the name seen here is not the one apko sees; refusing" % path)
    hdrs = headers(tar_bytes)
    names = [h[0] for h in hdrs]
    if any(n.startswith("./.SIGN.") for n in names):
        refuse("%s: an entry named ./.SIGN.* is not a signature to apko (the first header is compared as written); refusing" % path)
    if raw_name.startswith(".SIGN."):
        if len(hdrs) != 1 or hdrs[0][1] != tarfile.REGTYPE:
            refuse("%s: the signature stream must hold exactly one regular .SIGN entry and nothing else (found %s)" % (path, ", ".join(names) or "nothing"))
        return True
    if any(norm(n).startswith(".SIGN.") for n in names):
        refuse("%s: a section whose first entry is not a .SIGN entry also carries a .SIGN entry; apko and melange would read it as a control or data section (signature confusion)" % path)
    return False


def sections(path):
    """(signature or None, control, data) of an apk. The layout is strict: three streams are signature + control + data (the first MUST be a
    signature), two streams are control + data (the first must NOT be one); anything else is refused, and the control has a .PKGINFO."""
    s = streams(path)
    first_is_sig = is_signature_stream(path, s[0][1])
    for extra in s[1:]:   # the other sections must carry no .SIGN entry either (their first entry may be a directory or carry a PAX record)
        if any(norm(h[0]).startswith(".SIGN.") or h[0].startswith("./.SIGN.") for h in headers(extra[1])):
            refuse("%s: a .SIGN entry outside the first stream; refusing (signature confusion)" % path)
    if len(s) == 3:
        if not first_is_sig:
            refuse("%s has three gzip streams but the first is not a signature (.SIGN.*): an extra stream between control and data is refused" % path)
        sig, ctrl, data = s
    elif len(s) == 2:
        if first_is_sig:
            refuse("%s has two gzip streams and the first is a signature: there is no control section" % path)
        sig, (ctrl, data) = None, s
    else:
        refuse("%s has %d gzip streams; an apk is signature + control + data or control + data" % (path, len(s)))
    if ".PKGINFO" not in members(ctrl[1]):
        refuse("%s: the control section has no .PKGINFO" % path)
    return sig, ctrl, data


def data_digest(path):
    """sha256 over the control and the data section (each length-prefixed): everything melange sign covers except the signature."""
    _, ctrl, data = sections(path)
    h = hashlib.sha256()
    for raw in (ctrl[0], data[0]):
        h.update(len(raw).to_bytes(8, "big") + raw)
    return "sha256:" + h.hexdigest()


def cmd_digest(a):
    print(data_digest(a[0]))


def cmd_same(a):
    if data_digest(a[0]) != data_digest(a[1]):
        refuse("%s has a different control or data section from %s" % (a[1], a[0]), 1)


def _write_new(path, data):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        refuse("cannot create %s: %s" % (path, e))
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def cmd_control(a):
    _, ctrl, _ = sections(a[0])
    _write_new(a[1], ctrl[0])


def cmd_attach_signature(a):
    """the apk with its signature stream replaced: one gzip of a tar with the one member .SIGN.RSA256.release.rsa.pub, then the control and data streams as stored"""
    try:
        sig = open(a[1], "rb").read()
    except OSError as e:
        refuse("cannot read the signature %s: %s" % (a[1], e))
    if not sig:
        refuse("the signature file %s is empty" % a[1])
    _, ctrl, data = sections(a[0])
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w", format=tarfile.GNU_FORMAT) as t:
        i = tarfile.TarInfo(".SIGN.RSA256.release.rsa.pub")
        i.size, i.mtime, i.mode = len(sig), 0, 0o644
        t.addfile(i, io.BytesIO(sig))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(tar.getvalue()[:512 + (len(sig) + 511) // 512 * 512])   # header and data blocks only: apk reads the three streams as ONE tar, so an end-of-archive block here would hide .PKGINFO
    _write_new(a[2], gz.getvalue() + ctrl[0] + data[0])


def cmd_signer(a):
    sig = sections(a[0])[0]
    names = [n for n in members(sig[1])] if sig else []
    if not names:
        print("unsigned")
        return
    if len(names) != 1:
        refuse("%s has %d signature members; exactly one is expected (which one counts?)" % (a[0], len(names)))
    m = re.fullmatch(r"\.SIGN\.RSA(?:256|512)?\.(.+)", names[0])   # melange writes .SIGN.RSA256.<key name>
    if not m:
        refuse("unrecognised signature member %s in %s" % (names[0], a[0]))
    print(m.group(1))


def _openssl():
    """The OpenSSL this check trusts: a fixed location, never whatever the caller's search path holds (REQ-BUILDAPK-001-AC4)."""
    for p in ("/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"):
        if os.access(p, os.X_OK):
            return p
    refuse("openssl is not installed at a fixed location (/usr/bin/openssl)")


def cmd_verify(a):
    """The signer command reads a NAME; this checks the bytes: openssl dgst verifies the member's RSA signature over the control stream exactly as
    stored (REQ-BUILDAPK-001-AC4, AC7). PUBKEY may carry comment lines before its PEM block; the first PUBLIC KEY block is the key."""
    import subprocess, tempfile
    sig, ctrl, data = sections(a[0])
    names = list(members(sig[1])) if sig else []
    if sig and len(sig[1]) != 512 + (int(sig[1][124:136].rstrip(b"\0 ") or b"0", 8) + 511) // 512 * 512:
        refuse("%s: the signature segment has bytes after its one member (end-of-archive blocks): apk-tools reads the signature, control and data streams as one tar and would stop before .PKGINFO; refusing" % a[0], 1)
    if len(names) != 1:
        refuse("%s is %s: nothing to verify" % (a[0], "unsigned" if not names else "signed by %d members" % len(names)), 1)
    m = re.fullmatch(r"\.SIGN\.(RSA|RSA256)\.(.+)", names[0])
    if not m:
        refuse("%s: the signature member %s is not .SIGN.RSA.<name> or .SIGN.RSA256.<name>" % (a[0], names[0]), 1)
    alg = {"RSA": "sha1", "RSA256": "sha256"}[m.group(1)]
    # the signature covers the control stream, whose .PKGINFO names the data stream by its sha256 (datahash): the data is part of what was signed only
    # through that line, so exactly one datahash must be present and must equal the sha256 of the stream as stored
    pkginfo = members(ctrl[1]).get(".PKGINFO", b"").decode("utf-8", "replace")
    dh = re.findall(r"(?m)^datahash\s*=\s*([0-9a-f]{64})\s*$", pkginfo)
    if len(dh) != 1 or len(re.findall(r"(?m)^datahash\b", pkginfo)) != 1:
        refuse("%s: the control section has no single datahash line: the data section is not bound to the signature" % a[0], 1)
    if dh[0] != hashlib.sha256(data[0]).hexdigest():
        refuse("%s: the data section does not match the datahash the signature covers" % a[0], 1)
    try:
        text = open(a[1]).read()
    except (OSError, UnicodeDecodeError) as e:
        refuse("cannot read the public key %s: %s" % (a[1], e))
    pem = re.search(r"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+?-----END PUBLIC KEY-----\n?", text)
    if not pem:
        refuse("%s holds no PEM PUBLIC KEY block" % a[1])
    with tempfile.TemporaryDirectory() as d:
        for n, b in (("key.pem", pem.group(0).encode()), ("sig.bin", members(sig[1])[names[0]]), ("ctrl.bin", ctrl[0])):
            with open(os.path.join(d, n), "wb") as f:
                f.write(b)
        openssl = _openssl()
        try:
            r = subprocess.run([openssl, "dgst", "-" + alg, "-verify", os.path.join(d, "key.pem"), "-signature",
                os.path.join(d, "sig.bin"), os.path.join(d, "ctrl.bin")], capture_output=True, text=True,
                stdin=subprocess.DEVNULL, env={"LC_ALL": "C", "PATH": "/nonexistent"})
        except OSError as e:
            refuse("cannot run openssl: %s" % e)
    if r.returncode != 0 or "Verified OK" not in r.stdout:
        refuse("%s: the signature member %s does not verify against %s" % (a[0], names[0], a[1]), 1)
    print("verified:" + m.group(2))


def member(path, name):
    m = members(sections(path)[2][1])
    return m.get(norm(name))


def cmd_cat(a):
    b = member(a[0], a[1])
    if b is None:
        refuse("%s is not in %s" % (a[1], a[0]))
    sys.stdout.buffer.write(b)


def cmd_binary_check(a):
    b = member(a[0], "usr/bin/fscache")
    if b is None:
        refuse("%s has no usr/bin/fscache" % a[0])
    try:
        f = open(a[1], "rb").read()
    except OSError as e:
        refuse("cannot read %s: %s" % (a[1], e))
    if f != b:
        refuse("%s differs from usr/bin/fscache in %s: sha256 %s vs %s" % (
            a[1], a[0], hashlib.sha256(f).hexdigest(), hashlib.sha256(b).hexdigest()), 1)


def cmd_inputs_manifest(a):
    o = {}
    i = 0
    while i < len(a):
        if a[i] in ("--apk", "--melange-lock", "--out") and i + 1 < len(a):
            o[a[i]] = a[i + 1]; i += 2
        else:
            refuse("unknown or incomplete argument: %s" % a[i])
    if len(o) != 3:
        refuse("usage: inputs-manifest --apk APK --melange-lock FILE --out FILE")
    ctrl = members(sections(o["--apk"])[1][1]).get(".melange.yaml")
    if ctrl is None:
        refuse("%s has no .melange.yaml in its control section" % o["--apk"])
    try:
        env = yaml.safe_load(ctrl)["environment"]["contents"]["packages"]
        if not isinstance(env, list) or not all(isinstance(p, str) for p in env):
            refuse("the build environment in %s lists a package that is not a plain string (a null or a number); refusing" % o["--apk"], 1)
        lock = [l for l in open(o["--melange-lock"]).read().splitlines() if l.strip()]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as e:
        refuse("cannot read the build environment or the lock: %s" % e)
    if not env:
        refuse("the build environment in %s lists no packages: an empty environment proves nothing about the inputs" % o["--apk"], 1)
    missing = sorted(p for p in env if p not in set(lock))
    if missing:
        refuse("the build environment in the apk has packages that are not in the melange lock: " + ", ".join(missing), 1)
    with open(o["--out"], "w") as f:
        json.dump({"melange_lock": sorted(lock), "apk_environment": sorted(env)}, f, indent=1, sort_keys=True)
        f.write("\n")


CMDS = {"digest": (cmd_digest, 1), "same": (cmd_same, 2), "signer": (cmd_signer, 1), "verify": (cmd_verify, 2), "cat": (cmd_cat, 2),
        "control": (cmd_control, 2), "attach-signature": (cmd_attach_signature, 3),
        "binary-check": (cmd_binary_check, 2), "inputs-manifest": (cmd_inputs_manifest, None)}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        refuse("usage: apk-tool.py digest|same|signer|verify|control|attach-signature|cat|binary-check|inputs-manifest ...")
    fn, n = CMDS[sys.argv[1]]
    args = sys.argv[2:]
    if n is not None and len(args) != n:
        refuse("%s takes %d argument(s)" % (sys.argv[1], n))
    fn(args)


main()
