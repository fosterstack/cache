#!/usr/bin/env bash
# apko lock-file checks used by the image build (v0.3.0 rules 27, 28, 29, 33, 37, 44).
#
#   apko-lock.sh compare BASE FULL --apk NAME
#       Rule 37. FULL (made at build time) must equal BASE plus our apk: compared by sorted package entries (name,
#       version, architecture, control/data/signature checksums); url order and the config checksum are ignored.
#       exit 0 equal | 1 differs (names the package or the arch) | 2 refused (BASE already holds our apk, bad input)
#   apko-lock.sh arch-check LOCK
#       Rule 33. Every package resolves to the same version on every architecture in LOCK.
#       exit 0 | 1 a package differs between architectures, or is locked for one only (names it) | 2 bad input, including a lock that does not
#       cover exactly x86_64 and aarch64
#   apko-lock.sh verify-archive --lock L --archive DIR [--melange-repo DIR]
#       Rules 27, 28, 44. Every package of L is in DIR/<arch>/<name>-<version>.apk (or, for our apk, in the melange
#       repo) and its signature, control and data sections match the lock's checksums; every repository used has its
#       APKINDEX.tar.gz. No network.   exit 0 | 1 missing, tampered or no index (names the file) | 2 bad input
#   apko-lock.sh evidence --lock L --archive DIR --out DIR
#       Rule 29. Copies L to OUT/ and writes OUT/archive-checksums.txt: a sha256sum-format list ("<hex>  <path>", paths
#       relative to DIR, byte-sorted) of every file in the archive (packages, indexes, the Wolfi key, the Go tarballs).
#       exit 0 | 1 a package of L is not in the archive (names it) or the archive is unreadable | 2 bad input
set -euo pipefail
exec python3 - "$@" <<'PY'
import base64, hashlib, json, os, re, shutil, sys

ARCH_ERR = 2


class Check(ValueError):
    pass


def ok(cond):
    """an explicit check (python -O would drop an assert)"""
    if not cond:
        raise Check("check failed")


def die(msg, code=1):
    print("apko-lock.sh: " + msg, file=sys.stderr)
    sys.exit(code)


def load(path):
    try:
        d = json.load(open(path))
        pk = d["contents"]["packages"]
        ok(d.get("version") == "v1" and isinstance(pk, list))
    except (OSError, ValueError, KeyError) as e:
        die("cannot read lock file %s: %s" % (path, e), 2)
    for i, e in enumerate(pk):
        try:
            ok(all(isinstance(e[k], str) and e[k] for k in ("name", "version", "architecture")))
            ok(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", e["name"]) and ".." not in e["name"])
            ok(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]*", e["version"]) and ".." not in e["version"])
            ok(re.fullmatch(r"[a-z0-9_]+", e["architecture"]))
            ok(all(isinstance(e[p]["checksum"], str) for p in ("control", "data")))
        except (KeyError, TypeError, ValueError):
            die("malformed lock entry %d in %s (%s): name, version, architecture and the control and data checksums are required" % (i, path, e.get("name", "?") if isinstance(e, dict) else "?"), 2)
    return d, pk


def key(e):
    sig = (e.get("signature") or {}).get("checksum", "")
    return (e["name"], e["version"], e["architecture"], e["control"]["checksum"], e["data"]["checksum"], sig, e.get("checksum", ""))


def b64(raw): return base64.b64encode(raw).decode()


def opts(argv, names):
    out, i = {}, 0
    while i < len(argv):
        if argv[i] in names and i + 1 < len(argv):
            out[argv[i]] = argv[i + 1]; i += 2   # a repeated flag: the last one wins
        else:
            die("unknown or incomplete argument: %s" % argv[i], 2)
    return out


def compare(argv):
    if len(argv) < 2:
        die("usage: compare BASE FULL --apk NAME", 2)
    base_p, full_p, o = argv[0], argv[1], opts(argv[2:], ("--apk",))
    apk = o.get("--apk") or die("--apk NAME is required", 2)
    _, bpk = load(base_p)
    _, fpk = load(full_p)
    if any(e["name"] == apk for e in bpk):
        die("the base lock %s already holds %s; the base lock must not hold our apk" % (base_p, apk), 2)
    ours = [e for e in fpk if e["name"] == apk]
    if not ours:
        die("the full lock has no entry for our apk %s" % apk)
    archs = sorted({e["architecture"] for e in bpk})
    for a in archs:
        n = sum(1 for e in ours if e["architecture"] == a)
        if n == 0:
            die("our apk %s is missing for architecture %s in the full lock" % (apk, a))
        if n != 1:
            die("the full lock has %d entries for our apk %s on %s; exactly one is expected" % (n, apk, a))
    extra = sorted({e["architecture"] for e in ours} - set(archs))
    if extra:
        die("the full lock holds our apk %s for architecture(s) %s that the base lock does not have" % (apk, ", ".join(extra)))
    if len({e["version"] for e in ours}) != 1:
        die("the full lock holds our apk %s at more than one version" % apk)
    rest = {key(e) for e in fpk if e["name"] != apk}
    base = {key(e) for e in bpk}
    msgs = []
    for k in sorted(base - rest):
        msgs.append("%s %s (%s) is in the base lock but not, or not identically, in the full lock" % (k[0], k[1], k[2]))
    for k in sorted(rest - base):
        msgs.append("%s %s (%s) is in the full lock but not, or not identically, in the base lock" % (k[0], k[1], k[2]))
    if msgs:
        die("the full lock is not the base lock plus %s:\n  %s" % (apk, "\n  ".join(msgs)))


def arch_check(argv):
    if len(argv) != 1:
        die("usage: arch-check LOCK", 2)
    _, pk = load(argv[0])
    archs = {e["architecture"] for e in pk}
    if archs != {"x86_64", "aarch64"}:
        die("the lock must cover exactly the architectures x86_64 and aarch64; it covers %s" % (", ".join(sorted(archs)) or "none"), ARCH_ERR)
    per = {}
    for e in pk:
        per.setdefault(e["name"], {}).setdefault(e["architecture"], set()).add(e["version"])
    bad = []
    for n, by_arch in sorted(per.items()):
        vers = {a: v for a, v in by_arch.items()}
        if set(vers) != archs:
            bad.append("%s is locked for %s only" % (n, ", ".join(sorted(vers))))
        elif any(len(v) != 1 for v in vers.values()) or len({next(iter(v)) for v in vers.values()}) != 1:
            bad.append("%s resolves to different or several versions (%s)" % (n, "; ".join("%s: %s" % (a, ",".join(sorted(v))) for a, v in sorted(vers.items()))))
    if bad:
        die("these packages do not resolve identically on both architectures: " + "; ".join(bad), 1)


def verify_apk(path, e):
    """Every byte of the apk must be covered by the lock: contiguous signature (optional, Wolfi's apks have none), control and data
    ranges that end exactly at the end of the file, each with its checksum, and the data stream hashes to the datahash in the control."""
    raw = open(path, "rb").read()
    fname = os.path.basename(path)
    spans = []
    for part in ("signature", "control", "data"):
        p = e.get(part) or {}
        if not p.get("range"):
            if part == "signature":
                continue
            die("%s: the lock has no %s range; an entry with nothing to check is not accepted" % (fname, part))
        m = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", p["range"])
        kind, _, want = p.get("checksum", "").partition("-")
        if not m or kind not in ("sha1", "sha256"):
            die("%s: cannot read the %s range or checksum in the lock" % (fname, part))
        lo, hi = int(m.group(1)), int(m.group(2))
        got = b64(getattr(hashlib, kind)(raw[lo:hi + 1]).digest())
        if got != want:
            die("%s: %s section does not match the lock (%s-%s, lock says %s-%s)" % (fname, part, kind, got, kind, want))
        spans.append((part, lo, hi))
    pos = 0
    for part, lo, hi in spans:
        if lo != pos:
            die("%s: the %s range starts at byte %d but the previous section ends at %d; the lock's ranges must be contiguous" % (fname, part, lo, pos))
        pos = hi + 1
    if pos != len(raw):
        die("%s: the lock's ranges end at byte %d but the file has %d bytes; bytes after the last range (or a short file) are not accepted: size/length mismatch, the end of the file is not covered" % (fname, pos, len(raw)))
    ctl = [(n, lo, hi) for n, lo, hi in spans if n == "control"][0]; dat = [(n, lo, hi) for n, lo, hi in spans if n == "data"][0]
    try:
        import io, tarfile, zlib
        pk = tarfile.open(fileobj=io.BytesIO(zlib.decompressobj(31).decompress(raw[ctl[1]:ctl[2] + 1], 16 * 1024 * 1024))).extractfile(".PKGINFO").read().decode()
        dhs = re.findall(r"^datahash = ([0-9a-f]{64})$", pk, re.M)
        ok(len(dhs) == 1)
        dh = dhs[0]
    except Exception:
        die("%s: the control section has no readable .PKGINFO datahash (exactly one datahash line is required)" % fname)
    if hashlib.sha256(raw[dat[1]:dat[2] + 1]).hexdigest() != dh:
        die("%s: the data stream does not hash to the datahash in its control section" % fname)


def verify_archive(argv):
    o = opts(argv, ("--lock", "--archive", "--melange-repo"))
    if "--lock" not in o or "--archive" not in o:
        die("usage: verify-archive --lock L --archive DIR [--melange-repo DIR]", 2)
    _, pk = load(o["--lock"])
    repos = [o["--archive"]] + ([o["--melange-repo"]] if "--melange-repo" in o else [])
    used = set()
    for e in sorted(pk, key=lambda e: (e["architecture"], e["name"], e["version"])):
        rel = "%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])
        for r in repos:
            if os.path.isfile(os.path.join(r, rel)):
                verify_apk(os.path.join(r, rel), e)
                used.add((r, e["architecture"]))
                break
        else:
            die("%s is not in the archive%s (needed by the lock)" % (rel, " or the melange repository" if len(repos) > 1 else ""))
    for r, a in sorted(used):
        ix = os.path.join(r, a, "APKINDEX.tar.gz")
        if not os.path.isfile(ix):
            die("%s/%s/APKINDEX.tar.gz is missing; assembly needs the package index" % (r, a))
        if os.path.getsize(ix) == 0:
            die("%s/%s/APKINDEX.tar.gz is empty; assembly needs the package index" % (r, a))


def evidence(argv):
    o = opts(argv, ("--lock", "--archive", "--out"))
    if not all(k in o for k in ("--lock", "--archive", "--out")):
        die("usage: evidence --lock L --archive DIR --out DIR", 2)
    _, pk = load(o["--lock"])
    if not os.path.isdir(o["--archive"]):
        die("the archive %s is not a directory" % o["--archive"])
    for e in pk:   # evidence of a release must describe an archive that holds everything the lock needs
        rel = "%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])
        if not os.path.isfile(os.path.join(o["--archive"], rel)):
            die("%s is in the lock but not in the archive" % rel)
    os.makedirs(o["--out"], exist_ok=True)
    shutil.copyfile(o["--lock"], os.path.join(o["--out"], os.path.basename(o["--lock"])))
    rows = []
    for root, _, files in os.walk(o["--archive"]):
        for f in files:
            p = os.path.join(root, f)
            rows.append((os.path.relpath(p, o["--archive"]).replace(os.sep, "/"), hashlib.sha256(open(p, "rb").read()).hexdigest()))
    if not rows:
        die("the archive %s is empty" % o["--archive"])
    with open(os.path.join(o["--out"], "archive-checksums.txt"), "w") as f:
        for p, h in sorted(rows, key=lambda r: r[0].encode()):
            f.write("%s  %s\n" % (h, p))


def main():
    cmds = {"compare": compare, "arch-check": arch_check, "verify-archive": verify_archive, "evidence": evidence}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        die("usage: apko-lock.sh compare|arch-check|verify-archive|evidence ...", 2)
    cmds[sys.argv[1]](sys.argv[2:])


try:
    main()
except (KeyError, TypeError, AttributeError) as exc:
    die("malformed lock entry (missing or mistyped key %s)" % exc, 2)
PY
