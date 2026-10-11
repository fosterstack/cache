#!/usr/bin/env python3
"""Build's Linux archives (PROPOSED/UNVERIFIED layout, REQ-PLAT-001): the four tar.gz files Release publishes, made from the melange repo's apks.

  build-archives.py --melange-repo DIR --version V --out DIR      (V is the tag minus the leading v; SOURCE_DATE_EPOCH is read from the environment)

DIR/x86_64/ and DIR/aarch64/ each hold one standard apk (fscache-<ver>-r0.apk) and one fips apk (fscache-fips-<ver>-r0.apk). For each variant and
architecture the binary is read with `python3 bin/apk-tool.py cat APK usr/bin/fscache` and written to OUT as goreleaser names the archive:
  fscache_<V>_linux_<amd64|arm64>.tar.gz       holds one file, fscache       (standard)
  fscache-fips_<V>_linux_<amd64|arm64>.tar.gz  holds one file, fscache-fips  (fips)
Layout choice (deterministic): the archive holds only the binary, at the top level, mode 0755, uid/gid 0, no user/group name, mtime =
SOURCE_DATE_EPOCH (0 if unset), ustar format; gzip level 9 with a zero timestamp and no file name. Same apks give the same bytes.
"""
import argparse
import glob
import gzip
import io
import os
import subprocess
import sys
import tarfile

ARCHES = (("x86_64", "amd64"), ("aarch64", "arm64"))
VARIANTS = (("standard", "fscache", "fscache-[0-9]*-r0.apk"), ("fips", "fscache-fips", "fscache-fips-*-r0.apk"))


def refuse(why):
    sys.stderr.write("archives refused: %s\n" % why)
    sys.exit(1)


def find_apk(repo, arch, pattern):
    found = sorted(glob.glob(os.path.join(repo, arch, pattern)))
    if len(found) != 1:
        refuse("%d apks matching %s in %s/%s, exactly one is required" % (len(found), pattern, repo, arch))
    return found[0]


def read_binary(apk):
    r = subprocess.run([sys.executable, "bin/apk-tool.py", "cat", apk, "usr/bin/fscache"], stdout=subprocess.PIPE)
    if r.returncode != 0 or not r.stdout:
        refuse("apk-tool.py cat %s usr/bin/fscache failed (exit %d)" % (apk, r.returncode))
    return r.stdout


def archive_bytes(name, binary, mtime):
    tar = io.BytesIO()
    with tarfile.open(fileobj=tar, mode="w", format=tarfile.USTAR_FORMAT) as t:
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(binary), 0o755, mtime
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        t.addfile(info, io.BytesIO(binary))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, compresslevel=9, mtime=0) as g:
        g.write(tar.getvalue())
    return out.getvalue()


def main(argv):
    p = argparse.ArgumentParser(prog="build-archives.py")
    p.add_argument("--melange-repo", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--out", required=True)
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    sde = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if not sde.isdigit():
        refuse("SOURCE_DATE_EPOCH %r is not digits" % sde)
    os.makedirs(args.out, exist_ok=True)
    for _variant, binary_name, pattern in VARIANTS:
        for arch, goarch in ARCHES:
            binary = read_binary(find_apk(args.melange_repo, arch, pattern))
            path = os.path.join(args.out, "%s_%s_linux_%s.tar.gz" % (binary_name, args.version, goarch))
            with open(path, "wb") as f:
                f.write(archive_bytes(binary_name, binary, int(sde)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
