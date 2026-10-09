#!/usr/bin/env python3
"""Build's version check (REQ-CHAIN-004-AC7): the binary says it is the tag, built from the tagged commit, from a clean tree.

  build-version-check.py (--binary PATH | --apk-dir DIR --variant standard|fips) --tag TAG --sha SHA

With --apk-dir the ONE apk of the variant is found in DIR (standard fscache-<ver>-r0.apk, fips fscache-fips-<ver>-r0.apk; PROPOSED/UNVERIFIED,
cache-3f), usr/bin/fscache is extracted with `python3 bin/apk-tool.py cat APK usr/bin/fscache` to a temporary file, and that file is checked
exactly as --binary is. The build info is read with `go version -m PATH` (the binary is never executed).
Exit 0: version == tag, vcs.revision == SHA, tree not modified. Exit 1: "version check refused at <what>: <why>". Exit 2: usage error.
"""
import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile


class Refusal(Exception):
    def __init__(self, what, why):
        super().__init__("version check refused at %s: %s" % (what, why))


def usage(message):
    sys.stderr.write("usage error: %s\n" % message)
    sys.exit(2)


def parse_args(argv):
    p = argparse.ArgumentParser(prog="build-version-check.py", add_help=True)
    p.add_argument("--binary")
    p.add_argument("--apk-dir")
    p.add_argument("--variant", choices=("standard", "fips"))
    p.add_argument("--tag", required=True)
    p.add_argument("--sha", required=True)
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        sys.exit(2 if e.code else 0)
    if bool(args.binary) == bool(args.apk_dir):
        usage("exactly one of --binary and --apk-dir is required")
    if args.apk_dir and not args.variant:
        usage("--apk-dir needs --variant")
    if args.binary and args.variant:
        usage("--variant belongs to --apk-dir")
    return args


def find_apk(apk_dir, variant):
    pattern = "fscache-fips-*-r0.apk" if variant == "fips" else "fscache-[0-9]*-r0.apk"
    found = sorted(glob.glob(os.path.join(apk_dir, pattern)))
    if len(found) != 1:
        raise Refusal("apk", "%d %s apks in %s, exactly one is required" % (len(found), variant, apk_dir))
    return found[0]


def extract_binary(apk, dest):
    r = subprocess.run([sys.executable, "bin/apk-tool.py", "cat", apk, "usr/bin/fscache"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0 or not r.stdout:
        raise Refusal("apk", "apk-tool.py cat %s usr/bin/fscache failed (exit %d)" % (apk, r.returncode))
    with open(dest, "wb") as f:
        f.write(r.stdout)


def build_info(binary):
    try:
        r = subprocess.run(["go", "version", "-m", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, GOTOOLCHAIN="local"))
    except OSError as e:
        raise Refusal("buildinfo", "cannot run go: %s" % e)
    if r.returncode != 0:
        raise Refusal("buildinfo", "go version -m failed (exit %d)" % r.returncode)
    return r.stdout.decode("utf-8", "replace")


def fields_of(text):
    """Tab-indented lines of `go version -m`: [(kind, rest of fields)], in order."""
    out = []
    for line in text.splitlines():
        if line.startswith("\t"):
            parts = line.strip().split("\t")
            out.append((parts[0], parts[1:]))
    return out


def check_info(text, tag, sha):
    fields = fields_of(text)
    mods = [f for k, f in fields if k == "mod"]
    if len(mods) != 1:
        raise Refusal("mod", "%d main-module lines, exactly one is required" % len(mods))
    version = mods[0][1].strip() if len(mods[0]) > 1 else ""
    if version == "(devel)":
        raise Refusal("devel", "the embedded module version is (devel)")
    if version != tag:
        raise Refusal("version", "embedded %r, tag %r" % (version, tag))
    build = [f[0] for k, f in fields if k == "build" and f]
    revisions = [b[len("vcs.revision="):] for b in build if b.startswith("vcs.revision=")]
    if len(revisions) != 1 or not revisions[0]:
        raise Refusal("revision", "%d vcs.revision lines (or an empty one), exactly one is required" % len(revisions))
    if revisions[0] != sha:
        raise Refusal("revision", "embedded %r, tagged commit %r" % (revisions[0], sha))
    modified = [b[len("vcs.modified="):] for b in build if b.startswith("vcs.modified=")]
    if modified != ["false"]:
        raise Refusal("modified", "vcs.modified is %r, the tree must be clean" % modified)


def main(argv):
    args = parse_args(argv)
    try:
        if args.binary:
            check_info(build_info(args.binary), args.tag, args.sha)
        else:
            apk = find_apk(args.apk_dir, args.variant)
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "fscache")
                extract_binary(apk, path)
                check_info(build_info(path), args.tag, args.sha)
    except Refusal as e:
        sys.stderr.write("%s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
