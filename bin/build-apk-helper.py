#!/usr/bin/env python3
"""The three pieces of the apk build driver that were inline Python or a hand-built environment, as one listed file (advisor
ruling Oct 12, handoff 0393: the release chain's judge admits no inline Python, no assignment of a protected variable and no
interpreter run on a variable path).

  build-apk-helper.py build-date EPOCH
      prints EPOCH (digits) as an ISO 8601 UTC time (2026-09-21T00:59:40Z); exit 1 when it is not a date.
  build-apk-helper.py recipe-facts RECIPE GOARCH OUTFILE
      writes name=, file=, sha= (this architecture's toolchain fetch) and one pin= line per pinned build package; exit 1 when the
      recipe cannot be read or has not exactly one such fetch for GOARCH.
  build-apk-helper.py sealed-env DATAFILE
      prints the closed list of the privileged melange call's variables as NAME=value items, each ended by a NUL byte: the entries
      of DATAFILE's "closed", then each of its "from_environment" names read from this process (exit 1 when one is missing).
      Nothing else is ever passed: there is no test mode, no inherited name and no prefix rule (REQ-BUILDAPK-001-AC3). DATAFILE is read as a
      closed object: any other key or value type is refused (exit 1).

  build-apk-helper.py fips-module FILE
      prints GOFIPS140=<the module id that FILE (build/locks/fips-module.txt) holds>, read with the grammar the daily refresh reads it with: plain
      ASCII, exactly one line vMAJOR.MINOR.PATCH-<8 lower-case hex> (no leading zeros) and a plain newline; exit 1 for anything else
      (REQ-BUILDAPK-001-AC4).

  build-apk-helper.py sealed-call ARG...
      judges the argument list of the privileged melange call, as the driver will run it after `sudo` (sandboxed-build ratify Oct 27 2026, rule 2): `env -i`, then
      NAME=value items only, then `unshare -n`, then melange, then `build` with exactly one `--runner` and its value `bubblewrap`. Prints the first reason on standard
      error and exits 1 for anything else (a call without the bubblewrap runner, without the cut network namespace, or with an environment that is not closed).

Exit codes: 0 ok | 1 failed | 2 usage.
"""
import datetime
import json
import os
import re
import stat
import sys


def build_date(epoch):
    if not epoch.isdigit() or len(epoch) > 12:
        return 1
    try:
        t = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return 1
    print(t.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return 0


def recipe_facts(recipe, goarch, outfile):
    import yaml
    try:
        d = yaml.safe_load(open(recipe))
        name = d["package"]["name"]
        fetches = [s["with"] for s in d.get("pipeline", []) if s.get("uses") == "fetch" and ("linux-%s." % goarch) in s["with"]["uri"]]
        if len(fetches) != 1:
            return 1
        pins = [str(p) for p in d["environment"]["contents"]["packages"]]
        with open(outfile, "w") as f:
            f.write("name=%s\nfile=%s\nsha=%s\n" % (name, fetches[0]["uri"].rsplit("/", 1)[1], fetches[0]["expected-sha256"]))
            f.write("".join("pin=%s\n" % p for p in pins))
    except (OSError, KeyError, TypeError, AttributeError, yaml.YAMLError):
        return 1
    return 0


def sealed_env(datafile):
    try:
        d = json.load(open(datafile))
        keys = {"closed", "from_environment"}
        if not isinstance(d, dict) or set(d) != keys:
            return 1
        fixed = d["closed"]
        if not isinstance(fixed, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in fixed.items()):
            return 1
        for k in keys - {"closed"}:
            if not isinstance(d[k], list) or not all(isinstance(x, str) for x in d[k]):
                return 1
    except (OSError, ValueError):
        return 1
    out = ["%s=%s" % kv for kv in fixed.items()]
    for name in d["from_environment"]:
        if name not in os.environ:
            return 1
        out.append("%s=%s" % (name, os.environ[name]))
    sys.stdout.buffer.write(b"".join(x.encode() + b"\0" for x in out))
    return 0


def fips_module(path):
    try:
        # open without following a symlink, take the handle's own word that it is a regular file, and read THAT handle: the shell pre-check of the
        # path cannot be raced between its test and this open (O_NONBLOCK so a fifo cannot hang the open)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return 1
            raw = os.read(fd, 4097).decode("ascii")   # one byte over the longest line the grammar could ever allow: a longer file is refused, never cut
            if len(raw) > 4096:
                return 1
        finally:
            os.close(fd)
    except (OSError, UnicodeDecodeError):
        return 1
    num = r"(?:0|[1-9][0-9]*)"
    if not raw.endswith("\n") or raw.count("\n") != 1 or not re.fullmatch(r"v%s\.%s\.%s-[0-9a-f]{8}" % (num, num, num), raw[:-1]):
        return 1
    sys.stdout.write("GOFIPS140=" + raw[:-1])
    return 0


def sealed_call(call):
    """None when the call is the sealed one, else the first reason."""
    if len(call) < 6 or os.path.basename(call[0]) != "env" or call[1] != "-i":
        return "the call does not start with env -i"
    i = 2
    while i < len(call) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", call[i], re.S):
        i += 1
    if i + 3 >= len(call) or os.path.basename(call[i]) != "unshare" or call[i + 1] != "-n":
        return "the call is not run under unshare -n (the network namespace is not cut)"
    if os.path.basename(call[i + 2]) != "melange" or call[i + 3] != "build":
        return "the program under unshare -n is not melange build"
    args = call[i + 4:]
    runners = [k for k, a in enumerate(args) if a == "--runner" or a.startswith("--runner=")]
    if len(runners) != 1 or args[runners[0]] != "--runner" or runners[0] + 1 >= len(args) or args[runners[0] + 1] != "bubblewrap":
        return "melange is not run with exactly one --runner bubblewrap"
    return None


def main(argv):
    if len(argv) >= 3 and argv[1] == "sealed-call":
        why = sealed_call(argv[2:])
        if why:
            print(why, file=sys.stderr)
            return 1
        return 0
    if len(argv) == 3 and argv[1] == "build-date":
        return build_date(argv[2])
    if len(argv) == 5 and argv[1] == "recipe-facts":
        return recipe_facts(argv[2], argv[3], argv[4])
    if len(argv) == 3 and argv[1] == "sealed-env":
        return sealed_env(argv[2])
    if len(argv) == 3 and argv[1] == "fips-module":
        return fips_module(argv[2])
    print("usage: build-apk-helper.py build-date EPOCH | recipe-facts RECIPE GOARCH OUTFILE | sealed-env DATAFILE | sealed-call ARG... | fips-module FILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
