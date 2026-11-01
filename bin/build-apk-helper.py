#!/usr/bin/env python3
"""The three pieces of the apk build driver that were inline Python or a hand-built environment, as one listed file (advisor
ruling Oct 12, handoff 0393: the release chain's judge admits no inline Python, no assignment of a protected variable and no
interpreter run on a variable path).

  build-apk-helper.py recipe-facts RECIPE GOARCH OUTFILE
      writes name=, file=, sha= (this architecture's toolchain fetch) and one pin= line per pinned build package; exit 1 when the
      recipe cannot be read or has not exactly one such fetch for GOARCH.
  build-apk-helper.py sealed-env DATAFILE
      prints the closed list of the privileged melange call's variables as NAME=value items, each ended by a NUL byte: the entries
      of DATAFILE's "closed", then each of its "from_environment" names read from this process (exit 1 when one is missing).
      Nothing else is ever passed: there is no test mode, no inherited name and no prefix rule (REQ-BUILDAPK-001-AC3). DATAFILE is read as a
      closed object: any other key or value type is refused (exit 1).


  build-apk-helper.py sealed-call [--sealed-env FILE] ARG...
      judges the argument list of the privileged melange call, as the driver will run it with raised rights
      (sandboxed-build ratify Oct 27 2026, rule 2): an ABSOLUTE `env` and
      `-i`, then NAME=value items only (with --sealed-env: exactly the items FILE yields, in order), then an absolute
      `unshare -n`, then an absolute melange and `build`, the
      recipe file, and only the options of MELANGE_FLAGS, each once with one value, `--runner` being `bubblewrap` and
      `--namespace` being `fosterstack`.
      Prints the first reason on standard error and exits 1 for
      anything else (a call without the bubblewrap runner, without the cut network namespace, with a bare program name,
      another option or an environment that is not the file's).

  The other subcommands are the decisions the build driver makes, so that its script is straight-line text. Each prints
  its answer or the refusal "<script name>: <reason>" on standard error and exits with the status the script had for
  that refusal:
  check-args UNAME_S UNAME_M ARG...     the host, the options, the environment and the inputs; prints "sde" or "build"
    (exit 2 refused)
  arg NAME ARG...                       one value of the options (src variant arch goarch version apkver build-date
    repo keyring
                                        go-archive melange-lock out render-dir apk-cache-dir); a directory is printed
                                        absolute
  abs-file FILE                         FILE as an absolute path
  exclude-file EXCLUDE_FILE DIR         adds the job's nine paths to the checkout's exclude file, each once
                                        (exit 1 refused)
  melange-verdict RC PROBE              the status of the melange call (and of the network probe, empty if none ran):
    0, 1 or 4
  check-buildinfo FILE VERSION          the binary is stamped, clean, and carries the version being built (exit 1
    refused)
  check-revision FILE HEAD VARIANT MODULEFILE   the binary's revision is the source HEAD; the GOFIPS140 records fit the
    variant
  go-verdict RC GOOUT BUILDINFO GOERR   buildinfo.txt is the binary's own go version -m output (RC is the go tool's
    exit status)

Exit codes: 0 ok | 1 failed | 2 usage.
"""
import datetime
import json
import os
import re
import stat
import sys


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


def sealed_env_items(datafile):
    """The NAME=value items of the closed list (None when the file is refused): the fixed items, then each named
    variable of the environment."""
    try:
        d = json.load(open(datafile))
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or set(d) != {"closed", "from_environment"}:
        return None
    fixed, names = d["closed"], d["from_environment"]
    if not isinstance(fixed, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in fixed.items()):
        return None
    if not isinstance(names, list) or not all(isinstance(x, str) for x in names):
        return None
    out = ["%s=%s" % kv for kv in fixed.items()]
    for name in names:
        if name not in os.environ:
            return None
        out.append("%s=%s" % (name, os.environ[name]))
    return out


def sealed_env(datafile):
    out = sealed_env_items(datafile)
    if out is None:
        return 1
    sys.stdout.buffer.write(b"".join(x.encode() + b"\0" for x in out))
    return 0


def read_fips_module(path):
    """GOFIPS140=<the module id> read from the file, or None when the file or its grammar is refused."""
    try:
        # open without following a symlink, take the handle's own word that it is a regular file, and read THAT handle:
        # check_revision's isfile and islink test of the
        # path cannot be raced between that test and this open (O_NONBLOCK so a fifo cannot hang the open)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            raw = os.read(fd, 4097).decode("ascii")   # one byte over the longest line the grammar could ever allow: a longer file is refused, never cut
            if len(raw) > 4096:
                return None
        finally:
            os.close(fd)
    except (OSError, UnicodeDecodeError):
        return None
    num = r"(?:0|[1-9][0-9]*)"
    if not raw.endswith("\n") or raw.count("\n") != 1 or not re.fullmatch(r"v%s\.%s\.%s-[0-9a-f]{8}" % (num, num, num), raw[:-1]):
        return None
    return "GOFIPS140=" + raw[:-1]


# the closed set of the driver's melange call, each once, each with one value
MELANGE_FLAGS = ("--arch", "--runner", "--namespace", "--signing-key", "--keyring-append", "--repository-append",
    "--build-date", "--cache-dir", "--source-dir", "--out-dir", "--apk-cache-dir")


def sealed_call(call, expected_env=None):
    """None when the call is the sealed one, else the first reason. expected_env: the NAME=value items the sealed
    environment file yields, in order (None: only their form is judged)."""
    if len(call) < 6 or os.path.basename(call[0]) != "env" or not os.path.isabs(call[0]) or call[1] != "-i":
        return "the call does not start with an absolute path to env and -i"
    i = 2
    while i < len(call) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", call[i], re.S):
        i += 1
    if expected_env is not None and call[2:i] != expected_env:
        return "the environment of the call is not exactly the items of the sealed environment file"
    if (i + 3 >= len(call) or os.path.basename(call[i]) != "unshare" or not os.path.isabs(call[i])
            or call[i + 1] != "-n"):
        return "the call is not run under an absolute unshare -n (the network namespace is not cut)"
    if os.path.basename(call[i + 2]) != "melange" or not os.path.isabs(call[i + 2]) or call[i + 3] != "build":
        return "the program under unshare -n is not an absolute path to melange build"
    args = call[i + 4:]
    if not args or args[0].startswith("-"):
        return "melange build is not given the recipe file first"
    seen, k = {}, 1
    while k < len(args):
        flag = args[k]
        if flag not in MELANGE_FLAGS:
            return "melange option %r is not one of the sealed call's options" % flag
        if flag in seen:
            return "melange option %s is given twice" % flag
        if k + 1 >= len(args) or args[k + 1].startswith("-"):
            return "melange option %s has no value" % flag
        seen[flag] = args[k + 1]
        k += 2
    if seen.get("--runner") != "bubblewrap":
        return "melange is not run with exactly one --runner bubblewrap"
    if seen.get("--namespace") != "fosterstack":
        return "melange is not given --namespace fosterstack (the supplier and package URL of the apk's SBOM)"
    if seen.get("--arch") not in ("x86_64", "aarch64"):
        return "melange is not given --arch x86_64 or aarch64"
    return None


# ---- the decisions of the build driver: each one prints its answer, or raises Refused with the old message and exit
# status ----

PREFIX = "build-apk.sh: "
VALUE_OPTIONS = ("--variant", "--arch", "--version", "--source-dir", "--repo", "--keyring", "--go-archive",
    "--melange-lock",
                 "--out", "--render-dir", "--apk-cache-dir")
EXCLUDE_PATHS = ("/archive/", "/host-tools/", "/out/", "/witness-apk/", "/admission.json", "/build-in/",
    "/witness-build/",
                 "/witness-rapk/", "/policy.json")
PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
VERSION_GRAMMAR = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc[1-9][0-9]*)?"   # X.Y.Z or X.Y.Z-rcN


class Refused(Exception):
    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def iso_time(epoch):
    """EPOCH (digits) as an ISO 8601 UTC time, or None when it is not a date."""
    if not re.fullmatch(r"[0-9]{1,12}", epoch):
        return None
    try:
        return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def parse_options(args, allowed=None):
    """The options of the build driver as a dict without the leading dashes; the last of a repeated option wins.
    allowed: the value options this driver takes (the base-layout driver takes fewer); only the apk driver also takes
    --print-source-date-epoch."""
    opts = {}
    i = 0
    while i < len(args):
        word = args[i]
        if word == "--print-source-date-epoch" and allowed is None:
            opts[word[2:]] = "1"
            i += 1
        elif word == "--signing-key":
            raise Refused("--signing-key is not accepted: the apk is signed with the committed assembly key only")
        elif word in (VALUE_OPTIONS if allowed is None else allowed):
            if i + 1 >= len(args):
                raise Refused("missing value for " + word)
            opts[word[2:]] = args[i + 1]
            i += 2
        else:
            raise Refused("unknown argument: " + word)
    return opts


def check_args(uname_s, uname_m, *args):
    """Every refusal that comes before a tool runs, in the order the script made them. Prints sde or build."""
    if uname_s != "Linux":
        raise Refused("refusing to run on %s: this script uses sudo, unshare and the sealed build tools, which run on "
            "Linux "
                      "only (inside a Linux container or on a GitHub runner), never on the Mac itself" % uname_s)
    opts = parse_options(args)
    src = opts.get("source-dir", "")
    if not src:
        raise Refused("--source-dir is required")
    if "print-source-date-epoch" in opts:
        if not os.path.exists(src + "/.git"):
            raise Refused("%s has no .git; there is no commit time to print" % src)
        return "sde"
    check_variant_arch_version(uname_m, opts)
    check_environment()
    check_inputs(opts)
    return "build"


def check_variant_arch_version(uname_m, opts):
    arch = opts.get("arch", "")
    version = opts.get("version", "")
    if opts.get("variant") not in ("standard", "fips"):
        raise Refused("--variant must be standard or fips")
    if arch not in ("x86_64", "aarch64"):
        raise Refused("--arch must be an apk architecture name: x86_64 or aarch64 (not '%s')" % arch)
    host = {"amd64": "x86_64", "arm64": "aarch64"}.get(uname_m, uname_m)
    if arch != host:
        raise Refused("refusing to build %s on a %s host: each architecture builds natively on its own runner, no "
            "emulation"
                      % (arch, host))
    # exactly the chain's grammar (the tag minus its v) and the one fixed snapshot version (REQ-CHAIN-004-AC12)
    if not (re.fullmatch(VERSION_GRAMMAR, version) or version == "0.0.0-rc.1"):
        raise Refused("--version must be X.Y.Z, X.Y.Z-rcN or the snapshot version 0.0.0-rc.1 "
                      "(numbers without leading zeros; not '%s')" % version)


def check_environment():
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not re.fullmatch(r"[0-9]{1,12}", epoch):
        raise Refused("SOURCE_DATE_EPOCH must hold digits (the commit time, at most 12 digits)")
    if iso_time(epoch) is None:
        raise Refused("SOURCE_DATE_EPOCH %s is not a date" % epoch)
    if os.environ.get("APK_RELEASE_SIGNING_KEY"):
        raise Refused("the release signing key must not be in a build's environment (APK_RELEASE_SIGNING_KEY is "
            "defined)")
    if os.environ.get("GOPROXY", "off") != "off":
        raise Refused("GOPROXY must be off or unset (its value is not printed: it can carry a credential)")
    for name in PROXY_NAMES:
        if os.environ.get(name):
            raise Refused("a proxy is defined in the environment (%s); the sealed build has no network" % name)


def check_inputs(opts):
    repo = opts.get("repo")
    keyring = opts.get("keyring", "")
    src = opts["source-dir"]
    if repo is None:
        raise Refused("--repo DIR (the local package repository melange installs the build tools from) is required; "
                      "a cache alone is not an input")
    if "://" in repo:
        raise Refused("--repo must be a local directory, not an address (%s)" % repo)
    if not os.path.isdir(repo):
        raise Refused("--repo %s is not a directory" % repo)
    if not keyring or not os.path.isfile(keyring):
        raise Refused("--keyring file not found: " + keyring)
    if not opts.get("go-archive"):
        raise Refused("--go-archive DIR is required")
    melange_lock = opts.get("melange-lock", "")
    if not melange_lock or not os.path.isfile(melange_lock):
        raise Refused("--melange-lock file not found: " + melange_lock)
    if not opts.get("out"):
        raise Refused("--out DIR is required")
    if not os.path.isdir(src + "/vendor"):
        raise Refused("%s/vendor is missing: the build uses only vendored Go code" % src)
    if not os.path.exists(src + "/.git"):
        raise Refused("%s has no .git: the binary's stamp would say (devel)" % src)


def abs_dir_if_there(value):
    """A directory that exists as an absolute path; anything else as it was typed."""
    return os.path.abspath(value) if os.path.isdir(value) else value


def arg(name, *args):
    """One value of the options, as the script uses it."""
    opts = parse_options(args)
    version = opts.get("version", "")
    if name in ("variant", "arch", "version"):
        return opts.get(name, "")
    if name == "goarch":
        return "arm64" if opts.get("arch") == "aarch64" else "amd64"
    if name == "apkver":   # the apk version syntax of a pre-release: 0.3.0-rc1 -> 0.3.0_rc1, 0.0.0-rc.1 -> 0.0.0_rc1
        return version.replace("-rc.", "_rc", 1).replace("-rc", "_rc", 1)
    if name == "build-date":
        return iso_time(os.environ.get("SOURCE_DATE_EPOCH", "")) or ""
    if name in ("keyring", "melange-lock"):
        return abs_file(opts.get(name, ""))
    if name in ("out", "render-dir"):   # made by the script next: absolute even while it does not exist
        return os.path.abspath(opts[name]) if opts.get(name) else ""
    if name in ("src", "repo", "go-archive", "apk-cache-dir"):
        return abs_dir_if_there(opts.get("source-dir" if name == "src" else name, ""))
    raise Refused("unknown value name " + name, 2)


def abs_file(path):
    return os.path.abspath(path) if path else ""


def exclude_file(excl, exdir):
    """Adds the job's own paths to the checkout's exclude file: each once, the lines already there kept in front."""
    if not os.path.isdir(exdir) or os.path.isdir(excl):
        raise Refused("the exclude file %s cannot be used: its directory %s is not a directory, "
                      "or the exclude path itself is a directory" % (excl, exdir), 1)
    old = b""
    try:
        if os.path.exists(excl):
            with open(excl, "rb") as f:
                old = f.read()
        lines = old.split(b"\n")
        missing = [path for path in EXCLUDE_PATHS if path.encode() not in lines]
        if missing:
            # a last line with no newline would swallow the pattern
            glue = b"\n" if old and not old.endswith(b"\n") else b""
            with open(excl, "ab") as f:
                f.write(glue + "".join(path + "\n" for path in missing).encode())
    except OSError as e:
        raise Refused("cannot update the exclude file %s: %s" % (excl, e.strerror), 1)


def melange_verdict(rc, probe):
    """rc: the exit status of the sealed melange call; probe: the exit status of the network probe, empty when it did
    not run."""
    if rc == "0":
        return
    if probe == "":
        raise Refused("melange build failed (exit %s)" % rc, 1)
    if probe == "101":
        raise Refused("a network attempt was made inside the sealed melange call (the probe confirms the namespace "
            "has no route); "
                      "the build must use only declared inputs", 4)
    raise Refused("melange failed with a network error, but the probe says the namespace is not sealed (exit %s); "
                  "fix the seal first" % probe, 1)


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            return f.read()
    except OSError as e:
        raise Refused("cannot read %s: %s" % (path, e.strerror), 1)


def build_values(text, prefix):
    """The values of the 'build' lines of buildinfo.txt (tab-separated: empty, build, KEY=value) that start with
    PREFIX."""
    fields = [line.split("\t") for line in text.split("\n")]
    return [f[2][len(prefix):] for f in fields if len(f) > 2 and f[1] == "build" and f[2].startswith(prefix)]


def check_buildinfo(path, version):
    text = read_text(path)
    if "(devel)" in text:
        raise Refused("the binary says (devel): the source was not stamped", 1)
    if "vcs.modified=true" in text:
        raise Refused("the binary was built from a modified (dirty) tree (vcs.modified=true)", 1)
    mainver = ""
    for f in [line.split("\t") for line in text.split("\n")]:   # the first module line is the main module
        if len(f) > 1 and f[1] == "mod":
            mainver = f[3] if len(f) > 3 else ""
            break
    if mainver != "v" + version:
        raise Refused("the binary's main module version is '%s', not v%s: the build is not stamped with the version "
            "being built "
                      "(a tag at the source HEAD is needed)" % (mainver or "none", version), 1)


def check_revision(path, head, variant, module_file):
    text = read_text(path)
    revisions = build_values(text, "vcs.revision=")
    binrev = revisions[0] if revisions else ""
    if not binrev or binrev != head:
        raise Refused("the binary's vcs.revision is '%s', not the source HEAD %s: the binary is not tied to this source"
                      % (binrev or "none", head), 1)
    recorded = "\n".join("GOFIPS140=" + v for v in build_values(text, "GOFIPS140="))
    if variant != "fips":
        if recorded:
            raise Refused("the standard binary records GOFIPS140 (%s); only the fips variant may" % recorded, 1)
        return
    # REQ-BUILDAPK-001-AC4: the module is the one build/locks/fips-module.txt names, read with the grammar the daily
    # refresh reads it with
    if not os.path.isfile(module_file) or os.path.islink(module_file):
        raise Refused("build/locks/fips-module.txt is missing, not a regular file or a symlink: "
                      "the module the fips binary must record is unknown", 1)
    wanted = read_fips_module(module_file)
    if wanted is None:
        raise Refused("build/locks/fips-module.txt must hold exactly one line vMAJOR.MINOR.PATCH-<8 hex> and a plain "
            "newline; "
                      "refusing", 1)
    if recorded != wanted:
        raise Refused("the fips binary must record exactly one %s (the module build/locks/fips-module.txt names) "
                      "and nothing else (found: %s)" % (wanted, recorded or "none"), 1)


def split_first_line(text):
    """(the first line without its 'file name: ' lead, the rest without its trailing newlines)."""
    first, _, rest = text.partition("\n")
    return re.sub(r"^[^:]*: ", "", first), rest.rstrip("\n")


def go_verdict(rc, go_out, buildinfo, go_err):
    """rc: the exit status of go version -m on the packaged binary (127: no Go toolchain found)."""
    if rc == "127":
        if os.environ.get("GITHUB_ACTIONS"):
            raise Refused("no Go toolchain on PATH in CI: the buildinfo.txt cross-check against the packaged binary "
                "cannot be "
                          "skipped there; the runner must have Go (put it on the search path)", 1)
        print(PREFIX + "note: buildinfo.txt not verified against the binary (no Go toolchain found); the check is "
            "skipped",
              file=sys.stderr)
        return
    if rc != "0":
        try:
            with open(go_err, "rb") as f:
                said = f.read(120).decode(errors="replace").rstrip("\n")
        except OSError:
            said = ""
        raise Refused("'go version -m' failed on the packaged binary (exit %s: %s); the build information cannot be "
            "checked, "
                      "refusing" % (rc, said), 1)
    go_first, go_rest = split_first_line(read_text(go_out).rstrip("\n"))
    info_first, info_rest = split_first_line(read_text(buildinfo))
    if go_first != info_first:
        raise Refused("the Go toolchain in buildinfo.txt (%s) differs from the one go version -m reports for the "
            "packaged binary (%s)"
                      % (info_first, go_first), 1)
    if go_rest != info_rest:
        raise Refused("buildinfo.txt in the apk differs from 'go version -m' of the packaged binary: "
                      "the recorded build information is not the binary's own", 1)


# ---- the base-layout driver: the same decisions, with a smaller set of options ----

BASELAYOUT_PREFIX = "build-baselayout-apk.sh: "
BASELAYOUT_OPTIONS = ("--arch", "--version", "--source-dir", "--repo", "--keyring", "--melange-lock", "--out",
    "--render-dir", "--apk-cache-dir")
BASELAYOUT_PACKAGE = "fscache-baselayout"


def baselayout_check_args(uname_s, uname_m, *args):
    """Every refusal of the base-layout driver that comes before a tool runs. Prints build."""
    if uname_s != "Linux":
        raise Refused("refusing to run on %s: this script uses sudo, unshare and the sealed build tools, which run on "
            "Linux only (inside a Linux container or on a GitHub runner), never on the Mac itself" % uname_s)
    opts = parse_options(args, BASELAYOUT_OPTIONS)
    src = opts.get("source-dir", "")
    if not src:
        raise Refused("--source-dir is required")
    arch = opts.get("arch", "")
    version = opts.get("version", "")
    if arch not in ("x86_64", "aarch64"):
        raise Refused("--arch must be an apk architecture name: x86_64 or aarch64 (not '%s')" % arch)
    host = {"amd64": "x86_64", "arm64": "aarch64"}.get(uname_m, uname_m)
    if arch != host:
        raise Refused("refusing to build %s on a %s host: each architecture builds natively on its own runner, no "
            "emulation" % (arch, host))
    if not (re.fullmatch(VERSION_GRAMMAR, version) or version == "0.0.0-rc.1"):
        raise Refused("--version must be X.Y.Z, X.Y.Z-rcN or the snapshot version 0.0.0-rc.1 "
                      "(numbers without leading zeros; not '%s')" % version)
    check_environment()
    repo = opts.get("repo")
    keyring = opts.get("keyring", "")
    if repo is None:
        raise Refused("--repo DIR (the local package repository melange installs the build tools from) is required")
    if "://" in repo:
        raise Refused("--repo must be a local directory, not an address (%s)" % repo)
    if not os.path.isdir(repo):
        raise Refused("--repo %s is not a directory" % repo)
    if not keyring or not os.path.isfile(keyring):
        raise Refused("--keyring file not found: " + keyring)
    melange_lock = opts.get("melange-lock", "")
    if not melange_lock or not os.path.isfile(melange_lock):
        raise Refused("--melange-lock file not found: " + melange_lock)
    if not opts.get("out"):
        raise Refused("--out DIR is required")
    if not os.path.exists(src + "/.git"):
        raise Refused("%s has no .git: the files of the package are read from a checkout" % src)
    return "build"


def baselayout_arg(name, *args):
    """One value of the base-layout driver's options, as the script uses it (the names of arg, without variant, goarch
    and go-archive)."""
    parse_options(args, BASELAYOUT_OPTIONS)   # called for its refusals: an option the base-layout driver does not know stops here
    if name in ("goarch", "variant", "go-archive"):
        raise Refused("unknown value name " + name, 2)
    return arg(name, *(a for a in args))


BASELAYOUT_PACKAGE_KEYS = ("name", "version", "epoch", "description", "copyright")
BASELAYOUT_COMMANDS = ("mkdir", "chmod", "cp")
BASELAYOUT_LINE_CHARS = re.compile(r"[A-Za-z0-9._/ -]*")
BASELAYOUT_PART = re.compile(r"[A-Za-z0-9._-]+")
BASELAYOUT_MODE = re.compile(r"[0-7]{4}")
BASELAYOUT_SOURCE = re.compile(r"build/baselayout/etc/[A-Za-z0-9._-]+")
DESTDIR_TOKEN = "${{targets.destdir}}"


def baselayout_destination(word):
    """True for ${{targets.destdir}}/rel where every component of rel is plain ASCII and none is . or .. """
    if not word.startswith(DESTDIR_TOKEN + "/"):
        return False
    parts = word[len(DESTDIR_TOKEN) + 1:].split("/")
    return all(BASELAYOUT_PART.fullmatch(p) and p not in (".", "..") for p in parts)


def baselayout_line_ok(words):
    """One line of the recipe, already split on single spaces: mkdir -p DEST..., chmod MODE DEST..., or
    cp build/baselayout/etc/NAME... ${{targets.destdir}}/etc/ (DEST is a path under the destdir token)."""
    if words[0] == "mkdir":
        return len(words) >= 3 and words[1] == "-p" and all(baselayout_destination(w) for w in words[2:])
    if words[0] == "chmod":
        return len(words) >= 3 and bool(BASELAYOUT_MODE.fullmatch(words[1])) and all(baselayout_destination(w) for w in words[2:])
    sources = words[1:-1]
    return len(words) >= 3 and words[-1] == DESTDIR_TOKEN + "/etc/" and all(
        BASELAYOUT_SOURCE.fullmatch(w) and not w.endswith(("/.", "/..")) for w in sources)


def baselayout_step_lines(step, recipe):
    """The lines of one pipeline step of the base-layout recipe, each checked: the step has the key runs only, and every
    non-empty line is one of three exact forms (see baselayout_line_ok): ASCII only, single spaces, every destination
    under the destdir token with no . or .. component. Python and the shell split a line differently on any other
    separator, so no other separator is allowed at all."""
    if not isinstance(step, dict) or set(step) != {"runs"} or not isinstance(step["runs"], str):
        raise Refused("the recipe %s has a pipeline step that is not exactly one runs: text" % recipe)
    for line in step["runs"].split("\n"):
        if line == "":
            continue
        if not BASELAYOUT_LINE_CHARS.fullmatch(line.replace(DESTDIR_TOKEN, "")):
            raise Refused("the recipe %s has a line with a character that chains or expands a command, or a separator the "
                "shell does not split on (only letters, digits, . _ - / and single spaces are allowed): %r" % (recipe, line))
        words = line.split(" ")
        if "" in words:
            raise Refused("the recipe %s has a line outside the allowed form (an empty word: a leading, trailing or double "
                "space): %r" % (recipe, line))
        if any(DESTDIR_TOKEN in w and w != DESTDIR_TOKEN and not w.startswith(DESTDIR_TOKEN + "/") for w in words):
            raise Refused("the recipe %s has the destdir token inside a word (it must stand alone or start a path "
                "${{targets.destdir}}/...): %s" % (recipe, line))
        if words[0] not in BASELAYOUT_COMMANDS:
            raise Refused("the recipe %s runs %s: only mkdir, chmod and cp are allowed" % (recipe, words[0]))
        if not baselayout_line_ok(words):
            raise Refused("the recipe %s has a line outside the allowed form (mkdir -p, chmod MODE, or cp build/baselayout/etc/NAME "
                "to ${{targets.destdir}}/etc/; every destination under ${{targets.destdir}}/ with no . or .. part): %s"
                % (recipe, line))


def baselayout_source(src):
    """The files the recipe copies must be what they look like: build, build/baselayout and build/baselayout/etc are
    real folders, and everything under build/baselayout is a regular file or a real folder (no link, no device)."""
    top = os.path.join(src, "build", "baselayout")
    try:
        for path in (os.path.join(src, "build"), top, os.path.join(top, "etc")):
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                raise Refused("%s is not a real folder (it is a link or a file)" % path)
        for folder, names, files in os.walk(top):
            for name in names + files:
                mode = os.lstat(os.path.join(folder, name)).st_mode
                if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise Refused("%s is not a regular file or a real folder" % os.path.join(folder, name))
    except OSError:
        raise Refused("cannot read the base-layout files under %s" % top)


def baselayout_facts(recipe, outfile):
    """The recipe must be the base-layout package and nothing more: a closed set of keys, a build environment of package
    pins, and pipeline steps that only run mkdir, chmod and cp. Writes name= and one pin= line per build-environment package.
    Everything is read inside the try, so a wrong shape is a refusal and never a traceback."""
    import yaml
    try:
        d = yaml.safe_load(open(recipe, encoding="utf-8"))
        if not isinstance(d, dict) or not isinstance(d.get("package"), dict) or d["package"].get("name") != BASELAYOUT_PACKAGE:
            raise Refused("the recipe %s is not for the package %s: this driver builds only the base layout" % (recipe, BASELAYOUT_PACKAGE))
        if set(d) != {"package", "environment", "pipeline"}:
            raise Refused("the recipe %s must have exactly the keys package, environment and pipeline" % recipe)
        pkg = d["package"]
        if not set(pkg) <= set(BASELAYOUT_PACKAGE_KEYS):
            raise Refused("the recipe %s has a package section with keys other than %s" % (recipe, ", ".join(BASELAYOUT_PACKAGE_KEYS)))
        env = d["environment"]
        if not isinstance(env, dict) or set(env) != {"contents"} or not isinstance(env["contents"], dict) \
                or set(env["contents"]) != {"packages"} or not isinstance(env["contents"]["packages"], list) \
                or not all(isinstance(p, str) for p in env["contents"]["packages"]):
            raise Refused("the recipe %s must have an environment of exactly contents: packages: a list of strings" % recipe)
        if not isinstance(d["pipeline"], list) or not d["pipeline"]:
            raise Refused("the recipe %s must have a pipeline with at least one step" % recipe)
        for step in d["pipeline"]:
            baselayout_step_lines(step, recipe)
        name = pkg["name"]
        pins = env["contents"]["packages"]
    except (OSError, ValueError, RecursionError, yaml.YAMLError):   # ValueError holds bytes that are not UTF-8
        raise Refused("cannot read the recipe %s" % recipe)
    with open(outfile, "w") as f:
        f.write("name=%s\n" % name)
        f.write("".join("pin=%s\n" % p for p in pins))


# name -> (function, fewest words, most words); the answer a function returns is printed
DECISIONS = {
    "check-args": (check_args, 2, None),
    "arg": (arg, 1, None),
    "abs-file": (abs_file, 1, 1),
    "exclude-file": (exclude_file, 2, 2),
    "melange-verdict": (melange_verdict, 2, 2),
    "check-buildinfo": (check_buildinfo, 2, 2),
    "check-revision": (check_revision, 4, 4),
    "go-verdict": (go_verdict, 4, 4),
    "baselayout-check-args": (baselayout_check_args, 2, None),
    "baselayout-arg": (baselayout_arg, 1, None),
    "baselayout-source": (baselayout_source, 1, 1),
    "baselayout-facts": (baselayout_facts, 2, 2),
}


def decide(name, words):
    function, fewest, most = DECISIONS[name]
    if len(words) < fewest or (most is not None and len(words) > most):
        print("usage: build-apk-helper.py %s: wrong number of words" % name, file=sys.stderr)
        return 2
    try:
        answer = function(*words)
    except Refused as e:
        print((BASELAYOUT_PREFIX if name.startswith("baselayout-") else PREFIX) + str(e), file=sys.stderr)
        return e.code
    if answer is not None:
        print(answer)
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] in DECISIONS:
        return decide(argv[1], argv[2:])
    if len(argv) >= 5 and argv[1] == "sealed-call" and argv[2] == "--sealed-env":
        got = sealed_env_items(argv[3])
        if got is None:
            print("the sealed environment file cannot be read", file=sys.stderr)
            return 1
        why = sealed_call(argv[4:], got)
        if why:
            print(why, file=sys.stderr)
            return 1
        return 0
    if len(argv) >= 3 and argv[1] == "sealed-call":
        why = sealed_call(argv[2:])
        if why:
            print(why, file=sys.stderr)
            return 1
        return 0
    if len(argv) == 5 and argv[1] == "recipe-facts":
        return recipe_facts(argv[2], argv[3], argv[4])
    if len(argv) == 3 and argv[1] == "sealed-env":
        return sealed_env(argv[2])
    print("usage: build-apk-helper.py recipe-facts RECIPE GOARCH OUTFILE | sealed-env DATAFILE | sealed-call ARG... | "
        "check-args | arg | abs-file | exclude-file | melange-verdict | check-buildinfo | check-revision | go-verdict",
        file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
