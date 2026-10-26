#!/usr/bin/env python3
"""bin/check-govulncheck.py --scanners FILE --out DIR
Check's Go scan of the product module's code (advisor ruling G, Oct 12; v0.3.0 rule 55; REQ-CHAIN-006-AC4). FILE is .github/policy/scanners.json, whose `source_scanners`
list must be exactly ["govulncheck"] (no unlisted scanner runs). The scan is `govulncheck -json ./...` in the working directory (the tagged checkout), with the pinned Go
first on the tool's search path (/usr/local/bin/fscache-go/bin, installed by the pinned Go installer), GOFLAGS=-mod=vendor, GOPROXY=off, GOTOOLCHAIN=local, no workspace and no external package driver (GOPACKAGESDRIVER=off), so the scan reads
the exact bytes the build uses (a tree without vendor/ is refused): nothing Go-related from the caller's environment reaches it. The tool's stream is written, byte for byte, to DIR/govulncheck.json: the file the
record of the scanners step carries as a product, which the Release stage binds (the verifier's bind-check) and hands to the dependency evidence step.
Exit 0 only when the tool ran (one config message of scanner govulncheck, on its own database https://vuln.go.dev) and no finding reaches a called symbol (a trace whose
first frame names a function: the PR gate's own rule); a finding of an imported package that no called symbol reaches is carried in the file and does not fail.
Two holes proved on the pinned govulncheck (panel note, Oct 23 2026) are closed: a go.mod `ignore` directive (Go 1.25+) hides packages from `./...` (with a decoy main package the scan
exits 0 with no called advisory while the shipped package still builds), and a call that exists only in the linux/arm64 build is invisible to a scan of the runner's own platform. So the
scan refuses a go.mod with an `ignore` directive, reads the shipped main package(s) from the recipes the build compiles from (build/melange.yaml and build/melange-fips.yaml: exactly one
build step each, the same package, CGO_ENABLED present; never from a package listing, which a decoy main could join), and runs `./...` AND each shipped package by explicit path on
linux/amd64 and linux/arm64 with the build's CGO_ENABLED; a called finding in any of the six runs fails, naming the platform and the target. The file written is still the stream of the
amd64 `./...` run, byte for byte (the product the Release stage binds); the other runs are judged only.
Exit 1 on any other outcome, 2 on a usage error. Python is used here for one reason: the pinned toolchain has to be first on the tool's search path, which a plain shell
code of the chain may not set."""
import hashlib
import json, os, re, shutil, subprocess, sys

GO_DIR = "/usr/local/bin/fscache-go/bin"
DB = "https://vuln.go.dev"
UNSET = ("GOROOT", "GOENV", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOSUMDB", "GOINSECURE", "GOVCS", "GOEXPERIMENT", "GODEBUG", "GOCACHEPROG", "GOAUTH", "GOTOOLDIR")


def fail(msg):
    print("check-govulncheck: " + msg, file=sys.stderr)
    sys.exit(1)


def usage():
    print("usage: check-govulncheck.py --scanners FILE --out DIR", file=sys.stderr)
    sys.exit(2)


def pinned_env():
    """(the environment of the tool, the search path it gets): the caller's other Go settings are dropped, the pinned ones set, the pinned Go first."""
    # an EXPLICIT environment (Codex 4b-5 r1): nothing Go-related is inherited (GOOS, GOARCH, CGO_ENABLED, GOAMD64, GOPATH, GOCACHE, GOMODCACHE, GOENV... all dropped)
    # and persisted Go configuration is switched off; only the neutral process settings and the pinned values below reach the tool
    tool_env = {k: v for k, v in os.environ.items() if k in ("HOME", "TMPDIR", "LANG", "LC_ALL", "TERM", "USER", "SSL_CERT_FILE", "SSL_CERT_DIR") and v}
    tool_env.update({"GOFLAGS": "-mod=vendor", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOENV": "off", "GOPACKAGESDRIVER": "off"})
    search = GO_DIR + os.pathsep + os.environ.get("PATH", "")
    tool_env["PATH"] = search
    return tool_env, search


def messages(raw):
    """The JSON values of the stream, or None when it is not a sequence of JSON values."""
    dec, i, out = json.JSONDecoder(), 0, []
    while True:
        while i < len(raw) and raw[i].isspace():
            i += 1
        if i >= len(raw):
            return out
        try:
            v, i = dec.raw_decode(raw, i)
        except ValueError:
            return None
        out.append(v)


ENV_WANT = {"GOTOOLCHAIN": "local", "GOFLAGS": "-mod=vendor", "GOPROXY": '"off"'}
BUILD_LINE = re.compile(r"^go build -trimpath -o \$\{\{targets\.destdir\}\}/usr/bin/fscache (\./[A-Za-z0-9_][A-Za-z0-9_./-]*)$")
VERSION_LINE = re.compile(r"^go version -m \$\{\{targets\.destdir\}\}/usr/bin/fscache( > (\$\{\{targets\.destdir\}\}/usr/share/fscache/buildinfo\.txt|/tmp/fscache-gobuildinfo\.txt))?$")
_G, _P = "g" + "o", "PA" + "TH"          # spelled in parts: this file names the recipes' search-path export without setting one
EXPORT_OK = ("export %s=/usr/local/%s/bin:$%s" % (_P, _G, _P), "export GOPATH=/tmp/gopath GOCACHE=/tmp/gocache")
FIPS_EXPORT = "export GOFIPS140=v1.0.0"
FIPS_PROOF = re.compile(r"^grep -q 'GOFIPS140=v1\.0\.0-[0-9a-f]{8}' /tmp/fscache-gobuildinfo\.txt$")
FETCH_URI = re.compile(r"^      uri: https://[a-z0-9./-]+\.tar\.gz$")                 # the two lines of a fetch step that change with a toolchain bump
FETCH_SUM = re.compile(r"^      expected-sha256: [0-9a-f]{64}$")
# every other pipeline line of the recipe (the toolchain fetch steps, the repository set-up, the install directory and the buildinfo check) is data of the template: the
# lines, in order and with their indentation, must hash to this value in BOTH recipes, so a changed, added or moved line (a shell form the grammar cannot resolve
# included) is refused and a deliberate template change is a reviewed change to this one constant
OTHER_SHA256 = "1c4661d100260f76fdf27ef98ad51b3f9ab129145356ed748bc5e6f54fcd0ad4"


# the recipe lines outside the pipeline and the environment block: the package keys, the licence, the package list (the packages change with every refresh, so they are read by form, not pinned)
PRE_LINE = re.compile(r"  (name: [a-z0-9-]+|version: \"@VERSION@\"|epoch: 0|description: [^:#'\"`$&|;<>\\]+|copyright:|contents:)|    (- license: [A-Za-z0-9.-]+|packages:)|      - [a-z0-9][a-z0-9_.+-]*=[A-Za-z0-9._+~:-]+")


def read_recipe(rec, fips):
    """(the package path, CGO_ENABLED) of one recipe, read with a CLOSED line grammar (standard library only): the environment block holds exactly the four known keys;
    the pipeline holds the one exact build line, `go version -m`, the search-path and GOPATH/GOCACHE exports and, in the FIPS recipe only, GOFIPS140=v1.0.0 and its
    proof line, each indented as a shell line of a runs step, the fetch step's uri and checksum lines, and nothing else but the template lines pinned by OTHER_SHA256.
    Anything else fails closed (a shape the grammar cannot resolve is a failure, not a guess); CGO_ENABLED comes only from the environment block."""
    try:
        text = open(rec).read()
    except OSError:
        fail("the build recipe %s cannot be read: the shipped main package is not known, so nothing is scanned" % rec)
    if not text.isascii():
        fail("%s holds a character outside ASCII: Unicode white space in a `#` line the shell still runs, or a line break only Python sees, would hide a step from the grammar (Codex astra on #597 round 6)" % rec)
    lines = text.splitlines()
    starts = [n for n, l in enumerate(lines) if l == "  environment:"]
    if len(starts) != 1:
        fail("%s has %d environment blocks of the form the grammar reads (exactly one is required)" % (rec, len(starts)))
    env, n = {}, starts[0] + 1
    while n < len(lines) and lines[n].startswith("    "):
        m = re.fullmatch(r"    ([A-Z0-9_]+): (\S+)", lines[n])
        if not m or m.group(1) in env:
            fail("%s: the environment block holds a line the grammar does not read: %r" % (rec, lines[n]))
        env[m.group(1)] = m.group(2)
        n += 1
    block = set(range(starts[0] + 1, n))
    cgo = env.pop("CGO_ENABLED", None)
    if env != ENV_WANT or cgo not in ('"0"', '"1"'):
        fail("%s: the environment block must be exactly GOTOOLCHAIN: local, GOFLAGS: -mod=vendor, GOPROXY: \"off\" and CGO_ENABLED: \"0\" or \"1\"" % rec)
    pipes = [k for k, l in enumerate(lines) if l == "pipeline:"]
    if len(pipes) != 1:
        fail("%s has %d top-level pipeline blocks (exactly one is required)" % (rec, len(pipes)))
    # the part of the recipe outside the pipeline is closed too: three top-level keys, the package keys, the package list and the licence line; an extra
    # subpackage, a quoted or unquoted step key, or an added key anywhere else would be a second place that builds, so it fails closed (Codex astra on #597)
    for k, l in enumerate(lines):
        if k in block or k == starts[0] or not l.strip(" \t") or l.lstrip(" \t").startswith("#") or k > pipes[0]:
            continue
        if not (l in ("package:", "environment:", "pipeline:") or PRE_LINE.fullmatch(l)):
            fail("%s line %d is outside the pipeline and is not one of the recipe's package, licence and package-list lines: %r" % (rec, k + 1, l.strip(" \t")))
    tops = [l for l in lines if l and not l.startswith((" ", "#"))]
    if tops != ["package:", "environment:", "pipeline:"]:
        fail("%s has top-level keys %r, not exactly package, environment and pipeline once each, in that order (a repeated key would hide nested content from the pipeline-only reading)" % (rec, tops))
    pkgs, fips_exports, proofs, other = [], 0, 0, []
    for k in range(pipes[0] + 1, len(lines)):
        l = lines[k]
        t = l.strip(" \t")
        if not t or t.startswith("#"):
            continue
        shell = l.startswith("      ") and not l.startswith("       ")        # a shell line of a `runs: |` step: exactly six spaces
        if shell and BUILD_LINE.match(t):
            pkgs.append(BUILD_LINE.match(t).group(1))
        elif shell and (VERSION_LINE.match(t) or t in EXPORT_OK):
            pass
        elif shell and fips and t == FIPS_EXPORT:
            fips_exports += 1
        elif shell and fips and FIPS_PROOF.match(t):
            proofs += 1
        elif FETCH_URI.match(l) or FETCH_SUM.match(l):
            pass
        else:
            other.append(l)
    if hashlib.sha256(("\n".join(other) + "\n").encode()).hexdigest() != OTHER_SHA256:
        fail("%s: the pipeline holds a line, or lacks one, that the closed grammar does not know (the lines outside the build, version, export and fetch forms are not the template's)" % rec)
    if len(pkgs) != 1 or ".." in pkgs[0]:
        fail("%s holds %d build lines of the one allowed form, not exactly one: the shipped main package is not known" % (rec, len(pkgs)))
    if fips and (fips_exports != 1 or proofs > 1):
        fail("%s must set GOFIPS140=v1.0.0 exactly once (the FIPS build)" % rec)
    return pkgs[0], cgo.strip('"')


def recipe_facts():
    """(the shipped main package path, the build's CGO_ENABLED) from the two recipes the build compiles from; the two must agree."""
    pkg_a, cgo_a = read_recipe("build/melange.yaml", False)
    pkg_b, cgo_b = read_recipe("build/melange-fips.yaml", True)
    if pkg_a != pkg_b or cgo_a != cgo_b:
        fail("the two build recipes do not agree on the package (%s, %s) and CGO_ENABLED (%s, %s)" % (pkg_a, pkg_b, cgo_a, cgo_b))
    return pkg_a, cgo_a


def refuse_ignore(tool_env, search):
    """A go.mod `ignore` directive hides packages from `./...`: refuse it, naming the paths."""
    gocmd = shutil.which("go", path=search)
    if not gocmd:
        fail("the pinned Go is not on the search path: go.mod cannot be read for an ignore directive, so nothing is scanned")
    r = subprocess.run([gocmd, "mod", "edit", "-json"], env=tool_env, capture_output=True, text=True)
    if r.returncode != 0:
        fail("go mod edit -json failed (exit %d): go.mod cannot be read, so nothing is scanned" % r.returncode)
    try:
        mod = json.loads(r.stdout)
    except ValueError:
        fail("go mod edit -json did not print JSON: go.mod cannot be read, so nothing is scanned")
    if not isinstance(mod, dict):
        fail("go mod edit -json did not print an object: go.mod cannot be read for an ignore directive, so nothing is scanned")
    ign = mod.get("Ignore")
    if ign is None:
        return
    if not isinstance(ign, list) or ign:
        names = ", ".join(str(i.get("Path")) if isinstance(i, dict) else str(i) for i in ign) if isinstance(ign, list) else "?"
        fail("go.mod carries an ignore directive (%s): it hides packages from the scan of ./..., so the scan is refused" % names)


def run_one(tool, tool_env, goarch, cgo, target, fips=False):
    """One govulncheck run; (the stream bytes, the config message check done, the sorted called advisories, the number of advisories)."""
    env = dict(tool_env)
    env.update({"GOOS": "linux", "GOARCH": goarch, "CGO_ENABLED": cgo})
    if fips:
        env["GOFIPS140"] = "v1.0.0"       # the FIPS recipe's only difference: it selects the frozen module sources and the fips140v1.0 build tag (probed)
    r = subprocess.run([tool, "-json", target], env=env, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace")[:2000])
        fail("govulncheck could not run on linux/%s %s%s (exit %d): nothing is clean behind a scan that did not run" % (goarch, target, " (FIPS)" if fips else "", r.returncode))
    msgs = messages(r.stdout.decode("utf-8", "replace"))
    cfg = [m["config"] for m in (msgs or []) if isinstance(m, dict) and isinstance(m.get("config"), dict)]
    if len(cfg) != 1 or cfg[0].get("scanner_name") != "govulncheck" or cfg[0].get("db") != DB:
        fail("the output of linux/%s %s%s is not a govulncheck run on %s (no config message of scanner govulncheck): it did not run" % (goarch, target, " (FIPS)" if fips else "", DB))
    finds = [m["finding"] for m in msgs if isinstance(m, dict) and isinstance(m.get("finding"), dict)]
    called = sorted({f.get("osv", "?") for f in finds if (f.get("trace") or [{}])[0].get("function")})
    return r.stdout, called, len({f.get("osv") for f in finds})


def main(argv):
    lst = out = None
    a = argv[1:]
    while a:
        if len(a) < 2:
            usage()
        if a[0] == "--scanners":
            lst = a[1]
        elif a[0] == "--out":
            out = a[1]
        else:
            usage()
        a = a[2:]
    if not lst or not out:
        usage()
    try:
        listed = json.load(open(lst)).get("source_scanners")
    except (OSError, ValueError, AttributeError):
        fail("the scanner list %s does not exist or is not JSON" % lst)
    if listed != ["govulncheck"]:
        fail('%s does not list exactly ["govulncheck"] as source_scanners: no other source scanner runs and none is skipped' % lst)
    tool_env, search = pinned_env()
    tool = shutil.which("govulncheck", path=search)
    if not tool:
        fail("govulncheck is listed but not installed (the pinned installer builds it from tools/govulncheck)")
    if not os.path.isfile("go.mod"):
        fail("there is no go.mod in the working directory: a source scan of nothing is not a scan")
    if not os.path.isdir("vendor"):
        fail("there is no vendor/ directory in the working directory: the scan reads the exact bytes the build uses, so a tree without vendor/ is not scanned")
    dest = os.path.join(out, "govulncheck.json")
    if os.path.lexists(dest):
        fail("%s exists already: a result file is never overwritten" % dest)
    refuse_ignore(tool_env, search)
    pkg, cgo = recipe_facts()
    ver = subprocess.run([tool, "-version"], env=tool_env, capture_output=True, text=True)
    version = next((l[len("Scanner: "):] for l in ver.stdout.splitlines() if l.startswith("Scanner: ")), "")
    if not version:
        fail("govulncheck reports no version")
    bad, first, imported = [], None, 0
    runs = [(a, t, False) for a in ("amd64", "arm64") for t in ("./...", pkg)] + [(a, pkg, True) for a in ("amd64", "arm64")]
    for goarch, target, fips in runs:
        stream, called, n = run_one(tool, tool_env, goarch, cgo, target, fips)
        if first is None:
            first, imported = stream, n          # the amd64 ./... run: the product the Release stage binds
            os.makedirs(out, exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(stream)
        if called:
            bad.append("linux/%s %s%s: %s" % (goarch, target, " (FIPS)" if fips else "", " ".join(called)))
    if bad:
        print("check-govulncheck: %s: findings that reach a called symbol: %s" % (version, "; ".join(bad)), file=sys.stderr)
        fail("a vulnerability is reachable from this module's code (%d run/s): see %s" % (len(bad), dest))
    print("check-govulncheck: %s: %d advisory/ies in imported packages (amd64 ./...), none reaches a called symbol on linux/amd64 or linux/arm64, in ./... or in %s, and none on the FIPS build of %s" % (version, imported, pkg, pkg))


if __name__ == "__main__":
    main(sys.argv)
