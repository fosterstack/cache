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
linux/amd64 and linux/arm64 with the build's CGO_ENABLED; a called finding in any of the four runs fails, naming the platform and the target. The file written is still the stream of the
amd64 `./...` run, byte for byte (the product the Release stage binds); the other runs are judged only.
Exit 1 on any other outcome, 2 on a usage error. Python is used here for one reason: the pinned toolchain has to be first on the tool's search path, which a plain shell
code of the chain may not set."""
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


def recipe_facts():
    """(the shipped main package paths, the build's CGO_ENABLED) read from the two recipes the build compiles from; any doubt is a failure."""
    pkgs, cgos = [], []
    for rec in ("build/melange.yaml", "build/melange-fips.yaml"):
        try:
            text = open(rec).read()
        except OSError:
            fail("the build recipe %s cannot be read: the shipped main package is not known, so nothing is scanned" % rec)
        steps = [l.split() for l in text.splitlines() if re.match(r"^\s*go build\b", l)]
        if len(steps) != 1:
            fail("%s holds %d build steps, not exactly one: the shipped main package is not known" % (rec, len(steps)))
        pkg = steps[0][-1]
        if not re.fullmatch(r"\./[A-Za-z0-9_][A-Za-z0-9_./-]*", pkg) or ".." in pkg:
            fail("%s names %r as the package to build: not a plain relative package path" % (rec, pkg))
        cg = re.findall(r'^\s*CGO_ENABLED:\s*"?([01])"?\s*$', text, re.M)
        if len(cg) != 1:
            fail("%s does not give CGO_ENABLED exactly once as 0 or 1" % rec)
        pkgs.append(pkg)
        cgos.append(cg[0])
    if pkgs[0] != pkgs[1] or cgos[0] != cgos[1]:
        fail("the two build recipes do not agree on the package (%s, %s) and CGO_ENABLED (%s, %s)" % (pkgs[0], pkgs[1], cgos[0], cgos[1]))
    return [pkgs[0]], cgos[0]


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
    ign = mod.get("Ignore") if isinstance(mod, dict) else None
    if ign is None:
        return
    if not isinstance(ign, list) or ign:
        names = ", ".join(str(i.get("Path")) if isinstance(i, dict) else str(i) for i in ign) if isinstance(ign, list) else "?"
        fail("go.mod carries an ignore directive (%s): it hides packages from the scan of ./..., so the scan is refused" % names)


def run_one(tool, tool_env, goarch, cgo, target):
    """One govulncheck run; (the stream bytes, the config message check done, the sorted called advisories, the number of advisories)."""
    env = dict(tool_env)
    env.update({"GOOS": "linux", "GOARCH": goarch, "CGO_ENABLED": cgo})
    r = subprocess.run([tool, "-json", target], env=env, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace")[:2000])
        fail("govulncheck could not run on linux/%s %s (exit %d): nothing is clean behind a scan that did not run" % (goarch, target, r.returncode))
    msgs = messages(r.stdout.decode("utf-8", "replace"))
    cfg = [m["config"] for m in (msgs or []) if isinstance(m, dict) and isinstance(m.get("config"), dict)]
    if len(cfg) != 1 or cfg[0].get("scanner_name") != "govulncheck" or cfg[0].get("db") != DB:
        fail("the output of linux/%s %s is not a govulncheck run on %s (no config message of scanner govulncheck): it did not run" % (goarch, target, DB))
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
    pkgs, cgo = recipe_facts()
    ver = subprocess.run([tool, "-version"], env=tool_env, capture_output=True, text=True)
    version = next((l[len("Scanner: "):] for l in ver.stdout.splitlines() if l.startswith("Scanner: ")), "")
    if not version:
        fail("govulncheck reports no version")
    bad, first, imported = [], None, 0
    for goarch in ("amd64", "arm64"):
        for target in ["./..."] + pkgs:
            stream, called, n = run_one(tool, tool_env, goarch, cgo, target)
            if first is None:
                first, imported = stream, n          # the amd64 ./... run: the product the Release stage binds
                os.makedirs(out, exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(stream)
            if called:
                bad.append("linux/%s %s: %s" % (goarch, target, " ".join(called)))
    if bad:
        print("check-govulncheck: %s: findings that reach a called symbol: %s" % (version, "; ".join(bad)), file=sys.stderr)
        fail("a vulnerability is reachable from this module's code (%d run/s): see %s" % (len(bad), dest))
    print("check-govulncheck: %s: %d advisory/ies in imported packages (amd64 ./...), none reaches a called symbol on linux/amd64 or linux/arm64, in ./... or in %s" % (version, imported, " ".join(pkgs)))


if __name__ == "__main__":
    main(sys.argv)
