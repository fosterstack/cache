#!/usr/bin/env python3
"""bin/check-govulncheck.py --scanners FILE --out DIR
Check's Go scan of the product module's code (advisor ruling G, Oct 12; v0.3.0 rule 55; REQ-CHAIN-006-AC4). FILE is .github/policy/scanners.json, whose `source_scanners`
list must be exactly ["govulncheck"] (no unlisted scanner runs). The scan is `govulncheck -json ./...` in the working directory (the tagged checkout), with the pinned Go
first on the tool's search path (/usr/local/bin/fscache-go/bin, installed by the pinned Go installer), GOFLAGS=-mod=vendor, GOPROXY=off, GOTOOLCHAIN=local and no workspace, so the scan reads
the exact bytes the build uses (a tree without vendor/ is refused): nothing Go-related from the caller's environment reaches it. The tool's stream is written, byte for byte, to DIR/govulncheck.json: the file the
record of the scanners step carries as a product, which the Release stage binds (the verifier's bind-check) and hands to the dependency evidence step.
Exit 0 only when the tool ran (one config message of scanner govulncheck, on its own database https://vuln.go.dev) and no finding reaches a called symbol (a trace whose
first frame names a function: the PR gate's own rule); a finding of an imported package that no called symbol reaches is carried in the file and does not fail.
Exit 1 on any other outcome, 2 on a usage error. Python is used here for one reason: the pinned toolchain has to be first on the tool's search path, which a plain shell
code of the chain may not set."""
import json, os, shutil, subprocess, sys

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
    tool_env.update({"GOFLAGS": "-mod=vendor", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOENV": "off"})
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
    ver = subprocess.run([tool, "-version"], env=tool_env, capture_output=True, text=True)
    version = next((l[len("Scanner: "):] for l in ver.stdout.splitlines() if l.startswith("Scanner: ")), "")
    if not version:
        fail("govulncheck reports no version")
    r = subprocess.run([tool, "-json", "./..."], env=tool_env, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode("utf-8", "replace")[:2000])
        fail("govulncheck could not run (exit %d): nothing is clean behind a scan that did not run" % r.returncode)
    msgs = messages(r.stdout.decode("utf-8", "replace"))
    cfg = [m["config"] for m in (msgs or []) if isinstance(m, dict) and isinstance(m.get("config"), dict)]
    if len(cfg) != 1 or cfg[0].get("scanner_name") != "govulncheck" or cfg[0].get("db") != DB:
        fail("the output is not a govulncheck run on %s (no config message of scanner govulncheck): it did not run" % DB)
    os.makedirs(out, exist_ok=True)
    with open(dest, "wb") as fh:
        fh.write(r.stdout)
    finds = [m["finding"] for m in msgs if isinstance(m, dict) and isinstance(m.get("finding"), dict)]
    called = sorted({f.get("osv", "?") for f in finds if (f.get("trace") or [{}])[0].get("function")})
    if called:
        print("check-govulncheck: %s: findings that reach a called symbol: %s" % (version, " ".join(called)), file=sys.stderr)
        fail("a vulnerability is reachable from this module's code (%d advisory/ies): see %s" % (len(called), dest))
    print("check-govulncheck: %s: %d advisory/ies in imported packages, none reaches a called symbol" % (version, len({f.get("osv") for f in finds})))


if __name__ == "__main__":
    main(sys.argv)
