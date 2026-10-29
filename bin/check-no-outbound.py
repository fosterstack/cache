#!/usr/bin/env python3
"""0710 item 4 (REQ-IMAGE-001-AC13, docs/ratify/2026-10-28-no-ca-bundle-in-images.md, rules 1 and 2):
the cache has no HTTP client and dials no outbound connection.

  check-no-outbound.py [ROOT]      scan the non-test Go source under ROOT/cmd and ROOT/internal (ROOT: the repository)
  check-no-outbound.py binary BIN  list the symbols of the linked program BIN (needs `go` on the search path)

Source scan: comments and string literals are blanked, then a use of an HTTP client or a dial name is refused (exit 1,
file:line). The names are in BANNED below; import aliases are followed and a dot import is refused.

Binary check: the Go linker drops every function main cannot reach, so a symbol of `go tool nm BIN` is code the
program can run, dependencies included. The symbols in BANNED_SYMBOLS are refused (exit 1); each has a test program
that uses it. Exit 2 when BIN or go cannot be used, or BIN has no symbols (a stripped binary would pass vacuously).

Residual: net.(*Dialer).DialContext is in every net/http program, so it proves nothing. A dependency that dials
through net.Dialer alone, or through a symbol not listed, is not caught by the binary check. The source scan covers
our own code only.
"""
import os
import re
import subprocess
import sys

BANNED = {
    "net/http": {"Client", "DefaultClient", "Transport", "DefaultTransport", "Get", "Head", "Post", "PostForm",
                 "NewRequest", "NewRequestWithContext"},
    "net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer", "LookupAddr", "LookupCNAME",
            "LookupHost", "LookupIP", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT", "Resolver",
            "DefaultResolver"},
    "crypto/tls": {"Dial", "DialWithDialer", "Dialer"},
}
BANNED_IMPORTS = {"net/http/httputil"}
BANNED_SYMBOLS = ["net/http.(*Client).do", "net/http.(*Transport).roundTrip", "net.Dial", "net.DialTimeout",
                  "net.(*Resolver).LookupHost", "crypto/tls.Dial"]
DOT_BANNED = set(BANNED)


def strip(src):
    """The source with comments and string and rune literals blanked (newlines kept), so a name in text is not a use."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif c == "`":
            j = src.find("`", i + 1)
            j = n if j < 0 else j + 1
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + " " * (j - i - 2) + c if j - i >= 2 else c); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def imports(src):
    """[(alias or None, path, line)] of the imports, read before strip() because import paths are string literals."""
    res = []
    for m in re.finditer(r'^[ \t]*import[ \t]*\(([^)]*)\)', src, re.M):
        base = src.count("\n", 0, m.start(1))
        for k, line in enumerate(m.group(1).split("\n")):
            g = re.match(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"([^"]+)"', line)
            if g:
                res.append((g.group(1), g.group(2), base + k + 1))
    for m in re.finditer(r'^[ \t]*import[ \t]+(?:([A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"([^"]+)"', src, re.M):
        res.append((m.group(1), m.group(2), src.count("\n", 0, m.start()) + 1))
    return res


def check_file(path):
    src = open(path, encoding="utf-8").read()
    found, names = [], {}
    for alias, imp, line in imports(src):
        if imp in BANNED_IMPORTS:
            found.append((line, "imports " + imp))
        if alias == "." and imp in DOT_BANNED:
            found.append((line, "dot import of " + imp))
        if imp in BANNED and alias not in (".", "_"):
            names[alias or imp.rsplit("/", 1)[-1]] = imp
    body = strip(src)
    for alias, imp in names.items():
        for m in re.finditer(r"(?<![A-Za-z0-9_.])" + re.escape(alias) + r"\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)", body):
            if m.group(1) in BANNED[imp]:
                found.append((body.count("\n", 0, m.start()) + 1, "uses %s.%s" % (imp, m.group(1))))
    return found


def go_files(root):
    for top in ("cmd", "internal"):
        for d, dirs, files in os.walk(os.path.join(root, top)):
            dirs[:] = sorted(x for x in dirs if x != "vendor")
            for f in sorted(files):
                if f.endswith(".go") and not f.endswith("_test.go"):
                    yield os.path.join(d, f)


def check_tree(root):
    bad, seen = [], 0
    try:
        for path in go_files(root):
            seen += 1
            for line, what in check_file(path):
                bad.append("%s:%d: %s" % (os.path.relpath(path, root), line, what))
    except (OSError, UnicodeDecodeError) as e:
        sys.stderr.write("check-no-outbound: cannot read %s\n" % getattr(e, "filename", "a file"))
        return 2
    if not seen:
        sys.stderr.write("check-no-outbound: no Go files under %s/cmd or %s/internal\n" % (root, root))
        return 2
    for b in bad:
        sys.stderr.write(b + "\n")
    if bad:
        return 1
    print("check-no-outbound: %d non-test Go files, no HTTP client and no outbound dial" % seen)
    return 0


def check_binary(path):
    if not os.path.isfile(path):
        sys.stderr.write("check-no-outbound: cannot read the binary %s\n" % path)
        return 2
    try:
        nm = subprocess.run(["go", "tool", "nm", path], capture_output=True, text=True)
    except OSError:
        sys.stderr.write("check-no-outbound: go is not installed, the binary cannot be read\n")
        return 2
    if nm.returncode:
        sys.stderr.write("check-no-outbound: go tool nm failed on %s: %s\n" % (path, nm.stderr.strip()[:200]))
        return 2
    rows = [line.split(None, 2) for line in nm.stdout.splitlines()]      # each row: address, type letter, name
    symbols = {row[2] for row in rows if len(row) == 3}
    if "runtime.main" not in symbols:      # every Go program has it; without it the list proves nothing
        sys.stderr.write("check-no-outbound: %s has no readable symbols (no runtime.main): stripped or not Go\n" % path)
        return 2
    found = [sym for sym in BANNED_SYMBOLS if sym in symbols]
    for sym in found:
        sys.stderr.write("%s: holds %s\n" % (path, sym))
    if found:
        return 1
    print("check-no-outbound: %s holds no HTTP client symbol and no dial symbol" % path)
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "binary":
        if len(argv) != 3:
            sys.stderr.write("check-no-outbound: usage: binary BIN\n")
            return 2
        return check_binary(argv[2])
    if len(argv) > 2:
        sys.stderr.write("check-no-outbound: at most one argument (ROOT)\n")
        return 2
    return check_tree(argv[1] if len(argv) == 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
