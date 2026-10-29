#!/usr/bin/env python3
"""0710 item 4: the cache has no HTTP client, dials nothing, runs no program and verifies no certificate
(REQ-IMAGE-001-AC13).

  check-no-outbound.py [ROOT]      scan the non-test Go source under ROOT/cmd and ROOT/internal (default: this repo)
  check-no-outbound.py binary BIN  refuse BIN if it holds a listed symbol; the linker keeps only what main can reach,
                                   so `go tool nm` is the call graph

Exit 0: clean. Exit 1: a refusal, named. Exit 2: the check could not run. The residual is written in REQ-IMAGE-001-AC13.
"""
import ast
import os
import re
import subprocess
import sys

# package path -> the names of it that our own code may not use
BANNED = {
    "net/http": {"Client", "DefaultClient", "Transport", "DefaultTransport", "Get", "Head", "Post", "PostForm",
                 "NewRequest", "NewRequestWithContext"},
    "net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer", "LookupAddr", "LookupCNAME",
            "LookupHost", "LookupIP", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT", "Resolver",
            "DefaultResolver", "ResolveIPAddr", "ResolveTCPAddr", "ResolveUDPAddr"},
    "crypto/tls": {"Client", "Dial", "DialWithDialer", "Dialer"},
    "crypto/x509": {"SystemCertPool", "VerifyOptions"},
    "syscall": {"Connect", "Exec", "ForkExec", "RawSyscall", "RawSyscall6", "Socket", "StartProcess", "Syscall",
                "Syscall6"},
    "golang.org/x/sys/unix": {"Connect", "Exec", "RawSyscall", "RawSyscall6", "Socket", "Syscall", "Syscall6"},
    "os": {"StartProcess"},
}
BANNED_IMPORTS = {"net/http/httputil", "os/exec"}
# a packet socket is what a UDP send needs, so listening for packets is refused on any value (net.ListenConfig included)
BANNED_CALLS = ("ListenIP", "ListenMulticastUDP", "ListenPacket", "ListenUDP")
# a server that sets tls.Config.ClientAuth verifies client certificates against the system roots: refused anywhere
BANNED_WORDS = ("ClientAuth",)
# a symbol is listed only where a test program holds it and a plain net/http server and the real binaries do not
BANNED_SYMBOLS = ["net/http.(*Client).do", "net/http.(*Transport).roundTrip", "net.Dial", "net.DialTimeout",
                  "net.(*Resolver).LookupHost", "net.ResolveIPAddr", "net.ResolveTCPAddr", "net.ResolveUDPAddr",
                  "crypto/tls.Dial", "crypto/tls.(*Dialer).DialContext", "os/exec.(*Cmd).Start"]

# One token: a comment, a raw string, a quoted string or rune, a name, or any other single character.
# It reads `"net/\"x"` as one token and `// import "a"` as one comment;
# an unclosed `"abc` is not a string and falls to single characters.
TOKEN = re.compile(
    r"""//[^\n]*|/\*.*?\*/|`[^`]*`|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|\w+|\S""", re.S
)


def tokens(src):
    """[(text, line)] of the Go source, comments dropped; a string is one token, so its text never looks like code."""
    found, line, pos = [], 1, 0
    for m in TOKEN.finditer(src):
        line += src.count("\n", pos, m.start())
        pos = m.start()
        if not m.group().startswith(("//", "/*")):
            found.append((m.group(), line))
    return found


def go_string(token):
    """The text a Go string literal stands for: raw as written, quoted with its escapes read."""
    if token[0] == "`":
        return token[1:-1].replace("\r", "")      # Go drops a carriage return inside a raw string
    try:
        return ast.literal_eval(token)
    except (ValueError, SyntaxError):
        return token


def imports(toks):
    """[(alias or None, path, line)] of the import declarations; an alias is a name, "." or "_"."""
    words = [word for word, _ in toks]
    found = []
    for i, word in enumerate(words):
        if word != "import":
            continue
        end = i + 3      # import [alias] "path"
        if words[i + 1:i + 2] == ["("]:
            end = len(words)
            if ")" in words[i:]:
                end = words.index(")", i)
        for j in range(i + 1, min(end, len(words))):
            if words[j][0] not in "\"`":
                continue
            before = words[j - 1]
            has_alias = j - 1 > i and (before[0].isalpha() or before[0] in "._")
            found.append((before if has_alias else None, go_string(words[j]), toks[j][1]))
    return found


def method_calls(toks):
    """{name: line of its first use} for every `.name` in the source."""
    calls = {}
    for (dot, _), (name, line) in zip(toks, toks[1:]):
        if dot == ".":
            calls.setdefault(name, line)
    return calls


def first_lines(toks):
    """{token text: line of its first use}."""
    lines = {}
    for word, line in toks:
        lines.setdefault(word, line)
    return lines


def check_file(path):
    """[(line, what)] this file does that the cache may not."""
    with open(path, encoding="utf-8", newline="") as f:      # newline="": keep a carriage return, as Go sees it
        toks = tokens(f.read())
    found, names, packages = [], {}, set()
    for alias, pkg, line in imports(toks):
        packages.add(pkg)
        if pkg in BANNED_IMPORTS:
            found.append((line, "imports " + pkg))
        if alias == "." and pkg in BANNED:
            found.append((line, "dot import of " + pkg))
        if pkg in BANNED and alias not in (".", "_"):
            names[alias or pkg.rsplit("/", 1)[-1]] = pkg
    words = [word for word, _ in toks]
    for k in range(len(words) - 2):
        alias, dot, name = words[k:k + 3]
        pkg = names.get(alias)
        selects_from_a_value = k > 0 and words[k - 1] == "."
        if dot == "." and pkg and not selects_from_a_value and name in BANNED[pkg]:
            found.append((toks[k][1], "uses %s.%s" % (pkg, name)))
    calls = method_calls(toks)
    for name in BANNED_CALLS:
        if name in calls:
            found.append((calls[name], "calls " + name))
    used = first_lines(toks)
    for word in BANNED_WORDS:
        if word in used:
            found.append((used[word], "uses " + word))
    if "crypto/x509" in packages and "Verify" in calls:
        found.append((calls["Verify"], "crypto/x509 and Verify"))
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
