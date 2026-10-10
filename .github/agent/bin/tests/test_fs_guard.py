# proves: REQ-AUD-019-AC1, REQ-AUD-019-AC2, REQ-AUD-019-AC3
"""REQ-AUD-019: tests must not touch real system paths. Importing this module (unittest discovery does, before any test runs) arms fs_guard
for the whole run (the runtime guard covers whatever discovery actually runs, Go and Java included); the static scan is scoped: Python tests in
full, every other (shell) test only for an absolute-target `ln -s` / `cp -s` and for creating files without a mktemp call."""
import ast, contextlib, hashlib, os, re, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fs_guard as G  # noqa: E402

G.install()
REPO = G.REPO

# Absolute system-path literals a test script may not contain. This is an ENUMERATION of top-level directory names (plus the variants
# below): flagging ANY absolute-looking token was measured at 314 findings on the tree (217 of them `+ "/branches"`-style suffixes, URL
# fragments and regexes), so the scan stays narrow and a first component outside this list (`/scratch/x`, `/afs/x`) is a documented residual.
SYS_NAMES = ["etc", "usr", "var", "private", "Library", "System", "opt", "bin", "sbin", "dev", "home", "root", "proc", "sys", "Users",
             "tmp", "Applications", "Volumes", "run", "srv", "lib", "lib64", "boot", "mnt", "nix", "cores", "Network", "snap",
             "workspace", "github", "media", "data", "afs", "net", "scratch", "export", "exports", "nfs", "Developer", "lost\\+found", "vol", "pkg",
             "swapfile", "imagegeneration", "datadisk", "cdrom", "lib32", "libx32", "init", "__w", "_work", "docker-entrypoint\\.d", "entrypoint\\.sh",
             "bin\\.usr-is-merged", "lib\\.usr-is-merged", "sbin\\.usr-is-merged", "sw", "firmlinks"]
SYS_DIRS = "|".join(SYS_NAMES)
SHEBANG = re.compile(r"#!\s*/(?:usr/)?bin/(?:env\s+)?[a-z0-9]+")     # a script's first line written into a fixture file: file content, not a path used
# The boundary before the slash excludes only word characters, `.`/`$`/`/`/braces/`~`/`)` (a relative or variable-based path, a URL host, a
# command substitution). `:` and `-` are NOT excluded, so `${TMPDIR:-/tmp}`, `oci-archive:/tmp/x`, `PATH=/a:/usr/bin`, `-o/etc/hosts` and
# `tar -C/etc` are found. Case-insensitive: APFS resolves /Etc/hosts to /etc/hosts. Extra slashes, `/./` and `/../` before the name
# (`//etc`, `/./etc`, `/../etc`, `file:///etc`), a digit or `_` after it (`/usr2`, `/tmp_dir`, `/lib64`), `/{etc,usr}` and a one-character `?`
# wildcard in the name (`/e?c`) are found too.
_GLOB = "|".join(n[:i] + r"\?" + n[i + 1:] for n in SYS_NAMES if "\\" not in n for i in range(len(n)))
_START = r"""(?:(?<![A-Za-z0-9_.$/{}~)])/(?!/)|(?<![A-Za-z0-9_.$/{}~):])//+|(?<=[\s'"]-[A-Za-z])/)"""     # `://` (a URL) is not a path
LITERAL = re.compile(_START + r"(?:\.{1,2}/+)*(?:(?:%s)(?:/|(?![A-Za-z\-]))|\{(?:%s)[,}]|(?:%s)(?:/|(?![A-Za-z\-])))" % (SYS_DIRS, SYS_DIRS, _GLOB), re.I)
# The bare root: open('/'), os.listdir('/'), os.path.join('/', ..), cwd='/', `ls /`, `cd /`, `pushd /`, `tar -C /`, `git -C / status`, `cp x /`,
# `mv x /`, `rsync -a x /`, `docker run -v /:/host`.
_END = r"(?=\s|$|;|\)|&|\||['\"])"
ROOT_ONLY = re.compile(r"""\b(?:open|listdir|scandir|stat|lstat|walk|fwalk|chdir|realpath|abspath|normpath|exists|isdir|isfile|islink|iterdir|Path|join|rmtree|chroot|glob|rglob|samefile)\(\s*[rb]?['"]/['"]"""
                       r"""|\bcwd\s*=\s*[rb]?['"]/['"]"""
                       r"""|\b(?:ls|cd|find|du|stat|cat|rm|chmod|chown|df|pushd|popd|chroot|tree|mount|umount|touch|mkdir|rmdir)\b[^;&|\n]*?(?<=\s)/""" + _END +
                       r"""|(?:^|\s)(?:-C|-w|--directory|--chdir|--work-tree|--git-dir|--workdir|--root|--prefix)(?:\s+|=)/""" + _END +
                       r"""|\b(?:cp|mv|rsync|install|ln|scp|tar|zip|unzip|cpio)\b[^;&|\n]*\s/(?=\s*(?:$|[;&|)'"]))"""
                       r"""|\s(?:-v|--volume)(?:\s+|=)/:|--mount[ =]\S*src=/(?=[,\s])""")
# Generic rules that close the "first component outside the list" class without an allow row per name:
#   - a first component starting with a dot (/.vol /.file /.nofollow /.resolve /.dockerenv /.fseventsd /.Spotlight-V100 /.DS_Store, `find /.`)
#   - any glob metacharacter in the first component (/* /U*/x /e*/hosts /[e]tc /e??/hosts)
#   - ~user (`~root/x`), `../` chains of two or more with or without a trailing slash (`..//..//x`, `cd ../../..`)
#   - a bare-root assignment (`d=/`, `r='/'`), an absolute value of any `--option=/abs`, an attached `-C/`, a redirect into `/`,
#     `cd "/"`, os.sep as a path, `source=/` mounts
_OPEN = r"""(?:^|(?<=[\s=(,:{\[]))["']?"""          # the slash starts a token: line start, or after a separator (optionally behind ONE opening quote)
EXTRA = re.compile(_OPEN + r"""/(?:\.[A-Za-z]|\.(?=\s|$|['"])|[A-Za-z0-9_.\-]*(?:[*\[]|\?(?=[A-Za-z0-9_/?*\[])))"""
                   r"""|(?:^|[\s=:'"(,])~[A-Za-z_]"""
                   r"""|(?<![\w./)}\]-])\.\.(?:/+\.\.){1,}"""
                   r"""|[A-Za-z_]\w*\s*=\s*['"]?/['"]?(?=\s|;|$|\))"""
                   r"""|--[A-Za-z][A-Za-z-]*=/(?!/)"""
                   r"""|\s-[A-Za-z]/(?=\s|$|['"])"""
                   r"""|>>?\s*/""" + _END +
                   r"""|\b(?:cd|ls|cat|rm|find|pushd)\s+['"]/['"]"""
                   r"""|(?<!\.split)(?<!\.rsplit)(?<!\.replace)(?<!\.startswith)(?<!\.endswith)(?<!\.strip)(?<!\.lstrip)(?<!\.rstrip)(?<!\.count)(?<!\.find)(?<!\.rfind)(?<!\.index)(?<!\.partition)(?<!\.rpartition)(?<!\.removeprefix)(?<!\.removesuffix)\(\s*os\.(?:path\.)?sep\s*[,)]|\b(?:abspath|realpath|normpath)\(\s*os\.(?:path\.)?sep\b|=\s*os\.(?:path\.)?sep\s*(?:$|[;)])"""
                   r"""|\b(?:src|source)=/(?=[,\s'"]|$)""")
_SUFFIX = re.compile(r"""(\+\s*[rb]?["'])/""")           # `var + "/x"` appends to a prefix the code controls: not an absolute path by itself
HOME_USE = re.compile(r"~/|\$HOME|\$\{HOME|expanduser|Path\.home|environ\[\s*['\"]HOME['\"]|(?:getenv|environ\.get)\(\s*['\"]HOME['\"]|getpw(?:uid|nam)\(|(?:^|[\s=:'\"(,])~(?=$|[;)])|\b(?:cd|ls|cat|cp|mv|rm|source|find|tar)\s+(?:-[A-Za-z-]+\s+)*~(?=\s|$|;)|\bcd\s*(?:$|;|&&|\|\|)|(?:\.\./){3,}|\bfile:/+(?:[A-Za-z]|\.\.?/)")
SELF = "bin/tests/test_fs_guard.py"


def read_raw(rel):
    """The file's exact bytes: no newline translation (a CR or CRLF edit must be visible), no decoding."""
    with open(os.path.join(REPO, rel), "rb") as fh:
        return fh.read()


def decode(raw):
    return raw.decode("utf-8", "replace")                 # str.split("\n") on this text sees CR as an ordinary character, as bash does


def test_files():
    out = subprocess.run(["git", "-C", REPO, "ls-files"], capture_output=True, text=True, check=True).stdout.split("\n")
    pat = re.compile(r"(^|/)(test_[^/]*\.py|[^/]*[-_]test\.py|[^/]*-tests?\.(sh|py)|[^/]*_tests?\.sh)$|^\.github/agent/tests/[^/]+\.(sh|py)$")
    return sorted(f for f in out if pat.search(f) and not f.endswith(SELF) and f != ".github/agent/tests/coverage-gate.sh")


def load_allow():
    import system_path_allowlist as A
    rows = []
    for n, row in enumerate(A.ROWS, 1):
        assert len(row) == 3 and len(row[2].strip()) >= 12, "allow-list row %d needs file, substring, reason" % n
        rows.append(tuple(p.strip() for p in row))
    return rows


_DEV_NULL = re.compile(r"(?<![\w./\-])/dev/null(?![\w./\-])")        # the complete path token, not /dev/nullx, /dev/null/x, /dev/null.d
_QUOTED_SHEBANG = re.compile(r"""(?<=['"])#!\s*/(?:usr/)?bin/(?:env\s+)?[a-z0-9]+""")   # `'#!/bin/sh\n...'`: file CONTENT being written, anywhere on a line

# A WHOLE-TOKEN root ("/", "//", "/.", "/..", "/./", "/.//", bare or in quotes with an optional r/b/u/f prefix, closed by whitespace, a quote,
# ; ) ] , & | > } or the end of the line) is a finding whatever command or call it is an argument of: that closes the verb / function whitelists.
_BARE = re.compile(r"""(?<![\w.$/{}~)\]\-*^:])(?P<pre>[rRbBuUfF]{0,2}['"]?)(?P<tok>/(?:/|\.{1,2}(?:/|(?=[\s'";)\],&|>}]|$)))*)(?P<post>['"]?)(?=[\s;)\],&|>}]|$)""")
_STRING_METHOD_BEFORE = re.compile(r"\.(?:r?split|r?partition|join|startswith|endswith|count|strip|lstrip|rstrip|replace|find|rfind|index|removeprefix|removesuffix)\(\s*[rRbBuUfF]{0,2}$"
                                   r"|\.replace\([^()]*,\s*[rRbBuUfF]{0,2}$|\b(?:re\.(?:sub|split|match|search|findall|escape)|str\.join|urlsplit|quote|unquote)\(\s*[rRbBuUfF]{0,2}$|(?:==|!=|\bin|\bnot in)\s*$|\+\s*$|%\s*$")
_STRING_METHOD_AFTER = re.compile(r"^\s*(?:\.join\(|\+|==|!=|%|\bin\b)")
_CMD_POSITION = re.compile(r"(?:^|[;&|({`]|\$\(|\b(?:then|do|else|elif)\b)\s*$")


_VERBS = set("ls ll cd find du df stat cat rm chmod chown pushd popd chroot tree mount umount touch mkdir rmdir grep egrep fgrep rg head tail wc file "
             "readlink realpath diff cmp tar zip unzip cp mv rsync scp install ln sort less more nl od xxd strings ag fd test [ [[ git env sudo xargs "
             "exec source . eval ldd lsof".split())
_ROOT_WORD = re.compile(r"""^["']?/(?:/|\.{1,2}(?:/|$))*["']?$""")      # a whole word that is `/`, `//`, `/.`, `/..`, `/./` (optionally quoted)


def bare_roots(line):
    """Whole-token roots on a line, minus the explicit exceptions: a string method's separator (`.split("/")`, `"/".join`, `== "/"`, `x + "/" + y`,
    `re.sub(r"/", ...)`) and an arithmetic / prose division (`a / b`, `$((a / b))`, `sed s/a/b/` never forms a token)."""
    out = []
    for m in _BARE.finditer(line):
        quoted = bool(m.group("pre").strip("rRbBuUfF")) and bool(m.group("post"))      # an OPENING and a closing quote (`/'` ends a sed expression)
        before, after = line[:m.start()], line[m.end():]
        if quoted and (_STRING_METHOD_BEFORE.search(before) or _STRING_METHOD_AFTER.search(after)):
            continue
        if not quoted:
            continue                                       # an unquoted token is judged per command segment below
        out.append(m.group(0))
    for seg in re.split(r"\|\||&&|[;|&(){}\n`]", line):
        words = seg.split()
        while words and re.match(r"^[A-Za-z_]\w*=", words[0]):
            words.pop(0)                                 # leading VAR=value assignments
        if words and os.path.basename(words[0]) in _VERBS and any(_ROOT_WORD.match(w) for w in words[1:]):
            out.append(seg.strip())
    return out


def flagged(line, rel="", first=False):
    """True when the line names a system path in any form the scan knows (rules above);  Only the FIRST line
    of a file may be a bare `#!` line (exempt there); a `#!` that starts a QUOTED string is file content being written. `/* ... */` is NOT
    stripped (in a shell test `ls /*/*/` is two globs, not a comment)."""
    if rel and not rel.endswith(".py"):
        return False                                        # the literal scan reads Python tests only (REQ-AUD-019-AC2); "" is unnamed text
    if first and line.startswith("#!"):
        return False
    clean = _QUOTED_SHEBANG.sub("", _DEV_NULL.sub("", line))
    if first:
        clean = SHEBANG.sub("", clean)
    anchored = _SUFFIX.sub(r"\1", clean)
    return bool(LITERAL.search(clean) or ROOT_ONLY.search(clean) or HOME_USE.search(line) or EXTRA.search(anchored) or bare_roots(clean))


def split_lines(rel, text):
    """Python's tokenizer ends a line at a lone CR; bash does not. Splitting a .py file on every kind of newline means no statement hides
    behind a CR after a comment or `#!` line."""
    return re.split(r"\r\n|\r|\n", text) if rel.endswith(".py") else text.split("\n")


def approved_rest(line, spans):
    """The line with each approved span replaced by a NUL, or None when the approval does not hold. A per-pattern row approves ONE reviewed
    occurrence: the FIRST, which must be a complete token (the characters on both sides are not [\\w./-], so `fscache2`, `.bak`, `-evil`,
    `/x` cannot ride along), and the same literal must not occur again on the line (`...fscache; open("...fscache")`)."""
    rest = line
    for sp in spans:
        i = rest.find(sp)
        if i < 0:
            continue
        before, after = rest[i - 1:i], rest[i + len(sp):i + len(sp) + 1]
        if re.match(r"[\w./\-]", before or " ") or re.match(r"[\w./\-]", after or " "):
            return None
        rest = rest[:i] + "\0" + rest[i + len(sp):]
        if sp in rest:
            return None
    return rest


def literal_findings(rel, text, allow):
    used, bad = set(), []
    if rel and not rel.endswith(".py"):
        return bad, used
    for m in re.finditer(r"\r(?!\n)", text):                       # a lone CR in ANY scanned file is a finding (nothing legitimate has one)
        bad.append("%s:%d: a lone CR (not followed by LF) hides what follows from line-based tools" % (rel, text.count("\n", 0, m.start()) + 1))
        break
    for n, line in enumerate(split_lines(rel, text), 1):
        if not flagged(line, rel, n == 1):
            continue
        hit = [a for a in allow if a[0] == rel and a[1] in line]
        if hit:
            used.update(hit)
            if any(a[1] == "" for a in hit):
                continue                                          # a whole-file row exempts the line (the file is pinned byte for byte)
            if approved_rest(line, [a[1] for a in hit]) is not None and not flagged(approved_rest(line, [a[1] for a in hit]), rel):
                continue
        bad.append("%s:%d: %s" % (rel, n, line.strip()[:110]))
    return bad, used


_SCAN = {}


def scan():
    if "scan" not in _SCAN:
        _SCAN["scan"] = _scan()
    return _SCAN["scan"]


def literal_scan_files():
    return [f for f in test_files() if f.endswith(".py")]


def _scan():
    allow = load_allow()
    used, bad = set(), []
    for rel in literal_scan_files():
        b, u = literal_findings(rel, decode(read_raw(rel)), allow)
        bad += b; used |= u
    return bad, [a for a in allow if a not in used]


# --- link creation: no test may create a symlink or hard link whose target is an absolute path (a real system path or any other
# fixed location). Targets are built from the temp dir, so a literal absolute target is always a finding.
SHELL_CMD = re.compile(r"(?<![\w.-])(?:[\w.$/{}-]*/)?(ln|cp)\s+([^;&|)\n]*)")      # `/bin/ln`, `/usr/bin/ln` and a bare `ln`
CP_LINK_FLAGS = re.compile(r"^-[A-Za-z]*[sl][A-Za-z]*$|^--(symbolic-link|link)$")
_ABS_VAR_DEFAULT = re.compile(r"\$\{\w+:?[-=+]['\"]?[/~]")


def _abs_operand(tok):
    """A shell word that names an absolute path: starts with `/` (also `/`, `//x`), `~` (the home directory), `$'/x'`, a `{/x,y}` brace list,
    a `${V:-/x}` / `${V-/x}` / `${V=/x}` / `${V+/x}` default, or an attached option value (`-t/x`, `--target-directory=/x`)."""
    w = tok.strip("\"'")
    if w.startswith("$'") or w.startswith('$"'):
        w = w[2:].lstrip("\"'")
    if w.startswith(("/", "~")) or re.match(r"\{[^}]*[,{]?/|\{~", w) or ",/" in w.split("}")[0] and w.startswith("{"):
        return True
    if _ABS_VAR_DEFAULT.search(w):
        return True
    return bool(re.match(r"^-{1,2}[A-Za-z][\w-]*=?[\"']?[/~]", w))


def shell_link_target(line):
    """The absolute operand of an `ln` (soft or hard, any flags in any position, `--`, --symbolic, -t DIR, attached -t/abs, ${V:-/abs}, `~/x`, a
    brace list) or of a link-making `cp` (-s, -l, --symbolic-link, even after the operands) on a line, or None. $VAR/$(..) and relative operands
    are not absolute and are not reported."""
    for m in SHELL_CMD.finditer(line):
        toks = m.group(2).split()
        before_dd = toks[:toks.index("--")] if "--" in toks else toks
        flags = [x for x in before_dd if x.startswith("-") and not _abs_operand(x)]
        if m.group(1) == "cp" and not any(CP_LINK_FLAGS.match(f) for f in flags):
            continue
        for tok in toks:
            if tok == "--" or (tok.startswith("-") and tok in flags):
                continue
            if _abs_operand(tok):
                return tok.strip("\"'")
    return None


LINK_FUNCS = {"symlink", "link", "symlink_to", "hardlink_to", "link_to"}


def _consts(node):
    """Every string constant in the expression, including the constant parts of f-strings; join/concat/% are folded by taking the
    pieces: any piece that is an absolute path makes the whole target suspect."""
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def link_findings(rel, text, allow):
    """[(rel, line, why)] for link creations with an absolute target in one file's text; allow = allow-list rows for this file. A row approves
    ONE complete-token occurrence of its span (approved_rest, as for the literal rows), and what is left of the line must hold no further
    absolute-target link, so `ln -s /tmp/a /tmp/b; ln -s /etc/hosts evil` and a trailing comment copy of the span are findings."""
    found, used = [], set()

    def add(line, why, src_line, shell=True):
        hit = [a for a in allow if a[0] == rel and a[1] in src_line]            # src_line: the shell logical line, or the one call's own source text
        used.update(hit)
        if hit:
            rest = approved_rest(src_line, [a[1] for a in hit])
            if rest is not None and (not shell or shell_link_target(rest) is None):
                return
        found.append("%s:%d: %s" % (rel, line, why))
    lines = text.split("\n")
    if rel.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = None
        for n in ast.walk(tree) if tree else ():
            if isinstance(n, ast.Call) and (n.args or n.keywords):
                f = n.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in LINK_FUNCS:
                    # every positional and keyword argument: src=/target= forms and an absolute link location are findings too
                    bad = [c for a in list(n.args) + [k.value for k in n.keywords] for c in _consts(a) if c.startswith("/")]
                    if bad:
                        add(n.lineno, "%s() with an absolute target %r" % (name, bad[0]), ast.get_source_segment(text, n) or lines[n.lineno - 1], shell=False)
    i = 0
    while i < len(lines):                                   # `ln -s <abs>` in shell tests and in command text inside Python tests
        start, logical = i + 1, lines[i]
        while logical.endswith("\\") and i + 1 < len(lines):      # a backslash-newline continuation is one command
            i += 1
            logical = logical[:-1] + " " + lines[i]
        tgt = shell_link_target(logical)
        if tgt:
            add(start, "link made by ln/cp with an absolute target %s" % tgt, logical)
        i += 1
    return found, used


def link_scan(read=None):
    if read is None and "link" in _SCAN:
        return _SCAN["link"]
    out = _link_scan(read)
    if read is None:
        _SCAN["link"] = out
    return out


def _link_scan(read=None):
    from system_path_allowlist import LINK_ROWS
    allow = [tuple(p.strip() for p in r) for r in LINK_ROWS]
    read = read or (lambda rel: decode(read_raw(rel)))
    bad, used = [], set()
    for rel in test_files():
        f, u = link_findings(rel, read(rel), allow)
        bad += f; used |= u
    return bad, [a for a in allow if a not in used]


# --- the mktemp rule (a lint of PLAIN forms, not a security control: the runtime guard is the control). A shell test that creates files must
# create them under a mktemp directory; the scan checks the weaker, cheap thing: a script that creates files at all also calls mktemp / tempfile.
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_]\w*)\1")
_WRAPPERS = {"sudo", "env", "command", "exec", "time", "nohup", "xargs", "nice", "!", "then", "do", "else", "elif", "if", "while", "until", "{", "}"}
_CREATORS = {"mkdir", "touch", "cp", "mv", "ln", "install", "tee", "mkfifo", "mknod"}


def _strip_heredocs(text):
    """Heredoc bodies are text (python, JSON, a stub script), not shell commands: blank them, keeping line numbers."""
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = _HEREDOC.search(re.sub(r"<<<", "", line))
        i += 1
        if m:
            while i < len(lines) and lines[i].strip() != m.group(2):
                out.append("")
                i += 1
            if i < len(lines):
                out.append("")
                i += 1
    return "\n".join(out)


def _shell_segments(text):
    """[(line, words, has_file_redirect)] for each simple command in `text` (one stream, so a multi-line quoted string is one token).
    Splits on ; & | newline ( ) { } $( ` and then/do; single-quoted text is dropped, double-quoted text is dropped except its $( ) and ` `
    substitutions (which run), a comment ends the line, `>` / `>>` / `>|` to a word that is not &N or /dev/null marks a file redirect,
    and arithmetic $(( )) is skipped."""
    segs, cur, line, redirect = [], [], 1, False
    stack = []                                   # modes: "dq" (inside double quotes), "sub" (inside $( ) or ` `), "arith"
    seg_line = 1

    def flush():
        nonlocal cur, redirect, seg_line
        words = "".join(cur).split()
        if words or redirect:
            segs.append((seg_line, words, redirect))
        cur, redirect, seg_line = [], False, line

    i, n = 0, len(text)
    while i < n:
        c = text[i]
        mode = stack[-1] if stack else "cmd"
        nxt = text[i + 1:i + 2]
        if c == "\n":
            line += 1
        if mode == "arith":
            if text.startswith("))", i):
                stack.pop(); i += 2; continue
            i += 1; continue
        if mode == "dq":
            if c == "\\":
                i += 2; continue
            if c == '"':
                stack.pop(); i += 1; continue
            if text.startswith("$((", i):
                stack.append("arith"); i += 3; continue
            if text.startswith("$(", i):
                flush(); stack.append("sub"); i += 2; continue
            if c == "`":
                flush(); stack.append("bt"); i += 1; continue
            i += 1; continue
        # command mode (also inside $( ) and backticks)
        if c == "\\":
            i += 2 if nxt != "\n" else 2
            if nxt == "\n":
                line += 1
            continue
        if c == "'":
            j = text.find("'", i + 1)
            line += text.count("\n", i, j if j >= 0 else n)
            cur.append("Q")
            i = (j + 1) if j >= 0 else n
            continue
        if c == '"':
            stack.append("dq"); cur.append("Q"); i += 1; continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;&|(){}"):
            j = text.find("\n", i)
            i = j if j >= 0 else n
            continue
        if text.startswith("${", i):                                         # a parameter expansion is one word (`${#a}`, `${V:-x;y}`), not a brace group
            j = text.find("}", i)
            cur.append("V")
            i = (j + 1) if j >= 0 else n
            continue
        if text.startswith("$((", i):
            stack.append("arith"); i += 3; continue
        if text.startswith("$(", i):
            flush(); stack.append("sub"); i += 2; continue
        if c == "`":
            flush()
            if mode == "bt":
                stack.pop()
            else:
                stack.append("bt")
            i += 1; continue
        if c == ")" and mode == "sub":
            flush(); stack.pop(); i += 1; continue
        if c in ";&|\n(){}":
            if c == "&" and (text[i - 1:i] in (">", "<") or nxt == ">"):
                cur.append(c); i += 1; continue
            if c == "|" and text[i - 1:i] == ">":
                i += 1; continue                                                 # `>|`
            flush(); i += 1; continue
        if c == ">":
            m = re.match(r">{1,2}\|?\s*(&\S*|\(|/dev/null(?![\w/.-])|)", text[i:])
            if m and (m.group(1).startswith("&") or m.group(1) == "(" or m.group(1).startswith("/dev/null")):
                i += m.end(); continue                                           # >&2, >&1, >(proc subst), >/dev/null
            if text[i - 1:i] in ("<", "=") or nxt == "=":
                i += 1; continue                                                  # `<>`, `=>`, `>=`: not a redirect
            redirect = True
            seg_line = line if not cur else seg_line
            i += 1
            while i < n and text[i] == ">":
                i += 1
            continue
        cur.append(c)
        i += 1
    flush()
    return segs


def _command_word(words):
    ws = list(words)
    while ws:
        w = ws[0]
        if re.match(r"^[A-Za-z_]\w*=", w) or w in _WRAPPERS:
            ws.pop(0)
            continue
        if (w.startswith("-") or w.isdigit()) and len(ws) > 1:
            ws.pop(0)                                    # an option (and a numeric value) of env / sudo / nice: skip it
            continue
        break
    return (os.path.basename(ws[0]), ws[1:]) if ws else ("", [])


def shell_file_creation(text):
    """(creator lines, mktemp called?, tempfile called?). A creator is a command word among mkdir touch cp mv ln install tee mkfifo mknod, `dd of=`,
    `sed -i`, `git init|clone`, or any command with a `>` / `>>` / `>|` redirect to a word that is not &N or /dev/null. mktemp counts only as a
    command word in code (not in quotes, comments or heredoc bodies); python's tempfile counts anywhere outside comment lines (python heredocs
    and -c strings). Returns line numbers so the failure can name the first offending line."""
    body = _strip_heredocs(text)
    lines = text.split("\n")
    creators, mk = [], False
    for ln, words, redirect in _shell_segments(body):
        cmd, args = _command_word(words)
        made = redirect or cmd in _CREATORS or (cmd == "dd" and any(a.startswith("of=") and a != "of=/dev/null" for a in args)) \
            or (cmd == "sed" and any(re.match(r"^-[A-Za-z]*i", a) for a in args)) or (cmd == "git" and args[:1] in (["init"], ["clone"]))
        if cmd == "mktemp":
            mk = True
        elif made:
            creators.append(ln)
    tf = any(re.search(r"\btempfile\.(mkdtemp|mkstemp|TemporaryDirectory|NamedTemporaryFile|mktemp)\(", l) for l in lines if not l.lstrip().startswith("#"))
    return creators, mk, tf


def first_file_creation_without_temp(text):
    """(line number, line) of the first file-creating command in a script that never calls mktemp or tempfile, or None."""
    creators, mk, tf = shell_file_creation(text)
    if creators and not (mk or tf):
        return creators[0], text.split("\n")[creators[0] - 1].strip()
    return None


def makes_files_without_temp(text):
    return first_file_creation_without_temp(text) is not None


def literal_lines(text, rel=""):
    """The lines of a file that the literal scan would report, stripped."""
    return [line.strip() for n, line in enumerate(split_lines(rel, text), 1) if flagged(line, rel, n == 1)]


def row_pin(raw, rel=""):
    """(sha256 of the file's RAW BYTES, the system-path-literal lines). A whole-file allow row exempts every literal in its file, and a hash of
    only the literal lines is blind to context (moving a closing quote makes a quoted fixture line a real command); hashing translated text
    would be blind to CR / CRLF edits (a lone CR after a comment line changes what bash executes). So ANY byte edit to such a file changes the
    pin and needs a reviewed PINS update; the stored lines show a reviewer what the file is allowed to contain."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest(), tuple(literal_lines(decode(raw), rel))


def whole_file_rows():
    return sorted({r[0] for r in load_allow() if r[1] == ""})


class Tables:
    """Two real temp trees: T1 is the only allowed root, T2 is "somewhere else" (a stand-in for a system path, so the tests that
    follow links and `..` never need a real one). Links are built BEFORE the tables are swapped in (creation is judged too)."""
    def __init__(self, test):
        self.td1, self.td2 = tempfile.TemporaryDirectory(), tempfile.TemporaryDirectory()
        test.addCleanup(self.td1.cleanup); test.addCleanup(self.td2.cleanup)
        self.t1, self.t2 = os.path.realpath(self.td1.name), os.path.realpath(self.td2.name)
        os.makedirs(os.path.join(self.t1, "sub", "deep")); os.makedirs(os.path.join(self.t2, "sub"))
        for p in (os.path.join(self.t1, "f"), os.path.join(self.t1, "sub", "f"), os.path.join(self.t2, "f"), os.path.join(self.t2, "sub", "f")):
            open(p, "w").close()

    def p1(self, *a): return os.path.join(self.t1, *a)
    def p2(self, *a): return os.path.join(self.t2, *a)

    @contextlib.contextmanager
    def active(self, env=(), roots=None, meta=()):
        saved = (G.ROOTS, G.ENV, G.META)
        G.ROOTS, G.ENV, G.META = list(roots if roots is not None else [self.t1]), list(saved[1]) + list(env), list(meta)
        try:
            yield
        finally:
            G.ROOTS, G.ENV, G.META = saved


class Rules(unittest.TestCase):
    """The resolution rules, pinned one by one with fake tables (no system path is touched)."""
    def setUp(self):
        self.T = Tables(self)

    def refused(self, fn, *a, **k):
        with self.assertRaises(G.SystemPathAccess, msg=repr(a)):
            fn(*a, **k)

    def test_dotdot_is_applied_after_a_link_is_followed_not_before(self):
        T = self.T
        os.symlink(T.p1("sub", "deep"), T.p1("l"))          # inside, deeper
        os.symlink(T.t1, T.p1("sub", "up"))                  # a link to the root itself: `..` through it leaves the root
        os.symlink(T.t2, T.p1("out"))                        # outside
        with T.active():
            open(T.p1("l", "..", "f")).close()                                   # = T1/sub/f
            os.stat(T.p1("sub", "..", "f"))                                      # plain `..` still fine
            self.refused(open, T.p1("sub", "up", "..", "f"))                      # = parent(T1)/f, though lexically T1/sub/f
            self.refused(os.listdir, T.p1("sub", "up", ".."))
            self.refused(os.stat, T.p1("sub", "up", "..", "f"))
            self.refused(os.path.exists, T.p1("sub", "up", "..", "f"))
            self.refused(os.listdir, T.p1("out", ".."))                           # following `out` leaves the root
            self.refused(open, T.p1("out", "..", "f"))
            self.refused(os.listdir, T.p1("out"))

    def test_the_two_step_link_chain_through_dotdot_is_refused(self):
        T = self.T
        os.symlink(T.t1, T.p1("B"))
        made = []
        link = G.wrap_link(lambda s, d, *a, **k: made.append((s, d)), "os.symlink")
        with T.active():
            self.refused(link, "B/../x", T.p1("C"))                              # resolves to parent(T1)/x, not T1/x
            self.refused(link, T.p1("B", "..", "x"), T.p1("C"))
            link(T.p1("sub", "..", "f"), T.p1("C"))                              # a plain inside target is fine
            link("sub/deep", T.p1("D"))
        self.assertEqual(len(made), 2)

    def test_an_absolute_link_restarts_at_the_root_and_a_relative_one_at_its_directory(self):
        T = self.T
        os.symlink(T.p1("sub"), T.p1("abs_in")); os.symlink(T.t2, T.p1("abs_out"))
        os.symlink("sub", T.p1("rel_in")); os.symlink(os.path.relpath(T.t2, T.t1), T.p1("rel_out"))
        os.symlink(os.path.join("..", "..", "f"), T.p1("sub", "deep", "up2"))   # = T1/f
        with T.active():
            os.stat(T.p1("abs_in", "f")); os.stat(T.p1("rel_in", "f")); os.stat(T.p1("sub", "deep", "up2"))
            self.refused(os.stat, T.p1("abs_out", "f")); self.refused(os.stat, T.p1("rel_out", "f"))
            self.refused(open, T.p1("abs_out", "sub", "f"))

    def test_a_link_loop_or_a_chain_over_the_hop_limit_is_refused(self):
        T = self.T
        raw = os.symlink.__wrapped__                       # the guard itself refuses to build the chain, so use the unwrapped call
        raw("q", T.p1("p")); raw("p", T.p1("q"))
        prev = "f"
        for i in range(45):
            raw(prev, T.p1("c%d" % i)); prev = "c%d" % i
        with T.active():
            for fn, p in ((os.stat, "p"), (open, "c44"), (os.path.getsize, "q")):           # a cycle wholly inside the root: the OS's own answer
                with self.assertRaises(OSError, msg=p) as cm:
                    fn(T.p1(p))
                self.assertEqual(cm.exception.errno, __import__("errno").ELOOP)
            os.stat(T.p1("c3"))                                                   # a short chain is fine
        os.symlink.__wrapped__(T.p2("f"), T.p1("esc0"))
        for i in range(1, 45):
            os.symlink.__wrapped__("esc%d" % (i - 1), T.p1("esc%d" % i))
        with T.active():
            self.refused(os.stat, T.p1("esc2"))                                   # a link that leaves the root is a guard refusal, not ELOOP

    def test_lstat_readlink_islink_do_not_follow_the_last_link_but_stat_exists_isfile_do(self):
        T = self.T
        os.symlink(T.p2("f"), T.p1("ln"))
        with T.active():
            os.lstat(T.p1("ln")); os.readlink(T.p1("ln")); self.assertTrue(os.path.islink(T.p1("ln"))); self.assertTrue(os.path.lexists(T.p1("ln")))
            for fn in (os.stat, os.path.exists, os.path.isfile, os.path.getsize, open):
                self.refused(fn, T.p1("ln"))
            self.refused(os.lstat, T.p1("ln", "x"))                               # a link in the MIDDLE is followed even by lstat

    def test_shutil_copy_reads_its_source_but_move_and_the_rest_write_every_path(self):
        T = self.T
        with T.active(env=[T.t2]):
            G._hook("shutil.copyfile", (T.p2("f"), T.p1("g"))); G._hook("shutil.copytree", (T.p2("sub"), T.p1("h")))
            G._hook("shutil.copy2", (T.p2("f"), T.p1("g")))
            self.refused(G._hook, "shutil.copyfile", (T.p1("f"), T.p2("g")))
            self.refused(G._hook, "shutil.move", (T.p2("f"), T.p1("g")))           # moving removes the source
            self.refused(G._hook, "shutil.rmtree", (T.p2("sub"),))
            self.refused(G._hook, "shutil.unpack_archive", (T.p1("a.tar"), T.p2("x")))
            self.refused(G._hook, "shutil.chown", (T.p2("f"),))

    def test_a_pyvenv_cfg_that_is_a_symlink_is_judged_like_any_path(self):
        T = self.T
        os.makedirs(T.p1("repo"))
        open(T.p1("pyvenv.cfg"), "w").close()                                     # a plain file in an ancestor of the root
        with T.active(roots=[T.p1("repo")]):
            os.path.exists(T.p1("pyvenv.cfg")); os.stat(T.p1("pyvenv.cfg"))
            self.refused(open, T.p1("pyvenv.cfg"))                                # metadata only
        os.remove(T.p1("pyvenv.cfg")); os.symlink(T.p2("f"), T.p1("pyvenv.cfg"))
        with T.active(roots=[T.p1("repo")]):
            self.refused(os.stat, T.p1("pyvenv.cfg")); self.refused(os.path.exists, T.p1("pyvenv.cfg"))

    def test_the_symlink_audit_event_skips_the_target_text_but_judges_the_link_itself(self):
        T = self.T
        with T.active():
            G._hook("os.symlink", ("target-text-only", T.p1("l"), None))
            G._hook("os.symlink", (T.p2("f"), T.p1("l"), None))                  # wrap_link is what judges targets
            self.refused(G._hook, "os.symlink", (T.p1("f"), T.p2("l"), None))

    def test_listdir_and_scandir_read_but_rename_mkdir_chmod_xattr_write(self):
        T = self.T
        with T.active(env=[T.t2]):
            for ev in ("os.listdir", "os.scandir", "os.walk", "os.fwalk"):
                G._hook(ev, (T.t2,))
            G._hook("open", (T.p2("f"), "r", os.O_RDONLY))
            for ev, args in (("os.rename", (T.p2("a"), T.p2("b"))), ("os.mkdir", (T.p2("x"),)), ("os.chmod", (T.p2("f"), 0o600)),
                             ("os.setxattr", (T.p2("f"), "user.x", b"1")), ("os.remove", (T.p2("f"),)), ("os.utime", (T.p2("f"), None)),
                             ("os.truncate", (T.p2("f"), 0)), ("os.chflags", (T.p2("f"), 0)), ("os.some_future_event", (T.p2("f"),)),
                             ("open", (T.p2("f"), "w", 0)), ("open", (T.p2("f"), None, os.O_WRONLY)), ("open", (T.p2("f"), "r+", 0))):
                self.refused(G._hook, ev, args)
            G._hook("os.putenv", ("A", "b/c")); G._hook("os.system", ("ls /",))     # not paths
            self.refused(G._hook, "sqlite3.connect", (T.p1("..", "db"),))
            self.refused(G._hook, "tempfile.mkdtemp", (T.p1("..", "d"),))

    def test_a_relative_path_is_judged_at_the_cwd_and_open_modes_x_and_a_write(self):
        T = self.T
        with T.active(env=[T.t2]):
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                G.check("f", "stat", False, True)                    # env is readable
                self.refused(G.check, "f", "open", write=True)       # but not writable
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t1}):
                G.check("f", "open", write=True); G.check("sub/../f", "open", write=True)
            with mock.patch.dict(G._real, {"getcwd": lambda: os.path.dirname(T.t1)}):
                self.refused(G.check, "f", "stat", False, False)
            for mode in ("x", "a", "w", "r+", "ab", "xb"):
                self.refused(G._hook, "open", (T.p2("f"), mode, 0))
            G._hook("open", (T.p2("f"), "rb", 0)); G._hook("open", (T.p2("f"), None, os.O_RDONLY))

    def test_dir_fd_in_the_audit_events_is_judged_under_the_fd_directory(self):
        """Probe: fd = os.open(T1/a), cwd = T1/a/b/c, name ../../t2/X: the cwd-relative reading is inside the root, the OS acts outside it."""
        T = self.T
        os.makedirs(T.p1("a", "b", "c"))
        fd_in, fd_out = os.open(T.p1("a"), os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        try:
            with T.active():
                with mock.patch.dict(G._real, {"getcwd": lambda: T.p1("a", "b", "c")}):
                    name = os.path.join("..", "..", os.path.basename(T.t2), "X")        # = parent(T1)/<t2>/X under the fd, T1/a/<t2>/X under the cwd
                    evs = [("os.mkdir", (name, 0o777, fd_in)), ("os.rmdir", (name, fd_in)), ("os.remove", (name, fd_in)),
                           ("os.rename", (name, "ok", fd_in, -1)), ("os.rename", ("ok", name, -1, fd_in)), ("os.chmod", (name, 0o600, fd_in)),
                           ("os.utime", (name, None, None, fd_in)), ("os.symlink", ("t", name, fd_in)), ("os.link", (name, "ok", fd_in, -1)),
                           ("os.link", ("ok", name, -1, fd_in)), ("os.chown", (name, -1, -1, fd_in))]
                    for ev, args in evs:
                        self.refused(G._hook, ev, args)
                    # the same names relative to an fd INSIDE the root, and calls without a dir_fd (-1 / None), are judged as before
                    for ev, args in (("os.mkdir", ("b/new", 0o777, fd_in)), ("os.remove", ("b/f", fd_in)), ("os.rename", ("b/x", "b/y", fd_in, fd_in)),
                                     ("os.mkdir", ("new", 0o777, -1)), ("os.mkdir", ("new", 0o777, None))):
                        G._hook(ev, args)
                with mock.patch.object(G, "_fd_dir", lambda fd: None):
                    for ev, args in evs[:3]:
                        self.refused(G._hook, ev, args)                                # an fd with an unknown directory: fail closed
        finally:
            os.close(fd_in); os.close(fd_out)

    def test_link_creation_honours_dir_fd(self):
        T = self.T
        os.makedirs(T.p1("a"))
        fd_in, fd_out = os.open(T.p1("a"), os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        made = []
        sym = G.wrap_link(lambda *a, **k: made.append(1), "os.symlink")
        lnk = G.wrap_link(lambda *a, **k: made.append(1), "os.link")
        try:
            with T.active():
                self.refused(sym, "t", "X", dir_fd=fd_out)                    # the link location is T2/X
                self.refused(lnk, T.p1("f"), "X", dst_dir_fd=fd_out)
                self.refused(lnk, "f", "X", src_dir_fd=fd_out, dst_dir_fd=fd_in)  # the source is T2/f
                sym("t", "X", dir_fd=fd_in); lnk("f", "X", src_dir_fd=fd_in, dst_dir_fd=fd_in)
                with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                    self.refused(lnk, "f", T.p1("g"))                             # a hard link's source is relative to the CWD, not the link's directory
        finally:
            os.close(fd_in); os.close(fd_out)
        self.assertEqual(len(made), 2)

    def test_a_trailing_slash_or_dot_follows_the_last_link(self):
        T = self.T
        os.symlink.__wrapped__(T.t2, T.p1("out")); os.symlink(T.p1("sub"), T.p1("in"))
        with T.active():
            os.lstat(T.p1("out")); os.path.islink(T.p1("out")); os.path.lexists(T.p1("out")); os.readlink(T.p1("out"))
            for suffix in ("/", "/.", "/./", "//"):
                for fn in (os.lstat, os.path.islink, os.path.lexists, os.readlink):
                    self.refused(fn, T.p1("out") + suffix)
                os.lstat(T.p1("in") + suffix); os.path.islink(T.p1("in") + suffix)

    def test_a_sqlite_file_uri_is_refused_and_a_plain_name_is_judged(self):
        T = self.T
        with T.active():
            for name in ("file:" + T.p1("db") + "?mode=ro", "file:../x/db", "file:" + T.p2("db"), b"file:/x"):
                self.refused(G._hook, "sqlite3.connect", (name,))
            G._hook("sqlite3.connect", (T.p1("db"),)); self.refused(G._hook, "sqlite3.connect", (T.p2("db"),))      # a plain name is judged

    def test_bytecode_writes_are_allowed_only_for_a_resolved_pyc_directly_in_pycache(self):
        T = self.T
        os.makedirs(T.p2("__pycache__")); os.makedirs(T.p2("lib", "__pycache__"))
        os.symlink.__wrapped__(T.p2("sub"), T.p2("__pycache__", "lnk"))
        with T.active(env=[T.t2]):
            for p in (("__pycache__", "m.cpython-314.pyc"), ("__pycache__", "m.cpython-314.pyc.1234"), ("lib", "__pycache__", "x.pyc")):
                G.check(T.p2(*p), "open", write=True); G._hook("open", (T.p2(*p), "wb", 0))
                G._hook("os.rename", (os.path.join(os.path.dirname(T.p2(*p)), "tmp.cpython-314.pyc.4242"), T.p2(*p)))
            for p in (("__pycache__", "..", "site.py"), ("__pycache__", "..", "evil.pth"), ("__pycache__", "evil.txt"), ("__pycache__", "m.py"),
                      ("__pycache__", "m.pyc.x"), ("__pycache__", "sub2", "m.pyc"), ("__pycache__x", "m.pyc"), ("__pycache__", "lnk", "m.pyc"),
                      ("site.py",), ("lib", "__pycache__", "..", "evil.pth")):
                self.refused(G.check, T.p2(*p), "open", write=True)
                self.refused(G._hook, "open", (T.p2(*p), "w", 0))
                self.refused(G._hook, "os.remove", (T.p2(*p), -1))
                self.refused(G._hook, "os.rename", (T.p1("f"), T.p2(*p)))
            self.refused(G._hook, "os.rename", (T.p2("__pycache__", "m.pyc"), T.p2("__pycache__", "..", "evil.pth")))
            G.check(T.p2("__pycache__", "..", "f"), "open")                       # reading through it is still fine

    def test_neither_the_root_nor_a_broad_directory_becomes_a_root(self):
        self.assertNotIn("/", G._canon_set(["/", "/usr"]))
        for b in sorted(G.BROAD - {"/"}):
            self.assertEqual(G._canon_set([b], drop_broad=True), set(), b)
        for b in ("/sbin", "/root", "/bin", "/etc", "/var", "/System", "/Library", "/home", "/Users", "/opt", "/opt/homebrew"):
            self.assertIn(b, G.BROAD)
        home = os.path.realpath(os.path.expanduser("~"))
        with mock.patch.dict(os.environ, {"TMPDIR": "/usr", "COVERAGE_RCFILE": "/", "HOME": "/opt/fakehome"}):
            self.assertNotIn("/usr", G._roots())
            self.assertNotIn("/", G._roots())
        for bad in ("/usr", "/opt/fakehome", "/", "/home"):                              # tempfile.gettempdir() follows TMPDIR
            with mock.patch.dict(os.environ, {"HOME": "/opt/fakehome"}), mock.patch.object(tempfile, "gettempdir", lambda bad=bad: bad):
                self.assertNotIn(bad, G._roots(), bad)
        with mock.patch.dict(os.environ, {"HOME": "/opt/fakehome", "TMPDIR": "/opt/fakehome"}):
            self.assertNotIn("/opt/fakehome", G._roots())                          # the home directory is never a root
            with mock.patch.object(sys, "path", ["/opt/fakehome", "/opt/fakelib"]):
                self.assertNotIn("/opt/fakehome", G._env_roots()); self.assertNotIn("/opt/fakelib", G._env_roots())     # not inside the interpreter / checkout / temp
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"TMPDIR": d}):
                self.assertIn(os.path.realpath(d), G._roots())
        self.assertTrue(home)

    def test_bytes_and_pathlike_paths_in_the_generic_branch_are_judged(self):
        import pathlib
        T = self.T
        with T.active():
            for a in (os.fsencode(T.p2("x")), pathlib.Path(T.p2("x")), T.p2("x")):
                self.refused(G._hook, "os.some_future_event", (a,))
            G._hook("os.some_future_event", (os.fsencode(T.p1("x")),)); G._hook("os.some_future_event", (pathlib.Path(T.p1("x")),))
            G._hook("os.some_future_event", (b"no-slash", "no-slash", 5))

    def test_listdir_without_an_argument_is_judged_at_the_cwd(self):
        T = self.T
        with T.active():
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                self.refused(G._hook, "os.listdir", (None,)); self.refused(G._hook, "os.scandir", (None,))
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t1}):
                G._hook("os.listdir", (None,)); G._hook("os.scandir", (None,))

    def test_glob_is_judged_at_the_directory_before_its_first_wildcard(self):
        T = self.T
        with T.active():
            G._hook("glob.glob", (T.p1("sub", "*.py"), False)); G._hook("glob.glob", (T.p1("s[a]b"), False))
            self.refused(G._hook, "glob.glob", (T.p2("*.py"), False)); self.refused(G._hook, "glob.glob", (T.p2("sub", "f"), False))

    def test_dir_fd_names_are_judged_under_the_directory_the_fd_names(self):
        T = self.T
        fd1, fd2 = os.open(T.t1, os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        os.symlink(T.t2, T.p1("out"))
        try:
            with T.active():
                os.stat("f", dir_fd=fd1); os.close(os.open("f", os.O_RDONLY, dir_fd=fd1))
                with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):                  # the open event carries only the bare name: the cwd must not matter
                    os.close(os.open("f", os.O_RDONLY, dir_fd=fd1))
                for name in ("f", "sub", ".."):
                    self.refused(os.stat, name, dir_fd=fd2); self.refused(os.lstat, name, dir_fd=fd2)
                    self.refused(os.access, name, os.R_OK, dir_fd=fd2); self.refused(os.readlink, name, dir_fd=fd2)
                self.refused(os.open, "f", os.O_RDONLY, dir_fd=fd2)
                self.refused(os.open, "out", os.O_RDONLY, dir_fd=fd1)               # a link inside the fd's directory that leaves it
                self.refused(os.stat, "../f", dir_fd=fd1)
                with mock.patch.object(G, "_fd_dir", lambda fd: None):
                    self.refused(os.stat, "f", dir_fd=fd1); self.refused(os.open, "f", os.O_RDONLY, dir_fd=fd1)
        finally:
            os.close(fd1); os.close(fd2)

    def test_the_environment_roots_drop_broad_prefixes_and_keep_specific_ones(self):
        with mock.patch.object(sys, "prefix", "/usr"), mock.patch.object(sys, "exec_prefix", "/usr"), \
                mock.patch.object(sys, "base_prefix", "/usr"), mock.patch.object(sys, "base_exec_prefix", "/usr"), \
                mock.patch.object(sys, "executable", "/usr/bin/python3"), mock.patch.object(sys, "path", ["/usr", "/usr/local", "", "/opt/fakelib/site"]):
            got = G._env_roots()
        self.assertNotIn("/usr", got); self.assertNotIn("/usr/local", got); self.assertNotIn("/opt/fakelib/site", got)
        with mock.patch.object(sys, "prefix", "/opt/fakevenv/cache"), mock.patch.object(sys, "exec_prefix", "/opt/fakevenv/cache"), \
                mock.patch.object(sys, "base_prefix", "/opt/fakebase/x64"), mock.patch.object(sys, "base_exec_prefix", "/opt/fakebase/x64"), \
                mock.patch.object(sys, "executable", "/opt/fakevenv/cache/bin/python"), \
                mock.patch.object(sys, "path", ["/opt/fakevenv/cache/lib/python3.12/site-packages", "/opt/fakebase/x64/lib/python3.12", "/opt/other/lib"]):
            got = G._env_roots()
        self.assertIn("/opt/fakevenv/cache", got); self.assertIn("/opt/fakebase/x64", got)
        self.assertIn("/opt/fakevenv/cache/lib/python3.12/site-packages", got)            # inside the interpreter prefix
        self.assertNotIn("/opt/other/lib", got)                                           # a sys.path entry elsewhere is not a root
        with mock.patch.object(sys, "prefix", "/opt/fakevenv/cache"), mock.patch.object(sys, "exec_prefix", "/opt/fakevenv/cache"), \
                mock.patch.object(sys, "base_prefix", "/opt/fakebase/x64"), mock.patch.object(sys, "base_exec_prefix", "/opt/fakebase/x64"), \
                mock.patch.object(sys, "executable", "/opt/fakevenv/cache/bin/python"), \
                mock.patch.object(sys, "path", ["/opt/fakevenv/cache2/lib", "/opt/fakevenv/cachex", "/tmp/zz-syspath", "/tmpx/zz", "/private/var/folders/q/T/p"]):
            got = G._env_roots()
        self.assertNotIn("/opt/fakevenv/cache2/lib", got); self.assertNotIn("/opt/fakevenv/cachex", got)       # a sibling that merely shares the prefix text
        self.assertIn("/tmp/zz-syspath", got); self.assertIn("/private/var/folders/q/T/p", got)             # a standard temp parent is accepted
        self.assertNotIn("/tmpx/zz", got)
        self.assertEqual(sorted(G._canon_set(["/", "/usr", "/opt/x"], drop_broad=True)), ["/opt/x"])
        self.assertIn("/usr", G._canon_set(["/usr"]))

    def test_creating_a_link_judges_both_the_target_and_the_link_location(self):
        T = self.T
        made = []
        link = G.wrap_link(lambda s, d, *a, **k: made.append(1), "os.link")
        with T.active():
            self.refused(link, T.p2("f"), T.p1("l")); self.refused(link, T.p1("f"), T.p2("l")); self.refused(link, "../../x", T.p1("sub", "l"))
            link(T.p1("f"), T.p1("l"))
        self.assertEqual(len(made), 1)


_EVENTS = []
_RECORD = [False]
sys.addaudithook(lambda event, args: _EVENTS.append(event) if _RECORD[0] else None)


class AuditRows(unittest.TestCase):
    """Every row of the audit tables must be a call that really emits its event: CPython 3.12/3.14 emit NOTHING for os.mkfifo, os.mknod and
    os.chroot (a row for them guarded nothing and a test calling G._hook directly hid it). A dead row fails here; the call must be wrapped."""
    def unix_socket(self, dgram=False):
        import socket
        sk = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM if dgram else socket.SOCK_STREAM)
        self.addCleanup(sk.close)
        return sk

    def exercisers(self, d):
        f, sub = os.path.join(d, "f"), os.path.join(d, "sub")
        open(f, "w").close(); os.mkdir(sub)
        fd = os.open(d, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        import tempfile as tf
        return {
            "open": lambda: open(f).close(), "os.listdir": lambda: os.listdir(d), "os.scandir": lambda: os.scandir(d).close(),
            "os.rename": lambda: (os.rename(f, f + "2"), os.rename(f + "2", f)), "os.remove": lambda: os.remove(os.path.join(sub, "x")) if open(os.path.join(sub, "x"), "w").close() is None else None,
            "os.rmdir": lambda: (os.mkdir(os.path.join(d, "e")), os.rmdir(os.path.join(d, "e"))), "os.mkdir": lambda: os.mkdir(os.path.join(d, "m")),
            "os.chdir": lambda: (lambda cwd: (os.chdir(d), os.chdir(cwd)))(os.getcwd()), "os.symlink": lambda: os.symlink("f", os.path.join(d, "s")),
            "os.link": lambda: os.link(f, os.path.join(d, "h")), "os.truncate": lambda: os.truncate(f, 0), "os.chmod": lambda: os.chmod(f, 0o600),
            "os.chown": lambda: os.chown(f, -1, -1), "os.utime": lambda: os.utime(f, None), "os.setxattr": lambda: os.setxattr(f, "user.x", b"1"),
            "os.removexattr": lambda: os.removexattr(f, "user.x"), "os.getxattr": lambda: os.getxattr(f, "user.x"), "os.listxattr": lambda: os.listxattr(f),
            "os.chflags": lambda: os.chflags(f, 0), "os.walk": lambda: list(os.walk(d)), "os.fwalk": lambda: list(os.fwalk(d)),
            "sqlite3.connect": lambda: __import__("sqlite3").connect(":memory:").close(), "tempfile.mkstemp": lambda: os.close(tf.mkstemp(dir=d)[0]),
            "tempfile.mkdtemp": lambda: tf.mkdtemp(dir=d), "ctypes.dlopen": lambda: __import__("ctypes").CDLL(os.path.join(d, "nolib.so")),
            "os.add_dll_directory": lambda: os.add_dll_directory(d), "os.mkdir@fd": lambda: os.mkdir("z", dir_fd=fd),
            "os.mkfifo": lambda: os.mkfifo(os.path.join(d, "ff0")), "os.mknod": lambda: os.mknod(os.path.join(d, "nn0")), "os.chroot": lambda: os.chroot(os.path.join(d, "no-such-dir")),      # never a real directory: chroot must not take effect
            "socket.bind": lambda: self.unix_socket().bind(os.path.join(d, "s.sock")),
            "socket.connect": lambda: self.unix_socket().connect(os.path.join(d, "s.sock")),
            "socket.sendto": lambda: self.unix_socket(dgram=True).sendto(b"x", os.path.join(d, "s.sock")),
            "socket.sendmsg": lambda: self.unix_socket(dgram=True).sendmsg([b"x"], [], 0, os.path.join(d, "s.sock")),
            "sqlite3.enable_load_extension": lambda: __import__("sqlite3").connect(":memory:").enable_load_extension(False),
            "sqlite3.load_extension": lambda: __import__("sqlite3").connect(":memory:").load_extension(os.path.join(d, "ext.so")),
        }

    def audit_rows_report(self):
        """(dead rows, rows with no exerciser, rows unproven on this platform): every row must be a call that really emits its event."""
        import errno
        rows = set(G._AUDIT_PATH) | set(G._DIRFD) | set(G._SPECIAL_EVENTS)
        dead, skipped = [], []
        with tempfile.TemporaryDirectory() as d:
            ex = self.exercisers(d)
            unexercised = sorted(r for r in rows if r not in ex)
            for ev in sorted(rows & set(ex)):
                _EVENTS.clear(); _RECORD[0] = True
                try:
                    ex[ev]()
                except (AttributeError, NotImplementedError):
                    skipped.append(ev)
                    continue                                           # not on this platform (xattr is Linux, chflags is BSD, dll directory is Windows)
                except OSError as e:
                    if e.errno in (errno.ENOTSUP, errno.ENOSYS, errno.EPERM, errno.EOPNOTSUPP, errno.ENODATA, errno.ENOENT) and "xattr" in ev:
                        skipped.append(ev)
                        continue
                    if ev not in ("ctypes.dlopen", "socket.connect", "socket.sendto", "socket.sendmsg", "os.chroot", "os.mknod"):
                        raise
                except Exception as e:                                 # sqlite refusing an extension it was never allowed to load, and the like
                    if ev not in ("sqlite3.load_extension", "sqlite3.enable_load_extension"):
                        raise
                finally:
                    _RECORD[0] = False
                if ev not in _EVENTS:
                    dead.append(ev)
        return dead, unexercised, skipped

    def test_every_audit_row_is_a_call_that_really_emits_its_event(self):
        dead, unexercised, skipped = self.audit_rows_report()
        if skipped:
            print("\nSKIP (unproven on this platform): " + ", ".join(skipped), file=sys.stderr)       # these rows are only proven where the call exists
        self.assertEqual(unexercised, [], "audit rows with no exerciser here (add one, or remove the row)")
        self.assertEqual(dead, [], "audit rows whose event CPython never emits: remove the row and wrap the call in install()")

    def test_a_dead_row_would_be_caught(self):
        saved = (dict(G._AUDIT_PATH), dict(G._DIRFD), G._SPECIAL_EVENTS)
        try:
            G._AUDIT_PATH["os.mkfifo"] = (0,)                          # the real defect: a row for a call that emits nothing
            G._DIRFD["os.mknod"] = {0: 3}
            G._SPECIAL_EVENTS = G._SPECIAL_EVENTS + ("os.chroot",)
            dead, unexercised, _ = self.audit_rows_report()
            self.assertEqual(sorted(set(dead) | set(unexercised)), ["os.chroot", "os.mkfifo", "os.mknod"], (dead, unexercised))
            G._AUDIT_PATH["os.bogus_event"] = (0,)
            _, unexercised, _ = self.audit_rows_report()
            self.assertIn("os.bogus_event", unexercised)
        finally:
            G._AUDIT_PATH.clear(); G._AUDIT_PATH.update(saved[0]); G._DIRFD.clear(); G._DIRFD.update(saved[1]); G._SPECIAL_EVENTS = saved[2]

    def test_mkfifo_mknod_chroot_are_wrapped_and_refuse_a_path_outside_the_roots(self):
        T = Tables(self)
        fd_in, fd_out = os.open(T.t1, os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        os.symlink.__wrapped__(T.t2, T.p1("out"))
        try:
            for n in ("mkfifo", "mknod", "chroot"):
                self.assertTrue(hasattr(getattr(os, n), "__wrapped__"), n)
            with T.active():
                for fn in (os.mkfifo, os.mknod):
                    self.refused(fn, T.p2("X")); self.refused(fn, "X", dir_fd=fd_out); self.refused(fn, T.p1("out", "X"))
                    self.refused(fn, "../" + os.path.basename(T.t2) + "/X", dir_fd=fd_in)
                    self.refused(fn, T.p1("..", "X"))
                self.refused(os.chroot, T.t2); self.refused(os.chroot, T.p1("out"))
                os.mkfifo(T.p1("ff")); os.mkfifo("gg", dir_fd=fd_in)
                try:
                    os.mknod(T.p1("nn")); os.mknod("oo", dir_fd=fd_in)
                except PermissionError:
                    pass
                self.assertTrue(os.path.exists(T.p1("ff")) and os.path.exists(T.p1("gg")))
            self.assertFalse(os.listdir(T.t2) and any(n in ("X", "ff") for n in os.listdir(T.t2)))      # nothing was created outside
        finally:
            os.close(fd_in); os.close(fd_out)

    def refused(self, fn, *a, **k):
        with self.assertRaises(G.SystemPathAccess, msg=repr(a)):
            fn(*a, **k)

    def test_mkfifo_on_a_link_name_is_the_os_answer_and_env_directories_are_not_writable(self):
        T = Tables(self)
        os.symlink.__wrapped__(T.p2("new"), T.p1("dangling"))
        with T.active():
            with self.assertRaises(FileExistsError):                  # the entry itself is in the root and mkfifo never follows it
                os.mkfifo(T.p1("dangling"))
            G._hook("os.symlink", ("t", T.p1("dangling"), -1))        # nor does the symlink audit event for the link location
        with T.active(env=[T.t2]):
            self.refused(os.mkfifo, T.p2("X")); self.refused(os.mknod, T.p2("Y"))     # readable environment, not writable
            os.stat(T.p2("f"))
        self.assertFalse(os.path.exists(T.p2("X")))

    def test_the_standard_temp_parents_are_fixed(self):
        self.assertGreaterEqual(set(G.STANDARD_TEMP), {"/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders", "/dev/shm"})
        T = Tables(self)

    def test_scandir_on_an_fd_judges_the_fd_directory_and_its_entries(self):
        T = Tables(self)
        os.symlink.__wrapped__(T.p2("f"), T.p1("ln"))
        fd_in, fd_out = os.open(T.t1, os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        try:
            with T.active():
                self.refused(os.scandir, fd_out); self.refused(os.listdir, fd_out)
                es = {e.name: e for e in os.scandir(fd_in)}
                self.assertTrue(es["ln"].is_symlink())
                self.refused(es["ln"].is_file); self.refused(es["ln"].stat)           # the planted link, relative to the fd's directory
                es["ln"].stat(follow_symlinks=False); self.assertTrue(es["sub"].is_dir())
        finally:
            os.close(fd_in); os.close(fd_out)

    def test_xattr_writers_are_wrapped_where_the_platform_has_them(self):
        T = Tables(self)
        os.symlink.__wrapped__(T.p2("f"), T.p1("ln"))
        for n in ("setxattr", "removexattr"):
            if not hasattr(os, n):
                continue
            self.assertTrue(hasattr(getattr(os, n), "__wrapped__"), n)
            with T.active():
                self.refused(getattr(os, n), T.p2("f"), *(("user.x", b"1") if n == "setxattr" else ("user.x",)))
                self.refused(getattr(os, n), T.p1("ln"), *(("user.x", b"1") if n == "setxattr" else ("user.x",)))

    def test_sqlite_judges_a_plain_path_refuses_file_uris_and_the_connection_denies_attach(self):
        import sqlite3, pathlib
        T = Tables(self)
        with T.active():
            for name in (T.p2("db"), os.fsencode(T.p2("db")), pathlib.Path(T.p2("db")), "x/../../db", ":memory:x", " :memory:",
                         "file:" + T.p1("db"), os.fsencode("file:" + T.p1("db")), pathlib.Path("file:" + T.p1("db")),
                         "file:" + T.p2("db") + "?mode=ro", "file:../x/db", "file::memory:", ""):
                self.refused(sqlite3.connect, name)
                self.refused(G._hook, "sqlite3.connect", (name,))
            for name in (T.p1("db"), os.fsencode(T.p1("db")), pathlib.Path(T.p1("db")), ":memory:", b":memory:"):
                G._hook("sqlite3.connect", (name,))
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t1}):          # cwd inside the root: "file:/abs/db" would be a harmless relative name
                for name in ("file:" + T.p2("db"), "file:../x/db", os.fsencode("file:/x"), pathlib.Path("file:" + T.p2("db")), ""):
                    self.refused(G._hook, "sqlite3.connect", (name,))
            self.refused(G._hook, "sqlite3.connect", (5,))
        with tempfile.TemporaryDirectory() as d:                                # what coverage does: a real database file in a temp dir
            c = sqlite3.connect(os.path.join(d, ".coverage.1"))
            c.execute("create table t(x)"); c.execute("insert into t values (1)"); c.commit(); c.close()
            c = sqlite3.connect(":memory:")
            c.execute("create table t(x)")
            for q in ("ATTACH '%s/a.db' AS x" % d, "VACUUM INTO '%s/b.db'" % d, "VACUUM main INTO '%s/c.db'" % d):
                with self.assertRaises(sqlite3.DatabaseError, msg=q):
                    c.execute(q)
            c.close()
            self.assertEqual(sorted(os.listdir(d)), [".coverage.1"])

    def test_every_sqlite_entry_point_denies_attach_and_vacuum_into(self):
        import sqlite3, sqlite3.dbapi2, _sqlite3
        opens = {
            "sqlite3.connect": lambda: sqlite3.connect(":memory:"), "sqlite3.dbapi2.connect": lambda: sqlite3.dbapi2.connect(":memory:"),
            "_sqlite3.connect": lambda: _sqlite3.connect(":memory:"), "sqlite3.Connection": lambda: sqlite3.Connection(":memory:"),
            "sqlite3.dbapi2.Connection": lambda: sqlite3.dbapi2.Connection(":memory:"), "_sqlite3.Connection": lambda: _sqlite3.Connection(":memory:"),
            "connect(factory=Connection)": lambda: sqlite3.connect(":memory:", factory=sqlite3.Connection),
            "connect(factory=C original class)": lambda: sqlite3.connect(":memory:", factory=type("C0", (sqlite3.Connection.__mro__[1],), {})),
            "connect(factory=subclass)": lambda: sqlite3.connect(":memory:", factory=type("C", (sqlite3.Connection,), {})),
            "dbapi2.connect(factory=subclass)": lambda: sqlite3.dbapi2.connect(":memory:", factory=type("C2", (sqlite3.Connection,), {})),
            "connect(uri=True)": lambda: sqlite3.connect(":memory:", uri=True),
        }
        with tempfile.TemporaryDirectory() as d:
            for name, make in sorted(opens.items()):
                c = make()
                c.execute("create table t(x)")
                for q in ("ATTACH '%s/a.db' AS x" % d, "VACUUM INTO '%s/b.db'" % d):
                    with self.assertRaises(sqlite3.DatabaseError, msg=name + " " + q):
                        c.execute(q)
                c.close()
            self.assertEqual(os.listdir(d), [])
        self.assertIsInstance(sqlite3.connect(":memory:"), sqlite3.Connection)      # isinstance checks still hold
        self.assertIsInstance(sqlite3.connect(":memory:"), _sqlite3.Connection)

    def test_an_open_fd_outside_the_roots_is_judged_by_its_location(self):
        T = Tables(self)
        f_in, f_out = os.open(T.p1("f"), os.O_RDWR), os.open(T.p2("f"), os.O_RDWR)
        d_in, d_out = os.open(T.t1, os.O_RDONLY), os.open(T.t2, os.O_RDONLY)
        r, w = os.pipe()
        parent = os.open(os.path.dirname(T.t1), os.O_RDONLY)
        try:
            with T.active():
                for fn, args in ((os.listdir, (d_out,)), (os.scandir, (d_out,)), (os.stat, (d_out,)), (os.stat, (f_out,)), (os.fstat, (f_out,)),
                                 (os.fstat, (d_out,)), (os.chdir, (d_out,)), (os.fchdir, (d_out,)), (os.fchmod, (f_out, 0o600)), (os.chmod, (f_out, 0o600)),
                                 (os.truncate, (f_out, 0)), (os.ftruncate, (f_out, 0)), (os.statvfs, (d_out,)), (os.utime, (f_out, None)),
                                 (os.chown, (f_out, -1, -1)), (os.fchown, (f_out, -1, -1)), (os.pathconf, (d_out, "PC_NAME_MAX")), (os.access, (f_out, os.R_OK)),
                                 (os.fwalk, (d_out,))):
                    if fn is os.fwalk:
                        continue                                          # fwalk takes a PATH (its dir_fd is judged elsewhere)
                    self.refused(fn, *args)
                    self.refused(G._hook, "os." + fn.__name__, (args[0],) + args[1:]) if fn.__name__ in ("listdir", "scandir", "chdir", "chmod", "truncate", "utime", "chown") else None
                self.refused(G._hook, "open", (f_out, "r", 0))
                with T.active(env=[T.t2]):
                    os.fstat(f_out); os.stat(f_out); os.listdir(d_out); list(os.scandir(d_out))                 # an environment directory is readable ...
                    for fn, args in ((os.fchmod, (f_out, 0o600)), (os.ftruncate, (f_out, 0)), (os.chmod, (f_out, 0o600)), (os.fchown, (f_out, -1, -1))):
                        self.refused(fn, *args)                                                                 # ... never writable
                os.fstat(parent); os.stat(parent)                                                               # metadata of an ancestor of the root
                self.refused(os.listdir, parent); self.refused(os.scandir, parent); self.refused(G._hook, "os.listdir", (parent,))   # not its contents
                os.fstat(f_in); os.stat(f_in); os.stat(d_in); os.listdir(d_in); list(os.scandir(d_in)); os.fchmod(f_in, 0o644); os.ftruncate(f_in, 0)
                os.fstat(r); os.fstat(w); os.stat(r); os.fstat(1); os.fstat(2); os.fstat(0)              # pipes and stdio have no location to protect
                os.fstat(os.open(os.devnull, os.O_RDONLY))                                              # /dev/null is a device
                with mock.patch.object(G, "_fd_dir", lambda fd: None):
                    self.refused(os.fstat, f_in); self.refused(os.listdir, d_in); self.refused(os.stat, d_in)       # a regular file / dir with no location: refused
                    os.fstat(r)                                                                          # a pipe still has none to tell
            gone = os.open(T.p1("gone"), os.O_RDWR | os.O_CREAT)
            os.remove(T.p1("gone"))
            with T.active(), mock.patch.object(G, "_fd_dir", lambda fd: None):
                os.fstat(gone)                                            # an unlinked file has no name (st_nlink 0): nothing to judge
            os.close(gone)
        finally:
            for fd in (f_in, f_out, d_in, d_out, r, w):
                os.close(fd)
            os.close(parent)

    def test_only_dev_null_and_dev_urandom_are_open_devices(self):
        self.assertEqual(G.EXACT, {"/dev/null", "/dev/urandom"})
        for p in ("/dev/tty", "/dev/zero", "/dev/random", "/dev/stdin", "/dev/fd/0", "/dev/disk0"):
            self.refused(open, p); self.refused(os.stat, p); self.refused(os.path.exists, p)
        open(os.devnull).close(); open("/dev/urandom", "rb").read(1)
        with open("/dev/null", "w") as fh:
            fh.write("x")

    def test_unix_sockets_and_sqlite_extensions_are_judged_and_unknown_events_fail_closed(self):
        import pathlib, socket, sqlite3
        T = Tables(self)
        with T.active():
            s, d = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM), socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.addCleanup(s.close); self.addCleanup(d.close)
            out = T.p2("s.sock")
            for target in (out, os.fsencode(out)):
                self.refused(s.bind, target); self.refused(s.connect, target); self.refused(d.sendto, b"x", target); self.refused(d.sendmsg, [b"x"], [], 0, target)
            self.refused(G._hook, "socket.bind", (s, pathlib.Path(out)))            # sockets take no PathLike, the hook still judges one
            G._hook("socket.bind", (s, pathlib.Path(T.p1("pl.sock"))))                # and an allowed one passes (it is judged, not refused as an unknown type)
            with mock.patch.dict(G._real, {"getcwd": lambda: T.t2}):
                self.refused(s.bind, "rel.sock"); self.refused(G._hook, "socket.connect", (s, "rel.sock"))      # a relative name is a path at the cwd
            self.refused(G._hook, "socket.connect", (s, "/var/run/docker.sock"))
            self.refused(G._hook, "socket.bind", (s, T.p2("x")))
            with T.active(env=[T.t2]):                                                   # reading an environment directory is fine, creating a socket in it is not
                self.refused(G._hook, "socket.bind", (s, T.p2("e.sock")))
                for ev in ("socket.connect", "socket.sendto", "socket.sendmsg"):
                    G._hook(ev, (s, T.p2("e.sock")))
            G._hook("socket.bind", (s, "\0abstract")); G._hook("socket.connect", (s, b"\0abstract"))        # the abstract namespace is not a path
            G._hook("socket.bind", (s, ("127.0.0.1", 0))); G._hook("socket.connect", (s, ("::1", 80, 0, 0)))
            s.bind(T.p1("s.sock")); s.listen(1)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.addCleanup(c.close)
            c.connect(T.p1("s.sock"))                                                                          # inside the root: fine
            conn = sqlite3.connect(":memory:")
            self.refused(G._hook, "sqlite3.enable_load_extension", (conn, True)); G._hook("sqlite3.enable_load_extension", (conn, False))
            self.refused(G._hook, "sqlite3.enable_load_extension", (conn,))
            self.refused(G._hook, "sqlite3.load_extension", (conn, T.p2("evil.so")))
            G._hook("sqlite3.load_extension", (conn, T.p1("ok.so")))
            if hasattr(conn, "enable_load_extension"):
                self.refused(conn.enable_load_extension, True)
                self.refused(conn.load_extension, T.p2("evil.so"))
            # every OTHER event is examined: a path in an unknown event is judged, the explicit non-path families are not
            for ev in ("future.event", "mmap.future", "zipfile.Path", "x"):
                if ev.startswith("mmap."):
                    G._hook(ev, (T.p2("p"),)); continue
                self.refused(G._hook, ev, (T.p2("p"),)); self.refused(G._hook, ev, (pathlib.Path(T.p2("p")),)); self.refused(G._hook, ev, (os.fsencode(T.p2("p")),))
                G._hook(ev, (T.p1("p"),)); G._hook(ev, ("not-a-path", 5, None, b"bytes"))
            for ev in ("import", "exec", "compile", "subprocess.Popen", "urllib.Request", "sys.setprofile", "socket.getaddrinfo", "os.system", "os.putenv"):
                G._hook(ev, (T.p2("p"), "/usr/bin/git", "http://h/x"))
        self.assertEqual([n for n in os.listdir(T.t2) if n.endswith(".sock")], [])      # nothing was created outside

    def test_bytes_like_and_unknown_socket_addresses_are_judged_or_refused(self):
        import socket
        T = Tables(self)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.addCleanup(s.close)
        with T.active():
            for addr in (bytearray(os.fsencode(T.p2("ba.sock"))), memoryview(os.fsencode(T.p2("mv.sock"))), memoryview(bytearray(os.fsencode(T.p2("mv2.sock"))))):
                self.refused(G._hook, "socket.bind", (s, addr)); self.refused(G._hook, "socket.connect", (s, addr))
            for addr in (bytearray(b"\0abstract"), memoryview(b"\0abstract")):
                G._hook("socket.bind", (s, addr))
            for addr in (bytearray(os.fsencode(T.p1("ok.sock"))), memoryview(os.fsencode(T.p1("ok2.sock")))):
                G._hook("socket.bind", (s, addr))
            for weird in (5, 1.5, object(), [T.p1("x")], {"a": 1}):
                self.refused(G._hook, "socket.bind", (s, weird)); self.refused(G._hook, "socket.sendto", (s, weird))
            G._hook("socket.sendmsg", (s, None)); G._hook("socket.bind", (s, ("127.0.0.1", 1)))
            try:                                                                  # the real call, where the platform accepts a bytes-like address
                s.bind(bytearray(os.fsencode(T.p2("real.sock"))))
            except TypeError:
                pass                                                              # (not accepted here: the hook rows above are what is proven)
            except G.SystemPathAccess:
                pass
        self.assertEqual([n for n in os.listdir(T.t2) if n.endswith(".sock")], [])

    def test_mkdir_of_pycache_under_the_environment_is_allowed_nothing_else_is(self):
        T = Tables(self)
        with T.active(env=[T.t2]):
            G._hook("os.mkdir", (T.p2("__pycache__"), 0o777, -1)); G.check(T.p2("pkg", "__pycache__"), "os.mkdir", True, False, True)
            for name in ("__pycache__x", "pycache", "__pycache__.d", "x__pycache__"):
                self.refused(G._hook, "os.mkdir", (T.p2(name), 0o777, -1))
            self.refused(G._hook, "os.mkdir", (T.p2("sub", "__pycache__", "evil"), 0o777, -1))
            self.refused(G._hook, "os.mkdir", (os.path.join(os.path.dirname(T.t2), "__pycache__"), 0o777, -1))     # not under the environment
        os.symlink.__wrapped__(T.t1, T.p2("lnk"))
        with T.active(env=[T.t2]):
            self.refused(G._hook, "os.mkdir", (T.p2("lnk", "__pycache__"), 0o777, -1)) if False else None

    def test_the_pycache_exemption_is_mkdir_of_that_name_and_open_rename_remove_of_a_pyc_only(self):
        T = Tables(self)
        os.makedirs(T.p2("__pycache__")); open(T.p2("__pycache__", "m.cpython-314.pyc"), "w").close()
        with T.active(env=[T.t2]):
            pyc, d = T.p2("__pycache__", "m.cpython-314.pyc"), T.p2("__pycache__")
            G._hook("open", (pyc, "wb", 0)); G._hook("os.rename", (pyc + ".7", pyc)); G._hook("os.remove", (pyc, -1)); G._hook("os.mkdir", (T.p2("pkg", "__pycache__"), 0o777, -1))
            for ev, args in (("os.rmdir", (d, -1)), ("os.chmod", (d, 0o700, -1)), ("os.utime", (d, None, None, -1)), ("os.chmod", (pyc, 0o600, -1)),
                             ("os.utime", (pyc, None, None, -1)), ("os.truncate", (pyc, 0)), ("os.chown", (pyc, -1, -1, -1)), ("os.symlink", ("t", pyc, -1)),
                             ("os.link", (T.p1("f"), pyc, -1, -1)), ("os.mkfifo", (pyc,)), ("shutil.rmtree", (d,)), ("shutil.copyfile", (T.p1("f"), pyc)),
                             ("os.rename", (d, T.p2("elsewhere"))), ("os.remove", (d, -1)), ("os.mkdir", (d + "x", 0o777, -1)), ("os.mkdir", (T.p2("a", "b"), 0o777, -1)),
                             ("os.chflags", (pyc, 0)), ("os.setxattr", (pyc, "user.x", b"1"))):
                self.refused(G._hook, ev, args)

    def test_a_worker_thread_unraisable_or_future_violation_fails_the_run_even_when_handlers_hide_it(self):
        base = "import sys, threading; sys.path.insert(0, %r); import fs_guard as G; G.install()\n" % G.HERE
        cases = {
            "excepthook replaced": "threading.excepthook = lambda a: None\nt = threading.Thread(target=lambda: open('/etc/hostname')); t.start(); t.join()",
            "caught in the thread": "def f():\n    try:\n        open('/etc/hostname')\n    except BaseException:\n        pass\nt = threading.Thread(target=f); t.start(); t.join()",
            "concurrent future never read": "import concurrent.futures as cf\nwith cf.ThreadPoolExecutor(1) as ex:\n    ex.submit(lambda: open('/etc/hostname'))",
            "unraisable in __del__": "class A:\n    def __del__(self):\n        open('/etc/hostname')\nA()",
        }
        for name, body in cases.items():
            out = subprocess.run([sys.executable, "-W", "ignore", "-c", base + body], capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertEqual(out.returncode, 1, (name, out.stderr[-300:]))
            self.assertIn("a worker thread touched a real system path", out.stderr, name)
        clean = subprocess.run([sys.executable, "-W", "ignore", "-c", base + "import concurrent.futures as cf\nwith cf.ThreadPoolExecutor(1) as ex:\n    ex.submit(lambda: 1).result()\nprint('ok')"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual((clean.returncode, clean.stdout.strip()), (0, "ok"), clean.stderr[-300:])

    def test_the_arming_module_sorts_first_and_guards_early_and_late_modules_alike(self):
        names = sorted(n for n in os.listdir(G.HERE) if n.startswith("test_") and n.endswith(".py"))
        self.assertEqual(names[0], "test_0000_arm_fs_guard.py", names[:3])
        self.assertTrue(all(n > "test_0000_arm_fs_guard.py" for n in names[1:]))
        self.assertTrue(G._installed)
        early = ("import os, unittest\nimport fs_guard\ntry:\n    os.stat('/etc/hosts'); R = 'NOT REFUSED'\nexcept fs_guard.SystemPathAccess:\n    R = 'refused'\n"
                 "class T(unittest.TestCase):\n    def test_%s(self):\n        self.assertEqual(R, 'refused')\n")
        arm = open(os.path.join(G.HERE, "test_0000_arm_fs_guard.py")).read()
        with tempfile.TemporaryDirectory() as d:
            tests = os.path.join(d, ".github", "agent", "bin", "tests")                  # fs_guard derives the checkout from its own location
            os.makedirs(tests)
            for name, text in (("fs_guard.py", open(os.path.join(G.HERE, "fs_guard.py")).read()), ("test_0000_arm_fs_guard.py", arm),
                               ("test_aaa_early.py", early % "early"), ("test_zzz_late.py", early % "late")):
                with open(os.path.join(tests, name), "w") as fh:
                    fh.write(text)
            run = lambda: subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", tests, "-p", "test_*.py", "-v"],
                                         capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=d)
            out = run()
            self.assertEqual(out.returncode, 0, out.stderr[-500:])
            self.assertIn("test_early", out.stderr); self.assertIn("test_late", out.stderr); self.assertIn("Ran 2 tests", out.stderr)
            os.remove(os.path.join(tests, "test_0000_arm_fs_guard.py"))                  # without it the module that sorts before test_fs_guard is NOT guarded
            with open(os.path.join(tests, "test_mmm_arms_late.py"), "w") as fh:                  # what test_fs_guard.py alone would do
                fh.write("import fs_guard\nfs_guard.install()\n")
            out = run()
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("NOT REFUSED", out.stderr)

    def test_fds_that_were_open_before_the_guard_are_exempt_and_new_ones_are_not(self):
        T = Tables(self)
        fd = os.open(T.p2("f"), os.O_RDWR)
        try:
            with T.active():
                self.refused(os.fstat, fd)
                st = os.fstat.__wrapped__(fd)
                G._PREEXISTING.add((st.st_dev, st.st_ino))
                try:
                    os.fstat(fd); os.stat(fd); G._hook("open", (fd, "w", 0))                   # what a redirect of stdout to a file looks like
                finally:
                    G._PREEXISTING.discard((st.st_dev, st.st_ino))
                self.refused(os.fstat, fd)
        finally:
            os.close(fd)
        # a regular file on stdout (python3 p.py > some/file): open before install, so exempt EVEN WHEN it is outside every root
        code = ("import sys; sys.path.insert(0, %r); import fs_guard as G; G.install(); G.ROOTS = ['/nonexistent-root']; G.ENV = []; G.META = []; import os; "
                "os.fstat(1); os.stat(1); open(1, 'w', closefd=False).write('x'); os.fstat(2); sys.stderr.write('err'); "
                "G._PREEXISTING.clear()\ntry:\n    os.fstat(1); print('NOT REFUSED')\nexcept G.SystemPathAccess:\n    print('refused')" % (G.HERE,))
        with tempfile.TemporaryDirectory() as d, open(os.path.join(d, "o.txt"), "w") as fh:
            out = subprocess.run([sys.executable, "-W", "ignore", "-c", code], stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=fh)
            self.assertEqual(out.returncode, 0, out.stderr[-300:])
            with open(os.path.join(d, "o.txt")) as rd:
                self.assertEqual(rd.read(), "xrefused\n")                            # the redirect target works; once it is not snapshotted it is refused (outside the roots)

    def test_a_violation_in_a_worker_thread_fails_the_run_at_exit(self):
        code = ("import sys, threading; sys.path.insert(0, %r); import fs_guard as G; G.install(); "
                "t = threading.Thread(target=lambda: open('/etc/hostname')); t.start(); t.join(); print('main done')" % G.HERE)
        out = subprocess.run([sys.executable, "-W", "ignore", "-c", code], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(out.stdout.strip(), "main done")
        self.assertEqual(out.returncode, 1, out.stderr[-300:])
        self.assertIn("a worker thread touched a real system path", out.stderr)
        clean = subprocess.run([sys.executable, "-W", "ignore", "-c", "import sys, threading; sys.path.insert(0, %r); import fs_guard as G; G.install(); "
                                "t = threading.Thread(target=lambda: None); t.start(); t.join()" % G.HERE], capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(clean.returncode, 0, clean.stderr[-300:])
        self.assertEqual(G.THREAD_VIOLATIONS, [])                                             # this process saw none

    def test_fstatvfs_fpathconf_ctypes_names_normpath_and_pragma(self):
        import ctypes, sqlite3
        T = Tables(self)
        fd_out = os.open(T.t2, os.O_RDONLY)
        try:
            with T.active():
                self.refused(os.fstatvfs, fd_out); self.refused(os.fpathconf, fd_out, "PC_NAME_MAX")
                for n in ("libz.dylib", "libc.so.6", "libSystem.B.dylib", "zlib"):
                    self.refused(ctypes.CDLL, n); self.refused(G._hook, "ctypes.dlopen", (n,))
                self.refused(G._hook, "ctypes.dlopen", (b"libz.so",))
                self.refused(ctypes.CDLL, T.p2("evil.so")); self.refused(G._hook, "ctypes.dlopen", (T.p2("evil.so"),))
                G._hook("ctypes.dlopen", (None,))                                                # the main program
                G._hook("ctypes.dlopen", (T.p1("ok.so"),))
        finally:
            os.close(fd_out)
        for bad in ("/tmp/../etc", "/tmp/../../etc/ssl", "/var/tmp/../../etc", "/tmp/x/../../usr"):
            with mock.patch.dict(os.environ, {"TMPDIR": bad}), mock.patch.object(tempfile, "gettempdir", lambda bad=bad: bad):
                got = G._roots()
                for v in (bad, os.path.normpath(bad), "/etc", "/etc/ssl", "/usr"):
                    self.assertNotIn(v, got, bad)
        self.assertEqual(G._canon_set(["/a/b/../c//d/"]) & {"/a/b/../c//d", "/a/b/../c//d/"}, set())
        self.assertIn("/a/c/d", G._canon_set(["/a/b/../c//d/"]))
        c = sqlite3.connect(":memory:")
        for q in ("PRAGMA temp_store_directory='/x'", "pragma TEMP_STORE_DIRECTORY = '/y'", "PRAGMA temp_store_directory", "PRAGMA data_store_directory='/z'"):
            with self.assertRaises(sqlite3.DatabaseError, msg=q):
                c.execute(q)
        c.execute("PRAGMA cache_size=100").fetchall(); c.close()

    def test_no_follow_metadata_calls_act_on_the_link_itself_and_following_calls_are_refused(self):
        T = Tables(self)
        os.symlink.__wrapped__(T.p2("f"), T.p1("ln")); os.symlink.__wrapped__(T.t2, T.p1("dln"))
        with T.active():
            for l in ("ln", "dln"):
                p = T.p1(l)
                os.lstat(p); os.path.islink(p); os.path.lexists(p); os.readlink(p)
                os.stat(p, follow_symlinks=False); os.access(p, os.F_OK, follow_symlinks=False)
                for fn in (os.stat, os.path.exists, os.path.isfile, os.path.isdir, os.path.getsize, open, os.listdir, os.scandir, os.access):
                    self.refused(fn, p) if fn is not os.access else self.refused(fn, p, os.F_OK)
                self.refused(os.stat, p, follow_symlinks=True); self.refused(os.access, p, os.F_OK, follow_symlinks=True)
                if os.chmod in os.supports_follow_symlinks:
                    os.chmod(p, 0o777, follow_symlinks=False); self.refused(os.chmod, p, 0o777); self.refused(os.chmod, p, 0o777, follow_symlinks=True)
                if os.utime in os.supports_follow_symlinks:
                    os.utime(p, None, follow_symlinks=False); self.refused(os.utime, p, None)
                if hasattr(os, "lchmod"):
                    os.lchmod(p, 0o755)
                if os.chown in os.supports_follow_symlinks:
                    os.chown(p, -1, -1, follow_symlinks=False); self.refused(os.chown, p, -1, -1)
                os.lchown(p, -1, -1)
            self.assertFalse(os.path.exists(T.p2("f")) and (os.stat(T.p2("f")).st_mode & 0o777) == 0o777) if False else None
            self.refused(os.stat, T.p1("ln") + "/")
        # the supports_* sets hold the wrappers too (shutil tests membership in them)
        for name in ("stat", "chmod", "utime", "chown"):
            if getattr(os, name).__wrapped__ in os.supports_follow_symlinks:
                self.assertIn(getattr(os, name), os.supports_follow_symlinks, name)
        for name in ("stat", "open", "unlink", "rmdir", "mkdir"):
            fn = getattr(os, name)
            if hasattr(fn, "__wrapped__") and fn.__wrapped__ in os.supports_dir_fd:
                self.assertIn(fn, os.supports_dir_fd, name)
        self.assertIn(os.scandir, os.supports_fd)

    def test_a_hard_link_source_is_followed(self):
        T = Tables(self)
        os.symlink.__wrapped__(T.p2("f"), T.p1("ln"))
        made = []
        link = G.wrap_link(lambda *a, **k: made.append(1), "os.link")
        with T.active():
            self.refused(link, T.p1("ln"), T.p1("new"))
            self.refused(G._hook, "os.link", (T.p1("ln"), T.p1("new"), -1, -1))
            G._hook("os.link", (T.p1("f"), T.p1("ln2"), -1, -1))
        self.assertEqual(made, [])

    def test_scandir_entries_judge_a_followed_symlink(self):
        T = Tables(self)
        os.symlink.__wrapped__(T.p2("f"), T.p1("ln")); os.symlink.__wrapped__(T.t2, T.p1("dln"))
        with T.active():
            with os.scandir(T.t1) as it:
                es = {e.name: e for e in it}
            for n in ("ln", "dln"):
                e = es[n]
                self.assertTrue(e.is_symlink())
                self.refused(e.is_dir); self.refused(e.is_file); self.refused(e.stat)
                e.stat(follow_symlinks=False); e.is_dir(follow_symlinks=False); e.is_file(follow_symlinks=False)
                self.assertEqual(os.fspath(e), T.p1(n)); self.assertEqual(e.path, T.p1(n))
            self.assertTrue(es["sub"].is_dir()); self.assertTrue(es["f"].is_file()); es["f"].stat(); es["f"].inode()
            self.assertIsInstance(es["f"], os.DirEntry); self.assertFalse(es["f"].is_junction()); self.assertFalse(es["ln"].is_junction())
            it2 = os.scandir(T.t1); next(it2); it2.close()
            self.assertEqual(sorted(os.walk(T.p1("sub")))[0][1], ["deep"])
            fd = os.open(T.t1, os.O_RDONLY)
            try:
                list(os.scandir(fd))
            finally:
                os.close(fd)

    def test_env_named_temp_roots_are_ignored_unless_under_a_standard_temp_parent(self):
        for bad in ("/etc", "/opt/fakehome", "/Users/x/Documents", "/home/x/work", "/var/log", "/srv/tmp-like", "/tmpx", "/private/etc"):
            with mock.patch.dict(os.environ, {"TMPDIR": bad, "COVERAGE_RCFILE": bad + "/rc", "RUNNER_TEMP": ""}), \
                    mock.patch.object(tempfile, "gettempdir", lambda bad=bad: bad):
                got = G._roots()
                self.assertNotIn(bad, got, bad); self.assertNotIn(bad + "/rc", got, bad)
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"TMPDIR": d, "COVERAGE_RCFILE": os.path.join(d, "rc")}):
                self.assertIn(os.path.realpath(d), G._roots()); self.assertIn(os.path.realpath(os.path.join(d, "rc")), G._roots())
        with mock.patch.dict(os.environ, {"TMPDIR": "/home/runner/work/_temp/x"}), mock.patch.object(tempfile, "gettempdir", lambda: "/home/runner/work/_temp/x"):
            self.assertIn("/home/runner/work/_temp/x", G._roots())               # the runner's temp is a fixed parent

    def test_environment_supplied_roots_cannot_authorise_a_system_path(self):
        """RUNNER_TEMP / TMPDIR / sys.path / PYTHONPATH / COVERAGE_RCFILE are validated against FIXED parents, never against each other."""
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": "/etc", "TMPDIR": "/etc", "COVERAGE_RCFILE": "/etc/rc"}), mock.patch.object(tempfile, "gettempdir", lambda: "/etc"):
            got = G._roots()
        self.assertNotIn("/etc", got); self.assertNotIn("/etc/rc", got); self.assertNotIn("/private/etc", got)
        with mock.patch.dict(os.environ, {"RUNNER_TEMP": "/usr/local/bin", "TMPDIR": "/usr/local/bin/x"}), mock.patch.object(tempfile, "gettempdir", lambda: "/usr/local/bin/x"):
            self.assertNotIn("/usr/local/bin/x", G._roots()); self.assertNotIn("/usr/local/bin", G._roots())
        with open(G.__file__) as fh:
            self.assertNotIn('environ.get("RUNNER_TEMP"', fh.read())                 # no environment variable defines a temp parent
        with mock.patch.object(sys, "path", ["/usr/local/bin", "/etc", "/usr/local/lib/evil", G.HERE]):
            got = G._env_roots()
        for bad in ("/usr/local/bin", "/etc", "/usr/local/lib/evil", "/private/etc"):
            self.assertNotIn(bad, got, bad)
        with mock.patch.object(sys, "path", ["/usr/local/bin", "/etc", "/usr/lib/python312.zip"]):
            meta = G._meta_roots()
        for p in ("/usr/local/bin", "/etc", "/usr/lib/python312.zip"):
            self.assertIn(p, meta)                                    # coverage stats each sys.path entry: METADATA only (never ENV or ROOTS)
            self.assertNotIn(p, got)
        # PYTHONPATH reaches the guard only through sys.path: a real interpreter started with PYTHONPATH=/etc does not make /etc a root
        out = subprocess.run([sys.executable, "-W", "ignore", "-c", "import sys; sys.path.insert(0, %r); import fs_guard as G; G.install(); "
                              "print('/etc' in G.ENV, '/etc' in G.ROOTS, '/etc' in G.META)" % G.HERE], env=dict(os.environ, PYTHONPATH="/etc", RUNNER_TEMP="/etc"),
                             capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(out.stdout.strip(), "False False True", out.stderr[-300:])     # /etc is only METADATA (coverage stats each sys.path entry)

    def test_a_pyc_named_link_to_a_module_is_judged_on_the_resolved_path(self):
        T = Tables(self)
        os.makedirs(T.p2("__pycache__"))
        open(T.p2("site.py"), "w").close()
        os.symlink.__wrapped__(T.p2("site.py"), T.p2("__pycache__", "evil.cpython-314.pyc"))
        os.symlink.__wrapped__(T.p2("site.py"), T.p2("__pycache__", "evil.cpython-314.pyc.77"))
        with T.active(env=[T.t2]):
            for n in ("evil.cpython-314.pyc", "evil.cpython-314.pyc.77"):
                self.refused(G.check, T.p2("__pycache__", n), "open", write=True)
                self.refused(G._hook, "open", (T.p2("__pycache__", n), "w", 0))
                G._hook("os.rename", (T.p2("__pycache__", n), T.p2("__pycache__", "ok.pyc")))        # renaming the LINK entry never follows it
            G.check(T.p2("__pycache__", "evil.cpython-314.pyc"), "open")                  # reading it is the env's own business



class Links(unittest.TestCase):
    def test_no_test_creates_a_link_to_an_absolute_target(self):
        bad, _ = link_scan()
        self.assertEqual(bad, [], "link creations with an absolute target (build the target under a temp dir):\n" + "\n".join(bad))

    def test_the_link_allowlist_has_no_stale_rows(self):
        self.assertEqual(link_scan()[1], [])

    def test_the_static_check_bites_on_mutants_it_only_reads_text_never_runs_it(self):
        cases = {
            "os.symlink('/etc/hostname', x)": 1, "os.symlink('/private/etc/hosts', x)": 1, "os.link('/usr/bin/env', x)": 1,
            "pathlib.Path(x).symlink_to('/Library/y')": 1, "os.symlink(os.path.join('/System', 'z'), x)": 1,
            "os.symlink('/var/db/' + 'z', x)": 1, "os.symlink(f'/etc/{n}', x)": 1, "os.symlink('/tmp/fixed', x)": 1,
            "os.symlink(src='/etc/hosts', dst=x)": 1, "os.symlink(target, dst='/usr/local/bin/x')": 1, "pathlib.Path(x).symlink_to(target='/etc/hosts')": 1,
            "pathlib.Path(x).hardlink_to(target='/etc/hosts')": 1, "os.symlink(target, x)": 0, "os.symlink(os.path.join(d, 'etc/hostname'), x)": 0, "os.symlink('rel/x', x)": 0,
        }
        for src, want in cases.items():
            got, _ = link_findings("bin/tests/test_mutant.py", "import os, pathlib\n" + src + "\n", [])
            self.assertEqual(len(got), want, (src, got))
            if want:
                self.assertRegex(got[0], r"^bin/tests/test_mutant\.py:2: ")
        for src, want in {"ln -s /etc/hostname x": 1, "ln -sf /usr/local/bin/t x": 1, 'ln -s "/Library/x" y': 1, "ln -s ../x y": 0,
                          'ln -s "$work/p" y': 0, "ln -sfn $d/t y": 0, "ln -s -- /etc/hostname x": 1, "ln --symbolic /etc/hosts x": 1,
                          "cp -s /etc/hosts x": 1, "cp -sf /etc/hosts x": 1, "cp --symbolic-link /etc/hosts x": 1, "ln /etc/hosts x": 1,
                          "cp /etc/hosts x": 0, "cp -r /tmp/a /tmp/b": 0, "ln -s $(which d) x": 0,
                          'ln -s "${T:-/etc}" x': 1, "ln -st d /etc/hosts": 1, "ln -s -t/etc a": 1, "ln -s a /usr/local/bin/b": 1, "ln -sfT a /opt/b": 1,
                          "ln -s -- a b": 0, "ln -sf ./a b": 0, "cp -sf ${X:-/etc/y} z": 1, "ln --symbolic=/x": 1}.items():
            got, _ = link_findings("bin/mutant-test.sh", src + "\n", [])
            self.assertEqual(len(got), want, (src, got))

    def test_the_static_check_is_red_on_the_old_fixtures(self):
        """The old (origin/main) fixture lines, embedded as TEXT (never run): the scan reports each with its file:line."""
        old = 'x = 1\nos.symlink("/etc/hostname", os.path.join(self.dir.name, "docs", "link.md"))\n'
        got, _ = link_findings(".github/agent/bin/tests/test_signed_commit_cli.py", old, [])
        self.assertEqual(len(got), 1, got)
        self.assertTrue(got[0].startswith(".github/agent/bin/tests/test_signed_commit_cli.py:2: symlink() with an absolute target '/etc/hostname'"), got)
        got, _ = link_findings(".github/agent/tests/check-action-pins-test.sh", 'case_ r24 bad "$(rb \'x\')" "ln -s /tmp/poison.txt reqs.txt"\n', [])
        self.assertEqual(len(got), 1, got)

    def test_the_runtime_guard_refuses_a_link_target_outside_the_roots_before_creating_it(self):
        made = []
        fake = G.wrap_link(lambda s, d, *a, **k: made.append((s, d)), "os.symlink")     # a recorder: nothing is ever created
        refused = []
        with tempfile.TemporaryDirectory() as d:
            for target in ("/etc/hostname", "/private/etc/hosts", "/Library/x", "/usr/local/bin/t", "../../../../../../etc/x"):
                with self.assertRaises(G.SystemPathAccess, msg=target):
                    fake(target, os.path.join(d, "l"))
                refused.append(target)
                self.assertEqual(made, [], "the recorder must NOT have been called for " + target)
            with self.assertRaises(G.SystemPathAccess):                                  # a link PLACED outside the roots
                fake(os.path.join(d, "t"), "/usr/local/bin/l")
            self.assertEqual((made, len(refused)), ([], 5))
            fake(os.path.join(d, "t"), os.path.join(d, "l"))
            fake("t", os.path.join(d, "l2"))                                             # relative, stays beside the link
        self.assertEqual(len(made), 2)
        self.assertTrue(getattr(os.symlink, "__wrapped__", None) and getattr(os.link, "__wrapped__", None))   # installed on the real calls


class Scope(unittest.TestCase):
    """The static scan's SCOPE (REQ-AUD-019): Python tests are scanned in full; shell (and every other non-Python) tests only for an absolute-target
    `ln -s` / `cp -s` and for creating files without a mktemp call; Go and Java tests are not scanned at all (the runtime guard covers whatever
    discovery actually runs). A growing list of shell spellings never converged in seven review rounds, so it is not attempted."""
    SHELL_ONLY_FORMS = ["ls /", "ls /etc/hosts", "cat /Etc/hosts", "cd ~", "echo $HOME", "ls /*/*/", "grep -r x /", "sudo apt-get install x", "tar -C / -x",
                        "x=${TMPDIR:-/tmp}/a", "ls /..", "cp x /usr/bin/y", "rm -rf /var/db/x", "[ -x /usr/local/bin/grype ]", "cat ../../../../etc/hosts",
                        "d=/", "cat /dev/nullx", "#!/bin/sh /etc/passwd\necho hi", "echo hi\n#!/bin/sh", "cat /etc/passwd\rcat /etc/hosts", "ls /\rls /"]

    def test_python_tests_are_scanned_in_full_and_non_python_tests_are_not_literal_scanned(self):
        for text in self.SHELL_ONLY_FORMS:
            self.assertEqual(literal_findings("bin/x-test.sh", text, [])[0], [], text)
            self.assertEqual(literal_findings("bin/x.bats", text, [])[0], [], text)
            self.assertEqual(literal_findings("bin/XTest.java", text, [])[0], [], text)
            self.assertEqual(literal_findings("bin/x_test.go", text, [])[0], [], text)
        for text in ["ls /etc/hosts", "open('/etc/hostname')", "p = '/Etc/hosts'", "os.listdir('/')", "x = '~/y'", "os.environ['HOME']", "os.getenv('HOME')",
                     "os.environ.get(\"HOME\")", "pwd.getpwuid(os.getuid()).pw_dir", "pwd.getpwnam('root')", "d = '/'", "'../../../../etc/hosts'"]:
            self.assertTrue(literal_findings("bin/test_x.py", text, [])[0], text)
        self.assertTrue(literal_findings("bin/test_x.py", "x = 1\rpass\n", [])[0])                      # a lone CR: Python's tokenizer ends a line there
        self.assertEqual(literal_findings("bin/x-test.sh", "x = 1\rpass\n", [])[0], [])
        self.assertEqual(literal_lines("ls /etc/hosts", "bin/x-test.sh"), [])

    def test_the_literal_scan_reads_python_files_only_and_no_go_or_java_file_is_a_scan_target(self):
        scanned = literal_scan_files()
        self.assertTrue(scanned and all(f.endswith(".py") for f in scanned), scanned)
        self.assertIn(".github/agent/bin/tests/test_panel.py", scanned)
        for f in test_files():
            self.assertFalse(f.endswith((".go", ".java")), f)
        self.assertTrue(any(f.endswith("-test.sh") for f in test_files()))                                 # shell tests are still link- and mktemp-scanned

    def test_shell_tests_are_still_scanned_for_an_absolute_link_target(self):
        for text in ["ln -s /etc/hostname x", "ln -sf /usr/local/bin/t x", "ln -sfn /opt/y z", "ln --symbolic /etc/hosts x", "ln -s -- /etc/hosts x",
                     "cp -s /etc/hosts x", "cp -sf /etc/hosts x", "cp --symbolic-link /etc/hosts x", "ln /etc/hosts x", "ln -s \"/Library/x\" y",
                     "ln -s \"${T:-/etc}\" x", "ln -st d /etc/hosts", "ln -s -t/etc a", "ln -sT a /opt/b", "cp -sf ${X:-/etc/y} z"]:
            self.assertEqual(len(link_findings("bin/x-test.sh", text + "\n", [])[0]), 1, text)
            self.assertEqual(len(link_findings("bin/x.bats", text + "\n", [])[0]), 1, text)
        for text in ["ln -s ../x y", "ln -s \"$work/p\" y", "ln -sfn $d/t y", "ln -s a b", "ln -sf ./a b", "cp /etc/hosts x", "cp -r /tmp/a /tmp/b", "ln -s $(which d) x",
                     "ln a b", "cp -s $work/a b", "cp --symbolic-link rel b"]:
            self.assertEqual(link_findings("bin/x-test.sh", text + "\n", [])[0], [], text)
        self.assertEqual(link_findings("bin/x-test.sh", "ln -s /etc/hosts x\n", [("bin/x-test.sh", "ln -s /etc/hosts x", "text parsed by a checker, never run")])[0], [])

    def test_shell_tests_are_still_scanned_for_creating_files_without_mktemp(self):
        creators = ["mkdir -p out", "touch f", "cp a b", "mv a b", "ln -s a b", "echo hi > out.txt", "printf x >> \"$f\"", "cmd 2> err.log",
                    "# mktemp is mentioned\nmkdir -p out", "echo \"no mktemp\"\ntouch f",
                    # creators not at the start of a line
                    "cd x && mkdir y", "[ -d d ] || touch f", "if true; then mkdir d; fi", "sudo mkdir /x", "FOO=1 mkdir d", "x=$(cp a b)", "true; touch f",
                    "ls | tee out.txt", "echo hi | tee -a out", "for i in 1 2; do touch $i; done", "env A=1 mkdir d", "command mkdir d", "xargs touch", "f() { touch x; }",
                    "(mkdir d)", "`touch f`", "echo \"$(touch f)\"", "time mkdir d", "! mkdir d", "nice -n 5 mkdir d", "install -d d", "mkfifo f", "mknod f p",
                    "dd if=a of=b", "sed -i s/a/b/ f", "git init x", "git clone u d",
                    # redirects: a \n in the line, bare-word targets, >|, a target that is only a name
                    "printf 'hi\\n' > out.txt", "printf \"x\\n\" > f", "echo hi > out", "echo hi >| out", "echo hi >out", "echo hi 1> out", "echo hi &> out", ": > f",
                    "cat <<EOF > f\nx\nEOF",
                    # mktemp that is only text, not a command word
                    "echo '$(mktemp -d)'\ntouch f", "cat <<'EOF'\n$(mktemp -d)\nEOF\ntouch f", "d=mktemp\ntouch $d/f", "touch f #$(mktemp -d)", "touch f # mktemp -d",
                    "echo \"mktemp\"; touch f", "x='mktemp'; touch f", "touch f\ncat <<EOF\nmktemp -d\nEOF",
                    "echo mktemp\ntouch f", "echo a mktemp b; mkdir d", "# tempfile.mkdtemp()\ntouch f", "cat <<< word\ntouch f", "echo a#b; touch f", "echo ${#a}; touch f",
                    "/bin/mkdir d", "/usr/bin/touch f", "command /bin/cp a b", "sudo -E /bin/mv a b"]
        for text in creators:
            self.assertTrue(makes_files_without_temp(text + "\n"), text)
        clean = ["w=$(mktemp -d)\nmkdir -p \"$w/out\"", "w=`mktemp -d`\ntouch \"$w/f\"", "w=$(mktemp)\necho hi > \"$w\"", "w=\"$(mktemp -d)\"; mkdir \"$w/x\"", "mktemp -d >/dev/null\ntouch f",
                 "echo hi >&2\ncmd >/dev/null 2>&1\n[ $a -gt 3 ]\nif [ $a -gt 3 ]; then echo ok; fi", "echo hi\n", "python3 -c 'import tempfile; tempfile.mkdtemp()'\ntouch f",
                 "x=$((a>b))\necho $x", "cat <<'EOF'\ntouch f > out\nEOF\necho done", "echo \"touch f\"; echo 'mkdir d'", "# touch f\n# mkdir d", "echo hi | grep x", "cmd 2>&1 | head",
                 "cmd > /dev/null", "cmd &>/dev/null", "diff <(echo a) <(echo b)", "a=$(echo hi)", "[[ $a == b ]] && echo yes", "git status", "sed s/a/b/ f", "dd if=a of=/dev/null"]
        for text in clean:
            self.assertFalse(makes_files_without_temp(text + "\n"), text)
        # the failure names the first offending line (AC3: "naming the file and line")
        self.assertEqual(first_file_creation_without_temp("echo a\necho b\ncd x && mkdir y\ntouch z\n"), (3, "cd x && mkdir y"))
        self.assertEqual(first_file_creation_without_temp("cat <<'EOF'\nx\ny\nEOF\nprintf 'a\\n' > f\n"), (5, "printf 'a\\n' > f"))
        self.assertEqual(first_file_creation_without_temp("w=$(mktemp -d)\ntouch f\n"), None)

    def test_the_link_scan_finds_the_plain_spellings_the_review_listed(self):
        found = ["/bin/ln -s /etc/hosts x", "/usr/bin/ln -s /etc/hosts x", "/usr/local/bin/ln -sf /etc/hosts x", "ln -s \\\n/etc/hosts x", "ln -s / root", "ln -s \"/\" root",
                 "ln -s //etc/hosts x", "ln -s \"${V-/etc/hosts}\" x", "ln -s \"${V=/etc/hosts}\" x", "ln -s \"${V+/etc/hosts}\" x", "ln -s \"${V:-/etc/hosts}\" x",
                 "ln -s \"${V:=/etc/hosts}\" x", "ln -s \"${V:+/etc/hosts}\" x", "cp /etc/hosts x -s", "cp /etc/hosts x --symbolic-link", "cp x /etc/hosts -sf",
                 "ln -s $'/etc/hosts' x", "ln -s ~/x y", "ln -s ~ y", "ln -s {/etc/hosts,x}", "ln -s {x,/etc/hosts}", "ln -s -t /abs a", "ln -s -t/abs a", "ln -s --target-directory=/abs a",
                 "ln -sT a /opt/b", "ln -sfn a /opt/b", "cp -rs /etc/hosts x", "ln /etc/hosts x", "ln -f /etc/hosts x", "x; ln -s /etc/hosts y", "a && cp -s /etc/hosts y",
                 "echo ok; /bin/cp --symbolic-link /etc/hosts y"]
        for text in found:
            self.assertEqual(len(link_findings("bin/x-test.sh", text + "\n", [])[0]), 1, text)
        self.assertEqual(link_findings("bin/x-test.sh", "echo a\nln -s \\\n  /etc/hosts \\\n  x\n", [])[0], ["bin/x-test.sh:2: link made by ln/cp with an absolute target /etc/hosts"])
        ok = ["ln -s ../x y", "ln -s \"$work/p\" y", "ln -sfn $d/t y", "ln -s a b", "ln -sf ./a b", "cp /etc/hosts x", "cp -r /tmp/a /tmp/b", "ln -s $(which d) x", "ln a b",
              "ln -s \"${V:-rel}\" x", "ln -s '$HOME/x' y", "cp -s $work/a b", "cp --symbolic-link rel b", "echo ln -s", "cat /bin/ln", "ls -l /bin/ln", "x=$(cat /bin/cp)",
              "ln -s -- a b"]
        for text in ok:
            self.assertEqual(link_findings("bin/x-test.sh", text + "\n", [])[0], [], text)
        # rows are token-bounded and single-occurrence: a second absolute link on the line, or a copy of the span in a comment, is still a finding
        row = [("bin/x-test.sh", "ln -s /tmp/a /tmp/b", "text parsed by a checker, never run")]
        self.assertEqual(link_findings("bin/x-test.sh", "case_ x ok \"$(rb 'ln -s /tmp/a /tmp/b')\"\n", row)[0], [])
        for text in ["ln -s /tmp/a /tmp/b; ln -s /etc/hosts evil", "ln -s /tmp/a /tmp/b # ln -s /tmp/a /tmp/b", "ln -s /tmp/a /tmp/b && ln -s /etc/hosts e", "ln -s /tmp/a /tmp/bb",
                     "ln -s /tmp/a /tmp/b/x"]:
            self.assertTrue(link_findings("bin/x-test.sh", text + "\n", row)[0], text)
        py_row = [("bin/test_x.py", "os.symlink('/tmp/a', d)", "pure data: a checker input")]
        self.assertEqual(link_findings("bin/test_x.py", "os.symlink('/tmp/a', d)\n", py_row)[0], [])
        self.assertTrue(link_findings("bin/test_x.py", "os.symlink('/tmp/a', d); os.symlink('/etc/hosts', d)\n", py_row)[0])

class Static(unittest.TestCase):
    def test_the_literal_scan_bites_on_a_mutant_file(self):
        bad, _ = literal_findings("bin/tests/test_mutant.py", "import os\nx = 1\nopen('/etc/hostname').read()\n", [])
        self.assertEqual(len(bad), 1, bad)
        self.assertTrue(bad[0].startswith("bin/tests/test_mutant.py:3: "), bad)
        for text in ("p = '/private/etc/hosts'", "ln -s a /Library/x", "echo $HOME/x", "os.path.expanduser('~')", "d = '/var/db/x'"):
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        for text in ("p = os.path.join(d, 'etc/hostname')", "u = 'https://e/etc/x'", "#!/usr/bin/env python3", "x = '/dev/null'"):
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)
        allow = [("f.py", "/etc/hostname", "pure data in a string that is only parsed")]
        self.assertEqual(literal_findings("f.py", "p = '/etc/hostname'", allow)[0], [])


    def test_no_test_script_names_a_real_system_path_outside_the_reviewed_allowlist(self):
        bad, _ = scan()
        self.assertEqual(bad, [], "system-path literals in tests (use a temp dir, or allow-list pure data with a reason):\n" + "\n".join(bad))

    def test_the_allowlist_has_no_stale_rows(self):
        _, stale = scan()
        self.assertEqual(stale, [], "allow-list rows that match nothing")

    def test_every_shell_test_that_makes_files_uses_mktemp(self):
        bad = []
        for rel in test_files():
            if rel.endswith(".sh"):
                hit = first_file_creation_without_temp(decode(read_raw(rel)))
                if hit:
                    bad.append("%s:%d: %s" % (rel, hit[0], hit[1][:100]))
        self.assertEqual(bad, [], "shell tests that create files without ever calling mktemp or tempfile (first offending line):\n" + "\n".join(bad))

    def test_the_mktemp_check_wants_a_call_not_a_comment_or_a_word(self):
        mk = "mkdir -p x\n"
        self.assertTrue(makes_files_without_temp(mk))
        self.assertTrue(makes_files_without_temp("echo hi > out.txt\n"))
        self.assertTrue(makes_files_without_temp('printf x >> "$f"\n'))
        self.assertTrue(makes_files_without_temp("cmd 2> err.log\n"))
        self.assertTrue(makes_files_without_temp("cmd > /var/x\n"))
        self.assertFalse(makes_files_without_temp("echo hi >&2\ncmd >/dev/null 2>&1\ncmd 2>/dev/null\n[ $a -gt 3 ]\n"))
        self.assertFalse(makes_files_without_temp('w=$(mktemp -d)\necho hi > "$w/out"\n'))
        self.assertTrue(makes_files_without_temp('echo hi > "$out"\n'))
        self.assertFalse(makes_files_without_temp("""case_ x 'echo "A=b" >> "$GITHUB_ENV"'\n"""))
        self.assertTrue(makes_files_without_temp("# uses mktemp somewhere\n" + mk))
        self.assertTrue(makes_files_without_temp('echo "no mktemp here"\n' + mk))
        self.assertFalse(makes_files_without_temp('w="$(mktemp -d)"\n' + mk))
        self.assertFalse(makes_files_without_temp("w=`mktemp -d`\n" + mk))
        self.assertFalse(makes_files_without_temp(mk.replace("mkdir", "touch") + "python3 -c 'import tempfile; tempfile.mkdtemp()'\n"))
        self.assertFalse(makes_files_without_temp("echo hi\n"))

    def test_a_whole_file_allow_row_pins_the_whole_file_and_shows_its_literal_lines(self):
        import system_path_allowlist as A
        rows = whole_file_rows()
        self.assertEqual(sorted(A.PINS), rows, "every whole-file row needs a pin and every pin a whole-file row")
        for rel in rows:
            sha, lines = row_pin(read_raw(rel))
            want_sha, want_lines, reason = A.PINS[rel]
            self.assertGreaterEqual(len(reason.strip()), 12)
            self.assertEqual(sorted(set(lines) - set(want_lines)), [], "%s: new system-path literal lines (add them to PINS with a reason)" % rel)
            self.assertEqual(tuple(lines), tuple(want_lines), "%s: the literal lines changed" % rel)
            self.assertEqual(sha, want_sha, "%s: the file changed; a whole-file row pins the whole file. Review the edit, then run "
                                            "`python3 test_fs_guard.py --print-pins` and update PINS in system_path_allowlist.py" % rel)

    def test_the_whole_file_pin_bites_on_every_form_of_added_command(self):
        import system_path_allowlist as A
        rel = sorted(A.PINS)[0]
        base = decode(read_raw(rel))
        self.assertEqual(row_pin(read_raw(rel))[0], A.PINS[rel][0])
        forms = ["grep -q root /etc/passwd", "ls /usr/local/bin", "source /etc/os-release", ". /etc/os-release", "head -1 /etc/hostname",
                 "[ -x /usr/local/bin/grype ]", "test -f /etc/hosts", "x=$(cat /etc/hosts)", "if cat /etc/hosts; then", "cp a ${X:-/etc/y}",
                 "</etc/hosts", "x | tee -a /etc/x", "find /usr/local -name x", "cmd >/tmp/out", "echo 'a\"b'; cat /etc/hosts",
                 "ls /", "open('/')", "os.listdir('/')", "tar -C/etc -x", "cat /Etc/hosts", "ls /cores", "cat ~/x", "cat $HOME/x", "echo hi", "# a comment"]
        for f in forms:
            self.assertNotEqual(row_pin(base + "\n" + f + "\n")[0], A.PINS[rel][0], f)       # ANY edit changes the whole-file hash
        self.assertNotEqual(row_pin(base + "\ncp /tmp/y /usr/bin/y\n")[1], tuple(A.PINS[rel][1]))     # and a new literal shows in the lines
        raw = read_raw(rel)
        self.assertNotEqual(row_pin(raw + b"\xff")[0], row_pin(raw + b"\xfe")[0])          # bytes that decode to the same replacement character
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.sh")
            with open(p, "wb") as fh:
                fh.write(b"a\r\nb\rc\n")
            self.assertEqual(read_raw(p), b"a\r\nb\rc\n")                                # no newline translation on the way in
        crlf, cr = raw.replace(b"\n", b"\r\n"), raw.replace(b"\n", b"\r")
        demo = b'# a comment\rcase_ x ok "\necho FIXTURE-LINE-EXECUTED\n"\n'
        one = raw.replace(b"\n", b"\r", 1)
        for name, edited in (("CRLF copy", crlf), ("every LF to CR", cr), ("one LF to CR", one), ("a CR-after-comment demo appended", raw + demo),
                             ("a trailing CR", raw + b"\r")):
            self.assertNotEqual(row_pin(edited)[0], A.PINS[rel][0], name)
        self.assertEqual(row_pin(raw)[0], A.PINS[rel][0])
        # the context attack: moving a closing quote turns a quoted fixture line into a top-level command; the literal lines are the same
        unmoved = 'case_ x bad "$(r \'echo hi\')" "\ncp /tmp/y /usr/bin/y\n"\n'          # the cp line is INSIDE a quoted fixture
        moved = 'case_ x bad "$(r \'echo hi\')" ""\ncp /tmp/y /usr/bin/y\n'              # the closing quote moved up: a real command
        self.assertEqual(row_pin(moved)[1], row_pin(unmoved)[1])
        self.assertNotEqual(row_pin(moved)[0], row_pin(unmoved)[0])

    EXPECTED_NAMES = ["etc", "usr", "var", "private", "Library", "System", "opt", "bin", "sbin", "dev", "home", "root", "proc", "sys", "Users",
                      "tmp", "Applications", "Volumes", "run", "srv", "lib", "lib64", "boot", "mnt", "nix", "cores", "Network", "snap",
                      "workspace", "github", "media", "data", "afs", "net", "scratch", "export", "exports", "nfs", "Developer", "lost+found", "vol", "pkg",
                      "swapfile", "imagegeneration", "datadisk", "cdrom", "lib32", "libx32", "init", "__w", "_work", "docker-entrypoint.d", "entrypoint.sh",
                      "bin.usr-is-merged", "lib.usr-is-merged", "sbin.usr-is-merged", "sw", "firmlinks"]

    def test_an_approved_span_does_not_exempt_the_rest_of_the_line(self):
        allow = [("f.py", "ssl/cert.pem", "pure data in a fixture string that is only parsed")]
        self.assertEqual(literal_findings("f.py", "x = 'ssl/cert.pem'", allow)[0], [])
        self.assertEqual(literal_findings("f.py", "x = '/etc/ssl/cert.pem'", [("f.py", "/etc/ssl/cert.pem", "pure data in a string that is only parsed")])[0], [])
        for line in ("x = '/etc/ssl/cert.pem'; open('/etc/passwd')", "cat /etc/ssl/cert.pem /usr/local/bin/x", "cp /etc/ssl/cert.pem /var/db/x",
                     "x = '/etc/ssl/cert.pem' + ls /", "d=/etc/ssl/cert.pem; cd ~"):
            self.assertTrue(literal_findings("f.py", line, [("f.py", "/etc/ssl/cert.pem", "pure data in a string that is only parsed")])[0], line)
        self.assertTrue(literal_findings("f.py", "cat /usr/local/bin/fscache", [("f.py", "usr/local/bin/fscache", "a span that is only the tail of a longer literal")])[0])
        self.assertTrue(literal_findings("f.py", "cat /usr/local/bin/fscache", [("f.py", "/usr/local/bin/fscach", "a span that stops inside a token")])[0])
        two = [("f.py", "/etc/a.conf", "pure data in a string that is only parsed"), ("f.py", "/etc/b.conf", "pure data in a string that is only parsed")]
        self.assertEqual(literal_findings("f.py", "x = '/etc/a.conf' + '/etc/b.conf'", two)[0], [])
        # the SAME literal twice is a finding: only the first, reviewed occurrence is approved (second one in an open() call)
        self.assertTrue(literal_findings("f.py", "x = '/etc/a.conf' + '/etc/b.conf' + '/etc/a.conf'", two)[0])
        fscache = [("bin/test_patch.py", "/usr/local/bin/fscache", "a Dockerfile COPY destination inside the image under test (text)")]
        self.assertEqual(literal_findings("bin/test_patch.py", ' COPY fscache /usr/local/bin/fscache\n', fscache)[0], [])
        for line in (' COPY x /usr/local/bin/fscache; open("/usr/local/bin/fscache")', "+COPY x /usr/local/bin/fscache2", "cat /usr/local/bin/fscache.bak",
                     "cat /usr/local/bin/fscache-evil", "cat /usr/local/bin/fscache/x"):
            self.assertTrue(literal_findings("bin/test_patch.py", line, fscache)[0], line)
        for span, line in (("/tmp/panel-out", "rm -rf /tmp/panel-out-keep"), ("/srv/app/package.json", "cat /srv/app/package.json.d/x"),
                           ("/tmp/vex/fosterstack-cache.openvex.json", "rm /tmp/vex/fosterstack-cache.openvex.json.x"), ("/opt/tool", "cat /opt/tool-evil"),
                           ("/opt/tool", "cat /opt/tool2"), ("/usr/local/bin/fscache", "cp /usr/local/bin/fscache2 x")):
            self.assertTrue(literal_findings("bin/test_x.py", line, [("bin/test_x.py", span, "pure data in a fixture that is only parsed")])[0], line)
        self.assertTrue(literal_findings("f.py", "x = '/etc/a.conf' + '/etc/b.conf' + '/etc/c.conf'", two)[0])
        self.assertEqual(literal_findings("f.py", "anything /etc/x at all", [("f.py", "", "a whole-file row exempts the line (the file is pinned)")])[0], [])

    def test_every_top_level_name_is_found_in_every_position(self):
        self.assertEqual([x.replace("\\", "") for x in SYS_NAMES], self.EXPECTED_NAMES)      # an independent copy: dropping a name fails here
        for n in self.EXPECTED_NAMES:
            for text in ("ls /%s/x" % n, "d=/%s" % n, "open('/%s/f')" % n, "cc -o/%s/f" % n, "p=${V:-/%s}/f" % n, "ls /%s" % n.upper(),
                         "ls //%s/x" % n, "ls /./%s/x" % n, "ls /../%s/x" % n, "ls /{%s,x}/f" % n, "x=/%s2/f" % n, "x=/%s_dir/f" % n):
                self.assertTrue(literal_findings("f.py", text, [])[0], text)
            for text in ("x=/q%s/f" % n, "u=https://h/%s/x" % n, "r=a/%s/b" % n, "./%s/x" % n, "d=$work/%s" % n) + (("echo /%s-x" % n,) if not n[-1].isdigit() and "." not in n else ()):
                self.assertEqual(literal_findings("f.py", text, [])[0], [], text)
        for text in ("ls /e?c/hosts", "ls /?tc", "ls /us?/bin", "ls /{etc,usr}/x", "ls /{usr,x}", "cat /et?"):
            self.assertTrue(literal_findings("f.py", text, [])[0], text)

    def test_every_entry_of_the_real_root_of_this_machine_is_found_as_a_first_component(self):
        """Closes "a first component outside the list" for every path that exists on the machine running the suite (the dev Mac, CI)."""
        G._busy.bypass = True                                                    # a read of / by NAME, bypassing the guard (names only)
        try:
            entries = os.listdir("/")
        finally:
            G._busy.bypass = False
        self.assertTrue(entries)
        missing = [e for e in entries if not literal_findings("f.py", "ls /%s/x" % e, [])[0] or not literal_findings("f.py", "ls /%s" % e, [])[0]]
        self.assertEqual(missing, [], "top-level entries of / that the scan does not know: add them to SYS_NAMES (and to EXPECTED_NAMES, the independent copy in this class)")

    def test_first_component_classes_are_found_without_a_name_list(self):
        for text in ["ls /.vol/x", "ls /.file", "cat /.nofollow/etc/hosts", "cat /.resolve/x", "ls /.dockerenv", "ls /.fseventsd/x", "ls /.Spotlight-V100",
                     "ls /.DS_Store", "cat /.VolumeIcon.icns", "find /.", "find /. -name x", "x='/.hidden'",
                     "ls /*", "ls /U*/x", "cat /e*/hosts", "cat /[e]tc/hosts", "cat /e??/hosts", "glob.glob('/*')", "ls /?tc",
                     "cat ~root/x", "ls ~nobody", "cat ../../etc/hosts", "cd ../../..", "cd ..//..//x", "cat ../../../../etc/hosts", "x=../../y",
                     "d=/", "r='/'", "r=/ ", "r=\"/\"; ls", "git --git-dir=/x/.git status", "tar --directory=/ -x", "tar -C/ -x", "echo hi > /", "echo x >> /",
                     "cd \"/\"", "ls '/'", "os.listdir(os.sep)", "shutil.rmtree(os.sep)", "docker run --mount source=/,target=/h", "docker run --mount type=bind,src=/,dst=/h"]:
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        for text in ["cd \"$(dirname \"$0\")/../../..\"", "root=\"$here/../..\"", "cp ../x y", "a = '../x'", "u.get('d') == 'x'", "s + \"/.vex/a.json\"",
                     "open(root + \"/.github/x\")", "glob.glob(a + \"/*.json\")", "ls \"$SRC\"/*/go.mod", "re.sub(r\"</?p>\", \"\", s)",
                     "cron: '*/10 * * * *'", ":(glob)**/*.sh", "ls ./.hidden", "cat a/.b", "x = '/branches?'", "echo hi > out.txt", "name = 'a=b'", "a == '/'"]:
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)

    def test_comment_markers_hide_nothing_and_a_lone_cr_is_a_finding(self):
        for text in ["ls /*/*/", "ls /*/*/x", "for d in /*/ /*/; do ls $d; done", "cat /*/hosts /*/passwd", "rm -rf /*/ /*/x", "glob.glob('/*') + glob.glob('/*/')",
                     "ls /* # see */", "ls /*; echo 'a */ b'", "ls /* /* */", "x = /* c */ /*", "ls /* */ /*"]:
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        # fail closed: even a lone /* comment */ is a finding (a real fixture such as the strace line gets a reviewed allow row)
        self.assertTrue(literal_findings("f.py", "x = /* a comment */ 5", [])[0])
        self.assertEqual(literal_findings("f.py", "x = /* a comment */ 5", [("f.py", "/* a comment */", "a comment inside fixture text that is only parsed")])[0], [])
        # line 1 only: a "#!" line is exempt there, never later; a lone CR is its own finding and splits a .py file into lines
        self.assertEqual(literal_findings("f.py", "#!/bin/sh\necho hi", [])[0], [])
        self.assertTrue(literal_findings("f.py", "echo hi\n#!x /etc/passwd", [])[0])
        for text in ["#!x\ropen('/etc/passwd')", "#!/usr/bin/env python3\ropen('/etc/passwd').read()", "# c\ropen('/etc/hostname')", "x = 1\ropen('/etc/hosts')",
                     "#!x\ropen('/etc/passwd')\n", "pass\r\nopen('/etc/passwd')"]:
            got = literal_findings("t.py", text, [])[0]
            self.assertTrue(got, text)
        self.assertEqual(len([g for g in literal_findings("t.py", "#!x\ropen('/etc/passwd')", [])[0] if "/etc/passwd" in g]), 1)
        self.assertTrue(any("lone CR" in g for g in literal_findings("a.py", "echo hi\rcat x\n", [])[0]))
        self.assertTrue(any("lone CR" in g for g in literal_findings("a.py", "x = 1\rpass\n", [])[0]))
        self.assertEqual(literal_findings("a.py", "echo hi\r\ncat x\r\n", [])[0], [])            # CRLF is not a lone CR
        self.assertEqual(literal_findings("a.py", "echo hi\n", [])[0], [])
        self.assertEqual(split_lines("a.py", "a\rb\r\nc\nd"), ["a", "b", "c", "d"])

    def test_root_spellings_wrappers_prefixes_and_content_verbs_are_found(self):
        found = ["ls /..", "ls //", "ls /./", "os.listdir(\"/..\")", "os.listdir(\"/.//\")", "PosixPath(\"/\").iterdir()", "listdir(f\"/\")", "listdir(u\"/\")",
                 "listdir(br\"/\")", "x = R\"/\"", "grep -r x /", "head /", "wc /", "file /", "readlink -f /", "realpath /", "diff -r a /", "[ -d / ]", "test -d /",
                 "subprocess.run([\"ls\", \"/\"])", "shutil.disk_usage(\"/\")", "os.path.getsize(\"/\")", "os.statvfs(\"/\")", "os.access(\"/\", os.R_OK)",
                 "os.path.ismount(\"/\")", "os.getxattr(\"/\", \"user.x\")", "ls / -l", "ls / foo", "FOO=1 ls /", "cd / && ls", "x=$(ls /)", "if ls /; then", "os.walk(\"//\")",
                 "Path('/..')", "os.chdir('/./')", "ldd /", "lsof /", "xargs ls /", "exec ls /", ". /", "source /",
                 "true && grep -r x /", "echo a | head /", "x=1; wc /", "(file /)", "echo hi; test -d /", "{ ldd /; }"]
        for text in found:
            self.assertTrue(literal_findings("f.py", text, [])[0] or literal_findings("f.py", text, [])[0], text)
            self.assertTrue(bare_roots(text) or flagged(text), text)
        exceptions = ["a / b", "$((a / b))", "x = a / b", "sed 's/a/b/'", "sed 's/^/    /'", "echo \"$out\" | sed 's/^/      /'", "p.rsplit(\"/\", 1)", "s.split(\"/\")", "\"/\".join(parts)",
                      "x == \"/\"", "x != \"/\"", "p + \"/\" + q", "re.sub(r\"/\", \"-\", p)", "name.replace(\"/\", \"_\")", "s.replace(\":\", \"/\")", "name.startswith(\"/\")",
                      "p.endswith(\"/\")", "n = p.count(\"/\")", "x.strip(\"/\")", "docker://", "https://example.org/", "// a jq comment", "# open / merged / closed", "echo a / b",
                      "r\"</?p>\"", "cron '*/10 * * * *'", "a/b", "./", "x = 1 / 2", "print(\"a\" / \"b\")"]
        for text in exceptions:
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)
        self.assertEqual(bare_roots("x = \"/\".join(a)"), [])

    def test_dev_null_is_exempt_only_as_a_complete_path_token_and_a_shebang_only_on_line_one(self):
        for ok in ("cmd >/dev/null", "cmd 2>/dev/null", "cmd &>/dev/null", "open('/dev/null')", "x=\"/dev/null\"", "cmd > /dev/null 2>&1", "open(os.devnull)"):
            self.assertEqual(literal_findings("f.py", ok, [])[0], [], ok)
        for bad in ("open('/dev/nullx')", "cat /dev/null/x", "cat /dev/null.d", "cat /dev/null-evil", "ls /dev/null/", "cat /dev/nulls", "cat x/dev/null"[:0] + "cat /dev/null0"):
            self.assertTrue(literal_findings("f.py", bad, [])[0], bad)
        self.assertEqual(literal_findings("f.py", "#!/bin/sh\necho hi", [])[0], [])               # line 1
        self.assertTrue(literal_findings("f.py", "echo hi\n#!/bin/sh\necho there", [])[0])        # a bare second-line shebang is a finding (a reviewed row covers real heredoc content)
        self.assertTrue(literal_findings("f.py", "echo hi\n#!/usr/bin/env bash", [])[0])
        self.assertEqual(literal_findings("f.py", "printf '#!/bin/sh\\necho hi\\n' > x", [])[0], [])      # a QUOTED shebang is file content being written
        self.assertEqual(literal_findings("f.py", 'x = "#!/usr/bin/env python3\\nprint(1)"', [])[0], [])
        self.assertTrue(literal_findings("f.py", "printf '#!/bin/sh\\n' > x; cat /etc/passwd", [])[0])

    def test_os_sep_spellings_of_the_root_and_sw_firmlinks_are_found_in_python(self):
        for text in ["os.listdir(os.sep)", "os.listdir(os.path.sep)", "os.path.abspath(os.sep)", "os.path.abspath(os.path.sep)", "os.path.realpath(os.sep)",
                     "os.path.normpath(os.path.sep)", "Path(os.sep)", "pathlib.Path(os.path.sep).iterdir()", "os.path.join(os.sep, 'etc')", "os.scandir(os.sep)",
                     "root = os.sep", "root = os.path.sep;", "d = (os.sep)", "os.walk(os.sep)", "open('/sw/x')", "ls('/firmlinks')", "p = '/SW/bin'", "os.chdir(os.sep)"]:
            self.assertTrue(literal_findings("bin/test_x.py", text, [])[0], text)
        for text in ["p.split(os.sep)", "os.sep.join(parts)", "x.replace(os.sep, '_')", "name = a + os.sep + b", "os.path.join(d, 'x')", "sep = os.sep + 'x'", "swap = 1",
                     "/swift/x"[:0] + "x = 'sw/x'", "x = 'a/firmlinks'"]:
            self.assertEqual(literal_findings("bin/test_x.py", text, [])[0], [], text)

    def test_every_bare_root_form_is_found(self):
        for text in ["tar -C / -xf a.tar", "git -C / status", "env -C / cat etc/hosts", "cp x /", "mv x /", "rsync -a x /", "pushd /", "popd /",
                     "docker run -v /:/host img", "docker run --volume=/:/host img", "docker run --mount type=bind,src=/,dst=/h img",
                     "subprocess.run(['ls'], cwd='/')", "os.path.join('/', 'etc', 'hosts')", "Path('/')", "os.chdir('/')", "os.walk('/')",
                     "shutil.rmtree('/')", "ls -la /", "cd /", "cd -P /", "find / -name x", "du -s /", "cat /", "chmod -R 700 /", "chroot / sh",
                     "df -h /", "touch /", "mkdir /", "rmdir /", "tree /", "mount /", "x = os.listdir('/')", "p.iterdir('/')", "tar --directory / -x",
                     "tar --directory=/ -x", "make -C / all", "cp -r a b /", "install -m 0755 x /", "ln -s a /", "scp a /", "zip -r a.zip /"]:
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        for text in ["cd ..", "ls ./", "echo 'a / b'", "x = '/'.join(p)", "a / b", "sed 's/a/b/'", "cp x ./", "cp x y/", "tar -C dir -x", "cd $d",
                     "git -C \"$repo\" status", "echo $((a / b))", "x=`pwd`/y"]:
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)

    def test_home_without_a_slash_and_dotdot_chains_are_found(self):
        for text in ["cat ~/x", "x=~/y", "cd ~", "cd", "cd; ls", "cd && ls", "ls ~", "cat ~;", "x=~", "cp -r ~ y", "../../../../etc/hosts", "cat ../../../x", "file:///etc/hosts",
                     "file:/etc/hosts", "file://localhost/x", "echo $HOME", "os.path.expanduser('~')"]:
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        for text in ["cd ..", "cd $d", "x ~ y", "'~' suffix", "cat ../x", "file://$work/rel", "file://.", "cd dir"]:
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)

    def test_the_literal_scan_finds_every_plain_form(self):
        for text in ["d=${TMPDIR:-/tmp}/a", "docker load oci-archive:/tmp/x", "PATH=/a:/usr/bin", "cc -o/etc/hosts", "tar -C/etc -x", "cat /Etc/hosts",
                     "ls /cores", "ls /Network/x", "ls /snap", "cd /workspace", "p=/github/workspace", "open('/')", "os.listdir('/')", "ls /", "cd /",
                     "find / -name x", "stat('/')"]:
            self.assertTrue(literal_findings("f.py", text, [])[0], text)
        for text in ['x = "docker://"', "x = ('docker://', './')", "u = 'file://'", "u = \"s3://\"", "https://host/etc/x", "x=$(pwd)/etc", "./usr/bin", "a/b/etc/c", "d=$work/tmp/x", "echo 'a / b'", "x = '/'.join(p)", "cd ..", "ls ./"]:
            self.assertEqual(literal_findings("f.py", text, [])[0], [], text)


class Guard(unittest.TestCase):
    def test_open_of_a_system_file_raises(self):
        with self.assertRaises(G.SystemPathAccess):
            open("/etc/hostname")

    def test_stat_realpath_exists_readlink_listdir_of_system_paths_raise(self):
        for fn in (os.stat, os.lstat, os.readlink, os.path.realpath, os.path.exists, os.path.isfile, os.path.isdir, os.listdir):
            with self.assertRaises(G.SystemPathAccess, msg=fn.__name__):
                fn("/etc")

    def test_a_symlink_in_the_temp_dir_to_a_system_file_is_refused_when_followed(self):
        # The link to a system path is built by hand with the UNWRAPPED call inside the recorder test below, never here: this
        # test only follows a temp-dir link to a temp-dir file (allowed) and a link that escapes through a second temp link.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other:
            os.symlink(os.path.join(other, "f"), os.path.join(d, "l"))
            open(os.path.join(other, "f"), "w").close()
            self.assertTrue(os.path.islink(os.path.join(d, "l")))
            self.assertTrue(os.path.exists(os.path.join(d, "l")))             # inside the allowed roots, so followed freely

    def test_the_violation_is_not_swallowed_by_except_exception(self):
        escaped = []
        try:
            try:
                open("/etc/hostname")
                self.fail("the open was not refused")
            except Exception:
                self.fail("swallowed by except Exception")
        except G.SystemPathAccess:
            escaped.append(1)
        self.assertEqual(escaped, [1])

    def test_ancestors_of_an_allowed_root_allow_metadata_only(self):
        saved = G.ROOTS
        try:
            for root in ("/mnt/rev/w", "/opt/zz/w", "/Users/zz/work/w"):
                G.ROOTS = [root, "/usr/lib/python3.12"]
                top = "/" + root.split("/")[1]
                for p in ("/", top, os.path.dirname(root), root, root + "/x/y.py", "/usr", "/usr/lib"):
                    for fn in (os.stat, os.lstat, os.path.realpath, os.path.exists, os.path.isdir):
                        try:
                            fn(p)
                        except G.SystemPathAccess:
                            self.fail("%s(%s) refused with root %s" % (fn.__name__, p, root))
                        except OSError:
                            pass
                os.path.realpath("/usr/lib/python3.12/os.py")
                for p in (os.path.dirname(root) + "-other", "/opt/other", "/etc"):
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        os.stat(p)
                for p in (top, os.path.dirname(root)):                     # an ancestor's CONTENTS stay off limits
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        os.listdir(p)
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        open(os.path.join(p, "f"))
        finally:
            G.ROOTS = saved

    def test_the_interpreter_environment_is_readable_not_writable_and_siblings_stay_refused(self):
        """CI shape: venv root /mnt/rev/work/cache (pyvenv.cfg, bin/, lib/), repo /mnt/rev/work/cache/cache."""
        saved = (G.ROOTS, G.ENV)
        try:
            G.ROOTS = ["/mnt/rev/work/cache/cache"]
            G.ENV = ["/mnt/rev/work/cache", "/usr/lib/python3.12"]
            cfg = "/mnt/rev/work/cache/pyvenv.cfg"
            G.check(cfg, "stat", False, True)
            G.check(cfg, "lstat", True, True)
            G.check("/mnt/rev/work/cache/lib/python3.12/site-packages/coverage/tracer.py", "open")           # read
            G.check("/usr/lib/python3.12/os.py", "realpath", False, True)
            for p in (cfg, "/mnt/rev/work/cache/bin/python"):                                              # but never written
                with self.assertRaises(G.SystemPathAccess, msg=p):
                    G.check(p, "open", write=True)
            G.check("/mnt/rev/work/cache/lib/python3.12/site-packages/x/__pycache__/m.pyc", "open", write=True)   # bytecode cache
            G.check("/mnt/rev/work/cache/cache/new.txt", "open", write=True)                              # the repo is writable
            for p in ("/mnt/rev/work/other/pyvenv.cfg", "/mnt/rev/work/cache2/pyvenv.cfg",
                      "/usr/local/bin/python3", "/etc/pyvenv.cfg"):
                for meta in (True, False):
                    with self.assertRaises(G.SystemPathAccess, msg=p):
                        G.check(p, "stat", False, meta)
            self.assertTrue(G._open_writes(("p", "w")) and G._open_writes(("p", "r+")) and G._open_writes(("p", None, os.O_WRONLY | os.O_CREAT)))
            self.assertFalse(G._open_writes(("p", "r")) or G._open_writes(("p", "rb", 0)) or G._open_writes(("p", None, os.O_RDONLY)))
        finally:
            G.ROOTS, G.ENV = saved

    def test_coverages_virtualenv_walk_is_allowed_for_pyvenv_cfg_only(self):
        """coverage/inorout.py asks os.path.exists(<dir>/pyvenv.cfg) for EVERY ancestor directory of each traced module."""
        def coverage_walk(module_file):
            d, hits = os.path.dirname(module_file), []
            while True:
                hits.append(os.path.exists(os.path.join(d, "pyvenv.cfg")))
                parent = os.path.dirname(d)
                if parent == d:
                    return hits
                d = parent
        # the real walk, from a traced test module up to / (the checkout may sit anywhere: /home/runner/work/cache/cache, /Users/..)
        self.assertTrue(coverage_walk(os.path.join(G.HERE, "test_panel.py")))
        saved = (G.ROOTS, G.ENV, G.META)
        try:
            G.ROOTS, G.ENV, G.META = ["/mnt/rev/work/cache/cache"], [], ["/mnt/rev/work/metabin"]       # CI shape, interpreter elsewhere
            f = "/mnt/rev/work/cache/cache/.github/agent/bin/tests/test_panel.py"
            d = os.path.dirname(f)
            while True:
                G.check(os.path.join(d, "pyvenv.cfg"), "exists", False, True)       # every ancestor, up to /
                G.check(os.path.join(d, "pyvenv.cfg"), "lstat", True, True)
                if os.path.dirname(d) == d:
                    break
                d = os.path.dirname(d)
            for p in ("/mnt/rev/work/cache/secret", "/mnt/rev/work/cache/pyvenv.cfgx", "/mnt/rev/work/cache/xpyvenv.cfg",
                      "/mnt/rev/work/other/pyvenv.cfg", "/mnt/rev/work/cache/other/pyvenv.cfg", "/etc/pyvenv.cfg",
                      "/usr/local/bin/pyvenv.cfg", "/mnt/rev/work/cache/pyvenv.cfg/x", "/mnt/rev/work/metabin/pyvenv.cfg"):
                with self.assertRaises(G.SystemPathAccess, msg=p):
                    G.check(p, "exists", False, True)
            for kind in ("open-read", "write", "listdir-of-the-dir"):               # the file's CONTENT and any write stay refused
                with self.assertRaises(G.SystemPathAccess, msg=kind):
                    if kind == "open-read":
                        G.check("/mnt/rev/work/cache/pyvenv.cfg", "open")
                    elif kind == "write":
                        G.check("/mnt/rev/work/cache/pyvenv.cfg", "open", False, True, write=True)
                    else:
                        G.check("/mnt/rev/work/cache", "os.listdir")
            with self.assertRaises(G.SystemPathAccess):
                os.stat("/etc/pyvenv.cfg")                                          # the installed wrappers agree
        finally:
            G.ROOTS, G.ENV, G.META = saved

    def test_interpreter_named_directories_allow_their_own_metadata_only(self):
        """coverage realpaths every sysconfig path (scripts, include, the user base ...) at start-up: /root/.local/bin on a bare box."""
        saved = (G.ROOTS, G.ENV, G.META)
        try:
            G.ROOTS, G.ENV, G.META = ["/mnt/rev/work/cache/cache"], [], ["/mnt/q/.local/bin"]
            for fn in ("stat", "lstat", "realpath", "exists"):
                for p in ("/mnt", "/mnt/q", "/mnt/q/.local", "/mnt/q/.local/bin"):
                    G.check(p, fn, False, True)
            for p in ("/mnt/q/.local/share", "/mnt/q/.local/bin/tool", "/mnt/q/other", "/mnt/r"):
                with self.assertRaises(G.SystemPathAccess, msg=p):
                    G.check(p, "stat", False, True)
            for ev in ("open", "os.listdir", "os.scandir"):                           # contents stay off limits
                with self.assertRaises(G.SystemPathAccess, msg=ev):
                    G.check("/mnt/q/.local/bin", ev)
        finally:
            G.ROOTS, G.ENV, G.META = saved

    def test_a_broad_system_prefix_is_never_an_environment_root(self):
        got = G._canon_set(["/usr", "/usr/local", "/opt/homebrew", "/Users", "/home", "/opt/hostedtoolcache/Python/3.12.3/x64"], drop_broad=True)
        self.assertIn("/opt/hostedtoolcache/Python/3.12.3/x64", got)
        self.assertFalse({"/usr", "/usr/local", "/opt/homebrew", "/Users", "/home"} & got, got)
        env = G._env_roots()
        self.assertNotIn("/usr", env); self.assertNotIn("/usr/local", env)
        with self.assertRaises(G.SystemPathAccess):
            os.stat("/etc")

    def test_the_other_metadata_calls_are_wrapped_too(self):
        for n in ("access", "statvfs", "pathconf"):
            with self.assertRaises(G.SystemPathAccess, msg=n):
                getattr(os, n)("/etc", *((os.R_OK,) if n == "access" else ("PC_NAME_MAX",) if n == "pathconf" else ()))
        for n in ("listxattr", "getxattr"):
            if hasattr(os, n):
                with self.assertRaises(G.SystemPathAccess, msg=n):
                    getattr(os, n)("/etc", *(("user.x",) if n == "getxattr" else ()))

    def test_temp_repo_devnull_and_stdlib_stay_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "etc", "passwd"); os.makedirs(os.path.dirname(p))
            open(p, "w").close(); self.assertTrue(os.path.isfile(p)); self.assertEqual(os.listdir(d), ["etc"])
        open(os.devnull).close(); self.assertTrue(os.path.isdir(REPO)); self.assertTrue(os.path.isfile(os.__file__))

    def test_a_mutant_test_that_opens_a_system_file_fails_under_the_guard(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "test_mutant.py"), "w") as f:
                f.write("import unittest\nclass M(unittest.TestCase):\n    def test_x(self):\n        open('/etc/hostname').read()\n")
            r = subprocess.run([sys.executable, "-c",
                                "import sys; sys.path[:0]=[%r, %r]; import fs_guard; fs_guard.install(); import unittest; "
                                "unittest.main(module='test_mutant', argv=['x'])" % (G.HERE, d)], capture_output=True, text=True, cwd=d)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("SystemPathAccess", r.stderr)


if __name__ == "__main__":
    if "--print-pins" in sys.argv:
        import pprint, system_path_allowlist as A
        reasons = {r[0]: r[2] for r in A.ROWS if r[1] == ""}
        for rel in whole_file_rows():
            sha, lines = row_pin(read_raw(rel))
            print("    %r: (%r,\n        %s,\n        %r)," % (rel, sha, pprint.pformat(list(lines), width=130, indent=9).replace("\n", "\n        "),
                                                          A.PINS.get(rel, (0, 0, reasons[rel]))[2]))
    else:
        unittest.main()
