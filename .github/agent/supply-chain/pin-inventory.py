#!/usr/bin/env python3
"""The inventory of what our workflows pin and download (REQ-SUP-001, rule 1 and rule 2).

One item is "<kind>:<name>@<version>":
  action   owner/repo@<40-hex commit>   from `uses:` in workflows and in the composite actions under .github/actions
  tool     name@version                 installer-action inputs (golangci-lint, python) and the *_VER pins of bin/install-scanner.sh
  gotool   module/path@version          `go install path@version` in a run step
  package  pypi/name@version            the hash-pinned requirements files
  image    name@sha256:digest           container:/services: images and docker:// actions (name:tag@sha256:digest is the SAME item: Docker ignores the tag)
NOT in the inventory (rule 1, amendments 1 and 2): the product's base image, Go modules and the Go toolchain.

Used as a module by pin-age-check.py and pin-audit.py; run alone it prints the inventory of a tree.
"""
import bisect
import collections
import configparser
import copy
import fnmatch
import hashlib
import shlex
import stat
import json
import os
import posixpath
import re
import subprocess
import sys

import yaml

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# installer-action inputs that name a version of something the action downloads: action -> (input, tool name)
INSTALLER_INPUTS = {
    "golangci/golangci-lint-action": [("version", "golangci-lint")],
    "actions/setup-python": [("python-version", "python")],
    "actions/setup-java": [("java-version", "java")],
    "actions/setup-node": [("node-version", "node")],
    "goreleaser/goreleaser-action": [("version", "goreleaser")],
    "sigstore/cosign-installer": [("cosign-release", "cosign")],
    "google-github-actions/setup-gcloud": [("version", "gcloud")],
    "azure/setup-helm": [("version", "helm")],
    "docker/setup-buildx-action": [("version", "buildx")],
    "docker/setup-qemu-action": [("image", None)],
    "helm/kind-action": [("version", "kind"), ("kubectl_version", "kubectl"), ("node_image", None)],  # None: the input names an image
}
# NOT here, on purpose (rule 1, amendment 2): actions/setup-go's go-version and go.mod's toolchain line; the standard library ships in our binary.
_GO_INSTALL = re.compile(r"\bgo\s+install\b([^\n;&|]*)")
_GO_TARGET = re.compile(r"(?<![\w.\-/@])((?:\$\{var\}|[\w.\-/])+)@((?:\$\{\{expression\}\}|\$\{var\}|[\w.\-+()]|\$(?!\{\{))+)")
_GH_DOWNLOAD = re.compile(r"github\.com/([\w.-]+/[\w.-]+)/releases/download/(v?)((?:\$\{\{expression\}\}|\$\{var\}|[\w.+()-]|\$(?!\{\{))+)/([^\s/'\x22?#;|&]+)")
_GH_LATEST = re.compile(r"github\.com/([\w.-]+/[\w.-]+)/releases/latest/download/")
_GO_RUN_GET = re.compile(r"\bgo\s+(?:run|get)\b([^\n;&|]*)")

def _word(t):
    """The command word hidden in one whitespace token: the part after the last assignment/quote/paren/substitution character, without trailing ones, as a BASENAME
    (`X="pip` `cmd=(pip` `$(pip` `os.system('pip` `--cmd="pip` `/usr/bin/pip3` `.venv/bin/pip` `"$V/bin/pip"` all give `pip`; `-mpip` gives `pip`)."""
    w = re.split(r"[\s'\"`({\[,=:$#;&|<>]", t.rstrip("'\"`)}],;:"))[-1].rsplit("/", 1)[-1]
    return "pip" if w == "-mpip" else w


class Word:
    """One shell word, resolved statically: text (quote fragments concatenated, escapes resolved), dyn (a `$`, backtick or `$(` that is not one of this inventory's placeholders),
    meta (an UNQUOTED character the shell would expand: glob * ?, brace {a,b}, a leading ~ or !), open (a quote left open in it)."""
    __slots__ = ("text", "dyn", "meta", "open")

    def __init__(self, text, dyn=False, meta=False, open_=False):
        self.text, self.dyn, self.meta, self.open = text, dyn, meta, open_


class Cmd:
    __slots__ = ("words", "meta")

    def __init__(self):
        self.words, self.meta = [], False


_LEX_BUDGET = 4_000_000      # characters of nested text one _lex call may read (a 4000-character line, the longest this check reads, nested a thousand deep, costs under 3 million)
_LEX_LIMIT = [False]
_SCAN_DEEP = [False]         # the file just scanned was nested beyond the safe depth


def _lex(text):
    """The commands of one line of shell text, nested text (quoted strings, comments, substitutions) included, with an explicit work-list: ANY nesting depth is scanned in full. The only
    bound is a budget on the total characters read; when it is hit the scan stops, _LEX_LIMIT is set and the file gets an unmeasured `scan limit reached` item (never a silent stop)."""
    cmds, work, spent = [], [text], 0
    while work:
        t = work.pop()
        spent += len(t)
        if spent > _LEX_BUDGET:
            _LEX_LIMIT[0] = True
            break
        cmds.extend(_lex_level(t, work))
    return cmds


_BRACE = re.compile(r"\{[^{}]*(?:,|\.\.)[^{}]*\}")
_FD_PREFIX = re.compile(r"\d+|\{[A-Za-z_]\w*\}")


def _lex_level(text, work):
    """THE shell lexer for install commands (one place, no ad-hoc token scans): the commands of one line of shell text, each a list of Words. Quote fragments concatenate and backslash
    escapes resolve; the operators ; & | ( ) $( ` split commands even when attached to a word; redirections (> >> < << <<< >& <& &> >| <> with an optional fd or {name} prefix and the target
    as the next word or attached, quoted or escaped) are removed together with their target; a word-initial unquoted # starts a comment, which is lexed as a command line of its own (an install
    string in a comment still counts, but its characters are not arguments of the command before it); the content of every quoted string is lexed as a line of its own too (AC11: no
    data/code classification)."""
    cmds = []
    cur_cmd = [Cmd()]
    st = {"cur": [], "dyn": False, "meta": False, "have": False, "opn": False, "unq": []}
    n, i = len(text), 0

    def reset():
        st.update(cur=[], dyn=False, meta=False, have=False, opn=False, unq=[])

    def end_word():
        if st["have"]:
            cur_cmd[0].words.append(Word("".join(st["cur"]), st["dyn"], st["meta"] or bool(_BRACE.search("".join(st["unq"]))), st["opn"]))
        reset()

    def end_cmd():
        end_word()
        if cur_cmd[0].words or cur_cmd[0].meta:
            cmds.append(cur_cmd[0])
        cur_cmd[0] = Cmd()

    def read_quoted(i):
        """The quoted segment starting at text[i] is appended to the current word; returns the index of its closing quote (n when it is left open)."""
        q = text[i]
        st["have"] = True
        if q == "'":
            j = text.find("'", i + 1)
            body = text[i + 1:j if j >= 0 else n]
        else:
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] in '"\\$`':
                    j += 1
                if text[j] == "`" or (text[j] == "$" and text[j + 1:j + 2] not in ("{", "")):
                    st["dyn"] = True
                buf.append(text[j])
                j += 1
            body = "".join(buf)
            if j >= n:
                j = -1
        st["cur"].append(body)
        if j < 0:
            st["opn"] = True
            j = n
        if body.strip() and (len(body.split()) > 1 or "=" in body):
            work.append(body)        # a quoted string that holds a command line is a command line too
        return j

    def read_target(i):
        """Skip whitespace, read one word (quotes, escapes) and discard it; returns the index after it."""
        while i < n and text[i] in " \t":
            i += 1
        saved = dict(st)
        saved["cur"], saved["unq"] = list(st["cur"]), list(st["unq"])
        reset()
        while i < n and text[i] not in " \t\n;&|()<>":
            c = text[i]
            if c == "\\":
                i += 2
                continue
            if c in "'\"":
                i = read_quoted(i) + 1
                continue
            i += 1
        st.update(saved)
        return i

    while i < n:
        c = text[i]
        if c in " \t":
            end_word()
        elif c == "\n":
            end_cmd()
        elif c == "#" and not st["have"]:
            rest = text[i + 1:]
            if rest.strip():
                work.append(rest)        # a comment is not an argument; an install string in it still counts
            break
        elif c == "\\":
            st["have"] = True
            if i + 1 < n:
                i += 1
                st["cur"].append(text[i])
        elif c in "'\"":
            i = read_quoted(i)
        elif c in "<>" or (c == "&" and text[i + 1:i + 2] == ">"):
            if c in "<>" and text[i + 1:i + 2] == "(":        # <( ) and >( ): a process substitution cannot be read statically
                cur_cmd[0].meta = True
                end_word()
                j, d = i + 2, 1
                while j < n and d:
                    d += (text[j] == "(") - (text[j] == ")")
                    j += 1
                work.append(text[i + 2:j - 1])
                i = j - 1
            else:
                if st["have"] and _FD_PREFIX.fullmatch("".join(st["cur"])):
                    reset()                                   # the fd (or {name}) of a redirection is not a word
                else:
                    end_word()
                j = i + 1 if c == "&" else i
                op = text[j]
                j += 1
                while j < n and text[j] == op and j - i < 3:
                    j += 1                                    # >> << <<<
                if op == "<" and text[j:j + 1] == "-":
                    j += 1                                    # <<-
                if op in "<>" and text[j:j + 1] == "&":       # >&2 <&3 >&- and >&file
                    j += 1
                    k = j
                    while k < n and (text[k].isdigit() or text[k] == "-"):
                        k += 1
                    if k > j and (k >= n or text[k] in " \t\n;&|()<>"):
                        i = k
                        continue
                elif op == ">" and text[j:j + 1] == "|":
                    j += 1
                i = read_target(j)
                continue
        elif c in ";&|()":
            end_cmd()
            if c in "&|" and text[i + 1:i + 2] in ("&", "|"):
                i += 1
            elif c == "|" and text[i + 1:i + 2] == "&":
                i += 1
        elif c == "$" and text[i + 1:i + 2] == "(":
            j, d = i + 2, 1
            while j < n and d:
                d += (text[j] == "(") - (text[j] == ")")
                j += 1
            st["cur"].append("$(")
            st["dyn"] = st["have"] = True
            work.append(text[i + 2:j - 1 if d == 0 else j])      # a command substitution is a command line of its own; the word it sits in goes on
            if d:
                st["opn"] = True
            i = j - 1
        elif c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            st["cur"].append("`")
            st["dyn"] = st["have"] = True
            work.append(re.sub(r"\\([`\\$])", r"\1", text[i + 1:j]))      # the escapes of a nested backtick pair are removed as the shell does
            if j >= n:
                st["opn"] = True
            i = min(j, n)
        else:
            if c == "$" and text[i + 1:i + 2] not in ("{", ""):
                st["dyn"] = True
            if c in "*?" or (c in "~!" and not st["have"]):
                st["meta"] = True
            st["have"] = True
            st["cur"].append(c)
            st["unq"].append(c)
        i += 1
    end_cmd()
    return cmds


def _cmd_scan(run, is_cmd, subcommands, skip_values=(), known_opts=None):
    """[(subcommand, [Word] after it, an option unknown to known_opts stood before the subcommand, the command held a process substitution)] for every command word `is_cmd` accepts."""
    out = []
    for line in run.split("\n"):
        for cmd in _lex(line):
            ws = cmd.words
            for i, w in enumerate(ws):
                if not is_cmd(_word(w.text)):
                    continue
                j, unknown = i + 1, False
                while j < len(ws) and ws[j].text.startswith("-"):
                    t = ws[j].text
                    j += 1
                    if known_opts is not None and not known_opts(t):
                        unknown = True
                        if j < len(ws) and not ws[j].text.startswith("-") and ws[j].text not in subcommands:
                            j += 1                     # an option this scan does not know may take the next word as its value
                    elif t in skip_values and "=" not in t:
                        j += 1
                while j < len(ws) and ws[j].text in ("container", "image") and ws[j].text not in subcommands:
                    j += 1
                if known_opts is not None and j < len(ws) and ws[j].text not in subcommands and (ws[j].dyn or ws[j].meta or "${" in ws[j].text) and not ws[j].text.startswith("-"):
                    out.append(("(dynamic)", ws[j + 1:], True, cmd.meta))       # the subcommand is built at run time ($'install', ins$'t'all, install{,}, $SUB): it cannot be read, so it is unmeasured
                elif j < len(ws) and ws[j].text in subcommands:
                    out.append((ws[j].text, ws[j + 1:], unknown, cmd.meta))
                    if len(out) > MAX_ITEMS_PER_STEP:
                        raise RuntimeError("a step repeats one command more than %d times: refusing to read it (a hostile text could exhaust the readers)" % MAX_ITEMS_PER_STEP)
    return out


def _tails(run, is_cmd, subcommands, skip_values=(), keep_sub=False):
    """For every command word `is_cmd` accepts, the resolved words after its subcommand, joined by a space."""
    out = []
    for sub, ws, _unknown, _meta in _cmd_scan(run, is_cmd, subcommands, skip_values):
        t = " ".join(shlex.quote(w.text) if (not w.text or re.search(r"[\s'\"\\]", w.text)) else w.text for w in ws)      # a word with a space stays ONE word for the readers that split the tail again
        out.append((sub, t) if keep_sub else t)
    return out


class Tail(str):
    """A pip install tail: the joined resolved words (what the stdin/heredoc readers search), with the Words and the scan's flags."""
    words = ()
    unknown = False
    cmd_meta = False
    sub = "install"


_PIP_GLOBAL_VAL = {"--proxy", "--retries", "--timeout", "--exists-action", "--trusted-host", "--cert", "--client-cert", "--cache-dir", "--log", "--python", "--use-feature"}
_PIP_GLOBAL_BOOL = {"-v", "--verbose", "-q", "--quiet", "--no-input", "--isolated", "--require-virtualenv", "--debug", "--no-cache-dir", "--disable-pip-version-check", "--no-color", "-V",
                    "--version", "-h", "--help", "--no-python-version-warning"}


def _pip_known_opt(t):
    return t.split("=", 1)[0] in _PIP_GLOBAL_VAL or t in _PIP_GLOBAL_BOOL or re.fullmatch(r"-[vq]+", t) is not None


_PIP_INSTALL_FLAGS = {"--no-deps", "--pre", "--user", "--upgrade", "--force-reinstall", "--ignore-installed", "--ignore-requires-python", "--no-build-isolation", "--use-pep517", "--no-use-pep517",
                      "--check-build-dependencies", "--break-system-packages", "--compile", "--no-compile", "--no-warn-script-location", "--no-warn-conflicts", "--prefer-binary", "--require-hashes",
                      "--no-clean", "--no-index", "--dry-run", "--disable-pip-version-check", "--no-cache-dir", "--quiet", "--verbose", "--no-input", "--isolated", "--no-color", "--debug",
                      "--require-virtualenv", "--no-python-version-warning", "--help", "--version", "--no-binary-all", "--hash", "--no-user"}


def _known_install_opt(t):
    base = t.split("=", 1)[0]
    if t.startswith("--"):
        return base in _PIP_VALUE_OPTS or base in _PIP_INSTALL_FLAGS or base in _PIP_GLOBAL_VAL or base in _PIP_GLOBAL_BOOL
    return t in _PIP_VALUE_OPTS or t in _PIP_GLOBAL_BOOL or re.fullmatch(r"-[vqUIhV]+", t) is not None or _REF_SHORT.match(t) is not None


_PIP_NAME = re.compile(r"[A-Za-z0-9][\w.-]*(?:\[[\w.,\s-]*\])?")


def _pip_items(tail, out):
    """The items of one `pip install` tail. Every argument must resolve statically; one that cannot (an open quote, a variable or substitution, a brace, a glob, a tilde, a process
    substitution, a name that is not a plain name with extras directly after it) is ONE unmeasured item and the other arguments are still measured."""
    def unmeasured(what):
        out.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(what.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)"))
    if tail.unknown or tail.cmd_meta:
        unmeasured(str(tail) + "|opt")
    for ref, ok in _tail_file_refs(tail.words, tail.sub):          # a FILE fed to pip with -r / -c (or to pip-sync): read as a requirements file (its pins are items) or, when it cannot be read, unmeasured
        if ok:
            out.append(Item("package", "pypi/(reqref)", ref))
        else:
            unmeasured(ref)
    if tail.sub == "sync":
        return                                                    # pip-sync / uv pip sync install what the files list: no package arguments of their own
    keep, prev, skip_next = [], "", False
    for w in tail.words:
        t = w.text
        if skip_next:
            skip_next = False
            if not t.startswith("-"):
                prev = t
                continue                           # the value of an option this check does not know: never a package
        value_of_option = _takes_value(prev)      # `-r deps.txt` and `-qr deps.txt` name a file, not a package
        prev = t
        if t.startswith("-") and len(t) > 1 and not value_of_option and not _known_install_opt(t):
            unmeasured(t)                          # an option unknown to this check (--chdir sub, --anything): unmeasured, and what follows it is its value, not a package
            skip_next = "=" not in t
            keep.append(w)
            continue
        if value_of_option or t.startswith("-"):
            if w.open:
                unmeasured(t)
            keep.append(w)             # an option or its value (an index URL with a ? or * drops nothing): not a package argument
            continue
        if w.open or re.search(r"`|\$\(", t):
            unmeasured(t)
            continue
        if w.meta:
            unmeasured(t)
            continue
        nm = re.match(r"([^=<>!~]+)(?:===|==|>=|<=|~=|!=|[<>])", t)
        if w.dyn and nm is not None and "$" in nm.group(1):
            unmeasured(t)
            continue
        if nm is not None and "$" not in nm.group(1) and not _PIP_NAME.fullmatch(nm.group(1).strip()):
            unmeasured(t)              # not a plain package name (a bracket expression is a shell glob; extras only directly after a name)
            continue
        if nm is None and "$" not in t and not re.search(r"[:/\\]", t) and t not in ("==", ">=", "<=", "~=", "!=", "===", "<", ">") and not _PIP_NAME.fullmatch(t) and not re.fullmatch(r"[\d.]+", t):
            unmeasured(t)              # an unversioned argument that is no plain name
            continue
        keep.append(w)
    tail = _OPS.sub(r"\1", " ".join(w.text for w in keep))         # PEP 508 allows spaces around the operator
    for p in _PIP_PIN.finditer(tail):  # a range (>=, ~=...) is not a pin: kept with its operator, it cannot be proven and fails closed
        ver = p.group(3) if p.group(2) == "==" else p.group(2) + p.group(3)
        out.append(Item("package", f"pypi/{p.group(1).lower().replace('_', '-')}", ver))
    prev = ""
    for tok in tail.split():
        value_of_option = _takes_value(prev)
        prev = tok
        if value_of_option:
            continue
        if not tok.startswith("-") and re.search(r"[:/\\]", tok) and "$" not in tok:
            out.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(tok.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)"))   # a URL or a path: it cannot be read as a version
            continue
        if "$" in tok and not tok.startswith("-"):
            out.append(Item("package", "pypi/(variable)", "(unpinned)"))     # pip install $DEPS: a variable list, a placeholder
            continue
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(\[[\w,.-]*\])?", tok) and not tok.startswith("-") and not re.fullmatch(r"[\d.]+", tok):
            out.append(Item("package", f"pypi/{tok.split('[')[0].lower().replace('_', '-')}", "(unpinned)"))  # no version at all: it cannot be proven, so adding one fails closed


def _pip_tails(run):
    out = []
    for sub, ws, unknown, meta in _cmd_scan(run, lambda t: re.fullmatch(r"pip[0-9.]*", t) is not None, {"install", "sync"}, _PIP_VALUE_OPTS | {"--timeout", "--retries", "--proxy", "--cert", "--cache-dir", "--log"}, known_opts=_pip_known_opt):
        t = Tail(" ".join(w.text for w in ws))
        t.words, t.unknown, t.cmd_meta, t.sub = ws, unknown, meta, sub
        out.append(t)
    for line in run.split("\n"):
        if "pip-sync" not in line and "piptools" not in line:
            continue
        for cmd in _lex(line):
            for i, w in enumerate(cmd.words):
                base = w.text.rsplit("/", 1)[-1]
                if base == "pip-sync" or (base == "piptools" and i + 1 < len(cmd.words) and cmd.words[i + 1].text == "sync"):
                    ws = cmd.words[i + (1 if base == "pip-sync" else 2):]
                    t = Tail(" ".join(x.text for x in ws))
                    t.words, t.unknown, t.cmd_meta, t.sub = ws, False, cmd.meta, "sync"
                    out.append(t)
    return out


_PIP_PIN = re.compile(r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]*\])?(===|==|>=|<=|~=|!=|>|<)((?:\$\{\{expression\}\}|\$\{var\}|[^\s\\;'\",$`)]|\$(?!\{\{))+)")
_STDIN_REQ = re.compile(r"(?:^|\s)(?:-r|--requirement)[\s=]*(?:/dev/stdin|-)(?=\s|$)")
_HEREDOC_OPEN = re.compile(r"<<-?[ \t]*(['\"]?)(\w+)\1[^\n]*\n")
_WORD_LINE = re.compile(r"^[ \t]*(\w+)[ \t]*$", re.M)


_Heredoc = collections.namedtuple("_Heredoc", "start body")          # where the `<<` stands, and the text between the opener line and its terminator


def _heredocs(text):
    """The heredocs of a text, in LINEAR time: terminator lines are indexed once by their word and found by bisection (a regex with a lazy body re-scans the rest of the text for every
    unterminated opener, which is quadratic). A heredoc starts at `<<WORD` and ends at the first later line that is only WORD."""
    where = {}
    for m in _WORD_LINE.finditer(text):
        where.setdefault(m.group(1), []).append(m.start())
    out, skip = [], 0
    for m in _HEREDOC_OPEN.finditer(text):
        if m.start() < skip:
            continue                               # inside a previous heredoc
        offs = where.get(m.group(2), ())
        k = bisect.bisect_left(offs, m.end() + 1)
        if k >= len(offs):
            continue                               # unterminated: not a heredoc
        t = offs[k]
        out.append(_Heredoc(m.start(), text[m.end():t - 1]))
        e = text.find("\n", t)
        skip = len(text) if e < 0 else e
    return out
_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]*\])?\s*==\s*([^\s;\\]+)\s*(?:;[^\n]*?)?(?:\s+--hash[=\s]\S+)*\s*$")
_OPS = re.compile(r"\s*(===|==|>=|<=|~=|!=)\s*(?=[\w.$'\"])")
_RUN_IMAGE = re.compile(r"(?<![\w./:@-])((?:[\w.-]+(?::\d+)?/)*[\w.-]+(?::[\w.-]+)?@sha256:[0-9a-f]{64})")
_VER_PIN = re.compile(r"^[ \t]*(?:(?:export|readonly|declare(?:\s+-\w+)?|local)\s+)?([A-Z][A-Z0-9]*)_VER=['\"]?([^\s'\"#]+)", re.M)
_REQ_PIN = re.compile(r"^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]*\])?==([^\s;\\]+)", re.M)
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml",
                  ".github/actions/*/*/action.yml", ".github/actions/*/*/action.yaml")



MAX_FILE = 1_000_000
VERSION_FILES = (".python-version", ".nvmrc", ".node-version", ".java-version", ".tool-versions", ".sdkmanrc", ".ruby-version")


def _strip_expressions(text):
    """Every ${{ ... }} becomes the placeholder, in LINEAR time (a lazy regex over an unclosed run of '${{' is quadratic and could stall a reader for minutes)."""
    out, i = [], 0
    while True:
        a = text.find("${{", i)
        if a < 0:
            out.append(text[i:])
            return "".join(out)
        b = text.find("}}", a + 3)
        if b < 0:
            out.append(text[i:a] + "${{expression}}")   # unclosed: the rest is one expression
            return "".join(out)
        out.append(text[i:a] + "${{expression}}")
        i = b + 2


def _hide(text):
    """An expression (which may name a secret or an environment) becomes a placeholder: it can never be proven, so it fails closed, and it never prints."""
    if not isinstance(text, str):
        return text
    text = _strip_expressions(text)
    return re.sub(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", "${var}", text)  # a shell variable's name (an env var, maybe a secret's) never prints either


class Item:
    def __init__(self, kind, name, version, label="", path=""):
        self.expr = any("${{" in str(x) for x in (name, version, label, path)) or name == "(expression)"     # an expression anywhere in what is pinned (advisor 0245)
        self.kind, self.name, self.version, self.label, self.path = kind, _hide(name), _hide(version), _hide(label), _hide(path)  # path: an action's subdirectory
        self.step = ""   # a placeholder's identity: the hash of the step it sits in
        self.file, self.line = "", 0
        self.why = ""
        self.incomplete = False   # the item of a scan that was not complete: its own class, never an expression
        self.labels = {self.label} if self.label else set()      # every comment this pin carries in the tree (the same commit may be pinned twice)

    @property
    def key(self):
        sub = f"/{self.path}" if self.path else ""
        return f"{self.kind}:{self.name}{sub}@{self.version}" + (f"#{self.step}" if self.step else "")

    def __repr__(self):
        return self.key


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, errors="replace")  # a non-UTF-8 blob must never crash the readers
    if r.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


_UNSET = object()
_BLOBS = {}  # blob id -> bytes: a history scan reads each distinct file version once, not once per commit


MANIFEST = ".github/agent/supply-chain/harness-manifest.json"

_REQ_COMMENT = re.compile(r"(^|\s+)#.*$")
_REQ_ONE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.\s-]*\])?\s*(===|==|~=|!=|<=|>=|<|>)\s*([^\s;\\]+)")


def _req_lines(text):
    """The requirement lines of a requirements file the way pip reads it: split like str.splitlines (CR, FF, VT, FS, GS, RS, NEL, LS and PS each end a line), a trailing backslash joins the next
    line with NOTHING unless the line is a comment line, and a comment (a # at the start or after whitespace) runs to the end of the JOINED line."""
    out, new = [], []
    for line in text.splitlines():
        if not line.endswith("\\") or _REQ_COMMENT.match(line):
            if _REQ_COMMENT.match(line):
                line = " " + line
            if new:
                new.append(line)
                out.append("".join(new))
                new = []
            else:
                out.append(line)
        else:
            new.append(line.strip("\\"))
    if new:
        out.append("".join(new))
    return [b for b in (_REQ_COMMENT.sub("", l).strip() for l in out) if b]


def _shell_shebang(text):
    """Is the first line a shebang that runs a SHELL (the list is in AC11)? Decided by the TEXT of every `#!` line, fail closed: the line holds a shell-vocabulary word (a name ending in `sh`,
    bounded by non-word characters, with an optional version suffix) once its quote characters and env's escape sequences are removed; a `${`, `$(` or backtick, or an escape this check does
    not know, is treated as a shell. So `env -S ba"s"h`, `nice bash`, `timeout 5 bash`, `exec bash`, `busybox sh`, `bash\\_-e` are shell scripts; python, node, perl are not."""
    first = (text[1:] if text.startswith("\ufeff") else text).split("\n", 1)[0].rstrip("\r")
    if not first.startswith("#!"):
        return False
    line = first[2:]
    if "${" in line or "$(" in line or "`" in line:
        return True
    if re.search(r"\\(?![_c\"'\\$#])", line):          # an escape this check does not know: treated as a shell, fail closed
        return True
    line = re.sub(r"\\[_c\"'\\$#]", " ", line).replace('"', "").replace("'", "")       # env's own escapes (\_ is a separator) become spaces; quote characters go
    return re.search(r"(?<![A-Za-z0-9_])[A-Za-z0-9_.-]*sh[0-9]*(?:\.[0-9]+)*(?![A-Za-z0-9_])", line, re.I) is not None


class Files(dict):
    """{path: text}; .sha256 = {path: hex digest of the file's exact bytes} (a symlink: of its link text); .links = {path: link text} for the symlinks."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.sha256 = {}
        self.links = {}
        self.reqrefs = set()
        self.limit = {}                # path -> digest of the include chain that was NOT read after it
        self.symlinks = set()          # EVERY tracked symlink (also those that are not read): a reference through a symlinked directory cannot be bound by its text


def _is_script_name(n):
    return n.lower().endswith((".sh", ".bash", ".ksh", ".zsh", ".bats", ".dash", ".fish", ".csh", ".tcsh"))


def _wf_or_action_name(n):
    return any(fnmatch.fnmatchcase(n, g) for g in WORKFLOW_GLOBS) or bool(re.search(r"(^|/)action\.ya?ml$", n))


def _requirements_name(n):
    return bool(re.search(r"(^|/)[\w.-]*requirements[\w.-]*\.txt$", n))


def _is_script(path, text):
    """A shell script: a .sh/.bash file, or any file whose first line is a shell shebang, whatever its name; the file kind by NAME comes first (a workflow or an action file that
    starts with a `#!` comment stays a workflow; so does a requirements file)."""
    if _wf_or_action_name(path) or _requirements_name(path) or path == MANIFEST:
        return False
    return _is_script_name(path) or _shell_shebang(text)


HEAD_BYTES = 4096


def _pip_file_refs(text, path=""):
    """The FILE names a text feeds to pip with -r / --requirement / -c / --constraint (attached, clustered and `=` forms too), to pip-sync and to uv pip sync, found with the lexer on the raw
    lines (backslash-newline deleted): [(name, resolvable)]; a name that is `-`, `/dev/stdin` or a heredoc is not a file."""
    out = []
    for line in re.sub(r"\\\r?\n", "", text).split("\n"):
        if "pip" not in line:
            continue
        for tail in _pip_tails(line):
            out += _tail_file_refs(tail.words, tail.sub)
    return out + _env_file_refs(text, path)


_SYNC_VALUE_OPTS = {"--pip-args", "--index-url", "-i", "--extra-index-url", "-f", "--find-links", "--python-executable", "--cert", "--client-cert", "--trusted-host", "--python", "--target"}
_REF_SHORT = re.compile(r"^-[vqUIhV]*([rc])(=?)(.*)$")


def _takes_value(prev):
    """Does the option word before this one take it as its value (-r FILE, -qr FILE, --index-url URL ...)?"""
    return prev in _PIP_VALUE_OPTS or prev == "--hash" or re.fullmatch(r"-[vqUIhV]*[rc]", prev) is not None


def _tail_file_refs(words, sub="install"):
    out, take, prev = [], False, ""
    for w in words:
        t = w.text
        ok = not (w.dyn or w.meta or w.open)
        if sub == "sync":
            if not t.startswith("-") and prev not in _SYNC_VALUE_OPTS:
                out.append((t, ok))                 # pip-sync FILE...: every positional word is a requirements file
            prev = t
            continue
        if take:
            take = False
            out.append((t, ok))
            continue
        if t in ("-r", "--requirement", "-c", "--constraint") or re.fullmatch(r"-[vqUIhV]*[rc]", t):
            take = True
        else:
            m = re.match(r"^(?:--requirement=|--constraint=)(.+)$", t)
            m2 = _REF_SHORT.match(t) if not t.startswith("--") else None
            if m:
                out.append((m.group(1), ok))
            elif m2 and m2.group(3):
                out.append((m2.group(3), ok))        # -rFILE, -r=FILE, -qrFILE
    if take:
        out.append(("(no value)", False))            # a trailing -r or -c: its value arrives from xargs or find, so the file cannot be named
    return [(n, ok) for n, ok in out if n not in ("-", "/dev/stdin")]


MAX_INCLUDE_DEPTH = 8          # how deep a chain of `-r other.txt` includes is followed; deeper is reported ("scan limit reached"), never dropped silently
_ENV_REF_RX = re.compile(r"\b(PIP_(?:CONSTRAINT|REQUIREMENT|CONFIG_FILE))\b[ \t]*[:=][ \t]*(?:\"([^\"\n]*)\"|'([^'\n]*)'|([^\s#;&|,}\]]*))")
_REQ_INCLUDE = re.compile(r"^(?:--requirement|--constraint|-r|-c)(?:[ \t]*=[ \t]*|[ \t]+|(?=[^\s=-]))(\S.*?)\s*$")


def _pip_conf_refs(text):
    """The reference markers of a pip.conf / pip.ini: the `requirement` and `constraint` keys of its [install] and [global] sections (whitespace-separated files); a file that cannot be parsed is unmeasured."""
    cp = configparser.RawConfigParser(strict=False)
    try:
        cp.read_string(text)
    except configparser.Error:
        return [_unmeasured_item("(pip configuration file)")]
    found = []
    for sec in ("install", "global"):
        if cp.has_section(sec):
            for key in ("requirement", "constraint"):
                if cp.has_option(sec, key):
                    for ref in (cp.get(sec, key) or "").split():
                        found.append(Item("package", "pypi/(reqref)", ref) if not any(c in ref for c in "$`{") else _unmeasured_item(ref))
    return found


def _unmeasured_item(what):
    return Item("package", "pypi/(unmeasured:" + hashlib.sha256(what.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)")


YAML_SAFE_DEPTH = 200          # the steps that BUILD structures (the composer, the constructor, the walkers) are safe to about 450 levels, measured; a document nested deeper is scanned FLAT


def _yaml_guard(text, path=""):
    """Read a YAML text as EVENTS only, one at a time, BEFORE anything builds or walks the document. Refused: an alias or anchor (a nest of aliases expands exponentially when the parsed tree is
    walked) and an absurd number of nodes. Nesting NEVER refuses: the result is True when the document is nested deeper than YAML_SAFE_DEPTH, and the caller then reads it flat (every decoded scalar
    from the event stream, no nested structure built) and reports `scan limit reached`. This is the first thing that touches the text; no function may walk a document that has not passed it."""
    name = path or "a file"
    nodes = depth = peak = 0
    try:
        for ev in yaml.parse(text, Loader=yaml.BaseLoader):
            if isinstance(ev, yaml.AliasEvent):
                raise RuntimeError(f"{name} uses a YAML alias or anchor, which this check refuses (it cannot be read safely)")
            if isinstance(ev, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                depth += 1
                if depth > peak:
                    peak = depth
            elif isinstance(ev, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                depth -= 1
            nodes += 1
            if nodes > 200000:
                raise RuntimeError(f"{name} is too large to read safely")
    except RecursionError:
        return True
    return peak > YAML_SAFE_DEPTH


def _all_scalars(text):
    """EVERY decoded scalar of a YAML text (plain, quoted with escapes decoded, folded, literal; keys too), from the event stream: no nested structure is built, so any depth is read. Flattened, once each."""
    seen, out = set(), []
    try:
        for ev in yaml.parse(text, Loader=yaml.BaseLoader):
            if isinstance(ev, yaml.ScalarEvent) and ev.value:
                v = " ".join(ev.value.split())
                if v and v not in seen:
                    seen.add(v)
                    out.append(v)
    except (yaml.YAMLError, RecursionError):
        pass
    return out


_ENV_MEMO = {}
_PIP_ENV_KEYS = ("PIP_CONSTRAINT", "PIP_REQUIREMENT")
_PIP_CONFIG_REF = ("(pip configuration file)", False)
_PIP_NONSCALAR_REF = ("(pip environment value)", False)


def _env_file_refs(text, path=""):
    """The files PIP_CONSTRAINT and PIP_REQUIREMENT name, and the fact that PIP_CONFIG_FILE is set. In YAML (a workflow, an action) they are read from the PARSED document, after the alias refusal:
    an env mapping with a quoted key, a value on the next line, a block scalar, flow style or a YAML escape (workflow, job, step and composite-action env), and an assignment or export inside any
    decoded string (a run block). A value that is not a scalar string is unmeasured. In a script, from the raw text: a quoted or unquoted assignment, an export, an inline assignment before pip.
    [(name, resolvable)]"""
    key = (hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), _wf_or_action_name(path))
    if key in _ENV_MEMO:
        return list(_ENV_MEMO[key])
    out = []

    def add(val):
        for w in str(val).split():
            out.append((w, not any(c in w for c in "$`{")))

    def scan(string):
        for m in _ENV_REF_RX.finditer(re.sub(r"\\\r?\n", "", string)):
            if m.group(1) == "PIP_CONFIG_FILE":
                out.append(_PIP_CONFIG_REF)
            else:
                add(next((g for g in m.groups()[1:] if g is not None), ""))
    doc = None
    if _wf_or_action_name(path):                       # always: a key written with a YAML escape never shows `PIP_` in the raw text
        try:
            doc = None if _yaml_guard(text, path) else yaml.load(text, Loader=yaml.BaseLoader)       # first: refuse aliases and anchors; a very deep document is not built (read flat by the file reader)
        except yaml.YAMLError:
            doc = None                                  # does not parse: refused with its own message by the file reader
    if isinstance(doc, (dict, list)):
        work = [doc]
        while work:                                     # an explicit work-list: any nesting depth
            node = work.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in _PIP_ENV_KEYS:
                        if isinstance(v, str):
                            add(v)
                        else:
                            out.append(_PIP_NONSCALAR_REF)      # a sequence or a mapping: which file it names cannot be told
                    elif k == "PIP_CONFIG_FILE":
                        out.append(_PIP_CONFIG_REF)
                    elif isinstance(k, str):
                        scan(k)
                    work.append(v)
            elif isinstance(node, list):
                work.extend(node)
            elif isinstance(node, str):
                scan(node)
    else:
        scan(text)
    seen, res = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            res.append(item)
    _ENV_MEMO[key] = tuple(res)
    return res


def _req_include_refs(text):
    """[(name, resolvable)] for the `-r FILE` / `-c FILE` / `--requirement=FILE` lines INSIDE a requirements file."""
    out = []
    for body in _req_lines(text):
        m = _REQ_INCLUDE.match(body)
        if m:
            f = m.group(1).strip("'\"")
            out.append((f, not any(c in f for c in "$`{") and "://" not in f))
    return out


def _norm_ref(ref):
    """(the referenced path normalised like posixpath.normpath, whether that was clean): no ./ and no doubled separators, an interior `..` collapses with the segment before it, a leading `..`
    that would leave the repository is dropped. Not clean: a `..` that escapes AFTER a real segment (`a/../../x`), where the text no longer says which file is meant."""
    out, clean, seen = [], True, False
    for part in ref.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if out:
                out.pop()
            elif seen:
                clean = False
            continue
        out.append(part)
        seen = True
    return "/".join(out), clean


class _PathIndex:
    """Tracked paths indexed by path (a set) and by last segment (a dict), and the basenames of the tracked symlinks: a candidate lookup is O(1), not a scan of every file."""
    def __init__(self, names, symlinks=()):
        self.names = set()
        self.by_base = {}
        self.link_bases = {x.rsplit("/", 1)[-1] for x in symlinks}
        for n in names:
            self.add(n)

    def add(self, n):
        if n not in self.names:
            self.names.add(n)
            self.by_base.setdefault(n.rsplit("/", 1)[-1], []).append(n)

    def __contains__(self, n):
        return n in self.names


def _ref_matches(ref, idx):
    """The files a pip FILE argument can name: EVERY tracked file with the same last segment (all are read), wherever it sits and however the directories in front are spelled (a symlinked
    directory or a `..` makes the text useless). Nothing for a URL, an absolute path or a variable."""
    n, _clean = _norm_ref(ref)
    if not n or "://" in ref or ref.startswith("/") or "$" in ref or "`" in ref:
        return []
    return sorted(idx.by_base.get(n.rsplit("/", 1)[-1], ()))


def _ref_is_bound(ref, cands, idx):
    """A reference is BOUND (nothing is unmeasured) only when exactly one file has that last segment, its path equals the normalised reference or ends with a separator and it, the
    normalisation was clean, and no tracked symlink has the name of a directory in front of the file. Anything else: all candidates are read and the reference is unmeasured too."""
    n, clean = _norm_ref(ref)
    if len(cands) != 1 or not clean:
        return False
    c = cands[0]
    if not (c == n or c.endswith("/" + n)):
        return False
    return not any(seg in idx.link_bases for seg in n.split("/")[:-1])


def _include_matches(ref, from_path, idx):
    """An include inside a requirements file: the file next to the including one when it exists (pip's own rule), otherwise the rule for every reference."""
    exact = posixpath.normpath(posixpath.join(posixpath.dirname(from_path), ref))
    if exact in idx and not exact.startswith("..") and not ref.startswith("/"):
        return [exact]
    return _ref_matches(ref, idx)


def tree_files(root, rev, soft=None):
    """{path: text} for every file the inventory reads, at a revision (rev None: the working tree): workflows, action files, EVERY tracked file that is a shell script (.sh/.bash/.ksh/.zsh/.bats
    or a shell shebang on its first line, whatever its name), the requirement/version/checksum files, every file a script or run step feeds to pip with -r or -c (whatever its name), and the
    harness manifest. A symlink is read as its link text in both modes. The first 4 KB of every blob is read however large it is: a shell script over 1 MB is refused ("too large", exit 2), a
    large file that is not a shell script is skipped. A tracked file that cannot be read is REFUSED ("cannot read", exit 2), never skipped. soft: a list that collects refusals as (path,
    reason) and goes on (a historical commit)."""
    def wanted(n):
        return (_wf_or_action_name(n) or n == "bin/install-scanner.sh" or n == MANIFEST or _is_script_name(n) or n.rsplit("/", 1)[-1] in VERSION_FILES
                or re.search(r"(?i)(^|/)[\w.-]*(sha256|checksums?|sha256sums?)[\w.-]*(\.txt|\.sha256|\.sum)?$", n) or _requirements_name(n) or n.rsplit("/", 1)[-1] in ("pip.conf", "pip.ini"))
    out = Files()

    def refuse(n, why):
        if soft is None:
            raise RuntimeError(why)
        soft.append((n, why))

    def add(n, raw, size, link=False, force=False):
        head = raw[:HEAD_BYTES].decode("utf-8", "replace")
        if not force and not wanted(n) and not _shell_shebang(head):
            return
        if size > MAX_FILE or len(raw) > MAX_FILE:
            refuse(n, f"{n} is too large to read safely")
            return
        text = raw.decode("utf-8", "replace")
        out[n] = text
        out.sha256[n] = hashlib.sha256(raw).hexdigest()
        if link:
            out.links[n] = text
    if rev is None:
        r = subprocess.run(["git", "-C", root, "-c", "core.quotePath=false", "ls-files", "-s", "-z"], capture_output=True)
        if r.returncode:
            raise RuntimeError("git ls-files: " + r.stderr.decode("utf-8", "replace").strip())
        names = {}
        for ent in r.stdout.split(b"\0"):
            meta, _, rn = ent.partition(b"\t")
            if rn and not meta.startswith(b"160000"):          # a gitlink (submodule) is a directory, not a file to read
                names[rn.decode("utf-8", "replace")] = rn
                if meta.startswith(b"120000"):
                    out.symlinks.add(rn.decode("utf-8", "replace"))
        rbase = os.fsencode(root)

        def read_wt(n, force=False):
            full = rbase + b"/" + names[n]
            try:
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    raw = os.readlink(full)
                    add(n, raw, len(raw), link=True, force=force)
                elif stat.S_ISREG(st.st_mode):
                    with open(full, "rb") as fh:
                        head = fh.read(HEAD_BYTES)
                        if not force and not wanted(n) and not _shell_shebang(head.decode("utf-8", "replace")):
                            return
                        raw = head + fh.read(MAX_FILE + 1 - len(head)) if st.st_size <= MAX_FILE else head
                    add(n, raw, st.st_size, force=force)
            except OSError as e:
                refuse(n, f"cannot read {n}: {e.strerror or e}")      # never skipped: a file the daily run cannot read is a file it cannot measure
        for n in names:
            read_wt(n)
        def peek_wt(n):
            try:
                with open(rbase + b"/" + names[n], "rb") as fh:
                    raw = fh.read(MAX_FILE + 1)
            except OSError:
                return "unreadable", ""
            return hashlib.sha256(raw).hexdigest(), raw.decode("utf-8", "replace")
        _read_refs(out, names, lambda n: read_wt(n, force=True), peek_wt)
        return out
    entries = {}
    for line in git(root, "ls-tree", "-r", "-l", "-z", rev).split("\0"):
        meta, _, n = line.partition("\t")
        if not n:
            continue
        parts = meta.split()
        if len(parts) < 4 or parts[1] != "blob":
            continue                              # a gitlink (submodule) has no blob to read
        entries[n] = (parts[0], parts[2], int(parts[3]) if parts[3].isdigit() else 0)
        if parts[0] == "120000":
            out.symlinks.add(n)

    def read_rev(n, force=False):
        mode, blob, size = entries[n]
        if size > MAX_FILE:
            pr = subprocess.Popen(["git", "-C", root, "cat-file", "blob", blob], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            head = pr.stdout.read(HEAD_BYTES)
            pr.kill()
            pr.wait()
            raw = head
        else:
            if blob not in _BLOBS:
                rr = subprocess.run(["git", "-C", root, "cat-file", "blob", blob], capture_output=True)
                if rr.returncode:
                    raise RuntimeError("git cat-file: " + rr.stderr.decode("utf-8", "replace").strip())
                _BLOBS[blob] = rr.stdout
            raw = _BLOBS[blob]
        add(n, raw, size, link=(mode == "120000"), force=force)
    _prefetch(root, [b for (_m, b, sz) in entries.values() if sz <= MAX_FILE])
    for n in entries:
        read_rev(n)
    def peek_rev(n):
        blob = entries[n][1]
        if blob not in _BLOBS:
            rr = subprocess.run(["git", "-C", root, "cat-file", "blob", blob], capture_output=True)
            _BLOBS[blob] = rr.stdout if rr.returncode == 0 else b""
        return hashlib.sha256(_BLOBS[blob]).hexdigest(), _BLOBS[blob].decode("utf-8", "replace")
    _read_refs(out, entries, lambda n: read_rev(n, force=True), peek_rev)
    return out


def _prefetch(root, blobs):
    """Every blob a tree needs that is not remembered yet, in ONE git process (a process per file costs most of a history scan)."""
    todo = sorted({b for b in blobs if b not in _BLOBS})
    if not todo:
        return
    r = subprocess.run(["git", "-C", root, "cat-file", "--batch"], input=("\n".join(todo) + "\n").encode(), capture_output=True)
    data, pos = r.stdout, 0
    for b in todo:
        nl = data.find(b"\n", pos)
        if r.returncode or nl < 0:
            return                                  # fall back to one process per blob
        head = data[pos:nl].split()
        if len(head) != 3 or head[1] != b"blob":
            return
        size = int(head[2])
        _BLOBS[b] = data[nl + 1:nl + 1 + size]
        pos = nl + 1 + size + 1


def _unread_tail(out, tracked, start, peek):
    """A digest over (path, exact-bytes hash) of every file the include chain reaches from `start` that is not read (no depth bound, cycles stop it): changing ANY of them moves the incomplete item."""
    seen, pairs, queue = {start}, [], [start]
    while queue:
        f = queue.pop()
        text = out.get(f) if f in out else (peek(f)[1] if peek else "")
        for ref, ok in _req_include_refs(text or ""):
            if not ok:
                continue
            for c in _include_matches(ref, f, tracked):
                if c in seen:
                    continue
                seen.add(c)
                dig, txt = (out.sha256.get(c, ""), out.get(c)) if c in out else (peek(c) if peek else ("", ""))
                pairs.append((c, dig))
                queue.append(c)
    return hashlib.sha256("\n".join("%s\0%s" % pr for pr in sorted(pairs)).encode("utf-8", "replace")).hexdigest()


def _read_refs(out, tracked, read, peek=None):
    """Second pass: every tracked file a script, workflow or action feeds to pip with -r or -c (or names in PIP_CONSTRAINT / PIP_REQUIREMENT, or gives pip-sync) is read too, whatever it is called, and
    so is every file those requirements files include, to a bounded depth. A reference is bound by PATH SUFFIX alone (see _ref_matches); every candidate is read."""
    todo, done = collections.deque(), set()
    tracked = _PathIndex(tracked, out.symlinks)        # indexed once: a reference is a lookup by last segment

    def take(c, d):
        if c not in out:
            read(c)
            if c in out:
                out.reqrefs.add(c)
        if c in out and c not in done:
            todo.append((c, d))
    for p, t in list(out.items()):
        if p in out.links:
            continue
        if p.rsplit("/", 1)[-1] in ("pip.conf", "pip.ini"):
            for it in _pip_conf_refs(t):
                if it.name == "pypi/(reqref)":
                    for c in _ref_matches(it.version, tracked):
                        take(c, 1)
            continue
        if not (_wf_or_action_name(p) or _is_script(p, t) or p == "bin/install-scanner.sh"):
            continue
        for ref, ok in _pip_file_refs(t, p):
            if ok:
                for c in _ref_matches(ref, tracked):
                    take(c, 1)
    todo.extend((p, 0) for p in sorted(out) if _requirements_name(p) and p not in out.links)
    while todo:
        f, d = todo.popleft()
        if f in done or f in out.links:
            continue
        done.add(f)
        for ref, ok in _req_include_refs(out[f]):
            if not ok:
                continue
            if d + 1 > MAX_INCLUDE_DEPTH:
                out.limit[f] = _unread_tail(out, tracked, f, peek)          # what the chain still holds is not read, but it is part of this file's identity
                continue
            for c in _include_matches(ref, f, tracked):
                take(c, d + 1)


def manifest_text(root, rev):
    """The harness manifest's text at a revision (rev None: the working tree), or None when there is none."""
    if rev is None:
        try:
            return open(f"{root}/{MANIFEST}").read()
        except OSError:
            return None
    r = subprocess.run(["git", "-C", root, "show", f"{rev}:{MANIFEST}"], capture_output=True, text=True, errors="replace")
    return r.stdout if r.returncode == 0 else None


def _pairs_no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key " + k)
        d[k] = v
    return d


def _read_manifest(text):
    """({path: sha256}, [problem text]): a malformed manifest exempts nothing; any INVALID entry for a path (a missing or empty reason, a bad digest, extra keys, a duplicate, a path outside
    the repository or not normalised) exempts nothing for that path, even beside a valid one."""
    if text is None:
        return {}, []
    try:
        d = json.loads(text, object_pairs_hook=_pairs_no_dups)
        entries = d["files"]
        assert isinstance(d, dict) and isinstance(entries, list)
    except (ValueError, KeyError, TypeError, AssertionError):
        return {}, ["the harness manifest %s is malformed: no file is exempt" % MANIFEST]
    count, bad, good, invalid = {}, [], {}, set()
    for e in entries:
        pth = e.get("path") if isinstance(e, dict) else None
        ok = (isinstance(e, dict) and set(e) == {"path", "sha256", "reason"} and all(isinstance(e.get(k), str) and e.get(k).strip() for k in ("path", "sha256", "reason"))
              and not re.search(r"[\x00-\x1f\x7f]", e["reason"]))        # a one-line reason: no newline or control character
        if not ok:
            bad.append("a harness manifest entry is malformed (exactly path, sha256 and a one-line reason): no exemption" + (" for " + pth[:80] if isinstance(pth, str) else ""))
            if isinstance(pth, str):
                invalid.add(pth)
                invalid.add(posixpath.normpath(pth))          # an alias of a listed path with any invalid entry invalidates the path
            continue
        if pth.startswith("/") or "\\" in pth or ".." in pth.split("/") or posixpath.normpath(pth) != pth or pth == MANIFEST:
            bad.append("the harness manifest lists %r, a path outside the repository or not normalised: no exemption" % pth[:80])
            invalid.add(pth)
            invalid.add(posixpath.normpath(pth))
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", e["sha256"]):
            bad.append("the harness manifest entry for %s has no valid sha256: no exemption" % pth)
            invalid.add(pth)
            invalid.add(posixpath.normpath(pth))
            continue
        count[pth] = count.get(pth, 0) + 1
        good[pth] = e["sha256"]
    for pth, n in count.items():
        if n > 1:
            invalid.add(pth)
            bad.append("the harness manifest lists %s %d times: no exemption" % (pth, n))
    for pth in invalid:
        good.pop(pth, None)
    return good, bad


def _problem(name, why, step):
    it = Item("tool", name, "${{unresolved}}")
    it.step = step
    it.file, it.line, it.why = MANIFEST, 1, why
    return it


def harness_exempt(files, manifest=_UNSET, mode="daily"):
    """(exempt paths, problem items). A listed script or requirements file whose exact bytes hash to the listed sha256 is exempt. mode 'daily' (the tree as it is) also reports a hash
    mismatch (naming both hashes) and a dangling entry; mode 'pr' (a pull request's head read with the BASE manifest) leaves a changed listed file in scope in full and reports
    neither (the pull request must update the manifest, which the base copy does not honour; the daily run after the merge verifies it); mode 'history' reports nothing."""
    text = files.get(MANIFEST) if manifest is _UNSET else manifest
    good, bad = _read_manifest(text)
    exempt, problems = set(), []
    if mode != "history":
        for why in bad:
            problems.append(_problem("(harness-manifest)", why, "why:" + hashlib.sha256(why.encode()).hexdigest()[:8]))
    sha = getattr(files, "sha256", {})
    for pth, want in sorted(good.items()):
        if pth not in files:
            if mode == "daily":
                problems.append(_problem("(harness-manifest)", "the harness manifest lists %s, which is not in the tree: a dangling entry exempts nothing" % pth, "dangling:" + pth))
            continue
        t = files[pth]
        if not (_is_script(pth, t) or _requirements_name(pth)):
            if mode == "daily":
                problems.append(_problem("(harness-manifest)", "the harness manifest lists %s, which is not a shell script or a requirements file: no exemption" % pth, "kind:" + pth))
            continue
        have = sha.get(pth) or hashlib.sha256(t.encode("utf-8")).hexdigest()
        if have == want:
            exempt.add(pth)
        elif mode == "daily":
            problems.append(_problem("(harness-hash)", "the harness file %s is listed in %s with sha256 %s but its bytes hash to %s: it is in scope in full" % (pth, MANIFEST, want, have), "path:" + pth))
    return exempt, problems


def _strip_tag(name):
    """name:tag -> name (a colon after the last slash is a tag, a colon before it is a registry port)."""
    head, _, tail = name.rpartition("/")
    return (head + "/" if head else "") + tail.split(":")[0]


def _image_item(ref, label=""):
    ref = ref.strip()
    m = DIGEST.search(ref)
    if m:
        return Item("image", _strip_tag(ref[:m.start()].rstrip("@")), m.group(0), label)
    return Item("image", ref, "", label)  # tag only: kept so the age check can fail it


MAX_LINE = 4000


def _cap(text):
    """A command line longer than MAX_LINE is REFUSED, never read as its prefix (a dependency appended after the limit would otherwise go unseen)."""
    for l in text.split("\n"):
        if len(l) > MAX_LINE:
            raise RuntimeError(f"a command line of {len(l)} characters is longer than the {MAX_LINE} this check reads: refusing to read it partially")
    return text


def _ctx_tag(node):
    node = {k: v for k, v in node.items() if k != "uses"} if isinstance(node, dict) else node    # the action's own pin is measured separately: bumping it must not re-key its placeholders
    return "step:" + hashlib.sha256((json.dumps(node, sort_keys=True, default=str) + "\0" + _ENV_CTX[0]).encode("utf-8", "replace")).hexdigest()[:10]


def _uses(u, node, out, labels):
    u = u.strip()
    if u.startswith("docker://"):
        out.append(_image_item(u[len("docker://"):]))
    elif u.startswith("./"):
        out.append(Item("action", "local:" + _hide(u), "(local)"))   # a local action outside the globs: its content is not read, so a new one cannot pass
    elif "${{" in u:
        out.append(Item("action", "(expression)", "${{expression}}"))        # an action ref given by an expression: never skipped (advisor 0245)
    elif u and "${{" not in u:
        ref_path, _, ref = u.partition("@")
        repo = "/".join(ref_path.split("/")[:2])
        labs = labels.get(f"{ref_path}@{ref}", [])
        it = Item("action", repo, ref, labs[0] if labs else "", "/".join(ref_path.split("/")[2:]))
        it.labels = {_hide(l) for l in labs}
        out.append(it)
        w = node.get("with")
        known = {i for i, _ in INSTALLER_INPUTS.get(repo.lower(), [])}
        if isinstance(w, dict) and repo.lower() != "actions/setup-go":     # the Go toolchain is a product dependency (rule 1, amendment 2)
            for key, val in w.items():
                if (key not in known and isinstance(val, str) and val.strip() and val.strip().lower() not in ("true", "false", "0", "1")
                        and not key.startswith(("fetch-", "persist-")) and re.search(r"(^|[-_])(versions?|tags?|releases?|tools|images?)(-file)?$", key)):
                    it = Item("tool", f"{repo}:{key}", "(input)")       # an installer-shaped input nobody classified: a placeholder, so a new or changed one is refused
                    it.step = _ctx_tag(node)                           # identified by the whole step (its value included) and the env/matrix it reads
                    it.expr = "${{" in val and bool(re.search(r"(^|[-_])(versions?|releases?)(-file)?$", key))     # only a version position (not `tags: ...${{ github.sha }}`)
                    out.append(it)
        for inp, tool in INSTALLER_INPUTS.get(repo.lower(), []):
            if tool is not None and not (isinstance(w, dict) and isinstance(w.get(inp), str) and w[inp].strip()):
                it = Item("tool", tool, "(default)")       # no version given: the action installs whatever its default is, so removing the input must not remove the obligation
                it.step = "default:" + inp + ":" + hashlib.sha256(json.dumps({k: v for k, v in node.items() if k not in ("with", "uses")}, sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()[:8]
                out.append(it)
            if isinstance(w, dict) and isinstance(w.get(inp), str) and w[inp].strip():
                val = w[inp].strip()
                it = _image_item(val) if tool is None else Item("tool", tool, val)
                if _NONPIN.search(it.version or ""):
                    it.step = _ctx_tag(node)       # an expression (a matrix value, an env var): identified by the step AND the env/matrix it reads
                out.append(it)


_PIP_VALUE_OPTS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target",
                   "--prefix", "--root", "--cache-dir", "--python", "--platform", "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary", "--progress-bar",
                   "--proxy", "--retries", "--timeout", "--trusted-host", "--src", "--upgrade-strategy", "--report", "--log", "--exists-action", "--cert", "--client-cert", "--root-user-action",
                   "--config-settings", "-C", "--use-feature", "--global-option", "--install-option", "--build-option", "--use-deprecated", "--keyring-provider", "--lang", "--constraint-file"}
# docker run/pull/create options that take a value (the next word is not the image); options not listed here and not in _DOCKER_BOOL_OPTS withhold the --pull=never exemption
_DOCKER_VALUE_OPTS = {
    "--add-host", "--annotation", "--blkio-weight", "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--config", "--context",
    "--cpu-period", "--cpu-quota", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device", "--dns", "--dns-option",
    "--dns-search", "--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval",
    "--health-retries", "--health-start-period", "--health-timeout", "--host", "--hostname", "--init-path", "--ip", "--ip6", "--ipc", "--isolation",
    "--label", "--label-file", "--link", "--log-driver", "--log-level", "--log-opt", "--mac-address", "--memory", "--memory-reservation",
    "--memory-swap", "--mount", "--name", "--net", "--network", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform",
    "--publish", "--pull", "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--sysctl", "--tlscacert",
    "--tlscert", "--tlskey", "--tmpfs", "--ulimit", "--user", "--userns", "--uts", "--volume", "--volumes-from", "--workdir", "-H", "-c", "-e", "-h",
    "-l", "-m", "-p", "-u", "-v", "-w"}


def _docker_tails(run):
    return _tails(run, lambda t: t in ("docker", "podman", "nerdctl", "buildah"), {"run", "pull", "create"}, _DOCKER_VALUE_OPTS, keep_sub=True)


_DOCKER_BOOL_OPTS = {"--rm", "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--init", "--privileged", "--read-only", "--no-healthcheck",
                     "--sig-proxy", "--oom-kill-disable", "-P", "--publish-all", "--help", "--quiet", "-q", "--disable-content-trust",
                     "--platform-none"}


def _docker_operand(cmd_args):
    """(the image of a docker run/pull/create, the effective --pull policy): the image is the first argument that is not an option or an option's
    value (quotes read as a shell would); the policy is the LAST --pull among the options before it (pflag keeps the final value), read by the SAME
    walk so the two can never disagree about which words are options, values or the operand (Codex #187 rounds 2-3). The `never` policy only
    counts when EVERY option before the operand has a known arity (a value option, a boolean, a short cluster of booleans, or --name=value of a
    known option): a guessed arity (a number after an unknown option is taken as its value) once let `--rm 123 --pull=never localhost/x` read the
    container's own arguments as a policy (round 4), so an unknown option withholds the exemption."""
    try:
        toks = shlex.split(cmd_args)
    except ValueError:
        toks = cmd_args.split()
    i, pull, guessed = 0, None, False
    while i < len(toks):
        t = toks[i]
        if t.startswith("--pull="):
            pull = t.split("=", 1)[1]; i += 1; continue
        if t == "--pull" and i + 1 < len(toks):
            pull = toks[i + 1]; i += 2; continue
        if t.startswith("-"):
            known_value = t in _DOCKER_VALUE_OPTS and "=" not in t
            known = known_value or t in _DOCKER_BOOL_OPTS or (t.startswith("--") and t.split("=", 1)[0] in _DOCKER_VALUE_OPTS and "=" in t) \
                or re.fullmatch(r"-[dit]+", t) is not None
            guess = not known and i + 1 < len(toks) and re.fullmatch(r"[\d.]+[kmgb]?", toks[i + 1]) is not None and "=" not in t and t.startswith("--")
            guessed = guessed or not known
            i += 2 if (known_value or guess) else 1
            continue
        if "$" in t:
            return ["(variable)"], (None if guessed else pull)                # the image is a shell variable: a placeholder item that cannot be proven, so a new one is refused
        return ([t] if re.fullmatch(r"[\w.\-/:]+(@sha256:[0-9a-f]{64})?", t) else []), (None if guessed else pull)
    return [], (None if guessed else pull)


_ENV_CTX = [""]
_JOB_SUMS = [[]]


_NONPIN = re.compile(r"^$|^\(|\$\{|^latest$|^(main|master|nightly|stable)$|[*<>=~!]")


MAX_ITEMS_PER_STEP = 500
MAX_ITEMS_PER_FILE = 5000
MAX_LINES_PER_FILE = 20000


def _expr_bodies(text):
    """The bodies of the ${{ ... }} expressions in a text, in linear time (find, no backtracking): an opener with no closer after it ends the search, since none after it can close either."""
    out, pos = [], 0
    while True:
        i = text.find("${{", pos)
        if i < 0:
            return out
        j = text.find("}}", i + 3)
        if j < 0:
            return out
        out.append(text[i + 3:j])
        pos = j + 2


def _bodies(out, text, labels, depth=0):
    """An expression's body is text like any other: a literal install-looking string inside `${{ 'pip install a==1' }}` is an item (a command built from non-literals stays an expression, fail
    closed). Nested bodies are read from an explicit work-list, so any depth is read in full; the only bound is the shared budget of characters, and hitting it sets _LEX_LIMIT (reported, never silent)."""
    work, spent = [text if isinstance(text, str) else ""], 0
    while work:
        t = work.pop()
        for body in _expr_bodies(t):
            body = body.strip()
            if not body:
                continue
            spent += len(body)
            if spent > _LEX_BUDGET:
                _LEX_LIMIT[0] = True
                return
            _step({"run": body, "_nobodies": 1}, out, labels)
            if "${{" in body:
                work.append(body)


def _step(node, out, labels):
    n0 = len(out)
    _step_items(node, out, labels)
    if isinstance(node.get("run"), str) and "${{" in node["run"] and node.get("_nobodies") is None:
        _bodies(out, node["run"], labels)
    if len(out) - n0 > MAX_ITEMS_PER_STEP:
        raise RuntimeError(f"a single step or script line yields more than {MAX_ITEMS_PER_STEP} items: refusing to read it (a hostile line could exhaust the readers)")
    run = node.get("run")
    if isinstance(run, str):
        ctx = " ".join(run.split()) + "\0" + json.dumps(node.get("env"), sort_keys=True, default=str) + "\0" + _ENV_CTX[0]
        tag = "step:" + hashlib.sha256(ctx.encode("utf-8", "replace")).hexdigest()[:10]
        for it in out[n0:]:
            if _NONPIN.search(it.version or "") and not it.step:
                it.step = tag     # a placeholder (variable, @latest, @main, unpinned) is identified by the step it sits in, so a NEW or EDITED one is a new key and is refused


_SOURCE_ASSIGN = re.compile(r"^[ \t]*(?:export\s+|readonly\s+|local\s+)?((?:url|URL)|[A-Z][A-Z0-9_]*_(?:BASE_URL|BASE|URL))=(.*)$")


def _step_items(node, out, labels):
    """A step (or a job-level reusable-workflow call): `uses` and `run` mean something only here; the same word in `env:` or `with:` is data."""
    if isinstance(node.get("uses"), str):
        _uses(node["uses"], node, out, labels)
    run = node.get("run")
    if isinstance(run, str):
        run = _cap(_hide(re.sub(r"\\\r?\n", "", run)))  # a backslash continuation is one command; an expression becomes a placeholder before any pattern can cut it
        for m in list(_GO_INSTALL.finditer(run)) + list(_GO_RUN_GET.finditer(run)):
            for t in _GO_TARGET.finditer(m.group(1)):
                out.append(Item("gotool", t.group(1), t.group(2).rstrip(")") if "(" not in t.group(2) else t.group(2)))
            for tok in m.group(1).split():
                tok = tok.strip("'\"")
                if not tok.startswith("-") and "@" not in tok and re.fullmatch(r"[\w.\-]+\.[\w.\-]+/[\w.\-/]+", tok):
                    out.append(Item("gotool", tok, "(unversioned)"))     # go install with no @version: a placeholder, refused when added
                elif not tok.startswith("-") and "$" in tok:
                    out.append(Item("gotool", "(variable)", "(unversioned)"))   # go install "$TOOL": the target is a variable, so it cannot be proven
        for m in _GH_LATEST.finditer(run):  # "latest" is not a pin: an item that cannot be proven, so adding one fails closed
            out.append(Item("tool", m.group(1), "latest"))
        for sub, tail in _docker_tails(run):
            images, pull = _docker_operand(tail)
            local_only = sub in ("run", "create") and pull == "never"
            for img in images:
                it = _image_item(img)
                if local_only and it.name.startswith("localhost/"):
                    continue      # run/create with --pull=never can only use an image already in the daemon: built or loaded by this job, never downloaded, no age to prove (advisor 0203); a pull, a container:/services: image, uses: docker:// and localhost:PORT/ stay items
                out.append(it)
        for ln in run.split("\n"):    # where a script downloads FROM: an assignment of a URL/BASE variable is a source line identified by its own text
            m = _SOURCE_ASSIGN.match(ln)
            if m:
                out.append(Item("tool", "source:" + m.group(1).lower() + "=" + hashlib.sha256(" ".join(ln.split()).encode("utf-8", "replace")).hexdigest()[:12], "(source)"))
        for m in _GH_DOWNLOAD.finditer(run):  # curl/wget of a release asset: the tool is its repo at that version; the EXACT tag is kept as its label
            sums = sorted(set(re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", run)) | set(_JOB_SUMS[0]))   # checksums, not image digests
            out.append(Item("tool", m.group(1), m.group(2) + m.group(3), m.group(2) + m.group(3), m.group(4) + ("#" + hashlib.sha256(" ".join(sums).encode()).hexdigest()[:8] if sums else "")))   # the asset's name is part of the identity: a different file under the same tag is a moved item
        for tail in _pip_tails(run):
            _pip_items(tail, out)
        heredocs = None          # found only when a pip command reads a requirements list from stdin
        used = set()
        for tail in _pip_tails(run):
            if _STDIN_REQ.search(tail):          # a requirements list on stdin: read ITS heredoc (the one opened on its own line), or refuse what cannot be read
                if heredocs is None:
                    heredocs = _heredocs(run)
                body = None
                for n, h in enumerate(heredocs):
                    hdr = run[run.rfind("\n", 0, h.start) + 1:h.start]
                    if n not in used and tail.split("<<")[0].strip() and tail.split("<<")[0].strip() in hdr:
                        used.add(n)
                        body = h.body
                        break
                if body is None:
                    out.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(tail.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)"))
                for ln in (body or "").split("\n"):
                    s_ln = ln.strip()
                    if not s_ln or s_ln.startswith("#") or s_ln.startswith("--hash"):
                        continue
                    m = _REQ_LINE.match(s_ln)
                    if m:
                        out.append(Item("package", f"pypi/{m.group(1).lower().replace('_', '-')}", m.group(2)))
                    else:
                        out.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(s_ln.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)"))
        if re.search(r"\bpip[0-9.]*\b", run) and "--require-hashes" in run:  # a requirements list fed on stdin (a heredoc): its `name==version \\` lines
            for p in _REQ_PIN.finditer(run):
                out.append(Item("package", f"pypi/{p.group(1).lower().replace('_', '-')}", p.group(2)))


def _walk(node, out, labels, path="", in_step=False):
    if isinstance(node, str):
        for m in _RUN_IMAGE.finditer(node):  # a digest-pinned image in ANY value: run text, env, driver-opts, an action input
            out.append(_image_item(m.group(1)))
    elif isinstance(node, dict):
        if in_step or path.startswith("job:"):
            _step(node, out, labels)
        for k, v in node.items():
            if k == "env" and isinstance(v, dict):
                for ek, ev in v.items():
                    if re.fullmatch(r"[A-Z][A-Z0-9_]*_(?:BASE_URL|BASE|URL)", str(ek)):
                        out.append(Item("tool", "source:env:" + ("(expression)" if "${{" in str(ev) else str(ek).lower()) + "=" + hashlib.sha256(str(ev).encode("utf-8", "replace")).hexdigest()[:12], "(source)"))   # an env var that retargets a download
            if k in ("container", "image") and isinstance(v, (str, dict)):
                img = v if isinstance(v, str) else v.get("image")
                # an `image:` input of an action counts only when it names a digest (other inputs called image are not pins)
                if isinstance(img, str) and "${{" in img and k == "container":
                    it = Item("image", "(expression)", ""); it.expr = True; it.step = _ctx_tag(v); out.append(it)    # a container image given by an expression: a placeholder
                elif isinstance(img, str) and "${{" not in img and (path != "with" or k == "container" or DIGEST.search(img)):
                    out.append(_image_item(img))
            if k == "services" and isinstance(v, dict):
                for svc in v.values():
                    if isinstance(svc, dict) and isinstance(svc.get("image"), str):
                        if "${{" in svc["image"]:
                            it = Item("image", "(expression)", ""); it.expr = True; it.step = _ctx_tag(svc); out.append(it)
                        else:
                            out.append(_image_item(svc["image"]))
            if k == "jobs" and isinstance(v, dict):
                top_env = json.dumps(node.get("env"), sort_keys=True, default=str) + json.dumps(node.get("on"), sort_keys=True, default=str)   # a called workflow's input defaults count
                for job in v.values():
                    _ENV_CTX[0] = top_env + json.dumps(job.get("env") if isinstance(job, dict) else None, sort_keys=True, default=str) + json.dumps(job.get("strategy") if isinstance(job, dict) else None, sort_keys=True, default=str)
                    _JOB_SUMS[0] = re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", json.dumps(job, default=str)) if isinstance(job, dict) else []   # a checksum in ANY step of the job (a separate verify step) belongs to the job's downloads
                    _walk(job, out, labels, "job:" + k)
                    if isinstance(job, dict) and isinstance(job.get("uses"), str) and job["uses"].startswith("./") and job.get("with"):
                        for it in out:                       # a local reusable-workflow call: what it passes in is part of that call's identity
                            if it.version == "(local)" and it.name == "local:" + _hide(job["uses"]) and not it.step:
                                it.step = "with:" + hashlib.sha256(json.dumps(job.get("with"), sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()[:10]
                _ENV_CTX[0] = ""
                _JOB_SUMS[0] = []
                continue
            _walk(v, out, labels, k, in_step=(k == "steps"))
    elif isinstance(node, list):
        for v in node:
            _walk(v, out, labels, path, in_step=in_step)


def _decoded_scalars(text):
    """The DECODED value of every YAML scalar (single-line or not; plain, quoted with escapes such as \\x20, folded, literal; mapping values, list items, keys), whitespace-flattened. An
    install can sit in any of them, and a run step can consume it; the decoded value is read in addition to the raw lines (AC11)."""
    out = []
    try:
        for ev in yaml.parse(text, Loader=yaml.BaseLoader):
            if isinstance(ev, yaml.ScalarEvent) and ev.value and ev.style != "|":      # a literal block is its own raw lines
                out.append(" ".join(ev.value.split()))
    except yaml.YAMLError:
        return []
    return out


def _raw_views(text):
    """The flattened raw lines, and each line with its `key:` prefix and quotes removed: what the line-by-line read has already seen."""
    seen = set()
    for ln in re.sub(r"\\\r?\n", "", text).split("\n"):
        seen.add(" ".join(ln.split()))
        seen.add(re.sub(r"^\s*(?:-\s*)?[\w.-]+:\s*", "", ln).strip().strip("'\""))
        seen.add(re.sub(r"^\s*-\s*", "", ln).strip().strip("'\""))
    return seen


def _extra_scalars(text, skip=()):
    seen = _raw_views(text) | set(skip)
    out, done = [], set()
    for v in _decoded_scalars(text):
        if v not in seen and v not in done:
            done.add(v)
            out.append(v)
    return out


def _locate(text, it, used):
    """The 1-based line of the expression an item came from (the first not already given to another item)."""
    lines = [(n, l) for n, l in enumerate(text.split("\n"), 1) if "${{" in l]
    nm = it.name.split("/", 1)[1] if it.kind == "package" and "/" in it.name else it.name
    flex = re.sub(r"\\[-_.]|[-_.]", "[-_.]", re.escape(nm))
    pats = []
    if it.kind == "gotool":
        pats.append(re.escape(it.name) + r"@\S*\$\{\{")
    elif it.kind == "package":
        pats.append("(?i)" + flex + r"(\[[^\]]*\])?\s*==\s*\S*\$\{\{")
    elif it.kind == "action":
        pats.append(r"uses:\s*\S*@\S*\$\{\{")
    elif it.kind == "image":
        pats.append(r"(image|container)['\"]?\s*:.*\$\{\{|docker://\S*\$\{\{")
    elif it.kind == "tool":
        keys = [inp for act, ins in INSTALLER_INPUTS.items() for inp, tool in ins if tool == it.name]
        if ":" in it.name:
            keys.append(it.name.split(":", 1)[1])
        for k in keys:
            pats.append(r"\b" + re.escape(k) + r"['\"]?\s*:.*\$\{\{")
        pats.append(re.escape(it.name) + r"/releases/\S*\$\{\{")
    for pat in pats:
        for n, l in lines:
            if n not in used and re.search(pat, l):
                used.add(n)
                return n
    for n, l in lines:
        if n not in used:
            used.add(n)
            return n
    return lines[0][0] if lines else 0


_STDIN_HEADER = re.compile(r"^[^\n]*(?:-r|--requirement)[ =]*(?:/dev/stdin|-)[^\n]*<<-?[ \t]*['\"]?(\w+)['\"]?[^\n]*$")


def _stdin_heredoc_blocks(lines):
    """[(header line, header..terminator text)] for every `pip ... -r /dev/stdin <<WORD` line of a script and the heredoc that follows it, in linear time (terminators are indexed by word)."""
    where = {}
    for i, ln in enumerate(lines):
        w = ln.strip(" \t")
        if re.fullmatch(r"\w+", w):
            where.setdefault(w, []).append(i)
    out, skip = [], -1
    for i, ln in enumerate(lines):
        if i <= skip or "<<" not in ln:
            continue
        m = _STDIN_HEADER.match(ln)
        if not m:
            continue
        offs = where.get(m.group(1), ())
        k = bisect.bisect_left(offs, i + 2)
        if k >= len(offs):
            continue
        j = offs[k]
        out.append((ln, "\n".join(lines[i:j + 1])))
        skip = j
    return out


def _scan_script(path, text, found):
    joined = re.sub(r"\\\r?\n", "", text).split("\n")
    if len(joined) > MAX_LINES_PER_FILE:
        raise RuntimeError(f"{path} has {len(joined)} lines: more than the {MAX_LINES_PER_FILE} this check reads")
    assigns = {}
    for ln in joined:
        am = re.match(r"^[ \t]*(?:export\s+|readonly\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", ln)
        if am:
            assigns[am.group(1)] = am.group(2)
    hd_lines = set()
    for first, block in _stdin_heredoc_blocks(joined):
        _step({"run": block}, found, {})            # a pip requirements HEREDOC is read as one command text (its body is the requirement list)
        hd_lines.add(first)
    for ln in joined:   # a script is read LINE by line (continuations joined): a placeholder's identity is its own line PLUS the assignments of the variables that line references
        if ln in hd_lines:
            continue
        refs = {v: assigns[v] for v in set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", ln)) if v in assigns}
        _step({"run": ln, "env": refs} if refs else {"run": ln}, found, {})
        if len(found) > MAX_ITEMS_PER_FILE:
            raise RuntimeError(f"{path} yields more than {MAX_ITEMS_PER_FILE} items: refusing to read it")   # a script's go install / pip install / docker run / release download are measured like a run step's


_SCAN_MEMO = {}


def _scan_file_cached(path, text, reqrefs):
    """_scan_file, remembered per (path, content, budget): a history scan reads the same file version in many commits, and a version is scanned once (the items are copied out, never shared)."""
    key = (path, hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(), path in reqrefs, _LEX_BUDGET)
    hit = _SCAN_MEMO.get(key)
    if hit is None:
        found = _scan_file(path, text, reqrefs)
        _SCAN_MEMO[key] = (copy.deepcopy(found), _LEX_LIMIT[0], _SCAN_DEEP[0])
        return found
    _LEX_LIMIT[0], _SCAN_DEEP[0] = hit[1], hit[2]
    return copy.deepcopy(hit[0])


def _scan_file(path, text, reqrefs):
    """The raw items of one in-scope file (by its KIND: install-scanner.sh, a version or checksum file, a shell script, a requirements file, a workflow or action file)."""
    found = []
    if path == "bin/install-scanner.sh":
        found = [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in _VER_PIN.finditer(text) if m.group(1) != "PATH"]
        found += [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Z][A-Z0-9]*)_VERSION=['\"]?([^\s'\"#]+)", text, re.M)]
        found += [Item("tool", "source:" + m.group(1).lower() + "=" + _hide(m.group(2)), "(source)") for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Z][A-Z0-9_]*_BASE(?:_URL)?)=['\"]?(?:\$\{[A-Z0-9_]+:?-)?(https?://[^\s'\"}]+)", text, re.M)]  # where it downloads from: changing it is refused (not a pin)
        found += [Item("tool", "scout", m.group(1)) for m in re.finditer(r"\bdocker-scout-(\d+(?:\.\d+)+)\b", text)]  # older versions the script can still install
        for ln in re.sub(r"\\\r?\n", "", text).split("\n"):   # and the rest of the script like any other: an appended download is seen
            _step({"run": ln}, found, {})
    elif not _is_script(path, text) and not _requirements_name(path) and path not in reqrefs and not _wf_or_action_name(path) and (path.rsplit("/", 1)[-1] in VERSION_FILES or re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1])):
        found = [Item("tool", "file:" + path, "(file)")]   # a version file or a checksum file: its content is the identity (a replaced asset behind the same URL moves the item)
        found[0].step = "content:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]      # what an installer's *-version-file selects: a changed content is a changed key
    elif _is_script(path, text):
        found = []
        _scan_script(path, text, found)
        if path.rsplit("/", 1)[-1] in VERSION_FILES or re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1]):
            fi = Item("tool", "file:" + path, "(file)")
            fi.step = "content:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]
            found.append(fi)           # a script that is also named like a version or checksum file: the content item AND the script's items
    elif path.rsplit("/", 1)[-1] in ("pip.conf", "pip.ini") and not _requirements_name(path):
        found = _pip_conf_refs(text)
    elif _requirements_name(path) or path in reqrefs:
        found = []
        for body in _req_lines(text):
            if body.startswith("--hash="):
                continue
            m = _REQ_ONE.match(body)
            if m and m.group(2) == "==":
                found.append(Item("package", f"pypi/{m.group(1).lower().replace('_', '-')}", m.group(3)))      # name==version (with its --hash options)
            elif m and m.group(2) == "===":
                it3 = Item("package", f"pypi/{m.group(1).lower().replace('_', '-')}", "===" + m.group(3))   # its own operator: an item that cannot be proven
                it3.step = "line:" + hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:10]
                found.append(it3)
            elif _REQ_INCLUDE.match(body):
                for ref, ok in _req_include_refs(body):          # an include of another requirements file: followed (the second pass), or unmeasured when it cannot be named
                    if ok:
                        mk = Item("package", "pypi/(reqref)", ref)
                        mk.why = "nested"
                        found.append(mk)
                    else:
                        found.append(_unmeasured_item(ref))
            else:
                found.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)"))   # a URL requirement, a range, an index option, a bare name
        if re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1]):
            fi = Item("tool", "file:" + path, "(file)")
            fi.step = "content:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]
            found.append(fi)           # requirements kind beats the name rule; the checksum-named file's content item stays beside its packages
    elif _wf_or_action_name(path):
        labels = {}
        for m in re.finditer(r"uses:\s*['\"]?([^\s#'\"]+)['\"]?\s*#\s*(?:tag:\s*)?(\S+)", text):
            labels.setdefault(m.group(1), []).append(m.group(2))
        try:
            deep = _yaml_guard(text, path)               # events first: an alias bomb is refused before anything is built or walked; nesting never refuses
            doc = None if deep else yaml.load(text, Loader=yaml.BaseLoader)
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)  # the line number only: the message would quote source text (names that must stay private)
            raise RuntimeError(f"{path} does not parse (line {mark.line + 1 if mark else '?'})")
        if deep:
            for fv in _all_scalars(text):            # a document nested beyond the safe depth: every decoded scalar is an install-looking candidate, no structure is built
                _step({"run": fv}, found, {})
                _bodies(found, fv, {})
        else:
            _walk(doc, found, labels, "")
        runs = []

        def _collect(n):
            if isinstance(n, dict):
                for k, v in n.items():
                    if k == "run" and isinstance(v, str):
                        runs.append(v)
                    _collect(v)
            elif isinstance(n, list):
                for v in n:
                    _collect(v)
        if not deep:
            _collect(doc)
        for fv in ([] if deep else _extra_scalars(text, [" ".join(r.split()) for r in runs])):      # a run scalar is read whole by the walk already
            _step({"run": fv}, found, {})
            _bodies(found, fv, {})
        for ln in re.sub(r"\\\r?\n", "", text).split("\n"):        # every install-looking string counts, wherever it sits: a comment, an env value, an input default, a name (AC11)
            rest = re.sub(r"^\s*(?:-\s*)?[\w.-]+:\s*", "", ln).strip().strip("'\"")
            if rest and any(rest in r for r in runs):
                continue                    # a line of a run block: already read as one command text
            _step({"run": ln}, found, {})
            _bodies(found, ln, {})
        if deep:
            _LEX_LIMIT[0] = True
            _SCAN_DEEP[0] = True                     # the structure-dependent readings (the walk, the environment mapping) were not done: reported as `scan limit reached`
    if _wf_or_action_name(path) or _is_script(path, text) or path == "bin/install-scanner.sh":
        for ref, ok in _env_file_refs(text, path):          # PIP_CONSTRAINT / PIP_REQUIREMENT: files pip reads without a command-line flag; PIP_CONFIG_FILE: a configuration file that is not followed
            found.append(Item("package", "pypi/(reqref)", ref) if ok else _unmeasured_item(ref))
    return found


def _resolve_reqrefs(found, path, files, idx):
    """The pip FILE arguments a file named (markers left by the readers): bound by path suffix. EXACTLY ONE candidate was read (it is in scope as a requirements file): nothing more. None, or
    more than one (all of them were read): the reference is also an unmeasured item."""
    for it in [i for i in found if i.name == "pypi/(reqref)"]:
        found.remove(it)
        ref = it.version
        if it.why == "nested":
            cands = _include_matches(ref, path, idx)
            bound = len(cands) == 1 and (posixpath.normpath(posixpath.join(posixpath.dirname(path), ref)) == cands[0] or _ref_is_bound(ref, cands, idx))
        else:
            cands = _ref_matches(ref, idx)
            bound = _ref_is_bound(ref, cands, idx)
        if not bound:
            found.append(_unmeasured_item(ref))


class Items(dict):
    """{key: Item} with .refused = [(path, reason)] for the files a historical commit could not be read in (mode 'history' only; any other mode raises)."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.refused = []


def inventory(files, manifest=_UNSET, mode="daily", exempt_on=True, exempt_set=None):
    """The items of one tree's files ({path: text}). Raises on a file that cannot be read safely (a workflow that does not parse, a line over the limit): a pin we cannot read is never
    skipped. In mode 'history' such a file is collected in .refused and the rest is read."""
    items = Items()
    exempt, problems = harness_exempt(files, manifest, mode) if (exempt_on or exempt_set is not None) else (set(), [])
    if exempt_set is not None:
        exempt = set(exempt_set)
    reqrefs = getattr(files, "reqrefs", set())
    path_index = _PathIndex((c for c in files if c not in getattr(files, "links", {})), getattr(files, "symlinks", ()))
    for pi in problems:
        items.setdefault(pi.key, pi)
    for lp, target in sorted(getattr(files, "links", {}).items()):          # a symlink with an in-scope name (script, workflow, action, requirements, version, checksum) whose target is not itself in scope cannot be measured: fail closed
        tgt = posixpath.normpath(posixpath.join(posixpath.dirname(lp), target))
        if tgt not in files or tgt in getattr(files, "links", {}):
            pi = _problem("(symlink)", "the symlink %s points to %s, which is not a file in scope: it cannot be measured" % (lp, target[:80]), "link:" + lp)
            pi.file = lp
            items.setdefault(pi.key, pi)
    for path, text in sorted(files.items()):
        _LEX_LIMIT[0] = False
        _SCAN_DEEP[0] = False
        if path in exempt or path == MANIFEST:
            continue                          # listed in the reviewed manifest, bytes unchanged: fixture data (AC11); the manifest itself is not a source of items
        try:
            found = _scan_file_cached(path, text, reqrefs)
            _resolve_reqrefs(found, path, files, path_index)
        except RuntimeError as e:
            if mode != "history":
                raise
            items.refused.append((path, str(e)))          # a historical commit holds a file this check refuses: reported as information, the rest is read
            continue
        if _LEX_LIMIT[0] or path in getattr(files, "limit", ()):
            lim = Item("package", "pypi/(unmeasured:scan limit reached)", "(unpinned)")
            raw = lambda p: getattr(files, "sha256", {}).get(p) or hashlib.sha256(files[p].encode("utf-8", "replace")).hexdigest()          # the hash of the exact BYTES the reader kept
            if _SCAN_DEEP[0]:
                basis = path + "\0" + raw(path)                                    # a deep document: the file's own exact bytes are everything that was not read
            else:
                basis = path + "\0" + hashlib.sha256(("\n".join("%s\0%s" % (q, raw(q)) for q in sorted(files)) + "\0" + getattr(files, "limit", {}).get(path, "")).encode("utf-8", "replace")).hexdigest()
                # an include chain or a character budget: the scope digest of EVERY in-scope file plus the unread tail, so a change anywhere moves the item
            lim.step = "file:" + hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:10]
            lim.incomplete, lim.why, lim.file, lim.line = True, "incompletely scanned: action references and installer inputs not read", path, 1       # its own class: judged as an unparseable finding naming the file, never an expression
            found.append(lim)           # a bound was hit: the file was not read in full, which is reported, never silent
        used = set()
        for it in found:
            if not it.file:
                it.file = path
            if it.expr and not it.line:
                it.line = _locate(text, it, used)
        for it in found:
            if it.key in items and (it.version.startswith("(") or "${{" in it.version or it.version in ("latest", "(unversioned)")):     # two identical unresolved occurrences are two items: removing a version from the second must not hide behind the first
                n = 2
                while True:
                    it.step = re.sub(r"~\d+$", "", it.step or "") + f"~{n}"
                    if it.key not in items:
                        break
                    n += 1
            if it.key in items and items[it.key] is not it:
                items[it.key].labels |= it.labels      # the same pin written twice with different comments: every comment is kept and judged
            items.setdefault(it.key, it)
    return items


def _pr_exempt(base_files, head_files, base_manifest):
    """(exempt on the base side, exempt on the head side) for a pull request, ONE rule: the BASE manifest's exemptions are applied to each side's own files (a listed path whose bytes
    still match the listed hash). A listed harness the PR edits or deletes is therefore exempt at the base and measured in full at the head (its fixture strings are then moved, and the
    owner reviews them); an unchanged one is exempt on both sides. A fixture can never stand in as 'already present' for the same pin introduced elsewhere."""
    return harness_exempt(base_files, base_manifest, "pr")[0], harness_exempt(head_files, base_manifest, "pr")[0]


def pr_inventories(root, base, head):
    """(base items, head items) of a pull request, measured like with like. A manifest entry the PR itself adds that points at no file (or is invalid) is a finding in the head."""
    bf, hf = tree_files(root, base), tree_files(root, head)
    bm = manifest_text(root, base)
    eb, eh = _pr_exempt(bf, hf, bm)
    base_items = inventory(bf, bm, mode="pr", exempt_set=eb)
    head_items = inventory(hf, bm, mode="pr", exempt_set=eh)
    hm = manifest_text(root, head)
    if hm is not None and hm != bm:
        _, own = harness_exempt(hf, hm, "daily")
        _, theirs = harness_exempt(hf, bm, "daily")
        known = {p.key for p in theirs}
        for p in own:
            if p.name == "(harness-manifest)" and p.key not in known:
                head_items.setdefault(p.key, p)
    return base_items, head_items


def pr_unmeasured(root, base, head):
    bf, hf = tree_files(root, base), tree_files(root, head)
    bm = manifest_text(root, base)
    eb, eh = _pr_exempt(bf, hf, bm)
    return unmeasured(bf, bm, mode="pr", exempt_set=eb), unmeasured(hf, bm, mode="pr", exempt_set=eh)


def moved(base_items, head_items):
    """Items in the head that the base did not have: a new pin, or a changed version, counts as moved."""
    return [head_items[k] for k in sorted(head_items) if k not in base_items or (head_items[k].kind == "action" and head_items[k].labels - base_items[k].labels)]   # a comment added to a pin already there is moved too


def load_at(root, rev, manifest_rev=None, exempt=True, mode=None):
    """Items at a revision. The harness manifest is read from manifest_rev when given (a pull request's own exemptions never count: its BASE decides); exempt=False measures every
    in-scope file in full (the BASE side of a pull request); mode: 'daily' (default), 'pr' or 'history'."""
    mode = mode or ("pr" if manifest_rev is not None else "daily")
    soft = [] if mode == "history" else None          # a historical commit's refusals are collected, not raised
    files = tree_files(root, rev, soft)
    if manifest_rev is None:
        items = inventory(files, exempt_on=exempt, mode=mode)
    else:
        items = inventory(files, manifest_text(root, manifest_rev), mode=mode, exempt_on=exempt)
    if soft:
        items.refused += soft
    return items


_UNMEASURED = [
    (re.compile(r"\b(?:npm|pnpm|yarn|bun|deno)\b[^\n;&|]*?\s(?:install|add|i|exec|x|dlx)(?=\s|$)|\b(?:npx|bunx)\b|\bcargo\s+(?:install|binstall)\b|\bgem\s+install\b|\bpipx\s+(?:install|run)\b|\buvx?\s+\S|\bbrew\s+(?:install|reinstall|upgrade)\b|\bconda\s+(?:install|create)\b|\bmamba\s+install\b|\bbundle\s+(?:install|add)\b|\bdotnet\s+(?:tool\s+install|add\s+package|restore)\b|\bgo\s+(?:get|run)\b[^\n]*\$"), "a package-manager install"),
    (re.compile(r"\b(?:apt|apt-get|dnf|yum|microdnf|zypper|apk|snap|pacman|choco|winget)\s+(?:-\S+\s+)*(?:install|add|reinstall|upgrade)\b"), "a system package install"),
    (re.compile(r"\bgh\s+(?:release\s+download|extension\s+install)\b"), "a gh release or extension download"),
    (re.compile(r"\bgit\s+(?:-\S+\s+)*(?:clone|submodule\s+update|fetch\s+\S*https?://|archive\s+--remote)\b"), "a git clone or remote fetch"),
    (re.compile(r"\b(?:helm\s+(?:repo\s+add|install|upgrade)|kubectl\s+(?:apply|create)\s+[^\n]*https?://)"), "a helm or kubectl fetch"),
    (re.compile(r"\bpip[0-9.]*\b[^\n;&|]*?\b(?:install|download)\b[^\n]*(?:git\+|https?://)"), "a pip install from a URL"),
    (re.compile(r"\bdocker\s+build\s+[^\n]*https?://"), "a docker build from a URL"),
]


def unmeasured(files, manifest=_UNSET, exempt_on=True, mode="daily", exempt_set=None):
    """{(file, form, command line): occurrences} for every install form in the workflows and scripts that this inventory does not measure, read after
    joining backslash continuations. Reported as information; a pull request that ADDS an entry (a new command line, even in place of another) is refused."""
    out = {}
    exempt, _problems = harness_exempt(files, manifest, mode) if (exempt_on or exempt_set is not None) else (set(), [])
    if exempt_set is not None:
        exempt = set(exempt_set)
    for path, text in sorted(files.items()):
        if path in exempt:
            continue                          # listed in the reviewed manifest, bytes unchanged (AC11)
        if not (_wf_or_action_name(path) or _is_script(path, text)):
            continue                          # the SAME scope as the inventory (AC11): workflows, action files, shell scripts; no .github/agent/ exclusion
        extra = _extra_scalars(text) if _wf_or_action_name(path) else []
        for line in re.sub(r"\\\r?\n", "", text).split("\n") + extra:
            flat = " ".join(line.split())
            if len(flat) > MAX_LINE:
                raise RuntimeError(f"{path}: a command line of {len(flat)} characters is longer than the {MAX_LINE} this check reads: refusing to read it partially")
            for seg in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat):    # each downloader invocation on its own: a release URL elsewhere on the line excuses nothing
                urls = re.findall(r"https?://[^\s'\"]+", _hide(seg))
                plain = urls and all(re.match(r"^https?://github\.com/[\w.-]+/[\w.-]+/releases/(?:latest/)?download/", u) and (_GH_DOWNLOAD.search(u) or _GH_LATEST.search(u)) for u in urls)
                if re.search(r"\b(?:curl|wget)\b", seg) and not plain:
                    key = (path, "a download", hashlib.sha256(seg.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(seg)[:100])
                    out[key] = out.get(key, 0) + 1
            for rx, what in _UNMEASURED:
                if rx.search(flat):
                    key = (path, what, hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(flat)[:100])  # the WHOLE line decides identity (its hash), never a truncation
                    out[key] = out.get(key, 0) + 1
    return out


def main():
    root, rev = (sys.argv[1] if len(sys.argv) > 1 else "."), (sys.argv[2] if len(sys.argv) > 2 else None)
    print(json.dumps(sorted(load_at(root, rev)), indent=1))


if __name__ == "__main__":
    main()
