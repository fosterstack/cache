#!/usr/bin/env python3
"""The pin scan (REQ-SUP-001-AC2): names every version a pull request moves and passes only a pin it can read.

  pin-age-check.py --root REPO --base REV --head REV [--json FILE] [--base-inputs FILE] [--exceptions FILE]

Exit 0: nothing moved, or every moved version is a pin the scan can read (an exact version, a commit or a
digest) or is ruled. Exit 1: a moved item the scan
cannot read or pin (a range, a moving name, an expression, an unpinned install) and that no ruling covers.
Exit 2: the check could not run (unreadable input,
a tree that does not parse). No time is measured: the scan never waits for a version to age.
"""
import argparse
import hashlib
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inv = _load("pin-inventory")


def parse_time(s, clock=False):
    """ISO 8601 -> aware datetime, or None when it is not one."""
    if not isinstance(s, str):
        return None
    t = s.strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$", t)
    if not m:
        return None
    base, frac, tz = m.groups()
    try:
        d = dt.datetime.strptime(base.replace(" ", "T"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        d = d - sign * dt.timedelta(hours=hh, minutes=mm)
    d = d.replace(tzinfo=dt.timezone.utc)
    if frac and not clock:
        # a publication time's fractional second is rounded UP, a clock's (clock=True) is truncated:
        # a publication time is never shown earlier than it was
        d += dt.timedelta(seconds=1)
    return d


_PIN = re.compile(r"^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64}|v?\d+(?:\.\d+)*(?:[-+._][0-9A-Za-z][0-9A-Za-z.\-+]*)?)$")


def is_pin(version):
    """An exact version: a commit, a digest, or dotted numbers (an optional suffix such as -rc.1). Never a name (main, nightly, lts/*), a wildcard (1.*, 3.x), a range or an expression."""
    return bool(version) and bool(_PIN.match(version)) and "*" not in version and not re.search(r"(?i)(^|[.\-_])(x|latest|main|master|nightly|stable|lts)($|[.\-_])", version)


def judge_item(item):
    """(ok, reason): a moved item passes when it is a pin the scan can read."""
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or "$" in (item.path or "") or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or "")):
        return False, (f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, "
                       "or an action not named by its commit")
    if (item.kind == "tool" and item.name in ("python", "java", "node")
            and len(item.version.lstrip("v").split(".")) < 3):
        return False, (f"not a pin: {item.version!r} is a series, not an exact release "
                       "(the installer picks the newest patch)")
    return True, f"pinned at {item.version}"


class CouldNotLook(Exception):
    """The server could not be asked (rate limit, outage): the check cannot run. Never read as 'no proof', never a pass."""


GH_TIMEOUT = 120


def _gh_run(cmd, **kw):
    """subprocess.run for the gh and git calls here, with a timeout: a call that hangs is CouldNotLook (the run stops), never an answer."""
    try:
        return subprocess.run(cmd, **dict({"timeout": GH_TIMEOUT}, **kw))
    except subprocess.TimeoutExpired:
        raise CouldNotLook(f"{cmd[0]} {' '.join(map(str, cmd[1:3]))} did not answer in {GH_TIMEOUT}s")


def _gh_failed(r):
    """True for a plain miss (404 and friends); raises when the failure is the service's, not the answer's."""
    if not re.search(r"\b(404|410|422)\b", r.stderr + r.stdout):  # only "not there" is an answer; a 401/403, a rate limit or an outage means we could not look
        raise CouldNotLook(f"GitHub API: {(r.stderr or r.stdout).strip()[:120]}")
    return True


def _gh_pages(path):
    """Every page of a list endpoint (gh --paginate with --jq '.[]' prints one JSON object per line)."""
    r = _gh_run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except ValueError:
        return None


def _http_json(url, timeout=30):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except (OSError, ValueError):
        return None


TOOL_REPOS = {  # tool -> (github repo, tag prefix to try after the bare version)
    "trivy": "aquasecurity/trivy", "grype": "anchore/grype", "syft": "anchore/syft", "snyk": "snyk/cli", "osv": "google/osv-scanner",
    "scout": "docker/scout-cli", "gitsign": "sigstore/gitsign", "golangci-lint": "golangci/golangci-lint", "python": "actions/python-versions",
    "buildx": "docker/buildx", "goreleaser": "goreleaser/goreleaser", "cosign": "sigstore/cosign", "kind": "kubernetes-sigs/kind", "helm": "helm/helm", "node": "nodejs/node",
}


_TAGS = {}


def _tag_refs(repo):
    """{tag: commit} for EVERY tag of a public repository, annotated tags peeled, from ONE `git ls-remote` (no REST call per tag: a repository with hundreds
    of annotated tags would otherwise exhaust the shared API budget)."""
    if repo not in _TAGS:
        try:
            r = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"], capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise CouldNotLook(f"git ls-remote of {repo} failed: {type(e).__name__}")
        if r.returncode:
            raise CouldNotLook(f"git ls-remote of {repo} failed")
        refs = {}
        for line in r.stdout.splitlines():
            sha, _, ref = line.partition("\t")
            if not ref.startswith("refs/tags/"):
                continue
            name = ref[len("refs/tags/"):]
            if name.endswith("^{}"):
                refs[name[:-3]] = sha          # peeled: the commit an annotated tag points at
            else:
                refs.setdefault(name, sha)
        _TAGS[repo] = refs
    return _TAGS[repo]


def _tags_for_commit(repo, sha):
    """EVERY tag that points at the commit: v4 and v4.1.0 may both."""
    return sorted(t for t, c in _tag_refs(repo).items() if c == sha)


def _tag_for_commit(repo, sha):
    tags = _tags_for_commit(repo, sha)
    return tags[0] if tags else None


def _go_module(path, version):
    parts = path.split("/")
    for n in range(len(parts), 0, -1):
        mod = "/".join(parts[:n])
        info = _http_json(f"https://proxy.golang.org/{urllib.parse.quote(mod, safe='/').lower()}/@v/{urllib.parse.quote(version)}.info")
        if info and info.get("Version"):
            return mod, info
    return None, None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--json")
    ap.add_argument("--base-inputs", help="the base-inputs list (default: .github/policy/base-inputs.json beside this script's own checkout, the base branch in CI)")
    ap.add_argument("--exceptions", help="the rulings file (default: the one beside this script's own checkout, the base branch in CI)")
    a = ap.parse_args(argv)
    try:
        base_items = inv.load_at(a.root, a.base)
        head_items = inv.load_at(a.root, a.head)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"pin-age: cannot run: {e}", file=sys.stderr)
        return 2
    moved = inv.moved(base_items, head_items)
    try:
        return _run(a, moved)
    except RuntimeError as e:
        print(f"pin-age: cannot run: {e} (not a pass)", file=sys.stderr)
        return 2


def _line_hash(flat):
    return hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()


_OCC = {}


def _occurrences(root, rev):
    """{key: {whole-line hash: occurrences}}. A line bash reads differently from the flattening (whitespace other than space or tab, a continuation) gets
    a group no row can name ('unruled:' + its hash). Read once per revision."""
    if (root, rev) not in _OCC:
        _OCC[(root, rev)] = _read_occurrences(root, rev)
    return _OCC[(root, rev)]


def _read_occurrences(root, rev):
    out = {}
    for k, flat, bashlike in inv.unmeasured_occurrences({**inv.tree_surfaces(root, rev), **inv.tree_files(root, rev), **inv.tree_scripts(root, rev)}):   # a read error propagates (exit 2)
        lh = _line_hash(flat) if bashlike else "unruled:" + _line_hash(flat)
        _LINE_TEXT[lh] = flat
        per = out.setdefault(k, {})
        per[lh] = per.get(lh, 0) + 1
    return out


def _unmeasured_counts(root, base, head):
    """{key: {whole-line hash: head occurrences}} for every (key, whole line) the head has MORE of than the base: an occurrence is identified by its key
    AND the whole line it sits in, so an edited line that keeps its download segment is an addition, like a new one (REQ-SUP-001-AC16)."""
    b, h = _occurrences(root, base), _occurrences(root, head)
    added = {}
    for k, per in h.items():
        for lh, n in per.items():
            if n > b.get(k, {}).get(lh, 0):
                added.setdefault(k, {})[lh] = n
    return added


def _added_unmeasured(root, base, head):  # keys are (file, form, the normalised command): an in-place swap or an edit of the line around it is an ADDITION
    """Install forms this check cannot measure that the head has MORE of than the base (per file, form and whole line): a PR that adds one is refused."""
    return sorted(_unmeasured_counts(root, base, head))


# REQ-SUP-001-AC16: the advisor's rulings on lines that only MENTION a download tool (a comment, an echo string, a stub written as data). They are read from
# the exceptions file beside the checkout this script runs from: in CI that is trusted/ (the base branch), never the pull request's tree (--root).
DEFAULT_EXCEPTIONS = os.path.normpath(os.path.join(HERE, "..", "..", "supply-chain-exceptions.json"))
_RULED_FIELDS = ("file", "form", "key", "line", "ruling")
TEXT_RULING = "text, not a command: "      # the convention: a line that only MENTIONS a download tool
LIVE_RULING = "live fetch from the Wolfi package host: "   # a real fetch, honored only for https on packages.wolfi.dev (see _live_fetch_line_ok)
GO_RULING = "pinned toolchain fetch (the recipe pin is verified before storing): "   # the Go toolchain tarball (REQ-SUP-001-AC23): honored only for https://go.dev/dl/ plus one variable
LOOPBACK_RULING = "loopback fetch (REQ-SUP-001-AC25): "   # the one line of the loopback helper that starts the fetch program (REQ-SUP-001-AC24): honored for that file and that line's sha256 only
LOOPBACK_FILE = "bin/loopback-get.sh"
LOOPBACK_LINE = """curl -q -g --noproxy '*' --proto "=$proto" --max-redirs 0 "$@" "$url" || exit $?"""    # the raw text of the line, byte for byte (no indent, no trailing space, no carriage return)
LOOPBACK_LINE_SHA256 = "7dd5872cd29aa6ff52be7b831d287c5d72b58507d90b3a39489c70a5f8f58ccd"   # sha256 of that line as the scan hashes it (whitespace collapsed); the raw text above is what the head file must hold
DOWNLOAD_FORM = "a download"
_LIVE_URL = re.compile(r"https://packages\.wolfi\.dev(?:/[A-Za-z0-9._+~/-]*)?")
# the per-package fetch (advisor, Oct 15, owner rule 48): the literal https://packages.wolfi.dev/os/ (trailing slash included, so the host cannot change) followed by
# exactly ONE variable and nothing else
_LIVE_URL_VAR = re.compile(r"https://packages\.wolfi\.dev/os/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_GO_OUT = re.compile(r"(?:[A-Za-z0-9_./-]|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})+")
_GO_URL_VAR = re.compile(r"https://go\.dev/dl/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_ANY_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"]+")
_LINE_TEXT = {}                              # whole-line hash -> the flattened line, filled by _occurrences


_LIVE_FLAG_PLAIN = {"-f", "-s", "-S", "-L", "-fsSL", "-fsS", "-fSL", "-sSL", "-g", "--globoff", "--fail", "--silent", "--show-error", "--location", "--tlsv1.2"}
_LIVE_FLAG_VALUE = {"--max-filesize": r"[0-9]+", "--max-time": r"[0-9]+", "--proto": r"=https", "-o": r"[A-Za-z0-9_./${}-]+", "--output": r"[A-Za-z0-9_./${}-]+"}


def _live_fetch_line_ok(flat, toolchain=False):
    """The bound line is exactly ONE curl command: curl or /usr/bin/curl, then only flags from a fixed list (with a plain value where one is taken), then exactly one
    URL operand that is https on the host packages.wolfi.dev (with toolchain=True instead: exactly https://go.dev/dl/ followed by ONE variable, REQ-SUP-001-AC23); optionally followed by `|| die "plain text" [digit]` or `|| exit N`. The line is split into shell words,
    so quote concatenation cannot change a word after the check; a variable may appear only as part of the -o file name; no second command, pipe, redirection,
    substitution, other operand or schemeless host is accepted."""
    import shlex
    left, sep, right = flat.partition("||")
    if sep and not re.fullmatch(r'\s*(?:die(?: "[^"$`\\]*")?(?: [0-9]+)?|exit [1-9][0-9]*)\s*', right):
        return False
    if re.search(r"[;&|<>`]|\$\(", left):
        return False
    try:
        w = shlex.split(left, posix=True)
    except ValueError:
        return False
    if len(w) < 3 or w[0] not in ("curl", "/usr/bin/curl") or w[1] not in (("-q",) if toolchain else ("-q", "--disable")):
        return False                                   # -q first: no default .curlrc (CURL_HOME) can add a URL or an option (the Go shape takes only the spelling -q)
    raw = re.findall(r"""(?:"[^"]*"|'[^']*'|[^\s"']+)+""", left)
    if len(raw) != len(w):
        return False
    if toolchain and "'" in left:
        return False                                   # the Go shape has no single quote anywhere: a single-quoted $name is a literal dollar sign, never a variable
    for rt in raw:
        # an expansion, brace, glob or tilde may appear only inside double quotes: unquoted, the shell splits it into several words
        if re.search(r"[$`{}*?\[\]~]", re.sub(r'"[^"]*"|\'[^\']*\'', "", rt)):
            return False
    i, operands, globoff, op_raw = 2, [], False, []
    while i < len(w):
        t = w[i]
        if t in _LIVE_FLAG_PLAIN:
            globoff = globoff or t in (("-g",) if toolchain else ("-g", "--globoff"))
            i += 1
        elif t in _LIVE_FLAG_VALUE:
            if i + 1 >= len(w) or not re.fullmatch(_LIVE_FLAG_VALUE[t], w[i + 1]) or (t not in ("-o", "--output") and "$" in w[i + 1]):
                return False
            if toolchain and t in ("-o", "--output") and not _GO_OUT.fullmatch(w[i + 1]):
                return False                           # the Go shape: an output value is literal characters and plain $name / ${name} references only
            i += 2
        elif t.startswith("-"):
            return False                               # an option outside the list (-x, -K, --resolve, --url, an attached value, a cluster not listed)
        else:
            operands.append(t)
            op_raw.append(raw[i])
            i += 1
    if len(operands) != 1:
        return False
    if toolchain:
        # the variable form only, only with -g, and the operand must be double-quoted or bare: a single-quoted $f is a literal dollar sign, not a variable
        return globoff and "'" not in op_raw[0] and _GO_URL_VAR.fullmatch(operands[0]) is not None
    if _LIVE_URL_VAR.fullmatch(operands[0]) is not None:
        return globoff                                  # curl itself expands {a,b} and [1-2] in a URL: a variable operand is one transfer only with -g
    return _LIVE_URL.fullmatch(operands[0]) is not None


# REQ-SUP-001-AC16, the optional row field `context`: `assignment` only. The row's line must be ONE plain NAME=word assignment (no substitution, no second command), which the
# checker proves from the head file at scan time. A context only narrows: a row whose context does not hold rules nothing. A row naming any other context is a malformed list.
CONTEXTS = ("assignment",)
_INTERP_WORDS = frozenset("sh bash dash zsh ksh ash csh tcsh fish eval source . exec xargs python python2 python3 node nodejs perl ruby awk gawk mawk nawk php lua".split())
_DATA_CONSUMERS = frozenset("cat grep egrep fgrep sort head tail wc cut tr diff cmp jq base64 sha256sum shasum md5sum od".split())
_DEF_FUNC = re.compile(r"^[ \t]*(?:function[ \t]+([A-Za-z_][\w.-]*)|([A-Za-z_][\w.-]*)[ \t]*\([ \t]*\))", re.M)


def _unquote(raw):
    """Shell quote removal of one word (single quotes literal, double quotes with a backslash only before dollar, backtick, double quote and backslash, a backslash escapes the next character): the text bash compares a heredoc terminator with."""
    out, i = [], 0
    while i < len(raw):
        c = raw[i]
        if c == "'":
            k = raw.find("'", i + 1)
            if k < 0: return None
            out.append(raw[i + 1:k]); i = k + 1
        elif c == '"':
            k, buf = i + 1, []
            while k < len(raw) and raw[k] != '"':
                if raw[k] == "\\" and k + 1 < len(raw) and raw[k + 1] in '$`"\\': k += 1
                buf.append(raw[k]); k += 1
            if k >= len(raw): return None
            out.append("".join(buf)); i = k + 1
        elif c == "\\":
            if i + 1 < len(raw): out.append(raw[i + 1])
            i += 2
        else:
            out.append(c); i += 1
    return "".join(out)


def _shell_lex(lines):
    """Walk the script once, quote-aware across lines. Returns (heredocs, sane, state): state[i] is the quote/substitution stack at the START of line i as a tuple (() = plain code
    position) or None when line i lies inside a here-document body; each heredoc is {open, start, end (the terminator's index; None if there is none), quoted, nested, bad, opener (the
    command line, continuation lines joined), targets (files its output goes to), ops (how many heredocs the line opens)}. A `<<` counts only in code position (not inside quotes, a
    comment, arithmetic or a here-string). sane is False when the walk ends inside an open quote or substitution: then nothing in the file is proved."""
    hds, stack, i, n = [], [], 0, len(lines)
    insane = False
    state = [None] * n
    while i < n:
        state[i] = tuple(stack)
        line, j, ops, cmt = lines[i], 0, [], False
        while j < len(line) and not cmt:
            c, top = line[j], (stack[-1] if stack else "")
            if top == "'":
                if c == "'": stack.pop()
            elif top == '"':
                if c == "\\": j += 1
                elif c == '"': stack.pop()
                elif c == "`": stack.append("`")
                elif c == "$" and line[j + 1:j + 2] == "{":
                    k, d = j + 2, 1
                    while k < len(line) and d: d += (line[k] == "{") - (line[k] == "}"); k += 1
                    if d: insane = True                 # a parameter expansion that does not close on its line: its word can hold substitutions the walk does not follow
                    else: j = k - 1
                elif c == "$" and line[j + 1:j + 2] == "(":
                    if line[j + 2:j + 3] == "(": stack.append("$(("); j += 2
                    else: stack.append("$("); j += 1
            else:                                   # code position: top level, $( ), $(( )), (( )), backticks, ( )
                if c == "$" and line[j + 1:j + 2] == "{":
                    k, d = j + 2, 1
                    while k < len(line) and d: d += (line[k] == "{") - (line[k] == "}"); k += 1
                    if d: insane = True
                    else: j = k - 1
                elif c == "\\": j += 1
                elif c == "'": stack.append("'")
                elif c == '"': stack.append('"')
                elif c == "`":
                    if top == "`": stack.pop()
                    else: stack.append("`")
                elif c == "$" and line[j + 1:j + 2] == "(":
                    if line[j + 2:j + 3] == "(": stack.append("$(("); j += 2
                    else: stack.append("$("); j += 1
                elif c.isalpha() and (j == 0 or line[j - 1] in " \t;&|({") and re.match(r"(?:if|while|until|for|select|case)(?![\w.-])", line[j:]) and re.search(r"(?:^|[;&|({]|\bthen|\bdo|\belse|\belif)[ \t]*$", line[:j]):
                    stack.append("kw")                      # a compound command: what follows its fi / done / esac (a pipe to a shell) decides what a heredoc inside it feeds
                elif c.isalpha() and top == "kw" and (j == 0 or line[j - 1] in " \t;&|({") and re.match(r"(?:fi|done|esac)(?![\w.-])", line[j:]):
                    stack.pop()
                elif c == "{" and (j == 0 or line[j - 1] in " \t;&|(") and (j + 1 == len(line) or line[j + 1] in " \t"):
                    stack.append("{")                       # a brace group: what a heredoc inside it feeds is decided by what follows the closing brace
                elif c == "}" and top == "{" and (j == 0 or line[j - 1] in " \t;&|"):
                    stack.pop()
                elif c == "(":
                    if top == "(" and line[j - 1:j] == "(": stack[-1] = "(("
                    else: stack.append("(")
                elif c == ")" and top in ("$(", "(", "$((", "(("):
                    if top == "$(" and re.match(r"[ \t]*\(?[^\s()]+(?:\|[^\s()]+)*$", line[:j]):
                        insane = True                   # a bare word, then `)`, at the start of a line inside $( ): a case pattern, not the end of the substitution; not followed
                    stack.pop()
                    if top in ("$((", "((") and line[j + 1:j + 2] == ")": j += 1
                elif c == "#" and (j == 0 or line[j - 1] in " \t;&|(") : cmt = True
                elif c == "<" and line[j:j + 3] == "<<<":
                    j += 2                          # a here-string, not a heredoc
                elif c == "<" and line[j:j + 2] == "<<" and top not in ("$((", "(("):
                    m = re.match(r"<<(-?)[ \t]*((?:'[^']*'|\"[^\"]*\"|\\.|[^\s;&|()<>'\"\\])+)", line[j:])
                    if m:
                        raw = m.group(2)
                        quoted = bool(re.search(r"['\"\\]", raw))
                        delim = _unquote(raw)
                        ops.append((m.group(1) == "-", quoted, delim, any(s in ("$(", "`", '"', "(", "((", "{", "kw") for s in stack)))
                        j += m.end() - 1
            j += 1
        i += 1
        if not ops:
            continue
        o = i - 1                                   # the opener line
        first = o
        while first > 0 and lines[first - 1].rstrip().endswith("\\"):
            first -= 1
        opener = " ".join(lines[first:o + 1])
        bad = lines[o].rstrip().endswith("\\")      # the command goes on after the operator: where the body starts is not something this walk claims
        stripped = re.sub(r"<<-?[ \t]*(?:'[^']*'|\"[^\"]*\"|\\.|\w+)", " ", opener)
        tee_ops = []
        for m in re.finditer(r"\btee\b((?:[ \t]+(?:-\w+|\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+))+)", opener):
            tee_ops += re.findall(r"\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+", re.sub(r"(?:^|[ \t])-\w+", " ", m.group(1)))
        targets = [t.strip("'\"") for t in re.findall(r"(?:^|[^\d<>&])(?:\d*>>?|&>>?)[ \t]*(\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+)", stripped) + tee_ops]
        targets = [t for t in targets if t and not t.startswith("&") and t not in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty") and not t.startswith("/dev/fd/")]
        for tab, quoted, delim, nested in ops:
            start, k = i, i
            if delim is None:
                hds.append({"open": o, "start": start, "end": None, "quoted": quoted, "nested": nested, "bad": True, "opener": opener, "targets": targets, "ops": len(ops)})
                continue
            while k < n and (lines[k].lstrip("\t") if tab else lines[k]) != delim:
                state[k] = None
                k += 1
            hds.append({"open": o, "start": start, "end": k if k < n else None, "quoted": quoted, "nested": nested, "bad": bad, "opener": opener, "targets": targets, "ops": len(ops)})
            i = (k + 1) if k < n else n
            if k >= n:
                break
    return hds, not stack and not insane, state


_NOT_CODE = frozenset(("'", '"', "`", "$((", "(("))        # a stack entry that makes a line text or arithmetic, not a command position


def _func_bodies(lines):
    """{name: body text} of the shell functions the file defines (both `name() {` and `function name {`, the brace on the same or the next line)."""
    out = {}
    for idx, ln in enumerate(lines):
        m = _DEF_FUNC.match(ln)
        if not m:
            continue
        name = m.group(1) or m.group(2)
        if "{" not in ln and not (idx + 1 < len(lines) and lines[idx + 1].lstrip().startswith("{")):
            continue
        depth, body, k, seen = 0, [], idx, False
        while k < len(lines):
            bare = re.sub(r"(?:^|(?<=\s))#.*$", "", re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", "", lines[k]))        # a brace inside a quoted string or a comment does not open or close the function
            body.append(lines[k]); depth += bare.count("{") - bare.count("}"); seen = seen or "{" in bare
            if seen and depth <= 0: break
            k += 1
        out[name] = out[name] + "\n" + "\n".join(body) if name in out else "\n".join(body)    # every definition counts, not only the last
    return out


def _plain_value(s):
    """True when the assignment text has no substitution that RUNS: no $( or backtick outside single quotes, no <( or >( outside every quote, no old-style $[ arithmetic."""
    sq = dq = False
    i = 0
    while i < len(s):
        c = s[i]
        if sq:
            sq = c != "'"
        elif c == "\\":
            i += 1
        elif c == "'" and not dq:
            sq = True
        elif c == '"':
            dq = not dq
        elif c == "`" or (c == "$" and s[i + 1:i + 2] in ("(", "[")):
            return False
        elif not dq and c in "<>" and s[i + 1:i + 2] == "(":
            return False
        i += 1
    return not (sq or dq)


def _commands_redefined(lines, text, extra=()):
    """True when the file defines a function named like a command the grammars trust (plus `extra`), or switches aliases on: the command's name then proves nothing."""
    trusted = "|".join(re.escape(w) for w in sorted(_DATA_CONSUMERS | _INTERP_WORDS | {"echo", "printf", "true", "test", "tee", "uniq", "xxd"} | set(extra))) + r"|python[\d.]*"
    return bool((set(_func_bodies(lines)) & (_DATA_CONSUMERS | _INTERP_WORDS | {"python", "python3", "echo", "printf", "true", "test"} | set(extra))) or "expand_aliases" in text or re.search(r"(?m)^[ \t]*alias[ \t]+[^\s=]", text) \
            or re.search(r"(?m)(?<![\w.$-])(?:function[ \t]+(?:" + trusted + r")(?![\w.-])|(?:" + "|".join(w for w in trusted.split("|") if w[:1].isalpha()) + r")[ \t]*\(\s*\))", text))


def _context_holds(text, line_hash):
    """True only when EVERY single-line occurrence of the ruled line (by the hash of its whole flattened text) in `text` is one plain NAME=word assignment at a command
    position. None found: False."""
    lines = text.split("\n")
    hits = [i for i, l in enumerate(lines)
            if " ".join(l.split()) and all(c in " \t" or not c.isspace() for c in l) and _line_hash(" ".join(l.split())) == line_hash and not (i and lines[i - 1].rstrip().endswith("\\"))]
    if not hits:
        return False
    _, sane, state = _shell_lex(lines)
    if not sane:
        return False
    if _commands_redefined(lines, text):
        return False                           # a command the grammar trusts is redefined (or aliases are on): its name proves nothing here
    if re.search(r"\b(?:declare|typeset|integer|(?:local|readonly|export)[ \t]+-\w+)\b", text):
        return False                           # a variable with attributes (integer, array, nameref ...) evaluates or redirects its assignment: nothing in this file is judged plain
    import shlex
    for i in hits:
        if state[i] is None or set(state[i]) & _NOT_CODE:    # inside a quote, arithmetic or a here-document: the shell state decides what it is; a function or compound body is plain code
            return False
        s = lines[i].strip()
        if not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", s) or s.endswith("\\") or not _plain_value(s): return False
        lx = shlex.shlex(s, posix=True, punctuation_chars=True); lx.whitespace_split = True; lx.commenters = ""
        try:
            toks = list(lx)
        except ValueError:
            return False
        if len(toks) != 1 or not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", toks[0]): return False
    return True


_HEAD_SCRIPTS = {}


def _scripts_at(root, rev):
    return _HEAD_SCRIPTS.setdefault((root, rev), inv.tree_scripts(root, rev))


_RAW_CR = {}


def _has_cr(root, rev, path):
    """True when the file's real bytes hold a carriage return (the scan reads text with universal newlines, which hides one: bash would see a different line). Unreadable: True."""
    key = (root, rev, path)
    if key not in _RAW_CR:
        try:
            raw = subprocess.run(["git", "-C", root, "show", f"{rev}:{path}"], capture_output=True, check=True, timeout=120).stdout if rev is not None else open(os.path.join(root, path), "rb").read()
            _RAW_CR[key] = b"\r" in raw
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            _RAW_CR[key] = True
    return _RAW_CR[key]


_LOOPBACK_OK = {}


PINNED_FETCH_RULING = "pinned fetch (REQ-SUP-001-AC26): "   # nineteen script lines, each honored for its file and its whole-line sha256 only (see PINNED_FETCH)
PINNED_FETCH = {   # file -> the raw text of each pinned line, byte for byte (no trailing space, no carriage return); the head file must hold each exactly once
    'bin/release-assets.sh': [
        'gh release download "$rel" -D release-published',
    ],
    'bin/acceptance-k8s.sh': [
        'docker pull -q curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 && docker tag curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 "$CLIENT_LOCAL"',
    ],
    'bin/acceptance-gradle.sh': [
        '  code=$(curl -s -o /dev/null -w \'%{http_code}\' -I "localhost:18095/${key}")',
        'curl -s localhost:18095/metrics > /tmp/metrics-cold.txt',
        'curl -s localhost:18095/metrics > /tmp/metrics-warm.txt',
    ],
    'bin/acceptance-gradle-capped.sh': [
        'head_code() { curl -s -o /dev/null -w \'%{http_code}\' -I "localhost:18096/$1"; }',
        'curl -s localhost:18096/metrics > /tmp/capped-metrics.txt',
        'hdr=$(curl -s -D - -o /dev/null -X PUT --data-binary @/tmp/oversized-probe.bin http://localhost:18096/oversizedprobe)',
        "code=$(curl -s -o /dev/null -w '%{http_code}' -I http://localhost:18096/oversizedprobe)",
    ],
    'bin/acceptance-maven.sh': [
        'curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-cold.txt',
        'curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-warm.txt',
        'before_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk \'/^fscache_http_requests_total\\{method="PUT",status="201"\\}/ {print $2}\')',
        'after_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk \'/^fscache_http_requests_total\\{method="PUT",status="201"\\}/ {print $2}\')',
    ],
    'bin/acceptance-maven-capped.sh': [
        'app_code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w \'%{http_code}\' -I "http://localhost:18099/maven/v1.1/com.fosterstack.bench/app/${app_key}/app.jar")',
        'hdr=$(curl -s -u mvn:acceptance-secret -D - -o /dev/null -X PUT --data-binary @/tmp/mvn-oversized-probe.bin http://localhost:18099/maven/oversizedprobe)',
        "code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w '%{http_code}' -I http://localhost:18099/maven/oversizedprobe)",
    ],
    'bin/install-scanner.sh': [
        '    curl -q -fsSL -g -o "$tmp/go.tgz" "https://go.dev/dl/${gofile}" || die "download failed: go toolchain"',
    ],
    'bin/go-bump-open-pr.sh': [
        '  curl -q -fsSL -g -o "${dl}/published.json" "https://go.dev/dl/${jsonq}" || die "go.dev is unreachable: cannot read the published checksums" 1',
        '    curl -q -fsSL -g -o "${dl}/${tarball}" "https://go.dev/dl/${tarball}" || die "cannot download the Go tarball from go.dev" 1',
    ],
}
_PINNED_FETCH_SHA = {f: {hashlib.sha256(" ".join(l.split()).encode("utf-8", "replace")).hexdigest(): l for l in ls} for f, ls in PINNED_FETCH.items()}
_PINNED_OK = {}


def _pinned_line_ok(root, head, f, lh):
    """True only when the pinned line of file f whose whole-line sha256 is lh is held by the head file byte for byte exactly once, the file is a regular file (not a link),
    there is no carriage return in it and no other line that differs from the pinned one only in whitespace (the scan hashes with whitespace collapsed, so the raw
    text is compared here). Unreadable, or a line the checker does not pin: False. The same shape as the loopback ruling (AC25), for the nineteen lines of AC26."""
    key = (root, head, f, lh)
    if key not in _PINNED_OK:
        ok = False
        raw_line = _PINNED_FETCH_SHA.get(f, {}).get(lh)
        try:
            if raw_line is not None:
                if head is None:
                    path = os.path.join(root, f)
                    ok = os.path.isfile(path) and not os.path.islink(path)
                    raw = open(path, "rb").read() if ok else b""
                else:
                    ent = subprocess.run(["git", "-C", root, "ls-tree", head, "--", f], capture_output=True, check=True, timeout=120).stdout.decode("utf-8", "replace").split()
                    ok = len(ent) >= 4 and ent[0] in ("100644", "100755") and ent[1] == "blob"
                    raw = subprocess.run(["git", "-C", root, "show", f"{head}:{f}"], capture_output=True, check=True, timeout=120).stdout if ok else b""
                if ok:
                    lines = raw.split(b"\n")
                    same = [ln for ln in lines if " ".join(ln.decode("utf-8", "replace").split()) == " ".join(raw_line.split())]
                    ok = b"\r" not in raw and lines.count(raw_line.encode()) == 1 and len(same) == 1
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            ok = False
        _PINNED_OK[key] = ok
    return _PINNED_OK[key]


def _loopback_line_ok(root, head):
    """True only when the head file bin/loopback-get.sh is a regular file (not a link) holding the pinned line byte for byte exactly once, no carriage return anywhere
    and no other line that differs from it only in whitespace (the scan hashes with whitespace collapsed, so the raw text is compared here). Unreadable: False."""
    key = (root, head)
    if key not in _LOOPBACK_OK:
        ok = False
        try:
            if head is None:
                path = os.path.join(root, LOOPBACK_FILE)
                ok = os.path.isfile(path) and not os.path.islink(path)
                raw = open(path, "rb").read() if ok else b""
            else:
                ent = subprocess.run(["git", "-C", root, "ls-tree", head, "--", LOOPBACK_FILE], capture_output=True, check=True, timeout=120).stdout.decode("utf-8", "replace").split()
                ok = len(ent) >= 4 and ent[0] in ("100644", "100755") and ent[1] == "blob"
                raw = subprocess.run(["git", "-C", root, "show", f"{head}:{LOOPBACK_FILE}"], capture_output=True, check=True, timeout=120).stdout if ok else b""
            if ok:
                lines = raw.split(b"\n")
                same = [ln for ln in lines if " ".join(ln.decode("utf-8", "replace").split()) == " ".join(LOOPBACK_LINE.split())]
                ok = b"\r" not in raw and lines.count(LOOPBACK_LINE.encode()) == 1 and len(same) == 1
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            ok = False
        _LOOPBACK_OK[key] = ok
    return _LOOPBACK_OK[key]


def _context_proved(root, head, path, line_hash, row):
    """A row without a context is as it always was; a row with one rules its line only when the context is proved from the head file."""
    ruling, count, context = row
    if context is None:
        return True
    if not path.endswith(".sh"):
        return False
    text = _scripts_at(root, head).get(path)
    return text is not None and not _has_cr(root, head, path) and _context_holds(text, line_hash)


def _context_regressions(root, base, head, rulings):
    """{(key, line hash)} of lines a context row rules that held their context in the base and no longer do in the head. Such a line is not "added" (its count is unchanged),
    so the delta never looks at it: without this, a ruled line could be moved out of its heredoc and stay ruled."""
    out = {}
    for k, per in _occurrences(root, head).items():
        for lh, n in per.items():
            row = rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh))
            if not row or row[2] is None or not k[0].endswith(".sh"):
                continue
            was = _scripts_at(root, base).get(k[0])
            if was is not None and not _has_cr(root, base, k[0]) and _context_holds(was, lh) and not _context_proved(root, head, k[0], lh, row):
                out.setdefault(k, {})[lh] = n
    return out


def _row_for(rulings, root, head, k, lh):
    """The base branch's row for the line when its context (if any) holds in the head, else None: a row with a context that does not hold rules nothing."""
    r = rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh))
    return r if r is not None and _context_proved(root, head, k[0], lh, r) else None


MAX_RULED_COUNT = 100


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a JSON object repeats a key ({sorted(k for k in set(keys) if keys.count(k) > 1)})")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (Python's reader accepts NaN, Infinity and -Infinity; this file must not hold them)")


def load_ruled_text(path, required=False):
    """{(file, form, 64-hex segment hash, 64-hex whole-line hash): (ruling, count, context or None)} from the file's unmeasured_text list. A missing default file is no rulings; anything malformed
    raises RuntimeError (the check cannot run, exit 2): never 'nothing ruled' and never 'everything ruled'."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the exceptions file {path} (unmeasured_text) does not exist")
        return {}
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)   # a repeated key would let a later copy silently win
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the exceptions file {path} (unmeasured_text) is unreadable: {e}")
    rows = d.get("unmeasured_text", []) if isinstance(d, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: unmeasured_text is not a list")
    out = {}
    for i, r in enumerate(rows):
        bad = lambda why: RuntimeError(f"{path}: unmeasured_text row {i} {why}")
        if not isinstance(r, dict) or set(r) - set(_RULED_FIELDS) - {"count", "context"} or not set(_RULED_FIELDS) <= set(r):
            raise bad("must be an object with exactly file, form, key, line, ruling (and an optional count and context)")
        if not all(isinstance(r[k], str) and r[k].strip() for k in _RULED_FIELDS):
            raise bad("has an empty or non-text file, form, key, line or ruling")
        if not re.fullmatch(r"[0-9a-f]{64}", r["key"]):
            raise bad("key is not the scan's 64 lowercase hex hash")
        if not re.fullmatch(r"[0-9a-f]{64}", r["line"]):
            raise bad("line is not the 64 lowercase hex hash of the whole flattened line")
        count = r.get("count", 1)
        if type(count) is not int or not 1 <= count <= MAX_RULED_COUNT:
            raise bad(f"count is not a whole number from 1 to {MAX_RULED_COUNT}")
        if r["form"] == LOCAL_CALL_FORM and "context" in r:
            raise bad("is a local-call row, which does not take a context")
        if "context" in r and (type(r["context"]) is not str or r["context"] not in CONTEXTS):
            raise bad("has a context that is not one of " + ", ".join(CONTEXTS))
        k = (r["file"], r["form"], r["key"], r["line"])
        if k in out:
            raise bad("repeats an earlier row (file, form, key and line)")
        out[k] = (r["ruling"].strip(), count, r.get("context"))
    return out


DEFAULT_BASE_INPUTS = os.path.normpath(os.path.join(HERE, "..", "..", "policy", "base-inputs.json"))


def load_base_inputs(path, required=False):
    """REQ-SUP-001-AC21: the set of paths .github/policy/base-inputs.json lists (read from the base branch's copy beside this script, never the pull request's tree).
    A missing default file lists nothing; anything malformed raises RuntimeError (exit 2): never 'nothing exempted' and never 'everything'."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the base-inputs list {path} does not exist")
        return set()
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the base-inputs list {path} is unreadable: {e}")
    lst = d.get("base_inputs") if isinstance(d, dict) else None
    if not isinstance(lst, list) or not all(isinstance(x, str) and x for x in lst):
        raise RuntimeError(f"{path}: base_inputs is not a list of non-empty paths")
    return set(lst)


def split_base_inputs(moved, paths):
    """A (file) item whose repository path the list names is no item: its content is the repository's own base record. Exact equality with the path as git
    names it (Item.raw), never with the display name, which _hide() rewrites."""
    keep, ruled = [], []
    for m in moved:
        (ruled if (m.kind == "tool" and m.version == "(file)" and m.raw is not None and m.raw in paths) else keep).append(m)
    return keep, ruled


UNPINNED_FORM = "an unpinned package install"
LOCAL_CALL_FORM = "a local reusable workflow call"


def _item_hash(item):
    return hashlib.sha256(item.key.encode("utf-8", "replace")).hexdigest()


def unresolved_call_rows(root, rev, exceptions_path):
    """The local-call rows of the exceptions file that would rule NO item of the tree at rev, judged by the very tuple split_ruled_local_calls() looks up
    ((file, form, h, h) for an eligible item: kind action, version (local), with an origin file): [] when every row resolves to exactly one item."""
    rows = [k for k in load_ruled_text(exceptions_path, required=True) if k[1] == LOCAL_CALL_FORM]
    have = {}
    for it in inv.load_at(root, rev).values():
        if it.kind == "action" and it.version == "(local)" and it.src:
            h = _item_hash(it)
            have.setdefault((it.src[0], LOCAL_CALL_FORM, h, h), []).append(it.key)
    return [k for k in rows if len(have.get(k, [])) != 1]


def split_ruled_local_calls(moved, rulings):
    """REQ-SUP-001-AC19: a local reusable-workflow call that keeps a with: block is an item that cannot pass, unless a base-branch row names it: file, form
    "a local reusable workflow call", key and line both the 64-hex hash of the item's whole identity (its path and the hash of its with: block), so an edited
    with: block is another item. Returns (still moved, [(item, ruling)])."""
    keep, ruled = [], []
    for m in moved:
        r = None
        if m.kind == "action" and m.version == "(local)" and m.src:
            h = _item_hash(m)
            r = rulings.get((m.src[0], LOCAL_CALL_FORM, h, h))
        (ruled if r else keep).append((m, r[0]) if r else m)
    return keep, ruled


def drop_ruled_unpinned(items, ruled_lines):
    """REQ-SUP-001-AC20: an unpinned package item leaves the list only when the script line that made it (its own path and line id) is a ruled occurrence."""
    return [m for m in items if not (m.kind == "package" and m.version == "(unpinned)" and m.src and tuple(m.src) in ruled_lines)]


def ruled_unpinned_lines(root, base, head, exceptions_path):
    """The (script path, line id) pairs of the unpinned-package occurrences the head ADDS that a base-branch row rules, within the row's count. Shared by this check and
    pin-audit.py, so the one required job judges a ruled line once."""
    rulings = load_ruled_text(exceptions_path, required=False)
    in_base = _occurrences(root, base)
    out = set()
    for k, per in _unmeasured_counts(root, base, head).items():
        if k[1] != UNPINNED_FORM:
            continue
        rs = [_row_for(rulings, root, head, k, lh) for lh in per]
        # a line the base already holds is never ruled here: an item of that line may have moved because an assignment it reads changed, and a copy of
        # the line cannot be told from it (the occurrence is still reported; the item keeps failing)
        if all(r and n <= r[1] and not in_base.get(k, {}).get(lh) for r, (lh, n) in zip(rs, per.items())):
            out.update((k[0], lh) for lh in per)
    return out


GO_INSTALL_REASON = ("Go's own release, downloaded from go.dev and verified against its pinned sha256 "
                     "(REQ-SUP-001-AC27); the advisory check still applies")
_GO_VER_LINE = re.compile(r"^GO_VER=(\d+\.\d+\.\d+)$")
_GO_FILE = re.compile(r'^[ \t]*gofile="go\$\{GO_VER\}\.\$\{A_GO\}\.tar\.gz"[ \t]*$')
_GO_CURL = re.compile(r'^[ \t]*curl -q -fsSL -g -o "\$tmp/go\.tgz" "https://go\.dev/dl/\$\{gofile\}" \|\| die "download failed: go toolchain"[ \t]*$')
_GO_VERIFY = ["verify() { # file", "  local got", "  got=$(sha256sum \"$1\" | cut -d' ' -f1)",
              '  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM}) - refusing to run an unverified scanner"', "}"]
_GO_EXTRACT = re.compile(r'^[ \t]*mkdir -p "\$tmp/x" && tar -xzf "\$tmp/go\.tgz" -C "\$tmp/x" \|\| pipeline_fail "extract failed for go"[ \t]*$')
_GO_MSG = r'"(?:[^"$`\\]|\$\{[A-Za-z_]+\})*"'
_GO_WANT = re.compile(r'^[ \t]*\[ "\$want" = "\$GO_VER" \] \|\| pipeline_fail ' + _GO_MSG + r'[ \t]*$')
_GO_SHOW = re.compile(r'^[ \t]*"\$\{DEST\}/fscache-go/bin/go" version \| grep -q "go\$\{GO_VER\} " \|\| pipeline_fail ' + _GO_MSG + r'[ \t]*$')
_GO_FAIL = ['pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }']
_SUM_ROW = re.compile(r"^[ \t]*[A-Za-z0-9_.:|-]+\) SUM=[0-9a-f]{64} ;;[ \t]*$")
_SUM_MODULE = re.compile(r'^[ \t]*govulncheck:\*\) SUM="" ;;[ \t]*(?:#.*)?$')   # a module pinned by go.sum: its own key, empty sum
_GO_SUM = {a: re.compile(r"^[ \t]*go:" + a + r"\) SUM=[0-9a-f]{64} ;;[ \t]*$") for a in (r"x86_64\|go:amd64", r"aarch64\|go:arm64")}


def go_install_pin(root, head):
    """The pinned Go version when the head's bin/install-scanner.sh fetches Go ONLY from https://go.dev/dl/ at its
    pinned GO_VER, pins the sha256 of both
    architectures (64 hex each) and verifies the file right after the download; otherwise None. Any other line
    that downloads
    something Go-shaped (curl or wget naming go.tgz, GO_VER, go.dev or golang) voids it."""
    try:
        text = inv.tree_files(root, head).get("bin/install-scanner.sh")
    except (OSError, ValueError, RuntimeError):
        return None
    if not text:
        return None
    lines = text.split("\n")
    joined = re.sub(r"\\[ \t]*\n", " ", text).split("\n")   # a shell continuation is one command: a download written over two lines is still one
    vers = [m.group(1) for m in (_GO_VER_LINE.match(l) for l in lines) if m]
    if len(vers) != 1 or sum(1 for l in lines if re.match(r"^[ \t]*(?:export[ \t]+)?GO_VER=", l)) != 1:
        return None
    fetch = [i for i, l in enumerate(joined) if re.search(r"\b(curl|wget)\b", l) and re.search(r"go\.tgz|GO_VER|gofile|go\.dev|golang|go\$\{|go[0-9]+\.[0-9]", l)]
    if len(fetch) != 1 or not _GO_CURL.match(joined[fetch[0]]):
        return None
    names = [l for l in joined if re.match(r"^[ \t]*(?:export[ \t]+|readonly[ \t]+|local[ \t]+)?gofile=", l)]
    if len(names) != 1 or not _GO_FILE.match(names[0]):
        return None
    nxt = next((l.strip() for l in joined[fetch[0] + 1:] if l.strip()), "")
    if nxt != 'verify "$tmp/go.tgz"':
        return None
    if any(sum(1 for l in lines if rx.match(l)) != 1 for rx in _GO_SUM.values()) or sum(1 for l in lines if re.search(r"\bgo:", l) and re.search(r"\bSUM", l)) != 2:
        return None
    # the verifier and the failure helper are the reviewed ones, each defined once in ANY spelling (verify() / verify () / function verify)
    for name, want in (("verify", _GO_VERIFY), ("pipeline_fail", _GO_FAIL)):
        if len(re.findall(r"\bfunction[ \t]+" + name + r"\b|\b" + name + r"[ \t]*\([ \t]*\)", text)) != 1:
            return None
        starts = [i for i, l in enumerate(lines) if re.match(r"^" + name + r"\(\)", l)]
        if len(starts) != 1 or [l.rstrip() for l in lines[starts[0]:starts[0] + len(want)]] != want:
            return None
    # the installer defines only the reviewed helpers (a redefined sha256sum, cut or echo would change what verify() computes) and aliases nothing
    defs = set()
    for l in joined:
        if not l.lstrip().startswith("#"):
            q = re.sub(r"'[^']*'|\"[^\"]*\"", '""', l)
            defs.update(re.findall(r"([A-Za-z_][\w.-]*)[ \t]*\([ \t]*\)", q) + re.findall(r"\bfunction[ \t]+([\w.-]+)", q))
            if re.search(r"(?:^|[;&|{(]|\bthen|\bdo|\belse)[ \t]*(?:alias|enable|builtin|unalias)\b", q):
                return None
    if defs - {"verify", "pipeline_fail", "die"}:
        return None
    # the download and its verify call sit at the top level of the go arm of the one tool dispatch: counted from the START of the file, the only open construct at the
    # download is that dispatch `case` (a wrapper around it, a group or loop or condition around the arm, an inline `; (` all raise the depth: refused)
    arm = [i for i, l in enumerate(joined[:fetch[0]]) if re.match(r"^[ \t]*go\)[ \t]*$", l)]
    if len(arm) != 1:
        return None
    depth = 0
    for l in joined[:fetch[0]]:
        t = re.sub(r"'[^']*'|\"[^\"]*\"", '""', l.strip())
        if t.startswith("#"):
            continue
        depth += (len(re.findall(r"(?:^|[;&|)][ \t]*|\bthen[ \t]+|\bdo[ \t]+|\belse[ \t]+)(?:if|while|until|for|select|case)\b", t)) + (1 if t[:1] in "({" else 0)
                 + len(re.findall(r"[;&|][ \t]*[({]", t)) + (1 if re.search(r"\)[ \t]*\{[ \t]*(?:#.*)?$", t) else 0))
        depth -= len(re.findall(r"(?:^|[;&|)][ \t]*)(?:fi|done|esac)\b", t)) + (1 if t[:1] in ")}" else 0)
    if depth != 1:
        return None
    # outside the reviewed lines the Go names appear ONLY in the two reviewed read shapes (a version comparison and
    # the installed-version grep, each ending in a
    # pipeline_fail whose message contains no command substitution); ANY other mention of GO_VER, gofile, go.tgz,
    # go.dev or a Go archive name (go<N>.<N>) in a
    # non-comment line voids the pin: a write in any form, a second transfer by any command, a URL variable,
    # a read in another command
    for i, l in enumerate(joined):
        if i == fetch[0] or l.lstrip().startswith("#") or _GO_FILE.match(l) or _GO_VER_LINE.match(l) or l.strip() == 'verify "$tmp/go.tgz"' or _GO_EXTRACT.match(l) \
                or _GO_WANT.match(l) or _GO_SHOW.match(l):
            continue
        if re.search(r"GO_VER|gofile|go\.tgz|go\.dev|\bgo[0-9]+\.[0-9]", l):
            return None
    # every SUM assignment, anywhere on any line, is a pinned row: a literal pattern (no glob), `) SUM=<64 hex> ;;`; any other mention of SUM must only read it
    for l in joined:
        rest = re.sub(r"\$\{SUM\}|\$SUM\b", "", l)
        if re.search(r"\bSUM\b", rest) and not (_SUM_ROW.match(l) or _SUM_MODULE.match(l)):
            return None
    return vers[0]


def split_go_install(moved, root, head):
    """(the moved items without the Go release the installer pins, those Go items):
    only `tool:go` at the installer's own pinned version."""
    ver = go_install_pin(root, head) if any(it.kind == "tool" and it.name == "go" for it in moved) else None
    keep = [it for it in moved if not (ver and it.kind == "tool" and it.name == "go" and it.version == ver)]
    return keep, [it for it in moved if it not in keep]


def _run(a, moved):
    rulings = load_ruled_text(a.exceptions or DEFAULT_EXCEPTIONS, required=bool(a.exceptions))   # before the scan: a malformed list stops the check
    lines = _unmeasured_counts(a.root, a.base, a.head)
    for k, per in _context_regressions(a.root, a.base, a.head, rulings).items():
        lines.setdefault(k, {}).update(per)
    added, ruled = [], []
    for k in sorted(lines):
        # ruled only when EVERY added (key, whole line) is named by a row and its head occurrences are within that row's count (1 unless it says more):
        # the same segment inside any other line, an edited line, or one copy too many leaves the item refused
        rs = [_row_for(rulings, a.root, a.head, k, lh) for lh in lines[k]]
        if k[1] == DOWNLOAD_FORM and any(r and not r[0].startswith((TEXT_RULING, LIVE_RULING, GO_RULING, LOOPBACK_RULING, PINNED_FETCH_RULING)) for r in rs):
            rs = [None]                                  # a download row rules a line only with one of the two rulings the owner's rules name
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(LIVE_RULING) and not _live_fetch_line_ok(_LINE_TEXT.get(lh, "")) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # a live-fetch ruling on a line that is not wholly https on packages.wolfi.dev rules nothing
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(GO_RULING) and not (k[0].endswith(".sh") and not k[0].startswith(".github/") and _live_fetch_line_ok(_LINE_TEXT.get(lh, ""), toolchain=True)) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # a Go-toolchain ruling on a line that is not exactly the one go.dev/dl/ shape rules nothing (AC23)
        if any(r and r[0].startswith(LOOPBACK_RULING) and not (k[0] == LOOPBACK_FILE and lh == LOOPBACK_LINE_SHA256 and _loopback_line_ok(a.root, a.head)) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # the loopback ruling on any line but the helper's one pinned line rules nothing (AC25)
        if any(r and r[0].startswith(PINNED_FETCH_RULING) and not _pinned_line_ok(a.root, a.head, k[0], lh) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # the pinned-fetch ruling on any line but one of the nineteen pinned lines of its own file rules nothing (AC26)
        if all(r and n <= r[1] for r, n in zip(rs, lines[k].values())):
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in rs))))
        else:
            added.append(k)
    moved = drop_ruled_unpinned(moved, ruled_unpinned_lines(a.root, a.base, a.head, a.exceptions or DEFAULT_EXCEPTIONS))   # REQ-SUP-001-AC20
    moved, base_files = split_base_inputs(moved, load_base_inputs(a.base_inputs or DEFAULT_BASE_INPUTS, required=bool(a.base_inputs)))   # REQ-SUP-001-AC21
    moved, ruled_calls = split_ruled_local_calls(moved, rulings)                                                       # REQ-SUP-001-AC19: judged by the ruled row of ITS OWN line, never by another line's
    moved, go_free = split_go_install(moved, a.root, a.head)
    if not moved and not added and not go_free:
        print("pin-age: no pin moved")
        rows = []
    else:
        rows = []
        for it in moved:
            ok, reason = judge_item(it)
            # the Go release passes only by the installer's own lines (split_go_install above), never as a plain pin
            if it.kind == "tool" and it.name == "go":
                ok, reason = False, (f"Go {it.version} is not the release bin/install-scanner.sh pins from go.dev "
                                     "with both sha256 pins and the verify call (REQ-SUP-001-AC27)")
            rows.append({"item": it.key, "label": it.label, "ok": ok, "reason": reason})
        for it in go_free:
            rows.append({"item": it.key, "label": it.label, "ok": True, "reason": GO_INSTALL_REASON})
        print(f"pin-age: {len(rows)} moved version(s):")
        for r in rows:
            print(f"  {'ok  ' if r['ok'] else 'FAIL'} {r['item']}: {r['reason']}")
    for path, what, line in added:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": False,
                     "reason": f"{what} was added to {path} ({line[:100]}): this check cannot measure it, so a pull request that adds one is refused (use a pinned form it can measure)"})
        print(f"  FAIL unmeasured:{path}: {what} added: not measurable, refused")
    for it in base_files:
        rows.append({"item": it.key, "label": "", "ok": True,
                     "reason": f"base input: {it.name[5:]} is listed in .github/policy/base-inputs.json"})
        print(f"  ok   {it.key}: base input (REQ-SUP-001-AC21)")
    for it, ruling in ruled_calls:
        rows.append({"item": it.key, "label": "", "ok": True,
                     "reason": f"ruled text: a local reusable workflow call in {it.src[0]}: {ruling[:200]}"})
        print(f"  ok   {it.key}: ruled text (REQ-SUP-001-AC19): {ruling[:200]}")
    for (path, what, line), ruling in ruled:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": True,
                     "reason": f"ruled text: {what} in {path} ({line[:100]}) is listed in the base branch's unmeasured_text: {ruling[:200]}"})
        print(f"  ok   unmeasured:{path}: {what} ({line[:60]}): ruled text (REQ-SUP-001-AC16): {ruling[:200]}")
    failing = [r for r in rows if not r["ok"]]
    if a.json:
        json.dump({"moved": rows}, open(a.json, "w"), indent=1)
    if failing:
        print(f"pin-age: FAIL: {len(failing)} of {len(rows)} moved version(s) not a pin the scan can read")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
