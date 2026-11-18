#!/usr/bin/env python3
"""The pin-reading functions the daily pin audit loads (pin-audit.py): how a pin is read, and how a version is looked up at its source.

Used as a module only. The pull-request scan that was its command line is deleted (REQ-REL-014-AC2); a moved version is no longer judged on a pull request.
"""
import hashlib
import http.client
import importlib.util
import json
import os
import re
import subprocess
import urllib.parse
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inv = _load("pin-inventory")


is_pin = inv.is_pin


INSTALLER_TOOLS = {tool for inputs in inv.INSTALLER_INPUTS.values() for _, tool in inputs if tool}


def judge_item(item):
    """(ok, reason): a moved item passes only as a pin the scan can read."""
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or "$" in (item.path or "") \
        or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or "")):
        return False, (f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, "
                       "or an action not named by its commit")
    if item.kind == "tool" and item.name in INSTALLER_TOOLS and len(item.version.lstrip("v").split(".")) < 3:
        return False, (f"not a pin: {item.version!r} is a series, not an exact release "
                       "(the installer picks the newest patch)")
    if item.kind == "image" and _image_registry(item.name) not in ("ghcr.io", "docker.io") \
            and _publisher_entry(item.name) is None:
        return False, f"registry {_image_registry(item.name)} is not in image-publishers.json, so nothing vouches for the image"
    return True, f"{item.version!r} is a pin the scan can read"


# ---------- the server answers the advisory audit reads (pin-audit.py) ----------
class CouldNotLook(Exception):
    """The server could not be asked (rate limit, outage): the check cannot run. Never read as 'no proof', never a
    pass."""


GH_TIMEOUT = 120


def _gh_run(cmd, **kw):
    """subprocess.run for the gh and git calls here, with a timeout: a call that hangs is CouldNotLook (the run
    stops), never an answer."""
    try:
        return subprocess.run(cmd, **dict({"timeout": GH_TIMEOUT}, **kw))
    except subprocess.TimeoutExpired:
        raise CouldNotLook(f"{cmd[0]} {' '.join(map(str, cmd[1:3]))} did not answer in {GH_TIMEOUT}s")


def _gh_status(r):
    """The status gh reports: the token "(HTTP 404)" that ends the last line of its error text, else None. A URL or a
    body that mentions a token earlier in the text is not read."""
    lines = r.stderr.strip().splitlines()
    m = re.search(r"\(HTTP (\d{3})\)$", lines[-1].strip()) if lines else None
    return int(m.group(1)) if m else None


def _gh_failed(r):
    """True for a plain miss; raises when the failure is the service's, not the answer's."""
    if _gh_status(r) not in (404, 410, 422):
        raise CouldNotLook(f"GitHub API: {(r.stderr or r.stdout).strip()[:120]}")
    return True


def _shaped(value, need, what):
    """The one way to read a JSON object answer: `need` is ((key, type or tuple of types), ...), given by every caller
    (no default). An answer that is not an object,
    or lacks a needed key, or holds it as another type, is an answer we cannot read (CouldNotLook): never 'nothing
    there'. Keys a caller reads with .get are the
    optional ones; each of those is type-checked where it is used."""
    if not isinstance(value, dict):
        raise CouldNotLook(f"{what} is not a JSON object")
    for key, typ in need:
        types = typ if isinstance(typ, tuple) else (typ,)
        got = value.get(key)
        if key not in value or not isinstance(got, types) or (isinstance(got, bool) and bool not in types):
            raise CouldNotLook(f"{what} lacks {key!r} of the expected type")
    return value


def _dicts(value, what, need):
    """A list of JSON objects each holding every key of `need` (CouldNotLook otherwise): an element of another shape
    is an answer we cannot read."""
    if not isinstance(value, list):
        raise CouldNotLook(f"{what} is not a list of JSON objects")
    for x in value:
        _shaped(x, need, what)
    return value


def _gh_pages(path, rows):
    """Every page of a list endpoint (gh --paginate with --jq '.[]' prints one JSON object per line); every row must
    hold the keys of `rows`."""
    r = _gh_run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except ValueError:
        raise CouldNotLook(f"GitHub API {path.split('?')[0]} did not return JSON")
    return _dicts(got, f"GitHub API {path.split('?')[0]}", rows)


_GONE = object()        # strict mode: the server said 404 or 410, the one answer that means "not there"


def _fetch_json(url, timeout=30):
    """The raw decoded answer, or _GONE for a 404/410. A network error, a timeout, a 5xx or a body that is not JSON
    means we could not look (CouldNotLook).
    PRIVATE: its one caller is _http_dict, which shapes it before anyone else sees it (a test enforces the single
    caller)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return _GONE
        raise CouldNotLook(f"{urllib.parse.urlsplit(url).netloc} answered HTTP {e.code}")
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise CouldNotLook(f"{urllib.parse.urlsplit(url).netloc} could not be asked ({type(e).__name__})")


def _http_dict(url, need, timeout=30):
    """An endpoint that answers with a JSON object holding every key of `need` (no default: the caller says what it
    reads). None only when the server said 404/410;
    valid JSON of another shape, a JSON null or a missing key is an answer we cannot read (CouldNotLook), never 'nothing
    there'."""
    d = _fetch_json(url, timeout)
    if d is _GONE:
        return None
    return _shaped(d, need, urllib.parse.urlsplit(url).netloc + " answer")


TOOL_REPOS = {  # tool -> (github repo, tag prefix to try after the bare version)
    "trivy": "aquasecurity/trivy", "grype": "anchore/grype", "syft": "anchore/syft", "snyk": "snyk/cli",
        "osv": "google/osv-scanner",
    "scout": "docker/scout-cli", "golangci-lint": "golangci/golangci-lint", "python": "actions/python-versions",
    "buildx": "docker/buildx", "goreleaser": "goreleaser/goreleaser", "cosign": "sigstore/cosign",
        "kind": "kubernetes-sigs/kind", "helm": "helm/helm", "node": "nodejs/node",
}


_TAGS = {}


def _tag_refs(repo):
    """{tag: commit} for EVERY tag of a public repository, annotated tags peeled, from ONE `git ls-remote` (no REST call
    per tag: a repository with hundreds
    of annotated tags would otherwise exhaust the shared API budget)."""
    if repo not in _TAGS:
        try:
            r = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"], capture_output=True,
                text=True, timeout=180)
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


def _go_escape(path):
    """The Go module proxy's case encoding: each upper-case letter is written "!" and its lower-case form."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


_MODINFO = (("Version", str),)      # a module info answer holds its version


def _go_module(path, version):
    parts = path.split("/")
    for n in range(len(parts), 0, -1):
        mod = "/".join(parts[:n])
        url = (f"https://proxy.golang.org/{urllib.parse.quote(_go_escape(mod), safe='/!')}"
               f"/@v/{urllib.parse.quote(version)}.info")
        info = _http_dict(url, _MODINFO)
        if info is None:
            continue      # not there: try the shorter module path
        if not info["Version"]:
            # a 200 we cannot read is not "module not found", in either mode
            raise CouldNotLook("proxy.golang.org answered with something that is not a module info object")
        return mod, info
    return None, None


HUB_HOSTS = ("docker.io", "index.docker.io", "registry-1.docker.io")


def _split_image(name):
    """(registry, path) of an image name. A first part with a dot, a colon or localhost is the registry, lowercase,
    without :443, Docker Hub's hosts as docker.io; else Docker Hub (a name of three parts without a host has no
    registry we know, so its first part stands)."""
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host = first.lower().removesuffix(":443")
        return ("docker.io" if host in HUB_HOSTS else host), rest
    return ("docker.io" if name.count("/") <= 1 else first), name


def _image_registry(name):
    return _split_image(name)[0]


def _json_file(path):
    """The JSON in a local file (OSError or ValueError if it cannot be read)."""
    with open(path) as f:
        return json.load(f)


POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "policy")
PUBLISHER_PINS_FILE = os.path.join(POLICY_DIR, "image-publishers.json")     # pinned by hand, never discovered


PIN_FIELDS = ("key", "keyless", "unsigned", "source", "key_source")


def _is_identity(i):
    return isinstance(i, dict) and all(isinstance(i.get(k), str) and i[k] for k in ("issuer", "subject"))


def _checked_pins(pins):
    """The publisher entries of the pins file (names starting with _ are notes). ValueError unless each entry has a key
    or
    keyless identities and every field it has is well formed."""
    entries = {k: v for k, v in pins.items() if not k.startswith("_")} if isinstance(pins, dict) else None
    if not entries:
        raise ValueError("image-publishers.json pins no image")
    for name, pin in entries.items():
        if not isinstance(pin, dict) or not ({"key", "keyless", "unsigned"} & set(pin)) or set(pin) - set(PIN_FIELDS):
            raise ValueError(f"image-publishers.json: {name} has no key, keyless identity or unsigned reason, "
                             "or a field that is not known")
        if "unsigned" in pin and ({"key", "keyless"} & set(pin) or not (isinstance(pin["unsigned"], str)
                                                                         and pin["unsigned"].strip())):
            raise ValueError(f"image-publishers.json: {name} has an unsigned that is not text, or beside a key")
        if "key" in pin and not (isinstance(pin["key"], str) and pin["key"].strip()):
            raise ValueError(f"image-publishers.json: {name} has a key that is not text")
        for note in ("source", "key_source"):
            if note in pin and not (isinstance(pin[note], str) and pin[note].strip()):
                raise ValueError(f"image-publishers.json: {name} has a {note} that is not text")
        idents = pin.get("keyless", [])
        if "keyless" in pin and not (isinstance(idents, list) and idents and all(_is_identity(i) for i in idents)):
            raise ValueError(f"image-publishers.json: {name} has keyless identities that are not a list of "
                             "issuer and subject")
    return entries


def _publisher_entry(name, pins=None):
    """The image-publishers.json entry for an image, named by its registry and path; None when it is not enrolled."""
    try:
        pins = pins or _checked_pins(_json_file(PUBLISHER_PINS_FILE))
    except (OSError, ValueError) as e:
        raise RuntimeError(f"cannot read image-publishers.json: {e}")
    host, path = _split_image(name)
    return pins.get(f"{host}/{path}")






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
    """{key: {whole-line hash: head occurrences}} for every (key, whole line) the head has MORE of than the base: an
    occurrence is identified by its key
    AND the whole line it sits in, so an edited line that keeps its download segment is an addition, like a new one
    (REQ-SUP-001-AC16)."""
    b, h = _occurrences(root, base), _occurrences(root, head)
    added = {}
    for k, per in h.items():
        for lh, n in per.items():
            if n > b.get(k, {}).get(lh, 0):
                added.setdefault(k, {})[lh] = n
    return added




# REQ-SUP-001-AC16: the advisor's rulings on lines that only MENTION a download tool (a comment, an echo string, a stub
# written as data). They are read from
# the exceptions file beside the checkout this script runs from: in CI that is trusted/ (the base branch), never the
# pull request's tree (--root).
DEFAULT_EXCEPTIONS = os.path.normpath(os.path.join(HERE, "..", "..", "supply-chain-exceptions.json"))
_RULED_FIELDS = ("file", "form", "key", "line", "ruling")
TEXT_RULING = "text, not a command: "      # the convention: a line that only MENTIONS a download tool
_LINE_TEXT = {}                              # whole-line hash -> the flattened line, filled by _occurrences














WHOLE_FILE = float("inf")      # the count of a reviewed_files ruling: the whole file is reviewed, no count


def _rule_of(rows, reviewed, file, form, segment, line_hash):
    """(ruling, count) of the ruling that rules this unmeasured occurrence, or None: its own unmeasured_text row, else
    the file's reviewed_files row (no count: the whole file is reviewed)."""
    row = rows.get((file, form, segment, line_hash))
    if row:
        return row
    ruling = reviewed.get(file)
    if line_hash.startswith("unruled:") or not ruling:      # a line bash reads differently from the flattening is never ruled
        return None
    return ruling, WHOLE_FILE


MAX_RULED_COUNT = 100


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a JSON object repeats a key ({sorted(k for k in set(keys) if keys.count(k) > 1)})")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (Python's reader accepts NaN, Infinity and -Infinity; "
                     "this file must not hold them)")


CONTEXTS = ("assignment",)


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


UNPINNED_FORM = "an unpinned package install"
LOCAL_CALL_FORM = "a local reusable workflow call"


def drop_ruled_unpinned(items, ruled_lines):
    """REQ-SUP-001-AC20: an unpinned package item leaves the list only when the script line that made it (its own path
    and line id) is a ruled occurrence."""
    return [m for m in items
        if not (m.kind == "package" and m.version == "(unpinned)" and m.src and tuple(m.src) in ruled_lines)]


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


_DEF_FUNC = re.compile(r"^[ \t]*(?:function[ \t]+([A-Za-z_][\w.-]*)|([A-Za-z_][\w.-]*)[ \t]*\([ \t]*\))", re.M)


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


def _row_for(rulings, root, head, k, lh):
    """The base branch's row for the line when its context (if any) holds in the head, else None: a row with a context that does not hold rules nothing."""
    r = rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh))
    return r if r is not None and _context_proved(root, head, k[0], lh, r) else None


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
