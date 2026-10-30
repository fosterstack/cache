"""Release's post-publish verification (v0.3.0 rule 79 as amended by the owner, Oct 10; REQ-CHAIN-006-AC7).

Reads docs/verify-release.cannot-run.json (rows {command, reason}, the exact-text list Check also reads) and runs
each command against what was just published, in BOTH registries (ghcr.io/fosterstack/cache, then
docker.io/fosterstack/cache; the same digests). A command naming <IMAGE_REF> or <IMAGE_REF_FIPS> runs once per
registry, with the image-production / image-fips digest of witness-build/digests.json filled in; any other command
runs once. A command that names a repository literally is refused, <TAG> = $GITHUB_REF_NAME, <IDENTITY> = Sign's
workflow identity at the tag.

Every command is judged before any runs (a refusal runs nothing): a pipe of the verify forms (cosign verify,
verify-attestation, verify-blob, verify-blob-attestation, gh attestation verify) and jq, with at least one verify
form, no other shell syntax ($ only inside single quotes), and no placeholder left unfilled. A command that fails
fails the run (exit 1) after all have run. The step holds the job's GITHUB_TOKEN (the Release job's own
contents/packages/id-token grant) and no registry credential.

Every command runs with release-published/ (the assets just downloaded from the published release) as its working
directory, so the guide's bare file names resolve as a customer's do (REQ-CHAIN-007-AC20). A command made only of jq is
accepted only when every file it reads is named by an EARLIER command of the same list that is a verify form, and at run
time only after that verify exited 0.
"""
import json, os, re, shlex, subprocess, sys

LIST = "docs/verify-release.cannot-run.json"
ASSETS = "release-published"   # gh release download -D release-published: the files a customer downloads
DIGESTS = "witness-build/digests.json"
# Constants: releases publish identical digests to both, and no input names a repository.
REPOSITORIES = ("ghcr.io/fosterstack/cache", "docker.io/fosterstack/cache")
# v0.3.0 yes, v0.3.0-rc1 no: a release candidate publishes nothing to verify
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
PH = re.compile(r"<([A-Z][A-Z0-9_]*)>")   # <TAG> yes, <tag> no
# sha256: and 64 lowercase hex digits yes; sha256:abc and an upper-case digest no
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
# a filled placeholder is one plain word: ghcr.io/fosterstack/cache@sha256:ab12 yes; "a b" and "$(id)" no
SAFE = re.compile(r"^[A-Za-z0-9._:/@+-]+$")
HOST = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]+(:[0-9]+)?/")   # ghcr.io/x yes, x/y no: a registry host written out
FORMS = (("cosign", "verify"), ("cosign", "verify-attestation"), ("cosign", "verify-blob"),
         ("cosign", "verify-blob-attestation"), ("gh", "attestation", "verify"))
SYNTAX = "();<>|&"   # a shell word made only of these is an operator; "|" alone is the one we allow


def refuse(msg):
    print("release-postverify: " + msg, file=sys.stderr)
    sys.exit(1)


def PHM(m):
    """A placeholder as a marker no plain file name can equal (never PH_X, which a file could be called)."""
    return "‹" + m.group(1) + "›"


def words_of(c, mark):
    """The shell words of a command with each placeholder replaced by mark(match); ValueError if it cannot be split."""
    lexer = shlex.shlex(PH.sub(mark, c), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def operator_in(words, empty_counts):
    """The first word that is shell syntax other than a pipe, or None. An empty word ('') counts only when
    empty_counts: all() of nothing is true, which jq_files keeps as a refusal."""
    return next((w for w in words if w != "|" and (w or empty_counts) and all(ch in SYNTAX for ch in w)), None)


def split_pipe(words):
    """The words as one list per pipe segment."""
    segs = [[]]
    for w in words:
        if w == "|":
            segs.append([])
        else:
            segs[-1].append(w)
    return segs


def quote_error(c):
    """Why bash would run something else than the words we judge (a backquote, an expansion, a comment, a newline),
    or None. We walk the quotes ourselves because shlex does not know bash's expansions."""
    if "`" in c:
        return "a backquote"
    quote, i = None, 0
    while i < len(c):
        ch = c[i]
        # A backslash outside single quotes turns the next character into a literal: it never opens or closes a quote.
        if ch == "\\" and quote != "'" and i + 1 < len(c) and c[i + 1] != "$":
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
            elif ch == "$" and quote == '"':
                return "an expansion ($) inside double quotes"
        elif ch in "'\"":
            quote = ch
        elif ch == "$":
            return "an expansion ($) outside single quotes"
        elif ch == "#":
            return "a # outside quotes (a shell comment would hide what follows from this check and not from bash)"
        elif ch in "\n\r":
            return "a newline outside quotes (bash runs what follows as another command)"
        i += 1
    return None


def literal_repository(words):
    """The first word that names a registry by hand, or None; only <IMAGE_REF> and <IMAGE_REF_FIPS> may name one."""
    for w in words:
        w = w[len("oci://"):] if w.startswith("oci://") else w
        if "://" not in w and (HOST.match(w) or "@sha256:" in w):
            return w
    return None


def form_error(c, jq_only=False):
    """None when the command is a pipe of verify forms and jq with at least one verify form, else why not.
    With jq_only the command is a pure jq pipe (judged by jq_files after this): only the character-level refusals
    apply, because jq opens no network and no repository."""
    why = quote_error(c)
    if why:
        return why
    try:
        words = words_of(c, lambda m: "PH_" + m.group(1))
    except ValueError as e:
        return "unparseable: %s" % e
    op = operator_in(words, empty_counts=False)
    if op is not None:
        return "shell syntax other than a pipe: %s" % op
    repo = None if jq_only else literal_repository(words)
    if repo is not None:
        return ("it names a repository literally (%s); only the two constant repositories, "
                "through <IMAGE_REF> and <IMAGE_REF_FIPS>" % repo)
    verify = False
    for seg in split_pipe(words):
        if not seg:
            return "an empty pipe segment"
        if seg[0] == "jq":
            continue
        if not any(tuple(seg[:len(f)]) == f for f in FORMS):
            return "`%s` is not a verify form or jq" % " ".join(seg[:3])
        verify = True
    return None if (verify or jq_only) else "no verify form in it"


# ---- jq-only commands (REQ-CHAIN-007-AC20): a CLOSED grammar, fail closed -----------------------------------------
# A jq-only command is accepted only when it is spelled in this small grammar and every file it reads is a plain file
# name that an EARLIER verify form of the list named as a file operand (and, at run time, only after that verify exited
# 0). Whatever the grammar does not name is refused, so no option, module, program file, glob or combined flag can
# get jq to read what nothing verified.
JQ_FLAGS = ("-e", "-r", "-c", "-S", "--exit-status", "--raw-output", "--compact-output", "--sort-keys")   # whole words
# the name after --arg: ref yes; 1x and a-b no
JQ_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
JQ_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")   # provenance.bundle.json yes; ../x, a/b, *.json, $X, <TAG> no
# the jq word at the start of the text: "fromjson | .a" gives fromjson; ".a" and "1x" give none
JQ_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
JQ_KEYWORDS = {"if", "then", "elif", "else", "end", "and", "or", "as"}
JQ_BUILTINS = {
    "any", "all", "not", "select", "map", "length", "keys", "has", "contains", "startswith", "endswith", "ltrimstr",
    "rtrimstr", "split", "join", "tostring", "tonumber", "type", "fromjson", "tojson", "first", "last", "empty", "add",
    "unique", "sort", "min", "max", "test", "ascii_downcase", "ascii_upcase", "values", "nulls", "arrays", "objects",
    "strings", "numbers", "booleans", "to_entries", "from_entries", "with_entries", "paths", "flatten", "reverse",
    "index", "indices", "isvalid", "error", "ascii", "walk"}
JQ_FORMATS = {"@base64d", "@base64", "@json", "@text"}
# The flags of the verify forms whose value is a file. The value of any other flag (an identity, an issuer, a type)
# never counts as a file the command verified.
FILE_FLAGS = {"--bundle", "--signature", "--certificate", "--certificate-chain", "--trusted-root",
              "--custom-trusted-root"}


def jq_filter_why(f, names):
    """None when the filter uses only keywords, allowed builtins, field names, declared variables and allowed formats;
    else why not. `names` are the --arg names; `EXPR as $x` adds x."""
    if "\\(" in f:
        return "a string interpolation"
    if PH.search(f):
        return "a placeholder inside the filter"
    i, n = 0, len(f)
    while i < n:
        ch = f[i]
        if ch == '"':
            i += 1
            while i < n and f[i] != '"':
                i += 2 if f[i] == "\\" else 1
            if i >= n:
                return "an unterminated string"
            i += 1
        elif ch == "#":
            return "a comment"
        elif ch == "@":
            m = re.match(r"@[A-Za-z0-9_]+", f[i:])   # "@base64d | x" gives @base64d; "@ x" gives none
            if not m or m.group(0) not in JQ_FORMATS:
                return "the format %s" % (m.group(0) if m else "@")
            i += len(m.group(0))
        elif ch == "$":
            m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", f[i:])   # "$ref == 1" gives ref; "$1" and "$ " give none
            if not m:
                return "the variable $"
            if re.search(r"\bas\s+$", f[:i]):   # text before the $ ends in "as ": ".a as $x" yes; ".a | $x" no
                names = names | {m.group(1)}
            elif m.group(1) not in names or m.group(1) == "ENV":
                return "the variable %s (only an --arg name or a name bound by `as`)" % m.group(0)
            i += len(m.group(0))
        elif JQ_WORD.match(f[i:]):
            word = JQ_WORD.match(f[i:]).group(0)
            after_dot = f[:i].rstrip(" ").endswith(".")   # .name is a field of the input, not a call
            if not after_dot and word not in JQ_KEYWORDS | JQ_BUILTINS | {"true", "false", "null"}:
                return "the word %s" % word
            i += len(word)
        elif ch.isdigit() or ch in " .[]{}()|,;:+-*/%=<>!?":
            i += 1
        else:
            return "the character %r" % ch
    return None


def all_jq(c):
    """True when every pipe segment of the command is a jq call and nothing else (no semicolon, redirect, background
    job or subshell)."""
    try:
        words = words_of(c, PHM)
    except ValueError:
        return False
    if operator_in(words, empty_counts=False) is not None:
        return False
    return bool(words) and all(seg and seg[0] == "jq" for seg in split_pipe(words))


def jq_words(words, first, files):
    """Reads the words of one jq call: [flags | --arg NAME VALUE]... 'filter' [FILE...]. Only the first call of a pipe
    may name files (appended to `files`). Returns why not, or None."""
    i, names, filt = 0, set(), None
    while i < len(words):
        w = words[i]
        if filt is not None:
            if not first:
                return "a later jq of a pipe names a file (%s)" % w
            if not JQ_FILE.match(w):
                return "the file operand %r is not a plain file name of release-published/" % w
            files.append(w)
            i += 1
        elif w in JQ_FLAGS:
            i += 1
        elif w == "--arg":
            if i + 2 >= len(words) or not JQ_NAME.match(words[i + 1]):
                return "--arg needs a plain name and a value"
            names.add(words[i + 1])
            i += 3
        elif w.startswith("-"):
            return "the jq option %s is not in the closed set" % w
        else:
            why = jq_filter_why(w, names)
            if why:
                return "the jq filter uses %s, which is not in the closed grammar" % why
            filt = w
            i += 1
    return None if filt is not None else "a jq with no filter"


def jq_files(c):
    """(files, None, argv per segment) for a command made ONLY of jq in the closed grammar, else (None, why, None).
    `files` are the files the first jq reads."""
    try:
        words = words_of(c, PHM)
    except ValueError as e:
        return None, "unparseable: %s" % e, None
    op = operator_in(words, empty_counts=True)
    if op is not None:
        return None, "shell syntax other than a pipe: %s" % op, None
    segs, files = split_pipe(words), []
    for n, seg in enumerate(segs):
        if not seg or seg[0] != "jq":
            return None, "not a jq-only command", None
        why = jq_words(seg[1:], n == 0, files)
        if why:
            return None, why, None
    if not files:
        return None, "it reads no file (stdin is not a verified input)", None
    return files, None, segs


def file_operands(words):
    """The files named by the words after a verify form: the value of a file flag and every positional word. The word
    after an unknown flag is taken as its value, so it never licenses a file."""
    out, i = set(), 0
    while i < len(words):
        w = words[i]
        if not w.startswith("-"):
            out.add(w)
            i += 1
            continue
        flag, equals, value = w.partition("=")
        if equals:
            if flag in FILE_FLAGS:
                out.add(value)
            i += 1
            continue
        has_next = i + 1 < len(words)
        if flag in FILE_FLAGS and has_next:
            out.add(words[i + 1])
        i += 2 if has_next else 1
    return out


def verify_files(c):
    """The files an (already judged) command names as operands of its verify forms."""
    try:
        words = words_of(c, PHM)
    except ValueError:
        return set()
    out = set()
    for seg in split_pipe(words):
        form = next((f for f in FORMS if tuple(seg[:len(f)]) == f), None)
        if form:
            out |= file_operands(seg[len(form):])
    return out


def run_jq(run):
    """Runs a judged jq-only command WITHOUT a shell: the validated words are the argv, so no expansion (brace, glob,
    tilde, variable) can add an option or a file after the check. Every jq of a pipe must exit 0 (pipefail)."""
    files, why, segs = jq_files(run)
    if files is None:
        print("release-postverify: %s" % why, file=sys.stderr)
        return 1
    procs, prev = [], subprocess.DEVNULL
    for n, argv in enumerate(segs):
        last = n == len(segs) - 1
        p = subprocess.Popen(argv, stdin=prev, stdout=None if last else subprocess.PIPE, cwd=ASSETS)
        if prev is not subprocess.DEVNULL:
            prev.close()
        prev = p.stdout
        procs.append(p)
    codes = [p.wait() for p in procs]
    return next((rc for rc in codes if rc != 0), 0)


def read_commands():
    """The commands of the list, each once, from rows of exactly {command, reason}."""
    if not os.path.exists(LIST):
        refuse("the list %s is missing: the post-publish verification has nothing to run "
               "(a missing list is a failed release)" % LIST)
    try:
        with open(LIST) as f:
            rows = json.load(f)
    except ValueError as e:
        refuse("the list %s is not JSON: %s" % (LIST, e))
    if not isinstance(rows, list):
        refuse("the list %s is not a list" % LIST)
    cmds = []
    for r in rows:
        whole = (isinstance(r, dict) and set(r) == {"command", "reason"}
                 and all(isinstance(r[k], str) and r[k].strip() for k in r))
        if not whole:
            refuse("a row of %s must be exactly {command, reason}, both non-empty: %r" % (LIST, r))
        if r["command"] in cmds:
            refuse("%s lists `%s` twice" % (LIST, r["command"]))
        cmds.append(r["command"])
    return cmds


def read_digests():
    try:
        with open(DIGESTS) as f:
            digests = json.load(f)
    except (OSError, ValueError) as e:
        refuse("the digest list %s cannot be read: %s" % (DIGESTS, e))
    for key in ("image-production", "image-fips"):
        d = digests.get(key) if isinstance(digests, dict) else None
        if not (isinstance(d, str) and DIGEST.match(d)):
            refuse("the digest list %s has no valid %s digest (sha256:<64 lowercase hex>): nothing is run"
                   % (DIGESTS, key))
    return digests


def judge(c, verified):
    """Refuses the command unless it is an allowed verify form; returns the files a jq-only command reads (else None).
    `verified` are the file sets of the verify forms before it in the list."""
    if all_jq(c):
        why = form_error(c, jq_only=True)
        if why:
            refuse("`%s` is not an allowed verify form (%s)" % (c, why))
        files, why, _ = jq_files(c)
        if files is None:
            refuse("`%s` is not an allowed verify form (a jq-only command needs an earlier verify of its file: %s)"
                   % (c, why))
        for f in files:
            if not any(f in names for names in verified):
                refuse("`%s` is not an allowed verify form (no verify form in it): "
                       "no earlier command of the list is a verify form that names %s" % (c, f))
        return files
    why = form_error(c)
    if why:
        refuse("`%s` is not an allowed verify form (%s)" % (c, why))
    verified.append(verify_files(c))
    return None


KEYFILE = "release-key.verified.pub"   # written only by a step that checked the key manifest against the root key


def verified_key():
    """The absolute path of the verified release public key file; a refusal when there is none. Never a key
    reference, never a private key, never a file of the repository: nothing on this base writes KEYFILE yet."""
    if os.path.islink(KEYFILE) or not os.path.isfile(KEYFILE):
        refuse("<RELEASE_KEY> needs the verified release key file %s, and there is none" % KEYFILE)
    text = open(KEYFILE, errors="replace").read()
    pem = text.startswith("-----BEGIN PUBLIC KEY-----\n") and text.rstrip().endswith("-----END PUBLIC KEY-----")
    if not (pem and len(text) < 2000 and "PRIVATE" not in text and "awskms" not in text):
        refuse("%s is not one PEM public key" % KEYFILE)
    return os.path.abspath(KEYFILE)


def fill(c, values):
    """The command with every placeholder replaced; a placeholder with no value, or a value that is not one plain
    word, is refused."""
    run = c
    for u in sorted(set(PH.findall(c))):
        if u not in values:
            refuse("`%s` uses <%s>, which the post-publish step cannot fill (unsubstituted placeholder)" % (c, u))
        if not SAFE.match(values[u]):
            refuse("the value for <%s> is not a plain reference: %r" % (u, values[u]))
        run = run.replace("<%s>" % u, values[u])
    return run


def make_plan(cmds, digests, tag):
    """[(registry, command, filled command, files a jq-only command reads)]: one pass per registry, in order."""
    base = {"TAG": tag}
    if any("<RELEASE_KEY>" in c for c in cmds):
        base["RELEASE_KEY"] = verified_key()
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if repo:
        base["IDENTITY"] = "https://github.com/%s/.github/workflows/stage-sign.yml@refs/tags/%s" % (repo, tag)
    plan = []
    for reg in REPOSITORIES:
        values = dict(base, IMAGE_REF="%s@%s" % (reg, digests["image-production"]),
                      IMAGE_REF_FIPS="%s@%s" % (reg, digests["image-fips"]))
        verified = []
        for c in cmds:
            files = judge(c, verified)
            has_image = set(PH.findall(c)) & {"IMAGE_REF", "IMAGE_REF_FIPS"}
            if reg != REPOSITORIES[0] and not has_image:
                continue   # no image placeholder: the same command, run once
            plan.append((reg, c, fill(c, values), files))
    return plan


def run_plan(plan):
    """Runs the plan; returns [(registry, command, exit code)] of the runs that failed."""
    failed = []
    passed = set()   # files named by the verify forms that have exited 0 so far: a jq-only command may read only these
    for reg, c, run, files in plan:
        if files is not None and not all(f in passed for f in files):
            failed.append((reg, c, 1))
            print("::error::post-publish verification failed against %s: `%s` was not run: "
                  "the earlier verify of %s did not pass" % (reg, c, ", ".join(files)), file=sys.stderr, flush=True)
            continue
        print("release-postverify: [%s] $ %s" % (reg, run), flush=True)
        if files is not None:
            rc = run_jq(run)
        else:
            rc = subprocess.run(["bash", "-o", "pipefail", "-c", run], stdin=subprocess.DEVNULL, cwd=ASSETS).returncode
        if rc != 0:
            failed.append((reg, c, rc))
            print("::error::post-publish verification failed against %s: `%s` exited %d" % (reg, c, rc),
                  file=sys.stderr, flush=True)
        elif files is None:
            passed |= verify_files(c)
    return failed


def main():
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if not TAG.match(tag):
        refuse("refused at tag: %r is not vX.Y.Z" % tag)
    cmds = read_commands()
    plan = make_plan(cmds, read_digests(), tag)
    if not os.path.isdir(ASSETS):
        refuse("%s/ is not a directory: the assets of the published release are not here, so no listed command can "
               "resolve its files; nothing is run" % ASSETS)
    failed = run_plan(plan)
    if failed:
        refuse("post-publish verification failed: %d of %d runs failed: %s"
               % (len(failed), len(plan), "; ".join("[%s] `%s` exited %d" % f for f in failed)))
    print("release-postverify: all %d post-publish verification runs passed (%d commands, %d registries)"
          % (len(plan), len(cmds), len(REPOSITORIES)))


main()
