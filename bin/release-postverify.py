"""Release's post-publish verification (v0.3.0 rule 79 as amended by the owner, Oct 10; REQ-CHAIN-006-AC7).

Reads docs/verify-release.cannot-run.json (rows {command, reason}, the exact-text list Check also reads) and runs each command against
what was just published, in BOTH registries (ghcr.io/fosterstack/cache, then docker.io/fosterstack/cache; the same digests): a command naming
<IMAGE_REF> or <IMAGE_REF_FIPS> runs once per registry, with the image-production / image-fips digest of witness-build/digests.json
filled; any other command runs once. A command that names a repository literally is refused, <TAG> = $GITHUB_REF_NAME, <IDENTITY> = Sign's workflow identity at the tag. Every command is judged before
any runs (a refusal runs nothing): a pipe of the verify forms (cosign verify, verify-attestation, verify-blob, verify-blob-attestation,
gh attestation verify) and jq, with at least one verify form, no other shell syntax ($ only inside single quotes), and no placeholder left
unfilled. A command that fails fails the run (exit 1) after all have run. The step holds the job's GITHUB_TOKEN (the Release job's own contents/packages/id-token grant) and no registry credential.
Every command runs with release-published/ (the assets just downloaded from the published release) as its working directory, so the guide's bare
file names resolve as a customer's do (REQ-CHAIN-007-AC20). A command made only of jq is accepted only when every file it reads is named by an
EARLIER command of the same list that is a verify form, and at run time only after that verify exited 0."""
import json, os, re, shlex, subprocess, sys

LIST = "docs/verify-release.cannot-run.json"
ASSETS = "release-published"   # gh release download -D release-published (bin/release-assets.sh): the files a customer downloads
DIGESTS = "witness-build/digests.json"
REPOSITORIES = ("ghcr.io/fosterstack/cache", "docker.io/fosterstack/cache")   # constants: releases publish identical digests to both; no input names a repository
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")   # a release candidate publishes nothing, so there is nothing to verify (REQ-CHAIN-007-AC14)
PH = re.compile(r"<([A-Z][A-Z0-9_]*)>")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE = re.compile(r"^[A-Za-z0-9._:/@+-]+$")
FORMS = (("cosign", "verify"), ("cosign", "verify-attestation"), ("cosign", "verify-blob"), ("cosign", "verify-blob-attestation"),
         ("gh", "attestation", "verify"))


def refuse(msg):
    print("release-postverify: " + msg, file=sys.stderr)
    sys.exit(1)


def form_error(c, jq_only=False):
    """None when the command is a pipe of verify forms and jq with at least one verify form, else why not. With jq_only the command is a pure jq
    pipe (judged by jq_files after this): only the character-level refusals apply, because jq opens no network and no repository."""
    if "`" in c:
        return "a backquote"
    quote, i = None, 0
    while i < len(c):
        ch = c[i]
        if ch == "\\" and quote != "'":
            # a backslash outside single quotes makes the next character literal: it never opens or closes a quoted region (a $ stays refused)
            if i + 1 < len(c) and c[i + 1] != "$":
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
    lx = shlex.shlex(PH.sub(lambda m: "PH_" + m.group(1), c), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        toks = list(lx)
    except ValueError as e:
        return "unparseable: %s" % e
    segs, verify = [[]], False
    for w in toks:
        if w == "|":
            segs.append([])
        elif w and all(ch in "();<>|&" for ch in w):
            return "shell syntax other than a pipe: %s" % w
        else:
            segs[-1].append(w)
    for w in ([] if jq_only else toks):
        w = w[len("oci://"):] if w.startswith("oci://") else w
        if "://" not in w and (re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]+(:[0-9]+)?/", w) or "@sha256:" in w):
            return "it names a repository literally (%s); only the two constant repositories, through <IMAGE_REF> and <IMAGE_REF_FIPS>" % w
    for s in segs:
        if not s:
            return "an empty pipe segment"
        if s[0] == "jq":
            continue
        if any(tuple(s[:len(f)]) == f for f in FORMS):
            verify = True
        else:
            return "`%s` is not a verify form or jq" % " ".join(s[:3])
    return None if (verify or jq_only) else "no verify form in it"

# ---- jq-only commands (REQ-CHAIN-007-AC20): a CLOSED grammar, fail closed -----------------------------------------------------------
# A jq-only command is accepted only when it is spelled in this small grammar and every file it reads is a plain file name that an EARLIER
# verify form of the list named as a file operand (and, at run time, only after that verify exited 0). Whatever the grammar does not name is
# refused, so no option, module, program file, glob or combined flag can make jq read what nothing verified.
PHM = lambda m: "\u2039" + m.group(1) + "\u203a"   # a placeholder is a marker no plain file name can equal (never PH_X, which a file could be called)
JQ_FLAGS = ("-e", "-r", "-c", "-S", "--exit-status", "--raw-output", "--compact-output", "--sort-keys")   # each a separate word: no -er, no -L., no -f
JQ_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
JQ_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")   # a plain name in release-published/: no slash, glob, brace, tilde, $, space or placeholder
JQ_KEYWORDS = {"if", "then", "elif", "else", "end", "and", "or", "as"}
JQ_BUILTINS = {"any", "all", "not", "select", "map", "length", "keys", "has", "contains", "startswith", "endswith", "ltrimstr", "rtrimstr", "split",
               "join", "tostring", "tonumber", "type", "fromjson", "tojson", "first", "last", "empty", "add", "unique", "sort", "min", "max", "test",
               "ascii_downcase", "ascii_upcase", "values", "nulls", "arrays", "objects", "strings", "numbers", "booleans", "to_entries", "from_entries",
               "with_entries", "paths", "flatten", "reverse", "index", "indices", "isvalid", "error", "tostring", "ascii", "walk"}
JQ_FORMATS = {"@base64d", "@base64", "@json", "@text"}
VERIFY_VALUE_FLAGS = {"--certificate-identity", "--certificate-identity-regexp", "--certificate-oidc-issuer", "--certificate-oidc-issuer-regexp",
                      "--type", "--key", "--bundle", "--signature", "--certificate", "--certificate-chain", "--trusted-root", "--output", "-o",
                      "--owner", "--repo", "-R", "--predicate-type", "--signer-workflow", "--signer-repo", "--cert-identity", "--cert-identity-regex",
                      "--cert-oidc-issuer", "--source-ref", "--source-digest", "--digest-alg", "--format", "--jq", "-q", "--template", "-t",
                      "--hostname", "--custom-trusted-root", "--signer-digest", "--insecure-ignore-tlog", "--max-attempts"}
VERIFY_FILE_FLAGS = {"--bundle", "--signature", "--certificate", "--certificate-chain", "--trusted-root", "--custom-trusted-root"}


def jq_filter_why(f, names):
    """None when the filter uses only keywords, allowed builtins, field names, declared variables and allowed formats; else why not."""
    if "\\(" in f:
        return "a string interpolation"
    if re.search(r"<[A-Z][A-Z0-9_]*>", f):
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
            continue
        if ch == "#":
            return "a comment"
        if ch == "@":
            m = re.match(r"@[A-Za-z0-9_]+", f[i:])
            if not m or m.group(0) not in JQ_FORMATS:
                return "the format %s" % (m.group(0) if m else "@")
            i += len(m.group(0))
            continue
        if ch == "$":
            m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)", f[i:])
            if not m:
                return "the variable $"
            if re.search(r"\bas\s+$", f[:i]):          # `EXPR as $name` binds a name
                names = names | {m.group(1)}
            elif m.group(1) not in names or m.group(1) == "ENV":
                return "the variable %s (only an --arg name or a name bound by `as`)" % m.group(0)
            i += len(m.group(0))
            continue
        if ch.isalpha() or ch == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", f[i:])
            word = m.group(0)
            j = i - 1
            while j >= 0 and f[j] == " ":
                j -= 1
            field = j >= 0 and f[j] == "."          # .name is a field of the input, not a call
            if not field and word not in JQ_KEYWORDS and word not in JQ_BUILTINS and word not in ("true", "false", "null"):
                return "the word %s" % word
            i += len(word)
            continue
        if ch.isdigit() or ch in " .[]{}()|,;:+-*/%=<>!?":
            i += 1
            continue
        return "the character %r" % ch
    return None


def all_jq(c):
    """True when every pipe segment of the command is a jq call and nothing else (no ; < > & ( ))."""
    try:
        lx = shlex.shlex(PH.sub(PHM, c), posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return False
    segs, ok = [[]], True
    for w in toks:
        if w == "|":
            segs.append([])
        elif w and all(ch in "();<>|&" for ch in w):
            return False
        else:
            segs[-1].append(w)
    return bool(toks) and all(sg and sg[0] == "jq" for sg in segs)


def jq_files(c):
    """The files a command made ONLY of jq reads, or (None, why, None). Returns (files, None, argv segments). Grammar: jq [flags from JQ_FLAGS | --arg NAME VALUE]... 'filter' FILE...
    for the first segment; each later segment of a pipe is jq [flags] 'filter' with no file."""
    try:
        lx = shlex.shlex(PH.sub(PHM, c), posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError as e:
        return None, "unparseable: %s" % e, None
    segs = [[]]
    for w in toks:
        if w == "|":
            segs.append([])
        elif all(ch in "();<>|&" for ch in w):
            return None, "shell syntax other than a pipe: %s" % w, None
        else:
            segs[-1].append(w)
    files = []
    for n, seg in enumerate(segs):
        if not seg or seg[0] != "jq":
            return None, "not a jq-only command", None
        words, i, names, filt = seg[1:], 0, set(), None
        while i < len(words):
            w = words[i]
            if filt is None:
                if w in JQ_FLAGS:
                    i += 1
                elif w == "--arg":
                    if i + 2 >= len(words) or not JQ_NAME.match(words[i + 1]):
                        return None, "--arg needs a plain name and a value", None
                    names.add(words[i + 1])
                    i += 3
                elif w.startswith("-"):
                    return None, "the jq option %s is not in the closed set" % w, None
                else:
                    why = jq_filter_why(w, names)
                    if why:
                        return None, "the jq filter uses %s, which is not in the closed grammar" % why, None
                    filt = w
                    i += 1
            else:
                if n != 0:
                    return None, "a later jq of a pipe names a file (%s)" % w, None
                if not JQ_FILE.match(w):
                    return None, "the file operand %r is not a plain file name of release-published/" % w, None
                files.append(w)
                i += 1
        if filt is None:
            return None, "a jq with no filter", None
    if not files:
        return None, "it reads no file (stdin is not a verified input)", None
    return files, None, segs


def verify_files(c):
    """The files an (already judged) verify-form command names as file operands: the value of a file flag and every positional word of a
    verify segment. The value of any other flag (an identity, an issuer, a type) never counts, and the word after an unknown flag is taken
    as its value (so it never licenses a file)."""
    out = set()
    try:
        lx = shlex.shlex(PH.sub(PHM, c), posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return out
    seg = []
    for w in toks + ["|"]:
        if w != "|":
            seg.append(w)
            continue
        f = next((k for k in FORMS if tuple(seg[:len(k)]) == k), None)
        if f:
            words, i = seg[len(f):], 0
            while i < len(words):
                w2 = words[i]
                if w2.startswith("-"):
                    flag, eq, val = w2.partition("=")
                    if eq:
                        if flag in VERIFY_FILE_FLAGS:
                            out.add(val)
                        i += 1
                    else:
                        if flag in VERIFY_FILE_FLAGS and i + 1 < len(words):
                            out.add(words[i + 1])
                        i += 2 if i + 1 < len(words) else 1
                else:
                    out.add(w2)
                    i += 1
        seg = []
    return out


def run_jq(run):
    """Runs a judged jq-only command WITHOUT a shell: the validated words are the argv, so no expansion (brace, glob, tilde, variable) can add an
    option or a file after the check. Every jq of a pipe must exit 0 (pipefail)."""
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
    rcs = [p.wait() for p in procs]
    return 0 if all(r == 0 for r in rcs) else next(r for r in rcs if r != 0)


def main():
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if not TAG.match(tag):
        refuse("refused at tag: %r is not vX.Y.Z" % tag)
    if not os.path.exists(LIST):
        refuse("the list %s is missing: the post-publish verification has nothing to run (a missing list is a failed release)" % LIST)
    try:
        rows = json.load(open(LIST))
    except ValueError as e:
        refuse("the list %s is not JSON: %s" % (LIST, e))
    if not isinstance(rows, list):
        refuse("the list %s is not a list" % LIST)
    cmds = []
    for r in rows:
        if not (isinstance(r, dict) and set(r) == {"command", "reason"} and isinstance(r["command"], str) and isinstance(r["reason"], str)
                and r["command"].strip() and r["reason"].strip()):
            refuse("a row of %s must be exactly {command, reason}, both non-empty: %r" % (LIST, r))
        if r["command"] in cmds:
            refuse("%s lists `%s` twice" % (LIST, r["command"]))
        cmds.append(r["command"])
    try:
        digests = json.load(open(DIGESTS))
    except (OSError, ValueError) as e:
        refuse("the digest list %s cannot be read: %s" % (DIGESTS, e))
    for key in ("image-production", "image-fips"):
        d = digests.get(key) if isinstance(digests, dict) else None
        if not (isinstance(d, str) and DIGEST.match(d)):
            refuse("the digest list %s has no valid %s digest (sha256:<64 lowercase hex>): nothing is run" % (DIGESTS, key))
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    base = {"TAG": tag}
    if repo:
        base["IDENTITY"] = "https://github.com/%s/.github/workflows/stage-sign.yml@refs/tags/%s" % (repo, tag)
    plan = []   # (registry, command, filled command): one pass per registry, in order
    for reg in REPOSITORIES:
        values = dict(base, IMAGE_REF="%s@%s" % (reg, digests["image-production"]), IMAGE_REF_FIPS="%s@%s" % (reg, digests["image-fips"]))
        verified = []   # (index, words) of the verify forms before the current command
        for ci, c in enumerate(cmds):
            jq_need = None
            if all_jq(c):
                why = form_error(c, jq_only=True)
                if why:
                    refuse("`%s` is not an allowed verify form (%s)" % (c, why))
                files, jwhy, _ = jq_files(c)
                if files is None:
                    refuse("`%s` is not an allowed verify form (a jq-only command needs an earlier verify of its file: %s)" % (c, jwhy))
                for f in files:
                    if not any(f in names for _, names in verified):
                        refuse("`%s` is not an allowed verify form (no verify form in it): no earlier command of the list is a verify form that names %s" % (c, f))
                jq_need = files
            else:
                why = form_error(c)
                if why:
                    refuse("`%s` is not an allowed verify form (%s)" % (c, why))
                verified.append((ci, verify_files(c)))
            used = set(PH.findall(c))
            if reg != REPOSITORIES[0] and not used & {"IMAGE_REF", "IMAGE_REF_FIPS"}:
                continue   # no image placeholder: the same command, run once
            run = c
            for u in sorted(used):
                if u not in values:
                    refuse("`%s` uses <%s>, which the post-publish step cannot fill (unsubstituted placeholder)" % (c, u))
                if not SAFE.match(values[u]):
                    refuse("the value for <%s> is not a plain reference: %r" % (u, values[u]))
                run = run.replace("<%s>" % u, values[u])
            plan.append((reg, c, run, jq_need))
    if not os.path.isdir(ASSETS):
        refuse("%s/ is not a directory: the assets of the published release are not here, so no listed command can resolve its files; nothing is run" % ASSETS)
    failed = []
    passed_words = set()   # the words of every verify form that has exited 0 so far (a jq-only command may read only these files)
    for reg, c, run, jq_need in plan:
        if jq_need is not None and not all(f in passed_words for f in jq_need):
            failed.append((reg, c, 1))
            print("::error::post-publish verification failed against %s: `%s` was not run: the earlier verify of %s did not pass" % (reg, c, ", ".join(jq_need)), file=sys.stderr, flush=True)
            continue
        print("release-postverify: [%s] $ %s" % (reg, run), flush=True)
        if jq_need is not None:
            rc = run_jq(run)
        else:
            rc = subprocess.run(["bash", "-o", "pipefail", "-c", run], stdin=subprocess.DEVNULL, cwd=ASSETS).returncode
        if rc != 0:
            failed.append((reg, c, rc))
            print("::error::post-publish verification failed against %s: `%s` exited %d" % (reg, c, rc), file=sys.stderr, flush=True)
        elif jq_need is None:
            passed_words |= verify_files(c)
    if failed:
        refuse("post-publish verification failed: %d of %d runs failed: %s" % (len(failed), len(plan), "; ".join("[%s] `%s` exited %d" % f for f in failed)))
    print("release-postverify: all %d post-publish verification runs passed (%d commands, %d registries)" % (len(plan), len(cmds), len(REPOSITORIES)))


main()
