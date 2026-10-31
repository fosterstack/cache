"""bin/check-guide-plan.py GUIDE CANNOT_RUN_LIST DIGEST PLAN DIGEST_FIPS: the planner of bin/check-guide.sh (REQ-CHAIN-006-AC7). Reads the customer guide and its cannot-run
list, judges every command, substitutes the candidate's values and writes one plan row per command, in order, to PLAN; any fault exits 1."""
import json, os, re, shlex, sys
guide, listpath, digest, planpath, digest_fips = sys.argv[1:6]
def fail(m):
    print("check-guide: " + m, file=sys.stderr); sys.exit(1)
lines = open(guide).read().replace("\r", "").split("\n")
PH = re.compile(r"<([A-Z][A-Z0-9_]*)>")
DEF = re.compile(r"^\s*[-*]\s+`?<([A-Z][A-Z0-9_]*)>`?\s*:")
first = next((i for i, l in enumerate(lines) if l.strip().startswith("```")), len(lines))
defined = set()
for l in lines[:first]:
    m = DEF.match(l)
    if m:
        if m.group(1) in defined:
            fail("the placeholder <%s> is defined twice" % m.group(1))
        defined.add(m.group(1))
cmds, state, pending = [], None, None
for l in lines:
    s = l.strip()
    if state is None:
        if s == "```sh":
            state = "sh"
        elif s.startswith("```"):
            state = "other"
        continue
    if s == "```":
        if pending is not None:
            fail("a command ends in a line continuation")
        state = None
        continue
    if state == "other":
        continue
    if pending is not None:
        s, pending = pending + " " + s, None
    elif not s or s.startswith("#"):
        continue
    if s.endswith("\\"):
        pending = s[:-1].rstrip()
        continue
    cmds.append(s)
if state is not None:
    fail("the guide ends inside a fenced block")
if not cmds:
    fail("no command was extracted from the guide %s (a vacuous pass is not a pass)" % guide)
if len(cmds) > 10:
    fail("the guide has %d commands; at most ten are allowed" % len(cmds))

FORMS2 = ("cosign verify", "cosign verify-attestation", "cosign verify-blob", "cosign verify-blob-attestation")
# the forms as tuples of words: a command word that holds a space ("cosign verify") is one word and is not a form
FORM_WORDS2 = tuple(tuple(f.split()) for f in FORMS2)
# the only flags a listed verify carries; any other (--rekor-url, --trusted-root, --insecure-ignore-tlog, ...) changes
# which log or trust
# root the default check reads, or skips it
ALLOWED_FLAGS = ("--key", "--bundle", "--type", "--check-claims")
# The flags of the verify forms that take a value (an unknown flag is taken as taking none, so its next word is judged as an operand:
# the safe direction, a command the check cannot place is not run).
VALUE_FLAGS = {"--certificate-identity", "--certificate-identity-regexp", "--certificate-oidc-issuer", "--certificate-oidc-issuer-regexp",
               "--type", "--key", "--bundle", "--signature", "--certificate", "--certificate-chain", "--trusted-root", "--output", "-o",
               "--owner", "--repo", "-R", "--predicate-type", "--signer-workflow", "--signer-repo", "--cert-identity",
               "--cert-identity-regex", "--cert-oidc-issuer", "--source-ref", "--source-digest", "--digest-alg", "--format", "--jq", "-q",
               "--template", "-t", "--hostname", "--custom-trusted-root", "--signer-digest", "--cert", "--sig", "--rekor-url"}
# The value of these flags names a file the command reads: a file operand unless it is a URL (a value with ://), so a command whose only file operand is
# such a value, not local to Check, is not runnable at Check (it may be listed; Release's post-publish verification runs it with the downloaded files).
FILE_FLAGS = {"--bundle", "--certificate", "--cert", "--signature", "--sig", "--key", "--certificate-chain"}
JQ_TWO = {"--arg", "--argjson", "--slurpfile", "--rawfile"}
LOCAL = {"TAG"}     # the placeholder Check fills with a local value
IMAGE = {"IMAGE_REF", "IMAGE_REF_FIPS"}


def image_ref(word):
    """An image reference: an image placeholder, oci://..., or a literal with a path and a tag or digest (no URL scheme)."""
    if any(p in IMAGE for p in PH.findall(word)) or word.startswith("oci://"):
        return True
    w = PH.sub("X", word)
    return "://" not in w and "/" in w and (":" in w or "@" in w)


def file_value(v, nonlocal_):
    """The value of a file-valued flag: a URL is not a file operand; anything else is a local-file operand (judged as the file it names in Check)."""
    if v and "://" not in v and not os.path.isfile(fill(v)):
        nonlocal_.append(v)


def split_pipes(c):
    """The pipe segments of a command: split on | outside single and double quotes only (a backslash escapes the next character outside single quotes);
    None when a quote is left open (the command cannot be placed)."""
    segs, cur, quote, i = [], "", None, 0
    while i < len(c):
        ch = c[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif quote == '"':
            if ch == "\\" and i + 1 < len(c):
                cur += ch; i += 1; ch = c[i]
            elif ch == '"':
                quote = None
        elif ch == "\\" and i + 1 < len(c):
            cur += ch; i += 1; ch = c[i]
        elif ch in "'\"":
            quote = ch
        elif ch == "|":
            segs.append(cur); cur = ""; i += 1
            continue
        cur += ch; i += 1
    if quote:
        return None
    segs.append(cur)
    return segs


def syntax_why(c):
    """Why the command has shell syntax no command of the guide may have (a backquote, an expansion, an unquoted brace, glob
    or tilde), or None. bash expands these after any check of the words, so they are judged on the text, before the
    cannot-run list is consulted."""
    if "`" in c:
        return "shell syntax: a backquote"
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
                return "shell syntax: an expansion ($) inside double quotes"
        elif ch in "'\"":
            quote = ch
        elif ch == "$":
            return "shell syntax: an expansion ($) outside single quotes"
        elif ch in "{}*?[]~":
            return "shell syntax: a brace, glob or tilde outside quotes: bash would expand it after this check"
        i += 1
    return None


def classify(c):
    """("run", "") | ("registry", why) | ("no", why) | ("syntax", why): the command runs, needs a registry, cannot run on a candidate, or has shell syntax no
    command of the guide may have (judged before the cannot-run list is consulted, so a listed command is never excused for its syntax)."""
    why = syntax_why(c)
    if why:
        return "syntax", why
    lx = shlex.shlex(PH.sub(lambda m: "PH_" + m.group(1), c), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        toks = [PH_BACK.sub(lambda m: "<%s>" % m.group(1), w) for w in lx]
    except ValueError as e:
        return "syntax", "shell syntax: unparseable (%s)" % e
    segs = [[]]
    for w in toks:
        if w == "|":
            segs.append([])
        elif w and all(ch in "();<>|&" for ch in w):
            return "syntax", "shell syntax other than a pipe: %s" % w
        else:
            segs[-1].append(w)
    registry, nonlocal_ = [], []
    for s in segs:
        if not s:
            return "syntax", "shell syntax: an empty pipe segment"
        if s[0] == "jq":
            words, i, filt = s[1:], 0, False
            while i < len(words):
                w = words[i]
                if w in JQ_TWO:
                    i += 3; continue
                if w.startswith("-"):
                    i += 1; continue
                if not filt:
                    filt = True
                elif not os.path.isfile(fill(w)):
                    nonlocal_.append(w)
                i += 1
            continue
        if tuple(s[:2]) in FORM_WORDS2:
            words = s[2:]
        else:
            return "no", "`%s` is not one of the verify forms or jq" % " ".join(s[:3])
        i = 0
        while i < len(words):
            w = words[i]
            if w.startswith("-"):
                flag, eq, val = w.partition("=")
                if eq:
                    if flag in FILE_FLAGS:
                        file_value(val, nonlocal_)
                    i += 1
                elif w in VALUE_FLAGS:
                    if w in FILE_FLAGS and i + 1 < len(words):
                        file_value(words[i + 1], nonlocal_)
                    i += 2
                else:
                    i += 1
                continue
            if image_ref(w):
                registry.append(w)
            elif not os.path.isfile(fill(w)):
                nonlocal_.append(w)
            i += 1
    if registry:
        return "registry", "it verifies the image reference %s" % ", ".join(registry)
    if nonlocal_:
        return "no", "its operand %s is not a local file" % ", ".join(nonlocal_)
    return "run", ""


def shell_segments(c):
    """The pipe segments of the command as shell words, a placeholder being a marker no file name can equal (so
    --insecure-ignore-tlo''g is the flag); [] when the command cannot be split (classify refuses it for its syntax)."""
    lx = shlex.shlex(PH.sub(lambda m: "\u2039%s\u203a" % m.group(1), c), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        words = list(lx)
    except ValueError:
        return []
    segs = [[]]
    for w in words:   # a pipe or any other shell operator starts a new segment (classify refuses the operators)
        segs.append([]) if w and all(ch in "();<>|&" for ch in w) else segs[-1].append(w)
    return segs


def key_error(c):
    """None when every verify segment of the command has exactly one key flag (--key X or --key=X) whose value is
    <RELEASE_KEY> and no flag outside ALLOWED_FLAGS; else why not."""
    for seg in shell_segments(c):
        if tuple(seg[:2]) not in FORM_WORDS2:   # jq, or a word verify_form and classify refuse by name
            continue
        keys = []
        for i, w in enumerate(seg):
            flag, eq, value = w.partition("=")
            if flag == "--key":
                keys.append(value if eq else (seg[i + 1] if i + 1 < len(seg) else ""))
        if len(keys) != 1:
            return "it needs exactly one key flag whose value is <RELEASE_KEY> (found %d)" % len(keys)
        if keys[0] != "\u2039RELEASE_KEY\u203a":
            return "its key flag names %r, not <RELEASE_KEY>" % keys[0]
        for w in seg:
            flag = w.partition("=")[0]
            if w.startswith("-") and flag not in ALLOWED_FLAGS:
                return "the flag %s is outside the closed set (--key, --bundle, --type, --check-claims)" % flag
    return None


excused = {}
if os.path.exists(listpath):
    try:
        rows = json.load(open(listpath))
    except ValueError as e:
        fail("the cannot-run list %s is not JSON: %s" % (listpath, e))
    if not isinstance(rows, list):
        fail("the cannot-run list %s is not a list" % listpath)
    for r in rows:
        if not (isinstance(r, dict) and set(r) == {"command", "reason"} and isinstance(r["command"], str) and isinstance(r["reason"], str)
                and r["command"].strip() and r["reason"].strip()):
            fail("a cannot-run entry must be exactly {command, reason}, both non-empty: %r" % (r,))
        if r["command"] in excused:
            fail("the cannot-run list names `%s` twice" % r["command"])
        excused[r["command"]] = r["reason"]
def verify_form(c):
    """Every pipe segment is a verify form or jq (what Release's post-publish step runs from this list)."""
    segs = split_pipes(c)
    if segs is None:
        return False
    for seg in segs:
        try:
            w = shlex.split(seg)
        except ValueError:
            return False
        if not (w[:1] == ["jq"] or tuple(w[:2]) in FORM_WORDS2):
            return False
    return True
for c in excused:
    if not verify_form(c):
        fail("the cannot-run entry `%s` is not a verify form (Release runs only the verify forms from this list)" % c)
    why = syntax_why(c)
    if why:
        fail("the cannot-run entry `%s` has %s: no command of the guide may, listed or not (Release runs the listed "
                "commands unattended)" % (c, why))
    why = key_error(c)
    if why:
        fail("the cannot-run entry `%s` is refused: %s (Release runs it with the verified key)" % (c, why))
    if c not in cmds:
        fail("the cannot-run entry `%s` is not in the guide (a stale list)" % c)

PH_BACK = re.compile(r"PH_([A-Z][A-Z0-9_]*)")
repo = os.environ.get("CANDIDATE_REPOSITORY", "")
values = {"IMAGE_REF": repo + "@" + digest if repo else "", "IMAGE_REF_FIPS": repo + "@" + digest_fips if repo else "",
          "TAG": os.environ.get("GITHUB_REF_NAME", "")}
SAFE = re.compile(r"^[A-Za-z0-9._:/@+-]+$")


def fill(word):
    """The word with the local placeholders filled (an operand is judged as the file it names in Check)."""
    return PH.sub(lambda m: values.get(m.group(1), m.group(0)) if m.group(1) in LOCAL else m.group(0), word)
plan = []
for c in cmds:
    for u in PH.findall(c):
        if u not in defined:
            fail("the command `%s` uses <%s>, which the guide does not define (undefined placeholder)" % (c, u))
    kind, why = classify(c)
    if kind == "syntax":
        fail("the command `%s` has %s: no command of the guide may, listed as not-run or not (Release runs the listed commands unattended)" % (c, why))
    for u in sorted(set(PH.findall(c))):
        if u == "RELEASE_KEY":     # Release fills it with the verified key; Check never holds it: only a listed command
            if c not in excused:
                fail("the command `%s` uses <RELEASE_KEY> and is not on the cannot-run list: Check never holds the "
                     "verified release key, so a runnable command may not name it" % c)
        elif u not in LOCAL and u not in IMAGE:
            fail("the command `%s` uses <%s>, a defined placeholder that neither Check nor Release can substitute (unsupported placeholder; "
                 "unsubstituted placeholder): listed as not-run or not, it is refused" % (c, u))
    if c in excused:
        if kind == "run":
            fail("the cannot-run entry `%s` is runnable: a runnable command is run, never excused" % c)
        plan.append({"command": c, "run": None, "reason": excused[c]})
        continue
    if kind == "registry":
        fail("unlisted command needs a registry: `%s` (%s); Check holds the candidate as a file, so it is never run: list it exactly, "
             "with its reason, in %s" % (c, why, listpath))
    if kind != "run":
        fail("the command `%s` is not runnable on a candidate (%s) and the cannot-run list does not name it" % (c, why))
    run = c
    for u in sorted(set(PH.findall(c))):
        if u not in values:
            fail("the command `%s` keeps <%s>: Check has no candidate value for it (unsubstituted placeholder)" % (c, u))
        v = values[u]
        if not v:
            if u == "IMAGE_REF":
                fail("Check has no registry reference for the candidate (CANDIDATE_REPOSITORY is not set): <IMAGE_REF> in `%s` cannot be substituted" % c)
            fail("Check has no value for <%s> in this run: `%s` cannot be substituted" % (u, c))
        if not SAFE.match(v):
            fail("the candidate value for <%s> is not a plain reference: %r" % (u, v))
        run = run.replace("<%s>" % u, v)
    if PH.search(run):
        fail("the command `%s` keeps a placeholder after substitution (unsubstituted placeholder)" % c)
    plan.append({"command": c, "run": run, "reason": None})
with open(planpath, "w") as f:
    for p in plan:
        f.write(json.dumps(p) + "\n")
