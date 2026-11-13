"""The one judge of a customer-guide command (REQ-CHAIN-006-AC7, REQ-CHAIN-007-AC20), imported by
bin/check-guide-plan.py (Check) and bin/release-postverify.py (Release), so both give a command the same verdict.

A command is a pipe of the cosign verify forms and jq. It is read as bash reads it, without a shell: shell syntax
that bash would expand or run after this check is refused, and so is an operator character that is quoted or
escaped (a splitter that does not read quotes would see a pipe where bash sees a word). A placeholder <X> is
read as the marker word of marker(); a verify form carries only --key release.rsa.pub, --bundle, --type and
--check-claims; a literal image reference is refused (only <IMAGE_REF> and <IMAGE_REF_FIPS> name an image,
so every run verifies the released digest, never a movable tag); a jq call is in a closed grammar."""
import re

PH = re.compile(r"<([A-Z][A-Z0-9_]*)>")
MARK = re.compile("‹([A-Z][A-Z0-9_]*)›")   # a placeholder as a word no file name can equal
IMAGE_MARKS = ("‹IMAGE_REF›", "‹IMAGE_REF_FIPS›")
FORMS = ("verify", "verify-attestation", "verify-blob", "verify-blob-attestation")
OPERATORS = "|;&<>()"
# jq is a closed grammar: no option, module, program file, glob or combined flag reads what nothing verified
JQ_FLAGS = ("-e", "-r", "-c", "-S", "--exit-status", "--raw-output", "--compact-output", "--sort-keys")
JQ_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")   # the name after --arg: ref yes; 1x and a-b no
JQ_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")   # provenance.bundle.json yes; ../x, a/b, *.json, $X, <TAG> no
JQ_KEYWORDS = {"if", "then", "elif", "else", "end", "and", "or", "as"}
JQ_BUILTINS = {
    "any", "all", "not", "select", "map", "length", "keys", "has", "contains", "startswith", "endswith", "ltrimstr",
    "rtrimstr", "split", "join", "tostring", "tonumber", "type", "fromjson", "tojson", "first", "last", "empty", "add",
    "unique", "sort", "min", "max", "test", "ascii_downcase", "ascii_upcase", "values", "nulls", "arrays", "objects",
    "strings", "numbers", "booleans", "to_entries", "from_entries", "with_entries", "paths", "flatten", "reverse",
    "index", "indices", "isvalid", "error", "ascii", "walk"}
JQ_FORMATS = {"@base64d", "@base64", "@json", "@text"}


def marker(c):
    """The command with each placeholder <X> replaced by its marker word."""
    return PH.sub(lambda m: "‹%s›" % m.group(1), c)


def split(c):
    """(segments, None): the words of each pipe segment as bash reads them, or (None, why) for shell syntax no guide
    command may have. Only an unquoted | ends a segment, so a word that holds an operator was quoted or escaped."""
    segs, cur, have, quote, i = [[]], "", False, None, 0
    while i < len(c):
        ch = c[i]
        nxt = c[i + 1] if i + 1 < len(c) else ""
        if quote == "'":
            if ch == "'":
                quote = None
            else:
                cur += ch
        elif quote == '"':
            if ch == '"':
                quote = None
            elif ch in "$`":
                return None, "an expansion (%s) inside double quotes" % ch
            elif ch == "\\" and nxt in ('"', "\\"):
                cur, i = cur + nxt, i + 1
            else:
                cur += ch
        elif ch in " \t" or ch == "|":
            if have:
                segs[-1].append(cur)
            cur, have = "", False
            if ch == "|":
                segs.append([])
        else:
            have = True
            if ch == "\\":
                if nxt == "" or nxt in "$`\n\r":
                    return None, "a backslash before %s" % (repr(nxt) if nxt else "the end")
                cur, i = cur + nxt, i + 1
            elif ch in "'\"":
                quote = ch
            elif ch in "$`":
                return None, "an expansion (%s) outside single quotes" % ch
            elif ch == "#":
                return None, "a # outside quotes (bash reads a comment there, shlex does not)"
            elif ch in "\n\r":
                return None, "a newline outside quotes (bash runs what follows as another command)"
            elif ch in ";&<>()":
                return None, "shell syntax other than a pipe: %s" % ch
            elif ch in "{}*?[]~":
                return None, "a brace, glob or tilde outside quotes: bash would expand it"
            else:
                cur += ch
        i += 1
    if quote:
        return None, "a quote left open"
    if have:
        segs[-1].append(cur)
    if not all(segs):
        return None, "an empty pipe segment"
    return segs, None


def literal_image(w):
    """True for a word that names an image or a registry by hand: only the two placeholders may. oci://x, a:b/c,
    c@sha256:d and ghcr.io/x are refused; a URL (a word with ://), a file name and a.json are not."""
    if w in IMAGE_MARKS:
        return False
    if w.startswith("oci://") or "@sha256:" in w:
        return True
    return "://" not in w and "/" in w and (":" in w or "@" in w or "." in w.partition("/")[0])


def read_verify(seg):
    """(flags, operands, why) of one verify segment: flags are the (--key|--bundle|--type, value) pairs, operands the
    other non-flag words; why is None or the first fault. --key, --bundle and --type take a value (=value, else the next
    word, which never starts with "-"); --check-claims alone means true, and =false is allowed only on
    verify-blob-attestation (it unties a signature from the digest)."""
    words, flags, operands, i = seg[2:], [], [], 0
    for w in seg:
        if any(ch in OPERATORS for ch in w):
            return flags, operands, "an operator character inside quotes or after a backslash: %r" % w
        if literal_image(w):
            return flags, operands, "it names an image by hand (%s); only <IMAGE_REF>, <IMAGE_REF_FIPS>" % w
    while i < len(words):
        flag, eq, value = words[i].partition("=")
        if not words[i].startswith("-"):
            operands.append(words[i])
            i += 1
        elif flag in ("--key", "--bundle", "--type"):
            if eq:
                i += 1
            elif i + 1 < len(words) and not words[i + 1].startswith("-"):
                value, i = words[i + 1], i + 2
            else:
                value, i = "", i + 1
            if value == "" or value.startswith("-"):
                return flags, operands, "the %sflag %s has no value" % ("key " if flag == "--key" else "", flag)
            flags.append((flag, value))
        elif flag == "--check-claims":
            if eq and value != "true" and not (value == "false" and seg[1] == "verify-blob-attestation"):
                return flags, operands, "--check-claims=%s: only =false on verify-blob-attestation, else =true" % value
            i += 1
        else:
            return flags, operands, "the flag %s is outside the set --key, --bundle, --type, --check-claims" % flag
    keys = [v for f, v in flags if f == "--key"]
    if keys != ["release.rsa.pub"]:
        return flags, operands, "it needs exactly one key flag whose value is release.rsa.pub (found %r)" % keys
    return flags, operands, None


def jq_filter_why(f, names):
    """None when the filter uses only keywords, allowed builtins, field names, declared variables and allowed formats;
    else why not. `names` are the --arg names; `EXPR as $x` adds x."""
    if "\\(" in f:
        return "a string interpolation"
    if MARK.search(f):
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
        elif re.match(r"[A-Za-z_]", ch):
            word = re.match(r"[A-Za-z_][A-Za-z0-9_]*", f[i:]).group(0)
            after_dot = f[:i].rstrip(" ").endswith(".")   # .name is a field of the input, not a call
            if not after_dot and word not in JQ_KEYWORDS | JQ_BUILTINS | {"true", "false", "null"}:
                return "the word %s" % word
            i += len(word)
        elif ch.isdigit() or ch in " .[]{}()|,;:+-*/%=<>!?":
            i += 1
        else:
            return "the character %r" % ch
    return None


def jq_words(words, may_name_files, files):
    """Why one jq call is outside the grammar [flags | --arg NAME VALUE]... 'filter' [FILE...], or None. File operands
    (plain names of release-published/) go to `files` and are allowed only when may_name_files."""
    i, names, filt = 0, set(), None
    while i < len(words):
        w = words[i]
        if filt is not None:
            if not may_name_files:
                return "a jq that follows another command names a file (%s)" % w
            if not JQ_FILE.fullmatch(w):
                return "the file operand %r is not a plain file name of release-published/" % w
            files.append(w)
            i += 1
        elif w in JQ_FLAGS:
            i += 1
        elif w == "--arg":
            if i + 2 >= len(words) or not JQ_NAME.fullmatch(words[i + 1]):
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


def guide_commands(lines):
    """(commands, why) of the guide's lines: a command is a line of a ```sh fenced block (a line ending in a backslash joins
    the next, a pipeline counts once); blank lines and # lines are skipped. why is None or the first fault."""
    cmds, state, pending = [], None, None
    for l in lines:
        s = l.strip()
        if state is None:
            state = "sh" if s == "```sh" else "other" if s.startswith("```") else None
            continue
        if s == "```":
            if pending is not None:
                return cmds, "the command `%s` is refused: it ends in a line continuation" % pending
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
    return cmds, "the guide ends inside a fenced block" if state is not None else None


def image_subject(segs):
    """True when a verify segment of a judged command verifies an image reference (<IMAGE_REF>, <IMAGE_REF_FIPS>):
    it needs a registry image. A jq over a file that only names the placeholder in --arg is a file command."""
    return any(w in IMAGE_MARKS for s in segs if s[0] != "jq" for w in read_verify(s)[1])


def judge(c):
    """(segments, files, why) for a command. segments: the words of each pipe segment, placeholders as markers. files:
    the file operands of a command made only of jq, else None. why: None, or why the command is refused."""
    segs, why = split(marker(c))
    if why:
        return None, None, why
    jq_only, files = all(s[0] == "jq" for s in segs), []
    for n, s in enumerate(segs):
        if s[0] == "jq":
            why = jq_words(s[1:], jq_only and n == 0, files)
        elif len(s) > 1 and s[0] == "cosign" and s[1] in FORMS:
            why = read_verify(s)[2]
        else:
            why = "`%s` is not one of the verify forms or jq" % " ".join(s[:3])
        if why:
            return None, None, why
    return segs, files if jq_only else None, None
