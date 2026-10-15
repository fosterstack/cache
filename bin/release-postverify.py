"""Release's post-publish verification (v0.3.0 rule 79 as amended by the owner, Oct 10; REQ-CHAIN-006-AC7).

Reads docs/verify-release.cannot-run.json (rows {command, reason}, the exact-text list Check also reads) and runs each command against
what was just published, in BOTH registries (ghcr.io/fosterstack/cache, then docker.io/fosterstack/cache; the same digests): a command naming
<IMAGE_REF> or <IMAGE_REF_FIPS> runs once per registry, with the image-production / image-fips digest of witness-build/digests.json
filled; any other command runs once. A command that names a repository literally is refused, <TAG> = $GITHUB_REF_NAME, <IDENTITY> = Sign's workflow identity at the tag. Every command is judged before
any runs (a refusal runs nothing): a pipe of the verify forms (cosign verify, verify-attestation, verify-blob, verify-blob-attestation,
gh attestation verify) and jq, with at least one verify form, no other shell syntax ($ only inside single quotes), and no placeholder left
unfilled. A command that fails fails the run (exit 1) after all have run. The step holds a read token and no registry credential.
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


def form_error(c):
    """None when the command is a pipe of verify forms and jq with at least one verify form, else why not."""
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
    for w in toks:
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
    return None if verify else "no verify form in it"

JQ_VALUE_FLAGS = ("--arg", "--argjson")      # name and value (neither is a file)
JQ_REFUSED = ("--slurpfile", "--rawfile", "--args", "--jsonargs", "-f", "--from-file", "-L", "--library-path", "--seq", "--stream-errors")


def jq_files(c):
    """The files a command made ONLY of jq reads, or (None, why). Every segment's first non-flag word is the filter; the rest of the FIRST
    segment are files (the later segments read the pipe: a file operand there is refused). A jq that reads another file, loads a program or has
    no file operand is refused: it would read stdin or something nothing verified."""
    lx = shlex.shlex(PH.sub(lambda m: "PH_" + m.group(1), c), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    segs = [[]]
    for w in lx:
        if w == "|":
            segs.append([])
        else:
            segs[-1].append(w)
    files = []
    for n, seg in enumerate(segs):
        if not seg or seg[0] != "jq":
            return None, "not a jq-only command"
        words, i, filt = seg[1:], 0, False
        while i < len(words):
            w = words[i]
            if w in JQ_REFUSED:
                return None, "the jq option %s reads other files or loads a program" % w
            if w in JQ_VALUE_FLAGS:
                i += 3
                continue
            if w.startswith("-") and len(w) > 1:
                i += 1
                continue
            if not filt:
                filt = True
            elif n == 0:
                files.append(w)
            else:
                return None, "a later jq of a pipe names a file (%s)" % w
            i += 1
        if not filt:
            return None, "a jq with no filter"
    if not files:
        return None, "it reads no file (stdin is not a verified input)"
    return files, None


def verify_words(c):
    """The words of a command that is a verify form (placeholders as written): the names it can have verified."""
    try:
        return set(shlex.split(c))
    except ValueError:
        return set()


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
            why = form_error(c)
            jq_need = None
            if why == "no verify form in it":
                files, jwhy = jq_files(c)
                if files is None:
                    refuse("`%s` is not an allowed verify form (%s; a jq-only command needs an earlier verify of its file: %s)" % (c, why, jwhy))
                for f in files:
                    if not any(f in words for _, words in verified):
                        refuse("`%s` is not an allowed verify form (%s): no earlier command of the list is a verify form that names %s" % (c, why, f))
                jq_need = files
                why = None
            if why:
                refuse("`%s` is not an allowed verify form (%s)" % (c, why))
            if jq_need is None:
                verified.append((ci, verify_words(c)))
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
    if plan and not os.path.isdir(ASSETS):
        refuse("%s/ is not a directory: the assets of the published release are not here, so no listed command can resolve its files; nothing is run" % ASSETS)
    failed = []
    passed_words = set()   # the words of every verify form that has exited 0 so far (a jq-only command may read only these files)
    for reg, c, run, jq_need in plan:
        if jq_need is not None and not all(f in passed_words for f in jq_need):
            failed.append((reg, c, 1))
            print("::error::post-publish verification failed against %s: `%s` was not run: the earlier verify of %s did not pass" % (reg, c, ", ".join(jq_need)), file=sys.stderr, flush=True)
            continue
        print("release-postverify: [%s] $ %s" % (reg, run), flush=True)
        rc = subprocess.run(["bash", "-o", "pipefail", "-c", run], stdin=subprocess.DEVNULL, cwd=ASSETS).returncode
        if rc != 0:
            failed.append((reg, c, rc))
            print("::error::post-publish verification failed against %s: `%s` exited %d" % (reg, c, rc), file=sys.stderr, flush=True)
        elif jq_need is None:
            passed_words |= verify_words(c)
    if failed:
        refuse("post-publish verification failed: %d of %d runs failed: %s" % (len(failed), len(plan), "; ".join("[%s] `%s` exited %d" % f for f in failed)))
    print("release-postverify: all %d post-publish verification runs passed (%d commands, %d registries)" % (len(plan), len(cmds), len(REPOSITORIES)))


main()
