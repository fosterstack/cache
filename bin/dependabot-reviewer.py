#!/usr/bin/env python3
"""Dependabot reviewer (register row 75).

Three dependency lanes: the auditor opens CVE bumps (cron), Dependabot opens "latest" bumps,
and THIS reviewer judges every pull request Dependabot opens into main, whatever its update
kind (patch, minor, major, flagged), so no human has to. It runs hourly from main
(dependabot-reviewer.yml), never on a PR event: Dependabot-triggered runs hold no repository
secrets, so the federation identity is only reachable from a scheduled run on main.

Subcommands (each one is small and testable on its own; the workflow strings them together):

  updates  --title T --body-file F           -> JSON list of {name, from, to, major, flagged, kind}; kind is major,
                                                 flagged, not-major or unparsed
  gather   --pr N --sha SHA --updates F --out DIR
                                              -> DIR/bundle.md (commits + the whole diff of SHA against main
                                                 + release notes + our usage)
  same-diff --repo R --base B SHA SHA         -> exit 0 only when both commits change B by the same diff text
  read     --bundle F --prompt F --model-env NAME --out F
                                              -> one reader's ranked findings (JSON)
  decide   --reader F [--reader F ...] --out F
                                              -> {"decision": "merge"|"hold"|"error", ...}

The DECISION is mechanical (row 75 d): zero `breaks-us` findings from every reader => merge;
any `breaks-us` => hold; a reader that failed or answered unparseably => error (no check is
posted; the next hourly run retries). Readers return RANKED FINDINGS, never a verdict
(row 51). No vendor or model name appears in any output (row 48): model ids are masked.
"""
import argparse, html, json, os, re, subprocess, sys
from html.parser import HTMLParser

SEVERITIES = ("breaks-us", "check", "noise")
# The reader's whole budget: any reasoning it does before answering counts against it too. 2048
# cut every answer of one reader mid-JSON and left the other's answer empty (first live run,
# 36640316796). The call streams, so no per-model non-streaming ceiling (8192 for some model
# families in the pinned SDK) can reject it; get_final_message() returns the same Message.
MAX_TOKENS = 16000
_FINDING_KEYS = {"severity", "title", "release_note", "our_line", "why"}
# The diff is never cut: the readers get every character of what the pull request changes, or (over CAP_DIFF) no
# bundle and no verdict. Release notes and usage are cut at their caps, and the bundle says so where it happens.
CAP_DIFF, CAP_NOTES, CAP_USAGE = 200000, 60000, 20000

_SECRET_ENVS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
                "AUDITOR_MODEL_PRIMARY", "AUDITOR_MODEL_FALLBACK", "AUDITOR_APP_PRIVATE_KEY")


def mask(s):
    """Redact identifiers/model ids from anything that could reach a public surface."""
    s = str(s or "")
    # an escaped identifier (\\uXXXX, e.g. inside a JSON answer kept as a string) is decoded first
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    for k in _SECRET_ENVS:
        v = os.environ.get(k)
        if v and len(v) >= 4:
            s = re.sub(re.escape(v), "<%s>" % k, s, flags=re.IGNORECASE)  # in any letter case
    s = re.sub(r"claude-[A-Za-z0-9._-]+", "<model-id>", s)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]{6,}", "Bearer <redacted>", s)
    # a reader naming itself or its maker (row 48): no vendor or model name on a public surface
    s = re.sub(r"(?i)\b(?:anthropic|claude|openai|chatgpt|gpt-?[0-9][A-Za-z0-9.-]*|gemini|opus|sonnet|haiku)\b",
               "<model>", s)
    return s


def mask_tree(root):
    """Mask every file of the evidence directory in place, right before it is uploaded (owner, Oct 1):
    the bundle the readers read unmasked becomes, like every other evidence file, free of identifiers."""
    for d, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p):
                continue
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            masked = mask(text)
            if f.endswith(".json"):  # decode first: a \\u-escaped identifier is masked too
                try:
                    masked = json.dumps(_mask_json(json.loads(text)), indent=1, ensure_ascii=False)
                except ValueError:
                    pass
            if masked != text:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(masked)


def _mask_json(v):
    if isinstance(v, str):
        return mask(v)
    if isinstance(v, list):
        return [_mask_json(x) for x in v]
    if isinstance(v, dict):
        return {mask(k): _mask_json(x) for k, x in v.items()}
    return v


def cmd_mask_tree(a):
    mask_tree(a.dir)
    print("evidence masked: %s" % a.dir)


# ----------------------------------------------------------------------------- updates

_VER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_BUMPS = re.compile(r"(?:[Bb]umps?|[Uu]pdates)\s+\[?`?([A-Za-z0-9._/@-]+)`?\]?(?:\([^)]*\))?\s+from\s+`?([^\s`]+)`?\s+to\s+`?([^\s`.]+(?:\.[^\s`.]+)*?)`?\.?(?:\s|$)")


_DIGEST = re.compile(r"^(?:sha256:)?[0-9a-f]{7,64}$")


def _major(v):
    """The major of a version string; None for a digest or anything that is not a version.
    A docker digest such as `3f3c01a` starts with digits but is not a version."""
    v = str(v).strip()
    if _DIGEST.match(v) and not re.fullmatch(r"\d+", v):
        return None
    m = _VER.match(v)
    return int(m.group(1)) if m else None


def is_major(old, new):
    """True when both look like versions and the major differs. Digests (`abc123`) and
    anything unparseable are NOT majors: they stay on the patch/minor lane, which is what
    Dependabot's own metadata action does for docker digest bumps."""
    a, b = _major(old), _major(new)
    return a is not None and b is not None and a != b


_DETAILS = re.compile(r"<details(?:\s[^>]*)?>(?:(?!<details[\s>]).)*?</details\s*>", re.S | re.I)


def dependabot_summary(body):
    """The body without its <details> blocks. Dependabot writes its own "Bumps X from A to B" /
    "Updates `X` from A to B" lines OUTSIDE them; inside are the upstream release notes and
    commit lists, which quote upstream's own bumps (actions/checkout's notes name
    docker/login-action 3->4) and must never be read as updates of this PR."""
    s, prev = str(body or ""), None
    while prev != s:                      # innermost first, so nested blocks go too
        prev, s = s, _DETAILS.sub("", s)
    return s


_FLAG = re.compile(r"breaking|deprecat", re.I)
_MDADJ = re.compile(r"[A-Za-z0-9]\[|\][A-Za-z0-9]|\]\([^\n]*\)[A-Za-z0-9]|\]\[[^\]\n]*\][A-Za-z0-9]")
_MDEXOTIC = re.compile(r"\\[\[\]]|\]\(\s*<|&(?:#0*(?:91|93)|#x0*(?:5b|5d)|lbrack|rbrack|lsqb|rsqb);", re.I)
_MDLINK = re.compile(r"\]\(|\]\[|\]:")
_CHARREF = re.compile(r"&(?:#|[A-Za-z][A-Za-z0-9]*;)")
_MDLABEL = re.compile(r"\]\[[^\]]*\]")
_MDDEF = re.compile(r"(?m)^ {0,3}\[[^\]\n]+\]:.*$")


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def _drop_targets(v, quotes):
    # Markdown inline link/image targets `](...)`, parentheses balanced, over lines; quotes=True also honours a quoted title that holds a ')'.
    # An unterminated target is unresolvable: None.
    out, i, n = [], 0, len(v)
    while i < n:
        if v.startswith("](", i):
            j, depth, inq = i + 2, 1, None
            while j < n and depth > 0:
                c = v[j]
                if c == "\\":
                    j += 2
                    continue
                if quotes and inq is None and c in "\"'" and v[j - 1] in " \t\n":
                    inq = c
                elif quotes and inq == c:
                    inq = None
                elif inq is None:
                    depth += 1 if c == "(" else -1 if c == ")" else 0
                j += 1
            if depth > 0:
                return None
            i = j
            continue
        out.append(v[i])
        i += 1
    return "".join(out)


def is_flagged(body):
    """True when a Dependabot PR body says "breaking" or "deprecat" (any case) as a reader would see it. The release notes and commit
    list between old and new are the body's <details> blocks, but markup makes block boundaries unreliable, so the WHOLE body is read and any
    hit counts: over-flagging only sends a bump to the two readers, never toward auto-merge (tighten-only). Views, any one of which counts:
    the raw body; with character references decoded; the HTML-rendered text (tags and comments dropped, nothing put in their place); and for
    each of those the letters and digits only, also with Markdown link targets (balanced parentheses, with and without a quoted title),
    reference labels and reference definitions removed first, so formatting, links and references between a word's pieces vanish. A body
    the parser cannot read, an unterminated link target, a word character touching link syntax, an escaped or encoded bracket, an <angle> destination,
    any character reference in a body that has link syntax, or link syntax left over after every reduction is flagged (fail toward the readers: the class is closed, not enumerated).
    A non-major so flagged is judged like a major (REQ-DEP-001-AC10)."""
    raw = str(body or "")
    try:
        p = _Text()
        p.feed(raw)
        p.close()
        views = (raw, html.unescape(raw), "".join(p.parts))
        if _MDADJ.search(raw) or _MDEXOTIC.search(raw):   # link syntax this check does not resolve: an escaped bracket, an <angle> destination, an encoded bracket
            return True
        if _MDLINK.search(raw) and _CHARREF.search(raw):   # a character reference (numeric in any spelling, or named with ';'; a URL's &key=value is not one) in a body that has
            return True                                    # link syntax can spell a bracket or parenthesis of the destination: not resolved here, the readers decide
        more = []
        for v in views:
            more.append(v)
            for q in (False, True):
                t = _drop_targets(v, q)
                if t is None:
                    return True
                t = _MDDEF.sub("", _MDLABEL.sub("", t))
                if "](" in t or "][" in t:   # link syntax that survives every reduction is unresolved
                    return True
                more.append(t)
        views += tuple(re.sub(r"[^A-Za-z0-9]", "", v) for v in more)
        return any(_FLAG.search(v) for v in views + tuple(more))
    except Exception:
        return True


def parse_updates(title, body):
    """Every (name, from, to) Dependabot names in the PR body's own summary ("Bumps X from A
    to B." or, for a group, one "Updates `X` from A to B" line per member), falling back to
    the title."""
    found, seen = [], set()
    flagged = is_flagged(body)
    for src in (dependabot_summary(body), title or ""):
        for m in _BUMPS.finditer(src):
            name, old, new = m.group(1), m.group(2), m.group(3).rstrip(".")
            key = (name, old, new)
            if key in seen:
                continue
            seen.add(key)
            major = is_major(old, new)
            found.append({"name": name, "from": old, "to": new, "major": major,
                          "flagged": flagged and not major,
                          "kind": "major" if major else "flagged" if flagged else "not-major"})
        if found:
            break
    if not found:
        # The update lines cannot be read (markup, an odd title): the pull request is still read. One placeholder
        # so the readers judge the diff; it names no repository, so no notes are fetched.
        found.append({"name": "(unparsed Dependabot update)", "from": "?", "to": "?", "major": False,
                      "flagged": flagged, "kind": "unparsed"})
    return found


def cmd_updates(a):
    body = open(a.body_file).read() if a.body_file else ""
    json.dump(parse_updates(a.title, body), sys.stdout)


# ----------------------------------------------------------------------------- gather

def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return (p.stdout if p.returncode == 0 else ""), p.returncode


def _gh_json(args):
    out, rc = _run(["gh", "api"] + args)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _vertuple(v):
    """The components a version actually states: `4` -> (4,), `4.2` -> (4, 2), `v7.0.1` -> (7, 0, 1)."""
    m = _VER.match(str(v).strip())
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


def in_range(t, old, new):
    """Is release `t` after `old` and at most `new`, comparing only the components each bound
    states? A floating major pin `4` means every 4.x (so 4.x releases are NOT after it) and `7`
    means every 7.x (so 7.0.1 IS within it)."""
    if not t or not old or not new:
        return False
    return t[:len(old)] > old and t[:len(new)] <= new


def _upstream_repo(name):
    """The GitHub repo that publishes release notes for a dependency, or None.
    github-actions: `actions/checkout`, `github/codeql-action/init` -> owner/repo (first two
    segments). gomod: `github.com/x/y/v2` -> x/y. Anything else: no notes available."""
    parts = name.split("/")
    if name.startswith("github.com/") and len(parts) >= 3:
        return "%s/%s" % (parts[1], parts[2])
    if "." not in parts[0] and len(parts) >= 2:
        return "%s/%s" % (parts[0], parts[1])
    return None


MAX_RELEASE_PAGES = 20


def release_notes(name, old, new):
    """(text, count): upstream release notes for every release after `old` and up to `new`
    (in_range), oldest first; a plain statement and count 0 when none exist (never a guess); a
    failed read is UNAVAILABLE with count None — an error, never "none found"."""
    repo = _upstream_repo(name)
    if not repo:
        return "(no upstream release notes available for %s: not a GitHub-hosted dependency)\n" % name, 0
    lo, hi = _vertuple(old), _vertuple(new)
    rels, complete = [], False
    for page in range(1, MAX_RELEASE_PAGES + 1):
        chunk = _gh_json(["repos/%s/releases?per_page=100&page=%d" % (repo, page)])
        if chunk is None:  # the read failed: never mistaken for "none found" (owner, Oct 1)
            return ("(release notes UNAVAILABLE for %s: the GitHub API read of %s failed; this bundle "
                    "cannot be judged)\n" % (name, repo)), None
        rels.extend(chunk)
        # every page, to the end: release branches interleave (a backport can appear before a newer
        # in-range release), so nothing short of the last page proves the range was read
        if len(chunk) < 100:
            complete = True
            break
    if not complete:
        return ("(release notes UNAVAILABLE for %s: more than %d pages of releases on %s and the old version "
                "%s was not reached; this bundle cannot be judged)\n" % (name, MAX_RELEASE_PAGES, repo, old)), None
    picked = []
    for r in rels:
        t = _vertuple(r.get("tag_name", ""))
        if in_range(t, lo, hi):
            picked.append((t, r))
    if not picked:
        return ("(no upstream release notes found for %s between %s and %s on %s; "
                "the reader must say so and judge from the diff and our usage only)\n" % (name, old, new, repo)), 0
    picked.sort(key=lambda x: x[0])
    out = []
    for _t, r in picked:
        out.append("### %s — %s\n\n%s\n" % (r.get("tag_name"), r.get("name") or "", (r.get("body") or "").strip()))
    text = "\n".join(out)
    if len(text) > CAP_NOTES:
        text = text[:CAP_NOTES] + "\n[... release notes truncated at %d characters ...]\n" % CAP_NOTES
    return text, len(picked)


def step_context(lines, i):
    """(start, end) of the YAML list item (a workflow step) holding line i: up to the `- ` that
    opens it, down to the next line at or left of that indent. Lets the reader see a step's
    `with:` inputs (fetch-depth, persist-credentials, ...), not just its `uses:` line."""
    def indent(l):
        return len(l) - len(l.lstrip(" "))
    start = i
    while start > 0 and not lines[start].lstrip().startswith("- "):
        start -= 1
    if not lines[start].lstrip().startswith("- "):
        return i, i
    dash = indent(lines[start])
    end = i
    while end + 1 < len(lines) and (not lines[end + 1].strip() or indent(lines[end + 1]) > dash):
        end += 1
    while end > i and not lines[end].strip():
        end -= 1
    return start, end


def usage_blocks(hits, read_file):
    """git-grep hits ("path:line:text") -> text with each workflow hit expanded to its whole
    step (numbered), each other hit as is; overlapping steps printed once."""
    out, seen = [], set()
    for h in hits:
        path, _, rest = h.partition(":")
        ln, _, text = rest.partition(":")
        if not ln.isdigit():
            continue
        i = int(ln) - 1
        if path.startswith(".github/") and path.endswith((".yml", ".yaml")):
            lines = read_file(path)
            a, b = step_context(lines, i) if 0 <= i < len(lines) else (i, i)
            if (path, a) in seen:
                continue
            seen.add((path, a))
            out.append("\n".join("%s:%d: %s" % (path, k + 1, lines[k]) for k in range(a, b + 1)))
        else:
            out.append(h)
    return "\n".join(out) + ("\n" if out else "")


USAGE_UNAVAILABLE = "(usage UNAVAILABLE for %s: the repository search failed (rc %s); this bundle cannot be judged)\n"


def our_usage(name):
    """Every line of ours that names the dependency (workflows, go.mod, Dockerfiles, scripts);
    a workflow hit comes with its whole step, inputs included."""
    short = name.split("/")
    out, rc = _run(["git", "grep", "-n", "-I", "--", name])
    if rc not in (0, 1):  # git grep: 1 is "no match"; anything else is a failed search, never "none"
        return USAGE_UNAVAILABLE % (name, rc)
    if not out and len(short) >= 2 and "." not in short[0]:
        out, rc = _run(["git", "grep", "-n", "-I", "--", "%s/%s" % (short[0], short[1])])
        if rc not in (0, 1):
            return USAGE_UNAVAILABLE % (name, rc)
    if not out:
        return "(no line in this repository names %s)\n" % name
    try:
        text = usage_blocks(out.splitlines(), lambda p: open(p, encoding="utf-8", errors="replace").read().splitlines())
    except OSError as e:  # a hit whose file cannot be read: unavailable, never a partial "this is all"
        return USAGE_UNAVAILABLE % (name, type(e).__name__)
    if len(text) > CAP_USAGE:
        text = text[:CAP_USAGE] + "\n[... usage truncated at %d characters ...]\n" % CAP_USAGE
    return text


# the author GitHub reports on a commit Dependabot made; GitHub commits and signs it (web-flow)
DEPENDABOT = ("dependabot[bot]", 49699333, "Bot")
MAX_COMMIT_PAGES = 3                                  # GitHub lists at most 250 commits of a pull request


def head_diff(repo, base, sha):
    """(text, rc): GitHub's diff of the commit `sha` against its merge base with `base`: what that exact commit changes,
    whatever the pull request's head is by now."""
    return _run(["gh", "api", "-H", "Accept: application/vnd.github.diff",
                 "repos/%s/compare/%s...%s" % (repo, base, sha)])


def pr_commits(pr, sha):
    """(text, state): one line per commit of the pull request, oldest first, each one GitHub does not report as
    Dependabot's own marked; state is "ok", "unavailable" (a failed or empty read, or 250 commits: GitHub lists no
    more) or "moved" (the list does not end at `sha`, the commit the verdict is for)."""
    repo = os.environ.get("GITHUB_REPOSITORY") or "{owner}/{repo}"
    commits = []
    for page in range(1, MAX_COMMIT_PAGES + 1):
        chunk = _gh_json(["repos/%s/pulls/%s/commits?per_page=100&page=%d" % (repo, pr, page)])
        if not isinstance(chunk, list) or (page == 1 and not chunk):
            return ("(commit list UNAVAILABLE: the GitHub API read failed; "
                    "this bundle cannot be judged)\n"), "unavailable"
        commits.extend(chunk)
        if len(chunk) < 100:
            break
    if len(commits) >= 250 or not all(isinstance(c, dict) for c in commits):
        return ("(commit list UNAVAILABLE: GitHub lists at most 250 commits of a pull request, "
                "or its answer is not a commit "
                "list; this bundle cannot be judged)\n"), "unavailable"
    if commits[-1].get("sha") != sha:
        return ("(the pull request's head is no longer %s: its last commit is %s)\n"
                % (sha, commits[-1].get("sha"))), "moved"
    lines = []
    for c in commits:
        author = c.get("author") or {}
        commit = c.get("commit") or {}
        who = author.get("login") or (commit.get("author") or {}).get("name") or "unknown author"
        merge = len(c.get("parents") or []) != 1
        own = ((author.get("login"), author.get("id"), author.get("type")) == DEPENDABOT and not merge
               and (c.get("committer") or {}).get("login") == "web-flow"
               and (commit.get("verification") or {}).get("verified") is True)
        subject = (str(commit.get("message") or "").splitlines() or [""])[0][:120]
        lines.append("- %s %s%s%s: %s" % (str(c.get("sha") or "")[:10], "" if own else "NOT Dependabot's — ", who,
                                         " (a merge commit)" if merge else "", subject))
    return "\n".join(lines) + "\n", "ok"


def _is_vendored(head):
    """True for the header line of a file under vendor/ that is not renamed: `diff --git a/vendor/x b/vendor/x`."""
    old, _, new = head.removeprefix("diff --git ").partition(" ")
    return (head.startswith("diff --git ") and old.startswith("a/vendor/")
            and new.startswith("b/vendor/") and " " not in new)


def vendor_is_required(path=".github/policy/required-checks.json"):
    """True when main's required-check list (this checkout is main) holds the `vendor` check: the job that regenerates
    vendor/ from go.mod and go.sum and compares it byte for byte (REQ-VEND-001-AC2, AC3). Unreadable is False."""
    try:
        return any(c.get("context") == "vendor" for c in json.load(open(path))["required_checks"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False


def shown_diff(diff, omit_vendor):
    """The diff as the readers get it. With omit_vendor, a section whose old and new path are both under vendor/
    keeps its header line and a count of its lines: the required `vendor` check compares those bytes with what
    go.mod and go.sum make."""
    if not omit_vendor:
        return diff
    out = []
    # one section per file: each starts at a line that begins with "diff --git "
    pieces = diff.split("\ndiff --git ")
    sections = [pieces[0]] + ["diff --git " + piece for piece in pieces[1:]]
    # the split took the newline that ended every section but the last: put it back
    sections = [section + "\n" for section in sections[:-1]] + sections[-1:]
    for section in sections:
        head, _, body = section.partition("\n")
        if not _is_vendored(head):
            out.append(section)
            continue
        hunks = body[body.index("\n@@") + 1:] if "\n@@" in body else ""
        added = sum(1 for l in hunks.splitlines() if l.startswith("+"))
        removed = sum(1 for l in hunks.splitlines() if l.startswith("-"))
        out.append("%s\n(a vendored module file: %d added and %d removed line(s) not shown; "
                   "the required `vendor` check regenerates vendor/ from go.mod and go.sum and compares it "
                   "byte for byte)\n"
                   % (head, added, removed))
    return "".join(out)


_KIND_LABEL = {"major": "MAJOR",
               "flagged": "FLAGGED: its release notes say breaking or deprecated",
               "not-major": "not major",
               "unparsed": "UNPARSED: the title and description name no update that could be read"}


def _has_binary(diff):
    """True when the diff names a changed binary file: its bytes are not in a diff."""
    return any(line.startswith(("Binary files ", "GIT binary patch")) for line in diff.split("\n"))


def cmd_gather(a):
    updates = json.load(open(a.updates))
    os.makedirs(a.out, exist_ok=True)
    # a whole commit id: "4c6dc6cd69fdfaac24b46d3227bb2d1208c46115" matches, "4c6dc6cd" and "HEAD" do not
    if not re.fullmatch(r"[0-9a-f]{40}", a.sha):
        sys.stderr.write("gather: --sha is not a full commit id — no bundle, no review\n")
        sys.exit(3)
    repo = os.environ.get("GITHUB_REPOSITORY") or "{owner}/{repo}"
    commits, state = pr_commits(a.pr, a.sha)
    if state == "moved":  # the verdict would be for a commit that is not the head any more: nothing is judged
        sys.stderr.write("gather: PR #%s moved: %s— no bundle, no review\n" % (a.pr, commits.strip() + " "))
        sys.exit(5)
    # the diff of exactly that commit against main, by its id: a head that moves after this changes nothing in it
    diff, rc = head_diff(repo, a.base, a.sha)
    if rc != 0 or not diff.strip():
        sys.stderr.write("gather: could not fetch the diff of %s (PR #%s, rc %s) — no bundle, no review\n"
                         % (a.sha, a.pr, rc))
        sys.exit(3)
    diff = shown_diff(diff, vendor_is_required())
    # the readers cannot be given a binary file's bytes: what they were not shown could merge unread
    if _has_binary(diff):
        sys.stderr.write("gather: the diff of PR #%s names a binary file, whose bytes are not in a diff "
                         "— no bundle, no review\n" % a.pr)
        sys.exit(3)
    if len(diff) > CAP_DIFF:  # never a cut diff, for the same reason
        sys.stderr.write("gather: the diff of PR #%s is %d characters, over the %d the readers are given "
                         "— no bundle, no review\n"
                         % (a.pr, len(diff), CAP_DIFF))
        sys.exit(3)
    kinds = [u.get("kind") or ("flagged" if u.get("flagged") else "major" if u["major"] else "not-major")
             for u in updates]
    parts = ["# Bundle for Dependabot PR #%s at its head %s\n" % (a.pr, a.sha),
             "## Updates in this PR (as Dependabot's title and description name them)\n",
             "\n".join("- %s: %s -> %s (%s)" % (u["name"], u["from"], u["to"], _KIND_LABEL.get(k, k))
                       for u, k in zip(updates, kinds)) + "\n",
             "## Commits in this PR\n\n%s" % commits,
             "## The PR diff (the whole pull request, every commit above: %s against %s)\n\n```diff\n%s```\n"
             % (a.sha, a.base, diff)]
    notes, unavailable = 0, ([] if state == "ok" else ["the commit list"])
    for u in updates:
        text, count = release_notes(u["name"], u["from"], u["to"])
        if count is None:
            unavailable.append("release notes of %s" % u["name"])
        notes += count or 0
        parts.append("## Upstream release notes: %s %s -> %s\n\n%s" % (u["name"], u["from"], u["to"], text))
        usage = our_usage(u["name"])
        if usage.startswith("(usage UNAVAILABLE"):
            unavailable.append("our usage of %s" % u["name"])
        parts.append("## Every line of ours that uses %s\n\n```\n%s```\n" % (u["name"], usage))
    text = "\n".join(parts)
    open(os.path.join(a.out, "bundle.md"), "w").write(text)
    if unavailable:  # labeled in the bundle (kept as evidence) and an error: no reader, no verdict, retried
        sys.stderr.write("gather: UNAVAILABLE — %s; no review this hour\n" % "; ".join(unavailable))
        sys.exit(4)
    print("bundle: %d characters, %d update(s) (%s), %d upstream release note(s)%s"
          % (len(text), len(updates), ", ".join(sorted(set(kinds))) or "none", notes,
             "" if notes else " — NONE found; the readers judge from the diff and our usage only"))


# ----------------------------------------------------------------------------- same-diff

def same_diff(repo, base, shas):
    """(same, why). True only when GitHub's diff of each commit against its merge base with `base` is, byte for byte,
    the same non-empty text, at most CAP_DIFF characters, naming no binary file. Then both commits make the same change
    to `base`: the same files, the same hunks at the same lines with the same context, the same mode changes and
    renames. A binary file's bytes are not in a diff, so it is never "the same"; a read that fails is never
    "the same"."""
    texts = []
    for sha in shas:
        out, rc = head_diff(repo, base, sha)
        if rc != 0 or not out.strip():
            return False, "the diff of %s against %s could not be read" % (sha[:10], base)
        texts.append(out)
    if len(set(texts)) != 1:
        return False, "the diffs against %s differ" % base
    if len(texts[0]) > CAP_DIFF:
        return False, "the diff is %d characters, over %d" % (len(texts[0]), CAP_DIFF)
    if _has_binary(texts[0]):
        return False, "the diff names a binary file"
    return True, "the same %d characters of diff against %s" % (len(texts[0]), base)


def cmd_same_diff(a):
    same, why = same_diff(a.repo, a.base, a.sha)
    print("same-diff %s: %s" % (" ".join(s[:10] for s in a.sha), why))
    sys.exit(0 if same else 1)


# ----------------------------------------------------------------------------- read

def parse_answer(text):
    """The reader's answer must be exactly ONE JSON object, optionally wrapped in a single code
    fence, and nothing else. No searching inside prose or a truncated answer for some object
    that happens to parse (round 1: `{"findings": [], "x": {"findings": []}` truncated read as a
    clean answer). Returns the dict or None."""
    s = str(text or "").strip()
    m = re.fullmatch(r"```[A-Za-z]*\s*\n(.*?)\n?```", s, re.S)
    if m:
        s = m.group(1).strip()
    def no_duplicates(pairs):
        keys = [k for k, _v in pairs]
        if len(keys) != len(set(keys)):     # a second "findings"/"severity" must never override the first
            raise ValueError("duplicate key")
        return dict(pairs)
    try:
        obj = json.loads(s, object_pairs_hook=no_duplicates)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def _extract_json(text):
    s = str(text or "")
    dec = json.JSONDecoder()
    i = s.find("{")
    while i != -1:
        try:
            obj, _end = dec.raw_decode(s[i:])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        i = s.find("{", i + 1)
    return None


def normalize_findings(obj):
    """A reader's answer, validated: a list of findings each with a known severity. Returns
    (findings, error). Unknown severity or a missing list is an ERROR, never a pass."""
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return None, "answer has no findings list"
    # The schema is exact: an extra field ("error": "I could not finish", a second findings-like
    # list, a verdict) is something the mechanical decision would silently drop, so it is an error.
    if set(obj) != {"findings"}:
        return None, "answer has fields other than `findings`"
    out = []
    for f in obj["findings"]:
        if not isinstance(f, dict):
            return None, "finding is not an object"
        if not set(f) <= _FINDING_KEYS:
            return None, "a finding has fields outside the schema"
        if not all(isinstance(f.get(k, ""), str) for k in _FINDING_KEYS):
            return None, "a finding has a field that is not text"
        sev = f.get("severity")
        if not isinstance(sev, str) or sev.strip().lower() not in SEVERITIES:
            return None, "a finding has no known severity (breaks-us, check, noise)"   # never echo it
        sev = sev.strip().lower()
        out.append({"severity": sev,
                    "title": mask(f.get("title", ""))[:200],
                    "release_note": mask(f.get("release_note", ""))[:1000],
                    "our_line": mask(f.get("our_line", ""))[:300],
                    "why": mask(f.get("why", ""))[:1000]})
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out.sort(key=lambda f: rank[f["severity"]])
    return out, None


def answer_of(msg):
    """(text, meta, error) from a model response. meta records how the answer ended (stop reason,
    content block types, token usage) for the evidence; a response cut off at the token limit or
    carrying no text is an explicit error, never a parse of whatever arrived."""
    blocks = list(getattr(msg, "content", None) or [])
    text = "".join(getattr(b, "text", "") or "" for b in blocks if getattr(b, "type", "text") == "text")
    usage = getattr(msg, "usage", None)
    meta = {"stop_reason": getattr(msg, "stop_reason", None),
            "blocks": [getattr(b, "type", "?") for b in blocks],
            "output_tokens": getattr(usage, "output_tokens", None) if usage else None}
    if meta["stop_reason"] == "max_tokens":
        return text, meta, "answer cut off at the token limit (%s output tokens)" % meta["output_tokens"]
    if meta["stop_reason"] != "end_turn":  # a refusal, a pause, anything unknown: never a clean read
        return text, meta, "answer did not finish normally (stop reason %r)" % (meta["stop_reason"],)
    if not text.strip():
        return text, meta, "answer has no text (blocks: %s)" % ",".join(map(str, meta["blocks"])) 
    return text, meta, None


def cmd_read(a):
    bundle = open(a.bundle).read()
    prompt = open(a.prompt).read().replace("{bundle}", bundle)
    model = os.environ.get(a.model_env)
    result = {"reader": a.model_env, "findings": None, "error": None, "raw": None}
    if not model:
        result["error"] = "no model configured in %s" % a.model_env
    else:
        try:
            import anthropic  # the SDK exchanges the federated identity token for a scoped access token
            client = anthropic.Anthropic()
            with client.messages.stream(model=model, max_tokens=MAX_TOKENS,
                                        messages=[{"role": "user", "content": prompt}]) as stream:
                msg = stream.get_final_message()
            text, meta, err = answer_of(msg)
            result["raw"], result["meta"] = mask(text), meta
            if err:
                result["error"] = err
            else:
                obj = parse_answer(text)
                if obj is None:
                    result["error"] = "answer is not exactly one JSON object"
                else:
                    findings, err = normalize_findings(obj)
                    result["findings"], result["error"] = findings, (mask(err) if err else None)
        except Exception as e:  # federation, network, SDK — all "error", never a pass
            status = getattr(e, "status_code", None) or getattr(e, "status", None)
            step = "identity/federation" if status in (401, 403) else "model-call"
            result["error"] = "%s step failed: %s%s: %s" % (step, type(e).__name__,
                                                           (" status=%s" % status) if status else "", mask(str(e)))
    json.dump(result, open(a.out, "w"), indent=1)
    print("reader %s: %s" % (a.model_env, ("error: " + result["error"]) if result["error"]
                             else "%d finding(s)" % len(result["findings"])))


# ----------------------------------------------------------------------------- decide

def decide(readers):
    """Mechanical, in code, no model: any breaks-us from a reader that answered -> hold (even if the
    other errored); otherwise every reader answered -> merge iff no breaks-us; else error (retry)."""
    if not readers:
        return {"decision": "error", "reason": "no readers"}
    errors = [r for r in readers if r.get("error") or r.get("findings") is None]
    breaks = [dict(f, reader=r.get("reader")) for r in readers if r not in errors
              for f in r["findings"] if f["severity"] == "breaks-us"]
    if breaks:  # "breaks us" from either reader holds, even when the other errored (owner, Oct 1)
        return {"decision": "hold", "breaks_us": breaks,
                "readers": [{"reader": r.get("reader"), "findings": r.get("findings") or [],
                             **({"error": mask(r.get("error") or "no findings")} if r in errors else {})}
                            for r in readers]}
    if errors:
        return {"decision": "error", "reason": mask("; ".join("%s: %s" % (r.get("reader"), r.get("error")) for r in errors))}
    return {"decision": "hold" if breaks else "merge",
            "breaks_us": breaks,
            "readers": [{"reader": r.get("reader"), "findings": r["findings"]} for r in readers]}


def cmd_decide(a):
    readers = []
    for p in a.reader:
        name = re.sub(r"^reader-|\.json$", "", os.path.basename(p))
        try:
            readers.append(json.load(open(p)))
        except (OSError, ValueError) as e:  # a reader that wrote no answer is an errored reader, never a crash
            readers.append({"reader": name, "findings": None, "error": "no answer (%s)" % type(e).__name__})
    d = decide(readers)
    json.dump(d, open(a.out, "w"), indent=1)
    print("decision: %s%s" % (d["decision"], (" (%s)" % d.get("reason")) if d.get("reason") else ""))


# ----------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("updates")
    p.add_argument("--title", default="")
    p.add_argument("--body-file")
    p.set_defaults(fn=cmd_updates)
    p = sub.add_parser("gather")
    p.add_argument("--pr", required=True)
    p.add_argument("--sha", required=True)
    p.add_argument("--base", default="main")
    p.add_argument("--updates", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_gather)
    p = sub.add_parser("same-diff")
    p.add_argument("--repo", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("sha", nargs=2)
    p.set_defaults(fn=cmd_same_diff)
    p = sub.add_parser("mask-tree"); p.add_argument("dir"); p.set_defaults(fn=cmd_mask_tree)
    p = sub.add_parser("read"); p.add_argument("--bundle", required=True); p.add_argument("--prompt", required=True); p.add_argument("--model-env", required=True); p.add_argument("--out", required=True); p.set_defaults(fn=cmd_read)
    p = sub.add_parser("decide"); p.add_argument("--reader", action="append", required=True); p.add_argument("--out", required=True); p.set_defaults(fn=cmd_decide)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
