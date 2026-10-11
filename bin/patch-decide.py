#!/usr/bin/env python3
"""The automatic patch-release decision (owner RATIFIED Oct 2: ops/docs/ratify/2026-10-02-automatic-patch-releases.md,
with the floating-tags amendment; advisor read-backs 0051/0055/0056; REQ-REL-009).

  classify / patch_clean  rule 1: a patch carries fixes only. Each commit since the latest tag is, by the files it
                          changes, fix-class (dependency version pins of existing modules in go.mod/go.sum, the
                          base-image digest pins in build/docker/Dockerfile.*, the VEX and suppression files), neutral
                          (no shipped byte: .github/, docs/, requirements/, test-evidence/, tests) or not patch-clean
                          (anything else, unless its merged PR carries the `patch-fix` label, which the owner applies,
                          or the lane only when both step-8 reviewers recorded "no behavior change").
  next_patch              rule 1: vX.Y.Z -> vX.Y.(Z+1); CI never makes a minor or major.
  daily_cut               rule 2: at most one daily patch (a critical/high fix may cut at once, outside this rule).
  notes                   rule 5: per fix the CVE, package, old -> new, severity, variants; each VEX change; a
                          no-behavior-change line, or (advisor 0130) the behavior changes listed in
                          docs/next-release-notes.md, each citing the handoff that judged it; no vendor or model names.
  removed_critical_high   rule 2: the latest release's critical/high findings that HEAD removes (a Go module or the
                          toolchain at or past the advisory's fixed version; a distribution package the new base
                          image no longer reports); unknown or unreadable never counts as removed.
  floating                amendment: :X.Y always; :X and :latest only when this is the highest released version.
"""
import argparse, json, os, re, subprocess, sys, unicodedata
FIX_EXACT = {".snyk", "osv-scanner.toml"}
FIX_PREFIX = (".vex/", ".auditor/")
NEUTRAL_PREFIX = (".github/", "docs/", "requirements/", "test-evidence/")
DOCKERFILES = re.compile(r"^build/docker/Dockerfile\.[a-z0-9-]+$")
SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?$")
def _sep(*words):
    """An alternation of names in which - _ or . may split any two letters: open-ai, co_here, deep.seek are the same
    names (Sonnet #159 r2, BLOCKER-1)."""
    return "|".join("[-_.]?".join(re.escape(c) for c in w) for w in words)


# no vendor or model names in public text (row 48; Codex #158 r1, B06: the wider set)
# A platform name that qualifies a model goes with it (Codex #158 phase-2 r2, B06: "Google Gemini" left "Google").
VENDOR = re.compile(r"(?i)((" + _sep("google", "microsoft", "amazon", "aws", "azure", "xai", "meta", "github")
                    + r"|x\.ai)\s+)?(chat[-_.\s]*gpt|"
                    + _sep("anthropic", "claude", "openai", "gpt", "codex", "gemini", "llama", "mistral", "mixtral", "grok",
                           "bedrock", "deepseek", "qwen", "copilot", "cohere", "bard", "sonnet", "opus", "haiku", "xai")
                    + r")(?:[\w-]|\.(?=\w))*|\bo[1-9](-(mini|pro|preview))?\b")
# a vendor named alone (Sonnet #158 r3: rule 5 forbids vendor OR model names) is redacted wherever it stands, next to a
# hyphen or slash too (Sonnet #158 r3b, NEW-BLOCKER-2: "AWS-reported", "Google/Microsoft"); fail closed — only a whole token
# that is a wholly lowercase domain or module path stays readable (google.golang.org/protobuf, github.com/aws/aws-sdk-go-v2);
# a camelCase boundary counts as a word boundary (Codex #159 r1, B5: providerGoogle.go), an ordinary word (laws) does not;
# Meta too, with the separators every name takes (Codex #158 phase-2 r3, NEW-BLOCKER-4: Me-ta, providerMeta.go)
VENDOR_ALONE = re.compile(r"(?i)(?:(?<![a-z0-9])|(?<=[a-z0-9])(?-i:(?=[A-Z])))("
                          + _sep("google", "microsoft", "amazon", "aws", "azure", "meta") + r")(?-i:(?![a-z0-9]))")
MODULE_PATH = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(/[a-z0-9_.@~+-]+)*/?$")   # every part lowercase (Sonnet r3c, NEW-BLOCKER-3)


def _alone(m):
    text, i, j = m.string, m.start(), m.end()
    while i > 0 and not text[i - 1].isspace() and text[i - 1] not in "([{\"'<,;":
        i -= 1
    while j < len(text) and not text[j].isspace() and text[j] not in ")]}\"'>,;":
        j += 1
    token = text[i:j].rstrip(".:")
    return m.group(0) if MODULE_PATH.match(token) else "<redacted>"


# the release chain's build inputs shape the shipped image: never neutral (Codex #158 r1, B04). Fail closed (Sonnet #158 r2,
# NEW-01): a workflow is neutral only when it is reviewed as outside the release chain (release.yml calls stage-*.yml and
# the acceptance workflows); any other — including one added later — is not patch-clean until it is reviewed here.
NEUTRAL_WORKFLOWS = {"agent-review-gate.yml", "auditor.yml", "ci.yml", "codeql.yml", "daily-rescan.yml",
                     "dependabot-auto-merge.yml", "dependabot-reviewer.yml", "dependency-review.yml", "go-freshness.yml",
                     "hygiene.yml", "main-candidate-rescan.yml", "release-chain-pr.yml", "requirements.yml",
                     "rescan-v010.yml", "reserved-branch-guard.yml", "scan.yml", "scorecard.yml"}
BUILD_INPUTS = re.compile(r"^\.goreleaser\.ya?ml$")
# Outside workflows, .github/ is release-chain input by default: the stage workflows run .github/agent/bin and read
# .github/policy (Codex #158 phase-2 r2, B04). Neutral only what is reviewed as never read by the release chain.
NEUTRAL_GITHUB = {".github/dependabot.yml", ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md"}
NEUTRAL_GITHUB_PREFIX = (".github/agent/reviews/", ".github/agent/docs/")   # tests are never neutral (AC1, owner Oct 3)


def _changed_lines(diff):
    return [ln for ln in (diff or "").splitlines() if ln[:1] in "+-" and ln[1:].strip()]


GO_BLOCK = re.compile(r"^(require|replace|exclude|retract|tool|ignore|godebug)\s*\($")
GO_REQ = re.compile(r"^(\S+)\s+(v\S+)(\s*//\s*indirect)?$")


def _go_mod_changes(diff):
    """{key: {sign: value}} for a go.mod diff that changes only require versions (in a require block known from the
    diff's context, or a single-line require) and the go/toolchain line; None for anything else, including an absent
    or empty diff (Codex #158 r1, B01/B02: replace, exclude, a line whose block is unknown — all fail closed)."""
    if not diff or not diff.strip():
        return None
    block, ch = None, {}
    for raw in diff.splitlines():
        if raw.startswith("@@"):
            block = None                    # a new hunk: its block is known only from its own context (r2, B02)
            continue
        sign, body = (raw[0], raw[1:]) if raw[:1] in ("+", "-", " ") else (" ", raw)
        t = body.strip()
        if sign == " ":
            if GO_BLOCK.match(t):
                block = GO_BLOCK.match(t).group(1)
            elif t == ")":
                block = None
            continue
        if not t or t.startswith("//"):
            continue
        m = re.match(r"^(go|toolchain)\s+(\S+)$", t)
        if m:
            key, val = "dir:" + m.group(1), m.group(2)
        else:
            m = re.match(r"^require\s+(\S+)\s+(v\S+)(\s*//\s*indirect)?$", t) or (block == "require" and GO_REQ.match(t))
            if not m:
                return None
            key, val = "req:" + m.group(1), (m.group(2), bool(m.group(3)))
        if sign in ch.setdefault(key, {}):
            return None
        ch[key][sign] = val
    if not ch:
        return None
    for key, v in ch.items():
        if set(v) != {"+", "-"} or v["+"] == v["-"]:
            return None                     # added, removed or unchanged: not a version move of an existing pin
        if key.startswith("req:") and v["+"][1] != v["-"][1]:
            return None                     # the indirect marker changed
    return ch


def _go_sum_ok(diff, moved):
    """go.sum lines only follow go.mod version moves of the same module tree: no go.sum-only edit, and never a
    checksum rewrite of the same module version (Codex #158 r1, B02)."""
    if not diff or not diff.strip() or not moved:
        return False
    # each line is the old version (removed) or the new version (added) of a module whose require moved; a go or
    # toolchain move explains no go.sum line (Codex #158 phase-2 r2, B02)
    allowed = {("-" if s == "-" else "+", k[4:], v[0]) for k, vs in moved.items() if k.startswith("req:")
               for s, v in vs.items()}
    if not allowed:
        return False
    seen = {}
    for ln in _changed_lines(diff):
        m = re.match(r"^([+-])(\S+) (v\S+?)(/go\.mod)? h1:\S+$", ln)
        if not m or m.group(1, 2, 3) not in allowed:
            return False
        seen.setdefault(m.group(2, 3, 4), set()).add(m.group(1))
    return all(signs != {"+", "-"} for signs in seen.values())


FROM = re.compile(r"^FROM\s+((?:--\S+\s+)*)(\S+?)@sha256:([0-9a-f]{64})(\s+AS\s+\S+)?\s*$", re.I)


def _digest_only(diff):
    """Each FROM keeps its flags, image, tag and alias and only the digest moves; no stage added or removed
    (Codex #158 r1, B03)."""
    # each change is a removed FROM directly followed by its replacement, so the instruction keeps its place
    # (Codex #158 phase-2 r2, B03)
    raw = [ln for ln in (diff or "").splitlines() if not ln.startswith(("+++", "---"))]
    pairs, i = 0, 0
    while i < len(raw):
        if raw[i][:1] == "+":
            return False                    # an added line not directly replacing a removed FROM
        if raw[i][:1] == "-":
            o = FROM.match(raw[i][1:].strip())
            n = FROM.match(raw[i + 1][1:].strip()) if i + 1 < len(raw) and raw[i + 1][:1] == "+" else None
            if not o or not n or o.group(1, 2, 4) != n.group(1, 2, 4) or o.group(3) == n.group(3):
                return False
            pairs, i = pairs + 1, i + 2
            continue
        i += 1
    if not pairs:
        return False
    return True


DATA_FILE = re.compile(r"\.(md|txt|json|ya?ml|toml|csv)$")


# REQ-REL-009 AC1 (owner RATIFIED Oct 3, item h): an executable test is never patch-neutral
TEST_FILE = re.compile(r"(-tests?\.sh|_test\.go|(^|/)test_[^/]*\.py|-check\.py)$|^\.github/agent/(bin/)?tests/")


def _reviewed_workflow(f):
    """A reviewed workflow by its full path, .github/workflows/<name> — never a same-named file deeper (Codex B02)."""
    return f.count("/") == 2 and f.split("/")[-1] in NEUTRAL_WORKFLOWS


def classify(commit):
    """('fix' | 'neutral' | 'dirty', reason) for one commit. Neutral means non-executable data only — docs/, requirements/,
    test-evidence/ data and the reviewed .github files; an executable test never counts (REQ-REL-009 AC1, owner Oct 3)."""
    files, diffs, modes = commit.get("files") or [], commit.get("diffs") or {}, commit.get("modes") or {}
    kinds, why = set(), []
    for f in files:
        if modes.get(f) in ("100755", "120000") or re.search(r"(?m)^\+#!", diffs.get(f) or ""):
            # data is not executable: Git's executable bit, a symlink, or a script's #! line (Codex #159 AC1(h), B01)
            kinds.add("dirty"); why.append("%s is executable (mode %s or a #! line), never data" % (f, modes.get(f, "?")))
        elif TEST_FILE.search(f):
            kinds.add("dirty"); why.append("%s is a test: executable, never patch-neutral (REQ-REL-009 AC1, owner Oct 3)" % f)
        elif f.startswith(NEUTRAL_PREFIX) and not DATA_FILE.search(f) and not f.startswith(".github/workflows/") \
                and f not in NEUTRAL_GITHUB:
            # only data is neutral by its directory (Sonnet #159 r7 B4, r8): anything without a data extension —
            # a script, an extensionless file, another extension — could be executed, so it is not
            kinds.add("dirty"); why.append("%s is not a data file; a directory does not make it neutral" % f)
        elif f in FIX_EXACT or (f.startswith(FIX_PREFIX) and DATA_FILE.search(f)):
            # the auditor's output directories make only DATA fix-class — never a script there (Codex #159 r5b, B10)
            kinds.add("fix")
        elif f in ("go.mod", "tools/requirements/go.mod"):
            if _go_mod_changes(diffs.get(f)) is not None:
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes more than existing modules' versions (or has no diff)" % f)
        elif f in ("go.sum", "tools/requirements/go.sum"):
            mod = f[:-len("go.sum")] + "go.mod"
            if _go_sum_ok(diffs.get(f), _go_mod_changes(diffs.get(mod)) if mod in files else None):
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes checksums its go.mod's version moves do not explain" % f)
        elif DOCKERFILES.match(f):
            if _digest_only(diffs.get(f)):
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes more than the base-image digest pin" % f)
        elif BUILD_INPUTS.match(f) or (f.startswith(".github/workflows/") and not _reviewed_workflow(f)):
            kinds.add("dirty"); why.append("%s builds or ships the release image" % f)
        elif f.startswith(".github/") and not f.startswith(".github/workflows/") \
                and f not in NEUTRAL_GITHUB and not f.startswith(NEUTRAL_GITHUB_PREFIX):
            kinds.add("dirty"); why.append("%s is read by the release chain (or not reviewed as outside it)" % f)
        elif f.startswith(NEUTRAL_PREFIX):
            kinds.add("neutral")
        else:
            kinds.add("dirty"); why.append("%s is shipped source or configuration" % f)
    if "dirty" in kinds and "patch-fix" in (commit.get("labels") or []):
        return "fix", "labelled patch-fix (no behavior change)"
    if "dirty" in kinds:
        return "dirty", "; ".join(why)
    return ("fix" if "fix" in kinds else "neutral"), ""


def ships_bytes(commits):
    return any(classify(c)[0] == "fix" for c in commits)


def patch_clean(commits):
    """(True, []) when every commit is fix-class or neutral and at least one ships bytes; (False, why) otherwise
    (why is empty when nothing would ship)."""
    why = ["%s: %s" % (c.get("sha", "?")[:7], r) for c in commits for k, r in [classify(c)] if k == "dirty"]
    if why:
        return False, why
    return ships_bytes(commits), []


def _semver(tag):
    m = SEMVER.match(tag or "")
    return tuple(int(x) for x in m.groups()) if m else None


def next_patch(tags):
    vs = sorted(v for v in (_semver(t) for t in tags) if v)
    if not vs:
        return None
    x, y, z = vs[-1]
    return "v%d.%d.%d" % (x, y, z + 1)


def daily_cut(ships, cut_today):
    return bool(ships) and not cut_today


def _clean(s):
    return VENDOR_ALONE.sub(_alone, VENDOR.sub("<redacted>", str(s)))


def _visible(s):
    """Markdown output (notes, changelog, tag notes): the redaction marker as visible text — "<redacted>" parses as an
    HTML tag and renders as nothing (Codex #300 r4, B low); an older text's marker is shown the same way"""
    return s.replace("<redacted>", "(redacted)")


def _clean_md(s):
    """_clean for Markdown output, with the visible marker"""
    return _visible(_clean(s))


PUNCT = r"!-/:-@\[-`{-~"                         # every ASCII punctuation character (CommonMark: each may be escaped)
ESC = re.compile(r"([%s])" % PUNCT)
ESCAPED = re.compile(r"(?:\\[%s]|[^%s])*\Z" % (PUNCT, PUNCT))
UNESC = re.compile(r"\\([%s])" % PUNCT)
MARK = re.compile(r"(?i)redacted")                # the marker in every form it was ever written: <..>, (..), escaped, any case
FREE_PRE = re.compile(r"- |#{1,6} ")             # a bullet or an ATX heading stays one
SHOWN_SPAN = re.compile(r"`[^`]+`")
SHOWN_BAD = re.compile(r"[!\"#$%&'*+<=>?@\\^`{|}~]|//|(?i:www)\.|(?<![A-Za-z0-9])_(?![A-Za-z0-9])")
SHOWN_BRACKETS = re.compile(r"[^\[\]]*(?: \[[^\[\]]*\]: [^\[\]]*)?\Z")


def _shows(body):
    """the body of a line holding the marker shows it as text as written (Codex #300 r6, A R5-1 / B F1): outside its
    code spans (single backticks, none adjacent: literal text in every renderer) it holds letters, digits, spaces,
    non-ASCII text and . , ; : ( ) / - only, '_' only beside a letter or digit, '[' only as the one ' [...]: ' list a VEX
    line prints, no '//' or 'www.': nothing that starts a link, image, reference definition, HTML, comment, autolink,
    entity, escape, code, footnote, table or math construct can take the marker into its syntax. Anything else is not
    judged: the line is escaped (fail closed, no construct list to keep up)."""
    if "``" in body:
        return False
    rest = SHOWN_SPAN.sub("C", body)
    return not SHOWN_BAD.search(rest) and bool(SHOWN_BRACKETS.match(rest))


def _clean_free(line):
    """one line of free text (a fix line, a behavior entry, any line of a tag's own text) for Markdown output. The
    marker is recognised in every form it was ever written — origin/main's "<redacted>", round 4's "(redacted)", the
    escaped forms, any case (Codex #300 r6, A R5-1 / B F1). A line holding it after _clean is kept as written only when
    the marker was already there (_clean redacted nothing new) and _shows() finds nothing around it that could hide it
    (so a VEX line the notes print reads back unchanged); otherwise every ASCII punctuation character is backslash-
    escaped, the marker written '\\(redacted\\)': no link, image, HTML tag, comment, code span or other construct can take
    it into its syntax (Codex #300 r5, A R4-4 / B F3). A line in that escaped form that holds the marker is read
    unescaped, cleaned and escaped again, so cleaning twice changes nothing; a line without the marker is never read as
    escaped — it is _clean's output unchanged ('google\\.com' is redacted as before round 5; r6, A (d) / B F6). A leading
    '- ' bullet or an ATX heading's '#... ' stays one."""
    m = FREE_PRE.match(line)
    pre = m.group(0) if m else ""
    body = line[len(pre):]
    own = bool(MARK.search(body) and "\\" in body and ESCAPED.match(body))   # this function's own escaped form
    raw = UNESC.sub(r"\1", body) if own else body
    c = _visible(_clean(raw))
    if not MARK.search(c) or (not own and c == raw and _shows(c)):
        return pre + c
    return pre + ESC.sub(r"\\\1", c)


NOTES_LINE = re.compile(r"(?:- .*|#{1,6}(?: .*)?|No behavior change: this release contains fixes only\.)?\Z", re.S)


def _shaped(text):
    """a text holding the marker is published only when every line is blank, a '- ' bullet, an ATX heading, the
    no-behavior-change line (what notes() writes), or a paragraph line standing alone (a blank line or the text's edge
    before and after it, no leading space) that is fully escaped or that _shows() reads as plain text: then no line can
    open a block (HTML, comment, fence, quote, indented code, reference definition) or continue a construct (a link title,
    inline HTML) across lines, and a marker on another line cannot be taken into it (Codex #300 r6, B F2; fail closed).
    A text without the marker is not judged."""
    lines = text.split("\n")
    if not any(MARK.search(ln) for ln in lines):
        return True
    for i, ln in enumerate(lines):
        if NOTES_LINE.match(ln):
            continue
        alone = (i == 0 or lines[i - 1] == "") and (i + 1 == len(lines) or lines[i + 1] == "")
        if not (alone and ln[:1].strip() and (ESCAPED.match(ln) or _shows(ln))):
            return False
    return True


def _clean_lines(s):
    """_clean_free one line at a time, split at every line boundary str.splitlines() knows (LF, CR, CRLF, VT, FF, FS,
    GS, RS, NEL, LS, PS), each written back as LF: no redaction ever matches across a line break and merges two lines
    (Codex #300 r3 B1; r4 A R3-4, B low). Its callers judge the whole text with _shaped() (r6, B F2)."""
    out = []
    for ln in str(s).splitlines(True):
        body = ln.splitlines()[0]
        out.append(_clean_free(body) + ("\n" if len(body) < len(ln) else ""))
    return "".join(out)


UNPRINTED = ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn")


def _oneline(s):
    """s with every control (C0, DEL, C1), format, line or paragraph separator, surrogate, private-use or unassigned
    character written as a \\uXXXX escape: one printed line, UTF-8 writable (Codex #300 r3, A1)"""
    return "".join(("\\u%04x" % ord(c) if ord(c) <= 0xFFFF else "\\U%08x" % ord(c))
                   if unicodedata.category(c) in UNPRINTED else c for c in str(s))


# A value the VEX document supplies prints bare only in a conservative allowed form no renderer (CommonMark, GFM,
# GitHub's mention, issue-reference, emoji, autolink and commit-SHA filters) can show as anything else (Codex #300 r3 B3;
# r4 A R3-5, B low): a letter, then letters, digits and - . _ / only, optionally after one pkg: / urn: / cpe: prefix
# (purl, URN, CPE; no other "scheme:" form, so no mailto:, xmpp:, http:); no '@' anywhere (a mention or an e-mail
# autolink), no '#' (an issue reference), no GH- or GHSA- reference, no '//', no www., an underscore only inside a word,
# no emoji-shortcode shape, no SHA-like hex run of 7 or more. Anything else (a control character, a space, Markdown or
# HTML, an empty name, text shaped like a position label) prints as its JSON string in a code span: one line, shown
# literally by every renderer, decoding back to exactly that value (fail closed). The guarantee covers the renderers'
# built-in forms; an autolink a repository configures in its own settings (a custom prefix such as "TICKET-") is a
# repository setting outside this code and is not covered (Codex #300 r5, A R4-2: documented, not handled).
BARE = re.compile(r"(?:(?:pkg|urn|cpe):)?[A-Za-z][A-Za-z0-9._/-]*\Z")
NOT_BARE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])|:[A-Za-z0-9_+-]+:|//|(?i:www)\.|(?i:(?<![A-Za-z0-9])gh(?:sa)?-)|"
                      r"(?<![A-Za-z0-9])[0-9a-fA-F]{7,}(?![A-Za-z0-9])")


def _lit(v, before_colon=False):
    """the printed form of a document-supplied value; before_colon: the notes print ':' right after it (a CVE name). In
    the quoted form a hyphen followed by four more is written \\u002d (the same JSON string): no run of five hyphens, a
    signature-block delimiter, is ever printed, so the tag of the notes stays readable (Codex #300 r6, B F4)"""
    v = str(v)
    if BARE.match(v) and not NOT_BARE.search(v + (":" if before_colon else "")):
        return v
    return "`%s`" % re.sub(r"-(?=----)", r"\\u002d", json.dumps(v, ensure_ascii=True).replace("`", "\\u0060"))


CITED = re.compile(r"\((?:[^()]*[\s;,])?(?:advisor|handoff) \d{4}\)\.?$")


def behavior_entries(text):
    """The entries of docs/next-release-notes.md (advisor 0130): each "- " bullet, its indented continuation lines joined.
    An entry is only a change the owner or the advisor judged unable to affect supported clients, so each must end by
    citing that handoff, "(... advisor NNNN)"; an entry without one is refused (ValueError) and nothing is cut."""
    out = []
    for ln in text.splitlines():
        if ln.startswith("- "):
            out.append(ln[2:].strip())
        elif out and ln.startswith("  ") and ln.strip():
            out[-1] += " " + ln.strip()
    for e in out:
        _check_entry(e)
    return out


def _check_entry(e):
    """An entry cites the handoff that judged it (advisor 0130), and no vendor or model name hides in it split by a
    space or the line wrap — refused, not redacted (Sonnet #158 r2, SEC-1/SEC-2)."""
    if not CITED.search(e):
        raise ValueError("next-release-notes entry cites no handoff: %r" % e)
    # any run of up to ten adjacent words that spells a name (the longest has nine letters): "Goo gle", "G o o g l e"
    # (Sonnet #158 r2b); a run starting with a word that is already a name is _clean's, which redacts it
    words = re.findall(r"[A-Za-z0-9]+", e)
    for i in range(len(words)):
        for j in range(i + 2, min(i + 10, len(words)) + 1):
            joined = "".join(words[i:j])
            if any(VENDOR.search(w) or VENDOR_ALONE.search(w) for w in words[i:j]):
                continue                    # a word that is a name already: _clean redacts it
            if VENDOR.fullmatch(joined) or VENDOR_ALONE.fullmatch(joined):
                raise ValueError("next-release-notes entry names a vendor or model split by whitespace: %r" % e)


def _vex_line(v):
    """the notes line of one VEX statement entry, before redaction (vex_changes checks the redacted lines name one
    statement each and are distinct); the CVE name prints as _lit, the products as vex_changes printed them
    (products_shown; else the products as one line), everything else is one line whatever a caller hands in"""
    return "- %s%s: %s (%s)%s" % (
        _lit(v["cve"], before_colon=True), " [products unreadable]" if v.get("products_unreadable")
        else " [%s]" % _oneline(", ".join(v.get("products_shown") or v["products"])) if v.get("products") else "",
        _oneline(v["status"]), _oneline(v["change"]), " — %s" % _oneline(v["statement"]) if v.get("statement") else "")


def _entry_line(e):
    """the notes line of one behavior entry, exactly as notes() prints it (and so as the tag and changelog carry it)"""
    return _clean_free("- %s" % _oneline(e))


def notes(version, fixes, vex_changes, behavior=()):
    """every line is one line (_oneline) cleaned on its own: a VEX line as _clean_md (its document values are bare
    identifier text or code spans; vex_changes checked that final form), every other line as free text (_clean_free:
    a line holding the marker is written escaped, Codex #300 r5)"""
    lines = [_clean_free("## %s — patch release" % _oneline(version)), "", "### Fixes"]
    for f in fixes:
        lines.append(_clean_free(_oneline("- %s in %s: %s → %s (severity %s; variants: %s)" % (
            f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or [])))))
    if not fixes:
        lines.append("- none (dependency or VEX maintenance only)")
    lines += ["", "### VEX"]
    stmts = [v for v in vex_changes if "document" not in v]
    vl = [_clean_md(_vex_line(v)) for v in stmts]
    if len(set(vl)) != len(vl):  # every published statement line is its own (Codex #300 r3)
        raise ValueError("VEX notes: two statement lines read alike")
    if any(_clean_free(ln) != ln for ln in vl):     # the tag of the notes reads back as the notes (r6, fail closed)
        raise ValueError("VEX notes: a statement line the tag would not read back unchanged")
    lines += vl
    lines += [_clean_md("- document fields changed (%s)%s" % (", ".join(_lit(k) for k in v["document"]),
                                                             "" if stmts else "; no statement changed"))
              for v in vex_changes if "document" in v]
    if not vex_changes:
        lines.append("- no change")
    for b in behavior:
        _check_entry(b)
    if behavior:
        lines += ["", "### Behavior changes"] + [_entry_line(b) for b in behavior]
    else:
        lines += ["", "No behavior change: this release contains fixes only."]
    text = "\n".join(lines) + "\n"
    if not _shaped(text):                            # every line notes() writes is a bullet, a heading or blank (r6)
        raise ValueError("notes: a line that is not a bullet, a heading or blank")
    return text


def _precedence(tag):
    """Semantic-version precedence including our -rc.N prereleases: vX.Y.Z-rc.N sorts below vX.Y.Z."""
    m = VERSION.match(tag or "")
    if not m:
        return None
    x, y, z, rc = m.groups()
    return (int(x), int(y), int(z), 1, 0) if rc is None else (int(x), int(y), int(z), 0, int(rc))


def floating(version, released):
    """The floating tags a CI patch moves (amendment, owner Oct 2): :X.Y always; :X and :latest only when it outranks
    every released version, prereleases included (Codex #158 r1, B05)."""
    v = _semver(version)
    mine = _precedence(version)
    others = [o for o in (_precedence(t) for t in released) if o]
    out = ["%d.%d" % v[:2]]
    if all(mine >= o for o in others):
        out += ["%d" % v[0], "latest"]
    return out


GO_VERSION = re.compile(r"^(?:go|v)?(\d+)\.(\d+)(?:\.(\d+))?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def _go_ver(v):
    """((X, Y, Z), prerelease?) for a Go module or toolchain version; None when it cannot be read (go1.26rc1)."""
    m = GO_VERSION.match(str(v or ""))
    return ((int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)), bool(m.group(4))) if m else None


def _at_least(have, want):
    """Is `have` at or past a fix? A prerelease or pseudo-version is below its release (Codex #159 r1, B1); with several
    fix versions (one per release stream), `have` counts only past the fix of its own X.Y stream, or past every one.
    Anything unreadable is never "fixed"."""
    h = _go_ver(have)
    fixes = [_go_ver(w) for w in ([want] if isinstance(want, str) else list(want or []))]
    if not h or not fixes or not all(fixes) or any(f[1] for f in fixes):
        return False
    (hv, pre), mains = h, [f[0] for f in fixes]

    def past(f):
        return hv > f or (hv == f and not pre)
    same = [f for f in mains if f[:2] == hv[:2]]
    return any(past(f) for f in same) if same else all(past(f) for f in mains)


def removed_critical_high(release_findings, head):
    """The latest release's critical/high findings that HEAD removes. head: {"go": {module: version at HEAD},
    "base_findings": [findings of the new base image] or None when it could not be scanned}."""
    out = []
    for f in release_findings:
        if str(f.get("severity", "")).lower() not in ("critical", "high") or not f.get("fixed"):
            continue
        if f.get("type") == "go-module":
            have = (head.get("go") or {}).get(f["package"])
            if have and _at_least(have, f["fixed"]):
                out.append(f)
        elif f.get("type") == "deb":
            base = head.get("base_findings")
            if base is not None and not any(b.get("id") == f["id"] and b.get("package") == f["package"] for b in base):
                out.append(f)
    return out


def _fixed(f, head):
    """The version HEAD fixes f at, or None: a Go module at or past the fixed version; a distribution package the new base
    image no longer reports (only with base evidence)."""
    if f.get("type") == "go-module":
        have = (head.get("go") or {}).get(f.get("package"))
        return have if have and f.get("fixed") and _at_least(have, f["fixed"]) else None
    if f.get("type") == "deb":
        base = head.get("base_findings")
        if base is not None and f.get("fixed") and not any(
                b.get("id") == f["id"] and b.get("package") == f["package"] for b in base):
            return f["fixed"]
    return None


def fixed_findings(release_by_variant, head):
    """AC8: every finding of the latest release (any severity) that HEAD fixes, one per CVE and package, with the image
    variants it was found in ("" is the default image). release_by_variant: {variant: [grype findings]}."""
    out = {}
    for variant in sorted(release_by_variant):
        for f in release_by_variant[variant]:
            new = _fixed(f, head)
            if new is None:
                continue
            k = (f["id"], f["package"])
            e = out.setdefault(k, {"cve": f["id"], "package": f["package"], "old": f.get("installed", ""), "new": new,
                                   "severity": f.get("severity", ""), "variants": []})
            name = variant or "default"
            if name not in e["variants"]:
                e["variants"].append(name)
    for e in out.values():
        e["variants"].sort()
    return [out[k] for k in sorted(out)]


VEX_STATUS = ("not_affected", "affected", "fixed", "under_investigation")
VEX_ID_FORMS = ("purl", "cpe23", "cpe22")     # the OpenVEX v0.2 identifiers forms (.github/agent/bin/auditorlib/openvex-schema.json)


def vex_changes(old_doc, new_doc):
    """AC8 (rule 0254: the notes name the statements that changed): each VEX statement added, changed or removed since
    the latest tag. A change to any field of a statement (products, status, justification, impact or action text,
    status_notes, anything else, nested values too) is a change, named by field; values compare as JSON, type-sensitive
    (1 and true differ). A CVE may carry several statements. Pairing is total, order-independent and never guesses
    (Codex #300 r1, A2/B F1; r2): within a CVE, (1) identical statements pair first; (2) then statements whose own @id
    appears exactly once in each WHOLE document (r2, A2); (3) then statements whose product scope is unique on both
    sides among the rest — the scope is the products with their subcomponents, subcomponent order ignored (r2, A4); an
    absent or empty products is no scope (r2, A3); a CVE with exactly one statement on each side pairs those two; anything
    left is removed + added. A product or subcomponent is read when it is an object with a string @id or with
    identifiers holding only purl / cpe23 / cpe22 strings (the schema's forms, r2 A5), named by its @id, else by those
    identifiers; a statement whose products is anything else is unpairable beyond step (1) and is named "products
    unreadable", never iterated (A3). Each statement of a CVE that has several is named by its products and by its own
    @id (unique in its document), else its position in the new document (the old one when removed) (A1); a statement is
    named by its position instead whenever redaction would change its CVE name, its FINAL line (cleaned line by line, as
    notes() prints it) no longer carries its label or CVE name verbatim, or two final lines read the same (r2, A1/B; r3);
    a line that still names no single statement is refused (ValueError). Every value the document supplies (CVE name,
    @id, product and identifier, field name) prints through _lit: bare identifier text, or a quoted JSON literal in a code
    span, so every statement is exactly one line, Markdown renders it literally, and an @id never reads as a position
    label (r3, A1/A2/B2/B3). An empty vulnerability name is schema-valid: read, printed "", named by position (r3, A3).
    Entries sort by content, not input order (B F3). A change to the document's own fields (version, timestamp, author,
    ...) adds one {"document": [fields]} entry, last (advisor ruling on 0389 (d)). A document the notes cannot read is
    refused with ValueError: no notes, no patch (B F4) — not an object, no statements array, a statement that is not an
    object, has no string vulnerability name or a status outside OpenVEX's four (r2, A6). This is what the notes read,
    not a full OpenVEX schema check."""
    def canon(v):
        return json.dumps(v, sort_keys=True)

    def by_cve(doc, side):
        if not isinstance(doc, dict) or not isinstance(doc.get("statements"), list):
            raise ValueError("VEX %s document: not an object with a statements array" % side)
        out, ids = {}, {}
        for pos, s_ in enumerate(doc["statements"], 1):
            v_ = s_.get("vulnerability") if isinstance(s_, dict) else None
            if not isinstance(v_, dict) or not isinstance(v_.get("name"), str):    # "" is schema-valid (r3, A3)
                raise ValueError("VEX %s document: statement %d has no vulnerability name" % (side, pos))
            if not isinstance(s_.get("status"), str) or s_["status"] not in VEX_STATUS:
                raise ValueError("VEX %s document: statement %d has no OpenVEX status" % (side, pos))
            out.setdefault(v_["name"], []).append((pos, s_))
            if isinstance(s_.get("@id"), str):
                ids[s_["@id"]] = ids.get(s_["@id"], 0) + 1
        return out, ids

    def component(c):
        """(raw label, printed label) of a component the schema allows (a string @id, or identifiers with only
        purl/cpe23/cpe22 strings), else None"""
        if not isinstance(c, dict) or ("@id" in c and not isinstance(c["@id"], str)):
            return None
        idf = c.get("identifiers")
        if "identifiers" in c and (not isinstance(idf, dict) or not idf
                                   or not all(k in VEX_ID_FORMS and isinstance(v, str) for k, v in idf.items())):
            return None
        if isinstance(c.get("@id"), str):
            return c["@id"], _lit(c["@id"])
        if not idf:
            return None
        vals = [idf[k] for k in VEX_ID_FORMS if k in idf]
        return " ".join(vals), " ".join(_lit(v) for v in vals)

    def products(s_):
        """(raw labels, scope key or None when there is no scope, printed labels), or None when products is present but
        unreadable; both label lists in the order of the raw values, equal ones by their source content, so how a value
        prints never reorders anything (Codex #300 r4, B; r5, B F4)"""
        ps = s_.get("products", [])
        if not isinstance(ps, list):
            return None
        labels, keys = [], []
        for p in ps:
            subs = p.get("subcomponents", []) if isinstance(p, dict) else None
            label = component(p)
            sub_labels = [component(c) for c in subs] if isinstance(subs, list) else [None]
            if label is None or None in sub_labels:
                return None
            sub_labels = [x + (canon(c),) for x, c in zip(sub_labels, subs)]
            sub_labels.sort(key=lambda x: (x[0], x[2]))
            key = canon(dict(p, subcomponents=sorted(subs, key=canon)) if "subcomponents" in p else p)
            labels.append((label[0] + (" (subcomponents: %s)" % ", ".join(x[0] for x in sub_labels) if sub_labels else ""),
                           key,
                           label[1] + (" (subcomponents: %s)" % ", ".join(x[1] for x in sub_labels) if sub_labels else "")))
            keys.append(key)
        labels.sort(key=lambda x: (x[0], x[1]))     # raw label, then the source content: never the printed form (r5, B F4)
        return [x[0] for x in labels], (tuple(sorted(keys)) if keys else None), [x[2] for x in labels]

    def match(ro, rn, key, unique):
        """pair the statements of ro and rn whose key (not None; key(statement, side)) is equal; with unique, only a key
        held once per side"""
        ko, kn = {}, {}
        for side, name, rest in ((ko, "old", ro), (kn, "new", rn)):
            for x in rest:
                k = key(x[1], name)
                if k is not None:
                    side.setdefault(k, []).append(x)
        got = []
        for k in sorted(set(ko) & set(kn), key=repr):
            if unique and (len(ko[k]) != 1 or len(kn[k]) != 1):
                continue
            got += list(zip(ko[k], kn[k]))      # equal keys under (1) are identical statements: interchangeable
        for x, y in got:
            ro.remove(x); rn.remove(y)
        return got

    if old_doc is not None:
        old, old_ids = by_cve(old_doc, "old")
    else:
        old, old_ids = {}, {}
    new, new_ids = by_cve(new_doc, "new")
    side_ids = {"old": old_ids, "new": new_ids}

    def own_id(s_, side):
        """the statement's @id when it is held exactly once in its whole document (r2, A2), else None"""
        sid = s_.get("@id")
        return sid if isinstance(sid, str) and side_ids[side].get(sid) == 1 else None

    recs = []       # (entry, position, side)
    for cve in sorted(set(old) | set(new)):
        olds, news = list(old.get(cve, [])), list(new.get(cve, []))
        several = len(olds) > 1 or len(news) > 1
        lone = len(olds) == 1 and len(news) == 1
        pairs = match(olds, news, lambda s_, side: canon(s_), False)
        pairs += match(olds, news, lambda s_, side: own_id(s_, side) if products(s_) is not None else None, True)
        pairs += match(olds, news, lambda s_, side: products(s_)[1] if products(s_) is not None else None, True)
        if lone and olds and news and products(olds[0][1]) is not None and products(news[0][1]) is not None:
            pairs.append((olds.pop(), news.pop()))

        def entry(x, side, change, raw):
            """raw: the change with the raw field names, the sort key (how a field name prints never reorders, r5 B F4)"""
            pos, s_ = x
            e = {"cve": cve, "status": s_["status"], "change": change}
            prod = products(s_)
            if prod is None:
                e["products_unreadable"] = True
            elif several:
                e["products"], e["products_shown"] = prod[0], prod[2]
            if several or cve == "":
                sid = own_id(s_, side) if cve != "" else None
                e["statement"] = ("statement %s" % _lit(sid) if sid is not None
                                  else "statement %d of the %s document" % (pos, side))
            return (e.get("products", []), "products_unreadable" in e, raw, e["status"], canon(s_)), (e, pos, side)

        found = []
        for (_, o), n in ((p[0], p[1]) for p in pairs):
            fields = sorted(k for k in set(o) | set(n[1]) if k not in o or k not in n[1] or canon(o[k]) != canon(n[1][k]))
            others = [k for k in fields if k != "status"]
            if "status" in fields:
                found.append(entry(n, "new", "changed from %s" % o["status"]
                                   + ("; also " + ", ".join(_lit(k) for k in others) if others else ""),
                                   "changed from %s" % o["status"] + ("; also " + ", ".join(others) if others else "")))
            elif fields:
                found.append(entry(n, "new", "changed: " + ", ".join(_lit(k) for k in fields), "changed: " + ", ".join(fields)))
        found += [entry(x, "new", "added", "added") for x in news] + [entry(x, "old", "removed", "removed") for x in olds]
        recs += [r for _, r in sorted(found, key=lambda f: f[0])]

    # r2 (A1/B), r3: the published lines are the redacted ones, cleaned line by line exactly as notes() prints them; each
    # must still name exactly one statement. A statement whose CVE name redaction would change, or whose FINAL line no
    # longer carries its own label (or, unlabelled, its CVE name) verbatim, or whose final line reads like another, is
    # named by its position, which is unique: a new-document statement is in at most one entry (changed or added), an
    # old one only in a removed one; a position label ("statement N of the new document") never shares a form with an
    # @id label, which is bare identifier text or a quoted literal (r3, A2/B2). Anything still unresolved is refused.
    def by_position(r):
        e, pos, side = r
        label = "statement %d of the %s document" % (pos, side)
        changed_ = e.get("statement") != label
        e["statement"] = label
        return changed_

    def names_one(e):
        fin, lab = _clean_md(_vex_line(e)), e.get("statement")
        if lab:
            return fin.endswith(" — " + lab)
        name = "- " + _lit(e["cve"], before_colon=True)
        return fin.startswith(name + ": ") or fin.startswith(name + " [")
    for r in recs:
        name = _lit(r[0]["cve"], before_colon=True)
        if _clean_md(name) != name or not names_one(r[0]):
            by_position(r)
    while True:
        seen = {}
        for r in recs:
            seen.setdefault(_clean_md(_vex_line(r[0])), []).append(r)
        if not [by_position(r) for rs in seen.values() if len(rs) > 1 for r in rs if by_position(r)]:
            break
    if not all(names_one(r[0]) for r in recs) or any(len(rs) > 1 for rs in seen.values()):
        raise ValueError("VEX notes: a statement line that names no single statement after redaction")
    out = [r[0] for r in recs]
    if old_doc is not None:     # advisor ruling (0389 (d)): a document-level change is a VEX change too, named by field
        doc_fields = sorted(k for k in (set(old_doc) | set(new_doc)) - {"statements"}
                            if k not in old_doc or k not in new_doc or canon(old_doc[k]) != canon(new_doc[k]))
        if doc_fields:
            out.append({"document": doc_fields})
    return out


def unpublished(entries, published_text):
    """Advisor 0135: an entry an earlier patch already published (any v* tag message, CHANGELOG.md) is not published
    again — the clear-and-changelog PR may not have merged when the next patch is decided."""
    return [e for e in entries if not any(f in published_text for f in _published_forms(e))]


def _published_forms(e):
    """every line a behavior entry was ever published as: this code's (_entry_line), origin/main's "<redacted>" and
    round 4's "(redacted)" forms (r4; r6, B F1: changelog() removes an entry by them too)"""
    legacy = "- %s" % _clean(_oneline(e))
    return (_entry_line(e), legacy, _visible(legacy))


PATCH_HEAD = re.compile(r"^## (v\d+\.\d+\.\d+) — patch release$")


RELEASE_TAGGER = "fosterstack release <release@users.noreply.github.com>"   # decide's git identity (release.yml)


def tag_notes(raw):
    """AC8: the notes a generated patch tag carries (`git cat-file tag` output), or None for any other tag (an owner's
    release keeps the fixed release text). The heading must name the tag itself; the signature block is dropped."""
    head, _, body = raw.partition("\n\n")
    tag = next((ln[4:] for ln in head.splitlines() if ln.startswith("tag ")), None)
    tagger = next((ln[7:] for ln in head.splitlines() if ln.startswith("tagger ")), "")
    # exactly one signature-shaped block, genuinely last (Codex #159 fresh r2d): "the real signature is last" alone
    # is not fail-closed — ssh-keygen's own check does not require a signature to be an object's literal last bytes,
    # so a hand-crafted object could carry a real signature then append a second, fake block after it. No block, or
    # more than one anywhere, is refused; exactly one is read if it is the message's own last bytes.
    if body.count("-----BEGIN ") == 1:
        body, _, sig = body.partition("-----BEGIN ")
    else:
        sig = ""
    # only the release workflow's own patch tag: its tagger and a gitsign (x509) signature — an owner's tag is SSH-signed
    # and never carries notes, whatever its message (Sonnet #159 r2, BLOCKER-1); admission verified the signature
    if not tagger.startswith(RELEASE_TAGGER + " ") or not sig.startswith("SIGNED MESSAGE-----"):
        return None
    # the generated heading ends in LF and nothing else: CR, CRLF, VT, FF, FS, GS, RS, NEL, LS or PS after it is refused
    # (as in round 3; Codex #300 r5, B low)
    head_, lf_, _ = body.partition("\n")
    m = PATCH_HEAD.fullmatch(head_) if lf_ else None
    if not (m and m.group(1) == tag):
        return None
    out = _clean_lines(body)
    return out if _shaped(out) else None            # a marker beside a line not shaped as notes (r6, B F2): no notes


def changelog(notes_text, changelog_text, next_notes_text):
    """AC8 + advisor 0130: (CHANGELOG.md with these notes on top, newest first; next-release-notes.md without the
    entries these notes published — an entry added since stays). The new notes are cleaned line by line; the existing
    history is copied unchanged, never rewritten — and is refused (ValueError, nothing written) unless it is exactly
    what this function writes, so cleaning it would change nothing: LF line ends only, no name, no unescaped marker
    (Codex #300 r5, A R4-1 / B low; fail closed). After the title, the one blank line this function writes is dropped and
    everything else is copied byte for byte, its own spacing kept (r6, A R5-5). The whole changelog holding the marker
    must be shaped as notes (r6, B F2): new notes cannot open a construct that takes a marker of the history below."""
    notes_text = _clean_lines(notes_text)
    title = "# Changelog\n"
    rest = (changelog_text or title)
    if rest.startswith(title):
        rest = rest[len(title):]
        rest = rest[1:] if rest.startswith("\n") else rest
    if _clean_lines(rest) != rest or not _shaped(rest):
        raise ValueError("CHANGELOG.md history is not clean (a line end other than LF, a name, an unescaped marker, or a "
                         "marker beside a line that is not a bullet, a heading or blank): refused, not rewritten")
    new_cl = title + "\n" + notes_text.rstrip("\n") + "\n" + ("\n" + rest if rest else "")
    if not _shaped(new_cl):
        raise ValueError("CHANGELOG.md with these notes holds the marker beside a line that is not a bullet, a heading or "
                         "blank: refused")
    lines, keep, i = next_notes_text.splitlines(keepends=True), [], 0
    while i < len(lines):
        j = i + 1
        if lines[i].startswith("- "):                      # an entry and its indented continuation lines
            while j < len(lines) and lines[j].startswith("  ") and lines[j].strip():
                j += 1
            entry = " ".join(ln.strip() for ln in lines[i:j])[2:]
            if any(f in notes_text for f in _published_forms(entry)):
                i = j
                continue
        keep += lines[i:j]
        i = j
    return new_cl, "".join(keep)


def decide(event, commits, tags, cut_today, removed):
    """{cut, version, reason, not_clean}: rule 1 (patch-clean, fix-only), rule 2 (a critical/high fix at once on push;
    otherwise at most one daily patch on the schedule)."""
    version = next_patch(tags)
    clean, why = patch_clean(commits)
    out = {"cut": False, "version": version, "reason": "", "not_clean": why}
    if version is None:
        out["reason"] = "no release yet: the first release is the owner's"
    elif why:
        out["reason"] = "main is not patch-clean"
    elif not clean:
        out["reason"] = "nothing shipped since the latest tag"
    elif event == "push":
        if removed is None:
            out["reason"] = "the latest release could not be scanned: no at-once cut (the daily run decides)"
        elif removed:
            out.update(cut=True, reason="a critical or high finding removed: %s" % ", ".join(f["id"] for f in removed))
        else:
            out["reason"] = "no critical or high finding removed"
    elif daily_cut(True, cut_today):
        out.update(cut=True, reason="daily: shipped bytes ahead of the latest tag")
    else:
        out["reason"] = "a patch was already cut today"
    return out


def _scope(req):
    """admission reads `.scope // "push"`: absent, null or false is push (Codex #159 pin pass, B01)."""
    s = req.get("scope")
    return "push" if s is None or s is False else s      # identity, not ==: scope 0 is not push (Codex #159 r2, B6)


def ready(required, check_runs):
    """(verdict, why) for the tagged commit's push-scoped required checks, judged as source admission judges them
    (stage-admission.yml): a check counts only as a success from its pinned app. "ready": every one has one. "wait": none
    is red with nothing left to run (a run is missing, queued or in progress). "no": a check finished without success and
    no run of it is still pending. pull_request-scoped checks are admission's to read on the merged PR head."""
    waiting, red = [], []
    reqs = required.get("required_checks") if isinstance(required, dict) else None
    # a policy admission would reject is never ready (Codex #159 r1, B6): admission fails on these
    if not isinstance(reqs, list) or not reqs:
        return "no", "policy error: no required_checks list"
    for req in reqs:
        if not isinstance(req, dict) or not req.get("context") or not isinstance(req.get("integration_id"), int):
            return "no", "policy error: a required check without a context or integration_id"
        if _scope(req) not in ("push", "pull_request"):
            return "no", "policy error: unknown scope %r for required check %r" % (req.get("scope"), req["context"])
    for req in reqs:
        if _scope(req) != "push":
            continue
        mine = [r for r in check_runs if r.get("name") == req["context"] and r.get("app_id") == req["integration_id"]]
        if any(r.get("status") == "completed" and r.get("conclusion") == "success" for r in mine):
            continue
        if not mine or any(r.get("status") != "completed" for r in mine):
            waiting.append(req["context"])
        else:
            red.append(req["context"])
    if red and not waiting:
        return "no", "not green on the tagged commit: " + ", ".join(red)
    if waiting:
        return "wait", "waiting on: " + ", ".join(waiting)
    return "ready", "every push-scoped required check is green"


def _git(*args, cwd="."):
    return subprocess.run(["git", "-C", cwd] + list(args), capture_output=True, text=True, check=True).stdout


def gather_commits(since, cwd=".", labels=lambda sha: []):
    """The commits since a tag (oldest first) with the files each changes, each file's changed lines, and the labels of
    the PR that merged it (from `labels`; none when it cannot be read: a missing label never admits a change)."""
    out = []
    for sha in _git("rev-list", "--reverse", "%s..HEAD" % since, cwd=cwd).split():
        files = [f for f in _git("show", "--format=", "--name-only", sha, cwd=cwd).splitlines() if f]
        # full context: the classifier needs a go.mod line's block (require vs replace/exclude) to judge it
        diffs = {f: "\n".join(ln for ln in _git("show", "--format=", "--unified=100000", sha, "--", f, cwd=cwd).splitlines()
                              if ln[:1] in "+- " and not ln.startswith(("+++", "---")))
                 for f in files}
        # each file's mode after the commit (":old new oldsha newsha status\tpath"); 000000 is a deletion (Codex B01)
        modes = {}
        for ln in _git("diff-tree", "-r", "--no-commit-id", "--raw", "-M", sha, cwd=cwd).splitlines():
            meta, _, paths = ln.partition("\t")
            if meta.startswith(":"):
                modes[paths.split("\t")[-1]] = meta.split()[1]
        out.append({"sha": sha, "files": files, "diffs": diffs, "modes": modes, "labels": list(labels(sha))})
    return out


def grype_findings(doc):
    """Grype's matches, every fix version kept (B1). A document without a matches list is not a clean scan: refused
    (Codex #159 r1, B2)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("matches"), list):
        raise ValueError("not a grype scan: no matches list")
    out = []
    for m in doc["matches"]:
        # every field this decision reads has its type checked, so a malformed scan takes the handled path (refused
        # here) and never crashes the caller into a release-wide unknown (Codex #159 r3, NEW-1)
        v, a = (m.get("vulnerability"), m.get("artifact")) if isinstance(m, dict) else (None, None)
        if not isinstance(v, dict) or not isinstance(a, dict):
            raise ValueError("not a grype scan: a match without its vulnerability or artifact object")
        if not all(isinstance(x, str) and x for x in (v.get("id"), a.get("name"), a.get("version"))):
            raise ValueError("not a grype scan: a match without its id, package or version")   # Codex #159 r2, B2
        fix = v.get("fix") or {}
        fixed = fix.get("versions") or [] if isinstance(fix, dict) else None
        if not isinstance(fixed, list) or not all(isinstance(x, str) for x in fixed):
            raise ValueError("not a grype scan: fix.versions is not a list of versions")
        if not all(x is None or isinstance(x, str) for x in (v.get("severity"), a.get("type"))):
            raise ValueError("not a grype scan: a severity or package type that is not a string")
        out.append({"id": v.get("id"), "package": a.get("name"), "installed": a.get("version"), "severity": v.get("severity"),
                    "fixed": list(fixed),
                    "type": "go-module" if a.get("type") in ("go-module", "golang") else a.get("type")})
    return out


def gomod_versions(text):
    """{module: version} from go.mod, plus the toolchain as stdlib (go1.X.Y from the go directive)."""
    out = {m.group(1): m.group(2) for m in re.finditer(r"(?m)^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+(v\S+)", text)}
    m = re.search(r"(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$", text)
    if m:
        out["stdlib"] = "go" + m.group(1)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="patch-decide")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--event", choices=("push", "schedule", "workflow_dispatch"), required=True)
    d.add_argument("--repo", default=".")
    d.add_argument("--cut-today", choices=("true", "false"), required=True)
    d.add_argument("--removed", help="JSON list of the release's critical/high findings HEAD removes")
    d.add_argument("--removed-unknown", action="store_true", help="the latest release could not be scanned")
    d.add_argument("--released", required=True,
                   help="JSON list of the tags with a published release: the baseline is the latest of these, never a "
                        "tag whose release failed (Codex #159 r1, B4)")
    d.add_argument("--labels", help="JSON {sha: [labels]} of the PRs that merged each commit")
    d.add_argument("--out", required=True)
    k = sub.add_parser("ready")
    k.add_argument("--required", required=True, help=".github/policy/required-checks.json")
    k.add_argument("--check-runs", required=True, help="JSON list of the commit's check runs {name, status, conclusion, app_id}")
    r = sub.add_parser("removed")
    r.add_argument("--release-grype", required=True, action="append", help="one per scanned release image")
    r.add_argument("--gomod", required=True)
    r.add_argument("--base-grype", action="append", help="one per scanned base image")
    r.add_argument("--out", required=True)
    n = sub.add_parser("notes")
    n.add_argument("--version", required=True)
    n.add_argument("--variant-grype", required=True, action="append", help="VARIANT=scan.json; '' is the default image")
    n.add_argument("--gomod", required=True)
    n.add_argument("--base-grype", action="append", help="one per scanned base image; none: no deb fix is claimed")
    n.add_argument("--vex-old", help="the VEX document at the latest tag (absent: every statement is added)")
    n.add_argument("--vex-new", required=True)
    n.add_argument("--next-notes", required=True)
    n.add_argument("--published", required=True, help="every v* tag message and CHANGELOG.md, concatenated")
    n.add_argument("--out", required=True)
    sub.add_parser("tag-notes", help="stdin: git cat-file tag; stdout: a generated patch tag's notes, else exit 1")
    c = sub.add_parser("changelog")
    c.add_argument("--notes", required=True)
    c.add_argument("--changelog", required=True)
    c.add_argument("--next-notes", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "notes":
        try:
            rel = {}
            for v in a.variant_grype:
                name, _, path = v.partition("=")
                rel[name] = grype_findings(json.load(open(path)))
            base = [f for p in a.base_grype for f in grype_findings(json.load(open(p)))] if a.base_grype else None
            nn = open(a.next_notes).read() if os.path.exists(a.next_notes) else ""     # no file: no entries
            behavior = unpublished(behavior_entries(nn), open(a.published).read())
            old = json.load(open(a.vex_old)) if a.vex_old else None
            if a.vex_old and old is None:       # a supplied file holding null is not "no old document" (Codex #300 r2, B)
                raise ValueError("VEX old document %s: null" % a.vex_old)
            fixes = fixed_findings(rel, {"go": gomod_versions(open(a.gomod).read()), "base_findings": base})
            text = notes(a.version, fixes, vex_changes(old, json.load(open(a.vex_new))), behavior=behavior)
        except (ValueError, OSError, KeyError, TypeError) as e:
            print("notes: %s — no notes, no patch" % _clean(str(e)), file=sys.stderr)
            return 2
        with open(a.out, "w") as fh:
            fh.write(text)
        return 0
    if a.cmd == "tag-notes":
        t = tag_notes(sys.stdin.read())
        if t is None:
            return 1
        sys.stdout.write(t)
        return 0
    if a.cmd == "changelog":
        cl_path = a.changelog
        old_cl = open(cl_path, newline="").read() if os.path.exists(cl_path) else None    # line ends as stored (r5)
        has_nn = os.path.exists(a.next_notes)
        try:
            new_cl, new_nn = changelog(open(a.notes).read(), old_cl, open(a.next_notes).read() if has_nn else "")
        except ValueError as e:
            print("changelog: %s — nothing written" % _clean(str(e)), file=sys.stderr)
            return 2
        with open(cl_path, "w") as fh:
            fh.write(new_cl)
        if has_nn:
            with open(a.next_notes, "w") as fh:
                fh.write(new_nn)
        return 0
    if a.cmd == "ready":
        verdict, why = ready(json.load(open(a.required)), json.load(open(a.check_runs)))
        print(verdict, _clean(why))
        return 0
    if a.cmd == "removed":
        try:
            release = [f for p in a.release_grype for f in grype_findings(json.load(open(p)))]
        except (ValueError, OSError) as e:
            print("removed: the release scan is unusable: %s" % e, file=sys.stderr)
            return 2
        try:
            base = [f for p in a.base_grype for f in grype_findings(json.load(open(p)))] if a.base_grype else None
        except (ValueError, OSError):
            base = None                     # an unusable base scan removes no deb finding
        found = removed_critical_high(release, {"go": gomod_versions(open(a.gomod).read()), "base_findings": base})
        with open(a.out, "w") as fh:
            json.dump(found, fh, indent=1)
        return 0
    tags = [t for t in _git("tag", "-l", "v*", cwd=a.repo).split()]
    released = [t for t in json.load(open(a.released)) if _semver(t) and t in tags]
    since = max(released, key=_semver) if released else None
    labels = json.load(open(a.labels)) if a.labels else {}
    commits = gather_commits(since, a.repo, labels=lambda sha: labels.get(sha, [])) if since else []
    removed = None if a.removed_unknown else json.load(open(a.removed)) if a.removed else []
    event = "schedule" if a.event == "workflow_dispatch" else a.event
    # no published release yet: the first release is the owner's, whatever tags a failed attempt left
    dec = decide(event, commits, tags if since else [], a.cut_today == "true", removed)
    dec["since"] = since
    # decision.json feeds a public issue (the "not patch-clean" list): every string in it is redacted as stdout is
    dec = {k: ([_clean(x) for x in v] if isinstance(v, list) else _clean(v) if isinstance(v, str) else v)
           for k, v in dec.items()}
    with open(a.out, "w") as fh:
        json.dump(dec, fh, indent=1)
    print(_clean("patch decision: %s — %s" % ("cut " + dec["version"] if dec["cut"] else "no cut", dec["reason"])))
    for w in dec["not_clean"]:
        print(_clean("  not patch-clean: " + w))
    return 0


if __name__ == "__main__":
    sys.exit(main())
