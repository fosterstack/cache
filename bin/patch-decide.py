#!/usr/bin/env python3
"""The automatic patch-release decision (owner RATIFIED Oct 2: ops/docs/ratify/2026-10-02-automatic-patch-releases.md,
with the floating-tags amendment; advisor read-backs 0051/0055/0056; REQ-REL-009).

  classify / patch_clean  rule 1: a patch carries fixes only. Each commit since the latest tag is, by the files it
                          changes, fix-class (dependency version pins of existing modules in go.mod/go.sum, the
                          base inputs listed in .github/policy/base-inputs.json (the apko base locks, the melange
                          lock and the archive records: no base image exists, rules 61 and 62), the VEX and suppression files), neutral
                          (no shipped byte: .github/, docs/, requirements/, test-evidence/, tests) or not patch-clean
                          (anything else, unless its merged PR carries the `patch-fix` label, which the owner applies,
                          or the lane only when both step-8 reviewers recorded "no behavior change").
  next_patch              rule 1: vX.Y.Z -> vX.Y.(Z+1); CI never makes a minor or major.
  daily_cut               rule 2: at most one daily patch (a critical/high fix may cut at once, outside this rule).
  notes                   rule 5: per fix the CVE, package, old -> new, severity, variants; each VEX change; a
                          no-behavior-change line, or (advisor 0130) the behavior changes listed in
                          docs/next-release-notes.md, each citing the handoff that judged it; no vendor or model names.
                          Its sources are refused, never rewritten, when a line holds a form Markdown could hide text in
                          (REQ-REL-009-AC14, advisor step 5): file:line, exit 2, nothing written.
  removed_critical_high   rule 2: the latest release's critical/high findings that HEAD removes (a Go module or the
                          toolchain at or past the advisory's fixed version; a distribution package the new base
                          no longer reports, only with base evidence, which the chain does not produce today);
                          unknown or unreadable never counts as removed.
  base-moved              the base inputs of the list that differ between a release tag and HEAD (the decide job
                          prints them: the "base input changed" signal).
  floating                amendment: :X.Y always; :X and :latest only when this is the highest released version.
"""
import argparse, html, json, os, re, subprocess, sys, unicodedata
FIX_EXACT = {".snyk", "osv-scanner.toml"}
# data that ships nothing: the auditor's own work (three names) and the .vex README (REQ-REL-009 AC15); every other path under .vex/ and .auditor/ stays fix-class
NEUTRAL_EXACT = {".auditor/panel-state.json", ".auditor/knowledge.md", ".vex/README.md"}
NEUTRAL_PROPOSALS = re.compile(r"^\.auditor/proposals/[^/]+\.json$")
FIX_PREFIX = (".vex/", ".auditor/")
NEUTRAL_PREFIX = (".github/", "docs/", "requirements/", "test-evidence/")
# The base inputs are DATA in one committed file, read by the decide job (through `base-moved`) and by `classify` here (rules 61 and 65; advisor Oct 12): a change
# in a listed lock or record is the "base input changed" signal, fix-class (the daily refresh PRs change exactly these). The recipes (build/apko*.yaml,
# build/melange*.yaml) declare the build and are build inputs, never base signals: they fall to the shipped-source rule.
BASE_INPUTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "policy", "base-inputs.json")
_BASE_INPUTS = {}


def load_base_inputs(path=None):
    """The listed base-input paths, fail closed: a file that is missing, not JSON, without a non-empty `base_inputs` list of unique plain relative paths
    (no leading / or ./, no .. or empty segment, no glob, backslash or trailing /) is a ValueError, never an empty list."""
    path = path or BASE_INPUTS_FILE
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as e:
        raise ValueError("the base-input list %s is unreadable: %s" % (path, e))
    items = doc.get("base_inputs") if isinstance(doc, dict) else None
    if not isinstance(items, list) or not items:
        raise ValueError("the base-input list %s has no non-empty base_inputs list" % path)
    seen = set()
    for it in items:
        if not isinstance(it, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*", it) or "\\" in it:
            raise ValueError("the base-input list %s names %r, which is not a plain relative file path" % (path, it))
        if it in seen:
            raise ValueError("the base-input list %s names %s twice" % (path, it))
        seen.add(it)
    return list(items)


def _base_inputs(given=None):
    if given is not None:
        return given
    if "list" not in _BASE_INPUTS:
        _BASE_INPUTS["list"] = load_base_inputs()
    return _BASE_INPUTS["list"]
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


def _alone(m, mark="<redacted>"):
    text, i, j = m.string, m.start(), m.end()
    while i > 0 and not text[i - 1].isspace() and text[i - 1] not in "([{\"'<,;":
        i -= 1
    while j < len(text) and not text[j].isspace() and text[j] not in ")]}\"'>,;":
        j += 1
    token = text[i:j].rstrip(".:")
    return m.group(0) if MODULE_PATH.match(token) else mark


# the release chain's build inputs shape the shipped image: never neutral (Codex #158 r1, B04). Fail closed (Sonnet #158 r2,
# NEW-01): a workflow is neutral only when it is reviewed as outside the release chain (release.yml calls stage-*.yml and
# the acceptance workflows); any other — including one added later — is not patch-clean until it is reviewed here.
NEUTRAL_WORKFLOWS = {"agent-review-gate.yml", "auditor.yml", "ci.yml", "codeql.yml", "dependabot-auto-merge.yml",
                     "dependabot-reviewer.yml", "go-freshness.yml", "main-candidate-rescan.yml",
                     "reserved-branch-guard.yml", "scan.yml", "scorecard.yml"}
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


DATA_FILE = re.compile(r"\.(md|txt|json|ya?ml|toml|csv)$")


# REQ-REL-009 AC1 (owner RATIFIED Oct 3, item h): an executable test is never patch-neutral
TEST_FILE = re.compile(r"(-tests?\.sh|_test\.go|(^|/)test_[^/]*\.py|-check\.py)$|^\.github/agent/(bin/)?tests/")


def _reviewed_workflow(f):
    """A reviewed workflow by its full path, .github/workflows/<name> — never a same-named file deeper (Codex B02)."""
    return f.count("/") == 2 and f.split("/")[-1] in NEUTRAL_WORKFLOWS


SHEBANG_LINE = re.compile(r"(?m)^#!")


def _not_data(f, diff, mode, old_mode, contents=None):
    """why a neutral-named path is not data (None when it is): its file types before and after, and its committed content.
    A script line is a shebang line (`#!` at the start of ANY line); it is looked for in the whole new content and in the
    whole old content (what a commit deletes or replaces), read from the blobs in `contents`; a record without them is not proven data (fail closed)."""
    if old_mode in ("100755", "120000"):
        return "%s was %s before: not data" % (f, "a symlink" if old_mode == "120000" else "executable")
    if mode != "000000" and mode != "100644":
        return "%s has mode %s; data is a regular non-executable file (100644)" % (f, mode or "?")
    if old_mode not in ("000000", "100644"):
        return "%s has no usable old file type (%s): a neutral path is data only when its file type before and after is known" % (f, old_mode or "missing")
    if mode == "000000" and old_mode != "100644":
        return "%s is deleted and its old file type is unknown" % f
    if not isinstance(contents, dict) or "old" not in contents or "new" not in contents:
        return "%s has no whole-blob evidence (old and new content): not proven data" % f
    old_text, new_text = contents["old"], contents["new"]
    if (old_mode == "100644" and old_text is None) or (mode == "100644" and new_text is None):
        return "%s: a blob that exists could not be read: not proven data" % f
    for label, text in (("new", new_text), ("old", old_text)):
        if text is not None and ("\0" in text):
            return "%s holds NUL or non-text bytes (%s content): not text" % (f, label)
        if text is not None and SHEBANG_LINE.search(text):
            return "%s has a shebang line in its %s content: a script, not data" % (f, label)
    if mode == "000000":
        return None
    if new_text is None:
        return "%s shows no content (binary, or a mode-only change): not proven data" % f
    return None


def classify(commit, base_inputs=None):
    """('fix' | 'neutral' | 'dirty', reason) for one commit. Neutral means non-executable data only — docs/, requirements/,
    test-evidence/ data and the reviewed .github files; an executable test never counts (REQ-REL-009 AC1, owner Oct 3).
    base_inputs: the listed base-input paths (default: .github/policy/base-inputs.json, loaded once, fail closed)."""
    files, diffs, modes = commit.get("files") or [], commit.get("diffs") or {}, commit.get("modes") or {}
    kinds, why = set(), []
    base = _base_inputs(base_inputs)
    hard = False      # a base input deleted, made executable or a symlink, or without mode evidence: no label upgrades it (an image change is not "no behavior change")
    old_modes = commit.get("old_modes") or {}
    for f in files:
        if f in NEUTRAL_EXACT or NEUTRAL_PROPOSALS.match(f):
            # neutral only as DATA, proven from the committed content and the old and new file types (REQ-REL-009 AC15)
            bad = _not_data(f, diffs.get(f), modes.get(f), old_modes.get(f), (commit.get("contents") or {}).get(f))
            if bad:
                kinds.add("dirty"); why.append(bad); hard = True       # no label turns this into a fix
            else:
                kinds.add("neutral")
        elif f in base and modes.get(f) is None:
            kinds.add("dirty"); hard = True; why.append("%s has no mode evidence: a base input is a refresh only with its file mode known" % f)
        elif f in base and modes.get(f) == "000000":
            kinds.add("dirty"); hard = True; why.append("%s is deleted: a base input removed is not a refresh" % f)
        elif f in base and modes.get(f) != "100644":
            kinds.add("dirty"); hard = True; why.append("%s has mode %s: a base input is a regular non-executable file (100644), never a refresh when it is not" % (f, modes.get(f)))
        elif modes.get(f) in ("100755", "120000") or re.search(r"(?m)^\+#!", diffs.get(f) or ""):
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
        elif f in base:
            kinds.add("fix")           # a base lock or record moved (rules 61, 65): the whole file is the signal, no line parsing
        elif f.startswith(".github/workflows/") and not _reviewed_workflow(f):
            kinds.add("dirty"); why.append("%s builds or ships the release image" % f)
        elif f.startswith(".github/") and not f.startswith(".github/workflows/") \
                and f not in NEUTRAL_GITHUB and not f.startswith(NEUTRAL_GITHUB_PREFIX):
            kinds.add("dirty"); why.append("%s is read by the release chain (or not reviewed as outside it)" % f)
        elif f.startswith(NEUTRAL_PREFIX):
            kinds.add("neutral")
        else:
            kinds.add("dirty"); why.append("%s is shipped source or configuration" % f)
    if "dirty" in kinds and not hard and "patch-fix" in (commit.get("labels") or []):
        return "fix", "labelled patch-fix (no behavior change)"
    if "dirty" in kinds:
        return "dirty", "; ".join(why)
    return ("fix" if "fix" in kinds else "neutral"), ""


def ships_bytes(commits, base_inputs=None):
    return any(classify(c, base_inputs)[0] == "fix" for c in commits)


def patch_clean(commits, base_inputs=None):
    """(True, []) when every commit is fix-class or neutral and at least one ships bytes; (False, why) otherwise
    (why is empty when nothing would ship)."""
    why = ["%s: %s" % (c.get("sha", "?")[:7], r) for c in commits for k, r in [classify(c, base_inputs)] if k == "dirty"]
    if why:
        return False, why
    return ships_bytes(commits, base_inputs), []


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


def _clean_value(v):
    """a VEX value redacted for its quoted form (_lit): each vendor or model name replaced as _clean replaces it, the
    code writing the visible marker '(redacted)' itself. Nothing in the value is converted into the marker: a value
    holding a marker form is refused before this runs (_marker_form; advisor narrow cut, Codex #300 b11, B item 2)"""
    return VENDOR_ALONE.sub(lambda m: _alone(m, "(redacted)"), VENDOR.sub("(redacted)", str(v)))


def _visible(s):
    """Markdown output (notes, changelog, tag notes): the redaction marker as visible text — "<redacted>" parses as an
    HTML tag and renders as nothing (Codex #300 r4, B low). Lines only: a VEX value is never converted (_lit; Codex #300
    b11, B item 2: a value holding a marker form is refused, _marker_form)"""
    return s.replace("<redacted>", "(redacted)")


def _clean_md(s):
    """_clean for Markdown output, with the visible marker"""
    return _visible(_clean(s))


PUNCT = r"!-/:-@\[-`{-~"                         # every ASCII punctuation character (CommonMark: each may be escaped)
ESC = re.compile(r"([%s])" % PUNCT)
ESCAPED = re.compile(r"(?:\\[%s]|[^%s])*\Z" % (PUNCT, PUNCT))
UNESC = re.compile(r"\\([%s])" % PUNCT)
MARKS = ("(redacted)", "\\(redacted\\)")         # the marker as the notes print it, and as it renders after one escape
FREE_PRE = re.compile(r"- |#{1,6} ")             # a bullet or an ATX heading stays one
# the marker the code writes and the one the notes print, as written or in its Markdown-escaped form, any case
MARKER_FORM = re.compile(r"(?i)<redacted>|\(redacted\)|\\<redacted\\>|\\\(redacted\\\)")
JSON_ESC = re.compile(r'\\(?:u([0-9A-Fa-f]{4})|(["\\/bfnrt]))')
JSON_CHAR = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _json_body(s):
    """s read once as the body of a JSON string (the printer's quoted form): \\uXXXX and the two-character escapes"""
    return JSON_ESC.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else JSON_CHAR[m.group(2)], s)


def _readings(s):
    """the one definition of the readings of a string (advisor (c), Codex #300 b13: the readers recognise exactly what the
    refusal refuses): as written, with the Markdown backslash escapes undone once, as a JSON string body, with its HTML
    character references decoded. _marker_form searches all four; _marked (the readers) uses the first two; each alone, once"""
    return (s, UNESC.sub(r"\1", s), _json_body(s), html.unescape(s))


def _marker_form(v):
    """v holds a redaction-marker form the printer or the readers recognise: '<redacted>' or '(redacted)' in any case, or
    its Markdown-escaped form ('\\<redacted\\>', '\\(redacted\\)'), found in v as written, in v read once with the
    Markdown backslash escapes undone (what _marked and _clean_free read), in v read once as a JSON string body (the
    printer's quoted form: '\\u003c', '\\u0028', '\\\\'), or in v read once with its HTML character references decoded
    ('&lt;', '&#60;', '&#x3c;', '&lpar;'). Each reading is applied alone and once: a spelling that needs two readings,
    nested or mixed, a percent-encoding or a compatibility form (fullwidth) is not decoded and is an ordinary value,
    printed quoted (advisor cut after Codex #300 b12, B Medium: the nested, iterated decoding is deleted). A VEX value
    holding a marker form is refused before any redaction, never converted (advisor narrow cut, Codex #300 b11, B item
    2: a literal marker turned into the printed one lost the statement's identity)."""
    return any(MARKER_FORM.search(t) for t in _readings(str(v)))


def _marked(s):
    """s holds the marker, as written or read unescaped once (Codex #300 r8: the historical forms are cut back, advisor
    step 5: no published text ever held '<redacted>' or another form, and a source holding '<' before a letter is refused,
    REQ-REL-009-AC14; 'notredacted' is not the marker, r7 A medium)"""
    return any(m in t for m in MARKS for t in _readings(s)[:2])


def _own_form(body):
    """body is a line this printer wrote: every punctuation character escaped, and the marker in it, the line read ONCE
    (a second unescape would recognise a spelling the refusal does not cover; advisor (c), Codex #300 b13)"""
    return bool("\\" in body and ESCAPED.match(body) and _marked(body))


def _clean_free(line):
    """one line of free text (a fix line, a behavior entry, a VEX line, any line of a tag's own text) for
    Markdown output: the escape-whole-line rule (Codex #300 r5, A R4-4 / B F3; r8, advisor step 5). A line whose cleaned
    text holds the marker is written with every ASCII punctuation character backslash-escaped, the marker '\\(redacted\\)':
    no link, image, HTML, code span or other construct can take it into its syntax; any other line is _clean's output
    unchanged. A line already in that escaped form that holds the marker is read unescaped, cleaned and escaped again, so
    cleaning twice changes nothing; a line without the marker is never read as escaped ('google\\.com' is redacted as
    before round 5; r6, A (d) / B F6). A leading '- ' bullet or an ATX heading's '#... ' stays one."""
    m = FREE_PRE.match(line)
    pre = m.group(0) if m else ""
    body = line[len(pre):]
    own = _own_form(body)                       # this function's own form
    raw = UNESC.sub(r"\1", body) if own else body
    c = _visible(_clean(raw))
    return pre + (ESC.sub(r"\\\1", c) if _marked(c) else c)


VEX_HEAD = "### VEX"


def _clean_lines(s):
    """the notes text cleaned one line at a time, split at every line boundary str.splitlines() knows (LF, CR, CRLF, VT,
    FF, FS, GS, RS, NEL, LS, PS), each written back as LF: no redaction ever matches across a line break and merges two
    lines (Codex #300 r3 B1; r4 A R3-4, B low). Every line, a VEX line too, is written by _clean_free, the one function
    notes() prints each line with: the notes' own lines read back unchanged (advisor decision Oct 11: no VEX exemption)."""
    parts = str(s).splitlines(True)
    out = []
    for ln in parts:
        body = (ln.splitlines() or [""])[0]
        out.append(_clean_free(body) + ("\n" if len(body) < len(ln) else ""))
    return "".join(out)


# REQ-REL-009-AC14 (advisor step 5, Oct 11; owner rule 5): the notes sources are refused outright, never decoded, escaped or
# rewritten, when a line holds one of these forms. The reference-definition shape is read after any list or quote markers
# and indentation (a definition can open inside a list item, '-  [x]: /u', or after an item that starts blank,
# '-\n    [x]: /u'), and a '[' label left open at the line end is refused too (a label may span lines): wider than
# CommonMark, fail closed. 'Letter' after '<' is any Unicode letter (str.isalpha).
REFDEF = re.compile(r"(?:[ \t]*(?:>|(?:[-+*]|\d{1,9}[.)])(?=[ \t]|$)))*[ \t]*\[(?:[^\]\\]|\\.)*(?:\]:|$)")
CHARREF = re.compile(r"&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);")
SIG_DELIM = "-----BEGIN "


def _refused_form(line):
    """why REQ-REL-009-AC14 refuses this line, or None"""
    line = str(line)
    if any(c == "<" and i + 1 < len(line) and (line[i + 1] in "/!?" or line[i + 1].isalpha()) for i, c in enumerate(line)):
        return "'<' before a letter, '/', '!' or '?'"
    if REFDEF.match(line):
        return "the shape of a link reference definition"
    if CHARREF.search(line):
        return "a character reference"
    if SIG_DELIM in line:
        return "the signature delimiter '-----BEGIN '"
    return None


def _refuse_text(text, name):
    """refuse (ValueError naming name:line) a text any line of which holds a refused form: every line, a line of a
    '### VEX' section too (advisor decision Oct 11: no VEX exemption; _lit prints no refused form in a VEX line)"""
    for n, ln in enumerate(str(text).splitlines(), 1):
        why = _refused_form(ln)
        if why:
            raise ValueError("%s:%d: %s" % (name, n, why))


def _no_dup_bullets(text, name):
    """refuse (ValueError naming both name:line) two '- ' lines of one release block (from one '## ' heading to the next)
    that publish the same line, trailing whitespace ignored (REQ-REL-009-AC14 (5) in the readers: a tag's notes, the
    changelog's notes, the history; Codex #300 r9, B 4). Each line is compared as it is published, cleaned by _clean_free
    ('- gpt' and '- claude' publish the same line; so do a marker line and its escaped spelling: Codex #300 r10, A medium /
    B 2), and named by its source line; the raw lines are checked for the refused forms by _refuse_text. The same line in
    two release blocks is a repetition across releases, not a collision."""
    seen = {}
    for n, ln in enumerate(str(text).splitlines(), 1):
        c = _clean_free(ln)                 # the line as published: compared cleaned, named by its source line (r10, A / B 2)
        if c.startswith("## "):
            seen = {}
        elif c.startswith("- "):
            k = c.rstrip()
            if k in seen:
                raise ValueError("%s:%d: %s:%d: two entries publish the same line" % (name, seen[k], name, n))
            seen[k] = n


ATX = re.compile(r"#{1,6}(?:[ \t]|$)")


def _refuse_continued_marker(text, name):
    """refuse (ValueError naming name:line) a cleaned text in which a free-text line holding the marker continues the line
    above it — not a '- ' bullet or a heading, and right after a line that is neither blank nor a heading. Only a line
    that starts a block shows the marker as text: a link title, link destination or any other construct opened on the line
    above can take a continuation line into its syntax, and escaping that line cannot stop it (Codex #300 r8, B F5); a
    bullet or heading interrupts any paragraph, and no inline construct crosses a blank line. Refused, never rewritten."""
    lines = str(text).splitlines()
    for n, ln in enumerate(lines):
        if FREE_PRE.match(ln) or not _marked(ln):
            continue
        prev = lines[n - 1] if n else ""
        if prev.strip() and not ATX.match(prev):
            raise ValueError("%s:%d: a line holding the marker continues the line above it (a construct spanning lines could "
                             "hide the marker)" % (name, n + 1))


def _refused_value(v):
    """why REQ-REL-009-AC14 refuses a source value, or None: each of its own lines (every boundary str.splitlines() knows),
    checked before it is made one line, then its one-line form (Codex #300 r8, B F2)"""
    for ln in str(v).splitlines():
        why = _refused_form(ln)
        if why:
            return why + " (a line of the value)"
    return _refused_form(_oneline(v))


def _no_collision(items):
    """items: (published line, location 'file:line:'); two that publish the same line (trailing whitespace ignored, as
    'already published' reads it) are refused, both named (REQ-REL-009-AC14 (5))"""
    seen = {}
    for line, loc in items:
        k = line.rstrip()
        if k in seen:
            raise ValueError("%s %s two entries publish the same line" % (seen[k], loc))
        seen[k] = loc


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
NOT_BARE = re.compile(r"-----|(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])|:[A-Za-z0-9_+-]+:|//|(?i:www)\.|(?i:(?<![A-Za-z0-9])gh(?:sa)?-)|"
                      r"(?<![A-Za-z0-9])[0-9a-fA-F]{7,}(?![A-Za-z0-9])")


def _lit(v, before_colon=False):
    """the printed form of a document-supplied value; before_colon: the notes print ':' right after it (a CVE name). A
    value holding five hyphens is never bare (a space the notes print after it would complete '-----BEGIN '; Codex #300
    r7, B F4), and in the quoted form a hyphen followed by four more is written \\u002d (the same JSON string): no run of
    five hyphens, a signature-block delimiter, is ever printed, so the tag of the notes stays readable (r6, B F4). In the
    quoted form '<' and '&' are written \\u003c and \\u0026 (the same JSON string; advisor decision Oct 11, option A): no
    printed value holds a refused form of REQ-REL-009-AC14, so the notes' own VEX lines pass every reader with no
    exemption. A reader sees the JSON string: a statement named <b>x shows as "\\u003cb\\u003ex" in its code span. The
    quoted value is redacted before it is encoded, so a vendor or model name right after an escaped character is
    redacted as it would be in plain text (Codex #300 r10, B 1); vex_changes names a statement whose name or @id redaction
    changes by its position. A value holding a redaction-marker form (_marker_form) is refused (ValueError) before any
    redaction; the redaction of a vendor or model name is written as the visible '(redacted)' directly, and no value is
    ever converted into the marker (advisor narrow cut, Codex #300 b11, B item 2)."""
    v = str(v)
    if _marker_form(v):
        raise ValueError("a VEX value holds a redaction-marker form (refused, never converted)")
    if BARE.match(v) and not NOT_BARE.search(v + (":" if before_colon else "")):
        return v
    # the value is redacted as text BEFORE it is encoded: an escape ('<' -> \u003c) ends in a letter or digit and would
    # erase the word boundary the redactor reads ('<google', '&o1'; Codex #300 r10, B 1)
    return "`%s`" % re.sub(r"-(?=----)", r"\\u002d", json.dumps(_clean_value(v), ensure_ascii=True).replace("`", "\\u0060")
                           .replace("<", "\\u003c").replace("&", "\\u0026"))


CITED = re.compile(r"\((?:[^()]*[\s;,])?(?:advisor|handoff) \d{4}\)\.?$")


def _entries(text):
    """[entry, line number of its bullet] of a next-release-notes text: each "- " bullet, its indented continuation lines
    joined"""
    out = []
    for n, ln in enumerate(text.splitlines(), 1):
        if ln.startswith("- "):
            out.append([ln[2:].strip(), n])
        elif out and ln.startswith("  ") and ln.strip():
            out[-1][0] += " " + ln.strip()
    return out


def _source_entries(text, name):
    """the entries of a next-release-notes text read as a notes source (REQ-REL-009-AC14): every line of the file, and
    every entry with its lines joined as notes() prints it, is refused (ValueError naming name:line) when it holds a
    refused form; two entries whose published lines are the same line are refused, both named"""
    _refuse_text(text, name)
    ents = _entries(text)
    for e, n in ents:
        why = _refused_form("- " + _oneline(e))
        if why:
            raise ValueError("%s:%d: %s (the entry, its lines joined)" % (name, n, why))
    _no_collision([(_entry_line(e), "%s:%d:" % (name, n)) for e, n in ents])
    return ents


def behavior_entries(text, name="docs/next-release-notes.md", located=False):
    """The entries of docs/next-release-notes.md (advisor 0130). An entry is only a change the owner or the advisor judged
    unable to affect supported clients, so each must end by citing that handoff, "(... advisor NNNN)"; an entry without
    one is refused (ValueError) and nothing is cut. The file is a notes source (REQ-REL-009-AC14): a refused form or two
    entries publishing the same line are refused, naming name:line. located: each entry with its location 'name:line:'."""
    ents = _source_entries(text, name)
    for e, n in ents:
        try:
            _check_entry(e)
        except ValueError as x:
            raise ValueError("%s:%d: %s" % (name, n, x))
    return [(e, "%s:%d:" % (name, n)) for e, n in ents] if located else [e for e, _ in ents]


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


FIX_FIELDS = ("cve", "package", "old", "new", "severity")


def _fix_raw(f):
    """the fix line of one fix record before cleaning (one line)"""
    return _oneline("- %s in %s: %s → %s (severity %s; variants: %s)" % (
        f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or [])))


def notes(version, fixes, vex_changes, behavior=(), fix_locs=None, behavior_locs=None):
    """every line is one line (_oneline) cleaned on its own by _clean_free, a VEX line too (its document values are bare
    identifier text or code spans, _lit; a line holding the marker is written escaped, Codex #300 r5). The fix records and behavior entries are notes sources
    (REQ-REL-009-AC14): a field (each of its own lines, then its one-line form; r8 B F2), a fix line or an entry holding a
    refused form is refused (ValueError), and so are any two published lines — fix, VEX or behavior — that are the same
    line (one set across all of them, r8 B medium); fix_locs / behavior_locs name each record's source ('scan:matches[i]:',
    'file:line:'; else 'fix record N:' / 'behavior entry N:'). The written text is checked to hold no refused form on any
    line, its VEX section included (advisor decision Oct 11: no exemption), and to read back unchanged as a tag's notes."""
    fix_locs = list(fix_locs) if fix_locs is not None else ["fix record %d:" % i for i in range(1, len(fixes) + 1)]
    behavior_locs = (list(behavior_locs) if behavior_locs is not None
                     else ["behavior entry %d:" % i for i in range(1, len(behavior) + 1)])
    for f, loc in zip(fixes, fix_locs):
        for k in FIX_FIELDS:
            why = _refused_value(f[k])
            if why:
                raise ValueError("%s %s: %s" % (loc, k, why))
        for v in f.get("variants") or []:
            why = _refused_value(v)
            if why:
                raise ValueError("%s variant: %s" % (loc, why))
        why = _refused_form(_fix_raw(f))
        if why:
            raise ValueError("%s its fix line: %s" % (loc, why))
    for b, loc in zip(behavior, behavior_locs):
        _check_entry(b)
        why = _refused_value(b) or _refused_form("- " + _oneline(b))
        if why:
            raise ValueError("%s %s" % (loc, why))
    fl = [_clean_free(_fix_raw(f)) for f in fixes]
    published = list(zip(fl, fix_locs))
    lines = [_clean_free("## %s — patch release" % _oneline(version)), "", "### Fixes"] + fl
    if not fixes:
        lines.append("- none (dependency or VEX maintenance only)")
        published.append((lines[-1], "the Fixes section:"))
    lines += ["", "### VEX"]
    stmts = [v for v in vex_changes if "document" not in v]
    # a VEX line is printed by _clean_free like every other line, the function every reader cleans each line with (advisor
    # decision Oct 11: no VEX exemption; one printer, so a printed line is never refused by its own reader: Codex #300 r9,
    # A (a)(2) / B 3); unmarked, it is _clean_md's text, so vex_changes' checks of the rendered line still hold
    vl = [_clean_free(_vex_line(v)) for v in stmts]
    if len(set(vl)) != len(vl):  # every published statement line is its own (Codex #300 r3)
        raise ValueError("VEX notes: two statement lines read alike")
    lines += vl
    lines += [_clean_free("- document fields changed (%s)%s" % (", ".join(_lit(k) for k in v["document"]),
                                                               "" if stmts else "; no statement changed"))
              for v in vex_changes if "document" in v]
    if not vex_changes:
        lines.append("- no change")
    vex_lines = lines[lines.index(VEX_HEAD) + 1:]
    published += [(ln, "VEX line %d:" % i) for i, ln in enumerate(vex_lines, 1)]
    bl = [_entry_line(b) for b in behavior]
    published += list(zip(bl, behavior_locs))
    _no_collision(published)        # one set across every published line: fix, VEX and behavior (Codex #300 r8, B medium)
    if behavior:
        lines += ["", "### Behavior changes"] + bl
    else:
        lines += ["", "No behavior change: this release contains fixes only."]
    text = "\n".join(lines) + "\n"
    _refuse_text(text, "notes")      # fail closed: no refused form on any line of the published text (AC14; no exemption)
    if _clean_lines(text) != text:
        raise ValueError("notes: the tag of these notes would not read back unchanged")
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


def _fixing(release_by_variant, head):
    """(variant, index, finding, the version HEAD fixes it at) for each finding HEAD fixes, in reading order: variants
    sorted, each scan in document order. fixed_findings prints a record from the first of these for its CVE and package,
    and check_fix_sources judges that same one (Codex #300 r8, A medium / B F3)"""
    for variant in sorted(release_by_variant):
        for i, f in enumerate(release_by_variant[variant]):
            new = _fixed(f, head)
            if new is not None:
                yield variant, i, f, new


def fixed_findings(release_by_variant, head):
    """AC8: every finding of the latest release (any severity) that HEAD fixes, one per CVE and package, with the image
    variants it was found in ("" is the default image). release_by_variant: {variant: [grype findings]}. The record's
    old version, fix and severity come from the first fixing match (_fixing)."""
    out = {}
    for variant, _, f, new in _fixing(release_by_variant, head):
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

    def printed_values(s_):
        """(field, value) of every string of a statement the notes can print: its vulnerability name, its @id, each
        product's and subcomponent's @id and identifiers, and its field names (advisor narrow cut, Codex #300 b11)"""
        yield "vulnerability.name", s_["vulnerability"]["name"]
        if isinstance(s_.get("@id"), str):
            yield "@id", s_["@id"]
        for k in s_:
            yield "a field name", k

        def comp(c, at):
            if isinstance(c.get("@id"), str):
                yield at + ".@id", c["@id"]
            if isinstance(c.get("identifiers"), dict):
                for k, v in c["identifiers"].items():
                    yield "%s.identifiers.%s" % (at, k), k
                    if isinstance(v, str):
                        yield "%s.identifiers.%s" % (at, k), v
        for i, p in enumerate(s_.get("products") if isinstance(s_.get("products"), list) else [], 1):
            if isinstance(p, dict):
                yield from comp(p, "products[%d]" % i)
                for j, c in enumerate(p.get("subcomponents") if isinstance(p.get("subcomponents"), list) else [], 1):
                    if isinstance(c, dict):
                        yield from comp(c, "products[%d].subcomponents[%d]" % (i, j))

    def by_cve(doc, side):
        if not isinstance(doc, dict) or not isinstance(doc.get("statements"), list):
            raise ValueError("VEX %s document: not an object with a statements array" % side)
        for k in doc:
            if _marker_form(k):
                raise ValueError("VEX %s document: a document field name holds a redaction-marker form (refused, never "
                                 "converted)" % side)
        out, ids = {}, {}
        for pos, s_ in enumerate(doc["statements"], 1):
            v_ = s_.get("vulnerability") if isinstance(s_, dict) else None
            if not isinstance(v_, dict) or not isinstance(v_.get("name"), str):    # "" is schema-valid (r3, A3)
                raise ValueError("VEX %s document: statement %d has no vulnerability name" % (side, pos))
            if not isinstance(s_.get("status"), str) or s_["status"] not in VEX_STATUS:
                raise ValueError("VEX %s document: statement %d has no OpenVEX status" % (side, pos))
            for field, val in printed_values(s_):
                if _marker_form(val):
                    raise ValueError("VEX %s document: statement %d: %s holds a redaction-marker form (refused, never "
                                     "converted)" % (side, pos, field))
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
                if sid is not None and _clean(sid) != sid:     # redaction changes the @id: named by position (r10, B 1)
                    sid = None
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
        # redaction changes the CVE name as text (the value _lit redacts before encoding it) or as printed: by position
        if _clean(r[0]["cve"]) != r[0]["cve"] or _clean_md(name) != name or not names_one(r[0]):
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


def _published_lines(text):
    """the lines of a published text, each without its trailing whitespace: git's tag-message cleanup strips trailing
    whitespace, so only that is ignored; leading and interior whitespace stay significant"""
    return {ln.rstrip() for ln in str(text).splitlines()}


def unpublished(entries, published_text):
    """Advisor 0135: an entry an earlier patch already published (any v* tag message, CHANGELOG.md) is not published
    again — the clear-and-changelog PR may not have merged when the next patch is decided. Published means a whole line
    of the published text is the line notes() prints for the entry, trailing whitespace ignored on both sides; a line
    that only contains it is not (REQ-REL-009-AC14, advisor step 5; Codex #300 r7, A medium / B F2). No published text
    ever held another form of an entry (no CHANGELOG.md on main, no v* tag message holds 'redacted')."""
    pub = _published_lines(published_text)
    return [e for e in entries if _entry_line(e).rstrip() not in pub]


PATCH_HEAD = re.compile(r"^## (v\d+\.\d+\.\d+) — patch release$")


RELEASE_TAGGER = "fosterstack release <release@users.noreply.github.com>"   # decide's git identity (release.yml)


def tag_notes(raw):
    """AC8: the notes a generated patch tag carries (`git cat-file tag` output), or None for any other tag (an owner's
    release keeps the fixed release text). The heading must name the tag itself; the signature block is dropped. A
    generated tag's notes holding a refused form on any line, or two bullets of one release block publishing the same
    line, are refused (ValueError naming the line of the
    tag message; REQ-REL-009-AC14, advisor step 5: tag-notes exits 2 like notes and changelog)."""
    head, _, body = raw.partition("\n\n")
    tag = next((ln[4:] for ln in head.splitlines() if ln.startswith("tag ")), None)
    tagger = next((ln[7:] for ln in head.splitlines() if ln.startswith("tagger ")), "")
    # the signature is the LAST signature-shaped block (Sonnet #159 r2b); everything before it is the notes region
    cut = body.rfind(SIG_DELIM)
    if cut < 0:
        return None
    body, sig = body[:cut], body[cut + len(SIG_DELIM):]
    # only the release workflow's own patch tag: its tagger and an x509 signature (no job signs one now: handoff 0713 P8) — an owner's tag is SSH-signed
    # and never carries notes, whatever its message (Sonnet #159 r2, BLOCKER-1); admission verified the signature
    if not tagger.startswith(RELEASE_TAGGER + " ") or not sig.startswith("SIGNED MESSAGE-----"):
        return None
    # the generated heading ends in LF and nothing else: CR, CRLF, VT, FF, FS, GS, RS, NEL, LS or PS after it is refused
    # (as in round 3; Codex #300 r5, B low)
    head_, lf_, _ = body.partition("\n")
    m = PATCH_HEAD.fullmatch(head_) if lf_ else None
    if not (m and m.group(1) == tag):
        return None
    # a generated patch tag from here. Exactly one signature-shaped block, genuinely last (Codex #159 fresh r2d): a
    # '-----BEGIN ' anywhere in the notes region — a second block, before or after a real one, or a delimiter in a note
    # line — is refused with the line named (exit 2, as notes and changelog; Codex #300 r8, A (c) / B F4), never read
    _refuse_text(body, "tag message")
    _no_dup_bullets(body, "tag message")
    out = _clean_lines(body)
    _refuse_continued_marker(out, "tag message")
    return out


def changelog(notes_text, changelog_text, next_notes_text, names=("notes", "CHANGELOG.md", "docs/next-release-notes.md")):
    """AC8 + advisor 0130: (CHANGELOG.md with these notes on top, newest first; next-release-notes.md without the
    entries these notes published — an entry added since stays). The three inputs are notes sources (REQ-REL-009-AC14):
    a line holding a refused form (any line, a VEX line too), or two entries publishing the same line (in
    next-release-notes, or two bullets of one release block of the notes or the history), is
    refused (ValueError naming file:line; names: the three inputs' names) before anything is cleaned or removed. The new
    notes are cleaned line by line; the existing history is copied unchanged, never rewritten — and is refused unless it
    is exactly what this function writes, so cleaning it would change nothing: LF line ends only, no name, no unescaped
    marker in free text (Codex #300 r5, A R4-1 / B low; fail closed). After the title, the one blank line this function
    writes is dropped and everything else is copied byte for byte, its own spacing kept (r6, A R5-5). An entry leaves
    next-release-notes only when a whole line of the cleaned notes is the line notes() prints for it, trailing whitespace
    ignored (r8, R14-9)."""
    notes_name, cl_name, nn_name = names
    _refuse_text(notes_text, notes_name)
    _refuse_text(changelog_text or "", cl_name)
    _no_dup_bullets(notes_text, notes_name)
    _no_dup_bullets(changelog_text or "", cl_name)
    _source_entries(next_notes_text, nn_name)
    notes_text = _clean_lines(notes_text)
    _refuse_continued_marker(notes_text, notes_name)     # r8 B F5: refused, never rewritten
    title = "# Changelog\n"
    rest = (changelog_text or title)
    if rest.startswith(title):
        rest = rest[len(title):]
        rest = rest[1:] if rest.startswith("\n") else rest
    if _clean_lines(rest) != rest:
        raise ValueError("%s: the history is not clean (a line end other than LF, a name, or an unescaped marker in free "
                         "text): refused, not rewritten" % cl_name)
    _refuse_continued_marker(changelog_text or "", cl_name)
    new_cl = title + "\n" + notes_text.rstrip("\n") + "\n" + ("\n" + rest if rest else "")
    published = _published_lines(notes_text)
    lines, keep, i = next_notes_text.splitlines(keepends=True), [], 0
    while i < len(lines):
        j = i + 1
        if lines[i].startswith("- "):                      # an entry and its indented continuation lines
            while j < len(lines) and lines[j].startswith("  ") and lines[j].strip():
                j += 1
            entry = " ".join(ln.strip() for ln in lines[i:j])[2:]
            if _entry_line(entry).rstrip() in published:
                i = j
                continue
        keep += lines[i:j]
        i = j
    return new_cl, "".join(keep)


def decide(event, commits, tags, cut_today, removed, base_inputs=None):
    """{cut, version, reason, not_clean}: rule 1 (patch-clean, fix-only), rule 2 (a critical/high fix at once on push;
    otherwise at most one daily patch on the schedule)."""
    version = next_patch(tags)
    clean, why = patch_clean(commits, base_inputs)
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


def _blob(spec, cwd):
    """a file's text at a revision (git show rev:path); non-UTF-8 bytes read as binary; a read that fails is "\0unreadable" (not text),
    never None: the caller asks only for blobs that exist, so a failure is not an absence"""
    p = subprocess.run(["git", "-C", cwd, "show", spec], capture_output=True)
    if p.returncode != 0:
        return "\0unreadable"
    try:
        return p.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return "\0binary"


def gather_commits(since, cwd=".", labels=lambda sha: []):
    """The commits since a tag (oldest first) with the files each changes, each file's changed lines, and the labels of
    the PR that merged it (from `labels`; none when it cannot be read: a missing label never admits a change)."""
    out = []
    for sha in _git("rev-list", "--reverse", "%s..HEAD" % since, cwd=cwd).split():
        files = [f for f in _git("show", "--format=", "--name-only", "--no-renames", "-m", "--first-parent", sha, cwd=cwd).splitlines() if f]
        # full context: the classifier needs a go.mod line's block (require vs replace/exclude) to judge it
        diffs = {f: "\n".join(ln for ln in _git("show", "--format=", "--no-renames", "-m", "--first-parent", "--unified=100000", sha, "--", f, cwd=cwd).splitlines()
                              if ln[:1] in "+- " and not ln.startswith(("+++", "---")))
                 for f in files}
        # each file's mode after the commit (":old new oldsha newsha status\tpath"); 000000 is a deletion (Codex B01)
        modes, old_modes = {}, {}
        try:       # against the FIRST parent (a merge is read the same way as the name list and the diffs above); a root commit has none
            raw = _git("diff", "--raw", "-r", "--no-renames", sha + "^1", sha, cwd=cwd)
        except subprocess.CalledProcessError:
            raw = _git("diff-tree", "--root", "-r", "--no-commit-id", "--raw", "--no-renames", sha, cwd=cwd)
        for ln in raw.splitlines():
            meta, _, paths = ln.partition("\t")
            if meta.startswith(":"):
                modes[paths.split("\t")[-1]] = meta.split()[1]
                old_modes[paths.split("\t")[-1]] = meta.split()[0].lstrip(":")
        # the old and new blobs of every neutral-named path, read whole (a diff's context window is no limit on what is checked)
        contents = {}
        for f in files:
            if f in NEUTRAL_EXACT or NEUTRAL_PROPOSALS.match(f):
                contents[f] = {"old": None if old_modes.get(f) == "000000" else _blob("%s^1:%s" % (sha, f), cwd),
                               "new": None if modes.get(f) == "000000" else _blob("%s:%s" % (sha, f), cwd)}
        out.append({"sha": sha, "files": files, "diffs": diffs, "modes": modes, "old_modes": old_modes, "contents": contents, "labels": list(labels(sha))})
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


def check_fix_sources(fixes, docs, gomod_path, gomod_text, head):
    """REQ-REL-009-AC14: each printed fix record's source values — the scan match that produced it (the first match HEAD
    fixes, in the order fixed_findings reads them: _fixing; Codex #300 r8, A medium / B F3) and, for a Go module, its
    go.mod line, whole — and its composed fix line are refused (ValueError) when any line of them holds a refused form,
    named by the scan file and the JSON key path (JSON has no line) or by go.mod:line. docs: {variant: (path, grype
    document)}; head as fixed_findings takes it. A finding HEAD does not fix is not printed and not judged. Returns each
    record's location 'scan:matches[i]:' (the collision check names it)."""
    glines = gomod_text.split("\n")
    parsed = parse_gomod(gomod_text, gomod_path)      # the same parse gomod_versions read the versions from
    first = {}
    for v, i, f_, _ in _fixing({v: grype_findings(docs[v][1]) for v in docs}, head):
        first.setdefault((f_["id"], f_["package"]), (v, i))
    locs = []
    for f in fixes:
        if (f["cve"], f["package"]) not in first:
            raise ValueError("fix record %s: no scan match" % f["cve"])
        v, i = first[(f["cve"], f["package"])]
        path, m = docs[v][0], docs[v][1]["matches"][i]
        go = m["artifact"].get("type") in ("go-module", "golang")
        vals = [("vulnerability.id", m["vulnerability"]["id"]), ("artifact.name", m["artifact"]["name"]),
                ("artifact.version", m["artifact"].get("version")), ("vulnerability.severity", m["vulnerability"].get("severity"))]
        if not go:                          # a distribution package prints its scan's fix versions
            vals += [("vulnerability.fix.versions[%d]" % j, x)
                     for j, x in enumerate((m["vulnerability"].get("fix") or {}).get("versions") or [])]
        for key, val in vals:
            why = _refused_value(val) if val is not None else None
            if why:
                raise ValueError("%s:matches[%d].%s: %s" % (path, i, key, why))
        where = ""
        if go:
            # the line the version came from: the parsed require (or the go directive for stdlib), never a text search
            # (stdlib: the go directive's version, compared as go1.X.Y; r10, A low 3 / B 4)
            std = f["package"] == "stdlib"
            src = parsed["go"] if std else parsed["require"].get(f["package"])
            if src is None or ("go" + src[0] if std else src[0]) != f["new"]:
                raise ValueError("%s:matches[%d]: %s: no %s in %s gives %s" % (
                    path, i, f["package"], "go directive" if std else "require line", gomod_path, f["new"]))
            n = src[1]
            where = " %s:%d:" % (gomod_path, n)
            why = _refused_value(f["new"]) or _refused_form(glines[n - 1])
            if why:
                raise ValueError("%s:matches[%d]:%s %s" % (path, i, where, why))
        why = _refused_form(_fix_raw(f))
        if why:
            raise ValueError("%s:matches[%d]:%s the composed fix line: %s" % (path, i, where, why))
        locs.append("%s:matches[%d]:%s" % (path, i, where))
    return locs


# go.mod, read by a strict parser of its grammar (advisor decision Oct 11 (2): the parsed require directives only, one
# source of truth for the version and the line a fix is judged on; Codex #300 r9, A (a)(3) / B 1). It follows Go's modfile
# lexer (golang.org/x/mod/modfile): '//' starts a comment anywhere outside a quoted string and runs to the line end; ( )
# [ ] { } , are tokens of their own; a directive is one line 'verb args...' or a block 'verb (' ... ')'. Fail closed: what
# this reader does not read is refused (ValueError naming name:line), never guessed — a '/* */' comment (Go refuses it), a
# quoted string (Go accepts one in place of a path; the repository's go.mod files use none, so it is refused: a documented
# limit, r10 A), a character other than a printable one, space or tab (a CR only at the line end), a block opened on a
# line with anything after '(', a ')' outside a block, a block never closed, an unknown directive, a 'go' or 'toolchain'
# or 'module' directive twice or inside a block, [ ] { } , outside a 'retract' line, and each directive's arguments in any
# shape but its own (Codex #300 r10, A low 2 / B 3): module PATH; go a Go release version (modfile's GoVersionRE: 1.21,
# 1.21.0, 1.21rc1); toolchain 'default' or go + a Go release version; require / exclude PATH VERSION; replace
# PATH [VERSION] => DIR or => PATH VERSION; retract VERSION or [VERSION, VERSION]; godebug KEY=VALUE; tool / ignore PATH.
# A VERSION is a semantic version as golang.org/x/mod/semver reads it: vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD], ASCII
# digits only, no leading zero in a number or a numeric prerelease identifier, no empty identifier ('v0.34.0-..' is
# refused). The module name 'stdlib' is reserved for the toolchain (the go directive): any directive naming it is refused
# (r10, A low 3 / B 4). Go itself is not on the decide job's PATH (release.yml installs no Go toolchain), so the parser is
# this code, not `go mod edit -json`.
GO_DIRECTIVES = {"module", "go", "toolchain", "require", "replace", "exclude", "retract", "tool", "ignore", "godebug"}
GO_BLOCKS = GO_DIRECTIVES - {"go", "toolchain", "module"}
_N = r"(?:0|[1-9][0-9]*)"
_PRE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_BUILD = r"[0-9A-Za-z-]+"
GO_SEMVER = re.compile(r"v%s\.%s\.%s(?:-%s(?:\.%s)*)?(?:\+%s(?:\.%s)*)?" % (_N, _N, _N, _PRE, _PRE, _BUILD, _BUILD))
GO_RELEASE = re.compile(r"[1-9][0-9]*\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?(?:[a-z]+[0-9]+)?")
GO_TOOLCHAIN = re.compile(r"default|go" + GO_RELEASE.pattern)
GO_GODEBUG = re.compile(r"[A-Za-z0-9_.-]+=[A-Za-z0-9_.+-]*")
GO_TOKEN = re.compile(r"[()\[\]{},]|[^ \t()\[\]{},]+")
GO_RESERVED = "stdlib"


def _go_dir(p):
    """a replacement that is a directory path (modfile.IsDirectoryPath, the forms this reader takes: ., .., ./, ../, /)"""
    return p in (".", "..") or p.startswith(("./", "../", "/"))


def _gomod_args(verb, args):
    """why a directive's arguments are not in its own shape, or None"""
    ver = GO_SEMVER.fullmatch
    paths = []
    if verb in ("module", "tool", "ignore"):
        if len(args) != 1:
            return "a %s that is not exactly one path" % verb
        paths = args
    elif verb == "go":
        if len(args) != 1 or not GO_RELEASE.fullmatch(args[0]):
            return "a go directive that is not one Go release version (1.21, 1.21.0, 1.21rc1)"
    elif verb == "toolchain":
        if len(args) != 1 or not GO_TOOLCHAIN.fullmatch(args[0]):
            return "a toolchain that is not 'default' or go and a Go release version"
    elif verb in ("require", "exclude"):
        if len(args) != 2 or not ver(args[1]):
            return "a %s that is not a module path and a semantic version" % verb
        paths = args[:1]
    elif verb == "replace":
        if args.count("=>") != 1:
            return "a replace that is not 'path [version] => replacement'"
        i = args.index("=>")
        old, new = args[:i], args[i + 1:]
        if (len(old) not in (1, 2) or (len(old) == 2 and not ver(old[1])) or len(new) not in (1, 2)
                or (len(new) == 1 and not _go_dir(new[0])) or (len(new) == 2 and (_go_dir(new[0]) or not ver(new[1])))):
            return "a replace that is not 'path [version] => directory' or 'path [version] => path version'"
        paths = [old[0], new[0]]
    elif verb == "retract":
        if not ((len(args) == 1 and ver(args[0])) or (len(args) == 5 and args[0] == "[" and ver(args[1]) and args[2] == ","
                                                       and ver(args[3]) and args[4] == "]")):
            return "a retract that is not a version or [version, version]"
    elif verb == "godebug":
        if len(args) != 1 or not GO_GODEBUG.fullmatch(args[0]):
            return "a godebug that is not one key=value"
    if any(p in GO_DIRECTIVES or p in ("=>", "[", "]", ",") for p in paths):
        return "a %s whose path is a keyword or a token" % verb
    if GO_RESERVED in paths:
        return "the module name 'stdlib' (reserved for the toolchain: the go directive)"
    return None


def _gomod_tokens(line, name, n):
    """the tokens of one go.mod line, its comment dropped; ValueError naming name:n for what the parser does not read"""
    body = line[:-1] if line.endswith("\r") else line
    cut = body.find("//")
    if cut >= 0:
        body = body[:cut]
    if "/*" in body:
        raise ValueError("%s:%d: a /* */ comment (go.mod uses // comments only)" % (name, n))
    if any(c in "\"`" or not (c in " \t" or (c.isprintable() and not c.isspace())) for c in body):
        raise ValueError("%s:%d: a quoted string or a character the go.mod reader does not read" % (name, n))
    return GO_TOKEN.findall(body)


def parse_gomod(text, name="go.mod"):
    """{"require": {module: (version, line)}, "go": (version, line) or None} of a go.mod text, lines numbered from 1;
    ValueError naming name:line for anything the strict reader refuses (see above)"""
    req, go, block, once = {}, None, None, {}
    for n, line in enumerate(str(text).split("\n"), 1):
        toks = _gomod_tokens(line, name, n)
        if not toks:
            continue
        if block is not None:
            if toks == [")"]:
                block = None
                continue
            verb, args = block[0], toks
        elif len(toks) == 2 and toks[1] == "(":
            if toks[0] not in GO_BLOCKS:
                raise ValueError("%s:%d: a block of a directive the reader does not read as a block %r" % (name, n, toks[0]))
            block = (toks[0], n)
            continue
        else:
            verb, args = toks[0], toks[1:]
            if verb not in GO_DIRECTIVES:
                raise ValueError("%s:%d: not a go.mod directive the reader knows" % (name, n))
        if "(" in args or ")" in args or (verb != "retract" and any(t in ("[", "]", ",") for t in args)) or "{" in args or "}" in args:
            raise ValueError("%s:%d: a block opened or closed where the reader does not read one" % (name, n))
        why = _gomod_args(verb, args)
        if why:
            raise ValueError("%s:%d: %s" % (name, n, why))
        if verb in ("go", "toolchain", "module"):
            if verb in once:
                raise ValueError("%s:%d: a %s directive twice (also line %d)" % (name, n, verb, once[verb]))
            once[verb] = n
        if verb == "require":
            if args[0] in req:
                raise ValueError("%s:%d: %s required twice (also line %d)" % (name, n, args[0], req[args[0]][1]))
            req[args[0]] = (args[1], n)
        elif verb == "go":
            go = (args[0], n)
    if block is not None:
        raise ValueError("%s:%d: a %s block never closed" % (name, block[1], block[0]))
    return {"require": req, "go": go}


def gomod_versions(text, name="go.mod"):
    """{module: version} of go.mod's parsed require directives (parse_gomod), plus the toolchain as stdlib (go1.X.Y from
    the go directive). ValueError for a go.mod the parser refuses."""
    g = parse_gomod(text, name)
    out = {m: v for m, (v, _) in g["require"].items()}
    if g["go"] and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", g["go"][0]):
        out["stdlib"] = "go" + g["go"][0]
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
    d.add_argument("--base-inputs", help="the list of base inputs (default: .github/policy/base-inputs.json beside this script)")
    d.add_argument("--out", required=True)
    bm = sub.add_parser("base-moved", help="the listed base inputs that differ between a release tag and HEAD (the base-input-changed signal)")
    bm.add_argument("--since", required=True, help="the latest release's tag")
    bm.add_argument("--base-inputs", help="the list of base inputs (default: .github/policy/base-inputs.json beside this script)")
    bm.add_argument("--repo", default=".")
    q = sub.add_parser("rc-proof", help="REQ-CHAIN-001-AC6: exit 0 only when the committed rc-proof marker validates for the commit about to be tagged; else exit 1, naming the marker")
    q.add_argument("--marker", required=True)
    q.add_argument("--commit", required=True)
    q.add_argument("--repo", default=".")
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
    vv = sub.add_parser("variants", help="the image tags of release X.Y.Z that exist: X.Y.Z, X.Y.Z-fips, and X.Y.Z-debug only before v0.3.0 (the owner dropped debug for v0.3.0)")
    vv.add_argument("--version", required=True)
    sub.add_parser("tag-notes", help="stdin: git cat-file tag; stdout: a generated patch tag's notes, else exit 1")
    c = sub.add_parser("changelog")
    c.add_argument("--notes", required=True)
    c.add_argument("--changelog", required=True)
    c.add_argument("--next-notes", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "rc-proof":
        # the helper is the ONE definition of the chain-file set and of the marker's checks (bin/chain-bytes-sha.py, next to this file); no marker, no helper,
        # an unreadable or mismatching marker: no patch decision (never a skip)
        helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chain-bytes-sha.py")
        if not os.path.isfile(helper):
            print("refused at marker: %s is missing, so the rc-proof marker %s cannot be checked: no patch decision" % (helper, a.marker), file=sys.stderr)
            return 1
        r = subprocess.run([sys.executable, helper, "check-marker", "--marker", a.marker, "--commit", a.commit, "--repo", a.repo], capture_output=True, text=True)
        if r.returncode != 0:
            print(_clean("refused at marker: no patch decision: " + (r.stderr.strip().splitlines() or ["the marker does not validate"])[0].replace("refused at marker: ", "")), file=sys.stderr)
            return 1
        print("rc-proof: the marker %s validates for %s" % (a.marker, a.commit))
        return 0
    if a.cmd == "base-moved":
        try:
            listed = load_base_inputs(a.base_inputs)
            _git("rev-parse", "--verify", "-q", "refs/tags/%s^{commit}" % a.since, cwd=a.repo)       # a release that is not a tag here is an error, never "nothing moved"
            moved = [f for f in _git("diff", "--name-only", "--no-renames", "%s..HEAD" % a.since, "--", *listed, cwd=a.repo).splitlines() if f in listed]
        except (ValueError, subprocess.CalledProcessError) as e:
            print("base-moved: %s — no patch decision" % _clean(str(e)), file=sys.stderr)
            return 2
        if moved:
            print("base input moved since %s:" % a.since)
            for f in sorted(moved):
                print("  " + f)
        else:
            print("no base input moved since %s" % a.since)
        return 0
    if a.cmd == "variants":
        m = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", a.version)
        if not m:
            print("patch-decide: version %r is not X.Y.Z" % a.version, file=sys.stderr)
            return 2
        tags = [a.version] + ([a.version + "-debug"] if (int(m.group(1)), int(m.group(2))) < (0, 3) else []) + [a.version + "-fips"]
        print("\n".join(tags))
        return 0
    if a.cmd == "notes":
        try:
            rel, docs = {}, {}
            for v in a.variant_grype:
                name, _, path = v.partition("=")
                why = _refused_value(name)
                if why:
                    raise ValueError("--variant-grype %s: the variant name: %s" % (path, why))
                docs[name] = (path, json.load(open(path)))
                rel[name] = grype_findings(docs[name][1])
            base = [f for p in a.base_grype for f in grype_findings(json.load(open(p)))] if a.base_grype else None
            nn = open(a.next_notes).read() if os.path.exists(a.next_notes) else ""     # no file: no entries
            ents = behavior_entries(nn, a.next_notes, located=True)
            old = json.load(open(a.vex_old)) if a.vex_old else None
            if a.vex_old and old is None:       # a supplied file holding null is not "no old document" (Codex #300 r2, B)
                raise ValueError("VEX old document %s: null" % a.vex_old)
            gomod_text = open(a.gomod).read()
            head = {"go": gomod_versions(gomod_text, a.gomod), "base_findings": base}
            fixes = fixed_findings(rel, head)
            fix_locs = check_fix_sources(fixes, docs, a.gomod, gomod_text, head)
            # every source is refused before any entry is dropped as already published (REQ-REL-009-AC14 (5)): a fix line
            # and any entry publishing the same line, both named (one set across them; Codex #300 r8, B medium)
            _no_collision([(_clean_free(_fix_raw(f)), loc) for f, loc in zip(fixes, fix_locs)]
                          + [(_entry_line(e), loc) for e, loc in ents])
            keep = set(unpublished([e for e, _ in ents], open(a.published).read()))
            ents = [(e, loc) for e, loc in ents if e in keep]
            text = notes(a.version, fixes, vex_changes(old, json.load(open(a.vex_new))), behavior=[e for e, _ in ents],
                         fix_locs=fix_locs, behavior_locs=[loc for _, loc in ents])
        except (ValueError, OSError, KeyError, TypeError) as e:
            print("notes: %s — no notes, no patch" % _clean(str(e)), file=sys.stderr)
            return 2
        with open(a.out, "w") as fh:
            fh.write(text)
        return 0
    if a.cmd == "tag-notes":
        try:
            t = tag_notes(sys.stdin.read())
        except ValueError as e:             # a generated patch tag's notes holding a refused form (REQ-REL-009-AC14)
            print("tag-notes: %s — no notes" % _clean(str(e)), file=sys.stderr)
            return 2
        if t is None:
            return 1
        sys.stdout.write(t)
        return 0
    if a.cmd == "changelog":
        cl_path = a.changelog
        old_cl = open(cl_path, newline="").read() if os.path.exists(cl_path) else None    # line ends as stored (r5)
        has_nn = os.path.exists(a.next_notes)
        try:
            new_cl, new_nn = changelog(open(a.notes).read(), old_cl, open(a.next_notes).read() if has_nn else "",
                                       names=(a.notes, cl_path, a.next_notes))
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
        try:
            gov = gomod_versions(open(a.gomod).read(), a.gomod)
        except (ValueError, OSError) as e:      # a go.mod the parser refuses: unknown, never "nothing removed"
            print("removed: %s" % e, file=sys.stderr)
            return 2
        found = removed_critical_high(release, {"go": gov, "base_findings": base})
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
    try:
        base_inputs = load_base_inputs(a.base_inputs)      # an unreadable list is exit 2 and no decision (never a silent empty list)
    except ValueError as e:
        print("decide: %s — no patch decision" % _clean(str(e)), file=sys.stderr)
        return 2
    dec = decide(event, commits, tags if since else [], a.cut_today == "true", removed, base_inputs)
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
