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
import argparse, json, os, re, subprocess, sys
FIX_EXACT = {".snyk", "osv-scanner.toml"}
# data that ships nothing: the auditor's own work (three names) and the .vex README (REQ-REL-009 AC15)
NEUTRAL_EXACT = {".auditor/panel-state.json", ".auditor/knowledge.md", ".vex/README.md"}
NEUTRAL_PROPOSALS = re.compile(r"^\.auditor/proposals/[^/]+\.json$")
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
    while i > 0 and not text[i - 1].isspace() and text[i - 1] not in "([{\"'<,;`":
        i -= 1
    while j < len(text) and not text[j].isspace() and text[j] not in ")]}\"'>,;`":
        j += 1
    token = text[i:j].rstrip(".:")
    token = token.strip("`").lstrip("+-").strip("`")             # a signed product list: +pkg:..., -pkg:..., `pkg:...`
    token = re.sub(r"^pkg:[a-z0-9.+-]+/", "", token)          # a package URL's type is not part of the module path
    token = re.sub(r"@(?:v?[0-9][A-Za-z0-9._~+-]*)$", "", token)   # nor is its version: it starts with v or a digit, never a vendor word
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


SHEBANG_LINE = re.compile(r"(?m)^#!")


def _not_data(f, diff, mode, old_mode, contents=None):
    """why a neutral-named path is not data (None when it is): its file types before and after, and its committed content.
    A script line is a shebang line (`#!` at the start of ANY line); it is looked for in the whole new content and in the
    whole old content (what a commit deletes or replaces), read from the blobs when `contents` has them, else from the diff."""
    if old_mode in ("100755", "120000"):
        return "%s was %s before: not data" % (f, "a symlink" if old_mode == "120000" else "executable")
    if mode != "000000" and mode != "100644":
        return "%s has mode %s; data is a regular non-executable file (100644)" % (f, mode or "?")
    if mode == "000000" and old_mode != "100644":
        return "%s is deleted and its old file type is unknown" % f
    if contents is not None:
        old_text, new_text = contents.get("old"), contents.get("new")
    else:
        lines = (diff or "").split("\n")
        old_text = "\n".join(l[1:] for l in lines if l[:1] in ("-", " ")) or None
        new_text = "\n".join(l[1:] for l in lines if l[:1] in ("+", " ")) or None
    for label, text in (("new", new_text), ("old", old_text)):
        if text is not None and ("\0" in text):
            return "%s holds NUL or non-text bytes (%s content): not text" % (f, label)
        if text is not None and SHEBANG_LINE.search(text):
            return "%s has a shebang line in its %s content: a script, not data" % (f, label)
    if mode == "000000":
        return None
    if not new_text:
        return "%s shows no content (binary, or a mode-only change): not proven data" % f
    if f.endswith(".json"):
        try:
            if not isinstance(json.loads(new_text), (dict, list)):
                return "%s is not a JSON object or array" % f
        except ValueError:
            return "%s is not valid JSON" % f
    return None


def classify(commit):
    """('fix' | 'neutral' | 'dirty', reason) for one commit. Neutral means non-executable data only — docs/, requirements/,
    test-evidence/ data and the reviewed .github files; an executable test never counts (REQ-REL-009 AC1, owner Oct 3)."""
    files, diffs, modes = commit.get("files") or [], commit.get("diffs") or {}, commit.get("modes") or {}
    kinds, why, hard = set(), [], False
    old_modes = commit.get("old_modes") or {}
    for f in files:
        if f in NEUTRAL_EXACT or NEUTRAL_PROPOSALS.match(f):
            # neutral only as DATA, proven from the committed content and the old and new file types (REQ-REL-009 AC15)
            bad = _not_data(f, diffs.get(f), modes.get(f), old_modes.get(f), (commit.get("contents") or {}).get(f))
            if bad:
                kinds.add("dirty"); why.append(bad); hard = True       # no label turns this into a fix
            else:
                kinds.add("neutral")
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
    if "dirty" in kinds and not hard and "patch-fix" in (commit.get("labels") or []):
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


def notes(version, fixes, vex_changes, behavior=(), vex_bytes_changed=False):
    lines = ["## %s — patch release" % version, "", "### Fixes"]
    for f in fixes:
        lines.append("- %s in %s: %s → %s (severity %s; variants: %s)" % (
            f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or [])))
    if not fixes:
        lines.append("- none (dependency or VEX maintenance only)")
        statement_changes = [v for v in vex_changes if v["cve"] != "(document)"]
        if not behavior and statement_changes:
            lines.append("- VEX-only: this patch changes VEX statements and nothing else")
        elif not behavior and (vex_changes or vex_bytes_changed):
            lines.append("- VEX-only (no statement change): the VEX file changed but no statement did")
    lines += ["", "### VEX"]
    lines += ["- %s: %s (%s)" % (v["cve"], v["status"], v["change"]) for v in vex_changes] or ["- no change"]
    for b in behavior:
        _check_entry(b)
    if behavior:
        lines += ["", "### Behavior changes"] + ["- %s" % b for b in behavior]
    else:
        lines += ["", "No behavior change: this release contains fixes only."]
    return _clean("\n".join(lines)) + "\n"


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


def vex_changes(old_doc, new_doc):
    """AC8/AC14: each VEX statement added, removed or changed since the latest tag. A statement is identified by its
    vulnerability and its product SET (order-insensitive); statements of one vulnerability are paired by equal product
    sets first, the rest in file order (a changed product list). A vulnerability with several statements is named with
    the statement's product set, "CVE [pkg:a, pkg:b]". Reordering is no change; a changed statement names the fields
    that differ (products as +added -removed); a document-level change is one 'document metadata' entry."""
    def canon_product(p_):
        if isinstance(p_, dict) and isinstance(p_.get("subcomponents"), list):
            p_ = dict(p_, subcomponents=sorted(p_["subcomponents"], key=lambda x: json.dumps(x, sort_keys=True)))
        return p_
    def canon(st):
        st = dict(st)
        if isinstance(st.get("products"), list):
            st["products"] = sorted((canon_product(p_) for p_ in st["products"]), key=lambda p_: json.dumps(p_, sort_keys=True))
        return st
    def pid(p_):
        return p_.get("@id") if isinstance(p_, dict) and p_.get("@id") else json.dumps(p_, sort_keys=True)
    def members(st):
        out_ = []
        for p_ in st.get("products", []):
            out_.append(pid(p_))
            for sc in (p_.get("subcomponents") or []) if isinstance(p_, dict) else []:
                out_.append("%s[%s]" % (pid(p_), pid(sc)))
        return out_
    def pset(st):
        return tuple(sorted(members(st)))
    def groups(doc):
        g = {}
        for st in (doc or {}).get("statements", []):
            g.setdefault(st.get("vulnerability", {}).get("name", ""), []).append(canon(st))
        return g
    old, new = groups(old_doc), groups(new_doc)
    out = []
    for cve in sorted(set(old) | set(new)):
        o, n = list(old.get(cve, [])), list(new.get(cve, []))
        many = len(o) > 1 or len(n) > 1
        label = lambda st: "%s [%s]" % (cve, ", ".join(pset(st))) if many else cve
        pairs = []
        for st in list(o):                       # exactly equal statements pair first (a swap of look-alikes is no change)
            m = next((x for x in n if x == st), None)
            if m is not None:
                o.remove(st); n.remove(m)
        for st in list(o):                       # then equal product sets, in file order
            m = next((x for x in n if pset(x) == pset(st)), None)
            if m is not None:
                o.remove(st); n.remove(m); pairs.append((st, m))
        while o and n:
            pairs.append((o.pop(0), n.pop(0)))
        for st, m in pairs:
            if st != m:
                fields = sorted(f for f in set(st) | set(m) if st.get(f) != m.get(f))
                parts = []
                if "status" in fields:
                    parts.append("changed from %s" % st.get("status", ""))
                other = [f for f in fields if f not in ("status", "products")]
                if "products" in fields:
                    plus = [x for x in pset(m) if x not in pset(st)]
                    minus = [x for x in pset(st) if x not in pset(m)]
                    other.insert(0, "products " + " ".join(["+" + x for x in plus] + ["-" + x for x in minus]))
                if other:
                    parts.append(("also " if parts else "changed: ") + ", ".join(other))
                out.append({"cve": label(m), "status": m.get("status", ""), "change": "; ".join(parts)})
        for st in o:
            out.append({"cve": label(st), "status": st.get("status", ""), "change": "removed"})
        for st in n:
            out.append({"cve": label(st), "status": st.get("status", ""), "change": "added"})
    meta = sorted(f for f in set(old_doc or {}) | set(new_doc or {}) if f != "statements" and (old_doc or {}).get(f) != (new_doc or {}).get(f))
    if old_doc is not None and meta:
        out.append({"cve": "(document)", "status": "-", "change": "document metadata: " + ", ".join(meta)})
    return out


def unpublished(entries, published_text):
    """Advisor 0135: an entry an earlier patch already published (any v* tag message, CHANGELOG.md) is not published
    again — the clear-and-changelog PR may not have merged when the next patch is decided."""
    return [e for e in entries if ("- %s" % _clean(e)) not in published_text]


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
    m = PATCH_HEAD.match(body.split("\n", 1)[0])
    return _clean(body) if m and m.group(1) == tag else None


def changelog(notes_text, changelog_text, next_notes_text):
    """AC8 + advisor 0130: (CHANGELOG.md with these notes on top, newest first; next-release-notes.md without the
    entries these notes published — an entry added since stays)."""
    notes_text = _clean(notes_text)
    title = "# Changelog\n"
    rest = (changelog_text or title)
    rest = rest[len(title):].lstrip("\n") if rest.startswith(title) else rest
    new_cl = title + "\n" + notes_text.rstrip("\n") + "\n" + ("\n" + rest if rest.strip() else "")
    lines, keep, i = next_notes_text.splitlines(keepends=True), [], 0
    while i < len(lines):
        j = i + 1
        if lines[i].startswith("- "):                      # an entry and its indented continuation lines
            while j < len(lines) and lines[j].startswith("  ") and lines[j].strip():
                j += 1
            entry = " ".join(ln.strip() for ln in lines[i:j])[2:]
            if ("- %s" % _clean(entry)) in notes_text:
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


def _blob(spec, cwd):
    """a file's text at a revision (git show rev:path); None when it does not exist there; non-UTF-8 bytes read as binary"""
    p = subprocess.run(["git", "-C", cwd, "show", spec], capture_output=True)
    if p.returncode != 0:
        return None
    try:
        return p.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return "\0binary"


def gather_commits(since, cwd=".", labels=lambda sha: []):
    """The commits since a tag (oldest first) with the files each changes, each file's changed lines, and the labels of
    the PR that merged it (from `labels`; none when it cannot be read: a missing label never admits a change)."""
    out = []
    for sha in _git("rev-list", "--reverse", "%s..HEAD" % since, cwd=cwd).split():
        files = [f for f in _git("show", "--format=", "--name-only", "--no-renames", sha, cwd=cwd).splitlines() if f]
        # full context: the classifier needs a go.mod line's block (require vs replace/exclude) to judge it
        diffs = {f: "\n".join(ln for ln in _git("show", "--format=", "--no-renames", "--unified=100000", sha, "--", f, cwd=cwd).splitlines()
                              if ln[:1] in "+- " and not ln.startswith(("+++", "---")))
                 for f in files}
        # each file's mode after the commit (":old new oldsha newsha status\tpath"); 000000 is a deletion (Codex B01)
        modes, old_modes = {}, {}
        for ln in _git("diff-tree", "-r", "--no-commit-id", "--raw", "--no-renames", sha, cwd=cwd).splitlines():
            meta, _, paths = ln.partition("\t")
            if meta.startswith(":"):
                modes[paths.split("\t")[-1]] = meta.split()[1]
                old_modes[paths.split("\t")[-1]] = meta.split()[0].lstrip(":")
        # the old and new blobs of every neutral-named path, read whole (a diff's context window is no limit on what is checked)
        contents = {}
        for f in files:
            if f in NEUTRAL_EXACT or NEUTRAL_PROPOSALS.match(f):
                contents[f] = {"old": _blob("%s^:%s" % (sha, f), cwd), "new": _blob("%s:%s" % (sha, f), cwd)}
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
            fixes = fixed_findings(rel, {"go": gomod_versions(open(a.gomod).read()), "base_findings": base})
            text = notes(a.version, fixes, vex_changes(old, json.load(open(a.vex_new))), behavior=behavior,
                         vex_bytes_changed=bool(a.vex_old) and open(a.vex_old, "rb").read() != open(a.vex_new, "rb").read())
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
        old_cl = open(cl_path).read() if os.path.exists(cl_path) else None
        has_nn = os.path.exists(a.next_notes)
        new_cl, new_nn = changelog(open(a.notes).read(), old_cl, open(a.next_notes).read() if has_nn else "")
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
