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
  floating                amendment: :X.Y always; :X and :latest only when this is the highest released version.
"""
import re

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
VENDOR = re.compile(r"(?i)(?<![a-z])((" + _sep("google", "microsoft", "amazon", "aws", "azure", "xai", "meta", "github")
                    + r"|x\.ai)\s+)?(chat[-_.\s]*gpt|"
                    + _sep("anthropic", "claude", "openai", "gpt", "codex", "gemini", "llama", "mistral", "mixtral", "grok",
                           "bedrock", "deepseek", "qwen", "copilot", "cohere", "bard", "sonnet", "opus", "haiku", "xai")
                    + r")(?:[\w-]|\.(?=\w))*|\bo[1-9](-(mini|pro|preview))?\b")
# a vendor named alone (Sonnet #158 r3: rule 5 forbids vendor OR model names) is redacted wherever it stands, next to a
# hyphen or slash too (Sonnet #158 r3b, NEW-BLOCKER-2: "AWS-reported", "Google/Microsoft"); fail closed — only a whole token
# that is a wholly lowercase domain or module path stays readable (google.golang.org/protobuf, github.com/aws/aws-sdk-go-v2)
# Meta too, with the separators every name takes (Codex #158 phase-2 r3, NEW-BLOCKER-4: Me-ta, me_ta_client.go)
VENDOR_ALONE = re.compile(r"(?i)(?<![a-z0-9])(" + _sep("google", "microsoft", "amazon", "aws", "azure", "meta")
                          + r")(?![a-z0-9])")
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
NEUTRAL_GITHUB_PREFIX = (".github/agent/reviews/", ".github/agent/tests/", ".github/agent/bin/tests/", ".github/agent/docs/")


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


def _is_test(path):
    return path.endswith("_test.go") or bool(re.match(r"^bin/[^/]+-test\.sh$", path))


def classify(commit):
    """('fix' | 'neutral' | 'dirty', reason) for one commit."""
    files, diffs = commit.get("files") or [], commit.get("diffs") or {}
    kinds, why = set(), []
    for f in files:
        if f in FIX_EXACT or f.startswith(FIX_PREFIX):
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
        elif BUILD_INPUTS.match(f) or (f.startswith(".github/workflows/") and f.split("/")[-1] not in NEUTRAL_WORKFLOWS):
            kinds.add("dirty"); why.append("%s builds or ships the release image" % f)
        elif f.startswith(".github/") and not f.startswith(".github/workflows/") \
                and f not in NEUTRAL_GITHUB and not f.startswith(NEUTRAL_GITHUB_PREFIX):
            kinds.add("dirty"); why.append("%s is read by the release chain (or not reviewed as outside it)" % f)
        elif f.startswith(NEUTRAL_PREFIX) or _is_test(f):
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
        if not CITED.search(e):
            raise ValueError("next-release-notes entry cites no handoff: %r" % e)
    return out


def notes(version, fixes, vex_changes, behavior=()):
    lines = ["## %s — patch release" % version, "", "### Fixes"]
    for f in fixes:
        lines.append("- %s in %s: %s → %s (severity %s; variants: %s)" % (
            f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or [])))
    if not fixes:
        lines.append("- none (dependency or VEX maintenance only)")
    lines += ["", "### VEX"]
    lines += ["- %s: %s (%s)" % (v["cve"], v["status"], v["change"]) for v in vex_changes] or ["- no change"]
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
