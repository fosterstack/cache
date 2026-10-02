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
                          no-behavior-change line; no vendor or model names.
  floating                amendment: :X.Y always; :X and :latest only when this is the highest released version.
"""
import re

FIX_EXACT = {".snyk", "osv-scanner.toml"}
FIX_PREFIX = (".vex/", ".auditor/")
NEUTRAL_PREFIX = (".github/", "docs/", "requirements/", "test-evidence/")
DOCKERFILES = re.compile(r"^build/docker/Dockerfile\.[a-z0-9-]+$")
SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VENDOR = re.compile(r"(?i)(?<![a-z])(anthropic|claude|openai|chat\s*gpt|gpt|codex|gemini)[\w.-]*")


def _changed_lines(diff):
    return [ln for ln in (diff or "").splitlines() if ln[:1] in "+-" and ln[1:].strip()]


def _gomod_pins_only(diffs):
    """go.mod / go.sum change only the versions of modules that were already required (no module added or removed)."""
    for path in ("go.mod", "go.sum", "tools/requirements/go.mod", "tools/requirements/go.sum"):
        lines = _changed_lines(diffs.get(path))
        if not lines:
            continue
        mods = {}
        for ln in lines:
            m = re.match(r"^[+-]\s*(?:require\s+)?(\S+)\s+v\S+", ln)
            if not m:
                return False
            mods.setdefault(m.group(1), set()).add(ln[0])
        if any(v != {"+", "-"} for v in mods.values()):        # a module only added or only removed
            return False
    return True


def _digest_only(diff):
    lines = _changed_lines(diff)
    return bool(lines) and all(re.match(r"^[+-]FROM\s+\S+@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?\s*$", ln) for ln in lines)


def _is_test(path):
    return path.endswith("_test.go") or bool(re.match(r"^bin/[^/]+-test\.sh$", path))


def classify(commit):
    """('fix' | 'neutral' | 'dirty', reason) for one commit."""
    files, diffs = commit.get("files") or [], commit.get("diffs") or {}
    kinds, why = set(), []
    for f in files:
        if f in FIX_EXACT or f.startswith(FIX_PREFIX):
            kinds.add("fix")
        elif f in ("go.mod", "go.sum", "tools/requirements/go.mod", "tools/requirements/go.sum"):
            if _gomod_pins_only(diffs):
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes more than existing modules' versions" % f)
        elif DOCKERFILES.match(f):
            if _digest_only(diffs.get(f)):
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes more than the base-image digest pin" % f)
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
    return VENDOR.sub("<redacted>", str(s))


def notes(version, fixes, vex_changes):
    lines = ["## %s — patch release" % version, "", "### Fixes"]
    for f in fixes:
        lines.append("- %s in %s: %s → %s (severity %s; variants: %s)" % (
            f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or [])))
    if not fixes:
        lines.append("- none (dependency or VEX maintenance only)")
    lines += ["", "### VEX"]
    lines += ["- %s: %s (%s)" % (v["cve"], v["status"], v["change"]) for v in vex_changes] or ["- no change"]
    lines += ["", "No behavior change: this release contains fixes only."]
    return _clean("\n".join(lines)) + "\n"


def floating(version, released):
    """The floating tags a CI patch moves (amendment, owner Oct 2)."""
    v = _semver(version)
    others = [o for o in (_semver(t) for t in released) if o]
    out = ["%d.%d" % v[:2]]
    if all(v >= o for o in others):
        out += ["%d" % v[0], "latest"]
    return out
