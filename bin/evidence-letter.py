#!/usr/bin/env python3
"""evidence-letter.py: the monthly evidence letter (REQ-REL-013).

Makes one letter from a template out of the assets of the releases published in a month. Every fact in it is read
from those assets; the fetch step has already checked the assets' signatures. Any missing or malformed asset makes
no letter (exit 1, one line on stderr). No model, no network, no signing: the signing job takes the letter this
script wrote.

  evidence-letter.py --month YYYY-MM --releases DIR --advisories FILE --controls FILE --signatory FILE --out DIR
                     [--draft]

DIR holds one folder per release, named by its tag, with the release page's release.json and the downloaded assets.
Exit 0: letter written, or no release that month (nothing written). 1: refused. 2: bad arguments. 3: the signatory is
still the placeholder (without --draft).
"""
import argparse
import calendar
import hashlib
import json
import os
import re
import sys

TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")  # v0.3.1 matches; v0.3.1-rc1 and 0.3.1 do not
MONTH = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])")  # 2026-11 matches; 2026-13 and 2026-1 do not
SAFE_NAME = re.compile(r"[A-Za-z0-9._:-]+")  # CVE-2026-1111 matches; "CVE 1" and "a;b" do not
# the only characters a quoted note or summary may hold: no markup, entity or link can be written with them
QUOTED = re.compile(r"[A-Za-z0-9 .,:;()'/-]+")  # "Fix: a crash (rare)." matches; "a&#105;b" and "[x](y)" do not
RECORDS = ("scanners-collection.json", "acceptance-collection.json", "runtime-collection.json", "arm64-collection.json")
FORBIDDEN = ("warranty", "certified", "compliant", "guarantee", "soc2")  # tested on the letter with its spaces removed
PAGE = "https://github.com/fosterstack/cache/releases/tag/"
PLACEHOLDER = "PLACEHOLDER"
SIGNED = "\nSigned, "
NONE = "- none this month"
NONE_RELEASED = "- none published this month"
UNCHANGED = ("The build and images in this letter were produced by the process in the controls document, version %d, "
             "signed on %s, unchanged this month.")
CHANGED_NOW = "The controls document changed this month."
BOUND = ("The build and images in this letter were produced by the process in the controls document version that was "
         "in force on each release's date:")
OTHER = "Other versions of the controls document, signed from the first of those dates to the end of the month:"
INTRO = ("This letter rolls up public facts about evidence that is already published. It adds no new information and "
         "makes no promise beyond those facts.")
EVIDENCE = ("The signatures, provenance, SBOMs and VEX of each release are public assets of the release page "
            "linked above.")


class Refuse(Exception):
    pass


def load(path):
    if os.path.islink(path) or not os.path.isfile(path):
        raise Refuse("%s is missing or not a regular file" % os.path.basename(path))
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        raise Refuse("%s cannot be read" % os.path.basename(path))


def sha256_of(path):
    return hashlib.sha256(load(path)).hexdigest()


def load_json(path):
    try:
        return json.loads(load(path))
    except (ValueError, RecursionError):
        raise Refuse("%s is not valid JSON" % os.path.basename(path))


def quoted(text, what, limit=200):
    """A line the letter quotes from an asset: short, and only the characters of QUOTED."""
    if not (isinstance(text, str) and 0 < len(text) <= limit and QUOTED.fullmatch(text)):
        raise Refuse("%s is not one plain line of letters, digits and . , : ; ( ) ' / - (at most %d characters)"
                     % (what, limit))
    return text


def day(stamp, what):
    """The date part of a timestamp as the asset wrote it (2026-11-04T12:00:00Z gives 2026-11-04)."""
    if not (isinstance(stamp, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T.*", stamp)):
        raise Refuse("%s has no timestamp" % what)
    return stamp[:10]


def month_title(month):
    return "%s %s" % (calendar.month_name[int(month[5:])], month[:4])


def controls_versions(controls_text):
    """[(version, signed date)] from the rows `| 1 | 2026-10-20 | ... |` of the controls document, oldest first."""
    rows = re.findall(r"^\| *([0-9]+) *\| *([0-9]{4}-[0-9]{2}-[0-9]{2}) *\|", controls_text, re.M)
    if not rows:
        raise Refuse("the controls document has no version row")
    return sorted((int(v), d) for v, d in rows)


def release_dates(rel_dir):
    """{tag: published day} of every release folder, from release.json only."""
    try:
        names = sorted(os.listdir(rel_dir))
    except OSError:
        raise Refuse("the releases folder cannot be read")
    dates = {}
    for name in names:
        if TAG.fullmatch(name):
            dates[name] = day(load_json(os.path.join(rel_dir, name, "release.json")).get("published_at"), name)
    return dates


def release_of(rel_dir, name, date):
    path = os.path.join(rel_dir, name)
    info = load_json(os.path.join(path, "release.json"))
    manifest = load_json(os.path.join(path, "release-manifest.json"))
    if info.get("tag_name") != name:
        raise Refuse("the release folder %s does not match its release.json" % name)
    if info.get("html_url") != PAGE + name:
        raise Refuse("%s: the release page link is not the release's own" % name)
    if manifest.get("version") != name[1:] or not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("commit"))):
        raise Refuse("%s: the release manifest names another version or no commit" % name)
    return {"tag": name, "dir": path, "date": date, "info": info, "manifest": manifest}


def releases_used(rel_dir, month):
    """(the releases published in the month, the newest release before it). Only those are read in full: a release
    that is neither needs no v0.3 manifest, so an older one in the folder does not stop the letter."""
    dates = release_dates(rel_dir)
    in_month = sorted((d, t) for t, d in dates.items() if d.startswith(month))
    before = sorted((d, t) for t, d in dates.items() if d < month + "-01")
    releases = [release_of(rel_dir, t, d) for d, t in in_month]
    prior = release_of(rel_dir, before[-1][1], before[-1][0]) if before and not releases else None
    return releases, prior


def patch_reason(rel):
    lines = [x.strip() for x in str(rel["info"].get("body") or "").splitlines() if x.strip()]
    if not lines:
        raise Refuse("%s is a patch release with no line in its notes" % rel["tag"])
    return quoted(lines[0].lstrip("# "), "the first notes line of " + rel["tag"])


def vex_statements(rel, month):
    """[(date, name)] of the OpenVEX statements dated in the month; the file must be the one the manifest hashes."""
    path = os.path.join(rel["dir"], "fosterstack-cache.openvex.json")
    entries = [v for v in rel["manifest"].get("vex", []) if isinstance(v, dict) and v.get("form") == "openvex"]
    if len(entries) != 1 or entries[0].get("sha256") != sha256_of(path):
        raise Refuse("%s: the OpenVEX file is not the one in the release manifest" % rel["tag"])
    out = []
    for st in load_json(path).get("statements", []):
        date = day(st.get("timestamp"), rel["tag"] + " VEX statement")
        if date.startswith(month):
            name = str(st["vulnerability"]["name"])
            if not SAFE_NAME.fullmatch(name):
                raise Refuse("%s: a VEX statement name is not a plain identifier" % rel["tag"])
            out.append((date, name))
    return sorted(out)


def advisories_of(advisories, month):
    out = []
    for adv in advisories:
        date = day(adv.get("published_at"), "an advisory")
        if date.startswith(month):
            ident = str(adv["ghsa_id"])
            if not SAFE_NAME.fullmatch(ident):
                raise Refuse("an advisory id is not a plain identifier")
            out.append((date, ident, quoted(adv.get("summary"), "the summary of " + ident, 150)))
    return sorted(out)


def controls_lines(rels, month, controls_text):
    """Each release is bound to the controls version in force on its date. If the version changed in the month, or
    after the release, every such version is named too."""
    versions = controls_versions(controls_text)
    end = "%s-%02d" % (month, calendar.monthrange(int(month[:4]), int(month[5:]))[1])
    bound = {}
    for rel in rels:
        in_force = [v for v in versions if v[1] <= rel["date"]]
        if not in_force:
            raise Refuse("%s was published before the first controls version was signed" % rel["tag"])
        bound.setdefault(in_force[-1], []).append(rel["tag"])
    first = min(r["date"] for r in rels)
    other = [v for v in versions if v not in bound and v[1] <= end and (v[1].startswith(month) or v[1] > first)]
    changed = any(d.startswith(month) for _v, d in versions)
    if len(bound) == 1 and not other and not changed:
        (version, signed), = bound
        return [UNCHANGED % (version, signed)]
    lines = [CHANGED_NOW] if changed else []
    lines.append(BOUND)
    lines += ["- version %d, signed on %s: %s" % (v, d, ", ".join(tags)) for (v, d), tags in sorted(bound.items())]
    if other:
        lines.append(OTHER)
        lines += ["- version %d, signed on %s" % v for v in other]
    return lines


def check_words(text):
    """Refuses a letter that holds a forbidden word (spaces removed, so SOC 2 and SOC  2 and SOC2 are all caught)."""
    squeezed = "".join(text.lower().split())
    words = [w for w in FORBIDDEN if w in squeezed]
    if words or "@" in text:
        raise Refuse("the letter would hold a word it must not (%s) or an address" % ", ".join(words or ["@"]))


def body_of(rel_dir, month, advisories, controls_text):
    """The letter without its signature, or None when no release has ever been published."""
    releases, prior = releases_used(rel_dir, month)
    if not releases and prior is None:
        return None
    lines = ["# FosterStack evidence letter, " + month_title(month), "", INTRO, "", "## Releases"]
    if not releases:
        lines.append(NONE_RELEASED)
    for r in releases:
        link, commit = r["info"]["html_url"], r["manifest"]["commit"]
        lines.append("- %s, published %s, %s, commit %s" % (r["tag"], r["date"], link, commit))
    patches = [r for r in releases if not r["tag"].endswith(".0")]
    lines += ["", "## Patch releases"]
    lines += ["- %s: %s" % (r["tag"], patch_reason(r)) for r in patches] or [NONE]
    vex = [(r["tag"], d, n) for r in releases for d, n in vex_statements(r, month)]
    lines += ["", "## VEX statements added"]
    lines += ["- %s: %s, dated %s" % (t, n, d) for t, d, n in vex] or [NONE]
    lines += ["", "## Check records"]
    if not releases:  # the current images are those of the latest release
        lines.append("Records of %s, the latest release:" % prior["tag"])
    for r in releases or [prior]:
        for name in RECORDS:
            lines.append("- %s: %s sha256 %s" % (r["tag"], name, sha256_of(os.path.join(r["dir"], name))))
    advs = advisories_of(advisories, month)
    lines += ["", "## Advisories"]
    lines += ["- %s, published %s, %s" % (i, d, s) for d, i, s in advs] or ["- No advisory was published this month."]
    lines += ["", "## Controls"] + controls_lines(releases or [prior], month, controls_text)
    lines += ["", "## Evidence", EVIDENCE]
    return "\n".join(lines) + "\n"


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def run(a):
    if not MONTH.fullmatch(a.month):
        raise Refuse("--month is YYYY-MM")
    signatory = load(a.signatory).decode("ascii", "replace").strip()
    if PLACEHOLDER in signatory and not a.draft:
        print("evidence-letter: refused: the signatory is still the placeholder", file=sys.stderr)
        return 3
    advisories = load_json(a.advisories)
    if not isinstance(advisories, list):
        raise Refuse("the advisories file is not a list")
    controls_text = load(a.controls).decode("utf-8", "replace")
    body = body_of(a.releases, a.month, advisories, controls_text)
    if body is None:
        print("evidence-letter: no release was published in %s: no letter" % a.month)
        return 0
    if not (0 < len(signatory) <= 200 and all(" " <= c <= "~" for c in signatory)):
        raise Refuse("the signatory is not one plain line")
    text = body + SIGNED + signatory + "\n"
    check_words(text)
    os.makedirs(a.out, exist_ok=True)
    if PLACEHOLDER in signatory:
        write(os.path.join(a.out, "evidence-letter-%s.DRAFT.md" % a.month), "DRAFT: not signed, not to be sent.\n\n" + text)
    else:
        write(os.path.join(a.out, "evidence-letter-%s.md" % a.month), text)
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="evidence-letter.py")
    for name in ("month", "releases", "advisories", "controls", "signatory", "out"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--draft", action="store_true")
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return 2
    try:
        return run(a)
    except (Refuse, KeyError, TypeError, AttributeError) as why:
        reason = why if isinstance(why, Refuse) else "an asset is malformed"
        print("evidence-letter: refused: %s" % reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
