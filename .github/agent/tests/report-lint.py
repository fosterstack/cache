#!/usr/bin/env python3
"""Lint a rendered auditor report (owner's test, Sep 27; handoff 0004 ACs 3 and 5).

usage: report-lint.py [--no-render] <report.md> [...]

1. Uniqueness: within every list section (a `## ` heading or a `**…**` sub-heading), no two list
   lines (`- …`) are identical — "a list section lists one line per thing" — and every list line is
   one physical line (no item spills onto the next line).
2. Render safety: rendered with GitHub's own cmark-gfm (cmarkgfm), the report has no
   strikethrough (<del>), no emphasis (<em>), bold only where the source intends it (`**…**`
   labels), every table-looking line really is a table, and the STRUCTURE is the source's: as many
   list items, headings and blockquotes as the source writes — never one smuggled in by text
   (e.g. a `#`-led line of tool stderr becoming a heading).
--no-render skips (2) when cmarkgfm is unavailable (it never silently passes: it says so).
"""
import re, sys


def sections(text):
    cur, out = "(top)", {}
    for line in text.splitlines():
        if line.startswith("## ") or re.fullmatch(r"\*\*[^*].*\*\*", line.strip()):
            cur = line.strip(); out.setdefault(cur, []); continue
        if line.startswith("- "):
            out.setdefault(cur, []).append(line)
    return out


def one_line_problems(text):
    """Every list line is ONE physical line: a non-blank line directly after a list line that is not
    itself a list line is that item spilling over (multi-line tool stderr) — and a `#`/`>` line there
    would render as a heading/quote in the middle of the report."""
    probs, lines = [], text.splitlines()
    for i in range(1, len(lines)):
        if lines[i - 1].startswith("- ") and lines[i].strip() and not lines[i].startswith("- "):
            probs.append("list item continues onto another line: %r" % lines[i][:120])
    return probs


def uniqueness_problems(text):
    probs = []
    for sec, lines in sections(text).items():
        seen = {}
        for l in lines:
            seen[l] = seen.get(l, 0) + 1
        probs += ["%s: line repeated %d times: %s" % (sec, n, l[:160]) for l, n in seen.items() if n > 1]
    return probs


def render_problems(text):
    import cmarkgfm
    html = cmarkgfm.github_flavored_markdown_to_html(text)
    probs = []
    if "<del>" in html:
        for m in re.finditer(r"<del>(.*?)</del>", html, re.S):
            probs.append("strikethrough: %r" % m.group(1)[:120])
    for m in re.finditer(r"<em>(.*?)</em>", html, re.S):
        probs.append("unintended emphasis: %r" % m.group(1)[:120])
    import html as H

    def plain(frag):
        return H.unescape(re.sub(r"<[^>]+>", "", frag)).strip()
    # what each INTENDED `**…**` span renders to (escapes and entities resolved the same way)
    intended = {plain(re.sub(r"</?p>", "", cmarkgfm.github_flavored_markdown_to_html("**%s**" % x)))
                for x in re.findall(r"\*\*((?:\\.|[^*\\\n])+?)\*\*", text)}   # escaped chars (\*) allowed inside
    for m in re.finditer(r"<strong>(.*?)</strong>", html, re.S):
        inner = plain(m.group(1))
        if inner not in intended:
            probs.append("unintended bold: %r" % inner[:120])
    if any(l.lstrip().startswith("|") for l in text.splitlines()) and "<table>" not in html:
        probs.append("a table-looking line did not render as a table")
    lines = text.splitlines()
    want = {"list items": sum(1 for l in lines if l.startswith("- ")),
            "headings": sum(1 for l in lines if re.match(r"#{1,6} ", l)),
            "blockquotes": sum(1 for i, l in enumerate(lines) if l.startswith("> ") and (i == 0 or not lines[i - 1].startswith("> ")))}
    got = {"list items": len(re.findall(r"<li>", html)), "headings": len(re.findall(r"<h[1-6]>", html)),
           "blockquotes": len(re.findall(r"<blockquote>", html))}
    for k in want:
        if want[k] != got[k]:
            probs.append("structure: the source writes %d %s, GitHub renders %d (text changed the document's shape)"
                         % (want[k], k, got[k]))
    return probs


def main(argv):
    render = "--no-render" not in argv
    files = [a for a in argv if not a.startswith("--")]
    if render:
        try:
            import cmarkgfm  # noqa: F401
        except ImportError:
            print("report-lint: cmarkgfm not installed — install .github/agent/test-requirements.txt "
                  "or pass --no-render", file=sys.stderr)
            return 2
    bad = 0
    for f in files:
        text = open(f, encoding="utf-8").read()
        probs = uniqueness_problems(text) + one_line_problems(text) + (render_problems(text) if render else [])
        for p in probs:
            print("%s: %s" % (f, p))
        bad += len(probs)
        if not probs:
            print("%s: ok (%s)" % (f, "unique + renders clean" if render else "unique; render NOT checked"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
