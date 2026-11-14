#!/usr/bin/env bash
# proves: REQ-DEP-001-AC2, REQ-DEP-001-AC3, REQ-DEP-001-AC4, REQ-DEP-001-AC5, REQ-DEP-001-AC6, REQ-DEP-001-AC7
# proves: REQ-DEP-001-AC8, REQ-DEP-001-AC9, REQ-DEP-001-AC10, REQ-DEP-001-AC11, REQ-DEP-001-AC12
# proves: REQ-DEP-001-AC13, REQ-DEP-001-AC14, REQ-DEP-003-AC1, REQ-DEP-003-AC2, REQ-DEP-003-AC3
# proves: REQ-DEP-004-AC1, REQ-DEP-004-AC2
# Offline suite for bin/dependabot-reviewer.py (register row 75). Pure functions only:
# `gather` and `read` need gh / the model and are never called here; release_notes is
# exercised with `_gh_json` stubbed. Real Dependabot PR bodies from this repository are in
# test-evidence/dependabot-reviewer/ (#99 single major whose notes quote upstream's own
# bumps; #91 major whose commit list names certifi 2020->2024; #124 a four-member group;
# #90 a patch). The rest are written in Dependabot's own format.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
export REVIEWER_PY="$here/dependabot-reviewer.py" FIX="$repo/test-evidence/dependabot-reviewer"
python3 - <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("reviewer", os.environ["REVIEWER_PY"])
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
FIX = os.environ["FIX"]
passed = failed = 0

def check(name, cond, detail=""):
    global passed, failed
    if cond:
        print("ok: " + name); passed += 1
    else:
        print("FAIL: %s %s" % (name, detail)); failed += 1

def real(n):
    d = json.load(open(os.path.join(FIX, "pr-%d.json" % n)))
    return r.parse_updates(d["title"], d["body"])

def triples(u):
    return [(x["name"], x["from"], x["to"], x["major"]) for x in u]

# --- updates: real bodies
u = real(99)
check("real #99: exactly checkout 4->7, major (upstream's own bumps in the notes ignored)",
      triples(u) == [("actions/checkout", "4", "7", True)], triples(u))
u = real(91)
check("real #91: only setup-python 5.6.0->7.0.0 (certifi in the commit list ignored)",
      triples(u) == [("actions/setup-python", "5.6.0", "7.0.0", True)], triples(u))
u = real(124)
check("real #124 group: four codeql-action members, none major",
      len(u) == 4 and all(x["name"].startswith("github/codeql-action/") and not x["major"] for x in u), triples(u))
u = real(90)
check("real #90 patch: setup-java 6.0.0->6.0.1, not major",
      triples(u) == [("actions/setup-java", "6.0.0", "6.0.1", False)], triples(u))

# --- updates: Dependabot-format bodies
grouped = ("Bumps the actions group with 2 updates: [actions/cache](https://github.com/actions/cache) "
           "and [actions/setup-node](https://github.com/actions/setup-node).\n\n"
           "Updates `actions/cache` from 4.2.0 to 5.0.1\n<details>\n<summary>Release notes</summary>\n"
           "<blockquote>Bump foo/bar from 1 to 9</blockquote>\n</details>\n\n"
           "Updates `actions/setup-node` from 4.1.0 to 4.4.0\n<details>\n<summary>Commits</summary>\n"
           "<ul><li>Bumps [x/y](https://e) from 2 to 3.</li></ul>\n</details>\n")
u = r.parse_updates("Build(deps): bump the actions group with 2 updates", grouped)
check("group: one major + one minor, nothing from inside <details>",
      triples(u) == [("actions/cache", "4.2.0", "5.0.1", True), ("actions/setup-node", "4.1.0", "4.4.0", False)], triples(u))
u = r.parse_updates("Build(deps): bump golang from `3f3c01a` to `9e8d7c6`",
                    "Bumps golang from `3f3c01a` to `9e8d7c6`.\n\n---\n")
check("docker digest bump (digits-first digests) is NOT major",
      len(u) == 1 and u[0]["major"] is False and u[0]["from"] == "3f3c01a", triples(u))
u = r.parse_updates("", "Bumps golang from `sha256:abcdef0123456789` to `sha256:0123456789abcdef`.\n")
check("sha256:-prefixed digest bump is NOT major", len(u) == 1 and u[0]["major"] is False, triples(u))
u = r.parse_updates("Build(deps): bump golang.org/x/net from 0.21.0 to 0.22.0",
                    "Bumps [golang.org/x/net](https://github.com/golang/net) from 0.21.0 to 0.22.0.\n<details></details>")
check("gomod 0.x minor is NOT major", triples(u) == [("golang.org/x/net", "0.21.0", "0.22.0", False)], triples(u))
u = r.parse_updates("Build(deps): bump actions/setup-go from 5 to 7", "")
check("title-only fallback (empty body)", triples(u) == [("actions/setup-go", "5", "7", True)], triples(u))
u = r.parse_updates("Build(deps): bump actions/setup-go from 5 to 7", None)
check("title-only fallback (null body)", triples(u) == [("actions/setup-go", "5", "7", True)], triples(u))
# --- flagged: a non-major whose release notes (the <details> blocks) say "breaking" or "deprecat"
# goes the major path (REQ-DEP-001-AC10); the real #400 codeql group quotes a "Breaking change" note
u = real(400)
check("real #400: four non-major codeql members, all flagged (4.39.0 notes say 'Breaking change')",
      len(u) == 4 and all(x["major"] is False and x["flagged"] is True for x in u), [(x["name"], x["major"], x.get("flagged")) for x in u])
check("real #124, #90 (no such words in their notes): not flagged",
      not any(x["flagged"] for x in real(124) + real(90)), "")
check("a major is never also 'flagged' (it is already the major path); real #99 and #91",
      all(x["major"] and not x["flagged"] for x in real(99) + real(91)), "")
def one(body, title="Build(deps): bump x/y from 1.2.0 to 1.3.0"):
    return r.parse_updates(title, body)
NOTE = "Bumps x/y from 1.2.0 to 1.3.0.\n<details>\n<summary>Release notes</summary>\n<p>%s</p>\n</details>\n"
check("flagged: 'breaking' in the notes", one(NOTE % "Breaking change: drop old API")[0]["flagged"] is True, "")
check("flagged: 'deprecat' in the notes (Deprecated, DEPRECATION, deprecates)",
      all(one(NOTE % w)[0]["flagged"] is True for w in ("Deprecated the flag", "DEPRECATION notice", "deprecates foo")), "")
check("flagged: the words in the commit list <details> count too",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n<details><summary>Commits</summary><ul><li>deprecate old</li></ul></details>")[0]["flagged"] is True, "")
check("not flagged: ordinary notes", one(NOTE % "Fixes a typo")[0]["flagged"] is False, "")
check("flagged: the words OUTSIDE the <details> blocks count too (the whole body is read; over-flagging only reaches the readers)",
      one("Bumps x/y from 1.2.0 to 1.3.0. This is a breaking or deprecated thing.\n<details><summary>Release notes</summary>fine</details>")[0]["flagged"] is True, "")
check("not flagged: no notes at all (a digest bump)",
      one("Bumps golang from `3f3c01a` to `9e8d7c6`.\n", "Build(deps): bump golang from `3f3c01a` to `9e8d7c6`")[0]["flagged"] is False, "")
check("flagged: a words-in-nested-details body still flags", 
      one("Bumps x/y from 1.2.0 to 1.3.0.\n<details><summary>a</summary><details><summary>b</summary>breaking</details></details>")[0]["flagged"] is True, "")
check("unclosed / stray <details> tags without those words are not flagged; with them they are",
      [one("Bumps x/y from 1.2.0 to 1.3.0.\n%s" % b)[0]["flagged"] for b in ("<details><summary>Release notes</summary>fine", "</details> stray", "<details>unclosed breaking")] == [False, False, True], "")
check("flagged: <details open> is a block like any other, its words count",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n<details open>Breaking change</details>")[0]["flagged"] is True, "")
check("not flagged: <details open> with ordinary notes, balanced",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n<details open><summary>s</summary>fine</details>")[0]["flagged"] is False, "")
# what the reader sees (round 2): comments, quoted attributes, references, code, fences
RENDERED = ["break<b>ing</b> change", "depre&#99;ated", "&lt;breaking change&gt;", "break<!-- > -->ing", "depre<span title=\">\">cat</span>ed",
            "<code>&lt;breaking&gt;</code>", "<!-- </details> -->Breaking change<!-- <details> -->", "```\n<details>deprecated</details>\n```", "DEPRECATION", "BrEaKiNg"]
check("flagged: every shape of the words a reader sees (tags/comments splitting a word, references, entity-escaped code, fences, case)",
      all(one("Bumps x/y from 1.2.0 to 1.3.0.\n<details>%s</details>" % w)[0]["flagged"] is True for w in RENDERED),
      [w for w in RENDERED if not one("Bumps x/y from 1.2.0 to 1.3.0.\n<details>%s</details>" % w)[0]["flagged"]])
MDSPLIT = ["**Break**ing change", "Depre*cat*ed API", "[Break](https://example.invalid)ing change", "break**ing** change", "![break*ing*](https://example.invalid/i.png)",
           "break_ing_ change", "~~brea~~king", "`break`ing"]
check("flagged: Markdown formatting, links and image alt text splitting the words (round 3)",
      all(one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"] is True for w in MDSPLIT),
      [w for w in MDSPLIT if not one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"]])
MDLINK = ["[Break][ref]ing change\n\n[ref]: https://example.invalid", "[Break](https://example.invalid/(a)b)ing change", "[Break](https://example.invalid/a(b)c)ing",
          "[Break](u \"a)b\")ing", "[Break]ing change\n\n[break]: https://e.invalid", "x[Break](u)ing"]
check("flagged: valid Markdown link/reference forms that hide the word's pieces are unresolvable and flagged (round 4)",
      all(one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"] is True for w in MDLINK),
      [w for w in MDLINK if not one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"]])
MDCOMBO = ["[Break](https://example.invalid/a(b)/c)**ing** change", "[Depre](u(a)/b)*cat*ed", "[Break][ref]**ing** change\n\n[ref]: https://example.invalid",
           "[Break][ref]<b>ing</b> change\n\n[ref]: https://example.invalid", "[Break](https://e.invalid/\n(x))ing", "[Break](u \"a)b\")**ing**", "[Break](unterminated"]
check("flagged: combined link, reference and formatting forms (round 5)",
      all(one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"] is True for w in MDCOMBO),
      [w for w in MDCOMBO if not one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"]])
MDEXO = ["[Break][ref\\]*x]**ing** change\n\n[ref\\]*x]: https://example.invalid", "[Break][r\\] x]**ing** change\n\n[r\\] x]: https://example.invalid",
         "[Depre][r\\] x]**cated**\n\n[r\\] x]: https://e.invalid", "[Break](<#a)/b>)**ing** change", "[Depre](<../a)/b>)*cat*ed", "[Break][r&#93; x]**ing**\n\n[r&#93; x]: u",
         "[Break][r&#x5d; x]**ing**", "[Break][r&rbrack; x]**ing**",
         "[Break](a&#41;b)<em>ing</em>", "[Break](a&#x29;b)<b>ing</b>", "[Break](a&rpar;b)**ing**", "[Depre](a&#0041;b)<i>cat</i>ed", "[Break](a&#40;b)<em>ing</em>", "[Break](a&lpar;b)<em>ing</em>",
         "[Break](a&#X29;b)<em>ing</em>", "[Break](a&#x0029;b)<em>ing</em>", "[Break](a&#00000041;b)<em>ing</em>", "[Break](a&#41b)<em>ing</em>", "[Break](a&RPAR;b)<em>ing</em>",
         "[Break](a&Rpar;b)<em>ing</em>", "[Depre](a&#x29;b)*cat*ed", "[Break](a&#9;b)<em>ing</em>", "[Break](a&Tab;b)<em>ing</em>", "[Break](a&amp;b)<em>ing</em>"]
check("flagged: escaped or encoded brackets and <angle> destinations are unresolved link syntax and flagged (round 6, the class closed)",
      all(one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"] is True for w in MDEXO),
      [w for w in MDEXO if not one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n%s\n\n</details>" % w)[0]["flagged"]])
check("not flagged: a URL's &key=value (Dependabot's own badge URL) is not a character reference",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n\n[![c](https://example.invalid/badge?dependency-name=x%2Fy&package-manager=github_actions&previous-version=1.2.0&new-version=1.3.0)](https://example.invalid/docs)")[0]["flagged"] is False, "")
check("a body with a character reference but NO link syntax is judged on its words alone (no blanket flag)",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>Fixes &amp; speeds up &lt;things&gt;</details>")[0]["flagged"] is False, "")
check("not flagged: real Dependabot bodies #90, #91, #124 still pass the closed class", not any(r.is_flagged(json.load(open(os.path.join(FIX, "pr-%d.json" % n)))["body"]) for n in (90, 91, 124)), "")
check("not flagged: Markdown links with ordinary words, nested parentheses and titles",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\nSee [the docs](https://e.invalid/a(b)/c \"a title\") and [more][ref] for **details**.\n\n[ref]: https://e.invalid\n\n</details>")[0]["flagged"] is False, "")
check("not flagged: ordinary Markdown with links and emphasis",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n\n<details>\n\n**Fixes** a [typo](https://example.invalid/typo) and `speeds` up *parsing*.\n\n</details>")[0]["flagged"] is False, "")
check("not flagged: tags, comments and references around ordinary words",
      one("Bumps x/y from 1.2.0 to 1.3.0.\n<details><p>Fixes &amp; <b>speed</b><!-- note --></p></details>")[0]["flagged"] is False, "")
_T = r._Text
r._Text = None
_unreadable = r.is_flagged("x")
r._Text = _T
check("a body the parser cannot read is flagged (fail toward the readers)", _unreadable is True, "")
# a body whose update lines cannot be read is still read: one placeholder, flagged or not (round 2, seat A; every bump
# is read)
u = r.parse_updates("Bump the actions group with 1 update",
    "Bumps the actions group with 1 update.\n<!-- <details> -->\nUpdates `x/y` from 1.0.0 to 1.1.0\n<details><summary>Release notes</summary>Breaking: removed.</details>\n<!-- </details> -->\n<!-- <details> -->\n")
check("flagged body with unreadable update lines -> one placeholder of its own kind (unparsed), flagged, major false",
      len(u) == 1 and u[0]["kind"] == "unparsed" and u[0]["flagged"] is True and u[0]["major"] is False
      and "unparsed" in u[0]["name"], u)
u = r.parse_updates("t", "nothing to see")
check(
      "an unflagged body with no update lines -> one placeholder too, kind unparsed (never not-major: it is not the "
      "lane's), not flagged: the pull request is still read",
      len(u) == 1 and u[0]["kind"] == "unparsed" and u[0]["flagged"] is False and u[0]["major"] is False
      and "unparsed" in u[0]["name"], u)
check("title-only fallback (no body) is not flagged", one("", "Build(deps): bump x/y from 1.2.0 to 1.3.0")[0]["flagged"] is False, "")
check("kind = major, else flagged, else not-major (what the bundle calls the update)",
      [x["kind"]
      for x in r.parse_updates("t",
      "Updates `a/b` from 1.0.0 to 2.0.0\nUpdates `c/d` from 1.0.0 to 1.1.0\n<details>breaking</details>")]
      == ["major", "flagged"]
      and [x["kind"] for x in one(NOTE % "Fixes a typo")] == ["not-major"], "")
# gather fetches notes and our usage for EVERY update (a plain patch or minor too) and says what each one is
calls = []
_saved = (r._run, r.release_notes, r.our_usage, r._gh_json)
r._run = lambda cmd: ("diff --git a/x b/x\n", 0)
r._gh_json = lambda args: [
      {"sha": "d" * 40, "parents": [{}], "author": {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"},
                            "committer": {"login": "web-flow"},
                            "commit": {"message": "Bump a/flag", "verification": {"verified": True}}}]
r.release_notes = lambda n, o, nw: (calls.append(n) or ("notes of " + n + "\n", 1))
r.our_usage = lambda n: "usage of " + n + "\n"
import tempfile
def gathered(updates):
    del calls[:]
    d = tempfile.mkdtemp(); p = os.path.join(d, "u.json"); json.dump(updates, open(p, "w"))
    class A: pass
    a = A(); a.pr, a.sha, a.base, a.updates, a.out = 7, "d" * 40, "main", p, os.path.join(d, "out")
    r.cmd_gather(a)
    return open(os.path.join(a.out, "bundle.md")).read()
import io as _gio, contextlib as _gcl
with _gcl.redirect_stdout(_gio.StringIO()):
    b = gathered(
          [{"name": "a/flag", "from": "1.0.0", "to": "1.1.0", "major": False, "flagged": True, "kind": "flagged"},
                  {"name": "a/plain", "from": "1.0.0", "to": "1.0.1", "major": False, "flagged": False,
                  "kind": "not-major"},
                  {"name": "a/big", "from": "1.0.0", "to": "2.0.0", "major": True, "flagged": False, "kind": "major"}])
    calls_all = list(calls)
    b_old = gathered(
          [{"name": "a/old", "from": "1.0.0", "to": "2.0.0", "major": True},
          {"name": "a/oldminor", "from": "1.0.0", "to": "1.0.1", "major": False}])
r._run, r.release_notes, r.our_usage, r._gh_json = _saved
check("gather: notes and usage for every update: the flagged, the plain patch and the major",
      calls_all == ["a/flag", "a/plain", "a/big"], calls_all)
check("gather: the bundle calls each update what it is (FLAGGED, not major, MAJOR)",
      "a/flag: 1.0.0 -> 1.1.0 (FLAGGED" in b and "a/flag: 1.0.0 -> 1.1.0 (MAJOR" not in b and "a/plain: 1.0.0 -> 1.0.1 (not major)" in b and "a/big: 1.0.0 -> 2.0.0 (MAJOR)" in b, b[:400])
check("gather: an update with no `kind` is named from its own fields",
      "a/old: 1.0.0 -> 2.0.0 (MAJOR)" in b_old and "a/oldminor: 1.0.0 -> 1.0.1 (not major)" in b_old, b_old[:300])
# --- the commit list: which commits are not Dependabot's own (REQ-DEP-001-AC2)
def commit(sha, login="dependabot[bot]", uid=49699333, typ="Bot", committer="web-flow", verified=True, parents=1,
      msg="Bump x"):
    return {"sha": sha * 40, "parents": [{}] * parents,
          "author": {"login": login, "id": uid, "type": typ} if login else None,
            "committer": {"login": committer},
            "commit": {"message": msg, "author": {"name": "git name"}, "verification": {"verified": verified}}}
_saved_gh = r._gh_json
def commits_of(pages, repo="o/r", sha=None):
    asked = []
    if sha is None:   # the commit the verdict is for: by default the last one listed
        listed = [c for pg in pages if pg for c in pg]
        sha = listed[-1]["sha"] if listed else "0" * 40
    r._gh_json = lambda args: (asked.append(args[0]) or (pages[len(asked) - 1] if len(asked) <= len(pages) else []))
    was = os.environ.pop("GITHUB_REPOSITORY", None)
    if repo:
        os.environ["GITHUB_REPOSITORY"] = repo
    try:
        return r.pr_commits(7, sha) + (asked,)
    finally:
        r._gh_json = _saved_gh
        os.environ.pop("GITHUB_REPOSITORY", None)
        if was is not None:
            os.environ["GITHUB_REPOSITORY"] = was
text, ok, asked = commits_of(
      [
      [commit("a"),
      commit("b", login="some-writer", uid=7, typ="User", committer="some-writer", msg="Keep our pin\n\nbody"),
                               commit("c", login="lane[bot]", uid=9, committer="web-flow", parents=2,
                               msg="Merge branch 'main' into x")]])
check(
      "commits: Dependabot's own commit is unmarked; a writer's commit and a merge of main are marked NOT "
      "Dependabot's, first line only",
      ok == "ok"
      and text.splitlines()
      == ["- aaaaaaaaaa dependabot[bot]: Bump x", "- bbbbbbbbbb NOT Dependabot's — some-writer: Keep our pin",
                                   "- cccccccccc NOT Dependabot's — lane[bot] (a merge commit): Merge branch "
                                   "'main' into x"], text)
check("commits: the list is read from this repository's pull request, page 1",
      asked == ["repos/o/r/pulls/7/commits?per_page=100&page=1"], asked)
_, _, asked = commits_of([[commit("a")]], repo=None)
check("commits: with no GITHUB_REPOSITORY the repository is left to gh (its {owner}/{repo} of the checkout)",
      asked == ["repos/{owner}/{repo}/pulls/7/commits?per_page=100&page=1"], asked)
IMPOSTORS = {"author spelled as Dependabot but not signed (anyone can write an author line)":
      commit("d", verified=False),
             "author Dependabot, committed by somebody else": commit("d", committer="some-writer"),
             "another account with the same login": commit("d", uid=1),
             "a user, not a bot": commit("d", typ="User"),
             "a merge commit authored by Dependabot": commit("d", parents=2),
             "no account on the author": commit("d", login=None)}
for why, c in IMPOSTORS.items():
    text, ok, _ = commits_of([[c]])
    check("commits: %s is marked NOT Dependabot's" % why, ok == "ok" and "NOT Dependabot's" in text, text)
text, ok, _ = commits_of([None])
check("commits: a failed read is UNAVAILABLE and not ok, never an empty list",
      ok == "unavailable" and "commit list UNAVAILABLE" in text, text)
text, ok, _ = commits_of([[]])
check("commits: an empty answer (no open pull request has no commit) is UNAVAILABLE and not ok",
      ok == "unavailable" and "UNAVAILABLE" in text, text)
text, ok, _ = commits_of([[commit("a")] * 100, None])
check("commits: a later page that cannot be read is UNAVAILABLE too", ok == "unavailable" and "UNAVAILABLE" in text,
      text)
text, ok, asked = commits_of(
      [[commit("a")] * 100, [commit("b", login="w", uid=7, typ="User")] * 100, [commit("c")] * 50])
check(
      "commits: 250 listed commits (GitHub lists no more, so the list cannot be shown to end at the head) is "
      "UNAVAILABLE, after all three pages were read",
      ok == "unavailable" and len(asked) == 3 and "at most 250 commits" in text, (ok, len(asked)))
text, ok, _ = commits_of([[commit("a"), commit("b", login="w", uid=7, typ="User")]], sha="a" * 40)
check(
      "commits: a list whose last commit is not the commit the verdict is for -> moved (the head is another commit "
      "by now)", ok == "moved" and "no longer " + "a" * 40 in text, (ok, text))
text, ok, _ = commits_of([[commit("a"), commit("b", login="w", uid=7, typ="User")]], sha="b" * 40)
check("commits: the list ends at the commit the verdict is for -> ok", ok == "ok", (ok, text))

# --- the diff the readers get: whole, never cut; vendored module files by header only while the vendor check is
# required
VDIFF = (
      "diff --git a/go.mod b/go.mod\nindex 1..2 100644\n--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n-require a/b "
      "v1.0.0\n+require a/b v1.1.0\n"
         "diff --git a/vendor/a/b/x.go b/vendor/a/b/x.go\nindex 3..4 100644\n--- a/vendor/a/b/x.go\n+++ "
         "b/vendor/a/b/x.go\n@@ -1,2 +1,3 @@\n package b\n-old()\n+new()\n+more()\n"
         "diff --git a/internal/vendor/y.go b/internal/vendor/y.go\nindex 5..6 100644\n--- "
         "a/internal/vendor/y.go\n+++ b/internal/vendor/y.go\n@@ -1 +1 @@\n-ours()\n+OURS()\n"
         "diff --git a/vendor/a b.go b/vendor/a b.go\nindex 7..8 100644\n--- a/vendor/a b.go\n+++ b/vendor/a "
         "b.go\n@@ -1 +1 @@\n-spaced()\n+SPACED()\n"
         "diff --git a/cmd/z.go b/vendor/z.go\nsimilarity index 90%\nrename from cmd/z.go\nrename to vendor/z.go\n@@ "
         "-1 +1 @@\n-moved()\n+MOVED()\n")
sd = r.shown_diff(VDIFF, True)
check(
      "shown_diff: a file under vendor/ keeps its header and says how many lines are not shown and which required "
      "check judges them",
      "diff --git a/vendor/a/b/x.go b/vendor/a/b/x.go\n(a vendored module file: 2 added and 1 removed line(s) not "
      "shown; the required `vendor` check" in sd
      and "+new()" not in sd and "+more()" not in sd, sd)
check(
      "shown_diff: every other file is whole: ours, a path that only contains vendor, a path with a space, a file "
      "moved INTO vendor/ from outside",
      all(x in sd for x in ("+require a/b v1.1.0", "+OURS()", "+SPACED()", "+MOVED()", "rename from cmd/z.go")), sd)
check("shown_diff: with the vendor check not required, nothing is left out", r.shown_diff(VDIFF, False) == VDIFF, "")
_t = tempfile.mkdtemp()
json.dump({"required_checks": [{"context": "test"}, {"context": "vendor"}]}, open(os.path.join(_t, "with.json"), "w"))
json.dump({"required_checks": [{"context": "test"}]}, open(os.path.join(_t, "without.json"), "w"))
open(os.path.join(_t, "broken.json"), "w").write("{")
check(
      "vendor_is_required: only when main's required-check list holds `vendor`; a list without it, unreadable or "
      "missing is no",
      [r.vendor_is_required(os.path.join(_t, f))
      for f in ("with.json", "without.json", "broken.json", "missing.json")] == [True, False, False, False], "")
check("vendor_is_required: this repository's list holds it (so a module bump's vendored files are left to that check)",
      r.vendor_is_required(
      os.path.join(os.path.dirname(os.environ["REVIEWER_PY"]), "..", ".github/policy/required-checks.json")) is True,
      "")
ran = []
def gather_diff(diff, required, sha="a" * 40):
    del ran[:]
    d = tempfile.mkdtemp()
    u = os.path.join(d, "u.json")
    json.dump([{"name": "a/b", "from": "1.0.0", "to": "1.1.0", "major": True, "kind": "not-major"}], open(u, "w"))
    class A: pass
    a = A(); a.pr, a.sha, a.base, a.updates, a.out = 7, sha, "main", u, os.path.join(d, "out")
    saved = (r._run, r.release_notes, r.our_usage, r._gh_json, r.vendor_is_required)
    r._run = lambda cmd: (ran.append(cmd) or (diff, 0))
    r._gh_json = lambda args: [commit("a")]
    r.release_notes = lambda n, o, nw: ("notes\n", 1)
    r.our_usage = lambda n: "usage\n"
    r.vendor_is_required = lambda: required
    try:
        with _gcl.redirect_stdout(_gio.StringIO()), _gcl.redirect_stderr(_gio.StringIO()) as err:
            try:
                r.cmd_gather(a); code = 0
            except SystemExit as e:
                code = e.code
        return code, (open(os.path.join(a.out, "bundle.md")).read()
              if os.path.exists(os.path.join(a.out, "bundle.md")) else None), err.getvalue()
    finally:
        r._run, r.release_notes, r.our_usage, r._gh_json, r.vendor_is_required = saved
# well over the 20000 the diff used to be cut at
big = "diff --git a/x b/x\n" + "".join("+line %06d of what the pull request changes\n" % i for i in range(1200))
code, b, _ = gather_diff(big, False)
check(
      "gather: a diff of %d characters reaches the readers whole: its last line is in the bundle and nothing says "
      "truncated" % len(big),
      code == 0 and "+line 001199 of what the pull request changes" in b and "truncated" not in b, code)
over = "diff --git a/x b/x\n" + "+" + "y" * r.CAP_DIFF + "\n"
code, b, err = gather_diff(over, False)
check("gather: a diff over the readers' limit is never cut: exit 3, no bundle, so no reader and no verdict",
      code == 3 and b is None and "over the %d" % r.CAP_DIFF in err, (code, err))
vend = ("diff --git a/go.mod b/go.mod\n+require a/b v1.1.0\n"
        + "diff --git a/vendor/a/b/x.go b/vendor/a/b/x.go\n--- a/vendor/a/b/x.go\n+++ b/vendor/a/b/x.go\n"
        "@@ -1 +1,2 @@\n"
        + "+" + "y" * r.CAP_DIFF + "\n")
code, b, _ = gather_diff(vend, True)
check(
      "gather: a module bump whose vendored files alone exceed the limit is judged: go.mod whole, the vendored file "
      "by header",
      code == 0 and "+require a/b v1.1.0" in b
      and "a vendored module file: 1 added and 0 removed line(s) not shown" in b and "yyyy" not in b, code)
code, b, _ = gather_diff(vend, False)
check(
      "gather: the same bump while `vendor` is NOT a required check is shown whole, so it is over the limit: no "
      "bundle", code == 3 and b is None, code)

# --- the verdict's commit (REQ-DEP-001-AC2): the diff is GitHub's diff of exactly that commit against main, read by
# its id
code, b, _ = gather_diff("diff --git a/x b/x\n+one\n", False)
check(
      "gather: the diff is read as compare/main...<the commit's full id>, with gh api and nothing else (never the "
      "pull request's diff of the moment)",
      code == 0
      and ran
      == [
      ["gh", "api", "-H", "Accept: application/vnd.github.diff",
      "repos/%s/compare/main...%s" % (os.environ.get("GITHUB_REPOSITORY") or "{owner}/{repo}", "a" * 40)]], ran)
check("gather: the bundle names the commit it is for, in its title and over the diff",
      b.startswith("# Bundle for Dependabot PR #7 at its head %s\n" % ("a" * 40))
      and "every commit above: %s against main)" % ("a" * 40) in b, b[:200])
code, b, err = gather_diff("diff --git a/x b/x\n+one\n", False, sha="b" * 40)
check(
      "gather: the pull request's commits end at another commit than the one the verdict is for -> exit 5, no diff "
      "read, no bundle",
      code == 5 and b is None and ran == [] and "moved" in err, (code, ran, err))
for bad_sha in ("main", "a" * 39, "A" * 40, "refs/pull/7/head"):
    code, b, err = gather_diff("diff --git a/x b/x\n+one\n", False, sha=bad_sha)
    check("gather: %r is not a full commit id -> exit 3, nothing read, no bundle" % bad_sha,
          code == 3 and b is None and ran == [], (code, ran))

# --- a binary file's bytes are not in a diff: gather refuses such a diff, with the test same-diff uses
# (REQ-DEP-001-AC2)
BIN_FILE = ("diff --git a/go.mod b/go.mod\n+require a/b v1.1.0\ndiff --git a/tool.bin b/tool.bin\nindex 1..2 100755\n"
            "Binary files a/tool.bin and b/tool.bin differ\n")
code, b, err = gather_diff(BIN_FILE, False)
check("gather: a diff that names a changed binary file -> exit 3, no bundle (the readers cannot be given its bytes)",
      code == 3 and b is None and "binary file" in err, (code, err))
code, b, err = gather_diff("diff --git a/x.bin b/x.bin\nindex 1..2 100644\nGIT binary patch\nliteral 3\n", False)
check("gather: a git binary patch -> exit 3, no bundle", code == 3 and b is None and "binary file" in err, (code, err))
code, b, _ = gather_diff(
      "diff --git a/x b/x\n+Binary files are mentioned in a changed line\n-GIT binary patch, said a removed line\n",
      False)
check("gather: the words inside a changed line are not a binary file: bundled",
      code == 0 and "+Binary files are mentioned" in b, code)
VBIN = ("diff --git a/go.mod b/go.mod\n+require a/b v1.1.0\n"
        "diff --git a/vendor/a/b/data.bin b/vendor/a/b/data.bin\nindex 1..2 100644\n"
        "Binary files a/vendor/a/b/data.bin and b/vendor/a/b/data.bin differ\n")
code, b, _ = gather_diff(VBIN, True)
check(
      "gather: a binary file under vendor/ while the vendor check is required is shown by its header like any "
      "vendored file (that check compares its bytes): bundled",
      code == 0 and "diff --git a/vendor/a/b/data.bin b/vendor/a/b/data.bin\n(a vendored module file:" in b
      and "Binary files" not in b, code)
code, b, _ = gather_diff(VBIN, False)
check("gather: the same vendored binary file while the vendor check is NOT required -> exit 3, no bundle",
      code == 3 and b is None, code)
_src = open(os.environ["REVIEWER_PY"]).read()
check("gather and same-diff use one test for a binary file",
      r._has_binary(BIN_FILE) and "_has_binary(texts[0])" in _src and "_has_binary(diff)" in _src, "")
# SCF rule 7: _has_binary is true only when a line of the diff starts with "Binary files " or "GIT binary patch"
for name, diff, want in (
        ("a Binary files line", "diff --git a/t.bin b/t.bin\nBinary files a/t.bin and b/t.bin differ\n", True),
        ("a GIT binary patch line", "diff --git a/t.bin b/t.bin\nGIT binary patch\nliteral 3\n", True),
        ("the words Binary files in an added line", "diff --git a/n.md b/n.md\n+Binary files are not shown\n", False),
        ("the words Binary files in a context line", "diff --git a/n.md b/n.md\n Binary files are not shown\n", False),
        ("the words GIT binary patch in a removed line", "diff --git a/n.md b/n.md\n-GIT binary patch\n", False),
        ("the words Binary files in the middle of a line",
         "diff --git a/n.md b/n.md\n@@ -1 +1 @@ see Binary files here\n", False),
        ("a diff with no binary line", "diff --git a/go.mod b/go.mod\n+require a/b v1.1.0\n", False)):
    check("_has_binary: %s -> %s" % (name, want), r._has_binary(diff) is want, r._has_binary(diff))
# _is_vendored is true only for the header of a file under vendor/ that is not renamed, with no space in its new path
for name, head, want in (
        ("a vendor file header", "diff --git a/vendor/x/y.go b/vendor/x/y.go", True),
        ("a file outside vendor/", "diff --git a/go.mod b/go.mod", False),
        ("a rename from vendor/ to another path", "diff --git a/vendor/x/y.go b/other/y.go", False),
        ("a rename from another path into vendor/", "diff --git a/other/y.go b/vendor/x/y.go", False),
        ("a vendor-like path that is not vendor/", "diff --git a/vendors/x b/vendors/x", False),
        ("a new path with a space", "diff --git a/vendor/x b/vendor/x y", False),
        ("a line that is not a header", "+diff --git a/vendor/x b/vendor/x", False)):
    check("_is_vendored: %s -> %s" % (name, want), r._is_vendored(head) is want, r._is_vendored(head))

# --- same-diff: the spend guard's proof that two heads change main in the same way (REQ-DEP-001-AC11)
D1 = ("diff --git a/go.mod b/go.mod\nindex 1..2 100644\n--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n"
      "-require a/b v1.0.0\n+require a/b v1.1.0\n")
def same(diffs, fail=()):
    asked = []
    saved = r._run
    r._run = lambda cmd: (asked.append(cmd)
          or (("", 1) if cmd[-1].rsplit("...", 1)[1] in fail else (diffs[cmd[-1].rsplit("...", 1)[1]], 0)))
    try:
        return r.same_diff("o/r", "main", ["old", "new"]) + (asked,)
    finally:
        r._run = saved
ok, why, asked = same({"old": D1, "new": D1})
check("same-diff: byte for byte the same diff against main -> the same", ok is True, why)
check("same-diff: both diffs are GitHub's diff of the commit against its merge base with main, read and nothing else",
      asked
      == [["gh", "api", "-H", "Accept: application/vnd.github.diff", "repos/o/r/compare/main...%s" % x]
      for x in ("old", "new")], asked)
for name, new in (("one more changed line", D1 + "+one more\n"), ("another version", D1.replace("v1.1.0", "v1.1.1")),
      ("a shifted hunk", D1.replace("@@ -1 +1 @@", "@@ -2 +2 @@")),
                  ("a mode change",
                  D1.replace("index 1..2 100644\n", "old mode 100644\nnew mode 100755\nindex 1..2\n")),
                  ("one byte of trailing space", D1 + " ")):
    ok, why, _ = same({"old": D1, "new": new})
    check("same-diff: %s -> not the same" % name, ok is False and "differ" in why, why)
ok, why, _ = same({"old": D1, "new": D1}, fail=("old",))
check("same-diff: a diff that cannot be read -> not the same", ok is False and "could not be read" in why, why)
ok, why, _ = same({"old": "", "new": ""})
check("same-diff: two empty diffs -> not the same (an empty answer is not a diff)", ok is False, why)
BIN = "diff --git a/x.bin b/x.bin\nindex 1..2 100644\nBinary files a/x.bin and b/x.bin differ\n"
ok, why, _ = same({"old": BIN, "new": BIN})
check("same-diff: the same text naming a binary file -> not the same (the bytes are not in a diff)",
      ok is False and "binary" in why, why)
GBIN = "diff --git a/x.bin b/x.bin\nindex 1..2 100644\nGIT binary patch\nliteral 3\n"
ok, why, _ = same({"old": GBIN, "new": GBIN})
check("same-diff: a git binary patch -> not the same", ok is False and "binary" in why, why)
TXT = D1 + "+Binary files are mentioned in a changed line\n"
ok, why, _ = same({"old": TXT, "new": TXT})
check("same-diff: the words 'Binary files' inside a changed line are not a binary file", ok is True, why)
HUGE = "diff --git a/x b/x\n+" + "y" * r.CAP_DIFF + "\n"
ok, why, _ = same({"old": HUGE, "new": HUGE})
check("same-diff: over the readers' limit -> not the same", ok is False and "over" in why, why)
check("is_major: v1.2.3 -> v2.0.0", r.is_major("v1.2.3", "v2.0.0") is True)
check("is_major: 0.21.0 -> 0.22.0 is not", r.is_major("0.21.0", "0.22.0") is False)
check("is_major: unparseable is not", r.is_major("latest", "stable") is False)

# --- release-note range (floating major pins) and release_notes with _gh_json stubbed
V = r._vertuple
got = [t for t in ("v4.2.0", "v5.0.0", "v6.1.0", "v7.0.0", "v7.0.1", "v8.0.0") if r.in_range(V(t), V("4"), V("7"))]
check("range 4 -> 7 = every 5.x..7.x, no 4.x, no 8", got == ["v5.0.0", "v6.1.0", "v7.0.0", "v7.0.1"], got)
got = [t for t in ("v5.6.0", "v5.6.1", "v6.0.0", "v7.0.0", "v7.0.1") if r.in_range(V(t), V("5.6.0"), V("7.0.0"))]
check("range 5.6.0 -> 7.0.0 is exact", got == ["v5.6.1", "v6.0.0", "v7.0.0"], got)
r._gh_json = lambda args: [{"tag_name": "v7.0.0", "name": "seven", "body": "removed input foo"},
                           {"tag_name": "v4.3.0", "name": "old", "body": "not ours"},
                           {"tag_name": "v5.0.0", "name": "five", "body": "node24"}]
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: in-range releases oldest first, counted",
      n == 2 and text.index("v5.0.0") < text.index("v7.0.0") and "v4.3.0" not in text, (n, text))
r._gh_json = lambda args: [{"tag_name": "v3.0.0", "body": "older"}]
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: none found is said, count 0", n == 0 and "no upstream release notes found" in text, (n, text))
r._gh_json = lambda args: None
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: a failed API read is UNAVAILABLE (count None), never 'none found' (owner, Oct 1)",
      n is None and "UNAVAILABLE" in text and "no upstream release notes found" not in text, (n, text))
_newer = [{"tag_name": "v9.%d.0" % i, "body": "later"} for i in range(100)]
r._gh_json = lambda args: (_newer if args[0].endswith(("&page=1", "&page=2", "&page=3"))
                           else [{"tag_name": "v7.0.0", "body": "the one"}, {"tag_name": "v4.0.0", "body": "old"}])
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: an in-range release on page 4 is found, never 'none found' (round 1 B2)", n == 1 and "the one" in text, (n, text[:120]))
_bp = [{"tag_name": "v9.%d.0" % i, "body": "later"} for i in range(99)] + [{"tag_name": "v4.2.1", "body": "backport"}]
r._gh_json = lambda args: (_bp if args[0].endswith("&page=1") else
                           [{"tag_name": "v5.0.0", "body": "removed foo"}, {"tag_name": "nightly", "body": "n"},
                            {"tag_name": "codeql-bundle-20260101", "body": "b"}] if args[0].endswith("&page=2") else [])
text, n = r.release_notes("actions/checkout", "4.2.2", "7")
check("release_notes: a backport interleaved on page 1 never ends the read early; v5.0.0 on page 2 is found (round 2 B2)",
      n == 1 and "removed foo" in text, (n, text[:120]))
check("release_notes: non-version tags (nightly, codeql-bundle-*) never crash the read (round 2 Sonnet)", True, "")
r._gh_json = lambda args: _newer
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: pages run out before the old version is reached -> UNAVAILABLE (round 1 B2)", n is None and "UNAVAILABLE" in text, (n, text[:120]))
text, n = r.release_notes("golang", "`3f3c01a`", "`9e8d7c6`")
check("release_notes: non-GitHub dependency is said, count 0", n == 0 and "not a GitHub-hosted" in text, (n, text))

# --- normalize_findings: errors, never a pass
f, e = r.normalize_findings({"findings": [{"severity": "critical", "title": "x"}]})
check("unknown severity is an error", f is None and "no known severity" in e, (f, e))
f, e = r.normalize_findings({"verdict": "fine"})
check("missing findings list is an error", f is None and e, (f, e))
f, e = r.normalize_findings(None)
check("unparseable answer is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": ["just a string"]})
check("non-object finding is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "noise", "title": "n"}, {"severity": "Breaks-Us", "title": "b"},
                                          {"severity": "check", "title": "c"}]})
check("valid answer ranked breaks-us, check, noise (case-insensitive)",
      e is None and [x["severity"] for x in f] == ["breaks-us", "check", "noise"], (f, e))
f, e = r.normalize_findings(r.parse_answer('```json\n{"findings": []}\n```'))
check("one object in one code fence = read, nothing found", e is None and f == [], (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": []}'))
check("bare object = read, nothing found", e is None and f == [], (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [], "unfinished": {"findings": []}'))
check("truncated answer is an error, not an inner object (round-1 P1)", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": []}\n{"findings": [{"severity": "breaks-us", "title": "x"}]}'))
check("two objects is an error, never the first one only", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('Here you go:\n{"findings": []}'))
check("prose around the object is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "claude-opus-9 says critical", "title": "x"}]})
check("the unknown-severity error never echoes the value", f is None and "claude" not in e.lower() and "opus" not in e.lower(), e)
os.environ["AUDITOR_MODEL_FALLBACK"] = "Secret-Model-X"
f, e = r.normalize_findings({"findings": [{"severity": "SECRET-MODEL-X", "title": "x"}]})
check("a configured identifier in a transformed severity never reaches the error", f is None and "secret-model-x" not in e.lower(), e)
f, e = r.normalize_findings({"findings": [{"severity": 3, "title": "x"}]})
check("a non-string severity is an error", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [], "error": "I could not complete this review: the bundle was too long."}'))
check("an extra top-level field (a declared failure) is an error, never a clean answer (round-3 P1)", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [], "more_findings": [{"severity": "breaks-us", "title": "x"}]}'))
check("a second findings-like list is an error (round-3 P1)", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "t", "verdict": "safe to merge"}]})
check("a finding with a field outside the schema is an error", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "t", "why": {"error": "I could not complete the review"}}]})
check("a non-text field value is an error, never stringified (round-4 P1)", f is None and e, (f, e))
f, e = r.normalize_findings({"findings": [{"severity": "noise", "title": ["a"]}]})
check("a list-valued field is an error", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [{"severity": "breaks-us", "title": "x"}], "findings": []}'))
check("duplicate findings key is an error, never the later empty list (round-2 P1)", f is None and e, (f, e))
f, e = r.normalize_findings(r.parse_answer('{"findings": [{"severity": "breaks-us", "severity": "noise", "title": "x"}]}'))
check("duplicate severity key is an error (round-2 P1)", f is None and e, (f, e))
os.environ["AUDITOR_MODEL_PRIMARY"] = "Private-Model-X"
check("mask: a configured identifier in ANY letter case is redacted (owner, Oct 1)",
      r.mask("uses PRIVATE-model-x and private-model-X") == "uses <AUDITOR_MODEL_PRIMARY> and <AUDITOR_MODEL_PRIMARY>", r.mask("uses PRIVATE-model-x and private-model-X"))
import tempfile as _tf
_ev = _tf.mkdtemp(); os.makedirs(os.path.join(_ev, "pr-99"))
open(os.path.join(_ev, "pr-99", "bundle.md"), "w").write("notes: PRIVATE-MODEL-X and Claude\n")
open(os.path.join(_ev, "candidates.txt"), "w").write("99 abc none\n")
open(os.path.join(_ev, "pr-99", "reader-X.json"), "w").write('{"raw": "\\u0050RIVATE-MODEL-X said so"}')
r.mask_tree(_ev)
_j = json.load(open(os.path.join(_ev, "pr-99", "reader-X.json")))
open(os.path.join(_ev, "pr-99", "reader-Y.json"), "w").write(json.dumps({"raw": '{"findings": [{"title": "\\u0050RIVATE-MODEL-X"}]}'}))
r.mask_tree(_ev)
_y = json.load(open(os.path.join(_ev, "pr-99", "reader-Y.json")))["raw"]
check("mask_tree: an identifier escaped inside the raw answer (JSON in a JSON string) is masked (round 2 B3)",
      "PRIVATE-MODEL-X" not in json.loads(_y)["findings"][0]["title"].upper(), _y)
check("mask: \\uXXXX escapes are decoded before masking", "PRIVATE" not in r.mask("\\u0050RIVATE-MODEL-X").upper(), r.mask("\\u0050RIVATE-MODEL-X"))
check("mask_tree: a JSON-escaped identifier is masked after decoding (round 1 B3)",
      "PRIVATE-MODEL-X" not in json.dumps(_j, ensure_ascii=False).upper(), _j)
_b = open(os.path.join(_ev, "pr-99", "bundle.md")).read()
check("mask_tree: the evidence bundle is masked in place before upload (owner, Oct 1)",
      "PRIVATE" not in _b.upper().replace("<AUDITOR_MODEL_PRIMARY>", "") and "Claude" not in _b and "<AUDITOR_MODEL_PRIMARY>" in _b, _b)
del os.environ["AUDITOR_MODEL_PRIMARY"]
check("mask: plain vendor and model names", r.mask("As Claude (Anthropic), like GPT-4o or Gemini") ==
      "As <model> (<model>), like <model> or <model>", r.mask("As Claude (Anthropic), like GPT-4o or Gemini"))

# --- usage: a workflow hit comes with its whole step (inputs included); others as is
wf = ["jobs:", "  a:", "    steps:", "      - name: get", "        uses: actions/checkout@v4", "        with:",
      "          fetch-depth: 0", "          persist-credentials: false", "", "      - run: echo next"]
check("step_context: from the `- ` to the step's end, inputs included", r.step_context(wf, 4) == (3, 7), r.step_context(wf, 4))
txt = r.usage_blocks([".github/workflows/x.yml:5:        uses: actions/checkout@v4", "go.mod:3:require x v1"],
                     lambda p: wf)
check("usage_blocks: numbered step with fetch-depth and persist-credentials; non-workflow hit kept",
      ".github/workflows/x.yml:7:           fetch-depth: 0" in txt and "persist-credentials" in txt
      and "echo next" not in txt and "go.mod:3:require x v1" in txt, txt)
txt = r.usage_blocks([".github/workflows/x.yml:5:  uses: a", ".github/workflows/x.yml:7:  fetch-depth: 0"], lambda p: wf)
check("usage_blocks: two hits in one step print it once", txt.count("uses: actions/checkout@v4") == 1, txt)

# --- mask: no model id or configured identifier reaches a finding
os.environ["AUDITOR_MODEL_PRIMARY"] = "some-private-model-7"
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "as claude-opus-9-9 I think",
                                           "why": "some-private-model-7 says so; Bearer abcdefghij"}]})
check("mask: model ids and bearer tokens redacted in findings",
      e is None and "claude-" not in json.dumps(f) and "some-private-model-7" not in json.dumps(f)
      and "abcdefghij" not in json.dumps(f) and "<model-id>" in f[0]["title"], f)

# --- answer_of: how the answer ended (first live run: every primary answer cut off mid-JSON)
class B:
    def __init__(self, t, x=""): self.type, self.text = t, x
class U:
    output_tokens = 2048
class M:
    def __init__(self, blocks, stop, usage=True): self.content, self.stop_reason, self.usage = blocks, stop, (U() if usage else None)
t, m, e = r.answer_of(M([B("text", '{"findings": [{"severity": "check", "title": "Action internals upgraded to ')], "max_tokens"))
check("answer_of: cut off at the token limit is an explicit error (live run 36640316796)",
      e and "token limit" in e and m["stop_reason"] == "max_tokens" and m["output_tokens"] == 2048, (e, m))
t, m, e = r.answer_of(M([B("thinking")], "max_tokens"))
check("answer_of: reasoning only, no text, at the limit -> the token-limit error", e and "token limit" in e, (e, m))
t, m, e = r.answer_of(M([B("thinking")], "end_turn"))
check("answer_of: no text block -> 'no text', block types recorded", e and "no text" in e and m["blocks"] == ["thinking"], (e, m))
t, m, e = r.answer_of(M([B("thinking"), B("text", '{"findings": []}')], "end_turn", usage=False))
check("answer_of: reasoning then a complete answer -> the text only, no error", e is None and t == '{"findings": []}', (t, e))
for stop in ("refusal", "stop_sequence", "pause_turn", None):
    t, m, e = r.answer_of(M([B("text", '{"findings": []}')], stop))
    check("answer_of: a clean-looking answer that ended %r is an error, never a clean read (backfill r2 B2)" % (stop,),
          e and "did not finish normally" in e and m["stop_reason"] == stop, (e, m))
check("the reader budget is well above the 2048 that cut every answer", r.MAX_TOKENS >= 16000, r.MAX_TOKENS)

# --- decide: mechanical
clean = lambda n: {"reader": n, "findings": [{"severity": "check", "title": "t"}], "error": None}
brk = {"reader": "B", "findings": [{"severity": "breaks-us", "title": "removed foo"}], "error": None}
err = {"reader": "B", "findings": None, "error": "model-call step failed"}
d = r.decide([clean("A"), clean("B")])
check("decide: both clean -> merge", d["decision"] == "merge" and d["breaks_us"] == [], d)
d = r.decide([clean("A"), brk])
check("decide: one breaks-us -> hold, attributed", d["decision"] == "hold" and d["breaks_us"][0]["reader"] == "B", d)
d = r.decide([clean("A"), err])
check("decide: one reader errored -> error", d["decision"] == "error" and "model-call" in d["reason"], d)
d = r.decide([brk, dict(err, reader="A")])
check("decide: breaks-us + an error -> HOLD, attributed; the errored reader is carried with its error (owner, Oct 1)",
      d["decision"] == "hold" and d["breaks_us"][0]["reader"] == "B"
      and any(x["reader"] == "A" and x.get("error") for x in d["readers"]), d)
import tempfile as _tf2
_dd = _tf2.mkdtemp(); json.dump(brk, open(os.path.join(_dd, "reader-AUDITOR_MODEL_PRIMARY.json"), "w"))
class _DA: reader = [os.path.join(_dd, "reader-AUDITOR_MODEL_PRIMARY.json"), os.path.join(_dd, "reader-AUDITOR_MODEL_FALLBACK.json")]; out = os.path.join(_dd, "d.json")
import io as _io, contextlib as _cl
with _cl.redirect_stdout(_io.StringIO()):
    r.cmd_decide(_DA)
_d = json.load(open(_DA.out))
check("decide: a missing answer file is an errored reader, and the other's breaks-us still holds (round 1 B4)",
      _d["decision"] == "hold" and any(x["reader"] == "AUDITOR_MODEL_FALLBACK" and "no answer" in x.get("error", "") for x in _d["readers"]), _d)
d = r.decide([err, dict(err, reader="A")])
check("decide: two errors and no breaks-us -> error (no verdict, retry)", d["decision"] == "error", d)
d = r.decide([clean("A")] + [{"reader": "B", "findings": None, "error": None}])
check("decide: a reader with no findings and no error -> error", d["decision"] == "error", d)
check("decide: no readers -> error", r.decide([])["decision"] == "error")

print("----")
print("dependabot-reviewer: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
py_rc=$?

# ============================================================================ the act step
# The committed "gather, read twice, decide, act" step, run as written under GitHub's default
# `bash -e`, with: a recording `gh` (per-scenario failures), a stub token endpoint (`curl`), the
# committed required-check guard fed a matching or drifted ruleset, and a fake SDK module that
# returns each reader's canned answer. Asserts WHAT is called, in WHAT order, and whether a check
# goes up — the round-1 paths (malformed answer, failed diff, re-hold with auto-merge armed,
# partial failures, -e aborting the loop, guard drift).
w="$(mktemp -d)"; trap 'rm -rf "$w"' EXIT
pass=0; fail=0
# <checkout>: the reviewer's version (REQ-DEP-001-AC14), computed here and not by bin/dependabot-reviewer-version.sh:
# the sha256 of the output of sha256sum over the five files in order
ver3() {
  (cd "$1" && sha256sum bin/dependabot-reviewer.py .github/policy/dependabot-reviewer-prompt.txt \
    .github/workflows/dependabot-reviewer.yml .github/policy/required-checks.json bin/required-check-guard.sh |
    sha256sum | cut -d' ' -f1)
}
VER=$(ver3 "$repo"); OLDVER=$(printf '%064d' 0); PYVER=$(sha256sum "$repo/bin/dependabot-reviewer.py" | cut -d' ' -f1)
# the versions before this definition: the three files joined, and the three files' sha256sum lines
OLD3=$(cd "$repo" && cat bin/dependabot-reviewer.py .github/policy/dependabot-reviewer-prompt.txt \
  .github/workflows/dependabot-reviewer.yml | sha256sum | cut -d' ' -f1)
OLD3S=$(cd "$repo" && sha256sum bin/dependabot-reviewer.py .github/policy/dependabot-reviewer-prompt.txt \
  .github/workflows/dependabot-reviewer.yml | sha256sum | cut -d' ' -f1)
# <dir> <prompt-changed|workflow-changed|checks-changed|guard-changed|no-prompt|no-workflow|no-checks|no-guard>: the
# files the steps read, with one of the five reviewer files changed or left out
mkalt() {
  local d="$1" f
  # git grep reads the usage
  rm -rf "$d"; mkdir -p "$d/bin" "$d/.github/policy" "$d/.github/workflows"; git init -q "$d"
  for f in "$repo"/bin/*; do ln -s "$f" "$d/bin/"; done
  for f in "$repo"/.github/policy/*; do ln -s "$f" "$d/.github/policy/"; done
  for f in .github/policy/dependabot-reviewer-prompt.txt .github/workflows/dependabot-reviewer.yml \
    .github/policy/required-checks.json bin/required-check-guard.sh; do
    rm -f "$d/$f"; cp "$repo/$f" "$d/$f"
  done
  case "$2" in
    prompt-changed) printf '\nAlso read the lockfile.\n' >> "$d/.github/policy/dependabot-reviewer-prompt.txt" ;;
    workflow-changed) printf '# changed\n' >> "$d/.github/workflows/dependabot-reviewer.yml" ;;
    checks-changed) printf '\n' >> "$d/.github/policy/required-checks.json" ;;
    guard-changed) printf '# changed\n' >> "$d/bin/required-check-guard.sh" ;;
    no-prompt) rm "$d/.github/policy/dependabot-reviewer-prompt.txt" ;;
    no-workflow) rm "$d/.github/workflows/dependabot-reviewer.yml" ;;
    no-checks) rm "$d/.github/policy/required-checks.json" ;;
    no-guard) rm "$d/bin/required-check-guard.sh" ;;
  esac
}
verdicts() { # <[[conclusion, external_id (left out: none), app slug], ...]> oldest first, as GitHub lists them
  jq -cn --argjson r "$1" \
    '{total_count: ($r | length), check_runs: [$r | to_entries[] | {id: .key, conclusion: .value[0],
                                         app: {slug: (.value[2] // "fosterstack-automation")}}
                                         + (if (.value | length) > 1 then {external_id: .value[1]} else {} end)]}'
}
# verdicts, but GitHub says there are 31 runs and the page holds 30: 29 neutral ones, then <last run>
verdicts_cut() {
  verdicts "$(jq -c '. + ['"$1"']' <<<"$(jq -nc '[range(29) | ["neutral"]]')")" | jq -c '.total_count = 31'
}
# every gh log line that asks for the reviewer's check runs asks for every run (filter=all) and 100 of them at a time,
# and there is at least one
asks_all_runs() {
  if grep -q 'check_name=dependabot-reviewer' "$w/gh.log" \
      && ! grep 'check_name=dependabot-reviewer' "$w/gh.log" | grep -qv 'filter=all' \
      && ! grep 'check_name=dependabot-reviewer' "$w/gh.log" | grep -qv 'per_page=100'; then
    echo "ok: $1"; pass=$((pass+1))
  else echo "FAIL: $1"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); fi
}
# <name> [version]: every dependabot-reviewer check in the gh log of the last run carries the current version, and
# there is one
ext_on_every_check() {
  local n m want="${2:-$VER}"
  n=$(grep -cE 'check-runs -f name=dependabot-reviewer' "$w/gh.log") || true
  m=$(grep -E 'check-runs -f name=dependabot-reviewer' "$w/gh.log" | grep -cE -- "-f external_id=$want( |$)") || true
  if [ "$n" -ge 1 ] && [ "$n" = "$m" ]; then echo "ok: $1"; pass=$((pass+1))
  else echo "FAIL: $1 ($n reviewer checks, $m with the current external_id)"; sed 's/^/    gh: /' "$w/gh.log";
    fail=$((fail+1)); fi
}
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" "$w/act.sh" <<'PY'
import sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]
run = [s["run"] for s in steps if s.get("id") == "act"]
assert len(run) == 1, "act step not found"
open(sys.argv[2], "w").write(run[0])
PY
mkdir -p "$w/bin" "$w/py/anthropic" "$w/noprog/bin"
jq -n --slurpfile a "$FIX/pr-99.json" --slurpfile b "$FIX/pr-90.json" --slurpfile c "$FIX/pr-91.json" --slurpfile d "$FIX/pr-400.json" \
  '[($a[0] + {number: 99, headRefOid: "sha99"}), ($b[0] + {number: 90, headRefOid: "sha90"}), ($c[0] + {number: 91, headRefOid: "sha91"}), ($d[0] + {number: 400, headRefOid: "sha400"})]' > "$w/prs-flagged.json"
cat > "$w/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
fails() { case " ${FAIL:-} " in *" $1 "*) exit 1 ;; esac; }
case "$1 $2" in
  "api repos/o/r/contents/.github/policy/required-checks.json?ref=main") base64 < "$LIST" | tr -d '\n' ;;
  "api repos/o/r/check-runs") case "$*" in *name=auditor-review-gate*) fails gate ;; *) fails check ;; esac ;;
  "api repos/fosterstack/ops/dispatches") fails dispatch ;;
  # cancellation cleanup lookups: success, or CANCELA_JSON through the step's own filter
  "api repos/o/r/commits/shaA/check-runs?check_name=dependabot-reviewer"*)
              if [ -n "${CANCELA_JSON:-}" ]; then f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done;
                jq -r "$f" <<<"$CANCELA_JSON"
              else echo success; fi ;;
  "api repos/o/r/commits/shaB/check-runs?check_name=dependabot-reviewer"*) echo none ;;
  "api repos/a/b/releases"*) fails notes; echo '[]' ;;      # upstream releases: a successful read, none published
  # the PR's commits: Dependabot's own, then one a writer pushed, which is the head (COMMITS_HEAD: another last
  # commit, a head that moved)
  "api repos/o/r/pulls/"*"/commits"*) fails commits; n=${2#repos/o/r/pulls/}; n=${n%%/*};
    sed "s/HEADSHA/${COMMITS_HEAD:-$(printf '%040d' "$n")}/" "$COMMITS" ;;
  "api -H") fails diff; case "$4" in repos/o/r/compare/main...0000000000000000000000000000000000*)
    printf -- \
    '--- a/.github/workflows/x.yml\n+++ b/.github/workflows/x.yml\n-      - uses: a/b@v4\n+      - uses: a/b@v7\n' ;;
    *) exit 1 ;; esac ;;
  "api "*) exit 1 ;;
  "pr merge") if [ "$3" = "--disable-auto" ]; then fails disarm; else fails merge; fi ;;
  "pr view") case "$*" in *headRefOid*) fails head; echo "${HEAD_NOW:-$(printf '%040d' "$3")}" ;; *) fails view;
    echo "${ARMED:-false}" ;; esac ;;
  "issue list") fails issuelist; echo '[]' ;;
  "issue create") fails issue; echo "https://example.invalid/issues/5" ;;
  "issue edit") fails issue ;;
esac
EOF
cat > "$w/bin/curl" <<'EOF'
#!/usr/bin/env bash
echo '{"value":"header.eyJzdWIiOiJ4In0.sig"}'
EOF
cat > "$w/py/anthropic/__init__.py" <<'EOF'
import os
class _Block:
    def __init__(self, t): self.text = t
class _Msg:
    def __init__(self, t): self.content, self.stop_reason = [_Block(t)], "end_turn"   # the real API always sets one
class _Messages:
    def create(self, model, max_tokens, messages):
        if model == "boom":
            raise RuntimeError("connection reset")
        if model == "die":
            os._exit(3)   # the reader process dies before writing its answer file
        m = _Msg(os.environ["ANSWER_" + model])
        if model == "cut":
            m.stop_reason = "max_tokens"
        return m
    def stream(self, model, max_tokens, messages):   # the reader streams (no non-streaming ceiling)
        outer = self
        class _S:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def get_final_message(self): return outer.create(model, max_tokens, messages)
        return _S()
class Anthropic:
    def __init__(self): self.messages = _Messages()
EOF
chmod +x "$w/bin/gh" "$w/bin/curl"
cat > "$w/commits.json" <<'EOF'
[{"sha": "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0", "parents": [{"sha": "m"}],
  "author": {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"},
  "committer": {"login": "web-flow"},
  "commit": {"message": "Bump a/b from 4 to 7\n\nbody", "verification": {"verified": true}}},
 {"sha": "HEADSHA", "parents": [{"sha": "d"}], "author": {"login": "some-writer", "id": 7, "type": "User"},
  "committer": {"login": "some-writer"},
  "commit": {"message": "Keep our pin in step", "verification": {"verified": true}}}]
EOF
export COMMITS="$w/commits.json"
jq '[{"type":"required_status_checks","parameters":{"required_status_checks":[.required_checks[]|{context,integration_id}]}}]' \
  "$repo/.github/policy/required-checks.json" > "$w/rules-match.json"
jq '(.[0].parameters.required_status_checks) |= .[1:]' "$w/rules-match.json" > "$w/rules-drift.json"
CLEAN='{"findings": [{"severity": "check", "title": "node24 runtime", "release_note": "v5: node24", "our_line": ".github/workflows/x.yml:3", "why": "runtime"}]}'
BREAKS='{"findings": [{"severity": "breaks-us", "title": "input removed", "release_note": "v7: removed foo", "our_line": ".github/workflows/x.yml:3", "why": "we pass foo"}]}'
TRUNC='{"findings": [], "unfinished": {"findings": []}'

S99=$(printf '%040d' 99)
MAJOR_UPDATE='[{"name":"a/b","from":"4","to":"7","major":true}]'
# name; env: A B (answers), PRS, FAIL, ARMED, RULES, UPDATES (the updates file the candidates step would have written)
act() {
  local W="$w/run"; rm -rf "$W"; mkdir -p "$W/work"; : > "$w/gh.log"
  : > "$W/work/candidates.txt"
  for n in ${PRS:-99}; do
    # a full commit id, as the candidates step writes it
    echo "$n $(printf '%040d' "$n") ${PRIOR:-none}" >> "$W/work/candidates.txt"
    echo "${UPDATES:-$MAJOR_UPDATE}" > "$W/work/updates-$n.json"
  done
  (cd "${ACTDIR:-$repo}" &&
    env PATH="$w/bin:$PATH" PYTHONPATH="$w/py" GH_LOG="$w/gh.log" LIST="$repo/.github/policy/required-checks.json" \
     GUARD_RULES_JSON="${RULES:-$w/rules-match.json}" FAIL="${FAIL:-}" ARMED="${ARMED:-false}" \
     GITHUB_REPOSITORY=o/r RUNNER_TEMP="$W" GITHUB_STEP_SUMMARY="$W/summary" GITHUB_OUTPUT="$W/output" \
     RUN_URL=https://example.invalid/run ANTHROPIC_IDENTITY_TOKEN_FILE="$W/token" \
     ACTIONS_ID_TOKEN_REQUEST_TOKEN=t ACTIONS_ID_TOKEN_REQUEST_URL="https://example.invalid/oidc?x=1" \
     AUDITOR_MODEL_PRIMARY=ma AUDITOR_MODEL_FALLBACK="${MB:-mb}" ANSWER_ma="$A" ANSWER_mb="$B" \
     GH_TOKEN=job CHECKS_TOKEN=chk MERGE_TOKEN=mrg DISPATCH_TOKEN="${DT-ops}" \
     bash --noprofile --norc -e -o pipefail "$w/act.sh") > "$w/act.out" 2>&1
  echo $? > "$w/act.rc"
}
expect() { # name; then grep -E assertions on the gh log: +regex must appear, -regex must not
  local name="$1" ok=1; shift
  for a in "$@"; do
    case "$a" in
      +*) grep -qE -- "${a:1}" "$w/gh.log" || ok=0 ;;
      -*) grep -qE -- "${a:1}" "$w/gh.log" && ok=0 ;;
      ORDER:*) local x="${a#ORDER:}" y; y="${x#*>}"; x="${x%%>*}"
               [ "$(grep -nE -- "$x" "$w/gh.log" | head -1 | cut -d: -f1)" -lt "$(grep -nE -- "$y" "$w/gh.log" | head -1 | cut -d: -f1)" ] 2>/dev/null || ok=0 ;;
      ERRORED=*) grep -qx "errored=${a#ERRORED=}" "$w/run/output" || ok=0 ;;
    esac
  done
  if [ "$ok" = 1 ]; then echo "ok: act: $name"; pass=$((pass+1))
  else echo "FAIL: act: $name"; sed 's/^/    gh: /' "$w/gh.log"; tail -15 "$w/act.out" | sed 's/^/    out: /'; fail=$((fail+1)); fi
}
CHK='check-runs'; SUCCESS='conclusion=success'; FAILURE='conclusion=failure'
step_fails() { # <name> <exit status>: the step ended non-zero
  if [ "$2" != 0 ]; then echo "ok: $1 (exit $2)"; pass=$((pass+1)); else echo "FAIL: $1 (exit 0)"; fail=$((fail+1)); fi
}

A="$CLEAN" B="$CLEAN" act; expect "both clean -> arm auto-merge, THEN the success check" \
  "+pr merge --auto --squash --match-head-commit [0-9a-f]+ 99" "+$CHK" "ORDER:pr merge --auto>$CHK" ERRORED=0
grep -qE -- "pr merge --auto --squash --match-head-commit $S99 99" "$w/gh.log" \
  && { echo "ok: act: auto-merge is armed only for the reviewed head (--match-head-commit, owner Oct 1)"; pass=$((pass+1)); } \
  || { echo "FAIL: act: arm not bound to the reviewed head"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
grep -q -- "-f conclusion=success" "$w/gh.log" && { echo "ok: act: the check says success"; pass=$((pass+1)); } || { echo "FAIL: act: success conclusion"; fail=$((fail+1)); }
grep -q "^- d0d0d0d0d0 dependabot\[bot\]: Bump a/b from 4 to 7$" "$w/run/work/pr-99/bundle.md" \
  && grep -q "^- 0000000000 NOT Dependabot's — some-writer: Keep our pin in step$" "$w/run/work/pr-99/bundle.md" \
  && grep -q "^# Bundle for Dependabot PR #99 at its head $S99$" "$w/run/work/pr-99/bundle.md" &&
    grep -q "compare/main\.\.\.$S99" "$w/gh.log" \
  && grep -q "^+      - uses: a/b@v7$" "$w/run/work/pr-99/bundle.md" \
  && { echo \
    "ok: act: the bundle lists the PR's commits, the writer's one marked NOT Dependabot's, above the whole diff";
    pass=$((pass+1)); } \
  || { echo "FAIL: act: commits in the bundle"; sed 's/^/    /' "$w/run/work/pr-99/bundle.md" | head -20;
    fail=$((fail+1)); }
A="$CLEAN" B="$CLEAN" FAIL="commits" act;
  expect "the PR's commits cannot be read -> UNAVAILABLE: no reader, no merge, no check; retried" "-pr merge" \
  "-$CHK" ERRORED=1
grep -q "commit list UNAVAILABLE" "$w/run/work/pr-99/bundle.md" 2>/dev/null \
  && { echo "ok: act: the bundle labels the unread commit list UNAVAILABLE"; pass=$((pass+1)); } || {
    echo "FAIL: act: commit list unavailable label"; fail=$((fail+1)); }
# every bump is read: a plain patch, as the candidates step writes it (major false, kind not-major), goes the same way
PATCH='[{"name":"a/b","from":"4.0.0","to":"4.0.1","major":false,"flagged":false,"kind":"not-major"}]'
A="$CLEAN" B="$CLEAN" UPDATES="$PATCH" ARMED=true act;
  expect "a plain patch, both clean -> armed for the reviewed head, THEN the success check, like a major" \
  "+pr merge --auto --squash --match-head-commit $S99 99" "+$CHK" "ORDER:pr merge --auto>$CHK" "-disable-auto" ERRORED=0
grep -q -- "-f conclusion=success" "$w/gh.log" &&
  grep -q "a/b: 4.0.0 -> 4.0.1 (not major)" "$w/run/work/pr-99/bundle.md" && grep -q "a/b 4.0.0→4.0.1" "$w/gh.log" \
  && { echo "ok: act: the patch's check says success and names it; its bundle calls it not major"; pass=$((pass+1));
    } || { echo "FAIL: act: patch success"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" UPDATES="$PATCH" ARMED=true act;
  expect "a plain patch a reader says breaks us -> auto-merge off, issue, THEN the failure check, like a major" \
  "+pr merge --disable-auto 99" "+issue create" "+$CHK" "-pr merge --auto --squash" \
    "ORDER:disable-auto>issue create" "ORDER:issue create>$CHK" ERRORED=0
grep -q -- "-f conclusion=failure" "$w/gh.log" && { echo "ok: act: the patch's check says failure"; pass=$((pass+1));
  } || { echo "FAIL: act: patch failure"; fail=$((fail+1)); }
grep -q -- "issue create --title bump held: PR #99 --body-file" "$w/gh.log" &&
  grep -q "^Dependabot PR #99 (\`0000000\`: a/b 4.0.0→4.0.1) is a bump that a reader says breaks a line of ours" \
  "$w/run/work/pr-99/issue.md" && ! grep -qi "major" "$w/run/work/pr-99/issue.md" \
  && { echo \
    "ok: act: a held patch's issue is titled by its PR, names the bump in its body and never calls it a major";
    pass=$((pass+1)); } || { echo "FAIL: act: held patch issue text"; fail=$((fail+1)); }
# a grouped bump: the title stays the PR's (GitHub cuts a title off at 256 characters, and a group's members change),
# every member is in the body and in the check
GROUP=$(jq -cn '[range(0; 40) | {name: "a-pip-dependency-with-quite-a-long-name-\(.)", from: "1.0.\(.)", to: "1.1.\(.)",
                                 major: false, flagged: false, kind: "not-major"}]')
A="$CLEAN" B="$BREAKS" UPDATES="$GROUP" act;
  expect "a held group of 40 updates -> one issue titled by the PR, failure check published" \
  "+issue create --title bump held: PR #99 --body-file" "+$CHK" ERRORED=0
grep -q "a-pip-dependency-with-quite-a-long-name-0 1.0.0→1.1.0, " "$w/run/work/pr-99/issue.md" &&
  grep -q "a-pip-dependency-with-quite-a-long-name-39 1.0.39→1.1.39" "$w/run/work/pr-99/issue.md" \
  && { echo "ok: act: the group's members are named in the issue body, first to last"; pass=$((pass+1)); } || {
    echo "FAIL: act: group members in the issue"; fail=$((fail+1)); }

# REQ-DEP-001-AC13: a verdict that is not success first fails the review gate's own check on that head (same name,
# same App token, the gate's
# own fields); a success publishes nothing on the gate; without the gate failure the reviewer's own check does not go up
GATE='check-runs -f name=auditor-review-gate -f head_sha=[0-9a-f]{40} -f status=completed -f conclusion=failure'
GATE+=' -f details_url=[^ ]+ -f output\[title\]=auditor review gate: failure'
OWN='check-runs -f name=dependabot-reviewer'
A="$CLEAN" B="$BREAKS" act;
  expect "hold -> the gate's check fails FIRST, then the reviewer's failure check (last)" "+$GATE" \
  "+$OWN .*conclusion=failure" "ORDER:name=auditor-review-gate>name=dependabot-reviewer" \
  "ORDER:issue create>name=auditor-review-gate" ERRORED=0
[ "$(grep -c 'name=auditor-review-gate' "$w/gh.log")" = 1 ] &&
  grep -q "name=auditor-review-gate -f head_sha=$S99 " "$w/gh.log" &&
  ! grep -q "name=auditor-review-gate.*conclusion=success" "$w/gh.log" \
  && { echo "ok: act: exactly one gate check, failure, on the reviewed head"; pass=$((pass+1)); } || {
    echo "FAIL: act: gate check on hold"; fail=$((fail+1)); }
A="$CLEAN" B="$CLEAN" act;
  expect "merge -> nothing is published on the review gate's check (the gate judges a success itself)" \
  "-auditor-review-gate" "+$OWN .*conclusion=success" ERRORED=0
A="$CLEAN" B="$BREAKS" FAIL="gate" act;
  expect "hold, the gate's check cannot be failed -> the reviewer's failure is NOT published; unfinished, retried" \
  "-$OWN" "+issue create" ERRORED=1
A="$CLEAN" B="$CLEAN" MB=boom ARMED=true PRIOR=success act;
  expect "a forced re-review that errors -> the gate's check fails first, then the neutral" \
  "+$GATE" "+$OWN .*conclusion=neutral" "ORDER:name=auditor-review-gate>name=dependabot-reviewer" ERRORED=1
A="$CLEAN" B="$CLEAN" MB=boom ARMED=true PRIOR=success FAIL="gate" act;
  expect "the neutral's gate failure cannot be published -> no neutral either (an error is logged)" "-$OWN" ERRORED=1

# REQ-DEP-001-AC14: every check the act step publishes carries the version of the reviewer program as its external_id
A="$CLEAN" B="$CLEAN" act; ext_on_every_check "act: the success check carries the reviewer's version as external_id"
A="$CLEAN" B="$BREAKS" act; ext_on_every_check "act: the failure check carries the reviewer's version as external_id"
A="$CLEAN" B="$CLEAN" MB=boom ARMED=true PRIOR=success act;
  ext_on_every_check \
  "act: the neutral check of a forced review that errors carries the reviewer's version as external_id"
# the version is of the program, the prompt and the workflow as this run checked them out: a change to any of them is
# a new version
for what in prompt-changed workflow-changed checks-changed guard-changed; do
  mkalt "$w/alt" "$what"
  A="$CLEAN" B="$CLEAN" ACTDIR="$w/alt" act;
    ext_on_every_check "act: with the $what the success check carries the version of the five files as they are" \
    "$(ver3 "$w/alt")"
done
# a version that cannot be computed stops the step before any verdict: nothing armed, disarmed or published, not even
# a neutral
for what in no-prompt no-workflow no-checks no-guard; do
  mkalt "$w/alt" "$what"
  A="$CLEAN" B="$CLEAN" ARMED=true PRIOR=success ACTDIR="$w/alt" act;
    expect "act: $what: the version cannot be computed -> no arm, no disarm, no check of any kind" "-pr merge" "-$CHK"
  step_fails "act: $what: the step fails" "$(cat "$w/act.rc")"
done

# REQ-DEP-001-AC2, AC9: the verdict is for the commit whose diff was gathered. A head that is another commit when the
# readers have answered
# gets nothing: no check, no arm, no disarm, no issue; it is not an error (the new head is a candidate next hour)
A="$CLEAN" B="$CLEAN" ARMED=true HEAD_NOW=1111111111111111111111111111111111111111 act;
  expect "the head moved during the review (readers clean) -> no arm, no check, the arm it has is left alone" \
  "-pr merge" "-check-runs" ERRORED=0
grep -q "PR #99: its head moved from 0000000 to 1111111 during the review" "$w/act.out" &&
  grep -q "head moved during the review (new head next hour): 1;" "$w/run/summary" \
  && { echo "ok: act: a moved head is said in the log and counted in the summary"; pass=$((pass+1)); } || {
    echo "FAIL: act: moved head report"; tail -5 "$w/act.out"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" ARMED=true HEAD_NOW=1111111111111111111111111111111111111111 act;
  expect "the head moved during the review (a reader says breaks-us) -> no issue, no check, no disarm" \
  "-pr merge" "-check-runs" "-issue create" ERRORED=0
A="$CLEAN" B="$CLEAN" FAIL="head" act;
  expect "the PR's head cannot be read after the review -> unfinished: no arm, no check" "-pr merge --auto" \
  "-check-runs" ERRORED=1
A="$CLEAN" B="$CLEAN" ARMED=true COMMITS_HEAD=2222222222222222222222222222222222222222 act;
  expect \
  "the PR's commits end at another commit than the candidate's (gather exit 5) -> nothing read or done" \
  "-compare/" "-pr merge" "-check-runs" "-pr view" ERRORED=0
[ ! -e "$w/run/work/pr-99/bundle.md" ] && [ ! -e "$w/run/work/pr-99/reader-AUDITOR_MODEL_PRIMARY.json" ] \
  && { echo "ok: act: a head that moved before the gather leaves no bundle and no reader answer"; pass=$((pass+1));
    } || { echo "FAIL: act: moved before gather"; fail=$((fail+1)); }
A="$CLEAN" B="$TRUNC" act; expect "a truncated answer -> no merge, no check (round-1 P1)" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" FAIL="diff" act; expect "diff cannot be fetched -> no reader, no merge, no check (round-1 P1)" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$BREAKS" ARMED=true act; expect "re-hold with auto-merge armed -> disarm, issue, THEN failure check (round-1 P1)" \
  "+pr merge --disable-auto 99" "+issue create" "+$CHK" "-pr merge --auto --squash" "ORDER:disable-auto>issue create" "ORDER:issue create>$CHK" ERRORED=0
grep -q -- "-f conclusion=failure" "$w/gh.log" && { echo "ok: act: the check says failure"; pass=$((pass+1)); } || { echo "FAIL: act: failure conclusion"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" ARMED=false act; expect "hold, not armed -> no disarm call, issue, failure check" "-disable-auto" "+issue create" "+$CHK" ERRORED=0
A="$CLEAN" B="$BREAKS" FAIL="issue" act; expect "held issue cannot be created -> no check; retry (round-1 P1)" "-$CHK" ERRORED=1
A="$CLEAN" B="$BREAKS" ARMED=true FAIL="disarm" act; expect "auto-merge cannot be disarmed -> no issue, no check" "-issue create" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" FAIL="merge" act; expect "auto-merge cannot be armed -> no success check; retry (round-1 P1)" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" RULES="$w/rules-drift.json" act; expect "required-check drift -> no major armed, no check (Sonnet round 1)" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" MB=boom act; expect "a reader raises -> no merge, no check" "-pr merge" "-$CHK" ERRORED=1
A="$CLEAN" B="$CLEAN" FAIL="notes" act; expect "release notes cannot be read -> UNAVAILABLE: no reader, no merge, no check; retried (owner, Oct 1)" "-pr merge" "-$CHK" ERRORED=1
grep -q "release notes UNAVAILABLE" "$w/run/work/pr-99/bundle.md" 2>/dev/null \
  && { echo "ok: act: the bundle labels the failed read UNAVAILABLE"; pass=$((pass+1)); } || { echo "FAIL: act: unavailable label"; fail=$((fail+1)); }
A="$BREAKS" B="$CLEAN" MB=die act; expect "breaks-us while the other reader's process dies without an answer -> HOLD, the missing answer an error (round 1 B4)" \
  "-pr merge --auto" "+issue create" "+$CHK" ERRORED=0
grep -q "reader B" "$w/run/work/pr-99/issue.md" && grep -qi "no answer" "$w/run/work/pr-99/issue.md" && ! grep -q "_(no findings)_" "$w/run/work/pr-99/issue.md" \
  && { echo "ok: act: the issue shows the errored reader as errored, never as 'no findings' (round 1 Sonnet B1)"; pass=$((pass+1)); } \
  || { echo "FAIL: act: errored reader rendering"; sed 's/^/    /' "$w/run/work/pr-99/issue.md"; fail=$((fail+1)); }
A="$BREAKS" B="$CLEAN" MB=boom act; expect "breaks-us from one reader while the other errors -> HOLD: issue, failure check, no merge (owner, Oct 1)" \
  "-pr merge --auto" "+issue create" "+$CHK" "ORDER:issue create>$CHK" ERRORED=0
A="$CLEAN" B="$BREAKS" PRS="99 100" FAIL="issuelist" act; expect "issue lookup fails on #99 -> #100 still reviewed, errored counted (bash -e, round 1)" \
  "+compare/main\.\.\.$(printf '%040d' 100)" ERRORED=2
A="$CLEAN" B='{"findings": [{"severity": "breaks-us", "title": "as claude-opus-9 I see", "release_note": "n", "our_line": "l", "why": "Anthropic says"}]}' act
if grep -rqiE "claude|anthropic" "$w/run/work/pr-99/issue.md" "$w/run/work/pr-99/decision.json" "$w/run/work/pr-99/reader-AUDITOR_MODEL_FALLBACK.json"; then
  echo "FAIL: act: a model/vendor name reached the issue or the evidence"; fail=$((fail+1))
else echo "ok: act: no model/vendor name in the issue or the evidence"; pass=$((pass+1)); fi
grep -q "reader A" "$w/run/work/pr-99/issue.md" && grep -q "reader B" "$w/run/work/pr-99/issue.md" && grep -q "release note: n" "$w/run/work/pr-99/issue.md" \
  && { echo "ok: act: the issue carries both readers' findings, attributed, with release notes"; pass=$((pass+1)); } \
  || { echo "FAIL: act: issue content"; sed 's/^/    /' "$w/run/work/pr-99/issue.md"; fail=$((fail+1)); }

# --- row 76: a completed hold dispatches the fixer (best effort)
A="$CLEAN" B="$BREAKS" act; expect "hold -> issue, failure check, THEN the fixer dispatch with issue and PR (row 76)" \
  "+api repos/fosterstack/ops/dispatches -f event_type=fix-held-bump -f client_payload\[issue\]=5 -f client_payload\[pr\]=99 -f client_payload\[repo\]=o/r" \
  "ORDER:$CHK>ops/dispatches" ERRORED=0
A="$CLEAN" B="$BREAKS" FAIL="dispatch" act; expect "the dispatch fails -> the hold still stands: issue, failure check, not unfinished" "+issue create" "+$CHK" ERRORED=0
grep -q "fixer dispatch (fix-held-bump, issue #5): the dispatch call failed" "$w/act.out" \
  && { echo "ok: act: a failed dispatch is a warning naming the issue"; pass=$((pass+1)); } || { echo "FAIL: act: dispatch warning"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" DT="" act; expect "no ops token (App not on ops) -> no dispatch call, hold stands" "-ops/dispatches" "+$CHK" ERRORED=0
A="$CLEAN" B="$CLEAN" act; expect "a merge never dispatches the fixer" "-ops/dispatches"
out=$(bash "$here/dispatch-fixer.sh" fix-something 5 2>&1); rc=$?
[ "$rc" = 1 ] && grep -q "unknown event type" <<<"$out" && { echo "ok: dispatch-fixer: unknown event type refused"; pass=$((pass+1)); } || { echo "FAIL: unknown event"; fail=$((fail+1)); }
out=$(DISPATCH_TOKEN=t bash "$here/dispatch-fixer.sh" fix-held-bump "" 2>&1); rc=$?
[ "$rc" = 1 ] && grep -q "no issue number" <<<"$out" && { echo "ok: dispatch-fixer: no issue number refused"; pass=$((pass+1)); } || { echo "FAIL: no issue"; fail=$((fail+1)); }
python3 - "$repo/.github/workflows/ci.yml" "$w/drift-dispatch.sh" <<'PY5'
import sys, yaml
j = yaml.safe_load(open(sys.argv[1]))["jobs"]["drift-fixer-dispatch"]
assert "push" in j["if"] and "refs/heads/main" in j["if"] and j["environment"] == "agent"
open(sys.argv[2], "w").write([s for s in j["steps"] if s.get("name") == "dispatch"][0]["run"])
PY5
for mode in ok dispatch; do
  : > "$w/gh.log"
  (cd "$repo" && env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" FAIL="$([ $mode = dispatch ] && echo dispatch)" DISPATCH_TOKEN=ops ISSUE=12 GITHUB_REPOSITORY=o/r \
     bash --noprofile --norc -e -o pipefail "$w/drift-dispatch.sh") >/dev/null 2>&1; rc=$?
  if [ "$rc" = 0 ] && grep -q "ops/dispatches -f event_type=fix-required-check-drift -f client_payload\[issue\]=12 -f client_payload\[pr\]= " "$w/gh.log"; then
    echo "ok: hygiene drift dispatch ($mode): fix-required-check-drift for issue 12, step never fails"; pass=$((pass+1))
  else echo "FAIL: hygiene drift dispatch ($mode) rc=$rc"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); fi
done

# --- round 2
A="$CLEAN" B="$CLEAN" ARMED=true FAIL="check" act; expect "armed but the success check fails -> counted unfinished, auto-merge turned back off (round-2)" \
  "+pr merge --auto --squash --match-head-commit [0-9a-f]+ 99" "+pr merge --disable-auto 99" ERRORED=1
A="$CLEAN" B="$BREAKS" FAIL="check" act; expect "held but the failure check fails -> counted unfinished (round-2)" "+issue create" ERRORED=1
A="$CLEAN" B="$CLEAN" MB=boom ARMED=true PRIOR=success act; expect "forced re-review errors over an old success -> disarm + neutral check (round-2 P1)" \
  "+pr merge --disable-auto 99" "+check-runs" "-pr merge --auto" ERRORED=1
grep -q -- "-f conclusion=neutral" "$w/gh.log" && { echo "ok: act: the superseding check is neutral"; pass=$((pass+1)); } || { echo "FAIL: act: neutral check"; fail=$((fail+1)); }
A="$CLEAN" B="$BREAKS" ARMED=true FAIL="disarm" PRIOR=success act; expect "forced re-hold whose disarm fails -> neutral check, no failure verdict (round-2 P1)" \
  "+check-runs" "-issue create" ERRORED=1
grep -q -- "name=dependabot-reviewer .*-f conclusion=neutral" "$w/gh.log" &&
  ! grep -q -- "name=dependabot-reviewer .*-f conclusion=failure" "$w/gh.log" \
  && { echo \
    "ok: act: only a neutral check of the reviewer's own after a failed disarm (and the gate's failure before it)";
    pass=$((pass+1)); } || { echo "FAIL: act: neutral-only"; fail=$((fail+1)); }
A="$CLEAN" B="$CLEAN" MB=boom act; expect "first-time reader error -> NO check at all (row 75)" "-check-runs" ERRORED=1
ANSWER_cut="$CLEAN" A="$CLEAN" B="$CLEAN" MB=cut act; expect "a complete-looking answer that stopped at the token limit -> error, no merge (live run)" "-pr merge" "-check-runs" ERRORED=1
grep -q '"stop_reason": "max_tokens"' "$w/run/work/pr-99/reader-AUDITOR_MODEL_FALLBACK.json" && grep -q "token limit" "$w/run/work/pr-99/reader-AUDITOR_MODEL_FALLBACK.json" \
  && { echo "ok: act: the evidence records the stop reason and says 'token limit'"; pass=$((pass+1)); } || { echo "FAIL: act: stop reason in evidence"; fail=$((fail+1)); }
A="$CLEAN" B="$CLEAN" ARMED=true FAIL="check" act
grep -c "check-runs" "$w/gh.log" | grep -qx 3 && grep -q -- "-f conclusion=neutral" "$w/gh.log" &&
  grep -q "name=auditor-review-gate" "$w/gh.log" \
  && { echo "ok: act: a success write that errored is superseded by neutral (lost response, round-3 P1)"; pass=$((pass+1)); } \
  || { echo "FAIL: act: lost-response neutral"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
A="$CLEAN" B='{"findings": [], "error": "I could not complete this review."}' act; expect "a reader declaring failure in an extra field -> no merge, no check (round-3 P1)" "-pr merge" "-check-runs" ERRORED=1
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" <<'PY3' && { echo "ok: conditions: productive steps are cancellation-aware; act needs the merge token; evidence cannot fail the job (round 3)"; pass=$((pass+1)); } || { echo "FAIL: conditions"; fail=$((fail+1)); }
import sys, yaml
st = {s.get("id"): s for s in yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]}
ok = all("!cancelled()" in st[i]["if"] and "always()" not in st[i]["if"] for i in ("mint", "sdk", "act"))
ok = ok and "steps.app-merge.outcome == 'success'" in st["act"]["if"]
up = [s for s in yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"] if s.get("name", "").startswith("upload the evidence")][0]
sys.exit(0 if ok and up.get("continue-on-error") is True else 1)
PY3

A="$CLEAN" B="$CLEAN" act
[ ! -s "$w/run/work/armed-unpublished.txt" ] && { echo "ok: act: after arm + published check the cancellation ledger is empty"; pass=$((pass+1)); } \
  || { echo "FAIL: act: ledger not cleared"; cat "$w/run/work/armed-unpublished.txt"; fail=$((fail+1)); }
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" "$w/cancel.sh" <<'PY4'
import sys, yaml
st = [s for s in yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"] if s.get("name", "").startswith("on cancellation")]
assert len(st) == 1 and st[0]["if"] == "cancelled()"
open(sys.argv[2], "w").write(st[0]["run"])
PY4
mkdir -p "$w/cx/work"; printf '99 shaA\n100 shaB\n101 shaC\n' > "$w/cx/work/armed-unpublished.txt"; : > "$w/gh.log"
(cd "$repo" &&
  env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" RUNNER_TEMP="$w/cx" GITHUB_REPOSITORY=o/r APP_TOKEN=a APP_SLUG=s \
  RUN_URL=https://example.invalid/run \
   bash --noprofile --norc -e -o pipefail "$w/cancel.sh") >/dev/null 2>&1
! grep -q "pr merge --disable-auto 99" "$w/gh.log" && grep -q "pr merge --disable-auto 100" "$w/gh.log" && grep -q "pr merge --disable-auto 101" "$w/gh.log" \
  && { echo "ok: cancellation: disarms arms with no success on the head (none, lookup failed); keeps one whose success landed (rounds 5-6)"; pass=$((pass+1)); } \
  || { echo "FAIL: cancellation cleanup"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
grep -q -- "check-runs -f name=dependabot-reviewer -f head_sha=shaC .*conclusion=neutral" "$w/gh.log" \
  && ! grep -q -- "head_sha=shaB" "$w/gh.log" \
  && [ "$(grep -n 'name=dependabot-reviewer -f head_sha=shaC' "$w/gh.log" | cut -d: -f1)" -lt \
    "$(grep -n 'disable-auto 101' "$w/gh.log" | cut -d: -f1)" ] \
  && [ "$(grep -n 'name=auditor-review-gate -f head_sha=shaC .*conclusion=failure' "$w/gh.log" | cut -d: -f1)" -lt \
    "$(grep -n 'name=dependabot-reviewer -f head_sha=shaC' "$w/gh.log" | cut -d: -f1)" ] \
  && { echo \
    "ok: cancellation: a failed lookup fails the gate, posts neutral, THEN disarms (round-7 P1)"; pass=$((pass+1)); } \
  || { echo "FAIL: cancellation: neutral on unknown"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
ext_on_every_check "cancellation: the neutral check carries the reviewer's version as external_id"
: > "$w/gh.log"
(cd "$repo" &&
  env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" FAIL="gate" RUNNER_TEMP="$w/cx" GITHUB_REPOSITORY=o/r APP_TOKEN=a \
  APP_SLUG=s RUN_URL=https://example.invalid/run \
   bash --noprofile --norc -e -o pipefail "$w/cancel.sh") >/dev/null 2>&1
grep -q "name=auditor-review-gate -f head_sha=shaC" "$w/gh.log" &&
  ! grep -q "name=dependabot-reviewer -f head_sha=shaC" "$w/gh.log" &&
  grep -q "pr merge --disable-auto 101" "$w/gh.log" \
  && { echo \
    "ok: cancellation: gate not failed -> no neutral; the arm still comes off (REQ-DEP-001-AC13)"; pass=$((pass+1)); } \
  || { echo "FAIL: cancellation: neutral without the gate failure"; sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
# REQ-DEP-001-AC14: the cancellation step's lookup counts a success only with the current version
cancel_one() { # <check runs of shaA> <left-as-is yes|no> <name>
  printf '99 shaA\n' > "$w/cx/work/armed-unpublished.txt"; : > "$w/gh.log"
  (cd "${CANCELDIR:-$repo}" &&
    env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" CANCELA_JSON="$1" RUNNER_TEMP="$w/cx" GITHUB_REPOSITORY=o/r \
    APP_TOKEN=a APP_SLUG=s RUN_URL=https://example.invalid/run \
     bash --noprofile --norc -e -o pipefail "$w/cancel.sh") >/dev/null 2>&1
  if grep -q "pr merge --disable-auto 99" "$w/gh.log"; then got=no; else got=yes; fi
  [ "$got" = "$2" ] && { echo "ok: cancellation: $3 (arm left as is: $got)"; pass=$((pass+1)); } || {
    echo "FAIL: cancellation: $3 (arm left as is: $got, want $2)"; fail=$((fail+1)); }
}
cancel_one "$(verdicts "[[\"success\",\"$VER\",\"s\"]]")" yes \
  "a success of the current version is on the head: the arm is recorded"
cancel_one "$(verdicts "[[\"success\",\"$OLDVER\",\"s\"]]")" no \
  "a success of another version is no success: the arm comes off"
cancel_one "$(verdicts '[["success",null,"s"]]')" no \
  "a success with an external_id of null is no success: the arm comes off"
cancel_one "$(verdicts '[["success","","s"]]')" no \
  "a success with an empty external_id is no success: the arm comes off"
cancel_one "$(verdicts '[["success",null,"s"]]' | jq -c '.check_runs[0] |= del(.external_id)')" no \
  "a success with no external_id is no success: the arm comes off"
cancel_one "$(verdicts "[[\"success\",\"$VER\",\"s\"],[\"success\",\"$OLDVER\",\"s\"]]")" no \
  "a success of another version finishing after the current one (newest by id): the arm comes off"
cancel_one "$(verdicts "[[\"success\",\"$OLDVER\",\"s\"],[\"success\",\"$VER\",\"s\"]]")" yes \
  "a success of the current version after an older one: the arm is recorded"
cancel_one "$(verdicts "[[\"success\",\"$PYVER\",\"s\"]]")" no \
  "a success carrying the sha256 of the program alone is no success: the arm comes off"
cancel_one "$(verdicts "[[\"success\",\"$OLD3\",\"s\"]]")" no \
  "a success carrying the version of the three files joined is no success: the arm comes off"
cancel_one "$(verdicts "[[\"success\",\"$OLD3S\",\"s\"]]")" no \
  "a success carrying the version of the three files' sha256sum lines is no success: the arm comes off"
# a cut answer (31 runs, 30 read) is no verdict: whatever the newest run read says, the arm comes off
cancel_one "$(verdicts_cut "[\"success\",\"$VER\",\"s\"]")" no \
  "a success of the current version among 30 of 31 runs is no success: the arm comes off"
asks_all_runs "cancellation: the check runs are asked with filter=all, 100 at a time"
cancel_one "$(verdicts_cut "[\"success\",\"$OLDVER\",\"s\"]")" no \
  "a success of another version among 30 of 31 runs is no success: the arm comes off"
cancel_one "$(verdicts_cut '["success",null,"s"]')" no \
  "a plain success among 30 of 31 runs is no success: the arm comes off"
for what in prompt-changed workflow-changed checks-changed guard-changed; do
  mkalt "$w/alt" "$what"
  CANCELDIR="$w/alt" cancel_one "$(verdicts "[[\"success\",\"$VER\",\"s\"]]")" no \
    "with the $what a success of the version of the old text is no success: the arm comes off"
  CANCELDIR="$w/alt" cancel_one "$(verdicts "[[\"success\",\"$(ver3 "$w/alt")\",\"s\"]]")" yes \
    "with the $what a success of the version of the five files as they are is recorded"
done
for what in no-prompt no-workflow no-checks no-guard; do
  mkalt "$w/alt" "$what"
  printf '99 shaC\n' > "$w/cx/work/armed-unpublished.txt"; : > "$w/gh.log"
  (cd "$w/alt" &&
    env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" RUNNER_TEMP="$w/cx" GITHUB_REPOSITORY=o/r APP_TOKEN=a APP_SLUG=s \
    RUN_URL=https://example.invalid/run \
     bash --noprofile --norc -e -o pipefail "$w/cancel.sh") >/dev/null 2>&1; rc=$?
  ! grep -q "check-runs -f" "$w/gh.log" && {
    echo \
    "ok: cancellation: $what: no version -> no check at all is published (no version=unknown)"; pass=$((pass+1)); } \
    || { echo "FAIL: cancellation: $what: a check was published without a version"; sed 's/^/    gh: /' "$w/gh.log";
      fail=$((fail+1)); }
  step_fails "cancellation: $what: the step fails" "$rc"
done

# ============================================================================ candidates step
python3 - "$repo/.github/workflows/dependabot-reviewer.yml" "$w/cand.sh" "$w/streak.sh" "$w/settle.sh" <<'PY2'
import sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]
c = [s["run"] for s in steps if s.get("id") == "candidates"]
k = [s["run"] for s in steps if s.get("name", "").startswith("three unfinished runs in a row")]
t = [s for s in steps if s.get("id") == "settle"]
assert len(c) == 1 and len(k) == 1 and len(t) == 1
# the settle step runs after the act step and the cancellation cleanup, whatever became of them (finished, failed,
# cancelled)
names = [s.get("id") or s.get("name", "") for s in steps]
assert names.index("act") < [i for i, x in enumerate(names) if x.startswith("on cancellation")][0] \
    < names.index("settle"), names
assert t[0]["if"] == ("${{ always() && steps.candidates.outputs.count != '0' && steps.candidates.outputs.count != ''"
                      " && steps.app-merge.outcome == 'success' }}"), t[0]["if"]
assert "continue-on-error" not in t[0]
open(sys.argv[2], "w").write(c[0]); open(sys.argv[3], "w").write(k[0]); open(sys.argv[4], "w").write(t[0]["run"])
PY2
# the default list: the two real majors (#99, #91). prs-all.json adds the real plain patch (#90); prs-flagged.json
# adds the flagged group (#400) too.
jq -n --slurpfile a "$FIX/pr-99.json" --slurpfile c "$FIX/pr-91.json" \
  '[($a[0] + {number: 99, headRefOid: "sha99"}), ($c[0] + {number: 91, headRefOid: "sha91"})]' > "$w/prs.json"
jq -n --slurpfile a "$FIX/pr-99.json" --slurpfile b "$FIX/pr-90.json" --slurpfile c "$FIX/pr-91.json" \
  '[($a[0] + {number: 99, headRefOid: "sha99"}), ($b[0] + {number: 90, headRefOid: "sha90"}),
    ($c[0] + {number: 91, headRefOid: "sha91"})]' > "$w/prs-all.json"
jq -n --slurpfile b "$FIX/pr-90.json" '[($b[0] + {number: 90, headRefOid: "sha90"})]' > "$w/prs-patch.json"
cat > "$w/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
own_check() { # <check runs as JSON, or empty> <the answer otherwise> <the call's own arguments>
  local json="$1" answer="$2" f=; shift 2
  [ -n "$json" ] || { echo "$answer"; return; }
  while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done
  jq -r "$f" <<<"$json"
}
case "$1 $2" in
  "pr list") cat "$PRS_JSON" ;;
  # the reviewer's own check on a head: PRIOR99 as the answer, or PRIOR99_JSON through the step's own filter
  "api repos/o/r/commits/sha99/check-runs?check_name=dependabot-reviewer"*)
              [ "${LOOKUP99:-}" = fail ] && exit 1; own_check "${PRIOR99_JSON:-}" "${PRIOR99:-none}" "$@" ;;
  "api repos/o/r/commits/p1/check-runs?check_name=dependabot-reviewer"*)
              [ "${LOOKUPP1:-}" = fail ] && exit 1; own_check "${PRIORP1_JSON:-}" "${PRIORP1:-none}" "$@" ;;
  "api repos/o/r/commits/sha90/check-runs?check_name=dependabot-reviewer"*) [ "${LOOKUP90:-}" = fail ] && exit 1;
    own_check "${PRIOR90_JSON:-}" "${PRIOR90:-none}" "$@" ;;
  "api repos/o/r/commits/sha91/check-runs?check_name=dependabot-reviewer"*) echo "${PRIOR91:-none}" ;;
  "api repos/o/r/commits/sha400/check-runs?check_name=dependabot-reviewer"*) echo "${PRIOR400:-none}" ;;
  # earlier heads of #99 and #90 (the spend guard): p1 is the head's first parent, p0 is p1's
  "api repos/o/r/commits/p0/check-runs?check_name=dependabot-reviewer"*) echo "${PRIORP0:-none}" ;;
  # a commit as GitHub gives it, read by the step's own filter: PARENT=x makes the head a merge commit (first parent
  # x, second on main);
  # ONEPARENT=x makes it an ordinary commit on top of x; neither: an ordinary commit on main
  "api repos/o/r/commits/sha99"|"api repos/o/r/commits/sha90"|"api repos/o/r/commits/p1")
              case "$2" in */p1) one="${ONEPARENTP1:-}"; two="${PARENTP1:-}" ;; *) one="${ONEPARENT:-}";
                two="${PARENT:-}" ;; esac
              f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done
              if [ -n "$two" ]; then jq -r "$f" <<<"{\"parents\": [{\"sha\": \"$two\"}, {\"sha\": \"main1\"}]}"
              else jq -r "$f" <<<"{\"parents\": [{\"sha\": \"${one:-main0}\"}]}"; fi ;;
  "api -H") case "$4" in     # same-diff: GitHub's diff of a commit against its merge base with main
              repos/o/r/compare/main...p1|repos/o/r/compare/main...p0) [ "${DIFFFAIL:-}" = 1 ] && exit 1;
                printf '%b' "${DIFF_OLD-$DIFF_SAME}" ;;
              repos/o/r/compare/main...sha99|repos/o/r/compare/main...sha90) printf '%b' "${DIFF_NEW-$DIFF_SAME}" ;;
              *) exit 1 ;;
            esac ;;
  "api repos/o/r/issues/99/events") [ "${EVENTSFAIL:-}" = 1 ] && exit 1
              # the step's own filter, run for real
              if [ -n "${EVENTS99_JSON:-}" ]; then f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done;
                jq -r "$f" <<<"$EVENTS99_JSON"
              else printf '%b' "${EVENTS99:-}"; fi ;;
  "api repos/o/r/contents/.github/policy/required-checks.json?ref=main") base64 < "$REPO_CHECKS" | tr -d '\n' ;;
  "api repos/o/r/check-runs") case "$*" in *name=auditor-review-gate*) [ "${GATEFAIL:-}" = 1 ] && exit 1; : ;; *)
    [ "${NEUTRALFAIL:-}" = 1 ] && exit 1; : ;; esac ;;
  # the review gate's own check on a head (the App's latest): GATE99, none unless set; no gate check on any other head
  "api repos/o/r/commits/sha99/check-runs?check_name=auditor-review-gate") [ "${GATELOOKUP:-}" = fail ] && exit 1
              # the step's own filter, run for real
              if [ -n "${GATE99_JSON:-}" ]; then f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done;
                jq -r "$f" <<<"$GATE99_JSON"
              else echo "${GATE99:-none}"; fi ;;
  "api repos/o/r/commits/"*"/check-runs?check_name=auditor-review-gate") echo none ;;
  # #77: a PR whose title and body name no update that can be read
  "api repos/o/r/commits/sha77/check-runs?check_name=dependabot-reviewer"*) echo "${PRIOR77:-none}" ;;
  # the PR as GitHub gives it, read by the step's own filter
  "pr view") case "$3" in 90) v="${ARMED90:-${ARMED99:-false}}" ;; 77) v="${ARMED77:-false}" ;; *)
    v="${ARMED99:-false}" ;; esac
              h="sha$3"; [ "${MOVED:-}" = "$3" ] && h=shaNEW
              case "$v" in true)
                j='{"state":"OPEN","headRefOid":"'$h'","autoMergeRequest":{"mergeMethod":"SQUASH"}}' ;; closed)
                j='{"state":"MERGED","headRefOid":"'$h'","autoMergeRequest":null}' ;; *)
                j='{"state":"OPEN","headRefOid":"'$h'","autoMergeRequest":null}' ;; esac
              f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done; jq -r "$f" <<<"$j" ;;
  "pr merge") case "$*" in *--auto*) [ "${REARMFAIL:-}" = 1 ] && exit 1; : ;; *) [ "${DISARMFAIL:-}" = 1 ] && exit 1; : ;; esac ;;
  "run list") [ "${RUNLIST:-}" = fail ] && exit 1
              f=; while [ $# -gt 0 ]; do [ "$1" = --jq ] && f="$2"; shift; done
              jq -c "${f:-.}" <<<"${HISTORY:-[]}" ;;
  "issue list") echo '[]' ;;
  "issue create"|"issue comment") ;;
esac
EOF
chmod +x "$w/bin/gh"
DIFF_SAME='diff --git a/go.mod b/go.mod\nindex 1111111..2222222 100644\n--- a/go.mod\n+++ b/go.mod\n@@ -1,3 +1,3 @@\n'
DIFF_SAME+=' module x\n-require a/b v4.0.0\n+require a/b v7.0.0\n'
export DIFF_SAME
cand() { # expected-candidates (* = any) expected-rc (nz = any failure); env PRIOR99 PRIOR91 LOOKUP99 FORCE
  local W="$w/cand"; rm -rf "$W"; mkdir -p "$W"; : > "$w/gh.log"
  (cd "${CANDDIR:-$repo}" &&
    env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" PRS_JSON="${PRSFILE:-$w/prs.json}" GITHUB_REPOSITORY=o/r \
    RUNNER_TEMP="$W" REPO_CHECKS="$repo/.github/policy/required-checks.json" \
    GUARD_RULES_JSON="${RULES:-$w/rules-match.json}" \
     GITHUB_OUTPUT="$W/output" APP_TOKEN=a APP_SLUG=fosterstack-automation MERGE_TOKEN=m RUN_URL=https://example.invalid/run \
     ONLY_PR="${ONLY:-}" FORCE="${FORCE:-false}" \
     bash --noprofile --norc -e -o pipefail "$w/cand.sh") > "$w/cand.out" 2>&1; local rc=$?
  local got; got=$(cut -d' ' -f1,3 "$W/work/candidates.txt" 2>/dev/null | tr '\n' ',')
  CAND_GOT="$got"; CAND_RC="$rc"
  if { [ "$1" = '*' ] || [ "$got" = "$1" ]; } && { [ "$rc" = "$2" ] || { [ "$2" = nz ] && [ "$rc" != 0 ]; } \
      || [ "$2" = any ]; }; then
    # rc any: no answer is wrong here, the caller's own check follows, and only that one counts
    [ "$2" = any ] || { echo "ok: candidates: $3"; pass=$((pass+1)); }
  else echo "FAIL: candidates: $3 (got '$got' rc $rc)"; sed 's/^/    /' "$w/cand.out" | tail -8; fail=$((fail+1)); fi
}
also() { # <name> then +regex / -regex assertions on the gh log of the last cand, settle or lane run
  local name="$1" ok=1; shift
  for a in "$@"; do
    case "$a" in
      +*) grep -qE -- "${a:1}" "$w/gh.log" || ok=0 ;;
      -*) grep -qE -- "${a:1}" "$w/gh.log" && ok=0 ;;
    esac
  done
  if [ "$ok" = 1 ]; then echo "ok: $name"; pass=$((pass+1)); else echo "FAIL: $name"; sed 's/^/    gh: /' "$w/gh.log";
    fail=$((fail+1)); fi
}
cand "99 none,91 none," 0 "real bodies: the majors #99 and #91 are selected"
# every open Dependabot PR is a candidate, whatever its updates are (REQ-DEP-001-AC2): the real plain patch #90 beside
# the majors
PRSFILE="$w/prs-all.json" cand "99 none,90 none,91 none," 0 \
  "real bodies: the plain patch #90 is selected beside the majors #99 and #91"
PRSFILE="$w/prs-all.json" PRIOR90=success cand "99 none,91 none," 0 \
  "a plain patch with a success verdict is not reviewed again"
PRSFILE="$w/prs-all.json" PRIOR90=failure cand "99 none,91 none," 0 \
  "a plain patch with a failure verdict is not reviewed again"
PRIOR99=success cand "91 none," 0 "a success verdict is not reviewed again"
PRIOR99=failure PRIOR91=neutral cand "91 neutral," 0 "failure is a verdict; neutral means retry"
PRIOR99=success FORCE=true cand "99 neutral,91 none," 0 "force: old verdict invalidated up front (disarm + neutral), reviewed from neutral (round-3 P1)"
grep -q "pr merge --disable-auto 99" "$w/gh.log" && grep -q -- "-f conclusion=neutral" "$w/gh.log" \
  && { echo "ok: candidates: the forced invalidation happened before any later step"; pass=$((pass+1)); } || { echo "FAIL: candidates: forced invalidation calls"; fail=$((fail+1)); }
[ "$(grep -n 'name=auditor-review-gate -f head_sha=sha99 .*conclusion=failure' "$w/gh.log" | cut -d: -f1)" -lt \
  "$(grep -n 'name=dependabot-reviewer -f head_sha=sha99 .*conclusion=neutral' "$w/gh.log" | cut -d: -f1)" ] \
  2>/dev/null \
  && { echo "ok: candidates: force: the review gate's check is failed FIRST, then the neutral (REQ-DEP-001-AC13)";
    pass=$((pass+1)); } || { echo "FAIL: candidates: forced gate failure before neutral";
    sed 's/^/    gh: /' "$w/gh.log"; fail=$((fail+1)); }
PRIOR99=success FORCE=true NEUTRALFAIL=1 cand "91 none," 1 "force: neutral cannot be posted -> skipped, step fails (round-3 P1)"
PRIOR99=success FORCE=true GATEFAIL=1 cand "91 none," 1 \
  "force: the review gate's check cannot be failed -> skipped, step fails"
also "candidates: without the gate failure the old verdict is not superseded (no neutral)" \
  "-name=dependabot-reviewer -f head_sha=sha99"
# REQ-DEP-001-AC13: every hour, a gate success standing over a failure or neutral verdict is failed again (a gate run
# that read before the verdict and published after it)
GFAIL='check-runs -f name=auditor-review-gate -f head_sha=sha99 -f status=completed -f conclusion=failure'
PRIOR99=failure GATE99=success cand "91 none," 0 "a failure verdict whose gate check says success"
also "candidates: the gate's check is failed again over the failure verdict" "+$GFAIL"
PRIOR99=failure GATE99=failure cand "91 none," 0 "a failure verdict whose gate check says failure"
also "candidates: nothing is published when the gate already says failure" "-check-runs -f"
PRIOR99=failure cand "91 none," 0 "a failure verdict with no gate check yet"
also "candidates: nothing is published when the gate has no check (none is not green)" "-check-runs -f"
PRIOR99=failure GATE99=success GATEFAIL=1 cand "91 none," 1 \
  "the gate's check cannot be failed again over a failure verdict -> the step fails"
PRIOR99=failure GATELOOKUP=fail cand "91 none," 1 \
  "the gate's check cannot be read over a failure verdict -> the step fails"
PRIOR99=neutral GATE99=success cand "99 neutral,91 none," 0 \
  "a neutral verdict whose gate check says success -> failed again, then reviewed"
also "candidates: the gate's check is failed again over the neutral verdict" "+$GFAIL"
PRIOR99=neutral GATE99=success GATEFAIL=1 cand "91 none," 1 \
  "the gate's check cannot be failed again over a neutral verdict -> skipped this hour, the step fails"
# REQ-DEP-001-AC13: a gate success never stands over a verdict that is not a success of the current version: not over
# a cancelled, timed_out or action_required
# check either (the verdict is the conclusion as GitHub gives it, whatever it is)
for concl in cancelled timed_out action_required; do
  ONLY=99 PRIOR99_JSON=$(verdicts "[[\"$concl\",\"$VER\"]]") GATE99=success cand '*' 0 \
    "a $concl verdict whose gate check says success"
  also "candidates: the gate's check is failed again over the $concl verdict" "+$GFAIL .*verdict on this head is $concl"
  ONLY=99 PRIOR99_JSON=$(verdicts "[[\"$concl\",\"$VER\"]]") GATE99=failure cand '*' 0 \
    "a $concl verdict whose gate check says failure"
  also "candidates: nothing is published over the $concl verdict when the gate already says failure" \
    "-check-runs -f name=auditor-review-gate"
  ONLY=99 PRIOR99_JSON=$(verdicts "[[\"$concl\",\"$VER\"]]") GATE99=success GATEFAIL=1 cand '*' nz \
    "the gate's check cannot be failed again over a $concl verdict -> the step fails"
  ONLY=99 PRIOR99_JSON=$(verdicts "[[\"$concl\",\"$VER\"]]") GATELOOKUP=fail cand '*' nz \
    "the gate's check cannot be read over a $concl verdict -> the step fails"
done
# The other way round: a head the reviewer passed whose gate failure is older than the six hours the gate's sweep
# looks back is never judged again. The failure is published anew (never a success), which puts it back in the sweep's
# window.
GREFRESH="$GFAIL .*passed this head, and this check last failed more than six hours ago"
PRIOR99=success GATE99=stale cand "91 none," 0 "a success verdict over a stale gate failure"
also "candidates: the stale gate failure is published again, as a failure" "+$GREFRESH" \
  "-name=auditor-review-gate.*conclusion=success"
PRIOR99=success GATE99=success cand "91 none," 0 "a success verdict over a gate success"
also "candidates: a gate success over a success verdict is left alone" "-check-runs -f name=auditor-review-gate"
PRIOR99=success GATE99=failure cand "91 none," 0 "a success verdict over a gate failure of the last six hours"
also "candidates: a recent gate failure is left to the sweep, which still judges it" \
  "-check-runs -f name=auditor-review-gate"
PRIOR99=success cand "91 none," 0 "a success verdict with no gate check yet"
also "candidates: nothing to refresh without a gate check" "-check-runs -f name=auditor-review-gate"
PRIOR99=success GATE99=stale GATEFAIL=1 cand "91 none," 1 \
  "the stale gate failure cannot be published again -> the step fails (retried next hour)"
PRIOR99=success GATELOOKUP=fail cand "91 none," 1 \
  "the gate's check cannot be read over a success verdict -> the step fails"
ONLY=99 PARENT=p1 PRIORP1=success GATE99=stale cand "" 0 "a carried success over a stale gate failure"
also "candidates: the carried success is published, then the stale gate failure again" \
  "+name=dependabot-reviewer -f head_sha=sha99 .*conclusion=success" "+$GREFRESH"
PRIOR99=failure GATE99=stale cand "91 none," 0 "a failure verdict over a stale gate failure"
also "candidates: a stale gate failure over a failure verdict is not published again" "-check-runs -f"
# the step's own filter over check runs as GitHub lists them: the App's newest by completion time decides; six hours
# is the line
runs_json() {
  jq -cn --argjson r "$1" \
  '{check_runs: [$r[] | {conclusion: .[0], completed_at: .[1], app: {slug: (.[2] // "fosterstack-automation")}}]}'; }
RECENT=$(date -u -d '-2 hours' +%Y-%m-%dT%H:%M:%SZ); OLD=$(date -u -d '-7 hours' +%Y-%m-%dT%H:%M:%SZ);
  OLDER=$(date -u -d '-9 hours' +%Y-%m-%dT%H:%M:%SZ)
PRIOR99=success GATE99_JSON=$(runs_json "[[\"failure\",\"$OLD\"]]") cand "91 none," 0 \
  "real check runs: a gate failure seven hours old over a success verdict"
also "candidates: seven hours is stale: published again" "+$GREFRESH"
PRIOR99=success GATE99_JSON=$(runs_json "[[\"failure\",\"$RECENT\"]]") cand "91 none," 0 \
  "real check runs: a gate failure two hours old over a success verdict"
also "candidates: two hours is inside the sweep's window: left alone" "-check-runs -f name=auditor-review-gate"
PRIOR99=success GATE99_JSON=$(runs_json "[[\"failure\",\"$OLDER\"],[\"success\",\"$OLD\"]]") cand "91 none," 0 \
  "real check runs: an old failure, then a later success"
also "candidates: the newest check is the success: left alone" "-check-runs -f name=auditor-review-gate"
PRIOR99=success GATE99_JSON=$(runs_json "[[\"success\",\"$OLDER\"],[\"failure\",\"$OLD\"]]") cand "91 none," 0 \
  "real check runs: an old success, then a later failure that is stale now"
also "candidates: the newest check is the stale failure: published again" "+$GREFRESH"
PRIOR99=success GATE99_JSON=$(runs_json "[[\"failure\",\"$OLD\",\"github-actions\"]]") cand "91 none," 0 \
  "real check runs: a same-named check from another app"
also "candidates: another app's check is not the gate's: nothing published" "-check-runs -f name=auditor-review-gate"
PRIOR99=failure GATE99_JSON=$(runs_json "[[\"failure\",\"$OLDER\"],[\"success\",\"$RECENT\"]]") cand "91 none," 0 \
  "real check runs: a gate success newer than its failure, over a failure verdict"
also "candidates: the gate success over the failure verdict is failed again" "+$GFAIL .*verdict on this head is failure"

# REQ-DEP-001-AC14: a success counts only if its external_id is the version of the reviewer as this run checked it out
# (the sha256 of the sha256sum lines of the five files). A success of another version, or with none, is no verdict:
# the head is read as a head with none is.
CUR_OK="[\"success\",\"$VER\"]"; OLD_OK="[\"success\",\"$OLDVER\"]"; OWN99='name=dependabot-reviewer -f head_sha=sha99'
ONLY=99 ARMED99=true PRIOR99_JSON=$(verdicts "[$CUR_OK,$OLD_OK]") cand "99 none," 0 \
  "a success of another version finishing after the current one (the newest by id) is no verdict: read"
also "candidates: its arm comes off before the review and no verdict is published" "+pr merge --disable-auto 99" \
  "-name=dependabot-reviewer .*conclusion="
ONLY=99 PRIOR99_JSON=$(verdicts '[["success"]]') cand "99 none," 0 \
  "a success from before the change (no external_id) is read"
ONLY=99 PRIOR99_JSON=$(verdicts '[["success",null]]') cand "99 none," 0 "a success whose external_id is null is read"
ONLY=99 PRIOR99_JSON=$(verdicts '[["success",""]]') cand "99 none," 0 "a success whose external_id is empty is read"
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"${VER^^}\"]]") cand "99 none," 0 \
  "a success whose external_id is the current version in upper case is read"
ONLY=99 PRIOR99_JSON=$(verdicts "[$OLD_OK]") cand "99 none," 0 "a success of another version alone is read"
also "candidates: it is not superseded, forced or published over" "-check-runs -f" "-pr merge --disable-auto"
ONLY=99 PRIOR99_JSON=$(verdicts "[$CUR_OK]") cand "" 0 \
  "a success of the current version is still a success: not read again"
also "candidates: nothing is published over a current success" "-check-runs -f name=dependabot-reviewer"
ONLY=99 PRIOR99_JSON=$(verdicts "[$OLD_OK,$CUR_OK]") cand "" 0 \
  "a success of another version replaced by a newer one of the current version is a success"
# a cut answer (total_count 31, 30 runs read) is no verdict: the head is not passed over as a success; the lookup fails
# (skipped, the step fails) or reads none (the head is taken up)
for what in "[\"success\",\"$VER\"]" "[\"success\",\"$OLDVER\"]" '["success"]'; do
  ONLY=99 PRIOR99_JSON=$(verdicts_cut "$what") cand '*' any "30 of 31 runs read, the newest $what"
  if [ -z "$CAND_GOT" ] && [ "$CAND_RC" = 0 ]; then
    echo "FAIL: candidates: 30 of 31 runs read, the newest $what: counted as a success (nothing taken up, no failure)"
    fail=$((fail+1))
  else echo "ok: candidates: 30 of 31 runs read, the newest $what: not counted as a success"; pass=$((pass+1)); fi
done
asks_all_runs "candidates: the check runs are asked with filter=all, 100 at a time"
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"failure\",\"$OLDVER\"]]") cand "" 0 \
  "a failure of another version is still a failure verdict"
ONLY=99 PRIOR99_JSON=$(verdicts '[["failure"]]') cand "" 0 "a failure with no external_id is still a failure verdict"
ONLY=99 PRIOR99_JSON=$(verdicts "[$CUR_OK,[\"failure\",\"$OLDVER\"]]") cand "" 0 \
  "a failure of another version after a current success decides"
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"neutral\",\"$OLDVER\"]]") cand "99 neutral," 0 \
  "a neutral of another version is still neutral"
ONLY=99 PRIOR99_JSON=$(verdicts '[["neutral"]]') cand "99 neutral," 0 "a neutral with no external_id is still neutral"
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"$VER\",\"github-actions\"]]") cand "99 none," 0 \
  "another app's success is no verdict at all"
ONLY=99 PARENT=p1 PRIORP1_JSON=$(verdicts "[$OLD_OK]") cand "99 none," 0 \
  "a merge of main over a head whose success is of another version -> read: it is not carried"
also "candidates: no diff is compared and no success published from an ancestor of another version" "-compare/" \
  "-check-runs -f"
ONLY=99 PARENT=p1 PRIORP1_JSON=$(verdicts '[["success"]]') cand "99 none," 0 \
  "a merge of main over a head whose success has no external_id -> read: it is not carried"
also "candidates: no diff is compared and no success published from an ancestor with no external_id" "-compare/" \
  "-check-runs -f"
ONLY=99 PARENT=p1 PRIORP1_JSON=$(verdicts "[$CUR_OK,$OLD_OK]") cand "99 none," 0 \
  "a merge of main over a head whose newest success is of another version (after the current one) -> read"
also "candidates: nothing carried from an ancestor whose newest success is of another version" "-compare/" \
  "-check-runs -f"
ONLY=99 PARENT=p1 PARENTP1=p0 PRIORP1_JSON=$(verdicts "[$OLD_OK]") PRIORP0=success cand "" 0 \
  "a success of another version is no verdict: the walk goes on past it to the current success behind it"
also \
  "candidates: the success is carried from the older head, the ancestor with the success of another version skipped" \
  "+check-runs -f name=dependabot-reviewer -f head_sha=sha99 .*conclusion=success .*carried over from that head" \
  "+compare/main\.\.\.p0" "+compare/main\.\.\.sha99"
ONLY=99 PARENT=p1 PARENTP1=p0 PRIORP1_JSON=$(verdicts "[$OLD_OK]") cand "99 none," 0 \
  "a success of another version, and no verdict behind it within reach -> the head is read"
also "candidates: nothing is carried when only a success of another version is within reach" "-compare/" \
  "-check-runs -f"
ONLY=99 PARENT=p1 PRIORP1_JSON=$(verdicts "[$OLD_OK,$CUR_OK]") cand "" 0 \
  "a merge of main over a head whose success of another version was replaced by the current one is still carried"
also "candidates: the current success is carried to the head, after both diffs were read" \
  "+compare/main\.\.\.p1" "+compare/main\.\.\.sha99" \
  "+$OWN99 -f status=completed -f conclusion=success .*carried over from that head"
ext_on_every_check "candidates: the carried success carries the reviewer's version as external_id"
ONLY=99 PARENT=p1 PRIORP1=success cand "" 0 "a merge of main over a success (no filter) is carried"
ext_on_every_check \
  "candidates: a carried success carries the reviewer's version as external_id whatever the ancestor's was"
PRIOR99=success FORCE=true cand "99 neutral,91 none," 0 "force over a success: reviewed from neutral"
ext_on_every_check "candidates: the neutral that supersedes a verdict carries the reviewer's version as external_id"
ONLY=99 CANDDIR="$w/noprog" PRIOR99=success cand "" 1 \
  "the reviewer's version cannot be read (no bin/dependabot-reviewer.py) -> the step fails before any verdict is read"
also "candidates: nothing is listed, read or published without the version" "-pr list" "-check-runs" "-pr merge"
# REQ-DEP-001-AC14: the version is of bin/dependabot-reviewer.py, the prompt and the workflow, joined in that order,
# as this run checked them out
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"$PYVER\"]]") cand "99 none," 0 \
  "a success carrying the sha256 of the program alone (the version before the prompt and the workflow counted) is read"
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"$OLD3\"]]") cand "99 none," 0 \
  "a success carrying the version of the three files joined (the version before the five files and sha256sum) is read"
ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"$OLD3S\"]]") cand "99 none," 0 \
  "a success carrying the version of the three files' sha256sum lines is read"
for what in prompt-changed workflow-changed checks-changed guard-changed; do
  mkalt "$w/alt" "$what"
  CANDDIR="$w/alt" ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"$VER\"]]") cand "99 none," 0 \
    "with the $what a success of the version of the old text is read"
  also "candidates: it is not superseded, forced or published over" "-check-runs -f name=dependabot-reviewer"
  CANDDIR="$w/alt" ONLY=99 PRIOR99_JSON=$(verdicts "[[\"success\",\"$(ver3 "$w/alt")\"]]") cand "" 0 \
    "with the $what a success of the version of the five files as they are is still a success"
done
for what in no-prompt no-workflow no-checks no-guard; do
  mkalt "$w/alt" "$what"
  CANDDIR="$w/alt" PRIOR99=success cand "" 1 \
    "a missing file ($what): the version cannot be computed -> the step fails before any verdict is read"
  also "candidates: $what: nothing is listed, read or published" "-pr list" "-check-runs" "-pr merge"
done
# REQ-DEP-001-AC13: a head whose newest verdict is none (a success of another version or with no version too) never
# keeps a gate success
ONLY=99 PRIOR99_JSON=$(verdicts "[$OLD_OK]") GATE99=success cand "99 none," 0 \
  "a success of another version over a gate success"
also "candidates: the gate's check is failed again over the success of another version" "+$GFAIL"
ONLY=99 PRIOR99_JSON=$(verdicts '[["success"]]') GATE99=success cand "99 none," 0 \
  "a success with no external_id over a gate success"
also "candidates: the gate's check is failed again over the unversioned success" "+$GFAIL"
ONLY=99 PRIOR99_JSON=$(verdicts "[$OLD_OK]") GATE99=failure cand "99 none," 0 \
  "a success of another version over a gate failure"
also "candidates: a gate failure is left as it is" "-check-runs -f name=auditor-review-gate"
ONLY=99 PRIOR99_JSON=$(verdicts "[$OLD_OK]") GATE99=success GATEFAIL=1 cand '*' nz \
  "the gate's check cannot be failed again over a success of another version -> the step fails"
ONLY=99 PRIOR99_JSON=$(verdicts "[$OLD_OK]") GATELOOKUP=fail cand '*' nz \
  "the gate's check cannot be read over a success of another version -> the step fails"
ONLY=99 GATE99=success GATEFAIL=1 cand '*' nz \
  "the gate's check cannot be failed again over a head with no reviewer check -> the step fails"
ONLY=99 GATELOOKUP=fail cand '*' nz \
  "the gate's check cannot be read over a head with no reviewer check -> the step fails"

# REQ-DEP-001-AC10: a PR whose update lines cannot be read is read like any other, and is not the lane's: an arm with
# no verdict comes off first
jq -n '[{number: 77, title: "An odd title", body: "nothing here names an update", headRefOid: "sha77"}]' > \
  "$w/prs-unparsed.json"
PRSFILE="$w/prs-unparsed.json" ARMED77=true cand "77 none," 0 \
  "an armed PR whose updates cannot be read, no verdict -> a candidate"
also "candidates: its arm is turned off before the review (it is not the lane's)" "+pr merge --disable-auto 77"
[ ! -s "$w/cand/work/lane-arms.txt" ] &&
  [ "$(jq -c '[.[]|[.kind, .major, .flagged]]' "$w/cand/work/updates-77.json")" = '[["unparsed",false,false]]' ] \
  && { echo "ok: candidates: the unreadable PR is not remembered as a lane arm; its one update is of kind unparsed";
    pass=$((pass+1)); } \
  || { echo "FAIL: candidates: unparsed PR"; cat "$w/cand/work/lane-arms.txt" "$w/cand/work/updates-77.json";
    fail=$((fail+1)); }
PRSFILE="$w/prs-unparsed.json" cand "77 none," 0 \
  "an unarmed PR whose updates cannot be read -> a candidate, nothing to turn off"
also "candidates: no disarm call for it" "-disable-auto"
GATE99=success cand "99 none,91 none," 0 \
  "a head with no reviewer check whose gate check says success: failed again, then reviewed"
also "candidates: the gate's check is failed again over a head with no verdict (none never keeps a gate success)" \
  "+$GFAIL"
PRIOR99=success FORCE=true DISARMFAIL=1 ARMED99=true cand "" 1 "force: auto-merge cannot be turned off -> skipped, step fails (the stub shows #91 armed too: skipped as well)"
PRIOR99=success ARMED99=false cand "91 none," 0 "a success verdict whose PR someone disarmed is left alone (no re-arm, round-4 P1)"
ARMED99=true cand "99 none,91 none," 0 "armed with no verdict (cancelled mid-act) -> disarmed BEFORE review (round-4 P1)"
grep -q "pr merge --disable-auto 99" "$w/gh.log" && { echo "ok: candidates: the unsupported arm was turned off up front"; pass=$((pass+1)); } || { echo "FAIL: candidates: up-front disarm"; fail=$((fail+1)); }
cand "99 none,91 none," 0 "not armed, no verdict -> no disarm call"
grep -q "disable-auto" "$w/gh.log" && { echo "FAIL: candidates: needless disarm"; fail=$((fail+1)); } || { echo "ok: candidates: no needless disarm"; pass=$((pass+1)); }
ARMED99=true DISARMFAIL=1 cand "" 1 "armed with no verdict and the disarm fails -> skipped, step fails"
LOOKUP99=fail cand "91 none," 1 "a failed check lookup skips that PR and FAILS the step (round-2 P2)"
PRSFILE="$w/prs-all.json" ONLY=90 cand "90 none," 0 "pr=90 (a plain patch) selects it"
PRSFILE="$w/prs-all.json" ONLY=90 PRIOR90=success cand "" 0 "pr=90 with a success verdict and no force selects nothing"
PRSFILE="$w/prs-all.json" ONLY=90 PRIOR90=success FORCE=true cand "90 neutral," 0 \
  "pr=90 forced over a success verdict: auto-merge off, neutral, reviewed again (a patch like a major)"
also "candidates: the forced patch was disarmed and its verdict superseded" "+pr merge --disable-auto 90" \
  "+head_sha=sha90 .*conclusion=neutral"
PRSFILE="$w/prs-all.json" FORCE=true PRIOR99=success PRIOR90=failure cand "99 neutral,90 neutral,91 none," 0 \
  "force with no pr: every open Dependabot PR is reviewed again, verdict or not"
# REQ-DEP-001-AC10: a flagged non-major (real #400, codeql 4.38.2 -> 4.38.3, notes say 'Breaking change') is a candidate like a major
PRSFILE="$w/prs-flagged.json" cand "99 none,90 none,91 none,400 none," 0 \
  "a flagged non-major (#400) is selected beside the majors and the plain patch"
PRSFILE="$w/prs-flagged.json" PRIOR400=success cand "99 none,90 none,91 none," 0 \
  "a flagged non-major with a success verdict is not reviewed again"
PRSFILE="$w/prs-flagged.json" ARMED99=true ARMED90=false cand "99 none,90 none,91 none,400 none," 0 \
  "armed flagged non-major with no verdict -> disarmed up front like a major"
grep -q "pr merge --disable-auto 400" "$w/gh.log" && { echo "ok: candidates: the armed flagged non-major was turned off up front"; pass=$((pass+1)); } || { echo "FAIL: candidates: flagged up-front disarm"; fail=$((fail+1)); }
ONLY=400 PRSFILE="$w/prs-flagged.json" cand "400 none," 0 "pr=400 (flagged) selects it"
# the updates reach the act step as the parser wrote them: what each one is (major, flagged, kind)
[ "$(jq -r '[.[]|select((.major|not) and .flagged and .kind == "flagged")]|length' "$w/cand/work/updates-400.json")" \
  = 4 ] \
  && { echo "ok: candidates: flagged updates reach the act step as flagged, not major (4 codeql members)";
    pass=$((pass+1)); } || { echo "FAIL: candidates: flagged updates changed on the way to the act step";
    fail=$((fail+1)); }
ONLY=99 cand "99 none," 0 "pr=99 selects the plain major"
[ "$(jq -r '[.[]|select(.major and (.flagged|not) and .kind == "major")]|length' "$w/cand/work/updates-99.json")" = \
  1 ] \
  && { echo "ok: candidates: a plain major is left as it was (major, not flagged)"; pass=$((pass+1)); } || { echo "FAIL: candidates: plain major changed"; fail=$((fail+1)); }
PRSFILE="$w/prs-all.json" ONLY=90 cand "90 none," 0 "pr=90: its updates are handed on"
[ "$(jq -c '[.[]|[.name, .major, .flagged, .kind]]' "$w/cand/work/updates-90.json")" = \
  '[["actions/setup-java",false,false,"not-major"]]' ] \
  && { echo \
    "ok: candidates: a plain patch reaches the act step as what it is (not major, not flagged, kind not-major)";
    pass=$((pass+1)); } \
  || { echo "FAIL: candidates: plain patch not handed to the act step"; cat "$w/cand/work/updates-90.json";
    fail=$((fail+1)); }

# REQ-DEP-003-AC1: the patch/minor lane's arm on a plain patch stays on through the review (nothing is slower than
# before the reviewer read
# patch and minor bumps) and is remembered, so the settle step can put it back; a major's or a flagged bump's arm
# without a verdict comes off.
PRSFILE="$w/prs-all.json" ARMED99=true cand "99 none,90 none,91 none," 0 \
  "an armed plain patch with no verdict is reviewed with its arm left on"
also "candidates: the lane's arm on the plain patch is not turned off; the majors' arms are" "-disable-auto 90" \
  "+pr merge --disable-auto 99" "+pr merge --disable-auto 91"
[ "$(cat "$w/cand/work/lane-arms.txt")" = "90 sha90" ] && {
  echo "ok: candidates: the lane's arm is remembered for the settle step (lane-arms.txt), and only that one";
  pass=$((pass+1)); } \
  || { echo "FAIL: candidates: lane-arms.txt"; cat "$w/cand/work/lane-arms.txt"; fail=$((fail+1)); }
PRSFILE="$w/prs-all.json" ARMED90=true PRIOR90=neutral cand "99 none,90 neutral,91 none," 0 \
  "an armed plain patch whose last review did not finish (neutral) keeps the lane's arm too"
also "candidates: no disarm of the neutral plain patch" "-disable-auto"
PRSFILE="$w/prs-all.json" cand "99 none,90 none,91 none," 0 "a plain patch that is not armed: nothing to remember"
[ ! -s "$w/cand/work/lane-arms.txt" ] && { echo "ok: candidates: lane-arms.txt is empty when the lane armed nothing";
  pass=$((pass+1)); } || { echo "FAIL: candidates: lane-arms.txt not empty"; fail=$((fail+1)); }

# REQ-DEP-003-AC3: a failure verdict never stays armed: every hourly run turns off an arm made since (the lane's, a
# person's)
PRSFILE="$w/prs-all.json" PRIOR90=failure ARMED90=true cand "99 none,91 none," 0 \
  "a failed plain patch that is armed again -> auto-merge turned off, not reviewed again"
also "candidates: the arm over the failure verdict was turned off, and never put back" "+pr merge --disable-auto 90" \
  "-pr merge --auto"
PRIOR99=failure ARMED99=true PRIOR91=success cand "" 0 \
  "a failed major that is armed again -> auto-merge turned off, not reviewed again"
also "candidates: the failed major's arm was turned off" "+pr merge --disable-auto 99"
PRSFILE="$w/prs-all.json" PRIOR90=failure cand "99 none,91 none," 0 \
  "a failed plain patch that is not armed -> nothing to do"
also "candidates: no disarm call for an unarmed failure" "-disable-auto"
PRSFILE="$w/prs-patch.json" PRIOR90=failure ARMED90=true DISARMFAIL=1 cand "" 1 \
  "a failed patch that is armed and cannot be disarmed -> the step fails (retried next hour)"

# REQ-DEP-001-AC11, the spend guard: a head with no verdict that is a merge commit over a head the readers passed,
# with byte for byte the same diff against main, gets the success published on it and no reader. Anything else is read.
carried() { also "candidates: $1" \
  "+check-runs -f name=dependabot-reviewer -f head_sha=$2 .*conclusion=success .*carried over from that head" \
  "+compare/main\.\.\.$3" "+compare/main\.\.\.$2"; }
PRSFILE="$w/prs-patch.json" PARENT=p1 PRIORP1=success cand "" 0 \
  "a patch head that only merges main into a passed head (same diff) is not a candidate"
carried "the success is published on the new head, naming the head it is carried from, after both diffs were read" \
  sha90 p1
grep -q "output\[summary\]=Not read again: this head's diff against main is byte for byte the diff of p1," "$w/gh.log" \
  && { echo "ok: candidates: the carried check says which head it is carried from"; pass=$((pass+1)); } || {
    echo "FAIL: candidates: carried summary"; fail=$((fail+1)); }
ONLY=99 PARENT=p1 PRIORP1=success cand "" 0 \
  "a major head that only merges main into a passed head is not a candidate either"
carried "the success is carried to the major's new head" sha99 p1
ONLY=99 PARENT=p1 PARENTP1=p0 PRIORP0=success cand "" 0 \
  "two merges of main since the passed head (the first has no verdict): carried from the passed one"
carried "the walk went back over the unjudged merge to the passed head" sha99 p0
ONLY=99 PARENT=p1 PRIORP1=success \
  EVENTS99='auto_merge_enabled fosterstack-automation\nauto_merge_disabled github-actions[bot]\n' cand "" 0 \
  "a carried major whose arm the lane turned off on the new head"
also "candidates: the carried success puts the lane-voided arm back for exactly that head, after the guard" \
  "+pr merge --auto --squash --match-head-commit sha99 99"
ONLY=99 PARENT=p1 PRIORP1=success DIFF_NEW="${DIFF_SAME}+one more line\n" cand "99 none," 0 \
  "the new head's diff against main differs from the passed head's -> read"
also "candidates: nothing is published for a head whose diff differs" "-check-runs -f" "+compare/main\.\.\.sha99"
ONLY=99 PARENT=p1 PRIORP1=failure cand "99 none," 0 \
  "the head under the merge carries a FAILURE -> read (a failure is never carried, and never passed over)"
also "candidates: no diff is compared and nothing published under a failure" "-compare/" "-check-runs -f"
ONLY=99 PARENT=p1 PRIORP1=neutral cand "99 none," 0 \
  "the head under the merge carries a neutral (an unfinished re-review) -> read"
also "candidates: nothing published under a neutral" "-compare/" "-check-runs -f"
ONLY=99 PARENT=p1 PRIORP1=failure PARENTP1=p0 PRIORP0=success cand "99 none," 0 \
  "an older success behind a newer failure is not reached -> read"
also "candidates: the walk stops at the first verdict" "-commits/p0" "-check-runs -f"
ONLY=99 cand "99 none," 0 "a head that is not a merge commit (Dependabot's own, a writer's commit) -> read"
also "candidates: no earlier head is looked up for a head with one parent" "-commits/p1" "-compare/"
ONLY=99 ONEPARENT=p1 PRIORP1=success cand "99 none," 0 \
  "an ordinary commit on top of a passed head (somebody pushed a commit) -> read, whatever its diff"
also "candidates: the head under an ordinary commit is not looked up, no diff compared, nothing published" \
  "-commits/p1" "-compare/" "-check-runs -f"
ONLY=99 PARENT=p1 ONEPARENTP1=p0 PRIORP0=success cand "99 none," 0 \
  "a merge over an unjudged ordinary commit over a passed head -> read (the walk goes back over merge commits only)"
also "candidates: the walk does not pass an ordinary commit" "-commits/p0" "-compare/" "-check-runs -f"
ONLY=99 PARENT=p1 cand "99 none," 0 "a merge over a head with no verdict that is not itself a merge -> read"
also "candidates: nothing to carry from" "-compare/" "-check-runs -f"
ONLY=99 PARENT=p1 PRIORP1=success FORCE=true cand "99 none," 0 \
  "force: a head with no verdict is read even over a passed head with the same diff"
also "candidates: a forced run does not look for a head to carry from" "-commits/sha99 " "-compare/"
ONLY=99 PARENT=p1 PRIORP1=success DIFFFAIL=1 cand "99 none," 0 "the passed head's diff cannot be read -> read"
ONLY=99 PARENT=p1 LOOKUPP1=fail cand "99 none," 0 "the earlier head's verdict cannot be read -> read"
ONLY=99 PARENT=p1 PRIORP1=success \
  DIFF_SAME='diff --git a/x.bin b/x.bin\nindex 1111111..2222222 100644\nBinary files a/x.bin and b/x.bin differ\n' \
  cand "99 none," 0 "the same diff text naming a binary file -> read (its bytes are not in a diff)"
ONLY=99 PARENT=p1 PRIORP1=success DIFF_SAME='' cand "99 none," 0 "an empty diff -> read"
ONLY=99 PARENT=p1 PRIORP1=success NEUTRALFAIL=1 cand "" 1 \
  "the carried success cannot be published -> not reviewed this hour, the step fails (retried next hour)"
ONLY=99 PRIOR99=neutral PARENT=p1 PRIORP1=success cand "99 neutral," 0 \
  "a head whose own latest check is neutral is read, never carried"
also "candidates: no walk from a neutral head" "-commits/sha99 " "-compare/"

# The lane turned an arm off just as the reviewer approved the head (the reviewer arms, then publishes): a success verdict on the
# head, no arm, and the LAST auto-merge event being a disable by github-actions (the workflow token) means put the arm back, after
# the required-check guard; a person's disarm, an earlier lane disarm followed by a later enable, or no event at all stays.
LANE_OFF='auto_merge_enabled fosterstack-automation\nauto_merge_disabled github-actions[bot]\n'
heal() { # <events> <rc> <expect-rearm yes|no> <name>   (PRIOR99=success; ARMED99, RULES, REARMFAIL, EVENTSFAIL from the environment)
  PRIOR99=success EVENTS99="$1" cand "91 none," "$2" "$4"
  if grep -q "pr merge --auto --squash --match-head-commit sha99 99" "$w/gh.log"; then got=yes; else got=no; fi
  [ "$got" = "$3" ] && { echo "ok: candidates: $4 (re-arm: $got)"; pass=$((pass+1)); } || { echo "FAIL: candidates: $4 (re-arm: $got, want $3)"; fail=$((fail+1)); }
}
heal "$LANE_OFF" 0 yes "success + not armed + last event = disable by github-actions[bot] -> the arm is put back for exactly that head"
heal 'auto_merge_enabled fosterstack-automation\nauto_merge_disabled someone\n' 0 no "last event = a person's disable -> left alone"
heal 'auto_merge_disabled github-actions[bot]\nauto_merge_enabled fosterstack-automation\nauto_merge_disabled someone\n' 0 no "an earlier lane disable, then a normal arm, then a person's disable -> left alone (round-4 B3)"
heal 'auto_merge_disabled github-actions[bot]\nauto_merge_enabled fosterstack-automation\n' 0 no "an earlier lane disable followed by an enable (the PR is simply not armed in the stub) -> left alone"
heal '' 0 no "no auto-merge event at all -> left alone"
heal 'auto_merge_enabled fosterstack-automation\nauto_merge_disabled github-actions-maintainer\n' 0 no "a login that only STARTS with github-actions (a person or app) is not the workflow token (round 5)"
heal 'auto_merge_enabled fosterstack-automation\nauto_merge_disabled github-actions[bot]x\n' 0 no "github-actions[bot] followed by anything else is not the workflow token"
heal 'auto_merge_enabled fosterstack-automation\nauto_merge_disabled github-actions\n' 0 yes "the bare login github-actions is accepted too (the API names the bot either way)"
ARMED99=true heal "$LANE_OFF" 0 no "already armed -> nothing to do"
RULES="$w/rules-drift.json" heal "$LANE_OFF" 1 no "the required-check guard refuses -> no arm, the step fails (the approved arm stays off, retried next hour)"
REARMFAIL=1 heal "$LANE_OFF" 1 yes "the re-arm cannot be made -> the step fails (retry next hour)"
EVENTSFAIL=1 heal "$LANE_OFF" 1 no "the events cannot be read -> skipped, the step fails"
PRIOR99=failure EVENTS99="$LANE_OFF" cand "91 none," 0 "a FAILURE verdict is never re-armed"
grep -q "pr merge --auto" "$w/gh.log" && { echo "FAIL: candidates: a failure verdict was armed"; fail=$((fail+1)); } || { echo "ok: candidates: no arm for a failure verdict"; pass=$((pass+1)); }
# The step's own filter over events as GitHub records them (issues/N/events of this repository's bumps, Nov 2026):
# turning squash auto-merge ON is recorded as auto_squash_enabled, turning it off as auto_merge_disabled.
# The LAST of them decides.
ev() { jq -cn --argjson e "$1" \
  '[$e[] | {event: .[0], actor: {login: .[1]}}] + [{event: "labeled", actor: {login: "dependabot[bot]"}}]'; }
EVENTS99_JSON=$(ev \
  '[["auto_squash_enabled","fosterstack-automation[bot]"],["auto_merge_disabled","github-actions[bot]"]]') \
  heal "" 0 yes \
  "real event names: squash enabled by the App, then disabled by github-actions[bot] -> the arm is put back"
EVENTS99_JSON=$(ev \
  '[["auto_merge_disabled","github-actions[bot]"],["auto_squash_enabled","fosterstack-automation[bot]"]]') \
  heal "" 0 no \
  "real event names: a squash ENABLE after the lane's disable is the last event -> left alone"
EVENTS99_JSON=$(ev \
  '[["auto_squash_enabled","github-actions[bot]"],["auto_merge_disabled","github-actions[bot]"],
   ["auto_rebase_enabled","someone"]]') heal "" 0 no \
  "real event names: a later enable by another merge method is the last event -> left alone"
EVENTS99_JSON=$(ev '[["auto_squash_enabled","fosterstack-automation[bot]"],["auto_merge_disabled","someone"]]') heal \
  "" 0 no \
  "real event names: a person's disable is the last event -> left alone"

# ============================================================================ settle step
# REQ-DEP-001-AC12: after the act step (and the cancellation cleanup), for every head taken up for review: none is
# armed over a failure verdict. A plain patch the lane had armed, whose review did not finish, is armed again for that
# exact head after the guard.
# settle <candidates lines> <lane-arms lines> <rc> <name>
# env: PRIOR99 PRIOR90 ARMED99 ARMED90 RULES REARMFAIL DISARMFAIL LOOKUP90
settle() {
  local W="$w/settle"; rm -rf "$W"; mkdir -p "$W/work"; : > "$w/gh.log"
  printf '%b' "$1" > "$W/work/candidates.txt"; printf '%b' "$2" > "$W/work/lane-arms.txt"
  (cd "${SETTLEDIR:-$repo}" &&
    env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" GITHUB_REPOSITORY=o/r RUNNER_TEMP="$W" \
    REPO_CHECKS="$repo/.github/policy/required-checks.json" \
     GUARD_RULES_JSON="${RULES:-$w/rules-match.json}" APP_TOKEN=a APP_SLUG=fosterstack-automation MERGE_TOKEN=m \
       GH_TOKEN=job \
     bash --noprofile --norc -e -o pipefail "$w/settle.sh") > "$w/settle.out" 2>&1; local rc=$?
  SETTLE_RC="$rc"
  if [ "$3" = any ] || [ "$rc" = "$3" ]; then
    # rc any: no answer is wrong here, the caller's own check follows, and only that one counts
    [ "$3" = any ] || { echo "ok: settle: $4"; pass=$((pass+1)); }
  else
    echo "FAIL: settle: $4 (rc $rc)"; sed 's/^/    /' "$w/settle.out" | tail -6; fail=$((fail+1))
  fi
}
BOTH='99 sha99 none\n90 sha90 none\n'
PRIOR90=failure ARMED90=true ARMED99=false settle "$BOTH" '90 sha90\n' 0 \
  "a patch that now carries the failure verdict and is armed (the lane armed it meanwhile)"
also "settle: auto-merge is turned off over the failure verdict, and nothing is armed" "+pr merge --disable-auto 90" \
  "-pr merge --auto" "-disable-auto 99"
PRIOR99=failure ARMED99=true ARMED90=false PRIOR90=success settle "$BOTH" '' 0 \
  "a major that now carries the failure verdict and is armed"
also "settle: the failed major's arm is turned off too" "+pr merge --disable-auto 99" "-pr merge --auto"
PRIOR90=failure settle "$BOTH" '90 sha90\n' 0 "a failure verdict that is not armed"
also "settle: nothing to turn off, nothing armed" "-pr merge"
settle "$BOTH" '90 sha90\n' 0 \
  "a lane-armed patch whose review did not finish (no verdict) and that the act step disarmed"
also "settle: the lane's arm is put back for exactly that head, after the required-check guard; the major stays off" \
  "+pr merge --auto --squash --match-head-commit sha90 90" "+required-checks.json\?ref=main" "-match-head-commit sha99"
PRIOR90=neutral settle "$BOTH" '90 sha90\n' 0 "a lane-armed patch left neutral by an unfinished review"
also "settle: the lane's arm is put back over a neutral too" "+pr merge --auto --squash --match-head-commit sha90 90"
settle "$BOTH" '' 0 "an unfinished patch the lane had NOT armed (not in lane-arms.txt)"
also "settle: an arm that was not there before the review is not made" "-pr merge"
ARMED90=true settle "$BOTH" '90 sha90\n' 0 "a lane-armed patch that is still armed"
also "settle: nothing to do for an arm that is still on" "-pr merge"
PRIOR90=success settle "$BOTH" '90 sha90\n' 0 "a lane-armed patch that passed"
also "settle: a success verdict is left as the act step left it" "-pr merge"
RULES="$w/rules-drift.json" settle "$BOTH" '90 sha90\n' 1 \
  "the required-check guard refuses -> the lane's arm stays off and the step fails"
also "settle: nothing is armed past a refusing guard" "-pr merge --auto"
REARMFAIL=1 settle "$BOTH" '90 sha90\n' 1 "the lane's arm cannot be put back -> the step fails"
PRIOR90=failure ARMED90=true DISARMFAIL=1 settle "$BOTH" '90 sha90\n' 1 \
  "an arm over a failure verdict cannot be turned off -> the step fails"
LOOKUP90=fail settle "$BOTH" '90 sha90\n' 1 "a head's verdict cannot be read -> the step fails, nothing is armed blind"
also "settle: no arm without a read verdict" "-pr merge --auto"
ARMED90=closed settle "$BOTH" '90 sha90\n' 0 "the PR is no longer open (merged or closed during the run)"
also "settle: nothing is done to a PR that is not open (1)" "-pr merge"
MOVED=90 settle "$BOTH" '90 sha90\n' 0 \
  "the PR's head is no longer the commit this run took up (lane-armed, unfinished, unarmed)"
also "settle: no arm for a commit that is not the head any more" "-pr merge"
MOVED=90 PRIOR90=failure ARMED90=true settle "$BOTH" '90 sha90\n' 0 \
  "the failure verdict is on a commit that is not the head any more"
also "settle: nothing is done to a PR that is not open" "-pr merge"
# REQ-DEP-001-AC12, AC14: the verdict is read as everywhere else: a success counts only with the current version, a
# failure or neutral whatever its external_id
REARM90="+pr merge --auto --squash --match-head-commit sha90 90"
PRIOR90_JSON=$(verdicts "[$OLD_OK]") settle "$BOTH" '90 sha90\n' 0 \
  "a lane-armed patch whose review did not finish, its newest check a success of another version"
also "settle: a success of another version is no verdict: the lane's arm is put back, after the guard" "$REARM90" \
  "+required-checks.json\?ref=main"
PRIOR90_JSON=$(verdicts '[["success"]]') settle "$BOTH" '90 sha90\n' 0 \
  "a lane-armed patch whose review did not finish, its newest check an unversioned success"
also "settle: an unversioned success is no verdict: the lane's arm is put back" "$REARM90"
PRIOR90_JSON=$(verdicts "[$CUR_OK,$OLD_OK]") settle "$BOTH" '90 sha90\n' 0 \
  "a success of another version finishing after the current one (the newest by id)"
also "settle: the newest success is of another version: the lane's arm is put back" "$REARM90"
PRIOR90_JSON=$(verdicts "[$OLD_OK,$CUR_OK]") settle "$BOTH" '90 sha90\n' 0 \
  "a success of the current version after one of another version"
also "settle: a success of the current version is left as the act step left it" "-pr merge"
PRIOR90_JSON=$(verdicts "[$OLD_OK]") ARMED90=true settle "$BOTH" '90 sha90\n' 0 \
  "a success of another version on an armed lane patch"
also "settle: an armed bump is never disarmed by a success of another version" "-pr merge"
PRIOR90_JSON=$(verdicts "[[\"failure\",\"$OLDVER\"]]") ARMED90=true settle "$BOTH" '90 sha90\n' 0 \
  "a failure of another version over an arm"
also "settle: a failure counts whatever its external_id: the arm is turned off" "+pr merge --disable-auto 90"
PRIOR90_JSON=$(verdicts "[[\"neutral\",\"$OLDVER\"]]") settle "$BOTH" '90 sha90\n' 0 \
  "a neutral check of another version on a lane-armed patch"
also "settle: a neutral counts whatever its external_id: the lane's arm is put back" "$REARM90"
PRIOR90_JSON=$(verdicts "[[\"success\",\"$PYVER\"]]") settle "$BOTH" '90 sha90\n' 0 \
  "a success carrying the sha256 of the program alone"
PRIOR90_JSON=$(verdicts "[[\"success\",\"$OLD3\"]]") settle "$BOTH" '90 sha90\n' 0 \
  "a success carrying the version of the three files joined"
PRIOR90_JSON=$(verdicts "[[\"success\",\"$OLD3S\"]]") settle "$BOTH" '90 sha90\n' 0 \
  "a success carrying the version of the three files' sha256sum lines"
also "settle: it is no verdict: the lane's arm is put back" "$REARM90"
# a cut answer is no verdict: a lane-armed patch is not left as "passed" on 30 of 31 runs; the step fails or re-arms
for what in "[\"success\",\"$VER\"]" "[\"success\",\"$OLDVER\"]" '["success"]'; do
  PRIOR90_JSON=$(verdicts_cut "$what") settle "$BOTH" '90 sha90\n' any "30 of 31 runs read, the newest $what"
  if [ "$SETTLE_RC" = 0 ] && ! grep -q "pr merge --auto" "$w/gh.log"; then
    echo "FAIL: settle: 30 of 31 runs read, the newest $what: left as a success (rc 0, nothing armed)"; fail=$((fail+1))
  else echo "ok: settle: 30 of 31 runs read, the newest $what: not taken for a success"; pass=$((pass+1)); fi
done
asks_all_runs "settle: the check runs are asked with filter=all, 100 at a time"
for what in prompt-changed workflow-changed checks-changed guard-changed; do
  mkalt "$w/alt" "$what"
  SETTLEDIR="$w/alt" PRIOR90_JSON=$(verdicts "[$CUR_OK]") settle "$BOTH" '90 sha90\n' 0 \
    "with the $what a success of the version of the old text"
  also "settle: it is no verdict: the lane's arm is put back" "$REARM90"
  SETTLEDIR="$w/alt" PRIOR90_JSON=$(verdicts "[[\"success\",\"$(ver3 "$w/alt")\"]]") settle "$BOTH" '90 sha90\n' 0 \
    "with the $what a success of the version of the five files as they are"
  also "settle: it is a success: left as the act step left it" "-pr merge"
done
for what in no-prompt no-workflow no-checks no-guard; do
  mkalt "$w/alt" "$what"
  SETTLEDIR="$w/alt" settle "$BOTH" '90 sha90\n' 1 \
    "a missing file ($what): the version cannot be computed -> the step fails"
  also "settle: $what: nothing is armed or disarmed blind" "-pr merge"
done

# the verdict reader is in the reviewer workflow three times (the candidates step, the cancellation cleanup and the
# settle step): their jq filters are one text once whitespace is collapsed, so they cannot drift apart
same_filters=$(python3 - "$repo/.github/workflows/dependabot-reviewer.yml" <<'PY'
import re, sys, yaml
steps = yaml.safe_load(open(sys.argv[1]))["jobs"]["review"]["steps"]
code = "\n".join(s.get("run") or "" for s in steps)
read = r'gh api "\$run_url&filter=all&per_page=100" \\\n\s*--jq "((?:[^"\\]|\\.)*)"'
# the pattern takes this reader and refuses the same one without filter=all
assert re.findall(read, 'gh api "$run_url&filter=all&per_page=100" \\\n  --jq ".x"') == [".x"]
assert not re.findall(read, 'gh api "$run_url&per_page=100" \\\n  --jq ".x"')
filters = {" ".join(f.split()) for f in re.findall(read, code)}
count = len(re.findall(read, code))
print("ok" if count == 3 and len(filters) == 1 else "%d readers, %d different filters" % (count, len(filters)))
PY
)
if [ "$same_filters" = ok ]; then echo "ok: the three verdict readers have one jq filter"; pass=$((pass+1))
else echo "FAIL: the three verdict readers have one jq filter ($same_filters)"; fail=$((fail+1)); fi

# ============================================================================ streak step
streak() { # history rc-expect want-issue name
  : > "$w/gh.log"
  (cd "$repo" && env PATH="$w/bin:$PATH" GH_LOG="$w/gh.log" HISTORY="$1" RUNLIST="${RUNLIST:-}" GITHUB_RUN_ID=500 \
     RUNNER_TEMP="$w" RUN_URL=https://example.invalid/run bash --noprofile --norc -e -o pipefail "$w/streak.sh") > "$w/streak.out" 2>&1; local rc=$?
  local issued=no; grep -q "^gh issue create" "$w/gh.log" && issued=yes
  if [ "$rc" = 0 ] && [ "$issued" = "$2" ]; then echo "ok: streak: $3"; pass=$((pass+1))
  else echo "FAIL: streak: $3 (rc $rc, issued $issued)"; sed 's/^/    /' "$w/streak.out"; fail=$((fail+1)); fi
}
streak '[{"databaseId":500,"conclusion":"failure"},{"databaseId":499,"conclusion":"failure"},{"databaseId":498,"conclusion":"failure"}]' yes "third failure in a row opens the issue"
streak '[{"databaseId":499,"conclusion":"failure"},{"databaseId":498,"conclusion":"success"}]' no "a success in between resets it"
streak '[{"databaseId":499,"conclusion":"failure"}]' no "only two runs so far: no issue"
RUNLIST=fail streak '[]' no "history unreadable: nothing decided, step does not fail"

echo "----"
echo "dependabot-reviewer act step: ${pass} passed, ${fail} failed"
[ "$py_rc" -eq 0 ] && [ "$fail" -eq 0 ]
