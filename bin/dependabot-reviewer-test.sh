#!/usr/bin/env bash
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
r._gh_json = lambda args: None
text, n = r.release_notes("actions/checkout", "4", "7")
check("release_notes: none found is said, count 0", n == 0 and "no upstream release notes found" in text, (n, text))
text, n = r.release_notes("golang", "`3f3c01a`", "`9e8d7c6`")
check("release_notes: non-GitHub dependency is said, count 0", n == 0 and "not a GitHub-hosted" in text, (n, text))

# --- normalize_findings: errors, never a pass
f, e = r.normalize_findings({"findings": [{"severity": "critical", "title": "x"}]})
check("unknown severity is an error", f is None and "unknown severity" in e, (f, e))
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
f, e = r.normalize_findings(r._extract_json('Here you go:\n```json\n{"findings": []}\n```'))
check("empty list inside prose/code fence = read, nothing found", e is None and f == [], (f, e))

# --- mask: no model id or configured identifier reaches a finding
os.environ["AUDITOR_MODEL_PRIMARY"] = "some-private-model-7"
f, e = r.normalize_findings({"findings": [{"severity": "check", "title": "as claude-opus-9-9 I think",
                                           "why": "some-private-model-7 says so; Bearer abcdefghij"}]})
check("mask: model ids and bearer tokens redacted in findings",
      e is None and "claude-" not in json.dumps(f) and "some-private-model-7" not in json.dumps(f)
      and "abcdefghij" not in json.dumps(f) and "<model-id>" in f[0]["title"], f)

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
d = r.decide([brk, err])
check("decide: breaks-us + an error -> error (no check, retry)", d["decision"] == "error", d)
d = r.decide([clean("A")] + [{"reader": "B", "findings": None, "error": None}])
check("decide: a reader with no findings and no error -> error", d["decision"] == "error", d)
check("decide: no readers -> error", r.decide([])["decision"] == "error")

print("----")
print("dependabot-reviewer: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
