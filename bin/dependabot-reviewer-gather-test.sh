#!/usr/bin/env bash
# proves: REQ-DEP-001-AC2
# (and, owner Oct 1: a failed read of release notes or usage is labeled "unavailable" and is an error,
# never "none found"; a genuine absence is still said plainly)
# The Dependabot reviewer's gather step (register row 75 (b)), run offline: `cmd_gather` with its one external
# seam (`_run`: the gh and git calls) standing in, so the test reads the bundle the readers actually receive.
# It must carry the PR's commits (each one not Dependabot's own marked so), the whole diff of the exact head commit, the upstream release
# notes for EVERY version after the old one up to the new one (none outside), and every line of ours that names the
# dependency with its whole workflow step, for a patch as for a major; no model is involved; a diff that cannot be
# fetched means no bundle at all, and a commit list that cannot be read is an error like any other failed read.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir -p .github/workflows
cat > .github/workflows/w.yml <<'Y'
jobs:
  j:
    steps:
      - name: fetch
        uses: actions/checkout@0000000000000000000000000000000000000000 # v4.2.2
        with:
          fetch-depth: 0
      - run: true
Y
python3 - "$here/dependabot-reviewer.py" <<'PY'
import importlib.util, io, json, os, sys, contextlib
spec = importlib.util.spec_from_file_location("reviewer", sys.argv[1]); r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
calls = []
releases = [{"tag_name": t, "name": t, "body": "notes of " + t} for t in
            ("v8.0.0", "v7.0.1", "v7.0.0", "v6.2.0", "v6.0.0", "v5.0.0", "v4.3.1", "v4.2.2", "v4.0.0")]
def commit(sha, login, uid, typ, committer, msg, parents=1):
    return {"sha": sha * 40, "parents": [{}] * parents, "author": {"login": login, "id": uid, "type": typ}, "committer": {"login": committer},
            "commit": {"message": msg, "verification": {"verified": True}}}
commits = [commit("a", "dependabot[bot]", 49699333, "Bot", "web-flow", "Bump actions/checkout from 4.2.2 to 7.0.1"),
           commit("b", "some-writer", 7, "User", "some-writer", "Drop the input v7 removed"),
           commit("c", "lane[bot]", 9, "Bot", "web-flow", "Merge branch 'main' into dependabot/x", parents=2)]
HEAD = "c" * 40   # the commit the verdict is for: the last one of the pull request
def fake_run(cmd):
    calls.append(cmd)
    if cmd[:3] == ["gh", "api", "-H"]:
        assert cmd[3:] == ["Accept: application/vnd.github.diff", "repos/{owner}/{repo}/compare/main..." + HEAD], cmd
        if os.environ.get("BINARY"):
            return "diff --git a/logo.png b/logo.png\nindex 1..2 100644\nBinary files a/logo.png and b/logo.png differ\n", 0
        return ("" if os.environ.get("NODIFF") else "-uses: actions/checkout@aaaa # v4.2.2\n+uses: actions/checkout@bbbb # v7.0.1\n"), (1 if os.environ.get("NODIFF") else 0)
    if cmd[:2] == ["gh", "api"] and "/pulls/99/commits?" in cmd[2]:
        return ("", 1) if os.environ.get("COMMITS") == "fail" else (json.dumps(commits if "page=1" in cmd[2] else []), 0)
    if cmd[:2] == ["gh", "api"]:
        if os.environ.get("NOTES") == "fail":
            return "", 1
        if os.environ.get("NOTES") == "none":
            return "[]", 0
        return json.dumps(releases if "page=1" in cmd[2] else []), 0
    if cmd[:2] == ["git", "grep"]:
        if os.environ.get("USAGE") == "fail":
            return "", 2
        if os.environ.get("USAGE") == "none":
            return "", 1
        if os.environ.get("USAGE") == "vanished":
            return ".github/workflows/gone.yml:5:        uses: actions/checkout@x\n", 0
        return ".github/workflows/w.yml:5:        uses: actions/checkout@0000000000000000000000000000000000000000 # v4.2.2\n", 0
    raise AssertionError("unexpected command: %r" % (cmd,))
r._run = fake_run
json.dump([{"name": "actions/checkout", "from": "4.2.2", "to": "7.0.1", "major": True}], open("updates.json", "w"))
os.environ.pop("GITHUB_REPOSITORY", None)
class A: pr = 99; sha = HEAD; base = "main"; updates = "updates.json"; out = "out"
fails = []
def check(ok, what):
    print(("PASS " if ok else "FAIL ") + what); ok or fails.append(what)
with contextlib.redirect_stdout(io.StringIO()):
    r.cmd_gather(A)
b = open("out/bundle.md").read()
check("+uses: actions/checkout@bbbb # v7.0.1" in b, "the PR diff is in the bundle")
check("- aaaaaaaaaa dependabot[bot]: Bump actions/checkout from 4.2.2 to 7.0.1\n" in b, "Dependabot's own commit is listed, unmarked")
check("- bbbbbbbbbb NOT Dependabot's — some-writer: Drop the input v7 removed\n" in b, "a commit somebody else pushed onto the PR is listed and marked NOT Dependabot's")
check("- cccccccccc NOT Dependabot's — lane[bot] (a merge commit): Merge branch 'main' into dependabot/x\n" in b, "a merge of main is listed and marked too")
check(b.index("## Commits in this PR") < b.index("## The PR diff (the whole pull request, every commit above: %s against main)" % HEAD) < b.index("## Upstream release notes"),
      "the commits come before the diff, which is said to be the whole pull request")
for t in ("v4.3.1", "v5.0.0", "v6.0.0", "v6.2.0", "v7.0.0", "v7.0.1"):
    check("notes of " + t in b, "release notes of %s (between 4.2.2 and 7.0.1) are in the bundle" % t)
for t in ("v4.0.0", "v4.2.2", "v8.0.0"):
    check("notes of " + t not in b, "release notes of %s (outside the range) are not" % t)
check(b.index("notes of v4.3.1") < b.index("notes of v5.0.0") < b.index("notes of v7.0.1"), "release notes are oldest first")
check("uses: actions/checkout@0000000000000000000000000000000000000000 # v4.2.2" in b.split("Every line of ours that uses actions/checkout", 1)[-1],
      "the usage line itself is in the bundle, under our-usage")
check("Every line of ours that uses actions/checkout" in b and "fetch-depth: 0" in b and "name: fetch" in b,
      "our usage line is in the bundle with its whole step (inputs included)")
check(all(c[0] in ("gh", "git") for c in calls), "only gh and git were called: no model is involved in gathering")
check(["gh", "api", "-H", "Accept: application/vnd.github.diff", "repos/{owner}/{repo}/compare/main..." + HEAD] in calls and not any(c[:3] == ["gh", "pr", "diff"] for c in calls),
      "the diff read is the diff of the exact head commit against main (compare/main...<commit id>), not the pull request's diff of the moment")
check(b.startswith("# Bundle for Dependabot PR #99 at its head " + HEAD), "the bundle names the commit it is for")
os.environ["NODIFF"] = "1"
try:
    with contextlib.redirect_stderr(io.StringIO()):
        class B(A): out = "out2"
        r.cmd_gather(B); code = 0
except SystemExit as e:
    code = e.code
check(code == 3 and not os.path.exists("out2/bundle.md"), "no diff -> exit 3 and no bundle (no review)")
del os.environ["NODIFF"]
os.environ["BINARY"] = "1"
try:
    with contextlib.redirect_stderr(io.StringIO()):
        class C(A): out = "out2b"
        r.cmd_gather(C); code = 0
except SystemExit as e:
    code = e.code
check(code == 3 and not os.path.exists("out2b/bundle.md"), "a diff that names a changed binary file -> exit 3 and no bundle (its bytes cannot be given to the readers)")
del os.environ["BINARY"]
def gather_to(out):
    class G(A): pass
    G.out = out
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            r.cmd_gather(G)
        return 0, open(out + "/bundle.md").read()
    except SystemExit as e:
        return e.code, (open(out + "/bundle.md").read() if os.path.exists(out + "/bundle.md") else "")
os.environ["NOTES"] = "fail"
code, b = gather_to("out3")
check(code not in (0, None) and "release notes UNAVAILABLE" in b and "no upstream release notes found" not in b,
      "a failed release-notes read is labeled unavailable and is an error, never 'none found'")
os.environ["NOTES"] = "none"
code, b = gather_to("out4")
check(code in (0, None) and "no upstream release notes found" in b, "a genuine absence of release notes is still said plainly (no error)")
del os.environ["NOTES"]
os.environ["USAGE"] = "fail"
code, b = gather_to("out5")
check(code not in (0, None) and "usage UNAVAILABLE" in b and "no line in this repository names" not in b,
      "a failed usage search is labeled unavailable and is an error, never 'none found'")
os.environ["USAGE"] = "none"
code, b = gather_to("out6")
check(code in (0, None) and "no line in this repository names" in b, "a genuine absence of usage is still said plainly (no error)")
os.environ["USAGE"] = "vanished"
code, b = gather_to("out7")
check(code not in (0, None) and "usage UNAVAILABLE" in b, "a usage hit whose file cannot be read is unavailable and an error (round 1 R1)")
del os.environ["USAGE"]
os.environ["COMMITS"] = "fail"
code, b = gather_to("out8")
check(code not in (0, None) and "commit list UNAVAILABLE" in b, "a commit list that cannot be read is labeled unavailable and is an error, never 'no other commits'")
del os.environ["COMMITS"]
class M(A): sha = "b" * 40; out = "out10"
try:
    with contextlib.redirect_stderr(io.StringIO()):
        r.cmd_gather(M); code = 0
except SystemExit as e:
    code = e.code
check(code == 5 and not os.path.exists("out10/bundle.md"), "a commit that is not the pull request's last commit (the head moved) -> exit 5 and no bundle")
# a plain patch gets the same bundle as a major: its notes, our usage, the commits, the diff
json.dump([{"name": "actions/checkout", "from": "4.2.2", "to": "4.3.1", "major": True, "flagged": False, "kind": "not-major"}], open("updates.json", "w"))
code, b = gather_to("out9")
check(code in (0, None) and "- actions/checkout: 4.2.2 -> 4.3.1 (not major)" in b, "a plain patch is gathered and the bundle calls it not major")
check("notes of v4.3.1" in b and "notes of v5.0.0" not in b, "a patch's release notes (4.2.2 to 4.3.1, none outside) are in the bundle")
check("fetch-depth: 0" in b and "NOT Dependabot's — some-writer" in b and "+uses: actions/checkout@bbbb # v7.0.1" in b, "a patch's bundle has our usage, the commits and the diff too")
print("dependabot-reviewer gather: %d failed" % len(fails))
sys.exit(1 if fails else 0)
PY
