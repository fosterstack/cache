#!/usr/bin/env bash
# proves: REQ-DEP-001-AC2
# The Dependabot reviewer's gather step (register row 75 (b)), run offline: `cmd_gather` with its one external
# seam (`_run`: the gh and git calls) standing in, so the test reads the bundle the readers actually receive.
# It must carry the PR diff, the upstream release notes for EVERY version after the old one up to the new one
# (none outside), and every line of ours that names the dependency with its whole workflow step; no model is
# involved; a diff that cannot be fetched means no bundle at all.
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
def fake_run(cmd, cap=None):
    calls.append(cmd)
    if cmd[:3] == ["gh", "pr", "diff"]:
        return ("" if os.environ.get("NODIFF") else "-uses: actions/checkout@aaaa # v4.2.2\n+uses: actions/checkout@bbbb # v7.0.1\n"), (1 if os.environ.get("NODIFF") else 0)
    if cmd[:2] == ["gh", "api"]:
        return json.dumps(releases if "page=1" in cmd[2] else []), 0
    if cmd[:2] == ["git", "grep"]:
        return ".github/workflows/w.yml:5:        uses: actions/checkout@0000000000000000000000000000000000000000 # v4.2.2\n", 0
    raise AssertionError("unexpected command: %r" % (cmd,))
r._run = fake_run
json.dump([{"name": "actions/checkout", "from": "4.2.2", "to": "7.0.1", "major": True}], open("updates.json", "w"))
class A: pr = 99; updates = "updates.json"; out = "out"
fails = []
def check(ok, what):
    print(("PASS " if ok else "FAIL ") + what); ok or fails.append(what)
with contextlib.redirect_stdout(io.StringIO()):
    r.cmd_gather(A)
b = open("out/bundle.md").read()
check("+uses: actions/checkout@bbbb # v7.0.1" in b, "the PR diff is in the bundle")
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
os.environ["NODIFF"] = "1"
try:
    with contextlib.redirect_stderr(io.StringIO()):
        class B(A): out = "out2"
        r.cmd_gather(B); code = 0
except SystemExit as e:
    code = e.code
check(code == 3 and not os.path.exists("out2/bundle.md"), "no diff -> exit 3 and no bundle (no review)")
print("dependabot-reviewer gather: %d failed" % len(fails))
sys.exit(1 if fails else 0)
PY
