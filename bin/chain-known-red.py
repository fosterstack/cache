#!/usr/bin/env python3
"""The known-red list of the release chain's integration branch (test-evidence/known-red.json).

On chain-v030 a few cases of the chain suites are red on purpose until a later PR or a cache item lands (the old chain jobs of PRs 3 and 4, the cache lane's
build scripts P4/P5). They are listed here by case and reason, so a red CI run means exactly "the list and the red cases differ", never "red is normal".

  judge --suite SUITE [--list FILE]        stdin is the suite's output: exit 0 only when the set of FAIL cases is EXACTLY the list's entries for SUITE
                                           (a red case that is not listed fails; a listed case that passes fails, naming it: remove the entry in the PR that fixes it)
  base-check [--list FILE] [--base REF] [--event FILE]
                                           an entry added or changed since the merge base (compared in full: suite, case, reason, green_by) fails unless the PR body names it with a line `known-red-add: <id>`
                                           (the body is read from the GitHub event file, GITHUB_EVENT_PATH; --event overrides;
                                           locally, with no event file, the environment variable KNOWN_RED_ADD='id id ...' names them; a push event is not compared)
  empty [--list FILE]                      exit 1 while the list has entries (the cutover condition)

An entry is {id, suite, case, reason, green_by}. `case` is the text after `FAIL ` up to ` -> ` or `: ` of the suite's FAIL line (a prefix match: the line must
start with FAIL and the case, followed by the end, ` -> ` or `: `).
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIST = os.path.join(HERE, "..", "test-evidence", "known-red.json")
KEYS = {"id", "suite", "case", "reason", "green_by"}


def fail(msg):
    print("known-red: " + msg)
    sys.exit(1)


def pairs_hook(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def load(path):
    try:
        with open(path) as f:
            doc = json.load(f, object_pairs_hook=pairs_hook)
    except (OSError, ValueError) as ex:
        fail("%s is not a readable JSON file (%s)" % (path, ex))
    ents = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(ents, list):
        fail("%s has no `entries` list" % path)
    seen = set()
    for e in ents:
        if not isinstance(e, dict) or set(e) != KEYS or not all(isinstance(e[k], str) and e[k].strip() for k in KEYS):
            fail("an entry must be an object of exactly %s, each a non-empty string: %r" % (sorted(KEYS), e))
        if e["id"] in seen:
            fail("entry id %s is listed twice" % e["id"])
        seen.add(e["id"])
    return ents


def fail_lines(text):
    return [l[5:] for l in text.splitlines() if l.startswith("FAIL ")]


def matches(line, case):
    return line == case or line.startswith(case + " -> ") or line.startswith(case + ": ") or line.startswith(case + " (")


def cmd_judge(args):
    suite = args[args.index("--suite") + 1]
    path = args[args.index("--list") + 1] if "--list" in args else DEFAULT_LIST
    ents = [e for e in load(path) if e["suite"] == suite]
    text = sys.stdin.read()
    if not re.search(r"^pass=\d+ fail=\d+$", text, re.M):
        fail("the suite %s printed no `pass=N fail=M` summary: it did not finish" % suite)
    lines = fail_lines(text)
    problems = []
    used = {e["id"]: 0 for e in ents}
    for l in lines:
        hit = [e for e in ents if matches(l, e["case"])]
        if len(hit) != 1:
            problems.append("a red case that is not on the known-red list: %s" % l[:200])
        else:
            used[hit[0]["id"]] += 1
    for e in ents:
        if used[e["id"]] == 0:
            problems.append("a listed case now passes (remove entry %s from test-evidence/known-red.json): %s" % (e["id"], e["case"][:200]))
    if problems:
        print("\n".join("known-red: " + p for p in problems))
        sys.exit(1)
    print("known-red: %s: %d red case(s), exactly the %d listed (each turns green with its named item)" % (suite, len(lines), len(ents)))


def git(*a):
    return subprocess.run(["git"] + list(a), capture_output=True, text=True)


def cmd_base_check(args):
    path = args[args.index("--list") + 1] if "--list" in args else DEFAULT_LIST
    event = args[args.index("--event") + 1] if "--event" in args else os.environ.get("GITHUB_EVENT_PATH", "")
    base = args[args.index("--base") + 1] if "--base" in args else ""
    body = ""
    if event and os.path.isfile(event):
        try:
            with open(event) as f:
                ev = json.load(f)
            pr = ev.get("pull_request") or {}
            if not pr and "--base" not in args:
                print("known-red: not a pull request event; the list is compared with the merge base at pull request time only")
                return
            body = pr.get("body") or ""
            if not base:
                base = (pr.get("base") or {}).get("sha") or ev.get("before") or ""
        except ValueError:
            fail("the event file %s is not JSON" % event)
    if not base:
        base = "origin/chain-v030"
    if git("cat-file", "-e", base + "^{commit}").returncode != 0 and re.fullmatch(r"[0-9a-f]{40}", base):
        git("fetch", "-q", "--depth=1", "origin", base)       # a shallow CI checkout: fetch the one base commit
    if git("cat-file", "-e", base + "^{commit}").returncode != 0:
        fail("cannot resolve the merge base %r, so the list cannot be compared with it" % base)
    mb = git("merge-base", "HEAD", base)
    mbs = mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else base
    old = git("show", "%s:test-evidence/known-red.json" % mbs)
    old_entries = {}
    if old.returncode == 0:
        try:
            old_entries = {e["id"]: e for e in json.loads(old.stdout)["entries"]}
        except (ValueError, KeyError, TypeError):
            fail("the list at the merge base is not readable")
    # an entry is NEW when its id is new or its content (suite, case, reason, green_by) differs from the merge base's: a retained id must not change meaning
    added = [e["id"] for e in load(path) if old_entries.get(e["id"]) != {k: e[k] for k in KEYS}]
    named = set(re.findall(r"(?m)^known-red-add:\s*(\S+)\s*$", body)) | set(os.environ.get("KNOWN_RED_ADD", "").split())
    missing = [i for i in added if i not in named]
    if missing:
        fail("entries added since the merge base and not named in the PR body (a line `known-red-add: <id>`): %s" % " ".join(missing))
    print("known-red: %d entr(ies) added since the merge base, all named in the PR body" % len(added))


def cmd_empty(args):
    path = args[args.index("--list") + 1] if "--list" in args else DEFAULT_LIST
    ents = load(path)
    if ents:
        fail("the list still has %d entr(ies): %s (cutover needs it empty)" % (len(ents), " ".join(e["id"] for e in ents)))
    print("known-red: the list is empty")


def main(argv):
    if not argv or argv[0] not in ("judge", "base-check", "empty"):
        print("usage: chain-known-red.py judge --suite S [--list F] | base-check [--list F] [--base R] [--event F] | empty [--list F]", file=sys.stderr)
        return 2
    {"judge": cmd_judge, "base-check": cmd_base_check, "empty": cmd_empty}[argv[0]](argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
