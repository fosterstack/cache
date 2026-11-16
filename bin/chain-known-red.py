#!/usr/bin/env python3
"""The known-red list of the release chain's integration branch (test-evidence/known-red.json).

On chain-v030 a few cases of the chain suites are red on purpose until a later PR or a cache item lands (the old chain jobs of PRs 3 and 4, the cache lane's
build scripts P4/P5). They are listed here by case and reason, so a red CI run means exactly "the list and the red cases differ", never "red is normal".

  judge --suite SUITE --inner-rc N [--list FILE]   stdin is the suite's output: exit 0 only when the set of FAIL cases is EXACTLY the list's entries for SUITE
                                           (a red case that is not listed fails; a listed case that passes fails, naming it: remove the entry in the PR that fixes it)
  base-check [--list FILE] [--base REF] [--event FILE]
                                           an entry added or changed since the merge base (the COMPLETE entry is compared, findings included) fails unless the PR body names it with a line `known-red-add: <id>`
                                           (the body is read from the GitHub event file, GITHUB_EVENT_PATH; --event overrides;
                                           locally, with no event file, the environment variable KNOWN_RED_ADD='id id ...' names them; a push event is not compared)
  empty [--list FILE]                      exit 1 while the list has entries (the marker PR's condition: KR-CUTOVER goes with the marker, REQ-CHAIN-001-AC6)
  empty-except ID [--list FILE]            exit 1 while the list has an entry other than ID (the cutover PR's condition, with ID = KR-CUTOVER: every other entry is
                                           gone, ID alone means "rc proof pending"); ID is exactly one argument; an unreadable list fails

An entry is {id, suite, case, reason, green_by}. `case` is the text after `FAIL ` up to ` -> ` or `: ` of the suite's FAIL line (a prefix match: the line must
start with FAIL and the case, followed by the end, ` -> ` or `: `).
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIST = os.path.join(HERE, "..", "test-evidence", "known-red.json")
KEYS = {"id", "suite", "case", "reason", "green_by"}
OPTIONAL = {"findings"}      # the structured identity of the case's findings: a list of strings, with multiplicity (one element per finding)


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
        if not isinstance(e, dict) or not KEYS <= set(e) <= KEYS | OPTIONAL or not all(isinstance(e[k], str) and e[k].strip() for k in KEYS):
            fail("an entry must be an object of exactly %s (and optionally %s), each a non-empty string: %r" % (sorted(KEYS), sorted(OPTIONAL), e))
        if "findings" in e and (not isinstance(e["findings"], list) or not e["findings"] or not all(isinstance(x, str) and x for x in e["findings"])):
            fail("entry %s: findings must be a non-empty list of non-empty strings" % e.get("id"))
        if e["id"] in seen:
            fail("entry id %s is listed twice" % e["id"])
        seen.add(e["id"])
    return ents


def fail_lines(text):
    return [l[5:] for l in text.splitlines() if l.startswith("FAIL ")]


def matches(line, case):
    return line == case or line.startswith(case + " -> ") or line.startswith(case + ": ") or line.startswith(case + " (")


def parse_output(text):
    """[(line, structured ids or None)] for every FAIL line: the ids are those of the FINDINGS-JSON line printed IMMEDIATELY before it."""
    out, prev = [], None
    for raw in text.split("\n"):
        if raw.startswith("FAIL "):
            ids = None
            if prev is not None and prev.startswith("FINDINGS-JSON "):
                try:
                    ids = json.loads(prev[len("FINDINGS-JSON "):])
                except ValueError:
                    ids = False
                if not (isinstance(ids, list) and all(isinstance(x, str) for x in ids)):
                    ids = False
            out.append((raw[5:], ids))
        prev = raw
    return out


def cmd_judge(args):
    suite = args[args.index("--suite") + 1]
    path = args[args.index("--list") + 1] if "--list" in args else DEFAULT_LIST
    if "--inner-rc" not in args:
        usage_fail("--inner-rc is required: the suite's own exit status (the wrapper must not discard it)")
    try:
        inner = int(args[args.index("--inner-rc") + 1])
    except (ValueError, IndexError):
        usage_fail("--inner-rc must be an integer exit status")
    ents = [e for e in load(path) if e["suite"] == suite]
    text = sys.stdin.read()
    m = re.findall(r"^pass=(\d+) fail=(\d+)$", text, re.M)
    if not m:
        fail("the suite %s printed no `pass=N fail=M` summary: it did not finish" % suite)
    cases = parse_output(text)
    problems = []
    claimed = int(m[-1][1])
    if claimed != len(cases):
        problems.append("the summary says fail=%d but the output has %d FAIL line(s): the summary is not trusted" % (claimed, len(cases)))
    if inner not in (0, 1) or (inner == 0) != (len(cases) == 0):
        problems.append("the suite's exit status %d does not agree with its %d FAIL line(s) (0 exactly when there is none; never another status)" % (inner, len(cases)))
    used = {e["id"]: [] for e in ents}
    for line, ids in cases:
        hit = [e for e in ents if matches(line, e["case"])]
        if len(hit) != 1:
            problems.append("a red case that is not on the known-red list: %s" % line[:200])
        else:
            used[hit[0]["id"]].append(ids)
    for e in ents:
        got = used[e["id"]]
        if not got:
            problems.append("a listed case now passes (remove entry %s from test-evidence/known-red.json): %s" % (e["id"], e["case"][:200]))
            continue
        if len(got) != 1:
            problems.append("entry %s: its case was printed %d times (twice or more is not the listed case): %s" % (e["id"], len(got), e["case"][:120]))
            continue
        if "findings" in e:
            ids = got[0]
            if ids is None or ids is False:
                problems.append("entry %s lists its findings but the output has no valid FINDINGS-JSON line right before its FAIL line" % e["id"])
            else:
                want, have = sorted(e["findings"]), sorted(ids)
                if want != have:
                    extra = [x for x in have if x not in want or have.count(x) > want.count(x)]
                    missing = [x for x in want if x not in have or want.count(x) > have.count(x)]
                    problems.append("entry %s: the findings differ from the listed ones (%d printed, %d listed); additional: %s; missing: %s"
                                    % (e["id"], len(have), len(want), "; ".join(dict.fromkeys(extra))[:300] or "none", "; ".join(dict.fromkeys(missing))[:300] or "none"))
    if problems:
        print("\n".join("known-red: " + p for p in problems))
        sys.exit(1)
    print("known-red: %s: %d red case(s), exactly the %d listed (each turns green with its named item)" % (suite, len(cases), len(ents)))


def usage_fail(msg):
    print("known-red: " + msg)
    sys.exit(2)


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
    # an entry is NEW when its id is new or any part of it (suite, case, reason, green_by, findings) differs from the merge base's: a retained id must not change meaning
    added = [e["id"] for e in load(path) if old_entries.get(e["id"]) != e]
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


def cmd_empty_except(args):
    rest = list(args)
    path = DEFAULT_LIST
    if "--list" in rest:
        i = rest.index("--list")
        if i + 1 >= len(rest):
            usage_fail("--list needs a file")
        path = rest[i + 1]
        del rest[i:i + 2]
    if len(rest) != 1 or rest[0].startswith("-"):
        usage_fail("empty-except takes exactly one entry id (the entry that may remain)")
    keep = rest[0]
    others = [e["id"] for e in load(path) if e["id"] != keep]
    if others:
        fail("the list still has %d entr(ies) besides %s: %s (the cutover needs every other entry gone)" % (len(others), keep, " ".join(others)))
    print("known-red: no entry besides %s" % keep)


def main(argv):
    if not argv or argv[0] not in ("judge", "base-check", "empty", "empty-except"):
        print("usage: chain-known-red.py judge --suite S [--list F] | base-check [--list F] [--base R] [--event F] | empty [--list F] | empty-except ID [--list F]", file=sys.stderr)
        return 2
    {"judge": cmd_judge, "base-check": cmd_base_check, "empty": cmd_empty, "empty-except": cmd_empty_except}[argv[0]](argv[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
