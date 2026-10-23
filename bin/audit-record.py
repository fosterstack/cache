#!/usr/bin/env python3
"""Gate 6 of the release process: a pull request into main carries a passed-audit record for its exact head, or it cannot merge.

(REQ-REL-012; owner RATIFIED Oct 23 2026, ops/docs/ratify/2026-10-23-release-process-features-sections-audits.md, rule 6.)

The record is a branch named audit/<the pull request's head sha>. It holds ONE commit whose only parent is that head, that GitHub verified,
that the writer named in .github/policy/audit-writers.json of the BASE checkout authored (login AND id), and that changes no file. Nothing
is stored in the pull request's own files, so a pull request cannot carry, edit or forge its own record, and a new push changes the head
sha, so an old record then names a different sha and does not apply.

  audit-record.py verify --head SHA --base-ref REF --base-root DIR [--ref-json FILE --commit-json FILE]
      FILE = the answers of `gh api repos/R/git/ref/heads/audit/SHA` and `gh api repos/R/commits/<that ref's sha>`.
      Exit 0: a base that is not main (nothing is read), or a good record. Exit 1: anything else, with the reason on stdout. Exit 2: usage.

Every doubt fails closed: a missing or malformed answer, a head that is not 40 lower-case hex, a missing policy file.
"""
import argparse
import json
import os
import re
import sys

RECORD_MESSAGE = "audit record"       # the one fixed, neutral line the writer commits; the record names no tool, model or reviewer
_SHA = re.compile(r"^[0-9a-f]{40}$")
WRITERS_PATH = ".github/policy/audit-writers.json"


def record_branch(head):
    return "audit/" + head


def _writers(doc):
    """The (login, id) pairs of a well-formed writers policy, else None."""
    if not isinstance(doc, dict) or doc.get("schema") != 1 or set(doc) != {"schema", "writers"} or not isinstance(doc["writers"], list) or not doc["writers"]:
        return None
    out = set()
    for w in doc["writers"]:
        if (not isinstance(w, dict) or set(w) != {"login", "id"} or not isinstance(w["login"], str) or not w["login"]
                or not isinstance(w["id"], int) or isinstance(w["id"], bool) or w["id"] <= 0):
            return None
        out.add((w["login"], w["id"]))
    return out


def verify_record(head, base_ref, ref, commit, writers):
    """(True, "") for a good record or a base that is not main; (False, reason) for everything else."""
    if not isinstance(base_ref, str) or not base_ref:
        return False, "the pull request's base branch is unknown"
    if base_ref != "main":
        return True, ""
    if not isinstance(head, str) or not _SHA.match(head):
        return False, "the pull request's head sha is not 40 lower-case hex"
    allowed = _writers(writers)
    if allowed is None:
        return False, "the audit writers policy (%s of the base checkout) is missing or malformed" % WRITERS_PATH
    want = record_branch(head)
    if not isinstance(ref, dict) or ref.get("ref") != "refs/heads/" + want:
        return False, "no passed-audit record for this head: there is no branch %s" % want
    obj = ref.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "commit" or not isinstance(obj.get("sha"), str) or not _SHA.match(obj["sha"]):
        return False, "the record branch %s does not point at a commit" % want
    if not isinstance(commit, dict) or commit.get("sha") != obj["sha"]:
        return False, "the record commit answer is not the commit the branch %s points at" % want
    parents = commit.get("parents")
    if not (isinstance(parents, list) and len(parents) == 1 and isinstance(parents[0], dict) and parents[0].get("sha") == head):
        return False, "the record is not one commit parented on this head (a record for an older head is stale)"
    files = commit.get("files")
    if not isinstance(files, list) or files:
        return False, "the record commit changes files (or does not say it changes none)"
    c = commit.get("commit")
    ver = c.get("verification") if isinstance(c, dict) else None
    if not isinstance(ver, dict) or ver.get("verified") is not True or ver.get("reason") != "valid":
        return False, "the record commit is not verified by GitHub"
    a = commit.get("author")
    if not isinstance(a, dict) or a.get("type") != "Bot" or (a.get("login"), a.get("id")) not in allowed:
        return False, "the record commit was not authored by an audit writer named in %s" % WRITERS_PATH
    return True, ""


def _load(path):
    if not path:
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def main(argv):
    ap = argparse.ArgumentParser(prog="audit-record.py")
    sub = ap.add_subparsers(dest="cmd")
    v = sub.add_parser("verify")
    v.add_argument("--head", required=True)
    v.add_argument("--base-ref", required=True)
    v.add_argument("--base-root", required=True)
    v.add_argument("--ref-json")
    v.add_argument("--commit-json")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    if a.cmd != "verify":
        return 2
    if a.base_ref != "main":
        print("audit-record: base %r is not main: nothing to check" % a.base_ref)
        return 0
    ok, why = verify_record(a.head, a.base_ref, _load(a.ref_json), _load(a.commit_json),
                            _load(os.path.join(a.base_root, WRITERS_PATH)))
    print("audit-record: " + ("passed-audit record found for " + a.head if ok else why))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
