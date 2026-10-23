#!/usr/bin/env python3
"""Gate 6 of the release process: a pull request into main carries a passed-audit record for its exact head, or it cannot merge.

(REQ-REL-012; owner RATIFIED Oct 23 2026, ops/docs/ratify/2026-10-23-release-process-features-sections-audits.md, rule 6.)

The record is a branch named audit/<the pull request's head sha>. It holds ONE commit whose only parent is that head, that GitHub verified,
that the writer named in .github/policy/audit-writers.json of the BASE checkout authored (login AND id) and committed (the writer, or GitHub's own
web-flow committer, which only GitHub applies), whose message is the one fixed neutral line, and that adds exactly one file, audit-record (its content
is the head sha). Nothing is stored in the pull request's own files, so a pull request cannot carry, edit or forge its own record, and a new push changes the head
sha, so an old record then names a different sha and does not apply.

  audit-record.py plan --pr N --head SHA --pr-json FILE --actor LOGIN --base-root DIR      (the writer: may a record be made now, at this actor's request? FILE = `gh api repos/R/pulls/N`)
  audit-record.py verify --head SHA --base-ref REF --base-root DIR [--ref-json FILE --commit-json FILE]
      FILE = the answers of `gh api repos/R/git/ref/heads/audit/SHA` and `gh api repos/R/commits/<that ref's sha>`.
      Exit 0: a base that is not main (the judge decides; nothing is read), or a good record. Exit 1: anything else, with the reason on stdout. Exit 2: usage.

Every doubt fails closed: a missing or malformed answer, a head that is not 40 lower-case hex, a missing policy file.
"""
import argparse
import json
import os
import re
import sys

RECORD_MESSAGE = "audit record"       # the one fixed, neutral line the writer commits; the record names no tool, model or reviewer
RECORD_FILE = "audit-record"          # the one file the record commit adds (createCommitOnBranch needs a change to make a commit); its content is the head sha
WEB_FLOW = ("web-flow", 19864447)     # GitHub's own committer for commits it makes and signs on an actor's behalf
_SHA = re.compile(r"^[0-9a-f]{40}$")
WRITERS_PATH = ".github/policy/audit-writers.json"


def record_branch(head):
    return "audit/" + head


def _policy(doc):
    """(the (login, id) pairs of the writers, the logins allowed to dispatch the writer) of a well-formed policy, else None."""
    if not isinstance(doc, dict) or doc.get("schema") != 1 or set(doc) != {"schema", "writers", "dispatchers"} or not isinstance(doc["writers"], list) or not doc["writers"]:
        return None
    d = doc["dispatchers"]
    if not isinstance(d, list) or not d or any(not isinstance(x, str) or not x for x in d):
        return None
    out = set()
    for w in doc["writers"]:
        if (not isinstance(w, dict) or set(w) != {"login", "id"} or not isinstance(w["login"], str) or not w["login"]
                or not isinstance(w["id"], int) or isinstance(w["id"], bool) or w["id"] <= 0):
            return None
        out.add((w["login"], w["id"]))
    return out, set(d)


def _writers(doc):
    p = _policy(doc)
    return p[0] if p else None


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
    if not (isinstance(files, list) and len(files) == 1 and isinstance(files[0], dict) and files[0].get("filename") == RECORD_FILE and files[0].get("status") == "added"):
        return False, "the record commit does not add exactly the one file %s" % RECORD_FILE
    c = commit.get("commit")
    if not isinstance(c, dict) or not isinstance(c.get("message"), str) or c["message"].strip() != RECORD_MESSAGE:
        return False, "the record commit's message is not the fixed record line"
    ver = c.get("verification") if isinstance(c, dict) else None
    if not isinstance(ver, dict) or ver.get("verified") is not True or ver.get("reason") != "valid":
        return False, "the record commit is not verified by GitHub"
    a = commit.get("author")
    if not isinstance(a, dict) or a.get("type") != "Bot" or (a.get("login"), a.get("id")) not in allowed:
        return False, "the record commit was not authored by an audit writer named in %s" % WRITERS_PATH
    k = commit.get("committer")
    if not isinstance(k, dict) or ((k.get("login"), k.get("id")) not in allowed and (k.get("login"), k.get("id")) != WEB_FLOW):
        return False, "the record commit was not committed by an audit writer or by GitHub itself (a signature made with someone else's own key does not count)"
    return True, ""


def plan_record(number, head, pr, actor=None, policy=None):
    """(True, "") when a record may be written for this pull request and head now, on the request of this actor; (False, reason) otherwise. The writer checks the pull request
    itself, so a record is never made for a closed or merged pull request, for another base, or for a head that has since moved, and only an actor the policy names as a
    dispatcher can ask for one (anyone with write access can start a workflow; not everyone may vouch for a review)."""
    pol = _policy(policy)
    if pol is None:
        return False, "the audit policy (%s of the default branch) is missing or malformed" % WRITERS_PATH
    if not isinstance(actor, str) or actor not in pol[1]:
        return False, "the dispatching actor is not named as a dispatcher in %s" % WRITERS_PATH
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return False, "the pull request number is not a positive integer"
    if not isinstance(head, str) or not _SHA.match(head):
        return False, "the head sha is not 40 lower-case hex"
    if not isinstance(pr, dict) or pr.get("number") != number:
        return False, "the pull request answer is missing or is another pull request"
    if pr.get("state") != "open" or pr.get("merged") is not False:
        return False, "the pull request is not open"
    base = pr.get("base")
    if not isinstance(base, dict) or base.get("ref") != "main":
        return False, "the pull request is not into main"
    h = pr.get("head")
    if not isinstance(h, dict) or h.get("sha") != head:
        return False, "the pull request's head is not %s (it moved)" % head
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
    p = sub.add_parser("plan")
    p.add_argument("--pr", required=True, type=int)
    p.add_argument("--head", required=True)
    p.add_argument("--pr-json", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--base-root", required=True)
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    if a.cmd == "plan":
        ok, why = plan_record(a.pr, a.head, _load(a.pr_json), a.actor, _load(os.path.join(a.base_root, WRITERS_PATH)))
        print("audit-record: " + ("a record may be written for #%d at %s" % (a.pr, a.head) if ok else why))
        return 0 if ok else 1
    if a.cmd != "verify":
        return 2
    ok, why = verify_record(a.head, a.base_ref, _load(a.ref_json), _load(a.commit_json),
                            _load(os.path.join(a.base_root, WRITERS_PATH)))
    print("audit-record: " + (why if not ok else ("passed-audit record found for " + a.head if a.base_ref == "main" else "base %r is not main: nothing to check" % a.base_ref)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
