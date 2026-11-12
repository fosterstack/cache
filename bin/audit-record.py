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
  audit-record.py bump --head SHA --repo OWNER/NAME --base-root DIR      (the judge, for a head with no passing record)
      Exit 0: exactly one open pull request has this head, Dependabot opened it, and the Dependabot reviewer passes it
      (bump_passes; REQ-REL-012-AC9). Exit 1 with a line on stdout: such a pull request, not passed. Exit 1 with no
      line: no such pull request, or no readable writers policy, so the record rule stands. Exit 3: a GitHub API
      error, on stderr.
      It asks GitHub through gh with the caller's token and reads commits as git objects of DIR.

Every doubt fails closed: a missing or malformed answer, a head that is not 40 lower-case hex, a missing policy file.
"""
import argparse
import json
import os
import re
import subprocess
import sys

RECORD_MESSAGE = "audit record"       # the one fixed, neutral line the writer commits; the record names no tool, model or reviewer
RECORD_FILE = "audit-record"          # the one file the record commit adds (createCommitOnBranch needs a change to make a commit); its content is the head sha
WEB_FLOW = ("web-flow", 19864447)     # GitHub's own committer for commits it makes and signs on an actor's behalf
_SHA = re.compile(r"^[0-9a-f]{40}$")
WRITERS_PATH = ".github/policy/audit-writers.json"
DEPENDABOT = ("dependabot[bot]", 49699333)   # GitHub's own Dependabot, the user of a pull request it opened
REVIEWER_CHECK = "dependabot-reviewer"       # the check run dependabot-reviewer.yml publishes as its verdict on a head
NO_RUN = object()                            # reviewer_verdict's answer for a commit the reviewer has not run on; no string a run can carry equals it
MAX_UPDATES = 50                             # the merges of main followed back from a head


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


def dependabot_pull(pr):
    """True for an open pull request into main that Dependabot opened from a dependabot/ branch of the repository itself
    (the answer of `gh api repos/R/pulls/N`, or one item of `gh api repos/R/commits/SHA/pulls`)."""
    if not isinstance(pr, dict):
        return False
    user, head, base = pr.get("user"), pr.get("head"), pr.get("base")
    if not all(isinstance(x, dict) for x in (user, head, base)):
        return False
    ours, theirs = base.get("repo"), head.get("repo")
    return (pr.get("state") == "open" and base.get("ref") == "main"
            and (user.get("login"), user.get("id")) == DEPENDABOT and user.get("type") == "Bot"
            and isinstance(head.get("ref"), str) and head["ref"].startswith("dependabot/")
            and isinstance(ours, dict) and isinstance(theirs, dict)
            and type(ours.get("id")) is int and ours["id"] == theirs.get("id"))


def bump_pull(head, pulls):
    """The one open pull request with this head sha, when Dependabot opened it (`gh api repos/R/commits/SHA/pulls`),
    else None. The gate's check run belongs to the commit, so any other open pull request on it, or an item that
    cannot be read, leaves the record rule in force."""
    if not isinstance(pulls, list) or len(pulls) >= 100:
        return None
    for p in pulls:
        if not isinstance(p, dict) or p.get("state") not in ("open", "closed"):
            return None
        sha = p["head"].get("sha") if isinstance(p.get("head"), dict) else None
        if p["state"] == "open" and not (isinstance(sha, str) and _SHA.fullmatch(sha)):
            return None
    same = [p for p in pulls if p["state"] == "open" and p["head"]["sha"] == head]
    return same[0] if len(same) == 1 and dependabot_pull(same[0]) else None


def reviewer_verdict(checks, logins):
    """The conclusion of the newest dependabot-reviewer check run on a commit that one of the bot logins put there
    (the reviewer publishes as the App that writes the records, so its login is the App's slug plus [bot]):
    NO_RUN when it put none, "unfinished" for one still running, None when the answer of
    `gh api repos/R/commits/SHA/check-runs?check_name=dependabot-reviewer&filter=all&per_page=100` is malformed or
    cut, or the completed run has no conclusion."""
    runs = checks.get("check_runs") if isinstance(checks, dict) else None
    if not isinstance(runs, list) or checks.get("total_count") != len(runs):
        return None
    mine = []
    for r in runs:
        app = r.get("app") if isinstance(r, dict) else None
        if (not isinstance(app, dict) or not isinstance(app.get("slug"), str) or not app["slug"]
                or type(r.get("id")) is not int or not isinstance(r.get("name"), str) or not r["name"]):
            return None
        if r["name"] == REVIEWER_CHECK and app["slug"] + "[bot]" in logins:
            mine.append(r)
    if not mine:
        return NO_RUN
    last = max(mine, key=lambda r: r["id"])
    return last.get("conclusion") if last.get("status") == "completed" else "unfinished"


def bump_passes(head, verdict_of, update_of):
    """(True, why) when verdict_of(head) is "success", or is NO_RUN and the head only merges main into a head that
    passes (update_of gives the first parent of such a commit, else None); else (False, why). Any other verdict
    refuses, and so does no verdict at all."""
    c = head
    for _ in range(MAX_UPDATES + 1):
        v = verdict_of(c)
        if v == "success":
            return True, "the Dependabot reviewer passed " + (
                "this head" if c == head else "%s, and this head only merges main into it" % c)
        if v is not NO_RUN:
            return False, "the Dependabot reviewer's newest verdict on %s is %s, not success" % (c, v or "unreadable")
        c = update_of(c)
        if c is None:
            return False, ("the Dependabot reviewer has not passed this head: it has no verdict, and it is not only "
                           "main merged into a head the reviewer passed")
    return False, "the Dependabot reviewer has not passed this head or any of the %d before it" % MAX_UPDATES


# matches v1.2.3, v0.3.0, v1.0.0-rc.2; refuses v1.2, v01.2.3, v1.2.3-rc1, v1.2.3-rc.
_RELEASE_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[0-9]+)?$")
# matches v1.2.3, v0.9.10; refuses v1.2.0, v1.2.3-rc.1, v01.2.3, v1.2.
_PATCH_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.[1-9][0-9]*$")
# matches "Audit-approved: " plus 40 lower-case hex; refuses upper-case hex, 39 or 41 digits, a trailing space.
_APPROVED = re.compile(r"^Audit-approved: ([0-9a-f]{40})$")
_SIG_BEGIN = ("-----BEGIN SSH SIGNATURE-----", "-----BEGIN SIGNED MESSAGE-----", "-----BEGIN PGP SIGNATURE-----")


def is_patch_tag(tag):
    return isinstance(tag, str) and bool(_PATCH_TAG.match(tag))


def _approval(tag_object):
    """The record commit sha the owner approved in the signed tag message, else None.
    Exactly one line `Audit-approved: <40 hex>` in the message (above the signature block); any other line that
    starts like an approval, in any case or indented, refuses (an ambiguous approval is no approval)."""
    if not isinstance(tag_object, str) or "\n\n" not in tag_object:
        return None
    msg = tag_object.split("\n\n", 1)[1]
    found = []
    for ln in msg.split("\n"):
        # exactly the labels the admission signer recognises (bin/admission-tag-signer.py BLOCKS);
        # any other PEM-looking block is message text
        if ln in _SIG_BEGIN:
            break
        if ln.strip().lower().startswith("audit-approved"):
            m = _APPROVED.match(ln)
            if not m:
                return None
            found.append(m.group(1))
    return found[0] if len(found) == 1 else None


def verify_release(tag, tag_object, tagged_sha, ref, commit, policy):
    """Gate 7 (release process rule 7): (True, "") for a patch tag or for a release tag whose commit has a
    passed-audit record that the owner's signed tag message approves; else (False, reason).
    The tag's signature is verified by the admission step before this runs, so a line in the message is the
    owner's own."""
    if not isinstance(tag, str) or not _RELEASE_TAG.match(tag):
        return False, "the tag is not a release version"
    if _PATCH_TAG.match(tag):
        return True, ""
    approved = _approval(tag_object)
    if approved is None:
        return False, ("the signed tag message does not carry exactly one 'Audit-approved: <40-hex record commit>' "
                       "line (the owner's approval of the whole-release audit)")
    ok, why = verify_record(tagged_sha, "main", ref, commit, policy)
    if not ok:
        return False, "the whole-release audit: " + why
    if commit.get("sha") != approved:
        return False, "the owner approved record commit %s, but the record of this commit is %s" % (
            approved, commit.get("sha"))
    return True, ""


def plan_release(head, cmp_json, actor=None, policy=None):
    """(True, "") when a whole-release record may be written for this commit now, on the request of this actor:
    the commit is on main (main is identical to it or ahead of it)."""
    pol = _policy(policy)
    if pol is None:
        return False, "the audit policy (%s of the default branch) is missing or malformed" % WRITERS_PATH
    if not isinstance(actor, str) or actor not in pol[1]:
        return False, "the dispatching actor is not named as a dispatcher in %s" % WRITERS_PATH
    if not isinstance(head, str) or not _SHA.match(head):
        return False, "the commit sha is not 40 lower-case hex"
    if not isinstance(cmp_json, dict) or cmp_json.get("status") not in ("identical", "ahead"):
        return False, "the commit is not on main (compare main...commit)"
    return True, ""


def plan_record(number, head, pr, actor=None, policy=None):
    """(True, "") when a record may be written for this pull request and head now, on the request of this actor; (False, reason) otherwise. The writer checks the pull request
    itself, so a record is never made for a closed or merged pull request, for another base, or for a head that has since moved, and only an actor the policy names as a
    dispatcher can ask for one (anyone with write access can start a workflow; not everyone may vouch for a review).
    A pull request Dependabot opened is refused: no record is written for it."""
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
    if dependabot_pull(pr):
        return False, "Dependabot opened the pull request: no passed-audit record is written for it"
    return True, ""


class _ApiError(Exception):
    pass


def _gh(path):
    """The parsed answer of `gh api PATH` (gh and its token as the caller set them); None for a 404; _ApiError for
    any other failure."""
    p = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if p.returncode != 0:
        if re.search(r"HTTP 404|Not Found", p.stderr):
            return None
        raise _ApiError("%s: %s" % (path, " ".join(p.stderr[-200:].split())))
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise _ApiError(path + ": the answer is not JSON")


def _update_of(root, commit):
    """The first parent of a commit that is main merged into that parent and nothing more, else None: two parents,
    the second a commit of the checked-out main (HEAD: both jobs of the gate judge from the default branch), and the
    very tree git makes of merging the two. Whoever made such a commit put nothing of their own in it."""
    def git(*args):
        p = subprocess.run(("git", "-C", root) + args, capture_output=True, text=True)
        return p.stdout.strip() if p.returncode == 0 else None
    parents = (git("rev-list", "--parents", "-n", "1", commit) or "").split()[1:]
    if len(parents) != 2 or git("merge-base", "--is-ancestor", parents[1], "HEAD") is None:
        return None
    merged, tree = git("merge-tree", "--write-tree", *parents), git("rev-parse", commit + "^{tree}")
    return parents[0] if merged and merged == tree else None


def bump(head, repo, root):
    """(None, "") when the record rule stands (no exemption can be read for this head); else (passes, why).
    _ApiError when GitHub cannot be asked."""
    allowed = _writers(_load(os.path.join(root, WRITERS_PATH)))
    if not (isinstance(head, str) and _SHA.fullmatch(head) and allowed is not None
            and isinstance(repo, str) and re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo)):
        return None, ""
    logins = {login for login, _ in allowed}
    pr = bump_pull(head, _gh("repos/%s/commits/%s/pulls?per_page=100" % (repo, head)))
    if pr is None:
        return None, ""

    def verdict_of(commit):
        path = "repos/%s/commits/%s/check-runs?check_name=%s&filter=all&per_page=100" % (repo, commit, REVIEWER_CHECK)
        return reviewer_verdict(_gh(path), logins)
    ok, why = bump_passes(head, verdict_of, lambda commit: _update_of(root, commit))
    if ok:
        return True, "Dependabot pull request #%s needs no passed-audit record: %s" % (pr.get("number"), why)
    return False, "Dependabot pull request #%s: %s" % (pr.get("number"), why)


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
    r = sub.add_parser("release")
    r.add_argument("--tag", required=True)
    r.add_argument("--tag-object", required=True)
    r.add_argument("--tagged-sha", required=True)
    r.add_argument("--base-root", required=True)
    r.add_argument("--ref-json")
    r.add_argument("--commit-json")
    q = sub.add_parser("plan-release")
    q.add_argument("--head", required=True)
    q.add_argument("--cmp-json", required=True)
    q.add_argument("--actor", required=True)
    q.add_argument("--base-root", required=True)
    b = sub.add_parser("bump")
    b.add_argument("--head", required=True)
    b.add_argument("--repo", required=True)
    b.add_argument("--base-root", required=True)
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
    if a.cmd == "release":
        try:
            obj = open(a.tag_object).read()
        except OSError:
            obj = None
        ok, why = verify_release(a.tag, obj, a.tagged_sha, _load(a.ref_json), _load(a.commit_json),
                                 _load(os.path.join(a.base_root, WRITERS_PATH)))
        done = ("no whole-release record needed" if is_patch_tag(a.tag)
                else "the owner's approval matches the passed-audit record")
        print("audit-record: " + ("release %s: %s" % (a.tag, done) if ok else why))
        return 0 if ok else 1
    if a.cmd == "plan-release":
        ok, why = plan_release(a.head, _load(a.cmp_json), a.actor, _load(os.path.join(a.base_root, WRITERS_PATH)))
        print("audit-record: " + ("a whole-release record may be written for %s" % a.head if ok else why))
        return 0 if ok else 1
    if a.cmd == "plan":
        ok, why = plan_record(a.pr, a.head, _load(a.pr_json), a.actor, _load(os.path.join(a.base_root, WRITERS_PATH)))
        print("audit-record: " + ("a record may be written for #%d at %s" % (a.pr, a.head) if ok else why))
        return 0 if ok else 1
    if a.cmd == "bump":
        try:
            ok, why = bump(a.head, a.repo, a.base_root)
        except _ApiError as e:
            print("audit-record: could not ask GitHub about this head (GitHub API error on %s)" % e, file=sys.stderr)
            return 3
        if ok is not None:
            print("audit-record: " + why)
        return 0 if ok else 1
    if a.cmd != "verify":
        return 2
    ok, why = verify_record(a.head, a.base_ref, _load(a.ref_json), _load(a.commit_json),
                            _load(os.path.join(a.base_root, WRITERS_PATH)))
    print("audit-record: " + (why if not ok else ("passed-audit record found for " + a.head if a.base_ref == "main" else "base %r is not main: nothing to check" % a.base_ref)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
