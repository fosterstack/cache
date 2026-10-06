"""The auditor's delivery commits, made through the GitHub API so GitHub signs them (REQ-AUD-17, REQ-AUD-15).

main's ruleset requires signed commits. A commit made by `git commit` in the runner is not signed, so the PR it
carried stayed BLOCKED forever. A commit made through the GraphQL `createCommitOnBranch` mutation with the App's
installation token is created and signed by GitHub. The same App, the same permissions, no new token.

commit_via_api(repo, branch, base_sha, message, changes):
  1. the branch is created, or force-reset, at base_sha with the REST git-data refs API (a branch is rebuilt on the
     CURRENT main every run);
  2. ONE commit is made on it with expectedHeadOid = base_sha (a concurrent change to the branch fails the call
     instead of being overwritten);
  3. the new commit must be confirmed signed (the mutation's signature, else a follow-up GET of the commit);
  4. the new commit's oid is returned.
Anything else (an API error, no oid, an unconfirmed signature, a file over 5 MB, a branch outside auditor/) is a
CommitError: the delivery fails closed and says so. A commit that is not provably signed is never reported delivered.
"""
import base64, json, os, re, subprocess

MAX_FILE_BYTES = 5 * 1024 * 1024        # createCommitOnBranch is a request body, not a git push: refuse what it cannot take
BRANCH_PREFIX = "auditor/"              # the reserved lane: the only branches the App writes
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_BRANCH = re.compile(r"^auditor/[A-Za-z0-9._/+-]+$")

MUTATION = ("mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) "
            "{ commit { oid signature { isValid state } } } }")


class CommitError(RuntimeError):
    pass


def _api(run, cmd, stdin=None):
    kw = {"capture_output": True, "text": True}
    if stdin is not None:
        kw["input"] = stdin
    r = (run or subprocess.run)(cmd, **kw)
    return r.returncode, (r.stdout or ""), (r.stderr or "")


def _json(text, what):
    try:
        doc = json.loads(text)
    except ValueError:
        raise CommitError("signed commit: %s did not return JSON; the commit is not confirmed signed" % what)
    if not isinstance(doc, dict):
        raise CommitError("signed commit: %s returned %s, not an object" % (what, type(doc).__name__))
    return doc


def ref_commands(repo, branch, base_sha):
    """The REST calls that create the branch (it is absent) or force it onto base_sha (it exists)."""
    return {
        "get": ["gh", "api", "repos/%s/git/ref/heads/%s" % (repo, branch)],
        "reset": ["gh", "api", "--method", "PATCH", "repos/%s/git/refs/heads/%s" % (repo, branch),
                  "-f", "sha=%s" % base_sha, "-F", "force=true"],
        "create": ["gh", "api", "--method", "POST", "repos/%s/git/refs" % repo,
                   "-f", "ref=refs/heads/%s" % branch, "-f", "sha=%s" % base_sha],
    }


GRAPHQL_COMMAND = ["gh", "api", "graphql", "--input", "-"]


def planned_commands(repo, branch, base_sha):
    """What a dry run plans (nothing is called): the ref calls, then the signed commit."""
    c = ref_commands(repo, branch, base_sha)
    return [c["get"], c["reset"], list(GRAPHQL_COMMAND)]


def _check(repo, branch, base_sha, message, changes):
    if not isinstance(repo, str) or not _REPO.match(repo):
        raise CommitError("signed commit: the repository %r is not owner/name" % (repo,))
    if not isinstance(branch, str) or not _BRANCH.match(branch) or ".." in branch or branch.endswith(("/", ".lock")):
        raise CommitError("signed commit: refusing branch %r: the App writes only %s* branches" % (branch, BRANCH_PREFIX))
    if not isinstance(base_sha, str) or not _SHA.match(base_sha):
        raise CommitError("signed commit: the base %r is not a full commit sha" % (base_sha,))
    if not isinstance(message, str) or not message.strip():
        raise CommitError("signed commit: an empty commit message")
    if not changes:
        raise CommitError("signed commit: no file changes to commit")
    for path, content in changes.items():
        parts = path.split("/") if isinstance(path, str) else []
        if not parts or path.startswith("/") or any(p in ("", ".", "..") for p in parts):
            raise CommitError("signed commit: refusing path %r (not a plain relative path)" % (path,))
        if content is not None:
            if not isinstance(content, (bytes, bytearray)):
                raise CommitError("signed commit: the content of %s is not bytes" % path)
            if len(content) > MAX_FILE_BYTES:
                raise CommitError("signed commit: %s is %d bytes, over the %d-byte limit of createCommitOnBranch; the commit cannot be made through the API (and a git commit would be unsigned)"
                                  % (path, len(content), MAX_FILE_BYTES))


def _point_branch(run, repo, branch, base_sha):
    cmds = ref_commands(repo, branch, base_sha)
    rc, out, err = _api(run, cmds["get"])
    if rc == 0:
        rc, out, err = _api(run, cmds["reset"])
        what = "resetting"
    elif "404" in err + out or "Not Found" in err + out:
        rc, out, err = _api(run, cmds["create"])
        what = "creating"
    else:
        raise CommitError("signed commit: reading branch %s failed: %s" % (branch, (err or out).strip()[-300:]))
    if rc != 0:
        raise CommitError("signed commit: %s branch %s at %s failed: %s" % (what, branch, base_sha[:12], (err or out).strip()[-300:]))


def _confirm_signed(run, repo, oid, signature):
    """The commit must be provably signed: the mutation's own answer when it gave one, else GitHub's verification of the commit."""
    if isinstance(signature, dict):
        if signature.get("isValid") is True and signature.get("state") == "VALID":
            return
        raise CommitError("signed commit: GitHub reports commit %s as NOT validly signed (isValid=%r, state=%r); it is unsigned, so it is not delivered"
                          % (oid[:12], signature.get("isValid"), signature.get("state")))
    rc, out, err = _api(run, ["gh", "api", "repos/%s/commits/%s" % (repo, oid)])
    if rc != 0:
        raise CommitError("signed commit: could not confirm commit %s is signed: %s" % (oid[:12], (err or out).strip()[-300:]))
    commit = _json(out, "the commit lookup").get("commit")
    verification = commit.get("verification") if isinstance(commit, dict) else None
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        raise CommitError("signed commit: commit %s is not verified by GitHub (%r); it is unsigned, so it is not delivered"
                          % (oid[:12], (verification or {}).get("reason") if isinstance(verification, dict) else None))


def commit_via_api(repo, branch, base_sha, message, changes, run=None):
    """repo: "owner/name". changes: {path: bytes to write, or None to delete}. Returns the new commit's oid."""
    _check(repo, branch, base_sha, message, changes)
    _point_branch(run, repo, branch, base_sha)
    headline, _, body = message.strip().partition("\n")
    additions = [{"path": p, "contents": base64.b64encode(bytes(c)).decode("ascii")} for p, c in sorted(changes.items()) if c is not None]
    deletions = [{"path": p} for p, c in sorted(changes.items()) if c is None]
    variables = {"input": {"branch": {"repositoryNameWithOwner": repo, "branchName": branch},
                           "message": {"headline": headline.strip(), "body": body.strip()},
                           "expectedHeadOid": base_sha,
                           "fileChanges": {"additions": additions, "deletions": deletions}}}
    rc, out, err = _api(run, GRAPHQL_COMMAND, json.dumps({"query": MUTATION, "variables": variables}))
    if rc != 0:
        raise CommitError("signed commit: createCommitOnBranch on %s failed: %s" % (branch, (err or out).strip()[-300:]))
    doc = _json(out, "createCommitOnBranch")
    if doc.get("errors"):
        raise CommitError("signed commit: createCommitOnBranch on %s returned errors: %s" % (branch, json.dumps(doc["errors"])[:300]))
    payload = (doc.get("data") or {}).get("createCommitOnBranch")
    commit = payload.get("commit") if isinstance(payload, dict) else None
    oid = commit.get("oid") if isinstance(commit, dict) else None
    if not isinstance(oid, str) or not _SHA.match(oid):
        raise CommitError("signed commit: createCommitOnBranch on %s returned no commit oid; nothing is confirmed delivered" % branch)
    _confirm_signed(run, repo, oid, commit.get("signature"))
    return oid


def read_changes(root, paths):
    """{path: bytes} for each path present under root; None (a deletion) for one that is not."""
    out = {}
    for p in paths:
        full = os.path.join(root, p)
        if os.path.isfile(full):
            with open(full, "rb") as fh:
                out[p] = fh.read()
        else:
            out[p] = None
    return out
