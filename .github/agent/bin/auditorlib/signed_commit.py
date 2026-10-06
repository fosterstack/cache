"""The auditor's delivery commits, made through the GitHub API so GitHub signs them (REQ-AUD-17, REQ-AUD-15).

main's ruleset requires signed commits. A commit made by `git commit` in the runner is not signed, so the PR it
carried stayed BLOCKED forever. A commit made through the GraphQL `createCommitOnBranch` mutation with the App's
installation token is created and signed by GitHub. The same App, the same permissions, no new token.

commit_via_api(repo, branch, base_sha, message, changes): the LIVE branch is touched only AFTER a signed replacement commit exists.
  1. read the live branch's head H1 (absent = none);
  2. create a TEMPORARY ref auditor/tmp-<id> at base_sha (REST);
  3. make ONE commit on the temporary branch (expectedHeadOid = base_sha) and confirm it is signed (the mutation's signature, else a
     follow-up GET of the commit);
  4. read the live head again: if it is not H1, someone wrote since step 1: delete the temporary ref and FAIL CLOSED, nothing overwritten;
  5. point the live branch at the new commit (PATCH force when it exists, POST create when absent);
  6. ALWAYS delete the temporary ref (best effort: a failure to delete is not fatal and is reported in `notes` / the error).
So a failed mutation, a failed signature check or a lease miss leaves the live branch, its open PR and the PR's pending additions exactly as
they were; the live branch is never reset to main and the PR never has an empty-diff head.

branch_reusable(repo, branch, base_sha): an EXISTING delivery branch may be left as it is only when its head commit is verified by GitHub and its
first parent is base_sha (today's main); otherwise the caller rebuilds it through commit_via_api.

Anything else (an API error, no oid, an unconfirmed signature, a file over 5 MB, a branch outside auditor/) is a CommitError: the delivery fails
closed and says so. A commit that is not provably signed is never reported delivered.

KNOWN RESIDUAL: between step 4 and step 5 a concurrent writer to the live branch can still be overwritten (the refs API has no
compare-and-swap for a forced update). The window is two API calls long; the auditor's workflow runs in the concurrency group
`auditor-daily-delivery` (cancel-in-progress: false), so two deliveries never overlap, and only the App writes auditor/* (the
only-the-app-pushes-auditor-lane guard).
"""
import base64, hashlib, json, os, re, subprocess, time, urllib.parse

MAX_FILE_BYTES = 5 * 1024 * 1024        # createCommitOnBranch is a request body, not a git push: refuse what it cannot take
BRANCH_PREFIX = "auditor/"              # the reserved lane: the only branches the App writes
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_PREFIXES = ("auditor/", "patch-notes/")   # the only lanes the App may write: a caller names which of them it uses
_BRANCH = re.compile(r"^(?:auditor|patch-notes)/[A-Za-z0-9._/+-]+$")

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


GRAPHQL_COMMAND = ["gh", "api", "graphql", "--input", "-"]


def _tmp_branch(base_sha):
    """A temporary branch name in the reserved lane, unique per run, time and base."""
    seed = "%s/%s/%d/%s" % (os.environ.get("GITHUB_RUN_ID", ""), os.getpid(), time.time_ns(), base_sha)
    return "auditor/tmp-" + hashlib.sha256(seed.encode()).hexdigest()[:12]


def _get_cmd(repo, branch):
    return ["gh", "api", "repos/%s/git/ref/heads/%s" % (repo, branch)]


def _patch_cmd(repo, branch, sha):
    return ["gh", "api", "--method", "PATCH", "repos/%s/git/refs/heads/%s" % (repo, branch), "-f", "sha=%s" % sha, "-F", "force=true"]


def _post_cmd(repo, branch, sha):
    return ["gh", "api", "--method", "POST", "repos/%s/git/refs" % repo, "-f", "ref=refs/heads/%s" % branch, "-f", "sha=%s" % sha]


def _delete_cmd(repo, branch):
    return ["gh", "api", "--method", "DELETE", "repos/%s/git/refs/heads/%s" % (repo, branch)]


def planned_commands(repo, branch, base_sha):
    """What a dry run plans (nothing is called)."""
    tmp = "auditor/tmp-<run>"
    return [_get_cmd(repo, branch), _post_cmd(repo, tmp, base_sha), list(GRAPHQL_COMMAND),
            _patch_cmd(repo, branch, "<new signed commit>"), _delete_cmd(repo, tmp)]


def _check_branch(branch, prefixes=(BRANCH_PREFIX,)):
    """The branch must have the strict shape AND start with one of `prefixes` (each itself one of ALLOWED_PREFIXES)."""
    if not isinstance(prefixes, (tuple, list)) or not prefixes or any(p not in ALLOWED_PREFIXES for p in prefixes):
        raise CommitError("signed commit: refusing prefixes %r: the App writes only %s" % (prefixes, " or ".join(ALLOWED_PREFIXES)))
    if not isinstance(branch, str) or not _BRANCH.match(branch) or ".." in branch or branch.endswith(("/", ".lock")) \
            or not branch.startswith(tuple(prefixes)):
        raise CommitError("signed commit: refusing branch %r: the App writes only %s* branches" % (branch, "* or ".join(prefixes)))


def _check(repo, branch, base_sha, message, changes, prefixes=(BRANCH_PREFIX,)):
    if not isinstance(repo, str) or not _REPO.match(repo):
        raise CommitError("signed commit: the repository %r is not owner/name" % (repo,))
    _check_branch(branch, prefixes)
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


def _head(run, repo, branch):
    """The branch's head sha, or None when it is absent (404). Any other failure, or an answer without a sha, is an error."""
    rc, out, err = _api(run, _get_cmd(repo, branch))
    if rc != 0:
        if "404" in err + out or "Not Found" in err + out:
            return None
        raise CommitError("signed commit: reading branch %s failed: %s" % (branch, (err or out).strip()[-300:]))
    obj = _json(out, "the branch lookup").get("object")
    sha = obj.get("sha") if isinstance(obj, dict) else None
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise CommitError("signed commit: the lookup of branch %s returned no commit sha" % branch)
    return sha


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


def _make_commit(run, repo, tmp, base_sha, message, changes):
    """ONE commit on the temporary branch; returns its oid once it is confirmed signed."""
    headline, _, body = message.strip().partition("\n")
    additions = [{"path": p, "contents": base64.b64encode(bytes(c)).decode("ascii")} for p, c in sorted(changes.items()) if c is not None]
    deletions = [{"path": p} for p, c in sorted(changes.items()) if c is None]
    variables = {"input": {"branch": {"repositoryNameWithOwner": repo, "branchName": tmp},
                           "message": {"headline": headline.strip(), "body": body.strip()},
                           "expectedHeadOid": base_sha,
                           "fileChanges": {"additions": additions, "deletions": deletions}}}
    rc, out, err = _api(run, GRAPHQL_COMMAND, json.dumps({"query": MUTATION, "variables": variables}))
    if rc != 0:
        raise CommitError("signed commit: createCommitOnBranch failed: %s" % (err or out).strip()[-300:])
    doc = _json(out, "createCommitOnBranch")
    if doc.get("errors"):
        raise CommitError("signed commit: createCommitOnBranch returned errors: %s" % json.dumps(doc["errors"])[:300])
    payload = (doc.get("data") or {}).get("createCommitOnBranch")
    commit = payload.get("commit") if isinstance(payload, dict) else None
    oid = commit.get("oid") if isinstance(commit, dict) else None
    if not isinstance(oid, str) or not _SHA.match(oid):
        raise CommitError("signed commit: createCommitOnBranch returned no commit oid; nothing is confirmed delivered")
    _confirm_signed(run, repo, oid, commit.get("signature"))
    return oid


def commit_via_api(repo, branch, base_sha, message, changes, run=None, notes=None, prefixes=(BRANCH_PREFIX,)):
    """repo: "owner/name". changes: {path: bytes to write, or None to delete}. Returns the new signed commit's oid; the live `branch` then holds it.
    notes: an optional list that receives non-fatal remarks (a temporary ref that could not be deleted).
    prefixes: the lanes `branch` may be in (default auditor/ only; the release workflow passes ("patch-notes/",)). The temporary ref is always auditor/tmp-*."""
    _check(repo, branch, base_sha, message, changes, prefixes)
    tmp = _tmp_branch(base_sha)
    _check_branch(tmp)
    h1 = _head(run, repo, branch)                                            # 1. observe the live branch
    rc, out, err = _api(run, _post_cmd(repo, tmp, base_sha))                 # 2. the temporary ref, at main
    if rc != 0:
        raise CommitError("signed commit: creating temporary branch %s at %s failed: %s" % (tmp, base_sha[:12], (err or out).strip()[-300:]))
    leftover = None
    try:
        oid = _make_commit(run, repo, tmp, base_sha, message, changes)       # 3. signed commit, off to the side
        if _head(run, repo, branch) != h1:                                   # 4. the lease
            raise CommitError("signed commit: branch %s changed while the commit was being made (lease lost): nothing was overwritten, the delivery stops" % branch)
        if h1 is None:                                                       # 5. only now does the live branch move
            rc, out, err = _api(run, _post_cmd(repo, branch, oid)); what = "creating"
        else:
            rc, out, err = _api(run, _patch_cmd(repo, branch, oid)); what = "moving"
        if rc != 0:
            raise CommitError("signed commit: %s branch %s to the signed commit %s failed: %s" % (what, branch, oid[:12], (err or out).strip()[-300:]))
        return oid
    except CommitError as e:
        leftover = e
        raise
    finally:                                                                 # 6. always
        rc, out, err = _api(run, _delete_cmd(repo, tmp))
        if rc != 0:
            note = "temporary branch %s could not be deleted (delete it by hand): %s" % (tmp, (err or out).strip()[-200:])
            if notes is not None:
                notes.append(note)
            if leftover is not None:
                leftover.args = (str(leftover) + "; " + note,)


def _content(run, repo, path, ref):
    """The bytes of `path` at commit `ref`, or None when it is absent there (404). Anything unreadable is an error."""
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))     # a path like go.mod?ref=main# must not alter the request
    rc, out, err = _api(run, ["gh", "api", "repos/%s/contents/%s?ref=%s" % (repo, quoted, urllib.parse.quote(ref, safe=""))])
    if rc != 0:
        if "404" in err + out or "Not Found" in err + out:
            return None
        raise CommitError("signed commit: reading %s at %s failed: %s" % (path, ref[:12], (err or out).strip()[-300:]))
    doc = _json(out, "the contents lookup")
    if doc.get("encoding") != "base64" or not isinstance(doc.get("content"), str):
        raise CommitError("signed commit: %s at %s did not come back as base64 content" % (path, ref[:12]))
    try:
        return base64.b64decode(doc["content"])
    except ValueError:
        raise CommitError("signed commit: %s at %s is not valid base64" % (path, ref[:12]))


def branch_reusable(repo, branch, base_sha, want, run=None):
    """The head oid of `branch` when it may be left as it is, else None (the caller rebuilds through commit_via_api, which is fail-closed). Reuse means ONE
    reviewed commit: GitHub verifies the head as signed, it has EXACTLY ONE parent and that is base_sha (today's main), it changes only files named in
    `want` ({path: the bytes this run wants there, or None for absent}; no renames), and at the head each wanted path holds exactly those bytes.
    The caller binds arming to the returned oid. Every other answer, a failed lookup included, is None."""
    try:
        _check_branch(branch)
        if not isinstance(repo, str) or not _REPO.match(repo) or not isinstance(base_sha, str) or not _SHA.match(base_sha):
            return None
        _check(repo, branch, base_sha, "m", want)          # the wanted paths and bytes are held to the same rules as a commit's
        head = _head(run, repo, branch)
        if head is None or head == base_sha:               # absent, or exactly main (nothing delivered on it): rebuild
            return None
        rc, out, err = _api(run, ["gh", "api", "repos/%s/commits/%s" % (repo, head)])
        if rc != 0:
            return None
        doc = _json(out, "the commit lookup")
        commit, parents, files = doc.get("commit"), doc.get("parents"), doc.get("files")
        verification = commit.get("verification") if isinstance(commit, dict) else None
        if not (isinstance(verification, dict) and verification.get("verified") is True):
            return None
        if not (isinstance(parents, list) and len(parents) == 1 and isinstance(parents[0], dict) and parents[0].get("sha") == base_sha):
            return None
        if not (isinstance(files, list) and files):
            return None
        for f in files:
            if not (isinstance(f, dict) and f.get("filename") in want and f.get("status") in ("added", "modified", "removed") and "previous_filename" not in f):
                return None
        for path, wanted in want.items():
            if _content(run, repo, path, head) != (bytes(wanted) if wanted is not None else None):
                return None
    except CommitError:
        return None
    return head


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
