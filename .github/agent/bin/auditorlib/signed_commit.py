"""The auditor's delivery commits, made through the GitHub API so GitHub signs them.

main's ruleset requires signed commits, and a commit made by `git commit` in the runner is unsigned. A commit made
through the GraphQL `createCommitOnBranch` mutation with the App's installation token is created and signed by GitHub.

Each function says what it proves in its own docstring. commit_via_api builds the commit on a temporary auditor/tmp-*
ref and only then points the live branch at it; if deleting that temporary ref fails, the ref stays behind, and the live
branch, its open PR and the PR's pending additions are as they were.

Anything that cannot be proved, such as an API error, a missing oid, an unconfirmed signature, a file over 5 MB or a
branch outside the allowed prefixes, is a CommitError: the delivery fails closed, and a commit that is not provably
signed is never reported delivered.

Known race: between the lease check and the move of the live branch in commit_via_api, a concurrent writer can be
overwritten, because the refs API has no compare-and-swap for a forced update. The workflow's concurrency group
auditor-daily-delivery keeps two deliveries from overlapping.
"""
import base64, hashlib, json, os, re, subprocess, time, urllib.parse

# createCommitOnBranch is a request body, not a git push: refuse what it cannot take
MAX_FILE_BYTES = 5 * 1024 * 1024
BRANCH_PREFIX = "auditor/"              # the default lane of commit_via_api
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
# the lanes commit_via_api may write; a caller names which it uses (audit/ = the passed-audit record, REQ-REL-012)
ALLOWED_PREFIXES = ("auditor/", "patch-notes/", "audit/")
_BRANCH = re.compile(r"^(?:auditor|patch-notes|audit)/[A-Za-z0-9._/+-]+$")
_AUDIT_BRANCH = re.compile(r"^audit/[0-9a-f]{40}$")
# the lanes commit_on_branch may write: Dependabot's Go branches and the auditor's own bump branches
BUMP_PREFIXES = ("dependabot/go_modules/", "auditor/bump-")
# matches dependabot/go_modules/github.com/prometheus/client_golang-1.25.0 and auditor/bump-example.com-m-1.1.0;
# refuses dependabot/npm_and_yarn/x, auditor/panel, auditor/bump- (nothing after the dash) and main
_BUMP_BRANCH = re.compile(r"^(?:%s)[A-Za-z0-9._/+-]+\Z" % "|".join(map(re.escape, BUMP_PREFIXES)))
# the first words of the sweep's commit message
RECORDS_HEADLINE = "Vendor records for the "
# beside everything under vendor/, the places a records commit may write
RECORDS_FILES = ("dependency-provenance.json", "test-evidence/dependency-licenses.yaml")
# GitHub itself commits (and signs) what the API creates; a pushed commit cannot carry that signature
GITHUB_COMMITTER = "web-flow"

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
    return ["gh", "api", "--method", "PATCH", "repos/%s/git/refs/heads/%s" % (repo, branch),
            "-f", "sha=%s" % sha, "-F", "force=true"]


def _post_cmd(repo, branch, sha):
    return ["gh", "api", "--method", "POST", "repos/%s/git/refs" % repo,
            "-f", "ref=refs/heads/%s" % branch, "-f", "sha=%s" % sha]


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
        raise CommitError("signed commit: refusing prefixes %r: the App writes only %s"
                          % (prefixes, " or ".join(ALLOWED_PREFIXES)))
    if not isinstance(branch, str) or not _BRANCH.match(branch) or ".." in branch or branch.endswith(("/", ".lock")) \
            or not branch.startswith(tuple(prefixes)):
        raise CommitError("signed commit: refusing branch %r: the App writes only %s* branches"
                          % (branch, "* or ".join(prefixes)))
    if branch.startswith("audit/") and not _AUDIT_BRANCH.match(branch):
        raise CommitError("signed commit: refusing branch %r: the passed-audit record branch is audit/ and a full "
                          "commit sha, nothing else" % (branch,))


def is_records_path(path):
    """The only places a records commit writes: anything under vendor/, the provenance record, the reviewed licences. A
    plain relative path."""
    if not isinstance(path, str) or path.startswith("/") or any(p in ("", ".", "..") for p in path.split("/")):
        return False
    return path in RECORDS_FILES or path.startswith("vendor/")


def records_message(branch):
    """The whole message of the sweep's commit on `branch`: one line naming the last part of the branch."""
    return RECORDS_HEADLINE + "%s bump" % branch.rsplit("/", 1)[1]


def is_bump_branch(branch):
    """True for a dependency-bump branch name (see _BUMP_BRANCH)."""
    return isinstance(branch, str) and bool(_BUMP_BRANCH.match(branch))


def _check_bump_branch(branch):
    if not is_bump_branch(branch) or ".." in branch or branch.endswith(("/", ".lock")):
        raise CommitError("signed commit: refusing branch %r: a records commit goes on a dependabot/go_modules/* "
                          "or auditor/bump-* branch only" % (branch,))


def _check(repo, branch, base_sha, message, changes, prefixes=(BRANCH_PREFIX,), bump=False):
    if not isinstance(repo, str) or not _REPO.match(repo):
        raise CommitError("signed commit: the repository %r is not owner/name" % (repo,))
    if bump:
        _check_bump_branch(branch)
    else:
        _check_branch(branch, prefixes)
    if not isinstance(base_sha, str) or not _SHA.match(base_sha):
        raise CommitError("signed commit: the base %r is not a full commit sha" % (base_sha,))
    if not bump and branch.startswith("audit/") and branch != "audit/" + base_sha:
        raise CommitError("signed commit: the record branch %s is not audit/ plus its base commit %s"
                          % (branch, base_sha))
    if not isinstance(message, str) or not message.strip():
        raise CommitError("signed commit: an empty commit message")
    if not changes:
        raise CommitError("signed commit: no file changes to commit")
    for path, content in changes.items():
        parts = path.split("/") if isinstance(path, str) else []
        if not parts or path.startswith("/") or any(p in ("", ".", "..") for p in parts):
            raise CommitError("signed commit: refusing path %r (not a plain relative path)" % (path,))
        if bump and not is_records_path(path):
            raise CommitError("signed commit: refusing path %r: a records commit writes only vendor/, "
                              "the provenance record and the licences" % (path,))
        if content is not None:
            if not isinstance(content, (bytes, bytearray)):
                raise CommitError("signed commit: the content of %s is not bytes" % path)
            if len(content) > MAX_FILE_BYTES:
                raise CommitError("signed commit: %s is %d bytes, over the %d-byte limit of createCommitOnBranch; "
                                  "the commit cannot be made through the API (and a git commit would be unsigned)"
                                  % (path, len(content), MAX_FILE_BYTES))


def _head(run, repo, branch):
    """The branch's head sha, or None when it is absent (404). Any other failure, or an answer
    without a sha, is an error."""
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
    """The commit must be provably signed: the mutation's own answer when it gave one, else GitHub's
    verification of the commit."""
    if isinstance(signature, dict):
        if signature.get("isValid") is True and signature.get("state") == "VALID":
            return
        raise CommitError("signed commit: GitHub reports commit %s as NOT validly signed (isValid=%r, state=%r); "
                          "it is unsigned, so it is not delivered"
                          % (oid[:12], signature.get("isValid"), signature.get("state")))
    rc, out, err = _api(run, ["gh", "api", "repos/%s/commits/%s" % (repo, oid)])
    if rc != 0:
        raise CommitError("signed commit: could not confirm commit %s is signed: %s"
                          % (oid[:12], (err or out).strip()[-300:]))
    commit = _json(out, "the commit lookup").get("commit")
    verification = commit.get("verification") if isinstance(commit, dict) else None
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        raise CommitError("signed commit: commit %s is not verified by GitHub (%r); "
                          "it is unsigned, so it is not delivered"
                          % (oid[:12], (verification or {}).get("reason") if isinstance(verification, dict) else None))


def _make_commit(run, repo, tmp, base_sha, message, changes):
    """ONE commit on the temporary branch; returns its oid once it is confirmed signed."""
    headline, _, body = message.strip().partition("\n")
    additions = [{"path": p, "contents": base64.b64encode(bytes(c)).decode("ascii")}
                 for p, c in sorted(changes.items()) if c is not None]
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
    """repo: "owner/name". changes: {path: bytes to write, or None to delete}. Returns the new signed commit's oid; the
    live `branch` then holds it.
    notes: an optional list that receives non-fatal remarks (a temporary ref that could not be deleted).
    prefixes: the lanes `branch` may be in (default auditor/ only; the release workflow passes ("patch-notes/",)).
    The temporary ref is always auditor/tmp-*."""
    _check(repo, branch, base_sha, message, changes, prefixes)
    tmp = _tmp_branch(base_sha)
    _check_branch(tmp)
    h1 = _head(run, repo, branch)                                            # 1. observe the live branch
    rc, out, err = _api(run, _post_cmd(repo, tmp, base_sha))                 # 2. the temporary ref, at main
    if rc != 0:
        raise CommitError("signed commit: creating temporary branch %s at %s failed: %s"
                          % (tmp, base_sha[:12], (err or out).strip()[-300:]))
    leftover = None
    try:
        oid = _make_commit(run, repo, tmp, base_sha, message, changes)       # 3. signed commit, off to the side
        if _head(run, repo, branch) != h1:                                   # 4. the lease
            raise CommitError("signed commit: branch %s changed while the commit was being made (lease lost): "
                              "nothing was overwritten, the delivery stops" % branch)
        if h1 is None:                                                       # 5. only now does the live branch move
            rc, out, err = _api(run, _post_cmd(repo, branch, oid)); what = "creating"
        else:
            rc, out, err = _api(run, _patch_cmd(repo, branch, oid)); what = "moving"
        if rc != 0:
            raise CommitError("signed commit: %s branch %s to the signed commit %s failed: %s"
                              % (what, branch, oid[:12], (err or out).strip()[-300:]))
        return oid
    except CommitError as e:
        leftover = e
        raise
    finally:                                                                 # 6. always
        rc, out, err = _api(run, _delete_cmd(repo, tmp))
        if rc != 0:
            note = ("temporary branch %s could not be deleted (delete it by hand): %s"
                    % (tmp, (err or out).strip()[-200:]))
            if notes is not None:
                notes.append(note)
            if leftover is not None:
                leftover.args = (str(leftover) + "; " + note,)


def commit_on_branch(repo, branch, head_sha, message, changes, run=None):
    """ONE signed commit on the bump branch's own head. head_sha is the parent and the lease: if the branch is no
    longer there, nothing is written. Returns the new commit's oid, confirmed signed."""
    _check(repo, branch, head_sha, message, changes, bump=True)
    if _head(run, repo, branch) != head_sha:
        raise CommitError("signed commit: branch %s moved since it was read (it is not at %s): nothing was written"
                          % (branch, head_sha[:12]))
    return _make_commit(run, repo, branch, head_sha, message, changes)


def _content(run, repo, path, ref):
    """The bytes of `path` at commit `ref`, or None when it is absent there (404). Anything unreadable is an error."""
    # a path like go.mod?ref=main# must not alter the request
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    rc, out, err = _api(run, ["gh", "api",
                              "repos/%s/contents/%s?ref=%s" % (repo, quoted, urllib.parse.quote(ref, safe=""))])
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


def _commit_doc(run, repo, sha):
    """GitHub's answer for a commit; CommitError when it cannot be read (branch_reusable turns that into None)."""
    rc, out, err = _api(run, ["gh", "api", "repos/%s/commits/%s" % (repo, sha)])
    if rc != 0:
        raise CommitError("signed commit: reading commit %s failed" % str(sha)[:12])
    return _json(out, "the commit lookup")


def _verified(doc):
    commit = doc.get("commit")
    verification = commit.get("verification") if isinstance(commit, dict) else None
    return isinstance(verification, dict) and verification.get("verified") is True


def _login(doc, who):
    """The GitHub login of the commit's "author" or "committer", or None when the doc has none."""
    person = doc.get(who)
    return person.get("login") if isinstance(person, dict) else None


def _by_app(doc, app_login):
    """The commit was made through the API on the App's behalf: the API's author.login is the App's (e.g. 'name[bot]';
    null is refused) and GitHub itself is the committer. Without a login to compare, nothing is by the App."""
    return bool(app_login) and _login(doc, "author") == app_login and _login(doc, "committer") == GITHUB_COMMITTER


def _is_records_commit(doc, branch):
    commit = doc.get("commit")
    return isinstance(commit, dict) and commit.get("message") == records_message(branch)


def _only_records_paths(run, repo, sha):
    """Every file of commit `sha` is a plain add, change or delete of a records path. GitHub pages a commit's
    files at 100 a page (its cap) and stops at 3000, so a list is complete only when a page comes back short;
    anything else proves nothing."""
    files = []
    for page in range(1, 31):
        rc, out, _ = _api(run, ["gh", "api", "repos/%s/commits/%s?per_page=100&page=%d" % (repo, sha, page)])
        if rc != 0:
            return False
        chunk = _json(out, "the commit lookup").get("files")
        if not isinstance(chunk, list):
            return False
        files += chunk
        if len(chunk) < 100:
            return bool(files) and all(isinstance(f, dict) and is_records_path(f.get("filename"))
                                       and f.get("status") in ("added", "modified", "removed")
                                       and "previous_filename" not in f for f in files)
    return False


def commits_authored_by(run, repo, base_sha, head_sha, logins, notes=None):
    """True when every commit after base_sha up to head_sha is verified by GitHub, authored by one of `logins`
    (e.g. 'dependabot[bot]') and committed by one of them or by the GitHub web-flow account that signs API commits.
    A list GitHub may have cut short, or any failed lookup, is False; `notes` (a list) then receives the cause."""
    logins = {login for login in logins if login}      # an unset App login must not match an author with no login
    rc, out, err = _api(run, ["gh", "api", "repos/%s/compare/%s...%s?per_page=100" % (repo, base_sha, head_sha)])
    if rc != 0:
        return _refused(notes, "the compare lookup failed: %s" % (err or out).strip()[-200:])
    try:
        doc = _json(out, "the compare lookup")
    except CommitError as e:
        return _refused(notes, str(e))
    commits = doc.get("commits")
    if not isinstance(commits, list) or not commits:
        return _refused(notes, "the compare lookup listed no commits")
    if doc.get("total_commits") != len(commits):
        return _refused(notes, "the branch has %s commits, more than the %d listed"
                        % (doc.get("total_commits"), len(commits)))
    if not all(isinstance(c, dict) and _verified(c) and _login(c, "author") in logins
               and _login(c, "committer") in logins | {GITHUB_COMMITTER} for c in commits):
        return _refused(notes, "a commit is not verified, or not authored and committed by %s or GitHub"
                        % ", ".join(sorted(logins)))
    return True


def _refused(notes, why):
    if notes is not None:
        notes.append(why)
    return False


def branch_reusable(repo, branch, base_sha, want, run=None, app_login=None):
    """The head oid of `branch` when it may be left as it is, else None (the caller rebuilds through commit_via_api,
    which is fail-closed). Reuse means ONE reviewed commit: GitHub verifies the head as signed, it has EXACTLY ONE
    parent and that is base_sha (today's main), it changes only files named in `want` ({path: the bytes this run wants
    there, or None for absent}; no renames), and at the head each wanted path holds exactly those bytes.
    Every commit judged is authored by the App (`app_login`, e.g. 'name[bot]'; none given = nothing is reusable). The
    head may be ONE more commit, the records sweep's: verified, by the App, its message exactly
    records_message(branch), one parent, files only on records paths, which is then judged as above.
    The caller binds arming to the returned oid. Every other answer, a failed lookup included, is None."""
    try:
        _check_branch(branch)
        if not (isinstance(repo, str) and _REPO.match(repo) and isinstance(base_sha, str) and _SHA.match(base_sha)):
            return None
        # the wanted paths and bytes are held to the same rules as a commit's
        _check(repo, branch, base_sha, "m", want)
        head = _head(run, repo, branch)
        if head is None or head == base_sha:               # absent, or exactly main (nothing delivered on it): rebuild
            return None
        doc = _commit_doc(run, repo, head)
        if not (_verified(doc) and _by_app(doc, app_login)):
            return None
        # the sweep's commit: it writes records paths only; judge the commit under it by the ordinary rules
        if _is_records_commit(doc, branch):
            if not _only_records_paths(run, repo, head):
                return None
            parents = doc.get("parents")
            if not (isinstance(parents, list) and len(parents) == 1 and isinstance(parents[0], dict)):
                return None
            doc = _commit_doc(run, repo, parents[0].get("sha"))
        parents, files = doc.get("parents"), doc.get("files")
        if not (_verified(doc) and _by_app(doc, app_login)):
            return None
        if not (isinstance(parents, list) and len(parents) == 1 and isinstance(parents[0], dict)
                and parents[0].get("sha") == base_sha):
            return None
        if not (isinstance(files, list) and files):
            return None
        for f in files:
            if not (isinstance(f, dict) and f.get("filename") in want
                    and f.get("status") in ("added", "modified", "removed") and "previous_filename" not in f):
                return None
        for path, wanted in want.items():
            if _content(run, repo, path, head) != (bytes(wanted) if wanted is not None else None):
                return None
    except CommitError:
        return None
    return head


def _no_symlink(root, path):
    """Refuse a path with a symlink in ANY component (a link out of the tree reads a file outside it; a link inside
    the tree is refused too, so what is read is exactly the file the path names), and a real path that leaves the
    root. A component that does not exist ends the walk."""
    base = os.path.realpath(root)
    cur = base
    for part in path.split("/"):
        cur = os.path.join(cur, part)
        if os.path.islink(cur):
            raise CommitError("signed commit: refusing path %r: %s is a symlink; a symlink is never followed"
                              % (path, part))
        if not os.path.lexists(cur):
            return
    if os.path.commonpath([base, os.path.realpath(cur)]) != base:
        raise CommitError("signed commit: refusing path %r: it resolves outside the working directory" % path)


def read_changes(root, paths):
    """{path: bytes} for each path present under root; None (a deletion) for one that is not. A symlink in any
    component of any path is a CommitError, raised before anything is read."""
    for p in paths:
        _no_symlink(root, p)
    out = {}
    for p in paths:
        full = os.path.join(root, p)
        if os.path.isfile(full):
            with open(full, "rb") as fh:
                out[p] = fh.read()
        else:
            out[p] = None
    return out
