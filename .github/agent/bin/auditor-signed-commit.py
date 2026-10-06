#!/usr/bin/env python3
"""A signed commit through the GitHub API, from a workflow step (the release workflow's changelog-and-clear PR).

main requires signed commits; `git commit` in a runner is unsigned. This makes ONE commit on --branch through createCommitOnBranch with the
caller's GH_TOKEN (the App's installation token), via auditorlib.signed_commit.commit_via_api (temporary ref, signature check, lease).

  auditor-signed-commit.py --repo OWNER/NAME --branch B --base FULLSHA --prefix PREFIX [--prefix PREFIX ...] --message TEXT --path P [--path P ...]

--prefix: the lanes B may be in; only `auditor/` and `patch-notes/` are accepted. --path: read from the CURRENT directory; a path that does not
exist there is a DELETION. Prints the new commit's oid on stdout. Exit 0 = made and confirmed signed; 1 = refused or failed (plain message on
stderr, nothing on stdout); 2 = bad arguments. stdlib only; no git credentials are needed or used.
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import signed_commit

PREFIXES = signed_commit.ALLOWED_PREFIXES


def _refuse_path(root, path):
    """A reason this path may not be read from the working directory, else None."""
    parts = path.split("/")
    if path.startswith("/") or any(p in ("", ".", "..") for p in parts):
        return "refusing path %r (not a plain relative path)" % path
    if os.path.islink(os.path.join(root, path)):
        return "refusing path %r (a symlink is never followed)" % path
    return None


def main(argv=None, run=None, root=None):
    ap = argparse.ArgumentParser(prog="auditor-signed-commit", description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--branch", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--prefix", required=True, action="append", choices=PREFIXES)
    ap.add_argument("--message", required=True)
    ap.add_argument("--path", required=True, action="append")
    a = ap.parse_args(argv)
    root = root or os.getcwd()
    try:
        for p in a.path:
            why = _refuse_path(root, p)
            if why:
                raise signed_commit.CommitError(why)
        oid = signed_commit.commit_via_api(a.repo, a.branch, a.base, a.message, signed_commit.read_changes(root, a.path),
                                           run=run, prefixes=tuple(a.prefix))
    except (signed_commit.CommitError, OSError) as e:
        print("auditor-signed-commit: %s" % e, file=sys.stderr)
        return 1
    print(oid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
