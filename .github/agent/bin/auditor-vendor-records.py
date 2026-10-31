#!/usr/bin/env python3
"""The records sweep (run hourly from dependabot-reviewer.yml): every open dependency-bump branch gets the vendored
tree and provenance records its go.mod and go.sum change calls for, as ONE signed commit by the App
(auditorlib.vendor_records).

  auditor-vendor-records.py --repo OWNER/NAME --workspace DIR [--dry-run] [--branch B ...]

--workspace: a full clone of main whose bin/ holds the provenance scripts; the bump branches are fetched into it as
data and never run. --branch: only these branches (a manual run); default every dependabot/go_modules/* and
auditor/bump-* branch. --dry-run: commit nothing.
Prints one line per branch. Exit 0 = every branch committed, was up to date or was skipped (a skip is a normal
answer and says why); 1 = a branch failed or the branches could not be listed. The App token is GH_TOKEN; stdlib
only.
"""
import argparse, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import signed_commit, vendor_records


def main(argv=None, run=None, regenerate=None):
    ap = argparse.ArgumentParser(prog="auditor-vendor-records", description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--branch", action="append")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    run = run or subprocess.run
    regenerate = regenerate or vendor_records.make_regenerate(a.workspace)
    if a.branch:
        branches = a.branch
    else:
        r = run(["gh", "api", "--paginate", "repos/%s/branches?per_page=100" % a.repo, "--jq", ".[].name"],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("could not list the branches: %s" % (r.stderr or "").strip()[-300:], file=sys.stderr)
            return 1
        branches = [b for b in r.stdout.split("\n") if signed_commit._BUMP_BRANCH.match(b)]
    failed = 0
    for branch in branches:
        line = vendor_records.process_branch(a.repo, branch, a.workspace, run, regenerate, dry_run=a.dry_run)
        print("%s: %s" % (branch, " ".join(line.split())))
        failed += line.startswith("failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
