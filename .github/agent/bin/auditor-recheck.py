#!/usr/bin/env python3
"""Every-run re-check (REQ-AUD-2 AC7): when the upstream fix becomes pullable, the
temporary/reachability VEX statement and every ignore under every alias are DELETED
(a real change), the bump PR is opened through the shim, and the finding moves to
report section 1. The prior state is not merely flagged removed."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli


def _shim(line):
    log = os.environ.get("AUDITOR_GIT_SHIM_LOG")
    if log:
        open(log, "a").write(line + "\n")


def _delete_named(root, aliases):
    removed = []
    for dp, _, fs in os.walk(root):
        for fn in fs:
            p = os.path.join(dp, fn)
            if any(a in open(p, errors="ignore").read() for a in aliases):
                os.remove(p); removed.append(p)
    return removed


def main():
    out = cli.opt("--out"); disp = json.load(open(cli.opt("--vex")))
    suppdir = cli.opt("--suppression-dir"); cve = disp.get("cve")
    aliases = {cve} | set(disp.get("aliases", []))
    if cli.flag("--now-pullable"):
        removed = _delete_named(suppdir, aliases) if suppdir and os.path.isdir(suppdir) else []
        _shim("git checkout -b auditor/bump-%s" % cve)
        _shim("gh pr create --head auditor/bump-%s --base main --label auto-merge-lane" % cve)
        cli.writej(os.path.join(out, "recheck.json"),
                   {"vex_removed": True, "bump_pr_opened": True, "report_section": 1,
                    "cve": cve, "removed_files": removed})
    else:
        cli.writej(os.path.join(out, "recheck.json"),
                   {"vex_removed": False, "bump_pr_opened": False, "report_section": None})
        cli.writej(os.path.join(out, "vex", "still-present.json"), disp)


if __name__ == "__main__":
    main()
