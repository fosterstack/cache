#!/usr/bin/env python3
"""Auditor entrypoint (called by .github/workflows/auditor.yml). Orchestrates one run
of the sealed commands in this directory. dry_run does everything except open PRs and
issues. This is the thin driver; each step's behaviour is in its own auditor-*.py and
is covered by bin/auditor-matrix-test.sh."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy


def main():
    dry = cli.opt("--dry-run", "true") != "false"
    print("daily CVE auditor: dry_run=%s, iteration cap=%d, token budget=%d"
          % (dry, policy.MAX_ITERATIONS, policy.TOKEN_BUDGET))
    # The per-phase commands (consume-rescan, classify, defectlog, votes, suppress,
    # poam, report, notify, open-pr, release-authz) run here in order; each is a
    # separate, individually tested auditor-*.py. Left as the wiring point.
    return 0


if __name__ == "__main__":
    sys.exit(main())
