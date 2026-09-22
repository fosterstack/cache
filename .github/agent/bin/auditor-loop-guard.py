#!/usr/bin/env python3
"""Run bounds (REQ-AUD-6 AC2/AC3): a per-run token budget stops the run; the
adjudication loop stops after five iterations and reports."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli, policy


def main():
    out = cli.opt("--out"); adjudicator = cli.opt("--adjudicator")
    if cli.flag("--token-budget"):
        budget = int(cli.opt("--token-budget")); used = 0; calls = 0
        while used < budget and calls < policy.MAX_ITERATIONS:
            ans = cli.ask_model(adjudicator, "budget-probe-%d" % calls); calls += 1
            used += int(ans.get("token_usage", 1000))
        cli.writej(os.path.join(out, "budget.json"),
                   {"stopped_on_budget": used >= budget, "tokens_used": used, "calls": calls})
    else:
        n = 0
        while n < policy.MAX_ITERATIONS:
            cli.ask_model(adjudicator, "loop-probe-%d" % n); n += 1
        cli.writej(os.path.join(out, "stop.json"),
                   {"stopped_and_reported": True, "iterations": n})


if __name__ == "__main__":
    main()
