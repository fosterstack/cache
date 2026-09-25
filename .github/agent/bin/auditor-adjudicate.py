#!/usr/bin/env python3
"""Refusal handling (REQ-AUD-8). Deterministic steps make no model call. On a refusal
the auditor escalates primary -> defensive rephrase -> fallback model, logging every
refusal; a finding refused through the whole chain lands in report section 4."""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli

ATTEMPTS = [("primary", "primary"), ("rephrase", "primary"), ("fallback", "fallback")]


def main():
    scenario = json.load(open(cli.opt("--scenario"))); adjudicator = cli.opt("--adjudicator")
    out = cli.opt("--out"); prompts = cli.opt("--capture-prompts")
    if prompts:
        # defensive phrasing, no exploit code
        cli.writef(prompts, "Assess reachability for our own image from govulncheck "
                            "evidence and decide a defensive VEX status. Reason only about "
                            "whether our code reaches the vulnerable path.\n")
        cli.writej(os.path.join(out, "note.json"), {"defensive": True})
        return
    adjudication = {}; refusals = []
    for case in scenario.get("cases", []):
        fid = case["finding_id"]; answered = False
        for attempt, role in ATTEMPTS:
            try:
                cli.ask_model(adjudicator, fid, attempt, role)
                adjudication[fid] = {"final": "answered", "attempt": attempt}
                answered = True
                break
            except cli.Refused:
                refusals.append({"finding_id": fid, "attempt": attempt, "model": role})
        if not answered:
            adjudication[fid] = {"final": "under_investigation", "report_section": 4}
    cli.writej(os.path.join(out, "adjudication.json"), adjudication)
    cli.writej(os.path.join(out, "refusal-log.json"), {"refusals": refusals})


if __name__ == "__main__":
    main()
