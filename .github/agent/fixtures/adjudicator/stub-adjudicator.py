#!/usr/bin/env python3
"""SYNTHETIC TEST DOUBLE — not the auditor.

A canned-answer adjudicator that satisfies the same interface the real model
client will: read one adjudication request as JSON on stdin, print one JSON
answer on stdout. It holds NO judgment logic — it is a lookup table keyed by
(finding_id, attempt) — so tests that drive it are deterministic and never call
a real model.

The table is keyed on the REAL finding identifiers the native fixtures carry
(the CVE/GO ids in run/manifest-multi.json, plus their common aliases), so a
correct classify can actually reach these answers. The refusal case uses a real,
famous "cyber" CVE (CVE-2021-44228) that is deliberately NOT in the scan manifest,
so its refuse-then-fallback answers never collide with a classify answer.

Independent model-call ledger: on every invocation this appends one line
    <finding_id>|<attempt>|<model_role>
to the file named by $AUDITOR_MODEL_LEDGER (if set). A test proves a phase made
no model call by asserting that ledger is empty, and proves the fallback order /
iteration count by reading the ledger lines — never by trusting a number the
auditor prints about itself.
"""
import json, os, sys

FP  = {"refused": False, "category": "false_positive", "justification": "vulnerable_code_not_present"}
NRU = {"refused": False, "category": "not_affected_unreachable", "justification": "vulnerable_code_not_in_execute_path"}
FIX = {"refused": False, "category": "real_fixable", "justification": "a pullable fix exists in an authorized bump class"}

CANNED = {
    # real finding ids from run/manifest-multi.json (native scanner reports)
    ("CVE-2016-2781", "primary"): FP,     # grype-only OS finding -> false positive
    ("CVE-2011-3374", "primary"): dict(FP, same_defect=True),  # log-verified FP; reconcile: same defect
    ("CVE-2022-48303", "primary"): FIX,   # OS finding with a fixed version
    ("CVE-2023-4911", "primary"): FIX,    # glibc, fixed version available in this image
    ("GO-2020-0015", "primary"): NRU,     # x/text, imported but not called
    ("GO-2021-0113", "primary"): FIX,     # x/text, reachable and fixed in a newer minor
    # common aliases the extractor may key on
    ("CVE-2020-14040", "primary"): NRU,
    ("CVE-2021-38561", "primary"): FIX,
    # refusal case (real cyber CVE, NOT in the scan manifest): refuse, refuse, then answer
    ("CVE-2021-44228", "primary"):  {"refused": True},
    ("CVE-2021-44228", "rephrase"): {"refused": True},
    ("CVE-2021-44228", "fallback"): {"refused": False, "category": "risk_acceptance",
                                     "justification": "reachable, no pullable fix; owner decides"},
    # a finding that stays refused through every attempt -> report section 4
    ("UNASSESSABLE", "primary"):  {"refused": True},
    ("UNASSESSABLE", "rephrase"): {"refused": True},
    ("UNASSESSABLE", "fallback"): {"refused": True},
}

def _answer(req):
    fid = req.get("finding_id"); attempt = req.get("attempt", "primary"); role = req.get("model", "primary")
    ledger = os.environ.get("AUDITOR_MODEL_LEDGER")
    if ledger:
        with open(ledger, "a") as fh:
            fh.write("%s|%s|%s\n" % (fid, attempt, role))
    ans = dict(CANNED.get((fid, attempt), {"refused": False, "category": "unknown", "justification": ""}))
    ans["token_usage"] = 1000
    return ans


def main():
    # --serve: the driver keeps ONE process for the whole run and sends one request per line
    # (so the real client exchanges its identity token once). Back-compat one-shot otherwise.
    if "--serve" in sys.argv:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            sys.stdout.write(json.dumps(_answer(json.loads(line))) + "\n")
            sys.stdout.flush()
        return
    json.dump(_answer(json.load(sys.stdin)), sys.stdout)

if __name__ == "__main__":
    main()
