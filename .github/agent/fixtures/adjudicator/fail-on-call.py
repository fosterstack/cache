#!/usr/bin/env python3
"""SYNTHETIC TEST DOUBLE — the "no model" spy.

A deterministic phase (scanner diff, known-defect lookup, KEV lookup,
reachability extraction, votes, consistency, release authorization) must make
NO model call. Tests pass this as the adjudicator: if the auditor invokes it,
it records the call in $AUDITOR_MODEL_LEDGER and exits 99, so the phase both
leaves a ledger line AND fails. A correct deterministic phase never runs this,
the ledger stays empty, and the command exits 0.
"""
import os, sys
ledger = os.environ.get("AUDITOR_MODEL_LEDGER")
if ledger:
    with open(ledger, "a") as fh:
        fh.write("UNEXPECTED-MODEL-CALL\n")
sys.stderr.write("fail-on-call: a deterministic phase invoked the model\n")
sys.exit(99)
