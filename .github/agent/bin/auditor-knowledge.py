#!/usr/bin/env python3
"""Generate the auditor knowledge document from the structured records (REQ-AUD-16 AC3).

    auditor-knowledge.py generate --log <known-defect-log.json> [--out <knowledge.md>]

Deterministic, no model call: it reads the known-defect log and emits the knowledge document the
model reads for pattern judgment. The generation logic lives in auditorlib.knowledge so the daily
driver produces the same document inline. Prints to stdout when --out is omitted.
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import cli
from auditorlib import knowledge as K


def main():
    op = cli.positional(0)
    if op != "generate":
        sys.exit("knowledge: unknown op %r (expected 'generate')" % op)
    logpath = cli.opt("--log")
    log = json.load(open(logpath)) if logpath and os.path.exists(logpath) else {"defects": []}
    doc = K.generate(log)
    out = cli.opt("--out")
    if out:
        cli.writef(out, doc)
    else:
        sys.stdout.write(doc)


if __name__ == "__main__":
    main()
