#!/usr/bin/env python3
"""REQ-AUD-18 AC1: all auditor code, prompts, fixtures and tests live under .github/agent/ and
nowhere else; the only auditor-related files outside it are the workflow files and the
allowlist entries.

Reads tracked paths (one per line) on stdin — `git ls-files | auditor-layout-check.py` — and
fails on any path OUTSIDE .github/agent/ that is auditor-related: its path names the auditor,
or its content refers to .github/agent/. The exemptions below are the whole list, each with its
reason; adding one is a reviewed change to this file.

  --root DIR   resolve paths against DIR (default: cwd) when reading content
"""
import json, os, re, sys

AGENT = ".github/agent/"

# (pattern, reason) — the only auditor-related paths allowed outside .github/agent/.
EXEMPT = [
    (r"^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$",
     "workflow files (GitHub reads them only from .github/workflows/)"),
    (r"^\.github/dependabot\.yml$",
     "GitHub config: pins the adjudicator SDK requirements (read only from .github/)"),
    (r"^bin/check-file-allowlist(-test)?\.sh$",
     "the allowlist and its regressions (the allowlist entries)"),
    (r"^\.githooks/pre-commit$",
     "the allowlist's pre-commit hook"),
    (r"^test-evidence/(mappings|unmapped)\.yaml$",
     "the requirements traceability files: they name test paths as metadata and hold no auditor code "
     "(REQ-AUD-18 AC1 amendment, owner Oct 2)"),
    (r"^bin/patch-decide(\.py|-test\.sh)$",
     "the patch-release classifier and its test: they name the auditor directory as data and hold no auditor code "
     "(REQ-AUD-18 AC1 amendment, owner Oct 3)"),
    # exactly the output contract (auditor-run.py stages these paths; the allowlist scopes their
    # change to auditor/ branches) — never a directory wildcard, and a .json one must parse.
    (r"^(\.vex/fosterstack-cache\.openvex\.json|\.snyk|osv-scanner\.toml|\.auditor/accepted-items\.json"
     r"|\.auditor/knowledge\.md|\.auditor/proposals/[A-Za-z0-9._-]+\.json|\.auditor/panel-state\.json)$",
     "the auditor's generated OUTPUTS, delivered through its own PR lane and read by the "
     "scanners / release gate at these fixed paths — not auditor code, prompts, fixtures or tests"),
]
_OUTPUT = len(EXEMPT) - 1
_EXEMPT = [re.compile(p) for p, _ in EXEMPT]
_NAMED = re.compile(r"auditor", re.I)


def _is_json(path):
    try:
        with open(path, "rb") as fh:
            json.load(fh)
        return True
    except (OSError, ValueError):
        return False


def offenders(paths, root="."):
    bad = []
    for p in paths:
        if not p or p.startswith(AGENT):
            continue
        hit = [i for i, r in enumerate(_EXEMPT) if r.search(p)]
        if hit and hit[0] == _OUTPUT and p.endswith(".json") and not _is_json(os.path.join(root, p)):
            bad.append((p, "an output-contract .json path that is not JSON"))
            continue
        if hit:
            continue
        if _NAMED.search(p):
            bad.append((p, "path names the auditor"))
            continue
        try:
            with open(os.path.join(root, p), "rb") as fh:
                body = fh.read()
        except OSError:
            continue
        if AGENT.encode() in body:
            bad.append((p, "refers to %s" % AGENT))
    return bad


def main(argv):
    root = argv[argv.index("--root") + 1] if "--root" in argv else "."
    # each path verbatim, only the line terminator removed: "bin/patch-decide.py " is another file (Codex r1 B1)
    paths = [ln[:-1] if ln.endswith("\n") else ln for ln in sys.stdin]
    bad = offenders([p for p in paths if p], root)
    for p, why in bad:
        print("::error file=%s::auditor-related file outside %s (%s) — move it under %s "
              "(REQ-AUD-18 AC1)" % (p, AGENT, why, AGENT))
    if bad:
        return 1
    print("auditor layout: everything auditor-related is under %s (exemptions: %d)"
          % (AGENT, len(EXEMPT)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
