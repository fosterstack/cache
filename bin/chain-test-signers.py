"""Shared by bin/chain-sign-wiring-test.sh and bin/chain-records-test.sh (test infrastructure, not product code): the one
engine that finds signing calls, so the two judges cannot disagree about what a signer is (REQ-CHAIN-001-AC1, REQ-CHAIN-003-AC3).
Table: bin/chain-test-signers.json. `prov` is: never | always | if:<regex on the logical command line> | unless:<regex>
(provenance unless the line matches the regex: FAIL CLOSED for signers whose type may be a variable or absent).
Comments: a full-line comment goes; a trailing `# ...` goes only when the quotes before it are balanced on that line, otherwise
the line is kept whole (fail closed: `echo "step #1"; cosign sign` keeps its signer). Modelled on: in-toto-witness
options/run.go:64 (attestations flag forms), docs/commands.md."""
import json, os, re

def load_table(path=None):
    return json.load(open(path or os.environ["CHAIN_SIGNER_TABLE"]))["signers"]

def strip_line(l):
    if l.lstrip().startswith("#"):
        return ""
    sq = dq = False
    for i, ch in enumerate(l):
        if ch == "\\" : continue
        if ch == "'" and not dq: sq = not sq
        elif ch == '"' and not sq: dq = not dq
        elif ch == "#" and not sq and not dq and i > 0 and l[i - 1].isspace():
            return l[:i]
    if sq or dq:                       # unbalanced quotes on this line: do not guess where a comment starts
        return l
    return l

def strip(text):
    return "\n".join(strip_line(l) for l in text.splitlines())

def logical(text):
    return re.sub(r"\\\n\s*", " ", text)

def is_prov(e, line):
    p = e["prov"]
    if p == "always": return True
    if p == "never": return False
    if p.startswith("if:"): return re.search(p[3:], line, re.I) is not None
    if p.startswith("unless:"): return re.search(p[7:], line, re.I) is None
    raise ValueError("bad prov " + p)

def signer_calls(text, table):
    """[(entry, is_provenance, logical line)] for every signing call in comment-stripped text."""
    res = []
    for line in logical(strip(text)).splitlines():
        for e in table:
            if re.search(e["regex"], line):
                res.append((e, is_prov(e, line), line.strip()))
    return res

# files a workflow can run: shell, python, node, ruby, perl; `make` runs the Makefile
RUNNER = re.compile(r"(?:\b(?:bash|sh|python3?|node|ruby|perl|source)\s+|(?<![\w/.-])\.\s+|(?<![\w/.-]))(\.?/?(?:[\w.-]+/)*[\w.-]+\.(?:sh|py|js|mjs|cjs|rb|pl))\b")
MAKE = re.compile(r"(?<![\w./-])make\b")

def script_refs(text):
    refs = [os.path.normpath(m.group(1)) for m in RUNNER.finditer(logical(strip(text)))]
    if MAKE.search(logical(strip(text))): refs.append("Makefile")
    return refs
