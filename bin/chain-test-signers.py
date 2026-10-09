"""Shared by bin/chain-sign-wiring-test.sh and bin/chain-records-test.sh (test infrastructure, not product code): the one
engine that finds signing calls and the scripts a workflow reaches, so the two judges cannot disagree about what a signer is
(REQ-CHAIN-001-AC1, REQ-CHAIN-003-AC3).
Table: bin/chain-test-signers.json. `prov` is: never | always | if:<regex on the command context> | unless:<regex> |
fn:<resolver> (witness_run | actions_attest | cosign_attest | sign_blob: look at the whole command, FAIL CLOSED when the type or
attestor list cannot be read literally).
Comments: a full-line comment goes; a trailing `# ...` goes only when the quotes before it are balanced on that line, otherwise
the line is kept whole (fail closed: `echo "step #1"; cosign sign` keeps its signer).
Command context (round 5): a signing call is judged on its logical line (backslash continuations joined) PLUS the following lines
that continue it: a next line that starts with a flag (YAML folded scalar `run: >-`), or when the line so far ends with a flag
or a comma (`-a` / value on the next line); for a YAML step (`uses: actions/attest@...`) the whole step block up to the next
`- ` list item, so `with: predicate-type:` on a later line is read.
Scripts (round 5): every file a workflow or composite action runs is found with `reachable_scripts` (bash/sh/python/node/ruby/
perl/source/`.` plus a path, ./path with or without an extension if it starts with `#!`, $GITHUB_WORKSPACE and
${{ github.workspace }} prefixes, `cd dir && ./x.sh`, `python -m pkg.mod`, `make` -> Makefile, and scripts that call other
scripts, transitively: the scripts they call are judged STRICTLY too, round 6). A reference that looks like a script path but cannot be resolved is an ERROR naming the workflow (fail
closed), never skipped. Stated exclusion: a bare `./name` with no extension that is not a file in the tree is taken to be a built
binary and ignored. Modelled on: in-toto-witness options/run.go:64 (attestations flag forms), docs/commands.md."""
import json, os, re

def load_table(path=None):
    return json.load(open(path or os.environ["CHAIN_SIGNER_TABLE"]))["signers"]

def strip_line(l):
    if l.lstrip().startswith("#"):
        return ""
    sq = dq = False
    for i, ch in enumerate(l):
        if ch == "\\": continue
        if ch == "'" and not dq: sq = not sq
        elif ch == '"' and not sq: dq = not dq
        elif ch == "#" and not sq and not dq and i > 0 and l[i - 1].isspace():
            return l[:i]
    return l                                  # unbalanced quotes: do not guess where a comment starts

def strip(text):
    return "\n".join(strip_line(l) for l in text.splitlines())

def logical(text):
    return re.sub(r"\\\n\s*", " ", text)

STEP_START = re.compile(r"^\s*-\s")
FLAG_START = re.compile(r"^\s*--?[A-Za-z]")
ENDS_FLAG = re.compile(r"(?:\s-[A-Za-z]|\s--[\w-]+|,)\s*$")

def context(lines, i, kind="shell"):
    """The command context of lines[i]: the line plus what continues it."""
    ctx = lines[i]
    if kind == "step":
        j = i + 1
        while j < len(lines) and not STEP_START.match(lines[j]) and j < i + 40:
            ctx += " " + lines[j].strip(); j += 1
        return ctx
    j = i + 1
    while j < len(lines) and j < i + 12 and (FLAG_START.match(lines[j]) or ENDS_FLAG.search(ctx)) and not STEP_START.match(lines[j]):
        ctx += " " + lines[j].strip(); j += 1
    return ctx

# ---- resolvers ---------------------------------------------------------------------------------------------------------
UNRESOLVED = re.compile(r"[$`]|\{\{")

def witness_attestors(ctx):
    """[(value, literal)] for every -a/--attestations/--attestor(s) in a witness run command, every flag form."""
    out = []
    for m in re.finditer(r"(?:^|\s)(?:-a[ =]?|--attestations?[ =]|--attestors?[ =])(\"[^\"]*\"|'[^']*'|[^\s]*)", ctx):
        v = m.group(1).strip("\"'")
        out.append((v, not (UNRESOLVED.search(m.group(1)) or v == "" or v.endswith(","))))
    return out

def witness_run_is_prov(ctx):
    if re.search(r"(?:^|\s)(?:-c[ =]|--config[ =])", ctx): return True      # a config file can list the slsa attestor
    for v, lit in witness_attestors(ctx):
        if not lit or "slsa" in v.lower(): return True
    return False

NONPROV_TYPES = {"spdx", "spdxjson", "cyclonedx", "vuln", "openvex", "link"}

def cosign_types(ctx):
    return [m.group(1).strip("\"'") for m in re.finditer(r"--type[ =]+(\"[^\"]*\"|'[^']*'|\S+)", ctx)]

def type_is_nonprov(v):
    if UNRESOLVED.search(v): return False
    if v in NONPROV_TYPES: return True
    return re.fullmatch(r"https?://(?!slsa\.dev/provenance)\S+", v) is not None

def cosign_attest_is_prov(ctx):
    ts = cosign_types(ctx)
    return not ts or not all(type_is_nonprov(t) for t in ts)             # no type, or ANY type that is not a literal non-provenance one

def attest_action_type(ctx):
    """predicate-type of an actions/attest step block: the literal, or None when absent or not literal."""
    m = re.search(r"predicate-type:\s*(\"[^\"]*\"|'[^']*'|\S+)", ctx)
    if not m: return None
    v = m.group(1).strip("\"'")
    return None if UNRESOLVED.search(v) or not re.fullmatch(r"https?://\S+", v) else v

def attest_action_is_prov(ctx):
    t = attest_action_type(ctx)
    return t is None or "slsa.dev/provenance" in t

def sign_blob_is_prov(ctx):
    return re.search(r"provenance|slsa|intoto|\.intoto", ctx, re.I) is not None

RESOLVERS = {"witness_run": witness_run_is_prov, "actions_attest": attest_action_is_prov,
             "cosign_attest": cosign_attest_is_prov, "sign_blob": sign_blob_is_prov}

def is_prov(e, ctx):
    p = e["prov"]
    if p == "always": return True
    if p == "never": return False
    if p.startswith("if:"): return re.search(p[3:], ctx, re.I) is not None
    if p.startswith("unless:"): return re.search(p[7:], ctx, re.I) is None
    if p.startswith("fn:"): return RESOLVERS[p[3:]](ctx)
    raise ValueError("bad prov " + p)

def calls(text, table):
    """[(entry, ctx)] for every signing call in comment-stripped text, ctx = the command context."""
    lines = logical(strip(text)).splitlines()
    res = []
    for i, line in enumerate(lines):
        for e in table:
            if re.search(e["regex"], line):
                res.append((e, context(lines, i, e.get("kind", "shell"))))
    return res

def signer_calls(text, table):
    """[(entry, is_provenance, command context)] for every signing call."""
    return [(e, is_prov(e, ctx), ctx.strip()) for e, ctx in calls(text, table)]

# ---- scripts a workflow reaches ----------------------------------------------------------------------------------------
INTERP = {"bash", "sh", "dash", "zsh", "python", "python3", "node", "ruby", "perl", "source", "."}
EXTS = (".sh", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".bash")
WS = re.compile(r"\$\{GITHUB_WORKSPACE\}|\$GITHUB_WORKSPACE|\$\{\{\s*github\.workspace\s*\}\}")
OWN = re.compile(r"\$\(dirname\s+\"?\$\{?(?:0|BASH_SOURCE(?:\[0\])?)\}?\"?\)|\$\{?SCRIPT_DIR\}?|\$\{?(?:ROOT|REPO_ROOT)\}?")

def _tokens(line):
    return [m.group(0) for m in re.finditer(r"[^\s;&|()<>]+", line)]

def _cmdstart(line):
    """The set of token indexes that start a command (line start, or after ; && || | ( $( ` )."""
    out, k = set(), 0
    for m in re.finditer(r"[^\s;&|()<>]+", line):
        before = line[:m.start()].rstrip()
        if not before or before[-1] in ";&|(`" or before.endswith("$("): out.add(k)
        k += 1
    return out

def _find_by_basename(base, name):
    hits = []
    for dp, dn, fn in os.walk(base):
        dn[:] = [d for d in dn if d not in (".git", "node_modules")]
        if name in fn: hits.append(os.path.relpath(os.path.join(dp, name), base))
    return hits

def _is_script_file(base, rel):
    full = os.path.join(base, rel)
    if not os.path.isfile(full): return False
    if rel.endswith(EXTS) or os.path.basename(rel) == "Makefile": return True
    try: return open(full, "rb").read(2) == b"#!"
    except OSError: return False

def without_heredocs(text):
    out, end = [], None
    for l in text.splitlines():
        if end is not None:
            if l.strip() == end: end = None
            continue
        out.append(l)
        m = re.search(r"<<-?\s*[\"']?(\w+)[\"']?", l)
        if m: end = m.group(1)
    return "\n".join(out)

RUNTIME = re.compile(r"^\$\{?(?:RUNNER_TEMP|RUNNER_TOOL_CACHE|HOME|GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT|TMPDIR)\}?/|^/(?:tmp|usr|opt|home|var|dev|proc|sys|etc)/")

def script_refs_ex(base, text, owndir=None, strict=True):
    """(set of repo-relative script paths, [error strings]) for the scripts one file runs."""
    refs, errs = set(), []
    for line in logical(without_heredocs(strip(text))).splitlines():
        cd = None
        for m in re.finditer(r"\bcd\s+(\S+)\s*(?:&&|;)", line):
            c = m.group(1).strip("\"'")
            cd = None if UNRESOLVED.search(WS.sub("", c)) else WS.sub("", c).lstrip("/")
        toks = _tokens(line); starts = _cmdstart(line)
        for i, t in enumerate(toks):
            cand, is_interp = None, False
            if t in INTERP and (t not in ("source", ".") or i in starts):
                j = i + 1
                if t.startswith("python") and j + 1 < len(toks) and toks[j] == "-m":
                    mod = toks[j + 1].strip("\"'")
                    paths = [mod.replace(".", "/") + ".py", mod.replace(".", "/") + "/__main__.py"]
                    found = [p for p in paths if os.path.isfile(os.path.join(base, p))]
                    top = mod.split(".")[0]
                    if found: refs.update(found)
                    elif os.path.exists(os.path.join(base, top)) or os.path.exists(os.path.join(base, top + ".py")):
                        errs.append("unresolved `python -m %s` (the package is in the tree but %s is not)" % (mod, " or ".join(paths)))
                    # else: an installed module (pip, venv, a third-party tool): stated exclusion
                    continue
                while j < len(toks) and toks[j].startswith("-"):
                    if toks[j] in ("-c", "-e", "-E", "-"): j = len(toks)       # inline code: no script file to find
                    else: j += 1
                if j < len(toks): cand, is_interp = toks[j].strip("\"'"), True
            elif t.startswith(("./", "../")) or t.endswith(EXTS) or t.strip("\"'").endswith(EXTS):
                cand = t.strip("\"'")
            if cand is None: continue
            cand = re.sub(r"^[A-Za-z_]\w*=", "", cand).strip("\"'")
            if cand in EXTS or cand.startswith("\\") or len(os.path.basename(cand)) <= 3 and cand.endswith(EXTS): continue
            shaped = ("/" in cand or cand.endswith(EXTS) or bool(UNRESOLVED.search(cand)) or bool(OWN.search(cand))) and not cand.startswith(("<", "-"))
            if not shaped or re.search(r"[*?\[]", cand) or RUNTIME.match(cand) or os.path.basename(cand) == "chain-verify.py": continue
            c = cand
            if OWN.search(c):
                if owndir is None:
                    if strict: errs.append("unresolved script path %r (relative to the script's own directory, but a workflow has none)" % cand)
                    continue
                c = OWN.sub(owndir, c)
            c = WS.sub("", c)
            if UNRESOLVED.search(c):
                hit = [p for p in _find_by_basename(base, os.path.basename(c)) if _is_script_file(base, p)] if not UNRESOLVED.search(os.path.basename(c)) else []
                if hit: refs.update(hit)
                elif strict: errs.append("unresolved script path %r (a variable or expression with no file of that name in the tree: fail closed)" % cand)
                continue
            c = c.lstrip("/") if cand.startswith(("$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE", "${{")) else c
            paths = [os.path.normpath(os.path.join(cd, c))] if cd else []
            paths.append(os.path.normpath(c))
            hit = [p for p in paths if _is_script_file(base, p)]
            if not hit:
                hit = [p for p in _find_by_basename(base, os.path.basename(c)) if _is_script_file(base, p)]
            if hit: refs.update(hit)
            elif strict and (is_interp or c.endswith(EXTS)):
                errs.append("unresolved script reference %r (no such file in the tree)" % cand)
            # else: a bare ./name without an extension that is not in the tree is a built binary: stated exclusion
        if re.search(r"(?<![\w./-])make\b", line):
            mm = re.search(r"make\s+(?:-\w+\s+)*-C\s+(\S+)", line)
            mk = os.path.join(mm.group(1), "Makefile") if mm else "Makefile"
            if os.path.isfile(os.path.join(base, mk)): refs.add(mk)
            elif mm: errs.append("make -C names a directory with no %s in the tree" % mk)
    return refs, errs

TEST_WORKFLOWS = {".github/workflows/ci.yml"}

def is_test_script(sp):
    return os.path.basename(sp).endswith("-test.sh") or sp.startswith(".github/agent/tests/")

def reachable_scripts(base, texts):
    """texts: {relpath of a workflow/action file: its text}. Returns ({script relpath: {who}}, [errors naming the file]).
    Round 6: scripts called by scripts are judged STRICTLY (an unresolved reference is an error). The one carve-out: a TEST script
    (`*-test.sh`, `.github/agent/tests/*`) that is reached ONLY from ci.yml (the workflow that runs the tests) may build
    throw-away scripts at run time ($work/x.py, $sut): its unresolved references are not errors. The same script reached from
    any other workflow (a stage file, release.yml) is judged strictly, and a non-test script is always judged strictly."""
    found, errs, queue, serrs, roots = {}, [], [], {}, {}
    for rel, txt in sorted(texts.items()):
        refs, e = script_refs_ex(base, txt)
        errs += ["%s: %s" % (rel, x) for x in e]
        for r in refs:
            found.setdefault(r, set()).add(rel); roots.setdefault(r, set()).add(rel); queue.append(r)
    seen = set()
    while queue:
        sp = queue.pop()
        if sp in seen or sp == "bin/chain-verify.py": continue
        seen.add(sp)
        try: txt = open(os.path.join(base, sp), errors="replace").read()
        except OSError: continue
        if not (sp.endswith((".sh", ".bash")) or txt.startswith(("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/env sh"))):
            continue                          # python/js/ruby source is scanned for signing calls but not tokenised for further scripts (stated exclusion)
        refs, e = script_refs_ex(base, txt, owndir=os.path.dirname(sp) or ".", strict=True)
        serrs[sp] = e
        for r in refs:
            found.setdefault(r, set()).add(sp)
            if r not in seen: queue.append(r)
    grow = True
    while grow:                               # which workflows reach each script, transitively
        grow = False
        for sp, who in found.items():
            for w in list(who):
                for rr in roots.get(w, set()) if w in roots else ([w] if w in texts else []):
                    if rr not in roots.setdefault(sp, set()): roots[sp].add(rr); grow = True
    for sp, e in serrs.items():
        if is_test_script(sp) and roots.get(sp, set()) <= TEST_WORKFLOWS: continue
        errs += ["%s (run by %s): %s" % (sp, ", ".join(sorted(found.get(sp, []))), x) for x in e]
    return found, errs
