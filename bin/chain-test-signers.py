"""Shared by bin/chain-sign-wiring-test.sh and bin/chain-records-test.sh (test infrastructure, not product code).
Two small things, and nothing else:
 (1) the ONE table of signing tools (bin/chain-test-signers.json) with the direct-signer-call finder, so the two judges cannot
     disagree about what a signer is (REQ-CHAIN-001-AC1, REQ-CHAIN-003-AC3). A direct call is found in comment-stripped text.
     `prov` is: never | always | if:<regex on the command context> | unless:<regex> | fn:<resolver> (witness_run |
     actions_attest | cosign_attest | sign_blob: look at the whole command, FAIL CLOSED when the type or attestor list cannot be
     read literally). A trailing `# ...` goes only when the quotes before it are balanced on that line (`echo "step #1"; cosign
     sign` keeps its signer).
 (2) the stage-file GRAMMAR (advisor decision, Oct 9, replaces the script-reach scan of rounds 4-11): the engine no longer tries to
     work out what a shell might reach (variables, globs, heredocs, make, xargs: an unbounded class, a new finding almost every
     review round). Instead a release-chain stage file may only run what a committed allowlist names:
       .github/policy/chain-scripts.json  {"scripts":[{"path","sha256","tools":[...],"signs":false|"provenance"|"other",
                                                      "runs":[listed paths it may start],"reason"}]}
     * every `run:` line of every stage-*.yml is exactly one of: `set -euo pipefail`; `bash PATH ARGS`; `python3 PATH ARGS`;
       `printf '%s' "$NAME" > FILE` (the one write the Sign job needs); PATH is a plain relative literal that is LISTED, with
       the sha256 the file has; ARGS are literal words, quoted literals, or a whole "$NAME"/"${NAME}" read of the step's env:.
       Anything else at command position (a variable, a glob, make, xargs, find, npm, run-parts, a pipe or `;`/`&&`, a direct
       tool such as cosign or gh, an unlisted or `..` path) is an ERROR naming the file and line.
     * a LISTED shell script may use only the commands in its `tools` list (plus shell builtins), may start no other script
       (the interpreters and `source`/`eval`/`exec`/`make`/`xargs`/`find -exec` are errors unless listed as tools, and a script
       path in it must be in its own `runs` list and itself listed), and its direct signing calls are judged by its `signs` value:
       `provenance` is allowed only for a script that stage-sign.yml alone runs. Python/JS scripts are scanned for direct signing
       calls only (stated exclusion: a signer reached through an argv array in script code or a binary downloaded at run time).
     * other workflows (ci.yml, scan.yml ...), composite actions and release.yml's non-stage jobs are NOT stage files: they keep only
       the direct signer-call scan (listed with a reason in .github/policy/chain-signers.json).
Modelled on: in-toto-witness options/run.go:64 (attestations flag forms), docs/commands.md."""
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

# ---- the stage-file grammar ---------------------------------------------------------------------------------------------
import hashlib

SHELL_EXTS = (".sh", ".bash")
SCRIPT_EXTS = (".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl")
LITERAL_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*")
LIT_WORD = re.compile(r"[A-Za-z0-9_./:=@%+,-]+")
ENV_OK = re.compile(r"(GITHUB|RUNNER)_[A-Z_]+")
SIGNS = (False, "provenance", "other")
INTERPRETERS = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "node", "ruby", "perl", "source", "eval", "exec",
                "make", "gmake", "xargs", "run-parts", "npm", "yarn", "pnpm", "just", "task", "parallel", "env", "sudo", "nohup",
                "timeout", "nice", "command", "builtin", "watch", "at"}
BUILTINS = {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in", "select", "function",
            "time", "{", "}", "!", "[", "[[", "]", "]]", "test", "echo", "printf", "cd", "set", "export", "unset", "local",
            "declare", "typeset", "readonly", "shift", "return", "exit", "true", "false", ":", "read", "trap", "wait", "getopts",
            "let", "umask", "pwd", "break", "continue", "type", "hash", "ulimit", "alias"}

def load_scripts(base):
    """(rows by path, [errors]) from .github/policy/chain-scripts.json, every row validated against the tree."""
    f = os.path.join(base, ".github/policy/chain-scripts.json")
    if not os.path.exists(f):
        return {}, ["missing .github/policy/chain-scripts.json (the scripts a release-chain stage file may run, by path and sha256)"]
    errs, rows = [], {}
    try:
        data = json.load(open(f)).get("scripts")
    except Exception as e:
        return {}, ["chain-scripts.json does not parse: %s" % e]
    if not isinstance(data, list):
        return {}, ["chain-scripts.json has no `scripts` list"]
    for r in data:
        p = r.get("path", "") if isinstance(r, dict) else ""
        if not isinstance(p, str) or not LITERAL_PATH.fullmatch(p) or ".." in p.split("/") or p.startswith("/"):
            errs.append("chain-scripts.json: bad path %r (a plain relative literal)" % (p,)); continue
        if p in rows: errs.append("chain-scripts.json: %s listed twice" % p); continue
        full = os.path.join(base, p)
        if not os.path.isfile(full): errs.append("chain-scripts.json: %s is not a file in the tree" % p); continue
        if hashlib.sha256(open(full, "rb").read()).hexdigest() != str(r.get("sha256", "")):
            errs.append("chain-scripts.json: %s has a different sha256 than the file (a changed script must change its row)" % p)
        if not isinstance(r.get("tools"), list) or not all(isinstance(t, str) and re.fullmatch(r"[A-Za-z0-9_.+-]+", t) for t in r["tools"]):
            errs.append("chain-scripts.json: %s `tools` must be a list of plain command names" % p)
        if r.get("signs", False) not in SIGNS:
            errs.append("chain-scripts.json: %s `signs` must be false, \"provenance\" or \"other\"" % p)
        if r.get("signs", False) and not str(r.get("reason") or "").strip():
            errs.append("chain-scripts.json: %s signs but has no reason" % p)
        if not isinstance(r.get("runs", []), list):
            errs.append("chain-scripts.json: %s `runs` must be a list" % p)
        rows[p] = r
    for p, r in rows.items():
        for q in r.get("runs", []) if isinstance(r.get("runs", []), list) else []:
            if q not in rows: errs.append("chain-scripts.json: %s runs %r, which is not listed" % (p, q))
    return rows, errs

def _words(line):
    """Tokenise one logical shell line into words; returns ([(raw, parts)], error|None). Anything the grammar does not
    allow unquoted (; & | < > ( ) { } ` $ * ? [ ~ ! # \\ and a newline) is an error, never guessed."""
    words, i, n = [], 0, len(line)
    while i < n:
        if line[i].isspace(): i += 1; continue
        parts, raw = [], ""
        while i < n and not line[i].isspace():
            c = line[i]
            if c == "'":
                j = line.find("'", i + 1)
                if j < 0: return words, "unterminated single quote"
                parts.append(("sq", line[i + 1:j])); raw += line[i:j + 1]; i = j + 1
            elif c == '"':
                j = i + 1
                while j < n and line[j] != '"':
                    if line[j] == "\\": return words, "a backslash inside double quotes"
                    j += 1
                if j >= n: return words, "unterminated double quote"
                parts.append(("dq", line[i + 1:j])); raw += line[i:j + 1]; i = j + 1
            elif c in ";&|<>(){}`$*?[~!#\\":
                return words, "the character %r at command position/arguments (only literals and whole \"$NAME\" reads are allowed)" % c
            else:
                j = i
                while j < n and not line[j].isspace() and line[j] not in "'\"" + ";&|<>(){}`$*?[~!#\\":
                    j += 1
                parts.append(("lit", line[i:j])); raw += line[i:j]; i = j
        words.append((raw, parts))
    return words, None

def _arg_error(parts, envnames):
    for kind, t in parts:
        if kind == "lit" and not LIT_WORD.fullmatch(t): return "argument %r is not a plain literal" % t
        if kind == "sq" and ("$" in t or "`" in t): return "single-quoted argument %r contains $ or a backtick" % t
        if kind == "dq":
            m = re.fullmatch(r"\$(\w+)|\$\{(\w+)\}", t)
            if m:
                nm = m.group(1) or m.group(2)
                if nm not in envnames and not ENV_OK.fullmatch(nm):
                    return "\"$%s\" is not a variable of this step's env: (only a whole read of the step's own env is allowed)" % nm
            elif "$" in t or "`" in t or "!" in t:
                return "double-quoted argument %r mixes text with a variable or substitution (use a whole \"$NAME\" from env:)" % t
    return None

def check_run(run, envnames, rows):
    """Grammar errors (list of 'line N: ...') for one stage-file `run:` text; also returns the listed paths it runs."""
    errs, ran = [], []
    lines = logical(strip(run)).splitlines()
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line: continue
        if line == "set -euo pipefail": continue
        words, err = _words(line) if not re.match(r"printf '%s' \"\$\w+\" > ", line) else (None, None)
        m = re.fullmatch(r"printf '%s' \"\$(\w+)\" > ([A-Za-z0-9_][A-Za-z0-9_./-]*)", line)
        if m:                                           # the one write: an env var into a literal file
            if m.group(1) not in envnames: errs.append("line %d: printf of $%s, which is not in this step's env:" % (n, m.group(1)))
            if ".." in m.group(2).split("/"): errs.append("line %d: the file name has `..`" % n)
            continue
        if err: errs.append("line %d: %s: %s" % (n, line[:90], err)); continue
        if not words: continue
        cmd = words[0][0]
        if cmd not in ("bash", "python3") or len(words) < 2:
            errs.append("line %d: %s: the command must be `bash PATH ...` or `python3 PATH ...` (found %r): a variable, glob, make, xargs, find, npm, a pipe or a direct tool is an error" % (n, line[:90], cmd)); continue
        pw = words[1]
        path = "".join(t for _, t in pw[1])
        if len(pw[1]) != 1 or pw[1][0][0] != "lit" or not LITERAL_PATH.fullmatch(path) or ".." in path.split("/"):
            errs.append("line %d: %s: the script path must be a plain relative literal (no variable, glob, quote or `..`)" % (n, line[:90])); continue
        if path not in rows:
            errs.append("line %d: %s: %s is not listed in .github/policy/chain-scripts.json" % (n, line[:90], path)); continue
        for rawa, parts in words[2:]:
            e = _arg_error(parts, envnames)
            if e: errs.append("line %d: %s: %s" % (n, line[:90], e))
        ran.append(path)
    return errs, ran

def stage_grammar(rel, d, rows):
    """(errors, listed paths run) for a parsed stage workflow file (YAML via the caller)."""
    errs, ran = [], []
    for jn, j in ((d.get("jobs") or {}).items()):
        for s in (j.get("steps") or []):
            run = s.get("run")
            if run is None: continue
            nm = s.get("name") or str(run).strip().splitlines()[0][:40]
            if str(s.get("shell", "bash")) not in ("bash", "bash -e {0}"): errs.append("%s job %s step %r: `shell: %s` is not bash" % (rel, jn, nm, s.get("shell")))
            if "working-directory" in s: errs.append("%s job %s step %r: working-directory reroutes every path" % (rel, jn, nm))
            e, r = check_run(str(run), set((s.get("env") or {}).keys()), rows)
            errs += ["%s job %s step %r: %s" % (rel, jn, nm, x) for x in e]; ran += r
    return errs, ran

def check_script(path, text, row, rows):
    """Errors for one LISTED script: shell scripts may use only their tools + builtins and start only their `runs`."""
    errs = []
    if not path.endswith(SHELL_EXTS) and not text.startswith(("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash", "#!/usr/bin/env sh")):
        return errs                                    # python/js: direct signing calls only (stated exclusion)
    tools, runs = set(row.get("tools", [])), set(row.get("runs", []))
    body = logical(strip(text))
    for n, line in enumerate(body.splitlines(), 1):
        if not line.strip(): continue
        # blank out quoted strings so `;` or a word inside them does not split or count as a command
        flat = re.sub(r"'[^']*'", "''", line)
        flat = re.sub(r'"((?:[^"\\]|\\.)*)"', lambda m: m.group(0) if ("$(" in m.group(1) or "`" in m.group(1)) else '""', flat)   # a substitution inside "..." still runs a command: keep it visible
        for seg in re.split(r"[;&|(){}`\n]|\$\(|\bthen\b|\bdo\b|\belse\b", flat):
            seg = re.sub(r"^\s*[^\s()]*\)\s*", "", seg)                 # a case pattern `a)`
            seg = re.sub(r"^\s*(?:[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=\S*\s+)*", "", seg)   # VAR=val prefixes
            w = seg.split()
            if not w: continue
            c = w[0]
            if c in BUILTINS or re.fullmatch(r"[A-Za-z_]\w*\+?=.*", c): continue
            if re.search(r"[$*?\[~]", c): errs.append("%s line %d: %r at command position is a variable, glob or expression" % (path, n, c)); continue
            if c in tools: continue
            errs.append("%s line %d: command %r is not in this script's `tools` list" % (path, n, c))
        # a script start anywhere in the line: interpreters/`source` as ANY word, or a path to a script
        for tok in re.findall(r"[^\s;&|(){}<>`\"']+", flat):
            t = tok.strip()
            if t in INTERPRETERS and t not in tools: errs.append("%s line %d: `%s` can start another script (not in `tools`)" % (path, n, t))
            elif t.endswith(SCRIPT_EXTS) or t.startswith("./") or t in rows:
                if t not in runs: errs.append("%s line %d: starts or names the script %r, which is not in this script's `runs` list" % (path, n, t))
    return errs
