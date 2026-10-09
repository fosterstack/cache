"""Shared by bin/chain-sign-wiring-test.sh and bin/chain-records-test.sh (test infrastructure, not product code).
Two small things, and nothing else:
 (1) the ONE table of signing tools (bin/chain-test-signers.json) with the direct-signer-call finder, so the two judges cannot
     disagree about what a signer is (REQ-CHAIN-001-AC1, REQ-CHAIN-003-AC3). A direct call is found in comment-stripped text.
     `prov` is: never | always | if:<regex on the command context> | unless:<regex> | fn:<resolver> (witness_run |
     actions_attest | cosign_attest | sign_blob: look at the whole command, FAIL CLOSED when the type or attestor list cannot be
     read literally). A trailing `# ...` goes only when the quotes before it are balanced on that line (`echo "step #1"; cosign
     sign` keeps its signer).
 (2) the stage-file GRAMMAR (advisor decision b, Oct 9; finite grammar; replaces the script-reach scan of rounds 4-11): the engine no
     longer tries to work out what a shell might reach. A release-chain stage file may only run what a committed allowlist names:
       .github/policy/chain-scripts.json  {"env_names":[...],"scripts":[{"path","sha256","tools":[...],"signs":false|"provenance"|"other",
                                                      "runs":[listed paths it may start],"reason"}]}
     * KEYS are closed at workflow (name, on, permissions, jobs), job (name, needs, if, runs-on, permissions, steps, outputs,
       timeout-minutes, strategy.matrix of literal labels, environment) and step level (name, id, uses, with, run, env, if,
       timeout-minutes). No defaults, container, services, shell, working-directory, workflow/job env, continue-on-error.
     * step env: names come from the closed `env_names` list, never BASH_ENV/ENV/PATH/LD_*/PYTHON*/NODE_*/GITHUB_*, and each is read
       whole ("$NAME") by that step's run text. Nothing names GITHUB_ENV/GITHUB_PATH/GITHUB_OUTPUT.
     * step `uses` is a closed list: a digest-pinned actions/checkout (persist-credentials: false, no ref/repository/path/token),
       actions/download-artifact (explicit path that cannot overwrite a listed script, bin/ or .github/) and actions/upload-artifact.
       No local composite action, no docker://, no github-script, no job-level `uses`.
     * every `run:` line is exactly one of: `set -euo pipefail`; `bash PATH ARGS`; `python3 PATH ARGS`; `printf '%s' "$NAME" >
       digests.json` (the ONE write the Sign job needs; any other line starting with printf is an error); PATH is a plain relative
       literal that is LISTED, with the sha256 the file has; ARGS are literal words or a whole "$NAME" read of the step's env:.
       Anything else at command position is an ERROR naming the file and line.
     * a LISTED script is not parsed. scan_script is a conservative TEXT scan over the raw file (any extension or shebang): a command
       from the finite DENY list not in its `tools`; another script not in its `runs`; `witness run ... --` followed by anything but a
       literal path in `runs`; setting PATH/BASH_ENV/LD_*/PYTHON*... Its signing calls are judged from the row's `signs` on the raw
       text (comments, quotes and heredocs included). `provenance` is allowed only for a script that stage-sign.yml alone runs.
       STATED EXCLUSION: a command or script path built at run time inside a listed script is not detected; listed scripts are
       committed, sha256-bound and reviewed at PR time (row 78). Python/JS argv-array signers and downloaded binaries likewise.
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

def calls(text, table, strip_comments=True):
    """[(entry, ctx)] for every signing call, ctx = the command context. Comments are stripped unless strip_comments is False (a
    LISTED script is scanned raw: a signer name inside a comment, quote or heredoc counts, the scan over-reports by design)."""
    lines = logical(strip(text) if strip_comments else text).splitlines()
    res = []
    for i, line in enumerate(lines):
        for e in table:
            if re.search(e["regex"], line):
                res.append((e, context(lines, i, e.get("kind", "shell"))))
    return res

def signer_calls(text, table, strip_comments=True):
    """[(entry, is_provenance, command context)] for every signing call."""
    return [(e, is_prov(e, ctx), ctx.strip()) for e, ctx in calls(text, table, strip_comments)]

# ---- the stage-file grammar ---------------------------------------------------------------------------------------------
import hashlib

SCRIPT_EXTS = (".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl")
LITERAL_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*")
LIT_WORD = re.compile(r"[A-Za-z0-9_./:=@%+,-]+")
ENV_OK = re.compile(r"(GITHUB|RUNNER)_[A-Z_]+")                  # READS of these are fine; they may never be SET in env:
FORBID_ENV = re.compile(r"(BASH_ENV|ENV|PATH|LD_[A-Z0-9_]*|PYTHON[A-Z0-9_]*|NODE_[A-Z_]*|IFS|SHELL|SHELLOPTS|BASHOPTS|BASH_[A-Z_]*|CDPATH|"
                        r"PS4|PROMPT_COMMAND|HOME|TMPDIR|GIT_[A-Z_]*|GITHUB_[A-Z_]*|RUNNER_[A-Z_]*|LC_[A-Z_]*|LANG|USER|"
                        r"RUBY[A-Z_]*|PERL[A-Z0-9_]*|CLASSPATH|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS)")
SIGNS = (False, "provenance", "other")
INTERPRETERS = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "node", "ruby", "perl", "source", "eval", "exec",
                "make", "gmake", "xargs", "run-parts", "npm", "yarn", "pnpm", "just", "task", "parallel", "env", "sudo", "nohup",
                "timeout", "nice", "command", "builtin", "watch", "at", "find"}
# commands a listed script may NOT name unless its row lists them in `tools` (a finite list of the usual ways out, not a parser)
DENY = INTERPRETERS | {"curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "socat", "gh", "git",
                       "docker", "podman", "kubectl", "aws", "gcloud", "az", "terraform", "pip", "pip3", "go", "cargo", "apt",
                       "apt-get", "dpkg", "su", "trap", "crontab", "systemd-run", "script"}
STAGE_WF_KEYS = {"name", "on", "permissions", "jobs"}
STAGE_JOB_KEYS = {"name", "needs", "if", "runs-on", "permissions", "steps", "outputs", "timeout-minutes", "strategy", "environment"}
STAGE_STEP_KEYS = {"name", "id", "uses", "with", "run", "env", "if", "timeout-minutes"}
RUNS_ON = re.compile(r"ubuntu-[0-9.]+(-arm)?|ubuntu-latest|\$\{\{ ?matrix\.[A-Za-z_][\w-]* ?\}\}")
MATRIX_LIT = re.compile(r"[A-Za-z0-9_.-]+")
USES_OK = re.compile(r"actions/(checkout|download-artifact|upload-artifact)@([0-9a-f]{40})")

def load_scripts(base):
    """(rows by path, [errors], env_names) from .github/policy/chain-scripts.json, every row validated against the tree.
    env_names is the closed set of names a stage step may put in env: (never BASH_ENV, PATH, LD_*, PYTHON*, ...)."""
    f = os.path.join(base, ".github/policy/chain-scripts.json")
    if not os.path.exists(f):
        return {}, ["missing .github/policy/chain-scripts.json (the scripts a release-chain stage file may run, by path and sha256)"], set()
    errs, rows = [], {}
    try:
        doc = json.load(open(f))
        data = doc.get("scripts")
    except Exception as e:
        return {}, ["chain-scripts.json does not parse: %s" % e], set()
    if not isinstance(data, list):
        return {}, ["chain-scripts.json has no `scripts` list"], set()
    names = doc.get("env_names", [])
    env_names = set()
    if not isinstance(names, list): errs.append("chain-scripts.json: env_names must be a list")
    else:
        for n in names:
            if not isinstance(n, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", n) or FORBID_ENV.fullmatch(n):
                errs.append("chain-scripts.json: env_names has %r, which is not an allowed variable name (never BASH_ENV, PATH, LD_*, PYTHON*, NODE_*, GITHUB_*, ...)" % (n,))
            else: env_names.add(n)
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
    return rows, errs, env_names

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

PRINTF_OK = re.compile(r"printf '%s' \"\$(\w+)\" > digests\.json")

def check_run(run, envnames, rows):
    """Grammar errors (list of 'line N: ...') for one stage-file `run:` text; also returns the listed paths it runs."""
    errs, ran = [], []
    if re.search(r"GITHUB_(ENV|PATH|OUTPUT|STEP_SUMMARY)", run):
        errs.append("a stage run step names GITHUB_ENV, GITHUB_PATH, GITHUB_OUTPUT or GITHUB_STEP_SUMMARY (nothing may be written into the job's environment, path or outputs)")
    lines = logical(strip(run)).splitlines()
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line: continue
        if line == "set -euo pipefail": continue
        if line.startswith("printf"):                   # the one write: an env var into digests.json; ANYTHING else starting with printf is an error
            m = PRINTF_OK.fullmatch(line)
            if not m: errs.append("line %d: %s: a printf line must be exactly printf '%%s' \"$NAME\" > digests.json (the one write the Sign job needs)" % (n, line[:90]))
            elif m.group(1) not in envnames: errs.append("line %d: printf of $%s, which is not in this step's env:" % (n, m.group(1)))
            continue
        words, err = _words(line)
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

def _lit_leaves(x):
    if isinstance(x, dict): return [v for k in x for v in _lit_leaves(x[k])]
    if isinstance(x, list): return [v for e in x for v in _lit_leaves(e)]
    return [x]

def _artifact_path_error(p, rows, download):
    if not isinstance(p, str) or not p.strip(): return "needs an explicit literal `path`"
    for ln in p.splitlines():
        ln = ln.strip()
        if not ln: continue
        if re.search(r"[$`*?\[{]|\.\.", ln) or ln.startswith("/") or ln in (".", "./"): return "path %r is not a plain relative literal" % ln
        q = ln.rstrip("/")
        if download:
            if q == "bin" or q.startswith("bin/") or q.startswith(".github") or q.startswith("./"):
                return "downloads into %r, which is where the repository's scripts and policy live" % ln
            for L in rows:
                if L == q or L.startswith(q + "/"): return "downloads into %r, over the listed script %s" % (ln, L)
    return None

def stage_grammar(rel, d, rows, env_names=frozenset()):
    """(errors, listed paths run) for a parsed stage workflow file (YAML via the caller). The grammar is FINITE over keys:
    workflow, job and step keys come from closed sets; step `uses` from a closed list; env names from a closed set; the run
    lines from the grammar of check_run."""
    errs, ran = [], []
    extra = set(d) - STAGE_WF_KEYS
    if extra: errs.append("%s: workflow keys %s are not allowed in a stage file (env, defaults, concurrency, run-name can reroute every step)" % (rel, sorted(extra)))
    for jn, j in ((d.get("jobs") or {}).items()):
        pre = "%s job %s" % (rel, jn)
        extra = set(j) - STAGE_JOB_KEYS
        if extra: errs.append("%s: job keys %s are not allowed (container, services, defaults, env, uses, secrets, with run other code or reroute steps)" % (pre, sorted(extra)))
        ro = j.get("runs-on")
        if ro is not None and (not isinstance(ro, str) or not RUNS_ON.fullmatch(ro)):
            errs.append("%s: runs-on %r is not a GitHub-hosted ubuntu runner or a matrix read" % (pre, ro))
        st = j.get("strategy")
        if st is not None:
            if not isinstance(st, dict) or set(st) - {"matrix", "fail-fast", "max-parallel"}: errs.append("%s: strategy may hold only matrix, fail-fast, max-parallel" % pre)
            else:
                for leaf in _lit_leaves(st.get("matrix") or {}):
                    if not isinstance(leaf, str) or not MATRIX_LIT.fullmatch(leaf): errs.append("%s: matrix value %r is not a literal runner label or name" % (pre, leaf))
        for s in (j.get("steps") or []):
            nm = s.get("name") or str(s.get("run") or s.get("uses") or "").strip().splitlines()[0][:40]
            sp = "%s step %r" % (pre, nm)
            extra = set(s) - STAGE_STEP_KEYS
            if extra: errs.append("%s: step keys %s are not allowed (shell, working-directory, continue-on-error reroute or hide the run)" % (sp, sorted(extra)))
            run, uses, env, w = s.get("run"), s.get("uses"), s.get("env") or {}, s.get("with") or {}
            if (run is None) == (uses is None): errs.append("%s: must have exactly one of run/uses" % sp); continue
            for k in env:
                if FORBID_ENV.fullmatch(k): errs.append("%s: env %s is never allowed (it can make a shell or interpreter load other code)" % (sp, k))
                elif k not in env_names: errs.append("%s: env %s is not in the closed env_names list of chain-scripts.json" % (sp, k))
            if uses is not None:
                if env: errs.append("%s: an action step passes env" % sp)
                m = USES_OK.fullmatch(str(uses).split(" #")[0].strip())
                if not m:
                    errs.append("%s: uses %r; a stage file may use only a digest-pinned actions/checkout, download-artifact or upload-artifact (no local composite action, docker://, github-script, reusable workflow)" % (sp, uses)); continue
                act = m.group(1)
                if act == "checkout":
                    if set(w) - {"persist-credentials", "fetch-depth"} or w.get("persist-credentials") != "false":
                        errs.append("%s: checkout may carry only persist-credentials: false (explicit) and fetch-depth (no ref, repository, path, token): %s" % (sp, w))
                elif act == "download-artifact":
                    if set(w) - {"name", "path", "pattern", "merge-multiple"}: errs.append("%s: download-artifact keys %s are not allowed" % (sp, sorted(set(w) - {"name", "path", "pattern", "merge-multiple"})))
                    e = _artifact_path_error(w.get("path"), rows, True)
                    if e: errs.append("%s: download-artifact %s" % (sp, e))
                else:
                    if set(w) - {"name", "path", "if-no-files-found", "retention-days"}: errs.append("%s: upload-artifact keys %s are not allowed" % (sp, sorted(set(w) - {"name", "path", "if-no-files-found", "retention-days"})))
                    e = _artifact_path_error(w.get("path"), rows, False)
                    if e: errs.append("%s: upload-artifact %s" % (sp, e))
                continue
            if w: errs.append("%s: a run step has `with`" % sp)
            for k in env:
                if not re.search(r"\"\$%s\"|\"\$\{%s\}\"" % (k, k), str(run)): errs.append("%s: env %s is not read whole (\"$%s\") by the step's run line" % (sp, k, k))
            e, r = check_run(str(run), set(env.keys()), rows)
            errs += ["%s: %s" % (sp, x) for x in e]; ran += r
    return errs, ran

ENV_SET = re.compile(r"(?<![\w$])(?:(?:export|local|readonly|typeset)\s+|declare\s+(?:-\w+\s+)?)?(PATH|BASH_ENV|ENV|LD_[A-Z0-9_]+|PYTHON[A-Z0-9_]*|NODE_OPTIONS|IFS|CDPATH|PROMPT_COMMAND|PS4|SHELLOPTS|BASHOPTS)\+?=")
LAUNCHER = re.compile(r"\bwitness\b[^\n]*?\brun\b(?P<rest>[^\n]*)")

def scan_script(path, text, row, rows, base):
    """Errors for one LISTED script. Not a shell parser: a conservative TEXT scan over the raw file whatever its extension or shebang
    (it over-reports by design): (a) a command from the finite DENY list (interpreters, source/eval/exec, make/xargs/find, curl/wget/ssh,
    gh/git/docker ...) anywhere in the text unless the row lists it in `tools`; (b) any token naming another script (a path ending
    in a script extension, or a file in the tree with a shebang, or a listed path) that is not the file itself and not in its `runs`;
    (c) `witness run ... --`: the first word after `--` must be a literal path in `runs` (never $@, "$@", $*, a variable or
    substitution); (d) setting PATH, BASH_ENV, ENV, LD_*, PYTHON*, NODE_OPTIONS, IFS ... anywhere. Signing calls are judged by the
    caller from the row's `signs` (raw text, comments and quotes included). Stated exclusion: a command or script path BUILT AT RUN
    TIME inside a listed script is not detected; listed scripts are committed, sha256-bound and reviewed at PR time (row 78)."""
    errs = []
    tools, runs = set(row.get("tools", [])), set(row.get("runs", []))
    runbase = {os.path.basename(r) for r in runs}
    selfbase = os.path.basename(path)
    body = text.split("\n", 1)[1] if text.startswith("#!") and "\n" in text else ("" if text.startswith("#!") else text)   # the shebang names the file's OWN interpreter
    for t in dict.fromkeys(re.findall(r"[^\s;&|(){}<>`\"'=,]+", body)):
        if t in DENY and t not in tools:
            errs.append("%s: names the command %r, which is not in this script's `tools` list" % (path, t))
        is_script = t.endswith(SCRIPT_EXTS) or t in rows
        if not is_script and "/" in t and not t.startswith(("-", "$")):
            full = os.path.join(base, t)
            if os.path.isfile(full):
                with open(full, "rb") as fh: is_script = fh.read(2) == b"#!"
        if is_script and t != path and os.path.basename(t) != selfbase and t not in runs and os.path.basename(t) not in runbase:
            errs.append("%s: names the script %r, which is not in this script's `runs` list" % (path, t))
    for m in ENV_SET.finditer(text):
        errs.append("%s: sets %s (it can make a shell, interpreter or tool load other code)" % (path, m.group(1)))
    for ln in logical(text).splitlines():
        m = LAUNCHER.search(ln)
        if not m: continue
        rest = m.group("rest")
        if " -- " not in rest + " " and not rest.rstrip().endswith("--"):
            errs.append("%s: `witness run` without `-- PATH` on the same logical line: %s" % (path, ln.strip()[:80])); continue
        after = (rest + " ").split(" -- ", 1)[1].strip() if " -- " in rest + " " else ""
        first = after.split()[0] if after.split() else ""
        if not LITERAL_PATH.fullmatch(first) or first not in runs:
            errs.append("%s: after `witness run --` the command %r is not a literal path in this script's `runs` list ($@, \"$@\", $*, a variable or a substitution is an error)" % (path, first))
    return errs
