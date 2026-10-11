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
     * every `run:` line is exactly one of: `set -euo pipefail`; `bash PATH ARGS`; `python3 -I [-B] PATH ARGS`; `printf '%s' "$NAME" >
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

def jload(path):
    """json.load that REFUSES a repeated object key at any depth (round 1 (6)): a plain reader keeps only the last of two equal keys, so the
    judged value need not be the one a reviewer read. ValueError names the file and the key. The ONE loader of the policy JSON files."""
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d: raise ValueError("%s: duplicate key %r (a JSON reader keeps only one of them)" % (path, k))
            d[k] = v
        return d
    with open(path) as fh:
        return json.load(fh, object_pairs_hook=hook)

def load_table(path=None):
    return jload(path or os.environ["CHAIN_SIGNER_TABLE"])["signers"]

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

class DuplicateKey(Exception): pass

def yload(text):
    """YAML as plain strings (BaseLoader) refusing a mapping key that repeats another of the same mapping, trimmed and case-folded, at any
    depth, and a key that is not a plain scalar (Codex #249 r4 B3a): BaseLoader alone keeps only the LAST of two equal keys, so the judged
    value need not be the one GitHub runs. The ONE loader of the chain test judges (wiring and hostile); PyYAML is imported only here, so
    the records judge, which reads text only, still needs none. bin/chain-verify.py keeps its own copy (it is a sealed product script)."""
    import yaml
    class NoDuplicateKeys(yaml.BaseLoader):
        def construct_mapping(self, mnode, deep=False):
            first = {}
            for key, _value in mnode.value:
                if not isinstance(key, yaml.ScalarNode):
                    raise DuplicateKey("a mapping key at line %d is not a plain scalar" % (key.start_mark.line + 1))
                norm = key.value.strip().casefold()
                if norm in first:
                    raise DuplicateKey("duplicate key %r at line %d repeats %r at line %d (a YAML reader keeps only one of them)"
                                       % (key.value, key.start_mark.line + 1, first[norm].value, first[norm].start_mark.line + 1))
                first[norm] = key
            return super().construct_mapping(mnode, deep)
    return yaml.load(text, Loader=NoDuplicateKeys)

def logical(text):
    """Join backslash-newline continuations exactly as bash does: the two characters are removed and NOTHING is inserted
    (Sonnet #249: `cos\\<newline>ign sign` is `cosign sign` to bash; joining with a space would hide it from the signer scan)."""
    return text.replace("\\\n", "")

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
    base = strip(text) if strip_comments else text
    # A continuation is joined three ways and every reading is scanned (the scan over-reports by design; Sonnet #249): as bash joins a
    # script (nothing inserted), as bash joins a YAML block scalar read from the raw file (the next line's indentation is YAML's, so it
    # goes too), and with a space (the reading before this fix). A signer split across a continuation is seen whichever file it is in.
    res, seen = [], set()
    for joined in (logical(base), re.sub(r"\\\n[ \t]*", "", base), re.sub(r"\\\n\s*", " ", base)):
        lines = joined.splitlines()
        for i, line in enumerate(lines):
            for e in table:
                if re.search(e["regex"], line):
                    ctx = context(lines, i, e.get("kind", "shell"))
                    if (e["name"], ctx.strip()) not in seen:
                        seen.add((e["name"], ctx.strip())); res.append((e, ctx))
    return res

def signer_calls(text, table, strip_comments=True):
    """[(entry, is_provenance, command context)] for every signing call."""
    return [(e, is_prov(e, ctx), ctx.strip()) for e, ctx in calls(text, table, strip_comments)]

# ---- the stage-file grammar ---------------------------------------------------------------------------------------------
import hashlib

SCRIPT_EXTS = (".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl")
LITERAL_PATH = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./-]*")
LIT_WORD = re.compile(r"[A-Za-z0-9_./-]+")                       # closed to what a stage line needs (Codex #249 r6 sweep); quote the rest
# Round 1 (2) + round 2 (3): the forbidden CLASS by shape, case-insensitively. A FAMILY is a PREFIX with any suffix, empty included, of letters,
# digits and underscores (GIT, GITHUB, RUNNER, NODE, PYTHON: GITASKPASS, GITHUBTOKEN, RUNNERX, NODERUNTIME, PYTHON3 are all members); LD_, BASH_, LC_,
# PS<digit> and the tool families need their separator. Exact names are listed whole.
FORBID_ENV = re.compile(r"(?:GIT.*|GITHUB.*|RUNNER.*|NODE.*|PYTHON.*|LD_.*|BASH_.*|LC_.*|PS[0-9].*|TERM.*|NPM_.*|BUNDLE_.*|GEM_.*|XDG_.*|"
                        r"SSL_CERT_.*|CURL.*|WITNESS.*|COSIGN.*|SIGSTORE.*|TUF_.*|RUBY.*|PERL.*|"
                        r"BASH_ENV|ENV|PATH|IFS|SHELL|SHELLOPTS|BASHOPTS|CDPATH|GLOBIGNORE|PROMPT_COMMAND|HOME|TMPDIR|LANG|USER|CLASSPATH|"
                        r"JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY|FTP_PROXY|GOFLAGS|GOPROXY|GOSUMDB|GONOSUMDB|"
                        r"GOTOOLCHAIN|GOPRIVATE|GONOPROXY|GOINSECURE|GOENV)",
                        re.IGNORECASE | re.DOTALL)
SIGNS = (False, "provenance", "other")
# PR 1b: the CLOSED list of rules a per-row `exceptions` entry may waive (extend only by a reviewed edit when a real text needs it)
# Round 2 (2): the ONE shape a pinned step may have (REQ-CHAIN-004-AC2): echo "NAME=$(jq -c . FILE)" >> "$GITHUB_OUTPUT"
PINNED_SHAPE = re.compile(r'echo "[a-z][a-z0-9_]*=\$\(jq -c \. ([A-Za-z0-9_][A-Za-z0-9_./-]*)\)" >> "\$GITHUB_OUTPUT"')
EXC_RULES = ("launcher", "evaluator", "deny", "script-name", "witness-target")
# PR 1b (B): the value an AMBIENT env name may carry: one whole plain expression (the job token, a workflow input or a matrix key) or a
# plain literal; never a secret, a glued expression or a substitution
AMBIENT_VALUE = re.compile(r"\$\{\{ ?(?:github\.token|inputs\.[A-Za-z_][\w-]*|matrix\.[A-Za-z_][\w-]*) ?\}\}|[A-Za-z0-9_./-]+")

# STATED LIMITS of the PR 1b mechanisms (round 1 (8)); none of them is closed by a judge of this kind:
#  - ambient reach is NAME-LEVEL: a listed script named as the step's script, as an ARGUMENT, or through the `runs` of either counts as run by
#    the step, so `bash bin/x.sh bin/adm.py` hands an ambient name listed for bin/adm.py to bin/x.sh as well; the step's env reaches every
#    process it starts, which no text judge can restrict to one script.
#  - a path or command name SPLIT by quoting or built at run time (`"dist"/sed`, `b''ash`, a variable) is not seen; the path-like word test reads
#    words as written.
#  - an exception waives ONE occurrence of exactly its rule and text; repeated invocations of one listed script belong in a `runs` row, not in
#    exceptions (a second occurrence of an excepted text stays a finding by design).
#  - a command text that crosses a backslash-newline is named by its JOINED text (bash joins with nothing inserted).
class EnvNames(set):
    """The closed `env_names` (a set of names) that also carries `.ambient`: {name: {listed script paths that read it from their own
    environment}} from the top-level `ambient_env` list of chain-scripts.json (PR 1b, B). A step env name that its run line does not read
    whole is allowed only through this map."""
    def __init__(self, *a):
        super().__init__(*a); self.ambient = {}; self.pinned = {}
INTERPRETERS = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3", "node", "ruby", "perl", "source", "eval", "exec",
                "make", "gmake", "xargs", "run-parts", "npm", "yarn", "pnpm", "just", "task", "parallel", "env", "sudo", "nohup",
                "timeout", "nice", "command", "builtin", "watch", "at", "find"}
# commands a listed script may NOT name unless its row lists them in `tools` (a finite list of the usual ways out, not a parser)
DENY = INTERPRETERS | {"curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp", "rsync", "ftp", "socat", "gh", "git",
                       "docker", "podman", "kubectl", "aws", "gcloud", "az", "terraform", "pip", "pip3", "go", "cargo", "apt",
                       "apt-get", "dpkg", "su", "trap", "crontab", "systemd-run", "script",
                       # final batch R-g: the evaluator words, seen ANYWHERE in a listed script's text (a trap handler, a string, an
                       # argument), unless the row's `tools` names the word
                       "awk", "gawk", "mawk", "nawk", "sed", "php", "lua", "tar"}
STAGE_WF_KEYS = {"name", "on", "permissions", "jobs"}
STAGE_JOB_KEYS = {"name", "needs", "if", "runs-on", "permissions", "steps", "outputs", "timeout-minutes", "strategy", "environment"}
STAGE_STEP_KEYS = {"name", "id", "uses", "with", "run", "env", "if", "timeout-minutes"}
HOSTED = re.compile(r"ubuntu-(22\.04|24\.04)(-arm)?|ubuntu-latest")  # CLOSED set of GitHub-hosted labels (Codex #249 r6 B5); extend only by a reviewed edit
MATRIX_READ = re.compile(r"\$\{\{ ?matrix\.([A-Za-z_][\w-]*) ?\}\}")  # the one expression runs-on may hold: a whole read of one matrix key
MATRIX_LIT = re.compile(r"[A-Za-z0-9_.-]+")
USES_OK = re.compile(r"actions/(checkout|download-artifact|upload-artifact)@([0-9a-f]{40})")

def action_files(base):
    """Every composite action file (action.yml / action.yaml, any case) anywhere in the tree (Opus #249 r6)."""
    out = []
    for dp, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x != ".git"]
        out += [os.path.join(dp, x) for x in fs if x.lower() in ("action.yml", "action.yaml")]
    return sorted(out)

def non_utf8_yaml(base):
    """Every .yml/.yaml file anywhere (outside .git) whose bytes are not valid UTF-8, as relative paths (final batch R-f): the judges
    report each by name and stop, instead of reading it with a traceback (GitHub refuses such a workflow too)."""
    out = []
    for dp, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x != ".git"]
        for x in fs:
            if not x.lower().endswith((".yml", ".yaml")): continue
            f = os.path.join(dp, x)
            try: open(f, "rb").read().decode("utf-8")
            except UnicodeDecodeError: out.append(os.path.relpath(f, base))
            except OSError: out.append(os.path.relpath(f, base))
    return sorted(out)

def signing_files(base, errs=None):
    """The ONE discovery routine of the chain judges (Codex #249 r7 B8, r8 B4; the wiring and records judges both use it, so they cannot
    drift): every .yml/.yaml under .github/workflows/ (any depth), every composite action file anywhere (any case), and every other
    .yml/.yaml anywhere (any case) whose PARSED root (duplicate-refusing loader: indentation, ---, comments, CRLF and flow style are the
    parser's business, not a text pattern's) is a mapping with a `jobs` or `runs` key. Fail closed: a candidate under .github/, or one
    whose text mentions a jobs:/runs: key, that does not parse is reported in `errs` (it cannot be classified, so it cannot be cleared)."""
    errs = [] if errs is None else errs
    wf = os.path.join(base, ".github", "workflows")
    gh = os.path.join(base, ".github")
    out = set(action_files(base))
    for dp, dirs, fs in os.walk(base):
        dirs[:] = [x for x in dirs if x != ".git"]
        for x in fs:
            if not x.lower().endswith((".yml", ".yaml")): continue
            f = os.path.join(dp, x)
            if os.path.commonpath([f, wf]) == wf: out.add(f); continue
            if f in out: continue
            try: text = open(f, errors="replace").read()
            except OSError: continue
            try: d = yload(text)
            except Exception as ex:
                if os.path.commonpath([f, gh]) == gh or re.search(r"[\"']?\b(?:jobs|runs)\b[\"']?\s*:", text):
                    errs.append("%s does not parse as one YAML mapping (%s), so it cannot be classified as a workflow or not (fail closed)" % (os.path.relpath(f, base), type(ex).__name__))
                continue
            if isinstance(d, dict) and ({"jobs", "runs"} & set(d)): out.add(f)
    return sorted(out)

def unresolved_signing(e, ctx):
    """Why a signing call's record type cannot be resolved from its text, or None (Codex #249 r7 B7: an explicit error, never an
    assumption). witness run: a config file (-c/--config), a WITNESS_* environment setting, or any attestor value that is not a literal.
    cosign sign-blob and sigstore (python) sign: an argument that is a variable, substitution or glob (the blob, and so its type,
    is unknown). The type-bearing calls (cosign attest --type, witness sign -t, actions/attest predicate-type) are resolved by the
    records judge itself and refused there when not literal."""
    n = e["name"]
    if n == "witness run":
        if re.search(r"(?:^|\s)(?:-c[ =]?|--config[ =])", ctx) or re.search(r"(?:^|[\s;])WITNESS_[A-Z_]*=", ctx):
            return "witness run with an unresolved attestor list (a config file or WITNESS_ setting) (fail closed)"
        if any(not lit for _v, lit in witness_attestors(ctx)):
            return "witness run with an unresolved attestor list (fail closed)"
    if n in ("cosign sign-blob", "sigstore python sign") and (UNRESOLVED.search(ctx) or re.search(r"[*?]", ctx)):
        return "%s with an unresolved argument (its blob, and so its type, cannot be known) (fail closed)" % n
    return None

def mentions_outside_comments(path, text, name):
    """Round 1 (7): does the script mention `name` as a word somewhere that can run? Shell: outside a `#` comment and not only inside a
    single-quoted string. Python (tokenize): outside comments, and not in a statement that is only a string (a docstring or bare string); a
    string that is part of code (os.environ.get("NAME")) counts. A script that does not tokenize counts as not mentioning (fail closed)."""
    pat = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(name))
    if not _is_python(path, text):
        return pat.search(re.sub(r"'[^']*'", "''", strip(text))) is not None
    import io, tokenize
    skip = {tokenize.COMMENT, tokenize.NL, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING}
    line = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in skip: continue
            if tok.type in (tokenize.NEWLINE, tokenize.ENDMARKER):
                if line and not all(t.type == tokenize.STRING for t in line):
                    if any(pat.search(t.string) for t in line): return True
                line = []; continue
            line.append(tok)
    except (tokenize.TokenError, SyntaxError):
        return False
    return False

def exception_entries(path, ex):
    """([valid entries], [errors]) for a row's `exceptions` (PR 1b): a list of objects with exactly rule, text and why; rule in EXC_RULES;
    text a non-empty string; why a non-blank string; no two entries with the same rule and text. Fail closed: an entry that is not valid is
    reported and never used."""
    if not isinstance(ex, list):
        return [], ["chain-scripts.json: %s `exceptions` must be a list of {rule, text, why}" % path]
    errs, good, seen = [], [], set()
    for e in ex:
        if not isinstance(e, dict) or set(e) != {"rule", "text", "why"}:
            errs.append("chain-scripts.json: %s exceptions entry %r must be an object with exactly rule, text and why" % (path, e)); continue
        rule, text, why = e["rule"], e["text"], e["why"]
        if not isinstance(rule, str) or rule not in EXC_RULES:
            errs.append("chain-scripts.json: %s exceptions entry has rule %r, which is not one of %s" % (path, rule, ", ".join(EXC_RULES))); continue
        if not isinstance(text, str) or not text.strip():
            errs.append("chain-scripts.json: %s exceptions entry (%s) needs a non-empty text string" % (path, rule)); continue
        if not isinstance(why, str) or not why.strip():
            errs.append("chain-scripts.json: %s exceptions entry %r (%s) has no reason (why)" % (path, text, rule)); continue
        if (rule, text) in seen:
            errs.append("chain-scripts.json: %s exceptions entry %r (%s) is listed twice" % (path, text, rule)); continue
        seen.add((rule, text)); good.append(e)
    return good, errs

def load_scripts(base):
    """(rows by path, [errors], env_names) from .github/policy/chain-scripts.json, every row validated against the tree.
    env_names is the closed set of names a stage step may put in env: (never BASH_ENV, PATH, LD_*, PYTHON*, ...)."""
    f = os.path.join(base, ".github/policy/chain-scripts.json")
    if not os.path.exists(f):
        return {}, ["missing .github/policy/chain-scripts.json (the scripts a release-chain stage file may run, by path and sha256)"], set()
    errs, rows = [], {}
    try:
        doc = jload(f)
        data = doc.get("scripts")
    except Exception as e:
        return {}, ["chain-scripts.json does not parse: %s" % e], set()
    if not isinstance(data, list):
        return {}, ["chain-scripts.json has no `scripts` list"], set()
    names = doc.get("env_names", [])
    env_names = EnvNames()
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
        em = r.get("env_mentions", [])
        if not isinstance(em, list) or not all(isinstance(e, dict) and set(e) == {"name", "text", "why"} and all(isinstance(e[k], str) for k in e) for e in em):
            errs.append("chain-scripts.json: %s `env_mentions` must be a list of {name, text, why} strings" % p)
        txt = open(full, errors="replace").read()
        if "reads_env" in r:
            re_ = r["reads_env"]
            if not isinstance(re_, list) or not all(isinstance(n, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", n) and not FORBID_ENV.fullmatch(n) for n in re_):
                errs.append("chain-scripts.json: %s `reads_env` must be a list of allowed variable names (never BASH_ENV, PATH, LD_*, PYTHON*, NODE_*, GITHUB_*, ...)" % p)
            else:
                for n in re_:
                    if not mentions_outside_comments(p, txt, n):
                        errs.append("chain-scripts.json: %s reads_env names %s, which the script never mentions outside a comment, a docstring or a single-quoted string (stale)" % (p, n))
        if "exceptions" in r:
            good, ee = exception_entries(p, r["exceptions"])
            errs += ee
            for e in good:
                if e["text"] not in txt and e["text"] not in logical(txt):
                    errs.append("chain-scripts.json: %s exceptions entry %r (%s) matches nothing in the file (stale)" % (p, e["text"], e["rule"]))
        rows[p] = r
    for p, r in rows.items():
        for q in r.get("runs", []) if isinstance(r.get("runs", []), list) else []:
            if q not in rows: errs.append("chain-scripts.json: %s runs %r, which is not listed" % (p, q))
    amb = doc.get("ambient_env", [])
    if not isinstance(amb, list): errs.append("chain-scripts.json: ambient_env must be a list of {name, script, why}")
    else:
        seen = set()
        for e in amb:
            if not isinstance(e, dict) or set(e) != {"name", "script", "why"} or not all(isinstance(v, str) for v in e.values()):
                errs.append("chain-scripts.json: ambient_env entry %r must be an object with exactly name, script and why (strings)" % (e,)); continue
            nm, sc, why = e["name"], e["script"], e["why"]
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", nm) or FORBID_ENV.fullmatch(nm):
                errs.append("chain-scripts.json: ambient_env name %r is not an allowed variable name (never BASH_ENV, PATH, LD_*, PYTHON*, NODE_*, GITHUB_*, ...)" % nm); continue
            if sc not in rows:
                errs.append("chain-scripts.json: ambient_env %s names script %r, which is not a listed script" % (nm, sc)); continue
            if not isinstance(rows[sc].get("reads_env"), list) or nm not in rows[sc]["reads_env"]:
                errs.append("chain-scripts.json: ambient_env %s names %s, whose row does not list %s in reads_env" % (nm, sc, nm)); continue
            if not why.strip():
                errs.append("chain-scripts.json: ambient_env %s for %s has no reason (why)" % (nm, sc)); continue
            if (nm, sc) in seen:
                errs.append("chain-scripts.json: ambient_env %s for %s is listed twice" % (nm, sc)); continue
            seen.add((nm, sc)); env_names.ambient.setdefault(nm, set()).add(sc)
    pins = doc.get("pinned_steps", [])
    if not isinstance(pins, list): errs.append("chain-scripts.json: pinned_steps must be a list of {file, job, id, run, why}")
    else:
        for e in pins:
            if not isinstance(e, dict) or set(e) != {"file", "job", "id", "run", "why"} or not all(isinstance(v, str) for v in e.values()):
                errs.append("chain-scripts.json: pinned_steps entry %r must be an object with exactly file, job, id, run and why (strings)" % (e,)); continue
            f, j, i, run, why = e["file"], e["job"], e["id"], e["run"], e["why"]
            if not re.fullmatch(r"\.github/workflows/stage-[A-Za-z0-9_.-]+\.ya?ml", f) or ".." in f:
                errs.append("chain-scripts.json: pinned_steps file %r is not a stage file (.github/workflows/stage-*.yml)" % f); continue
            if not os.path.isfile(os.path.join(base, f)):
                errs.append("chain-scripts.json: pinned_steps file %s is not in the tree" % f); continue
            if not re.fullmatch(r"[A-Za-z0-9_-]+", j) or not re.fullmatch(r"[A-Za-z0-9_-]+", i):
                errs.append("chain-scripts.json: pinned_steps job/id %r/%r must be plain names" % (j, i)); continue
            if not run.strip() or run != run.strip() or any(not (" " <= c <= "~") for c in run):
                errs.append("chain-scripts.json: pinned_steps %s %s %s: run must be one line of printable ASCII with no edge space" % (f, j, i)); continue
            pm = PINNED_SHAPE.fullmatch(run)
            if not pm or ".." in pm.group(1).split("/") or "//" in pm.group(1):
                errs.append("chain-scripts.json: pinned_steps %s %s %s: run must be exactly echo \"NAME=$(jq -c . FILE)\" >> \"$GITHUB_OUTPUT\" (NAME [a-z][a-z0-9_]*, FILE a plain relative path with no ..)" % (f, j, i)); continue
            if not why.strip():
                errs.append("chain-scripts.json: pinned_steps %s %s %s has no reason (why)" % (f, j, i)); continue
            if (f, j, i) in env_names.pinned:
                errs.append("chain-scripts.json: pinned_steps %s %s %s is listed twice (at most one pinned step per file, job and id)" % (f, j, i)); continue
            if run not in open(os.path.join(base, f), errors="replace").read():
                errs.append("chain-scripts.json: pinned_steps %s %s %s: the run text is not in the file (stale)" % (f, j, i)); continue
            env_names.pinned[(f, j, i)] = e
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
    # Codex #249 r5 B4 (the class closed): a word that reads a variable is exactly ONE part, the whole "$NAME"; a read glued to
    # any literal, quoted text or a second read (prefix"$X", "$X"suffix, "$A""$B", "$X"'lit') is not a whole read of the env
    if len(parts) > 1 and any(k == "dq" and ("$" in t or "`" in t) for k, t in parts):
        return "argument %r glues a variable read to other text (a word that reads a variable must be exactly one whole \"$NAME\")" % "".join(
            ('"%s"' if k == "dq" else "'%s'" if k == "sq" else "%s") % t for k, t in parts)
    for kind, t in parts:
        if kind == "lit" and not LIT_WORD.fullmatch(t): return "argument %r is not a plain literal" % t
        if kind == "sq" and ("$" in t or "`" in t): return "single-quoted argument %r contains $ or a backtick" % t
        if kind == "dq":
            m = re.fullmatch(r"\$(\w+)|\$\{(\w+)\}", t)
            if m:
                nm = m.group(1) or m.group(2)
                if nm not in envnames:                  # AC1: the step's OWN env only (Codex #249 r4 B3b: no GITHUB_*/RUNNER_* exception)
                    return "\"$%s\" is not a variable of this step's env: (only a whole read of the step's own env is allowed)" % nm
            elif "$" in t or "`" in t or "!" in t:
                return "double-quoted argument %r mixes text with a variable or substitution (use a whole \"$NAME\" from env:)" % t
    return None

PRINTF_OK = re.compile(r"printf '%s' \"\$(\w+)\" > digests\.json")

def check_run(run, envnames, rows, reads=None, argpaths=None):
    """Grammar errors (list of 'line N: ...') for one stage-file `run:` text; also returns the listed paths it runs. `reads` (a set, when
    given) receives every env name the PARSED command words read whole (comments stripped; Codex #249 r8 B2), the only reads that count."""
    errs, ran = [], []
    reads = set() if reads is None else reads
    # Sonnet #249 continuation (advisor: refuse, never model how bash joins or splits): a backslash-newline anywhere, and any character
    # outside printable ASCII and the newline (CR, tab, VT, FF, NUL, other controls, NBSP, U+200B, U+2028, ...), are refused before the
    # line is read, so the judge's words are bash's words. A backslash outside a single-quoted literal is refused by _words.
    if "\\\n" in run:
        errs.append("a backslash-newline continuation in a run line (bash joins the lines with no space; write one line)")
    bad_ch = sorted({"U+%04X" % ord(c) for c in run if c != "\n" and not (" " <= c <= "~")})
    if bad_ch:
        errs.append("a run line holds %s: only printable ASCII and newlines are allowed (a control, non-ASCII whitespace or invisible character changes how bash splits words)" % ", ".join(bad_ch))
    if errs: return errs, ran
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
            else: reads.add(m.group(1))
            continue
        words, err = _words(line)
        if err: errs.append("line %d: %s: %s" % (n, line[:90], err)); continue
        if not words: continue
        cmd = words[0][0]
        if cmd == "python3":                            # isolated only (-I): bin/ off sys.path, so no bin/<stdlib name>.py can shadow a module
            if len(words) < 3 or words[1][0] != "-I":
                errs.append("line %d: %s: python3 must run isolated, `python3 -I PATH ...` (without -I a file next to the script shadows the standard library)" % (n, line[:90])); continue
            words = [words[0]] + words[2:]
            if words[1][0] == "-B": words = [words[0]] + words[2:]      # -B (write no bytecode cache) may follow -I
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
            if argpaths is not None and len(parts) == 1 and parts[0][0] == "lit" and parts[0][1] in rows: argpaths.add(parts[0][1])
            if e: errs.append("line %d: %s: %s" % (n, line[:90], e))
            elif len(parts) == 1 and parts[0][0] == "dq":
                wm = re.fullmatch(r"\$(\w+)|\$\{(\w+)\}", parts[0][1])
                if wm: reads.add(wm.group(1) or wm.group(2))
        ran.append(path)
    return errs, ran

def _artifact_path_error(p, rows, download):
    if not isinstance(p, str) or not p.strip(): return "needs an explicit literal `path`"
    for ln in p.splitlines():
        ln = ln.strip()
        if not ln: continue
        # final batch R-e: a plain relative literal of [A-Za-z0-9_./-] only (no ~ % $ ` * ? [ { or anything else), no .., no leading /
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", ln) or ".." in ln.split("/") or ln.startswith("/") or ln in (".", "./"): return "path %r is not a plain relative literal" % ln
        q = ln.rstrip("/")
        if download:
            if q == "bin" or q.startswith("bin/") or q.startswith(".github") or q.startswith("./"):
                return "downloads into %r, which is where the repository's scripts and policy live" % ln
            for L in rows:
                if L == q or L.startswith(q + "/"): return "downloads into %r, over the listed script %s" % (ln, L)
    return None

def _runner_errors(pre, j):
    """REQ-CHAIN-001-AC1 (Codex #249 r5 B3, the class closed): a stage job runs on a GitHub-hosted runner, never self-hosted, and its
    strategy is only a matrix of literal labels. runs-on is a plain string: a hosted ubuntu label, or exactly one whole matrix read
    whose key is in the job's matrix and EVERY value of that key is a hosted ubuntu label. The matrix is a mapping of key -> non-empty
    list of literal strings: no include/exclude (they add or reshape combinations), no string or expression matrix, no nested leaves."""
    errs = []
    ro, st = j.get("runs-on"), j.get("strategy")
    matrix = None
    if st is not None:
        if not isinstance(st, dict) or set(st) - {"matrix", "fail-fast", "max-parallel"}:
            errs.append("%s: strategy may hold only matrix, fail-fast, max-parallel" % pre)
        elif "matrix" in st:
            matrix = st["matrix"]
            if not isinstance(matrix, dict):
                errs.append("%s: the matrix %r is not a mapping of literal lists (a string or expression matrix cannot be judged)" % (pre, matrix)); matrix = None
            else:
                for k, v in matrix.items():
                    if str(k).strip().lower() in ("include", "exclude"):
                        errs.append("%s: matrix %s is not allowed (it adds or reshapes combinations outside the literal lists)" % (pre, k)); continue
                    if not isinstance(v, list) or not v:
                        errs.append("%s: matrix key %s must be a non-empty list of literal labels, found %r" % (pre, k, v)); continue
                    for leaf in v:
                        if not isinstance(leaf, str) or not MATRIX_LIT.fullmatch(leaf):
                            errs.append("%s: matrix value %r of %s is not a literal runner label or name" % (pre, leaf, k))
    if ro is None: return errs
    if not isinstance(ro, str):
        errs.append("%s: runs-on %r is not a plain string (a label list or a group/labels mapping can pick a self-hosted runner)" % (pre, ro)); return errs
    if HOSTED.fullmatch(ro): return errs
    m = MATRIX_READ.fullmatch(ro)
    if not m:
        errs.append("%s: runs-on %r is not a GitHub-hosted ubuntu runner or one whole matrix read" % (pre, ro)); return errs
    key = m.group(1)
    if not isinstance(matrix, dict) or key not in matrix:
        errs.append("%s: runs-on reads matrix.%s, which the job's matrix does not define (exactly, same case)" % (pre, key)); return errs
    vals = matrix[key]
    for leaf in (vals if isinstance(vals, list) else [vals]):
        if not isinstance(leaf, str) or not HOSTED.fullmatch(leaf):
            errs.append("%s: runs-on reads matrix.%s, whose value %r is not a GitHub-hosted ubuntu runner" % (pre, key, leaf))
    return errs

def _reach(paths, rows):
    """The listed scripts a step can run: the ones it names (as the command or as an argument) and, transitively, their `runs`."""
    seen, todo = set(), list(paths)
    while todo:
        p = todo.pop()
        if p in seen or p not in rows: continue
        seen.add(p)
        r = rows[p].get("runs")
        if isinstance(r, list): todo += [q for q in r if isinstance(q, str)]
    return seen

def stage_grammar(rel, d, rows, env_names=frozenset(), path=None):
    """(errors, listed paths run) for a parsed stage workflow file (YAML via the caller). The grammar is FINITE over keys:
    workflow, job and step keys come from closed sets; step `uses` from a closed list; env names from a closed set; the run
    lines from the grammar of check_run."""
    errs, ran = [], []
    full = path or ".github/workflows/" + rel      # round 2 (2): a pin binds the FULL repo path of the file
    pins = getattr(env_names, "pinned", {})        # round 1 (5): (file, job, id) -> the reviewed pinned step
    found = set()
    amb = getattr(env_names, "ambient", {})        # PR 1b (B): name -> listed scripts that read it from their own environment
    extra = set(d) - STAGE_WF_KEYS
    if extra: errs.append("%s: workflow keys %s are not allowed in a stage file (env, defaults, concurrency, run-name can reroute every step)" % (rel, sorted(extra)))
    for jn, j in ((d.get("jobs") or {}).items()):
        pre = "%s job %s" % (rel, jn)
        extra = set(j) - STAGE_JOB_KEYS
        if extra: errs.append("%s: job keys %s are not allowed (container, services, defaults, env, uses, secrets, with run other code or reroute steps)" % (pre, sorted(extra)))
        errs += _runner_errors(pre, j)
        for s in (j.get("steps") or []):
            pin = pins.get((full, jn, s.get("id"))) if isinstance(s.get("id"), str) else None
            if pin is not None:
                # round 1 (5), a REVIEWED PINNED STEP: exactly name/id/run, and the run text equal to the entry's; nothing else about it is relaxed
                found.add((full, jn, s.get("id")))
                if set(s) - {"name", "id", "run"}: errs.append("%s: pinned step %r has keys %s; a pinned step has only name, id and run" % (pre, s.get("id"), sorted(set(s) - {"name", "id", "run"})))
                elif s.get("run") != pin["run"]: errs.append("%s: pinned step %r has a run text that differs from its pinned_steps entry" % (pre, s.get("id")))
                continue
            nm = s.get("name") or str(s.get("run") or s.get("uses") or "").strip().splitlines()[0][:40]
            sp = "%s step %r" % (pre, nm)
            extra = set(s) - STAGE_STEP_KEYS
            if extra: errs.append("%s: step keys %s are not allowed (shell, working-directory, continue-on-error reroute or hide the run)" % (sp, sorted(extra)))
            run, uses, env, w = s.get("run"), s.get("uses"), s.get("env") or {}, s.get("with") or {}
            if (run is None) == (uses is None): errs.append("%s: must have exactly one of run/uses" % sp); continue
            for k in env:
                if FORBID_ENV.fullmatch(k): errs.append("%s: env %s is never allowed (it can make a shell or interpreter load other code)" % (sp, k))
                elif k not in env_names and k not in amb: errs.append("%s: env %s is not in the closed env_names list of chain-scripts.json" % (sp, k))
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
            got = set()
            argp = set()
            e, r = check_run(str(run), set(env.keys()), rows, got, argp)
            reach = _reach(set(r) | argp, rows)
            for k, v in env.items():            # Codex #249 r8 B2: read only by a whole word of the PARSED command (a comment never counts)
                # Round 1 (1): an AMBIENT name is valid in a step only if the step reaches a listed script the name is listed for AND its value is
                # one plain expression; both checks run whether or not the run line also reads the name whole (a whole read of an ambient name in a
                # step that does not reach its script is an error). An ambient name is never an ordinary env_names name.
                if k in got and k not in amb: continue
                if k in amb and not FORBID_ENV.fullmatch(k):    # PR 1b (B): an ambient name is read by a listed script from its own environment
                    if not (amb[k] & reach):
                        errs.append("%s: env %s is listed ambient only for %s, which this step does not run (as its script, an argument or through `runs`)" % (sp, k, ", ".join(sorted(amb[k]))))
                    elif (set(r) | argp) - amb[k]:
                        errs.append("%s: env %s reaches %s, which is not authorized in ambient_env for it (the step's command script and every listed script named as an argument receive the environment too; each needs its own ambient_env entry with a reason and reads_env)" % (sp, k, ", ".join(sorted((set(r) | argp) - amb[k]))))
                    elif not isinstance(v, str) or not AMBIENT_VALUE.fullmatch(v):
                        errs.append("%s: ambient env %s has the value %r, which is not one plain expression (github.token, inputs.X, matrix.X) or a plain literal" % (sp, k, v))
                else:
                    errs.append("%s: env %s is not read whole (\"$%s\") by the step's run line" % (sp, k, k))
            errs += ["%s: %s" % (sp, x) for x in e]; ran += r
    for key in pins:
        if key[0] == full and key not in found:
            errs.append("%s: pinned_steps entry %s job %s id %s matches no step in the file (stale)" % (rel, key[0], key[1], key[2]))
    return errs, ran

ENV_SET = re.compile(r"(?<![\w$])(?:(?:export|local|readonly|typeset)\s+|declare\s+(?:-\w+\s+)?)?(PATH|BASH_ENV|ENV|LD_[A-Z0-9_]+|PYTHON[A-Z0-9_]*|NODE_OPTIONS|IFS|CDPATH|PROMPT_COMMAND|PS4|SHELLOPTS|BASHOPTS)\+?=")
LAUNCHER = re.compile(r"\bwitness\b[^\n]*?\brun\b(?P<rest>[^\n]*)")
# Codex #249 r8 B3 + Sonnet 2/6 (the class closed, positive): at ANY command position of a shell listed script, a LAUNCHER is refused
# outright (whatever follows, whatever `tools` says: it runs another program the row cannot name), an EVALUATOR is refused unless the
# row lists that exact word, and an INTERPRETER must be handed an exact listed path of `runs` as its first argument (no option, no -c,
# no stdin). A path or ./word at command position must itself be an exact listed path.
LAUNCH_OUTRIGHT = {"env", "command", "exec", "builtin", "nohup", "sudo", "doas", "timeout", "nice", "ionice", "xargs", "setsid", "stdbuf",
                   "chroot", "unshare", "nsenter", "flock", "time", "strace", "chrt", "taskset", "eval", "source", ".", "busybox", "setpriv"}
EVALUATORS = {"awk", "gawk", "mawk", "nawk", "sed", "perl", "ruby", "php", "lua", "node", "tar", "find", "ssh", "openssl"}
SHELL_INTERP = {"bash", "sh", "dash", "zsh", "ksh", "python", "python3"}
CMDPOS = re.compile(r"(?:^|[;&|(){}!`]|\$\(|\b(?:then|do|else|elif|time|if|while|until)\b)[ \t]*"
                    r"(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|[^\s;&|()]*)[ \t]+)*(?P<w>[^\s;&|(){}<>`\"'=!]+)", re.M)
CMD_AT = re.compile(r"[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|[^\s;&|()]*)[ \t]+)*(?P<w>[^\s;&|(){}<>`\"'=!]+)")
RESERVED = {"if", "then", "elif", "else", "fi", "do", "done", "while", "until", "case", "esac", "in", "time", "function", "select", "coproc"}

def _is_python(path, text):
    return path.endswith(".py") or bool(re.match(r"#!\S*(?:/|\s)python", text))

def _mask(line):
    """The line with every single-quoted string, every ${...} and every double-quoted string reduced to a placeholder OF THE SAME LENGTH
    (PR 1b: a position in the masked line is the same position in the original, so the original text of a word can be read back), so
    their contents are never read as command positions; the $( ) and backtick substitutions INSIDE a double-quoted string are returned
    (as original text) as extra segments (they are command positions)."""
    extra = []
    cur, prev = line, None
    while prev != cur:
        prev = cur; cur = re.sub(r"\$\{[^{}]*\}", lambda m: "X" * len(m.group(0)), cur)
    cur = re.sub(r"'[^']*'", lambda m: "Q" * len(m.group(0)), cur)
    def dq(m):
        for mm in re.finditer(r"\$\(([^()]*)\)|`([^`]*)`", m.group(0)):
            g = 1 if mm.group(1) is not None else 2
            extra.append(line[m.start() + mm.start(g):m.start() + mm.end(g)])
        return "Q" * len(m.group(0))
    cur = re.sub(r'"(?:[^"\\]|\\.)*"', dq, cur)
    return cur, extra

def _cmd_end(line, i):
    """Index where the simple command that continues at line[i:] ends (round 1 (3)): at the next ; & | (but not 2>&1, &>, >|), a backtick, a closing
    ) or } that does not close a ( opened inside it (so <( ) and $( ) belong to the command), or the end of the line."""
    depth, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == "(": depth += 1
        elif c == ")":
            if depth == 0: return i
            depth -= 1
        elif depth == 0:
            if c in ";`}": return i
            if c == "|" and not (i > 0 and line[i - 1] == ">"): return i
            if c == "&" and not ((i > 0 and line[i - 1] in "<>") or (i + 1 < n and line[i + 1] == ">")): return i
        i += 1
    return n

def command_items(text):
    """(word, rest-of-command, original word, WHOLE command text) at every command position of comment-stripped, continuation-joined
    shell text (quotes and ${...} masked; substitutions inside double quotes scanned as their own segments). The last two are the text as
    written (quotes and spacing kept): the command word through the end of the simple command (_cmd_end), for a finding to name its exact
    span; an exception entry must equal it, so a changed tail makes the finding reappear."""
    out = []
    todo = list(logical(strip(text)).splitlines())
    while todo:
        orig = todo.pop(0)
        line, extra = _mask(orig)
        todo += extra
        for m in CMDPOS.finditer(line):
            w, end, ws = m.group("w"), m.end(), m.start("w")
            while w in RESERVED:                  # a reserved word is not the command: the next word is (`elif setsid`, `time setsid`)
                if w == "time": out.append((w, "", w, ""))
                n2 = CMD_AT.match(line, end)
                if not n2: w = None; break
                w, end, ws = n2.group("w"), n2.end(), n2.start("w")
            if w is None: continue
            rest = re.split(r"[;&|)`]", line[end:], 1)[0]
            out.append((w, rest, orig[ws:ws + len(w)], orig[ws:_cmd_end(line, end)].rstrip()))
    return out

# Round 1 (4), fail closed by default: a path-like word (it holds a /) whose LAST component is a deny-class command is refused wherever it appears,
# unless it is an OPERAND (not the command word) of (a) an interpreter run on an exact listed path of `runs` (bash|python3 LISTED ...), (b) a
# listed script invoked by its exact path, or (c) a closed list of data-only commands with no option that runs a program. That covers the
# command word after a leading redirection or an assignment, find -exec/-execdir/-ok, xargs, trap, env/command/exec/nohup/time operands,
# bash -c strings, here-document bodies and eval, none of which the command-position reader can follow.
DENYCLASS = DENY | LAUNCH_OUTRIGHT | EVALUATORS
DATA_ONLY = {"cp", "mv", "rm", "mkdir", "rmdir", "ls", "cat", "echo", "printf", "test", "[", "[[", "sha256sum", "shasum", "tar", "mktemp", "touch",
             "chmod", "ln", "readlink", "basename", "dirname", "head", "tail", "wc", "sort", "grep", "cut", "tr", "diff", "cmp", "install", "du",
             "stat", "date", "sleep", "true", "false"}
EXECY = ("-exec", "-execdir", "-ok", "-okdir", "--exec", "--to-command", "--use-compress-program", "--compress-program", "--checkpoint-action",
         "--rsh-command", "--info-script", "--new-volume-script", "-I", "-F", "--use-compress")
TOKEN = re.compile(r"[^\s;&|(){}<>`\"'=,]+")

def pathlike_deny(text, rows, runs):
    """The path-like words (see above) of comment-stripped, continuation-joined shell text that are neither the command word of their command
    (judged by the command-word rule) nor an admitted operand. Every observed line is judged on its own (a substitution inside a double-quoted
    string is its own line); a word no command claims is refused."""
    out = []
    todo = list(logical(strip(text)).splitlines())
    while todo:
        orig = todo.pop(0)
        line, extra = _mask(orig); todo += extra
        segs = []
        for m in CMDPOS.finditer(line):
            w, end, ws = m.group("w"), m.end(), m.start("w")
            while w in RESERVED:
                n2 = CMD_AT.match(line, end)
                if not n2: w = None; break
                w, end, ws = n2.group("w"), n2.end(), n2.start("w")
            if w is not None: segs.append((ws, end, _cmd_end(line, end), w))
        for tm in TOKEN.finditer(orig):
            t = tm.group(0); n = t[2:] if t.startswith("./") else t
            if "/" not in n or n.startswith(("-", "$")) or "://" in n or n.rsplit("/", 1)[-1] not in DENYCLASS: continue
            p = tm.start()
            inner = [g for g in segs if g[0] <= p < g[2]]
            if inner:
                ws, end, cend, w = max(inner, key=lambda g: g[0])
                if p < ws + len(w): continue                     # the command word itself
                cw = w[2:] if w.startswith("./") else w
                words = [x.strip("\"'") for x in orig[end:cend].split()]
                first = words[0] if words else ""
                if cw in rows: continue                          # (b) a listed script invoked by its exact path
                if cw in SHELL_INTERP and (first[2:] if first.startswith("./") else first) in runs: continue      # (a)
                if w in DATA_ONLY and not any(x.startswith(EXECY) for x in TOKEN.findall(orig[end:cend])): continue   # (c)
            out.append(t)
    return out

def command_words(text):
    """(word, rest-of-command) at every command position (see command_items)."""
    return [(w, rest) for w, rest, _ow, _on in command_items(text)]

# REQ-CHAIN-001-AC1 "sets no PATH, BASH_ENV, ENV, LD_*, PYTHON* or NODE_OPTIONS" (final batch B1, the class closed): a listed script may
# mention one of these names ONLY as a pure read: $NAME / ${NAME} in shell; os.environ.get("NAME"), os.getenv("NAME") or an
# os.environ["NAME"] that is not assigned or deleted in Python. Any other mention (for/read/printf -v/mapfile/getopts/declare -n/unset/
# ${NAME:=}, putenv/update/setdefault/pop, env={...}, a comment or a string) is refused unless the row's `env_mentions` lists that
# exact text with a reason; an entry whose text is not in the file is stale and refused.
PROTECTED = re.compile(r"(?<![A-Za-z0-9_])(PATH|BASH_ENV|ENV|LD_[A-Za-z0-9_]+|PYTHON[A-Za-z0-9_]*|NODE_OPTIONS|IFS|SHELLOPTS|BASHOPTS|CDPATH|"
                       r"GLOBIGNORE|PS4|PROMPT_COMMAND|BASH_FUNC_[A-Za-z0-9_%]*)(?![A-Za-z0-9_])")

def protected_env_mentions(path, text, row):
    errs, spans = [], []
    for e in row.get("env_mentions") or []:
        t, nm = e.get("text", ""), e.get("name", "")
        if not str(e.get("why") or "").strip(): errs.append("%s: env_mentions entry %r has no reason" % (path, t)); continue
        hits = [(m.start(), m.end(), nm) for m in re.finditer(re.escape(t), text)] if t else []
        if not hits or not any(PROTECTED.fullmatch(nm or "") and nm in text[a:b] for a, b, _ in hits):
            errs.append("%s: env_mentions entry %r (%s) matches nothing in the file (stale)" % (path, t, nm)); continue
        spans += hits
    py = _is_python(path, text)
    for m in PROTECTED.finditer(text):
        a, b, nm = m.start(), m.end(), m.group(1)
        if any(x <= a and b <= y and nm == n for x, y, n in spans): continue
        before, after = text[max(0, a - 40):a], text[b:b + 40]
        if not py and (before.endswith("$") or (before.endswith("${") and after.startswith("}"))): continue
        if py and re.search(r"(?:environ\.get|getenv)\(\s*[\"']$", before) and re.match(r"[\"']", after): continue
        if py and re.search(r"(?<!del )os\.environ\[\s*[\"']$", before) and re.match(r"[\"']\s*\](?!\s*=(?!=))", after) \
                and not re.search(r"\bdel\s+os\.environ\[\s*[\"']$", before): continue
        line = text.count("\n", 0, a) + 1
        errs.append("%s: line %d mentions %s outside a pure read (only $NAME/${NAME}, or an os.environ read; a listed exception goes in env_mentions)" % (path, line, nm))
    return errs

def scan_script(path, text, row, rows, base):
    """Errors for one LISTED script. Not a shell parser: a conservative TEXT scan over the raw file whatever its extension or shebang
    (it over-reports by design): (a) a command from the finite DENY list (interpreters, source/eval/exec, make/xargs/find, curl/wget/ssh,
    gh/git/docker ...) anywhere in the text unless the row lists it in `tools`; (b) any token naming another script (a path ending
    in a script extension, or a file in the tree with a shebang, or a listed path) that is not the file itself and not in its `runs`;
    (c) `witness run ... --`: the first word after `--` must be a literal path in `runs` (never $@, "$@", $*, a variable or
    substitution); (d) setting PATH, BASH_ENV, ENV, LD_*, PYTHON*, NODE_OPTIONS, IFS ... anywhere. Signing calls are judged by the
    caller from the row's `signs` (raw text, comments and quotes included). Stated exclusion: a command or script path BUILT AT RUN
    TIME inside a listed script is not detected; listed scripts are committed, sha256-bound and reviewed at PR time (row 78).
    PR 1b, reviewed exceptions: a finding of rule launcher, evaluator, deny, script-name or witness-target carries the exact text it matched
    (launcher / evaluator / script-name at a command position: the WHOLE simple command, command word through the next ; & | ) } or end of line, as
    written; deny and a script token: the
    word; witness-target: everything after `witness run ... --`, or the `witness run` text when there is no `--`). A row's `exceptions`
    entry {rule, text, why} waives the FIRST finding with exactly that rule and exactly that text, and nothing else: a second finding
    with the same text, a different text, or a different rule stays a finding. An entry that waives nothing is itself an error. Findings
    that set PATH, BASH_ENV ... are never waived here (`env_mentions` is the only exception for those)."""
    fnd = []                                       # (rule or None, exact text, message); rule None = never waived
    def add(rule, txt, msg): fnd.append((rule, txt, msg))
    tools, runs = set(row.get("tools", [])), set(row.get("runs", []))
    selfbase = os.path.basename(path)
    py = _is_python(path, text)
    listed_base = {os.path.basename(r) for r in rows}
    body = text.split("\n", 1)[1] if text.startswith("#!") and "\n" in text else ("" if text.startswith("#!") else text)   # the shebang names the file's OWN interpreter
    # Codex #249 r7 B3 (the class closed): a script token is compared to the manifest EXACTLY (only a leading ./ is normalised; no
    # basename match), a command named by ANY path is refused even when its bare name is in `tools` (the row governs the bare name only),
    # and a launcher prefix (env, command, exec, builtin, nohup, sudo, timeout, nice, xargs, ...) followed by another program is refused.
    tok_script = set()                             # script tokens already reported (a command-position report of the same word is the same finding)
    for tm in re.finditer(r"[^\s;&|(){}<>`\"'=,]+", body):
        t = tm.group(0)
        n = t[2:] if t.startswith("./") else t
        name = n.rsplit("/", 1)[-1]
        pathlike = "/" in n and not n.startswith(("-", "$")) and "://" not in n
        if pathlike and name in DENY:
            # PR 1b: in a SHELL script a path-like word is judged as a command only at command position (below); an argument such as
            # archive/go is judged by the script rule alone. A Python script has no command position, so it keeps the word-level test.
            if py: add("deny", t, "%s: names the command %r by a path (name it bare, so its `tools` row governs it)" % (path, t))
        elif n in DENY and n not in tools:
            add("deny", t, "%s: names the command %r, which is not in this script's `tools` list" % (path, t))
        is_script = n.endswith(SCRIPT_EXTS) or n in rows or name in listed_base
        if not is_script and (pathlike or t.startswith("./")):
            full = os.path.join(base, n)
            if os.path.isfile(full):          # Sonnet 1: the existence, shebang and executable tests run on the normalised path
                with open(full, "rb") as fh: is_script = fh.read(2) == b"#!" or os.access(full, os.X_OK)
        if is_script and n != path and n not in runs and not (n == selfbase):
            add("script-name", t, "%s: names the script %r, which is not exactly a path in this script's `runs` list" % (path, t)); tok_script.add(t)
    if not py:
        for t in pathlike_deny(body, rows, runs):
            add("deny", t, "%s: names the command %r by a path (name it bare, so its `tools` row governs it; only an operand of a data-only command, of an interpreter run on a listed script or of a listed script is allowed)" % (path, t))
        for w, rest, ow, on in command_items(body):
            n = w[2:] if w.startswith("./") else w
            name = n.rsplit("/", 1)[-1]
            span = on                              # the whole simple command, as written
            dq = ow.strip("\"'")                  # a COMMAND named by a path is refused whatever `tools` says (the row governs the bare name only)
            dn = dq[2:] if dq.startswith("./") else dq
            if "/" in dn and not dn.startswith(("-", "$")) and "://" not in dn and dn.rsplit("/", 1)[-1] in DENYCLASS:
                add("deny", dq, "%s: names the command %r by a path (name it bare, so its `tools` row governs it)" % (path, dq))
            if name in LAUNCH_OUTRIGHT:
                add("launcher", span, "%s: %r at command position launches another program (refused whatever `tools` says)" % (path, w)); continue
            if name in EVALUATORS and not (name == "openssl" and not re.match(r"\s*s_client\b", rest)):
                if name not in tools: add("evaluator", span, "%s: %r at command position is an evaluator not in this script's `tools` list" % (path, w))
                continue
            if name in SHELL_INTERP:
                args = [x.strip("\"'") for x in rest.split()]
                first = args[0] if args else ""
                fn = first[2:] if first.startswith("./") else first
                if "<" in rest or not first or first.startswith("-") or fn not in runs:
                    add("script-name", span, "%s: %r is handed %r, not an exact listed path of this script's `runs` (no option, -c, stdin or other file)" % (path, w, first or "stdin"))
                continue
            in_tree = ("/" in w or w.startswith("./")) and os.path.isfile(os.path.join(base, n))
            if (w.startswith("./") or in_tree) and n != path and n not in runs and w not in tok_script:
                add("script-name", span, "%s: %r at command position is not an exact listed path of this script's `runs`" % (path, w))
    for m in ENV_SET.finditer(text):
        add(None, "", "%s: sets %s (it can make a shell, interpreter or tool load other code)" % (path, m.group(1)))
    for x in protected_env_mentions(path, text, row): add(None, "", x)
    for ln in logical(text).splitlines():
        m = LAUNCHER.search(ln)
        if not m: continue
        rest = m.group("rest")
        if " -- " not in rest + " " and not rest.rstrip().endswith("--"):
            add("witness-target", ln[m.start():].strip(), "%s: `witness run` without `-- PATH` on the same logical line: %s" % (path, ln.strip()[:80])); continue
        after = (rest + " ").split(" -- ", 1)[1].strip() if " -- " in rest + " " else ""
        first = after.split()[0] if after.split() else ""
        if not LITERAL_PATH.fullmatch(first) or first not in runs:
            add("witness-target", after, "%s: after `witness run --` the command %r is not a literal path in this script's `runs` list ($@, \"$@\", $*, a variable or a substitution is an error)" % (path, first))
    waived, errs = set(), []
    for e in (exception_entries(path, row["exceptions"])[0] if "exceptions" in row else []):
        for i, (rule, txt, _msg) in enumerate(fnd):
            if i not in waived and rule == e["rule"] and txt == e["text"]:
                waived.add(i); break
        else:
            errs.append("%s: exceptions entry %r (%s) waives nothing (no finding of that rule has exactly that text)" % (path, e["text"], e["rule"]))
    return list(dict.fromkeys([m for i, (_r, _t, m) in enumerate(fnd) if i not in waived] + errs))
