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
import fnmatch, hashlib, json, os, re

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

WORKSPACE_ROOT = re.compile(r"(?<![^\s;&|(){}<>`\"'=,])\$(?:GITHUB_WORKSPACE|\{GITHUB_WORKSPACE\})/")   # the runner's checkout root, written as the variable and a slash, at the START of a word (an exact variable name: GITHUB_WORKSPACEX does not match; bin/$GITHUB_WORKSPACE/x and ./$GITHUB_WORKSPACE/x do not either)
WORKSPACE_PLAIN = re.compile(r"\$GITHUB_WORKSPACE(?![A-Za-z0-9_])|\$\{GITHUB_WORKSPACE\}")   # the only forms in which a listed script may name the variable: a plain read
WORKSPACE_PIECE = re.compile(r"[A-Z]{3,}")   # an upper-case run that is a piece of WORKSPACE, or holds five letters of it in a row: a name can be built from pieces only if a script holds them
HEREDOC_QUOTED = re.compile(r"<<-?[ \t]*(?:(['\"])([^'\"\n]+)\1|\\([^\s;&|()<>]+))")   # any quoted or backslashed delimiter, whatever characters it holds
def single_quoted_spans(body):
    """(start, end) of every stretch of a shell text whose dollar signs are plain text: single-quoted stretches (across lines) and bodies of quoted here-documents. Quotes inside double quotes, after a backslash or in a comment do not count, except that a command substitution (dollar-paren or backquote) inside double quotes is scanned afresh; an unclosed quote runs to the end."""
    spans, i, n, a = [], 0, len(body), 0
    stack = ["n"]                                            # n: plain text, d: double quotes, s: single quotes, p: inside $( ), b: inside backquotes
    depth = [0]
    pend = []                                                # terminators of quoted here-documents whose body starts after this line
    while i < n:
        c, st = body[i], stack[-1]
        if st in ("n", "p", "b"):
            if c == "\\": i += 2; continue
            m = HEREDOC_QUOTED.match(body, i) if c == "<" else None
            if m: pend.append(m.group(2) or m.group(3)); i = m.end(); continue
            if c == "\n" and pend:
                pos = i + 1
                for term in pend:
                    start = pos
                    while pos < n:
                        e = body.find("\n", pos); line = body[pos:n if e < 0 else e]
                        pos = n if e < 0 else e + 1
                        if line.strip() == term: break
                    spans.append((start, pos))
                pend = []; i = pos; continue
            if c == "'": a = i; stack.append("s")
            elif c == '"': stack.append("d")
            elif c == "`":
                if st == "b": stack.pop()
                else: stack.append("b")
            elif c == "$" and body[i + 1:i + 2] == "(": stack.append("p"); depth.append(0); i += 2; continue
            elif c == "(" and st == "p": depth[-1] += 1
            elif c == ")" and st == "p":
                if depth[-1] == 0: stack.pop(); depth.pop()
                else: depth[-1] -= 1
            elif c == "#" and st != "b" and (i == 0 or body[i - 1] in " \t\n;&|("):
                e = body.find("\n", i); i = n if e < 0 else e; continue
        elif st == "d":
            if c == "\\": i += 2; continue
            if c == '"': stack.pop()
            elif c == "`": stack.append("b")
            elif c == "$" and body[i + 1:i + 2] == "(": stack.append("p"); depth.append(0); i += 2; continue
        else:
            if c == "'": spans.append((a, i)); stack.pop()
        i += 1
    if stack[-1] == "s": spans.append((a, n))
    return spans
WORKSPACE_SLICE = re.compile(r"\$\{[A-Za-z_0-9@*]+(?::[^-=+?}]|[#%/^,])")   # a slice or pattern edit of a variable's value: ${x:2:4} ${x#?} ${x%?} ${x/a/b} ${x^^}
def workspace_strict(body):
    """The script that READS the variable to name a listed helper gets the strictest text test: no slice or pattern edit of any value, and no upper-case run holding even three letters in a row of WORKSPACE."""
    rest = WORKSPACE_PLAIN.sub("", body)
    return bool(WORKSPACE_SLICE.search(rest)) or any(r[k:k + 3] in "WORKSPACE" for r in WORKSPACE_PIECE.findall(rest) for k in range(len(r) - 2))
def workspace_touched(body):
    """Does this script do anything with GITHUB_WORKSPACE but read it plainly (set, export, unset, read into, default-expand, brace-expand, build the name)?"""
    quoted = single_quoted_spans(body)                      # a read inside a single quote (on any line) or after a backslash is the text itself: it can be sliced into a name
    for m in WORKSPACE_PLAIN.finditer(body):
        if body[max(0, m.start() - 1):m.start()] == "\\" or any(a <= m.start() < b for a, b in quoted): return True
    if re.search(r"\$\{![A-Za-z_0-9]*[*@]", body): return True       # ${!PREFIX*} lists every variable whose name starts with PREFIX
    rest = WORKSPACE_PLAIN.sub("", body)
    if re.search(r"GITHUB_(?![A-Z])", rest): return True                  # the variable's prefix with no name after it: the name is finished at run time
    return "GITHUB_WORKSPACE" in rest or any(r in "WORKSPACE" or any(r[k:k + 5] in "WORKSPACE" for k in range(len(r) - 4)) for r in WORKSPACE_PIECE.findall(rest))   # a name built at run time (any builtin that takes a variable name) needs a piece of it in the text


def read_script(path):
    """The text of a listed script with CR and LF kept exactly (no universal-newline translation: a CR is refused by scan_script)."""
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", "replace")

def load_table(path=None):
    return jload(path or os.environ["CHAIN_SIGNER_TABLE"])["signers"]

def strip_line(l):
    if l.lstrip().startswith("#"):
        return ""
    sq = dq = esc = prev_ws = False
    for i, ch in enumerate(l):
        if esc: esc = False; prev_ws = False; continue         # round 3 (8): a backslash outside single quotes escapes the next character
        if ch == "\\" and not sq: esc = True; prev_ws = False; continue
        if ch == "'" and not dq: sq = not sq
        elif ch == '"' and not sq: dq = not dq
        elif ch == "#" and not sq and not dq and i > 0 and prev_ws:
            return l[:i]
        prev_ws = ch.isspace()
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
    return re.sub(r"(\\+)\n", lambda m: m.group(1)[:-1] if len(m.group(1)) % 2 else m.group(0), text)      # round 3 (8): only an ODD run of backslashes escapes the newline

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
                        r"GOTOOLCHAIN|GOPRIVATE|GONOPROXY|GOINSECURE|GOENV|GOROOT|GOPATH|GOCACHEPROG|JDK_JAVA_OPTIONS|MAKEFLAGS|MFLAGS|LESSOPEN|LESSCLOSE|OPENSSL_CONF|ACTIONS_.*|PIP_.*|DOCKER_.*|KUBE.*|TAR_OPTIONS|MAKEFILES|EDITOR|VISUAL|PAGER|GH_HOST|GH_REPO|GH_EDITOR|GH_PAGER|GH_CONFIG_DIR|OPENSSL_.*|REGISTRY_AUTH_FILE|CC|CXX|CFLAGS|LDFLAGS|PWD|OLDPWD)",
                        re.IGNORECASE | re.DOTALL)
SIGNS = (False, "provenance", "other")
# PR 1b: the CLOSED list of rules a per-row `exceptions` entry may waive (extend only by a reviewed edit when a real text needs it)
# Round 3 (5): the ONE pinned step REQ-CHAIN-004-AC2 ratifies, as an exact tuple (file, job, id) -> run text. An entry for any other tuple or text is
# an error until a later reviewed change adds it HERE.
PINNED_ALLOWED = {(".github/workflows/stage-build.yml", "assemble", "digests"): 'echo "digests=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"'}
EXC_RULES = ("launcher", "evaluator", "deny", "script-name", "witness-target")
# PR 1b (B): the value an AMBIENT env name may carry: one whole plain expression (the job token, a workflow input or a matrix key) or a
# plain literal; never a secret, a glued expression or a substitution
AMBIENT_VALUE = re.compile(r"\$\{\{ ?(?:github\.token|inputs\.[A-Za-z_][\w-]*|matrix\.[A-Za-z_][\w-]*) ?\}\}|[A-Za-z0-9_./-]+")

# Release's NAMED SECRETS (rule 56: only Release holds a stored secret; advisor 0386 J): ONE closed list of five rows, in code, so that a sixth row, another name, another place
# or another script is a reviewed edit of this file and nothing else.  name -> {(stage file, job): the listed scripts that may receive it}.  bin/witnessed.sh receives every
# name at the place it is bound (it is the wrapper), GH_TOKEN being bound at exactly the two places below.
_SB, _SP, _WIT = ".github/workflows/stage-build.yml", ".github/workflows/stage-promote.yml", "bin/witnessed.sh"
_HUB = {(_SP, "release"): {_WIT, "bin/release-publish.sh", "bin/release-sign.sh"}}
SECRET_ROWS = {
    "GH_TOKEN": {(_SB, "apk"): {_WIT, "bin/build-stage-apk.sh", "bin/build-admit.py"},                      # row 1: the run's own token, admission only
                 (_SP, "release"): {_WIT, "bin/release-publish.sh", "bin/release-sign.sh", "bin/release-assets.sh", "bin/release-postverify.sh"}},   # row 5
    "APK_RELEASE_SIGNING_KEY": {(_SP, "release"): {_WIT, "bin/release-apks.sh"}},                          # row 2
    "DOCKERHUB_USERNAME": _HUB,                                                                             # row 3
    "DOCKERHUB_TOKEN": _HUB,                                                                                # row 4
}
SECRET_VALUE = {"GH_TOKEN": "${{ github.token }}", "APK_RELEASE_SIGNING_KEY": "${{ secrets.APK_RELEASE_SIGNING_KEY }}",
                "DOCKERHUB_USERNAME": "${{ secrets.DOCKERHUB_USERNAME }}", "DOCKERHUB_TOKEN": "${{ secrets.DOCKERHUB_TOKEN }}"}
# the job that holds a named credential holds exactly these permissions (Build's apk job: read-only plus the identity token Witness needs; Release: the three writes)
PLACE_PERMS = {(_SB, "apk"): {"contents": "read", "checks": "read", "statuses": "read", "pull-requests": "read", "id-token": "write"},
               (_SP, "release"): {"contents": "write", "packages": "write", "id-token": "write"}}
CHAIN_STAGE_FILES = {_SB, _SP, ".github/workflows/stage-sign.yml", ".github/workflows/stage-reproducibility.yml", ".github/workflows/stage-verify.yml"}
CLOSED = "not in the closed secret list"

# STATED LIMITS of the PR 1b mechanisms (round 1 (8)); none of them is closed by a judge of this kind:
#  - ambient reach is NAME-LEVEL: a listed script named as the step's script, as an ARGUMENT, or through the `runs` of either counts as run by
#    the step, so `bash bin/x.sh bin/adm.py` hands an ambient name listed for bin/adm.py to bin/x.sh as well; the step's env reaches every
#    process it starts, which no text judge can restrict to one script.
#  - a path or command name SPLIT by quoting or built at run time (`"dist"/sed`, `b''ash`, a variable) is not seen; the path-like word test reads
#    words as written.
#  - an exception waives ONE occurrence of exactly its rule and text; repeated invocations of one listed script belong in a `runs` row, not in
#    exceptions (a second occurrence of an excepted text stays a finding by design).
#  - a command text that crosses a backslash-newline is named by its JOINED text (bash joins with nothing inserted).
#  - reads_env is satisfied by any mention outside comments and docstrings, so a string that merely contains the name counts: it is a staleness
#    tripwire, not proof that the script reads the variable.
#  - the AC8 `unset GH_TOKEN` after admission cannot be judged by a text judge; the review of the script and the Witness record are what show it.
#  - AC1 wording residual: the English of REQ-CHAIN-001-AC1 predates the reviewed mechanisms (exceptions, ambient_env, pinned_steps); REQ-CHAIN-004-AC2
#    (ratified) is their basis; the owner is asked to add the clause.
#  - round 3: comment stripping inside ${..}, backticks and $'..' contexts; strings that span lines (a quote spanning lines pairs with a later quote on
#    its own line, read as unterminated and so left unmasked); brace expansion that builds a command word ({se,d}); and the ambient handoff is judged on
#    the script text only (textual order of simple commands, no loops or conditionals followed), not on what runs.
#  - the AC8 `unset GH_TOKEN` placement relative to child scripts is a reviewed line bound by the script's sha256 and the exact-text row below
#    (ambient_env `handoff_line`), not modelled: the judge does not follow order, depth, lists, functions, subshells or here-documents.
#  - round 4: quote-split word forms in the raw-token words beyond what the normalized reader resolves; trap and alias string bodies; a bare "$x" command
#    word (not refused: it would be a new class of finding for plain variable use, not measured against real scripts); git rebase -x, bisect run,
#    submodule foreach, tar old-style option bundles that consume following words, and GNU long-option abbreviations shorter than the 4-character prefix
#    rule (a finite option list in a text reader; the reviewed `deny` exception with the whole command is the way to admit a use).
#  - recorded limits after the round-5 check: the reader's normalized command word is not checked for curl, gh, git, docker, wget, nc, aws, kubectl, go,
#    pip, dpkg, su, crontab, script, trap (quote-split and backslash-escaped spellings such as \curl, cu""rl, c\x27\x27url are a stated limit); the positional
#    skip of a deny budget was tried (e059a3f on branch pipeline-chain-judge-exceptions-fix5) and withdrawn: it skipped a token whenever any command
#    word started there and read CRLF text as LF.
#  - deny exceptions bind the exact physical line with its sha256 and an exact count; the normalized-word check for \curl, cu""rl, c\x27\x27url is a stated limit.
class EnvNames(set):
    """The closed `env_names` (a set of names) that also carries `.ambient`: {name: {listed script paths that read it from their own
    environment}} from the top-level `ambient_env` list of chain-scripts.json (PR 1b, B). A step env name that its run line does not read
    whole is allowed only through this map."""
    def __init__(self, *a):
        super().__init__(*a); self.ambient = {}; self.pinned = {}; self.ambient_bind = {}; self.closed = False   # closed: the tree has a Release (stage-promote.yml job release), so the five named-secret rows are enforced
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
        if isinstance(e, dict) and e.get("rule") == "deny":
            # the LINE-BOUND shape: a deny exception binds the exact physical line, its sha256 and the exact number of such lines
            if set(e) != {"rule", "line", "line_sha256", "count", "why"}:
                errs.append("chain-scripts.json: %s a deny exception is line-bound: an object with exactly rule, line, line_sha256, count and why (the {rule, text, why} shape is not accepted for deny): %r" % (path, e)); continue
            ln, sha, cnt, why = e["line"], e["line_sha256"], e["count"], e["why"]
            if not isinstance(ln, str) or not ln or any(not (" " <= ch <= "~") for ch in ln):
                errs.append("chain-scripts.json: %s deny exception line %r must be one non-empty line of printable ASCII" % (path, ln)); continue
            if not isinstance(sha, str) or sha != hashlib.sha256(ln.encode("utf-8")).hexdigest():
                errs.append("chain-scripts.json: %s deny exception line %r: line_sha256 is not the sha256 of the line" % (path, ln)); continue
            if not isinstance(cnt, int) or isinstance(cnt, bool) or cnt < 1:
                errs.append("chain-scripts.json: %s deny exception line %r: count must be a positive integer" % (path, ln)); continue
            if not isinstance(why, str) or not why.strip():
                errs.append("chain-scripts.json: %s deny exception line %r has no reason (why)" % (path, ln)); continue
            if ("deny", ln) in seen:
                errs.append("chain-scripts.json: %s deny exception for line %r is listed twice" % (path, ln)); continue
            seen.add(("deny", ln)); good.append(e); continue
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
    try:       # the five rows are enforced once the tree has a Release: stage-promote.yml with a job named release (a tree without one has nothing to bind them to)
        env_names.closed = re.search(r"(?m)^  release:\s*$", open(os.path.join(base, ".github/workflows/stage-promote.yml"), errors="replace").read()) is not None
    except OSError:
        env_names.closed = False
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
        if "arg_words" in r and (not isinstance(r["arg_words"], list) or not r["arg_words"]
                                 or not all(isinstance(w, str) and re.fullmatch(r"[A-Za-z0-9_-]+", w) for w in r["arg_words"])):
            errs.append("chain-scripts.json: %s `arg_words` must be a non-empty list of plain words" % p)
        if "arg_map" in r and (not isinstance(r["arg_map"], dict) or not r["arg_map"]
                               or not all(isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_-]+", k) for k in r["arg_map"])
                               or not all(isinstance(v, str) for v in r["arg_map"].values())):
            errs.append("chain-scripts.json: %s `arg_map` must be a non-empty object of plain STEP words to listed script paths" % p)
        if not isinstance(r.get("runs", []), list):
            errs.append("chain-scripts.json: %s `runs` must be a list" % p)
        em = r.get("env_mentions", [])
        if not isinstance(em, list) or not all(isinstance(e, dict) and set(e) == {"name", "text", "why"} and all(isinstance(e[k], str) for k in e) for e in em):
            errs.append("chain-scripts.json: %s `env_mentions` must be a list of {name, text, why} strings" % p)
        txt = read_script(full)
        if "\r" in txt: errs.append("chain-scripts.json: %s contains a carriage return, which bash reads as part of a word" % p)
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
            plines = txt.split("\n")
            for e in good:
                if e["rule"] == "deny":
                    have = plines.count(e["line"])
                    if have == 0: errs.append("chain-scripts.json: %s deny exception line %r is not a line of the script (stale)" % (p, e["line"]))
                    elif have != e["count"]: errs.append("chain-scripts.json: %s deny exception line %r: the script has %d such lines, count says %d" % (p, e["line"], have, e["count"]))
                elif e["text"] not in txt and e["text"] not in logical(txt):
                    errs.append("chain-scripts.json: %s exceptions entry %r (%s) matches nothing in the file (stale)" % (p, e["text"], e["rule"]))
        rows[p] = r
    for p, r in rows.items():
        if isinstance(r.get("arg_map"), dict):
            for k, v in r["arg_map"].items():
                if isinstance(v, str) and v not in rows: errs.append("chain-scripts.json: %s arg_map %s names %r, which is not a listed row" % (p, k, v))
        for q in r.get("runs", []) if isinstance(r.get("runs", []), list) else []:
            if q not in rows: errs.append("chain-scripts.json: %s runs %r, which is not listed" % (p, q))
    amb = doc.get("ambient_env", [])
    if not isinstance(amb, list): errs.append("chain-scripts.json: ambient_env must be a list of {name, script, why}")
    else:
        seen, seen_at = set(), set()
        for e in amb:
            if (not isinstance(e, dict) or not {"name", "script", "why", "file", "job"} <= set(e) or set(e) - {"name", "script", "why", "file", "job", "handoff_line"}
                    or not all(isinstance(e[k], str) for k in e)):
                errs.append("chain-scripts.json: ambient_env entry %r must be an object with name, script, why, file and job (strings; file is the full stage path, job the job name) and optionally handoff_line" % (e,)); continue
            nm, sc, why = e["name"], e["script"], e["why"]
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", nm) or FORBID_ENV.fullmatch(nm):
                errs.append("chain-scripts.json: ambient_env name %r is not an allowed variable name (never BASH_ENV, PATH, LD_*, PYTHON*, NODE_*, GITHUB_*, ...)" % nm); continue
            if env_names.closed and e["file"] in CHAIN_STAGE_FILES and (e["file"], e["job"]) not in SECRET_ROWS.get(nm, {}):
                errs.append("chain-scripts.json: ambient_env %s for %s at %s job %s is %s (rule 56: five rows, each bound to exact scripts)" % (nm, sc, e["file"], e["job"], CLOSED)); continue
            if sc not in rows:
                errs.append("chain-scripts.json: ambient_env %s names script %r, which is not a listed script" % (nm, sc)); continue
            if not isinstance(rows[sc].get("reads_env"), list) or nm not in rows[sc]["reads_env"]:
                errs.append("chain-scripts.json: ambient_env %s names %s, whose row does not list %s in reads_env" % (nm, sc, nm)); continue
            if not why.strip():
                errs.append("chain-scripts.json: ambient_env %s for %s has no reason (why)" % (nm, sc)); continue
            if env_names.closed and e["file"] in CHAIN_STAGE_FILES and (e["file"] not in {f for f, _j in SECRET_ROWS.get(nm, {})} or (e["file"], e["job"]) not in SECRET_ROWS.get(nm, {}) or sc not in SECRET_ROWS[nm][(e["file"], e["job"])]):
                errs.append("chain-scripts.json: ambient_env %s for %s at %s job %s is %s (rule 56: five rows, each bound to exact scripts)" % (nm, sc, e["file"], e["job"], CLOSED)); continue
            if env_names.closed and nm in SECRET_VALUE and nm != "GH_TOKEN" and e["file"] not in CHAIN_STAGE_FILES:
                errs.append("chain-scripts.json: ambient_env %s for %s at %s job %s is %s" % (nm, sc, e["file"], e["job"], CLOSED)); continue
            if (nm, sc, e["file"], e["job"]) in seen_at:
                errs.append("chain-scripts.json: ambient_env %s for %s is listed twice at %s job %s" % (nm, sc, e["file"], e["job"])); continue
            if (nm, sc) in seen and not (nm == "GH_TOKEN" and sc == _WIT):      # only the wrapper is bound at both places of GH_TOKEN
                errs.append("chain-scripts.json: ambient_env %s for %s is listed twice" % (nm, sc)); continue
            if "file" in e and not re.fullmatch(r"\.github/workflows/stage-[A-Za-z0-9_.-]+\.ya?ml", e["file"]):
                errs.append("chain-scripts.json: ambient_env %s for %s: file %r is not a stage file path (.github/workflows/stage-*.yml)" % (nm, sc, e["file"])); continue
            if "job" in e and not re.fullmatch(r"[A-Za-z0-9_-]+", e["job"]):
                errs.append("chain-scripts.json: ambient_env %s for %s: job %r is not a plain job name" % (nm, sc, e["job"])); continue
            hl = e.get("handoff_line")
            if "handoff_line" in e and (not isinstance(hl, str) or any(not (" " <= ch <= "~") for ch in hl)):
                errs.append("chain-scripts.json: ambient_env %s for %s: handoff_line must be one line of printable ASCII" % (nm, sc)); continue
            if isinstance(hl, str) and hl.strip():       # round 4 (B): ONE exact source line, once, outside comments (its position is bound by the sha256 pin and review)
                n_hl = sum(1 for l in strip(open(os.path.join(base, sc), errors="replace").read()).splitlines() if l.strip() == hl.strip())
                if n_hl != 1:
                    errs.append("chain-scripts.json: ambient_env %s for %s: handoff_line %r occurs %d times outside comments in %s (exactly once is required)" % (nm, sc, hl, n_hl, sc)); continue
            seen.add((nm, sc)); seen_at.add((nm, sc, e["file"], e["job"])); env_names.ambient.setdefault(nm, set()).add(sc)
            env_names.ambient_bind.setdefault(nm, []).append((sc, e.get("file"), e.get("job")))
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
            if PINNED_ALLOWED.get((f, j, i)) != run:
                errs.append("chain-scripts.json: pinned_steps %s %s %s: only the ratified step is allowed (%s)" % (f, j, i, "; ".join("%s %s %s" % k for k in PINNED_ALLOWED))); continue
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

def _literal_value(parts):
    """The shell word a quote-only word stands for (round 3 (1)): lit, single-quoted and double-quoted parts without an expansion, joined (bi'n/x' is
    bin/x), or None when any part reads a variable or substitutes."""
    out = []
    for kind, t in parts:
        if kind == "dq" and re.search(r"[$`!]", t): return None
        if kind == "sq" and re.search(r"[$`]", t): return None
        out.append(t)
    return "".join(out)

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
        am, aw = rows[path].get("arg_map"), rows[path].get("arg_words")
        if isinstance(am, dict) and cmd != "bash":
            errs.append("line %d: %s: %s has an arg_map: it runs only as `bash %s STEP TARGET` (found %r)" % (n, line[:90], path, path, cmd))
        if isinstance(am, dict):                # round 3 (2): the wrapper's line is EXACTLY `bash WRAPPER STEP TARGET`, STEP bound to its one TARGET
            args = words[2:]
            raw0, raw1 = (args[0][0], args[1][0]) if len(args) == 2 else (None, None)
            if len(args) != 2 or am.get(raw0) != raw1 or any(len(a[1]) != 1 or a[1][0][0] != "lit" for a in args):
                errs.append("line %d: %s: %s takes exactly STEP TARGET as plain words with TARGET the one path its arg_map binds to STEP (%s)" % (n, line[:90], path, ", ".join("%s %s" % kv for kv in sorted(am.items()))))
        elif isinstance(aw, list):              # round 2 (4b): a wrapper's FIRST argument is one of its closed words
            f0 = _literal_value(words[2][1]) if len(words) > 2 else None
            if f0 is None or f0 not in aw:
                errs.append("line %d: %s: the first argument of %s must be one of its arg_words %s" % (n, line[:90], path, aw))
        for rawa, parts in words[2:]:
            e = _arg_error(parts, envnames)
            a = _literal_value(parts)       # round 3 (1): quote-only words are normalized BEFORE the path and reach rules
            if a is not None and (a.startswith(("/", "./", "../", "bin/")) or ".." in a.split("/") or "//" in a or a.endswith(SCRIPT_EXTS)) and a not in rows:
                errs.append("line %d: %s: argument %r names a script or a path under bin/ that is not an exact listed row path of chain-scripts.json" % (n, line[:90], a))
            if argpaths is not None and a is not None and a in rows: argpaths.add(a)
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
    run_count = {}                                  # round 4 (7): how often each run text occurs in the whole file
    for _jn, _j in ((d.get("jobs") or {}).items()):
        for _s in ((_j.get("steps") or []) if isinstance(_j, dict) else []):
            if isinstance(_s, dict) and isinstance(_s.get("run"), str): run_count[_s["run"]] = run_count.get(_s["run"], 0) + 1
    amb = getattr(env_names, "ambient", {})        # PR 1b (B): name -> listed scripts that read it from their own environment
    closed = getattr(env_names, "closed", False)
    if closed and full in CHAIN_STAGE_FILES:       # rule 56: a stored secret is read only as the value of a named env entry of Release; nowhere else, in no other stage
        def _noenv(x):
            if isinstance(x, dict): return {k: _noenv(v) for k, v in x.items() if not (k == "env" and full == _SP)}
            if isinstance(x, list): return [_noenv(v) for v in x]
            return x
        if re.search(r"(?i)\bsecrets\b", json.dumps(_noenv(d))):
            errs.append("%s: a stored secret outside %s (rule 56: %s)" % (rel, "the named env entries of Release" if full == _SP else "Release", "only Release holds a stored secret"))
    extra = set(d) - STAGE_WF_KEYS
    if extra: errs.append("%s: workflow keys %s are not allowed in a stage file (env, defaults, concurrency, run-name can reroute every step)" % (rel, sorted(extra)))
    for jn, j in ((d.get("jobs") or {}).items()):
        pre = "%s job %s" % (rel, jn)
        extra = set(j) - STAGE_JOB_KEYS
        if extra: errs.append("%s: job keys %s are not allowed (container, services, defaults, env, uses, secrets, with run other code or reroute steps)" % (pre, sorted(extra)))
        errs += _runner_errors(pre, j)
        if closed and (full, jn) in PLACE_PERMS and j.get("permissions") != PLACE_PERMS[(full, jn)]:
            errs.append("%s: job %s must hold exactly the permissions %s, found %s" % (full, jn, PLACE_PERMS[(full, jn)], j.get("permissions")))
        for s in (j.get("steps") or []):
            pin = pins.get((full, jn, s.get("id"))) if isinstance(s.get("id"), str) else None
            if pin is not None:
                # round 1 (5), a REVIEWED PINNED STEP: exactly name/id/run, and the run text equal to the entry's; nothing else about it is relaxed
                found.add((full, jn, s.get("id")))
                same_id = sum(1 for x in (j.get("steps") or []) if isinstance(x, dict) and x.get("id") == s.get("id"))
                if same_id != 1 or run_count.get(pin["run"], 0) != 1:
                    errs.append("%s: pinned step %r occurs %d time(s) in its job and its run text %d time(s) in the file; exactly once each is required" % (pre, s.get("id"), same_id, run_count.get(pin["run"], 0)))
                if set(s) != {"name", "id", "run"}: errs.append("%s: pinned step %r has keys %s; a pinned step has exactly name, id and run" % (pre, s.get("id"), sorted(s)))
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
                elif k not in env_names and k not in amb: errs.append("%s: env %s is not in the closed env_names list of chain-scripts.json%s" % (sp, k, (" and " + CLOSED) if closed and full in CHAIN_STAGE_FILES else ""))
            if uses is not None:
                if env: errs.append("%s: an action step passes env" % sp)
                ref = str(uses).partition(" #")[0]      # actions/setup-go is not allowed: Go is installed by the checksum-pinned `bash bin/install-scanner.sh go`
                m = USES_OK.fullmatch(ref.strip())
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
                if closed and full in CHAIN_STAGE_FILES and k in SECRET_ROWS:     # the five rows: name, place, scripts and value are exact
                    used = set(r) | argp
                    scripts = SECRET_ROWS[k].get((full, jn))
                    if scripts is None or not used <= scripts:
                        errs.append("%s: %s is allowed only %s (%s): found in %s job %s, reaching %s" % (sp, k, "for the admission step of stage-build.yml job apk" if k == "GH_TOKEN" else "in the named steps of stage-promote.yml job release",
                                    CLOSED, full, jn, ", ".join(sorted(used - (scripts or set())) or ["no listed script"])))
                    elif v != SECRET_VALUE[k]:
                        errs.append("%s: %s must be exactly %s, found %r" % (sp, k, SECRET_VALUE[k], v))
                elif closed and full in CHAIN_STAGE_FILES and k in amb:
                    errs.append("%s: env %s is %s" % (sp, k, CLOSED))
                if k in got and k not in amb: continue
                if k in amb and not FORBID_ENV.fullmatch(k):    # PR 1b (B): an ambient name is read by a listed script from its own environment
                    _bind = env_names.ambient_bind.get(k, [])       # a script may be bound at several places (the wrapper's GH_TOKEN): one of them must be this file and job
                    bad_bind = [(f, j) for sc, f, j in _bind if sc in reach and not any(sc2 == sc and f2 == full and j2 == jn for sc2, f2, j2 in _bind)]
                    if bad_bind:
                        errs.append("%s: env %s is bound to file/job %s, not to %s job %s" % (sp, k, ", ".join("%s/%s" % fj for fj in bad_bind), full, jn))
                    elif not (amb[k] & reach):
                        errs.append("%s: env %s is listed ambient only for %s, which this step does not run (as its script, an argument or through `runs`)" % (sp, k, ", ".join(sorted(amb[k]))))
                    elif (set(r) | argp) - amb[k]:
                        errs.append("%s: env %s reaches %s, which is not authorized in ambient_env for it (the step's command script and every listed script named as an argument receive the environment too; each needs its own ambient_env entry with a reason and reads_env)" % (sp, k, ", ".join(sorted((set(r) | argp) - amb[k]))))
                    elif closed and full in CHAIN_STAGE_FILES and k in SECRET_VALUE and v == SECRET_VALUE[k]:
                        pass                                           # the named value of the closed list, checked exactly above
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
def _is_python(path, text):
    return path.endswith(".py") or bool(re.match(r"#!\S*(?:/|\s)python", text))

# ---- the shell reader (round 2 (9), (5), (6)): ONE left-to-right pass per logical line over single quotes, double quotes, $'..', $".." backticks,
# ${..}, $(..) and <( ) / >( ), producing the simple commands. An UNTERMINATED quote, brace or backtick leaves the rest of the line UNMASKED (the
# quote character is dropped and the rest is read as ordinary text), so a quote that is never closed can hide nothing (this is the construct that
# failed open in the reverted attempt 3bac826 of PR 1). A quote that spans lines is read as unterminated on each line (fail closed, over-reports).
# Each simple command: leading assignments and redirections (any order and repetition: NAME=v, N>f, >f, &>f, >|f, <<<w, <<EOF, N>&M, {fd}>f) are
# skipped before the command word; keywords (if then elif else fi do done while until case esac in function select coproc ! { }) are skipped.
_REDIR_RE = re.compile(r"(?:[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\})?(?:&>>|&>|<<<|<<-?|>>|>\||>&|<&|<>|>|<)")
_ASSIGN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\s]*\])?\+?=")
_SKIP_WORDS = {"if", "then", "elif", "else", "fi", "do", "done", "while", "until", "case", "esac", "in", "function", "select", "coproc", "!", "{", "}"}

class Cmd:
    """One simple command: `text` as written from its first assignment or redirection (or its command word) to the separator; `cw` its command
    word (quotes removed, None when there is none); `operands` the other words (quotes removed); `redirs` [(operator, target)]."""
    def __init__(self, text, cw, operands, redirs): self.text, self.cw, self.operands, self.redirs, self.line = text, cw, operands, redirs, None

def _flush(s, items, end, cmds):
    if not items: return
    cw, ops, redirs = None, [], []
    for kind, _st, _en, _raw, val in items:
        if kind == "redir": redirs.append(val)
        elif kind == "word":
            if cw is None: cw = val
            else: ops.append(val)
    cmds.append(Cmd(s[items[0][1]:end].rstrip(), cw, ops, redirs))
    del items[:]

def _bt(s, j, cmds):
    """Index after the backtick substitution that opens at s[j]: it ends at the next UNESCAPED backtick (round 3 (6)); its body, with \\`, \\\\ and \\$
    unescaped (nesting by escaped backticks), is read as commands of its own. A substitution that is never closed reads the rest of the line."""
    n, k = len(s), j + 1
    while k < n and s[k] != "`": k += 2 if s[k] == "\\" else 1
    body = re.sub(r"\\([`\\$])", r"\1", s[j + 1:min(k, n)])
    _lex(body, 0, None, cmds)
    return min(k + 1, n)

def _brace(s, j, cmds):
    """Index after the ${...} that starts at s[j:j+2] == '${', or None when it is never closed."""
    n, k, depth = len(s), j + 2, 1
    while k < n:
        c = s[k]
        if c == "\\": k += 2; continue
        if c == "'":
            e = s.find("'", k + 1)
            if e < 0: return None
            k = e + 1; continue
        if c == '"':
            r = _dq(s, k, cmds)
            if r is None: return None
            k = r[0]; continue
        if c == "$" and s.startswith("$(", k): k = _lex(s, k + 2, ")", cmds); continue
        if c == "`": k = _bt(s, k, cmds); continue
        if c == "$" and s.startswith("${", k): depth += 1; k += 2; continue
        if c == "}":
            depth -= 1; k += 1
            if depth == 0: return k
            continue
        k += 1
    return None

def _dq(s, j, cmds):
    """(index after the closing quote, value) of the double-quoted string at s[j], or None when it is never closed. Commands found inside it
    ($( ), backticks, ${ }) are appended to `cmds` only when the string closes."""
    n, k, parts, tmp = len(s), j + 1, [], []
    while k < n:
        c = s[k]
        if c == '"':
            cmds.extend(tmp); return k + 1, "".join(parts)
        if c == "\\":
            nxt = s[k + 1] if k + 1 < n else ""
            parts.append(nxt if nxt in '$`"\\' else "\\" + nxt); k += 2; continue
        if c == "$" and s.startswith("$(", k): k = _lex(s, k + 2, ")", tmp); parts.append("$(..)"); continue
        if c == "$" and s.startswith("${", k):
            e = _brace(s, k, tmp)
            if e is None: parts.append("$"); k += 1; continue
            parts.append(s[k:e]); k = e; continue
        if c == "`": k = _bt(s, k, tmp); parts.append("`..`"); continue
        parts.append(c); k += 1
    return None

def _word(s, i, cmds):
    """(end, raw text, value with quotes and escapes removed) of the word starting at s[i]."""
    n, j, parts = len(s), i, []
    while j < n:
        c = s[j]
        if c in " \t;&|()": break
        if c in "<>":
            if j + 1 < n and s[j + 1] == "(": j = _lex(s, j + 2, ")", cmds); parts.append("<(..)"); continue
            break
        if c == "\\":
            if j + 1 < n: parts.append(s[j + 1]); j += 2
            else: j += 1
            continue
        if c == "'":
            e = s.find("'", j + 1)
            if e < 0: j += 1; continue                     # unterminated: the quote is dropped, the rest stays unmasked
            parts.append(s[j + 1:e]); j = e + 1; continue
        if c == '"':
            r = _dq(s, j, cmds)
            if r is None: j += 1; continue
            parts.append(r[1]); j = r[0]; continue
        if c == "$":
            if s.startswith("$'", j):
                k = j + 2
                while k < n and s[k] != "'": k += 2 if s[k] == "\\" else 1
                if k >= n: j += 1; parts.append("$"); continue
                parts.append(re.sub(r"\\(.)", r"\1", s[j + 2:k])); j = k + 1; continue
            if s.startswith('$"', j):
                r = _dq(s, j + 1, cmds)
                if r is None: j += 1; parts.append("$"); continue
                parts.append(r[1]); j = r[0]; continue
            if s.startswith("$(", j): j = _lex(s, j + 2, ")", cmds); parts.append("$(..)"); continue
            if s.startswith("${", j):
                e = _brace(s, j, cmds)
                if e is None: parts.append("$"); j += 1; continue
                parts.append(s[j:e]); j = e; continue
        if c == "`": j = _bt(s, j, cmds); parts.append("`..`"); continue
        parts.append(c); j += 1
    return j, s[i:j], "".join(parts)

def _lex(s, i, closer, cmds):
    n, items, kw = len(s), [], None
    while i < n:
        c = s[i]
        if c in " \t": i += 1; continue
        if closer == ")" and c == ")":
            _flush(s, items, i, cmds); return i + 1
        m = _REDIR_RE.match(s, i)
        if m and not (m.end() < n and s[m.end()] == "(" and m.group(0) in ("<", ">")):
            j = m.end()
            while j < n and s[j] in " \t": j += 1
            e, val = j, ""
            if j < n and s[j] not in ";|&()":
                e, _raw, val = _word(s, j, cmds)
            items.append(("redir", i, e, s[i:e], (m.group(0), val))); i = e; continue
        if c in ";|&()": _flush(s, items, i, cmds); i += 1; continue
        e, raw, val = _word(s, i, cmds)
        if e == i: i += 1; continue
        if kw is not None:                   # round 3 (7): the NAME after `function` / `coproc NAME {` is not a command; the body that follows is
            skip, kw = (kw == "function" or re.match(r"[ \t]*[({]", s[e:]) is not None), None
            if skip and not items: i = e; continue
        if not any(k == "word" for k, *_ in items):
            if _ASSIGN_RE.match(raw): items.append(("assign", i, e, raw, val)); i = e; continue
            if raw == val and val in _SKIP_WORDS:
                if val == "}": _flush(s, items, i, cmds)
                if val in ("function", "coproc"): kw = val
                i = e; continue
        items.append(("word", i, e, raw, val)); i = e
    _flush(s, items, n, cmds)
    return n

def shell_commands(text):
    """The simple commands (Cmd) of comment-stripped, continuation-joined shell text, every logical line read on its own."""
    cmds = []
    for k, line in enumerate(logical(strip(text)).splitlines()):
        before = len(cmds)
        _lex(line, 0, None, cmds)
        for c in cmds[before:]: c.line = k                 # the logical line the command was read from (scan_script maps it to a physical line)
    return cmds

# Round 1 (4) + round 2 (8): fail closed by default for a path-like word whose LAST component is a deny-class command (or a glob that could be one).
# It is refused wherever it appears unless it is an OPERAND (not the command word) of (a) an interpreter run on an exact listed path of `runs`,
# (b) a listed script invoked by its exact path, or (c) a closed list of data-only commands none of whose options runs a program.
VERSIONED = re.compile(r"(?:python|perl|ruby|lua|php|node|bash|sh|dash|zsh|ksh|awk|gawk|mawk|nawk|sed|gsed)[0-9][0-9.]*")
ALT_ANY = {"nodejs", "rbash", "gsed", "tcsh", "csh", "emacs", "nvi"}                       # denied wherever the word appears
ALT_CMD = {"ash", "fish", "vi", "vim", "view", "ex", "ed", "man", "less", "more", "pdksh", "mksh"}   # common English words: judged at command position and as a path's last component only
_INTERP_BASES = {"python", "bash", "sh", "dash", "zsh", "ksh", "rbash", "ash", "csh", "tcsh", "fish", "pdksh", "mksh"}

def family_kind(name):
    """'interp' or 'eval' for a versioned or alternate name of an interpreter or evaluator (python3.11, perl5.38, rbash, gsed, vi, ex ...), else None."""
    if name in ALT_ANY or name in ALT_CMD or VERSIONED.fullmatch(name):
        return "interp" if re.sub(r"[0-9][0-9.]*$", "", name) in _INTERP_BASES else "eval"
    return None

def is_deny_token(n):
    return n in DENY or n in ALT_ANY or VERSIONED.fullmatch(n) is not None

DENYCLASS = DENY | LAUNCH_OUTRIGHT | EVALUATORS | ALT_ANY | ALT_CMD
GLOBCH = re.compile(r"[*?\[\]]")
def deny_class_last(last):
    """Is this path component a deny-class command, or a glob pattern that could match one?"""
    if last in DENYCLASS or VERSIONED.fullmatch(last): return True
    return bool(GLOBCH.search(last)) and any(fnmatch.fnmatchcase(c, last) for c in DENYCLASS)

# Round 3 (3): the OPTIONS that run a program, refused as options (rule deny, text the whole command) for the commands that have them. Long options are
# matched by name, including an unambiguous abbreviation of 4+ characters (GNU getopt); short ones letter by letter inside a bundle (-xIf, -cMF,
# -I/bin/sh), up to the first letter that takes an argument.
LONG_RUN = {"tar": ("use-compress-program", "to-command", "checkpoint-action", "info-script", "new-volume-script", "rsh-command"),
            "sort": ("compress-program",), "install": ("strip-program",), "rsync": ("rsh", "rsync-path"), "git": ("exec-path", "upload-pack", "receive-pack")}
# round 4 (5), REDUCED: git configuration keys that load a program (a finite list in a text reader; rebase -x, bisect run, submodule foreach, tar old-style
# bundles and GNU long-option abbreviations beyond the 4+ character prefix rule are stated limits)
GIT_RUN_KEY = re.compile(r"(?i)(core\.(sshcommand|pager|editor|fsmonitor|hookspath|askpass)|credential\.[^=]*helper|diff\.external|gpg\.[^=]*program)")
SHORT_RUN = {"tar": "IF", "rsync": "e"}
TAR_ARG_LETTERS = "bCfFgIKLNTVX"
def program_option(cmd, operands):
    """The first program-running option of this command, or None. make, xargs (any command operand) and the find/ssh/git forms are covered too."""
    if re.fullmatch(r"g?make[0-9.]*", cmd): return cmd
    ops = list(operands)
    if cmd == "tar" and ops and re.fullmatch(r"[A-Za-z]+", ops[0]): ops[0] = "-" + ops[0]      # old style: tar xIf ...
    for idx, o in enumerate(ops):
        if cmd == "find" and o in ("-exec", "-execdir", "-ok", "-okdir"): return o
        if cmd == "ssh" and (o == "-o" and idx + 1 < len(ops) and re.match(r"(?i)(proxycommand|localcommand|permitlocalcommand)", ops[idx + 1]) or re.match(r"(?i)-o(proxycommand|localcommand)", o)): return o
        if cmd == "git" and o == "-c" and idx + 1 < len(ops) and (GIT_RUN_KEY.match(ops[idx + 1]) or re.match(r"(?i)alias\.[^=]*=!", ops[idx + 1])): return "-c " + ops[idx + 1]
        if cmd == "git" and (o == "--config-env" and idx + 1 < len(ops) or o.startswith("--config-env=")):
            kv = ops[idx + 1] if o == "--config-env" else o.split("=", 1)[1]
            if GIT_RUN_KEY.match(kv) or kv.lower().startswith("alias."): return o + " " + kv
        if not o.startswith("-") or o == "-": continue
        if o.startswith("--"):
            name = o[2:].split("=")[0]
            for full in LONG_RUN.get(cmd, ()):
                if name == full or (len(name) >= 4 and full.startswith(name) and name != "checkpoint"): return o
        else:
            for ch in o[1:]:
                if ch in SHORT_RUN.get(cmd, ""): return o
                if cmd == "tar" and ch in TAR_ARG_LETTERS: break
    return None

DATA_ONLY = {"cp", "mv", "rm", "mkdir", "rmdir", "ls", "cat", "echo", "printf", "test", "[", "[[", "sha256sum", "shasum", "tar", "mktemp", "touch",
             "chmod", "ln", "readlink", "basename", "dirname", "head", "tail", "wc", "sort", "grep", "cut", "tr", "diff", "cmp", "install", "du",
             "stat", "date", "sleep", "true", "false"}
RUNNY_OPT = ("program", "command", "exec", "action", "filter", "rsh", "shell")
def runs_a_program(operands):
    """An option whose name says it runs a program (--use-compress-program, --to-command, --checkpoint-action, -exec, -I ...)."""
    for o in operands:
        if not o.startswith("-") or o == "-": continue
        opt = o.lstrip("-").split("=")[0].lower()
        if any(k in opt for k in RUNNY_OPT) or o in ("-I", "-F", "-ok", "-okdir"): return True
    return False
TOKEN = re.compile(r"[^\s;&|(){}<>`\"'=,]+")

def pathlike_deny(cmds, rows, runs):
    """The path-like words (see above) of the commands that are neither the command word of their command (judged by the command-word rule)
    nor an admitted operand."""
    out = []
    for c in cmds:
        if c.cw is None: continue
        cw = c.cw[2:] if c.cw.startswith("./") else c.cw
        admitted = (cw in rows or (cw in SHELL_INTERP and bool(c.operands) and (c.operands[0][2:] if c.operands[0].startswith("./") else c.operands[0]) in runs)
                    or family_kind(cw) == "interp" and bool(c.operands) and (c.operands[0][2:] if c.operands[0].startswith("./") else c.operands[0]) in runs
                    or (c.cw in DATA_ONLY and not runs_a_program(c.operands)))
        if admitted: continue
        for o in c.operands:
            for t in TOKEN.findall(o):
                n = t[2:] if t.startswith("./") else t
                if "/" in n and not n.startswith(("-", "$")) and "://" not in n and deny_class_last(n.rsplit("/", 1)[-1]): out.append((t, c.line))
    return out

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
    if "\r" in text:                               # bash reads a CR as part of a word: no waiver applies, nothing else is judged
        return ["%s: contains a carriage return, which bash reads as part of a word" % path]
    fnd = []                                       # (rule or None, exact text, message, physical line index or None); rule None = never waived
    def add(rule, txt, msg, ln=None): fnd.append((rule, txt, msg, ln))
    tools, runs = set(row.get("tools", [])), set(row.get("runs", []))
    selfbase = os.path.basename(path)
    py = _is_python(path, text)
    listed_base = {os.path.basename(r) for r in rows}
    body = text.split("\n", 1)[1] if text.startswith("#!") and "\n" in text else ("" if text.startswith("#!") else text)   # the shebang names the file's OWN interpreter
    # Codex #249 r7 B3 (the class closed): a script token is compared to the manifest EXACTLY (only a leading ./ is normalised; no
    # basename match), a command named by ANY path is refused even when its bare name is in `tools` (the row governs the bare name only),
    # and a launcher prefix (env, command, exec, builtin, nohup, sudo, timeout, nice, xargs, ...) followed by another program is refused.
    off = 1 if text.startswith("#!") and "\n" in text else 0          # physical line index of body line 0
    bl = body.split("\n")
    if bl and bl[-1] == "": bl.pop()
    exotic = len(body.splitlines()) != len(bl)                        # another line separator: line numbers cannot be trusted (fail closed: not waivable)
    starts, i_ = [], 0                                                # first physical body line of each logical (continuation-joined) line
    pcode = [strip_line(l_) for l_ in body.splitlines()]
    while i_ < len(pcode):
        starts.append(i_)
        while i_ + 1 < len(pcode) and len(pcode[i_]) - len(pcode[i_].rstrip("\\")) in range(1, len(pcode[i_]) + 1) and (len(pcode[i_]) - len(pcode[i_].rstrip("\\"))) % 2 == 1:
            i_ += 1
        i_ += 1
    def phys(k):                                   # the physical line of a command-level finding: known only when its logical line is ONE physical line
        if exotic or k is None or k >= len(starts): return None
        end = starts[k + 1] if k + 1 < len(starts) else len(pcode)
        return off + starts[k] if end - starts[k] == 1 else None
    cmds = [] if py else shell_commands(body)
    cw_budget = {}                                 # round 2 (1): a script path at a COMMAND POSITION is judged once, as the whole command (below),
    for c in cmds:                                 # never by its token: the token pass skips as many occurrences as there are commands named by it
        if c.cw is not None: cw_budget[c.cw] = cw_budget.get(c.cw, 0) + 1
    def repo_file(n):
        """Is `n` a regular file of THIS tree? Only a relative path without `..` is looked up: an absolute path, or one that climbs out, is judged by its text
        and the rules alone and never by what the host has there (advisor ruling, finding 5: no host file may change a verdict)."""
        return not n.startswith("/") and ".." not in n.split("/") and os.path.isfile(os.path.join(base, n))
    def script_like(t):
        n = t[2:] if t.startswith("./") else t
        pathlike = "/" in n and not n.startswith(("-", "$")) and "://" not in n
        ok = n.endswith(SCRIPT_EXTS) or n in rows or n.rsplit("/", 1)[-1] in listed_base
        if not ok and (pathlike or t.startswith("./")):
            full = os.path.join(base, n)
            if repo_file(n):                  # Sonnet 1: the existence, shebang and executable tests run on the normalised path (of the tree only)
                with open(full, "rb") as fh: ok = fh.read(2) == b"#!" or os.access(full, os.X_OK)
        return ok
    for tm in re.finditer(r"[^\s;&|(){}<>`\"'=,]+", WORKSPACE_ROOT.sub("", body)):      # the checkout root written as the runner's variable is the listed path itself
        t = tm.group(0)
        n = t[2:] if t.startswith("./") else t
        name = n.rsplit("/", 1)[-1]
        pathlike = "/" in n and not n.startswith(("-", "$")) and "://" not in n
        if pathlike and (name in DENY or (py and (name in DENYCLASS or VERSIONED.fullmatch(name)))):     # round 4 (8): Python strings get the whole deny class
            # PR 1b: in a SHELL script a path-like word is judged as a command only at command position (below); an argument such as
            # archive/go is judged by the script rule alone. A Python script has no command position, so it keeps the word-level test.
            tline = None if exotic else off + body.count("\n", 0, tm.start())
            if py: add("deny", t, "%s: names the command %r by a path (name it bare, so its `tools` row governs it)" % (path, t), tline)
        elif is_deny_token(n) and n not in tools:
            add("deny", t, "%s: names the command %r, which is not in this script's `tools` list" % (path, t), None if exotic else off + body.count("\n", 0, tm.start()))
        if script_like(t) and n != path and n not in runs and not (n == selfbase):
            if cw_budget.get(t, 0) > 0: cw_budget[t] -= 1; continue
            add("script-name", t, "%s: names the script %r, which is not exactly a path in this script's `runs` list" % (path, t))
    if not py and workspace_touched(text):               # round 5: a parent script that changes the variable moves every listed child that reads it, so no listed shell script may do more than read it
        add("script-name", "GITHUB_WORKSPACE", "%s: the variable GITHUB_WORKSPACE is set, unset, read into, brace-expanded or reached by a built name here: a listed script may only read it plainly" % path)
    if not py:
        for t, cline in pathlike_deny(cmds, rows, runs):
            add("deny", t, "%s: names the command %r by a path (name it bare, so its `tools` row governs it; only an operand of a data-only command, of an interpreter run on a listed script or of a listed script is allowed)" % (path, t), phys(cline))
        for c in cmds:
            if c.cw is None: continue
            w = c.cw
            n = w[2:] if w.startswith("./") else w
            name = n.rsplit("/", 1)[-1]
            span = c.text                          # the whole simple command, from its first assignment or redirection, as written
            if "/" in n and not n.startswith(("-", "$")) and "://" not in n and deny_class_last(name):
                add("deny", w, "%s: names the command %r by a path (name it bare, so its `tools` row governs it)" % (path, w), phys(c.line))
            elif "/" not in n and GLOBCH.search(n) and re.search(r"[A-Za-z]", n) and deny_class_last(n):      # a bare * or ? is a case pattern, not a command name
                add("deny", w, "%s: names the command %r by a pattern that could match a denied command (a path or pattern: name it bare)" % (path, w), phys(c.line))
            if w.startswith(("/", "$(..)", "`..`")):         # round 4 (10): minimal: an absolute path or a substitution as the command word (a bare "$x" stays a stated limit)
                add("script-name", span, "%s: %r is a command word that is an absolute path or built at run time: run time or absolute, it is not judged (name it bare or by an exact listed path)" % (path, w))
            kind = family_kind(name)
            po = program_option(name, c.operands)
            if po is not None:
                add("deny", c.text, "%s: %r uses the program-running option %r (refused as an option; a reviewed line-bound `deny` exception may waive it)" % (path, w, po), phys(c.line))
            if name in LAUNCH_OUTRIGHT:
                add("launcher", span, "%s: %r at command position launches another program (refused whatever `tools` says)" % (path, w)); continue
            if (name in EVALUATORS and not (name == "openssl" and not (c.operands and c.operands[0] == "s_client"))) or kind == "eval":
                if name not in tools: add("evaluator", span, "%s: %r at command position is an evaluator not in this script's `tools` list" % (path, w))
                continue
            if name in SHELL_INTERP or kind == "interp":
                first = c.operands[0] if c.operands else ""
                ws = WORKSPACE_ROOT.match(first)                # "$GITHUB_WORKSPACE/<exact listed path>": a script that moves its directory names the helper from the checkout root
                if ws and (workspace_touched(text) or workspace_strict(text)):              # round 4: the name must still be the runner's own: any use but a plain read is refused
                    add("script-name", span, "%s: the variable GITHUB_WORKSPACE is set, unset, read into or expanded with a default in this script, so %r no longer names the checkout root" % (path, first)); continue
                if ws and any(span[max(0, m.start() - 1):m.start()] == "\\" or "'" in span[:m.start()] for m in re.finditer(r"\$\{?GITHUB_WORKSPACE", span)):
                    ws = None                                   # round 4: in a single quote or after a backslash the shell passes the text itself, not the checkout root
                fn = first[ws.end():] if ws else (first[2:] if first.startswith("./") else first)
                if any(op.startswith("<") for op, _t in c.redirs) or not first or first.startswith("-") or fn not in runs:
                    add("script-name", span, "%s: %r is handed %r, not an exact listed path of this script's `runs` (no option, -c, stdin or other file)" % (path, w, first or "stdin"))
                continue
            in_tree = ("/" in w or w.startswith("./")) and repo_file(n)
            if (w.startswith("./") or in_tree or script_like(w)) and n != path and n not in runs and n != selfbase:
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
    plines = text.split("\n")
    for e in (exception_entries(path, row["exceptions"])[0] if "exceptions" in row else []):
        if e["rule"] == "deny":                    # line-bound: every deny finding on a physical line that equals `line`, if the script has exactly `count` such lines
            if plines.count(e["line"]) != e["count"]: continue
            hit = False
            for i, (rule, _t, _m, ln) in enumerate(fnd):
                if rule == "deny" and ln is not None and ln < len(plines) and plines[ln] == e["line"]: waived.add(i); hit = True
            if not hit: errs.append("%s: deny exception for line %r waives nothing (no deny finding is on a line with exactly that text)" % (path, e["line"]))
            continue
        for i, (rule, txt, _msg, _ln) in enumerate(fnd):
            if i not in waived and rule == e["rule"] and txt == e["text"]:
                waived.add(i); break
        else:
            errs.append("%s: exceptions entry %r (%s) waives nothing (no finding of that rule has exactly that text)" % (path, e["text"], e["rule"]))
    return list(dict.fromkeys([m for i, (_r, _t, m, _l) in enumerate(fnd) if i not in waived] + errs))
