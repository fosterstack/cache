#!/usr/bin/env python3
"""The automatic patch-release decision (owner RATIFIED Oct 2: ops/docs/ratify/2026-10-02-automatic-patch-releases.md,
with the floating-tags amendment; advisor read-backs 0051/0055/0056; REQ-REL-009).

  classify / patch_clean  rule 1: a patch carries fixes only. Each commit since the latest tag is, by the files it
                          changes, fix-class (dependency version pins of existing modules in go.mod/go.sum, the
                          base-image digest pins in build/docker/Dockerfile.*, the VEX and suppression files), neutral
                          (no shipped byte: .github/, docs/, requirements/, test-evidence/, tests) or not patch-clean
                          (anything else, unless its merged PR carries the `patch-fix` label, which the owner applies,
                          or the lane only when both step-8 reviewers recorded "no behavior change").
  next_patch              rule 1: vX.Y.Z -> vX.Y.(Z+1); CI never makes a minor or major.
  daily_cut               rule 2: at most one daily patch (a critical/high fix may cut at once, outside this rule).
  notes                   rule 5: per fix the CVE, package, old -> new, severity, variants; each VEX change; a
                          no-behavior-change line; no vendor or model names.
  removed_critical_high   rule 2: the latest release's critical/high findings that HEAD removes (a Go module or the
                          toolchain at or past the advisory's fixed version; a distribution package the new base
                          image no longer reports); unknown or unreadable never counts as removed.
  floating                amendment: :X.Y always; :X and :latest only when this is the highest released version.
"""
import argparse, json, os, re, subprocess, sys

FIX_EXACT = {".snyk", "osv-scanner.toml"}
FIX_PREFIX = (".vex/", ".auditor/")
NEUTRAL_PREFIX = (".github/", "docs/", "requirements/", "test-evidence/")
DOCKERFILES = re.compile(r"^build/docker/Dockerfile\.[a-z0-9-]+$")
SEMVER = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?$")
def _sep(*words):
    """An alternation of names in which - _ or . may split any two letters: open-ai, co_here, deep.seek are the same
    names (Sonnet #159 r2, BLOCKER-1)."""
    return "|".join("[-_.]?".join(re.escape(c) for c in w) for w in words)


# no vendor or model names in public text (row 48; Codex #158 r1, B06: the wider set)
# A platform name that qualifies a model goes with it (Codex #158 phase-2 r2, B06: "Google Gemini" left "Google").
VENDOR = re.compile(r"(?i)((" + _sep("google", "microsoft", "amazon", "aws", "azure", "xai", "meta", "github")
                    + r"|x\.ai)\s+)?(chat[-_.\s]*gpt|"
                    + _sep("anthropic", "claude", "openai", "gpt", "codex", "gemini", "llama", "mistral", "mixtral", "grok",
                           "bedrock", "deepseek", "qwen", "copilot", "cohere", "bard", "sonnet", "opus", "haiku", "xai")
                    + r")(?:[\w-]|\.(?=\w))*|\bo[1-9](-(mini|pro|preview))?\b")
# a vendor named alone (Sonnet #158 r3: rule 5 forbids vendor OR model names) is redacted wherever it stands, next to a
# hyphen or slash too (Sonnet #158 r3b, NEW-BLOCKER-2: "AWS-reported", "Google/Microsoft"); fail closed — only a whole token
# that is a wholly lowercase domain or module path stays readable (google.golang.org/protobuf, github.com/aws/aws-sdk-go-v2);
# a camelCase boundary counts as a word boundary (Codex #159 r1, B5: providerGoogle.go), an ordinary word (laws) does not;
# Meta too, with the separators every name takes (Codex #158 phase-2 r3, NEW-BLOCKER-4: Me-ta, providerMeta.go)
VENDOR_ALONE = re.compile(r"(?i)(?:(?<![a-z0-9])|(?<=[a-z0-9])(?-i:(?=[A-Z])))("
                          + _sep("google", "microsoft", "amazon", "aws", "azure", "meta") + r")(?-i:(?![a-z0-9]))")
MODULE_PATH = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+(/[a-z0-9_.@~+-]+)*/?$")   # every part lowercase (Sonnet r3c, NEW-BLOCKER-3)


def _alone(m):
    text, i, j = m.string, m.start(), m.end()
    while i > 0 and not text[i - 1].isspace() and text[i - 1] not in "([{\"'<,;":
        i -= 1
    while j < len(text) and not text[j].isspace() and text[j] not in ")]}\"'>,;":
        j += 1
    token = text[i:j].rstrip(".:")
    return m.group(0) if MODULE_PATH.match(token) else "<redacted>"


# the release chain's build inputs shape the shipped image: never neutral (Codex #158 r1, B04). Fail closed (Sonnet #158 r2,
# NEW-01): a workflow is neutral only when it is reviewed as outside the release chain (release.yml calls stage-*.yml and
# the acceptance workflows); any other — including one added later — is not patch-clean until it is reviewed here.
NEUTRAL_WORKFLOWS = {"agent-review-gate.yml", "auditor.yml", "ci.yml", "codeql.yml", "daily-rescan.yml",
                     "dependabot-auto-merge.yml", "dependabot-reviewer.yml", "dependency-review.yml", "go-freshness.yml",
                     "hygiene.yml", "main-candidate-rescan.yml", "release-chain-pr.yml", "requirements.yml",
                     "rescan-v010.yml", "reserved-branch-guard.yml", "scan.yml", "scorecard.yml"}
BUILD_INPUTS = re.compile(r"^\.goreleaser\.ya?ml$")
# Outside workflows, .github/ is release-chain input by default: the stage workflows run .github/agent/bin and read
# .github/policy (Codex #158 phase-2 r2, B04). Neutral only what is reviewed as never read by the release chain.
NEUTRAL_GITHUB = {".github/dependabot.yml", ".github/CODEOWNERS", ".github/PULL_REQUEST_TEMPLATE.md"}
NEUTRAL_GITHUB_PREFIX = (".github/agent/reviews/", ".github/agent/docs/")   # tests: NEUTRAL_TESTS (advisor 0107)


def _changed_lines(diff):
    return [ln for ln in (diff or "").splitlines() if ln[:1] in "+-" and ln[1:].strip()]


GO_BLOCK = re.compile(r"^(require|replace|exclude|retract|tool|ignore|godebug)\s*\($")
GO_REQ = re.compile(r"^(\S+)\s+(v\S+)(\s*//\s*indirect)?$")


def _go_mod_changes(diff):
    """{key: {sign: value}} for a go.mod diff that changes only require versions (in a require block known from the
    diff's context, or a single-line require) and the go/toolchain line; None for anything else, including an absent
    or empty diff (Codex #158 r1, B01/B02: replace, exclude, a line whose block is unknown — all fail closed)."""
    if not diff or not diff.strip():
        return None
    block, ch = None, {}
    for raw in diff.splitlines():
        if raw.startswith("@@"):
            block = None                    # a new hunk: its block is known only from its own context (r2, B02)
            continue
        sign, body = (raw[0], raw[1:]) if raw[:1] in ("+", "-", " ") else (" ", raw)
        t = body.strip()
        if sign == " ":
            if GO_BLOCK.match(t):
                block = GO_BLOCK.match(t).group(1)
            elif t == ")":
                block = None
            continue
        if not t or t.startswith("//"):
            continue
        m = re.match(r"^(go|toolchain)\s+(\S+)$", t)
        if m:
            key, val = "dir:" + m.group(1), m.group(2)
        else:
            m = re.match(r"^require\s+(\S+)\s+(v\S+)(\s*//\s*indirect)?$", t) or (block == "require" and GO_REQ.match(t))
            if not m:
                return None
            key, val = "req:" + m.group(1), (m.group(2), bool(m.group(3)))
        if sign in ch.setdefault(key, {}):
            return None
        ch[key][sign] = val
    if not ch:
        return None
    for key, v in ch.items():
        if set(v) != {"+", "-"} or v["+"] == v["-"]:
            return None                     # added, removed or unchanged: not a version move of an existing pin
        if key.startswith("req:") and v["+"][1] != v["-"][1]:
            return None                     # the indirect marker changed
    return ch


def _go_sum_ok(diff, moved):
    """go.sum lines only follow go.mod version moves of the same module tree: no go.sum-only edit, and never a
    checksum rewrite of the same module version (Codex #158 r1, B02)."""
    if not diff or not diff.strip() or not moved:
        return False
    # each line is the old version (removed) or the new version (added) of a module whose require moved; a go or
    # toolchain move explains no go.sum line (Codex #158 phase-2 r2, B02)
    allowed = {("-" if s == "-" else "+", k[4:], v[0]) for k, vs in moved.items() if k.startswith("req:")
               for s, v in vs.items()}
    if not allowed:
        return False
    seen = {}
    for ln in _changed_lines(diff):
        m = re.match(r"^([+-])(\S+) (v\S+?)(/go\.mod)? h1:\S+$", ln)
        if not m or m.group(1, 2, 3) not in allowed:
            return False
        seen.setdefault(m.group(2, 3, 4), set()).add(m.group(1))
    return all(signs != {"+", "-"} for signs in seen.values())


FROM = re.compile(r"^FROM\s+((?:--\S+\s+)*)(\S+?)@sha256:([0-9a-f]{64})(\s+AS\s+\S+)?\s*$", re.I)


def _digest_only(diff):
    """Each FROM keeps its flags, image, tag and alias and only the digest moves; no stage added or removed
    (Codex #158 r1, B03)."""
    # each change is a removed FROM directly followed by its replacement, so the instruction keeps its place
    # (Codex #158 phase-2 r2, B03)
    raw = [ln for ln in (diff or "").splitlines() if not ln.startswith(("+++", "---"))]
    pairs, i = 0, 0
    while i < len(raw):
        if raw[i][:1] == "+":
            return False                    # an added line not directly replacing a removed FROM
        if raw[i][:1] == "-":
            o = FROM.match(raw[i][1:].strip())
            n = FROM.match(raw[i + 1][1:].strip()) if i + 1 < len(raw) and raw[i + 1][:1] == "+" else None
            if not o or not n or o.group(1, 2, 4) != n.group(1, 2, 4) or o.group(3) == n.group(3):
                return False
            pairs, i = pairs + 1, i + 2
            continue
        i += 1
    if not pairs:
        return False
    return True


# Advisor 0107 (AC1's "tests" = tests no release stage runs, written down): a test is neutral only when it is listed here
# — seeded with the tests only ci.yml runs (its scripts and `go test ./...`); additions only by a reviewed change. Any
# other test is not patch-clean. cross_check turns red when a listed test is found run by a release stage.
NEUTRAL_TESTS = frozenset("""
.github/agent/tests/auditor-matrix-test.sh
.github/agent/tests/auditor-parser-tests.sh
.github/agent/tests/coverage-check.py
.github/agent/tests/coverage-gate.sh
.github/agent/tests/govulncheck-fixtures-test.sh
.github/agent/tests/pin-wiring-test.sh
bin/authorize-acceptance-check-test.sh
bin/check-file-allowlist-test.sh
bin/dependabot-reviewer-gather-test.sh
bin/dependabot-reviewer-test.sh
bin/dependency-lanes-test.sh
bin/go-bump-open-pr-test.sh
bin/go-freshness-wiring-test.sh
bin/inspector-gate-test.sh
bin/install-scanner-test.sh
bin/panel-test.sh
bin/panel-wiring-test.sh
bin/patch-decide-test.sh
bin/release-patch-wiring-test.sh
bin/required-check-guard-test.sh
bin/rescan-statement-test.sh
bin/vex-both-scanners-test.sh
bin/vex-forms-test.sh
bin/vex-scope-test.sh
bin/workflow-consolidation-test.sh
cmd/fscache/main_test.go
cmd/fscache/serve_test.go
internal/blobstore/blobstore_faults_test.go
internal/blobstore/blobstore_test.go
internal/blobstore/perms_test.go
internal/buildinfo/buildinfo_test.go
internal/cache/cache_test.go
internal/cache/fault_test.go
internal/cache/reconcile_test.go
internal/metadata/metadata_errors_test.go
internal/metadata/metadata_test.go
internal/server/bounds_test.go
internal/server/errorpaths_test.go
internal/server/router_test.go
internal/server/server_test.go
internal/server/status_test.go
internal/server/surface_test.go
tools/requirements/cli_test.go
tools/requirements/fixed_test.go
tools/requirements/main_test.go
tools/requirements/trace_test.go
""".split())


DATA_FILE = re.compile(r"\.(md|txt|json|ya?ml|toml|csv)$")


def _is_test(path, neutral=None):
    return path in (NEUTRAL_TESTS if neutral is None else neutral)


# commands find -exec / xargs may run without making every test chain input (Sonnet #159 r7, B3): anything else —
# an interpreter, quoted or wrapped (env), a script, a variable — fails closed
SAFE_INDIRECT = {"rm", "sha256sum", "sha1sum", "md5sum", "chmod", "chown", "touch", "cat", "ls", "stat", "wc", "echo",
                 "grep", "test", "du", "basename", "dirname"}


def _shell_tokens(line):
    """The words of a shell line, with | ; & ( ) as their own tokens (no spaces needed), quotes honoured; None when it
    cannot be tokenized."""
    import shlex
    lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
    lex.whitespace_split = True
    lex.commenters = "#"
    try:
        return list(lex)
    except ValueError:
        return None


def _indirect_exec(text, depth=0):
    """True when a find -exec/-execdir/-ok/-okdir or an xargs runs anything but a bare SAFE_INDIRECT command. Every line
    that mentions one is tokenized as the shell reads it (quotes honoured, | ; & split without spaces); a quoted word that
    is itself a command (a YAML scalar, bash -c '…') is read again; an untokenizable line fails closed (Codex #159 r8/r9)."""
    op = re.compile(r"(?<![\w-])[\"']?-(?:exec|execdir|ok|okdir)[\"']?(?![\w-])|(?<![\w-])xargs(?![\w-])")
    for line in re.sub(r"\\\n", " ", text).splitlines():
        if not op.search(line):
            continue
        toks = _shell_tokens(line)
        if toks is None or depth > 3:
            return True
        for k, t in enumerate(toks):
            if " " in t and op.search(t) and _indirect_exec(t, depth + 1):
                return True                                       # a command inside a quoted word
            cmd = None
            if t in ("-exec", "-execdir", "-ok", "-okdir"):
                cmd = toks[k + 1] if k + 1 < len(toks) else ""
            elif os.path.basename(t) == "xargs":
                i = k + 1
                while i < len(toks) and toks[i].startswith("-"):
                    i += 2 if re.fullmatch(r"-[nLPsdIEaJ]", toks[i]) else 1      # an option with a separate value
                cmd = toks[i] if i < len(toks) else "echo"
                if re.fullmatch(r"[|;&()]+|[<>]", cmd):
                    cmd = "echo"                                                 # xargs with no command runs echo
            if cmd is not None and ("/" in cmd or cmd not in SAFE_INDIRECT):
                return True
    return False


def effective_neutral(texts):
    """NEUTRAL_TESTS at decision time (Sonnet #159 r6, B2): a listed test that any release-chain file names — by path
    or by file name, in any form (an env value, a subprocess list) — is not neutral; and when a chain file runs an
    interpreter through find -exec or xargs (it executes files it never names) no test is neutral. texts: {path:
    content} of the chain; the classifier's own list (this file) is not a mention."""
    out = set(NEUTRAL_TESTS)
    for path, text in texts.items():
        if path == "bin/patch-decide.py":
            continue
        if _indirect_exec(text):
            return set()
        out -= {t for t in out if t in text or re.search(r"(?<![\w.-])" + re.escape(t.rsplit("/", 1)[-1]) + r"(?![\w.-])", text)}
    return out


def cross_check(chain, texts):
    """The walk as a cross-check of NEUTRAL_TESTS (advisor 0107): ValueError when a listed test is in the release chain,
    or a chain file runs `go test` (the listed Go tests would then be gates). texts: {path: content} of the chain (or
    one workflow/shell text); shell and YAML are read without comments, Python by an argv list naming go then test."""
    run = sorted(NEUTRAL_TESTS & set(chain))
    if run:
        raise ValueError("listed neutral tests are run by the release chain: %s" % ", ".join(run))
    for path, text in (texts.items() if isinstance(texts, dict) else [("chain.yml", texts or "")]):
        if path.endswith(".py"):
            hit = re.search(r"[\"']go[\"']\s*,\s*[\"']test[\"']", text)
        else:
            hit = any(re.search(r"\bgo\s+test\b", ln.split(" #")[0]) for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        if hit:
            raise ValueError("%s runs go test: the listed Go tests would be gates" % path)


EXECUTABLE = re.compile(r"\.(sh|py|ya?ml)$")


def release_chain_files(cwd=".", start=".github/workflows/release.yml"):
    """Every workflow and script the release chain executes at HEAD (advisor 0105): release.yml, the workflows it calls
    (uses: ./…, transitively), every script or program they name, and every script those name in turn — found by path
    or next to their caller ($here/x.py). A test a stage runs as a gate is in it; a test no stage runs is not."""
    tree = set(_git("ls-tree", "-r", "--name-only", "HEAD", cwd=cwd).split())
    seen, todo = set(), [start] if start in tree else []
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        try:
            text = _git("show", "HEAD:" + f, cwd=cwd)
        except subprocess.CalledProcessError:
            continue
        here = os.path.dirname(f)
        # executed, not merely named: a workflow by uses:, a script by an interpreter, by ./path or by $dir/path —
        # a path read as data (git show main:…/ci.yml, a fixture, a policy file) is not followed
        refs = set(re.findall(r"uses:\s*\./(\.github/workflows/[\w.-]+\.ya?ml)", text))
        for d in re.findall(r"uses:\s*\./((?!\.github/workflows/)[\w./-]+?)/?\s*$", text, re.M):   # a local composite
            refs |= {d.rstrip("/") + "/" + a for a in ("action.yml", "action.yaml") if d.rstrip("/") + "/" + a in tree}
            # action (Sonnet #159 r5, F1): its steps run too
        # an interpreter only at the start of a command (after whitespace or a separator) — never the "sh" that ends a
        # file name such as x-test.sh (Codex #159 r6, B1: a list of test names is data, not executions)
        # any file executed, whatever its extension (Codex #159 r9, B4: bash docs/gate, bash docs/gate.txt) — kept only
        # when it is a file of the tree, and walked through
        # only at command position — the first word of a command: a line start (after "- " / "run:" / a quote), after
        # ; & | ( `, or after a keyword or wrapper — so "osv-scanner scan source go.mod" names no program (Codex r9)
        # a quoted scalar opens only right after "run:" (B8) — never at the start of a continued line, where a quote
        # starts an argument (Codex #159 r5a, B9)
        cmdpos = (r"(?:^[ \t]*(?:-[ \t]+)?(?:run:[ \t]*(?:\n[ \t]*)?[\"']|run:[ \t]*)?[|>]?[ \t]*|[;&|(`][ \t]*)"
                  # any chain of keywords and wrappers (if ! …, while ! …, env …; Codex #159 r10, B7) and VAR=value
                  r"(?:(?:(?:then|do|else|if|elif|while|until|exec|env|nohup|time|sudo|command|builtin)|!)[ \t]+"
                  r"|[A-Za-z_]\w*=\S*[ \t]+|(?:/[\w.-]+)*/env[ \t]+)*[\"']?")
        # an interpreter by name or absolute path, quoted or not, in any of the languages a runner has (r10, R1)
        cands = re.findall(cmdpos + r"(?:/[\w.-]+)*/?(?:bash|sh|dash|zsh|ksh|python[\d.]*|source|\.|node|nodejs|deno|bun|"
                           r"perl|ruby|php|pwsh|lua|Rscript|awk|gawk)[\"']?[ \t]+(?:-[\w-]+[ \t]+)*[\"']?(?:\$\{?\w+\}?/)?"
                           r"([\w./-]*[\w-])", text, re.M)
        cands += re.findall(cmdpos + r"\./([\w./-]*[\w-])", text, re.M)
        cands += re.findall(cmdpos + r"\$\{?\w+\}?/([\w./-]*[\w-])", text, re.M)
        for c in cands:
            for r in (os.path.normpath(c), os.path.normpath(os.path.join(here, c))):
                if r in tree:
                    refs.add(r)
                    break
        todo += [r for r in refs if r not in seen]
    return seen


def classify(commit):
    """('fix' | 'neutral' | 'dirty', reason) for one commit. commit["chain"]: the files the release chain executes
    (release_chain_files) — any of them is not patch-clean, whatever its path (advisor 0105)."""
    files, diffs = commit.get("files") or [], commit.get("diffs") or {}
    chain = set(commit.get("chain") or ())
    kinds, why = set(), []
    for f in files:
        if f in chain and not (f in FIX_EXACT or (f.startswith(FIX_PREFIX) and DATA_FILE.search(f)) or f in ("go.mod", "go.sum", "tools/requirements/go.mod",
                                                                                  "tools/requirements/go.sum") or DOCKERFILES.match(f)):
            # a fix-class file keeps its own strict, line-level rule even when something names it (Codex #159 r5a, B9)
            kinds.add("dirty"); why.append("%s is executed by the release chain" % f)
        elif _is_test(f, commit.get("neutral")):
            kinds.add("neutral")
        elif f.startswith(NEUTRAL_PREFIX) and not DATA_FILE.search(f) and not f.startswith(".github/workflows/") \
                and f not in NEUTRAL_GITHUB:
            # only data is neutral by its directory (Sonnet #159 r7 B4, r8): anything without a data extension —
            # a script, an extensionless file, another extension — could be executed, so it is not
            kinds.add("dirty"); why.append("%s is not a data file; a directory does not make it neutral" % f)
        elif f in FIX_EXACT or (f.startswith(FIX_PREFIX) and DATA_FILE.search(f)):
            # the auditor's output directories make only DATA fix-class — never a script there (Codex #159 r5b, B10)
            kinds.add("fix")
        elif f in ("go.mod", "tools/requirements/go.mod"):
            if _go_mod_changes(diffs.get(f)) is not None:
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes more than existing modules' versions (or has no diff)" % f)
        elif f in ("go.sum", "tools/requirements/go.sum"):
            mod = f[:-len("go.sum")] + "go.mod"
            if _go_sum_ok(diffs.get(f), _go_mod_changes(diffs.get(mod)) if mod in files else None):
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes checksums its go.mod's version moves do not explain" % f)
        elif DOCKERFILES.match(f):
            if _digest_only(diffs.get(f)):
                kinds.add("fix")
            else:
                kinds.add("dirty"); why.append("%s changes more than the base-image digest pin" % f)
        elif BUILD_INPUTS.match(f) or (f.startswith(".github/workflows/") and f.split("/")[-1] not in NEUTRAL_WORKFLOWS):
            kinds.add("dirty"); why.append("%s builds or ships the release image" % f)
        elif f.startswith(".github/") and not f.startswith(".github/workflows/") \
                and f not in NEUTRAL_GITHUB and not f.startswith(NEUTRAL_GITHUB_PREFIX):
            kinds.add("dirty"); why.append("%s is read by the release chain (or not reviewed as outside it)" % f)
        elif f.startswith(NEUTRAL_PREFIX) or _is_test(f, commit.get("neutral")):
            kinds.add("neutral")
        else:
            kinds.add("dirty"); why.append("%s is shipped source or configuration" % f)
    if "dirty" in kinds and "patch-fix" in (commit.get("labels") or []):
        return "fix", "labelled patch-fix (no behavior change)"
    if "dirty" in kinds:
        return "dirty", "; ".join(why)
    return ("fix" if "fix" in kinds else "neutral"), ""


def ships_bytes(commits):
    return any(classify(c)[0] == "fix" for c in commits)


def patch_clean(commits):
    """(True, []) when every commit is fix-class or neutral and at least one ships bytes; (False, why) otherwise
    (why is empty when nothing would ship)."""
    why = ["%s: %s" % (c.get("sha", "?")[:7], r) for c in commits for k, r in [classify(c)] if k == "dirty"]
    if why:
        return False, why
    return ships_bytes(commits), []


def _semver(tag):
    m = SEMVER.match(tag or "")
    return tuple(int(x) for x in m.groups()) if m else None


def next_patch(tags):
    vs = sorted(v for v in (_semver(t) for t in tags) if v)
    if not vs:
        return None
    x, y, z = vs[-1]
    return "v%d.%d.%d" % (x, y, z + 1)


def daily_cut(ships, cut_today):
    return bool(ships) and not cut_today


def _clean(s):
    return VENDOR_ALONE.sub(_alone, VENDOR.sub("<redacted>", str(s)))


def notes(version, fixes, vex_changes):
    lines = ["## %s — patch release" % version, "", "### Fixes"]
    for f in fixes:
        lines.append("- %s in %s: %s → %s (severity %s; variants: %s)" % (
            f["cve"], f["package"], f["old"], f["new"], f["severity"], ", ".join(f.get("variants") or [])))
    if not fixes:
        lines.append("- none (dependency or VEX maintenance only)")
    lines += ["", "### VEX"]
    lines += ["- %s: %s (%s)" % (v["cve"], v["status"], v["change"]) for v in vex_changes] or ["- no change"]
    lines += ["", "No behavior change: this release contains fixes only."]
    return _clean("\n".join(lines)) + "\n"


def _precedence(tag):
    """Semantic-version precedence including our -rc.N prereleases: vX.Y.Z-rc.N sorts below vX.Y.Z."""
    m = VERSION.match(tag or "")
    if not m:
        return None
    x, y, z, rc = m.groups()
    return (int(x), int(y), int(z), 1, 0) if rc is None else (int(x), int(y), int(z), 0, int(rc))


def floating(version, released):
    """The floating tags a CI patch moves (amendment, owner Oct 2): :X.Y always; :X and :latest only when it outranks
    every released version, prereleases included (Codex #158 r1, B05)."""
    v = _semver(version)
    mine = _precedence(version)
    others = [o for o in (_precedence(t) for t in released) if o]
    out = ["%d.%d" % v[:2]]
    if all(mine >= o for o in others):
        out += ["%d" % v[0], "latest"]
    return out


GO_VERSION = re.compile(r"^(?:go|v)?(\d+)\.(\d+)(?:\.(\d+))?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def _go_ver(v):
    """((X, Y, Z), prerelease?) for a Go module or toolchain version; None when it cannot be read (go1.26rc1)."""
    m = GO_VERSION.match(str(v or ""))
    return ((int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)), bool(m.group(4))) if m else None


def _at_least(have, want):
    """Is `have` at or past a fix? A prerelease or pseudo-version is below its release (Codex #159 r1, B1); with several
    fix versions (one per release stream), `have` counts only past the fix of its own X.Y stream, or past every one.
    Anything unreadable is never "fixed"."""
    h = _go_ver(have)
    fixes = [_go_ver(w) for w in ([want] if isinstance(want, str) else list(want or []))]
    if not h or not fixes or not all(fixes) or any(f[1] for f in fixes):
        return False
    (hv, pre), mains = h, [f[0] for f in fixes]

    def past(f):
        return hv > f or (hv == f and not pre)
    same = [f for f in mains if f[:2] == hv[:2]]
    return any(past(f) for f in same) if same else all(past(f) for f in mains)


def removed_critical_high(release_findings, head):
    """The latest release's critical/high findings that HEAD removes. head: {"go": {module: version at HEAD},
    "base_findings": [findings of the new base image] or None when it could not be scanned}."""
    out = []
    for f in release_findings:
        if str(f.get("severity", "")).lower() not in ("critical", "high") or not f.get("fixed"):
            continue
        if f.get("type") == "go-module":
            have = (head.get("go") or {}).get(f["package"])
            if have and _at_least(have, f["fixed"]):
                out.append(f)
        elif f.get("type") == "deb":
            base = head.get("base_findings")
            if base is not None and not any(b.get("id") == f["id"] and b.get("package") == f["package"] for b in base):
                out.append(f)
    return out


def decide(event, commits, tags, cut_today, removed):
    """{cut, version, reason, not_clean}: rule 1 (patch-clean, fix-only), rule 2 (a critical/high fix at once on push;
    otherwise at most one daily patch on the schedule)."""
    version = next_patch(tags)
    clean, why = patch_clean(commits)
    out = {"cut": False, "version": version, "reason": "", "not_clean": why}
    if version is None:
        out["reason"] = "no release yet: the first release is the owner's"
    elif why:
        out["reason"] = "main is not patch-clean"
    elif not clean:
        out["reason"] = "nothing shipped since the latest tag"
    elif event == "push":
        if removed is None:
            out["reason"] = "the latest release could not be scanned: no at-once cut (the daily run decides)"
        elif removed:
            out.update(cut=True, reason="a critical or high finding removed: %s" % ", ".join(f["id"] for f in removed))
        else:
            out["reason"] = "no critical or high finding removed"
    elif daily_cut(True, cut_today):
        out.update(cut=True, reason="daily: shipped bytes ahead of the latest tag")
    else:
        out["reason"] = "a patch was already cut today"
    return out


def _scope(req):
    """admission reads `.scope // "push"`: absent, null or false is push (Codex #159 pin pass, B01)."""
    s = req.get("scope")
    return "push" if s is None or s is False else s      # identity, not ==: scope 0 is not push (Codex #159 r2, B6)


def ready(required, check_runs):
    """(verdict, why) for the tagged commit's push-scoped required checks, judged as source admission judges them
    (stage-admission.yml): a check counts only as a success from its pinned app. "ready": every one has one. "wait": none
    is red with nothing left to run (a run is missing, queued or in progress). "no": a check finished without success and
    no run of it is still pending. pull_request-scoped checks are admission's to read on the merged PR head."""
    waiting, red = [], []
    reqs = required.get("required_checks") if isinstance(required, dict) else None
    # a policy admission would reject is never ready (Codex #159 r1, B6): admission fails on these
    if not isinstance(reqs, list) or not reqs:
        return "no", "policy error: no required_checks list"
    for req in reqs:
        if not isinstance(req, dict) or not req.get("context") or not isinstance(req.get("integration_id"), int):
            return "no", "policy error: a required check without a context or integration_id"
        if _scope(req) not in ("push", "pull_request"):
            return "no", "policy error: unknown scope %r for required check %r" % (req.get("scope"), req["context"])
    for req in reqs:
        if _scope(req) != "push":
            continue
        mine = [r for r in check_runs if r.get("name") == req["context"] and r.get("app_id") == req["integration_id"]]
        if any(r.get("status") == "completed" and r.get("conclusion") == "success" for r in mine):
            continue
        if not mine or any(r.get("status") != "completed" for r in mine):
            waiting.append(req["context"])
        else:
            red.append(req["context"])
    if red and not waiting:
        return "no", "not green on the tagged commit: " + ", ".join(red)
    if waiting:
        return "wait", "waiting on: " + ", ".join(waiting)
    return "ready", "every push-scoped required check is green"


def _git(*args, cwd="."):
    return subprocess.run(["git", "-C", cwd] + list(args), capture_output=True, text=True, check=True).stdout


def gather_commits(since, cwd=".", labels=lambda sha: []):
    """The commits since a tag (oldest first) with the files each changes, each file's changed lines, and the labels of
    the PR that merged it (from `labels`; none when it cannot be read: a missing label never admits a change)."""
    out = []
    chain = sorted(release_chain_files(cwd))       # what the release chain executes at HEAD (advisor 0105)
    texts = {f: _git("show", "HEAD:" + f, cwd=cwd) for f in chain}
    # advisor 0107's cross-check never aborts a decision (Codex #159 r8, B6: an inert string naming a listed test made a
    # dependency patch impossible): what it finds only narrows the neutral list for this decision; the repository's own
    # test (bin/patch-decide-test.sh, in CI) keeps it red
    neutral = effective_neutral(texts) - set(chain)
    try:
        cross_check([], texts)
    except ValueError:
        neutral = {t for t in neutral if not t.endswith("_test.go")}          # the chain runs go test
    neutral = sorted(neutral)
    for sha in _git("rev-list", "--reverse", "%s..HEAD" % since, cwd=cwd).split():
        files = [f for f in _git("show", "--format=", "--name-only", sha, cwd=cwd).splitlines() if f]
        # full context: the classifier needs a go.mod line's block (require vs replace/exclude) to judge it
        diffs = {f: "\n".join(ln for ln in _git("show", "--format=", "--unified=100000", sha, "--", f, cwd=cwd).splitlines()
                              if ln[:1] in "+- " and not ln.startswith(("+++", "---")))
                 for f in files}
        out.append({"sha": sha, "files": files, "diffs": diffs, "labels": list(labels(sha)), "chain": chain,
                    "neutral": neutral})
    return out


def grype_findings(doc):
    """Grype's matches, every fix version kept (B1). A document without a matches list is not a clean scan: refused
    (Codex #159 r1, B2)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("matches"), list):
        raise ValueError("not a grype scan: no matches list")
    out = []
    for m in doc["matches"]:
        # every field this decision reads has its type checked, so a malformed scan takes the handled path (refused
        # here) and never crashes the caller into a release-wide unknown (Codex #159 r3, NEW-1)
        v, a = (m.get("vulnerability"), m.get("artifact")) if isinstance(m, dict) else (None, None)
        if not isinstance(v, dict) or not isinstance(a, dict):
            raise ValueError("not a grype scan: a match without its vulnerability or artifact object")
        if not all(isinstance(x, str) and x for x in (v.get("id"), a.get("name"), a.get("version"))):
            raise ValueError("not a grype scan: a match without its id, package or version")   # Codex #159 r2, B2
        fix = v.get("fix") or {}
        fixed = fix.get("versions") or [] if isinstance(fix, dict) else None
        if not isinstance(fixed, list) or not all(isinstance(x, str) for x in fixed):
            raise ValueError("not a grype scan: fix.versions is not a list of versions")
        if not all(x is None or isinstance(x, str) for x in (v.get("severity"), a.get("type"))):
            raise ValueError("not a grype scan: a severity or package type that is not a string")
        out.append({"id": v.get("id"), "package": a.get("name"), "installed": a.get("version"), "severity": v.get("severity"),
                    "fixed": list(fixed),
                    "type": "go-module" if a.get("type") in ("go-module", "golang") else a.get("type")})
    return out


def gomod_versions(text):
    """{module: version} from go.mod, plus the toolchain as stdlib (go1.X.Y from the go directive)."""
    out = {m.group(1): m.group(2) for m in re.finditer(r"(?m)^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+(v\S+)", text)}
    m = re.search(r"(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$", text)
    if m:
        out["stdlib"] = "go" + m.group(1)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="patch-decide")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--event", choices=("push", "schedule", "workflow_dispatch"), required=True)
    d.add_argument("--repo", default=".")
    d.add_argument("--cut-today", choices=("true", "false"), required=True)
    d.add_argument("--removed", help="JSON list of the release's critical/high findings HEAD removes")
    d.add_argument("--removed-unknown", action="store_true", help="the latest release could not be scanned")
    d.add_argument("--released", required=True,
                   help="JSON list of the tags with a published release: the baseline is the latest of these, never a "
                        "tag whose release failed (Codex #159 r1, B4)")
    d.add_argument("--labels", help="JSON {sha: [labels]} of the PRs that merged each commit")
    d.add_argument("--out", required=True)
    k = sub.add_parser("ready")
    k.add_argument("--required", required=True, help=".github/policy/required-checks.json")
    k.add_argument("--check-runs", required=True, help="JSON list of the commit's check runs {name, status, conclusion, app_id}")
    r = sub.add_parser("removed")
    r.add_argument("--release-grype", required=True, action="append", help="one per scanned release image")
    r.add_argument("--gomod", required=True)
    r.add_argument("--base-grype", action="append", help="one per scanned base image")
    r.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "ready":
        verdict, why = ready(json.load(open(a.required)), json.load(open(a.check_runs)))
        print(verdict, _clean(why))
        return 0
    if a.cmd == "removed":
        try:
            release = [f for p in a.release_grype for f in grype_findings(json.load(open(p)))]
        except (ValueError, OSError) as e:
            print("removed: the release scan is unusable: %s" % e, file=sys.stderr)
            return 2
        try:
            base = [f for p in a.base_grype for f in grype_findings(json.load(open(p)))] if a.base_grype else None
        except (ValueError, OSError):
            base = None                     # an unusable base scan removes no deb finding
        found = removed_critical_high(release, {"go": gomod_versions(open(a.gomod).read()), "base_findings": base})
        with open(a.out, "w") as fh:
            json.dump(found, fh, indent=1)
        return 0
    tags = [t for t in _git("tag", "-l", "v*", cwd=a.repo).split()]
    released = [t for t in json.load(open(a.released)) if _semver(t) and t in tags]
    since = max(released, key=_semver) if released else None
    labels = json.load(open(a.labels)) if a.labels else {}
    commits = gather_commits(since, a.repo, labels=lambda sha: labels.get(sha, [])) if since else []
    removed = None if a.removed_unknown else json.load(open(a.removed)) if a.removed else []
    event = "schedule" if a.event == "workflow_dispatch" else a.event
    # no published release yet: the first release is the owner's, whatever tags a failed attempt left
    dec = decide(event, commits, tags if since else [], a.cut_today == "true", removed)
    dec["since"] = since
    # decision.json feeds a public issue (the "not patch-clean" list): every string in it is redacted as stdout is
    dec = {k: ([_clean(x) for x in v] if isinstance(v, list) else _clean(v) if isinstance(v, str) else v)
           for k, v in dec.items()}
    with open(a.out, "w") as fh:
        json.dump(dec, fh, indent=1)
    print(_clean("patch decision: %s — %s" % ("cut " + dec["version"] if dec["cut"] else "no cut", dec["reason"])))
    for w in dec["not_clean"]:
        print(_clean("  not patch-clean: " + w))
    return 0


if __name__ == "__main__":
    sys.exit(main())
