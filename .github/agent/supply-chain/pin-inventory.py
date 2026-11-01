#!/usr/bin/env python3
"""The inventory of what our workflows pin and download (REQ-SUP-001, rule 1 and rule 2).

One item is "<kind>:<name>@<version>":
  action   owner/repo@<40-hex commit>   from `uses:` in workflows and in the composite actions under .github/actions
  tool     name@version                 installer-action inputs (golangci-lint, python) and the *_VER pins of bin/install-scanner.sh
  gotool   module/path@version          `go install path@version` in a run step
  package  pypi/name@version            the hash-pinned requirements files
  image    name@sha256:digest           container:/services: images and docker:// actions (name:tag@sha256:digest is the SAME item: Docker ignores the tag)
NOT in the inventory (rule 1, amendments 1 and 2): the product's base image, Go modules and the Go toolchain.

Used as a module by pin-age-check.py and pin-audit.py; run alone it prints the inventory of a tree.
"""
import copy
import fnmatch
import hashlib
import shlex
import json
import os
import re
import subprocess
import sys

import yaml

SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# installer-action inputs that name a version of something the action downloads: action -> (input, tool name)
INSTALLER_INPUTS = {
    "golangci/golangci-lint-action": [("version", "golangci-lint")],
    "actions/setup-python": [("python-version", "python")],
    "actions/setup-java": [("java-version", "java")],
    "actions/setup-node": [("node-version", "node")],
    "goreleaser/goreleaser-action": [("version", "goreleaser")],
    "sigstore/cosign-installer": [("cosign-release", "cosign")],
    "google-github-actions/setup-gcloud": [("version", "gcloud")],
    "azure/setup-helm": [("version", "helm")],
    "docker/setup-buildx-action": [("version", "buildx")],
    "docker/setup-qemu-action": [("image", None)],
    "helm/kind-action": [("version", "kind"), ("kubectl_version", "kubectl"), ("node_image", None)],  # None: the input names an image
}
# NOT here, on purpose (rule 1, amendment 2): actions/setup-go's go-version and go.mod's toolchain line; the standard library ships in our binary.
_GO_INSTALL = re.compile(r"\bgo\s+install\b([^\n;&|]*)")
_GO_TARGET = re.compile(r"(?<![\w.\-/@])((?:\$\{var\}|[\w.\-/])+)@((?:\$\{\{expression\}\}|\$\{var\}|[\w.\-+()]|\$(?!\{\{))+)")
_GH_DOWNLOAD = re.compile(r"github\.com/([\w.-]+/[\w.-]+)/releases/download/(v?)((?:\$\{\{expression\}\}|\$\{var\}|[\w.+()-]|\$(?!\{\{))+)/([^\s/'\x22?#;|&]+)")
_GH_LATEST = re.compile(r"github\.com/([\w.-]+/[\w.-]+)/releases/latest/download/")
_GO_RUN_GET = re.compile(r"\bgo\s+(?:run|get)\b([^\n;&|]*)")
_SEP = re.compile(r"[;&|]")


def _tails(run, is_cmd, subcommands, skip_values=(), keep_sub=False):
    """For every command word `is_cmd` accepts, the text after its subcommand: found by walking tokens (linear time: a regex over an option chain can backtrack exponentially)."""
    out = []
    for line in run.split("\n"):
        toks = re.sub(r"[;&|]+", " ; ", line).split()      # `cd x&&pip install y` and `a;pip install y` are two commands
        for i, t in enumerate(toks):
            if not is_cmd(t):
                continue
            j = i + 1
            while j < len(toks) and toks[j].startswith("-"):
                j += 2 if (toks[j] in skip_values and "=" not in toks[j]) else 1
            while j < len(toks) and toks[j] in ("container", "image") and toks[j] not in subcommands:
                j += 1
            if j < len(toks) and toks[j] in subcommands:
                tail = []
                for tk in toks[j + 1:]:
                    if _SEP.search(tk):
                        tail.append(_SEP.split(tk)[0])
                        break
                    tail.append(tk)
                out.append((toks[j], " ".join(tail)) if keep_sub else " ".join(tail))
                if len(out) > MAX_ITEMS_PER_STEP:
                    raise RuntimeError("a step repeats one command more than %d times: refusing to read it (a hostile text could exhaust the readers)" % MAX_ITEMS_PER_STEP)
    return out


def _pip_tails(run):
    return _tails(run, lambda t: re.fullmatch(r"pip[0-9.]*", t) is not None, {"install"}, _PIP_VALUE_OPTS | {"--timeout", "--retries", "--proxy", "--cert", "--cache-dir", "--log"})
_PIP_PIN = re.compile(r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]*\])?(==|>=|<=|~=|!=|>|<)((?:\$\{\{expression\}\}|\$\{var\}|[^\s\\;'\",$]|\$(?!\{\{))+)")
_RUN_IMAGE = re.compile(r"(?<![\w./:@-])((?:[\w.-]+(?::\d+)?/)*[\w.-]+(?::[\w.-]+)?@sha256:[0-9a-f]{64})")
_VER_PIN = re.compile(r"^[ \t]*(?:(?:export|readonly|declare(?:\s+-\w+)?|local)\s+)?([A-Z][A-Z0-9]*)_VER=['\"]?([^\s'\"#]+)", re.M)
_REQ_PIN = re.compile(r"^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w,.-]*\])?==([^\s;\\]+)", re.M)
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml",
                  ".github/actions/*/*/action.yml", ".github/actions/*/*/action.yaml")


_EXPR = re.compile(r"\$\{\{.*?\}\}", re.S)


MAX_FILE = 1_000_000
VERSION_FILES = (".python-version", ".nvmrc", ".node-version", ".java-version", ".tool-versions", ".sdkmanrc", ".ruby-version")


def _strip_expressions(text):
    """Every ${{ ... }} becomes the placeholder, in LINEAR time (a lazy regex over an unclosed run of '${{' is quadratic and could stall a reader for minutes)."""
    out, i = [], 0
    while True:
        a = text.find("${{", i)
        if a < 0:
            out.append(text[i:])
            return "".join(out)
        b = text.find("}}", a + 3)
        if b < 0:
            out.append(text[i:a] + "${{expression}}")   # unclosed: the rest is one expression
            return "".join(out)
        out.append(text[i:a] + "${{expression}}")
        i = b + 2


def _hide(text):
    """An expression (which may name a secret or an environment) becomes a placeholder: it can never be proven, so it fails closed, and it never prints."""
    if not isinstance(text, str):
        return text
    text = _strip_expressions(text)
    return re.sub(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", "${var}", text)  # a shell variable's name (an env var, maybe a secret's) never prints either


class Item:
    def __init__(self, kind, name, version, label="", path=""):
        self.kind, self.name, self.version, self.label, self.path = kind, _hide(name), _hide(version), _hide(label), _hide(path)  # path: an action's subdirectory
        self.rawid = False   # the item's name is a release asset's: it is identified by the RAW text of its step (a "latest" download included)
        self.step = ""   # a placeholder's identity: the hash of the step it sits in
        self.raw = None  # a file item's repository path, exactly as git names it (name goes through _hide(); REQ-SUP-001-AC21 compares this)
        self.src = None  # (script path, line id) of the script line that made this item (not part of its identity): REQ-SUP-001-AC20 binds a ruled row to that line
        self.sums = []   # the checksum(s) the repo pins for this tool or package (an install-scanner.sh SUM, a requirements --hash), from every occurrence: part of the item's identity (rc-5b item 6) but not of its key

    @property
    def key(self):
        sub = f"/{self.path}" if self.path else ""
        return f"{self.kind}:{self.name}{sub}@{self.version}" + (f"#{self.step}" if self.step else "")

    @property
    def sum(self):
        return _sumid(self.sums)

    @property
    def ident(self):
        return self.key + (f"#sum:{self.sum}" if self.sum else "")

    def __repr__(self):
        return self.key


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, errors="replace")  # a non-UTF-8 blob must never crash the readers
    if r.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


_BLOBS = {}  # blob id -> text: a history scan reads each distinct file version once, not once per commit


def _wanted(n):
    return not n.startswith("vendor/") and (any(fnmatch.fnmatchcase(n, g) for g in WORKFLOW_GLOBS) or n == "bin/install-scanner.sh" or n == PERSONA_TOOLS or re.search(r"(^|/)action\.ya?ml$", n)
            or (n.endswith(".sh") and not n.startswith(".github/agent/")) or n.rsplit("/", 1)[-1] in VERSION_FILES or re.search(r"(?i)(^|/)[\w.-]*(sha256|checksums?|sha256sums?)[\w.-]*(\.txt|\.sha256|\.sum)?$", n)
            or re.search(r"(^|/)[\w.-]*requirements[\w.-]*\.txt$", n))


def tree_key(root, rev):
    """The identity of what tree_files would read at a revision: the (path, blob) pairs of the files it reads, without reading them. Two revisions with the same key give the same inventory."""
    pairs = []
    for line in git(root, "ls-tree", "-r", "-z", rev).split("\0"):
        meta, _, n = line.partition("\t")
        if n and _wanted(n):
            pairs.append((n, meta.split()[2]))
    return tuple(pairs)


def tree_files(root, rev):
    """{path: text} for every file the inventory reads, at a revision (rev None: the working tree)."""
    wanted = _wanted
    out = {}
    if rev is None:
        for n in git(root, "-c", "core.quotePath=false", "ls-files", "-z").split("\0"):
            if n and wanted(n):
                try:
                    out[n] = open(f"{root}/{n}").read()
                except OSError as e:
                    if n == PERSONA_TOOLS:
                        raise RuntimeError(f"{n} is tracked but cannot be read ({e.strerror}): its images would go unchecked")
                    continue
                if len(out[n]) > MAX_FILE:
                    raise RuntimeError(f"{n} is too large to read safely")
        return out
    for line in git(root, "ls-tree", "-r", "-z", rev).split("\0"):
        meta, _, n = line.partition("\t")
        if not n or not wanted(n):
            continue
        blob = meta.split()[2]
        if blob not in _BLOBS:
            _BLOBS[blob] = git(root, "cat-file", "blob", blob)
        if len(_BLOBS[blob]) > MAX_FILE:
            raise RuntimeError(f"{n} is too large to read safely")
        out[n] = _BLOBS[blob]
    return out


def _strip_tag(name):
    """name:tag -> name (a colon after the last slash is a tag, a colon before it is a registry port)."""
    head, _, tail = name.rpartition("/")
    return (head + "/" if head else "") + tail.split(":")[0]


PERSONA_IMAGE = re.compile(r"(?:[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/)?(?:[a-z0-9._-]+/)*[a-z0-9._-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}")      # [registry[:port]/]path/name[:tag]@sha256:<digest>
PERSONA_TOOLS = "bin/persona-uat-tools.json"   # the images the persona UAT driver runs, by digest; no workflow names them, so the inventory reads the file itself (REQ-SUP-001-AC2)


def _persona_tool_items(path, text):
    """One image item per entry of the persona UAT tools file ({"<tool>": "<image>@sha256:<digest>", ...}). A file that is not JSON, not an object, or holds a value that is not a string is
    an error (exit 2 of the check): an image we cannot read is never skipped. A value without a digest is kept as a tag-only item, so the age check fails it."""
    def pairs(kv):
        d = {}
        for k, v in kv:
            if k in d:
                raise ValueError(f"the key {k!r} appears twice")
            d[k] = v
        return d
    try:
        d = json.loads(text, object_pairs_hook=pairs)
    except ValueError as e:
        raise RuntimeError(f"{path} is not JSON: {e}")
    if not isinstance(d, dict) or not d:
        raise RuntimeError(f"{path} is not a non-empty object of tool names and image references")
    out = []
    for k in sorted(d):
        if not k.strip() or not isinstance(d[k], str) or not d[k].strip():
            raise RuntimeError(f"{path}: the name {k!r} or its value is not an image reference string")
        if re.search(r"(?i)sha256", d[k]) and not PERSONA_IMAGE.fullmatch(d[k].strip()):
            raise RuntimeError(f"{path}: the value of {k!r} is not exactly <image>[:tag]@sha256:<64 lowercase hex>")
        it = _image_item(d[k], k)
        it.src = (path, hashlib.sha256(f"{k}={d[k]}".encode("utf-8", "replace")).hexdigest())
        out.append(it)
    return out


def _image_item(ref, label=""):
    ref = ref.strip()
    m = DIGEST.search(ref)
    if m:
        return Item("image", _strip_tag(ref[:m.start()].rstrip("@")), m.group(0), label)
    return Item("image", ref, "", label)  # tag only: kept so the age check can fail it


MAX_LINE = 4000


def _cap(text):
    """A command line longer than MAX_LINE is REFUSED, never read as its prefix (a dependency appended after the limit would otherwise go unseen)."""
    for l in text.split("\n"):
        if len(l) > MAX_LINE:
            raise RuntimeError(f"a command line of {len(l)} characters is longer than the {MAX_LINE} this check reads: refusing to read it partially")
    return text


def _ctx_tag(node):
    node = {k: v for k, v in node.items() if k != "uses"} if isinstance(node, dict) else node    # the action's own pin is measured separately: bumping it must not re-key its placeholders
    return "step:" + hashlib.sha256((json.dumps(node, sort_keys=True, default=str) + "\0" + _ENV_CTX[0]).encode("utf-8", "replace")).hexdigest()


_LOCAL_CALL = re.compile(r"\./\.github/workflows/(?!.*\.\.)[A-Za-z0-9._-]+\.yml")


def _exempt_local_call(raw, job):
    """REQ-SUP-001-AC19 (the closed form, orchestrator Oct 14): a job calling exactly ./.github/workflows/<plain name>.yml, a workflow of this tree with a
    workflow_call trigger and jobs, with NO with: block (absent or empty: no caller can hand it anything), is no item: the called file is inventoried itself.
    Any with: value, any other local form, a step, keeps the call an item that cannot pass."""
    if not _LOCAL_CALL.fullmatch(raw):
        return False
    _READS.append(_read_of(raw[2:]))      # what the answer below rests on besides the caller's own text: the file inventory() memoises on (cache#693)
    if raw[2:] not in _TREE[0] or job.get("with"):
        return False
    try:
        doc = yaml.load(_FILES[0].get(raw[2:], ""), Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        return False
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return False
    on = doc.get("on")
    return on == "workflow_call" or (isinstance(on, list) and "workflow_call" in on) or (isinstance(on, dict) and "workflow_call" in on)


def _local_name(raw):
    """A local reference's identity: its hidden spelling plus a digest of the RAW text, so two references that differ only where _hide() folds them (two expressions,
    padding) are two items and the row of one never rules the other (REQ-SUP-001-AC19)."""
    return "local:" + _hide(raw) + "~" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _uses(u, node, out, labels):
    raw = u
    u = u.strip()
    if u.startswith("docker://"):
        out.append(_image_item(u[len("docker://"):]))
    elif u.startswith("./"):
        it = Item("action", _local_name(raw), "(local)")
        keys = ("with",) if _LOCAL_CALL.match(u) else ("with", "env")        # a local action also gets the calling step's env; a local workflow call keeps its with: only (its job-level identity is set where its jobs are read)
        callctx = {k: node[k] for k in keys if isinstance(node.get(k), dict) and node[k]}
        if keys != ("with",) and _ENV_PRESENT[0]:      # no env and no matrix: no context, no change of key
            callctx["inherited"] = _ENV_CTX[0]      # the workflow's and job's env and the job's matrix: a composite reads them too
        if callctx:
            payload = callctx["with"] if list(callctx) == ["with"] else callctx      # with: alone hashes as it always has (a local workflow call's row identity)
            it.step = "with:" + hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()   # what a step hands a local action is part of the call: a changed value is a moved item
        out.append(it)   # the RAW spelling is the identity: a padded reference is never the exact one (REQ-SUP-001-AC19). A local action outside the globs: its content is not read, so a new one cannot pass
    elif u and "${{" not in u:
        ref_path, _, ref = u.partition("@")
        repo = "/".join(ref_path.split("/")[:2])
        out.append(Item("action", repo, ref, labels.get(f"{ref_path}@{ref}", ""), "/".join(ref_path.split("/")[2:])))
        w = node.get("with")
        known = {i for i, _ in INSTALLER_INPUTS.get(repo.lower(), [])}
        if isinstance(w, dict) and repo.lower() != "actions/setup-go":     # the Go toolchain is a product dependency (rule 1, amendment 2)
            for key, val in w.items():
                if (key not in known and isinstance(val, str) and val.strip() and val.strip().lower() not in ("true", "false", "0", "1")
                        and not key.startswith(("fetch-", "persist-")) and re.search(r"(^|[-_])(versions?|tags?|releases?|tools|images?)(-file)?$", key)):
                    it = Item("tool", f"{repo}:{key}", "(input)")       # an installer-shaped input nobody classified: a placeholder, so a new or changed one is refused
                    it.step = _ctx_tag(node)                           # identified by the whole step (its value included) and the env/matrix it reads
                    out.append(it)
        for inp, tool in INSTALLER_INPUTS.get(repo.lower(), []):
            if tool is not None and not (isinstance(w, dict) and isinstance(w.get(inp), str) and w[inp].strip()):
                it = Item("tool", tool, "(default)")       # no version given: the action installs whatever its default is, so removing the input must not remove the obligation
                it.step = "default:" + inp + ":" + hashlib.sha256(json.dumps({k: v for k, v in node.items() if k not in ("with", "uses")}, sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()
                out.append(it)
            if isinstance(w, dict) and isinstance(w.get(inp), str) and w[inp].strip():
                val = w[inp].strip()
                it = _image_item(val) if tool is None else Item("tool", tool, val)
                if _NONPIN.search(it.version or ""):
                    it.step = _ctx_tag(node)       # an expression (a matrix value, an env var): identified by the step AND the env/matrix it reads
                out.append(it)


_PIP_VALUE_OPTS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target",
                   "--prefix", "--root", "--cache-dir", "--python", "--platform", "--python-version", "--implementation", "--abi", "--only-binary", "--no-binary", "--progress-bar",
                   "--proxy", "--retries", "--timeout", "--trusted-host", "--src", "--upgrade-strategy", "--report", "--log", "--exists-action", "--cert", "--client-cert", "--root-user-action"}
def _docker_tails(run):
    return _tails(run, lambda t: t in ("docker", "podman", "nerdctl", "buildah"), {"run", "pull", "create"}, _DOCKER_VALUE_OPTS, keep_sub=True)
_DOCKER_VALUE_OPTS = {"--context", "-c", "--host", "-H", "--config", "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey", "--cpus", "--memory", "-m", "--cpu-shares", "--pids-limit", "--shm-size", "--ulimit", "--restart", "--log-driver", "--log-opt", "--group-add", "--security-opt", "--tmpfs", "--init-path", "--stop-signal", "--stop-timeout", "--ip", "--ip6", "--hostname", "--cidfile", "--cgroupns", "--ipc", "--pid", "--uts", "--userns", "--gpus", "--runtime", "--sysctl", "--annotation", "--volumes-from", "--link", "--expose", "--detach-keys", "--health-cmd", "--health-interval", "--pull","-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir", "-u", "--user", "--entrypoint",
                      "--platform", "-l", "--label", "--mount", "--env-file", "-h", "--hostname", "--add-host", "--cap-add", "--cap-drop", "--device", "--dns", "--pull", "--cpu-period", "--cpu-quota", "--cpuset-cpus", "--cpuset-mems", "--memory-swap", "--memory-reservation", "--stop-timeout", "--stop-signal", "--health-cmd", "--health-interval", "--health-retries", "--health-timeout", "--health-start-period", "--tmpfs", "--volumes-from", "--link", "--ip", "--network-alias", "--user", "-u", "-w", "--workdir", "--entrypoint", "--name", "-e", "--env", "-p", "--publish", "-v", "--volume", "--network", "--net", "--security-opt", "--sysctl", "--group-add", "--runtime", "--isolation", "--cgroup-parent", "--blkio-weight", "--annotation", "--cidfile", "--pid", "--ipc", "--uts", "--userns", "--expose", "--log-opt", "--mac-address", "--oom-score-adj", "--dns-search", "--dns-option", "--detach-keys", "--label-file", "--gpus"}


def _docker_images(cmd_args):
    return _docker_operand(cmd_args)[0]


_DOCKER_BOOL_OPTS = {"--rm", "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--init", "--privileged", "--read-only", "--no-healthcheck",
                     "--sig-proxy", "--oom-kill-disable", "-P", "--publish-all", "--help", "--quiet", "-q", "--disable-content-trust",
                     "--platform-none"}


def _docker_operand(cmd_args):
    """(the image of a docker run/pull/create, the effective --pull policy): the image is the first argument that is not an option or an option's
    value (quotes read as a shell would); the policy is the LAST --pull among the options before it (pflag keeps the final value), read by the SAME
    walk so the two can never disagree about which words are options, values or the operand (Codex #187 rounds 2-3). The `never` policy only
    counts when EVERY option before the operand has a known arity (a value option, a boolean, a short cluster of booleans, or --name=value of a
    known option): a guessed arity (a number after an unknown option is taken as its value) once let `--rm 123 --pull=never localhost/x` read the
    container's own arguments as a policy (round 4), so an unknown option withholds the exemption."""
    try:
        toks = shlex.split(cmd_args)
    except ValueError:
        toks = cmd_args.split()
    i, pull, guessed = 0, None, False
    while i < len(toks):
        t = toks[i]
        if t.startswith("--pull="):
            pull = t.split("=", 1)[1]; i += 1; continue
        if t == "--pull" and i + 1 < len(toks):
            pull = toks[i + 1]; i += 2; continue
        if t.startswith("-"):
            known_value = t in _DOCKER_VALUE_OPTS and "=" not in t
            known = known_value or t in _DOCKER_BOOL_OPTS or (t.startswith("--") and t.split("=", 1)[0] in _DOCKER_VALUE_OPTS and "=" in t) \
                or re.fullmatch(r"-[dit]+", t) is not None
            guess = not known and i + 1 < len(toks) and re.fullmatch(r"[\d.]+[kmgb]?", toks[i + 1]) is not None and "=" not in t and t.startswith("--")
            guessed = guessed or not known
            i += 2 if (known_value or guess) else 1
            continue
        if "$" in t:
            return ["(variable)"], (None if guessed else pull)                # the image is a shell variable: a placeholder item that cannot be proven, so a new one is refused
        return ([t] if re.fullmatch(r"[\w.\-/:]+(@sha256:[0-9a-f]{64})?", t) else []), (None if guessed else pull)
    return [], (None if guessed else pull)


def _asset_word(text, start):
    """The release asset's name as the shell reads it, from `start` to the end of the word. Quotes, $( ) and backticks nest as a stack (a quote opened inside a
    substitution closes there, whatever the depth); an unquoted space or shell operator, and a ? or # (a query or a fragment: URL syntax, quoted or not) end the
    name; the quote that held the whole URL closing does not end it ("url/tool-"${A}.tgz is one word). A name with a substitution in it is returned whole; the
    caller keeps the plain match for a concrete name."""
    i, n, depth, stack = text.rfind("\n", 0, start) + 1, len(text), 0, []    # stack of (quote char, substitution depth it was opened at); quote state is read from the line start
    bt = []                                                                    # depths at which a backtick substitution is open
    d0 = s0 = -1                                                              # the depth and quote depth the name itself starts at: its word ends there
    while i < n:
        c = text[i]
        if i == start:
            d0, s0 = depth, len(stack)
        in_string = bool(stack) and (stack[-1][0] == "'" or depth == stack[-1][1])
        if i >= start and depth == d0 and c in "?#":
            break
        if i >= start and c == ")" and depth == d0 and d0 > 0 and len(stack) <= s0 and not in_string:
            break                            # the substitution that holds the name closes: the name is over
        if i >= start and c == "`" and bt and bt[-1] == d0 and d0 > 0 and len(stack) == s0 and not (stack and stack[-1][0] == "'"):
            break                            # the backticks that hold the name close
        if stack and stack[-1][0] == "'":
            if c == "'":
                stack.pop()
            elif i >= start and depth == d0 and len(stack) == s0 and stack[-1][2] < start and (c.isspace() or c in ";|&<>" or (c == ")" and d0 > 0)):
                break                          # a single-quoted program string (bash -c 'curl url/x.tgz -o x'): the name ends at its own word boundary
        elif in_string:                      # inside double quotes, not inside a substitution
            if i >= start and depth == d0 and len(stack) == s0 and stack and stack[-1][1] == d0 and stack[-1][2] < start and c.isspace():
                break                        # a double-quoted program string: the name ends at whitespace
            if c == "\\" and i + 1 < n:
                i += 1
            elif c == '"':
                stack.pop()
            elif c == "$" and text[i + 1:i + 2] == "(":
                depth += 1
                i += 1
            elif c == "`":
                bt.append(depth + 1); depth += 1
        else:                                # code: unquoted, or inside $( ) within quotes
            if c == "\\" and i + 1 < n:
                i += 1
            elif c == "`":
                if bt and depth == bt[-1]:
                    bt.pop(); depth -= 1
                else:
                    bt.append(depth + 1); depth += 1
            elif c == "$" and text[i + 1:i + 2] == "(":
                depth += 1
                i += 1
            elif c == ")" and depth > 0:
                depth -= 1
            elif c in "'\"":
                stack.append((c, depth, i))
            elif i >= start and depth == d0 and len(stack) <= s0 and (c.isspace() or c in ";|&<>)"):
                break
        i += 1
    return text[start:i]


def _nested_program(text, pos):
    """True when `pos` sits inside a quoted PROGRAM string (bash -c '...', sh -c "...", eval "...") whose outermost quote also holds a $, a backtick or a
    command separator (; && || |): the inner program's own word boundaries are not read here, so a release URL in it is refused as unresolved (closed
    fail-closed, advisor 0080: parse the inner program or refuse it; this refuses it). A position inside a $( ) or backtick substitution is NOT this case:
    the name reader parses code there. A quoted string with nothing dynamic in it is an ordinary quoted word."""
    i = text.rfind("\n", 0, pos) + 1
    stack, bt = [], False                  # open contexts, innermost last: "'", '"', "$("; and whether backticks are open
    while i < pos:
        c = text[i]
        top = stack[-1] if stack else None
        if top == "'":
            if c == "'":
                stack.pop()
        elif c == "\\":
            i += 2; continue
        elif c == "`":
            bt = not bt
        elif c == "$" and text[i + 1:i + 2] == "(":
            stack.append("$("); i += 1
        elif c == ")" and top == "$(":
            stack.pop()
        elif c == '"' and top == '"':
            stack.pop()
        elif c in "'\"" and top != "'":
            stack.append(c)
        i += 1
    if bt or "$(" in stack or not stack or stack[0] not in "'\"":
        return False
    q = stack[0]
    start = pos
    # the outermost quote's span: from its opening (rescan) to its closing after pos
    k, st = text.rfind("\n", 0, pos) + 1, []
    while k < pos:
        c = text[k]
        top = st[-1] if st else None
        if top == "'":
            if c == "'": st.pop()
        elif c == "\\": k += 2; continue
        elif c == "$" and text[k + 1:k + 2] == "(": st.append("$("); k += 1
        elif c == ")" and top == "$(": st.pop()
        elif c == '"' and top == '"': st.pop()
        elif c in "'\"" and top != "'":
            st.append(c)
            if len(st) == 1: start = k
        k += 1
    j, n = pos, len(text)
    while j < n:
        if text[j] == "\\" and q == '"':
            j += 2; continue
        if text[j] == q:
            break
        j += 1
    return bool(re.search(r"[$`;|]|&&", text[start + 1:j]))


_ENV_CTX = [""]
_ENV_PRESENT = [False]    # the workflow or the job sets an env or a matrix: only then does a local action call inherit context
_JOB_RUNS = [[]]          # the run texts of the steps of the job being read (a step can hand a name to a later one through GITHUB_ENV)
_INPUT_CTX = [""]   # a composite action's input definitions: part of a release asset's identity only (never of another item's key)
_TREE = [frozenset()]   # the paths of the tree being inventoried that are read as workflows: a local reusable-workflow call is judged against it (REQ-SUP-001-AC19)
_FILES = [{}]           # and their text
_JOB_SUMS = [[]]


_NONPIN = re.compile(r"^$|^\(|\$\{|^latest$|^(main|master|nightly|stable)$|[*<>=~!]")


_CONT = re.compile(r"(\\\n\s*)")
_ASSIGN_LINE = re.compile(r"^[ \t]*(?:export\s+|readonly\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def _script_lines(text):
    """(joined, raw) per logical line of a script: joined is the line with each backslash continuation folded to one space (what the readers match on),
    raw keeps the continuation exactly as written, so a change of spacing inside a continued value is a change."""
    parts = _CONT.split(text)
    joined, raw, cj, cr = [], [], "", ""
    for i, part in enumerate(parts):
        if i % 2:
            cj += " "; cr += part
            continue
        segs = part.split("\n")
        for j, seg in enumerate(segs):
            cj += seg; cr += seg
            if j < len(segs) - 1:
                joined.append(cj); raw.append(cr); cj = cr = ""
    joined.append(cj); raw.append(cr)
    return joined, raw


_ASSIGN_ANY = re.compile(r"(?:^|[\s;&|(])[\"']?([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\+?=")   # export "A=$B" and declare -x 'A=x' name A too


def _assign_context(joined, raw):
    """For each logical line (a generator: only a line that names a release download is worked out): every assignment, in file order and as written, to the
    variables the line reads, and (transitively) to the variables those assignments read. An assignment is any NAME= at the start of a word (A=x B=old,
    export A=x, declare -r A=), so a later one, an indirect one (A=$B) and spacing inside a continued value are all part of a download's identity."""
    byname, order = {}, 0
    for jl, rl in zip(joined, raw):
        names = set(m.group(1) for m in _ASSIGN_ANY.finditer(jl))
        if "=" in jl or re.search(r"\b(?:printf\s+-v|read|mapfile|readarray|declare|typeset|local|export|readonly|eval|let|unset|getopts|set)\b", jl):
            names |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", jl))     # printf -v A, read A, eval "A=...": any word of such a line may be a name it writes
        for name in names:
            byname.setdefault(name, []).append((order, jl, rl))
        order += 1
    def refs(t):
        names = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", t))
        for body in re.findall(r"\$\{([^}]*)\}", t):
            names |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))     # ${!SEL}, ${A[IDX]}, ${A:-$B}: every name inside the braces is read
        if "((" in t:
            names |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", t))     # a bare name inside $(( )) or (( )) is read: take every identifier of the line
        return names
    for jl in joined:
        if "releases/" not in jl:
            yield []
            continue
        indirect = "${!" in jl
        seen, todo, rows = set(), sorted(refs(jl)), []
        while todo:
            v = todo.pop()
            if v in seen or v not in byname:
                seen.add(v)
                continue
            seen.add(v)
            for ix, j2, r2 in byname[v]:
                rows.append((ix, r2))
                more = refs(j2)
                if indirect:
                    more |= set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", j2.split("=", 1)[-1]))    # ${!P}: the VALUE of P names the variable that is read
                todo.extend(sorted(more - seen))
        yield [r for _, r in sorted(set(rows))]      # file order: B=x, A=$B, B=y is not B=y, A=$B, B=x


MAX_ITEMS_PER_STEP = 500
MAX_ITEMS_PER_FILE = 5000
MAX_LINES_PER_FILE = 20000


def _step(node, out, labels):
    n0 = len(out)
    _step_items(node, out, labels)
    if len(out) - n0 > MAX_ITEMS_PER_STEP:
        raise RuntimeError(f"a single step or script line yields more than {MAX_ITEMS_PER_STEP} items: refusing to read it (a hostile line could exhaust the readers)")
    run = node.get("run")
    if isinstance(run, str):
        legacy = " ".join(run.split()) + "\0" + json.dumps(node.get("env"), sort_keys=True, default=str) + "\0" + _ENV_CTX[0]
        legacy_tag = "step:" + hashlib.sha256(legacy.encode("utf-8", "replace")).hexdigest()       # the identity every other placeholder item has always had: its key must not move
        sib = []
        if _JOB_RUNS[0] and any(("$" in (it.path or "") or "`" in (it.path or "")) or it.rawid for it in out[n0:]):
            read = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", run)) | set(w for b in re.findall(r"\$\{([^}]*)\}", run) for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", b))
            for other in _JOB_RUNS[0]:
                if other == run:
                    continue
                for ln in other.split("\n"):
                    if read & set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", ln)):
                        sib.append(ln)      # an earlier step's line that mentions a name this step reads (echo ASSET=$B >> "$GITHUB_ENV")
        ctx = node.get("_raw", run) + "\0" + json.dumps(node.get("env"), sort_keys=True, default=str) + "\0" + _ENV_CTX[0] + "\0" + json.dumps(node.get("_assign")) + "\0" + _INPUT_CTX[0] + "\0" + json.dumps(sorted(set(sib)))   # a release asset's NAME behind a variable: the RAW step text and every assignment it can read
        k = 0
        for it in out[n0:]:
            if (("$" in (it.path or "") or "`" in (it.path or "")) or it.rawid) and not it.step:
                k += 1
                it.step = "step:" + hashlib.sha256((ctx + "\0" + str(k)).encode("utf-8", "replace")).hexdigest()   # the ordinal keeps two placeholders of one step apart
            elif _NONPIN.search(it.version or "") and not it.step:
                it.step = legacy_tag # a placeholder (variable, @latest, @main, unpinned; a release asset's NAME that holds a variable or expression) is identified by the step it sits in, so a NEW or EDITED one is a new key and is refused: _hide() folds two spellings of the name into one


_SOURCE_ASSIGN = re.compile(r"^[ \t]*(?:export\s+|readonly\s+|local\s+)?((?:url|URL)|[A-Z][A-Z0-9_]*_(?:BASE_URL|BASE|URL))=(.*)$")


def _step_items(node, out, labels):
    """A step (or a job-level reusable-workflow call): `uses` and `run` mean something only here; the same word in `env:` or `with:` is data."""
    if isinstance(node.get("uses"), str):
        _uses(node["uses"], node, out, labels)
    run = node.get("run")
    if isinstance(run, str):
        run = _cap(_hide(re.sub(r"\\\n\s*", " ", run)))  # a backslash continuation is one command; an expression becomes a placeholder before any pattern can cut it
        for m in list(_GO_INSTALL.finditer(run)) + list(_GO_RUN_GET.finditer(run)):
            for t in _GO_TARGET.finditer(m.group(1)):
                out.append(Item("gotool", t.group(1), t.group(2)))
            for tok in m.group(1).split():
                tok = tok.strip("'\"")
                if not tok.startswith("-") and "@" not in tok and re.fullmatch(r"[\w.\-]+\.[\w.\-]+/[\w.\-/]+", tok):
                    out.append(Item("gotool", tok, "(unversioned)"))     # go install with no @version: a placeholder, refused when added
                elif not tok.startswith("-") and "$" in tok:
                    out.append(Item("gotool", "(variable)", "(unversioned)"))   # go install "$TOOL": the target is a variable, so it cannot be proven
        for m in _GH_LATEST.finditer(run):  # "latest" is not a pin: an item that cannot be proven, so adding one fails closed
            it = Item("tool", m.group(1), "latest")
            it.rawid = True      # a "latest" download is an item that cannot be proven: its step's raw text, an expression's literals included, is its identity
            out.append(it)
        for sub, tail in _docker_tails(run):
            images, pull = _docker_operand(tail)
            local_only = sub in ("run", "create") and pull == "never"
            for img in images:
                it = _image_item(img)
                if local_only and it.name.startswith("localhost/"):
                    continue      # run/create with --pull=never can only use an image already in the daemon: built or loaded by this job, never downloaded, no age to prove (advisor 0203); a pull, a container:/services: image, uses: docker:// and localhost:PORT/ stay items
                out.append(it)
        for ln in run.split("\n"):    # where a script downloads FROM: an assignment of a URL/BASE variable is a source line identified by its own text
            m = _SOURCE_ASSIGN.match(ln)
            if m:
                out.append(Item("tool", "source:" + m.group(1).lower() + "=" + hashlib.sha256(" ".join(ln.split()).encode("utf-8", "replace")).hexdigest(), "(source)"))
        for m in _GH_DOWNLOAD.finditer(run):  # curl/wget of a release asset: the tool is its repo at that version; the EXACT tag is kept as its label
            sums = sorted(set(re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", run)) | set(_JOB_SUMS[0]))   # checksums, not image digests
            word = _asset_word(run, m.start(4))
            asset = word if ("$" in word or "`" in word) else m.group(4)
            if "$" not in asset and "`" not in asset and _nested_program(run, m.start(4)):
                asset += "$(nested program)"      # a URL in a quoted program string that is dynamic: unresolved, refused (the inner shell's boundaries are not parsed)   # the name goes on past a quote or a space inside $( ): it is a name behind a variable too
            out.append(Item("tool", m.group(1), m.group(2) + m.group(3), m.group(2) + m.group(3), asset + ("#" + hashlib.sha256(" ".join(sums).encode()).hexdigest() if sums else "")))   # the asset's name is part of the identity: a different file under the same tag is a moved item
        for tail in _pip_tails(run):
            for p in _PIP_PIN.finditer(tail):  # a range (>=, ~=...) is not a pin: kept with its operator, it cannot be proven and fails closed
                ver = p.group(3) if p.group(2) == "==" else p.group(2) + p.group(3)
                out.append(Item("package", f"pypi/{p.group(1).lower().replace('_', '-')}", ver))
        for tail in _pip_tails(run):
            prev = ""
            for tok in tail.split():
                value_of_option = prev in _PIP_VALUE_OPTS      # `-r deps.txt` names a file, not a package
                prev = tok
                if value_of_option:
                    continue
                tok = tok.strip("'\"")
                if "$" in tok and not tok.startswith("-"):
                    out.append(Item("package", "pypi/(variable)", "(unpinned)"))     # pip install $DEPS: a variable list, a placeholder
                    continue
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*(\[[\w,.-]*\])?", tok) and not tok.startswith("-"):
                    out.append(Item("package", f"pypi/{tok.split('[')[0].lower().replace('_', '-')}", "(unpinned)"))  # no version at all: it cannot be proven, so adding one fails closed
        if re.search(r"\bpip[0-9.]*\b", run) and "--require-hashes" in run:  # a requirements list fed on stdin (a heredoc): its `name==version \\` lines
            rsums = _req_sums(run)
            for p in _REQ_PIN.finditer(run):
                out.append(Item("package", f"pypi/{p.group(1).lower().replace('_', '-')}", p.group(2)))
                out[-1].sums = rsums.get((p.group(1).lower().replace("_", "-"), p.group(2)), [])


def _walk(node, out, labels, path="", in_step=False):
    if isinstance(node, str):
        if True:
            for m in _RUN_IMAGE.finditer(node):  # a digest-pinned image in ANY value: run text, env, driver-opts, an action input
                out.append(_image_item(m.group(1)))
    elif isinstance(node, dict):
        if in_step or path.startswith("job:"):
            _step(node, out, labels)
        for k, v in node.items():
            if k == "env" and isinstance(v, dict):
                for ek, ev in v.items():
                    if re.fullmatch(r"[A-Z][A-Z0-9_]*_(?:BASE_URL|BASE|URL)", str(ek)):
                        out.append(Item("tool", "source:env:" + ("(expression)" if "${{" in str(ev) else str(ek).lower()) + "=" + hashlib.sha256(str(ev).encode("utf-8", "replace")).hexdigest(), "(source)"))   # an env var that retargets a download
            if k in ("container", "image") and isinstance(v, (str, dict)):
                img = v if isinstance(v, str) else v.get("image")
                # an `image:` input of an action counts only when it names a digest (other inputs called image are not pins)
                if isinstance(img, str) and "${{" in img and k == "container":
                    it = Item("image", "(expression)", ""); it.step = _ctx_tag(v); out.append(it)    # a container image given by an expression: a placeholder
                elif isinstance(img, str) and "${{" not in img and (path != "with" or k == "container" or DIGEST.search(img)):
                    out.append(_image_item(img))
            if k == "services" and isinstance(v, dict):
                for svc in v.values():
                    if isinstance(svc, dict) and isinstance(svc.get("image"), str):
                        if "${{" in svc["image"]:
                            it = Item("image", "(expression)", ""); it.step = _ctx_tag(svc); out.append(it)
                        else:
                            out.append(_image_item(svc["image"]))
            if k == "jobs" and isinstance(v, dict):
                # the triggers count (rule 1), except the paths filters
                top_env = (json.dumps(node.get("env"), sort_keys=True, default=str)
                           + json.dumps(_on_key(node.get("on")), sort_keys=True, default=str))
                try:
                    for job in v.values():
                        _ENV_CTX[0] = top_env + json.dumps(job.get("env") if isinstance(job, dict) else None, sort_keys=True, default=str) + json.dumps(job.get("strategy") if isinstance(job, dict) else None, sort_keys=True, default=str)
                        _ENV_PRESENT[0] = bool(node.get("env")) or (isinstance(job, dict) and bool(job.get("env") or job.get("strategy")))
                        _JOB_RUNS[0] = [st.get("run") for st in (job.get("steps") if isinstance(job, dict) and isinstance(job.get("steps"), list) else []) if isinstance(st, dict) and isinstance(st.get("run"), str)]
                        _JOB_SUMS[0] = re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", json.dumps(job, default=str)) if isinstance(job, dict) else []   # a checksum in ANY step of the job (a separate verify step) belongs to the job's downloads
                        n0 = len(out)
                        _walk(job, out, labels, "job:" + k)
                        if isinstance(job, dict) and isinstance(job.get("uses"), str) and job["uses"].strip().startswith("./"):
                            mine = [it for it in out[n0:] if it.version == "(local)" and it.name == _local_name(job["uses"]) and not it.step]
                            if mine and _exempt_local_call(job["uses"], job):
                                for it in mine:
                                    out.remove(it)       # REQ-SUP-001-AC19: the called file is inventoried itself
                            elif job.get("with"):
                                for it in mine:          # a local reusable-workflow call: what it passes in is part of that call's identity
                                    it.step = "with:" + hashlib.sha256(json.dumps(job.get("with"), sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()
                finally:      # a raise inside a job leaves the next file no job context (cache#693)
                    _ENV_CTX[0] = ""
                    _ENV_PRESENT[0] = False
                    _JOB_RUNS[0] = []
                    _JOB_SUMS[0] = []
                continue
            _walk(v, out, labels, k, in_step=(k == "steps"))
    elif isinstance(node, list):
        for v in node:
            _walk(v, out, labels, path, in_step=in_step)


_MEMO_ON = [True]
_FILE_MEMO = {}     # (path, sha256 of the text) -> (the items _file_found made, the reads they rest on)
_READS = []         # the other files the walk of the current file looked at: (name, is it a workflow of the tree, sha256 of its text), as _exempt_local_call saw them


def _read_of(name):
    text = _FILES[0].get(name)
    return (name, name in _TREE[0], hashlib.sha256(text.encode("utf-8", "replace")).hexdigest() if text is not None else "")


def _sumid(sums):
    return hashlib.sha256(" ".join(sorted(set(sums))).encode()).hexdigest()[:24] if sums else ""


_CASE_SUM = re.compile(r"^[ \t]*([\w.\-]+):[^)\n]*\)[ \t]*SUM=['\"]?([0-9a-fA-F]{64})['\"]?", re.M)


def _scanner_sums(text, name, version):
    """The sha256 values install-scanner.sh pins for a tool: the `<tool>:<arch>) SUM=<hex>` rows whose tool label is the item's name (docker-scout for scout, osv-scanner for osv ...).
    A label that carries a version (docker-scout-1.25.0) belongs to that version only; a label without one belongs to the item the *_VER variable names."""
    exact, plain = [], []
    for lab, hx in _CASE_SUM.findall(text):
        lab = lab.lower()
        m = re.fullmatch(r"(.+?)-(\d+(?:\.\d+)+)", lab)
        if m and (m.group(1) == name or m.group(1).endswith("-" + name)):
            if m.group(2) == version:
                exact.append(hx.lower())
        elif lab == name or lab.endswith("-" + name) or lab.startswith(name + "-"):
            plain.append(hx.lower())
    return exact or plain


def _arm_of(text, rawln):
    """The tool label of the installer arm (`  <tool>)`) a script line sits in, or None.
    The LAST marker before the line decides: any `  <label>)` (a label with `|` or `*` included), a `  ;;` or an `esac` line. Only a plain single-label arm is an arm; a multi-label arm,
    a glob arm, or a line after a terminator is in no single tool's arm (None: the whole-script identity applies, so no foreign sums attach)."""
    at = text.find(rawln) if rawln else -1
    if at < 0 or text.count(rawln) > 1:      # a line that occurs twice cannot be placed by its text: no arm (the whole-script identity applies)
        return None
    marks = re.findall(r"^(?:  ([^\s;()#][^()\n]*)\)[ \t]*(?:#.*)?|(  ;;.*|esac\b.*))$", text[:at], re.M)
    if not marks or marks[-1][1]:
        return None
    return marks[-1][0] if re.fullmatch(r"[\w.\-]+", marks[-1][0]) else None


_REQ_HASH = re.compile(r"--hash=([A-Za-z0-9]+:[0-9A-Fa-f]+)")


def _req_sums(text):
    """{(name, version): [hash, ...]} of the requirement lines (continuations joined) that carry --hash options."""
    out = {}
    for ln in re.sub(r"\\\n\s*", " ", text).split("\n"):
        m = _REQ_PIN.match(ln)
        if m:
            out.setdefault((m.group(1).lower().replace("_", "-"), m.group(2)), []).extend(h.lower() for h in _REQ_HASH.findall(ln))
    return out


def _file_found(path, text):
    """The items one file yields (before the tree-wide de-duplication of inventory()). A function of the path and the text, and of the local
    workflows the walk reads (_exempt_local_call records them in _READS): inventory() memoises it on exactly that."""
    _ENV_CTX[0], _ENV_PRESENT[0], _JOB_RUNS[0], _JOB_SUMS[0], _INPUT_CTX[0] = "", False, [], [], ""      # every file starts from the neutral context, whatever raised before it
    _READS.clear()
    found = []
    if path == "bin/install-scanner.sh":
        found = [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in _VER_PIN.finditer(text) if m.group(1) != "PATH"]
        found += [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Z][A-Z0-9]*)_VERSION=['\"]?([^\s'\"#]+)", text, re.M)]
        found += [Item("tool", "source:" + m.group(1).lower() + "=" + _hide(m.group(2)), "(source)") for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Z][A-Z0-9_]*_BASE(?:_URL)?)=['\"]?(?:\$\{[A-Z0-9_]+:?-)?(https?://[^\s'\"}]+)", text, re.M)]  # where it downloads from: changing it is refused (not a pin)
        found += [Item("tool", "scout", m.group(1)) for m in re.finditer(r"\bdocker-scout-(\d+(?:\.\d+)+)\b", text)]  # older versions the script can still install
        for it in found:
            if it.kind == "tool" and not it.name.startswith("source:"):
                it.sums = _scanner_sums(text, it.name, it.version)
        sjoined, sraw = _script_lines(text)
        sctx = _assign_context(sjoined, sraw)
        for ln, lid, actx, rawln in zip(sjoined, _line_ids(text), sctx, sraw):   # and the rest of the script like any other: an appended download is seen, and a placeholder's identity holds the assignments it can read
            before = len(found)
            _step({"run": ln, "_assign": actx, "_raw": rawln} if actx else {"run": ln, "_raw": rawln}, found, {})
            for it in found[before:]:
                it.src = (path, lid)
                if it.kind == "tool" and not it.sums and not it.name.startswith("source:"):
                    arm = _arm_of(text, rawln)
                    if arm:
                        it.sums = _scanner_sums(text, arm, "")      # a literal release download inside the installer's `<tool>)` arm carries that tool's pinned sums
                    if not it.sums and it.path and _CASE_SUM.search(text):      # a sum-pinned installer: a download with none found is not trusted
                        it.step = "file:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()      # no sums found for a literal download (an arm label the text scan could not trust): fail closed, any edit of the script moves the item
    elif path == PERSONA_TOOLS:
        found = _persona_tool_items(path, text)
    elif path.rsplit("/", 1)[-1] in VERSION_FILES or (re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1]) and not path.startswith(".github/workflows/") and not path.endswith((".sh", ".yml", ".yaml", ".py"))):
        found = [Item("tool", "file:" + path, "(file)")]
        found[0].raw = path   # a version file or a checksum file: its content is the identity (a replaced asset behind the same URL moves the item)
        found[0].step = "content:" + hashlib.sha256((path + "\0" + text).encode("utf-8", "replace")).hexdigest()      # what an installer's *-version-file selects: a changed content is a changed key
    elif path.endswith(".sh"):
        found = []
        joined = re.sub(r"\\\n\s*", " ", text).split("\n")
        if len(joined) > MAX_LINES_PER_FILE:
            raise RuntimeError(f"{path} has {len(joined)} lines: more than the {MAX_LINES_PER_FILE} this check reads")
        assigns = {}
        for ln in joined:
            am = re.match(r"^[ \t]*(?:export\s+|readonly\s+|local\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", ln)
            if am:
                assigns[am.group(1)] = am.group(2)
        _j2, _raw2 = _script_lines(text)
        gctx = _assign_context(_j2, _raw2) if len(_j2) == len(joined) else [[ln for ln in joined]] * len(joined)   # a line count that differs is read whole: fail closed
        graw = _raw2 if len(_raw2) == len(joined) else joined
        for ln, lid, actx, rawln in zip(joined, _line_ids(text), gctx, graw):   # a script is read LINE by line (continuations joined): a placeholder's identity is its own line PLUS the assignments of the variables that line references
            refs = {v: assigns[v] for v in set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", ln)) if v in assigns}
            before = len(found)
            node = {"run": ln, "env": refs} if refs else {"run": ln}
            node["_raw"] = rawln
            if actx:
                node["_assign"] = actx
            _step(node, found, {})
            for it in found[before:]:
                it.src = (path, lid)
            if len(found) > MAX_ITEMS_PER_FILE:
                raise RuntimeError(f"{path} yields more than {MAX_ITEMS_PER_FILE} items: refusing to read it")   # a script's go install / pip install / docker run / release download are measured like a run step's
    elif path.endswith("requirements.txt") or re.search(r"requirements[\w.-]*\.txt$", path):
        found = [Item("package", f"pypi/{m.group(1).lower().replace('_', '-')}", m.group(2)) for m in _REQ_PIN.finditer(text)]
        rsums = _req_sums(text)
        for it in found:
            it.sums = rsums.get((it.name[5:], it.version), [])
        for ln in re.sub(r"\\\n\s*", " ", text).split("\n"):
            body = ln.split("#", 1)[0].strip()
            if not body or body.startswith("--hash="):
                continue
            if _REQ_PIN.match(body):
                continue                      # name==version (with its --hash options)
            found.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(body.encode("utf-8", "replace")).hexdigest() + ")", "(unpinned)"))   # a URL requirement, a range, an index option, a bare name
    else:
        labels = {}
        for m in re.finditer(r"uses:\s*([^\s#'\"]+)\s*#\s*(\S+)", text):
            labels[m.group(1)] = m.group(2)
        try:
            nodes = 0
            for ev in yaml.parse(text, Loader=yaml.BaseLoader):  # events, not expanded nodes: an alias bomb is refused before anything is built
                if isinstance(ev, yaml.AliasEvent):
                    raise RuntimeError(f"{path} uses a YAML alias or anchor, which this check refuses (it cannot be read safely)")
                nodes += 1
                if nodes > 200000:
                    raise RuntimeError(f"{path} is too large to read safely")
            doc = yaml.load(text, Loader=yaml.BaseLoader)
        except yaml.YAMLError as e:
            mark = getattr(e, "problem_mark", None)  # the line number only: the message would quote source text (names that must stay private)
            raise RuntimeError(f"{path} does not parse (line {mark.line + 1 if mark else '?'})")
        if isinstance(doc, dict) and isinstance(doc.get("runs"), dict):
            _INPUT_CTX[0] = json.dumps(doc.get("inputs"), sort_keys=True, default=str)   # a composite action's input defaults select what its steps download
        try:
            _walk(doc, found, labels, "")
        finally:
            _INPUT_CTX[0] = ""
        for it in found:
            if it.src is None:
                it.src = (path, "")      # a workflow item's origin is its file (REQ-SUP-001-AC19: a local call is ruled by its identity)
    nfile = 0
    for it in found:
        if ("$" in (it.path or "") or "`" in (it.path or "")) or it.rawid:
            # a release asset whose NAME is not literal (a variable, a substitution, a "latest" download) cannot be proven, so any change that could select a
            # different asset must be a moved item: its identity is the WHOLE file it sits in and its ordinal there. Closed fail-closed (advisor 0080: an
            # open-ended class of shell forms on a security control is refused, not enumerated): no assignment, array, indirection, GITHUB_ENV or quoting
            # form needs to be recognised for an edit to be seen.
            nfile += 1
            it.step = "step:" + hashlib.sha256((path + "\0" + text + "\0" + str(nfile)).encode("utf-8", "replace")).hexdigest()
    return found


def inventory(files):
    """The items of one tree's files ({path: text}). Raises on a workflow that does not parse: a pin we cannot read is never skipped."""
    items = {}
    _TREE[0] = frozenset(n for n in files if any(fnmatch.fnmatchcase(n, g) for g in WORKFLOW_GLOBS))
    _FILES[0] = files
    for path, text in sorted(files.items()):
        mk = (path, hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()) if _MEMO_ON[0] else None
        hit = _FILE_MEMO.get(mk) if mk is not None else None
        if hit is not None and all(_read_of(r[0]) == r for r in hit[1]):      # the reads the walk made are re-asked of THIS tree: the same answers, the same items
            found = [copy.copy(it) for it in hit[0]]      # the de-duplication below renames steps: it must never touch the remembered items
        else:
            found = _file_found(path, text)
            if mk is not None:                              # a raise left nothing here: only a completed file is remembered
                _FILE_MEMO[mk] = ([copy.copy(it) for it in found], tuple(_READS))
        for it in found:
            if it.key in items and (it.version.startswith("(") or "${{" in it.version or it.version in ("latest", "(unversioned)") or "$" in (it.path or "") or "`" in (it.path or "")):     # two identical unresolved occurrences are two items: removing a version from the second must not hide behind the first
                n = 2
                while True:
                    it.step = re.sub(r"~\d+$", "", it.step or "") + f"~{n}"
                    if it.key not in items:
                        break
                    n += 1
            if it.key in items:
                items[it.key].sums = items[it.key].sums + it.sums     # every occurrence's checksums count: a change in a second file is not hidden by the first
            else:
                items[it.key] = it
    return items


def moved(base_items, head_items):
    """Items in the head that the base did not have: a new pin, or a changed version, counts as moved."""
    return [head_items[k] for k in sorted(head_items) if k not in base_items or base_items[k].sum != head_items[k].sum]   # the pinned checksum is part of the identity: the same version with a new sum is a moved item


def _on_key(on):
    """What of a workflow's `on:` is part of a step's identity: all of it except the `paths` and `paths-ignore`
    filters under each event.
    Owner rule 1 (Oct 5): no NEW version of what a workflow downloads until it has been public 7 days. A trigger
    can change what a step downloads (the event name, the ref, a schedule and the event payload all reach steps;
    a called workflow's inputs and outputs select what is fetched), so triggers stay in the key. A changed set of
    changed-file paths only chooses WHETHER a run happens, never what it fetches. A scalar or list `on`
    (`on: push`, `[push, merge_group]`) is unchanged."""
    if not isinstance(on, dict):
        return on
    out = {}
    for ev, body in on.items():
        if isinstance(body, dict):
            # the loader reads a bare event as "": an event with only a paths filter is the bare event
            body = {k: v for k, v in body.items() if k not in ("paths", "paths-ignore")} or ""
        out[str(ev)] = body
    return out


def load_at(root, rev):
    return inventory(tree_files(root, rev))


def main():
    root, rev = (sys.argv[1] if len(sys.argv) > 1 else "."), (sys.argv[2] if len(sys.argv) > 2 else None)
    print(json.dumps(sorted(load_at(root, rev)), indent=1))



_UNMEASURED = [
    (re.compile(r"\b(?:npm|pnpm|yarn|bun|deno)\b[^\n;&|]*?\s(?:install|add|i|exec|x|dlx)(?=\s|$)|\b(?:npx|bunx)\b|\bcargo\s+(?:install|binstall)\b|\bgem\s+install\b|\bpipx\s+(?:install|run)\b|\buvx?\s+\S|\bbrew\s+(?:install|reinstall|upgrade)\b|\bconda\s+(?:install|create)\b|\bmamba\s+install\b|\bbundle\s+(?:install|add)\b|\bdotnet\s+(?:tool\s+install|add\s+package|restore)\b|\bgo\s+(?:get|run)\b[^\n]*\$"), "a package-manager install"),
    (re.compile(r"\b(?:apt|apt-get|dnf|yum|microdnf|zypper|apk|snap|pacman|choco|winget)\s+(?:-\S+\s+)*(?:install|add|reinstall|upgrade)\b"), "a system package install"),
    (re.compile(r"\bgh\s+(?:release\s+download|extension\s+install)\b"), "a gh release or extension download"),
    (re.compile(r"\bgit\s+(?:-\S+\s+)*(?:clone|submodule\s+update|fetch\s+\S*https?://|archive\s+--remote)\b"), "a git clone or remote fetch"),
    (re.compile(r"\b(?:helm\s+(?:repo\s+add|install|upgrade)|kubectl\s+(?:apply|create)\s+[^\n]*https?://)"), "a helm or kubectl fetch"),
    (re.compile(r"\bpip[0-9.]*\b[^\n;&|]*?\b(?:install|download)\b[^\n]*(?:git\+|https?://)"), "a pip install from a URL"),
    (re.compile(r"\bpip[0-9.]*\b[^\n;&|]*?\b(?:install|download)\b[^\n]*\s(?:-r|--requirement)[\s=]*(?![^\s]*requirements[\w.-]*\.txt(?:\s|$))\S+"), "a pip requirements file not named requirements*.txt"),
    (re.compile(r"\bdocker\s+build\s+[^\n]*https?://"), "a docker build from a URL"),
]


def tree_scripts(root, rev):
    """{path: text} for every shell script at a revision (rev None: the working tree): where a download or install can hide outside the workflows."""
    out = {}
    if rev is None:
        names = [n for n in git(root, "-c", "core.quotePath=false", "ls-files", "-z").split("\0") if n.endswith(".sh") and not n.startswith((".github/agent/", "vendor/"))]
        for n in names:
            try:
                out[n] = open(f"{root}/{n}").read()
            except OSError:
                continue
            if len(out[n]) > MAX_FILE:
                raise RuntimeError(f"{n} is too large to read safely")
        return out
    for line in git(root, "ls-tree", "-r", "-z", rev).split("\0"):
        meta, _, n = line.partition("\t")
        if n.endswith(".sh") and not n.startswith((".github/agent/", "vendor/")):
            blob = meta.split()[2]
            if blob not in _BLOBS:
                _BLOBS[blob] = git(root, "cat-file", "blob", blob)
            if len(_BLOBS[blob]) > MAX_FILE:
                raise RuntimeError(f"{n} is too large to read safely")
            out[n] = _BLOBS[blob]
    return out


def unmeasured(files):
    """{(file, form, command line): occurrences} for every install form in the workflows and scripts that this inventory does not measure, read after
    joining backslash continuations. Reported as information; a pull request that ADDS an entry (a new command line, even in place of another) is refused."""
    out = {}
    for key, _flat, _bashlike in unmeasured_occurrences(files):
        out[key] = out.get(key, 0) + 1
    return out


def _line_ids(text):
    """One id per line of a script (continuations joined, as the inventory reads it): the 64-hex hash of the whole whitespace-flattened line, prefixed
    'unruled:' for a line bash reads differently from that flattening (REQ-SUP-001-AC16, AC20)."""
    mark = "\ue000"                                    # marks where a continuation was joined; a file that already holds it is never bash-like
    tainted = mark in text
    ids = []
    for line in re.sub(r"\\\n\s*", " " if tainted else " " + mark, text).split("\n"):
        bashlike = not tainted and mark not in line and all(c in " \t" or not c.isspace() for c in line)
        if not tainted:
            line = line.replace(mark, "")
        h = hashlib.sha256(" ".join(line.split()).encode("utf-8", "replace")).hexdigest()
        ids.append(h if bashlike else "unruled:" + h)
    return ids


# The top-level vendor/ is skipped by this inventory because nothing runs from it (REQ-VEND-001; owner exception 1 of Oct 15). That premise is held by a
# FILE-LEVEL rule, not by reading commands: a non-comment line of a scanned file outside vendor/ that names the vendored folder (a path under vendor/, a bare vendor
# word; `go mod vendor` and -mod=vendor are the tool's own words) is an unmeasured occurrence unless the file is one of these exact paths. A new workflow or script that
# names vendor/ is therefore refused until a security-tier change lists it here: a human gate on every new consumer, with no shell syntax to spell around.
# bin/check-no-outbound.py and its test are listed because they are ours: the check skips vendor/ by name and
# the test builds a vendor/ fixture to prove it.
# bin/build-apk-helper.py holds the "$src/vendor is missing" refusal that moved out of bin/build-apk.sh;
# bin/chain-test-shape.py holds, as exact text, the build-apk.sh line that names $src/vendor/modules.txt.
_VENDOR_NAMING_FILES = frozenset("""
.github/workflows/ci.yml
.github/workflows/release.yml
bin/assemble-image-test.sh
bin/build-apk-test.sh
bin/build-apk.sh
bin/build-helpers-test.sh
bin/dependabot-reviewer.py
bin/go-module-sbom.py
bin/patch-decide.py
bin/vex-forms.py
bin/check-file-allowlist-test.sh
bin/check-file-allowlist.sh
bin/dependabot-reviewer-test.sh
bin/melange-apko-lib.sh
bin/patch-decide-test.sh
bin/sealed-proof.sh
bin/vendor-check.sh
bin/vendor-provenance-test.sh
bin/vendor-provenance.py
bin/vendoring-test.sh
bin/vex-forms-test.sh
bin/vex-scope-test.sh
bin/chain-check-scripts-test.sh
bin/chain-install-witness-test.sh
bin/chain-release-scripts-test.sh
bin/check-govulncheck.py
bin/check-no-outbound-test.sh
bin/check-no-outbound.py
bin/install-scanner.sh
bin/release-metadata.py
bin/build-apk-helper.py
bin/chain-test-shape.py
""".split())
_VENDOR_LETTER = lambda c: r"(?:" + c + r"|\[[^\]]*" + c + r"[^\]]*\]|\?|\*)"
_VENDOR_SPELLING = r"(?:[\"'\\]|\*)*".join(_VENDOR_LETTER(c) for c in "vendor")       # ven""dor, ven\dor, vendo[r], v*ndor, vend?r
_VENDOR_NAMED = re.compile(r"(?:^|[^\w.-])(?:\./)?(?:vendor|" + _VENDOR_SPELLING + r")(?:/|(?![\w-]))")
_VENDOR_TOOLWORD = re.compile(r"(?<![\w-])go\s+mod\s+vendor(?![\w/.-])|(?<![\w-])-mod=vendor(?![\w/.-])")
_ESCAPE = re.compile(r"\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2}))")
_SURFACE = re.compile(r"(?:\.py|\.mk|(?:^|/)(?:GNU)?[Mm]akefile|(?:^|/)Dockerfile[\w.-]*|\.dockerfile)$")


def tree_surfaces(root, rev):
    """{path: text} for the executable surfaces the other readers skip (python helpers, Makefiles, Dockerfiles), for the vendored-folder rule only."""
    out = {}
    if rev is None:
        names = [n for n in git(root, "-c", "core.quotePath=false", "ls-files", "-z").split("\0") if n and _SURFACE.search(n)]
        for n in names:
            try:
                out[n] = open(f"{root}/{n}").read()
            except (OSError, UnicodeDecodeError):
                continue
        return out
    for line in git(root, "ls-tree", "-r", "-z", rev).split("\0"):
        meta, _, n = line.partition("\t")
        if n and _SURFACE.search(n):
            blob = meta.split()[2]
            if blob not in _BLOBS:
                _BLOBS[blob] = git(root, "cat-file", "blob", blob)
            out[n] = _BLOBS[blob]
    return out


def _names_vendor(line):
    """The line names the vendored folder in any spelling a shell or YAML reads as it: vendor, ./vendor, a quoted, backslashed, globbed or bracketed spelling,
    a YAML \\xNN or \\uNNNN escape. A line that is entirely a comment names nothing; text after a # is still read (a quoted # is not a comment)."""
    s = line.strip()
    if s.startswith("#"):
        return False
    for cand in (s, _ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), s)):
        if _VENDOR_NAMED.search(_VENDOR_TOOLWORD.sub("", cand)):
            return True
    return False


def vendor_list_extras(root, files):
    """Sorted listed paths that EXIST under root but do not name the vendored folder. A listed path with no file is not reported: listing a path is the reviewed
    gate, so an absent entry pre-authorizes only that one exact path (a file that arrives later and names the folder)."""
    naming = {p for p, t in files.items() if not p.startswith((".github/agent/", "vendor/")) and any(_names_vendor(ln) for ln in t.split("\n"))}
    return sorted(p for p in _VENDOR_NAMING_FILES - naming if os.path.lexists(os.path.join(root, p)))


def unmeasured_occurrences(files):
    """Each unmeasured occurrence as (key, the WHOLE flattened line it was found in, bashlike): the line binds a ruled-text row (REQ-SUP-001-AC16) to the
    line, not to the one downloader segment the key hashes. bashlike is False when the line holds whitespace other than a space or a tab, or was joined from
    a backslash-newline continuation: bash reads such a line differently from this flattening, so no row may ever match it."""
    for path, text in sorted(files.items()):
        if path.startswith((".github/agent/", "vendor/")):
            continue  # .github/agent/ is covered by the independent second review (and its tests quote such commands as fixtures)
        scan_all = path.startswith(".github/") or path.endswith(".sh")
        if not scan_all and not _SURFACE.search(path):
            continue
        if path not in _VENDOR_NAMING_FILES:      # a name split by a backslash-newline reads as vendor in the shell: the joined text has no space there
            for ln in re.sub(r"\\\n", "", text).split("\n"):
                if _names_vendor(ln) and not any(_names_vendor(x) for x in text.split("\n") if x.strip() and x.strip() in ln):
                    yield (path, "a line that names the vendored folder", hashlib.sha256(ln.encode("utf-8", "replace")).hexdigest() + ":" + _hide(ln)[:100]), " ".join(ln.split()), False
                    break
        mark = "\ue000"                                    # marks where a continuation was joined; a file that already holds it is never bash-like
        tainted = mark in text
        for line in re.sub(r"\\\n\s*", " " if tainted else " " + mark, text).split("\n"):
            bashlike = not tainted and mark not in line and all(c in " \t" or not c.isspace() for c in line)
            if not tainted:
                line = line.replace(mark, "")
            flat = " ".join(line.split())
            if len(flat) > MAX_LINE:
                raise RuntimeError(f"{path}: a command line of {len(flat)} characters is longer than the {MAX_LINE} this check reads: refusing to read it partially")
            if path not in _VENDOR_NAMING_FILES and _names_vendor(line):
                yield (path, "a line that names the vendored folder", hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest() + ":" + _hide(flat)[:100]), flat, bashlike
            if not scan_all:
                continue
            for seg in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat):    # each downloader invocation on its own: a release URL elsewhere on the line excuses nothing
                urls = re.findall(r"https?://[^\s'\"]+", _hide(seg))
                plain = urls and all(re.match(r"^https?://github\.com/[\w.-]+/[\w.-]+/releases/(?:latest/)?download/", u) and (_GH_DOWNLOAD.search(u) or _GH_LATEST.search(u)) for u in urls)
                if re.search(r"\b(?:curl|wget)\b", seg) and not plain:
                    yield (path, "a download", hashlib.sha256(seg.encode("utf-8", "replace")).hexdigest() + ":" + _hide(seg)[:100]), flat, bashlike
            if path.endswith(".sh"):    # REQ-SUP-001-AC20: a script line that names an unpinned package; ruled like a text line, by the hash of the whole line
                probe = []
                _step({"run": flat}, probe, {})
                if any(i.kind == "package" and i.version == "(unpinned)" for i in probe):
                    yield (path, "an unpinned package install", hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest() + ":" + _hide(flat)[:100]), flat, bashlike
            for rx, what in _UNMEASURED:
                if rx.search(flat):
                    yield (path, what, hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest() + ":" + _hide(flat)[:100]), flat, bashlike  # the WHOLE line decides identity (its hash), never a truncation


if __name__ == "__main__":
    main()
