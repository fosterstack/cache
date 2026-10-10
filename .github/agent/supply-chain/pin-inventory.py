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
import fnmatch
import hashlib
import shlex
import json
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
        self.step = ""   # a placeholder's identity: the hash of the step it sits in

    @property
    def key(self):
        sub = f"/{self.path}" if self.path else ""
        return f"{self.kind}:{self.name}{sub}@{self.version}" + (f"#{self.step}" if self.step else "")

    def __repr__(self):
        return self.key


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, errors="replace")  # a non-UTF-8 blob must never crash the readers
    if r.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


_BLOBS = {}  # blob id -> text: a history scan reads each distinct file version once, not once per commit


def tree_files(root, rev):
    """{path: text} for every file the inventory reads, at a revision (rev None: the working tree)."""
    def wanted(n):
        return (any(fnmatch.fnmatchcase(n, g) for g in WORKFLOW_GLOBS) or n == "bin/install-scanner.sh" or re.search(r"(^|/)action\.ya?ml$", n)
                or (n.endswith(".sh") and not n.startswith(".github/agent/")) or n.rsplit("/", 1)[-1] in VERSION_FILES or re.search(r"(?i)(^|/)[\w.-]*(sha256|checksums?|sha256sums?)[\w.-]*(\.txt|\.sha256|\.sum)?$", n)
                or re.search(r"(^|/)[\w.-]*requirements[\w.-]*\.txt$", n))
    out = {}
    if rev is None:
        for n in git(root, "-c", "core.quotePath=false", "ls-files", "-z").split("\0"):
            if n and wanted(n):
                try:
                    out[n] = open(f"{root}/{n}").read()
                except OSError:
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
    return "step:" + hashlib.sha256((json.dumps(node, sort_keys=True, default=str) + "\0" + _ENV_CTX[0]).encode("utf-8", "replace")).hexdigest()[:10]


def _uses(u, node, out, labels):
    u = u.strip()
    if u.startswith("docker://"):
        out.append(_image_item(u[len("docker://"):]))
    elif u.startswith("./"):
        out.append(Item("action", "local:" + _hide(u), "(local)"))   # a local action outside the globs: its content is not read, so a new one cannot pass
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
                it.step = "default:" + inp + ":" + hashlib.sha256(json.dumps({k: v for k, v in node.items() if k not in ("with", "uses")}, sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()[:8]
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


_ENV_CTX = [""]
_JOB_SUMS = [[]]


_NONPIN = re.compile(r"^$|^\(|\$\{|^latest$|^(main|master|nightly|stable)$|[*<>=~!]")


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
        ctx = " ".join(run.split()) + "\0" + json.dumps(node.get("env"), sort_keys=True, default=str) + "\0" + _ENV_CTX[0]
        tag = "step:" + hashlib.sha256(ctx.encode("utf-8", "replace")).hexdigest()[:10]
        for it in out[n0:]:
            if _NONPIN.search(it.version or "") and not it.step:
                it.step = tag     # a placeholder (variable, @latest, @main, unpinned) is identified by the step it sits in, so a NEW or EDITED one is a new key and is refused


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
            out.append(Item("tool", m.group(1), "latest"))
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
                out.append(Item("tool", "source:" + m.group(1).lower() + "=" + hashlib.sha256(" ".join(ln.split()).encode("utf-8", "replace")).hexdigest()[:12], "(source)"))
        for m in _GH_DOWNLOAD.finditer(run):  # curl/wget of a release asset: the tool is its repo at that version; the EXACT tag is kept as its label
            sums = sorted(set(re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", run)) | set(_JOB_SUMS[0]))   # checksums, not image digests
            out.append(Item("tool", m.group(1), m.group(2) + m.group(3), m.group(2) + m.group(3), m.group(4) + ("#" + hashlib.sha256(" ".join(sums).encode()).hexdigest()[:8] if sums else "")))   # the asset's name is part of the identity: a different file under the same tag is a moved item
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
            for p in _REQ_PIN.finditer(run):
                out.append(Item("package", f"pypi/{p.group(1).lower().replace('_', '-')}", p.group(2)))


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
                        out.append(Item("tool", "source:env:" + ("(expression)" if "${{" in str(ev) else str(ek).lower()) + "=" + hashlib.sha256(str(ev).encode("utf-8", "replace")).hexdigest()[:12], "(source)"))   # an env var that retargets a download
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
                top_env = json.dumps(node.get("env"), sort_keys=True, default=str) + json.dumps(node.get("on"), sort_keys=True, default=str)   # a called workflow's input defaults count
                for job in v.values():
                    _ENV_CTX[0] = top_env + json.dumps(job.get("env") if isinstance(job, dict) else None, sort_keys=True, default=str) + json.dumps(job.get("strategy") if isinstance(job, dict) else None, sort_keys=True, default=str)
                    _JOB_SUMS[0] = re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", json.dumps(job, default=str)) if isinstance(job, dict) else []   # a checksum in ANY step of the job (a separate verify step) belongs to the job's downloads
                    _walk(job, out, labels, "job:" + k)
                    if isinstance(job, dict) and isinstance(job.get("uses"), str) and job["uses"].startswith("./") and job.get("with"):
                        for it in out:                       # a local reusable-workflow call: what it passes in is part of that call's identity
                            if it.version == "(local)" and it.name == "local:" + _hide(job["uses"]) and not it.step:
                                it.step = "with:" + hashlib.sha256(json.dumps(job.get("with"), sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()[:10]
                _ENV_CTX[0] = ""
                _JOB_SUMS[0] = []
                continue
            _walk(v, out, labels, k, in_step=(k == "steps"))
    elif isinstance(node, list):
        for v in node:
            _walk(v, out, labels, path, in_step=in_step)


def inventory(files):
    """The items of one tree's files ({path: text}). Raises on a workflow that does not parse: a pin we cannot read is never skipped."""
    items = {}
    for path, text in sorted(files.items()):
        found = []
        if path == "bin/install-scanner.sh":
            found = [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in _VER_PIN.finditer(text) if m.group(1) != "PATH"]
            found += [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Z][A-Z0-9]*)_VERSION=['\"]?([^\s'\"#]+)", text, re.M)]
            found += [Item("tool", "source:" + m.group(1).lower() + "=" + _hide(m.group(2)), "(source)") for m in re.finditer(r"^[ \t]*(?:export\s+)?([A-Z][A-Z0-9_]*_BASE(?:_URL)?)=['\"]?(?:\$\{[A-Z0-9_]+:?-)?(https?://[^\s'\"}]+)", text, re.M)]  # where it downloads from: changing it is refused (not a pin)
            found += [Item("tool", "scout", m.group(1)) for m in re.finditer(r"\bdocker-scout-(\d+(?:\.\d+)+)\b", text)]  # older versions the script can still install
            for ln in re.sub(r"\\\n\s*", " ", text).split("\n"):   # and the rest of the script like any other: an appended download is seen
                _step({"run": ln}, found, {})
        elif path.rsplit("/", 1)[-1] in VERSION_FILES or (re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1]) and not path.startswith(".github/workflows/") and not path.endswith((".sh", ".yml", ".yaml", ".py"))):
            found = [Item("tool", "file:" + path, "(file)")]   # a version file or a checksum file: its content is the identity (a replaced asset behind the same URL moves the item)
            found[0].step = "content:" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]      # what an installer's *-version-file selects: a changed content is a changed key
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
            for ln in joined:   # a script is read LINE by line (continuations joined): a placeholder's identity is its own line PLUS the assignments of the variables that line references
                refs = {v: assigns[v] for v in set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", ln)) if v in assigns}
                _step({"run": ln, "env": refs} if refs else {"run": ln}, found, {})
                if len(found) > MAX_ITEMS_PER_FILE:
                    raise RuntimeError(f"{path} yields more than {MAX_ITEMS_PER_FILE} items: refusing to read it")   # a script's go install / pip install / docker run / release download are measured like a run step's
        elif path.endswith("requirements.txt") or re.search(r"requirements[\w.-]*\.txt$", path):
            found = [Item("package", f"pypi/{m.group(1).lower().replace('_', '-')}", m.group(2)) for m in _REQ_PIN.finditer(text)]
            for ln in re.sub(r"\\\n\s*", " ", text).split("\n"):
                body = ln.split("#", 1)[0].strip()
                if not body or body.startswith("--hash="):
                    continue
                if _REQ_PIN.match(body):
                    continue                      # name==version (with its --hash options)
                found.append(Item("package", "pypi/(unmeasured:" + hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:12] + ")", "(unpinned)"))   # a URL requirement, a range, an index option, a bare name
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
            _walk(doc, found, labels, "")
        for it in found:
            if it.key in items and (it.version.startswith("(") or "${{" in it.version or it.version in ("latest", "(unversioned)")):     # two identical unresolved occurrences are two items: removing a version from the second must not hide behind the first
                n = 2
                while True:
                    it.step = re.sub(r"~\d+$", "", it.step or "") + f"~{n}"
                    if it.key not in items:
                        break
                    n += 1
            items.setdefault(it.key, it)
    return items


def moved(base_items, head_items):
    """Items in the head that the base did not have: a new pin, or a changed version, counts as moved."""
    return [head_items[k] for k in sorted(head_items) if k not in base_items]


def load_at(root, rev):
    return inventory(tree_files(root, rev))


def main():
    root, rev = (sys.argv[1] if len(sys.argv) > 1 else "."), (sys.argv[2] if len(sys.argv) > 2 else None)
    print(json.dumps(sorted(load_at(root, rev)), indent=1))


if __name__ == "__main__":
    main()


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
        names = [n for n in git(root, "-c", "core.quotePath=false", "ls-files", "-z").split("\0") if n.endswith(".sh") and not n.startswith(".github/agent/")]
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
        if n.endswith(".sh") and not n.startswith(".github/agent/"):
            blob = meta.split()[2]
            if blob not in _BLOBS:
                _BLOBS[blob] = git(root, "cat-file", "blob", blob)
            if len(_BLOBS[blob]) > MAX_FILE:
                raise RuntimeError(f"{n} is too large to read safely")
            out[n] = _BLOBS[blob]
    return out


# --- where a script EXECUTES text (REQ-SUP-001-AC16, AC17) -------------------------------------------------------------------------------------------------------------
# A download counts only where the shell would run it. A small, conservative reader of shell syntax finds the text that is NOT executed: comments, the
# arguments of commands that never run their arguments (echo, printf, cat, ...) while their output is not piped into something that may run it, and the
# words of a heredoc body fed as data (to cat, tee, ...) that are not at a command position of the body read as shell (a body written to a file may be run
# later: a real `curl ...` line in it counts; a stub that only mentions curl in echo, strings or comments does not). Everything else counts as executed:
# the whole text of any other command (its arguments too: `xargs curl`, `docker exec c curl`, a test harness that runs its arguments), every $( ), ` `,
# <( ) and $(( )), a heredoc fed to a shell (read again as shell) or to anything else (python, an unknown command: every word counts), and an assignment
# whose value names a download. A command word is matched as written AND as the shell reads it ('cu''rl', c\url). A script this reader cannot read with
# certainty (an unterminated quote, heredoc or substitution, too deep a nesting, an alias whose definition is computed) is read as before, every line
# executed. A command built from an expansion nobody can read is refused under its own form: eval of an expansion, sh -c of an expansion that supplies a
# command, a command word (or a here-string or heredoc fed to a shell or interpreter) from a variable this script never assigns, a descriptor or coprocess
# that feeds a shell (exec 3> >(sh), coproc). (( )), $(( )) and $[ ] are arithmetic (a << there is a shift, never a heredoc) and their text counts. A group
# ({ }, ( ), if, for, while, case) whose output is piped or redirected into a process makes its text commands count, and a function whose output
# is piped into one makes the whole script read as before. Workflow files are read as before (every line).
_SH_SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "mksh"}
_SH_INTERP = _SH_SHELLS | {"python", "python2", "python3", "perl", "ruby", "node", "php", "lua", "source", "."}
_SH_WRAPPERS = {"env", "sudo", "command", "exec", "nohup", "time", "nice", "timeout", "xargs", "stdbuf", "doas", "setsid", "builtin", "chroot", "ionice", "unbuffer"}
_SH_TEXT = {"echo", "printf", ":", "true", "false", "test", "[", "[[", "cat", "tee", "grep", "egrep", "fgrep", "chmod", "chown", "mkdir", "rm", "rmdir", "cp",
            "mv", "ln", "touch", "read", "local", "export", "declare", "readonly", "typeset", "cd", "basename", "dirname", "wc", "sort", "uniq", "head", "tail",
            "cut", "tr", "for", "select", "case", "mktemp", "ls", "sha256sum", "shasum"}     # commands that never execute their arguments
_SH_DATA = {"cat", "tee", ":", "true", "read", "grep", "egrep", "fgrep", "wc", "sort", "uniq", "head", "tail", "cut", "tr", "diff", "cmp", "base64",
            "sha256sum", "shasum", "jq", "echo", "printf"}      # a heredoc fed to one of these (and piped only into these) is data
_SH_DECLARE = {"local", "export", "declare", "readonly", "typeset"}
_SH_SKIP = {"if", "then", "else", "elif", "do", "while", "until", "!", "time", "fi", "done", "esac"}   # reserved words before a command
_SH_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\n]*\])?\+?=")
_SH_DEFINED = re.compile(r"(?:^|[\s;&|(){}])(?:function\s+([^\s(){};&|<>]+)|([^\s(){};&|<>'\"=$`]+)\s*\(\s*\))|\balias\s+([^\s=]+)=")
_SH_SPECIAL = set("0123456789@*#?$!-")       # positional and special parameters: what a caller passes is counted at the call
_SH_DOWNLOADER = {"curl", "wget"}
_SH_MAX_DEPTH = 40
_SH_DQ_RUN = re.compile(r'[^"\\$`]+')
_SH_WORD_RUN = re.compile(r"[^ \t\r\n;&|()<>\\'\"$`]+")
_SH_VAR = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]")
_SH_BRACE_VAR = re.compile(r"[!#]?([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])")


class _ShellUnreadable(Exception):
    pass


class _Word:
    __slots__ = ("start", "end", "value", "shape", "expanded", "quoted", "procsub", "vars", "subst")

    def __init__(self, start):
        self.start, self.end, self.value, self.shape, self.expanded, self.quoted, self.procsub = start, start, "", "", False, False, False
        self.vars, self.subst = [], False      # the variables it expands; whether it holds a command substitution

    def lit(self, text):
        self.value += text; self.shape += text


class _Cmd:
    def __init__(self, start):
        self.start, self.end, self.words, self.name, self.piped_to, self.procsub = start, start, [], None, None, False
        self.assigns, self.herestrings = [], []
        self.group_out = False      # inside a group ({ }, ( ), if, for, while, case) whose output is piped or redirected into a process: its text may be run


def _base(word):
    return word.value.rsplit("/", 1)[-1] if word is not None and not word.expanded else None


class _ShellScan:
    """What a shell text executes: spans [(start, end)] whose words count, hits (offsets of a command word the shell reads as curl or wget), norms
    ((offset, the command as the shell reads its words)) and the offsets of commands built from an expansion nobody can read. data=True reads a heredoc
    body written as data: only its command positions count, and nothing in it is refused as dynamic (it is not run here)."""

    def __init__(self, s, depth=0, untrusted=frozenset(), known=frozenset(), data=False):
        self.s, self.n, self.i, self.depth, self.data = s, len(s), 0, depth, data
        self.spans, self.dynamic, self.cmds, self.pending, self.heredocs, self.hits, self.norms = [], [], [], [], [], [], []
        defined = list(_SH_DEFINED.finditer(s))
        self.untrusted = set(untrusted) | {m.group(1) or m.group(2) or m.group(3) for m in defined}  # a function or alias may shadow echo or cat
        self.functions = {m.group(1) or m.group(2) for m in defined if m.group(1) or m.group(2)}
        self.known = set(known) | _SH_SPECIAL
        self.sources = []      # the base names of the files this text sources (. lib.sh): the variables they assign are known here

    def run(self):
        self.parse_list(None)
        if self.pending:
            raise _ShellUnreadable("a heredoc with no body")
        for cmd in self.cmds:     # every variable this text assigns plainly (NAME=value, local/export/declare NAME=value)
            self.known.update(w.value.split("=", 1)[0].split("[", 1)[0].rstrip("+") for w in cmd.assigns)
            if _base(cmd.name) in _SH_DECLARE:
                self.known.update(re.match(r"[A-Za-z_][A-Za-z0-9_]*", w.value).group(0) for w in cmd.words if re.match(r"[A-Za-z_]", w.value))
            if _base(cmd.name) in (".", "source") and cmd.words:
                self.sources.append(cmd.words[0].shape.replace('"', "").replace("'", "").rsplit("/", 1)[-1])
        self.classify()
        return self

    def _deeper(self):
        if self.depth >= _SH_MAX_DEPTH:
            raise _ShellUnreadable("nested too deep")
        self.depth += 1

    # ---- the command level ----
    def parse_list(self, stop):
        s, n = self.s, self.n
        self._deeper()
        cmd, pipe_from, paren, case = None, None, 0, 0
        last_op = None
        groups, closed = [], None      # open groups (closer, index of their first command); the group that just closed

        def mark(start):      # { echo "curl x"; } | sh: every command of the group writes into the consumer
            for c in self.cmds[start:]:
                c.group_out = True

        def end(op):
            nonlocal cmd, pipe_from
            if cmd is not None:
                self.cmds.append(cmd)
                if op in ("|", "|&"):
                    pipe_from = cmd
                cmd = None
            elif pipe_from is not None and op not in ("|", "|&", "\n"):
                pipe_from.piped_to = "unknown"; pipe_from = None
        while True:
            if self.i >= n:
                if stop:
                    raise _ShellUnreadable("an unterminated substitution")
                end(None)
                self.depth -= 1
                return
            c = s[self.i]
            if c in " \t\r":
                self.i += 1; continue
            if c == "\\" and s.startswith("\n", self.i + 1):
                self.i += 2; continue
            if c == "\n":
                if last_op not in ("|", "|&", "&&", "||"):
                    end("\n")
                    last_op = "\n"
                self.i += 1
                self.read_heredocs()
                continue
            if c == "#":
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j
                continue
            if c == ")" and stop and paren == 0 and case == 0:
                end(")")
                self.i += 1
                self.depth -= 1
                return
            after, closed = closed, None
            if s.startswith("((", self.i):      # an arithmetic command (or a for (( ))): no heredoc and no command inside; its text counts, fail closed
                self.i = self.arith(self.i + 2, 2, "(", ")")
                last_op = None
                continue
            op = next((o for o in (";;&", ";;", ";&", "&&", "||", "|&", ";", "&", "|", "(", ")") if s.startswith(o, self.i)), None)
            if op and not (op == "&" and s.startswith(("&>",), self.i)):
                self.i += len(op)
                closes = op == ")" and paren > 0
                if op == "(":
                    paren += 1
                elif op == ")":
                    if paren:
                        paren -= 1
                if pipe_from is not None and cmd is None and op not in ("|", "|&"):
                    pipe_from.piped_to = "unknown"; pipe_from = None
                if after is not None and op in ("|", "|&"):
                    mark(after)
                end(op)
                if op == "(":
                    groups.append((")", len(self.cmds)))
                elif closes and groups and groups[-1][0] == ")":
                    closed = groups.pop()[1]
                last_op = op
                continue
            redir = next((o for o in ("<<<", "<<-", "<<", "&>>", "&>", "<>", "<&", ">&", ">>", ">|", "<", ">") if s.startswith(o, self.i)), None)
            if redir and not (redir in ("<", ">") and s.startswith("(", self.i + 1)):
                if cmd is None:
                    cmd = self._new(self.i, pipe_from); pipe_from = None
                self.i += len(redir)
                while self.i < n and s[self.i] in " \t":
                    self.i += 1
                if self.i >= n or (s[self.i] in "\n;&|()<>" and not (s[self.i] in "<>" and s.startswith("(", self.i + 1))):
                    raise _ShellUnreadable("a redirection with no word")
                w = self.parse_word()
                cmd.end = w.end
                if redir in ("<<", "<<-"):
                    self.pending.append((cmd, w, redir == "<<-"))
                elif redir == "<<<":
                    cmd.herestrings.append(w)
                if w.procsub:
                    cmd.procsub = True
                    if after is not None:
                        mark(after)      # { ...; } > >(sh)
                elif after is not None:
                    closed = after       # } 2>&1 | sh: the group's redirections come before its pipe
                last_op = None
                continue
            w = self.parse_word()
            last_op = None
            if not w.quoted and not w.expanded and w.value in ("{", "}"):
                if pipe_from is not None and cmd is None:
                    pipe_from.piped_to = "unknown"; pipe_from = None
                end(w.value)
                if w.value == "{":
                    groups.append(("}", len(self.cmds)))
                elif groups and groups[-1][0] == "}":
                    closed = groups.pop()[1]
                continue
            if cmd is None:
                cmd = self._new(w.start, pipe_from); pipe_from = None
            cmd.end = w.end
            cmd.procsub = cmd.procsub or w.procsub
            if cmd.name is None:
                plain = not w.quoted and not w.expanded
                if plain and w.value in _SH_SKIP:
                    if w.value == "esac" and case:
                        case -= 1
                    if w.value in ("if", "while", "until"):
                        groups.append(("fi" if w.value == "if" else "done", len(self.cmds)))
                    elif w.value in ("fi", "done", "esac") and groups and groups[-1][0] == w.value:
                        closed = groups.pop()[1]
                    continue
                if _SH_ASSIGN.match(s, w.start):
                    cmd.assigns.append(w)
                    continue
                cmd.name = w
                if plain and w.value == "case":
                    case += 1
                if plain and w.value in ("case", "for", "select"):
                    groups.append(("esac" if w.value == "case" else "done", len(self.cmds)))
            else:
                cmd.words.append(w)

    def _new(self, start, pipe_from):
        c = _Cmd(start)
        if pipe_from is not None:
            pipe_from.piped_to = c
        return c

    def read_heredocs(self):
        s, n = self.s, self.n
        todo, self.pending = self.pending, []
        for cmd, w, strip in todo:
            delim = w.value
            start = self.i
            joined = False
            while True:
                if self.i >= n:
                    raise _ShellUnreadable("an unterminated heredoc")
                j = s.find("\n", self.i)
                e = n if j < 0 else j
                line = s[self.i:e]
                if not joined and (line.lstrip("\t") if strip else line) == delim:
                    body_end = self.i
                    self.i = e + 1 if j >= 0 else n
                    break
                joined = not w.quoted and (len(line) - len(line.rstrip("\\"))) % 2 == 1   # an unquoted body joins a line ending in a backslash
                self.i = e + 1 if j >= 0 else n
                if j < 0:
                    raise _ShellUnreadable("an unterminated heredoc")
            ew = self.expansions(start, body_end) if not w.quoted else None    # $( ) and ` ` in an unquoted body are executed whatever reads the body
            self.heredocs.append((cmd, start, body_end, ew))

    def expansions(self, a, b):
        save = self.i
        self.i = a
        w = _Word(a)
        while self.i < b:
            c = self.s[self.i]
            if c == "\\":
                self.i += 2
            elif c == "$":
                self.dollar(w)
            elif c == "`":
                self.backtick(w)
            else:
                self.i += 1
        if self.i > b:
            raise _ShellUnreadable("a substitution runs out of its heredoc")
        self.i = save
        return w

    # ---- words ----
    def parse_word(self):
        s, n = self.s, self.n
        w = _Word(self.i)
        while self.i < n:
            c = s[self.i]
            if c in "<>" and s.startswith("(", self.i + 1):
                a = self.i
                self.i += 2
                self.parse_list(")")
                self.spans.append((a, self.i)); w.expanded = w.procsub = w.subst = True; w.shape += s[a:self.i]
                continue
            if c == "(" and not w.quoted and not w.expanded and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\n]*\])?\+?=", w.value):
                self.array(w); continue      # name=( ... ): an array assignment, its elements are words
            if c in " \t\r\n;&|()<>":
                break
            if c == "\\":
                if s.startswith("\n", self.i + 1):
                    self.i += 2; continue
                w.lit(s[self.i + 1:self.i + 2]); w.quoted = True; self.i += 2; continue
            if c == "'":
                j = s.find("'", self.i + 1)
                if j < 0:
                    raise _ShellUnreadable("an unterminated quote")
                w.lit(s[self.i + 1:j]); w.quoted = True; self.i = j + 1; continue
            if c == '"':
                self.i += 1; self.dquote(w); w.quoted = True; continue
            if c == "$":
                self.dollar(w); continue
            if c == "`":
                self.backtick(w); continue
            m = _SH_WORD_RUN.match(s, self.i)
            w.lit(m.group(0)); self.i = m.end()
        w.end = self.i
        return w

    def array(self, w):
        s, n = self.s, self.n
        self.i += 1
        while True:
            if self.i >= n:
                raise _ShellUnreadable("an unterminated array")
            c = s[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif c == "\\" and s.startswith("\n", self.i + 1):
                self.i += 2
            elif c == "#":
                j = s.find("\n", self.i)
                self.i = n if j < 0 else j
            elif c == ")":
                self.i += 1
                return
            elif c in ";&|(<>":
                raise _ShellUnreadable("an array element that is not a word")
            else:
                e = self.parse_word()
                w.value += " " + e.value; w.shape += " " + e.shape
                w.vars += e.vars; w.expanded |= e.expanded; w.subst |= e.subst; w.procsub |= e.procsub

    def dquote(self, w):
        s, n = self.s, self.n
        while True:
            if self.i >= n:
                raise _ShellUnreadable("an unterminated quote")
            c = s[self.i]
            if c == '"':
                self.i += 1; return
            if c == "\\":
                w.lit(s[self.i + 1:self.i + 2]); self.i += 2
            elif c == "$":
                self.dollar(w)
            elif c == "`":
                self.backtick(w)
            else:
                m = _SH_DQ_RUN.match(s, self.i)
                w.lit(m.group(0)); self.i = m.end()

    def arith(self, i, depth, opener, closer):
        """Skip an arithmetic text from i (depth openers already read) to its end; the whole text counts as executed (fail closed)."""
        s, n = self.s, self.n
        a = i - depth
        while depth:
            if i >= n:
                raise _ShellUnreadable("an unterminated arithmetic expression")
            c = s[i]
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
            elif c in "'\"`":
                j = s.find(c, i + 1)
                if j < 0:
                    raise _ShellUnreadable("an unterminated quote")
                i = j
            i += 1
        self.spans.append((a, i))
        return i

    def backtick(self, w):
        s, n = self.s, self.n
        a = self.i
        self.i += 1
        while True:
            if self.i >= n:
                raise _ShellUnreadable("an unterminated backquote")
            if s[self.i] == "\\":
                self.i += 2; continue
            if s[self.i] == "`":
                self.i += 1; break
            self.i += 1
        self.spans.append((a, self.i)); w.expanded = w.subst = True; w.shape += s[a:self.i]

    def dollar(self, w):
        s, n = self.s, self.n
        a = self.i
        nxt = s[self.i + 1:self.i + 2]
        if s.startswith("$((", self.i):
            self.i += 3
            depth = 2
            while depth:
                if self.i >= n:
                    raise _ShellUnreadable("an unterminated arithmetic expansion")
                c = s[self.i]
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                elif c in "'\"":
                    j = s.find(c, self.i + 1)
                    if j < 0:
                        raise _ShellUnreadable("an unterminated quote")
                    self.i = j
                self.i += 1
            self.spans.append((a, self.i)); w.expanded = w.subst = True
        elif nxt == "(":
            self.i += 2
            self.parse_list(")")
            self.spans.append((a, self.i)); w.expanded = w.subst = True
        elif nxt == "[":      # $[ ]: the old arithmetic expansion (no heredoc inside)
            self.i = self.arith(self.i + 2, 1, "[", "]")
            w.expanded = w.subst = True
        elif nxt == "{":
            self.i += 2
            m = _SH_BRACE_VAR.match(s, self.i)
            w.vars.append(m.group(1) if m else "")       # "" is never known: an unreadable parameter name fails closed
            self._deeper()
            depth = 1
            inner = _Word(self.i)
            while depth:
                if self.i >= n:
                    raise _ShellUnreadable("an unterminated parameter expansion")
                c = s[self.i]
                if c == "\\":
                    self.i += 2
                elif c == "'":
                    j = s.find("'", self.i + 1)
                    if j < 0:
                        raise _ShellUnreadable("an unterminated quote")
                    self.i = j + 1
                elif c == '"':
                    self.i += 1; self.dquote(inner)
                elif c == "$":
                    self.dollar(inner)
                elif c == "`":
                    self.backtick(inner)
                else:
                    depth += 1 if c == "{" else -1 if c == "}" else 0
                    self.i += 1
            self.depth -= 1
            w.expanded = True
            w.subst = w.subst or inner.subst
            w.vars += inner.vars
        elif nxt == "'":
            j = self.i + 2
            while True:
                if j >= n:
                    raise _ShellUnreadable("an unterminated quote")
                if s[j] == "\\":
                    j += 2; continue
                if s[j] == "'":
                    break
                j += 1
            w.lit(s[self.i + 2:j]); w.quoted = True; self.i = j + 1
            return
        elif nxt == '"':
            self.i += 2; self.dquote(w); w.quoted = True
            return
        elif nxt and (nxt.isalnum() or nxt == "_"):
            m = _SH_VAR.match(s, self.i + 1)
            self.i = m.end(); w.expanded = True; w.vars.append(m.group(0))
        elif nxt and nxt in "@*#?$!-":
            self.i += 2; w.expanded = True; w.vars.append(nxt)
        else:
            w.lit("$"); self.i += 1
            return
        w.shape += s[a:self.i]

    # ---- what is executed ----
    def _name(self, cmd):
        w = cmd.name
        if w is None or w.expanded or w.value in self.untrusted:
            return None
        return w.value

    def _sub(self, text, data=False):
        return _ShellScan(text, self.depth + 1, self.untrusted, self.known, data).run()

    def _dynamic_in(self, text):
        """Whether a string that a shell runs again (eval, sh -c, a here-string) holds a command built from an expansion nobody can read."""
        try:
            return bool(self._sub(text).dynamic)
        except (_ShellUnreadable, RecursionError):
            return False

    def _unknown(self, w):
        return w.expanded and (not w.vars or any(v not in self.known for v in w.vars)) and not (w.subst and not w.vars)

    def _data_chain(self, cmd):
        """Whether a command and everything its output is piped into only read data (cat, tee, grep, ...: nothing that runs what it reads)."""
        while cmd is not None:
            if cmd == "unknown" or cmd.procsub or cmd.group_out or (cmd.name is not None and self._name(cmd) not in _SH_DATA):
                return False
            cmd = cmd.piped_to
        return True

    def _runner(self, cmd):
        """(index into [name] + words, base name) of the shell or interpreter a command runs, itself or through a wrapper (env sh -c ...), or None."""
        ws = [cmd.name] + cmd.words
        if _base(cmd.name) in _SH_INTERP or re.fullmatch(r"python[0-9.]*", _base(cmd.name) or ""):
            return 0, _base(cmd.name)
        if _base(cmd.name) in _SH_WRAPPERS:
            for k, w in enumerate(ws[1:], 1):
                b = _base(w)
                if b in _SH_INTERP or re.fullmatch(r"python[0-9.]*", b or ""):
                    return k, b
        return None

    def _dyn(self, offset):
        if not self.data:
            self.dynamic.append(offset)

    def classify(self):
        for cmd in self.cmds:
            if any(w.expanded for w in cmd.words + [cmd.name] if w is not None) and "alias" in {_base(w) for w in [cmd.name] + cmd.words if w is not None}:
                raise _ShellUnreadable("an alias whose definition is computed")    # it can turn any word into a command: no text exemption holds
            for w in cmd.assigns + ([x for x in cmd.words if _SH_ASSIGN.match(self.s, x.start) or _SH_ASSIGN.match(x.value)] if _base(cmd.name) in _SH_DECLARE else []):
                if re.search(r"\b(?:curl|wget)\b", w.value) or any(rx.search(w.value) for rx, _ in _UNMEASURED):
                    self.spans.append((w.start, w.end)); self.hits.append(w.start) if re.search(r"\b(?:curl|wget)\b", w.value) else None
                    self.norms.append((w.start, w.value.split("=", 1)[-1]))    # C=curl, CMD='curl ...': a download held for later is counted where it is named
            if cmd.name is None:
                continue
            name = self._name(cmd)
            if name in _SH_TEXT and not cmd.procsub and not cmd.group_out and self._data_chain(cmd.piped_to):
                continue      # its arguments are text, unless its output is piped into something that may run it (echo "curl x" | sh)
            if not cmd.name.expanded and cmd.name.value in self.functions and (cmd.procsub or not self._data_chain(cmd.piped_to)):
                raise _ShellUnreadable("a function whose output is piped into a process")     # f | sh: no text exemption holds
            ws = [cmd.name] + cmd.words
            if self.data:      # a body written as data: a command word the shell reads as a download counts (a wrapper's words too), never the text around it
                counted = ws if name in _SH_WRAPPERS else [cmd.name]
            else:
                self.spans.append((cmd.start, cmd.end))
                counted = ws
            self.hits += [w.start for w in counted if _base(w) in _SH_DOWNLOADER]
            self.norms.append((cmd.name.start, " ".join(w.value for w in ws)))
            if self._unknown(cmd.name):
                self._dyn(cmd.name.start)      # "$TOOL" ...: a command word from a variable this script never assigns
            if name in _SH_WRAPPERS:
                rest = [w for w in cmd.words if not w.value.startswith("-") and not _SH_ASSIGN.match(w.value)]
                if rest and self._unknown(rest[0]):
                    self._dyn(cmd.name.start)
            if name == "eval":
                if any(w.expanded for w in cmd.words) or self._dynamic_in(" ".join(w.value for w in cmd.words)):
                    self._dyn(cmd.name.start)
            if name in ("exec", "coproc") and (cmd.procsub or name == "coproc"):
                self._dyn(cmd.name.start)      # exec 3> >(sh): what is written to the descriptor later is run
            run = self._runner(cmd)
            if run is not None:
                k, base = run
                shell = base in _SH_SHELLS
                for j, w in enumerate(ws[k + 1:], k + 1):
                    if not w.expanded and re.fullmatch(r"-[A-Za-z]*[ce][A-Za-z]*", w.value):
                        cs = next((x for x in ws[j + 1:] if not x.value.startswith("-") or x.expanded), None)
                        if cs is not None and cs.expanded and (not cs.value.strip() or (self._dynamic_in(cs.shape) if shell else self._unknown(cs))):
                            self._dyn(cmd.name.start)    # sh -c "$x" is eval $x
                        elif cs is not None and not cs.expanded and shell and self._dynamic_in(cs.value):
                            self._dyn(cmd.name.start)
                        break
                for hs in cmd.herestrings:      # sh <<< "$CMD"
                    if hs.expanded and (not hs.value.strip() or (self._dynamic_in(hs.shape) if shell else self._unknown(hs))):
                        self._dyn(cmd.name.start)
        for cmd, a, b, ew in self.heredocs:
            name = self._name(cmd) if cmd.name is not None else ":"
            if self.data or self._data_chain(cmd):
                try:      # written as data: its command positions still count (it may be run later)
                    sub = self._sub(self.s[a:b], data=True)
                except (_ShellUnreadable, RecursionError):
                    for m in re.finditer(r"(?m)^[ \t]*([^\s;&|()<>]+)", self.s[a:b]):    # not shell: the first word of each line counts
                        tok = re.sub(r"[\\'\"]", "", m.group(1)).rsplit("/", 1)[-1]
                        if tok in _SH_DOWNLOADER or any(rx.match(self.s, a + m.start(1)) for rx, _ in _UNMEASURED):
                            self.spans.append((a + m.start(1), a + m.end(1))); self.hits.append(a + m.start(1))
                    continue
                self._take(sub, a, dynamic=False)
                continue
            run = self._runner(cmd)
            if run is not None and ew is not None and any(v not in self.known for v in ew.vars):
                self._dyn(cmd.name.start)     # an unquoted heredoc fed to a shell or interpreter, built from a variable nobody can read
            if run is not None and run[1] in _SH_SHELLS and all(w.value.startswith("-") and not w.expanded and "c" not in w.value for w in cmd.words):
                try:
                    sub = self._sub(self.s[a:b])
                except (_ShellUnreadable, RecursionError):
                    self.spans.append((a, b)); continue
                self._take(sub, a, dynamic=True)
                continue
            self.spans.append((a, b))      # fed to python or an unknown command: every word counts

    def _take(self, sub, a, dynamic):
        self.spans += [(x + a, y + a) for x, y in sub.spans]
        self.hits += [x + a for x in sub.hits]
        self.norms += [(x + a, t) for x, t in sub.norms]
        if dynamic:
            for x in sub.dynamic:
                self._dyn(x + a)


def _executed(text, known=frozenset()):
    """(merged executed spans, dynamic offsets, hits, norms) of a script, or None when it cannot be read with certainty (then every line counts, as before)."""
    try:
        sc = _ShellScan(text, known=known).run()
    except (_ShellUnreadable, RecursionError):
        return None
    merged = []
    for a, b in sorted(sc.spans):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged, sorted(sc.dynamic), sorted(set(sc.hits)), sc.norms


def _sourced_known(path, files):
    """The variables assigned by the scripts that a script sources (transitively), matched by base name, nearest directory first."""
    known, seen, todo = set(), {path}, [path]
    while todo:
        p = todo.pop()
        try:
            sc = _ShellScan(files[p]).run()
        except (_ShellUnreadable, RecursionError):
            continue
        if p != path:
            known |= sc.known
        for base in sc.sources:
            cands = sorted((q for q in files if q.endswith(".sh") and q.rsplit("/", 1)[-1] == base), key=lambda q: (q.rsplit("/", 1)[0] != p.rsplit("/", 1)[0], q))
            if cands and cands[0] not in seen:
                seen.add(cands[0]); todo.append(cands[0])
    return known


def _script_forms(path, text, out, known=frozenset()):
    """unmeasured() for one script: the same keys as before, counted only where the text is executed."""
    import bisect
    conts = list(re.finditer(r"\\\n\s*", text))
    starts = [m.start() for m in conts]
    removed = [0]
    for m in conts:
        removed.append(removed[-1] + len(m.group(0)) - 1)

    def joined_at(p):      # a raw offset -> its offset in the text with continuations joined
        k = bisect.bisect_right(starts, p) - 1
        if k >= 0 and p < conts[k].end():
            return conts[k].start() - removed[k]
        return p - removed[k + 1]
    ex = _executed(text, known)
    joined = re.sub(r"\\\n\s*", " ", text)
    if ex is None:
        spans, dyn, hits, norms = [(0, len(joined) + 1)], [], [], []
    else:
        spans = [(joined_at(a), joined_at(b - 1) + 1 if b > a else joined_at(a)) for a, b in ex[0]]
        dyn, hits, norms = [joined_at(p) for p in ex[1]], [joined_at(p) for p in ex[2]], [(joined_at(p), t) for p, t in ex[3]]
    sstarts = [a for a, _ in spans]
    hits.sort()
    norms.sort(key=lambda x: x[0])
    nstarts = [p for p, _ in norms]

    def executed(p):
        k = bisect.bisect_right(sstarts, p) - 1
        return k >= 0 and p < spans[k][1]
    base = 0
    for line in joined.split("\n"):
        flat = " ".join(line.split())
        lo, hi = base, base + len(line)
        base = hi + 1
        cuts = [0]
        for m in re.finditer(r"\s*(?:;|&&|\|\||\|)\s*", line):
            cuts += [m.start(), m.end()]
        cuts.append(len(line))
        for x in range(0, len(cuts), 2):
            seg = line[cuts[x]:cuts[x + 1]]
            a, b = lo + cuts[x], lo + cuts[x + 1]
            k = bisect.bisect_left(hits, a)
            if not (k < len(hits) and hits[k] <= b) and not any(executed(a + m.start()) for m in re.finditer(r"\b(?:curl|wget)\b", seg)):
                continue      # neither written as curl/wget where it is executed, nor read by the shell as curl/wget ('cu''rl')
            seg = " ".join(seg.split())
            urls = re.findall(r"https?://[^\s'\"]+", _hide(seg))
            plain = urls and all(re.match(r"^https?://github\.com/[\w.-]+/[\w.-]+/releases/(?:latest/)?download/", u) and (_GH_DOWNLOAD.search(u) or _GH_LATEST.search(u)) for u in urls)
            if not plain:
                key = (path, "a download", hashlib.sha256(seg.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(seg)[:100])
                out[key] = out.get(key, 0) + 1
        read = [t for p, t in norms[bisect.bisect_left(nstarts, lo):bisect.bisect_right(nstarts, hi)]]
        for rx, what in _UNMEASURED:
            pos = 0
            while True:
                m = rx.search(line, pos)
                if m is None or executed(lo + m.start()):
                    break
                pos = m.start() + 1
            if m is not None or any(rx.search(t) for t in read):
                key = (path, what, hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(flat)[:100])
                out[key] = out.get(key, 0) + 1
        for p in dyn:
            if lo <= p <= hi:
                key = (path, "a command built from an expansion (eval, sh -c), which this check cannot read", hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(flat)[:100])
                out[key] = out.get(key, 0) + 1


def unmeasured(files):
    """{(file, form, command line): occurrences} for every install form in the workflows and scripts that this inventory does not measure, read after
    joining backslash continuations. Reported as information; a pull request that ADDS an entry (a new command line, even in place of another) is refused.
    In a script (*.sh) only executed text counts (REQ-SUP-001-AC16, AC17: see _ShellScan); a workflow is read line by line as before."""
    out = {}
    for path, text in sorted(files.items()):
        if not (path.startswith(".github/") or path.endswith(".sh")) or path.startswith(".github/agent/"):
            continue  # .github/agent/ is covered by the review-record gate (and its tests quote such commands as fixtures)
        if path.endswith(".sh"):
            for line in re.sub(r"\\\n\s*", " ", text).split("\n"):
                if len(" ".join(line.split())) > MAX_LINE:
                    raise RuntimeError(f"{path}: a command line of {len(' '.join(line.split()))} characters is longer than the {MAX_LINE} this check reads: refusing to read it partially")
            _script_forms(path, text, out, _sourced_known(path, files))
            continue
        for line in re.sub(r"\\\n\s*", " ", text).split("\n"):
            flat = " ".join(line.split())
            if len(flat) > MAX_LINE:
                raise RuntimeError(f"{path}: a command line of {len(flat)} characters is longer than the {MAX_LINE} this check reads: refusing to read it partially")
            for seg in re.split(r"\s*(?:;|&&|\|\||\|)\s*", flat):    # each downloader invocation on its own: a release URL elsewhere on the line excuses nothing
                urls = re.findall(r"https?://[^\s'\"]+", _hide(seg))
                plain = urls and all(re.match(r"^https?://github\.com/[\w.-]+/[\w.-]+/releases/(?:latest/)?download/", u) and (_GH_DOWNLOAD.search(u) or _GH_LATEST.search(u)) for u in urls)
                if re.search(r"\b(?:curl|wget)\b", seg) and not plain:
                    key = (path, "a download", hashlib.sha256(seg.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(seg)[:100])
                    out[key] = out.get(key, 0) + 1
            for rx, what in _UNMEASURED:
                if rx.search(flat):
                    key = (path, what, hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()[:16] + ":" + _hide(flat)[:100])  # the WHOLE line decides identity (its hash), never a truncation
                    out[key] = out.get(key, 0) + 1
    return out
