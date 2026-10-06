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


def _tails(run, is_cmd, subcommands, skip_values=()):
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
                out.append(" ".join(tail))
                if len(out) > MAX_ITEMS_PER_STEP:
                    raise RuntimeError("a step repeats one command more than %d times: refusing to read it (a hostile text could exhaust the readers)" % MAX_ITEMS_PER_STEP)
    return out


def _pip_tails(run):
    return _tails(run, lambda t: re.fullmatch(r"pip[0-9.]*", t) is not None, {"install"}, _PIP_VALUE_OPTS | {"--timeout", "--retries", "--proxy", "--cert", "--cache-dir", "--log", "--isolated"})
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
                or (n.endswith(".sh") and not n.startswith(".github/agent/")) or n in VERSION_FILES
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
                if key not in known and isinstance(val, str) and val.strip() and re.search(r"(^|[-_])(versions?|tags?|releases?|tools|images?)(-file)?$", key):
                    it = Item("tool", f"{repo}:{key}", "(input)")       # an installer-shaped input nobody classified: a placeholder, so a new or changed one is refused
                    it.step = _ctx_tag(node)                           # identified by the whole step (its value included) and the env/matrix it reads
                    out.append(it)
        for inp, tool in INSTALLER_INPUTS.get(repo.lower(), []):
            if tool is not None and not (isinstance(w, dict) and isinstance(w.get(inp), str) and w[inp].strip()):
                it = Item("tool", tool, "(default)")       # no version given: the action installs whatever its default is, so removing the input must not remove the obligation
                it.step = "default:" + inp + ":" + hashlib.sha256(json.dumps({k: v for k, v in node.items() if k != "with"}, sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()[:8]
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
    return _tails(run, lambda t: t in ("docker", "podman", "nerdctl", "buildah"), {"run", "pull", "create"}, _DOCKER_VALUE_OPTS)
_DOCKER_VALUE_OPTS = {"--context", "-c", "--host", "-H", "--config", "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey", "--cpus", "--memory", "-m", "--cpu-shares", "--pids-limit", "--shm-size", "--ulimit", "--restart", "--log-driver", "--log-opt", "--group-add", "--security-opt", "--tmpfs", "--init-path", "--stop-signal", "--stop-timeout", "--ip", "--ip6", "--hostname", "--cidfile", "--cgroupns", "--ipc", "--pid", "--uts", "--userns", "--gpus", "--runtime", "--sysctl", "--annotation", "--volumes-from", "--link", "--expose", "--detach-keys", "--health-cmd", "--health-interval", "--pull","-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "-w", "--workdir", "-u", "--user", "--entrypoint",
                      "--platform", "-l", "--label", "--mount", "--env-file", "-h", "--hostname", "--add-host", "--cap-add", "--cap-drop", "--device", "--dns", "--pull"}


def _docker_images(cmd_args):
    """The image of a docker run/pull/create: the first argument that is not an option or an option's value (quotes read as a shell would)."""
    try:
        toks = shlex.split(cmd_args)
    except ValueError:
        toks = cmd_args.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("-"):
            takes = (t in _DOCKER_VALUE_OPTS and "=" not in t) or (i + 1 < len(toks) and re.fullmatch(r"[\d.]+[kmgb]?", toks[i + 1]) is not None and "=" not in t and t.startswith("--"))
            i += 2 if takes else 1
            continue
        if "$" in t:
            return ["(variable)"]                      # the image is a shell variable: a placeholder item that cannot be proven, so a new one is refused
        return [t] if re.fullmatch(r"[\w.\-/:]+(@sha256:[0-9a-f]{64})?", t) else []
    return []


_ENV_CTX = [""]


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
        for tail in _docker_tails(run):
            for img in _docker_images(tail):
                out.append(_image_item(img))
        for ln in run.split("\n"):    # where a script downloads FROM: an assignment of a URL/BASE variable is a source line identified by its own text
            m = _SOURCE_ASSIGN.match(ln)
            if m:
                out.append(Item("tool", "source:" + m.group(1).lower() + "=" + hashlib.sha256(" ".join(ln.split()).encode("utf-8", "replace")).hexdigest()[:12], "(source)"))
        for m in _GH_DOWNLOAD.finditer(run):  # curl/wget of a release asset: the tool is its repo at that version; the EXACT tag is kept as its label
            sums = sorted(set(re.findall(r"(?<!sha256:)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", run)))   # checksums, not image digests
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
                        out.append(Item("tool", "source:env:" + str(ek).lower() + "=" + hashlib.sha256(str(ev).encode("utf-8", "replace")).hexdigest()[:12], "(source)"))   # an env var that retargets a download
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
                    _walk(job, out, labels, "job:" + k)
                    if isinstance(job, dict) and isinstance(job.get("uses"), str) and job["uses"].startswith("./") and job.get("with"):
                        for it in out:                       # a local reusable-workflow call: what it passes in is part of that call's identity
                            if it.version == "(local)" and it.name == "local:" + _hide(job["uses"]) and not it.step:
                                it.step = "with:" + hashlib.sha256(json.dumps(job.get("with"), sort_keys=True, default=str).encode("utf-8", "replace")).hexdigest()[:10]
                _ENV_CTX[0] = ""
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
        elif path in VERSION_FILES:
            found = [Item("tool", "file:" + path, "(file)")]
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


def unmeasured(files):
    """{(file, form, command line): occurrences} for every install form in the workflows and scripts that this inventory does not measure, read after
    joining backslash continuations. Reported as information; a pull request that ADDS an entry (a new command line, even in place of another) is refused."""
    out = {}
    for path, text in sorted(files.items()):
        if not (path.startswith(".github/") or path.endswith(".sh")) or path.startswith(".github/agent/"):
            continue  # .github/agent/ is covered by the review-record gate (and its tests quote such commands as fixtures)
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
