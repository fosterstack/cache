#!/usr/bin/env python3
"""Every GitHub Action a workflow uses is pinned to a full commit digest with the version in a comment
(register row 78). A tag or branch reference fails. Fails closed: a file it cannot parse, or a
reference it cannot classify, is a finding.

It lives under .github/agent/ so that changing it needs the two-vendor review record
(auditor-review-gate.py): the enforcement cannot be loosened by an ordinary merge. The gate runs the
DEFAULT branch's copy over a PR head read as git objects (--git), never checked out.

What is read: every file under .github/workflows/ (a non-.yml/.yaml file there is itself a finding),
every other .yml/.yaml under .github/, and every action.yml/action.yaml (any case) anywhere. A
symlink or submodule among them is a finding, never followed. Each file is parsed as YAML (every
document, every scalar read as a string) and every node is walked, so flow style and quoting cannot
hide a key. YAML anchors and aliases are refused (an alias would carry one line's version comment to
another use; this repo uses none). A mapping key that is not a plain string, or that holds a ${{ }}
expression (GitHub folds `${{ 'uses' }}` into `uses`), is a finding. Values are judged exactly as
written — never trimmed — so a trailing non-breaking space (legal in a git tag name) cannot pass.

  uses:      owner/repo[/path]@<40 lowercase hex> followed on the same line, directly after the
             value, by `# v<version>`;
             ./.github/workflows/<file>.yml as a job's `uses` (a local reusable workflow: GitHub
             reads it from the commit, and it is checked here as a file of its own). A REMOTE
             reusable workflow is refused: its jobs would run actions this check never reads
             (this repo calls none; vendor one locally to use it);
             docker://<image>@sha256:<64 hex>.
             Nothing else: no tag, branch, short or uppercase SHA, ${{ }} expression, non-string, and
             no local action (./path at step level): its action.yml is read from the workspace at
             run time, where a script can rewrite it after this check has passed.
  services:  a mapping of plain identifiers (the runner passes the name unquoted to docker); each
             service is an image string or a mapping with an image.
  An action path with a `.`, `..` or empty segment is refused (it could reach another action).
  container:/service mappings may carry only image, credentials and env (plainly named variables):
             the runner splices `options`, `ports` and `volumes` unquoted into `docker create` ahead
             of the image, where any of them can name another image (this repo uses none).
  Every action must be CLASSIFIED (ACTIONS below, or EXECUTOR_ALLOWED): an action we have not
             classified may run an image we hand it through an input, so it fails closed until a
             reviewed change to this file says what it runs.
  docker://  steps, and classified Docker actions (DOCKER_ACTIONS), take no `entrypoint` or `args`
             input (the runner quotes them into the docker command unsafely) and only plain ASCII
             input names.
  Script-text inputs: an input an action executes as a command (github-script `script`,
             golangci-lint-action `args`, goreleaser-action `args`) is script text, the same class as
             a `run:` block — outside this check, covered by the review pass (see ACTIONS).
  Package-manager installs: `apt-get install` / `pip install` in a `run:` block (skopeo from the runner's
             signed Ubuntu archive, PyYAML for this checker) are distribution packages, not actions —
             outside this check, the same class as a binary installed by version; covered by the review
             pass (row 78 pass on PR #148, Oct 2: documented here rather than pinned).
  The gate's own wiring: .github/workflows/agent-review-gate.yml is pinned here by GATE_WORKFLOW_SHA256
             (its action pins masked, so a Dependabot bump still passes). Any other edit to it fails
             until this file is updated — a change under .github/agent/, so it needs the review record:
             the enforcement cannot be removed from its caller by an ordinary merge either.
  container: / image: / each service: <image>@sha256:<64 hex>, optionally docker://; never ${{ }}.
  Executor images: a pinned action that runs a container image of its own must be given that image
             by digest through its input (EXECUTOR_INPUTS) — a pinned action with a mutable default
             image is still a mutable reference. Action identity is case-folded (GitHub resolves
             owner/repo case-insensitively). Such an action's `with:` must be a mapping whose every
             input name is on EXECUTOR_ALLOWED, written exactly (so no Unicode, spacing or case
             variant can export to the same INPUT_ variable, and inputs like buildx `endpoint`,
             `append` or kind `config` that can re-set the image are refused); buildx runs only its
             default docker-container driver or the docker driver (kubernetes and remote bring
             images of their own, e.g. qemu.image); its driver-opts is read one option per line, as
             the action reads it — and each line as CSV, as buildx reads it, so exactly one image=
             may appear across them all — and its `append` (which can re-set a node's image) is refused.
             helm/kind-action: node_image, if given, by digest (unset, kind's own default for the
             pinned kind version is digest-pinned in the kind binary); `registry: true` needs a
             registry_image by digest (its default is registry:2); `config` (a kind config file can
             name node images) and `cloud_provider: true` (an extra component) are refused.
  Exempt by position only: the other inputs under a step's or a job's `with:` and the variables under
  a workflow's, job's or step's `env:` are data passed along (the image a scanner scans), not
  something the runner resolves as an action or a container.
  --verify-tags  each `# vX` comment must resolve, through the GitHub API, to the pinned commit.

The boundary: the owner's instruction of Sep 30 (handoff 0023), "no exceptions, anywhere", and "every finding
is a fix or a documented exclusion in the check's own allowlist with a reason". So this check pins every `uses:`,
every image a workflow or action names (container:, services:, image:, executor inputs), and every LITERAL image a
`run:` script runs or pulls (docker/podman run|create|pull, skopeo copy|inspect docker://, crane copy|pull),
and every package a `run:` script installs (handoff 0070): a Python install (pip, python -m pip, uv pip, a venv's
bin/pip) passes only when every package comes from a -r file checked with --require-hashes; pipx, uv tool, uvx,
npx and npm/yarn/pnpm/gem installs are always flagged (they cannot be held to hashes here). What
a pinned commit references on its own (e.g. the container image inside ossf/scorecard-action's action.yaml) is
fixed by our pin to that commit and is that action's supply chain, not ours; it is not read here, and no action
is excepted by name.

Outside this check, each a documented exclusion with its reason (row 78):
  - an image a `run:` script names through a shell variable or an expression: the shell is not evaluated here, so
    the row-78 review pass answers it (on Oct 2 every such image in the workflows is bound to a digest);
  - a name the same job made locally (docker tag / build -t / skopeo docker-daemon:, or a template like `fa-${v}`
    with a literal prefix of two or more characters): those are our own bytes, pinned where they were pulled;
  - `runs-on` labels: GitHub-hosted runner images are GitHub's to build and cannot be named by digest;
  - Go tools installed by module version (`go install …@vX.Y.Z`): the module proxy serves them checksum-verified
    against the Go checksum database, so a version names fixed bytes;
  - the Go toolchain `setup-go` selects with `check-latest`: deliberately the newest patch of the line go.mod
    names (the go-freshness lane), each download verified by the action; and binaries a pinned action downloads
    by version.

usage: check-action-pins.py [--verify-tags] [--git <commit>] [repo-root]
"""
import csv
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("check-action-pins: PyYAML is required")

SHA = r"[0-9a-f]{40}"
ACTION = re.compile(rf"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@({SHA})")
DIGEST = r"@sha256:[0-9a-f]{64}"
REF = r"[A-Za-z0-9][A-Za-z0-9._/:-]*"
DOCKER_USES = re.compile(rf"docker://{REF}{DIGEST}")
IMAGE = re.compile(rf"(docker://)?{REF}{DIGEST}")
LOCAL_WORKFLOW = re.compile(r"\./\.github/workflows/([A-Za-z0-9._-]+\.ya?ml)")
COMMENT = re.compile(r"[ \t]+#[ \t]*(v[0-9][0-9A-Za-z.+-]*)[ \t]*")
# every non-executor action this repo uses (owner/repo, lower case) -> why no input we pass it names
# an image it runs. Positively classified: an action missing here fails closed.
ACTIONS = {
    "actions/attest": "node: signs attestations; no image run",
    "actions/attest-build-provenance": "composite over actions/attest; no image run",
    "actions/checkout": "node: git checkout",
    "actions/create-github-app-token": "node: mints a token",
    "actions/dependency-review-action": "node: GitHub API diff review",
    "actions/download-artifact": "node: artifact download",
    "actions/github-script": "node: `script` is script text we write (the run: class; review pass)",
    "actions/setup-go": "node: installs the Go toolchain by version (a binary, outside this check)",
    "actions/setup-java": "node: installs a JDK by version (a binary, outside this check)",
    "actions/setup-python": "node: installs Python by version (a binary, outside this check)",
    "actions/upload-artifact": "node: artifact upload",
    "anchore/sbom-action": "node: syft catalogs an image as DATA (its `image` input is read, never run)",
    "anchore/scan-action": "node: grype scans an image as DATA (its `image` input is read, never run)",
    "aws-actions/configure-aws-credentials": "node: OIDC credentials",
    "dependabot/fetch-metadata": "node: PR metadata",
    "github/codeql-action": "node: CodeQL init/autobuild/analyze/upload-sarif",
    "golangci/golangci-lint-action": "node: installs golangci-lint by version (a binary); `args` reaches "
    "a shell — script text we write (the run: class; review pass)",
    "google-github-actions/auth": "node: Google workload identity federation (OIDC); no image run",
    "google-github-actions/setup-gcloud": "node: installs gcloud by version (a binary, outside this check)",
    "goreleaser/goreleaser-action": "node: installs goreleaser by version (a binary); `args` is command "
    "text we write (the run: class; review pass)",
    "ossf/scorecard-action": "docker: its own image, fixed inside the pinned commit (owner, Sep 30)",
    "sigstore/cosign-installer": "composite: installs cosign by version with checksum (a binary)",
}
# classified actions that are Docker actions: their step inputs follow the docker:// rules
DOCKER_ACTIONS = {"ossf/scorecard-action"}
GATE_WORKFLOW = ".github/workflows/agent-review-gate.yml"
GATE_WORKFLOW_SHA256 = "e2a5938e14aa50c3b1a14d04c0b6ef299d1d43117329476effd6486cdf652631"
# executor actions (owner/repo, lower case) -> the only input names they may be given (positively
# classified; anything else fails closed)
EXECUTOR_ALLOWED = {
    "docker/setup-qemu-action": {"image", "platforms"},
    "docker/setup-buildx-action": {"driver", "driver-opts", "name", "platforms", "use", "install",
                                   "version", "buildkitd-flags", "cleanup", "keep-state"},
    "helm/kind-action": {"version", "node_image", "cluster_name", "wait", "verbosity", "kubectl_version",
                         "registry", "registry_image", "registry_name", "registry_port",
                         "registry_enable_delete", "install_only", "ignore_failed_clean", "kubeconfig"},
}
# action (owner/repo, lower case) -> how it must be given its container image: (input, prefix)
EXECUTOR_INPUTS = {
    "docker/setup-qemu-action": ("image", ""),
    "docker/setup-buildx-action": ("driver-opts", "image="),
}


class StrLoader(yaml.SafeLoader):
    """Every plain scalar is a string; GitHub reads `uses: 1.0` as the string "1.0"."""


StrLoader.yaml_implicit_resolvers = {}


# ---------------------------------------------------------------------------- the tree read

class FsTree:
    def __init__(self, root):
        self.root = pathlib.Path(root).resolve()
        self.entries = {}  # rel -> "file" | "symlink"
        for d, dirs, names in os.walk(self.root, followlinks=False):
            rd = pathlib.Path(d).relative_to(self.root)
            for n in dirs + names:
                p = pathlib.Path(d) / n
                rel = (rd / n).as_posix()
                if p.is_symlink():
                    self.entries[rel] = "symlink"
                elif n in names:
                    self.entries[rel] = "file"
            # never descend into .git or through a symlinked directory
            dirs[:] = [x for x in dirs if x != ".git" and not (pathlib.Path(d) / x).is_symlink()]

    def read(self, rel):
        return (self.root / rel).read_text(encoding="utf-8", errors="replace")


class GitTree:
    """A commit's tree read as git objects: nothing is checked out, nothing is executed."""

    def __init__(self, commit):
        out = subprocess.run(["git", "ls-tree", "-r", "-z", "--full-tree", commit],
                             capture_output=True, check=True).stdout.decode("utf-8", "replace")
        self.entries, self.blobs = {}, {}
        for rec in filter(None, out.split("\0")):
            meta, path = rec.split("\t", 1)
            mode, kind, obj = meta.split()
            if mode == "120000":
                self.entries[path] = "symlink"
            elif kind == "commit":
                self.entries[path] = "submodule"
            else:
                self.entries[path] = "file"
                self.blobs[path] = obj

    def read(self, rel):
        return subprocess.run(["git", "cat-file", "blob", self.blobs[rel]], capture_output=True,
                              check=True).stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------------------- the walk

def data_block(path):
    """True when the path runs through a structural `with:` or `env:` (inputs/variables, not refs)."""
    for i, k in enumerate(path):
        if k not in ("with", "env"):
            continue
        if k == "env" and i == 0:
            return True  # workflow-level env
        if len(path) > 2 and path[0] == "jobs" and i == 2:
            return True  # jobs.<id>.with / jobs.<id>.env
        if i >= 2 and isinstance(path[i - 1], int) and path[i - 2] == "steps":
            return True  # steps[n].with / steps[n].env (workflow or composite action)
    return False


def position(p):
    """Where GitHub resolves an action or an image (workflow and action.yml schemas) — by structure,
    never by a key's spelling alone (a job may be named `image` or `with`)."""
    n, job = len(p), len(p) >= 3 and p[0] == "jobs"
    step = n == 5 and job and p[2] == "steps" and isinstance(p[3], int)
    action_step = n == 4 and p[:2] == ["runs", "steps"] and isinstance(p[2], int)
    return {
        "uses": (n == 3 and job) or step or action_step,
        "container": n == 3 and job,
        "services": n == 3 and job,
        "image": (n == 4 and job and p[2] == "container") or p == ["runs", "image"],
    }[p[-1]]


def show(path):
    return "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in path)


def key_of(k):
    return k.value.strip().lower() if isinstance(k, yaml.ScalarNode) else None


def walk(node, path, out, bad, where):
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if not isinstance(k, yaml.ScalarNode):
                bad.append(f"{where}{show(path)}: a mapping key that is not a plain string")
                continue
            if "${{" in k.value:
                bad.append(f"{where}{show(path)}: a mapping key holding an expression: {k.value!r}")
                continue
            key = key_of(k)
            p = path + [key]
            if key in ("uses", "image", "container", "services") and not data_block(p):
                if position(p):
                    out.append((key, p, v, node))
                elif key == "uses":
                    bad.append(f"{where}{show(p)}: uses at a position GitHub does not read as an action")
            walk(v, p, out, bad, where)
    elif isinstance(node, yaml.SequenceNode):
        for i, v in enumerate(node.value):
            walk(v, path + [i], out, bad, where)


# ---------------------------------------------------------------------------- the rules

def container_keys(where, node, bad):
    """A job container or service mapping: only image, credentials, and env with plain names."""
    for k, v in node.value:
        name = k.value if isinstance(k, yaml.ScalarNode) else None
        if name == "env" and isinstance(v, yaml.MappingNode):
            for kk, _ in v.value:
                if not (isinstance(kk, yaml.ScalarNode) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", kk.value)):
                    bad.append(f"{where}.env: a variable name that is not plain: {getattr(kk, 'value', None)!r}")
        elif name not in ("image", "credentials"):
            bad.append(f"{where}.{name}: refused (only image, credentials and env; the runner splices "
                       f"the rest into the docker command ahead of the image)")


def check_image(where, node, bad):
    if not isinstance(node, yaml.ScalarNode):
        return bad.append(f"{where}: image is not a plain string")
    v = node.value
    if "${{" in v:
        bad.append(f"{where}: image is an expression, not a pin: {v!r}")
    elif not IMAGE.fullmatch(v):
        bad.append(f"{where}: image not pinned by digest: {v!r}")


def executor_inputs(where, action, step, bad):
    """The executor action's inputs, or None (and a finding) when any is not positively classified."""
    withs = [w for k, w in (step.value if isinstance(step, yaml.MappingNode) else []) if key_of(k) == "with"]
    if any(not isinstance(w, yaml.MappingNode) for w in withs) or len(withs) > 1:
        bad.append(f"{where}: {action} `with:` must be one plain mapping")
        return None
    got, allowed = {}, EXECUTOR_ALLOWED[action]
    for k, v in withs[0].value if withs else []:
        name = k.value if isinstance(k, yaml.ScalarNode) else None
        if name not in allowed or name in got:
            bad.append(f"{where}: {action} input {name!r} is not one this check classifies (or is repeated)")
            return None
        got[name] = [v]
    return got


def check_kind(where, got, bad):
    def one(name):
        vals = got.get(name, [])
        return vals[0].value if len(vals) == 1 and isinstance(vals[0], yaml.ScalarNode) else None
    if "node_image" in got and not IMAGE.fullmatch(one("node_image") or ""):
        bad.append(f"{where}: helm/kind-action node_image not pinned by digest")
    if "registry" in got and (one("registry") or "").lower() != "false":
        if not IMAGE.fullmatch(one("registry_image") or ""):
            bad.append(f"{where}: helm/kind-action with a registry needs registry_image by digest")
    # `config` (a kind config file can name node images) and `cloud_provider` (a component of its own)
    # are not on EXECUTOR_ALLOWED, so executor_inputs() has already refused them


def check_executor(where, action, step, bad):
    action = action.lower()
    if action not in EXECUTOR_ALLOWED:
        return
    got = executor_inputs(where, action, step, bad)
    if got is None:
        return
    if action == "helm/kind-action":
        return check_kind(where, got, bad)
    inp, prefix = EXECUTOR_INPUTS[action]  # every other executor action names its image input here
    if action == "docker/setup-buildx-action":
        drivers = [v.value if isinstance(v, yaml.ScalarNode) else None for v in got.get("driver", [])]
        if drivers == ["docker"]:
            return  # the docker driver runs no BuildKit container of its own
        if drivers not in ([], ["docker-container"]):
            return bad.append(f"{where}: {action} driver {drivers[0]!r} is refused (only docker-container or docker)")
    ok = False
    vals = got.get(inp, [])
    if len(vals) == 1 and isinstance(vals[0], yaml.ScalarNode) and "${{" not in vals[0].value:
        if prefix:  # one option per line (the action's getInputList), each line CSV (buildx)
            lines = [o.strip() for o in vals[0].value.split("\n") if o.strip()]
            try:
                fields = [f.strip() for row in csv.reader(lines, strict=True) for f in row]
            except csv.Error:
                fields = None
            imgs = [f[len(prefix):] for f in fields or [] if f.lower().startswith(prefix)]
            ok = fields is not None and len(imgs) == 1 and IMAGE.fullmatch(imgs[0]) is not None
        else:
            ok = IMAGE.fullmatch(vals[0].value) is not None
    if not ok:
        bad.append(f"{where}: {action} runs a container image of its own; give it by digest "
                   f"in with.{inp}{' (' + prefix + '<image>@sha256:…, one per line)' if prefix else ''}")


def docker_inputs(where, step, bad):
    """A Docker action's inputs: plain ASCII names only, never entrypoint or args."""
    for k, w in step.value if isinstance(step, yaml.MappingNode) else []:
        if key_of(k) != "with":
            continue
        names = [kk.value if isinstance(kk, yaml.ScalarNode) else None
                 for kk, _ in (w.value if isinstance(w, yaml.MappingNode) else [(None, None)])]
        for n in names:
            if n is None or not re.fullmatch(r"[a-z0-9_-]+", n) or n in ("entrypoint", "args"):
                bad.append(f"{where}: Docker action input {n!r} is refused (entrypoint/args, or not a plain name)")


def gate_digest(text):
    """The gate workflow's sha256 with each action pin masked (a Dependabot bump moves only those)."""
    masked = re.sub(rf"@{SHA}[ \t]+#[ \t]*v[0-9][0-9A-Za-z.+-]*", "@<pin>", text)
    return hashlib.sha256(masked.encode("utf-8")).hexdigest()


def check_uses(tree, where, path, node, parent, lines, pins, bad):
    if not isinstance(node, yaml.ScalarNode):
        return bad.append(f"{where}: uses is not a plain string")
    v = node.value
    if "${{" in v:
        return bad.append(f"{where}: uses is an expression, not a pin: {v!r}")
    if v.startswith("./"):
        m = LOCAL_WORKFLOW.fullmatch(v)
        job_level = len(path) == 3 and path[0] == "jobs"
        if m and job_level and tree.entries.get(f".github/workflows/{m.group(1)}") == "file":
            return  # a local reusable workflow, read from the commit and checked as a file of its own
        return bad.append(f"{where}: local reference is not a job-level call of a workflow file in "
                          f".github/workflows/ (local actions are not allowed): {v!r}")
    m = ACTION.fullmatch(v)
    if m and any(seg in (".", "..", "") for seg in v.split("@")[0].split("/")):
        return bad.append(f"{where}: an action path with a `.`/`..`/empty segment is refused: {v!r}")
    ident = "/".join(v.split("@")[0].split("/")[:2]).lower() if m else ""
    if m and ident not in ACTIONS and ident not in EXECUTOR_ALLOWED and not (len(path) == 3 and path[0] == "jobs"):
        bad.append(f"{where}: {ident} is not a classified action (add it to ACTIONS with what it runs, "
                   f"or to EXECUTOR_ALLOWED): {v!r}")
    if m and len(path) == 3 and path[0] == "jobs":
        return bad.append(f"{where}: a remote reusable workflow is refused (its jobs run actions this check "
                          f"never reads; vendor it under .github/workflows/): {v!r}")
    if m:
        sha = m.group(2)
        tag = None
        if node.start_mark.line == node.end_mark.line and node.end_mark.line < len(lines):
            c = COMMENT.fullmatch(lines[node.end_mark.line][node.end_mark.column:])
            tag = c.group(1) if c else None
        if tag is None:
            bad.append(f"{where}: {v!r} is not followed directly by a `# vX` comment on its line")
        else:
            pins.append((where, v.rsplit("@", 1)[0], sha, tag))
        if ident in DOCKER_ACTIONS:
            docker_inputs(where, parent, bad)
        check_executor(where, "/".join(v.split("@")[0].split("/")[:2]), parent, bad)
        return
    if DOCKER_USES.fullmatch(v):
        return docker_inputs(where, parent, bad)
    bad.append(f"{where}: not a full commit digest: {v!r}")


def verify_pins(pins):
    """--verify-tags: each `# vX` comment names the pinned commit."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        return ["--verify-tags: GH_TOKEN is not set"]
    found, tags = [], {}

    def api(path):
        req = urllib.request.Request(f"https://api.github.com/{path}",
                                     headers={"Authorization": f"Bearer {token}",
                                              "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    for where, repo, sha, tag in pins:
        slug = "/".join(repo.split("/")[:2])
        if (slug, tag) not in tags:
            try:
                ref = api(f"repos/{slug}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
                if ref.get("ref") != f"refs/tags/{tag}":  # the API answered for a different ref
                    raise LookupError(ref.get("ref"))
                obj = ref["object"]
                while obj["type"] == "tag":  # annotated tag -> its commit
                    obj = api(f"repos/{slug}/git/tags/{obj['sha']}")["object"]
                tags[(slug, tag)] = obj["sha"]
            except Exception as e:  # fail closed
                tags[(slug, tag)] = f"unresolvable ({e.__class__.__name__})"
        if tags[(slug, tag)] != sha:
            found.append(f"{where}: {slug} {tag} is {tags[(slug, tag)]}, not the pinned {sha}")
    return found


# ---------------------------------------------------------------------------- images a run: script names
# (handoff 0068; owner Sep 30, handoff 0023: "no exceptions, anywhere"). A LITERAL image a script runs or pulls must
# be a digest. Not flagged: an argument holding a shell variable or an expression (the review pass covers those), a
# local name the same job made (docker tag / build -t / skopeo docker-daemon:), or a digest reference.
DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}$")
# docker run/create options that take NO value; every other option takes one (fails closed: a value-less option
# not listed here would swallow the image and leave the next token judged as the image)
DOCKER_BOOL = {"-d", "--detach", "--rm", "-i", "--interactive", "-t", "--tty", "-it", "-ti", "-dit", "-itd", "-di",
               "-dt", "-td", "--privileged", "--init", "--read-only", "-P", "--publish-all", "--no-healthcheck",
               "--oom-kill-disable", "--sig-proxy", "--disable-content-trust", "-q", "--quiet", "-a", "--all-tags"}
PULL_ONLY_BOOL = {"-a", "--all-tags"}
TOOLS = {"docker", "podman", "skopeo", "crane"}
# package installers (handoff 0070): matched by the command word's basename, so a venv path (…/bin/pip) counts
PKG_TOOL = re.compile(r"^(pip3?(\.[0-9]+)?|python3?(\.[0-9]+)?|pipx|uv|uvx|npm|npx|gem|yarn|pnpm)$")
SHELLS = {"bash", "sh", "dash", "zsh"}
PRINTERS = {"echo", "printf", ":"}  # commands that only print their arguments
SEPARATORS = re.compile(r"&&|\|\||[;|&\n`]|\$\(|\)")


def _base(word):
    return word.rsplit("/", 1)[-1]


def _commands(script, depth=0):
    """The simple commands of a shell script, each a token list (quotes removed, comments dropped), starting at the
    first tool word; a `bash -c "…"` / `sh -c` / `eval "…"` argument is read as a script of its own."""
    import shlex
    text = re.sub(r"\\\n", " ", script)
    out = []
    for chunk in SEPARATORS.split(text):
        try:
            toks = shlex.split(chunk, comments=True)
        except ValueError:
            toks = chunk.split()
        if not toks or toks[0] in PRINTERS:
            continue
        if depth < 4:
            for i, w in enumerate(toks):
                if _base(w) in SHELLS and "-c" in toks[i + 1:]:
                    j = toks.index("-c", i + 1)
                    if j + 1 < len(toks):
                        out += _commands(toks[j + 1], depth + 1)
                    break
                if w == "eval" and toks[i + 1:]:
                    out += _commands(" ".join(toks[i + 1:]), depth + 1)
                    break
        # the tool word anywhere in the command (`if docker …`, `timeout 30 docker …`, `xargs docker …`): fail closed
        at = next((i for i, w in enumerate(toks) if _base(w) in TOOLS or PKG_TOOL.match(_base(w))), None)
        if at is not None:
            out.append([_base(toks[at])] + toks[at + 1:])
    return out


def _pip_install(args):
    """True when a pip install's every package comes from a -r file checked with --require-hashes."""
    reqs, specs, i = 0, 0, 0
    while i < len(args):
        a = args[i]
        if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)", a):     # a redirection (<<'EOF', 2>/dev/null, > f)
            i += 1 if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)[^<>]", a) else 2
            continue
        if a in ("-r", "--requirement"):
            reqs, i = reqs + 1, i + 2
            continue
        if a.startswith(("--requirement=", "-r=")) or (a.startswith("-r") and len(a) > 2 and not a.startswith("--")):
            reqs += 1
        elif a in ("-e", "--editable"):
            specs, i = specs + 1, i + 2
            continue
        elif a in ("-c", "--constraint", "-t", "--target", "--prefix", "--root", "-i", "--index-url",
                   "--extra-index-url", "-f", "--find-links", "--platform", "--python-version", "--implementation",
                   "--abi", "--src", "--report", "--progress-bar", "--only-binary", "--no-binary", "--log",
                   "--cache-dir", "--proxy", "--timeout", "--retries", "--trusted-host", "--cert", "--client-cert",
                   "--root-user-action", "--upgrade-strategy", "--python", "--exists-action", "--keyring-provider"):
            i += 2
            continue
        elif not a.startswith("-"):
            specs += 1
        i += 1
    return "--require-hashes" in args and reqs > 0 and specs == 0


def script_installs(script):
    """(command, why) for every package install the script makes that is not hash-pinned (handoff 0070)."""
    found = []
    for t in _commands(script):
        cmd, args = t[0], t[1:]
        if re.match(r"^python3?(\.[0-9]+)?$", cmd):
            if "-m" not in args or args.index("-m") + 1 >= len(args) or args[args.index("-m") + 1] != "pip":
                continue
            cmd, args = "python -m pip", args[args.index("-m") + 2:]
        if cmd == "uv" and args[:1] == ["pip"]:
            cmd, args = "uv pip", args[1:]
        if re.match(r"^pip3?(\.[0-9]+)?$", cmd) or cmd in ("python -m pip", "uv pip"):
            if "install" in args:
                rest = args[args.index("install") + 1:]
                if not _pip_install(rest):
                    found.append((cmd + " install", "not every package from a -r file checked with --require-hashes"))
        elif cmd == "pipx" and args[:1] and args[0] in ("install", "run", "inject", "upgrade", "reinstall"):
            found.append(("pipx " + args[0], "pipx cannot check hashes"))
        elif cmd == "uv" and args[:1] == ["tool"] and args[1:2] and args[1] in ("install", "run", "upgrade"):
            found.append(("uv tool " + args[1], "uv tool cannot check hashes"))
        elif cmd in ("uvx", "npx"):
            found.append((cmd, "runs a package fetched by name"))
        elif cmd in ("npm", "yarn", "pnpm", "gem") and args[:1] and args[0] in ("install", "i", "ci", "add", "update", "exec", "dlx"):
            found.append((cmd + " " + args[0], "a %s package install (none is reviewed for hashes here)" % cmd))
        elif cmd in ("yarn", "pnpm") and not args:
            found.append((cmd, "a %s package install" % cmd))
    return found


def _variable(tok):
    return "$" in tok or "${{" in tok


def _first_positional(args, bool_opts):
    i = 0
    while i < len(args):
        a = args[i]
        if _variable(a) and a.startswith("$"):
            return a  # a variable here may be options or the image: the review pass (documented boundary)
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("-"):
            i += 1 if ("=" in a or a in bool_opts) else 2
            continue
        return a
    return None


def script_images(script):
    """(command, image) for every image the script runs or pulls, and the local names it makes."""
    used, local = [], set()
    for t in _commands(script):
        cmd, args = t[0], t[1:]
        if cmd in ("docker", "podman") and args:
            verb, rest = args[0], args[1:]
            if verb in ("container", "image") and rest:
                verb, rest = rest[0], rest[1:]
            if verb in ("run", "create"):
                used.append(("docker " + verb, _first_positional(rest, DOCKER_BOOL - PULL_ONLY_BOOL)))
            elif verb == "pull":
                used.append(("docker pull", _first_positional(rest, DOCKER_BOOL)))
            elif verb == "tag" and len(rest) >= 2:
                local.add(rest[-1])
            elif verb in ("build", "buildx"):
                for i, a in enumerate(rest):
                    if a in ("-t", "--tag") and i + 1 < len(rest):
                        local.add(rest[i + 1])
                    elif a.startswith(("--tag=", "-t=")):
                        local.add(a.split("=", 1)[1])
        elif cmd == "skopeo" and args and args[0] in ("copy", "inspect"):
            pos = [a for a in args[1:] if not a.startswith("-")]
            if pos and pos[0].startswith("docker://"):
                used.append(("skopeo " + args[0], pos[0][len("docker://"):]))
            for a in pos[1:]:
                if a.startswith("docker-daemon:"):
                    local.add(a[len("docker-daemon:"):])
        elif cmd == "crane" and args and args[0] in ("copy", "cp", "pull", "export"):
            pos = [a for a in args[1:] if not a.startswith("-")]
            if pos:
                used.append(("crane " + args[0], pos[0]))
    return used, local


def _local(ref, local):
    """A name the job made: exactly, as name:latest, or by a template (`fa-${v}`) with a literal prefix of at least
    two characters before its first variable (a bare `${x}` would cover any image, so it covers none)."""
    if ref in local or (":" not in ref.rsplit("/", 1)[-1] and ref + ":latest" in local):
        return True
    for name in local:
        if "$" in name:
            prefix = name.split("$", 1)[0]
            if len(prefix) >= 2 and re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9._-]+", ref):
                return True
    return False


def check_runs(where_job, scripts, bad):
    """scripts: [(where, text)] of ONE job (or one composite action); a local name counts only within it."""
    found, local = [], set()
    for where, text in scripts:
        used, made = script_images(text)
        local |= made
        found += [(where, c, img) for c, img in used]
    for where, c, img in found:
        if img is None or _variable(img) or DIGEST_REF.search(img) or _local(img, local):
            continue
        bad.append(f"{where}: `{c}` names an image not pinned by digest: {img!r}")
    for where, text in scripts:
        for c, why in script_installs(text):
            bad.append(f"{where}: `{c}`: {why}")


def run_scripts(doc):
    """{job or composite: [(path, run text)]} for every step run: GitHub executes."""
    groups = {}
    if not isinstance(doc, yaml.MappingNode):
        return groups
    top = {key_of(k): v for k, v in doc.value}

    def steps_of(seq, base, group):
        if isinstance(seq, yaml.SequenceNode):
            for i, st in enumerate(seq.value):
                if isinstance(st, yaml.MappingNode):
                    for k, v in st.value:
                        if key_of(k) == "run" and isinstance(v, yaml.ScalarNode):
                            groups.setdefault(group, []).append((f"{base}[{i}].run", v.value))
    jobs = top.get("jobs")
    if isinstance(jobs, yaml.MappingNode):
        for k, j in jobs.value:
            if isinstance(j, yaml.MappingNode):
                for kk, vv in j.value:
                    if key_of(kk) == "steps":
                        steps_of(vv, f".jobs.{k.value}.steps", "jobs." + k.value)
    runs = top.get("runs")
    if isinstance(runs, yaml.MappingNode):
        for kk, vv in runs.value:
            if key_of(kk) == "steps":
                steps_of(vv, ".runs.steps", "runs")
    return groups


def check_file(tree, rel, pins, bad):
    text = tree.read(rel)
    lines = text.splitlines()
    try:
        if any(isinstance(e, yaml.AliasEvent) or getattr(e, "anchor", None)
               for e in yaml.parse(text, Loader=StrLoader)):
            return bad.append(f"{rel}: uses a YAML anchor or alias")
        docs = list(yaml.compose_all(text, Loader=StrLoader))
    except yaml.YAMLError as e:
        return bad.append(f"{rel}: does not parse as YAML ({e.__class__.__name__})")
    refs = []
    for i, d in enumerate(docs):
        if d is not None:
            walk(d, [], refs, bad, rel + (f"[doc{i}]" if len(docs) > 1 else ""))
            for group, scripts in run_scripts(d).items():
                check_runs(group, [(rel + w, t) for w, t in scripts], bad)
    for key, path, node, parent in refs:
        where = f"{rel}{show(path)}"
        if key == "uses":
            check_uses(tree, where, path, node, parent, lines, pins, bad)
        elif key == "container":
            if not isinstance(node, yaml.MappingNode):
                check_image(where, node, bad)
            else:
                if not any(key_of(k) == "image" for k, _ in node.value):
                    bad.append(f"{where}: container mapping without an image")  # its image: is checked by position
                container_keys(where, node, bad)
        elif key == "services":
            if not isinstance(node, yaml.MappingNode):
                bad.append(f"{where}: services is not a mapping")
                continue
            for k, v in node.value:
                sw = f"{where}.{getattr(k, 'value', '?')}"
                if not (isinstance(k, yaml.ScalarNode) and re.fullmatch(r"[A-Za-z0-9_-]+", k.value)):
                    bad.append(f"{sw}: a service name that is not a plain identifier (the runner "
                               f"passes it unquoted to docker)")
                if isinstance(v, yaml.MappingNode):
                    imgs = [vv for kk, vv in v.value if key_of(kk) == "image"]
                    if not imgs:
                        bad.append(f"{sw}: service without an image")
                    container_keys(sw, v, bad)
                    for vv in imgs:
                        check_image(f"{sw}.image", vv, bad)
                else:
                    check_image(sw, v, bad)
        elif key == "image":
            check_image(where, node, bad)


def main():
    argv = sys.argv[1:]
    verify = "--verify-tags" in argv
    argv = [a for a in argv if a != "--verify-tags"]
    if argv[:1] == ["--git"]:
        if len(argv) != 2:
            sys.exit("usage: check-action-pins.py [--verify-tags] --git <commit>")
        tree = GitTree(argv[1])
    else:
        tree = FsTree(argv[0] if argv else ".")
    if not any(r.startswith(".github/workflows/") for r in tree.entries):
        sys.exit("check-action-pins: no .github/workflows/ — nothing checked")
    bad, pins, files = [], [], []
    for rel, kind in sorted(tree.entries.items()):
        parts = rel.split("/")
        in_wf = parts[:2] == [".github", "workflows"]
        name = parts[-1]
        wanted = in_wf or name.lower() in ("action.yml", "action.yaml") or \
            (parts[0] == ".github" and name.lower().endswith((".yml", ".yaml")))
        if not wanted:
            continue
        if kind != "file":
            bad.append(f"{rel}: a {kind} where a workflow or action file is read (not followed)")
        elif in_wf and not name.endswith((".yml", ".yaml")):
            bad.append(f"{rel}: a file under .github/workflows/ that is not .yml/.yaml")
        else:
            files.append(rel)

    for rel in files:
        check_file(tree, rel, pins, bad)
    if GATE_WORKFLOW not in files:
        bad.append(f"{GATE_WORKFLOW}: missing — the gate that runs this check")
    elif gate_digest(tree.read(GATE_WORKFLOW)) != GATE_WORKFLOW_SHA256:
        bad.append(f"{GATE_WORKFLOW}: changed — update GATE_WORKFLOW_SHA256 in this checker "
                   f"(a reviewed .github/agent/ change) to {gate_digest(tree.read(GATE_WORKFLOW))}")
    if verify:
        bad += verify_pins(pins)
    for b in bad:
        print(b)
    print(f"check-action-pins: {len(files)} YAML file(s), {len(pins)} pinned action(s)"
          f"{' verified against their tags' if verify else ''}, {len(bad)} finding(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
