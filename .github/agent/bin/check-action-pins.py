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

Scope (advisor 0080): ubuntu runners only. Every job that runs steps must name an ubuntu runner literally
(ubuntu-latest, ubuntu-<version>, ubuntu-<version>-arm); any other runs-on — Windows, macOS, self-hosted labels, a
group, an expression, none — is a finding, so a bypass that needs another runner OS is closed by that refusal. Inside
the scope, anything the parser cannot fully resolve fails closed (forwarded arguments, substitutions, unknown options,
a program name built by a substitution — d$()ocker). A program named only through a shell variable ("$gosec") is
outside the check today: the repository uses it (ci.yml, go-freshness.yml), so failing it closed is an outbox question.

The boundary: the owner's instruction of Sep 30 (handoff 0023), "no exceptions, anywhere", and "every finding
is a fix or a documented exclusion in the check's own allowlist with a reason". So this check pins every `uses:`,
every image a workflow or action names (container:, services:, image:, executor inputs), and every LITERAL image a
`run:` script runs or pulls (docker/podman run|create|pull, skopeo copy|inspect docker://, crane copy|pull),
and every package a `run:` script installs (handoff 0070): a Python install (pip, python -m pip, uv pip, a venv's
bin/pip) passes only when every package comes from a -r file checked with --require-hashes; pipx, uv tool, uvx,
npx and npm/yarn/pnpm/gem installs are always flagged (they cannot be held to hashes here). Fail-closed edges
(Sonnet #164 r1): an option this check does not know, before the verb or the image, is a finding (it cannot tell which
word is the image); docker compose / docker-compose / buildx bake / stack are findings (their files name images this
check does not read); a build's Dockerfile — a literal path, or a template like Dockerfile.${v} matched against the
tree — must exist in the repository and every FROM be a digest, scratch or an earlier stage (stdin or a generated
Dockerfile is a finding); an image name this job built or tagged is NOT trusted (r23: reference a build by its image id or a digest); a step in a non-POSIX shell that names
a container or package tool is a finding (this check reads POSIX shell only). Round 2 (Sonnet #164): a tool
given forwarded arguments ("$@", $*) or a variable verb is a finding; copying, linking or aliasing a tool binary under
another name is a finding; pip download/wheel follow the install rule; conda/mamba/micromamba installs are flagged;
docker manifest create and buildx imagetools create sources must be digests. After round 3: nerdctl is read as docker;
buildah, ctr, crictl, apptainer, singularity and kaniko are findings on use (not read); uv add/sync/lock/run, pipenv,
poetry, pdm, hatch, flit, pip-sync, pip-compile, rye, python setup.py and python -m build are findings (not holdable to
hashes); uv pip sync follows the install rule. Round 4: a command substitution ($(…), `…`) is cut out and read
as its own script, and where it stands for an image or package it is a finding; a build's Dockerfile must be the
exact repository path (or every file matching its template) — an absolute path, a substituted name, or a file the
script itself writes under that name is a finding. Round 5: "writes" is an allow-list, not a blocklist — any
command naming a build's Dockerfile or a pip -r file is a finding unless it is the consuming build/install, a
read-only command without a write redirection, or a copy of the committed file into a context (relative sources,
destination not named); a pip -r file must be an exact repository file or a heredoc on stdin in the same step.
Round 6: that judgment covers every POSIX step of the job (steps share a workspace), and a shell keyword or a loop's
word list is not a write. Across jobs (a fresh runner each), a file passed through an artifact is the review pass's.
Round 16 (NEW-24): without -f the Dockerfile is <context>/Dockerfile; a literal Dockerfile path read after a cd/pushd or
under a working-directory (step, job or workflow) cannot be placed in the repository and is refused (templates match
every file of their pattern, as before).
Round 15 (NEW-23): a build's context and every --build-context must be a local path; a URL, git address, variable or
substitution builds from bytes this check never sees and is refused.
Round 14 (NEW-21/22; SUPERSEDED in r23: no built or tagged name is trusted any more): a name counts as the job's own only when it is built (docker build, its FROM lines checked),
tagged from a digest-pinned, local or variable source, or copied into the daemon from a digest-pinned docker:// source;
a loaded tarball's image ID or an archive copied into the daemon may be scanned, but tagging or running it is a finding.
Round 13 (NEW-16..20): nothing may point docker or buildx at another daemon or context — -H/--host, -c/--context and
--config are refused, and so are DOCKER_HOST, DOCKER_CONTEXT, BUILDKIT_HOST and any DOCKER_CONFIG but a fresh
$(mktemp -d), in scripts or env blocks; plugin, context, import, system, trust, secret, config and buildx create/use
are off the reviewed list (refused).
Round 12 (NEW-14/15): every verb of docker/podman/nerdctl, skopeo and crane is either read (run/create/pull/build/
scout/…), on a reviewed list of verbs that pull or run nothing remote, or refused (podman kube play, skopeo sync, crane
append/mutate, …). Tool words match by exact case (the scope is ubuntu runners, where `Docker` is not found); PATH
lookups (command -v, which, type) are not runs.
Round 10 (NEW-12): a step in any non-POSIX shell (pwsh, python, node, …; pwsh ships on ubuntu runners too) is refused
outright, whatever it contains — this check reads POSIX shell only.
Round 8 (before the ubuntu-only scope made it moot; kept as defense in depth): choco, winget, scoop and brew installs are findings; tool words and their verbs match case-insensitively
(Windows resolves `Docker RUN`); a job on a Windows runner, or one named by an expression, defaults to pwsh (the
non-POSIX catch-all) unless it declares a POSIX shell. What
static reading cannot see is the
review pass's (documented boundary): a tool named only through a shell variable, a tool binary fetched from the
network under another name, and OS packages the runner installs from its signed distribution archives (apt). An
image a pinned action's own manifest names is NOT fixed by our pin (Codex #164 adversarial r1, R01; closed in our
own tree r1 B1/0140 by invoking the executor directly, `docker://<image>@sha256:…`, which this check's own DIGEST
rule then covers): the commit fixes the manifest's text, not a registry tag's resolution — ossf/scorecard-action's
pinned action.yaml runs docker://ghcr.io/ossf/scorecard-action:v2.4.4, a mutable tag, if used in its composite form.
That executor is the upstream's supply chain; it is listed here so it is not mistaken for pinned, and no action is
excepted by name.

Scripts a step runs (Codex #164 adversarial r1 C02; advisor ruling 0094): a committed shell script (bash/sh x.sh,
source x.sh, ./x.sh, a $RUNNER_TEMP copy of main's committed script) is read at its committed bytes, recursively; a
script that is not a committed file, a variable script path, or nesting past the depth limit is refused. Inline code
for another interpreter (python -c, node -e, perl -e, ruby -e, …) is refused. Code in another language in a heredoc
or a committed file is the documented boundary: not parsed; every diff that adds or changes it gets both reviewers,
whose row-78 pass asks whether any non-shell code fetches an image or package without a digest or hash.

Outside this check, each a documented exclusion with its reason (row 78):
  - an image a `run:` script names through a shell variable or an expression: the shell is not evaluated here, so
    the row-78 review pass answers it (on Oct 2 every such image in the workflows is bound to a digest);
  - (REMOVED in r23, owner Oct 3 "a simple parse"; advisor 0080: nineteen rounds of review kept finding one more way a hand-written
    tracker of "a name the job made earlier is ours" was wrong, and no real workflow relied on it) an image name the job built or
    tagged is NOT trusted: a `docker run` names a digest, or a variable holding one, such as the image id a build wrote with
    --iidfile; the build itself (FROM lines, context, Dockerfile) is still fully checked;
  - a committed TEST HARNESS a step runs (tests/, *-test.sh): its probes are the very constructs this check refuses,
    as fixture data; it is not read recursively (it is committed and reviewed like any diff);
  - /tmp/smoke-assert.sh in stage-acceptance-k8s.yml: the documented smoke commands of docs/kubernetes.md
    (committed, reviewed), written by the step's own python heredoc; they assert against the kind cluster;
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
    "ossf/scorecard-action": "retired (advisor 0140): the composite wrapper's own action.yaml ran its executor image "
                             "by a mutable tag, never fixed by a commit pin on the wrapper; refused outright below — "
                             "use docker://ghcr.io/ossf/scorecard-action@<digest> directly instead",
    "sigstore/cosign-installer": "composite: installs cosign by version with checksum (a binary)",
}
# classified actions that are Docker actions: their step inputs follow the docker:// rules
DOCKER_ACTIONS = {"ossf/scorecard-action"}
RETIRED_COMPOSITE = {"ossf/scorecard-action"}   # refused outright (advisor 0140); DOCKER_ACTIONS kept for docstring/test
                                                 # continuity, never reached since RETIRED_COMPOSITE returns first
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
    if m and ident in RETIRED_COMPOSITE:
        return bad.append(f"{where}: {ident} is retired (advisor 0140) — its composite wrapper ran a mutable "
                          f"executor image no commit pin fixes; invoke docker://<its image>@<digest> directly: {v!r}")
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
# digest reference. An image name the job built or tagged itself is NOT trusted (r23, owner Oct 3: every image is pinned by digest; run a build by its image id).
DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}$")
# docker options (Sonnet #164 r1, B2/B4): every option before the image must be KNOWN — a long or short form that
# takes a value (attached `--x=v` / `-pV`, or the next word), or one that takes none (short ones may combine: -dit).
# An unknown option fails closed: this check cannot tell which word is the image, so it is a finding.
# no -H/--host, -c/--context or --config: they point docker at another daemon (Sonnet #164 r13, NEW-18) — unknown, refused
DOCKER_GLOBAL_VAL = {"-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey"}
DOCKER_GLOBAL_BOOL = {"-D", "--debug", "--tls", "--tlsverify"}
RUN_VAL = {"--add-host", "--annotation", "-a", "--attach", "--blkio-weight", "--blkio-weight-device", "--cap-add",
           "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-rt-period",
           "--cpu-rt-runtime", "-c", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--detach-keys",
           "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops", "--device-write-bps",
           "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname", "--entrypoint", "-e", "--env",
           "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval", "--health-retries",
           "--health-start-interval", "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6",
           "--ipc", "--isolation", "--kernel-memory", "-l", "--label", "--label-file", "--link", "--link-local-ip",
           "--log-driver", "--log-opt", "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap",
           "--memory-swappiness", "--mount", "--name", "--network", "--net", "--network-alias", "--net-alias",
           "--oom-score-adj", "--pid", "--pids-limit", "--platform", "-p", "--publish", "--pull", "--restart",
           "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl",
           "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts", "-v", "--volume", "--volume-driver",
           "--volumes-from", "-w", "--workdir"}
RUN_BOOL = {"-d", "--detach", "--disable-content-trust", "--init", "-i", "--interactive", "--no-healthcheck",
            "--oom-kill-disable", "--privileged", "-P", "--publish-all", "-q", "--quiet", "--read-only", "--rm",
            "--sig-proxy", "-t", "--tty"}
PULL_VAL = {"--platform"}
PULL_BOOL = {"-a", "--all-tags", "--disable-content-trust", "-q", "--quiet"}
TOOLS = {"docker", "podman", "nerdctl", "skopeo", "crane", "docker-compose", "podman-compose",
         "buildah", "ctr", "crictl", "apptainer", "singularity", "kaniko", "executor"}
# container CLIs this check does not parse (Sonnet #164 r3): any use is a finding — run images through docker,
# podman, nerdctl, skopeo or crane, whose arguments are read
UNREAD_CONTAINER = {"buildah", "ctr", "crictl", "apptainer", "singularity", "kaniko", "executor"}
PRINTERS = {"echo", "printf", ":"}  # commands that only print their arguments
# package installers (handoff 0070): matched by the command word's basename, so a venv path (…/bin/pip) counts
PKG_TOOL = re.compile(r"^(pip3?(\.[0-9]+)?|python3?(\.[0-9]+)?|pipx|uv|uvx|npm|npx|gem|yarn|pnpm|bun|conda|mamba|micromamba"
                      r"|pipenv|poetry|pdm|hatch|flit|pip-sync|pip-compile|rye|choco|winget|scoop|brew)$")
# Python installers / build frontends that cannot be held to hashes here (Sonnet #164 r3): any use is a finding
UNREAD_PY = {"pipenv", "poetry", "pdm", "hatch", "flit", "pip-sync", "pip-compile", "rye"}
# OS package managers of Windows / macOS runners (Sonnet #164 r8, NEW-9): installs cannot be held to hashes here
OS_PKG = {"choco", "winget", "scoop", "brew"}
# Package managers this repository does not use: ANY invocation is refused — their many verb aliases and option forms
# (npm in, npm --prefix x install, uv --no-cache pip install, pipx --verbose install) cannot be read reliably (Codex #164
# adversarial r1, C04). pip, through `python -m pip` or pip itself, is read by a strict parser instead.
REFUSED_PKG = {"pipx", "uv", "uvx", "npm", "npx", "gem", "yarn", "pnpm", "bun", "conda", "mamba", "micromamba"}
# pip install / download / wheel options (pip 24-26): the ones that take a value, and the flags. Any other option is
# refused, and --require-hashes counts only as a flag of its own, never as another option's value (C05).
PIP_VAL = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-t", "--target", "-d", "--dest", "-w",
           "--wheel-dir", "--prefix", "--root", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
           "--platform", "--python-version", "--implementation", "--abi", "--src", "--report", "--progress-bar",
           "--only-binary", "--no-binary", "--log", "--log-file", "--cache-dir", "--proxy", "--timeout", "--retries",
           "--trusted-host", "--cert", "--client-cert", "--root-user-action", "--upgrade-strategy", "--python",
           "--exists-action", "--keyring-provider", "--config-settings", "-C", "--global-option", "--use-feature",
           "--use-deprecated", "--resume-retries", "--group"}
PIP_BOOL = {"-q", "--quiet", "-v", "--verbose", "--dry-run", "-I", "--ignore-installed", "--break-system-packages",
            "--no-deps", "-U", "--upgrade", "--force-reinstall", "--user", "--no-cache-dir", "--disable-pip-version-check",
            "--no-input", "--isolated", "--pre", "--no-build-isolation", "--no-warn-script-location", "--compile",
            "--no-compile", "--prefer-binary", "--require-virtualenv", "--no-color", "--no-python-version-warning",
            "--no-index", "--require-hashes", "--ignore-requires-python", "--no-clean", "--no-warn-conflicts",
            "--check-build-dependencies", "--ignore-installed", "--no-deps", "--quiet", "-qq", "-qqq", "-vv", "-vvv"}
# pip's global options (before the subcommand): a value option's value is never the subcommand (Codex r2, C05)
PIP_GLOBAL_VAL = {"--log", "--log-file", "--cache-dir", "--proxy", "--timeout", "--retries", "--cert", "--client-cert",
                  "--exists-action", "--trusted-host", "--python", "--keyring-provider", "--use-feature",
                  "--use-deprecated", "--resume-retries", "--local-log"}
PIP_GLOBAL_BOOL = {"-q", "--quiet", "-v", "--verbose", "-qq", "-qqq", "-vv", "-vvv", "--isolated", "--no-input",
                   "--no-color", "--disable-pip-version-check", "--no-cache-dir", "--require-virtualenv",
                   "--no-python-version-warning", "--debug", "-h", "--help", "-V", "--version"}
PIP_READ = {"list", "freeze", "show", "check", "hash", "inspect", "help", "--version", "-V", "cache", "uninstall", "debug"}
FORWARD = {"$@", "$*", "${@}", "${*}"}   # a wrapper forwarding its own arguments (Sonnet #164 r2, N1)
TOOL_WORDS = r"(docker|podman|skopeo|crane|pip3?|pipx|uvx?|npm|npx|gem|yarn|pnpm|conda|mamba|micromamba|python3?)"
# a tool binary copied, linked or aliased under another name (N2): the renamed command is invisible to name matching
RENAMED = re.compile(r"(?m)(^|[;&|(\s])(cp|ln|install|mv|rsync)\s[^\n;&|]*?(\$\((command\s+-v|which|type\s+-p)\s+[\"']?"
                     + TOOL_WORDS + r"[\"']?\)|/" + TOOL_WORDS + r"(?=[\s\"']|$))"
                     r"|(^|[;&|\s])alias\s+[A-Za-z0-9_.-]+=[\"']?" + TOOL_WORDS + r"\b")
# Raw-text detectors read the script with every quote and backslash removed: d""ocker, c""d and c\\d are the words bash
# runs (Sonnet #164 r18, NEW-27/28). Aliases hide a command from any static reading: refused outright (nothing in this
# repository uses one). ANSI-C quoting may carry only \n, \t and \r (the repository's $'\t' and $'\n'); any other escape
# ($'\x64ocker', octal, \u) can spell any word and is refused (fail closed)
ALIASING = re.compile(r"(?<![\w.-])(alias|expand_aliases)(?![\w.-])")


# A parameter expansion with a default, assign or alternate word (${x:-docker}, ${x-docker}, ${x:=docker}, ${x:+docker},
# nested) can run that literal word: every check reads it as the word (Sonnet #164 r19, NEW-29, fail closed). ${x:?word}
# too: bash expands the word, and any substitution in it runs, before it reports the error (Codex #164 adversarial r1,
# C03). A bare $x / ${x} stays the documented variable boundary.
PARAM_WORD = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*])(:?)([-=+?])([^{}]*)\}")


def _expand_defaults(text):
    while True:   # each pass removes at least one ${...}: it ends
        new = PARAM_WORD.sub(lambda m: m.group(4), text)
        if new == text:
            return new
        text = new


def _mark_defaults(text):
    """${x:-word} as `${x}word`: still named by a variable, for the variable-program rule — bash runs $x when it is set,
    and the default word is only one of the programs it can run (Codex #164 r3, N03)."""
    while True:
        new = PARAM_WORD.sub(lambda m: "${%s}%s" % (m.group(1), m.group(4)), text)
        if new == text:
            return new
        text = new


def _decode_dollar_quotes(text):
    """bash reads $'d'ocker and $"d"ocker as docker (Sonnet #164 r20, NEW-30/31): outside other quotes, $'...' becomes a
    plain '...' (its only allowed escapes, \\n \\t \\r, become the characters; _ansi_c_hidden refuses any other on the raw
    text) and $"..." becomes "...", so every check reads the word bash runs."""
    out, i, q = [], 0, None
    while i < len(text):
        c = text[i]
        if q == "'":
            q = None if c == "'" else q
        elif q == '"':
            if c == "\\" and i + 1 < len(text):
                out.append(c); i += 1; c = text[i]
            elif c == '"':
                q = None
        elif c == "\\" and i + 1 < len(text):
            out.append(c); i += 1; c = text[i]
        elif c == "$" and text[i + 1:i + 2] == "'":
            j, word = i + 2, []
            while j < len(text) and text[j] != "'":
                if text[j] == "\\" and text[j + 1:j + 2] in ("n", "t", "r"):
                    word.append({"n": "\n", "t": "\t", "r": "\r"}[text[j + 1]]); j += 2
                else:
                    word.append(text[j]); j += 1
            out.append("'" + "".join(word) + "'")
            i = j + 1
            continue
        elif c == "$" and text[i + 1:i + 2] == '"':
            i += 1
            continue
        elif c in "'\"":
            q = c
        out.append(c)
        i += 1
    return "".join(out)


def _unquoted(text):
    return re.sub(r"[\"'\\]", "", text)


def _ansi_c_hidden(text):
    """True when an ANSI-C string ($'...' outside any quotes) carries an escape other than \\n, \\t or \\r. A '$' that
    closes a single-quoted regex ('x$') is not one: the scan tracks single and double quotes as bash does."""
    i, q = 0, None
    while i < len(text):
        c = text[i]
        if q == "'":
            q = None if c == "'" else q
        elif q == '"':
            if c == "\\":
                i += 1
            elif c == '"':
                q = None
        elif c == "\\":
            i += 1
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;|&("):
            j = text.find("\n", i)                       # a comment: its apostrophes open nothing (rescan probe step)
            i = len(text) if j < 0 else j
            continue
        elif c in "'\"":
            q = c
        elif c == "$" and text[i + 1:i + 2] == "'":
            j = i + 2
            while j < len(text) and text[j] != "'":
                if text[j] == "\\":
                    if text[j + 1:j + 2] not in ("n", "t", "r"):
                        return True
                    j += 1
                j += 1
            i = j
        i += 1
    return False


SHELLS = {"bash", "sh", "dash", "zsh"}
# Verbs reviewed as running or pulling nothing remote (Sonnet #164 r12: every verb is checked, reviewed here, or refused)
DOCKER_SAFE = {"login", "logout", "images", "ps", "rm", "rmi", "stop", "kill", "start", "restart", "logs", "inspect",
               "exec", "cp", "version", "info", "push", "load", "save", "export", "wait", "top", "port",
               "stats", "events", "history", "pause", "unpause", "rename", "update", "attach", "diff", "commit",
               "network", "volume", "search"}   # not plugin, context, import, system, trust, secret, config (NEW-16/17/20)
DOCKER_SAFE_SUB = {("image", "ls"), ("image", "rm"), ("image", "inspect"), ("image", "prune"), ("image", "history"),
                   ("image", "save"), ("image", "load"), ("image", "push"), ("image", "tag"), ("container", "ls"),
                   ("container", "rm"), ("container", "inspect"), ("container", "logs"), ("container", "stop"),
                   ("container", "prune"), ("manifest", "inspect"), ("manifest", "push"), ("manifest", "annotate"),
                   ("manifest", "rm"), ("buildx", "inspect"), ("buildx", "ls"),
                   ("buildx", "rm"), ("buildx", "stop"), ("buildx", "version"), ("buildx", "du"), ("buildx", "prune"),
                   ("buildx imagetools", "inspect"), ("builder", "prune"), ("builder", "ls")}
SKOPEO_SAFE = {"login", "logout", "list-tags", "manifest-digest", "delete", "standalone-verify", "--version", "-v"}
CRANE_SAFE = {"digest", "manifest", "ls", "tag", "auth", "config", "validate", "catalog", "delete", "push", "blob",
              "version"}   # "index" is split below: append/filter fetch their sources, list is read-only (Codex r1, B5)
SEPARATORS = re.compile(r"&&|\|\||[;|&\n]|\)")
def _tokens(chunk):
    """A command chunk's words. Comments come off with _mask_shell's rule (a `#` at the start of a word, outside any quote),
    then shlex splits with ITS comment handling off: shlex itself treats a `#` in the middle of a word as a comment and
    silently drops the rest of the line, so `NOTE=hello#world docker run alpine:latest` lost its `docker run` (Codex
    #164 r17, B09 — a fail-open hole). An unbalanced quote falls back to a whitespace split, as before."""
    import shlex
    text = _mask_shell(chunk)[0]
    try:
        return shlex.split(text, comments=False)
    except ValueError:
        return text.split()


def _split_commands(text):
    """The simple commands of a shell text, split as bash splits them: at ; & | ( ) and newlines OUTSIDE quotes ('…',
    "…", $'…') and escapes, with comments (# at the start of a word, outside quotes) dropped. A raw split at these
    characters cut quoted text and comments into false commands (Codex #164 adversarial r1, C02 noise)."""
    out, cur, i, q, n = [], [], 0, None, len(text)
    while i < n:
        c = text[i]
        if q == "'":
            cur.append(c)
            q = None if c == "'" else q
        elif q == "$'":
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 1
            elif c == "'":
                q = None
        elif q == '"':
            cur.append(c)
            if c == "\\" and i + 1 < n:
                cur.append(text[i + 1]); i += 1
            elif c == '"':
                q = None
        elif c == "\\" and i + 1 < n:
            cur += [c, text[i + 1]]; i += 1
        elif c == "$" and text[i + 1:i + 2] == "'":
            cur += ["$", "'"]; q = "$'"; i += 1
        elif c in "'\"":
            cur.append(c); q = c
        elif c == "#" and (not cur or cur[-1] in " \t"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c == "(" and cur and cur[-1] == "=":         # NAME=( … ): an array's words, not commands
            depth, j, aq = 1, i + 1, None
            while j < n and depth:
                d = text[j]
                if aq == "'":                              # no escaping at all inside a single quote
                    aq = None if d == "'" else aq
                elif aq == '"' or d == "\\":                # a backslash escapes the next char, inside a
                    if d == "\\" and j + 1 < n:              # double quote OR outside any quote (Sonnet #164
                        j += 2                                # r14, B1: the classic 'x'\''y' idiom embeds a
                        continue                             # literal apostrophe this way — the backslash is
                    aq = None if d == '"' else aq            # NOT a new quote opening)
                elif d in "'\"":
                    aq = d
                elif d == "#" and (j == i + 1 or text[j - 1] in " \t\n"):
                    # a comment inside the array (Codex #164 r13, B1): its own ')' or apostrophe is not real
                    # syntax and must not move depth or open a quote — same rule as the outer loop's own #
                    while j < n and text[j] != "\n":
                        j += 1
                    continue
                elif d == "(":
                    depth += 1
                elif d == ")":
                    depth -= 1
                j += 1
            cur.append(text[i:j].replace("\n", " "))
            i = j
            continue
        elif c in ";&|()\n":
            out.append("".join(cur)); cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur))
    return [x for x in out if x.strip()]


SUBST = "$__SUBST__"   # stands where a command substitution was cut out (Sonnet #164 r4, NEW-4): fails closed


def _cut_substitutions(text, data=False):
    """Replace every $(…) and `…` (nesting respected) with SUBST, returning (text, [inner scripts]). Splitting on `$(`
    used to sever an image or package argument from its command; now the argument stays, as a value no reader can
    know, and the inner command is read as a script of its own. Read as bash reads it: nothing inside '…' is a
    substitution, an escaped \\` or \\$ is a character, and quotes inside $(…) do not end it (Codex #164 r1 C02 noise).
    data=True reads an unquoted heredoc body: quotes and # are plain characters there, so '$(x)' runs (Codex r3, N01)."""
    out, inner, i, n, q = [], [], 0, len(text), None
    while i < n:
        c = text[i]
        if q == "'":
            out.append(c)
            q = None if c == "'" else q
            i += 1
        elif c == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
        elif data and c in "'\"#":
            out.append(c)
            i += 1
        elif c == "#" and q is None and (
            i == 0 or (text[i - 1] in " \t\n;(" and not (out and len(out[-1]) == 2 and out[-1][0] == "\\"))
        ):
            # a '#' right after '(' starts a comment too (Codex #164 r14, B2): an array literal's opening
            # paren, or a subshell's, both begin a new word there, same as whitespace/;/newline already did.
            # Any of those boundary characters can itself be escaped (Codex #164 r16, B3: \ , \;, a literal
            # tab) -- then it's data inside the current word, not a real boundary, and the '#' right after
            # it is not a comment either; out[-1] is the literal 2-char escape pair when that happened
            j = text.find("\n", i)                      # a comment: no quotes, no substitutions
            j = n if j < 0 else j
            out.append(text[i:j])
            i = j
        elif c == "'" and q is None:
            out.append(c)
            q = "'"
            i += 1
        elif c == '"':
            out.append(c)
            q = None if q == '"' else '"'
            i += 1
        elif text.startswith("$(", i):            # $(…) and arithmetic $((…)) alike: a value, its inside read too
            depth, j, iq = 1, i + 2, None
            while j < n and depth:
                d = text[j]
                if iq:
                    if d == "\\" and iq == '"':
                        j += 2
                        continue
                    iq = None if d == iq else iq
                elif d == "\\":
                    j += 2
                    continue
                elif d in "'\"":
                    iq = d
                elif d == "#" and (j == i + 2 or text[j - 1] in " \t\n;("):
                    # the same comment rule the top-level scanner has (Codex #164 r15, B3): a ')' or
                    # apostrophe inside a comment here is not real syntax either, and this nested scan had
                    # never learned that rule at all
                    while j < n and text[j] != "\n":
                        j += 1
                    continue
                elif d == "(":
                    depth += 1
                elif d == ")":
                    depth -= 1
                j += 1
            inner.append(text[i + 2:j - 1] if depth == 0 else text[i + 2:])
            out.append(SUBST)
            i = j
        elif c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            inner.append(text[i + 1:min(j, n)])
            out.append(SUBST)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out), inner


def _options(args, val, boolean):
    """Skip the options at the front of args. Returns (index of the first operand, an unknown option or None);
    a variable where an option or the operand would be stops the walk (the review pass covers it)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return i + 1, None
        if not a.startswith("-") or a == "-" or (_variable(a) and a.startswith("$")):
            return i, None
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if name in boolean or (name in val and "=" in a):
                i += 1
            elif name in val:
                i += 2
            else:
                return i, a
            continue
        short = {o[1] for o in val | boolean if len(o) == 2}
        j = 1
        while j < len(a):
            o = "-" + a[j]
            if o in boolean:
                j += 1
                continue
            if o in val:
                i += 1 if j + 1 < len(a) else 2
                break
            return i, a if a[j] not in short else a
        else:
            i += 1
    return i, None


KEYWORDS = {"if", "then", "elif", "else", "while", "until", "do", "!", "{", "time"}
WRAPPERS = {"sudo", "env", "nohup", "nice", "timeout", "xargs", "exec", "command", "stdbuf", "ionice", "setsid",
            "unbuffer", "chronic", "time", "doas"}
# a wrapper's options that take a value: the value is never the program (Codex #164 r3, C02: env -u BASH_ENV bash x.sh)
WRAPPER_VAL = {"env": {"-u", "--unset"}, "sudo": {"-u", "-g", "-h", "-p", "-U", "-r", "-t", "-T", "-D", "-R", "-C"},
               "doas": {"-u", "-C"}, "timeout": {"-k", "--kill-after", "-s", "--signal"}, "nice": {"-n", "--adjustment"},
               "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}, "stdbuf": {"-i", "-o", "-e"},
               "xargs": {"-I", "-L", "-n", "-P", "-d", "-a", "-E", "-s", "--arg-file", "--delimiter", "--max-args",
                         "--max-procs", "--max-lines", "--replace"}, "exec": {"-a"}}
# wrapper options that run a string or move the working directory: refused (env -S 'bash x.sh', env -C dir)
WRAPPER_REFUSED = {"env": ("-S", "--split-string", "-C", "--chdir")}


_ARRAY_LITERAL = re.compile(r"^\s*(?:(?:if|then|elif|else|while|until|do)\s+)?"
                             r"[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=\(")


def _skip_array_literal(chunk):
    """chunk, or "" when it opens a NAME=(...) or NAME+=(...) array literal (an ordinary bash idiom for building
    a flag list; never itself runs a program). Finding exactly where such a literal CLOSES was tried twice and
    failed twice (Codex #164 r12, B2/B3): shlex has already stripped quotes by the time a token-level count can
    run, so a literal '(' / ')' inside a quoted element is indistinguishable from the array's own; and a '#'
    comment INSIDE the array (an ordinary, common idiom — this repo's own bin/check-file-allowlist.sh has one)
    can itself contain an apostrophe that a quote-aware scanner misreads as opening a real quote, corrupting
    everything after it (confirmed: ALLOW_PATTERNS's own comment "product's" did exactly this). Real bash's
    comment and quoting rules together are not worth re-implementing a third time for this (advisor 0080):
    the chunk this opens is simply treated as fully inert, including anything bash would actually run AFTER
    the array literal closes on the same line (`a=(x) realcommand` — a genuine, if rare, bash idiom; not seen
    anywhere plain in this repo) — an accepted residual, not a blocker, same trade as the trap rule's."""
    return "" if _ARRAY_LITERAL.match(chunk) else chunk


def _command_words(toks):
    """The words a simple command will run as a program: past redirections, assignments and shell keywords, and through
    wrappers (timeout 5, env -u X, xargs -n1, sudo -u u …) to their targets, each wrapper's value options consumed."""
    words, i = [], 0
    while i < len(toks):
        t = toks[i]
        if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>>?|>&)", t):          # a redirection before the program (C02: > /dev/null bash x)
            i += 1 if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>>?|>&)[^<>&]", t) else 2
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=.*", t) or t in KEYWORDS:
            i += 1
            continue
        words.append(t)
        w = _base(t).lower()
        if w not in WRAPPERS:
            break
        i += 1
        while i < len(toks) and (toks[i].startswith("-") or re.fullmatch(r"[0-9.]+[smhd]?", toks[i])
                                 or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=.*", toks[i])):
            o = toks[i].split("=", 1)[0]
            i += 1
            if o in WRAPPER_VAL.get(w, ()) and "=" not in toks[i - 1] and not (len(o) == 2 and len(toks[i - 1]) > 2):
                i += 1                                          # the option's value
    return words


def _commands(script, depth=0):
    """The simple commands of a shell script, each a token list (quotes removed, comments dropped), starting at the
    first tool word; a `bash -c "…"` / `sh -c` / `eval "…"` argument is read as a script of its own."""
    import shlex
    text, inner = _cut_substitutions(re.sub(r"\\\n", "", script))
    out = []
    if any(re.search(r"(?<![\w.-])case(?![\w.-])", sub) for sub in inner):
        out.append(["__too_deep__", "case ... esac inside $( )"])    # a case pattern's `)` ends the substitution early: refuse (Codex #164 r19, B10)
    if depth < 6:
        for sub in inner:
            if sub.startswith("(") and sub.endswith(")"):     # $(( … )) arithmetic: only its own $( … ) run
                out += [c for n in _cut_substitutions(sub[1:-1])[1] for c in _commands(n, depth + 1)]
            else:
                out += _commands(sub, depth + 1)
    elif inner:
        out.append(["__too_deep__", "command substitutions"])   # never silently dropped (C02)
    for chunk in _split_commands(text):
        chunk = _skip_array_literal(chunk)
        toks = _tokens(chunk)
        if not toks or toks[0] in PRINTERS:
            continue
        for i, w in enumerate(toks):
            c = next((j for j in range(i + 1, len(toks)) if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", toks[j])), None) \
                if _base(w) in SHELLS else None
            # `trap 'CMD' SIGSPEC...` runs CMD on the signal; a literal, non-option command argument is read like an
            # eval body (Codex #164 adversarial r1, B2) — `trap -p`, `trap -l` and a bare `trap SIGSPEC` (listing or
            # resetting, no separate command) run nothing; `trap -- CMD SIG` (Codex r2, B2) is the option terminator,
            # not an option itself, and once consumed CMD is unconditional — it may itself start with "-" as literal
            # text, not a trap option (Sonnet r5: that dash check must not survive past --)
            dashdash = w == "trap" and toks[i + 1:i + 2] == ["--"]
            j_ = i + 2 if dashdash else i + 1
            trap_cmd = toks[j_] if w == "trap" and j_ + 1 < len(toks) and (dashdash or not toks[j_].startswith("-")) else None
            if c is not None or (w == "eval" and toks[i + 1:]) or trap_cmd is not None:
                if depth >= 4:                                # nesting past the limit is refused (Codex r1, C02)
                    out.append(["__too_deep__", w])
                elif c is not None:
                    out += _commands(toks[c + 1], depth + 1) if c + 1 < len(toks) else []
                elif trap_cmd is not None:
                    out += _commands(trap_cmd, depth + 1)
                else:
                    out += _commands(" ".join(toks[i + 1:]), depth + 1)
                break
        inline = next((w for w in _command_words(toks) if _base(w) in INTERPRETERS and any(
            re.match(INTERPRETERS[_base(w)], t) for t in toks[toks.index(w) + 1:])), None)
        if inline:            # inline code for another interpreter is refused (handoff 0094)
            out.append(["__inline__", inline])
            continue
        stdin = _stdin_shell(toks)
        if stdin:             # a shell fed by a pipe, a herestring or a process substitution (Sonnet #164 r21, NEW-32)
            out.append(["__stdin_shell__", stdin])
            continue
        words = _command_words(toks)
        bad_wrap = next((w for w in words if any(t.split("=", 1)[0] in WRAPPER_REFUSED.get(_base(w), ())
                                                  for t in toks[toks.index(w) + 1:toks.index(words[-1]) + 1])), None)
        if bad_wrap:          # env -S runs a string, env -C moves the working directory (Codex r3, C02)
            out.append(["__wrapper_opt__", bad_wrap])
            continue
        if words:             # a script this command runs (Codex #164 r2, C02): through wrappers, $( ), -c, eval alike
            w = words[-1]
            rest = toks[toks.index(w) + 1:]
            ops = [a for k, a in enumerate(rest) if not a.startswith(("-", "<", ">")) and not re.match(r"^[0-9]+[<>]", a)
                   and not (k > 0 and re.fullmatch(r"[-+][a-zA-Z]*[oO]", rest[k - 1]))]
            if _base(w) in SHELLS and ops and not any(re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a) for a in rest):
                out.append(["__script__", ops[0]])
            elif (w == "source" or (w == "." and w == words[0])) and ops:     # command source x.sh too (r3)
                out.append(["__script__", ops[0]])
            elif ("/" in w or w.endswith(".sh")) and _base(w) not in TOOLS | SHELLS and not PKG_TOOL.match(_base(w)) \
                    and not re.search(r"[$*?\[]", w):
                out.append(["__exec__", w])
            elif _base(w) in ("node", "nodejs", "perl", "ruby", "php") or re.match(r"^python3?(\.[0-9]+)?$", _base(w)):
                kind, what, _ = _python_run(rest) if _base(w).startswith("python") else (
                    ("script", ops[0], []) if ops else ("none", None, []))
                if kind == "script" and what not in ("-", None):
                    out.append(["__foreign__", what])     # another language's FILE: committed = boundary, else refused (r3)
            elif re.search(r"[*?\[]", w) and re.search(r"[A-Za-z]", w) and "$" not in w and w not in ("[", "[["):
                out.append(["__globexec__", w])          # ./[r]unner: matched against committed files (r3, C02)
        named = [w for w in _command_words(toks) if re.search(r"\$[{A-Za-z_0-9@*#?!]", _base(w)) and SUBST not in w]
        if named:             # a program named by a variable runs text this check cannot read (advisor 0084 (2);
            out.append(["__variable_program__", named[0]])   # Sonnet #164 r22, NEW-33): refused
            continue
        computed = [w for w in _command_words(toks) if SUBST in w]
        if computed:          # a program name built by a substitution (d$()ocker): it cannot be resolved (NEW-11)
            out.append(["__computed__", computed[0]])
            continue
        # the tool word anywhere in the command (`if docker …`, `timeout 30 docker …`, `xargs docker …`): fail closed
        if toks[0] == "hash" and any(t.startswith("-") and "p" in t for t in toks[1:]):
            out.append(["__hash_p__", " ".join(toks)])   # hash -p binds a name to a program (Codex #164 adversarial r1, C12)
            continue
        globbed = [w for w in _command_words(toks) if re.search(r"[*?\[]", w) and _glob_guarded(_base(w))]
        if globbed:           # a glob in a program name resolves to a file this check cannot see (C01)
            out.append(["__glob__", globbed[0]])
            continue
        if toks[0] in ("which", "type", "hash") or (toks[0] == "command" and toks[1:2] and toks[1] in ("-v", "-V")):
            continue          # a PATH lookup names a tool without running it
        # exact case: on an ubuntu runner (the scope) `Docker` is "command not found"; prose in a quoted string is not a run
        at = next((i for i, w in enumerate(toks) if _base(w) in TOOLS or PKG_TOOL.match(_base(w))), None)
        if at is not None:
            out.append([_base(toks[at])] + toks[at + 1:])
    return out


GUARDED = ("docker", "podman", "nerdctl", "skopeo", "crane", "docker-compose", "podman-compose", "buildah", "ctr",
           "crictl", "pip", "pip3", "pipx", "python", "python3", "uv", "uvx", "npm", "npx", "gem", "yarn", "pnpm", "bun",
           "conda", "mamba", "micromamba", "bash", "sh", "dash", "zsh", "cd", "pushd", "alias", "hash", "eval", "source",
           "cp", "ln", "install", "mv", "rsync")


def _glob_guarded(pattern):
    """True when a glob used as a program name could match a name this check guards (docke[r], dock?r). A pattern with
    no literal letter (`*)` case labels, `**` in quoted text the splitter cut) names no particular program: not refused."""
    import fnmatch
    if "[:" in pattern:                                  # [[:lower:]]ocker: fnmatch cannot read POSIX classes (r3, C01)
        return True
    return bool(re.search(r"[A-Za-z]|\[[^]]*\]", pattern)) and \
        any(fnmatch.fnmatchcase(name, pattern) for name in GUARDED)   # [d][o][c][k][e][r] too (Codex r2, C01)


# Inline-code flags of other interpreters (handoff 0094): their code in the workflow is refused; python's -c is read in
# script_installs. A heredoc or a committed file in another language is the documented boundary.
INTERPRETERS = {"node": r"-[a-zA-Z]*[ep]|--eval|--print", "nodejs": r"-[a-zA-Z]*[ep]|--eval|--print",
                "perl": r"-[a-zA-Z]*[eE]", "ruby": r"-[a-zA-Z]*e", "php": r"-[a-zA-Z]*r",
                "deno": r"eval", "bun": r"-e|--eval|-p|--print", "Rscript": r"-e", "lua": r"-e", "pwsh": r"-[cC]",
                "osascript": r"-e", "awk": r"$^"}   # matched as a PREFIX: -e'…', --eval=… attached (Codex r2, C02)


def _stdin_shell(toks):
    """The shell word when a program word of this command is a shell that would read its script from stdin, a
    herestring, a process substitution or /dev/stdin, instead of `-c "…"` (read as a script) or a file operand; and
    `source` / `.` of a process substitution or stdin. (A bare `.` without an operand is a bash error, not a run.)"""
    words = _command_words(toks)
    for w in words:
        dot = _base(w) in ("source", ".")
        if not (_base(w) in SHELLS or (dot and w == words[0])):
            continue
        rest = toks[toks.index(w) + 1:]
        if not dot and any(re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a) for a in rest):
            return None
        i = 0
        while i < len(rest):
            a = rest[i]
            if a.startswith("<(") or (re.fullmatch(r"[0-9]*<", a) and (i + 1 == len(rest) or rest[i + 1] == "<")):
                return w                                  # the script is a process substitution's output (NEW-34)
            if a.startswith("<"):                          # a redirection or herestring: not an operand
                i += 1 if re.match(r"^<(<<?|&)?[^<>&]", a) else 2
                continue
            if re.match(r"^[0-9]*(>>?|<>|&>)", a):
                i += 1 if re.match(r"^[0-9]*(>>?|<>|&>)[^<>]", a) else 2
                continue
            if not dot and a.startswith("-") and a not in ("-", "--"):
                if re.fullmatch(r"-[a-z]*s[a-z]*", a):
                    return w                              # -s: the script comes from stdin
                i += 1 + bool(re.fullmatch(r"[-+][a-zA-Z]*[oO]", a))   # -o / -eo / +O take a value
                continue
            if a == "--":
                i += 1
                continue
            return w if a in ("-", "/dev/stdin") or a.startswith(("/dev/fd/", "/proc/self/fd/")) else None
        return None if dot else w
    return None


def _base(word):
    return word.rsplit("/", 1)[-1]


def _variable(tok):
    return "$" in tok or "${{" in tok


def _build(args):
    """(dockerfile, context, tags, named, cache_from) of a docker build / buildx build: dockerfile None = the default
    name. cache_from: each --cache-from registry image (a type=local/gha/... source names nothing remote)."""
    dockerfile, tags, pos, named, cache_from, i = None, set(), [], [], [], 0
    while i < len(args):
        a = args[i]
        if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)", a):     # a shell redirection is not an argument (`- < Dockerfile`)
            i += 1 if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)[^<>]", a) else 2
            continue
        if a in ("-f", "--file"):
            dockerfile, i = (args[i + 1] if i + 1 < len(args) else "-"), i + 2
            continue
        if a.startswith("--file="):
            dockerfile = a.split("=", 1)[1]
        elif a.startswith("-f") and not a.startswith("--") and len(a) > 2:
            dockerfile = a[2:][1:] if a[2] == "=" else a[2:]       # -fFILE / -f=FILE (Codex #164 adversarial r1, C07)
        elif a in ("-t", "--tag") and i + 1 < len(args):
            tags.add(args[i + 1]); i += 2
            continue
        elif a.startswith(("--tag=", "-t=")):
            tags.add(a.split("=", 1)[1])
        elif a == "--build-context" and i + 1 < len(args):
            named.append(args[i + 1].split("=", 1)[-1]); i += 2
            continue
        elif a.startswith("--build-context="):
            named.append(a.split("=", 2)[-1])
        elif a == "--cache-from" and i + 1 < len(args):
            cache_from.append(args[i + 1]); i += 2
            continue
        elif a.startswith("--cache-from="):
            cache_from.append(a.split("=", 1)[1])
        elif a.startswith("-") and a != "-":
            if "=" not in a and i + 1 < len(args) and not args[i + 1].startswith("-") and a not in (
                    "--push", "--load", "--no-cache", "--pull", "-q", "--quiet", "--rm", "--force-rm"):
                i += 2
                continue
        else:
            pos.append(a)
        i += 1
    return dockerfile, (pos[-1] if pos else "."), tags, named, cache_from


def _pip_install(args):
    """True when a pip install / download / wheel takes every package from a -r file with --require-hashes in force:
    the options are read with their values, an unknown option fails closed (Codex #164 adversarial r1, C05)."""
    reqs, specs, hashes, i = 0, 0, False, 0
    while i < len(args):
        a = args[i]
        if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)", a):     # a redirection (<<'EOF', 2>/dev/null, > f)
            i += 1 if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)[^<>]", a) else 2
            continue
        name = a.split("=", 1)[0] if a.startswith("--") else a
        if a.startswith("-r") and not a.startswith("--") and len(a) > 2:
            reqs += 1                                    # -rFILE / -r=FILE
        elif name in ("-r", "--requirement"):
            reqs += 1
            i += 1 if "=" in a else 2
            continue
        elif name in ("-e", "--editable"):
            specs += 1
            i += 1 if "=" in a else 2
            continue
        elif name in PIP_VAL:
            i += 1 if "=" in a else 2
            continue
        elif a == "--require-hashes":
            hashes = True
        elif a in PIP_BOOL:
            pass
        elif a.startswith("-"):
            return False                                 # an option this check does not know: fail closed
        else:
            specs += 1
        i += 1
    return hashes and reqs > 0 and specs == 0


def _python_run(args):
    """(kind, what, rest) for a python invocation, its options read as python reads them, clusters too (-Im pip, -Ic …;
    Codex r2, C04): ("module", name, rest) for -m, ("inline", None, []) for -c (refused, handoff 0094), ("script", path,
    rest) for a script operand (stdin `-` included), ("none", None, []) otherwise."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-" or not a.startswith("-"):
            return "script", a, args[i + 1:]
        if a.startswith("--"):
            i += 1 + (a in ("--check-hash-based-pycs",))
            continue
        for k, ch in enumerate(a[1:], 1):
            if ch == "m":
                mod = a[k + 1:] or (args[i + 1] if i + 1 < len(args) else None)
                rest = args[i + 1:] if a[k + 1:] else args[i + 2:]
                return ("module", mod, rest) if mod else ("none", None, [])
            if ch == "c":
                return "inline", None, []
            if ch in "WX":                                # takes a value: the rest of the token or the next word
                i += 0 if a[k + 1:] else 1
                break
        i += 1
    return "none", None, []


def script_installs(script):
    """(command, why) for every package install the script makes that is not hash-pinned (handoff 0070)."""
    found = []
    for t in _commands(script):
        cmd, args = t[0], t[1:]
        if cmd in OS_PKG and args[:1] and args[0] in ("install", "upgrade", "reinstall", "add", "update", "bundle"):
            found.append((cmd + " " + args[0], "an OS package manager install (none is held to hashes here)"))
            continue
        if cmd in UNREAD_PY:
            found.append((cmd, "a Python installer this check cannot hold to hashes"))
            continue
        if cmd in REFUSED_PKG:
            found.append((cmd, "a package manager this repository does not use; any invocation is refused"))
            continue
        if re.match(r"^python3?(\.[0-9]+)?$", cmd):
            kind, what, rest = _python_run(args)
            if kind == "inline":
                found.append((cmd + " -c", "inline code in the workflow is not read; put it in a committed file "
                                            "(handoff 0094)"))
                continue
            if kind == "script":
                if what.rsplit("/", 1)[-1] == "setup.py":
                    found.append(("python setup.py", "setuptools fetches and builds packages without hashes"))
                continue                                 # a committed .py file or a heredoc: the documented boundary
            if kind != "module":
                continue
            top = what.split(".")[0]
            if top in ("build", "pipx", "poetry", "pipenv", "pdm", "hatch", "flit", "uv"):
                found.append(("python -m " + what, "a Python installer or build frontend this check cannot hold to hashes"))
                continue
            if top != "pip":
                continue
            cmd, args = "python -m pip", rest
        if FORWARD & set(args):
            found.append((cmd, "forwards its caller's arguments; the packages cannot be seen"))
            continue
        if re.match(r"^pip3?(\.[0-9]+)?$", cmd) or cmd == "python -m pip":
            k, unknown = 0, None
            while k < len(args) and args[k].startswith("-") and args[k] != "-":
                name = args[k].split("=", 1)[0]
                if name in PIP_GLOBAL_VAL:
                    k += 1 if "=" in args[k] else 2
                elif name in PIP_GLOBAL_BOOL:
                    k += 1
                else:
                    unknown = args[k]
                    break
            if unknown:
                found.append((cmd, "a global option this check does not know (%s)" % unknown))
                continue
            verb = args[k] if k < len(args) else None
            if verb is not None and _variable(verb):
                found.append((cmd, "its subcommand is a variable; the packages cannot be seen"))
            elif verb in ("install", "download", "wheel"):     # download/wheel build from source (N3)
                if not _pip_install(args[k + 1:]):
                    found.append((cmd + " " + verb, "not every package from a -r file checked with --require-hashes"))
            elif verb is not None and verb not in PIP_READ:
                found.append((cmd + " " + verb, "a pip subcommand this check does not read"))
    return found


SCOUT_VAL = {"--format", "--vex-location", "--output", "-o", "--platform", "--org", "--env", "--only-severity",
             "--only-package-type", "--only-cve-id", "--only-base", "--ref", "--tag", "--vex-author",
             "--file", "--predicate-type"}   # `docker scout attestation add` (#176, main-candidate-rescan.yml)
SCOUT_BOOL = {"--ignore-base", "--only-fixed", "--only-unfixed", "--exit-code", "-e", "--details", "--multi-stage",
              "--only-vex-affected", "--vex", "--locations"}
SCOUT_LOCAL = ("local://", "oci-dir://", "archive://", "fs://", "sbom://")


def _scout(args):
    """docker scout <sub> [options] <image>: a local:// (or file) image is ours; a registry image must be a digest; an
    unknown option fails closed."""
    if not args:
        return []
    sub, rest = args[0], args[1:]
    if sub == "attestation" and rest[:1] and not rest[0].startswith("-"):
        # `docker scout attestation add|rm|ls ...` (#176, main-candidate-rescan.yml): attestation's own verb is a
        # second bare word, not the image -- fold it into the subcommand name so parsing resumes at the real args
        sub, rest = sub + " " + rest[0], rest[1:]
    ev, i = [], 0
    while i < len(rest):
        a = rest[i]
        if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)", a):     # a shell redirection is not an argument
            i += 1 if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)[^<>]", a) else 2
            continue
        if a.startswith("-"):
            name = a.split("=", 1)[0]
            if name in SCOUT_BOOL or (name in SCOUT_VAL and "=" in a):
                i += 1
            elif name in SCOUT_VAL:
                i += 2
            else:
                return [("finding", "`docker scout %s` has an option this check does not know (%s)" % (sub, a))]
            continue
        if not a.startswith(SCOUT_LOCAL):
            ev.append(("use", "docker scout " + sub, a.split("://", 1)[1] if a.startswith(("registry://", "image://")) else a))
        i += 1
    return ev


def script_images(script):
    """Events, in order, for the images a script names: ("use", command, image), ("local", name), ("finding", why)."""
    ev = []
    for t in _commands(script):
        cmd, args = t[0], t[1:]
        if cmd in ("docker-compose", "podman-compose"):
            ev.append(("finding", "`%s` runs images named in compose files, which this check does not read" % cmd))
            continue
        if cmd in UNREAD_CONTAINER:
            ev.append(("finding", "`%s` runs or pulls images through a CLI this check does not read" % cmd))
            continue
        if cmd == "__variable_program__":
            ev.append(("finding", "a program is named by a variable (%s); what it runs cannot be read, refused "
                                  "(name the program literally)" % args[0]))
            continue
        if cmd == "__too_deep__":
            ev.append(("finding", "`%s` nests scripts deeper than this check reads; refused" % args[0]))
            continue
        if cmd == "__inline__":
            ev.append(("finding", "`%s` runs inline code from the workflow, which is not read; put it in a committed file "
                                  "(handoff 0094)" % args[0]))
            continue
        if cmd == "__wrapper_opt__":
            ev.append(("finding", "`%s` runs a string or moves the working directory (-S / -C); refused" % args[0]))
            continue
        if cmd in ("__glob__", "__hash_p__"):
            ev.append(("finding", ("a program name is a glob (%s); the file it runs cannot be seen" if cmd == "__glob__"
                                   else "`%s` binds a command name to a program; the renamed command cannot be checked")
                       % args[0]))
            continue
        if cmd == "__stdin_shell__":
            ev.append(("finding", "`%s` reads its script from stdin, a herestring or a process substitution; text this "
                       "check never reads, refused" % args[0]))
            continue
        if cmd == "__computed__":
            ev.append(("finding", "a program name is built by a command substitution (%s); it cannot be resolved"
                       % args[0].replace(SUBST, "$(…)")))
            continue
        if cmd in ("docker", "podman", "nerdctl") and args:
            k, unknown = _options(args, DOCKER_GLOBAL_VAL, DOCKER_GLOBAL_BOOL)
            if unknown:
                ev.append(("finding", "`%s` has a global option this check does not know (%s)" % (cmd, unknown)))
                continue
            rest = args[k:]
            if not rest:
                continue
            if FORWARD & set(args) or _variable(rest[0]):
                ev.append(("finding", "`%s` is given forwarded arguments or a variable verb; its image cannot be seen"
                                      % cmd))
                continue
            verb, rest = rest[0], rest[1:]
            if verb in ("load", "import", "commit") or (verb == "image" and rest[:1] in (["load"], ["import"])):
                ev.append(("unlocal", "*"))   # an archive or a commit replaces tags with bytes this check never saw (Codex #164 r21, B9)
            if verb == "rmi" or (verb == "image" and rest[:1] in (["rm"], ["remove"], ["prune"])):
                gone = [a for a in (rest if verb == "rmi" else rest[1:]) if not a.startswith("-")]
                if any(_variable(a) or SUBST in a or re.search(r"[*?\[]", a) for a in gone):
                    ev.append(("unlocal", "*"))      # a computed or globbed name removes SOME local tag: none stays trusted (Sonnet #164 r21, B1)
                else:
                    ev += [("unlocal", x) for x in gone] or [("unlocal", "*")]   # prune: every local name (C10)
                continue
            if verb in ("container", "image", "builder", "manifest") and rest and (verb, rest[0]) in DOCKER_SAFE_SUB:
                continue
            if verb == "buildx" and len(rest) >= 2 and rest[0] == "imagetools" and ("buildx imagetools", rest[1]) in DOCKER_SAFE_SUB:
                continue
            if verb == "buildx" and rest and ("buildx", rest[0]) in DOCKER_SAFE_SUB:
                continue
            if verb in ("container", "image", "builder") and rest:
                verb, rest = rest[0], rest[1:]
            if verb == "buildx" and rest:
                verb, rest = ("build" if rest[0] in ("build", "b") else "buildx " + rest[0]), rest[1:]
                if verb == "buildx imagetools" and rest[:1] == ["create"]:
                    verb, rest = "imagetools create", rest[1:]
            if verb == "manifest" and rest[:1] == ["create"]:
                pos = [a for a in rest[1:] if not a.startswith("-")]
                ev += [("use", "docker manifest create", x) for x in pos[1:]]
                continue
            if verb == "imagetools create":
                i, pos = 0, []
                while i < len(rest):
                    a = rest[i]
                    if a in ("-t", "--tag", "-f", "--file", "--progress", "--builder", "--annotation", "--platform"):
                        i += 2
                        continue
                    if not a.startswith("-"):
                        pos.append(a)
                    i += 1
                ev += [("use", "docker buildx imagetools create", x) for x in pos]
                continue
            if verb in ("compose", "buildx bake", "stack"):
                ev.append(("finding", "`docker %s` runs images named in files this check does not read" % verb))
            elif verb in ("run", "create", "pull"):
                val, boolean = (PULL_VAL, PULL_BOOL) if verb == "pull" else (RUN_VAL, RUN_BOOL)
                k, unknown = _options(rest, val, boolean)
                if unknown:
                    ev.append(("finding", "`docker %s` has an option this check does not know (%s): it cannot tell "
                                          "which word is the image" % (verb, unknown)))
                else:
                    # pull, and run/create --pull=always, fetch from the registry whatever is local (Codex #164
                    # adversarial r1, C10; r1 B3: a string flag's value is whichever --pull was LAST on the line, not
                    # whether --pull=never appears anywhere — Docker/pflag keep only the final assignment)
                    pull_state = None
                    for j, a in enumerate(rest[:k]):
                        if a == "--pull" and rest[j + 1:j + 2] and rest[j + 1] in ("always", "missing", "never"):
                            pull_state = rest[j + 1]
                        elif a.startswith("--pull="):
                            pull_state = a.split("=", 1)[1]
                    never = verb != "pull" and pull_state == "never"
                    fetch = verb == "pull" or (pull_state == "always" if pull_state is not None else False)
                    if not never:     # --pull=never can only use an image already in the daemon (Codex r3, C10)
                        ev.append(("fetch" if fetch else "use", "docker " + verb, rest[k] if k < len(rest) else None))
            elif verb == "scout":
                ev += _scout(rest)
            elif verb == "tag" and len(rest) >= 2:
                ev.append(("tag", rest[-2], rest[-1]))      # judged in check_runs: the source must be ours (NEW-21)
            elif verb in DOCKER_SAFE:
                pass
            elif verb not in ("build",):
                ev.append(("finding", "`%s %s` is not a verb this check reads or has reviewed as pulling nothing; "
                                      "it is refused" % (cmd, verb)))
            elif verb == "build":
                dockerfile, context, tags, named, cache_from = _build(rest)
                # a BUILDKIT_SYNTAX build argument selects the frontend image that runs the build (C09)
                for k, b in enumerate(rest):
                    v = rest[k + 1] if b == "--build-arg" and k + 1 < len(rest) else (
                        b.split("=", 1)[1] if b.startswith("--build-arg=") else "")
                    if (v == "BUILDKIT_SYNTAX" or v.startswith("BUILDKIT_SYNTAX=")) and not (
                            DIGEST_REF.search(v) and not _variable(v)):
                        ev.append(("finding", "a build sets its frontend image by tag or from the environment (%s)" % v))
                # an SBOM / attestation generator is an image the build runs (Codex r2, C09)
                joined = " ".join(rest)
                sbom = re.search(r"--sbom(=|\s+)(?!false\b)\S|--attest(=|\s+)\S*type=sbom", joined)
                if sbom and not re.search(r"generator=", joined):
                    ev.append(("finding", "a build generates an SBOM with BuildKit's default scanner image (a tag); name a "
                                          "generator pinned by digest or turn it off (Codex r3, C09)"))
                for gen in re.findall(r"generator=([^,\s\"']+)", joined):
                    if not (DIGEST_REF.search(gen) and not _variable(gen)):
                        ev.append(("finding", "a build runs a generator image not pinned by digest (%s)" % gen))
                ev.append(("build", dockerfile, context, named))
                if cmd == "docker":         # podman and nerdctl build into their OWN stores, not the daemon `docker run` reads (Codex #164 r21, B7)
                    ev += [("local", x) for x in tags]
                for cf in cache_from:
                    # a bare ref or type=registry,ref=... names a registry image; any other type (local/gha/...)
                    # reads from something this check does not treat as a remote pull (Codex r1, B4). Both forms are
                    # comma-splitting CSV (buildx's cache-source parser), so each one may name several refs (N2); a
                    # repeated type=/ref= attribute keeps only its LAST value, same as any repeated key (Codex r5, B2)
                    m = re.match(r"type=", cf)
                    attrs = dict(p.split("=", 1) for p in cf.split(",") if "=" in p) if m else {}
                    refstr = attrs.get("ref") if m else cf
                    if m and attrs.get("type") != "registry":
                        continue
                    if refstr is None:
                        ev.append(("finding", "a build's --cache-from registry source names no ref (%s)" % cf))
                    else:
                        # BuildKit's registry cache importer always fetches remotely; a matching local/output tag
                        # never exempts it (Codex #164 r2, B4)
                        for img in refstr.split(","):
                            ev.append(("fetch", "docker build --cache-from", img))
        elif cmd == "skopeo" and args and args[0] not in ("copy", "inspect") + tuple(SKOPEO_SAFE):
            ev.append(("finding", "`skopeo %s` is not a verb this check reads; it is refused" % args[0]))
        elif cmd == "skopeo" and args and args[0] in ("copy", "inspect"):
            pos, unknown = _operands(args[1:], SKOPEO_VAL, SKOPEO_BOOL)
            if unknown:
                ev.append(("finding", "`skopeo %s` has an option this check does not know (%s)" % (args[0], unknown)))
                continue
            if pos and pos[0].startswith("docker://"):
                ev.append(("fetch", "skopeo " + args[0], pos[0][len("docker://"):]))   # a registry read (r3, C10)
            elif pos and SUBST in pos[0]:                         # a substituted source could be docker://…
                ev.append(("fetch", "skopeo " + args[0], pos[0]))
            src = pos[0] if pos else ""
            trusted = (src.startswith("docker://") and DIGEST_REF.search(src)) or _variable(src)
            for a in pos[1:]:
                if a.startswith("docker-daemon:") and trusted:
                    ev.append(("local", a[len("docker-daemon:"):]))
                # an archive copied into the daemon (oci-archive:, dir:, docker-archive:) is NOT the job's own bytes: it
                # may be scanned, but running it is a finding (Sonnet #164 r14, NEW-22)
        elif cmd == "crane" and args and args[0] == "index" and args[1:2] == ["list"]:
            pass    # read-only: lists an index's own manifests, fetches no new source (Codex r1, B5)
        elif cmd == "crane" and args and args[0] == "index" and args[1:2] not in (["append"], ["filter"]):
            ev.append(("finding", "`crane index %s` is not a subcommand this check reads; it is refused"
                       % (args[1] if args[1:2] else "")))
        elif cmd == "crane" and args and args[0] == "index" and args[1:2] in (["append"], ["filter"]):
            pos, unknown = _operands(args[2:], CRANE_INDEX_VAL, CRANE_INDEX_BOOL)
            if unknown:
                ev.append(("finding", "`crane index %s` has an option this check does not know (%s)" % (args[1], unknown)))
                continue
            manifests = [args[2:][i + 1] for i, a in enumerate(args[2:]) if a in ("-m", "--manifest")] + \
                        [a.split("=", 1)[1] for a in args[2:] if a.startswith(("-m=", "--manifest="))]
            # every positional operand is a source (base + append's extra manifests after it), and -m/--manifest is a
            # comma-splitting pflag string-slice, same as --cache-from below (Codex #164 r2, B5/N2)
            for img in [x for p in pos for x in p.split(",")] + [x for m in manifests for x in m.split(",")]:
                ev.append(("fetch", "crane index " + args[1], img))
        elif cmd == "crane" and args and args[0] not in ("copy", "cp", "pull", "export") + tuple(CRANE_SAFE):
            ev.append(("finding", "`crane %s` is not a verb this check reads (it may take a base image); it is refused"
                       % args[0]))
        elif cmd == "crane" and args and args[0] in ("copy", "cp", "pull", "export"):
            pos, unknown = _operands(args[1:], CRANE_VAL, CRANE_BOOL)
            if unknown:
                ev.append(("finding", "`crane %s` has an option this check does not know (%s)" % (args[0], unknown)))
                continue
            if pos:
                ev.append(("fetch", "crane " + args[0], pos[0]))
    return ev


# skopeo copy / inspect and crane copy / pull / export options: a value option's value is never an image operand, and an
# option outside these reviewed sets is refused (Codex #164 adversarial r1, C06)
SKOPEO_VAL = {"--override-arch", "--override-os", "--override-variant", "--format", "-f", "--retry-times",
              "--authfile", "--src-authfile", "--dest-authfile", "--digestfile", "--additional-tag", "--retry-delay"}
SKOPEO_BOOL = {"--all", "-a", "--quiet", "-q", "--remove-signatures", "--preserve-digests", "--raw", "--config",
               "--dest-precompute-digests", "--src-tls-verify", "--dest-tls-verify", "--tls-verify", "--no-tags"}
CRANE_VAL = {"--platform", "--format", "-j", "--jobs", "--cache_path"}
CRANE_BOOL = {"--insecure", "-v", "--verbose", "--no-clobber", "-a", "--all-tags", "--allow-nondistributable-artifacts"}
CRANE_INDEX_VAL = {"-m", "--manifest", "-t", "--tag", "--platform"}
CRANE_INDEX_BOOL = {"--insecure", "-v", "--verbose", "--allow-nondistributable-artifacts", "--docker-empty-base", "--flatten"}


def _operands(args, val, boolean):
    """(positional operands, unknown option or None) of a skopeo / crane verb's arguments."""
    pos, i = [], 0
    while i < len(args):
        a = args[i]
        if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)", a):     # a redirection
            i += 1 if re.match(r"^[0-9]*(<<?-?|>>?|<>|&>)[^<>]", a) else 2
            continue
        if a.startswith("-") and a != "-":
            name = a.split("=", 1)[0]
            if name in val:
                i += 1 if "=" in a else 2
                continue
            if name in boolean:
                i += 1
                continue
            return pos, a
        pos.append(a)
        i += 1
    return pos, None


def _mask_shell(text, info=None):
    """(no_comments, blanked, open_quote): TWO copies of `text`, each the same length with every newline in place so
    positions and line numbers line up. no_comments has every real comment replaced by spaces; blanked also has every
    quoted string's CONTENT (and every backslash-escaped character) replaced by spaces. Quote state runs across the whole
    text, never reset per line (Sonnet #164 r17, B2 / Codex r17, B01: a quoted string spanning lines hid a real
    keyword from a per-line scan and fabricated one from its second line), and a `#` starts a comment only at the start
    of a word, never inside one (`hello#world`, `${#x}`, `$#`). open_quote is True when a quote is still open at the end:
    the text cannot be read with confidence, so the caller denies trust (fail closed, advisor 0080)."""
    n, q, i = len(text), None, 0
    nc, bl = list(text), list(text)
    def blank(k):
        if text[k] != "\n":
            bl[k] = " "
    while i < n:
        c = text[i]
        if q is not None and c == "\n" and info is not None:
            info["nl_in_quote"] = True
        if q == "'":
            if c == "'":
                q = None
            else:
                blank(i)
        elif q == '"':
            if c == "\\" and i + 1 < n:
                blank(i); blank(i + 1); i += 2
                continue
            if c == '"':
                q = None
            else:
                blank(i)
        elif c == "\\" and i + 1 < n:
            blank(i); blank(i + 1); i += 2
            continue
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;&|()<>"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                nc[k] = bl[k] = " "
            i = j
            continue
        i += 1
    return "".join(nc), "".join(bl), q is not None


def _dockerfiles(tree, dockerfile):
    """The tree's files a build's Dockerfile argument names: a literal path exactly, or a template (`Dockerfile.${v}`)
    matched against every file name in the tree (all of which must then be pinned)."""
    entries = [e for e, kind in (getattr(tree, "entries", {}) or {}).items() if kind == "file"]
    name = dockerfile or "Dockerfile"
    if _variable(name):
        parts = re.split(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", _base(name))
        pat = re.compile(".+".join(re.escape(x) for x in parts) + "$")
        return [e for e in entries if pat.match(_base(e))]
    return [name] if name in entries else []   # a literal path names exactly one repository file (NEW-3: no decoys)


READ_ONLY = {"cat", "head", "tail", "grep", "egrep", "fgrep", "diff", "cmp", "sha256sum", "shasum", "sha1sum",
             "md5sum", "wc", "test", "[", "ls", "stat", "file", "echo", "printf", ":"}
READ_ONLY_GIT = {"show", "diff", "log", "ls-files", "cat-file", "hash-object", "status"}


def _name_pattern(name):
    base = _base(name)
    if _variable(base):
        parts = re.split(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*", base)
        return ".+".join(re.escape(x) for x in parts)
    return re.escape(base)


def _touches(script, name, consumer):
    """True when any command other than the consumer (the build that reads this Dockerfile, the pip install that
    reads this -r file) or a read-only command without a write redirection names the file — an allow-list, so curl -o,
    python -c, dd of=, sed -i, rsync … all count (Sonnet #164 r5, NEW-5/NEW-6)."""
    import shlex
    mention = re.compile(r"(^|[^A-Za-z0-9._-])" + _name_pattern(name) + r"($|[^A-Za-z0-9._-])")
    text, inner = _cut_substitutions(re.sub(r"\\\n", "", script))
    for sub in inner:
        if _touches(sub, name, consumer):
            return True
    for chunk in _split_commands(text):
        toks = _tokens(chunk)
        if _fills_dir(toks, name, script):     # writes into the file's directory without naming it (C11)
            return True
        if not any(mention.search(t) for t in toks):
            continue
        redirects = any(mention.search(t) for t in _redirect_targets(chunk))
        if consumer(toks) and not redirects:   # the consumer itself must not write the file (C11)
            continue
        words = [t for t in toks if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=.*", t) and t != "sudo"]
        while words and words[0] in ("if", "then", "elif", "else", "while", "until", "do", "!", "{", "time"):
            words = words[1:]                   # a shell keyword arranges the command after it
        if words and words[0] in ("for", "select", "case"):
            continue                            # a loop's / case's word list only names things
        cmd = _base(words[0]) if words else ""
        writes = any(mention.search(t) for t in _redirect_targets(chunk))
        read_only = cmd in READ_ONLY or (cmd == "git" and len(words) > 1 and words[1] in READ_ONLY_GIT)
        if cmd in ("cp", "rsync", "install") and not writes:
            pos = [t for t in words[1:] if not t.startswith("-")]
            # copying the repository's own file INTO a build context (cp build/docker/Dockerfile.* /tmp/ctx/): the name
            # appears only in relative, non-variable sources, never in the destination; any other write under the name
            # is itself a finding, so a relative source can only be the committed file
            if len(pos) >= 2 and not mention.search(pos[-1]) and all(
                    not mention.search(t) or (not t.startswith("/") and not _variable(t) and SUBST not in t) for t in pos[:-1]):
                continue
        if writes or not read_only:
            return True
    return False


OUTSIDE = ("$RUNNER_TEMP", "${RUNNER_TEMP}", "/", "$(mktemp")   # outside the checkout: never the file's directory


def _outside(target, script, depth=0):
    """A destination that cannot be the checkout's directory: an absolute path outside the runner's workspace, a path
    under $RUNNER_TEMP or a fresh $(mktemp …), or a variable every assignment of which in the job is one of those —
    followed through other variables (f="$work/x", work=$(mktemp -d))."""
    if target.startswith(("/home/runner/work", "/github/workspace")):
        return False                                     # the checkout's own absolute path (Codex #164 r3, C11)
    if target.startswith(OUTSIDE):
        return True
    if re.match(r"[\"']?\$\{?HOME\}?/(?!work(/|$))", target):
        return True                                      # $HOME/.docker …: the workspace is under $HOME/work
    m = re.match(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?(/.*)?$", target.strip("\"'"))
    if not m or depth > 4:
        return False
    values = re.findall(r"(?:^|[\s;(])" + m.group(1) + r"=[\"']?([^\s\"';)]*)", script)
    return bool(values) and all(_outside(v, script, depth + 1) for v in values)


def _redirect_targets(chunk):
    """The files a command's output redirections write, read outside quotes as bash reads them — attached too
    (printf 'x'>Dockerfile; Codex #164 r3, C11). `>&2` / `2>&1` duplicate a descriptor and write no file."""
    out, i, q, n = [], 0, None, len(chunk)
    while i < n:
        c = chunk[i]
        if q:
            if c == "\\" and q == '"':
                i += 1
            elif c == q:
                q = None
        elif c == "\\":
            i += 1
        elif c in "'\"":
            q = c
        elif c == ">":
            j = i + 1 + (chunk[i + 1:i + 2] in (">", "|"))
            if chunk[j:j + 1] == "&":
                i = j + 1
                continue
            while j < n and chunk[j] in " \t":
                j += 1
            m = re.match(r"(\"[^\"]*\"|'[^']*'|[^\s;&|<>]+)", chunk[j:])
            if m:
                out.append(m.group(1).strip("\"'"))
                i = j + len(m.group(1))
                continue
        i += 1
    return out


def _fills_dir(toks, name, script=""):
    """True when a copy, move, sync, archive extraction, git checkout or patch writes into the directory that holds
    `name` (or into a directory this check cannot place): it can replace the file without spelling its name (Codex #164
    adversarial r1, C11)."""
    words = _command_words(toks)
    if not words:
        return False
    cmd, rest = _base(words[-1]), toks[toks.index(words[-1]) + 1:]   # through env / sudo … (Codex r2, C11)
    where = os.path.normpath(os.path.dirname(name) or ".")
    pos = [t for t in rest if not t.startswith("-") and not re.match(r"^[0-9]*(<|>|&>)", t)]

    def hits(target):
        if re.match(r"[\"']?(/home/runner/work|/github/workspace)(/|$)", target):
            return True                                  # the checkout's own absolute path (Codex #164 r3, C11)
        if _outside(target, script):
            return False
        t = os.path.normpath(target.rstrip("/") or "/")
        # the file's directory or any directory above it (cp -R evil/. . replaces safe/Dockerfile too; Codex r2, C11)
        return _variable(target) or SUBST in target or t in (where, ".") or where.startswith(t + "/")
    if cmd in ("cp", "mv", "rsync", "install", "ln") and len(pos) >= 2:
        # `cp -R dir dest` makes dest/dir; only dir/. , dir/* or rsync's dir/ put dir's CONTENTS into dest
        if all(not re.search(r"/(\.|\*)?$", src) for src in pos[:-1]) and cmd in ("cp", "rsync") \
                and any(t in rest for t in ("-R", "-r", "-a", "--recursive", "--archive")):
            return any(hits(pos[-1].rstrip("/") + "/" + _base(src.rstrip("/"))) for src in pos[:-1])
        return hits(pos[-1])
    if cmd == "tar" and any(re.match(r"^-?[a-zA-Z]*x", t) or t == "--extract" for t in rest[:2]):
        c = rest[rest.index("-C") + 1] if "-C" in rest[:-1] else next(
            (t.split("=", 1)[1] for t in rest if t.startswith("--directory=")), ".")
        return hits(c)
    if cmd == "unzip":
        return hits(rest[rest.index("-d") + 1] if "-d" in rest[:-1] else ".")
    if cmd == "git" and pos[:1] and pos[0] in ("checkout", "restore", "apply", "am", "pull", "merge", "reset", "stash",
                                               "switch", "cherry-pick", "rebase", "revert", "clone", "worktree"):
        return pos[0] != "clone" or len(pos) < 3 or hits(pos[-1])
    if cmd == "patch":
        return True
    return False


def _is_build(toks):
    """The consuming build: its program is docker / podman / nerdctl with `build`, and it writes nothing (C11)."""
    words = _command_words(toks)
    return bool(words) and _base(words[0]) in ("docker", "podman", "nerdctl") and "build" in toks


def _is_pip_reading(toks):
    words = _command_words(toks)
    return bool(words) and re.match(r"^(pip3?|python3?)(\.[0-9]+)?$", _base(words[0])) is not None and \
        any(t in ("-r", "--requirement") or t.startswith(("--requirement=", "-r")) for t in toks) and \
        any(t in ("install", "download", "wheel", "sync") for t in toks)


def _pip_req_files(script):
    """(command, path) for every -r file a pip / python -m pip / uv pip install reads."""
    out = []
    for t in _commands(script):
        cmd, args = t[0], t[1:]
        if re.match(r"^python3?(\.[0-9]+)?$", cmd):    # -m pip, -mpip, -Im pip, -m pip.__main__ (Codex r3, C11)
            kind, mod, rest = _python_run(args)
            if kind != "module" or (mod or "").split(".")[0] != "pip":
                continue
            cmd, args = "python -m pip", rest
        if cmd == "uv" and args[:1] == ["pip"]:
            cmd, args = "uv pip", args[1:]
        if not (re.match(r"^pip3?(\.[0-9]+)?$", cmd) or cmd in ("python -m pip", "uv pip")):
            continue
        if not any(v in args for v in ("install", "download", "wheel", "sync")):
            continue
        for k, a in enumerate(args):
            if a in ("-r", "--requirement") and k + 1 < len(args):
                out.append((cmd, args[k + 1]))
            elif a.startswith("--requirement="):
                out.append((cmd, a.split("=", 1)[1]))
            elif a.startswith("-r") and len(a) > 2 and not a.startswith("--"):
                out.append((cmd, a[2:]))
    return out


def _local_path(x):
    """A plain relative or absolute filesystem path: no scheme, no git address, no variable or substitution."""
    return not (_variable(x) or "://" in x or x.startswith(("git@", "github.com/", "gitlab.com/", "bitbucket.org/"))
                or re.search(r"\.git(#.*)?$", x) or re.match(r"^[A-Za-z0-9.-]+\.[a-z]{2,}/", x))


def check_dockerfile(text):
    """Every image a build fetches is a digest, scratch or an earlier stage; anything else (a tag, a variable) is
    returned. Read as BuildKit reads it (Codex #164 adversarial r1, C08/C09): a FROM's base is resolved against the stages
    BEFORE its own name is added; COPY/ADD --from and RUN --mount from= name images too; a `# syntax=` parser directive
    and an ARG BUILDKIT_SYNTAX select the frontend image that runs the build; ONBUILD instructions are read as well."""
    stages, bad, n, header = set(), [], 0, True

    def ok(ref):
        r = ref.lower()
        return r in stages or r == "scratch" or (r.isdigit() and int(r) < n) or (
            DIGEST_REF.search(ref) is not None and not _variable(ref))
    for line in re.sub(r"\\\n", " ", text).splitlines():
        directive = re.match(r"(?i)^\s*#\s*syntax\s*=\s*(\S+)", line)
        if directive and header:
            if not ok(directive.group(1)):
                bad.append(directive.group(1))
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        header = False
        body = re.sub(r"(?i)^\s*ONBUILD\s+", "", line)
        m = re.match(r"(?i)^\s*FROM\s+(.*)$", body)
        if m:
            words = [w for w in m.group(1).split() if not w.startswith("--")]
            if not words:
                continue
            if words[0].isdigit() or not ok(words[0]):   # a number in FROM is an image name, never a stage (r3, C08)
                bad.append(words[0])
            if len(words) >= 3 and words[1].lower() == "as":
                stages.add(words[2].lower())
            n += 1
            continue
        arg = re.match(r"(?i)^\s*ARG\s+BUILDKIT_SYNTAX=(\S+)", body)
        if arg and not ok(arg.group(1).strip("'\"")):
            bad.append(arg.group(1))
        for src in re.findall(r"(?i)--from=(\S+)", body) + re.findall(r"(?i)--mount=\S*?\bfrom=([^,\s]+)", body):
            if not ok(src.strip("'\"")):
                bad.append(src)
    return bad


DAEMON_ENV = re.compile(r"(^|[\s;&|(])(export\s+)?(DOCKER_HOST|DOCKER_CONTEXT|BUILDKIT_HOST|DOCKER_CONFIG)=(\S*)")


DAEMON_SET = re.compile(r"(?<![$\w{])(DOCKER_HOST|DOCKER_CONTEXT|BUILDKIT_HOST)\b(?!\s*[}:])")


def daemon_redirects(text):
    """DOCKER_HOST / DOCKER_CONTEXT / BUILDKIT_HOST set anywhere, or DOCKER_CONFIG set to anything but a fresh
    $(mktemp -d), point later commands at another daemon or credential/context set (Sonnet #164 r13, NEW-18)."""
    out = []
    # any mention of the daemon variables as a word (printf -v NAME, read NAME, declare NAME, export NAME …) can set
    # them; only expansions ($DOCKER_HOST, ${DOCKER_HOST}) are reads (Codex r2, C13)
    out += [m.group(1) for m in DAEMON_SET.finditer(text) if m.group(1) not in out]
    if re.search(r"(?<![$\w{])(?<!export )(?<!unset )DOCKER_CONFIG\b(?!\s*[}:=])", text):
        out.append("DOCKER_CONFIG")                      # printf -v / read … DOCKER_CONFIG; export / unset are fine
    for m in DAEMON_ENV.finditer(text):
        name, value = m.group(3), m.group(4)
        if name == "DOCKER_CONFIG" and value.rstrip(";") == "$(mktemp":
            continue
        out.append(name)
    return out


# Documented exclusion (advisor 0094 asks every exclusion to carry its reason): a committed TEST HARNESS a step runs is
# not read recursively. The harnesses of this very checker and of the auditor must contain, as literal fixture data, the
# constructs the checker refuses (DOCKER_HOST=…, alias, docker pull alpine); they write fixtures and run the code under
# test, never a container. They are committed files, and every diff that adds or changes one gets both reviewers.
TEST_HARNESS = re.compile(r"^(\.github/agent/tests/[^/]+\.sh|bin/[^/]+-test\.sh)$")   # exactly these roots (Codex r2, R03)


HEREDOC = re.compile(r"(?<!<)<<(-?)(?!<)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def _heredoc_marks(lines):
    """For each line, the HEREDOC matches bash reads as operators: outside quotes and comments, inside $( ) and `…`
    too, with quote state carried across lines (Codex #164 r3, N01: `# <<EOF` and `echo '<<EOF'` start nothing).
    An unbalanced quote makes later markers unseen, so their bodies are read as shell: stricter, never looser."""
    stack, marks = [], []
    for line in lines:
        found, i, n = [], 0, len(line)
        while i < n:
            c, top = line[i], (stack[-1] if stack else None)
            if top == "'":
                if c == "'":
                    stack.pop()
            elif top == '"':
                if c == "\\":
                    i += 1
                elif c == '"':
                    stack.pop()
                elif line.startswith("$(", i):
                    stack.append("(")
                    i += 1
                elif c == "`":
                    stack.append("`")
            else:
                if c == "\\":
                    i += 1
                elif c == "#" and (i == 0 or line[i - 1] in " \t;(|&"):
                    break                                  # a comment: the rest of the line
                elif c in "'\"":
                    stack.append(c)
                elif line.startswith("$(", i):
                    stack.append("(")
                    i += 1
                elif c == "(" and top == "(":
                    stack.append("(")
                elif c == ")" and top == "(":
                    stack.pop()
                elif c == "`":
                    if top == "`":
                        stack.pop()
                    else:
                        stack.append("`")
                elif line.startswith("<<", i) and not line.startswith("<<<", i) and (i == 0 or line[i - 1] != "<"):
                    m = HEREDOC.match(line, i)
                    if m:
                        found.append(m)
                        i = m.end()
                        continue
            i += 1
        marks.append(found)
    return marks


def _drop_foreign_heredocs(text):
    """A heredoc body is data for its command, not commands (advisor 0084 (1)): it is not parsed as shell. Only what
    bash runs inside it stays — the $( … ) and `…` substitutions of an unquoted-delimiter body. A heredoc fed to a shell
    (bash <<EOF) is refused as a shell reading stdin; other-language heredocs are the documented boundary (0094)."""
    lines, out, i = text.split("\n"), [], 0
    marks = _heredoc_marks(lines)
    while i < len(lines):
        line, found = lines[i], marks[i]
        out.append(line)
        i += 1
        for m in found:                                  # bash's operators only: inside $(cat <<EOF …) too
            body = []
            while i < len(lines) and (lines[i].strip() if m.group(1) else lines[i]) != m.group(3):
                body.append(lines[i])
                i += 1
            i += 1                                       # the delimiter line
            if not m.group(2):                           # unquoted: substitutions in the body run, quotes or not
                out += ["$(%s)" % x for x in _cut_substitutions("\n".join(body), data=True)[1]]
    return "\n".join(out)


# Documented exclusions of a non-committed script a step runs (each with its reason, handoff 0023):
# Fenced (advisor 0084 (4)): exactly these two files of that one workflow; bin/k8s-harness-fence-test.sh proves both
# are written only from docs/kubernetes.md at the checked-out commit (no env, no network, no other input), and any
# other eval of a variable, anywhere, is refused by the variable-program rule.
GENERATED_OK = {
    (".github/workflows/stage-acceptance-k8s.yml", "/tmp/smoke-assert.sh"):
        "the documented smoke commands of docs/kubernetes.md (committed, reviewed), written by the step's own python "
        "heredoc; they assert against the kind cluster and fetch nothing",
    (".github/workflows/stage-acceptance-k8s.yml", "/tmp/pf-forward.sh"):
        "the documented kubectl port-forward command of docs/kubernetes.md, written by the same heredoc; run verbatim "
        "because rule 12 tests the customer's commands exactly as published",
}


def _resolve_script(path, text, entries):
    """A script path as a committed file: relative (./x), under $GITHUB_WORKSPACE, or a COPY that a real
    `git show <ref>:<file> > <dir>/<name>` or `gh api repos/${GITHUB_REPOSITORY}/contents/<file>?ref=main` command of the
    job writes (main's copy of a reviewed script; Codex #164 r2, C02: an echo of the words, another repository, or a second
    write of the copy do not count). <dir> is $RUNNER_TEMP or a directory under /tmp, and the write may be in another step
    of the job than the run (main's own stage-admission.yml writes /tmp/policy/<name> in one step and runs it in the next;
    Sonnet #164 r20, B2). None otherwise."""
    rel = re.sub(r"^(\$\{?GITHUB_WORKSPACE\}?/|\./)", "", path)
    if entries.get(rel) == "file":
        return rel
    m = re.match(r"^(\$\{?RUNNER_TEMP\}?|/tmp(?:/[\w.-]+)*)/([\w.-]+)$", path)
    if not m:
        return None
    d, base = m.group(1), m.group(2)
    dpat = r"\$\{?RUNNER_TEMP\}?" if d.startswith("$") else re.escape(d)
    dst = r">\s*\"?" + dpat + r"/(" + re.escape(base) + r"|\$\(basename[^)]*\))"
    writes = len(re.findall(dst + r"\"?", text))
    if writes != 1:
        return None
    lines = [ln for ln in re.sub(r"\\\n", " ", text).splitlines() if re.search(dst, ln)]
    pipes = [p for ln in lines for p in re.split(r"\s*(?:;|&&|\|\|)\s*", ln) if re.search(dst, p)]
    for chunk in [c for p in pipes for c in _split_commands(p)]:  # the fetch must be in the pipeline that writes it (r3)
        toks = chunk.split()
        if toks[:2] == ["git", "show"]:
            g = re.search(r"(\S+?):([\w./-]+)\s*>\s*\"?" + dpat + r"/" + re.escape(base) + r"\"?\s*$", chunk.strip())
            # only main's copy (or the checked commit's) is the reviewed file (Codex #164 r3, C02: git show attacker:x)
            if g and g.group(1) in ("origin/main", "main", "HEAD", "$GITHUB_SHA", "${GITHUB_SHA}") \
                    and entries.get(g.group(2)) == "file" and _base(g.group(2)) == base:
                full = re.compile(dpat + r"/" + re.escape(base) + r"(?![\w.-])")
                for ln in re.sub(r"\\\n", " ", text).splitlines():
                    if not full.search(ln) or re.search(dst, ln):
                        continue
                    bare = full.sub("PATH", ln)          # the file's own name (install-scanner.sh) is not a command
                    if re.search(r"(?<![\w.-])(?:sed\s+-\w*i|perl\s+-\w*i|awk\s+-i|cp|mv|ln|install|tee|dd|rsync|curl|wget|truncate|patch|ed|ex)(?![\w.-])", bare) \
                            or re.search(r">>?\s*\"?" + dpat + r"/" + re.escape(base), ln):
                        return None      # something else writes the copy (sed -i, cp, mv, tee ...): it is not main's committed bytes
                return g.group(2)
        if toks[:2] == ["gh", "api"]:
            g = re.search(r"\"?repos/\$\{?GITHUB_REPOSITORY\}?/contents/([^\"?\s]+)\?ref=main\"?", chunk)
            if not g:
                continue
            want = g.group(1)
            if re.fullmatch(r"\$\{?f\}?", want):          # for f in <committed files>; do gh api …/${f}?ref=main
                lists = re.findall(r"\bfor\s+f\s+in\s+([^;\n]*?)\s*;\s*do\b", text)
                cands = [x for lst in lists for x in lst.split() if _base(x) == base and entries.get(x) == "file"]
                if len(cands) == 1:
                    return cands[0]
            elif entries.get(want) == "file" and _base(want) == base:
                return want
    return None


READ_SCRIPTS = []                                       # the committed scripts _run_scripts read, for check_runs


def _all_texts(text, depth=0):
    """The text and every script it hands to a shell: $( ) bodies, bash -c / sh -c strings, eval arguments — so a write
    made through any of them counts (Codex #164 r3, C02: bash -c "printf … > ci-ok.sh")."""
    import shlex
    body, inner = _cut_substitutions(text)
    out = [text]
    if depth >= 6:
        return out
    for sub in inner:
        out += _all_texts(sub, depth + 1)
    for chunk in _split_commands(body):
        try:
            toks = shlex.split(_mask_shell(chunk)[0], comments=False)    # comments off the same way _tokens() does
        except ValueError:
            continue
        words = _command_words(toks)
        if words and _base(words[-1]) in TOOLS:
            continue                                     # docker run … sh -c '…' runs in the container, not here
        for i, w in enumerate(toks):
            c = next((j for j in range(i + 1, len(toks)) if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", toks[j])), None) \
                if _base(w) in SHELLS else None
            if c is not None and c + 1 < len(toks):
                out += _all_texts(toks[c + 1], depth + 1)
                break
            if w == "eval" and toks[i + 1:]:
                out += _all_texts(" ".join(toks[i + 1:]), depth + 1)
                break
    return out


SHELL_SHEBANG = re.compile(r"#!\s*\S*/(?:env\s+(?:-\S+\s+)*)?(ba|da|z)?sh\b")


def _writes(script, rel, ctx=None):
    """True when a command of the job writes the exact file rel before it runs: a redirection onto it, tee, cp / mv /
    install / ln / rsync onto it, sed / perl -i on it, or a copy or extraction over its directory (_fills_dir)."""
    import shlex
    text, inner = _cut_substitutions(re.sub(r"\\\n", "", script))
    ctx = script if ctx is None else ctx                # where the job assigns its variables (f="$work/x" …)
    for sub in inner:
        if _writes(sub, rel, ctx):
            return True
    same = lambda t: os.path.normpath(re.sub(r"^\./", "", t.strip("'\""))) == rel
    for chunk in _split_commands(text):
        toks = _tokens(chunk)
        if any(same(t) for t in _redirect_targets(chunk)):
            return True
        words = _command_words(toks)
        if not words:
            continue
        cmd, rest = _base(words[-1]), toks[toks.index(words[-1]) + 1:]
        pos = [t for t in rest if not t.startswith("-")]
        if (cmd == "tee" and any(same(t) for t in pos)) or (cmd in ("cp", "mv", "install", "ln", "rsync") and pos and
                                                              same(pos[-1])) or \
                (cmd in ("sed", "perl") and any(t.startswith("-i") for t in rest) and any(same(t) for t in pos)) or \
                _fills_dir(toks, rel, ctx):
            return True
    return False


def _made_executable(script, path):
    """How the job makes path, if it does: downloads it (curl -o / wget -O), writes it (a redirection, cp, tee …), or
    makes it executable (chmod). A program the job made this way is a script this check cannot read."""
    p = re.escape(path)
    if re.search(r"(?<![\w./-])chmod\b[^\n;&|]*\s[\"']?" + p + r"[\"']?(\s|$|;)", script):
        return "makes executable (chmod)"
    for chunk in _split_commands(_cut_substitutions(script)[0]):    # a downloader's output file (not go build -o)
        words = _command_words(chunk.split())
        if words and _base(words[-1]) in ("curl", "wget", "aria2c") and re.search(
                r"(?:\s-o|\s-O|--output(?:-document)?(?:=|\s))\s*[\"']?" + p + r"[\"']?(\s|$)", chunk):
            return "downloads"
    if _writes(script, path.lstrip("./") if not path.startswith("/") else path):
        return "writes"
    return None


def _run_scripts(text, tree, moved, depth=0, where="", job=""):
    """(the committed shell scripts this text runs, their bytes appended; findings). A script is what _commands names as
    run — bash/sh/dash/zsh <path>, source / . <path>, or a path executed directly that is a *.sh file or a committed file
    starting with a shell #! (#!/usr/bin/env bash too) or none — through every channel _commands reads (wrappers, $( ),
    -c, eval). It is read at its committed bytes, recursively, with its own cd carried into what it runs; one that is not
    a committed file, a variable path, a script the job changes before it runs, or nesting past the depth limit is
    refused (Codex #164 adversarial r1 C02, r2 C02; advisor 0094)."""
    added, found = [], []
    entries = getattr(tree, "entries", {}) or {}
    for t in _commands(text):
        if t[0] == "__globexec__":
            import fnmatch
            pat = re.sub(r"^(\$\{?GITHUB_WORKSPACE\}?/|\./)", "", t[1])
            if "[:" in pat or any(fnmatch.fnmatchcase(e, pat) for e, k in entries.items() if k == "file"):
                found.append("runs %s, a glob that names a committed file; what it runs cannot be bound, refused" % t[1])
            continue
        if t[0] == "__foreign__":
            rel = re.sub(r"^(\$\{?GITHUB_WORKSPACE\}?/|\./)", "", t[1])
            if entries.get(rel) != "file" and _resolve_script(t[1], job or text, entries) is None:
                found.append("runs %s with another language's interpreter, and it is not a committed file; refused "
                             "(handoff 0094: only committed files and heredocs are the boundary)" % t[1])
            continue
        if t[0] not in ("__script__", "__exec__"):
            continue
        path = t[1]
        if path in ("-", "/dev/stdin"):
            continue
        if t[0] == "__exec__":
            rel = re.sub(r"^(\$\{?GITHUB_WORKSPACE\}?/|\./)", "", path)
            if entries.get(rel) != "file":
                made = _made_executable(job or text, path)
                if made:                                 # downloaded / written / chmod-ed by the job (Sonnet r23, NEW-35)
                    found.append("runs %s, which the job %s; what it runs cannot be read, refused" % (path, made))
                    continue
                if not path.endswith(".sh"):
                    continue                             # a program, not a script of this repository
            elif tree.read(rel).startswith("#!") and not SHELL_SHEBANG.match(tree.read(rel)):
                continue                                 # another language: the documented boundary (0094)
        if (where.split(".jobs.", 1)[0], path) in GENERATED_OK:
            # fenced: written only by the step's python heredoc; a shell write anywhere in the job breaks the fence
            # (Codex #164 r3, N04; proven by .github/agent/tests/k8s-harness-fence-test.sh)
            if any(_writes(t, path) or re.search(r"(^|[\s;|&])(cp|mv|ln|install|tee|rsync|dd|tar|unzip|curl|wget)\b[^\n;|&]*"
                                                  + re.escape(path), t) for t in _all_texts(job or text)):
                found.append("%s is fenced as written only by its python heredoc, and a shell command of the job "
                             "writes it; refused" % path)
            continue
        rel = _resolve_script(path, job or text, entries)
        if rel is None and (_variable(path) or SUBST in path):
            found.append("runs a shell script named by a variable (%s); it cannot be read, refused" % path)
            continue
        if rel is None:
            found.append("runs %s, which is not a committed file; its commands cannot be read, refused" % path)
            continue
        if moved and not path.startswith(("/", "$")):
            found.append("runs %s from a working directory this check cannot place; refused" % path)
            continue
        READ_SCRIPTS.append((rel, tree.read(rel)))       # bound to its committed bytes after inlining (check_runs)
        if TEST_HARNESS.search(rel):
            continue                                     # a test harness: its probes are fixture data (documented)
        if depth >= 4:
            found.append("scripts nest deeper than this check reads (%s); refused" % path)
            continue
        content = tree.read(rel)
        inner = _drop_foreign_heredocs(_decode_dollar_quotes(_expand_defaults(re.sub(r"\\\n", "", content))))
        cd = bool(re.search(r"(?<![\w./$-])(cd|pushd)(?![\w./-])", _unquoted(inner)))
        more, also = _run_scripts(inner, tree, cd, depth + 1, where, job)
        added.append(content + ("\n" + more if more else ""))
        found += also
    return "\n".join(added), found


def check_runs(where_job, scripts, bad, tree=None):
    """scripts: [(where, text, shell)] of ONE job (or one composite action), in order. No image name this job built or tagged is
    trusted (the owner's rule, Oct 3: every image is pinned by digest; reference a build you made by its image id, e.g. --iidfile, or
    a digest). A step in a non-POSIX shell that names a container or package tool is a finding: this
    check reads POSIX shell only (Sonnet B8)."""
    def read(raw):
        return _drop_foreign_heredocs(_decode_dollar_quotes(_expand_defaults(re.sub(r"\\\n", "", raw))))
    posix = [not item[2] or re.match(r"^(bash|sh)(\s|$)", item[2]) for item in scripts]
    # steps of one job share a workspace: a file changed in ANY step of the job counts (Sonnet #164 r6, NEW-7); the
    # committed scripts they run are part of it (Codex #164 r2, C11)
    job0 = "\n".join(read(item[1]) for item, ok in zip(scripts, posix) if ok)
    for item, ok in zip(scripts, posix):
        marked = _drop_foreign_heredocs(_decode_dollar_quotes(_mark_defaults(re.sub(r"\\\n", "", item[1]))))
        for t in (_commands(marked) if ok else []):
            if t[0] == "__variable_program__" and PARAM_WORD.search(item[1]):
                bad.append(f"{item[0]}: a program is named by a variable with a default ({t[1]}); bash runs the "
                           f"variable when it is set, which cannot be read, refused (Codex #164 r3, N03)")
                break
    inlined = []
    for item, ok in zip(scripts, posix):
        where, raw = item[0], item[1]
        wdir = item[3] if len(item) > 3 else None
        # a working directory this check cannot place in the repository: a step/job/workflow working-directory, or a
        # cd / pushd in the script — a literal relative path then resolves somewhere else (Sonnet #164 r16, NEW-24).
        # The word anywhere counts, quoted or nested in sh -c / eval: fail closed (Sonnet #164 r17, NEW-25)
        moved = bool(wdir) or bool(re.search(r"(?<![\w./$-])(cd|pushd)(?![\w./-])", _unquoted(read(raw))))
        inlined.append(_run_scripts(read(raw), tree, moved, 0, where, job0) if ok else ("", []))

    job_text = job0 + "".join("\n" + read(m) for m, _ in inlined if m)
    # every committed script read for this job must run as committed: nothing in the job, its -c / eval strings or the
    # scripts it runs writes it first (Codex #164 r3, C02 — after inlining, over normalized paths, harnesses included)
    read_scripts = dict(READ_SCRIPTS)
    for rel in sorted(read_scripts):
        # what writes it before it runs: the job's own text or ANOTHER script it runs (its own later writes do not count)
        # a harness's own text is fixture data here as everywhere (documented); a write TO a harness still counts
        others = [read(c) for r, c in read_scripts.items() if r != rel and not TEST_HARNESS.search(r)]
        lines = job0.split("\n")                        # only what runs before the script's first RUN
        norm = lambda p: re.sub(r"^(\$\{?GITHUB_WORKSPACE\}?/|\./)", "", p)
        k = next((n for n, ln in enumerate(lines) if any(t[0] in ("__script__", "__exec__") and norm(t[1]) == rel
                                                          for t in _commands(ln))), len(lines))
        before = "\n".join(lines[:k + 1])               # the run's own line too (printf … > x; bash x)
        if any(_writes(t, rel, src) for src in [before] + others for t in _all_texts(src)):   # each in its own context
            bad.append(f"{scripts[0][0] if scripts else where_job}: {rel} is changed by the job before it runs; the "
                       f"committed bytes are not what runs, refused")
    READ_SCRIPTS.clear()
    for item, (more, also) in zip(scripts, inlined):
        where, raw, shell = item[:3]
        wdir = item[3] if len(item) > 3 else None
        bad += [f"{where}: {x}" for x in also]
        own = read(raw)
        raw = raw + ("\n" + more if more else "")     # the scripts' commands are checked as this step's own
        text = read(raw)
        moved = bool(wdir) or bool(re.search(r"(?<![\w./$-])(cd|pushd)(?![\w./-])", _unquoted(text)))
        for name in daemon_redirects(_unquoted(text)):
            bad.append(f"{where}: sets {name}, which points docker or buildx at another daemon or context; refused")
        if ALIASING.search(_unquoted(text)):
            bad.append(f"{where}: defines an alias; the command it hides cannot be checked, refused")
        if _ansi_c_hidden(raw):
            bad.append(f"{where}: ANSI-C quoting ($'...') with an escape other than \\n \\t \\r can spell any word; refused")
        if RENAMED.search(_unquoted(text)):
            bad.append(f"{where}: copies, links or aliases a container or package tool under another name; the "
                       f"renamed command cannot be checked")
        if shell and not re.match(r"^(bash|sh)(\s|$)", shell):
            # this check reads POSIX shell only, and pwsh / python / node ship on ubuntu runners too: a step in any
            # other shell is refused outright, whatever it contains (Sonnet #164 r10, NEW-12; advisor 0080)
            bad.append(f"{where}: a `{shell}` step; this check reads POSIX shell only and refuses any other shell")
            continue
        for ev in [e for e in script_images(read(more)) if e[0] != "local"] + script_images(own) if more else \
                script_images(own):
            if ev[0] in ("local", "unlocal"):
                continue        # a locally built or tagged name is never trusted (see below): nothing to register
            elif ev[0] == "tag":
                src, dst = ev[1], ev[2]
                if not (_variable(src) or DIGEST_REF.search(src)):
                    # an image ID from a loaded tarball, or an unpinned name: never "our own bytes" (NEW-21); a name this job built is
                    # not trusted either, so tagging it is refused too
                    bad.append(f"{where}: `docker tag` makes {dst!r} from {src!r}, which is not pinned by digest; refused")
            elif ev[0] == "finding":
                bad.append(f"{where}: {ev[1]}")
            elif ev[0] == "build":
                dockerfile, context, named = ev[1], ev[2], ev[3]
                # the context, and every named context, must be a local path in this checkout (Sonnet #164 r15, NEW-23):
                # a URL, a git address or a computed value builds from bytes this check never sees
                remote = [x for x in [context] + named if x != "-" and not _local_path(x)]
                if remote:
                    bad.append(f"{where}: a build context is not a local path ({', '.join(repr(x) for x in remote)}); "
                               f"refused")
                    continue
                if dockerfile == "-" or (dockerfile is None and context == "-"):
                    bad.append(f"{where}: a build reads its Dockerfile from stdin; its FROM lines cannot be checked")
                    continue
                # without -f, docker reads <context>/Dockerfile (NEW-24)
                name = dockerfile or os.path.normpath(os.path.join(context, "Dockerfile"))
                if name.startswith("./"):
                    name = name[2:]
                if moved and not _variable(name):
                    bad.append(f"{where}: a build's Dockerfile ({name}) is a literal path read from a working directory "
                               f"this check cannot place (cd / working-directory); refused")
                    continue
                if name.startswith("/") or SUBST in name:
                    bad.append(f"{where}: a build's Dockerfile ({name}) is outside the repository, so its FROM lines "
                               f"cannot be checked")
                    continue
                if _touches(job_text, name, _is_build):
                    bad.append(f"{where}: the script writes a file named like its Dockerfile ({name}); the build "
                               f"cannot be bound to a reviewed file")
                    continue
                files = _dockerfiles(tree, name) if tree is not None else []
                if not files:
                    bad.append(f"{where}: a build's Dockerfile ({dockerfile or 'Dockerfile'}) is not a file in the "
                               f"repository, so its FROM lines cannot be checked")
                for f in files:
                    for img in check_dockerfile(tree.read(f)):
                        bad.append(f"{where}: {f} builds FROM an image not pinned by digest: {img!r}")
            else:
                _, c, img = ev
                if img is not None and SUBST in img:
                    bad.append(f"{where}: `{c}` takes its image from a command substitution; it cannot be checked")
                    continue
                if img is None or _variable(img) or DIGEST_REF.search(img) or False:
                    continue
                bad.append(f"{where}: `{c}` names an image not pinned by digest: {img!r} (an image this job built or tagged is not trusted by "
                           f"name either: run a build by the image id it wrote with --iidfile, or by a digest)")
        for c, why in script_installs(text):
            bad.append(f"{where}: `{c}`: {why}")
        for c, path in _pip_req_files(text):     # NEW-6: the hashes are only as good as the file they come from
            if SUBST in path:
                bad.append(f"{where}: `{c}` reads -r from a command substitution; it cannot be checked")
            elif _variable(path):
                continue                       # a variable: the review pass (documented boundary)
            elif path == "/dev/stdin":
                if "<<" not in text:
                    bad.append(f"{where}: `{c}` reads -r from stdin that is not a heredoc in this step")
            elif path.startswith("/"):
                bad.append(f"{where}: `{c}` reads -r from {path}, outside the repository")
            elif moved:                        # Sonnet #164 r17, NEW-26: resolved from a directory this check cannot place
                bad.append(f"{where}: `{c}` reads -r from {path}, a literal path read from a working directory this "
                           f"check cannot place (cd / working-directory); refused")
            elif tree is not None and "file" not in ((getattr(tree, "entries", {}) or {}).get(path.lstrip("./")),
                                                     (getattr(tree, "entries", {}) or {}).get(path)):   # a regular file (r24)
                bad.append(f"{where}: `{c}` reads -r from {path}, which is not a file in the repository")
            elif _touches(job_text, path, _is_pip_reading):
                bad.append(f"{where}: the script writes or changes {path}, the -r file `{c}` reads")


def _default_wd(node):
    """defaults.run.working-directory of a workflow or job mapping, or None."""
    m = {key_of(k): v for k, v in node.value} if isinstance(node, yaml.MappingNode) else {}
    d = m.get("defaults")
    r = {key_of(k): v for k, v in d.value}.get("run") if isinstance(d, yaml.MappingNode) else None
    w = {key_of(k): v for k, v in r.value}.get("working-directory") if isinstance(r, yaml.MappingNode) else None
    return w.value if isinstance(w, yaml.ScalarNode) else None


def _default_shell(node):
    """defaults.run.shell of a workflow or job mapping, or None."""
    m = {key_of(k): v for k, v in node.value} if isinstance(node, yaml.MappingNode) else {}
    d = m.get("defaults")
    r = {key_of(k): v for k, v in d.value}.get("run") if isinstance(d, yaml.MappingNode) else None
    sh = {key_of(k): v for k, v in r.value}.get("shell") if isinstance(r, yaml.MappingNode) else None
    return sh.value if isinstance(sh, yaml.ScalarNode) else None


def run_scripts(doc):
    """{job or composite: [(path, run text, shell)]} for every step run: GitHub executes, in order; shell is the
    step's own `shell:`, else its job's then its workflow's defaults.run.shell, else None (bash)."""
    groups = {}
    if not isinstance(doc, yaml.MappingNode):
        return groups
    top = {key_of(k): v for k, v in doc.value}

    def steps_of(seq, base, group, inherited, inherited_wd=None):
        if isinstance(seq, yaml.SequenceNode):
            for i, st in enumerate(seq.value):
                if isinstance(st, yaml.MappingNode):
                    m = {key_of(k): v for k, v in st.value}
                    run, sh, wd = m.get("run"), m.get("shell"), m.get("working-directory")
                    if isinstance(run, yaml.ScalarNode):
                        shell = sh.value if isinstance(sh, yaml.ScalarNode) else inherited
                        wdir = wd.value if isinstance(wd, yaml.ScalarNode) else inherited_wd
                        coe = m.get("continue-on-error")
                        soft = coe is not None and not (isinstance(coe, yaml.ScalarNode) and coe.value.strip() == "false")
                        ifn = m.get("if")
                        groups.setdefault(group, []).append((f"{base}[{i}].run", run.value, shell, wdir, "if" in m or soft,
                                                              ifn.value if isinstance(ifn, yaml.ScalarNode) else ""))
    jobs = top.get("jobs")
    if isinstance(jobs, yaml.MappingNode):
        for k, j in jobs.value:
            if isinstance(j, yaml.MappingNode):
                inherited = _default_shell(j) or _default_shell(doc)
                ro = {key_of(kk): vv for kk, vv in j.value}.get("runs-on")
                ro_text = yaml.serialize(ro) if ro is not None else ""
                if inherited is None and ("windows" in ro_text.lower() or "${{" in ro_text):
                    inherited = "pwsh"   # NEW-10: a Windows (or not statically known) runner's default shell is pwsh
                inherited_wd = _default_wd(j) or _default_wd(doc)
                for kk, vv in j.value:
                    if key_of(kk) == "steps":
                        steps_of(vv, f".jobs.{k.value}.steps", "jobs." + k.value, inherited, inherited_wd)
    runs = top.get("runs")
    if isinstance(runs, yaml.MappingNode):
        for kk, vv in runs.value:
            if key_of(kk) == "steps":
                steps_of(vv, ".runs.steps", "runs", None)
    return groups


UBUNTU_RUNNER = re.compile(r"^ubuntu-(latest|[0-9]+\.[0-9]+)(-arm)?$")


def check_runners(where, doc, bad):
    """The checker's scope is ubuntu runners (advisor 0080, closing the open-ended OS classes fail-closed): every job
    that runs steps must name one literally; another OS, a label list, a group, an expression or no runs-on at all is a
    finding — adding such a runner turns this check red before any Windows/macOS-only bypass can matter."""
    m = {key_of(k): v for k, v in doc.value} if isinstance(doc, yaml.MappingNode) else {}
    jobs = m.get("jobs")
    if not isinstance(jobs, yaml.MappingNode):
        return
    for k, j in jobs.value:
        jm = {key_of(kk): vv for kk, vv in j.value} if isinstance(j, yaml.MappingNode) else {}
        if "uses" in jm:
            continue                                  # a reusable-workflow call has no runner of its own
        ro = jm.get("runs-on")
        if not (isinstance(ro, yaml.ScalarNode) and UBUNTU_RUNNER.fullmatch(ro.value.strip())):
            shown = ro.value if isinstance(ro, yaml.ScalarNode) else ("missing" if ro is None else "not a plain label")
            bad.append(f"{where}.jobs.{k.value}.runs-on: {shown!r} is not an ubuntu runner; this check covers ubuntu "
                       f"runners only and refuses any other")


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
            if rel.startswith(".github/workflows/"):
                check_runners(rel, d, bad)
            # every mapping key of the parsed document — quoted, flow-style or block (Codex #164 r3, C13)
            stack = [d]
            while stack:
                n = stack.pop()
                if isinstance(n, yaml.MappingNode):
                    for k, v in n.value:
                        if isinstance(k, yaml.ScalarNode) and k.value in ("DOCKER_HOST", "DOCKER_CONTEXT", "BUILDKIT_HOST",
                                                                          "DOCKER_CONFIG"):
                            bad.append(f"{rel}: an env block sets {k.value}, which points docker or buildx elsewhere; "
                                       f"refused")
                        stack.append(v)
                elif isinstance(n, yaml.SequenceNode):
                    stack.extend(n.value)
            for group, scripts in run_scripts(d).items():
                check_runs(group, [(rel + item[0],) + tuple(item[1:]) for item in scripts], bad, tree)
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
