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
  services:  a mapping; each service is an image string or a mapping with an image.
  container:/service `options:` is refused: the runner passes it to docker before the image, where
             it can name a different image (this repo uses none).
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

The boundary (owner, Sep 30): we pin every reference WE write — every `uses:`, every image we name,
every image input we pass. What a pinned commit references on its own (e.g. the container image
inside ossf/scorecard-action's action.yaml) is fixed by our pin to that commit and is that action's
supply chain, not ours; it is not read here, and no action is excepted by name.

Outside this check (the review pass covers it): images a `run:` script pulls through a shell variable,
and binaries a pinned action downloads by version.

usage: check-action-pins.py [--verify-tags] [--git <commit>] [repo-root]
"""
import csv
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
        check_executor(where, "/".join(v.split("@")[0].split("/")[:2]), parent, bad)
        return
    if DOCKER_USES.fullmatch(v):
        return
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
                if any(key_of(k) == "options" for k, _ in node.value):
                    bad.append(f"{where}.options: refused (docker options can name another image)")
        elif key == "services":
            if not isinstance(node, yaml.MappingNode):
                bad.append(f"{where}: services is not a mapping")
                continue
            for k, v in node.value:
                sw = f"{where}.{getattr(k, 'value', '?')}"
                if isinstance(v, yaml.MappingNode):
                    imgs = [vv for kk, vv in v.value if key_of(kk) == "image"]
                    if not imgs:
                        bad.append(f"{sw}: service without an image")
                    if any(key_of(kk) == "options" for kk, _ in v.value):
                        bad.append(f"{sw}.options: refused (docker options can name another image)")
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
    if verify:
        bad += verify_pins(pins)
    for b in bad:
        print(b)
    print(f"check-action-pins: {len(files)} YAML file(s), {len(pins)} pinned action(s)"
          f"{' verified against their tags' if verify else ''}, {len(bad)} finding(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
