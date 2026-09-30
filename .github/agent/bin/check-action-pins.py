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
  container: / image: / each service: <image>@sha256:<64 hex>, optionally docker://; never ${{ }}.
  Executor images: a pinned action that runs a container image of its own must be given that image
             by digest through its input (EXECUTOR_INPUTS) — a pinned action with a mutable default
             image is still a mutable reference. Action identity is case-folded (GitHub resolves
             owner/repo case-insensitively); input names are matched exactly as the runner does
             (case-insensitive, never trimmed); buildx's driver-opts is read one option per line, as
             the action reads it — and each line as CSV, as buildx reads it, so exactly one image=
             may appear across them all — and its `append` (which can re-set a node's image) is refused.
  Exempt by position only: the other inputs under a step's or a job's `with:` and the variables under
  a workflow's, job's or step's `env:` are data passed along (the image a scanner scans), not
  something the runner resolves as an action or a container.
  --verify-tags  each `# vX` comment must resolve, through the GitHub API, to the pinned commit;
             and each pinned action's own action.yml at that commit is read: node is fine, a Docker
             action must name its image docker://…@sha256 (never a Dockerfile), and a composite
             action's steps are held to these same rules, recursively (no expression keys, no
             `./` action: GitHub resolves that in the CALLER's workspace, where a script can write
             it). action.yaml is read only when action.yml is definitively absent (HTTP 404); any
             other API error is a finding. The only exclusion is TRANSITIVE_EXCLUSIONS below.

Outside this check (the review pass covers it): images a `run:` script pulls through a shell variable,
and binaries a pinned action downloads by version.

usage: check-action-pins.py [--verify-tags] [--git <commit>] [repo-root]
"""
import base64
import csv
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
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
# action (owner/repo, lower case) -> how it must be given its container image: (input, prefix)
EXECUTOR_INPUTS = {
    "docker/setup-qemu-action": ("image", ""),
    "docker/setup-buildx-action": ("driver-opts", "image="),
}
# pinned actions whose own action.yml names a container image by tag — the only exclusions, each
# with its reason (register row 78: "a documented exclusion in the check's own allowlist").
TRANSITIVE_EXCLUSIONS = {
    "ossf/scorecard-action": "its action.yaml names docker://ghcr.io/ossf/scorecard-action:<tag>, and "
    "the Scorecard API accepts published results (the README badge) only from the official action, "
    "so it cannot be replaced by a docker:// digest without dropping publish_results — the owner's call",
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


def inputs_of(step):
    """The step's `with:` inputs as {name: [value nodes]}, names exactly as the runner matches them."""
    got = {}
    for k, w in step.value if isinstance(step, yaml.MappingNode) else []:
        if key_of(k) == "with" and isinstance(w, yaml.MappingNode):
            for kk, v in w.value:
                if isinstance(kk, yaml.ScalarNode):
                    got.setdefault(kk.value.lower(), []).append(v)
    return got


def check_executor(where, action, step, bad):
    action = action.lower()
    need = EXECUTOR_INPUTS.get(action)
    if not need:
        return
    inp, prefix = need
    got = inputs_of(step)
    if action == "docker/setup-buildx-action":
        if "append" in got:
            return bad.append(f"{where}: {action} with `append` (it can re-set a node's image) is refused")
        drivers = [v.value for v in got.get("driver", []) if isinstance(v, yaml.ScalarNode)]
        if drivers == ["docker"]:
            return  # the docker driver runs no BuildKit container of its own
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
    """--verify-tags: each `# vX` comment is the pinned commit, and what each pinned action runs is
    itself pinned (its action.yml at that commit, recursively through composite actions)."""
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        return ["--verify-tags: GH_TOKEN is not set"]
    found, tags, seen = [], {}, set()

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
        found += transitive(api, where, repo, sha, seen, 0)
    return found


def transitive(api, where, repo, sha, seen, depth):
    """What the pinned action at `repo`@`sha` runs, read from its own action.yml."""
    parts = repo.split("/")
    slug, sub = "/".join(parts[:2]), "/".join(parts[2:])
    if (slug.lower(), sub, sha) in seen:
        return []
    seen.add((slug.lower(), sub, sha))
    at = f"{where} -> {repo}@{sha[:12]}"
    if depth > 8:
        return [f"{at}: composite actions nested more than 8 deep"]
    text = None
    for name in ("action.yml", "action.yaml"):  # the runner's own precedence
        path = urllib.parse.quote(f"{sub}/{name}" if sub else name)
        try:
            doc = api(f"repos/{slug}/contents/{path}?ref={sha}")
            text = base64.b64decode(doc["content"]).decode("utf-8", "replace")
            break
        except urllib.error.HTTPError as e:
            if e.code != 404:  # only a definitive absence moves on to the next name
                return [f"{at}: {name} unreadable (HTTP {e.code})"]
        except Exception as e:  # fail closed
            return [f"{at}: {name} unreadable ({e.__class__.__name__})"]
    if text is None:
        return [f"{at}: no action.yml/action.yaml at the pinned commit"]
    try:
        runs = yaml.load(text, Loader=StrLoader)["runs"]
        using = runs["using"]
    except Exception as e:
        return [f"{at}: its action.yml does not parse ({e.__class__.__name__})"]
    if isinstance(using, str) and re.fullmatch(r"node[0-9]+", using):
        return []
    if using == "docker":
        image = runs.get("image")
        if isinstance(image, str) and DOCKER_USES.fullmatch(image):
            return []
        if slug.lower() in TRANSITIVE_EXCLUSIONS:
            return []  # the documented exclusion (see TRANSITIVE_EXCLUSIONS for why)
        return [f"{at}: a Docker action whose image is not a docker://…@sha256 digest: {image!r}"]
    if using != "composite":
        return [f"{at}: runs.using {using!r} is not node, docker or composite"]
    found = []
    try:
        nodes = yaml.compose(text, Loader=StrLoader)
        steps = next(v for k, v in nodes.value if key_of(k) == "runs")
        steps = next(v for k, v in steps.value if key_of(k) == "steps").value
    except Exception as e:
        return [f"{at}: composite steps unreadable ({e.__class__.__name__})"]
    for i, step in enumerate(steps):
        keys = step.value if isinstance(step, yaml.MappingNode) else []
        if any(not isinstance(k, yaml.ScalarNode) or "${{" in k.value for k, _ in keys):
            found.append(f"{at}.runs.steps[{i}]: a mapping key that is not a plain string or holds an expression")
        for k, u in keys:
            if key_of(k) != "uses":
                continue
            v = u.value if isinstance(u, yaml.ScalarNode) else None
            sw = f"{at}.runs.steps[{i}].uses"
            m = ACTION.fullmatch(v or "")
            if m:
                check_executor(sw, "/".join(v.split("@")[0].split("/")[:2]), step, found)
                found += transitive(api, sw, v.rsplit("@", 1)[0], m.group(2), seen, depth + 1)
            elif v and v.startswith("./"):
                found.append(f"{sw}: a local action, resolved in the caller's workspace at run time: {v!r}")
            elif not (v and DOCKER_USES.fullmatch(v)) or "${{" in (v or ""):
                found.append(f"{sw}: not a full commit digest: {v!r}")
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
            elif not any(key_of(k) == "image" for k, _ in node.value):
                bad.append(f"{where}: container mapping without an image")  # its image: is checked by position
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
