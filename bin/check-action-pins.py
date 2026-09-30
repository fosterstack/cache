#!/usr/bin/env python3
"""Every GitHub Action a workflow uses is pinned to a full commit digest with the version in a comment
(register row 78). A tag or branch reference fails. Fails closed: a file it cannot parse, or a
reference it cannot classify, is a finding.

What is read: every file under .github/workflows/ (a non-.yml/.yaml file there is itself a finding),
every other .yml/.yaml under .github/, and every action.yml/action.yaml (any case) anywhere in the
repo. A symlink among them is a finding, never followed. Each file is parsed as YAML (every document,
every scalar read as a string) and every node is walked, so flow style and quoting cannot hide a key.
YAML anchors and aliases are refused outright: an alias would carry one line's version comment to
another use (and this repo uses none). A mapping key that is not a plain string, or that holds a
${{ }} expression (GitHub folds `${{ 'uses' }}` into `uses`), is a finding.

  uses:      owner/repo[/path]@<40 lowercase hex> followed on the same line, directly after the
             value, by `# v<version>` (a remote reusable workflow is the same form);
             ./.github/workflows/<file>.yml as a job's `uses` (a local reusable workflow — GitHub
             reads it from the commit, and it is checked here as a file of its own);
             docker://<image>@sha256:<64 hex>.
             Nothing else: no tag, branch, short or uppercase SHA, ${{ }} expression, non-string, and
             no local action (./path at step level): its action.yml is read from the workspace at
             run time, where a script can rewrite it after this check has passed.
  services:  a mapping; each service is an image string or a mapping with an image.
  container: / image: / each service: <image>@sha256:<64 hex>, optionally docker://; never ${{ }}.
  Exempt by position only: the inputs under a step's or a job's `with:` and the variables under a
  workflow's, job's or step's `env:` are data passed along (the image a scanner scans), not
  something the runner resolves as an action or a container.
  --verify-tags  each `# vX` comment must resolve, through the GitHub API, to the pinned commit.

Outside this check (the review pass covers it): images a `run:` script pulls through a shell variable.

usage: check-action-pins.py [--verify-tags] [repo-root]
"""
import json
import os
import pathlib
import re
import sys
import urllib.request

try:
    import yaml
except ImportError:
    sys.exit("check-action-pins: PyYAML is required")

SHA = r"[0-9a-f]{40}"
ACTION = re.compile(rf"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@({SHA})$")
DIGEST = r"@sha256:[0-9a-f]{64}"
DOCKER_USES = re.compile(rf"^docker://[^@\s]+{DIGEST}$")
IMAGE = re.compile(rf"^(docker://)?[^@\s]+{DIGEST}$")
LOCAL_WORKFLOW = re.compile(r"^\./\.github/workflows/([^/]+\.ya?ml)$")
COMMENT = re.compile(r"^\s+#\s*(v[0-9]\S*)\s*$")


class StrLoader(yaml.SafeLoader):
    """Every plain scalar is a string; GitHub reads `uses: 1.0` as the string "1.0"."""


StrLoader.yaml_implicit_resolvers = {}


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


def walk(node, path, out, bad, where):
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if not isinstance(k, yaml.ScalarNode):
                bad.append(f"{where}{show(path)}: a mapping key that is not a plain string")
                continue
            if "${{" in k.value:
                bad.append(f"{where}{show(path)}: a mapping key holding an expression: {k.value!r}")
                continue
            key = k.value.strip().lower()
            p = path + [key]
            if key in ("uses", "image", "container", "services") and not data_block(p):
                if position(p):
                    out.append((key, p, v))
                elif key == "uses":
                    bad.append(f"{where}{show(p)}: uses at a position GitHub does not read as an action")
            walk(v, p, out, bad, where)
    elif isinstance(node, yaml.SequenceNode):
        for i, v in enumerate(node.value):
            walk(v, path + [i], out, bad, where)


def check_image(where, node, bad):
    if not isinstance(node, yaml.ScalarNode):
        return bad.append(f"{where}: image is not a plain string")
    v = node.value.strip()
    if "${{" in v:
        bad.append(f"{where}: image is an expression, not a pin: {v!r}")
    elif not IMAGE.match(v):
        bad.append(f"{where}: image not pinned by digest: {v!r}")


def check_uses(root, where, path, node, lines, pins, bad):
    if not isinstance(node, yaml.ScalarNode):
        return bad.append(f"{where}: uses is not a plain string")
    v = node.value.strip()
    if "${{" in v:
        return bad.append(f"{where}: uses is an expression, not a pin: {v!r}")
    if v.startswith("./"):
        m = LOCAL_WORKFLOW.match(v)
        job_level = len(path) == 3 and path[0] == "jobs"
        if m and job_level and m.group(1) in os.listdir(root / ".github" / "workflows"):
            return  # a local reusable workflow, read from the commit and checked as a file of its own
        return bad.append(f"{where}: local reference is not a job-level call of a workflow file in "
                          f".github/workflows/ (local actions are not allowed): {v!r}")
    m = ACTION.match(v)
    if m:
        sha = m.group(2)
        tag = None
        if node.start_mark.line == node.end_mark.line and node.end_mark.line < len(lines):
            c = COMMENT.match(lines[node.end_mark.line][node.end_mark.column:])
            tag = c.group(1) if c else None
        if tag is None:
            bad.append(f"{where}: {v!r} is not followed directly by a `# vX` comment on its line")
        else:
            pins.append((where, v.rsplit("@", 1)[0], sha, tag))
        return
    if DOCKER_USES.match(v):
        return
    bad.append(f"{where}: not a full commit digest: {v!r}")


def verify_tags(pins):
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        return ["--verify-tags: GH_TOKEN is not set"]
    found, cache = [], {}

    def api(path):
        req = urllib.request.Request(f"https://api.github.com/{path}",
                                     headers={"Authorization": f"Bearer {token}",
                                              "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    for where, repo, sha, tag in pins:
        slug = "/".join(repo.split("/")[:2])
        if (slug, tag) not in cache:
            try:
                obj = api(f"repos/{slug}/git/ref/tags/{tag}")["object"]
                while obj["type"] == "tag":  # annotated tag -> its commit
                    obj = api(f"repos/{slug}/git/tags/{obj['sha']}")["object"]
                cache[(slug, tag)] = obj["sha"]
            except Exception as e:  # fail closed
                cache[(slug, tag)] = f"unresolvable ({e.__class__.__name__})"
        if cache[(slug, tag)] != sha:
            found.append(f"{where}: {slug} {tag} is {cache[(slug, tag)]}, not the pinned {sha}")
    return found


def check_file(root, f, pins, bad):
    rel = f.relative_to(root).as_posix()
    text = f.read_text(encoding="utf-8", errors="replace")
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
    for key, path, node in refs:
        where = f"{rel}{show(path)}"
        if key == "uses":
            check_uses(root, where, path, node, lines, pins, bad)
        elif key == "container":
            if not isinstance(node, yaml.MappingNode):
                check_image(where, node, bad)
            elif not any(isinstance(k, yaml.ScalarNode) and k.value.strip().lower() == "image" for k, _ in node.value):
                bad.append(f"{where}: container mapping without an image")  # its image: is checked by position
        elif key == "services":
            if not isinstance(node, yaml.MappingNode):
                bad.append(f"{where}: services is not a mapping")
                continue
            for k, v in node.value:
                if isinstance(v, yaml.MappingNode):
                    imgs = [vv for kk, vv in v.value
                            if isinstance(kk, yaml.ScalarNode) and kk.value.strip().lower() == "image"]
                    if not imgs:
                        bad.append(f"{where}.{getattr(k, 'value', '?')}: service without an image")
                    for vv in imgs:
                        check_image(f"{where}.{getattr(k, 'value', '?')}.image", vv, bad)
                else:
                    check_image(f"{where}.{getattr(k, 'value', '?')}", v, bad)
        elif key == "image":
            check_image(where, node, bad)


def main():
    args = [a for a in sys.argv[1:] if a != "--verify-tags"]
    verify = "--verify-tags" in sys.argv[1:]
    root = pathlib.Path(args[0] if args else ".").resolve()
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        sys.exit("check-action-pins: no .github/workflows/ — nothing checked")
    bad, pins, files = [], [], set()
    for p in root.rglob("*"):
        parts = p.relative_to(root).parts
        if ".git" in parts or p.is_dir():
            continue
        in_wf = parts[:2] == (".github", "workflows")
        wanted = in_wf or p.name.lower() in ("action.yml", "action.yaml") or \
            (parts[0] == ".github" and p.suffix.lower() in (".yml", ".yaml"))
        if not wanted:
            continue
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            bad.append(f"{rel}: a symlink where a workflow or action file is read (not followed)")
        elif in_wf and p.suffix not in (".yml", ".yaml"):
            bad.append(f"{rel}: a file under .github/workflows/ that is not .yml/.yaml")
        elif p.is_file():
            files.add(p)

    for f in sorted(files):
        check_file(root, f, pins, bad)
    if verify:
        bad += verify_tags(pins)
    for b in bad:
        print(b)
    print(f"check-action-pins: {len(files)} YAML file(s), {len(pins)} pinned action(s)"
          f"{' verified against their tags' if verify else ''}, {len(bad)} finding(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
