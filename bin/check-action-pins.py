#!/usr/bin/env python3
"""Every GitHub Action a workflow uses is pinned to a full commit digest with the version in a comment
(register row 78). A tag or branch reference fails. Fails closed: a file it cannot
parse, or a reference it cannot classify, is a finding.

What is read: every file under .github/workflows/ (a non-.yml/.yaml file there is itself a finding),
every other .yml/.yaml under .github/, and every action.yml/action.yaml anywhere in the repo. Each is
parsed as YAML (every document, anchors and aliases resolved, every scalar read as a string, the
way GitHub reads it) and every node is walked, so flow style, quoting and anchors cannot hide a key.

  uses:     owner/repo[/path]@<40 lowercase hex>, with `# v<version>` after it on the same line
            (a remote reusable workflow is the same form);
            ./<path> only when it is a workflow file under .github/workflows/ or a directory holding
            an action.yml (both are checked here in turn);
            docker://<image>@sha256:<64 hex>.
            Nothing else: no tag, branch, short or uppercase SHA, ${{ }} expression, or non-string.
  image: / container: (a job container, a service, a Docker action's runs.image)
            <image>@sha256:<64 hex>, optionally docker://; never a Dockerfile, never ${{ }}.
            Exception: an `image:` that is an input under `with:` is data passed to an action (the
            image a scanner scans), not something the runner executes — not checked.
  --verify-tags  each `# vX` comment must resolve, through the GitHub API, to the pinned commit.

Exclusions (the only ones): none by path. Docker images a `run:` script pulls through a shell
variable are outside this check (a static reader cannot resolve them); the review pass covers them.

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


class StrLoader(yaml.SafeLoader):
    """Every plain scalar is a string; GitHub reads `uses: 1.0` as the string "1.0"."""


StrLoader.yaml_implicit_resolvers = {}


def walk(node, path, out, parent_key="", seen=None):
    """(key, path, value-node, parent key) for every uses/image/container key, at any depth."""
    seen = set() if seen is None else seen
    if id(node) in seen:  # an alias points back at a node already walked on this path
        return
    seen = seen | {id(node)}
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            key = k.value.strip().lower() if isinstance(k, yaml.ScalarNode) else "?"
            p = f"{path}.{key}"
            if key in ("uses", "image", "container") and parent_key != "with":
                out.append((key, p, v, parent_key))
            walk(v, p, out, key, seen)
    elif isinstance(node, yaml.SequenceNode):
        for i, v in enumerate(node.value):
            walk(v, f"{path}[{i}]", out, parent_key, seen)


def version_comment(lines, node, sha):
    """The `# vX` after the pinned SHA on the value's own line, else None."""
    if node.start_mark.line != node.end_mark.line:
        return None  # a folded/multi-line scalar has no single line to carry the comment
    src = lines[node.start_mark.line] if node.start_mark.line < len(lines) else ""
    m = re.search(rf"@{sha}\b[^#\n]*#\s*(v[0-9][^\s,}}\]]*)", src)
    return m.group(1) if m else None


def check_uses(root, rel, where, v, node, lines, pins, bad):
    if v.startswith("./"):
        target = (root / v).resolve()
        try:
            inside = target.relative_to(root)
        except ValueError:
            return bad.append(f"{where}: local reference leaves the repository: {v!r}")
        if inside.parts[:2] == (".github", "workflows") and target.suffix in (".yml", ".yaml") and target.is_file():
            return  # a local reusable workflow: checked as a file of its own
        if any((target / n).is_file() for n in ("action.yml", "action.yaml")):
            return  # a local action: its action.yml is checked as a file of its own
        return bad.append(f"{where}: local reference is neither a workflow nor an action: {v!r}")
    m = ACTION.match(v)
    if m:
        sha = m.group(2)
        tag = version_comment(lines, node, sha)
        if tag is None:
            bad.append(f"{where}: {v!r} has no `# vX` version comment on its own line")
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


def main():
    args = [a for a in sys.argv[1:] if a != "--verify-tags"]
    verify = "--verify-tags" in sys.argv[1:]
    root = pathlib.Path(args[0] if args else ".").resolve()
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        sys.exit("check-action-pins: no .github/workflows/ — nothing checked")
    bad, pins, files = [], [], set()
    for p in wf_dir.rglob("*"):
        if p.is_file():
            if p.suffix in (".yml", ".yaml"):
                files.add(p)
            else:
                bad.append(f"{p.relative_to(root).as_posix()}: a file under .github/workflows/ that is not .yml/.yaml")
    for p in root.rglob("*"):
        if not p.is_file() or ".git" in p.relative_to(root).parts:
            continue
        parts = p.relative_to(root).parts
        if p.name in ("action.yml", "action.yaml") or (parts[0] == ".github" and p.suffix in (".yml", ".yaml")):
            files.add(p)

    for f in sorted(files):
        rel = f.relative_to(root).as_posix()
        text = f.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        try:
            docs = list(yaml.compose_all(text, Loader=StrLoader))
        except yaml.YAMLError as e:
            bad.append(f"{rel}: does not parse as YAML ({e.__class__.__name__})")
            continue
        refs = []
        for i, d in enumerate(docs):
            if d is not None:
                walk(d, f"[doc{i}]" if len(docs) > 1 else "", refs)
        for key, p, node, parent in refs:
            where = f"{rel}{p}"
            if key == "container" and isinstance(node, yaml.MappingNode):
                continue  # its image: is walked
            if key == "image" and parent != "container" and parent not in ("runs",) and ".services." not in p:
                continue  # an `image:` that is neither a job container, a service nor a Docker action
            if not isinstance(node, yaml.ScalarNode):
                bad.append(f"{where}: {key} is not a plain string")
                continue
            v = node.value.strip()
            if "${{" in v:
                bad.append(f"{where}: {key} is an expression, not a pin: {v!r}")
            elif key == "uses":
                check_uses(root, rel, where, v, node, lines, pins, bad)
            elif not IMAGE.match(v):
                bad.append(f"{where}: image not pinned by digest: {v!r}")

    if verify:
        bad += verify_tags(pins)
    for b in bad:
        print(b)
    print(f"check-action-pins: {len(files)} YAML file(s), {len(pins)} pinned action(s)"
          f"{' verified against their tags' if verify else ''}, {len(bad)} finding(s)")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
