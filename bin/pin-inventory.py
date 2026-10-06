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
    "helm/kind-action": [("version", "kind"), ("kubectl_version", "kubectl"), ("node_image", None)],  # None: the input names an image
}
# NOT here, on purpose (rule 1, amendment 2): actions/setup-go's go-version and go.mod's toolchain line; the standard library ships in our binary.
_GO_INSTALL = re.compile(r"\bgo\s+install\s+(?:-\S+\s+)*([\w.\-/]+)@([\w.\-+]+)")
_GH_DOWNLOAD = re.compile(r"github\.com/([\w.-]+/[\w.-]+)/releases/download/v?([\w.+-]+)/")
_PIP_INSTALL = re.compile(r"\bpip3?\s+install\b([^\n]*)")
_PIP_PIN = re.compile(r"(?<![\w.-])([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;'\"]+)")
_RUN_IMAGE = re.compile(r"(?<![\w./:@-])((?:[\w.-]+(?::\d+)?/)*[\w.-]+(?::[\w.-]+)?@sha256:[0-9a-f]{64})")
_VER_PIN = re.compile(r"^([A-Z][A-Z0-9]*)_VER=['\"]?([^\s'\"#]+)", re.M)
_REQ_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", re.M)
WORKFLOW_GLOBS = (".github/workflows/*.yml", ".github/workflows/*.yaml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml",
                  ".github/actions/*/*/action.yml", ".github/actions/*/*/action.yaml")


class Item:
    def __init__(self, kind, name, version, label=""):
        self.kind, self.name, self.version, self.label = kind, name, version, label

    @property
    def key(self):
        return f"{self.kind}:{self.name}@{self.version}"

    def __repr__(self):
        return self.key


def git(root, *args):
    r = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


_BLOBS = {}  # blob id -> text: a history scan reads each distinct file version once, not once per commit


def tree_files(root, rev):
    """{path: text} for every file the inventory reads, at a revision (rev None: the working tree)."""
    def wanted(n):
        return (any(fnmatch.fnmatchcase(n, g) for g in WORKFLOW_GLOBS) or n == "bin/install-scanner.sh"
                or re.search(r"(^|/)[\w.-]*requirements[\w.-]*\.txt$", n))
    out = {}
    if rev is None:
        for n in git(root, "-c", "core.quotePath=false", "ls-files", "-z").split("\0"):
            if n and wanted(n):
                try:
                    out[n] = open(f"{root}/{n}").read()
                except OSError:
                    continue
        return out
    for line in git(root, "ls-tree", "-r", "-z", rev).split("\0"):
        meta, _, n = line.partition("\t")
        if not n or not wanted(n):
            continue
        blob = meta.split()[2]
        if blob not in _BLOBS:
            _BLOBS[blob] = git(root, "cat-file", "blob", blob)
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


def _walk(node, out, labels, path):
    if isinstance(node, dict):
        u = node.get("uses")
        if isinstance(u, str):
            u = u.strip()
            if u.startswith("docker://"):
                out.append(_image_item(u[len("docker://"):]))
            elif not u.startswith("./"):
                ref_path, _, ref = u.partition("@")
                repo = "/".join(ref_path.split("/")[:2])
                out.append(Item("action", repo, ref, labels.get(f"{ref_path}@{ref}", "")))
                w = node.get("with")
                for inp, tool in INSTALLER_INPUTS.get(repo, []):
                    if isinstance(w, dict) and isinstance(w.get(inp), str) and w[inp].strip() and "${{" not in w[inp]:
                        val = w[inp].strip()
                        out.append(_image_item(val) if tool is None else Item("tool", tool, val))
        run = node.get("run")
        if isinstance(run, str):
            for m in _GO_INSTALL.finditer(run):
                out.append(Item("gotool", m.group(1), m.group(2)))
            for m in _GH_DOWNLOAD.finditer(run):  # curl/wget of a release asset: the tool is its repo at that version
                out.append(Item("tool", m.group(1), m.group(2)))
            for m in _PIP_INSTALL.finditer(run):
                for p in _PIP_PIN.finditer(m.group(1)):
                    out.append(Item("package", f"pypi/{p.group(1).lower().replace('_', '-')}", p.group(2)))
            for m in _RUN_IMAGE.finditer(run):  # docker run/pull of an image by digest
                out.append(_image_item(m.group(1)))
        for k, v in node.items():
            if k in ("container", "image") and isinstance(v, (str, dict)):
                img = v if isinstance(v, str) else v.get("image")
                # an `image:` input of an action counts only when it names a digest (other inputs called image are not pins)
                if isinstance(img, str) and "${{" not in img and (path != "with" or k == "container" or DIGEST.search(img)):
                    out.append(_image_item(img))
            if k == "services" and isinstance(v, dict):
                for svc in v.values():
                    if isinstance(svc, dict) and isinstance(svc.get("image"), str) and "${{" not in svc["image"]:
                        out.append(_image_item(svc["image"]))
            _walk(v, out, labels, k)
    elif isinstance(node, list):
        for v in node:
            _walk(v, out, labels, path)


def inventory(files):
    """The items of one tree's files ({path: text}). Raises on a workflow that does not parse: a pin we cannot read is never skipped."""
    items = {}
    for path, text in sorted(files.items()):
        found = []
        if path == "bin/install-scanner.sh":
            found = [Item("tool", m.group(1).lower().replace("_", "-"), m.group(2)) for m in _VER_PIN.finditer(text) if m.group(1) != "PATH"]
        elif path.endswith("requirements.txt") or re.search(r"requirements[\w.-]*\.txt$", path):
            found = [Item("package", f"pypi/{m.group(1).lower().replace('_', '-')}", m.group(2)) for m in _REQ_PIN.finditer(text)]
        else:
            labels = {}
            for m in re.finditer(r"uses:\s*([^\s#'\"]+)\s*#\s*(\S+)", text):
                labels[m.group(1)] = m.group(2)
            try:
                doc = yaml.load(text, Loader=yaml.BaseLoader)
            except yaml.YAMLError as e:
                raise RuntimeError(f"{path} does not parse: {e}")
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
