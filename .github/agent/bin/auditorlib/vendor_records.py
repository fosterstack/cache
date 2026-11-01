"""The records sweep's library: a dependency-bump branch gets ONE signed commit holding the vendored tree and the
provenance records its go.mod and go.sum change calls for, so nobody finishes a bump by hand (the gap behind
cache#394, cache#620 B1/B2).

process_branch(repo, branch, ws, run, regenerate): for one dependabot/go_modules/* or auditor/bump-* branch,
  1. the branch must change go.mod (and go.sum) and otherwise only records paths (anything under vendor/, the
     provenance record, the reviewed licences), and its go.mod must add no replace, toolchain or godebug line:
     go mod vendor decides what to vendor from the package imports, so the branch's own tree equals the base's
     only while nothing else changed;
  2. the head is exported (data, never run) and `regenerate` rebuilds the records in a copy: go mod vendor, the
     licences, the records step, the provenance build;
  3. what differs from the head in the records paths is committed on the head through the API
     (signed_commit.commit_on_branch); nothing differs = no commit; go.mod and go.sum are never written; a
     regeneration that raises Skip (or leaves go.mod or go.sum changed) leaves the branch alone.
A head that already is a records commit but still differs from the regeneration is left alone too, so the sweep
never commits twice in a row.

carry_licences: the reviewed licences file (test-evidence/dependency-licenses.yaml) is keyed module@version and
nothing is ever invented in it: a changed module@version gets its earlier versions' licence id only when the
module's vendored LICENSE is byte-identical to the base's; a changed LICENSE, a new module or a missing LICENSE
is a Skip and a human does it as before.
"""
import json, os, shutil, subprocess, tempfile

from . import signed_commit

BUMP_FILES = ("go.mod", "go.sum")
LICENCES = "test-evidence/dependency-licenses.yaml"
NOT_UTF8 = "the tree holds a path that is not valid UTF-8"
_GO_MOD_DIRECTIVES = ("replace", "toolchain", "godebug")
# the pinned toolchain at its fixed install path (bin/install-scanner.sh go), never a go found by name
GO = "/usr/local/bin/fscache-go/bin/go"
# reviewed, read only: a module whose origin neither the toolchain nor this file supplies makes the records step refuse
ORIGINS = "test-evidence/dependency-origins.yaml"
PROVENANCE = "dependency-provenance.json"


class Skip(Exception):
    """The branch is left alone; the message is the reason that goes in the log."""


subject = signed_commit.records_message


def modules_of(text):
    """[(path, version)] of a vendor/modules.txt: its '# path version' lines. A replaced module, a malformed line or no
    module is a Skip."""
    mods = []
    for line in text.decode("utf-8", "replace").split("\n"):
        if line.startswith("# "):
            parts = line[2:].split(" ")
            if "=>" in parts or len(parts) != 2 or not parts[1].startswith("v"):
                raise Skip("vendor/modules.txt has a line that is not a plain module: %r" % line)
            mods.append((parts[0], parts[1]))
    if not mods:
        raise Skip("vendor/modules.txt lists no module")
    return mods


def carry_licences(modules, old, old_license, new_license):
    """{module@version: licence id} for exactly `modules`. `old` is the reviewed file as it stands at the base.
    old_license(path) and new_license(path) are the bytes of the module's vendored LICENSE at the base and in the
    new tree (None = no such file)."""
    out = {}
    for path, version in modules:
        key = "%s@%s" % (path, version)
        if key in old:
            out[key] = old[key]
            continue
        ids = {v for k, v in old.items() if k.rsplit("@", 1)[0] == path}
        if not ids:
            raise Skip("new module %s: it has no reviewed licence" % path)
        if len(ids) != 1 or not all(isinstance(i, str) for i in ids):
            raise Skip("module %s: its reviewed versions do not agree on one licence" % path)
        before, after = old_license(path), new_license(path)
        if before is None or after is None:
            raise Skip("module %s: no LICENSE file to compare" % path)
        if before != after:
            raise Skip("module %s: its LICENSE changed, so its licence is not carried forward" % path)
        out[key] = ids.pop()
    return out


def render_licences(licences):
    """The file's own layout: one key per line, sorted, one space of indent, a final newline."""
    return (json.dumps(licences, indent=1, sort_keys=True) + "\n").encode()


def _records(root):
    """{path: bytes} of every records path under root."""
    out = {}
    for name in signed_commit.RECORDS_FILES:
        if os.path.isfile(os.path.join(root, name)):
            with open(os.path.join(root, name), "rb") as fh:
                out[name] = fh.read()
    for here, _, files in os.walk(os.path.join(root, "vendor")):
        for entry in files:
            with open(os.path.join(here, entry), "rb") as fh:
                out[os.path.relpath(os.path.join(here, entry), root)] = fh.read()
    return out


def records_changes(head_dir, work_dir):
    """What turns the head's records into the regenerated ones: {path: bytes}, None for a file the regeneration no
    longer has."""
    before, after = _records(head_dir), _records(work_dir)
    changes = {p: b for p, b in after.items() if before.get(p) != b}
    changes.update({p: None for p in before if p not in after})
    return changes


def _git(ws, *args):
    r = subprocess.run(["git", "-C", ws, *args], capture_output=True)
    if r.returncode != 0:
        why = r.stderr.decode("utf-8", "replace").strip()[-300:]
        raise RuntimeError("git %s failed: %s" % (" ".join(args[:2]), why))
    return r.stdout


def _show(ws, rev, path):
    r = subprocess.run(["git", "-C", ws, "show", "%s:%s" % (rev, path)], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def _export(ws, head, dest):
    """The head's whole tree as plain files in dest, read from the raw git tree (so no attribute on the branch can hide
    a path): data only. A link or a submodule anywhere in it is a Skip."""
    files = {}
    for entry in _git(ws, "ls-tree", "-r", "-z", head).split(b"\0"):
        if entry:
            try:
                meta, path = entry.decode("utf-8").split("\t", 1)
            except UnicodeDecodeError:
                raise Skip(NOT_UTF8)
            mode, _, sha = meta.split(" ")
            if mode not in ("100644", "100755"):
                raise Skip("%s is a link or a submodule" % path)
            files[path] = sha
    blobs = subprocess.run(["git", "-C", ws, "cat-file", "--batch"],
        input="".join(sha + "\n" for sha in sorted(set(files.values()))).encode(),
                           capture_output=True)
    if blobs.returncode != 0:
        raise RuntimeError("git cat-file failed: %s" % " ".join(blobs.stderr.decode("utf-8", "replace").split())[-300:])
    contents, out, at = {}, blobs.stdout, 0
    for sha in sorted(set(files.values())):
        header_end = out.index(b"\n", at)
        size = int(out[at:header_end].split(b" ")[2])
        contents[sha] = out[header_end + 1:header_end + 1 + size]
        at = header_end + 1 + size + 1
    for path, sha in files.items():
        target = os.path.join(dest, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(contents[sha])


def _skip_reason(names, base_go_mod, head_go_mod):
    for name in names:
        if name not in BUMP_FILES and not signed_commit.is_records_path(name):
            return "the branch changes %s, which is not go.mod, go.sum or a records path" % name
    if "go.mod" not in names:
        return "the branch does not change go.mod"
    added = {l.strip() for l in head_go_mod.decode("utf-8",
        "replace").split("\n")} - {l.strip() for l in base_go_mod.decode("utf-8", "replace").split("\n")}
    if any(l.startswith(_GO_MOD_DIRECTIVES) or "=>" in l for l in added):
        return "go.mod adds a replace, toolchain or godebug line"
    return None


def process_branch(repo, branch, ws, run, regenerate, dry_run=False):
    """One branch; returns the line the sweep logs: 'committed <oid>', 'up to date', 'dry run: ...', 'gone',
    'skipped: <reason>' or 'failed: <reason>'."""
    if not signed_commit._BUMP_BRANCH.match(branch):
        return "skipped: not a dependency-bump branch"
    try:
        head = signed_commit._head(run, repo, branch)
        if head is None:
            return "gone"
        _git(ws, "fetch", "-q", "origin", "+refs/heads/main:refs/remotes/origin/main",
             "+refs/heads/%s:refs/remotes/origin/%s" % (branch, branch))
        if _git(ws, "rev-parse", "refs/remotes/origin/" + branch).decode().strip() != head:
            return "skipped: the branch moved while it was fetched"
        base = _git(ws, "merge-base", "origin/main", head).decode().strip()
        names = [n for n in _git(ws, "diff", "--name-only", "-z", "--no-renames", base, head).decode().split("\0") if n]
        why = _skip_reason(names, _show(ws, base, "go.mod") or b"", _show(ws, head, "go.mod") or b"")
        if why:
            return "skipped: " + why
        tmp = tempfile.mkdtemp(prefix="vendor-records-")
        try:
            head_dir, work_dir = os.path.join(tmp, "head"), os.path.join(tmp, "work")
            _export(ws, head, head_dir)
            shutil.copytree(head_dir, work_dir, symlinks=True)
            base_licences = json.loads((_show(ws, base, LICENCES) or b"{}").decode())
            regenerate(work_dir, base_licences, lambda path: _show(ws, base, "vendor/%s/LICENSE" % path))
            for name in BUMP_FILES:
                if _records_read(head_dir, name) != _records_read(work_dir, name):
                    return "skipped: the regeneration changed %s; the sweep never writes it" % name
            changes = records_changes(head_dir, work_dir)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if not changes:
            return "up to date"
        if _git(ws, "log", "-1", "--format=%B", head).decode().strip() == subject(branch):
            return ("skipped: the records commit on the head does not match what is regenerated (%d files differ)"
                    % len(changes))
        if dry_run:
            return "dry run: would commit %d files" % len(changes)
        return "committed " + signed_commit.commit_on_branch(repo, branch, head, subject(branch), changes, run=run)
    except Skip as e:
        return "skipped: %s" % e
    except UnicodeDecodeError:
        return "skipped: " + NOT_UTF8
    except (signed_commit.CommitError, RuntimeError, OSError, ValueError) as e:
        return "failed: %s" % e


def _records_read(root, name):
    full = os.path.join(root, name)
    if not os.path.isfile(full):
        return None
    with open(full, "rb") as fh:
        return fh.read()


def go_env(scratch):
    """A closed environment: only these variables, the checksum database on at its default, no workspace file, no
    credential helper."""
    return {"GOTOOLCHAIN": "local", "GOFLAGS": "", "GOENV": "off", "GOWORK": "off", "GOAUTH": "off",
        "GOSUMDB": "sum.golang.org",
            "GOPROXY": "https://proxy.golang.org", "GOPATH": os.path.join(scratch, "gopath"),
                "GOMODCACHE": os.path.join(scratch, "gopath", "pkg", "mod"),
            "GOCACHE": os.path.join(scratch, "gocache"), "HOME": os.path.join(scratch, "home"), "TMPDIR": scratch,
                "PATH": os.environ.get("PATH", "")}


def make_regenerate(tools, runner=subprocess.run, go=GO):
    """The function process_branch calls on a copy of the branch's tree: go mod vendor, the carried licences, the
    records step, the provenance build and check. `tools` is the checkout whose bin/ holds the two provenance
    scripts (main's copy, never the branch's). Exit 2 of a script is its refusal: a Skip."""
    def step(what, cmd, work, env):
        r = runner(cmd, cwd=work, env=env, capture_output=True, stdin=subprocess.DEVNULL)
        if r.returncode != 0:
            tail = " ".join((r.stderr or b"").decode("utf-8", "replace").split())[-300:]
            if r.returncode == 2:
                raise Skip("%s refused: %s" % (what, tail))
            raise RuntimeError("%s failed (exit %d): %s" % (what, r.returncode, tail))

    def regenerate(work, base_licences, base_license):
        scratch = tempfile.mkdtemp(prefix="vendor-records-go-")
        try:
            env = go_env(scratch)
            for d in ("gopath", "gocache", "home"):
                os.makedirs(os.path.join(scratch, d))
            r = runner([go, "mod", "vendor"], cwd=work, env=env, capture_output=True, stdin=subprocess.DEVNULL)
            if r.returncode != 0:
                raise Skip("go mod vendor failed: %s" % " ".join((r.stderr or b"").decode("utf-8",
                    "replace").split())[-300:])
            with open(os.path.join(work, "vendor", "modules.txt"), "rb") as fh:
                modules = modules_of(fh.read())
            def new_license(path):
                full = os.path.join(work, "vendor", path, "LICENSE")
                if not os.path.isfile(full):
                    return None
                with open(full, "rb") as fh:
                    return fh.read()
            with open(os.path.join(work, LICENCES), "wb") as fh:
                fh.write(render_licences(carry_licences(modules, base_licences, base_license, new_license)))
            out = os.path.join(scratch, "records")
            script = lambda name: os.path.join(tools, "bin", name)
            vendor_args = ["--vendor-dir", "vendor", "--go-sum", "go.sum"]
            step("the records step", ["python3", "-I", script("vendor-provenance-records.py"), *vendor_args,
                "--licenses", LICENCES,
                                      "--recorded-origins", ORIGINS, "--out-dir", out], work, env)
            # build refuses a destination that exists, and the branch has one
            built = os.path.join(scratch, "provenance.json")
            step("the provenance build", ["python3", "-I", script("vendor-provenance.py"), "build", *vendor_args,
                "--sumdb-record", out + "/sumdb.json",
                                          "--origins", out + "/origins.json", "--licenses", out + "/licenses.json",
                                              "--recorded-origins", ORIGINS,
                                          "--out", built], work, env)
            os.replace(built, os.path.join(work, PROVENANCE))
            step("the provenance check", ["python3", "-I", script("vendor-provenance.py"), "check", *vendor_args,
                "--provenance", PROVENANCE], work, env)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    return regenerate
