# proves: REQ-VEND-001-AC16, REQ-VEND-001-AC17, REQ-VEND-001-AC18, REQ-VEND-001-AC20
"""auditorlib.vendor_records: what the records sweep may write to a dependency-bump branch and when it must leave the
branch alone.
Real git repositories in a temporary directory (an origin and a clone); a fake GitHub API; the Go steps are a function
the test supplies."""
import json, os, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import signed_commit as S  # noqa: E402
from auditorlib import vendor_records as V  # noqa: E402

REPO = "o/r"
BR = "dependabot/go_modules/example.com/m-1.1.0"
OID = "9" * 40
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
           "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ["PATH"]}
LIC = json.dumps({"example.com/m@v1.0.0": "MIT"}, indent=1, sort_keys=True) + "\n"


def git(cwd, *args, check=True):
    r = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args], cwd=cwd,
        env=GIT_ENV, capture_output=True, text=True, errors="replace")
    if check and r.returncode != 0:
        raise AssertionError("git %s: %s" % (args, r.stderr))
    return r.stdout.strip()


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def put(root, files):
    for path, data in files.items():
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)


class Api:
    """A fake GitHub: one branch ref, the mutation answer, and a record of the commits made."""
    def __init__(self, branch, head, signature=True):
        self.refs, self.made, self.signature = {branch: head}, [], signature

    def __call__(self, cmd, **kw):
        cmd = list(cmd)
        done = lambda rc, out, err="": subprocess.CompletedProcess(cmd, rc, out, err)
        if cmd[2] == "graphql":
            self.made.append(json.loads(kw["input"])["variables"]["input"])
            sig = {"isValid": True, "state": "VALID"} if self.signature else {"isValid": False, "state": "UNSIGNED"}
            return done(0, json.dumps({"data": {"createCommitOnBranch": {"commit": {"oid": OID, "signature": sig}}}}))
        branch = cmd[2].split("/git/ref/heads/")[1]
        if branch not in self.refs:
            return done(1, "", "gh: Not Found (HTTP 404)")
        return done(0, json.dumps({"object": {"sha": self.refs[branch]}}))


class Sweep(unittest.TestCase):
    BASE_FILES = {"go.mod": b"module r\n\nrequire example.com/m v1.0.0\n", "go.sum": b"sum1\n",
        "vendor/modules.txt": b"# example.com/m v1.0.0\n",
                  "vendor/example.com/m/m.go": b"package m // 1.0.0\n", "vendor/example.com/m/LICENSE": b"MIT text\n",
                  "dependency-provenance.json": b"{}\n", "test-evidence/dependency-licenses.yaml": LIC.encode(),
                      "README.md": b"hi\n"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.tmp, True)
        self.seed = os.path.join(self.tmp, "seed"); os.makedirs(self.seed)
        git(self.seed, "init", "-q")
        put(self.seed, self.BASE_FILES)
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "base")
        self.bump(BR, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n", "go.sum": b"sum2\n"})
        git(self.tmp, "clone", "-q", "--bare", self.seed, "origin.git")
        git(self.tmp, "clone", "-q", "origin.git", "ws"); self.ws = os.path.join(self.tmp, "ws")
        self.origin = os.path.join(self.tmp, "origin.git")

    def bump(self, branch, files, message="Bump example.com/m from 1.0.0 to 1.1.0", remove=()):
        git(self.seed, "checkout", "-q", "-B", branch, "main"); put(self.seed, files)
        for r in remove:
            os.remove(os.path.join(self.seed, r))
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", message)
        head = git(self.seed, "rev-parse", "HEAD")
        git(self.seed, "checkout", "-q", "main")
        if os.path.isdir(os.path.join(self.tmp, "origin.git")):
            git(self.seed, "push", "-q", "-f", self.origin, branch)
        return head

    def head(self, branch=BR):
        return git(self.origin, "rev-parse", "refs/heads/" + branch)

    # the Go steps, as a test function: a new vendored file, the new module line, the provenance and licences files
    @staticmethod
    def regen(work, old_licences, old_license):
        put(work, {"vendor/modules.txt": b"# example.com/m v1.1.0\n",
            "vendor/example.com/m/m.go": b"package m // 1.1.0\n",
                   "dependency-provenance.json": b'{"m": "1.1.0"}\n'})
        put(work, {"test-evidence/dependency-licenses.yaml": V.render_licences(V.carry_licences(
            [("example.com/m", "v1.1.0")], old_licences, old_license, lambda p: read(os.path.join(work, "vendor", p,
                "LICENSE"))))})

    def sweep(self, regenerate=None, branch=BR, dry_run=False, api=None):
        api = api or Api(branch, self.head(branch))
        return V.process_branch(REPO, branch, self.ws, api, regenerate or self.regen, dry_run=dry_run), api

    def test_a_bump_that_only_changes_go_mod_and_go_sum_gets_one_commit_of_the_regenerated_records(self):
        status, api = self.sweep()
        self.assertEqual(status, "committed " + OID)
        inp = api.made[0]
        # on the branch's own head
        self.assertEqual(inp["expectedHeadOid"], self.head())
        self.assertEqual(inp["message"]["headline"], "Vendor records for the m-1.1.0 bump")
        adds = {a["path"]: a["contents"] for a in inp["fileChanges"]["additions"]}
        self.assertEqual(sorted(adds), ["dependency-provenance.json", "test-evidence/dependency-licenses.yaml",
            "vendor/example.com/m/m.go", "vendor/modules.txt"])
        self.assertTrue(all(S.is_records_path(p) for p in adds))
        self.assertEqual(inp["fileChanges"]["deletions"], [])
        self.assertEqual(json.loads(__import__("base64").b64decode(adds["test-evidence/dependency-licenses.yaml"])),
            {"example.com/m@v1.1.0": "MIT"})

    def test_a_vendored_file_the_new_tree_no_longer_has_is_deleted(self):
        def regen(work, a, b):
            self.regen(work, a, b); os.remove(os.path.join(work, "vendor/example.com/m/m.go"))
        status, api = self.sweep(regen)
        self.assertEqual(api.made[0]["fileChanges"]["deletions"], [{"path": "vendor/example.com/m/m.go"}])

    def test_dry_run_commits_nothing_and_says_what_it_would_do(self):
        status, api = self.sweep(dry_run=True)
        self.assertEqual(status, "dry run: would commit 4 files"); self.assertEqual(api.made, [])

    def test_records_that_already_match_make_no_commit(self):
        sha = self.head()
        self.bump(BR, {**self.regen_files(), "go.mod": b"module r\n\nrequire example.com/m v1.1.0\n",
            "go.sum": b"sum2\n"})
        status, api = self.sweep()
        self.assertEqual(status, "up to date"); self.assertEqual(api.made, []); self.assertNotEqual(sha, self.head())

    def regen_files(self):
        w = os.path.join(self.tmp, "gen")
        shutil.rmtree(w, True)
        shutil.copytree(self.seed, w, ignore=shutil.ignore_patterns(".git"))
        git(self.seed, "checkout", "-q", "main")
        self.regen(w, json.loads(LIC), lambda p: b"MIT text\n")
        out = {}
        for root, _, names in os.walk(w):
            for n in names:
                full = os.path.join(root, n); out[os.path.relpath(full, w)] = read(full)
        return {k: v for k, v in out.items() if S.is_records_path(k)}

    def test_a_records_commit_that_regeneration_still_disagrees_with_is_left_alone_not_rewritten_again(self):
        # two commits on the branch: the bump, then a records commit whose files are not what the regeneration gives
        git(self.seed, "checkout", "-q", "-B", BR, "main")
        put(self.seed, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n", "go.sum": b"sum2\n"})
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "Bump")
        put(self.seed, {"vendor/example.com/m/m.go": b"stale\n"})
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "Vendor records for the m-1.1.0 bump")
        git(self.seed, "push", "-q", "-f", self.origin, BR)
        status, api = self.sweep()
        self.assertTrue(status.startswith("skipped: the records commit"), status); self.assertEqual(api.made, [])

    def test_a_branch_that_changes_anything_beyond_the_bump_and_records_is_skipped_with_the_reason(self):
        cases = {"README.md": b"x\n", ".github/workflows/ci.yml": b"x\n", "bin/x.sh": b"x\n",
            "tools/govulncheck/go.mod": b"x\n", "test-evidence/dependency-origins.yaml": b"[]\n"}
        for path, data in cases.items():
            self.bump(BR, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n", "go.sum": b"sum2\n", path: data})
            status, api = self.sweep()
            self.assertEqual(status,
                "skipped: the branch changes %s, which is not go.mod, go.sum or a records path" % path, path)
            self.assertEqual(api.made, [])

    def test_a_branch_that_does_not_change_go_mod_is_skipped(self):
        self.bump(BR, {"go.sum": b"sum2\n"})
        status, api = self.sweep()
        self.assertEqual(status, "skipped: the branch does not change go.mod"); self.assertEqual(api.made, [])

    def test_a_go_mod_that_adds_replace_toolchain_or_godebug_is_skipped(self):
        for line in ("replace example.com/m => ../m", "toolchain go9.9.9", "godebug x=1",
            "  replace example.com/m => ../elsewhere"):
            self.bump(BR, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n" + line.encode() + b"\n",
                "go.sum": b"sum2\n"})
            status, api = self.sweep()
            self.assertTrue(status.startswith("skipped: go.mod adds"), (line, status)); self.assertEqual(api.made, [])

    def test_a_replace_the_base_already_has_is_not_new(self):
        base = b"module r\n\nreplace example.com/x => example.com/y v1.0.0\n"
        git(self.seed, "checkout", "-q", "main")
        put(self.seed, {"go.mod": base})
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "r")
        git(self.seed, "push", "-q", "-f", self.origin, "main:main")
        self.bump(BR, {"go.mod": base + b"require example.com/m v1.1.0\n", "go.sum": b"sum2\n"})
        git(self.ws, "fetch", "-q", "origin")
        status, api = self.sweep()
        self.assertEqual(status, "committed " + OID)

    def test_a_regeneration_that_gives_up_is_a_skip_with_its_reason(self):
        def regen(work, a, b):
            raise V.Skip("go mod vendor failed: no such host")
        status, api = self.sweep(regen)
        self.assertEqual(status, "skipped: go mod vendor failed: no such host"); self.assertEqual(api.made, [])

    def test_a_regeneration_that_changes_go_mod_or_go_sum_is_a_skip(self):
        for name in ("go.mod", "go.sum"):
            def regen(work, a, b, name=name):
                self.regen(work, a, b); put(work, {name: b"changed\n"})
            status, api = self.sweep(regen)
            self.assertEqual(status, "skipped: the regeneration changed %s; the sweep never writes it" % name)
            self.assertEqual(api.made, [])

    def test_a_branch_without_go_sum_or_a_provenance_file_is_regenerated_the_same_way(self):
        self.bump(BR, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n"}, remove=("go.sum",
            "dependency-provenance.json"))
        status, api = self.sweep(self.regen)
        self.assertEqual(status, "committed " + OID)

    def test_a_link_in_the_branch_tree_is_not_followed_and_a_git_failure_is_a_failed_line(self):
        git(self.seed, "checkout", "-q", "-B", BR, "main")
        put(self.seed, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n"})
        os.symlink("target", os.path.join(self.seed, "evil"))
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "b")
        git(self.seed, "push", "-q", "-f", self.origin, BR)
        status, api = self.sweep()
        self.assertEqual(status, "skipped: the branch changes evil, which is not go.mod, go.sum or a records path")
        git(self.seed, "checkout", "-q", "-B", BR, "main")
        put(self.seed, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n"})
        os.symlink("target", os.path.join(self.seed, "vendor", "link"))
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "b")
        git(self.seed, "push", "-q", "-f", self.origin, BR)
        status, api = self.sweep()
        self.assertEqual(status, "skipped: vendor/link is a link or a submodule"); self.assertEqual(api.made, [])
        status, api = self.sweep(api=Api("dependabot/go_modules/not-in-origin", OID),
            branch="dependabot/go_modules/not-in-origin")
        self.assertTrue(status.startswith("failed: git fetch"), status)

    def commit_files(self, files, links=()):
        git(self.seed, "checkout", "-q", "-B", BR, "main")
        put(self.seed, {"go.mod": b"module r\n\nrequire example.com/m v1.1.0\n", **files})
        for name in links:
            os.symlink("target", os.path.join(self.seed, name))
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "b")
        git(self.seed, "push", "-q", "-f", self.origin, BR)

    def test_attributes_on_the_branch_cannot_hide_a_link_from_the_sweep(self):
        self.commit_files({"vendor/.gitattributes": b"link export-ignore\n"}, links=("vendor/link",))
        status, api = self.sweep()
        self.assertEqual(status, "skipped: vendor/link is a link or a submodule"); self.assertEqual(api.made, [])

    def test_attributes_on_the_branch_cannot_hide_a_file_from_the_deletion_list(self):
        self.commit_files({"vendor/.gitattributes": b"hidden.go export-ignore\n",
            "vendor/hidden.go": b"package hidden\n"})

        def regen(work, a, b):                       # what go mod vendor does: the whole vendored tree is rebuilt
            shutil.rmtree(os.path.join(work, "vendor"))
            put(work, {"vendor/example.com/m/LICENSE": b"MIT text\n"})
            self.regen(work, a, b)
        status, api = self.sweep(regen)
        self.assertEqual(status, "committed " + OID)
        self.assertEqual(sorted(d["path"] for d in api.made[0]["fileChanges"]["deletions"]),
                         ["vendor/.gitattributes", "vendor/hidden.go"])

    def test_an_executable_file_is_a_file_and_a_submodule_is_a_skip(self):
        self.commit_files({"vendor/run.sh": b"#!/bin/sh\n"})
        os.chmod(os.path.join(self.seed, "vendor/run.sh"), 0o755)
        git(self.seed, "add", "-A")
        git(self.seed, "commit", "-qm", "x")
        git(self.seed, "push", "-q", "-f", self.origin, BR)
        status, api = self.sweep()
        self.assertEqual(status, "committed " + OID)
        sha = git(self.seed, "rev-parse", "HEAD")
        git(self.seed, "update-index", "--add", "--cacheinfo", "160000,%s,vendor/sub" % sha)
        git(self.seed, "commit", "-qm", "sub")
        git(self.seed, "push", "-q", "-f", self.origin, BR)
        status, api = self.sweep()
        self.assertEqual(status, "skipped: vendor/sub is a link or a submodule")

    def odd_path(self, branch):
        """commit a vendored path that is not valid UTF-8 on `branch`, by git plumbing"""
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=self.seed, input=b"x", capture_output=True,
                              env=GIT_ENV).stdout.decode().strip()
        subprocess.run(["git", "update-index", "--add", "--cacheinfo", b"100644," + blob.encode() + b",vendor/\xff"],
                       cwd=self.seed, env=GIT_ENV, check=True)
        git(self.seed, "commit", "-qm", "odd"); git(self.seed, "push", "-q", "-f", self.origin, branch)

    def test_a_path_that_is_not_valid_utf8_is_a_skip_in_the_diff_and_in_the_export(self):
        self.commit_files({})
        self.odd_path(BR)
        status, api = self.sweep()                                      # the diff of the branch meets it first
        self.assertEqual(status, "skipped: " + V.NOT_UTF8); self.assertEqual(api.made, [])
        # and a tree that holds it (the base, say) never exports
        with self.assertRaises(V.Skip) as ctx:
            V._export(self.ws, self.head(), os.path.join(self.tmp, "out"))
        self.assertEqual(str(ctx.exception), V.NOT_UTF8)

    def test_a_failing_blob_read_is_a_failed_line(self):
        real = subprocess.run
        fail = lambda cmd, **kw: (subprocess.CompletedProcess(cmd, 1, b"",
            b"fatal:\nno blob") if "cat-file" in cmd else real(cmd, **kw))
        with mock.patch.object(V.subprocess, "run", fail):
            status, api = self.sweep()
        self.assertEqual(status, "failed: git cat-file failed: fatal: no blob"); self.assertEqual(api.made, [])

    def test_a_missing_branch_a_moved_branch_and_a_failed_commit(self):
        status, api = self.sweep(api=Api("other", OID))
        self.assertEqual(status, "gone")
        status, api = self.sweep(api=Api(BR, "7" * 40))
        self.assertEqual(status, "skipped: the branch moved while it was fetched")
        status, api = self.sweep(api=Api(BR, self.head(), signature=False))
        self.assertTrue(status.startswith("failed: "), status)

    def test_a_branch_name_outside_the_bump_lanes_is_never_touched(self):
        status, api = self.sweep(branch="main", api=Api("main", OID))
        self.assertEqual(status, "skipped: not a dependency-bump branch")

    def test_the_subject_names_the_last_part_of_the_branch(self):
        self.assertEqual(V.subject("dependabot/go_modules/github.com/prometheus/client_golang-1.25.0"),
            "Vendor records for the client_golang-1.25.0 bump")
        self.assertEqual(V.subject("auditor/bump-example.com-m-1.1.0"),
            "Vendor records for the bump-example.com-m-1.1.0 bump")


class Licences(unittest.TestCase):
    OLD = {"example.com/m@v1.0.0": "MIT", "example.com/n@v2.0.0": "Apache-2.0", "example.com/n@v1.0.0": "Apache-2.0",
        "example.com/q@v1.0.0": "MIT", "example.com/q@v0.1.0": "BSD-3-Clause"}

    def carry(self, modules, old=None, old_license=lambda p: b"L", new_license=lambda p: b"L"):
        return V.carry_licences(modules, self.OLD if old is None else old, old_license, new_license)

    def test_the_old_versions_licence_is_carried_only_when_the_license_file_is_byte_identical(self):
        self.assertEqual(self.carry([("example.com/m", "v1.1.0")]), {"example.com/m@v1.1.0": "MIT"})

    def test_an_entry_already_reviewed_is_kept_whatever_the_file_says(self):
        self.assertEqual(self.carry([("example.com/m", "v1.0.0")], new_license=lambda p: b"other"),
            {"example.com/m@v1.0.0": "MIT"})

    def test_versions_of_one_module_that_agree_on_the_licence_carry_it(self):
        self.assertEqual(self.carry([("example.com/n", "v3.0.0")]), {"example.com/n@v3.0.0": "Apache-2.0"})

    def test_every_reason_to_skip(self):
        cases = {"a changed LICENSE file": dict(modules=[("example.com/m", "v1.1.0")],
            new_license=lambda p: b"changed"),
                 "a new module": dict(modules=[("example.com/new", "v1.0.0")]),
                 "no LICENSE in the new tree": dict(modules=[("example.com/m", "v1.1.0")], new_license=lambda p: None),
                 "no LICENSE in the base": dict(modules=[("example.com/m", "v1.1.0")], old_license=lambda p: None),
                 "earlier versions that disagree": dict(modules=[("example.com/q", "v2.0.0")]),
                 "a licence that is not text": dict(modules=[("example.com/m", "v1.1.0")],
                     old={"example.com/m@v1.0.0": 7})}
        for name, kw in cases.items():
            with self.assertRaises(V.Skip, msg=name):
                self.carry(**kw)

    def test_the_reasons_name_the_module(self):
        for kw, word in ((dict(modules=[("example.com/m", "v1.1.0")], new_license=lambda p: b"x"), "LICENSE"),
            (dict(modules=[("example.com/new", "v1.0.0")]), "new module")):
            with self.assertRaises(V.Skip) as ctx:
                self.carry(**kw)
            self.assertIn(word, str(ctx.exception)); self.assertIn(kw["modules"][0][0], str(ctx.exception))

    def test_entries_for_versions_that_are_gone_are_dropped(self):
        self.assertEqual(sorted(self.carry([("example.com/m", "v1.1.0")])), ["example.com/m@v1.1.0"])

    def test_rendering_is_the_files_own_layout(self):
        self.assertEqual(V.render_licences({"b@v1": "MIT", "a@v1": "BSD-3-Clause"}),
            b'{\n "a@v1": "BSD-3-Clause",\n "b@v1": "MIT"\n}\n')
        here = os.path.abspath(os.path.join(BIN, "..", "..", ".."))
        raw = read(os.path.join(here, "test-evidence", "dependency-licenses.yaml"))
        # the committed file is exactly what the sweep writes
        self.assertEqual(V.render_licences(json.loads(raw)), raw)

    def test_the_modules_of_a_vendor_modules_txt(self):
        text = (b"# example.com/m v1.1.0\n## explicit; go 1.24\nexample.com/m\n"
                b"# example.com/n v2.0.0-20200101000000-abcdefabcdef\nexample.com/n\n")
        self.assertEqual(V.modules_of(text), [("example.com/m", "v1.1.0"), ("example.com/n",
            "v2.0.0-20200101000000-abcdefabcdef")])
        for bad in (b"", b"# example.com/m v1.0.0 => ../m\n", b"# x\n"):
            with self.assertRaises(V.Skip):
                V.modules_of(bad)


class Regenerate(unittest.TestCase):
    """make_regenerate: the Go steps in order (go mod vendor, the licences, the records step, the provenance build and
    check), each a command run in the
    copy of the branch's tree with a closed environment. A refusal (exit 2) is a Skip; any other failure is an error."""
    TOOLS = "/ws"

    def setUp(self):
        self.work = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.work, True)
        os.makedirs(os.path.join(self.work, "test-evidence"))
        put(self.work, {"dependency-provenance.json": b"old\n"})                 # the branch's tree already has one
        self.calls = []

    def runner(self, fail=None):
        def run(cmd, cwd=None, env=None, capture_output=None, stdin=None):
            self.calls.append((list(cmd), cwd, dict(env)))
            if cmd[1:3] == ["mod", "vendor"]:
                put(cwd, {"vendor/modules.txt": b"# example.com/m v1.1.0\n",
                    "vendor/example.com/m/LICENSE": b"MIT text\n"})
            if "--out-dir" in cmd:
                os.makedirs(cmd[cmd.index("--out-dir") + 1])
            # the real builder refuses a destination that exists; the branch's tree has one
            if "build" in cmd:
                dest = cmd[cmd.index("--out") + 1]
                if os.path.lexists(dest):
                    return subprocess.CompletedProcess(cmd, 2, b"", b"--out %s already exists" % dest.encode())
                put(os.path.dirname(dest), {os.path.basename(dest): b'{"built": true}\n'})
            rc = 0
            for key, code in (fail or {}).items():
                if key in cmd or key in cmd[1:3]:
                    rc = code
            return subprocess.CompletedProcess(cmd, rc, b"", b"the reason it gave\n")
        return run

    def go(self, fail=None, licences=None):
        V.make_regenerate(self.TOOLS, runner=self.runner(fail), go="/go")(self.work,
            {"example.com/m@v1.0.0": "MIT"} if licences is None else licences, lambda p: b"MIT text\n")

    def test_the_steps_run_in_order_with_these_exact_commands(self):
        self.go()
        cmds = [c[0] for c in self.calls]
        self.assertEqual(cmds[0], ["/go", "mod", "vendor"])
        out = cmds[1][cmds[1].index("--out-dir") + 1]
        self.assertEqual(cmds[1], ["python3", "-I", "/ws/bin/vendor-provenance-records.py", "--vendor-dir", "vendor",
            "--go-sum", "go.sum", "--licenses",
                                   "test-evidence/dependency-licenses.yaml", "--recorded-origins",
                                       "test-evidence/dependency-origins.yaml", "--out-dir", out])
        built = cmds[2][cmds[2].index("--out") + 1]
        # a fresh path: the branch's file exists
        self.assertNotEqual(built, os.path.join(self.work, "dependency-provenance.json"))
        self.assertEqual(cmds[2], ["python3", "-I", "/ws/bin/vendor-provenance.py", "build", "--vendor-dir", "vendor",
            "--go-sum", "go.sum",
                                   "--sumdb-record", out + "/sumdb.json", "--origins", out + "/origins.json",
                                       "--licenses", out + "/licenses.json",
                                   "--recorded-origins", "test-evidence/dependency-origins.yaml", "--out", built])
        # then put in place, before the check
        self.assertEqual(read(os.path.join(self.work, "dependency-provenance.json")), b'{"built": true}\n')
        self.assertEqual(cmds[3], ["python3", "-I", "/ws/bin/vendor-provenance.py", "check", "--vendor-dir", "vendor",
            "--go-sum", "go.sum", "--provenance", "dependency-provenance.json"])
        self.assertEqual(len(cmds), 4)
        self.assertTrue(all(c[1] == self.work for c in self.calls))
        # written BEFORE the records step reads it
        self.assertEqual(read(os.path.join(self.work, "test-evidence/dependency-licenses.yaml")),
            b'{\n "example.com/m@v1.1.0": "MIT"\n}\n')

    def test_the_environment_is_closed(self):
        self.go()
        env = self.calls[0][2]
        self.assertEqual({k: v for k, v in env.items() if k.startswith("GO")} | {}, {"GOTOOLCHAIN": "local",
            "GOFLAGS": "", "GOENV": "off", "GOWORK": "off", "GOAUTH": "off",
                         "GOSUMDB": "sum.golang.org", "GOPROXY": "https://proxy.golang.org", "GOPATH": env["GOPATH"],
                             "GOMODCACHE": env["GOMODCACHE"], "GOCACHE": env["GOCACHE"]})
        self.assertNotIn("GITHUB_TOKEN", env); self.assertNotIn("GH_TOKEN", env)
        self.assertEqual(sorted(k for k in env if not k.startswith("GO")), ["HOME", "PATH", "TMPDIR"])

    def test_a_failed_go_mod_vendor_and_a_refused_records_step_or_build_or_check_are_skips_naming_the_reason(self):
        for key, code, word in (("vendor", 1, "go mod vendor"), ("--out-dir", 2, "records step"), ("build", 2,
            "provenance build"), ("check", 2, "provenance check")):
            self.calls.clear()
            shutil.rmtree(self.work)
            os.makedirs(os.path.join(self.work, "test-evidence"))
            put(self.work, {"dependency-provenance.json": b"old\n"})
            with self.assertRaises(V.Skip, msg=key) as ctx:
                self.go(fail={key: code})
            self.assertIn(word, str(ctx.exception)); self.assertIn("the reason it gave", str(ctx.exception))

    def test_any_other_failure_of_a_step_is_an_error_not_a_skip(self):
        for key in ("--out-dir", "build", "check"):
            shutil.rmtree(self.work)
            os.makedirs(os.path.join(self.work, "test-evidence"))
            put(self.work, {"dependency-provenance.json": b"old\n"})
            with self.assertRaises(RuntimeError, msg=key):
                self.go(fail={key: 1})

    def test_a_licence_that_cannot_be_carried_stops_before_the_records_step(self):
        with self.assertRaises(V.Skip):
            self.go(licences={})
        self.assertEqual([c[0][1:3] for c in self.calls], [["mod", "vendor"]])

    def test_a_module_without_a_license_file_is_a_skip_for_the_carry_rule(self):
        def run(cmd, cwd=None, env=None, capture_output=None, stdin=None):
            put(cwd, {"vendor/modules.txt": b"# example.com/m v1.1.0\n"})
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with self.assertRaises(V.Skip):
            V.make_regenerate(self.TOOLS, runner=run, go="/go")(self.work, {"example.com/m@v1.0.0": "MIT"},
                lambda p: b"MIT text\n")


if __name__ == "__main__":
    unittest.main()
