"""auditor-signed-commit.py: the release workflow's way to make a signed commit through the API. Arguments, file reading (a missing path is a
deletion), the two accepted prefixes, exit codes. A recording fake `gh`; nothing touches the network."""
import importlib.util, io, json, os, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
sys.path.insert(0, os.path.dirname(__file__))
from auditorlib import signed_commit as S  # noqa: E402
import test_signed_commit as T  # noqa: E402

_spec = importlib.util.spec_from_file_location("auditor_signed_commit_cli", os.path.join(BIN, "auditor-signed-commit.py"))
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

BASE, OID, REPO = "1" * 40, "2" * 40, "o/r"
BR = "patch-notes/v0.2.9"


class Fake(T.Prefixes.Rec):
    pass


def argv(**over):
    a = {"--repo": REPO, "--branch": BR, "--base": BASE, "--prefix": "patch-notes/", "--message": "Release notes for v0.2.9: x"}
    a.update(over)
    out = []
    for k, v in a.items():
        if v is not None:
            out += [k, v]
    return out


class Cli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory(); self.addCleanup(self.dir.cleanup)
        os.makedirs(os.path.join(self.dir.name, "docs"))
        with open(os.path.join(self.dir.name, "docs", "a.md"), "wb") as f:
            f.write(b"A\n")
        p = mock.patch.object(S, "_tmp_branch", lambda base: "auditor/tmp-test0001"); p.start(); self.addCleanup(p.stop)

    def run_cli(self, args, rec=None):
        out, err = io.StringIO(), io.StringIO()
        rec = rec or Fake()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            rc = C.main(args, run=rec, root=self.dir.name)
        return rc, out.getvalue(), err.getvalue(), rec

    def test_a_commit_prints_only_the_new_oid_and_exits_zero(self):
        rc, out, err, rec = self.run_cli(argv() + ["--path", "docs/a.md"])
        self.assertEqual((rc, out, err), (0, OID + "\n", ""))
        gql = [c for c in rec.calls if c[2] == "graphql"]
        self.assertEqual(len(gql), 1)

    def test_files_are_read_from_the_working_directory_and_a_missing_path_is_a_deletion(self):
        seen = []
        rec = Fake(); orig = rec.__call__
        def spy(cmd, **kw):
            if cmd[2] == "graphql":
                seen.append(json.loads(kw["input"])["variables"]["input"])
            return orig(cmd, **kw)
        rc, out, err, _ = self.run_cli(argv() + ["--path", "docs/a.md", "--path", "docs/gone.md"], rec=spy)
        self.assertEqual(rc, 0)
        fc = seen[0]["fileChanges"]
        self.assertEqual([a["path"] for a in fc["additions"]], ["docs/a.md"])
        self.assertEqual(fc["deletions"], [{"path": "docs/gone.md"}])
        self.assertEqual(seen[0]["branch"]["branchName"], "auditor/tmp-test0001")
        self.assertEqual(seen[0]["expectedHeadOid"], BASE)
        self.assertEqual(seen[0]["message"]["headline"], "Release notes for v0.2.9: x")

    def test_the_branch_must_be_in_a_prefix_the_caller_named(self):
        for br, prefix in (("auditor/x", "patch-notes/"), (BR, "auditor/"), ("main", "patch-notes/")):
            rc, out, err, rec = self.run_cli(argv(**{"--branch": br, "--prefix": prefix}) + ["--path", "docs/a.md"])
            self.assertEqual((rc, out), (1, ""), br)
            self.assertIn("refusing branch", err); self.assertEqual(rec.calls, [], br)
        rc, out, err, rec = self.run_cli(argv(**{"--branch": "auditor/x", "--prefix": "auditor/"}) + ["--prefix", "patch-notes/", "--path", "docs/a.md"])
        self.assertEqual((rc, out), (0, OID + "\n"))                                 # repeatable: either lane is allowed

    def test_only_the_two_prefixes_are_accepted(self):
        for bad in ("main/", "release/", "", "auditor", "refs/heads/", "patch-notes"):
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stderr", io.StringIO()):
                C.main(argv(**{"--prefix": bad}) + ["--path", "docs/a.md"], run=Fake(), root=self.dir.name)
            self.assertEqual(cm.exception.code, 2, bad)

    def test_required_arguments_are_required(self):
        full = argv() + ["--path", "docs/a.md"]
        for drop in ("--repo", "--branch", "--base", "--prefix", "--message", "--path"):
            a = list(full)
            while drop in a:
                i = a.index(drop); del a[i:i + 2]
            with self.assertRaises(SystemExit) as cm, mock.patch("sys.stderr", io.StringIO()):
                C.main(a, run=Fake(), root=self.dir.name)
            self.assertEqual(cm.exception.code, 2, drop)

    def test_bad_values_exit_nonzero_with_a_plain_message_and_no_call(self):
        cases = [argv(**{"--repo": "o"}), argv(**{"--base": "abc"}), argv(**{"--message": "  "}), argv(**{"--base": "A" * 40})]
        for a in cases:
            rc, out, err, rec = self.run_cli(a + ["--path", "docs/a.md"])
            self.assertEqual((rc, out), (1, ""), a); self.assertTrue(err.startswith("auditor-signed-commit: "), err); self.assertEqual(rec.calls, [])
        for p in ("/etc/passwd", "../x", "docs/../../x", "a//b", "./x", "docs/"):
            rc, out, err, rec = self.run_cli(argv() + ["--path", p])
            self.assertEqual((rc, out), (1, ""), p); self.assertIn("path", err); self.assertEqual(rec.calls, [], p)

    def test_a_symlink_is_refused_not_followed(self):
        os.symlink("/etc/hostname", os.path.join(self.dir.name, "docs", "link.md"))
        os.symlink("/nonexistent/x", os.path.join(self.dir.name, "docs", "dangling.md"))
        for p in ("docs/link.md", "docs/dangling.md"):
            rc, out, err, rec = self.run_cli(argv() + ["--path", p])
            self.assertEqual((rc, out), (1, ""), p); self.assertIn("symlink", err); self.assertEqual(rec.calls, [])

    def test_a_symlinked_directory_in_the_path_is_refused_before_anything_is_read(self):
        with tempfile.TemporaryDirectory() as out:
            with open(os.path.join(out, "secret.txt"), "wb") as f:
                f.write(b"SECRET")
            os.symlink(out, os.path.join(self.dir.name, "outside"))                  # out of the tree
            os.symlink(os.path.join(self.dir.name, "docs"), os.path.join(self.dir.name, "inside"))   # stays in the tree
            for p in ("outside/secret.txt", "inside/a.md"):
                rc, o, err, rec = self.run_cli(argv() + ["--path", p])
                self.assertEqual((rc, o), (1, ""), p); self.assertIn("symlink", err); self.assertEqual(rec.calls, [], p)
        rc, o, err, rec = self.run_cli(argv() + ["--path", "docs/a.md"])             # the plain case still works
        self.assertEqual((rc, o), (0, OID + "\n"))

    def test_a_commit_error_is_a_nonzero_exit_with_the_reason_and_no_oid(self):
        class Fail(Fake):
            def __call__(self, cmd, **kw):
                if cmd[2] == "graphql":
                    self.calls.append(list(cmd))
                    return subprocess.CompletedProcess(cmd, 1, "", "HTTP 502")
                return super().__call__(cmd, **kw)
        rc, out, err, rec = self.run_cli(argv() + ["--path", "docs/a.md"], rec=Fail())
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("createCommitOnBranch failed", err); self.assertIn("HTTP 502", err)

    def test_an_unsigned_commit_is_a_nonzero_exit(self):
        class Unsigned(Fake):
            def __call__(self, cmd, **kw):
                if cmd[2] == "graphql":
                    self.calls.append(list(cmd))
                    return subprocess.CompletedProcess(cmd, 0, T.mutation(signature={"isValid": False, "state": "UNSIGNED"}), "")
                return super().__call__(cmd, **kw)
        rc, out, err, _ = self.run_cli(argv() + ["--path", "docs/a.md"], rec=Unsigned())
        self.assertEqual((rc, out), (1, "")); self.assertIn("NOT validly signed", err)

    def test_the_script_runs_as_a_program_and_fails_closed_without_a_token(self):
        env = dict(os.environ, PATH=self.dir.name)                                    # no gh on PATH: every API call fails, nothing is reachable
        r = subprocess.run([sys.executable, os.path.join(BIN, "auditor-signed-commit.py")] + argv() + ["--path", "docs/a.md"],
                           cwd=self.dir.name, env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0); self.assertEqual(r.stdout, "")
        r = subprocess.run([sys.executable, os.path.join(BIN, "auditor-signed-commit.py")], cwd=self.dir.name, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
