# proves: REQ-VEND-001-AC16, REQ-VEND-001-AC17, REQ-VEND-001-AC21
"""auditor-vendor-records.py: which branches the sweep visits and what its exit code says. The per-branch work is
auditorlib.vendor_records (its own tests)."""
import importlib.util, io, os, subprocess, sys, unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import vendor_records as V  # noqa: E402

spec = importlib.util.spec_from_file_location("vendor_records_cli", os.path.join(BIN, "auditor-vendor-records.py"))
CLI = importlib.util.module_from_spec(spec); spec.loader.exec_module(CLI)


class Cli(unittest.TestCase):
    def gh(self, names, rc=0):
        self.calls = []
        def run(cmd, **kw):
            self.calls.append(list(cmd))
            return subprocess.CompletedProcess(cmd, rc, "\n".join(names) + "\n", "HTTP 500" if rc else "")
        return run

    def main(self, argv, run, answers):
        seen = []
        def process(repo, branch, ws, run_, regenerate, dry_run=False):
            seen.append((repo, branch, ws, dry_run)); return answers.get(branch, "up to date")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(V, "process_branch", process), redirect_stdout(out), redirect_stderr(err):
            rc = CLI.main(argv, run=run, regenerate=lambda *a: None)
        return rc, seen, out.getvalue(), err.getvalue()

    def test_only_the_two_bump_lanes_are_visited_and_skips_are_a_normal_exit(self):
        names = ["main", "auditor/panel", "dependabot/go_modules/x-1.0", "dependabot/npm_and_yarn/y",
            "auditor/bump-a-1.0", "patch-notes/v1"]
        rc, seen, out, err = self.main(["--repo", "o/r", "--workspace", "/ws"], self.gh(names),
            {"auditor/bump-a-1.0": "skipped: because"})
        self.assertEqual(rc, 0)
        self.assertEqual([s[1] for s in seen], ["dependabot/go_modules/x-1.0", "auditor/bump-a-1.0"])
        self.assertEqual(out, "dependabot/go_modules/x-1.0: up to date\nauditor/bump-a-1.0: skipped: because\n")
        self.assertEqual(self.calls, [["gh", "api", "--paginate", "repos/o/r/branches?per_page=100", "--jq",
            ".[].name"]])

    def test_a_status_with_newlines_is_printed_as_one_line(self):
        rc, seen, out, err = self.main(["--repo", "o/r", "--workspace", "/ws", "--branch", "dependabot/go_modules/a"],
            self.gh([]),
                                       {"dependabot/go_modules/a": "skipped: a\nb\r\n  c"})
        self.assertEqual(out, "dependabot/go_modules/a: skipped: a b c\n")

    def test_a_failed_branch_makes_the_exit_one_after_the_others_were_visited(self):
        rc, seen, out, err = self.main(["--repo", "o/r", "--workspace", "/ws", "--dry-run"],
            self.gh(["dependabot/go_modules/a", "dependabot/go_modules/b"]),
                                       {"dependabot/go_modules/a": "failed: boom"})
        self.assertEqual(rc, 1); self.assertEqual(len(seen), 2); self.assertTrue(all(s[3] for s in seen))

    def test_named_branches_are_visited_without_listing(self):
        run = self.gh([])
        rc, seen, out, err = self.main(["--repo", "o/r", "--workspace", "/ws", "--branch", "dependabot/go_modules/a"],
            run, {})
        self.assertEqual((rc, [s[1] for s in seen], self.calls), (0, ["dependabot/go_modules/a"], []))

    def test_a_listing_that_fails_is_exit_one_and_visits_nothing(self):
        rc, seen, out, err = self.main(["--repo", "o/r", "--workspace", "/ws"], self.gh([], rc=1), {})
        self.assertEqual((rc, seen), (1, [])); self.assertIn("could not list the branches: HTTP 500", err)

    def test_the_default_runner_and_regeneration_are_wired(self):
        with mock.patch.object(V, "make_regenerate", return_value="regen") as mk, mock.patch.object(V, "process_branch",
            return_value="gone") as pb, \
                mock.patch.object(CLI.subprocess, "run", self.gh([])), redirect_stdout(io.StringIO()):
            self.assertEqual(CLI.main(["--repo", "o/r", "--workspace", "/ws", "--branch", "auditor/bump-a"]), 0)
        mk.assert_called_once_with("/ws"); self.assertEqual(pb.call_args.args[4], "regen")

    def test_run_as_a_script_it_exits_with_the_argument_parsers_status(self):
        script = os.path.join(BIN, "auditor-vendor-records.py")
        r = subprocess.run([sys.executable, script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2); self.assertIn("--repo", r.stderr)



class Workflow(unittest.TestCase):
    """The vendor-records job in dependabot-reviewer.yml (AC21): main's copy only, a read-only job token, one App token
    with contents:write for this repository."""
    TEXT = open(os.path.join(BIN, "..", "..", "workflows", "dependabot-reviewer.yml")).read()
    JOB = TEXT[TEXT.index("\n  vendor-records:\n"):]

    def test_the_job_runs_in_the_agent_environment_whose_branch_policy_keeps_it_on_main(self):
        self.assertIn("    environment: agent\n", self.JOB)
        # the checkout follows the ref the environment admits
        self.assertNotIn("ref:", self.JOB)

    def test_the_job_token_reads_and_the_one_app_token_writes_contents_of_this_repository(self):
        self.assertIn("    permissions:\n      contents: read\n    steps:", self.JOB)
        self.assertEqual(self.JOB.count("permission-"), 1)
        self.assertIn("          repositories: cache\n          permission-contents: write\n", self.JOB)

    def test_no_pull_request_target_and_no_second_trigger_for_the_job(self):
        self.assertNotIn("pull_request_target", self.TEXT)
        self.assertNotIn("\n  push:", self.TEXT)


if __name__ == "__main__":
    unittest.main()
