"""Tests for check-action-pins.py: env-file writes made inside a committed script a step runs.

A step may not set a startup-hook name through $GITHUB_ENV, nor write $GITHUB_PATH. The same write made
in a committed script (`run: ./bin/setup.sh`, a file in the tree) is refused the same way; a finding
names the job, the step and the name (or the route).
"""
import contextlib, importlib.util, io, os, runpy, shutil, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
# the vendored pure-Python PyYAML as `yaml` (the CI coverage job installs no PyYAML of its own)
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins_script_writes", SRC)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

GATE = os.path.join(BIN, "..", "..", "workflows", "agent-review-gate.yml")
# the programs the gate workflow names; the checker wants each to exist in the tree
GATE_PROGRAMS = dict.fromkeys([".github/agent/bin/auditor-review-gate.py", ".github/agent/bin/check-action-pins.py",
                              "bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh",
                              "bin/scan-no-workflow-call-test.sh", "bin/audit-record-judge.sh",
                              "bin/audit-record-prepare.sh", ".github/agent/bin/auditor-signed-commit.py"], "")
WORKFLOW = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./bin/setup.sh\n"


def repo(files, gate=True):
    """A throwaway tree; it carries the real, pinned gate workflow unless gate=False."""
    if gate:
        with open(GATE) as fh:
            files = {".github/workflows/agent-review-gate.yml": fh.read(), **files}
    d = tempfile.mkdtemp()
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
    return d


def run(argv, cwd=None):
    out, old = io.StringIO(), os.getcwd()
    try:
        if cwd:
            os.chdir(cwd)
        with mock.patch.object(sys, "argv", ["check-action-pins.py", *argv]), contextlib.redirect_stdout(out):
            try:
                runpy.run_path(SRC, run_name="__main__")
                code = 0
            except SystemExit as e:
                code = e.code
    finally:
        os.chdir(old)
    return code, out.getvalue()


class ScriptWrites(unittest.TestCase):
    def check(self, line):
        """Check a tree whose one step runs ./bin/setup.sh, a script holding `line`."""
        d = repo({".github/workflows/w.yml": WORKFLOW, "bin/setup.sh": "#!/usr/bin/env bash\n" + line + "\n",
                  **GATE_PROGRAMS})
        self.addCleanup(shutil.rmtree, d)
        return run([d])

    def refused(self, line, name):
        code, out = self.check(line)
        self.assertEqual(code, 1, out)
        self.assertNotIn(" 0 finding(s)", out)
        self.assertIn(".github/workflows/w.yml", out)
        self.assertIn("build", out)
        self.assertIn("step 1", out)
        self.assertIn(name, out)

    def test_script_writing_a_startup_hook_name_to_github_env_is_refused(self):
        self.refused('echo "BASH_ENV=x" >> "$GITHUB_ENV"', "BASH_ENV")

    def test_script_writing_github_path_is_refused(self):
        self.refused('echo "bin" >> "$GITHUB_PATH"', "GITHUB_PATH")

    def test_script_writing_an_unrelated_name_to_github_env_is_accepted(self):
        code, out = self.check('echo "REF=x" >> "$GITHUB_ENV"')
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)


    def split(self, step, script, job_env=""):
        """Check a tree whose one step (YAML lines `step`) runs a script holding `script`."""
        wf = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n" + job_env
              + "    steps:\n      - " + step + "\n")
        d = repo({".github/workflows/w.yml": wf, "bin/setup.sh": "#!/usr/bin/env bash\n" + script + "\n",
                  **GATE_PROGRAMS})
        self.addCleanup(shutil.rmtree, d)
        return run([d])

    def split_refused(self, step, script, job_env=""):
        code, out = self.split(step, script, job_env)
        self.assertEqual(code, 1, out)
        self.assertNotIn(" 0 finding(s)", out)
        self.assertIn("build", out)
        self.assertIn("step 1", out)
        self.assertIn("CURL_HOME", out)

    def test_route_in_run_text_and_name_in_script_is_refused(self):
        self.split_refused("run: OUT=\"$GITHUB_ENV\" bash ./bin/setup.sh",
                           'echo "CURL_HOME=x" >> "$OUT"')

    def test_route_in_step_env_and_name_in_script_is_refused(self):
        self.split_refused("run: bash ./bin/setup.sh\n        env: {OUT: '${{ github.env }}'}",
                           'echo "CURL_HOME=x" >> "$OUT"')

    def test_route_in_job_env_and_name_in_script_is_refused(self):
        self.split_refused("run: bash ./bin/setup.sh", 'echo "CURL_HOME=x" >> "$OUT"',
                           "    env: {OUT: '${{ github.env }}'}\n")

    def test_name_in_step_env_and_route_in_script_is_refused(self):
        self.split_refused("run: bash ./bin/setup.sh\n        env: {N: CURL_HOME}",
                           'echo "$N=x" >> "$GITHUB_ENV"')

    def test_route_in_run_text_and_unrelated_name_in_script_is_accepted(self):
        code, out = self.split("run: OUT=\"$GITHUB_ENV\" bash ./bin/setup.sh", 'echo "REF=x" >> "$OUT"')
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)


if __name__ == "__main__":
    unittest.main()
