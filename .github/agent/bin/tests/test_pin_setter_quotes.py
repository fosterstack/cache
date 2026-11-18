"""Tests for check-action-pins.py `_outside`: a setter ends at an unquoted `&` or `|`, and quoted text holds no setter."""
import contextlib, importlib.util, io, os, runpy, shutil, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
# the vendored pure-Python PyYAML as `yaml` (the CI coverage job installs no PyYAML of its own)
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins_setter_quotes", SRC)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

GATE = os.path.join(BIN, "..", "..", "workflows", "agent-review-gate.yml")
# the programs the gate workflow names; the checker wants each to exist in the tree
GATE_PROGRAMS = dict.fromkeys([".github/agent/bin/auditor-review-gate.py", ".github/agent/bin/check-action-pins.py",
                              "bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh",
                              "bin/scan-no-workflow-call-test.sh", "bin/audit-record-judge.sh",
                              "bin/audit-record-prepare.sh", ".github/agent/bin/auditor-signed-commit.py"], "")


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


def check(setters, dest="out", env=""):
    """A tree whose one step runs `setters`, copies over the Dockerfile, then builds; `env` is the step's env."""
    lines = [setters, 'cp -R evil/. "$%s"' % dest, "docker build -t img ."]
    run_text = "".join("          " + ln + "\n" for ln in lines)
    wf = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n" + run_text + env)
    d = repo({".github/workflows/w.yml": wf, "Dockerfile": "FROM scratch\n", **GATE_PROGRAMS})
    return d


class Base(unittest.TestCase):
    def flagged(self, setters, dest="out", env=""):
        d = repo_for(self, setters, dest, env)
        code, out = run([d])
        self.assertEqual(code, 1, out)
        self.assertNotIn(" 0 finding(s)", out)

    def clean(self, setters, dest="out"):
        d = repo_for(self, setters, dest)
        code, out = run([d])
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)


def repo_for(case, setters, dest, env=""):
    d = check(setters, dest, env)
    case.addCleanup(shutil.rmtree, d)
    return d


DECOYS = {
    "single_quoted_amp": "printf '%s\\n' 'x&out=$RUNNER_TEMP/x'",
    "double_quoted_pipe": 'echo "ignore|out=$RUNNER_TEMP/x"',
    "double_quoted_space": 'echo "ignore out=$RUNNER_TEMP/x"',
}
CURL_DECOY = 'curl "https://x?a=1&dest=/zz/x"'   # a value that would read as outside if counted
ENV_OUT = "        env:\n          out: .\n"          # the real setter: out=. outside the script text
ENV_DEST = "        env:\n          dest: .\n"
CHAINS = {
    "and": "out=$RUNNER_TEMP/x&&out=.",
    "semicolon_then_and": ":;out=$RUNNER_TEMP/x&&out=.",
    "or": "out=$RUNNER_TEMP/x||out=.",
    "pipe": "out=$RUNNER_TEMP/x|out=.",
}
CONTROLS = {
    "single_real_setter": "out=$RUNNER_TEMP/x",
    "quoted_value": 'out="$RUNNER_TEMP/x"',
    "followed_by_echo": "out=$RUNNER_TEMP/x && echo done",
}


class QuotedDecoyUnit(unittest.TestCase):
    def test_single_quoted_amp(self):
        self.assertIs(M._outside("$out", DECOYS["single_quoted_amp"]), False)

    def test_double_quoted_pipe(self):
        self.assertIs(M._outside("$out", DECOYS["double_quoted_pipe"]), False)

    def test_double_quoted_space(self):
        self.assertIs(M._outside("$out", DECOYS["double_quoted_space"]), False)

    def test_curl_url_decoy(self):
        self.assertIs(M._outside("$dest", CURL_DECOY), False)

    def test_curl_url_decoy_with_later_real_setter(self):
        self.assertIs(M._outside("$dest", CURL_DECOY + "; dest=."), False)


class QuotedDecoyFlagged(Base):
    def test_single_quoted_amp(self):
        self.flagged(DECOYS["single_quoted_amp"], env=ENV_OUT)

    def test_double_quoted_pipe(self):
        self.flagged(DECOYS["double_quoted_pipe"], env=ENV_OUT)

    def test_double_quoted_space(self):
        self.flagged(DECOYS["double_quoted_space"], env=ENV_OUT)

    def test_curl_url_decoy(self):
        self.flagged(CURL_DECOY, "dest", ENV_DEST)


class ChainUnit(unittest.TestCase):
    def test_and(self):
        self.assertIs(M._outside("$out", CHAINS["and"]), False)

    def test_semicolon_then_and(self):
        self.assertIs(M._outside("$out", CHAINS["semicolon_then_and"]), False)

    def test_or(self):
        self.assertIs(M._outside("$out", CHAINS["or"]), False)

    def test_pipe(self):
        self.assertIs(M._outside("$out", CHAINS["pipe"]), False)


class ChainFlagged(Base):
    def test_and(self):
        self.flagged(CHAINS["and"])

    def test_semicolon_then_and(self):
        self.flagged(CHAINS["semicolon_then_and"])

    def test_or(self):
        self.flagged(CHAINS["or"])

    def test_pipe(self):
        self.flagged(CHAINS["pipe"])


class Controls(Base):
    def test_unit_single_real_setter(self):
        self.assertIs(M._outside("$out", CONTROLS["single_real_setter"]), True)

    def test_unit_quoted_value(self):
        self.assertIs(M._outside("$out", CONTROLS["quoted_value"]), True)

    def test_unit_followed_by_echo(self):
        self.assertIs(M._outside("$out", CONTROLS["followed_by_echo"]), True)

    def test_single_real_setter_not_flagged(self):
        self.clean(CONTROLS["single_real_setter"])

    def test_quoted_value_not_flagged(self):
        self.clean(CONTROLS["quoted_value"])

    def test_followed_by_echo_not_flagged(self):
        self.clean(CONTROLS["followed_by_echo"])

    def test_no_setter_is_flagged(self):
        self.flagged("true")


if __name__ == "__main__":
    unittest.main()
