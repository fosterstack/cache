"""Tests for check-action-pins.py `_outside`: which `NAME=value` text reads as a command-start setter."""
import importlib.util, os, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
# the vendored pure-Python PyYAML as `yaml` (the CI coverage job installs no PyYAML of its own)
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins_values_setter", SRC)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)


class OutsideSetter(unittest.TestCase):
    def test_and_no_blanks(self):
        self.assertIs(M._outside("$out", 'true&&out=$RUNNER_TEMP/x'), True)

    def test_and_blanks(self):
        self.assertIs(M._outside("$out", 'true && out=$RUNNER_TEMP/x'), True)

    def test_or_no_blanks(self):
        self.assertIs(M._outside("$out", 'false||out=$RUNNER_TEMP/x'), True)

    def test_or_blanks(self):
        self.assertIs(M._outside("$out", 'false || out=$RUNNER_TEMP/x'), True)

    def test_semicolon_no_blanks(self):
        self.assertIs(M._outside("$out", ':;out=$RUNNER_TEMP/x'), True)

    def test_semicolon_blanks(self):
        self.assertIs(M._outside("$out", ': ; out=$RUNNER_TEMP/x'), True)

    def test_double_bracket_comparison_unread(self):
        self.assertIs(M._outside("$a", '[[ a == $RUNNER_TEMP/x ]]'), False)

    def test_single_bracket_comparison_unread(self):
        self.assertIs(M._outside("$x", '[ x==$RUNNER_TEMP/y ]'), False)

    def test_comparison_after_and_unread(self):
        self.assertIs(M._outside("$x", 'true&&[ x==$RUNNER_TEMP/y ]'), False)

    def test_mixed_one_inside_is_false(self):
        self.assertIs(M._outside("$out", 'out=$RUNNER_TEMP/a; true&&out=b'), False)


if __name__ == "__main__":
    unittest.main()
