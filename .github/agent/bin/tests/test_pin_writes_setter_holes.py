"""Tests for check-action-pins.py: setters hidden by process substitution or named by default.

Written from the English rules only, not from the checker's source.
"""
import importlib.util, os, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins", SRC)
M = importlib.util.module_from_spec(_spec)
sys.modules["check_action_pins"] = M
_spec.loader.exec_module(M)

REL = "scripts/build.sh"


def w(script):
    return bool(M._writes(script, REL))


def fixture(var, setter):
    # Every case has one shape: var set outside the checkout, a setter, a copy onto var, a run.
    return "%s=$RUNNER_TEMP/out\n%s\ncp payload \"$%s\"\nbash scripts/build.sh\n" % (var, setter, var)


class ProcessSubstitution(unittest.TestCase):
    def test_setter_with_process_substitution_writes(self):
        for setter in ['read < <(echo scripts/build.sh) out',
                       'read -r < <(echo scripts/build.sh) out',
                       'read out < <(echo scripts/build.sh)',
                       'mapfile -t < <(echo scripts/build.sh) out',
                       'mapfile -t out < <(echo scripts/build.sh)',
                       'read out > >(cat)']:
            with self.subTest(setter=setter):
                self.assertTrue(w(fixture("out", setter)))

    def test_process_substitution_without_setter_is_not_a_write(self):
        for setter in ['cat <(echo scripts/build.sh) > /dev/null',
                       'diff <(echo a) <(echo b)',
                       'echo read <(echo x)']:
            with self.subTest(setter=setter):
                self.assertFalse(w(fixture("out", setter)))

    def test_setter_naming_other_variable_is_not_a_write(self):
        self.assertFalse(w(fixture("out", 'read other < <(echo x)')))


class DefaultNames(unittest.TestCase):
    def test_bare_read_and_select_set_reply(self):
        for setter in ['read <<< scripts/build.sh',
                       'read -r <<< scripts/build.sh',
                       'read -r < file',
                       'read < /dev/null',
                       'IFS= read -r <<< scripts/build.sh',
                       'select x in a b; do break; done']:
            with self.subTest(setter=setter):
                self.assertTrue(w(fixture("REPLY", setter)))

    def test_bare_mapfile_and_readarray_set_mapfile(self):
        for setter in ['mapfile -t <<< scripts/build.sh',
                       'readarray -t <<< scripts/build.sh']:
            with self.subTest(setter=setter):
                self.assertTrue(w(fixture("MAPFILE", setter)))

    def test_explicit_name_leaves_default_alone(self):
        for setter in ['read -r line <<< x',
                       'read -a arr <<< x',
                       'read -p "prompt: " v']:
            with self.subTest(setter=setter):
                self.assertFalse(w(fixture("REPLY", setter)))
        self.assertFalse(w(fixture("MAPFILE", 'mapfile -t lines < f')))
        self.assertFalse(w(fixture("MAPFILE", 'readarray -t lines < f')))

    def test_no_setter_command_is_not_a_write(self):
        self.assertFalse(w(fixture("REPLY", 'true')))
        self.assertFalse(w(fixture("REPLY", 'echo read')))
        self.assertFalse(w(fixture("MAPFILE", 'true')))


if __name__ == "__main__":
    unittest.main()
