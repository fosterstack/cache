"""Tests for check-action-pins.py `_outside`: a setter in a background job or a pipeline runs in a subshell, and a line continuation joins a word."""
import unittest

from test_pin_setter_quotes import ENV_OUT, M, Base

# each case is the script's lines; the shell that copies has out=. (the step's env, or the joined word)
HOLES = {
    "background_direct": ["out=$RUNNER_TEMP/x&wait"],
    "pipeline_direct": ["out=$RUNNER_TEMP/x|cat"],
    "pipeline_last": ["cat|out=$RUNNER_TEMP/x"],
    "line_continuation": ["out=$RUNNER_TEMP/x", "ou\\", "t=."],
}
# the safe twins: the setter runs in the shell that copies, so the copy goes to a safe folder
TWINS = {
    "background_after": ["out=$RUNNER_TEMP/x;wait"],
    "and_list": ["out=$RUNNER_TEMP/x&&cat"],
    "or_list": ["out=$RUNNER_TEMP/x||cat"],
    "line_continuation": ["out=$RUNNER_TEMP/\\", "x"],
}


class HolesUnit(unittest.TestCase):
    def test_holes_leave_out_unset(self):
        for name, lines in HOLES.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", "\n".join(lines)), False)

    def test_twins_set_out(self):
        for name, lines in TWINS.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", "\n".join(lines)), True)


class HolesFlagged(Base):
    def test_holes(self):
        for name, lines in HOLES.items():
            with self.subTest(name):
                self.flagged("\n          ".join(lines), env=ENV_OUT)


class TwinsClean(Base):
    def test_twins(self):
        for name, lines in TWINS.items():
            with self.subTest(name):
                self.clean("\n          ".join(lines))


if __name__ == "__main__":
    unittest.main()
