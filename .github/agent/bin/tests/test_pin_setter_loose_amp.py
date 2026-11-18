"""Tests for check-action-pins.py `_outside`: `out=$safe&wait` and `out=$safe|cat` run in a background job or a pipeline subshell, so the parent shell's `out` stays `.`."""
import unittest

from test_pin_setter_quotes import ENV_OUT, M, Base

# each case is the script's lines; the parent shell's out is still . where the copy runs
CASES = {
    "background_job": ["safe=$RUNNER_TEMP/x", "out=$safe&wait"],
    "pipeline_subshell": ["safe=$RUNNER_TEMP/x", "out=$safe|cat"],
}


class LooseAmpUnit(unittest.TestCase):
    def test_background_job(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["background_job"])), False)

    def test_pipeline_subshell(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["pipeline_subshell"])), False)


class LooseAmpFlagged(Base):
    def test_background_job(self):
        self.flagged("; ".join(CASES["background_job"]), env=ENV_OUT)

    def test_pipeline_subshell(self):
        self.flagged("; ".join(CASES["pipeline_subshell"]), env=ENV_OUT)


if __name__ == "__main__":
    unittest.main()
