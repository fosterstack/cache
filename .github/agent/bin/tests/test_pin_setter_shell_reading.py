"""Tests for check-action-pins.py `_outside`: a setter is read as bash reads it, and the gate fails closed."""
import shutil, unittest

from test_pin_setter_quotes import M, check, run, ENV_OUT

GOOD = "out=$RUNNER_TEMP/x"
INDENT = "\n          "

SCRIPTS = {
    "redirect_clobber": ["out=.>|/dev/null"],
    "redirect_dup_out": ["out=.>&2"],
    "redirect_dup_in": ["out=.<&0"],
    "comment_pipe_before": ["# note |", "out=."],
    "escaped_pipe_before": [r"echo \|", "out=."],
    "lastpipe_lines": ["shopt -s lastpipe", "printf x | out=."],
    "lastpipe_one_line": ["shopt -s lastpipe; true | out=."],
    "param_pipe_trim": ["v=.", "out=${v%|}"],
    "subshell_pipe": ["out=$(pwd|cat)"],
    "param_pipe_replace": ["out=${PWD//|/}"],
    "subshell_amp": ["out=$(pwd&wait)"],
    "backtick_pipe": ["out=`pwd|cat`"],
    "default_dot_pipe": ["out=${unset:-.|}"],
    "default_dot_amp": ["out=${unset:-.&}"],
    "alt_pipe": ["out=${unset:+|}"],
    "heredoc_quote_hides_setter": ["cat <<EOF", '"', "EOF", "#\\", "out=.", "cat <<EOF", '"', "EOF"],
}
ONE_HEREDOC = ["cat <<EOF", '"', "EOF", "#\\", "out=."]

CLEAN = {
    "comment_pipe": ["# note |", GOOD],
    "escaped_pipe": [r"echo \|", GOOD],
    "plain": [GOOD],
    "and_chain": ["true&&" + GOOD],
    "then_echo": [GOOD + "; echo done"],
}

BACKGROUND = {
    "background_after_redirect": "true&&out=$RUNNER_TEMP/x >/dev/null & wait",
    "background_after_other_setter": "true&&out=$RUNNER_TEMP/x other=y & wait",
}


class SetterShellReading(unittest.TestCase):
    def flagged(self, setters, env=""):
        d = check(setters, env=env)
        self.addCleanup(shutil.rmtree, d)
        code, out = run([d])
        self.assertEqual(code, 1, out)
        self.assertNotIn(" 0 finding(s)", out)

    def clean(self, setters):
        d = check(setters)
        self.addCleanup(shutil.rmtree, d)
        code, out = run([d])
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)

    def test_unit_script_with_a_real_setter_is_not_outside(self):
        for name, lines in SCRIPTS.items():
            with self.subTest(name):
                script = "\n".join([GOOD, *lines])
                self.assertIs(M._outside("$out", script), False)

    def test_end_to_end_script_with_a_real_setter_is_flagged(self):
        for name, lines in SCRIPTS.items():
            if name != "heredoc_quote_hides_setter":
                with self.subTest(name):
                    self.flagged(INDENT.join([GOOD, *lines]))

    def test_end_to_end_one_heredoc_then_comment_backslash_setter_is_flagged(self):
        self.flagged(INDENT.join([GOOD, *ONE_HEREDOC]))

    def test_lastpipe_with_semicolons_on_one_line_is_flagged(self):
        self.flagged("out=$RUNNER_TEMP/x; shopt -s lastpipe; true | out=.")

    def test_unit_lastpipe_with_semicolons_on_one_line_is_not_outside(self):
        script = "out=$RUNNER_TEMP/x; shopt -s lastpipe; true | out=."
        self.assertIs(M._outside("$out", script), False)

    def test_background_setter_leaves_the_env_dot(self):
        for name, setter in BACKGROUND.items():
            with self.subTest(name):
                self.flagged(setter, env=ENV_OUT)

    def test_harmless_scripts_stay_clean(self):
        for name, lines in CLEAN.items():
            with self.subTest(name):
                self.clean(INDENT.join(lines))


if __name__ == "__main__":
    unittest.main()
