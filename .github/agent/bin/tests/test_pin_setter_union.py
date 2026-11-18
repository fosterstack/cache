"""Tests for check-action-pins.py `_outside`: the checker refuses when either of its two setter readers refuses.

Written from the English rules only, not from the checker's source.
"""
import shutil, unittest

from test_pin_setter_quotes import M, check, run, ENV_OUT

SAFE = "out=$RUNNER_TEMP/x"
INDENT = "\n          "

# Setter is not a whole command of the shell that copies, so the step env's `out: .` stays.
# Red on the unfixed checker: pipe_last_assignment, brace_background, brace_in_pipeline,
# pipe_then_substitution_assignment.
ENV_FLAGGED = {
    "background_direct": "out=$RUNNER_TEMP/x&wait",
    "pipeline_direct": "out=$RUNNER_TEMP/x|cat",
    "pipeline_last": "cat|out=$RUNNER_TEMP/x",
    "background_redirect": "out=$RUNNER_TEMP/x >/dev/null &",
    "pipe_redirect": "out=$RUNNER_TEMP/x 2>&1|cat",
    "pipe_assignment": "out=$RUNNER_TEMP/x a=1|cat",
    "pipe_last_assignment": "cat|a=1 out=$RUNNER_TEMP/x",  # red
    "paren_group": "(out=$RUNNER_TEMP/x)",
    "command_substitution": "$(out=$RUNNER_TEMP/x)",
    "prefix_of_command": "out=$RUNNER_TEMP/x true",
    "brace_background": "{ out=$RUNNER_TEMP/x; } &",  # red
    "brace_in_pipeline": "cat | { out=$RUNNER_TEMP/x; }",  # red
    "pipe_then_substitution_assignment": "cat | a=$(x) out=$RUNNER_TEMP/x",  # red
    "pipe_then_arith_assignment": "cat | a=$((1|2)) out=$RUNNER_TEMP/x",
    "and_then_background": "true&&out=$RUNNER_TEMP/x >/dev/null & wait",
    "or_then_background": "false||out=$RUNNER_TEMP/x&wait",
}

# A later real setter after SAFE, no env. Red on the unfixed checker: comment_backslash,
# nested_quotes_substitution, nested_quotes_backticks.
LATER_FLAGGED = {
    "and_setter": [SAFE, "true&&out=."],
    "or_setter": [SAFE, "false||out=."],
    "comment_backslash": [SAFE, "#comment\\", "out=."],  # red
    "nested_quotes_substitution": [SAFE, 'echo "$(echo "\'")"', "#c\\", "out=."],  # red
    "nested_quotes_backticks": [SAFE, 'echo "`echo "\'"`"', "#c\\", "out=."],  # red
    "quoted_hash_continuation": [SAFE, 'echo " #"; ou\\', "t=."],
    "escaped_hash_continuation": [SAFE, "echo \\#; ou\\", "t=."],
    "escaped_semicolon_hash_continuation": [SAFE, "echo \;#x; ou\\", "t=."],
}

# A heredoc body is text: its lone quote opens no quote after it. All red on the unfixed checker.
HEREDOC = ["cat <<EOF", '"', "EOF"]
HEREDOC_FLAGGED = {
    "one_heredoc_comment": [SAFE, *HEREDOC, "#\\", "out=."],
    "two_heredocs_comment": [SAFE, *HEREDOC, "#\\", "out=.", *HEREDOC],
    "one_heredoc_escaped_hash": [SAFE, *HEREDOC, "echo \\#", "out=."],
    "two_heredocs_escaped_hash": [SAFE, *HEREDOC, "echo \\#", "out=.", *HEREDOC],
}

# End to end only: a backslash-newline splits the name.
CONTINUATION_FLAGGED = {"line_continuation": [SAFE, "ou\\", "t=."]}

# Both readers: the checker's own reader refuses these, the union keeps that.
OWN_FLAGGED = {
    "other_assignment": [SAFE + " other=1"],
    "redirect": [SAFE + " >/dev/null"],
}

# Default names: the read or mapfile with no name resets the copy's variable.
DEFAULT_FLAGGED = {
    "reply_redirect_read": ("REPLY", ["REPLY=$RUNNER_TEMP/x", "12>/dev/null read -r <<< ."]),
    "reply_command_read": ("REPLY", ["REPLY=$RUNNER_TEMP/x", "command read <<< ."]),
    "reply_read_E": ("REPLY", ["REPLY=$RUNNER_TEMP/x", "read -E <<< ."]),
    "mapfile_command": ("MAPFILE", ["MAPFILE=$RUNNER_TEMP/x", "command mapfile -t <<< ."]),
    "mapfile_d_option": ("MAPFILE", ["MAPFILE=$RUNNER_TEMP/x", "mapfile -t -d -abc <<< ."]),
}

CLEAN = {
    "and_after_true": ["true&&" + SAFE],
    "or_after_false": ["false||" + SAFE],
    "and_then_cat": [SAFE + "&&cat"],
    "or_then_cat": [SAFE + "||cat"],
    "semicolon_wait": [SAFE + ";wait"],
    "value_continuation": ["out=$RUNNER_TEMP/\\", "x"],
    "comment_pipe_before": ["# comment |", SAFE],
    "escaped_pipe_before": ["echo \\|", SAFE],
    "comment_backslash_after": [SAFE, "#comment\\", "echo hi"],
    "alone": [SAFE],
    "quoted_setter_text": [SAFE, "echo 'out=.'"],
}


def text(lines):
    return "\n".join(lines)


class SetterUnion(unittest.TestCase):
    def flagged(self, setters, dest="out", env=""):
        d = check(setters, dest, env)
        self.addCleanup(shutil.rmtree, d)
        code, out = run([d])
        self.assertEqual(code, 1, out)
        self.assertNotIn(" 0 finding(s)", out)

    def clean(self, setters, dest="out"):
        d = check(setters, dest)
        self.addCleanup(shutil.rmtree, d)
        code, out = run([d])
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)

    def test_unit_env_flagged(self):
        for name, setter in ENV_FLAGGED.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", setter), False)

    def test_end_to_end_env_flagged(self):
        for name, setter in ENV_FLAGGED.items():
            with self.subTest(name):
                self.flagged(setter, env=ENV_OUT)

    def test_unit_later_setter_flagged(self):
        for name, lines in {**LATER_FLAGGED, **OWN_FLAGGED}.items():
            if name.endswith("_continuation"):
                continue  # a join of backslash-newline is end to end only
            with self.subTest(name):
                self.assertIs(M._outside("$out", text(lines)), False)

    def test_end_to_end_later_setter_flagged(self):
        cases = {**LATER_FLAGGED, **HEREDOC_FLAGGED, **CONTINUATION_FLAGGED, **OWN_FLAGGED}
        for name, lines in cases.items():
            with self.subTest(name):
                self.flagged(INDENT.join(lines))

    def test_unit_default_names_flagged(self):
        for name, (dest, lines) in DEFAULT_FLAGGED.items():
            with self.subTest(name):
                self.assertIs(M._outside("$" + dest, text(lines)), False)

    def test_end_to_end_default_names_flagged(self):
        for name, (dest, lines) in DEFAULT_FLAGGED.items():
            with self.subTest(name):
                self.flagged(INDENT.join(lines), dest)

    def test_unit_clean(self):
        for name, lines in CLEAN.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", text(lines)), True)

    def test_end_to_end_clean(self):
        for name, lines in CLEAN.items():
            with self.subTest(name):
                self.clean(INDENT.join(lines))


if __name__ == "__main__":
    unittest.main()
