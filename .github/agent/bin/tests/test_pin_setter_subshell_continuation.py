"""Tests for check-action-pins.py `_outside`: background and pipeline setters, and backslash-newline joins.

Written from the English rules only, not from the checker's source.
"""
import unittest

from test_pin_setter_quotes import M, Base, ENV_OUT

SAFE = "$RUNNER_TEMP/x"
SUBSHELL = {
    "b1_amp_wait": "out=%s&wait" % SAFE,
    "b1_amp_space_wait": "out=%s & wait" % SAFE,
    "b1_trailing_amp": "out=%s &" % SAFE,
    "b2_pipe": "out=%s|cat" % SAFE,
    "b2_pipe_space": "out=%s | cat" % SAFE,
    "b2_after_pipe": "echo hi | out=%s" % SAFE,
    "b2_after_pipe_amp": "echo hi |& out=%s" % SAFE,
}
IN_SHELL = {
    "and_echo_spaced": "out=%s && echo done" % SAFE,
    "true_and": "true&&out=%s" % SAFE,
    "false_or": "false||out=%s" % SAFE,
    "semicolon": "true;out=%s" % SAFE,
    "and_echo": "out=%s&&echo a" % SAFE,
    "or_echo": "out=%s||echo a" % SAFE,
}


class SubshellUnit(unittest.TestCase):
    def test_subshell_setter_is_not_outside(self):
        for k, s in SUBSHELL.items():
            with self.subTest(k):
                self.assertIs(M._outside("$out", s), False)

    def test_in_shell_setter_is_outside(self):
        for k, s in IN_SHELL.items():
            with self.subTest(k):
                self.assertIs(M._outside("$out", s), True)

    def test_real_setter_before_subshell_one_decides(self):
        self.assertIs(M._outside("$out", "out=%s; out=%s&wait" % (SAFE, SAFE.replace("x", "y"))), True)
        self.assertIs(M._outside("$out", "out=.; out=%s&wait" % SAFE), False)


class SubshellFlagged(Base):
    def test_flagged(self):
        for k, s in SUBSHELL.items():
            with self.subTest(k):
                self.flagged(s, env=ENV_OUT)

    def test_clean(self):
        for k, s in IN_SHELL.items():
            with self.subTest(k):
                self.clean(s)


class ContinuationUnit(unittest.TestCase):
    def test_joined_setter_dot(self):
        self.assertIs(M._outside("$out", "ou\\\nt=."), False)

    def test_joined_value_safe(self):
        self.assertIs(M._outside("$out", "out=$RUNNER_TEMP/\\\nx"), True)

    def test_comment_does_not_join(self):
        self.assertIs(M._outside("$out", "# note \\\nout=."), False)

    def test_single_quotes_keep_backslash_newline(self):
        self.assertIs(M._outside("$out", "echo 'a\\\nb'\nout=%s" % SAFE), True)

    def test_double_backslash_does_not_join(self):
        self.assertIs(M._outside("$out", "\\\\\nout=."), False)


class ContinuationFlagged(Base):
    def test_joined_setter_flagged(self):
        self.flagged("ou\\\n          t=.")

    def test_joined_value_clean(self):
        self.clean("out=$RUNNER_TEMP/\\\n          x")


class ContinuationHidesSetterUnit(unittest.TestCase):
    def test_continuation_behind_safe_setter(self):
        cases = {
            "newline": "out=%s\nou\\\nt=." % SAFE,
            "semicolon": "out=%s; ou\\\nt=." % SAFE,
            "joined_read": "read ou\\\nt <<< x\nout=%s" % SAFE,
        }
        for k, s in cases.items():
            with self.subTest(k):
                self.assertIs(M._outside("$out", s), False)


class ContinuationHidesSetterFlagged(Base):
    def test_safe_then_joined_dot(self):
        self.flagged("out=$RUNNER_TEMP/x\n          ou\\\n          t=.")
