"""Tests for check-action-pins.py `_outside`: a setter after `&&`, `||` or `;` is read, and `out==x` sets "=x"."""
import unittest

from test_pin_setter_quotes import M, Base


class AfterOperatorsUnit(unittest.TestCase):
    def test_and_safe_is_outside(self):
        self.assertIs(M._outside("$out", "true&&out=$RUNNER_TEMP/x"), True)

    def test_and_dot_is_not_outside(self):
        self.assertIs(M._outside("$out", "true&&out=."), False)

    def test_or_dot_is_not_outside(self):
        self.assertIs(M._outside("$out", "false||out=."), False)

    def test_semicolon_dot_is_not_outside(self):
        self.assertIs(M._outside("$out", "true;out=."), False)

    def test_or_safe_is_outside(self):
        self.assertIs(M._outside("$out", "false||out=$RUNNER_TEMP/x"), True)

    def test_semicolon_safe_is_outside(self):
        self.assertIs(M._outside("$out", "true;out=$RUNNER_TEMP/x"), True)

    def test_safe_then_and_dot(self):
        self.assertIs(M._outside("$out", "out=$RUNNER_TEMP/x\ntrue&&out=."), False)

    def test_double_equals(self):
        self.assertIs(M._outside("$out", "out==build.sh"), False)

    def test_double_equals_after_and(self):
        self.assertIs(M._outside("$out", "true&&out==build.sh"), False)

    def test_double_equals_after_or(self):
        self.assertIs(M._outside("$out", "false||out==build.sh"), False)

    def test_double_equals_after_semicolon(self):
        self.assertIs(M._outside("$out", "true;out==build.sh"), False)

    def test_double_equals_after_safe_setter(self):
        self.assertIs(M._outside("$out", "out=$RUNNER_TEMP/x\ntrue&&out==build.sh"), False)


class AfterOperatorsFlagged(Base):
    def test_and_dot(self):
        self.flagged("true&&out=.")

    def test_or_dot(self):
        self.flagged("false||out=.")

    def test_semicolon_dot(self):
        self.flagged("true;out=.")

    def test_safe_then_and_dot(self):
        self.flagged("out=$RUNNER_TEMP/x; true&&out=.")

    def test_double_equals(self):
        self.flagged("out==build.sh")

    def test_double_equals_after_and(self):
        self.flagged("true&&out==build.sh")

    def test_double_equals_after_or(self):
        self.flagged("false||out==build.sh")

    def test_double_equals_after_semicolon(self):
        self.flagged("true;out==build.sh")


class AfterOperatorsClean(Base):
    def test_and_safe(self):
        self.clean("true&&out=$RUNNER_TEMP/x")

    def test_or_safe(self):
        self.clean("false||out=$RUNNER_TEMP/x")

    def test_semicolon_safe(self):
        self.clean("true;out=$RUNNER_TEMP/x")


if __name__ == "__main__":
    unittest.main()
