"""Tests for check-action-pins.py `_outside`: a backslash-newline joins lines except after a comment."""
import time, unittest

from test_pin_setter_quotes import M, Base, run

COPY = 'cp -R evil/. "$out"'
SAFE = "out=$RUNNER_TEMP/x"

# the shell reads the last setter, out=. ; the unit text keeps the backslash-newline as written
FLAGGED = {
    "comment_backslash_then_setter": [SAFE, "#comment\\", "out=.", COPY],
    "quoted_hash_joins": [SAFE, 'echo " #"; ou\\', "t=.", COPY],
    "escaped_hash_joins": [SAFE, "echo \\#; ou\\", "t=.", COPY],
}
CLEAN = {
    "plain_comments": [SAFE, "# a plain comment", "# nothing is set here", COPY],
    "comment_backslash_then_echo": [SAFE, "#comment\\", "echo hi", COPY],
}


def raw(lines):
    return "\n".join(lines)


class ReadJoinsUnit(unittest.TestCase):
    def test_clean_keep_out_safe(self):
        for name, lines in CLEAN.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", raw(lines)), True)

    def test_deep_parentheses_are_fast(self):
        setters = "\n".join(SAFE for _ in range(10))
        script = "(" * 2000 + setters + "\n" + COPY
        start = time.perf_counter()
        result = M._outside("$out", script)
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertIs(result, False)


class ReadJoinsEndToEnd(Base):
    def test_flagged(self):
        for name, lines in FLAGGED.items():
            with self.subTest(name):
                self.flagged("\n          ".join(lines[:-1]))

    def test_clean(self):
        for name, lines in CLEAN.items():
            with self.subTest(name):
                self.clean("\n          ".join(lines[:-1]))


if __name__ == "__main__":
    unittest.main()
