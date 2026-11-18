"""Tests for check-action-pins.py `_join_lines` and its one-pass parenthesis collapse: a backslash-newline joins lines except after a real comment."""
import re, time, unittest

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

# each script is one bash would run to out=. : a backslash-newline splits `ou\` / `t=.` after a `#` that is no comment
NOT_COMMENT = {
    "escaped_space": [SAFE, "echo \\ #; ou\\", "t=."],
    "escaped_tab": [SAFE, "echo \\\t#; ou\\", "t=."],
    "escaped_semicolon": [SAFE, "echo \\;#; ou\\", "t=."],
    "escaped_paren": [SAFE, "echo \\(#; ou\\", "t=."],
    "after_command_substitution": [SAFE, "echo $(echo x)#; ou\\", "t=."],
    "after_arithmetic": [SAFE, "echo $((1))#; ou\\", "t=."],
    "after_process_substitution": [SAFE, "echo <(echo x)#; ou\\", "t=."],
    "quotes_inside_substitution": [SAFE, 'echo "$(echo " #")"; ou\\', "t=."],
    "heredoc_quoted_delimiter_double_quote": [SAFE, "cat <<'EOF'", '"', "EOF", 'echo " #"; ou\\', "t=."],
    "heredoc_bare_delimiter_apostrophe": [SAFE, "cat <<EOF", "it's", "EOF", "echo ' #'; ou\\", "t=."],
}
ENV_ROUTE = "echo \\;#x; echo LD_PRELOAD=e.so >> $GITHUB_E\\\nNV"


def joined(text):
    """The script as the checker joins it: `_join_lines` when the module has it, else main's plain join."""
    join = getattr(M, "_join_lines", None)
    return join(text) if join else re.sub(r"\\\n", "", text)


def raw(lines):
    return "\n".join(lines)


class ReadJoinsUnit(unittest.TestCase):
    def test_clean_keep_out_safe(self):
        for name, lines in CLEAN.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", raw(lines)), True)

    def test_deep_parentheses_are_fast(self):
        script = "(" * 2000 + "\n".join([SAFE] * 10) + "\n" + COPY
        start = time.perf_counter()
        result = M._outside("$out", script)
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertIs(result, False)

    def test_very_deep_balanced_parentheses_are_fast(self):
        script = "(" * 5000 + ")" * 5000 + "\n" + "\n".join([SAFE] * 10) + "\n" + COPY
        start = time.perf_counter()
        result = M._outside("$out", script)
        self.assertLess(time.perf_counter() - start, 1.0)
        self.assertIs(result, True)

    def test_not_a_comment_keeps_out_outside(self):
        for name, lines in NOT_COMMENT.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", joined(raw(lines + [COPY]))), False)

    def test_escaped_hash_env_route_is_refused(self):
        self.assertTrue(M.step_write_findings("where", ENV_ROUTE))


class ReadJoinsEndToEnd(Base):
    def test_not_a_comment_is_flagged(self):
        for name, lines in NOT_COMMENT.items():
            with self.subTest(name):
                self.flagged("\n          ".join(lines))

    def test_escaped_hash_env_route_is_flagged(self):
        self.flagged("\n          ".join([SAFE, ENV_ROUTE]))

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
