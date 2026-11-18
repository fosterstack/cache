"""Tests for check-action-pins.py `_join_lines` and its one-pass parenthesis collapse: a backslash-newline joins lines except after a real comment."""
import re, shutil, time, unittest

from test_pin_setter_quotes import M, Base, run, repo, GATE_PROGRAMS

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


def hand_repo(case, lines, env="", style="|"):
    """A tree whose one step runs `lines` exactly as given (no helper lines added); `env` follows the run block."""
    text = "\n".join("          " + ln for ln in lines) + ("\n" if style == "|" else "")
    wf = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: " + style + "\n" + text + "\n" + env)
    d = repo({".github/workflows/w.yml": wf, "Dockerfile": "FROM scratch\n", **GATE_PROGRAMS})
    case.addCleanup(shutil.rmtree, d)
    return d


ENV_DOT = "        env:\n          out: .\n"
BUILD = [COPY, "docker build -t img ."]


class ReadsStayApart(unittest.TestCase):
    """Round 3 cases; the RED-FIRST ones fail on the round-2 checker (8c1fabc3)."""

    def end_to_end(self, lines, code, env="", style="|"):
        out = run([hand_repo(self, lines, env, style)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    def test_red_first_open_quote_in_full_read_is_flagged(self):
        lines = ["echo '", "out=$RUNNER_TEMP/x", "echo '", *BUILD, "#c\\", "echo '", "foo", "'"]
        self.end_to_end(lines, 1, ENV_DOT)

    def test_red_first_trailing_comment_backslash_is_clean(self):
        self.end_to_end(["echo FOO=bar >> $GITHUB_ENV", "#c\\"], 0, style="|-")

    def test_red_first_trailing_comment_backslash_then_echo_is_clean(self):
        self.end_to_end(["echo FOO=bar >> $GITHUB_ENV", "#c\\", "echo ok"], 0, style="|-")

    def test_red_first_trailing_comment_backslash_unit(self):
        self.assertEqual(M.step_write_findings("w", "echo FOO=bar >> $GITHUB_ENV\n#c\\"), [])

    def test_trailing_comment_backslash_then_echo_unit(self):
        self.assertEqual(M.step_write_findings("w", "echo FOO=bar >> $GITHUB_ENV\n#c\\\necho ok"), [])

    def test_red_first_join_is_idempotent(self):
        texts = {"double_backslash": "echo \\\\\necho ok", "comment_backslash": "#c\\\necho ok",
                 "quoted_hash": 'echo " #"; ou\\\nt=.'}
        for name, t in texts.items():
            with self.subTest(name):
                self.assertEqual(joined(joined(t)), joined(t))

    def test_red_first_many_lines_then_double_backslash_is_fast(self):
        lines = [SAFE] * 500 + ["echo \\\\", "echo ok", *BUILD]
        d = hand_repo(self, lines)
        start = time.perf_counter()
        code, out = run([d])
        self.assertLess(time.perf_counter() - start, 4.0)
        self.assertEqual(code, 0, out)

    def test_quoted_default_hash_then_split_setter_is_flagged(self):
        self.end_to_end(["echo ${x:- #x}; ou\\", "t=.", *BUILD], 1)


if __name__ == "__main__":
    unittest.main()
