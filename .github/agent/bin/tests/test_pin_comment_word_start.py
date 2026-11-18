"""Tests: the checker takes a # as a comment only at a word start, and reads the quote state of a script once (nesting inside $( ), ${ } and backticks does not change it).

Cases marked RED-ON-MAIN fail on origin/main."""
import unittest

from test_pin_setter_quotes import M
from test_pin_read_joins import SAFE, COPY, BUILD, hand_repo, run

# bash runs out=. after each of these: the quotes inside the substitution do not change the quote state around it
NESTED = {
    "dollar_paren": 'echo "$(echo "\'")"',
    "backticks": 'echo "`echo "\'"`"',
    "default_expansion": 'echo "${x:-"\'"}"',
}


def nested_script(echo):
    return "\n".join([SAFE, echo, "#c\\", "out=.", COPY])


class EndToEnd(unittest.TestCase):
    def end_to_end(self, lines, code, env=""):
        out = run([hand_repo(self, lines, env)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    # RED-ON-MAIN (each)
    def test_red_nested_quote_then_comment_backslash_then_setter_is_flagged(self):
        # default_expansion is left out: another reader (command splitting) hides it with no `#c\\` line at all
        for name, echo in NESTED.items():
            if name == "default_expansion":
                continue
            with self.subTest(name):
                self.end_to_end([SAFE, echo, "#c\\", "out=.", *BUILD], 1)

    def test_hash_after_escaped_semicolon_is_no_comment(self):
        # `echo \\;#x; ou\` + `t=.`: the # continues the word, so the backslash-newline joins
        self.end_to_end([SAFE, "echo \\;#x; ou\\", "t=.", *BUILD], 1)

    # real comments stay comments
    def test_comment_backslash_then_echo_is_clean(self):
        self.end_to_end([SAFE, "#comment\\", "echo hi", *BUILD], 0)

    def test_comment_after_blank_is_clean(self):
        self.end_to_end([SAFE, "echo hi #out=.", *BUILD], 0)

    def test_hash_in_word_is_no_comment_but_setter_after_newline_is_seen(self):
        self.end_to_end([SAFE, "echo hello#world", "out=.", *BUILD], 1)


class MaskShell(unittest.TestCase):
    def no_comments(self, text):
        return M._mask_shell(text)[0]

    # RED-ON-MAIN
    def test_red_hash_after_escaped_semicolon_is_kept(self):
        self.assertIn("#x", self.no_comments("echo \\;#x"))

    def test_red_hash_after_closed_command_substitution_is_kept(self):
        self.assertIn("#x", self.no_comments("echo $(echo x)#x"))

    def test_hash_after_closed_brace_expansion_is_kept(self):
        self.assertIn("#x", self.no_comments("echo ${y}#x"))

    def test_hash_in_word_and_expansions_are_kept(self):
        for text in ("echo hello#world", "echo ${#x}", "echo $#"):
            with self.subTest(text):
                self.assertEqual(self.no_comments(text), text)

    def test_real_comments_are_blanked(self):
        for sep in (" ", "\t", "\n", ";", "&", "|", "(", ")", "<", ">"):
            with self.subTest(repr(sep)):
                text = "echo" + sep + "#zz"
                self.assertNotIn("zz", self.no_comments(text))

    def test_comment_line_keeps_newline(self):
        self.assertEqual(self.no_comments("a\n#c\nb"), "a\n  \nb")

    # RED-ON-MAIN (each nested case)
    def test_red_open_quote_false_for_nested_quotes(self):
        for name, echo in NESTED.items():
            with self.subTest(name):
                self.assertIs(M._mask_shell(nested_script(echo))[2], False)

    def test_open_quote_true_for_a_truly_open_quote(self):
        for text in ("echo 'abc", 'echo "abc', "echo $(echo 'x"):
            with self.subTest(text):
                self.assertIs(M._mask_shell(text)[2], True)

    def test_open_quote_false_for_closed_quotes(self):
        self.assertIs(M._mask_shell("echo 'a' \"b\"")[2], False)


class JoinOutsideComments(unittest.TestCase):
    # RED-ON-MAIN (each nested case): `#c\` is a comment, a comment's backslash-newline does not join, so out=. starts a line
    def test_red_nested_quotes_keep_setter_on_its_own_line(self):
        for name, echo in NESTED.items():
            with self.subTest(name):
                joined = M._join_outside_comments(nested_script(echo))
                self.assertNotIn("#cout=.", joined)
                self.assertIn("\nout=.", joined)

    def test_comment_backslash_keeps_next_line(self):
        joined = M._join_outside_comments("#c\\\necho hi")
        self.assertTrue(joined.startswith("#c"))
        self.assertIn("\necho hi", joined)

    def test_split_word_outside_comment_joins(self):
        self.assertEqual(M._join_outside_comments("ou\\\nt=."), "out=.")

    # RED-ON-MAIN
    def test_red_hash_after_escaped_semicolon_joins(self):
        self.assertEqual(M._join_outside_comments("echo \\;#x; ou\\\nt=."), "echo \\;#x; out=.")


if __name__ == "__main__":
    unittest.main()
