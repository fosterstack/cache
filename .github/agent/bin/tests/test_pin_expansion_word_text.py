"""Tests: inside ${ } the text is word text (a # opens no comment, a ( or ) opens or closes no group; quotes, $( ), ${ } and
backticks still nest); a backtick substitution ends at the next unescaped backtick before its inside is scanned; a script the
scanner cannot read (a frame still open at the end) grants no trust.

Cases marked RED-ON-MAIN fail on origin/main."""
import unittest

from test_pin_setter_quotes import M
from test_pin_read_joins import SAFE, COPY, BUILD, ENV_DOT, hand_repo, run

BQ = "`"
# bash ends each of these with the unsafe value (the image is :latest; out is . from the step env)
IMAGE_RUN = ['echo "${x// #/}"; img=alpine:latest', 'docker run "$img"']
IMAGE_KIND = ['echo "${x// #/}"; img=alpine:latest', 'kind create cluster --image "$img"']
IMAGE_SEMI = ["x=abc", 'echo "${x/a/a; #x}"; img=ubuntu:latest', 'kind create cluster --image "$img"']
PAREN_CLOSE = ["(", 'echo "${x//)}"', SAFE, ")"]
PAREN_OPEN = ['echo "${x//a/(}"', "(out=$RUNNER_TEMP/x)"]
PAREN_HASH = ['echo "${x#(}"', "(out=$RUNNER_TEMP/x)"]
BACKTICK = ['echo "' + BQ + 'echo # hi' + BQ + '"', "(out=$RUNNER_TEMP/x)"]


class EndToEnd(unittest.TestCase):
    def end_to_end(self, lines, code, env=""):
        out = run([hand_repo(self, lines, env)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    # RED-ON-MAIN (each)
    def test_red_hash_in_expansion_is_no_comment_image_flagged(self):
        for name, lines in {"docker_run": IMAGE_RUN, "kind": IMAGE_KIND, "semicolon": IMAGE_SEMI}.items():
            with self.subTest(name):
                self.end_to_end(lines, 1)

    # RED-ON-MAIN (each)
    def test_red_paren_in_expansion_is_no_group_setter_stays_in_subshell(self):
        for name, head in {"close": PAREN_CLOSE, "open": PAREN_OPEN, "hash": PAREN_HASH}.items():
            with self.subTest(name):
                self.end_to_end([*head, *BUILD], 1, ENV_DOT)

    # RED-ON-MAIN
    def test_red_comment_in_backticks_ends_at_the_backtick(self):
        self.end_to_end([*BACKTICK, *BUILD], 1, ENV_DOT)

    # guards
    def test_backtick_with_comment_then_setter_line_is_flagged(self):
        self.end_to_end(["echo " + BQ + "echo # hi" + BQ, "out=.", *BUILD], 1)

    def test_quote_in_default_expansion_still_nests(self):
        self.end_to_end([SAFE, 'echo "${x:-"a b"}"', *BUILD], 0)

    def test_real_comment_is_clean(self):
        self.end_to_end([SAFE, "echo hi # x", *BUILD], 0)


class MaskShell(unittest.TestCase):
    def no_comments(self, text):
        return M._mask_shell(text)[0]

    # RED-ON-MAIN (each)
    def test_red_hash_in_expansion_is_kept(self):
        for text in ('echo "${x// #/}"', 'echo "${x/a/a; #x}"', "echo ${x// #/}", 'echo "${x#(}"'):
            with self.subTest(text):
                self.assertEqual(self.no_comments(text + "\nout=."), text + "\nout=.")

    # RED-ON-MAIN (each): the backtick ends at its own backtick, so the code line after it is code
    def test_red_comment_in_backticks_ends_at_backtick(self):
        for text in ('echo "`echo # hi`"', "echo `echo # hi`"):
            with self.subTest(text):
                masked = self.no_comments(text + "\nout=.")
                self.assertTrue(masked.endswith("\nout=."))
                self.assertNotIn("hi", masked)
                self.assertIs(M._mask_shell(text + "\nout=.")[2], False)

    def test_red_unbalanced_paren_in_expansion_leaves_nothing_open(self):
        for text in ('echo "${x//)}"', 'echo "${x//a/(}"', 'echo "${x#(}"', "echo ${x//)}"):
            with self.subTest(text):
                self.assertIs(M._mask_shell(text + "\n")[2], False)

    # RED-ON-MAIN: a ) in an expansion must not close the group around it
    def test_red_paren_in_expansion_keeps_group_open_to_its_own_close(self):
        self.assertIs(M._mask_shell('(\necho "${x//)}"\n')[2], True)
        self.assertIs(M._mask_shell('(\necho "${x//)}"\n)\n')[2], False)

    # R3: a frame still open at the end is open_quote
    def test_open_frame_at_end_is_open(self):
        for text in ("(echo hi", "echo $(echo x", "echo ${x", "echo `echo x", 'echo "${x:-"a'):
            with self.subTest(text):
                self.assertIs(M._mask_shell(text)[2], True)

    # guards
    def test_quote_in_default_expansion_nests(self):
        text = 'echo "${x:-"a b"}"\nout=.'
        self.assertIs(M._mask_shell(text)[2], False)
        self.assertEqual(self.no_comments(text), text)

    def test_real_comment_is_masked(self):
        self.assertNotIn("x", self.no_comments("echo hi # x")[8:])
        self.assertEqual(self.no_comments("echo hi # x"), "echo hi    ")

    def test_length_expansions_are_no_comment(self):
        for text in ("echo ${#x}", "echo $#", 'echo "${#x}"'):
            with self.subTest(text):
                self.assertEqual(self.no_comments(text), text)

    def test_real_comment_after_closed_expansion_with_hash_is_masked(self):
        self.assertEqual(self.no_comments("echo ${x#a} #zz"), "echo ${x#a}    ")

    def test_backtick_comment_then_code_line_keeps_setter(self):
        self.assertIn("\nout=.", self.no_comments("echo `echo # hi`\nout=."))


if __name__ == "__main__":
    unittest.main()
