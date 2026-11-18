"""Tests: inside an unquoted ${ } a <( or >( is a process substitution bash runs, so it is a command frame (a # after a blank
starts a comment, a ) closes it); inside a double-quoted "${ }" bash prints it literally and it stays word text. An unsafe image
assignment that bash really executes must not be hidden.

Cases marked RED-AT-4F7B5DB1 and flagged on main fail at 4f7b5db1 and pass on main."""
import unittest

from test_pin_setter_quotes import M
from test_pin_read_joins import SAFE, COPY, BUILD, ENV_DOT, hand_repo, run

# bash ends each of these running `docker run alpine:latest` (checked with stubs)
TAIL_RUN = ['echo " # "; img=alpine:latest', 'docker run "$img"']
TAIL_KIND = ['echo " # "; img=alpine:latest', 'kind create cluster --image "$img"']


def heads():
    out = {}
    for op in ("/a/", "//a/", "#", "%"):
        for sub in ("<", ">"):
            out[op + sub] = ["x=a", "echo ${x" + op + sub + "(echo # } \"", ")}"]
    return out


class EndToEnd(unittest.TestCase):
    def end_to_end(self, lines, code, env=""):
        out = run([hand_repo(self, lines, env)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    # RED-AT-4F7B5DB1 and flagged on main (each)
    def test_red_process_subst_in_expansion_image_flagged_docker_run(self):
        for name, head in heads().items():
            with self.subTest(name):
                self.end_to_end([*head, *TAIL_RUN], 1)

    # RED-AT-4F7B5DB1 and flagged on main (each)
    def test_red_process_subst_in_expansion_image_flagged_kind(self):
        for name, head in heads().items():
            with self.subTest(name):
                self.end_to_end([*head, *TAIL_KIND], 1)

    # guards
    def test_quoted_process_subst_is_word_text_clean(self):
        self.end_to_end([SAFE, 'echo "${x:-<(echo hi)}"', *BUILD], 0)

    def test_nested_quoted_process_subst_is_word_text_clean(self):
        self.end_to_end([SAFE, 'echo "${x:-${y:-<(echo # hi)}}"', *BUILD], 0)

    def test_unquoted_well_formed_process_subst_hides_nothing(self):
        self.end_to_end([SAFE, "echo ${x:-<(echo hi)}", *BUILD], 0)


class MaskShell(unittest.TestCase):
    def no_comments(self, text):
        return M._mask_shell(text)[0]

    # RED-AT-4F7B5DB1 and flagged on main
    def test_red_unquoted_process_subst_comment_is_blanked_image_visible(self):
        masked = self.no_comments("echo ${x/a/<(echo # c\n)}; img=alpine:latest")
        self.assertNotIn("# c", masked)
        self.assertIn("img=alpine:latest", masked)

    def test_quoted_process_subst_hash_stays_visible(self):
        self.assertIn("# hi", self.no_comments('"${x:-<(echo # hi)}"'))


if __name__ == "__main__":
    unittest.main()
