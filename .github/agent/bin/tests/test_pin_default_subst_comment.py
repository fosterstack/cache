"""Tests: inside a double-quoted "${x:-<( ... )}" word bash opens a process-substitution frame at <(, a # at a word start in
that frame is a comment to the end of the line (so the } after it does not close the brace), and the frame closes at a later ).
Bash then runs the rest of the script, so an unsafe image assignment after it must not be hidden. A form bash rejects as a
syntax error (frame never closed) keeps the answer main gave.

Cases marked RED-AT-240B511C and flagged at the fix fail at 240b511c and pass at the fix."""
import unittest

from test_pin_read_joins import SAFE, BUILD, hand_repo, run

RUN = ['echo " # "; img=alpine:latest', 'docker run "$img"']
KIND = ['echo " # "; img=alpine:latest', 'kind create cluster --image "$img"']
OPS = [":-", ":=", ":+", "-", "+", "="]


def n1(op, word=""):
    return ["x=a", 'echo "${x' + op + word + '<(echo # } "', ')}"']


class EndToEnd(unittest.TestCase):
    def end_to_end(self, lines, code, env=""):
        out = run([hand_repo(self, lines, env)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    def cases(self, tail_run, tail_kind, row14_run, row14_kind):
        return {
            "n1 run": [*n1(":-"), *tail_run],
            "n1 kind": [*n1(":-"), *tail_kind],
            "n1 text run": [*n1(":-", "text"), *tail_run],
            "n1 text kind": [*n1(":-", "text"), *tail_kind],
            "row14 run": row14_run,
            "row14 kind": row14_kind,
        }

    # RED-AT-240B511C and flagged at the fix (each)
    def test_red_default_subst_comment_image_flagged(self):
        head = ["x=a", 'echo "${x/a/${y:-<(echo # }}"']
        for name, lines in self.cases(
            RUN, KIND,
            [*head, ')}}" ; docker run alpine:latest # "'],
            [*head, ')}}" ; kind create cluster --image alpine:latest # "'],
        ).items():
            with self.subTest(name):
                self.end_to_end(lines, 1)

    # RED-AT-240B511C and flagged at the fix (each)
    def test_red_default_subst_comment_operators_flagged(self):
        for op in OPS:
            with self.subTest(op):
                self.end_to_end([*n1(op), *RUN], 1)

    # guards
    def test_quoted_well_formed_process_subst_clean(self):
        self.end_to_end([SAFE, 'echo "${x:-<(echo hi)}"', *BUILD], 0)

    def test_nested_quoted_syntax_error_clean(self):
        self.end_to_end([SAFE, 'echo "${x:-${y:-<(echo # hi)}}"', *BUILD], 0)

    def test_unquoted_well_formed_process_subst_clean(self):
        self.end_to_end([SAFE, "echo ${x:-<(echo hi)}", *BUILD], 0)

    def test_unquoted_process_subst_runs_image_flagged(self):
        self.end_to_end([SAFE, "echo ${x:-<(docker run alpine:latest)}", *BUILD], 1)

    def test_unclosed_frame_syntax_error_keeps_main_answer(self):
        self.end_to_end(["x=a", 'echo "${x:-<(echo # hi)}"', *RUN[:1], RUN[1]], 1)

    def test_real_comment_stays_comment(self):
        self.end_to_end([SAFE, 'echo "${x:-<(echo a)}" # img=alpine:latest', *BUILD], 0)


if __name__ == "__main__":
    unittest.main()
