"""Tests: three scanner holes that hid a setter or an image bash really runs.
1. the `)` of a case pattern inside $( ) does not close the $( frame;
2. an ANSI-C string holding an escaped quote ($'\\'') leaves no open quote;
3. inside double quotes bash runs a process substitution in "${x<op><(...)}" for the pattern, trim and case operators
   (not for :- := :+ - + =, which print it literally).

Cases marked RED-ON-MAIN fail on origin/main; cases marked NOT red on main pass there. Every case was checked in bash 5.2."""
import unittest

from test_pin_setter_quotes import M
from test_pin_read_joins import SAFE, COPY, BUILD, hand_repo, run

# bash ends each of these running `docker run alpine:latest` (checked with a docker function)
TAIL_RUN = ['echo " # "; img=alpine:latest', 'docker run "$img"']
TAIL_KIND = ['echo " # "; img=alpine:latest', 'kind create cluster --image "$img"']
OPS = ["/a/", "//a/", "/#a/", "/%a/", "#", "%", "##", "%%", "^", ",", "^^", ",,"]

# bash runs `out=.` after each of these (the `#c\` line is a comment, its backslash-newline does not continue)
CASES = {
    "case_pattern": 'echo "$(case x in a) echo hi;; esac)"',
    "case_leading_paren": 'echo "$(case x in (a) echo hi;; esac)"',
    "case_alternatives": 'echo "$(case x in a|b) echo hi;; esac)"',
    "case_nested_substitution": 'echo "$(echo "$(case x in a) echo hi;; esac)")"',
    "case_unquoted": "echo $(case x in a) echo hi;; esac)",
}


def heads():
    out = {}
    for op in OPS:
        for sub in ("<", ">"):
            out[op + sub] = ["x=a", 'echo "${x' + op + sub + '(echo # } "', ')}"']
    return out


class EndToEnd(unittest.TestCase):
    def end_to_end(self, lines, code, env=""):
        out = run([hand_repo(self, lines, env)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    # NOT red on main: main refuses `case ... esac inside $( )` (exit 1 for that reason); bash runs out=. so exit 1 is also right
    def test_case_pattern_paren_in_substitution_setter_flagged(self):
        for name, echo in CASES.items():
            with self.subTest(name):
                self.end_to_end([SAFE, echo, "#c\\", "out=.", *BUILD], 1)

    def test_quoted_paren_in_substitution_still_handled(self):
        self.end_to_end([SAFE, 'echo "$(echo \')\')"', *BUILD], 0)
        self.end_to_end([SAFE, 'echo "$(echo \')\')"', "#c\\", "out=.", *BUILD], 1)

    # NOT red on main (_ansi_c_hidden may refuse it, so main flags it for that reason)
    def test_ansi_c_escaped_quote_then_setter_flagged(self):
        self.end_to_end([SAFE, "echo $'\\''", "#c\\", "out=.", *BUILD], 1)

    def test_ansi_c_escaped_quote_without_setter_is_not_checked_here(self):
        # main refuses the escape other than \n \t \r, so it is not asserted clean; only the exit is recorded as 1 or 0
        out = run([hand_repo(self, [SAFE, "echo $'\\''", *BUILD])])
        self.assertIn(out[0], (0, 1), out[1])

    # NOT red on main
    def test_ansi_c_newline_and_tab_clean(self):
        self.end_to_end([SAFE, "echo $'a\\nb'", *BUILD], 0)
        self.end_to_end([SAFE, "echo $'\\t'", *BUILD], 0)

    # NOT red on main
    def test_ansi_c_newline_and_tab_then_setter_flagged(self):
        self.end_to_end([SAFE, "echo $'a\\nb'", "#c\\", "out=.", *BUILD], 1)
        self.end_to_end([SAFE, "echo $'\\t'", "#c\\", "out=.", *BUILD], 1)

    # NOT red on main: other escapes stay flagged as today (the checker refuses what it cannot read)
    def test_ansi_c_other_escape_stays_flagged(self):
        self.end_to_end([SAFE, "echo $'\\x41'", *BUILD], 1)

    # RED-ON-MAIN (each)
    def test_red_quoted_process_subst_in_expansion_image_flagged_docker_run(self):
        for name, head in heads().items():
            with self.subTest(name):
                self.end_to_end([*head, *TAIL_RUN], 1)

    # RED-ON-MAIN (each)
    def test_red_quoted_process_subst_in_expansion_image_flagged_kind(self):
        for name, head in heads().items():
            with self.subTest(name):
                self.end_to_end([*head, *TAIL_KIND], 1)

    # guards (bash prints these literally)
    def test_quoted_default_process_subst_clean(self):
        self.end_to_end([SAFE, 'echo "${x:-<(echo hi)}"', *BUILD], 0)

    def test_quoted_nested_default_process_subst_clean(self):
        self.end_to_end([SAFE, 'echo "${x:-${y:-<(echo # hi)}}"', *BUILD], 0)

    def test_quoted_alternative_process_subst_clean(self):
        self.end_to_end([SAFE, 'echo "${x:+<(echo hi)}"', *BUILD], 0)

    def test_quoted_literal_forms_clean(self):
        for op in (":-", ":=", ":+", "-", "+", "="):
            with self.subTest(op):
                self.end_to_end([SAFE, 'echo "${x' + op + '<(echo # hi)}"', *BUILD], 0)


    # RED-ON-MAIN for the first two (bash runs out=. in each; the ANSI-C string sits where _ansi_c_hidden does not look);
    # the backtick form is NOT red on main
    def test_red_ansi_c_escaped_quote_inside_double_quotes_setter_flagged(self):
        forms = {
            "dollar_paren": 'echo "$(echo $\'\\\'\')"',
            "default_expansion": 'echo "${x:-$\'\\\'\'}"',
            "backticks": 'echo "`echo $\'\\\'\'`"',
        }
        for name, echo in forms.items():
            with self.subTest(name):
                self.end_to_end([SAFE, echo, "#c\\", "out=.", *BUILD], 1)


class SetterValues(unittest.TestCase):
    def values(self, script):
        got = None
        for _ in M._reads():
            got = M._setter_values("out", script)      # the last read is the comment-aware one
        return got

    # RED-ON-MAIN (returns [])
    def test_red_case_in_substitution_keeps_both_setters(self):
        script = 'out=$RUNNER_TEMP/x\necho "$(case $x in a) echo "\'" ;; esac)"\n#c\\\nout=.\n'
        self.assertEqual(self.values(script), ["$RUNNER_TEMP/x", "."])

    # RED-ON-MAIN (returns [])
    def test_red_ansi_c_escaped_quote_keeps_both_setters(self):
        script = "out=$RUNNER_TEMP/x\necho $'\\''\n#c\\\nout=.\n"
        self.assertEqual(self.values(script), ["$RUNNER_TEMP/x", "."])


class MaskShell(unittest.TestCase):
    def no_comments(self, text):
        return M._mask_shell(text)[0]

    # RED-ON-MAIN (each)
    def test_red_quoted_process_subst_comment_is_blanked_image_visible(self):
        for op in ("/a/", "#", "%", "^", ","):
            with self.subTest(op):
                masked = self.no_comments('echo "${x' + op + '<(echo # c\n)}"; img=alpine:latest')
                self.assertNotIn("# c", masked)
                self.assertIn("img=alpine:latest", masked)

    # NOT red on main
    def test_case_pattern_paren_does_not_close_frame(self):
        masked = self.no_comments('echo "$(case x in a) echo hi;; esac)"\n#c\\\nout=.')
        self.assertNotIn("#c", masked)
        self.assertIn("out=.", masked)

    def test_quoted_default_process_subst_hash_stays_visible(self):
        self.assertIn("# hi", self.no_comments('"${x:-<(echo # hi)}"'))


if __name__ == "__main__":
    unittest.main()
