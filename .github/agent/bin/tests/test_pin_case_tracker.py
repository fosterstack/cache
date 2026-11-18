"""Tests: the scanner's tracking of `case` inside $( ) and <( ), and of $' in a shell without ANSI-C quoting.
Groups A and B are RED-ON-MAIN-HEAD (5c403291): each case fails there. Groups C and D keep their answers (green before and after).
Every script was run in bash 5.2 (a docker function printing its args); the shell: sh case also in /usr/bin/dash."""
import os
import shutil
import unittest

from test_pin_setter_quotes import repo, run, GATE_PROGRAMS
from test_pin_read_joins import SAFE, COPY, BUILD, hand_repo

TAIL_RUN = ['echo " # "; img=alpine:latest', 'docker run "$img"']
TAIL_KIND = ['echo " # "; img=alpine:latest', 'kind create cluster --image "$img"']


def sh_repo(case, lines, shell):
    """Like hand_repo, with the step's `shell:` set."""
    text = "".join("          " + ln + "\n" for ln in lines)
    wf = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: " + shell + "\n        run: |\n" + text)
    d = repo({".github/workflows/w.yml": wf, "Dockerfile": "FROM scratch\n", **GATE_PROGRAMS})
    case.addCleanup(shutil.rmtree, d)
    return d


class Base(unittest.TestCase):
    def end_to_end(self, lines, code, shell=None):
        d = sh_repo(self, lines, shell) if shell else hand_repo(self, lines)
        out = run([d])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])


# bash runs `docker run alpine:latest` (or kind create cluster --image alpine:latest) in each of these
class RedFlagged(Base):
    """RED-ON-MAIN-HEAD (5c403291): must be flagged."""

    def test_red_case_word_in_process_subst_docker_run(self):
        self.end_to_end(["x=a", 'echo "${x/a/<(echo case in)}"', *TAIL_RUN], 1)

    def test_red_case_word_in_process_subst_kind(self):
        self.end_to_end(["x=a", 'echo "${x/a/<(echo case in)}"', *TAIL_KIND], 1)

    def test_red_case_assignment_in_process_subst(self):
        self.end_to_end(["x=a", 'echo "${x/a/<(case=x; echo in)}"', *TAIL_RUN], 1)

    def test_red_case_fallthrough_comment_in_process_subst(self):
        self.end_to_end(["x=a", 'echo "${x/a/<(case y in a) :;& b) echo # } "', ';; esac)}"', *TAIL_RUN], 1)

    def test_red_dollar_dollar_then_quote_bash(self):
        # bash reads $$ as one unit, so the ' opens a plain quote
        self.end_to_end(["echo \"$(echo $$'\\'' # ')\"; img=alpine:latest", 'docker run "$img"'], 1)

    def test_red_ansi_c_quote_shell_sh(self):
        # dash has no $'..': it runs the image
        self.end_to_end(["echo \"$(echo $'\\'' # ')\"; img=alpine:latest", 'docker run "$img"'], 1, shell="sh")

    def test_ansi_c_quote_default_shell_recorded(self):
        # bash stops on this script (unexpected EOF), so only the exit is recorded
        d = hand_repo(self, ["echo \"$(echo $'\\'' # ')\"; img=alpine:latest", 'docker run "$img"'])
        out = run([d])
        self.assertIn(out[0], (0, 1), out[1])


class RedClean(Base):
    """RED-ON-MAIN-HEAD (5c403291): must be clean (main answers 0; HEAD refuses, the frame stays open)."""

    MIDDLES = {
        "echo_case_x_in_x": "(echo case x in x)",
        "echo_case_in": "(echo case in)",
        "echo_case_slash": "(echo case/foo in)",
        "case_assignment": "(case=x; echo in)",
    }

    def test_red_case_as_plain_word_is_clean(self):
        for name, mid in self.MIDDLES.items():
            with self.subTest(name):
                self.end_to_end([SAFE, mid, *BUILD], 0)


class KeepAnswers(Base):
    """Green at HEAD and after."""

    CASE_FALL = "(case x in x) echo hi;& y) echo hi;; esac)"

    def test_case_fallthrough_clean(self):
        self.end_to_end([SAFE, self.CASE_FALL, *BUILD], 0)

    def test_case_fallthrough_then_setter_flagged(self):
        self.end_to_end([SAFE, self.CASE_FALL, "#c\\", "out=.", *BUILD], 1)

    def test_valid_case_forms_clean(self):
        forms = {
            "leading_paren_alternatives": "(case $x in (a) echo hi;; b|c) echo y;; esac)",
            "nested": "(case x in a) case y in b) :;; esac;; c) :;; esac)",
            "paren_esac_pattern": "(case x in (esac) :;; esac)",
            "alternative_esac_pattern": "(case x in a|esac) :;; esac)",
            "subject_in": "(case in in in) :;; esac)",
        }
        for name, mid in forms.items():
            with self.subTest(name):
                self.end_to_end([SAFE, mid, *BUILD], 0)


class ReservedWordPositions(Base):
    """Group D: green at HEAD and after."""

    def test_case_after_then_clean(self):
        self.end_to_end([SAFE, "(if true; then case x in a) :;; esac; fi)", *BUILD], 0)


if __name__ == "__main__":
    unittest.main()
