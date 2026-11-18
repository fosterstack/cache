"""Tests for check-action-pins.py `_set_by_setter`: `read`, `mapfile` and `readarray` with no variable name set REPLY or MAPFILE.

Written from the English rules only, not from the checker's source.
"""
import unittest

from test_pin_setter_quotes import M, Base

HEREDOC_DASH = "read <<- EOF\nx\nEOF\n"
HEREDOC_DASH_TIGHT = "read <<-EOF\nx\nEOF\n"

SETS_REPLY = {
    "a1_two_digit_redirect_first": "12>/dev/null read -r <<< x",
    "a1_u_then_redirect": "read -u 10 10< f",
    "a1_redirect_after": "read 10<f",
    "a1_redirect_before": "10<f read",
    "a2_command": "command read <<< x",
    "a2_builtin": "builtin read -r <<< x",
    "a2_command_p": "command -p read <<< x",
    "a3_quoted_dash_a": 'read -p "-a" <<< x',
    "a3_prompt_dash_abc": "read -p -abc <<< x",
    "a3_pa": "read -pa <<< x",
    "a4_var": "read $f <<< x",
    "a4_two_vars": "read -r $f $g <<< x",
    "a5_unknown_option": "read -E <<< x",
    "a6_heredoc_dash": HEREDOC_DASH,
    "a6_heredoc_dash_tight": HEREDOC_DASH_TIGHT,
    "a6_clobber": "read -r >| f <<< x",
    "unchanged_stdin_file": "read -r < f",
    "unchanged_herestring": "read <<< x",
    "unchanged_ifs": "IFS= read -r <<< x",
}
NOT_REPLY = {
    "aarr": "read -aarr <<< x",
    "raarr": "read -raarr <<< x",
    "a_arr": "read -a arr <<< x",
    "ra_arr": "read -ra arr <<< x",
    "pa_x": "read -pa x",
    "prompt_v": 'read -p "prompt: " v',
    "line": "read -r line <<< y",
    "command_x": "command read x <<< y",
    "x_var": "read x $f",
    "u_x_redirect": "read -u 10 x 10< f",
}
SETS_MAPFILE = {
    "a2_command_mapfile": "command mapfile -t <<< x",
    "a2_builtin_mapfile": "builtin mapfile -t <<< x",
    "a2_command_readarray": "command readarray -t <<< x",
    "a3_d_dash_abc": "mapfile -d -abc <<< x",
    "a3_t_d_dash_abc": "mapfile -t -d -abc <<< x",
}
NOT_MAPFILE = {
    "lines": "mapfile -t lines < f",
    "command_lines": "command mapfile -t lines < f",
    "echo_read": "echo read",
    "true": "true",
}


class DefaultNamesUnit(unittest.TestCase):
    def test_sets_reply(self):
        for k, s in SETS_REPLY.items():
            with self.subTest(k):
                self.assertIs(M._set_by_setter("REPLY", s), True)

    def test_names_a_variable_so_not_reply(self):
        for k, s in NOT_REPLY.items():
            with self.subTest(k):
                self.assertIs(M._set_by_setter("REPLY", s), False)

    def test_sets_mapfile(self):
        for k, s in SETS_MAPFILE.items():
            with self.subTest(k):
                self.assertIs(M._set_by_setter("MAPFILE", s), True)

    def test_not_mapfile(self):
        for k, s in NOT_MAPFILE.items():
            with self.subTest(k):
                self.assertIs(M._set_by_setter("MAPFILE", s), False)


class DefaultNamesFlagged(Base):
    def test_two_digit_descriptor_reply(self):
        self.flagged("12>/dev/null read -r <<< x", dest="REPLY")

    def test_command_read_reply(self):
        self.flagged("command read <<< x", dest="REPLY")

    def test_unknown_option_reply(self):
        self.flagged("read -E <<< x", dest="REPLY")

    def test_command_mapfile(self):
        self.flagged("command mapfile -t <<< x", dest="MAPFILE")

    def test_mapfile_d_dash_abc(self):
        self.flagged("mapfile -t -d -abc <<< x", dest="MAPFILE")
