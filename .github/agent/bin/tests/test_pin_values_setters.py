"""Tests for check-action-pins.py: a variable set by any form other than NAME= is set to an unknown value.

Written from the English rule only, not from the checker's source.
"""
import unittest

import test_pin_writes_redirect as base


class VariableSetByOtherForms(unittest.TestCase):
    FILES = {"scripts/build.sh": "#!/bin/sh\necho hi\n"}
    SETTERS = {
        "read -r": "read -r out <<< scripts/build.sh",
        "mapfile -t": "mapfile -t out <<< scripts/build.sh",
        "readarray": "readarray out <<< scripts/build.sh",
        "getopts": "getopts 'a:' out -a",
        "printf -v": "printf -v out %s scripts/build.sh",
        "declare": "declare out=scripts/build.sh",
        "typeset": "typeset out=scripts/build.sh",
        "local": "f() { local out=scripts/build.sh; }\nf",
        "export": "export out=scripts/build.sh",
        "readonly": "readonly out=scripts/build.sh",
        "let": "let out=1",
        "select": "select out in scripts/build.sh; do break; done <<< 1",
        "arith": "(( out = 1 ))",
        "default assign": ': "${out:=scripts/build.sh}"',
        "eval": "eval 'out=scripts/build.sh'",
        "array element": "out[0]=scripts/build.sh",
        "for in": "for out in scripts/build.sh; do :; done",
        "append": "out+=x",
    }

    def hits(self, run):
        hits, out = base.JobOrder("test_r4_case_d_own_step_text_before_run_is_finding").check(
            [base.step(run)], self.FILES)
        return [l for l in out.splitlines() if base.FINDING in l and "build.sh" in l], out

    def test_setter_then_write_then_run_by_name_is_reported(self):
        for name, setter in self.SETTERS.items():
            with self.subTest(setter=name):
                hits, out = self.hits('out=$RUNNER_TEMP/out\n%s\ncp payload "$out"\nbash scripts/build.sh' % setter)
                self.assertTrue(hits, out)

    def run_through_variable(self, setter):
        _, out = self.hits('out=$RUNNER_TEMP/out\n%s\nbash "$out"' % setter)
        return [l for l in out.splitlines() if "steps[0]" in l]

    def test_setter_then_run_through_variable_is_reported(self):
        self.assertTrue(self.run_through_variable("read -r out <<< scripts/build.sh"))

    def test_single_outside_assignment_write_not_reported(self):
        hits, out = self.hits('out=$RUNNER_TEMP/out\ncp payload "$out"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    def test_plain_reads_not_reported(self):
        hits, out = self.hits('out=$RUNNER_TEMP/out\necho "$out"\necho ${out}\ncat "${out}" "$out"\n'
                              'cp payload "$out"\ncp payload "${out}"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    # a setter inside a comment or single quotes sets nothing (rows A, B, F1, F7)
    def test_default_in_comment_or_single_quotes_is_not_a_known_value(self):
        for name, setter in {"comment": "# ${out:=w}", "single quotes": "echo '${out:=w}'",
                             "trailing comment": "true # ${out:=w}"}.items():
            with self.subTest(setter=name):
                hits, out = self.hits('%s\ncp payload "$out"\nbash scripts/build.sh' % setter)
                self.assertTrue(hits, out)

    def test_default_on_an_already_set_variable_makes_it_unknown(self):
        hits, out = self.hits('out=$RUNNER_TEMP/out\n: "${out:=$RUNNER_TEMP/other}"\ncp payload "$out"\nbash scripts/build.sh')
        self.assertTrue(hits, out)

    def test_quote_in_a_default_word_does_not_hide_later_commands(self):
        for line in ['out=$RUNNER_TEMP/out\n: "${x:="}"}"', ': "${x:="}"}"']:
            with self.subTest(line=line):
                hits, out = self.hits(line + "\ncp payload scripts/build.sh\nbash scripts/build.sh")
                self.assertTrue(hits, out)

    def test_default_with_an_option_word_does_not_make_an_options_variable(self):
        bad = []
        base.M.check_runs("j", [("w", 'IMG=alpine\n: "${IMG:=--rm}"\ndocker run "$IMG"', None)], bad)
        self.assertTrue(bad)
        self.assertFalse([b for b in bad if "no image operand" in b], bad)

    # a setter anywhere bash expands it (row A, B, F2)
    def test_default_in_an_unquoted_heredoc_or_command_substitution_makes_it_unknown(self):
        forms = {
            "heredoc": "cat <<EOF\n${out:=scripts/build.sh}\nEOF",
            "heredoc assign": "cat <<EOF\n${out=scripts/build.sh}\nEOF",
            "multi-line substitution": 'x=$(\necho ${out:=scripts/build.sh}\n)',
            "multi-line substitution assign": 'x=$(\necho ${out=scripts/build.sh}\n)',
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.hits('out=$RUNNER_TEMP/out\n%s\ncp payload "$out"\nbash scripts/build.sh' % setter)
                self.assertTrue(hits, out)

    # option values attached to the option letters (F3)
    def test_attached_option_values_set_the_variable(self):
        forms = {
            "printf -vout": "printf -vout %s scripts/build.sh",
            "read -raout": "read -raout <<< x",
            "mapfile -tout": "mapfile -tout <<< x",
            "readarray -tout": "readarray -tout <<< x",
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.hits('out=$RUNNER_TEMP/out\n%s\ncp payload "$out"\nbash scripts/build.sh' % setter)
                self.assertTrue(hits, out)

    # a trap action runs in the current shell (F4)
    def test_trap_action_sets_the_variable(self):
        for sig in ("DEBUG", "EXIT"):
            with self.subTest(signal=sig):
                hits, out = self.hits("out=$RUNNER_TEMP/out\ntrap 'out=scripts/build.sh' %s\n"
                                      'cp payload "$out"\nbash scripts/build.sh' % sig)
                self.assertTrue(hits, out)

    # a nameref sets the variable it names (F5)
    def test_nameref_assignment_sets_the_named_variable(self):
        for decl in ("declare -n r=out", "local -n r=out", "typeset -n r=out"):
            with self.subTest(decl=decl):
                hits, out = self.hits('out=$RUNNER_TEMP/out\n%s\nr=scripts/build.sh\n'
                                      'cp payload "$out"\nbash scripts/build.sh' % decl)
                self.assertTrue(hits, out)

    def test_nameref_to_another_variable_leaves_out_known(self):
        hits, out = self.hits('out=$RUNNER_TEMP/out\ndeclare -n r=other\nr=scripts/build.sh\n'
                              'cp payload "$out"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    def scenario(self, setter, prefix="out=$RUNNER_TEMP/out"):
        return self.hits('%s\n%s\ncp payload "$out"\nbash scripts/build.sh' % (prefix, setter))

    # hole 1: a default or assign word that is nested, quoted or a substitution still sets the variable
    def test_default_with_a_nested_quoted_or_substituted_word_makes_it_unknown(self):
        forms = {
            "nested colon": ": ${out:=${target}}",
            "nested assign": ": ${out=${target}}",
            "nested quoted": ': "${out:=${target}}"',
            "substitution colon": ": ${out:=$(echo x)}",
            "substitution assign": ": ${out=$(echo x)}",
            "double quoted word": ': ${out:="a b"}',
            "single quoted word": ": ${out:='a b'}",
        }
        for prefix in ("out=$RUNNER_TEMP/out", "if false; then out=$RUNNER_TEMP/out; fi"):
            for name, setter in forms.items():
                with self.subTest(setter=name, prefix=prefix):
                    hits, out = self.scenario(setter, prefix)
                    self.assertTrue(hits, out)

    def test_control_without_the_nested_setter_is_accepted(self):
        for prefix in ("out=$RUNNER_TEMP/out", "if false; then out=$RUNNER_TEMP/out; fi"):
            with self.subTest(prefix=prefix):
                hits, out = self.scenario(": ${target}", prefix)
                self.assertFalse(hits, out)

    # hole 2: a redirection glued to the setter token does not hide it
    def test_redirection_glued_to_the_setter_does_not_hide_it(self):
        forms = {
            "printf -vout>": "printf -vout>/dev/null '%s' /inside",
            "declare -n r=out>": "declare -n r=out>/dev/null; r=/inside",
            "declare -n r=out> newline": "declare -n r=out>/dev/null\nr=/inside",
            "read -rout>": "read -rout>/dev/null <<< /inside",
            "mapfile -tout>": "mapfile -tout>/dev/null <<< /inside",
            "readarray -tout>": "readarray -tout>/dev/null <<< /inside",
            "printf -v out>": "printf -v out>/dev/null '%s' /inside",
            "declare out=x>": "declare out=/inside>/dev/null",
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.scenario(setter)
                self.assertTrue(hits, out)

    def test_control_redirection_forms_that_do_not_name_the_variable_are_accepted(self):
        forms = {
            "printf -vother>": "printf -vother>/dev/null '%s' /inside",
            "declare -n r=other>": "declare -n r=other>/dev/null; r=/inside",
            "read -rother>": "read -rother>/dev/null <<< /inside",
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.scenario(setter)
                self.assertFalse(hits, out)

    # hole 3: the literal body of an eval or trap word counts like top level
    def test_eval_or_trap_body_naming_the_variable_makes_it_unknown(self):
        forms = {
            "trap printf -vout": "trap 'printf -vout %s scripts/build.sh' DEBUG",
            "trap printf -v out": "trap 'printf -v out %s scripts/build.sh' DEBUG",
            "trap declare -n": "trap 'declare -n r=out; r=/inside' EXIT",
            "trap read": "trap 'read out <<< /inside' EXIT",
            "trap double quoted": 'trap "printf -v out %s /inside" EXIT',
            "eval printf -v": "eval 'printf -v out %s /inside'",
            "eval read": "eval 'read out <<< /inside'",
            "eval double quoted": 'eval "printf -v out %s /inside"',
            "eval declare -n": "eval 'declare -n r=out; r=/inside'",
            "eval default": "eval ': ${out:=/inside}'",
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.scenario(setter)
                self.assertTrue(hits, out)

    def test_eval_or_trap_body_not_naming_the_variable_is_accepted(self):
        forms = {
            "trap echo": "trap 'echo hi' DEBUG",
            "trap other printf -v": "trap 'printf -v other %s /inside' DEBUG",
            "trap other nameref": "trap 'declare -n r=other; r=/inside' EXIT",
            "eval echo": "eval 'echo hi'",
            "eval other read": "eval 'read other <<< /inside'",
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.scenario(setter)
                self.assertFalse(hits, out)

    # a < or > inside quotes is part of the word, not a redirection: a quoted subscript still names the variable
    def test_quoted_subscript_with_angle_bracket_still_names_the_variable(self):
        forms = {}
        for ch in "<>":
            for q in ("'", '"'):
                sub = "%sout[1%s0]%s" % (q, ch, q)
                forms["declare -n %s" % sub] = "declare -n r=%s; r=scripts/build.sh" % sub
                forms["printf -v %s" % sub] = "printf -v %s %%s scripts/build.sh" % sub
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.scenario(setter)
                self.assertTrue(hits, out)

    def test_control_quoted_angle_bracket_in_an_unrelated_word_changes_nothing(self):
        forms = {
            "echo single <": "echo 'a<b'",
            "echo double >": 'echo "a>b"',
            "other quoted subscript printf -v": "printf -v 'other[1<0]' %s /inside",
            "other quoted subscript nameref": 'declare -n r="other[1>0]"; r=/inside',
        }
        for name, setter in forms.items():
            with self.subTest(setter=name):
                hits, out = self.scenario(setter)
                self.assertFalse(hits, out)


if __name__ == "__main__":
    unittest.main()
