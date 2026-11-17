"""Tests for check-action-pins.py: a variable set by any form other than NAME= is set to an unknown value.

Written from the English rule only, not from the checker's source.
"""
import unittest

from test_pin_writes_redirect import FINDING, JobOrder, step


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
        hits, out = JobOrder("test_r4_case_d_own_step_text_before_run_is_finding").check(
            [step(run)], self.FILES)
        return [l for l in out.splitlines() if FINDING in l and "build.sh" in l], out

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


if __name__ == "__main__":
    unittest.main()
