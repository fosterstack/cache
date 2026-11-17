"""Tests for check-action-pins.py: a redirect or tee onto a variable path is a write onto the committed file.

Written from the English rules only (R1-R5), not from the checker's source.
"""
import importlib.util, os, subprocess, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
ROOT = os.path.abspath(os.path.join(BIN, "..", ".."))
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins", SRC)
M = importlib.util.module_from_spec(_spec)
sys.modules["check_action_pins"] = M
_spec.loader.exec_module(M)

REL = ".github/agent/bin/run.sh"
FINDING = "is changed by the job before it runs"


def w(script):
    return bool(M._writes(script, REL))


class VariableRedirect(unittest.TestCase):
    # R1: each redirect form answers as cp onto the same target does
    TARGETS = ['$f', '"$f"', '"${f}"', '"$dir/x"', '"$(pick)"']
    FORMS = ['cat x > {t}', 'cat x >> {t}', 'cat x >| {t}', 'cat x | tee {t}', 'cat x | tee -a {t}']

    def test_r1_unplaceable_targets_write(self):
        for t in self.TARGETS:
            self.assertTrue(w("cp x %s\n" % t), "cp baseline " + t)
            for form in self.FORMS:
                with self.subTest(form=form, target=t):
                    self.assertTrue(w(form.format(t=t) + "\n"))

    def test_r1_same_answer_as_cp(self):
        targets = self.TARGETS + ['"$RUNNER_TEMP/x"', '/tmp/x', '/dev/null']
        for t in targets:
            for form in self.FORMS:
                with self.subTest(form=form, target=t):
                    self.assertEqual(w(form.format(t=t) + "\n"), w("cp x %s\n" % t))

    # R2: targets placed outside the checkout
    def test_r2_placeable_targets_not_write(self):
        pre = ['', 't=$(mktemp)\n', 'd=$(mktemp -d)\n']
        cases = [
            't=$(mktemp)\n{c} "$t"',
            'd=$(mktemp -d)\n{c} "$d/out"',
            'd=$(mktemp -d)\ne="$d/sub"\n{c} "$e/out"',
            '{c} "$RUNNER_TEMP/out"',
            '{c} /tmp/out',
            '{c} /dev/null',
        ] + ['{c} %s' % v for v in ('$GITHUB_OUTPUT', '"$GITHUB_OUTPUT"', '"${GITHUB_OUTPUT}"',
             '$GITHUB_ENV', '"$GITHUB_ENV"', '"${GITHUB_ENV}"', '$GITHUB_PATH', '"${GITHUB_PATH}"',
             '$GITHUB_STATE', '"${GITHUB_STATE}"', '$GITHUB_STEP_SUMMARY', '"${GITHUB_STEP_SUMMARY}"')]
        for case in cases:
            for c in ('cat x >', 'cat x >>', 'cat x >|', 'cat x | tee', 'cat x | tee -a'):
                with self.subTest(case=case, c=c):
                    self.assertFalse(w(case.replace('{c}', c) + "\n"))

    def test_r2_variable_assigned_committed_path_writes(self):
        self.assertTrue(w('f=%s\ncat x > "$f"\n' % REL))

    def test_r2_variable_assigned_two_ways_writes(self):
        self.assertTrue(w('f=$(mktemp)\nif [ -n "$A" ]; then f=%s; fi\ncat x > "$f"\n' % REL))
        self.assertTrue(w('f=$(mktemp)\nf="$other"\ncat x > "$f"\n'))

    def test_r2_literal_redirects(self):
        for op in ('>', '>>', '>|'):
            with self.subTest(op=op):
                self.assertTrue(w("cat x %s %s\n" % (op, REL)))
                self.assertFalse(w("cat x %s other.txt\n" % op))
        self.assertTrue(w("cat x | tee %s\n" % REL))
        self.assertFalse(w("cat x | tee other.txt\n"))

    def test_r2_stderr_dup_not_write(self):
        self.assertFalse(w("echo hi 2>&1\n"))
        self.assertFalse(w("echo hi >/dev/null 2>&1\n"))

    # R3
    def test_r3_clobber_redirect_is_one_redirection(self):
        self.assertTrue(w("cat x >| %s\n" % REL))
        self.assertTrue(w("cat x >| .github/agent/bin/run.sh\n"))


WF = """on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
%s
"""


def step(run):
    return "      - run: |\n" + "".join("          %s\n" % l for l in run.splitlines())


class JobOrder(unittest.TestCase):
    """R4: the variable-redirect rule judges only the job's own step text before the step that runs the script;
    other committed scripts keep only the literal-path rule. R5: the cp rule is unchanged: cp onto a
    destination under a variable the gate cannot place, in a script the job runs before the target, is a finding;
    a cat redirect onto the same destination is not."""

    def check(self, steps, files):
        d = tempfile.mkdtemp()
        tree = {".github/workflows/x.yml": WF % "".join(steps).rstrip("\n"), **files}
        for rel, text in tree.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(text)
        r = subprocess.run([sys.executable, SRC, d], cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, "LC_ALL": "C"})
        out = r.stdout + r.stderr
        return [l for l in out.splitlines() if FINDING in l and "target.sh" in l], out

    HELPER = {"bin/helper.sh": '#!/bin/sh\ncat x > "$dest"\n', "bin/target.sh": "#!/bin/sh\necho hi\n"}

    def test_r4_case_a_helper_variable_redirect_not_judged_by_variable_rule(self):
        hits, out = self.check([step("bash bin/helper.sh"), step("bash bin/target.sh")], self.HELPER)
        self.assertFalse(hits, out)

    def test_r5_cp_onto_variable_destination_in_helper_is_finding(self):
        files = {"bin/helper.sh": '#!/bin/sh\ncp .github/policy/release-key-root.pub "$dir/release-key-root.pub"\n',
                 "bin/target.sh": "#!/bin/sh\necho hi\n"}
        hits, out = self.check([step("bash bin/helper.sh"), step("bash bin/target.sh")], files)
        self.assertTrue(hits, out)

    def test_r5_cat_redirect_onto_variable_destination_in_helper_no_finding(self):
        files = {"bin/helper.sh": '#!/bin/sh\ncat .github/policy/release-key-root.pub > "$dir/release-key-root.pub"\n',
                 "bin/target.sh": "#!/bin/sh\necho hi\n"}
        hits, out = self.check([step("bash bin/helper.sh"), step("bash bin/target.sh")], files)
        self.assertFalse(hits, out)

    def test_r5_helper_with_literal_path_redirect_is_finding(self):
        files = {"bin/helper.sh": "#!/bin/sh\ncat x > bin/target.sh\n",
                 "bin/target.sh": "#!/bin/sh\necho hi\n"}
        hits, out = self.check([step("bash bin/helper.sh"), step("bash bin/target.sh")], files)
        self.assertTrue(hits, out)

    def test_r4_case_b_helper_after_target_no_finding(self):
        hits, out = self.check([step("bash bin/target.sh"), step("bash bin/helper.sh")], self.HELPER)
        self.assertFalse(hits, out)

    def test_r4_case_c_target_holds_redirect_no_finding(self):
        files = {"bin/target.sh": '#!/bin/sh\ncat x > "$dest"\n'}
        hits, out = self.check([step("bash bin/target.sh")], files)
        self.assertFalse(hits, out)

    def test_r4_case_d_own_step_text_before_run_is_finding(self):
        hits, out = self.check([step('cat x > "$dest"\nbash bin/target.sh')],
                               {"bin/target.sh": "#!/bin/sh\necho hi\n"})
        self.assertTrue(hits, out)

    def test_r4_case_d_separate_earlier_step_is_finding(self):
        hits, out = self.check([step('cat x > "$dest"'), step("bash bin/target.sh")],
                               {"bin/target.sh": "#!/bin/sh\necho hi\n"})
        self.assertTrue(hits, out)

class FixEscapedGreaterAndRunnerFiles(unittest.TestCase):
    def images(self, script):
        return M.script_images(script)

    # AC1: an escaped greater-than is a literal, so the pipe after it is real and the next command is inspected
    def test_fix_escaped_gt_then_pipe_reports_unpinned_image(self):
        self.assertTrue(self.images("echo \\>| docker run alpine:latest\n"))

    # AC1 guard: escaped backslash then a real clobber redirect: target is docker, no second command exists
    def test_fix_escaped_backslash_then_clobber_has_no_second_command(self):
        self.assertTrue(self.images("docker run alpine:latest\n"))
        self.assertEqual(self.images("echo \\\\>| docker run alpine:latest\n"), [])

    # AC1 carry-over: an escape in an earlier command does not change how a later command's clobber redirect is read
    def test_fix_escape_does_not_outlive_semicolon_command(self):
        self.assertEqual(self.images("echo \\x;echo x>| docker run alpine:latest\n"), [])

    def test_fix_escape_does_not_outlive_newline_command(self):
        self.assertEqual(self.images("echo \\x\necho x>| docker run alpine:latest\n"), [])

    def test_fix_escape_does_not_outlive_pipe_command(self):
        self.assertEqual(self.images("echo \\x | echo x>| docker run alpine:latest\n"), [])

    # AC1 guard: a clobber redirect is still one redirection and is a write onto the committed file
    def test_fix_clobber_redirect_still_one_redirection(self):
        self.assertTrue(w("echo x >| %s\n" % REL))
        self.assertFalse(w("echo x >| out.txt\n"))

    # AC2: when the job never assigns the runner file names, they stay exempt
    def test_fix_runner_files_unassigned_not_write(self):
        self.assertFalse(w('cp x "$GITHUB_OUTPUT"\n'))
        self.assertFalse(w('echo y >> "$GITHUB_ENV"\n'))

    # AC2a: an assigned runner-file name is the value assigned: the committed file
    def test_fix_assigned_runner_file_is_committed_file_write(self):
        self.assertTrue(M._writes('GITHUB_OUTPUT=bin/target.sh\ncp x "$GITHUB_OUTPUT"\nbash bin/target.sh\n', "bin/target.sh"))

    # AC2a whole-job: the same script as a step reports the finding
    def test_fix_assigned_runner_file_whole_job_finding(self):
        hits, out = JobOrder("test_r4_case_d_own_step_text_before_run_is_finding").check(
            [step('GITHUB_OUTPUT=bin/target.sh\ncp x "$GITHUB_OUTPUT"\nbash bin/target.sh')],
            {"bin/target.sh": "#!/bin/sh\necho hi\n"})
        self.assertTrue(hits, out)

    # AC2b: assignment to the file's directory: a copy into it lands in the directory
    def test_fix_assigned_runner_file_directory_is_write(self):
        self.assertTrue(M._writes('GITHUB_OUTPUT=bin\ncp x "$GITHUB_OUTPUT"\n', "bin/target.sh"))

    # AC2c: assignment outside the checkout keeps the destination exempt
    def test_fix_assigned_runner_file_outside_checkout_exempt(self):
        self.assertFalse(M._writes('GITHUB_ENV=$RUNNER_TEMP/env\ncp x "$GITHUB_ENV"\n', "bin/target.sh"))
        self.assertFalse(M._writes('GITHUB_ENV=$RUNNER_TEMP/env\necho y >> "$GITHUB_ENV"\n', "bin/target.sh"))


class RunnerFileSetByOtherForms(unittest.TestCase):
    """The runner-file exemption holds only when every mention of the name is a plain $NAME or ${NAME} read."""
    FILES = {"scripts/build.sh": "#!/bin/sh\necho hi\n"}

    def hits(self, run):
        hits, out = JobOrder("test_r4_case_d_own_step_text_before_run_is_finding").check(
            [step(run)], self.FILES)
        return [l for l in out.splitlines() if FINDING in l and "build.sh" in l], out

    def reported(self, setter):
        hits, out = self.hits(setter + '\necho "x=1" >> "$GITHUB_OUTPUT"\nbash scripts/build.sh')
        self.assertTrue(hits, out)

    def test_runner_file_set_by_read_r_is_reported(self):
        self.reported('read -r GITHUB_OUTPUT <<< scripts/build.sh')

    def test_runner_file_set_by_read_is_reported(self):
        self.reported('read GITHUB_OUTPUT <<< scripts/build.sh')

    def test_runner_file_set_by_for_in_is_reported(self):
        self.reported('for GITHUB_OUTPUT in scripts/build.sh; do break; done')

    def test_runner_file_set_by_printf_v_is_reported(self):
        self.reported("printf -v GITHUB_OUTPUT '%s' scripts/build.sh")

    def test_runner_file_set_by_default_assign_colon_is_reported(self):
        self.reported('unset GITHUB_OUTPUT\n: "${GITHUB_OUTPUT:=scripts/build.sh}"')

    def test_runner_file_set_by_default_assign_is_reported(self):
        self.reported('unset GITHUB_OUTPUT\n: "${GITHUB_OUTPUT=scripts/build.sh}"')

    def test_runner_file_set_by_arith_is_reported(self):
        self.reported('(( GITHUB_OUTPUT = 1 ))')

    def test_runner_file_set_by_let_is_reported(self):
        self.reported('let "GITHUB_OUTPUT = 1"')

    def test_runner_file_set_by_split_eval_is_reported(self):
        self.reported('eval \'GITHUB_\'"OUTPUT=scripts/build.sh"')

    def test_runner_file_set_by_array_element_is_reported(self):
        self.reported('GITHUB_OUTPUT[0]=scripts/build.sh')

    def test_runner_file_set_by_mapfile_is_reported(self):
        self.reported('mapfile GITHUB_OUTPUT <<< scripts/build.sh')

    def test_runner_file_set_by_getopts_is_reported(self):
        self.reported("getopts 'a:' GITHUB_OUTPUT -a")

    def test_fills_dir_runner_file_set_by_read_is_not_exempt(self):
        # _fills_dir asks _outside() too: tar -C onto a name set by `read` must count as filling the directory
        self.assertTrue(M._writes('read -r GITHUB_OUTPUT <<< scripts\ntar -xf a.tar -C "$GITHUB_OUTPUT"\n', "scripts/build.sh"))

    def test_plain_dollar_read_not_reported(self):
        hits, out = self.hits('echo "x=1" >> "$GITHUB_OUTPUT"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    def test_braced_read_not_reported(self):
        hits, out = self.hits('echo y >> "${GITHUB_OUTPUT}"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    # The name is judged as bash forms it: after quote and backslash removal, failing closed on names built at run time
    def reported_cp(self, setter):
        hits, out = self.hits(setter + '\ncp payload "$GITHUB_OUTPUT"\nbash scripts/build.sh')
        self.assertTrue(hits, out)

    def test_cp_runner_file_set_by_read_with_quote_split_name_is_reported(self):
        self.reported_cp('read -r GITHUB_""OUTPUT <<< scripts/build.sh')

    def test_cp_runner_file_set_by_printf_v_with_quote_split_name_is_reported(self):
        self.reported_cp('printf -v GITHUB_""OUTPUT %s scripts/build.sh')

    def test_cp_runner_file_set_by_quote_split_eval_word_is_reported(self):
        self.reported_cp('e""val \'GITHUB_\'"OUTPUT=scripts/build.sh"')

    def test_cp_runner_file_set_by_backslash_split_name_is_reported(self):
        self.reported_cp('GITHUB_OUT\\PUT=scripts/build.sh')

    def test_cp_runner_file_set_by_read_with_ansi_c_name_is_reported(self):
        self.reported_cp("read -r $'GITHUB_OUTPUT' <<< scripts/build.sh")

    def test_cp_runner_file_set_by_read_with_name_built_at_run_time_is_reported(self):
        self.reported_cp('n=GITHUB_; read -r "${n}OUTPUT" <<< scripts/build.sh')

    def test_fills_dir_runner_file_set_by_read_with_quote_split_name_is_not_exempt(self):
        self.assertTrue(M._writes('read -r GITHUB_""OUTPUT <<< scripts\ntar -xf a.tar -C "$GITHUB_OUTPUT"\n', "scripts/build.sh"))

    def test_fills_dir_runner_file_set_by_read_with_name_built_at_run_time_is_not_exempt(self):
        self.assertTrue(M._writes('n=GITHUB_; read -r "${n}OUTPUT" <<< scripts\ntar -xf a.tar -C "$GITHUB_OUTPUT"\n', "scripts/build.sh"))

    def test_cp_runner_file_set_through_declare_nameref_is_reported(self):
        self.reported_cp('n=GITHUB_; declare -n ref="${n}OUTPUT"; ref=scripts/build.sh')

    def test_cp_runner_file_set_by_read_with_here_string_before_name_is_reported(self):
        self.reported_cp('n=GITHUB_; read -r <<< scripts/build.sh "${n}OUTPUT"')

    def test_cp_runner_file_set_by_read_with_lt_in_prompt_is_reported(self):
        self.reported_cp('n=GITHUB_; read -p "<" "${n}OUTPUT" <<< scripts/build.sh')

    def test_cp_runner_file_set_by_read_with_equals_in_prompt_is_reported(self):
        self.reported_cp('n=GITHUB_; read -p "=" "${n}OUTPUT" <<< scripts/build.sh')

    def test_cp_runner_file_set_by_printf_v_attached_run_time_name_is_reported(self):
        self.reported_cp('n=GITHUB_; printf -v"${n}OUTPUT" %s scripts/build.sh')

    def test_cp_runner_file_set_by_indirect_default_assign_is_reported(self):
        self.reported_cp('n=GITHUB_; ref=${n}OUTPUT; unset "$ref"; : "${!ref:=scripts/build.sh}"')

    def test_cp_runner_file_set_by_read_with_ansi_c_name_after_run_time_name_is_reported(self):
        self.reported_cp("read -r $'GITHUB_OUTPUT' <<< scripts/build.sh")
        self.reported_cp('n=GITHUB_; read -r "${n}OUTPUT" <<< scripts/build.sh')

    def test_fills_dir_runner_file_set_through_declare_nameref_is_not_exempt(self):
        self.assertTrue(M._writes('n=GITHUB_; declare -n ref="${n}OUTPUT"; ref=scripts\ntar -xf a.tar -C "$GITHUB_OUTPUT"\n', "scripts/build.sh"))

    def test_cp_onto_plain_dollar_read_not_reported(self):
        hits, out = self.hits('echo x >> "$GITHUB_OUTPUT"\ncp payload "$GITHUB_OUTPUT"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    def test_cp_onto_braced_read_not_reported(self):
        hits, out = self.hits('echo x >> "${GITHUB_OUTPUT}"\ncp payload "${GITHUB_OUTPUT}"\nbash scripts/build.sh')
        self.assertFalse(hits, out)

    def test_cp_with_unrelated_literal_read_keeps_exemption(self):
        hits, out = self.hits('read -r line <<< hello\ncp payload "$GITHUB_OUTPUT"\nbash scripts/build.sh')
        self.assertFalse(hits, out)


if __name__ == "__main__":
    unittest.main()
