# proves: REQ-REL-005-AC4, REQ-REL-005-AC5
"""Tests for check-action-pins.py: an environment write is read only in three plain forms; every PATH write is refused.

A finding names the job, the step and the route; the step keys may be spelled in any letter case.
"""
import contextlib, importlib.util, io, os, runpy, shutil, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins_env_names", SRC)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

GATE = os.path.join(BIN, "..", "..", "workflows", "agent-review-gate.yml")
GATE_PROGRAMS = dict.fromkeys([".github/agent/bin/auditor-review-gate.py", ".github/agent/bin/check-action-pins.py",
                              "bin/check-file-allowlist.sh", ".github/agent/tests/pin-wiring-test.sh",
                              "bin/scan-no-workflow-call-test.sh", "bin/audit-record-judge.sh",
                              "bin/audit-record-prepare.sh", ".github/agent/bin/auditor-signed-commit.py"], "")
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
W = ".github/workflows/w.yml"


def repo(files, gate=True):
    """A throwaway tree; it carries the real, pinned gate workflow unless gate=False."""
    if gate:
        with open(GATE) as fh:
            files = {".github/workflows/agent-review-gate.yml": fh.read(), **files}
    d = tempfile.mkdtemp()
    for rel, text in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
    return d


def run(argv, cwd=None):
    out, old = io.StringIO(), os.getcwd()
    try:
        if cwd:
            os.chdir(cwd)
        with mock.patch.object(sys, "argv", ["check-action-pins.py", *argv]), contextlib.redirect_stdout(out):
            try:
                runpy.run_path(SRC, run_name="__main__")
                code = 0
            except SystemExit as e:
                code = e.code
    finally:
        os.chdir(old)
    return code, out.getvalue()


def indent(text, n):
    return text.replace("\n", "\n" + " " * n)


def run_step(text, key="run"):
    return f"      - {key}: |\n          {indent(text, 10)}\n"


def script_step(js, uses_key="uses", with_key="with"):
    return (f"      - {uses_key}: actions/github-script@{SHA} # v7.0.1\n        {with_key}:\n          script: |\n"
            f"            {indent(js, 12)}\n")


def workflow(steps, steps_key="steps", job_extra=""):
    return f"on: push\njobs:\n  build:\n    runs-on: ubuntu-24.04\n{job_extra}    {steps_key}:\n{steps}"


class Base(unittest.TestCase):
    def check(self, wf, files=None, name=W):
        d = repo({name: wf, **GATE_PROGRAMS, **(files or {})})
        self.addCleanup(shutil.rmtree, d)
        return run([d])

    def accepted(self, wf, files=None, name=W):
        code, out = self.check(wf, files, name)
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)

    def refused(self, wf, route, files=None, step=1, name=W, job="build"):
        """A finding line names the file, the job, the step and the route."""
        code, out = self.check(wf, files, name)
        self.assertEqual(code, 1, out)
        mine = [ln for ln in out.splitlines() if f"step {step}" in ln and route in ln]
        self.assertTrue(any(name in ln and (not job or f"job {job}" in ln) for ln in mine),
                        f"no finding names {job}, step {step} and {route}:\n{out}")


class ShellWrites(Base):
    def test_literal_non_hook_name_is_accepted(self):
        self.accepted(workflow(run_step('echo "GOTOOLCHAIN=local" >> "$GITHUB_ENV"')))

    def test_literal_name_with_expansion_in_value_is_accepted(self):
        self.accepted(workflow(run_step('echo "REF=ghcr.io/x@${d}" >> "$GITHUB_ENV"')))

    def test_braced_route_and_expansion_value_is_accepted(self):
        self.accepted(workflow(run_step('echo "A=$RUNNER_TEMP/x" >> "${GITHUB_ENV}"')))

    def test_printf_is_accepted(self):
        self.accepted(workflow(run_step("printf 'A=%s\\n' \"$v\" >> \"$GITHUB_ENV\"")))

    def test_step_with_no_env_route_is_accepted(self):
        self.accepted(workflow(run_step('echo hello')))

    def test_name_split_by_quotes_into_a_non_hook_name_is_accepted(self):
        self.accepted(workflow(run_step('echo "MY_""VAR=1" >> "$GITHUB_ENV"')))

    def test_set_env_with_literal_name_is_accepted(self):
        self.accepted(workflow(run_step('echo "::set-env name=ABC::v"')))

    def test_split_quotes_hook_name_is_refused(self):
        self.refused(workflow(run_step('echo "LD_PRE""LOAD=x" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_name_from_inputs_is_refused(self):
        self.refused(workflow(run_step('echo "${{ inputs.n }}=1" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_name_from_matrix_is_refused(self):
        self.refused(workflow(run_step('echo "${{ matrix.n }}=1" >> "$GITHUB_ENV"'), job_extra="    strategy:\n      matrix:\n        n: [A, B]\n"),
                     "GITHUB_ENV")

    def test_name_from_needs_is_refused(self):
        self.refused(workflow(run_step('echo "${{ needs.a.outputs.n }}=1" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_name_from_shell_variable_is_refused(self):
        self.refused(workflow(run_step('echo "$n=1" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_name_from_command_substitution_is_refused(self):
        self.refused(workflow(run_step('echo "$(date +%s)=1" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_names_read_from_a_file_are_refused(self):
        self.refused(workflow(run_step('echo "A=1" > vars.txt\ncat vars.txt >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_heredoc_is_refused(self):
        self.refused(workflow(run_step('cat >> "$GITHUB_ENV" <<EOF\nA=1\nEOF')), "GITHUB_ENV")

    def test_tee_is_refused(self):
        self.refused(workflow(run_step('echo "A=1" | tee -a "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_route_in_env_value_is_refused(self):
        self.refused(workflow(run_step('echo hi', ) + "        env:\n          OUT: ${{ github.env }}\n"), "github.env")

    def test_route_put_in_a_variable_is_refused(self):
        self.refused(workflow(run_step('OUT="$GITHUB_ENV"\necho "A=1" >> "$OUT"')), "GITHUB_ENV")

    def test_route_in_a_comment_is_refused(self):
        self.refused(workflow(run_step('# echo "A=1" >> "$GITHUB_ENV"\necho hi')), "GITHUB_ENV")

    def test_backslash_in_the_middle_of_the_argument_is_refused(self):
        self.refused(workflow(run_step('echo "A=1\\nB=2" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_set_env_name_from_expression_is_refused(self):
        self.refused(workflow(run_step('echo "::set-env name=${{ inputs.n }}::v"')), "::set-env")

    def test_literal_hook_name_is_still_refused(self):
        self.refused(workflow(run_step('echo "LD_PRELOAD=x" >> "$GITHUB_ENV"')), "GITHUB_ENV")

    def test_github_path_is_still_refused(self):
        self.refused(workflow(run_step('echo "$p" >> "$GITHUB_PATH"')), "GITHUB_PATH")

    def test_plain_step_and_unreadable_step_only_the_second_is_named(self):
        wf = workflow(run_step('echo "A=1" >> "$GITHUB_ENV"') + run_step('echo "$n=1" >> "$GITHUB_ENV"'))
        self.refused(wf, "GITHUB_ENV", step=2)
        _, out = self.check(wf)
        self.assertNotIn("step 1", out)


class JsWrites(Base):
    def test_literal_name_is_accepted(self):
        self.accepted(workflow(script_step("core.exportVariable('ANTHROPIC_IDENTITY_TOKEN_FILE', p)")))

    def test_name_from_process_env_is_refused(self):
        self.refused(workflow(script_step("core.exportVariable(process.env.N, v)")), "exportVariable")

    def test_name_built_from_pieces_is_refused(self):
        self.refused(workflow(script_step('core.exportVariable("A" + "B", v)')), "exportVariable")

    def test_hook_name_is_still_refused(self):
        self.refused(workflow(script_step("core.exportVariable('BASH_ENV', p)")), "BASH_ENV")

    def test_add_path_is_still_refused(self):
        self.refused(workflow(script_step("core.addPath(p)")), "addPath")


class CommittedScripts(Base):
    def script(self, line, step="run: ./bin/setup.sh", job_extra=""):
        wf = workflow(f"      - {step}\n", job_extra=job_extra)
        return wf, {"bin/setup.sh": "#!/usr/bin/env bash\n" + line + "\n"}

    def test_plain_write_in_a_script_is_accepted(self):
        wf, files = self.script('echo "REF=x" >> "$GITHUB_ENV"')
        self.accepted(wf, files)

    def test_name_built_in_a_script_is_refused(self):
        wf, files = self.script('echo "${N}=1" >> "$GITHUB_ENV"')
        self.refused(wf, "GITHUB_ENV", files)

    def test_script_heredoc_is_refused(self):
        wf, files = self.script('cat >> "$GITHUB_ENV" <<EOF\nA=1\nEOF')
        self.refused(wf, "GITHUB_ENV", files)

    def test_route_put_in_a_variable_for_a_script_is_refused(self):
        wf, files = self.script('echo "A=1" >> "$OUT"', 'run: OUT="$GITHUB_ENV" bash ./bin/setup.sh')
        self.refused(wf, "GITHUB_ENV", files)


class LetterCase(Base):
    LOWER_FLOW = {"steps": "Steps"}

    def test_steps_key_unreadable_write_is_refused(self):
        self.refused(workflow(run_step('echo "$n=1" >> "$GITHUB_ENV"'), steps_key="Steps"), "GITHUB_ENV")

    def test_steps_key_hook_name_is_refused(self):
        self.refused(workflow(run_step('echo "LD_PRELOAD=x" >> "$GITHUB_ENV"'), steps_key="Steps"), "GITHUB_ENV")

    def test_steps_key_plain_write_is_accepted(self):
        self.accepted(workflow(run_step('echo "A=1" >> "$GITHUB_ENV"'), steps_key="Steps"))

    def test_steps_key_path_write_is_refused(self):
        self.refused(workflow(run_step('echo "$p" >> "$GITHUB_PATH"'), steps_key="Steps"), "GITHUB_PATH")

    def test_run_key_unreadable_write_is_refused(self):
        self.refused(workflow(run_step('echo "$n=1" >> "$GITHUB_ENV"', key="Run")), "GITHUB_ENV")

    def test_run_key_hook_name_is_refused(self):
        self.refused(workflow(run_step('echo "LD_PRELOAD=x" >> "$GITHUB_ENV"', key="Run")), "GITHUB_ENV")

    def test_run_key_plain_write_is_accepted(self):
        self.accepted(workflow(run_step('echo "A=1" >> "$GITHUB_ENV"', key="Run")))

    def test_with_key_unreadable_write_is_refused(self):
        self.refused(workflow(script_step("core.exportVariable(process.env.N, v)", with_key="With")), "exportVariable")

    def test_with_key_hook_name_is_refused(self):
        self.refused(workflow(script_step("core.exportVariable('BASH_ENV', p)", with_key="With")), "BASH_ENV")

    def test_with_key_plain_write_is_accepted(self):
        self.accepted(workflow(script_step("core.exportVariable('A', p)", with_key="With")))

    def test_env_key_unreadable_route_is_refused(self):
        self.refused(workflow(run_step("echo hi") + "        Env:\n          OUT: ${{ github.env }}\n"), "github.env")

    def test_env_key_hook_name_write_is_refused(self):
        self.refused(workflow(run_step('echo "LD_PRELOAD=x" >> "$GITHUB_ENV"') + "        Env:\n          K: v\n"), "GITHUB_ENV")

    def test_env_key_plain_write_is_accepted(self):
        self.accepted(workflow(run_step('echo "A=1" >> "$GITHUB_ENV"') + "        Env:\n          K: v\n"))

    def test_steps_key_script_with_unreadable_name_is_refused(self):
        wf = workflow("      - run: ./bin/setup.sh\n", steps_key="Steps")
        self.refused(wf, "GITHUB_ENV", {"bin/setup.sh": '#!/usr/bin/env bash\necho "${N}=1" >> "$GITHUB_ENV"\n'})

    def test_steps_key_script_with_plain_name_is_accepted(self):
        wf = workflow("      - run: ./bin/setup.sh\n", steps_key="Steps")
        self.accepted(wf, {"bin/setup.sh": '#!/usr/bin/env bash\necho "REF=x" >> "$GITHUB_ENV"\n'})

    def action(self, run_text, steps_key="Steps"):
        return f"name: a\nruns:\n  using: composite\n  {steps_key}:\n    - run: |\n        {indent(run_text, 8)}\n      shell: bash\n"

    def test_composite_action_unreadable_write_is_refused(self):
        self.refused(self.action('echo "$n=1" >> "$GITHUB_ENV"'), "GITHUB_ENV", name="action.yml", job="")

    def test_composite_action_plain_write_is_accepted(self):
        self.accepted(self.action('echo "A=1" >> "$GITHUB_ENV"'), name="action.yml")

    def test_composite_action_hook_name_is_refused(self):
        self.refused(self.action('echo "LD_PRELOAD=x" >> "$GITHUB_ENV"'), "GITHUB_ENV", name="action.yml", job="")


if __name__ == "__main__":
    unittest.main()
