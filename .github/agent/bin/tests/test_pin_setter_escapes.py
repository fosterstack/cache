"""Tests for check-action-pins.py `_outside`: a backslash, a `#` that starts no comment, or an eval can hide a real `out=.`."""
import shutil, unittest

from test_pin_setter_quotes import GATE_PROGRAMS, M, repo, run

# each case is the script's lines; every one really assigns out=. where the shell reads it
CASES = {
    "escaped_dquote_in_dquotes": [r'out="$RUNNER_TEMP/\""; out=.'],
    "escaped_squote_lines": ["out=$RUNNER_TEMP/x", r"echo \'; out=.; echo \'"],
    "escaped_dquote_lines": ["out=$RUNNER_TEMP/x", r'echo \"; out=.; echo \"'],
    "backslash_space_hash": [r"out=$RUNNER_TEMP/x; echo \ #; out=."],
    "hash_in_expansion": ["out=$RUNNER_TEMP/x; y=${x// #/}; out=."],
    "eval_string": ['out=$RUNNER_TEMP/x; eval " out=."'],
}
# the same escaped-quote text split over two steps of one job
SPLIT = [["out=$RUNNER_TEMP/x", r"echo \'"], [r"out=.; echo \'"]]
CONTROLS = {"plain": "out=$RUNNER_TEMP/x", "quoted": 'out="$RUNNER_TEMP/x"'}


def tree(steps):
    """A tree with one job; each item of `steps` is one `- run: |` step, the last also copies and builds."""
    steps = [list(s) for s in steps]
    steps[-1] += ['cp -R evil/. "$out"', "docker build -t img ."]
    body = "".join("      - run: |\n" + "".join("          " + ln + "\n" for ln in s) for s in steps)
    wf = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + body
    return repo({".github/workflows/w.yml": wf, "Dockerfile": "FROM scratch\n", **GATE_PROGRAMS})


class Base(unittest.TestCase):
    def result(self, steps):
        d = tree(steps)
        self.addCleanup(shutil.rmtree, d)
        return run([d])

    def flagged(self, steps):
        code, out = self.result(steps)
        self.assertEqual(code, 1, out)
        self.assertNotIn(" 0 finding(s)", out)

    def clean(self, steps):
        code, out = self.result(steps)
        self.assertEqual(code, 0, out)
        self.assertIn(" 0 finding(s)", out)


class EscapesUnit(unittest.TestCase):
    def test_escaped_dquote_in_dquotes(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["escaped_dquote_in_dquotes"])), False)

    def test_escaped_squote_lines(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["escaped_squote_lines"])), False)

    def test_escaped_dquote_lines(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["escaped_dquote_lines"])), False)

    def test_backslash_space_hash(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["backslash_space_hash"])), False)

    def test_hash_in_expansion(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["hash_in_expansion"])), False)

    def test_eval_string(self):
        self.assertIs(M._outside("$out", "\n".join(CASES["eval_string"])), False)

    def test_split_over_two_steps(self):
        # the checker joins a job's step scripts with newlines
        self.assertIs(M._outside("$out", "\n".join("\n".join(s) for s in SPLIT)), False)


class EscapesFlagged(Base):
    def test_escaped_dquote_in_dquotes(self):
        self.flagged([CASES["escaped_dquote_in_dquotes"]])

    def test_escaped_squote_lines(self):
        self.flagged([CASES["escaped_squote_lines"]])

    def test_escaped_dquote_lines(self):
        self.flagged([CASES["escaped_dquote_lines"]])

    def test_backslash_space_hash(self):
        self.flagged([CASES["backslash_space_hash"]])

    def test_hash_in_expansion(self):
        self.flagged([CASES["hash_in_expansion"]])

    def test_eval_string(self):
        self.flagged([CASES["eval_string"]])

    def test_split_over_two_steps(self):
        self.flagged(SPLIT)


class Controls(Base):
    def test_unit_plain(self):
        self.assertIs(M._outside("$out", CONTROLS["plain"]), True)

    def test_unit_quoted(self):
        self.assertIs(M._outside("$out", CONTROLS["quoted"]), True)

    def test_plain_not_flagged(self):
        self.clean([[CONTROLS["plain"]]])

    def test_quoted_not_flagged(self):
        self.clean([[CONTROLS["quoted"]]])


if __name__ == "__main__":
    unittest.main()
