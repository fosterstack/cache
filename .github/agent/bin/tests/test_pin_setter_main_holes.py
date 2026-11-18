"""Tests for check-action-pins.py `_outside`: a setter in a background job or a pipeline runs in a subshell, and a line continuation joins a word."""
import shutil, unittest

from test_pin_setter_quotes import ENV_OUT, GATE_PROGRAMS, M, Base, repo, run

COPY = 'cp -R evil/. "$out"'

# each case is the script's lines; the shell that copies has out=. (the step's env, or the joined word)
HOLES = {
    "background_direct": ["out=$RUNNER_TEMP/x&wait"],
    "pipeline_direct": ["out=$RUNNER_TEMP/x|cat"],
    "pipeline_last": ["cat|out=$RUNNER_TEMP/x"],
}
# the continuation joins a word in the shell, which the unit text (already joined by production) cannot show
END_TO_END_ONLY = {"line_continuation": ["out=$RUNNER_TEMP/x", "ou\\", "t=."]}
# the safe twins: the setter runs in the shell that copies, so the copy goes to a safe folder
TWINS = {
    "background_after": ["out=$RUNNER_TEMP/x;wait"],
    "and_list": ["out=$RUNNER_TEMP/x&&cat"],
    "or_list": ["out=$RUNNER_TEMP/x||cat"],
    "line_continuation": ["out=$RUNNER_TEMP/\\", "x"],
}
# the setter is not a whole command of the shell that copies, whose out is the step's env `.`
FORMS = {
    "background_redirect": "out=$RUNNER_TEMP/x >/dev/null &",
    "pipe_redirect": "out=$RUNNER_TEMP/x 2>&1|cat",
    "pipe_assignment": "out=$RUNNER_TEMP/x a=1|cat",
    "pipe_last_assignment": "cat|a=1 out=$RUNNER_TEMP/x",
    "paren_group": "(out=$RUNNER_TEMP/x)",
    "command_substitution": "$(out=$RUNNER_TEMP/x)",
    "prefix_of_command": "out=$RUNNER_TEMP/x true",
}
# known limits: group braces are not read, so these may stay unflagged; kept to see when they are
KNOWN_LIMITS = {
    "brace_background": "{ out=$RUNNER_TEMP/x; } &",
    "brace_in_pipeline": "cat | { out=$RUNNER_TEMP/x; }",
}
# a `|` in a comment or after a backslash is no pipeline
COMMENT_CLEAN = {
    "comment_pipe": ["# comment |", "out=$RUNNER_TEMP/x"],
    "escaped_pipe": ["echo \\|", "out=$RUNNER_TEMP/x"],
}
# steps whose texts the production code joins with a newline; the copy follows the last one
JOINS = {
    "comment_backslash_across_steps": (["out=$RUNNER_TEMP/x", "# comment\\"], ["out=.", COPY, "docker build -t img ."]),
    "double_backslash_comment": (["out=$RUNNER_TEMP/x", "#comment\\\\", "", "out=."], [COPY, "docker build -t img ."]),
    "setter_backslash_across_steps": (["out=$RUNNER_TEMP/x\\"], ["out=.", COPY, "docker build -t img ."]),
}


def production_text(steps):
    return "\n".join("\n".join(s).replace("\\\n", "") for s in steps)


def steps_repo(case, steps, env=""):
    body = ""
    for i, lines in enumerate(steps):
        body += "      - run: |-\n" + "".join("          " + ln + "\n" for ln in lines)
        if i == len(steps) - 1:
            body += env
    wf = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + body
    d = repo({".github/workflows/w.yml": wf, "Dockerfile": "FROM scratch\n", **GATE_PROGRAMS})
    case.addCleanup(shutil.rmtree, d)
    return d


class HolesUnit(unittest.TestCase):
    def test_holes_leave_out_unset(self):
        for name, lines in HOLES.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", "\n".join(lines)), False)

    def test_twins_set_out(self):
        for name, lines in TWINS.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", "\n".join(lines)), True)


class FormsUnit(unittest.TestCase):
    def test_forms_leave_out_unset(self):
        for name, form in {**FORMS, **KNOWN_LIMITS}.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", form + "\n" + COPY), False)

    def test_comment_and_escape_keep_setter(self):
        for name, lines in COMMENT_CLEAN.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", "\n".join(lines)), True)

    def test_joins_leave_out_unset(self):
        for name, steps in JOINS.items():
            with self.subTest(name):
                text = production_text(steps)
                self.assertIs(M._outside("$out", text), False)
                self.assertIs(M._outside("$out", "\n".join("\n".join(s) for s in steps)), False)


class HolesFlagged(Base):
    def test_holes(self):
        for name, lines in {**HOLES, **END_TO_END_ONLY}.items():
            with self.subTest(name):
                self.flagged("\n          ".join(lines), env=ENV_OUT)


class FormsFlagged(Base):
    def test_forms(self):
        for name, form in FORMS.items():
            with self.subTest(name):
                self.flagged(form, env=ENV_OUT)

    def test_known_limits(self):
        for name, form in KNOWN_LIMITS.items():
            with self.subTest(name):
                self.flagged(form, env=ENV_OUT)

    def test_joins(self):
        for name, steps in JOINS.items():
            with self.subTest(name):
                code, out = run([steps_repo(self, steps)])
                self.assertEqual(code, 1, out)
                self.assertNotIn(" 0 finding(s)", out)


class TwinsClean(Base):
    def test_comment_and_escape(self):
        for name, lines in COMMENT_CLEAN.items():
            with self.subTest(name):
                self.clean("\n          ".join(lines))

    def test_twins(self):
        for name, lines in TWINS.items():
            with self.subTest(name):
                self.clean("\n          ".join(lines))


if __name__ == "__main__":
    unittest.main()
