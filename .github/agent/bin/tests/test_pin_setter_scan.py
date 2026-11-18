"""Tests for check-action-pins.py `_outside`: a setter counts only as a whole command of the shell that copies."""
import multiprocessing, time, unittest

from test_pin_setter_quotes import ENV_OUT, M, Base

COPY = 'cp -R evil/. "$out"'

# the setter is followed only by name=value words and redirections, or it follows name=value words: it counts
CLEAN = {
    "assignment_after": "out=$RUNNER_TEMP/x other=1",
    "redirect_after": "out=$RUNNER_TEMP/x >/dev/null",
    "assignment_before": "a=1 out=$RUNNER_TEMP/x",
}
# a command word after the setter, or a pipe before the assignments that lead it: it does not count
FLAGGED = {
    "pipe_then_assignments": "cat|a=1 out=$RUNNER_TEMP/x >/dev/null",
    "redirect_then_command": "out=$RUNNER_TEMP/x >/dev/null true",
}
SLOW = "echo x | " + "a=" * 40 + "!\necho hi\nout=$RUNNER_TEMP/x"


def _call(q, text):
    start = time.monotonic()
    result = M._outside("$out", text)
    q.put((result, time.monotonic() - start))


class ScanUnit(unittest.TestCase):
    def test_clean_forms_count(self):
        for name, form in CLEAN.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", form + "\n" + COPY), True)

    def test_flagged_forms_do_not_count(self):
        for name, form in FLAGGED.items():
            with self.subTest(name):
                self.assertIs(M._outside("$out", form + "\n" + COPY), False)

    def test_many_assignment_words_are_fast(self):
        ctx = multiprocessing.get_context("fork")
        q = ctx.Queue()
        p = ctx.Process(target=_call, args=(q, SLOW))
        p.start()
        p.join(5)
        if p.is_alive():
            p.terminate()
            p.join()
            self.fail("_outside did not return within 5 s")
        _, elapsed = q.get(timeout=1)
        self.assertLess(elapsed, 1.0)


class ScanFlagged(Base):
    def test_flagged_forms(self):
        for name, form in FLAGGED.items():
            with self.subTest(name):
                self.flagged(form, env=ENV_OUT)


class ScanClean(Base):
    def test_clean_forms(self):
        for name, form in CLEAN.items():
            with self.subTest(name):
                self.clean(form)


if __name__ == "__main__":
    unittest.main()
