import unittest
from test_pin_setter_quotes import repo, run, GATE_PROGRAMS
from test_pin_read_joins import SAFE, BUILD, hand_repo

TAIL_RUN = ['echo " # "; img=alpine:latest', 'docker run "$img"']
TAIL_KIND = ['echo " # "; img=alpine:latest', 'kind create cluster --image "$img"']
TAILS = {"run": TAIL_RUN, "kind": TAIL_KIND}
OPENERS = ['a=(', 'a+=(', 'a=( # array']


class Base(unittest.TestCase):
    def end_to_end(self, lines, code, shell=None):
        d = hand_repo(self, lines)
        out = run([d])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    def flagged_both(self, build):
        for name, tail in TAILS.items():
            with self.subTest(tail=name):
                self.end_to_end(build(tail), 1)


class Row16Flagged(Base):
    def test_case_body_comment_then_esac(self):
        self.flagged_both(lambda t: [
            'x=a', 'echo "${x/a/<(case x in x) : # "',
            'echo in esac;; y) : # } "', ';; esac)}"', *t])

    def test_case_body_esac_image(self):
        self.flagged_both(lambda t: [
            'x=a', 'echo "${x/a/<(case x in x) echo in esac;; y) echo # } "',
            ';; esac)}"', *t])


class Row17Flagged(Base):
    def test_array_then_case(self):
        for op in OPENERS:
            with self.subTest(opener=op):
                self.flagged_both(lambda t: [
                    'x=a', 'echo "${x/a/<(' + op, 'case x in x))}"', *t])


class Row17Clean(Base):
    def test_array_then_case_clean(self):
        for op in OPENERS:
            with self.subTest(opener=op):
                self.end_to_end([SAFE, '(' + op, 'case x in x))', *BUILD], 0)


class KeepClean(Base):
    def test_keep_clean(self):
        for mid in ['(case x in esac)', '(case x in x) :;; esac>/dev/null)',
                    '(a=(case x in x))', '(a+=(case x in x))',
                    '(echo case x in x)', '(echo case in)',
                    '(echo case/foo in)', '(case=x; echo in)',
                    '(case x in x) echo hi;& y) echo hi;; esac)']:
            with self.subTest(mid=mid):
                self.end_to_end([SAFE, mid, *BUILD], 0)


class KeepFlagged(Base):
    def test_keep_flagged(self):
        cases = [
            ['x=a', 'echo "${x/a/<(case x in esac)}"'],
            ['x=a', 'echo "${x/a/<(case x in x) :;; esac>/dev/null)}"'],
            ['x=a', 'echo "${x/a/<(case x in x) :;; esac | cat)}"'],
            ['x=a', 'echo "${x/a/<(if true; then a=1; (case x in x) :;; esac); fi)}"'],
            ['x=a', 'echo "${x/a/<(case x in # hi', 'esac)}"'],
            ['x=a', 'echo "${x/a/<(case x in x) case y in esac;; esac)}"'],
            ['x=a', 'echo "${x/a/<(a=($(case x in x) :;; esac)))}"'],
        ]
        for i, head in enumerate(cases):
            with self.subTest(case=i):
                self.end_to_end([*head, *TAIL_RUN], 1)


if __name__ == "__main__":
    unittest.main()
