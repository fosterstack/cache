import shutil, unittest
from test_pin_setter_quotes import repo, run, GATE_PROGRAMS
from test_pin_read_joins import SAFE, BUILD, hand_repo

TAIL_RUN = ['echo " # "; img=alpine:latest', 'docker run "$img"']
TAIL_KIND = ['echo " # "; img=alpine:latest', 'kind create cluster --image "$img"']


def sh_repo(case, lines, shell):
    text = "".join("          " + ln + "\n" for ln in lines)
    wf = ("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: " + shell + "\n        run: |\n" + text)
    d = repo({".github/workflows/w.yml": wf, "Dockerfile": "FROM scratch\n", **GATE_PROGRAMS})
    case.addCleanup(shutil.rmtree, d)
    return d


class Base(unittest.TestCase):
    def end_to_end(self, lines, code, shell=None):
        d = sh_repo(self, lines, shell) if shell else hand_repo(self, lines)
        out = run([d])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])


class Flagged(Base):
    def test_flagged(self):
        scripts = {
            "A": ["x=a", 'echo "${x/a/<(case x in esac)}"'],
            "B": ["x=a", 'echo "${x/a/<(case x in x) :;; esac>/dev/null)}"'],
            "C": ["x=a", 'echo "${x/a/<(a=(case x in x))}"'],
            "C2": ["x=a", 'echo "${x/a/<(a+=(case x in x))}"'],
        }
        for name, head in scripts.items():
            for tname, tail in (("run", TAIL_RUN), ("kind", TAIL_KIND)):
                with self.subTest(case=name, tail=tname):
                    self.end_to_end([*head, *tail], 1)

    def test_flagged_D_sh(self):
        lines = ['echo "$(echo $\\', "'\\'' # ')\"; img=alpine:latest", 'docker run "$img"']
        self.end_to_end(lines, 1, shell="sh")

    def test_flagged_D_sh_kind(self):
        lines = ['echo "$(echo $\\', "'\\'' # ')\"; img=alpine:latest", 'kind create cluster --image "$img"']
        self.end_to_end(lines, 1, shell="sh")


class Clean(Base):
    def test_clean(self):
        mids = [
            '(case x in esac)',
            '(case x in x) :;; esac>/dev/null)',
            '(a=(case x in x))',
            '(a+=(case x in x))',
            '(echo case x in x)',
            '(echo case in)',
            '(echo case/foo in)',
            '(case=x; echo in)',
            '(case x in x) echo hi;& y) echo hi;; esac)',
        ]
        for mid in mids:
            with self.subTest(mid=mid):
                self.end_to_end([SAFE, mid, *BUILD], 0)


class OppositeFailure(Base):
    def test_still_tracked(self):
        bodies = [
            'echo "${x/a/<(case x in x) :;; esac | cat)}"',
            'echo "${x/a/<(case x in x) :;; esac & )}"',
            'echo "${x/a/<(case x in x) :;; esac; echo hi)}"',
            'echo "${x/a/<(case x in x) :;; esac)}"',
            'echo "${x/a/<(case x in x) :;; esac )}"',
            'echo "${x/a/<(if true; then a=1; (case x in x) :;; esac); fi)}"',
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.end_to_end(["x=a", body, *TAIL_RUN], 1)


if __name__ == "__main__":
    unittest.main()
