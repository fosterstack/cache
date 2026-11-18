"""End-to-end tests of the digest-pin checker on quoted "${x:-<( ... )}" words.

Bash opens a process-substitution frame at `<(` inside the quoted word; a `#`
at a word start there is a comment, so the `}` after it does not close the brace.
The checker must read this as bash does, and must not let heredoc data (a `#`
line, a `"`, an `'`, or a `${x:-<(}`) change that reading:
 R1 an unquoted-delimiter heredoc body runs `$( )`, so its image is flagged;
 R2 a `"` in quoted-delimiter heredoc data does not make a later `#` a comment;
 R3 text outside the frame cannot turn the fix off;
 R4 the genuine syntax error stays flagged;
 R5 clean scripts exit 0.
The flagged cases fail on the previous head.
"""
import unittest
from test_pin_read_joins import SAFE, BUILD, hand_repo, run


class EndToEnd(unittest.TestCase):
    def end_to_end(self, lines, code, env=""):
        out = run([hand_repo(self, lines, env)])
        self.assertEqual(out[0], code, out[1])
        self.assertEqual(" 0 finding(s)" in out[1], code == 0, out[1])

    def check(self, cases, code):
        for name, lines in cases.items():
            with self.subTest(name):
                self.end_to_end(lines, code)


def n1(op=":-"):
    return ["x=a", 'echo "${x%s<(echo # } "' % op, ')}"',
            'echo " # "; img=alpine:latest', 'docker run "$img"']


def n1_kind(op=":-"):
    return n1(op)[:-1] + ['kind create cluster --image "$img"']


HEREDOC_APOS = ["cat <<EOF", "it's", "EOF"]
HEREDOC_BRACE = ["cat <<'EOF'", "${x:-<(}", "EOF"]
QUOTED = 'echo "${x:-<(echo hi)}"'


class PinDefaultSubstHeredoc(EndToEnd):
    def test_r1_unquoted_heredoc_substitution_seen(self):
        def body(line, cmd="docker run alpine:latest"):
            return ["x=a", line, "cat <<EOF", "# $(%s)" % cmd, "EOF"]
        mid = "echo hi # $(docker run alpine:latest)"
        self.check({
            "docker": body(QUOTED),
            "kind": body(QUOTED, "kind create cluster --image alpine:latest"),
            "mid-line": ["x=a", QUOTED, "cat <<EOF", mid, "EOF"],
            "comment trigger": ["x=a", "# ${x:-<(y)}", "cat <<EOF",
                                "# $(docker run alpine:latest)", "EOF"],
        }, 1)

    def test_r2_quote_in_heredoc_data_is_not_a_comment(self):
        head = [QUOTED, "cat <<'EOF'", '"', "EOF"]
        self.check({
            "docker run": head + ['echo " # "; docker run alpine:latest'],
            "docker var": head + ['echo " # "; img=alpine:latest',
                                  'docker run "$img"'],
            "kind var": head + ['echo " # "; img=alpine:latest',
                                'kind create cluster --image "$img"'],
        }, 1)

    def test_r3_outside_text_cannot_turn_fix_off(self):
        self.check({
            "docker trailing": n1() + HEREDOC_APOS,
            "kind trailing": n1_kind() + HEREDOC_APOS,
            "docker leading": HEREDOC_BRACE + n1(),
            "kind leading": HEREDOC_BRACE + n1_kind(),
        }, 1)

    def test_operators(self):
        self.check({op: n1(op) for op in (":?", "?")}, 1)
        self.check({op + " kind": n1_kind(op) for op in (":?", "?")}, 1)

    def test_r4_genuine_syntax_error_flagged(self):
        self.check({"syntax error": ["x=a", 'echo "${x:-<(echo # hi)}"',
                                     "img=alpine:latest",
                                     'docker run "$img"']}, 1)

    def test_r5_clean_scripts(self):
        self.check({
            "safe": [SAFE, QUOTED, "cat <<EOF", "# harmless", "EOF"] + BUILD,
            "quoted delimiter": [SAFE, QUOTED, "cat <<'EOF'", '"', "EOF",
                                 'echo " # "'] + BUILD,
        }, 0)


if __name__ == "__main__":
    unittest.main()
