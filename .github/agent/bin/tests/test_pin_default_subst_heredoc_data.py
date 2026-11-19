"""End-to-end tests of the digest-pin checker: heredoc bodies are data.

Bash opens a process-substitution frame at `<(` inside a quoted "${x:-<( ... )}"
word; a `#` at a word start there is a comment. Rule H: a heredoc body is data,
so
 H1 a `${x:-<(` inside heredoc data starts no frame;
 H2 a quote, `#` or `)}` in heredoc data never changes how later code is read;
 H3 inert triggers (quoted, escaped, commented, in a substitution or in
    heredoc data) start no frame, and a later image is still flagged;
 H4 a real frame in code keeps its comments blanked, and a genuinely
    unclosed frame stays flagged.
Every case below runs an unpinned image, so each must be flagged.
"""
import unittest
from test_pin_default_subst_heredoc import EndToEnd, n1, n1_kind

TRAP = ["cat <<'EOF'", '${x:-<("', "EOF"]
TAIL = ["cat <<'EOF'", ")}", "it's", "EOF"]
DOCKER = 'echo " # "; docker run alpine:latest'
KIND = 'echo " # "; kind create cluster --image alpine:latest'
IMG = ['echo " # "; img=alpine:latest']
RUN = ['docker run "$img"']
KIND_VAR = ['kind create cluster --image "$img"']


class PinDefaultSubstHeredocData(EndToEnd):
    def test_h1_heredoc_data_starts_no_frame(self):
        self.check({
            "docker": TRAP + [DOCKER] + TAIL,
            "kind": TRAP + [KIND] + TAIL,
            "docker var": TRAP + IMG + RUN + TAIL,
            "kind var": TRAP + IMG + KIND_VAR + TAIL,
            "unquoted first heredoc": ["cat <<EOF"] + TRAP[1:] + [DOCKER] + TAIL,
        }, 1)

    def test_h2_heredoc_data_does_not_shift_quotes(self):
        self.check({"quote in data then frame": [
            "cat <<'EOF'", '"', "EOF", "x=a", 'echo "${x:-<(echo # } "', ')}"',
            'echo " # "; img=alpine:latest', 'docker run "$img"']}, 1)

    def test_h3_inert_triggers(self):
        after = ["cat <<EOF", "# $(docker run alpine:latest)", "EOF"]
        triggers = {
            "single quoted": ["echo '${x:-<(echo hi)}'"],
            "escaped": ['echo "\\${x:-<(echo hi)}"'],
            "comment": ["# ${x:-<(echo hi)}"],
            "backtick": ["echo `printf %s '${x:-<(echo hi)}'`"],
            "quoted heredoc": ["cat <<'EOF'", "${x:-<(echo hi)}", "EOF"],
        }
        self.check({k: v + after for k, v in triggers.items()}, 1)

    def test_h4_real_frames_keep_blanking(self):
        self.check({
            "docker": n1(),
            "kind": n1_kind(),
            "text form": ["x=a", 'echo "${x:-text<(echo # } "', ')}"'] +
                         IMG + RUN,
            "unclosed frame": ["x=a", 'echo "${x:-<(echo # hi)}"',
                               "img=alpine:latest", 'docker run "$img"'],
        }, 1)


if __name__ == "__main__":
    unittest.main()
