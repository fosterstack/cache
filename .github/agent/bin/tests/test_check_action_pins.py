"""Coverage + behaviour tests for check-action-pins.py (register row 78; REQ-AUD-18 AC2 measures it).

The fixture cases in .github/agent/tests/check-action-pins-test.sh prove the rules end to end; these
reach the branches a fixture workflow cannot: the tag verifier (GitHub's API is a patched
urllib.request.urlopen — no network), a submodule in a git tree, a missing PyYAML, and the
command-line errors.
"""
import contextlib, importlib.util, io, json, os, re, runpy, shutil, subprocess, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "check-action-pins.py")
# the vendored pure-Python PyYAML as `yaml` (the CI coverage job installs no PyYAML of its own)
_PYLIB = tempfile.mkdtemp()
os.symlink(os.path.join(BIN, "..", "fixtures", "testlib", "pyyaml"), os.path.join(_PYLIB, "yaml"))
sys.path.insert(0, _PYLIB)
sys.modules.pop("yaml", None)
_spec = importlib.util.spec_from_file_location("check_action_pins_cov", SRC)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
OTHER = "1111111111111111111111111111111111111111"
TAGOBJ = "2222222222222222222222222222222222222222"
HEAD = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"


GATE = os.path.join(BIN, "..", "..", "workflows", "agent-review-gate.yml")


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


class Resp:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return self.body


def manifest(slug, sha, text, name="action.yml", sub=""):
    """A contents-API answer for <slug>/<sub>/<name> at <sha>."""
    import base64
    path = f"{sub}/{name}" if sub else name
    return {f"/repos/{slug}/contents/{path}?ref={sha}": {"content": base64.b64encode(text.encode()).decode()}}


NODE = "runs:\n  using: node24\n  main: index.js\n"
CHECKOUT = manifest("actions/checkout", SHA, NODE)


def api(table):
    """urlopen stand-in: answers from {url-suffix: body}; anything else raises (like a 404)."""
    seen = []

    def urlopen(req, timeout=None):
        url = req.full_url
        seen.append(url)
        for suffix, body in table.items():
            if url.endswith(suffix):
                if isinstance(body, Exception):
                    raise body
                return Resp(body)
        raise urllib_error().HTTPError(url, 404, "Not Found", {}, None)
    return urlopen, seen


class VerifyTags(unittest.TestCase):
    PIN = [("w.yml.jobs.j.steps[0].uses", "actions/checkout", SHA, "v7.0.1")]

    def test_no_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(M.verify_pins(self.PIN), ["--verify-tags: GH_TOKEN is not set"])

    def test_lightweight_tag_matches(self):
        f, seen = api({"/repos/actions/checkout/git/ref/tags/v7.0.1":
                       {"ref": "refs/tags/v7.0.1", "object": {"type": "commit", "sha": SHA}}, **CHECKOUT})
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), mock.patch.object(M.urllib.request, "urlopen", f):
            self.assertEqual(M.verify_pins(self.PIN * 2), [])
        self.assertEqual(len(seen), 1)  # one lookup per (repo, tag)

    def test_annotated_tag_is_followed_to_its_commit(self):
        f, _ = api({"/git/ref/tags/v7.0.1": {"ref": "refs/tags/v7.0.1", "object": {"type": "tag", "sha": TAGOBJ}},
                    f"/git/tags/{TAGOBJ}": {"object": {"type": "commit", "sha": SHA}}, **CHECKOUT})
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), mock.patch.object(M.urllib.request, "urlopen", f):
            self.assertEqual(M.verify_pins(self.PIN), [])

    def test_tag_on_another_commit_is_a_finding(self):
        f, _ = api({"/git/ref/tags/v7.0.1": {"ref": "refs/tags/v7.0.1", "object": {"type": "commit", "sha": OTHER}},
                    **CHECKOUT})
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "t"}, clear=True), \
                mock.patch.object(M.urllib.request, "urlopen", f):
            (msg,) = M.verify_pins(self.PIN)
        self.assertIn(f"v7.0.1 is {OTHER}, not the pinned {SHA}", msg)

    def test_api_answering_for_another_ref_fails_closed(self):
        f, _ = api({"/git/ref/tags/v7.0.1": {"ref": "refs/tags/v7.0.10", "object": {"type": "commit", "sha": SHA}},
                    **CHECKOUT})
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), mock.patch.object(M.urllib.request, "urlopen", f):
            (msg,) = M.verify_pins(self.PIN)
        self.assertIn("unresolvable (LookupError)", msg)

    def test_unresolvable_tag_fails_closed_and_the_tag_is_encoded(self):
        f, seen = api(CHECKOUT)
        pin = [("w", "actions/checkout", SHA, "v7.0.1+x")]
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), mock.patch.object(M.urllib.request, "urlopen", f):
            (msg,) = M.verify_pins(pin)
        self.assertIn("unresolvable (HTTPError)", msg)
        self.assertTrue(seen[0].endswith("/git/ref/tags/v7.0.1%2Bx"), seen)


class Main(unittest.TestCase):
    def test_verify_tags_through_main(self):
        d = repo({".github/workflows/w.yml": HEAD + f"    steps:\n      - uses: actions/checkout@{SHA} # v7.0.1\n",
                  "README.md": "not read\n", ".git/x.yml": "uses: [\n",
                  ".github/agent/bin/auditor-review-gate.py": "", ".github/agent/bin/check-action-pins.py": "",
                  "bin/check-file-allowlist.sh": "", ".github/agent/tests/pin-wiring-test.sh": ""})   # the gate's committed programs
        table = {"/repos/actions/checkout/git/ref/tags/v7.0.1":
                 {"ref": "refs/tags/v7.0.1", "object": {"type": "commit", "sha": SHA}}}
        with open(GATE) as fh:  # the gate's own pins answer truthfully too
            for slug, sha, tag in re.findall(r"uses: ([\w.-]+/[\w.-]+)@([0-9a-f]{40}) # (v\S+)", fh.read()):
                table[f"/repos/{slug}/git/ref/tags/{tag}"] = {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": sha}}
        f, _ = api(table)
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), mock.patch.object(urllib_request(), "urlopen", f):
            code, out = run(["--verify-tags", d])
        self.assertEqual(code, 0, out)
        self.assertIn("pinned action(s) verified against their tags, 0 finding(s)", out)

    def test_nothing_to_check(self):
        code, _ = run([repo({"README.md": "x\n"}, gate=False)])
        self.assertEqual(code, "check-action-pins: no .github/workflows/ — nothing checked")

    def test_git_usage(self):
        code, _ = run(["--git"])
        self.assertIn("usage:", code)

    def test_missing_pyyaml(self):
        with mock.patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaises(SystemExit) as e:
                runpy.run_path(SRC, run_name="not_main")
        self.assertEqual(e.exception.code, "check-action-pins: PyYAML is required")

    def test_shapes_a_fixture_workflow_rarely_has(self):
        d = repo({".github/workflows/w.yml":
                  "env:\n  image: alpine:3.20\n" + HEAD +
                  "    container: [alpine]\n"
                  "    steps:\n      - ? [a]\n        : b\n"
                  "  k:\n    runs-on: x\n    container:\n      ports: ['1']\n    steps:\n      - run: true\n"})
        code, out = run([d])
        self.assertEqual(code, 1)
        self.assertIn(".jobs.j.container: image is not a plain string", out)
        self.assertIn(".jobs.j.steps[0]: a mapping key that is not a plain string", out)
        self.assertIn(".jobs.k.container: container mapping without an image", out)
        self.assertNotIn(".env.image", out)  # a workflow-level env variable is data

    def test_git_tree_submodule_is_refused(self):
        d = repo({".github/workflows/w.yml": HEAD + "    steps:\n      - run: true\n"})
        g = ["git", "-C", d]
        subprocess.run(g + ["init", "-q"], check=True)
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["update-index", "--add", "--cacheinfo", f"160000,{SHA},.github/workflows/sub"], check=True)
        subprocess.run(g + ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "t"], check=True)
        code, out = run(["--git", "HEAD"], cwd=d)
        self.assertEqual(code, 1)
        self.assertIn(".github/workflows/sub: a submodule where a workflow or action file is read", out)


def urllib_error():
    import urllib.error
    return urllib.error


def urllib_request():
    import urllib.request
    return urllib.request



class RunScriptImages(unittest.TestCase):              # handoff 0068: literal images a run: script names
    def test_double_dash_ends_the_options(self):
        self.assertEqual(M.script_images("docker run --rm -- alpine true"), [("use", "docker run", "alpine")])
        self.assertEqual([e[0] for e in M.script_images("docker run --rm --")], ["finding"])      # no operand: refused (Codex #164 r23, B5)

    def test_a_command_without_an_image(self):
        self.assertEqual([e[0] for e in M.script_images("docker run --rm")], ["finding"])         # no operand: stdin or a wrapper, refused (Codex #164 r23, B5)
        self.assertEqual(M.script_images("docker"), [])
        self.assertEqual(M.script_images("docker --tls"), [])
        bad = []
        M.check_runs("j", [("w", "docker run --rm", None)], bad)
        self.assertEqual(len(bad), 1)
        self.assertIn("has no image operand", bad[0])

    def test_tag_equals_form_makes_a_local_name(self):
        ev = M.script_images("docker build --tag=img1 . && docker buildx build -t img2 .")
        self.assertEqual([e[0] for e in ev], ["build", "build"])           # a name this job built is never trusted (owner, Oct 3): no "local" events

    def test_a_document_that_is_not_a_mapping_has_no_scripts(self):
        self.assertEqual(M.run_scripts(M.yaml.compose("- a\n- b\n", Loader=M.StrLoader)), {})

    def test_build_without_a_tree_cannot_be_checked(self):           # Sonnet #164 B6: fails closed
        bad = []
        M.check_runs("j", [("w", "docker build .", None)], bad)
        self.assertIn("not a file in the repository", bad[0])

    def test_dockerfile_forms(self):
        self.assertEqual(M.check_dockerfile("FROM --platform=x a@sha256:" + "0" * 64 + " AS b\nFROM b\nFROM scratch\nRUN x\nFROM\n"), [])
        self.assertEqual(M.check_dockerfile("FROM alpine:3\n"), ["alpine:3"])
        self.assertEqual(M.check_dockerfile("FROM --platform=x\n"), [])

    def test_build_option_forms(self):
        self.assertEqual(M._build(["--file=D", "--platform", "x", "--push", "ctx"]), ("D", "ctx", set(), [], [], None))
        self.assertEqual(M._build(["-f"]), ("-", ".", set(), [], [], None))
        self.assertEqual(M._build(["--build-context=a=./x", "."])[3], ["./x"])

    def test_short_option_forms(self):
        self.assertEqual(M._options(["-dit", "img"], M.RUN_VAL, M.RUN_BOOL), (1, None))
        self.assertEqual(M._options(["-p", "1:2", "img"], M.RUN_VAL, M.RUN_BOOL), (2, None))
        self.assertEqual(M._options(["-p1:2", "img"], M.RUN_VAL, M.RUN_BOOL), (1, None))
        self.assertEqual(M._options(["--rm"], M.RUN_VAL, M.RUN_BOOL), (1, None))


class RunScriptInstalls(unittest.TestCase):             # handoff 0070: package installs a run: script makes
    def test_attached_requirement_forms_count(self):
        self.assertEqual(M.script_installs("pip install --require-hashes --requirement=r.txt"), [])
        self.assertEqual(M.script_installs("pip install --require-hashes -rr.txt"), [])

    def test_a_bare_yarn_or_pnpm_installs(self):
        self.assertEqual(M.script_installs("yarn"),          # Codex #164 adversarial r1 C04: any use is refused
                         [("yarn", "a package manager this repository does not use; any invocation is refused")])
        self.assertEqual([c for c, _ in M.script_installs("pnpm")], ["pnpm"])

    def test_redirections_are_not_packages(self):
        self.assertEqual(M.script_installs("pip install --require-hashes -r r.txt 2>/dev/null > log"), [])
        self.assertEqual(M.script_installs("pip install --require-hashes -r r.txt > log"), [])


class RunScriptRound2(unittest.TestCase):               # Sonnet #164 r2: forwarding, variable subcommands
    def test_a_variable_pip_subcommand(self):
        self.assertEqual([w for _, w in M.script_installs('pip "$sub" requests')],
                         ["its subcommand is a variable; the packages cannot be seen"])

    def test_other_python_modules_are_not_installs(self):     # r3: only installers and build frontends are flagged
        self.assertEqual(M.script_installs("python3 -m venv /tmp/v && python3 -m json.tool f"), [])

    def test_the_non_posix_catch_all_knows_every_tool(self):          # Sonnet #164 r7, NEW-8: no drift
        for t in M.TOOLS | M.UNREAD_CONTAINER | M.UNREAD_PY | M.OS_PKG:
            bad = []
            M.check_runs("j", [("w", "%s run x" % t, "pwsh")], bad)
            self.assertTrue(bad, t)

    def test_a_workflow_without_jobs_has_no_runners_to_judge(self):   # advisor 0080: ubuntu-only scope
        bad = []
        M.check_runners("w", M.yaml.compose("on: push\n", Loader=M.StrLoader), bad)
        self.assertEqual(bad, [])


class ReaderBranches(unittest.TestCase):
    """Every branch of the shell readers has a case of its own (the 100% gate, REQ-AUD-18 AC2): a quote, an escape, an array, a
    redirection or an option spelling that no workflow of this repository uses must still be read the way bash reads it."""
    def test_split_commands_ansi_c_quote_and_nested_array(self):
        self.assertEqual(M._split_commands("echo $'a\\'b' ; echo $'c' && d"), ["echo $'a\\'b' ", " echo $'c' ", " d"])
        self.assertEqual(M._split_commands("A=(a (b) c); d"), ["A=(a (b) c)", " d"])

    def test_substitution_with_an_escaped_paren_and_the_depth_limits(self):
        self.assertEqual(M._cut_substitutions("x $(echo a\\)b) y")[1], ["echo a\\)b"])
        self.assertEqual(M._commands("echo $(x y)", 6), [["__too_deep__", "command substitutions"]])
        self.assertEqual(M._commands("eval x y", 4), [["__too_deep__", "eval"]])
        self.assertEqual(M._all_texts("echo hi", 6), ["echo hi"])
        self.assertEqual(M._all_texts("echo 'unterminated"), ["echo 'unterminated"])
        self.assertEqual(M._all_texts('eval "touch x"'), ['eval "touch x"', "touch x"])

    def test_shell_that_reads_stdin_through_redirections(self):
        for toks in (["bash", ">", "out", "-s"], ["bash", "2>/dev/null", "-s"], ["bash", "--", "-s"], ["bash", "<<<", "x", "-"],
                     ["bash", ">&2", "-"]):
            self.assertEqual(M._stdin_shell(toks), "bash", toks)

    def test_download_detector_spellings(self):
        self.assertEqual(M._downloaded_commands("curl --output=/tmp/x https://e/x\ncp /tmp/x /usr/local/bin/tool"), {"tool", "x"})
        self.assertEqual(M._downloaded_commands("curl -o /tmp/x https://e/x\ninstall --target-directory=/usr/local/bin /tmp/x"), {"x"})

    def test_build_cache_from_equals_form_and_python_option_forms(self):
        self.assertEqual(M._build(["--cache-from=type=registry,ref=a", "."])[4], ["type=registry,ref=a"])
        self.assertEqual(M._python_run(["--check-hash-based-pycs", "always", "x.py"]), ("script", "x.py", []))
        self.assertEqual(M._python_run(["-W", "ignore", "x.py"]), ("script", "x.py", []))
        self.assertEqual(M._python_run(["-Wignore", "x.py"]), ("script", "x.py", []))
        self.assertEqual(M._python_run(["-V"]), ("none", None, []))

    def test_package_installs_with_unknown_options_and_python_frontends(self):
        self.assertEqual(M.script_installs("pip --weird-flag install x==1")[0][1], "a global option this check does not know (--weird-flag)")
        self.assertEqual(M.script_installs("python3 -m poetry install")[0][0], "python -m poetry")
        self.assertEqual(M.script_installs("python3 -m json.tool x"), [])
        self.assertEqual(M.script_installs("python3 setup.py install")[0][0], "python setup.py")

    def test_image_commands_with_unknown_options_and_bare_subcommands(self):
        self.assertIn("names no ref", M.script_images("docker buildx build --cache-from type=registry .")[1][1])
        self.assertEqual(M.script_images("docker buildx build --cache-from type=local,src=x ."), [("build", None, ".", [])])
        for cmdline, text in (("skopeo copy --weird docker://a b", "has an option this check does not know"),
                              ("skopeo inspect --weird docker://a", "has an option this check does not know"),
                              ("crane index", "is not a subcommand this check reads"),
                              ("crane index frob x", "is not a subcommand this check reads"),
                              ("crane index append --weird -t x", "has an option this check does not know"),
                              ("crane copy --weird a b", "has an option this check does not know")):
            ev = M.script_images(cmdline)
            self.assertEqual(ev[0][0], "finding", cmdline)
            self.assertIn(text, ev[0][1])

    def test_scout_attestation_verb_is_folded_into_the_subcommand(self):
        self.assertEqual(M.script_images("docker scout attestation add --file x img"), [("use", "docker scout attestation add", "img")])

    def test_operands_skip_redirections_and_report_an_unknown_option(self):
        self.assertEqual(M._operands(["a", ">", "f", "b"], set(), set()), (["a", "b"], None))
        self.assertEqual(M._operands(["a", ">f", "b"], set(), set()), (["a", "b"], None))
        self.assertEqual(M._operands(["--zz", "a"], set(), set()), ([], "--zz"))

    def test_mask_reports_a_newline_inside_a_quote(self):
        info = {}
        M._mask_shell("echo 'a\nb'", info)
        self.assertTrue(info["nl_in_quote"])

    def test_outside_destinations(self):
        self.assertFalse(M._outside("/home/runner/work/x", ""))
        self.assertTrue(M._outside("$HOME/.docker/x", ""))
        self.assertTrue(M._outside("$d/x", "d=$RUNNER_TEMP/y\n"))
        self.assertFalse(M._outside("$d", "d=/tmp/y; d=/home/runner/work/z"))

    def test_redirect_targets_through_escapes_quotes_and_fd_duplication(self):
        self.assertEqual(M._redirect_targets("echo x >&2 > out"), ["out"])
        self.assertEqual(M._redirect_targets("echo \\> x > out"), ["out"])
        self.assertEqual(M._redirect_targets("echo '>' \"a\\\"b\" > out"), ["out"])

    def test_commands_that_fill_a_directory(self):
        for toks in (["tar", "-xf", "a.tgz", "-C", "safe"], ["unzip", "a.zip", "-d", "safe"], ["unzip", "a.zip"], ["git", "clone", "u", "safe"],
                     ["git", "clone", "u"], ["git", "checkout", "x"], ["patch", "-p1"]):
            self.assertTrue(M._fills_dir(toks, "safe/Dockerfile"), toks)
        self.assertFalse(M._fills_dir(["ls"], "safe/Dockerfile"))

    def test_dockerfile_continuation_at_the_end_and_a_syntax_argument(self):
        self.assertEqual(M.check_dockerfile("FROM a@sha256:" + "0" * 64 + "\nRUN x \\"), [])
        self.assertEqual(M.check_dockerfile("ARG BUILDKIT_SYNTAX=docker/dockerfile:1\nFROM scratch\n"), ["docker/dockerfile:1"])

    def test_daemon_config_set_by_printf(self):
        self.assertEqual(M.daemon_redirects("printf -v DOCKER_CONFIG %s x"), ["DOCKER_CONFIG"])

    def test_heredoc_markers_inside_backticks(self):
        marks = M._heredoc_marks(["echo `date`", "cat <<EOF", "x", "EOF"])
        self.assertEqual([len(m) for m in marks], [0, 1, 0, 0])

    def test_writes_through_a_substitution(self):
        self.assertTrue(M._writes("x=$(printf a > f)", "f"))

    def test_python_without_a_script_or_module_installs_nothing(self):
        self.assertEqual(M.script_installs("python3 -V"), [])

    def test_backticks_inside_double_quotes_and_a_downloaded_program(self):
        marks = M._heredoc_marks(['echo "`date`"', "cat <<EOF", "x", "EOF"])
        self.assertEqual([len(m) for m in marks], [0, 1, 0, 0])
        self.assertEqual(M._made_executable("curl -o /usr/local/bin/t https://e/t", "/usr/local/bin/t"), "downloads")

    def test_download_long_output_and_unknown_short_build_option(self):
        self.assertEqual(M._downloaded_commands("curl --output /usr/local/bin/x https://e/x"), {"x"})
        self.assertEqual(M._build(["-Z", "."])[5], "-Z")
        self.assertEqual(M._build(["--frob", "."])[5], "--frob")
        self.assertEqual(M._build(["-qf", "d/Dockerfile", "ctx"]), ("d/Dockerfile", "ctx", set(), [], [], None))


class LiteralRunnerMatrix(unittest.TestCase):
    """REQ-REL-005-AC2 (advisor-approved read-back Oct 9, pin matrix): a job whose runs-on is the single expression
    ${{ matrix.<key> }}, with a strategy.matrix of that one key holding only the two literal GitHub-hosted labels the
    Build needs, is judged under bash; every other form is a runs-on finding and never a silent choice of shell.
    Each case builds a throwaway tree that the case removes again. Every tree commits plain, pin-clean stub scripts for
    the commands the fixtures call (the checker follows `bash bin/x.sh` into the file), so the runs-on rule is the only
    thing that can turn an accepted case."""

    STUB = "#!/usr/bin/env bash\nset -euo pipefail\n:\n"
    FILES = {".github/agent/bin/auditor-review-gate.py": "", ".github/agent/bin/check-action-pins.py": "",
             "bin/check-file-allowlist.sh": "", ".github/agent/tests/pin-wiring-test.sh": "",   # the gate's committed programs
             **dict.fromkeys(["bin/build.sh", "bin/witnessed.sh", "bin/build-stage-apk.sh", "bin/build-stage-rebuild-apk.sh",
                              "bin/install-scanner.sh"], STUB)}
    DIGEST = "sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
    CHECKOUT = f"      - uses: actions/checkout@{SHA} # v7.0.1\n"
    BUILD = "      - run: bash bin/build.sh\n"
    MATRIX = "    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n"
    OK_HEAD = "    runs-on: ${{ matrix.runner }}\n" + MATRIX
    # the two real jobs, `apk` in full, copied verbatim from the PR 2 branch (origin/pipeline-chain-build-rebuild @ 2942097)
    REAL_BUILD_APK = """  apk:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
    permissions:
      contents: read
      checks: read
      statuses: read
      pull-requests: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
          fetch-tags: true
      - name: install Witness (pinned by checksum)
        run: ./bin/install-scanner.sh witness
      - name: apk under Witness
        env:
          GH_TOKEN: ${{ github.token }}
        run: bash bin/witnessed.sh apk bin/build-stage-apk.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: apk-${{ matrix.runner }}
          path: out
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: witness-apk-${{ matrix.runner }}
          path: witness-apk
"""
    REAL_REBUILD_APK = """  apk:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
          fetch-tags: true
      - name: install Witness (pinned by checksum)
        run: ./bin/install-scanner.sh witness
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: witness-build
          path: witness-build
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: digests
          path: build-in
      - name: rapk under Witness
        run: bash bin/witnessed.sh rapk bin/build-stage-rebuild-apk.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: rapk-${{ matrix.runner }}
          path: out
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: witness-rapk-${{ matrix.runner }}
          path: witness-rapk
"""

    def findings(self, workflow, extra=None):
        d = repo({".github/workflows/w.yml": workflow, **self.FILES, **(extra or {})})
        self.addCleanup(shutil.rmtree, d)
        return run([d])

    def job(self, head, steps=None):
        return "on: push\njobs:\n  apk:\n" + head + "    steps:\n" + (steps or self.CHECKOUT + self.BUILD)

    def accepted(self, head, steps=None):
        code, out = self.findings(self.job(head, steps))
        self.assertEqual(code, 0, out)
        self.assertIn("0 finding(s)", out)
        self.assertNotIn("pwsh", out)

    def refused(self, head, steps=None):
        code, out = self.findings(self.job(head, steps))
        self.assertNotEqual(code, 0, out)
        runner_lines = [l for l in out.splitlines() if ".runs-on: " in l]
        self.assertEqual(len(runner_lines), 1, "the refusal must name the runner, once: " + out)

    def judged(self, head, steps, finding):
        """The job's runner is accepted; its steps are still judged, each by its own rule: its own finding, no runs-on one."""
        code, out = self.findings(self.job(head, steps))
        self.assertNotEqual(code, 0, out)
        self.assertRegex(out, finding)
        self.assertNotIn("runs-on", out)

    # ---- the forms that pass
    def test_the_real_build_job(self):
        code, out = self.findings("on: push\njobs:\n" + self.REAL_BUILD_APK)
        self.assertEqual(code, 0, out)
        self.assertIn("0 finding(s)", out)

    def test_the_real_rebuild_job(self):
        code, out = self.findings("on: push\njobs:\n" + self.REAL_REBUILD_APK)
        self.assertEqual(code, 0, out)
        self.assertIn("0 finding(s)", out)

    def test_one_label(self):
        self.accepted("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n")

    def test_the_arm_label_alone(self):
        self.accepted("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04-arm]\n")

    def test_a_block_list(self):
        self.accepted("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner:\n          - ubuntu-24.04\n          - ubuntu-24.04-arm\n")

    def test_fail_fast_is_a_literal_true_or_false(self):
        for v in ("true", "false"):
            with self.subTest(v):
                self.accepted(f"    runs-on: ${{{{ matrix.runner }}}}\n    strategy:\n      fail-fast: {v}\n      matrix:\n        runner: [ubuntu-24.04-arm]\n")

    def test_another_key_name(self):
        self.accepted("    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n        os: [ubuntu-24.04, ubuntu-24.04-arm]\n")

    def test_a_clean_docker_step_is_judged_as_bash(self):
        self.accepted(self.OK_HEAD, self.CHECKOUT + f"      - run: docker run alpine@{self.DIGEST} true\n")

    # ---- the steps of an accepted job are still judged, under bash, each by its own rule
    def test_steps_are_judged_unpinned_uses(self):
        self.judged(self.OK_HEAD, "      - uses: actions/checkout@v4\n" + self.BUILD, r"not a full commit digest")

    def test_steps_are_judged_container(self):
        self.judged(self.OK_HEAD + "    container: alpine:3.20\n", self.CHECKOUT + self.BUILD, r"container: image not pinned by digest")

    def test_steps_are_judged_services(self):
        self.judged(self.OK_HEAD + "    services:\n      db:\n        image: postgres:16\n", self.CHECKOUT + self.BUILD,
                    r"services\.db\.image: image not pinned")

    def test_steps_are_judged_step_pwsh(self):
        self.judged(self.OK_HEAD, self.CHECKOUT + "      - shell: pwsh\n        run: bash bin/build.sh\n", r"a `pwsh` step")

    def test_steps_are_judged_job_default_pwsh(self):
        self.judged(self.OK_HEAD + "    defaults:\n      run:\n        shell: pwsh\n", self.CHECKOUT + self.BUILD, r"a `pwsh` step")

    def test_steps_are_judged_a_piped_download(self):
        self.judged(self.OK_HEAD, self.CHECKOUT + "      - run: curl -fsSL https://example.org/install.sh | sh\n", r"reads its script from stdin")

    def test_steps_are_judged_an_unpinned_image(self):
        self.judged(self.OK_HEAD, self.CHECKOUT + "      - run: docker pull alpine:latest\n", r"alpine")

    # ---- every refused variant
    def test_refused_runs_on_forms(self):
        for name, head in {
            "another expression": "    runs-on: ${{ inputs.runner }}\n" + self.MATRIX,
            "env": "    runs-on: ${{ env.RUNNER }}\n" + self.MATRIX,
            "vars": "    runs-on: ${{ vars.RUNNER }}\n" + self.MATRIX,
            "a function": "    runs-on: ${{ format(matrix.runner) }}\n" + self.MATRIX,
            "a default": "    runs-on: ${{ matrix.runner || 'ubuntu-24.04' }}\n" + self.MATRIX,
            "an index": "    runs-on: ${{ matrix['runner'] }}\n" + self.MATRIX,
            "an array index": "    runs-on: ${{ matrix.runner[0] }}\n" + self.MATRIX,
            "a property of the label": "    runs-on: ${{ matrix.runner.name }}\n" + self.MATRIX,
            "no spaces inside the braces": "    runs-on: ${{matrix.runner}}\n" + self.MATRIX,
            "a key that does not exist": "    runs-on: ${{ matrix.runnr }}\n" + self.MATRIX,
            "a list holding the expression": '    runs-on: ["${{ matrix.runner }}"]\n' + self.MATRIX,
            "a list of labels": "    runs-on: [self-hosted, linux]\n",
            "no strategy": "    runs-on: ${{ matrix.runner }}\n",
            "text before the expression": "    runs-on: ubuntu-${{ matrix.runner }}\n" + self.MATRIX,
            "text after the expression": "    runs-on: ${{ matrix.runner }}-8core\n" + self.MATRIX,
            "more text after the expression": "    runs-on: ${{ matrix.runner }}-xlarge\n" + self.MATRIX,
            "a second expression, glued": "    runs-on: ${{ matrix.runner }}${{ inputs.x }}\n" + self.MATRIX,
            "a second expression, spaced": "    runs-on: ${{ matrix.runner }} ${{ vars.R }}\n" + self.MATRIX,
            "a literal block scalar (trailing newline)": "    runs-on: |\n      ${{ matrix.runner }}\n" + self.MATRIX,
            "a folded block scalar (trailing newline)": "    runs-on: >\n      ${{ matrix.runner }}\n" + self.MATRIX,
        }.items():
            with self.subTest(name):
                self.refused(head)

    def test_refused_matrices(self):
        ro = "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n"
        for name, matrix in {
            "an extra key": "        runner: [ubuntu-24.04]\n        os: [ubuntu-24.04-arm]\n",
            "fromJSON": "        runner: ${{ fromJSON('[\"ubuntu-24.04\"]') }}\n",
            "the matrix as an expression": "        ${{ fromJSON(needs.x.outputs.m) }}\n",
            "include": "        include:\n          - runner: ubuntu-24.04\n",
            "include beside the key": "        runner: [ubuntu-24.04]\n        include:\n          - runner: macos-14\n",
            "exclude": "        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n        exclude:\n          - runner: ubuntu-24.04-arm\n",
            "self-hosted": "        runner: [ubuntu-24.04, self-hosted]\n",
            "one bad label": "        runner: [macos-14]\n",
            "a windows label": "        runner: [ubuntu-24.04, windows-2022]\n",
            "ubuntu-latest": "        runner: [ubuntu-latest]\n",
            "another ubuntu version": "        runner: [ubuntu-22.04]\n",
            "a larger runner": "        runner: [ubuntu-24.04-8core]\n",
            "an arm64 suffix": "        runner: [ubuntu-24.04-arm64]\n",
            "different case": "        runner: [Ubuntu-24.04]\n",
            "a trailing space": "        runner: ['ubuntu-24.04 ']\n",
            "a leading space": "        runner: [' ubuntu-24.04']\n",
            "a double-quoted trailing newline": '        runner: ["ubuntu-24.04\\n"]\n',
            "a block-scalar label": "        runner:\n          - |\n            ubuntu-24.04\n",
            "a Greek upsilon for u": "        runner: [\u03c5buntu-24.04]\n",
            "an en dash for the hyphen": "        runner: [ubuntu\u201324.04]\n",
            "a Cyrillic O for the zero": "        runner: [ubuntu-24.\u041e4]\n",
            "an explicit binary tag": "        runner: [!!binary ubuntu-24.04]\n",
            "an unknown explicit tag": "        runner: [!x ubuntu-24.04]\n",
            "a nested list": "        runner: [[ubuntu-24.04]]\n",
            "a mapping as a label": "        runner: [{name: ubuntu-24.04}]\n",
            "a number": "        runner: [24.04]\n",
            "a boolean": "        runner: [true]\n",
            "null": "        runner: [null]\n",
            "an expression label": "        runner: [ubuntu-24.04, '${{ inputs.runner }}']\n",
            "an empty list": "        runner: []\n",
            "a scalar, not a list": "        runner: ubuntu-24.04\n",
            "a duplicate key": "        runner: [ubuntu-24.04]\n        runner: [ubuntu-24.04-arm]\n",
        }.items():
            with self.subTest(name):
                self.refused(ro + matrix)

    def test_a_matrix_of_only_include_or_exclude_is_refused(self):
        """include and exclude are not label keys: a matrix of only one of them, read as `${{ matrix.include }}`, is refused."""
        for key in ("include", "exclude"):
            with self.subTest(key):
                self.refused("    runs-on: ${{ matrix.%s }}\n    strategy:\n      matrix:\n        %s: [ubuntu-24.04]\n" % (key, key))

    def test_an_explicit_str_tag_is_accepted(self):
        """!!str resolves to the plain string tag, so it is the same scalar; any other explicit tag is refused (above)."""
        self.accepted("    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [!!str ubuntu-24.04]\n")

    def test_refused_strategy_shapes(self):
        for name, head in {
            "strategy as an expression": "    runs-on: ${{ matrix.runner }}\n    strategy: ${{ fromJSON(needs.x.outputs.s) }}\n",
            "an extra strategy key": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n",
            "fail-fast as an expression": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      fail-fast: ${{ inputs.f }}\n      matrix:\n        runner: [ubuntu-24.04]\n",
            "fail-fast as a capital True": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      fail-fast: True\n      matrix:\n        runner: [ubuntu-24.04]\n",
            "fail-fast as yes": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      fail-fast: yes\n      matrix:\n        runner: [ubuntu-24.04]\n",
            "a strategy with no matrix key": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      fail-fast: true\n",
            "matrix given twice (both valid)": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n"
                                               "      matrix:\n        runner: [ubuntu-24.04]\n",
            "matrix given twice (the last invalid)": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n"
                                                     "      matrix:\n        runner: [macos-14]\n",
            # YAML keeps the last of two `strategy` keys: here the last is the invalid one, so a reader that takes the first is fooled
            "a second strategy key": "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n"
                                     "    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n",
        }.items():
            with self.subTest(name):
                self.refused(head)

    def test_a_key_given_twice_is_refused_with_the_key_named(self):
        """A key repeated in a job, its strategy or its matrix is refused, whatever its last copy holds (YAML keeps the last
        copy; GitHub rejects the file). Each family runs with a valid last copy and with an invalid one."""
        ok = "    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n"
        for name, (key, head) in {
            "a job key, both valid": ("name", "    name: one\n    name: two\n    runs-on: ${{ matrix.runner }}\n" + ok),
            "a job key, the last invalid": ("container", f"    container: alpine@{self.DIGEST}\n    container: alpine:3.20\n"
                                                         "    runs-on: ${{ matrix.runner }}\n" + ok),
            "runs-on, the last valid": ("runs-on", "    runs-on: self-hosted\n    runs-on: ${{ matrix.runner }}\n" + ok),
            "runs-on, the last invalid": ("runs-on", "    runs-on: ${{ matrix.runner }}\n    runs-on: macos-14\n" + ok),
            "strategy, the last valid": ("strategy", "    runs-on: ${{ matrix.runner }}\n    strategy:\n      max-parallel: 1\n"
                                                     "      matrix:\n        runner: [ubuntu-24.04]\n" + ok),
            "strategy, the last invalid": ("strategy", "    runs-on: ${{ matrix.runner }}\n" + ok +
                                                       "    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n"),
            "matrix, the last valid": ("matrix", "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [macos-14]\n"
                                                 "      matrix:\n        runner: [ubuntu-24.04]\n"),
            "matrix, the last invalid": ("matrix", "    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n"
                                                   "      matrix:\n        runner: [macos-14]\n"),
        }.items():
            with self.subTest(name):
                code, out = self.findings(self.job(head))
                self.assertNotEqual(code, 0, out)
                self.assertRegex(out, rf"duplicate key '{re.escape(key)}'")

    def test_a_key_given_twice_in_a_call_job_is_refused(self):
        code, out = self.findings("on: push\njobs:\n  c:\n    uses: ./.github/workflows/w.yml\n    uses: ./.github/workflows/w.yml\n")
        self.assertNotEqual(code, 0, out)
        self.assertRegex(out, r"duplicate key 'uses'")

    def test_a_matrix_on_another_job_does_not_count(self):
        code, out = self.findings("on: push\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    strategy:\n      matrix:\n"
                                  "        runner: [ubuntu-24.04]\n    steps:\n      - run: true\n"
                                  "  b:\n    runs-on: ${{ matrix.runner }}\n    steps:\n      - run: true\n")
        self.assertNotEqual(code, 0, out)
        self.assertRegex(out, r"jobs\.b\.runs-on")

    def test_a_matrix_defined_at_the_workflow_level_does_not_count(self):
        code, out = self.findings("on: push\nstrategy:\n  matrix:\n    runner: [ubuntu-24.04]\njobs:\n  a:\n"
                                  "    runs-on: ${{ matrix.runner }}\n    steps:\n      - run: true\n")
        self.assertNotEqual(code, 0, out)
        self.assertIn("runs-on", out)

    def test_any_anchor_in_the_file_is_refused(self):
        code, out = self.findings("on: push\nx-m: &m\n  runner: [ubuntu-24.04]\njobs:\n  a:\n    runs-on: ${{ matrix.runner }}\n"
                                  "    strategy:\n      matrix: *m\n    steps:\n      - run: true\n")
        self.assertNotEqual(code, 0, out)
        self.assertIn("anchor", out)

    def test_an_unresolved_runs_on_is_a_finding_not_a_shell_guess(self):
        code, out = self.findings(self.job("    runs-on: ${{ inputs.runner }}\n" + self.MATRIX))
        self.assertNotEqual(code, 0, out)
        self.assertRegex(out, r"jobs\.apk\.runs-on: '\$\{\{ inputs\.runner \}\}' is not an ubuntu runner")

    def test_a_reusable_workflow_call_has_no_runner_to_judge(self):
        code, out = self.findings("on: push\njobs:\n  c:\n    uses: ./.github/workflows/w.yml\n")
        self.assertEqual(code, 0, out)

    # ---- scope: the runner rule is read in .github/workflows/ files only
    def test_the_runner_rule_is_read_in_workflow_files_only(self):
        plain = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
        other = "on: push\njobs:\n  a:\n    runs-on: %s\n%s    steps:\n      - run: bash bin/build.sh\n"
        code, out = self.findings(plain, {".github/other.yml": other % ("${{ matrix.runner }}", "    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n")})
        self.assertEqual(code, 0, out)       # a valid matrix reads as bash there too
        code, out = self.findings(plain, {".github/other.yml": other % ("${{ inputs.runner }}", "")})
        self.assertNotEqual(code, 0, out)    # an unresolved runner there only makes its steps read as pwsh
        self.assertRegex(out, r"other\.yml.*a `pwsh` step")
        self.assertNotIn("runs-on", out)
        code, out = self.findings(plain, {".github/other.yml": other % ("${{ matrix.runner }}", "    strategy:\n      matrix:\n        runner: [windows-2022]\n")})
        self.assertNotEqual(code, 0, out)    # a Windows label there: the steps read as pwsh, still no runs-on finding
        self.assertRegex(out, r"other\.yml.*a `pwsh` step")
        self.assertNotIn("runs-on", out)


if __name__ == "__main__":       # last: every test class above is defined first (Codex #164 adversarial r1, R02)
    unittest.main()
