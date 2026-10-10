"""Coverage + behaviour tests for check-action-pins.py (register row 78; REQ-AUD-18 AC2 measures it).

The fixture cases in .github/agent/tests/check-action-pins-test.sh prove the rules end to end; these
reach the branches a fixture workflow cannot: the tag verifier (GitHub's API is a patched
urllib.request.urlopen — no network), a submodule in a git tree, a missing PyYAML, and the
command-line errors.
"""
import contextlib, importlib.util, io, json, os, re, runpy, subprocess, sys, tempfile, unittest
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


GATE_A = "0c34cbbba707b8b3944064eae259985af22f8981d2ae5b9d22ccfd58d40b0447"   # main's gate workflow before #251
GATE_B = "7007f77f62f9312ca8e0290afccbba284cd8d07e1b2b90dcbe0f44527466df83"   # the gate workflow of cache PR #251
# cache PR #251's three edits to the gate workflow (old text, new text): the second accepted digest is the gate
# workflow with these applied; either variant is derived from whichever one the repository carries
PR251_HUNKS = (
    ('          PYTHONPATH="$RUNNER_TEMP/yaml-shim" PIN_WIRING_JUDGE_GIT="$HEAD_SHA" bash .github/agent/tests/pin-wiring-test.sh || verdict=failure\n',
     '          PYTHONPATH="$RUNNER_TEMP/yaml-shim" PIN_WIRING_JUDGE_GIT="$HEAD_SHA" bash .github/agent/tests/pin-wiring-test.sh || verdict=failure\n'
     '          # REQ-SCAN-015: main\'s scanner guard judges the head\'s workflows and composite actions as git objects, so a step\n'
     '          # of the PR\'s own CI that overwrites the guard on disk changes nothing\n'
     '          PYTHONPATH="$RUNNER_TEMP/yaml-shim" SCAN_GUARD_JUDGE_GIT="$HEAD_SHA" bash bin/scan-no-workflow-call-test.sh || verdict=failure\n'),
    ('          else conclusion=failure; summary="No valid review-loop record for this .github/agent/ content, or an action reference that is not a commit digest (or the judge did not finish) — see the run log."; fi\n',
     '          else conclusion=failure; summary="No valid review-loop record for this .github/agent/ content, an action reference that is not a commit digest, or a failure of main\'s allowlist guard, pin-wiring judge or scanner guard over the head (or the judge did not finish) — see the run log."; fi\n'),
    ('               && PYTHONPATH="$RUNNER_TEMP/yaml-shim" PIN_WIRING_JUDGE_GIT="$sha" bash .github/agent/tests/pin-wiring-test.sh; then\n'
     '              conclusion=success   # the review record, every action reference a digest (row 78), main\'s allowlist guard and pin-wiring judge\n',
     '               && PYTHONPATH="$RUNNER_TEMP/yaml-shim" PIN_WIRING_JUDGE_GIT="$sha" bash .github/agent/tests/pin-wiring-test.sh \\\n'
     '               && PYTHONPATH="$RUNNER_TEMP/yaml-shim" SCAN_GUARD_JUDGE_GIT="$sha" bash bin/scan-no-workflow-call-test.sh; then\n'
     '              conclusion=success   # the review record, every action reference a digest (row 78), main\'s allowlist guard, pin-wiring judge and scanner guard\n'),
)


def gate_variants():
    """(the gate workflow before #251, the gate workflow of #251), from the repository's copy."""
    with open(GATE) as fh:
        cur = fh.read()
    if all(cur.count(old) == 1 for old, _ in PR251_HUNKS):
        a, b = cur, cur
        for old, new in PR251_HUNKS:
            b = b.replace(old, new)
    else:
        assert all(cur.count(new) == 1 for _, new in PR251_HUNKS), "the gate workflow is neither variant"
        a, b = cur, cur
        for old, new in PR251_HUNKS:
            a = a.replace(new, old)
    return a, b


def gate_tree(gate_text):
    """A minimal tree the checker passes, carrying `gate_text` as the gate workflow."""
    return repo({".github/workflows/agent-review-gate.yml": gate_text,
                 ".github/workflows/w.yml": HEAD + f"    steps:\n      - uses: actions/checkout@{SHA} # v7.0.1\n",
                 ".github/agent/bin/auditor-review-gate.py": "", ".github/agent/bin/check-action-pins.py": "",
                 "bin/check-file-allowlist.sh": "", ".github/agent/tests/pin-wiring-test.sh": "",
                 "bin/scan-no-workflow-call-test.sh": ""}, gate=False)


def bump_first_pin(text):
    """A Dependabot-style bump: the first `@<40 hex> # v<ver>` pin moves to another commit and tag."""
    out, n = re.subn(r"@[0-9a-f]{40} # v[0-9][0-9A-Za-z.+-]*", f"@{OTHER} # v99.0.0", text, count=1)
    assert n == 1
    return out


class GateWorkflowDigestSet(unittest.TestCase):
    """The bootstrap of cache PR #251 (PR A): the pin checker accepts exactly two gate-workflow digests, main's
    and #251's, both taken by gate_digest (pins masked); PR C later removes main's old one."""

    def test_the_constant_is_a_frozen_set_of_exactly_two_digests(self):
        s = M.GATE_WORKFLOW_SHA256
        self.assertIsInstance(s, frozenset)      # immutable: no code path can add a digest at run time
        self.assertEqual(len(s), 2)              # not empty, not one, not three (a frozenset has no duplicates)
        for d in s:
            self.assertRegex(d, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(s, frozenset({GATE_A, GATE_B}))

    def test_both_variants_are_taken_by_gate_digest(self):
        a, b = gate_variants()
        self.assertEqual(M.gate_digest(a), GATE_A)
        self.assertEqual(M.gate_digest(b), GATE_B)

    def test_a_tree_with_either_accepted_gate_workflow_passes(self):
        for name, text in zip(("main", "pr251"), gate_variants()):
            with self.subTest(gate=name):
                code, out = run([gate_tree(text)])
                self.assertEqual(code, 0, out)
                self.assertIn(", 0 finding(s)", out)

    def test_a_dependabot_pin_bump_in_either_still_matches(self):
        for name, text in zip(("main", "pr251"), gate_variants()):
            with self.subTest(gate=name):
                bumped = bump_first_pin(text)
                self.assertNotEqual(bumped, text)
                self.assertIn(M.gate_digest(bumped), M.GATE_WORKFLOW_SHA256)
                code, out = run([gate_tree(bumped)])
                self.assertEqual(code, 0, out)

    def test_a_third_digest_is_refused_and_the_message_names_the_accepted_set(self):
        a, _ = gate_variants()
        third = a.replace("--verify-tags --git", "--git", 1)
        self.assertNotEqual(third, a)
        d3 = M.gate_digest(third)
        self.assertNotIn(d3, (GATE_A, GATE_B))
        code, out = run([gate_tree(third)])
        self.assertEqual(code, 1, out)
        (line,) = [ln for ln in out.splitlines() if ln.startswith(".github/workflows/agent-review-gate.yml:")]
        self.assertIn("changed — update GATE_WORKFLOW_SHA256 in this checker", line)
        self.assertIn(d3, line)
        self.assertIn(GATE_A, line)
        self.assertIn(GATE_B, line)

    def test_a_missing_gate_workflow_still_fails(self):
        a, _ = gate_variants()
        d = gate_tree(a)
        os.remove(os.path.join(d, ".github/workflows/agent-review-gate.yml"))
        code, out = run([d])
        self.assertEqual(code, 1, out)
        self.assertIn(".github/workflows/agent-review-gate.yml: missing", out)


if __name__ == "__main__":       # last: every test class above is defined first (Codex #164 adversarial r1, R02)
    unittest.main()
