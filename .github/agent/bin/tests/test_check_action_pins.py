"""Coverage + behaviour tests for check-action-pins.py (register row 78; REQ-AUD-18 AC2 measures it).

The fixture cases in .github/agent/tests/check-action-pins-test.sh prove the rules end to end; these
reach the branches a fixture workflow cannot: the tag verifier (GitHub's API is a patched
urllib.request.urlopen — no network), a submodule in a git tree, a missing PyYAML, and the
command-line errors.
"""
import contextlib, importlib.util, io, json, os, runpy, subprocess, sys, tempfile, unittest
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


def repo(files):
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
        self.assertEqual(len(seen), 2)  # one tag lookup and one manifest read per pinned action

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


class Transitive(unittest.TestCase):
    """What a pinned action runs, read from its own action.yml at the pinned commit."""

    def judge(self, table, repo="o/a", sha=SHA):
        f, seen = api(table)
        out = M.transitive(lambda path: json.loads(f(type("R", (), {"full_url": "https://api.github.com/" + path})())
                                                   .read()), "w", repo, sha, set(), 0)
        return out, seen

    def test_node_action(self):
        self.assertEqual(self.judge(manifest("o/a", SHA, NODE))[0], [])

    def test_action_yaml_name_and_subpath(self):
        out, _ = self.judge(manifest("o/a", SHA, NODE, name="action.yaml", sub="x/y"), repo="o/a/x/y")
        self.assertEqual(out, [])

    def test_docker_by_digest(self):
        t = manifest("o/a", SHA, "runs:\n  using: docker\n  image: docker://alpine@sha256:" + "a" * 64 + "\n")
        self.assertEqual(self.judge(t)[0], [])

    def test_docker_by_tag(self):
        (msg,) = self.judge(manifest("o/a", SHA, "runs:\n  using: docker\n  image: docker://alpine:3.20\n"))[0]
        self.assertIn("a Docker action whose image is not a docker://…@sha256 digest: 'docker://alpine:3.20'", msg)

    def test_docker_from_a_dockerfile(self):
        (msg,) = self.judge(manifest("o/a", SHA, "runs:\n  using: docker\n  image: Dockerfile\n"))[0]
        self.assertIn("'Dockerfile'", msg)

    def test_documented_exclusion(self):
        t = manifest("OSSF/scorecard-action", SHA, "runs:\n  using: docker\n  image: docker://ghcr.io/ossf/scorecard-action:v2\n")
        self.assertEqual(self.judge(t, repo="OSSF/scorecard-action")[0], [])

    def test_unknown_runtime(self):
        (msg,) = self.judge(manifest("o/a", SHA, "runs:\n  using: wasm\n"))[0]
        self.assertIn("runs.using 'wasm' is not node, docker or composite", msg)

    def test_no_manifest(self):
        (msg,) = self.judge({})[0]
        self.assertIn("no action.yml/action.yaml at the pinned commit", msg)

    def test_an_api_error_is_not_an_absence(self):
        err = urllib_error().HTTPError("u", 503, "Unavailable", {}, None)
        t = {f"/repos/o/a/contents/action.yml?ref={SHA}": err, **manifest("o/a", SHA, NODE, name="action.yaml")}
        (msg,) = self.judge(t)[0]
        self.assertIn("action.yml unreadable (HTTP 503)", msg)
        t = {f"/repos/o/a/contents/action.yml?ref={SHA}": OSError("reset")}
        (msg,) = self.judge(t)[0]
        self.assertIn("action.yml unreadable (OSError)", msg)

    def test_manifest_without_runs(self):
        (msg,) = self.judge(manifest("o/a", SHA, "name: x\n"))[0]
        self.assertIn("its action.yml does not parse (KeyError)", msg)

    def test_composite_recurses_and_checks_every_step(self):
        comp = ("runs:\n  using: composite\n  steps:\n"
                f"    - uses: o/b@{OTHER}\n"
                "    - uses: ./sub\n"
                "    - \"${{ 'uses' }}\": docker://alpine:latest\n"
                "    - uses: docker://alpine@sha256:" + "b" * 64 + "\n"
                "    - uses: o/c@v1\n"
                "    - uses: ../escape\n"
                f"    - uses: docker/setup-qemu-action@{OTHER}\n"
                "    - run: true\n      shell: bash\n")
        t = {**manifest("o/a", SHA, comp), **manifest("o/b", OTHER, NODE),
             **manifest("docker/setup-qemu-action", OTHER, NODE)}
        out, _ = self.judge(t)
        self.assertEqual(len(out), 5, out)
        self.assertIn("runs.steps[1].uses: a local action, resolved in the caller's workspace at run time: './sub'", out[0])
        self.assertIn("runs.steps[2]: a mapping key that is not a plain string or holds an expression", out[1])
        self.assertIn("runs.steps[4].uses: not a full commit digest: 'o/c@v1'", out[2])
        self.assertIn("runs.steps[5].uses: not a full commit digest: '../escape'", out[3])
        self.assertIn("docker/setup-qemu-action runs a container image of its own", out[4])

    def test_composite_seen_once_and_depth_bounded(self):
        loop = f"runs:\n  using: composite\n  steps:\n    - uses: o/a@{SHA}\n"
        self.assertEqual(self.judge(manifest("o/a", SHA, loop))[0], [])  # a cycle is read once
        f, _ = api({})
        (msg,) = M.transitive(f, "w", "o/a", SHA, set(), 9)
        self.assertIn("composite actions nested more than 8 deep", msg)

    def test_composite_steps_unreadable(self):
        (msg,) = self.judge(manifest("o/a", SHA, "runs:\n  using: composite\n"))[0]
        self.assertIn("composite steps unreadable (StopIteration)", msg)


class Main(unittest.TestCase):
    def test_verify_tags_through_main(self):
        d = repo({".github/workflows/w.yml": HEAD + f"    steps:\n      - uses: actions/checkout@{SHA} # v7.0.1\n",
                  "README.md": "not read\n", ".git/x.yml": "uses: [\n"})
        f, _ = api({"/git/ref/tags/v7.0.1": {"ref": "refs/tags/v7.0.1", "object": {"type": "commit", "sha": SHA}},
                    **CHECKOUT})
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), mock.patch.object(urllib_request(), "urlopen", f):
            code, out = run(["--verify-tags", d])
        self.assertEqual(code, 0, out)
        self.assertIn("1 pinned action(s) verified against their tags, 0 finding(s)", out)

    def test_nothing_to_check(self):
        code, _ = run([repo({"README.md": "x\n"})])
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


if __name__ == "__main__":
    unittest.main()
