"""Coverage + behaviour tests for auditor-adjudicator-client.py (REQ-AUD-18 AC2).

The real client talks to Anthropic through the `anthropic` SDK. Here the SDK is replaced by a
fake module injected into sys.modules (a stub transport): it records every client construction
and every messages.create call and returns canned responses, so request/response handling,
one-client-per-run behaviour, error surfacing and secret masking all run offline."""
import importlib.util, io, json, os, runpy, sys, tempfile, types, unittest
from unittest import mock

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SRC = os.path.join(BIN, "auditor-adjudicator-client.py")


def load():
    spec = importlib.util.spec_from_file_location("adjudicator_client", SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


C = load()

# Built at RUNTIME via join (not "a" + "b", which the compiler constant-folds into the .pyc): no
# key-shaped literal may exist anywhere under .github/agent/ (req6-ac4-no-key-leak scans it).
FAKE_KEY = "-".join(("sk", "ant", "abcdef123456"))
FAKE_KEY2 = "-".join(("sk", "ant", "zzzzzzzz"))

SECRETS = {
    "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_SECRETRULE",
    "ANTHROPIC_ORGANIZATION_ID": "org-SECRETORG",
    "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_SECRETSVC",
    "ANTHROPIC_WORKSPACE_ID": "wrkspc_SECRETWS",
    "AUDITOR_MODEL_PRIMARY": "claude-primary-x1",
    "AUDITOR_MODEL_FALLBACK": "claude-fallback-y2",
}


# ---------------------------------------------------------------- fake SDK
class Block:
    def __init__(self, text):
        self.text = text


class Usage:
    def __init__(self, i, o):
        self.input_tokens, self.output_tokens = i, o


class Msg:
    def __init__(self, text, usage=(10, 5)):
        self.content = [Block(text)]
        self.usage = Usage(*usage) if usage else None


class SDKError(Exception):
    def __init__(self, msg, status_code=None, status=None):
        super().__init__(msg)
        if status_code is not None:
            self.status_code = status_code
        if status is not None:
            self.status = status


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        r = self.responses.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r


class FakeClient:
    def __init__(self, responses):
        self.messages = FakeMessages(responses)


def fake_sdk(responses=(), ctor_error=None):
    """A fake `anthropic` module. `mod.constructed` counts Anthropic() calls."""
    mod = types.ModuleType("anthropic")
    mod.constructed = []

    def Anthropic(*a, **kw):
        if ctor_error is not None:
            raise ctor_error
        c = FakeClient(responses)
        mod.constructed.append((a, kw, c))
        return c
    mod.Anthropic = Anthropic
    return mod


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.token = os.path.join(self.tmp.name, "id-token")
        open(self.token, "w").write("eyJ.fake.jwt")
        env = {k: v for k, v in os.environ.items()
               if k not in C._SECRET_ENVS and k != "ANTHROPIC_IDENTITY_TOKEN_FILE"}
        env.update(SECRETS)
        env["ANTHROPIC_IDENTITY_TOKEN_FILE"] = self.token
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start(); self.addCleanup(p.stop)

    def run_main(self, argv, stdin, sdk, as_script=False):
        """Run main() with patched argv/stdin/stdout/stderr and the given fake SDK.
        Returns (exit_code or None, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        code = None
        with mock.patch.dict(sys.modules, {"anthropic": sdk}), \
                mock.patch.object(sys, "argv", [SRC] + argv), \
                mock.patch.object(sys, "stdin", io.StringIO(stdin)), \
                mock.patch.object(sys, "stdout", out), \
                mock.patch.object(sys, "stderr", err):
            try:
                if as_script:
                    runpy.run_path(SRC, run_name="__main__")
                else:
                    C.main()
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------- masking
class Mask(Base):
    def test_secret_env_values_model_ids_keys_bearer_masked(self):
        s = ("rule fdrl_SECRETRULE org org-SECRETORG ws wrkspc_SECRETWS "
             "model claude-primary-x1 other claude-3-5-sonnet-20241022 "
             "key " + FAKE_KEY + " hdr Bearer abcdefghijk")
        m = C._mask(s)
        for v in ("fdrl_SECRETRULE", "org-SECRETORG", "wrkspc_SECRETWS", "claude-primary-x1",
                  "claude-3-5", FAKE_KEY, "abcdefghijk"):
            self.assertNotIn(v, m)
        self.assertIn("<ANTHROPIC_FEDERATION_RULE_ID>", m)
        self.assertIn("<ANTHROPIC_ORGANIZATION_ID>", m)
        self.assertIn("<ANTHROPIC_WORKSPACE_ID>", m)
        # the env-named model id is replaced by its env label first (exact value match)
        self.assertIn("<AUDITOR_MODEL_PRIMARY>", m)
        self.assertIn("<model-id>", m)
        self.assertIn("<redacted-key>", m)
        self.assertIn("Bearer <redacted>", m)

    def test_short_env_values_not_masked_and_none_is_empty(self):
        os.environ["SNYK_TOKEN"] = "abc"          # < 4 chars: must not be replaced
        self.assertEqual(C._mask("abc def"), "abc def")
        self.assertEqual(C._mask(None), "")
        # short sk-/bearer tokens (under 6 chars) are left alone
        self.assertEqual(C._mask("sk-abc bearer xyz"), "sk-abc bearer xyz")


class ErrDetail(Base):
    def test_401_403_reclassified_as_identity(self):
        for st in (401, 403):
            step, d = C._err_detail("model-call", SDKError("denied org-SECRETORG", status_code=st))
            self.assertEqual(step, "identity/federation")
            self.assertEqual(d, "SDKError status=%d: denied <ANTHROPIC_ORGANIZATION_ID>" % st)

    def test_other_status_via_status_attr_keeps_step(self):
        step, d = C._err_detail("model-call", SDKError("overloaded", status=529))
        self.assertEqual((step, d), ("model-call", "SDKError status=529: overloaded"))

    def test_no_status(self):
        step, d = C._err_detail("model-call", ValueError("bad claude-foo"))
        self.assertEqual((step, d), ("model-call", "ValueError: bad <model-id>"))

    def test_fail_writes_masked_stderr_and_exits_5(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            with self.assertRaises(SystemExit) as cm:
                C._fail("model-call", SDKError("nope " + FAKE_KEY2, status_code=403))
        self.assertEqual(cm.exception.code, 5)
        self.assertEqual(err.getvalue(),
                         "adjudicator-client: identity/federation step failed: "
                         "SDKError status=403: nope <redacted-key>\n")


# ---------------------------------------------------------------- client construction
class BuildClient(Base):
    def _build(self, sdk):
        err = io.StringIO()
        code = None; c = None
        with mock.patch.dict(sys.modules, {"anthropic": sdk}), mock.patch.object(sys, "stderr", err):
            try:
                c = C._build_client()
            except SystemExit as e:
                code = e.code
        return code, c, err.getvalue()

    def test_no_token_env_exits_3(self):
        del os.environ["ANTHROPIC_IDENTITY_TOKEN_FILE"]
        sdk = fake_sdk()
        code, c, err = self._build(sdk)
        self.assertEqual(code, 3)
        self.assertIn("no identity token file", err)
        self.assertEqual(sdk.constructed, [])

    def test_token_file_missing_exits_3(self):
        os.environ["ANTHROPIC_IDENTITY_TOKEN_FILE"] = os.path.join(self.tmp.name, "absent")
        code, _c, err = self._build(fake_sdk())
        self.assertEqual(code, 3)
        self.assertEqual(err, "adjudicator-client: no identity token file; cannot reach the model\n")

    def test_sdk_import_failure_exits_4(self):
        # sys.modules[name] = None makes `import anthropic` raise ImportError
        code, _c, err = self._build(None)
        self.assertEqual(code, 4)
        self.assertTrue(err.startswith("adjudicator-client: sdk-import step failed: ModuleNotFoundError"), err)

    def test_constructor_failure_is_identity_federation_exit_5(self):
        sdk = fake_sdk(ctor_error=SDKError("exchange failed for wrkspc_SECRETWS"))
        code, _c, err = self._build(sdk)
        self.assertEqual(code, 5)
        self.assertEqual(err, "adjudicator-client: identity/federation step failed: "
                              "SDKError: exchange failed for <ANTHROPIC_WORKSPACE_ID>\n")
        self.assertNotIn("wrkspc_SECRETWS", err)

    def test_success_returns_sdk_client_no_args(self):
        sdk = fake_sdk()
        code, c, err = self._build(sdk)
        self.assertIsNone(code)
        self.assertEqual(len(sdk.constructed), 1)
        self.assertEqual(sdk.constructed[0][:2], ((), {}))
        self.assertIs(c, sdk.constructed[0][2])
        self.assertEqual(err, "")


# ---------------------------------------------------------------- prompts
class Prompts(Base):
    def test_unreadable_prompt_file_is_none_and_labelled_error(self):
        with mock.patch.object(C, "_PROMPT_FILE", os.path.join(self.tmp.name, "nope.md")):
            self.assertIsNone(C._load_prompt("disposition"))
            with self.assertRaises(RuntimeError) as cm:
                C._require_prompt("disposition")
        self.assertTrue(str(cm.exception).startswith("prompt-load: section 'disposition' missing"))

    def test_missing_section_raises(self):
        p = os.path.join(self.tmp.name, "p.md")
        open(p, "w").write("## other\nbody\n")
        with mock.patch.object(C, "_PROMPT_FILE", p):
            self.assertEqual(C._require_prompt("other"), "body")
            self.assertRaises(RuntimeError, C._require_prompt, "narrative")

    def test_handle_surfaces_prompt_load_error_not_model_call(self):
        client = FakeClient([])
        with mock.patch.object(C, "_PROMPT_FILE", os.path.join(self.tmp.name, "nope.md")):
            with self.assertRaisesRegex(RuntimeError, "prompt-load"):
                C._handle({"mode": "narrative", "structured": {}}, client)
        self.assertEqual(client.messages.calls, [])


# ---------------------------------------------------------------- _handle
class Handle(Base):
    def test_narrative(self):
        client = FakeClient([Msg("All clear.", usage=(100, 20))])
        ans = C._handle({"mode": "narrative", "structured": {"accepted": 3}}, client)
        self.assertEqual(ans, {"refused": False, "narrative": "All clear.", "token_usage": 120})
        call = client.messages.calls[0]
        self.assertEqual(call["model"], "claude-primary-x1")
        self.assertEqual(call["max_tokens"], 512)
        content = call["messages"][0]["content"]
        self.assertEqual(call["messages"][0]["role"], "user")
        self.assertIn(json.dumps({"accepted": 3}, indent=1), content)
        self.assertNotIn("{context}", content)

    def test_narrative_joins_blocks_ignores_textless(self):
        m = Msg("A")
        m.content = [Block("A"), object(), Block("B")]
        ans = C._handle({"mode": "narrative", "structured": None}, FakeClient([m]))
        self.assertEqual(ans["narrative"], "AB")

    def test_fallback_model_selected_and_default_when_unset(self):
        client = FakeClient([Msg("real_fixable"), Msg("real_fixable")])
        C._handle({"attempt": "fallback", "finding_id": "CVE-1"}, client)
        self.assertEqual(client.messages.calls[0]["model"], "claude-fallback-y2")
        del os.environ["AUDITOR_MODEL_FALLBACK"]
        C._handle({"attempt": "fallback", "finding_id": "CVE-1"}, client)
        self.assertEqual(client.messages.calls[1]["model"], "claude-primary-x1")

    def test_disposition_context_prompt_and_category(self):
        client = FakeClient([Msg("I judge this false_positive because ...", usage=(7, 3))])
        req = {"finding_id": "CVE-2024-1", "package": "zlib", "installed_version": "1.2",
               "severity": None, "scanners": ["grype", "trivy"]}
        ans = C._handle(req, client)
        self.assertEqual(ans, {"refused": False, "category": "false_positive",
                               "proposed": True, "token_usage": 10})
        call = client.messages.calls[0]
        self.assertEqual((call["model"], call["max_tokens"]), ("claude-primary-x1", 512))
        p = call["messages"][0]["content"]
        self.assertIn("- finding_id: CVE-2024-1\n- package: zlib\n- installed_version: 1.2\n"
                      "- scanners: ['grype', 'trivy']", p)
        self.assertNotIn("- severity:", p)       # None-valued keys are omitted
        self.assertIn("(no prior scanner-defect or package patterns recorded yet)", p)
        self.assertNotIn("rephrase the question plainly", p)
        for ph in ("{ask}", "{knowledge}", "{context}"):
            self.assertNotIn(ph, p)

    def test_disposition_rephrase_and_knowledge_passthrough(self):
        client = FakeClient([Msg("not_affected_unreachable")])
        ans = C._handle({"finding_id": "X", "attempt": "rephrase",
                         "knowledge": "KNOWN: grype misreads zlib"}, client)
        p = client.messages.calls[0]["messages"][0]["content"]
        self.assertIn("rephrase the question plainly and answer", p)
        self.assertIn("KNOWN: grype misreads zlib", p)
        self.assertNotIn("(no prior scanner-defect", p)
        self.assertEqual(ans["category"], "not_affected_unreachable")

    def test_category_priority_order(self):
        # both appear: the tuple order decides (false_positive wins over risk_acceptance)
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("risk_acceptance or false_positive")]))
        self.assertEqual(ans["category"], "false_positive")
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("risk_acceptance")]))
        self.assertEqual(ans["category"], "risk_acceptance")

    def test_refusal_only_when_no_category(self):
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("I CANNOT decide this.")]))
        self.assertEqual((ans["refused"], ans["category"]), (True, "under_investigation"))
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("cannot be reached: not_affected_unreachable")]))
        self.assertEqual((ans["refused"], ans["category"]), (False, "not_affected_unreachable"))
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("unclear")]))
        self.assertEqual((ans["refused"], ans["category"]), (False, "under_investigation"))

    def test_propose_passthrough_only_when_dict(self):
        text = 'real_fixable\n```json\n{"category": "real_fixable", "propose": {"kind": "defect", "evidence": "a}b"}}\n```'
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg(text)]))
        self.assertEqual(ans["propose"], {"kind": "defect", "evidence": "a}b"})
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg('real_fixable {"propose": "free text"}')]))
        self.assertNotIn("propose", ans)
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("real_fixable, no json")]))
        self.assertNotIn("propose", ans)

    def test_no_usage_is_zero(self):
        ans = C._handle({"finding_id": "X"}, FakeClient([Msg("real_fixable", usage=None)]))
        self.assertEqual(ans["token_usage"], 0)

    def test_pullability(self):
        text = 'Analysis... {"pullable": false, "hold": "base", "lift_trigger": "rebase"} done'
        client = FakeClient([Msg(text, usage=(4, 4))])
        ans = C._handle({"kind": "pullability", "finding_id": "CVE-9", "carrier": "busybox",
                         "base": None}, client)
        self.assertEqual(ans, {"pullable": False, "hold": "base", "lift_trigger": "rebase",
                               "refused": False, "proposed": True, "token_usage": 8})
        call = client.messages.calls[0]
        self.assertEqual(call["max_tokens"], 1024)
        p = call["messages"][0]["content"]
        self.assertIn(json.dumps({"finding_id": "CVE-9", "carrier": "busybox"}, indent=1), p)
        ans = C._handle({"attempt": "pullability"}, FakeClient([Msg("I cannot tell")]))
        self.assertEqual(ans, {"refused": True, "proposed": True, "token_usage": 15})


class ExtractJson(unittest.TestCase):
    def test_cases(self):
        self.assertIsNone(C._extract_json(None))
        self.assertIsNone(C._extract_json("no braces"))
        self.assertIsNone(C._extract_json("{broken [1,2] {also"))
        self.assertEqual(C._extract_json('x {bad} y {"a": "}"} z'), {"a": "}"})


# ---------------------------------------------------------------- main()
class Main(Base):
    def test_one_shot_success(self):
        sdk = fake_sdk([Msg("real_fixable", usage=(2, 2))])
        code, out, err = self.run_main([], json.dumps({"finding_id": "CVE-1"}), sdk)
        self.assertIsNone(code)
        self.assertEqual(json.loads(out), {"refused": False, "category": "real_fixable",
                                           "proposed": True, "token_usage": 4})
        self.assertEqual(len(sdk.constructed), 1)
        self.assertEqual(err, "")

    def test_one_shot_model_error_exits_5_masked(self):
        sdk = fake_sdk([SDKError("model claude-primary-x1 not found", status_code=404)])
        code, out, err = self.run_main([], json.dumps({"finding_id": "CVE-1"}), sdk)
        self.assertEqual(code, 5)
        self.assertEqual(out, "")
        self.assertEqual(err, "adjudicator-client: model-call step failed: "
                              "SDKError status=404: model <AUDITOR_MODEL_PRIMARY> not found\n")

    def test_one_shot_federation_error_on_call(self):
        sdk = fake_sdk([SDKError("unauthorized", status_code=401)])
        code, _out, err = self.run_main([], json.dumps({"finding_id": "CVE-1"}), sdk)
        self.assertEqual(code, 5)
        self.assertIn("identity/federation step failed: SDKError status=401", err)

    def test_one_shot_no_token_exits_before_reading(self):
        del os.environ["ANTHROPIC_IDENTITY_TOKEN_FILE"]
        sdk = fake_sdk()
        code, out, _err = self.run_main([], "not json", sdk)
        self.assertEqual((code, out, sdk.constructed), (3, "", []))

    def test_serve_one_client_many_requests_errors_do_not_exit(self):
        sdk = fake_sdk([Msg("false_positive", usage=(1, 1)),
                        SDKError("rate limited Bearer abcdefghij", status_code=429),
                        SDKError("forbidden", status=403),
                        Msg("All good", usage=(3, 0))])
        lines = [json.dumps({"finding_id": "A"}), "", "   ",
                 json.dumps({"finding_id": "B"}),
                 json.dumps({"finding_id": "C"}),
                 "{not json",
                 json.dumps({"mode": "narrative", "structured": {}})]
        code, out, err = self.run_main(["--serve"], "\n".join(lines) + "\n", sdk)
        self.assertIsNone(code)
        self.assertEqual(err, "")
        answers = [json.loads(l) for l in out.splitlines()]
        self.assertEqual(len(answers), 5)            # blank lines skipped
        self.assertEqual(answers[0]["category"], "false_positive")
        self.assertEqual(answers[1], {"error": "adjudicator-client: model-call step failed: "
                                               "SDKError status=429: rate limited Bearer <redacted>"})
        self.assertEqual(answers[2], {"error": "adjudicator-client: identity/federation step "
                                               "failed: SDKError status=403: forbidden"})
        self.assertTrue(answers[3]["error"].startswith(
            "adjudicator-client: model-call step failed: JSONDecodeError"))
        self.assertEqual(answers[4], {"refused": False, "narrative": "All good", "token_usage": 3})
        # ONE client / ONE exchange for the whole run
        self.assertEqual(len(sdk.constructed), 1)
        self.assertEqual(len(sdk.constructed[0][2].messages.calls), 4)

    def test_run_as_script(self):
        sdk = fake_sdk([Msg("risk_acceptance", usage=(1, 2))])
        code, out, _err = self.run_main([], json.dumps({"finding_id": "Z"}), sdk, as_script=True)
        self.assertIsNone(code)
        self.assertEqual(json.loads(out)["category"], "risk_acceptance")
        self.assertEqual(len(sdk.constructed), 1)


if __name__ == "__main__":
    unittest.main()
