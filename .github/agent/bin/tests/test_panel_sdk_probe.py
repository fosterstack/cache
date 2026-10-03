# proves: REQ-SCAN-008-AC3
"""The probe's request cap against the PINNED SDKs (.github/agent/adjudicator-requirements.txt), over a mock transport.

Codex #155 phase-2 round 2 blocker: both SDKs re-send once after a 401 outside max_retries (a federated token refresh),
so the probe could send A, B, B and still report both seats valid. With the capped client each seat sends ONE model
request, and a 401 from it is reported as such. Skipped where the SDKs are not installed (the coverage job); CI runs it
in its own step against the hash-pinned SDKs with PANEL_SDK_TEST_REQUIRED=1, where a missing SDK fails instead.
"""
import base64, importlib.util, json, os, sys, tempfile, time, unittest
from unittest import mock

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
spec = importlib.util.spec_from_file_location("auditor_panel_sdk", os.path.join(BIN, "auditor-panel.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

try:
    import httpx2, openai, anthropic                                   # noqa: F401  (the pinned SDKs)
except ImportError:                                                     # pragma: no cover - the coverage job
    httpx2 = None
REQUIRED = os.environ.get("PANEL_SDK_TEST_REQUIRED") == "1"
ANSWER = json.dumps({"verdict": "false", "evidence": ["x"], "why": None, "case": "c"})


def jwt():
    def part(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    now = int(time.time())
    return "%s.%s.sig" % (part({"alg": "RS256", "typ": "JWT"}),
                          part({"iss": "https://token.actions.githubusercontent.com", "sub": "repo:x", "aud": "a",
                                "iat": now, "exp": now + 600}))


class PinnedSdkProbe(unittest.TestCase):
    def setUp(self):
        if httpx2 is None:
            if REQUIRED:
                self.fail("PANEL_SDK_TEST_REQUIRED=1 but the pinned SDKs are not installed")
            self.skipTest("the pinned SDKs are not installed here")    # pragma: no cover
        self.d = tempfile.mkdtemp()

    def transport(self, model_path, statuses, body):
        sent = []

        def handler(request):
            sent.append(request.url.path)
            if request.url.path in ("/oauth/token", "/v1/oauth/token"):
                return httpx2.Response(200, json={"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
                                                  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"})
            if request.url.path == model_path:
                st = statuses.pop(0)
                if st == 200:
                    return httpx2.Response(200, json=body)
                return httpx2.Response(st, json={"type": "error", "error": {"type": "authentication_error",
                                                                            "message": "invalid token"}})
            return httpx2.Response(404, json={"error": {"message": "unexpected %s" % request.url.path}})
        t = httpx2.MockTransport(handler)
        # every client the SDKs build for themselves (the federated token exchanges) reaches this handler too: the test
        # never touches the network
        for target in (httpx2, sys.modules.get("httpx2._client")):
            if target is not None and hasattr(target, "HTTPTransport"):
                p = mock.patch.object(target, "HTTPTransport", lambda *a, **k: t)
                p.start()
                self.addCleanup(p.stop)
        return t, sent

    def env_a(self):
        return {"PANEL_AUDIT_A_MODEL": "m", "ANTHROPIC_IDENTITY_TOKEN_FILE": os.path.join(self.d, "t"),
                "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_x", "ANTHROPIC_ORGANIZATION_ID": "00000000-0000-0000-0000-000000000000",
                "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_x", "ANTHROPIC_WORKSPACE_ID": "wrkspc_x"}

    ENV_B = {"PANEL_AUDIT_B_IDENTITY_PROVIDER_ID": "i", "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID": "s",
             "PANEL_AUDIT_B_PROJECT_ID": "p", "PANEL_AUDIT_B_MODEL": "m"}
    BODY_A = {"id": "msg_1", "type": "message", "role": "assistant", "model": "m", "stop_reason": "end_turn",
              "stop_sequence": None, "content": [{"type": "text", "text": ANSWER}],
              "usage": {"input_tokens": 1, "output_tokens": 1}}
    BODY_B = {"id": "resp_1", "object": "response", "created_at": 0, "model": "m", "status": "completed",
              "output": [{"type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
                          "content": [{"type": "output_text", "text": ANSWER, "annotations": []}]}],
              "parallel_tool_calls": False, "tool_choice": "auto", "tools": [],
              "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                        "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}

    def seat(self, which, statuses):
        if which == "A":
            t, sent = self.transport("/v1/messages", statuses, self.BODY_A)
            env = self.env_a()
            with mock.patch.dict(os.environ, env):
                ask = P.seat_a(env, mint=lambda a: jwt(), retries=0, transport=t)
        else:
            t, sent = self.transport("/v1/responses", statuses, self.BODY_B)
            ask = P.seat_b(self.ENV_B, mint=lambda a: jwt(), retries=0, transport=t)
        return ask, sent

    def ask(self, which, ask):
        env = self.env_a() if which == "A" else {}
        with mock.patch.dict(os.environ, env), mock.patch.object(P, "render", lambda r: "x"):
            return P._ask(ask, which, {"mode": "audit"})

    def test_a_401_is_reported_and_never_resent(self):
        for which, path in (("A", "/v1/messages"), ("B", "/v1/responses")):
            with self.subTest(seat=which):
                ask, sent = self.seat(which, [401, 200])
                ans = self.ask(which, ask)
                self.assertIn("HTTP 401", ans.get("error", ""), ans)
                self.assertEqual(sent.count(path), 1, sent)

    def test_a_healthy_seat_answers_with_one_model_request(self):
        for which, path in (("A", "/v1/messages"), ("B", "/v1/responses")):
            with self.subTest(seat=which):
                ask, sent = self.seat(which, [200])
                ans = self.ask(which, ask)
                self.assertEqual(ans.get("verdict"), "false", ans)
                self.assertEqual(sent.count(path), 1, sent)


if __name__ == "__main__":
    unittest.main()
