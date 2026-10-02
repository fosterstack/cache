"""Proves (traced in the auditor's docs/scanner-panel-trace.md; REQ-AUD-18 AC1): REQ-SCAN-008-AC3, REQ-SCAN-008-AC5, REQ-SCAN-008-AC10, REQ-SCAN-009-AC1, REQ-SCAN-009-AC5, REQ-SCAN-013-AC4, REQ-SCAN-014-AC2, REQ-SCAN-014-AC3.

The scanner panel audits' input and output (scanner-panel rules 8, 9, 13, 14; owner Oct 2-3).

The evidence bundle is read from a synthetic OCI archive; both seats run against fake SDK modules (no network, no
key); delivery runs against a fake git/gh that records every command. Asserts: the evidence an auditor may quote,
keyless seat construction with identifiers only from the environment, masking, the judge and deliver commands, and
that every change reaches main only as a pull request (rule 0) while issues carry the tracking and owner reports.
"""
import gzip, hashlib, importlib.util, io, json, os, runpy, subprocess, sys, tarfile, tempfile, types, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPO = os.path.abspath(os.path.join(BIN, "..", "..", ".."))
PATH = os.path.join(BIN, "auditor-panel.py")


def load():
    spec = importlib.util.spec_from_file_location("auditor_panel_io", PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


P = load()
GO_BIN = b"\x7fELF....." + P.GO_MARK + b"...."


def tar_bytes(files, gz=True):
    """files: [(name, bytes|None for a dir, mode)]"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as t:
        for name, data, mode in files:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            if data is None:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def oci_archive(path, layers, arch="arm64"):
    blobs = {}

    def put(b):
        d = "sha256:" + hashlib.sha256(b).hexdigest()
        blobs[d] = b
        return d
    man = json.dumps({"layers": [{"digest": put(l)} for l in layers]}).encode()
    inner = json.dumps({"manifests": [
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": put(b'{"layers": []}'),
         "platform": {"os": "unknown", "architecture": "unknown"}},
        {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": put(man),
         "platform": {"os": "linux", "architecture": arch}}]}).encode()
    empty_index = json.dumps({"manifests": []}).encode()
    index = json.dumps({"manifests": [
        {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": put(empty_index)},
        {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": put(inner)}]}).encode()
    files = [("index.json", index, 0o644)] + [("blobs/" + d.replace(":", "/"), b, 0o644) for d, b in blobs.items()]
    with open(path, "wb") as fh:
        fh.write(tar_bytes(files, gz=False))


STATUS = b"Package: tzdata\nVersion: 2026c-0+deb13u1\nStatus: install ok installed\n\nPackage: base-files\nVersion: 13.8\n"


class Tmp(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = self._td.name
        self.addCleanup(self._td.cleanup)


class Image(Tmp):
    def make(self):
        l1 = tar_bytes([("var/lib/dpkg/status.d", None, 0o755), ("var/lib/dpkg/status.d/tzdata", STATUS, 0o644),
                        ("usr/share/zoneinfo/tzdata.zi", b"# version 2026c\n", 0o644),
                        ("usr/bin/cache", GO_BIN, 0o755), ("usr/bin/tool", b"\x7fELF no go", 0o755),
                        ("etc/old-tzdata.conf", b"x", 0o644)])
        l2 = tar_bytes([("etc/.wh.old-tzdata.conf", b"", 0o644), ("var/lib/dpkg/status", b"Package: netbase\n", 0o644)])
        oci_archive(os.path.join(self.d, "fips.oci"), [l1, l2])
        return os.path.join(self.d, "fips.oci")

    def test_layers_apply_in_order_and_whiteouts_remove(self):
        facts = P.read_image(self.make(), "arm64")
        self.assertIn("/usr/share/zoneinfo/tzdata.zi", facts["paths"])
        self.assertNotIn("/etc/old-tzdata.conf", facts["paths"])
        self.assertEqual(sorted(facts["status"]), ["/var/lib/dpkg/status", "/var/lib/dpkg/status.d/tzdata"])
        self.assertEqual(list(facts["gobins"]), ["/usr/bin/cache"])

    def test_opaque_directories_and_replaced_files(self):                  # Codex r1 R4
        l1 = tar_bytes([("opt/lib/old-tzdata", b"x", 0o644), ("var/lib/dpkg/status.d/tzdata", STATUS, 0o644),
                        ("usr/bin/cache", GO_BIN, 0o755)])
        l2 = tar_bytes([("opt/lib/.wh..wh..opq", b"", 0o644), ("opt/lib/new", b"y", 0o644),
                        ("var/lib/dpkg/status.d/.wh..wh..opq", b"", 0o644),
                        ("usr/bin/cache", b"\x7fELF not go any more", 0o755)])
        oci_archive(os.path.join(self.d, "x.oci"), [l1, l2])
        facts = P.read_image(os.path.join(self.d, "x.oci"), "arm64")
        self.assertNotIn("/opt/lib/old-tzdata", facts["paths"])
        self.assertIn("/opt/lib/new", facts["paths"])                        # same-layer entry survives its opaque marker
        self.assertIn("/opt/lib/new", facts["paths"])
        self.assertEqual(facts["status"], {})
        self.assertEqual(facts["gobins"], {})                               # replaced by a non-Go executable

    def test_a_removed_directory_takes_its_contents(self):                 # Codex r2 R4
        l1 = tar_bytes([("srv/old", None, 0o755), ("srv/old/tzdata.txt", b"x", 0o644), ("srv/oldest", b"y", 0o644)])
        l2 = tar_bytes([("srv/.wh.old", b"", 0o644)])
        oci_archive(os.path.join(self.d, "y.oci"), [l1, l2])
        paths = P.read_image(os.path.join(self.d, "y.oci"), "arm64")["paths"]
        self.assertEqual([p for p in paths if p.startswith("/srv")], ["/srv/oldest"])

    def test_no_image_for_the_architecture(self):
        with self.assertRaises(ValueError):
            P.read_image(self.make(), "s390x")

    def test_go_build_info_runs_go_version_m(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=0, stdout="%s: go1.26.6\n\tdep\tgolang.org/x/sys\tv0.47.0\n" % cmd[-1])
        info = P.go_buildinfo({"/usr/bin/cache": GO_BIN}, run=run)
        self.assertEqual(calls[0][:3], ["go", "version", "-m"])
        self.assertIn("/usr/bin/cache: go1.26.6", info["/usr/bin/cache"])
        self.assertFalse(os.path.exists(calls[0][-1]))         # the temp copy is removed
        bad = P.go_buildinfo({"/x": GO_BIN}, run=lambda c, **k: types.SimpleNamespace(returncode=1, stdout="junk"))
        self.assertEqual(bad, {"/x": ""})

    def test_bundle_quotes_records_paths_and_build_info_and_states_absence(self):
        facts = P.read_image(self.make(), "arm64")
        info = {"/usr/bin/cache": "go1.26.6\n\tdep\tgolang.org/x/sys\tv0.47.0\n"}
        f = {"image": "fips-arm64", "package": "tzdata", "version": "2026c-0+deb13u1", "seen_by": ["scout"]}
        b = P.bundle_text(facts, info, f)
        self.assertIn("Package: tzdata\nVersion: 2026c-0+deb13u1", b)
        self.assertIn("file: /usr/share/zoneinfo/tzdata.zi", b)
        self.assertIn("go build info: no Go binary in the image records tzdata", b)
        g = P.bundle_text(facts, info, dict(f, package="golang.org/x/sys", version="v0.47.0"))
        self.assertIn("go build info /usr/bin/cache: dep\tgolang.org/x/sys\tv0.47.0", g)
        self.assertIn("package database: no record names golang.org/x/sys", g)
        self.assertIn("files: no path in the image mentions golang.org/x/sys", g)
        src = {"paths": [], "status": {"/s": "Package: libc-bin\nSource: glibc (2.36)\n"}, "gobins": {}}
        self.assertIn("Package: libc-bin", P.bundle_text(src, {}, dict(f, package="glibc")))

    def test_bundles_read_each_image_once_and_survive_a_bad_image(self):
        calls = []

        def read(path, arch):
            calls.append((os.path.basename(path), arch))
            if "debug" in path:
                raise ValueError("no linux/amd64 image")
            return {"paths": ["/x/tzdata"], "status": {}, "gobins": {}}
        B = P.Bundles(self.d, read=read, buildinfo=lambda g: {})
        f = {"image": "fips-arm64", "package": "tzdata", "version": "1", "seen_by": ["scout"]}
        B(f); B(f)
        self.assertEqual(calls, [("fips.oci", "arm64")])
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertIn("could not be read", B(dict(f, image="debug-amd64")))
        self.assertIn("no evidence from image debug-amd64", err.getvalue())


class Prompts(unittest.TestCase):
    def test_sections_and_rendering(self):
        req = {"mode": "case", "finding": {"id": "CVE-1"}, "bundle": "BUNDLE-TEXT", "own_case": None,
               "opponent_case": "theirs", "scoring": "SCORING-TEXT"}
        t = P.render(req)
        for want in ("BUNDLE-TEXT", "theirs", "(none)", "SCORING-TEXT", '"id": "CVE-1"'):
            self.assertIn(want, t)
        for k in ("audit", "verdict"):
            self.assertTrue(P.prompt_section(k))
        with self.assertRaises(RuntimeError):
            P.prompt_section("nope")

    def test_prompts_name_no_vendor(self):                                  # REQ-SCAN-008-AC3 (public text)
        self.assertIsNone(P.VENDOR_WORDS.search(open(P.PROMPTS).read()))

    def test_answers_are_one_json_object(self):
        self.assertEqual(P._answer('text {"verdict": "real", "x": "}"} tail'), {"verdict": "real", "x": "}"})
        self.assertEqual(P._answer("{not json} [1] {\"a\": 1}"), {"a": 1})
        self.assertEqual(P._answer("no object"), {"error": "no JSON answer"})
        self.assertIsNone(P.extract_json('["list only"]'))


class Seats(Tmp):                                                           # REQ-SCAN-008-AC3
    def test_seat_a_uses_the_federated_sdk_and_the_configured_model(self):
        created = []

        class Msgs:
            def create(self, **kw):
                created.append(kw)
                return types.SimpleNamespace(content=[types.SimpleNamespace(text='{"verdict": "false", "evidence": []}')])
        fake = types.ModuleType("anthropic")
        fake.Anthropic = lambda: types.SimpleNamespace(messages=Msgs())
        tok = os.path.join(self.d, "a-token")
        minted = []
        with mock.patch.dict(sys.modules, {"anthropic": fake}):
            ask = P.seat_a({"PANEL_AUDIT_A_MODEL": "model-a", "ANTHROPIC_IDENTITY_TOKEN_FILE": tok},
                           mint=lambda aud: minted.append(aud) or "jwt-%d" % len(minted))
        self.assertEqual(open(tok).read(), "jwt-1")                          # minted before the client exchanges it
        a = ask({"mode": "audit", "finding": {}, "bundle": "b"})
        self.assertEqual((a["verdict"], a["_tokens"]), ("false", 0))
        self.assertEqual(created[0]["model"], "model-a")
        self.assertNotIn("api_key", created[0])
        self.assertEqual(minted, ["https://api.anthropic.com"])

    def test_the_token_file_is_reminted_when_it_ages(self):                # Codex r1 B6
        now = [1000.0]
        minted = []
        tf = P.TokenFile(os.path.join(self.d, "t"), "aud", mint=lambda a: minted.append(a) or "t%d" % len(minted),
                         clock=lambda: now[0], max_age=240)
        tf.fresh(); tf.fresh()
        now[0] += 241
        tf.fresh()
        self.assertEqual((len(minted), open(os.path.join(self.d, "t")).read()), (2, "t2"))

    def test_mint_oidc_asks_the_jobs_endpoint_and_masks_the_token(self):
        seen = {}

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            seen["url"], seen["auth"] = req.full_url, req.get_header("Authorization")
            return Resp(b'{"value": "jwt-value"}')
        env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://x/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req"}
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(P.mint_oidc("https://api.openai.com/v1", env=env, opener=opener), "jwt-value")
        self.assertEqual(seen["url"], "https://x/token?api-version=2.0&audience=https%3A%2F%2Fapi.openai.com%2Fv1")
        self.assertEqual(seen["auth"], "bearer req")
        self.assertIn("::add-mask::jwt-value", out.getvalue())
        with self.assertRaises(RuntimeError):
            P.mint_oidc("aud", env={})

    def test_the_budget_stops_asking_and_counts_usage(self):              # Codex r1 B7
        b = P.Budget(100)
        ask = b.wrap(lambda r: {"verdict": "real", "_tokens": 80})
        self.assertEqual(ask({})["verdict"], "real")
        self.assertNotIn("_tokens", ask({}))
        self.assertEqual(b.used, 160)
        self.assertIn("token budget is spent", ask({})["error"])
        self.assertTrue(b.stopped)
        self.assertIsNone(P.Budget(10).wrap(lambda r: None)({}))

    def test_seat_b_federates_without_a_key(self):
        made = {}

        class Responses:
            def create(self, **kw):
                made["call"] = kw
                return types.SimpleNamespace(output_text='{"verdict": "real", "evidence": ["x"]}',
                                             usage=types.SimpleNamespace(total_tokens=321))

        def OpenAI(**kw):
            made["client"] = kw
            return types.SimpleNamespace(responses=Responses())
        fake = types.ModuleType("openai")
        fake.OpenAI = OpenAI
        env = {"PANEL_AUDIT_B_IDENTITY_PROVIDER_ID": "idp_x",
               "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID": "sa_x", "PANEL_AUDIT_B_PROJECT_ID": "proj_x", "PANEL_AUDIT_B_MODEL": "model-b"}
        with mock.patch.dict(sys.modules, {"openai": fake}):
            ask = P.seat_b(env, mint=lambda aud: "fresh-jwt-for " + aud)
        a = ask({"mode": "audit", "finding": {}, "bundle": "b"})
        self.assertEqual((a["verdict"], a["_tokens"]), ("real", 321))
        self.assertEqual(made["call"]["max_output_tokens"], 4096)
        wi = made["client"]["workload_identity"]
        self.assertEqual((wi["identity_provider_id"], wi["service_account_id"], wi["provider"]["token_type"]),
                         ("idp_x", "sa_x", "jwt"))
        self.assertEqual(wi["provider"]["get_token"](), "fresh-jwt-for https://api.openai.com/v1")   # minted per exchange
        self.assertEqual(made["client"]["project"], "proj_x")
        self.assertNotIn("api_key", made["client"])
        self.assertEqual(made["call"]["model"], "model-b")

    def test_make_seats(self):
        none = P.make_seats("none")
        self.assertEqual(none["A"]({}), {"error": "no auditor in this run (none)"})

        def boom(env):
            raise ImportError("no module named openai; key sk-abcdef123456 gpt-9")
        seats = P.make_seats("real", env={}, a=lambda env: (lambda r: {"verdict": "real"}), b=boom)
        self.assertEqual(seats["A"]({}), {"verdict": "real"})
        err = seats["B"]({})["error"]
        self.assertIn("seat B could not start: ImportError", err)
        self.assertNotIn("gpt-9", err)

    def test_public_masks_identifiers_and_names(self):
        with mock.patch.dict(os.environ, {"PANEL_AUDIT_B_PROJECT_ID": "proj_secret_1", "PANEL_AUDIT_A_MODEL": "abc"}):
            self.assertEqual(P.public("proj_secret_1 via openai and claude-x; abc"),
                             "<PANEL_AUDIT_B_PROJECT_ID> via <auditor> and <auditor>; <PANEL_AUDIT_A_MODEL>")
        self.assertIsNone(P.public(None))


def verdict_file(d, findings):
    p = os.path.join(d, "verdict.json")
    json.dump({"findings": findings}, open(p, "w"))
    return p


UNIQUE = {"image": "fips-arm64", "id": "CVE-2099-0002", "package": "tzdata", "version": "2026c-0+deb13u1",
          "seen_by": ["scout"], "of": 3, "unique": True, "status": "unique",
          "purls": ["pkg:deb/debian/tzdata@2026c-0%2Bdeb13u1"]}
BUNDLE = ("image fips-arm64 (tzdata 2026c-0+deb13u1)\n" + P.EVIDENCE_MARK +
          "\nPackage: tzdata\nVersion: 2026c-0+deb13u1\n/usr/share/zoneinfo/tzdata.zi (version 2026a)\n")


def args(**kw):
    return types.SimpleNamespace(**kw)


class Judge(Tmp):
    def a(self, **kw):
        base = dict(verdict=verdict_file(self.d, [UNIQUE]), state=os.path.join(self.d, "none.json"),
                    profiles=os.path.join(REPO, ".github", "policy", "scanner-profiles.json"), oci=self.d,
                    out=os.path.join(self.d, "out"), seats="none", today="2026-10-03", token_budget=200000)
        base.update(kw)
        return args(**base)

    def test_missing_verdict_is_a_failure(self):
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(self.a(verdict=os.path.join(self.d, "missing.json"))), 2)
        self.assertIn("no panel verdict", err.getvalue())

    def test_invalid_profiles_stop_the_judgment(self):
        bad = os.path.join(self.d, "p.json")
        json.dump({"entries": [{"scanner": "nope"}]}, open(bad, "w"))
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(self.a(profiles=bad)), 2)
        self.assertIn("scanner profiles", err.getvalue())

    def test_no_auditor_errors_are_reported_and_false_by_default(self):
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(P.cmd_judge(self.a(), bundles=lambda f: BUNDLE), 0)
        day = json.load(open(os.path.join(self.d, "out", "day.json")))
        self.assertEqual(day["log"][0]["status"], "false-default")
        self.assertIn("::warning::scanner panel audit error (vendor A)", out.getvalue())
        self.assertIn("2 audit error(s)", open(os.path.join(self.d, "out", "summary.md")).read())
        st = json.load(open(os.path.join(self.d, "out", "state.json")))
        self.assertEqual(st["false"][0]["id"], "CVE-2099-0002")

    def test_a_spent_budget_is_reported(self):                            # Codex r1 B7
        seats = {"A": lambda r: {"verdict": "real", "evidence": [], "_tokens": 5}, "B": lambda r: {"error": "x"}}
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(P.cmd_judge(self.a(token_budget=0), seats=seats, bundles=lambda f: BUNDLE), 0)
        self.assertIn("token budget (0) is spent", out.getvalue())
        self.assertIn("STOPPED at the budget", open(os.path.join(self.d, "out", "summary.md")).read())

    def test_real_seats_judge_with_the_bundle(self):
        good = {"verdict": "real", "evidence": ["Package: tzdata Version: 2026c-0+deb13u1"], "why": "reads status.d",
                "case": "listed"}
        seats = {"A": lambda r: good, "B": lambda r: good}
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(P.cmd_judge(self.a(), seats=seats, bundles=lambda f: BUNDLE), 0)
        day = json.load(open(os.path.join(self.d, "out", "day.json")))
        self.assertIn("CVE-2099-0002", day["issue"])
        self.assertEqual(day["profiles"][0]["behavior"], "reads status.d")


class Deliver(Tmp):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.d, "repo")
        for rel, obj in ((P.VEX, {"@id": "https://x/vex", "version": 3, "timestamp": "t", "statements": []}),
                         (P.PROFILES, {"entries": []})):
            os.makedirs(os.path.dirname(os.path.join(self.repo, rel)), exist_ok=True)
            json.dump(obj, open(os.path.join(self.repo, rel), "w"))
        self.out = os.path.join(self.d, "out")
        os.makedirs(self.out)

    def day(self, **kw):
        st = {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"}
        d = {"issue": "", "vex": [], "profiles": [], "owner": [], "misses": [], "log": []}
        d.update(kw)
        json.dump(st, open(os.path.join(self.out, "state.json"), "w"))
        json.dump(d, open(os.path.join(self.out, "day.json"), "w"))

    def a(self, dry=False):
        return args(out=self.out, repo=self.repo, dry_run=dry, today="2026-10-03")

    def fake(self, outputs=None):
        calls = []

        def run(cmd, **kw):
            calls.append((cmd, kw.get("env", {}).get("GH_TOKEN")))
            out = (outputs or {}).get(tuple(cmd[:3]), "")
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
        return calls, run

    def test_nothing_to_deliver(self):
        with mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(P.cmd_deliver(self.a()), 2)

    def test_dry_run_only_plans(self):                                       # rule 0
        self.day(issue="tracking text", owner=["for the owner"])
        calls, run = self.fake()
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1"}), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(P.cmd_deliver(self.a(dry=True), run=run), 0)
        self.assertEqual(calls, [])
        plan = json.load(open(os.path.join(self.out, "plan.json")))
        self.assertFalse(plan["real"])
        self.assertEqual(plan["changed"], [P.STATE])
        self.assertTrue(any(c[:3] == ["gh", "pr", "create"] for c in plan["commands"]))

    def test_changes_go_through_a_pull_request_and_issues(self):           # REQ-SCAN-009-AC1, AC5, 013-AC4, 014-AC2
        self.day(issue="CVE-2099-0002 confirmed", owner=["the primary seat moves from vendor A to vendor B"],
                 vex=[{"image": "fips-arm64", "id": "CVE-2099-0003", "package": "tzdata", "version": "1",
                       "status": "not_affected", "purls": ["pkg:deb/debian/tzdata@1"],
                       "impact_statement": "Audited from the image: Version: 2"}],
                 profiles=[{"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"},
                            "behavior": "unexplained", "finding": "f", "evidence": "e", "unexplained": True}])
        calls, run = self.fake()
        env = {"AUDITOR_ALLOW_REAL_GH": "1", "AUDITOR_ISSUES_TOKEN": "issues-token", "GH_TOKEN": "app-token",
               "GITHUB_SHA": "abc123"}
        with mock.patch.dict(os.environ, env), mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(P.cmd_deliver(self.a(), run=run), 0)
        cmds = [c for c, _ in calls]
        self.assertEqual(cmds[0][:3], ["gh", "pr", "list"])
        self.assertEqual(cmds[1], ["git", "-C", self.repo, "checkout", "--force", "-B", "auditor/panel", "abc123"])
        self.assertEqual(cmds[2][:4], ["git", "-C", self.repo, "add"])
        self.assertEqual(sorted(cmds[2][5:]), sorted([P.STATE, P.VEX, P.PROFILES]))
        self.assertEqual(cmds[4][-1], "HEAD:refs/heads/auditor/panel")        # never main
        self.assertTrue(any(c[:4] == ["gh", "pr", "create", "--draft"] for c in cmds))
        issue_calls = [(c, t) for c, t in calls if c[:2] == ["gh", "issue"]]
        self.assertTrue(all(t == "issues-token" for _, t in issue_calls))
        self.assertTrue(any(c[:3] == ["gh", "issue", "create"] and "daily-rescan" in c and
                            "auditor: Daily scanner panel: findings on main" in c for c, _ in issue_calls))
        self.assertTrue(any("owner-decision" in c for c, _ in issue_calls))
        vex = json.load(open(os.path.join(self.repo, P.VEX)))
        st = vex["statements"][0]
        self.assertEqual((st["status"], st["justification"], vex["version"]), ("not_affected", "component_not_present", 4))
        self.assertEqual(st["products"][0]["subcomponents"], [{"@id": "pkg:deb/debian/tzdata@1"}])
        for c in cmds:                                                         # no vendor or model name anywhere
            self.assertIsNone(P.VENDOR_WORDS.search(" ".join(c)))

    def test_one_statement_per_scope_and_auto_merge_only_when_on_and_no_profile_change(self):
        prop = {"image": "fips-arm64", "id": "CVE-2099-0004", "package": "tzdata", "version": "1",
                "status": "not_affected", "purls": ["pkg:deb/debian/tzdata@1"], "impact_statement": "x"}
        self.day(vex=[prop, dict(prop)])
        calls, run = self.fake()
        env = {"AUDITOR_ALLOW_REAL_GH": "1", "AUDITOR_AUTOMERGE": "on"}
        with mock.patch.dict(os.environ, env), mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_deliver(self.a(), run=run)
        self.assertEqual(len(json.load(open(os.path.join(self.repo, P.VEX)))["statements"]), 1)
        cmds = [c for c, _ in calls]
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "auditor/panel"], cmds)
        self.assertTrue(P.automerge_allowed([P.STATE, P.VEX], env={"AUDITOR_AUTOMERGE": "on"}))
        self.assertFalse(P.automerge_allowed([P.STATE, P.PROFILES], env={"AUDITOR_AUTOMERGE": "on"}))
        self.assertFalse(P.automerge_allowed([P.STATE], env={}))

    def test_existing_pr_and_issue_are_updated_and_affected_turns(self):
        vpath = os.path.join(self.repo, P.VEX)
        mine = {"image": "fips-arm64", "id": "CVE-2099-0003", "package": "tzdata", "version": "1",
                "purls": ["pkg:deb/debian/tzdata@1"]}
        other_image = dict(mine, image="fips-amd64")
        json.dump({"@id": "https://x/vex", "statements": [
            {"@id": P.statement_id(mine), "vulnerability": {"name": "CVE-2099-0003"},
             "status": "not_affected", "justification": "component_not_present", "impact_statement": "old"},
            {"@id": "https://x/vex#stmt-cve-2099-0003", "vulnerability": {"name": "CVE-2099-0003"}, "status": "not_affected"},
            {"@id": P.statement_id(other_image), "vulnerability": {"name": "CVE-2099-0003"}, "status": "not_affected"}]},
            open(vpath, "w"))
        self.day(issue="miss", owner=["an audit miss"],
                 vex=[dict(mine, status="affected", impact_statement="another scanner reported it")])
        calls, run = self.fake({("gh", "pr", "list"): "17\n", ("gh", "issue", "list"): "42\n",
                                ("gh", "pr", "diff"): ".github/policy/scanner-profiles.json\n.auditor/panel-state.json\n"})
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1", "AUDITOR_AUTOMERGE": "on"}), \
                mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_deliver(self.a(), run=run)
        cmds = [c for c, _ in calls]
        self.assertNotIn(["gh", "pr", "merge", "--auto", "--squash", "auditor/panel"], cmds)   # the open PR holds a profile entry (r2 R7)
        self.assertIn(["git", "-C", self.repo, "fetch", "origin", "auditor/panel"], cmds)   # builds on the open PR
        self.assertIn(["git", "-C", self.repo, "checkout", "--force", "-B", "auditor/panel", "FETCH_HEAD"], cmds)
        self.assertIn(["gh", "pr", "edit", "17"], [c[:4] for c in cmds])
        self.assertIn(["gh", "issue", "comment", "42"], [c[:4] for c in cmds])
        stmts = json.load(open(vpath))["statements"]
        self.assertEqual(stmts[0]["status"], "affected")
        self.assertNotIn("justification", stmts[0])
        self.assertEqual(stmts[1]["status"], "not_affected")                 # only the panel's own statement turns
        self.assertEqual(stmts[2]["status"], "not_affected")                 # same CVE, another image: untouched
        self.assertEqual([c[:4] for c in cmds].count(["gh", "issue", "comment", "42"]), 2)   # tracking + owner, updated

    def test_a_failed_command_stops_delivery_with_a_masked_error(self):
        self.day(issue="x")

        def run(cmd, **kw):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="denied for openai seat")
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1"}), self.assertRaises(RuntimeError) as e:
            P.cmd_deliver(self.a(), run=run)
        self.assertNotIn("openai", str(e.exception))


sys.path.insert(0, os.path.join(BIN, "..", "fixtures", "testlib"))
import pyyaml as yaml  # noqa: E402  (vendored, test-only)


class Wiring(unittest.TestCase):                                            # REQ-SCAN-008-AC10, REQ-SCAN-009-AC5
    """The audits and debates run in the auditor's daily run, right after the rescan, in one of its steps."""

    def setUp(self):
        self.wf = yaml.safe_load(open(os.path.join(REPO, ".github", "workflows", "auditor.yml")))
        self.steps = self.wf["jobs"]["audit"]["steps"]
        self.names = [st.get("name", "") for st in self.steps]

    def step(self, needle):
        return next(i for i, st in enumerate(self.steps) if needle in (st.get("run") or ""))

    def test_one_step_judges_after_the_rescan_in_the_daily_run(self):
        on = self.wf.get("on", self.wf.get(True))
        self.assertIn("schedule", on)
        rescan = self.step("gh run list --workflow main-candidate-rescan.yml")
        self.assertIn("-n panel-evidence", self.steps[rescan]["run"])
        judges = [i for i, st in enumerate(self.steps) if "auditor-panel.py judge" in (st.get("run") or "")]
        self.assertEqual(len(judges), 1)
        self.assertGreater(judges[0], rescan)
        self.assertIn("--verdict \"${RUNNER_TEMP}/panel/verdict.json\"", self.steps[judges[0]]["run"])
        self.assertIn("always()", self.steps[judges[0]]["if"])               # not skipped when the CVE audit fails

    def test_both_seats_are_keyless_and_named_only_by_secrets(self):        # REQ-SCAN-008-AC3
        j = self.steps[self.step("auditor-panel.py judge")]
        env = j["env"]
        for k, v in env.items():
            self.assertFalse(str(v).startswith("${{ vars."), k)
            if k.endswith(("_ID", "_MODEL")):
                self.assertTrue(str(v).startswith("${{ secrets."), k)
        self.assertNotIn("API_KEY", " ".join(env))
        self.assertEqual(self.wf["jobs"]["audit"]["permissions"]["id-token"], "write")   # the step mints its own tokens
        self.assertIn("--token-budget 200000", j["run"])                             # REQ-AUD-6 AC2, in the workflow

    def test_state_comes_only_from_an_open_panel_pr_or_main(self):         # Codex r1 R3
        run = self.steps[self.step("auditor-panel.py judge")]["run"]
        self.assertIn("gh pr list --head auditor/panel --state open", run)
        self.assertIn('[ -n "$open_pr" ] && git fetch', run)

    def test_the_seat_never_moves_the_daily_cve_auditor(self):             # REQ-SCAN-014-AC3
        cve = self.steps[self.step("auditor-run.py")]
        self.assertEqual(cve["env"]["AUDITOR_MODEL_PRIMARY"], "${{ secrets.AUDITOR_MODEL_PRIMARY }}")
        self.assertFalse([k for k in cve["env"] if k.startswith("PANEL_")])
        self.assertNotIn("panel", cve["run"])
        self.assertLess(self.step("auditor-run.py"), self.step("auditor-panel.py judge"))   # it runs before the panel
        # the CVE auditor's code never reads the panel's state or its seat
        cve_code = ["auditor-run.py", "auditor-adjudicator-client.py", "auditor-adjudicate.py"] + \
            [os.path.join("auditorlib", n) for n in os.listdir(os.path.join(BIN, "auditorlib")) if n.endswith(".py")]
        for name in cve_code:
            text = open(os.path.join(BIN, name)).read()
            self.assertNotIn("panel-state", text, name)
            self.assertNotIn("PANEL_AUDIT", text, name)

    def test_delivery_is_the_auditor_lane_only(self):                       # rule 0
        d = self.steps[self.step("auditor-panel.py deliver")]
        self.assertIn("steps.panel.outcome == 'success'", d["if"])
        self.assertEqual(d["env"]["AUDITOR_ISSUES_TOKEN"], "${{ github.token }}")
        self.assertEqual(d["env"]["AUDITOR_AUTOMERGE"], "${{ vars.AUDITOR_AUTOMERGE }}")   # Codex r2 B6: the switch arrives


class Main(Tmp):
    def test_dispatch(self):
        seen = []
        P.main(["judge", "--verdict", "v", "--state", "s", "--profiles", "p", "--oci", "o", "--out", "x", "--seats", "real"],
               judge=lambda a: seen.append(("judge", a.seats)) or 0)
        P.main(["deliver", "--out", "x", "--dry-run"], deliver=lambda a: seen.append(("deliver", a.dry_run)) or 0)
        self.assertEqual(seen, [("judge", "real"), ("deliver", True)])

    def test_runs_as_a_script(self):
        with mock.patch.object(sys, "argv", ["auditor-panel.py", "deliver", "--out", self.d]), \
                mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as e:
            runpy.run_path(PATH, run_name="__main__")
        self.assertEqual(e.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
