# proves: REQ-SCAN-008-AC3, REQ-SCAN-008-AC5, REQ-SCAN-008-AC10, REQ-SCAN-009-AC1, REQ-SCAN-009-AC5, REQ-SCAN-013-AC4, REQ-SCAN-014-AC2, REQ-SCAN-014-AC3
"""The scanner panel audits' input and output (scanner-panel rules 8, 9, 13, 14; owner Oct 2-3).

The evidence bundle is read from a synthetic OCI archive; both seats run against fake SDK modules (no network, no
key); delivery runs against a fake git/gh that records every command. Asserts: the evidence an auditor may quote,
keyless seat construction with identifiers only from the environment, masking, the judge and deliver commands, and
that every change reaches main only as a pull request (rule 0) while issues carry the tracking and owner reports.
"""
import gzip, hashlib, importlib.util, io, json, os, re, runpy, subprocess, sys, tarfile, tempfile, types, unittest
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


HEAD = "a" * 40
MAIN = "b" * 40
DIGEST = "sha256:" + "c" * 64


def rescan_oci(d, variant="fips", digest=DIGEST, blob=True, arch="arm64", readable=True):
    """A rescan OCI archive whose top-level index names exactly one manifest at `digest` — genuinely readable by
    read_image() for `arch` (Codex #177 r2, B2: a present member alone proves nothing; the evidence must actually
    parse the same way Bundles() reads it), unless blob=False (no blob at all) or readable=False (present but not a
    real manifest — the getmember-only check of r1's fix passed this, r2 correctly still refuses it)."""
    path = os.path.join(d, variant + ".oci")
    if not readable:
        with tarfile.open(path, "w") as t:
            ti = tarfile.TarInfo("index.json")
            raw = json.dumps({"schemaVersion": 2, "manifests": [{"digest": digest}]}).encode()
            ti.size = len(raw); t.addfile(ti, io.BytesIO(raw))
            if blob:
                bi = tarfile.TarInfo("blobs/" + digest.replace(":", "/")); bi.size = 1
                t.addfile(bi, io.BytesIO(b"{"))   # present, but not parseable JSON
        return
    man = json.dumps({"layers": []}).encode()
    man_digest = "sha256:" + hashlib.sha256(man).hexdigest()
    index = json.dumps({"manifests": [{"digest": digest, "platform": {"os": "linux", "architecture": arch}}]}).encode()
    files = [("index.json", index, 0o644), ("blobs/" + digest.replace(":", "/"), man, 0o644)]
    if digest != man_digest:
        files.append(("blobs/" + man_digest.replace(":", "/"), man, 0o644))
    with open(path, "wb") as fh:
        fh.write(tar_bytes(files, gz=False))


def binding(d, **kw):
    b = dict(run_id="123", head=HEAD, main_head=HEAD, conclusion="success")
    b.update(kw)
    raw = json.dumps(b, sort_keys=True)
    p = os.path.join(d, "rescan-%s.json" % hashlib.sha256(raw.encode()).hexdigest()[:12])   # one file per binding
    open(p, "w").write(raw)
    return p


class Judge(Tmp):
    def a(self, **kw):
        rescan_oci(self.d)
        base = dict(verdict=verdict_file(self.d, [UNIQUE]), state=os.path.join(self.d, "none.json"),
                    profiles=os.path.join(REPO, ".github", "policy", "scanner-profiles.json"), oci=self.d,
                    out=os.path.join(self.d, "out"), seats="none", today="2026-10-03", token_budget=200000)
        base.update(kw)
        if "rescan" not in base:
            base["rescan"] = binding(self.d)
        return args(**base)

    # owner RATIFIED Oct 3 (item a; advisor 0113, 0136): the judgment is bound to the rescan's own head and image digests;
    # main having moved past it, or a red conclusion, is reported, never a failure; no binding or no digests is refused
    def judged(self, **kw):
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(P.cmd_judge(self.a(**kw), bundles=lambda f: BUNDLE), 0)
        day = json.load(open(os.path.join(self.d, "out", "day.json")))
        return out.getvalue(), open(os.path.join(self.d, "out", "summary.md")).read(), day

    def test_the_judgment_names_the_scanned_run_head_and_digests(self):
        _, summary, day = self.judged()
        self.assertIn("rescan run 123 of main at %s (conclusion success)" % HEAD, summary)
        self.assertIn("fips %s" % DIGEST, summary)
        self.assertEqual(day["rescan"], {"run_id": "123", "head": HEAD, "main_head": HEAD, "conclusion": "success",
                                         "digests": {"fips": DIGEST}})
        self.assertFalse([o for o in day["owner"] if "rescan" in o])

    def test_main_moved_past_the_scanned_head_warns_and_reports(self):
        out, summary, day = self.judged(rescan=binding(self.d, main_head=MAIN))
        self.assertIn("::warning::scanner panel: main has moved past the scanned head %s" % HEAD, out)
        self.assertTrue([o for o in day["owner"] if "main has moved past the scanned head %s" % HEAD in o and MAIN in o])

    def test_a_red_rescan_is_judged_and_its_conclusion_named(self):
        _, summary, day = self.judged(rescan=binding(self.d, conclusion="failure"))
        self.assertIn("(conclusion failure)", summary)
        self.assertTrue([o for o in day["owner"] if "rescan run 123 finished failure" in o])

    def test_no_binding_or_no_digests_is_refused(self):
        junk = os.path.join(self.d, "junk.json"); open(junk, "w").write("not json")
        for bad in (os.path.join(self.d, "missing.json"), junk, binding(self.d, head="x"), binding(self.d, run_id=""),
                    binding(self.d, main_head=None), binding(self.d, conclusion="")):
            with mock.patch("sys.stderr", new=io.StringIO()) as err:
                self.assertEqual(P.cmd_judge(self.a(rescan=bad)), 2)
            self.assertIn("no rescan binding", err.getvalue())
        empty = os.path.join(self.d, "empty"); os.makedirs(empty)
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(self.a(oci=empty)), 2)
        self.assertIn("no image digest", err.getvalue())
        bad_oci = os.path.join(self.d, "bad"); os.makedirs(bad_oci); open(os.path.join(bad_oci, "x.oci"), "w").write("junk")
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(self.a(oci=bad_oci)), 2)
        self.assertIn("no image digest", err.getvalue())

    # Codex #177 r1, B2: a syntactically valid digest over a missing/unreadable blob, or an archive missing entirely
    # for an image the verdict judges, must refuse — never fall through to "no evidence, false by default"
    def test_a_digest_whose_blob_is_missing_is_refused(self):
        unreadable = os.path.join(self.d, "unreadable"); os.makedirs(unreadable)
        rescan_oci(unreadable, readable=False, blob=False)
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(self.a(oci=unreadable)), 2)
        self.assertIn("no image digest", err.getvalue())

    # Codex #177 r2, B2 (reopened): a member present in the archive (passes getmember) but not a real, parseable
    # manifest must still refuse — read_image() is actually tried, the same way Bundles() reads it for real
    def test_a_present_but_unparseable_blob_is_refused(self):
        unparseable = os.path.join(self.d, "unparseable"); os.makedirs(unparseable)
        rescan_oci(unparseable, readable=False, blob=True)   # the blob exists, but its bytes are "{" (truncated JSON)
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(self.a(oci=unparseable)), 2)
        self.assertIn("missing or unreadable for fips-arm64", err.getvalue())

    def test_an_image_the_verdict_judges_with_no_archive_at_all_is_refused(self):
        no_production = os.path.join(self.d, "no-production"); os.makedirs(no_production)
        rescan_oci(no_production, variant="fips")   # UNIQUE's image is fips-arm64: only this one is needed to pass
        args = self.a(oci=no_production)
        verdict_file(self.d, [UNIQUE, dict(UNIQUE, image="production-arm64")])   # args.verdict is this same path
        with mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(P.cmd_judge(args), 2)
        self.assertIn("missing or unreadable for production-arm64", err.getvalue())

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

    def test_an_sdk_exception_never_publishes_its_vendor_named_class(self):   # Codex p2-r2 blocker
        OpenAIError = type("OpenAIError", (Exception,), {})
        AnthropicError = type("AnthropicError", (Exception,), {})

        def b(r):
            raise OpenAIError("Token exchange failed with status 500")

        def a(r):
            raise AnthropicError("AnthropicAPIError: overloaded")
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(P.cmd_judge(self.a(), seats={"A": a, "B": b}, bundles=lambda f: BUNDLE), 0)
        published = out.getvalue() + open(os.path.join(self.d, "out", "day.json")).read() + \
            open(os.path.join(self.d, "out", "summary.md")).read() + open(os.path.join(self.d, "out", "state.json")).read()
        self.assertIn("Token exchange failed with status 500", published)
        for name in ("openai", "anthropic"):
            self.assertNotIn(name, published.lower())

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
        ss = os.path.join(self.d, "state-source"); open(ss, "w").write("")      # the fake rev-parse answers "": the judgment read the same tip
        return args(out=self.out, repo=self.repo, dry_run=dry, today="2026-10-03", state_source=ss)

    def fake(self, outputs=None):
        calls = []

        def run(cmd, **kw):
            calls.append((cmd, kw.get("env", {}).get("GH_TOKEN")))
            out = (outputs or {}).get(tuple(cmd[:3]), "")
            if cmd[:2] == ["gh", "api"] and "check-runs" in cmd[2]:
                out = "success"
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

    def test_a_profile_entry_already_in_the_file_is_not_added_again(self):  # Sonnet r3 blocker
        entry = {"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"}, "behavior": "b",
                 "finding": "f", "evidence": "e"}
        json.dump({"entries": [entry]}, open(os.path.join(self.repo, P.PROFILES), "w"))
        self.day(profiles=[dict(entry, finding="another day")])
        calls, run = self.fake()
        with mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_deliver(self.a(dry=True), run=run)
        self.assertEqual(len(json.load(open(os.path.join(self.repo, P.PROFILES)))["entries"]), 1)
        self.assertNotIn(P.PROFILES, json.load(open(os.path.join(self.out, "plan.json")))["changed"])

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
        other_image = dict(mine, package="busybox", purls=["pkg:generic/busybox@1"])   # same CVE, another package
        json.dump({"@id": "https://x/vex", "statements": [
            {"@id": P.statement_id(mine), "vulnerability": {"name": "CVE-2099-0003"},
             "status": "not_affected", "justification": "component_not_present", "impact_statement": "old"},
            {"@id": "https://x/vex#stmt-cve-2099-0003", "vulnerability": {"name": "CVE-2099-0003"}, "status": "not_affected"},
            {"@id": P.statement_id(other_image), "vulnerability": {"name": "CVE-2099-0003"}, "status": "not_affected"}]},
            open(vpath, "w"))
        self.day(issue="miss", owner=["an audit miss"],
                 vex=[dict(mine, status="affected", impact_statement="another scanner reported it")])
        calls, run = self.fake({("gh", "pr", "list"): "17\n", ("gh", "issue", "list"): "42\n", ("gh", "pr", "view"): "true\n",
                                ("gh", "pr", "diff"): ".github/policy/scanner-profiles.json\n.auditor/panel-state.json\n"})
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1", "AUDITOR_AUTOMERGE": "on"}), \
                mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_deliver(self.a(), run=run)
        cmds = [c for c, _ in calls]
        self.assertNotIn(["gh", "pr", "merge", "--auto", "--squash", "17"], cmds)   # the open PR holds a profile entry (r2 R7)
        # advisor 0186 (replaces "builds on the open PR's FETCH_HEAD", which left the branch behind main forever): the open PR's branch is
        # READ (fetched) so its files carry forward, but the branch is rebuilt on the run's main commit
        self.assertTrue(any(c[:4] == ["git", "-C", self.repo, "fetch"] and c[-1] == "auditor/panel" and "origin" in c for c in cmds))
        self.assertIn(["git", "-C", self.repo, "checkout", "--force", "-B", "auditor/panel", os.environ.get("GITHUB_SHA") or "HEAD"], cmds)
        self.assertNotIn(["git", "-C", self.repo, "checkout", "--force", "-B", "auditor/panel", "FETCH_HEAD"], cmds)
        self.assertIn(["gh", "pr", "edit", "17"], [c[:4] for c in cmds])
        self.assertIn(["gh", "issue", "comment", "42"], [c[:4] for c in cmds])
        stmts = json.load(open(vpath))["statements"]
        self.assertEqual(stmts[0]["status"], "affected")
        self.assertNotIn("justification", stmts[0])
        self.assertEqual(stmts[1]["status"], "not_affected")                 # only the panel's own statement turns
        self.assertEqual(stmts[2]["status"], "not_affected")                 # same CVE, another package: untouched
        self.assertIn(["gh", "pr", "merge", "--disable-auto", "17"], cmds)    # Codex r3 R5: disarmed, a profile entry is open
        self.assertEqual([c[:4] for c in cmds].count(["gh", "issue", "comment", "42"]), 2)   # tracking + owner, updated

    def test_an_armed_pr_is_disarmed_on_a_quiet_day_when_the_switch_is_off(self):   # Sonnet r4 residual
        st = {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"}
        os.makedirs(os.path.join(self.repo, ".auditor"), exist_ok=True)
        json.dump(st, open(os.path.join(self.repo, P.STATE), "w"), indent=1, sort_keys=True)
        self.day()                                                            # nothing new today
        calls, run = self.fake({("gh", "pr", "list"): "17\n", ("gh", "pr", "view"): "true\n"})
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1", "AUDITOR_AUTOMERGE": ""}), \
                mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_deliver(self.a(), run=run)
        cmds = [c for c, _ in calls]
        self.assertNotIn("commit", [c[3] for c in cmds if c[:1] == ["git"]])
        self.assertIn(["gh", "pr", "merge", "--disable-auto", "17"], cmds)
        calls, run = self.fake({("gh", "pr", "list"): "17\n", ("gh", "pr", "view"): "false\n"})
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1", "AUDITOR_AUTOMERGE": ""}), \
                mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_deliver(self.a(), run=run)
        self.assertNotIn(["gh", "pr", "merge", "--disable-auto", "17"], [c for c, _ in calls])   # not armed: left alone

    def test_a_failed_command_stops_delivery_with_a_masked_error(self):
        self.day(issue="x")

        def run(cmd, **kw):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="denied for openai seat")
        with mock.patch.dict(os.environ, {"AUDITOR_ALLOW_REAL_GH": "1"}), self.assertRaises(RuntimeError) as e:
            P.cmd_deliver(self.a(), run=run)
        self.assertNotIn("openai", str(e.exception))


class RebuildReal(Tmp):
    """advisor 0186 (REQ-AUD-17): with an open PR the branch is rebuilt on the run's CURRENT main commit and the PR's files carry forward.
    Real git against a local origin; only gh is faked."""

    VEXDOC = {"@id": "https://x/vex", "version": 1, "timestamp": "t", "statements": []}

    def git(self, *a, cwd=None):
        r = subprocess.run(["git", *a], cwd=cwd or self.work, capture_output=True, text=True)
        assert r.returncode == 0, (a, r.stderr)
        return r.stdout.strip()

    def write(self, rel, obj):
        path = os.path.join(self.work, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        json.dump(obj, open(path, "w"), indent=2)
        open(path, "a").write("\n")

    def stmt(self, name, status="not_affected"):
        return {"@id": "https://x/vex#" + name, "vulnerability": {"name": name}, "status": status}

    def setUp(self):
        super().setUp()
        self.origin = os.path.join(self.d, "origin.git")
        self.work = os.path.join(self.d, "work")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", self.origin], check=True)
        subprocess.run(["git", "clone", "-q", "file://" + self.origin, self.work], check=True, capture_output=True)
        for k, v in (("user.name", "t"), ("user.email", "t@x"), ("commit.gpgsign", "false")):
            self.git("config", k, v)
        self.write(P.VEX, dict(self.VEXDOC, statements=[self.stmt("CVE-0-BASE")]))
        self.write(P.PROFILES, {"entries": []})
        self.write(P.STATE, {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"})
        self.git("add", "-A"); self.git("commit", "-q", "-m", "m0"); self.git("branch", "-M", "main"); self.git("push", "-q", "origin", "main")
        self.m0 = self.git("rev-parse", "HEAD")
        # yesterday's panel PR: ONE commit on m0 carrying a pending VEX proposal and a pending profile entry
        self.git("checkout", "-q", "-b", "auditor/panel")
        doc = json.load(open(os.path.join(self.work, P.VEX))); doc["statements"].append(self.stmt("CVE-1-PANEL")); doc["version"] = 2
        self.write(P.VEX, doc)
        self.entry = {"scanner": "scout", "kind": "sees_alone", "match": {"package": "^tzdata$"}, "behavior": "b", "finding": "f", "evidence": "e"}
        self.write(P.PROFILES, {"entries": [self.entry]})
        self.git("add", "-A"); self.git("commit", "-q", "-m", "panel yesterday"); self.git("push", "-q", "origin", "auditor/panel")
        self.git("checkout", "-q", "main")
        # main moves on: the CVE auditor merged a suppression since
        doc = json.load(open(os.path.join(self.work, P.VEX))); doc["statements"].append(self.stmt("CVE-2-MAIN")); doc["version"] = 2
        self.write(P.VEX, doc)
        self.git("add", "-A"); self.git("commit", "-q", "-m", "m1 (main moved)"); self.git("push", "-q", "origin", "main")
        self.m1 = self.git("rev-parse", "HEAD")
        self.out = os.path.join(self.d, "out"); os.makedirs(self.out)
        self.guard = "success"
        self.pr_head = None

    def deliver(self, vex=(), existing="17", pr_files=None, env_extra=None, state_source=None, view_armed=False):
        st = {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A", "note": "today"}
        json.dump(st, open(os.path.join(self.out, "state.json"), "w"))
        json.dump({"issue": "", "vex": list(vex), "profiles": [], "owner": [], "misses": [], "log": []}, open(os.path.join(self.out, "day.json"), "w"))
        files = pr_files if pr_files is not None else "%s\n%s\n%s\n" % (P.PROFILES, P.STATE, P.VEX)
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if cmd[0] == "git":
                return subprocess.run(cmd, capture_output=True, text=True)
            out = {("gh", "pr", "list"): existing + "\n" if existing else "", ("gh", "pr", "diff"): files,
                   ("gh", "pr", "view"): "true\n" if view_armed else "false\n"}.get(tuple(cmd[:3]), "")
            if cmd[:2] == ["gh", "api"] and "check-runs" in cmd[2]:
                out = self.guard
            if cmd[:2] == ["gh", "api"] and "/pulls/" in cmd[2]:
                out = self.pr_head or subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.work, capture_output=True, text=True).stdout.strip()
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
        env = {"AUDITOR_ALLOW_REAL_GH": "1", "GITHUB_SHA": self.m1, "AUDITOR_AUTOMERGE": "on"}
        env.update(env_extra or {})
        if state_source is None:
            state_source = os.path.join(self.d, "ss-auto")
            open(state_source, "w").write(self.git("ls-remote", "origin", "refs/heads/auditor/panel").split()[0] if existing else "")
        a = types.SimpleNamespace(out=self.out, repo=self.work, dry_run=False, today="2026-10-06", state_source=state_source)
        with mock.patch.dict(os.environ, env), mock.patch("sys.stdout", new=io.StringIO()):
            rc = P.cmd_deliver(a, run=run)
        return rc, calls

    def pushed(self, path):
        return json.loads(self.git("show", "origin/auditor/panel:" + path, cwd=self.work))

    def test_the_rebuilt_branch_is_one_commit_on_the_runs_main_commit(self):
        rc, calls = self.deliver()
        self.assertEqual(rc, 0)
        self.git("fetch", "-q", "origin")
        self.assertEqual(self.git("rev-parse", "origin/auditor/panel^"), self.m1)                      # parent = today's main, not yesterday's
        self.assertEqual(self.git("rev-list", "--count", self.m1 + "..origin/auditor/panel"), "1")

    def test_the_open_prs_files_survive_and_mains_newer_changes_are_kept(self):
        self.deliver(vex=[{"image": "fips-arm64", "id": "CVE-3-TODAY", "package": "tzdata", "version": "1", "status": "not_affected",
                           "purls": ["pkg:deb/debian/tzdata@1"], "impact_statement": "x"}])
        self.git("fetch", "-q", "origin")
        ids = {s["vulnerability"]["name"] for s in self.pushed(P.VEX)["statements"]}
        self.assertEqual(ids, {"CVE-0-BASE", "CVE-1-PANEL", "CVE-2-MAIN", "CVE-3-TODAY"})              # yesterday's proposal kept, main's newer statement not clobbered
        self.assertEqual(self.pushed(P.PROFILES)["entries"], [self.entry])                              # the pending profile entry survived
        self.assertEqual(self.pushed(P.STATE)["note"], "today")

    def test_a_profile_entry_still_blocks_auto_merge_and_disarms(self):
        rc, calls = self.deliver()
        self.assertNotIn(["gh", "pr", "merge", "--auto", "--squash", "17"], calls)                       # the carried profile entry keeps it manual
        self.assertTrue(any(c[:3] == ["gh", "pr", "view"] for c in calls))                              # and an armed PR is checked for disarming

    def test_a_carried_profile_entry_blocks_auto_merge_even_when_the_listing_hides_it(self):     # review r4 B1
        rc, calls = self.deliver(pr_files="%s\n%s\n" % (P.STATE, P.VEX))                 # the (stub) gh listing says only state and VEX
        self.assertNotIn(["gh", "pr", "merge", "--auto", "--squash", "17"], calls)           # but the branch carried a profile entry: still manual

    def test_arming_is_bound_to_the_head_this_run_pushed(self):                                  # review r7 B1
        self.git("checkout", "-q", "-B", "auditor/panel", self.m0)
        doc = json.load(open(os.path.join(self.work, P.VEX))); doc["statements"].append(self.stmt("CVE-9-ONLY")); doc["version"] = 2
        self.write(P.VEX, doc); self.git("add", "-A"); self.git("commit", "-q", "-m", "vex only"); self.git("push", "-q", "-f", "origin", "auditor/panel"); self.git("checkout", "-q", "main")
        self.pr_head = "e" * 40                                                                # another run replaced the head after our push
        with self.assertRaises(RuntimeError) as e:
            self.deliver(pr_files="%s\n%s\n" % (P.STATE, P.VEX))
        self.assertIn("not arming", str(e.exception))

    def test_a_pr_with_only_the_panels_own_records_is_armed_by_number(self):
        self.git("checkout", "-q", "-B", "auditor/panel", self.m0)
        doc = json.load(open(os.path.join(self.work, P.VEX))); doc["statements"].append(self.stmt("CVE-9-ONLY")); doc["version"] = 2
        self.write(P.VEX, doc)
        self.git("add", "-A"); self.git("commit", "-q", "-m", "vex only"); self.git("push", "-q", "-f", "origin", "auditor/panel"); self.git("checkout", "-q", "main")
        rc, calls = self.deliver(pr_files="%s\n%s\n" % (P.STATE, P.VEX))
        self.assertIn(["gh", "pr", "merge", "--auto", "--squash", "17"], calls)               # state + VEX only: armed, through the PR's number
        self.assertIn(["gh", "pr", "ready", "17"], calls)

    def test_closing_the_source_pr_before_delivery_does_not_launder_the_judgment(self):     # review r5 B1
        tip = self.git("ls-remote", "origin", "refs/heads/auditor/panel").split()[0]
        ss = os.path.join(self.d, "ss-closed"); open(ss, "w").write(tip)
        with self.assertRaises(RuntimeError) as e:
            self.deliver(existing="", state_source=ss)                                      # the PR the judgment read is gone
        self.assertIn("absent", str(e.exception))
        ss2 = os.path.join(self.d, "ss-none"); open(ss2, "w").write("")
        with self.assertRaises(RuntimeError):
            self.deliver(existing="17", state_source=ss2)                                   # a PR appeared that the judgment never read
        with self.assertRaises(RuntimeError):
            self.deliver(existing="", state_source=os.path.join(self.d, "no-such-record"))   # no record at all: refused, PR or not

    def test_both_lookups_select_only_a_same_repo_pr_into_main(self):                       # review r5 B3
        rc, calls = self.deliver()
        lst = [c for c in calls if c[:3] == ["gh", "pr", "list"]][0]
        self.assertIn('.baseRefName == "main"', lst[lst.index("--jq") + 1])
        self.assertIn("isCrossRepository == false", lst[lst.index("--jq") + 1])

    def test_main_vex_timestamp_never_regresses_by_instant_through_the_whole_delivery(self):   # review r5 B2
        self.assertEqual(P._later("2026-10-05T09:00:00-04:00", "2026-10-05T10:00:00Z"), "2026-10-05T09:00:00-04:00")   # 13:00Z beats 10:00Z
        self.assertEqual(P._later("2026-10-05T18:00:00Z", "2026-10-06T00:00:00Z"), "2026-10-06T00:00:00Z")
        self.assertEqual(P._later("not a time", "2026-10-06T00:00:00Z"), "2026-10-06T00:00:00Z")
        self.assertEqual(P._later("2026-10-06T00:00:00Z", "not a time"), "2026-10-06T00:00:00Z")
        self.assertEqual(P._later("x", "y"), "x")
        self.git("checkout", "-q", "main")
        doc = json.load(open(os.path.join(self.work, P.VEX))); doc["timestamp"] = "2026-10-06T18:00:00Z"
        self.write(P.VEX, doc); self.git("add", "-A"); self.git("commit", "-q", "-m", "later ts"); self.git("push", "-q", "origin", "main")
        self.m1 = self.git("rev-parse", "HEAD")
        self.deliver(vex=[{"image": "fips-arm64", "id": "CVE-3-TODAY", "package": "tzdata", "version": "1", "status": "not_affected",
                           "purls": ["pkg:deb/debian/tzdata@1"], "impact_statement": "x"}])
        self.git("fetch", "-q", "origin")
        self.assertEqual(self.pushed(P.VEX)["timestamp"], "2026-10-06T18:00:00Z")           # today's midnight must not replace main's later instant

    def test_a_real_delivery_with_an_open_pr_needs_the_state_source_record(self):
        with self.assertRaises(RuntimeError) as e:
            self.deliver(state_source=os.path.join(self.d, "missing"))
        self.assertIn("--state-source", str(e.exception))
        self.assertEqual(P.automerge_allowed([], env={"AUDITOR_AUTOMERGE": "on"}), False)       # nothing changed arms nothing

    def test_the_pr_branch_not_the_listing_decides_what_is_carried(self):
        rc, calls = self.deliver(pr_files="%s\n" % P.STATE)
        self.assertEqual(rc, 0)
        self.assertEqual(self.pushed(P.STATE)["note"], "today")
        self.assertEqual(self.pushed(P.PROFILES)["entries"], [self.entry])      # still carried: the PR branch holds it, whatever gh pr diff says

    def test_a_conflict_with_a_newer_main_change_fails_loudly_instead_of_clobbering(self):
        # the PR flipped CVE-0-BASE to affected; main ALSO changed that statement since: neither silently wins
        self.git("checkout", "-q", "auditor/panel")
        doc = json.load(open(os.path.join(self.work, P.VEX)))
        doc["statements"][0]["status"] = "affected"
        self.write(P.VEX, doc); self.git("add", "-A"); self.git("commit", "-q", "-m", "flip"); self.git("push", "-q", "origin", "auditor/panel")
        self.git("checkout", "-q", "main")
        doc = json.load(open(os.path.join(self.work, P.VEX)))
        doc["statements"][0]["status"] = "under_investigation"
        self.write(P.VEX, doc); self.git("add", "-A"); self.git("commit", "-q", "-m", "main edits it"); self.git("push", "-q", "origin", "main")
        self.m1 = self.git("rev-parse", "HEAD")
        with self.assertRaises(RuntimeError) as e:
            self.deliver()
        self.assertIn("conflict", str(e.exception).lower())

    def test_a_tip_that_did_not_pass_the_reserved_branch_guard_is_never_carried(self):      # reviewer r2 blocker: a human's push must not be laundered
        for verdict in ("failure", "", "success,failure", "cancelled"):
            self.guard = verdict
            before = self.git("ls-remote", "origin", "refs/heads/auditor/panel").split()[0]
            with self.assertRaises(RuntimeError) as e:
                self.deliver()
            self.assertIn("reserved-branch guard", str(e.exception))
            self.assertEqual(self.git("ls-remote", "origin", "refs/heads/auditor/panel").split()[0], before)   # nothing pushed
        self.guard = "success"
        self.assertEqual(self.deliver()[0], 0)

    def test_a_forks_pr_from_a_branch_of_the_same_name_is_not_the_panel_pr(self):
        rc, calls = self.deliver()
        lst = [c for c in calls if c[:3] == ["gh", "pr", "list"]][0]
        self.assertIn("isCrossRepository == false", lst[lst.index("--jq") + 1])

    def test_an_unreadable_object_aborts_it_is_never_read_as_absent(self):          # review r3 B3
        def failing(cmd, **kw):
            return types.SimpleNamespace(returncode=128, stdout="", stderr="fatal: bad object")
        with self.assertRaises(RuntimeError):
            P.carry_forward(self.work, "FETCH_HEAD", self.m0, [P.VEX], [], True, failing)

    def test_the_judgment_state_source_is_authenticated_and_bound_to_the_delivery(self):    # review r3 B1
        out = os.path.join(self.d, "state.json"); shaf = os.path.join(self.d, "sha")
        a = types.SimpleNamespace(repo=self.work, state=out, sha_out=shaf)

        def run(cmd, **kw):
            if cmd[0] == "git":
                return subprocess.run(cmd, capture_output=True, text=True)
            o = {("gh", "pr", "list"): "17\n"}.get(tuple(cmd[:3]), "")
            if cmd[:2] == ["gh", "api"] and "check-runs" in cmd[2]:
                o = self.guard
            return types.SimpleNamespace(returncode=0, stdout=o, stderr="")
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(P.cmd_state_source(a, run=run), 0)
        tip = self.git("rev-parse", "origin/auditor/panel")
        self.assertEqual(open(shaf).read(), tip)                                        # the exact commit read is recorded
        self.assertEqual(json.load(open(out))["seat"], "A")
        # a tip that did not pass the guard is never read
        self.guard = "failure"
        with self.assertRaises(RuntimeError):
            P.cmd_state_source(a, run=run)
        self.guard = "success"
        # delivery refuses when the branch is no longer the one the judgment read
        open(shaf, "w").write("0" * 40)
        with self.assertRaises(RuntimeError) as e:
            self.deliver(env_extra={}, state_source=shaf)
        self.assertIn("moved", str(e.exception))
        open(shaf, "w").write(tip)
        self.assertEqual(self.deliver(state_source=shaf)[0], 0)
        # no open PR: main's state, an empty recorded sha, and the file removed when there is none anywhere
        def nopr(cmd, **kw):
            if cmd[0] == "git":
                return subprocess.run(cmd, capture_output=True, text=True)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch("sys.stdout", new=io.StringIO()) as so:
            P.cmd_state_source(a, run=nopr)
        self.assertIn("main", so.getvalue()); self.assertEqual(open(shaf).read(), "")
        os.remove(os.path.join(self.work, P.STATE)); self.git("checkout", "-q", "--", ".") if False else None
        with mock.patch("sys.stdout", new=io.StringIO()) as so:
            P.cmd_state_source(a, run=nopr)
        self.assertIn("first day", so.getvalue()); self.assertFalse(os.path.exists(out))
        # a PR whose branch has no state file at all falls back to main's
        self.git("checkout", "-q", "auditor/panel"); self.git("rm", "-q", P.STATE); self.git("commit", "-q", "-m", "no state"); self.git("push", "-q", "origin", "auditor/panel"); self.git("checkout", "-q", "main")
        self.git("checkout", "-q", "--", P.STATE)
        with mock.patch("sys.stdout", new=io.StringIO()) as so:
            P.cmd_state_source(a, run=run)
        self.assertIn("main", so.getvalue())

    def test_an_armed_pr_is_disarmed_before_its_head_is_replaced(self):             # review r3 B2
        rc, calls = self.deliver(view_armed=True)
        order = [c[:3] + c[-1:] for c in calls if c[:3] in (["gh", "pr", "merge"], ["git", "-C", self.work])]
        flat = [" ".join(c) for c in calls]
        disarm = next(i for i, c in enumerate(flat) if "merge --disable-auto 17" in c)
        push = next(i for i, c in enumerate(flat) if " push --force " in c)
        self.assertLess(disarm, push)                                                   # disarmed first, even if a later command fails

    def test_the_guard_is_read_with_the_job_token_never_the_apps(self):                            # review r6 B1
        seen = []
        orig = P._sh
        def spy(cmd, plan, real, run=subprocess.run, check=True, **kw):
            if cmd[:2] == ["gh", "api"] and "check-runs" in cmd[2]:
                seen.append(kw.get("env", {}).get("GH_TOKEN"))
            return orig(cmd, plan, real, run, check, **kw)
        with mock.patch.object(P, "_sh", spy):
            self.deliver(env_extra={"GH_TOKEN": "app-token", "AUDITOR_CHECKS_TOKEN": "job-token"})
        self.assertTrue(seen and set(seen) == {"job-token"}, seen)

    def test_main_state_that_moved_since_the_prs_base_stops_the_run_before_judgment(self):         # review r6 B3
        out = os.path.join(self.d, "state.json"); shaf = os.path.join(self.d, "sha")
        a = types.SimpleNamespace(repo=self.work, state=out, sha_out=shaf)
        self.git("checkout", "-q", "main")
        self.write(P.STATE, {"version": 1, "false": [], "real": [{"id": "NEWER-ON-MAIN"}], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"})
        self.git("add", "-A"); self.git("commit", "-q", "-m", "main's state moved"); self.git("push", "-q", "origin", "main")

        def run(cmd, **kw):
            if cmd[0] == "git":
                return subprocess.run(cmd, capture_output=True, text=True)
            o = {("gh", "pr", "list"): "17\n"}.get(tuple(cmd[:3]), "")
            if cmd[:2] == ["gh", "api"] and "check-runs" in cmd[2]:
                o = "success"
            return types.SimpleNamespace(returncode=0, stdout=o, stderr="")
        with self.assertRaises(RuntimeError) as e:
            P.cmd_state_source(a, run=run)
        self.assertIn("main's panel state changed", str(e.exception))

    def test_a_pr_branch_with_a_planted_file_fails_the_run_before_any_push(self):
        self.git("checkout", "-q", "auditor/panel")
        os.makedirs(os.path.join(self.work, ".github/agent/prompts"), exist_ok=True)
        open(os.path.join(self.work, ".github/agent/prompts/p.md"), "w").write("planted")
        self.git("add", "-A"); self.git("commit", "-q", "-m", "human push"); self.git("push", "-q", "origin", "auditor/panel")
        self.git("checkout", "-q", "main")
        before = self.git("rev-parse", "origin/auditor/panel")
        with self.assertRaises(RuntimeError) as e:
            self.deliver()
        self.assertIn("never writes", str(e.exception))
        self.git("fetch", "-q", "origin")
        self.assertEqual(self.git("rev-parse", "origin/auditor/panel"), before)       # nothing was pushed

    def test_auto_merge_is_only_for_the_panels_own_records(self):
        on = {"AUDITOR_AUTOMERGE": "on"}
        self.assertTrue(P.automerge_allowed([P.STATE, P.VEX], env=on))
        for extra in (P.PROFILES, ".github/agent/prompts/x.md", ".github/workflows/auditor.yml", "bin/x.sh"):
            self.assertFalse(P.automerge_allowed([P.STATE, extra], env=on), extra)

    def test_no_open_pr_still_starts_from_the_runs_main_commit(self):
        rc, calls = self.deliver(existing="")
        self.assertEqual(rc, 0)
        self.git("fetch", "-q", "origin")
        self.assertEqual(self.git("rev-parse", "origin/auditor/panel^"), self.m1)
        self.assertEqual([s["vulnerability"]["name"] for s in self.pushed(P.VEX)["statements"]][:2], ["CVE-0-BASE", "CVE-2-MAIN"])   # no PR: nothing carried
        self.assertFalse(any(c[:4] == ["git", "-C", self.work, "fetch"] for c in calls))


class CarryForward(Tmp):
    """carry_forward (advisor 0186) branch by branch, against canned `git show` contents."""

    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.d, "r"); os.makedirs(self.repo)
        self.texts = {}

    def put(self, ref, path, obj):
        self.texts[(ref, path)] = obj if isinstance(obj, str) else json.dumps(obj)

    def cur(self, path, obj):
        full = os.path.join(self.repo, path); os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").write(obj if isinstance(obj, str) else json.dumps(obj))

    def go(self, files):
        def fake(cmd, **kw):
            if cmd[3] == "ls-tree":
                present = (cmd[4], cmd[-1]) in self.texts and self.texts[(cmd[4], cmd[-1])] != ""
                return types.SimpleNamespace(returncode=0, stdout="100644 blob x\t%s" % cmd[-1] if present else "", stderr="")
            ref, _, path = cmd[-1].partition(":")
            return types.SimpleNamespace(returncode=0, stdout=self.texts.get((ref, path), ""), stderr="")
        return P.carry_forward(self.repo, "PR", "BASE", files, [], True, fake)

    def st(self, name, status="not_affected"):
        return {"@id": "https://x/v#" + name, "status": status}

    def test_state_removed_unchanged_and_already_on_main_are_skipped(self):
        self.put("PR", P.STATE, {"a": 1}); self.put("BASE", P.STATE, {"a": 0})
        self.put("PR", P.PROFILES, ""); self.put("BASE", P.PROFILES, "was")                        # removed by the PR
        self.assertEqual(self.go([P.STATE, P.PROFILES]), [])
        self.assertFalse(os.path.exists(os.path.join(self.repo, P.STATE)))                        # the state is rewritten from the judgment, never carried
        self.put("PR", P.VEX, json.dumps({"statements": []})); self.put("BASE", P.VEX, json.dumps({"statements": []}))   # untouched by the PR
        self.assertEqual(self.go([P.VEX]), [])
        self.put("PR", P.VEX, "new"); self.put("BASE", P.VEX, "old"); self.cur(P.VEX, "new")      # main already has exactly this
        self.assertEqual(self.go([P.VEX]), [])

    def test_a_foreign_path_is_refused_even_when_deleted_or_identical(self):                       # review r6 B4
        for pr_txt, base_txt in (("", "was"), ("same", "same")):
            self.put("PR", "bin/foreign.sh", pr_txt); self.put("BASE", "bin/foreign.sh", base_txt)
            with self.assertRaises(RuntimeError) as e:
                self.go(["bin/foreign.sh"])
            self.assertIn("never writes", str(e.exception))

    def test_vex_additions_changes_and_conflicts(self):
        base = {"version": 1, "statements": [self.st("A"), self.st("B")]}
        pr = {"version": 2, "timestamp": "2026-02-01T00:00:00Z", "statements": [self.st("A"), self.st("B", "affected"), self.st("NEW")]}
        self.put("PR", P.VEX, pr); self.put("BASE", P.VEX, base)
        self.cur(P.VEX, {"version": 5, "timestamp": "2026-01-01T00:00:00Z", "statements": [self.st("A"), self.st("B"), self.st("MAIN")]})
        self.assertEqual(self.go([P.VEX]), [P.VEX])
        doc = json.load(open(os.path.join(self.repo, P.VEX)))
        by = {x["@id"].split("#")[1]: x for x in doc["statements"]}
        self.assertEqual((by["B"]["status"], sorted(by)), ("affected", ["A", "B", "MAIN", "NEW"]))   # changed statement carried, main's own kept
        self.assertEqual((doc["version"], doc["timestamp"]), (6, "2026-02-01T00:00:00Z"))
        # the same addition already on main, identical: nothing to carry
        self.cur(P.VEX, {"version": 5, "statements": [self.st("A"), self.st("B", "affected"), self.st("NEW")]})
        self.assertEqual(self.go([P.VEX]), [])
        # an addition main holds DIFFERENTLY, and a change main also changed: conflicts
        self.cur(P.VEX, {"version": 5, "statements": [self.st("A"), self.st("B", "affected"), self.st("NEW", "affected")]})
        with self.assertRaises(RuntimeError):
            self.go([P.VEX])
        self.cur(P.VEX, {"version": 5, "statements": [self.st("A"), self.st("B", "under_investigation"), self.st("NEW")]})
        with self.assertRaises(RuntimeError):
            self.go([P.VEX])

    def test_hand_written_statements_without_an_id_are_never_collapsed(self):      # reviewer r3 blocker: the real VEX file has four of them
        legacy = [{"vulnerability": {"name": "CVE-2024-51744"}, "status": "not_affected"}, {"vulnerability": {"name": "CVE-2025-60876"}, "status": "not_affected"},
                  {"vulnerability": {"name": "CVE-2025-46394"}, "status": "not_affected"}]
        base = {"version": 1, "timestamp": "2026-01-01T00:00:00Z", "statements": legacy}
        pr = {"version": 2, "timestamp": "2026-02-01T00:00:00Z", "statements": legacy + [self.st("NEW")]}
        self.put("PR", P.VEX, pr); self.put("BASE", P.VEX, base)
        self.cur(P.VEX, {"version": 3, "timestamp": "2026-03-01T00:00:00Z", "statements": legacy + [self.st("MAIN")]})
        self.assertEqual(self.go([P.VEX]), [P.VEX])
        doc = json.load(open(os.path.join(self.repo, P.VEX)))
        self.assertEqual([x.get("vulnerability", {}).get("name") or x["@id"].split("#")[1] for x in doc["statements"]],
                         ["CVE-2024-51744", "CVE-2025-60876", "CVE-2025-46394", "MAIN", "NEW"])      # every legacy statement intact, in order
        self.assertEqual(doc["timestamp"], "2026-03-01T00:00:00Z")                                  # main's newer timestamp is never regressed
        # a statement without an id that the PR ADDED is carried by its content, once
        extra = {"vulnerability": {"name": "CVE-2099-1"}, "status": "not_affected"}
        self.put("PR", P.VEX, dict(pr, statements=legacy + [extra]))
        self.assertEqual(self.go([P.VEX]), [P.VEX])
        self.assertEqual(self.go([P.VEX]), [])                                                         # already there now: nothing more to carry

    def test_the_real_vex_file_of_this_repository_survives_a_carry_intact(self):
        real = open(os.path.join(REPO, P.VEX)).read()
        base = json.loads(real)
        pr = json.loads(real); pr["statements"].append(self.st("CVE-2099-REAL")); pr["version"] = int(pr.get("version", 1)) + 1
        self.put("PR", P.VEX, pr); self.put("BASE", P.VEX, base); self.cur(P.VEX, real)
        self.assertEqual(self.go([P.VEX]), [P.VEX])
        doc = json.load(open(os.path.join(self.repo, P.VEX)))
        self.assertEqual(doc["statements"][:len(base["statements"])], base["statements"])           # every published statement untouched, in order
        self.assertEqual(len(doc["statements"]), len(base["statements"]) + 1)

    def test_profile_entries_are_carried_once_and_conflicts_are_loud(self):                       # review r7 B2
        e1 = {"scanner": "scout", "kind": "k", "match": {"package": "^a$"}, "finding": "f1"}
        e2 = {"scanner": "scout", "kind": "k", "match": {"package": "^b$"}, "finding": "f2"}
        self.put("BASE", P.PROFILES, {"entries": [e1]}); self.put("PR", P.PROFILES, {"entries": [e1, e2]})
        self.cur(P.PROFILES, {"entries": [e1]})
        self.assertEqual(self.go([P.PROFILES]), [P.PROFILES])
        self.assertEqual(json.load(open(os.path.join(self.repo, P.PROFILES)))["entries"], [e1, e2])
        self.cur(P.PROFILES, {"entries": [e1, e2]})                                                 # main already holds exactly it: nothing to carry
        self.assertEqual(self.go([P.PROFILES]), [])
        self.cur(P.PROFILES, {"entries": [e1, dict(e2, finding="main's different one")]})            # main holds a DIFFERENT entry for the same key: loud
        with self.assertRaises(RuntimeError):
            self.go([P.PROFILES])
        # the PR CHANGED e1: carried if main still has the base's, loud if main changed it too
        self.put("PR", P.PROFILES, {"entries": [dict(e1, finding="changed by the PR")]})
        self.cur(P.PROFILES, {"entries": [e1]})
        self.assertEqual(self.go([P.PROFILES]), [P.PROFILES])
        self.assertEqual(json.load(open(os.path.join(self.repo, P.PROFILES)))["entries"][0]["finding"], "changed by the PR")
        self.cur(P.PROFILES, {"entries": [dict(e1, finding="main changed it as well")]})
        with self.assertRaises(RuntimeError):
            self.go([P.PROFILES])
        self.put("PR", P.PROFILES, {"entries": []})                                                 # the PR REMOVED e1: not silently dropped
        self.cur(P.PROFILES, {"entries": [e1]})
        with self.assertRaises(RuntimeError):
            self.go([P.PROFILES])

    def test_a_file_the_panel_never_writes_is_refused_not_carried(self):      # reviewer r1 blocker 1: a human push must not ride into an App commit
        for path in (".github/agent/prompts/x.md", ".github/workflows/auditor.yml", ".auditor/proposals/p.json", "bin/evil.sh"):
            self.put("PR", path, "pr-version"); self.put("BASE", path, "base-version")
            with self.assertRaises(RuntimeError) as e:
                self.go([path])
            self.assertIn("never writes", str(e.exception))
            self.assertFalse(os.path.exists(os.path.join(self.repo, path)))


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

    # matrix case changed, owner-ratified Oct 3 (item a; advisor 0113, 0136), AC unchanged: replaces the #150 round-3
    # head-only refusal with an equivalent binding to the scanned bytes
    def test_the_panel_judges_a_completed_rescan_of_main_within_a_day_bound_to_its_scanned_head(self):
        sel = self.steps[self.step("gh run list --workflow main-candidate-rescan.yml")]["run"]
        self.assertIn('gh run view "$rid" --json status --jq .status', sel)            # waits for completion
        for out in ("rescan_status=", "rescan_created=", "rescan_head=", "rescan_conclusion=", "main_head="):
            self.assertIn(out, sel)
        self.assertNotIn("select(.headSha==", sel)            # any head: the newest run of main, bound to its own head
        self.assertNotIn("head_bound", yaml.safe_dump(self.wf))
        j = self.steps[self.step("auditor-panel.py judge")]
        for k, v in (("RESCAN_RUN", "run_id"), ("RESCAN_HEAD", "rescan_head"), ("RESCAN_CONCLUSION", "rescan_conclusion")):
            self.assertEqual(j["env"][k], "${{ steps.rescan.outputs.%s }}" % v)
        self.assertNotIn("MAIN_HEAD", j.get("env", {}))     # never the selection-time value (Codex r1, B3)
        # COMPLETED (advisor 0136): finished, any conclusion, with its evidence; a running or evidence-less run is refused
        for must in ('[ "${RESCAN_STATUS}" = completed ] ||', '[ "$age" -le 86400 ] ||',
                     '[ -f "${RUNNER_TEMP}/panel/verdict.json" ] ||', "--rescan \"${RUNNER_TEMP}/rescan-binding.json\""):
            self.assertIn(must, j["run"])
        # main's head is refetched live, right before the binding is built — not reused from selection time, which can
        # be up to 90 minutes stale by the time the bounded wait finishes (Codex r1, B3)
        self.assertIn('MAIN_HEAD=$(gh api "repos/${GITHUB_REPOSITORY}/commits/main" --jq', j["run"])
        self.assertLess(j["run"].index('MAIN_HEAD=$(gh api'), j["run"].index("'{run_id: $r"))
        self.assertNotIn("RESCAN_CONCLUSION}\" = success", j["run"])    # a red rescan is judged, its conclusion named
        self.assertLess(j["run"].index("verdict.json\" ] ||"), j["run"].index("auditor-panel.py judge"))
        self.assertEqual(j["run"].count("exit 1; }"), 3)

    def test_state_comes_only_from_an_open_panel_pr_or_main(self):         # review r1 R3; advisor 0186: through the tested command, bound to the delivery
        run = self.steps[self.step("auditor-panel.py judge")]["run"]
        self.assertIn("auditor-panel.py state-source", run)
        self.assertLess(run.index("auditor-panel.py state-source"), run.index("auditor-panel.py judge"))
        self.assertNotIn("gh pr list --head auditor/panel", run)             # the old unguarded, fork-unfiltered lookup is gone
        deliver = self.steps[self.step("auditor-panel.py deliver")]["run"]
        self.assertIn('--state-source "${RUNNER_TEMP}/panel-state-source"', deliver)
        self.assertIn('--sha-out "${RUNNER_TEMP}/panel-state-source"', run)

    def test_the_guard_reader_has_checks_read_and_the_app_token_never_does(self):                    # review r6 B1
        self.assertEqual(self.wf["jobs"]["audit"]["permissions"].get("checks"), "read")
        deliver = self.steps[self.step("auditor-panel.py deliver")]
        self.assertEqual(deliver["env"]["AUDITOR_CHECKS_TOKEN"], "${{ github.token }}")
        app = next(st for st in self.steps if st.get("id") == "app-token")
        self.assertNotIn("permission-checks", app["with"])

    def test_overlapping_audits_are_serialised(self):                                              # review r7 B1
        c = self.wf["jobs"]["audit"].get("concurrency") or {}
        self.assertEqual((c.get("group"), c.get("cancel-in-progress")), ("auditor-daily-delivery", False))

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

    def test_the_probe_runs_only_on_request_from_main_and_alone(self):   # advisor 0051; Codex r1 blockers 1-2 (#155)
        on = self.wf.get("on", self.wf.get(True))
        inputs = on["workflow_dispatch"]["inputs"]
        self.assertEqual((inputs["panel_probe"]["type"], inputs["panel_probe"]["default"]), ("boolean", False))
        jobs = self.wf["jobs"]
        self.assertEqual(jobs["audit"]["if"].replace(" ", ""), "${{!inputs.panel_probe}}")   # nothing else runs
        p = jobs["panel-probe"]
        self.assertEqual(p["if"].replace(" ", ""), "${{inputs.panel_probe&&github.ref=='refs/heads/main'}}")
        self.assertEqual((p["environment"], p["permissions"]), ("agent", {"contents": "read", "id-token": "write"}))
        runs = " ".join(st.get("run") or "" for st in p["steps"])
        self.assertIn("auditor-panel.py probe --seats real", runs)
        for absent in ("auditor-run.py", "deliver", "judge", "getIDToken", "create-github-app-token", "gh "):
            self.assertNotIn(absent, runs + " ".join(str(st.get("uses", "")) for st in p["steps"]))
        self.assertFalse([st for st in p["steps"] if st.get("id") == "oidc"])
        env = next(st for st in p["steps"] if "auditor-panel.py probe" in (st.get("run") or ""))["env"]
        self.assertEqual(env["PANEL_AUDIT_B_MODEL"], "${{ secrets.PANEL_AUDIT_B_MODEL }}")
        self.assertLess(list(jobs).index("audit"), list(jobs).index("panel-probe"))   # the matrix reads the audit job

    def test_delivery_is_the_auditor_lane_only(self):                       # rule 0
        d = self.steps[self.step("auditor-panel.py deliver")]
        self.assertIn("steps.panel.outcome == 'success'", d["if"])
        self.assertEqual(d["env"]["AUDITOR_ISSUES_TOKEN"], "${{ github.token }}")
        self.assertEqual(d["env"]["AUDITOR_AUTOMERGE"], "${{ vars.AUDITOR_AUTOMERGE }}")   # Codex r2 B6: the switch arrives


class Probe(Tmp):                                                           # REQ-SCAN-008-AC3 (live proof)
    """The seat probe: one fixed audit per seat from a committed synthetic bundle; nothing published."""

    def a(self, **kw):
        return args(**dict(dict(out=os.path.join(self.d, "out"), seats="none", token_budget=200000), **kw))

    def test_the_bundle_is_synthetic(self):
        text = open(P.PROBE_BUNDLE).read()
        self.assertIn(P.EVIDENCE_MARK, text)
        self.assertEqual(set(re.findall(r"Package: (\S+)", text)), {"probe-pkg"})
        self.assertIsNone(re.search(r"CVE-\d", text))

    def test_both_seats_answering_is_success_and_nothing_is_published(self):
        asked = []

        def seat(name):
            def ask(req):
                asked.append((name, req["mode"], req["finding"]["id"]))
                return {"verdict": "real", "evidence": ["Package: probe-pkg Version: 1.0.0"], "why": "x", "case": "y",
                        "_tokens": 10}
            return ask
        with mock.patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(P.cmd_probe(self.a(), seats={"A": seat("A"), "B": seat("B")}), 0)
        self.assertEqual(asked, [("A", "audit", "PROBE-0001"), ("B", "audit", "PROBE-0001")])   # at most two calls
        summary = open(os.path.join(self.d, "out", "summary.md")).read()
        self.assertIn("vendor A: answered with a valid vote (real)", summary)
        self.assertIn("vendor B: answered with a valid vote (real)", summary)
        self.assertEqual(sorted(os.listdir(os.path.join(self.d, "out"))), ["summary.md"])        # no state, day or plan
        self.assertIn("Tokens used: 20", out.getvalue())

    def test_an_errored_or_silent_seat_fails_the_probe_with_a_masked_reason(self):
        OpenAIError = type("OpenAIError", (Exception,), {})

        def b(req):
            raise OpenAIError("Token exchange failed with status 401 for gpt-6-astra")
        with mock.patch("sys.stdout", new=io.StringIO()):
            rc = P.cmd_probe(self.a(), seats={"A": lambda r: {"verdict": "maybe"}, "B": b})
        self.assertEqual(rc, 1)
        summary = open(os.path.join(self.d, "out", "summary.md")).read()
        self.assertIn("vendor A: answered without a valid vote", summary)
        self.assertIn("vendor B: error: seat error: Token exchange failed with status 401", summary)
        self.assertNotIn("openai", summary.lower())
        self.assertNotIn("gpt", summary.lower())

    def test_no_seats_configured_is_a_failed_probe(self):
        with mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(P.cmd_probe(self.a()), 1)

    def test_the_probe_disables_retries_in_both_sdks(self):              # Codex r1 blocker 2 (#155)
        made = {}

        def make_seats(mode, retries=None):
            made["retries"] = retries
            return {"A": lambda r: {"error": "x"}, "B": lambda r: {"error": "x"}}
        with mock.patch.object(P, "make_seats", make_seats), mock.patch("sys.stdout", new=io.StringIO()):
            P.cmd_probe(self.a(seats="real"))
        self.assertEqual(made["retries"], 0)
        seen = []
        P.make_seats("real", env={}, a=lambda env, retries=None: seen.append(("A", retries)) or (lambda r: {}),
                     b=lambda env, retries=None: seen.append(("B", retries)) or (lambda r: {}), retries=0)
        self.assertEqual(seen, [("A", 0), ("B", 0)])
        kw = {}
        fake = types.ModuleType("anthropic")
        fake.Anthropic = lambda **k: kw.update(k) or types.SimpleNamespace(messages=None)
        fake_httpx = types.ModuleType("httpx2")
        fake_httpx.Client = lambda **k: k
        with mock.patch.dict(sys.modules, {"anthropic": fake, "httpx2": fake_httpx}):
            P.seat_a({"PANEL_AUDIT_A_MODEL": "m", "ANTHROPIC_IDENTITY_TOKEN_FILE": os.path.join(self.d, "t")},
                     mint=lambda a: "jwt", retries=0)
        self.assertEqual(kw["max_retries"], 0)
        self.assertIn("http_client", kw)      # Codex #155 phase-2 r2: the capped client (one model request, 401 named)
        got = {}
        fo = types.ModuleType("openai")
        fo.OpenAI = lambda **k: got.update(k) or types.SimpleNamespace(responses=None)
        env = {"PANEL_AUDIT_B_IDENTITY_PROVIDER_ID": "i", "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID": "s",
               "PANEL_AUDIT_B_PROJECT_ID": "p", "PANEL_AUDIT_B_MODEL": "m"}
        with mock.patch.dict(sys.modules, {"openai": fo, "httpx2": fake_httpx}):
            P.seat_b(env, mint=lambda a: "jwt", retries=0)
        self.assertEqual(got["max_retries"], 0)
        self.assertIn("http_client", got)

    # Codex #155 phase-2 round 2 blocker: both pinned SDKs re-send once after a 401 outside max_retries (a federated
    # token refresh), so max_retries=0 still allowed a second model request and hid the first failure. The probe's seats
    # now send through an HTTP client whose hooks allow ONE model-endpoint request per seat and turn a 401 from it into a
    # named failure before the SDK can re-send. (The same sequence against the real pinned SDKs:
    # test_panel_sdk_probe.py.)
    def _req(self, path):
        return types.SimpleNamespace(url=types.SimpleNamespace(path=path))

    def test_the_cap_counts_model_requests_only_and_refuses_a_second(self):
        cap = P.SeatCap()
        for path in ("/v1/oauth/token", "/oauth/token"):     # the federated token exchanges are not model requests
            cap.on_request(self._req(path))
        cap.on_request(self._req("/v1/messages"))
        with self.assertRaises(P.SeatCapError) as e:
            cap.on_request(self._req("/v1/responses"))
        self.assertIn("second model request", str(e.exception))
        self.assertEqual(cap.failure, str(e.exception))

    def test_the_cap_names_a_401_from_the_model_endpoint_only(self):
        cap = P.SeatCap()
        cap.on_response(types.SimpleNamespace(status_code=401, request=self._req("/v1/oauth/token")))
        cap.on_response(types.SimpleNamespace(status_code=200, request=self._req("/v1/responses")))
        self.assertIsNone(cap.failure)
        with self.assertRaises(P.SeatCapError) as e:
            cap.on_response(types.SimpleNamespace(status_code=401, request=self._req("/v1/responses")))
        self.assertIn("HTTP 401", str(e.exception))

    def test_the_capped_client_hooks_both_events(self):
        made = {}
        fake = types.ModuleType("httpx2")
        fake.Client = lambda **k: made.update(k) or "client"
        cap = P.SeatCap()
        with mock.patch.dict(sys.modules, {"httpx2": fake}):
            self.assertEqual(P.capped_client(cap), "client")
            self.assertNotIn("transport", made)
            P.capped_client(cap, transport="t")
        self.assertEqual(made["event_hooks"], {"request": [cap.on_request], "response": [cap.on_response]})
        self.assertEqual(made["transport"], "t")

    def _sdk_failing_with_401(self, kw, path):
        """A fake SDK call: the transport answers 401, the capped client's hook fires, and the SDK wraps what it raised
        in its own generic error (as both pinned SDKs do with max_retries=0)."""
        try:
            kw["http_client"]["event_hooks"]["response"][0](
                types.SimpleNamespace(status_code=401, request=self._req(path)))
        except P.SeatCapError:
            raise RuntimeError("Connection error.")

    def test_a_capped_seat_reports_the_cap_failure_not_the_sdk_error(self):
        fake_httpx = types.ModuleType("httpx2")
        fake_httpx.Client = lambda **k: k
        kw, got = {}, {}
        fa = types.ModuleType("anthropic")
        fa.Anthropic = lambda **k: kw.update(k) or types.SimpleNamespace(messages=types.SimpleNamespace(
            create=lambda **c: self._sdk_failing_with_401(kw, "/v1/messages")))
        fo = types.ModuleType("openai")
        fo.OpenAI = lambda **k: got.update(k) or types.SimpleNamespace(responses=types.SimpleNamespace(
            create=lambda **c: self._sdk_failing_with_401(got, "/v1/responses")))
        env = {"PANEL_AUDIT_A_MODEL": "m", "ANTHROPIC_IDENTITY_TOKEN_FILE": os.path.join(self.d, "t"),
               "PANEL_AUDIT_B_IDENTITY_PROVIDER_ID": "i", "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID": "s",
               "PANEL_AUDIT_B_PROJECT_ID": "p", "PANEL_AUDIT_B_MODEL": "m"}
        with mock.patch.dict(sys.modules, {"anthropic": fa, "openai": fo, "httpx2": fake_httpx}), \
                mock.patch.object(P, "render", lambda r: "x"):
            for seat in (P.seat_a(env, mint=lambda a: "jwt", retries=0), P.seat_b(env, mint=lambda a: "jwt", retries=0)):
                ans = P._ask(seat, "A", {"mode": "audit"})
                self.assertIn("HTTP 401", ans["error"])
                self.assertNotIn("Connection error", ans["error"])

    def test_an_uncapped_seat_passes_other_sdk_errors_through(self):
        fake_httpx = types.ModuleType("httpx2")
        fake_httpx.Client = lambda **k: k
        fo = types.ModuleType("openai")
        fo.OpenAI = lambda **k: types.SimpleNamespace(responses=types.SimpleNamespace(
            create=lambda **c: (_ for _ in ()).throw(RuntimeError("upstream 500"))))
        env = {"PANEL_AUDIT_B_IDENTITY_PROVIDER_ID": "i", "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID": "s",
               "PANEL_AUDIT_B_PROJECT_ID": "p", "PANEL_AUDIT_B_MODEL": "m"}
        with mock.patch.dict(sys.modules, {"openai": fo, "httpx2": fake_httpx}), mock.patch.object(P, "render", lambda r: "x"):
            self.assertIn("upstream 500", P._ask(P.seat_b(env, mint=lambda a: "jwt", retries=0), "B", {"mode": "audit"})["error"])

    def test_ordinary_runs_keep_the_sdk_default_client(self):
        got, kw = {}, {}
        fo = types.ModuleType("openai")
        fo.OpenAI = lambda **k: got.update(k) or types.SimpleNamespace(responses=None)
        fa = types.ModuleType("anthropic")
        fa.Anthropic = lambda **k: kw.update(k) or types.SimpleNamespace(messages=None)
        env = {"PANEL_AUDIT_B_IDENTITY_PROVIDER_ID": "i", "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID": "s",
               "PANEL_AUDIT_B_PROJECT_ID": "p", "PANEL_AUDIT_B_MODEL": "m", "PANEL_AUDIT_A_MODEL": "m",
               "ANTHROPIC_IDENTITY_TOKEN_FILE": os.path.join(self.d, "t")}
        with mock.patch.dict(sys.modules, {"openai": fo, "anthropic": fa}):
            P.seat_b(env, mint=lambda a: "jwt")
            P.seat_a(env, mint=lambda a: "jwt")
        self.assertNotIn("http_client", got)
        self.assertEqual(kw, {})

    def test_dispatch(self):
        seen = []
        P.main(["probe", "--out", "x", "--seats", "real"], probe=lambda a: seen.append(a.seats) or 0)
        self.assertEqual(seen, ["real"])


class Main(Tmp):
    def test_dispatch(self):
        seen = []
        P.main(["judge", "--verdict", "v", "--state", "s", "--profiles", "p", "--oci", "o", "--out", "x", "--seats", "real",
                "--rescan", "r"],
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
