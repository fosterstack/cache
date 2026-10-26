"""Coverage + behaviour tests for auditor-manifest.py (REQ-AUD-18 AC2).

The tools the producer still runs (syft, govulncheck, skopeo) are replaced by ONE
fake executable symlinked under each tool name on a private PATH. It logs its argv and answers
from a per-test rule table, so every test asserts the exact argv the producer issued and the
manifest it wrote. endoflife.date is served by a patched urllib.request.urlopen — no network.
"""
import contextlib, importlib.util, io, json, os, runpy, shutil, stat, sys, tempfile, unittest
from datetime import date
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(BIN, "auditor-manifest.py")
_spec = importlib.util.spec_from_file_location("auditor_manifest_cov", SRC)
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

def _wr(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def _rd(path):
    with open(path) as fh:
        return fh.read()


def _rj(path):
    return json.loads(_rd(path))


C40 = "c" * 40
TOOLS = ("grype", "trivy", "osv-scanner", "syft", "snyk", "govulncheck", "skopeo")

FAKE = r'''#!%s
import json, os, sys
tool = os.path.basename(sys.argv[0]); args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as fh:
    fh.write(json.dumps([tool] + args) + "\n")
if os.environ.get("FAKE_ENVLOG"):
    with open(os.environ["FAKE_ENVLOG"], "a") as fh:
        fh.write(json.dumps({"tool": tool, "args": args, "cwd": os.path.realpath(os.getcwd()),
                             "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN"), "GOFLAGS": os.environ.get("GOFLAGS"), "GOPROXY": os.environ.get("GOPROXY"), "CGO_ENABLED": os.environ.get("CGO_ENABLED"), "GOENV": os.environ.get("GOENV")}) + "\n")
TAG = ":ghcr.io/fosterstack/cache:cand-production"
for r in json.load(open(os.environ["FAKE_CFG"])):
    if r["tool"] != tool:
        continue
    if not all(h in args for h in r.get("has", [])):
        continue
    if not all(any(a.startswith(p) for a in args) for p in r.get("has_prefix", [])):
        continue
    if r.get("touch"):
        dst = args[-1].split(":", 1)[1]
        if dst.endswith(TAG):
            dst = dst[: -len(TAG)]
        with open(dst, "w") as fh:
            fh.write("archive-bytes")
    out = r.get("stdout", "")
    if "stdout_json" in r:
        out = json.dumps(r["stdout_json"])
    sys.stdout.write(out); sys.stderr.write(r.get("stderr", ""))
    sys.exit(r.get("rc", 0))
sys.exit(2)
''' % sys.executable


def _pkgs(n, kind="deb"):
    return [{"id": "p%d" % i, "name": "pkg%d" % i, "version": "1.%d" % i, "type": kind,
             "purl": "pkg:%s/debian/pkg%d@1.%d" % (kind, i, i)} for i in range(n)]


GRYPE = {"matches": [{"artifact": {"name": "libc6", "version": "2.36", "type": "deb"}},
                     {"artifact": {"name": "libc6", "version": "2.36", "type": "deb"}},
                     {"artifact": {"name": "golang.org/x/net", "version": "0.1", "type": "go-module"}}],
         "descriptor": {"db": {"status": {"from": "https://x/vulnerability-db_v6_2026-09-22T01:02:03Z.tar.zst"}}}}
SYFT = {"distro": {"id": "Debian", "versionID": "12.0"},
        "artifacts": _pkgs(10) + [
            {"id": "node", "name": "node", "version": "18.19.0", "type": "binary", "purl": "pkg:generic/node@18.19.0"},
            {"id": "ossl", "name": "openssl", "version": "3.0.2", "type": "binary", "purl": "pkg:generic/openssl@3.0.2"}],
        "artifactRelationships": [
            {"parent": "node", "child": "ossl", "type": "contains"},
            {"parent": "p0", "child": "p1", "type": "dependency-of"}]}
EOL = {"debian": [{"cycle": "12", "eol": "2028-06-10", "lts": "2026-06-10", "latest": "12.7",
                   "latestReleaseDate": "2026-08-31"}],
       "nodejs": [{"cycle": "18", "eol": "2025-04-30", "latest": "18.20.4"}]}


class _Resp:
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def read(self):
        return self.body


def _fake_urlopen(url, timeout=None):
    prod = url.rsplit("/", 1)[1][:-len(".json")]
    if prod not in EOL:
        raise OSError("404 " + url)
    return _Resp(json.dumps(EOL[prod]).encode())


class Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="covmanifest-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fb = os.path.join(self.tmp, "fakebin"); os.makedirs(self.fb)
        fake = os.path.join(self.fb, "_fake")
        _wr(fake, FAKE)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IXUSR)
        for t in TOOLS:
            os.symlink(fake, os.path.join(self.fb, t))
        self.log = os.path.join(self.tmp, "argv.log"); _wr(self.log, "")
        self.cfg = os.path.join(self.tmp, "cfg.json")
        self.reports = os.path.join(self.tmp, "reports")
        self.source = os.path.join(self.tmp, "src"); os.makedirs(self.source)
        _wr(os.path.join(self.source, "go.mod"), "// c\nmodule github.com/fosterstack/cache\n\ngo 1.22\n")
        self.rescan = os.path.join(self.tmp, "rescan", "a", "b"); os.makedirs(self.rescan)
        self.prod_oci = os.path.join(self.rescan, "production"); os.makedirs(os.path.join(self.prod_oci, "blobs", "sha256")); _wr(os.path.join(self.prod_oci, "oci-layout"), "{}")   # the OCI layout directory of the images artifact
        self.kdl = os.path.join(self.tmp, "kdl.json"); _wr(self.kdl, "{}")
        self.out = os.path.join(self.tmp, "out", "manifest.json")
        self.oci = os.path.join(self.reports, "candidate.oci"); self.tar = os.path.join(self.reports, "candidate.tar")
        self.envlog = os.path.join(self.tmp, "env.log"); _wr(self.envlog, "")
        self.env = {"PATH": self.fb, "FAKE_LOG": self.log, "FAKE_ENVLOG": self.envlog, "FAKE_CFG": self.cfg, "AUDITOR_TODAY": "2026-09-27"}

    def rules(self, rules):
        _wr(self.cfg, json.dumps(rules))

    def argv(self):
        return [json.loads(l) for l in _rd(self.log).splitlines() if l.strip()]

    def run_main(self, args, env_extra=None, drop=(), runner=None):
        env = dict(os.environ); env.update(self.env); env.update(env_extra or {})
        for k in tuple(drop) + ("AUDITOR_TEST_IMAGE", "GITHUB_SHA"):
            if k not in (env_extra or {}):
                env.pop(k, None)
        buf = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(M.cli, "ARGS", list(args)), \
                mock.patch("urllib.request.urlopen", _fake_urlopen), contextlib.redirect_stdout(buf):
            (runner or M.main)()
        return buf.getvalue()

    def base_args(self, *extra):
        return ["--rescan-dir", os.path.dirname(os.path.dirname(self.rescan)), "--reports", self.reports,
                "--source-dir", self.source, "--out", self.out, "--known-defect-log", self.kdl] + list(extra)


GOOD_RULES = [
    {"tool": "skopeo", "has": ["copy"], "touch": True},
    {"tool": "skopeo", "has": ["inspect"], "has_prefix": ["docker-archive:"], "stdout": "sha256:deadbeef\n"},
    {"tool": "syft", "stdout_json": SYFT},
    {"tool": "govulncheck", "has": ["-version"], "stdout": "Go: go1.22\n"},
    {"tool": "govulncheck", "has": ["-json"], "stdout": "{\"config\":{}}\n", "rc": 3},
]


class MainHappy(Harness):
    def test_full_run_rescan_dir(self):
        self.rules(GOOD_RULES)
        pd = self.panel_dir()
        out = self.run_main(self.base_args("--kev", "/k/kev.json", "--panel-dir", pd, "--commit", C40))
        m = _rj(self.out)
        calls = self.argv()
        copies = [c for c in calls if c[:2] == ["skopeo", "copy"]]
        self.assertEqual(copies, [
            ["skopeo", "copy", "--override-arch", "amd64", "--override-os", "linux", "oci:" + self.prod_oci,
             "oci-archive:%s:%s" % (self.oci, M.TAG)],
            ["skopeo", "copy", "--override-arch", "amd64", "--override-os", "linux", "oci:" + self.prod_oci,
             "docker-archive:%s:%s" % (self.tar, M.TAG)]])
        self.assertIn(["syft", "oci-archive:" + self.oci, "-o", "syft-json"], calls)
        self.assertIn(["govulncheck", "-json", "./..."], calls)
        self.assertEqual({c[0] for c in calls}, {"skopeo", "syft", "govulncheck"})            # no scanner of its own runs
        inspects = [c for c in calls if c[:2] == ["skopeo", "inspect"]]
        self.assertEqual(inspects, [["skopeo", "inspect", "--format", "{{.Digest}}", "docker-archive:" + self.tar]])
        # manifest content
        self.assertEqual(m["commit"], C40)
        self.assertEqual(m["module"], "github.com/fosterstack/cache")
        self.assertEqual(m["base_os"], "debian 12.0")
        self.assertEqual(m["candidate_digests"], {"production": "sha256:deadbeef"})
        self.assertEqual(m["known_defect_log"], self.kdl)
        self.assertEqual(m["kev_catalog"], "/k/kev.json")
        self.assertEqual(m["provenance"], {"source": "own-scan", "candidate": "production", "scanned": "docker-archive"})
        self.assertEqual(m["scanner_set"], "panel")
        self.assertEqual(m["govulncheck"], {"path": os.path.join(self.reports, "govulncheck.json"),
                                            "module": "github.com/fosterstack/cache", "commit": C40,
                                            "complete": True, "scan_level": "symbol"})
        self.assertEqual(m["carriers"], [{"component": "openssl", "component_purl": "pkg:generic/openssl@3.0.2",
                                          "component_version": "3.0.2", "carrier": "node",
                                          "carrier_purl": "pkg:generic/node@18.19.0", "carrier_version": "18.19.0",
                                          "how": "bundled"}])
        self.assertEqual(m["eol"], [
            {"carrier": "debian", "cycle": "12", "status": "maintenance", "eol_date": "2028-06-10"},
            {"carrier": "nodejs", "cycle": "18", "status": "eol", "eol_date": "2025-04-30"}])
        self.assertEqual(m["base"], {"release": "debian 12.0", "behind_threshold_days": 30,
                                     "days_behind": 27, "latest": "12.7"})
        # job log
        self.assertIn("archives: oci=True tar=True", out)
        self.assertIn("image scanners that ran: ['grype', 'scout', 'inspector', 'google']", out)

    def panel_dir(self, findings=(), dnr=None):
        """A valid full-matrix panel-evidence directory (every scanner ran everywhere unless `dnr` {image: [scanners]} says otherwise)."""
        from auditorlib import parsers as PL
        d = os.path.join(self.tmp, "panel"); os.makedirs(d, exist_ok=True)
        images = {}
        for im in sorted(PL.panel_images()):
            exp = [x for x in PL.PANEL_SCANNERS if PL.panel_expected(x, im)]
            bad = [x for x in (dnr or {}).get(im, []) if x in exp]
            ran = sorted(x for x in exp if x not in bad)
            images[im] = {"counts": {x: 10 for x in ran}, "did_not_run": sorted(bad), "ran": ran, "counts_for_day": len(ran) >= 3}
        v = {"images": images, "not_counted": sorted(i for i, st in images.items() if not st["counts_for_day"]),
             "scanner_failures": sorted("%s on %s" % (x, i) for i, st in images.items() for x in st["did_not_run"]),
             "findings": list(findings), "unique": [f for f in findings if f["unique"]], "vex_covered": [], "issue": ""}
        v["exit"] = 2 if (v["not_counted"] or v["scanner_failures"]) else 0
        _wr(os.path.join(d, "verdict.json"), json.dumps(v))
        return d

    def test_panel_mode_runs_no_scanner_and_records_the_four(self):
        # 0600 option A, PR 2b-1: with --panel-dir the auditor reads the panel's four scanners from the rescan's verdict and runs none of its own
        self.rules([r for r in GOOD_RULES if r["tool"] in ("skopeo", "syft", "govulncheck")])
        pd = self.panel_dir()
        self.run_main(self.base_args("--panel-dir", pd, "--commit", C40))
        m = _rj(self.out)
        tools = {c[0] for c in self.argv()}
        self.assertFalse(tools & {"grype", "trivy", "osv-scanner", "snyk"}, tools)
        self.assertTrue({"syft", "govulncheck"} <= tools)                      # the cataloguer and the reachability scan are not panel scanners
        self.assertEqual(m["scanner_set"], "panel")
        verdict = os.path.join(pd, "verdict.json")
        self.assertEqual(m["scanner_reports"], {x: verdict for x in ("grype", "scout", "inspector", "google")})
        self.assertTrue(all(m["scanner_status"][x]["ran"] for x in m["scanner_reports"]))
        self.assertEqual(m["panel"]["not_counted"], []); self.assertEqual(m["panel"]["scanner_failures"], [])
        self.assertEqual(m["base_os"], "debian 12.0")                            # syft still supplies the base OS and the carriers
        self.assertTrue(m["carriers"])

    def test_panel_mode_with_a_scanner_that_missed_an_image_records_it_never_clean(self):
        self.rules([r for r in GOOD_RULES if r["tool"] in ("skopeo", "syft", "govulncheck")])
        from auditorlib import parsers as PL
        dbg = sorted(i for i in PL.panel_images() if i.endswith("-amd64") and not i.startswith("production"))[0]    # main ships debug, chain-v030 drops it
        pd = self.panel_dir(dnr={dbg: ["scout", "google"]})
        self.run_main(self.base_args("--panel-dir", pd))
        m = _rj(self.out)
        self.assertEqual(m["scanner_reports"]["scout"], None); self.assertEqual(m["scanner_reports"]["google"], None)
        self.assertIn(dbg, m["scanner_status"]["scout"]["reason"])
        self.assertEqual(m["panel"]["not_counted"], [dbg])             # two scanners on an image is under the quorum of three

    def test_panel_mode_without_a_verdict_is_all_four_did_not_run(self):
        self.rules([r for r in GOOD_RULES if r["tool"] in ("skopeo", "syft", "govulncheck")])
        empty = os.path.join(self.tmp, "no-panel"); os.makedirs(empty)
        self.run_main(self.base_args("--panel-dir", empty))
        m = _rj(self.out)
        self.assertEqual(m["scanner_set"], "panel")
        self.assertTrue(all(m["scanner_reports"][x] is None and not m["scanner_status"][x]["ran"] for x in ("grype", "scout", "inspector", "google")))
        self.assertIsNone(m["panel"]["not_counted"])                              # unknown, so the auditor cannot call the day complete

    def test_script_entrypoint_runs_main(self):
        # `python auditor-manifest.py ...` reaches main(): with no archive source it exits non-zero.
        self.rules([{"tool": "skopeo", "rc": 1, "stderr": "boom"}])
        shutil.rmtree(os.path.join(self.tmp, "rescan"))
        os.makedirs(os.path.join(self.tmp, "rescan"))
        with self.assertRaises(SystemExit) as cm:
            self.run_main(self.base_args(), runner=lambda: runpy.run_path(SRC, run_name="__main__"))
        self.assertEqual(str(cm.exception),
                         "auditor-manifest: cannot ingest the candidate — no production OCI layout directory (images/production) in the rescan artifacts")
        self.assertEqual(self.argv(), [])


HEAD40 = "0123456789abcdef0123456789abcdef01234567"


class SourceBinding(Harness):
    """rc-5b fix 4 (handoff 0663, ruling A2): the source scan runs on the tree it is told to (the selected rescan's head), stamps that head,
    and is recorded 'did not run' when there is no such tree."""

    panel_dir = MainHappy.panel_dir

    def gv(self):
        return [json.loads(l) for l in _rd(self.envlog).splitlines() if l.strip() and json.loads(l)["tool"] == "govulncheck" and "-json" in json.loads(l)["args"]]

    def test_the_scan_runs_in_the_source_dir_and_stamps_the_given_head(self):
        self.rules(GOOD_RULES)
        self.run_main(self.base_args("--panel-dir", self.panel_dir(), "--commit", HEAD40), env_extra={"GITHUB_SHA": "f" * 40})
        m = _rj(self.out)
        self.assertEqual(m["commit"], HEAD40)
        self.assertEqual(m["govulncheck"]["commit"], HEAD40)
        (call,) = self.gv()
        self.assertEqual(call["cwd"], os.path.realpath(self.source))      # never the process's own directory

    def test_a_foreign_tree_cannot_fetch_a_toolchain_or_modules(self):
        self.rules(GOOD_RULES)
        self.run_main(self.base_args("--panel-dir", self.panel_dir(), "--commit", HEAD40))
        (call,) = self.gv()
        self.assertEqual((call["GOTOOLCHAIN"], call["GOFLAGS"], call["GOPROXY"], call["CGO_ENABLED"], call["GOENV"]), ("local", "-mod=vendor", "off", "0", "off"))

    def test_a_commit_that_is_not_40_hex_is_refused(self):
        self.rules(GOOD_RULES)
        for bad in ("abc123", "", "unknown", HEAD40.upper(), HEAD40 + "0", HEAD40[:-1] + "g", "HEAD", HEAD40[:-1] + "\n"):
            with self.assertRaises(SystemExit, msg=repr(bad)):
                self.run_main(self.base_args("--panel-dir", self.panel_dir(), "--commit", bad))
        self.assertFalse(os.path.exists(self.out))

    def test_the_runs_own_sha_is_never_the_stamped_head(self):
        self.rules(GOOD_RULES)
        self.run_main(self.args_without_source_or_commit(), env_extra={"GITHUB_SHA": "f" * 40})
        m = _rj(self.out)
        self.assertEqual(m["commit"], "unknown")
        self.assertIsNone(m["govulncheck"])

    def test_a_tree_with_no_govulncheck_installed_is_did_not_run(self):
        self.rules(GOOD_RULES)
        real = M._version

        def no_govulncheck(tool, args=("--version",)):
            return None if tool == "govulncheck" else real(tool, args)
        with mock.patch.object(M, "_version", no_govulncheck):
            out = self.run_main(self.base_args("--panel-dir", self.panel_dir(), "--commit", HEAD40))
        self.assertEqual(self.gv(), [])                      # the tool is never run
        self.assertIsNone(_rj(self.out)["govulncheck"])
        self.assertIn("govulncheck did not run: the tool is not installed", out)

    def test_a_scan_that_fails_says_why(self):
        self.rules([r for r in GOOD_RULES if r.get("has") != ["-json"]] + [{"tool": "govulncheck", "has": ["-json"], "stdout": "", "stderr": "go: inconsistent vendoring in /src", "rc": 1}])
        out = self.run_main(self.base_args("--panel-dir", self.panel_dir(), "--commit", HEAD40))
        self.assertIsNone(_rj(self.out)["govulncheck"])
        self.assertIn("govulncheck did not complete (rc 1)", out)
        self.assertIn("inconsistent vendoring", out)

    def test_a_source_tree_with_no_govulncheck_installed_says_so(self):
        self.rules([r for r in GOOD_RULES if r.get("tool") != "govulncheck"])
        out = self.run_main(self.base_args("--panel-dir", self.panel_dir(), "--commit", HEAD40))
        self.assertIsNone(_rj(self.out)["govulncheck"])
        self.assertIn("govulncheck did not run: the tool is not installed", out)

    def args_without_source_or_commit(self):
        return self.base_args("--panel-dir", self.panel_dir())

    def args_without_source(self):
        a = self.base_args("--panel-dir", self.panel_dir(), "--commit", HEAD40)
        i = a.index("--source-dir")
        return a[:i] + a[i + 2:]

    def test_no_source_dir_is_did_not_run_never_the_current_directory(self):
        self.rules(GOOD_RULES)
        out = self.run_main(self.args_without_source())
        self.assertEqual(self.gv(), [])
        self.assertIsNone(_rj(self.out)["govulncheck"])
        self.assertIn("govulncheck did not run", out)

    def test_a_source_dir_that_is_not_a_directory_is_did_not_run(self):
        self.rules(GOOD_RULES)
        for bad in (os.path.join(self.tmp, "nope"), ""):
            a = self.args_without_source() + ["--source-dir", bad]
            self.run_main(a)
            self.assertIsNone(_rj(self.out)["govulncheck"], repr(bad))
        self.assertEqual(self.gv(), [])


class MainDegraded(Harness):
    def test_test_image_both_copies_fail_exits(self):
        self.rules([{"tool": "skopeo", "has": ["copy"], "rc": 1, "stderr": "unauthorized\n"}])
        with self.assertRaises(SystemExit) as cm:
            self.run_main(self.base_args("--test-image", "debian:12.0@sha256:abc"))
        self.assertEqual(str(cm.exception),
                         "auditor-manifest: cannot ingest the candidate — skopeo could not pull docker://debian@sha256:abc")
        srcs = {c[-2] for c in self.argv()}
        self.assertEqual(srcs, {"docker://debian@sha256:abc"})

    def test_test_image_without_digest_is_refused(self):     # Codex #164 adversarial r2, N02
        with self.assertRaises(SystemExit) as cm:
            self.run_main(self.base_args("--test-image", "debian:12.0"))
        self.assertEqual(str(cm.exception), "auditor-manifest: cannot ingest the candidate — "
                         "test image debian:12.0 is not pinned by digest (ref@sha256:…); refused")
        self.assertEqual(self.argv(), [])                        # nothing was fetched

    def test_test_image_env_tar_only_and_no_panel_directory(self):
        rules = [
            {"tool": "skopeo", "has": ["copy"], "has_prefix": ["docker-archive:"], "touch": True},
            {"tool": "skopeo", "has": ["copy"], "rc": 1, "stderr": "no oci\n"},
            {"tool": "syft", "rc": 1},
        ]
        self.rules(rules)
        with mock.patch.object(M, "_lifecycle", side_effect=RuntimeError("eol down")):
            out = self.run_main(self.base_args(), env_extra={"AUDITOR_TEST_IMAGE": "debian:12.0@sha256:abc"})
        m = _rj(self.out)
        calls = self.argv()
        self.assertIn(["syft", "docker-archive:" + self.tar, "-o", "syft-json"], calls)
        self.assertFalse(any(c[:2] == ["govulncheck", "-json"] for c in calls))
        self.assertEqual([c for c in calls if c[:2] == ["skopeo", "inspect"]],
                         [["skopeo", "inspect", "--format", "{{.Digest}}", "docker-archive:" + self.tar]])
        self.assertEqual(m["scanner_set"], "panel")                              # no panel directory: all four did not run, the day is not complete
        self.assertEqual(set(m["scanner_reports"].values()), {None})
        self.assertEqual({v["reason"] for v in m["scanner_status"].values()}, {"no panel-evidence directory was given"})
        self.assertIsNone(m["panel"]["not_counted"])
        self.assertIsNone(m["govulncheck"])
        self.assertEqual(m["base_os"], "debian")
        self.assertEqual(m["candidate_digests"]["production"], "sha256:abc")
        self.assertEqual((m["eol"], m["base"], m["carriers"]), ([], {}, []))
        self.assertEqual(m["provenance"]["source"], "test-image")
        self.assertEqual(m["provenance"]["candidate"], "test_image=debian:12.0@sha256:abc")
        self.assertEqual(m["commit"], "unknown")
        self.assertIn("skopeo docker://debian@sha256:abc -> oci-archive:", out)
        self.assertIn("FAILED (rc 1): no oci", out)
        self.assertIn("archives: oci=False tar=True", out)
        self.assertIn("syft did not run (rc 1); the carriers and base OS stay unknown", out)
        self.assertIn("lifecycle lookup failed: eol down", out)
        self.assertIn("image scanners that ran: NONE", out)

    def test_syft_parse_failure_oci_digest_and_today_fallback(self):
        rules = [
            {"tool": "skopeo", "has": ["copy"], "touch": True},
            {"tool": "skopeo", "has": ["inspect"], "has_prefix": ["docker-archive:"], "rc": 1},
            {"tool": "skopeo", "has": ["inspect"], "has_prefix": ["oci-archive:"], "stdout": "sha256:ocid\n"},
            {"tool": "syft", "stdout": "{not json"},
            {"tool": "govulncheck", "has": ["--version"], "stdout": "govulncheck v1\n"},
            {"tool": "govulncheck", "has": ["-json"], "stdout": "", "rc": 0},
        ]
        self.rules(rules)

        class _NoToday(date):
            @classmethod
            def today(cls):
                raise OSError("no clock")
        with mock.patch("datetime.date", _NoToday), mock.patch.object(M, "_lifecycle", wraps=M._lifecycle) as lc:
            out = self.run_main(self.base_args("--commit", C40), env_extra={}, drop=("AUDITOR_TODAY",))
        self.assertEqual(lc.call_args.args[3], "1970-01-01")
        self.assertEqual(lc.call_args.args[0], "debian")
        m = _rj(self.out)
        self.assertEqual((m["carriers"], m["base_os"]), ([], "debian"))        # an unreadable SBOM yields no carriers and the default base OS
        self.assertEqual(m["candidate_digests"]["production"], "sha256:ocid")
        self.assertEqual([c[-1] for c in self.argv() if c[:2] == ["skopeo", "inspect"]],
                         ["docker-archive:" + self.tar, "oci-archive:" + self.oci])
        # govulncheck: found via --version fallback, ran, but empty output -> no evidence block
        self.assertIn(["govulncheck", "-version"], self.argv())
        self.assertIn(["govulncheck", "-json", "./..."], self.argv())
        self.assertIsNone(m["govulncheck"])
        self.assertEqual(m["known_defect_log"], self.kdl)
        # clock fallback 1970-01-01: debian 12's LTS date has not "passed" yet, so no maintenance flag
        # (with the real date it would be flagged — see test_full_run_rescan_dir)
        self.assertEqual(m["eol"], [])
        self.assertEqual(m["base"]["days_behind"], (date(1970, 1, 1) - date(2026, 8, 31)).days)


class Helpers(Harness):
    def test_run_capture_outfile_and_exception(self):
        self.rules([{"tool": "grype", "stdout": "hello\n", "stderr": "err!\n", "rc": 3}])
        with mock.patch.dict(os.environ, self.env):
            self.assertEqual(M._run(["grype", "x"]), (3, "hello\n"))
            p = os.path.join(self.tmp, "o.txt")
            self.assertEqual(M._run(["grype", "y"], out_path=p), (3, "err!\n"))
            self.assertEqual(_rd(p), "hello\n")
            rc, msg = M._run([os.path.join(self.tmp, "no-such-tool")])
            self.assertEqual(rc, 255); self.assertIn("no-such-tool", msg)
        self.assertEqual(self.argv(), [["grype", "x"], ["grype", "y"]])

    def test_version(self):
        self.rules([{"tool": "grype", "has": ["--version"], "stdout": "  grype 1.0\nmore\n"},
                    {"tool": "trivy", "has": ["-v"], "stdout": "   \n"},
                    {"tool": "syft", "rc": 1, "stdout": "syft 1\n"}])
        with mock.patch.dict(os.environ, self.env):
            self.assertEqual(M._version("grype"), "grype 1.0")
            self.assertIsNone(M._version("trivy", ("-v",)))
            self.assertIsNone(M._version("syft"))
        self.assertEqual(self.argv(), [["grype", "--version"], ["trivy", "-v"], ["syft", "--version"]])

    def test_skopeo_ok_and_fail(self):
        self.rules([{"tool": "skopeo", "has": ["good"]}, {"tool": "skopeo", "rc": 5, "stderr": "  " + "e" * 500}])
        buf = io.StringIO()
        with mock.patch.dict(os.environ, self.env), contextlib.redirect_stdout(buf):
            self.assertTrue(M._skopeo("good", "d1"))
            self.assertFalse(M._skopeo("bad", "d2"))
        self.assertEqual(buf.getvalue(), "skopeo bad -> d2 FAILED (rc 5): %s\n" % ("e" * 400))

    def test_archives_rescan_failure_paths(self):
        empty = os.path.join(self.tmp, "empty"); os.makedirs(empty)
        self.assertEqual(M._archives(empty, "", self.oci, self.tar), (None, "no production OCI layout directory (images/production) in the rescan artifacts"))
        self.rules([{"tool": "skopeo", "rc": 1}])
        with mock.patch.dict(os.environ, self.env), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M._archives(os.path.join(self.tmp, "rescan"), "", self.oci, self.tar),
                             (None, "skopeo convert failed"))
            self.rules([{"tool": "skopeo", "has_prefix": ["docker-archive:"]}, {"tool": "skopeo", "rc": 1}])
            self.assertEqual(M._archives(os.path.join(self.tmp, "rescan"), "", self.oci, self.tar),
                             ("production", None))

    def test_norm_ref(self):
        self.assertEqual(M._norm_ref("debian:12.0@sha256:X"), "debian@sha256:X")
        self.assertEqual(M._norm_ref("ghcr.io/a/b@sha256:Y"), "ghcr.io/a/b@sha256:Y")
        self.assertEqual(M._norm_ref("debian:12.0"), "debian:12.0")

    def test_module(self):
        self.assertEqual(M._module(self.source), "github.com/fosterstack/cache")
        d = os.path.join(self.tmp, "nomod"); os.makedirs(d)
        self.assertIsNone(M._module(d))
        _wr(os.path.join(d, "go.mod"), "go 1.22\n")
        self.assertIsNone(M._module(d))


def w(obj, tmp):
    fd, p = tempfile.mkstemp(suffix=".json", dir=tmp); os.close(fd)
    _wr(p, obj if isinstance(obj, str) else json.dumps(obj))
    return p


class Inventories(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="covmanifest-inv-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_base_os(self):
        self.assertEqual(M._base_os(w(SYFT, self.tmp)), "debian 12.0")
        self.assertEqual(M._base_os(w({"distro": {"id": " Alpine "}}, self.tmp)), "alpine")
        self.assertIsNone(M._base_os(w({"distro": None}, self.tmp)))
        self.assertIsNone(M._base_os(w("{broken", self.tmp)))
        self.assertIsNone(M._base_os(os.path.join(self.tmp, "missing.json")))

    def test_a_syft_document_of_the_wrong_shape_yields_no_carriers_and_no_base_os(self):
        for bad in ([], "x", 5, {"artifacts": 5}, {"artifacts": [1]}, {"artifacts": [{"id": "a"}], "artifactRelationships": 3},
                    {"artifacts": [{"id": "a"}], "artifactRelationships": [7]}, {"distro": [1]}):
            self.assertEqual(M._carriers(w(bad, self.tmp)), [], bad)
            self.assertIsNone(M._base_os(w(bad, self.tmp)), bad)

    def test_carriers(self):
        self.assertEqual(M._carriers(w("nope", self.tmp)), [])
        art = [{"id": "a", "name": "node", "version": "18", "purl": "pkg:generic/node@18"},
               {"id": "b", "name": "openssl", "version": "3", "purl": "pkg:generic/openssl@3"},
               {"id": "c", "name": "file", "version": None},
               {"id": "d", "name": "node2", "version": "18", "purl": "pkg:generic/node@18"}]
        rels = [{"parent": "a", "child": "b", "type": "contains"},
                {"parent": "a", "child": "b", "type": "contains"},          # duplicate -> once
                {"parent": "a", "child": "zzz", "type": "contains"},        # dangling child
                {"parent": "a", "child": "c", "type": "contains"},          # child without purl
                {"parent": "a", "child": "a", "type": "contains"},          # self
                {"parent": "d", "child": "a", "type": "contains"},          # same purl
                {"parent": "b", "child": "a", "type": "dependency-of"},     # not a carrying relation
                {"parent": "b", "child": "a", "type": "ownership-by-file-overlap"}]
        out = M._carriers(w({"artifacts": art + [{"name": "noid"}], "artifactRelationships": rels}, self.tmp))
        self.assertEqual(out, [{"component": "openssl", "component_purl": "pkg:generic/openssl@3", "component_version": "3",
                                "carrier": "node", "carrier_purl": "pkg:generic/node@18", "carrier_version": "18",
                                "how": "bundled"}])


class Lifecycle(unittest.TestCase):
    def test_eol_fetch(self):
        with mock.patch("urllib.request.urlopen", side_effect=_fake_urlopen) as u:
            self.assertEqual(M._eol_fetch("debian"), EOL["debian"])
            self.assertIsNone(M._eol_fetch("nosuch"))
        self.assertEqual([c.args[0] for c in u.call_args_list],
                         ["https://endoflife.date/api/debian.json", "https://endoflife.date/api/nosuch.json"])
        self.assertEqual(u.call_args.kwargs, {"timeout": 10})
        with mock.patch("urllib.request.urlopen", return_value=_Resp(b"<html>")):
            self.assertIsNone(M._eol_fetch("debian"))

    def test_small_helpers(self):
        self.assertEqual(M._major("12.7"), "12.7"); self.assertEqual(M._major("v1"), None); self.assertIsNone(M._major(None))
        self.assertEqual(M._days_between("2026-09-01", "2026-09-27"), 26)
        self.assertIsNone(M._days_between("garbage", "2026-09-27"))
        today = "2026-09-27"
        self.assertEqual(M._cycle_status({"eol": "2026-01-01"}, today), "eol")
        self.assertEqual(M._cycle_status({"eol": "2030-01-01", "lts": True}, today), "maintenance")
        self.assertEqual(M._cycle_status({"eol": "2030-01-01", "lts": "2026-01-01"}, today), "maintenance")
        self.assertEqual(M._cycle_status({"eol": "2030-01-01", "lts": "2027-01-01"}, today), "active")
        self.assertEqual(M._cycle_status({"eol": False, "lts": False}, today), "active")
        data = [{"cycle": "3.12"}, {"cycle": 3}, {"cycle": "18"}]
        self.assertEqual(M._match_cycle(data, "3.12.4"), {"cycle": "3.12"})
        self.assertEqual(M._match_cycle(data, "3.11.1"), {"cycle": 3})
        self.assertIsNone(M._match_cycle(data, "20.1"))
        self.assertIsNone(M._match_cycle(data, "latest"))

    def test_lifecycle(self):
        calls = []
        feed = {"debian": [{"cycle": "11", "eol": "2026-08-14"}, {"cycle": "12", "latest": "12.0",
                                                                  "latestReleaseDate": "2026-01-01"}],
                "python": [{"cycle": "3.12", "eol": "2028-10-31"}],
                "nodejs": [{"cycle": "20", "eol": "2026-04-30"}],
                "openssl": None}

        def fetch(p):
            calls.append(p); return feed.get(p)
        carriers = [{"carrier": "Node", "carrier_version": "20.1"},
                    {"carrier": "node", "carrier_version": "20.2"},     # same product -> not repeated
                    {"carrier": "python", "carrier_version": "3.12.1"},  # active -> no flag
                    {"carrier": "openssl", "carrier_version": "3.0"},    # fetch returns None
                    {"carrier": "busybox", "carrier_version": "1.36"},   # unknown product, no fetch
                    {"carrier": "golang", "carrier_version": "1.99"}]    # no data at all
        eol, base = M._lifecycle("debian 12.0", carriers, fetch, "2026-09-27")
        self.assertEqual(eol, [{"carrier": "nodejs", "cycle": "20", "status": "eol", "eol_date": "2026-04-30"}])
        # latest == pinned release -> no pin-lag
        self.assertEqual(base, {"release": "debian 12.0", "behind_threshold_days": 30})
        self.assertEqual(calls, ["debian", "nodejs", "nodejs", "python", "openssl", "go"])
        # unmatched base cycle falls back to the first listed cycle; unknown base -> no fetch
        eol2, base2 = M._lifecycle("debian 99", [], fetch, "2026-09-27")
        self.assertEqual(eol2, [{"carrier": "debian", "cycle": "11", "status": "eol", "eol_date": "2026-08-14"}])
        self.assertEqual(base2, {"release": "debian 99", "behind_threshold_days": 30})
        calls.clear()
        self.assertEqual(M._lifecycle("scratch", None, fetch, "2026-09-27"), ([], {}))
        self.assertEqual(M._lifecycle(None, None, fetch, "2026-09-27"), ([], {}))
        self.assertEqual(calls, [])
        # malformed latestReleaseDate -> pin-lag has no days_behind
        _, base3 = M._lifecycle("ubuntu 22.04", [], lambda p: [{"cycle": "22.04", "latest": "22.04.5",
                                                               "latestReleaseDate": "2026-13-45"}], "2026-09-27")
        self.assertEqual(base3, {"release": "ubuntu 22.04", "behind_threshold_days": 30})


if __name__ == "__main__":
    unittest.main()
