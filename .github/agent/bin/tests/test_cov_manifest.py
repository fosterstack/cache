"""Coverage + behaviour tests for auditor-manifest.py (REQ-AUD-18 AC2).

The scanners (grype, trivy, osv-scanner, syft, snyk, govulncheck, skopeo) are replaced by ONE
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


TOOLS = ("grype", "trivy", "osv-scanner", "syft", "snyk", "govulncheck", "skopeo")

FAKE = r'''#!%s
import json, os, sys
tool = os.path.basename(sys.argv[0]); args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as fh:
    fh.write(json.dumps([tool] + args) + "\n")
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
TRIVY = {"Results": [{"Class": "os-pkgs", "Packages": _pkgs(10), "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]},
                     {"Class": "lang-pkgs", "Packages": _pkgs(2, "golang")}]}
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
        self.prod_oci = os.path.join(self.rescan, "production.oci"); _wr(self.prod_oci, "x")
        self.kdl = os.path.join(self.tmp, "kdl.json"); _wr(self.kdl, "{}")
        self.out = os.path.join(self.tmp, "out", "manifest.json")
        self.oci = os.path.join(self.reports, "candidate.oci"); self.tar = os.path.join(self.reports, "candidate.tar")
        self.env = {"PATH": self.fb, "FAKE_LOG": self.log, "FAKE_CFG": self.cfg, "AUDITOR_TODAY": "2026-09-27"}

    def rules(self, rules):
        _wr(self.cfg, json.dumps(rules))

    def argv(self):
        return [json.loads(l) for l in _rd(self.log).splitlines() if l.strip()]

    def run_main(self, args, env_extra=None, drop=("SNYK_TOKEN",), runner=None):
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
    {"tool": "grype", "has": ["--version"], "stdout": "grype 0.118.0\nextra\n"},
    {"tool": "grype", "stdout_json": GRYPE, "stderr": "a\nwarn one\nwarn two\n"},
    {"tool": "trivy", "has": ["--version"], "stdout": "Version: 0.56.0\n"},
    {"tool": "trivy", "stdout_json": TRIVY},
    {"tool": "osv-scanner", "has": ["--version"], "stdout": "osv-scanner version: 1.9.0\n"},
    {"tool": "osv-scanner", "has": ["image"], "stdout_json": {"results": []}},
    {"tool": "osv-scanner", "has": ["source"], "stdout_json": {"results": []}, "rc": 1},
    {"tool": "syft", "stdout_json": SYFT},
    {"tool": "snyk", "has": ["--version"], "stdout": "1.1293.0\n"},
    {"tool": "snyk", "has": ["container"], "stdout_json": {"dependencyCount": 100, "vulnerabilities": [{}, {}]}, "rc": 1},
    {"tool": "govulncheck", "has": ["-version"], "stdout": "Go: go1.22\n"},
    {"tool": "govulncheck", "has": ["-json"], "stdout": "{\"config\":{}}\n", "rc": 3},
]


class MainHappy(Harness):
    def test_full_run_rescan_dir(self):
        self.rules(GOOD_RULES)
        out = self.run_main(self.base_args("--kev", "/k/kev.json"),
                            env_extra={"SNYK_TOKEN": "tok", "GITHUB_SHA": "abc123"})
        m = _rj(self.out)
        # argv issued
        calls = self.argv()
        copies = [c for c in calls if c[:2] == ["skopeo", "copy"]]
        self.assertEqual(copies, [
            ["skopeo", "copy", "--override-arch", "amd64", "--override-os", "linux", "oci-archive:" + self.prod_oci,
             "oci-archive:%s:%s" % (self.oci, M.TAG)],
            ["skopeo", "copy", "--override-arch", "amd64", "--override-os", "linux", "oci-archive:" + self.prod_oci,
             "docker-archive:%s:%s" % (self.tar, M.TAG)]])
        self.assertIn(["grype", "oci-archive:" + self.oci, "-o", "json"], calls)
        self.assertIn(["trivy", "image", "--input", self.tar, "--quiet", "--format", "json"], calls)
        self.assertIn(["osv-scanner", "scan", "image", "--archive", self.tar, "--format", "json"], calls)
        self.assertIn(["syft", "oci-archive:" + self.oci, "-o", "syft-json"], calls)
        self.assertIn(["snyk", "container", "test", "docker-archive:" + self.tar, "--json", "--org=fosterstack-admin"], calls)
        self.assertIn(["osv-scanner", "scan", "source", "--format", "json", os.path.join(self.source, "go.mod")], calls)
        self.assertIn(["govulncheck", "-json", "./..."], calls)
        inspects = [c for c in calls if c[:2] == ["skopeo", "inspect"]]
        self.assertEqual(inspects, [["skopeo", "inspect", "--format", "{{.Digest}}", "docker-archive:" + self.tar]])
        # manifest content
        self.assertEqual(m["commit"], "abc123")
        self.assertEqual(m["module"], "github.com/fosterstack/cache")
        self.assertEqual(m["base_os"], "debian 12.0")
        self.assertEqual(m["candidate_digests"], {"production": "sha256:deadbeef"})
        self.assertEqual(m["known_defect_log"], self.kdl)
        self.assertEqual(m["kev_catalog"], "/k/kev.json")
        self.assertEqual(m["provenance"], {"source": "own-scan", "candidate": "production.oci", "scanned": "docker-archive"})
        st = m["scanner_status"]
        g = st["grype"]
        self.assertEqual((g["ran"], g["quorum_ok"], g["package_count"], g["os_package_count"], g["findings"],
                          g["db_date"], g["version"], g["reason"]),
                         (True, True, 12, 10, 3, "2026-09-22", "grype 0.118.0", "ok"))
        t = st["trivy"]
        self.assertEqual((t["ran"], t["package_count"], t["os_package_count"], t["findings"], t["version"]),
                         (True, 12, 10, 1, "Version: 0.56.0"))
        o = st["osv-scanner"]
        self.assertEqual((o["ran"], o["scan_ok"], o["package_count"]), (False, True, 0))
        self.assertEqual(o["reason"], "0 packages (osv-scanner does not read distroless dpkg status.d)")
        s = st["snyk"]
        self.assertTrue(s["ran"]); self.assertFalse(s["quorum_ok"])
        self.assertEqual((s["package_count"], s["findings"], s["version"]), (100, 2, "1.1293.0"))
        self.assertTrue(s["reason"].startswith("excluded from quorum: inventory outlier (os_packages=100 vs median 10)"))
        self.assertEqual(m["scanner_reports"], {
            "grype": os.path.join(self.reports, "grype.json"), "trivy": os.path.join(self.reports, "trivy.json"),
            "osv-scanner": None, "snyk": os.path.join(self.reports, "snyk.json"),
            "osv-scanner-gomod": os.path.join(self.reports, "osv-gomod.json")})
        self.assertEqual(st["osv-scanner-gomod"]["reason"], "ok")
        self.assertEqual(st["osv-scanner-gomod"]["version"], "osv-scanner version: 1.9.0")
        self.assertEqual(m["govulncheck"], {"path": os.path.join(self.reports, "govulncheck.json"),
                                            "module": "github.com/fosterstack/cache", "commit": "abc123",
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
        self.assertIn("grype stderr: warn one | warn two", out)
        self.assertIn("grype(syft) packages=12 os_packages=10 findings=3 scan_ok=True ran=True", out)
        self.assertIn("snyk QUORUM-EXCLUDED (findings kept): os_packages=100 outside [5.0, 20.0]", out)
        self.assertIn("snyk 1.1293.0 packages=100 findings=2 ran=True", out)
        self.assertIn("image scanners that ran: ['grype', 'trivy', 'snyk']", out)

    def test_script_entrypoint_runs_main(self):
        # `python auditor-manifest.py ...` reaches main(): with no archive source it exits non-zero.
        self.rules([{"tool": "skopeo", "rc": 1, "stderr": "boom"}])
        shutil.rmtree(os.path.join(self.tmp, "rescan"))
        os.makedirs(os.path.join(self.tmp, "rescan"))
        with self.assertRaises(SystemExit) as cm:
            self.run_main(self.base_args(), runner=lambda: runpy.run_path(SRC, run_name="__main__"))
        self.assertEqual(str(cm.exception),
                         "auditor-manifest: cannot ingest the candidate — no production.oci in the rescan artifacts")
        self.assertEqual(self.argv(), [])


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

    def test_test_image_env_tar_only_scanners_fail(self):
        rules = [
            {"tool": "skopeo", "has": ["copy"], "has_prefix": ["docker-archive:"], "touch": True},
            {"tool": "skopeo", "has": ["copy"], "rc": 1, "stderr": "no oci\n"},
            {"tool": "grype", "has_prefix": ["docker-archive:"], "stdout": "not json"},
            {"tool": "trivy", "has": ["image"], "rc": 2, "stderr": "l1\nl2\nl3\nl4\n"},
            {"tool": "osv-scanner", "has": ["image"], "stdout_json": {"results": []}},
            {"tool": "syft", "rc": 1},
            {"tool": "osv-scanner", "has": ["source"], "rc": 2},
        ]
        self.rules(rules)
        with mock.patch.object(M, "_lifecycle", side_effect=RuntimeError("eol down")):
            out = self.run_main(self.base_args(), env_extra={"AUDITOR_TEST_IMAGE": "debian:12.0@sha256:abc"})
        m = _rj(self.out)
        calls = self.argv()
        self.assertIn(["grype", "docker-archive:" + self.tar, "-o", "json"], calls)
        self.assertIn(["syft", "docker-archive:" + self.tar, "-o", "syft-json"], calls)
        self.assertFalse(any(c[0] == "snyk" for c in calls))
        self.assertFalse(any(c[:2] == ["govulncheck", "-json"] for c in calls))
        self.assertEqual([c for c in calls if c[:2] == ["skopeo", "inspect"]],
                         [["skopeo", "inspect", "--format", "{{.Digest}}", "docker-archive:" + self.tar]])
        st = m["scanner_status"]
        self.assertEqual((st["grype"]["ran"], st["grype"]["reason"]), (False, "scan failed (rc 255)"))
        self.assertEqual((st["trivy"]["ran"], st["trivy"]["reason"]), (False, "scan failed (rc 2)"))
        self.assertEqual(st["osv-scanner"]["reason"], "0 packages inventoried (scanner produced no package inventory)")
        self.assertEqual(st["snyk"], {"ran": False, "version": None, "reason": "no SNYK_TOKEN available; Snyk did not run",
                                      "package_count": None, "db_date": None})
        self.assertEqual(st["osv-scanner-gomod"]["reason"], "did not run (rc 2)")
        self.assertEqual(set(m["scanner_reports"].values()), {None})
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
        self.assertIn("trivy scan rc=2 stderr: ['l2', 'l3', 'l4']", out)
        self.assertIn("syft did not run (rc 1); grype inventory falls back to matched packages", out)
        self.assertIn("lifecycle lookup failed: eol down", out)
        self.assertIn("image scanners that ran: NONE", out)

    def test_syft_parse_failure_snyk_quota_oci_digest_and_today_fallback(self):
        rules = [
            {"tool": "skopeo", "has": ["copy"], "touch": True},
            {"tool": "skopeo", "has": ["inspect"], "has_prefix": ["docker-archive:"], "rc": 1},
            {"tool": "skopeo", "has": ["inspect"], "has_prefix": ["oci-archive:"], "stdout": "sha256:ocid\n"},
            {"tool": "grype", "stdout_json": GRYPE},
            {"tool": "trivy", "stdout_json": TRIVY},
            {"tool": "osv-scanner", "has": ["image"], "stdout_json": {"results": []}},
            {"tool": "syft", "stdout": "{not json"},
            {"tool": "snyk", "has": ["container"], "stdout": "You have reached your monthly limit", "rc": 2},
            {"tool": "govulncheck", "has": ["--version"], "stdout": "govulncheck v1\n"},
            {"tool": "govulncheck", "has": ["-json"], "stdout": "", "rc": 0},
        ]
        self.rules(rules)

        class _NoToday(date):
            @classmethod
            def today(cls):
                raise OSError("no clock")
        env = {"SNYK_TOKEN": "tok"}
        with mock.patch("datetime.date", _NoToday), mock.patch.object(M, "_lifecycle", wraps=M._lifecycle) as lc:
            out = self.run_main(self.base_args(), env_extra=env, drop=("SNYK_TOKEN", "AUDITOR_TODAY"))
        self.assertEqual(lc.call_args.args[3], "1970-01-01")
        self.assertEqual(lc.call_args.args[0], "debian")
        m = _rj(self.out)
        st = m["scanner_status"]
        self.assertIn("syft inventory parse failed:", out)
        # grype falls back to its matched-package inventory: 2 distinct, 1 OS
        self.assertEqual((st["grype"]["ran"], st["grype"]["package_count"], st["grype"]["os_package_count"]), (True, 2, 1))
        self.assertEqual((st["snyk"]["ran"], st["snyk"]["reason"], st["snyk"]["package_count"]),
                         (False, "quota/auth: could not run", 0))
        self.assertIsNone(m["scanner_reports"]["snyk"])
        self.assertEqual(m["candidate_digests"]["production"], "sha256:ocid")
        self.assertEqual([c[-1] for c in self.argv() if c[:2] == ["skopeo", "inspect"]],
                         ["docker-archive:" + self.tar, "oci-archive:" + self.oci])
        # govulncheck: found via --version fallback, ran, but empty output -> no evidence block
        self.assertIn(["govulncheck", "-version"], self.argv())
        self.assertIn(["govulncheck", "-json", "./..."], self.argv())
        self.assertIsNone(m["govulncheck"])
        # grype os=1 vs trivy os=10: median 5.5, grype below 2.75 -> excluded, trivy (10 <= 11) kept
        self.assertFalse(st["grype"]["quorum_ok"]); self.assertTrue(st["trivy"]["quorum_ok"])
        self.assertEqual(m["known_defect_log"], self.kdl)
        # clock fallback 1970-01-01: debian 12's LTS date has not "passed" yet, so no maintenance flag
        # (with the real date it would be flagged — see test_full_run_rescan_dir)
        self.assertEqual(m["eol"], [])
        self.assertEqual(m["base"]["days_behind"], (date(1970, 1, 1) - date(2026, 8, 31)).days)

    def test_grype_scan_failed_stays_not_run_even_with_syft_inventory(self):
        rules = [r for r in GOOD_RULES if not (r["tool"] == "grype" and "has" not in r)]
        rules.append({"tool": "grype", "rc": 2, "stderr": "db error"})
        self.rules(rules)
        args = self.base_args()
        args[args.index("--known-defect-log") + 1] = os.path.join(self.tmp, "absent.json")
        out = self.run_main(args)
        m = _rj(self.out)
        g = m["scanner_status"]["grype"]
        self.assertEqual((g["ran"], g["scan_ok"], g["package_count"], g["reason"]), (False, False, 12, "scan failed (rc 2)"))
        self.assertIsNone(m["scanner_reports"]["grype"])
        self.assertIsNone(m["known_defect_log"])
        self.assertIn("grype(syft) packages=12 os_packages=10 findings=0 scan_ok=False ran=False", out)
        # only trivy ran among grype/trivy/snyk -> osv's reason is NOT rewritten
        self.assertEqual(m["scanner_status"]["osv-scanner"]["reason"],
                         "0 packages inventoried (scanner produced no package inventory)")

    def test_syft_empty_inventory_marks_grype_not_run(self):
        rules = [r for r in GOOD_RULES if r["tool"] != "syft"]
        rules.append({"tool": "syft", "stdout_json": {"artifacts": []}})
        self.rules(rules)
        self.run_main(self.base_args())
        g = _rj(self.out)["scanner_status"]["grype"]
        self.assertEqual((g["ran"], g["scan_ok"], g["reason"]), (False, True, "0 packages inventoried"))


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
        self.assertEqual(M._archives(empty, "", self.oci, self.tar), (None, "no production.oci in the rescan artifacts"))
        self.rules([{"tool": "skopeo", "rc": 1}])
        with mock.patch.dict(os.environ, self.env), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M._archives(os.path.join(self.tmp, "rescan"), "", self.oci, self.tar),
                             (None, "skopeo convert failed"))
            self.rules([{"tool": "skopeo", "has_prefix": ["docker-archive:"]}, {"tool": "skopeo", "rc": 1}])
            self.assertEqual(M._archives(os.path.join(self.tmp, "rescan"), "", self.oci, self.tar),
                             ("production.oci", None))

    def test_scan_writes_stdout(self):
        os.makedirs(self.reports)
        self.rules([{"tool": "trivy", "stdout": "{\"a\":1}", "rc": 1}])
        with mock.patch.dict(os.environ, self.env), contextlib.redirect_stdout(io.StringIO()) as b:
            path, rc = M._scan("trivy", ["trivy", "q"], self.reports)
        self.assertEqual((path, rc), (os.path.join(self.reports, "trivy.json"), 1))
        self.assertEqual(_rd(path), "{\"a\":1}")
        self.assertEqual(b.getvalue(), "")

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

    def test_grype(self):
        self.assertEqual(M._inv_grype(w(GRYPE, self.tmp)), (2, 1, "2026-09-22", 3))
        self.assertEqual(M._inv_grype(w({}, self.tmp)), (0, 0, None, 0))

    def test_trivy(self):
        self.assertEqual(M._inv_trivy(w(TRIVY, self.tmp)), (12, 10, None, 1))
        self.assertEqual(M._inv_trivy(w({"Results": None}, self.tmp)), (0, 0, None, 0))

    def test_osv(self):
        d = {"results": [{"packages": [
            {"package": {"ecosystem": "Debian:12"}, "vulnerabilities": [{}, {}]},
            {"package": {"ecosystem": "Alpine:v3.19"}},
            {"package": {"ecosystem": "Go"}, "vulnerabilities": [{}]},
            {"package": None}]}, {"packages": None}]}
        self.assertEqual(M._inv_osv(w(d, self.tmp)), (4, 2, None, 3))

    def test_syft(self):
        self.assertEqual(M._inv_syft(w(SYFT, self.tmp)), (12, 10))
        self.assertEqual(M._inv_syft(w({"artifacts": [{"type": "npm", "purl": "pkg:rpm/x@1"}, {"type": "npm"}]}, self.tmp)), (2, 1))

    def test_snyk(self):
        self.assertEqual(M._inv_snyk(w({"dependencyCount": 7, "vulnerabilities": [{}]}, self.tmp)), (7, 7, None, 1))
        self.assertEqual(M._inv_snyk(w([{"dependencyCount": 3, "vulnerabilities": [{}]},
                                        {"dependencyCount": 9}, {"vulnerabilities": [{}, {}]}], self.tmp)), (9, 9, None, 3))

    def test_base_os(self):
        self.assertEqual(M._base_os(w(SYFT, self.tmp)), "debian 12.0")
        self.assertEqual(M._base_os(w({"distro": {"id": " Alpine "}}, self.tmp)), "alpine")
        self.assertIsNone(M._base_os(w({"distro": None}, self.tmp)))
        self.assertIsNone(M._base_os(w("{broken", self.tmp)))
        self.assertIsNone(M._base_os(os.path.join(self.tmp, "missing.json")))

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
