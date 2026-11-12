"""The strict, closed reader of the scanner panel's verdict.json (auditorlib/parsers.py, cache#466; scanner-panel rules 1, 3, 6).

Every refusal in the validator and the loader has its own case here, so a refusal that never fires is a failing test and a refusal that
fires for the wrong reason is too (each case names the message it must produce). The matrix suite (auditor-matrix-test.sh panel-4) proves
the same refusals end to end through every reader; this module proves each ONE branch in-process.
"""
import copy, importlib.util, json, os, sys, tempfile, unittest
from unittest import mock

BIN = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BIN)
from auditorlib import parsers as P  # noqa: E402


def good():
    """A valid full-matrix verdict: every scanner ran everywhere, two reported findings and one unique."""
    pm = P._panel_module()
    images = {}
    for im in sorted(P.panel_images()):
        ran = sorted(s for s in P.PANEL_SCANNERS if P.panel_expected(s, im))
        images[im] = {"counts": {s: 10 for s in ran}, "did_not_run": [], "ran": ran, "counts_for_day": len(ran) >= 3}

    def f(im, vid, pkg, ver, seen, details=None):
        return {"image": im, "id": vid, "package": pkg, "version": ver, "seen_by": sorted(seen), "of": len(images[im]["ran"]),
                "unique": len(seen) == 1, "status": "unique" if len(seen) == 1 else "report",
                "purls": ["pkg:deb/debian/%s@%s" % (pkg, ver)],
                "details": details if details is not None else {s: {} for s in seen}}
    fs = [f("production-amd64", "CVE-2099-0001", "openssl", "3.0.1", ["grype", "inspector"],
            {"grype": {"severity": "high", "fixed_version": "3.0.2", "aliases": ["GHSA-aaaa-bbbb-cccc"], "known_exploited": True,
                       "purl": "pkg:deb/debian/openssl@3.0.1?arch=amd64&distro=debian-12"},
             "inspector": {"severity": "critical", "purl": "pkg:deb/debian/openssl@3.0.1"}}),
          f("production-amd64", "CVE-2099-0002", "zlib", "1.3", ["inspector"])]
    d = {"images": images, "not_counted": [], "scanner_failures": [], "findings": fs,
         "unique": [x for x in fs if x["unique"]],
         "vex_covered": [{"image": "production-amd64", "scanner": "inspector", "id": "CVE-2099-0009", "package": "busybox", "version": "1.36"}],
         "issue": pm.render_issue([x for x in fs if x["status"] == "report"]), "exit": 1}
    return d


def refuse(case, mutate, pattern):
    d = good(); mutate(d)
    with case.assertRaisesRegex(P.ParseError, pattern):
        P.validate_panel_verdict(d)


class Validator(unittest.TestCase):
    def test_a_good_verdict_is_accepted(self):
        d = good()
        self.assertIs(P.validate_panel_verdict(d), d)

    def test_every_refusal_fires_for_its_own_reason(self):
        def img(d): return d["images"]["production-amd64"]
        cases = [
            ("not an object", lambda d: d.clear() or d.update(x=1), "missing or unknown keys|no images object"),
            ("unknown top key", lambda d: d.update(note="x"), "the verdict has missing or unknown keys"),
            ("findings is not a list", lambda d: d.update(findings={}), "no images object or findings array"),
            ("a missing image", lambda d: d["images"].pop("fips-arm64"), "image set is not the panel's fixed set"),
            ("an image that is not an object", lambda d: d["images"].update({"fips-arm64": 5}), "is not an object"),
            ("an image with unknown keys", lambda d: img(d).update(extra=1), "image production-amd64 has missing or unknown keys"),
            ("ran is not a list", lambda d: img(d).update(ran="x"), "has no ran/did_not_run/counts"),
            ("a scanner that is not a name", lambda d: img(d)["ran"].append(1), "is not a name"),
            ("a scanner twice", lambda d: img(d)["ran"].append("grype"), "twice or as both ran and did not run"),
            ("ran and did_not_run overlap", lambda d: img(d)["did_not_run"].append("grype"), "twice or as both ran and did not run"),
            ("a scanner in neither list", lambda d: img(d)["ran"].remove("scout") or img(d)["counts"].pop("scout"), "does not list exactly its expected scanners"),
            ("a ran scanner without a count", lambda d: img(d)["counts"].pop("grype"), "without a positive integer package count"),
            ("a boolean count", lambda d: img(d)["counts"].update(grype=True), "without a positive integer package count"),
            ("a zero count", lambda d: img(d)["counts"].update(grype=0), "without a positive integer package count"),
            ("counts_for_day against the quorum", lambda d: img(d).update(counts_for_day=False), "counts_for_day disagrees"),
            ("not_counted against the images", lambda d: d.update(not_counted=["fips-arm64"]), "not_counted disagrees"),
            ("scanner_failures against the images", lambda d: d.update(scanner_failures=["x on y"]), "scanner_failures disagrees"),
            ("a finding with unknown keys", lambda d: d["findings"][0].update(extra=1), "a finding has missing or unknown keys"),
            ("a finding without details", lambda d: d["findings"][0].pop("details"), "a finding has missing or unknown keys"),
            ("details for a scanner that did not report it", lambda d: d["findings"][0]["details"].update(google={}), "details for different scanners than seen_by"),
            ("details missing a reporting scanner", lambda d: d["findings"][0]["details"].pop("inspector"), "details for different scanners than seen_by"),
            ("details that are not an object", lambda d: d["findings"][0].update(details=[]), "details for different scanners than seen_by"),
            ("an unknown key in a scanner's details", lambda d: d["findings"][0]["details"]["grype"].update(cvss=9.8), "unknown key in grype's details"),
            ("a scanner's details that are not an object", lambda d: d["findings"][0]["details"].update(grype=[]), "unknown key in grype's details"),
            ("a non-text package URL in a scanner's details", lambda d: d["findings"][0]["details"]["grype"].update(purl=3), "malformed value in grype's details"),
            ("an empty package URL in a scanner's details", lambda d: d["findings"][0]["details"]["grype"].update(purl=""), "malformed value in grype's details"),
            ("a scanner's package URL that is not pkg:", lambda d: d["findings"][0]["details"]["inspector"].update(purl="openssl@3.0.1"), "malformed value in inspector's details"),
            ("a package URL with an empty version", lambda d: d["findings"][0]["details"]["inspector"].update(purl="pkg:deb/debian/openssl@"), "malformed value in inspector's details"),
            ("a package URL with an empty qualifier value", lambda d: d["findings"][0]["details"]["inspector"].update(purl="pkg:deb/debian/openssl@3.0.1?arch="), "malformed value in inspector's details"),
            ("a package URL with a repeated qualifier key", lambda d: d["findings"][0]["details"]["inspector"].update(purl="pkg:deb/debian/openssl@3.0.1?arch=amd64&arch=arm64"), "malformed value in inspector's details"),
            ("a package URL with an empty subpath", lambda d: d["findings"][0]["details"]["inspector"].update(purl="pkg:deb/debian/openssl@3.0.1#"), "malformed value in inspector's details"),
            ("a finding package URL with a repeated qualifier key", lambda d: d["findings"][0].update(purls=["pkg:deb/debian/openssl@3.0.1?arch=amd64&arch=arm64"]), "is not pkg:TYPE"),
            ("a scanner's package URL for another package", lambda d: d["findings"][0]["details"]["inspector"].update(purl="pkg:deb/debian/other@3.0.1"), "inspector's package URL is for a different package or version"),
            ("a scanner's package URL for another version", lambda d: d["findings"][0]["details"]["grype"].update(purl="pkg:deb/debian/openssl@9.9"), "grype's package URL is for a different package or version"),
            ("a severity outside the normalised words", lambda d: d["findings"][0]["details"]["grype"].update(severity="HIGH"), "malformed value in grype's details"),
            ("a non-text severity", lambda d: d["findings"][0]["details"]["grype"].update(severity=3), "malformed value in grype's details"),
            ("an empty fixed version", lambda d: d["findings"][0]["details"]["grype"].update(fixed_version=""), "malformed value in grype's details"),
            ("a fixed version outside the charset", lambda d: d["findings"][0]["details"]["grype"].update(fixed_version="1\n2"), "malformed value in grype's details"),
            ("aliases that are not a list", lambda d: d["findings"][0]["details"]["grype"].update(aliases="GHSA-aaaa-bbbb-cccc"), "malformed value in grype's details"),
            ("duplicate aliases", lambda d: d["findings"][0]["details"]["grype"].update(aliases=["GHSA-aaaa-bbbb-cccc"] * 2), "malformed value in grype's details"),
            ("an alias outside the id charset", lambda d: d["findings"][0]["details"]["grype"].update(aliases=["bad alias"]), "malformed value in grype's details"),
            ("an empty aliases list", lambda d: d["findings"][0]["details"]["grype"].update(aliases=[]), "malformed value in grype's details"),
            ("a non-boolean known_exploited", lambda d: d["findings"][0]["details"]["grype"].update(known_exploited="yes"), "malformed value in grype's details"),
            ("a finding id outside the charset", lambda d: d["findings"][0].update(id="CVE 1"), "character outside the allowed set"),
            ("a finding with an empty package", lambda d: d["findings"][0].update(package=""), "incomplete finding or one on an unknown image"),
            ("a finding on an unknown image", lambda d: d["findings"][0].update(image="nowhere-amd64"), "incomplete finding or one on an unknown image"),
            ("a seen_by scanner that did not run there at all", lambda d: d["findings"][0].update(seen_by=["grype", "trivy"]),
             "inconsistent seen_by/of/unique/status"),
            ("a wrong of", lambda d: d["findings"][0].update(of=3), "inconsistent seen_by/of/unique/status"),
            ("a wrong unique", lambda d: d["findings"][1].update(unique=False), "inconsistent seen_by/of/unique/status"),
            ("a wrong status", lambda d: d["findings"][1].update(status="report"), "inconsistent seen_by/of/unique/status"),
            ("a package URL that is not pkg:", lambda d: d["findings"][0].update(purls=["openssl@3.0.1"]), "is not pkg:TYPE"),
            ("a package URL for another package", lambda d: d["findings"][0].update(purls=["pkg:deb/debian/other@3.0.1"]), "different package or version"),
            ("two findings with one identity", lambda d: d["findings"].append(dict(d["findings"][1])), "share one identity"),
            ("the unique list against the findings", lambda d: d.update(unique=[]), "unique list, vex_covered or issue disagrees"),
            ("vex_covered not a list", lambda d: d.update(vex_covered={}), "unique list, vex_covered or issue disagrees"),
            ("issue not a string", lambda d: d.update(issue=None), "unique list, vex_covered or issue disagrees"),
            ("the issue text against the findings", lambda d: d.update(issue="stale"), "not the tally's rendering"),
            ("a vex_covered entry with unknown keys", lambda d: d["vex_covered"][0].update(extra=1), "a vex_covered entry has missing or unknown keys"),
            ("a vex_covered entry for a scanner the tally does not filter", lambda d: d["vex_covered"][0].update(scanner="grype"), "vex_covered entry is incomplete"),
            ("a vex_covered id outside the charset", lambda d: d["vex_covered"][0].update(id="CVE 9"), "vex_covered id, package or version holds a character"),
            ("an exit status against the findings", lambda d: d.update(exit=0), "exit status disagrees"),
            ("a boolean exit", lambda d: d.update(exit=True), "exit status disagrees"),
        ]
        for name, mutate, pattern in cases:
            with self.subTest(name):
                refuse(self, mutate, pattern)

    def test_each_scanner_keeps_its_own_package_url_and_borrows_none(self):
        # handoff 0601 item 2: a scanner's package identity is what THAT scanner reported; absent stays absent (a generic one is built
        # from the finding's package and version), never copied from another scanner
        path = tempfile.mkstemp(suffix=".json")[1]; self.addCleanup(os.unlink, path)
        with open(path, "w") as fh:
            json.dump(good(), fh)
        grype = {f["finding_id"]: f for f in P.parse_panel(path, "grype")}
        insp = {f["finding_id"]: f for f in P.parse_panel(path, "inspector")}
        self.assertEqual(grype["CVE-2099-0001"]["purl"], "pkg:deb/debian/openssl@3.0.1?arch=amd64&distro=debian-12")
        self.assertEqual(insp["CVE-2099-0001"]["purl"], "pkg:deb/debian/openssl@3.0.1")
        self.assertEqual(insp["CVE-2099-0002"]["purl"], "pkg:generic/zlib@1.3")        # reported no package URL: not the finding's, not another scanner's

    def test_one_scanner_with_two_package_urls_on_two_images_is_two_records(self):
        d = good()
        second = copy.deepcopy(d["findings"][0]); second["image"] = "production-arm64"
        second["of"] = len(d["images"]["production-arm64"]["ran"])
        second["details"]["grype"]["purl"] = "pkg:deb/debian/openssl@3.0.1?arch=arm64&distro=debian-12"
        d["findings"].append(second)
        d["issue"] = P._panel_module().render_issue([x for x in d["findings"] if x["status"] == "report"])
        path = tempfile.mkstemp(suffix=".json")[1]; self.addCleanup(os.unlink, path)
        with open(path, "w") as fh:
            json.dump(d, fh)
        recs = sorted(r["purl"] for r in P.parse_panel(path, "grype"))
        self.assertEqual(recs, ["pkg:deb/debian/openssl@3.0.1?arch=amd64&distro=debian-12", "pkg:deb/debian/openssl@3.0.1?arch=arm64&distro=debian-12"])

    def test_the_document_must_be_an_object(self):
        with self.assertRaisesRegex(P.ParseError, "no images object or findings array"):
            P.validate_panel_verdict([])

    def test_any_type_error_in_a_malformed_document_is_a_parse_error_not_a_traceback(self):
        for exc in (TypeError("t"), AttributeError("a"), KeyError("k"), ValueError("v")):
            with mock.patch.object(P, "_validate_panel_verdict", side_effect=exc):
                with self.assertRaisesRegex(P.ParseError, "malformed"):
                    P.validate_panel_verdict({})

    def test_a_parse_error_from_the_inner_check_passes_through_unchanged(self):
        with mock.patch.object(P, "_validate_panel_verdict", side_effect=P.ParseError("panel verdict: x")):
            with self.assertRaisesRegex(P.ParseError, "^panel verdict: x$"):
                P.validate_panel_verdict({})


class Loader(unittest.TestCase):
    def write(self, text):
        fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def test_a_valid_file_loads_and_parse_panel_returns_a_scanners_findings(self):
        path = self.write(json.dumps(good()))
        self.assertEqual(P.load_panel_verdict(path)["exit"], 1)
        insp = P.parse_panel(path, "inspector")
        self.assertEqual([f["finding_id"] for f in insp if not f["extra"].get("carried")], ["CVE-2099-0001", "CVE-2099-0002"])
        # the tally's vex_covered entry for Inspector rides along flagged carried (rc-5b fix 5), with a generic package URL and the image it was hidden on
        carried = [f for f in insp if f["extra"].get("carried")]
        self.assertEqual([(f["finding_id"], f["package"], f["purl"], f["extra"]["images"]) for f in carried],
                         [("CVE-2099-0009", "busybox", "pkg:generic/busybox@1.36", ["production-amd64"])])
        self.assertEqual([f["finding_id"] for f in P.parse_panel(path, "google")], [])
        self.assertFalse([f for f in P.parse_panel(path, "grype") if f["extra"].get("carried")])      # a scanner the VEX is not filtered for carries nothing

    def test_parse_panel_carries_a_scanners_own_severity_fix_aliases_and_exploitation(self):
        d = good()
        # the same finding on a second image: the scanner's record keeps the HIGHEST severity, the first fixed version, the union of aliases
        second = copy.deepcopy(d["findings"][0]); second["image"] = "production-arm64"
        second["of"] = len(d["images"]["production-arm64"]["ran"]); second["seen_by"] = ["grype", "inspector"]
        second["details"] = {"grype": {"severity": "critical", "fixed_version": "9.9", "aliases": ["GHSA-dddd-eeee-ffff"],
                                       "purl": d["findings"][0]["details"]["grype"]["purl"]}, "inspector": {}}       # the same package URL on both images: one record
        d["findings"].append(second)
        d["issue"] = P._panel_module().render_issue([x for x in d["findings"] if x["status"] == "report"])
        path = self.write(json.dumps(d))
        g = P.parse_panel(path, "grype")[0]
        self.assertEqual((g["severity"], g["fixed_version"], g["extra"].get("known_exploited")), ("critical", "3.0.2", True))
        self.assertEqual(g["aliases"], ["CVE-2099-0001", "GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"])
        self.assertEqual(sorted(g["extra"]["by_image"]), ["production-amd64", "production-arm64"])
        i = P.parse_panel(path, "inspector")[0]
        self.assertEqual((i["severity"], i["fixed_version"], i["aliases"]), ("critical", None, ["CVE-2099-0001"]))
        low = copy.deepcopy(d); low["findings"][0]["details"]["grype"]["severity"] = "low"; low["findings"][2]["details"]["grype"]["severity"] = "negligible"
        self.assertEqual(P.parse_panel(self.write(json.dumps(low)), "grype")[0]["severity"], "low")      # a lower one later never lowers it

    def test_a_repeated_key_at_any_depth_is_refused(self):
        with self.assertRaisesRegex(P.ParseError, "appears twice"):
            P.load_panel_verdict(self.write('{"findings": [1], "findings": []}'))
        with self.assertRaisesRegex(P.ParseError, "appears twice"):
            P.load_panel_verdict(self.write('{"a": {"b": 1, "b": 2}}'))

    def test_nan_and_infinity_are_not_json_here(self):
        for text in ('{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}'):
            with self.assertRaisesRegex(P.ParseError, "is not valid JSON"):
                P.load_panel_verdict(self.write(text))

    def test_a_document_nested_too_deeply_is_refused(self):
        # the interpreter's own recursion limit differs by version, so the limit is raised by the json module itself here
        with mock.patch("json.load", side_effect=RecursionError("maximum recursion depth exceeded")):
            with self.assertRaisesRegex(P.ParseError, "nested too deeply"):
                P.load_panel_verdict(self.write("[]"))

    def test_a_missing_file_is_an_os_error_from_the_loader_and_a_parse_error_from_parse_panel(self):
        gone = os.path.join(tempfile.gettempdir(), "no-such-verdict-%d.json" % os.getpid())
        with self.assertRaises(OSError):
            P.load_panel_verdict(gone)
        with self.assertRaisesRegex(P.ParseError, "cannot load"):
            P.parse_panel(gone, "grype")

    def test_a_verdict_that_is_not_json_is_a_parse_error_from_parse_panel(self):
        with self.assertRaises(P.ParseError):
            P.parse_panel(self.write("{not json"), "grype")


class Matrix(unittest.TestCase):
    def test_an_unloadable_panel_matrix_is_a_parse_error_and_is_not_cached(self):
        saved = list(P._PANEL); P._PANEL.clear()
        try:
            with mock.patch("importlib.util.spec_from_file_location", side_effect=OSError("no panel.py")):
                with self.assertRaisesRegex(P.ParseError, "cannot load the panel's scanner/image matrix"):
                    P.panel_images()
            self.assertEqual(P._PANEL, [])
        finally:
            P._PANEL[:] = saved


if __name__ == "__main__":
    unittest.main()
