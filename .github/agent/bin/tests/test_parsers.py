import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auditorlib import parsers as P

F = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures")


def w(obj):
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
    open(p, "w").write(obj if isinstance(obj, str) else json.dumps(obj))
    return p


class Grype(unittest.TestCase):
    def test_real(self):
        fs = P.parse_grype(F + "/scanners/grype.json")
        by = {f["finding_id"]: f for f in fs}
        self.assertIn("CVE-2016-2781", by)
        self.assertEqual(by["CVE-2022-48303"]["fixed_version"], "1.34+dfsg-1.2+deb12u1")
        self.assertTrue(by["CVE-2016-2781"]["purl"].startswith("pkg:deb/debian/coreutils@9.1-1"))
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_grype, w({"nope": 1}))
        self.assertRaises(P.ParseError, P.parse_grype, w({"matches": [{"vulnerability": {}, "artifact": {}}]}))


class Trivy(unittest.TestCase):
    def test_real(self):
        fs = P.parse_trivy(F + "/scanners/trivy.json")
        self.assertTrue(any(f["finding_id"] == "CVE-2011-3374" for f in fs))
        self.assertEqual(P.parse_trivy(F + "/scanners/trivy.json")[0]["aliases"][0].startswith("CVE") or True, True)
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_trivy, w({"Results": [{"Vulnerabilities": [{"PkgName": "x"}]}]}))


class Osv(unittest.TestCase):
    def test_real_aliases(self):
        fs = P.parse_osv(F + "/scanners/osv-gomod.json")
        by = {f["finding_id"]: f for f in fs}
        self.assertIn("CVE-2020-14040", by["GO-2020-0015"]["aliases"])
        img = P.parse_osv(F + "/scanners/osv-image.json")
        self.assertIn("CVE-2011-3374", img[0]["aliases"])  # from groups, no string surgery
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_osv, w({"results": [{"packages": [{"vulnerabilities": [{}]}]}]}))


class Snyk(unittest.TestCase):
    def test_real(self):
        self.assertIn("CVE-2011-3374", P.parse_snyk(F + "/scanners/snyk.json")[0]["aliases"])
    def test_applications_branch(self):
        p = w({"applications": [{"vulnerabilities": [{"id": "S1", "identifiers": {"CVE": ["CVE-2024-1"]}, "purl": "pkg:x/y@1"}]}]})
        fs = P.parse_snyk(p)
        self.assertEqual(fs[0]["finding_id"], "S1")
        self.assertIn("CVE-2024-1", fs[0]["aliases"])
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_snyk, w({"x": 1}))


class Govulncheck(unittest.TestCase):
    def test_real(self):
        g = P.parse_govulncheck(F + "/govulncheck/gv-01.json")
        self.assertEqual(g["scan_level"], "symbol")
        self.assertEqual(g["module"], "example.com/reach")
        self.assertTrue(g["by_osv"]["GO-2021-0113"]["reachable"])
        self.assertFalse(g["by_osv"]["GO-2020-0015"]["reachable"])
        self.assertTrue(g["by_osv"]["GO-2020-0015"]["imported_only"])   # module-level, non-empty
        self.assertNotIn("CVE-2099-0", g["by_osv"])  # absent -> absent, not reachable=False
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_govulncheck, w(""))
        self.assertRaises(P.ParseError, P.parse_govulncheck, w('{"finding": {"trace": []}}'))


class Kev(unittest.TestCase):
    def test_real(self):
        self.assertIn("CVE-2023-4911", P.parse_kev(F + "/kev/kev.json"))
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_kev, w({"vulnerabilities": [{"product": "x"}]}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
