import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auditorlib import parsers as P

F = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures")


def w(obj):
    fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
    open(p, "w").write(obj if isinstance(obj, str) else json.dumps(obj))
    return p


class Govulncheck(unittest.TestCase):
    def test_real(self):
        g = P.parse_govulncheck(F + "/govulncheck/gv-01.json")
        self.assertEqual(g["scan_level"], "symbol")
        self.assertEqual(g["module"], "example.com/reach")
        self.assertTrue(g["by_osv"]["GO-2021-0113"]["reachable"])
        self.assertFalse(g["by_osv"]["GO-2020-0015"]["reachable"])
        self.assertTrue(g["by_osv"]["GO-2020-0015"]["imported_only"])   # module-level, non-empty
        self.assertNotIn("CVE-2099-0", g["by_osv"])  # absent -> absent, not reachable=False
    def test_fix_and_installed_version_come_from_the_stream(self):        # the bump PR's from/to, with no module scanner (0600 option A)
        by = P.parse_govulncheck(F + "/govulncheck/gv-01.json")["by_osv"]
        mod = by["GO-2021-0113"]["mods"]["golang.org/x/text"]
        self.assertEqual((mod["fixed"], mod["installed"], mod["reachable"]), ("v0.3.7", "v0.3.0", True))
        self.assertEqual(by["GO-2020-0015"]["mods"]["golang.org/x/text"]["fixed"], "v0.3.3")
        self.assertFalse(by["GO-2020-0015"]["mods"]["golang.org/x/text"]["reachable"])
        self.assertIn("CVE-2021-38561", by["GO-2021-0113"]["aliases"])      # from the stream's own osv entry
    def test_a_finding_without_a_fixed_version_has_none(self):
        g = P.parse_govulncheck(w('{"finding": {"osv": "GO-1", "trace": [{"module": "m", "version": "v1.0.0"}]}}'))
        self.assertEqual(g["by_osv"]["GO-1"]["mods"], {"m": {"installed": "v1.0.0", "fixed": None, "reachable": False}})
    def test_versions_stay_with_their_own_module(self):                   # one advisory, two modules: a version of one never pairs with the other's fix
        g = P.parse_govulncheck(w('{"finding": {"osv": "GO-1", "trace": [{"module": "m/v1", "version": "v1.0.0"}]}}\n'
                                  '{"finding": {"osv": "GO-1", "fixed_version": "v2.2.0", "trace": [{"module": "m/v2", "version": "v2.0.0", "function": "F"}, {"module": "app"}]}}'))
        self.assertEqual(g["by_osv"]["GO-1"]["mods"],
                         {"m/v1": {"installed": "v1.0.0", "fixed": None, "reachable": False},
                          "m/v2": {"installed": "v2.0.0", "fixed": "v2.2.0", "reachable": True}})
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_govulncheck, w(""))
        self.assertRaises(P.ParseError, P.parse_govulncheck, w("not a stream\n"))        # junk is a ParseError, not a JSONDecodeError escaping the callers
        self.assertRaises(P.ParseError, P.parse_govulncheck, w('{"finding": {"trace": []}}'))


class Kev(unittest.TestCase):
    def test_real(self):
        self.assertIn("CVE-2023-4911", P.parse_kev(F + "/kev/kev.json"))
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_kev, w({"vulnerabilities": [{"product": "x"}]}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
