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


class RefuseConstant(unittest.TestCase):
    def test_nan_and_the_infinities_are_refused_with_a_parse_error_naming_the_document(self):
        for c in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(P.ParseError) as cm:
                P.refuse_constant("state", c)
            self.assertEqual(str(cm.exception), "state: %s is not valid JSON" % c)

    def test_the_document_name_comes_from_the_caller(self):
        for document in ("panel verdict", "profiles"):
            with self.assertRaises(P.ParseError) as cm:
                P.refuse_constant(document, "NaN")
            self.assertEqual(str(cm.exception), "%s: NaN is not valid JSON" % document)

    def test_it_works_as_the_json_hook(self):
        hook = lambda name: P.refuse_constant("doc", name)
        with self.assertRaises(P.ParseError):
            json.loads('{"a": NaN}', parse_constant=hook)
        self.assertEqual(json.loads('{"a": 1.5}', parse_constant=hook), {"a": 1.5})

    def test_the_old_private_name_is_gone(self):
        self.assertFalse(hasattr(P, "_refuse_constant"))


class PublicNames(unittest.TestCase):
    def test_the_helpers_other_modules_call_are_public(self):
        for name in ("finding", "panel_module", "no_dup_pairs"):
            self.assertTrue(callable(getattr(P, name, None)), name)
            self.assertFalse(hasattr(P, "_" + name), "_" + name)

    def test_the_panel_module_has_the_issue_renderer_and_the_purl_splitter(self):
        pm = P.panel_module()
        self.assertTrue(callable(pm.render_issue))
        self.assertTrue(callable(pm.purl_name_version))
        self.assertFalse(hasattr(pm, "_purl_name_version"))

    def test_no_dup_pairs_keeps_distinct_keys_in_a_dict(self):
        doc = json.loads('{"a": 1, "b": {"c": 2}}', object_pairs_hook=P.no_dup_pairs)
        self.assertEqual(doc, {"a": 1, "b": {"c": 2}})

    def test_no_dup_pairs_refuses_a_repeated_key_at_any_depth(self):
        for text in ('{"a": 1, "a": 2}', '{"x": {"a": 1, "a": 2}}', '[{"a": 1, "a": 1}]'):
            self.assertRaises(ValueError, json.loads, text, object_pairs_hook=P.no_dup_pairs)


class Kev(unittest.TestCase):
    def test_real(self):
        self.assertIn("CVE-2023-4911", P.parse_kev(F + "/kev/kev.json"))
    def test_malformed(self):
        self.assertRaises(P.ParseError, P.parse_kev, w({"vulnerabilities": [{"product": "x"}]}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
