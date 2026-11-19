"""Reviewed allow-list for test_fs_guard.Static: a system-path literal in a test script is allowed ONLY when it is pure data
(text parsed, compared or injected into an in-memory copy; never opened, stat-ed or resolved by the test or the code under test).
Row: (file, substring of the line - empty means the whole file, reason). A row that matches nothing fails the test.
Real file access on a system path is never allow-listed: build the same shape under a temp dir instead."""
ROWS = [
    ('bin/branch_sweep_test.py',
     'or "/").split("/")',
     "the default of a dict lookup whose result is split on '/' to compare an owner name; a string separator, not a path"),
    ('.github/agent/bin/tests/test_panel.py',
     '',
     'container-image-internal paths inside evidence text (package-database and go-build-info lines) that the panel voter parses; no filesystem access'),
    ('.github/agent/bin/tests/test_panel_io.py',
     '',
     'container-image-internal paths: tar member names written into an in-memory layer archive and read back from a temp .oci file; assertions compare the parsed in-image paths, never the host filesystem (go_buildinfo takes the in-image name as a dict key and copies to its own temp file)'),
]

# Link creations with an absolute target that are pure data: command text inside a fixture that nothing executes.
# (file, substring of the line, reason)
LINK_ROWS = [
]

# A WHOLE-FILE row (empty span) exempts every system-path literal in a PYTHON test, and the scan cannot tell a quoted fixture line from a command,
# so each file lists the literal-bearing lines it may contain, with a reason. A new literal line in one of these files must be added here
# with a reason (`python3 test_fs_guard.py --print-pins`).
PINS = {
    '.github/agent/bin/tests/test_panel.py': (
        [        '"package database /var/lib/dpkg/status.d/tzdata:\\nPackage: tzdata\\nVersion: 2026c-0+deb13u1\\n"',
                 '"file: /usr/share/zoneinfo/tzdata.zi (version 2026a)\\n"',
                 'b = ("h\\n%s\\npackage database /var/lib/dpkg/status.d/tzdata:\\nPackage: tzdata\\nVersion: 2026c-0+deb13u1\\n"',
                 '"Breaks: tzdata-legacy (= 2023c-8)\\nfile: /var/lib/dpkg/status.d/tzdata.md5sums\\n" % P.EVIDENCE_MARK)',
                 'self.assertIsNone(P.vote(false(ev="file: /var/lib/dpkg/status.d/tzdata.md5sums"), b, finding()))',
                 'gb = "h\\n%s\\ngo build info /usr/bin/cache: dep golang.org/x/sys v0.47.0 h1:abc\\n" % P.EVIDENCE_MARK',
                 'named = b(["package database: no record names libssl3", "file: /usr/lib/libssl3.so"])'],
        'container-image-internal paths inside evidence text (package-database and go-build-info lines) that the panel voter parses; no filesystem access'),
    '.github/agent/bin/tests/test_panel_io.py': (
        [        'self.assertIn("/usr/share/zoneinfo/tzdata.zi", facts["paths"])',
                 'self.assertNotIn("/etc/old-tzdata.conf", facts["paths"])',
                 'self.assertEqual(sorted(facts["status"]), ["/var/lib/dpkg/status", "/var/lib/dpkg/status.d/tzdata"])',
                 'self.assertEqual(list(facts["gobins"]), ["/usr/bin/cache"])',
                 'self.assertNotIn("/opt/lib/old-tzdata", facts["paths"])',
                 'self.assertIn("/opt/lib/new", facts["paths"])                        # same-layer entry survives its opaque marker',
                 'self.assertIn("/opt/lib/new", facts["paths"])',
                 'self.assertEqual([p for p in paths if p.startswith("/srv")], ["/srv/oldest"])',
                 'info = P.go_buildinfo({"/usr/bin/cache": GO_BIN}, run=run)',
                 'self.assertIn("/usr/bin/cache: go1.26.6", info["/usr/bin/cache"])',
                 'info = {"/usr/bin/cache": "go1.26.6\\n\\tdep\\tgolang.org/x/sys\\tv0.47.0\\n"}',
                 'self.assertIn("file: /usr/share/zoneinfo/tzdata.zi", b)',
                 'self.assertIn("go build info /usr/bin/cache: dep\\tgolang.org/x/sys\\tv0.47.0", g)'],
        'container-image-internal paths: tar member names written into an in-memory layer archive and read back from a temp .oci file; assertions compare the parsed in-image paths, never the host filesystem (go_buildinfo takes the in-image name as a dict key and copies to its own temp file)'),
}
