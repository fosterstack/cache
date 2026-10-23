"""Reviewed allow-list for test_fs_guard.Static: a system-path literal in a test script is allowed ONLY when it is pure data
(text parsed, compared or injected into an in-memory copy; never opened, stat-ed or resolved by the test or the code under test).
Row: (file, substring of the line - empty means the whole file, reason). A row that matches nothing fails the test.
Real file access on a system path is never allow-listed: build the same shape under a temp dir instead."""
ROWS = [
    ('bin/branch_sweep_test.py',
     'or "/").split("/")',
     "the default of a dict lookup whose result is split on '/' to compare an owner name; a string separator, not a path"),
    ('.github/agent/bin/tests/test_check_action_pins.py',
     '',
     "shell-script TEXT handed to the pin checker's string analysers (script_installs, _downloaded_commands, _outside, _made_executable); /home/runner/work and /usr/local/bin are the literal GitHub-runner and install-location strings those rules match on, and the functions never open, stat or resolve them (the checker reads only entries of the tree it is given; the guard proves the suite touches no system path at run time)"),
    ('.github/agent/bin/tests/test_panel.py',
     '',
     'container-image-internal paths inside evidence text (package-database and go-build-info lines) that the panel voter parses; no filesystem access'),
    ('.github/agent/bin/tests/test_panel_io.py',
     '',
     'container-image-internal paths: tar member names written into an in-memory layer archive and read back from a temp .oci file; assertions compare the parsed in-image paths, never the host filesystem (go_buildinfo takes the in-image name as a dict key and copies to its own temp file)'),
]

# Link creations with an absolute target that are pure data: command text inside a fixture workflow/script that the pin checker
# judges as text and nothing executes. (file, substring of the line, reason)
LINK_ROWS = [
    ('.github/agent/tests/check-action-pins-test.sh',
     'ln -s /tmp/a /tmp/b',
     'text of a workflow run: step (case n2-copy-other-file) that the pin checker judges as text; nothing executes it'),
]

# A WHOLE-FILE row (empty span) exempts every system-path literal in a PYTHON test, and the scan cannot tell a quoted fixture line from a command,
# so the WHOLE FILE is pinned: (sha256 of the file's raw bytes, the literal-bearing lines it may contain, reason). Any edit to one of these files
# needs a reviewed update here (`python3 test_fs_guard.py --print-pins`); a new literal line must be added with a reason.
PINS = {
    '.github/agent/bin/tests/test_check_action_pins.py': ('bf185018d8a626730f16282546fccdb1abadc375f54f855c866b06d2d11f2a93',
        [        'self.assertEqual(M.script_installs("python3 -m venv /tmp/v && python3 -m json.tool f"), [])',
                 'self.assertEqual(M._downloaded_commands("curl --output=/tmp/x https://e/x\\ncp /tmp/x /usr/local/bin/tool"), {"tool", '
                 '"x"})',
                 'self.assertEqual(M._downloaded_commands("curl -o /tmp/x https://e/x\\ninstall --target-directory=/usr/local/bin '
                 '/tmp/x"), {"x"})',
                 'self.assertFalse(M._outside("/home/runner/work/x", ""))',
                 'self.assertTrue(M._outside("$HOME/.docker/x", ""))',
                 'self.assertFalse(M._outside("$d", "d=/tmp/y; d=/home/runner/work/z"))',
                 'self.assertEqual(M._made_executable("curl -o /usr/local/bin/t https://e/t", "/usr/local/bin/t"), "downloads")',
                 'self.assertEqual(M._downloaded_commands("curl --output /usr/local/bin/x https://e/x"), {"x"})'],
        "shell-script TEXT handed to the pin checker's string analysers (script_installs, _downloaded_commands, _outside, _made_executable); /home/runner/work and /usr/local/bin are the literal GitHub-runner and install-location strings those rules match on, and the functions never open, stat or resolve them (the checker reads only entries of the tree it is given; the guard proves the suite touches no system path at run time)"),
    '.github/agent/bin/tests/test_panel.py': ('16902bc4026ff3b916fb96be8b08ce3aebc1fbbf4070ff449b65d820a81f89f2',
        [        '"package database /var/lib/dpkg/status.d/tzdata:\\nPackage: tzdata\\nVersion: 2026c-0+deb13u1\\n"',
                 '"file: /usr/share/zoneinfo/tzdata.zi (version 2026a)\\n"',
                 'b = ("h\\n%s\\npackage database /var/lib/dpkg/status.d/tzdata:\\nPackage: tzdata\\nVersion: 2026c-0+deb13u1\\n"',
                 '"Breaks: tzdata-legacy (= 2023c-8)\\nfile: /var/lib/dpkg/status.d/tzdata.md5sums\\n" % P.EVIDENCE_MARK)',
                 'self.assertIsNone(P.vote(false(ev="file: /var/lib/dpkg/status.d/tzdata.md5sums"), b, finding()))',
                 'gb = "h\\n%s\\ngo build info /usr/bin/cache: dep golang.org/x/sys v0.47.0 h1:abc\\n" % P.EVIDENCE_MARK',
                 'named = b(["package databases read: dpkg", "package database: no record names libssl3", "file: /usr/lib/libssl3.so"])'],
        'container-image-internal paths inside evidence text (package-database and go-build-info lines) that the panel voter parses; no filesystem access'),
    '.github/agent/bin/tests/test_panel_io.py': ('95d8886a2028c80295d92029f1c7d246ac8355464080d779dd497f3ed48dda81',
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
