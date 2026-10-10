"""Reviewed allow-list for test_fs_guard.Static: a system-path literal in a test script is allowed ONLY when it is pure data
(text parsed, compared or injected into an in-memory copy; never opened, stat-ed or resolved by the test or the code under test).
Row: (file, substring of the line - empty means the whole file, reason). A row that matches nothing fails the test.
Real file access on a system path is never allow-listed: build the same shape under a temp dir instead."""
ROWS = [
    (".github/agent/tests/auditor-matrix-test.sh", '=="/.github/agent"',
     "the dependabot.yml `directory` value being compared (a repo-relative setting, not a filesystem path)"),
    (".github/agent/tests/pin-age-check-test.sh", "sudo apt-get install -y skopeo",
     "workflow run: text the pin-age inventory parses; nothing executes it (sudo appears in the fixture on purpose)"),
    (".github/agent/tests/pin-age-check-test.sh", "curl -fsSL \\\\\\n",
     "workflow run: text (a line-continued curl with sudo) the pin-age inventory parses; nothing executes it"),
    (".github/agent/tests/pin-age-check-test.sh", "url=/URL=/*_BASE_URL",
     "prose in a case description naming the shell variable forms the inventory recognises; not a path"),
    ('.github/agent/bin/tests/test_check_action_pins.py',
     '',
     "shell-script TEXT handed to the pin checker's string analysers (script_installs, _downloaded_commands, _outside, _made_executable); /home/runner/work and /usr/local/bin are the literal GitHub-runner and install-location strings those rules match on, and the functions never open, stat or resolve them (the checker reads only entries of the tree it is given; the guard proves the suite touches no system path at run time)"),
    ('.github/agent/bin/tests/test_panel.py',
     '',
     'container-image-internal paths inside evidence text (package-database and go-build-info lines) that the panel voter parses; no filesystem access'),
    ('.github/agent/bin/tests/test_panel_io.py',
     '',
     'container-image-internal paths: tar member names written into an in-memory layer archive and read back from a temp .oci file; assertions compare the parsed in-image paths, never the host filesystem (go_buildinfo takes the in-image name as a dict key and copies to its own temp file)'),
    ('.github/agent/tests/check-action-pins-test.sh',
     '',
     "text of workflow run: steps, Dockerfiles and script bodies written into per-case temp trees and judged by the pin checker, which reads only the tree's own entries (FsTree/GitTree); the one fixture that creates a link (r24) now points at a file under $work"),
    ('.github/agent/tests/k8s-harness-fence-test.sh',
     '',
     "workflow-step text and the names of the two generated scripts the checker's fence excludes; the generator's own python is run with /tmp/ rewritten to a temp dir (line 40) so nothing is written to the system"),
    ('.github/agent/tests/pin-wiring-test.sh',
     '',
     'values injected into an in-memory copy of a workflow (env PATH, BASH_ENV ...) to prove the wiring check rejects them; never used as paths by the test'),
    ('.github/agent/tests/pip-pin-test.sh',
     '',
     "venv-relative suffixes (/bin, /bin/activate) inside the checker's own string rules under test"),
    ('.github/agent/tests/release-notes-signed-test.sh',
     '/tmp/auditor-signed-commit.py',
     'run-step text mutated to prove an absolute-path invocation is rejected by the wiring check'),
    ('.github/agent/tests/supply-chain-wiring-test.sh',
     '',
     'run-step text injected into an in-memory workflow copy to prove the wiring check rejects it'),
    ('.github/agent/tests/auditor-labels-test.sh',
     '/tmp/panel-out',
     "the sed pattern that points the workflow step's hard-coded panel directory at the temp dir; nothing is read or written there"),
    ('.github/agent/tests/auditor-matrix-test.sh',
     "'/usr/bin/x'",
     "an SBOM component NAME (a file path inside a scanned image) fed to the panel's counter; no filesystem access"),
    ('bin/acceptance-maven-413-test.sh',
     '/tmp/mvn-capped-a',
     "regex over the text of a workflow step (the runner's log path); not opened"),
    ('bin/admission-tag-signer-test.sh',
     '',
     'the runner paths the admission workflow uses (/tmp/policy/...), as text in assertions and in string replacements on an in-memory workflow copy'),
    ('bin/panel-test.sh',
     '',
     'SBOM file-component names (paths inside a scanned image) used as data in a JSON document'),
    ('bin/panel-wiring-test.sh',
     '',
     'workflow step text compared and mutated in memory'),
    ('bin/patch-decide-test.sh',
     '/usr/local/bin/fscache',
     'a line of a unified diff of a Dockerfile (COPY destination inside the image) classified as text'),
    ('bin/release-patch-wiring-test.sh',
     '',
     'run-step text and path-suffix rules for the release wiring check (absolute-path git, PATH injection) evaluated on in-memory workflow copies'),
    ('bin/rescan-statement-test.sh',
     '/srv/app/package.json',
     "a scanner report's target field (a path inside the scanned image) carried through jq as data"),
    ('bin/vex-forms-test.sh',
     '/tmp/vex/fosterstack-cache.openvex.json',
     "text of the release workflow's upload step searched for the file name; not opened"),
    ('bin/workflow-consolidation-test.sh',
     '/tmp/evil',
     'value injected into an in-memory workflow copy to prove the check rejects a PATH override'),
]

# Link creations with an absolute target that are pure data: command text inside a fixture workflow/script that the pin checker
# judges as text and nothing executes. (file, substring of the line, reason)
LINK_ROWS = [
    ('.github/agent/tests/check-action-pins-test.sh', "ln -s /tmp/a /tmp/b",
     "text of a workflow run: step (case n2-copy-other-file) that the pin checker judges as text; nothing executes it"),
]

# A WHOLE-FILE row exempts every system-path literal in its file, and the scan cannot tell a quoted fixture line from a command, so
# the WHOLE FILE is pinned: (sha256 of the file's raw bytes, the literal-bearing lines it may contain, reason). Any edit to one of these files
# needs a reviewed update here (`python3 test_fs_guard.py --print-pins`); a new literal line must be added with a reason.
PINS = {
    '.github/agent/bin/tests/test_check_action_pins.py': ('eb2d5bdb6b18a541d2c8e179e77dfa5d6e470165dd8316c36f0e512350a89ea8',
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
    '.github/agent/bin/tests/test_panel.py': ('3508d5169f33071846e9458845b16f467700c6e1b34cc1d958babcaaffd941ae',
        [        '"package database /var/lib/dpkg/status.d/tzdata:\\nPackage: tzdata\\nVersion: 2026c-0+deb13u1\\n"',
                 '"file: /usr/share/zoneinfo/tzdata.zi (version 2026a)\\n"',
                 'b = ("h\\n%s\\npackage database /var/lib/dpkg/status.d/tzdata:\\nPackage: tzdata\\nVersion: 2026c-0+deb13u1\\n"',
                 '"Breaks: tzdata-legacy (= 2023c-8)\\nfile: /var/lib/dpkg/status.d/tzdata.md5sums\\n" % P.EVIDENCE_MARK)',
                 'self.assertIsNone(P.vote(false(ev="file: /var/lib/dpkg/status.d/tzdata.md5sums"), b, finding()))',
                 'gb = "h\\n%s\\ngo build info /usr/bin/cache: dep golang.org/x/sys v0.47.0 h1:abc\\n" % P.EVIDENCE_MARK',
                 'named = b(["package database: no record names libssl3", "file: /usr/lib/libssl3.so"])'],
        'container-image-internal paths inside evidence text (package-database and go-build-info lines) that the panel voter parses; no filesystem access'),
    '.github/agent/bin/tests/test_panel_io.py': ('86d4009c47fc78f7760098b3cb87b5ef02a7283dbe41a9826bef2cb890593c00',
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
    '.github/agent/tests/check-action-pins-test.sh': ('c6547081c115a76396f48daa523c03f7a4c39e5f6e8c627eeafad76404f4161d',
        [        'options: --entrypoint /bin/sh alpine:latest',
                 "- '8080:80 --entrypoint /bin/sh alpine:latest'",
                 'entrypoint: \'/bin/echo\\" alpine:latest \\"x\'"',
                 'entrypoint: \'/bin/echo\\" alpine:latest \\"\'"',
                 '- uses: actions/checkout/../../../docker/setup-qemu-action/$SHA@$SHA # v7.0.1',
                 "'db --entrypoint /bin/sh alpine:latest --':",
                 'case_ run-flags-first          bad "$(r \'docker run -d --name x -p 127.0.0.1:1:2 -e A=b --entrypoint /bin/sh alpine '
                 '-c true\')"',
                 'case_ run-subshell             bad "$(r \'x=$(docker run alpine cat /etc/os-release)\')"',
                 'case_ run-skopeo-src           bad "$(r \'skopeo copy docker://alpine:3 oci-archive:/tmp/a.oci\')"',
                 'case_ run-local-skopeo         bad "$(r \'skopeo copy oci-archive:/tmp/a.oci docker-daemon:fa-debug:latest && docker '
                 'run fa-debug:latest\')"',
                 'case_ run-skopeo-push-dst      ok  "$(r \'skopeo copy oci-archive:/tmp/a.oci docker://ghcr.io/x/y:t\')"',
                 "python3 -m pip install --quiet --require-hashes --only-binary=:all: -r /dev/stdin <<'REQ'",
                 'case_ pkg-dry-run              ok  "$(rb \'python3 -m pip install --dry-run --ignore-installed --require-hashes '
                 '--target /tmp/x -r r.txt\')" "printf \'x==1 --hash=sha256:00\\\\n\' > r.txt"',
                 'case_ b1-abs-path              bad "$(r \'/usr/bin/docker run alpine:latest\')"',
                 'case_ n2-copied-binary         bad "$(rb \'cp "$(command -v docker)" /tmp/d && /tmp/d run alpine:latest\')"',
                 'case_ n2-linked-binary         bad "$(rb \'ln -s "$(which docker)" /tmp/d\')"',
                 'case_ n2-copied-pip            bad "$(rb \'cp /usr/bin/pip3 /tmp/p\')"',
                 'case_ n2-copy-other-file       ok  "$(rb \'cp Dockerfile.production /tmp/Dockerfile && ln -s /tmp/a /tmp/b\')"',
                 'case_ n3-download-hashed       ok  "$(rb \'pip download --require-hashes -r r.txt -d /tmp/w\')" "printf \'x==1 '
                 '--hash=sha256:00\\\\n\' > r.txt"',
                 'case_ n3-absolute-dockerfile   bad "$(rb \'docker build -f /tmp/Dockerfile .\')" "mkdir -p sub; printf \'FROM '
                 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\\\n\' > sub/Dockerfile"',
                 'case_ n4-subst-skopeo          bad "$(rb \'skopeo copy $(echo docker://alpine:latest) dir:/tmp/x\')"',
                 'case_ n6-r-absolute            bad "$(r \'pip install --require-hashes -r /tmp/nonexistent.txt\')"',
                 "pip install --require-hashes -r /dev/stdin <<'REQ'",
                 'case_ n6-r-stdin-no-heredoc    bad "$(rb \'curl -s https://x.example/r | pip install --require-hashes -r '
                 '/dev/stdin\')"',
                 'case_ n5-copy-into-context     ok  "$(rb \'cp build/docker/Dockerfile.* /tmp/ctx/ && cd /tmp/ctx && docker build -f '
                 'Dockerfile.$v .\')" "mkdir -p build/docker; printf \'FROM '
                 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\\\n\' > build/docker/Dockerfile.a"',
                 'case_ n5-copy-from-outside     bad "$(rb \'cp /tmp/evil/Dockerfile.a /tmp/ctx/ && cd /tmp/ctx && docker build -f '
                 'Dockerfile.$v .\')" "mkdir -p build/docker; printf \'FROM '
                 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\\\n\' > build/docker/Dockerfile.a"',
                 'case_ n15-skopeo-sync          bad "$(r \'skopeo sync --src docker --dest dir alpine /tmp/x\')"',
                 'case_ n18-config-other         bad "$(rb \'export DOCKER_CONFIG=/tmp/attacker; docker ps\')"',
                 'case_ n22-archive-to-daemon-run bad "$(rb \'skopeo copy oci-archive:/tmp/x.oci docker-daemon:img:1; docker run '
                 'img:1\')"',
                 'case_ n22-archive-scan-ok      ok  "$(rb \'skopeo copy oci-archive:/tmp/x.oci docker-daemon:img:1; grype docker:img:1; '
                 'docker scout cves local://img:1\')"',
                 'case_ n24-cd-template-ok       ok  "$(rb \'cp build/docker/Dockerfile.* /tmp/ctx/ && cd /tmp/ctx && docker build -f '
                 'Dockerfile.$v .\')" "mkdir -p build/docker; printf \'FROM '
                 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\\\n\' > build/docker/Dockerfile.a"',
                 '# --- Sonnet #164 r17 (NEW-25, NEW-26): a cd / pushd anywhere in the step, quoted or nested, moves the working '
                 'directory;',
                 'case_ n27-cp-split             bad "$(rb \'cp "$(command -v d""ocker)" /usr/local/bin/foo; foo run alpine:3.20\')"',
                 'case_ n29-cp-rename            bad "$(rb \'${x:-cp} "$(command -v docker)" /tmp/foo; /tmp/foo run alpine:3.20\')"',
                 'case_ n30-ansi-path            bad "$(rb "/usr/bin/\\$\'d\'ocker run alpine:latest")"',
                 'case_ n32-cat-pipe-bash        bad "$(rb \'printf x > /tmp/gen.sh; cat /tmp/gen.sh | bash\')"',
                 'case_ n32-bash-s               bad "$(rb \'bash -s < /tmp/gen.sh\')"',
                 'case_ n32-bash-dev-stdin       bad "$(rb \'bash /dev/stdin < /tmp/gen.sh\')"',
                 'case_ c01-glob-name            bad "$(rb \'/usr/bin/docke[r] run alpine:3.20\')"',
                 'case_ c01-glob-star            bad "$(rb \'/usr/bin/dock?r run alpine:3.20\')"',
                 'case_ c04-npm-prefix           bad "$(rb \'npm --prefix /tmp/pkg install lodash\')"',
                 'case_ c06-skopeo-optval        bad "$(rb \'skopeo copy --override-os linux docker://alpine:latest dir:/tmp/img\')"',
                 'case_ c06-crane-optval         bad "$(rb \'PLATFORM=linux/amd64; crane pull --platform "$PLATFORM" alpine:latest '
                 '/tmp/img.tar\')"',
                 'case_ c09-copy-from-image      bad "$(rb \'docker build -f Dockerfile.copy .\')" "printf \'FROM scratch\\\\nCOPY '
                 '--from=alpine:latest /etc/os-release /r\\\\n\' > Dockerfile.copy"',
                 'case_ c09-copy-from-stage-ok   ok  "$(rb \'docker build -f Dockerfile.ms .\')" "printf \'FROM '
                 'alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS base\\\\nFROM scratch\\\\nCOPY '
                 '--from=base /etc/os-release /r\\\\n\' > Dockerfile.ms"',
                 'case_ c12-hash-p               bad "$(rb \'hash -p /usr/bin/docker d; d run alpine:3.20\')"',
                 'case_ c02-uncommitted-script   bad "$(rb \'printf x > /tmp/gen.sh; bash /tmp/gen.sh\')"',
                 'case_ c02-generated-elsewhere  bad "$(rb \'printf x > /tmp/smoke-assert.sh; bash /tmp/smoke-assert.sh\')"',
                 'case_ r2c01-bracket-only       bad "$(rb \'/usr/bin/[d][o][c][k][e][r] run alpine\')"',
                 'case_ n35-curl-chmod-run       bad "$(rb \'curl -sL -o /tmp/setup https://example.com/ci/setup; chmod +x /tmp/setup; '
                 '/tmp/setup\')"',
                 'case_ n35-base64-chmod-run     bad "$(rb "printf \'%s\\\\n\' \'docker pull alpine:latest\' | base64 > /tmp/x.b64; '
                 'base64 -d /tmp/x.b64 > /tmp/x; chmod +x /tmp/x; /tmp/x")"',
                 'case_ n35-wget-run             bad "$(rb \'wget -O /tmp/inst https://example.com/i; chmod 755 /tmp/inst; /tmp/inst '
                 '--flag\')"',
                 'case_ n35-built-binary-ok      ok  "$(rb \'mkdir -p /tmp/bins; tar xzf dist/fscache.tgz -C /tmp/bins fscache; '
                 '/tmp/bins/fscache --version\')"',
                 'case_ r3c01-posix-class        bad "$(rb \'/usr/bin/[[:lower:]]ocker run alpine\')"',
                 'case_ r3c02-python-generated   bad "$(rb "printf \'import os\\\\n\' > /tmp/fetch.py; python3 /tmp/fetch.py")"',
                 'case_ r3c09-sbom-true          bad "$(rb \'docker buildx build --sbom=true --output type=local,dest=/tmp/out .\')" '
                 '"printf \'FROM scratch\\\\n\' > Dockerfile"',
                 'case_ r3c09-attest-sbom        bad "$(rb \'docker buildx build --attest=type=sbom --output type=local,dest=/tmp/out '
                 '.\')" "printf \'FROM scratch\\\\n\' > Dockerfile"',
                 'case_ r3c10-skopeo-local       bad "$(rb \'docker build -t alpine .; skopeo copy docker://alpine '
                 'docker-archive:/tmp/a\')" "printf \'FROM scratch\\\\n\' > Dockerfile"',
                 'case_ r3c10-crane-local        bad "$(rb \'docker build -t alpine .; crane pull alpine /tmp/image.tar\')" "printf '
                 '\'FROM scratch\\\\n\' > Dockerfile"',
                 'case_ r3c11-workspace-abs      bad "$(rb \'cp -R evil/. /home/runner/work/cache/cache/; docker build .\')" "printf '
                 '\'FROM scratch\\\\n\' > Dockerfile; mkdir -p evil; printf \'FROM alpine\\\\n\' > evil/Dockerfile"',
                 'case_ r3c11-tar-workspace      bad "$(rb \'tar xf evil.tar -C /home/runner/work/cache/cache; docker build .\')" '
                 '"printf \'FROM scratch\\\\n\' > Dockerfile"',
                 'case_ r3c11-mpip-req           bad "$(rb \'curl -fsSL https://example.org/req.txt -o /tmp/req.txt; python3 -Im pip '
                 'install --require-hashes -r /tmp/req.txt\')"',
                 'case_ r3c11-pipmain-req        bad "$(rb \'python3 -m pip.__main__ install --require-hashes -r /tmp/req.txt\')"',
                 "# --- r20 (Sonnet B2): main's own stage-admission.yml writes main's copy of a committed script to /tmp/policy in ONE "
                 'step and runs it in',
                 "# ANOTHER (#163's design). A /tmp copy that a step of the job writes ONCE from `git show origin/main:<committed file>` "
                 'resolves to that',
                 'mkdir -p /tmp/policy',
                 'git show origin/main:bin/tool.sh > /tmp/policy/tool.sh',
                 '- run: bash /tmp/policy/tool.sh" "$mkdir_bin"',
                 'mkdir -p /tmp/policy',
                 'git show origin/main:bin/tool.py > /tmp/policy/tool.py',
                 '- run: python3 /tmp/policy/tool.py" "$mkdir_bin"',
                 'git show attacker:bin/tool.sh > /tmp/policy/tool.sh',
                 '- run: bash /tmp/policy/tool.sh" "$mkdir_bin"',
                 '- run: bash /tmp/policy/tool.sh" "$mkdir_bin"',
                 'git show origin/main:bin/tool.sh > /tmp/policy/tool.sh',
                 'curl -sSf https://example.invalid/x > /tmp/policy/tool.sh',
                 '- run: bash /tmp/policy/tool.sh" "$mkdir_bin"',
                 'git show origin/main:bin/missing.sh > /tmp/policy/missing.sh',
                 '- run: bash /tmp/policy/missing.sh" "$mkdir_bin"',
                 'git show origin/main:bin/tool.sh > /tmp/policy/other.sh',
                 '- run: bash /tmp/policy/other.sh" "$mkdir_bin"',
                 'case_ r20-b09-local-exporter-bad bad "$(rb \'docker buildx build --output=type=local,dest=/tmp/out -t alpine:latest .',
                 'case_ r20-b09-short-output-bad bad "$(rb \'docker build -o /tmp/out -t alpine:latest .',
                 'case_ r21-attached-output-type-bad bad "$(rb \'docker build -otype=tar,dest=/tmp/o.tar -t alpine:latest .',
                 'mkdir -p /tmp/policy',
                 'git show origin/main:bin/tool.sh > /tmp/policy/tool.sh',
                 "- run: sed -i 's/echo hi/docker run alpine:latest/' /tmp/policy/tool.sh",
                 '- run: bash /tmp/policy/tool.sh" "$mkdir_bin"',
                 'mkdir -p /tmp/policy',
                 'git show origin/main:bin/tool.sh > /tmp/policy/tool.sh',
                 '- run: cp replacement.sh /tmp/policy/tool.sh',
                 '- run: bash /tmp/policy/tool.sh" "$mkdir_bin"',
                 'case_ r23c-b09-download-install-path-bad bad "$(rb \'curl -fsSL '
                 'https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64 -o /tmp/cosign',
                 'sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign',
                 'case_ r23c-b09-download-mv-then-bare-name-bad bad "$(rb \'curl -fsSL https://example.org/tool -o /tmp/tool',
                 'mv /tmp/tool /usr/local/bin/tool',
                 'case_ r23c-b09-install-of-committed-file-ok ok "$(rb \'sudo install -m 0755 bin/tool.sh /usr/local/bin/tool',
                 'case_ r24-install-download-into-directory-bad bad "$(rb \'curl -fsSL https://example.org/tool -o /tmp/tool',
                 'sudo install -m 0755 /tmp/tool /usr/local/bin/',
                 'case_ r24-install-t-directory-bad bad "$(rb \'curl -fsSL https://example.org/tool -o /tmp/tool',
                 'sudo install -t /usr/local/bin /tmp/tool',
                 'case_ r26-b9-curl-clustered-o-then-install-bad bad "$(rb \'curl -fsSLo /tmp/cosign '
                 'https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64',
                 'sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign',
                 'case_ r26-b9-curl-straight-into-path-bad bad "$(rb \'curl -fsSL -o /usr/local/bin/cosign '
                 'https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64',
                 'chmod +x /usr/local/bin/cosign',
                 'case_ r26-b9-wget-straight-into-path-bad bad "$(rb \'wget -qO /usr/local/bin/cosign '
                 'https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64',
                 'chmod +x /usr/local/bin/cosign',
                 'case_ r26-b9-curl-attached-o-then-copy-bad bad "$(rb \'curl -o/tmp/y https://e.example/y',
                 'cp /tmp/y /usr/bin/y',
                 'skopeo copy "$SRC" docker-archive:/tmp/probe.tar\')"',
                 'skopeo copy "$SRC" docker-archive:/tmp/probe.tar\')"',
                 'case_ r31-b4-curl-redirected-then-installed-bad bad "$(rb \'curl -fsSL https://example.org/releases/latest/tool > '
                 '/tmp/tool',
                 'sudo install -m 0755 /tmp/tool /usr/local/bin/tool',
                 'case_ r31-b4-curl-redirected-into-a-path-directory-bad bad "$(rb \'curl -fsSL https://example.org/releases/latest/tool '
                 '> /usr/local/bin/tool',
                 'chmod +x /usr/local/bin/tool',
                 'skopeo copy "${SRC[0]}" docker-archive:/tmp/probe.tar\')"',
                 'case_ r32-b4-curl-ampersand-redirect-then-installed-bad bad "$(rb \'curl -fsSL '
                 'https://example.org/releases/latest/tool &> /tmp/tool',
                 'sudo install -m 0755 /tmp/tool /usr/local/bin/tool',
                 'case_ r32-b4-curl-ampersand-redirect-into-a-path-directory-bad bad "$(rb \'curl -fsSL '
                 'https://example.org/releases/latest/tool &> /usr/local/bin/tool',
                 'chmod +x /usr/local/bin/tool',
                 'case_ r33-b1-ampersand-redirect-to-a-quoted-name-with-a-space-bad bad "$(rb \'curl -fsSL '
                 'https://example.org/releases/latest/tool &> "/tmp/my tool"',
                 'sudo install -m 0755 "/tmp/my tool" /usr/local/bin/tool',
                 'case_ r33-b1-ampersand-append-redirect-to-a-quoted-name-bad bad "$(rb \'curl -fsSL '
                 'https://example.org/releases/latest/tool &>> "/tmp/my tool"',
                 'sudo install -m 0755 "/tmp/my tool" /usr/local/bin/tool'],
        "text of workflow run: steps, Dockerfiles and script bodies written into per-case temp trees and judged by the pin checker, which reads only the tree's own entries (FsTree/GitTree); the one fixture that creates a link (r24) now points at a file under $work"),
    '.github/agent/tests/k8s-harness-fence-test.sh': ('db412b5dcd814aad71a9a2e436ac7a255507aa9a79f0f6a66884d889f67038c9',
        [        '# the pin checker excludes exactly two generated files of stage-acceptance-k8s.yml (/tmp/pf-forward.sh,',
                 "# /tmp/smoke-assert.sh). The fence: both are written by the step's own python ONLY from docs/kubernetes.md at the",
                 'gen = [s for s in steps if "/tmp/pf-forward.sh" in (s.get("run") or "") and "python3 - <<\'PY\'" in (s.get("run") or '
                 '"")]',
                 'check("it writes the two fenced scripts (and the pod yaml)", {"/tmp/pf-forward.sh", "/tmp/smoke-assert.sh"} <= '
                 'set(writes), writes)',
                 'code = src.replace("/tmp/", d + "/out-")',
                 '(".github/workflows/stage-acceptance-k8s.yml", "/tmp/pf-forward.sh"),',
                 '(".github/workflows/stage-acceptance-k8s.yml", "/tmp/smoke-assert.sh")}, set(P.GENERATED_OK))',
                 'P.check_runs(".github/workflows/x.yml.jobs.j.steps[0].run", [("x", \'c=$(cat /tmp/c); eval "$c"\', None)], bad)',
                 'P.check_runs(".github/workflows/x.yml.jobs.j.steps[0].run", [("x", "bash /tmp/pf-forward.sh", None)], bad)',
                 'for name, extra in [("a redirect", "echo id > /tmp/pf-forward.sh"), ("a copy", "cp /tmp/x /tmp/smoke-assert.sh"),',
                 '("a download", "curl -fsSL https://example.invalid/x -o /tmp/pf-forward.sh"),',
                 '("a bash -c write", "bash -c \'printf id > /tmp/smoke-assert.sh\'")]:',
                 '"bash /tmp/pf-forward.sh; bash /tmp/smoke-assert.sh", None)], bad)',
                 '[(".github/workflows/stage-acceptance-k8s.yml.jobs.k8s.steps[0].run", "bash /tmp/pf-forward.sh", None)], bad)'],
        "workflow-step text and the names of the two generated scripts the checker's fence excludes; the generator's own python is run with /tmp/ rewritten to a temp dir (line 40) so nothing is written to the system"),
    '.github/agent/tests/pin-wiring-test.sh': ('8131e9a1b306e377889cee4e2c267abc47af871ba011f6b3c57a4703dff98054',
        [        'case_ bash-env-on-step      bad "$pick[\'env\'] = {\'BASH_ENV\': \'/tmp/x.sh\'}"',
                 'case_ bash-env-on-job       bad "d[\'jobs\'][\'allowlist\'][\'env\'] = {\'BASH_ENV\': \'/tmp/x.sh\'}"',
                 'case_ path-on-workflow      bad "d[\'env\'] = {\'PATH\': \'/tmp/fake:/usr/bin\'}"',
                 'case_ github-env-write      bad "$steps.insert(1, {\'run\': \'echo BASH_ENV=/tmp/x.sh >> \\"\\$GITHUB_ENV\\"\'})"',
                 'case_ github-path-write     bad "$steps.insert(1, {\'run\': \'echo /tmp/fake >> \\"\\$GITHUB_PATH\\"\'})"',
                 'case_ job-env-index-file        bad "d[\'jobs\'][\'allowlist\'][\'env\'] = {\'GIT_INDEX_FILE\': \'/tmp/i\'}"',
                 'case_ wf-env-index-file         bad "d[\'env\'] = {\'GIT_INDEX_FILE\': \'/tmp/i\'}"',
                 'case_ step-env-index-file       bad "$steps[2][\'env\'][\'GIT_INDEX_FILE\'] = \'/tmp/i\'"',
                 'case_ fetch-env-git-dir         bad "$steps[1][\'env\'][\'GIT_DIR\'] = \'/tmp/g\'"',
                 'case_ ld-preload-step           bad "$steps[4][\'env\'] = {\'LD_PRELOAD\': \'/tmp/x.so\'}"'],
        'values injected into an in-memory copy of a workflow (env PATH, BASH_ENV ...) to prove the wiring check rejects them; never used as paths by the test'),
    '.github/agent/tests/pip-pin-test.sh': ('254f1417c7d4b26d6d441dd12db8bffba3eefe2062eba067285fb20aa52cb35b',
        [        '# holds PER ENVIRONMENT: every install through a venv (<venv>/bin/pip, <venv>/bin/python -m pip, or pip after `source '
                 '<venv>/bin/activate`) needs the',
                 '# pin installed INTO THAT VENV first (<venv>/bin/python -m pip install ... -r the file, then <venv>/bin/python -m pip '
                 '--version).',
                 'if d.endswith("/bin"):',
                 'if base in ("source", ".") and rest and norm(rest[0]).endswith("/bin/activate"):',
                 'return ("activate", norm(rest[0])[: -len("/bin/activate")], None)',
                 'pips = [u for u in ups if u.get("package-ecosystem") == "pip" and u.get("directory") == "/.github/agent"]',
                 'r.append(("C4", "dependabot.yml has no pip entry for directory /.github/agent"))'],
        "venv-relative suffixes (/bin, /bin/activate) inside the checker's own string rules under test"),
    '.github/agent/tests/supply-chain-wiring-test.sh': ('e14085714fd02e3c9555436e0d9695a8227ed31053ce01f566ac6e04a3e868cf',
        [        'mut_wf("a step writes BASH_ENV", "writes the job\'s environment", lambda d: J(d, "pin-age")["steps"].insert(0, {"run": '
                 '\'echo "BASH_ENV=/tmp/x" >> "$GITHUB_ENV"\'}))',
                 'mut_wf("the PR job writes observations", "only daily-audit may write the tag observations", lambda d: '
                 '[x.update(run=x["run"] + " --observations-out /tmp/x") for x in J(d, "pin-age")["steps"] if "run" in x])',
                 'mut_db("docker\'s directory changes", "docker entry is not unchanged", lambda d: eco(d, '
                 '"docker").update(directory="/"))'],
        'run-step text injected into an in-memory workflow copy to prove the wiring check rejects it'),
    'bin/admission-tag-signer-test.sh': ('1f6b11ee3c249eac940d3a2783311fb8fd357233527b523524bab40e4fa842a4',
        [        'if "/tmp/policy/admission-tag-signer.py" not in run or "/tmp/policy/install-scanner.sh gitsign" not in run:',
                 'if "/tmp/policy/admission-tag-signer.py owner-baselines" not in brun or "--allowed-signers '
                 '/tmp/policy/allowed_signers" not in brun \\',
                 'if \'/tmp/policy/admission-tag-signer.py baseline\' not in brun or "steps.tagsig.outputs.method" not in '
                 'str(base[0].get("env", {})) if base else True:',
                 'case_ route-from-tag     bad "sig[\'run\'] = sig[\'run\'].replace(\'/tmp/policy/admission-tag-signer.py\', '
                 '\'bin/admission-tag-signer.py\')"',
                 'case_ gitsign-from-tag   bad "sig[\'run\'] = sig[\'run\'].replace(\'/tmp/policy/install-scanner.sh gitsign\', '
                 '\'./bin/install-scanner.sh gitsign\')"',
                 'case_ keyless-own-baseline bad "B = [s for s in S if \'APPROVED\' in s.get(\'name\',\'\')][0]; B[\'run\'] = '
                 'B[\'run\'].replace(\'/tmp/policy/admission-tag-signer.py baseline\', \'echo\')"',
                 'case_ any-signer-baselines bad "B = [s for s in S if \'APPROVED\' in s.get(\'name\',\'\')][0]; B[\'run\'] = '
                 'B[\'run\'].replace(\'--allowed-signers /tmp/policy/allowed_signers\', \'--allowed-signers allowed_signers\')"'],
        'the runner paths the admission workflow uses (/tmp/policy/...), as text in assertions and in string replacements on an in-memory workflow copy'),
    'bin/panel-test.sh': ('f65aee500abf3216cc10eca7d5988918310e747b44b3541c4128558df580ea00',
        [        'files = [{"bom-ref": "f%d" % i, "type": "file", "name": "/usr/lib/f%d" % i} for i in range(5)] if pkgs else []',
                 '"components": [{"bom-ref": "f1", "type": "file", "name": "/etc/passwd"}]})   # files but no package: did not run'],
        'SBOM file-component names (paths inside a scanned image) used as data in a JSON document'),
    'bin/panel-wiring-test.sh': ('d7a916a9f5a9c7aedca1ace4915fd394e61f57bc13846d3bf2fa48f501e6b081',
        [        '\'cp -r "$RUNNER_TEMP/probe" /tmp/panel/scout-probe\'):',
                 'case_ panel-reads-history     bad "s=$(step_of panel \'bin/panel.py tally\'); s[\'run\'] = '
                 's[\'run\'].replace(\'--out\', \'--prior /tmp/prior/judgments.json --out\')"'],
        'workflow step text compared and mutated in memory'),
    'bin/release-patch-wiring-test.sh': ('d499258d6ae69dbfa7f8ee2b7b0e83f953327c5a59c7b20a0acff07b32696006',
        [        'if _call and not (_call.group(2).startswith(".github/") and _call.group(2).endswith("/bin") and '
                 '_call.group(2).count("/") == 2 and',
                 '_got = [re.sub(r"python3 \\.github/[a-z]+/bin/auditor-signed-commit\\.py", "python3 @CLI@", " ".join(l.split()))',
                 'mutrun git-abs-path-push       "$BASE" "/usr/bin/git push origin HEAD:main; $BASE"',
                 'case_ ctx-step-env-path       bad "[s[\'env\'].__setitem__(\'PATH\', \'/tmp/evil\') for s in $N[\'steps\'] if \'gh pr '
                 'create\' in (s.get(\'run\') or \'\')]"',
                 'case_ ctx-job-env-path        bad "$N[\'env\'] = {\'PATH\': \'/tmp/evil:\\$PATH\'}"'],
        'run-step text and path-suffix rules for the release wiring check (absolute-path git, PATH injection) evaluated on in-memory workflow copies'),
}
