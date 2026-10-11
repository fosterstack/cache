// Package platforms holds the repository checks for the release platform matrix (REQ-PLAT-001): what
// .goreleaser.yaml builds, what the public docs claim, and what the next release notes say. It has no
// non-test code; the tests read the repository files from the module root.
package platforms

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// root is the module root, two directories up from internal/platforms.
const root = "../.."

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// relBuild is one entry of the builds: section of .goreleaser.yaml, as far as the platform check reads it.
type relBuild struct {
	id           string
	goos, goarch []string
	hasGoos      bool
	hasGoarch    bool
}

var (
	platformKey = regexp.MustCompile(`(?i)\b(goos|goarch|targets|ignore)\b`)
	anchorAlias = regexp.MustCompile(`(^|[\s:\[\],{}-])[&*][A-Za-z0-9_.-]`)
	mergeKey    = regexp.MustCompile(`<<\s*:`)
	buildItem   = regexp.MustCompile(`^  - (.*)$`)
	buildKey    = regexp.MustCompile(`^    ([a-z_]+):(.*)$`)
	listItem    = regexp.MustCompile(`^      - (.*)$`)
	itemKey     = regexp.MustCompile(`^([a-z_]+):(.*)$`)
	plainWord   = regexp.MustCompile(`^[a-z0-9]+$`)
	plainID     = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// parseBuilds reads the builds: section line by line, in the one block style the file uses. It reports, and
// never guesses at, anything it cannot read: an anchor, alias or merge key anywhere; a goos/goarch key that
// is not `goos:` alone on its line inside a build (a flow list, a quoted key, a key outside builds:); a list
// item that is not a plain lower-case word; any targets: or ignore: key; a line of builds: of another shape.
func parseBuilds(text string) (builds []relBuild, problems []string) {
	lines := strings.Split(text, "\n")
	accepted := map[int]bool{} // lines holding a goos/goarch key the parser read
	for n, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if anchorAlias.MatchString(line) || mergeKey.MatchString(line) {
			problems = append(problems, fmt.Sprintf("line %d: anchor, alias or merge key: %s", n+1, strings.TrimSpace(line)))
		}
	}
	in := false
	var cur *relBuild
	listKey := "" // the key whose block list the next items belong to
	for n := 0; n < len(lines); n++ {
		line := strings.TrimRight(lines[n], " \t")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			in = line == "builds:"
			if strings.HasPrefix(line, "builds") && !in {
				problems = append(problems, fmt.Sprintf("line %d: builds key in another form: %s", n+1, line))
			}
			continue
		}
		if !in {
			continue
		}
		var key, val string
		if m := buildItem.FindStringSubmatch(line); m != nil {
			builds = append(builds, relBuild{})
			cur = &builds[len(builds)-1]
			km := itemKey.FindStringSubmatch(m[1])
			if km == nil {
				problems = append(problems, fmt.Sprintf("line %d: a build that does not start with a plain key: %s", n+1, line))
				listKey = ""
				continue
			}
			key, val = km[1], km[2]
		} else if m := buildKey.FindStringSubmatch(line); m != nil && cur != nil {
			key, val = m[1], m[2]
		} else if m := listItem.FindStringSubmatch(line); m != nil && cur != nil {
			item := strings.TrimSpace(m[1])
			switch listKey {
			case "goos", "goarch":
				if !plainWord.MatchString(item) {
					problems = append(problems, fmt.Sprintf("line %d: %s item is not a plain word: %s", n+1, listKey, item))
				} else if listKey == "goos" {
					cur.goos = append(cur.goos, item)
				} else {
					cur.goarch = append(cur.goarch, item)
				}
			case "":
				problems = append(problems, fmt.Sprintf("line %d: a list item under no block key: %s", n+1, line))
			}
			continue
		} else {
			problems = append(problems, fmt.Sprintf("line %d: a builds line of a shape this check does not read: %s", n+1, line))
			continue
		}
		val = strings.TrimSpace(val)
		listKey = ""
		switch key {
		case "goos", "goarch":
			if val != "" {
				problems = append(problems, fmt.Sprintf("line %d: %s is not a block list: %s", n+1, key, strings.TrimSpace(line)))
				continue
			}
			if (key == "goos" && cur.hasGoos) || (key == "goarch" && cur.hasGoarch) {
				problems = append(problems, fmt.Sprintf("line %d: %s repeated in one build", n+1, key))
			}
			if key == "goos" {
				cur.hasGoos = true
			} else {
				cur.hasGoarch = true
			}
			accepted[n] = true
			listKey = key
		case "id":
			if !plainID.MatchString(val) || cur.id != "" {
				problems = append(problems, fmt.Sprintf("line %d: build id not plain or repeated: %s", n+1, strings.TrimSpace(line)))
			}
			cur.id = val
		default:
			if val == "" {
				listKey = key
			}
		}
	}
	for n, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || accepted[n] {
			continue
		}
		if m := platformKey.FindString(line); m != "" {
			problems = append(problems, fmt.Sprintf("line %d: %s outside the block form this check reads: %s", n+1, m, strings.TrimSpace(line)))
		}
	}
	return builds, problems
}

// checkReleaseConfig returns every reason the given .goreleaser.yaml text does not build exactly the
// fscache and fscache-fips builds for linux amd64/arm64 and nothing else.
func checkReleaseConfig(text string) []string {
	builds, problems := parseBuilds(text)
	want := map[string]bool{"fscache": true, "fscache-fips": true}
	seen := map[string]bool{}
	if len(builds) != len(want) {
		problems = append(problems, fmt.Sprintf("%d builds, want exactly fscache and fscache-fips", len(builds)))
	}
	for i, b := range builds {
		if !want[b.id] || seen[b.id] {
			problems = append(problems, fmt.Sprintf("build %d has id %q, not one of fscache, fscache-fips (each once)", i+1, b.id))
		}
		seen[b.id] = true
		if !b.hasGoos || strings.Join(b.goos, ",") != "linux" {
			problems = append(problems, fmt.Sprintf("build %q goos is %v, want exactly [linux] (a missing goos defaults to darwin, linux, windows)", b.id, b.goos))
		}
		if !b.hasGoarch || strings.Join(b.goarch, ",") != "amd64,arm64" {
			problems = append(problems, fmt.Sprintf("build %q goarch is %v, want exactly [amd64 arm64]", b.id, b.goarch))
		}
	}
	if regexp.MustCompile(`(?i)darwin|windows|macos`).MatchString(text) {
		problems = append(problems, "names darwin, windows or macos")
	}
	return problems
}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigBuildsOnlyLinux: .goreleaser.yaml builds exactly two builds (fscache, fscache-fips), each
// for goos [linux] and goarch [amd64, arm64], and names no darwin or windows target anywhere (no `targets:`
// or `ignore:` route around goos either).
func TestReleaseConfigBuildsOnlyLinux(t *testing.T) {
	for _, p := range checkReleaseConfig(read(t, ".goreleaser.yaml")) {
		t.Error(".goreleaser.yaml: " + p)
	}
}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigCheckRefusesMutants: each edit of the real .goreleaser.yaml that would ship a non-Linux
// target, an extra build or architecture, or a form the check cannot read is refused (fail closed).
func TestReleaseConfigCheckRefusesMutants(t *testing.T) {
	real := read(t, ".goreleaser.yaml")
	const fipsGoos = "      - GOFIPS140=v1.0.0\n    goos:\n      - linux\n"
	const extraBuild = "\n  - id: fscache-bsd\n    main: ./cmd/fscache\n    binary: fscache-bsd\n    goos:\n      - freebsd\n    goarch:\n      - amd64\n"
	edit := func(old, new string) string {
		if strings.Count(real, old) != 1 {
			t.Fatalf("mutant anchor not found exactly once: %q", old)
		}
		return strings.Replace(real, old, new, 1)
	}
	mutants := map[string]string{
		"extra build without goos":          edit("\narchives:", "\n  - id: fscache-x\n    main: ./cmd/fscache\n    binary: fscache-x\n\narchives:"),
		"extra build, dash-form block goos": edit("\narchives:", "\n  - goos:\n      - freebsd\n    goarch:\n      - amd64\n    id: fscache-bsd\n\narchives:"),
		"extra build, block goos":           edit("\narchives:", extraBuild+"\narchives:"),
		"extra build, dash-form goos":       edit("\narchives:", "\n  - goos: [freebsd]\n    goarch:\n      - amd64\n    main: ./cmd/fscache\n    id: fscache-bsd\n\narchives:"),
		"dash-form goos key on a build":     edit("  - id: fscache-fips\n", "  - goos:\n      - freebsd\n    id: fscache-fips\n"),
		"flow goos list":                    edit(fipsGoos, "      - GOFIPS140=v1.0.0\n    goos: [linux, freebsd]\n"),
		"extra goos item":                   edit(fipsGoos, fipsGoos+"      - freebsd\n"),
		"goarch addition":                   edit("      - arm64\n    flags:\n      - -trimpath\n    ldflags:\n      - -s -w\n    mod_timestamp: \"{{ .CommitTimestamp }}\"\n\narchives:", "      - arm64\n      - riscv64\n    flags:\n      - -trimpath\n    ldflags:\n      - -s -w\n    mod_timestamp: \"{{ .CommitTimestamp }}\"\n\narchives:"),
		"goarch flow list":                  edit("    goarch:\n      - amd64\n      - arm64\n    flags:\n      - -trimpath\n    ldflags:\n      - -s -w\n    mod_timestamp: \"{{ .CommitTimestamp }}\"\n\narchives:", "    goarch: [amd64, arm64, riscv64]\n    flags:\n      - -trimpath\n    ldflags:\n      - -s -w\n    mod_timestamp: \"{{ .CommitTimestamp }}\"\n\narchives:"),
		"anchor and alias":                  edit(fipsGoos, "      - GOFIPS140=v1.0.0\n    goos: &os\n      - linux\n"),
		"alias goos":                        edit(fipsGoos, "      - GOFIPS140=v1.0.0\n    goos: *os\n"),
		"alias item":                        edit(fipsGoos, "      - GOFIPS140=v1.0.0\n    goos:\n      - *os\n"),
		"templated goos":                    edit(fipsGoos, "      - GOFIPS140=v1.0.0\n    goos:\n      - \"{{ .Env.OS }}\"\n"),
		"quoted goos key":                   edit(fipsGoos, "      - GOFIPS140=v1.0.0\n    \"goos\":\n      - freebsd\n"),
		"targets key":                       edit(fipsGoos, fipsGoos+"    targets:\n      - freebsd_amd64\n"),
		"merge key":                         edit(fipsGoos, fipsGoos+"    <<: *other\n"),
		"darwin goos added":                 edit(fipsGoos, fipsGoos+"      - darwin\n"),
		"ignore key":                        edit(fipsGoos, fipsGoos+"    ignore:\n      - goos: linux\n"),
		"second empty builds section":       real + "\nbuilds:\n",
		"second builds section, flow":       real + "\nbuilds: []\n",
		"second builds section, one build":  real + "\nbuilds:\n  - id: fscache\n    goos:\n      - linux\n    goarch:\n      - amd64\n      - arm64\n",
		"double-quoted builds key":          real + "\n\"builds\": []\n",
		"single-quoted builds key":          real + "\n'builds': []\n",
		"builds key with a space":           real + "\nbuilds : []\n",
		"explicit-key builds":               real + "\n? builds\n: []\n",
		"flow mapping at top level":         real + "\n{builds: []}\n",
		"second document":                   real + "\n---\nbuilds: []\n",
		"tab-indented top-level line":       real + "\n\tbuilds: []\n",
		"repeated other top-level key":      real + "\nrelease:\n  draft: true\n",
		"no builds section":                 edit("\nbuilds:\n", "\nbuildz:\n"),
	}
	for name, text := range mutants {
		ps := checkReleaseConfig(text)
		if len(ps) == 0 {
			t.Errorf("mutant %q passes the release-config check", name)
		}
		t.Logf("%s: refused: %v", name, ps)
	}
}

// platformWord finds a mention of a non-Linux desktop platform.
var platformWord = regexp.MustCompile(`(?i)darwin|mac\s?os|\bmacs?\b|apple silicon|\bosx\b|windows`)

// docsScanned are the public docs that describe what a release ships.
var docsScanned = []string{"README.md", "docs/install.md", "docs/docker-deploy.md", "RELEASING.md", "docs/verify-images.md"}

// allowedLine is a line of a scanned doc that names a non-Linux platform without claiming a darwin or
// windows binary exists. The text is the whole line, trimmed; each must still be present (a stale entry fails).
type allowedLine struct {
	file, text, why string
	optional        bool // may be absent: the line arrives when this branch next takes main
}

var allowedLines = []allowedLine{
	{"README.md", "Linux. No macOS or Windows binaries are shipped: on a Mac, run the container image", "the REQ-PLAT-001 statement itself", false},
	{"README.md", "resolves the right image by itself on Apple Silicon and Graviton. Windows is", "the multi-arch container image runs on an Apple Silicon host; Windows is stated as not built", false},
	{"README.md", "runners; develop on Windows via WSL2, which is `linux/amd64`.", "WSL2 runs the Linux binary", false},
	{"docs/install.md", "**No macOS or Windows binaries are shipped.** On a Mac, run the container", "the REQ-PLAT-001 statement itself", false},
	{"docs/install.md", "`docker pull` resolves the right one automatically — including on Apple Silicon and Graviton.", "the multi-arch container image runs on an Apple Silicon host (the name wraps across two lines)", false},
	{"docs/install.md", "**Windows is not built and not planned.** This is a server-side cache that", "states that no Windows build exists", false},
	{"docs/install.md", "lives next to your CI runners; there's no meaningful market for a Windows", "states that no Windows build exists", false},
	{"docs/install.md", "build. If you develop on Windows, run the server under WSL2 — that's", "WSL2 runs the Linux binary", false},
	{"docs/install.md", "sha256sum -c checksums.txt 2>/dev/null | grep OK   # or `shasum -a 256 -c` on macOS", "shell portability for the machine that verifies a download, not a shipped binary", false},
	{"docs/docker-deploy.md", "image for the node automatically — Apple Silicon and Graviton included. You", "the multi-arch container image runs on an Apple Silicon host", false},
	{"docs/docker-deploy.md", "There are no darwin or windows images and no darwin or windows binaries: on a", "states that no darwin or windows artifact exists", false},
	{"docs/docker-deploy.md", "Mac or a Windows host, run the `linux/amd64` or `linux/arm64` image under", "the container route for Mac and Windows hosts", false},
	{"RELEASING.md", "authentication, so it works on a stock macOS or a minimal container.", "shell portability of the verify commands, not a shipped binary", false},
	{"docs/verify-images.md", "macOS 14 and later; on older macOS use `base64 -D`.)", "shell portability of the verify commands, not a shipped binary (on main since #275)", true},
}

// notScanned are files and directories outside docsScanned that mention a non-Linux platform on purpose;
// they are not claims about what a release ships. TestNotScannedListIsCurrent keeps the list honest: each
// entry exists and a scan of it would flag a line, so a stale entry fails.
var notScanned = map[string]string{
	"docs/gradle.md":                                   "line 136 records the historical test environment (Gradle on a macOS arm64 host), marked pinned: historical",
	"internal/storesample":                             "build tags that let the package compile on a developer's macOS host; not a release target",
	"internal/blobstore":                               "comments on darwin ReadDir behaviour seen on developer hosts",
	"bench/gradle-sample/gradlew":                      "vendored Gradle wrapper script",
	".github/agent":                                    "its runner and developer-host logic names Windows and macOS runners it refuses or works around",
	"docs/quality/traceability.md":                     "generated from requirements.yaml",
	"requirements/":                                    "the requirement text and frozen v0.2.x baselines",
	"docs/next-release-notes.md":                       "carries the REQ-PLAT-001 release-notes line (checked by TestNextReleaseNotesSayLinuxOnly)",
	".github/workflows/stage-acceptance-artifacts.yml": "frozen legacy stage file (legacy-stage-files.json); its archive check is rewritten by the release-chain pull requests",
}

// releaseArchiveCount is the number of archives the real .goreleaser.yaml produces: one per build, goos and
// goarch. It fails the test if the config cannot be read.
func releaseArchiveCount(t *testing.T) int {
	t.Helper()
	builds, problems := parseBuilds(read(t, ".goreleaser.yaml"))
	if len(problems) > 0 {
		t.Fatalf(".goreleaser.yaml cannot be read: %v", problems)
	}
	n := 0
	for _, b := range builds {
		n += len(b.goos) * len(b.goarch)
	}
	return n
}

// checkDoc returns every problem in one scanned doc and the allowed texts it found.
func checkDoc(file, text string, allowed []allowedLine, archives int) (problems []string, seen map[string]bool) {
	_ = archives
	ok := map[string]bool{}
	for _, a := range allowed {
		if a.file == file {
			ok[a.text] = true
		}
	}
	seen = map[string]bool{}
	for n, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(l), "_darwin_") {
			problems = append(problems, fmt.Sprintf("%s:%d names a darwin archive: %s", file, n+1, l))
		}
		if !platformWord.MatchString(l) {
			continue
		}
		if ok[l] {
			seen[l] = true
			continue
		}
		problems = append(problems, fmt.Sprintf("%s:%d names a non-Linux platform and is not an allowed line: %s", file, n+1, l))
	}
	return problems, seen
}

// proves: REQ-PLAT-001-AC1
// TestDocsClaimNoDarwinOrWindowsBinary: every line of the public docs that names darwin, macOS, a Mac,
// Apple Silicon, OS X or Windows is one of the named allowed lines (none of which claims such a binary);
// darwin archive names are gone, and each allowed line is still present.
func TestDocsClaimNoDarwinOrWindowsBinary(t *testing.T) {
	archives := releaseArchiveCount(t)
	for _, f := range docsScanned {
		if _, skip := notScanned[f]; skip {
			t.Fatalf("%s is both scanned and listed as not scanned", f)
		}
		problems, seen := checkDoc(f, read(t, f), allowedLines, archives)
		for _, p := range problems {
			t.Error(p)
		}
		for _, a := range allowedLines {
			if a.file == f && !seen[a.text] && !a.optional {
				t.Errorf("%s: allowed line no longer present (remove it from allowedLines): %s", f, a.text)
			}
		}
	}
	for _, a := range allowedLines {
		if a.why == "" {
			t.Errorf("allowed line in %s has no reason: %s", a.file, a.text)
		}
	}
}

// proves: REQ-PLAT-001-AC1
// TestDocsCheckRefusesMutants: a platform claim wrapped across a Markdown soft line break, an OS X claim, an
// archive count that disagrees with .goreleaser.yaml, and a darwin archive name are each refused; the
// wrapped Apple Silicon mention in docs/install.md passes only through its named exception.
func TestDocsCheckRefusesMutants(t *testing.T) {
	const f = "docs/install.md"
	install := read(t, f)
	archives := releaseArchiveCount(t)
	mutants := map[string]string{
		"wrapped Apple Silicon claim": install + "\nNative binaries are available for Apple\nSilicon.\n",
		"wrapped Mac OS claim":        install + "\nNative binaries are available for Mac\nOS hosts.\n",
		"OS X claim":                  install + "\nAn OS X build is attached to each release.\n",
		"OSX claim":                   install + "\nAn OSX build is attached to each release.\n",
		"six archives":                install + "\nEvery release ships six archives.\n",
		"wrapped six archives":        install + "\nEvery release ships six\nrelease archives.\n",
		"digit archive count":         install + "\nEvery release ships 6 archives.\n",
		"darwin archive name":         install + "\nDownload `fscache_1.0.0_darwin_arm64.tar.gz`.\n",
		"claim inside a code fence":   install + "\n```sh\n# macOS: fscache_1.0.0_mac.tar.gz\n```\n",
	}
	for name, text := range mutants {
		ps, _ := checkDoc(f, text, allowedLines, archives)
		if len(ps) == 0 {
			t.Errorf("mutant %q passes the docs check", name)
		}
		t.Logf("%s: refused: %v", name, ps)
	}
	var without []allowedLine
	for _, a := range allowedLines {
		if a.file != f || !strings.Contains(a.text, "Apple Silicon") {
			without = append(without, a)
		}
	}
	if len(without) != len(allowedLines)-1 {
		t.Fatalf("want exactly one Apple Silicon exception for %s, found %d", f, len(allowedLines)-len(without))
	}
	ps, _ := checkDoc(f, install, without, archives)
	if !strings.Contains(strings.Join(ps, "\n"), "Apple Silicon") {
		t.Errorf("%s: without its exception the wrapped Apple Silicon mention is not flagged: %v", f, ps)
	}
}

// notesFile is the next release's notes; notesSentence is the one platform mention they may carry.
const (
	notesFile     = "docs/next-release-notes.md"
	notesSentence = "No macOS or Windows binaries are shipped; use the container image."
)

// checkNotes returns every reason the next release notes fail REQ-PLAT-001.
func checkNotes(text string, archives int) []string {
	_ = archives
	if !strings.Contains(strings.Join(strings.Fields(text), " "), strings.TrimSuffix(notesSentence, ".")) {
		return []string{fmt.Sprintf("%s does not say %q", notesFile, notesSentence)}
	}
	return nil
}

// proves: REQ-PLAT-001-AC1
// TestNextReleaseNotesSayLinuxOnly: the next release's notes say, exactly once, that no macOS or Windows
// binaries are shipped and point to the container image; nothing else in them names a non-Linux platform
// or claims an archive count other than the one .goreleaser.yaml produces.
func TestNextReleaseNotesSayLinuxOnly(t *testing.T) {
	for _, p := range checkNotes(read(t, notesFile), releaseArchiveCount(t)) {
		t.Error(p)
	}
}

// proves: REQ-PLAT-001-AC1
// TestNextReleaseNotesCheckRefusesMutants: a second line claiming a macOS binary, a changed or missing
// required sentence, a repeated sentence and a wrong archive count are each refused.
func TestNextReleaseNotesCheckRefusesMutants(t *testing.T) {
	notes := read(t, notesFile)
	archives := releaseArchiveCount(t)
	mutants := map[string]string{
		"second line claims macOS binaries": notes + "- macOS binaries for Apple Silicon are attached to the release.\n",
		"wrapped Windows claim":             notes + "- A signed installer for\n  Windows ships with this release.\n",
		"sentence missing":                  strings.Replace(notes, notesSentence, "Linux only.", 1),
		"sentence extended":                 strings.Replace(notes, notesSentence, strings.TrimSuffix(notesSentence, ".")+", or the macOS archive.", 1),
		"sentence repeated":                 notes + "- " + notesSentence + "\n",
		"archive count":                     notes + "- The release ships six archives.\n",
	}
	for name, text := range mutants {
		if text == notes {
			t.Fatalf("mutant %q does not change the notes", name)
		}
		ps := checkNotes(text, archives)
		if len(ps) == 0 {
			t.Errorf("mutant %q passes the release-notes check", name)
		}
		t.Logf("%s: refused: %v", name, ps)
	}
}

// proves: REQ-PLAT-001-AC1
// TestEvidenceMappingsClaimNoDarwin: test-evidence/mappings.yaml names no darwin, macOS, Mac, Apple Silicon,
// OS X or Windows platform as evidence; the only mentions allowed are the names of this package's tests.
func TestEvidenceMappingsClaimNoDarwin(t *testing.T) {
	names := regexp.MustCompile(`internal/platforms:Test[A-Za-z]+`)
	for n, line := range strings.Split(read(t, "test-evidence/mappings.yaml"), "\n") {
		if m := platformWord.FindString(names.ReplaceAllString(line, "")); m != "" {
			t.Errorf("test-evidence/mappings.yaml:%d names %q: %s", n+1, m, strings.TrimSpace(line))
		}
	}
}

// proves: REQ-PLAT-001-AC1
// TestNotScannedListIsCurrent: every path left out of the docs scan exists and holds at least one line the
// scan would flag, so the named-exceptions list cannot keep an entry that no longer needs excepting.
func TestNotScannedListIsCurrent(t *testing.T) {
	for path, why := range notScanned {
		if why == "" {
			t.Errorf("%s: no reason given", path)
		}
		flagged := false
		err := filepath.WalkDir(filepath.Join(root, path), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || flagged {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			flagged = platformWord.Match(b)
			return nil
		})
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !flagged {
			t.Errorf("%s: nothing in it names a non-Linux platform any more; remove it from notScanned", path)
		}
	}
}
