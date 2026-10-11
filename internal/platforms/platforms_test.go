// Package platforms holds the repository checks for the release platform matrix (REQ-PLAT-001): what
// .goreleaser.yaml builds, what the public docs claim, and what the next release notes say. It has no
// non-test code; the tests read the repository files from the module root.
package platforms

import (
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

// goosLists returns each `goos:` list of .goreleaser.yaml as written in block style (`goos:` alone on its
// line, then `- item` lines). Any other form of the key (a flow list, an inline scalar) is returned as a
// problem: the check refuses what it cannot read rather than passing it.
func goosLists(text string) (lists [][]string, problems []string) {
	lines := strings.Split(text, "\n")
	key := regexp.MustCompile(`^(\s*)goos\s*:(.*)$`)
	item := regexp.MustCompile(`^\s*-\s*(\S+)\s*$`)
	for i := 0; i < len(lines); i++ {
		m := key.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		if rest := strings.TrimSpace(m[2]); rest != "" && !strings.HasPrefix(rest, "#") {
			problems = append(problems, "goos is not a block list: "+strings.TrimSpace(lines[i]))
			continue
		}
		var l []string
		for i+1 < len(lines) {
			im := item.FindStringSubmatch(lines[i+1])
			if im == nil {
				break
			}
			l = append(l, strings.Trim(im[1], `"'`))
			i++
		}
		lists = append(lists, l)
	}
	return lists, problems
}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigBuildsOnlyLinux: .goreleaser.yaml builds exactly two builds (fscache, fscache-fips), each
// for goos linux only, and names no darwin or windows target anywhere (no `targets:` or `ignore:` route
// around goos either).
func TestReleaseConfigBuildsOnlyLinux(t *testing.T) {
	text := read(t, ".goreleaser.yaml")
	lists, problems := goosLists(text)
	for _, p := range problems {
		t.Error(p)
	}
	if len(lists) != 2 {
		t.Fatalf(".goreleaser.yaml has %d goos lists, want 2 (fscache and fscache-fips)", len(lists))
	}
	for i, l := range lists {
		if len(l) != 1 || l[0] != "linux" {
			t.Errorf("goos list %d is %v, want exactly [linux]", i+1, l)
		}
	}
	for _, id := range []string{"id: fscache\n", "id: fscache-fips\n"} {
		if !strings.Contains(text, id) {
			t.Errorf(".goreleaser.yaml has no build %q", strings.TrimSpace(id))
		}
	}
	if regexp.MustCompile(`(?i)darwin|windows|macos`).MatchString(text) {
		t.Error(".goreleaser.yaml names darwin, windows or macos")
	}
	if regexp.MustCompile(`(?m)^\s*(targets|ignore)\s*:`).MatchString(text) {
		t.Error(".goreleaser.yaml has a targets: or ignore: key, a second way to choose platforms")
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

// notScanned are files outside docsScanned that mention a non-Linux platform on purpose; they are not
// claims about what a release ships.
var notScanned = map[string]string{
	"docs/gradle.md":                                   "line 136 records the historical test environment (Gradle on a macOS arm64 host), marked pinned: historical",
	"internal/storesample/":                            "build tags that let the package compile on a developer's macOS host; not a release target",
	"internal/blobstore/":                              "comments on darwin ReadDir behaviour seen on developer hosts",
	"bench/gradle-sample/gradlew":                      "vendored Gradle wrapper script",
	"the auditor tooling":                              "its runner and developer-host logic names Windows and macOS runners it refuses or works around",
	"bin/build-helpers-test.sh":                        "a captured `go version -m` fixture from a developer host",
	"docs/quality/traceability.md":                     "generated from requirements.yaml",
	"requirements/":                                    "the requirement text and frozen v0.2.x baselines",
	"docs/next-release-notes.md":                       "carries the REQ-PLAT-001 release-notes line (checked by TestNextReleaseNotesSayLinuxOnly)",
	".github/workflows/stage-acceptance-artifacts.yml": "frozen legacy stage file (legacy-stage-files.json); its archive check is rewritten by the release-chain pull requests",
}

// proves: REQ-PLAT-001-AC1
// TestDocsClaimNoDarwinOrWindowsBinary: every line of the public docs that names darwin, macOS, a Mac,
// Apple Silicon, OS X or Windows is one of the named allowed lines (none of which claims such a binary);
// darwin archive names are gone, and each allowed line is still present.
func TestDocsClaimNoDarwinOrWindowsBinary(t *testing.T) {
	allowed := map[string]map[string]bool{}
	optional := map[string]bool{}
	for _, a := range allowedLines {
		if allowed[a.file] == nil {
			allowed[a.file] = map[string]bool{}
		}
		allowed[a.file][a.text] = true
		if a.optional {
			optional[a.file+"\x00"+a.text] = true
		}
	}
	for _, f := range docsScanned {
		if _, skip := notScanned[f]; skip {
			t.Fatalf("%s is both scanned and listed as not scanned", f)
		}
		text := read(t, f)
		seen := map[string]bool{}
		for n, line := range strings.Split(text, "\n") {
			l := strings.TrimSpace(line)
			if strings.Contains(strings.ToLower(l), "_darwin_") {
				t.Errorf("%s:%d names a darwin archive: %s", f, n+1, l)
			}
			if !platformWord.MatchString(l) {
				continue
			}
			if allowed[f][l] {
				seen[l] = true
				continue
			}
			t.Errorf("%s:%d names a non-Linux platform and is not an allowed line: %s", f, n+1, l)
		}
		for l := range allowed[f] {
			if !seen[l] && !optional[f+"\x00"+l] {
				t.Errorf("%s: allowed line no longer present (remove it from allowedLines): %s", f, l)
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
// TestNextReleaseNotesSayLinuxOnly: the next release's notes say that no macOS or Windows binaries are
// shipped and point to the container image.
func TestNextReleaseNotesSayLinuxOnly(t *testing.T) {
	const want = "No macOS or Windows binaries are shipped; use the container image"
	text := strings.Join(strings.Fields(read(t, "docs/next-release-notes.md")), " ")
	if !strings.Contains(text, want) {
		t.Errorf("docs/next-release-notes.md does not say %q", want)
	}
}
