// Package platforms holds the repository checks for the release platform matrix (REQ-PLAT-001): what
// .goreleaser.yaml builds, what the public docs claim, and what the next release notes say. It has no
// non-test code; the tests read the repository files from the module root.
package platforms

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
	topKey      = regexp.MustCompile(`^([a-z_][a-z0-9_]*):(\s.*)?$`)
)

// parseBuilds reads the builds: section line by line, in the one block style the file uses. It reports, and
// never guesses at, anything it cannot read: an anchor, alias or merge key anywhere; a goos/goarch key that
// is not `goos:` alone on its line inside a build (a flow list, a quoted key, a key outside builds:); a list
// item that is not a plain lower-case word; any targets: or ignore: key; a line of builds: of another shape.
// Every top-level line must be a plain unquoted key (`name:` at column 0); a quoted, explicit (`?`) or flow
// key, a document marker or directive, a tab-indented line and a repeated top-level key are each refused,
// and there must be exactly one top-level builds section, written `builds:` alone on its line.
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
	top := map[string]bool{} // top-level keys already read
	sections := 0            // top-level builds keys
	var cur *relBuild
	listKey := "" // the key whose block list the next items belong to
	for n := 0; n < len(lines); n++ {
		line := strings.TrimRight(lines[n], " \t")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			in = line == "builds:"
			m := topKey.FindStringSubmatch(line)
			if m == nil {
				problems = append(problems, fmt.Sprintf("line %d: a top-level line of a shape this check does not read: %s", n+1, line))
				continue
			}
			if top[m[1]] {
				problems = append(problems, fmt.Sprintf("line %d: top-level key %s repeated", n+1, m[1]))
			}
			top[m[1]] = true
			if m[1] == "builds" {
				sections++
				if !in {
					problems = append(problems, fmt.Sprintf("line %d: builds key in another form: %s", n+1, line))
				}
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
	if sections != 1 {
		problems = append(problems, fmt.Sprintf("%d top-level builds sections, want exactly one", sections))
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
	archives, aproblems := releaseArchives(text, builds)
	problems = append(problems, aproblems...)
	var got []string
	for _, a := range archives {
		got = append(got, a.String())
	}
	sort.Strings(got)
	if strings.Join(got, ", ") != strings.Join(wantArchives, ", ") {
		problems = append(problems, fmt.Sprintf("the archives are [%s], want exactly the four Linux archives [%s]", strings.Join(got, ", "), strings.Join(wantArchives, ", ")))
	}
	if regexp.MustCompile(`(?i)darwin|windows|macos`).MatchString(text) {
		problems = append(problems, "names darwin, windows or macos")
	}
	return problems
}

// wantArchives are the four Linux archives REQ-PLAT-001-AC1 names, one tar.gz per build, goos and goarch.
var wantArchives = []string{"fscache linux/amd64 tar.gz", "fscache linux/arm64 tar.gz", "fscache-fips linux/amd64 tar.gz", "fscache-fips linux/arm64 tar.gz"}

// releaseArchive is one archive file a release produces.
type releaseArchive struct{ build, goos, goarch, format string }

func (a releaseArchive) String() string {
	return a.build + " " + a.goos + "/" + a.goarch + " " + a.format
}

// yamlDocs decodes every document in text with a YAML loader.
func yamlDocs(text string) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(text))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		docs = append(docs, &n)
	}
}

func keySet(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// The keys of .goreleaser.yaml the archive reader resolves. Any other key, at any of these levels, could add,
// drop or reshape an archive (nfpms, source, universal_binaries, format_overrides, wrap_in_directory, files,
// goamd64, skip, builder, extra_files, ...) and is refused by name: a new one needs this check to learn it.
var (
	releaseTopKeys     = keySet("version", "project_name", "before", "builds", "archives", "checksum", "sboms", "release", "changelog")
	releaseBuildKeys   = keySet("id", "main", "binary", "env", "goos", "goarch", "flags", "ldflags", "mod_timestamp")
	releaseArchiveKeys = keySet("id", "ids", "formats", "name_template")
	releaseChecksum    = keySet("name_template")
	releaseSBOMKeys    = keySet("artifacts")
	releaseReleaseKeys = keySet("github", "draft")
)

// yamlFields returns the entries of a mapping node by key. It refuses a node that is not a mapping, a key
// that is not a plain string (a merge key, an alias, a complex key), a repeated key and a key not allowed.
func yamlFields(n *yaml.Node, where string, allowed map[string]bool, problems *[]string) map[string]*yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		*problems = append(*problems, where+" is not a mapping")
		return map[string]*yaml.Node{}
	}
	out := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		switch {
		case k.Kind != yaml.ScalarNode || k.Tag != "!!str":
			*problems = append(*problems, fmt.Sprintf("%s: a key that is not a plain string (line %d)", where, k.Line))
		case out[k.Value] != nil:
			*problems = append(*problems, fmt.Sprintf("%s: key %q repeated", where, k.Value))
		case !allowed[k.Value]:
			*problems = append(*problems, fmt.Sprintf("%s: key %q is not one this check resolves (it may add or change release archives)", where, k.Value))
		default:
			out[k.Value] = n.Content[i+1]
		}
	}
	return out
}

// yamlString returns a plain string scalar, refusing anything else.
func yamlString(n *yaml.Node, where string, problems *[]string) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		*problems = append(*problems, where+" is missing or not a plain string")
		return ""
	}
	return n.Value
}

// yamlStrings returns a list of plain string scalars, refusing anything else.
func yamlStrings(n *yaml.Node, where string, problems *[]string) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		*problems = append(*problems, where+" is missing or not a list")
		return nil
	}
	var out []string
	for _, c := range n.Content {
		out = append(out, yamlString(c, where+" item", problems))
	}
	return out
}

// releaseArchives decodes .goreleaser.yaml with a YAML loader and lists every archive file it produces: for
// each archives entry, each build its ids name, each goos and goarch of that build, and each of its formats.
// It fails closed: it refuses, naming it, anything it does not resolve - a second YAML document; a key
// outside the ones it reads; an archive without ids (which takes every build) or without formats; a format
// other than tar.gz, or one listed twice; an archive id repeated; an id naming no build; a build in no
// archive or in two; and builds the line reader (parseBuilds) reads differently.
func releaseArchives(text string, lineBuilds []relBuild) (archives []releaseArchive, problems []string) {
	docs, err := yamlDocs(text)
	if err != nil {
		return nil, []string{"the YAML loader cannot read it: " + err.Error()}
	}
	if len(docs) != 1 || len(docs[0].Content) != 1 {
		return nil, []string{fmt.Sprintf("%d YAML documents, want exactly one", len(docs))}
	}
	top := yamlFields(docs[0].Content[0], "the top level", releaseTopKeys, &problems)

	type target struct{ goos, goarch []string }
	builds := map[string]target{}
	var order []string
	if top["builds"] == nil || top["builds"].Kind != yaml.SequenceNode {
		problems = append(problems, "builds is missing or not a list")
	} else {
		for i, b := range top["builds"].Content {
			where := fmt.Sprintf("build %d", i+1)
			f := yamlFields(b, where, releaseBuildKeys, &problems)
			id := yamlString(f["id"], where+" id", &problems)
			if _, dup := builds[id]; dup {
				problems = append(problems, fmt.Sprintf("%s: build id %q repeated", where, id))
			}
			builds[id] = target{yamlStrings(f["goos"], where+" goos", &problems), yamlStrings(f["goarch"], where+" goarch", &problems)}
			order = append(order, id)
		}
	}
	var lineIDs []string
	for _, b := range lineBuilds {
		lineIDs = append(lineIDs, b.id)
		y, ok := builds[b.id]
		if !ok || strings.Join(y.goos, ",") != strings.Join(b.goos, ",") || strings.Join(y.goarch, ",") != strings.Join(b.goarch, ",") {
			problems = append(problems, fmt.Sprintf("the YAML loader and the line reader disagree on build %q", b.id))
		}
	}
	if strings.Join(lineIDs, ",") != strings.Join(order, ",") {
		problems = append(problems, fmt.Sprintf("the YAML loader reads builds %v, the line reader %v", order, lineIDs))
	}

	archived := map[string]string{} // build id -> the archive that takes it
	ids := map[string]bool{}        // archive ids
	if top["archives"] == nil || top["archives"].Kind != yaml.SequenceNode {
		problems = append(problems, "archives is missing or not a list")
	} else {
		for i, a := range top["archives"].Content {
			where := fmt.Sprintf("archive %d", i+1)
			f := yamlFields(a, where, releaseArchiveKeys, &problems)
			id := yamlString(f["id"], where+" id", &problems)
			if ids[id] {
				problems = append(problems, fmt.Sprintf("%s: archive id %q repeated", where, id))
			}
			ids[id] = true
			yamlString(f["name_template"], where+" name_template", &problems)
			formats := yamlStrings(f["formats"], where+" formats (an archive without them takes a default)", &problems)
			if strings.Join(formats, ",") != "tar.gz" {
				problems = append(problems, fmt.Sprintf("%s (%s) formats are %q, want exactly [tar.gz]", where, id, formats))
			}
			for _, b := range yamlStrings(f["ids"], where+" ids (an archive without them takes every build)", &problems) {
				tg, ok := builds[b]
				if !ok {
					problems = append(problems, fmt.Sprintf("%s (%s) names build %q, which does not exist", where, id, b))
					continue
				}
				if prev, dup := archived[b]; dup {
					problems = append(problems, fmt.Sprintf("build %q is in two archives: %q and %q", b, prev, id))
				}
				archived[b] = id
				for _, o := range tg.goos {
					for _, arch := range tg.goarch {
						for _, format := range formats {
							archives = append(archives, releaseArchive{b, o, arch, format})
						}
					}
				}
			}
		}
	}
	for _, b := range order {
		if _, ok := archived[b]; !ok {
			problems = append(problems, fmt.Sprintf("build %q is in no archive", b))
		}
	}
	if n := top["checksum"]; n != nil {
		yamlFields(n, "checksum", releaseChecksum, &problems)
	}
	if n := top["release"]; n != nil {
		yamlFields(n, "release", releaseReleaseKeys, &problems)
	}
	if n := top["sboms"]; n != nil {
		if n.Kind != yaml.SequenceNode {
			problems = append(problems, "sboms is not a list")
		} else {
			for i, sb := range n.Content {
				where := fmt.Sprintf("sbom %d", i+1)
				f := yamlFields(sb, where, releaseSBOMKeys, &problems)
				if v := yamlString(f["artifacts"], where+" artifacts", &problems); v != "archive" {
					problems = append(problems, fmt.Sprintf("%s covers %q, want archive", where, v))
				}
			}
		}
	}
	return archives, problems
}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigBuildsOnlyLinux: .goreleaser.yaml builds exactly two builds (fscache, fscache-fips), each
// for goos [linux] and goarch [amd64, arm64], names no darwin or windows target anywhere (no `targets:`
// or `ignore:` route around goos either), and its archives definitions produce exactly the four tar.gz Linux
// archives, read by a YAML loader that refuses any key or form it does not resolve.
func TestReleaseConfigBuildsOnlyLinux(t *testing.T) {
	for _, p := range checkReleaseConfig(read(t, ".goreleaser.yaml")) {
		t.Error(".goreleaser.yaml: " + p)
	}
}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigCheckRefusesMutants: each edit of the real .goreleaser.yaml that would ship a non-Linux
// target, an extra build, architecture, archive or archive format, or a form the check cannot read is
// refused (fail closed).
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
	const stdFormats = "    formats:\n      - tar.gz\n    name_template: >-\n      {{ .ProjectName }}_{{"
	const fipsFormats = "    formats:\n      - tar.gz\n    name_template: >-\n      {{ .ProjectName }}-fips_{{"
	const fipsIDs = "    ids:\n      - fscache-fips\n"
	// Archive mutants: each could add, drop or reshape an archive file while the builds stay Linux-only.
	archiveMutants := map[string]string{
		"zip format beside tar.gz":           edit(stdFormats, "    formats:\n      - tar.gz\n      - zip\n    name_template: >-\n      {{ .ProjectName }}_{{"),
		"zip format replaces tar.gz":         edit(fipsFormats, "    formats:\n      - zip\n    name_template: >-\n      {{ .ProjectName }}-fips_{{"),
		"flow formats with zip":              edit(stdFormats, "    formats: [tar.gz, zip]\n    name_template: >-\n      {{ .ProjectName }}_{{"),
		"tar.gz listed twice":                edit(stdFormats, "    formats:\n      - tar.gz\n      - tar.gz\n    name_template: >-\n      {{ .ProjectName }}_{{"),
		"templated format":                   edit(stdFormats, "    formats:\n      - \"{{ .Env.FORMAT }}\"\n    name_template: >-\n      {{ .ProjectName }}_{{"),
		"singular format key":                edit(stdFormats, "    format: zip\n"+stdFormats),
		"no formats key":                     edit(stdFormats, "    name_template: >-\n      {{ .ProjectName }}_{{"),
		"format_overrides":                   edit(stdFormats, "    format_overrides:\n      - formats:\n          - zip\n"+stdFormats),
		"wrap_in_directory":                  edit(stdFormats, "    wrap_in_directory: true\n"+stdFormats),
		"files key":                          edit(stdFormats, "    files:\n      - LICENSE\n"+stdFormats),
		"third archive definition":           edit("\nchecksum:", "\n  - id: fscache-extra\n    ids:\n      - fscache\n    formats:\n      - tar.gz\n    name_template: extra_{{ .Os }}_{{ .Arch }}\n\nchecksum:"),
		"archive without ids":                edit(fipsIDs, ""),
		"archive id names no build":          edit(fipsIDs, "    ids:\n      - fscache-fips\n      - fscache-bsd\n"),
		"build in two archives, one in none": edit(fipsIDs, "    ids:\n      - fscache\n"),
		"repeated archive id":                edit("  - id: fscache-fips-archive\n", "  - id: fscache-archive\n"),
		"flow archive entry":                 edit("\nchecksum:", "\n  - {id: x, ids: [fscache], formats: [zip], name_template: x}\n\nchecksum:"),
		"nfpms section":                      real + "\nnfpms:\n  - id: pkg\n    formats:\n      - deb\n",
		"source archive":                     real + "\nsource:\n  enabled: true\n",
		"universal binaries":                 real + "\nuniversal_binaries:\n  - id: u\n",
		"release extra_files":                edit("  draft: true\n", "  draft: true\n  extra_files:\n    - glob: ./dist/*.zip\n"),
		"checksum extra_files":               edit("  name_template: \"checksums.txt\"\n", "  name_template: \"checksums.txt\"\n  extra_files:\n    - glob: ./dist/*.zip\n"),
		"sbom over binaries":                 edit("  - artifacts: archive\n", "  - artifacts: binary\n"),
		"goamd64 levels":                     edit(fipsGoos, fipsGoos[:len(fipsGoos)-len("    goos:\n      - linux\n")]+"    goamd64:\n      - v1\n      - v3\n    goos:\n      - linux\n"),
		"skipped build":                      edit(fipsGoos, fipsGoos+"    skip: true\n"),
		"prebuilt builder":                   edit(fipsGoos, fipsGoos+"    builder: prebuilt\n"),
	}
	for name, text := range archiveMutants {
		if _, dup := mutants[name]; dup {
			t.Fatalf("mutant %q listed twice", name)
		}
		mutants[name] = text
	}
	for name, text := range mutants {
		ps := checkReleaseConfig(text)
		if len(ps) == 0 {
			t.Errorf("mutant %q passes the release-config check", name)
		}
		t.Logf("%s: refused: %v", name, ps)
	}
}

// platformWord finds a mention of a non-Linux desktop platform. The checks match it against decoded,
// whitespace-collapsed text (a whole Markdown paragraph, a decoded YAML value), so a name wrapped across a
// line break is one match; "Apple Silicon" and "OS X" also match with the space removed.
var platformWord = regexp.MustCompile(`(?i)darwin|mac\s?os|\bmacs?\b|apple\s*silicon|\bos\s?x\b|windows`)

// markdownMarks are the inline Markdown and HTML marks the docs checks remove before reading text, so
// emphasis, code spans, links, escapes and tags cannot split a claim from its words: `**six** archives` reads
// "six archives" and `Win**dows**` reads "Windows".
var (
	htmlTag       = regexp.MustCompile(`<[^<>]*>`)
	markdownMarks = strings.NewReplacer("*", "", "_", "", "`", "", "~", "", "[", "", "]", "", "\\", "")
)

// plainText is text as a reader of the rendered Markdown sees it: tags and inline marks removed, whitespace
// collapsed to single spaces.
func plainText(s string) string {
	return strings.Join(strings.Fields(markdownMarks.Replace(htmlTag.ReplaceAllString(s, " "))), " ")
}

// countWords are the words read as a count, with their value. "a" and "an" are not counts on their own:
// before "archive" they are the indefinite article ("download an archive"); before a quantity word they are
// read through that word ("a single archive", "a dozen archives", "a couple of archives").
var countWords = map[string]int{
	"zero": 0, "single": 1, "one": 1, "both": 2, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
	"eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "dozen": 12, "thirteen": 13, "fourteen": 14,
	"fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
	"forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90, "hundred": 100,
	"thousand": 1000,
}

// vagueCounts are quantity words with no single value: an archive claim made with one cannot be checked, so
// it is refused.
var vagueCounts = keySet("couple", "few", "several", "multiple", "many", "handful", "dozens", "hundreds", "pair", "various", "numerous", "some")

// countWindow is the most words that may stand between a count and "archive" or "archives".
const countWindow = 5

// countToken splits plain text into words (a hyphen separates words, so "six-archive" is two) and boundaries:
// a sentence or clause end (. ! ? ; : before a space or the end) and a table cell bar.
var countToken = regexp.MustCompile(`[A-Za-z0-9]+(?:[./+][A-Za-z0-9]+)*|[.!?;:](?:\s|$)|\|`)

var digits = regexp.MustCompile(`^[0-9]+$`)

// archiveCountProblems returns every archive-count claim in plain text whose count is not archives. Each count
// word or number is examined on its own, so a count is read even inside a longer phrase ("one of six
// archives" is read as "six archives"). A count claims archives when "archive" or "archives" follows within
// countWindow words, with no boundary and no other count between (the nearer count binds). A count directly
// followed by "of" is partitive ("one of the archives") and is skipped; the words after it are still read. A
// compound count ("twenty-four", "one hundred") and a vague one ("several", "a couple of") cannot be resolved
// and are refused.
func archiveCountProblems(text string, archives int) (problems []string) {
	var toks []string
	for _, m := range countToken.FindAllString(text, -1) {
		toks = append(toks, strings.ToLower(strings.TrimSpace(m)))
	}
	boundary := func(w string) bool { return len(w) == 1 && strings.ContainsAny(w, ".!?;:|") }
	isCount := func(w string) bool {
		_, n := countWords[w]
		return n || vagueCounts[w] || digits.MatchString(w)
	}
	for i, w := range toks {
		if !isCount(w) || (!vagueCounts[w] && i+1 < len(toks) && toks[i+1] == "of") {
			continue
		}
		compound := false
		for j := i + 1; j < len(toks) && j <= i+1+countWindow; j++ {
			x := toks[j]
			if boundary(x) {
				break
			}
			if isCount(x) {
				if j == i+1 {
					compound = true
					continue
				}
				break
			}
			if x != "archive" && x != "archives" {
				continue
			}
			claim := strings.Join(toks[i:j+1], " ")
			n, known := countWords[w]
			if !known {
				var err error
				if n, err = strconv.Atoi(w); err != nil {
					n = -1 // digits too large for an int: still not the count
				}
			}
			switch {
			case compound:
				problems = append(problems, fmt.Sprintf("claims %q, a compound count this check does not resolve", claim))
			case vagueCounts[w]:
				problems = append(problems, fmt.Sprintf("claims %q, a count this check cannot resolve", claim))
			case n != archives:
				problems = append(problems, fmt.Sprintf("claims %q, but .goreleaser.yaml produces %d archives", claim, archives))
			}
			break
		}
	}
	return problems
}

// docsScanned are the public docs that describe what a release ships.
var docsScanned = []string{"README.md", "docs/install.md", "docs/docker-deploy.md", "RELEASING.md", "docs/verify-images.md"}

// allowedLine is a run of text in a scanned doc that names a non-Linux platform without claiming a darwin or
// windows binary exists. The text is matched exactly, with whitespace collapsed, inside one Markdown
// paragraph (or one line of a code block), so it may span a soft line break; a platform name is excused only
// if it lies wholly inside an allowed text. Each must still be present (a stale entry fails).
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
	".github/workflows/stage-acceptance-artifacts.yml": "frozen legacy stage file (legacy-stage-files.json); its archive check is rewritten by the release-chain pull requests",
}

// releaseArchiveCount is the number of archive files the real .goreleaser.yaml produces, read from its
// builds and its archives definitions. It fails the test if the config cannot be read.
func releaseArchiveCount(t *testing.T) int {
	t.Helper()
	text := read(t, ".goreleaser.yaml")
	builds, problems := parseBuilds(text)
	archives, aproblems := releaseArchives(text, builds)
	if problems = append(problems, aproblems...); len(problems) > 0 {
		t.Fatalf(".goreleaser.yaml cannot be read: %v", problems)
	}
	return len(archives)
}

// unit is a run of Markdown a reader takes as one piece of text: a paragraph (consecutive non-blank lines
// outside a code fence, so a sentence wrapped across a soft line break is one unit), or one line of a fenced
// code block. text has its whitespace collapsed to single spaces; line is its first physical line.
type unit struct {
	line int
	text string
}

func units(text string) []unit {
	var out []unit
	var para []string
	start := 0
	flush := func() {
		if len(para) > 0 {
			out = append(out, unit{start, strings.Join(strings.Fields(strings.Join(para, " ")), " ")})
			para = nil
		}
	}
	fenced := false
	for n, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		fence := strings.HasPrefix(l, "```") || strings.HasPrefix(l, "~~~")
		if fenced || fence || l == "" {
			flush()
			if l != "" {
				out = append(out, unit{n + 1, strings.Join(strings.Fields(l), " ")})
			}
			if fence {
				fenced = !fenced
			}
			continue
		}
		if len(para) == 0 {
			start = n + 1
		}
		para = append(para, l)
	}
	flush()
	return out
}

// checkDoc returns every problem in one scanned doc and the allowed texts it found: a darwin archive name;
// an archive-count claim that is not the count .goreleaser.yaml produces; a platform name that does not lie
// wholly inside one of the file's allowed texts. Counts and platform names are read in plainText, and the
// allowed texts are matched in plainText too.
func checkDoc(file, text string, allowed []allowedLine, archives int) (problems []string, seen map[string]bool) {
	seen = map[string]bool{}
	for _, u := range units(text) {
		plain := plainText(u.text)
		if strings.Contains(strings.ToLower(u.text), "_darwin_") {
			problems = append(problems, fmt.Sprintf("%s:%d names a darwin archive: %s", file, u.line, u.text))
		}
		for _, p := range archiveCountProblems(plain, archives) {
			problems = append(problems, fmt.Sprintf("%s:%d %s: %s", file, u.line, p, u.text))
		}
		var spans [][2]int
		for _, a := range allowed {
			want := plainText(a.text)
			if a.file != file || want == "" {
				continue
			}
			for off := 0; ; {
				k := strings.Index(plain[off:], want)
				if k < 0 {
					break
				}
				seen[a.text] = true
				spans = append(spans, [2]int{off + k, off + k + len(want)})
				off += k + 1
			}
		}
		for _, loc := range platformWord.FindAllStringIndex(plain, -1) {
			covered := false
			for _, sp := range spans {
				if sp[0] <= loc[0] && loc[1] <= sp[1] {
					covered = true
				}
			}
			if !covered {
				problems = append(problems, fmt.Sprintf("%s:%d names a non-Linux platform (%q) outside an allowed text: %s", file, u.line, plain[loc[0]:loc[1]], u.text))
			}
		}
	}
	return problems, seen
}

// proves: REQ-PLAT-001-AC1
// TestDocsClaimNoDarwinOrWindowsBinary: every mention of darwin, macOS, a Mac, Apple Silicon, OS X or
// Windows in the public docs, read paragraph by paragraph so a soft-wrapped name counts, lies inside one of
// the named allowed texts (none of which claims such a binary); darwin archive names are gone; every
// archive-count claim is the count .goreleaser.yaml produces; and each allowed text is still present.
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
// TestDocsCheckRefusesMutants: a platform claim wrapped across a Markdown soft line break or split by inline
// Markdown, an OS X claim, an archive count that disagrees with .goreleaser.yaml (behind Markdown, up to five
// words before "archives", after "one of", in any number word, digits, compound or vague), and a darwin
// archive name are each refused; phrases that name archives without a wrong count pass; the wrapped Apple
// Silicon mention in docs/install.md passes only through its named exception.
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
		// Round-2 regressions (both seats): inline Markdown, wider gaps, a count after "of", more number words.
		"bold six archives":            install + "\nEvery release ships **six** archives.\n",
		"italic six archives":          install + "\nEvery release ships _six_ archives.\n",
		"code-span six archives":       install + "\nEvery release ships `six` archives.\n",
		"linked six archives":          install + "\nEvery release ships [six](https://example.com/x) archives.\n",
		"html bold six archives":       install + "\nEvery release ships <b>six</b> archives.\n",
		"three words between":          install + "\nEvery release ships six signed Linux release archives.\n",
		"five words between":           install + "\nEvery release ships six signed, static, stripped Linux release archives.\n",
		"one of six archives":          install + "\nChoose one of six archives.\n",
		"one of 6 archives":            install + "\nChoose one of 6 archives.\n",
		"wrapped one of six archives":  install + "\nChoose one of\nsix archives.\n",
		"thirteen archives":            install + "\nEvery release ships thirteen archives.\n",
		"twenty archives":              install + "\nEvery release ships twenty archives.\n",
		"a single archive":             install + "\nEvery release is a single archive.\n",
		"one archive per platform":     install + "\nThere is one archive per platform.\n",
		"both archives":                install + "\nDownload both archives.\n",
		"a dozen archives":             install + "\nEvery release ships a dozen archives.\n",
		"zero archives":                install + "\nThe release has zero archives.\n",
		"twenty-four archives":         install + "\nEvery release ships twenty-four archives.\n",
		"one hundred archives":         install + "\nEvery release ships one hundred archives.\n",
		"a couple of archives":         install + "\nEvery release ships a couple of archives.\n",
		"several archives":             install + "\nEvery release ships several archives.\n",
		"hyphenated six-archive":       install + "\nThis is a six-archive release.\n",
		"bold wrapped Windows":         install + "\nNative binaries for Win**dows** are attached.\n",
		"bold Apple Silicon, no space": install + "\nNative binaries for Apple**Silicon** are attached.\n",
	}
	for name, text := range mutants {
		ps, _ := checkDoc(f, text, allowedLines, archives)
		if len(ps) == 0 {
			t.Errorf("mutant %q passes the docs check", name)
		}
		t.Logf("%s: refused: %v", name, ps)
	}
	// Precision: these name archives without claiming a count other than the one .goreleaser.yaml produces.
	for _, ok := range []string{
		"One of the archives is the FIPS build.",
		"One of the four archives is the FIPS build; two of the four archives are arm64.",
		"Download an archive for your machine, then verify the archive.",
		"There is no archive for this machine.",
		"All **four** Linux archives are signed.",
		"Every release ships a `checksums.txt` covering all four Linux archives.",
	} {
		if ps, _ := checkDoc(f, install+"\n"+ok+"\n", allowedLines, archives); len(ps) > 0 {
			t.Errorf("%q is refused: %v", ok, ps)
		}
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

// checkNotes returns every reason the next release notes fail REQ-PLAT-001. The whole file is checked as a
// scanned doc whose only allowed text is notesSentence, matched exactly; the sentence must appear exactly once.
func checkNotes(text string, archives int) []string {
	problems, _ := checkDoc(notesFile, text, []allowedLine{{notesFile, notesSentence, "the REQ-PLAT-001 release-notes line", false}}, archives)
	count := 0
	for _, u := range units(text) {
		count += strings.Count(plainText(u.text), notesSentence)
	}
	if count != 1 {
		problems = append(problems, fmt.Sprintf("%s says %q %d times, want exactly once", notesFile, notesSentence, count))
	}
	return problems
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
		"bold archive count":                notes + "- The release ships **six** archives.\n",
		"count after one of":                notes + "- Pick one of six archives.\n",
		"sentence repeated with emphasis":   notes + "- No **macOS** or Windows binaries are shipped; use the container image.\n",
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

// mappingsFile is the AC-to-evidence mappings file.
const mappingsFile = "test-evidence/mappings.yaml"

// testFunc finds a top-level test function declaration in a Go test file.
var testFunc = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{`)

// packageTests returns the names of the test functions declared in this package's test files.
func packageTests(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	tests := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range testFunc.FindAllStringSubmatch(string(b), -1) {
			tests[m[1]] = true
		}
	}
	return tests
}

// platformsTestRef is an exact go-test reference to a test of this package.
var platformsTestRef = regexp.MustCompile(`^internal/platforms:(Test[A-Za-z0-9_]+)$`)

// checkEvidenceMappings returns every platform name in the evidence mappings outside an exact reference to
// one of this package's tests. The file is read twice and both readings must be clean: decoded by a YAML
// loader (every document; every key, value, anchor, tag and comment, in plainText, so a quoted, escaped,
// folded or wrapped scalar is read as the text it means), and as raw text in plainText (so nothing the
// loader drops escapes). The one exception is the whole value of `ref` in an evidence item whose `type` is
// `go-test`, when that value is exactly internal/platforms:<name> and tests holds name.
func checkEvidenceMappings(text string, tests map[string]bool) (problems []string) {
	scan := func(where, s string) {
		s = plainText(s)
		for _, loc := range platformWord.FindAllStringIndex(s, -1) {
			from, to := max(0, loc[0]-60), min(len(s), loc[1]+60)
			problems = append(problems, fmt.Sprintf("%s names %q: ...%s...", where, s[loc[0]:loc[1]], s[from:to]))
		}
	}
	docs, err := yamlDocs(text)
	if err != nil {
		return []string{mappingsFile + ": the YAML loader cannot read it: " + err.Error()}
	}
	exempt := map[string]bool{} // the exact references excepted
	var walk func(n *yaml.Node, skip bool)
	walk = func(n *yaml.Node, skip bool) {
		where := fmt.Sprintf("%s:%d", mappingsFile, n.Line)
		scan(where, n.HeadComment+" \n "+n.LineComment+" \n "+n.FootComment+" \n "+n.Anchor+" \n "+n.Tag)
		if !skip {
			scan(where, n.Value)
		}
		goTest := false
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "type" && n.Content[i+1].Kind == yaml.ScalarNode && n.Content[i+1].Value == "go-test" {
					goTest = true
				}
			}
		}
		for i, c := range n.Content {
			ok := false
			if goTest && i%2 == 1 && n.Content[i-1].Value == "ref" && c.Kind == yaml.ScalarNode {
				if m := platformsTestRef.FindStringSubmatch(c.Value); m != nil && tests[m[1]] {
					ok = true
					exempt[c.Value] = true
				}
			}
			walk(c, ok)
		}
	}
	for _, d := range docs {
		walk(d, false)
	}
	raw := text
	for ref := range exempt {
		raw = strings.ReplaceAll(raw, ref, " ")
	}
	scan(mappingsFile+" (raw text)", raw)
	return problems
}

// proves: REQ-PLAT-001-AC1
// TestEvidenceMappingsClaimNoDarwin: test-evidence/mappings.yaml names no darwin, macOS, Mac, Apple Silicon,
// OS X or Windows platform as evidence; the only mentions allowed are exact go-test references to this
// package's existing tests.
func TestEvidenceMappingsClaimNoDarwin(t *testing.T) {
	tests := packageTests(t)
	for _, name := range []string{"TestDocsClaimNoDarwinOrWindowsBinary", "TestEvidenceMappingsClaimNoDarwin"} {
		if !tests[name] {
			t.Fatalf("the test-function scan does not find %s in this package", name)
		}
	}
	for _, p := range checkEvidenceMappings(read(t, mappingsFile), tests) {
		t.Error(p)
	}
}

// proves: REQ-PLAT-001-AC1
// TestEvidenceMappingsCheckRefusesMutants: a platform name in the evidence mappings is refused wherever it
// is, once the YAML is decoded: in a fabricated or misplaced test reference, in prose, in a quoted, escaped
// or folded scalar that wraps the name across lines, in a comment, and in a second document.
func TestEvidenceMappingsCheckRefusesMutants(t *testing.T) {
	real := read(t, mappingsFile)
	tests := packageTests(t)
	const lastRef = "      - { type: go-test, ref: \"internal/platforms:TestEvidenceMappingsClaimNoDarwin\" }\n"
	const plat2 = "so a missing variant/arch fails\" }\n"
	edit := func(old, new string) string {
		if strings.Count(real, old) != 1 {
			t.Fatalf("mutant anchor not found exactly once: %q", old)
		}
		return strings.Replace(real, old, new, 1)
	}
	mutants := []struct{ name, text, want string }{
		{"fabricated go-test name", edit(lastRef, lastRef+"      - { type: go-test, ref: \"internal/platforms:TestDarwin\" }\n"), "Darwin"},
		{"fabricated name in prose", edit(plat2, "so a missing variant/arch fails (internal/platforms:TestDarwinBinariesRun)\" }\n"), "Darwin"},
		{"real name in prose", edit(plat2, "so a missing variant/arch fails; see internal/platforms:TestDocsClaimNoDarwinOrWindowsBinary\" }\n"), "Darwin"},
		{"real name under another type", edit(lastRef, lastRef+"      - { type: shell-test, ref: \"internal/platforms:TestDocsClaimNoDarwinOrWindowsBinary\" }\n"), "Darwin"},
		{"real name in another package", edit(lastRef, lastRef+"      - { type: go-test, ref: \"internal/server:TestDocsClaimNoDarwinOrWindowsBinary\" }\n"), "Darwin"},
		{"real name with a suffix", edit(lastRef, lastRef+"      - { type: go-test, ref: \"internal/platforms:TestDocsClaimNoDarwinOrWindowsBinary on macOS\" }\n"), "macOS"},
		{"double-quoted scalar wraps Apple Silicon", edit(plat2, "so a missing variant/arch fails; Apple\n        Silicon is the documented equivalent\" }\n"), "Apple"},
		{"escaped line break joins Apple Silicon", edit(plat2, "so a missing variant/arch fails; Apple\\\n        Silicon is the documented equivalent\" }\n"), "Apple"},
		{"escape sequence spells macOS", edit(plat2, "so a missing variant/arch fails; \\x6dacOS is the documented equivalent\" }\n"), "macOS"},
		{"single-quoted scalar wraps OS X", edit(lastRef, lastRef+"      - { type: inspection, ref: 'runs on OS\n          X hosts' }\n"), "OS X"},
		{"folded block scalar wraps Mac OS", edit(lastRef, lastRef+"      - type: inspection\n        ref: >-\n          runs on Mac\n          OS hosts\n"), "Mac OS"},
		{"comment names Windows", edit(lastRef, lastRef+"      # Windows is a documented equivalent\n"), "Windows"},
		{"second document", real + "---\nnote: darwin is a documented equivalent\n", "darwin"},
	}
	for _, m := range mutants {
		ps := checkEvidenceMappings(m.text, tests)
		if !strings.Contains(strings.ToLower(strings.Join(ps, "\n")), strings.ToLower(m.want)) {
			t.Errorf("mutant %q: the check does not name %q: %v", m.name, m.want, ps)
		}
		t.Logf("%s: refused: %v", m.name, ps)
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
