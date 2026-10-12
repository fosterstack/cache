// Package platforms holds the repository checks for the release platform matrix (REQ-PLAT-001): what
// .goreleaser.yaml builds, what the public docs claim, and what the next release notes say. It has no
// non-test code; the tests read the repository files from the module root.
package platforms

import (
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// root is the module root, two directories up from internal/platforms.
const root = "../.."

// readOptional is the file's text, or "" when it does not exist.
func readOptional(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

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
	var names []string
	for _, a := range archives {
		names = append(names, a.name)
	}
	sort.Strings(names)
	if strings.Join(names, ", ") != strings.Join(wantArchiveNames, ", ") {
		problems = append(problems, fmt.Sprintf("the archive files are named [%s], want exactly [%s]", strings.Join(names, ", "), strings.Join(wantArchiveNames, ", ")))
	}
	if regexp.MustCompile(`(?i)darwin|windows|macos`).MatchString(text) {
		problems = append(problems, "names darwin, windows or macos")
	}
	return problems
}

// wantArchives are the four Linux archives REQ-PLAT-001-AC1 names, one tar.gz per build, goos and goarch.
var wantArchives = []string{"fscache linux/amd64 tar.gz", "fscache linux/arm64 tar.gz", "fscache-fips linux/amd64 tar.gz", "fscache-fips linux/arm64 tar.gz"}

// archiveDefs are the two archive definitions of the committed .goreleaser.yaml, pinned exactly: each takes
// exactly its one build (by ids) and names its files with exactly its template. An archive definition with
// another id, empty ids (GoReleaser then takes every build), more than one build (GoReleaser then groups the
// builds' binaries into one archive per platform), or another name template is refused, not modelled: a
// change to the archive set changes this table in a reviewed pull request.
var archiveDefs = []struct{ id, build, template string }{
	{"fscache-archive", "fscache", "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"},
	{"fscache-fips-archive", "fscache-fips", "{{ .ProjectName }}-fips_{{ .Version }}_{{ .Os }}_{{ .Arch }}"},
}

// archiveFormatExt is the file extension GoReleaser gives the one archive format the check accepts.
const archiveFormatExt = ".tar.gz"

// templateVar is one template expression of the form the archive templates use: {{ .Name }}.
var templateVar = regexp.MustCompile(`\{\{\s*\.([A-Za-z]+)\s*\}\}`)

// renderArchiveName renders an archive name template for one platform, with the release version written
// <version>. It resolves only {{ .ProjectName }}, {{ .Version }}, {{ .Os }} and {{ .Arch }}; any other
// expression, or a brace left over, is refused.
func renderArchiveName(tmpl, project, goos, goarch string) (string, error) {
	vars := map[string]string{"ProjectName": project, "Version": "<version>", "Os": goos, "Arch": goarch}
	var bad []string
	out := templateVar.ReplaceAllStringFunc(tmpl, func(m string) string {
		v, ok := vars[templateVar.FindStringSubmatch(m)[1]]
		if !ok {
			bad = append(bad, m)
		}
		return v
	})
	if len(bad) > 0 || strings.ContainsAny(out, "{}") {
		return "", fmt.Errorf("name template %q has an expression this check does not resolve", tmpl)
	}
	return out + archiveFormatExt, nil
}

// releaseArchive is one archive file a release produces.
type releaseArchive struct{ build, goos, goarch, format, name string }

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

// yamlTagProblems is the YAML tag scan. It reads the raw text, before anything is decoded and without any decoder
// flag, and refuses, naming file and line: every "!" anywhere in the text (every tag token, "!", "!!x", "!x",
// "!<...>", is one; the scan does not parse YAML's quoting, comments or flow context to tell a tag token from text,
// and the files it reads hold no "!" at all, so any "!" is refused), and every YAML directive (a line starting "%",
// a byte order mark before it ignored: a %TAG directive can remap a tag).
func yamlTagProblems(file, text string) (problems []string) {
	for n, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimPrefix(line, "\ufeff"), "%") {
			problems = append(problems, fmt.Sprintf("%s:%d: a YAML directive refused (a %%TAG directive can remap a tag): %s", file, n+1, line))
		}
		if strings.Contains(line, "!") {
			problems = append(problems, fmt.Sprintf("%s:%d: explicit YAML tag refused: a \"!\" anywhere in the raw text (a tag token, or text the scan does not tell from one) is refused before decoding: %s", file, n+1, strings.TrimSpace(line)))
		}
	}
	return problems
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

// pinnedBuilds are the committed configuration's values of the admitted build fields the archive model does not
// resolve, by build id. Each is compared exactly, by its decoded value: a missing field, another value, another type
// and a template are refused (the one template admitted, mod_timestamp's, is the pinned value itself). These fields
// can change what is built and where: the linker writes files (-memprofile), an ellipsis main renames the binary,
// GOFLAGS or a flag redirects the output, CGO changes the binary. A change to them changes this table in a reviewed
// pull request.
var pinnedBuilds = map[string]map[string]any{
	"fscache": {
		"main": "./cmd/fscache", "binary": "fscache", "env": []any{"CGO_ENABLED=0"},
		"flags": []any{"-trimpath"}, "ldflags": []any{"-s -w"}, "mod_timestamp": "{{ .CommitTimestamp }}",
	},
	"fscache-fips": {
		"main": "./cmd/fscache", "binary": "fscache-fips", "env": []any{"CGO_ENABLED=0", "GOFIPS140=v1.0.0"},
		"flags": []any{"-trimpath"}, "ldflags": []any{"-s -w"}, "mod_timestamp": "{{ .CommitTimestamp }}",
	},
}

// pinnedTop are the committed configuration's values of the admitted top-level sections the archive model does not
// resolve, compared exactly by decoded value (missing, another value or another type is refused): the config
// version, the project name, the hooks GoReleaser runs before building (a hook can write anything), the release
// target, the changelog and the archive SBOMs (exactly one definition, artifacts: archive: a missing, empty or other
// section would drop or change the per-archive SBOMs the release promotes).
var pinnedTop = map[string]any{
	"version":      2,
	"project_name": "fscache",
	"before":       map[string]any{"hooks": []any{"go mod verify", "git diff --exit-code go.mod go.sum"}},
	"release":      map[string]any{"github": map[string]any{"owner": "fosterstack", "name": "cache"}, "draft": true},
	"changelog":    map[string]any{"sort": "asc", "filters": map[string]any{"exclude": []any{"^docs:", "^test:", "^ci:"}}},
	"sboms":        []any{map[string]any{"artifacts": "archive"}},
}

// pinnedValue refuses a node that is missing, cannot be decoded, or decodes to anything but want.
func pinnedValue(n *yaml.Node, where string, want any, problems *[]string) {
	var got any
	if n == nil {
		*problems = append(*problems, fmt.Sprintf("%s is missing, want exactly %v", where, want))
		return
	}
	if err := n.Decode(&got); err != nil || !reflect.DeepEqual(got, want) {
		*problems = append(*problems, fmt.Sprintf("%s is %v, want exactly the pinned %v", where, got, want))
	}
}

// pinnedFields applies pinnedValue to every key of pins, in key order.
func pinnedFields(f map[string]*yaml.Node, where string, pins map[string]any, problems *[]string) {
	keys := make([]string, 0, len(pins))
	for k := range pins {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pinnedValue(f[k], where+" "+k, pins[k], problems)
	}
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
// each of the two archive definitions (archiveDefs), each goos and goarch of its one build, one tar.gz file
// named by its template. It fails closed: it refuses, naming it, anything it does not resolve - a second YAML
// document; a key outside the ones it reads; a project_name that is missing or not a plain string; an archive
// count other than two; an archive id not in archiveDefs, or repeated; ids that are not exactly the archive's
// one build (missing, empty, grouped, or naming no build); formats that are not exactly [tar.gz]; a name
// template that is not exactly the pinned one, or that does not render; two archive files with one name; a
// build in no archive or in two; builds the line reader (parseBuilds) reads differently; a checksum section
// that is missing or not exactly name_template "checksums.txt"; and two release files (archives, the checksum,
// the archive SBOMs, GoReleaser's own record files) with one name.
func releaseArchives(text string, lineBuilds []relBuild) (archives []releaseArchive, problems []string) {
	archives, _, problems = releaseOutputs(text, lineBuilds)
	return archives, problems
}

// plainBinary is a binary name the check resolves: a plain file name, no path separator, no template, not "." or
// "..". GoReleaser writes each build's binary to dist/<id>_<os>_<arch>_<level>/<binary>; a name that is a path
// could leave that directory (../<an archive's name>) and collide with another release file.
var plainBinary = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// archLevel is GoReleaser's default architecture level in a build directory name (GOAMD64 v1, GOARM64 v8.0); the
// builds are pinned to amd64 and arm64 and goamd64/goarm64 keys are refused.
var archLevel = map[string]string{"amd64": "v1", "arm64": "v8.0"}

// releaseOutputs is releaseArchives with the map of every release output it resolved (path under dist/ -> what
// writes it): the archives, the checksum file, the archive SBOMs, GoReleaser's own record files and each build's
// binary at dist/<id>_<os>_<arch>_<level>/<binary>. A build without a binary name, or with one plainBinary refuses,
// is refused, and no two outputs may share a path.
func releaseOutputs(text string, lineBuilds []relBuild) (archives []releaseArchive, outputs map[string]string, problems []string) {
	problems = yamlTagProblems(".goreleaser.yaml", text)
	docs, err := yamlDocs(text)
	if err != nil {
		return nil, nil, append(problems, "the YAML loader cannot read it: "+err.Error())
	}
	if len(docs) != 1 || len(docs[0].Content) != 1 {
		return nil, nil, append(problems, fmt.Sprintf("%d YAML documents, want exactly one", len(docs)))
	}
	top := yamlFields(docs[0].Content[0], "the top level", releaseTopKeys, &problems)
	project := yamlString(top["project_name"], "project_name (without it GoReleaser takes a default)", &problems)
	pinnedFields(top, "the top-level", pinnedTop, &problems)

	type target struct {
		goos, goarch []string
		binary       string
	}
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
			if pins, ok := pinnedBuilds[id]; ok {
				pinnedFields(f, where+" ("+id+")", pins, &problems)
			} else {
				problems = append(problems, fmt.Sprintf("%s: build id %q has no pinned field values", where, id))
			}
			bin := yamlString(f["binary"], where+" binary (without it GoReleaser names the binary after the project)", &problems)
			if !plainBinary.MatchString(bin) || bin == "." || bin == ".." {
				problems = append(problems, fmt.Sprintf("%s binary %q is not a plain file name (no path separator, template, \".\" or \"..\"): this check does not resolve where it is written", where, bin))
			}
			builds[id] = target{yamlStrings(f["goos"], where+" goos", &problems), yamlStrings(f["goarch"], where+" goarch", &problems), bin}
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
		if n := len(top["archives"].Content); n != len(archiveDefs) {
			problems = append(problems, fmt.Sprintf("%d archive definitions, want exactly %d (one per build)", n, len(archiveDefs)))
		}
		names := map[string]string{} // archive file name -> the archive that makes it
		for i, a := range top["archives"].Content {
			where := fmt.Sprintf("archive %d", i+1)
			f := yamlFields(a, where, releaseArchiveKeys, &problems)
			id := yamlString(f["id"], where+" id", &problems)
			if ids[id] {
				problems = append(problems, fmt.Sprintf("%s: archive id %q repeated", where, id))
			}
			ids[id] = true
			def := -1
			for k, d := range archiveDefs {
				if d.id == id {
					def = k
				}
			}
			if def < 0 {
				problems = append(problems, fmt.Sprintf("%s: archive id %q is not one of the pinned archive definitions", where, id))
				continue
			}
			want := archiveDefs[def]
			tmpl := yamlString(f["name_template"], where+" name_template", &problems)
			if tmpl != want.template {
				problems = append(problems, fmt.Sprintf("%s (%s) name_template is %q, want exactly %q", where, id, tmpl, want.template))
			}
			formats := yamlStrings(f["formats"], where+" formats (an archive without them takes a default)", &problems)
			if strings.Join(formats, ",") != "tar.gz" {
				problems = append(problems, fmt.Sprintf("%s (%s) formats are %q, want exactly [tar.gz]", where, id, formats))
			}
			sel := yamlStrings(f["ids"], where+" ids (an archive without them takes every build)", &problems)
			if len(sel) != 1 || sel[0] != want.build {
				problems = append(problems, fmt.Sprintf("%s (%s) ids are %q, want exactly [%s] (empty ids take every build; several are grouped into one archive per platform)", where, id, sel, want.build))
				continue
			}
			tg, ok := builds[want.build]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s (%s) names build %q, which does not exist", where, id, want.build))
				continue
			}
			if prev, dup := archived[want.build]; dup {
				problems = append(problems, fmt.Sprintf("build %q is in two archives: %q and %q", want.build, prev, id))
			}
			archived[want.build] = id
			for _, o := range tg.goos {
				for _, arch := range tg.goarch {
					name, err := renderArchiveName(tmpl, project, o, arch)
					if err != nil {
						problems = append(problems, fmt.Sprintf("%s (%s): %v", where, id, err))
						continue
					}
					if prev, dup := names[name]; dup {
						problems = append(problems, fmt.Sprintf("archive file %s is made by both %q and %q", name, prev, id))
					}
					names[name] = id
					archives = append(archives, releaseArchive{want.build, o, arch, "tar.gz", name})
				}
			}
		}
	}
	for _, b := range order {
		if _, ok := archived[b]; !ok {
			problems = append(problems, fmt.Sprintf("build %q is in no archive", b))
		}
	}
	// Every other file the release writes into dist/ is resolved too, and no two may share a name: GoReleaser
	// writes the checksum file after the archives and opens it with O_TRUNC, so a checksum named like an archive
	// replaces it. The checksum name is pinned (a missing section takes a templated default), each SBOM is named
	// GoReleaser's default for an archive SBOM, and GoReleaser's own record files are reserved.
	outputs = map[string]string{}
	for _, f := range goreleaserRecordFiles {
		outputs[f] = "GoReleaser's own record"
	}
	addOutput := func(name, what string) {
		if prev, dup := outputs[name]; dup {
			problems = append(problems, fmt.Sprintf("release file %s is written by both %s and %s", name, prev, what))
		}
		outputs[name] = what
	}
	for _, a := range archives {
		addOutput(a.name, "archive "+a.String())
	}
	for _, id := range order {
		b := builds[id]
		for _, o := range b.goos {
			for _, arch := range b.goarch {
				level, ok := archLevel[arch]
				if !ok {
					problems = append(problems, fmt.Sprintf("build %q: goarch %q has no build directory this check resolves", id, arch))
					continue
				}
				dir := id + "_" + o + "_" + arch + "_" + level
				addOutput(dir, "the build directory of "+id+" "+o+"/"+arch)
				addOutput(dir+"/"+b.binary, "the binary of "+id+" "+o+"/"+arch)
			}
		}
	}
	if n := top["checksum"]; n == nil {
		problems = append(problems, fmt.Sprintf("checksum is missing (GoReleaser then names the file from a template), want name_template exactly %q", checksumName))
	} else {
		f := yamlFields(n, "checksum", releaseChecksum, &problems)
		name := yamlString(f["name_template"], "checksum name_template", &problems)
		if name != checksumName {
			problems = append(problems, fmt.Sprintf("checksum name_template is %q, want exactly %q", name, checksumName))
		}
		addOutput(name, "the checksum")
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
					continue
				}
				for _, a := range archives {
					addOutput(a.name+sbomSuffix, where+" of "+a.name)
				}
			}
		}
	}
	return archives, outputs, problems
}

// checksumName is the checksum file name of the committed .goreleaser.yaml, pinned: it is a literal (no
// template), and it is the name RELEASING.md, docs/install.md and docs/verify-images.md tell users to verify.
const checksumName = "checksums.txt"

// sbomSuffix is GoReleaser's default SBOM document name for an archive, {{ .ArtifactName }}.sbom.json; an
// sbom with any other key (documents, cmd, args, ...) is refused by releaseSBOMKeys.
const sbomSuffix = ".sbom.json"

// goreleaserRecordFiles are the files GoReleaser itself writes into dist/; a release file may not take
// their names.
var goreleaserRecordFiles = []string{"artifacts.json", "metadata.json", "config.yaml"}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigBuildsOnlyLinux: .goreleaser.yaml builds exactly two builds (fscache, fscache-fips), each
// for goos [linux] and goarch [amd64, arm64], names no darwin or windows target anywhere (no `targets:`
// or `ignore:` route around goos either), and its two pinned archive definitions produce exactly the four
// tar.gz Linux archives named wantArchiveNames, read by a YAML loader that refuses any key or form it does
// not resolve.
func TestReleaseConfigBuildsOnlyLinux(t *testing.T) {
	text := read(t, ".goreleaser.yaml")
	for _, p := range checkReleaseConfig(text) {
		t.Error(".goreleaser.yaml: " + p)
	}
	builds, _ := parseBuilds(text)
	archives, _ := releaseArchives(text, builds)
	var names []string
	for _, a := range archives {
		names = append(names, a.name)
	}
	sort.Strings(names)
	if strings.Join(names, ", ") != strings.Join(wantArchiveNames, ", ") {
		t.Errorf(".goreleaser.yaml renders the archive names [%s], want exactly [%s]", strings.Join(names, ", "), strings.Join(wantArchiveNames, ", "))
	}
}

// wantArchiveNames are the four archive files the committed .goreleaser.yaml renders, as docs/install.md
// lists them (fscache_X.Y.Z_linux_amd64.tar.gz, ...), with the release version written <version>: the
// standard template "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}" and the FIPS template
// "{{ .ProjectName }}-fips_{{ .Version }}_{{ .Os }}_{{ .Arch }}", project_name fscache, goos linux, goarch
// amd64 and arm64, and GoReleaser's .tar.gz extension for the tar.gz format.
var wantArchiveNames = []string{
	"fscache-fips_<version>_linux_amd64.tar.gz",
	"fscache-fips_<version>_linux_arm64.tar.gz",
	"fscache_<version>_linux_amd64.tar.gz",
	"fscache_<version>_linux_arm64.tar.gz",
}

// proves: REQ-PLAT-001-AC1
// TestReleaseConfigCheckRefusesMutants: each edit of the real .goreleaser.yaml that would ship a non-Linux
// target, an extra build, architecture, archive or archive format, an archive definition with empty or
// grouped ids, an archive file name other than the pinned four (template, project name, collision), a
// checksum file name other than the pinned literal (one that would overwrite an archive, a template, a missing
// section), two release files with one name (a second SBOM definition), a binary name that is not a plain file
// name (a path out of its build directory onto an archive's path, a separator, a template, missing), any admitted
// field whose value is not the committed configuration's pinned literal (main, env, flags, ldflags, mod_timestamp,
// binary, the hooks, release, changelog, version: a linker profile, an ellipsis main, an output redirect, a hook
// writing into dist/, a template), any "!" in the raw text (every explicit YAML tag, a bare "!" and one decoding to the
// pinned value included, and a "!" in a quoted scalar or a comment: the raw scan runs before decoding and does not tell
// them apart), a YAML directive, or a form the check cannot read is refused (fail closed); the real configuration's
// binary output paths are resolved.
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
	const stdLdflags = "    ldflags:\n      - -s -w\n    mod_timestamp: \"{{ .CommitTimestamp }}\"\n\n  # GOFIPS140"
	const fipsTail = "    flags:\n      - -trimpath\n    ldflags:\n      - -s -w\n    mod_timestamp: \"{{ .CommitTimestamp }}\"\n\narchives:"
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
		// Round-3 regressions (both seats): empty or grouped ids, and the archive file names.
		"third archive with empty ids": edit("\nchecksum:", "\n  - id: fscache-all\n    ids: []\n    formats:\n      - tar.gz\n    name_template: all_{{ .Os }}_{{ .Arch }}\n\nchecksum:"),
		"fips archive with empty ids":  edit(fipsIDs, "    ids: []\n"),
		"both builds in one archive":   edit("    ids:\n      - fscache\n", "    ids:\n      - fscache\n      - fscache-fips\n"),
		"one grouped archive only":     edit(fipsIDs, "    ids:\n      - fscache-fips\n      - fscache\n"),
		"standard template renamed":    edit("      {{ .ProjectName }}_{{ .Version }}", "      other_{{ .Version }}"),
		"fips template collides":       edit("      {{ .ProjectName }}-fips_{{ .Version }}", "      {{ .ProjectName }}_{{ .Version }}"),
		"template adds an expression":  edit("      {{ .ProjectName }}-fips_{{ .Version }}_{{ .Os }}_{{ .Arch }}", "      {{ .ProjectName }}-fips_{{ .Version }}_{{ .Os }}_{{ .Arch }}{{ .Env.SUFFIX }}"),
		"template drops the arch":      edit("      {{ .ProjectName }}-fips_{{ .Version }}_{{ .Os }}_{{ .Arch }}", "      {{ .ProjectName }}-fips_{{ .Version }}_{{ .Os }}"),
		"project name changed":         edit("project_name: fscache\n", "project_name: fscache2\n"),
		"project name removed":         edit("project_name: fscache\n", ""),
		// Round-4 regressions (B1): the checksum file is written after the archives (O_TRUNC), so a checksum name
		// that is an archive's name overwrites it; every output file name is pinned or resolved, none may collide.
		"checksum overwrites an archive": edit("  name_template: \"checksums.txt\"\n", "  name_template: \"fscache_{{ .Version }}_linux_amd64.tar.gz\"\n"),
		"checksum renamed":               edit("  name_template: \"checksums.txt\"\n", "  name_template: \"sums.txt\"\n"),
		"checksum name templated":        edit("  name_template: \"checksums.txt\"\n", "  name_template: \"{{ .ProjectName }}_checksums.txt\"\n"),
		"checksum section removed":       edit("checksum:\n  name_template: \"checksums.txt\"\n", ""),
		"checksum without a name":        edit("checksum:\n  name_template: \"checksums.txt\"\n", "checksum: {}\n"),
		"second sbom definition":         edit("  - artifacts: archive\n", "  - artifacts: archive\n  - artifacts: archive\n"),
		// Round-7 regressions (A7-6): the archive SBOMs are pinned by value: the section missing, empty, null or with
		// another or an extra entry is refused.
		"A7-6 sboms section removed":    edit("sboms:\n  - artifacts: archive\n", ""),
		"A7-6 sboms empty list":         edit("sboms:\n  - artifacts: archive\n", "sboms: []\n"),
		"A7-6 sboms null":               edit("sboms:\n  - artifacts: archive\n", "sboms:\n"),
		"A7-6 sboms extra entry":        edit("  - artifacts: archive\n", "  - artifacts: archive\n  - artifacts: package\n"),
		"A7-6 sboms entry as a mapping": edit("sboms:\n  - artifacts: archive\n", "sboms:\n  artifacts: archive\n"),
		// Round-8 self-review (the YAML-decoding family, applied to the release configuration): any explicit YAML tag is
		// refused by name, also one that decodes to the pinned value (a !!binary main, a !!str hook), and a YAML
		// directive (%YAML, %TAG, which can remap a tag) is refused.
		"N8 main as !!binary of the pinned value": edit("  - id: fscache\n    main: ./cmd/fscache\n", "  - id: fscache\n    main: !!binary Li9jbWQvZnNjYWNoZQ==\n"),
		"N8 version tagged !!int":                 edit("version: 2\n", "version: !!int 2\n"),
		"N8 draft tagged !!bool":                  edit("  draft: true\n", "  draft: !!bool true\n"),
		"N8 hook tagged !!str":                    edit("    - go mod verify\n", "    - !!str go mod verify\n"),
		"N8 sbom artifacts tagged !!str":          edit("  - artifacts: archive\n", "  - artifacts: !!str archive\n"),
		"N8 checksum name tagged !!str":           edit("  name_template: \"checksums.txt\"\n", "  name_template: !!str \"checksums.txt\"\n"),
		"N8 project name tagged !!str":            edit("project_name: fscache\n", "project_name: !!str fscache\n"),
		"N8 archive ids item tagged !!str":        edit("    ids:\n      - fscache\n", "    ids:\n      - !!str fscache\n"),
		"N8 release github as a tagged mapping":   edit("  github:\n    owner: fosterstack\n", "  github: !!map\n    owner: fosterstack\n"),
		"N8 env item as !!binary GOOS=darwin":     edit("      - GOFIPS140=v1.0.0\n", "      - GOFIPS140=v1.0.0\n      - !!binary R09PUz1kYXJ3aW4=\n"),
		"N8 %YAML directive":                      "%YAML 1.2\n---\n" + real,
		"N8 %TAG directive remaps !!":             "%TAG !! tag:example.com,2000:\n---\n" + real,
		// Post-9 round (scope cut): the YAML tag scan reads the raw text before decoding and refuses every "!" (A9-1/R9-2:
		// a bare "!" is an explicit non-specific tag the decoder does not flag), wherever it is: the files hold none, and a
		// raw scan does not parse YAML's quoting, comments or flow context to tell a tag token from text.
		"A9-1/R9-2 main tagged with a bare !":  edit("  - id: fscache\n    main: ./cmd/fscache\n", "  - id: fscache\n    main: ! ./cmd/fscache\n"),
		"P9 hook item tagged with a bare !":    edit("    - go mod verify\n", "    - ! go mod verify\n"),
		"P9 project name tagged with a bare !": edit("project_name: fscache\n", "project_name: ! fscache\n"),
		"P9 binary tagged with a bare !":       edit("    binary: fscache-fips\n", "    binary: ! fscache-fips\n"),
		"P9 verbatim tag":                      edit("project_name: fscache\n", "project_name: !<tag:yaml.org,2002:str> fscache\n"),
		"P9 local tag":                         edit("project_name: fscache\n", "project_name: !local fscache\n"),
		"P9 bare ! on a mapping":               edit("  github:\n    owner: fosterstack\n", "  github: !\n    owner: fosterstack\n"),
		"P9 bare ! on a sequence":              edit("  hooks:\n", "  hooks: !\n"),
		"P9 bare ! in a flow sequence":         edit("    env:\n      - CGO_ENABLED=0\n    goos:", "    env: [! CGO_ENABLED=0]\n    goos:"),
		"P9 bare ! in a flow mapping":          edit("  - artifacts: archive\n", "  - {artifacts: ! archive}\n"),
		"P9 bare ! after a tab":                edit("    binary: fscache\n", "    binary:\t! fscache\n"),
		"P9 bare ! on a quoted scalar":         edit("  name_template: \"checksums.txt\"\n", "  name_template: ! \"checksums.txt\"\n"),
		"P9 ! in a whole-line comment":         real + "# Linux only!\n",
		"P9 ! in a line comment":               edit("version: 2\n", "version: 2 # pinned!\n"),
		// Round-5 regressions (B1): every build's binary output path is resolved (dist/<id>_<os>_<arch>_<level>/<binary>)
		// and enters the collision check; a binary name that leaves its build directory, holds a path separator or a
		// template, or is missing is refused.
		"binary escapes onto an archive path": edit("    binary: fscache\n", "    binary: ../fscache_{{ .Version }}_linux_amd64.tar.gz\n"),
		"binary climbs out of its directory":  edit("    binary: fscache\n", "    binary: ../fscache\n"),
		"binary is dot-dot":                   edit("    binary: fscache\n", "    binary: ..\n"),
		"binary holds a path separator":       edit("    binary: fscache\n", "    binary: bin/fscache\n"),
		"binary holds a backslash":            edit("    binary: fscache\n", "    binary: bin\\\\fscache\n"),
		"binary is templated":                 edit("    binary: fscache\n", "    binary: \"{{ .ProjectName }}\"\n"),
		"binary is absolute":                  edit("    binary: fscache\n", "    binary: /tmp/fscache\n"),
		"binary missing":                      edit("    binary: fscache\n", ""),
		"binary empty":                        edit("    binary: fscache\n", "    binary: \"\"\n"),
		// Round-6 regressions (B1): every admitted field is validated by value against the committed configuration's
		// pinned literal; a template is refused unless the pinned value is that template. The linker can write a file
		// (-memprofile), an ellipsis main renames the binary, GOFLAGS or flags can redirect the output, a hook can write
		// into dist/.
		"ldflags write a linker profile":    edit(stdLdflags, "    ldflags:\n      - -s -w -memprofile=/tmp/fscache-link.pprof\n"+stdLdflags[len("    ldflags:\n      - -s -w\n"):]),
		"fips ldflags write a profile":      edit(fipsTail, strings.Replace(fipsTail, "      - -s -w\n", "      - -s -w -memprofile=/tmp/fscache-link.pprof\n", 1)),
		"ldflags missing":                   edit(stdLdflags, stdLdflags[len("    ldflags:\n      - -s -w\n"):]),
		"ldflags templated":                 edit(fipsTail, strings.Replace(fipsTail, "      - -s -w\n", "      - \"{{ .Env.LDFLAGS }}\"\n", 1)),
		"fips main with an ellipsis":        edit("  - id: fscache-fips\n    main: ./cmd/fscache\n", "  - id: fscache-fips\n    main: ./cmd/fscache/...\n"),
		"main templated":                    edit("  - id: fscache\n    main: ./cmd/fscache\n", "  - id: fscache\n    main: \"{{ .Env.MAIN }}\"\n"),
		"main missing":                      edit("  - id: fscache\n    main: ./cmd/fscache\n", "  - id: fscache\n"),
		"env redirects the output":          edit(fipsGoos, "      - GOFIPS140=v1.0.0\n      - GOFLAGS=-o=/tmp/fscache\n    goos:\n      - linux\n"),
		"env enables cgo":                   edit("    env:\n      - CGO_ENABLED=0\n    goos:", "    env:\n      - CGO_ENABLED=1\n    goos:"),
		"env missing":                       edit("    env:\n      - CGO_ENABLED=0\n    goos:", "    goos:"),
		"env templated":                     edit(fipsGoos, "      - GOFIPS140=v1.0.0\n      - \"{{ .Env.EXTRA }}\"\n    goos:\n      - linux\n"),
		"flags redirect the output":         edit("    flags:\n      - -trimpath\n    # Version", "    flags:\n      - -trimpath\n      - -o=../fscache_x_linux_amd64.tar.gz\n    # Version"),
		"flags missing":                     edit("    flags:\n      - -trimpath\n    # Version", "    # Version"),
		"mod_timestamp templated otherwise": edit(stdLdflags, strings.Replace(stdLdflags, "{{ .CommitTimestamp }}", "{{ .Env.TS }}", 1)),
		"mod_timestamp missing":             edit(fipsTail, strings.Replace(fipsTail, "    mod_timestamp: \"{{ .CommitTimestamp }}\"\n", "", 1)),
		"binary renamed plainly":            edit("    binary: fscache-fips\n", "    binary: fscache-x\n"),
		"hook writes into dist":             edit("    - git diff --exit-code go.mod go.sum\n", "    - git diff --exit-code go.mod go.sum\n    - touch dist/fscache_x_linux_amd64.tar.gz\n"),
		"hooks removed":                     edit("    - go mod verify\n    - git diff --exit-code go.mod go.sum\n", ""),
		"release owner changed":             edit("    owner: fosterstack\n", "    owner: someone\n"),
		"release not a draft":               edit("  draft: true\n", "  draft: false\n"),
		"release draft as a string":         edit("  draft: true\n", "  draft: \"true\"\n"),
		"changelog filter dropped":          edit("      - \"^ci:\"\n", ""),
		"config version 1":                  edit("version: 2\n", "version: 1\n"),
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
	// Round-5 regression (B1): the binary output paths of the real configuration are resolved, one per build and
	// platform, each inside its own build directory.
	builds, _ := parseBuilds(real)
	_, outputs, _ := releaseOutputs(real, builds)
	for _, want := range []string{"fscache_linux_amd64_v1/fscache", "fscache_linux_arm64_v8.0/fscache", "fscache-fips_linux_amd64_v1/fscache-fips", "fscache-fips_linux_arm64_v8.0/fscache-fips"} {
		if _, ok := outputs[want]; !ok {
			t.Errorf("the release outputs do not hold the binary %s: %v", want, outputs)
		}
	}
}

// platformWord finds a mention of a non-Linux desktop platform. The checks match it against plain,
// whitespace-collapsed text (a whole Markdown paragraph, a decoded YAML value), so a name wrapped across a
// line break is one match; "Apple Silicon" and "OS X" also match with the space removed.
var platformWord = regexp.MustCompile(`(?i)darwin|mac\s?os|\bmacs?\b|apple\s*silicon|\bos\s?x\b|windows`)

// markdownMarks are the inline Markdown marks the docs checks remove before reading text, so emphasis, code
// spans, link brackets and escapes cannot split a claim from its words: `**six** archives` reads "six archives"
// and `Win**dows**` reads "Windows".
var markdownMarks = strings.NewReplacer("*", "", "_", "", "`", "", "~", "", "[", "", "]", "", "\\", "")

// The content guard. The prose checks are a consistency check on documents this project writes and reviews, not
// a security control: they read plain Markdown text. So that plain text is all there is, the guard refuses outright,
// naming file and line, what a plain-text reading would have to interpret: any tag-like "<" (htmlStart: a "<" before
// a letter, /, ! or ?, which opens a tag, a comment, a processing instruction, a declaration, CDATA or an autolink)
// anywhere in the file, code spans and code fences included (the guard reads no Markdown structure, so nothing can
// hide one), other than the exact allowedMarkup entries (an exception marker only where it ends its line); any
// character reference (charRef; the docs use none); any invisible or non-printing character (invisibleRune);
// strikethrough ("~~", which also opens a tilde fence); and every reference-style link form (refForm: "][", which a
// full "[text][label]" and a collapsed "[text][]" reference hold, and "]:", which ends every "[label]:" definition
// label, also one wrapped across lines or inside a quote or a list item), escaped or not: the checks read only inline
// links, "[text](destination)", so a reference form is refused rather than resolved.
var (
	htmlStart = regexp.MustCompile(`<[A-Za-z/!?]`)
	charRef   = regexp.MustCompile(`&(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);`)
	refForm   = regexp.MustCompile(`\]\[|\]:`)
)

// invisibleRune reports a character a reader cannot see as itself: everything that is not a letter, number,
// punctuation mark or symbol (Unicode Cc but tab, Cf, Mn, Mc, Me, Zl, Zp, Zs but the ASCII space, Co, Cs and
// unassigned code points), and the default-ignorable letters (the Hangul fillers) and the blank Braille pattern,
// which are letters or symbols that display as nothing.
func invisibleRune(r rune) bool {
	switch r {
	case ' ', '\t':
		return false
	case 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800:
		return true
	}
	return !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.IsPunct(r) && !unicode.IsSymbol(r)
}

// markupFor are the allowedMarkup texts that apply to file.
func markupFor(file string) []string {
	var out []string
	for _, m := range allowedMarkup {
		if m.files == file || (m.files == "*.md" && strings.HasSuffix(file, ".md")) {
			out = append(out, m.text)
		}
	}
	return out
}

// markupPlaced reports whether the allowed text a, found at byte i of the original (unscrubbed) line, stands where
// its exception holds. An exception marker (an HTML comment) holds only where it ends the line: nothing but spaces or
// tabs after it, and the line start or a space or tab before it; so two markers on one line are refused in either
// order. The mappings placeholder holds only on a whole-line comment at column 0 ("# ") inside the leading comment
// block (leading: every line up to it is blank or starts with "#" at column 0), never in a value, a key, a later or
// indented comment or a line comment.
func markupPlaced(a, line string, i int, leading bool) bool {
	if strings.HasPrefix(a, "<!--") {
		before, after := line[:i], line[i+len(a):]
		return strings.Trim(after, " \t") == "" && (before == "" || strings.HasSuffix(before, " ") || strings.HasSuffix(before, "\t"))
	}
	return leading && strings.HasPrefix(line, "# ")
}

// leadingLines reports, for each line, whether it lies in the leading comment block: it and every line before it
// is blank or starts with "#" at column 0.
func leadingLines(lines []string) []bool {
	out := make([]bool, len(lines))
	leading := true
	for n, line := range lines {
		leading = leading && (strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#"))
		out[n] = leading
	}
	return out
}

// guardText returns the guard's refusals for text, one per kind per line, each labelled by where(line). It reads no
// Markdown structure: a tag-like "<" is refused wherever it is on a line, in a code span or a code fence too, in a
// Markdown file and in the YAML mappings file (and its decoded values) alike. The allowed texts are excepted only
// where markupPlaced holds on the original line; every placement is decided before anything is scrubbed. The prose
// forms (proseFormProblems) are refused too.
func guardText(where func(line int) string, allowed []string, text string) (problems []string) {
	lines := strings.Split(text, "\n")
	leading := leadingLines(lines)
	problems = proseFormProblems(where, text)
	for n, line := range lines {
		for i := 0; i < len(line); {
			r, size := utf8.DecodeRuneInString(line[i:])
			if (r == utf8.RuneError && size == 1) || invisibleRune(r) {
				problems = append(problems, fmt.Sprintf("%s: invisible or non-printing character %U (or invalid UTF-8) refused outright: %q", where(n+1), r, line))
				break
			}
			i += size
		}
		if m := charRef.FindString(line); m != "" {
			problems = append(problems, fmt.Sprintf("%s: character reference %s refused outright (write the character itself): %q", where(n+1), m, line))
		}
		scrub := []byte(line)
		for _, a := range allowed {
			for off := 0; ; {
				i := strings.Index(line[off:], a)
				if i < 0 {
					break
				}
				i += off
				switch {
				case markupPlaced(a, line, i, leading[n]):
					copy(scrub[i:i+len(a)], strings.Repeat(" ", len(a)))
				case strings.HasPrefix(a, "<!--"):
					problems = append(problems, fmt.Sprintf("%s: exception marker %s refused where it does not end its line (it may only end its line, after a space, or stand alone, one per line): %q", where(n+1), a, line))
				}
				off = i + len(a)
			}
		}
		if loc := htmlStart.FindIndex(scrub); loc != nil {
			problems = append(problems, fmt.Sprintf("%s: inline HTML refused outright: a tag-like \"<\" (before a letter, /, ! or ?) is refused anywhere, in code spans and code fences too (write a placeholder as a word, POD_NAME; only allowedMarkup is excepted): %q", where(n+1), line))
		}
	}
	return problems
}

// proseFormProblems refuses outright, one per kind per line, each labelled by where(line), the prose forms the checks
// do not interpret: strikethrough ("~~") and every reference-style link form (refForm).
func proseFormProblems(where func(line int) string, text string) (problems []string) {
	for n, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "~~") {
			problems = append(problems, fmt.Sprintf("%s: strikethrough \"~~\" (or a tilde fence) refused outright: %q", where(n+1), line))
		}
		if m := refForm.FindString(line); m != "" {
			problems = append(problems, fmt.Sprintf("%s: a reference-style link form (%q: a [text][label] or [text][] reference, or a [label]: definition) refused outright (write an inline link, [text](destination)): %q", where(n+1), m, line))
		}
	}
	return problems
}

// contentProblems is the content guard for one whole file, naming file:line.
func contentProblems(file, text string) []string {
	return guardText(func(n int) string { return fmt.Sprintf("%s:%d", file, n) }, markupFor(file), text)
}

// linkParts splits Markdown text into what a reader sees and what is hidden: an inline link's destination and
// title ("](dest "title")", the destination with balanced parentheses, as CommonMark reads it) are hidden; everything
// else is visible (a backslash escape is visible text and opens or closes nothing). It reads inline links only (the
// content guard refuses every reference-style form). ok is false, and the text stays visible, when a "](" is a form
// it does not read: no unescaped "[" before it (CommonMark renders it as text), a nested link (another link's
// unescaped "[" still open when a link closes: a link inside link text, or an opener left unclosed before a link;
// CommonMark leaves the outer suffix as text; an image's "![" inside a link's text is not one), an unclosed
// destination or title, an angle-bracket destination, a backslash in a destination
// or title before a character CommonMark cannot escape (anything but ASCII punctuation), or a parenthesized title
// holding an unescaped "(": the caller refuses it rather than guess.
func linkParts(s string) (visible, hidden string, ok bool) {
	var v, h strings.Builder
	ok = true
	var openers []bool // the unescaped "[" not yet closed, innermost last: true for an image's "![", false for a link's
	esc := -1          // the index of the last backslash-escaped character
	skipSpace := func(j int) int {
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n') {
			j++
		}
		return j
	}
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			v.WriteString(s[i : i+2])
			esc = i + 1
			i += 2
			continue
		}
		if s[i] == '[' {
			openers = append(openers, i > 0 && s[i-1] == '!' && esc != i-1)
		}
		if s[i] != ']' || i+1 >= len(s) || s[i+1] != '(' {
			if s[i] == ']' && len(openers) > 0 {
				openers = openers[:len(openers)-1]
			}
			v.WriteByte(s[i])
			i++
			continue
		}
		if len(openers) == 0 {
			ok = false // no opener: CommonMark renders the "](" as text
			v.WriteByte(s[i])
			i++
			continue
		}
		image := openers[len(openers)-1]
		openers = openers[:len(openers)-1]
		if !image && slices.Contains(openers, false) {
			// a nested link: a link closes while another link's "[" is still open (an image, "![alt](src)", may sit
			// inside a link's text, as a badge does; a link may not, at any depth)
			ok = false
			v.WriteByte(s[i])
			i++
			continue
		}
		j, depth := skipSpace(i+2), 0
		if j < len(s) && s[j] == '<' {
			// an angle-bracket destination (<...>, where parentheses need not balance) is a form this check does
			// not read: refused
			ok = false
			v.WriteByte(s[i])
			i++
			continue
		}
		odd := false // a backslash before a character it cannot escape: a form this check does not read
		for ; j < len(s); j++ {
			c := s[j]
			if c == '\\' {
				if j+1 >= len(s) || !asciiPunct(s[j+1]) {
					odd = true
					break
				}
				j++
				continue
			}
			if c == ' ' || c == '\t' || c == '\n' || (c == ')' && depth == 0) {
				break
			}
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
			}
		}
		j = skipSpace(j)
		if j < len(s) && depth == 0 && (s[j] == '"' || s[j] == '\'' || s[j] == '(') {
			closer := s[j]
			if closer == '(' {
				closer = ')'
			}
			k := j + 1
			for !odd && k < len(s) && s[k] != closer {
				if closer == ')' && s[k] == '(' {
					odd = true // a parenthesized title holds "(" only escaped
					break
				}
				if s[k] == '\\' {
					if k+1 >= len(s) || !asciiPunct(s[k+1]) {
						odd = true
						break
					}
					k++
				}
				k++
			}
			j = skipSpace(k + 1)
		}
		if odd || depth != 0 || j >= len(s) || s[j] != ')' {
			ok = false
			v.WriteByte(s[i])
			i++
			continue
		}
		h.WriteString(" " + s[i+2:j] + " ")
		i = j + 1
	}
	return v.String(), h.String(), ok
}

// asciiPunct reports an ASCII punctuation character, the only characters a CommonMark backslash escapes.
func asciiPunct(c byte) bool {
	return strings.IndexByte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", c) >= 0
}

// collapse is s with its whitespace collapsed to single spaces.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// plainText is Markdown text as a reader of the rendered page sees it: link destinations and titles removed
// (linkParts), the allowed markers removed (they render nothing), inline marks removed, whitespace collapsed to single
// spaces. The content guard has refused anything else a renderer would interpret.
func plainText(s string) string {
	return collapse(markdownMarks.Replace(visibleText(s)))
}

// visibleText is linkParts' visible text with the allowed markers removed (they render nothing).
func visibleText(s string) string {
	visible, _, _ := linkParts(s)
	for _, m := range allowedMarkup {
		if m.files == "*.md" {
			visible = strings.ReplaceAll(visible, m.text, " ")
		}
	}
	return visible
}

// countReadings are the texts the archive-count check reads, each without bare URLs: the visible text as written
// (visibleText: nothing rewritten, every sign and mark kept, so a math sign stands in its clause) and the plain text
// (plainText: the inline marks removed, so a count split by a mark, "si**x**", is read whole). No sign or mark is
// ever rewritten into a word; a count either reading refuses is refused.
func countReadings(s string) []string {
	return []string{bareURL.ReplaceAllString(collapse(visibleText(s)), " "), bareURL.ReplaceAllString(plainText(s), " ")}
}

// bareURL is a URL written out as text: its digits are not a count, so the count check reads the text without it.
var bareURL = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S*|\bwww\.\S*`)

// countWords are the words read as a count, with their value. "a" and "an" are not counts on their own:
// before "archive" they are the indefinite article ("download an archive"); before a quantity word they are
// read through that word ("a single archive", "a dozen archives", "a couple of archives").
var countWords = map[string]int{
	"zero": 0, "none": 0, "single": 1, "one": 1, "both": 2, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
	"eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "dozen": 12, "thirteen": 13, "fourteen": 14,
	"fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30,
	"forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90, "hundred": 100,
	"thousand": 1000,
}

// vagueCounts are quantity words with no single value: an archive claim made with one cannot be checked, so
// it is refused.
var vagueCounts = keySet("couple", "few", "several", "multiple", "many", "handful", "dozens", "hundreds", "pair", "various", "numerous", "some")

// limitingWords before "a" or "an" make the article a count of one: "only an archive is shipped" claims
// one archive.
var limitingWords = keySet("only", "just", "solely")

// comparisonWords before a count make it a bound, not a count ("more than four", "at least four", "over four",
// "about four"; "up to four" is read as a pair): a bound cannot be checked against the archives, so it is refused.
var comparisonWords = keySet("than", "least", "most", "over", "under", "about", "around", "approximately", "nearly",
	"almost", "roughly", "exceeding", "beyond")

// comparisonPhrases anywhere in a clause make every count in it a bound, before or after the count ("more than the
// four archives", "four or more", "four archives at least"): refused, not resolved.
var comparisonPhrases = keySet("or more", "or fewer", "or less", "or greater", "or above", "or over", "or below",
	"or under", "or so", "at least", "at most", "more than", "fewer than", "less than", "up to", "and up", "and above",
	"and more", "and over")

// mathSign reports a count token that is a math symbol (Unicode Sm: + < = > ~ ± ≥ ≤ ≈ ＋ ⁺ ...) other than the
// table bar: a math sign anywhere in a count's clause makes the count a bound or an expression this check does not
// read ("4+", "4+Linux", "≥(4)", "~4", "a + b"), so it is refused, never interpreted.
func mathSign(w string) bool {
	r, size := utf8.DecodeRuneInString(w)
	return size == len(w) && w != "|" && unicode.Is(unicode.Sm, r)
}

// shippingWords make a clause a claim about what a release ships: a partitive count in such a clause ("each
// release ships three of the four archives") is a total, not a subset.
var shippingWords = keySet("ship", "ships", "shipped", "shipping", "publish", "publishes", "published", "produce",
	"produces", "produced", "include", "includes", "included", "contain", "contains", "attach", "attaches",
	"attached", "provide", "provides", "carry", "carries", "offer", "offers")

// countToken splits text into words (a hyphen or a plus separates words, so "six-archive" and "4+Linux" are two),
// boundaries (a sentence or clause end, . ! ? ; before a space or the end, and a table cell bar) and math signs (each
// Unicode Sm character other than the bar is a token of its own, mathSign). A colon is not a boundary: a label and its
// value ("Release archives: six") are one clause.
var countToken = regexp.MustCompile(`[A-Za-z0-9]+(?:[./][A-Za-z0-9]+)*|[.!?;](?:\s|$)|\||\p{Sm}`)

var digits = regexp.MustCompile(`^[0-9]+$`)

// allowedCountClaims are exact claims (as archiveCountProblems words them: lower case, one space between words,
// from the count through "archive(s)", or from "archive(s)" through a count after it) that read as a count
// claim but are not one, each with its reason. A new entry is reviewed.
var allowedCountClaims = map[string]string{
	"256 so verifying the checksums file and then checking an archive":                                                                              "RELEASING.md: the 256 of SHA-256 (the hyphen splits the hash name), not a count",
	"archives are fscache and fscache fips for linux/amd64 and linux/arm64 owner decision oct 9":                                                    "docs/next-release-notes.md: the 9 of the citation's date (Oct 9), not a count",
	"archive against that signed predicate before opening it assembles each variant with a copy only dockerfile digest pinned distroless base zero": "RELEASING.md: zero RUN instructions in the Dockerfile, not a count of archives",
	"archive against it is a complete chain not two":                                                                                                "RELEASING.md: not two half-measures, not a count of archives",
	"no archive for this machine": "docs/install.md: the architecture check's failure branch (no archive for this machine's architecture), not a count of the release's archives",
	"archive against that signed predicate before opening it assembles each variant with a copy only dockerfile digest pinned distroless base zero run and pushes by digest only to a private candidates package no tags nothing public": "RELEASING.md: no tags on the private candidates package, not a count of archives (the noun stands earlier in the clause)",
}

// archiveCountProblems returns every archive-count claim in plain text whose count is not archives. Every
// count word or number is validated on its own against its whole clause (up to a boundary: . ! ? ; before
// a space, a table bar; a colon joins a label and its value), before the next count is read; no later count ends its reading. A count claims
// archives when "archive" or "archives" follows anywhere in its clause, or when one stands before it in the
// clause and none follows (a total after the noun: "the archives number six"). Its qualifier decides what it
// must equal:
//   - after "all" ("all N", "all the N", "all of the N") it is a total, and after "only", "just" or "solely"
//     a limit ("only one of the four archives" says a release ships one): either must equal the archives
//     produced, and a partitive total ("all N of M") must also equal its whole M;
//   - a partitive ("N of ...") is a subset: N may not exceed the count that follows it, nor the archives; in a
//     clause that says what a release ships (shippingWords, before or after the count) it is a total;
//   - a plain count must equal the archives; a plain count with another count between it and "archive(s)"
//     ("six or four archives") cannot be resolved and is refused;
//   - "a" or "an" after "only", "just" or "solely" is a count of one; "none" and "zero" are counts of zero, and so is
//     "no" with "archive(s)" after it in its clause, whose claim runs from "no" to the clause end (only an exact
//     allowedCountClaims entry, "no archive for this machine", excepts one), or with "archive(s)" before it in its
//     clause ("Release archives: no"), whose claim runs from the noun to the clause end; a count of zero is a total
//     in any clause ("none of the archives exist"), so it must equal the archives;
//   - a count after a comparison word, also across "the" or "of" ("more than the four", "over", "about", ...), in a
//     clause holding a comparison phrase anywhere ("four or more", "at least", "or fewer", "up to"), followed by
//     "plus" ("four-plus"), or in a clause holding a math sign anywhere (mathSign: "4+", "≥ 4", "~4", "4+Linux",
//     "a + b"; the text is read as written, no sign is rewritten), is a bound, not a count, and is refused;
//   - a compound count ("twenty-four", "one hundred") and a vague one ("several", "a couple of", "some of the
//     archives") cannot be resolved and are refused.
//
// A claim this reading gets wrong is excepted only by an exact entry in allowedCountClaims.
func archiveCountProblems(text string, archives int) (problems []string) {
	var toks []string
	for _, m := range countToken.FindAllString(text, -1) {
		toks = append(toks, strings.ToLower(strings.TrimSpace(m)))
	}
	boundary := func(w string) bool { return len(w) == 1 && strings.ContainsAny(w, ".!?;|") }
	noun := func(w string) bool { return w == "archive" || w == "archives" }
	isCount := func(w string) bool {
		_, n := countWords[w]
		return n || vagueCounts[w] || digits.MatchString(w)
	}
	value := func(w string) int {
		if n, ok := countWords[w]; ok {
			return n
		}
		n, err := strconv.Atoi(w)
		if err != nil {
			return -1 // digits too large for an int (or a vague count): not a resolvable count
		}
		return n
	}
	// after reports whether the words before i, skipping "the" and "of", end with a word of set.
	after := func(i int, set map[string]bool) bool {
		for k := i - 1; k >= 0 && !boundary(toks[k]); k-- {
			if toks[k] != "the" && toks[k] != "of" {
				return set[toks[k]]
			}
		}
		return false
	}
	all := keySet("all")
	for i, w := range toks {
		article := (w == "a" || w == "an") && i > 0 && limitingWords[toks[i-1]]
		zeroNo := w == "no"
		if !isCount(w) && !article && !zeroNo {
			continue
		}
		n := 1
		switch {
		case zeroNo:
			n = 0
		case !article:
			n = value(w)
		}
		cs, ce := i, i+1 // the clause holding the count: [cs, ce)
		for cs > 0 && !boundary(toks[cs-1]) {
			cs--
		}
		for ce < len(toks) && !boundary(toks[ce]) {
			ce++
		}
		comparison := after(i, comparisonWords) || (i+1 < len(toks) && toks[i+1] == "plus") // "four-plus" is a bound
		for k := cs; k < ce; k++ {
			comparison = comparison || mathSign(toks[k]) || (k+1 < ce && comparisonPhrases[toks[k]+" "+toks[k+1]])
		}
		vague := vagueCounts[w]
		total := after(i, all)
		limiting := article || after(i, limitingWords)
		partitive := !vague && i+1 < len(toks) && toks[i+1] == "of"
		compound := i+1 < len(toks) && isCount(toks[i+1])
		nounAt, wholeAt, nounBefore := -1, -1, -1
		for j := i + 1; j < len(toks) && !boundary(toks[j]); j++ {
			if noun(toks[j]) && nounAt < 0 {
				nounAt = j
			}
			if isCount(toks[j]) && j > i+1 && wholeAt < 0 {
				wholeAt = j
			}
		}
		shipping := false
		for j := i + 1; j < len(toks) && !boundary(toks[j]); j++ {
			shipping = shipping || shippingWords[toks[j]]
		}
		for k := i - 1; k >= 0 && !boundary(toks[k]); k-- {
			shipping = shipping || shippingWords[toks[k]]
			if noun(toks[k]) && nounBefore < 0 {
				nounBefore = k
			}
		}
		// "no" is a count of zero wherever an archive follows it in its clause ("ships no archive", "has no
		// archive", "no archive exists"), or stands before it ("Release archives: no"); its claim runs to the clause
		// end, so only an exact allowedCountClaims entry excepts it ("no archive for this machine").
		if zeroNo && nounAt < 0 && nounBefore < 0 {
			continue
		}
		if partitive && wholeAt >= 0 && !vagueCounts[toks[wholeAt]] {
			m := value(toks[wholeAt])
			switch {
			case n < 0 || m < 0 || n > m:
				problems = append(problems, fmt.Sprintf("claims %q, a part larger than its whole", strings.Join(toks[i:wholeAt+1], " ")))
			case total && n != m:
				problems = append(problems, fmt.Sprintf("claims %q, a total that is not its whole", strings.Join(toks[i:wholeAt+1], " ")))
			}
		}
		var claim string
		switch {
		case zeroNo && nounAt >= 0:
			claim = strings.Join(toks[i:ce], " ")
		case zeroNo:
			claim = strings.Join(toks[nounBefore:ce], " ")
		case nounAt >= 0:
			claim = strings.Join(toks[i:nounAt+1], " ")
		case nounBefore >= 0:
			claim = strings.Join(toks[nounBefore:i+1], " ")
		default:
			continue // no archive in its clause
		}
		if _, ok := allowedCountClaims[claim]; ok {
			continue
		}
		switch {
		case compound:
			problems = append(problems, fmt.Sprintf("claims %q, a compound count this check does not resolve", claim))
		case vague:
			problems = append(problems, fmt.Sprintf("claims %q, a count this check cannot resolve", claim))
		case comparison:
			problems = append(problems, fmt.Sprintf("claims %q, a bound (a comparison word or phrase, or a math sign in its clause) this check does not resolve", claim))
		case total || limiting || n == 0 || nounAt < 0 || (partitive && shipping):
			if n != archives {
				problems = append(problems, fmt.Sprintf("claims %q, a total or limit (or a shipping claim), but .goreleaser.yaml produces %d archives", claim, archives))
			}
		case partitive:
			if n < 0 || n > archives {
				problems = append(problems, fmt.Sprintf("claims %q, more than the %d archives .goreleaser.yaml produces", claim, archives))
			}
		case wholeAt >= 0 && wholeAt < nounAt:
			problems = append(problems, fmt.Sprintf("claims %q, a count with another count between it and the archives: this check does not resolve it", claim))
		case n != archives:
			problems = append(problems, fmt.Sprintf("claims %q, but .goreleaser.yaml produces %d archives", claim, archives))
		}
	}
	return problems
}

// docsScanned are the public docs that describe what a release ships.
var docsScanned = []string{"README.md", "docs/install.md", "docs/docker-deploy.md", "RELEASING.md", "docs/verify-images.md"}

// allowedLine is a run of text in a scanned doc that names a non-Linux platform without claiming a darwin or
// windows binary exists. The text is matched exactly, with whitespace collapsed, inside one Markdown
// paragraph (unit: consecutive non-blank lines), so it may span a soft line break; a platform name is excused only
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

// unit is a run of text read as one piece: a paragraph, the consecutive non-blank lines between blank lines, so a
// sentence wrapped across a soft line break is one unit. No Markdown structure is read (a fence line is a line of
// text). text has its whitespace collapsed to single spaces; line is its first physical line.
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
	for n, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			flush()
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

// linkProblem is the refusal of a text holding a link form linkParts does not read.
func linkProblem(where, text string) string {
	return fmt.Sprintf("%s holds a link this check does not read (no opening bracket, a nested link, an unclosed destination or title, an angle-bracket destination, an unescaped \"(\" in a parenthesized title): %s", where, collapse(text))
}

// checkDoc returns every problem in one scanned doc and the allowed texts it found: the content guard's refusals
// (inline HTML, a character reference, an invisible or non-printing character, strikethrough, a reference-style link
// form); a darwin archive name; a link form linkParts does not read (linkProblem); an archive-count claim that is not
// the count .goreleaser.yaml produces, in either of countReadings; a platform name in the visible text that does not
// lie wholly inside one of the file's allowed texts; and any platform name in a link destination or title.
func checkDoc(file, text string, allowed []allowedLine, archives int) (problems []string, seen map[string]bool) {
	seen = map[string]bool{}
	reported := map[string]bool{}
	report := func(p string) {
		if !reported[p] {
			reported[p] = true
			problems = append(problems, p)
		}
	}
	for _, p := range contentProblems(file, text) {
		report(p)
	}
	for _, u := range units(text) {
		if strings.Contains(strings.ToLower(u.text), "_darwin_") {
			report(fmt.Sprintf("%s:%d names a darwin archive: %s", file, u.line, u.text))
		}
		_, hidden, ok := linkParts(u.text)
		if !ok {
			report(linkProblem(fmt.Sprintf("%s:%d", file, u.line), u.text))
		}
		for _, loc := range platformWord.FindAllStringIndex(hidden, -1) {
			report(fmt.Sprintf("%s:%d names a non-Linux platform (%q) in a link destination or title: %s", file, u.line, hidden[loc[0]:loc[1]], u.text))
		}
		plain := plainText(u.text)
		for _, r := range countReadings(u.text) {
			for _, p := range archiveCountProblems(r, archives) {
				report(fmt.Sprintf("%s:%d %s: %s", file, u.line, p, u.text))
			}
		}
		var spans [][2]int
		for _, a := range allowed {
			want := plainText(a.text)
			if a.file != file || want == "" {
				continue
			}
			for off := 0; ; {
				i := strings.Index(plain[off:], want)
				if i < 0 {
					break
				}
				seen[a.text] = true
				spans = append(spans, [2]int{off + i, off + i + len(want)})
				off += i + 1
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
				report(fmt.Sprintf("%s:%d names a non-Linux platform (%q) outside an allowed text: %s", file, u.line, plain[loc[0]:loc[1]], u.text))
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
// Markdown or by a link whose destination holds balanced parentheses, a platform name in a link destination, title
// or label, an OS X claim, a link form the check does not read, an archive count that disagrees with
// .goreleaser.yaml (behind Markdown, any number of words before "archives" in its clause, after "one of", a part
// larger than its whole, "all N of M" unequal to M or to the archives, "only" a part, "only an", a total after the
// noun, a label and its value across a colon, a partitive count in a shipping claim, two counts before the noun, a
// count interrupted by a link destination or a URL, in any number word, digits, compound or vague), a darwin
// archive name, and any inline HTML, character reference or invisible character (refused outright by the content
// guard, a tag-like "<" anywhere, a code span or fence included; an exception marker inside a line of prose is refused),
// an angle-bracket link destination, "no archives", "none of the archives", "no" after the archive noun and a count
// after a comparison (more than, at least, up to, four-plus, ...) or with a math sign anywhere in its clause (4+, 4+Linux,
// ≥(4), ~4, a + between words, ...) are each refused, as are a link close with no opener, a nested link, a
// parenthesized title holding an unescaped "(", strikethrough ("~~", a tilde fence included) and every reference-style
// link form (a full, collapsed or shortcut reference with its definition, a definition anywhere); nothing is rewritten
// (si~~x~~ is refused, not read as a bound); phrases that name archives without a wrong count pass (a count in a link
// destination or title is not read; a marker ending its line; a placeholder written as a word; a tilde outside a count
// clause); the wrapped Apple Silicon mention in docs/install.md passes only through its named exception.
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
		// Round-3 regressions (both seats): inline HTML inside a word, autolinks and attributes, counts past five
		// words, partitive counts, and limiting claims.
		"html bold inside six":            install + "\nEvery release ships si<b>x</b> archives.\n",
		"html bold starts six":            install + "\nEvery release ships <b>si</b>x archives.\n",
		"html bold inside Windows":        install + "\nNative binaries for Win<b>dows</b> are attached.\n",
		"html bold starts Windows":        install + "\nNative binaries for <b>Win</b>dows are attached.\n",
		"html span with class in Windows": install + "\nNative binaries for Win<span class=\"x\">dows</span> are attached.\n",
		"html code inside macOS":          install + "\nNative binaries for mac<code>OS</code> are attached.\n",
		"block break between six":         install + "\nEvery release ships six<br>archives.\n",
		"autolink names windows":          install + "\nNative binaries: <https://example.com/windows>\n",
		"link attribute names macos":      install + "\nNative binaries: <a href=\"https://example.com/macos\">here</a>.\n",
		"six words between":               install + "\nSix signed static stripped verified Linux release archives.\n",
		"ten words between":               install + "\nEvery release ships six signed, static, stripped, reproducible, verified, attested Linux and FIPS release archives.\n",
		"all six of the archives":         install + "\nAll six of the release archives are signed.\n",
		"six of the four archives":        install + "\nDownload six of the four archives.\n",
		"five of the archives":            install + "\nFive of the archives are FIPS builds.\n",
		"only an archive":                 install + "\nOnly an archive is shipped.\n",
		"just one archive":                install + "\nJust one archive is shipped.\n",
		// Round-4 regressions (A1, A2, B3, B4): inline HTML of every form, character references and invisible
		// characters inside a word (since round 5 refused outright by the content guard); a count is validated on
		// its own before the next one is read; link destinations and URLs are not visible counts.
		"unlisted inline element in Windows":     install + "\nNative binaries for Win<label>dows</label> are attached.\n",
		"unknown element in Windows":             install + "\nNative binaries for Win<foo-bar x=1>dows</foo-bar> are attached.\n",
		"decimal character reference in Windows": install + "\nNative binaries for Win&#100;ows are attached.\n",
		"hex character reference in Windows":     install + "\nNative binaries for Win&#x64;ows are attached.\n",
		"named space reference in Apple Silicon": install + "\nNative binaries for Apple&nbsp;Silicon are attached.\n",
		"soft hyphen inside Windows":             install + "\nNative binaries for Win&shy;dows are attached.\n",
		"zero-width space inside Windows":        install + "\nNative binaries for Win\u200bdows are attached.\n",
		"comment inside Windows":                 install + "\nNative binaries for Win<!--note-->dows are attached.\n",
		"processing instruction inside Windows":  install + "\nNative binaries for Win<?x?>dows are attached.\n",
		"declaration inside Windows":             install + "\nNative binaries for Win<!X y>dows are attached.\n",
		"CDATA inside Windows":                   install + "\nNative binaries for Win<![CDATA[x]]>dows are attached.\n",
		"quoted > in an attribute":               install + "\nNative binaries for Win<span title=\">\">dows</span> are attached.\n",
		"comment inside six":                     install + "\nEvery release ships si<!--note-->x archives.\n",
		"character reference inside six":         install + "\nEvery release ships si&#120; archives.\n",
		"all six of the four archives":           install + "\nAll six of the four archives are signed.\n",
		"only one of the four archives":          install + "\nEach release ships only one of the four archives.\n",
		"total after the noun":                   install + "\nThe release archives number six.\n",
		"two counts before the noun":             install + "\nEvery release ships six or four archives.\n",
		"link title interrupts a count":          install + "\nEvery release ships [six](https://example.com/a \"4\") archives.\n",
		"bare URL interrupts a count":            install + "\nEvery release ships six https://example.com/4 archives.\n",
		// Round-5 regressions (A3, B2, B4): a shipping claim with a partitive count is a total; a label and its value
		// across a colon are one clause; a link destination with balanced parentheses is read whole; a link this
		// check does not read is refused; a platform name in a link destination is refused.
		"ships three of the four archives":         install + "\nEach release ships three of the four archives.\n",
		"three of the four archives are shipped":   install + "\nThree of the four archives are shipped with each release.\n",
		"label and value across a colon":           install + "\nRelease archives: six.\n",
		"total label and value across a colon":     install + "\nTotal release archives: six.\n",
		"nested destination splits Windows":        install + "\nNative binaries for Win[do](https://example.com/a(b))ws are attached.\n",
		"nested destination splits a count":        install + "\nEvery release ships si[x](https://example.com/a(b)) archives.\n",
		"nested destination hides a wrong count":   install + "\nEvery release ships [six](https://example.com/a(4)) archives.\n",
		"title with a parenthesis hides a count":   install + "\nEvery release ships [six](https://example.com/a \"x)\") archives.\n",
		"unclosed link destination":                install + "\nEvery release ships [four](https://example.com/a(b archives.\n",
		"destination names windows":                install + "\nNative binaries are [here](https://example.com/windows).\n",
		"nested destination names macOS":           install + "\nNative binaries are [here](https://example.com/a(macos)).\n",
		"reference label names darwin":             install + "\nNative binaries are [here][darwin].\n",
		"inline html is refused outright":          install + "\nEvery release ships <b>four</b> archives.\n",
		"inline html in a word is refused":         install + "\nEvery release ships fo<b>ur</b> archives.\n",
		"autolink is refused outright":             install + "\nSee <https://example.com/linux> for the archives.\n",
		"unpinned comment is refused outright":     install + "\nThe four archives are signed; <!-- a comment --> each is a tar.gz.\n",
		"image tag splits Windows":                 install + "\nNative binaries for Win<img alt=\"\" width=\"0\" height=\"0\">dows are attached.\n",
		"combining grapheme joiner splits Windows": install + "\nNative binaries for Win͏dows are attached.\n",
		"combining grapheme joiner splits six":     install + "\nEvery release ships si͏x archives.\n",
		"entity for a joiner splits Windows":       install + "\nNative binaries for Win&#x034F;dows are attached.\n",
		// Round-6 regressions (A1, B3, A2, B4, B2, A3): a pseudo-fence hides nothing (since round 7 no fence is read at
		// all); an exception marker may only end its line, never sit inside a line of prose; an angle-bracket link
		// destination is a link form the check does not read; "no archives" is a count of zero and a comparison is not
		// resolved.
		"indented pseudo-fence hides html":         install + "\n    ```\n\nNative binaries for Win<b>dows</b> are attached.\n",
		"indented pseudo-fence hides a count":      install + "\n    ```\n\nEvery release ships si<b>x</b> archives.\n",
		"backtick info string hides html":          install + "\n```bad`\nEvery release ships si<b>x</b> archives.\n",
		"backtick info string hides Windows html":  install + "\n```bad`\nNative binaries for Win<b>dows</b> are attached.\n",
		"marker splits Windows":                    install + "\nNative binaries for Win<!-- pinned: upstream -->dows are attached.\n",
		"marker splits six":                        install + "\nEvery release ships si<!-- pinned: upstream -->x archives.\n",
		"historical marker splits Windows":         install + "\nNative binaries for Win<!-- pinned: historical -->dows are attached.\n",
		"marker inside a line of prose":            install + "\nThe version is pinned <!-- pinned: upstream --> for all four archives.\n",
		"angle-bracket destination splits Windows": install + "\nNative binaries for Win[do](<./a)b>)ws are attached.\n",
		"angle-bracket destination splits six":     install + "\nEvery release ships si[x](<./a)b>) archives.\n",
		"ships no archives":                        install + "\nThe release ships no archives.\n",
		"no archives are shipped":                  install + "\nNo release archives are shipped.\n",
		"ships no archive":                         install + "\nThe release ships no archive.\n",
		"more than four archives":                  install + "\nThe release ships more than four archives.\n",
		"fewer than six archives":                  install + "\nThe release ships fewer than six archives.\n",
		"at least four archives":                   install + "\nThe release ships at least four archives.\n",
		"at most four archives":                    install + "\nThe release ships at most four archives.\n",
		"up to four archives":                      install + "\nThe release ships up to four archives.\n",
		"over four archives":                       install + "\nThe release ships over four archives.\n",
		"about four archives":                      install + "\nThe release ships about four archives.\n",
		// Round-7 regressions (A7-5, B7-3, B7-5): "no" before an archive is a count of zero in any clause (only the
		// exact allowedCountClaims entry is excepted); a comparison is found across a determiner and after the count;
		// a link destination with a backslash before a character it cannot escape is refused.
		"A7-5 release has no archive":            install + "\nThis release has no archive.\n",
		"A7-5 no archive exists":                 install + "\nNo archive exists for a release.\n",
		"A7-5 no archive for any machine":        install + "\nThere is no archive for any machine.\n",
		"A7-5 none of the archives shipped":      install + "\nThe release ships none of the archives.\n",
		"B7-3 more than the four archives":       install + "\nEach release ships more than the four archives listed here.\n",
		"B7-3 four or more after a colon":        install + "\nRelease archives: four or more.\n",
		"B7-3 four or more archives":             install + "\nThe release ships four or more archives.\n",
		"B7-3 at least the four archives":        install + "\nThe release ships at least the four archives.\n",
		"B7-3 four archives at least":            install + "\nThe release ships four archives at least.\n",
		"B7-3 four archives or fewer":            install + "\nThe release ships four archives or fewer.\n",
		"B7-3 4+ archives":                       install + "\nThe release ships 4+ archives.\n",
		"B7-3 up to the four archives":           install + "\nThe release ships up to the four archives.\n",
		"B7-5 escaped space hides a count":       install + "\nRelease archives: [count](six\\ ).\n",
		"B7-5 backslash before a letter":         install + "\nEvery release ships [four](a\\b) archives.\n",
		"B7-5 backslash before a space in title": install + "\nEvery release ships [four](a \"x\\ y\") archives.\n",
		// Round-7 decision (advisor, final): no Markdown structure is read; a tag-like "<" is refused anywhere, in a
		// code span or fence too. The reviewer shapes (A7-1, A7-2, B7-1, B7-2) and the placeholders accepted until
		// round 7 are each refused.
		"A7-1/B7-1 list fence hides Windows html":  install + "\n- Example\n  ```\n  harmless\n\nWin<b>dows</b> binaries are shipped.\n```\n",
		"A7-2/B7-1 heading code span hides html":   install + "\n# `\nWin<b>dows</b> binaries are shipped.\n`\n",
		"B7-2 marker between code spans (Windows)": install + "\n`Win`<!-- pinned: upstream -->`dows`\n",
		"B7-2 marker between code spans (six)":     install + "\nEvery release ships `si`<!-- pinned: upstream -->`x archives`\n",
		"placeholder in a code span":               install + "\nRun `kubectl exec -it <pod> -- sh` to look inside the four archives' container.\n",
		"placeholder in an indented fence":         install + "\n   ```sh\n   kubectl exec -it <pod> -- sh\n   ```\n",
		"placeholder in a four-backtick fence":     install + "\n````\n```\nkubectl exec -it <pod> -- sh\n````\n",
		"placeholder in a tilde fence":             install + "\n~~~ sh `x`\nkubectl exec -it <pod> -- sh\n~~~\n",
		// Round-8 regressions (A8-2/B8-5, A8-4, B8-6, B8-4): a trailing plus before punctuation is a bound; a full
		// reference link whose label has no definition in the file is refused (CommonMark renders it as literal text);
		// a parenthesized title holding an unescaped "(" and a "](" with no "[" before it are not links and are refused;
		// "none of the archives" is a count of zero in any clause.
		"A8-2/B8-5 4+ before a full stop":          install + "\nRelease archives: 4+.\n",
		"B8-5 (4+) archives":                       install + "\nThe release ships (4+) archives.\n",
		"A8-4 reference label without definition":  install + "\nThe release ships [the][six] archives.\n",
		"B8-6 title with an unescaped parenthesis": install + "\nRelease archives: [count](six (a(b)).\n",
		"B8-6 link close with no opener":           install + "\nRelease archives: count](six).\n",
		"B8-4 none of the archives exist":          install + "\nNone of the archives exist.\n",
		"B8-4 has none of the archives":            install + "\nThe release has none of the archives.\n",
		// Round-8 self-review (the count and link family): neighbour shapes of each finding, each refused.
		"N8 4+ before a comma":                         install + "\nRelease archives: 4+, all signed.\n",
		"N8 4+ before a semicolon":                     install + "\nRelease archives: 4+; each is signed.\n",
		"N8 four+ in words":                            install + "\nRelease archives: four+.\n",
		"N8 fullwidth plus":                            install + "\nRelease archives: 4＋.\n",
		"N8 superscript plus":                          install + "\nRelease archives: 4⁺.\n",
		"N8 four-plus":                                 install + "\nThe release ships four-plus archives.\n",
		"N8 greater-than sign":                         install + "\nRelease archives: >4.\n",
		"N8 greater-or-equal sign":                     install + "\nRelease archives: ≥ 4.\n",
		"N8 tilde for about":                           install + "\nRelease archives: ~4.\n",
		"N8 at-least sign written >=":                  install + "\nRelease archives: >= 4.\n",
		"N8 reference label defined under another":     install + "\nThe release ships [the][six] archives.\n\n[seven]: https://example.com/x\n",
		"N8 collapsed reference without definition":    install + "\nThe release ships [the][] six archives.\n",
		"N8 escaped opener is no link":                 install + "\nThe release ships \\[the](six) archives.\n",
		"N8 link close with no opener mid-sentence":    install + "\nThe release ships the](six) archives.\n",
		"N8 title with a nested parenthesis and count": install + "\nEvery release ships [four](a (x(six)) archives.\n",
		"N8 zero of the archives":                      install + "\nZero of the archives are signed.\n",
		"N8 none of the four archives":                 install + "\nNone of the four archives exist.\n",
		"N8 none of the archives after a colon":        install + "\nRelease archives: none of them.\n",
		// Post-9 round (scope cut): the doors are closed by refusal. Strikethrough ("~~") is refused outright and no
		// sign is rewritten into words (R9-1: "si~~x~~" became "si at least x at least" and the count vanished); the
		// count reader reads the text as written and with the inline marks removed.
		"R9-1 strikethrough splits six":            install + "\nEvery release ships si~~x~~ archives.\n",
		"P9 single-tilde strikethrough splits six": install + "\nEvery release ships si~x~ archives.\n",
		"P9 strikethrough inside a count clause":   install + "\nThe four ~~signed~~ archives are attached.\n",
		"P9 strikethrough splits Windows":          install + "\nNative binaries for Win~~dows~~ are attached.\n",
		"P9 single-tilde strikethrough in Windows": install + "\nNative binaries for Win~dows~ are attached.\n",
		"P9 tilde fence (round-7 precision)":       install + "\n~~~ sh `x`\nkubectl exec -it POD_NAME -- sh\n~~~\n",
		"P9 strikethrough alone on a line":         install + "\n~~\n",
		"P9 strikethrough across a soft break":     install + "\nEvery release ships si~~x\n~~ archives.\n",
		"P9 four tildes":                           install + "\n~~~~\n",
		"P9 strikethrough in a table row":          install + "\n| ~~six~~ | archives |\n",
		"P9 strikethrough in link text":            install + "\nEvery release ships [si~~x~~](y) archives.\n",
		// Reference-style links are refused in every form (A9-2/R9-3: a definition without a destination authorized a
		// hidden label); the definition reader is deleted.
		"A9-2/R9-3 definition without a destination": install + "\nThe release ships [the][six] archives.\n\n[six]:\n",
		"P9 full reference with a definition":        install + "\nThe release ships [the][six] archives.\n\n[six]: https://example.com/x\n",
		"P9 full reference (round-8 precision)":      install + "\nThe release ships [the][Four] archives.\n\n[four]: https://example.com/x\n",
		"P9 collapsed reference with a definition":   install + "\nThe release ships [six][] archives.\n\n[six]: https://example.com/x\n",
		"P9 definition alone":                        install + "\n[four]: https://example.com/x\n",
		"P9 definition indented three spaces":        install + "\n   [four]: https://example.com/x\n",
		"P9 definition in a block quote":             install + "\n> [four]: https://example.com/x\n",
		"P9 definition in a list item":               install + "\n- [four]: https://example.com/x\n",
		"P9 definition label across a line break":    install + "\n[si\nx]: https://example.com/x\n",
		"P9 full reference in a table row":           install + "\n| [a][b] | four archives |\n",
		"P9 definition with a title naming Windows":  install + "\n[x]: https://example.com/x \"Windows\"\n",
		"P9 shortcut reference with a definition":    install + "\nThe release ships [six] archives.\n\n[six]: https://example.com/x\n",
		// Nested links are refused (R9-4: CommonMark leaves the outer link's suffix as text, the reader hid it).
		"R9-4 nested link hides a count":           install + "\nRelease archives: [[count](x)](six).\n",
		"P9 link inside link text":                 install + "\nRelease archives: [a [b](c) d](six).\n",
		"P9 three nested links":                    install + "\nRelease archives: [[[a](b)](c)](six).\n",
		"P9 unclosed opener before a link":         install + "\nEvery release ships [x [y](z) archives.\n",
		"P9 nested link splits Windows":            install + "\nNative binaries for Win[[do](x)](ws) are attached.\n",
		"P9 nested link around a count":            install + "\nEvery release ships [[four](x)](six) archives.\n",
		"P9 nested link inside emphasis":           install + "\nRelease archives: [**[count](x)**](six).\n",
		"P9 nested link with a title":              install + "\nRelease archives: [[count](x \"t\")](six).\n",
		"P9 nested link inside a code span":        install + "\nRelease archives: [`[count](x)`](six).\n",
		"P9 nested link with a space before":       install + "\nRelease archives: [[count](x)] (six).\n",
		"P9 nested link with an angle destination": install + "\nRelease archives: [[count](x)](<six>).\n",
		// A math sign in a count clause is refused, not interpreted (R9-5: "4+Linux" and "≥(4)" escaped the sign
		// rewriting); every earlier bound mutant stays refused.
		"R9-5 plus joined to a word":                install + "\nThe release ships 4+Linux archives.\n",
		"R9-5 sign before a parenthesis":            install + "\nRelease archives: ≥(4).\n",
		"P9 greater-than before a parenthesis":      install + "\nRelease archives: >(4).\n",
		"P9 fullwidth greater-than":                 install + "\nRelease archives: ＞4.\n",
		"P9 greater-than over equal":                install + "\nRelease archives: ≧ 4.\n",
		"P9 slanted greater-or-equal":               install + "\nRelease archives: ⩾4.\n",
		"P9 less-than before a digit":               install + "\nRelease archives: <4.\n",
		"P9 almost-equal sign":                      install + "\nRelease archives: ≈ 4.\n",
		"P9 plus-minus":                             install + "\nRelease archives: 4±0.\n",
		"P9 plus joined to a number word":           install + "\nThe release ships four+Linux archives.\n",
		"P9 plus between words (round-8 precision)": install + "\nThe four archives cover `linux/amd64` + `linux/arm64`.\n",
		"P9 equals sign":                            install + "\nRelease archives: = 4.\n",
		"P9 sign inside parentheses":                install + "\nRelease archives: (≥4).\n",
		"P9 plus between digits":                    install + "\nThe release ships 4 + 0 archives.\n",
		// "no" after the archive noun in its clause is a count of zero (R9-6).
		"R9-6 no after the noun":       install + "\nRelease archives: no.\n",
		"P9 no after the noun, plain":  install + "\nThe archives: no.\n",
		"P9 no after a singular noun":  install + "\nRelease archive: no.\n",
		"P9 no after a dash":           install + "\nRelease archives — no.\n",
		"P9 no in bold":                install + "\nRelease archives: **no**.\n",
		"P9 no split by emphasis":      install + "\nRelease archives: n**o**.\n",
		"P9 no in capitals":            install + "\nRelease archives: NO.\n",
		"P9 no as link text":           install + "\nRelease archives: [no](x).\n",
		"P9 no after a verb":           install + "\nArchives shipped: no.\n",
		"P9 no after a comma":          install + "\nRelease archives, no.\n",
		"P9 no followed by more words": install + "\nRelease archives: no, never.\n",
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
		"All four of the release archives are signed.",
		"Two of the four archives are FIPS builds.",
		"Pick one of the archives; two of them are arm64 builds.",
		"Every release ships four signed, static, stripped, reproducible, verified Linux release archives.",
		"Every release ships four [archives](https://example.com/v2/4).",
		"See https://example.com/v6 for the four archives.",
		"All of the four archives are signed.",
		// Round-5 precision (A4, B2): a link destination or title is not visible text, so a count in it is not read;
		// a destination with balanced parentheses ends at its own closing parenthesis.
		"Every release ships [four](six-archives.md) archives.",
		"Every release ships [four](https://example.com/a(6)) archives.",
		"Every release ships [four](https://example.com/a \"six)\") archives.",
		"Release archives: four.",
		"Two of the four archives are FIPS builds; each release ships all four archives.",
		"Run `kubectl exec -it POD_NAME -- sh` to look inside the four archives' container.",
		// Round-6 precision (A2, A3): an exception marker ending its line, or on a line of its own, passes; "no archive
		// for this machine" is not a count. Round 7: a placeholder written as a word passes in a fence.
		"The version is pinned for all four archives. <!-- pinned: upstream -->",
		"The version is pinned for all four archives.\n<!-- pinned: historical -->",
		"   ```sh\n   kubectl exec -it POD_NAME -- sh\n   ```",
		// Round-7 precision: the allowed "no archive for this machine" (docs/install.md:57's form) and an escaped
		// parenthesis in a destination pass.
		"If it prints anything else, there is no archive for this machine; run the container.",
		"Every release ships [four](https://example.com/a\\(b) archives.",
		// Round-8 precision: a parenthesized title without a nested "(" is read. (The round-8 precision cases for a
		// defined reference label and a "+" between words are refused since the post-9 round: see the mutants.)
		"Every release ships [four](https://example.com/a (a title)) archives.",
		// Post-9 precision: a single tilde as plain text outside a count clause ("~5 GB", "~/.gradle"), adjacent links,
		// "no" before a word that is not an archive, and a math sign in a clause without an archive count pass.
		"Size it from your eviction cap plus ~20% headroom.",
		"rm -rf ~/.gradle/caches/build-cache-1",
		"See [this](x) and [that](y) for the four archives.",
		"There is no shortcut; download the four archives.",
		"The cap is a + b bytes; each release ships four archives.",
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

// notesFile is the next release's notes; notesSentence is the one platform mention they may carry, and only as
// the start of an entry that ends with notesCitation; changelogFile is the durable release record the release
// flow moves published entries into.
const (
	notesFile     = "docs/next-release-notes.md"
	notesSentence = "No macOS or Windows binaries are shipped; use the container image."
	notesCitation = "(owner decision, Oct 9; advisor 0390)."
	changelogFile = "docs/quality/releases/CHANGELOG.md"
)

// bulletEntries are the entries of a notes or changelog text, read on plain lines (no Markdown structure, no fence
// concept): a line starting "- " or "* " after optional indentation (spaces or tabs) opens one, and each following
// non-blank line indented two spaces that opens none continues it, joined by a space (as bin/patch-decide.py joins
// continuation lines).
func bulletEntries(text string) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		item := strings.TrimLeft(ln, " \t")
		switch {
		case strings.HasPrefix(item, "- ") || strings.HasPrefix(item, "* "):
			out = append(out, strings.TrimSpace(item[2:]))
		case len(out) > 0 && strings.HasPrefix(ln, "  ") && strings.TrimSpace(ln) != "":
			out[len(out)-1] += " " + strings.TrimSpace(ln)
		}
	}
	return out
}

// linuxOnly counts, in a notes or changelog text, the entries that state the Linux-only sentence in the one form
// the release flow publishes (an entry starting exactly with notesSentence, raw, and ending exactly with
// notesCitation), and the mentions of the sentence anywhere in its plain text (a paragraph, a prefixed or emphasized
// bullet, an entry with another citation).
func linuxOnly(text string) (entries, mentions int) {
	for _, e := range bulletEntries(text) {
		if strings.HasPrefix(e, notesSentence) && strings.HasSuffix(e, notesCitation) {
			entries++
		}
	}
	for _, u := range units(text) {
		mentions += strings.Count(plainText(u.text), notesSentence)
	}
	return entries, mentions
}

// checkNotes returns every reason the next release notes fail REQ-PLAT-001, given the notes text and the
// changelog text ("" for a file that does not exist). The whole notes file is checked as a scanned doc whose
// only allowed text is notesSentence, matched exactly. The sentence may be in the notes only as one entry that
// starts with it and ends with notesCitation, and nowhere else. When that entry is not in them, the release flow
// has published it and removed it (bin/patch-decide.py changelog): the changelog, the durable record of what was
// published, must then carry such an entry; nowhere at all is refused. In the changelog too the sentence may appear
// only as such entries (its mentions equal its cited entries), on either path.
func checkNotes(text, changelog string, archives int) []string {
	problems, _ := checkDoc(notesFile, text, []allowedLine{{notesFile, notesSentence, "the REQ-PLAT-001 release-notes line", false}}, archives)
	entries, mentions := linuxOnly(text)
	switch {
	case mentions != entries:
		problems = append(problems, fmt.Sprintf("%s says %q outside an entry that starts with it and ends with %q (%d mentions, %d such entries)", notesFile, notesSentence, notesCitation, mentions, entries))
	case entries > 1:
		problems = append(problems, fmt.Sprintf("%s says %q %d times, want at most once", notesFile, notesSentence, entries))
	}
	// The changelog fallback is read for the sentence only, so the forms that would hide or rewrite what it shows are
	// refused in it outright: strikethrough, every reference-style link form and a link form linkParts does not read.
	problems = append(problems, proseFormProblems(func(n int) string { return fmt.Sprintf("%s:%d", changelogFile, n) }, changelog)...)
	for _, u := range units(changelog) {
		if _, _, ok := linkParts(u.text); !ok {
			problems = append(problems, linkProblem(fmt.Sprintf("%s:%d", changelogFile, u.line), u.text))
		}
	}
	published, pmentions := linuxOnly(changelog)
	if pmentions != published {
		problems = append(problems, fmt.Sprintf("%s says %q outside an entry that starts with it and ends with %q (%d mentions, %d such entries)", changelogFile, notesSentence, notesCitation, pmentions, published))
	}
	if entries == 0 && published == 0 {
		problems = append(problems, fmt.Sprintf("neither %s nor %s has an entry that starts %q and ends %q (the notes until it is published, then the changelog)", notesFile, changelogFile, notesSentence, notesCitation))
	}
	return problems
}

// proves: REQ-PLAT-001-AC1
// TestNextReleaseNotesSayLinuxOnly: the next release's notes say, exactly once, that no macOS or Windows
// binaries are shipped and point to the container image, or, once the release flow has published that entry
// and removed it from the notes, the changelog says so; nothing else in the notes names a non-Linux platform
// or claims an archive count other than the one .goreleaser.yaml produces.
func TestNextReleaseNotesSayLinuxOnly(t *testing.T) {
	for _, p := range checkNotes(readOptional(t, notesFile), readOptional(t, changelogFile), releaseArchiveCount(t)) {
		t.Error(p)
	}
}

// notesFixture is a notes file of the repository's shape carrying the Linux-only entry. The mutants are made
// from it, not from the repository's file, so they stay meaningful after the release flow publishes the entry
// and clears it from the notes.
const notesFixture = "# Notes for the next release\n\nBehavior changes since the last release, carried into its notes. Each entry ends by\n" +
	"citing that handoff (advisor 0130).\n\n- Go 1.27: a request with more than 500 header values is rejected with 431\n" +
	"  before it reaches the cache (owner accepted; advisor 0115).\n- " + notesSentence + " The release archives are fscache and\n" +
	"  fscache-fips for linux/amd64 and linux/arm64 (owner decision, Oct 9; advisor 0390).\n"

// proves: REQ-PLAT-001-AC1
// TestNextReleaseNotesCheckRefusesMutants: a second line claiming a macOS binary (also split by a nested link
// destination; inline HTML, character references and invisible characters are refused outright), a changed or
// missing required sentence, the sentence outside an entry that starts with it and ends with the 0390 citation
// (a paragraph, a prefixed or emphasized bullet, another citation), a repeated sentence, a wrong archive count and the
// post-9 forms (strikethrough, a reference-style link or definition, a nested link, a math sign in a count clause, "no"
// after the noun) are each refused; notes cleared after publication pass only while the changelog carries the cited
// entry, read on plain lines ("- " or "* " after optional indentation; no fence concept, so a fenced bullet line is an
// entry), only while the sentence appears in the changelog nowhere but in such entries, and only while the changelog
// holds no strikethrough (a tilde fence included), no reference-style link form and no link form the check does not
// read (a nested link hiding an uncited sentence).
func TestNextReleaseNotesCheckRefusesMutants(t *testing.T) {
	notes := notesFixture
	if ps := checkNotes(notes, "", releaseArchiveCount(t)); len(ps) > 0 {
		t.Fatalf("the notes fixture is refused: %v", ps)
	}
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
		"html inside the count":             notes + "- The release ships si<b>x</b> archives.\n",
		"html inside Windows":               notes + "- A signed installer for Win<i>dows</i> ships with this release.\n",
		// Round-4 regressions (A1, A2): unlisted elements, comments and character references inside a name; a
		// total that disagrees with its whole.
		"unlisted element inside Windows":    notes + "- A signed installer for Win<label>dows</label> ships with this release.\n",
		"character reference inside Windows": notes + "- A signed installer for Win&#100;ows ships with this release.\n",
		"comment inside Windows":             notes + "- A signed installer for Win<!--x-->dows ships with this release.\n",
		"all six of the four archives":       notes + "- All six of the four archives are signed.\n",
		// Round-5 regressions (B5, B2, A2): the sentence counts only as the start of a notes entry that ends with
		// the 0390 citation; anywhere else (a paragraph, a prefixed or emphasized bullet, another citation) it is
		// refused. A nested link destination splitting a name, and invisible characters, are refused.
		"sentence as an uncited paragraph":  strings.Replace(notes, "- "+notesSentence+" The release archives are fscache and\n  fscache-fips for linux/amd64 and linux/arm64 (owner decision, Oct 9; advisor 0390).\n", "\n"+notesSentence+"\n", 1),
		"sentence in a prefixed bullet":     strings.Replace(notes, "- "+notesSentence, "- Note: "+notesSentence, 1),
		"sentence in an emphasized bullet":  strings.Replace(notes, "- "+notesSentence, "- **"+notesSentence+"**", 1),
		"sentence with another citation":    strings.Replace(notes, "(owner decision, Oct 9; advisor 0390)", "(advisor 0130)", 1),
		"sentence entry without a citation": strings.Replace(notes, " (owner decision, Oct 9; advisor 0390)", "", 1),
		"nested destination splits Windows": notes + "- A signed installer for Win[do](https://example.com/a(b))ws ships with this release (advisor 0130).\n",
		"joiner splits Windows":             notes + "- A signed installer for Win͏dows ships with this release (advisor 0130).\n",
		"image tag splits Windows":          notes + "- A signed installer for Win<img alt=\"\">dows ships with this release (advisor 0130).\n",
		// Round-6 regressions (A2, B4, A1): an exception marker inside a line splits nothing; a pseudo-fence hides
		// nothing.
		"marker splits Windows":            notes + "- A signed installer for Win<!-- pinned: upstream -->dows ships with this release (advisor 0130).\n",
		"marker splits six":                notes + "- The release ships si<!-- pinned: upstream -->x archives (advisor 0130).\n",
		"indented pseudo-fence hides html": notes + "\n    ```\n\n- A signed installer for Win<b>dows</b> ships with this release (advisor 0130).\n",
		// Round-7 decision (advisor, final): no Markdown structure is read; a tag-like "<" is refused anywhere (the
		// A7-1/B7-1, A7-2/B7-1 and B7-2 shapes, and a placeholder in a code span or fence); an entry is a plain line,
		// so a "* " or indented entry with another citation is the sentence outside the cited entry.
		"A7-1/B7-1 list fence hides Windows html": notes + "- An example (advisor 0130).\n  ```\n  harmless\n\nWin<b>dows</b> binaries are shipped.\n```\n",
		"A7-2/B7-1 heading code span hides html":  notes + "\n# `\nWin<b>dows</b> binaries are shipped.\n`\n",
		"B7-2 marker between code spans":          notes + "- A signed installer for `Win`<!-- pinned: upstream -->`dows` ships with this release (advisor 0130).\n",
		"placeholder in a fence":                  notes + "\n```sh\nkubectl exec -it <pod> -- sh\n```\n",
		"star entry with another citation":        notes + "* " + notesSentence + " (advisor 0130).\n",
		"indented entry with another citation":    notes + "  - " + notesSentence + " (advisor 0130).\n",
		// Post-9 round (scope cut): strikethrough, reference-style links, nested links, a math sign in a count clause and
		// "no" after the archive noun are refused in the notes as in the docs.
		"R9-1 strikethrough splits six":  notes + "- The release ships si~~x~~ archives (advisor 0130).\n",
		"P9 reference link":              notes + "- The release ships [the][six] archives (advisor 0130).\n\n[six]:\n",
		"P9 definition":                  notes + "\n[six]: https://example.com/x\n",
		"R9-4 nested link hides a count": notes + "- Release archives: [[count](x)](six) (advisor 0130).\n",
		"R9-5 plus joined to a word":     notes + "- The release ships 4+Linux archives (advisor 0130).\n",
		"R9-6 no after the noun":         notes + "- Release archives: no (advisor 0130).\n",
		"P9 single-tilde strikethrough":  notes + "- The release ships si~x~ archives (advisor 0130).\n",
	}
	for name, text := range mutants {
		if text == notes {
			t.Fatalf("mutant %q does not change the notes", name)
		}
		ps := checkNotes(text, "", archives)
		if len(ps) == 0 {
			t.Errorf("mutant %q passes the release-notes check", name)
		}
		t.Logf("%s: refused: %v", name, ps)
	}
	// Round-4 regression (B2): the release flow publishes the entry into the changelog and removes it from the
	// notes (bin/patch-decide.py changelog). The cleared notes pass when the changelog carries the sentence, and
	// are refused when nothing carries it.
	start := strings.Index(notes, "- "+notesSentence)
	if start < 0 {
		t.Fatalf("%s holds no entry starting %q", notesFile, notesSentence)
	}
	end := strings.Index(notes[start+2:], "\n- ")
	entry := notes[start:]
	if end >= 0 {
		entry = notes[start : start+2+end+1]
	}
	cleared := strings.Replace(notes, entry, "", 1)
	published := "# Changelog\n\n## v0.3.1 — patch release\n\n### Behavior changes\n" + strings.TrimRight(entry, "\n") + "\n"
	if ps := checkNotes(cleared, published, archives); len(ps) > 0 {
		t.Errorf("the notes after publication and cleanup are refused although the changelog carries the sentence: %v", ps)
	}
	if ps := checkNotes("", published, archives); len(ps) > 0 {
		t.Errorf("a removed notes file is refused although the changelog carries the sentence: %v", ps)
	}
	if ps := checkNotes(cleared, "", archives); len(ps) == 0 {
		t.Errorf("the notes without the sentence pass with no changelog carrying it")
	}
	if ps := checkNotes(cleared, "# Changelog\n\n- Linux only (advisor 0390).\n", archives); len(ps) == 0 {
		t.Errorf("the notes without the sentence pass with a changelog that does not carry it")
	}
	if ps := checkNotes(notes, published, archives); len(ps) > 0 {
		t.Errorf("the notes and the changelog both carrying the sentence are refused: %v", ps)
	}
	// Round-5 regression (B5): the changelog carries the sentence only as a published entry that ends with the
	// 0390 citation; an uncited paragraph or an entry with another citation does not count.
	for name, cl := range map[string]string{
		"an uncited changelog paragraph":       "# Changelog\n\n## v0.3.1 — patch release\n\n" + notesSentence + "\n",
		"a changelog entry with another cite":  "# Changelog\n\n## v0.3.1 — patch release\n\n### Behavior changes\n- " + notesSentence + " (advisor 0130).\n",
		"a prefixed changelog entry":           "# Changelog\n\n## v0.3.1 — patch release\n\n### Behavior changes\n- Note: " + strings.TrimPrefix(strings.TrimRight(entry, "\n"), "- ") + "\n",
		"a changelog entry split by a joiner":  strings.Replace(published, "macOS", "mac͏OS", 1),
		"a changelog entry with no line start": "# Changelog\n\nSee: - " + strings.TrimPrefix(strings.TrimRight(entry, "\n"), "- ") + "\n",
		// Round-8 regression (A8-3) and self-review: beside a valid cited changelog entry, the sentence anywhere else in
		// the changelog (an uncited paragraph, an entry with another citation, a prefixed or emphasized bullet, a second
		// cited entry's sentence inside another entry) is refused, as in the notes.
		"A8-3 a cited entry and an uncited paragraph":   published + "\n" + notesSentence + "\n",
		"N8 a cited entry and another citation":         published + "- " + notesSentence + " (advisor 0130).\n",
		"N8 a cited entry and a prefixed bullet":        published + "- Note: " + notesSentence + "\n",
		"N8 a cited entry and an emphasized bullet":     published + "- **" + notesSentence + "**\n",
		"N8 a cited entry and the sentence mid-entry":   published + "- Packaging changed. " + notesSentence + " (owner decision, Oct 9; advisor 0390).\n",
		"N8 a cited entry and the sentence in a header": published + "\n## " + notesSentence + "\n",
		// Post-9 round (scope cut): the changelog fallback refuses the same forms outright (R9-4: a nested link hid an
		// uncited, visibly rendered sentence; a link form the reader does not read is refused), and a tilde fence is
		// strikethrough's "~~".
		"R9-4 a nested link hides an uncited sentence":     published + "[[entry](x)](y \"" + notesSentence + "\")\n",
		"P9 a nested link around the sentence":             published + "[[a](b) " + notesSentence + "](c)\n",
		"P9 a link with no opener in the changelog":        published + "x](" + notesSentence + ")\n",
		"P9 strikethrough in the changelog":                published + "- ~~Old entry~~ (advisor 0130).\n",
		"P9 a reference link in the changelog":             published + "- [the][x] (advisor 0130).\n\n[x]: https://example.com\n",
		"P9 a definition title holds the sentence":         published + "\n[x]: https://example.com \"" + notesSentence + "\"\n",
		"P9 a tilde-fenced changelog entry (was accepted)": "# Changelog\n\n~~~text\n" + strings.TrimRight(entry, "\n") + "\n~~~\n",
	} {
		if ps := checkNotes(cleared, cl, archives); len(ps) == 0 {
			t.Errorf("the cleared notes pass with %s", name)
		}
	}
	if ps := checkNotes(notes, published+"\n"+notesSentence+"\n", archives); len(ps) == 0 {
		t.Errorf("an uncited changelog mention passes while the notes still carry the entry")
	}
	// Round-7 decision (advisor, final): the checks read no Markdown structure, so an entry is a plain line: a line
	// starting "- " or "* " after optional indentation, whatever surrounds it (a fence line is plain text). These
	// changelogs carry the cited entry as such a line and pass (A7-3/B7-4: an entry inside an unclosed or closed fence
	// is read as a plain-line entry, by decision).
	for name, cl := range map[string]string{
		"a fenced changelog entry":            "# Changelog\n\n## v0.3.1 — patch release\n\n```\n" + strings.TrimRight(entry, "\n") + "\n```\n",
		"an unclosed-fence changelog entry":   "# Changelog\n\n```text\n" + strings.TrimRight(entry, "\n") + "\n",
		"a star changelog entry":              "# Changelog\n\n* " + strings.TrimPrefix(strings.TrimRight(entry, "\n"), "- ") + "\n",
		"an indented changelog entry":         "# Changelog\n\n  - " + strings.TrimPrefix(strings.TrimRight(entry, "\n"), "- ") + "\n",
		"a tab-indented star changelog entry": "# Changelog\n\n\t* " + strings.TrimPrefix(strings.TrimRight(entry, "\n"), "- ") + "\n",
	} {
		if ps := checkNotes(cleared, cl, archives); len(ps) > 0 {
			t.Errorf("the cleared notes are refused with %s: %v", name, ps)
		}
	}
}

// mappingsFile is the AC-to-evidence mappings file.
const mappingsFile = "test-evidence/mappings.yaml"

// packageTests returns the names of the test functions declared in this package's test files.
func packageTests(t *testing.T) map[string]bool {
	t.Helper()
	return testsInDir(t, ".")
}

// verifyPlatforms are the platforms the tests run on to verify a release: a test counts as evidence only if
// the go tool selects its file on every one of them.
var verifyPlatforms = [][2]string{{"linux", "amd64"}, {"linux", "arm64"}}

// targetToolTags are the go tool's feature tags for a build for goarch: the toolchain's GOEXPERIMENT tags (they
// are the toolchain's, whatever the target) and the target's architecture level tags at their defaults (GOAMD64=v1:
// amd64.v1; GOARM64=v8.0: arm64.v8.0), never the host's (build.Default carries the host architecture's).
func targetToolTags(goarch string) []string {
	var tags []string
	for _, tag := range build.Default.ToolTags {
		if strings.HasPrefix(tag, "goexperiment.") {
			tags = append(tags, tag)
		}
	}
	return append(tags, map[string]string{"amd64": "amd64.v1", "arm64": "arm64.v8.0"}[goarch])
}

// testsInDir returns the names of the test functions declared in the test files of the package in dir that
// the go tool selects (TestGoFiles and XTestGoFiles, after build constraints and file-name GOOS/GOARCH
// suffixes, with the target's architecture feature tags) on every one of verifyPlatforms. A file it ignores (//go:build ignore, a _windows_test.go file, a
// constraint for one architecture) declares nothing; a directory the go tool cannot read fails the test.
func testsInDir(t *testing.T, dir string) map[string]bool {
	t.Helper()
	var tests map[string]bool
	for _, pl := range verifyPlatforms {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = pl[0], pl[1], false
		ctx.ToolTags = targetToolTags(pl[1])
		pkg, err := ctx.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("the go tool cannot read %s for %s/%s: %v", dir, pl[0], pl[1], err)
		}
		found := map[string]bool{}
		for _, name := range append(append([]string{}, pkg.TestGoFiles...), pkg.XTestGoFiles...) {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			for test := range declaredTests(t, name, string(b)) {
				found[test] = true
			}
		}
		if tests == nil {
			tests = found
			continue
		}
		for test := range tests {
			if !found[test] {
				delete(tests, test)
			}
		}
	}
	return tests
}

// isTestName is go test's rule for a test function name (go help testfunc): Test, or Test followed by a
// character that is not a lower-case letter. go test does not run Testdarwin.
func isTestName(name string) bool {
	if !strings.HasPrefix(name, "Test") {
		return false
	}
	r, _ := utf8.DecodeRuneInString(name[len("Test"):])
	return len(name) == len("Test") || !unicode.IsLower(r)
}

// declaredTests returns the names of the test functions declared in one Go source file, read by the Go
// parser: a top-level function (no receiver, no type parameters, no results) named as isTestName says, with exactly one
// parameter of type *testing.T. A function inside a comment or a string is not a declaration and is not read.
func declaredTests(t *testing.T, file, src string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	tests := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Type.TypeParams != nil || fd.Type.Results != nil || !isTestName(fd.Name.Name) {
			continue
		}
		params := fd.Type.Params.List
		if len(params) != 1 || len(params[0].Names) > 1 {
			continue
		}
		star, ok := params[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "testing" && sel.Sel.Name == "T" {
			tests[fd.Name.Name] = true
		}
	}
	return tests
}

// platformsTestRef is an exact go-test reference to a test of this package.
var platformsTestRef = regexp.MustCompile(`^internal/platforms:(Test[A-Za-z0-9_]+)$`)

// mappingsReadings are the texts the mappings check reads one piece of YAML text as; every one must be
// clean: the literal text (whitespace collapsed, nothing removed, so a name inside a link destination or quotes is
// read); the text with every # removed (so a name wrapped across comment lines, "# Apple" then "# Silicon", is read
// joined); and the plain-text reading of each (plainText: link destinations removed, inline marks removed, so
// Win[do](https://example.com/a(b))ws and Win**dows** are read joined). The content guard has refused inline HTML,
// character references and invisible characters in the raw text and in every decoded value.
func mappingsReadings(s string) []string {
	noHash := strings.ReplaceAll(s, "#", "")
	return []string{collapse(s), collapse(noHash), plainText(s), plainText(noHash)}
}

// checkEvidenceMappings returns every platform name in the evidence mappings outside an exact reference to
// one of this package's tests. The file is read twice and both readings must be clean: decoded by a YAML
// loader (every document; every key, value, anchor, tag and comment, so a quoted, escaped, folded or wrapped
// scalar is read as the text it means), and as raw text (so nothing the loader drops escapes); each is read
// in every one of mappingsReadings, and a link form linkParts does not read is refused (as checkDoc refuses it). The one exception is the whole value of `ref` in an evidence item whose
// `type` is `go-test`, when that value is exactly internal/platforms:<name> and tests holds name. The content
// guard reads the raw text and every decoded comment and value first, and refuses inline HTML, character
// references, invisible characters, strikethrough and every reference-style link form outright (the allowed
// placeholder only in its leading comment line, never in a decoded key, value, anchor or tag). Before anything is
// decoded, the raw-text tag scan (yamlTagProblems) refuses every "!" (any explicit tag, !!str included) and a YAML
// directive; a !!binary scalar's decoded text is read as well.
func checkEvidenceMappings(text string, tests map[string]bool) (problems []string) {
	reported := map[string]bool{}
	scan := func(where, s string) {
		for _, v := range []string{s, strings.ReplaceAll(s, "#", "")} {
			if _, _, ok := linkParts(v); !ok {
				p := linkProblem(where, v)
				if !reported[p] {
					reported[p] = true
					problems = append(problems, p)
				}
			}
		}
		for _, r := range mappingsReadings(s) {
			for _, loc := range platformWord.FindAllStringIndex(r, -1) {
				from, to := max(0, loc[0]-60), min(len(r), loc[1]+60)
				p := fmt.Sprintf("%s names %q: ...%s...", where, r[loc[0]:loc[1]], r[from:to])
				if !reported[p] {
					reported[p] = true
					problems = append(problems, p)
				}
			}
		}
	}
	problems = append(contentProblems(mappingsFile, text), yamlTagProblems(mappingsFile, text)...)
	docs, err := yamlDocs(text)
	if err != nil {
		return append(problems, mappingsFile+": the YAML loader cannot read it: "+err.Error())
	}
	exempt := map[string]bool{} // the exact references excepted
	var walk func(n *yaml.Node, skip bool)
	walk = func(n *yaml.Node, skip bool) {
		where := fmt.Sprintf("%s:%d", mappingsFile, n.Line)
		comments := n.HeadComment + "\n" + n.LineComment + "\n" + n.FootComment
		decoded := comments + " \n " + n.Anchor + " \n " + n.Tag
		value := n.Value
		if n.Tag == "!!binary" {
			// a binary scalar means its decoded bytes (the explicit tag is refused by name): read those
			b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(n.Value), ""))
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: a !!binary scalar that cannot be decoded: %v", where, err))
			}
			value += " \n " + string(b)
		}
		// a decoded value can hold what the raw text spells as an escape ("\u200B", "\x3C"): guard it too. The
		// allowed placeholder is excepted only in a decoded comment line at its place; a key, value, anchor or tag
		// gets no exception.
		decodedWhere := func(int) string { return where + " (decoded YAML)" }
		problems = append(problems, guardText(decodedWhere, markupFor(mappingsFile), comments)...)
		problems = append(problems, guardText(decodedWhere, nil, n.Anchor+" \n "+n.Tag+" \n "+value)...)
		scan(where, decoded)
		if !skip {
			scan(where, value)
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
// is, once the YAML is decoded: in a fabricated or misplaced test reference (a commented-out test function, or one
// go test does not run, authorizes none), in prose, in a quoted, escaped or folded scalar that wraps the name
// across lines, split by a nested link destination, in a comment or wrapped across comment lines, and in a second
// document; inline HTML, character references and invisible characters (raw or as a YAML escape) are refused
// outright; a test declared only in a file the go tool does not select for linux/amd64 and linux/arm64 (with the
// target's architecture feature tags) authorizes no reference; a link form the plain-text reading does not read (an
// angle-bracket destination) is refused; the placeholder outside its leading comment line (a value, a key, an anchor,
// a later, indented or line comment), any "!" in the raw text (every explicit YAML tag, !!str and a bare "!" included,
// and a "!" in a quoted scalar or a comment: the raw scan runs before decoding; a !!binary scalar's decoded text is read
// too), a YAML directive, strikethrough, a reference-style link form and a nested link are refused.
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
		// Round-3 regressions (both seats): inline HTML inside a word, a bracketed name, comments wrapped.
		{"html tag inside Windows", edit(plat2, "so a missing variant/arch fails; Win<b>dows</b> is the documented equivalent\" }\n"), "inline HTML"},
		{"html tag starts Windows", edit(plat2, "so a missing variant/arch fails; <b>Win</b>dows is the documented equivalent\" }\n"), "inline HTML"},
		{"bracketed windows", edit(plat2, "so a missing variant/arch fails; <windows> is the documented equivalent\" }\n"), "windows"},
		{"comment wraps Apple Silicon", edit(lastRef, lastRef+"      # Apple\n      # Silicon binaries are available.\n"), "Apple"},
		{"comment wraps OS X", edit(lastRef, lastRef+"      # runs on OS\n      # X hosts\n"), "OS"},
		{"line comment wraps Apple Silicon", edit(lastRef, lastRef+"      - { type: inspection, ref: x } # Apple\n      # Silicon binaries\n"), "Apple"},
		// Round-4 regressions (A1, B3): character references, unlisted elements, comments and a quoted ">" inside
		// an attribute, each inside a name.
		{"character reference inside Windows", edit(plat2, "so a missing variant/arch fails; Win&#100;ows is the documented equivalent\" }\n"), "character reference"},
		{"named reference inside Apple Silicon", edit(plat2, "so a missing variant/arch fails; Apple&nbsp;Silicon is the documented equivalent\" }\n"), "character reference"},
		{"unlisted element inside Windows", edit(plat2, "so a missing variant/arch fails; Win<label>dows</label> is the documented equivalent\" }\n"), "inline HTML"},
		{"comment inside Windows", edit(plat2, "so a missing variant/arch fails; Win<!--x-->dows is the documented equivalent\" }\n"), "inline HTML"},
		{"quoted > in an attribute", edit(plat2, "so a missing variant/arch fails; Win<span title='>'>dows</span> is the documented equivalent\" }\n"), "inline HTML"},
		{"character reference in a comment", edit(lastRef, lastRef+"      # Win&#x64;ows is a documented equivalent\n"), "character reference"},
		// Round-5 regressions (B2, A2, B3): a nested link destination splitting a name; an invisible character
		// (raw, or written as a YAML escape the loader decodes, or as an entity) and inline HTML anywhere are
		// refused outright, naming the line.
		{"nested destination splits Windows", edit(plat2, "so a missing variant/arch fails; Win[do](https://example.com/a(b))ws is the documented equivalent\" }\n"), "Windows"},
		{"joiner splits Windows", edit(plat2, "so a missing variant/arch fails; Win͏dows is the documented equivalent\" }\n"), "invisible"},
		{"YAML escape decodes to a joiner", edit(plat2, "so a missing variant/arch fails; Win\\u034Fdows is the documented equivalent\" }\n"), "invisible"},
		{"YAML escape decodes to a zero-width space", edit(plat2, "so a missing variant/arch fails; Win\\u200Bdows is the documented equivalent\" }\n"), "invisible"},
		{"YAML escape decodes to a tag", edit(plat2, "so a missing variant/arch fails; Win\\x3Cb>dows is the documented equivalent\" }\n"), "inline HTML"},
		{"entity for a joiner", edit(plat2, "so a missing variant/arch fails; Win&#x034F;dows is the documented equivalent\" }\n"), "character reference"},
		{"image tag splits Windows", edit(plat2, "so a missing variant/arch fails; Win<img alt=''>dows is the documented equivalent\" }\n"), "inline HTML"},
		// Round-7 regression (A7-4): a link form the plain-text reading does not read (an angle-bracket destination)
		// is refused in the mappings as in the docs.
		{"A7-4 angle-bracket destination splits Windows", edit(plat2, "so a missing variant/arch fails; Win[do](<./a)b>)ws is the documented equivalent\" }\n"), "link this check does not read"},
		{"A7-4 angle-bracket destination in a comment", edit(lastRef, lastRef+"      # Win[do](<./a)b>)ws is a documented equivalent\n"), "link this check does not read"},
		// Round-8 regressions (A8-1/B8-3, B8-1): the placeholder exception holds only on a whole-line comment at column 0
		// in the file's leading comment block, never in a value; any explicit YAML tag other than !!str is refused by name
		// (a !!binary scalar decodes to text the raw value does not show), and a binary scalar's decoded text is read.
		{"A8-1 placeholder in a value", edit(lastRef, lastRef+"      - { type: inspection, ref: x, note: '\"<package dir>:<TestName>\"' }\n"), "inline HTML"},
		{"B8-3 placeholder as a ref", edit(lastRef, lastRef+"      - { type: inspection, ref: '\"<package dir>:<TestName>\"' }\n"), "inline HTML"},
		{"B8-1 !!binary decodes to a tag", edit(lastRef, lastRef+"      - { type: inspection, ref: !!binary PGI+ }\n"), "explicit YAML tag"},
		{"B8-1 !!binary decodes to Windows", edit(lastRef, lastRef+"      - { type: inspection, ref: !!binary V2luZG93cw== }\n"), "Windows"},
		// Round-8 self-review (the marker and YAML-decoding family): neighbour shapes, each refused.
		{"N8 !!binary tag named", edit(lastRef, lastRef+"      - { type: inspection, ref: !!binary V2luZG93cw== }\n"), "explicit YAML tag"},
		{"N8 local !binary tag", edit(lastRef, lastRef+"      - { type: inspection, ref: !binary V2luZG93cw== }\n"), "explicit YAML tag"},
		{"N8 !!binary block scalar", edit(lastRef, lastRef+"      - type: inspection\n        ref: !!binary |\n          V2luZG93cw==\n"), "explicit YAML tag"},
		{"N8 !!binary key", edit(lastRef, lastRef+"      - { type: inspection, ref: x, !!binary V2luZG93cw==: y }\n"), "explicit YAML tag"},
		{"N8 tagged mapping", edit(lastRef, lastRef+"      - !!map { type: inspection, ref: x }\n"), "explicit YAML tag"},
		{"N8 !!binary that is not base64", edit(lastRef, lastRef+"      - { type: inspection, ref: !!binary \"%%%\" }\n"), "cannot be decoded"},
		{"N8 %TAG directive", "%TAG !! tag:example.com,2000:\n---\n" + real, "directive"},
		{"N8 placeholder in a key", edit(lastRef, lastRef+"      - { type: inspection, ref: x, '\"<package dir>:<TestName>\"': y }\n"), "inline HTML"},
		{"N8 placeholder in a block scalar comment-like line", edit(lastRef, lastRef+"      - type: inspection\n        ref: |\n          # \"<package dir>:<TestName>\"\n"), "inline HTML"},
		{"N8 placeholder behind an anchor", edit(lastRef, lastRef+"      - { type: inspection, ref: &p '\"<package dir>:<TestName>\"' }\n"), "inline HTML"},
		{"N8 placeholder in a line comment", edit(lastRef, lastRef+"      - { type: inspection, ref: x } # \"<package dir>:<TestName>\"\n"), "inline HTML"},
		{"N8 placeholder in an indented comment", edit(lastRef, lastRef+"      # go-test refs are \"<package dir>:<TestName>\"\n"), "inline HTML"},
		{"N8 placeholder in a later column-0 comment", real + "# go-test refs are \"<package dir>:<TestName>\"\n", "inline HTML"},
		{"N8 placeholder in a second document's comment", real + "---\n# \"<package dir>:<TestName>\"\nx: 1\n", "inline HTML"},
		// Post-9 round (scope cut): the raw-text tag scan refuses every "!" before decoding (A9-1/R9-2: a bare "!" is an
		// explicit non-specific tag the decoder does not flag; the mappings use no tag, so !!str is refused too), wherever
		// it is: a raw scan does not parse quoting, comments or flow context to tell a tag token from text.
		{"A9-1/R9-2 ref tagged with a bare !", edit(lastRef, lastRef+"      - { type: inspection, ref: ! ordinary }\n"), "explicit YAML tag"},
		{"P9 block ref tagged with a bare !", edit(lastRef, lastRef+"      - type: inspection\n        ref: ! ordinary\n"), "explicit YAML tag"},
		{"P9 !!str no longer excepted", edit(lastRef, lastRef+"      - { type: inspection, ref: !!str ordinary }\n"), "explicit YAML tag"},
		{"P9 local tag", edit(lastRef, lastRef+"      - { type: inspection, ref: !x ordinary }\n"), "explicit YAML tag"},
		{"P9 verbatim tag", edit(lastRef, lastRef+"      - { type: inspection, ref: !<tag:yaml.org,2002:str> ordinary }\n"), "explicit YAML tag"},
		{"P9 bare ! on a flow mapping", edit(lastRef, lastRef+"      - ! { type: inspection, ref: x }\n"), "explicit YAML tag"},
		{"P9 bare ! on a key", edit(lastRef, lastRef+"      - { type: inspection, ! ref: x }\n"), "explicit YAML tag"},
		{"P9 bare ! in a flow sequence", edit(lastRef, lastRef+"      - { type: inspection, ref: [! x] }\n"), "explicit YAML tag"},
		{"P9 bare ! on a block scalar", edit(lastRef, lastRef+"      - type: inspection\n        ref: ! |\n          ordinary\n"), "explicit YAML tag"},
		{"P9 ! after an apostrophe in a plain scalar", edit(lastRef, lastRef+"      - { type: inspection, ref: it's, note: ! x }\n"), "explicit YAML tag"},
		{"P9 ! after a quoted # in a flow mapping", edit(lastRef, lastRef+"      - { type: inspection, ref: \"a #\", note: ! x }\n"), "explicit YAML tag"},
		{"P9 ! in a quoted scalar", edit(lastRef, lastRef+"      - { type: inspection, ref: \"x ! y\" }\n"), "explicit YAML tag"},
		{"P9 ! in a comment", edit(lastRef, lastRef+"      # tags are refused!\n"), "explicit YAML tag"},
		{"P9 %YAML directive", "%YAML 1.2\n---\n" + real, "directive"},
		// The prose forms are refused in the mappings as in the docs: strikethrough, every reference-style link form and
		// a nested link.
		{"P9 strikethrough in a comment", edit(lastRef, lastRef+"      # ~~x~~\n"), "strikethrough"},
		{"P9 strikethrough in a value", edit(lastRef, lastRef+"      - { type: inspection, ref: \"Win~~dows~~\" }\n"), "strikethrough"},
		{"P9 full reference in a value", edit(lastRef, lastRef+"      - { type: inspection, ref: \"[a][b]\" }\n"), "reference-style link"},
		{"P9 definition in a comment", edit(lastRef, lastRef+"      # [a]: https://example.com/x\n"), "reference-style link"},
		{"P9 nested link in a comment", edit(lastRef, lastRef+"      # [[a](b)](c)\n"), "link this check does not read"},
	}
	// A test function that is commented out, or that is not a top-level test, does not authorize a reference.
	const fake = "package platforms\n\nimport \"testing\"\n\n/*\nfunc TestDarwin(t *testing.T) {\n}\n*/\n\n// func TestMacOS(t *testing.T) {\n\nvar s = `\nfunc TestWindows(t *testing.T) {\n`\n\nfunc TestReal(t *testing.T) {}\n"
	declared := declaredTests(t, "fake_test.go", fake)
	if len(declared) != 1 || !declared["TestReal"] {
		t.Errorf("declared tests in the fake file are %v, want only TestReal", declared)
	}
	withFake := map[string]bool{}
	for k := range tests {
		withFake[k] = true
	}
	for k := range declared {
		withFake[k] = true
	}
	mutants = append(mutants, struct{ name, text, want string }{"commented-out test authorizes a ref", edit(lastRef, lastRef+"      - { type: go-test, ref: \"internal/platforms:TestDarwin\" }\n"), "Darwin"})
	// Round-4 regression (B5): a test file the go tool does not select for the verification platforms
	// (linux/amd64 and linux/arm64) declares no test: an ignore constraint, a file name for another GOOS, a
	// constraint for one architecture only. Only TestReal is declared.
	dir := t.TempDir()
	for name, src := range map[string]string{
		"real_test.go":           "package fake\n\nimport \"testing\"\n\nfunc TestReal(t *testing.T) {}\n",
		"ignored_test.go":        "//go:build ignore\n\npackage fake\n\nimport \"testing\"\n\nfunc TestDarwin(t *testing.T) {}\n",
		"host_windows_test.go":   "package fake\n\nimport \"testing\"\n\nfunc TestWindows(t *testing.T) {}\n",
		"host_darwin_test.go":    "package fake\n\nimport \"testing\"\n\nfunc TestMacOS(t *testing.T) {}\n",
		"amd64_only_test.go":     "//go:build linux && amd64\n\npackage fake\n\nimport \"testing\"\n\nfunc TestAmd64Only(t *testing.T) {}\n",
		"legacy_ignore_test.go":  "// +build ignore\n\npackage fake\n\nimport \"testing\"\n\nfunc TestOSX(t *testing.T) {}\n",
		"other_external_test.go": "package fake_test\n\nimport \"testing\"\n\nfunc TestExternal(t *testing.T) {}\n",
		// Round-5 regressions (A5, B7, B6): a name go test does not run (a lower-case letter after Test) is not a
		// test; an architecture feature tag is the target's, not the host's (amd64.v1 holds for amd64 only,
		// arm64.v8.0 for arm64 only), so a file for one of them declares nothing.
		"helper_test.go":      "package fake\n\nimport \"testing\"\n\nfunc Testdarwin(t *testing.T) {}\n",
		"amd64_level_test.go": "//go:build amd64.v1\n\npackage fake\n\nimport \"testing\"\n\nfunc TestAmd64Level(t *testing.T) {}\n",
		"arm64_level_test.go": "//go:build arm64.v8.0\n\npackage fake\n\nimport \"testing\"\n\nfunc TestArm64Level(t *testing.T) {}\n",
		"both_levels_test.go": "//go:build amd64.v1 || arm64.v8.0\n\npackage fake\n\nimport \"testing\"\n\nfunc TestBothLevels(t *testing.T) {}\n",
		"amd64_v3_test.go":    "//go:build amd64.v3\n\npackage fake\n\nimport \"testing\"\n\nfunc TestAmd64V3(t *testing.T) {}\n",
		"underscore_test.go":  "package fake\n\nimport \"testing\"\n\nfunc Test_linux(t *testing.T) {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selected := testsInDir(t, dir)
	if len(selected) != 4 || !selected["TestReal"] || !selected["TestExternal"] || !selected["TestBothLevels"] || !selected["Test_linux"] {
		t.Errorf("the tests declared in build-selected files are %v, want only TestReal, TestExternal, TestBothLevels and Test_linux", selected)
	}
	withSelected := map[string]bool{}
	for k := range tests {
		withSelected[k] = true
	}
	for k := range selected {
		withSelected[k] = true
	}
	if ps := checkEvidenceMappings(edit(lastRef, lastRef+"      - { type: go-test, ref: \"internal/platforms:TestDarwin\" }\n"), withSelected); !strings.Contains(strings.Join(ps, "\n"), "Darwin") {
		t.Errorf("a test declared only in an ignored file authorizes a ref: %v", ps)
	}
	if ps := checkEvidenceMappings(edit(lastRef, lastRef+"      - { type: go-test, ref: \"internal/platforms:Testdarwin\" }\n"), withSelected); !strings.Contains(strings.Join(ps, "\n"), "darwin") {
		t.Errorf("a function go test does not run (Testdarwin) authorizes a ref: %v", ps)
	}
	for _, m := range mutants {
		ps := checkEvidenceMappings(m.text, withFake)
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

// allowedMarkup are the only pieces of angle-bracket markup the guard lets through anywhere (it reads no code span or
// code fence), each matched exactly with its reason. A new entry is reviewed; each must still be used (a stale entry
// fails). files is the files it applies to ("*.md": every Markdown file the guard reads).
var allowedMarkup = []struct{ files, text, why string }{
	{"*.md", "<!-- pinned: upstream -->", "the version-literals marker bin/check-version-literals.sh reads (an upstream version, not ours); renders nothing"},
	{"*.md", "<!-- pinned: historical -->", "the version-literals marker bin/check-version-literals.sh reads (a historical version); renders nothing"},
	{mappingsFile, "\"<package dir>:<TestName>\"", "the placeholder form of a go-test ref, only on a whole-line comment at column 0 in the file's leading comment block (markupPlaced); the mappings file is never rendered as HTML"},
}

// markupUsed reports whether the allowedMarkup text a applies to file and appears in text where its exception holds
// (markupPlaced, on the original line): an occurrence anywhere else does not keep the exception current.
func markupUsed(file, text, a string) bool {
	if !slices.Contains(markupFor(file), a) {
		return false
	}
	lines := strings.Split(text, "\n")
	leading := leadingLines(lines)
	for n, line := range lines {
		for off := 0; ; {
			i := strings.Index(line[off:], a)
			if i < 0 {
				break
			}
			if markupPlaced(a, line, off+i, leading[n]) {
				return true
			}
			off += i + len(a)
		}
	}
	return false
}

// contentFiles are the files the content guard reads: the scanned docs, the next release notes and the evidence
// mappings, the documents this project writes and reviews.
func contentFiles() []string {
	return append(append([]string{}, docsScanned...), notesFile, mappingsFile)
}

// proves: REQ-PLAT-001-AC1
// TestDocsHoldNoInlineHTMLOrInvisibleCharacters: the scanned docs, the next release notes and the evidence
// mappings hold no tag-like "<" anywhere (code spans and code fences included; other than the listed exceptions), no
// character reference and no invisible or non-printing character; each listed exception is still used.
func TestDocsHoldNoInlineHTMLOrInvisibleCharacters(t *testing.T) {
	used := map[string]bool{}
	for _, f := range contentFiles() {
		text := readOptional(t, f) // the release flow may remove the notes file
		for _, p := range contentProblems(f, text) {
			t.Error(p)
		}
		for _, m := range allowedMarkup {
			if markupUsed(f, text, m.text) {
				used[m.text] = true
			}
		}
	}
	for _, m := range allowedMarkup {
		if m.why == "" {
			t.Errorf("allowed markup %q has no reason", m.text)
		}
		if !used[m.text] {
			t.Errorf("allowed markup %q is no longer used (remove it from allowedMarkup)", m.text)
		}
	}
}

// proves: REQ-PLAT-001-AC1
// TestContentGuardRefusesMutants: the content guard refuses outright, naming file and line, every invisible or
// non-printing character (Unicode Cc other than tab, Cf, Mn, Me, Mc, Zl, Zp, every space other than the ASCII
// space, the default-ignorable letters, unassigned and private-use code points, invalid UTF-8), every form of inline
// HTML (open and closing tags, comments other than the listed markers, processing instructions, declarations,
// CDATA, autolinks, a backslash-escaped tag: any tag-like "<") anywhere, a code span or a code fence included (no
// Markdown structure is read, so no fence, list, heading or code span hides one: the round-7 reviewer shapes and the
// placeholders accepted until round 7 are refused), every character reference, strikethrough ("~~", a tilde fence
// included), every reference-style link form ("][" and "]:", escaped or not), and an exception marker anywhere but the
// end of its line on the original line; placeholders written as words, the listed markers ending their lines, a single
// tilde ("~/.gradle", "~5 GB") and visible punctuation (a "<" before a space, a digit, "=" or "-") pass. Two markers on one line are refused in either
// order. In the mappings file angle-bracket markup is refused everywhere but the listed placeholder on a whole-line
// comment at column 0 in the leading comment block, and only that placement counts as the exception being used.
func TestContentGuardRefusesMutants(t *testing.T) {
	const md = "docs/install.md"
	invisible := map[string]string{
		"soft hyphen": "\u00ad", "zero-width space": "\u200b", "zero-width joiner": "\u200d", "word joiner": "\u2060",
		"byte order mark": "\ufeff", "left-to-right mark": "\u200e", "bidi override": "\u202e",
		"combining grapheme joiner": "\u034f", "combining acute accent": "\u0301", "enclosing circle": "\u20dd",
		"spacing mark": "\u0903", "variation selector": "\ufe0f", "mongolian vowel separator": "\u180e",
		"tag letter": "\U000e0041", "line separator": "\u2028", "paragraph separator": "\u2029", "next line": "\u0085",
		"null": "\x00", "escape": "\x1b", "carriage return": "\r", "delete": "\x7f", "no-break space": "\u00a0",
		"ideographic space": "\u3000", "hangul filler": "\u3164", "hangul choseong filler": "\u115f",
		"halfwidth hangul filler": "\uffa0", "braille blank": "\u2800", "private use": "\ue000",
		"khmer inherent vowel": "\u17b4", "unassigned": "\u0378", "invalid UTF-8": "\xff",
	}
	for _, f := range []string{md, notesFile, mappingsFile} {
		for name, ch := range invisible {
			ps := contentProblems(f, "a first line\nNative binaries for Win"+ch+"dows are attached.\n")
			if !strings.Contains(strings.Join(ps, "\n"), f+":2: invisible") {
				t.Errorf("%s: %s is not refused at line 2 as invisible: %v", f, name, ps)
			}
		}
	}
	html := map[string]string{
		"open tag": "Win<b>dows</b>", "closing tag": "Windows</b>", "image": "Win<img alt=\"\" width=\"0\">dows",
		"break": "six<br>archives", "comment": "Win<!--x-->dows", "unpinned comment": "four <!-- a comment --> archives",
		"processing instruction": "Win<?x?>dows", "declaration": "Win<!X y>dows", "CDATA": "Win<![CDATA[x]]>dows",
		"autolink": "see <https://example.com/linux>", "e-mail autolink": "mail <a@example.com>",
		"unknown element": "Win<foo-bar x=1>dows", "bracketed name": "<windows>", "escaped tag": "Win\\<b>dows",
		"tag open at a line end": "Win<span", "quoted > in an attribute": "Win<span title=\">\">dows</span>",
		"tag after an unmatched backtick": "a ` b <b>x</b>", "tag after an escaped backtick": "a \\`<b>x</b>`",
	}
	for _, f := range []string{md, notesFile, mappingsFile} {
		for name, s := range html {
			ps := contentProblems(f, "a first line\n"+s+"\n")
			if !strings.Contains(strings.Join(ps, "\n"), f+":2: inline HTML") {
				t.Errorf("%s: %s is not refused at line 2 as inline HTML: %v", f, name, ps)
			}
		}
	}
	// Post-9 round (scope cut): strikethrough ("~~", a tilde fence included) and every reference-style link form (a full
	// "[text][label]", a collapsed "[text][]", a "[label]:" definition anywhere on a line) are refused outright, naming
	// the line, in every file the guard reads.
	for _, f := range []string{md, notesFile, mappingsFile} {
		for name, c := range map[string]struct{ s, want string }{
			"strikethrough":               {"si~~x~~ archives", "strikethrough"},
			"tilde fence":                 {"~~~", "strikethrough"},
			"full reference":              {"[a][b]", "reference-style link"},
			"collapsed reference":         {"[a][]", "reference-style link"},
			"definition":                  {"[a]: https://example.com/x", "reference-style link"},
			"indented definition":         {"   [a]: https://example.com/x", "reference-style link"},
			"definition in a quote":       {"> [a]: https://example.com/x", "reference-style link"},
			"definition without a target": {"[six]:", "reference-style link"},
			"escaped bracket then label":  {"\\[a\\][b]", "reference-style link"},
			"label closing a wrapped def": {"x]: https://example.com/x", "reference-style link"},
		} {
			ps := contentProblems(f, "a first line\n"+c.s+"\n")
			found := false
			for _, p := range ps {
				found = found || (strings.HasPrefix(p, f+":2: ") && strings.Contains(p, c.want))
			}
			if !found {
				t.Errorf("%s: %s is not refused at line 2 as %s: %v", f, name, c.want, ps)
			}
		}
	}
	for _, f := range []string{md, notesFile, mappingsFile} {
		for _, s := range []string{"Win&#100;ows", "Win&#x64;ows", "Apple&nbsp;Silicon", "Win&shy;dows", "a &amp; b", "Win&#x034F;dows"} {
			ps := contentProblems(f, "a first line\n"+s+"\n")
			if !strings.Contains(strings.Join(ps, "\n"), f+":2: character reference") {
				t.Errorf("%s: %q is not refused at line 2 as a character reference: %v", f, s, ps)
			}
		}
	}
	// Round-7 decision (advisor, final): the guard reads no Markdown structure. A tag-like "<" (before a letter, /, !
	// or ?) is refused wherever it is, in a code span or a code fence too; placeholders are written as words
	// (POD_NAME). Each of these, accepted until round 7 as code, is now refused at the line holding the "<".
	for name, c := range map[string]struct {
		s    string
		line int
	}{
		"placeholder in a code span":                 {"Run `kubectl exec -it <pod> -- sh`.", 2},
		"placeholder in a code span across a break":  {"use `kubectl debug POD_NAME -it --copy-to=<new-name>\n--image=...`, and more", 2},
		"placeholder in a backtick fence":            {"```sh\nkubectl debug -it <pod> --target=<container> -- sh\n```", 3},
		"type argument in a tilde fence":             {"~~~\nremote<HttpBuildCache> {\n~~~", 3},
		"placeholder in a fence indented 3 spaces":   {"   ```sh\n   kubectl exec <pod>\n   ```", 3},
		"placeholder in a four-backtick fence":       {"````md\n```\n<pod>\n```\n````", 4},
		"placeholder in a tilde fence with backtick": {"~~~ `info` with backticks\n<pod>\n~~~", 3},
		"placeholder after an indented pseudo-close": {"```sh\nPOD_NAME\n    ```\n<container>\n```", 5},
		// The round-7 reviewer shapes (A7-1/B7-1: a fence that CommonMark ends with its list item; A7-2/B7-1: a code
		// span paired across a heading and a paragraph; B7-2: an exception marker between two code spans).
		"A7-1/B7-1 list fence hides a tag":          {"- item\n  ```\n  harmless\n\nWin<b>dows</b> binaries are shipped.\n```", 6},
		"A7-1 unindented line after a list fence":   {"- item\n  ```\nWin<b>dows</b>\n```", 4},
		"A7-2/B7-1 heading code span hides a tag":   {"# `\nWin<b>dows</b> binaries are shipped.\n`", 3},
		"B7-2 marker between code spans in Windows": {"`Win`<!-- pinned: upstream -->`dows`", 2},
		"B7-2 marker between code spans in six":     {"`si`<!-- pinned: upstream -->`x archives`", 2},
		"B7-2 historical marker between code spans": {"`Win`<!-- pinned: historical -->`dows`", 2},
	} {
		for _, f := range []string{md, notesFile} {
			ps := contentProblems(f, "a first line\n"+c.s+"\n")
			want := fmt.Sprintf("%s:%d: ", f, c.line)
			found := false
			for _, p := range ps {
				found = found || (strings.HasPrefix(p, want) && (strings.Contains(p, "tag-like \"<\"") || strings.Contains(p, "exception marker")))
			}
			if !found {
				t.Errorf("%s: %s is not refused at line %d for its \"<\": %v", f, name, c.line, ps)
			}
		}
	}
	for _, s := range []string{
		"Run `kubectl exec -it POD_NAME -- sh`.",
		"use `kubectl debug POD_NAME -it --copy-to=NEW_POD_NAME\n--image=...`, and more",
		"```sh\nkubectl debug -it POD_NAME --target=CONTAINER_NAME -- sh\n```",
		"rm -rf ~/.gradle/caches/build-cache-1",
		"cache cap + ~5 GB for OS/overhead",
		"Built with `GOFIPS140=v1.0.0`, selecting the module. <!-- pinned: upstream -->",
		"Cut four times. <!-- pinned: historical -->",
		"<!-- pinned: historical -->",
		"| a | b | <!-- pinned: upstream -->",
		"Visible punctuation: a — b – c · d → e × f ✓ g § h, x < y and y > x, a <= b, c <- d, <3, < x.",
		"\tan indented line with a tab",
	} {
		if ps := contentProblems(md, s+"\n"); len(ps) > 0 {
			t.Errorf("%q is refused: %v", s, ps)
		}
	}
	if ps := contentProblems(mappingsFile, "# go-test refs are \"<package dir>:<TestName>\" and the validator fails\n"); len(ps) > 0 {
		t.Errorf("the listed mappings placeholder is refused: %v", ps)
	}
	if ps := contentProblems(mappingsFile, "# go-test refs are \"<package dir>:<TestName>\" or <x>\n"); !strings.Contains(strings.Join(ps, "\n"), mappingsFile+":1: inline HTML") {
		t.Errorf("a tag-like \"<\" beside the listed mappings placeholder is not refused: %v", ps)
	}
	if ps := contentProblems(mappingsFile, "# run `kubectl exec <pod>` first\n"); !strings.Contains(strings.Join(ps, "\n"), mappingsFile+":1: inline HTML") {
		t.Errorf("a placeholder in the mappings file (YAML, not Markdown: no code span) is not refused: %v", ps)
	}
	// Round-8 regressions (A8-1/B8-3): the mappings placeholder is excepted only on a whole-line comment at column 0 in
	// the file's leading comment block; anywhere else (a value, a later or indented comment, a line comment) it is a
	// tag-like "<", and only a placeholder in that place counts as the exception being used.
	const placeholder = "\"<package dir>:<TestName>\""
	for name, s := range map[string]string{
		"in a value":                   "mappings:\n  - note: '" + placeholder + "'\n",
		"in a comment after a key":     "mappings: []\n# go-test refs are " + placeholder + "\n",
		"in an indented leading line":  "  # go-test refs are " + placeholder + "\n",
		"in a line comment":            "x: 1 # " + placeholder + "\n",
		"after a document marker":      "---\n# go-test refs are " + placeholder + "\n",
		"in a comment without a space": "#" + placeholder + "\n",
	} {
		if ps := contentProblems(mappingsFile, s); !strings.Contains(strings.Join(ps, "\n"), "inline HTML") {
			t.Errorf("the mappings placeholder %s is not refused: %v", name, ps)
		}
		if markupUsed(mappingsFile, s, placeholder) {
			t.Errorf("the mappings placeholder %s counts as the exception being used", name)
		}
	}
	if !markupUsed(mappingsFile, "# header\n#\n# go-test refs are "+placeholder+" and\n", placeholder) {
		t.Errorf("the mappings placeholder in the leading comment block does not count as used")
	}
	if markupUsed("docs/install.md", "x <!-- pinned: historical --> <!-- pinned: upstream -->\n", "<!-- pinned: historical -->") {
		t.Errorf("a marker that does not end its line counts as the exception being used")
	}
	if ps := contentProblems(notesFile, "Cut four times. <!-- pinned: upstream -->\n"); len(ps) > 0 {
		t.Errorf("a listed marker in the notes is refused: %v", ps)
	}
	// Round-6 regressions (A1, B3, A2, B4), kept since round 7 (no fence is read, so none of these hides anything): a
	// pseudo-fence of any form before a tag. An exception marker is allowed only where it ends its line (after a space,
	// or alone on the line), never inside a line of prose.
	for _, f := range []string{md, notesFile} {
		for name, s := range map[string]string{
			"indented pseudo-fence":              "    ```\n\nWin<b>dows</b>",
			"tab-indented pseudo-fence":          "\t```\n\nWin<b>dows</b>",
			"backtick in a backtick info":        "```bad`\nsi<b>x</b> archives",
			"short closing fence":                "````\nx\n```\n````x\nWin<b>dows</b>",
			"closing fence with text after":      "```\nx\n``` y\n```\n\nWin<b>dows</b>\n```z",
			"unclosed fence":                     "```\nWin<b>dows</b>",
			"marker splits Windows":              "Win<!-- pinned: upstream -->dows",
			"marker splits six":                  "si<!-- pinned: historical -->x archives",
			"marker inside a line of prose":      "The version is pinned <!-- pinned: upstream --> for all four archives.",
			"marker joined to a word at the end": "Windows<!-- pinned: upstream -->",
			// Round-8 regression (B8-2) and self-review: placement is decided on the original line, order independent:
			// each marker must itself end its line (or stand alone on it), so two markers on one line are refused in
			// either order, and so is a marker followed by anything.
			"B8-2 historical then upstream":       "x <!-- pinned: historical --> <!-- pinned: upstream -->",
			"B8-2 upstream then historical":       "x <!-- pinned: upstream --> <!-- pinned: historical -->",
			"N8 two markers alone":                "<!-- pinned: upstream --> <!-- pinned: historical -->",
			"N8 one marker twice":                 "x <!-- pinned: upstream --> <!-- pinned: upstream -->",
			"N8 markers joined":                   "x <!-- pinned: upstream --><!-- pinned: historical -->",
			"N8 markers split by a tab":           "x <!-- pinned: upstream -->\t<!-- pinned: historical -->",
			"N8 marker first, then prose":         "<!-- pinned: upstream --> four archives",
			"N8 marker mid table row":             "| a <!-- pinned: upstream --> | b |",
			"N8 marker then a backslash":          "x <!-- pinned: upstream --> \\",
			"N8 three markers":                    "x <!-- pinned: historical --> <!-- pinned: upstream --> <!-- pinned: historical -->",
			"N8 marker then a tag":                "x <!-- pinned: upstream --> <b>",
			"N8 marker after a tab then a marker": "\t<!-- pinned: historical -->\t<!-- pinned: upstream -->",
		} {
			ps := contentProblems(f, "a first line\n\n"+s+"\n")
			if !strings.Contains(strings.Join(ps, "\n"), f+":") || len(ps) == 0 {
				t.Errorf("%s: %s is not refused: %v", f, name, ps)
			}
		}
	}
}
