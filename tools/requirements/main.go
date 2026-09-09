// Command requirements validates the requirements baseline and generates the
// traceability matrix (traceability-plan.md §5-§6).
//
//	go run . validate    — schema + semantic checks; non-zero on any failure
//	go run . generate    — write docs/quality/traceability.md
//	go run . check       — validate, regenerate, and fail if the committed
//	                       matrix is stale (what CI runs; CI never commits)
//
// The checks implemented here are the §6 list as it applies before test
// mapping begins: duplicate IDs, schema violations, requirements without
// ACs (schema), mapping references to unknown ACs, and stale generated
// Markdown. Orphan-test detection and evidence-sufficiency checks activate
// with the mapping step, after the owner approves the baseline.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

const (
	reqFile    = "requirements/requirements.yaml"
	schemaFile = "requirements/schema.json"
	mapFile    = "test-evidence/mappings.yaml"
	outFile    = "docs/quality/traceability.md"
)

type AC struct {
	ID           string `yaml:"id"`
	Given        string `yaml:"given"`
	When         string `yaml:"when"`
	Then         string `yaml:"then"`
	Verification struct {
		Method          string `yaml:"method"`
		ReleaseBlocking bool   `yaml:"release_blocking"`
	} `yaml:"verification"`
	Status string `yaml:"status"`
}

type Requirement struct {
	ID         string   `yaml:"id"`
	Title      string   `yaml:"title"`
	Statement  string   `yaml:"statement"`
	Source     []string `yaml:"source"`
	Tier       string   `yaml:"tier"`
	Introduced string   `yaml:"introduced"`
	Origin     string   `yaml:"origin"`
	Deprecated bool     `yaml:"deprecated"`
	Confidence string   `yaml:"confidence"`
	Notes      string   `yaml:"notes"`
	ACs        []AC     `yaml:"acceptance_criteria"`
}

type File struct {
	Baseline struct {
		ExtractedFrom string `yaml:"extracted_from"`
		ExtractedOn   string `yaml:"extracted_on"`
		Approved      bool   `yaml:"approved"`
		ApprovedOn    string `yaml:"approved_on"`
		Note          string `yaml:"note"`
	} `yaml:"baseline"`
	Requirements []Requirement `yaml:"requirements"`
}

type Mappings struct {
	Mappings []struct {
		AC       string `yaml:"ac"`
		Evidence []struct {
			Type string `yaml:"type"`
			Ref  string `yaml:"ref"`
		} `yaml:"evidence"`
	} `yaml:"mappings"`
}

func main() {
	if len(os.Args) != 2 {
		fatal("usage: requirements validate|generate|check")
	}
	// Run from the repo root regardless of invocation directory.
	if _, err := os.Stat(reqFile); err != nil {
		if err := os.Chdir(repoRoot()); err != nil {
			fatal("chdir repo root: %v", err)
		}
	}
	switch os.Args[1] {
	case "validate":
		f, m := load()
		validate(f, m)
		fmt.Println("requirements: valid")
	case "generate":
		f, m := load()
		validate(f, m)
		if err := os.WriteFile(outFile, []byte(render(f, m)), 0o644); err != nil {
			fatal("write %s: %v", outFile, err)
		}
		fmt.Println("wrote", outFile)
	case "check":
		f, m := load()
		validate(f, m)
		want := render(f, m)
		got, err := os.ReadFile(outFile)
		if err != nil {
			fatal("%s missing — run `go run ./tools/requirements generate` and commit it", outFile)
		}
		if string(got) != want {
			fatal("%s is STALE relative to the requirements sources — regenerate and commit it (CI never commits generated output itself)", outFile)
		}
		fmt.Println("requirements: valid; matrix fresh")
	default:
		fatal("unknown command %q", os.Args[1])
	}
}

func repoRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		fatal("not in a git repository and %s not found", reqFile)
	}
	return strings.TrimSpace(string(out))
}

func load() (File, Mappings) {
	var f File
	unmarshalStrict(reqFile, &f)
	var m Mappings
	unmarshalStrict(mapFile, &m)
	return f, m
}

func unmarshalStrict(path string, v any) {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal("read %s: %v", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		fatal("parse %s: %v", path, err)
	}
}

func validate(f File, m Mappings) {
	var errs []string
	fail := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	// 1. JSON-Schema validation of the requirements file. The YAML is
	// converted to plain JSON types and validated against schema.json, so
	// the schema is the enforced contract, not documentation.
	schemaJSON, err := os.ReadFile(schemaFile)
	if err != nil {
		fatal("read %s: %v", schemaFile, err)
	}
	sch, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaJSON)))
	if err != nil {
		fatal("parse %s: %v", schemaFile, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaFile, sch); err != nil {
		fatal("schema: %v", err)
	}
	compiled, err := c.Compile(schemaFile)
	if err != nil {
		fatal("compile schema: %v", err)
	}
	raw, err := os.ReadFile(reqFile)
	if err != nil {
		fatal("read %s: %v", reqFile, err)
	}
	var generic any
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		fatal("parse %s: %v", reqFile, err)
	}
	if err := compiled.Validate(toJSONTypes(generic)); err != nil {
		fail("schema: %v", err)
	}

	// 2. Duplicate IDs, requirement and AC, and AC-prefix consistency.
	seenReq := map[string]bool{}
	seenAC := map[string]bool{}
	for _, r := range f.Requirements {
		if seenReq[r.ID] {
			fail("duplicate requirement id %s", r.ID)
		}
		seenReq[r.ID] = true
		for _, ac := range r.ACs {
			if seenAC[ac.ID] {
				fail("duplicate AC id %s", ac.ID)
			}
			seenAC[ac.ID] = true
			if !strings.HasPrefix(ac.ID, r.ID+"-AC") {
				fail("AC %s does not belong to its requirement %s", ac.ID, r.ID)
			}
		}
	}

	// 3. Mappings must reference known ACs.
	for _, mp := range m.Mappings {
		if !seenAC[mp.AC] {
			fail("mappings.yaml references unknown AC %s", mp.AC)
		}
		if len(mp.Evidence) == 0 {
			fail("mapping for %s lists no evidence", mp.AC)
		}
	}

	// 4. Approval-state consistency: an unapproved baseline must not
	// contain approved ACs, and approval requires a date.
	for _, r := range f.Requirements {
		for _, ac := range r.ACs {
			if !f.Baseline.Approved && ac.Status == "approved" {
				fail("AC %s is marked approved but the baseline is not", ac.ID)
			}
		}
	}
	if f.Baseline.Approved && f.Baseline.ApprovedOn == "" {
		fail("baseline approved without approved_on")
	}

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "requirements:", e)
		}
		os.Exit(1)
	}
}

// toJSONTypes converts YAML-decoded values to what the schema library
// expects (map[string]any keys, json-ish scalars).
func toJSONTypes(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			out[k] = toJSONTypes(val)
		}
		return out
	case []any:
		for i := range t {
			t[i] = toJSONTypes(t[i])
		}
		return t
	case int:
		return float64(t)
	case time.Time:
		// YAML decodes ISO dates as time.Time; the schema wants strings.
		return t.Format("2006-01-02")
	default:
		return v
	}
}

func render(f File, m Mappings) string {
	evidence := map[string]int{}
	for _, mp := range m.Mappings {
		evidence[mp.AC] = len(mp.Evidence)
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# Product promises and proof")
	w("")
	w("<!-- GENERATED by tools/requirements — do not edit. Regenerate with:")
	w("     go run ./tools/requirements generate -->")
	w("")
	w("Every externally observable behavior of FosterStack Cache, as a stable")
	w("requirement with measurable acceptance criteria, and the evidence for each.")
	w("The machine-readable source is [`requirements/requirements.yaml`](../../requirements/requirements.yaml);")
	w("this page is a generated view of it and CI fails if the two drift.")
	w("")
	if f.Baseline.Approved {
		w("Baseline extracted from `%s` on %s; approved by the owner on %s.",
			f.Baseline.ExtractedFrom, f.Baseline.ExtractedOn, f.Baseline.ApprovedOn)
	} else {
		w("Baseline extracted from `%s` on %s. **Owner review of the baseline is", f.Baseline.ExtractedFrom, f.Baseline.ExtractedOn)
		w("pending; every acceptance criterion below is `proposed`, and no test")
		w("mapping happens until the baseline is approved.**")
	}
	w("")
	w("The baseline was extracted from the documentation and implementation at the")
	w("revision above — it is retroactive and described as exactly that. Since")
	w("Sep 8, 2026, acceptance criteria are written before implementation.")
	w("")

	total, acTotal, blocking, mapped := 0, 0, 0, 0
	byConf := map[string]int{}
	for _, r := range f.Requirements {
		if r.Deprecated {
			continue
		}
		total++
		byConf[r.Confidence]++
		for _, ac := range r.ACs {
			acTotal++
			if ac.Verification.ReleaseBlocking {
				blocking++
			}
			if evidence[ac.ID] > 0 {
				mapped++
			}
		}
	}
	w("| Metric | Value |")
	w("|---|---|")
	w("| Active requirements | %d |", total)
	w("| Acceptance criteria | %d |", acTotal)
	w("| Release-blocking ACs | %d |", blocking)
	w("| ACs with mapped evidence | %d |", mapped)
	for _, k := range sortedKeys(byConf) {
		w("| Confidence: %s | %d |", k, byConf[k])
	}
	w("")

	group := ""
	for _, r := range f.Requirements {
		g := strings.Split(r.ID, "-")[1]
		if g != group {
			group = g
			w("## %s", groupTitle(g))
			w("")
		}
		w("### %s — %s", r.ID, r.Title)
		w("")
		w("%s", strings.TrimSpace(r.Statement))
		w("")
		w("*Introduced %s · tier %s · confidence %s · source: %s*",
			r.Introduced, r.Tier, r.Confidence, strings.Join(r.Source, "; "))
		if r.Notes != "" {
			w("")
			w("> %s", strings.TrimSpace(strings.ReplaceAll(r.Notes, "\n", " ")))
		}
		w("")
		w("| AC | Given / When / Then | Verification | Blocking | Status | Evidence |")
		w("|---|---|---|---|---|---|")
		for _, ac := range r.ACs {
			blockingMark := ""
			if ac.Verification.ReleaseBlocking {
				blockingMark = "yes"
			}
			ev := "none mapped"
			if n := evidence[ac.ID]; n > 0 {
				ev = fmt.Sprintf("%d item(s)", n)
			}
			w("| %s | Given %s; when %s; then %s | %s | %s | %s | %s |",
				ac.ID, esc(ac.Given), esc(ac.When), esc(ac.Then),
				ac.Verification.Method, blockingMark, ac.Status, ev)
		}
		w("")
	}
	return b.String()
}

func esc(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "|", "\\|") }

func groupTitle(g string) string {
	titles := map[string]string{
		"PROTO": "Cache protocol", "CFG": "Configuration", "AUTH": "Authentication",
		"STORE": "Storage", "EVICT": "Eviction", "OBS": "Observability",
		"PRIV": "Privacy", "PLAT": "Platforms and artifacts", "DEPLOY": "Deployment",
		"FIPS": "FIPS 140-3", "GRADLE": "Gradle", "MAVEN": "Maven",
		"REL": "Release evidence", "LIC": "Licensing",
	}
	if t, ok := titles[g]; ok {
		return t
	}
	return g
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "requirements: "+format+"\n", a...)
	os.Exit(1)
}

var _ = filepath.Join
