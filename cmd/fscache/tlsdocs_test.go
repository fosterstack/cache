package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// tlsPages are the pages REQ-TLS-001-AC7 names.
var tlsPages = []string{"../../README.md", "../../docs/kubernetes.md", "../../docs/docker-deploy.md", "../../docs/gradle.md"}

// bannedPhrases are the absolute or programme wordings these pages must not
// use (the design-rules list, advisor Oct 10), matched in lower case with
// any run of spaces or hyphens between words.
var bannedPhrases = []string{"immune", "secure by design", "secure by default", "cisa", "pledge", "certified", "compliant", "guarantee"}

func bannedWording(text string) string {
	norm := regexp.MustCompile(`[\s-]+`).ReplaceAllString(strings.ToLower(text), " ")
	for _, b := range bannedPhrases {
		if strings.Contains(norm, b) {
			return b
		}
	}
	return ""
}

// normSpace folds every run of whitespace (and blockquote markers) to one
// space, so a phrase wrapped across lines still matches.
func normSpace(s string) string {
	return regexp.MustCompile(`(?:\s|\n> ?)+`).ReplaceAllString(s, " ")
}

// proves: REQ-TLS-001-AC7 — the README table lists both variables (required together, default unset); kubernetes.md shows both options with a read-only Secret and HTTPS probes; every page says the files are read only at startup, so a rotation needs a restart
func TestTLSDocsDescribeBothOptions(t *testing.T) {
	text := map[string]string{}
	for _, p := range tlsPages {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		text[p] = string(b)
		flat := normSpace(string(b))
		for _, want := range []string{"FSCACHE_TLS_CERT", "FSCACHE_TLS_KEY", "read only at startup", "restart"} {
			if !strings.Contains(flat, want) {
				t.Errorf("%s does not say %q", p, want)
			}
		}
		if w := bannedWording(string(b)); w != "" {
			t.Errorf("%s uses the wording %q", p, w)
		}
	}

	// README: one table row, both variables, required together, default unset.
	var row string
	for _, line := range strings.Split(text["../../README.md"], "\n") {
		if strings.HasPrefix(line, "| `FSCACHE_TLS_CERT`") {
			row = line
		}
	}
	if row == "" {
		t.Fatal("the README configuration table has no FSCACHE_TLS_CERT row")
	}
	cells := strings.Split(row, "|")
	if len(cells) < 4 || !strings.Contains(cells[1], "`FSCACHE_TLS_KEY`") || !strings.HasPrefix(strings.TrimSpace(cells[2]), "unset") || !strings.Contains(row, "required together") {
		t.Errorf("README row %q must list both variables, default unset, required together", row)
	}

	// kubernetes.md: the old sentence is gone; both options; the Secret
	// mounted read-only; probes over HTTPS.
	k := text["../../docs/kubernetes.md"]
	kflat := normSpace(k)
	if strings.Contains(kflat, "no certificate handling of its own") {
		t.Error(`kubernetes.md still says "no certificate handling of its own"`)
	}
	for _, want := range []string{"TLS in front", "secretName:", "readOnly: true", "scheme: HTTPS", "FSCACHE_TLS_CERT", "FSCACHE_TLS_KEY"} {
		if !strings.Contains(kflat, want) {
			t.Errorf("kubernetes.md does not show %q", want)
		}
	}
	// The TLS example is the fenced yaml block that sets FSCACHE_TLS_CERT:
	// it mounts the Secret read-only and both of its probes (at least two
	// httpGet probes) carry scheme: HTTPS.
	var example string
	for _, m := range regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(k, -1) {
		if strings.Contains(m[1], "FSCACHE_TLS_CERT") {
			example = m[1]
			break
		}
	}
	if example == "" {
		t.Fatal("kubernetes.md has no yaml example setting FSCACHE_TLS_CERT")
	}
	for _, want := range []string{"FSCACHE_TLS_KEY", "secretName:", "readOnly: true"} {
		if !strings.Contains(example, want) {
			t.Errorf("the kubernetes.md TLS example does not set %q", want)
		}
	}
	// The example's Secret has a name no other example on the page uses
	// (the ingress example has its own), and the page says the files must
	// be readable by the container's non-root user.
	if m := regexp.MustCompile(`secretName:\s*(\S+)`).FindStringSubmatch(example); m == nil {
		t.Error("the kubernetes.md TLS example names no Secret")
	} else if n := strings.Count(k, "secretName: "+m[1]); n != 1 {
		t.Errorf("the TLS example's Secret %q is named %d times on the page, want once (a name of its own)", m[1], n)
	}
	if !strings.Contains(kflat, "readable by the container's non-root user") {
		t.Error("kubernetes.md does not say the files must be readable by the container's non-root user")
	}
	if n, m := strings.Count(example, "httpGet:"), strings.Count(example, "scheme: HTTPS"); n < 2 || m != n {
		t.Errorf("kubernetes.md TLS example: %d httpGet probes, %d with scheme: HTTPS; want at least two, all HTTPS", n, m)
	}

	// gradle.md keeps §3 and points to the new option from it.
	g := text["../../docs/gradle.md"]
	s3 := strings.Index(g, "## 3. Trying it out without TLS")
	if s3 < 0 {
		t.Fatal(`gradle.md lost "## 3. Trying it out without TLS"`)
	}
	sec := g[s3:]
	if end := strings.Index(sec[1:], "\n## "); end >= 0 {
		sec = sec[:end+1]
	}
	if !strings.Contains(sec, "FSCACHE_TLS_CERT") {
		t.Error("gradle.md §3 does not point to FSCACHE_TLS_CERT / FSCACHE_TLS_KEY")
	}
}

// proves: REQ-TLS-001-AC7 — the banned-wording check catches each phrase, hyphenated or spaced, in any case
func TestTLSDocsBannedWordingIsCaught(t *testing.T) {
	for _, s := range []string{"Immune to X", "secure by design", "Secure-By-Design", "secure-by-default", "per CISA",
		"the pledge", "FIPS certified", "compliant with", "we guarantee", "guarantees", "secure  by\n design"} {
		if bannedWording(s) == "" {
			t.Errorf("bannedWording(%q) found nothing", s)
		}
	}
	if w := bannedWording("compliance-tier buyers; a design rule; the default; a certificate"); w != "" {
		t.Errorf("bannedWording flagged ordinary text: %q", w)
	}
}
