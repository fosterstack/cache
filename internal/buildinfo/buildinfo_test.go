package buildinfo

import (
	"crypto/fips140"
	"strings"
	"testing"
)

func TestReadAlwaysReportsAVersion(t *testing.T) {
	got := Read()
	if got.Version == "" {
		t.Error("Version is empty; it must always report something, even for a devel build")
	}
}

// FIPSNote feeds the startup log and the status page, so it must never be
// empty: "off" is a real answer, "" is a broken one. It must also track
// the actual runtime state rather than a build tag someone forgot to set.
func TestFIPSNoteMatchesRuntimeState(t *testing.T) {
	got := Read()

	if got.FIPS140 != fips140.Enabled() {
		t.Errorf("FIPS140 = %v, want %v (crypto/fips140.Enabled)", got.FIPS140, fips140.Enabled())
	}

	note := got.FIPSNote()
	if note == "" {
		t.Fatal("FIPSNote() is empty; it must always report a posture")
	}
	if got.FIPS140 {
		if !strings.HasPrefix(note, "active") {
			t.Errorf("FIPSNote() = %q, want it to start with %q under a FIPS build", note, "active")
		}
		// The certificate number is what an assessor is looking for.
		if !strings.Contains(note, "5247") {
			t.Errorf("FIPSNote() = %q, want it to name the CMVP certificate", note)
		}
	} else if note != "off" {
		t.Errorf("FIPSNote() = %q, want %q on a standard build", note, "off")
	}
}

// REQ-FIPS-002: the posture line must tell the truth in every
// combination of runtime mode and build-time module selection. The
// forced-standard case (mode on, no module selected) previously
// over-claimed the certificate - the exact discrepancy the Sep 10
// review recorded and the Sep 12 review found still reported as a pass.
func TestFIPSNoteIsTruthfulPerModeAndModule(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "validated build, mode on",
			info: Info{FIPS140: true, FIPSModule: "v1.0.0-c2097c7c"},
			want: "active (Go validated module v1.0.0, CMVP cert #5247)",
		},
		{
			name: "standard build, mode forced at runtime",
			info: Info{FIPS140: true, FIPSModule: ""},
			want: "active (fips140 mode forced at runtime; not the validated-module build)",
		},
		{
			name: "validated module linked, mode disabled",
			info: Info{FIPS140: false, FIPSModule: "v1.0.0-c2097c7c"},
			want: "off (validated module v1.0.0 linked, mode disabled at runtime)",
		},
		{
			name: "standard build, mode off",
			info: Info{FIPS140: false, FIPSModule: ""},
			want: "off",
		},
		{
			name: "unrecognized module version never claims the certificate",
			info: Info{FIPS140: true, FIPSModule: "v1.1.0"},
			want: "active (Go module v1.1.0; certificate status not asserted)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.FIPSNote(); got != tc.want {
				t.Fatalf("FIPSNote() = %q, want %q", got, tc.want)
			}
		})
	}
}
