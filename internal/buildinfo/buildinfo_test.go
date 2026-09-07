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
