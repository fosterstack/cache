// Package buildinfo reports what this binary actually is: its version, the
// commit it was built from, and whether it links Go's FIPS 140-3 validated
// cryptographic module.
//
// Everything here is read from the runtime rather than injected at link
// time. The release build passes -X main.version, but no such variable has
// ever existed, so the linker silently discarded it — a value that looks
// configured and is always empty is worse than no value at all.
// debug.ReadBuildInfo needs no build-time cooperation and cannot drift out
// of sync with the tag that produced the binary.
package buildinfo

import (
	"crypto/fips140"
	"runtime/debug"
)

// Info describes the running binary.
type Info struct {
	// Version is the module version ("v0.1.0"), or "(devel)" for a build
	// straight from a working tree.
	Version string
	// Revision is the VCS commit, empty if the build had no VCS context.
	Revision string
	// Modified reports whether the working tree was dirty at build time.
	Modified bool
	// FIPS140 reports whether the validated cryptographic module is active.
	FIPS140 bool
}

// Read returns the running binary's build information.
func Read() Info {
	info := Info{Version: "unknown", FIPS140: fips140.Enabled()}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	if bi.Main.Version != "" {
		info.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Revision = s.Value
		case "vcs.modified":
			info.Modified = s.Value == "true"
		}
	}
	return info
}

// FIPSNote renders the FIPS posture for the startup log and the status
// page. The compliance buyer's entire reason for choosing the -fips build
// is this property, and until now it was unobservable at runtime: the
// startup line announced addr, data_dir, max_bytes and auth, and said
// nothing about the one thing they paid attention for. This is the line an
// assessor screenshots.
func (i Info) FIPSNote() string {
	if i.FIPS140 {
		return "active (Go validated module, CMVP cert #5247)"
	}
	return "off"
}
