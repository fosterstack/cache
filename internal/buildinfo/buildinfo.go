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
	"strings"
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
	// FIPS140 reports whether fips140 mode is enabled at runtime. Mode
	// alone does not establish the validated module: GODEBUG=fips140=on
	// forces the mode in ANY build. FIPSModule is the other half.
	FIPS140 bool
	// FIPSModule is the Go Cryptographic Module version selected into
	// this binary at build time (the GOFIPS140 build setting), empty for
	// a standard build. Only a binary built with the validated module
	// version may claim the certificate.
	FIPSModule string
}

// readBuildInfo is a testability seam over debug.ReadBuildInfo. Under
// `go test` the runtime always returns ok=true with a populated Main, so
// the not-ok and empty-version paths below are unreachable without
// overriding this variable. Production behavior is unchanged: nothing
// outside the package's own tests reassigns it.
var readBuildInfo = debug.ReadBuildInfo

// Read returns the running binary's build information.
func Read() Info {
	info := Info{Version: "unknown", FIPS140: fips140.Enabled()}
	bi, ok := readBuildInfo()
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
		case "GOFIPS140":
			info.FIPSModule = s.Value
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
// The note distinguishes runtime MODE from build-time MODULE selection
// (REQ-FIPS-002): GODEBUG=fips140=on forces the mode in any build, so
// mode alone must never claim the certificate. Only the validated
// module version does. The Go toolchain records the module setting as
// "v1.0.0" optionally suffixed with a build hash ("v1.0.0-c2097c7c"),
// so the certificate is claimed on the version prefix, not exact bytes.
func (i Info) validatedModule() bool {
	return i.FIPSModule == "v1.0.0" || strings.HasPrefix(i.FIPSModule, "v1.0.0-")
}

func (i Info) FIPSNote() string {
	switch {
	case i.FIPS140 && i.validatedModule():
		return "active (Go validated module v1.0.0, CMVP cert #5247)"
	case i.FIPS140 && i.FIPSModule == "":
		return "active (fips140 mode forced at runtime; not the validated-module build)"
	case i.FIPS140:
		return "active (Go module " + i.FIPSModule + "; certificate status not asserted)"
	case i.validatedModule():
		return "off (validated module v1.0.0 linked, mode disabled at runtime)"
	default:
		return "off"
	}
}
