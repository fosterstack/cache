// Package buildinfo reports what this binary actually is: its version, the
// commit it was built from, and whether it links Go's FIPS 140-3 validated
// cryptographic module.
//
// Everything is read from the runtime (debug.ReadBuildInfo), not injected
// with -X at link time: a link-time value for a variable that does not exist
// is silently dropped and reads as always empty.
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

// readBuildInfo is a seam for tests: under `go test` debug.ReadBuildInfo
// always succeeds with a populated Main, so the failure paths need it replaced.
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

// validatedModule reports whether the binary links the validated module. The
// toolchain records it as "v1.0.0", optionally with a build hash
// ("v1.0.0-c2097c7c"), so the version prefix is what counts.
func (i Info) validatedModule() bool {
	return i.FIPSModule == "v1.0.0" || strings.HasPrefix(i.FIPSModule, "v1.0.0-")
}

// FIPSNote renders the FIPS posture for the startup log and the status page.
// It keeps runtime MODE and build-time MODULE apart (REQ-FIPS-002):
// GODEBUG=fips140=on forces the mode in any build, so only the validated
// module version may claim the certificate.
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
