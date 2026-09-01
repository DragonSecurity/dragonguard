// Command dragon is the DragonGuard CLI: the security quality gate.
package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

// devVersion is what a build carries when nothing stamped it.
const devVersion = "0.1.0-dev"

// version is overridden at build time with -ldflags, or resolved from the
// module version by resolveVersion.
var version = devVersion

// resolveVersion recovers the version of a `go install module@version` build.
//
// Only a release build passes -ldflags, so `go install ...@v0.3.0` used to
// produce a binary that called itself 0.1.0-dev forever -- while the README
// recommended exactly that install. The version is stamped into every SARIF
// file and every scan the platform ingests, so the result was findings that
// could not say which build produced them, from the documented install path.
//
// Go records the module version in the build info for a versioned install, so
// it is available without the linker flag. A local `go build` inside the
// repository gets a VCS-derived version instead -- "0.3.0+dirty" for a tagged
// tree with uncommitted changes, a pseudo-version between tags -- which is
// strictly more useful than the "0.1.0-dev" it replaces, because it says
// which commit produced the finding. Only a build with no VCS information at
// all records "(devel)", and that one really is anonymous.
func resolveVersion() {
	if version != devVersion {
		return // -ldflags won; it is the more specific answer
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		return
	}
	version = strings.TrimPrefix(v, "v")
}

func main() {
	resolveVersion()
	if err := newRootCmd().Execute(); err != nil {
		// The root command sets SilenceErrors so a gate failure exits
		// non-zero without printing a spurious "Error:" line over the
		// verdict it just rendered. That silence covers real errors too, so
		// they are printed here -- otherwise every failure that is not a
		// gate verdict exits 2 with no explanation whatsoever.
		if _, ok := err.(exitCoder); !ok {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(exitCodeFor(err))
	}
}

// exitCoder lets a command choose the process exit status, which is how a CI
// gate communicates its verdict.
type exitCoder interface {
	error
	ExitCode() int
}

type gateFailure struct{ code int }

func (g gateFailure) Error() string { return "" }
func (g gateFailure) ExitCode() int { return g.code }

func exitCodeFor(err error) int {
	if ec, ok := err.(exitCoder); ok {
		return ec.ExitCode()
	}
	return 2
}
