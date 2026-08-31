// Command dragon is the DragonGuard CLI: the security quality gate.
package main

import (
	"fmt"
	"os"
)

// version is overridden at build time with -ldflags.
var version = "0.1.0-dev"

func main() {
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
