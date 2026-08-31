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
		// Cobra has already printed the message; exit non-zero without
		// repeating it.
		if _, ok := err.(exitCoder); !ok {
			fmt.Fprintln(os.Stderr)
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
