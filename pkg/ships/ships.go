// Package ships establishes which dependencies reach a production artifact.
//
// Every other ecosystem records this. npm splits dependencies from
// devDependencies, and Trivy's lockfile readers carry the distinction through.
// Go records nothing: go.mod lists what the module needs to build, and a
// code-generation tool imported by a package under tools/ sits in exactly the
// same list as the database driver the server opens at startup.
//
// The consequence was not that the information was missing but that its absence
// was reported as a fact. Every Go dependency arrived with dev_only false --
// not "unknown", false -- so the built-in policy rule written for build-only
// dependencies could never fire, and a scan attributed the whole GCP and
// Spanner tree that arrives through a schema-generation tool to a service that
// never links it. A project's dependencies dimension then reads differently
// from the same commit's hosted check, and neither number can be used as a
// floor.
//
// The toolchain can answer the question exactly, given the one thing only the
// project knows: which packages are the things it ships.
package ships

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// Report records what was established, or why nothing was.
type Report struct {
	// Determined is false when the closure could not be computed. The
	// difference matters: undetermined means every Go dependency keeps
	// dev_only false because nothing is known, which is what the old
	// behaviour was doing silently.
	Determined bool `json:"determined"`
	// Reason explains an undetermined result.
	Reason string `json:"reason,omitempty"`
	// Shipped and DevOnly count Go modules either side of the line.
	Shipped int `json:"shipped,omitempty"`
	DevOnly int `json:"dev_only,omitempty"`
}

// Note renders a one-line summary for the evidence block.
func (r Report) Note() string {
	if !r.Determined {
		if r.Reason == "" {
			return ""
		}
		return "build-only dependencies not determined: " + r.Reason
	}
	return fmt.Sprintf("%d of %d Go module(s) never reach a shipped binary",
		r.DevOnly, r.Shipped+r.DevOnly)
}

// Resolve returns the Go modules that reach one of the named packages.
//
// patterns are ordinary `go list` package patterns -- ".", "./cmd/...", an
// import path -- naming what this project actually ships. Everything the
// toolchain does not reach from them is build-only by construction: not a
// heuristic about directory names, but the same closure the linker walks.
func Resolve(ctx context.Context, dir string, patterns []string, offline bool) (map[string]bool, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("nothing declared; set ships: to name what reaches production")
	}
	if _, err := exec.LookPath("go"); err != nil {
		return nil, fmt.Errorf("the go toolchain is not on PATH")
	}

	args := append([]string{
		"list", "-deps", "-f", "{{if .Module}}{{.Module.Path}}{{end}}",
	}, patterns...)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	if offline {
		// An offline scan must not reach for the module proxy. Failing here is
		// the right outcome: a closure computed from a partial module cache
		// would mark real dependencies build-only, which is the one error this
		// package must not make.
		cmd.Env = append(cmd.Environ(), "GOPROXY=off", "GOFLAGS=-mod=mod")
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %s", firstLine(stderr.String(), err))
	}

	shipped := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if m := strings.TrimSpace(sc.Text()); m != "" {
			shipped[m] = true
		}
	}
	if len(shipped) == 0 {
		// A pattern that matched no package exits zero and prints nothing.
		// Treating that as "everything is build-only" would silence the whole
		// dependency dimension from a typo.
		return nil, fmt.Errorf("%s matched no packages", strings.Join(patterns, " "))
	}
	return shipped, nil
}

// Apply marks Go components and findings that fall outside the shipped
// closure, and reports what it did.
func Apply(shipped map[string]bool, components []scanner.PackageNode, findings []finding.Finding) Report {
	rep := Report{Determined: true}
	dev := map[string]bool{}

	for i := range components {
		c := &components[i]
		if !isGo(c.Ecosystem) || c.Root {
			continue
		}
		if shipped[c.Name] {
			rep.Shipped++
			continue
		}
		c.DevOnly = true
		dev[c.Name] = true
		rep.DevOnly++
	}

	// Findings carry their own copy of the package, and the ones from the
	// first pass were built before any of this was known.
	for i := range findings {
		p := findings[i].Package
		if p == nil || !isGo(p.Ecosystem) {
			continue
		}
		if dev[p.Name] {
			p.DevOnly = true
		}
	}
	return rep
}

// isGo accepts the spellings the ecosystem normaliser produces and the ones
// the adapters emit before it runs.
func isGo(eco string) bool {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "go", "gomod", "golang":
		return true
	}
	return false
}

func firstLine(s string, fallback error) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return fallback.Error()
}
