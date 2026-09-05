package ships

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// fixture builds a module whose tool dependency is reachable only from a
// package under tools/, which is the shape the whole problem has: two modules
// in one go.mod, one of them linked into the binary and one of them not.
//
// Local replace directives, so the test needs no network and no module cache.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("go.mod", `module example.com/app

go 1.21

require (
	example.com/prod v0.0.0
	example.com/tool v0.0.0
)

replace example.com/prod => ./deps/prod

replace example.com/tool => ./deps/tool
`)
	write("main.go", `package main

import "example.com/prod"

func main() { _ = prod.X }
`)
	write("tools/gen/main.go", `package main

import "example.com/tool"

func main() { _ = tool.Y }
`)
	write("deps/prod/go.mod", "module example.com/prod\n\ngo 1.21\n")
	write("deps/prod/prod.go", "package prod\n\nconst X = 1\n")
	write("deps/tool/go.mod", "module example.com/tool\n\ngo 1.21\n")
	write("deps/tool/tool.go", "package tool\n\nconst Y = 2\n")

	// A stale go.sum or workspace from the developer's environment would make
	// this test about their machine.
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "")
	return dir
}

func TestResolveSeparatesWhatShipsFromWhatOnlyBuilds(t *testing.T) {
	dir := fixture(t)

	shipped, err := Resolve(context.Background(), dir, []string{"."}, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !shipped["example.com/app"] {
		t.Error("the module under scan ships")
	}
	if !shipped["example.com/prod"] {
		t.Error("a module the binary links must be shipped")
	}
	if shipped["example.com/tool"] {
		t.Error("a module reachable only from tools/ is not shipped")
	}
}

// Naming the tool as an entry point too must bring its dependency back. The
// list is what the project ships, not a fixed idea of what a tool directory is.
func TestDeclaringAToolAsAnEntryPointShipsIt(t *testing.T) {
	dir := fixture(t)

	shipped, err := Resolve(context.Background(), dir, []string{".", "./tools/..."}, false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !shipped["example.com/tool"] {
		t.Error("a package named in ships: must contribute to the shipped closure")
	}
}

// The failure that must never happen quietly: a typo that matches nothing would
// otherwise mark every dependency build-only and silence the dimension.
func TestAPatternMatchingNothingIsAnErrorNotAnEmptyClosure(t *testing.T) {
	dir := fixture(t)

	if _, err := Resolve(context.Background(), dir, []string{"./no/such/dir/..."}, false); err == nil {
		t.Fatal("a pattern that matches nothing must fail rather than return an empty closure")
	}
	if _, err := Resolve(context.Background(), dir, nil, false); err == nil {
		t.Fatal("resolving nothing must fail")
	}
}

func TestApplyMarksComponentsAndTheFindingsThatCarryThem(t *testing.T) {
	shipped := map[string]bool{"example.com/app": true, "example.com/prod": true}
	components := []scanner.PackageNode{
		{Ecosystem: "go", Name: "example.com/app", Version: "v0.0.0", Root: true},
		{Ecosystem: "go", Name: "example.com/prod", Version: "v1.0.0", Direct: true},
		{Ecosystem: "gomod", Name: "example.com/tool", Version: "v1.0.0", Direct: true},
		// Another ecosystem records this itself; leave it alone.
		{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Direct: true},
	}
	findings := []finding.Finding{
		{Package: &finding.Package{Ecosystem: "go", Name: "example.com/tool", Version: "v1.0.0"}},
		{Package: &finding.Package{Ecosystem: "go", Name: "example.com/prod", Version: "v1.0.0"}},
		{Package: &finding.Package{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}},
		// A finding with no package at all must not panic anything.
		{RuleID: "some-sast-rule"},
	}

	rep := Apply(shipped, components, findings)

	if !rep.Determined {
		t.Fatal("Apply always determines; only Resolve can fail")
	}
	if rep.DevOnly != 1 || rep.Shipped != 1 {
		t.Errorf("report = %+v, want one shipped and one build-only (root and npm excluded)", rep)
	}
	if !components[2].DevOnly {
		t.Error("the tool-only module should be marked build-only")
	}
	if components[1].DevOnly {
		t.Error("a shipped module must not be marked build-only")
	}
	if components[0].DevOnly {
		t.Error("the project's own module is not a build-only dependency")
	}
	if components[3].DevOnly {
		t.Error("a non-Go component must be left as its own ecosystem reported it")
	}
	if !findings[0].Package.DevOnly {
		t.Error("the finding on the tool-only module should carry dev_only")
	}
	if findings[1].Package.DevOnly || findings[2].Package.DevOnly {
		t.Error("only findings on build-only Go modules should be marked")
	}
}

// "Not determined" and "nothing is build-only" are different answers, and
// reporting the first as the second is what made the built-in policy rule
// silently inert.
func TestAnUndeterminedResultSaysSoRatherThanReadingAsClean(t *testing.T) {
	undetermined := Report{Reason: "set ships: to name the packages that reach production"}
	if undetermined.Note() == "" {
		t.Error("an undetermined result must say something")
	}

	determined := Report{Determined: true, Shipped: 81, DevOnly: 47}
	note := determined.Note()
	if note == "" || note == undetermined.Note() {
		t.Errorf("a determined result should read differently: %q", note)
	}

	// No Go in the tree at all: nothing to report either way.
	if (Report{}).Note() != "" {
		t.Error("a project with no Go dependencies should say nothing about them")
	}
}
