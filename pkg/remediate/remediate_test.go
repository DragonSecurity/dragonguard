package remediate

import (
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// graph builds a dependency graph the way Trivy reports one.
func graph(nodes ...scanner.PackageNode) *scanner.PackageGraph {
	g := scanner.NewPackageGraph()
	for _, n := range nodes {
		g.Add(n)
	}
	return g
}

func node(name, version string, direct bool, deps ...string) scanner.PackageNode {
	return scanner.PackageNode{
		Ecosystem: "npm", Name: name, Version: version,
		Direct: direct, DependsOn: deps,
	}
}

// The whole point: name the dependency the developer can actually change.
func TestTracesTransitiveVulnerabilityToItsDirectDependency(t *testing.T) {
	g := graph(
		node("express", "4.17.1", true, "body-parser@1.19.0"),
		node("body-parser", "1.19.0", false, "qs@6.7.0"),
		node("qs", "6.7.0", false),
	)

	paths := LocalPaths(g, "npm", "qs", "6.7.0")
	if len(paths) != 1 {
		t.Fatalf("got %d paths, want 1", len(paths))
	}
	if paths[0].Direct != "express" {
		t.Errorf("direct = %q, want express -- the only thing in the manifest", paths[0].Direct)
	}
	want := []string{"body-parser", "qs"}
	if strings.Join(paths[0].Via, ",") != strings.Join(want, ",") {
		t.Errorf("via = %v, want %v", paths[0].Via, want)
	}

	action := actionSentence("qs", "6.7.0", "6.14.2", paths)
	for _, frag := range []string{"qs@6.7.0", "express@4.17.1", "upgrade express", ">= 6.14.2"} {
		if !strings.Contains(action, frag) {
			t.Errorf("action %q is missing %q", action, frag)
		}
	}
}

// Upgrading one direct dependency leaves the vulnerable version resolved
// through the others, so every route has to be named.
func TestEveryRouteIsReported(t *testing.T) {
	g := graph(
		node("express", "4.17.1", true, "qs@6.7.0"),
		node("body-parser", "1.19.0", true, "qs@6.7.0"),
		node("qs", "6.7.0", false),
	)

	paths := LocalPaths(g, "npm", "qs", "6.7.0")
	if len(paths) != 2 {
		t.Fatalf("got %d paths, want 2", len(paths))
	}
	action := actionSentence("qs", "6.7.0", "", paths)
	if !strings.Contains(action, "also reached via") {
		t.Errorf("action must name the other routes, got %q", action)
	}
}

// The shortest route is the one most likely fixable by a single upgrade.
func TestShortestRouteIsPreferred(t *testing.T) {
	g := graph(
		node("short", "1.0.0", true, "target@1.0.0"),
		node("long", "1.0.0", true, "mid@1.0.0"),
		node("mid", "1.0.0", false, "target@1.0.0"),
		node("target", "1.0.0", false),
	)
	paths := LocalPaths(g, "npm", "target", "1.0.0")
	if len(paths) != 2 {
		t.Fatalf("got %d paths, want 2", len(paths))
	}
	if paths[0].Direct != "short" {
		t.Errorf("first path is %q, want the shortest route (short)", paths[0].Direct)
	}
}

// A package that is itself direct needs no tracing; the manifest names it.
func TestDirectDependencyNeedsNoTracing(t *testing.T) {
	g := graph(node("lodash", "4.17.11", true))
	if paths := LocalPaths(g, "npm", "lodash", "4.17.11"); len(paths) != 0 {
		t.Errorf("a direct dependency should produce no trace, got %v", paths)
	}
}

func TestUnknownPackageProducesNoPaths(t *testing.T) {
	g := graph(node("express", "4.17.1", true))
	if paths := LocalPaths(g, "npm", "nothing-here", "1.0.0"); len(paths) != 0 {
		t.Error("a package absent from the graph should produce no paths")
	}
	if paths := LocalPaths(nil, "npm", "x", "1.0.0"); len(paths) != 0 {
		t.Error("a nil graph should produce no paths")
	}
}

// A cycle in the graph must not hang the resolver.
func TestCyclesTerminate(t *testing.T) {
	g := graph(
		node("a", "1.0.0", true, "b@1.0.0"),
		node("b", "1.0.0", false, "c@1.0.0"),
		node("c", "1.0.0", false, "b@1.0.0"),
	)
	done := make(chan []Path, 1)
	go func() { done <- LocalPaths(g, "npm", "c", "1.0.0") }()
	select {
	case paths := <-done:
		if len(paths) != 1 || paths[0].Direct != "a" {
			t.Errorf("paths = %v, want a single route through a", paths)
		}
	default:
		// LocalPaths is synchronous; if it had hung the goroutine would not
		// have delivered. Read again to be sure.
		if paths := <-done; len(paths) == 0 {
			t.Error("cycle produced no path")
		}
	}
}

// Scoped npm names contain @, so splitting on the first one would break them.
func TestScopedPackageNamesResolve(t *testing.T) {
	g := graph(
		node("app", "1.0.0", true, "@babel/core@7.0.0"),
		node("@babel/core", "7.0.0", false),
	)
	paths := LocalPaths(g, "npm", "@babel/core", "7.0.0")
	if len(paths) != 1 || paths[0].Direct != "app" {
		t.Errorf("scoped package was not resolved: %v", paths)
	}
}

// The inventory must come from the graph, not only from findings: findings
// cover just the vulnerable packages, and the direct dependency that needs
// upgrading is usually a healthy one.
func TestInventoryPrefersTheGraph(t *testing.T) {
	g := graph(
		node("express", "4.17.1", true),
		node("qs", "6.7.0", false),
	)
	inv := NewInventory(nil, g)
	if _, ok := inv.Direct[key("npm", "express")]; !ok {
		t.Error("a healthy direct dependency must be in the inventory")
	}
	if _, ok := inv.Direct[key("npm", "qs")]; ok {
		t.Error("a transitive dependency must not be listed as direct")
	}

	// Findings still contribute when no graph was collected.
	fs := []finding.Finding{{Package: &finding.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.11", Direct: true}}}
	inv = NewInventory(fs, nil)
	if _, ok := inv.Direct[key("npm", "lodash")]; !ok {
		t.Error("a direct package from a finding must be in the inventory")
	}
}

// Ecosystem spellings differ between engines; the graph key must canonicalize.
func TestGraphKeyIsSpellingIndependent(t *testing.T) {
	if scanner.GraphKey("gomod", "x", "v1.0.0") != scanner.GraphKey("Go", "x", "1.0.0") {
		t.Error("graph keys must be independent of ecosystem spelling and the v prefix")
	}
}

func TestPathStringReadsRootOutward(t *testing.T) {
	p := Path{Direct: "express", DirectVersion: "4.17.1", Via: []string{"body-parser", "qs"}}
	if got := p.String(); got != "express@4.17.1 -> body-parser -> qs" {
		t.Errorf("String() = %q", got)
	}
}
