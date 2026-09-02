package scanner

import (
	"context"
	"sort"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// PackageNode is one component in a resolved dependency graph.
type PackageNode struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl,omitempty"`
	// Direct reports that the project's own manifest names this package.
	Direct bool `json:"direct"`
	// Directness records how Direct was decided: "relationship", "indirect",
	// or "unknown" when the scanner classified nothing for this target.
	//
	// Carried separately because false means two different things. A package
	// the scanner examined and called transitive is not the same as one it
	// never classified, and a consumer that cannot tell them apart will read
	// the second as the first -- which is how every package in a yarn.lock
	// came to be reported as a direct dependency.
	Directness string `json:"directness,omitempty"`
	// DevOnly reports a dependency that never reaches a production artifact.
	DevOnly bool `json:"dev_only"`
	// DependsOn holds the keys of this node's resolved dependencies.
	DependsOn []string `json:"depends_on,omitempty"`
}

// PackageGraph is the dependency graph a scanner observed while reading a
// project's lockfiles.
//
// Collecting it is what lets remediation say "upgrade express" instead of
// "upgrade lodash", using data the scanner already had to parse. Doing it
// locally beats resolving the same graph over the network: it is faster, it
// works offline, and it reflects what this project actually resolved rather
// than what a public registry would resolve today.
type PackageGraph struct {
	Nodes map[string]PackageNode `json:"nodes"`
}

func NewPackageGraph() *PackageGraph {
	return &PackageGraph{Nodes: map[string]PackageNode{}}
}

// GraphKey is the canonical identity of a node.
func GraphKey(ecosystem, name, version string) string {
	return finding.NormalizeEcosystem(ecosystem) + "\x00" + name + "\x00" + strings.TrimPrefix(version, "v")
}

// Add inserts or merges a node.
func (g *PackageGraph) Add(n PackageNode) {
	if g.Nodes == nil {
		g.Nodes = map[string]PackageNode{}
	}
	k := GraphKey(n.Ecosystem, n.Name, n.Version)
	if existing, ok := g.Nodes[k]; ok {
		// Merge monotonically: once any scanner has established a package is
		// direct, another scanner's silence must not demote it.
		if existing.Direct {
			n.Direct = true
		}
		if len(n.DependsOn) == 0 {
			n.DependsOn = existing.DependsOn
		}
		if n.PURL == "" {
			n.PURL = existing.PURL
		}
	}
	g.Nodes[k] = n
}

// Sorted returns every node in a stable order.
//
// Stable because this travels: it is written into reports that get diffed and
// posted to the platform, and a map's iteration order would make two scans of
// an unchanged project look like a change.
func (g *PackageGraph) Sorted() []PackageNode {
	if g == nil || len(g.Nodes) == 0 {
		return nil
	}
	out := make([]PackageNode, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out
}

// Merge folds another graph into this one.
func (g *PackageGraph) Merge(other *PackageGraph) {
	if other == nil {
		return
	}
	for _, n := range other.Nodes {
		g.Add(n)
	}
}

// Direct returns the project's direct dependencies.
func (g *PackageGraph) Direct() []PackageNode {
	var out []PackageNode
	for _, n := range g.Nodes {
		if n.Direct {
			out = append(out, n)
		}
	}
	return out
}

// Lookup finds a node by identity, tolerating version-prefix differences.
func (g *PackageGraph) Lookup(ecosystem, name, version string) (PackageNode, bool) {
	n, ok := g.Nodes[GraphKey(ecosystem, name, version)]
	return n, ok
}

// Empty reports whether anything was collected.
func (g *PackageGraph) Empty() bool { return g == nil || len(g.Nodes) == 0 }

// GraphScanner is a Scanner that can also report the dependency graph it read.
//
// Optional on purpose: a SAST or DAST engine has no graph to report, and
// requiring one would put an empty method on every adapter. The pipeline type
// asserts for it and takes the graph when it is offered.
type GraphScanner interface {
	Scanner
	// ScanWithGraph returns findings and the dependency graph observed in the
	// same pass, so the lockfiles are only parsed once.
	ScanWithGraph(ctx context.Context, t Target) ([]finding.Finding, *PackageGraph, error)
}
