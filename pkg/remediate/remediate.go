// Package remediate turns a vulnerable package into an instruction a
// developer can act on.
//
// The gap this closes: a scanner says "lodash 4.17.11 is vulnerable, fixed in
// 4.17.21". But nothing in the project depends on lodash directly -- some
// build tool three levels up does. Telling somebody to upgrade a package that
// does not appear in their manifest is how security findings get closed as
// "won't fix".
//
// What is actually needed is:
//
//	vulnerable  lodash@4.17.11
//	introduced  express@4.17.1 -> body-parser@1.19.0 -> lodash
//	action      upgrade express to 4.18.2
//
// The direct dependency is the only thing the developer controls, so it is
// the only thing worth putting in a ticket.
package remediate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/DragonSecurity/dragonguard/pkg/depsdev"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// Path is a resolved route from a direct dependency to a vulnerable package.
type Path struct {
	// Direct is the dependency named in the project's own manifest.
	Direct string `json:"direct"`
	// DirectVersion is the version currently resolved for it.
	DirectVersion string `json:"direct_version"`
	// Via lists the intermediate packages, nearest-to-direct first.
	Via []string `json:"via,omitempty"`
	// Requirement is the version range the parent asked for, which decides
	// whether a fix is reachable without a major bump.
	Requirement string `json:"requirement,omitempty"`
}

// String renders the path the way it should appear in a report.
func (p Path) String() string {
	parts := append([]string{fmt.Sprintf("%s@%s", p.Direct, p.DirectVersion)}, p.Via...)
	return strings.Join(parts, " -> ")
}

// Advice is the remediation verdict for one finding.
type Advice struct {
	// Direct reports whether the vulnerable package is itself a direct
	// dependency, in which case there is nothing to trace.
	Direct bool `json:"direct"`
	// Paths are the routes by which the vulnerable package is introduced.
	// More than one means several direct dependencies must move.
	Paths []Path `json:"paths,omitempty"`
	// Action is the single sentence to put in front of a developer.
	Action string `json:"action"`
	// Confident reports whether a graph was actually resolved. Without it the
	// advice falls back to naming the vulnerable package, which is honest but
	// not necessarily actionable.
	Confident bool `json:"confident"`
}

// Resolver computes remediation advice from a resolved dependency graph.
type Resolver struct {
	Client *depsdev.Client
	// Offline skips every network call.
	Offline bool
	// Graph is the dependency graph a scanner already read from this
	// project's lockfiles. When present it is used in preference to the
	// network: it is instant, works offline, and describes what this project
	// actually resolved rather than what a registry would resolve today.
	Graph *scanner.PackageGraph
}

func New() *Resolver { return &Resolver{Client: depsdev.New()} }

// Inventory is the package list a scanner observed, used to identify which
// packages are direct dependencies of this project.
type Inventory struct {
	// Direct maps "ecosystem\x00name" to the version resolved for a direct
	// dependency.
	Direct map[string]string
}

// NewInventory builds an inventory of the project's direct dependencies.
//
// The graph is the better source when a scanner supplied one: findings only
// cover packages that turned out to be vulnerable, so an inventory built from
// them alone would miss every direct dependency that happens to be healthy --
// which is most of them, and exactly the ones a fix has to move.
func NewInventory(findings []finding.Finding, g *scanner.PackageGraph) *Inventory {
	inv := &Inventory{Direct: map[string]string{}}
	if !g.Empty() {
		for _, n := range g.Direct() {
			inv.Direct[key(n.Ecosystem, n.Name)] = n.Version
		}
	}
	for _, f := range findings {
		if f.Package != nil && f.Package.Direct {
			inv.Direct[key(f.Package.Ecosystem, f.Package.Name)] = f.Package.Version
		}
	}
	return inv
}

func key(ecosystem, name string) string {
	return finding.NormalizeEcosystem(ecosystem) + "\x00" + name
}

// Apply computes advice for every finding with a package and writes the
// result back onto Analysis.MinimalUpgrade and Package.IntroducedBy.
//
// Findings whose graph cannot be resolved keep whatever the scanner said.
// Degrading to the scanner's answer is the right failure mode: a slightly
// less useful instruction beats an empty one.
func (r *Resolver) Apply(ctx context.Context, findings []finding.Finding, inv *Inventory) map[string]Advice {
	out := map[string]Advice{}
	if inv == nil {
		inv = &Inventory{Direct: map[string]string{}}
	}

	// One resolution per distinct vulnerable package, shared across findings.
	type target struct {
		ecosystem, name, version, fixed string
	}
	targets := map[string]target{}
	byPkg := map[string][]int{}
	for i := range findings {
		p := findings[i].Package
		if p == nil || p.Name == "" {
			continue
		}
		k := key(p.Ecosystem, p.Name) + "\x00" + p.Version
		targets[k] = target{p.Ecosystem, p.Name, p.Version, findings[i].Analysis.FixedVersion}
		byPkg[k] = append(byPkg[k], i)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for k, t := range targets {
		wg.Add(1)
		go func(k string, t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			adv := r.adviseFor(ctx, t.ecosystem, t.name, t.version, t.fixed, inv)

			mu.Lock()
			defer mu.Unlock()
			for _, i := range byPkg[k] {
				f := &findings[i]
				out[f.Fingerprint] = adv
				if adv.Action != "" {
					f.Analysis.MinimalUpgrade = adv.Action
				}
				if len(adv.Paths) > 0 {
					f.Package.IntroducedBy = adv.Paths[0].Direct
					if f.Metadata == nil {
						f.Metadata = map[string]any{}
					}
					routes := make([]string, 0, len(adv.Paths))
					for _, p := range adv.Paths {
						routes = append(routes, p.String())
					}
					f.Metadata["introduced_via"] = routes
				}
			}
		}(k, t)
	}
	wg.Wait()
	return out
}

// adviseFor resolves one vulnerable package to an action.
func (r *Resolver) adviseFor(ctx context.Context, ecosystem, name, version, fixed string, inv *Inventory) Advice {
	// A direct dependency needs no tracing: the manifest already names it.
	if _, isDirect := inv.Direct[key(ecosystem, name)]; isDirect {
		return Advice{
			Direct:    true,
			Confident: true,
			Action:    upgradeSentence(name, version, fixed),
		}
	}

	// Local graph first.
	if local := LocalPaths(r.Graph, ecosystem, name, version); len(local) > 0 {
		return Advice{
			Confident: true,
			Paths:     local,
			Action:    actionSentence(name, version, fixed, local),
		}
	}

	if r.Offline || r.Client == nil {
		return Advice{Action: upgradeSentence(name, version, fixed)}
	}
	sys, ok := depsdev.SystemFor(ecosystem)
	if !ok {
		return Advice{Action: upgradeSentence(name, version, fixed)}
	}

	// Walk each direct dependency's resolved graph looking for the vulnerable
	// package. Doing it from the direct dependencies inward, rather than from
	// the vulnerable package outward, is what yields the name the developer
	// can actually change.
	paths := r.tracePaths(ctx, sys, name, version, inv)
	if len(paths) == 0 {
		return Advice{Action: upgradeSentence(name, version, fixed)}
	}

	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].Via) != len(paths[j].Via) {
			return len(paths[i].Via) < len(paths[j].Via)
		}
		return paths[i].Direct < paths[j].Direct
	})

	return Advice{
		Confident: true,
		Paths:     paths,
		Action:    actionSentence(name, version, fixed, paths),
	}
}

// tracePaths finds routes from each direct dependency to the vulnerable
// package.
func (r *Resolver) tracePaths(ctx context.Context, sys depsdev.System, wantName, wantVersion string, inv *Inventory) []Path {
	var mu sync.Mutex
	var paths []Path
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	prefix := string(sys) + "\x00"
	for k, ver := range inv.Direct {
		if !strings.HasPrefix(k, finding.NormalizeEcosystem(string(sys))+"\x00") && !strings.HasPrefix(k, prefix) {
			continue
		}
		directName := k[strings.Index(k, "\x00")+1:]
		if directName == wantName {
			continue
		}

		wg.Add(1)
		go func(directName, directVer string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			g, err := r.Client.Dependencies(ctx, sys, directName, directVer)
			if err != nil || g == nil {
				return
			}
			via, req, found := shortestRoute(g, wantName, wantVersion)
			if !found {
				return
			}
			mu.Lock()
			paths = append(paths, Path{
				Direct: directName, DirectVersion: directVer,
				Via: via, Requirement: req,
			})
			mu.Unlock()
		}(directName, ver)
	}
	wg.Wait()
	return paths
}

// shortestRoute breadth-first searches a resolved graph for the target
// package, returning the intermediate package names.
//
// Breadth-first rather than depth-first because the shortest route is the one
// most likely to be fixable by a single upgrade; a long chain usually means
// several maintainers have to move first.
func shortestRoute(g *depsdev.Graph, wantName, wantVersion string) (via []string, requirement string, found bool) {
	if g == nil || len(g.Nodes) == 0 {
		return nil, "", false
	}

	adj := map[int][]depsdev.Edge{}
	for _, e := range g.Edges {
		adj[e.FromNode] = append(adj[e.FromNode], e)
	}

	target := -1
	for i, n := range g.Nodes {
		if n.VersionKey.Name == wantName && versionsMatch(n.VersionKey.Version, wantVersion) {
			target = i
			break
		}
	}
	if target < 0 {
		return nil, "", false
	}
	if target == 0 {
		return nil, "", false
	}

	// BFS from the root (node 0 is always the SELF node).
	prev := map[int]depsdev.Edge{}
	seen := map[int]bool{0: true}
	queue := []int{0}
	for len(queue) > 0 && !seen[target] {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur] {
			if seen[e.ToNode] {
				continue
			}
			seen[e.ToNode] = true
			prev[e.ToNode] = e
			if e.ToNode == target {
				queue = nil
				break
			}
			queue = append(queue, e.ToNode)
		}
	}
	if !seen[target] {
		return nil, "", false
	}

	// Walk back to the root collecting the intermediate names.
	var chain []string
	node := target
	requirement = prev[target].Requirement
	for node != 0 {
		e, ok := prev[node]
		if !ok {
			break
		}
		chain = append(chain, g.Nodes[node].VersionKey.Name)
		node = e.FromNode
	}
	// chain is target-first; reverse so it reads root-outward.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, requirement, true
}

// versionsMatch compares versions tolerantly, since a resolved graph and a
// lockfile can spell the same release differently.
func versionsMatch(a, b string) bool {
	if b == "" {
		return true
	}
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

func upgradeSentence(name, version, fixed string) string {
	if fixed == "" {
		return ""
	}
	return fmt.Sprintf("%s %s -> %s", name, version, fixed)
}

// actionSentence names the direct dependency to move, which is the only part
// the developer controls.
func actionSentence(name, version, fixed string, paths []Path) string {
	if len(paths) == 0 {
		return upgradeSentence(name, version, fixed)
	}
	p := paths[0]
	base := fmt.Sprintf("%s@%s is pulled in via %s", name, version, p.String())
	if fixed != "" {
		base += fmt.Sprintf("; needs %s >= %s", name, fixed)
	}
	switch {
	case len(paths) == 1:
		return base + fmt.Sprintf(" -- upgrade %s", p.Direct)
	default:
		others := make([]string, 0, len(paths)-1)
		for _, o := range paths[1:] {
			others = append(others, o.Direct)
		}
		// Naming every route matters: upgrading one direct dependency leaves
		// the vulnerable version resolved through the others.
		return base + fmt.Sprintf(" -- upgrade %s (also reached via %s)",
			p.Direct, strings.Join(others, ", "))
	}
}
