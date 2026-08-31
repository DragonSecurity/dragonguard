package remediate

import (
	"sort"

	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// LocalPaths traces routes to a vulnerable package using the dependency graph
// a scanner already read from the project's lockfiles.
//
// Preferred over the network graph whenever it is available: it is instant, it
// works offline, and crucially it describes what this project actually
// resolved rather than what a public registry would resolve today. A lockfile
// pinned two years ago does not resolve the way deps.dev says it would.
func LocalPaths(g *scanner.PackageGraph, ecosystem, name, version string) []Path {
	if g.Empty() {
		return nil
	}
	targetKey := scanner.GraphKey(ecosystem, name, version)
	if _, ok := g.Nodes[targetKey]; !ok {
		return nil
	}

	// Breadth-first from every direct dependency. The shortest route is the
	// one most likely fixable by a single upgrade; a long chain usually means
	// several maintainers have to move before you can.
	var paths []Path
	for _, root := range g.Direct() {
		rootKey := scanner.GraphKey(root.Ecosystem, root.Name, root.Version)
		if rootKey == targetKey {
			// The vulnerable package is itself direct; nothing to trace.
			return nil
		}
		if chain, ok := bfs(g, rootKey, targetKey); ok {
			paths = append(paths, Path{
				Direct:        root.Name,
				DirectVersion: root.Version,
				Via:           chain,
			})
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i].Via) != len(paths[j].Via) {
			return len(paths[i].Via) < len(paths[j].Via)
		}
		return paths[i].Direct < paths[j].Direct
	})
	return paths
}

// bfs finds the shortest route between two nodes, returning the intermediate
// package names in root-outward order.
func bfs(g *scanner.PackageGraph, from, to string) ([]string, bool) {
	if from == to {
		return nil, true
	}
	prev := map[string]string{}
	seen := map[string]bool{from: true}
	queue := []string{from}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		node := g.Nodes[cur]
		for _, dep := range node.DependsOn {
			// Trivy's DependsOn holds package IDs ("name@version"), which are
			// resolved against the graph by matching on identity rather than
			// assuming the ID format.
			depKey, ok := resolveDep(g, node.Ecosystem, dep)
			if !ok || seen[depKey] {
				continue
			}
			seen[depKey] = true
			prev[depKey] = cur
			if depKey == to {
				return walkBack(g, prev, from, to), true
			}
			queue = append(queue, depKey)
		}
	}
	return nil, false
}

// resolveDep maps a scanner's dependency reference onto a graph key.
func resolveDep(g *scanner.PackageGraph, ecosystem, ref string) (string, bool) {
	// Trivy emits "name@version"; split on the last @ so scoped npm names
	// such as "@babel/core@7.0.0" survive.
	name, version := ref, ""
	for i := len(ref) - 1; i > 0; i-- {
		if ref[i] == '@' {
			name, version = ref[:i], ref[i+1:]
			break
		}
	}
	k := scanner.GraphKey(ecosystem, name, version)
	if _, ok := g.Nodes[k]; ok {
		return k, true
	}
	// Fall back to matching by name alone when the version does not line up.
	for key, n := range g.Nodes {
		if n.Name == name && n.Ecosystem == g.Nodes[k].Ecosystem {
			return key, true
		}
		if n.Name == ref {
			return key, true
		}
	}
	return "", false
}

func walkBack(g *scanner.PackageGraph, prev map[string]string, from, to string) []string {
	var chain []string
	cur := to
	for cur != from {
		chain = append(chain, g.Nodes[cur].Name)
		p, ok := prev[cur]
		if !ok {
			break
		}
		cur = p
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}
