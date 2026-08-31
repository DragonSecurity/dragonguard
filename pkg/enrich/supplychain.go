package enrich

import (
	"context"
	"sync"

	"github.com/DragonSecurity/dragonguard/pkg/depsdev"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// SupplyChainReport describes what supply-chain enrichment achieved.
type SupplyChainReport struct {
	Available bool `json:"available"`
	// Resolved counts packages for which a Scorecard was found.
	Resolved int `json:"resolved"`
	// Unresolved counts packages deps.dev knows nothing about. These are not
	// failures: a private or vendored package has no upstream to assess.
	Unresolved int      `json:"unresolved"`
	Queried    int      `json:"queried"`
	Notes      []string `json:"notes,omitempty"`
}

// SupplyChain annotates findings with the OpenSSF Scorecard of the project
// that publishes each package.
//
// This is what makes Dragon Risk's supply-chain component scoreable at all.
// Without it that 15% is permanently excluded, and the score reflects only
// what is wrong with a dependency today rather than how likely the project
// behind it is to ship the next problem -- or to be slow fixing it.
//
// Note what is deliberately *not* done here: a package with no Scorecard is
// left with HasScorecard false, so the risk engine excludes the component and
// redistributes its weight. Substituting an average score would be inventing
// evidence about a project nobody has assessed.
func (e *Enricher) SupplyChain(ctx context.Context, findings []finding.Finding) SupplyChainReport {
	var rep SupplyChainReport
	if e.opts.Offline {
		rep.Notes = append(rep.Notes, "offline: supply-chain posture not assessed")
		return rep
	}

	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	client := e.deps
	if client == nil {
		client = depsdev.New()
	}

	// One lookup per distinct package, not per finding: ten CVEs in lodash is
	// one upstream project to assess.
	type pkgKey struct {
		system        depsdev.System
		name, version string
	}
	targets := map[pkgKey][]int{}
	for i := range findings {
		p := findings[i].Package
		if p == nil || p.Name == "" || p.Version == "" {
			continue
		}
		sys, ok := depsdev.SystemFor(p.Ecosystem)
		if !ok {
			// OS packages (alpine, debian) have no upstream project in
			// deps.dev's sense; skipping them is correct, not a gap.
			continue
		}
		k := pkgKey{sys, p.Name, p.Version}
		targets[k] = append(targets[k], i)
	}
	rep.Queried = len(targets)
	if rep.Queried == 0 {
		return rep
	}

	conc := client.Concurrency
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for k, idxs := range targets {
		wg.Add(1)
		go func(k pkgKey, idxs []int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			sc, err := client.ScorecardFor(ctx, k.system, k.name, k.version)

			mu.Lock()
			defer mu.Unlock()
			if err != nil || sc == nil {
				rep.Unresolved++
				return
			}
			rep.Resolved++
			rep.Available = true
			for _, i := range idxs {
				findings[i].Analysis.ScorecardScore = sc.OverallScore
				findings[i].Analysis.HasScorecard = true
			}
		}(k, idxs)
	}
	wg.Wait()

	if rep.Resolved == 0 && rep.Queried > 0 {
		rep.Notes = append(rep.Notes, "supply-chain posture unavailable: no Scorecard results resolved")
	}
	return rep
}
