// Package supplychain assesses the projects behind a dependency, rather than
// the dependency itself.
//
// Every other engine answers "what is wrong with this code". This one answers
// "how likely is the project that publishes it to ship the next problem, or to
// be slow fixing it" -- which is the question a dependency choice is actually
// a bet on, and the only one that is answerable before anything has gone
// wrong.
//
// The data was already being fetched. OpenSSF Scorecard results arrive through
// deps.dev on every scan and were consumed only as a modifier on findings that
// already existed, so a dependency with no vulnerability contributed nothing
// and the supply_chain dimension reported "no engine configured" permanently.
// A dimension that can never be assessed is worse than one that does not
// exist: it looks like coverage.
package supplychain

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

// Name is the stable engine identifier.
const Name = "supplychain"

// lowScorecard is the overall OpenSSF Scorecard below which a direct
// dependency is worth a decision.
//
// Four rather than something higher because most of the ecosystem sits between
// four and seven, and a threshold that flags half the dependency tree is a
// threshold nobody reads. Below four means several of the checks that matter
// are failing at once, not that a project skipped one questionnaire.
const lowScorecard = 4.0

// quietAndWeak is the overall score below which prolonged inactivity is worth
// reporting. Above it, no recent commits usually means finished rather than
// abandoned.
const quietAndWeak = 5.0

// Why only deprecation gates.
//
// Scorecard measures how a project is run -- branch protection, code review,
// fuzzing, a CII badge -- not how dangerous its code is to you. Small, stable,
// finished libraries fail those checks by construction: clsx scores 3/10 on
// Branch-Protection, CII-Best-Practices, Code-Review and Fuzzing, and none of
// those is a thing wrong with a two-hundred-byte utility that does one thing
// correctly. Gating on it would mean a dimension whose findings are mostly
// "this tiny library does not run a fuzzer", which is the shape of report
// people learn to skip -- and once skipped, the deprecation notice sitting
// beside it gets skipped too.
//
// So process signals are recorded at info and deprecation is not. A publisher
// marking a version deprecated is an unambiguous statement that it will not be
// fixed, which is a decision the project has to make rather than a number to
// compare against a threshold.

// Scanner assesses the upstream posture of a project's direct dependencies.
type Scanner struct {
	Client *depsdev.Client
	// Concurrency bounds in-flight deps.dev lookups.
	Concurrency int
}

func New() *Scanner { return &Scanner{Client: depsdev.New(), Concurrency: 8} }

func (s *Scanner) Name() string { return Name }

// NeedsInventory marks this engine as second-pass: it assesses what the
// lockfile readers resolved, so it cannot run alongside them.
func (s *Scanner) NeedsInventory() bool { return true }

func (s *Scanner) Categories() []finding.Category {
	return []finding.Category{finding.CategorySupplyChain}
}

// Available reports whether this engine can say anything on this run.
//
// It needs a resolved inventory, which is produced by the engines that read
// lockfiles, so on the first pass it has nothing to assess and says so. That
// is the same answer a DAST engine gives with no target configured: a standing
// coverage gap rather than a failure.
func (s *Scanner) Available(_ context.Context, t scanner.Target) (bool, string) {
	if t.Config != nil && t.Config.Offline {
		return false, "offline: upstream posture needs deps.dev"
	}
	if len(t.Components) == 0 {
		return false, "no resolved components; run an SCA engine in the same scan"
	}
	if len(directOf(t.Components)) == 0 {
		// Not an error. Trivy classifies nothing for some lockfiles, so
		// "direct" is unestablished rather than false, and assessing every
		// transitive package would report projects nobody chose.
		return false, "no dependency was established as direct; nothing to assess"
	}
	return true, ""
}

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	direct := directOf(t.Components)
	if len(direct) == 0 {
		return nil, nil
	}

	conc := s.Concurrency
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var (
		mu  sync.Mutex
		out []finding.Finding
		wg  sync.WaitGroup
	)

	for i := range direct {
		n := direct[i]
		sys, ok := depsdev.SystemFor(n.Ecosystem)
		if !ok {
			// An ecosystem deps.dev does not serve is not a finding. Querying
			// the wrong system returns a confident answer about the wrong
			// package.
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fs := s.assess(ctx, sys, n)
			if len(fs) == 0 {
				return
			}
			mu.Lock()
			out = append(out, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Stable order: engines run concurrently and a report that reshuffles
	// between identical scans looks like it changed.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Package.Name < b.Package.Name
	})
	return out, nil
}

// assess produces the findings for one direct dependency.
func (s *Scanner) assess(ctx context.Context, sys depsdev.System, n scanner.PackageNode) []finding.Finding {
	var out []finding.Finding
	pkg := &finding.Package{
		Ecosystem: n.Ecosystem, Name: n.Name, Version: n.Version,
		PURL: n.PURL, Direct: true, DevOnly: n.DevOnly,
	}

	if deprecated, err := s.Client.Deprecated(ctx, sys, n.Name, n.Version); err == nil && deprecated {
		out = append(out, finding.Finding{
			Scanner:  Name,
			Category: finding.CategorySupplyChain,
			RuleID:   "supply-chain/deprecated",
			Title:    fmt.Sprintf("%s is deprecated upstream", n.Name),
			Message: "The publisher has marked this version deprecated. It will not " +
				"receive fixes, so the next vulnerability found in it stays open.",
			// The strongest signal here, and unambiguous: the upstream is
			// saying stop, in its own registry, rather than it being inferred
			// from commit activity.
			Severity:   finding.SeverityHigh,
			Package:    pkg,
			Location:   finding.Location{File: n.Name + "@" + n.Version},
			References: []string{"https://deps.dev/" + string(sys) + "/" + n.Name},
		})
	}

	card, err := s.Client.ScorecardFor(ctx, sys, n.Name, n.Version)
	if err != nil || card == nil {
		// A project deps.dev cannot resolve -- private, vendored, renamed --
		// has no upstream to assess. Reporting that as a finding would make
		// every internal dependency look risky.
		return out
	}

	// One finding per dependency, not one per rule that happens to match.
	//
	// These two conditions overlap by construction -- quiet requires an
	// overall below five, weak requires below four -- so anything under four
	// tripped both and the report carried "otp has been quiet and scores
	// 2.9/10" directly above "otp scores 2.9/10 on OpenSSF Scorecard". Two
	// rows, one fact, and a reader counting rows concludes there are twice as
	// many problems as there are.
	//
	// Inactivity alone is not abandonment either. The Maintained check scores
	// zero after ninety quiet days, which is normal for a library that is
	// simply finished, so silence only counts when the rest of the score is
	// weak too.
	maintained, hasMaintained := checkScore(card, "Maintained")
	quiet := hasMaintained && maintained == 0
	weak := card.OverallScore > 0 && card.OverallScore < lowScorecard

	switch {
	case weak:
		title := fmt.Sprintf("%s scores %.1f/10 on OpenSSF Scorecard", n.Name, card.OverallScore)
		msg := "Weakest checks: " + weakest(card) + ". Scorecard measures a " +
			"project's process, not this dependency's risk to you."
		if quiet {
			// The silence is worth saying, but as part of the same finding
			// rather than as a second one.
			title = fmt.Sprintf("%s scores %.1f/10 upstream and has been quiet",
				n.Name, card.OverallScore)
			msg = "No recent commits or releases, alongside weak scores elsewhere. " +
				"Weakest checks: " + weakest(card) + "."
		}
		out = append(out, finding.Finding{
			Scanner:    Name,
			Category:   finding.CategorySupplyChain,
			RuleID:     "supply-chain/weak-upstream",
			Title:      title,
			Message:    msg,
			Severity:   finding.SeverityInfo,
			Package:    pkg,
			Location:   finding.Location{File: n.Name + "@" + n.Version},
			References: scorecardRefs(card),
			Metadata:   map[string]any{"scorecard": card.OverallScore, "quiet": quiet},
		})

	case quiet && card.OverallScore > 0 && card.OverallScore < quietAndWeak:
		out = append(out, finding.Finding{
			Scanner:  Name,
			Category: finding.CategorySupplyChain,
			RuleID:   "supply-chain/quiet",
			Title: fmt.Sprintf("%s has been quiet and scores %.1f/10 upstream",
				n.Name, card.OverallScore),
			Message: "No recent commits or releases. Worth a look before the next " +
				"vulnerability lands in it, though a library that is simply " +
				"finished looks the same from here.",
			Severity:   finding.SeverityInfo,
			Package:    pkg,
			Location:   finding.Location{File: n.Name + "@" + n.Version},
			References: scorecardRefs(card),
			Metadata:   map[string]any{"scorecard": card.OverallScore, "quiet": true},
		})
	}

	return out
}

// directOf returns the dependencies the project's own manifest names.
//
// Direct only, deliberately. A weak Scorecard on a transitive dependency five
// levels down is not something anybody can act on -- you did not choose it and
// cannot replace it -- and a dimension full of findings nobody can action is
// one people learn to skip.
//
// The root package is excluded because it is not a dependency: it is the
// project being scanned. Looking it up returns whatever public package shares
// its name, which for a workspace called "ui" is a stranger's library, and the
// finding would be about their project attributed to this one.
func directOf(nodes []scanner.PackageNode) []scanner.PackageNode {
	var out []scanner.PackageNode
	for _, n := range nodes {
		if n.Direct && !n.Root && n.Name != "" {
			out = append(out, n)
		}
	}
	return out
}

func checkScore(card *depsdev.Scorecard, name string) (int, bool) {
	for _, c := range card.Checks {
		if strings.EqualFold(c.Name, name) {
			return c.Score, true
		}
	}
	return 0, false
}

// weakest names the checks dragging a score down, so the finding says what is
// actually wrong rather than only that a number is low.
func weakest(card *depsdev.Scorecard) string {
	var names []string
	for _, c := range card.Checks {
		if c.Score >= 0 && c.Score <= 2 {
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "no single check dominates the score"
	}
	if len(names) > 4 {
		names = names[:4]
	}
	return strings.Join(names, ", ")
}

func scorecardRefs(card *depsdev.Scorecard) []string {
	if card.Repo.Name == "" {
		return nil
	}
	return []string{"https://scorecard.dev/viewer/?uri=" + card.Repo.Name}
}
