// Package scanner defines the adapter contract every security engine is
// wrapped in, and the registry that runs them.
//
// The contract is deliberately narrow: an engine takes a target and returns
// canonical Findings. Everything an engine knows that the schema cannot
// express is dropped at this boundary on purpose -- if the control plane
// could see it, swapping the engine would become a breaking change.
package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// Target describes what is being scanned.
type Target struct {
	// Dir is the root of the source tree.
	Dir string
	// Image, when set, names a container image to scan instead of a directory.
	Image string
	// Config carries project context so an adapter can honour ignore globs.
	Config *config.Config
	// Components is the resolved inventory, for engines that assess what was
	// found rather than reading the tree themselves.
	//
	// Empty during the first pass, because it is what the first pass produces.
	// An engine that needs it reports itself unavailable until it has one,
	// which is the same answer a DAST engine gives with no target configured.
	Components []PackageNode
}

// Scanner is one security engine.
type Scanner interface {
	// Name is the stable identifier used in config and in Finding.Scanner.
	Name() string
	// Categories reports which evidence kinds this engine can produce.
	Categories() []finding.Category
	// Available reports whether the engine can run against this target, and
	// why not if it cannot. The target is passed because availability is not
	// only about a binary being installed: a DAST engine with no configured
	// URL is unavailable in exactly the same sense, and reporting that as a
	// scan failure would mark every unconfigured project as degraded.
	Available(ctx context.Context, t Target) (bool, string)
	// Scan runs the engine and returns canonical findings.
	Scan(ctx context.Context, t Target) ([]finding.Finding, error)
}

// Result records what one engine did, including the reason it did nothing.
// A scan that silently omits an engine is worse than one that reports the
// gap: the gate would pass on evidence it never actually collected.
type Result struct {
	Scanner   string            `json:"scanner"`
	Available bool              `json:"available"`
	Skipped   bool              `json:"skipped"`
	Reason    string            `json:"reason,omitempty"`
	Findings  []finding.Finding `json:"-"`
	// Graph is the dependency graph this engine observed, when it reports one.
	Graph      *PackageGraph `json:"-"`
	Count      int           `json:"count"`
	Duration   time.Duration `json:"-"`
	DurationMS int64         `json:"duration_ms"`
	Err        error         `json:"-"`
	Error      string        `json:"error,omitempty"`
	// Rules names where this engine's rules came from, for engines whose
	// ruleset is configurable.
	//
	// Reported because the alternative is a silent divergence: running the
	// engine by hand with one ruleset and DragonGuard with another produces
	// different findings from what looks like the same tool, and nothing on
	// screen says why. An unconfigured project falls back to the bundled
	// pack, which is a good default and a surprising one to discover by
	// comparing outputs.
	Rules []string `json:"rules,omitempty"`
	// Suppressed counts results the engine silenced in source -- a nosemgrep
	// comment and the like -- which are honoured rather than reported.
	//
	// Counted rather than dropped in silence, for the reason every other
	// filter here reports itself: a suppression nobody can see is
	// indistinguishable from a scanner that stopped looking.
	Suppressed int `json:"suppressed,omitempty"`
}

// SuppressionCounter is implemented by engines that honour in-source
// suppressions, so a scan can say how many it respected.
//
// Read immediately after Scan, in the same goroutine, which is what makes a
// count held on the adapter safe: one Scan per engine per pass.
type SuppressionCounter interface {
	SuppressedInLastScan() int
}

// RuleReporter is implemented by engines whose ruleset is configurable, so a
// scan can say which rules produced its findings.
//
// A separate method rather than a field on the adapter: resolution depends on
// the target, engines run concurrently, and a value stashed on the scanner
// during Scan would be shared mutable state for the sake of a log line.
type RuleReporter interface {
	RulesFor(t Target) []string
}

// Registry holds the available adapters.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]Scanner)}
}

func (r *Registry) Register(s Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[s.Name()] = s
}

func (r *Registry) Get(name string) (Scanner, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.scanners[name]
	return s, ok
}

// Names returns registered scanner names in stable order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.scanners))
	for n := range r.scanners {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// All returns every registered scanner in stable order.
func (r *Registry) All() []Scanner {
	names := r.Names()
	out := make([]Scanner, 0, len(names))
	for _, n := range names {
		if s, ok := r.Get(n); ok {
			out = append(out, s)
		}
	}
	return out
}

// ForCategories returns the scanners that can produce any of the given
// categories. An empty list means every scanner.
func (r *Registry) ForCategories(cats []finding.Category) []Scanner {
	if len(cats) == 0 {
		return r.All()
	}
	want := make(map[finding.Category]bool, len(cats))
	for _, c := range cats {
		want[c] = true
	}
	var out []Scanner
	for _, s := range r.All() {
		for _, c := range s.Categories() {
			if want[c] {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// RunOptions tunes a scan pass.
type RunOptions struct {
	// Only restricts the run to these scanner names when non-empty.
	Only []string
	// Except excludes these scanner names. Used to hold back engines that
	// assess the inventory until there is one to assess.
	Except []string
	// Categories restricts the run to engines producing these categories.
	Categories []finding.Category
	// Concurrency caps engines running at once. Zero means one per engine.
	Concurrency int
	// Timeout bounds a single engine. Zero means no per-engine bound.
	Timeout time.Duration
	// OnStart, when set, is called as each engine begins.
	OnStart func(name string)
	// OnDone, when set, is called as each engine finishes.
	OnDone func(Result)
}

// Run executes the selected engines and returns their results in stable order.
//
// An engine that is unavailable or that fails does not abort the pass. The
// caller gets a partial result plus an explicit record of what was missed, and
// decides whether that is good enough to gate on.
func (r *Registry) Run(ctx context.Context, t Target, opts RunOptions) []Result {
	scanners := r.ForCategories(opts.Categories)
	if len(opts.Only) > 0 {
		want := make(map[string]bool, len(opts.Only))
		for _, n := range opts.Only {
			want[n] = true
		}
		var filtered []Scanner
		for _, s := range scanners {
			if want[s.Name()] {
				filtered = append(filtered, s)
			}
		}
		scanners = filtered
	}

	if len(opts.Except) > 0 {
		skip := make(map[string]bool, len(opts.Except))
		for _, n := range opts.Except {
			skip[n] = true
		}
		var kept []Scanner
		for _, s := range scanners {
			if !skip[s.Name()] {
				kept = append(kept, s)
			}
		}
		scanners = kept
	}

	conc := opts.Concurrency
	if conc <= 0 {
		conc = len(scanners)
	}
	if conc <= 0 {
		return nil
	}

	results := make([]Result, len(scanners))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup

	for i, s := range scanners {
		wg.Add(1)
		go func(i int, s Scanner) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := Result{Scanner: s.Name()}
			if rr, ok := s.(RuleReporter); ok {
				res.Rules = rr.RulesFor(t)
			}
			if opts.OnStart != nil {
				opts.OnStart(s.Name())
			}

			// A panic in one adapter must not take down a security scan that
			// other engines have already contributed evidence to.
			defer func() {
				if p := recover(); p != nil {
					res.Err = fmt.Errorf("scanner %s panicked: %v", s.Name(), p)
					res.Error = res.Err.Error()
					results[i] = res
				}
			}()

			start := time.Now()
			ok, reason := s.Available(ctx, t)
			res.Available = ok
			if !ok {
				res.Skipped = true
				res.Reason = reason
				res.Duration = time.Since(start)
				res.DurationMS = res.Duration.Milliseconds()
				results[i] = res
				if opts.OnDone != nil {
					opts.OnDone(res)
				}
				return
			}

			runCtx := ctx
			if opts.Timeout > 0 {
				var cancel context.CancelFunc
				runCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
				defer cancel()
			}

			var (
				fs  []finding.Finding
				err error
			)
			// Take the dependency graph from any engine that offers one, in
			// the same pass, rather than re-reading the lockfiles for it.
			if gs, ok := s.(GraphScanner); ok {
				fs, res.Graph, err = gs.ScanWithGraph(runCtx, t)
			} else {
				fs, err = s.Scan(runCtx, t)
			}
			res.Duration = time.Since(start)
			res.DurationMS = res.Duration.Milliseconds()
			if err != nil {
				res.Err = err
				res.Error = err.Error()
			}
			res.Findings = fs
			if sc, ok := s.(SuppressionCounter); ok {
				res.Suppressed = sc.SuppressedInLastScan()
			}
			res.Count = len(fs)
			results[i] = res
			if opts.OnDone != nil {
				opts.OnDone(res)
			}
		}(i, s)
	}
	wg.Wait()
	return results
}

// Collect flattens engine results into one finding set, normalizing each.
func Collect(results []Result, now time.Time) []finding.Finding {
	var out []finding.Finding
	seen := make(map[string]int)
	for _, r := range results {
		for _, f := range r.Findings {
			f.Normalize(now)
			// The same problem found by two engines is one problem for the
			// developer. Merge rather than drop: each engine usually knows
			// something the other does not.
			if idx, dup := seen[f.Fingerprint]; dup {
				out[idx].Merge(f)
				continue
			}
			seen[f.Fingerprint] = len(out)
			out = append(out, f)
		}
	}
	return out
}

// LookPath reports whether a binary is on PATH, and a usable reason if not.
func LookPath(bin string) (string, bool, string) {
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", false, fmt.Sprintf("%s not found on PATH", bin)
	}
	return p, true, ""
}
