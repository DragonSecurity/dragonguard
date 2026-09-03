// Package pipeline wires the control plane together: evidence in, decision
// out.
//
// The stage order is load-bearing and worth stating explicitly, because
// several stages read what earlier ones wrote:
//
//	scan       engines produce raw evidence
//	normalize  evidence becomes canonical findings
//	diff       findings are compared against the recorded baseline
//	enrich     EPSS and KEV are attached
//	score      Dragon Risk runs, needing enrichment and the new/old diff
//	policy     CEL runs, needing risk scores it can reference and adjust
//	aggregate  the scorecard is built from post-policy risk
//	gate       the baseline breaks the circuit or does not
package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/enrich"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/ignore"
	"github.com/DragonSecurity/dragonguard/pkg/policy"
	"github.com/DragonSecurity/dragonguard/pkg/remediate"
	"github.com/DragonSecurity/dragonguard/pkg/report"
	"github.com/DragonSecurity/dragonguard/pkg/risk"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
	"github.com/DragonSecurity/dragonguard/pkg/scanner/dast"
	"github.com/DragonSecurity/dragonguard/pkg/scanner/gitleaks"
	"github.com/DragonSecurity/dragonguard/pkg/scanner/opengrep"
	"github.com/DragonSecurity/dragonguard/pkg/scanner/osv"
	"github.com/DragonSecurity/dragonguard/pkg/scanner/trivy"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
	"github.com/DragonSecurity/dragonguard/pkg/state"
	"github.com/DragonSecurity/dragonguard/pkg/vcs"
)

// Options control one scan.
type Options struct {
	Dir   string
	Image string

	Config   *config.Config
	Baseline *baseline.Baseline

	// Only restricts which engines run.
	Only []string
	// Categories restricts which evidence kinds are collected.
	Categories []finding.Category

	// Offline disables all network access.
	Offline bool
	// Record saves this scan as the new baseline snapshot.
	Record bool
	// Timeout bounds a single engine.
	EngineTimeout time.Duration

	// Progress, when set, receives human-readable stage updates.
	Progress func(string)

	// Registry overrides the engine set. Injectable so the control plane can
	// be tested against known evidence rather than against whatever the
	// machine happens to have installed.
	Registry *scanner.Registry
}

// DefaultRegistry returns the built-in engine adapters.
func DefaultRegistry() *scanner.Registry {
	r := scanner.NewRegistry()
	r.Register(trivy.New())
	r.Register(opengrep.New())
	r.Register(gitleaks.New())
	r.Register(osv.New())
	// DAST engines refuse to run without an explicitly configured target, so
	// registering them is safe: an unconfigured project simply reports the
	// API dimension as unassessed rather than scanning something by accident.
	r.Register(dast.NewZAP())
	r.Register(dast.NewSchemathesis())
	return r
}

// Run executes the full pipeline.
func Run(ctx context.Context, opts Options) (*report.Result, error) {
	cfg := opts.Config
	if cfg == nil {
		return nil, fmt.Errorf("no configuration supplied")
	}
	if opts.Offline {
		cfg.Offline = true
	}

	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}

	// --- scan ---
	reg := opts.Registry
	if reg == nil {
		reg = DefaultRegistry()
	}
	only := opts.Only
	if len(only) == 0 {
		// A disabled engine is a deliberate choice, not an outage; honour it.
		for _, s := range reg.All() {
			if ec, ok := cfg.Engines[s.Name()]; ok && !ec.IsEnabled() {
				continue
			}
			only = append(only, s.Name())
		}
	}

	target := scanner.Target{Dir: opts.Dir, Image: opts.Image, Config: cfg}
	engineResults := reg.Run(ctx, target, scanner.RunOptions{
		Only:       only,
		Categories: opts.Categories,
		Timeout:    opts.EngineTimeout,
		OnStart:    func(n string) { progress("scanning: " + n) },
		OnDone: func(r scanner.Result) {
			switch {
			case r.Skipped:
				progress(fmt.Sprintf("skipped %s: %s", r.Scanner, r.Reason))
			case r.Error != "":
				progress(fmt.Sprintf("%s failed: %s", r.Scanner, r.Error))
			default:
				progress(fmt.Sprintf("%s: %d findings", r.Scanner, r.Count))
			}
		},
	})

	// --- normalize ---
	now := time.Now().UTC()
	findings := scanner.Collect(engineResults, now)

	graph := scanner.NewPackageGraph()
	for _, r := range engineResults {
		graph.Merge(r.Graph)
	}

	// Apply the configured ignore list to every engine's output, not just the
	// engines that happen to have an exclude flag. Trivy, OpenGrep and OSV are
	// each handed the list; Gitleaks has no flag to hand it to, so a path in
	// `ignore:` was scanned and reported regardless of the configuration
	// saying otherwise. Enforcing it here is what makes the list mean the same
	// thing for all of them, and for the next engine added.
	cfgIgnore := ignore.New(cfg.Ignore)
	findings, excludedReport := ignore.Filter(cfgIgnore, opts.Dir, findings)
	if note := excludedReport.Note(); note != "" {
		progress(note)
	}

	// Drop findings in files git deliberately excludes, before anything
	// downstream counts them. Engines scan the working tree, which includes a
	// developer's local .env and any gitignored key material -- files that
	// were never committed and so were never disclosed. Reporting those as
	// critical secrets is a false positive that pushes genuine findings off
	// the page, and it can trip a gate on its own.
	tree := vcs.Open(ctx, opts.Dir)
	var ignoreReport vcs.FilterReport
	if !cfg.ScanIgnoredFiles {
		findings, ignoreReport = vcs.FilterIgnored(tree, findings)
		if note := ignoreReport.Note(); note != "" {
			progress(note)
		}
	}

	// --- diff against the recorded baseline ---
	branch, commit := gitInfo(opts.Dir)
	// The gate compares against the default branch, not the branch in hand.
	// "Does merging this make main worse" is the question; a branch measured
	// against its own last scan answers "is this worse than it was an hour
	// ago", which a branch that is already below main passes trivially.
	base := defaultBranch(opts.Dir, cfg.DefaultBranch)
	store := state.New(cfg.StatePath())
	prev, err := store.Load(base)
	if err != nil {
		// A corrupt snapshot must not silently become "no baseline", which
		// would make every finding look new and every regression invisible.
		return nil, fmt.Errorf("load baseline snapshot: %w", err)
	}
	_, fixed := state.MarkNew(findings, prev)

	// --- enrich ---
	progress("enriching with EPSS and KEV")
	enricher := enrich.New(enrich.Options{
		CacheDir: cfg.StatePath(),
		Offline:  cfg.Offline,
	})
	enrichReport := enricher.Enrich(ctx, findings)

	// Supply-chain posture must land before scoring: it is the evidence that
	// makes Dragon Risk's supply-chain component scoreable at all, and a
	// component scored after the fact would not be in the weighting.
	progress("resolving upstream supply-chain posture")
	enrichReport.SupplyChain = enricher.SupplyChain(ctx, findings)

	// --- remediate ---
	// Before scoring, because remediation decides whether a fix is available,
	// which is itself a scored component.
	progress("resolving remediation paths")
	resolver := remediate.New()
	resolver.Offline = cfg.Offline
	resolver.Graph = graph
	resolver.Apply(ctx, findings, remediate.NewInventory(findings, graph))

	// --- score ---
	riskEngine := risk.New(cfg.Asset)
	riskEngine.ScoreAll(findings)

	// --- policy ---
	policyEngine, err := policy.NewEngine()
	if err != nil {
		return nil, err
	}
	policyPaths := resolvePolicyPaths(cfg)
	if len(policyPaths) > 0 {
		if err := policyEngine.LoadPaths(policyPaths); err != nil {
			return nil, err
		}
	}
	// After the packs, so a hand-written rule can still be the last word on a
	// licence the project has an opinion about.
	if err := policyEngine.LoadLicensePolicy(cfg.Licenses); err != nil {
		return nil, err
	}
	if n := len(policyEngine.Rules()); n > 0 {
		progress(fmt.Sprintf("loaded %d policy rules", n))
	}
	scanCtx := map[string]any{
		"project":        cfg.Project,
		"branch":         branch,
		"commit":         commit,
		"total_findings": int64(len(findings)),
	}
	evaluations := policyEngine.EvaluateAll(findings, cfg.Asset, scanCtx)

	// A policy risk_boost changes the score, so the rating it implies has to
	// be recomputed. Leaving a stale rating would let a boosted finding be
	// counted in the wrong bucket by every gate downstream.
	for i := range findings {
		findings[i].RiskRating = risk.Rate(findings[i].RiskScore)
	}
	finding.SortByRisk(findings)

	// --- aggregate ---
	assessed := assessedDimensions(engineResults, reg)
	supported := supportedDimensions(reg, engineResults)
	var enginesRun, enginesUnavailable, enginesFailed []string
	for _, r := range engineResults {
		switch {
		case !r.Available:
			enginesUnavailable = append(enginesUnavailable, r.Scanner)
		case r.Error != "":
			enginesFailed = append(enginesFailed, r.Scanner)
		default:
			enginesRun = append(enginesRun, r.Scanner)
		}
	}

	sc := scorecard.Build(scorecard.Input{
		Project:             cfg.Project,
		Asset:               cfg.Asset.Name,
		Commit:              commit,
		Branch:              branch,
		Findings:            findings,
		Evaluations:         evaluations,
		EnginesRun:          enginesRun,
		EnginesUnavailable:  enginesUnavailable,
		EnginesFailed:       enginesFailed,
		AssessedDimensions:  assessed,
		SupportedDimensions: supported,
		Notes:               enrichReport.Notes,
	})

	// --- gate ---
	bl := opts.Baseline
	if bl == nil {
		bl = baseline.Default()
	}
	// Said out loud, the way the policy packs are. Every threshold in the
	// output comes from this file, but a reader cannot tell a loaded baseline
	// from the built-in defaults by looking at the numbers -- and when the
	// regression row says nothing was recorded, the natural conclusion is that
	// the file was not read at all. Naming it settles that before it is asked.
	if bl.Path != "" {
		progress("baseline: " + bl.Path)
	} else {
		progress("baseline: built-in defaults (none configured)")
	}
	var prevCard *scorecard.Scorecard
	if prev != nil {
		prevCard = prev.Scorecard
	}
	decision := bl.Evaluate(sc, prevCard, findings)

	// --- record ---
	if opts.Record {
		if err := store.Save(branch, sc, findings); err != nil {
			return nil, fmt.Errorf("record baseline: %w", err)
		}
		if base != "" && branch != base {
			// Said out loud because it is the obvious mistake: recording on a
			// feature branch looks like it has set the bar, and the gate will
			// go on comparing against the default branch regardless.
			progress(fmt.Sprintf("recorded snapshot for %s; the gate compares against %s, so this does not change it", branch, base))
		} else {
			progress("recorded baseline snapshot")
		}
	}

	return &report.Result{
		Ignored:     ignoreReport,
		Excluded:    excludedReport,
		Components:  graph.Sorted(),
		Scorecard:   sc,
		Decision:    decision,
		Findings:    findings,
		Evaluations: evaluations,
		Engines:     engineResults,
		Enrichment:  enrichReport,
		Fixed:       fixed,
	}, nil
}

// assessedDimensions reports which scorecard dimensions had an engine that
// actually ran successfully.
//
// This is computed from engines, not from findings. Deriving it from findings
// would make "no findings" and "nobody looked" identical, which is precisely
// the confusion the whole Assessed flag exists to prevent.
func assessedDimensions(results []scanner.Result, reg *scanner.Registry) map[string]bool {
	ran := make(map[string]bool)
	for _, r := range results {
		if r.Skipped || r.Error != "" {
			continue
		}
		ran[r.Scanner] = true
	}
	out := make(map[string]bool)
	for name := range ran {
		s, ok := reg.Get(name)
		if !ok {
			continue
		}
		for _, c := range s.Categories() {
			out[c.Dimension()] = true
		}
	}
	return out
}

// supportedDimensions reports which dimensions an engine could actually have
// covered on this run.
//
// Availability is the test, not registration. An engine whose binary is
// missing, or which has no target configured, covers nothing -- so its
// dimension is a standing coverage gap rather than a failure of this scan.
// Subtracting assessed from supported therefore leaves exactly the engines
// that could have run and did not, which is the set worth warning about.
func supportedDimensions(reg *scanner.Registry, results []scanner.Result) map[string]bool {
	out := map[string]bool{}
	for _, r := range results {
		if !r.Available {
			continue
		}
		s, ok := reg.Get(r.Scanner)
		if !ok {
			continue
		}
		for _, c := range s.Categories() {
			out[c.Dimension()] = true
		}
	}
	return out
}

func resolvePolicyPaths(cfg *config.Config) []string {
	var out []string
	for _, p := range cfg.Policies {
		out = append(out, cfg.Resolve(p))
	}
	if len(out) > 0 {
		return out
	}
	// Fall back to a conventional location so a project that drops policies
	// into policies/ gets them without also editing config.
	for _, candidate := range []string{"policies", ".dragon/policies"} {
		p := cfg.Resolve(candidate)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return []string{p}
		}
	}
	return nil
}

// gitInfo reads the branch and commit, tolerating a non-repository.
// defaultBranch resolves the branch the gate measures against.
//
// Configuration wins, then the remote's own idea of its trunk, then a local
// main or master. Empty when none of those exist -- a directory that is not a
// repository has no default branch, and inventing one would silently compare a
// scan against a snapshot belonging to something else.
func defaultBranch(dir, configured string) string {
	if configured != "" {
		return configured
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return ""
	}
	if ref := run("symbolic-ref", "--short", "refs/remotes/origin/HEAD"); ref != "" {
		return strings.TrimPrefix(ref, "origin/")
	}
	for _, candidate := range []string{"main", "master"} {
		if run("rev-parse", "--verify", "--quiet", "refs/heads/"+candidate) != "" {
			return candidate
		}
	}
	return ""
}

func gitInfo(dir string) (branch, commit string) {
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return "", ""
	}
	return run("rev-parse", "--abbrev-ref", "HEAD"), run("rev-parse", "HEAD")
}
