// Package baseline implements Dragon Baseline: the circuit breaker that turns
// a posture report into a ship / do-not-ship decision.
//
// The design follows OpenSSF Scorecard's own advice about aggregate scores:
// do not gate on the number alone. A single threshold is both too blunt to
// catch what matters and too easy to satisfy by fixing whatever is cheapest.
// So a baseline states three kinds of constraint, and any one of them can
// break the circuit:
//
//	hard gates       conditions that are never acceptable, at any score
//	score gates      absolute posture floors, overall and per dimension
//	regression gates you may not arrive worse than you left
//
// The regression gate is what makes this adoptable. A legacy codebase cannot
// pass an absolute floor on day one, but it can pass "no worse than
// yesterday" immediately, and that ratchet is what actually moves posture.
package baseline

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

// Verdict is the circuit breaker's output.
type Verdict string

const (
	VerdictPass  Verdict = "PASS"
	VerdictWarn  Verdict = "WARN"
	VerdictBlock Verdict = "BLOCK"
)

func (v Verdict) Rank() int {
	switch v {
	case VerdictBlock:
		return 3
	case VerdictWarn:
		return 2
	default:
		return 1
	}
}

// ExitCode is the process exit status for a verdict, so CI can gate on it.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictBlock:
		return 1
	default:
		return 0
	}
}

// Limit is an optional integer threshold. A pointer so that "0" (meaning none
// permitted) is distinguishable from "unset" (meaning no opinion).
type Limit struct {
	Maximum    *int `yaml:"maximum,omitempty" json:"maximum,omitempty"`
	MaximumNew *int `yaml:"maximum_new,omitempty" json:"maximum_new,omitempty"`
}

// DimensionRule constrains one dimension.
type DimensionRule struct {
	Minimum           *float64 `yaml:"minimum,omitempty" json:"minimum,omitempty"`
	MaximumRegression *float64 `yaml:"maximum_regression,omitempty" json:"maximum_regression,omitempty"`
	// Required demands the dimension actually be assessed. Without this, a
	// missing engine looks identical to a clean result.
	Required bool `yaml:"required,omitempty" json:"required,omitempty"`
}

// Baseline is the acceptable-posture definition.
type Baseline struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`
	Metadata   struct {
		Name        string `yaml:"name" json:"name"`
		Description string `yaml:"description,omitempty" json:"description,omitempty"`
	} `yaml:"metadata" json:"metadata"`

	MinimumScore           *float64 `yaml:"minimum_score,omitempty" json:"minimum_score,omitempty"`
	MaximumScoreRegression *float64 `yaml:"maximum_score_regression,omitempty" json:"maximum_score_regression,omitempty"`

	Critical Limit `yaml:"critical,omitempty" json:"critical,omitempty"`
	High     Limit `yaml:"high,omitempty" json:"high,omitempty"`
	Medium   Limit `yaml:"medium,omitempty" json:"medium,omitempty"`

	Dimensions map[string]DimensionRule `yaml:"dimensions,omitempty" json:"dimensions,omitempty"`

	// Mandatory names built-in conditions that must hold.
	Mandatory []string `yaml:"mandatory,omitempty" json:"mandatory,omitempty"`

	// BlockOnPolicyDeny fails the gate when any policy rule denied.
	BlockOnPolicyDeny *bool `yaml:"block_on_policy_deny,omitempty" json:"block_on_policy_deny,omitempty"`

	// AllowDegraded permits a pass when engines were skipped or intelligence
	// was unavailable. Defaults to false: a gate that passes because it could
	// not look is not a gate, it is a rubber stamp.
	AllowDegraded bool `yaml:"allow_degraded,omitempty" json:"allow_degraded,omitempty"`

	// WarnOnly downgrades every BLOCK to WARN. Useful when introducing the
	// gate to a team before enforcing it.
	WarnOnly bool `yaml:"warn_only,omitempty" json:"warn_only,omitempty"`

	Path string `yaml:"-" json:"-"`
}

// Check is one evaluated constraint.
type Check struct {
	Gate     string  `json:"gate"` // hard | score | regression | policy | evidence
	Name     string  `json:"name"`
	Passed   bool    `json:"passed"`
	Required string  `json:"required"`
	Actual   string  `json:"actual"`
	Verdict  Verdict `json:"verdict"`
	Detail   string  `json:"detail,omitempty"`
	// NotEvaluated marks a constraint that could not be assessed rather than
	// one that was assessed and held. It does not block -- there is nothing to
	// block on -- but it must not read as a green tick either: a gate that
	// silently cannot run looks exactly like a gate that is passing, and the
	// difference is the whole value of the gate.
	NotEvaluated bool `json:"not_evaluated,omitempty"`
}

// Decision is the circuit breaker's full result.
type Decision struct {
	Verdict Verdict  `json:"verdict"`
	Checks  []Check  `json:"checks"`
	Reasons []string `json:"reasons"`
	Score   float64  `json:"score"`
	// PreviousScore is negative when there is no baseline to compare to.
	PreviousScore float64 `json:"previous_score"`
	HasPrevious   bool    `json:"has_previous"`
	Baseline      string  `json:"baseline,omitempty"`
}

// Failures returns the checks that did not pass.
func (d *Decision) Failures() []Check {
	var out []Check
	for _, c := range d.Checks {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

// Default returns the baseline used when a project defines none.
//
// It enforces only what is indefensible anywhere -- a live credential, an
// actively exploited vulnerability, a critical risk -- plus a no-regression
// ratchet. It sets no absolute score floor, because an arbitrary floor on an
// unfamiliar codebase is the fastest way to get a security gate disabled.
func Default() *Baseline {
	zero := 0
	two := 2
	five := 5.0
	block := true
	return &Baseline{
		APIVersion: "dragonguard/v1",
		Kind:       "Baseline",
		Metadata: struct {
			Name        string `yaml:"name" json:"name"`
			Description string `yaml:"description,omitempty" json:"description,omitempty"`
		}{
			Name:        "dragon-default",
			Description: "Blocks what is indefensible anywhere, and ratchets everything else.",
		},
		MaximumScoreRegression: &five,
		Critical:               Limit{MaximumNew: &zero},
		High:                   Limit{MaximumNew: &two},
		Mandatory: []string{
			"no_active_secrets",
			"no_kev_in_production",
			"no_reachable_critical_vulnerability",
		},
		BlockOnPolicyDeny: &block,
	}
}

// Load reads a baseline from disk.
func Load(path string) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	// Accept both a bare document and one nested under a `baseline:` key,
	// since the concept documentation shows the nested form.
	var wrapper struct {
		Baseline *Baseline `yaml:"baseline"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err == nil && wrapper.Baseline != nil {
		wrapper.Baseline.Path = path
		return wrapper.Baseline, nil
	}
	var b Baseline
	if err := yaml.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Kind != "" && b.Kind != "Baseline" {
		return nil, fmt.Errorf("%s: kind %q is not Baseline", path, b.Kind)
	}
	b.Path = path
	return &b, nil
}

// Evaluate runs the circuit breaker.
//
// prev is the scorecard this scan is measured against, or nil on a first run.
// It is passed directly rather than through a storage type on purpose: the CLI
// reads it from a file and the platform reads it from Postgres, and the gate
// should not know or care which.
func (b *Baseline) Evaluate(sc *scorecard.Scorecard, prev *scorecard.Scorecard, findings []finding.Finding) *Decision {
	d := &Decision{
		Verdict:       VerdictPass,
		Score:         sc.Score,
		PreviousScore: -1,
		Baseline:      b.Metadata.Name,
	}
	if prev != nil {
		d.PreviousScore = prev.Score
		d.HasPrevious = true
	}

	b.evidenceGates(d, sc)
	b.hardGates(d, sc)
	b.scoreGates(d, sc)
	b.regressionGates(d, sc, prev)
	b.policyGates(d, sc)

	for _, c := range d.Checks {
		if !c.Passed && c.Verdict.Rank() > d.Verdict.Rank() {
			d.Verdict = c.Verdict
		}
	}
	if b.WarnOnly && d.Verdict == VerdictBlock {
		d.Verdict = VerdictWarn
		d.Reasons = append(d.Reasons, "baseline is warn_only: blocking conditions reported but not enforced")
	}

	for _, c := range d.Failures() {
		d.Reasons = append(d.Reasons, c.Detail)
	}
	return d
}

// evidenceGates check that the scan is trustworthy enough to gate on.
func (b *Baseline) evidenceGates(d *Decision, sc *scorecard.Scorecard) {
	if sc.Degraded && !b.AllowDegraded {
		detail := "scan was degraded: "
		var parts []string
		if len(sc.EnginesFailed) > 0 {
			parts = append(parts, "engines failed ("+strings.Join(sc.EnginesFailed, ", ")+")")
		}
		var missing []string
		for _, name := range scorecard.Dimensions {
			// Only dimensions an engine was meant to cover. A dimension with
			// no engine configured is reported in the scorecard as a
			// coverage gap, not as a failure of this scan.
			if dim, ok := sc.Dimensions[name]; ok && dim.Supported && !dim.Assessed {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			parts = append(parts, "dimensions not assessed ("+strings.Join(missing, ", ")+")")
		}
		parts = append(parts, sc.Notes...)
		detail += strings.Join(parts, "; ")

		d.Checks = append(d.Checks, Check{
			Gate: "evidence", Name: "complete evidence", Passed: false,
			Required: "all engines available", Actual: "degraded",
			// A degraded scan warns rather than blocks: the evidence is
			// incomplete, not damning. Set allow_degraded: false with a
			// required dimension to make a specific gap blocking.
			Verdict: VerdictWarn,
			Detail:  detail,
		})
	}

	for name, rule := range b.Dimensions {
		if !rule.Required {
			continue
		}
		dim, ok := sc.Dimensions[name]
		if !ok || !dim.Assessed {
			d.Checks = append(d.Checks, Check{
				Gate: "evidence", Name: "dimension " + name + " assessed", Passed: false,
				Required: "assessed", Actual: "not assessed", Verdict: VerdictBlock,
				Detail: fmt.Sprintf("dimension %q is required by the baseline but no engine assessed it", name),
			})
		}
	}
}

// hardGates are conditions unacceptable at any score.
func (b *Baseline) hardGates(d *Decision, sc *scorecard.Scorecard) {
	names := append([]string(nil), b.Mandatory...)
	sort.Strings(names)
	for _, name := range names {
		got, known := sc.Mandatory[name]
		if !known {
			d.Checks = append(d.Checks, Check{
				Gate: "hard", Name: name, Passed: false,
				Required: "satisfied", Actual: "unknown condition", Verdict: VerdictBlock,
				Detail: fmt.Sprintf("baseline requires unknown condition %q", name),
			})
			continue
		}
		d.Checks = append(d.Checks, Check{
			Gate: "hard", Name: name, Passed: got,
			Required: "true", Actual: fmt.Sprintf("%t", got), Verdict: VerdictBlock,
			Detail: fmt.Sprintf("mandatory condition %q is not satisfied", name),
		})
	}

	check := func(label string, lim Limit, total, isNew int) {
		if lim.Maximum != nil {
			d.Checks = append(d.Checks, Check{
				Gate: "hard", Name: label + " findings", Passed: total <= *lim.Maximum,
				Required: fmt.Sprintf("<= %d", *lim.Maximum), Actual: fmt.Sprintf("%d", total),
				Verdict: VerdictBlock,
				Detail:  fmt.Sprintf("%d %s-risk findings exceed the baseline maximum of %d", total, label, *lim.Maximum),
			})
		}
		if lim.MaximumNew != nil {
			d.Checks = append(d.Checks, Check{
				Gate: "hard", Name: "new " + label + " findings", Passed: isNew <= *lim.MaximumNew,
				Required: fmt.Sprintf("<= %d", *lim.MaximumNew), Actual: fmt.Sprintf("%d", isNew),
				Verdict: VerdictBlock,
				Detail:  fmt.Sprintf("%d new %s-risk findings exceed the baseline allowance of %d", isNew, label, *lim.MaximumNew),
			})
		}
	}
	check("critical", b.Critical, sc.Counts.Critical, sc.New.Critical)
	check("high", b.High, sc.Counts.High, sc.New.High)
	check("medium", b.Medium, sc.Counts.Medium, sc.New.Medium)
}

// scoreGates are absolute posture floors.
func (b *Baseline) scoreGates(d *Decision, sc *scorecard.Scorecard) {
	if b.MinimumScore != nil {
		d.Checks = append(d.Checks, Check{
			Gate: "score", Name: "overall score", Passed: sc.Score >= *b.MinimumScore,
			Required: fmt.Sprintf(">= %.0f", *b.MinimumScore), Actual: fmt.Sprintf("%.0f", sc.Score),
			Verdict: VerdictBlock,
			Detail:  fmt.Sprintf("overall posture %.0f is below the required baseline of %.0f", sc.Score, *b.MinimumScore),
		})
	}

	for _, name := range b.dimensionNames() {
		rule := b.Dimensions[name]
		if rule.Minimum == nil {
			continue
		}
		dim, ok := sc.Dimensions[name]
		if !ok || !dim.Assessed {
			// Handled by the evidence gate when Required is set; scoring an
			// unassessed dimension against a floor would be meaningless.
			continue
		}
		d.Checks = append(d.Checks, Check{
			Gate: "score", Name: name + " score", Passed: dim.Score >= *rule.Minimum,
			Required: fmt.Sprintf(">= %.0f", *rule.Minimum), Actual: fmt.Sprintf("%.0f", dim.Score),
			Verdict: VerdictBlock,
			Detail:  fmt.Sprintf("%s posture %.0f is below the required %.0f", name, dim.Score, *rule.Minimum),
		})
	}
}

// regressionGates enforce that posture has not decayed.
func (b *Baseline) regressionGates(d *Decision, sc *scorecard.Scorecard, prev *scorecard.Scorecard) {
	if prev == nil {
		// Every configured regression rule is reported, not just the overall
		// one. A dimension rule that vanishes when there is no baseline is a
		// constraint the author believes is enforced and which produces no
		// output at all -- indistinguishable from one that is passing.
		if b.MaximumScoreRegression != nil {
			d.Checks = append(d.Checks, Check{
				Gate: "regression", Name: "overall regression", Passed: true,
				Required:     fmt.Sprintf("<= %.0f point drop", *b.MaximumScoreRegression),
				Actual:       "not evaluated: nothing recorded",
				Verdict:      VerdictWarn,
				Detail:       "no snapshot recorded for the default branch to compare against; run `dragon scan --record` there",
				NotEvaluated: true,
			})
		}
		for _, name := range b.dimensionNames() {
			if b.Dimensions[name].MaximumRegression == nil {
				continue
			}
			d.Checks = append(d.Checks, Check{
				Gate: "regression", Name: name + " regression", Passed: true,
				Required:     fmt.Sprintf("<= %.0f point drop", *b.Dimensions[name].MaximumRegression),
				Actual:       "not evaluated: nothing recorded",
				Verdict:      VerdictWarn,
				Detail:       "no snapshot recorded for the default branch to compare against; run `dragon scan --record` there",
				NotEvaluated: true,
			})
		}
		return
	}

	if b.MaximumScoreRegression != nil {
		drop := prev.Score - sc.Score
		if drop < 0 {
			drop = 0
		}
		d.Checks = append(d.Checks, Check{
			Gate: "regression", Name: "overall regression",
			Passed:   drop <= *b.MaximumScoreRegression,
			Required: fmt.Sprintf("<= %.0f point drop", *b.MaximumScoreRegression),
			Actual:   fmt.Sprintf("%.0f point drop (%.0f -> %.0f)", drop, prev.Score, sc.Score),
			Verdict:  VerdictBlock,
			Detail: fmt.Sprintf("overall posture dropped %.0f points (%.0f -> %.0f), exceeding the allowed %.0f",
				drop, prev.Score, sc.Score, *b.MaximumScoreRegression),
		})
	}

	names := make([]string, 0, len(b.Dimensions))
	for n := range b.Dimensions {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		rule := b.Dimensions[name]
		if rule.MaximumRegression == nil {
			continue
		}
		cur, ok := sc.Dimensions[name]
		if !ok || !cur.Assessed {
			continue
		}
		before, ok := prev.Dimensions[name]
		if !ok || !before.Assessed {
			continue
		}
		drop := math.Max(0, before.Score-cur.Score)
		d.Checks = append(d.Checks, Check{
			Gate: "regression", Name: name + " regression",
			Passed:   drop <= *rule.MaximumRegression,
			Required: fmt.Sprintf("<= %.0f point drop", *rule.MaximumRegression),
			Actual:   fmt.Sprintf("%.0f -> %.0f", before.Score, cur.Score),
			Verdict:  VerdictBlock,
			Detail: fmt.Sprintf("%s posture regression %.0f -> %.0f exceeds the allowed %.0f point drop",
				name, before.Score, cur.Score, *rule.MaximumRegression),
		})
	}
}

// dimensionNames returns the configured dimensions in a stable order.
func (b *Baseline) dimensionNames() []string {
	names := make([]string, 0, len(b.Dimensions))
	for n := range b.Dimensions {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (b *Baseline) policyGates(d *Decision, sc *scorecard.Scorecard) {
	if b.BlockOnPolicyDeny == nil || !*b.BlockOnPolicyDeny {
		return
	}
	d.Checks = append(d.Checks, Check{
		Gate: "policy", Name: "policy denials", Passed: sc.Policy.Blocking == 0,
		Required: "0", Actual: fmt.Sprintf("%d", sc.Policy.Blocking), Verdict: VerdictBlock,
		Detail: fmt.Sprintf("%d finding(s) denied by policy", sc.Policy.Blocking),
	})

	// A policy that failed to evaluate has stopped enforcing. That is a
	// blocking condition in itself: the alternative is a gate that silently
	// stops checking the thing it was written to check.
	if sc.Policy.Errors > 0 {
		d.Checks = append(d.Checks, Check{
			Gate: "policy", Name: "policy evaluation", Passed: false,
			Required: "0 errors", Actual: fmt.Sprintf("%d", sc.Policy.Errors), Verdict: VerdictBlock,
			Detail: fmt.Sprintf("%d policy rule(s) failed to evaluate; enforcement is incomplete", sc.Policy.Errors),
		})
	}
}
