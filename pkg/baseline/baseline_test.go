package baseline

import (
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

func card(score float64, mutate ...func(*scorecard.Scorecard)) *scorecard.Scorecard {
	sc := &scorecard.Scorecard{
		Score:      score,
		Dimensions: map[string]scorecard.Dimension{},
		Mandatory: map[string]bool{
			"no_active_secrets":                   true,
			"no_kev_in_production":                true,
			"no_reachable_critical_vulnerability": true,
			"no_critical_risk":                    true,
			"no_policy_errors":                    true,
		},
	}
	for _, name := range scorecard.Dimensions {
		sc.Dimensions[name] = scorecard.Dimension{Name: name, Score: score, Assessed: true, Supported: true}
	}
	for _, m := range mutate {
		m(sc)
	}
	return sc
}

// prevCard is the scorecard a run is measured against.
func snapshot(score float64) *scorecard.Scorecard { return card(score) }

func ptrI(i int) *int         { return &i }
func ptrF(f float64) *float64 { return &f }

func TestHardGateBlocksRegardlessOfScore(t *testing.T) {
	bl := &Baseline{Mandatory: []string{"no_active_secrets"}}
	sc := card(99, func(s *scorecard.Scorecard) { s.Mandatory["no_active_secrets"] = false })

	d := bl.Evaluate(sc, snapshot(99), nil)
	if d.Verdict != VerdictBlock {
		t.Errorf("verdict = %s; a live credential must block even at posture 99", d.Verdict)
	}
}

// The ratchet: the gate a legacy codebase can actually pass on day one.
func TestRegressionGateBlocksADropAndAllowsASteadyState(t *testing.T) {
	bl := &Baseline{MaximumScoreRegression: ptrF(5)}

	if d := bl.Evaluate(card(75), snapshot(90), nil); d.Verdict != VerdictBlock {
		t.Errorf("a 15-point drop should block, got %s", d.Verdict)
	}
	if d := bl.Evaluate(card(88), snapshot(90), nil); d.Verdict != VerdictPass {
		t.Errorf("a 2-point drop is within tolerance, got %s: %v", d.Verdict, d.Reasons)
	}
	// A poor but stable codebase passes. That is the point: it can adopt the
	// gate today and improve from there.
	if d := bl.Evaluate(card(40), snapshot(40), nil); d.Verdict != VerdictPass {
		t.Errorf("stable low posture should pass the ratchet, got %s: %v", d.Verdict, d.Reasons)
	}
	// Improving must never be penalized.
	if d := bl.Evaluate(card(95), snapshot(60), nil); d.Verdict != VerdictPass {
		t.Errorf("an improvement should pass, got %s", d.Verdict)
	}
}

func TestNoBaselineWarnsRatherThanBlocks(t *testing.T) {
	bl := &Baseline{MaximumScoreRegression: ptrF(5)}
	d := bl.Evaluate(card(50), nil, nil)
	if d.Verdict == VerdictBlock {
		t.Error("a first scan with no recorded baseline must not block on regression")
	}
	if d.HasPrevious {
		t.Error("HasPrevious should be false with no snapshot")
	}
}

func TestNewFindingAllowanceIsEnforced(t *testing.T) {
	bl := &Baseline{High: Limit{MaximumNew: ptrI(2)}}

	sc := card(90, func(s *scorecard.Scorecard) { s.New.High = 3 })
	d := bl.Evaluate(sc, snapshot(90), nil)
	if d.Verdict != VerdictBlock {
		t.Errorf("3 new high findings should exceed an allowance of 2, got %s", d.Verdict)
	}

	sc2 := card(90, func(s *scorecard.Scorecard) { s.New.High = 2 })
	if d := bl.Evaluate(sc2, snapshot(90), nil); d.Verdict != VerdictPass {
		t.Errorf("2 new high findings is within the allowance, got %s: %v", d.Verdict, d.Reasons)
	}
}

// A gate that passes because it could not look is not a gate.
func TestDegradedScanDoesNotSilentlyPass(t *testing.T) {
	bl := &Baseline{}
	sc := card(100, func(s *scorecard.Scorecard) {
		s.Degraded = true
		s.EnginesSkipped = []string{"opengrep"}
	})

	d := bl.Evaluate(sc, snapshot(100), nil)
	if d.Verdict == VerdictPass {
		t.Error("a degraded scan must not report a clean pass")
	}

	bl.AllowDegraded = true
	if d := bl.Evaluate(sc, snapshot(100), nil); d.Verdict != VerdictPass {
		t.Errorf("allow_degraded should permit a pass, got %s", d.Verdict)
	}
}

// A dimension the baseline requires but nobody assessed is a blocking gap,
// not a clean result.
func TestRequiredDimensionMustBeAssessed(t *testing.T) {
	bl := &Baseline{Dimensions: map[string]DimensionRule{"secrets": {Required: true}}}
	sc := card(100, func(s *scorecard.Scorecard) {
		s.Dimensions["secrets"] = scorecard.Dimension{Name: "secrets", Assessed: false, Supported: true}
	})
	sc.Degraded = false

	if d := bl.Evaluate(sc, snapshot(100), nil); d.Verdict != VerdictBlock {
		t.Errorf("a required but unassessed dimension must block, got %s", d.Verdict)
	}
}

// A policy that failed to evaluate has stopped enforcing.
func TestPolicyErrorsBlock(t *testing.T) {
	block := true
	bl := &Baseline{BlockOnPolicyDeny: &block}
	sc := card(100, func(s *scorecard.Scorecard) { s.Policy.Errors = 1 })

	if d := bl.Evaluate(sc, snapshot(100), nil); d.Verdict != VerdictBlock {
		t.Errorf("policy evaluation errors must block, got %s", d.Verdict)
	}
}

func TestWarnOnlyDowngradesBlocks(t *testing.T) {
	bl := &Baseline{Mandatory: []string{"no_active_secrets"}, WarnOnly: true}
	sc := card(99, func(s *scorecard.Scorecard) { s.Mandatory["no_active_secrets"] = false })

	d := bl.Evaluate(sc, snapshot(99), nil)
	if d.Verdict != VerdictWarn {
		t.Errorf("warn_only should downgrade a block to warn, got %s", d.Verdict)
	}
	if len(d.Failures()) == 0 {
		t.Error("warn_only must still report what would have blocked")
	}
}

// An unknown mandatory condition is a typo in the baseline, and a typo that
// silently enforces nothing is the worst possible outcome.
func TestUnknownMandatoryConditionBlocks(t *testing.T) {
	bl := &Baseline{Mandatory: []string{"no_activ_secrets"}}
	if d := bl.Evaluate(card(100), snapshot(100), nil); d.Verdict != VerdictBlock {
		t.Error("a misspelled mandatory condition must block rather than silently pass")
	}
}

func TestDefaultBaselineBlocksTheIndefensible(t *testing.T) {
	bl := Default()
	clean := card(60) // deliberately mediocre posture
	if d := bl.Evaluate(clean, snapshot(60), nil); d.Verdict != VerdictPass {
		t.Errorf("the default baseline should not block a stable mediocre codebase, got %s: %v", d.Verdict, d.Reasons)
	}

	leaked := card(60, func(s *scorecard.Scorecard) { s.Mandatory["no_active_secrets"] = false })
	if d := bl.Evaluate(leaked, snapshot(60), nil); d.Verdict != VerdictBlock {
		t.Error("the default baseline must block a committed credential")
	}
}

func TestVerdictExitCodes(t *testing.T) {
	if VerdictPass.ExitCode() != 0 || VerdictWarn.ExitCode() != 0 || VerdictBlock.ExitCode() != 1 {
		t.Error("only a block should produce a non-zero exit status")
	}
}

var _ = finding.Finding{}
