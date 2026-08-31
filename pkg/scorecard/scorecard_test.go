package scorecard

import (
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/policy"
)

func f(dim finding.Category, risk float64, rating string) finding.Finding {
	return finding.Finding{Category: dim, RiskScore: risk, RiskRating: rating, Status: finding.StatusOpen}
}

// build treats every named dimension as both supported and assessed, which is
// the ordinary case: an engine covers it and the engine ran.
func build(fs []finding.Finding, assessed ...string) *Scorecard {
	m := map[string]bool{}
	for _, a := range assessed {
		m[a] = true
	}
	return Build(Input{
		Project: "t", Findings: fs,
		AssessedDimensions:  m,
		SupportedDimensions: m,
		EnginesRun:          []string{"trivy"},
	})
}

// The single most important property: a dimension nobody scanned must not
// look identical to a dimension that came back clean.
func TestUnassessedDimensionIsNotScoredAsClean(t *testing.T) {
	sc := build(nil, "dependencies")

	if dim := sc.Dimensions["code"]; dim.Assessed || dim.Score != 0 {
		t.Errorf("unassessed dimension scored %.0f assessed=%t; absence of evidence is not evidence of absence",
			dim.Score, dim.Assessed)
	}
	if sc.Dimensions["dependencies"].Score != 100 {
		t.Error("an assessed dimension with no findings should score 100")
	}
}

// An engine that was meant to run and did not is a degradation somebody can
// fix. Having no DAST engine configured at all is a standing coverage gap,
// and reporting it as a degradation on every scan makes the warning useless.
func TestOnlyMissingEnginesDegradeAScan(t *testing.T) {
	gap := Build(Input{
		Project:             "t",
		AssessedDimensions:  map[string]bool{"dependencies": true},
		SupportedDimensions: map[string]bool{"dependencies": true},
	})
	if gap.Degraded {
		t.Error("a dimension with no engine configured is a coverage gap, not a degraded scan")
	}
	if gap.Dimensions["api"].Supported {
		t.Error("api should not be marked supported when no engine covers it")
	}

	broke := Build(Input{
		Project:             "t",
		AssessedDimensions:  map[string]bool{"dependencies": true},
		SupportedDimensions: map[string]bool{"dependencies": true, "code": true},
	})
	if !broke.Degraded {
		t.Error("an engine that was supposed to cover a dimension and did not must degrade the scan")
	}
}

func TestCleanProjectScoresFull(t *testing.T) {
	sc := build(nil, "code", "dependencies", "container", "iac", "secrets", "api", "supply_chain")
	if sc.Score != 100 {
		t.Errorf("fully assessed clean project scored %.0f, want 100", sc.Score)
	}
	if sc.Degraded {
		t.Error("a complete clean scan must not be degraded")
	}
}

// No amount of arithmetic may let a project hold an unresolved critical and
// still show a healthy dimension score.
func TestCriticalFindingCapsDimensionScore(t *testing.T) {
	sc := build([]finding.Finding{f(finding.CategorySCA, 95, "critical")}, "dependencies")
	got := sc.Dimensions["dependencies"].Score
	if got > criticalCeiling {
		t.Errorf("dependencies scored %.0f with an unresolved critical; ceiling is %.0f", got, criticalCeiling)
	}
}

// A long tail of low-risk findings must not swamp the signal, or teams stop
// reading the number.
func TestManyLowFindingsDoNotCollapseScore(t *testing.T) {
	var fs []finding.Finding
	for i := 0; i < 40; i++ {
		fs = append(fs, f(finding.CategorySCA, 20, "low"))
	}
	sc := build(fs, "dependencies")
	if got := sc.Dimensions["dependencies"].Score; got < 60 {
		t.Errorf("40 low-risk findings scored %.0f; the long tail should not dominate", got)
	}
}

// Overall posture must be dragged down by the weakest dimension, not
// averaged away by strong ones.
func TestOverallLeansOnTheWeakestDimension(t *testing.T) {
	fs := []finding.Finding{
		f(finding.CategorySCA, 95, "critical"), // tanks dependencies
	}
	sc := build(fs, "code", "dependencies", "container", "iac", "secrets")

	mean := 0.0
	n := 0
	for _, name := range []string{"code", "dependencies", "container", "iac", "secrets"} {
		mean += sc.Dimensions[name].Score
		n++
	}
	mean /= float64(n)

	if sc.Score >= mean {
		t.Errorf("overall %.0f should sit below the plain mean %.0f so one bad area cannot be hidden",
			sc.Score, mean)
	}
}

func TestMandatoryConditionsDetectRealProblems(t *testing.T) {
	tests := []struct {
		name      string
		finding   finding.Finding
		condition string
	}{
		{"committed secret", f(finding.CategorySecret, 90, "critical"), "no_active_secrets"},
		{"known exploited", func() finding.Finding {
			x := f(finding.CategorySCA, 80, "high")
			x.Threat.KEV = true
			return x
		}(), "no_kev_in_production"},
		{"reachable critical", func() finding.Finding {
			x := f(finding.CategorySCA, 95, "critical")
			x.Analysis.Reachability = "reachable"
			return x
		}(), "no_reachable_critical_vulnerability"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := build([]finding.Finding{tc.finding}, "dependencies", "secrets")
			if sc.Mandatory[tc.condition] {
				t.Errorf("condition %q should be violated by %s", tc.condition, tc.name)
			}
		})
	}
}

// An accepted risk should stop depressing posture, or an accepted finding is
// indistinguishable from an ignored one.
func TestAcceptedFindingsDoNotDepressPosture(t *testing.T) {
	accepted := f(finding.CategorySCA, 95, "critical")
	accepted.Status = finding.StatusAccepted

	sc := build([]finding.Finding{accepted}, "dependencies")
	if sc.Dimensions["dependencies"].Score != 100 {
		t.Errorf("accepted finding still depressed the score to %.0f", sc.Dimensions["dependencies"].Score)
	}
	if !sc.Mandatory["no_critical_risk"] {
		t.Error("an accepted finding should not violate a mandatory condition")
	}
}

func TestPolicyCountsAreAggregated(t *testing.T) {
	sc := Build(Input{
		Project:            "t",
		AssessedDimensions: map[string]bool{"dependencies": true},
		Evaluations: []policy.Evaluation{
			{Decision: policy.DecisionDeny},
			{Decision: policy.DecisionWarn},
			{Decision: policy.DecisionAllow, Exempt: true},
			{Decision: policy.DecisionAllow, Errors: []string{"boom"}},
		},
	})
	if sc.Policy.Blocking != 1 || sc.Policy.Warnings != 1 || sc.Policy.Exempt != 1 || sc.Policy.Errors != 1 {
		t.Errorf("policy counts = %+v", sc.Policy)
	}
}
