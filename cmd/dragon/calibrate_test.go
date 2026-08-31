package main

import (
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/report"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

func card(overall float64, dims map[string]float64) *report.Result {
	sc := &scorecard.Scorecard{
		Score:      overall,
		Dimensions: map[string]scorecard.Dimension{},
		Mandatory: map[string]bool{
			"no_active_secrets":                   true,
			"no_kev_in_production":                true,
			"no_reachable_critical_vulnerability": true,
		},
	}
	for name, v := range dims {
		sc.Dimensions[name] = scorecard.Dimension{Name: name, Score: v, Assessed: true, Supported: true}
	}
	return &report.Result{
		Scorecard: sc,
		Decision:  &baseline.Decision{Verdict: baseline.VerdictPass},
	}
}

// A floor of zero is not a gate: nothing can fall below it. Writing one puts
// a line in the baseline that looks like protection and provides none, which
// is the failure mode this whole tool exists to avoid.
func TestZeroScoringDimensionsGetNoFloor(t *testing.T) {
	res := card(45, map[string]float64{
		"code":         85,
		"dependencies": 0,
		"secrets":      100,
	})

	bl, ungated := calibrate(res, false, false)

	if _, ok := bl.Dimensions["dependencies"]; ok {
		t.Error("a dimension scoring zero must not get a floor: minimum 0 can never fail")
	}
	if len(ungated) != 1 || ungated[0] != "dependencies" {
		t.Errorf("ungated = %v, want [dependencies]", ungated)
	}
	// Dimensions with a real score still get real floors.
	if d, ok := bl.Dimensions["code"]; !ok || d.Minimum == nil || *d.Minimum <= 0 {
		t.Errorf("code should keep a usable floor, got %+v", d)
	}
}

// The omission has to be visible. Silence would be worse than the zero floor
// it replaces: a reader noticing a missing dimension should learn it was a
// decision, not an oversight.
func TestUngatedDimensionsAreExplained(t *testing.T) {
	note := ungatedNote([]string{"dependencies", "api"})
	for _, want := range []string{"dependencies", "api", "floor of zero is not a gate", "regression ratchet"} {
		if !strings.Contains(note, want) {
			t.Errorf("note is missing %q:\n%s", want, note)
		}
	}
	if ungatedNote(nil) != "" {
		t.Error("nothing to say when every dimension is gated")
	}
}

// Secrets is the one dimension held at 100 rather than calibrated down: there
// is no defensible number of live credentials in a repository.
func TestSecretsIsHeldAtFullMarks(t *testing.T) {
	bl, _ := calibrate(card(90, map[string]float64{"secrets": 100, "code": 90}), false, false)
	d, ok := bl.Dimensions["secrets"]
	if !ok || d.Minimum == nil || *d.Minimum != 100 || !d.Required {
		t.Errorf("secrets rule = %+v, want minimum 100 and required", d)
	}
}

// Calibration exists so a legacy codebase can adopt the gate today, so the
// floors must sit below where the project currently is.
func TestFloorsSitBelowCurrentPosture(t *testing.T) {
	bl, _ := calibrate(card(45, map[string]float64{"code": 85}), false, false)
	if bl.MinimumScore == nil || *bl.MinimumScore >= 45 {
		t.Errorf("overall floor = %v, want below the current 45", bl.MinimumScore)
	}
	if d := bl.Dimensions["code"]; *d.Minimum >= 85 {
		t.Errorf("code floor = %.0f, want below the current 85", *d.Minimum)
	}

	// --strict calibrates at exactly current posture.
	strict, _ := calibrate(card(45, map[string]float64{"code": 85}), true, false)
	if *strict.MinimumScore != 45 {
		t.Errorf("strict floor = %.0f, want exactly 45", *strict.MinimumScore)
	}
}

// Committed credentials are the one thing calibration refuses to grandfather.
func TestCommittedSecretsAreNotCalibratedAway(t *testing.T) {
	res := card(45, map[string]float64{"secrets": 40})
	res.Scorecard.Mandatory["no_active_secrets"] = false

	bl, _ := calibrate(res, false, false)
	if !contains(bl.Mandatory, "no_active_secrets") {
		t.Error("no_active_secrets must stay mandatory: a disclosed key is already out")
	}

	// Unless explicitly overridden.
	relaxed, _ := calibrate(res, false, true)
	if contains(relaxed.Mandatory, "no_active_secrets") {
		t.Error("--allow-existing-secrets should drop the gate")
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
