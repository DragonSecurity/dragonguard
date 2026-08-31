package risk

import (
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// The concept this platform was designed from states two worked examples that
// the risk model has to reproduce, because they are the whole argument for
// scoring risk rather than sorting by CVSS.
func TestWorkedExamplesFromSpec(t *testing.T) {
	tests := []struct {
		name      string
		asset     config.Asset
		f         finding.Finding
		wantBand  string
		wantRange [2]float64
	}{
		{
			// CVSS 9.8, EPSS 0.001, not reachable, dev dependency => LOW.
			name:  "high cvss but nobody is exploiting it and it is not shipped",
			asset: config.Asset{Environment: "production", Criticality: "medium"},
			f: finding.Finding{
				Category: finding.CategorySCA,
				Severity: finding.SeverityCritical,
				Threat:   finding.Threat{CVSS: 9.8, EPSS: 0.001, EPSSKnown: true},
				Analysis: finding.Analysis{Reachability: "unreachable", FixAvailable: true},
				Package:  &finding.Package{Name: "left-pad", Version: "1.0.0", DevOnly: true},
			},
			wantBand:  "low",
			wantRange: [2]float64{10, 45},
		},
		{
			// CVSS 7.5, EPSS 0.91, KEV, internet-facing, reachable, prod => URGENT.
			name: "moderate cvss but actively exploited against an exposed asset",
			asset: config.Asset{
				Environment: "production", Criticality: "critical", InternetExposed: true,
			},
			f: finding.Finding{
				Category: finding.CategorySCA,
				Severity: finding.SeverityHigh,
				Threat:   finding.Threat{CVSS: 7.5, EPSS: 0.91, EPSSKnown: true, KEV: true, ExploitAvailab: true},
				Analysis: finding.Analysis{Reachability: "reachable", FixAvailable: true, MinimalUpgrade: "log4j 2.14 -> 2.17.1"},
				Package:  &finding.Package{Name: "log4j-core", Version: "2.14.0"},
			},
			wantBand:  "critical",
			wantRange: [2]float64{88, 100},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := New(tc.asset)
			got := e.Score(&tc.f)
			if got.Value < tc.wantRange[0] || got.Value > tc.wantRange[1] {
				t.Errorf("score = %.0f, want within %v (rating %s)\ncomponents: %+v",
					got.Value, tc.wantRange, got.Rating, got.Components)
			}
			if got.Rating != tc.wantBand {
				t.Errorf("rating = %q, want %q (score %.0f)", got.Rating, tc.wantBand, got.Value)
			}
		})
	}
}

// The whole point of the model is that the ordering inverts CVSS ordering
// when the world disagrees with the CVSS number.
func TestExploitedFindingOutranksHigherCVSS(t *testing.T) {
	asset := config.Asset{Environment: "production", Criticality: "critical", InternetExposed: true}
	e := New(asset)

	quiet := finding.Finding{
		Category: finding.CategorySCA, Severity: finding.SeverityCritical,
		Threat:   finding.Threat{CVSS: 9.8, EPSS: 0.0004, EPSSKnown: true},
		Analysis: finding.Analysis{Reachability: "unreachable"},
	}
	exploited := finding.Finding{
		Category: finding.CategorySCA, Severity: finding.SeverityHigh,
		Threat:   finding.Threat{CVSS: 7.5, EPSS: 0.91, EPSSKnown: true, KEV: true},
		Analysis: finding.Analysis{Reachability: "reachable", FixAvailable: true},
	}

	qs, es := e.Score(&quiet), e.Score(&exploited)
	if es.Value <= qs.Value {
		t.Errorf("actively exploited CVSS 7.5 (%.0f) should outrank quiet CVSS 9.8 (%.0f)", es.Value, qs.Value)
	}
}

// An offline run must not silently deflate scores by reading absent EPSS
// as an EPSS of zero.
func TestUnknownEPSSDoesNotDeflateScore(t *testing.T) {
	asset := config.Asset{Environment: "production", Criticality: "high"}
	e := New(asset)

	base := finding.Finding{
		Category: finding.CategorySCA, Severity: finding.SeverityCritical,
		Threat:   finding.Threat{CVSS: 9.8},
		Analysis: finding.Analysis{Reachability: "unknown", FixAvailable: true},
	}
	withZeroEPSS := base
	withZeroEPSS.Threat.EPSS = 0
	withZeroEPSS.Threat.EPSSKnown = true

	unknown := e.Score(&base)
	known := e.Score(&withZeroEPSS)

	if unknown.Value <= known.Value {
		t.Errorf("unknown EPSS (%.0f) must not score at or below a confirmed EPSS of 0 (%.0f)",
			unknown.Value, known.Value)
	}
	if unknown.Confidence >= 1.0 {
		t.Errorf("confidence should be below 1.0 when supply-chain and provenance evidence is missing, got %.2f", unknown.Confidence)
	}
}

// A committed credential is not a theoretical weakness.
func TestCommittedSecretScoresCritical(t *testing.T) {
	e := New(config.Asset{Environment: "production", Criticality: "high"})
	f := finding.Finding{
		Category: finding.CategorySecret,
		Severity: finding.SeverityCritical,
		RuleID:   "aws-access-key",
	}
	got := e.Score(&f)
	if got.Value < 85 {
		t.Errorf("committed credential scored %.0f (%s), expected >= 85\ncomponents: %+v",
			got.Value, got.Rating, got.Components)
	}
}

// Scoring must be reproducible: the same finding scores the same every run,
// or the regression gate becomes noise.
func TestScoringIsDeterministic(t *testing.T) {
	e := New(config.Asset{Environment: "production", Criticality: "critical", InternetExposed: true})
	f := finding.Finding{
		Category: finding.CategorySCA, Severity: finding.SeverityHigh,
		Threat:   finding.Threat{CVSS: 7.5, EPSS: 0.4, EPSSKnown: true, KEV: true},
		Analysis: finding.Analysis{Reachability: "reachable", FixAvailable: true, HasScorecard: true, ScorecardScore: 3.2},
	}
	first := e.Score(&f)
	for i := 0; i < 50; i++ {
		if got := e.Score(&f); got.Value != first.Value {
			t.Fatalf("run %d scored %.4f, first run scored %.4f", i, got.Value, first.Value)
		}
	}
}

// Exploit maturity is a CVE concept. Applying its discount to first-party
// code under-ranks exactly the flaws an attacker reaches for first.
func TestSASTIsNotPenalizedForHavingNoPublishedExploit(t *testing.T) {
	asset := config.Asset{Environment: "production", Criticality: "high", InternetExposed: true}
	e := New(asset)

	sast := finding.Finding{
		Category: finding.CategorySAST,
		Severity: finding.SeverityCritical,
		RuleID:   "dragon-js-command-injection",
		Threat:   finding.Threat{CVSS: 9.0},
		Analysis: finding.Analysis{Reachable: true, Reachability: "reachable"},
	}
	got := e.Score(&sast)
	if got.Value < 80 {
		t.Errorf("reachable command injection in an exposed production service scored %.0f (%s); "+
			"it should rank high\ncomponents: %+v", got.Value, got.Rating, got.Components)
	}

	// Unreachable first-party code is still discounted, just not for the
	// wrong reason.
	unreachable := sast
	unreachable.Analysis = finding.Analysis{Reachability: "unreachable"}
	if u := e.Score(&unreachable); u.Value >= got.Value {
		t.Errorf("unreachable (%.0f) should score below reachable (%.0f)", u.Value, got.Value)
	}
}
