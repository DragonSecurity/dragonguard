package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

func writePack(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pack.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func loadPack(t *testing.T, body string) *Engine {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.LoadFile(writePack(t, body)); err != nil {
		t.Fatalf("load pack: %v", err)
	}
	return e
}

// The reason for choosing CEL over Rego was that a policy mistake should be
// caught when it is written, not when it silently fails to fire during
// somebody's release.
func TestMisspelledFieldIsRejectedAtLoadTime(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	err = e.LoadFile(writePack(t, `
rules:
  - id: typo
    when: threat.kevv
    then:
      decision: deny
`))
	if err == nil {
		t.Fatal("a misspelled field must be rejected at load time, not silently never match")
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("error should name the offending rule, got: %v", err)
	}
}

func TestNonBooleanExpressionIsRejected(t *testing.T) {
	e, _ := NewEngine()
	err := e.LoadFile(writePack(t, `
rules:
  - id: not-a-predicate
    when: risk.score
    then:
      decision: deny
`))
	if err == nil || !strings.Contains(err.Error(), "bool") {
		t.Errorf("expected a bool-type error, got: %v", err)
	}
}

func TestDuplicateRuleIDIsRejected(t *testing.T) {
	e, _ := NewEngine()
	err := e.LoadFile(writePack(t, `
rules:
  - id: same
    when: "true"
    then: {decision: warn}
  - id: same
    when: "false"
    then: {decision: warn}
`))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected a duplicate-id error, got: %v", err)
	}
}

// Aggregate mode: every matching rule contributes, rather than the first
// match winning. The scorecard downstream needs all of them.
func TestEvaluateAggregatesEveryMatch(t *testing.T) {
	e := loadPack(t, `
rules:
  - id: is-critical
    when: risk.score >= 90
    then: {decision: warn, tags: [critical]}
  - id: is-production
    when: asset.environment == "production"
    then: {decision: deny, tags: [prod], actions: [block_merge]}
  - id: never-matches
    when: risk.score < 0
    then: {decision: deny}
`)
	f := finding.Finding{RiskScore: 95, RiskRating: "critical"}
	f.Normalize(f.LastSeen)

	ev := e.Evaluate(&f, config.Asset{Environment: "production"}, nil)

	if len(ev.Results) != 2 {
		t.Fatalf("got %d results, want 2 (aggregate mode must not stop at the first match)", len(ev.Results))
	}
	// The strongest decision governs the outcome.
	if ev.Decision != DecisionDeny {
		t.Errorf("decision = %s, want deny", ev.Decision)
	}
}

func TestExemptionOverridesDeny(t *testing.T) {
	e := loadPack(t, `
rules:
  - id: block-all-criticals
    when: risk.score >= 90
    then: {decision: deny}
  - id: accept-dev-dependencies
    when: component.dev_only
    then: {decision: allow, exempt: true}
`)
	f := finding.Finding{
		RiskScore: 95,
		Package:   &finding.Package{Name: "x", Version: "1", DevOnly: true},
	}
	f.Normalize(f.LastSeen)

	ev := e.Evaluate(&f, config.Asset{Environment: "production"}, nil)
	if !ev.Exempt {
		t.Fatal("rule marked exempt did not set the exemption")
	}
	if ev.Decision != DecisionAllow {
		t.Errorf("decision = %s, an explicit exemption must override a deny", ev.Decision)
	}
}

// A finding with no package must not blow up a rule that reads component
// fields, or a policy author's rule silently stops enforcing.
func TestAbsentPackageDoesNotErrorRules(t *testing.T) {
	e := loadPack(t, `
rules:
  - id: dev-only
    when: component.dev_only
    then: {decision: warn}
`)
	f := finding.Finding{Category: finding.CategorySAST, RiskScore: 50}
	f.Normalize(f.LastSeen)

	ev := e.Evaluate(&f, config.Asset{Environment: "production"}, nil)
	if len(ev.Errors) > 0 {
		t.Errorf("evaluating a finding without a package produced errors: %v", ev.Errors)
	}
	if len(ev.Results) != 0 {
		t.Error("component.dev_only should be false, not matching, for a finding with no package")
	}
}

func TestStructuredMatchCompilesToCEL(t *testing.T) {
	e := loadPack(t, `
rules:
  - id: structured
    match:
      all:
        - risk.score >= 90
        - asset.environment == "production"
      none:
        - component.dev_only
    then: {decision: deny}
`)
	r := e.Rules()[0]
	src := r.Source()
	for _, want := range []string{"risk.score >= 90", "&&", `asset.environment == "production"`, "!(component.dev_only)"} {
		if !strings.Contains(src, want) {
			t.Errorf("compiled CEL %q is missing %q", src, want)
		}
	}

	f := finding.Finding{RiskScore: 95}
	f.Normalize(f.LastSeen)
	ev := e.Evaluate(&f, config.Asset{Environment: "production"}, nil)
	if ev.Decision != DecisionDeny {
		t.Errorf("structured rule did not fire: %s", ev.Decision)
	}
}

func TestRiskBoostIsAppliedAndClamped(t *testing.T) {
	e := loadPack(t, `
rules:
  - id: boost
    when: threat.kev
    then: {decision: warn, risk_boost: 40}
`)
	fs := []finding.Finding{{RiskScore: 80, Threat: finding.Threat{KEV: true}}}
	fs[0].Normalize(fs[0].LastSeen)

	e.EvaluateAll(fs, config.Asset{Environment: "production"}, nil)
	if fs[0].RiskScore != 100 {
		t.Errorf("risk score = %.0f, want 100 (80 + 40 clamped)", fs[0].RiskScore)
	}
}

// A rule that fails at runtime must be reported, never silently treated as
// "did not match" -- that is a gate that has quietly stopped enforcing.
func TestDisabledRulesDoNotFire(t *testing.T) {
	e := loadPack(t, `
rules:
  - id: off
    enabled: false
    when: "true"
    then: {decision: deny}
`)
	f := finding.Finding{RiskScore: 10}
	f.Normalize(f.LastSeen)
	ev := e.Evaluate(&f, config.Asset{Environment: "production"}, nil)
	if ev.Decision != DecisionAllow || len(ev.Results) != 0 {
		t.Error("a disabled rule fired")
	}
}

// The platform stores policy packs in a database, so rules have to compile
// from bytes as well as from a file -- through the same validation, or a
// UI-authored policy would be held to a lower standard than a committed one.
func TestLoadRulesFromBytes(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	// A bare rule array, as stored in a jsonb column.
	err = e.LoadRules("stored-pack", []byte(`[
	  {"id":"kev-prod","when":"threat.kev","then":{"decision":"deny","tags":["kev"]}}
	]`))
	if err != nil {
		t.Fatalf("load from JSON: %v", err)
	}
	if len(e.Rules()) != 1 {
		t.Fatalf("got %d rules, want 1", len(e.Rules()))
	}

	f := finding.Finding{Threat: finding.Threat{KEV: true}}
	f.Normalize(f.LastSeen)
	if ev := e.Evaluate(&f, config.Asset{Environment: "production"}, nil); ev.Decision != DecisionDeny {
		t.Errorf("decision = %s, want deny", ev.Decision)
	}
}

// A full pack document must load too, so a pack can move between a repository
// and the platform unchanged.
func TestLoadRulesAcceptsAFullPackDocument(t *testing.T) {
	e, _ := NewEngine()
	err := e.LoadRules("doc", []byte(`{"apiVersion":"dragonguard/v1","kind":"PolicyPack",
	  "metadata":{"name":"x"},
	  "rules":[{"id":"r1","when":"risk.score >= 90","then":{"decision":"warn"}}]}`))
	if err != nil {
		t.Fatalf("load pack document: %v", err)
	}
	if len(e.Rules()) != 1 {
		t.Errorf("got %d rules, want 1", len(e.Rules()))
	}
}

// A stored policy that will not compile has stopped enforcing, and must fail
// loudly rather than be skipped.
func TestLoadRulesRejectsBadStoredPolicy(t *testing.T) {
	e, _ := NewEngine()
	if err := e.LoadRules("bad", []byte(`[{"id":"typo","when":"threat.kevv","then":{"decision":"deny"}}]`)); err == nil {
		t.Error("a misspelled field in a stored policy must be rejected")
	}
}

func TestLoadRulesRejectsDuplicateIDsAcrossPacks(t *testing.T) {
	e, _ := NewEngine()
	if err := e.LoadRules("a", []byte(`[{"id":"same","when":"true","then":{"decision":"warn"}}]`)); err != nil {
		t.Fatal(err)
	}
	if err := e.LoadRules("b", []byte(`[{"id":"same","when":"false","then":{"decision":"warn"}}]`)); err == nil {
		t.Error("a rule id duplicated across packs must be rejected: the second would silently never be attributable")
	}
}

func licenceFinding(pkg, licence string) finding.Finding {
	return finding.Finding{
		Category: finding.CategoryLicense,
		RuleID:   "license/" + licence,
		Title:    pkg + " licensed under " + licence,
		Severity: finding.SeverityMedium,
		Package:  &finding.Package{Name: pkg, Ecosystem: "gomod"},
		Metadata: map[string]any{"license": licence, "license_category": "reciprocal"},
	}
}

// The case this exists for. MPL-2.0 is file-level copyleft: consuming a
// library unmodified triggers nothing, and eleven findings at risk 50 were
// dragging the dependencies dimension down for an obligation nobody had
// incurred. Approving it must stop it counting, not merely annotate it.
func TestAnApprovedLicenceStopsCounting(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.LoadLicensePolicy(config.LicensePolicy{
		Allow: []config.LicenseDecision{{
			ID:     "MPL-2.0",
			Reason: "consumed unmodified; MPL obligations attach to modified MPL files",
		}},
	}); err != nil {
		t.Fatalf("LoadLicensePolicy: %v", err)
	}

	findings := []finding.Finding{
		licenceFinding("github.com/riverqueue/river", "MPL-2.0"),
		licenceFinding("some/other", "AGPL-3.0"),
	}
	e.EvaluateAll(findings, config.Asset{}, nil)

	if findings[0].Status != finding.StatusAccepted {
		t.Errorf("approved licence has status %q, want accepted so the scorecard skips it", findings[0].Status)
	}
	if findings[1].Status == finding.StatusAccepted {
		t.Error("a licence nobody approved was exempted too")
	}
}

// Denial has to work whatever the scanner thought of the licence, which is the
// point of having a project-level opinion at all.
func TestADeniedLicenceIsRefused(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.LoadLicensePolicy(config.LicensePolicy{
		Deny: []config.LicenseDecision{{ID: "AGPL-3.0", Reason: "we ship a hosted service"}},
	}); err != nil {
		t.Fatalf("LoadLicensePolicy: %v", err)
	}

	f := licenceFinding("some/thing", "AGPL-3.0")
	ev := e.Evaluate(&f, config.Asset{}, nil)
	if ev.Decision != DecisionDeny {
		t.Errorf("decision = %q, want deny", ev.Decision)
	}
}

// The licence name lived only in Metadata, which policy could not see, so the
// only way to write a rule about it was to match the rule_id string the Trivy
// adapter happens to build. Exposing it is what makes a hand-written rule
// readable, and the desugared ones are compiled from the same field.
func TestLicenceIsVisibleToHandWrittenRules(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.LoadRules("t", []byte(`
- id: mpl-is-fine
  when: finding.license == "MPL-2.0" && finding.license_category == "reciprocal"
  then:
    decision: allow
    exempt: true
`)); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	f := licenceFinding("github.com/riverqueue/river", "MPL-2.0")
	if ev := e.Evaluate(&f, config.Asset{}, nil); !ev.Exempt {
		t.Errorf("a rule written against finding.license did not match: %+v", ev)
	}

	// A finding with no licence metadata must read as empty, not error.
	other := finding.Finding{Category: finding.CategorySCA, RuleID: "CVE-2026-1"}
	if ev := e.Evaluate(&other, config.Asset{}, nil); ev.Exempt {
		t.Error("a non-licence finding matched a licence rule")
	}
}
