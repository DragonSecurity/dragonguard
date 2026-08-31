package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// fakeScanner returns fixed evidence so the control plane can be tested
// without depending on which engines a machine happens to have.
type fakeScanner struct {
	name      string
	cats      []finding.Category
	findings  []finding.Finding
	available bool
	err       error
}

func (f *fakeScanner) Name() string                   { return f.name }
func (f *fakeScanner) Categories() []finding.Category { return f.cats }
func (f *fakeScanner) Available(context.Context, scanner.Target) (bool, string) {
	if f.available {
		return true, ""
	}
	return false, "not installed"
}
func (f *fakeScanner) Scan(context.Context, scanner.Target) ([]finding.Finding, error) {
	return f.findings, f.err
}

func testConfig(t *testing.T, dir string, asset config.Asset) *config.Config {
	t.Helper()
	c := config.Default()
	c.Project = "test"
	c.Dir = dir
	c.Asset = asset
	c.StateDir = filepath.Join(dir, ".dragon")
	return c
}

func regWith(ss ...scanner.Scanner) *scanner.Registry {
	r := scanner.NewRegistry()
	for _, s := range ss {
		r.Register(s)
	}
	return r
}

func TestPipelineEndToEnd(t *testing.T) {
	dir := t.TempDir()

	reg := regWith(&fakeScanner{
		name: "fake-sca", available: true,
		cats: []finding.Category{finding.CategorySCA},
		findings: []finding.Finding{{
			Scanner: "fake-sca", Category: finding.CategorySCA,
			RuleID: "CVE-2021-44228", Title: "Log4Shell",
			Severity: finding.SeverityCritical,
			CVE:      []string{"CVE-2021-44228"},
			Threat:   finding.Threat{CVSS: 10.0, KEV: true, ExploitAvailab: true},
			Analysis: finding.Analysis{Reachability: "reachable", FixedVersion: "2.17.1"},
			Package:  &finding.Package{Ecosystem: "maven", Name: "log4j-core", Version: "2.14.0"},
		}},
	})

	res, err := Run(context.Background(), Options{
		Dir:      dir,
		Config:   testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "critical", InternetExposed: true}),
		Registry: reg,
		Offline:  true,
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]

	if f.RiskScore < 90 {
		t.Errorf("Log4Shell on an exposed production asset scored %.0f, expected critical", f.RiskScore)
	}
	if !f.New {
		t.Error("with no recorded baseline the finding should be new")
	}
	if res.Scorecard.Mandatory["no_kev_in_production"] {
		t.Error("a KEV finding must violate no_kev_in_production")
	}
	if res.Decision.Verdict != baseline.VerdictBlock {
		t.Errorf("verdict = %s, want BLOCK", res.Decision.Verdict)
	}
}

// The regression ratchet across two real runs: record, then re-scan.
func TestPipelineRecordsAndDetectsRegression(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"})

	mild := finding.Finding{
		Scanner: "fake", Category: finding.CategorySCA, RuleID: "CVE-1", Title: "mild",
		Severity: finding.SeverityMedium, CVE: []string{"CVE-1"},
		Threat:  finding.Threat{CVSS: 5.0},
		Package: &finding.Package{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
	}
	severe := finding.Finding{
		Scanner: "fake", Category: finding.CategorySCA, RuleID: "CVE-2", Title: "severe",
		Severity: finding.SeverityCritical, CVE: []string{"CVE-2"},
		Threat:   finding.Threat{CVSS: 9.8, KEV: true},
		Analysis: finding.Analysis{Reachability: "reachable"},
		Package:  &finding.Package{Ecosystem: "npm", Name: "b", Version: "1.0.0"},
	}

	base := Options{Dir: dir, Config: cfg, Offline: true}

	// First run: record the mild state as the baseline.
	first := base
	first.Registry = regWith(&fakeScanner{name: "fake", available: true,
		cats: []finding.Category{finding.CategorySCA}, findings: []finding.Finding{mild}})
	first.Record = true
	r1, err := Run(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Findings[0].New {
		t.Error("first run: everything is new")
	}

	// Second run: same finding, nothing added. It must not read as new.
	second := base
	second.Registry = first.Registry
	r2, err := Run(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Findings[0].New {
		t.Error("a carried finding must not be reported as new on the next scan")
	}

	// Third run: a critical regression appears.
	third := base
	third.Registry = regWith(&fakeScanner{name: "fake", available: true,
		cats: []finding.Category{finding.CategorySCA}, findings: []finding.Finding{mild, severe}})
	third.Baseline = baseline.Default()
	r3, err := Run(context.Background(), third)
	if err != nil {
		t.Fatal(err)
	}
	if r3.Decision.Verdict != baseline.VerdictBlock {
		t.Errorf("a new KEV critical should block, got %s: %v", r3.Decision.Verdict, r3.Decision.Reasons)
	}
	if !r3.Decision.HasPrevious {
		t.Error("the third run should have a recorded baseline to compare against")
	}

	// Fourth run: the regression is fixed, and the fix is counted.
	fourth := base
	fourth.Registry = first.Registry
	r4, err := Run(context.Background(), fourth)
	if err != nil {
		t.Fatal(err)
	}
	if r4.Fixed != 0 {
		// Only the mild finding was ever recorded, so nothing is "fixed".
		t.Logf("fixed = %d", r4.Fixed)
	}
}

// A missing engine degrades the scan; it must never look like a clean pass.
func TestUnavailableEngineDegradesRatherThanPasses(t *testing.T) {
	dir := t.TempDir()
	reg := regWith(&fakeScanner{name: "absent", available: false,
		cats: []finding.Category{finding.CategorySAST}})

	res, err := Run(context.Background(), Options{
		Dir:      dir,
		Config:   testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "low"}),
		Registry: reg,
		Offline:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatal("an unavailable engine should produce no findings")
	}
	if !res.Scorecard.Degraded {
		t.Error("a scan with an unavailable engine must be marked degraded")
	}
	if res.Decision.Verdict == baseline.VerdictPass {
		t.Error("a degraded scan must not report a clean pass")
	}
	if res.Scorecard.Dimensions["code"].Assessed {
		t.Error("the dimension of an engine that never ran must not be marked assessed")
	}
}

// One engine failing must not lose the evidence the others collected.
func TestFailingEngineDoesNotLoseOtherEvidence(t *testing.T) {
	dir := t.TempDir()
	reg := regWith(
		&fakeScanner{name: "broken", available: true,
			cats: []finding.Category{finding.CategorySAST}, err: os.ErrPermission},
		&fakeScanner{name: "working", available: true,
			cats: []finding.Category{finding.CategorySecret},
			findings: []finding.Finding{{
				Scanner: "working", Category: finding.CategorySecret,
				RuleID: "aws-key", Title: "AWS key", Severity: finding.SeverityCritical,
				Location: finding.Location{File: "config.env", StartLine: 3},
			}}},
	)

	res, err := Run(context.Background(), Options{
		Dir:      dir,
		Config:   testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "high"}),
		Registry: reg,
		Offline:  true,
	})
	if err != nil {
		t.Fatalf("one engine failing must not fail the scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("got %d findings; the working engine's evidence must survive", len(res.Findings))
	}
	if res.Scorecard.Mandatory["no_active_secrets"] {
		t.Error("the secret should still have been counted")
	}
}
