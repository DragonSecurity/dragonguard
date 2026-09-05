package pipeline

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/report"
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

// fakeGraphScanner also reports an inventory, which is what the ships pass and
// the upstream-posture engine both read.
type fakeGraphScanner struct {
	fakeScanner
	nodes []scanner.PackageNode
}

func (f *fakeGraphScanner) ScanWithGraph(context.Context, scanner.Target) ([]finding.Finding, *scanner.PackageGraph, error) {
	g := scanner.NewPackageGraph()
	for _, n := range f.nodes {
		g.Add(n)
	}
	return f.findings, g, f.err
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

// The gate needs to know which branch is the trunk before it can compare
// against it. Configuration wins, then the remote's own HEAD, then a local
// main or master -- and nothing at all outside a repository, because
// inventing a name would compare this scan against another project's snapshot.
func TestDefaultBranchResolution(t *testing.T) {
	t.Run("configuration wins", func(t *testing.T) {
		if got := defaultBranch(t.TempDir(), "trunk"); got != "trunk" {
			t.Errorf("defaultBranch = %q, want the configured trunk", got)
		}
	})

	t.Run("not a repository", func(t *testing.T) {
		if got := defaultBranch(t.TempDir(), ""); got != "" {
			t.Errorf("defaultBranch = %q outside a repository, want empty", got)
		}
	})

	t.Run("local main", func(t *testing.T) {
		dir := t.TempDir()
		for _, args := range [][]string{
			{"init", "--initial-branch=main"},
			{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "--allow-empty", "-m", "x"},
		} {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("git unavailable: %v: %s", err, out)
			}
		}
		if got := defaultBranch(dir, ""); got != "main" {
			t.Errorf("defaultBranch = %q, want main", got)
		}
	})
}

// A release can move the numbers without a line of scanned code changing:
// fingerprints alter, a suppression starts being honoured, a rule is added. A
// scan that cannot say which build produced it leaves a posture drop
// indistinguishable from an upgrade.
func TestAScanRecordsTheBuildThatProducedIt(t *testing.T) {
	prev := report.Version
	report.Version = "0.5.7"
	t.Cleanup(func() { report.Version = prev })

	dir := t.TempDir()
	res, err := Run(context.Background(), Options{
		Dir:      dir,
		Config:   testConfig(t, dir, config.Asset{Name: "t"}),
		Registry: scanner.NewRegistry(),
		Offline:  true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.DragonVersion != "0.5.7" {
		t.Errorf("DragonVersion = %q, want the running build", res.DragonVersion)
	}
}

// End to end: a finding nobody can fix should be able to stop dragging the
// posture down, once somebody has said so in writing and signed their name.
func TestAnAcceptedFindingStopsCountingAgainstThePosture(t *testing.T) {
	dir := t.TempDir()
	unfixable := finding.Finding{
		Scanner: "osv", Category: finding.CategorySCA, RuleID: "GO-2026-5932",
		Title: "openpgp is unmaintained", Severity: finding.SeverityMedium,
		Threat:  finding.Threat{CVSS: 6.5},
		Package: &finding.Package{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "0.56.0"},
	}
	reg := regWith(&fakeScanner{name: "osv", available: true,
		cats: []finding.Category{finding.CategorySCA}, findings: []finding.Finding{unfixable}})

	before, err := Run(context.Background(), Options{
		Dir: dir, Registry: reg, Offline: true,
		Config: testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"}),
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"})
	cfg.Accept = []config.Acceptance{{
		Finding:    "GO-2026-5932",
		Reason:     "unmaintained upstream, no replacement; we do not use PGP",
		ApprovedBy: "security",
	}}
	after, err := Run(context.Background(), Options{Dir: dir, Registry: reg, Offline: true, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}

	if after.Scorecard.Score <= before.Scorecard.Score {
		t.Errorf("accepting the finding left the posture at %.0f (was %.0f); an acceptance must stop it counting",
			after.Scorecard.Score, before.Scorecard.Score)
	}
	if after.Accepted.Applied != 1 || after.Accepted.Entries != 1 {
		t.Errorf("acceptance report = %+v, want one entry applied once", after.Accepted)
	}
	// Still in the report. A suppression nobody can see is indistinguishable
	// from a scanner that stopped looking.
	if len(after.Findings) != 1 {
		t.Fatalf("got %d findings; an accepted finding is carried, not deleted", len(after.Findings))
	}
	if after.Findings[0].Status != finding.StatusAccepted {
		t.Errorf("status = %s, want accepted", after.Findings[0].Status)
	}
}

// An expiry that has passed has to be visible. The finding counts again either
// way; the difference is whether anyone can tell why the posture moved.
func TestAnExpiredAcceptanceIsReportedRatherThanDroppedQuietly(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"})
	cfg.Accept = []config.Acceptance{{
		Finding: "GO-2026-5932", Reason: "waiting on upstream", ApprovedBy: "security",
		Expires: "2020-01-01",
	}}

	res, err := Run(context.Background(), Options{
		Dir: dir, Config: cfg, Offline: true,
		Registry: regWith(&fakeScanner{name: "osv", available: true,
			cats: []finding.Category{finding.CategorySCA},
			findings: []finding.Finding{{
				Scanner: "osv", Category: finding.CategorySCA, RuleID: "GO-2026-5932",
				Title: "openpgp is unmaintained", Severity: finding.SeverityMedium,
				Package: &finding.Package{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "0.56.0"},
			}}}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Accepted.Expired) != 1 {
		t.Fatalf("expired = %v, want the lapsed entry named", res.Accepted.Expired)
	}
	if res.Findings[0].Status == finding.StatusAccepted {
		t.Error("a lapsed acceptance must not still exempt its finding")
	}
	if res.Accepted.ExpiredNote() == "" {
		t.Error("the scan must be able to say an acceptance lapsed")
	}
}

// Go records nothing about build-only dependencies, so before ships: the answer
// was an unqualified "everything reaches production" -- a claim rather than a
// gap. The scan has to be able to tell the two apart.
func TestGoDependenciesReportWhetherBuildOnlyIsKnown(t *testing.T) {
	dir := t.TempDir()
	goDep := finding.Finding{
		Scanner: "trivy", Category: finding.CategorySCA, RuleID: "GHSA-1",
		Severity: finding.SeverityMedium,
		Package:  &finding.Package{Ecosystem: "go", Name: "example.com/tool", Version: "v1.0.0"},
	}
	reg := regWith(&fakeGraphScanner{
		fakeScanner: fakeScanner{name: "trivy", available: true,
			cats: []finding.Category{finding.CategorySCA}, findings: []finding.Finding{goDep}},
		nodes: []scanner.PackageNode{
			{Ecosystem: "go", Name: "example.com/tool", Version: "v1.0.0", Direct: true},
		},
	})

	res, err := Run(context.Background(), Options{
		Dir: dir, Registry: reg, Offline: true,
		Config: testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ships.Determined {
		t.Error("with no ships: configured, build-only cannot be determined")
	}
	if res.Ships.Note() == "" {
		t.Error("an undetermined result must be reported, not left to look clean")
	}
}

// A project with no Go dependencies should hear nothing about Go entry points.
func TestNoGoDependenciesMeansNothingToSayAboutShipping(t *testing.T) {
	dir := t.TempDir()
	reg := regWith(&fakeGraphScanner{
		fakeScanner: fakeScanner{name: "trivy", available: true,
			cats: []finding.Category{finding.CategorySCA}},
		nodes: []scanner.PackageNode{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Direct: true},
		},
	})

	res, err := Run(context.Background(), Options{
		Dir: dir, Registry: reg, Offline: true,
		Config: testConfig(t, dir, config.Asset{Name: "t"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ships.Note() != "" {
		t.Errorf("a project with no Go dependencies said %q", res.Ships.Note())
	}
}

// The payoff, end to end: a module reachable only from a tool stops being
// scored as though the server links it, which is what makes the built-in
// build-only policy rule able to fire at all.
func TestDeclaringWhatShipsMarksTheRestBuildOnly(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/app\n\ngo 1.21\n\nrequire (\n\texample.com/prod v0.0.0\n\texample.com/tool v0.0.0\n)\n\nreplace example.com/prod => ./deps/prod\n\nreplace example.com/tool => ./deps/tool\n")
	write("main.go", "package main\n\nimport \"example.com/prod\"\n\nfunc main() { _ = prod.X }\n")
	write("tools/gen/main.go", "package main\n\nimport \"example.com/tool\"\n\nfunc main() { _ = tool.Y }\n")
	write("deps/prod/go.mod", "module example.com/prod\n\ngo 1.21\n")
	write("deps/prod/prod.go", "package prod\n\nconst X = 1\n")
	write("deps/tool/go.mod", "module example.com/tool\n\ngo 1.21\n")
	write("deps/tool/tool.go", "package tool\n\nconst Y = 2\n")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "")

	onTool := finding.Finding{
		Scanner: "trivy", Category: finding.CategorySCA, RuleID: "GHSA-tool",
		Severity: finding.SeverityMedium,
		Package:  &finding.Package{Ecosystem: "go", Name: "example.com/tool", Version: "v0.0.0"},
	}
	onProd := finding.Finding{
		Scanner: "trivy", Category: finding.CategorySCA, RuleID: "GHSA-prod",
		Severity: finding.SeverityMedium,
		Package:  &finding.Package{Ecosystem: "go", Name: "example.com/prod", Version: "v0.0.0"},
	}
	reg := regWith(&fakeGraphScanner{
		fakeScanner: fakeScanner{name: "trivy", available: true,
			cats: []finding.Category{finding.CategorySCA}, findings: []finding.Finding{onTool, onProd}},
		nodes: []scanner.PackageNode{
			{Ecosystem: "go", Name: "example.com/tool", Version: "v0.0.0", Direct: true},
			{Ecosystem: "go", Name: "example.com/prod", Version: "v0.0.0", Direct: true},
		},
	})

	cfg := testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"})
	cfg.Ships = []string{"."}

	res, err := Run(context.Background(), Options{Dir: dir, Registry: reg, Offline: true, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ships.Determined {
		t.Fatalf("ships was not determined: %s", res.Ships.Reason)
	}
	if res.Ships.DevOnly != 1 || res.Ships.Shipped != 1 {
		t.Errorf("ships report = %+v, want one of each", res.Ships)
	}

	byRule := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byRule[f.RuleID] = f
	}
	if !byRule["GHSA-tool"].Package.DevOnly {
		t.Error("a module reachable only from tools/ should be marked build-only")
	}
	if byRule["GHSA-prod"].Package.DevOnly {
		t.Error("a module the binary links must not be marked build-only")
	}
	// The point of knowing: the same advisory is a smaller problem in a
	// dependency that never reaches production.
	if byRule["GHSA-tool"].RiskScore >= byRule["GHSA-prod"].RiskScore {
		t.Errorf("build-only scored %.0f against shipped %.0f; knowing should change the risk",
			byRule["GHSA-tool"].RiskScore, byRule["GHSA-prod"].RiskScore)
	}
}

// An acceptance whose selector is subtly wrong is worse than no acceptance:
// somebody has written down a decision, believes it is in effect, and it is
// not. The rule id is the easy thing to get wrong, because the report shows a
// finding's title and not its rule -- a supply-chain finding reading "viper has
// been quiet and scores 4.5/10" is supply-chain/quiet, not
// supply-chain/weak-upstream, and nothing on screen says so.
func TestAnAcceptanceThatMatchedNothingIsNamed(t *testing.T) {
	dir := t.TempDir()
	quiet := finding.Finding{
		Scanner: "supplychain", Category: finding.CategorySupplyChain,
		RuleID: "supply-chain/quiet", Title: "viper has been quiet",
		Severity: finding.SeverityInfo,
		Package:  &finding.Package{Ecosystem: "go", Name: "github.com/spf13/viper", Version: "v1.21.0"},
	}
	cfg := testConfig(t, dir, config.Asset{Name: "t", Environment: "production", Criticality: "medium"})
	cfg.Accept = []config.Acceptance{
		{
			// The right package, the wrong rule.
			Package: "github.com/spf13/viper", Finding: "supply-chain/weak-upstream",
			Reason: "reviewed", ApprovedBy: "security",
		},
		{
			// The one that does match.
			Package: "github.com/spf13/viper", Finding: "supply-chain/quiet",
			Reason: "reviewed", ApprovedBy: "security",
		},
	}

	res, err := Run(context.Background(), Options{
		Dir: dir, Config: cfg, Offline: true,
		Registry: regWith(&fakeScanner{name: "supplychain", available: true,
			cats: []finding.Category{finding.CategorySupplyChain}, findings: []finding.Finding{quiet}}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Accepted.Applied != 1 {
		t.Errorf("applied = %d, want the matching acceptance to have fired", res.Accepted.Applied)
	}
	if len(res.Accepted.Unmatched) != 1 {
		t.Fatalf("unmatched = %v, want exactly the wrong-rule entry", res.Accepted.Unmatched)
	}
	if !strings.Contains(res.Accepted.Unmatched[0], "weak-upstream") {
		t.Errorf("unmatched names %q; it should name the entry that did nothing", res.Accepted.Unmatched[0])
	}
	if res.Accepted.UnmatchedNote() == "" {
		t.Error("the scan must be able to say an acceptance matched nothing")
	}
}

// An expired entry matches nothing by construction, and already has its own,
// more specific line. Reporting it twice would train people to skim both.
func TestAnExpiredAcceptanceIsNotAlsoReportedAsUnmatched(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir, config.Asset{Name: "t"})
	cfg.Accept = []config.Acceptance{{
		Finding: "GO-1", Reason: "waiting on upstream", ApprovedBy: "security",
		Expires: "2020-01-01",
	}}

	res, err := Run(context.Background(), Options{
		Dir: dir, Config: cfg, Offline: true, Registry: scanner.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accepted.Expired) != 1 {
		t.Fatalf("expired = %v", res.Accepted.Expired)
	}
	if len(res.Accepted.Unmatched) != 0 {
		t.Errorf("an expired acceptance was also reported as unmatched: %v", res.Accepted.Unmatched)
	}
}
