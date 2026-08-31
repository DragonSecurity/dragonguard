package finding

import (
	"testing"
	"time"
)

func TestFingerprintIsStableAcrossLineMoves(t *testing.T) {
	a := Finding{
		Category: CategorySAST, Scanner: "opengrep", RuleID: "js.sqli",
		Location: Location{File: "app.js", StartLine: 12},
	}
	b := a
	b.Location.StartLine = 48

	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Error("a finding that moved down the file must keep its identity")
	}
}

func TestFingerprintIsScannerIndependentForSharedEvidence(t *testing.T) {
	tests := []struct {
		name string
		a, b Finding
	}{
		{
			name: "same CVE in same package from two SCA engines",
			a: Finding{
				Category: CategorySCA, Scanner: "trivy", RuleID: "CVE-2021-23337",
				CVE:     []string{"CVE-2021-23337"},
				Package: &Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.11"},
			},
			b: Finding{
				Category: CategorySCA, Scanner: "grype", RuleID: "GHSA-35jh-r3h4-6jhm",
				CVE:     []string{"CVE-2021-23337"},
				Package: &Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.11"},
			},
		},
		{
			name: "same credential found by two secret scanners",
			a: Finding{
				Category: CategorySecret, Scanner: "trivy", RuleID: "github-pat",
				Location: Location{File: "creds.env", StartLine: 2},
			},
			b: Finding{
				Category: CategorySecret, Scanner: "gitleaks", RuleID: "github-pat",
				Location: Location{File: "creds.env", StartLine: 7},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.a.ComputeFingerprint() != tc.b.ComputeFingerprint() {
				t.Error("the same problem reported by two engines must be one finding")
			}
		})
	}
}

// SAST rules mean different things in different engines, so two engines
// flagging one line are making two claims, not one.
func TestFingerprintKeepsScannerForSAST(t *testing.T) {
	a := Finding{Category: CategorySAST, Scanner: "opengrep", RuleID: "sqli", Location: Location{File: "a.js"}}
	b := Finding{Category: CategorySAST, Scanner: "bandit", RuleID: "sqli", Location: Location{File: "a.js"}}
	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Error("SAST findings from different engines must stay distinct")
	}
}

func TestDifferentPackageVersionsAreDifferentFindings(t *testing.T) {
	a := Finding{Category: CategorySCA, CVE: []string{"CVE-1"}, Package: &Package{Name: "x", Version: "1.0.0"}}
	b := Finding{Category: CategorySCA, CVE: []string{"CVE-1"}, Package: &Package{Name: "x", Version: "2.0.0"}}
	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Error("the same CVE in two versions is two findings")
	}
}

func TestMergeIsMonotone(t *testing.T) {
	rich := Finding{
		Scanner: "trivy", Severity: SeverityHigh,
		CVE:      []string{"CVE-1"},
		Threat:   Threat{CVSS: 7.5},
		Analysis: Analysis{FixedVersion: "1.2.3", Reachability: "unknown"},
	}
	poor := Finding{
		Scanner: "gitleaks", Severity: SeverityCritical,
		CVE:      []string{"CVE-2"},
		Analysis: Analysis{Reachability: "reachable", Reachable: true},
		Metadata: map[string]any{"commit": "abc123"},
	}

	a, b := rich, rich
	a.Merge(poor)

	// Merging must never lose or lower information.
	if a.Severity != SeverityCritical {
		t.Errorf("severity = %s, merge must raise to the higher severity", a.Severity)
	}
	if a.Threat.CVSS != b.Threat.CVSS {
		t.Error("merge must not drop an existing CVSS score")
	}
	if a.Analysis.FixedVersion != "1.2.3" {
		t.Error("merge must not drop a known fixed version")
	}
	if a.Analysis.Reachability != "reachable" {
		t.Error("one engine proving reachability outranks another failing to")
	}
	if len(a.CVE) != 2 {
		t.Errorf("CVEs = %v, merge must union them", a.CVE)
	}
	if a.Metadata["commit"] != "abc123" {
		t.Error("merge must keep metadata the other engine contributed")
	}
	also, _ := a.Metadata["also_reported_by"].([]string)
	if len(also) != 1 || also[0] != "gitleaks" {
		t.Errorf("also_reported_by = %v, want [gitleaks]", also)
	}
}

// Merge order must not change the outcome, or a verdict would depend on the
// order engines happen to be listed in a config file.
func TestMergeIsOrderIndependentForSeverity(t *testing.T) {
	a := Finding{Scanner: "one", Severity: SeverityLow}
	b := Finding{Scanner: "two", Severity: SeverityCritical}

	ab, ba := a, b
	ab.Merge(b)
	ba.Merge(a)

	if ab.Severity != ba.Severity {
		t.Errorf("merge order changed severity: %s vs %s", ab.Severity, ba.Severity)
	}
}

func TestNormalizeSeverityMapsScannerSpellings(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL": SeverityCritical, "Critical": SeverityCritical,
		"error": SeverityHigh, "HIGH": SeverityHigh,
		"warning": SeverityMedium, "moderate": SeverityMedium,
		"note": SeverityLow, "LOW": SeverityLow,
		"unknown": SeverityInfo, "": SeverityInfo,
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

// Engines spell ecosystems differently. Since the fingerprint is built from
// the ecosystem, an unnormalized name splits one problem into two findings.
func TestEcosystemSpellingsAreCanonicalized(t *testing.T) {
	groups := [][]string{
		{"go", "gomod", "Go", "golang", "go-module"},
		{"npm", "Node", "nodejs", "yarn"},
		{"pypi", "pip", "PyPI", "poetry"},
		{"maven", "gradle", "Java"},
		{"cargo", "crates.io", "Rust"},
	}
	for _, g := range groups {
		want := NormalizeEcosystem(g[0])
		for _, spelling := range g[1:] {
			if got := NormalizeEcosystem(spelling); got != want {
				t.Errorf("NormalizeEcosystem(%q) = %q, want %q", spelling, got, want)
			}
		}
	}
	// An unrecognized ecosystem is kept, lowercased, so two findings from the
	// same unknown ecosystem still match each other.
	if got := NormalizeEcosystem("Alpine"); got != "alpine" {
		t.Errorf("unknown ecosystem = %q, want alpine", got)
	}
}

func TestSameCVEFromTwoEnginesDedupesAcrossEcosystemSpellings(t *testing.T) {
	trivy := Finding{
		Category: CategorySCA, Scanner: "trivy", RuleID: "CVE-2021-4235",
		CVE:     []string{"CVE-2021-4235"},
		Package: &Package{Ecosystem: "gomod", Name: "gopkg.in/yaml.v2", Version: "2.2.2"},
	}
	osv := Finding{
		Category: CategorySCA, Scanner: "osv", RuleID: "GO-2021-0061",
		CVE:     []string{"CVE-2021-4235"},
		Package: &Package{Ecosystem: "Go", Name: "gopkg.in/yaml.v2", Version: "2.2.2"},
	}
	now := time.Now()
	trivy.Normalize(now)
	osv.Normalize(now)

	if trivy.Fingerprint != osv.Fingerprint {
		t.Errorf("same CVE in the same package produced two fingerprints: %s vs %s (ecosystems %q / %q)",
			trivy.Fingerprint[:8], osv.Fingerprint[:8], trivy.Package.Ecosystem, osv.Package.Ecosystem)
	}
}

// Go modules are the case that forces version canonicalization: Trivy reports
// "v2.2.2" and OSV-Scanner reports "2.2.2" for the same release.
func TestGoModuleVersionPrefixDoesNotSplitFindings(t *testing.T) {
	trivy := Finding{
		Category: CategorySCA, Scanner: "trivy", RuleID: "CVE-2021-4235",
		CVE:     []string{"CVE-2021-4235"},
		Package: &Package{Ecosystem: "gomod", Name: "gopkg.in/yaml.v2", Version: "v2.2.2"},
	}
	osv := Finding{
		Category: CategorySCA, Scanner: "osv", RuleID: "GO-2021-0061",
		CVE:     []string{"CVE-2021-4235"},
		Package: &Package{Ecosystem: "Go", Name: "gopkg.in/yaml.v2", Version: "2.2.2"},
	}
	now := time.Now()
	trivy.Normalize(now)
	osv.Normalize(now)

	if trivy.Fingerprint != osv.Fingerprint {
		t.Errorf("the v-prefix split one finding into two: %s vs %s", trivy.Fingerprint[:8], osv.Fingerprint[:8])
	}
	// The reported version must still be what the scanner said.
	if trivy.Package.Version != "v2.2.2" || osv.Package.Version != "2.2.2" {
		t.Error("canonicalization must not rewrite the version shown in reports")
	}
}

// A leading "v" that is part of the name, not a version prefix, must survive.
func TestCanonicalVersionOnlyStripsAVersionPrefix(t *testing.T) {
	cases := map[string]string{
		"v2.2.2": "2.2.2", "2.2.2": "2.2.2", "V1.0": "1.0",
		"valid": "valid", "v": "v", "": "",
		"1.2.3-rc1": "1.2.3-rc1", "vendor-2": "vendor-2",
	}
	for in, want := range cases {
		if got := canonicalVersion(in); got != want {
			t.Errorf("canonicalVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
