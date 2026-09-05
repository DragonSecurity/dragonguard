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

// Three matches of one rule in one file are three defects. They collapsed into
// one, so two were invisible -- and fixing the reported one left the finding
// open, because another site kept the same fingerprint alive.
func TestSeparateSitesAreSeparateFindings(t *testing.T) {
	at := func(line int, snippet string) Finding {
		return Finding{
			Category: CategorySAST, Scanner: "opengrep", RuleID: "go.sql-concat",
			Location: Location{File: "a.go", StartLine: line, Snippet: snippet},
		}
	}
	a := at(9, `db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", name))`)
	b := at(13, `db.Exec(fmt.Sprintf("DELETE FROM %s", table))`)
	c := at(17, `db.Exec(fmt.Sprintf("TRUNCATE %s", table))`)

	seen := map[string]bool{}
	for _, f := range []Finding{a, b, c} {
		fp := f.ComputeFingerprint()
		if seen[fp] {
			t.Fatalf("two sites share a fingerprint: %s", fp)
		}
		seen[fp] = true
	}
}

// The line is still not part of the identity, which is the whole reason it was
// excluded: adding a comment above a function would otherwise renumber every
// finding below it and report a file of unchanged problems as new.
func TestASiteKeepsItsIdentityWhenTheCodeMovesDown(t *testing.T) {
	snippet := `db.Exec(fmt.Sprintf("DELETE FROM %s", table))`
	before := Finding{
		Category: CategorySAST, Scanner: "opengrep", RuleID: "go.sql-concat",
		Location: Location{File: "a.go", StartLine: 13, Snippet: snippet},
	}
	after := before
	after.Location.StartLine = 48

	if before.ComputeFingerprint() != after.ComputeFingerprint() {
		t.Error("the same code at a different line became a new finding")
	}
}

// Reindentation is not a new defect.
func TestReindentingIsNotANewFinding(t *testing.T) {
	tight := Finding{
		Category: CategorySAST, Scanner: "opengrep", RuleID: "go.sql-concat",
		Location: Location{File: "a.go", Snippet: `db.Exec(fmt.Sprintf("X %s", v))`},
	}
	loose := tight
	loose.Location.Snippet = "\t\tdb.Exec(fmt.Sprintf(\"X  %s\",   v))\n"

	if tight.ComputeFingerprint() == loose.ComputeFingerprint() {
		return // collapsed whitespace matched, which is the intent
	}
	t.Error("reindented code produced a different fingerprint")
}

// Two secrets in one file are two rotations. The redacted form is what
// distinguishes them, because the plaintext must never reach a fingerprint --
// fingerprints are written to reports, snapshots and the platform database.
func TestTwoSecretsInOneFileAreTwoFindings(t *testing.T) {
	a := Finding{
		Category: CategorySecret, RuleID: "generic-api-key",
		Location: Location{File: ".env", Snippet: "AWS_SECRET_ACCESS_KEY=REDACTED"},
	}
	b := Finding{
		Category: CategorySecret, RuleID: "generic-api-key",
		Location: Location{File: ".env", Snippet: "STRIPE_SECRET_KEY=REDACTED"},
	}
	if a.ComputeFingerprint() == b.ComputeFingerprint() {
		t.Error("two different credentials in one file merged into one finding")
	}
}

// An engine that reports no snippet keeps the old file-level identity rather
// than every finding becoming its own, which would be worse: an empty
// discriminator must not be mistaken for a distinguishing one.
func TestNoSnippetFallsBackToFileIdentity(t *testing.T) {
	a := Finding{
		Category: CategorySAST, Scanner: "opengrep", RuleID: "r",
		Location: Location{File: "a.go", StartLine: 1},
	}
	b := a
	b.Location.StartLine = 99

	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Error("without a snippet the identity should still be file-level")
	}
}

// A vulnerable component is identified by what it is. Nothing about this
// change should touch that.
func TestDependencyIdentityIsUnchangedByTheSiteDiscriminator(t *testing.T) {
	a := Finding{
		Category: CategorySCA, CVE: []string{"CVE-2026-1"},
		Package:  &Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.11"},
		Location: Location{File: "ui/yarn.lock", Snippet: "lodash@4.17.11"},
	}
	b := a
	b.Location.Snippet = "something else entirely"

	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Error("a dependency finding's identity changed with its snippet")
	}
}

// The duplicate that started this: OSV and Trivy both read the Go
// vulnerability database, both reported GO-2026-5932 against
// golang.org/x/crypto, and the report carried it twice. Neither carried a CVE,
// so the fingerprint fell back to the scanner name and the two engines agreeing
// looked like two problems.
func TestOneAdvisoryFromTwoEnginesIsOneFinding(t *testing.T) {
	now := time.Now()
	osv := Finding{
		Scanner: "osv", Category: CategorySCA, RuleID: "GO-2026-5932",
		Title:    "The golang.org/x/crypto/openpgp package is unmaintained",
		Severity: SeverityMedium,
		Package:  &Package{Ecosystem: "go", Name: "golang.org/x/crypto", Version: "0.56.0"},
	}
	trivy := Finding{
		Scanner: "trivy", Category: CategorySCA, RuleID: "GO-2026-5932",
		Title:    "openpgp is unmaintained",
		Severity: SeverityLow,
		Package:  &Package{Ecosystem: "gomod", Name: "golang.org/x/crypto", Version: "v0.56.0"},
	}
	osv.Normalize(now)
	trivy.Normalize(now)

	if osv.Fingerprint != trivy.Fingerprint {
		t.Errorf("two engines reporting %s on the same package produced two findings:\n  osv   %s\n  trivy %s",
			osv.RuleID, osv.Fingerprint, trivy.Fingerprint)
	}
}

// The other direction, which is what keeps the merge honest. An engine's own
// rule id means whatever that engine decided it means, so two engines using the
// same string are not necessarily talking about the same thing. Merging those
// would hide a finding, which is worse than showing one twice.
func TestAnEngineSpecificRuleKeepsItsEngineInItsIdentity(t *testing.T) {
	now := time.Now()
	a := Finding{
		Scanner: "trivy", Category: CategorySCA, RuleID: "unmaintained-package",
		Title: "unmaintained", Severity: SeverityLow,
		Package: &Package{Ecosystem: "go", Name: "example.com/x", Version: "1.0.0"},
	}
	b := a
	b.Scanner = "osv"
	a.Normalize(now)
	b.Normalize(now)

	if a.Fingerprint == b.Fingerprint {
		t.Error("a rule id that is not an advisory identifier must stay scoped to the engine that defined it")
	}
}

func TestAdvisoryIDRecognisesTheDatabasesAndNothingElse(t *testing.T) {
	for _, id := range []string{
		"GO-2026-5932", "GHSA-xxxx-yyyy-zzzz", "OSV-2021-1", "PYSEC-2023-1",
		"RUSTSEC-2020-0001", "DSA-5555-1", "USN-1234-1", "ghsa-lower-case-id",
	} {
		if advisoryID(id) == "" {
			t.Errorf("advisoryID(%q) = \"\", want it recognised as an advisory", id)
		}
	}
	for _, id := range []string{
		"", "unmaintained-package", "go.lang.security.audit.sqli",
		"generic-api-key", "DS002", "supply-chain/quiet",
		// Near misses. An engine rule that merely starts with a letter pair
		// must not be mistaken for a database identifier.
		"GOSEC-G401", "GOLANG-STYLE-RULE",
	} {
		if got := advisoryID(id); got != "" {
			t.Errorf("advisoryID(%q) = %q, want it treated as engine-specific", id, got)
		}
	}
}
