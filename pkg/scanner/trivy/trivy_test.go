package trivy

import "testing"

// Most of any dependency tree is MIT and Apache-2.0. Reporting those as
// findings buries the copyleft and unknown cases that actually need a
// decision, and teaches people the licence dimension is noise.
func TestPermissiveLicensesAreNotReported(t *testing.T) {
	for _, c := range []string{"notice", "permissive", "unencumbered", "NOTICE", " notice "} {
		if licenseWorthReporting(c) {
			t.Errorf("licence category %q should not produce a finding", c)
		}
	}
}

func TestObligationBearingLicensesAreReported(t *testing.T) {
	// "unknown" is included deliberately: an unclassifiable licence cannot be
	// cleared without somebody reading it, which makes it a real finding.
	for _, c := range []string{"restricted", "reciprocal", "forbidden", "unknown", ""} {
		if !licenseWorthReporting(c) {
			t.Errorf("licence category %q should produce a finding", c)
		}
	}
}

// Vendors disagree on CVSS by several points, so the source has to be chosen
// deterministically or the score changes between identical runs.
func TestBestCVSSPrefersNVDAndIsDeterministic(t *testing.T) {
	v := vulnerability{CVSS: map[string]struct {
		V3Vector string  `json:"V3Vector"`
		V3Score  float64 `json:"V3Score"`
		V2Score  float64 `json:"V2Score"`
	}{
		"ghsa":   {V3Vector: "GHSA", V3Score: 9.1},
		"nvd":    {V3Vector: "NVD", V3Score: 7.5},
		"redhat": {V3Vector: "RH", V3Score: 5.0},
	}}

	score, vector := v.bestCVSS()
	if score != 7.5 || vector != "NVD" {
		t.Errorf("bestCVSS = %.1f/%s, want NVD 7.5", score, vector)
	}
	for i := 0; i < 50; i++ {
		if s, _ := v.bestCVSS(); s != score {
			t.Fatalf("run %d returned %.1f, not %.1f: map iteration order is leaking into the score", i, s, score)
		}
	}
}

func TestBestCVSSFallsBackWhenNoPreferredSourceExists(t *testing.T) {
	v := vulnerability{CVSS: map[string]struct {
		V3Vector string  `json:"V3Vector"`
		V3Score  float64 `json:"V3Score"`
		V2Score  float64 `json:"V2Score"`
	}{
		"vendor-a": {V3Vector: "A", V3Score: 4.0},
		"vendor-b": {V3Vector: "B", V3Score: 8.0},
	}}
	if score, _ := v.bestCVSS(); score != 8.0 {
		t.Errorf("fallback should take the highest score, got %.1f", score)
	}
}

// Enrichment can only look up CVEs, so GHSA and vendor advisory IDs must not
// be mixed into the CVE list.
func TestOnlyRealCVEIDsAreKept(t *testing.T) {
	got := cveIDs("CVE-2021-23337", []string{"GHSA-35jh-r3h4-6jhm", "CVE-2020-8203", "RHSA-2019:3024"})
	want := []string{"CVE-2021-23337", "CVE-2020-8203"}
	if len(got) != len(want) {
		t.Fatalf("cveIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cveIDs = %v, want %v", got, want)
		}
	}
}

// Trivy emits licences in their own result: Class "license", no Packages, and
// an empty Type. The licence findings were built from that result, so every one
// of them carried an empty ecosystem, no version, and direct=false -- while a
// vulnerability finding on the same package, from the lang-pkgs result beside
// it, carried all three. That is the shape reproduced here.
func TestLicenceFindingsTakeTheirFactsFromTheInventoryResult(t *testing.T) {
	results := []result{
		{
			Target: "go.mod", Class: "lang-pkgs", Type: "gomod",
			Packages: []pkgEntry{
				{Name: "github.com/riverqueue/river", Version: "v0.46.0", Relationship: "direct"},
				{Name: "github.com/go-sql-driver/mysql", Version: "v1.10.0", Relationship: "indirect", Indirect: true},
			},
		},
		{
			Target: "go.mod", Class: "license", Type: "",
			Licenses: []license{{PkgName: "github.com/riverqueue/river", Name: "MPL-2.0", Category: "reciprocal"}},
		},
	}

	inventory, ecosystemFor, directnessFor := indexInventory(results)

	if got := ecosystemFor["go.mod"]; got != "gomod" {
		t.Errorf("ecosystem for go.mod = %q, want gomod from the lang-pkgs result", got)
	}
	p := licensePackage(ecosystemFor["go.mod"], "github.com/riverqueue/river", inventory["go.mod"], directnessFor["go.mod"])
	if p.Version != "v0.46.0" {
		t.Errorf("version = %q, want the inventory's v0.46.0", p.Version)
	}
	if !p.Direct {
		t.Error("a direct dependency's licence finding reports direct=false")
	}
	if p.Ecosystem != "gomod" {
		t.Errorf("ecosystem = %q, want gomod", p.Ecosystem)
	}
}

// A licence on something the inventory does not list -- the project's own
// package.json declaring UNLICENSED, for instance -- still produces a usable
// finding rather than nothing.
func TestALicenceOnAnUnlistedPackageKeepsItsName(t *testing.T) {
	p := licensePackage("yarn", "my-own-app", map[string]pkgEntry{}, directnessUnknown)
	if p == nil || p.Name != "my-own-app" || p.Ecosystem != "yarn" {
		t.Errorf("lost the package: %+v", p)
	}
	if p.Version != "" || p.Direct {
		t.Errorf("invented facts for a package not in the inventory: %+v", p)
	}
}

// Where a name appears twice, the direct entry is the one a reader is deciding
// about -- and the order Trivy happens to list them in must not decide it.
func TestDirectWinsANameCollisionInEitherOrder(t *testing.T) {
	direct := pkgEntry{Name: "dup", Version: "2.0.0", Relationship: "direct"}
	indirect := pkgEntry{Name: "dup", Version: "1.0.0", Relationship: "indirect", Indirect: true}

	for _, order := range [][]pkgEntry{{direct, indirect}, {indirect, direct}} {
		inventory, _, _ := indexInventory([]result{{Target: "t", Type: "yarn", Packages: order}})
		if got := inventory["t"]["dup"]; got.Version != "2.0.0" {
			t.Errorf("picked %s; the direct entry should win regardless of order", got.Version)
		}
	}
}

// Which field classifies a package is a property of the target, not a constant.
// Trivy populates Relationship for Go modules, Indirect for some ecosystems,
// and neither for yarn -- every package in a yarn.lock arrives with an empty
// Relationship and Indirect false. Reading that as direct declared all 547
// packages in one lockfile to be direct dependencies of a project that names
// sixteen.
func TestDirectnessIsDecidedPerTarget(t *testing.T) {
	gomod := []pkgEntry{
		{Name: "a", Relationship: "root"},
		{Name: "b", Relationship: "direct"},
		{Name: "c", Relationship: "indirect", Indirect: true},
	}
	if got := directnessOf(gomod); got != byRelationship {
		t.Errorf("directnessOf(gomod) = %v, want byRelationship", got)
	}
	if !isDirect(gomod[1], byRelationship) || isDirect(gomod[2], byRelationship) {
		t.Error("Relationship was not read correctly")
	}
	// root is the project itself, which is as direct as a dependency gets.
	if !isDirect(gomod[0], byRelationship) {
		t.Error("the root package was not read as direct")
	}

	olderEcosystem := []pkgEntry{{Name: "a"}, {Name: "b", Indirect: true}}
	if got := directnessOf(olderEcosystem); got != byIndirect {
		t.Errorf("directnessOf = %v, want byIndirect where only Indirect is populated", got)
	}
	if !isDirect(olderEcosystem[0], byIndirect) || isDirect(olderEcosystem[1], byIndirect) {
		t.Error("Indirect was not read correctly")
	}
}

// The case that matters: a target where Trivy classifies nothing must not have
// every package declared direct. False here means unestablished, not indirect.
func TestYarnClassifiesNothingSoNothingIsClaimed(t *testing.T) {
	yarn := []pkgEntry{
		{Name: "react", Version: "19.2.8"},
		{Name: "lightningcss", Version: "1.32.0"},
		{Name: "isexe", Version: "2.0.0"},
	}
	if got := directnessOf(yarn); got != directnessUnknown {
		t.Fatalf("directnessOf(yarn) = %v, want directnessUnknown", got)
	}
	for _, p := range yarn {
		if isDirect(p, directnessUnknown) {
			t.Errorf("%s was reported direct on a target that classifies nothing", p.Name)
		}
	}
}
