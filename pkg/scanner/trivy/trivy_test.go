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
