package osv

import (
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// OSV-Scanner v1 and v2 have incompatible command lines: v2 introduced the
// "source" subcommand and renamed --output to --output-file. A v2-shaped
// command run against v1 treats "source" as a directory and fails with a
// confusing message about being unable to stat it -- which is exactly what
// happened on a machine that had v1 installed.
func TestVersionRegexReadsBothGenerations(t *testing.T) {
	cases := map[string]int{
		"osv-scanner version: 2.5.1\nosv-scalibr version: 0.5.2\n": 2,
		"osv-scanner version: 1.9.2\ncommit: n/a\n":                1,
		"osv-scanner version: 10.0.0\n":                            10,
	}
	for out, want := range cases {
		m := versionRe.FindStringSubmatch(out)
		if len(m) < 2 {
			t.Errorf("no version parsed from %q", out)
			continue
		}
		got := m[1]
		if want >= 10 && got != "10" {
			t.Errorf("parsed %q, want 10", got)
		}
		if want < 10 && got != string(rune('0'+want)) {
			t.Errorf("parsed %q, want %d", got, want)
		}
	}
}

func TestVersionRegexIgnoresUnrelatedOutput(t *testing.T) {
	if versionRe.MatchString("some other tool v3.1") {
		t.Error("version regex matched unrelated output")
	}
}

// Only real CVE identifiers may reach enrichment: EPSS and KEV cannot be
// looked up by GHSA or GO- identifiers.
func TestOnlyCVEAliasesAreKept(t *testing.T) {
	got := cveAliases("GO-2021-0061", []string{"GHSA-r88r-gmrh-7j83", "CVE-2021-4235"}, nil)
	if len(got) != 1 || got[0] != "CVE-2021-4235" {
		t.Errorf("cveAliases = %v, want [CVE-2021-4235]", got)
	}

	// A group's aliases can name a CVE the advisory itself omits.
	g := &group{Aliases: []string{"CVE-2020-8203"}}
	got = cveAliases("GHSA-xxxx", nil, g)
	if len(got) != 1 || got[0] != "CVE-2020-8203" {
		t.Errorf("cveAliases from group = %v, want [CVE-2020-8203]", got)
	}
}

// "Call analysis found no path" and "call analysis did not run" are different
// conclusions. Collapsing them would either discard the signal or invent it.
func TestReachabilityOnlyClaimedWhenAnalysisRan(t *testing.T) {
	pkg := pkgResult{
		Groups: []group{{
			IDs: []string{"GO-2021-0061"},
			ExperimentalAnalysis: map[string]struct {
				Called      bool `json:"called"`
				Unimportant bool `json:"unimportant"`
			}{"GO-2021-0061": {Called: false}},
		}},
		Vulnerabilities: []vulnerability{{ID: "GO-2021-0061", Summary: "x"}},
	}
	pkg.Package.Name = "gopkg.in/yaml.v2"
	pkg.Package.Version = "2.2.2"
	pkg.Package.Ecosystem = "Go"

	s := New()

	// Analysis ran for Go: "not called" is a real unreachable verdict.
	got := s.fromPackage(pkg, "go.mod", map[string]bool{"go": true})
	if len(got) != 1 || got[0].Analysis.Reachability != "unreachable" {
		t.Errorf("reachability = %q, want unreachable", got[0].Analysis.Reachability)
	}

	// Analysis did not run: absence of a result must read as unknown, never
	// as proof of safety.
	got = s.fromPackage(pkg, "go.mod", nil)
	if len(got) != 1 || got[0].Analysis.Reachability != "unknown" {
		t.Errorf("reachability = %q, want unknown when call analysis did not run", got[0].Analysis.Reachability)
	}
}

func TestCalledMeansReachable(t *testing.T) {
	pkg := pkgResult{
		Groups: []group{{
			IDs: []string{"GO-1"},
			ExperimentalAnalysis: map[string]struct {
				Called      bool `json:"called"`
				Unimportant bool `json:"unimportant"`
			}{"GO-1": {Called: true}},
		}},
		Vulnerabilities: []vulnerability{{ID: "GO-1"}},
	}
	pkg.Package.Ecosystem = "Go"

	got := New().fromPackage(pkg, "go.mod", map[string]bool{"go": true})
	if got[0].Analysis.Reachability != "reachable" || !got[0].Analysis.Reachable {
		t.Errorf("a called vulnerability must be reachable, got %q", got[0].Analysis.Reachability)
	}
	if got[0].Category != finding.CategorySCA {
		t.Errorf("category = %s", got[0].Category)
	}
}

// The earliest fixed version is the smallest upgrade that clears the advisory,
// which is more useful than "upgrade to latest".
func TestEarliestFixIsChosen(t *testing.T) {
	v := vulnerability{}
	v.Affected = []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	}{{}}
	v.Affected[0].Package.Name = "lodash"
	v.Affected[0].Ranges = append(v.Affected[0].Ranges, struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
		} `json:"events"`
	}{Events: []struct {
		Introduced string `json:"introduced"`
		Fixed      string `json:"fixed"`
	}{{Introduced: "0"}, {Fixed: "4.17.12"}, {Fixed: "4.17.21"}}})

	if got := earliestFix(v, "lodash"); got != "4.17.12" {
		t.Errorf("earliestFix = %q, want the smallest upgrade 4.17.12", got)
	}
}

// A project with no lockfiles is a legitimate outcome, not an engine failure.
func TestNoPackageSourcesIsNotAnError(t *testing.T) {
	if !noSources("No package sources found, --help for usage information.") {
		t.Error("the empty-project message should be recognised")
	}
	if noSources("some genuine failure") {
		t.Error("a real failure must not be treated as an empty project")
	}
}
