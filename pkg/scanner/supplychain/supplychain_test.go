package supplychain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/depsdev"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// The root entry of a lockfile is the project being scanned, not a dependency.
// It is direct in every sense, which is exactly why it needs excluding: asking
// a public registry about a workspace called "ui" returns a stranger's package
// of the same name, and the finding would be about their project attributed to
// this one.
func TestTheProjectItselfIsNotADependency(t *testing.T) {
	got := directOf([]scanner.PackageNode{
		{Name: "ui", Version: "0.0.0", Direct: true, Root: true},
		{Name: "clsx", Version: "2.1.1", Direct: true},
		{Name: "deep", Version: "1.0.0"},
	})
	if len(got) != 1 || got[0].Name != "clsx" {
		t.Errorf("directOf = %+v, want only the direct dependency", got)
	}
}

// Transitive dependencies are excluded because nobody can act on them: you did
// not choose the package five levels down and cannot replace it.
func TestOnlyDirectDependenciesAreAssessed(t *testing.T) {
	got := directOf([]scanner.PackageNode{
		{Name: "a", Direct: true},
		{Name: "b", Direct: false},
	})
	if len(got) != 1 || got[0].Name != "a" {
		t.Errorf("directOf = %+v, want only a", got)
	}
}

// Unavailable rather than empty, and with the reason. An engine that silently
// finds nothing is indistinguishable from one that could not look, which is
// the distinction the whole evidence table exists to preserve.
func TestUnavailableSaysWhy(t *testing.T) {
	s := New()
	cases := []struct {
		name   string
		target scanner.Target
		want   string
	}{
		{
			name:   "offline",
			target: scanner.Target{Config: &config.Config{Offline: true}, Components: []scanner.PackageNode{{Name: "a", Direct: true}}},
			want:   "offline",
		},
		{
			name:   "first pass, nothing resolved yet",
			target: scanner.Target{},
			want:   "no resolved components",
		},
		{
			name: "nothing established as direct",
			target: scanner.Target{Components: []scanner.PackageNode{
				{Name: "a"}, {Name: "b"},
			}},
			want: "direct",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := s.Available(context.Background(), tc.target)
			if ok {
				t.Fatal("reported available")
			}
			if !strings.Contains(reason, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
}

// A publisher marking a version deprecated is an unambiguous statement that it
// will not be fixed. It is the one signal here that gates.
func TestDeprecationIsReportedAndGates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/versions/") {
			_, _ = w.Write([]byte(`{"isDeprecated": true, "relatedProjects": []}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := &Scanner{Client: &depsdev.Client{BaseURL: srv.URL, HTTP: srv.Client(), Concurrency: 2}, Concurrency: 2}
	got, err := s.Scan(context.Background(), scanner.Target{
		Components: []scanner.PackageNode{{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Direct: true}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want the deprecation: %+v", len(got), got)
	}
	if got[0].RuleID != "supply-chain/deprecated" {
		t.Errorf("rule = %q", got[0].RuleID)
	}
	// Info would not gate, and a dependency the publisher has abandoned is a
	// decision the project has to make rather than a note to skim.
	if got[0].Severity != finding.SeverityHigh {
		t.Errorf("severity = %q, want high so it reaches the gate", got[0].Severity)
	}
}

// A healthy dependency produces nothing. Worth asserting, because an engine
// whose floor is "always says something" fills a dimension with noise and
// teaches people to skip it -- and the deprecation notice goes with it.
func TestAHealthyDependencyProducesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/versions/") {
			_, _ = w.Write([]byte(`{"isDeprecated": false, "relatedProjects": []}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := &Scanner{Client: &depsdev.Client{BaseURL: srv.URL, HTTP: srv.Client(), Concurrency: 2}, Concurrency: 2}
	got, err := s.Scan(context.Background(), scanner.Target{
		Components: []scanner.PackageNode{{Ecosystem: "npm", Name: "react", Version: "19.0.0", Direct: true}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings for a healthy dependency: %+v", len(got), got)
	}
}

// An ecosystem deps.dev does not serve is not a finding. Querying the wrong
// system returns a confident answer about the wrong package.
func TestAnUnknownEcosystemIsSkippedRatherThanGuessed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("deps.dev was queried for an ecosystem it does not serve")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := &Scanner{Client: &depsdev.Client{BaseURL: srv.URL, HTTP: srv.Client()}, Concurrency: 1}
	got, err := s.Scan(context.Background(), scanner.Target{
		Components: []scanner.PackageNode{{Ecosystem: "conan", Name: "zlib", Version: "1.3", Direct: true}},
	})
	if err != nil || len(got) != 0 {
		t.Errorf("got %d findings, err=%v", len(got), err)
	}
}

// weakest names the checks dragging a score down, so a reader can tell
// "nobody has touched this in three years" from "this two-hundred-byte utility
// does not run a fuzzer".
func TestWeakestNamesTheFailingChecks(t *testing.T) {
	card := &depsdev.Scorecard{
		OverallScore: 3,
		Checks: []depsdev.ScorecardCheck{
			{Name: "Fuzzing", Score: 0},
			{Name: "Branch-Protection", Score: 1},
			{Name: "Vulnerabilities", Score: 10},
		},
	}
	got := weakest(card)
	if !strings.Contains(got, "Fuzzing") || !strings.Contains(got, "Branch-Protection") {
		t.Errorf("weakest = %q, want the failing checks", got)
	}
	if strings.Contains(got, "Vulnerabilities") {
		t.Errorf("weakest = %q, named a check that passed", got)
	}
}

// The two process conditions overlap by construction -- quiet needs an overall
// below five, weak needs below four -- so anything under four produced both,
// and the report carried "otp has been quiet and scores 2.9/10" directly above
// "otp scores 2.9/10 on OpenSSF Scorecard". Two rows, one fact, and a reader
// counting rows concludes there are twice as many problems as there are.
func TestOneFindingPerDependencyNotOnePerRule(t *testing.T) {
	srv := scorecardServer(t, `{"overallScore": 2.9, "checks": [
		{"name": "Maintained", "score": 0},
		{"name": "Fuzzing", "score": 0}
	]}`)
	defer srv.Close()

	s := &Scanner{Client: &depsdev.Client{BaseURL: srv.URL, HTTP: srv.Client()}, Concurrency: 1}
	got, err := s.Scan(context.Background(), scanner.Target{
		Components: []scanner.PackageNode{{Ecosystem: "go", Name: "github.com/pquerna/otp", Version: "v1.5.0", Direct: true}},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		for _, f := range got {
			t.Logf("  %s: %s", f.RuleID, f.Title)
		}
		t.Fatalf("got %d findings for one dependency, want 1", len(got))
	}
	// Quiet and weak at once: the silence belongs in the same finding rather
	// than in a second one.
	if !strings.Contains(got[0].Title, "quiet") {
		t.Errorf("the finding does not mention the inactivity: %q", got[0].Title)
	}
	if !strings.Contains(got[0].Message, "Fuzzing") {
		t.Errorf("the finding does not name the failing checks: %q", got[0].Message)
	}
}

// Weak but actively developed is still worth recording, and must not claim the
// project has gone quiet when it has not.
func TestAWeakButActiveProjectIsNotCalledQuiet(t *testing.T) {
	srv := scorecardServer(t, `{"overallScore": 3.4, "checks": [
		{"name": "Maintained", "score": 10},
		{"name": "Branch-Protection", "score": 0}
	]}`)
	defer srv.Close()

	s := &Scanner{Client: &depsdev.Client{BaseURL: srv.URL, HTTP: srv.Client()}, Concurrency: 1}
	got, _ := s.Scan(context.Background(), scanner.Target{
		Components: []scanner.PackageNode{{Ecosystem: "go", Name: "github.com/go-chi/cors", Version: "v1.2.2", Direct: true}},
	})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if strings.Contains(got[0].Title, "quiet") || strings.Contains(got[0].Message, "No recent commits") {
		t.Errorf("an actively developed project was described as quiet: %q", got[0].Title)
	}
}

// scorecardServer fakes the deps.dev calls ScorecardFor makes: the version
// lookup that resolves a source repo, then the project holding the scorecard.
func scorecardServer(t *testing.T, scorecard string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/versions/"):
			_, _ = w.Write([]byte(`{"isDeprecated": false, "relatedProjects": [
				{"projectKey": {"id": "github.com/example/pkg"}, "relationType": "SOURCE_REPO"}
			]}`))
		case strings.Contains(r.URL.Path, "/projects/"):
			_, _ = w.Write([]byte(`{"scorecard": ` + scorecard + `}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// The defaults are a judgement about a whole ecosystem; a project that knows
// its own tree should be able to move the line without turning the engine off,
// which was the only control it had.
func TestThresholdsFallBackToTheDefaultsAndAreOverridable(t *testing.T) {
	weak, quiet := thresholds(nil)
	if weak != lowScorecard || quiet != quietAndWeak {
		t.Errorf("thresholds(nil) = %.1f/%.1f, want the defaults", weak, quiet)
	}

	// An empty block is a block nobody filled in, not a request for silence.
	weak, quiet = thresholds(&config.Config{})
	if weak != lowScorecard || quiet != quietAndWeak {
		t.Errorf("an unset supply_chain block changed the thresholds to %.1f/%.1f", weak, quiet)
	}

	weak, quiet = thresholds(&config.Config{
		SupplyChain: config.SupplyChainPolicy{MinScorecard: 2.5, QuietBelow: 3.5},
	})
	if weak != 2.5 || quiet != 3.5 {
		t.Errorf("thresholds = %.1f/%.1f, want the configured pair", weak, quiet)
	}
}
