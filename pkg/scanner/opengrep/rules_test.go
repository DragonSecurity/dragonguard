package opengrep

import (
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/ingest/sarif"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// engines.opengrep.rules replaces the default rather than extending it. A
// project that names its rules has said which rules it wants, and quietly
// adding ours would make the configured list a suggestion.
func TestConfiguredRulesReplaceTheDefault(t *testing.T) {
	s := New()
	got := s.RulesFor(scanner.Target{
		Dir: t.TempDir(),
		Config: &config.Config{
			Engines: map[string]config.EngineConfig{
				"opengrep": {Rules: []string{"p/security-audit"}},
			},
		},
	})
	if len(got) != 1 || got[0] != "p/security-audit" {
		t.Errorf("RulesFor = %v, want exactly the configured pack", got)
	}
}

// With nothing configured the built-in pack runs, which is the right default
// and the surprising one to discover by comparing a hand run of the engine
// against a scan. It is named rather than printed as the temporary directory
// it was extracted to, which tells a reader nothing.
func TestTheBuiltInPackSaysWhatItIs(t *testing.T) {
	s := New()
	got := s.RulesFor(scanner.Target{Dir: t.TempDir(), Config: &config.Config{}})
	if len(got) != 1 {
		t.Fatalf("RulesFor = %v, want one source", got)
	}
	if !strings.Contains(got[0], "built-in pack") {
		t.Errorf("RulesFor = %q, want it named rather than a temp path", got[0])
	}
	if strings.Contains(got[0], "/var/folders") || strings.Contains(got[0], "/tmp/") {
		t.Errorf("RulesFor leaked an extraction path: %q", got[0])
	}
}

// "the built-in rules plus a registry pack" was not expressible: rules only
// ever replaced, and the embedded pack has no stable path to name because it
// is extracted to a temporary directory at scan time.
func TestBuiltinCanBeCombinedWithAnotherPack(t *testing.T) {
	s := New()
	got := s.RulesFor(scanner.Target{
		Dir: t.TempDir(),
		Config: &config.Config{
			Engines: map[string]config.EngineConfig{
				"opengrep": {Rules: []string{BuiltinRules, "p/security-audit"}},
			},
		},
	})
	if len(got) != 2 {
		t.Fatalf("RulesFor = %v, want both sources", got)
	}
	if !strings.Contains(got[0], "built-in pack") {
		t.Errorf("first source = %q, want the built-in pack named", got[0])
	}
	if got[1] != "p/security-audit" {
		t.Errorf("second source = %q, want the configured pack", got[1])
	}
}

// The order a project writes is the order the engine gets, because opengrep
// applies configs in order and a reader comparing the two should not have to
// wonder whether we shuffled them.
func TestConfiguredOrderIsPreserved(t *testing.T) {
	s := New()
	got := s.RulesFor(scanner.Target{
		Dir: t.TempDir(),
		Config: &config.Config{
			Engines: map[string]config.EngineConfig{
				"opengrep": {Rules: []string{"p/security-audit", BuiltinRules}},
			},
		},
	})
	if len(got) != 2 || got[0] != "p/security-audit" || !strings.Contains(got[1], "built-in pack") {
		t.Errorf("RulesFor = %v, want the configured order kept", got)
	}
}

// The label has to be true in both directions. Saying "not set" when a project
// asked for the pack by name would be false, and the point of the line is that
// it can be trusted without checking the config.
func TestTheBuiltinLabelDoesNotClaimItWasUnconfigured(t *testing.T) {
	s := New()
	got := s.RulesFor(scanner.Target{
		Dir: t.TempDir(),
		Config: &config.Config{
			Engines: map[string]config.EngineConfig{
				"opengrep": {Rules: []string{BuiltinRules}},
			},
		},
	})
	if len(got) != 1 || !strings.Contains(got[0], "built-in pack") {
		t.Fatalf("RulesFor = %v", got)
	}
	if strings.Contains(got[0], "not set") {
		t.Errorf("label claims the rules were unconfigured when they name it: %q", got[0])
	}
}

// SARIF carries suppressed results rather than omitting them, marked with a
// suppressions array. Reading the file without checking that field reported
// every nosemgrep'd match anyway -- which looked exactly like the engine
// ignoring the comment, and is how it was reported.
func TestSuppressedResultsAreHonouredNotReported(t *testing.T) {
	log := &sarif.Log{Runs: []sarif.Run{{
		Results: []sarif.Result{
			{
				RuleID:       "go.sql",
				Message:      sarif.Message{Text: "silenced by a comment"},
				Suppressions: []sarif.Suppression{{Kind: "inSource"}},
				Locations:    []sarif.Location{loc("a.go", 12)},
			},
			{
				RuleID:    "go.sql",
				Message:   sarif.Message{Text: "not silenced"},
				Locations: []sarif.Location{loc("a.go", 51)},
			},
		},
	}}}

	s := New()
	got := s.fromSARIF(log, ".", nil)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want only the unsuppressed one", len(got))
	}
	if got[0].Location.StartLine != 51 {
		t.Errorf("kept the wrong result: line %d", got[0].Location.StartLine)
	}
	// Honoured, not hidden: a suppression nobody can see is indistinguishable
	// from a scanner that stopped looking.
	if n := s.SuppressedInLastScan(); n != 1 {
		t.Errorf("SuppressedInLastScan = %d, want 1", n)
	}
}

// The count is per parse, not cumulative, or a second scan in one process
// reports the first scan's suppressions again.
func TestTheSuppressionCountResetsEachParse(t *testing.T) {
	suppressed := &sarif.Log{Runs: []sarif.Run{{Results: []sarif.Result{{
		RuleID:       "go.sql",
		Suppressions: []sarif.Suppression{{Kind: "inSource"}},
		Locations:    []sarif.Location{loc("a.go", 1)},
	}}}}}
	clean := &sarif.Log{Runs: []sarif.Run{{Results: []sarif.Result{{
		RuleID:    "go.sql",
		Locations: []sarif.Location{loc("a.go", 1)},
	}}}}}

	s := New()
	s.fromSARIF(suppressed, ".", nil)
	s.fromSARIF(clean, ".", nil)
	if n := s.SuppressedInLastScan(); n != 0 {
		t.Errorf("SuppressedInLastScan = %d after a clean parse, want 0", n)
	}
}

func loc(file string, line int) sarif.Location {
	return sarif.Location{PhysicalLocation: &sarif.PhysicalLocation{
		ArtifactLocation: &sarif.ArtifactLocation{URI: file},
		Region:           &sarif.Region{StartLine: line, EndLine: line},
	}}
}
