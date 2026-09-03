package opengrep

import (
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
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
