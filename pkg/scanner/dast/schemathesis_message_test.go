package dast

import (
	"context"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// The message has to distinguish "you did not configure this" from "you
// configured it with one entry", because they need different actions and the
// second is the easy mistake: zap takes a single URL, so the same shape reads
// as complete here and the engine silently skips.
func TestSchemathesisSaysWhatIsActuallyMissing(t *testing.T) {
	target := func(rules ...string) scanner.Target {
		return scanner.Target{Config: &config.Config{
			Engines: map[string]config.EngineConfig{"schemathesis": {Rules: rules}},
		}}
	}

	cases := []struct {
		name  string
		rules []string
		want  string
	}{
		{"nothing configured", nil, "no schema/base URL configured"},
		{"one entry, the common mistake", []string{"https://api.example.com"}, "needs two entries"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := NewSchemathesis().Available(context.Background(), target(c.rules...))
			if ok {
				t.Fatal("expected the engine to report itself unavailable")
			}
			if !strings.Contains(reason, c.want) {
				t.Errorf("reason = %q, want it to contain %q", reason, c.want)
			}
		})
	}

	// And the one-entry case must not claim nothing is configured.
	_, reason := NewSchemathesis().Available(context.Background(), target("https://api.example.com"))
	if strings.Contains(reason, "no schema/base URL configured") {
		t.Errorf("reason = %q; it tells somebody who configured the setting that they did not", reason)
	}
}
