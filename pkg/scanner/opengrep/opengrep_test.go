package opengrep

import (
	"path/filepath"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/ingest/sarif"
)

// OpenGrep encodes the config path into the rule ID, so the same rule has a
// different ID on a laptop and in CI. Left unnormalized, the fingerprint
// changes with it and the regression gate reports the whole backlog as new
// on its first CI run -- which is how a gate loses its audience.
func TestRuleIDIsStableAcrossCheckoutPaths(t *testing.T) {
	local := normalizeRuleID("Users.dev.work.myrepo.rules.go.dragon-go-sql", []string{"/Users/dev/work/myrepo/rules"})
	ci := normalizeRuleID("home.runner.work.myrepo.myrepo.rules.go.dragon-go-sql", []string{"/home/runner/work/myrepo/myrepo/rules"})

	if local != ci {
		t.Errorf("rule ID differs by checkout path: %q vs %q", local, ci)
	}
	if local != "go.dragon-go-sql" {
		t.Errorf("normalized ID = %q, want go.dragon-go-sql", local)
	}
}

// A dotted registry rule name is genuine identity, not a path prefix, and
// must survive intact.
func TestRegistryRuleIDsAreNotTrimmed(t *testing.T) {
	id := "javascript.lang.security.audit.sqli"
	if got := normalizeRuleID(id, []string{"p/security-audit"}); got != id {
		t.Errorf("registry rule ID was altered: %q -> %q", id, got)
	}
	if got := normalizeRuleID(id, []string{"/some/other/rules"}); got != id {
		t.Errorf("unrelated config path altered the rule ID: %q", got)
	}
}

func TestPathPrefixIgnoresNonPaths(t *testing.T) {
	for _, in := range []string{"p/security-audit", "r/all", "https://example.com/rules.yaml", ""} {
		if got := pathPrefixes(in); len(got) != 0 {
			t.Errorf("pathPrefixes(%q) = %v, want empty", in, got)
		}
	}
}

// The prefix OpenGrep emits depends on how the config path was written, so
// a relative config must normalize just as an absolute one does.
func TestRelativeConfigPathIsAlsoStripped(t *testing.T) {
	if got := normalizeRuleID("rules.go.dragon-go-sql", []string{"rules"}); got != "go.dragon-go-sql" {
		t.Errorf("normalized = %q, want go.dragon-go-sql", got)
	}
}

// OpenGrep's shortDescription is the literal "Opengrep Finding: <id>", which
// tells a developer nothing. The report has to show the real message.
func TestTitleFallsBackToTheRuleMessage(t *testing.T) {
	rule := &sarif.Rule{
		ShortDescription: &sarif.Message{Text: "Opengrep Finding: rules.go.dragon-go-command-injection"},
	}
	res := &sarif.Result{
		Message: sarif.Message{Text: "Shell command built from a variable. Use execFile instead."},
	}
	got := ruleTitle(rule, res, "go.dragon-go-command-injection", "")
	if got != "Shell command built from a variable" {
		t.Errorf("title = %q, want the first sentence of the real message", got)
	}
}

func TestTitleKeepsAMeaningfulShortDescription(t *testing.T) {
	rule := &sarif.Rule{ShortDescription: &sarif.Message{Text: "SQL injection via string concatenation"}}
	res := &sarif.Result{Message: sarif.Message{Text: "something else"}}
	if got := ruleTitle(rule, res, "x", ""); got != "SQL injection via string concatenation" {
		t.Errorf("a real shortDescription should be kept, got %q", got)
	}
}

func TestSARIFConversionProducesUsableFindings(t *testing.T) {
	log := &sarif.Log{Runs: []sarif.Run{{
		Tool: sarif.Tool{Driver: sarif.Driver{
			Name: "opengrep", SemanticVersion: "1.11.5",
			Rules: []sarif.Rule{{
				ID:               "rules.go.dragon-go-sql",
				ShortDescription: &sarif.Message{Text: "Opengrep Finding: rules.go.dragon-go-sql"},
				FullDescription:  &sarif.Message{Text: "SQL built by concatenation. Use parameters."},
				DefaultConfig:    &sarif.ReportingConfig{Level: "error"},
				Properties: &sarif.RuleProperties{
					Tags:             []string{"CWE-89", "security"},
					SecuritySeverity: "7.5",
				},
			}},
		}},
		Results: []sarif.Result{{
			RuleID:  "rules.go.dragon-go-sql",
			Level:   "error",
			Message: sarif.Message{Text: "SQL built by concatenation. Use parameters."},
			Locations: []sarif.Location{{
				PhysicalLocation: &sarif.PhysicalLocation{
					ArtifactLocation: &sarif.ArtifactLocation{URI: "/repo/db.go"},
					Region:           &sarif.Region{StartLine: 12, EndLine: 12},
				},
			}},
		}},
	}}}

	got := New().fromSARIF(log, "/repo", []string{"/repo/rules"})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"rule ID", f.RuleID, "go.dragon-go-sql"},
		{"category", f.Category, finding.CategorySAST},
		{"severity", f.Severity, finding.SeverityHigh},
		{"file", f.Location.File, "db.go"},
		{"line", f.Location.StartLine, 12},
		{"CVSS from security-severity", f.Threat.CVSS, 7.5},
		{"reachability", f.Analysis.Reachability, "reachable"},
		{"scanner version", f.ScannerVersion, "1.11.5"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if len(f.CWE) != 1 || f.CWE[0] != "CWE-89" {
		t.Errorf("CWE = %v, want [CWE-89]", f.CWE)
	}
}

func TestAbsolutePathsAreMadeRelativeToTheScanRoot(t *testing.T) {
	dir := filepath.FromSlash("/repo")
	if got := relativize(filepath.Join(dir, "pkg", "a.go"), dir); got != filepath.Join("pkg", "a.go") {
		t.Errorf("relativize = %q", got)
	}
	// A path outside the scan root must be left alone rather than turned
	// into a confusing ../.. chain.
	outside := filepath.FromSlash("/elsewhere/a.go")
	if got := relativize(outside, dir); got != outside {
		t.Errorf("path outside the root was rewritten to %q", got)
	}
}
