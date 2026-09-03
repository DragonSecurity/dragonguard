package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

func renderOne(t *testing.T, f finding.Finding) string {
	t.Helper()
	var buf bytes.Buffer
	err := Text(&buf, &Result{
		Scorecard: &scorecard.Scorecard{},
		Findings:  []finding.Finding{f},
	}, Options{})
	if err != nil {
		t.Fatalf("Text: %v", err)
	}
	return buf.String()
}

// A suppression comment names a rule id, and the id was nowhere in the output.
//
// Reported as OpenGrep ignoring "// nosemgrep: ...". It was not: the comment
// named an upstream registry rule whose message looks similar, and a
// rule-scoped comment only suppresses the rule it names. The guess was wrong
// because the only identifier on screen was the human-readable title, and a
// wrong id suppresses nothing while looking like the engine ignored it.
func TestRuleIDIsShownWhereItIsNeededToSuppress(t *testing.T) {
	out := renderOne(t, finding.Finding{
		Category:   finding.CategorySAST,
		RuleID:     "go.dragon-go-sql-string-concat",
		Title:      "SQL query assembled by concatenation or Sprintf",
		RiskScore:  85,
		RiskRating: "high",
		Location:   finding.Location{File: "internal/jobs/x.go", StartLine: 83},
	})
	if !strings.Contains(out, "go.dragon-go-sql-string-concat") {
		t.Errorf("the rule id is absent, so a suppression cannot be written:\n%s", out)
	}
}

// A CVE already identifies a dependency finding, and nobody suppresses one by
// rule id. Repeating the identifier beside itself is noise.
func TestRuleIDIsNotRepeatedOnDependencyFindings(t *testing.T) {
	out := renderOne(t, finding.Finding{
		Category:   finding.CategorySCA,
		RuleID:     "CVE-2026-39408",
		Title:      "Hono: path traversal in toSSG()",
		RiskScore:  60,
		RiskRating: "medium",
		CVE:        []string{"CVE-2026-39408"},
		Location:   finding.Location{File: "ui/yarn.lock"},
	})
	if strings.Count(out, "CVE-2026-39408") != 1 {
		t.Errorf("the identifier appears twice on a dependency finding:\n%s", out)
	}
}
