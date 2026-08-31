package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

// A clean scan is the outcome most worth publishing, and it was the one that
// produced invalid SARIF: a nil slice marshals to null, and the schema
// requires an array. GitHub rejected the upload with
// "instance.runs[0].results is not of a type(s) array".
func TestSARIFAlwaysEmitsArraysNotNull(t *testing.T) {
	cases := map[string]*Result{
		"clean scan": {
			Scorecard: &scorecard.Scorecard{Dimensions: map[string]scorecard.Dimension{}},
			Findings:  nil,
		},
		"only suppressed findings": {
			Scorecard: &scorecard.Scorecard{Dimensions: map[string]scorecard.Dimension{}},
			Findings: []finding.Finding{{
				RuleID: "x", Status: finding.StatusAccepted,
				Category: finding.CategorySAST,
			}},
		},
	}

	for name, res := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := SARIF(&buf, res); err != nil {
				t.Fatal(err)
			}
			// The literal JSON matters: "null" is what GitHub rejects.
			if strings.Contains(buf.String(), `"results": null`) {
				t.Error(`SARIF emitted "results": null, which fails schema validation`)
			}

			var doc map[string]any
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			runs, _ := doc["runs"].([]any)
			if len(runs) != 1 {
				t.Fatalf("runs = %v", doc["runs"])
			}
			run := runs[0].(map[string]any)

			if _, ok := run["results"].([]any); !ok {
				t.Errorf("results is %T, must be an array", run["results"])
			}
			driver := run["tool"].(map[string]any)["driver"].(map[string]any)
			if _, ok := driver["rules"].([]any); !ok {
				t.Errorf("rules is %T, must be an array", driver["rules"])
			}
		})
	}
}

// A scan with findings still produces well-formed SARIF.
func TestSARIFWithFindings(t *testing.T) {
	res := &Result{
		Scorecard: &scorecard.Scorecard{Dimensions: map[string]scorecard.Dimension{}},
		Findings: []finding.Finding{{
			RuleID: "go.dragon-go-sql", Title: "SQL by concatenation",
			Category: finding.CategorySAST, RiskScore: 83, RiskRating: "high",
			Location: finding.Location{File: "db.go", StartLine: 12, EndLine: 12},
			Status:   finding.StatusOpen,
		}},
	}
	var buf bytes.Buffer
	if err := SARIF(&buf, res); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %v", results)
	}
	r := results[0].(map[string]any)
	if r["level"] != "error" {
		t.Errorf("level = %v, want error for a high finding", r["level"])
	}
	// Dragon Risk rides in security-severity, not the three-value level.
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rule := driver["rules"].([]any)[0].(map[string]any)
	props := rule["properties"].(map[string]any)
	if props["security-severity"] != "8.3" {
		t.Errorf("security-severity = %v, want 8.3 (risk 83 / 10)", props["security-severity"])
	}
}
