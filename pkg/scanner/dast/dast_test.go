package dast

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// DAST sends real traffic. A target must never be inferred, or a misconfigured
// scan becomes an unauthorized penetration test of somebody else's system.
func TestDASTRefusesToRunWithoutAnExplicitTarget(t *testing.T) {
	cfg := config.Default()

	if _, err := NewZAP().Scan(context.Background(), scanner.Target{Dir: t.TempDir(), Config: cfg}); err == nil {
		t.Error("ZAP must refuse to scan when no target is configured")
	}
	if _, err := NewSchemathesis().Scan(context.Background(), scanner.Target{Dir: t.TempDir(), Config: cfg}); err == nil {
		t.Error("Schemathesis must refuse to scan when no schema and base URL are configured")
	}
}

func TestTargetValidationRejectsUnsafeTargets(t *testing.T) {
	bad := []string{"", "example.com", "/local/path", "file:///etc/passwd", "ftp://x", "javascript:alert(1)", "http://"}
	for _, b := range bad {
		if err := validateTarget(b); err == nil {
			t.Errorf("validateTarget(%q) accepted an unsafe target", b)
		}
	}
	for _, good := range []string{"http://localhost:8080", "https://api.example.com/v1"} {
		if err := validateTarget(good); err != nil {
			t.Errorf("validateTarget(%q) = %v", good, err)
		}
	}
}

func TestZAPReportBecomesFindings(t *testing.T) {
	report := `{"site":[{"@name":"https://app.example.com","alerts":[
	  {"pluginid":"40018","alert":"SQL Injection","riskcode":"3","confidence":"2",
	   "desc":"<p>SQL injection may be possible.</p>","solution":"<p>Use parameterised queries.</p>",
	   "cweid":"89","reference":"<p>https://owasp.org/sqli</p>",
	   "instances":[{"uri":"https://app.example.com/users?id=1","method":"GET","param":"id","evidence":"syntax error"}]},
	  {"pluginid":"10021","alert":"X-Content-Type-Options Missing","riskcode":"1","cweid":"693","instances":[]}
	]}]}`

	got, err := parseZAPReport([]byte(report), "https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}

	sqli := got[0]
	checks := []struct {
		name      string
		got, want any
	}{
		{"category", sqli.Category, finding.CategoryDAST},
		{"severity", sqli.Severity, finding.SeverityHigh},
		{"reachability", sqli.Analysis.Reachability, "reachable"},
		{"title", sqli.Title, "SQL Injection"},
		{"location", sqli.Location.File, "https://app.example.com/users?id=1"},
		{"fix available", sqli.Analysis.FixAvailable, true},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if len(sqli.CWE) != 1 || sqli.CWE[0] != "CWE-89" {
		t.Errorf("CWE = %v, want [CWE-89]", sqli.CWE)
	}
	// ZAP wraps its prose in markup; a terminal report must not print tags.
	if strings.Contains(sqli.Message, "<p>") {
		t.Errorf("HTML survived into the message: %q", sqli.Message)
	}
	if sqli.Message != "SQL injection may be possible." {
		t.Errorf("message = %q", sqli.Message)
	}
}

// ZAP's riskcode 0 is informational, not "safe".
func TestZAPSeverityMapping(t *testing.T) {
	cases := map[string]finding.Severity{
		"3": finding.SeverityHigh, "2": finding.SeverityMedium,
		"1": finding.SeverityLow, "0": finding.SeverityInfo, "": finding.SeverityInfo,
	}
	for code, want := range cases {
		if got := zapSeverity(code); got != want {
			t.Errorf("zapSeverity(%q) = %s, want %s", code, got, want)
		}
	}
}

func TestSchemathesisOnlyReportsFailures(t *testing.T) {
	// Schemathesis 4's NDJSON: one event per line, results only in
	// ScenarioFinished, checks keyed by case ID.
	report := `{"EngineStarted":{}}
{"ScenarioFinished":{"status":"failure","recorder":{"label":"GET /users/{id}","checks":{"c1":[{"name":"not_a_server_error","status":"failure","failure_info":{"failure":{"type":"ServerError","operation":"GET /users/{id}","title":"Server error","message":"Received 500","severity":"critical"}}},{"name":"status_code_conformance","status":"success"},{"name":"response_schema_conformance","status":"failure","failure_info":{"failure":{"type":"SchemaMismatch","operation":"GET /users/{id}","title":"Schema mismatch","message":"missing field","severity":"low"}}}]},"interactions":{"c1":{"request":{"method":"GET","uri":"https://api.example.com/users/1"},"response":{"status_code":500}}}}}}
{"EngineFinished":{}}`

	got, err := parseSchemathesisReport([]byte(report), "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (a passing check is not a finding)", len(got))
	}

	bySeverity := map[finding.Severity]finding.Finding{}
	for _, f := range got {
		bySeverity[f.Severity] = f
	}
	// Schemathesis rates its own failures; "critical" must not be flattened
	// to the name-based table's "high".
	crit, ok := bySeverity[finding.SeverityCritical]
	if !ok {
		t.Fatalf("the reported critical severity was not used: %+v", got)
	}
	if crit.Location.File != "https://api.example.com/users/1" {
		t.Errorf("location = %q, want the URI actually requested", crit.Location.File)
	}
	if crit.Metadata["status_code"] != 500 {
		t.Errorf("status_code = %v, want 500", crit.Metadata["status_code"])
	}
	if _, ok := bySeverity[finding.SeverityLow]; !ok {
		t.Errorf("a schema mismatch should stay low: %+v", got)
	}
}

// The same check fails across every generated case, so findings are collapsed
// and the repetitions counted. Without this a single server error arrives as
// a hundred copies of itself and buries everything else.
func TestSchemathesisCollapsesRepeatedFailures(t *testing.T) {
	line := func(caseID string) string {
		return `{"ScenarioFinished":{"status":"failure","recorder":{"label":"GET /boom","checks":{"` + caseID + `":[` +
			`{"name":"not_a_server_error","status":"failure","failure_info":{"failure":{"type":"ServerError","operation":"GET /boom","title":"Server error","message":"","severity":"critical"}}}` +
			`]},"interactions":{"` + caseID + `":{"request":{"method":"GET","uri":"https://api.example.com/boom"},"response":{"status_code":500}}}}}}`
	}
	got, err := parseSchemathesisReport([]byte(line("a")+"\n"+line("b")+"\n"+line("c")), "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 collapsed finding", len(got))
	}
	if got[0].Metadata["occurrences"] != 3 {
		t.Errorf("occurrences = %v, want 3", got[0].Metadata["occurrences"])
	}
}

// A report captured from a real schemathesis 4 run against a deliberately
// broken endpoint. Hand-written fixtures encode what I believed the format
// to be; this one encodes what it is.
func TestSchemathesisParsesARealReport(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "schemathesis-v4.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseSchemathesisReport(data, "http://host.docker.internal:8731")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("no findings parsed from a run that reported 4 failures")
	}
	var sawServerError bool
	for _, f := range got {
		if f.Scanner != "schemathesis" || f.Category != finding.CategoryDAST {
			t.Errorf("wrong scanner/category: %+v", f)
		}
		if f.Title == "" {
			t.Errorf("finding with no title: %+v", f)
		}
		if !f.Analysis.Reachable {
			t.Error("a DAST finding was produced by reaching the endpoint; it is reachable by definition")
		}
		if f.Metadata["check"] == "not_a_server_error" {
			sawServerError = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("server error severity = %s, want the reported critical", f.Severity)
			}
		}
	}
	if !sawServerError {
		t.Errorf("the 500 was not reported; got %d findings", len(got))
	}
}

func TestStripHTML(t *testing.T) {
	cases := map[string]string{
		"<p>Hello <b>world</b></p>": "Hello world",
		"plain":                     "plain",
		"":                          "",
		"<p>a</p>\n<p>b</p>":        "a b",
	}
	for in, want := range cases {
		if got := stripHTML(in); got != want {
			t.Errorf("stripHTML(%q) = %q, want %q", in, got, want)
		}
	}
}
