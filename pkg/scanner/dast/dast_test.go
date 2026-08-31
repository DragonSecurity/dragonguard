package dast

import (
	"context"
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
	report := `{"results":[{"method":"GET","path":"/users/{id}","checks":[
	  {"name":"not_a_server_error","value":"failure","message":"Received 500"},
	  {"name":"status_code_conformance","value":"success","message":""},
	  {"name":"response_schema_conformance","value":"failure","message":"missing field"}
	]}]}`

	got, err := parseSchemathesisReport([]byte(report), "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (a passing check is not a finding)", len(got))
	}
	// A 500 on schema-valid input outranks a contract mismatch.
	if got[0].Severity != finding.SeverityHigh {
		t.Errorf("server error severity = %s, want high", got[0].Severity)
	}
	if got[1].Severity != finding.SeverityLow {
		t.Errorf("schema conformance severity = %s, want low", got[1].Severity)
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
