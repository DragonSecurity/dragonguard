package dast

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// Schemathesis property-tests an API against its own OpenAPI schema.
//
// It complements ZAP rather than overlapping it. ZAP probes for known attack
// patterns; Schemathesis derives cases from the contract and reports where the
// implementation disagrees with it -- a 500 on input the schema says is valid,
// a response that violates the declared shape. Those are the bugs that become
// vulnerabilities, found before anybody writes an exploit for them.
type Schemathesis struct {
	// Schema is the OpenAPI document URL or path. Required.
	Schema string
	// BaseURL is the running API to test against. Required.
	BaseURL string
}

func NewSchemathesis() *Schemathesis { return &Schemathesis{} }

func (s *Schemathesis) Name() string { return "schemathesis" }

func (s *Schemathesis) Categories() []finding.Category {
	return []finding.Category{finding.CategoryDAST}
}

func (s *Schemathesis) Available(ctx context.Context, t scanner.Target) (bool, string) {
	schema, baseURL := s.configFor(t)
	if schema == "" || baseURL == "" {
		return false, "no schema/base URL configured (set engines.schemathesis.rules)"
	}
	_, ok, reason := scanner.LookPath("schemathesis")
	if ok {
		return true, ""
	}
	if _, err := exec.LookPath("st"); err == nil {
		return true, ""
	}
	return false, reason
}

// configFor resolves the schema and base URL.
func (s *Schemathesis) configFor(t scanner.Target) (schema, baseURL string) {
	schema, baseURL = s.Schema, s.BaseURL
	if t.Config != nil {
		if ec, ok := t.Config.Engines["schemathesis"]; ok {
			if len(ec.Rules) > 0 {
				schema = ec.Rules[0]
			}
			if len(ec.Rules) > 1 {
				baseURL = ec.Rules[1]
			}
		}
	}
	return schema, baseURL
}

func (s *Schemathesis) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	schema, baseURL := s.configFor(t)
	if schema == "" || baseURL == "" {
		// Same reasoning as ZAP: a target is never inferred, because
		// inferring one means sending traffic somewhere nobody authorized.
		return nil, fmt.Errorf("set engines.schemathesis.rules to [<openapi-schema>, <base-url>]")
	}
	if err := validateTarget(baseURL); err != nil {
		return nil, err
	}

	report, cleanup, err := tempReport("dragon-schemathesis-*.json")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	bin := "schemathesis"
	if _, err := exec.LookPath(bin); err != nil {
		bin = "st"
	}
	args := []string{"run", schema, "--url", baseURL, "--report", "json", "--report-json-path", report}
	if t.Config != nil {
		if ec, ok := t.Config.Engines["schemathesis"]; ok {
			args = append(args, ec.Args...)
		}
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// Non-zero means failures were found, which is the point.
	_ = cmd.Run()

	data, err := os.ReadFile(report)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("schemathesis produced no report: %s", truncate(stderr.String(), 400))
	}
	return parseSchemathesisReport(data, baseURL)
}

type schemathesisReport struct {
	Results []struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Verbose string `json:"verbose_name"`
		Checks  []struct {
			Name    string `json:"name"`
			Value   string `json:"value"`
			Message string `json:"message"`
			Example struct {
				RequestBody string `json:"body"`
				Path        string `json:"path"`
				Method      string `json:"method"`
			} `json:"example"`
		} `json:"checks"`
		Errors []struct {
			Exception string `json:"exception"`
			Title     string `json:"title"`
		} `json:"errors"`
	} `json:"results"`
}

func parseSchemathesisReport(data []byte, baseURL string) ([]finding.Finding, error) {
	var rep schemathesisReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse schemathesis report: %w", err)
	}

	var out []finding.Finding
	for _, r := range rep.Results {
		endpoint := strings.TrimSpace(r.Method + " " + r.Path)
		for _, c := range r.Checks {
			// Only failures are findings; a passing check is not evidence of
			// anything worth a developer's attention.
			if !strings.EqualFold(c.Value, "failure") && !strings.EqualFold(c.Value, "error") {
				continue
			}
			out = append(out, finding.Finding{
				Scanner:          "schemathesis",
				ScannerFindingID: c.Name,
				Category:         finding.CategoryDAST,
				RuleID:           "schemathesis/" + c.Name,
				Title:            fmt.Sprintf("%s failed on %s", humanCheck(c.Name), endpoint),
				Message:          truncate(c.Message, 800),
				Severity:         schemathesisSeverity(c.Name),
				Location:         finding.Location{File: baseURL + r.Path},
				Analysis:         finding.Analysis{Reachable: true, Reachability: "reachable"},
				Metadata: map[string]any{
					"check":    c.Name,
					"method":   r.Method,
					"endpoint": endpoint,
				},
			})
		}
	}
	return out, nil
}

// schemathesisSeverity ranks the checks by what a failure actually implies.
//
// A 500 on schema-valid input is an unhandled path an attacker can reach on
// purpose. A response that merely disagrees with its declared schema is a
// contract bug: worth fixing, not worth blocking a release over.
func schemathesisSeverity(check string) finding.Severity {
	switch strings.ToLower(check) {
	case "not_a_server_error", "server_error":
		return finding.SeverityHigh
	case "status_code_conformance", "content_type_conformance":
		return finding.SeverityMedium
	case "response_schema_conformance", "response_headers_conformance":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

func humanCheck(name string) string {
	return strings.TrimSpace(strings.ReplaceAll(name, "_", " "))
}
