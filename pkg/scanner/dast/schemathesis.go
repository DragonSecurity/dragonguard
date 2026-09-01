package dast

import (
	"bufio"
	"bytes"
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
	switch {
	case schema == "" && baseURL == "":
		return false, "no schema/base URL configured (set engines.schemathesis.rules to [<openapi-schema>, <base-url>])"
	case baseURL == "":
		// Distinguished because the previous message said "not configured" to
		// somebody who had configured it, and sent them to look at a setting
		// that was already there. One entry is the easy mistake: zap takes a
		// single URL, so the same shape reads as complete here.
		return false, "engines.schemathesis.rules needs two entries, [<openapi-schema>, <base-url>]; only one is set"
	case schema == "":
		return false, "engines.schemathesis.rules is missing the schema URL; it takes [<openapi-schema>, <base-url>]"
	}
	if _, ok, _ := scanner.LookPath("schemathesis"); ok {
		return true, ""
	}
	if _, err := exec.LookPath("st"); err == nil {
		return true, ""
	}
	// Schemathesis is a Python tool, so on most machines the container is how
	// it is actually available -- the same reasoning that makes ZAP usable
	// here. Reporting "not found on PATH" while docker sits right there
	// describes the search, not the situation.
	if _, err := exec.LookPath("docker"); err == nil {
		return true, ""
	}
	return false, "neither schemathesis nor docker found on PATH"
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

	report, cleanup, err := tempReportDir("schemathesis-report.ndjson")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	var extra []string
	if t.Config != nil {
		if ec, ok := t.Config.Engines["schemathesis"]; ok {
			extra = ec.Args
		}
	}
	args, bin, err := s.command(schema, baseURL, report, extra)
	if err != nil {
		return nil, err
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

// command prefers a local schemathesis and falls back to the container.
func (s *Schemathesis) command(schema, baseURL, report string, extra []string) (args []string, bin string, err error) {
	run := func(reportPath string) []string {
		return append([]string{
			"run", schema,
			"--url", baseURL,
			// NDJSON, not JSON. Schemathesis 4 removed the JSON report
			// entirely; --report-json-path is rejected outright by any
			// current install, which this adapter never noticed because the
			// engine was skipped as "not found on PATH" on every machine
			// that did not have it.
			"--report", "ndjson",
			"--report-ndjson-path", reportPath,
		}, extra...)
	}

	for _, name := range []string{"schemathesis", "st"} {
		if p, err := exec.LookPath(name); err == nil {
			return run(report), p, nil
		}
	}
	if p, err := exec.LookPath("docker"); err == nil {
		// Deliberately NOT /app. That is the image's own installation -- it
		// holds hooks.py, which the image points SCHEMATHESIS_HOOKS at, so
		// mounting the report directory there shadows it and schemathesis
		// exits before it starts with "No such file or directory:
		// /app/hooks.py". The report gets its own mount point instead, and
		// the path passed in is absolute so it does not depend on whatever
		// working directory the image chooses.
		dir := "/reports"
		return append([]string{
			"run", "--rm",
			// Only the report directory. Mounting the parent of a file made
			// by os.CreateTemp would hand the system temp directory to a
			// container that exists to send hostile traffic.
			"-v", fmt.Sprintf("%s:%s:rw", tempDir(report), dir),
			// The container has its own loopback, so a localhost target
			// reaches the container rather than the host. Host networking
			// is not assumed here -- it is not available on every platform,
			// and silently rewriting somebody's target URL is worse than a
			// connection refused they can read.
			"schemathesis/schemathesis:stable",
		}, run(dir+"/"+baseName(report))...), p, nil
	}
	return nil, "", fmt.Errorf("neither schemathesis nor docker is available")
}

// The NDJSON report is a stream of events, one JSON object per line, keyed by
// event name. Only ScenarioFinished carries results, so the rest are skipped
// rather than modelled.
type schemathesisEvent struct {
	ScenarioFinished *struct {
		Status   string `json:"status"`
		Phase    string `json:"phase"`
		Recorder struct {
			// Label is the operation, e.g. "GET /users/{id}".
			Label string `json:"label"`
			// Checks, cases and interactions are all keyed by case ID.
			Checks map[string][]struct {
				Name        string `json:"name"`
				Status      string `json:"status"`
				FailureInfo *struct {
					Failure struct {
						Type      string `json:"type"`
						Operation string `json:"operation"`
						Title     string `json:"title"`
						Message   string `json:"message"`
						Severity  string `json:"severity"`
					} `json:"failure"`
				} `json:"failure_info"`
			} `json:"checks"`
			Interactions map[string]struct {
				Request struct {
					Method string `json:"method"`
					URI    string `json:"uri"`
				} `json:"request"`
				Response struct {
					StatusCode int `json:"status_code"`
				} `json:"response"`
			} `json:"interactions"`
		} `json:"recorder"`
	} `json:"ScenarioFinished"`
}

func parseSchemathesisReport(data []byte, baseURL string) ([]finding.Finding, error) {
	// One check fails across many generated cases -- the coverage phase alone
	// produces a case per mutation -- so findings are collapsed by what makes
	// them distinct and the repetitions are counted, exactly as the ZAP
	// adapter counts instances. Emitting one finding per generated request
	// would bury a real server error under a hundred copies of itself.
	type key struct{ check, operation, failureType string }
	var (
		order []key
		byKey = map[key]*finding.Finding{}
		seen  = map[key]int{}
	)

	sc := bufio.NewScanner(bytes.NewReader(data))
	// Interactions carry base64 response bodies, so a line is far longer than
	// the 64KB the scanner allows by default; without this a large report
	// stops parsing partway through and silently reports fewer findings.
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev schemathesisEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// A single malformed event must not discard the rest of a run.
			continue
		}
		if ev.ScenarioFinished == nil {
			continue
		}
		rec := ev.ScenarioFinished.Recorder

		for caseID, checks := range rec.Checks {
			for _, c := range checks {
				// Only failures are findings; a passing check is not evidence
				// of anything worth a developer's attention.
				if !strings.EqualFold(c.Status, "failure") && !strings.EqualFold(c.Status, "error") {
					continue
				}
				var f struct{ Type, Operation, Title, Message, Severity string }
				if c.FailureInfo != nil {
					fi := c.FailureInfo.Failure
					f.Type, f.Operation, f.Title, f.Message, f.Severity = fi.Type, fi.Operation, fi.Title, fi.Message, fi.Severity
				}

				operation := firstNonEmpty(f.Operation, rec.Label)
				k := key{check: c.Name, operation: operation, failureType: f.Type}
				seen[k]++
				if existing, ok := byKey[k]; ok {
					existing.Metadata["occurrences"] = seen[k]
					continue
				}

				interaction := rec.Interactions[caseID]
				location := interaction.Request.URI
				if location == "" {
					location = baseURL
				}

				nf := &finding.Finding{
					Scanner:          "schemathesis",
					ScannerFindingID: c.Name,
					Category:         finding.CategoryDAST,
					RuleID:           "schemathesis/" + c.Name,
					Title:            firstNonEmpty(f.Title, humanCheck(c.Name)) + " on " + operation,
					Message:          truncate(f.Message, 800),
					// Schemathesis rates its own failures now, and it knows
					// more about what each check means than a table here can.
					// The name-based ranking is the fallback, not the rule.
					Severity: schemathesisSeverity(c.Name, f.Severity),
					Location: finding.Location{File: location},
					// The request was actually sent and the response actually
					// received, so reachability is not a question -- the
					// scanner just proved it.
					Analysis: finding.Analysis{Reachable: true, Reachability: "reachable"},
					Metadata: map[string]any{
						"check":       c.Name,
						"endpoint":    operation,
						"occurrences": 1,
					},
				}
				if f.Type != "" {
					nf.Metadata["failure_type"] = f.Type
				}
				if m := interaction.Request.Method; m != "" {
					nf.Metadata["method"] = m
				}
				if code := interaction.Response.StatusCode; code != 0 {
					nf.Metadata["status_code"] = code
				}
				byKey[k] = nf
				order = append(order, k)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read schemathesis report: %w", err)
	}

	out := make([]finding.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// schemathesisSeverity prefers the severity schemathesis assigned, and falls
// back to ranking the check by what a failure implies.
//
// A 500 on schema-valid input is an unhandled path an attacker can reach on
// purpose. A response that merely disagrees with its declared schema is a
// contract bug: worth fixing, not worth blocking a release over.
func schemathesisSeverity(check, reported string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(reported)) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	}
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
