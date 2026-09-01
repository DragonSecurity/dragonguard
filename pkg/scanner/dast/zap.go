// Package dast adapts dynamic application security testing tools -- OWASP ZAP
// for web, Schemathesis for OpenAPI -- into DragonGuard's Finding schema.
//
// DAST differs from every other engine here in one way that shapes the whole
// design: it needs a running target, and it sends real traffic to it. A SAST
// scan of the wrong directory wastes a minute; a DAST scan of the wrong URL
// is an unauthorized penetration test of somebody else's system. So the
// target is never inferred -- it must be configured explicitly, and this
// adapter refuses to run without one.
package dast

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// ZAP runs an OWASP ZAP baseline scan against a configured target.
type ZAP struct {
	// Target is the base URL to scan. Required; there is no default.
	Target string
	// Full runs the active scan rather than the passive baseline. Active
	// scanning sends attack traffic, so it is opt-in.
	Full bool
	// Docker runs ZAP via its official container when the CLI is absent,
	// which is how most people actually have ZAP available.
	Docker bool
}

func NewZAP() *ZAP { return &ZAP{} }

func (z *ZAP) Name() string { return "zap" }

func (z *ZAP) Categories() []finding.Category {
	return []finding.Category{finding.CategoryDAST}
}

// zapBinaries are the wrapper scripts ZAP ships, newest naming first.
var zapBinaries = []string{"zap.sh", "zap-baseline.py", "zap-full-scan.py"}

func (z *ZAP) Available(ctx context.Context, t scanner.Target) (bool, string) {
	// No target is unavailability, not failure. DAST needs a running system
	// pointed at on purpose, and most projects will never configure one; a
	// scan of such a project should report the API dimension as uncovered,
	// not as a broken engine.
	if z.targetFor(t) == "" {
		return false, "no target configured (set engines.zap.rules to the base URL)"
	}
	for _, b := range zapBinaries {
		if _, err := exec.LookPath(b); err == nil {
			return true, ""
		}
	}
	if _, err := exec.LookPath("docker"); err == nil {
		return true, ""
	}
	return false, "neither ZAP nor docker found on PATH"
}

// targetFor resolves the configured base URL.
func (z *ZAP) targetFor(t scanner.Target) string {
	if t.Config != nil {
		if ec, ok := t.Config.Engines["zap"]; ok && len(ec.Rules) > 0 {
			return ec.Rules[0]
		}
	}
	return z.Target
}

func (z *ZAP) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	target := z.targetFor(t)
	if target == "" {
		// Refusing is the only safe answer. Guessing a target would mean
		// sending traffic at a URL nobody authorized.
		return nil, fmt.Errorf("no target configured: set engines.zap.rules to the base URL to scan")
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}

	report, cleanup, err := tempReportDir("zap-report.json")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	args, bin, err := z.command(target, report)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// ZAP exits non-zero when it finds issues, which is success here.
	_ = cmd.Run()

	data, err := os.ReadFile(report)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("zap produced no report: %s", truncate(stderr.String(), 400))
	}
	return parseZAPReport(data, target)
}

func (z *ZAP) command(target, report string) (args []string, bin string, err error) {
	script := "zap-baseline.py"
	if z.Full {
		script = "zap-full-scan.py"
	}
	if p, err := exec.LookPath(script); err == nil {
		return []string{"-t", target, "-J", report, "-I"}, p, nil
	}
	if p, err := exec.LookPath("docker"); err == nil {
		dir := "/zap/wrk"
		return []string{
			"run", "--rm",
			// Only the report directory, never the parent of a file made by
			// os.CreateTemp -- that is the system temp directory, and this
			// container's whole job is to attack things.
			"-v", fmt.Sprintf("%s:%s:rw", tempDir(report), dir),
			// ZAP resolves -J against its working directory, which in the
			// image is not the mount. Without this it writes the report
			// somewhere the host never sees and the scan ends with "zap
			// produced no report" while ZAP itself reports success.
			"-w", dir,
			"ghcr.io/zaproxy/zaproxy:stable",
			script, "-t", target, "-J", baseName(report), "-I",
		}, p, nil
	}
	return nil, "", fmt.Errorf("neither %s nor docker is available", script)
}

// zapReport mirrors ZAP's JSON report.
type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID    string `json:"pluginid"`
			AlertRef    string `json:"alertRef"`
			Alert       string `json:"alert"`
			Name        string `json:"name"`
			RiskCode    string `json:"riskcode"`
			Confidence  string `json:"confidence"`
			RiskDesc    string `json:"riskdesc"`
			Description string `json:"desc"`
			Solution    string `json:"solution"`
			Reference   string `json:"reference"`
			CWEID       string `json:"cweid"`
			WASCID      string `json:"wascid"`
			Instances   []struct {
				URI      string `json:"uri"`
				Method   string `json:"method"`
				Param    string `json:"param"`
				Evidence string `json:"evidence"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

func parseZAPReport(data []byte, target string) ([]finding.Finding, error) {
	var rep zapReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse zap report: %w", err)
	}

	var out []finding.Finding
	for _, site := range rep.Site {
		for _, a := range site.Alerts {
			f := finding.Finding{
				Scanner:          "zap",
				ScannerFindingID: a.PluginID,
				Category:         finding.CategoryDAST,
				RuleID:           "zap/" + firstNonEmpty(a.PluginID, a.AlertRef),
				Title:            firstNonEmpty(a.Alert, a.Name),
				Message:          stripHTML(a.Description),
				Severity:         zapSeverity(a.RiskCode),
				// A DAST finding was produced by actually reaching the
				// endpoint, so reachability is not a question: the scanner
				// just proved it.
				Analysis: finding.Analysis{
					Reachable:    true,
					Reachability: "reachable",
					FixAvailable: a.Solution != "",
				},
				Metadata: map[string]any{
					"confidence": a.Confidence,
					"solution":   stripHTML(a.Solution),
					"site":       site.Name,
				},
			}
			if cwe := strings.TrimSpace(a.CWEID); cwe != "" && cwe != "-1" && cwe != "0" {
				f.CWE = []string{"CWE-" + cwe}
			}
			if a.Reference != "" {
				f.References = splitRefs(a.Reference)
			}
			if len(a.Instances) > 0 {
				in := a.Instances[0]
				f.Location = finding.Location{File: in.URI, Snippet: in.Evidence}
				f.Metadata["method"] = in.Method
				f.Metadata["param"] = in.Param
				f.Metadata["instances"] = len(a.Instances)
			} else {
				f.Location = finding.Location{File: target}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// zapSeverity maps ZAP's riskcode. ZAP's 0 is informational, not "safe".
func zapSeverity(code string) finding.Severity {
	switch strings.TrimSpace(code) {
	case "3":
		return finding.SeverityHigh
	case "2":
		return finding.SeverityMedium
	case "1":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

// validateTarget refuses anything that is not an absolute http(s) URL.
//
// The check is about blast radius, not correctness: a relative or malformed
// target would either fail confusingly or, worse, resolve somewhere nobody
// intended to send attack traffic.
func validateTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("target %q is not a valid URL: %w", target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target %q must be an http or https URL", target)
	}
	if u.Host == "" {
		return fmt.Errorf("target %q has no host", target)
	}
	return nil
}

func splitRefs(s string) []string {
	var out []string
	for _, line := range strings.Split(stripHTML(s), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "http") {
			out = append(out, line)
		}
	}
	return out
}

// stripHTML removes the markup ZAP wraps its prose in, so a terminal report
// does not print raw <p> tags at somebody.
func stripHTML(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(b.String()), " "))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
