// Package gitleaks adapts Gitleaks into DragonGuard's Finding schema.
//
// Gitleaks complements Trivy's secret scanning rather than duplicating it:
// Trivy scans the working tree, Gitleaks walks git history. A credential
// deleted in the current commit but still present three commits back is
// still a live credential, and only the history scan finds it.
package gitleaks

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
	"github.com/DragonSecurity/dragonguard/pkg/verify"
)

const binary = "gitleaks"

// Scanner runs Gitleaks over a repository.
type Scanner struct {
	// Verify enables live-credential verification. Off by default: sending a
	// credential to a third party, even its rightful issuer, should be a
	// decision somebody made on purpose.
	Verify bool
	// Verifier performs the checks. Nil means the built-in set.
	Verifier *verify.Verifier
}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "gitleaks" }

func (s *Scanner) Categories() []finding.Category {
	return []finding.Category{finding.CategorySecret}
}

func (s *Scanner) Available(ctx context.Context, t scanner.Target) (bool, string) {
	_, ok, reason := scanner.LookPath(binary)
	return ok, reason
}

// leak mirrors Gitleaks' JSON report entries.
type leak struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	Entropy     float64  `json:"Entropy"`
	Fingerprint string   `json:"Fingerprint"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
}

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	tmp, err := os.CreateTemp("", "dragon-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp report: %w", err)
	}
	reportPath := tmp.Name()
	tmp.Close()
	defer os.Remove(reportPath)

	// Verification needs the plaintext, so redaction is dropped only when it
	// is enabled -- and the value then lives in this process for the length of
	// one HTTP call and is dropped before any finding is returned. It is never
	// written to the report, the snapshot or the database.
	verifying := s.Verify
	if t.Config != nil && t.Config.VerifySecrets {
		verifying = true
	}

	args := []string{
		"detect",
		"--source", t.Dir,
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "0",
		"--no-banner",
	}
	if !verifying {
		// Never write a live credential to our own report.
		args = append(args, "--redact")
	}
	// Scanning history needs a repository. Outside one, fall back to the
	// working tree rather than failing the whole engine.
	if !isGitRepo(t.Dir) {
		args = append(args, "--no-git")
	}
	if t.Config != nil {
		if ec, ok := t.Config.Engines["gitleaks"]; ok {
			args = append(args, ec.Args...)
		}
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run gitleaks: %w: %s", err, truncate(stderr.String(), 400))
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("read gitleaks report: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}

	var leaks []leak
	if err := json.Unmarshal(data, &leaks); err != nil {
		return nil, fmt.Errorf("parse gitleaks report: %w", err)
	}

	inHistory := isGitRepo(t.Dir)
	out := make([]finding.Finding, 0, len(leaks))
	var candidates []verify.Candidate

	for _, l := range leaks {
		f := finding.Finding{
			Scanner:          s.Name(),
			ScannerFindingID: l.Fingerprint,
			Category:         finding.CategorySecret,
			RuleID:           l.RuleID,
			Title:            firstNonEmpty(l.Description, l.RuleID),
			Message:          "Credential detected in source",
			// A committed credential is critical by default: it is not a
			// latent weakness that might be exploited, it is a key that is
			// already out. Verification can only lower this, never raise it.
			Severity: finding.SeverityCritical,
			Location: finding.Location{
				File:      relativize(l.File, t.Dir),
				StartLine: l.StartLine,
				EndLine:   l.EndLine,
				// Even when verifying, the snippet stored is the redacted
				// form. The plaintext is used and dropped, never persisted.
				Snippet: redact(l.Match, l.Secret),
			},
			Metadata: map[string]any{
				"entropy": l.Entropy,
				"tags":    l.Tags,
			},
		}
		if l.Commit != "" {
			f.Metadata["commit"] = l.Commit
			f.Metadata["author"] = l.Author
			f.Metadata["date"] = l.Date
			// A secret reachable only through history cannot be fixed by
			// editing the file, so the remediation is materially different.
			f.Metadata["in_git_history"] = inHistory
		}
		if verifying && l.Secret != "" {
			secret, ruleID := l.Secret, l.RuleID
			// AWS is the one provider needing two values, and detectors
			// report one line at a time. If the file this landed in also
			// holds the other half, pair them -- otherwise a credential
			// sitting in plain sight goes unverified.
			abs := l.File
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(t.Dir, l.File)
			}
			if verify.FileMentionsAWSKey(abs) {
				if paired, ok := verify.PairAWSCredential(abs, l.Secret); ok {
					secret, ruleID = paired, "aws-credential-pair"
				}
			}
			candidates = append(candidates, verify.Candidate{
				Index:  len(out),
				RuleID: ruleID,
				Secret: secret,
			})
		}
		out = append(out, f)
	}

	if len(candidates) > 0 {
		v := s.Verifier
		if v == nil {
			v = verify.New()
		}
		v.VerifyAll(ctx, out, candidates)
		// Drop every plaintext we were holding as soon as the verdicts are in.
		for i := range candidates {
			candidates[i].Secret = ""
		}
	}
	return out, nil
}

// redact replaces the plaintext secret inside a match with a fixed mask.
//
// Gitleaks' own --redact is disabled while verifying, so the masking has to
// happen here instead. Masking to a constant width rather than the secret's
// own length avoids leaking it by inference.
func redact(match, secret string) string {
	if secret == "" {
		return match
	}
	return strings.ReplaceAll(match, secret, "REDACTED")
}

func isGitRepo(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && (st.IsDir() || st.Mode().IsRegular())
}

func relativize(target, dir string) string {
	if dir == "" || target == "" || !filepath.IsAbs(target) {
		return target
	}
	if rel, err := filepath.Rel(dir, target); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return target
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
