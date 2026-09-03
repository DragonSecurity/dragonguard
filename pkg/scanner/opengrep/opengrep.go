// Package opengrep adapts OpenGrep, the Semgrep-compatible SAST engine, into
// DragonGuard's Finding schema.
//
// OpenGrep is a fork of Semgrep 1.100.0 and runs Semgrep-format rules
// unchanged. Note that engine compatibility is not permission to redistribute
// every Semgrep-maintained rule: rule licensing is a separate question from
// engine licensing, which is why DragonGuard ships its own rule pack rather
// than vendoring somebody else's.
package opengrep

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/ingest/sarif"
	dragonrules "github.com/DragonSecurity/dragonguard/pkg/rules"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

const binary = "opengrep"

// Scanner runs OpenGrep over a source tree.
type Scanner struct {
	// Rules overrides the rule configs passed with --config.
	Rules []string
}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "opengrep" }

func (s *Scanner) Categories() []finding.Category {
	return []finding.Category{finding.CategorySAST}
}

func (s *Scanner) Available(ctx context.Context, t scanner.Target) (bool, string) {
	_, ok, reason := scanner.LookPath(binary)
	return ok, reason
}

// RulesFor reports where this scan's rules come from.
//
// Worth reporting because engines.opengrep.rules *replaces* the default rather
// than adding to it, and an absent key falls back to a bundled pack. So
// `opengrep --config p/security-audit` and `dragon scan` can run entirely
// different rulesets and disagree completely, with nothing on screen to say
// they were not asked the same question.
func (s *Scanner) RulesFor(t scanner.Target) []string {
	rules := s.resolveRules(t)
	// The built-in pack resolves to a temporary extraction directory, and
	// printing that path tells a reader nothing except that something
	// unexplained is in /var/folders. Name it for what it is, and say that
	// nothing was configured -- which is the fact worth knowing when a hand
	// run of the engine disagrees with the scan.
	if embedded, err := dragonrules.Dir(); err == nil && embedded != "" {
		for i, r := range rules {
			if r == embedded {
				rules[i] = "built-in pack (engines.opengrep.rules not set)"
			}
		}
	}
	return rules
}

func (s *Scanner) resolveRules(t scanner.Target) []string {
	rules := s.Rules
	if t.Config != nil {
		if ec, ok := t.Config.Engines["opengrep"]; ok && len(ec.Rules) > 0 {
			// Replaces rather than extends: a project that names its rules has
			// said which rules it wants, and quietly adding ours to them would
			// make the configured list a suggestion.
			return ec.Rules
		}
	}
	if len(rules) == 0 {
		// A project that has chosen a ruleset on disk wins; otherwise fall
		// back to the pack embedded in the binary, so an unconfigured
		// repository still gets SAST coverage on its first scan instead of
		// reporting the code dimension as unassessed.
		if p := bundledRules(t); p != "" {
			rules = []string{p}
		} else if p, err := dragonrules.Dir(); err == nil && p != "" {
			rules = []string{p}
		}
	}
	return rules
}

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	rules := s.resolveRules(t)
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules available: set engines.opengrep.rules in .dragon.yaml")
	}

	// SARIF is written to a file rather than stdout because OpenGrep prints
	// progress on both streams.
	tmp, err := os.CreateTemp("", "dragon-opengrep-*.sarif")
	if err != nil {
		return nil, fmt.Errorf("create temp report: %w", err)
	}
	reportPath := tmp.Name()
	tmp.Close()
	defer os.Remove(reportPath)

	// Flag set verified against OpenGrep 1.11: --sarif emits SARIF, and
	// --sarif-output writes it to a file. Progress goes to both streams, so
	// the report has to come from a file rather than stdout.
	args := []string{"scan", "--sarif", "--sarif-output", reportPath, "--quiet"}
	for _, r := range rules {
		args = append(args, "--config", r)
	}
	if t.Config != nil {
		for _, ig := range t.Config.Ignore {
			args = append(args, "--exclude", ig)
		}
		if ec, ok := t.Config.Engines["opengrep"]; ok {
			args = append(args, ec.Args...)
		}
	}
	args = append(args, t.Dir)

	cmd := exec.CommandContext(ctx, binary, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// OpenGrep exits non-zero when findings exist, which is not an error for
	// us: a scan that finds problems has succeeded at its job.
	_ = cmd.Run()

	data, err := os.ReadFile(reportPath)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("opengrep produced no report: %s", truncate(stderr.String(), 400))
	}

	log, err := sarif.Parse(data)
	if err != nil {
		return nil, err
	}
	return s.fromSARIF(log, t.Dir, rules), nil
}

func (s *Scanner) fromSARIF(log *sarif.Log, dir string, configPaths []string) []finding.Finding {
	var out []finding.Finding
	for ri := range log.Runs {
		run := &log.Runs[ri]
		version := firstNonEmpty(run.Tool.Driver.SemanticVersion, run.Tool.Driver.Version)
		for i := range run.Results {
			res := &run.Results[i]
			rule := run.RuleFor(res)

			file, start, end, snippet := res.Primary()
			file = relativize(file, dir)

			sev := severityFor(res, rule)

			// OpenGrep derives a rule's ID from the path its config was
			// loaded from, so the same rule is "rules.go.x" locally and
			// "home.runner.work.repo.rules.go.x" in CI. Left alone that
			// changes the fingerprint on every machine, and the regression
			// gate would report the entire backlog as new on its first CI run.
			ruleID := normalizeRuleID(res.RuleID, configPaths)

			var help string
			if rule != nil {
				help = firstNonEmpty(rule.FullDescription.String(), rule.Help.String())
			}
			title := ruleTitle(rule, res, ruleID, help)

			f := finding.Finding{
				Scanner:          s.Name(),
				ScannerVersion:   version,
				ScannerFindingID: res.RuleID,
				Category:         finding.CategorySAST,
				RuleID:           ruleID,
				Title:            title,
				Message:          firstNonEmpty(res.Message.Text, help),
				Severity:         sev,
				Location: finding.Location{
					File:      file,
					StartLine: start,
					EndLine:   end,
					Snippet:   snippet,
				},
				// A SAST hit is by construction in first-party code that runs.
				// Treating it as reachable is the honest default; the risk
				// engine still discounts it if the asset says otherwise.
				Analysis: finding.Analysis{Reachable: true, Reachability: "reachable"},
			}
			if rule != nil {
				f.CWE = rule.CWEs()
				if rule.HelpURI != "" {
					f.References = []string{rule.HelpURI}
				}
				if cvss := securitySeverity(rule); cvss > 0 {
					f.Threat.CVSS = cvss
				}
			}
			if help != "" {
				f.Metadata = map[string]any{"help": help}
			}
			out = append(out, f)
		}
	}
	return out
}

// severityFor resolves a SARIF level into our scale.
//
// SARIF's three levels are coarser than five, so a rule's own severity
// property is preferred when it carries one.
func severityFor(res *sarif.Result, rule *sarif.Rule) finding.Severity {
	if rule != nil && rule.Properties != nil && rule.Properties.Severity != "" {
		return finding.NormalizeSeverity(rule.Properties.Severity)
	}
	level := res.Level
	if level == "" && rule != nil && rule.DefaultConfig != nil {
		level = rule.DefaultConfig.Level
	}
	switch strings.ToLower(level) {
	case "error":
		return finding.SeverityHigh
	case "warning":
		return finding.SeverityMedium
	case "note":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

// securitySeverity reads the SARIF security-severity property, which carries
// a CVSS-like 0-10 number that GitHub and Semgrep both populate.
func securitySeverity(rule *sarif.Rule) float64 {
	if rule == nil || rule.Properties == nil || rule.Properties.SecuritySeverity == "" {
		return 0
	}
	v, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64)
	if err != nil {
		return 0
	}
	return v
}

// bundledRules locates the Dragon rule pack shipped alongside the binary or
// checked into the project.
func bundledRules(t scanner.Target) string {
	var candidates []string
	if t.Config != nil {
		candidates = append(candidates, t.Config.Resolve("policies/rules"), t.Config.Resolve("rules"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "rules"))
	}
	candidates = append(candidates, filepath.Join(t.Dir, "rules"))
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

// normalizeRuleID strips the path-derived prefix OpenGrep prepends to rules
// loaded from a local directory, leaving an ID that is the same everywhere.
//
// The prefix is the config path with separators turned into dots, so it can
// be computed exactly rather than guessed at -- which matters, because a
// registry rule such as "javascript.lang.security.audit.sqli" is genuinely
// dotted and must not be trimmed down to its last segment.
func normalizeRuleID(id string, configPaths []string) string {
	best := id
	for _, cp := range configPaths {
		for _, prefix := range pathPrefixes(cp) {
			if trimmed, ok := strings.CutPrefix(id, prefix+"."); ok && len(trimmed) < len(best) {
				best = trimmed
			}
		}
	}
	return best
}

// pathPrefixes renders a config path the way OpenGrep encodes it into a rule
// ID: separators become dots, leading separators are dropped.
//
// Both the literal and the absolute form are returned, because the prefix
// OpenGrep produces depends on how the path was written on the command line
// -- "--config rules" yields "rules.go.x" while "--config /w/repo/rules"
// yields "w.repo.rules.go.x". Trying both costs nothing and means the rule ID
// is stable however the project happens to configure it.
func pathPrefixes(p string) []string {
	if p == "" || strings.Contains(p, "://") {
		return nil
	}
	// A registry shorthand such as "p/security-audit" is not a path.
	if strings.HasPrefix(p, "p/") || strings.HasPrefix(p, "r/") {
		return nil
	}

	var out []string
	add := func(s string) {
		cleaned := strings.Trim(filepath.ToSlash(filepath.Clean(s)), "/")
		if cleaned == "" || cleaned == "." {
			return
		}
		dotted := strings.ReplaceAll(cleaned, "/", ".")
		for _, e := range out {
			if e == dotted {
				return
			}
		}
		out = append(out, dotted)
	}

	// Every trailing sub-path is a candidate, longest first, because the
	// prefix OpenGrep emits tracks the path as written: "--config rules"
	// gives "rules.go.x" while "--config /w/repo/rules" gives
	// "w.repo.rules.go.x". Deriving candidates from the real config path
	// keeps this precise -- a dotted registry name such as
	// "javascript.lang.security" matches none of them and survives intact.
	addSuffixes := func(s string) {
		cleaned := strings.Trim(filepath.ToSlash(filepath.Clean(s)), "/")
		parts := strings.Split(cleaned, "/")
		for i := 0; i < len(parts); i++ {
			add(strings.Join(parts[i:], "/"))
		}
	}

	addSuffixes(p)
	if abs, err := filepath.Abs(p); err == nil {
		addSuffixes(abs)
	}

	// Longest first, so the most specific prefix wins.
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// ruleTitle produces a readable headline.
//
// OpenGrep sets shortDescription to the literal string "Opengrep Finding:
// <rule id>", which tells a developer nothing. The rule's own message is the
// real description, so its first sentence becomes the title and the whole
// thing stays as the body.
func ruleTitle(rule *sarif.Rule, res *sarif.Result, ruleID, help string) string {
	if rule != nil {
		short := strings.TrimSpace(rule.ShortDescription.String())
		if short != "" && !strings.HasPrefix(short, "Opengrep Finding:") && !strings.HasPrefix(short, "Semgrep Finding:") {
			return truncate(short, 90)
		}
	}
	if sentence := firstSentence(firstNonEmpty(res.Message.Text, help)); sentence != "" {
		return truncate(sentence, 90)
	}
	// Last resort: the bare rule name, which at least identifies the check.
	if i := strings.LastIndex(ruleID, "."); i >= 0 && i < len(ruleID)-1 {
		return ruleID[i+1:]
	}
	return ruleID
}

func firstSentence(s string) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func relativize(target, dir string) string {
	if dir == "" || target == "" {
		return target
	}
	if !filepath.IsAbs(target) {
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
