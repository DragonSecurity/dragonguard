// Package osv adapts Google's OSV-Scanner into DragonGuard's Finding schema.
//
// OSV-Scanner earns its place alongside Trivy for one reason: call analysis.
// Trivy tells you a vulnerable version is present; OSV-Scanner can tell you
// whether your code actually reaches the vulnerable function. That is the
// difference between a queue of 200 findings and a queue of 12, and it is the
// single largest lever on whether a security tool gets used.
//
// The distinction this adapter is careful to preserve: call analysis finding
// no path ("unreachable") is a real, load-bearing conclusion, while call
// analysis not having run at all is "unknown". Collapsing the two would either
// discard the signal or invent it.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

const binary = "osv-scanner"

// Scanner runs OSV-Scanner over a source tree.
type Scanner struct {
	// CallAnalysis lists languages to run call-graph analysis for. OSV-Scanner
	// supports "go" and "rust". Empty means none.
	CallAnalysis []string
}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "osv" }

func (s *Scanner) Categories() []finding.Category {
	return []finding.Category{finding.CategorySCA}
}

func (s *Scanner) Available(ctx context.Context, t scanner.Target) (bool, string) {
	_, ok, reason := scanner.LookPath(binary)
	return ok, reason
}

// report mirrors the subset of OSV-Scanner's JSON output we consume.
type osvReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		Packages []pkgResult `json:"packages"`
	} `json:"results"`
}

type pkgResult struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	// Groups collapse aliased advisories describing one underlying flaw, and
	// carry the call-analysis verdict.
	Groups          []group         `json:"groups"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type group struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
	// ExperimentalAnalysis is keyed by advisory ID.
	ExperimentalAnalysis map[string]struct {
		Called bool `json:"called"`
		// Unimportant marks a vulnerability the Go vulnerability database
		// considers not security-relevant in practice.
		Unimportant bool `json:"unimportant"`
	} `json:"experimental_analysis"`
}

type vulnerability struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

func (s *Scanner) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	langs := s.CallAnalysis
	if t.Config != nil {
		if ec, ok := t.Config.Engines["osv"]; ok && len(ec.Rules) > 0 {
			// Reuse the rules field to carry call-analysis languages rather
			// than inventing a second config shape for one engine.
			langs = ec.Rules
		}
	}

	// The report goes to a file, never stdout. OSV-Scanner writes progress
	// and warnings to whichever stream is convenient, so sharing one with the
	// report means an ordinary scan can fail to parse -- which is how a
	// security engine silently stops contributing evidence.
	report, err := os.CreateTemp("", "dragon-osv-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp report: %w", err)
	}
	reportPath := report.Name()
	report.Close()
	defer os.Remove(reportPath)

	args := s.buildArgs(ctx, reportPath, langs, t)

	cmd := exec.CommandContext(ctx, binary, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// OSV-Scanner exits 1 when it finds vulnerabilities, which is success for
	// our purposes, so the exit status is only consulted if no report landed.
	runErr := cmd.Run()

	out, readErr := os.ReadFile(reportPath)
	if readErr != nil || len(strings.TrimSpace(string(out))) == 0 {
		// A project with no lockfiles is not a failure. OSV-Scanner exits
		// non-zero and says so on stderr; treating that as an engine error
		// would mark every repository without dependencies as degraded.
		if noSources(stderr.String()) {
			return nil, nil
		}
		if runErr != nil {
			return nil, fmt.Errorf("osv-scanner failed: %s", truncate(stderr.String(), 400))
		}
		return nil, nil
	}

	var rep osvReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("parse osv-scanner output: %w", err)
	}

	// Call analysis only ran for the languages that were asked for, so
	// "unreachable" may only be concluded for those ecosystems.
	analysed := map[string]bool{}
	for _, l := range langs {
		analysed[strings.ToLower(strings.TrimSpace(l))] = true
	}

	var findings []finding.Finding
	for _, res := range rep.Results {
		rel := relativize(res.Source.Path, t.Dir)
		for _, p := range res.Packages {
			findings = append(findings, s.fromPackage(p, rel, analysed)...)
		}
	}
	return findings, nil
}

func (s *Scanner) fromPackage(p pkgResult, sourcePath string, analysed map[string]bool) []finding.Finding {
	// Index each advisory's group so reachability and severity can be looked
	// up per vulnerability.
	groupFor := map[string]*group{}
	for i := range p.Groups {
		g := &p.Groups[i]
		for _, id := range g.IDs {
			groupFor[id] = g
		}
	}

	ecosystem := p.Package.Ecosystem
	callAnalysed := analysed[callAnalysisLang(ecosystem)]

	var out []finding.Finding
	for _, v := range p.Vulnerabilities {
		g := groupFor[v.ID]

		f := finding.Finding{
			Scanner:          "osv",
			ScannerFindingID: v.ID,
			Category:         finding.CategorySCA,
			RuleID:           v.ID,
			Title:            firstNonEmpty(v.Summary, v.ID),
			Message:          v.Details,
			CVE:              cveAliases(v.ID, v.Aliases, g),
			Severity:         severityFor(v, g),
			Location:         finding.Location{File: sourcePath},
			Package: &finding.Package{
				Ecosystem: ecosystem,
				Name:      p.Package.Name,
				Version:   p.Package.Version,
				PURL:      purlFor(v, p.Package.Name),
			},
			Threat:     finding.Threat{CVSS: cvssFor(v, g)},
			Analysis:   finding.Analysis{Reachability: "unknown"},
			References: referenceURLs(v),
		}

		if fixed := earliestFix(v, p.Package.Name); fixed != "" {
			f.Analysis.FixAvailable = true
			f.Analysis.FixedVersion = fixed
			f.Analysis.MinimalUpgrade = fmt.Sprintf("%s %s -> %s", p.Package.Name, p.Package.Version, fixed)
		}

		// The reachability verdict. Only claim "unreachable" when analysis
		// actually ran for this ecosystem -- otherwise an absent result would
		// silently read as proof of safety.
		if g != nil && callAnalysed {
			if a, ok := g.ExperimentalAnalysis[v.ID]; ok {
				if a.Called {
					f.Analysis.Reachable = true
					f.Analysis.Reachability = "reachable"
				} else {
					f.Analysis.Reachability = "unreachable"
				}
				if a.Unimportant {
					// The Go vulnerability database marks some entries as not
					// security-relevant in practice. Record it rather than
					// dropping the finding: it is context for a human, not a
					// licence to hide evidence.
					f.Metadata = map[string]any{"osv_unimportant": true}
				}
			}
		}

		out = append(out, f)
	}
	return out
}

// callAnalysisLang maps an OSV ecosystem onto the language name OSV-Scanner
// uses for its --call-analysis flag.
// noSources reports the "nothing to scan" condition, which is a legitimate
// outcome rather than an error.
func noSources(stderr string) bool {
	return strings.Contains(stderr, "No package sources found")
}

// buildArgs assembles the command line for whichever OSV-Scanner is installed.
//
// v1 and v2 are not compatible: v2 introduced the "source" subcommand and
// renamed --output to --output-file, so a v2-shaped command run against v1
// treats "source" as a directory and fails with a message about being unable
// to stat it. Users get whatever their package manager ships, so the adapter
// detects the version rather than assuming.
func (s *Scanner) buildArgs(ctx context.Context, reportPath string, langs []string, t scanner.Target) []string {
	var args []string
	if majorVersion(ctx) >= 2 {
		args = []string{"scan", "source", "--format", "json", "--output-file", reportPath}
	} else {
		args = []string{"scan", "--format", "json", "--output", reportPath}
	}

	for _, l := range langs {
		args = append(args, "--call-analysis="+strings.TrimSpace(l))
	}
	if t.Config != nil {
		if majorVersion(ctx) >= 2 {
			// v1 has no equivalent exclude flag; skipping it there is better
			// than passing an unknown flag and failing the whole engine.
			for _, ig := range t.Config.Ignore {
				args = append(args, "--experimental-exclude", ig)
			}
		}
		if ec, ok := t.Config.Engines["osv"]; ok {
			args = append(args, ec.Args...)
		}
	}
	return append(args, t.Dir)
}

var (
	versionOnce  sync.Once
	versionMajor int
)

// majorVersion reads the installed OSV-Scanner's major version, once.
func majorVersion(ctx context.Context) int {
	versionOnce.Do(func() {
		versionMajor = 2 // assume current unless told otherwise
		out, err := exec.CommandContext(ctx, binary, "--version").Output()
		if err != nil {
			return
		}
		if m := versionRe.FindStringSubmatch(string(out)); len(m) > 1 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				versionMajor = n
			}
		}
	})
	return versionMajor
}

var versionRe = regexp.MustCompile(`osv-scanner version:\s*(\d+)\.`)

func callAnalysisLang(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "go":
		return "go"
	case "crates.io", "cargo":
		return "rust"
	default:
		return ""
	}
}

// cveAliases extracts CVE identifiers, since enrichment can only look those up.
func cveAliases(id string, aliases []string, g *group) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToUpper(strings.TrimSpace(s))
		if strings.HasPrefix(s, "CVE-") && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(id)
	for _, a := range aliases {
		add(a)
	}
	if g != nil {
		// A group's aliases can name a CVE the individual advisory omits.
		for _, a := range g.Aliases {
			add(a)
		}
	}
	return out
}

// cvssFor reads the CVSS score, preferring the advisory's own severity block
// and falling back to the group's max_severity.
func cvssFor(v vulnerability, g *group) float64 {
	for _, s := range v.Severity {
		if strings.HasPrefix(strings.ToUpper(s.Type), "CVSS") {
			if score, err := parseCVSSVector(s.Score); err == nil {
				return score
			}
		}
	}
	if g != nil && g.MaxSeverity != "" {
		if f, err := strconv.ParseFloat(g.MaxSeverity, 64); err == nil {
			return f
		}
	}
	return 0
}

// parseCVSSVector pulls a numeric score out of an OSV severity value, which
// may be a bare number or a full CVSS vector string.
func parseCVSSVector(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	// A vector carries no score of its own; the caller falls back to the
	// group's max_severity, which OSV-Scanner has already computed.
	return 0, fmt.Errorf("not a numeric severity")
}

func severityFor(v vulnerability, g *group) finding.Severity {
	if score := cvssFor(v, g); score > 0 {
		switch {
		case score >= 9.0:
			return finding.SeverityCritical
		case score >= 7.0:
			return finding.SeverityHigh
		case score >= 4.0:
			return finding.SeverityMedium
		default:
			return finding.SeverityLow
		}
	}
	// GitHub advisories carry their own severity word when no score exists.
	if v.DatabaseSpecific != nil {
		if sev, ok := v.DatabaseSpecific["severity"].(string); ok && sev != "" {
			return finding.NormalizeSeverity(sev)
		}
	}
	return finding.SeverityMedium
}

// earliestFix returns the first version that resolves the vulnerability.
//
// OSV expresses affected ranges as introduced/fixed event pairs. The earliest
// fixed event is the smallest upgrade that clears this advisory, which is what
// a developer wants over "upgrade to latest".
func earliestFix(v vulnerability, pkgName string) string {
	for _, aff := range v.Affected {
		if aff.Package.Name != "" && !strings.EqualFold(aff.Package.Name, pkgName) {
			continue
		}
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func purlFor(v vulnerability, pkgName string) string {
	for _, aff := range v.Affected {
		if aff.Package.PURL != "" && strings.EqualFold(aff.Package.Name, pkgName) {
			return aff.Package.PURL
		}
	}
	return ""
}

func referenceURLs(v vulnerability) []string {
	var out []string
	for _, r := range v.References {
		if r.URL != "" {
			out = append(out, r.URL)
		}
	}
	return out
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
