// Package report renders scan results for humans and for machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/enrich"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/ignore"
	"github.com/DragonSecurity/dragonguard/pkg/policy"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
	"github.com/DragonSecurity/dragonguard/pkg/vcs"
)

// Result bundles everything one scan produced.
type Result struct {
	Scorecard   *scorecard.Scorecard `json:"scorecard"`
	Decision    *baseline.Decision   `json:"decision"`
	Findings    []finding.Finding    `json:"findings"`
	Evaluations []policy.Evaluation  `json:"policy_evaluations,omitempty"`
	Engines     []scanner.Result     `json:"engines"`
	Enrichment  enrich.Report        `json:"enrichment"`
	Fixed       int                  `json:"fixed_since_baseline"`
	// Ignored records findings excluded because git ignores their file.
	// Surfaced rather than dropped silently: a filter nobody can see is
	// indistinguishable from a scanner that missed something.
	Ignored vcs.FilterReport `json:"ignored"`
	// Excluded records findings removed by the `ignore:` list in the
	// configuration, kept separate from Ignored because the two are different
	// claims: git excludes a file from the repository, `ignore:` excludes a
	// path from the scan, and only the second one is a decision this project
	// made about what it does not want to hear about.
	Excluded ignore.Report `json:"excluded"`
}

// Options tune rendering.
type Options struct {
	Color bool
	// MaxFindings caps the finding list; 0 means all.
	MaxFindings int
	// ShowAll includes findings below the "worth reading" bar.
	ShowAll bool
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	orange = "\033[38;5;208m"
)

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on {
		return s
	}
	return code + s + reset
}

// ColorEnabled reports whether ANSI colour should be used on a stream.
func ColorEnabled(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// Text renders the terminal report.
func Text(w io.Writer, r *Result, opts Options) error {
	p := painter{on: opts.Color}
	sc := r.Scorecard

	fmt.Fprintf(w, "\n%s\n", p.c(bold, "Dragon Scorecard"))
	fmt.Fprintln(w, rule(46))
	fmt.Fprintf(w, "  %-24s %s\n", "Overall", scoreCell(p, sc.Score, true))

	for _, name := range scorecard.Dimensions {
		d, ok := sc.Dimensions[name]
		if !ok {
			continue
		}
		label := displayName(name)
		if !d.Assessed {
			// "no engine configured" is a coverage gap; "not assessed" means
			// an engine was meant to cover this and did not. Only the second
			// is something to go and fix today.
			note := "no engine configured"
			if d.Supported {
				note = "not assessed"
			}
			fmt.Fprintf(w, "  %-24s %s\n", label, p.c(dim, note))
			continue
		}
		suffix := ""
		if d.Counts.Total > 0 {
			suffix = p.c(dim, fmt.Sprintf("   %s", countSummary(d.Counts)))
		}
		fmt.Fprintf(w, "  %-24s %s%s\n", label, scoreCell(p, d.Score, false), suffix)
	}

	// Findings worth reading now.
	top := scorecard.TopFindings(r.Findings, findingLimit(opts))
	if len(top) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.c(bold, "Dragon Risk"))
		fmt.Fprintln(w, rule(46))
		for _, f := range top {
			if !opts.ShowAll && f.RiskScore < 25 {
				continue
			}
			writeFinding(w, p, f)
		}
		hidden := countAbove(r.Findings, 0) - len(top)
		if hidden > 0 {
			fmt.Fprintf(w, "  %s\n", p.c(dim, fmt.Sprintf("... and %d more", hidden)))
		}
	}

	// Baseline gate.
	if r.Decision != nil {
		fmt.Fprintf(w, "\n%s\n", p.c(bold, "Dragon Baseline"))
		fmt.Fprintln(w, rule(46))
		if len(r.Decision.Checks) == 0 {
			fmt.Fprintf(w, "  %s\n", p.c(dim, "no constraints defined"))
		}
		for _, c := range r.Decision.Checks {
			mark := p.c(green, "OK")
			if !c.Passed {
				if c.Verdict == baseline.VerdictWarn {
					mark = p.c(yellow, "!!")
				} else {
					mark = p.c(red, "XX")
				}
			}
			fmt.Fprintf(w, "  %s  %-30s %-22s %s\n",
				mark, truncate(c.Name, 30), c.Required, p.c(dim, c.Actual))
		}
	}

	// Engines actually run: never let the report imply coverage it lacks.
	fmt.Fprintf(w, "\n%s\n", p.c(bold, "Evidence"))
	fmt.Fprintln(w, rule(46))
	for _, e := range r.Engines {
		switch {
		case e.Skipped:
			fmt.Fprintf(w, "  %s  %-14s %s\n", p.c(yellow, "--"), e.Scanner, p.c(dim, e.Reason))
		case e.Error != "":
			fmt.Fprintf(w, "  %s  %-14s %s\n", p.c(red, "XX"), e.Scanner, p.c(red, truncate(e.Error, 60)))
		default:
			fmt.Fprintf(w, "  %s  %-14s %s\n", p.c(green, "OK"), e.Scanner,
				p.c(dim, fmt.Sprintf("%d findings in %dms", e.Count, e.DurationMS)))
		}
	}
	intel := "EPSS " + sourceLabel(r.Enrichment.EPSSSource) + ", KEV " + sourceLabel(r.Enrichment.KEVSource)
	fmt.Fprintf(w, "  %s  %-14s %s\n", p.c(dim, ".."), "intelligence", p.c(dim, intel))
	if note := r.Ignored.Note(); note != "" {
		fmt.Fprintf(w, "  %s  %-14s %s\n", p.c(dim, ".."), "gitignore", p.c(dim, note))
	}
	if note := r.Excluded.Note(); note != "" {
		fmt.Fprintf(w, "  %s  %-14s %s\n", p.c(dim, ".."), "ignore", p.c(dim, note))
	}

	// Verdict.
	if r.Decision != nil {
		fmt.Fprintln(w)
		var label string
		switch r.Decision.Verdict {
		case baseline.VerdictPass:
			label = p.c(green+bold, "Dragon Gate: PASS")
		case baseline.VerdictWarn:
			label = p.c(yellow+bold, "Dragon Gate: WARN")
		default:
			label = p.c(red+bold, "Dragon Gate: BLOCKED")
		}
		fmt.Fprintf(w, "%s", label)
		if r.Decision.HasPrevious {
			fmt.Fprintf(w, "   %s", p.c(dim, fmt.Sprintf("posture %.0f (was %.0f)", r.Decision.Score, r.Decision.PreviousScore)))
		} else {
			fmt.Fprintf(w, "   %s", p.c(dim, fmt.Sprintf("posture %.0f (no baseline recorded)", r.Decision.Score)))
		}
		fmt.Fprintln(w)

		if fails := r.Decision.Failures(); len(fails) > 0 {
			fmt.Fprintln(w)
			for _, c := range fails {
				marker := "-"
				if c.Verdict == baseline.VerdictBlock {
					marker = p.c(red, "-")
				} else {
					marker = p.c(yellow, "-")
				}
				fmt.Fprintf(w, "  %s %s\n", marker, c.Detail)
			}
		}
		if r.Fixed > 0 {
			fmt.Fprintf(w, "\n  %s\n", p.c(green, fmt.Sprintf("%d finding(s) fixed since the last scan.", r.Fixed)))
		}
	}
	fmt.Fprintln(w)
	return nil
}

func writeFinding(w io.Writer, p painter, f finding.Finding) {
	color := green
	switch f.RiskRating {
	case "critical":
		color = red
	case "high":
		color = orange
	case "medium":
		color = yellow
	case "low":
		color = blue
	}
	tag := ""
	if f.New {
		tag = p.c(yellow, " NEW")
	}
	fmt.Fprintf(w, "  %s  %s%s\n",
		p.c(color+bold, fmt.Sprintf("%3.0f", f.RiskScore)),
		truncate(f.Title, 58), tag)

	meta := []string{string(f.Category)}
	if loc := f.LocationRef(); loc != "" {
		meta = append(meta, loc)
	}
	if cve := f.PrimaryCVE(); cve != "" {
		meta = append(meta, cve)
	}
	if f.Threat.KEV {
		meta = append(meta, "KEV")
	}
	if f.Threat.EPSSKnown && f.Threat.EPSS >= 0.01 {
		meta = append(meta, fmt.Sprintf("EPSS %.2f", f.Threat.EPSS))
	}
	fmt.Fprintf(w, "       %s\n", p.c(dim, strings.Join(meta, "  ")))

	if len(f.RiskReasons) > 0 {
		fmt.Fprintf(w, "       %s\n", p.c(dim, "why: "+strings.Join(f.RiskReasons, "; ")))
	}
	if f.Analysis.MinimalUpgrade != "" {
		fmt.Fprintf(w, "       %s\n", p.c(green, "fix: "+f.Analysis.MinimalUpgrade))
	}
}

func scoreCell(p painter, v float64, wide bool) string {
	color := green
	switch {
	case v < 50:
		color = red
	case v < 75:
		color = orange
	case v < 90:
		color = yellow
	}
	if wide {
		return p.c(color+bold, fmt.Sprintf("%3.0f/100", v))
	}
	return p.c(color, fmt.Sprintf("%3.0f", v))
}

func countSummary(c scorecard.Counts) string {
	var parts []string
	if c.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%dC", c.Critical))
	}
	if c.High > 0 {
		parts = append(parts, fmt.Sprintf("%dH", c.High))
	}
	if c.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%dM", c.Medium))
	}
	if c.Low > 0 {
		parts = append(parts, fmt.Sprintf("%dL", c.Low))
	}
	return strings.Join(parts, " ")
}

func sourceLabel(s string) string {
	switch s {
	case "network":
		return "live"
	case "cache":
		return "cached"
	case "":
		return "not needed"
	default:
		return "unavailable"
	}
}

func displayName(s string) string {
	switch s {
	case "iac":
		return "IaC"
	case "api":
		return "API"
	case "supply_chain":
		return "Supply Chain"
	default:
		return strings.ToUpper(s[:1]) + s[1:]
	}
}

func findingLimit(o Options) int {
	if o.MaxFindings > 0 {
		return o.MaxFindings
	}
	return 12
}

func countAbove(fs []finding.Finding, min float64) int {
	n := 0
	for _, f := range fs {
		if f.RiskScore >= min && f.Status != finding.StatusAccepted {
			n++
		}
	}
	return n
}

func rule(n int) string { return strings.Repeat("-", n) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// JSON renders the machine-readable report.
func JSON(w io.Writer, r *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
