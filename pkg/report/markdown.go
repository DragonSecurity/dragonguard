package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

// Markdown renders a report suitable for a pull request comment or a CI job
// summary.
//
// It leads with the gate decision and the reasons, because that is the only
// part a developer reads before deciding whether to care. The full finding
// table is collapsed behind a disclosure so a noisy scan does not bury the
// diff under a wall of text -- a review comment nobody reads enforces nothing.
func Markdown(w io.Writer, r *Result) error {
	sc := r.Scorecard

	badge := ":white_check_mark:"
	verdict := "PASS"
	if r.Decision != nil {
		verdict = string(r.Decision.Verdict)
		switch r.Decision.Verdict {
		case baseline.VerdictWarn:
			badge = ":warning:"
		case baseline.VerdictBlock:
			badge = ":no_entry:"
		}
	}

	fmt.Fprintf(w, "## %s DragonGuard: %s\n\n", badge, verdict)
	fmt.Fprintf(w, "**Posture %.0f/100**", sc.Score)
	if r.Decision != nil && r.Decision.HasPrevious {
		delta := sc.Score - r.Decision.PreviousScore
		sign := "+"
		if delta < 0 {
			sign = ""
		}
		fmt.Fprintf(w, " (%s%.0f from %.0f)", sign, delta, r.Decision.PreviousScore)
	}
	fmt.Fprintf(w, " · %d findings", sc.Counts.Total)
	if sc.New.Total > 0 {
		fmt.Fprintf(w, ", %d new", sc.New.Total)
	}
	if r.Fixed > 0 {
		fmt.Fprintf(w, ", %d fixed", r.Fixed)
	}
	fmt.Fprint(w, "\n\n")

	if r.Decision != nil {
		if fails := r.Decision.Failures(); len(fails) > 0 {
			fmt.Fprintln(w, "### Why")
			for _, c := range fails {
				icon := ":warning:"
				if c.Verdict == baseline.VerdictBlock {
					icon = ":x:"
				}
				fmt.Fprintf(w, "- %s %s\n", icon, c.Detail)
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, "### Posture")
	fmt.Fprintln(w, "| Dimension | Score | Findings |")
	fmt.Fprintln(w, "|---|---:|---|")
	for _, name := range scorecard.Dimensions {
		dim, ok := sc.Dimensions[name]
		if !ok {
			continue
		}
		if !dim.Assessed {
			note := "_no engine configured_"
			if dim.Supported {
				note = "_not assessed_"
			}
			fmt.Fprintf(w, "| %s | – | %s |\n", displayName(name), note)
			continue
		}
		summary := countSummary(dim.Counts)
		if summary == "" {
			summary = "clean"
		}
		fmt.Fprintf(w, "| %s | %.0f | %s |\n", displayName(name), dim.Score, summary)
	}
	fmt.Fprintln(w)

	top := scorecard.TopFindings(r.Findings, 20)
	if len(top) > 0 {
		fmt.Fprintln(w, "<details>")
		fmt.Fprintf(w, "<summary>Top findings (%d shown)</summary>\n\n", len(top))
		fmt.Fprintln(w, "| Risk | Finding | Location | Fix |")
		fmt.Fprintln(w, "|---:|---|---|---|")
		for _, f := range top {
			title := escapePipes(truncate(f.Title, 70))
			if f.New {
				title += " **(new)**"
			}
			fix := f.Analysis.MinimalUpgrade
			if fix == "" && f.Analysis.FixedVersion != "" {
				fix = "upgrade to " + f.Analysis.FixedVersion
			}
			if fix == "" {
				fix = "–"
			}
			fmt.Fprintf(w, "| %.0f | %s | `%s` | %s |\n",
				f.RiskScore, title, f.LocationRef(), escapePipes(fix))
		}
		fmt.Fprintln(w, "\n</details>")
	}

	if len(sc.EnginesFailed) > 0 {
		fmt.Fprintf(w, "\n> :warning: Engines failed: %s. This scan is missing evidence it should have had.\n",
			strings.Join(sc.EnginesFailed, ", "))
	}
	if len(sc.EnginesUnavailable) > 0 {
		fmt.Fprintf(w, "\n> :grey_exclamation: Engines not configured: %s.\n",
			strings.Join(sc.EnginesUnavailable, ", "))
	}
	return nil
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
