package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/report"
)

func newFindingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "Query the findings from a saved scan report",
	}
	cmd.AddCommand(newFindingsListCmd(), newFindingsShowCmd())
	return cmd
}

type findingsFilter struct {
	input    string
	category string
	minRisk  float64
	rating   string
	newOnly  bool
	fixable  bool
	kevOnly  bool
	limit    int
	asJSON   bool
}

func newFindingsListCmd() *cobra.Command {
	var f findingsFilter
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List findings from a JSON report",
		Long: `Reads a report produced by 'dragon scan --format json' and filters it.

Kept separate from scanning on purpose: re-running six engines to answer
"which of these can I actually fix today" wastes minutes for a question the
report already answers.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := loadReport(f.input)
			if err != nil {
				return err
			}
			out := filterFindings(res.Findings, f)

			if f.asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}

			if len(out) == 0 {
				fmt.Println("No findings match.")
				return nil
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "RISK\tRATING\tCATEGORY\tFINDING\tLOCATION\tFIX")
			for _, fd := range out {
				fix := fd.Analysis.MinimalUpgrade
				if fix == "" && fd.Analysis.FixedVersion != "" {
					fix = fd.Analysis.FixedVersion
				}
				if fix == "" {
					fix = "-"
				}
				title := fd.Title
				if fd.New {
					title += " (new)"
				}
				fmt.Fprintf(w, "%.0f\t%s\t%s\t%s\t%s\t%s\n",
					fd.RiskScore, fd.RiskRating, fd.Category,
					trunc(title, 50), fd.LocationRef(), trunc(fix, 30))
			}
			w.Flush()
			fmt.Printf("\n%d of %d findings shown.\n", len(out), len(res.Findings))
			return nil
		},
	}
	fs := cmd.Flags()
	fs.StringVarP(&f.input, "input", "i", "-", "JSON report to read (- for stdin)")
	fs.StringVar(&f.category, "category", "", "filter by category (SAST, SCA, CONTAINER, IAC, SECRET, LICENSE)")
	fs.Float64Var(&f.minRisk, "min-risk", 0, "only findings at or above this Dragon Risk score")
	fs.StringVar(&f.rating, "rating", "", "filter by rating (critical, high, medium, low, info)")
	fs.BoolVar(&f.newOnly, "new", false, "only findings absent from the baseline")
	fs.BoolVar(&f.fixable, "fixable", false, "only findings with a fix available")
	fs.BoolVar(&f.kevOnly, "kev", false, "only actively exploited (CISA KEV) vulnerabilities")
	fs.IntVar(&f.limit, "limit", 0, "maximum findings to show")
	fs.BoolVar(&f.asJSON, "json", false, "output JSON")
	return cmd
}

func newFindingsShowCmd() *cobra.Command {
	var input string
	cmd := &cobra.Command{
		Use:   "show <fingerprint-or-cve>",
		Short: "Show one finding in full, including why it scored what it did",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := loadReport(input)
			if err != nil {
				return err
			}
			q := strings.ToUpper(args[0])
			for _, fd := range res.Findings {
				if !strings.HasPrefix(strings.ToUpper(fd.Fingerprint), q) &&
					strings.ToUpper(fd.PrimaryCVE()) != q &&
					strings.ToUpper(fd.RuleID) != q {
					continue
				}
				printFinding(fd)
				return nil
			}
			return fmt.Errorf("no finding matches %q", args[0])
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "-", "JSON report to read (- for stdin)")
	return cmd
}

func printFinding(f finding.Finding) {
	fmt.Printf("%s\n\n", f.Title)
	fmt.Printf("  Dragon Risk    %.0f (%s)\n", f.RiskScore, f.RiskRating)
	fmt.Printf("  Category       %s\n", f.Category)
	fmt.Printf("  Scanner        %s\n", f.Scanner)
	if loc := f.LocationRef(); loc != "" {
		fmt.Printf("  Location       %s\n", loc)
	}
	if f.Package != nil {
		fmt.Printf("  Package        %s@%s (%s)\n", f.Package.Name, f.Package.Version, f.Package.Ecosystem)
	}
	if len(f.CVE) > 0 {
		fmt.Printf("  CVE            %s\n", strings.Join(f.CVE, ", "))
	}
	if len(f.CWE) > 0 {
		fmt.Printf("  CWE            %s\n", strings.Join(f.CWE, ", "))
	}
	fmt.Println()
	if f.Threat.CVSS > 0 {
		fmt.Printf("  CVSS           %.1f\n", f.Threat.CVSS)
	}
	if f.Threat.EPSSKnown {
		fmt.Printf("  EPSS           %.4f\n", f.Threat.EPSS)
	}
	fmt.Printf("  KEV            %t\n", f.Threat.KEV)
	fmt.Printf("  Reachability   %s\n", f.Analysis.Reachability)
	fmt.Println()
	if len(f.RiskReasons) > 0 {
		fmt.Println("  Why this score:")
		for _, r := range f.RiskReasons {
			fmt.Printf("    - %s\n", r)
		}
		fmt.Println()
	}
	if f.Analysis.MinimalUpgrade != "" {
		fmt.Printf("  Fix            %s\n\n", f.Analysis.MinimalUpgrade)
	}
	if len(f.PolicyTags) > 0 {
		fmt.Printf("  Policy tags    %s\n\n", strings.Join(f.PolicyTags, ", "))
	}
	if f.Message != "" {
		fmt.Printf("  %s\n\n", wrap(f.Message, 74, "  "))
	}
	for _, r := range f.References {
		fmt.Printf("  %s\n", r)
	}
	fmt.Printf("\n  Fingerprint    %s\n", f.Fingerprint)
}

func filterFindings(in []finding.Finding, f findingsFilter) []finding.Finding {
	var out []finding.Finding
	for _, fd := range in {
		if f.category != "" && !strings.EqualFold(string(fd.Category), f.category) {
			continue
		}
		if f.rating != "" && !strings.EqualFold(fd.RiskRating, f.rating) {
			continue
		}
		if fd.RiskScore < f.minRisk {
			continue
		}
		if f.newOnly && !fd.New {
			continue
		}
		if f.fixable && !fd.Analysis.FixAvailable {
			continue
		}
		if f.kevOnly && !fd.Threat.KEV {
			continue
		}
		out = append(out, fd)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RiskScore > out[j].RiskScore })
	if f.limit > 0 && len(out) > f.limit {
		out = out[:f.limit]
	}
	return out
}

func loadReport(path string) (*report.Result, error) {
	if path == "" {
		path = "-"
	}
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = os.ReadFile("/dev/stdin")
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read report: %w", err)
	}
	var res report.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("parse report (expected `dragon scan --format json` output): %w", err)
	}
	return &res, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			b.WriteString(line + "\n" + indent)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}
