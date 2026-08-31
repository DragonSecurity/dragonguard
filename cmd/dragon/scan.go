package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/pipeline"
	"github.com/DragonSecurity/dragonguard/pkg/report"
)

type scanFlags struct {
	configPath   string
	baselinePath string
	format       string
	output       string
	only         []string
	offline      bool
	record       bool
	image        string
	failOn       string
	quiet        bool
	showAll      bool
	timeout      time.Duration
	noColor      bool
}

func newScanCmd() *cobra.Command {
	var f scanFlags

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run the security engines and evaluate the gate",
		Long: `Scan runs every available engine over the target, scores what they find
against this project's asset context, applies policy, and evaluates the
baseline circuit breaker.

Exit status is the gate decision: 0 when the gate passes or warns, 1 when it
blocks, 2 when the scan itself could not complete. A scan that cannot run is
deliberately not the same as a scan that found nothing.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			return runScan(cmd, dir, f, nil)
		},
	}

	addScanFlags(cmd, &f)
	// Sub-commands scope the scan to one dimension, matching how teams
	// actually reach for this: "just tell me about the dependencies".
	for _, sub := range []struct {
		name  string
		short string
		cats  []finding.Category
	}{
		{"code", "Static analysis of first-party code (SAST)", []finding.Category{finding.CategorySAST}},
		{"dependencies", "Open-source dependency vulnerabilities (SCA)", []finding.Category{finding.CategorySCA, finding.CategoryLicense}},
		{"container", "Container image vulnerabilities", []finding.Category{finding.CategoryContainer}},
		{"iac", "Infrastructure-as-code misconfiguration", []finding.Category{finding.CategoryIaC}},
		{"secrets", "Hardcoded and committed credentials", []finding.Category{finding.CategorySecret}},
	} {
		sub := sub
		var sf scanFlags
		sc := &cobra.Command{
			Use:   sub.name + " [path]",
			Short: sub.short,
			Args:  cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				dir := "."
				if len(args) > 0 {
					dir = args[0]
				}
				return runScan(cmd, dir, sf, sub.cats)
			},
		}
		addScanFlags(sc, &sf)
		cmd.AddCommand(sc)
	}

	return cmd
}

func addScanFlags(cmd *cobra.Command, f *scanFlags) {
	fs := cmd.Flags()
	fs.StringVarP(&f.configPath, "config", "c", "", "path to .dragon.yaml (default: discovered)")
	fs.StringVarP(&f.baselinePath, "baseline", "b", "", "path to the baseline definition")
	fs.StringVarP(&f.format, "format", "f", "text", "output format: text, json, sarif, markdown")
	fs.StringVarP(&f.output, "output", "o", "", "write the report to a file instead of stdout")
	fs.StringSliceVar(&f.only, "engine", nil, "restrict to named engines (repeatable)")
	fs.BoolVar(&f.offline, "offline", false, "disable all network access, including threat intelligence")
	fs.BoolVar(&f.record, "record", false, "save this scan as the new baseline snapshot")
	fs.StringVar(&f.image, "image", "", "scan a container image instead of a directory")
	fs.StringVar(&f.failOn, "fail-on", "", "override the gate: block at or above this risk rating (critical, high, medium, low)")
	fs.BoolVarP(&f.quiet, "quiet", "q", false, "suppress progress output")
	fs.BoolVar(&f.showAll, "all", false, "include low and informational findings in the report")
	fs.DurationVar(&f.timeout, "engine-timeout", 10*time.Minute, "per-engine timeout")
	fs.BoolVar(&f.noColor, "no-color", false, "disable coloured output")
}

func runScan(cmd *cobra.Command, dir string, f scanFlags, cats []finding.Category) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dir, err)
	}
	if st, err := os.Stat(absDir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	cfg, err := config.Load(f.configPath, absDir)
	if err != nil {
		return err
	}

	bl, err := loadBaseline(f.baselinePath, cfg)
	if err != nil {
		return err
	}
	if f.failOn != "" {
		bl = applyFailOn(bl, f.failOn)
	}

	progress := func(msg string) {}
	if !f.quiet && f.format == "text" {
		progress = func(msg string) { fmt.Fprintf(os.Stderr, "  %s\n", msg) }
	}

	res, err := pipeline.Run(cmd.Context(), pipeline.Options{
		Dir:           absDir,
		Image:         f.image,
		Config:        cfg,
		Baseline:      bl,
		Only:          f.only,
		Categories:    cats,
		Offline:       f.offline,
		Record:        f.record,
		EngineTimeout: f.timeout,
		Progress:      progress,
	})
	if err != nil {
		return err
	}

	out := os.Stdout
	if f.output != "" {
		fh, err := os.Create(f.output)
		if err != nil {
			return fmt.Errorf("create %s: %w", f.output, err)
		}
		defer fh.Close()
		out = fh
	}

	opts := report.Options{
		Color:   !f.noColor && f.output == "" && report.ColorEnabled(out),
		ShowAll: f.showAll,
	}

	switch strings.ToLower(f.format) {
	case "text":
		err = report.Text(out, res, opts)
	case "json":
		err = report.JSON(out, res)
	case "sarif":
		err = report.SARIF(out, res)
	case "markdown", "md":
		err = report.Markdown(out, res)
	default:
		return fmt.Errorf("unknown format %q: use text, json, sarif or markdown", f.format)
	}
	if err != nil {
		return err
	}

	if res.Decision != nil && res.Decision.Verdict == baseline.VerdictBlock {
		return gateFailure{code: 1}
	}
	return nil
}

func loadBaseline(path string, cfg *config.Config) (*baseline.Baseline, error) {
	if path == "" {
		path = cfg.Baseline
		if path != "" {
			path = cfg.Resolve(path)
		}
	}
	if path == "" {
		// Conventional locations, so a project can add a baseline without
		// also editing config.
		for _, candidate := range []string{".dragon-baseline.yaml", "baseline.yaml", ".dragon/baseline.yaml"} {
			p := cfg.Resolve(candidate)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				path = p
				break
			}
		}
	}
	if path == "" {
		return baseline.Default(), nil
	}
	return baseline.Load(path)
}

// applyFailOn overrides the baseline with a simple severity threshold.
//
// This exists for the first five minutes of adoption, when somebody wants a
// gate before they have written one. It is deliberately blunt, and the help
// text says so: a real baseline states hard gates and a regression ratchet,
// neither of which a single threshold can express.
func applyFailOn(bl *baseline.Baseline, rating string) *baseline.Baseline {
	zero := 0
	out := *bl
	switch strings.ToLower(rating) {
	case "critical":
		out.Critical = baseline.Limit{Maximum: &zero}
	case "high":
		out.Critical = baseline.Limit{Maximum: &zero}
		out.High = baseline.Limit{Maximum: &zero}
	case "medium":
		out.Critical = baseline.Limit{Maximum: &zero}
		out.High = baseline.Limit{Maximum: &zero}
		out.Medium = baseline.Limit{Maximum: &zero}
	}
	return &out
}
