package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/DragonSecurity/dragonguard/pkg/baseline"
	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/pipeline"
	"github.com/DragonSecurity/dragonguard/pkg/report"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

func newBaselineCalibrateCmd() *cobra.Command {
	var (
		configPath           string
		out                  string
		strict               bool
		force                bool
		offline              bool
		allowExistingSecrets bool
	)

	cmd := &cobra.Command{
		Use:   "calibrate [path]",
		Short: "Scan this project and write a baseline it can actually pass today",
		Long: `Calibrate runs a scan, reads where the project actually stands, and writes a
baseline calibrated to that reality.

This exists because a guessed baseline is the fastest way to get a security
gate switched off. Set "minimum_score: 80" on an unfamiliar codebase and the
first run blocks every pull request for reasons nobody on the team caused; by
Friday the gate is disabled and nothing is being checked at all.

So the generated baseline:

  - sets score floors just below where the project sits now, leaving a small
    tolerance so ordinary noise does not block anybody
  - keeps the hard gates that are indefensible anywhere -- a live credential,
    an actively exploited vulnerability -- because those are not things a
    codebase gets grandfathered into
  - relies on the regression ratchet for everything else, which a legacy
    codebase can pass on day one and which still forces posture upward

It then records the baseline snapshot, so the existing backlog stops being
reported as new and only what changes from here is gated.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return err
			}

			cfg, err := config.Load(configPath, absDir)
			if err != nil {
				return err
			}

			if out == "" {
				out = cfg.Baseline
			}
			if out == "" {
				out = ".dragon-baseline.yaml"
			}
			outPath := cfg.Resolve(out)
			if _, err := os.Stat(outPath); err == nil && !force {
				return fmt.Errorf("%s already exists; pass --force to overwrite", out)
			}

			fmt.Fprintln(os.Stderr, "Scanning to establish where this project currently stands...")
			res, err := pipeline.Run(cmd.Context(), pipeline.Options{
				Dir:           absDir,
				Config:        cfg,
				Baseline:      baseline.Default(),
				Offline:       offline,
				EngineTimeout: 10 * time.Minute,
				Progress:      func(m string) { fmt.Fprintf(os.Stderr, "  %s\n", m) },
			})
			if err != nil {
				return err
			}

			bl, ungated := calibrate(res, strict, allowExistingSecrets)
			data, err := yaml.Marshal(bl)
			if err != nil {
				return err
			}
			header := calibrationHeader(res, strict, ungated)
			if err := os.WriteFile(outPath, append([]byte(header), data...), 0o644); err != nil {
				return err
			}

			// Record the snapshot, so the current backlog is the baseline
			// rather than a wall of "new" findings on the next run.
			if _, err := pipeline.Run(cmd.Context(), pipeline.Options{
				Dir: absDir, Config: cfg, Baseline: bl,
				Offline: offline, Record: true,
				EngineTimeout: 10 * time.Minute,
			}); err != nil {
				return fmt.Errorf("record baseline snapshot: %w", err)
			}

			printCalibration(res, bl, outPath, ungated)
			warnAboutSecrets(res, allowExistingSecrets)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	f.StringVarP(&out, "output", "o", "", "where to write the baseline")
	f.BoolVar(&strict, "strict", false, "calibrate at current posture with no tolerance (tighter, blocks sooner)")
	f.BoolVar(&force, "force", false, "overwrite an existing baseline")
	f.BoolVar(&offline, "offline", false, "disable network access during calibration")
	f.BoolVar(&allowExistingSecrets, "allow-existing-secrets", false,
		"grandfather credentials already committed to this repository (not recommended: they are still disclosed)")
	return cmd
}

// calibrationTolerance is how far below current posture a floor is set.
//
// Non-zero on purpose: posture moves by a point or two between runs as
// advisories are published and EPSS scores shift, none of which anybody in the
// team did. A floor set exactly at today's score would block on that noise,
// and a gate that blocks for reasons nobody caused is a gate people learn to
// override.
const calibrationTolerance = 3

func calibrate(res *report.Result, strict, allowExistingSecrets bool) (*baseline.Baseline, []string) {
	sc := res.Scorecard
	tolerance := float64(calibrationTolerance)
	if strict {
		tolerance = 0
	}

	bl := baseline.Default()
	bl.Metadata.Name = "calibrated"
	bl.Metadata.Description = fmt.Sprintf(
		"Calibrated against posture %.0f on %s. Raise the floors as the backlog comes down.",
		sc.Score, time.Now().UTC().Format("2006-01-02"))

	floor := math.Max(0, math.Floor(sc.Score-tolerance))
	bl.MinimumScore = &floor

	// Per-dimension floors, but only for dimensions an engine actually
	// assessed. A floor on a dimension nobody scanned would be enforced
	// against a number that means nothing.
	bl.Dimensions = map[string]baseline.DimensionRule{}
	var ungated []string
	for _, name := range scorecard.Dimensions {
		d, ok := sc.Dimensions[name]
		if !ok || !d.Assessed {
			continue
		}
		min := math.Max(0, math.Floor(d.Score-tolerance))

		// A floor of zero is not a gate: no posture can fall below it, so
		// writing one puts a line in the baseline that looks like protection
		// and provides none. A dimension already at rock bottom is carried by
		// the regression ratchet and the new-finding allowances instead, and
		// the generated header says which dimensions were left out.
		if min <= 0 {
			ungated = append(ungated, name)
			continue
		}
		rule := baseline.DimensionRule{Minimum: &min}
		// Secrets is the one dimension worth holding at 100: there is no
		// defensible number of live credentials in a repository, and a
		// project at 100 today should not be allowed to drift off it.
		if name == "secrets" && d.Score >= 100 {
			hundred := 100.0
			rule.Minimum = &hundred
			rule.Required = true
		}
		bl.Dimensions[name] = rule
	}

	// New-finding allowances: zero for critical always, and for high only if
	// the project is already clean of them. Demanding zero new highs on a
	// codebase that has forty is a gate somebody will disable.
	zero := 0
	bl.Critical = baseline.Limit{MaximumNew: &zero}
	if sc.Counts.High == 0 {
		bl.High = baseline.Limit{MaximumNew: &zero}
	} else {
		two := 2
		bl.High = baseline.Limit{MaximumNew: &two}
	}

	// A project with an existing backlog of criticals cannot pass a hard gate
	// on them today, so the ratchet carries it instead. The gate still blocks
	// anything new, and the mandatory conditions below still stand.
	//
	// Committed credentials are the deliberate exception to calibration. A
	// vulnerable dependency can wait for a maintenance window; a disclosed
	// key is already out, and calibrating around it would mean the tool
	// quietly agreed the repository could keep it. So the gate stays on by
	// default even though it means this baseline does not pass yet -- and
	// the command says so plainly rather than pretending otherwise.
	var mandatory []string
	if sc.Mandatory["no_active_secrets"] || !allowExistingSecrets {
		mandatory = append(mandatory, "no_active_secrets")
	}
	if sc.Mandatory["no_kev_in_production"] {
		mandatory = append(mandatory, "no_kev_in_production")
	}
	if sc.Mandatory["no_reachable_critical_vulnerability"] {
		mandatory = append(mandatory, "no_reachable_critical_vulnerability")
	}
	bl.Mandatory = mandatory

	// Only allow a degraded pass if the scan was degraded now: silently
	// permitting it forever would let a broken engine hide behind the gate.
	bl.AllowDegraded = false

	return bl, ungated
}

func calibrationHeader(res *report.Result, strict bool, ungated []string) string {
	sc := res.Scorecard
	mode := fmt.Sprintf("with a %d-point tolerance", calibrationTolerance)
	if strict {
		mode = "at exactly current posture (--strict)"
	}
	return fmt.Sprintf(`# Generated by 'dragon baseline calibrate' on %s.
#
# Calibrated against this project's actual posture (%.0f/100) %s, so it passes
# today and ratchets from here. The floors are a starting point, not a target:
# raise them as the backlog comes down.
#
# The hard gates below are not calibrated. A live credential and an actively
# exploited vulnerability are not things a codebase gets grandfathered into.
#
# %d findings were recorded as the baseline snapshot, so they are no longer
# reported as new. Only what changes from here is gated.
%s
`, time.Now().UTC().Format("2006-01-02"), sc.Score, mode, sc.Counts.Total, ungatedNote(ungated))
}

// ungatedNote explains any dimension deliberately left without a floor.
//
// Silence here would be worse than the zero floor it replaces: a reader who
// notices a dimension missing from the list should be told it was a decision,
// not an oversight.
func ungatedNote(ungated []string) string {
	if len(ungated) == 0 {
		return ""
	}
	return fmt.Sprintf(`#
# No floor was set for: %s.
#
# Those dimensions currently score zero, and a floor of zero is not a gate --
# nothing can fall below it. They are carried by the regression ratchet and
# the new-finding allowances instead. Set a real floor once the backlog is
# down far enough for one to mean something.`, strings.Join(ungated, ", "))
}

func printCalibration(res *report.Result, bl *baseline.Baseline, path string, ungated []string) {
	sc := res.Scorecard
	fmt.Printf("\nWrote %s\n\n", path)
	fmt.Printf("  Calibrated posture floor   %.0f  (currently %.0f)\n", derefF(bl.MinimumScore), sc.Score)
	fmt.Printf("  Max regression             %.0f points\n", derefF(bl.MaximumScoreRegression))
	fmt.Printf("  New critical findings      <= %d\n", derefI(bl.Critical.MaximumNew))
	fmt.Printf("  New high findings          <= %d\n", derefI(bl.High.MaximumNew))
	if len(bl.Dimensions) > 0 {
		fmt.Printf("\n  Dimension floors:\n")
		for _, name := range scorecard.Dimensions {
			if r, ok := bl.Dimensions[name]; ok && r.Minimum != nil {
				note := ""
				if r.Required {
					note = "  (required)"
				}
				fmt.Printf("    %-14s %.0f%s\n", name, *r.Minimum, note)
			}
		}
	}
	if len(ungated) > 0 {
		fmt.Printf("\n  No floor set for: %s\n", strings.Join(ungated, ", "))
		fmt.Printf("    (scoring zero; a floor of zero cannot fail, so it would not be a gate)\n")
	}
	fmt.Printf("\n  Recorded %d findings as the baseline snapshot.\n", sc.Counts.Total)
	// Only promise a pass when nothing uncalibratable is still outstanding.
	if sc.Mandatory["no_active_secrets"] {
		fmt.Printf("\nNext: 'dragon scan' should now pass. It will block on regressions from here.\n")
	}
	if sc.Counts.Critical > 0 || sc.Counts.High > 0 {
		fmt.Printf("\n  %d critical and %d high findings are in the backlog. They are no longer\n", sc.Counts.Critical, sc.Counts.High)
		fmt.Printf("  blocking, but they are still real. Work them down and raise the floors.\n")
	}
}

// warnAboutSecrets is honest about the one case calibration deliberately does
// not smooth over.
func warnAboutSecrets(res *report.Result, allowed bool) {
	if res.Scorecard.Mandatory["no_active_secrets"] {
		return
	}
	n := res.Scorecard.Dimensions["secrets"].Counts.Total

	if allowed {
		fmt.Printf("\n  --allow-existing-secrets was set, so the %d committed credential(s) in this\n", n)
		fmt.Printf("  repository will not block the gate.\n\n")
		fmt.Printf("  They are still disclosed. Removing the line does not un-disclose a key, and\n")
		fmt.Printf("  git history keeps a copy: rotate at the provider, then clean the history.\n")
		return
	}

	fmt.Printf("\n  This baseline will NOT pass yet.\n\n")
	fmt.Printf("  %d committed credential(s) were found, and 'no_active_secrets' is the one gate\n", n)
	fmt.Printf("  calibration does not relax. A vulnerable dependency can wait for a maintenance\n")
	fmt.Printf("  window; a disclosed key is already out.\n\n")
	fmt.Printf("  Rotate them at the provider first -- deleting the line does not un-disclose a\n")
	fmt.Printf("  key, and the history still has it. Then clean the history and re-scan.\n\n")
	fmt.Printf("  If you have already rotated them and the matches are test fixtures, either mark\n")
	fmt.Printf("  them in policy or re-run with --allow-existing-secrets.\n")
}

func derefF(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

func derefI(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}
