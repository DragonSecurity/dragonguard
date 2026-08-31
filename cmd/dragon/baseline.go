package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/state"
)

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage the acceptable-posture definition and its snapshot",
	}
	cmd.AddCommand(newBaselineInitCmd(), newBaselineCalibrateCmd(), newBaselineShowCmd(), newBaselineRecordCmd())
	return cmd
}

func newBaselineInitCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter baseline definition",
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				out = ".dragon-baseline.yaml"
			}
			if _, err := os.Stat(out); err == nil {
				return fmt.Errorf("%s already exists; remove it or pass --output", out)
			}
			if err := os.WriteFile(out, []byte(starterBaseline), 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote %s\n\nIt blocks only what is indefensible anywhere and ratchets the rest.\nRun `dragon scan --record` once to establish the snapshot it compares against.\n", out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "where to write the baseline")
	return cmd
}

func newBaselineShowCmd() *cobra.Command {
	var configPath, path string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the effective baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath, ".")
			if err != nil {
				return err
			}
			bl, err := loadBaseline(path, cfg)
			if err != nil {
				return err
			}
			src := bl.Path
			if src == "" {
				src = "(built-in default)"
			}
			fmt.Printf("# source: %s\n", src)
			enc := yaml.NewEncoder(os.Stdout)
			enc.SetIndent(2)
			defer enc.Close()
			return enc.Encode(bl)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	cmd.Flags().StringVarP(&path, "baseline", "b", "", "path to the baseline definition")
	return cmd
}

func newBaselineRecordCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the recorded snapshot the regression gate compares against",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath, ".")
			if err != nil {
				return err
			}
			store := state.New(cfg.StatePath())
			branch, _ := gitBranch()
			snap, err := store.Load(branch)
			if err != nil {
				return err
			}
			if snap == nil || snap.Scorecard == nil {
				fmt.Printf("No snapshot recorded in %s.\nRun `dragon scan --record` to establish one.\n",
					filepath.Clean(cfg.StatePath()))
				return nil
			}
			sc := snap.Scorecard
			fmt.Printf("Recorded %s\n", sc.Timestamp.Format("2006-01-02 15:04:05 MST"))
			if sc.Branch != "" {
				fmt.Printf("Branch   %s\n", sc.Branch)
			}
			if sc.Commit != "" {
				fmt.Printf("Commit   %s\n", short(sc.Commit))
			}
			fmt.Printf("Posture  %.0f/100\n", sc.Score)
			fmt.Printf("Findings %d recorded\n", len(snap.Fingerprints))
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	return cmd
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

const starterBaseline = `apiVersion: dragonguard/v1
kind: Baseline
metadata:
  name: default
  description: Acceptable security posture for this project.

# Hard gates: never acceptable, at any score.
mandatory:
  - no_active_secrets
  - no_kev_in_production
  - no_reachable_critical_vulnerability

critical:
  maximum_new: 0
high:
  maximum_new: 2

# Regression gate: the ratchet. This is the gate a legacy codebase can pass
# on day one, which is why it is the one that actually gets adopted.
maximum_score_regression: 5

# Score gates: absolute floors. Left unset deliberately -- run 'dragon scan'
# a few times first, see where this project actually sits, then set a floor
# just below it and raise it over time. A floor guessed in advance is a floor
# somebody disables in a week.
#
# minimum_score: 80
# dimensions:
#   secrets:
#     minimum: 100
#     required: true
#   dependencies:
#     minimum: 75
#     maximum_regression: 3

block_on_policy_deny: true

# Refuse to pass when engines were unavailable or intelligence could not be
# fetched. A gate that passes because it could not look is not a gate.
allow_degraded: false

# Set while introducing the gate to a team: reports blocking conditions
# without enforcing them.
warn_only: false
`
