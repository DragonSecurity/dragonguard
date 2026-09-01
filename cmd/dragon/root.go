package main

import (
	"github.com/spf13/cobra"

	"github.com/DragonSecurity/dragonguard/pkg/report"
)

func newRootCmd() *cobra.Command {
	report.Version = version

	cmd := &cobra.Command{
		Use:   "dragon",
		Short: "DragonGuard - the application security quality gate",
		Long: `DragonGuard runs open-source security engines, normalizes what they find,
scores it against your actual deployment context, evaluates your policies,
and decides whether this change is fit to ship.

  Policies determine what is risky.
  Scorecards tell you where you stand.
  Baselines determine whether you can ship.

The scanners are commodities and interchangeable. The risk model, the policy
engine and the gate are the product.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
	}

	cmd.AddCommand(
		newScanCmd(),
		newPushCmd(),
		newPolicyCmd(),
		newBaselineCmd(),
		newFindingsCmd(),
		newInitCmd(),
		newEnginesCmd(),
		newUpdateCmd(),
	)
	return cmd
}
