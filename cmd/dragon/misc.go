package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/pipeline"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

func gitBranch() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func newEnginesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "engines",
		Short: "Show which security engines are available on this machine",
		Long: `Lists every engine adapter and whether it can run here.

A missing engine degrades a scan rather than failing it, so this is the
command that tells you which dimensions your gate is currently blind to.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Availability depends on configuration as well as installation,
			// so the real project config is loaded rather than a bare default.
			dir, _ := os.Getwd()
			cfg, err := config.Load("", dir)
			if err != nil {
				return err
			}
			target := scanner.Target{Dir: dir, Config: cfg}

			reg := pipeline.DefaultRegistry()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ENGINE\tSTATUS\tCOVERS")
			for _, s := range reg.All() {
				ok, reason := s.Available(cmd.Context(), target)
				status := "available"
				if !ok {
					status = reason
				}
				var cats []string
				for _, c := range s.Categories() {
					cats = append(cats, string(c))
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", s.Name(), status, strings.Join(cats, ", "))
			}
			return w.Flush()
		},
	}
}

func newInitCmd() *cobra.Command {
	var force bool
	return &cobra.Command{
		Use:   "init",
		Short: "Create .dragon.yaml, a starter baseline and a policy pack",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := os.Getwd()
			if err != nil {
				return err
			}
			name := filepath.Base(dir)

			files := map[string]string{
				".dragon.yaml":          fmt.Sprintf(starterConfig, name, name),
				".dragon-baseline.yaml": starterBaseline,
			}
			for path, content := range files {
				if _, err := os.Stat(path); err == nil && !force {
					fmt.Printf("skip  %s (already exists)\n", path)
					continue
				}
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					return err
				}
				fmt.Printf("write %s\n", path)
			}

			if err := os.MkdirAll("policies", 0o755); err != nil {
				return err
			}
			pp := filepath.Join("policies", "dragon-recommended.yaml")
			if _, err := os.Stat(pp); err != nil || force {
				if err := os.WriteFile(pp, []byte(recommendedPolicies), 0o644); err != nil {
					return err
				}
				fmt.Printf("write %s\n", pp)
			} else {
				fmt.Printf("skip  %s (already exists)\n", pp)
			}

			fmt.Printf(`
Next:

  dragon engines                  see which engines are available
  dragon scan                     scan and evaluate the gate
  dragon scan --record            record the baseline the ratchet compares to

Edit .dragon.yaml first. The asset context -- environment, criticality,
internet exposure -- is what turns a CVSS number into a priority, and the
defaults assume production because assuming otherwise silently understates
real risk.
`)
			return nil
		},
	}
}

const starterConfig = `version: dragonguard/v1
project: %s

# Asset context. This is what separates "CVSS 9.8" from "fix this today":
# the same vulnerability is not the same problem in a public payments API and
# in an internal batch job.
asset:
  name: %s
  environment: production      # production | staging | development | test
  criticality: medium          # critical | high | medium | low
  internet_exposed: false
  handles_pii: false
  handles_payments: false
  # owner: platform-team

engines:
  trivy:
    enabled: true
  opengrep:
    enabled: true
    # Point at your own rules. Engine compatibility with Semgrep-format rules
    # is not permission to redistribute someone else's ruleset; check the
    # licence of any pack you bundle.
    rules:
      - p/security-audit
  gitleaks:
    enabled: true

policies:
  - policies

baseline: .dragon-baseline.yaml

ignore:
  - node_modules
  - vendor
  - .git

state_dir: .dragon
`

const recommendedPolicies = `apiVersion: dragonguard/v1
kind: PolicyPack
metadata:
  name: dragon-recommended
  description: The rules that mean the same thing at every organization.

rules:
  # Policies decide what to do. They never do it -- an action is a name the
  # enforcement layer resolves. That boundary is what stops a policy language
  # turning into an integration runtime.

  - id: active-credential-committed
    description: A credential reached the repository.
    when: finding.category == "SECRET"
    then:
      decision: deny
      actions: [block_merge, notify_security, create_incident]
      tags: [secret, rotate-now]
      message: >-
        A credential is present in the repository. Rotate it first: removing
        the line does not un-disclose the key, and history keeps a copy.

  - id: kev-in-production
    description: Actively exploited vulnerability in a production asset.
    when: threat.kev && asset.environment == "production"
    then:
      decision: deny
      actions: [block_merge, create_ticket, notify_security]
      risk_boost: 10
      tags: [kev, must-fix]
      message: This vulnerability is on CISA's Known Exploited Vulnerabilities list.

  - id: reachable-critical-internet-facing
    description: Critical, reachable, and exposed to the internet.
    match:
      all:
        - risk.score >= 90
        - analysis.reachable
        - asset.internet_exposed
    then:
      decision: deny
      actions: [block_merge, create_ticket]
      tags: [urgent]

  - id: high-risk-with-a-fix-available
    description: High risk, and someone can close it today.
    match:
      all:
        - risk.score >= 75
        - analysis.fix_available
        - finding.new
    then:
      decision: warn
      actions: [annotate_pr]
      tags: [fixable]
      message: A fix is available for this finding.

  - id: unmaintained-upstream-dependency
    description: Poor upstream security posture, even with no known CVE.
    match:
      all:
        - analysis.has_scorecard
        - analysis.scorecard_score < 4.0
    then:
      decision: warn
      actions: [annotate_pr]
      tags: [supply-chain]
      message: >-
        This dependency has a weak OpenSSF Scorecard. No CVE exists today, but
        the project's security practices make one more likely and slower to fix.

  # Exemptions are policy too, and belong in the same reviewed file as the
  # rules -- not in an ignore list nobody reads.
  - id: accept-dev-only-medium-risk
    description: Medium-risk findings in build-only dependencies are accepted.
    match:
      all:
        - component.dev_only
        - risk.score < 75
    then:
      decision: allow
      exempt: true
      tags: [accepted-dev-dependency]
`
