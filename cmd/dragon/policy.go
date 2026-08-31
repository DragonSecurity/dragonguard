package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/policy"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Author and test Dragon Policies",
	}
	cmd.AddCommand(newPolicyTestCmd(), newPolicyListCmd(), newPolicyEvalCmd())
	return cmd
}

func newPolicyTestCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "test [path...]",
		Short: "Compile and validate policy packs",
		Long: `Compiles every rule and proves it evaluates against a well-formed finding.

The second check matters as much as the first. CEL types a map lookup as dyn,
so a misspelled field name compiles cleanly and then silently never matches --
which means a policy you believe is enforcing something is not. Running each
rule against a canonical input turns that into an error you see here, rather
than a gap you discover after an incident.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := policyPaths(args, configPath)
			if err != nil {
				return err
			}
			if len(paths) == 0 {
				return fmt.Errorf("no policy packs found: pass a path or set `policies:` in .dragon.yaml")
			}

			eng, err := policy.NewEngine()
			if err != nil {
				return err
			}
			if err := eng.LoadPaths(paths); err != nil {
				fmt.Fprintf(os.Stderr, "FAIL  %v\n", err)
				return gateFailure{code: 1}
			}

			for _, pack := range eng.Packs() {
				fmt.Printf("OK    %s (%s): %d rules\n",
					pack.Metadata.Name, filepath.Base(pack.Path), len(pack.Rules))
			}
			enabled := 0
			for _, r := range eng.Rules() {
				if r.IsEnabled() {
					enabled++
				}
			}
			fmt.Printf("\n%d rules compiled, %d enabled.\n", len(eng.Rules()), enabled)
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	return cmd
}

func newPolicyListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list [path...]",
		Short: "List loaded policy rules and the CEL they compile to",
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := policyPaths(args, configPath)
			if err != nil {
				return err
			}
			eng, err := policy.NewEngine()
			if err != nil {
				return err
			}
			if err := eng.LoadPaths(paths); err != nil {
				return err
			}
			for _, r := range eng.Rules() {
				status := ""
				if !r.IsEnabled() {
					status = "  (disabled)"
				}
				fmt.Printf("%-34s %-7s%s\n", r.ID, r.Then.Decision, status)
				if r.Description != "" {
					fmt.Printf("  %s\n", r.Description)
				}
				// Showing the compiled CEL is what keeps a rule authored
				// through a form as auditable as one written by hand.
				fmt.Printf("  when: %s\n", r.Source())
				if len(r.Then.Actions) > 0 {
					fmt.Printf("  then: %s\n", strings.Join(r.Then.Actions, ", "))
				}
				fmt.Println()
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	return cmd
}

func newPolicyEvalCmd() *cobra.Command {
	var configPath, findingPath string
	cmd := &cobra.Command{
		Use:   "eval [path...]",
		Short: "Evaluate policies against a finding supplied as JSON or YAML",
		Long: `Reads one finding from --finding (or stdin) and reports which rules match.

This is the unit test for a policy: state the finding you are worried about,
and see whether your rules actually catch it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			paths, err := policyPaths(args, configPath)
			if err != nil {
				return err
			}
			eng, err := policy.NewEngine()
			if err != nil {
				return err
			}
			if err := eng.LoadPaths(paths); err != nil {
				return err
			}

			var raw []byte
			if findingPath == "" || findingPath == "-" {
				raw, err = os.ReadFile("/dev/stdin")
			} else {
				raw, err = os.ReadFile(findingPath)
			}
			if err != nil {
				return fmt.Errorf("read finding: %w", err)
			}

			var f finding.Finding
			if err := yaml.Unmarshal(raw, &f); err != nil {
				if err2 := json.Unmarshal(raw, &f); err2 != nil {
					return fmt.Errorf("parse finding: %w", err)
				}
			}
			f.Normalize(f.LastSeen)

			cfg, err := config.Load(configPath, ".")
			if err != nil {
				return err
			}

			ev := eng.Evaluate(&f, cfg.Asset, map[string]any{"project": cfg.Project})
			fmt.Printf("decision: %s\n", ev.Decision)
			if len(ev.Results) == 0 {
				fmt.Println("no rules matched")
			}
			for _, r := range ev.Results {
				fmt.Printf("  matched %-30s -> %s", r.RuleID, r.Decision)
				if r.RiskBoost != 0 {
					fmt.Printf("  risk %+0.f", r.RiskBoost)
				}
				if len(r.Actions) > 0 {
					fmt.Printf("  actions: %s", strings.Join(r.Actions, ", "))
				}
				fmt.Println()
			}
			for _, e := range ev.Errors {
				fmt.Fprintf(os.Stderr, "  error: %s\n", e)
			}
			if len(ev.Errors) > 0 {
				return gateFailure{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	cmd.Flags().StringVar(&findingPath, "finding", "-", "finding to evaluate (JSON or YAML; - for stdin)")
	return cmd
}

// policyPaths resolves explicit arguments, then config, then convention.
func policyPaths(args []string, configPath string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	cfg, err := config.Load(configPath, ".")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range cfg.Policies {
		out = append(out, cfg.Resolve(p))
	}
	if len(out) > 0 {
		return out, nil
	}
	for _, candidate := range []string{"policies", ".dragon/policies"} {
		p := cfg.Resolve(candidate)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return []string{p}, nil
		}
	}
	return nil, nil
}
