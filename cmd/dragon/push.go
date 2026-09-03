package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/pipeline"
	"github.com/DragonSecurity/dragonguard/pkg/platform"
)

func newPushCmd() *cobra.Command {
	var (
		configPath string
		serverURL  string
		apiKey     string
		project    string
		branch     string
		commit     string
		trigger    string
		prNumber   int
		record     bool
		offline    bool
		quiet      bool
		timeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "push [path]",
		Short: "Scan and submit the results to a DragonGuard server",
		Long: `Push runs the engines locally and sends what they found to the platform,
which scores it, applies your organization's policy, and returns the verdict.

The split matters. This machine has the source code, so it has to collect the
evidence. It does not know the asset context, does not hold the policy, and in
CI it is running inside the change being judged -- so it does not get a say in
the verdict. Exit status is whatever the server decided.

Credentials come from --api-key or DRAGON_API_KEY, and the server from
--server or DRAGON_SERVER. Prefer the environment variables: a key on the
command line ends up in shell history and in CI logs.`,
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

			if serverURL == "" {
				serverURL = os.Getenv("DRAGON_SERVER")
			}
			if apiKey == "" {
				apiKey = os.Getenv("DRAGON_API_KEY")
			}
			if serverURL == "" {
				return fmt.Errorf("no server configured: pass --server or set DRAGON_SERVER")
			}
			if apiKey == "" {
				return fmt.Errorf("no API key configured: pass --api-key or set DRAGON_API_KEY")
			}

			cfg, err := config.Load(configPath, absDir)
			if err != nil {
				return err
			}
			if project == "" {
				project = cfg.Project
			}
			if project == "" {
				return fmt.Errorf("no project: pass --project or set `project:` in .dragon.yaml")
			}

			progress := func(string) {}
			if !quiet {
				progress = func(m string) { fmt.Fprintf(os.Stderr, "  %s\n", m) }
			}

			// The local gate is not evaluated here: the server's verdict is
			// the one that counts, so a permissive local baseline cannot be
			// used to wave a change through.
			res, err := pipeline.Run(cmd.Context(), pipeline.Options{
				Dir:           absDir,
				Config:        cfg,
				Offline:       offline,
				EngineTimeout: timeout,
				Progress:      progress,
			})
			if err != nil {
				return err
			}

			req := platform.IngestRequest{
				Branch:         orEmptyStr(branch, res.Scorecard.Branch),
				Commit:         orEmptyStr(commit, res.Scorecard.Commit),
				Trigger:        orEmptyStr(trigger, "cli_ingest"),
				Findings:       res.Findings,
				Components:     res.Components,
				DragonVersion:  res.DragonVersion,
				RecordBaseline: record,
			}
			if prNumber > 0 {
				req.PRNumber = &prNumber
			}
			for _, e := range res.Engines {
				switch {
				case !e.Available:
					req.EnginesUnavailable = append(req.EnginesUnavailable, e.Scanner)
				case e.Error != "":
					req.EnginesFailed = append(req.EnginesFailed, e.Scanner)
				default:
					req.EnginesRun = append(req.EnginesRun, e.Scanner)
				}
			}

			if !quiet {
				fmt.Fprintf(os.Stderr, "  submitting %d findings to %s\n", len(req.Findings), serverURL)
			}
			client := platform.New(serverURL, apiKey)
			out, err := client.Ingest(cmd.Context(), project, req)
			if err != nil {
				return err
			}

			printPushResult(out, project)
			if out.Blocked() {
				return gateFailure{code: 1}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&configPath, "config", "c", "", "path to .dragon.yaml")
	f.StringVar(&serverURL, "server", "", "DragonGuard API base URL (or DRAGON_SERVER)")
	f.StringVar(&apiKey, "api-key", "", "organization scan key (or DRAGON_API_KEY)")
	f.StringVar(&project, "project", "", "project UUID or slug (defaults to the configured project)")
	f.StringVar(&branch, "branch", "", "branch scanned (defaults to the detected branch)")
	f.StringVar(&commit, "commit", "", "commit scanned (defaults to the detected commit)")
	f.StringVar(&trigger, "trigger", "", "what caused this scan: manual, push, pull_request, schedule, cli_ingest, api")
	f.IntVar(&prNumber, "pr", 0, "pull request number, when scanning one")
	f.BoolVar(&record, "record", false, "promote this scan to the branch baseline (default branch only)")
	f.BoolVar(&offline, "offline", false, "disable local network access during scanning")
	f.BoolVarP(&quiet, "quiet", "q", false, "suppress progress output")
	f.DurationVar(&timeout, "engine-timeout", 10*time.Minute, "per-engine timeout")
	return cmd
}

func printPushResult(r *platform.IngestResponse, project string) {
	var label string
	switch r.Verdict {
	case "PASS":
		label = "Dragon Gate: PASS"
	case "WARN":
		label = "Dragon Gate: WARN"
	default:
		label = "Dragon Gate: BLOCKED"
	}

	fmt.Printf("\n%s   posture %.0f", label, r.Posture)
	if r.PreviousPosture != nil {
		fmt.Printf(" (was %.0f)", *r.PreviousPosture)
	}
	fmt.Println()

	fmt.Printf("  project  %s\n", project)
	fmt.Printf("  scan     %s\n", r.ScanID)
	fmt.Printf("  findings %d critical, %d high", r.Critical, r.High)
	if r.NewFindings > 0 {
		fmt.Printf(", %d new", r.NewFindings)
	}
	if r.FixedFindings > 0 {
		fmt.Printf(", %d fixed", r.FixedFindings)
	}
	fmt.Println()

	if r.Degraded {
		fmt.Printf("  %s\n", "evidence was incomplete: some engines did not run")
	}
	if len(r.Reasons) > 0 {
		fmt.Println()
		for _, reason := range r.Reasons {
			fmt.Printf("  - %s\n", reason)
		}
	}
	fmt.Println()
}

func orEmptyStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
