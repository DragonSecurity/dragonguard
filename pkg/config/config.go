// Package config loads .dragon.yaml, the per-project description of what is
// being scanned and how much it matters.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultFilenames are searched, in order, when no --config is given.
var DefaultFilenames = []string{".dragon.yaml", ".dragon.yml", "dragon.yaml"}

// Asset describes the thing being scanned. This is the context that turns a
// CVSS number into an operational priority: the same vulnerability in an
// internet-facing production payments service and in a developer's local
// scratch tool are not the same problem.
type Asset struct {
	Name string `yaml:"name" json:"name"`
	// Environment is one of production, staging, development.
	Environment string `yaml:"environment" json:"environment"`
	// Criticality is one of critical, high, medium, low.
	Criticality string `yaml:"criticality" json:"criticality"`
	// InternetExposed reports whether an unauthenticated attacker can reach it.
	InternetExposed bool `yaml:"internet_exposed" json:"internet_exposed"`
	// HandlesPII / HandlesPayments raise the cost of a breach.
	HandlesPII      bool     `yaml:"handles_pii" json:"handles_pii"`
	HandlesPayments bool     `yaml:"handles_payments" json:"handles_payments"`
	Owner           string   `yaml:"owner,omitempty" json:"owner,omitempty"`
	Tags            []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// EngineConfig toggles and tunes a single scanner adapter.
type EngineConfig struct {
	Enabled *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Args    []string `yaml:"args,omitempty" json:"args,omitempty"`
	// Rules points an engine at a ruleset (OpenGrep config, Trivy policy dir).
	Rules []string `yaml:"rules,omitempty" json:"rules,omitempty"`
	// Timeout in seconds; 0 means the engine default.
	Timeout int `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// IsEnabled reports the toggle, defaulting to on when unset.
func (e EngineConfig) IsEnabled() bool { return e.Enabled == nil || *e.Enabled }

// Config is the root of .dragon.yaml.
type Config struct {
	Version string `yaml:"version" json:"version"`
	Project string `yaml:"project" json:"project"`

	Asset Asset `yaml:"asset" json:"asset"`

	// Engines is keyed by scanner name: trivy, opengrep, gitleaks, ...
	Engines map[string]EngineConfig `yaml:"engines,omitempty" json:"engines,omitempty"`

	// Policies lists policy pack files or directories. Relative paths resolve
	// against the config file's directory.
	Policies []string `yaml:"policies,omitempty" json:"policies,omitempty"`

	// Baseline is the path to the baseline (circuit breaker) definition.
	Baseline string `yaml:"baseline,omitempty" json:"baseline,omitempty"`

	// Ignore lists path globs excluded from all engines.
	//
	// Enforced by pkg/ignore over the findings every engine returns, not only
	// by the per-engine exclude flags. Those flags are an optimisation --
	// Gitleaks has none at all, and --skip-dirs cannot exclude a single file
	// -- so relying on them alone made the list mean something different for
	// each engine.
	//
	// A pattern with no "/" matches any path segment at any depth; a pattern
	// containing "/" is anchored at the scan root and covers that path and
	// everything beneath it. "*" and "?" glob within a segment, "**" spans
	// segments.
	Ignore []string `yaml:"ignore,omitempty" json:"ignore,omitempty"`

	// StateDir holds previous scorecards, which the regression gate needs.
	StateDir string `yaml:"state_dir,omitempty" json:"state_dir,omitempty"`

	// Offline disables every network call, including EPSS/KEV refresh.
	Offline bool `yaml:"offline,omitempty" json:"offline,omitempty"`

	// ScanIgnoredFiles includes findings from files .gitignore excludes.
	//
	// Off by default. A finding is a security problem because the code is
	// disclosed, and a gitignored file was never committed -- so a credential
	// in a developer's local .env is not a disclosure, and reporting it as a
	// critical one pushes real findings off the page. Turn it on when the
	// working tree itself is the artifact, such as when scanning a build
	// context that will be COPYed into an image.
	ScanIgnoredFiles bool `yaml:"scan_ignored_files,omitempty" json:"scan_ignored_files,omitempty"`

	// VerifySecrets enables live-credential verification: a detected secret is
	// sent to its own issuer's read-only identity endpoint to establish
	// whether it still authenticates. Off by default. The plaintext never
	// leaves the scanning process and is never stored -- only the verdict is
	// attached to the finding.
	VerifySecrets bool `yaml:"verify_secrets,omitempty" json:"verify_secrets,omitempty"`

	// Dir is the directory the config was loaded from. Not serialized.
	Dir string `yaml:"-" json:"-"`
	// Path is where the config was loaded from, empty if defaults were used.
	Path string `yaml:"-" json:"-"`
}

// Default returns the configuration used when a project has no .dragon.yaml.
//
// The defaults are deliberately conservative about context: an unknown asset
// is treated as production, because assuming otherwise silently downgrades
// real risk on every unconfigured repository.
func Default() *Config {
	return &Config{
		Version: "dragonguard/v1",
		Project: "unnamed",
		Asset: Asset{
			Name:        "unnamed",
			Environment: "production",
			Criticality: "medium",
		},
		StateDir: ".dragon",
	}
}

// Load reads a config from an explicit path, or discovers one by walking up
// from dir. A project with no config gets Default rather than an error.
func Load(path, dir string) (*Config, error) {
	if path == "" {
		path = discover(dir)
	}
	if path == "" {
		c := Default()
		c.Dir = dir
		if abs, err := filepath.Abs(dir); err == nil {
			c.Dir = abs
			c.Project = filepath.Base(abs)
			c.Asset.Name = c.Project
		}
		return c, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	c := Default()
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	c.Path = abs
	c.Dir = filepath.Dir(abs)
	if c.Asset.Name == "" {
		c.Asset.Name = c.Project
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// discover walks up from dir looking for a config file, stopping at the
// filesystem root or a .git directory boundary.
func discover(dir string) string {
	cur, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		for _, name := range DefaultFilenames {
			p := filepath.Join(cur, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return ""
		}
		cur = parent
	}
}

var (
	validEnvironments = map[string]bool{"production": true, "staging": true, "development": true, "test": true}
	validCriticality  = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
)

// Validate rejects a config that would silently misprice risk. An unknown
// environment string is a typo, and a typo that quietly reads as "not
// production" is exactly the failure this whole tool exists to prevent.
func (c *Config) Validate() error {
	env := strings.ToLower(c.Asset.Environment)
	if env == "" {
		env = "production"
	}
	if !validEnvironments[env] {
		return fmt.Errorf("asset.environment %q is not one of production, staging, development, test", c.Asset.Environment)
	}
	c.Asset.Environment = env

	crit := strings.ToLower(c.Asset.Criticality)
	if crit == "" {
		crit = "medium"
	}
	if !validCriticality[crit] {
		return fmt.Errorf("asset.criticality %q is not one of critical, high, medium, low", c.Asset.Criticality)
	}
	c.Asset.Criticality = crit
	return nil
}

// Resolve turns a config-relative path into an absolute one.
func (c *Config) Resolve(p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir, p)
}

// StatePath returns the absolute state directory.
func (c *Config) StatePath() string {
	sd := c.StateDir
	if sd == "" {
		sd = ".dragon"
	}
	return c.Resolve(sd)
}
