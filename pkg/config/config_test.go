package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// An unconfigured project must be treated as production. Assuming otherwise
// silently understates risk on every repository nobody has got to yet.
func TestUnconfiguredProjectDefaultsToProduction(t *testing.T) {
	c, err := Load("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if c.Asset.Environment != "production" {
		t.Errorf("environment = %q, an unconfigured asset must default to production", c.Asset.Environment)
	}
}

// A typo in the environment must be an error, not a silent downgrade to
// "not production" -- which is the exact failure this tool exists to prevent.
func TestInvalidEnvironmentIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, ".dragon.yaml", "project: x\nasset:\n  environment: prodcution\n")

	if _, err := Load(p, dir); err == nil {
		t.Fatal("a misspelled environment must be rejected, not silently treated as non-production")
	}
}

func TestInvalidCriticalityIsRejected(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, ".dragon.yaml", "project: x\nasset:\n  criticality: extreme\n")
	if _, err := Load(p, dir); err == nil {
		t.Fatal("an unrecognized criticality must be rejected")
	}
}

func TestEnvironmentIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, ".dragon.yaml", "project: x\nasset:\n  environment: Production\n  criticality: HIGH\n")
	c, err := Load(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Asset.Environment != "production" || c.Asset.Criticality != "high" {
		t.Errorf("case was not normalized: %+v", c.Asset)
	}
}

func TestConfigIsDiscoveredFromASubdirectory(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".dragon.yaml", "project: rooted\nasset:\n  environment: staging\n")
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	c, err := Load("", sub)
	if err != nil {
		t.Fatal(err)
	}
	if c.Project != "rooted" {
		t.Errorf("project = %q, config should be discovered by walking up", c.Project)
	}
}

func TestRelativePathsResolveAgainstTheConfigDirectory(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, ".dragon.yaml", "project: x\npolicies:\n  - custom/policies\nstate_dir: .state\n")
	c, err := Load(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "custom", "policies")
	if got := c.Resolve(c.Policies[0]); got != want {
		t.Errorf("resolved to %q, want %q", got, want)
	}
	if got := c.StatePath(); got != filepath.Join(dir, ".state") {
		t.Errorf("state path = %q", got)
	}
}

func TestEngineEnabledDefaultsToTrue(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, ".dragon.yaml", "project: x\nengines:\n  trivy: {}\n  opengrep:\n    enabled: false\n")
	c, err := Load(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Engines["trivy"].IsEnabled() {
		t.Error("an engine with no explicit toggle must default to enabled")
	}
	if c.Engines["opengrep"].IsEnabled() {
		t.Error("enabled: false must disable the engine")
	}
}
