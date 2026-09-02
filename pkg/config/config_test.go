package config

import (
	"os"
	"path/filepath"
	"strings"
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

// The configuration reference is only worth having if it is true. This parses
// the complete example out of docs/configuration.md and loads it through the
// real loader, so a field that gets renamed, removed or newly validated fails
// here rather than in the first user's terminal.
func TestDocumentedExampleConfigStillLoads(t *testing.T) {
	md, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read the configuration reference: %v", err)
	}
	_, block, ok := strings.Cut(string(md), "```yaml\n")
	if !ok {
		t.Fatal("docs/configuration.md has no yaml example")
	}
	block, _, ok = strings.Cut(block, "```")
	if !ok {
		t.Fatal("the yaml example in docs/configuration.md is unterminated")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("the documented example does not load: %v", err)
	}

	// Spot-check the fields the document makes specific claims about.
	if cfg.Asset.Environment != "production" || cfg.Asset.Criticality != "critical" {
		t.Errorf("asset context did not survive the round trip: %+v", cfg.Asset)
	}
	if !cfg.Asset.InternetExposed || !cfg.Asset.HandlesPII {
		t.Error("asset booleans did not load")
	}
	for _, name := range []string{"trivy", "opengrep", "gitleaks", "osv", "zap", "schemathesis"} {
		if got, ok := cfg.Engines[name]; !ok || !got.IsEnabled() {
			t.Errorf("engine %s should be present and enabled", name)
		}
	}
	// The two-entry schemathesis shape is the document's headline warning.
	if got := cfg.Engines["schemathesis"].Rules; len(got) != 2 {
		t.Errorf("schemathesis rules = %v, want two entries", got)
	}
	if got := cfg.Engines["zap"].Rules; len(got) != 1 {
		t.Errorf("zap rules = %v, want one entry", got)
	}
	if cfg.ScanIgnoredFiles || cfg.VerifySecrets || cfg.Offline {
		t.Error("the documented switches should all be false")
	}
}

// The reference documents a second, shorter engines block to show that a
// present-but-unset key is enabled and that `enabled: false` is the only way
// to turn an engine off. Both claims are load-bearing, so both are checked
// against the loader rather than trusted.
func TestDocumentedEnabledShorthandBehavesAsDocumented(t *testing.T) {
	md, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := strings.Split(string(md), "```yaml\n")
	if len(blocks) < 3 {
		t.Fatal("expected a second yaml example in docs/configuration.md")
	}
	block, _, ok := strings.Cut(blocks[2], "```")
	if !ok {
		t.Fatal("the second yaml example is unterminated")
	}

	dir := t.TempDir()
	cfg, err := Load(write(t, dir, ".dragon.yaml", "version: dragonguard/v1\n"+block), dir)
	if err != nil {
		t.Fatalf("the documented shorthand does not load: %v", err)
	}
	if got := cfg.Engines["trivy"]; !got.IsEnabled() {
		t.Error("enabled: true should be enabled")
	}
	if got, ok := cfg.Engines["gitleaks"]; !ok || !got.IsEnabled() {
		t.Error("an engine block with no enabled key should be enabled")
	}
	if got := cfg.Engines["osv"]; got.IsEnabled() {
		t.Error("enabled: false should turn an engine off")
	}
}

// A licence approval with no reason is the failure this field exists to
// prevent: it records the conclusion and loses the reasoning, so when somebody
// later vendors and patches that dependency, nothing reopens the question.
func TestLicenceApprovalNeedsAReason(t *testing.T) {
	c := &Config{Licenses: LicensePolicy{Allow: []LicenseDecision{{ID: "MPL-2.0"}}}}
	err := c.Validate()
	if err == nil {
		t.Fatal("an approval with no reason was accepted")
	}
	if !strings.Contains(err.Error(), "reason") {
		t.Errorf("error does not say what is missing: %v", err)
	}
}

// The identifier is interpolated into a CEL string literal, so anything that
// could close the quote is refused at load rather than escaped later.
func TestLicenceIDIsNotAnExpression(t *testing.T) {
	for _, id := range []string{`MPL-2.0" || true || "`, "MPL\n2.0", `a\"b`, ""} {
		c := &Config{Licenses: LicensePolicy{Allow: []LicenseDecision{{ID: id, Reason: "x"}}}}
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %q as a licence identifier", id)
		}
	}
}

// SPDX identifiers, including the ones with spaces and plus signs.
func TestRealLicenceIdentifiersAreAccepted(t *testing.T) {
	for _, id := range []string{"MPL-2.0", "BlueOak-1.0.0", "Apache-2.0 WITH LLVM-exception", "GPL-2.0+", "0BSD"} {
		c := &Config{Licenses: LicensePolicy{Allow: []LicenseDecision{{ID: id, Reason: "reviewed"}}}}
		if err := c.Validate(); err != nil {
			t.Errorf("rejected %q: %v", id, err)
		}
	}
}

// Listing a licence as both approved and refused is a contradiction, and
// resolving it silently would mean the gate's behaviour depends on which list
// happened to be evaluated first.
func TestALicenceCannotBeBothAllowedAndDenied(t *testing.T) {
	c := &Config{Licenses: LicensePolicy{
		Allow: []LicenseDecision{{ID: "MPL-2.0", Reason: "consumed unmodified"}},
		Deny:  []LicenseDecision{{ID: "mpl-2.0", Reason: "no copyleft"}},
	}}
	if err := c.Validate(); err == nil {
		t.Error("a licence listed in both allow and deny was accepted")
	}
}
