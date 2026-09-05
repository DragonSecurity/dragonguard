package config

import (
	"os"
	"path/filepath"
	"reflect"
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

// The documented example is the thing most people copy, and it drifted: it
// claimed to set every field while two of them sat commented out, which left
// it ambiguous whether `licenses` was top level or belonged under an engine.
// Documentation that is not executed is documentation that is eventually
// wrong, so the reference's own example is loaded here as a config.
func TestTheDocumentedExampleIsAValidConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read the configuration reference: %v", err)
	}
	block := yamlBlockAfter(t, string(raw), "## A complete example")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("the documented example does not load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the documented example does not validate: %v", err)
	}

	// Loading proves it parses. These prove the documented keys reach real
	// fields: a misspelled key unmarshals to nothing and would pass silently.
	if cfg.DefaultBranch == "" {
		t.Error("default_branch in the example did not reach Config.DefaultBranch")
	}
	if len(cfg.Licenses.Allow) == 0 || cfg.Licenses.Allow[0].ID == "" {
		t.Error("licenses.allow in the example did not reach Config.Licenses; is it nested under the wrong key?")
	}
	if len(cfg.Licenses.Deny) == 0 {
		t.Error("licenses.deny in the example did not reach Config.Licenses")
	}
	if len(cfg.Ignore) == 0 {
		t.Error("ignore in the example did not reach Config.Ignore")
	}
	if len(cfg.Engines) == 0 {
		t.Error("engines in the example did not reach Config.Engines")
	}
	if cfg.Asset.Environment == "" || cfg.Asset.Criticality == "" {
		t.Error("asset context in the example did not reach Config.Asset")
	}
	if len(cfg.Accept) == 0 || cfg.Accept[0].ApprovedBy == "" {
		t.Error("accept in the example did not reach Config.Accept")
	}
	if len(cfg.Ships) == 0 {
		t.Error("ships in the example did not reach Config.Ships")
	}
	if cfg.SupplyChain.MinScorecard == 0 || cfg.SupplyChain.QuietBelow == 0 {
		t.Error("supply_chain in the example did not reach Config.SupplyChain")
	}
	if cfg.Licenses.Allow[0].ApprovedBy == "" {
		t.Error("licenses.allow[].approved_by in the example did not reach LicenseDecision")
	}
}

// yamlBlockAfter returns the first fenced yaml block following a heading.
func yamlBlockAfter(t *testing.T, doc, heading string) string {
	t.Helper()
	i := strings.Index(doc, heading)
	if i < 0 {
		t.Fatalf("heading %q is not in the reference any more", heading)
	}
	rest := doc[i:]
	start := strings.Index(rest, "```yaml\n")
	if start < 0 {
		t.Fatalf("no yaml block follows %q", heading)
	}
	rest = rest[start+len("```yaml\n"):]
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatalf("unterminated yaml block after %q", heading)
	}
	return rest[:end]
}

// An exception with no reason and no author is the thing this surface exists to
// prevent: a line in a config that silences a finding and answers no question
// about why, so nobody can ever decide whether it is still true.
func TestAnAcceptanceMustSayWhyAndWhoDecided(t *testing.T) {
	good := Acceptance{Finding: "GO-1", Reason: "no upstream fix", ApprovedBy: "security"}

	for name, a := range map[string]Acceptance{
		"no selector":  {Reason: "x", ApprovedBy: "y"},
		"no reason":    {Finding: "GO-1", ApprovedBy: "y"},
		"no approver":  {Finding: "GO-1", Reason: "x"},
		"bad date":     {Finding: "GO-1", Reason: "x", ApprovedBy: "y", Expires: "next tuesday"},
		"quote in sel": {Finding: `GO-1" || true || "`, Reason: "x", ApprovedBy: "y"},
	} {
		if err := validateAcceptances([]Acceptance{a}); err == nil {
			t.Errorf("%s: accepted an entry that should have been refused", name)
		}
	}

	if err := validateAcceptances([]Acceptance{good}); err != nil {
		t.Errorf("a complete acceptance was refused: %v", err)
	}
	if err := validateAcceptances([]Acceptance{{
		Package: "@scope/pkg", Reason: "x", ApprovedBy: "y", Expires: "2027-01-01",
	}}); err != nil {
		t.Errorf("a scoped npm package name was refused: %v", err)
	}
}

func TestSupplyChainThresholdsMustBeOnTheScorecardScale(t *testing.T) {
	if err := (SupplyChainPolicy{MinScorecard: 11}).validate(); err == nil {
		t.Error("a threshold above 10 is not a Scorecard value")
	}
	if err := (SupplyChainPolicy{MinScorecard: -1}).validate(); err == nil {
		t.Error("a negative threshold is not a Scorecard value")
	}
	if err := (SupplyChainPolicy{MinScorecard: 6, QuietBelow: 7}).validate(); err != nil {
		t.Errorf("a valid pair was refused: %v", err)
	}
}

// The failure this replaces: a configuration written against a newer release
// loads on an older build, the setting is plainly there in the file, and the
// scan behaves exactly as though it were absent. Nothing on screen
// distinguishes that from a typo, or from the feature not working.
func TestASettingThisBuildDoesNotUnderstandIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example
# A block from a future release, and a typo, and a nested one.
teleport: true
licenses:
  alow:
    - id: MPL-2.0
      reason: consumed unmodified
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		// Reported, never refused: a config written for a newer DragonGuard
		// must still run on an older one, or a warning becomes an outage.
		t.Fatalf("an unrecognized key must not stop the config loading: %v", err)
	}

	got := map[string]bool{}
	for _, k := range cfg.Unrecognized {
		got[k] = true
	}
	for _, want := range []string{"teleport", "alow"} {
		if !got[want] {
			t.Errorf("%q was ignored in silence; Unrecognized = %v", want, cfg.Unrecognized)
		}
	}
	if cfg.UnrecognizedNote() == "" {
		t.Error("the scan must be able to say which settings it ignored")
	}
}

// The other half: a configuration this build fully understands must not
// produce a warning, or the warning stops being read.
func TestAConfigurationThisBuildUnderstandsWarnsAboutNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example
accept:
  - finding: GO-2026-5932
    reason: unmaintained upstream, no replacement
    approved_by: the security team
ships:
  - .
supply_chain:
  min_scorecard: 4.0
licenses:
  allow:
    - id: MPL-2.0
      reason: consumed unmodified
      approved_by: the security team
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Unrecognized) != 0 {
		t.Errorf("a fully understood configuration reported %v as unrecognized", cfg.Unrecognized)
	}
}

// "Every field below is optional except version. This example sets all of
// them" is a claim the document makes about itself, and it has now been wrong
// twice -- once when licenses arrived and once when accept, ships and
// supply_chain did. A reader copying from it cannot tell what it left out.
//
// So the claim is checked rather than trusted: every top-level key the loader
// understands must appear in the example.
func TestTheDocumentedExampleSetsEveryTopLevelKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read the configuration reference: %v", err)
	}
	block := yamlBlockAfter(t, string(raw), "## A complete example")

	documented := map[string]bool{}
	for _, line := range strings.Split(block, "\n") {
		// Top level only: a key at column zero, commented or not.
		trimmed := strings.TrimPrefix(line, "# ")
		if trimmed != line && strings.HasPrefix(line, "# ") {
			// A commented top-level key still counts as documented; ships: is
			// shown that way in dragon init for the same reason.
			line = trimmed
		}
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-") {
			continue
		}
		if k, _, ok := strings.Cut(line, ":"); ok {
			documented[strings.TrimSpace(k)] = true
		}
	}

	typ := reflect.TypeOf(Config{})
	var missing []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		if !documented[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the complete example claims to set every field but omits: %s",
			strings.Join(missing, ", "))
	}
}
