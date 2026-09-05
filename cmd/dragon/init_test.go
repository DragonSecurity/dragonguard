package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
)

// What `dragon init` writes is the first configuration most projects ever
// load, and it is a string constant that no test touched. A field renamed or
// newly validated would have shipped a starter config the tool then refuses.
func TestTheStarterConfigLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	body := fmt.Sprintf(starterConfig, "example", "example")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path, dir)
	if err != nil {
		t.Fatalf("the config dragon init writes does not load: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the config dragon init writes does not validate: %v", err)
	}
	if cfg.Project != "example" || cfg.Asset.Name != "example" {
		t.Errorf("project/asset name did not reach the config: %q/%q", cfg.Project, cfg.Asset.Name)
	}
	// The opengrep block exists to keep DragonGuard's own pack in play while
	// naming a second ruleset, which is the mistake it was added to prevent.
	if rules := cfg.Engines["opengrep"].Rules; len(rules) == 0 || rules[0] != "builtin" {
		t.Errorf("opengrep rules = %v, want builtin first", rules)
	}
}

// A commented suggestion is only a suggestion if uncommenting it works.
func TestTheCommentedShipsHintIsValidConfig(t *testing.T) {
	body := fmt.Sprintf(starterConfig, "example", "example")
	if !strings.Contains(body, "# ships:") {
		t.Fatal("the starter config no longer suggests ships:")
	}

	var uncommented []string
	for _, line := range strings.Split(body, "\n") {
		if trimmed := strings.TrimPrefix(line, "# "); strings.HasPrefix(line, "# ships:") ||
			(strings.HasPrefix(line, "#   - ") && strings.Contains(trimmed, "- ")) {
			uncommented = append(uncommented, trimmed)
			continue
		}
		uncommented = append(uncommented, line)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(strings.Join(uncommented, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path, dir)
	if err != nil {
		t.Fatalf("uncommenting the ships: hint produces a config that does not load: %v", err)
	}
	if len(cfg.Ships) != 2 {
		t.Errorf("ships = %v, want the two suggested patterns", cfg.Ships)
	}
}
