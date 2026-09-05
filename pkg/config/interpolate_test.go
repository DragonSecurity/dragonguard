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

	got, err := interpolate([]byte(`headers:
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

	_, err := interpolate([]byte(`Authorization: "Bearer ${DG_TEST_ABSENT}"`))
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

	if _, err := interpolate([]byte(`x: "${DG_TEST_EMPTY}"`)); err == nil {
		t.Error("an exported-but-empty variable is how a secret usually fails to arrive")
	}

	got, err := interpolate([]byte(`x: "${DG_TEST_EMPTY:-fallback}"`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "fallback") {
		t.Errorf("a default should apply to an empty value; got %q", got)
	}
}

func TestADefaultMayItselfBeEmpty(t *testing.T) {
	os.Unsetenv("DG_TEST_OPTIONAL")

	got, err := interpolate([]byte(`x: "${DG_TEST_OPTIONAL:-}"`))
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
	got, err := interpolate([]byte(`message: "cost is $${NOT_A_VARIABLE}"`))
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

	_, err := interpolate([]byte("a: ${DG_TEST_A}\nb: ${DG_TEST_B}\n"))
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
