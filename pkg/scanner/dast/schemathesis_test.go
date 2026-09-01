package dast

import (
	"path/filepath"
	"strings"
	"testing"
)

// The container is how Schemathesis is actually available on most machines:
// it is a Python tool, and reporting "not found on PATH" while docker sits
// right there describes the search rather than the situation.
func TestSchemathesisFallsBackToDocker(t *testing.T) {
	s := NewSchemathesis()
	args, bin, err := s.command("https://api.example.com/openapi.json", "https://api.example.com", "/tmp/dragon-dast-x/schemathesis-report.ndjson", nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")

	if filepath.Base(bin) == "docker" {
		// Only the report directory may be mounted; the system temp directory
		// must never be handed to a container that sends hostile traffic.
		if !strings.Contains(joined, "-v /tmp/dragon-dast-x:/reports:rw") {
			t.Errorf("mount is wrong: %s", joined)
		}
		// /app is the image's own installation and holds the hooks.py that
		// SCHEMATHESIS_HOOKS points at. Mounting over it makes schemathesis
		// exit before it starts, so nothing may be mounted there.
		if strings.Contains(joined, ":/app") {
			t.Errorf("mounting over /app shadows the image's own hooks.py: %s", joined)
		}
		// The report path is absolute inside the container, so it does not
		// depend on the image's working directory.
		if !strings.Contains(joined, "--report-ndjson-path /reports/schemathesis-report.ndjson") {
			t.Errorf("report path must be the absolute container path: %s", joined)
		}
		if strings.Contains(joined, "--report-ndjson-path /tmp") {
			t.Error("an absolute host path was passed into the container")
		}
	} else {
		// A local install writes straight to the host path.
		if !strings.Contains(joined, "--report-ndjson-path /tmp/dragon-dast-x/schemathesis-report.ndjson") {
			t.Errorf("local run should use the host path: %s", joined)
		}
	}

	// Either way the contract is the same.
	if !strings.Contains(joined, "run https://api.example.com/openapi.json") {
		t.Errorf("schema missing: %s", joined)
	}
	if !strings.Contains(joined, "--url https://api.example.com") {
		t.Errorf("base URL missing: %s", joined)
	}
}

// Extra args from the config must reach the tool, not be dropped by the
// container path.
func TestSchemathesisPassesConfiguredArgsThrough(t *testing.T) {
	s := NewSchemathesis()
	args, _, err := s.command("schema.json", "https://api.example.com", "/tmp/d/r.json", []string{"--max-examples", "5"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "--max-examples 5") {
		t.Errorf("configured args were dropped: %v", args)
	}
}
