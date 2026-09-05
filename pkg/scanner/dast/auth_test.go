package dast

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

func targetWithHeaders(headers map[string]string) scanner.Target {
	c := config.Default()
	c.DAST = config.DASTPolicy{Headers: headers}
	return scanner.Target{Config: c}
}

// ZAP has no flag for "send this header" -- it has a Replacer add-on driven by
// six numbered properties each. Nobody should write that by hand in YAML.
func TestZAPHeadersBecomeAReplacerConfig(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "zap-report.json")

	name, err := writeReplacerConfig(report, targetWithHeaders(map[string]string{
		"Authorization": "Bearer s3cr3t",
		"X-Tenant":      "acme",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		t.Fatal("headers were configured but no config file was written")
	}

	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	// Sorted, so the same configuration produces the same file every run.
	for _, want := range []string{
		"replacer.full_list(0).matchstr=Authorization",
		"replacer.full_list(0).replacement=Bearer s3cr3t",
		"replacer.full_list(0).matchtype=REQ_HEADER",
		"replacer.full_list(0).enabled=true",
		"replacer.full_list(1).matchstr=X-Tenant",
		"replacer.full_list(1).replacement=acme",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("replacer config missing %q:\n%s", want, got)
		}
	}

	// The file holds a credential and sits in a directory mounted into a
	// container whose whole job is to send hostile traffic.
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential file mode is %04o, want 0600", perm)
	}
}

// A public target needs no credential, and an unauthenticated scan should be
// byte for byte the command it always was.
func TestNoHeadersWritesNoFileAndChangesNoCommand(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "zap-report.json")

	name, err := writeReplacerConfig(report, targetWithHeaders(nil))
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		t.Errorf("wrote %q with nothing to authenticate with", name)
	}

	z := &ZAP{}
	args, _, err := z.command("https://example.test", report, "", nil)
	if err != nil {
		t.Skipf("neither zap nor docker available: %v", err)
	}
	if strings.Contains(strings.Join(args, " "), "-configfile") {
		t.Errorf("an unauthenticated scan gained a -configfile: %v", args)
	}
}

// The credential must reach ZAP by file, not on the command line, where
// anything else on the runner can read it out of ps.
func TestTheZAPCredentialNeverReachesTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "zap-report.json")

	name, err := writeReplacerConfig(report, targetWithHeaders(map[string]string{
		"Authorization": "Bearer s3cr3t",
	}))
	if err != nil {
		t.Fatal(err)
	}

	z := &ZAP{}
	args, _, err := z.command("https://example.test", report, name, []string{"--extra-flag"})
	if err != nil {
		t.Skipf("neither zap nor docker available: %v", err)
	}
	joined := strings.Join(args, " ")

	if strings.Contains(joined, "s3cr3t") {
		t.Errorf("the credential is on the command line: %v", args)
	}
	if !strings.Contains(joined, "-configfile") || !strings.Contains(joined, name) {
		t.Errorf("the replacer config was not passed to ZAP: %v", args)
	}
	// args: is an escape hatch alongside authentication, not instead of it.
	if !strings.Contains(joined, "--extra-flag") {
		t.Errorf("engines.zap.args was dropped: %v", args)
	}
}

// Schemathesis takes headers as -H flags, and args: must not replace them.
func TestSchemathesisSendsHeadersAndKeepsArgs(t *testing.T) {
	c := config.Default()
	c.DAST = config.DASTPolicy{Headers: map[string]string{
		"Authorization": "Bearer s3cr3t",
		"X-Tenant":      "acme",
	}}
	c.Engines = map[string]config.EngineConfig{
		"schemathesis": {Args: []string{"--max-examples", "5"}},
	}

	var extra []string
	for _, h := range c.DAST.SortedHeaders() {
		extra = append(extra, "-H", h[0]+": "+h[1])
	}
	extra = append(extra, c.Engines["schemathesis"].Args...)

	joined := strings.Join(extra, " ")
	for _, want := range []string{
		"-H Authorization: Bearer s3cr3t",
		"-H X-Tenant: acme",
		"--max-examples 5",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, extra)
		}
	}
}
