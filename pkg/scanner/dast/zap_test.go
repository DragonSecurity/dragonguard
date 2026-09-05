package dast

import (
	"strings"
	"testing"
)

// The reported reason was ZAP's opening line -- "Failed to access summary file
// /home/zap/zap_out.json" -- which it emits on every failed run and which says
// nothing about the cause. A scan that failed because a hostname did not
// resolve therefore looked like a file-permission problem inside the
// container, which is where somebody spends the afternoon.
func TestTheReportedReasonIsTheActualFailure(t *testing.T) {
	stderr := `2026-09-05 02:07:16,836 Failed to access summary file /home/zap/zap_out.json
Using the Automation Framework
Automation plan failures:
	Job spider failed to access URL https://example.invalid check that it is valid : example.invalid: Name or service not known
`
	got := zapFailureReason("", stderr)
	if !strings.Contains(got, "failed to access URL") {
		t.Errorf("reason = %q, want the spider failure", got)
	}
	if strings.Contains(got, "summary file") {
		t.Errorf("reason still leads with the line that explains nothing: %q", got)
	}
}

// ZAP puts the same block on stdout as often as on stderr, and the adapter
// used to capture only stderr -- so the one line that explained the failure
// was the line it threw away.
func TestTheReasonIsFoundOnStdoutToo(t *testing.T) {
	stdout := `Using the Automation Framework
Automation plan failures:
	Job spider failed to access URL https://example.invalid check that it is valid
`
	got := zapFailureReason(stdout, "2026-09-05 Failed to access summary file /home/zap/zap_out.json\n")
	if !strings.Contains(got, "failed to access URL") {
		t.Errorf("reason = %q, want the failure from stdout", got)
	}
}

// Without a structured failure block the tail is still a better guess than the
// head: whatever ZAP said last is closer to why it stopped than its banner.
func TestUnstructuredFailuresFallBackToTheTail(t *testing.T) {
	got := zapFailureReason("", "Failed to access summary file /home/zap/zap_out.json\nsomething broke deeper\n")
	if got != "something broke deeper" {
		t.Errorf("reason = %q, want the last meaningful line", got)
	}
}

// Silence is reported as silence rather than as an empty message, which reads
// like the field failed to render.
func TestNoOutputSaysSo(t *testing.T) {
	if got := zapFailureReason("", ""); got != "no output" {
		t.Errorf("reason = %q, want a statement that there was none", got)
	}
}
