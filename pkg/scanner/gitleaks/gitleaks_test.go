package gitleaks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// The bug this exists to prevent: gitleaks answers whichever question it is
// asked, and the adapter used to choose by whether .git happened to exist.
// Given a repository it walks commit diffs and never opens the working tree,
// so the same commit scanned locally saw history only and scanned from a
// hosted clone saw the tree only. Coverage was a property of the checkout.
func TestBothPassesAreMergedAndDeduplicated(t *testing.T) {
	tree := []finding.Finding{
		{RuleID: "github-pat", Location: finding.Location{File: "app.env", StartLine: 1}},
		{RuleID: "slack-token", Location: finding.Location{File: "pending.env", StartLine: 1}},
	}
	history := []finding.Finding{
		// The same tracked file, seen again in the commit that introduced it.
		{RuleID: "github-pat", Location: finding.Location{File: "app.env", StartLine: 1}},
		// A credential committed and later deleted: only history can see it,
		// and it is still disclosed.
		{RuleID: "aws-key", Location: finding.Location{File: "removed.env", StartLine: 3}},
	}

	got := mergeLeaks(tree, history)
	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3: the tracked file must not be reported twice", len(got))
	}

	seen := map[string]bool{}
	for _, f := range got {
		seen[f.RuleID] = true
	}
	for _, want := range []string{"github-pat", "slack-token", "aws-key"} {
		if !seen[want] {
			t.Errorf("%s was lost in the merge", want)
		}
	}
}

// A secret at the same path but a different line is a different secret, and
// collapsing the two would hide one.
func TestTheSameFileAtADifferentLineIsADifferentFinding(t *testing.T) {
	tree := []finding.Finding{
		{RuleID: "github-pat", Location: finding.Location{File: "app.env", StartLine: 1}},
	}
	history := []finding.Finding{
		{RuleID: "github-pat", Location: finding.Location{File: "app.env", StartLine: 9}},
	}
	if got := mergeLeaks(tree, history); len(got) != 2 {
		t.Errorf("got %d findings, want both lines", len(got))
	}
}

// Neither pass may be dropped for being empty: a repository with a clean
// history still has a working tree worth reading, and the other way round.
func TestAnEmptyPassDoesNotDiscardTheOther(t *testing.T) {
	only := []finding.Finding{
		{RuleID: "github-pat", Location: finding.Location{File: "app.env", StartLine: 1}},
	}
	if got := mergeLeaks(only, nil); len(got) != 1 {
		t.Errorf("an empty history discarded the tree: %d", len(got))
	}
	if got := mergeLeaks(nil, only); len(got) != 1 {
		t.Errorf("an empty tree discarded the history: %d", len(got))
	}
}

// What the engine covered has to be visible, because the failure it replaces
// was invisible: a scan that silently saw half of what the next one would.
func TestCoverageIsReported(t *testing.T) {
	s := New()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := s.RulesFor(scanner.Target{Dir: repo}); len(got) != 2 {
		t.Errorf("in a repository both passes should be reported; got %v", got)
	}

	plain := s.RulesFor(scanner.Target{Dir: t.TempDir()})
	if len(plain) != 1 || !strings.Contains(plain[0], "no repository") {
		t.Errorf("outside a repository the absent pass should be named; got %v", plain)
	}
}
