package state

import (
	"testing"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

func mk(fp string) finding.Finding {
	return finding.Finding{Fingerprint: fp, FirstSeen: time.Now().UTC()}
}

func TestFirstRunMarksEverythingNew(t *testing.T) {
	fs := []finding.Finding{mk("a"), mk("b")}
	n, fixed := MarkNew(fs, nil)
	if n != 2 || fixed != 0 {
		t.Errorf("new=%d fixed=%d, want 2/0", n, fixed)
	}
	for _, f := range fs {
		if !f.New {
			t.Error("with no baseline every finding is new by definition")
		}
	}
}

func TestCarriedFindingsAreNotNewAndKeepTheirAge(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := &Snapshot{
		Fingerprints: []string{"a", "b"},
		FirstSeen:    map[string]time.Time{"a": old},
	}
	fs := []finding.Finding{mk("a"), mk("c")}

	n, fixed := MarkNew(fs, prev)
	if n != 1 {
		t.Errorf("new=%d, want 1 (only c is new)", n)
	}
	if fixed != 1 {
		t.Errorf("fixed=%d, want 1 (b is gone)", fixed)
	}
	if fs[0].New {
		t.Error("a carried finding must not be reported as new")
	}
	if !fs[0].FirstSeen.Equal(old) {
		t.Errorf("FirstSeen = %v, a carried finding must keep its original age", fs[0].FirstSeen)
	}
	if !fs[1].New {
		t.Error("c should be new")
	}
}

func TestSnapshotRoundTripsPerBranch(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	sc := &scorecard.Scorecard{Score: 77, Branch: "feature/x"}
	if err := s.Save("feature/x", sc, []finding.Finding{mk("a")}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Load("feature/x")
	if err != nil || got == nil {
		t.Fatalf("load: %v %v", got, err)
	}
	if got.Scorecard.Score != 77 {
		t.Errorf("score = %.0f, want 77", got.Scorecard.Score)
	}

	// A branch with no snapshot of its own must not silently read another
	// feature branch's; it falls back to the default (main) baseline only.
	if got, _ := s.Load("feature/y"); got != nil {
		t.Error("an unrelated branch must not inherit feature/x's snapshot")
	}
}

// Branch names contain slashes; the snapshot filename must not escape the
// state directory because of one.
func TestBranchNamesAreSanitizedIntoFilenames(t *testing.T) {
	for _, branch := range []string{"feature/x", "../../etc/passwd", "a/b/c"} {
		name := baselineName(branch)
		for _, bad := range []string{"/", `\`, ".."} {
			if contains(name, bad) {
				t.Errorf("baselineName(%q) = %q contains %q", branch, name, bad)
			}
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMissingSnapshotIsNotAnError(t *testing.T) {
	got, err := New(t.TempDir()).Load("main")
	if err != nil || got != nil {
		t.Errorf("a project with no snapshot should load nil, nil; got %v %v", got, err)
	}
}

// The bug this replaced: Load tried the branch's own snapshot and then a file
// called baseline.json, which nothing ever wrote. Save names snapshots after
// the branch, and only a scan outside a git repository produces an empty
// branch name -- so the documented fallback to "main's baseline" could not
// fire, every feature branch reported no baseline, and the regression gate
// passed without evaluating anything.
func TestLoadFindsTheDefaultBranchSnapshot(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if err := s.Save("main", &scorecard.Scorecard{Score: 99}, nil); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// This is the call the pipeline makes on a feature branch: it asks for the
	// default branch's snapshot, not its own.
	got, err := s.Load("main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("no snapshot found for the default branch after recording one")
	}
	if got.Scorecard.Score != 99 {
		t.Errorf("Score = %v, want main's 99", got.Scorecard.Score)
	}
}

// A branch's own snapshot must not be what the gate reads. A branch that was
// already below main compares clean against itself, which is exactly how a
// posture drop reaches main unnoticed.
func TestABranchSnapshotDoesNotShadowTheDefault(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)

	if err := s.Save("main", &scorecard.Scorecard{Score: 99}, nil); err != nil {
		t.Fatalf("Save main: %v", err)
	}
	if err := s.Save("feature/x", &scorecard.Scorecard{Score: 96}, nil); err != nil {
		t.Fatalf("Save branch: %v", err)
	}

	got, err := s.Load("main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil || got.Scorecard.Score != 99 {
		t.Fatalf("gate would compare against %v, want main's 99", got)
	}
}

// No snapshot at all is not an error, and must not be a stale one either.
func TestLoadWithNothingRecordedReturnsNothing(t *testing.T) {
	got, err := New(t.TempDir()).Load("main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("invented a snapshot: %+v", got)
	}
}
