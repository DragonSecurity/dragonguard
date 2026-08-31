package vcs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

func repo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.test"},
		{"config", "user.name", "t"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if err := cmd.Run(); err != nil {
			t.Skipf("git unavailable: %v", err)
		}
	}
	return dir
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir string, paths ...string) {
	t.Helper()
	args := append([]string{"add", "--"}, paths...)
	for _, a := range [][]string{args, {"commit", "-q", "-m", "x"}} {
		cmd := exec.Command("git", a...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", a, err, out)
		}
	}
}

// The case that motivated this: a real repository where two of three
// "critical secrets" were a local .env and a gitignored .pem, which together
// tripped a gate the one genuinely committed key had not.
func TestIgnoredFilesAreNotDisclosures(t *testing.T) {
	dir := repo(t)
	write(t, dir, ".gitignore", "*.pem\n.env\n")
	write(t, dir, ".env", "SECRET=x\n")
	write(t, dir, "key.pem", "-----BEGIN PRIVATE KEY-----\n")
	write(t, dir, "committed_test.go", "const key = \"x\"\n")
	commit(t, dir, ".gitignore", "committed_test.go")

	tree := Open(context.Background(), dir)
	if !tree.IsRepo() {
		t.Fatal("expected a repository")
	}

	cases := map[string]Status{
		"committed_test.go": StatusTracked,
		".env":              StatusIgnored,
		"key.pem":           StatusIgnored,
	}
	for path, want := range cases {
		if got := tree.Status(path); got != want {
			t.Errorf("Status(%q) = %s, want %s", path, got, want)
		}
	}

	findings := []finding.Finding{
		{Category: finding.CategorySecret, Location: finding.Location{File: "committed_test.go"}},
		{Category: finding.CategorySecret, Location: finding.Location{File: ".env"}},
		{Category: finding.CategorySecret, Location: finding.Location{File: "key.pem"}},
	}
	kept, rep := FilterIgnored(tree, findings)

	if len(kept) != 1 || kept[0].Location.File != "committed_test.go" {
		t.Errorf("kept %v, want only the committed file", kept)
	}
	if rep.Removed != 2 || rep.Secrets != 2 {
		t.Errorf("report = %+v, want 2 removed, 2 secrets", rep)
	}
	if rep.Note() == "" {
		t.Error("filtering must be reported, never silent")
	}
}

// A file that is untracked but not ignored is one `git add .` from being
// disclosed. That is a warning, not a non-event.
func TestUntrackedButNotIgnoredIsKept(t *testing.T) {
	dir := repo(t)
	write(t, dir, ".gitignore", "*.pem\n")
	write(t, dir, "README.md", "x\n")
	commit(t, dir, ".gitignore", "README.md")
	write(t, dir, "new_secret.txt", "AKIA...\n")

	tree := Open(context.Background(), dir)
	if got := tree.Status("new_secret.txt"); got != StatusUntracked {
		t.Errorf("Status = %s, want untracked", got)
	}

	findings := []finding.Finding{{Category: finding.CategorySecret, Location: finding.Location{File: "new_secret.txt"}}}
	kept, rep := FilterIgnored(tree, findings)
	if len(kept) != 1 {
		t.Error("an untracked file is not yet disclosed but may be committed next; it must be kept")
	}
	if rep.Removed != 0 {
		t.Errorf("nothing should have been filtered, got %+v", rep)
	}
}

// Findings with no file — a vulnerable package, a container layer — have
// nothing for git to have an opinion about.
func TestFindingsWithoutAFileSurvive(t *testing.T) {
	dir := repo(t)
	write(t, dir, ".gitignore", "*.pem\n")
	commit(t, dir, ".gitignore")

	tree := Open(context.Background(), dir)
	findings := []finding.Finding{
		{Category: finding.CategorySCA, Package: &finding.Package{Name: "lodash", Version: "4.17.11"}},
	}
	kept, rep := FilterIgnored(tree, findings)
	if len(kept) != 1 || rep.Removed != 0 {
		t.Error("a package finding with no file path must not be filtered")
	}
}

// Outside a repository there is no gitignore semantics, so nothing is filtered.
func TestNonRepositoryFiltersNothing(t *testing.T) {
	tree := Open(context.Background(), t.TempDir())
	if tree.IsRepo() {
		t.Fatal("a bare directory is not a repository")
	}
	findings := []finding.Finding{{Location: finding.Location{File: "anything"}}}
	kept, rep := FilterIgnored(tree, findings)
	if len(kept) != 1 || rep.Removed != 0 {
		t.Error("outside a repository nothing may be filtered")
	}
	if tree.Status("anything") != StatusUnknown {
		t.Error("status outside a repository must be unknown")
	}
}

// Absolute paths from scanners must resolve against the tree root.
func TestAbsolutePathsResolve(t *testing.T) {
	dir := repo(t)
	write(t, dir, ".gitignore", ".env\n")
	write(t, dir, ".env", "x\n")
	commit(t, dir, ".gitignore")

	tree := Open(context.Background(), dir)
	if got := tree.Status(filepath.Join(dir, ".env")); got != StatusIgnored {
		t.Errorf("absolute path Status = %s, want ignored", got)
	}
}

// Ignored files in subdirectories must be recognised too.
func TestNestedIgnoredFiles(t *testing.T) {
	dir := repo(t)
	write(t, dir, ".gitignore", "secrets/\n")
	write(t, dir, "secrets/prod.env", "TOKEN=x\n")
	write(t, dir, "main.go", "package main\n")
	commit(t, dir, ".gitignore", "main.go")

	tree := Open(context.Background(), dir)
	if got := tree.Status("secrets/prod.env"); got != StatusIgnored {
		t.Errorf("nested ignored file Status = %s, want ignored", got)
	}
}
