package ignore

import (
	"path/filepath"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// The case this package exists for. atlas.sum is a checksum file: lines of
// high-entropy base64 that Gitleaks reads as credentials. It is listed in
// `ignore:` by exact path, Gitleaks has no exclude flag to be given, and so it
// was reported on every scan regardless of the configuration saying otherwise.
func TestExactFilePathIsIgnored(t *testing.T) {
	m := New([]string{"internal/migrations/tenant/atlas.sum"})

	if !m.Match("internal/migrations/tenant/atlas.sum") {
		t.Error("the exact path listed in ignore: was not matched")
	}
	// Anchored: the same basename elsewhere is a different file, and excluding
	// it too would hide a finding nobody asked to hide.
	if m.Match("vendor/other/internal/migrations/tenant/atlas.sum") {
		t.Error("an anchored pattern matched the same path nested elsewhere")
	}
	if m.Match("internal/migrations/tenant/schema.sql") {
		t.Error("a sibling file in the same directory was matched")
	}
}

func TestBareNameMatchesAtAnyDepth(t *testing.T) {
	m := New([]string{"node_modules", "vendor", ".git"})

	for _, p := range []string{
		"node_modules/react/index.js",
		"ui/node_modules/lodash/lodash.js",
		"vendor/github.com/x/y.go",
		".git/config",
	} {
		if !m.Match(p) {
			t.Errorf("%q was not matched by a bare-name pattern", p)
		}
	}
	// A segment has to match whole: "vendor" must not swallow "vendored".
	if m.Match("vendored/thing.go") {
		t.Error("a bare-name pattern matched a partial segment")
	}
}

func TestDirectoryPrefixCoversEverythingBeneath(t *testing.T) {
	m := New([]string{"internal/migrations/tenant"})

	if !m.Match("internal/migrations/tenant/atlas.sum") {
		t.Error("a file beneath the named directory was not matched")
	}
	if !m.Match("internal/migrations/tenant") {
		t.Error("the directory itself was not matched")
	}
	if m.Match("internal/migrations/control/atlas.sum") {
		t.Error("a sibling directory was matched")
	}
}

func TestGlobs(t *testing.T) {
	m := New([]string{"*.min.js", "docs/**/generated"})

	if !m.Match("ui/dist/app.min.js") {
		t.Error("a bare glob did not match at depth")
	}
	if !m.Match("docs/a/b/generated") || !m.Match("docs/generated") {
		t.Error("** did not span zero-or-more segments")
	}
	if m.Match("ui/dist/app.js") {
		t.Error("a glob matched a path it does not describe")
	}
}

func TestTrailingSlashAndBlanksAreTolerated(t *testing.T) {
	m := New([]string{"vendor/", "  ", "./node_modules", ""})

	if len(m.patterns) != 2 {
		t.Fatalf("blank entries survived compilation: %q", m.patterns)
	}
	if !m.Match("vendor/x.go") || !m.Match("node_modules/y.js") {
		t.Error("a pattern written with a trailing slash or ./ prefix did not match")
	}
}

// Engines disagree about whether a reported path is absolute. A pattern in
// .dragon.yaml is always relative to the repository, so an absolute path that
// went unmatched would be an ignore rule that works for one engine and not
// another -- which is the bug this package was written to end.
func TestAbsolutePathsAreMadeRelativeToTheScanRoot(t *testing.T) {
	root := filepath.FromSlash("/tmp/repo")
	findings := []finding.Finding{
		{Location: finding.Location{File: filepath.Join(root, "internal", "migrations", "tenant", "atlas.sum")}},
		{Location: finding.Location{File: "internal/migrations/tenant/atlas.sum"}},
		{Location: finding.Location{File: "internal/api/handler.go"}},
		// No file at all: a vulnerable package has no path to judge.
		{RuleID: "CVE-2026-0001"},
	}

	kept, rep := Filter(New([]string{"internal/migrations/tenant/atlas.sum"}), root, findings)

	if rep.Removed != 2 {
		t.Errorf("Removed = %d, want 2 (the absolute and the relative form)", rep.Removed)
	}
	if len(kept) != 2 {
		t.Errorf("kept %d findings, want 2", len(kept))
	}
	for _, f := range kept {
		if f.Location.File != "" && f.Location.File != "internal/api/handler.go" {
			t.Errorf("kept an ignored finding: %q", f.Location.File)
		}
	}
}

// An empty list must not become an accidental filter.
func TestEmptyListKeepsEverything(t *testing.T) {
	findings := []finding.Finding{{Location: finding.Location{File: "a.go"}}}
	kept, rep := Filter(New(nil), "/tmp/repo", findings)
	if len(kept) != 1 || rep.Removed != 0 || rep.Note() != "" {
		t.Errorf("an empty ignore list filtered something: kept=%d removed=%d", len(kept), rep.Removed)
	}
}
