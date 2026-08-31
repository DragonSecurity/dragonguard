package vcs

import (
	"fmt"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// FilterReport describes what a gitignore filter removed.
//
// Returned rather than logged so the caller can put it in the scan output. A
// filter that silently drops evidence is indistinguishable from a scanner that
// missed it, and the difference matters when somebody is deciding whether to
// trust the result.
type FilterReport struct {
	// Removed counts findings excluded because their file is gitignored.
	Removed int `json:"removed"`
	// Files lists the distinct ignored files that held findings.
	Files []string `json:"files,omitempty"`
	// Secrets counts how many of the removed findings were credentials,
	// which is the case worth mentioning out loud.
	Secrets int `json:"secrets"`
}

// Note renders a one-line summary, or empty when nothing was filtered.
func (r FilterReport) Note() string {
	if r.Removed == 0 {
		return ""
	}
	s := fmt.Sprintf("%d finding(s) in gitignored files were excluded", r.Removed)
	if r.Secrets > 0 {
		s += fmt.Sprintf(" (%d credential(s) — local only, not disclosed, but still on disk)", r.Secrets)
	}
	return s
}

// FilterIgnored removes findings whose file .gitignore excludes.
//
// The reasoning, which is the whole point of the feature: a finding is a
// security problem because the code is *disclosed*. A gitignored file was
// never committed and, as configured, never will be — so a credential in a
// developer's local .env is not a disclosure, and reporting it as a critical
// one is a false positive that pushes real findings off the page. It happened
// on the first real repository this was pointed at: two of three "critical
// secrets" were a local .env and a gitignored .pem, and together they tripped
// a gate that the one genuine committed key had not.
//
// Untracked-but-not-ignored files are deliberately kept. Those are one
// `git add .` away from being disclosed, which is a warning, not a non-event.
func FilterIgnored(t *Tree, findings []finding.Finding) ([]finding.Finding, FilterReport) {
	var rep FilterReport
	if t == nil || !t.IsRepo() {
		return findings, rep
	}

	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		path := f.Location.File
		// Findings with no file — a vulnerable package, a container layer —
		// have nothing for git to have an opinion about.
		if path == "" || !t.IsIgnored(path) {
			out = append(out, f)
			continue
		}
		rep.Removed++
		if f.Category == finding.CategorySecret {
			rep.Secrets++
		}
		if !seen[path] {
			seen[path] = true
			rep.Files = append(rep.Files, path)
		}
	}
	return out, rep
}
