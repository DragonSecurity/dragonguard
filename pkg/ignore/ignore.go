// Package ignore applies the .dragon.yaml `ignore:` list to findings.
//
// The list is documented as excluding paths from every engine, and that was
// only ever true of the engines whose CLI happens to have a suitable flag:
// Trivy takes --skip-dirs, OpenGrep and OSV take --exclude, and each is passed
// the list. Gitleaks has no such flag, so a path listed in `ignore:` was
// scanned and reported anyway -- and the flags the other engines do take are
// not equivalent to each other either (--skip-dirs will not exclude a single
// file).
//
// So the list is enforced once, here, over the findings every engine returns.
// Engine-level excludes are still worth passing where they exist, because they
// save the engine the work; this is what turns them from an optimisation into
// a guarantee, including for the next engine added.
package ignore

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// Matcher decides whether a path is covered by the configured ignore list.
//
// The semantics, which the documentation states and these rules implement:
//
//   - A pattern with no "/" matches any single path segment, at any depth.
//     "node_modules" therefore covers ui/node_modules/react/index.js, which is
//     what anyone writing it means.
//   - A pattern containing "/" is anchored at the scan root and matches that
//     path exactly, or anything beneath it. "internal/migrations/tenant" covers
//     the directory; "internal/migrations/tenant/atlas.sum" covers the one file.
//   - "*" and "?" glob within a segment; "**" spans zero or more segments.
//
// Anchoring the multi-segment case is deliberate. An unanchored "docs/build"
// would also match ui/vendor/docs/build, and a rule that quietly excludes more
// than it names is the kind of thing that hides a finding nobody knows is
// hidden.
type Matcher struct{ patterns []string }

// New compiles an ignore list. Blank entries are dropped, and trailing slashes
// are ignored so "vendor" and "vendor/" mean the same thing.
func New(patterns []string) Matcher {
	var m Matcher
	for _, p := range patterns {
		p = strings.TrimSpace(filepath.ToSlash(p))
		p = strings.TrimPrefix(p, "./")
		p = strings.Trim(p, "/")
		if p == "" {
			continue
		}
		m.patterns = append(m.patterns, p)
	}
	return m
}

// Empty reports whether there is nothing to match against.
func (m Matcher) Empty() bool { return len(m.patterns) == 0 }

// Match reports whether p is covered. p is expected relative to the scan root;
// Filter is what normalises it.
func (m Matcher) Match(p string) bool {
	p = strings.Trim(strings.TrimPrefix(filepath.ToSlash(p), "./"), "/")
	if p == "" {
		return false
	}
	segs := strings.Split(p, "/")
	for _, pat := range m.patterns {
		if !strings.Contains(pat, "/") {
			for _, s := range segs {
				if ok, _ := path.Match(pat, s); ok {
					return true
				}
			}
			continue
		}
		if matchSegments(strings.Split(pat, "/"), segs) {
			return true
		}
	}
	return false
}

// matchSegments matches an anchored pattern against a path, segment by segment.
//
// Running out of pattern is a match: it means the path is inside a directory
// the pattern named, which is the recursive behaviour "vendor/" implies.
// Running out of path is not, since the pattern still names something deeper.
func matchSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return true
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pat[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	if ok, _ := path.Match(pat[0], segs[0]); !ok {
		return false
	}
	return matchSegments(pat[1:], segs[1:])
}

// Report describes what the ignore list removed.
//
// Returned rather than logged, for the same reason vcs.FilterReport is: a
// filter that silently drops evidence is indistinguishable from a scanner that
// missed it, and somebody deciding whether to trust the result needs to be able
// to tell those apart.
type Report struct {
	// Removed counts findings excluded by the ignore list.
	Removed int `json:"removed"`
	// Files lists the distinct ignored paths that held findings.
	Files []string `json:"files,omitempty"`
}

// Note renders a one-line summary, or empty when nothing was filtered.
func (r Report) Note() string {
	if r.Removed == 0 {
		return ""
	}
	return fmt.Sprintf("%d finding(s) in ignored paths were excluded", r.Removed)
}

// Filter removes findings whose file the ignore list covers.
//
// root is the scan directory: engines are inconsistent about whether they
// report absolute or relative paths, and a pattern written in .dragon.yaml is
// always relative to the repository, so absolute paths are made relative before
// matching rather than being silently unmatchable.
func Filter(m Matcher, root string, findings []finding.Finding) ([]finding.Finding, Report) {
	var rep Report
	if m.Empty() {
		return findings, rep
	}

	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		// A finding with no file -- a vulnerable package, a container layer --
		// has no path for the list to have an opinion about.
		p := relativize(f.Location.File, root)
		if p == "" || !m.Match(p) {
			out = append(out, f)
			continue
		}
		rep.Removed++
		if !seen[p] {
			seen[p] = true
			rep.Files = append(rep.Files, p)
		}
	}
	return out, rep
}

func relativize(p, root string) string {
	if p == "" || root == "" || !filepath.IsAbs(p) {
		return p
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return filepath.ToSlash(rel)
}
