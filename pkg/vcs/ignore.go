// Package vcs answers questions about a working tree that only version
// control can answer.
package vcs

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Status describes how version control sees a file.
type Status string

const (
	// StatusTracked means the file is in the repository. Anything in it has
	// been disclosed to everyone with read access.
	StatusTracked Status = "tracked"
	// StatusIgnored means .gitignore deliberately excludes it. It is a local
	// file that was never committed and, as configured, never will be.
	StatusIgnored Status = "ignored"
	// StatusUntracked means it is neither tracked nor ignored: not disclosed
	// yet, but one `git add .` away from being so.
	StatusUntracked Status = "untracked"
	// StatusUnknown means there is no repository to ask.
	StatusUnknown Status = "unknown"
)

// Tree answers status questions about one working tree.
type Tree struct {
	dir    string
	isRepo bool

	tracked map[string]bool
	ignored map[string]bool
}

// Open inspects a directory. A path that is not a repository yields a Tree
// that reports everything as unknown, which callers treat as "no opinion"
// rather than as a reason to filter anything out.
func Open(ctx context.Context, dir string) *Tree {
	t := &Tree{dir: dir, tracked: map[string]bool{}, ignored: map[string]bool{}}

	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return t
	}
	if out, err := run(ctx, dir, "rev-parse", "--is-inside-work-tree"); err != nil || strings.TrimSpace(out) != "true" {
		return t
	}
	t.isRepo = true

	// Everything git has. One call each, rather than a check-ignore per
	// finding: a monorepo scan can produce thousands, and forking git that
	// many times costs more than the scan.
	if out, err := run(ctx, dir, "ls-files", "-z"); err == nil {
		for _, p := range splitZ(out) {
			t.tracked[normalize(p)] = true
		}
	}
	if out, err := run(ctx, dir, "ls-files", "-z", "--others", "--ignored", "--exclude-standard"); err == nil {
		for _, p := range splitZ(out) {
			t.ignored[normalize(p)] = true
		}
	}
	return t
}

// IsRepo reports whether there was a repository to ask.
func (t *Tree) IsRepo() bool { return t != nil && t.isRepo }

// Status classifies a path, which may be absolute or relative to the tree.
func (t *Tree) Status(path string) Status {
	if t == nil || !t.isRepo || path == "" {
		return StatusUnknown
	}
	rel := normalize(t.relative(path))
	switch {
	case t.tracked[rel]:
		return StatusTracked
	case t.ignored[rel]:
		return StatusIgnored
	default:
		// A path git has never heard of. It may be untracked, or it may not
		// be a real path at all -- a package name, a container layer, a URL.
		// Callers must not treat this as a reason to discard evidence.
		return StatusUntracked
	}
}

// IsIgnored reports whether .gitignore excludes a path.
func (t *Tree) IsIgnored(path string) bool { return t.Status(path) == StatusIgnored }

func (t *Tree) relative(path string) string {
	if !filepath.IsAbs(path) {
		return path
	}
	if rel, err := filepath.Rel(t.dir, path); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return path
}

func normalize(p string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.TrimSpace(p))), "./")
}

func splitZ(out string) []string {
	parts := strings.Split(out, "\x00")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}

func run(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
}
