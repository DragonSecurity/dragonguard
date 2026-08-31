// Package rules embeds DragonGuard's own SAST rule pack in the binary.
//
// Embedding rather than shipping a directory alongside the binary is what
// makes `dragon scan` work in a repository that has never been configured.
// The alternative -- refusing to run SAST until somebody sets
// engines.opengrep.rules -- means the very first scan of a project silently
// reports the code dimension as unassessed, which is the least useful moment
// to have no coverage.
//
// The rules are DragonGuard's own. OpenGrep runs Semgrep-format rules
// unchanged, but engine compatibility is not permission to redistribute
// somebody else's ruleset, so nothing here is vendored from a registry.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

//go:embed go javascript python
var files embed.FS

var (
	once       sync.Once
	extracted  string
	extractErr error
)

// Dir materializes the embedded rules into a directory and returns its path.
//
// OpenGrep takes a filesystem path, so the pack has to exist on disk for the
// length of a scan. It is written once per process into the OS temp directory
// and reused; the caller is not expected to clean it up, since a few kilobytes
// of rule YAML is not worth the lifecycle management.
func Dir() (string, error) {
	once.Do(func() {
		base, err := os.MkdirTemp("", "dragon-rules-*")
		if err != nil {
			extractErr = fmt.Errorf("create rules dir: %w", err)
			return
		}
		err = fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			target := filepath.Join(base, path)
			if d.IsDir() {
				return os.MkdirAll(target, 0o755)
			}
			data, err := files.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o644)
		})
		if err != nil {
			extractErr = fmt.Errorf("extract rules: %w", err)
			return
		}
		extracted = base
	})
	return extracted, extractErr
}

// Count reports how many rule files are embedded, for diagnostics.
func Count() int {
	n := 0
	_ = fs.WalkDir(files, ".", func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}
