package dast

import (
	"os"
	"path/filepath"
)

func tempReport(pattern string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", func() {}, err
	}
	name := f.Name()
	f.Close()
	return name, func() { os.Remove(name) }, nil
}

func tempDir(path string) string  { return filepath.Dir(path) }
func baseName(path string) string { return filepath.Base(path) }
