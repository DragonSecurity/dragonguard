package dast

import (
	"os"
	"path/filepath"
)

// tempReportDir creates a directory holding nothing but the report.
//
// The docker path bind-mounts this into the scanner container, and mounting
// the parent of a file made by os.CreateTemp would mount the SYSTEM temp
// directory -- every unrelated temp file on the machine, handed to a
// container whose whole job is to attack things.
//
// It is chmod 0777 because each container runs as its own non-root uid --
// zap as 1000, schemathesis as its own user -- and neither will match the
// host user, so a 0700 directory is one the scanner cannot write its report
// into. The directory exists for one file for the
// length of one scan and is removed afterwards.
func tempReportDir(name string) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "dragon-dast-*")
	if err != nil {
		return "", func() {}, err
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		os.RemoveAll(dir)
		return "", func() {}, err
	}
	return filepath.Join(dir, name), func() { os.RemoveAll(dir) }, nil
}

func tempDir(path string) string  { return filepath.Dir(path) }
func baseName(path string) string { return filepath.Base(path) }
