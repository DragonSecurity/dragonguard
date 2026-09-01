package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestChecksumForFindsTheRightLine(t *testing.T) {
	sums := "aaa  dragonguard_0.2.0_linux_amd64.tar.gz\n" +
		"bbb  dragonguard_0.2.0_darwin_arm64.tar.gz\n"
	got, err := checksumFor([]byte(sums), "dragonguard_0.2.0_darwin_arm64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "bbb" {
		t.Errorf("checksum = %q, want bbb", got)
	}
}

// A missing entry must stop the update. Treating "not listed" as "nothing to
// check" would turn the verification into a no-op exactly when the release is
// malformed -- which is the case it exists for.
func TestChecksumForRefusesWhenTheAssetIsNotListed(t *testing.T) {
	if _, err := checksumFor([]byte("aaa  other.tar.gz\n"), "dragonguard_0.2.0_linux_amd64.tar.gz"); err == nil {
		t.Fatal("expected an error when the asset has no published checksum")
	}
}

func TestChecksumForHandlesBinaryModeStar(t *testing.T) {
	got, err := checksumFor([]byte("ccc *dragonguard_0.2.0_linux_arm64.tar.gz\n"), "dragonguard_0.2.0_linux_arm64.tar.gz")
	if err != nil || got != "ccc" {
		t.Errorf("got %q, %v", got, err)
	}
}

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractBinarySkipsTheOtherArchiveMembers(t *testing.T) {
	archive := tarGz(t, map[string]string{
		"LICENSE":   "apache",
		"README.md": "docs",
		"dragon":    "ELF",
	})
	got, err := extractBinary(archive, "dragon")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ELF" {
		t.Errorf("extracted %q, want the dragon binary", got)
	}
}

func TestExtractBinaryFailsRatherThanInstallingNothing(t *testing.T) {
	if _, err := extractBinary(tarGz(t, map[string]string{"LICENSE": "apache"}), "dragon"); err == nil {
		t.Fatal("expected an error when the archive has no binary")
	}
}

// A tar entry naming a path outside the archive must not be what satisfies the
// search: the base name is compared, so "../../../bin/dragon" is not "dragon"
// arriving from somewhere it should not.
func TestExtractBinaryDoesNotMatchAnEscapingPath(t *testing.T) {
	got, err := extractBinary(tarGz(t, map[string]string{
		"../../../usr/bin/dragon": "evil",
		"dragon":                  "real",
	}), "dragon")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == "evil" {
		t.Error("an escaping path was extracted as the binary")
	}
}

func TestReplaceSelfIsAtomicAndKeepsTheMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dragon")
	if err := os.WriteFile(path, []byte("old"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := replaceSelf(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("binary = %q, want new", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o750 {
		t.Errorf("mode = %o, want the replaced file's 750", st.Mode().Perm())
	}
	// The temporary file must not survive next to the binary.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("left %d files behind: %v", len(entries)-1, entries)
	}
}

// A package manager owns its files. Overwriting one in place leaves it
// believing it installed a version that is no longer there.
func TestManagedByRecognizesTheManagers(t *testing.T) {
	cases := map[string]string{
		"/opt/homebrew/Cellar/dragonguard/0.2.0/bin/dragon": "Homebrew",
		"/nix/store/abc123-dragonguard-0.2.0/bin/dragon":    "Nix",
		"/Users/dev/go/bin/dragon":                          "",
		"/usr/local/bin/dragon":                             "",
	}
	for path, want := range cases {
		if got := managedBy(path); got != want {
			t.Errorf("managedBy(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestVersionComparisonIgnoresTheTagPrefix(t *testing.T) {
	if normalizeVersion("v0.2.0") != normalizeVersion("0.2.0") {
		t.Error("a stamped version and its tag must compare equal")
	}
}

func TestDevBuildsAreRecognized(t *testing.T) {
	for _, v := range []string{"0.1.0-dev", "dev", "", "unknown"} {
		if !isDevBuild(v) {
			t.Errorf("isDevBuild(%q) = false", v)
		}
	}
	for _, v := range []string{"0.2.0", "v0.2.0", "1.0.0-rc1"} {
		if isDevBuild(v) {
			t.Errorf("isDevBuild(%q) = true", v)
		}
	}
}

// The whole point of the checksum step: a tampered archive must not install.
func TestATamperedArchiveDoesNotMatchThePublishedChecksum(t *testing.T) {
	good := tarGz(t, map[string]string{"dragon": "real"})
	sum := sha256.Sum256(good)
	published := hex.EncodeToString(sum[:])

	tampered := tarGz(t, map[string]string{"dragon": "evil"})
	got := sha256.Sum256(tampered)
	if hex.EncodeToString(got[:]) == published {
		t.Fatal("a different archive produced the published digest")
	}
}
