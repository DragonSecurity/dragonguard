package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// The release this binary updates itself from. Hard-coded rather than
// configurable: a flag that redirects where a security tool fetches its own
// replacement from is an arbitrary-code-execution feature with a help string.
const (
	updateOwner = "DragonSecurity"
	updateRepo  = "dragonguard"
)

// maxDownload bounds what a redirect can make this process read into memory.
const maxDownload = 128 << 20

func newUpdateCmd() *cobra.Command {
	var (
		check  bool
		pinned string
	)
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the dragon binary to the latest release",
		Long: `Replaces this binary with the latest published release.

The archive's SHA-256 is checked against the checksums file published with
the release before anything is written. A tool that decides whether your
code is fit to ship has no business installing an unverified replacement for
itself, and "it came from the right URL" is not verification -- it is trust
in whatever answered.

The version is worth keeping current for a reason beyond features: it is
stamped into every finding this binary produces, so a stale CLI reports
findings under a version whose behaviour nobody can reproduce.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd.Context(), cmd.OutOrStdout(), check, pinned)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "report whether a newer release exists, without installing it")
	cmd.Flags().StringVar(&pinned, "release", "", "install this exact release (e.g. v0.2.0) instead of the latest")
	return cmd
}

func runUpdate(ctx context.Context, out io.Writer, checkOnly bool, pinned string) error {
	self, err := selfPath()
	if err != nil {
		return err
	}
	if mgr := managedBy(self); mgr != "" {
		return fmt.Errorf("this dragon was installed by %s (%s)\nupdate it with %s so the two do not disagree about which version is installed", mgr, self, managerHint(mgr))
	}

	target := pinned
	if target == "" {
		target, err = latestRelease(ctx)
		if err != nil {
			return err
		}
	}

	current := normalizeVersion(version)
	latest := normalizeVersion(target)

	if current == latest {
		fmt.Fprintf(out, "dragon %s is the latest release\n", current)
		return nil
	}
	// A dev build has no release to compare against, so it is always offered
	// the newest one rather than being told it is behind by an amount that
	// means nothing.
	if isDevBuild(version) {
		fmt.Fprintf(out, "this is an unreleased build (%s); the latest release is %s\n", version, latest)
	} else {
		fmt.Fprintf(out, "dragon %s -> %s\n", current, latest)
	}
	if checkOnly {
		return nil
	}

	assetName := fmt.Sprintf("dragonguard_%s_%s_%s.tar.gz", latest, runtime.GOOS, runtime.GOARCH)
	base := fmt.Sprintf("https://github.com/%s/%s/releases/download/v%s", updateOwner, updateRepo, latest)

	fmt.Fprintf(out, "downloading %s\n", assetName)
	archive, err := fetch(ctx, base+"/"+assetName)
	if err != nil {
		return fmt.Errorf("download %s: %w", assetName, err)
	}

	sums, err := fetch(ctx, base+"/checksums.txt")
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	want, err := checksumFor(sums, assetName)
	if err != nil {
		return err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("checksum mismatch for %s\n  published %s\n  received  %s\nthe download was not what the release says it should be; nothing was installed", assetName, want, hex.EncodeToString(got[:]))
	}
	fmt.Fprintln(out, "checksum verified")

	bin, err := extractBinary(archive, "dragon")
	if err != nil {
		return err
	}
	if err := replaceSelf(self, bin); err != nil {
		return err
	}

	fmt.Fprintf(out, "installed dragon %s to %s\n", latest, self)
	return nil
}

// selfPath resolves the binary actually running, following symlinks so a
// replacement lands on the real file rather than clobbering the link that
// points at it.
func selfPath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return p, nil
}

// managedBy names the package manager that owns a path, if any.
//
// Overwriting a managed binary in place leaves the manager convinced it
// installed a version that is no longer there, and the next upgrade silently
// reverts this one.
func managedBy(path string) string {
	switch {
	case strings.Contains(path, "/Cellar/"), strings.Contains(path, "/homebrew/"):
		return "Homebrew"
	case strings.HasPrefix(path, "/nix/store/"):
		return "Nix"
	case strings.Contains(path, "/pkg/mod/"):
		return "the Go module cache"
	}
	return ""
}

func managerHint(mgr string) string {
	switch mgr {
	case "Homebrew":
		return "`brew upgrade dragonguard`"
	case "Nix":
		return "your flake or channel"
	default:
		return "`go install github.com/DragonSecurity/dragonguard/cmd/dragon@latest`"
	}
}

// latestRelease asks GitHub for the newest non-prerelease tag.
func latestRelease(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", updateOwner, updateRepo)
	body, err := fetch(ctx, url)
	if err != nil {
		return "", fmt.Errorf("look up the latest release: %w", err)
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", fmt.Errorf("parse the release response: %w", err)
	}
	if rel.TagName == "" {
		return "", fmt.Errorf("the latest release has no tag name")
	}
	return rel.TagName, nil
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragon/"+version)
	// Unauthenticated GitHub API calls are rate-limited per IP, which a shared
	// CI egress address reaches quickly. A token, when one is already in the
	// environment, raises that limit; it is never required.
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && strings.HasPrefix(url, "https://api.github.com/") {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("not found (HTTP 404) -- no such release or no build for %s/%s", runtime.GOOS, runtime.GOARCH)
		}
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// checksumFor finds one file's digest in a goreleaser checksums.txt.
func checksumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// The name is prefixed with '*' in binary mode by some producers.
		if strings.TrimPrefix(fields[1], "*") == name {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("checksums.txt does not list %s, so the download cannot be verified; nothing was installed", name)
}

// extractBinary pulls one named file out of a .tar.gz.
func extractBinary(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		// The release archive is flat -- LICENSE, README.md, dragon -- so the
		// name must match exactly. Matching the base name instead would make
		// "../../../usr/bin/dragon" a match, since that is what Base returns.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if strings.TrimPrefix(hdr.Name, "./") != name {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, maxDownload))
	}
	return nil, fmt.Errorf("the archive contains no %s binary", name)
}

// replaceSelf swaps the running binary for a new one.
//
// The write goes to a temporary file in the same directory and is then
// renamed over the target, so the swap is atomic and an interrupted update
// leaves the existing binary intact rather than a half-written one. A rename
// over a running executable is fine on Unix: the kernel holds the old inode
// open until the process exits.
func replaceSelf(path string, bin []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dragon-update-*")
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("cannot write to %s: %w\nre-run with sudo, or install somewhere you own", dir, err)
		}
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Match the mode of what is being replaced, so an install that was
	// deliberately group-executable or setgid stays that way.
	mode := os.FileMode(0o755)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("cannot replace %s: %w\nre-run with sudo, or install somewhere you own", path, err)
		}
		return err
	}
	return nil
}

// normalizeVersion strips the leading v so a stamped version ("0.2.0") and a
// tag ("v0.2.0") compare equal.
func normalizeVersion(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "v")
}

// isDevBuild reports a version that no release produced.
func isDevBuild(s string) bool {
	v := normalizeVersion(s)
	if strings.Contains(v, "-dev") || v == "" || v == "dev" {
		return true
	}
	// A stamped release version starts with a number; anything else came from
	// a local build.
	if _, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0]); err != nil {
		return true
	}
	return false
}
