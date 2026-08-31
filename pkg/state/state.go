// Package state persists scorecards between runs.
//
// The regression gate is the most valuable gate in the system and the only
// one that needs memory: "you are not worse than you were" is enforceable on
// a legacy codebase from day one, where "you have no high findings" is not.
// A gate nobody can ever pass gets switched off in a week.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scorecard"
)

// Snapshot is one recorded scan.
type Snapshot struct {
	Scorecard    *scorecard.Scorecard `json:"scorecard"`
	Fingerprints []string             `json:"fingerprints"`
	// FirstSeen preserves when each finding was first observed, so age
	// survives across runs.
	FirstSeen map[string]time.Time `json:"first_seen,omitempty"`
}

// Store reads and writes snapshots under a state directory.
type Store struct{ dir string }

func New(dir string) *Store { return &Store{dir: dir} }

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, name)
}

// baselineName maps a branch to its snapshot file. Per-branch snapshots stop
// a feature branch's scan from becoming the baseline main is compared to.
//
// Branch names are attacker-influenceable in a fork-based workflow, and they
// routinely contain slashes, so the readable part is reduced to an alphabet
// that cannot express a path, and a hash of the original is appended. The
// hash also keeps two branches that sanitize to the same string apart, which
// matters because a collision would silently compare one branch's scan
// against another's baseline.
func baselineName(branch string) string {
	if branch == "" {
		return "baseline.json"
	}
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, branch)
	if len(safe) > 40 {
		safe = safe[:40]
	}
	sum := sha256.Sum256([]byte(branch))
	return fmt.Sprintf("baseline-%s-%s.json", safe, hex.EncodeToString(sum[:])[:8])
}

// Load reads the snapshot for a branch, falling back to the default snapshot
// so a new branch inherits main's baseline rather than starting from nothing.
func (s *Store) Load(branch string) (*Snapshot, error) {
	for _, name := range []string{baselineName(branch), "baseline.json"} {
		data, err := os.ReadFile(s.path(name))
		if err != nil {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return nil, fmt.Errorf("parse snapshot %s: %w", name, err)
		}
		return &snap, nil
	}
	return nil, nil
}

// Save writes a snapshot for a branch.
func (s *Store) Save(branch string, sc *scorecard.Scorecard, findings []finding.Finding) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	snap := Snapshot{
		Scorecard: sc,
		FirstSeen: make(map[string]time.Time, len(findings)),
	}
	for _, f := range findings {
		snap.Fingerprints = append(snap.Fingerprints, f.Fingerprint)
		snap.FirstSeen[f.Fingerprint] = f.FirstSeen
	}
	sort.Strings(snap.Fingerprints)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	path := s.path(baselineName(branch))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return os.Rename(tmp, path)
}

// MarkNew flags findings absent from the previous snapshot, delegating the
// diffing itself to the finding package so the CLI and the platform share one
// implementation.
func MarkNew(findings []finding.Finding, prev *Snapshot) (newCount, fixedCount int) {
	if prev == nil {
		return finding.MarkNew(findings, nil)
	}
	known := make(map[string]time.Time, len(prev.Fingerprints))
	for _, fp := range prev.Fingerprints {
		known[fp] = prev.FirstSeen[fp]
	}
	return finding.MarkNew(findings, known)
}

// Known renders a snapshot as the fingerprint-to-first-seen map the diffing
// logic consumes.
func (s *Snapshot) Known() map[string]time.Time {
	if s == nil {
		return nil
	}
	known := make(map[string]time.Time, len(s.Fingerprints))
	for _, fp := range s.Fingerprints {
		known[fp] = s.FirstSeen[fp]
	}
	return known
}
