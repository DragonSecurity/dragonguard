package pipeline_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/pipeline"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// The corpus check answers the one question DragonGuard cannot answer about
// itself: did an engine quietly stop finding something?
//
// Every other test here runs against recorded evidence, which is what makes
// them fast and deterministic -- and also what makes them blind to the engines
// changing underneath. This one runs the real scanners against deliberately
// broken fixtures and asserts the detections are still there. It is the test
// that gives a Renovate bump of trivy or opengrep something to prove.
//
// It must be run with -count=1. Go's test cache keys on the Go inputs, and the
// thing being tested here is not one: the engines are external binaries, the
// fixtures are read by those binaries rather than by this process, and the
// whole point is to notice when an engine version changes. A cached pass would
// report success for exactly the bump it exists to examine.

type expectation struct {
	Detections []struct {
		Scanner string `yaml:"scanner"`
		Rule    string `yaml:"rule"`
		File    string `yaml:"file"`
	} `yaml:"detections"`
	Packages []struct {
		Ecosystem string `yaml:"ecosystem"`
		Name      string `yaml:"name"`
		Version   string `yaml:"version"`
	} `yaml:"packages"`
	MinimumByCategory map[string]int `yaml:"minimum_by_category"`
}

func TestCorpusDetectionsHaveNotRegressed(t *testing.T) {
	// Absolute, because findings record their path relative to the scan root
	// and a relative Dir leaves every one of them prefixed with ../../ -- which
	// makes expected.yaml depend on where the test was invoked from.
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(filepath.Join(dir, ".dragon.yaml"), dir)
	if err != nil {
		t.Fatalf("load corpus config: %v", err)
	}

	var want expectation
	raw, err := os.ReadFile(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		t.Fatalf("read expected.yaml: %v", err)
	}
	if err := yaml.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse expected.yaml: %v", err)
	}

	writeCredentialFixture(t, dir)
	requireEngines(t, cfg, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	res, err := pipeline.Run(ctx, pipeline.Options{
		Dir:    dir,
		Config: cfg,
		// Offline: the corpus asserts what the engines detect, and EPSS/KEV
		// enrichment changes daily without any engine changing at all.
		Offline: true,
	})
	if err != nil {
		t.Fatalf("scan the corpus: %v", err)
	}

	type key struct{ scanner, rule, file string }
	found := map[key]bool{}
	byCategory := map[string]int{}
	for _, f := range res.Findings {
		found[key{f.Scanner, f.RuleID, filepath.ToSlash(f.Location.File)}] = true
		byCategory[string(f.Category)]++
	}

	// --- the asymmetric half: a detection that vanished is a regression ---
	var lost []string
	for _, d := range want.Detections {
		if !found[key{d.Scanner, d.Rule, d.File}] {
			lost = append(lost, fmt.Sprintf("%s %s in %s", d.Scanner, d.Rule, d.File))
		}
	}
	if len(lost) > 0 {
		sort.Strings(lost)
		t.Errorf("%d detection(s) present when expected.yaml was recorded are gone now:\n  %s\n\n"+
			"This is what a regression looks like: the fixtures did not change, so an engine "+
			"or a rule stopped matching. Do not update expected.yaml to make this pass without "+
			"establishing why the detection went away.",
			len(lost), strings.Join(lost, "\n  "))
	}

	// SCA by package, never by CVE: advisories are published and withdrawn
	// daily, so a pinned CVE list fails for reasons that are not regressions.
	for _, p := range want.Packages {
		if !flagged(res.Findings, p.Ecosystem, p.Name, p.Version) {
			t.Errorf("no vulnerability reported against %s %s@%s, which is pinned to a known-vulnerable version",
				p.Ecosystem, p.Name, p.Version)
		}
	}

	// A category at zero means an engine did not run, rather than ran and
	// matched nothing -- worth saying plainly instead of as a dozen separate
	// missing detections.
	for cat, min := range want.MinimumByCategory {
		if got := byCategory[cat]; got < min {
			t.Errorf("%s findings: %d, expected at least %d -- check whether the engine covering it ran at all", cat, got, min)
		}
	}

	// --- the other half: new detections are reported, never failed ---
	var added []string
	for k := range found {
		known := false
		for _, d := range want.Detections {
			if d.Scanner == k.scanner && d.Rule == k.rule && d.File == k.file {
				known = true
				break
			}
		}
		// SCA rule IDs are CVE identifiers and churn by design; listing them
		// as "new" every time the database updates would bury the signal.
		if !known && !strings.HasPrefix(k.rule, "CVE-") && !strings.HasPrefix(k.rule, "GHSA-") {
			added = append(added, fmt.Sprintf("%s %s in %s", k.scanner, k.rule, k.file))
		}
	}
	if len(added) > 0 {
		sort.Strings(added)
		t.Logf("%d new detection(s) the engines did not previously report:\n  %s\n\n"+
			"Not a failure. An engine got better, or a rule got broader. Add them to "+
			"expected.yaml to hold the new floor.",
			len(added), strings.Join(added, "\n  "))
	}
}

// writeCredentialFixture generates the secret the corpus is scanned for.
//
// It is generated per run and never committed, because gitleaks scans git
// history: a plausible credential committed once is found by every future scan
// of this repository, by GitHub's own secret scanning, and by anyone who
// clones it. Excluding it by path does not help -- the path filter applies to
// the working tree, and history is not the working tree. CI proved that the
// hard way, reporting the fixture as a critical finding on a run where the
// local scan had been clean.
//
// The key is random and was issued by nobody, so it authenticates to nothing.
// It still has to look like a credential, because a detector that skips it
// proves nothing; generating it per run is what keeps that resemblance
// temporary.
func writeCredentialFixture(t *testing.T, dir string) {
	t.Helper()

	// Structural token formats, not an AWS-shaped key, and the difference is
	// the whole point.
	//
	// gitleaks' generic-api-key rule -- the only thing that matched the old
	// AWS_SECRET_ACCESS_KEY fixture -- guards itself with an entropy floor and
	// a stopword allowlist. The stopwords are the problem: a random forty-
	// character string that happens to contain a common English substring is
	// filtered on purpose, and roughly one draw in fifty does. Measured
	// against gitleaks 8.30.1 over 400 generated fixtures: 9 produced no
	// generic-api-key finding at all, and the AKIA line produced
	// aws-access-token in only 61 of them.
	//
	// So the corpus was failing about one run in forty on fixtures nobody had
	// touched, which is the behaviour it exists to catch in other people. A
	// regression detector that cries wolf teaches everyone to re-run it, and
	// that is exactly how a real regression gets waved through.
	//
	// A GitHub PAT and a Slack bot token are matched structurally -- the
	// prefix and the length are the rule -- with no entropy floor and no
	// stopword list to trip over. The same 400-fixture measurement: 400 of
	// 400, two detections each, no variance at all.
	const (
		alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		digits       = "0123456789"
	)
	pick := func(alphabet string, n int) string {
		b := make([]byte, n)
		for i := range b {
			// crypto/rand, not math/rand: a fixture generated from a
			// predictable sequence would be the same string on every machine,
			// which is a committed credential with extra steps.
			v, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				t.Fatal(err)
			}
			b[i] = alphabet[v.Int64()]
		}
		return string(b)
	}

	body := fmt.Sprintf(`# Generated by the corpus test. Gitignored, never committed.
# Random, issued by nobody, authenticates to nothing.
GITHUB_TOKEN=ghp_%s
SLACK_BOT_TOKEN=xoxb-%s-%s
`, pick(alphanumeric, 36), pick(digits, 13), pick(alphanumeric, 24))

	path := filepath.Join(dir, "secrets", "config.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the credential fixture: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })
}

func flagged(findings []finding.Finding, ecosystem, name, version string) bool {
	for _, f := range findings {
		p := f.Package
		if p == nil {
			continue
		}
		if strings.EqualFold(p.Ecosystem, ecosystem) && p.Name == name && p.Version == version {
			return true
		}
	}
	return false
}

// requireEngines refuses to let the check pass by not running.
//
// A regression test that skips when its engines are missing is worse than no
// test: it reports success on every machine that cannot actually check
// anything. Locally that is a fair trade and it skips. In CI, where the
// engines are installed on purpose, DRAGON_CORPUS=require turns a skip into a
// failure -- otherwise a broken install would look exactly like a clean run.
func requireEngines(t *testing.T, cfg *config.Config, dir string) {
	t.Helper()

	var missing []string
	for _, s := range pipeline.DefaultRegistry().All() {
		if ec, ok := cfg.Engines[s.Name()]; ok && !ec.IsEnabled() {
			continue
		}
		// An engine that assesses the resolved inventory is correctly
		// unavailable before there is one. Asking it here is asking a
		// first-pass question of a second-pass engine, and the honest answer
		// reads as a missing binary.
		if inv, ok := s.(scanner.InventoryScanner); ok && inv.NeedsInventory() {
			continue
		}
		target := scanner.Target{Dir: dir, Config: cfg}
		if ok, reason := s.Available(context.Background(), target); !ok {
			missing = append(missing, fmt.Sprintf("%s (%s)", s.Name(), reason))
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)
	msg := "engines unavailable: " + strings.Join(missing, ", ")
	if os.Getenv("DRAGON_CORPUS") == "require" {
		t.Fatalf("%s\n\nDRAGON_CORPUS=require, so this is a failure rather than a skip: "+
			"a corpus check that quietly does not run is the same as not having one.", msg)
	}
	t.Skipf("%s; set DRAGON_CORPUS=require to make this a failure", msg)
}
