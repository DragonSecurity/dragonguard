// Package trivy adapts Aqua's Trivy into DragonGuard's Finding schema.
//
// Trivy earns its place as the first engine because one binary spans SCA,
// container, IaC misconfiguration, secrets and licences -- most of a
// Snyk-shaped product's surface area from a single subprocess.
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

const binary = "trivy"

// Scanner runs Trivy over a directory or a container image.
type Scanner struct {
	// Scanners overrides which Trivy sub-scanners run.
	Scanners []string
}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "trivy" }

func (s *Scanner) Categories() []finding.Category {
	return []finding.Category{
		finding.CategorySCA,
		finding.CategoryContainer,
		finding.CategoryIaC,
		finding.CategorySecret,
		finding.CategoryLicense,
	}
}

func (s *Scanner) Available(ctx context.Context, t scanner.Target) (bool, string) {
	_, ok, reason := scanner.LookPath(binary)
	return ok, reason
}

// report mirrors the subset of Trivy's JSON output we consume.
type report struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []result `json:"Results"`
}

// result is one scanned target. Trivy emits several per target: the lang-pkgs
// result carries the package inventory and the vulnerabilities, and a separate
// license result carries the licences with no Packages and an empty Type.
type result struct {
	Target string `json:"Target"`
	Class  string `json:"Class"`
	Type   string `json:"Type"`

	Packages          []pkgEntry      `json:"Packages"`
	Vulnerabilities   []vulnerability `json:"Vulnerabilities"`
	Misconfigurations []misconfig     `json:"Misconfigurations"`
	Secrets           []secret        `json:"Secrets"`
	Licenses          []license       `json:"Licenses"`
}

// pkgEntry is one component from Trivy's package inventory. Trivy already
// parses the lockfile to find vulnerabilities, so its Relationship and
// DependsOn fields are a complete local dependency graph for free -- no
// network round-trip, and it reflects what this project actually resolved.
type pkgEntry struct {
	ID           string   `json:"ID"`
	Name         string   `json:"Name"`
	Version      string   `json:"Version"`
	Relationship string   `json:"Relationship"`
	Indirect     bool     `json:"Indirect"`
	Dev          bool     `json:"Dev"`
	DependsOn    []string `json:"DependsOn"`
	Identifier   struct {
		PURL string `json:"PURL"`
	} `json:"Identifier"`
}

type vulnerability struct {
	VulnerabilityID string   `json:"VulnerabilityID"`
	VendorIDs       []string `json:"VendorIDs"`
	PkgID           string   `json:"PkgID"`
	PkgName         string   `json:"PkgName"`
	PkgPath         string   `json:"PkgPath"`
	PkgIdentifier   struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	CweIDs           []string `json:"CweIDs"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CVSS             map[string]struct {
		V3Vector string  `json:"V3Vector"`
		V3Score  float64 `json:"V3Score"`
		V2Score  float64 `json:"V2Score"`
	} `json:"CVSS"`
}

// bestCVSS picks the highest-authority score available.
//
// Vendors disagree, sometimes by several points. Preferring NVD then GHSA
// then whatever else keeps scoring stable between runs rather than depending
// on Go's map iteration order.
func (v vulnerability) bestCVSS() (float64, string) {
	for _, src := range []string{"nvd", "ghsa", "redhat"} {
		if c, ok := v.CVSS[src]; ok && c.V3Score > 0 {
			return c.V3Score, c.V3Vector
		}
	}
	var best float64
	var vector string
	// Deterministic fallback: highest score wins, ties broken by vector.
	for _, c := range v.CVSS {
		if c.V3Score > best || (c.V3Score == best && c.V3Vector < vector) {
			best, vector = c.V3Score, c.V3Vector
		}
	}
	if best == 0 {
		for _, c := range v.CVSS {
			if c.V2Score > best {
				best = c.V2Score
			}
		}
	}
	return best, vector
}

type misconfig struct {
	Type          string   `json:"Type"`
	ID            string   `json:"ID"`
	AVDID         string   `json:"AVDID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	PrimaryURL    string   `json:"PrimaryURL"`
	References    []string `json:"References"`
	Status        string   `json:"Status"`
	CauseMetadata struct {
		Resource  string `json:"Resource"`
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

type license struct {
	Severity   string  `json:"Severity"`
	Category   string  `json:"Category"`
	PkgName    string  `json:"PkgName"`
	FilePath   string  `json:"FilePath"`
	Name       string  `json:"Name"`
	Confidence float64 `json:"Confidence"`
	Link       string  `json:"Link"`
}

// Scan satisfies scanner.Scanner. Callers wanting the dependency graph should
// use ScanWithGraph, which the pipeline prefers automatically.
func (s *Scanner) Scan(ctx context.Context, t scanner.Target) ([]finding.Finding, error) {
	fs, _, err := s.ScanWithGraph(ctx, t)
	return fs, err
}

// ScanWithGraph runs Trivy once and returns both the findings and the
// dependency graph read from the same output.
func (s *Scanner) ScanWithGraph(ctx context.Context, t scanner.Target) ([]finding.Finding, *scanner.PackageGraph, error) {
	subScanners := s.Scanners
	if len(subScanners) == 0 {
		subScanners = []string{"vuln", "secret", "misconfig", "license"}
	}

	args := []string{}
	if t.Image != "" {
		args = append(args, "image", "--image-src", "remote")
	} else {
		args = append(args, "fs")
	}
	args = append(args,
		"--scanners", strings.Join(subScanners, ","),
		"--format", "json",
		"--quiet",
		// The package inventory is what carries Relationship and DependsOn,
		// which is the dependency graph remediation needs.
		"--list-all-pkgs",
		// Findings we cannot act on are noise; the gate should reason about
		// what is actually present.
		"--ignore-unfixed=false",
	)

	if t.Config != nil {
		for _, ig := range t.Config.Ignore {
			args = append(args, "--skip-dirs", ig)
		}
		if ec, ok := t.Config.Engines["trivy"]; ok {
			args = append(args, ec.Args...)
		}
	}

	target := t.Dir
	if t.Image != "" {
		target = t.Image
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, binary, args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			return nil, nil, fmt.Errorf("trivy failed (exit %d): %s", ee.ExitCode(), truncate(string(ee.Stderr), 400))
		}
		return nil, nil, fmt.Errorf("run trivy: %w", err)
	}

	var rep report
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, nil, fmt.Errorf("parse trivy output: %w", err)
	}

	version := trivyVersion(ctx)
	var findings []finding.Finding
	graph := scanner.NewPackageGraph()

	// Licences arrive in their own Result -- Class "license", Type empty, no
	// Packages -- separate from the lang-pkgs Result that carries the
	// inventory for the same Target. Indexed here so a licence finding can say
	// which ecosystem it belongs to and what the project's relationship to the
	// package is, both of which were being read from the licence Result that
	// does not have them.
	inventory, ecosystemFor, directnessFor := indexInventory(rep.Results)

	for _, res := range rep.Results {
		rel := relativize(res.Target, t.Dir)

		// Index this result's inventory so vulnerabilities can be told
		// whether the package is something the project depends on directly.
		byName := make(map[string]pkgEntry, len(res.Packages))
		for _, p := range res.Packages {
			byName[p.Name+"\x00"+p.Version] = p
			graph.Add(scanner.PackageNode{
				Ecosystem:  res.Type,
				Name:       p.Name,
				Version:    p.Version,
				PURL:       p.Identifier.PURL,
				Direct:     isDirect(p, directnessFor[res.Target]),
				Root:       strings.EqualFold(p.Relationship, "root"),
				Directness: directnessFor[res.Target].String(),
				DevOnly:    p.Dev,
				DependsOn:  p.DependsOn,
			})
		}

		for _, v := range res.Vulnerabilities {
			cvss, vector := v.bestCVSS()
			cat := finding.CategorySCA
			// Trivy reports OS packages from an image scan under the same
			// vulnerability shape; the distinction matters to the scorecard.
			if t.Image != "" || res.Class == "os-pkgs" {
				cat = finding.CategoryContainer
			}
			f := finding.Finding{
				Scanner:          s.Name(),
				ScannerVersion:   version,
				ScannerFindingID: v.VulnerabilityID,
				Category:         cat,
				RuleID:           v.VulnerabilityID,
				Title:            firstNonEmpty(v.Title, v.VulnerabilityID),
				Message:          v.Description,
				CVE:              cveIDs(v.VulnerabilityID, v.VendorIDs),
				CWE:              v.CweIDs,
				Severity:         finding.NormalizeSeverity(v.Severity),
				Location:         finding.Location{File: firstNonEmpty(v.PkgPath, rel)},
				Package: &finding.Package{
					Ecosystem: res.Type,
					Name:      v.PkgName,
					Version:   v.InstalledVersion,
					PURL:      v.PkgIdentifier.PURL,
					Direct:    isDirect(byName[v.PkgName+"\x00"+v.InstalledVersion], directnessFor[res.Target]),
					DevOnly:   byName[v.PkgName+"\x00"+v.InstalledVersion].Dev,
				},
				Threat: finding.Threat{CVSS: cvss, CVSSVector: vector},
				Analysis: finding.Analysis{
					FixAvailable: v.FixedVersion != "",
					FixedVersion: v.FixedVersion,
				},
				References: appendURL(v.References, v.PrimaryURL),
			}
			if v.FixedVersion != "" {
				f.Analysis.MinimalUpgrade = fmt.Sprintf("%s %s -> %s", v.PkgName, v.InstalledVersion, v.FixedVersion)
			}
			findings = append(findings, f)
		}

		for _, m := range res.Misconfigurations {
			if strings.EqualFold(m.Status, "PASS") {
				continue
			}
			findings = append(findings, finding.Finding{
				Scanner:          s.Name(),
				ScannerVersion:   version,
				ScannerFindingID: m.AVDID,
				Category:         finding.CategoryIaC,
				RuleID:           firstNonEmpty(m.AVDID, m.ID),
				Title:            m.Title,
				Message:          firstNonEmpty(m.Message, m.Description),
				Severity:         finding.NormalizeSeverity(m.Severity),
				Location: finding.Location{
					File:      rel,
					StartLine: m.CauseMetadata.StartLine,
					EndLine:   m.CauseMetadata.EndLine,
				},
				Analysis:   finding.Analysis{FixAvailable: m.Resolution != ""},
				References: appendURL(m.References, m.PrimaryURL),
				Metadata: map[string]any{
					"resolution": m.Resolution,
					"provider":   m.CauseMetadata.Provider,
					"service":    m.CauseMetadata.Service,
					"resource":   m.CauseMetadata.Resource,
				},
			})
		}

		for _, sec := range res.Secrets {
			findings = append(findings, finding.Finding{
				Scanner:          s.Name(),
				ScannerVersion:   version,
				ScannerFindingID: sec.RuleID,
				Category:         finding.CategorySecret,
				RuleID:           sec.RuleID,
				Title:            firstNonEmpty(sec.Title, sec.RuleID),
				// Trivy already masks the value in Match. We keep it masked:
				// a findings database that stores live credentials in clear
				// text is a second breach waiting to happen.
				Message:  fmt.Sprintf("%s credential detected", firstNonEmpty(sec.Category, "secret")),
				Severity: finding.NormalizeSeverity(sec.Severity),
				Location: finding.Location{
					File:      rel,
					StartLine: sec.StartLine,
					EndLine:   sec.EndLine,
					Snippet:   sec.Match,
				},
				Metadata: map[string]any{"secret_category": sec.Category},
			})
		}

		for _, l := range res.Licenses {
			if !licenseWorthReporting(l.Category) {
				continue
			}
			findings = append(findings, finding.Finding{
				Scanner:        s.Name(),
				ScannerVersion: version,
				Category:       finding.CategoryLicense,
				RuleID:         "license/" + l.Name,
				Title:          fmt.Sprintf("%s licensed under %s", l.PkgName, l.Name),
				Message:        fmt.Sprintf("License category %s", l.Category),
				Severity:       finding.NormalizeSeverity(l.Severity),
				Location:       finding.Location{File: firstNonEmpty(relativize(l.FilePath, t.Dir), rel)},
				// The inventory entry, not just a name. A licence finding is a
				// decision about a dependency, and the facts that decide it --
				// the version, whether the project asked for this itself, and
				// whether it reaches a production artifact at all -- were being
				// dropped on the floor here while vulnerability findings on the
				// same package carried them.
				Package:    licensePackage(ecosystemFor[res.Target], l.PkgName, inventory[res.Target], directnessFor[res.Target]),
				References: appendURL(nil, l.Link),
				Metadata:   map[string]any{"license": l.Name, "license_category": l.Category},
			})
		}
	}
	return findings, graph, nil
}

// indexInventory maps each target's package inventory by name, and each
// target to its ecosystem.
//
// Both exist because licences arrive in their own result -- Class "license",
// Type empty, no Packages -- separate from the lang-pkgs result holding the
// inventory for the same Target. Reading the ecosystem and the package facts
// from the licence result gets an empty string and nothing, which is what a
// licence finding used to carry.
func indexInventory(results []result) (map[string]map[string]pkgEntry, map[string]string, map[string]directness) {
	inventory := map[string]map[string]pkgEntry{}
	ecosystemFor := map[string]string{}
	directnessFor := map[string]directness{}
	for _, res := range results {
		if len(res.Packages) == 0 {
			continue
		}
		if res.Type != "" {
			ecosystemFor[res.Target] = res.Type
		}
		if d := directnessOf(res.Packages); d != directnessUnknown {
			directnessFor[res.Target] = d
		}
		byPkgName := inventory[res.Target]
		if byPkgName == nil {
			byPkgName = map[string]pkgEntry{}
			inventory[res.Target] = byPkgName
		}
		for _, p := range res.Packages {
			// A direct dependency wins a name collision: where the same
			// package appears twice, the one the project asked for itself is
			// the one a reader is deciding about.
			d := directnessFor[res.Target]
			if prev, ok := byPkgName[p.Name]; !ok || (!isDirect(prev, d) && isDirect(p, d)) {
				byPkgName[p.Name] = p
			}
		}
	}
	return inventory, ecosystemFor, directnessFor
}

// directness records which field, if either, actually classifies a target's
// packages.
//
// Trivy populates Relationship for some ecosystems, Indirect for others, and
// neither for yarn: every package in a yarn.lock comes back with an empty
// Relationship and Indirect false. Reading "empty and not indirect" as direct
// therefore declared all 547 packages in one lockfile to be direct
// dependencies, which Trivy never said and the manifest flatly contradicts --
// that project names sixteen.
//
// So which field to trust is decided per target, from whether the target uses
// it at all, and where neither does the answer is that we do not know.
type directness int

const (
	directnessUnknown directness = iota
	byRelationship
	byIndirect
)

// String names the basis for a directness verdict, for consumers that need to
// tell "classified as transitive" from "never classified".
func (d directness) String() string {
	switch d {
	case byRelationship:
		return "relationship"
	case byIndirect:
		return "indirect"
	default:
		return "unknown"
	}
}

func directnessOf(pkgs []pkgEntry) directness {
	for _, p := range pkgs {
		if p.Relationship != "" {
			return byRelationship
		}
	}
	for _, p := range pkgs {
		if p.Indirect {
			return byIndirect
		}
	}
	return directnessUnknown
}

// isDirect reports whether the project's own manifest names this package,
// where the target's data supports an answer.
func isDirect(p pkgEntry, d directness) bool {
	switch d {
	case byRelationship:
		return strings.EqualFold(p.Relationship, "direct") || strings.EqualFold(p.Relationship, "root")
	case byIndirect:
		return !p.Indirect
	default:
		// Not "false because indirect" -- false because unestablished. A
		// package the scanner cannot classify must not be reported as one the
		// project asked for.
		return false
	}
}

// licensePackage builds the package block for a licence finding from the scan's
// own inventory, falling back to the bare name when the package is not in it.
func licensePackage(ecosystem, name string, byPkgName map[string]pkgEntry, d directness) *finding.Package {
	p, ok := byPkgName[name]
	if !ok {
		return &finding.Package{Ecosystem: ecosystem, Name: name}
	}
	return &finding.Package{
		Ecosystem: ecosystem,
		Name:      name,
		Version:   p.Version,
		PURL:      p.Identifier.PURL,
		Direct:    isDirect(p, d),
		DevOnly:   p.Dev,
	}
}

// licenseWorthReporting filters out licences that carry no obligation worth
// gating a release on.
//
// Trivy classifies every dependency's licence, including the MIT and Apache-2.0
// ones that make up most of any dependency tree. Surfacing those as findings
// buries the copyleft and unknown-licence cases that actually need a decision,
// and teaches people that the licence dimension is noise. Attribution-only,
// permissive and public-domain licences are therefore dropped; copyleft,
// reciprocal, forbidden and unclassifiable ones are kept.
//
// An organization that does need to track attribution obligations should scan
// for them with an SBOM tool, not with a release gate.
func licenseWorthReporting(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "notice", "permissive", "unencumbered":
		return false
	default:
		// Includes forbidden, restricted, reciprocal and unknown. An
		// unclassifiable licence is a real finding: it cannot be cleared
		// without somebody reading it.
		return true
	}
}

func trivyVersion(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, binary, "--version", "--format", "json").Output()
	if err != nil {
		return ""
	}
	var v struct {
		Version string `json:"Version"`
	}
	if json.Unmarshal(out, &v) == nil {
		return v.Version
	}
	return ""
}

// cveIDs keeps only real CVE identifiers. Trivy's VendorIDs mix GHSA and
// vendor advisory IDs in with them, and enrichment can only look up CVEs.
func cveIDs(primary string, vendor []string) []string {
	var out []string
	for _, id := range append([]string{primary}, vendor...) {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

func relativize(target, dir string) string {
	if dir == "" || target == "" {
		return target
	}
	if rel, err := filepath.Rel(dir, target); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return target
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func appendURL(refs []string, url string) []string {
	if url == "" {
		return refs
	}
	for _, r := range refs {
		if r == url {
			return refs
		}
	}
	return append(refs, url)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}
