// Package finding defines DragonGuard's canonical evidence object.
//
// Every scanner adapter converts its native output into a Finding. Nothing
// downstream of normalization -- risk scoring, policy, the scorecard, the
// baseline gate -- knows which tool produced the evidence. That is what lets
// an engine be swapped out without touching the control plane.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Category is the security engine that produced the evidence.
type Category string

const (
	CategorySAST        Category = "SAST"
	CategorySCA         Category = "SCA"
	CategoryContainer   Category = "CONTAINER"
	CategoryIaC         Category = "IAC"
	CategoryDAST        Category = "DAST"
	CategorySecret      Category = "SECRET"
	CategoryLicense     Category = "LICENSE"
	CategorySupplyChain Category = "SUPPLY_CHAIN"
)

// Dimension maps a category onto the scorecard dimension it contributes to.
func (c Category) Dimension() string {
	switch c {
	case CategorySAST:
		return "code"
	case CategorySCA, CategoryLicense:
		return "dependencies"
	case CategoryContainer:
		return "container"
	case CategoryIaC:
		return "iac"
	case CategorySecret:
		return "secrets"
	case CategoryDAST:
		return "api"
	case CategorySupplyChain:
		return "supply_chain"
	default:
		return "other"
	}
}

// Severity is the raw severity as reported by the scanner. It is deliberately
// NOT the thing the gate acts on -- RiskScore is. Severity is an input.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Normalize maps the many spellings scanners use onto our five levels.
func NormalizeSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "blocker":
		return SeverityCritical
	case "high", "error", "major":
		return SeverityHigh
	case "medium", "moderate", "warning", "warn":
		return SeverityMedium
	case "low", "minor", "note":
		return SeverityLow
	case "info", "informational", "unknown", "none", "":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

// Rank orders severities, highest first, for sorting and counting.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

// Status is the triage state of a finding.
type Status string

const (
	StatusOpen          Status = "open"
	StatusFixed         Status = "fixed"
	StatusIgnored       Status = "ignored"
	StatusAccepted      Status = "accepted"
	StatusFalsePositive Status = "false_positive"
)

// Package identifies a software component, keyed on purl where available.
type Package struct {
	Ecosystem string `json:"ecosystem,omitempty" yaml:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty" yaml:"name,omitempty"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
	PURL      string `json:"purl,omitempty" yaml:"purl,omitempty"`
	// Direct reports whether the project depends on this package itself
	// rather than inheriting it transitively.
	Direct bool `json:"direct" yaml:"direct"`
	// IntroducedBy names the direct dependency that pulled in a transitive
	// package, which is what a developer actually has to upgrade.
	IntroducedBy string `json:"introduced_by,omitempty" yaml:"introduced_by,omitempty"`
	// DevOnly marks a dependency that never reaches a production artifact.
	DevOnly bool `json:"dev_only" yaml:"dev_only"`
}

// NormalizeEcosystem maps the many spellings of a package ecosystem onto one
// canonical name.
//
// This matters more than it looks. Trivy calls Go modules "gomod", OSV calls
// them "Go", and purls call them "golang". The fingerprint is built from the
// ecosystem, so without this the same CVE in the same package reported by two
// engines produces two different findings -- which is precisely the
// duplication normalization exists to prevent.
func NormalizeEcosystem(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "npm", "node", "nodejs", "yarn", "pnpm", "node-pkg":
		return "npm"
	case "go", "gomod", "golang", "go-module", "gobinary":
		return "go"
	case "maven", "gradle", "jar", "java", "pom":
		return "maven"
	case "pypi", "pip", "python", "poetry", "uv", "pipenv", "python-pkg":
		return "pypi"
	case "cargo", "crates.io", "rust", "rust-binary":
		return "cargo"
	case "nuget", "dotnet", "csharp", "dotnet-core":
		return "nuget"
	case "rubygems", "gem", "gems", "bundler", "ruby":
		return "rubygems"
	case "composer", "php", "packagist":
		return "composer"
	case "conan", "cpp", "c++":
		return "conan"
	case "pub", "dart", "flutter":
		return "pub"
	case "hex", "elixir", "erlang":
		return "hex"
	case "swift", "swifturl", "cocoapods":
		return "swift"
	case "":
		return ""
	default:
		// An unrecognized ecosystem is kept verbatim rather than blanked:
		// two findings from the same unknown ecosystem should still match
		// each other, and OS package ecosystems (alpine, debian, ...) are
		// already consistent between engines.
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// Threat holds exploitation intelligence about a vulnerability. It is
// populated by enrichment, not by the scanner.
type Threat struct {
	// EPSS is the Exploit Prediction Scoring System probability, 0..1.
	EPSS float64 `json:"epss" yaml:"epss"`
	// EPSSKnown distinguishes "EPSS says this is unlikely" from "we could not
	// look EPSS up". Conflating the two silently downgrades real risk on
	// every offline run, so the risk engine must be able to tell them apart.
	EPSSKnown bool `json:"epss_known" yaml:"epss_known"`
	// KEV reports membership of CISA's Known Exploited Vulnerabilities catalog.
	KEV bool `json:"kev" yaml:"kev"`
	// KEVRansomware flags KEV entries with known ransomware campaign use.
	KEVRansomware  bool    `json:"kev_ransomware" yaml:"kev_ransomware"`
	ExploitAvailab bool    `json:"exploit_available" yaml:"exploit_available"`
	ExploitMaturit string  `json:"exploit_maturity,omitempty" yaml:"exploit_maturity,omitempty"`
	CVSS           float64 `json:"cvss" yaml:"cvss"`
	CVSSVector     string  `json:"cvss_vector,omitempty" yaml:"cvss_vector,omitempty"`
}

// Analysis holds conclusions drawn about the finding in the context of this
// codebase rather than about the vulnerability in the abstract.
type Analysis struct {
	// Reachable reports whether the vulnerable code is callable from the
	// application. Unset means "not determined", which is materially
	// different from "not reachable" -- see Reachability.
	Reachable    bool   `json:"reachable" yaml:"reachable"`
	Reachability string `json:"reachability" yaml:"reachability"` // reachable|unreachable|unknown
	FixAvailable bool   `json:"fix_available" yaml:"fix_available"`
	FixedVersion string `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"`
	// MinimalUpgrade is the smallest change that removes the vulnerability,
	// expressed against the direct dependency the developer controls.
	MinimalUpgrade string `json:"minimal_upgrade,omitempty" yaml:"minimal_upgrade,omitempty"`
	// VEXStatus carries any VEX assertion supplied for this finding.
	VEXStatus string `json:"vex_status,omitempty" yaml:"vex_status,omitempty"`
	// Verified reports that a credential was proven live, not merely matched.
	Verified bool `json:"verified" yaml:"verified"`
	// ScorecardScore is the upstream project's OpenSSF Scorecard result, 0..10.
	ScorecardScore float64 `json:"scorecard_score" yaml:"scorecard_score"`
	HasScorecard   bool    `json:"has_scorecard" yaml:"has_scorecard"`
}

// Location points at the code the finding is about.
type Location struct {
	File      string `json:"file,omitempty" yaml:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty" yaml:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty" yaml:"end_line,omitempty"`
	Snippet   string `json:"snippet,omitempty" yaml:"snippet,omitempty"`
}

// Finding is the canonical evidence object.
type Finding struct {
	ID string `json:"id" yaml:"id"`

	TenantID     string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	ProjectID    string `json:"project_id,omitempty" yaml:"project_id,omitempty"`
	RepositoryID string `json:"repository_id,omitempty" yaml:"repository_id,omitempty"`

	Scanner          string `json:"scanner" yaml:"scanner"`
	ScannerVersion   string `json:"scanner_version,omitempty" yaml:"scanner_version,omitempty"`
	ScannerFindingID string `json:"scanner_finding_id,omitempty" yaml:"scanner_finding_id,omitempty"`

	Category Category `json:"category" yaml:"category"`
	RuleID   string   `json:"rule_id" yaml:"rule_id"`
	Title    string   `json:"title" yaml:"title"`
	Message  string   `json:"message,omitempty" yaml:"message,omitempty"`

	CWE []string `json:"cwe,omitempty" yaml:"cwe,omitempty"`
	CVE []string `json:"cve,omitempty" yaml:"cve,omitempty"`

	Severity Severity `json:"severity" yaml:"severity"`

	Location Location `json:"location,omitempty" yaml:"location,omitempty"`
	Package  *Package `json:"package,omitempty" yaml:"package,omitempty"`

	Threat   Threat   `json:"threat" yaml:"threat"`
	Analysis Analysis `json:"analysis" yaml:"analysis"`

	// Fingerprint identifies the same finding across scans even as line
	// numbers move, so a scorecard can distinguish new findings from carried
	// ones. It deliberately excludes line numbers.
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`

	FirstSeen time.Time `json:"first_seen" yaml:"first_seen"`
	LastSeen  time.Time `json:"last_seen" yaml:"last_seen"`
	Status    Status    `json:"status" yaml:"status"`

	// RiskScore is the Dragon Risk verdict, 0..100, higher is worse. It is
	// written by the risk engine, not by a scanner.
	RiskScore   float64  `json:"risk_score" yaml:"risk_score"`
	RiskRating  string   `json:"risk_rating" yaml:"risk_rating"`
	RiskReasons []string `json:"risk_reasons,omitempty" yaml:"risk_reasons,omitempty"`

	// New reports that this fingerprint was absent from the baseline scan.
	New bool `json:"new" yaml:"new"`

	// PolicyTags accumulate from matching policy rules.
	PolicyTags []string `json:"policy_tags,omitempty" yaml:"policy_tags,omitempty"`

	References []string       `json:"references,omitempty" yaml:"references,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// ComputeFingerprint derives a stable identity for a finding.
//
// Two properties matter, and they pull against each other.
//
// Stability across scans: line numbers are excluded, because a finding that
// shifted down three lines when somebody added an import is the same finding.
// A gate that reports it as new trains people to ignore the gate.
//
// Stability across engines: for evidence whose identity does not depend on
// who found it, the scanner name is excluded too. CVE-2021-23337 in
// lodash@4.17.11 is one problem whether Trivy or Grype reported it, and a
// credential at a location is one credential. Showing it twice makes the
// tool look broken and doubles the apparent size of the backlog.
//
// SAST is the exception: rule semantics are engine-specific, so two engines
// flagging the same line are making two different claims about it, and the
// scanner stays part of the identity.
// siteOf distinguishes one occurrence of a rule in a file from another.
//
// Without it a rule was one finding per file however many times it matched:
// three SQL injections in three functions collapsed into one, so two of the
// three defects were invisible, and fixing the reported one left the finding
// open because another site kept it alive. A suppression comment on one site
// looked like it had been ignored, for the same reason.
//
// The matched text rather than the line number, because the line is what the
// fingerprint was avoiding in the first place: adding a comment above a
// function would otherwise renumber every finding below it and report a file
// of unchanged problems as new. Text moves with the code.
//
// Whitespace is collapsed so reindentation is not a new finding. Two textually
// identical matches in one file still merge -- there is nothing left to tell
// them apart that does not reintroduce the line -- and a finding whose engine
// reports no snippet keeps the old file-level identity.
//
// For secrets this hashes the redacted form, which is what the adapters store.
// The plaintext must not reach a fingerprint: fingerprints are written to
// reports, snapshots and the platform database, and a hash of a live
// credential is a verifier for it.
func siteOf(f *Finding) string {
	snippet := strings.Join(strings.Fields(f.Location.Snippet), " ")
	if snippet == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(snippet))
	return hex.EncodeToString(sum[:])[:12]
}

func (f *Finding) ComputeFingerprint() string {
	h := sha256.New()
	parts := []string{string(f.Category)}

	switch f.Category {
	case CategorySCA, CategoryContainer:
		// A vulnerable component is identified by what it is, not by where
		// the lockfile happened to mention it or which tool read the file.
		if f.Package != nil {
			parts = append(parts, f.Package.Ecosystem, f.Package.Name, canonicalVersion(f.Package.Version))
		}
		cves := append([]string(nil), f.CVE...)
		sort.Strings(cves)
		parts = append(parts, strings.Join(cves, ","))
		if len(cves) == 0 {
			// A CVE is not the only scanner-independent name an advisory has.
			// GO-2026-5932, GHSA-…, RUSTSEC-… and the distro advisories are
			// issued by the database rather than by the tool that read it, so
			// two engines reporting one of them are reporting one problem.
			//
			// Treating them as scanner-specific produced exactly that: OSV and
			// Trivy both reported GO-2026-5932 against golang.org/x/crypto and
			// the report carried it twice, which doubles the apparent backlog
			// and makes the tool look like it cannot count.
			if id := advisoryID(f.RuleID); id != "" {
				parts = append(parts, id)
			} else {
				// A genuinely engine-specific rule. Its meaning depends on the
				// engine that defined it, so the engine stays in the identity.
				parts = append(parts, f.Scanner, f.RuleID)
			}
		}

	case CategorySecret:
		// Kind of credential, location, and which credential. Two keys in one
		// file are two keys: they are rotated separately, and merging them
		// meant fixing one and watching the finding stay open.
		parts = append(parts, f.RuleID, f.Location.File, siteOf(f))

	case CategoryIaC, CategoryDAST:
		parts = append(parts, f.RuleID, f.Location.File, siteOf(f))

	case CategoryLicense:
		name := ""
		if f.Package != nil {
			name = f.Package.Name
		}
		parts = append(parts, f.RuleID, name)

	default:
		// SAST and anything unrecognized: keep the scanner, because the rule
		// only means something in the context of the engine that defined it.
		parts = append(parts, f.Scanner, f.RuleID, f.Location.File, siteOf(f))
	}

	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Normalize fills in the derived fields a scanner adapter should not have to
// set by hand, and is safe to call more than once.
func (f *Finding) Normalize(now time.Time) {
	if f.Status == "" {
		f.Status = StatusOpen
	}
	if f.Severity == "" {
		f.Severity = SeverityInfo
	}
	if f.Analysis.Reachability == "" {
		f.Analysis.Reachability = "unknown"
	}
	if f.Analysis.FixedVersion != "" {
		f.Analysis.FixAvailable = true
	}
	if f.Title == "" {
		f.Title = f.RuleID
	}
	f.CVE = dedupeUpper(f.CVE)
	f.CWE = dedupeUpper(f.CWE)
	if f.Package != nil {
		f.Package.Ecosystem = NormalizeEcosystem(f.Package.Ecosystem)
	}
	f.Fingerprint = f.ComputeFingerprint()
	if f.ID == "" {
		f.ID = f.Fingerprint
	}
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	f.LastSeen = now
}

// PrimaryCVE returns the CVE a finding is chiefly about, if any.
func (f *Finding) PrimaryCVE() string {
	if len(f.CVE) == 0 {
		return ""
	}
	return f.CVE[0]
}

// Ref is a short human label for the finding, used in reports.
func (f *Finding) Ref() string {
	if cve := f.PrimaryCVE(); cve != "" {
		return cve
	}
	if f.RuleID != "" {
		return f.RuleID
	}
	return f.ID
}

// LocationRef renders the location as file:line, clickable in most terminals.
func (f *Finding) LocationRef() string {
	if f.Location.File == "" {
		if f.Package != nil {
			return fmt.Sprintf("%s@%s", f.Package.Name, f.Package.Version)
		}
		return ""
	}
	if f.Location.StartLine > 0 {
		return fmt.Sprintf("%s:%d", f.Location.File, f.Location.StartLine)
	}
	return f.Location.File
}

// canonicalVersion strips decoration that differs between engines describing
// the same release.
//
// Go modules are the case that forces this: Trivy reports "v2.2.2" and
// OSV-Scanner reports "2.2.2" for one version of one package. Only the
// fingerprint uses this form -- reports still show whatever the scanner
// actually said, because rewriting a version we were told is a good way to
// make a report disagree with the lockfile it came from.
// advisoryPrefixes are the advisory databases whose identifiers name a
// vulnerability rather than a tool's opinion of one.
//
// Deliberately a list rather than a pattern. "Looks like an identifier" would
// also match an engine's own rule naming scheme, and merging two engines'
// distinct rules because their ids rhyme is a worse failure than showing one
// advisory twice: it hides a finding rather than duplicating one.
var advisoryPrefixes = []string{
	"GHSA-",    // GitHub Security Advisories
	"GO-",      // Go vulnerability database
	"OSV-",     // OSV
	"PYSEC-",   // Python
	"RUSTSEC-", // Rust
	"GMS-",     // GitLab
	"DSA-",     // Debian
	"DLA-",     // Debian LTS
	"RHSA-",    // Red Hat
	"USN-",     // Ubuntu
	"ALAS-",    // Amazon Linux
	"ELSA-",    // Oracle Linux
}

// advisoryID returns the rule id when it names an advisory that any engine
// could have reported, and empty when the rule belongs to one engine.
func advisoryID(ruleID string) string {
	id := strings.ToUpper(strings.TrimSpace(ruleID))
	for _, p := range advisoryPrefixes {
		if strings.HasPrefix(id, p) {
			return id
		}
	}
	return ""
}

func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

func dedupeUpper(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SortByRisk orders findings most-urgent first, with a stable tiebreak so
// report output does not churn between identical scans.
func SortByRisk(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].RiskScore != fs[j].RiskScore {
			return fs[i].RiskScore > fs[j].RiskScore
		}
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].Fingerprint < fs[j].Fingerprint
	})
}

// Merge folds a duplicate finding from another engine into this one.
//
// Two engines reporting the same problem is corroboration, not noise, and
// each usually knows something the other does not: Trivy resolves a fixed
// version, Gitleaks knows which commit introduced a credential. Keeping only
// whichever happened to be collected first throws that away.
//
// The merge is deliberately monotone -- it only ever adds information or
// raises severity, never lowers it. A merge that could downgrade a finding
// would make the result depend on engine ordering, and a security verdict
// that changes when you reorder a config file is not a verdict.
func (f *Finding) Merge(other Finding) {
	if other.Severity.Rank() > f.Severity.Rank() {
		f.Severity = other.Severity
	}
	f.CVE = dedupeUpper(append(f.CVE, other.CVE...))
	f.CWE = dedupeUpper(append(f.CWE, other.CWE...))

	for _, r := range other.References {
		if !containsStr(f.References, r) {
			f.References = append(f.References, r)
		}
	}

	if f.Threat.CVSS == 0 && other.Threat.CVSS > 0 {
		f.Threat.CVSS = other.Threat.CVSS
		f.Threat.CVSSVector = other.Threat.CVSSVector
	}
	if other.Analysis.FixedVersion != "" && f.Analysis.FixedVersion == "" {
		f.Analysis.FixedVersion = other.Analysis.FixedVersion
		f.Analysis.FixAvailable = true
	}
	if other.Analysis.MinimalUpgrade != "" && f.Analysis.MinimalUpgrade == "" {
		f.Analysis.MinimalUpgrade = other.Analysis.MinimalUpgrade
	}
	if other.Analysis.Verified {
		f.Analysis.Verified = true
	}
	// Reachability only ever moves toward "reachable": one engine proving a
	// path outranks another failing to find one.
	if other.Analysis.Reachability == "reachable" {
		f.Analysis.Reachability = "reachable"
		f.Analysis.Reachable = true
	}

	if f.Message == "" {
		f.Message = other.Message
	}
	if f.Location.File == "" {
		f.Location = other.Location
	}
	if f.Package == nil {
		f.Package = other.Package
	}

	if f.Metadata == nil {
		f.Metadata = map[string]any{}
	}
	for k, v := range other.Metadata {
		if _, exists := f.Metadata[k]; !exists {
			f.Metadata[k] = v
		}
	}
	also, _ := f.Metadata["also_reported_by"].([]string)
	if !containsStr(also, other.Scanner) && other.Scanner != f.Scanner {
		f.Metadata["also_reported_by"] = append(also, other.Scanner)
	}
}

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// MarkNew flags findings absent from a previous scan and restores the
// first-seen timestamp of those carried over. It returns how many are new and
// how many previously-known findings have since disappeared.
//
// known maps fingerprint to when that finding was first observed. Passing a
// map rather than a storage type is deliberate: the CLI reads it from a file
// snapshot and the platform reads it from Postgres, and neither detail belongs
// in the diffing logic.
//
// A nil map means no baseline exists, in which case everything is new. Saying
// so is more honest than pretending a first run has no regressions.
func MarkNew(findings []Finding, known map[string]time.Time) (newCount, fixedCount int) {
	if known == nil {
		for i := range findings {
			findings[i].New = true
		}
		return len(findings), 0
	}

	current := make(map[string]bool, len(findings))
	for i := range findings {
		f := &findings[i]
		current[f.Fingerprint] = true
		first, seen := known[f.Fingerprint]
		if !seen {
			f.New = true
			newCount++
			continue
		}
		f.New = false
		if !first.IsZero() {
			f.FirstSeen = first
		}
	}
	for fp := range known {
		if !current[fp] {
			fixedCount++
		}
	}
	return newCount, fixedCount
}
