// Package policy implements Dragon Policy: CEL evaluation of individual
// findings.
//
// CEL rather than Rego, deliberately. The language is non-Turing-complete,
// which means a customer policy cannot hang the gate; it type-checks ahead of
// evaluation, so a typo is caught when the policy is saved rather than during
// somebody's release; and its surface is small enough to generate safely from
// a form-based UI. Rego's strength is composition over large sets of
// resources and relationships, which is not the shape of this problem: every
// rule here is a predicate over one finding.
//
// Policies return decisions. They never perform side effects. A rule can say
// "create a ticket"; only the enforcement layer knows how. That boundary is
// what stops a policy language from slowly turning into an integration
// runtime.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"gopkg.in/yaml.v3"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// Decision is what a rule concludes about a finding.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionWarn  Decision = "warn"
	DecisionDeny  Decision = "deny"
)

// Rank orders decisions by severity so the strongest match governs.
func (d Decision) Rank() int {
	switch d {
	case DecisionDeny:
		return 3
	case DecisionWarn:
		return 2
	default:
		return 1
	}
}

// Effect is what a matching rule asks for.
type Effect struct {
	Decision Decision `yaml:"decision" json:"decision"`
	// Actions are names the enforcement layer resolves. Policy does not know
	// what "create_ticket" means, and must not.
	Actions []string `yaml:"actions,omitempty" json:"actions,omitempty"`
	// RiskBoost adjusts the finding's Dragon Risk score, positive or
	// negative, for customer-specific context the generic model cannot know.
	RiskBoost float64 `yaml:"risk_boost,omitempty" json:"risk_boost,omitempty"`
	// Tags are attached to the finding for later filtering.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Message explains the decision to whoever is blocked by it.
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
	// Exempt suppresses the finding entirely; used for accepted risk.
	Exempt bool `yaml:"exempt,omitempty" json:"exempt,omitempty"`
}

// Match is the structured, non-CEL rule form.
//
// This exists so the product can offer policy authoring through a form
// without ever exposing an expression language. Every clause compiles to CEL,
// so structured and hand-written rules run through exactly one evaluator.
type Match struct {
	All  []string `yaml:"all,omitempty" json:"all,omitempty"`
	Any  []string `yaml:"any,omitempty" json:"any,omitempty"`
	None []string `yaml:"none,omitempty" json:"none,omitempty"`
}

// Expr renders the structured form as a single CEL expression.
func (m Match) Expr() string {
	var clauses []string
	if len(m.All) > 0 {
		clauses = append(clauses, "("+strings.Join(wrap(m.All), " && ")+")")
	}
	if len(m.Any) > 0 {
		clauses = append(clauses, "("+strings.Join(wrap(m.Any), " || ")+")")
	}
	for _, n := range m.None {
		clauses = append(clauses, "!("+n+")")
	}
	if len(clauses) == 0 {
		return ""
	}
	return strings.Join(clauses, " && ")
}

func wrap(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = "(" + s + ")"
	}
	return out
}

// Rule is one policy statement.
type Rule struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// When is a raw CEL expression over the evaluation context.
	When string `yaml:"when,omitempty" json:"when,omitempty"`
	// Match is the structured alternative to When.
	Match Match `yaml:"match,omitempty" json:"match,omitempty"`
	// Then is the effect applied when the rule matches.
	Then Effect `yaml:"then" json:"then"`
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	program cel.Program
	source  string
}

func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Source returns the CEL actually evaluated, whether hand-written or compiled
// from the structured form. Showing this in the UI is what keeps a
// form-authored policy auditable.
func (r *Rule) Source() string { return r.source }

// Pack is a set of rules loaded from one file.
type Pack struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Kind       string `yaml:"kind" json:"kind"`
	Metadata   struct {
		Name        string `yaml:"name" json:"name"`
		Description string `yaml:"description,omitempty" json:"description,omitempty"`
	} `yaml:"metadata" json:"metadata"`
	Rules []Rule `yaml:"rules" json:"rules"`

	Path string `yaml:"-" json:"-"`
}

// Result is one rule matching one finding.
type Result struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description,omitempty"`
	Decision    Decision `json:"decision"`
	Actions     []string `json:"actions,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Message     string   `json:"message,omitempty"`
	RiskBoost   float64  `json:"risk_boost,omitempty"`
	Exempt      bool     `json:"exempt,omitempty"`
	Fingerprint string   `json:"fingerprint"`
}

// Evaluation is the aggregate outcome for one finding.
type Evaluation struct {
	Fingerprint string   `json:"fingerprint"`
	Decision    Decision `json:"decision"`
	Results     []Result `json:"results"`
	Exempt      bool     `json:"exempt"`
	// Errors records rules that failed to evaluate. A rule that errors is
	// never treated as "did not match": a policy that silently stops
	// enforcing is the worst outcome this system can produce.
	Errors []string `json:"errors,omitempty"`
}

// Engine evaluates policy packs against findings.
type Engine struct {
	env   *cel.Env
	packs []*Pack
	rules []*Rule
}

// NewEngine builds the CEL environment. The variable set is the contract
// policies are written against, so it is declared once, here.
func NewEngine() (*Engine, error) {
	mapType := cel.MapType(cel.StringType, cel.DynType)
	env, err := cel.NewEnv(
		cel.Variable("finding", mapType),
		cel.Variable("threat", mapType),
		cel.Variable("analysis", mapType),
		cel.Variable("risk", mapType),
		cel.Variable("asset", mapType),
		// "component" rather than "package": package is a CEL reserved word.
		cel.Variable("component", mapType),
		cel.Variable("scan", mapType),
	)
	if err != nil {
		return nil, fmt.Errorf("build CEL environment: %w", err)
	}
	return &Engine{env: env}, nil
}

// Packs returns the loaded packs.
func (e *Engine) Packs() []*Pack { return e.packs }

// Rules returns every loaded rule, enabled or not.
func (e *Engine) Rules() []*Rule { return e.rules }

// LoadPaths loads policy packs from files and directories.
func (e *Engine) LoadPaths(paths []string) error {
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("policy path %s: %w", p, err)
		}
		if st.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				return fmt.Errorf("read policy dir %s: %w", p, err)
			}
			var files []string
			for _, en := range entries {
				if en.IsDir() {
					continue
				}
				if ext := strings.ToLower(filepath.Ext(en.Name())); ext == ".yaml" || ext == ".yml" {
					files = append(files, filepath.Join(p, en.Name()))
				}
			}
			// Deterministic load order keeps rule precedence stable.
			sort.Strings(files)
			for _, f := range files {
				if err := e.LoadFile(f); err != nil {
					return err
				}
			}
			continue
		}
		if err := e.LoadFile(p); err != nil {
			return err
		}
	}
	return nil
}

// LoadFile loads and compiles one policy pack.
func (e *Engine) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read policy %s: %w", path, err)
	}
	var pack Pack
	if err := yaml.Unmarshal(raw, &pack); err != nil {
		return fmt.Errorf("parse policy %s: %w", path, err)
	}
	pack.Path = path

	if pack.Kind != "" && pack.Kind != "PolicyPack" {
		return fmt.Errorf("%s: kind %q is not PolicyPack", path, pack.Kind)
	}

	seen := make(map[string]bool)
	for i := range pack.Rules {
		r := &pack.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("%s: rule %d has no id", path, i)
		}
		if seen[r.ID] {
			return fmt.Errorf("%s: duplicate rule id %q", path, r.ID)
		}
		seen[r.ID] = true

		if err := e.compile(r); err != nil {
			return fmt.Errorf("%s: rule %q: %w", path, r.ID, err)
		}
		e.rules = append(e.rules, r)
	}
	e.packs = append(e.packs, &pack)
	return nil
}

// compile type-checks a rule and proves it evaluates against a canonical
// input.
//
// The second half matters as much as the first. CEL type-checks a map lookup
// as dyn, so `threat.kevv` compiles cleanly and then fails at scan time on a
// real finding -- which is to say, it fails during somebody's release rather
// than when they wrote it. Running every rule against a fully-populated
// sample at load time turns that into an authoring error.
func (e *Engine) compile(r *Rule) error {
	src := strings.TrimSpace(r.When)
	if src == "" {
		src = r.Match.Expr()
	}
	if src == "" {
		return fmt.Errorf("has neither `when` nor `match`")
	}
	r.source = src

	ast, iss := e.env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return fmt.Errorf("invalid expression: %w", iss.Err())
	}
	// The context variables are declared as map(string, dyn), so a bare field
	// access such as `threat.kev` type-checks as dyn rather than bool even
	// though it always yields one. Rejecting dyn here would refuse the most
	// natural thing a policy author writes, so the static check only rules
	// out types that can never be a predicate, and the sample evaluation
	// below settles what dyn actually resolves to.
	outType := ast.OutputType()
	if !outType.IsExactType(cel.BoolType) && !outType.IsExactType(cel.DynType) {
		return fmt.Errorf("expression must evaluate to bool, got %s", outType)
	}
	prg, err := e.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return fmt.Errorf("build program: %w", err)
	}
	r.program = prg

	out, _, err := prg.Eval(sampleActivation())
	if err != nil {
		return fmt.Errorf("expression fails on a well-formed finding (check field names): %w", err)
	}
	if _, ok := out.Value().(bool); !ok {
		return fmt.Errorf("expression must evaluate to bool, got %T", out.Value())
	}

	if r.Then.Decision == "" {
		r.Then.Decision = DecisionWarn
	}
	switch r.Then.Decision {
	case DecisionAllow, DecisionWarn, DecisionDeny:
	default:
		return fmt.Errorf("decision %q is not allow, warn or deny", r.Then.Decision)
	}
	return nil
}

// Evaluate runs every enabled rule against a finding in aggregate mode.
//
// Aggregate rather than first-match: the scorecard downstream needs every
// contribution, and a security review that stops at the first matching rule
// hides the rest of what is wrong.
func (e *Engine) Evaluate(f *finding.Finding, asset config.Asset, scan map[string]any) Evaluation {
	act := activationFor(f, asset, scan)
	ev := Evaluation{Fingerprint: f.Fingerprint, Decision: DecisionAllow}

	for _, r := range e.rules {
		if !r.IsEnabled() {
			continue
		}
		out, _, err := r.program.Eval(act)
		if err != nil {
			// Fail loud, not open.
			ev.Errors = append(ev.Errors, fmt.Sprintf("rule %s: %v", r.ID, err))
			continue
		}
		matched, ok := out.Value().(bool)
		if !ok {
			ev.Errors = append(ev.Errors, fmt.Sprintf("rule %s: non-boolean result", r.ID))
			continue
		}
		if !matched {
			continue
		}

		res := Result{
			RuleID:      r.ID,
			Description: r.Description,
			Decision:    r.Then.Decision,
			Actions:     r.Then.Actions,
			Tags:        r.Then.Tags,
			Message:     r.Then.Message,
			RiskBoost:   r.Then.RiskBoost,
			Exempt:      r.Then.Exempt,
			Fingerprint: f.Fingerprint,
		}
		ev.Results = append(ev.Results, res)
		if res.Exempt {
			ev.Exempt = true
		}
		if res.Decision.Rank() > ev.Decision.Rank() {
			ev.Decision = res.Decision
		}
	}

	// An exemption is an explicit decision that this finding is acceptable,
	// so it overrides any deny that also matched.
	if ev.Exempt {
		ev.Decision = DecisionAllow
	}
	return ev
}

// EvaluateAll evaluates every finding and applies the effects back onto them.
func (e *Engine) EvaluateAll(findings []finding.Finding, asset config.Asset, scan map[string]any) []Evaluation {
	evals := make([]Evaluation, len(findings))
	for i := range findings {
		ev := e.Evaluate(&findings[i], asset, scan)
		evals[i] = ev

		f := &findings[i]
		for _, res := range ev.Results {
			f.PolicyTags = appendUnique(f.PolicyTags, res.Tags...)
			if res.RiskBoost != 0 {
				f.RiskScore = clampScore(f.RiskScore + res.RiskBoost)
			}
		}
		if ev.Exempt {
			f.Status = finding.StatusAccepted
		}
		sort.Strings(f.PolicyTags)
	}
	return evals
}

func clampScore(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func appendUnique(dst []string, vals ...string) []string {
	for _, v := range vals {
		found := false
		for _, e := range dst {
			if e == v {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

// metaString reads a string out of a finding's metadata, or "" when absent.
func metaString(f *finding.Finding, key string) string {
	if f.Metadata == nil {
		return ""
	}
	if v, ok := f.Metadata[key].(string); ok {
		return v
	}
	return ""
}

// LoadLicensePolicy compiles the project's licence decisions into ordinary
// rules.
//
// Desugared rather than evaluated separately, so there is one evaluation path
// and one place a decision can come from. A licence approval is a policy
// exemption that happens to have a friendlier spelling, and it shows up in the
// policy evaluations like any other rule -- Source() renders the CEL, so the
// list stays auditable rather than becoming a second hidden mechanism.
func (e *Engine) LoadLicensePolicy(lp config.LicensePolicy) error {
	rules := make([]Rule, 0, len(lp.Allow)+len(lp.Deny))
	build := func(d config.LicenseDecision, allow bool) Rule {
		id := strings.TrimSpace(d.ID)
		verdict, prefix := DecisionDeny, "license-deny/"
		if allow {
			verdict, prefix = DecisionAllow, "license-allow/"
		}
		return Rule{
			ID:          prefix + id,
			Description: d.Reason,
			Match: Match{All: []string{
				`finding.category == "LICENSE"`,
				fmt.Sprintf("finding.license == %q", id),
			}},
			Then: Effect{
				Decision: verdict,
				// An approved licence stops counting: the obligation was read
				// and accepted, and leaving it in the score would mean the
				// only way to a clean dependencies dimension is to not use the
				// dependency.
				Exempt: allow,
				Tags:   []string{"license"},
			},
		}
	}
	// Deny first: the strongest decision governs, and an operator reading the
	// evaluations should see the refusal before the approvals.
	for _, d := range lp.Deny {
		rules = append(rules, build(d, false))
	}
	for _, d := range lp.Allow {
		rules = append(rules, build(d, true))
	}
	if len(rules) == 0 {
		return nil
	}
	raw, err := yaml.Marshal(rules)
	if err != nil {
		return fmt.Errorf("build licence policy: %w", err)
	}
	return e.LoadRules("licenses (.dragon.yaml)", raw)
}

// splitPackageSelector separates "name@version" into its parts, and leaves a
// bare name alone.
//
// The last "@", not the first: an npm scoped package is "@scope/name", so a
// leading "@" is part of the name and splitting on it would produce a selector
// matching nothing at all -- the failure this is here to remove, reintroduced
// for the packages most likely to be scoped.
func splitPackageSelector(sel string) (name, version string) {
	i := strings.LastIndex(sel, "@")
	if i <= 0 {
		return sel, ""
	}
	return sel[:i], sel[i+1:]
}

// versionMatch accepts a Go module version written either way.
//
// The report prints "github.com/spf13/viper@v1.21.0" and npm packages without
// the prefix, so whichever form somebody copies has to work. Comparing both
// spellings is cheaper than another silently-unmatched entry.
func versionMatch(version string) string {
	alt := strings.TrimPrefix(version, "v")
	if alt == version {
		alt = "v" + version
	}
	return fmt.Sprintf("(component.version == %q || component.version == %q)", version, alt)
}

// fingerprintLen is the width ComputeFingerprint produces. A selector at least
// this long is compared exactly; anything shorter is treated as an abbreviation.
const fingerprintLen = 32

// AcceptRulePrefix marks the compiled form of an acceptance, so a caller can
// tell which of its own entries actually fired.
const AcceptRulePrefix = "accept/"

// AcceptRuleID is the rule an acceptance compiles to.
func AcceptRuleID(a config.Acceptance) string { return AcceptRulePrefix + a.Label() }

// LoadAcceptances compiles the project's standing exceptions into ordinary
// rules, and reports the ones that have expired.
//
// Desugared like the licence policy, for the same reason: one evaluation path,
// one place a decision can come from, and Source() renders the CEL so a
// standing exception stays auditable rather than becoming a second hidden
// mechanism.
//
// An expired acceptance is not compiled -- the finding counts again, which is
// the whole point of writing a date -- but it is returned so the scan can say
// so. Dropping it in silence would look identical to the acceptance never
// having been written, and the first anyone would know is a posture drop with
// no cause.
func (e *Engine) LoadAcceptances(now time.Time, list []config.Acceptance) ([]string, error) {
	var (
		rules   []Rule
		expired []string
	)
	for _, a := range list {
		if until, ok := a.ExpiresOn(); ok && now.After(until.AddDate(0, 0, 1)) {
			expired = append(expired, a.Label()+" (expired "+a.Expires+")")
			continue
		}

		var match []string
		if sel := strings.TrimSpace(a.Finding); sel != "" {
			// Advisory ids, CVEs and engine rule ids all arrive here. Which of
			// them a given string is depends on the engine that reported it,
			// so match either place rather than making the author know.
			match = append(match, fmt.Sprintf(
				"(finding.rule_id == %q || %q in finding.cve)", sel, sel))
		}
		if sel := strings.TrimSpace(a.Fingerprint); sel != "" {
			// Exact when a whole fingerprint is given, prefix when it is
			// abbreviated -- people copy identifiers the way git taught them
			// to, and a selector that silently fails on a short one is the
			// trap this is here to remove rather than repeat.
			if len(sel) >= fingerprintLen {
				match = append(match, fmt.Sprintf("finding.fingerprint == %q", sel))
			} else {
				match = append(match, fmt.Sprintf("finding.fingerprint.startsWith(%q)", sel))
			}
		}
		if sel := strings.TrimSpace(a.Package); sel != "" {
			// The report identifies a dependency as "next-themes@0.4.6", so
			// that is what somebody writing an acceptance copies. Matching only
			// the bare name meant the obvious thing to write silently matched
			// nothing -- the tool printing a string that looks exactly like an
			// identifier and then refusing it.
			name, version := splitPackageSelector(sel)
			match = append(match, fmt.Sprintf("component.name == %q", name))
			if version != "" {
				match = append(match, versionMatch(version))
			}
		}

		rules = append(rules, Rule{
			ID:          AcceptRuleID(a),
			Description: a.Reason + " -- approved by " + a.ApprovedBy,
			Match:       Match{All: match},
			Then: Effect{
				Decision: DecisionAllow,
				Exempt:   true,
				Tags:     []string{"accepted"},
			},
		})
	}
	if len(rules) == 0 {
		return expired, nil
	}
	raw, err := yaml.Marshal(rules)
	if err != nil {
		return expired, fmt.Errorf("build acceptance register: %w", err)
	}
	if err := e.LoadRules("accept (.dragon.yaml)", raw); err != nil {
		return expired, err
	}
	return expired, nil
}

// activationFor builds the CEL input for a finding.
//
// Every key is always present, including for absent data. A policy author
// writing `package.dev_only` should get false for a finding with no package,
// not an evaluation error that quietly disables their rule.
func activationFor(f *finding.Finding, asset config.Asset, scan map[string]any) map[string]any {
	pkg := map[string]any{
		"ecosystem": "", "name": "", "version": "", "purl": "",
		"direct": false, "dev_only": false, "introduced_by": "", "present": false,
	}
	if f.Package != nil {
		pkg = map[string]any{
			"ecosystem": f.Package.Ecosystem, "name": f.Package.Name,
			"version": f.Package.Version, "purl": f.Package.PURL,
			"direct": f.Package.Direct, "dev_only": f.Package.DevOnly,
			"introduced_by": f.Package.IntroducedBy, "present": true,
		}
	}
	if scan == nil {
		scan = map[string]any{}
	}

	return map[string]any{
		"finding": map[string]any{
			"id": f.ID,
			// Separate from id, which a control plane may reassign. The
			// fingerprint is the finding's identity across scans and is the
			// only thing that names one occurrence rather than a whole rule.
			"fingerprint": f.Fingerprint,
			"category":    string(f.Category),
			"rule_id":     f.RuleID,
			"title":       f.Title,
			"severity":    string(f.Severity),
			"scanner":     f.Scanner,
			"file":        f.Location.File,
			"line":        int64(f.Location.StartLine),
			"cve":         toStrList(f.CVE),
			"cwe":         toStrList(f.CWE),
			"new":         f.New,
			"status":      string(f.Status),
			"dimension":   f.Category.Dimension(),
			"tags":        toStrList(f.PolicyTags),
			// Always present, empty for findings that are not about a licence.
			// The name lived only in Metadata, which policy cannot see, so the
			// only way to write a rule about MPL-2.0 was to match the rule_id
			// string the Trivy adapter happens to build.
			"license":          metaString(f, "license"),
			"license_category": metaString(f, "license_category"),
		},
		"threat": map[string]any{
			"cvss":              f.Threat.CVSS,
			"cvss_vector":       f.Threat.CVSSVector,
			"epss":              f.Threat.EPSS,
			"epss_known":        f.Threat.EPSSKnown,
			"kev":               f.Threat.KEV,
			"kev_ransomware":    f.Threat.KEVRansomware,
			"exploit_available": f.Threat.ExploitAvailab,
			"exploit_maturity":  f.Threat.ExploitMaturit,
		},
		"analysis": map[string]any{
			"reachable":       f.Analysis.Reachable,
			"reachability":    f.Analysis.Reachability,
			"fix_available":   f.Analysis.FixAvailable,
			"fixed_version":   f.Analysis.FixedVersion,
			"minimal_upgrade": f.Analysis.MinimalUpgrade,
			"vex_status":      f.Analysis.VEXStatus,
			"verified":        f.Analysis.Verified,
			"scorecard_score": f.Analysis.ScorecardScore,
			"has_scorecard":   f.Analysis.HasScorecard,
		},
		"risk": map[string]any{
			"score":  f.RiskScore,
			"rating": f.RiskRating,
		},
		"asset": map[string]any{
			"name":             asset.Name,
			"environment":      asset.Environment,
			"criticality":      asset.Criticality,
			"internet_exposed": asset.InternetExposed,
			"handles_pii":      asset.HandlesPII,
			"handles_payments": asset.HandlesPayments,
			"owner":            asset.Owner,
			"tags":             toStrList(asset.Tags),
		},
		"component": pkg,
		"scan":      scan,
	}
}

// sampleActivation is a fully-populated context used to validate rules at
// load time.
func sampleActivation() map[string]any {
	f := &finding.Finding{
		ID: "sample", Category: finding.CategorySCA, RuleID: "CVE-0000-0000",
		Title: "sample", Severity: finding.SeverityHigh, Scanner: "trivy",
		CVE: []string{"CVE-0000-0000"}, CWE: []string{"CWE-000"},
		Status: finding.StatusOpen, RiskScore: 50, RiskRating: "medium",
		Location: finding.Location{File: "sample", StartLine: 1},
		Package:  &finding.Package{Ecosystem: "npm", Name: "sample", Version: "1.0.0"},
		Analysis: finding.Analysis{Reachability: "unknown"},
	}
	f.Fingerprint = "sample"
	return activationFor(f, config.Asset{
		Name: "sample", Environment: "production", Criticality: "medium",
	}, map[string]any{"project": "sample", "total_findings": int64(1)})
}

func toStrList(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// LoadRules compiles a rule set supplied as JSON or YAML bytes.
//
// The file-based loaders assume a repository; a platform stores its packs in a
// database. Both end up in the same compiler, including the load-time
// validation pass, so a policy authored in a web UI is held to exactly the
// same standard as one committed to a repo -- and fails at save time rather
// than during somebody's release.
//
// The source may be either a bare rule array or a full PolicyPack document,
// since a pack round-tripped through the API arrives as one and a pack
// exported from a repository arrives as the other.
func (e *Engine) LoadRules(packName string, raw []byte) error {
	if len(raw) == 0 {
		return nil
	}

	var rules []Rule
	if err := yaml.Unmarshal(raw, &rules); err != nil || len(rules) == 0 {
		var pack Pack
		if err2 := yaml.Unmarshal(raw, &pack); err2 != nil {
			if err == nil {
				err = err2
			}
			return fmt.Errorf("parse policy pack %q: %w", packName, err)
		}
		rules = pack.Rules
	}

	seen := make(map[string]bool, len(rules))
	for _, r := range e.rules {
		seen[r.ID] = true
	}

	pack := &Pack{Path: packName}
	pack.Metadata.Name = packName
	for i := range rules {
		r := &rules[i]
		if r.ID == "" {
			return fmt.Errorf("policy pack %q: rule %d has no id", packName, i)
		}
		if seen[r.ID] {
			return fmt.Errorf("policy pack %q: duplicate rule id %q", packName, r.ID)
		}
		seen[r.ID] = true

		if err := e.compile(r); err != nil {
			return fmt.Errorf("policy pack %q: rule %q: %w", packName, r.ID, err)
		}
		e.rules = append(e.rules, r)
		pack.Rules = append(pack.Rules, *r)
	}
	e.packs = append(e.packs, pack)
	return nil
}
