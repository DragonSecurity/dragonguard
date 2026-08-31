// Package risk implements Dragon Risk: the deterministic engine that turns an
// enriched finding into a 0-100 score, where higher is worse.
//
// Two design commitments make this useful rather than decorative.
//
// First, the scoring is ordinary application logic, not policy. Policy decides
// what to do about a risk; it should not also be where the arithmetic lives.
// Keeping the math here means a score is reproducible, testable and identical
// for every customer, which is what makes it comparable over time.
//
// Second, components with no evidence behind them are excluded and their
// weight is redistributed, rather than being filled in with a neutral guess.
// A neutral guess is indistinguishable from real evidence once it has been
// multiplied by a weight, and it systematically drags genuine emergencies
// toward the middle of the range. If we do not know a package's supply-chain
// posture, the score should reflect the evidence we do have -- more
// confidently, not less.
package risk

import (
	"fmt"
	"math"
	"sort"

	"github.com/DragonSecurity/dragonguard/pkg/config"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// Weights are the relative contributions of each risk component. They sum to
// 1.0 across all components, but any subset can be renormalized.
type Weights struct {
	Vulnerability  float64 `yaml:"vulnerability" json:"vulnerability"`
	Exploitability float64 `yaml:"exploitability" json:"exploitability"`
	AssetContext   float64 `yaml:"asset_context" json:"asset_context"`
	SupplyChain    float64 `yaml:"supply_chain" json:"supply_chain"`
	Remediation    float64 `yaml:"remediation" json:"remediation"`
	Provenance     float64 `yaml:"provenance" json:"provenance"`
}

// DefaultWeights is Dragon Risk v1.
func DefaultWeights() Weights {
	return Weights{
		Vulnerability:  0.35,
		Exploitability: 0.20,
		AssetContext:   0.15,
		SupplyChain:    0.15,
		Remediation:    0.10,
		Provenance:     0.05,
	}
}

// Component is one scored dimension, retained so a score can explain itself.
type Component struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`  // 0..1
	Weight float64 `json:"weight"` // as applied, after renormalization
	Reason string  `json:"reason"`
}

// Score is a full risk verdict for one finding.
type Score struct {
	Value      float64     `json:"value"`  // 0..100, higher is worse
	Rating     string      `json:"rating"` // critical|high|medium|low|info
	Components []Component `json:"components"`
	Modifiers  []string    `json:"modifiers,omitempty"`
	Reasons    []string    `json:"reasons"`
	// Confidence reflects how much of the weight was backed by evidence.
	Confidence float64 `json:"confidence"`
}

// Engine scores findings against an asset context.
type Engine struct {
	Weights Weights
	Asset   config.Asset
}

func New(asset config.Asset) *Engine {
	return &Engine{Weights: DefaultWeights(), Asset: asset}
}

// ScoreAll scores every finding and writes the result back onto it.
func (e *Engine) ScoreAll(findings []finding.Finding) []Score {
	scores := make([]Score, len(findings))
	for i := range findings {
		s := e.Score(&findings[i])
		findings[i].RiskScore = s.Value
		findings[i].RiskRating = s.Rating
		findings[i].RiskReasons = s.Reasons
		scores[i] = s
	}
	return scores
}

// Score computes Dragon Risk for a single finding.
func (e *Engine) Score(f *finding.Finding) Score {
	var comps []Component

	if c, ok := e.vulnerability(f); ok {
		c.Weight = e.Weights.Vulnerability
		comps = append(comps, c)
	}
	if c, ok := e.exploitability(f); ok {
		c.Weight = e.Weights.Exploitability
		comps = append(comps, c)
	}
	if c, ok := e.assetContext(f); ok {
		c.Weight = e.Weights.AssetContext
		comps = append(comps, c)
	}
	if c, ok := e.supplyChain(f); ok {
		c.Weight = e.Weights.SupplyChain
		comps = append(comps, c)
	}
	if c, ok := e.remediation(f); ok {
		c.Weight = e.Weights.Remediation
		comps = append(comps, c)
	}
	if c, ok := e.provenance(f); ok {
		c.Weight = e.Weights.Provenance
		comps = append(comps, c)
	}

	var totalWeight, weighted float64
	for _, c := range comps {
		totalWeight += c.Weight
		weighted += c.Weight * c.Value
	}

	s := Score{Components: comps}
	if totalWeight == 0 {
		// No evidence at all. Fall back to raw severity rather than
		// returning zero, which would read as "safe".
		s.Value = severityBase(f.Severity) * 100
		s.Reasons = []string{"scored from severity alone: no scoreable evidence"}
		s.Confidence = 0.1
		s.Rating = Rate(s.Value)
		return s
	}

	base := weighted / totalWeight
	s.Confidence = totalWeight / e.Weights.total()

	// Modifiers apply after normalization because they express context that
	// scales the whole verdict rather than one dimension of it.
	value := base
	for _, m := range e.modifiers(f) {
		value *= m.factor
		s.Modifiers = append(s.Modifiers, m.reason)
	}

	s.Value = math.Round(clamp01(value) * 100)
	s.Rating = Rate(s.Value)
	s.Reasons = topReasons(comps, s.Modifiers)
	return s
}

func (w Weights) total() float64 {
	return w.Vulnerability + w.Exploitability + w.AssetContext + w.SupplyChain + w.Remediation + w.Provenance
}

// vulnerability scores the intrinsic seriousness of the flaw, adjusted by
// what the world knows about its exploitation.
func (e *Engine) vulnerability(f *finding.Finding) (Component, bool) {
	base := severityBase(f.Severity)
	reason := fmt.Sprintf("severity %s", f.Severity)

	if f.Threat.CVSS > 0 {
		base = f.Threat.CVSS / 10
		reason = fmt.Sprintf("CVSS %.1f", f.Threat.CVSS)
	}

	// KEV means this is not theoretical. It floors the intrinsic score
	// regardless of what CVSS says, because observed exploitation outranks
	// a predicted impact rating.
	if f.Threat.KEV {
		if base < 0.9 {
			base = 0.9
		}
		reason += ", CISA KEV listed"
	}
	if f.Threat.KEVRansomware {
		base = math.Max(base, 0.95)
		reason += " (ransomware campaigns)"
	}

	// EPSS is only blended in when it was actually looked up. An offline run
	// keeps the CVSS-driven score rather than silently deflating it.
	if f.Threat.EPSSKnown {
		p := epssCurve(f.Threat.EPSS)
		base = 0.7*base + 0.3*p
		reason += fmt.Sprintf(", EPSS %.3f", f.Threat.EPSS)
	}

	return Component{Name: "vulnerability", Value: clamp01(base), Reason: reason}, true
}

// exploitability scores whether this flaw can be reached and whether working
// exploitation exists.
func (e *Engine) exploitability(f *finding.Finding) (Component, bool) {
	var reach float64
	var reachReason string
	switch f.Analysis.Reachability {
	case "reachable":
		reach, reachReason = 1.0, "reachable"
	case "unreachable":
		// Not zero: reachability analysis is an approximation, and a
		// dependency that is unreachable today becomes reachable the moment
		// somebody adds an import. It is a strong discount, not an excuse.
		reach, reachReason = 0.15, "not reachable from application code"
	default:
		reach, reachReason = 0.6, "reachability unknown"
	}

	exploit := 0.0
	exploitReason := "no known exploit"
	switch {
	case f.Threat.KEV:
		exploit, exploitReason = 1.0, "actively exploited in the wild"
	case f.Threat.ExploitAvailab:
		exploit, exploitReason = 0.75, "exploit code available"
	case f.Threat.EPSSKnown && f.Threat.EPSS >= 0.1:
		exploit, exploitReason = 0.5, "elevated exploitation probability"
	}

	// First-party code is a special case. Exploit maturity is a CVE-world
	// concept: it asks whether somebody has published working code against a
	// widely-deployed component. Nobody publishes an exploit for the SQL
	// injection in your own handler, and applying the "no known exploit"
	// discount to it systematically under-ranks the flaws an attacker will
	// actually reach for first. For a reachable flaw in code you wrote, the
	// flaw is the exploit.
	if f.Category == finding.CategorySAST {
		return Component{
			Name:   "exploitability",
			Value:  clamp01(reach),
			Reason: reachReason + ", directly exploitable in first-party code",
		}, true
	}

	// A secret is a special case too: there is nothing to exploit, the
	// credential simply works. Reachability and exploit maturity do not apply.
	if f.Category == finding.CategorySecret {
		v := 0.85
		r := "committed credential is directly usable"
		if f.Analysis.Verified {
			v, r = 1.0, "credential verified live against the provider"
		}
		return Component{Name: "exploitability", Value: v, Reason: r}, true
	}

	// The floor of 0.4 represents the residual exploitability of any real
	// flaw: no public exploit today is not the same as not exploitable.
	value := reach * (0.4 + 0.6*exploit)
	return Component{
		Name:   "exploitability",
		Value:  clamp01(value),
		Reason: reachReason + ", " + exploitReason,
	}, true
}

// assetContext scores how much this particular deployment stands to lose.
func (e *Engine) assetContext(f *finding.Finding) (Component, bool) {
	var v float64
	var reasons []string

	switch e.Asset.Environment {
	case "production":
		v, reasons = 0.6, append(reasons, "production")
	case "staging":
		v, reasons = 0.35, append(reasons, "staging")
	default:
		v, reasons = 0.15, append(reasons, e.Asset.Environment)
	}

	switch e.Asset.Criticality {
	case "critical":
		v += 0.2
		reasons = append(reasons, "business-critical")
	case "high":
		v += 0.12
		reasons = append(reasons, "high criticality")
	case "low":
		v -= 0.05
	}

	if e.Asset.InternetExposed {
		v += 0.15
		reasons = append(reasons, "internet-exposed")
	}
	if e.Asset.HandlesPayments {
		v += 0.1
		reasons = append(reasons, "handles payments")
	} else if e.Asset.HandlesPII {
		v += 0.07
		reasons = append(reasons, "handles personal data")
	}

	return Component{
		Name:   "asset_context",
		Value:  clamp01(v),
		Reason: joinReasons(reasons),
	}, true
}

// supplyChain scores latent upstream risk from OpenSSF Scorecard. It is only
// scored when a Scorecard result actually exists: a package we have not
// assessed must not be scored as if it were assessed and found average.
func (e *Engine) supplyChain(f *finding.Finding) (Component, bool) {
	if !f.Analysis.HasScorecard {
		return Component{}, false
	}
	// Scorecard runs 0-10 where higher is better; risk runs the other way.
	v := 1 - clamp01(f.Analysis.ScorecardScore/10)
	return Component{
		Name:   "supply_chain",
		Value:  v,
		Reason: fmt.Sprintf("OpenSSF Scorecard %.1f/10", f.Analysis.ScorecardScore),
	}, true
}

// remediation scores how actionable the finding is right now.
//
// This raises the score rather than lowering it, which surprises people. The
// reasoning: Dragon Risk ranks what to do next, not how dangerous something
// is in the abstract. A serious flaw with a one-line upgrade available should
// outrank an equally serious flaw with no fix, because one of them can be
// closed this afternoon and the other cannot. Backlogs that ignore this
// spend their effort on the problems nobody can solve.
func (e *Engine) remediation(f *finding.Finding) (Component, bool) {
	switch {
	case f.Analysis.MinimalUpgrade != "":
		return Component{Name: "remediation", Value: 0.9, Reason: "fix available: " + f.Analysis.MinimalUpgrade}, true
	case f.Analysis.FixAvailable:
		return Component{Name: "remediation", Value: 0.8, Reason: "fix available"}, true
	case f.Category == finding.CategorySecret:
		return Component{Name: "remediation", Value: 0.95, Reason: "rotate and revoke the credential"}, true
	case f.Category == finding.CategorySAST || f.Category == finding.CategoryIaC:
		return Component{Name: "remediation", Value: 0.7, Reason: "fixable in first-party code"}, true
	default:
		return Component{Name: "remediation", Value: 0.25, Reason: "no fix currently available"}, true
	}
}

// provenance scores trust in the artifact's origin. Only scored when a VEX
// assertion is present, since that is the only provenance signal currently
// ingested.
func (e *Engine) provenance(f *finding.Finding) (Component, bool) {
	if f.Analysis.VEXStatus == "" {
		return Component{}, false
	}
	switch f.Analysis.VEXStatus {
	case "not_affected":
		return Component{Name: "provenance", Value: 0.05, Reason: "VEX: not affected"}, true
	case "fixed":
		return Component{Name: "provenance", Value: 0.05, Reason: "VEX: already fixed"}, true
	case "under_investigation":
		return Component{Name: "provenance", Value: 0.5, Reason: "VEX: under investigation"}, true
	case "affected":
		return Component{Name: "provenance", Value: 1.0, Reason: "VEX: confirmed affected"}, true
	default:
		return Component{Name: "provenance", Value: 0.5, Reason: "VEX: " + f.Analysis.VEXStatus}, true
	}
}

type modifier struct {
	factor float64
	reason string
}

// modifiers scale the whole verdict for context that is not a dimension of
// risk so much as a statement about whether this finding reaches production.
func (e *Engine) modifiers(f *finding.Finding) []modifier {
	var out []modifier

	if f.Package != nil && f.Package.DevOnly {
		// A build-time dependency is not in the deployed artifact. It still
		// matters -- build systems get attacked -- but not as much.
		out = append(out, modifier{0.5, "development-only dependency"})
	}
	if f.Analysis.VEXStatus == "not_affected" {
		out = append(out, modifier{0.2, "VEX asserts not affected"})
	}
	if f.Status == finding.StatusAccepted {
		out = append(out, modifier{0.5, "risk formally accepted"})
	}
	return out
}

// epssCurve reshapes the EPSS probability so the low end is legible.
//
// EPSS is extremely skewed: the vast majority of CVEs score below 0.01, so a
// linear reading would treat 0.05 (top few percent of exploitation
// likelihood) as functionally zero. A log curve keeps the meaningful part of
// the distribution visible while preserving order.
func epssCurve(p float64) float64 {
	p = clamp01(p)
	return clamp01(math.Log10(1+99*p) / 2)
}

func severityBase(s finding.Severity) float64 {
	switch s {
	case finding.SeverityCritical:
		return 0.95
	case finding.SeverityHigh:
		return 0.75
	case finding.SeverityMedium:
		return 0.5
	case finding.SeverityLow:
		return 0.25
	default:
		return 0.1
	}
}

// Rate maps a 0-100 score onto the rating bands used in reports and policy.
func Rate(v float64) string {
	switch {
	case v >= 90:
		return "critical"
	case v >= 75:
		return "high"
	case v >= 50:
		return "medium"
	case v >= 25:
		return "low"
	default:
		return "info"
	}
}

// topReasons picks the explanations that actually drove the score, so a
// developer reads why this is urgent rather than a wall of every input.
func topReasons(comps []Component, modifiers []string) []string {
	ranked := append([]Component(nil), comps...)
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].Weight*ranked[i].Value > ranked[j].Weight*ranked[j].Value
	})
	var out []string
	for i, c := range ranked {
		if i >= 3 || c.Value == 0 {
			break
		}
		out = append(out, c.Reason)
	}
	return append(out, modifiers...)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += ", "
		}
		out += r
	}
	return out
}
