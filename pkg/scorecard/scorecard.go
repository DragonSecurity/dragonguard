// Package scorecard aggregates scored findings into a posture report.
//
// Note the inversion, which is a common source of confusion: Dragon Risk runs
// 0-100 where higher is worse, because it ranks findings. A scorecard runs
// 0-100 where higher is better, because it describes health. The two are
// deliberately different metrics with different audiences -- an engineer
// triaging a queue, and a release manager deciding whether to ship.
package scorecard

import (
	"math"
	"sort"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/policy"
)

// Dimensions are the posture areas reported, in display order.
var Dimensions = []string{"code", "dependencies", "container", "iac", "secrets", "api", "supply_chain"}

const (
	// penaltyScale tunes how fast posture decays with accumulated findings.
	penaltyScale = 400.0
	// criticalCeiling caps a dimension holding an unresolved critical risk.
	criticalCeiling = 70.0
	// highCeiling caps a dimension holding an unresolved high risk.
	highCeiling = 85.0
)

// Counts tallies findings by rating.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func (c *Counts) add(rating string) {
	switch rating {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	default:
		c.Info++
	}
	c.Total++
}

// Dimension is the posture of one security area.
type Dimension struct {
	Name string `json:"name"`
	// Score is 0-100, higher is better. Meaningless when Assessed is false.
	Score float64 `json:"score"`
	// Assessed reports whether any engine actually produced evidence here.
	// A dimension nobody scanned is not a clean dimension, and scoring it
	// 100 would let a gate pass on evidence that was never collected.
	Assessed bool `json:"assessed"`
	// Supported reports whether any registered engine covers this dimension
	// at all. The distinction matters: an engine that was installed and then
	// failed is a degradation somebody can fix today, while having no DAST
	// engine configured is a standing coverage gap. Reporting the second as
	// a degradation on every scan makes the warning worthless.
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Counts    Counts `json:"counts"`
	New       int    `json:"new"`
	// WorstRisk is the highest Dragon Risk score in this dimension.
	WorstRisk float64 `json:"worst_risk"`
}

// PolicyCounts summarizes policy decisions across the scan.
type PolicyCounts struct {
	Blocking int `json:"blocking"`
	Warnings int `json:"warnings"`
	Exempt   int `json:"exempt"`
	Errors   int `json:"errors"`
}

// Scorecard is the aggregate posture of one scan.
type Scorecard struct {
	Project   string    `json:"project"`
	Asset     string    `json:"asset"`
	Timestamp time.Time `json:"timestamp"`
	Commit    string    `json:"commit,omitempty"`
	Branch    string    `json:"branch,omitempty"`

	// Score is overall posture, 0-100, higher is better.
	Score float64 `json:"score"`

	Dimensions map[string]Dimension `json:"dimensions"`

	Counts Counts       `json:"counts"`
	New    Counts       `json:"new"`
	Policy PolicyCounts `json:"policy"`

	// EnginesRun, EnginesUnavailable and EnginesFailed make the evidence base
	// explicit. The last two are kept apart because they mean different
	// things: an engine nobody installed or configured is a coverage gap,
	// while an engine that was there and broke is a degradation somebody can
	// fix today.
	EnginesRun         []string `json:"engines_run"`
	EnginesUnavailable []string `json:"engines_unavailable,omitempty"`
	EnginesFailed      []string `json:"engines_failed,omitempty"`
	// EnginesSkipped is retained for compatibility and holds both sets.
	EnginesSkipped []string `json:"engines_skipped,omitempty"`
	// Degraded reports that the scan was missing engines or intelligence.
	Degraded bool     `json:"degraded"`
	Notes    []string `json:"notes,omitempty"`

	// Mandatory records the built-in security conditions, which baselines
	// reference by name.
	Mandatory map[string]bool `json:"mandatory"`
}

// Input is everything needed to build a scorecard.
type Input struct {
	Project            string
	Asset              string
	Commit             string
	Branch             string
	Findings           []finding.Finding
	Evaluations        []policy.Evaluation
	EnginesRun         []string
	EnginesUnavailable []string
	EnginesFailed      []string
	// AssessedDimensions lists dimensions an engine actually covered.
	AssessedDimensions map[string]bool
	// SupportedDimensions lists dimensions some registered engine could
	// cover, whether or not it ran.
	SupportedDimensions map[string]bool
	Notes               []string
}

// Build computes a scorecard from scored, policy-evaluated findings.
func Build(in Input) *Scorecard {
	sc := &Scorecard{
		Project:            in.Project,
		Asset:              in.Asset,
		Timestamp:          time.Now().UTC(),
		Commit:             in.Commit,
		Branch:             in.Branch,
		Dimensions:         make(map[string]Dimension, len(Dimensions)),
		EnginesRun:         in.EnginesRun,
		EnginesUnavailable: in.EnginesUnavailable,
		EnginesFailed:      in.EnginesFailed,
		EnginesSkipped:     append(append([]string(nil), in.EnginesUnavailable...), in.EnginesFailed...),
		Notes:              in.Notes,
		Mandatory:          make(map[string]bool),
	}

	byDim := make(map[string][]finding.Finding)
	for _, f := range in.Findings {
		// An exempted finding has been formally accepted; it should not keep
		// depressing the posture score forever.
		if f.Status == finding.StatusAccepted || f.Status == finding.StatusIgnored {
			continue
		}
		d := f.Category.Dimension()
		byDim[d] = append(byDim[d], f)
		sc.Counts.add(f.RiskRating)
		if f.New {
			sc.New.add(f.RiskRating)
		}
	}

	for _, name := range Dimensions {
		fs := byDim[name]
		dim := Dimension{
			Name:      name,
			Assessed:  in.AssessedDimensions[name],
			Supported: in.SupportedDimensions[name],
		}
		if !dim.Assessed {
			if dim.Supported {
				dim.Reason = "not assessed: the engine covering this dimension did not run"
			} else {
				dim.Reason = "no engine configured for this dimension"
			}
			sc.Dimensions[name] = dim
			continue
		}
		for _, f := range fs {
			dim.Counts.add(f.RiskRating)
			if f.New {
				dim.New++
			}
			if f.RiskScore > dim.WorstRisk {
				dim.WorstRisk = f.RiskScore
			}
		}
		dim.Score = dimensionScore(fs)
		sc.Dimensions[name] = dim
	}

	sc.Score = overallScore(sc.Dimensions)

	for _, ev := range in.Evaluations {
		switch ev.Decision {
		case policy.DecisionDeny:
			sc.Policy.Blocking++
		case policy.DecisionWarn:
			sc.Policy.Warnings++
		}
		if ev.Exempt {
			sc.Policy.Exempt++
		}
		sc.Policy.Errors += len(ev.Errors)
	}

	sc.Mandatory = mandatoryConditions(in.Findings)

	// Only an engine that was present and then failed degrades the scan. An
	// engine that is not installed or not configured covers nothing, which is
	// reported as a coverage gap -- warning about it on every scan would make
	// the degraded flag meaningless.
	if len(in.EnginesFailed) > 0 {
		sc.Degraded = true
	}
	for _, d := range sc.Dimensions {
		// Only a dimension an engine was supposed to cover counts as a
		// degradation. A dimension with no engine at all is a coverage gap,
		// stated plainly in the report; make it blocking with a baseline
		// `dimensions.<name>.required: true` if it matters here.
		if d.Supported && !d.Assessed {
			sc.Degraded = true
			break
		}
	}
	if len(in.Notes) > 0 {
		sc.Degraded = true
	}
	return sc
}

// dimensionScore converts a dimension's findings into a 0-100 posture score.
//
// Two rules, both intended to be explainable to somebody the gate just
// blocked:
//
//  1. Accumulated penalty. Each finding costs (risk/100)^3 x 100 points, and
//     posture decays as 100 x e^(-total/400). The cubic keeps a long tail of
//     low-risk findings from swamping the signal, which is what makes teams
//     stop reading the number.
//  2. A ceiling set by the worst finding. Any amount of arithmetic that lets
//     a project hold an unresolved critical and still show 90 has failed at
//     the only job posture has.
func dimensionScore(fs []finding.Finding) float64 {
	if len(fs) == 0 {
		return 100
	}
	var penalty, worst float64
	for _, f := range fs {
		r := f.RiskScore / 100
		penalty += r * r * r * 100
		if f.RiskScore > worst {
			worst = f.RiskScore
		}
	}
	score := 100 * math.Exp(-penalty/penaltyScale)

	switch {
	case worst >= 90:
		score = math.Min(score, criticalCeiling)
	case worst >= 75:
		score = math.Min(score, highCeiling)
	}
	return math.Round(score)
}

// overallScore blends the mean and the minimum of assessed dimensions.
//
// A plain mean lets a strong showing in five areas hide a bad one, which is
// exactly the failure mode that makes aggregate scores untrustworthy. Leaning
// 40% on the weakest dimension keeps the number honest: posture is limited by
// where you are weakest, not by where you are strongest.
func overallScore(dims map[string]Dimension) float64 {
	var sum, min float64
	min = 100
	n := 0
	for _, d := range dims {
		if !d.Assessed {
			continue
		}
		sum += d.Score
		if d.Score < min {
			min = d.Score
		}
		n++
	}
	if n == 0 {
		return 0
	}
	mean := sum / float64(n)
	return math.Round(0.6*mean + 0.4*min)
}

// mandatoryConditions evaluates the built-in security conditions a baseline
// can require by name. These are deliberately not customer-authored: they are
// the conditions that mean the same thing at every organization.
func mandatoryConditions(fs []finding.Finding) map[string]bool {
	m := map[string]bool{
		"no_active_secrets":                   true,
		"no_kev_in_production":                true,
		"no_reachable_critical_vulnerability": true,
		"no_critical_risk":                    true,
		"no_policy_errors":                    true,
	}
	for _, f := range fs {
		if f.Status == finding.StatusAccepted || f.Status == finding.StatusIgnored {
			continue
		}
		if f.Category == finding.CategorySecret {
			m["no_active_secrets"] = false
		}
		if f.Threat.KEV {
			m["no_kev_in_production"] = false
		}
		if f.RiskRating == "critical" {
			m["no_critical_risk"] = false
			if f.Analysis.Reachability == "reachable" {
				m["no_reachable_critical_vulnerability"] = false
			}
		}
	}
	return m
}

// TopFindings returns the highest-risk findings, for report headlines.
func TopFindings(fs []finding.Finding, n int) []finding.Finding {
	out := make([]finding.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Status == finding.StatusAccepted || f.Status == finding.StatusIgnored {
			continue
		}
		out = append(out, f)
	}
	finding.SortByRisk(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// AssessedNames lists the dimensions that were actually covered.
func (s *Scorecard) AssessedNames() []string {
	var out []string
	for name, d := range s.Dimensions {
		if d.Assessed {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
