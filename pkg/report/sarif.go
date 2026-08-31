package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// SARIF renders findings as SARIF 2.1.0 so they can be uploaded to GitHub
// code scanning, or to anything else that already speaks the format.
//
// Dragon Risk is carried in security-severity rather than the SARIF level,
// because level has three values and the whole argument of this platform is
// that three buckets of raw severity is not enough information to act on.
func SARIF(w io.Writer, r *Result) error {
	type message struct {
		Text string `json:"text"`
	}
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type region struct {
		StartLine int `json:"startLine,omitempty"`
		EndLine   int `json:"endLine,omitempty"`
	}
	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           *region          `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type ruleProps struct {
		Tags             []string `json:"tags,omitempty"`
		SecuritySeverity string   `json:"security-severity,omitempty"`
		Precision        string   `json:"precision,omitempty"`
	}
	type sarifRule struct {
		ID               string     `json:"id"`
		Name             string     `json:"name,omitempty"`
		ShortDescription message    `json:"shortDescription"`
		FullDescription  *message   `json:"fullDescription,omitempty"`
		HelpURI          string     `json:"helpUri,omitempty"`
		Properties       *ruleProps `json:"properties,omitempty"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             message           `json:"message"`
		Locations           []location        `json:"locations,omitempty"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties,omitempty"`
	}

	rulesByID := map[string]sarifRule{}
	var results []result

	for _, f := range r.Findings {
		if f.Status == finding.StatusAccepted || f.Status == finding.StatusIgnored {
			continue
		}
		if _, ok := rulesByID[f.RuleID]; !ok {
			var help *message
			if f.Message != "" {
				help = &message{Text: f.Message}
			}
			var uri string
			if len(f.References) > 0 {
				uri = f.References[0]
			}
			tags := append([]string{string(f.Category), "dragonguard"}, f.CWE...)
			tags = append(tags, f.PolicyTags...)
			rulesByID[f.RuleID] = sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: message{Text: f.Title},
				FullDescription:  help,
				HelpURI:          uri,
				Properties: &ruleProps{
					Tags: tags,
					// SARIF security-severity is a 0-10 scale; Dragon Risk is
					// 0-100, so it is divided rather than truncated to a level.
					SecuritySeverity: fmt.Sprintf("%.1f", f.RiskScore/10),
				},
			}
		}

		res := result{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.RiskRating),
			Message: message{Text: sarifMessage(f)},
			PartialFingerprints: map[string]string{
				"dragonguard/v1": f.Fingerprint,
			},
			Properties: map[string]any{
				"dragon_risk":   f.RiskScore,
				"dragon_rating": f.RiskRating,
				"category":      string(f.Category),
				"scanner":       f.Scanner,
				"new":           f.New,
			},
		}
		if f.Location.File != "" {
			loc := location{PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: f.Location.File},
			}}
			if f.Location.StartLine > 0 {
				loc.PhysicalLocation.Region = &region{
					StartLine: f.Location.StartLine,
					EndLine:   f.Location.EndLine,
				}
			}
			res.Locations = []location{loc}
		}
		results = append(results, res)
	}

	ids := make([]string, 0, len(rulesByID))
	for id := range rulesByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, rulesByID[id])
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":            "DragonGuard",
					"informationUri":  "https://dragonsecurity.io",
					"semanticVersion": Version,
					"rules":           rules,
				},
			},
			"results": results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(rating string) string {
	switch rating {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func sarifMessage(f finding.Finding) string {
	msg := f.Title
	if f.Message != "" && f.Message != f.Title {
		msg = f.Message
	}
	msg = fmt.Sprintf("[Dragon Risk %.0f/%s] %s", f.RiskScore, f.RiskRating, msg)
	if f.Analysis.MinimalUpgrade != "" {
		msg += " Fix: " + f.Analysis.MinimalUpgrade
	}
	return msg
}

// Version is stamped by the CLI at startup.
var Version = "dev"
