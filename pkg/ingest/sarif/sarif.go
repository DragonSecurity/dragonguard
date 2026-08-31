// Package sarif parses SARIF 2.1.0, the interchange format DragonGuard uses
// for code-shaped findings.
//
// Only the subset that carries real information is modelled. A scanner that
// emits richer SARIF loses nothing that the control plane would have used.
package sarif

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Log struct {
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	SemanticVersion string `json:"semanticVersion"`
	Rules           []Rule `json:"rules"`
}

type Rule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription *Message         `json:"shortDescription"`
	FullDescription  *Message         `json:"fullDescription"`
	Help             *Message         `json:"help"`
	HelpURI          string           `json:"helpUri"`
	Properties       *RuleProperties  `json:"properties"`
	DefaultConfig    *ReportingConfig `json:"defaultConfiguration"`
}

type ReportingConfig struct {
	Level string `json:"level"`
}

type RuleProperties struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision"`
	SecuritySeverity string   `json:"security-severity"`
	Severity         string   `json:"severity"`
}

type Message struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

func (m *Message) String() string {
	if m == nil {
		return ""
	}
	if m.Text != "" {
		return m.Text
	}
	return m.Markdown
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           *int              `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	Fingerprints        map[string]string `json:"fingerprints"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation"`
	Region           *Region           `json:"region"`
}

type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type Region struct {
	StartLine   int      `json:"startLine"`
	EndLine     int      `json:"endLine"`
	StartColumn int      `json:"startColumn"`
	Snippet     *Message `json:"snippet"`
}

// Parse reads a SARIF log.
func Parse(data []byte) (*Log, error) {
	var l Log
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	return &l, nil
}

// RuleFor resolves the rule a result refers to, by index when SARIF gives one
// and by ID otherwise. Engines differ on which they populate.
func (r *Run) RuleFor(res *Result) *Rule {
	if res.RuleIndex != nil {
		i := *res.RuleIndex
		if i >= 0 && i < len(r.Tool.Driver.Rules) {
			return &r.Tool.Driver.Rules[i]
		}
	}
	for i := range r.Tool.Driver.Rules {
		if r.Tool.Driver.Rules[i].ID == res.RuleID {
			return &r.Tool.Driver.Rules[i]
		}
	}
	return nil
}

// Primary returns the first physical location of a result, which is the one
// a developer should be pointed at.
func (res *Result) Primary() (file string, startLine, endLine int, snippet string) {
	for _, loc := range res.Locations {
		if loc.PhysicalLocation == nil {
			continue
		}
		pl := loc.PhysicalLocation
		if pl.ArtifactLocation != nil {
			file = strings.TrimPrefix(pl.ArtifactLocation.URI, "file://")
		}
		if pl.Region != nil {
			startLine = pl.Region.StartLine
			endLine = pl.Region.EndLine
			snippet = strings.TrimSpace(pl.Region.Snippet.String())
		}
		return
	}
	return
}

// CWEs pulls CWE identifiers out of a rule's tags, which is where every
// SARIF-emitting SAST engine puts them.
func (r *Rule) CWEs() []string {
	if r == nil || r.Properties == nil {
		return nil
	}
	var out []string
	for _, t := range r.Properties.Tags {
		up := strings.ToUpper(t)
		if strings.HasPrefix(up, "CWE-") || strings.HasPrefix(up, "CWE:") {
			// Tags arrive as "CWE-89" or "CWE-89: SQL Injection".
			id := up
			if i := strings.IndexAny(id, ": "); i > 0 {
				if strings.HasPrefix(id, "CWE-") && i > 4 {
					id = id[:i]
				}
			}
			out = append(out, strings.TrimSuffix(id, ":"))
		}
	}
	return out
}
