// Package platform is the client the CLI uses to submit scan results to a
// DragonGuard server.
//
// The split of responsibility it implements is deliberate: the runner sends
// evidence, the server returns the verdict. A runner has the source code and
// so must collect the findings, but it does not know the asset context, does
// not hold the organization's policy, and has an obvious incentive to report a
// pass. So it posts what it found and takes the answer it is given -- including
// the exit code.
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
	"github.com/DragonSecurity/dragonguard/pkg/scanner"
)

// Client talks to a DragonGuard platform API.
type Client struct {
	BaseURL string
	// Key is an organization scan key (dgk_...) or a user bearer token.
	Key  string
	HTTP *http.Client
}

// defaultBasePath mirrors the server's own base.path default.
//
// What a person has -- and what the deployment runbook prints, and what goes
// in DRAGON_SERVER -- is a server: "https://guard.example.com". Where the API
// lives underneath that is the client's business, not something every CI
// config should have to restate. A base URL that already carries a path is
// left alone, which is the escape hatch for a server running on a different
// base.path.
const defaultBasePath = "/api/v1"

func New(baseURL, key string) *Client {
	return &Client{
		BaseURL: normalizeBaseURL(baseURL),
		Key:     key,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

func normalizeBaseURL(raw string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" || u.Path != "" {
		return trimmed
	}
	return trimmed + defaultBasePath
}

// IngestRequest is a scan submission.
type IngestRequest struct {
	Branch   string `json:"branch,omitempty"`
	Commit   string `json:"commit,omitempty"`
	PRNumber *int   `json:"pr_number,omitempty"`
	Trigger  string `json:"trigger,omitempty"`

	Findings []finding.Finding `json:"findings"`

	// DragonVersion is the build that produced this scan, so the platform can
	// tell a posture change caused by the code from one caused by an upgrade.
	DragonVersion string `json:"dragon_version,omitempty"`

	// Components is the inventory the scan observed, findings or not. A clean
	// dependency is still a dependency the platform needs to know about: it is
	// what a future advisory gets matched against, and what "which projects
	// use this package" is answered from.
	Components []scanner.PackageNode `json:"components,omitempty"`

	EnginesRun         []string `json:"engines_run,omitempty"`
	EnginesUnavailable []string `json:"engines_unavailable,omitempty"`
	EnginesFailed      []string `json:"engines_failed,omitempty"`

	RecordBaseline bool `json:"record_baseline,omitempty"`
}

// IngestResponse is the server's verdict.
type IngestResponse struct {
	ScanID          string   `json:"scan_id"`
	Verdict         string   `json:"verdict"`
	Posture         float64  `json:"posture"`
	PreviousPosture *float64 `json:"previous_posture,omitempty"`
	NewFindings     int      `json:"new_findings"`
	FixedFindings   int      `json:"fixed_findings"`
	Critical        int      `json:"critical"`
	High            int      `json:"high"`
	Degraded        bool     `json:"degraded"`
	Reasons         []string `json:"reasons,omitempty"`
}

// Blocked reports whether the server refused this change.
func (r *IngestResponse) Blocked() bool { return r.Verdict == "BLOCK" }

// Ingest submits findings for a project and returns the gate decision.
//
// project may be a UUID or the project's slug, so a CI config can name the
// project the way a human wrote it rather than carrying a generated ID.
func (c *Client) Ingest(ctx context.Context, project string, req IngestRequest) (*IngestResponse, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("no platform URL configured")
	}
	if c.Key == "" {
		return nil, fmt.Errorf("no API key configured")
	}
	// Never send a nil slice: the server distinguishes "scanned and found
	// nothing" from "sent nothing", and only the first proves a project clean.
	if req.Findings == nil {
		req.Findings = []finding.Finding{}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/projects/%s/scans", c.BaseURL, project)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.Key)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "dragon-cli/0.1")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("submit scan: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("platform rejected the scan (%s): %s", resp.Status, apiError(data))
	}

	var out IngestResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse platform response: %w", err)
	}
	return &out, nil
}

// apiError extracts a readable message from a Huma error body.
func apiError(data []byte) string {
	var e struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
		Errors []struct {
			Message  string `json:"message"`
			Location string `json:"location"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &e) == nil {
		var parts []string
		if e.Detail != "" {
			parts = append(parts, e.Detail)
		} else if e.Title != "" {
			parts = append(parts, e.Title)
		}
		for _, x := range e.Errors {
			parts = append(parts, strings.TrimSpace(x.Location+": "+x.Message))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	s := strings.TrimSpace(string(data))
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
