// Package depsdev is a client for Google's deps.dev API.
//
// One upstream serves three things DragonGuard would otherwise have to build
// or run separately:
//
//   - OpenSSF Scorecard results, without needing a GitHub token or a local
//     scorecard binary, which is what makes the supply-chain risk component
//     usable rather than permanently unscored.
//   - The resolved dependency graph, with each node marked SELF, DIRECT or
//     INDIRECT. That is what turns "lodash is vulnerable" into "bump express,
//     which is the dependency you actually control".
//   - Published version lists, so a minimal upgrade can be computed rather
//     than quoted from whatever fixed version an advisory happened to name.
//
// The API is public and unauthenticated. Every call degrades to "unknown"
// rather than failing a scan: intelligence that cannot be fetched must not
// become intelligence that reads as an absence of risk.
package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultBaseURL = "https://api.deps.dev/v3alpha"

// System is a deps.dev package ecosystem.
type System string

const (
	SystemNPM      System = "npm"
	SystemGo       System = "go"
	SystemMaven    System = "maven"
	SystemPyPI     System = "pypi"
	SystemCargo    System = "cargo"
	SystemNuGet    System = "nuget"
	SystemRubyGems System = "rubygems"
)

// SystemFor maps the ecosystem strings scanners emit onto deps.dev systems.
//
// Scanners disagree on spelling -- Trivy says "gomod", OSV says "Go", purls
// say "golang" -- so the mapping is deliberately generous. An unrecognized
// ecosystem returns false rather than guessing, because querying the wrong
// system returns a confident answer about the wrong package.
func SystemFor(ecosystem string) (System, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "node", "nodejs", "yarn", "pnpm":
		return SystemNPM, true
	case "go", "gomod", "golang", "go-module":
		return SystemGo, true
	case "maven", "gradle", "jar", "java", "pom":
		return SystemMaven, true
	case "pypi", "pip", "python", "poetry", "uv", "pipenv":
		return SystemPyPI, true
	case "cargo", "crates.io", "rust":
		return SystemCargo, true
	case "nuget", "dotnet", "csharp":
		return SystemNuGet, true
	case "rubygems", "gem", "gems", "bundler", "ruby":
		return SystemRubyGems, true
	default:
		return "", false
	}
}

// Client talks to deps.dev.
type Client struct {
	BaseURL string
	HTTP    *http.Client

	// Concurrency bounds in-flight requests. deps.dev is a shared public
	// service; a monorepo with two thousand dependencies should not open two
	// thousand connections to it.
	Concurrency int

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	data []byte
	err  error
}

func New() *Client {
	return &Client{
		BaseURL:     defaultBaseURL,
		HTTP:        &http.Client{Timeout: 15 * time.Second},
		Concurrency: 8,
		cache:       map[string]cacheEntry{},
	}
}

// ---------- wire types ----------

// VersionKey identifies one published version of a package.
type VersionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type relatedProject struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	RelationType string `json:"relationType"`
}

type versionResponse struct {
	VersionKey   VersionKey `json:"versionKey"`
	PURL         string     `json:"purl"`
	PublishedAt  string     `json:"publishedAt"`
	IsDeprecated bool       `json:"isDeprecated"`
	AdvisoryKeys []struct {
		ID string `json:"id"`
	} `json:"advisoryKeys"`
	RelatedProjects []relatedProject `json:"relatedProjects"`
	Licenses        []string         `json:"licenses"`
	SLSAProvenances []struct {
		SourceRepository string `json:"sourceRepository"`
		Verified         bool   `json:"verified"`
	} `json:"slsaProvenances"`
	Attestations []struct {
		Type     string `json:"type"`
		Verified bool   `json:"verified"`
	} `json:"attestations"`
}

// ScorecardCheck is one OpenSSF Scorecard check result.
type ScorecardCheck struct {
	Name          string `json:"name"`
	Score         int    `json:"score"`
	Reason        string `json:"reason"`
	Documentation struct {
		Short string `json:"short"`
	} `json:"documentation"`
}

// Scorecard is a project's OpenSSF Scorecard result.
type Scorecard struct {
	Date         string           `json:"date"`
	OverallScore float64          `json:"overallScore"`
	Checks       []ScorecardCheck `json:"checks"`
	Repo         struct {
		Name   string `json:"name"`
		Commit string `json:"commit"`
	} `json:"repository"`
}

// FailedChecks returns the checks that scored below threshold, ignoring the
// -1 that Scorecard uses for "not applicable to this project". Treating -1 as
// a failure would report every project without a package registry as unsafe.
func (s *Scorecard) FailedChecks(threshold int) []ScorecardCheck {
	var out []ScorecardCheck
	for _, c := range s.Checks {
		if c.Score >= 0 && c.Score < threshold {
			out = append(out, c)
		}
	}
	return out
}

type projectResponse struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	StarsCount int        `json:"starsCount"`
	License    string     `json:"license"`
	Scorecard  *Scorecard `json:"scorecard"`
}

// ---------- dependency graph ----------

// Relation describes how a node reaches the root of the graph.
type Relation string

const (
	RelationSelf     Relation = "SELF"
	RelationDirect   Relation = "DIRECT"
	RelationIndirect Relation = "INDIRECT"
)

// Node is one package version in a resolved dependency graph.
type Node struct {
	VersionKey VersionKey `json:"versionKey"`
	Bundled    bool       `json:"bundled"`
	Relation   Relation   `json:"relation"`
	Errors     []string   `json:"errors"`
}

// Edge is a resolved dependency relationship, carrying the version range the
// parent asked for. The requirement is what makes a remediation actionable:
// it says whether a fixed version is even reachable without a major bump.
type Edge struct {
	FromNode    int    `json:"fromNode"`
	ToNode      int    `json:"toNode"`
	Requirement string `json:"requirement"`
}

// Graph is a resolved dependency graph rooted at a single package version.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
	Error string `json:"error"`
}

// ---------- API ----------

// Project fetches project metadata, including any OpenSSF Scorecard result.
// A project deps.dev has never assessed returns (nil, nil): unknown, not an
// error and emphatically not a zero score.
func (c *Client) Project(ctx context.Context, projectID string) (*projectResponse, error) {
	if projectID == "" {
		return nil, nil
	}
	path := fmt.Sprintf("/projects/%s", url.PathEscape(projectID))
	data, err := c.get(ctx, path)
	if err != nil || data == nil {
		return nil, err
	}
	var pr projectResponse
	if err := json.Unmarshal(data, &pr); err != nil {
		return nil, fmt.Errorf("parse project %s: %w", projectID, err)
	}
	return &pr, nil
}

// SourceRepo resolves a package version to the project that publishes it.
//
// Only a SOURCE_REPO relation is accepted. deps.dev also reports issue
// trackers and homepages, and scoring a package by its issue tracker's
// Scorecard would be quietly wrong.
func (c *Client) SourceRepo(ctx context.Context, sys System, name, version string) (string, error) {
	v, err := c.version(ctx, sys, name, version)
	if err != nil || v == nil {
		return "", err
	}
	for _, rp := range v.RelatedProjects {
		if rp.RelationType == "SOURCE_REPO" {
			return rp.ProjectKey.ID, nil
		}
	}
	return "", nil
}

// ScorecardFor resolves a package to its source project's Scorecard in one
// call. Returns nil when the package, the project or the Scorecard is unknown.
func (c *Client) ScorecardFor(ctx context.Context, sys System, name, version string) (*Scorecard, error) {
	repo, err := c.SourceRepo(ctx, sys, name, version)
	if err != nil || repo == "" {
		return nil, err
	}
	proj, err := c.Project(ctx, repo)
	if err != nil || proj == nil {
		return nil, err
	}
	return proj.Scorecard, nil
}

// Dependencies fetches the resolved dependency graph for a package version.
func (c *Client) Dependencies(ctx context.Context, sys System, name, version string) (*Graph, error) {
	path := fmt.Sprintf("/systems/%s/packages/%s/versions/%s:dependencies",
		sys, url.PathEscape(name), url.PathEscape(version))
	data, err := c.get(ctx, path)
	if err != nil || data == nil {
		return nil, err
	}
	var g Graph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse dependency graph: %w", err)
	}
	return &g, nil
}

// Versions lists the published versions of a package, oldest first as
// deps.dev returns them.
func (c *Client) Versions(ctx context.Context, sys System, name string) ([]VersionKey, error) {
	path := fmt.Sprintf("/systems/%s/packages/%s", sys, url.PathEscape(name))
	data, err := c.get(ctx, path)
	if err != nil || data == nil {
		return nil, err
	}
	var pkg struct {
		Versions []struct {
			VersionKey VersionKey `json:"versionKey"`
			IsDefault  bool       `json:"isDefault"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package versions: %w", err)
	}
	out := make([]VersionKey, 0, len(pkg.Versions))
	for _, v := range pkg.Versions {
		out = append(out, v.VersionKey)
	}
	return out, nil
}

func (c *Client) version(ctx context.Context, sys System, name, ver string) (*versionResponse, error) {
	path := fmt.Sprintf("/systems/%s/packages/%s/versions/%s",
		sys, url.PathEscape(name), url.PathEscape(ver))
	data, err := c.get(ctx, path)
	if err != nil || data == nil {
		return nil, err
	}
	var v versionResponse
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse version %s@%s: %w", name, ver, err)
	}
	return &v, nil
}

// get performs a cached GET. A 404 returns (nil, nil): deps.dev not knowing
// about a package is an ordinary answer, not a failure.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	c.mu.Lock()
	if e, ok := c.cache[path]; ok {
		c.mu.Unlock()
		return e.data, e.err
	}
	c.mu.Unlock()

	data, err := c.fetch(ctx, path)

	c.mu.Lock()
	// A cancelled context says nothing about the resource, so caching it
	// would poison every later lookup in the same run.
	if ctx.Err() == nil {
		c.cache[path] = cacheEntry{data: data, err: err}
	}
	c.mu.Unlock()
	return data, err
}

func (c *Client) fetch(ctx context.Context, path string) ([]byte, error) {
	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragonguard/0.1 (+https://dragonsecurity.io)")
	req.Header.Set("Accept", "application/json")

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("deps.dev GET %s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}
