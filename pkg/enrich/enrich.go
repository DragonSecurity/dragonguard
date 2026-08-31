// Package enrich adds exploitation intelligence to findings.
//
// A scanner tells you a vulnerability exists. Enrichment tells you whether
// anybody is actually exploiting it. That difference is most of what makes a
// risk score worth acting on: CVSS is a property of the vulnerability, EPSS
// and KEV are properties of the world.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/depsdev"
	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

const (
	epssAPI = "https://api.first.org/data/v1/epss"
	kevFeed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// cacheTTL bounds how stale intelligence may be before a refresh is
	// attempted. Exploitation data moves in days, not hours.
	cacheTTL = 24 * time.Hour

	// epssBatch is the number of CVEs per EPSS request. The API accepts a
	// comma-separated list; batching keeps a large monorepo to a few calls.
	epssBatch = 100
)

// Options configures an enrichment pass.
type Options struct {
	// CacheDir holds the intelligence caches between runs.
	CacheDir string
	// Offline forbids every network call. Cached data is still used.
	Offline bool
	// Timeout bounds the whole enrichment pass, not each request.
	Timeout time.Duration
	// HTTPClient overrides the client, for tests.
	HTTPClient *http.Client
}

// Report describes what enrichment managed to do, so a gate can tell the
// difference between "no exploitation intelligence found" and "we never
// looked". A gate that cannot tell those apart is not a gate.
type Report struct {
	EPSSAvailable bool              `json:"epss_available"`
	KEVAvailable  bool              `json:"kev_available"`
	EPSSSource    string            `json:"epss_source,omitempty"` // network | cache | none
	KEVSource     string            `json:"kev_source,omitempty"`
	KEVEntries    int               `json:"kev_entries"`
	EPSSResolved  int               `json:"epss_resolved"`
	CVEsQueried   int               `json:"cves_queried"`
	Degraded      bool              `json:"degraded"`
	Notes         []string          `json:"notes,omitempty"`
	SupplyChain   SupplyChainReport `json:"supply_chain"`
}

// Enricher applies threat intelligence to findings.
type Enricher struct {
	opts   Options
	client *http.Client
	deps   *depsdev.Client
}

func New(opts Options) *Enricher {
	c := opts.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 20 * time.Second}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 60 * time.Second
	}
	dd := depsdev.New()
	dd.HTTP = c
	return &Enricher{opts: opts, client: c, deps: dd}
}

// Enrich annotates findings in place and reports how complete the pass was.
func (e *Enricher) Enrich(ctx context.Context, findings []finding.Finding) Report {
	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	var rep Report

	cves := collectCVEs(findings)
	rep.CVEsQueried = len(cves)

	var (
		wg   sync.WaitGroup
		kev  map[string]kevEntry
		epss map[string]float64
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		var src string
		kev, src = e.loadKEV(ctx)
		rep.KEVSource = src
		rep.KEVAvailable = src != "none"
		rep.KEVEntries = len(kev)
	}()
	go func() {
		defer wg.Done()
		if len(cves) == 0 {
			// No CVEs to look up is not the same as EPSS being unreachable.
			// Reporting it as unavailable would mark every scan of a
			// vulnerability-free project as degraded.
			rep.EPSSSource = ""
			rep.EPSSAvailable = true
			return
		}
		var src string
		epss, src = e.loadEPSS(ctx, cves)
		rep.EPSSSource = src
		rep.EPSSAvailable = src != "none"
		rep.EPSSResolved = len(epss)
	}()
	wg.Wait()

	for i := range findings {
		f := &findings[i]
		for _, cve := range f.CVE {
			key := strings.ToUpper(cve)
			if score, ok := epss[key]; ok {
				// Several CVEs on one finding: the worst one governs.
				if score > f.Threat.EPSS {
					f.Threat.EPSS = score
				}
				f.Threat.EPSSKnown = true
			}
			if k, ok := kev[key]; ok {
				f.Threat.KEV = true
				f.Threat.ExploitAvailab = true
				if f.Threat.ExploitMaturit == "" {
					f.Threat.ExploitMaturit = "active"
				}
				if k.KnownRansomware {
					f.Threat.KEVRansomware = true
				}
			}
		}
		// A high EPSS is itself evidence that exploit code circulates, even
		// when the CVE has not reached the KEV catalog.
		if f.Threat.EPSS >= 0.5 && !f.Threat.ExploitAvailab {
			f.Threat.ExploitAvailab = true
			if f.Threat.ExploitMaturit == "" {
				f.Threat.ExploitMaturit = "likely"
			}
		}
	}

	if !rep.KEVAvailable || (len(cves) > 0 && !rep.EPSSAvailable) {
		rep.Degraded = true
		if !rep.KEVAvailable {
			rep.Notes = append(rep.Notes, "KEV catalog unavailable: known-exploited gates cannot be enforced")
		}
		if len(cves) > 0 && !rep.EPSSAvailable {
			rep.Notes = append(rep.Notes, "EPSS unavailable: exploit-probability scoring is disabled")
		}
	}
	return rep
}

func collectCVEs(findings []finding.Finding) []string {
	seen := make(map[string]bool)
	var out []string
	for _, f := range findings {
		for _, c := range f.CVE {
			c = strings.ToUpper(strings.TrimSpace(c))
			if c == "" || seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

// ---------- KEV ----------

type kevEntry struct {
	CVEID           string `json:"cveID"`
	VendorProject   string `json:"vendorProject"`
	Product         string `json:"product"`
	DateAdded       string `json:"dateAdded"`
	DueDate         string `json:"dueDate"`
	KnownRansomware bool   `json:"-"`
	RansomwareUse   string `json:"knownRansomwareCampaignUse"`
}

type kevCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	Count           int        `json:"count"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

func (e *Enricher) loadKEV(ctx context.Context) (map[string]kevEntry, string) {
	path := e.cachePath("kev.json")

	if data, fresh := e.readCache(path); fresh {
		if m := parseKEV(data); m != nil {
			return m, "cache"
		}
	}
	if !e.opts.Offline {
		if data, err := e.fetch(ctx, kevFeed); err == nil {
			if m := parseKEV(data); m != nil {
				e.writeCache(path, data)
				return m, "network"
			}
		}
	}
	// A stale cache still beats no intelligence at all. Being told a CVE was
	// on the KEV list yesterday is far more useful than being told nothing.
	if data, _ := e.readCache(path); data != nil {
		if m := parseKEV(data); m != nil {
			return m, "cache"
		}
	}
	return nil, "none"
}

func parseKEV(data []byte) map[string]kevEntry {
	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil
	}
	if len(cat.Vulnerabilities) == 0 {
		return nil
	}
	m := make(map[string]kevEntry, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		v.KnownRansomware = strings.EqualFold(strings.TrimSpace(v.RansomwareUse), "known")
		m[strings.ToUpper(v.CVEID)] = v
	}
	return m
}

// ---------- EPSS ----------

type epssResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

func (e *Enricher) loadEPSS(ctx context.Context, cves []string) (map[string]float64, string) {
	path := e.cachePath("epss.json")
	cached := map[string]float64{}
	if data, _ := e.readCache(path); data != nil {
		_ = json.Unmarshal(data, &cached)
	}

	_, fresh := e.readCache(path)
	missing := make([]string, 0, len(cves))
	for _, c := range cves {
		if _, ok := cached[c]; !ok || !fresh {
			missing = append(missing, c)
		}
	}

	if e.opts.Offline || len(missing) == 0 {
		if len(cached) == 0 {
			return nil, "none"
		}
		return filterTo(cached, cves), "cache"
	}

	fetched := 0
	for start := 0; start < len(missing); start += epssBatch {
		end := start + epssBatch
		if end > len(missing) {
			end = len(missing)
		}
		url := epssAPI + "?cve=" + strings.Join(missing[start:end], ",")
		data, err := e.fetch(ctx, url)
		if err != nil {
			break
		}
		var resp epssResponse
		if json.Unmarshal(data, &resp) != nil {
			break
		}
		for _, d := range resp.Data {
			if v, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				cached[strings.ToUpper(d.CVE)] = v
			}
		}
		// A CVE the API knows nothing about is recorded as zero so we do not
		// re-query it on every run; EPSS genuinely has no score for it.
		for _, c := range missing[start:end] {
			if _, ok := cached[c]; !ok {
				cached[c] = 0
			}
		}
		fetched++
	}

	if fetched > 0 {
		if out, err := json.Marshal(cached); err == nil {
			e.writeCache(path, out)
		}
		return filterTo(cached, cves), "network"
	}
	if len(cached) == 0 {
		return nil, "none"
	}
	return filterTo(cached, cves), "cache"
}

func filterTo(all map[string]float64, cves []string) map[string]float64 {
	out := make(map[string]float64, len(cves))
	for _, c := range cves {
		if v, ok := all[c]; ok {
			out[c] = v
		}
	}
	return out
}

// ---------- transport and cache ----------

func (e *Enricher) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dragonguard/0.1 (+https://dragonsecurity.io)")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	// Bound the read: a feed that suddenly returns gigabytes should not take
	// the scanner's memory with it.
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func (e *Enricher) cachePath(name string) string {
	dir := e.opts.CacheDir
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "cache", name)
}

// readCache returns the cached bytes and whether they are within the TTL.
func (e *Enricher) readCache(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, time.Since(st.ModTime()) < cacheTTL
}

func (e *Enricher) writeCache(path string, data []byte) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	// Write-then-rename so a killed process cannot leave a truncated cache
	// that later parses as an empty KEV catalog.
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}
