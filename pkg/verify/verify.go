// Package verify establishes whether a detected credential still works.
//
// Why this matters: secret scanners are noisy. A repository full of example
// keys, rotated tokens and test fixtures produces the same CRITICAL as one
// live production credential, and a team that has learned the alerts are
// usually false will not move quickly on the one that is not. Verification
// collapses "a string that looks like an AWS key" into "this key authenticates
// as arn:aws:iam::123456789012:user/deploy", which is not a finding anybody
// argues with.
//
// # Handling of the credential itself
//
// The raw secret never leaves this process and is never written anywhere.
// DragonGuard's scanner adapters redact by default; verification is the one
// path that needs the plaintext, so it runs in-process during the scan, and
// only the verdict is attached to the finding. A findings database holding
// live credentials in clear text is a second breach waiting to happen, and
// building one to reduce false positives would be a bad trade.
//
// # What the checks do
//
// Every check is a read-only identity call against the credential's own
// provider -- the same request the provider documents for "who am I". They
// establish liveness and, where cheap, whose credential it is. Nothing here
// writes, enumerates, escalates or persists. Verification is off by default
// and enabled per project, because sending a credential to a third party,
// even its rightful issuer, should be a decision somebody made on purpose.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// Status is the outcome of a verification attempt.
type Status string

const (
	// StatusActive means the credential authenticated. This is an incident.
	StatusActive Status = "active"
	// StatusInactive means the provider rejected it: already rotated, revoked
	// or never real. Still worth removing from the repository, but not urgent.
	StatusInactive Status = "inactive"
	// StatusUnknown means verification could not reach a conclusion -- no
	// checker for this credential type, no network, or an ambiguous response.
	// Deliberately distinct from inactive: "we could not check" must never be
	// allowed to read as "it is safe".
	StatusUnknown Status = "unknown"
)

// Result is a verification verdict.
type Result struct {
	Status Status `json:"status"`
	// Provider is the service the credential belongs to.
	Provider string `json:"provider,omitempty"`
	// Identity is who the credential authenticates as, when the provider says
	// so cheaply. It is what turns a finding into a rotation ticket.
	Identity string `json:"identity,omitempty"`
	// Detail explains an unknown result.
	Detail string `json:"detail,omitempty"`
	// CheckedAt records when the conclusion was drawn; liveness is perishable.
	CheckedAt time.Time `json:"checked_at"`
}

// Checker verifies one family of credential.
type Checker interface {
	// Provider names the service.
	Provider() string
	// Matches reports whether this checker handles a detected credential.
	//
	// Both the detector's rule ID and the value are considered. Detectors
	// frequently classify a real AWS or GitHub key as a "generic-api-key",
	// and matching on the label alone would leave those unverified -- which
	// is exactly the noisy middle of the queue verification exists to clear.
	// Value matching is restricted to vendor-registered prefixes (AKIA,
	// ghp_, xoxb-, ...) so a credential is only ever offered to the provider
	// that issued it.
	Matches(ruleID, secret string) bool
	// Check performs a read-only identity call.
	Check(ctx context.Context, client *http.Client, secret string) Result
}

// Verifier runs the registered checkers.
type Verifier struct {
	Checkers []Checker
	HTTP     *http.Client
	// Concurrency bounds simultaneous provider calls.
	Concurrency int
}

// New returns a Verifier with the built-in checkers registered.
func New() *Verifier {
	return &Verifier{
		Checkers: DefaultCheckers(),
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			// Never follow a redirect: a redirect away from the provider's
			// own host would forward the credential somewhere unintended.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Concurrency: 4,
	}
}

// Candidate pairs a finding with the plaintext secret detected for it.
type Candidate struct {
	// Index is the finding's position in the caller's slice.
	Index int
	// RuleID is the detector rule, used to pick a checker.
	RuleID string
	// Secret is the plaintext. It is read, used and dropped; it is never
	// stored on the finding.
	Secret string
}

// VerifyAll checks each candidate and writes the verdict onto the matching
// finding. The plaintext is not retained.
func (v *Verifier) VerifyAll(ctx context.Context, findings []finding.Finding, candidates []Candidate) map[int]Result {
	out := make(map[int]Result, len(candidates))
	if len(candidates) == 0 {
		return out
	}

	conc := v.Concurrency
	if conc <= 0 {
		conc = 4
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, c := range candidates {
		if c.Index < 0 || c.Index >= len(findings) || c.Secret == "" {
			continue
		}
		wg.Add(1)
		go func(c Candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := v.check(ctx, c)

			mu.Lock()
			defer mu.Unlock()
			out[c.Index] = res

			f := &findings[c.Index]
			if f.Metadata == nil {
				f.Metadata = map[string]any{}
			}
			f.Metadata["verification"] = string(res.Status)
			if res.Provider != "" {
				f.Metadata["verification_provider"] = res.Provider
			}
			switch res.Status {
			case StatusActive:
				f.Analysis.Verified = true
				f.Severity = finding.SeverityCritical
				if res.Identity != "" {
					f.Metadata["verification_identity"] = res.Identity
					f.Message = fmt.Sprintf("Credential is LIVE and authenticates as %s. Rotate it now.", res.Identity)
				} else {
					f.Message = "Credential is LIVE and still authenticates. Rotate it now."
				}
			case StatusInactive:
				// Not an emergency, but not nothing: the credential is still
				// in the repository and its history, and whoever committed it
				// will commit the next one the same way.
				f.Severity = finding.SeverityMedium
				f.Message = "Credential was rejected by the provider: already rotated or never valid. Remove it from the repository and its history."
			default:
				if res.Detail != "" {
					f.Metadata["verification_detail"] = res.Detail
				}
			}
		}(c)
	}
	wg.Wait()
	return out
}

func (v *Verifier) check(ctx context.Context, c Candidate) Result {
	for _, ch := range v.Checkers {
		if !ch.Matches(c.RuleID, c.Secret) {
			continue
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return ch.Check(ctx, v.HTTP, c.Secret)
	}
	return Result{
		Status:    StatusUnknown,
		Detail:    "no verifier for rule " + c.RuleID,
		CheckedAt: time.Now().UTC(),
	}
}

// ---------- helpers shared by checkers ----------

// probe issues a single read-only GET and classifies the response.
//
// The classification is deliberately conservative. Only an explicit 200 is
// treated as active, and only an explicit 401/403 as inactive. Anything else
// -- a rate limit, a 5xx, a network failure -- is unknown, because guessing
// "inactive" from an ambiguous answer is how a live credential gets filed as
// a false positive.
func probe(ctx context.Context, client *http.Client, method, url string, headers map[string]string) (status int, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "dragonguard-verify/0.1")
	req.Header.Set("Accept", "application/json")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// Bound the read: identity endpoints return small documents, and a
	// provider is not a reason to accept an unbounded body.
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, buf[:n], nil
}

func classify(status int, err error) (Status, string) {
	switch {
	case err != nil:
		return StatusUnknown, "could not reach provider: " + err.Error()
	case status == http.StatusOK:
		return StatusActive, ""
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return StatusInactive, ""
	case status == http.StatusTooManyRequests:
		return StatusUnknown, "rate limited by provider"
	default:
		return StatusUnknown, fmt.Sprintf("unexpected provider response %d", status)
	}
}

func jsonField(body []byte, keys ...string) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%.0f", t)
			}
		}
	}
	return ""
}

func ruleMatches(ruleID string, needles ...string) bool {
	id := strings.ToLower(ruleID)
	for _, n := range needles {
		if strings.Contains(id, n) {
			return true
		}
	}
	return false
}

// hasVendorPrefix reports whether a value carries one of a provider's
// registered credential prefixes.
//
// Only unambiguous, vendor-assigned prefixes belong here. A loose heuristic
// would risk sending one provider's credential to another, which is a far
// worse outcome than leaving a finding unverified.
func hasVendorPrefix(secret string, prefixes ...string) bool {
	s := strings.TrimSpace(secret)
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
		// Detectors often capture "KEY=value"; check the trailing token too.
		if i := strings.LastIndexAny(s, "=: \t\"'"); i >= 0 && i+1 < len(s) {
			if strings.HasPrefix(s[i+1:], p) {
				return true
			}
		}
	}
	return false
}

// containsVendorPrefix looks for a registered prefix anywhere in a captured
// blob, which is what a multi-line credential match looks like.
func containsVendorPrefix(secret string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.Contains(secret, p) {
			return true
		}
	}
	return false
}
