package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// "We could not check" must never be allowed to read as "it is safe".
func TestAmbiguousResponsesAreUnknownNotInactive(t *testing.T) {
	cases := []struct {
		status int
		want   Status
	}{
		{http.StatusOK, StatusActive},
		{http.StatusUnauthorized, StatusInactive},
		{http.StatusForbidden, StatusInactive},
		{http.StatusTooManyRequests, StatusUnknown},
		{http.StatusInternalServerError, StatusUnknown},
		{http.StatusBadGateway, StatusUnknown},
		{http.StatusNotFound, StatusUnknown},
	}
	for _, tc := range cases {
		got, _ := classify(tc.status, nil)
		if got != tc.want {
			t.Errorf("status %d classified %s, want %s", tc.status, got, tc.want)
		}
	}
	// A network failure says nothing about the credential.
	if got, _ := classify(0, context.DeadlineExceeded); got != StatusUnknown {
		t.Errorf("network error classified %s, want unknown", got)
	}
}

// Slack answers HTTP 200 even for a revoked token; only the payload says
// which. Classifying on the status code would report every rotated Slack
// token as live.
func TestSlackReadsThePayloadNotJustTheStatusCode(t *testing.T) {
	cases := []struct {
		name string
		body string
		want Status
		id   string
	}{
		{"revoked token still returns 200", `{"ok":false,"error":"invalid_auth"}`, StatusInactive, ""},
		{"live token", `{"ok":true,"team":"acme","user":"deploybot"}`, StatusActive, "slack acme deploybot"},
		{"token_revoked", `{"ok":false,"error":"token_revoked"}`, StatusInactive, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := slackVerdict([]byte(tc.body))
			if got.Status != tc.want {
				t.Errorf("status = %s, want %s", got.Status, tc.want)
			}
			if tc.id != "" && got.Identity != tc.id {
				t.Errorf("identity = %q, want %q", got.Identity, tc.id)
			}
		})
	}
}

// End to end through the HTTP path, with Slack's real 200-for-everything shape.
func TestSlackCheckerAgainstAServerThatAlways200s(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if strings.Contains(r.Header.Get("Authorization"), "good") {
			_, _ = w.Write([]byte(`{"ok":true,"team":"acme","user":"deploybot"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer srv.Close()

	c := slackChecker{endpoint: srv.URL}
	if got := c.Check(context.Background(), srv.Client(), "xoxb-good"); got.Status != StatusActive {
		t.Errorf("live token classified %s", got.Status)
	}
	if got := c.Check(context.Background(), srv.Client(), "xoxb-revoked"); got.Status != StatusInactive {
		t.Errorf("revoked token classified %s", got.Status)
	}
}

// A verified-live credential must be escalated, and the plaintext must not
// survive anywhere on the finding.
func TestActiveCredentialEscalatesAndDoesNotStorePlaintext(t *testing.T) {
	const plaintext = "ghp_EXAMPLE_PLAINTEXT_FOR_LEAK_TEST"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	v := &Verifier{
		HTTP:     srv.Client(),
		Checkers: []Checker{stubChecker{url: srv.URL}},
	}
	fs := []finding.Finding{{
		Category: finding.CategorySecret,
		RuleID:   "github-pat",
		Severity: finding.SeverityHigh,
	}}
	v.VerifyAll(context.Background(), fs, []Candidate{{Index: 0, RuleID: "github-pat", Secret: plaintext}})

	f := fs[0]
	if !f.Analysis.Verified {
		t.Error("a live credential must be marked verified")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("severity = %s, a proven-live credential is critical", f.Severity)
	}
	if f.Metadata["verification"] != string(StatusActive) {
		t.Errorf("verification metadata = %v", f.Metadata["verification"])
	}
	// The whole point: the plaintext must not be anywhere on the finding.
	for k, val := range f.Metadata {
		if s, ok := val.(string); ok && strings.Contains(s, plaintext) {
			t.Errorf("metadata[%q] leaked the plaintext credential", k)
		}
	}
	if strings.Contains(f.Message+f.Location.Snippet+f.Title, plaintext) {
		t.Error("the finding retained the plaintext credential")
	}
}

// A rejected credential is downgraded, not dropped: it is still in the
// repository and its history.
func TestInactiveCredentialIsDowngradedNotRemoved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v := &Verifier{HTTP: srv.Client(), Checkers: []Checker{stubChecker{url: srv.URL}}}
	fs := []finding.Finding{{Category: finding.CategorySecret, RuleID: "github-pat", Severity: finding.SeverityCritical}}
	v.VerifyAll(context.Background(), fs, []Candidate{{Index: 0, RuleID: "github-pat", Secret: "x"}})

	if fs[0].Analysis.Verified {
		t.Error("a rejected credential must not be marked verified")
	}
	if fs[0].Severity != finding.SeverityMedium {
		t.Errorf("severity = %s, want medium for a rotated credential", fs[0].Severity)
	}
}

// Without a checker the verdict is unknown and nothing is changed.
func TestUnhandledRuleLeavesTheFindingAlone(t *testing.T) {
	v := &Verifier{HTTP: http.DefaultClient, Checkers: nil}
	fs := []finding.Finding{{Category: finding.CategorySecret, RuleID: "exotic-token", Severity: finding.SeverityCritical}}
	v.VerifyAll(context.Background(), fs, []Candidate{{Index: 0, RuleID: "exotic-token", Secret: "x"}})

	if fs[0].Severity != finding.SeverityCritical {
		t.Error("an unverifiable credential must keep its original severity")
	}
	if fs[0].Analysis.Verified {
		t.Error("an unverifiable credential must not be marked verified")
	}
}

// AWS needs both halves of the credential; one half alone is unknown, never
// inactive, or a live production key would be filed as noise.
func TestAWSCredentialSplitting(t *testing.T) {
	const (
		id     = "AKIAIOSFODNN7EXAMPLE"
		secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYX"
	)
	if _, _, ok := splitAWSCredential(id); ok {
		t.Error("a key ID alone is not a verifiable credential")
	}

	pair := "aws_access_key_id=" + id + "\naws_secret_access_key=" + strings.Repeat("A", 40)
	gotID, gotSecret, ok := splitAWSCredential(pair)
	if !ok || gotID != id || len(gotSecret) != 40 {
		t.Errorf("split = (%q, %q, %v), want the full pair", gotID, gotSecret, ok)
	}

	res := awsChecker{}.Check(context.Background(), http.DefaultClient, id)
	if res.Status != StatusUnknown {
		t.Errorf("a lone key ID returned %s; only a complete pair can be verified", res.Status)
	}
	_ = secret
}

// Checkers must be matched by rule ID, not applied indiscriminately.
func TestCheckerRuleMatching(t *testing.T) {
	cases := []struct {
		checker Checker
		ruleID  string
		want    bool
	}{
		{githubChecker{}, "github-pat", true},
		{githubChecker{}, "aws-access-key", false},
		{awsChecker{}, "aws-access-token", true},
		{slackChecker{}, "slack-bot-token", true},
		{stripeChecker{}, "stripe-access-token", true},
		{gitlabChecker{}, "gitlab-pat", true},
		{gitlabChecker{}, "github-pat", false},
	}
	for _, tc := range cases {
		if got := tc.checker.Matches(tc.ruleID, ""); got != tc.want {
			t.Errorf("%s.Matches(%q) = %v, want %v", tc.checker.Provider(), tc.ruleID, got, tc.want)
		}
	}
}

// The signer must produce a well-formed SigV4 Authorization header.
func TestSTSRequestIsSigned(t *testing.T) {
	req, err := signedSTSRequest(context.Background(), "AKIAIOSFODNN7EXAMPLE", strings.Repeat("A", 40))
	if err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	for _, want := range []string{"AWS4-HMAC-SHA256", "Credential=AKIAIOSFODNN7EXAMPLE/", "SignedHeaders=host;x-amz-date", "Signature="} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization header missing %q: %s", want, auth)
		}
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date not set")
	}
}

func TestRedactionRemovesThePlaintext(t *testing.T) {
	// Mirrors the gitleaks adapter's masking. The value is deliberately
	// low-entropy and self-describing: a fixture that looks like a real
	// credential gets flagged by this repository's own secret scan, which is
	// noise for everybody and indistinguishable from the real thing.
	const secret = "ghp_EXAMPLE_NOT_A_REAL_TOKEN"
	match := "token = " + secret
	got := strings.ReplaceAll(match, secret, "REDACTED")
	if strings.Contains(got, secret) {
		t.Error("redaction left the plaintext behind")
	}
}

// stubChecker points a checker at a test server.
type stubChecker struct{ url string }

func (stubChecker) Provider() string                   { return "stub" }
func (stubChecker) Matches(ruleID, secret string) bool { return ruleID == "github-pat" }
func (s stubChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "stub", CheckedAt: time.Now().UTC()}
	status, body, err := probe(ctx, c, http.MethodGet, s.url, map[string]string{"Authorization": "Bearer " + secret})
	r.Status, r.Detail = classify(status, err)
	if r.Status == StatusActive {
		if login := jsonField(body, "login"); login != "" {
			r.Identity = "github user " + login
		}
	}
	return r
}

// Detectors routinely classify a real AWS or GitHub key as "generic-api-key".
// Matching only on the label leaves exactly those unverified.
func TestGenericDetectionsAreRoutedByVendorPrefix(t *testing.T) {
	cases := []struct {
		name    string
		checker Checker
		ruleID  string
		secret  string
		want    bool
	}{
		{"AWS key in a generic match", awsChecker{}, "generic-api-key", "AWS_ACCESS_KEY_ID=AKIAZ1V3EXAMPLE00000", true},
		{"STS temp credential", awsChecker{}, "generic-api-key", "ASIAZ1V3EXAMPLE00000", true},
		{"GitHub token in a generic match", githubChecker{}, "generic-api-key", "ghp_EXAMPLE_NOT_A_REAL_TOKEN", true},
		{"GitHub fine-grained", githubChecker{}, "generic-api-key", "github_pat_EXAMPLE_NOT_REAL", true},
		{"Slack bot token", slackChecker{}, "generic-api-key", "xoxb-EXAMPLE-NOT-A-REAL-TOKEN", true},
		{"Stripe live key", stripeChecker{}, "generic-api-key", "sk_live_EXAMPLE_NOT_A_REAL_KEY", true},
		{"GitLab PAT", gitlabChecker{}, "generic-api-key", "glpat-EXAMPLE_NOT_A_REAL_TOKEN", true},
		{"key=value capture", githubChecker{}, "generic-api-key", "GITHUB_TOKEN=ghp_EXAMPLE_NOT_A_REAL_TOKEN", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.checker.Matches(tc.ruleID, tc.secret); got != tc.want {
				t.Errorf("Matches(%q, %q) = %v, want %v", tc.ruleID, tc.secret, got, tc.want)
			}
		})
	}
}

// A credential must only ever be offered to the provider that issued it.
// Loose matching here would send one vendor's key to another.
func TestVendorPrefixMatchingDoesNotCrossProviders(t *testing.T) {
	cases := []struct {
		checker Checker
		secret  string
	}{
		{githubChecker{}, "AKIAZ1V3EXAMPLE00000"},
		{awsChecker{}, "ghp_EXAMPLE_NOT_A_REAL_TOKEN"},
		{slackChecker{}, "sk_live_EXAMPLE_NOT_A_REAL_KEY"},
		{stripeChecker{}, "xoxb-EXAMPLE-NOT-A-REAL-TOKEN"},
		{gitlabChecker{}, "ghp_EXAMPLE_NOT_A_REAL_TOKEN"},
		{npmChecker{}, "glpat-EXAMPLE_NOT_A_REAL_TOKEN"},
		// A high-entropy string that belongs to nobody in particular.
		{awsChecker{}, "d41d8cd98f00b204e9800998ecf8427e"},
		{githubChecker{}, "d41d8cd98f00b204e9800998ecf8427e"},
	}
	for _, tc := range cases {
		if tc.checker.Matches("generic-api-key", tc.secret) {
			t.Errorf("%s claimed a credential it does not issue: %q", tc.checker.Provider(), tc.secret)
		}
	}
}

// AWS credentials leak as a pair in one file, but detectors report one line
// at a time and usually skip the low-entropy access key ID entirely.
func TestAWSPairingRecoversBothHalvesFromTheFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.env"
	const (
		keyID  = "AKIAZ1V3EXAMPLE00000"
		secret = "abcdefghij0123456789ABCDEFGHIJ0123456789"
	)
	body := "AWS_ACCESS_KEY_ID=" + keyID + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if !FileMentionsAWSKey(path) {
		t.Fatal("file containing an AKIA key was not recognized")
	}

	// The detector found only the secret half.
	combined, ok := PairAWSCredential(path, secret)
	if !ok {
		t.Fatal("pairing failed despite both halves being present")
	}
	gotID, gotSecret, complete := splitAWSCredential(combined)
	if !complete || gotID != keyID || gotSecret != secret {
		t.Errorf("paired credential = (%q, %q, %v)", gotID, gotSecret, complete)
	}

	// Now the AWS checker claims it, where before nothing did.
	if !(awsChecker{}).Matches("generic-api-key", combined) {
		t.Error("the AWS checker should claim a paired credential")
	}
}

func TestAWSPairingDeclinesWhenOnlyOneHalfExists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/partial.env"
	if err := os.WriteFile(path, []byte("AWS_ACCESS_KEY_ID=AKIAZ1V3EXAMPLE00000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := PairAWSCredential(path, "AKIAZ1V3EXAMPLE00000"); ok {
		t.Error("pairing must not claim success with only the key ID")
	}
}

// Pairing must not read an arbitrary large file into memory.
func TestAWSPairingBoundsFileSize(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/huge.bin"
	big := make([]byte, maxPairScanBytes+1024)
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := PairAWSCredential(path, "x"); ok {
		t.Error("pairing should decline an oversized file")
	}
	if FileMentionsAWSKey(path) {
		t.Error("oversized file should not be scanned")
	}
}
