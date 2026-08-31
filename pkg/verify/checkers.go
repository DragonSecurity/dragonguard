package verify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultCheckers returns the built-in verifiers.
//
// Each is a single read-only identity call against the credential's own
// issuer. The set is deliberately small and boring: the providers whose keys
// actually leak, and whose "who am I" endpoint is documented and cheap.
func DefaultCheckers() []Checker {
	return []Checker{
		githubChecker{},
		gitlabChecker{},
		slackChecker{},
		stripeChecker{},
		npmChecker{},
		sendgridChecker{},
		openAIChecker{},
		awsChecker{},
	}
}

// ---------- GitHub ----------

type githubChecker struct{}

func (githubChecker) Provider() string { return "github" }
func (githubChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "github", "ghp", "gho-", "github-pat", "github-fine-grained") ||
		hasVendorPrefix(secret, "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")
}
func (githubChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "github", CheckedAt: time.Now().UTC()}
	status, body, err := probe(ctx, c, http.MethodGet, "https://api.github.com/user", map[string]string{
		"Authorization":        "Bearer " + secret,
		"X-GitHub-Api-Version": "2022-11-28",
	})
	r.Status, r.Detail = classify(status, err)
	if r.Status == StatusActive {
		if login := jsonField(body, "login"); login != "" {
			r.Identity = "github user " + login
		}
	}
	return r
}

// ---------- GitLab ----------

type gitlabChecker struct{}

func (gitlabChecker) Provider() string { return "gitlab" }
func (gitlabChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "gitlab", "glpat") || hasVendorPrefix(secret, "glpat-")
}
func (gitlabChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "gitlab", CheckedAt: time.Now().UTC()}
	status, body, err := probe(ctx, c, http.MethodGet, "https://gitlab.com/api/v4/user", map[string]string{
		"PRIVATE-TOKEN": secret,
	})
	r.Status, r.Detail = classify(status, err)
	if r.Status == StatusActive {
		if u := jsonField(body, "username"); u != "" {
			r.Identity = "gitlab user " + u
		}
	}
	return r
}

// ---------- Slack ----------

type slackChecker struct {
	// endpoint is overridable so the payload logic below can be tested
	// against the responses Slack actually returns.
	endpoint string
}

func (slackChecker) Provider() string { return "slack" }
func (slackChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "slack", "xoxb", "xoxp", "xoxa") ||
		hasVendorPrefix(secret, "xoxb-", "xoxp-", "xoxa-", "xoxs-", "xoxe-")
}
func (s slackChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	url := s.endpoint
	if url == "" {
		url = "https://slack.com/api/auth.test"
	}
	status, body, err := probe(ctx, c, http.MethodGet, url, map[string]string{
		"Authorization": "Bearer " + secret,
	})
	if err != nil || status != http.StatusOK {
		r := Result{Provider: "slack", CheckedAt: time.Now().UTC()}
		r.Status, r.Detail = classify(status, err)
		return r
	}
	return slackVerdict(body)
}

// slackVerdict reads Slack's payload rather than its status code.
//
// Slack answers HTTP 200 even for a revoked token, putting the real answer in
// an "ok" field. Classifying on the status code alone would report every
// rotated Slack token in the repository as live -- the exact false positive
// verification exists to remove.
func slackVerdict(body []byte) Result {
	r := Result{Provider: "slack", CheckedAt: time.Now().UTC()}
	if !strings.Contains(string(body), `"ok":true`) {
		r.Status = StatusInactive
		return r
	}
	r.Status = StatusActive
	team, user := jsonField(body, "team"), jsonField(body, "user")
	if team != "" || user != "" {
		r.Identity = strings.TrimSpace(fmt.Sprintf("slack %s %s", team, user))
	}
	return r
}

// ---------- Stripe ----------

type stripeChecker struct{}

func (stripeChecker) Provider() string { return "stripe" }
func (stripeChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "stripe", "sk_live", "rk_live") ||
		hasVendorPrefix(secret, "sk_live_", "rk_live_", "sk_test_", "rk_test_")
}
func (stripeChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "stripe", CheckedAt: time.Now().UTC()}
	// The smallest read there is: one account object, no list, no writes.
	status, body, err := probe(ctx, c, http.MethodGet, "https://api.stripe.com/v1/account", map[string]string{
		"Authorization": "Bearer " + secret,
	})
	r.Status, r.Detail = classify(status, err)
	if r.Status == StatusActive {
		if id := jsonField(body, "id"); id != "" {
			r.Identity = "stripe account " + id
		}
	}
	return r
}

// ---------- npm ----------

type npmChecker struct{}

func (npmChecker) Provider() string { return "npm" }
func (npmChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "npm") || hasVendorPrefix(secret, "npm_")
}
func (npmChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "npm", CheckedAt: time.Now().UTC()}
	status, body, err := probe(ctx, c, http.MethodGet, "https://registry.npmjs.org/-/whoami", map[string]string{
		"Authorization": "Bearer " + secret,
	})
	r.Status, r.Detail = classify(status, err)
	if r.Status == StatusActive {
		if u := jsonField(body, "username"); u != "" {
			r.Identity = "npm user " + u
		}
	}
	return r
}

// ---------- SendGrid ----------

type sendgridChecker struct{}

func (sendgridChecker) Provider() string { return "sendgrid" }
func (sendgridChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "sendgrid") || hasVendorPrefix(secret, "SG.")
}
func (sendgridChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "sendgrid", CheckedAt: time.Now().UTC()}
	status, _, err := probe(ctx, c, http.MethodGet, "https://api.sendgrid.com/v3/scopes", map[string]string{
		"Authorization": "Bearer " + secret,
	})
	r.Status, r.Detail = classify(status, err)
	return r
}

// ---------- OpenAI ----------

type openAIChecker struct{}

func (openAIChecker) Provider() string { return "openai" }
func (openAIChecker) Matches(ruleID, secret string) bool {
	return ruleMatches(ruleID, "openai") || hasVendorPrefix(secret, "sk-proj-", "sk-svcacct-")
}
func (openAIChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "openai", CheckedAt: time.Now().UTC()}
	status, _, err := probe(ctx, c, http.MethodGet, "https://api.openai.com/v1/models", map[string]string{
		"Authorization": "Bearer " + secret,
	})
	r.Status, r.Detail = classify(status, err)
	return r
}

// ---------- AWS ----------

type awsChecker struct{}

func (awsChecker) Provider() string { return "aws" }
func (awsChecker) Matches(ruleID, secret string) bool {
	// AKIA/ASIA are AWS-assigned and appear nowhere else, so a "generic"
	// detection containing one is still an AWS credential.
	return ruleMatches(ruleID, "aws", "akia") || containsVendorPrefix(secret, "AKIA", "ASIA")
}

// Check calls STS GetCallerIdentity, the canonical read-only "who am I".
//
// Unlike every other checker here, AWS needs the secret access key as well as
// the key ID to sign a request, and a secret scanner usually finds only one of
// the pair. When the secret is not a complete credential the honest answer is
// unknown -- reporting inactive would file a live production key as noise.
func (awsChecker) Check(ctx context.Context, c *http.Client, secret string) Result {
	r := Result{Provider: "aws", CheckedAt: time.Now().UTC()}

	keyID, secretKey, ok := splitAWSCredential(secret)
	if !ok {
		r.Status = StatusUnknown
		r.Detail = "AWS verification needs both the access key ID and the secret access key; only one was detected"
		return r
	}

	req, err := signedSTSRequest(ctx, keyID, secretKey)
	if err != nil {
		r.Status, r.Detail = StatusUnknown, "could not sign STS request: "+err.Error()
		return r
	}
	resp, err := c.Do(req)
	if err != nil {
		r.Status, r.Detail = StatusUnknown, "could not reach STS: "+err.Error()
		return r
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	switch resp.StatusCode {
	case http.StatusOK:
		r.Status = StatusActive
		if arn := between(body, "<Arn>", "</Arn>"); arn != "" {
			r.Identity = arn
		}
	case http.StatusForbidden:
		// STS answers 403 both for an invalid key and for a valid key denied
		// the call, so the error code has to be read to tell them apart.
		if strings.Contains(body, "InvalidClientTokenId") || strings.Contains(body, "SignatureDoesNotMatch") {
			r.Status = StatusInactive
		} else {
			// The signature was accepted, so the credential is real.
			r.Status = StatusActive
			r.Detail = "credential is valid but denied sts:GetCallerIdentity"
		}
	default:
		r.Status, r.Detail = StatusUnknown, fmt.Sprintf("unexpected STS response %d", resp.StatusCode)
	}
	return r
}

// splitAWSCredential recovers a key-ID/secret pair from a detector match.
//
// Detectors report either just the key ID (AKIA...) or a blob containing both.
// Only a complete pair can be verified.
func splitAWSCredential(s string) (keyID, secretKey string, ok bool) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '"' || r == '\'' ||
			r == ',' || r == '=' || r == ':' || r == ';'
	})
	for _, f := range fields {
		switch {
		case len(f) == 20 && (strings.HasPrefix(f, "AKIA") || strings.HasPrefix(f, "ASIA")):
			keyID = f
		case len(f) == 40 && isBase64ish(f):
			secretKey = f
		}
	}
	return keyID, secretKey, keyID != "" && secretKey != ""
}

func isBase64ish(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '+', r == '/':
		default:
			return false
		}
	}
	return true
}

// signedSTSRequest builds a SigV4-signed GetCallerIdentity call.
//
// Implemented inline rather than pulling in the AWS SDK: this is one
// unauthenticated-shape GET against one endpoint, and the SDK would add a
// large dependency tree to a security scanner for a single request.
func signedSTSRequest(ctx context.Context, keyID, secretKey string) (*http.Request, error) {
	const (
		service = "sts"
		region  = "us-east-1"
		host    = "sts.amazonaws.com"
		query   = "Action=GetCallerIdentity&Version=2011-06-15"
	)
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-date:%s\n", host, amzDate)
	signedHeaders := "host;x-amz-date"
	payloadHash := sha256Hex("")

	canonicalRequest := strings.Join([]string{
		http.MethodGet, "/", query, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/?"+query, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		keyID, scope, signedHeaders, signature))
	return req, nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
