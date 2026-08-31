package platform

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DragonSecurity/dragonguard/pkg/finding"
)

// DRAGON_SERVER holds a server, not an endpoint. The client is what knows
// the API lives under /api/v1 -- getting this wrong posts to a path that
// does not exist and the whole submission 404s.
func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://guard.example.com":            "https://guard.example.com/api/v1",
		"https://guard.example.com/":           "https://guard.example.com/api/v1",
		"http://localhost:8111":                "http://localhost:8111/api/v1",
		"https://guard.example.com/api/v1":     "https://guard.example.com/api/v1",
		"https://guard.example.com/api/v1/":    "https://guard.example.com/api/v1",
		"https://guard.example.com/dragon/api": "https://guard.example.com/dragon/api",
		"":                                     "",
	}
	for in, want := range cases {
		if got := normalizeBaseURL(in); got != want {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIngestPostsToTheVersionedPath(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(IngestResponse{Verdict: "PASS", Posture: 91})
	}))
	defer srv.Close()

	out, err := New(srv.URL, "dgk_test").Ingest(context.Background(), "my-project",
		IngestRequest{Findings: []finding.Finding{}})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if want := "/api/v1/projects/my-project/scans"; gotPath != want {
		t.Errorf("posted to %q, want %q", gotPath, want)
	}
	if want := "Bearer dgk_test"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
	if out.Verdict != "PASS" {
		t.Errorf("Verdict = %q, want PASS", out.Verdict)
	}
}
