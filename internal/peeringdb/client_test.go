package peeringdb

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupASN(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/api/net"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("asn"), "15169"; got != want {
			t.Fatalf("asn query = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("User-Agent"), userAgent; got != want {
			t.Fatalf("user-agent = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"data":[{"asn":15169,"name":"GOOGLE","name_long":"Google LLC","website":"https://google.com","policy_general":"Open","policy_ratio":false,"policy_locations":"Not Required","info_traffic":"100+Tbps","ix_count":200,"fac_count":120}]}`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/api"
	defer func() { baseURL = oldBaseURL }()

	n, err := LookupASN(15169)
	if err != nil {
		t.Fatalf("LookupASN returned error: %v", err)
	}
	if n.ASN != 15169 {
		t.Fatalf("ASN = %d, want 15169", n.ASN)
	}
	if n.Name != "GOOGLE" {
		t.Fatalf("Name = %q, want GOOGLE", n.Name)
	}
	if n.IXCount != 200 {
		t.Fatalf("IXCount = %d, want 200", n.IXCount)
	}
	if n.PolicyRatio != "" {
		t.Fatalf("PolicyRatio = %q, want empty for boolean false", n.PolicyRatio)
	}
}

func TestLookupASNPolicyRatioString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"asn":13335,"name":"Cloudflare","policy_ratio":"Balanced","ix_count":50,"fac_count":25}]}`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/api"
	defer func() { baseURL = oldBaseURL }()

	n, err := LookupASN(13335)
	if err != nil {
		t.Fatalf("LookupASN returned error: %v", err)
	}
	if n.PolicyRatio != "Balanced" {
		t.Fatalf("PolicyRatio = %q, want Balanced", n.PolicyRatio)
	}
}

func TestLookupASNNoData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/api"
	defer func() { baseURL = oldBaseURL }()

	if _, err := LookupASN(64500); err == nil {
		t.Fatal("expected error when peeringdb returns no data")
	}
}

func TestLookupASNHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/api"
	defer func() { baseURL = oldBaseURL }()

	if _, err := LookupASN(64501); err == nil {
		t.Fatal("expected error when peeringdb returns non-200")
	}
}

func TestLookupASNMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/api"
	defer func() { baseURL = oldBaseURL }()

	if _, err := LookupASN(64502); err == nil {
		t.Fatal("expected error when peeringdb returns malformed JSON")
	}
}
