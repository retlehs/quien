package bgp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/data/bgp-state/data.json"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("resource"), "1.1.1.1"; got != want {
			t.Fatalf("resource = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("User-Agent"), userAgent; got != want {
			t.Fatalf("user-agent = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"data":{"resource":"1.1.1.1","bgp_state":[{"target_prefix":"1.1.1.0/24","path":[13335],"source_id":"rrc00"}]}}`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/data"
	defer func() { baseURL = oldBaseURL }()

	info, err := LookupIP("1.1.1.1")
	if err != nil {
		t.Fatalf("LookupIP returned error: %v", err)
	}
	if info.OriginASN != 13335 {
		t.Fatalf("OriginASN = %d, want 13335", info.OriginASN)
	}
	if info.Prefix != "1.1.1.0/24" {
		t.Fatalf("Prefix = %q, want 1.1.1.0/24", info.Prefix)
	}
}

func TestLookupIPNoState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"resource":"1.1.1.1","bgp_state":[]}}`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/data"
	defer func() { baseURL = oldBaseURL }()

	if _, err := LookupIP("1.1.1.1"); err == nil {
		t.Fatal("expected error when bgp_state is empty")
	}
}

func TestLookupIPHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/data"
	defer func() { baseURL = oldBaseURL }()

	if _, err := LookupIP("1.1.1.1"); err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestLookupIPMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"bgp_state":[`))
	}))
	defer srv.Close()

	oldBaseURL := baseURL
	baseURL = srv.URL + "/data"
	defer func() { baseURL = oldBaseURL }()

	if _, err := LookupIP("1.1.1.1"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
