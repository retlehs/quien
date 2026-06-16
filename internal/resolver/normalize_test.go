package resolver

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"cyrillic IDN to punycode", "евау.world", "xn--80adi2d.world"},
		{"already punycode is idempotent", "xn--80adi2d.world", "xn--80adi2d.world"},
		{"uppercase ASCII lowercased", "EXAMPLE.COM", "example.com"},
		{"plain ASCII unchanged", "example.com", "example.com"},
		{"trailing dot trimmed", "евау.world.", "xn--80adi2d.world"},
		{"surrounding whitespace trimmed", "  example.com  ", "example.com"},
		{"IP literal passes through", "8.8.8.8", "8.8.8.8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeDomain(tt.in); got != tt.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainIDNProducesASCII(t *testing.T) {
	for _, in := range []string{"ébay.it", "iphone.セール", "zwick.ελ"} {
		got := NormalizeDomain(in)
		if utf8.RuneCountInString(got) != len(got) {
			t.Errorf("NormalizeDomain(%q) = %q, want all-ASCII", in, got)
		}
		if !strings.Contains(got, "xn--") {
			t.Errorf("NormalizeDomain(%q) = %q, want a punycode (xn--) label", in, got)
		}
	}
}

func TestRegistrableDomainIDN(t *testing.T) {
	// Cases where the exact registrable domain is known.
	exact := []struct {
		in   string
		want string
	}{
		{"евау.world", "xn--80adi2d.world"},
		{"www.евау.world", "xn--80adi2d.world"},
	}
	for _, tt := range exact {
		got, err := RegistrableDomain(tt.in)
		if err != nil {
			t.Errorf("RegistrableDomain(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	structural := []string{"ébay.it", "iphone.セール", "zwick.ελ"}
	for _, in := range structural {
		got, err := RegistrableDomain(in)
		if err != nil {
			t.Errorf("RegistrableDomain(%q) returned error: %v", in, err)
			continue
		}
		if utf8.RuneCountInString(got) != len(got) {
			t.Errorf("RegistrableDomain(%q) = %q, want all-ASCII", in, got)
		}
		if !strings.Contains(got, "xn--") {
			t.Errorf("RegistrableDomain(%q) = %q, want a punycode (xn--) label", in, got)
		}
	}
}

func TestRegistrableDomainASCIIRegression(t *testing.T) {
	ok := []struct {
		in   string
		want string
	}{
		{"mail.google.com", "google.com"},
		{"sub.example.co.jp", "example.co.jp"},
		{"example.com", "example.com"},
	}
	for _, tt := range ok {
		got, err := RegistrableDomain(tt.in)
		if err != nil {
			t.Errorf("RegistrableDomain(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	bad := []string{"hello", "co.jp", "x"}
	for _, in := range bad {
		if got, err := RegistrableDomain(in); err == nil {
			t.Errorf("RegistrableDomain(%q) = %q, want error", in, got)
		}
	}
}
