package tlsinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestIssuerName(t *testing.T) {
	tests := []struct {
		name string
		org  []string
		cn   string
		want string
	}{
		{"org and cn differ", []string{"Let's Encrypt"}, "E8", "Let's Encrypt E8"},
		{"cn only", nil, "R3", "R3"},
		{"org only", []string{"DigiCert Inc"}, "", "DigiCert Inc"},
		{"org equals cn", []string{"CloudFlare"}, "CloudFlare", "CloudFlare"},
		{"org equals cn case insensitive", []string{"Cloudflare"}, "CLOUDFLARE", "Cloudflare"},
		{"both empty", nil, "", ""},
		{"multiple orgs", []string{"Org A", "Org B"}, "CN", "Org A, Org B CN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				Issuer: pkix.Name{
					Organization: tt.org,
					CommonName:   tt.cn,
				},
			}
			got := issuerName(cert)
			if got != tt.want {
				t.Errorf("issuerName() = %q, want %q", got, tt.want)
			}
		})
	}
}
