package mail

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseBIMI(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		logo string
		vmc  string
	}{
		{
			name: "full record",
			raw:  "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem",
			logo: "https://example.com/logo.svg",
			vmc:  "https://example.com/vmc.pem",
		},
		{
			name: "no spaces",
			raw:  "v=BIMI1;l=https://example.com/logo.svg;a=https://example.com/vmc.pem",
			logo: "https://example.com/logo.svg",
			vmc:  "https://example.com/vmc.pem",
		},
		{
			name: "missing vmc",
			raw:  "v=BIMI1; l=https://example.com/logo.svg",
			logo: "https://example.com/logo.svg",
			vmc:  "",
		},
		{
			name: "missing logo",
			raw:  "v=BIMI1; a=https://example.com/vmc.pem",
			logo: "",
			vmc:  "https://example.com/vmc.pem",
		},
		{
			name: "uppercase keys",
			raw:  "v=BIMI1; L=https://example.com/logo.svg; A=https://example.com/vmc.pem",
			logo: "https://example.com/logo.svg",
			vmc:  "https://example.com/vmc.pem",
		},
		{
			name: "extra whitespace",
			raw:  "  v=BIMI1 ;  l =  https://example.com/logo.svg  ;  a =  https://example.com/vmc.pem  ",
			logo: "https://example.com/logo.svg",
			vmc:  "https://example.com/vmc.pem",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := parseBIMI(tc.raw)
			if rec.Raw != tc.raw {
				t.Errorf("Raw: want %q got %q", tc.raw, rec.Raw)
			}
			if rec.LogoURL != tc.logo {
				t.Errorf("LogoURL: want %q got %q", tc.logo, rec.LogoURL)
			}
			if rec.VMCURL != tc.vmc {
				t.Errorf("VMCURL: want %q got %q", tc.vmc, rec.VMCURL)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"169.254.169.254", false}, // AWS/GCE metadata
		{"fe80::1", false},
		{"100.64.0.1", false}, // CGNAT
		{"224.0.0.1", false},  // multicast
		{"0.0.0.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := isPublicIP(net.ParseIP(tc.ip))
			if got != tc.public {
				t.Errorf("isPublicIP(%s) = %v, want %v", tc.ip, got, tc.public)
			}
		})
	}
}

func TestSafeDialContextRejectsLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := safeDialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error dialing loopback, got nil")
	}
	if !strings.Contains(err.Error(), "no public address") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchVMCRejectsNonHTTPS(t *testing.T) {
	cases := []string{
		"http://example.com/vmc.pem",
		"file:///etc/passwd",
		"://bogus",
		"",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			info := fetchVMC(u)
			if info.Error == "" {
				t.Errorf("expected error for %q, got none", u)
			}
			if !strings.Contains(info.Error, "invalid VMC URL") {
				t.Errorf("unexpected error for %q: %v", u, info.Error)
			}
		})
	}
}

func TestCheckHTTPSRedirect(t *testing.T) {
	httpsReq := &http.Request{URL: mustParseURL(t, "https://example.com/next.pem")}
	httpReq := &http.Request{URL: mustParseURL(t, "http://example.com/next.pem")}

	if err := checkHTTPSRedirect(httpsReq, nil); err != nil {
		t.Errorf("expected https redirect to be allowed: %v", err)
	}

	if err := checkHTTPSRedirect(httpReq, nil); err == nil {
		t.Error("expected http redirect to be refused")
	} else if !strings.Contains(err.Error(), "non-https") {
		t.Errorf("unexpected error: %v", err)
	}

	via := make([]*http.Request, 5)
	if err := checkHTTPSRedirect(httpsReq, via); err == nil {
		t.Error("expected too-many-redirects error")
	}
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestHasBIMIEKU(t *testing.T) {
	cert := &x509.Certificate{
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			{1, 3, 6, 1, 5, 5, 7, 3, 1}, // server auth
		},
	}
	if hasBIMIEKU(cert) {
		t.Error("expected false for cert without BIMI EKU")
	}
	cert.UnknownExtKeyUsage = append(cert.UnknownExtKeyUsage, bimiEKU)
	if !hasBIMIEKU(cert) {
		t.Error("expected true for cert with BIMI EKU")
	}
}

func TestParsePEMChain(t *testing.T) {
	root, rootKey := makeCA(t, "Test Root", nil, nil)
	intermediate, intKey := makeCA(t, "Test Intermediate", root, rootKey)
	leaf := makeLeaf(t, "brand.example", intermediate, intKey, time.Now().Add(24*time.Hour), true)

	leafPEM := pemEncode(leaf)
	intPEM := pemEncode(intermediate)
	rootPEM := pemEncode(root)

	t.Run("leaf first", func(t *testing.T) {
		body := bytes.Join([][]byte{leafPEM, intPEM, rootPEM}, nil)
		got, pool, err := parsePEMChain(body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Raw, leaf.Raw) {
			t.Error("expected leaf cert")
		}
		if pool == nil {
			t.Error("expected non-nil intermediates pool")
		}
	})

	t.Run("leaf middle (chain-first ordering)", func(t *testing.T) {
		body := bytes.Join([][]byte{intPEM, leafPEM, rootPEM}, nil)
		got, _, err := parsePEMChain(body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Raw, leaf.Raw) {
			t.Errorf("expected leaf cert by IsCA, got %s", got.Subject.CommonName)
		}
	})

	t.Run("ignores non-certificate blocks", func(t *testing.T) {
		junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("ignored")})
		body := bytes.Join([][]byte{junk, leafPEM}, nil)
		got, _, err := parsePEMChain(body)
		if err != nil {
			t.Fatal(err)
		}
		if got.Subject.CommonName != "brand.example" {
			t.Errorf("unexpected leaf: %s", got.Subject.CommonName)
		}
	})

	t.Run("no certs", func(t *testing.T) {
		_, _, err := parsePEMChain([]byte("not a pem"))
		if err == nil {
			t.Error("expected error for empty input")
		}
	})

	t.Run("all CA fallback", func(t *testing.T) {
		body := bytes.Join([][]byte{intPEM, rootPEM}, nil)
		got, _, err := parsePEMChain(body)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Error("expected fallback leaf selection")
		}
	})
}

func TestValidateVMCBytes(t *testing.T) {
	root, rootKey := makeCA(t, "Test BIMI Root", nil, nil)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	now := time.Now()

	t.Run("valid chain with BIMI EKU", func(t *testing.T) {
		leaf := makeLeaf(t, "brand.example", root, rootKey, now.Add(30*24*time.Hour), true)
		body := bytes.Join([][]byte{pemEncode(leaf), pemEncode(root)}, nil)

		info := validateVMCBytes(body, roots, now)
		if info.Error != "" {
			t.Fatalf("unexpected error: %s", info.Error)
		}
		if !info.ChainValid {
			t.Error("expected ChainValid=true")
		}
		if !info.HasBIMIEKU {
			t.Error("expected HasBIMIEKU=true")
		}
		if info.IsExpired {
			t.Error("expected IsExpired=false")
		}
		if info.DaysLeft < 29 || info.DaysLeft > 30 {
			t.Errorf("unexpected DaysLeft: %d", info.DaysLeft)
		}
		if info.Subject != "brand.example" {
			t.Errorf("unexpected subject: %s", info.Subject)
		}
	})

	t.Run("missing BIMI EKU", func(t *testing.T) {
		leaf := makeLeaf(t, "brand.example", root, rootKey, now.Add(30*24*time.Hour), false)
		body := bytes.Join([][]byte{pemEncode(leaf), pemEncode(root)}, nil)

		info := validateVMCBytes(body, roots, now)
		if info.HasBIMIEKU {
			t.Error("expected HasBIMIEKU=false")
		}
		// Chain should still validate (EKU check is independent).
		if !info.ChainValid {
			t.Errorf("expected chain to validate: %s", info.Error)
		}
	})

	t.Run("expired leaf", func(t *testing.T) {
		leaf := makeLeaf(t, "brand.example", root, rootKey, now.Add(-1*time.Hour), true)
		body := bytes.Join([][]byte{pemEncode(leaf), pemEncode(root)}, nil)

		info := validateVMCBytes(body, roots, now)
		if !info.IsExpired {
			t.Error("expected IsExpired=true")
		}
		if info.ChainValid {
			t.Error("expected chain invalid for expired leaf")
		}
		if !strings.Contains(info.Error, "expired") && !strings.Contains(info.Error, "not yet valid") {
			t.Errorf("expected expiry error, got: %s", info.Error)
		}
	})

	t.Run("untrusted root", func(t *testing.T) {
		leaf := makeLeaf(t, "brand.example", root, rootKey, now.Add(30*24*time.Hour), true)
		body := bytes.Join([][]byte{pemEncode(leaf), pemEncode(root)}, nil)

		emptyPool := x509.NewCertPool()
		info := validateVMCBytes(body, emptyPool, now)
		if info.ChainValid {
			t.Error("expected chain invalid with empty root pool")
		}
		if info.Error == "" {
			t.Error("expected error message")
		}
	})
}

// --- test helpers ---

func makeCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makeLeaf(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notAfter time.Time, withBIMIEKU bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if withBIMIEKU {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{bimiEKU}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemEncode(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
