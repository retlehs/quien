package tlsinfo

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

type CertInfo struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	SANs      []string
	Serial    string
	SigAlgo   string
	KeyUsage  []string
	IsExpired bool
	DaysLeft  int
}

const timeout = 5 * time.Second

// Lookup performs a TLS handshake and returns certificate info.
func Lookup(domain string) (*CertInfo, error) {
	addr := net.JoinHostPort(domain, "443")

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: domain,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates presented")
	}

	cert := certs[0]
	now := time.Now()

	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	if daysLeft < 0 {
		daysLeft = 0
	}

	info := &CertInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    issuerName(cert),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		SANs:      cert.DNSNames,
		Serial:    cert.SerialNumber.Text(16),
		SigAlgo:   cert.SignatureAlgorithm.String(),
		IsExpired: now.After(cert.NotAfter),
		DaysLeft:  daysLeft,
	}

	info.KeyUsage = keyUsageStrings(cert)

	return info, nil
}

func keyUsageStrings(cert *x509.Certificate) []string {
	var usages []string
	for _, u := range cert.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Auth")
		default:
			usages = append(usages, fmt.Sprintf("ExtKeyUsage(%d)", u))
		}
	}
	return usages
}

func issuerName(cert *x509.Certificate) string {
	cn := cert.Issuer.CommonName
	org := strings.Join(cert.Issuer.Organization, ", ")
	switch {
	case org != "" && cn != "" && !strings.EqualFold(org, cn):
		return org + " " + cn
	case org != "":
		return org
	default:
		return cn
	}
}
