package mail

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// bimiEKU is the BIMI Extended Key Usage OID
// (id-kp-BrandIndicatorforMessageIdentification).
var bimiEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}

const vmcFetchTimeout = 10 * time.Second

var bimiRootPool = loadBIMIRoots()

func loadBIMIRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(bimiRootsPEM))
	return pool
}

// parseBIMI splits a "v=BIMI1; l=...; a=..." record into its fields.
func parseBIMI(raw string) *BIMIRecord {
	rec := &BIMIRecord{Raw: raw}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "l":
			rec.LogoURL = strings.TrimSpace(v)
		case "a":
			rec.VMCURL = strings.TrimSpace(v)
		}
	}
	return rec
}

// fetchVMC downloads the PEM bundle at rawURL and validates it as a BIMI VMC.
// Only https URLs are accepted, and the dialer rejects non-public addresses
// to prevent the DNS-driven fetch from reaching internal services.
func fetchVMC(rawURL string) *VMCInfo {
	info := &VMCInfo{}

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		info.Error = "invalid VMC URL (must be https)"
		return info
	}

	client := &http.Client{
		Timeout: vmcFetchTimeout,
		Transport: &http.Transport{
			DialContext: safeDialContext,
		},
		CheckRedirect: checkHTTPSRedirect,
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		info.Error = fmt.Sprintf("fetch failed: %v", err)
		return info
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("fetch failed: HTTP %d", resp.StatusCode)
		return info
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		info.Error = fmt.Sprintf("read failed: %v", err)
		return info
	}

	return validateVMCBytes(body, bimiRootPool, time.Now())
}

// validateVMCBytes parses a VMC PEM bundle and validates it against the
// supplied trust pool at the given point in time. Split out from fetchVMC so
// it can be exercised in tests without a real HTTP fetch.
func validateVMCBytes(body []byte, roots *x509.CertPool, now time.Time) *VMCInfo {
	info := &VMCInfo{}

	leaf, intermediates, err := parsePEMChain(body)
	if err != nil {
		info.Error = err.Error()
		return info
	}

	info.Subject = leaf.Subject.CommonName
	info.Issuer = leaf.Issuer.CommonName
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter
	info.IsExpired = now.After(leaf.NotAfter)
	info.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	info.HasBIMIEKU = hasBIMIEKU(leaf)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		info.Error = fmt.Sprintf("chain invalid: %v", err)
		return info
	}
	info.ChainValid = true
	return info
}

// checkHTTPSRedirect refuses redirect targets that downgrade to plaintext,
// so an attacker can't publish a BIMI record that 302s from https://... to
// http://... and swap the VMC mid-flight.
func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https URL: %s", req.URL.Scheme)
	}
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	return nil
}

// safeDialContext dials only public IPv4/IPv6 addresses. Loopback, private,
// link-local, multicast, and unspecified ranges are refused so that a BIMI
// record cannot redirect the fetch at internal infrastructure.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errors.New("no public address for host")
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	// Reject IPv4 CGNAT 100.64.0.0/10 (net.IP.IsPrivate doesn't cover it).
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return true
}

// parsePEMChain walks a PEM bundle, picks the leaf by !IsCA, and returns
// the remaining certs as intermediates.
func parsePEMChain(data []byte) (*x509.Certificate, *x509.CertPool, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse cert: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("no certificate found in PEM")
	}

	leafIdx := -1
	for i, c := range certs {
		if !c.IsCA {
			leafIdx = i
			break
		}
	}
	if leafIdx == -1 {
		leafIdx = 0 // fall back to first cert if everything looks like a CA
	}

	intermediates := x509.NewCertPool()
	for i, c := range certs {
		if i == leafIdx {
			continue
		}
		intermediates.AddCert(c)
	}
	return certs[leafIdx], intermediates, nil
}

func hasBIMIEKU(cert *x509.Certificate) bool {
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(bimiEKU) {
			return true
		}
	}
	return false
}
